defmodule Tightbeam.MemoryGuardTest do
  # Memory limits v1.1 (harness-memory-limits, art_4009cd68): the guard's own
  # decisions, on our side of the ACP seam. `/proc`, `/proc/meminfo` and the
  # cgroup filesystem are fake trees under a temp root; adapters are processes
  # that answer the guard's residency, idle and forget calls. The kill, the
  # close and the lane nudge are injected and report to the test. The real
  # processes, step and kernel limits are exercised by
  # memory_guard_containment_test.exs and cli/tests/memory_guard_step.rs.
  use Tightbeam.TestCase, async: false

  alias Tightbeam.{DB, Devices, EventLog, Gateway, Ledger, MemoryGuard, Org, Schema}

  alias Tightbeam.MemoryGuard.{
    Unguarded,
    Admission,
    Cgroup,
    HeldState,
    Probe,
    Records,
    Settings
  }

  @gib 1024 * 1024 * 1024
  @mib 1024 * 1024
  @host "testhost"

  defmodule FakeAdapter do
    # An adapter process as far as the guard sees one: it answers the idle
    # check and the residency forget, and reports both to the test.
    use GenServer

    def start_link(opts), do: GenServer.start_link(__MODULE__, Map.new(opts))
    def init(state), do: {:ok, Map.put_new(state, :busy, MapSet.new())}

    def handle_call({:idle_session?, sid}, _from, state),
      do: {:reply, if(MapSet.member?(state.busy, sid), do: :busy, else: :idle), state}

    def handle_call({:forget_session_residency, sid}, _from, state) do
      send(state.test, {:forgot, sid})
      {:reply, :ok, state}
    end

    def handle_call({:set_busy, sids}, _from, state),
      do: {:reply, :ok, %{state | busy: MapSet.new(sids)}}
  end

  setup do
    root = Path.join(System.tmp_dir!(), "tb-mg-#{System.unique_integer([:positive])}")
    base = Path.join(root, "base")
    File.mkdir_p!(Path.join(root, "proc"))
    File.mkdir_p!(base)
    on_exit(fn -> File.rm_rf!(root) end)

    db_name = :"mg_db_#{System.unique_integer([:positive])}"
    db = start_supervised!({DB, path: ":memory:", name: db_name}, id: db_name)
    :ok = Schema.ensure_all(db)
    Devices.add_user(db, "owner", true)
    Devices.add_user(db, "guest", false)
    start_supervised!({Registry, keys: :unique, name: Tightbeam.LaneRegistry})

    %{root: root, base: base, db: db}
  end

  ## Fake host

  defp meminfo!(root, total, available) do
    File.write!(
      Path.join(root, "proc/meminfo"),
      "MemTotal:       #{div(total, 1024)} kB\nMemFree:        0 kB\nMemAvailable:   #{div(available, 1024)} kB\n"
    )
  end

  # One fake process: ppid, start time and resident bytes.
  defp proc!(root, pid, ppid, start, bytes) do
    dir = Path.join([root, "proc", Integer.to_string(pid)])
    File.mkdir_p!(dir)
    fields = Enum.map_join(1..17, " ", fn _ -> "0" end)
    File.write!(Path.join(dir, "stat"), "#{pid} (fake proc) S #{ppid} #{fields} #{start} 0 0\n")

    File.write!(
      Path.join(dir, "status"),
      "Name:\tfake\nVmRSS:\t#{div(bytes, 1024)} kB\nVmSwap:\t0 kB\n"
    )
  end

  defp gone!(root, pid), do: File.rm_rf!(Path.join([root, "proc", Integer.to_string(pid)]))

  # The session process of `sid` has ended, as a close ends it: its fake
  # process goes, or, for a test that never recorded one, a launch record of an
  # already ended process is left for the close's confirmation (FS5).
  defp closed_process!(ctx, sid) do
    dir = Path.join(Records.dir(ctx.base), "sessions")

    records =
      case File.ls(dir) do
        {:ok, entries} ->
          for entry <- entries,
              String.ends_with?(entry, ".json"),
              {:ok, %{"sessionId" => ^sid} = record} <-
                [JSON.decode(File.read!(Path.join(dir, entry)))],
              do: record

        _ ->
          []
      end

    case records do
      [] ->
        pid = 900_000 + :erlang.phash2(sid, 50_000)
        launch!(ctx.base, "sl-closed-" <> sid, sid, pid, pid, 512 * @mib)

      records ->
        for record <- records, do: gone!(ctx.root, record["pid"])
    end

    :ok
  end

  defp target_pids(%{scope: "session", pid: pid}) when is_integer(pid), do: [pid]
  defp target_pids(%{scope: "adapter", row: %{os_pid: pid}}) when is_integer(pid), do: [pid]
  defp target_pids(_target), do: []

  # The guard has handled every kill it started.
  defp settle_kills!(attempts \\ 1500) do
    cond do
      :sys.get_state(MemoryGuard).killing == %{} -> :ok
      attempts == 0 -> flunk("a kill never finished")
      true -> Process.sleep(10) && settle_kills!(attempts - 1)
    end
  end

  # A launch record as the step writes it.
  defp launch!(base, launch, sid, pid, start, limit, adapter_launch \\ "adapter-launch-1") do
    dir = Path.join(Records.dir(base), "sessions")
    File.mkdir_p!(dir)
    identity = Path.join(dir, launch <> ".identity")
    File.write!(identity, "#{pid}\t#{pid}\tboot\t#{launch}\n")

    File.write!(
      Path.join(dir, launch <> ".json"),
      JSON.encode!(%{
        v: 1,
        launchId: launch,
        sessionId: sid,
        pid: pid,
        start: start,
        adapterLaunchId: adapter_launch,
        placement: "watched",
        unit: nil,
        identity: identity,
        sessionLimit: limit,
        oomScoreAdj: 100,
        errors: [],
        launchedAt: System.system_time(:millisecond)
      })
    )
  end

  defp guard!(ctx, opts \\ []) do
    test = self()
    mem_total = Keyword.get(opts, :mem_total, 16 * @gib)
    mode = Keyword.get(opts, :mode, :watched)

    probe =
      Keyword.get(opts, :probe, %{
        mode: mode,
        reason: if(mode == :watched, do: "not delegated (test)"),
        mem_total: mem_total,
        cgroup: nil
      })

    # The launch step is in place unless a test says otherwise (v1.13 FS1 A3):
    # a fake CLI file it links to; nothing executes it.
    cli_bin =
      Keyword.get_lazy(opts, :cli_bin, fn ->
        dir = Path.join(ctx.root, "cli-bin")
        File.mkdir_p!(dir)
        File.write!(Path.join(dir, "tightbeam"), "#!/bin/false\n")
        dir
      end)

    start_supervised!({
      MemoryGuard,
      # A kill on the fake host removes the fake processes it ends (unless
      # the test says the kill fails); nothing real is ever signalled.
      db: ctx.db,
      base_dir: ctx.base,
      cli_bin: cli_bin,
      local_host: @host,
      root: ctx.root,
      cgroup_fs: Keyword.get(opts, :cgroup_fs, Path.join(ctx.root, "sys/fs/cgroup")),
      probe: fn -> probe end,
      sample_ms: :manual,
      closer:
        Keyword.get(opts, :closer, fn _adapter, sid, reason ->
          send(test, {:closed, sid, reason})

          case Keyword.get(opts, :close_result, :ok) do
            # A close ends the session process (FS5 shows it gone).
            :ok -> closed_process!(ctx, sid)
            other -> other
          end
        end),
      idle_check: Keyword.get(opts, :idle_check, &Tightbeam.Acp.Adapter.idle_session?/2),
      before_close_commit: Keyword.get(opts, :before_close_commit, fn _ -> :ok end),
      before_kill_send: Keyword.get(opts, :before_kill_send, fn _ -> :ok end),
      close_confirm_ms: Keyword.get(opts, :close_confirm_ms, 300),
      killer: fn target, _host_state ->
        send(test, {:killed, target})

        case Keyword.get(opts, :kill_result, :ok) do
          killer when is_function(killer, 1) ->
            killer.(target)

          :ok ->
            for pid <- target_pids(target), do: gone!(ctx.root, pid)
            :ok

          failure ->
            failure
        end
      end,
      signaller: fn pids ->
        send(test, {:signalled, Enum.sort(pids)})
        if Keyword.get(opts, :signal_works, true), do: for(pid <- pids, do: gone!(ctx.root, pid))
        :ok
      end,
      nudge: Keyword.get(opts, :nudge, fn key -> send(test, {:nudged, key}) end)
    })
  end

  defp session!(ctx, key, sid \\ nil) do
    Org.create(ctx.db, %{
      session_key: key,
      display_name: key,
      owner_user_id: "owner",
      origin: "user:owner",
      archetype: "coder",
      host: @host,
      harness: "claude",
      provider: "anthropic",
      model: Tightbeam.Model.new("claude-sonnet-5", effort: "medium")
    })

    if sid, do: Org.append_pointer(ctx.db, key, sid, "created")
    key
  end

  defp queue!(ctx, key, text) do
    {:ok, seq} =
      Ledger.enqueue(ctx.db, %{
        session_key: key,
        message_id: "m-#{key}-#{text}-#{System.unique_integer([:positive])}",
        origin: "user:owner",
        prompt: text
      })

    seq
  end

  defp resident!(adapter, sids) do
    MemoryGuard.residency(
      adapter,
      {:claude, "shared", @host},
      "adapter-launch-1",
      MapSet.new(sids)
    )

    :sys.get_state(MemoryGuard)
  end

  defp adapter! do
    start_supervised!({FakeAdapter, test: self()}, id: {:adapter, System.unique_integer()})
  end

  defp events(db, kind) do
    {:ok, rows} =
      DB.query(db, "SELECT subject,detail FROM lifecycle_events WHERE kind=?1 ORDER BY id", [kind])

    Enum.map(rows, fn [subject, detail] -> {subject, detail && JSON.decode!(detail)} end)
  end

  ## R17 / R17a / T13: settings

  describe "settings (R17, T13)" do
    test "the defaults on Sirius's 31.25 GiB are the spec's numbers" do
      total = trunc(31.25 * @gib)
      settings = Settings.effective(%{}, total)

      assert settings.mode == "auto"
      assert settings.budget == div(total, 2)
      assert settings.session_limit == div(total, 5)
      # NB-1: residentCap 15 on Sirius, from ⌊budget / 1 GiB⌋.
      assert settings.resident_cap == 15
      assert settings.floor_hold == 12
      assert settings.floor_release == 15
      # R14/NB-3: the +100 is fixed, not a setting; R17 has exactly six settings.
      refute Map.has_key?(settings, :session_oom_score_adj)
      assert Settings.names() == ~w(mode budget sessionLimit residentCap floorHold floorRelease)
    end

    test "ranges and cross-field rules refuse a bad value and keep the stored one", ctx do
      total = 16 * @gib

      set = fn name, value ->
        {:ok, result} =
          DB.transaction(
            ctx.db,
            &Settings.set_in_txn(&1, @host, name, value, "user:owner", total)
          )

        result
      end

      assert {:ok, %{value: "15"}} = set.("residentCap", "15")
      assert {:error, %{code: "invalid_setting"}} = set.("residentCap", "0")
      assert {:error, %{code: "invalid_setting"}} = set.("residentCap", "257")
      assert {:error, %{code: "invalid_setting"}} = set.("budget", "95%")
      assert {:error, %{code: "invalid_setting"}} = set.("budget", "5%")
      assert {:ok, %{value: "8589934592"}} = set.("budget", "8G")

      assert {:error, %{message: "sessionLimit: must not exceed budget"}} =
               set.("sessionLimit", "9G")

      assert {:error, %{code: "invalid_setting"}} = set.("sessionLimit", "256M")
      assert {:ok, %{value: "536870912"}} = set.("sessionLimit", "512M")
      assert {:error, %{code: "invalid_setting"}} = set.("floorHold", "2")
      assert {:error, %{code: "invalid_setting"}} = set.("floorRelease", "12")
      assert {:ok, %{value: "20"}} = set.("floorRelease", "20%")
      assert {:error, %{code: "invalid_setting"}} = set.("sessionOomScoreAdj", "0")
      assert {:error, %{code: "invalid_setting"}} = set.("mode", "enforced")
      assert {:error, %{code: "invalid_setting"}} = set.("nonsense", "1")

      effective = Settings.effective(Settings.stored(ctx.db, @host), total)
      assert effective.resident_cap == 15
      assert effective.budget == 8 * @gib
      assert effective.session_limit == 512 * @mib
      assert effective.floor_release == 20

      assert {:ok, [["user:owner", set_at]]} =
               DB.query(
                 ctx.db,
                 "SELECT setBy,setAt FROM host_memory_settings WHERE host=?1 AND name='budget'",
                 [@host]
               )

      assert is_integer(set_at)
    end

    test "host-memory-set: an admin's change applies without a restart; a non-admin is refused",
         ctx do
      meminfo!(ctx.root, 16 * @gib, 12 * @gib)
      guard!(ctx)
      handlers = Gateway.handlers(%{db: ctx.db, base_dir: ctx.base})

      admin = session!(ctx, "agent:admin-session")

      assert %{setting: %{name: "residentCap", value: "3", setBy: "user:owner"}, hostMemory: read} =
               handlers["host-memory-set"].(%{
                 origin: "user:owner",
                 principal: {:session, admin},
                 params: %{host: @host, name: "residentCap", value: "3"}
               })

      # Applied to the next decision, no restart.
      assert read.settings.residentCap == 3
      assert MemoryGuard.read(@host).settings.residentCap == 3

      Org.create(ctx.db, %{
        session_key: "agent:guest-session",
        display_name: "guest",
        owner_user_id: "guest",
        origin: "user:guest",
        archetype: "coder",
        host: @host,
        harness: "claude",
        provider: "anthropic",
        model: Tightbeam.Model.new("claude-sonnet-5", effort: "medium")
      })

      assert %{code: "forbidden"} =
               handlers["host-memory-set"].(%{
                 origin: "agent:guest",
                 principal: {:session, "agent:guest-session"},
                 params: %{host: @host, name: "residentCap", value: "9"}
               })

      assert %{code: "invalid_setting"} =
               handlers["host-memory-set"].(%{
                 origin: "user:owner",
                 principal: {:session, admin},
                 params: %{host: @host, name: "floorHold", value: "70"}
               })

      assert MemoryGuard.read(@host).settings.residentCap == 3

      # R12: the change is re-determined and recorded.
      assert Enum.any?(events(ctx.db, "memory_guard_mode"), fn {_, detail} ->
               detail["settings"]["residentCap"] == 3
             end)
    end

    test "R17a: lowering sessionLimit kills no tree already running", ctx do
      meminfo!(ctx.root, 16 * @gib, 12 * @gib)
      proc!(ctx.root, 500, 1, 7, 900 * @mib)
      launch!(ctx.base, "sl-a", "sid-a", 500, 7, 2 * @gib)
      guard!(ctx)
      session!(ctx, "agent:a", "sid-a")

      {:ok, {:ok, _}} =
        DB.transaction(
          ctx.db,
          &Settings.set_in_txn(&1, @host, "sessionLimit", "512M", "user:owner", 16 * @gib)
        )

      :ok = MemoryGuard.settings_changed(@host)
      :ok = MemoryGuard.tick()
      refute_received {:killed, _}

      # The step reads the new limit for the next launch.
      assert %{"sessionLimit" => 536_870_912} =
               JSON.decode!(File.read!(Path.join(Records.dir(ctx.base), "launch.json")))
    end
  end

  ## R12 / R12a / R12b / T11: modes

  describe "modes (R12, R12a, R12b, T11)" do
    defp cgroup_tree!(root, own, opts) do
      fs = Path.join(root, "sys/fs/cgroup")
      File.mkdir_p!(fs)
      File.write!(Path.join(fs, "cgroup.controllers"), "cpu memory pids\n")
      File.mkdir_p!(Path.join(root, "proc/self"))
      File.write!(Path.join(root, "proc/self/cgroup"), "0::#{own}\n")
      delegated = Path.dirname(own)
      dir = Path.join(fs, String.trim_leading(delegated, "/"))
      File.mkdir_p!(Path.join(fs, String.trim_leading(own, "/")))

      for file <- ~w(cgroup.procs cgroup.subtree_control memory.swap.max),
          do: File.write!(Path.join(dir, file), "")

      File.write!(Path.join(dir, "cgroup.controllers"), "memory pids\n")

      if Keyword.get(opts, :read_only, false) do
        File.chmod!(Path.join(dir, "cgroup.procs"), 0o444)
        File.chmod!(Path.join(dir, "cgroup.subtree_control"), 0o444)
      end

      fs
    end

    test "(a) no delegation reads watched with the plain-words reason", ctx do
      meminfo!(ctx.root, 16 * @gib, 12 * @gib)
      File.mkdir_p!(Path.join(ctx.root, "sys/fs/cgroup"))
      File.write!(Path.join(ctx.root, "sys/fs/cgroup/cgroup.controllers"), "memory\n")
      File.mkdir_p!(Path.join(ctx.root, "proc/self"))
      File.write!(Path.join(ctx.root, "proc/self/cgroup"), "0::/system.slice/tightbeam.service\n")

      result =
        Probe.probe(root: ctx.root, os: {:unix, :linux}, systemctl: fn _ -> {:ok, "continue"} end)

      assert result.mode == :watched
      assert result.reason =~ "not enforced by the kernel"
      assert result.reason =~ "not delegated a cgroup"
      assert result.mem_total == 16 * @gib
    end

    test "(b) delegation with OOMPolicy=stop reads watched and names the policy", ctx do
      meminfo!(ctx.root, 16 * @gib, 12 * @gib)
      cgroup_tree!(ctx.root, "/system.slice/tightbeam.service/gateway", [])

      result =
        Probe.probe(
          root: ctx.root,
          os: {:unix, :linux},
          systemctl: fn ["show", "tightbeam.service", "-p", "OOMPolicy", "--value"] ->
            {:ok, "stop"}
          end
        )

      assert result.mode == :watched
      assert result.reason =~ "OOMPolicy=stop"
    end

    test "delegation with OOMPolicy=continue reads enforced and arranges the R12c layout", ctx do
      meminfo!(ctx.root, 16 * @gib, 12 * @gib)
      fs = cgroup_tree!(ctx.root, "/system.slice/tightbeam.service/gateway", [])

      result =
        Probe.probe(root: ctx.root, os: {:unix, :linux}, systemctl: fn _ -> {:ok, "continue"} end)

      assert result.mode == :enforced
      assert result.cgroup.root == "/system.slice/tightbeam.service"

      assert {:ok, layout} = Cgroup.setup(fs, result.cgroup, 8 * @gib)
      harness = Cgroup.dir(fs, layout.harness)
      assert File.read!(Path.join(harness, "memory.max")) == Integer.to_string(8 * @gib)
      assert File.read!(Path.join(harness, "memory.swap.max")) == "0"
      assert File.read!(Path.join(harness, "memory.oom.group")) == "0"

      assert {:ok, unit} = Cgroup.create_adapter_unit(layout, "L1")
      assert unit == "/system.slice/tightbeam.service/harness/adapter-L1"
      assert File.read!(Path.join(Cgroup.dir(fs, unit), "memory.oom.group")) == "1"
      assert File.read!(Path.join(Cgroup.dir(fs, unit), "memory.swap.max")) == "0"
    end

    test "(c) no /proc/meminfo reads count-only and R3 still holds turns at the cap", ctx do
      assert %{mode: :count_only, reason: reason} =
               Probe.probe(root: ctx.root, os: {:unix, :linux})

      assert reason =~ "/proc/meminfo"

      guard!(ctx, probe: %{mode: :count_only, reason: reason, mem_total: nil, cgroup: nil})

      {:ok, {:ok, _}} =
        DB.transaction(
          ctx.db,
          &Settings.set_in_txn(&1, @host, "residentCap", "1", "user:owner", nil)
        )

      :ok = MemoryGuard.settings_changed(@host)
      adapter = adapter!()
      session!(ctx, "agent:r", "sid-r")
      queue!(ctx, "agent:r", "busy")
      resident!(adapter, ["sid-r"])
      :ok = MemoryGuard.admit("agent:r")

      session!(ctx, "agent:new")
      queue!(ctx, "agent:new", "needs a launch")
      assert {:held, ["resident_cap"]} = MemoryGuard.admit("agent:new")

      read = MemoryGuard.read(@host)
      assert read.mode == "count-only"
      assert read.notEnforcedReason == reason

      assert read.heldTurns == %{
               "guard_unavailable" => 0,
               "memory_budget" => 0,
               "memory_floor" => 0,
               "resident_cap" => 1
             }

      assert read.residentCount == 1
      # Counts and totals only (v3 R2): no process list, pid or command line.
      refute Enum.any?(Map.keys(read), &(&1 in [:pids, :processes, :commands]))
    end

    test "macOS and other systems read count-only", ctx do
      assert %{mode: :count_only, reason: reason} =
               Probe.probe(root: ctx.root, os: {:unix, :darwin}, mem_total: 8 * @gib)

      assert reason =~ "need Linux"
    end

    test "(d) a launch whose unit cannot be created runs watched and the host stays enforced",
         ctx do
      meminfo!(ctx.root, 16 * @gib, 12 * @gib)
      fs = cgroup_tree!(ctx.root, "/svc/tightbeam.service/gateway", [])

      probe = %{
        mode: :enforced,
        reason: nil,
        mem_total: 16 * @gib,
        cgroup: %{
          root: "/svc/tightbeam.service",
          gateway: "/svc/tightbeam.service/gateway",
          move_self: false
        }
      }

      guard!(ctx, probe: probe, cgroup_fs: fs)
      assert MemoryGuard.read(@host).mode == "enforced"

      # The budget group refuses new children for this launch.
      harness = Path.join(fs, "svc/tightbeam.service/harness")
      File.chmod!(harness, 0o555)
      on_exit(fn -> File.chmod(harness, 0o755) end)

      env =
        MemoryGuard.launch_env(
          {:codex, "shared", @host},
          "LAUNCH-X",
          [cmd: ["/bin/codex-acp"], env: []],
          ctx.db
        )

      refute List.keymember?(env, "TIGHTBEAM_ADAPTER_CGROUP", 0)

      assert [{@host, %{"launchId" => "LAUNCH-X", "error" => error}}] =
               events(ctx.db, "memory_guard_launch_unplaced")

      assert error =~ "could not be created"
      assert MemoryGuard.read(@host).mode == "enforced"
    end

    test "(review B2) an adapter whose unit join failed is recorded, sampled and limited", ctx do
      meminfo!(ctx.root, 16 * @gib, 12 * @gib)
      fs = cgroup_tree!(ctx.root, "/svc/tightbeam.service/gateway", [])

      probe = %{
        mode: :enforced,
        reason: nil,
        mem_total: 16 * @gib,
        cgroup: %{
          root: "/svc/tightbeam.service",
          gateway: "/svc/tightbeam.service/gateway",
          move_self: false
        }
      }

      guard!(ctx, probe: probe, cgroup_fs: fs)

      {:ok, {:ok, _}} =
        DB.transaction(
          ctx.db,
          &Settings.set_in_txn(&1, @host, "budget", "2G", "user:owner", 16 * @gib)
        )

      :ok = MemoryGuard.settings_changed(@host)

      # The unit was created for the launch, but the adapter never joined it:
      # its own cgroup is still the gateway's.
      env =
        MemoryGuard.launch_env(
          {:codex, "shared", @host},
          "L-un",
          [cmd: ["/bin/x"], env: []],
          ctx.db
        )

      assert List.keymember?(env, "TIGHTBEAM_ADAPTER_CGROUP", 0)
      harness = Path.join(fs, "svc/tightbeam.service/harness")
      File.write!(Path.join(harness, "memory.current"), Integer.to_string(100 * @mib))
      File.write!(Path.join(harness, "adapter-L-un/memory.current"), "0")
      insert_adapter_row!(ctx.db, "L-un", 970, "codex")
      proc!(ctx.root, 970, 1, 970, 2100 * @mib)
      File.write!(Path.join(ctx.root, "proc/970/cgroup"), "0::/svc/tightbeam.service/gateway\n")

      :ok = MemoryGuard.tick()

      assert [{@host, %{"launchId" => "L-un", "error" => error}}] =
               events(ctx.db, "memory_guard_launch_unplaced")

      assert error =~ "not in its memory unit"
      # Its memory counts toward the budget, and over the budget it is ended.
      assert MemoryGuard.read(@host).tightbeamTotalBytes == 2200 * @mib
      assert_receive {:killed, %{scope: "adapter", row: %{os_pid: 970}}}
      settle_kills!()

      assert [{@host, %{"limit" => "budget", "scope" => "adapter"}}] =
               events(ctx.db, "memory_tree_ended")

      # Recorded once.
      :ok = MemoryGuard.tick()
      assert length(events(ctx.db, "memory_guard_launch_unplaced")) == 1
    end

    test "(review B4) enforced -> off lifts the kernel limits on live units; enforced again restores them",
         ctx do
      meminfo!(ctx.root, 16 * @gib, 12 * @gib)
      fs = cgroup_tree!(ctx.root, "/svc/tightbeam.service/gateway", [])

      probe = %{
        mode: :enforced,
        reason: nil,
        mem_total: 16 * @gib,
        cgroup: %{
          root: "/svc/tightbeam.service",
          gateway: "/svc/tightbeam.service/gateway",
          move_self: false
        }
      }

      guard!(ctx, probe: probe, cgroup_fs: fs)
      harness = Path.join(fs, "svc/tightbeam.service/harness")
      unit = Path.join(harness, "session-live")
      File.mkdir_p!(unit)

      for {f, v} <- [
            {"memory.max", "536870912"},
            {"memory.swap.max", "0"},
            {"memory.oom.group", "1"}
          ],
          do: File.write!(Path.join(unit, f), v)

      dir = Path.join(Records.dir(ctx.base), "sessions")
      File.mkdir_p!(dir)

      File.write!(
        Path.join(dir, "sl-live.json"),
        JSON.encode!(%{
          v: 1,
          launchId: "sl-live",
          sessionId: "live",
          pid: 1,
          start: 1,
          placement: "enforced",
          unit: "/svc/tightbeam.service/harness/session-live",
          sessionLimit: 536_870_912
        })
      )

      set_mode = fn mode ->
        {:ok, {:ok, _}} =
          DB.transaction(
            ctx.db,
            &Settings.set_in_txn(&1, @host, "mode", mode, "user:owner", 16 * @gib)
          )

        :ok = MemoryGuard.settings_changed(@host)
      end

      set_mode.("off")
      assert MemoryGuard.read(@host).mode == "off"
      assert File.read!(Path.join(harness, "memory.max")) == "max"
      assert File.read!(Path.join(unit, "memory.max")) == "max"
      assert File.read!(Path.join(unit, "memory.swap.max")) == "max"
      assert File.read!(Path.join(unit, "memory.oom.group")) == "0"
      # The live member stays where it is.
      assert File.dir?(unit)

      set_mode.("auto")
      assert MemoryGuard.read(@host).mode == "enforced"
      assert File.read!(Path.join(harness, "memory.max")) == Integer.to_string(8 * @gib)
      assert File.read!(Path.join(unit, "memory.max")) == "536870912"
      assert File.read!(Path.join(unit, "memory.swap.max")) == "0"
      assert File.read!(Path.join(unit, "memory.oom.group")) == "1"
    end

    test "(review R2) an unreadable cgroup.events is not an empty unit, so the tree is not certified ended",
         ctx do
      fs = Path.join(ctx.root, "cg")
      unit = "/h/session-x"
      dir = Cgroup.dir(fs, unit)
      events_file = Path.join(dir, "cgroup.events")
      File.mkdir_p!(dir)
      on_exit(fn -> File.chmod(events_file, 0o644) end)

      File.write!(events_file, "populated 0\nfrozen 0\n")
      assert Cgroup.populated?(fs, unit) == false
      File.chmod!(events_file, 0o000)
      assert Cgroup.populated?(fs, unit) == :unreadable

      # The root is gone and the kernel kill succeeded, but the unit's own
      # record cannot be read.
      state = %{root: ctx.root, killer: fn _, _ -> :ok end, signaller: fn _ -> :ok end}
      target = %{scope: "session", pid: 4242, start: 1, unit: unit}

      assert {:error, {:tree_survives, :ok}} =
               MemoryGuard.end_tree(state, %{layout: %{fs: fs}}, target)

      File.chmod!(events_file, 0o644)
      File.rm!(events_file)
      assert Cgroup.populated?(fs, unit) == :unreadable
      File.rmdir!(dir)
      assert Cgroup.populated?(fs, unit) == :gone
      assert :ok = MemoryGuard.end_tree(state, %{layout: %{fs: fs}}, target)
    end

    test "E2.unreadable / E1.unreadable (enforced, T25 c): an unplaced adapter whose tree cannot be read disables R1 and R2 and leaves the total unknown, never a smaller one",
         ctx do
      meminfo!(ctx.root, 16 * @gib, 12 * @gib)
      fs = cgroup_tree!(ctx.root, "/svc/tightbeam.service/gateway", [])
      guard!(ctx, probe: enforced_probe(), cgroup_fs: fs)

      _ =
        MemoryGuard.launch_env(
          {:codex, "shared", @host},
          "L-un",
          [cmd: ["/bin/x"], env: []],
          ctx.db
        )

      harness = Path.join(fs, "svc/tightbeam.service/harness")
      File.write!(Path.join(harness, "memory.current"), Integer.to_string(100 * @mib))
      File.write!(Path.join(harness, "adapter-L-un/memory.current"), "0")
      insert_adapter_row!(ctx.db, "L-un", 970, "codex")
      proc!(ctx.root, 970, 1, 970, 100 * @mib)
      File.write!(Path.join(ctx.root, "proc/970/cgroup"), "0::/svc/tightbeam.service/gateway\n")
      proc_dir = Path.join(ctx.root, "proc")
      stat = Path.join(proc_dir, "970/stat")

      on_exit(fn ->
        File.chmod(proc_dir, 0o755)
        File.chmod(stat, 0o644)
      end)

      :ok = MemoryGuard.tick()
      assert MemoryGuard.read(@host).mode == "enforced"
      assert MemoryGuard.read(@host).tightbeamTotalBytes == 200 * @mib

      # The known root exists but cannot be read.
      File.chmod!(stat, 0o000)
      :ok = MemoryGuard.tick()
      read = MemoryGuard.read(@host)
      assert read.mode == "enforced"
      assert [%{reading: "tree", disables: ["R1", "R2"]}] = read.unavailable
      assert read.tightbeamTotalBytes == nil
      assert [{@host, %{"reading" => "tree"}}] = events(ctx.db, "memory_guard_sampling_failed")

      File.chmod!(stat, 0o644)
      :ok = MemoryGuard.tick()
      read = MemoryGuard.read(@host)
      assert read.mode == "enforced"
      assert read.unavailable == []
      assert read.tightbeamTotalBytes == 200 * @mib

      # The whole process table cannot be read: the tree reading is recorded
      # once per run already; meminfo, under /proc here, is recorded now.
      File.chmod!(proc_dir, 0o000)
      :ok = MemoryGuard.tick()
      read = MemoryGuard.read(@host)
      assert read.mode == "enforced"
      assert Enum.sort(Enum.map(read.unavailable, & &1.reading)) == ["meminfo", "tree"]

      assert Enum.sort(
               for {_, d} <- events(ctx.db, "memory_guard_sampling_failed"), do: d["reading"]
             ) ==
               ["meminfo", "tree"]

      File.chmod!(proc_dir, 0o755)
      :ok = MemoryGuard.tick()
      assert MemoryGuard.read(@host).unavailable == []
    end

    test "E2.unreadable (watched): a known session root that cannot be read disables R1 and R2 and is not mistaken for its end",
         ctx do
      meminfo!(ctx.root, 16 * @gib, 12 * @gib)
      guard!(ctx)
      proc!(ctx.root, 981, 1, 981, 100 * @mib)
      launch!(ctx.base, "sl-r", "sid-r", 981, 981, 512 * @mib)
      stat = Path.join(ctx.root, "proc/981/stat")
      on_exit(fn -> File.chmod(stat, 0o644) end)

      :ok = MemoryGuard.tick()
      assert MemoryGuard.read(@host).mode == "watched"

      File.chmod!(stat, 0o000)
      :ok = MemoryGuard.tick()
      read = MemoryGuard.read(@host)
      assert read.mode == "watched"
      assert [%{reading: "tree", disables: ["R1", "R2"]}] = read.unavailable
      # Not mistaken for its end: custody stays.
      assert Map.has_key?(elem(Records.read_all(ctx.base), 1), "sl-r")
    end

    for {direction, failure} <- [
          {:leaving, :unit_write},
          {:leaving, :unit_list},
          {:returning, :unit_write},
          {:returning, :unit_list}
        ] do
      @tag direction: direction, failure: failure
      test "(review R4) #{direction} enforced with a #{failure} failure is not reported applied; retried until it is",
           ctx do
        {harness, unit, set_mode} = enforced_with_unit!(ctx)

        if ctx.direction == :returning, do: assert(:ok = set_mode.("off"))

        breaks =
          case ctx.failure do
            :unit_write -> {Path.join(unit, "memory.max"), 0o444, 0o644}
            :unit_list -> {harness, 0o300, 0o755}
          end

        {path, broken, fixed} = breaks
        File.chmod!(path, broken)
        on_exit(fn -> File.chmod(path, fixed) end)
        requested = if ctx.direction == :leaving, do: "off", else: "auto"
        modes_before = length(events(ctx.db, "memory_guard_mode"))

        assert {:error, {:not_applied, error}} = set_mode.(requested)

        case ctx.failure do
          :unit_write -> assert error =~ "memory.max could not be written"
          :unit_list -> assert error =~ "cannot be listed"
        end

        read = MemoryGuard.read(@host)
        assert read.mode == "watched"
        assert read.notEnforcedReason =~ "retried every sample"

        # The launch step is told the mode in effect, without a unit to join.
        assert %{"mode" => "watched", "fs" => nil, "harness" => nil} =
                 JSON.decode!(File.read!(Path.join(Records.dir(ctx.base), "launch.json")))

        # Neither the read nor the mode record says the requested mode.
        refute Enum.any?(
                 Enum.drop(events(ctx.db, "memory_guard_mode"), modes_before),
                 fn {_, detail} -> detail["mode"] in ["off", "enforced"] end
               )

        # The host-memory verb says the stored setting is not yet applied.
        session!(ctx, "agent:admin-session")

        result =
          Gateway.handlers(%{db: ctx.db, base_dir: ctx.base})["host-memory-set"].(%{
            origin: "user:owner",
            principal: {:session, "agent:admin-session"},
            params: %{host: @host, name: "mode", value: requested}
          })

        assert result.effect =~ "NOT yet applied"

        # The sampler retries; once the kernel takes it, the mode is in effect.
        File.chmod!(path, fixed)
        :ok = MemoryGuard.tick()

        if ctx.direction == :leaving do
          assert MemoryGuard.read(@host).mode == "off"
          assert File.read!(Path.join(unit, "memory.max")) == "max"
          assert File.read!(Path.join(unit, "memory.oom.group")) == "0"
        else
          assert MemoryGuard.read(@host).mode == "enforced"
          assert File.read!(Path.join(unit, "memory.max")) == "536870912"
          assert File.read!(Path.join(unit, "memory.oom.group")) == "1"
        end

        assert :ok = MemoryGuard.settings_changed(@host)
      end
    end

    test "(review B4) an adapter launched while off already starts its sessions through the step, which acts once the mode changes",
         ctx do
      meminfo!(ctx.root, 16 * @gib, 12 * @gib)
      cli = Path.join(ctx.root, "cli")
      File.mkdir_p!(cli)
      File.write!(Path.join(cli, "tightbeam"), "#!/bin/sh\n")

      start_supervised!(
        {MemoryGuard,
         db: ctx.db,
         base_dir: ctx.base,
         cli_bin: cli,
         local_host: @host,
         root: ctx.root,
         probe: fn -> %{mode: :watched, reason: "test", mem_total: 16 * @gib, cgroup: nil} end,
         sample_ms: :manual,
         nudge: fn _ -> :ok end}
      )

      launch_json = fn ->
        ctx.base |> Records.dir() |> Path.join("launch.json") |> File.read!() |> JSON.decode!()
      end

      set_mode = fn mode ->
        {:ok, {:ok, _}} =
          DB.transaction(
            ctx.db,
            &Settings.set_in_txn(&1, @host, "mode", mode, "user:owner", 16 * @gib)
          )

        :ok = MemoryGuard.settings_changed(@host)
      end

      set_mode.("off")
      assert %{"mode" => "off"} = launch_json.()

      env =
        MemoryGuard.launch_env(
          {:claude, "shared", @host},
          "L-off",
          [cmd: ["/x/.bin/claude-agent-acp"], env: [{"CLAUDE_CODE_EXECUTABLE", "/x/claude"}]],
          ctx.db
        )

      assert {"CLAUDE_CODE_EXECUTABLE", step} = List.keyfind(env, "CLAUDE_CODE_EXECUTABLE", 0)
      assert step == Records.step_path(ctx.base)

      assert {"TIGHTBEAM_SESSION_EXEC_TARGET", "/x/claude"} =
               List.keyfind(env, "TIGHTBEAM_SESSION_EXEC_TARGET", 0)

      # The step reads the mode at each session launch: it passes through under
      # `off` (cli/tests/memory_guard_step.rs) and acts once it reads `watched`.
      set_mode.("auto")
      assert %{"mode" => "watched"} = launch_json.()
    end

    test "(e) mode off: nothing acts", ctx do
      meminfo!(ctx.root, 16 * @gib, 1 * @gib)
      guard!(ctx)

      {:ok, {:ok, _}} =
        DB.transaction(
          ctx.db,
          &Settings.set_in_txn(&1, @host, "mode", "off", "user:owner", 16 * @gib)
        )

      :ok = MemoryGuard.settings_changed(@host)
      :ok = MemoryGuard.tick()

      session!(ctx, "agent:off")
      queue!(ctx, "agent:off", "runs")
      assert :ok = MemoryGuard.admit("agent:off")
      assert MemoryGuard.read(@host).mode == "off"

      # The step stays installed under `off` and passes the harness through
      # untouched (FS2); nothing places the adapter in a unit.
      env =
        MemoryGuard.launch_env(
          {:claude, "shared", @host},
          "L",
          [cmd: ["/x/.bin/claude-agent-acp"], env: []],
          ctx.db
        )

      refute List.keymember?(env, "TIGHTBEAM_ADAPTER_CGROUP", 0)

      assert HeldState.read(ctx.db, Org.get(ctx.db, "agent:off")) == nil
      refute_received {:closed, _, _}
      refute_received {:killed, _}
    end

    test "E1.absent (T25 c, R12a as amended): an unreadable process table disables R1 and R2 only, once per run, never count-only; meminfo going too disables R5",
         ctx do
      meminfo!(ctx.root, 16 * @gib, 12 * @gib)
      guard!(ctx)
      File.rm_rf!(Path.join(ctx.root, "proc"))
      File.mkdir_p!(ctx.root)
      # meminfo is gone with /proc; the tree read fails too.
      :ok = MemoryGuard.tick()
      :ok = MemoryGuard.tick()
      read = MemoryGuard.read(@host)
      assert read.mode == "watched"

      assert Enum.sort(Enum.map(read.unavailable, &{&1.reading, &1.disables})) == [
               {"meminfo", ["R5"]},
               {"tree", ["R1", "R2"]}
             ]

      failed = events(ctx.db, "memory_guard_sampling_failed")
      assert Enum.sort(for {_, d} <- failed, do: d["reading"]) == ["meminfo", "tree"]

      File.mkdir_p!(Path.join(ctx.root, "proc"))
      meminfo!(ctx.root, 16 * @gib, 12 * @gib)
      :ok = MemoryGuard.tick()
      read = MemoryGuard.read(@host)
      assert read.mode == "watched"
      assert read.unavailable == []
    end
  end

  ## R3 / R4 / R6 / T4, T5: resident cap and idle close

  describe "resident cap (R3, R4, R6, T4, T5)" do
    setup ctx do
      meminfo!(ctx.root, 16 * @gib, 12 * @gib)
      guard!(ctx)

      {:ok, {:ok, _}} =
        DB.transaction(
          ctx.db,
          &Settings.set_in_txn(&1, @host, "residentCap", "3", "user:owner", 16 * @gib)
        )

      :ok = MemoryGuard.settings_changed(@host)
      adapter = adapter!()
      for n <- 1..3, do: session!(ctx, "agent:s#{n}", "sid-#{n}")
      resident!(adapter, ["sid-1", "sid-2", "sid-3"])
      %{adapter: adapter}
    end

    test "T4: a fourth session's turn closes the LRU idle process and runs; with all busy it is held, then runs when a slot frees",
         ctx do
      # s1 is the least recently used; s2 and s3 are busy.
      for key <- ["agent:s2", "agent:s3"] do
        queue!(ctx, key, "working")
        assert :ok = MemoryGuard.admit(key)
      end

      session!(ctx, "agent:s4")
      queue!(ctx, "agent:s4", "fourth")
      assert :ok = MemoryGuard.admit("agent:s4")
      assert_receive {:closed, "sid-1", "resident_cap"}

      assert [{"agent:s1", %{"reason" => "resident_cap", "sessionId" => "sid-1"}}] =
               events(ctx.db, "memory_guard_idle_closed")

      # s4 now holds a slot (reserved until its process is resident).
      resident!(ctx.adapter, ["sid-2", "sid-3", "sid-4"])
      Org.append_pointer(ctx.db, "agent:s4", "sid-4", "created")

      # All three busy: the fifth is held, queued, unclaimed.
      session!(ctx, "agent:s5")
      seq5 = queue!(ctx, "agent:s5", "fifth")
      session!(ctx, "agent:s6")
      seq6 = queue!(ctx, "agent:s6", "sixth")
      assert {:held, ["resident_cap"]} = MemoryGuard.admit("agent:s5")
      assert {:held, ["resident_cap"]} = MemoryGuard.admit("agent:s6")

      assert {:ok, [["queued"], ["queued"]]} =
               DB.query(ctx.db, "SELECT status FROM turns WHERE seq IN (?1,?2)", [seq5, seq6])

      # R7: the held state is visible with its release condition.
      assert %{reasonClass: "host_capacity", reasons: [reason]} =
               HeldState.read(ctx.db, Org.get(ctx.db, "agent:s5"))

      assert %{detail: "resident_cap", host: @host, condition: condition, since: since} = reason
      assert condition =~ "one of 3 agent processes on #{@host} becomes free"
      assert is_integer(since)

      assert HeldState.sender_result(HeldState.read(ctx.db, Org.get(ctx.db, "agent:s5"))) ==
               "recipient held (host_capacity)"

      # s2's turn ends: the held lanes are nudged, oldest first.
      {:ok, _} =
        DB.query(ctx.db, "UPDATE turns SET status='delivered' WHERE seq=?1", [
          seq_of(ctx.db, "agent:s2")
        ])

      MemoryGuard.turn_finished("agent:s2")
      _ = :sys.get_state(MemoryGuard)
      assert_received {:nudged, "agent:s5"}

      # The younger turn does not jump the older one.
      assert {:held, ["resident_cap"]} = MemoryGuard.admit("agent:s6")
      assert :ok = MemoryGuard.admit("agent:s5")
      assert_receive {:closed, "sid-2", "resident_cap"}

      assert Enum.map(events(ctx.db, "admission_resumed"), &elem(&1, 0)) == ["agent:s5"]
    end

    test "T5: a session with an observed unfinished background task is never closed", ctx do
      GenServer.call(ctx.adapter, {:set_busy, ["sid-1", "sid-2", "sid-3"]})
      session!(ctx, "agent:s4")
      queue!(ctx, "agent:s4", "fourth")
      assert {:held, ["resident_cap"]} = MemoryGuard.admit("agent:s4")
      refute_received {:closed, _, _}
      assert events(ctx.db, "memory_guard_idle_closed") == []
    end

    test "R17a: lowering residentCap below the resident count closes idle processes only", ctx do
      queue!(ctx, "agent:s3", "working")
      assert :ok = MemoryGuard.admit("agent:s3")

      {:ok, {:ok, _}} =
        DB.transaction(
          ctx.db,
          &Settings.set_in_txn(&1, @host, "residentCap", "1", "user:owner", 16 * @gib)
        )

      :ok = MemoryGuard.settings_changed(@host)
      assert_receive {:closed, first, "resident_cap"}
      assert_receive {:closed, second, "resident_cap"}
      settle_closes!()
      assert Enum.sort([first, second]) == ["sid-1", "sid-2"]
      # The working one finishes; nothing more closes.
      MemoryGuard.turn_finished("agent:none")
      _ = :sys.get_state(MemoryGuard)
      refute_received {:closed, "sid-3", _}

      # host-memory, the supported read (R12b), shows it.
      assert %{residentCount: 1, settings: %{residentCap: 1}} =
               Gateway.handlers(%{db: ctx.db, base_dir: ctx.base})["host-memory"].(%{
                 origin: "agent:any",
                 params: %{host: @host}
               })
    end

    test "T5 variant (v1.6 R4 residual): with no async-task updates, an idle close says background shell tasks were ended, once",
         ctx do
      start_supervised!({Tightbeam.ConnRegistry, name: Tightbeam.ConnRegistry})
      refute Tightbeam.Acp.Adapter.async_tasks_observed?()

      # s1's last turn left a run_in_background shell task running; nothing
      # reports it on this line, so s1 counts as idle.
      for key <- ["agent:s2", "agent:s3"] do
        queue!(ctx, key, "working")
        assert :ok = MemoryGuard.admit(key)
      end

      session!(ctx, "agent:s4")
      queue!(ctx, "agent:s4", "fourth")
      assert :ok = MemoryGuard.admit("agent:s4")
      assert_receive {:closed, "sid-1", "resident_cap"}

      assert [{"agent:s1", %{"residual" => residual, "reason" => "resident_cap"}}] =
               events(ctx.db, "memory_guard_idle_closed")

      assert residual == "any background shell task this session had left running was ended"

      assert {:ok, [[text]]} =
               DB.query(
                 ctx.db,
                 "SELECT content FROM messages WHERE sessionKey='agent:s1' AND content LIKE 'To free memory%'"
               )

      assert text =~ "Any background shell task you had left running was ended"

      # Its next turn needs a fresh session process (residency is gone).
      refute MapSet.member?(
               :sys.get_state(MemoryGuard).adapters |> Map.values() |> hd() |> Map.get(:sids),
               "sid-1"
             )
    end

    test "R4: a session with a queued or running turn is not idle", ctx do
      for n <- 1..3, do: queue!(ctx, "agent:s#{n}", "pending")
      session!(ctx, "agent:s4")
      queue!(ctx, "agent:s4", "fourth")
      assert {:held, ["resident_cap"]} = MemoryGuard.admit("agent:s4")
      refute_received {:closed, _, _}
    end

    test "a resident session's turn needs no launch and is never held", ctx do
      for n <- 2..3,
          do: assert(:ok = MemoryGuard.admit("agent:s#{n}" |> tap(&queue!(ctx, &1, "w"))))

      queue!(ctx, "agent:s1", "resident turn")
      assert :ok = MemoryGuard.admit("agent:s1")
    end
  end

  # The guard has handled every finished close.
  defp settle_closes!(attempts \\ 200) do
    cond do
      :sys.get_state(MemoryGuard).closing == %{} -> :ok
      attempts == 0 -> flunk("a close never finished")
      true -> Process.sleep(10) && settle_closes!(attempts - 1)
    end
  end

  ## v1.4 R3a / R3b / R7 / T16-T21: priority and the reserved slot

  describe "priority and the reserved slot (v1.4 R3a, R3b, R7, T16-T21)" do
    # The setup's first user, "owner", is this gateway's founding user, so its
    # Main is the reserved Main; "guest"'s Main is another user's Main.
    setup ctx do
      # "owner" was created first; make that order strict.
      {:ok, _} =
        DB.query(ctx.db, "UPDATE users SET createdAt = createdAt + 1000 WHERE userId <> 'owner'")

      meminfo!(ctx.root, 16 * @gib, 12 * @gib)
      start_supervised!({Tightbeam.ConnRegistry, name: Tightbeam.ConnRegistry})
      guard!(ctx)
      set_cap!(ctx, 3)
      %{adapter: adapter!()}
    end

    defp set_cap!(ctx, cap) do
      {:ok, {:ok, _}} =
        DB.transaction(
          ctx.db,
          &Settings.set_in_txn(
            &1,
            @host,
            "residentCap",
            Integer.to_string(cap),
            "user:owner",
            16 * @gib
          )
        )

      :ok = MemoryGuard.settings_changed(@host)
    end

    defp main!(ctx, user, sid \\ nil) do
      key = Org.personal_session_key(user)

      Org.create(ctx.db, %{
        session_key: key,
        display_name: "Main",
        kind: "main",
        is_built_in: true,
        owner_user_id: user,
        origin: "user:" <> user,
        archetype: "coder",
        host: @host,
        harness: "claude",
        provider: "anthropic",
        model: Tightbeam.Model.new("claude-sonnet-5", effort: "medium")
      })

      if sid, do: Org.append_pointer(ctx.db, key, sid, "created")
      key
    end

    defp post!(ctx, key, origin, text) do
      {:ok, seq} =
        Ledger.enqueue(ctx.db, %{
          session_key: key,
          message_id: "m-#{key}-#{text}-#{System.unique_integer([:positive])}",
          origin: origin,
          prompt: text
        })

      seq
    end

    # Three resident sessions, each with a turn running (busy).
    defp full_cap!(ctx, adapter, n \\ 3) do
      keys = for i <- 1..n, do: session!(ctx, "agent:busy-#{i}", "sid-busy-#{i}")
      resident!(adapter, Enum.map(1..n, &"sid-busy-#{&1}"))

      for key <- keys do
        post!(ctx, key, "agent:boss", "working")
        assert :ok = MemoryGuard.admit(key)
      end

      keys
    end

    # A busy session's turn ends: its process is idle and closable.
    defp finish!(ctx, key) do
      {:ok, _} =
        DB.query(ctx.db, "UPDATE turns SET status='delivered' WHERE sessionKey=?1", [key])

      MemoryGuard.turn_finished(key)
      _ = :sys.get_state(MemoryGuard)
    end

    test "T16: at each free slot a Main, then a user-facing session, then workers oldest first; never past a standing reason",
         ctx do
      [b1, b2, b3] = full_cap!(ctx, ctx.adapter)

      w1 = session!(ctx, "agent:w1")
      post!(ctx, w1, "agent:boss", "w1")
      assert {:held, ["resident_cap"]} = MemoryGuard.admit(w1)
      w2 = session!(ctx, "agent:w2")
      post!(ctx, w2, "agent:boss", "w2")
      assert {:held, ["resident_cap"]} = MemoryGuard.admit(w2)
      m = main!(ctx, "guest")
      post!(ctx, m, "user:guest", "m")
      assert {:held, ["resident_cap"]} = MemoryGuard.admit(m)
      u = session!(ctx, "agent:u")
      post!(ctx, u, "user:owner", "u")
      assert {:held, ["resident_cap"]} = MemoryGuard.admit(u)

      # No working session was ended or closed to make room.
      refute_received {:closed, _, _}

      # R7: class and place in line.
      assert %{reasons: [%{priorityClass: "main", placeInLine: 1}]} =
               HeldState.read(ctx.db, Org.get(ctx.db, m))

      assert %{reasons: [%{priorityClass: "user-facing", placeInLine: 2}]} =
               HeldState.read(ctx.db, Org.get(ctx.db, u))

      assert %{reasons: [%{priorityClass: "worker", placeInLine: 3}]} =
               HeldState.read(ctx.db, Org.get(ctx.db, w1))

      # Each freed slot: every still-waiting lane asks (youngest first, to show
      # arrival order does not decide); exactly one, the first in line, runs.
      {admitted, _} =
        Enum.map_reduce([b1, b2, b3], [w2, w1, u, m], fn busy, waiting ->
          finish!(ctx, busy)
          results = for key <- waiting, into: %{}, do: {key, MemoryGuard.admit(key)}
          assert_receive {:closed, _, "resident_cap"}
          settle_closes!()
          assert [winner] = for(key <- waiting, results[key] == :ok, do: key)
          {winner, waiting -- [winner]}
        end)

      assert admitted == [m, u, w1]
    end

    test "T16 variant: a waiter with another standing reason is not admitted past it; the next in line is",
         ctx do
      [b1 | _] = full_cap!(ctx, ctx.adapter)
      m = main!(ctx, "guest")
      post!(ctx, m, "user:guest", "m")
      assert {:held, ["resident_cap"]} = MemoryGuard.admit(m)
      u = session!(ctx, "agent:u")
      post!(ctx, u, "user:owner", "u")
      assert {:held, ["resident_cap"]} = MemoryGuard.admit(u)

      # M is held by another standing reason (an open limit-fallback hold).
      {:ok, _} =
        DB.query(
          ctx.db,
          "INSERT INTO limit_fallback_evaluations (sessionKey, turnSeq, heldAt, createdAt) VALUES (?1, ?2, 1, 1)",
          [m, oldest!(ctx, m)]
        )

      finish!(ctx, b1)
      assert :ok = MemoryGuard.admit(u)
      assert_receive {:closed, "sid-busy-1", "resident_cap"}
    end

    test "T17: idle workers close first, then user-facing, then an idle Main last", ctx do
      a = session!(ctx, "agent:worker-a", "sid-a")
      b = session!(ctx, "agent:facing-b", "sid-b")
      m = main!(ctx, "guest", "sid-m")
      resident!(ctx.adapter, ["sid-m", "sid-b", "sid-a"])
      # B has a staged user post: user-facing, but its process is idle.
      stage_user_post!(ctx, b)
      _ = {a, m}

      for {n, expected} <- [{1, "sid-a"}, {2, "sid-b"}, {3, "sid-m"}] do
        key = session!(ctx, "agent:needs-#{n}")
        post!(ctx, key, "agent:boss", "go")
        assert :ok = MemoryGuard.admit(key)
        assert_receive {:closed, ^expected, "resident_cap"}
        settle_closes!()
      end
    end

    test "T17 variant: R3 never closes the reserved Main; under the floor it closes last", ctx do
      reserved = main!(ctx, "owner", "sid-r")
      w = session!(ctx, "agent:idle-w", "sid-w")
      resident!(ctx.adapter, ["sid-r", "sid-w"])
      _ = {reserved, w}
      set_cap!(ctx, 1)

      n1 = session!(ctx, "agent:new-1")
      post!(ctx, n1, "agent:boss", "go")
      assert :ok = MemoryGuard.admit(n1)
      assert_receive {:closed, "sid-w", "resident_cap"}
      settle_closes!()
      resident!(ctx.adapter, ["sid-r", "sid-n1"])
      Org.append_pointer(ctx.db, n1, "sid-n1", "created")
      post!(ctx, n1, "agent:boss", "busy")
      MemoryGuard.admit(n1)

      n2 = session!(ctx, "agent:new-2")
      post!(ctx, n2, "agent:boss", "go")
      assert {:held, ["resident_cap"]} = MemoryGuard.admit(n2)
      refute_received {:closed, "sid-r", _}

      # The floor: the reserved Main is shed only after every idle worker.
      finish!(ctx, n1)
      meminfo!(ctx.root, 16 * @gib, div(16 * @gib, 10))
      :ok = MemoryGuard.tick()
      assert_receive {:closed, "sid-n1", "memory_floor"}
      settle_closes!()
      resident!(ctx.adapter, ["sid-r"])
      :ok = MemoryGuard.tick()
      assert_receive {:closed, "sid-r", "memory_floor"}
    end

    test "T19: the reserved Main starts at once in the reserved slot with all cap slots busy; the floor still holds it",
         ctx do
      full_cap!(ctx, ctx.adapter)
      w = session!(ctx, "agent:waiting-w")
      post!(ctx, w, "agent:boss", "w")
      assert {:held, ["resident_cap"]} = MemoryGuard.admit(w)

      m = main!(ctx, "owner")
      post!(ctx, m, "user:owner", "hello")
      assert :ok = MemoryGuard.admit(m)
      refute_received {:closed, _, _}

      Org.append_pointer(ctx.db, m, "sid-main", "created")
      resident!(ctx.adapter, ["sid-busy-1", "sid-busy-2", "sid-busy-3", "sid-main"])
      assert {:held, ["resident_cap"]} = MemoryGuard.admit(w)

      read = MemoryGuard.read(@host)
      assert read.residentCount == 3
      assert read.reservedSlot.inUse

      assert read.reservedSlot.summary ==
               "resident: 3 of 3, plus owner's Main in its reserved slot"

      # Variant: under the floor the reserved Main is held by memory_floor, never resident_cap.
      resident!(ctx.adapter, ["sid-busy-1", "sid-busy-2", "sid-busy-3"])
      meminfo!(ctx.root, 16 * @gib, div(16 * @gib, 10))
      :ok = MemoryGuard.tick()
      post!(ctx, m, "user:owner", "again")
      MemoryGuard.turn_finished(m)
      assert {:held, ["memory_floor"]} = MemoryGuard.admit(m)

      assert %{reasons: [%{detail: "memory_floor", priorityClass: "main", placeInLine: 1}]} =
               HeldState.read(ctx.db, Org.get(ctx.db, m))
    end

    test "T20: only the reserved Main uses the slot, even when it is empty; with a cap slot free it still takes the reserve",
         ctx do
      set_cap!(ctx, 2)
      full_cap!(ctx, ctx.adapter, 2)
      w = session!(ctx, "agent:w")
      post!(ctx, w, "agent:boss", "w")
      u = session!(ctx, "agent:u")
      post!(ctx, u, "user:owner", "u")
      m2 = main!(ctx, "guest")
      post!(ctx, m2, "user:guest", "m2")

      for key <- [w, u, m2], do: assert({:held, ["resident_cap"]} = MemoryGuard.admit(key))
      assert MemoryGuard.read(@host).reservedSlot.inUse == false

      # The reserved Main becomes resident and goes idle: still nobody else's.
      m = main!(ctx, "owner", "sid-main")
      resident!(ctx.adapter, ["sid-busy-1", "sid-busy-2", "sid-main"])
      for key <- [w, u, m2], do: assert({:held, ["resident_cap"]} = MemoryGuard.admit(key))
      refute_received {:closed, "sid-main", _}

      # Cap slots free: M2, then U, then W.
      {order, _} =
        Enum.map_reduce(["agent:busy-1", "agent:busy-2"], [w, u, m2], fn busy, waiting ->
          finish!(ctx, busy)
          results = for key <- waiting, into: %{}, do: {key, MemoryGuard.admit(key)}
          assert_receive {:closed, closed, "resident_cap"}
          refute closed == "sid-main"
          settle_closes!()
          assert [winner] = for(key <- waiting, results[key] == :ok, do: key)
          {winner, waiting -- [winner]}
        end)

      assert order == [m2, u]

      # With a cap slot free, M still takes the reserved slot.
      resident!(ctx.adapter, [])
      post!(ctx, m, "user:owner", "hello")
      assert :ok = MemoryGuard.admit(m)
      assert %{reserved: true} = :sys.get_state(MemoryGuard).reservations[m]
    end

    test "T21: only the founding user's Main has the slot; an admin's Main waits; with the founder gone the slot stays empty",
         ctx do
      Devices.add_user(ctx.db, "synthetic-admin", true)
      full_cap!(ctx, ctx.adapter)

      # (a) another user's Main arrives first and waits; the founder's starts at once.
      m2 = main!(ctx, "guest")
      post!(ctx, m2, "user:guest", "first")
      assert {:held, ["resident_cap"]} = MemoryGuard.admit(m2)
      m = main!(ctx, "owner")
      post!(ctx, m, "user:owner", "second")
      assert :ok = MemoryGuard.admit(m)

      # (b) admin standing gives no claim to the slot.
      admin = main!(ctx, "synthetic-admin")
      post!(ctx, admin, "user:synthetic-admin", "admin")
      assert {:held, ["resident_cap"]} = MemoryGuard.admit(admin)

      # (c) the founder is gone: no reserved Main, and nobody inherits the slot.
      {:ok, _} = DB.query(ctx.db, "DELETE FROM devices WHERE userId='owner'")
      {:ok, _} = DB.query(ctx.db, "DELETE FROM users WHERE userId='owner'")
      MemoryGuard.turn_finished(m)
      assert {:held, ["resident_cap"]} = MemoryGuard.admit(m2)
      assert {:held, ["resident_cap"]} = MemoryGuard.admit(admin)
      assert MemoryGuard.read(@host).reservedSlot.reservedMain == nil
      assert MemoryGuard.read(@host).reservedSlot.summary =~ "there is no reserved Main"
    end

    test "T18: only gateway-recorded user origins make a session user-facing; a held user post gets one marker",
         ctx do
      full_cap!(ctx, ctx.adapter)

      # (a) a session's own post, even claiming a user, is agent-originated.
      a = session!(ctx, "agent:posted-by-agent")
      post!(ctx, a, "agent:agent:worker", "as-user george")
      assert Tightbeam.MemoryGuard.Priority.class(ctx.db, Org.get(ctx.db, a)) == "worker"

      # (b) a worker naming itself main is not Main.
      b = session!(ctx, "agent:main:clawline:owner:main-lookalike")

      {:ok, _} =
        DB.query(
          ctx.db,
          "UPDATE sessions SET displayName='main', archetype='main' WHERE sessionKey=?1",
          [b]
        )

      post!(ctx, b, "agent:boss", "x")
      assert Tightbeam.MemoryGuard.Priority.class(ctx.db, Org.get(ctx.db, b)) == "worker"

      # (c) George posts from his device while the cap is full.
      w = session!(ctx, "agent:worker-w")
      post!(ctx, w, "agent:boss", "w")
      assert {:held, _} = MemoryGuard.admit(w)
      c = session!(ctx, "agent:talked-to")
      post!(ctx, c, "user:owner", "hi")
      assert {:held, ["resident_cap"]} = MemoryGuard.admit(c)
      assert {:held, ["resident_cap"]} = MemoryGuard.admit(c)

      assert %{reasons: [%{priorityClass: "user-facing", placeInLine: 1}]} =
               HeldState.read(ctx.db, Org.get(ctx.db, c))

      assert [{^c, %{"detail" => "resident_cap", "placeInLine" => 1}}] =
               events(ctx.db, "memory_guard_waiting")

      assert [[text]] = markers(ctx.db, c)
      assert text =~ "Waiting for a free agent slot on #{@host}: all 3 are busy with other work."
      assert text =~ "You are first in line, and nothing was stopped to make room."
      # The worker's agent-originated hold posts no marker.
      assert markers(ctx.db, w) == []
    end
  end

  defp free!(ctx), do: meminfo!(ctx.root, 16 * @gib, div(16 * @gib * 16, 100))

  defp hold_other!(ctx, :park, _seq, true) do
    {:ok, _} =
      DB.query(
        ctx.db,
        "INSERT INTO harness_park_fences (adapterKey, requestedAt, generation) VALUES ('claude:shared@testhost', 1, 1)"
      )
  end

  defp hold_other!(ctx, :park, _seq, false),
    do: {:ok, _} = DB.query(ctx.db, "DELETE FROM harness_park_fences")

  defp hold_other!(ctx, :fallback, seq, true) do
    {:ok, _} =
      DB.query(
        ctx.db,
        "INSERT INTO limit_fallback_evaluations (sessionKey, turnSeq, heldAt, createdAt) VALUES ('agent:load', ?1, 1, 1)",
        [seq]
      )
  end

  defp hold_other!(ctx, :fallback, _seq, false),
    do:
      {:ok, _} =
        DB.query(
          ctx.db,
          "UPDATE limit_fallback_evaluations SET outcome='withheld', reason='test', decidedAt=2"
        )

  defp oldest!(ctx, key) do
    {:ok, [[seq]]} =
      DB.query(
        ctx.db,
        "SELECT seq FROM turns WHERE sessionKey=?1 AND status='queued' ORDER BY seq LIMIT 1",
        [key]
      )

    seq
  end

  defp stage_user_post!(ctx, key) do
    {:ok, _} =
      DB.query(
        ctx.db,
        "INSERT INTO wakes (wakeId, sessionKey, origin, prompt, dueAt, createdAt) VALUES (?1, ?2, 'user:owner', 'staged', 0, 0)",
        ["w-staged-#{System.unique_integer([:positive])}", key]
      )
  end

  defp markers(db, key) do
    {:ok, rows} =
      DB.query(
        db,
        "SELECT content FROM messages WHERE sessionKey=?1 AND content LIKE 'Waiting for%' ORDER BY seq",
        [key]
      )

    rows
  end

  defp seq_of(db, key) do
    {:ok, [[seq]]} =
      DB.query(db, "SELECT seq FROM turns WHERE sessionKey=?1 ORDER BY seq DESC LIMIT 1", [key])

    seq
  end

  ## R5 / R13 / T6: the host floor

  describe "floor (R5, R6, R7, R13, T6)" do
    test "below 12% launches are held and idle processes close one at a time; 13% holds; 15% releases in order",
         ctx do
      total = 16 * @gib
      meminfo!(ctx.root, total, div(total * 10, 100))
      guard!(ctx)
      adapter = adapter!()
      session!(ctx, "agent:idle-a", "sid-a")
      session!(ctx, "agent:idle-b", "sid-b")
      session!(ctx, "agent:busy", "sid-busy")
      resident!(adapter, ["sid-a", "sid-b", "sid-busy"])
      queue!(ctx, "agent:busy", "resident work")
      assert :ok = MemoryGuard.admit("agent:busy")

      :ok = MemoryGuard.tick()
      assert MemoryGuard.read(@host).floorHolds
      assert_receive {:closed, first, "memory_floor"}
      settle_closes!()
      refute_received {:closed, _, _}

      session!(ctx, "agent:new-1")
      session!(ctx, "agent:new-2")
      seq1 = queue!(ctx, "agent:new-1", "first held")
      seq2 = queue!(ctx, "agent:new-2", "second held")
      assert {:held, ["memory_floor"]} = MemoryGuard.admit("agent:new-1")
      assert {:held, ["memory_floor"]} = MemoryGuard.admit("agent:new-2")
      assert seq1 < seq2

      # A resident session's turn needs no launch: R5 never holds it.
      queue!(ctx, "agent:busy", "more resident work")
      assert :ok = MemoryGuard.admit("agent:busy")

      %{reasons: [reason]} = HeldState.read(ctx.db, Org.get(ctx.db, "agent:new-1"))
      assert %{reasonClass: "host_capacity", detail: "memory_floor", host: @host} = reason
      assert reason.condition == "starts when #{@host} has 15% of memory free; now 10.0%"

      # The next sample closes the other idle process, one at a time.
      settle_closes!()
      resident!(adapter, ["sid-a", "sid-b", "sid-busy"] -- [first])
      :ok = MemoryGuard.tick()
      assert_receive {:closed, second, "memory_floor"}
      assert Enum.sort([first, second]) == ["sid-a", "sid-b"]

      meminfo!(ctx.root, total, div(total * 13, 100))
      :ok = MemoryGuard.tick()
      assert MemoryGuard.read(@host).floorHolds
      assert {:held, ["memory_floor"]} = MemoryGuard.admit("agent:new-1")

      # 15% (meminfo counts kB, so exactly 15% of a GiB-sized host truncates
      # to just under it; the boundary is a hair above).
      meminfo!(ctx.root, total, div(total * 1501, 10_000))
      :ok = MemoryGuard.tick()
      refute MemoryGuard.read(@host).floorHolds

      assert [{@host, %{"detail" => "memory_floor", "remaining" => []}}] =
               events(ctx.db, "memory_guard_release")

      # Nudged oldest first; each is admitted.
      assert_received {:nudged, "agent:new-1"}
      assert_received {:nudged, "agent:new-2"}
      assert :ok = MemoryGuard.admit("agent:new-1")
      assert :ok = MemoryGuard.admit("agent:new-2")
    end

    # R13 says "above twice" earlyoom's 6%; §7's default and rationale say
    # "twice" (12%). The default is the table's 12%.
    test "R13: the default floor is twice earlyoom's 6% SIGTERM level, with hysteresis above it" do
      settings = Settings.effective(%{}, 32 * @gib)
      assert settings.floor_hold == 2 * 6
      assert settings.floor_release > settings.floor_hold
    end
  end

  ## R1 / R2 / R10a / T3: limits in watched mode

  describe "limits in watched mode (R1, R2, R10a, T3)" do
    test "R1: a session tree over its limit is ended whole, the intent recorded first", ctx do
      meminfo!(ctx.root, 16 * @gib, 12 * @gib)
      # Session process 600, a tool two levels down (601 -> 602).
      proc!(ctx.root, 600, 1, 11, 100 * @mib)
      proc!(ctx.root, 601, 600, 12, 10 * @mib)
      proc!(ctx.root, 602, 601, 13, 600 * @mib)
      proc!(ctx.root, 700, 1, 21, 200 * @mib)
      launch!(ctx.base, "sl-a", "sid-a", 600, 11, 512 * @mib)
      launch!(ctx.base, "sl-b", "sid-b", 700, 21, 512 * @mib)
      guard!(ctx)
      session!(ctx, "agent:a", "sid-a")

      :ok = MemoryGuard.tick()

      assert_receive {:killed,
                      %{scope: "session", pid: 600, launch_id: "sl-a", identity: identity}}

      assert identity =~ "sl-a.identity"
      refute_received {:killed, _}
      settle_kills!()

      assert [{@host, intent}] = events(ctx.db, "memory_kill_intent")
      assert %{"limit" => "session", "scope" => "session", "sessionId" => "sid-a"} = intent
      assert intent["bytes"] == 710 * @mib
      assert [{"agent:a", %{"limit" => "session"}}] = events(ctx.db, "memory_tree_ended")

      assert %{limit: "session", scope: "session", bytes: bytes} =
               MemoryGuard.memory_kill(%{host: @host, harness_session_id: "sid-a", since: 0})

      assert bytes == 710 * @mib
      assert MemoryGuard.memory_kill(%{host: @host, harness_session_id: "sid-b", since: 0}) == nil
    end

    test "D1.unreadable (B3, FS6): a sent kill that does not end its tree is never published as ended, is recorded as failed and retried; the turn it hit is still memory_limit (the kill was sent)",
         ctx do
      meminfo!(ctx.root, 16 * @gib, 12 * @gib)
      proc!(ctx.root, 640, 1, 41, 900 * @mib)
      launch!(ctx.base, "sl-f", "sid-f", 640, 41, 512 * @mib)
      guard!(ctx, kill_result: {:error, :harness_group_failed}, signal_works: false)
      session!(ctx, "agent:f", "sid-f")

      :ok = MemoryGuard.tick()
      assert_receive {:killed, %{pid: 640}}
      # The intent is recorded before the signal (R10a) ...
      assert [{@host, %{"sessionId" => "sid-f"}}] = events(ctx.db, "memory_kill_intent")
      settle_kills!()

      # ... nothing claims the tree ended ...
      assert events(ctx.db, "memory_tree_ended") == []

      assert [{@host, %{"sessionId" => "sid-f", "error" => error}}] =
               events(ctx.db, "memory_kill_failed")

      assert error =~ "tree_survives"

      # ... and settlement attributes the kill, because it was sent (FS6).
      assert %{limit: "session", scope: "session"} =
               MemoryGuard.memory_kill(%{host: @host, harness_session_id: "sid-f", since: 0})

      # It is still over its limit, so the next sample tries again.
      :ok = MemoryGuard.tick()
      assert_receive {:killed, %{pid: 640}}
      settle_kills!()
    end

    test "T3: at 90% of the budget launches hold and an idle process closes; past the budget exactly one growing tree ends; below 85% holds release",
         ctx do
      meminfo!(ctx.root, 16 * @gib, 12 * @gib)
      guard!(ctx)

      {:ok, {:ok, _}} =
        DB.transaction(
          ctx.db,
          &Settings.set_in_txn(&1, @host, "budget", "2G", "user:owner", 16 * @gib)
        )

      {:ok, {:ok, _}} =
        DB.transaction(
          ctx.db,
          &Settings.set_in_txn(&1, @host, "sessionLimit", "2G", "user:owner", 16 * @gib)
        )

      # The cap is not what this test is about.
      {:ok, {:ok, _}} =
        DB.transaction(
          ctx.db,
          &Settings.set_in_txn(&1, @host, "residentCap", "10", "user:owner", 16 * @gib)
        )

      :ok = MemoryGuard.settings_changed(@host)
      adapter = adapter!()
      session!(ctx, "agent:grow-1", "sid-g1")
      session!(ctx, "agent:grow-2", "sid-g2")
      session!(ctx, "agent:idle", "sid-i")
      resident!(adapter, ["sid-g1", "sid-g2", "sid-i"])

      for key <- ["agent:grow-1", "agent:grow-2"],
          do: queue!(ctx, key, "growing") && MemoryGuard.admit(key)

      grow = fn a, b ->
        proc!(ctx.root, 800, 1, 31, a)
        proc!(ctx.root, 810, 1, 41, b)
        proc!(ctx.root, 820, 1, 51, 10 * @mib)
      end

      launch!(ctx.base, "sl-g1", "sid-g1", 800, 31, 2 * @gib)
      launch!(ctx.base, "sl-g2", "sid-g2", 810, 41, 2 * @gib)
      launch!(ctx.base, "sl-i", "sid-i", 820, 51, 2 * @gib)

      # 1.84 GiB of 2 GiB: at 92%.
      grow.(900 * @mib, 975 * @mib)
      :ok = MemoryGuard.tick()
      assert MemoryGuard.read(@host).budgetHolds
      assert_receive {:closed, "sid-i", "memory_budget"}
      refute_received {:killed, _}

      session!(ctx, "agent:waiting")
      queue!(ctx, "agent:waiting", "needs a launch")
      assert {:held, ["memory_budget"]} = MemoryGuard.admit("agent:waiting")

      # Past the budget: exactly one, the larger, ends whole.
      grow.(1000 * @mib, 1100 * @mib)
      :ok = MemoryGuard.tick()
      assert_receive {:killed, %{scope: "session", pid: 810}}
      refute_received {:killed, _}

      assert [{@host, %{"limit" => "budget", "sessionId" => "sid-g2"}}] =
               events(ctx.db, "memory_kill_intent")

      # The killed tree is gone; the total falls below 85%.
      gone!(ctx.root, 810)
      grow_after = fn -> proc!(ctx.root, 800, 1, 31, 1000 * @mib) end
      grow_after.()
      send(MemoryGuard, {:killed, "session:sl-g2", :ok})
      :ok = MemoryGuard.tick()
      refute MemoryGuard.read(@host).budgetHolds
      assert_received {:nudged, "agent:waiting"}
      assert :ok = MemoryGuard.admit("agent:waiting")
      refute_received {:killed, _}
    end

    test "R2 ranking: a session tree is credited 10% of the budget, so it goes before a slightly larger adapter tree",
         ctx do
      meminfo!(ctx.root, 16 * @gib, 12 * @gib)
      guard!(ctx)

      {:ok, {:ok, _}} =
        DB.transaction(
          ctx.db,
          &Settings.set_in_txn(&1, @host, "budget", "2G", "user:owner", 16 * @gib)
        )

      {:ok, {:ok, _}} =
        DB.transaction(
          ctx.db,
          &Settings.set_in_txn(&1, @host, "sessionLimit", "2G", "user:owner", 16 * @gib)
        )

      :ok = MemoryGuard.settings_changed(@host)

      # An adapter (pid 900) with one session child (pid 901, setsid'ed).
      insert_adapter_row!(ctx.db, "adapter-launch-1", 900)
      proc!(ctx.root, 900, 1, 61, 1100 * @mib)
      proc!(ctx.root, 901, 900, 62, 1000 * @mib)
      launch!(ctx.base, "sl-s", "sid-s", 901, 62, 2 * @gib)

      :ok = MemoryGuard.tick()
      assert_receive {:killed, %{scope: "session", pid: 901}}
      refute_received {:killed, _}
    end
  end

  defp enforced_probe do
    %{
      mode: :enforced,
      reason: nil,
      mem_total: 16 * @gib,
      cgroup: %{
        root: "/svc/tightbeam.service",
        gateway: "/svc/tightbeam.service/gateway",
        move_self: false
      }
    }
  end

  # An enforced host with one live session unit and its launch record; returns
  # the budget group's directory, the unit's, and a mode setter.
  defp enforced_with_unit!(ctx) do
    meminfo!(ctx.root, 16 * @gib, 12 * @gib)
    fs = cgroup_tree!(ctx.root, "/svc/tightbeam.service/gateway", [])
    guard!(ctx, probe: enforced_probe(), cgroup_fs: fs)
    harness = Path.join(fs, "svc/tightbeam.service/harness")
    unit = Path.join(harness, "session-live")
    File.mkdir_p!(unit)

    for {f, v} <- [
          {"memory.max", "536870912"},
          {"memory.swap.max", "0"},
          {"memory.oom.group", "1"},
          {"memory.current", "0"}
        ],
        do: File.write!(Path.join(unit, f), v)

    File.write!(Path.join(harness, "memory.current"), "0")
    dir = Path.join(Records.dir(ctx.base), "sessions")
    File.mkdir_p!(dir)

    File.write!(
      Path.join(dir, "sl-live.json"),
      JSON.encode!(%{
        v: 1,
        launchId: "sl-live",
        sessionId: "live",
        pid: 1,
        start: 1,
        placement: "enforced",
        unit: "/svc/tightbeam.service/harness/session-live",
        sessionLimit: 536_870_912
      })
    )

    set_mode = fn mode ->
      {:ok, {:ok, _}} =
        DB.transaction(
          ctx.db,
          &Settings.set_in_txn(&1, @host, "mode", mode, "user:owner", 16 * @gib)
        )

      MemoryGuard.settings_changed(@host)
    end

    {harness, unit, set_mode}
  end

  defp insert_adapter_row!(db, launch_id, os_pid, harness \\ "claude") do
    {:ok, _} =
      DB.transaction(db, fn txn ->
        DB.Txn.q(
          txn,
          """
          INSERT INTO harness_processes
            (launchId, adapterKey, harness, preset, host, ssh, helperPath, identityPath,
             launchSequence, osPid, processGroupId, bootIdentity, identityToken, state, createdAt)
          VALUES (?1, ?4 || ':shared@testhost', ?4, 'shared', 'testhost', NULL, '/bin/false',
                  '/nonexistent', (SELECT COALESCE(MAX(launchSequence),0)+1 FROM harness_processes),
                  ?2, ?2, 'boot', ?1, 'running', ?3)
          """,
          [launch_id, os_pid, System.system_time(:millisecond), harness]
        )
      end)

    :ok
  end

  ## R2a / T15 (guard half): an adapter's end ends its session trees first

  describe "adapter end (R2a, M-V7)" do
    test "every session tree of the ended launch is ended before adapter_ended returns; residency is forgotten",
         ctx do
      meminfo!(ctx.root, 16 * @gib, 12 * @gib)
      guard!(ctx)
      adapter = adapter!()
      insert_adapter_row!(ctx.db, "adapter-launch-1", 950)

      for {sid, pid} <- [{"sid-a", 951}, {"sid-b", 952}, {"sid-d", 953}] do
        proc!(ctx.root, pid, 950, pid, 10 * @mib)
        launch!(ctx.base, "sl-" <> sid, sid, pid, pid, 512 * @mib)
      end

      # A session of another launch of the same key is not touched.
      launch!(ctx.base, "sl-other", "sid-other", 960, 960, 512 * @mib, "adapter-launch-2")
      resident!(adapter, ["sid-a", "sid-b", "sid-d"])

      :ok = MemoryGuard.adapter_ended({:claude, "shared", @host}, "adapter-launch-1")

      killed = for _ <- 1..3, do: assert_receive({:killed, %{scope: "session", pid: pid}}) && pid
      assert Enum.sort(killed) == [951, 952, 953]
      refute_received {:killed, _}

      # Residency is cleared for each (the adapter is told when it is still up).
      _ = :sys.get_state(MemoryGuard)
      Process.sleep(50)
      for sid <- ["sid-a", "sid-b", "sid-d"], do: assert_received({:forgot, ^sid})

      remaining = Records.read_all(ctx.base) |> elem(1) |> Map.keys()
      assert remaining == ["sl-other"]
    end
  end

  describe "adapter end failures (R2a, review B1)" do
    setup ctx do
      meminfo!(ctx.root, 16 * @gib, 12 * @gib)
      insert_adapter_row!(ctx.db, "adapter-launch-1", 950)
      proc!(ctx.root, 951, 950, 951, 10 * @mib)
      launch!(ctx.base, "sl-a", "sid-a", 951, 951, 512 * @mib)
      :ok
    end

    test "a failed group kill keeps the record, says the tree survives and refuses the replacement",
         ctx do
      # The helper fails while the tree lives and, like `harness-group` on an
      # empty group, succeeds once it has gone.
      guard!(ctx,
        kill_result: fn _target ->
          if File.dir?(Path.join(ctx.root, "proc/951")),
            do: {:error, :harness_group_failed},
            else: :ok
        end,
        signal_works: false
      )

      assert {:error, {:session_trees_survive, ["sl-a"]}} =
               MemoryGuard.adapter_ended({:claude, "shared", @host}, "adapter-launch-1")

      assert Map.keys(elem(Records.read_all(ctx.base), 1)) == ["sl-a"]

      assert [{@host, %{"survivors" => [%{"launchId" => "sl-a"}]}}] =
               events(ctx.db, "memory_guard_orphans")

      # The pre-launch backstop refuses while the tree lives ...
      {:ok, _} = DB.query(ctx.db, "UPDATE harness_processes SET state='exited'")
      assert {:error, _} = MemoryGuard.ensure_no_orphans({:claude, "shared", @host})

      # ... and allows the launch once it has ended.
      gone!(ctx.root, 951)
      assert :ok = MemoryGuard.ensure_no_orphans({:claude, "shared", @host})
      assert Records.read_all(ctx.base) == {:ok, %{}}
    end

    test "a missing identity with the recorded process alive is ended through its parent chain",
         ctx do
      File.rm!(Path.join([Records.dir(ctx.base), "sessions", "sl-a.identity"]))
      proc!(ctx.root, 952, 951, 952, 10 * @mib)
      guard!(ctx, kill_result: {:error, :identity_missing})

      assert :ok = MemoryGuard.adapter_ended({:claude, "shared", @host}, "adapter-launch-1")
      assert_received {:signalled, [951, 952]}
      assert Records.read_all(ctx.base) == {:ok, %{}}
    end

    test "(review R2) a helper that reports a captured survivor is not overruled by the root's end",
         ctx do
      proc!(ctx.root, 952, 951, 952, 10 * @mib)

      guard!(ctx,
        kill_result: fn _target ->
          gone!(ctx.root, 951)
          {:error, {:harness_group_failed, 1, "captured process 952 outlived SIGKILL"}}
        end,
        signal_works: false
      )

      assert {:error, {:session_trees_survive, ["sl-a"]}} =
               MemoryGuard.adapter_ended({:claude, "shared", @host}, "adapter-launch-1")

      # The captured descendant is signalled by its own identity, the root
      # having gone, and the custody record stays.
      assert_received {:signalled, [952]}
      assert Map.keys(elem(Records.read_all(ctx.base), 1)) == ["sl-a"]
      assert events(ctx.db, "memory_tree_ended") == []
    end

    test "(review R2) a helper error stands even when every process this read sees is gone",
         ctx do
      proc!(ctx.root, 952, 951, 952, 10 * @mib)

      # An escaped descendant the helper captured is invisible to the parent
      # chain: only the helper's verdict knows it.
      guard!(ctx,
        kill_result: fn _target ->
          gone!(ctx.root, 951)
          gone!(ctx.root, 952)
          {:error, {:harness_group_failed, 1, "captured process 4242 outlived SIGKILL"}}
        end
      )

      assert {:error, {:session_trees_survive, ["sl-a"]}} =
               MemoryGuard.adapter_ended({:claude, "shared", @host}, "adapter-launch-1")

      assert [{@host, %{"survivors" => [%{"error" => error}]}}] =
               events(ctx.db, "memory_guard_orphans")

      assert error =~ "kill_incomplete"
      assert Map.keys(elem(Records.read_all(ctx.base), 1)) == ["sl-a"]
    end

    test "(review R1) an expected guard that is not running refuses; one restarting is waited for; none configured passes",
         ctx do
      key = {:claude, "shared", @host}
      Application.put_env(:tightbeam, :memory_guard_restart_wait_ms, 200)

      on_exit(fn ->
        Application.delete_env(:tightbeam, :memory_guard_restart_wait_ms)
        MemoryGuard.expect(false)
      end)

      MemoryGuard.expect(false)
      assert :ok = MemoryGuard.ensure_no_orphans(key)
      assert :ok = MemoryGuard.adapter_ended(key, "adapter-launch-1")

      MemoryGuard.expect(true)

      assert {:error, {:memory_guard_unavailable, :not_running}} =
               MemoryGuard.ensure_no_orphans(key)

      assert {:error, {:memory_guard_unavailable, :not_running}} =
               MemoryGuard.adapter_ended(key, "adapter-launch-1")

      # Nothing was ended in its absence.
      assert Map.keys(elem(Records.read_all(ctx.base), 1)) == ["sl-a"]

      # A guard that comes back within the wait answers the call itself.
      Application.put_env(:tightbeam, :memory_guard_restart_wait_ms, 5_000)
      task = Task.async(fn -> MemoryGuard.adapter_ended(key, "adapter-launch-1") end)
      Process.sleep(200)
      guard!(ctx)
      assert :ok = Task.await(task, 10_000)
      assert_received {:killed, %{scope: "session", pid: 951}}
      assert Records.read_all(ctx.base) == {:ok, %{}}
    end

    test "(review R1 siblings) an expected guard that is down refuses an unplaced launch and stands as a reason for deferred hooks",
         ctx do
      local = Tightbeam.Placement.local_host_name()
      key = {:claude, "shared", local}
      opts = [cmd: ["/bin/claude-acp"], env: []]
      on_exit(fn -> MemoryGuard.expect(false) end)

      MemoryGuard.expect(false)
      assert MemoryGuard.launch_env(key, "L-down", opts, ctx.db) == []
      assert MemoryGuard.host_reasons(local) == []

      MemoryGuard.expect(true)

      assert {:error, :memory_guard_unavailable} =
               MemoryGuard.launch_env(key, "L-down", opts, ctx.db)

      # A satellite launch is not the guard's to place.
      assert MemoryGuard.launch_env(key, "L-down", [process_ssh: "sat"] ++ opts, ctx.db) == []
      assert MemoryGuard.host_reasons(local) == ["memory_guard_unavailable"]

      # A quota release meanwhile defers its hook rather than running it.
      assert {:ok, :deferred} =
               DB.transaction(
                 ctx.db,
                 &Admission.quota_released_in_txn(&1, "incident-down", "claude", local)
               )

      assert [{"incident-down", %{"remaining" => ["memory_guard_unavailable"]}}] =
               events(ctx.db, "admission_hold_remaining")
    end

    test "B2.partial / B3.partial / B2.unreadable / B3.unreadable (T33): a launch record that cannot be read or listed keeps the fence and holds launches guard_unavailable",
         ctx do
      guard!(ctx)
      key = {:claude, "shared", @host}
      dir = Path.join(Records.dir(ctx.base), "sessions")
      bad = Path.join(dir, "sl-bad.json")
      File.write!(bad, "{not json")
      on_exit(fn -> File.chmod(dir, 0o755) end)

      assert {:error, {:custody_unreadable, error}} =
               MemoryGuard.adapter_ended(key, "adapter-launch-1")

      assert error =~ "sl-bad.json"
      refute_received {:killed, _}
      assert File.exists?(Path.join(dir, "sl-a.json"))

      {:ok, _} = DB.query(ctx.db, "UPDATE harness_processes SET state='exited'")
      assert {:error, {:custody_unreadable, _}} = MemoryGuard.ensure_no_orphans(key)

      :ok = MemoryGuard.tick()
      read = MemoryGuard.read(@host)
      # Tightbeam's own records are not a host reading: no degradation, a hold.
      assert read.mode == "watched"
      assert read.unavailable == []
      assert read.recordsUnreadable =~ "sl-bad.json"
      assert [{@host, %{"error" => _}}] = events(ctx.db, "memory_guard_inventory_failed")
      session!(ctx, "agent:new", "sid-new")
      queue!(ctx, "agent:new", "needs a launch")
      assert {:held, ["guard_unavailable"]} = MemoryGuard.admit("agent:new", ctx.db)

      File.rm!(bad)
      File.chmod!(dir, 0o000)
      assert {:error, {:custody_unreadable, error}} = MemoryGuard.ensure_no_orphans(key)
      assert error =~ "inventory cannot be read"
      refute_received {:killed, _}

      assert {:held, ["guard_unavailable"]} = MemoryGuard.admit("agent:new", ctx.db)

      File.chmod!(dir, 0o755)
      assert :ok = MemoryGuard.ensure_no_orphans(key)
      assert_received {:killed, %{scope: "session", pid: 951}}
      assert Records.read_all(ctx.base) == {:ok, %{}}
      assert :ok = MemoryGuard.admit("agent:new", ctx.db)
    end

    test "a guard that cannot answer refuses the launch rather than allowing it", ctx do
      guard!(ctx)
      Application.put_env(:tightbeam, :memory_guard_call_timeout_ms, 500)
      on_exit(fn -> Application.delete_env(:tightbeam, :memory_guard_call_timeout_ms) end)
      :sys.suspend(MemoryGuard)

      try do
        task = Task.async(fn -> MemoryGuard.ensure_no_orphans({:claude, "shared", @host}) end)
        assert {:error, {:memory_guard_unavailable, _}} = Task.await(task, 5_000)
      after
        :sys.resume(MemoryGuard)
      end
    end
  end

  ## v1.13 §6.1 FS1 cells (matrix v4 group A, row F8)

  describe "matrix A / F8: the guard down (FS1)" do
    setup ctx do
      meminfo!(ctx.root, 16 * @gib, 12 * @gib)
      Application.put_env(:tightbeam, :memory_guard_restart_wait_ms, 50)

      on_exit(fn ->
        Application.delete_env(:tightbeam, :memory_guard_restart_wait_ms)
        Application.delete_env(:tightbeam, :memory_guard_admit_timeout_ms)
        MemoryGuard.expect(false)
      end)

      session!(ctx, "agent:new", "sid-new")
      queue!(ctx, "agent:new", "needs a launch")
      :ok
    end

    defp guard_down!, do: MemoryGuard.expect(true)

    defp holds(ctx, key) do
      for {^key, detail} <- events(ctx.db, "memory_guard_hold"), do: detail
    end

    test "A1.unreadable (T22): a non-resident turn is held guard_unavailable, shown, and never admitted by a time-out",
         ctx do
      guard_down!()

      assert {:held, ["guard_unavailable"]} = MemoryGuard.admit("agent:new", ctx.db)
      Process.sleep(120)
      assert {:held, ["guard_unavailable"]} = MemoryGuard.admit("agent:new", ctx.db)

      # One hold, recorded once (FS7), and shown on the held-state read (R7).
      assert [%{"detail" => "guard_unavailable", "host" => @host}] = holds(ctx, "agent:new")

      assert %{reasons: [%{reasonClass: "host_capacity", detail: "guard_unavailable"} = reason]} =
               HeldState.read(ctx.db, Org.get(ctx.db, "agent:new"))

      assert reason.condition =~ "memory guard"
    end

    test "A1.unreadable (T22): a resident session's turn runs while the guard is down", ctx do
      guard_down!()

      assert :ok =
               Unguarded.admit(ctx.db, "agent:new",
                 live_adapter: fn _key -> self() end,
                 resident?: fn _adapter, "sid-new" -> true end
               )

      assert holds(ctx, "agent:new") == []
    end

    test "A1.timeout: a guard that does not answer the admission check holds the launch", ctx do
      guard!(ctx)
      Application.put_env(:tightbeam, :memory_guard_admit_timeout_ms, 200)
      :sys.suspend(MemoryGuard)

      try do
        assert {:held, ["guard_unavailable"]} = MemoryGuard.admit("agent:new", ctx.db)
      after
        :sys.resume(MemoryGuard)
      end
    end

    test "A1 release (T22): when the guard answers again, every guard_unavailable hold is released and its lane nudged",
         ctx do
      guard_down!()
      assert {:held, ["guard_unavailable"]} = MemoryGuard.admit("agent:new", ctx.db)

      guard!(ctx)
      assert_receive {:nudged, "agent:new"}

      assert [{"agent:new", %{"detail" => "guard_unavailable", "because" => "guard_answers"}}] =
               events(ctx.db, "memory_guard_release")

      assert Unguarded.open_hold(ctx.db, "agent:new") == nil
    end

    test "A1 / F8.absent (T22 B): on a host with no kernel limit, off comes into force without the guard; a launch onto a live adapter runs, a new adapter stays held",
         ctx do
      guard_down!()
      assert {:held, _} = MemoryGuard.admit("agent:new", ctx.db)
      fs = Path.join(ctx.root, "sys/fs/cgroup")
      File.mkdir_p!(fs)

      assert :in_force =
               Unguarded.bring_off_into_force(ctx.db, @host, ctx.base,
                 cgroup_fs: fs,
                 harness_candidates: fn -> {:ok, ["/svc/tightbeam.service/harness"]} end
               )

      assert Unguarded.mode_in_force(ctx.db, @host) == "off"

      assert %{"mode" => "off"} =
               JSON.decode!(File.read!(Path.join(Records.dir(ctx.base), "launch.json")))

      # A new adapter is still not launched while the guard is down (R2a).
      assert {:held, ["guard_unavailable"]} =
               Unguarded.admit(ctx.db, "agent:new", live_adapter: fn _ -> nil end)

      assert :ok =
               Unguarded.admit(ctx.db, "agent:new",
                 live_adapter: fn _ -> self() end,
                 resident?: fn _, _ -> false end
               )

      assert [{"agent:new", %{"because" => "off"}}] = events(ctx.db, "memory_guard_release")
    end

    defp limited_harness!(ctx, unit_values) do
      fs = Path.join(ctx.root, "sys/fs/cgroup")
      harness = Path.join(fs, "svc/tightbeam.service/harness")
      File.mkdir_p!(harness)

      for {f, v} <- [{"memory.max", "max"}, {"memory.swap.max", "max"}, {"memory.oom.group", "0"}],
          do: File.write!(Path.join(harness, f), v)

      unit = Path.join(harness, "session-x")
      File.mkdir_p!(unit)
      for {f, v} <- unit_values, do: File.write!(Path.join(unit, f), v)
      {fs, unit}
    end

    defp off_without_guard(ctx, fs) do
      Unguarded.bring_off_into_force(ctx.db, @host, ctx.base,
        cgroup_fs: fs,
        harness_candidates: fn -> {:ok, ["/svc/tightbeam.service/harness"]} end
      )
    end

    test "A1 (T22 A) / F8.partial: kernel limits still on a unit: off is requested, not applied, and the launch stays held",
         ctx do
      guard_down!()

      {fs, _unit} =
        limited_harness!(ctx, [
          {"memory.max", "536870912"},
          {"memory.swap.max", "0"},
          {"memory.oom.group", "1"}
        ])

      assert {:not_applied, why} = off_without_guard(ctx, fs)
      assert why =~ "session-x"
      assert Unguarded.mode_in_force(ctx.db, @host) == nil

      assert {:held, ["guard_unavailable"]} =
               Unguarded.admit(ctx.db, "agent:new",
                 live_adapter: fn _ -> self() end,
                 resident?: fn _, _ -> false end
               )
    end

    test "F8.unreadable: a unit file that cannot be read, or an unreadable own cgroup, is no evidence",
         ctx do
      {fs, unit} =
        limited_harness!(ctx, [
          {"memory.max", "max"},
          {"memory.swap.max", "max"},
          {"memory.oom.group", "0"}
        ])

      file = Path.join(unit, "memory.max")
      File.chmod!(file, 0o000)
      on_exit(fn -> File.chmod(file, 0o644) end)
      assert {:not_applied, _} = off_without_guard(ctx, fs)

      assert {:not_applied, why} =
               Unguarded.bring_off_into_force(ctx.db, @host, ctx.base,
                 cgroup_fs: fs,
                 harness_candidates: fn -> :error end
               )

      assert why =~ "own cgroup"
    end

    test "F8.stale (T22 C): a transition recorded incomplete is no evidence, whatever the files read",
         ctx do
      fs = Path.join(ctx.root, "sys/fs/cgroup")
      File.mkdir_p!(fs)

      EventLog.lifecycle(
        ctx.db,
        "memory_guard_mode",
        @host,
        JSON.encode!(%{
          host: @host,
          mode: "watched",
          transition: "the session limits could not all be restored"
        })
      )

      assert {:not_applied, why} = off_without_guard(ctx, fs)
      assert why =~ "still incomplete"
      assert Unguarded.mode_in_force(ctx.db, @host) == nil
    end

    test "A3.unreadable / F6.absent: a session launch whose launch step is not in place is held guard_unavailable; under off it runs",
         ctx do
      guard!(ctx, cli_bin: nil)
      assert {:held, ["guard_unavailable"]} = MemoryGuard.admit("agent:new", ctx.db)

      assert %{reasons: [%{detail: "guard_unavailable"}]} =
               HeldState.read(ctx.db, Org.get(ctx.db, "agent:new"))

      {:ok, {:ok, _}} =
        DB.transaction(
          ctx.db,
          &Settings.set_in_txn(&1, @host, "mode", "off", "user:owner", 16 * @gib)
        )

      :ok = MemoryGuard.settings_changed(@host)
      assert :ok = MemoryGuard.admit("agent:new", ctx.db)
    end

    test "A6.unreadable: the host read says the guard is not running, never a mode", ctx do
      guard_down!()

      assert %{code: "memory_guard_unavailable"} =
               Gateway.handlers(%{db: ctx.db, base_dir: ctx.base})["host-memory"].(%{
                 origin: "user:owner",
                 params: %{host: @host}
               })
    end

    test "A7.unreadable: a setting stored while the guard is down says it is not yet applied; off on a host with no kernel limit comes into force",
         ctx do
      guard_down!()
      session!(ctx, "agent:admin-session")
      set = Gateway.handlers(%{db: ctx.db, base_dir: ctx.base})["host-memory-set"]
      call = &%{origin: "user:owner", principal: {:session, "agent:admin-session"}, params: &1}

      assert set.(call.(%{host: @host, name: "residentCap", value: "4"})).effect =~
               "NOT yet applied"

      # The test host is not the gateway's own, so it can carry no kernel limit.
      assert set.(call.(%{host: @host, name: "mode", value: "off"})).effect =~ "in force"
      assert Unguarded.mode_in_force(ctx.db, @host) == "off"
    end
  end

  ## v1.13 FS4 scope: Tightbeam's own inventories (matrix B2–B4, E4; T33)

  describe "matrix B: owned inventories (FS4 scope, T33)" do
    setup ctx do
      meminfo!(ctx.root, 16 * @gib, 12 * @gib)
      session!(ctx, "agent:new", "sid-new")
      queue!(ctx, "agent:new", "needs a launch")
      %{sessions: Path.join(Records.dir(ctx.base), "sessions")}
    end

    defp boot!(ctx, id) do
      dir = Path.join(ctx.root, "proc/sys/kernel/random")
      File.mkdir_p!(dir)
      File.write!(Path.join(dir, "boot_id"), id <> "\n")
    end

    test "B2.absent (first start): no inventory yet is an empty one, durably initialized", ctx do
      boot!(ctx, "boot-a")
      guard!(ctx)
      :ok = MemoryGuard.tick()

      assert [{_, %{"boot" => "boot-a", "generation" => generation}}] =
               events(ctx.db, "memory_guard_inventory")

      assert File.read!(Path.join(ctx.sessions, ".generation")) == generation
      assert MemoryGuard.read(@host).recordsUnreadable == nil
      assert :ok = MemoryGuard.adapter_ended({:claude, "shared", @host}, "L")
      assert :ok = MemoryGuard.admit("agent:new", ctx.db)
    end

    test "B2.absent / B3.absent (T33): an inventory lost on this boot holds launches and leaves the R2a fence unresolved",
         ctx do
      boot!(ctx, "boot-a")
      guard!(ctx)
      :ok = MemoryGuard.tick()
      File.rm_rf!(ctx.sessions)
      :ok = MemoryGuard.tick()

      assert MemoryGuard.read(@host).recordsUnreadable =~ "missing"
      assert {:held, ["guard_unavailable"]} = MemoryGuard.admit("agent:new", ctx.db)

      assert {:error, {:custody_unreadable, _}} =
               MemoryGuard.ensure_no_orphans({:claude, "shared", @host})

      # An empty directory without its generation marker is not the inventory.
      File.mkdir_p!(ctx.sessions)
      :ok = MemoryGuard.tick()
      assert MemoryGuard.read(@host).recordsUnreadable =~ "missing"
      assert {:held, ["guard_unavailable"]} = MemoryGuard.admit("agent:new", ctx.db)
      assert [_] = events(ctx.db, "memory_guard_inventory_failed")
    end

    test "B2.absent after a reboot: a new boot identity re-initializes the inventory as empty (FS9: a reboot ends every process)",
         ctx do
      boot!(ctx, "boot-a")
      guard!(ctx)
      :ok = MemoryGuard.tick()
      stop_supervised!(MemoryGuard)
      File.rm_rf!(ctx.sessions)

      boot!(ctx, "boot-b")
      guard!(ctx)
      :ok = MemoryGuard.tick()

      assert MemoryGuard.read(@host).recordsUnreadable == nil
      assert [_, {_, %{"boot" => "boot-b"}}] = events(ctx.db, "memory_guard_inventory")
      assert :ok = MemoryGuard.admit("agent:new", ctx.db)
    end

    test "B4.absent: returning to enforced with the inventory lost is not applied", ctx do
      {_harness, _unit, set_mode} = enforced_with_unit!(ctx)
      :ok = MemoryGuard.tick()
      assert :ok = set_mode.("off")
      File.rm_rf!(ctx.sessions)

      assert {:error, {:not_applied, error}} = set_mode.("auto")
      assert error =~ "inventory"
      assert MemoryGuard.read(@host).mode == "watched"
    end
  end

  ## v1.13 FS4: one failed host reading disables only what needs it (T25)

  describe "matrix C2 / C3 / E3 / E5: host readings (FS4, T25)" do
    test "E3.unreadable (T25 c): an unreadable process of ours inside a tree disables R1 and R2, nothing else",
         ctx do
      meminfo!(ctx.root, 16 * @gib, 12 * @gib)
      guard!(ctx)
      proc!(ctx.root, 981, 1, 981, 100 * @mib)
      proc!(ctx.root, 982, 981, 982, 100 * @mib)
      launch!(ctx.base, "sl-r", "sid-r", 981, 981, 512 * @mib)
      stat = Path.join(ctx.root, "proc/982/stat")
      on_exit(fn -> File.chmod(stat, 0o644) end)

      :ok = MemoryGuard.tick()
      assert MemoryGuard.read(@host).unavailable == []

      File.chmod!(stat, 0o000)
      :ok = MemoryGuard.tick()
      read = MemoryGuard.read(@host)
      assert read.mode == "watched"
      assert [%{reading: "tree", disables: ["R1", "R2"]}] = read.unavailable
      assert read.hostAvailablePercent == 75.0
    end

    test "C2.unreadable (T25 a): an unreadable budget-group total disables R2's approach only; its hold clears, the kernel budget stays",
         ctx do
      meminfo!(ctx.root, 16 * @gib, 12 * @gib)
      fs = cgroup_tree!(ctx.root, "/svc/tightbeam.service/gateway", [])
      guard!(ctx, probe: enforced_probe(), cgroup_fs: fs)

      {:ok, {:ok, _}} =
        DB.transaction(
          ctx.db,
          &Settings.set_in_txn(&1, @host, "budget", "2G", "user:owner", 16 * @gib)
        )

      :ok = MemoryGuard.settings_changed(@host)
      harness = Path.join(fs, "svc/tightbeam.service/harness")
      current = Path.join(harness, "memory.current")
      File.write!(current, Integer.to_string(1900 * @mib))
      on_exit(fn -> File.chmod(current, 0o644) end)
      :ok = MemoryGuard.tick()
      assert MemoryGuard.host_reasons(@host) == ["memory_budget"]

      File.chmod!(current, 0o000)
      :ok = MemoryGuard.tick()
      read = MemoryGuard.read(@host)
      assert read.mode == "enforced"
      assert [%{reading: "budget_total", disables: ["R2 approach"]}] = read.unavailable
      assert read.budgetHolds == false
      assert MemoryGuard.host_reasons(@host) == []

      assert [{@host, %{"detail" => "memory_budget", "because" => _}}] =
               events(ctx.db, "memory_guard_release")

      # The kernel's budget is untouched.
      assert File.read!(Path.join(harness, "memory.max")) == Integer.to_string(2 * @gib)
    end

    test "E5.unreadable (T25 b): meminfo failing at runtime disables R5 and its floor reason counts as clear",
         ctx do
      meminfo!(ctx.root, 16 * @gib, div(16 * @gib * 10, 100))
      guard!(ctx)
      :ok = MemoryGuard.tick()
      assert MemoryGuard.host_reasons(@host) == ["memory_floor"]

      File.rm!(Path.join(ctx.root, "proc/meminfo"))
      :ok = MemoryGuard.tick()
      read = MemoryGuard.read(@host)
      assert read.mode == "watched"
      assert [%{reading: "meminfo", disables: ["R5"]}] = read.unavailable
      assert read.floorHolds == false
      assert read.hostAvailablePercent == nil
      assert MemoryGuard.host_reasons(@host) == []

      assert [{@host, %{"detail" => "memory_floor", "because" => _}}] =
               events(ctx.db, "memory_guard_release")
    end

    test "C3.unreadable: an enforced unit's own counter that cannot be read fails nothing and is never counted 0",
         ctx do
      {harness, unit, _set_mode} = enforced_with_unit!(ctx)
      File.write!(Path.join(harness, "memory.current"), Integer.to_string(300 * @mib))
      counter = Path.join(unit, "memory.current")
      File.chmod!(counter, 0o000)
      on_exit(fn -> File.chmod(counter, 0o644) end)

      :ok = MemoryGuard.tick()
      read = MemoryGuard.read(@host)
      assert read.mode == "enforced"
      assert read.unavailable == []
      assert read.tightbeamTotalBytes == 300 * @mib
      assert events(ctx.db, "memory_guard_sampling_failed") == []
    end
  end

  ## v1.13 FS2 / R14 (matrix B5, C8, J3; the step's own cells are in cli/tests)

  describe "matrix B5 / C8 / J3: the launch step (FS2, R14)" do
    test "B5.stale / F6: the guard publishes the step's configuration in every mode, off included",
         ctx do
      meminfo!(ctx.root, 16 * @gib, 12 * @gib)
      guard!(ctx)
      config = fn -> JSON.decode!(File.read!(Path.join(Records.dir(ctx.base), "launch.json"))) end
      assert %{"v" => 1, "mode" => "watched"} = config.()

      {:ok, {:ok, _}} =
        DB.transaction(
          ctx.db,
          &Settings.set_in_txn(&1, @host, "mode", "off", "user:owner", 16 * @gib)
        )

      :ok = MemoryGuard.settings_changed(@host)
      assert %{"v" => 1, "mode" => "off"} = config.()
    end

    test "C8.absent: a session tree the step could not place in its unit on an enforced host is recorded once",
         ctx do
      {_harness, _unit, _set_mode} = enforced_with_unit!(ctx)
      dir = Path.join(Records.dir(ctx.base), "sessions")

      File.write!(
        Path.join(dir, "sl-out.json"),
        JSON.encode!(%{
          v: 1,
          launchId: "sl-out",
          sessionId: "out",
          pid: 2,
          start: 2,
          placement: "watched",
          unit: nil,
          errors: [
            "session unit /svc/tightbeam.service/harness/session-out could not be created: eacces"
          ],
          sessionLimit: 536_870_912
        })
      )

      :ok = MemoryGuard.tick()
      :ok = MemoryGuard.tick()

      assert [{@host, %{"launchId" => "sl-out", "scope" => "session", "error" => error}}] =
               events(ctx.db, "memory_guard_launch_unplaced")

      assert error =~ "could not be created"
      assert MemoryGuard.read(@host).mode == "enforced"
    end

    test "J3.unreadable: the read shows oom_score_adj values that cannot be read as unknown, never a substituted value",
         ctx do
      meminfo!(ctx.root, 16 * @gib, 12 * @gib)
      guard!(ctx)

      assert MemoryGuard.read(@host).oomScoreAdj == %{
               gatewayAndAdapters: nil,
               sessionProcesses: nil
             }

      File.mkdir_p!(Path.join(ctx.root, "proc/self"))
      File.write!(Path.join(ctx.root, "proc/self/oom_score_adj"), "950\n")

      assert MemoryGuard.read(@host).oomScoreAdj == %{
               gatewayAndAdapters: 950,
               sessionProcesses: 1000
             }
    end
  end

  ## v1.13 R4 / FS5: the idle proof and the conditional close (matrix K, D3; T26)

  describe "matrix K / D3: idle close (R4, FS5, T26)" do
    setup ctx do
      # The floor holds, so the guard sheds idle session processes one at a time.
      meminfo!(ctx.root, 16 * @gib, div(16 * @gib * 10, 100))
      adapter = adapter!()
      session!(ctx, "agent:idle", "sid-idle")
      %{adapter: adapter, test_pid: self()}
    end

    defp shed!(ctx, opts \\ []) do
      guard!(ctx, opts)
      resident!(ctx.adapter, ["sid-idle"])
      :ok = MemoryGuard.tick()
      _ = :sys.get_state(MemoryGuard)
    end

    test "K1.unreadable: turns that cannot be read are not idle; no close, recorded", ctx do
      {:ok, _} = DB.query(ctx.db, "ALTER TABLE turns RENAME TO turns_hidden")

      try do
        shed!(ctx)
        refute_received {:closed, _, _}

        assert [{@host, %{"sessionId" => "sid-idle", "why" => why}}] =
                 events(ctx.db, "memory_guard_idle_unproven")

        assert why =~ "turns cannot be read"
      after
        {:ok, _} = DB.query(ctx.db, "ALTER TABLE turns_hidden RENAME TO turns")
      end
    end

    test "K2.absent: a resident process with no session for it is not idle; no close, recorded",
         ctx do
      {:ok, _} =
        DB.query(ctx.db, "DELETE FROM harness_pointers WHERE harnessSessionId='sid-idle'")

      shed!(ctx)
      refute_received {:closed, _, _}

      assert [{_, %{"why" => "no session for the harness session"}}] =
               events(ctx.db, "memory_guard_idle_unproven")
    end

    test "K2.unreadable: an unreadable session pointer is not idle", ctx do
      {:ok, _} = DB.query(ctx.db, "ALTER TABLE harness_pointers RENAME TO hp_hidden")

      try do
        shed!(ctx)
        refute_received {:closed, _, _}
        assert [{_, %{"why" => why}}] = events(ctx.db, "memory_guard_idle_unproven")
        assert why =~ "pointer cannot be read"
      after
        {:ok, _} = DB.query(ctx.db, "ALTER TABLE hp_hidden RENAME TO harness_pointers")
      end
    end

    test "K4.unreadable: a session whose priority class cannot be read is not closed", ctx do
      {:ok, _} = DB.query(ctx.db, "ALTER TABLE wakes RENAME TO wakes_hidden")

      try do
        shed!(ctx)
        refute_received {:closed, _, _}
        assert [{_, %{"why" => why}}] = events(ctx.db, "memory_guard_idle_unproven")
        assert why =~ "priority cannot be read"
      after
        {:ok, _} = DB.query(ctx.db, "ALTER TABLE wakes_hidden RENAME TO wakes")
      end
    end

    test "K3.unreadable / K3.timeout: an adapter that cannot answer is not idle; nothing closes, nothing is a failure",
         ctx do
      shed!(ctx, idle_check: fn _adapter, _sid -> {:error, {:adapter_unavailable, :timeout}} end)
      settle_closes!()
      refute_received {:closed, _, _}
      assert events(ctx.db, "memory_guard_idle_closed") == []
      assert events(ctx.db, "memory_guard_close_failed") == []
    end

    test "K7 (before the commit): a turn enqueued after the idle read and before the closing transaction commits stops the close",
         ctx do
      test = self()

      shed!(ctx,
        before_close_commit: fn "agent:idle" ->
          seq = queue!(ctx, "agent:idle", "arrived just now")
          send(test, {:enqueued, seq})
        end
      )

      assert_received {:enqueued, _}
      settle_closes!()
      refute_received {:closed, _, _}
      assert events(ctx.db, "memory_guard_closing") == []
      assert events(ctx.db, "memory_guard_idle_closed") == []
    end

    test "K7 (after the commit) / K6: a turn enqueued after the closing transaction waits for the close, then starts fresh",
         ctx do
      test = self()

      shed!(ctx,
        closer: fn _adapter, sid, reason ->
          # The close has been decided; new work arrives before it is written.
          send(test, {:enqueued, queue!(ctx, "agent:idle", "arrived after the mark")})
          send(test, {:closed, sid, reason})
          closed_process!(ctx, sid)
        end
      )

      assert_receive {:closed, "sid-idle", "memory_floor"}
      assert_received {:enqueued, _}
      settle_closes!()
      assert [{"agent:idle", _}] = events(ctx.db, "memory_guard_closing")
      assert [{"agent:idle", _}] = events(ctx.db, "memory_guard_idle_closed")
      # Its next turn needs a fresh process, held now only by the floor.
      assert {:held, ["memory_floor"]} = MemoryGuard.admit("agent:idle", ctx.db)
    end

    test "K8 / K3.stale: a prompt the adapter takes after the guard's idle read makes its close-if-idle refuse; no close, no event, no marker",
         ctx do
      shed!(ctx,
        closer: fn _adapter, sid, reason ->
          send(ctx.test_pid, {:asked, sid, reason})
          {:error, {:not_idle, :busy}}
        end
      )

      assert_receive {:asked, "sid-idle", "memory_floor"}
      settle_closes!()
      assert events(ctx.db, "memory_guard_idle_closed") == []
      assert events(ctx.db, "memory_guard_idle_closed_marker") == []
      assert events(ctx.db, "memory_guard_close_failed") == []
      assert MemoryGuard.read(@host).residentCount == 1
    end

    test "K5.unreadable / D3.partial (T26): a close acknowledged while the process lives leaves it resident and counted, recorded, and retried until it is gone",
         ctx do
      proc!(ctx.root, 990, 1, 990, 100 * @mib)
      launch!(ctx.base, "sl-idle", "sid-idle", 990, 990, 512 * @mib)

      shed!(ctx,
        closer: fn _adapter, sid, reason ->
          send(ctx.test_pid, {:closed, sid, reason})
          :ok
        end
      )

      assert_receive {:closed, "sid-idle", _}
      settle_closes!()

      assert [{"agent:idle", %{"error" => error}}] = events(ctx.db, "memory_guard_close_failed")
      assert error =~ "still running"
      assert events(ctx.db, "memory_guard_idle_closed") == []
      assert events(ctx.db, "memory_guard_idle_closed_marker") == []

      # The adapter forgot it, but it still counts as resident (R3).
      resident!(ctx.adapter, [])
      assert MemoryGuard.read(@host).residentCount == 1

      # Retried on a later decision; once the process is gone it counts no more.
      :ok = MemoryGuard.tick()
      assert_receive {:closed, "sid-idle", _}
      settle_closes!()
      gone!(ctx.root, 990)
      :ok = MemoryGuard.tick()
      assert MemoryGuard.read(@host).residentCount == 0
    end

    test "D3.unreadable (T26): a close that errors stays resident and counted, is recorded, the next candidate closes, and it is retried later",
         ctx do
      session!(ctx, "agent:other", "sid-other")

      shed!(ctx,
        closer: fn _adapter, sid, reason ->
          send(ctx.test_pid, {:closed, sid, reason})

          if sid == "sid-idle",
            do: {:error, :close_timed_out},
            else: closed_process!(ctx, sid)
        end
      )

      resident!(ctx.adapter, ["sid-idle", "sid-other"])
      settle_closes!()
      :ok = MemoryGuard.tick()
      settle_closes!()

      assert [{"agent:idle", %{"error" => error}}] = events(ctx.db, "memory_guard_close_failed")
      assert error =~ "close_timed_out"
      assert [{"agent:other", _}] = events(ctx.db, "memory_guard_idle_closed")

      # The failed one is tried again on a later decision.
      :ok = MemoryGuard.tick()
      settle_closes!()
      closes = for {:closed, "sid-idle", _} <- flush_messages(), do: :retried
      assert length(closes) >= 1
    end
  end

  defp flush_messages(acc \\ []) do
    receive do
      message -> flush_messages([message | acc])
    after
      0 -> Enum.reverse(acc)
    end
  end

  ## v1.13 FS6: which cause wins (matrix A5, D4, D5, H1, H2; T27)

  describe "matrix A5 / D4 / D5 / H: attribution (FS6, T27)" do
    setup ctx do
      meminfo!(ctx.root, 16 * @gib, 12 * @gib)
      proc!(ctx.root, 650, 1, 51, 900 * @mib)
      launch!(ctx.base, "sl-k", "sid-k", 650, 51, 512 * @mib)
      session!(ctx, "agent:k", "sid-k")
      on_exit(fn -> Application.delete_env(:tightbeam, :memory_guard_attribution_wait_ms) end)
      %{match: %{host: @host, harness_session_id: "sid-k", since: 0}}
    end

    test "D4.stale (T27 first): the kill is sent while an outside SIGKILL also lands: memory_limit",
         ctx do
      guard!(ctx,
        kill_result: fn target ->
          # Both land: the tree is gone either way.
          gone!(ctx.root, target.pid)
          :ok
        end
      )

      :ok = MemoryGuard.tick()
      settle_kills!()
      assert %{limit: "session"} = MemoryGuard.memory_kill(ctx.match)
    end

    test "D4.stale (T27 second): the tree's end is observed after the intent and before the kill is sent: harness_exited",
         ctx do
      guard!(ctx, before_kill_send: fn target -> gone!(ctx.root, target.pid) end)

      :ok = MemoryGuard.tick()
      settle_kills!()
      refute_received {:killed, _}
      assert [{@host, _}] = events(ctx.db, "memory_kill_intent")
      assert MemoryGuard.memory_kill(ctx.match) == nil
      assert events(ctx.db, "memory_tree_ended") == []
    end

    test "D5.timeout (T27 third): the kill's confirmation does not arrive: memory_limit at once, because the kill was sent",
         ctx do
      test = self()

      guard!(ctx,
        kill_result: fn _target ->
          send(test, :sent)
          Process.sleep(:infinity)
        end
      )

      :ok = MemoryGuard.tick()
      assert_receive :sent
      started = System.monotonic_time(:millisecond)
      assert %{limit: "session"} = MemoryGuard.memory_kill(ctx.match)
      assert System.monotonic_time(:millisecond) - started < 1_000
    end

    test "A5.timeout: an intent never sent within the wait is not a memory kill; settlement does not wait past it",
         ctx do
      Application.put_env(:tightbeam, :memory_guard_attribution_wait_ms, 300)
      guard!(ctx, before_kill_send: fn _target -> Process.sleep(:infinity) end)

      :ok = MemoryGuard.tick()
      started = System.monotonic_time(:millisecond)
      assert MemoryGuard.memory_kill(ctx.match) == nil
      assert System.monotonic_time(:millisecond) - started < 2_000
    end

    test "A5.absent / H1.absent: no record of a kill is harness_exited (nil), never a guess",
         ctx do
      guard!(ctx)

      assert MemoryGuard.memory_kill(%{host: @host, harness_session_id: "sid-none", since: 0}) ==
               nil
    end

    test "H2.stale: a kill older than the turn's claim is not this turn's", ctx do
      guard!(ctx, kill_result: fn target -> gone!(ctx.root, target.pid) && :ok end)
      :ok = MemoryGuard.tick()
      settle_kills!()
      assert %{} = MemoryGuard.memory_kill(ctx.match)
      later = System.system_time(:millisecond) + 60_000
      assert MemoryGuard.memory_kill(%{ctx.match | since: later}) == nil
    end
  end

  ## v1.13 FS3 / FS7: transitions and their records (matrix F1, F3, F4, F7; T24, T28)

  describe "matrix F: transitions (FS3, FS7, T24, T28)" do
    defp set!(ctx, name, value) do
      {:ok, {:ok, _}} =
        DB.transaction(
          ctx.db,
          &Settings.set_in_txn(&1, @host, name, value, "user:owner", 16 * @gib)
        )

      MemoryGuard.settings_changed(@host)
    end

    test "F3.unreadable (T24): a budget change the kernel does not take leaves the host enforced on the earlier budget, and the read shows that budget",
         ctx do
      {harness, _unit, _set_mode} = enforced_with_unit!(ctx)
      before = MemoryGuard.read(@host).settings.budget
      max = Path.join(harness, "memory.max")
      File.chmod!(max, 0o444)
      on_exit(fn -> File.chmod(max, 0o644) end)

      assert {:error, {:not_applied, error}} = set!(ctx, "budget", "2G")
      assert error =~ "earlier budget still acts"
      read = MemoryGuard.read(@host)
      assert read.mode == "enforced"
      assert read.settings.budget == before
      assert File.read!(max) == Integer.to_string(before)

      File.chmod!(max, 0o644)
      :ok = MemoryGuard.tick()
      assert MemoryGuard.read(@host).settings.budget == 2 * @gib
      assert File.read!(max) == Integer.to_string(2 * @gib)
    end

    test "F1.unreadable / F1.partial (T24): leaving enforced with limits not lifted names the kernel limits still in force",
         ctx do
      {_harness, unit, set_mode} = enforced_with_unit!(ctx)
      file = Path.join(unit, "memory.max")
      File.chmod!(file, 0o444)
      on_exit(fn -> File.chmod(file, 0o644) end)

      assert {:error, {:not_applied, _}} = set_mode.("off")
      read = MemoryGuard.read(@host)
      assert read.mode == "watched"
      assert read.notEnforcedReason =~ "still in force: the budget group's memory.max (8.0 GiB)"
      assert read.notEnforcedReason =~ "each session unit's own memory.max"
    end

    test "F4.unreadable (T28 c): stored settings that cannot be read keep the last effective ones, and the read says so",
         ctx do
      meminfo!(ctx.root, 16 * @gib, 12 * @gib)
      guard!(ctx)
      :ok = set!(ctx, "residentCap", "4")
      assert MemoryGuard.read(@host).settings.residentCap == 4

      {:ok, _} = DB.query(ctx.db, "ALTER TABLE host_memory_settings RENAME TO hms_hidden")

      try do
        _ = MemoryGuard.settings_changed(@host)
        read = MemoryGuard.read(@host)
        assert read.settings.residentCap == 4
        assert read.notEnforcedReason =~ "stored memory settings cannot be read"
        assert read.notEnforcedReason =~ "last effective settings stay in use"
      after
        {:ok, _} = DB.query(ctx.db, "ALTER TABLE hms_hidden RENAME TO host_memory_settings")
      end
    end

    test "F7.unreadable (T28 a): a mode change whose record cannot be written is not established, reads watched, and is retried",
         ctx do
      meminfo!(ctx.root, 16 * @gib, 12 * @gib)
      guard!(ctx)

      {:ok, _} =
        DB.query(ctx.db, """
        CREATE TRIGGER mg_fail_mode BEFORE INSERT ON lifecycle_events
        WHEN NEW.kind='memory_guard_mode'
        BEGIN SELECT RAISE(ABORT, 'injected mode record failure'); END
        """)

      assert {:error, {:not_applied, error}} = set!(ctx, "mode", "off")
      assert error =~ "could not be recorded"
      assert MemoryGuard.read(@host).mode == "watched"
      refute Unguarded.mode_in_force(ctx.db, @host) == "off"

      {:ok, _} = DB.query(ctx.db, "DROP TRIGGER mg_fail_mode")
      :ok = MemoryGuard.tick()
      assert MemoryGuard.read(@host).mode == "off"
      assert Unguarded.mode_in_force(ctx.db, @host) == "off"
      assert :ok = MemoryGuard.settings_changed(@host)
    end
  end

  ## v1.13 FS7: bookkeeping writes (matrix C10, H3, I2, I3; T28 b, d, e)

  describe "matrix C10 / H3 / I2 / I3: bookkeeping (FS7, T28)" do
    defp fail_kind!(ctx, kind) do
      {:ok, _} =
        DB.query(ctx.db, """
        CREATE TRIGGER mg_fail_#{kind} BEFORE INSERT ON lifecycle_events
        WHEN NEW.kind='#{kind}'
        BEGIN SELECT RAISE(ABORT, 'injected #{kind} failure'); END
        """)
    end

    defp heal_kind!(ctx, kind), do: {:ok, _} = DB.query(ctx.db, "DROP TRIGGER mg_fail_#{kind}")

    defp floor_close!(ctx) do
      meminfo!(ctx.root, 16 * @gib, div(16 * @gib * 10, 100))
      adapter = adapter!()
      session!(ctx, "agent:idle", "sid-idle")
      guard!(ctx)
      resident!(adapter, ["sid-idle"])
      :ok = MemoryGuard.tick()
      settle_closes!()
    end

    test "I2.unreadable (T28 b): a marker that cannot be posted is recorded, retried, and delivered exactly once",
         ctx do
      fail_kind!(ctx, "memory_guard_idle_closed_marker")
      floor_close!(ctx)
      assert [{"agent:idle", _}] = events(ctx.db, "memory_guard_idle_closed")
      assert events(ctx.db, "memory_guard_idle_closed_marker") == []
      assert [{"agent:idle", %{"marker" => _}}] = events(ctx.db, "memory_guard_marker_failed")

      heal_kind!(ctx, "memory_guard_idle_closed_marker")
      :ok = MemoryGuard.tick()
      :ok = MemoryGuard.tick()

      assert [{"agent:idle", %{"markerKey" => _}}] =
               events(ctx.db, "memory_guard_idle_closed_marker")

      assert length(events(ctx.db, "memory_guard_marker_failed")) == 1
    end

    test "I3.unreadable (T28 b): a close shown complete stands when its event cannot be written; the event is retried until written",
         ctx do
      fail_kind!(ctx, "memory_guard_idle_closed")
      floor_close!(ctx)
      assert events(ctx.db, "memory_guard_idle_closed") == []
      assert MemoryGuard.read(@host).residentCount == 0

      heal_kind!(ctx, "memory_guard_idle_closed")
      :ok = MemoryGuard.tick()
      assert [{"agent:idle", _}] = events(ctx.db, "memory_guard_idle_closed")
      :ok = MemoryGuard.tick()
      assert length(events(ctx.db, "memory_guard_idle_closed")) == 1
    end

    test "I3.unreadable (holds): a hold whose record cannot be written is not established; the turn stays unclaimed and its lane asks again",
         ctx do
      meminfo!(ctx.root, 16 * @gib, div(16 * @gib * 10, 100))
      guard!(ctx)
      :ok = MemoryGuard.tick()
      session!(ctx, "agent:new", "sid-new")
      queue!(ctx, "agent:new", "needs a launch")
      fail_kind!(ctx, "memory_guard_hold")

      assert {:held, ["memory_floor"]} = MemoryGuard.admit("agent:new", ctx.db)
      refute Map.has_key?(:sys.get_state(MemoryGuard).held, "agent:new")

      heal_kind!(ctx, "memory_guard_hold")
      :ok = MemoryGuard.tick()
      assert_received {:nudged, "agent:new"}
      assert {:held, ["memory_floor"]} = MemoryGuard.admit("agent:new", ctx.db)
      assert [{"agent:new", %{"detail" => "memory_floor"}}] = events(ctx.db, "memory_guard_hold")
    end

    test "I3.unreadable (releases): a release whose record cannot be written leaves the hold standing until it is recorded",
         ctx do
      meminfo!(ctx.root, 16 * @gib, div(16 * @gib * 10, 100))
      guard!(ctx)
      :ok = MemoryGuard.tick()
      fail_kind!(ctx, "memory_guard_release")

      meminfo!(ctx.root, 16 * @gib, div(16 * @gib * 50, 100))
      :ok = MemoryGuard.tick()
      assert MemoryGuard.host_reasons(@host) == ["memory_floor"]

      heal_kind!(ctx, "memory_guard_release")
      :ok = MemoryGuard.tick()
      assert MemoryGuard.host_reasons(@host) == []
      assert [{@host, %{"detail" => "memory_floor"}}] = events(ctx.db, "memory_guard_release")
    end

    test "C10.unreadable (T28 d): a unit that cannot be removed is recorded and retried, and is never evidence of an end",
         ctx do
      {harness, _unit, _set_mode} = enforced_with_unit!(ctx)
      unit = Path.join(harness, "session-live")
      File.write!(Path.join(unit, "cgroup.events"), "populated 0\nfrozen 0\n")
      :ok = MemoryGuard.tick()

      # The tree ended (its unit is empty); the unit directory still holds
      # files, so removing it fails.
      assert [{"/svc/tightbeam.service/harness/session-live", %{"error" => _}}] =
               events(ctx.db, "memory_guard_unit_remove_failed")

      assert File.dir?(unit)

      for file <- File.ls!(unit), do: File.rm!(Path.join(unit, file))
      :ok = MemoryGuard.tick()
      refute File.dir?(unit)
      assert length(events(ctx.db, "memory_guard_unit_remove_failed")) == 1
    end

    test "H3.absent / H3.unreadable (T28 e): host memory unknown at an outside kill is recorded as unknown, never guessed",
         ctx do
      guard!(ctx)
      :ok = MemoryGuard.tick()
      assert MemoryGuard.read(@host).hostAvailablePercent == nil
      :ok = MemoryGuard.note_adapter_exit("L-outside", 137)
      assert %{status: 137, host_low: "unknown"} = MemoryGuard.adapter_exit("L-outside")
    end
  end

  ## Release delivery (matrix M1–M3; R6, R6a, R9)

  describe "matrix M: release delivery (R6, R6a, R9)" do
    setup ctx do
      meminfo!(ctx.root, 16 * @gib, div(16 * @gib * 10, 100))
      session!(ctx, "agent:a", "sid-a")
      session!(ctx, "agent:b", "sid-b")
      for key <- ["agent:a", "agent:b"], do: queue!(ctx, key, "needs a launch")
      :ok
    end

    test "M1.unreadable / M1.partial: a nudge that fails is not lost; the next sample nudges every held session no reason holds",
         ctx do
      test = self()
      failures = :counters.new(1, [])

      guard!(ctx,
        nudge: fn key ->
          # The first nudge after the release fails.
          if key == "agent:a" and :counters.get(failures, 1) == 0 do
            :counters.add(failures, 1, 1)
            raise "lane unavailable"
          end

          send(test, {:nudged, key})
        end
      )

      :ok = MemoryGuard.tick()
      for key <- ["agent:a", "agent:b"], do: assert({:held, _} = MemoryGuard.admit(key, ctx.db))

      meminfo!(ctx.root, 16 * @gib, div(16 * @gib * 50, 100))
      :ok = MemoryGuard.tick()
      assert_received {:nudged, "agent:b"}
      # The failed nudge is retried by the sample; the guard did not crash.
      assert Process.alive?(Process.whereis(MemoryGuard))
      :ok = MemoryGuard.tick()
      assert_received {:nudged, "agent:a"}
    end

    test "M1.stale: a lane nudged after its reason stood again re-asks and is held; nothing is claimed without a decision",
         ctx do
      guard!(ctx)
      :ok = MemoryGuard.tick()
      assert {:held, ["memory_floor"]} = MemoryGuard.admit("agent:a", ctx.db)
      meminfo!(ctx.root, 16 * @gib, div(16 * @gib * 50, 100))
      :ok = MemoryGuard.tick()
      assert_received {:nudged, "agent:a"}

      meminfo!(ctx.root, 16 * @gib, div(16 * @gib * 10, 100))
      :ok = MemoryGuard.tick()
      assert {:held, ["memory_floor"]} = MemoryGuard.admit("agent:a", ctx.db)
    end

    test "M3.unreadable: a re-admitted turn whose handoff never reached its lane is nudged by the next sample",
         ctx do
      meminfo!(ctx.root, 16 * @gib, 12 * @gib)
      guard!(ctx)
      seq = oldest!(ctx, "agent:a")

      {:ok, :readmitted} =
        DB.transaction(ctx.db, &Admission.not_started_in_txn(&1, seq, @host))

      # LaneManager is not running here: the handoff after commit reached no lane.
      :ok = MemoryGuard.tick()
      assert_received {:nudged, "agent:a"}
    end

    test "M2.absent: a deferred re-admission whose source turn is gone records its end and is not pending forever",
         ctx do
      meminfo!(ctx.root, 16 * @gib, 12 * @gib)
      guard!(ctx)

      EventLog.lifecycle(
        ctx.db,
        "memory_readmission_pending",
        "agent:a",
        JSON.encode!(%{host: @host, sourceSeq: 999_999})
      )

      assert Admission.pending?(ctx.db)
      _ = Admission.run_deferred(ctx.db, @host)

      assert [{_, %{"sourceSeq" => 999_999, "readmittedSeq" => nil, "sourceGone" => true}}] =
               events(ctx.db, "memory_readmission_done")

      refute Admission.pending?(ctx.db)
    end

    test "M2.stale: a source already re-admitted is never enqueued twice", ctx do
      meminfo!(ctx.root, 16 * @gib, 12 * @gib)
      guard!(ctx)
      seq = oldest!(ctx, "agent:a")
      {:ok, :readmitted} = DB.transaction(ctx.db, &Admission.not_started_in_txn(&1, seq, @host))

      # The same source again (a replayed settlement): no second turn.
      {:ok, _} =
        DB.transaction(ctx.db, fn txn ->
          EventLog.lifecycle_in_txn(
            txn,
            "memory_readmission_pending",
            "agent:a",
            JSON.encode!(%{host: @host, sourceSeq: seq})
          )
        end)

      _ = Admission.run_deferred(ctx.db, @host)
      assert length(events(ctx.db, "memory_readmission_done")) == 1
    end
  end

  describe "sibling failures (review family: failures never read as success)" do
    setup ctx do
      meminfo!(ctx.root, 16 * @gib, 12 * @gib)
      :ok
    end

    test "a setting stored while the guard cannot answer says it is not yet applied", ctx do
      guard!(ctx)
      Application.put_env(:tightbeam, :memory_guard_call_timeout_ms, 300)
      on_exit(fn -> Application.delete_env(:tightbeam, :memory_guard_call_timeout_ms) end)
      session!(ctx, "agent:admin-session")
      :sys.suspend(MemoryGuard)

      try do
        result =
          Gateway.handlers(%{db: ctx.db, base_dir: ctx.base})["host-memory-set"].(%{
            origin: "user:owner",
            principal: {:session, "agent:admin-session"},
            params: %{host: @host, name: "residentCap", value: "4"}
          })

        assert result.effect =~ "NOT yet applied"
      after
        :sys.resume(MemoryGuard)
      end
    end

    test "a host whose launch step is unavailable says sessions are not limited one by one",
         ctx do
      guard!(ctx, cli_bin: nil)
      read = MemoryGuard.read(@host)
      assert read.mode == "watched"
      assert read.notEnforcedReason =~ "session processes are not limited one by one"
      assert [_ | _] = events(ctx.db, "memory_guard_mode")
    end

    test "a failed idle close is recorded; a busy one is not a failure", ctx do
      guard!(ctx, close_result: {:error, :close_timed_out})

      {:ok, {:ok, _}} =
        DB.transaction(
          ctx.db,
          &Settings.set_in_txn(&1, @host, "residentCap", "1", "user:owner", 16 * @gib)
        )

      :ok = MemoryGuard.settings_changed(@host)
      adapter = adapter!()
      session!(ctx, "agent:idle", "sid-idle")
      resident!(adapter, ["sid-idle"])
      session!(ctx, "agent:new")
      queue!(ctx, "agent:new", "go")
      assert {:held, ["resident_cap"]} = MemoryGuard.admit("agent:new")
      assert_receive {:closed, "sid-idle", "resident_cap"}

      assert [{"agent:idle", %{"error" => error}}] = events(ctx.db, "memory_guard_close_failed")
      assert error =~ "close_timed_out"
      assert events(ctx.db, "memory_guard_idle_closed") == []
    end

    test "E4.absent / E4.unreadable (T33): a missing harness-process table is never 'nothing to end' (R2a) nor an empty host; launches are held guard_unavailable",
         ctx do
      guard!(ctx)
      session!(ctx, "agent:new", "sid-new")
      queue!(ctx, "agent:new", "needs a launch")

      {:ok, _} =
        DB.query(ctx.db, "ALTER TABLE harness_processes RENAME TO harness_processes_hidden")

      try do
        assert {:error, {:launches_unreadable, _}} =
                 MemoryGuard.adapter_ended({:claude, "shared", @host}, "L")

        assert {:error, _} = MemoryGuard.ensure_no_orphans({:claude, "shared", @host})

        :ok = MemoryGuard.tick()
        read = MemoryGuard.read(@host)
        assert read.mode == "watched"
        assert read.recordsUnreadable =~ "harness-process table"
        assert [_] = events(ctx.db, "memory_guard_inventory_failed")
        assert {:held, ["guard_unavailable"]} = MemoryGuard.admit("agent:new", ctx.db)
      after
        {:ok, _} =
          DB.query(ctx.db, "ALTER TABLE harness_processes_hidden RENAME TO harness_processes")
      end

      :ok = MemoryGuard.tick()
      assert MemoryGuard.read(@host).recordsUnreadable == nil
      assert :ok = MemoryGuard.admit("agent:new", ctx.db)
    end
  end

  ## R6a / T14 (admission composition)

  describe "standing reasons (R6a, T14)" do
    test "a quota release while the floor stands defers B5 re-admission, records the remaining hold, and runs it once at resumption",
         ctx do
      total = 16 * @gib
      meminfo!(ctx.root, total, div(total * 10, 100))
      guard!(ctx)
      :ok = MemoryGuard.tick()
      assert MemoryGuard.host_reasons(@host) == ["memory_floor"]

      {:ok, :deferred} =
        DB.transaction(
          ctx.db,
          &Admission.quota_released_in_txn(&1, "incident-1", "claude", @host)
        )

      assert [{"incident-1", %{"released" => "quota_park", "remaining" => ["memory_floor"]}}] =
               events(ctx.db, "admission_hold_remaining")

      assert [{"incident-1", _}] = events(ctx.db, "quota_readmission_deferred")
      assert events(ctx.db, "admission_resumed") == []

      meminfo!(ctx.root, total, div(total * 16, 100))
      :ok = MemoryGuard.tick()
      assert [{"incident-1", %{"after" => ["memory"]}}] = events(ctx.db, "admission_resumed")
      assert [{"incident-1", _}] = events(ctx.db, "quota_readmission_resumed")

      # Exactly once: a later release finds nothing pending.
      :ok = Admission.run_deferred(ctx.db, @host)
      assert length(events(ctx.db, "quota_readmission_resumed")) == 1
    end

    test "a floor release while a quota park stands records the remaining hold and admits nothing",
         ctx do
      total = 16 * @gib
      meminfo!(ctx.root, total, div(total * 10, 100))
      guard!(ctx)
      :ok = MemoryGuard.tick()
      session!(ctx, "agent:s")
      queue!(ctx, "agent:s", "q1")
      assert {:held, ["memory_floor"]} = MemoryGuard.admit("agent:s")

      {:ok, _} =
        DB.transaction(ctx.db, fn txn ->
          DB.Txn.q(
            txn,
            "INSERT INTO harness_park_fences (adapterKey, requestedAt, generation) VALUES ('claude:shared@testhost', 1, 1)"
          )
        end)

      assert [%{detail: "memory_floor"}, %{reasonClass: "provider_quota", detail: "quota_park"}] =
               HeldState.read(ctx.db, Org.get(ctx.db, "agent:s")).reasons

      meminfo!(ctx.root, total, div(total * 16, 100))
      :ok = MemoryGuard.tick()

      assert [{"agent:s", %{"released" => "memory_floor", "remaining" => ["quota_park"]}}] =
               events(ctx.db, "admission_hold_remaining")

      assert [%{reasonClass: "provider_quota"}] =
               HeldState.read(ctx.db, Org.get(ctx.db, "agent:s")).reasons

      assert events(ctx.db, "admission_resumed") == []
    end

    # Review B6: the R9 hook itself waits for every standing reason, in both
    # release orders, with a quota park and with a limit-fallback hold.
    for {other, label} <- [{:park, "quota park"}, {:fallback, "limit-fallback hold"}],
        order <- [:memory_first, :other_first] do
      @tag other: other, order: order
      test "R9 not-started with a #{label}, #{order}: re-admitted once, only after both clear",
           ctx do
        total = 16 * @gib
        meminfo!(ctx.root, total, div(total * 10, 100))
        guard!(ctx)
        :ok = MemoryGuard.tick()
        session!(ctx, "agent:load")
        seq = queue!(ctx, "agent:load", "load me")
        hold_other!(ctx, ctx.other, seq, true)

        assert {:ok, :deferred} =
                 DB.transaction(ctx.db, &Admission.not_started_in_txn(&1, seq, @host))

        {first, second} =
          if ctx.order == :memory_first,
            do: {fn -> free!(ctx) end, fn -> hold_other!(ctx, ctx.other, seq, false) end},
            else: {fn -> hold_other!(ctx, ctx.other, seq, false) end, fn -> free!(ctx) end}

        first.()
        :ok = MemoryGuard.tick()
        assert events(ctx.db, "memory_readmission_done") == []

        second.()
        :ok = MemoryGuard.tick()

        assert [{"agent:load", %{"sourceSeq" => ^seq}}] =
                 events(ctx.db, "memory_readmission_done")

        :ok = MemoryGuard.tick()
        assert length(events(ctx.db, "memory_readmission_done")) == 1
      end
    end

    test "R9 not-started: re-admitted exactly once, then exhausted", ctx do
      meminfo!(ctx.root, 16 * @gib, 12 * @gib)
      guard!(ctx)
      session!(ctx, "agent:load")
      seq = queue!(ctx, "agent:load", "load me")

      assert {:ok, :readmitted} =
               DB.transaction(ctx.db, &Admission.not_started_in_txn(&1, seq, @host))

      assert [{"agent:load", %{"sourceSeq" => ^seq, "readmittedSeq" => readmitted}}] =
               events(ctx.db, "memory_readmission_done")

      assert {:ok, :exhausted} =
               DB.transaction(ctx.db, &Admission.not_started_in_txn(&1, readmitted, @host))

      assert length(events(ctx.db, "memory_readmission_done")) == 1
    end
  end
end

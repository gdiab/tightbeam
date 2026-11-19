defmodule Tightbeam.MemoryGuardTest do
  # Memory limits v1.1 (harness-memory-limits, art_4009cd68): the guard's own
  # decisions, on our side of the ACP seam. `/proc`, `/proc/meminfo` and the
  # cgroup filesystem are fake trees under a temp root; adapters are processes
  # that answer the guard's residency, idle and forget calls. The kill, the
  # close and the lane nudge are injected and report to the test. The real
  # processes, step and kernel limits are exercised by
  # memory_guard_containment_test.exs and cli/tests/memory_guard_step.rs.
  use Tightbeam.TestCase, async: false

  alias Tightbeam.{DB, Devices, Gateway, Ledger, MemoryGuard, Org, Schema}
  alias Tightbeam.MemoryGuard.{Admission, Cgroup, HeldState, Probe, Records, Settings}

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

    start_supervised!(
      {MemoryGuard,
       db: ctx.db,
       base_dir: ctx.base,
       local_host: @host,
       root: ctx.root,
       cgroup_fs: Keyword.get(opts, :cgroup_fs, Path.join(ctx.root, "sys/fs/cgroup")),
       probe: fn -> probe end,
       sample_ms: :manual,
       closer: fn _adapter, sid, reason ->
         send(test, {:closed, sid, reason})
         Keyword.get(opts, :close_result, :ok)
       end,
       killer: fn target, _host_state ->
         send(test, {:killed, target})
         :ok
       end,
       nudge: fn key -> send(test, {:nudged, key}) end}
    )
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
      # NB-3: +100 by default, a setting.
      assert settings.session_oom_score_adj == 100
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
      assert {:error, %{code: "invalid_setting"}} = set.("sessionOomScoreAdj", "1001")
      assert {:ok, %{value: "0"}} = set.("sessionOomScoreAdj", "0")
      assert {:error, %{code: "invalid_setting"}} = set.("mode", "enforced")
      assert {:error, %{code: "invalid_setting"}} = set.("nonsense", "1")

      effective = Settings.effective(Settings.stored(ctx.db, @host), total)
      assert effective.resident_cap == 15
      assert effective.budget == 8 * @gib
      assert effective.session_limit == 512 * @mib
      assert effective.floor_release == 20
      assert effective.session_oom_score_adj == 0

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
      assert read.heldTurns == %{"memory_budget" => 0, "memory_floor" => 0, "resident_cap" => 1}
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

      assert MemoryGuard.launch_env({:claude, "shared", @host}, "L",
               cmd: ["/x/.bin/claude-agent-acp"],
               env: []
             ) == []

      assert HeldState.read(ctx.db, Org.get(ctx.db, "agent:off")) == nil
      refute_received {:closed, _, _}
      refute_received {:killed, _}
    end

    test "R12a: an unreadable tree sample degrades the host to count-only, once, until a read succeeds",
         ctx do
      meminfo!(ctx.root, 16 * @gib, 12 * @gib)
      guard!(ctx)
      File.rm_rf!(Path.join(ctx.root, "proc"))
      File.mkdir_p!(ctx.root)
      # meminfo is gone with /proc; the tree read fails.
      :ok = MemoryGuard.tick()
      :ok = MemoryGuard.tick()
      assert MemoryGuard.read(@host).mode == "count-only"
      assert length(events(ctx.db, "memory_guard_sampling_failed")) == 1

      File.mkdir_p!(Path.join(ctx.root, "proc"))
      meminfo!(ctx.root, 16 * @gib, 12 * @gib)
      :ok = MemoryGuard.tick()
      assert MemoryGuard.read(@host).mode == "watched"
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

      assert [{@host, intent}] = events(ctx.db, "memory_kill_intent")
      assert %{"limit" => "session", "scope" => "session", "sessionId" => "sid-a"} = intent
      assert intent["bytes"] == 710 * @mib
      assert [{"agent:a", %{"limit" => "session"}}] = events(ctx.db, "memory_tree_ended")

      assert %{limit: "session", scope: "session", bytes: bytes} =
               MemoryGuard.memory_kill(%{host: @host, harness_session_id: "sid-a", since: 0})

      assert bytes == 710 * @mib
      assert MemoryGuard.memory_kill(%{host: @host, harness_session_id: "sid-b", since: 0}) == nil
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

  defp insert_adapter_row!(db, launch_id, os_pid) do
    {:ok, _} =
      DB.transaction(db, fn txn ->
        DB.Txn.q(
          txn,
          """
          INSERT INTO harness_processes
            (launchId, adapterKey, harness, preset, host, ssh, helperPath, identityPath,
             launchSequence, osPid, processGroupId, bootIdentity, identityToken, state, createdAt)
          VALUES (?1, 'claude:shared@testhost', 'claude', 'shared', 'testhost', NULL, '/bin/false',
                  '/nonexistent', (SELECT COALESCE(MAX(launchSequence),0)+1 FROM harness_processes),
                  ?2, ?2, 'boot', ?1, 'running', ?3)
          """,
          [launch_id, os_pid, System.system_time(:millisecond)]
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

      remaining = Records.read_all(ctx.base) |> Map.keys()
      assert remaining == ["sl-other"]
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

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
    Journal,
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
    # A fake kill ends its fake processes at once; a tree a test keeps alive is
    # given up on sooner than a real one.
    Application.put_env(:tightbeam, :memory_guard_kill_wait_ms, 300)
    on_exit(fn -> Application.delete_env(:tightbeam, :memory_guard_kill_wait_ms) end)
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

  defp strict_finding do
    for m <- ["groups", "sudo", "sockets"],
        into: %{},
        do: {m, %{"result" => "absent", "detail" => []}}
  end

  defp residual_finding,
    do: Map.put(strict_finding(), "groups", %{"result" => "present", "detail" => ["docker"]})

  # A fake process in process group `pgrp` and session `sid` (the step's
  # `setsid` leader's pid), for the whole-tree proof after the leader is gone.
  defp proc_in!(root, pid, ppid, start, bytes, pgrp, sid) do
    dir = Path.join([root, "proc", Integer.to_string(pid)])
    File.mkdir_p!(dir)
    zeros = Enum.map_join(1..15, " ", fn _ -> "0" end)

    File.write!(
      Path.join(dir, "stat"),
      "#{pid} (fake proc) S #{ppid} #{pgrp} #{sid} #{zeros} #{start} 0 0\n"
    )

    File.write!(
      Path.join(dir, "status"),
      "Name:\tfake\nVmRSS:\t#{div(bytes, 1024)} kB\nVmSwap:\t0 kB\n"
    )
  end

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
      # FS9: the real owner-alerts route; the test is told when it created
      # an alert row.
      db: ctx.db,
      base_dir: ctx.base,
      cli_bin: cli_bin,
      local_host: @host,
      root: ctx.root,
      cgroup_fs: Keyword.get(opts, :cgroup_fs, Path.join(ctx.root, "sys/fs/cgroup")),
      probe: fn -> probe end,
      sample_ms: :manual,
      clock: Keyword.get(opts, :clock, fn -> System.system_time(:millisecond) end),
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
      close_hook: Keyword.get(opts, :close_hook, fn _point, _sid -> :ok end),
      before_kill_send: Keyword.get(opts, :before_kill_send, fn _ -> :ok end),
      root_uid: Keyword.get(opts, :root_uid, 0),
      finding: Keyword.get(opts, :finding, fn -> strict_finding() end),
      owner_alert:
        Keyword.get(opts, :owner_alert, fn txn, input ->
          result = Tightbeam.OwnerAlerts.memory_guard_stuck_in_txn(txn, input)
          if match?({:created, _}, result), do: send(test, {:owner_alert, input.episode_id})
          result
        end),
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

  # A rate-limit incident naming `session_key` (a member), opened as the
  # provider's evidence opens one.
  defp quota_incident!(ctx, session_key, host) do
    {:ok, _} =
      DB.transaction(ctx.db, fn txn ->
        Tightbeam.HarnessHealth.observe_in_txn(txn, %{
          correlation_id: "open-#{System.unique_integer([:positive])}",
          harness: "claude",
          host: host,
          failure_class: "rate-limit-dead",
          evidence_kind: "authoritative-provider",
          session_key: session_key,
          assignment_id: nil,
          observed_at: System.system_time(:millisecond),
          cause: "usageLimitExceeded",
          principal: "process:test"
        })
      end)

    {:ok, [[id]]} =
      DB.query(ctx.db, "SELECT incidentId FROM harness_health_members WHERE sessionKey=?1", [
        session_key
      ])

    # The park is released, as at the release that runs the hook.
    {:ok, _} = DB.query(ctx.db, "DELETE FROM harness_park_fences")
    id
  end

  # The wake scheduler's part (bounded-continuations design rev 2 D3): one
  # run of each pending quota-episode wake, due or not.
  defp run_quota_wakes!(ctx) do
    for wake_id <- quota_wakes(ctx),
        do: Admission.quota_wake(ctx.db, %{wake_id: wake_id})

    :ok
  end

  defp quota_wakes(ctx) do
    {:ok, rows} =
      DB.query(
        ctx.db,
        "SELECT wakeId FROM wakes WHERE consumer='memory_guard_quota' AND state='pending' ORDER BY wakeId"
      )

    Enum.map(rows, &hd/1)
  end

  defp events(db, kind) do
    {:ok, rows} =
      DB.query(db, "SELECT subject,detail FROM lifecycle_events WHERE kind=?1 ORDER BY id", [kind])

    Enum.map(rows, fn [subject, detail] -> {subject, detail && JSON.decode!(detail)} end)
  end

  ## R17 / R17a / T13: settings

  describe "settings (R17, T13)" do
    test "F4.absent: the defaults on Sirius's 31.25 GiB are the spec's numbers" do
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

    test "F5.absent (T11 a): no delegation reads watched with the plain-words reason", ctx do
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

    test "F5.partial (T11 b): delegation with OOMPolicy=stop reads watched and names the policy",
         ctx do
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

    test "E5.absent (T11 c2, v1.15): no /proc/meminfo reads count-only; with an admin-set residentCap, R3 holds turns at it",
         ctx do
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
      # A set residentCap is honoured where the memory size is unknown (R17).
      assert read.residentCapGap == nil
      # Counts and totals only (v3 R2): no process list, pid or command line.
      refute Enum.any?(Map.keys(read), &(&1 in [:pids, :processes, :commands]))
    end

    test "E5.absent (T11 c, v1.15, R12a): no /proc/meminfo reads count-only; with no residentCap, R3 applies no cap and the read names the gap",
         ctx do
      assert %{mode: :count_only, reason: reason, mem_total: nil} =
               Probe.probe(root: ctx.root, os: {:unix, :linux})

      guard!(ctx, probe: %{mode: :count_only, reason: reason, mem_total: nil, cgroup: nil})

      adapter = adapter!()
      sids = for n <- 1..3, do: "sid-r#{n}"

      for {sid, n} <- Enum.with_index(sids, 1) do
        session!(ctx, "agent:r#{n}", sid)
        queue!(ctx, "agent:r#{n}", "busy")
      end

      resident!(adapter, sids)
      for n <- 1..3, do: :ok = MemoryGuard.admit("agent:r#{n}")

      # Three resident and busy (more than the old floor of 2): a fourth that
      # needs a launch is still admitted.
      session!(ctx, "agent:new")
      queue!(ctx, "agent:new", "needs a launch")
      assert :ok = MemoryGuard.admit("agent:new")

      read = MemoryGuard.read(@host)
      assert read.mode == "count-only"
      # The admitted launch counts from its decision (R3): four, no cap.
      assert read.residentCount == 4
      assert read.heldTurns["resident_cap"] == 0

      assert read.residentCapGap ==
               "no resident cap: this machine's memory size is unknown; set one with " <>
                 "tightbeam host-memory set --host #{@host} residentCap <count>"
    end

    test "macOS and other systems read count-only", ctx do
      assert %{mode: :count_only, reason: reason} =
               Probe.probe(root: ctx.root, os: {:unix, :darwin}, mem_total: 8 * @gib)

      assert reason =~ "need Linux"
    end

    test "C7.absent / C7.unreadable (T11 d): a launch whose unit cannot be created runs watched and the host stays enforced",
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

    test "C7.partial (review B2): an adapter whose unit join failed is recorded, sampled and limited",
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

    test "C1.unreadable / C1.absent (review R2): an unreadable cgroup.events is not an empty unit, so the tree is not certified ended",
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
      test "#{if direction == :leaving, do: "F1", else: "F2"}.#{if failure == :unit_write, do: "unreadable", else: "partial"} (review R4): #{direction} enforced with a #{failure} failure is not reported applied; retried until it is",
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

    test "T4 / D3.absent / K1.absent / K5.absent: a fourth session's turn closes the LRU idle process and runs; with all busy it is held, then runs when a slot frees",
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

    test "T21 / L5.absent / L5.stale: only the founding user's Main has the slot; an admin's Main waits; with the founder gone the slot stays empty",
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

    test "D2.unreadable: a failed group kill keeps the record, says the tree survives and refuses the replacement",
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

    test "D1.partial / D2.partial (review R2): a helper that reports a captured survivor is not overruled by the root's end",
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

    test "A2.absent / A2.unreadable (review R1): an expected guard that is not running refuses; one restarting is waited for; none configured passes",
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

    test "A3.absent / A4.absent / A4.unreadable / A4.timeout / G3.unreadable (review R1 siblings): an expected guard that is down refuses an unplaced launch and stands as a reason for deferred hooks",
         ctx do
      local = Tightbeam.Placement.local_host_name()
      key = {:claude, "shared", local}
      opts = [cmd: ["/bin/claude-acp"], env: []]
      on_exit(fn -> MemoryGuard.expect(false) end)

      MemoryGuard.expect(false)
      # A quota incident of a session on this host (its wake is filed there).
      session!(ctx, "agent:quota")

      {:ok, _} =
        DB.query(ctx.db, "UPDATE sessions SET host=?1 WHERE sessionKey='agent:quota'", [local])

      incident = quota_incident!(ctx, "agent:quota", local)

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
                 &Admission.quota_released_in_txn(&1, incident, "claude", local)
               )

      assert [{^incident, %{"remaining" => ["memory_guard_unavailable"]}}] =
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

    test "A2.timeout: a guard that cannot answer refuses the launch rather than allowing it",
         ctx do
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

    test "A3.unreadable / F6.absent / F6.unreadable: a session launch whose launch step is not in place is held guard_unavailable; under off it runs",
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

      # No kernel limit of this contract exists here (none was ever set up).
      assert set.(call.(%{host: @host, name: "mode", value: "off"})).effect =~
               "in force on testhost"

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

    test "C8.absent / C8.unreadable / C8.partial: a session tree the step could not place in its unit on an enforced host is recorded once",
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

    test "K1.unreadable / K1.timeout: turns that cannot be read are not idle; no close, recorded",
         ctx do
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

    test "K2.absent / K4.absent: a resident process with no session for it is not idle; no close, recorded",
         ctx do
      {:ok, _} =
        DB.query(ctx.db, "DELETE FROM harness_pointers WHERE harnessSessionId='sid-idle'")

      shed!(ctx)
      refute_received {:closed, _, _}

      assert [{_, %{"why" => "no session for the harness session"}}] =
               events(ctx.db, "memory_guard_idle_unproven")
    end

    test "K2.unreadable / K2.timeout: an unreadable session pointer is not idle", ctx do
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

    test "K4.unreadable / K4.timeout: a session whose priority class cannot be read is not closed",
         ctx do
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

    test "K3.unreadable / K3.timeout / K3.absent: an adapter that cannot answer is not idle; nothing closes, nothing is a failure",
         ctx do
      shed!(ctx, idle_check: fn _adapter, _sid -> {:error, {:adapter_unavailable, :timeout}} end)
      settle_closes!()
      refute_received {:closed, _, _}
      assert events(ctx.db, "memory_guard_idle_closed") == []
      assert events(ctx.db, "memory_guard_close_failed") == []
    end

    test "K7.stale / K1.stale (before the commit): a turn enqueued after the idle read and before the closing transaction commits stops the close",
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

    test "K7.stale / K6.stale (after the commit): a turn enqueued after the closing transaction waits for the close, then starts fresh",
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

    test "K8.stale / K3.stale: a prompt the adapter takes after the guard's idle read makes its close-if-idle refuse; no close, no event, no marker",
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

    test "K5.unreadable / K5.partial / D3.partial (T26): a close acknowledged while the process lives leaves it resident and counted, recorded, and retried until it is gone",
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

    test "D5.timeout / H1.timeout (T27 third): the kill's confirmation does not arrive: memory_limit at once, because the kill was sent",
         ctx do
      test = self()

      # The kill call returns: the send is proven (rev 3 D1). The tree is not
      # yet shown gone (its confirmation lags).
      guard!(ctx,
        kill_result: fn _target ->
          send(test, :sent)
          :ok
        end,
        signal_works: false
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

    test "A5.absent / H1.absent / H1.unreadable: no record of a kill is harness_exited (nil), never a guess",
         ctx do
      guard!(ctx)

      assert MemoryGuard.memory_kill(%{host: @host, harness_session_id: "sid-none", since: 0}) ==
               nil
    end

    test "H2.stale / A5.stale: a kill older than the turn's claim is not this turn's", ctx do
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

    test "F4.unreadable / F4.partial (T28 c): stored settings that cannot be read keep the last effective ones, and the read says so",
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

    test "F7.unreadable / F7.absent (T28 a): a mode change whose record cannot be written is not established, reads watched, and is retried",
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

      # R2 sweep: the step was told `off` before the record failed; it is told
      # the mode the guard acts on, never left launching unrecorded under off.
      config = Path.join(Records.dir(ctx.base), "launch.json")
      assert %{"mode" => "watched"} = config |> File.read!() |> JSON.decode!()

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

    test "I2.unreadable / I2.timeout (T28 b): a marker that cannot be posted is recorded, retried, and delivered exactly once",
         ctx do
      fail_kind!(ctx, "memory_guard_idle_closed_marker")
      floor_close!(ctx)

      # The close's event, its marker and the journal's `done` are one step
      # (agreed design rev 5): while the marker cannot be written, neither is
      # recorded, and the close stays an open, durable obligation.
      assert events(ctx.db, "memory_guard_idle_closed") == []
      assert events(ctx.db, "memory_guard_idle_closed_marker") == []

      assert {:ok, [%{phase: "dispatched"}]} =
               Journal.page(ctx.db, @host, "idle_close", nil, nil, 8)

      heal_kind!(ctx, "memory_guard_idle_closed_marker")
      :ok = MemoryGuard.tick()
      :ok = MemoryGuard.tick()

      assert [{"agent:idle", _}] = events(ctx.db, "memory_guard_idle_closed")

      assert [{"agent:idle", %{"markerKey" => _}}] =
               events(ctx.db, "memory_guard_idle_closed_marker")

      assert {:ok, []} = Journal.page(ctx.db, @host, "idle_close", nil, nil, 8)
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

    test "M1.unreadable / M1.partial / M1.timeout: a nudge that fails is not lost; the next sample nudges every held session no reason holds",
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

    test "M3.unreadable / M3.absent / M3.timeout: a re-admitted turn whose handoff never reached its lane is nudged by the next sample",
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

      pending_readmission!(ctx, "agent:a", 999_999)
      assert Admission.pending?(ctx.db)
      :ok = MemoryGuard.tick()

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
      pending_readmission!(ctx, "agent:a", seq)
      assert Admission.pending?(ctx.db)
      :ok = MemoryGuard.tick()
      assert length(events(ctx.db, "memory_readmission_done")) == 1
      refute Admission.pending?(ctx.db)
    end

    # A not-started re-admission deferred as `not_started_in_txn` records it:
    # its open item and its record in one transaction.
    defp pending_readmission!(ctx, session_key, seq) do
      detail = JSON.encode!(%{host: @host, sourceSeq: seq})

      {:ok, _} =
        DB.transaction(ctx.db, fn txn ->
          Tightbeam.MemoryGuard.State.open_in_txn(
            txn,
            "memory_readmission",
            Integer.to_string(seq),
            session_key,
            @host,
            detail
          )

          EventLog.lifecycle_in_txn(txn, "memory_readmission_pending", session_key, detail)
        end)
    end
  end

  ## Whole-tree proof after the leader has gone (matrix B2.stale, B6, D1.absent, D2, E2.absent)

  describe "matrix B2 / B6 / D1 / D2 / E2: a dead root is not a dead tree (R2a, M-V7)" do
    setup ctx do
      meminfo!(ctx.root, 16 * @gib, 12 * @gib)
      insert_adapter_row!(ctx.db, "adapter-launch-1", 950)
      # The leader 951 has gone; 960, reparented to init, is still in its
      # process group and session.
      launch!(ctx.base, "sl-a", "sid-a", 951, 951, 512 * @mib)
      proc_in!(ctx.root, 960, 1, 960, 10 * @mib, 951, 951)
      :ok
    end

    test "B2.stale / B3.stale / B6.absent: with the identity missing and the leader gone, a surviving group member keeps the record and refuses the replacement; it is never signalled",
         ctx do
      guard!(ctx, kill_result: {:error, :identity_missing})
      {:ok, _} = DB.query(ctx.db, "UPDATE harness_processes SET state='exited'")

      assert {:error, {:session_trees_survive, ["sl-a"]}} =
               MemoryGuard.ensure_no_orphans({:claude, "shared", @host})

      refute_received {:signalled, _}
      assert Map.has_key?(elem(Records.read_all(ctx.base), 1), "sl-a")

      gone!(ctx.root, 960)
      assert :ok = MemoryGuard.ensure_no_orphans({:claude, "shared", @host})
      assert Records.read_all(ctx.base) == {:ok, %{}}
    end

    test "B6.stale: with a group member still there, a helper that refuses a mismatched identity is a failure, never an end",
         ctx do
      guard!(ctx,
        kill_result: {:error, {:harness_group_failed, 1, "identity changed"}},
        signal_works: false
      )

      {:ok, _} = DB.query(ctx.db, "UPDATE harness_processes SET state='exited'")

      assert {:error, {:session_trees_survive, ["sl-a"]}} =
               MemoryGuard.ensure_no_orphans({:claude, "shared", @host})
    end

    test "D2.absent: an adapter's end with a session leader already gone but its group alive records the orphan and keeps custody",
         ctx do
      guard!(ctx, kill_result: {:error, :identity_missing})

      assert {:error, {:session_trees_survive, ["sl-a"]}} =
               MemoryGuard.adapter_ended({:claude, "shared", @host}, "adapter-launch-1")

      assert [{@host, %{"survivors" => [%{"launchId" => "sl-a"}]}}] =
               events(ctx.db, "memory_guard_orphans")
    end

    test "E2.absent / E6.absent: a session leader that ended naturally with its group alive is not an ended tree; custody stays until the group is gone",
         ctx do
      guard!(ctx)
      :ok = MemoryGuard.tick()
      assert Map.has_key?(elem(Records.read_all(ctx.base), 1), "sl-a")

      gone!(ctx.root, 960)
      :ok = MemoryGuard.tick()
      assert Records.read_all(ctx.base) == {:ok, %{}}
    end

    test "D1.absent: a kill target whose leader is gone before the kill is sent is not certified; its group keeps custody",
         ctx do
      # An over-limit tree whose leader goes just before the signal.
      proc!(ctx.root, 971, 1, 971, 900 * @mib)
      launch!(ctx.base, "sl-big", "sid-big", 971, 971, 512 * @mib)
      proc_in!(ctx.root, 972, 1, 972, 10 * @mib, 971, 971)
      guard!(ctx, before_kill_send: fn target -> gone!(ctx.root, target.pid) end)

      :ok = MemoryGuard.tick()
      settle_kills!()
      assert events(ctx.db, "memory_tree_ended") == []
      :ok = MemoryGuard.tick()
      assert Map.has_key?(elem(Records.read_all(ctx.base), 1), "sl-big")

      gone!(ctx.root, 972)
      :ok = MemoryGuard.tick()
      refute Map.has_key?(elem(Records.read_all(ctx.base), 1), "sl-big")
    end
  end

  ## Admission's own reads (matrix L1–L5; FS1)

  describe "matrix L: admission reads (FS1)" do
    setup ctx do
      meminfo!(ctx.root, 16 * @gib, 12 * @gib)
      session!(ctx, "agent:new", "sid-new")
      queue!(ctx, "agent:new", "needs a launch")
      guard!(ctx)
      :ok
    end

    for {cell, table} <- [
          {"L1.unreadable / L1.timeout (the session row)", "sessions"},
          {"L2.unreadable / L2.timeout (the session's queued turns)", "turns"},
          {"L3.unreadable / L3.timeout (the harness session pointer)", "harness_pointers"},
          {"L5.unreadable / L5.timeout (the founding user)", "users"}
        ] do
      @tag table: table
      test "#{cell}: a read the decision needs that fails holds the launch guard_unavailable, never admits it, and the lane asks again",
           ctx do
        {:ok, _} = DB.query(ctx.db, "ALTER TABLE #{ctx.table} RENAME TO #{ctx.table}_hidden")

        try do
          assert {:held, ["guard_unavailable"]} = MemoryGuard.admit("agent:new", ctx.db)
          assert Process.alive?(Process.whereis(MemoryGuard))

          assert [{"agent:new", %{"error" => _}}] =
                   events(ctx.db, "memory_guard_admission_unreadable")
        after
          {:ok, _} = DB.query(ctx.db, "ALTER TABLE #{ctx.table}_hidden RENAME TO #{ctx.table}")
        end

        :ok = MemoryGuard.tick()
        assert_received {:nudged, "agent:new"}
        assert :ok = MemoryGuard.admit("agent:new", ctx.db)
      end
    end

    test "L1.absent: no such session: nothing to admit, nothing claimed", ctx do
      assert :no_turn = MemoryGuard.admit("agent:nobody", ctx.db)
    end

    test "L2.absent / L2.stale: no queued turn: nothing is claimed until a turn arrives", ctx do
      session!(ctx, "agent:empty", "sid-empty")
      assert :no_turn = MemoryGuard.admit("agent:empty", ctx.db)
    end

    test "L4.absent / M1.absent: an adapter that has gone no longer counts its sessions as resident",
         _ctx do
      adapter = adapter!()
      resident!(adapter, ["sid-new"])
      assert MemoryGuard.read(@host).residentCount == 1
      GenServer.stop(adapter)
      _ = :sys.get_state(MemoryGuard)
      assert MemoryGuard.read(@host).residentCount == 0
    end
  end

  ## v1.13 FS8: `off` and custody (matrix A2 under off; T29)

  describe "matrix A2 under off (FS8, T29)" do
    test "A2 (T29): a tree launched before a switch to off is still ended with its adapter, before any replacement; a tree launched under off has no record and is not touched",
         ctx do
      meminfo!(ctx.root, 16 * @gib, 12 * @gib)
      guard!(ctx)
      insert_adapter_row!(ctx.db, "adapter-launch-1", 950)
      proc!(ctx.root, 951, 950, 951, 10 * @mib)
      launch!(ctx.base, "sl-before", "sid-before", 951, 951, 512 * @mib)

      {:ok, {:ok, _}} =
        DB.transaction(
          ctx.db,
          &Settings.set_in_txn(&1, @host, "mode", "off", "user:owner", 16 * @gib)
        )

      :ok = MemoryGuard.settings_changed(@host)
      assert MemoryGuard.read(@host).mode == "off"

      # Launched under off: the step wrote no record (cli/tests mode_off).
      proc!(ctx.root, 952, 950, 952, 10 * @mib)

      assert :ok = MemoryGuard.adapter_ended({:claude, "shared", @host}, "adapter-launch-1")
      assert_received {:killed, %{scope: "session", pid: 951}}
      refute_received {:killed, %{pid: 952}}
      assert Records.read_all(ctx.base) == {:ok, %{}}
      assert File.dir?(Path.join(ctx.root, "proc/952"))
    end
  end

  ## v1.13 FS9: stuck episodes, alert, recovery and override (matrix N; T30–T36)

  describe "matrix N: stuck episodes (FS9)" do
    alias Tightbeam.MemoryGuard.{Episodes, RootActions, RootPath}

    setup ctx do
      meminfo!(ctx.root, 16 * @gib, 12 * @gib)
      Application.put_env(:tightbeam, :memory_guard_stuck_ms, 0)
      on_exit(fn -> Application.delete_env(:tightbeam, :memory_guard_stuck_ms) end)
      # The founding user is strictly the earliest (setup may add both users
      # in the same millisecond).
      {:ok, _} =
        DB.query(ctx.db, "UPDATE users SET createdAt=createdAt+1000 WHERE userId='guest'")

      main!(ctx, "owner")
      # Owner alerts are on, owned by the founding user ([G1] §7.1).
      :ok = Org.put_setting(ctx.db, "owner-alerts-user", "owner")
      %{uid: File.stat!(ctx.root).uid}
    end

    # An ended adapter left a session tree (951) that its kill cannot end; a
    # turn needing a new adapter for the key is held, so a replacement is
    # refused (R2a). Returns the opened episode.
    defp custody_stuck!(ctx, opts \\ []) do
      insert_adapter_row!(ctx.db, "adapter-launch-1", 950)
      {:ok, _} = DB.query(ctx.db, "UPDATE harness_processes SET state='exited'")
      proc!(ctx.root, 951, 1, 951, 10 * @mib)
      launch!(ctx.base, "sl-stuck", "sid-stuck", 951, 951, 512 * @mib)

      guard!(
        ctx,
        opts ++
          [kill_result: {:error, :harness_group_failed}, signal_works: false, root_uid: ctx.uid]
      )

      session!(ctx, "agent:new", "sid-new")
      queue!(ctx, "agent:new", "needs a new adapter")
      assert {:held, ["guard_unavailable"]} = MemoryGuard.admit("agent:new", ctx.db)
      :ok = MemoryGuard.tick()
      Episodes.active(ctx.db, @host) |> List.first()
    end

    defp root_record!(ctx, name, record) do
      dir = RootActions.dir(ctx.base)
      File.mkdir_p!(dir)
      path = Path.join(dir, name <> ".json")
      File.write!(path, JSON.encode!(Map.put(record, "v", 1)))
      path
    end

    defp recovery_record(episode, killed_at) do
      %{
        "action" => "recovery",
        "episodeId" => episode["episodeId"],
        "host" => @host,
        "kind" => episode["kind"],
        "key" => episode["key"],
        "killedAt" => killed_at,
        "operator" => %{"user" => "root", "sudoUser" => "unknown", "sudoUid" => "unknown"}
      }
    end

    # An override as `tightbeam memory-guard-override` writes it: the
    # statement it prints for this episode's failed recovery, operator and
    # `finding` (the text is pinned against the CLI's own in the golden test).
    defp override_record(ctx, episode, finding, extra \\ %{}) do
      stored = Episodes.get(ctx.db, episode["episodeId"])
      survivors = get_in(stored, ["recovery", "survivors"]) || []
      operator = %{"user" => "root", "sudoUser" => "george", "sudoUid" => "1000"}

      Map.merge(
        %{
          "action" => "override",
          "episodeId" => episode["episodeId"],
          "host" => @host,
          "kind" => episode["kind"],
          "key" => episode["key"],
          "statementKind" => RootPath.kind(finding),
          "statement" => RootActions.statement(stored, survivors, operator, finding),
          "finding" => finding,
          "operator" => operator,
          "trees" => survivors,
          "at" => System.system_time(:millisecond)
        },
        extra
      )
    end

    # A replacement adapter for the key runs: it registers with the guard.
    defp replacement_runs!(launch_id \\ "adapter-launch-2") do
      adapter = start_supervised!({FakeAdapter, test: self()}, id: {:adapter, launch_id})

      MemoryGuard.residency(
        adapter,
        {:claude, "shared", @host},
        launch_id,
        MapSet.new(["sid-new"])
      )

      _ = :sys.get_state(MemoryGuard)
      adapter
    end

    defp alert_rows(db) do
      {:ok, rows} =
        DB.query(
          db,
          "SELECT dedupeKey, title, body FROM owner_alerts WHERE kind='memory-guard-stuck' ORDER BY createdAt",
          []
        )

      rows
    end

    defp main_texts(db) do
      {:ok, rows} =
        DB.query(
          db,
          "SELECT content FROM messages WHERE sessionKey=?1 AND content LIKE '%memory-guard-recover%' ORDER BY seq",
          ["agent:main:clawline:owner:main"]
        )

      Enum.map(rows, &hd/1)
    end

    test "N1.absent (T30 b) / N2: a custody refusal held unbroken opens one episode, with exactly one owner alert and one Main notice",
         ctx do
      episode = custody_stuck!(ctx)

      assert %{"kind" => "custody", "key" => "claude:shared@testhost", "trees" => [tree]} =
               episode

      assert tree["launchId"] == "sl-stuck"
      id = episode["episodeId"]
      assert_received {:owner_alert, ^id}

      assert [{"agent:main:clawline:owner:main", %{"markerKey" => "memory-guard-stuck:" <> ^id}}] =
               events(ctx.db, "memory_guard_stuck_notified")

      # T30 (b): one owner alert row through the owner-alerts route, recorded
      # as created; it and the Main notice say, in plain words, the host,
      # what is held, why, the root recovery, the override and the current
      # root-path finding.
      sentence = RootPath.statement(strict_finding())
      assert [["memory-guard-stuck:" <> ^id, title, body]] = alert_rows(ctx.db)
      assert title =~ "testhost"

      for text <- [body | main_texts(ctx.db)] do
        assert text =~ "Tightbeam on testhost has held the replacement of the"
        assert text =~ "could not be confirmed stopped"
        assert text =~ "tightbeam memory-guard-recover --base #{ctx.base} #{id}"
        assert text =~ "An override exists only after a recovery has failed"
        assert text =~ "Root-path check now: " <> sentence
      end

      assert [{@host, %{"outcome" => "created", "alertId" => "oal_" <> _}}] =
               events(ctx.db, "memory_guard_stuck_alert")

      # Nothing more while it is open; the guard keeps retrying the end.
      :ok = MemoryGuard.tick()
      refute_received {:owner_alert, _}
      assert length(events(ctx.db, "memory_guard_stuck_notified")) == 1
      assert length(Episodes.active(ctx.db, @host)) == 1
      assert MemoryGuard.read(@host).stuckEpisodes |> hd() |> Map.get(:episodeId) == id
    end

    test "N1.unreadable: an episode whose record cannot be written is not opened; it is retried",
         ctx do
      {:ok, _} =
        DB.query(ctx.db, """
        CREATE TRIGGER fs9_fail_open BEFORE INSERT ON lifecycle_events
        WHEN NEW.kind='memory_guard_episode_opened'
        BEGIN SELECT RAISE(ABORT, 'injected'); END
        """)

      assert custody_stuck!(ctx) == nil
      {:ok, _} = DB.query(ctx.db, "DROP TRIGGER fs9_fail_open")
      :ok = MemoryGuard.tick()
      assert [%{"kind" => "custody"}] = Episodes.active(ctx.db, @host)
    end

    test "N1.stale: a refusal that clears before 15 minutes opens nothing", ctx do
      Application.put_env(:tightbeam, :memory_guard_stuck_ms, 15 * 60_000)
      assert custody_stuck!(ctx) == nil
      gone!(ctx.root, 951)
      :ok = MemoryGuard.tick()
      assert Episodes.active(ctx.db, @host) == []
      assert :sys.get_state(MemoryGuard).custody_refused == %{}
    end

    test "N2.absent (T30 c): with owner alerts off, the Main notice still goes and no alert is made",
         ctx do
      {:ok, _} = DB.query(ctx.db, "DELETE FROM org_settings WHERE key='owner-alerts-user'")
      %{"episodeId" => id} = custody_stuck!(ctx)
      assert [_] = events(ctx.db, "memory_guard_stuck_notified")
      assert [text] = main_texts(ctx.db)
      assert text =~ "Root-path check now: "
      assert alert_rows(ctx.db) == []
      refute_received {:owner_alert, _}
      assert [{@host, %{"outcome" => "off"}}] = events(ctx.db, "memory_guard_stuck_alert")
      assert [%{alert: "off", noticeSent: true, episodeId: ^id}] = Episodes.read(ctx.db, @host)
    end

    test "N2.unreadable / N2.partial / N2.timeout (T30 c): a broken or absent alert route is not alerts off: retried until made, once; one Main notice",
         ctx do
      # The route is broken: its table refuses the alert row.
      {:ok, _} =
        DB.query(ctx.db, """
        CREATE TRIGGER fs9_route_broken BEFORE INSERT ON owner_alerts
        BEGIN SELECT RAISE(ABORT, 'injected'); END
        """)

      %{"episodeId" => id} = custody_stuck!(ctx)
      refute_received {:owner_alert, _}
      assert events(ctx.db, "memory_guard_stuck_alert") == []
      assert [%{alert: nil, noticeSent: true}] = Episodes.read(ctx.db, @host)
      :ok = MemoryGuard.tick()
      assert events(ctx.db, "memory_guard_stuck_alert") == []

      # The route is absent altogether: still not sent, still retried.
      {:ok, _} = DB.query(ctx.db, "DROP TRIGGER fs9_route_broken")
      {:ok, _} = DB.query(ctx.db, "ALTER TABLE owner_alerts RENAME TO owner_alerts_away")
      :ok = MemoryGuard.tick()
      assert events(ctx.db, "memory_guard_stuck_alert") == []
      {:ok, _} = DB.query(ctx.db, "ALTER TABLE owner_alerts_away RENAME TO owner_alerts")

      :ok = MemoryGuard.tick()
      assert_received {:owner_alert, ^id}
      :ok = MemoryGuard.tick()
      refute_received {:owner_alert, _}
      assert [[_, _, body]] = alert_rows(ctx.db)
      assert body =~ "Root-path check now: "
      assert [{@host, %{"outcome" => "created"}}] = events(ctx.db, "memory_guard_stuck_alert")
      assert length(events(ctx.db, "memory_guard_stuck_notified")) == 1
    end

    test "N3 (T36): a custody episode ends only when every named tree is shown gone, recorded once",
         ctx do
      %{"episodeId" => id} = custody_stuck!(ctx)
      :ok = MemoryGuard.tick()
      assert [_] = Episodes.active(ctx.db, @host)
      gone!(ctx.root, 951)
      :ok = MemoryGuard.tick()
      assert Episodes.active(ctx.db, @host) == []
      assert [{^id, %{"reason" => _}}] = events(ctx.db, "memory_guard_episode_ended")
    end

    test "N3 (reboot) / N3.unreadable: a start on a new boot identity ends every episode; an unreadable boot identity ends none",
         ctx do
      {:opened, episode} =
        Episodes.open(ctx.db, %{host: @host, kind: "guard", since: 1, boot: "boot-a", why: "test"})

      # Boot identity unreadable: nothing is inferred.
      guard!(ctx)
      _ = :sys.get_state(MemoryGuard)

      assert [_] =
               Episodes.active(ctx.db, @host)
               |> Enum.filter(&(&1["episodeId"] == episode["episodeId"]))

      stop_supervised!(MemoryGuard)

      dir = Path.join(ctx.root, "proc/sys/kernel/random")
      File.mkdir_p!(dir)
      File.write!(Path.join(dir, "boot_id"), "boot-b\n")
      guard!(ctx)
      _ = :sys.get_state(MemoryGuard)
      id = episode["episodeId"]
      assert [{^id, %{"reason" => "reboot"}}] = events(ctx.db, "memory_guard_episode_ended")
    end

    test "N4 / N11 (T31 2): a root recovery that ends the named tree clears the episode", ctx do
      episode = custody_stuck!(ctx)
      root_record!(ctx, "recovery-1", recovery_record(episode, System.system_time(:millisecond)))
      gone!(ctx.root, 951)
      :ok = MemoryGuard.tick()

      assert %{"outcome" => "cleared"} = Episodes.recovery(ctx.db, episode["episodeId"])
      assert Episodes.active(ctx.db, @host) == []
    end

    test "N4.unreadable / N4.timeout (T31 3): a survivor still there 60 s after root's kill makes the recovery failed, with its state",
         ctx do
      episode = custody_stuck!(ctx)
      killed_at = System.system_time(:millisecond) - 61_000
      root_record!(ctx, "recovery-1", recovery_record(episode, killed_at))
      :ok = MemoryGuard.tick()

      assert %{
               "outcome" => "failed",
               "survivors" => [%{"launchId" => "sl-stuck", "state" => "S"}]
             } =
               Episodes.recovery(ctx.db, episode["episodeId"])

      assert [_] = Episodes.active(ctx.db, @host)
    end

    test "N4.absent: a recovery before its kill time and 60 s have passed stays pending; a pending recovery permits no override",
         ctx do
      episode = custody_stuck!(ctx)
      root_record!(ctx, "recovery-1", recovery_record(episode, System.system_time(:millisecond)))
      :ok = MemoryGuard.tick()
      assert %{"outcome" => "pending"} = Episodes.recovery(ctx.db, episode["episodeId"])
      root_record!(ctx, "override-1", override_record(ctx, episode, strict_finding()))
      :ok = MemoryGuard.tick()
      assert Episodes.override(ctx.db, episode["episodeId"]) == nil

      assert Enum.any?(events(ctx.db, "memory_guard_root_action_rejected"), fn {_, d} ->
               d["reason"] =~ "needs a failed recovery"
             end)
    end

    test "N11.unreadable / N11.absent / N11.stale (T34 c): records not root's, malformed, kindless, unreadable or not files are rejected, recorded once",
         ctx do
      episode = custody_stuck!(ctx, root_uid: 0)
      root_record!(ctx, "by-agent", recovery_record(episode, 1))
      root_record!(ctx, "dance", %{"kind" => "custody", "action" => "dance"})
      dir = RootActions.dir(ctx.base)
      File.write!(Path.join(dir, "malformed.json"), "{\"action\": \"recovery\", ")
      File.write!(Path.join(dir, "no-kind.json"), ~s({"action": "recovery", "episodeId": "x"}))
      File.write!(Path.join(dir, "array.json"), "[1, 2]")
      unreadable = Path.join(dir, "unreadable.json")
      File.write!(unreadable, JSON.encode!(recovery_record(episode, 1)))
      File.chmod!(unreadable, 0o000)
      on_exit(fn -> File.chmod(unreadable, 0o644) end)
      {_, 0} = System.cmd("mkfifo", [Path.join(dir, "fifo.json")])
      :ok = MemoryGuard.tick()

      reasons = for {_, d} <- events(ctx.db, "memory_guard_root_action_rejected"), do: d["reason"]
      assert "the record was not written by root" in reasons
      assert "the record is not valid JSON" in reasons
      assert "the record names no kind" in reasons
      assert "the record is not a JSON object" in reasons
      assert Enum.any?(reasons, &(&1 =~ "it is not a regular file (other)"))

      # Running as root, chmod 000 does not stop a read: then it is judged as
      # the agent-written record it is.
      if match?({:error, _}, File.read(unreadable)),
        do: assert(Enum.any?(reasons, &(&1 =~ "it cannot be read: eacces")))

      assert Episodes.recovery(ctx.db, episode["episodeId"]) == nil
      assert MemoryGuard.read(@host).rootActionsUnavailable == nil

      # Each is judged once: a later sample records nothing more.
      count = length(reasons)
      :ok = MemoryGuard.tick()
      assert length(events(ctx.db, "memory_guard_root_action_rejected")) == count

      # And root's next command run is told which records it may move aside.
      assert {:ok, listed} = File.read(RootActions.judged_list(ctx.base))

      assert %{"judged" => judged} = JSON.decode!(listed)
      assert "malformed.json" in judged and "fifo.json" in judged
    end

    test "N11.stale (T34 a, b, d): one digest is judged once, concurrently and after a restart; a record naming an ended episode is rejected for its successor",
         ctx do
      episode = custody_stuck!(ctx)
      record = recovery_record(episode, System.system_time(:millisecond))
      bytes = JSON.encode!(record)
      digest = :crypto.hash(:sha256, bytes) |> Base.encode16(case: :lower)

      results =
        1..4
        |> Enum.map(fn _ ->
          Task.async(fn -> Episodes.judge(ctx.db, record, digest, @host) end)
        end)
        |> Enum.map(&Task.await/1)

      assert Enum.count(results, &match?({:accepted, _}, &1)) == 1

      # After a restart the same record is still the one already judged.
      stop_supervised!(MemoryGuard)

      guard!(ctx,
        root_uid: ctx.uid,
        kill_result: {:error, :harness_group_failed},
        signal_works: false
      )

      assert {:rejected, "this record was already judged"} =
               Episodes.judge(ctx.db, record, digest, @host)

      # The episode ends; a new one opens on the same key; the old record is
      # rejected, because it names the ended episode.
      Episodes.finish(ctx.db, episode["episodeId"], "test")

      {:opened, _e2} =
        Episodes.open(ctx.db, %{
          host: @host,
          kind: "custody",
          key: episode["key"],
          since: 1,
          why: "t"
        })

      replay = Map.put(record, "note", "replayed")

      assert {:rejected, "the episode has ended"} =
               Episodes.judge(ctx.db, replay, "other-digest", @host)
    end

    test "N5.stale (T35, B5): an override whose statement is not exactly the one printed for its episode, survivors, operator and finding is refused",
         ctx do
      episode = custody_stuck!(ctx, finding: fn -> residual_finding() end)

      root_record!(
        ctx,
        "recovery-1",
        recovery_record(episode, System.system_time(:millisecond) - 61_000)
      )

      :ok = MemoryGuard.tick()
      assert %{"outcome" => "failed"} = Episodes.recovery(ctx.db, episode["episodeId"])

      rejected = fn ->
        for {_, d} <- events(ctx.db, "memory_guard_root_action_rejected"), do: d["reason"]
      end

      # The statement the strict finding selects, on a residual host.
      root_record!(ctx, "override-strict", override_record(ctx, episode, strict_finding()))
      :ok = MemoryGuard.tick()
      assert Episodes.override(ctx.db, episode["episodeId"]) == nil
      assert Enum.any?(rejected.(), &(&1 =~ "does not match the root-path finding"))

      # Forged same-kind bodies: a placeholder, and the real text with a tree
      # line changed, are refused.
      for {name, statement} <- [
            {"override-placeholder", "as printed"},
            {"override-edited",
             String.replace(
               override_record(ctx, episode, residual_finding())["statement"],
               "launch record sl-stuck",
               "launch record sl-other"
             )}
          ] do
        record =
          override_record(ctx, episode, residual_finding(), %{
            "statement" => statement,
            "note" => name
          })

        root_record!(ctx, name, record)
        :ok = MemoryGuard.tick()
        assert Episodes.override(ctx.db, episode["episodeId"]) == nil
      end

      assert Enum.count(rejected.(), &(&1 =~ "printed statement is not the one")) == 2

      # Trees that are not the failed recovery's survivors are refused.
      root_record!(
        ctx,
        "override-trees",
        override_record(ctx, episode, residual_finding(), %{"trees" => []})
      )

      :ok = MemoryGuard.tick()
      assert Enum.any?(rejected.(), &(&1 =~ "not the survivors"))

      # The exact statement is accepted, with the gateway's own finding.
      root_record!(ctx, "override-residual", override_record(ctx, episode, residual_finding()))
      :ok = MemoryGuard.tick()

      assert %{
               "finding" => %{"groups" => %{"result" => "present"}},
               "statementKind" => "residual",
               "statement" => statement
             } =
               Episodes.override(ctx.db, episode["episodeId"])

      assert statement =~ "launch record sl-stuck, process 951"
      assert statement =~ "Recorded as: root, invoked by george (uid 1000)."
      assert statement =~ "can gain root, here through groups (docker)"
      assert RootPath.kind(strict_finding()) == "strict"
    end

    test "N5 golden: the gateway's override statement is byte for byte the CLI's (same fixture)",
         _ctx do
      episode = %{
        "episodeId" => "ep_golden",
        "host" => "sirius",
        "kind" => "custody",
        "key" => "claude:shared@sirius",
        "why" => "1 agent processes could not be confirmed stopped"
      }

      survivors = [
        %{
          "launchId" => "sl-9",
          "pid" => 4242,
          "start" => 7,
          "unit" => "/tightbeam.slice/harness/session-sl-9",
          "state" => "D"
        }
      ]

      operator = %{"user" => "root", "sudoUser" => "george", "sudoUid" => "1000"}

      finding = %{
        "groups" => %{"result" => "present", "detail" => ["docker", "lxd"]},
        "sudo" => %{"result" => "unknown", "detail" => "no tty"},
        "sockets" => %{"result" => "absent", "detail" => []}
      }

      assert RootActions.statement(episode, survivors, operator, finding) ==
               "Episode ep_golden on sirius: Tightbeam holds the replacement of the " <>
                 "claude:shared@sirius adapter because 1 agent processes could not be " <>
                 "confirmed stopped.\n" <>
                 "  - launch record sl-9, process 4242 started at 7, unit " <>
                 "/tightbeam.slice/harness/session-sl-9, state D\n" <>
                 "Risk accepted: 1 agent processes could not be stopped, even by root. " <>
                 "Launching a replacement means they may keep using memory outside every " <>
                 "limit until they end or the machine reboots.\n" <>
                 "Recorded as: root, invoked by george (uid 1000).\n" <>
                 "This machine's agents run as a user that can gain root, here through " <>
                 "groups (docker, lxd); a path that could not be checked (sudo). So a " <>
                 "process with that access, including an agent breaking its rules, could " <>
                 "also run this override.\n"
    end

    test "N7.stale / N9.unreadable / N3.stale / N10.stale (T34 e, T31 3, T36 a): an accepted custody override lifts the fence for the named tree only, once; the episode stays open with its risk",
         ctx do
      episode = custody_stuck!(ctx)
      id = episode["episodeId"]

      root_record!(
        ctx,
        "recovery-1",
        recovery_record(episode, System.system_time(:millisecond) - 61_000)
      )

      :ok = MemoryGuard.tick()
      root_record!(ctx, "override-1", override_record(ctx, episode, strict_finding()))
      :ok = MemoryGuard.tick()
      assert %{"operator" => %{"sudoUser" => "george"}} = Episodes.override(ctx.db, id)

      # The replacement may launch: the fence no longer counts the named tree.
      # The override is applied once the replacement runs (FS9 B4).
      assert :ok = MemoryGuard.ensure_no_orphans({:claude, "shared", @host})
      assert %{"applied" => false} = Episodes.override(ctx.db, id)
      replacement_runs!()
      :ok = MemoryGuard.tick()
      assert %{"applied" => true} = Episodes.override(ctx.db, id)

      # A second, different override for the same episode is rejected.
      root_record!(
        ctx,
        "override-2",
        override_record(ctx, episode, strict_finding(), %{"note" => "again"})
      )

      :ok = MemoryGuard.tick()

      assert Enum.any?(events(ctx.db, "memory_guard_root_action_rejected"), fn {_, d} ->
               d["reason"] =~ "already accepted"
             end)

      # The episode stays open, its risk shown, until the tree is gone.
      [shown] = MemoryGuard.read(@host).stuckEpisodes
      assert shown.overridden and shown.risk =~ "outside every limit"
      gone!(ctx.root, 951)
      :ok = MemoryGuard.tick()
      assert MemoryGuard.read(@host).stuckEpisodes == []
    end

    test "N3.unreadable (B6): unlisted trees are unknown, never proof: the episode stays open until they are known and shown gone",
         ctx do
      insert_adapter_row!(ctx.db, "adapter-launch-1", 950)
      {:ok, _} = DB.query(ctx.db, "UPDATE harness_processes SET state='exited'")
      proc!(ctx.root, 951, 1, 951, 10 * @mib)
      launch!(ctx.base, "sl-stuck", "sid-stuck", 951, 951, 512 * @mib)
      # Tightbeam's own launch-record inventory cannot be read.
      bad = Path.join([Records.dir(ctx.base), "sessions", "sl-bad.json"])
      File.write!(bad, "{not json")

      guard!(ctx,
        kill_result: {:error, :harness_group_failed},
        signal_works: false,
        root_uid: ctx.uid
      )

      session!(ctx, "agent:new", "sid-new")
      queue!(ctx, "agent:new", "needs a new adapter")
      assert {:held, ["guard_unavailable"]} = MemoryGuard.admit("agent:new", ctx.db)

      # Sustained: many samples, one episode, never ended on an empty set.
      for _ <- 1..5, do: :ok = MemoryGuard.tick()

      assert [%{"episodeId" => id, "trees" => nil, "treesUnknown" => unknown}] =
               Enum.filter(Episodes.active(ctx.db, @host), &(&1["kind"] == "custody"))

      assert unknown =~ "sl-bad.json"
      assert events(ctx.db, "memory_guard_episode_ended") == []

      assert length(
               for {_, %{"kind" => "custody"}} <- events(ctx.db, "memory_guard_episode_opened"),
                   do: 1
             ) == 1

      assert [%{trees: "unknown: " <> _}] =
               Enum.filter(MemoryGuard.read(@host).stuckEpisodes, &(&1.kind == "custody"))

      # Root cannot recover unknown trees: the episode it publishes names none.
      assert {:ok, published} =
               File.read(Path.join([Records.dir(ctx.base), "episodes", id <> ".json"]))

      assert %{"trees" => nil} = JSON.decode!(published)

      # The inventory reads again: the trees are named, and still not gone.
      File.rm!(bad)
      :ok = MemoryGuard.tick()

      assert [%{"trees" => [%{"launchId" => "sl-stuck"}]}] =
               Enum.filter(Episodes.active(ctx.db, @host), &(&1["kind"] == "custody"))

      assert events(ctx.db, "memory_guard_episode_ended")
             |> Enum.filter(fn {subject, _} -> subject == id end) == []

      gone!(ctx.root, 951)
      :ok = MemoryGuard.tick()
      :ok = MemoryGuard.tick()

      assert [{^id, %{"reason" => "every named tree is shown gone"}}] =
               events(ctx.db, "memory_guard_episode_ended")
               |> Enum.filter(fn {subject, _} -> subject == id end)
    end

    test "B7: an already judged root record costs no read or lookup; many records are judged once",
         ctx do
      episode = custody_stuck!(ctx)
      dir = RootActions.dir(ctx.base)
      File.mkdir_p!(dir)

      for n <- 1..2_000 do
        File.write!(
          Path.join(dir, "recovery-#{n}.json"),
          JSON.encode!(Map.put(recovery_record(episode, 1), "host", "elsewhere-#{n}"))
        )
      end

      :ok = MemoryGuard.tick()
      seen = :sys.get_state(MemoryGuard).root_seen
      assert MapSet.size(seen) == 2_000
      assert length(events(ctx.db, "memory_guard_root_action_rejected")) == 2_000

      # With the judged set, a pass needs no database at all: an unreachable
      # one is never asked.
      assert %{seen: ^seen, error: nil} =
               RootActions.intake(:no_such_db, ctx.base, @host, root_uid: ctx.uid, seen: seen)

      # A record changed in place is a new record.
      changed = Path.join(dir, "recovery-1.json")
      File.write!(changed, JSON.encode!(Map.put(recovery_record(episode, 1), "host", "other")))
      File.touch!(changed, System.os_time(:second) + 5)

      assert %{error: error} =
               RootActions.intake(:no_such_db, ctx.base, @host, root_uid: ctx.uid, seen: seen)

      assert error =~ "recovery-1.json"
    end

    test "N9.unreadable / N9.stale (FS9 B4, R2, custody): override_applied only once the replacement runs; a failed record is retried; a restart in the gap records it once",
         ctx do
      episode = custody_stuck!(ctx)
      id = episode["episodeId"]

      root_record!(
        ctx,
        "recovery-1",
        recovery_record(episode, System.system_time(:millisecond) - 61_000)
      )

      :ok = MemoryGuard.tick()
      root_record!(ctx, "override-1", override_record(ctx, episode, strict_finding()))
      :ok = MemoryGuard.tick()

      # The fence is lifted for the named tree, but nothing has launched yet:
      # nothing is recorded as applied, sample after sample.
      key = {:claude, "shared", @host}
      assert :ok = MemoryGuard.ensure_no_orphans(key)
      :ok = MemoryGuard.tick()
      assert %{"applied" => false} = Episodes.override(ctx.db, id)
      assert events(ctx.db, "memory_guard_override_applied") == []

      # The gap: the gateway restarts after the fence was lifted and before
      # the replacement ran. The override is still only accepted.
      stop_supervised!(MemoryGuard)

      guard!(ctx,
        kill_result: {:error, :harness_group_failed},
        signal_works: false,
        root_uid: ctx.uid
      )

      assert :ok = MemoryGuard.ensure_no_orphans(key)
      assert %{"applied" => false} = Episodes.override(ctx.db, id)

      # The replacement runs, but the record cannot be written: still only
      # accepted, and retried.
      {:ok, _} =
        DB.query(ctx.db, """
        CREATE TRIGGER fs9_applied_fails BEFORE UPDATE OF applied ON memory_guard_episodes
        BEGIN SELECT RAISE(ABORT, 'injected'); END
        """)

      replacement_runs!()
      :ok = MemoryGuard.tick()
      assert %{"applied" => false} = Episodes.override(ctx.db, id)

      {:ok, _} = DB.query(ctx.db, "DROP TRIGGER fs9_applied_fails")
      :ok = MemoryGuard.tick()
      :ok = MemoryGuard.tick()
      assert %{"applied" => true} = Episodes.override(ctx.db, id)
      assert [{^id, _}] = events(ctx.db, "memory_guard_override_applied")
    end

    test "N10.unreadable: an episode read that cannot be completed says unknown, never none",
         _ctx do
      assert %{unknown: _} = Episodes.read(:no_such_db, @host)
    end
  end

  describe "matrix N: the guard down (FS9, Watcher)" do
    alias Tightbeam.MemoryGuard.{Episodes, RootActions, RootPath, Watcher}

    setup ctx do
      meminfo!(ctx.root, 16 * @gib, 12 * @gib)
      Application.put_env(:tightbeam, :memory_guard_stuck_ms, 0)
      Application.put_env(:tightbeam, :memory_guard_restart_wait_ms, 20)

      on_exit(fn ->
        Application.delete_env(:tightbeam, :memory_guard_stuck_ms)
        Application.delete_env(:tightbeam, :memory_guard_restart_wait_ms)
        MemoryGuard.expect(false)
      end)

      {:ok, _} =
        DB.query(ctx.db, "UPDATE users SET createdAt=createdAt+1000 WHERE userId='guest'")

      main!(ctx, "owner")
      session!(ctx, "agent:new", "sid-new")
      queue!(ctx, "agent:new", "needs a launch")
      MemoryGuard.expect(true)
      assert {:held, ["guard_unavailable"]} = MemoryGuard.admit("agent:new", ctx.db)
      test = self()
      clock = :counters.new(1, [])
      :counters.put(clock, 1, System.system_time(:millisecond))

      watcher =
        start_supervised!(
          {Watcher,
           db: ctx.db,
           base_dir: ctx.base,
           local_host: @host,
           interval_ms: :manual,
           name: :mg_watcher_test,
           clock: fn -> :counters.get(clock, 1) end,
           guard_running?: fn -> Process.whereis(MemoryGuard) != nil end,
           root_uid: File.stat!(ctx.root).uid,
           finding: fn -> strict_finding() end,
           started: :counters.get(clock, 1),
           owner_alert: fn txn, input ->
             result = Tightbeam.OwnerAlerts.memory_guard_stuck_in_txn(txn, input)
             if match?({:created, _}, result), do: send(test, {:owner_alert, input.episode_id})
             result
           end}
        )

      %{watcher: watcher, clock: clock}
    end

    # The gateway service restarts: a new watcher whose start is now.
    defp restart_watcher!(ctx) do
      test = self()
      stop_supervised!(Watcher)

      start_supervised!(
        {Watcher,
         db: ctx.db,
         base_dir: ctx.base,
         local_host: @host,
         interval_ms: :manual,
         name: :mg_watcher_test,
         clock: fn -> :counters.get(ctx.clock, 1) end,
         guard_running?: fn -> Process.whereis(MemoryGuard) != nil end,
         root_uid: File.stat!(ctx.root).uid,
         finding: fn -> strict_finding() end,
         started: :counters.get(ctx.clock, 1),
         owner_alert: fn txn, input ->
           result = Tightbeam.OwnerAlerts.memory_guard_stuck_in_txn(txn, input)
           if match?({:created, _}, result), do: send(test, {:owner_alert, input.episode_id})
           result
         end}
      )
    end

    defp guard_record!(ctx, episode, action, extra \\ %{}) do
      dir = RootActions.dir(ctx.base)
      File.mkdir_p!(dir)

      record =
        Map.merge(
          %{
            "v" => 1,
            "action" => action,
            "episodeId" => episode["episodeId"],
            "host" => @host,
            "kind" => "guard",
            "key" => nil,
            "operator" => %{"user" => "root", "sudoUser" => "unknown", "sudoUid" => "unknown"},
            # Root wrote it now.
            "at" => :counters.get(ctx.clock, 1)
          },
          extra
        )

      File.write!(
        Path.join(dir, action <> "-" <> episode["episodeId"] <> ".json"),
        JSON.encode!(record)
      )
    end

    test "N1.absent (T30 a): launches held because the guard is down for 15 minutes open one guard episode, with one alert and one Main notice; it ends when the guard answers",
         ctx do
      Org.put_setting(ctx.db, "owner-alerts-user", "owner")
      :ok = Watcher.tick(:mg_watcher_test)
      assert [%{"kind" => "guard", "episodeId" => id}] = Episodes.active(ctx.db, @host)
      assert_received {:owner_alert, ^id}
      assert [_] = events(ctx.db, "memory_guard_stuck_notified")

      {:ok, [[body]]} =
        DB.query(ctx.db, "SELECT body FROM owner_alerts WHERE dedupeKey=?1", [
          "memory-guard-stuck:" <> id
        ])

      assert body =~ "has held new agent launches"
      assert body =~ "because the memory guard is not running"
      assert body =~ "Root-path check now: " <> RootPath.statement(strict_finding())

      :ok = Watcher.tick(:mg_watcher_test)
      refute_received {:owner_alert, _}

      guard!(ctx)
      :ok = MemoryGuard.tick()
      assert Episodes.active(ctx.db, @host) == []

      assert [{^id, %{"reason" => "the memory guard answers"}}] =
               events(ctx.db, "memory_guard_episode_ended")
    end

    test "N4.absent / N4.unreadable / N4.timeout (guard, B2): pending without a restart; the first start that finds it starts the 5-minute clock",
         ctx do
      :ok = Watcher.tick(:mg_watcher_test)
      [episode] = Episodes.active(ctx.db, @host)
      guard_record!(ctx, episode, "recovery")
      :ok = Watcher.tick(:mg_watcher_test)

      assert %{"outcome" => "pending", "startedAt" => nil} =
               Episodes.recovery(ctx.db, episode["episodeId"])

      # No restart: still pending long after.
      :counters.add(ctx.clock, 1, 60 * 60_000)
      :ok = Watcher.tick(:mg_watcher_test)

      assert %{"outcome" => "pending", "startedAt" => nil} =
               Episodes.recovery(ctx.db, episode["episodeId"])

      # Root restarts the service; the new start finds the pending recovery.
      :counters.add(ctx.clock, 1, 1_000)
      restart_watcher!(ctx)
      started = :counters.get(ctx.clock, 1)
      :ok = Watcher.tick(:mg_watcher_test)

      assert %{"outcome" => "pending", "startedAt" => ^started} =
               Episodes.recovery(ctx.db, episode["episodeId"])

      assert [{_, %{"startedAt" => ^started}}] = events(ctx.db, "memory_guard_recovery_started")

      :counters.add(ctx.clock, 1, 5 * 60_000 - 1)
      :ok = Watcher.tick(:mg_watcher_test)
      assert %{"outcome" => "pending"} = Episodes.recovery(ctx.db, episode["episodeId"])

      # A second restart does not move the clock.
      restart_watcher!(ctx)
      :counters.add(ctx.clock, 1, 1)
      :ok = Watcher.tick(:mg_watcher_test)
      assert %{"outcome" => "failed"} = Episodes.recovery(ctx.db, episode["episodeId"])
    end

    test "N4.stale (guard): a pending guard recovery is cleared once, ending its episode, when the guard answers",
         ctx do
      :ok = Watcher.tick(:mg_watcher_test)
      [episode] = Episodes.active(ctx.db, @host)
      guard_record!(ctx, episode, "recovery")
      :ok = Watcher.tick(:mg_watcher_test)
      guard!(ctx)
      :ok = MemoryGuard.tick()
      assert %{"outcome" => "cleared"} = Episodes.recovery(ctx.db, episode["episodeId"])
      assert Episodes.active(ctx.db, @host) == []
    end

    test "N9 (guard) / T36 b: after a failed recovery, a root override admits the held launches without the guard; the risk stays shown until it answers",
         ctx do
      :ok = Watcher.tick(:mg_watcher_test)
      [episode] = Episodes.active(ctx.db, @host)
      guard_record!(ctx, episode, "recovery")
      :ok = Watcher.tick(:mg_watcher_test)
      :counters.add(ctx.clock, 1, 1_000)
      restart_watcher!(ctx)
      :ok = Watcher.tick(:mg_watcher_test)
      :counters.add(ctx.clock, 1, 6 * 60_000)
      :ok = Watcher.tick(:mg_watcher_test)
      assert %{"outcome" => "failed"} = Episodes.recovery(ctx.db, episode["episodeId"])

      stored = Episodes.get(ctx.db, episode["episodeId"])
      operator = %{"user" => "root", "sudoUser" => "unknown", "sudoUid" => "unknown"}

      guard_record!(ctx, episode, "override", %{
        "statementKind" => "strict",
        "statement" => RootActions.statement(stored, [], operator, strict_finding()),
        "trees" => []
      })

      :ok = Watcher.tick(:mg_watcher_test)
      assert %{"applied" => false} = Episodes.override(ctx.db, episode["episodeId"])

      assert :ok = MemoryGuard.admit("agent:new", ctx.db)
      assert %{"applied" => true} = Episodes.override(ctx.db, episode["episodeId"])

      assert [%{overridden: true, risk: risk}] = Episodes.read(ctx.db, @host)
      assert risk =~ "without the memory guard"
      assert [_] = Episodes.active(ctx.db, @host)
    end
  end

  ## T35 (FS9 Step 2, PO att_b685f272): the root-path check, one mechanism at a time

  describe "matrix N5 / T35: the root-path check" do
    alias Tightbeam.MemoryGuard.RootPath

    defp runner(id_groups, sudo, writable) do
      fn
        "id", ["-Gn"] -> id_groups
        "sudo", ["-n", "-l"] -> sudo
        "test", ["-w", path] -> if path in writable, do: {"", 0}, else: {"", 1}
      end
    end

    setup do
      dir = Path.join(System.tmp_dir!(), "tb-t35-#{System.unique_integer([:positive])}")
      File.mkdir_p!(dir)
      socket = Path.join(dir, "docker.sock")
      File.write!(socket, "")
      on_exit(fn -> File.rm_rf!(dir) end)
      %{socket: socket}
    end

    @no_sudo {"sudo: a password is required\n", 1}

    test "T35 (a): as gd on Sirius (docker, lxd, a passwordless sudo entry): residual, naming each path",
         ctx do
      finding =
        RootPath.finding(
          runner: runner({"gd docker lxd\n", 0}, {"(ALL) NOPASSWD: ALL\n", 0}, []),
          sockets: [ctx.socket]
        )

      assert RootPath.kind(finding) == "residual"
      statement = RootPath.statement(finding)
      assert statement =~ "groups (docker, lxd)"
      assert statement =~ "a passwordless sudo entry"
    end

    test "T35 (b) and (c): only docker membership, then only a passwordless sudo entry: residual",
         ctx do
      docker =
        RootPath.finding(runner: runner({"gd docker\n", 0}, @no_sudo, []), sockets: [ctx.socket])

      assert %{"groups" => %{"result" => "present"}, "sudo" => %{"result" => "absent"}} = docker
      assert RootPath.kind(docker) == "residual"

      sudo =
        RootPath.finding(
          runner: runner({"gd\n", 0}, {"(ALL) NOPASSWD: /bin/x\n", 0}, []),
          sockets: [ctx.socket]
        )

      assert %{"groups" => %{"result" => "absent"}, "sudo" => %{"result" => "present"}} = sudo
      assert RootPath.kind(sudo) == "residual"
    end

    test "T35 (d): only write access to the Docker socket (for example through an ACL): residual",
         ctx do
      finding =
        RootPath.finding(
          runner: runner({"gd\n", 0}, @no_sudo, [ctx.socket]),
          sockets: [ctx.socket]
        )

      assert %{"sockets" => %{"result" => "present", "detail" => [_]}} = finding
      assert RootPath.kind(finding) == "residual"
    end

    test "T35 (e) / N5.absent: none of them: strict, saying unchecked paths cannot be ruled out",
         ctx do
      finding = RootPath.finding(runner: runner({"gd\n", 0}, @no_sudo, []), sockets: [ctx.socket])
      assert RootPath.kind(finding) == "strict"
      assert RootPath.statement(finding) =~ "cannot be ruled out"
    end

    test "T35 (f) / N5.unreadable / N5.timeout: a mechanism that cannot be evaluated is unknown, and the statement is residual",
         ctx do
      failing = fn
        "id", _ -> {:error, "id is not installed"}
        "sudo", _ -> raise "sudo hung up"
        "test", _ -> {"", 2}
      end

      finding = RootPath.finding(runner: failing, sockets: [ctx.socket])
      assert Enum.all?(Map.values(finding), &(&1["result"] == "unknown"))
      assert RootPath.kind(finding) == "residual"
      assert RootPath.statement(finding) =~ "a path that could not be checked"
    end
  end

  describe "T32 (FS3, FS8, FS9)" do
    alias Tightbeam.MemoryGuard.{Episodes, RootActions}

    test "T32: enforced switched to off, limits not all lifted, a pre-off survivor: off not applied and no bypass; the survivor keeps the replacement refused; one alert; root recovery clears the fence only on proof",
         ctx do
      Application.put_env(:tightbeam, :memory_guard_stuck_ms, 0)
      on_exit(fn -> Application.delete_env(:tightbeam, :memory_guard_stuck_ms) end)

      {:ok, _} =
        DB.query(ctx.db, "UPDATE users SET createdAt=createdAt+1000 WHERE userId='guest'")

      main!(ctx, "owner")
      :ok = Org.put_setting(ctx.db, "owner-alerts-user", "owner")
      {harness, unit, set_mode} = enforced_with_unit!(ctx)

      # A session tree launched before the switch, of an adapter that has
      # since ended; its unit still holds it.
      insert_adapter_row!(ctx.db, "adapter-launch-1", 950)
      {:ok, _} = DB.query(ctx.db, "UPDATE harness_processes SET state='exited'")
      pre = Path.join(harness, "session-pre")
      File.mkdir_p!(pre)
      File.write!(Path.join(pre, "cgroup.events"), "populated 1\nfrozen 0\n")
      proc!(ctx.root, 960, 1, 960, 10 * @mib)

      File.write!(
        Path.join([Records.dir(ctx.base), "sessions", "sl-pre.json"]),
        JSON.encode!(%{
          v: 1,
          launchId: "sl-pre",
          sessionId: "pre",
          pid: 960,
          start: 960,
          adapterLaunchId: "adapter-launch-1",
          placement: "enforced",
          unit: "/svc/tightbeam.service/harness/session-pre",
          sessionLimit: 536_870_912
        })
      )

      # The switch to off cannot lift every limit.
      File.chmod!(Path.join(unit, "memory.max"), 0o444)
      on_exit(fn -> File.chmod(Path.join(unit, "memory.max"), 0o644) end)
      assert {:error, {:not_applied, _}} = set_mode.("off")
      read = MemoryGuard.read(@host)
      assert read.mode == "watched"
      assert read.notEnforcedReason =~ "off is not yet in effect"
      assert read.notEnforcedReason =~ "still in force"
      # No launch is admitted through the off bypass while it is incomplete.
      refute Unguarded.mode_in_force(ctx.db, @host) == "off"

      # The pre-off survivor keeps the replacement adapter refused (FS8).
      session!(ctx, "agent:new", "sid-new")
      queue!(ctx, "agent:new", "needs a new adapter")
      assert {:held, ["guard_unavailable"]} = MemoryGuard.admit("agent:new", ctx.db)
      :ok = MemoryGuard.tick()

      assert [%{"kind" => "custody", "episodeId" => id} = episode] =
               Episodes.active(ctx.db, @host)

      assert_received {:owner_alert, ^id}

      # Root's recovery ends the survivor; the fence clears on proof.
      File.mkdir_p!(RootActions.dir(ctx.base))

      File.write!(
        Path.join(RootActions.dir(ctx.base), "recovery.json"),
        JSON.encode!(%{
          v: 1,
          action: "recovery",
          episodeId: id,
          host: @host,
          kind: "custody",
          key: episode["key"],
          killedAt: System.system_time(:millisecond)
        })
      )

      File.write!(Path.join(pre, "cgroup.events"), "populated 0\nfrozen 0\n")
      gone!(ctx.root, 960)
      stop_supervised!(MemoryGuard)

      guard!(ctx,
        probe: enforced_probe(),
        cgroup_fs: Path.join(ctx.root, "sys/fs/cgroup"),
        root_uid: File.stat!(ctx.root).uid
      )

      :ok = MemoryGuard.tick()
      :ok = MemoryGuard.tick()
      assert %{"outcome" => "cleared"} = Episodes.recovery(ctx.db, id)
      assert Episodes.active(ctx.db, @host) == []
      assert :ok = MemoryGuard.ensure_no_orphans({:claude, "shared", @host})
    end
  end

  ## The remaining matrix v4 cells, one test each

  describe "matrix cells: the rest" do
    alias Tightbeam.MemoryGuard.{Episodes, ProcTree, RootActions, RootPath}

    setup ctx do
      meminfo!(ctx.root, 16 * @gib, 12 * @gib)
      on_exit(fn -> MemoryGuard.expect(false) end)
      :ok
    end

    test "A1.absent / A6.absent / A7.absent: with no guard configured, a launch is admitted, the read says no guard runs, and a stored setting is not applied",
         ctx do
      MemoryGuard.expect(false)
      session!(ctx, "agent:new", "sid-new")
      queue!(ctx, "agent:new", "go")
      assert :ok = MemoryGuard.admit("agent:new", ctx.db)
      handlers = Gateway.handlers(%{db: ctx.db, base_dir: ctx.base})

      assert %{code: "memory_guard_unavailable"} =
               handlers["host-memory"].(%{origin: "user:owner", params: %{host: @host}})

      session!(ctx, "agent:admin-session")

      result =
        handlers["host-memory-set"].(%{
          origin: "user:owner",
          principal: {:session, "agent:admin-session"},
          params: %{host: @host, name: "residentCap", value: "4"}
        })

      assert result.effect =~ "NOT applied: no memory guard runs"
    end

    test "A6.timeout: a guard that does not answer the read is said so, never a mode", ctx do
      guard!(ctx)
      :sys.suspend(MemoryGuard)

      try do
        assert %{mode: "unknown", error: error} = MemoryGuard.read(@host)
        assert error =~ "did not answer"
      after
        :sys.resume(MemoryGuard)
      end
    end

    test "A5.unreadable: with the guard down, a kill cannot be attributed: harness_exited, never a guess",
         ctx do
      guard!(ctx)
      stop_supervised!(MemoryGuard)
      assert MemoryGuard.memory_kill(%{host: @host, harness_session_id: "sid-x", since: 0}) == nil
    end

    test "B1.partial: a launch record still being written (.pending) is never read as a record",
         ctx do
      dir = Path.join(Records.dir(ctx.base), "sessions")
      File.mkdir_p!(dir)
      File.write!(Path.join(dir, "sl-half.json.pending"), "{\"v\":1,\"launchId\":\"sl-half\"")
      assert Records.read_all(ctx.base) == {:ok, %{}}
    end

    for variant <- [:unreadable, :partial, :stale] do
      @tag variant: variant
      test "B4.#{variant}: restoring unit limits on entering enforced reads the inventory, never guesses it",
           ctx do
        {_harness, _unit, set_mode} = enforced_with_unit!(ctx)
        :ok = MemoryGuard.tick()
        assert :ok = set_mode.("off")
        sessions = Path.join(Records.dir(ctx.base), "sessions")
        on_exit(fn -> File.chmod(sessions, 0o755) end)

        case ctx.variant do
          :unreadable ->
            File.chmod!(sessions, 0o000)
            assert {:error, {:not_applied, _}} = set_mode.("auto")
            assert MemoryGuard.read(@host).mode == "watched"

          :partial ->
            File.write!(Path.join(sessions, "sl-bad.json"), "{not json")
            assert {:error, {:not_applied, _}} = set_mode.("auto")
            assert MemoryGuard.read(@host).mode == "watched"

          :stale ->
            # A record whose unit no longer exists is skipped.
            launch!(ctx.base, "sl-old", "old", 2, 2, 512 * @mib)
            assert :ok = set_mode.("auto")
            assert MemoryGuard.read(@host).mode == "enforced"
        end
      end
    end

    test "C1.partial: a cgroup.events without its populated key is unreadable, never empty",
         ctx do
      fs = Path.join(ctx.root, "cg")
      dir = Cgroup.dir(fs, "/h/session-p")
      File.mkdir_p!(dir)
      File.write!(Path.join(dir, "cgroup.events"), "frozen 0\n")
      assert Cgroup.populated?(fs, "/h/session-p") == :unreadable
    end

    for {cell, target} <- [{"C2.absent", :harness}, {"C3.absent", :unit}] do
      @tag target: target
      test "#{cell}: a missing counter is a failed reading (C2) or an unknown size (C3), never 0",
           ctx do
        {harness, unit, _set_mode} = enforced_with_unit!(ctx)

        case ctx.target do
          :harness ->
            File.rm!(Path.join(harness, "memory.current"))
            :ok = MemoryGuard.tick()
            assert [%{reading: "budget_total"}] = MemoryGuard.read(@host).unavailable

          :unit ->
            File.rm!(Path.join(unit, "memory.current"))
            File.write!(Path.join(harness, "memory.current"), "100")
            :ok = MemoryGuard.tick()
            read = MemoryGuard.read(@host)
            assert read.unavailable == []
            assert read.tightbeamTotalBytes == 100
        end
      end
    end

    test "C4.absent / C4.unreadable / C4.stale: kernel attribution from a unit's counters, re-read briefly while they lag",
         ctx do
      Application.put_env(:tightbeam, :memory_guard_counter_retry_ms, 50)
      on_exit(fn -> Application.delete_env(:tightbeam, :memory_guard_counter_retry_ms) end)
      {harness, _unit, _set_mode} = enforced_with_unit!(ctx)
      match = %{host: @host, harness_session_id: "k", since: 0}

      # absent: no unit, no counters: no kernel attribution.
      assert MemoryGuard.memory_kill(match) == nil

      unit = Path.join(harness, "session-k")
      File.mkdir_p!(unit)
      events = Path.join(unit, "memory.events.local")
      File.write!(events, "oom 1\noom_kill 1\noom_group_kill 1\n")
      on_exit(fn -> File.chmod(events, 0o644) end)

      # unreadable: no attribution.
      File.chmod!(events, 0o000)
      assert MemoryGuard.memory_kill(match) == nil
      File.chmod!(events, 0o644)

      # stale: the counters move just after the first read.
      File.write!(events, "oom 0\noom_kill 0\noom_group_kill 0\n")

      Task.start(fn ->
        Process.sleep(80)
        File.write!(events, "oom 1\noom_kill 1\noom_group_kill 1\n")
      end)

      assert %{limit: "session", mode: "enforced"} = MemoryGuard.memory_kill(match)
    end

    test "C5.absent / C5.unreadable: memory.peak is evidence only; without it the kernel's end is still recorded",
         ctx do
      {harness, unit, _set_mode} = enforced_with_unit!(ctx)
      File.write!(Path.join(unit, "memory.events.local"), "oom 1\noom_kill 1\noom_group_kill 1\n")
      File.write!(Path.join(unit, "cgroup.events"), "populated 0\n")
      File.write!(Path.join(harness, "memory.current"), "0")
      :ok = MemoryGuard.tick()

      assert [{_, %{"limit" => "session", "bytes" => nil}}] = events(ctx.db, "memory_tree_ended")
    end

    for variant <- [:absent, :unreadable, :partial] do
      @tag variant: variant
      test "C6.#{variant}: a layout the guard cannot set up leaves the host watched, with the reason, never enforced",
           ctx do
        fs =
          cgroup_tree!(ctx.root, "/svc/tightbeam.service/gateway",
            read_only: ctx.variant == :unreadable
          )

        root_dir = Path.join(fs, "svc/tightbeam.service")

        case ctx.variant do
          :absent ->
            File.chmod!(root_dir, 0o555)

          :partial ->
            harness = Path.join(root_dir, "harness")
            File.mkdir_p!(harness)
            File.write!(Path.join(harness, "memory.max"), "max")
            File.chmod!(Path.join(harness, "memory.max"), 0o444)

          :unreadable ->
            :ok
        end

        on_exit(fn -> File.chmod(root_dir, 0o755) end)
        guard!(ctx, probe: enforced_probe(), cgroup_fs: fs)
        read = MemoryGuard.read(@host)
        assert read.mode == "watched"
        assert is_binary(read.notEnforcedReason)
      end
    end

    test "C9.absent / C9.unreadable / C9.partial: cgroup.kill on a gone unit is nothing to do; one that cannot be written falls back to the tree kill; a unit still populated is no end",
         ctx do
      fs = Path.join(ctx.root, "cg")
      host_state = %{layout: %{fs: fs}}

      # Nothing to kill, and no signal sent (rev 3 D1: not a proven send).
      assert {:error, :unit_gone} =
               MemoryGuard.default_kill(%{scope: "session", unit: "/h/session-gone"}, host_state)

      dir = Cgroup.dir(fs, "/h/session-c")
      File.mkdir_p!(dir)
      kill_file = Path.join(dir, "cgroup.kill")
      File.write!(kill_file, "")
      File.chmod!(kill_file, 0o444)
      on_exit(fn -> File.chmod(kill_file, 0o644) end)
      # Unwritable cgroup.kill: the group kill runs instead (no identity here).
      assert {:error, :no_identity} =
               MemoryGuard.default_kill(%{scope: "session", unit: "/h/session-c"}, host_state)

      File.chmod!(kill_file, 0o644)
      File.write!(Path.join(dir, "cgroup.events"), "populated 1\n")
      state = %{root: ctx.root, killer: &MemoryGuard.default_kill/2, signaller: fn _ -> :ok end}

      assert {:error, {:tree_survives, :ok}} =
               MemoryGuard.end_tree(state, host_state, %{
                 scope: "session",
                 pid: 4_000_001,
                 start: 1,
                 unit: "/h/session-c"
               })
    end

    test "C10.absent: a unit already gone is removed without error", ctx do
      assert :ok = Cgroup.remove(Path.join(ctx.root, "cg"), "/h/session-none")
    end

    test "D1.timeout / D2.timeout: a helper that times out is a failure, never an end", ctx do
      insert_adapter_row!(ctx.db, "adapter-launch-1", 950)
      proc!(ctx.root, 951, 950, 951, 10 * @mib)
      launch!(ctx.base, "sl-a", "sid-a", 951, 951, 512 * @mib)
      guard!(ctx, kill_result: {:error, :timeout}, signal_works: false)

      assert {:error, {:session_trees_survive, ["sl-a"]}} =
               MemoryGuard.adapter_ended({:claude, "shared", @host}, "adapter-launch-1")
    end

    test "D2.stale / D1.stale / E2.stale: a recorded pid now used by another process is not ours: never signalled, and the record is released",
         ctx do
      insert_adapter_row!(ctx.db, "adapter-launch-1", 950)
      # Recorded with start 1; the pid now runs another process (start 999).
      proc!(ctx.root, 970, 1, 999, 900 * @mib)
      launch!(ctx.base, "sl-reused", "sid-r", 970, 1, 512 * @mib)
      guard!(ctx)

      :ok = MemoryGuard.tick()
      refute_received {:killed, _}
      assert events(ctx.db, "memory_kill_intent") == []
      assert Records.read_all(ctx.base) == {:ok, %{}}
      assert File.dir?(Path.join(ctx.root, "proc/970"))
    end

    test "D3.timeout / K5.timeout: a close that times out stays resident and counted, recorded",
         ctx do
      meminfo!(ctx.root, 16 * @gib, div(16 * @gib * 10, 100))
      adapter = adapter!()
      session!(ctx, "agent:idle", "sid-idle")
      guard!(ctx, close_result: {:error, :timeout})
      resident!(adapter, ["sid-idle"])
      :ok = MemoryGuard.tick()
      settle_closes!()
      assert [{"agent:idle", %{"error" => error}}] = events(ctx.db, "memory_guard_close_failed")
      assert error =~ "timeout"
      assert MemoryGuard.read(@host).residentCount == 1
    end

    test "E3.absent / E3.partial: a process that ended is not counted and not unreadable; a zombie's missing VmRSS counts 0",
         ctx do
      refute ProcTree.unreadable?(ctx.root, 123_456)
      dir = Path.join(ctx.root, "proc/990")
      File.mkdir_p!(dir)
      zeros = Enum.map_join(1..17, " ", fn _ -> "0" end)
      File.write!(Path.join(dir, "stat"), "990 (zombie) Z 1 #{zeros} 990 0 0\n")
      File.write!(Path.join(dir, "status"), "Name:\tzombie\n")
      assert {:ok, %{state: "Z", bytes: 0}} = ProcTree.read(Path.join(ctx.root, "proc"), 990)
    end

    test "E5.partial: a meminfo without MemAvailable is a failed reading: R5 unavailable", ctx do
      File.write!(Path.join(ctx.root, "proc/meminfo"), "MemTotal: 16000000 kB\n")
      guard!(ctx)
      :ok = MemoryGuard.tick()
      assert [%{reading: "meminfo", disables: ["R5"]}] = MemoryGuard.read(@host).unavailable
    end

    test "F1.absent: leaving enforced when the units cannot be listed (the budget group has gone) is not applied",
         ctx do
      {harness, _unit, set_mode} = enforced_with_unit!(ctx)
      File.rm_rf!(harness)
      assert {:error, {:not_applied, error}} = set_mode.("off")
      assert error =~ "cannot be listed"
      assert MemoryGuard.read(@host).mode == "watched"
    end

    test "F5.timeout / F5.unreadable: a systemctl that does not answer is no delegation: watched with the reason",
         ctx do
      cgroup_tree!(ctx.root, "/system.slice/tightbeam.service/gateway", [])

      result =
        Probe.probe(
          root: ctx.root,
          os: {:unix, :linux},
          systemctl: fn _ -> {:error, :timeout} end
        )

      assert result.mode == :watched
      assert is_binary(result.reason)
    end

    test "F5.stale: a settings change re-probes the host", ctx do
      probes = :counters.new(1, [])

      guard!(ctx,
        probe: %{mode: :watched, reason: "test", mem_total: 16 * @gib, cgroup: nil},
        probe_counter: probes
      )

      calls = :sys.get_state(MemoryGuard).probe

      counting = fn ->
        :counters.add(probes, 1, 1)
        calls.()
      end

      :sys.replace_state(MemoryGuard, &%{&1 | probe: counting})
      assert :ok = MemoryGuard.settings_changed(@host)
      assert :counters.get(probes, 1) == 1
    end

    test "N3.partial: with some named trees gone, the episode stays open", ctx do
      {:opened, episode} =
        Episodes.open(ctx.db, %{
          host: @host,
          kind: "custody",
          key: "claude:shared@testhost",
          since: 1,
          why: "t",
          trees: [
            %{launchId: "a", pid: 4_000_002, start: 1},
            %{launchId: "b", pid: 981, start: 981}
          ]
        })

      proc!(ctx.root, 981, 1, 981, 10 * @mib)
      guard!(ctx)
      :ok = MemoryGuard.tick()
      assert [%{"episodeId" => id}] = Episodes.active(ctx.db, @host)
      assert id == episode["episodeId"]
    end

    test "N4.partial / N4.stale: at +60 s only the survivors are listed, and the terminal outcome is recorded once",
         ctx do
      proc!(ctx.root, 981, 1, 981, 10 * @mib)

      {:opened, episode} =
        Episodes.open(ctx.db, %{
          host: @host,
          kind: "custody",
          key: "claude:shared@testhost",
          since: 1,
          why: "t",
          trees: [
            %{launchId: "gone", pid: 4_000_003, start: 1},
            %{launchId: "alive", pid: 981, start: 981}
          ]
        })

      digest = "d-1"

      {:accepted, "recovery"} =
        Episodes.judge(
          ctx.db,
          %{
            "action" => "recovery",
            "episodeId" => episode["episodeId"],
            "host" => @host,
            "kind" => "custody",
            "key" => "claude:shared@testhost",
            "killedAt" => System.system_time(:millisecond) - 61_000
          },
          digest,
          @host
        )

      guard!(ctx)
      :ok = MemoryGuard.tick()

      assert %{"outcome" => "failed", "survivors" => [%{"launchId" => "alive"}]} =
               Episodes.recovery(ctx.db, episode["episodeId"])

      recovery = Episodes.recovery(ctx.db, episode["episodeId"])
      :ok = Episodes.record_outcome(ctx.db, recovery, "cleared", [])
      assert length(events(ctx.db, "memory_guard_recovery_outcome")) == 1
    end

    test "N5.partial / N5.stale: some mechanisms absent and some unknown is residual; the finding is taken afresh at each attempt",
         _ctx do
      partial = %{
        "groups" => %{"result" => "absent", "detail" => []},
        "sudo" => %{"result" => "unknown", "detail" => "x"},
        "sockets" => %{"result" => "absent", "detail" => []}
      }

      assert RootPath.kind(partial) == "residual"
      calls = :counters.new(1, [])

      runner = fn command, _args ->
        :counters.add(calls, 1, 1)
        if command == "id", do: {"gd\n", 0}, else: {"sudo: a password is required", 1}
      end

      RootPath.finding(runner: runner, sockets: [])
      RootPath.finding(runner: runner, sockets: [])
      assert :counters.get(calls, 1) == 4
    end

    test "N7.unreadable: with the database unreachable, nothing is accepted", _ctx do
      assert {:error, _} = Episodes.judge(:no_such_db, %{"action" => "override"}, "d", @host)
    end

    test "N8.absent / N8.partial / N8.unreadable: an accepted override records every field; what the record lacks is unknown",
         ctx do
      {:opened, episode} =
        Episodes.open(ctx.db, %{host: @host, kind: "guard", since: 1, why: "t"})

      {:accepted, "recovery"} =
        Episodes.judge(
          ctx.db,
          %{
            "action" => "recovery",
            "episodeId" => episode["episodeId"],
            "host" => @host,
            "kind" => "guard"
          },
          "r-1",
          @host
        )

      :ok =
        Episodes.record_outcome(
          ctx.db,
          Episodes.recovery(ctx.db, episode["episodeId"]),
          "failed",
          []
        )

      dir = RootActions.dir(ctx.base)
      File.mkdir_p!(dir)

      # No operator and no time in the record: as printed, the statement says
      # the operator is unknown.
      stored = Episodes.get(ctx.db, episode["episodeId"])

      File.write!(
        Path.join(dir, "override.json"),
        JSON.encode!(%{
          action: "override",
          episodeId: episode["episodeId"],
          host: @host,
          kind: "guard",
          statementKind: "strict",
          statement: RootActions.statement(stored, [], %{}, strict_finding()),
          trees: []
        })
      )

      RootActions.intake(ctx.db, ctx.base, @host,
        root_uid: File.stat!(ctx.root).uid,
        finding: fn -> strict_finding() end
      )

      assert %{
               "operator" => %{"user" => "root", "sudoUser" => "unknown", "sudoUid" => "unknown"},
               "statement" => statement,
               "trees" => [],
               "at" => "unknown",
               "finding" => %{}
             } = Episodes.override(ctx.db, episode["episodeId"])

      assert statement =~ "Recorded as: root, invoked by unknown (uid unknown)."
    end
  end

  describe "matrix cells: the last ones" do
    alias Tightbeam.MemoryGuard.{Episodes, RootActions}

    setup ctx do
      meminfo!(ctx.root, 16 * @gib, 12 * @gib)
      :ok
    end

    test "B6.unreadable: an identity that cannot be read means the helper never ran; the recorded tree is ended through its parent chain, with proof",
         ctx do
      insert_adapter_row!(ctx.db, "adapter-launch-1", 950)
      proc!(ctx.root, 951, 950, 951, 10 * @mib)
      launch!(ctx.base, "sl-a", "sid-a", 951, 951, 512 * @mib)
      guard!(ctx, kill_result: {:error, :eacces})

      assert :ok = MemoryGuard.adapter_ended({:claude, "shared", @host}, "adapter-launch-1")
      assert_received {:signalled, [951]}
      assert Records.read_all(ctx.base) == {:ok, %{}}
    end

    test "E6.unreadable: an adapter whose own cgroup file cannot be read is treated as not placed and measured watched",
         ctx do
      fs = cgroup_tree!(ctx.root, "/svc/tightbeam.service/gateway", [])
      guard!(ctx, probe: enforced_probe(), cgroup_fs: fs)

      _ =
        MemoryGuard.launch_env(
          {:codex, "shared", @host},
          "L-e6",
          [cmd: ["/bin/x"], env: []],
          ctx.db
        )

      harness = Path.join(fs, "svc/tightbeam.service/harness")
      File.write!(Path.join(harness, "memory.current"), "0")
      insert_adapter_row!(ctx.db, "L-e6", 975, "codex")
      proc!(ctx.root, 975, 1, 975, 10 * @mib)
      cgroup_file = Path.join(ctx.root, "proc/975/cgroup")
      File.write!(cgroup_file, "0::/svc/tightbeam.service/harness/adapter-L-e6\n")
      File.chmod!(cgroup_file, 0o000)
      on_exit(fn -> File.chmod(cgroup_file, 0o644) end)

      :ok = MemoryGuard.tick()
      assert [{@host, %{"launchId" => "L-e6"}}] = events(ctx.db, "memory_guard_launch_unplaced")
    end

    test "H3.stale: host available at an outside kill is the last sample's", ctx do
      meminfo!(ctx.root, 16 * @gib, div(16 * @gib * 5, 100))
      guard!(ctx)
      :ok = MemoryGuard.tick()
      :ok = MemoryGuard.note_adapter_exit("L-low", 143)
      assert %{status: 143, host_low: true} = MemoryGuard.adapter_exit("L-low")
    end

    test "L3.absent: a session with no harness session pointer needs a launch, and the cap counts it",
         ctx do
      guard!(ctx)

      {:ok, {:ok, _}} =
        DB.transaction(
          ctx.db,
          &Settings.set_in_txn(&1, @host, "residentCap", "1", "user:owner", 16 * @gib)
        )

      :ok = MemoryGuard.settings_changed(@host)
      adapter = adapter!()
      session!(ctx, "agent:busy", "sid-busy")
      resident!(adapter, ["sid-busy"])
      queue!(ctx, "agent:busy", "working")
      assert :ok = MemoryGuard.admit("agent:busy", ctx.db)
      session!(ctx, "agent:nopointer")
      queue!(ctx, "agent:nopointer", "go")
      assert {:held, ["resident_cap"]} = MemoryGuard.admit("agent:nopointer", ctx.db)
    end

    test "N9.stale: after a restart between acceptance and effect, an accepted custody override is carried out once from its accepted state",
         ctx do
      Application.put_env(:tightbeam, :memory_guard_stuck_ms, 0)
      on_exit(fn -> Application.delete_env(:tightbeam, :memory_guard_stuck_ms) end)
      insert_adapter_row!(ctx.db, "adapter-launch-1", 950)
      {:ok, _} = DB.query(ctx.db, "UPDATE harness_processes SET state='exited'")
      proc!(ctx.root, 951, 1, 951, 10 * @mib)
      launch!(ctx.base, "sl-stuck", "sid-stuck", 951, 951, 512 * @mib)
      uid = File.stat!(ctx.root).uid
      opts = [kill_result: {:error, :harness_group_failed}, signal_works: false, root_uid: uid]
      guard!(ctx, opts)
      assert {:error, _} = MemoryGuard.ensure_no_orphans({:claude, "shared", @host})
      :ok = MemoryGuard.tick()
      [episode] = Episodes.active(ctx.db, @host)
      dir = RootActions.dir(ctx.base)
      File.mkdir_p!(dir)

      for name <- ["recovery", "override"] do
        record =
          if name == "recovery" do
            %{action: "recovery", killedAt: System.system_time(:millisecond) - 61_000}
          else
            stored = Episodes.get(ctx.db, episode["episodeId"])
            survivors = stored["recovery"]["survivors"]
            finding = %{"groups" => %{"result" => "absent", "detail" => []}}

            finding =
              Map.merge(finding, %{"sudo" => finding["groups"], "sockets" => finding["groups"]})

            %{
              action: "override",
              statementKind: "strict",
              statement:
                Tightbeam.MemoryGuard.RootActions.statement(stored, survivors, %{}, finding),
              trees: survivors
            }
          end

        File.write!(
          Path.join(dir, name <> ".json"),
          JSON.encode!(
            Map.merge(record, %{
              episodeId: episode["episodeId"],
              host: @host,
              kind: "custody",
              key: episode["key"]
            })
          )
        )

        :ok = MemoryGuard.tick()
      end

      assert %{"applied" => false} = Episodes.override(ctx.db, episode["episodeId"])
      # The gateway restarts before the effect.
      stop_supervised!(MemoryGuard)
      guard!(ctx, opts)
      assert :ok = MemoryGuard.ensure_no_orphans({:claude, "shared", @host})
      assert :ok = MemoryGuard.ensure_no_orphans({:claude, "shared", @host})
      # Applied once the replacement adapter runs (FS9 B4), recorded once.
      assert %{"applied" => false} = Episodes.override(ctx.db, episode["episodeId"])
      adapter = start_supervised!({FakeAdapter, test: self()}, id: {:adapter, "replacement"})

      MemoryGuard.residency(
        adapter,
        {:claude, "shared", @host},
        "adapter-launch-2",
        MapSet.new(["sid-r"])
      )

      :ok = MemoryGuard.tick()
      :ok = MemoryGuard.tick()
      assert %{"applied" => true} = Episodes.override(ctx.db, episode["episodeId"])
      assert length(events(ctx.db, "memory_guard_override_applied")) == 1
    end
  end

  describe "sibling failures (review family: failures never read as success)" do
    setup ctx do
      meminfo!(ctx.root, 16 * @gib, 12 * @gib)
      :ok
    end

    test "A7.timeout: a setting stored while the guard cannot answer says it is not yet applied",
         ctx do
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

    test "E4.absent / E4.unreadable / E4.timeout (T33): a missing harness-process table is never 'nothing to end' (R2a) nor an empty host; launches are held guard_unavailable",
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
      # A quota incident of a session on this host (its wake is filed there).
      session!(ctx, "agent:quota")
      incident = quota_incident!(ctx, "agent:quota", @host)

      {:ok, :deferred} =
        DB.transaction(
          ctx.db,
          &Admission.quota_released_in_txn(&1, incident, "claude", @host)
        )

      assert [{^incident, %{"released" => "quota_park", "remaining" => ["memory_floor"]}}] =
               events(ctx.db, "admission_hold_remaining")

      assert [{^incident, _}] = events(ctx.db, "quota_readmission_deferred")
      assert events(ctx.db, "admission_resumed") == []

      meminfo!(ctx.root, total, div(total * 16, 100))
      :ok = MemoryGuard.tick()
      run_quota_wakes!(ctx)
      assert [{^incident, %{"after" => ["memory"]}}] = events(ctx.db, "admission_resumed")
      assert [{^incident, _}] = events(ctx.db, "quota_readmission_resumed")

      # Exactly once: the episode is done and its wake consumed.
      :ok = MemoryGuard.tick()
      run_quota_wakes!(ctx)
      assert length(events(ctx.db, "quota_readmission_resumed")) == 1
      assert quota_wakes(ctx) == []
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

  ## The review's failure class, swept: a failure or an unreadable input never
  ## reads as none, empty or done.

  describe "sweep: failures never read as none (review class B3-B6)" do
    alias Tightbeam.MemoryGuard.{Episodes, RootActions, RootPath, Unguarded}

    test "sweep (FS1 A3, FS2): an adapter whose session processes cannot get the launch step does not launch, outside off",
         ctx do
      meminfo!(ctx.root, 16 * @gib, 12 * @gib)
      # The installed CLI is missing, so the step cannot be put in place.
      empty = Path.join(ctx.root, "no-cli")
      File.mkdir_p!(empty)
      guard!(ctx, cli_bin: empty)

      assert {:error, :memory_guard_unavailable} =
               MemoryGuard.launch_env(
                 {:claude, "shared", @host},
                 "L-nostep",
                 [
                   cmd: ["/x/.bin/claude-agent-acp"],
                   env: [{"CLAUDE_CODE_EXECUTABLE", "/x/claude"}]
                 ],
                 ctx.db
               )

      assert [{@host, %{"launchId" => "L-nostep", "error" => error}}] =
               events(ctx.db, "memory_guard_launch_unplaced")

      assert error =~ "launch step is not in place"

      # A harness without session processes needs no step.
      assert MemoryGuard.launch_env(
               {:codex, "shared", @host},
               "L-codex",
               [cmd: ["/bin/codex-acp"], env: []],
               ctx.db
             ) == []
    end

    test "N4.stale (R2 sweep): a running guard whose own launch step holds launches does not clear a guard recovery",
         ctx do
      Application.put_env(:tightbeam, :memory_guard_stuck_ms, 0)
      on_exit(fn -> Application.delete_env(:tightbeam, :memory_guard_stuck_ms) end)
      meminfo!(ctx.root, 16 * @gib, 12 * @gib)
      empty = Path.join(ctx.root, "no-cli")
      File.mkdir_p!(empty)
      guard!(ctx, cli_bin: empty, root_uid: File.stat!(ctx.root).uid)
      :ok = MemoryGuard.tick()
      :ok = MemoryGuard.tick()
      assert [%{"kind" => "guard", "episodeId" => id}] = Episodes.active(ctx.db, @host)

      dir = RootActions.dir(ctx.base)
      File.mkdir_p!(dir)

      File.write!(
        Path.join(dir, "recovery-g.json"),
        JSON.encode!(%{
          v: 1,
          action: "recovery",
          episodeId: id,
          host: @host,
          kind: "guard",
          key: nil,
          at: System.system_time(:millisecond)
        })
      )

      :ok = MemoryGuard.tick()
      :ok = MemoryGuard.tick()
      assert %{"outcome" => "pending"} = Episodes.recovery(ctx.db, id)
      assert [%{"episodeId" => ^id}] = Episodes.active(ctx.db, @host)
    end

    test "N2.stale (R2 sweep): an episode opened before a restart whose alert was never recorded is alerted after it",
         ctx do
      Application.put_env(:tightbeam, :memory_guard_stuck_ms, 0)
      on_exit(fn -> Application.delete_env(:tightbeam, :memory_guard_stuck_ms) end)
      meminfo!(ctx.root, 16 * @gib, 12 * @gib)

      {:ok, _} =
        DB.query(ctx.db, "UPDATE users SET createdAt=createdAt+1000 WHERE userId='guest'")

      main!(ctx, "owner")
      :ok = Org.put_setting(ctx.db, "owner-alerts-user", "owner")

      # The episode was opened; the gateway stopped before its alert.
      {:opened, ep} =
        Episodes.open(ctx.db, %{
          host: @host,
          kind: "guard",
          since: 1,
          why: "the memory guard's launch step is not in place"
        })

      empty = Path.join(ctx.root, "no-cli")
      File.mkdir_p!(empty)
      guard!(ctx, cli_bin: empty)
      :ok = MemoryGuard.tick()
      :ok = MemoryGuard.tick()
      id = ep["episodeId"]

      assert %{"alert" => %{"outcome" => "created"}, "notified" => true} =
               Episodes.get(ctx.db, id)
    end

    test "F8 (R2 sweep): off whose record cannot be committed gives the step back its earlier settings",
         ctx do
      fs = Path.join(ctx.root, "sys/fs/cgroup")
      File.mkdir_p!(fs)
      config = Path.join(Records.dir(ctx.base), "launch.json")
      File.mkdir_p!(Path.dirname(config))
      File.write!(config, ~s({"v":1,"mode":"watched"}))

      {:ok, _} =
        DB.query(ctx.db, """
        CREATE TRIGGER off_fails BEFORE INSERT ON lifecycle_events WHEN NEW.kind='memory_guard_mode'
        BEGIN SELECT RAISE(ABORT, 'injected'); END
        """)

      assert {:not_applied, why} =
               Unguarded.bring_off_into_force(ctx.db, @host, ctx.base,
                 cgroup_fs: fs,
                 harness_candidates: fn -> {:ok, []} end
               )

      assert why =~ "could not be recorded"
      assert File.read!(config) == ~s({"v":1,"mode":"watched"})
    end

    test "R1 (FS7): a guard-down admission whose release cannot be recorded stays held, for a resident session, under off and under a root override",
         ctx do
      session!(ctx, "agent:g", "sid-g")
      queue!(ctx, "agent:g", "work")
      none = [live_adapter: fn _ -> nil end]
      assert {:held, ["guard_unavailable"]} = Unguarded.admit(ctx.db, "agent:g", none)
      assert %{since: _} = Unguarded.open_hold(ctx.db, "agent:g")

      {:ok, _} =
        DB.query(ctx.db, """
        CREATE TRIGGER r1_release_fails BEFORE DELETE ON memory_guard_open
        BEGIN SELECT RAISE(ABORT, 'injected'); END
        """)

      live = [live_adapter: fn _ -> self() end]
      resident = live ++ [resident?: fn _adapter, _sid -> true end]
      not_resident = live ++ [resident?: fn _adapter, _sid -> false end]

      # Resident.
      assert {:held, ["guard_unavailable"]} = Unguarded.admit(ctx.db, "agent:g", resident)

      # `off` in force.
      EventLog.lifecycle(
        ctx.db,
        "memory_guard_mode",
        @host,
        JSON.encode!(%{host: @host, mode: "off", transition: nil})
      )

      assert {:held, ["guard_unavailable"]} = Unguarded.admit(ctx.db, "agent:g", not_resident)
      {:ok, _} = DB.query(ctx.db, "DELETE FROM lifecycle_events WHERE kind='memory_guard_mode'")

      # A root override of the host's guard episode.
      {:opened, ep} = Episodes.open(ctx.db, %{host: @host, kind: "guard", since: 1, why: "t"})
      id = ep["episodeId"]
      base = %{"episodeId" => id, "host" => @host, "kind" => "guard", "key" => nil}
      {:accepted, _} = Episodes.judge(ctx.db, Map.put(base, "action", "recovery"), "r-d", @host)
      :ok = Episodes.record_outcome(ctx.db, Episodes.recovery(ctx.db, id), "failed", [])
      {:accepted, _} = Episodes.judge(ctx.db, Map.put(base, "action", "override"), "o-d", @host)
      assert {:held, ["guard_unavailable"]} = Unguarded.admit(ctx.db, "agent:g", none)

      # Nothing was released or applied: the hold stands.
      assert %{since: _} = Unguarded.open_hold(ctx.db, "agent:g")
      assert events(ctx.db, "memory_guard_release") == []
      assert %{"applied" => false} = Episodes.override(ctx.db, id)

      # The release and override_applied are one step: if the applied record
      # fails, the release does not happen either.
      {:ok, _} = DB.query(ctx.db, "DROP TRIGGER r1_release_fails")

      {:ok, _} =
        DB.query(ctx.db, """
        CREATE TRIGGER r2_applied_fails BEFORE UPDATE OF applied ON memory_guard_episodes
        BEGIN SELECT RAISE(ABORT, 'injected'); END
        """)

      assert {:held, ["guard_unavailable"]} = Unguarded.admit(ctx.db, "agent:g", none)
      assert %{since: _} = Unguarded.open_hold(ctx.db, "agent:g")
      assert events(ctx.db, "memory_guard_release") == []

      {:ok, _} = DB.query(ctx.db, "DROP TRIGGER r2_applied_fails")
      assert :ok = Unguarded.admit(ctx.db, "agent:g", none)
      assert Unguarded.open_hold(ctx.db, "agent:g") == nil

      assert [{"agent:g", %{"because" => "root override " <> ^id}}] =
               events(ctx.db, "memory_guard_release")

      assert %{"applied" => true} = Episodes.override(ctx.db, id)
    end

    test "sweep (B2.unreadable): a launch record without its tree's pid is unreadable, not a record",
         ctx do
      dir = Path.join(Records.dir(ctx.base), "sessions")
      File.mkdir_p!(dir)
      File.write!(Path.join(dir, "sl-nopid.json"), JSON.encode!(%{v: 1, launchId: "sl-nopid"}))
      assert {:error, error} = Records.read_all(ctx.base)
      assert error =~ "sl-nopid.json"
    end

    test "sweep (D1.absent, M-V7): a tree's unit is read even after the host left enforced; a populated one is not gone",
         ctx do
      meminfo!(ctx.root, 16 * @gib, 12 * @gib)
      insert_adapter_row!(ctx.db, "adapter-launch-1", 950)
      {:ok, _} = DB.query(ctx.db, "UPDATE harness_processes SET state='exited'")
      proc!(ctx.root, 951, 1, 951, 10 * @mib)
      launch!(ctx.base, "sl-unit", "sid-unit", 951, 951, 512 * @mib)
      unit = "/svc/tightbeam.service/harness/session-sid-unit"
      path = Path.join(Records.dir(ctx.base), "sessions/sl-unit.json")

      record =
        path
        |> File.read!()
        |> JSON.decode!()
        |> Map.merge(%{"placement" => "enforced", "unit" => unit})

      File.write!(path, JSON.encode!(record))
      events_file = Path.join([ctx.root, "sys/fs/cgroup", unit, "cgroup.events"])
      File.mkdir_p!(Path.dirname(events_file))
      File.write!(events_file, "populated 1\nfrozen 0\n")

      # The host is watched now (it left enforced): no layout, the unit stays.
      guard!(ctx)
      key = {:claude, "shared", @host}
      assert {:error, _} = MemoryGuard.ensure_no_orphans(key)
      assert File.exists?(path), "custody kept: the unit still has processes"

      File.write!(events_file, "populated 0\nfrozen 0\n")
      assert :ok = MemoryGuard.ensure_no_orphans(key)
    end

    test "sweep (L1, R12): a session on a host the guard has not seen is decided, never admitted unchecked",
         ctx do
      meminfo!(ctx.root, 16 * @gib, 12 * @gib)
      guard!(ctx)

      Org.create(ctx.db, %{
        session_key: "agent:far",
        display_name: "far",
        owner_user_id: "owner",
        origin: "user:owner",
        archetype: "coder",
        host: "farhost",
        harness: "claude",
        provider: "anthropic",
        model: Tightbeam.Model.new("claude-sonnet-5", effort: "medium")
      })

      queue!(ctx, "agent:far", "work")
      result = MemoryGuard.admit("agent:far", ctx.db)

      assert result == {:held, ["guard_unavailable"]} or
               Map.has_key?(:sys.get_state(MemoryGuard).hosts, "farhost")
    end

    test "sweep (FS2): refusal records that cannot be read are an unknown refusal, and the step's prerequisites hold",
         ctx do
      meminfo!(ctx.root, 16 * @gib, 12 * @gib)
      guard!(ctx)
      oom = Path.join(ctx.root, "proc/self/oom_score_adj")
      File.mkdir_p!(Path.dirname(oom))
      File.write!(oom, "0\n")
      File.mkdir_p!(Path.join(Records.dir(ctx.base), "sessions"))
      assert :ok = Records.step_prerequisites(ctx.base, ctx.root)

      refusals = Path.join(Records.dir(ctx.base), "refusals")
      File.mkdir_p!(refusals)
      bad = Path.join(refusals, "sl-x.json")
      File.write!(bad, ~s({"v":1,"sessionId":"sid-x","at":1}))
      File.chmod!(bad, 0o000)
      on_exit(fn -> File.chmod(bad, 0o644) end)

      assert {:error, error} = Records.refusal_for(ctx.base, "sid-other", 0)
      assert error =~ "sl-x.json"
      assert {:error, _} = Records.step_prerequisites(ctx.base, ctx.root)

      # A refusal directory that takes no write fails them too.
      File.chmod!(bad, 0o644)
      File.chmod!(refusals, 0o555)
      on_exit(fn -> File.chmod(refusals, 0o755) end)
      assert {:error, _} = Records.step_prerequisites(ctx.base, ctx.root)
      File.chmod!(refusals, 0o755)

      assert Records.refusal_for(ctx.base, "sid-other", 0) == nil
      assert %{reason: nil, at: 1} = Records.refusal_for(ctx.base, "sid-x", 0)
    end

    test "F4 (v1.15 §7): with the memory size unknown, no residentCap means no cap; a set one applies",
         _ctx do
      assert %{resident_cap: nil, budget: nil} = Settings.effective(%{}, nil)
      assert %{resident_cap: 5} = Settings.effective(%{"residentCap" => %{value: "5"}}, nil)
      assert %{resident_cap: 8} = Settings.effective(%{}, 16 * @gib)
    end

    test "sweep (R7, M-V2): a held read that cannot be completed says unknown, never not held",
         _ctx do
      session = %{
        session_key: "agent:x",
        harness: "claude",
        provider: "anthropic",
        model: nil,
        host: @host
      }

      assert %{reasonClass: "unknown", reasons: [%{condition: "unknown: " <> _}]} =
               HeldState.read(:no_such_db, session)
    end

    test "sweep (F8.unreadable): a budget group that cannot be looked at is no evidence that off may take effect",
         ctx do
      fs = Path.join(ctx.root, "sys/fs/cgroup")
      parent = Path.join(fs, "svc/tightbeam.service")
      File.mkdir_p!(Path.join(parent, "harness"))
      File.chmod!(parent, 0o000)
      on_exit(fn -> File.chmod(parent, 0o755) end)

      if match?({:error, _}, File.stat(Path.join(parent, "harness"))) do
        assert {:not_applied, why} =
                 Unguarded.bring_off_into_force(ctx.db, @host, ctx.base,
                   cgroup_fs: fs,
                   harness_candidates: fn -> {:ok, ["/svc/tightbeam.service/harness"]} end
                 )

        assert why =~ "cannot be looked at"
      end
    end

    test "sweep (N5.unreadable): a control socket that cannot be looked at is unknown, never absent",
         ctx do
      dir = Path.join(ctx.root, "locked")
      File.mkdir_p!(dir)
      File.chmod!(dir, 0o000)
      on_exit(fn -> File.chmod(dir, 0o755) end)
      socket = Path.join(dir, "docker.sock")

      if match?({:error, :eacces}, File.stat(socket)) do
        finding =
          RootPath.finding(
            runner: fn
              "id", _ -> {"gd\n", 0}
              "sudo", _ -> {"sudo: a password is required", 1}
            end,
            sockets: [socket]
          )

        assert %{"result" => "unknown", "detail" => [^socket]} = finding["sockets"]
        assert RootPath.kind(finding) == "residual"
      end
    end
  end

  ## The durable effect journal (agreed design: rev 2 art_10551253 as amended by
  ## rev 3 art_e42f1681, rev 4 art_191d7337 and rev 5 art_84ba2766). Each test
  ## drives one crash or failure point on the real path: the guard is stopped
  ## (a crash) or a write is refused, then started again.

  describe "durable effects: kills (O3/O4, rev 3 D1)" do
    setup ctx do
      meminfo!(ctx.root, 16 * @gib, 12 * @gib)
      proc!(ctx.root, 650, 1, 51, 900 * @mib)
      launch!(ctx.base, "sl-k", "sid-k", 650, 51, 512 * @mib)
      session!(ctx, "agent:k", "sid-k")
      Application.put_env(:tightbeam, :memory_guard_attribution_wait_ms, 300)
      on_exit(fn -> Application.delete_env(:tightbeam, :memory_guard_attribution_wait_ms) end)
      %{match: %{host: @host, harness_session_id: "sid-k", since: 0}}
    end

    defp kill_effects(ctx) do
      {:ok, rows} =
        DB.query(
          ctx.db,
          "SELECT effectId, phase, outcome FROM memory_guard_effects WHERE kind='tree_kill'",
          []
        )

      Enum.map(rows, fn [id, phase, outcome] -> {id, phase, outcome && JSON.decode!(outcome)} end)
    end

    defp await_phase(ctx, phase, attempts \\ 300) do
      cond do
        Enum.any?(kill_effects(ctx), &(elem(&1, 1) == phase)) -> :ok
        attempts == 0 -> flunk("no kill reached #{phase}")
        true -> Process.sleep(10) && await_phase(ctx, phase, attempts - 1)
      end
    end

    # The tree is under its limit after the restart, so no new kill starts.
    defp restart_quiet!(ctx, opts \\ []) do
      stop_supervised!(MemoryGuard)
      proc!(ctx.root, 650, 1, 51, 10 * @mib)
      guard!(ctx, opts)
    end

    test "O3 (rev 3 crash 1): crash after the intent, before the signal, tree alive: not_sent, nothing attributed",
         ctx do
      guard!(ctx, before_kill_send: fn _ -> Process.sleep(:infinity) end)
      :ok = MemoryGuard.tick()
      assert [{_, "intended", nil}] = kill_effects(ctx)

      restart_quiet!(ctx)
      :ok = MemoryGuard.tick()
      assert [{_, "done", %{"outcome" => "not_sent"}}] = kill_effects(ctx)
      assert MemoryGuard.memory_kill(ctx.match) == nil
      assert events(ctx.db, "memory_tree_ended") == []
      assert events(ctx.db, "memory_kill_failed") == []
    end

    test "O3 (rev 3 crash 2/3): crash after the intent, the tree ending on its own in the gap: unattributed, settlement harness_exited",
         ctx do
      guard!(ctx, before_kill_send: fn _ -> Process.sleep(:infinity) end)
      :ok = MemoryGuard.tick()
      stop_supervised!(MemoryGuard)
      gone!(ctx.root, 650)
      guard!(ctx)
      :ok = MemoryGuard.tick()
      assert [{_, "done", %{"outcome" => "unattributed_end"}}] = kill_effects(ctx)
      assert MemoryGuard.memory_kill(ctx.match) == nil
      assert events(ctx.db, "memory_tree_ended") == []
    end

    test "O3 (rev 3 crash 4): crash after the proven send, before the outcome, tree gone: memory_tree_ended once, and the killed turn still settles memory_limit",
         ctx do
      # The kill call returns (a proven send); the tree is not yet shown gone.
      guard!(ctx, kill_result: fn _ -> :ok end, signal_works: false)
      :ok = MemoryGuard.tick()
      await_phase(ctx, "dispatched")

      stop_supervised!(MemoryGuard)
      gone!(ctx.root, 650)
      guard!(ctx)
      assert %{limit: "session"} = MemoryGuard.memory_kill(ctx.match)
      :ok = MemoryGuard.tick()
      :ok = MemoryGuard.tick()
      assert [{_, "done", %{"outcome" => "ended"}}] = kill_effects(ctx)
      assert [_] = events(ctx.db, "memory_tree_ended")
    end

    test "O4: a proven send whose tree is still there after the proof window, after a restart: memory_kill_failed",
         ctx do
      guard!(ctx, kill_result: fn _ -> :ok end, signal_works: false)
      :ok = MemoryGuard.tick()
      await_phase(ctx, "dispatched")
      [{id, _, _}] = kill_effects(ctx)
      restart_quiet!(ctx, kill_result: {:error, :harness_group_failed}, signal_works: false)
      Process.sleep(700)
      :ok = MemoryGuard.tick()
      assert %{phase: "done", outcome: %{"outcome" => "failed"}} = Journal.get(ctx.db, id)
      assert [_ | _] = events(ctx.db, "memory_kill_failed")
    end

    test "O3 (rev 3 crash 5): the outcome write fails: the row stays and is resolved once the write succeeds",
         ctx do
      {:ok, _} =
        DB.query(ctx.db, """
        CREATE TRIGGER o3_fail BEFORE INSERT ON lifecycle_events WHEN NEW.kind='memory_tree_ended'
        BEGIN SELECT RAISE(ABORT, 'injected'); END
        """)

      guard!(ctx)
      :ok = MemoryGuard.tick()
      settle_kills!()
      assert [{_, "dispatched", nil}] = kill_effects(ctx)
      assert events(ctx.db, "memory_tree_ended") == []

      {:ok, _} = DB.query(ctx.db, "DROP TRIGGER o3_fail")
      :ok = MemoryGuard.tick()
      :ok = MemoryGuard.tick()
      assert [{_, "done", %{"outcome" => "ended"}}] = kill_effects(ctx)
      assert [_] = events(ctx.db, "memory_tree_ended")
    end

    test "D1 (rev 3): the helper errors before any signal and the tree then ends on its own: not sent, not attributed",
         ctx do
      guard!(ctx,
        kill_result: fn target ->
          gone!(ctx.root, target.pid)
          {:error, :harness_group_failed}
        end,
        signal_works: false
      )

      :ok = MemoryGuard.tick()
      settle_kills!()
      assert [{_, "done", %{"outcome" => "not_sent"}}] = kill_effects(ctx)
      assert MemoryGuard.memory_kill(ctx.match) == nil
      assert events(ctx.db, "memory_tree_ended") == []
    end
  end

  describe "durable effects: idle closes (O2, rev 4/5)" do
    setup ctx do
      meminfo!(ctx.root, 16 * @gib, 12 * @gib)

      {:ok, _} =
        DB.query(ctx.db, "UPDATE users SET createdAt=createdAt+1000 WHERE userId='guest'")

      session!(ctx, "agent:c", "sid-c")
      :ok
    end

    @conditional "Tightbeam had decided to close it to free memory and cannot confirm whether it did"

    # Drives the production close of sid-c (the floor is breached, so the
    # guard closes its idle process) to a crash point and stops the guard
    # there; the close task stays blocked, as a crashed gateway's would.
    # Points (rev 4 D1): `:before_call`, inside the close call before it acts;
    # `:called`, after the call returned `:ok` and before `dispatched` is
    # written; `:dispatched`, right after it. `ends_process: false`: the call
    # returns `:ok` but the process stays. Returns the close's journal id.
    defp crash_close!(ctx, point, opts \\ []) do
      test = self()

      block = fn ->
        send(test, {:crash_point, point})
        Process.sleep(:infinity)
      end

      closer = fn _adapter, sid, _reason ->
        if point == :before_call, do: block.()
        if Keyword.get(opts, :ends_process, true), do: closed_process!(ctx, sid)
        :ok
      end

      proc!(ctx.root, 961, 1, 961, 10 * @mib)
      launch!(ctx.base, "sl-c", "sid-c", 961, 961, 512 * @mib)
      meminfo!(ctx.root, 16 * @gib, div(16 * @gib * 10, 100))
      adapter = adapter!()

      guard!(ctx,
        closer: closer,
        close_hook: fn at, _sid -> if at == point, do: block.(), else: :ok end
      )

      resident!(adapter, ["sid-c"])
      :ok = MemoryGuard.tick()
      assert_receive {:crash_point, ^point}, 2_000
      stop_supervised!(MemoryGuard)
      meminfo!(ctx.root, 16 * @gib, 12 * @gib)
      {:ok, [%{id: id}]} = Journal.page(ctx.db, @host, "idle_close", nil, nil, 8)
      id
    end

    defp markers_of(ctx, key) do
      {:ok, rows} =
        DB.query(ctx.db, "SELECT content FROM messages WHERE sessionKey=?1 ORDER BY seq", [key])

      Enum.map(rows, &hd/1)
    end

    test "O2 (rev 5, 1): a closing mark that cannot be written: no close, no journal row",
         ctx do
      {:ok, _} =
        DB.query(ctx.db, """
        CREATE TRIGGER o2_mark BEFORE INSERT ON lifecycle_events WHEN NEW.kind='memory_guard_closing'
        BEGIN SELECT RAISE(ABORT, 'injected'); END
        """)

      meminfo!(ctx.root, 16 * @gib, div(16 * @gib * 10, 100))
      adapter = adapter!()
      guard!(ctx)
      resident!(adapter, ["sid-c"])
      :ok = MemoryGuard.tick()
      settle_closes!()
      refute_received {:closed, "sid-c", _}
      assert {:ok, []} = Journal.page(ctx.db, @host, "idle_close", nil, nil, 8)
    end

    test "O2 (rev 5, 2): crash in the close call, before it acts, process alive: abandoned, nothing recorded as attempted",
         ctx do
      id = crash_close!(ctx, :before_call)

      assert %{phase: "intended", intent: %{"markerKey" => "closed:agent:c:sid-c:" <> _}} =
               Journal.get(ctx.db, id)

      guard!(ctx)
      :ok = MemoryGuard.tick()
      assert %{phase: "done", outcome: %{"outcome" => "abandoned"}} = Journal.get(ctx.db, id)
      assert events(ctx.db, "memory_guard_close_failed") == []
      assert events(ctx.db, "memory_guard_idle_closed") == []
      assert markers_of(ctx, "agent:c") == []
    end

    test "O2 (rev 5, 3; the spec author's test): crash in the close call, the process then ending on its own: one close_unconfirmed, exactly one conditional marker, no idle_closed, a fresh next turn",
         ctx do
      id = crash_close!(ctx, :before_call)
      gone!(ctx.root, 961)
      guard!(ctx)
      :ok = MemoryGuard.tick()
      :ok = MemoryGuard.tick()

      assert %{phase: "done", outcome: %{"outcome" => "unconfirmed"}} = Journal.get(ctx.db, id)

      assert [{"agent:c", %{"sessionId" => "sid-c"}}] =
               events(ctx.db, "memory_guard_close_unconfirmed")

      assert events(ctx.db, "memory_guard_idle_closed") == []
      assert [marker] = markers_of(ctx, "agent:c")
      assert marker =~ @conditional

      # Residency is clear: the next turn needs, and gets, a fresh launch.
      assert MemoryGuard.read(@host).residentCount == 0
      queue!(ctx, "agent:c", "next")
      assert :ok = MemoryGuard.admit("agent:c")
    end

    test "O2 (rev 5, 4; the spec author's test): crash after the close call returned, before dispatched: the same neutral outcome and one conditional marker",
         ctx do
      id = crash_close!(ctx, :called)
      assert %{phase: "intended"} = Journal.get(ctx.db, id)
      guard!(ctx)
      :ok = MemoryGuard.tick()
      :ok = MemoryGuard.tick()

      assert %{phase: "done", outcome: %{"outcome" => "unconfirmed"}} = Journal.get(ctx.db, id)
      assert [{"agent:c", _}] = events(ctx.db, "memory_guard_close_unconfirmed")
      assert events(ctx.db, "memory_guard_idle_closed") == []
      assert [marker] = markers_of(ctx, "agent:c")
      assert marker =~ @conditional
    end

    test "O2 (rev 5, 5): crash after dispatched, process gone: idle_closed and one plain marker",
         ctx do
      id = crash_close!(ctx, :dispatched)
      assert %{phase: "dispatched", dispatch: %{"sentAt" => _}} = Journal.get(ctx.db, id)
      guard!(ctx)
      :ok = MemoryGuard.tick()
      assert %{phase: "done", outcome: %{"outcome" => "confirmed"}} = Journal.get(ctx.db, id)

      assert [{"agent:c", %{"certainty" => "confirmed"}}] =
               events(ctx.db, "memory_guard_idle_closed")

      assert [marker] = markers_of(ctx, "agent:c")
      assert marker =~ "Tightbeam closed this session's process while it was idle"
    end

    test "O2 (rev 5, 6): crash after dispatched, process alive past the confirm window: close_failed",
         ctx do
      id = crash_close!(ctx, :dispatched, ends_process: false)
      Process.sleep(400)
      guard!(ctx)
      :ok = MemoryGuard.tick()
      assert %{phase: "done", outcome: %{"outcome" => "failed"}} = Journal.get(ctx.db, id)
      assert [{"agent:c", _}] = events(ctx.db, "memory_guard_close_failed")
      assert markers_of(ctx, "agent:c") == []
    end

    test "O2 (rev 5, 7): the real close's outcome write fails: retried; the marker is never sent twice",
         ctx do
      {:ok, _} =
        DB.query(ctx.db, """
        CREATE TRIGGER o2_out BEFORE INSERT ON lifecycle_events WHEN NEW.kind='memory_guard_idle_closed'
        BEGIN SELECT RAISE(ABORT, 'injected'); END
        """)

      proc!(ctx.root, 961, 1, 961, 10 * @mib)
      launch!(ctx.base, "sl-c", "sid-c", 961, 961, 512 * @mib)
      meminfo!(ctx.root, 16 * @gib, div(16 * @gib * 10, 100))
      adapter = adapter!()
      guard!(ctx)
      resident!(adapter, ["sid-c"])
      :ok = MemoryGuard.tick()
      settle_closes!()
      assert_received {:closed, "sid-c", _}

      {:ok, [%{id: id, phase: "dispatched"}]} =
        Journal.page(ctx.db, @host, "idle_close", nil, nil, 8)

      assert markers_of(ctx, "agent:c") == []

      {:ok, _} = DB.query(ctx.db, "DROP TRIGGER o2_out")
      meminfo!(ctx.root, 16 * @gib, 12 * @gib)

      for _ <- 1..3, do: :ok = MemoryGuard.tick()
      assert %{phase: "done", outcome: %{"outcome" => "confirmed"}} = Journal.get(ctx.db, id)
      assert [_] = events(ctx.db, "memory_guard_idle_closed")
      assert [_] = markers_of(ctx, "agent:c")
    end
  end

  describe "durable effects: override admission under a guard override (O1, D2)" do
    alias Tightbeam.MemoryGuard.Episodes

    setup ctx do
      meminfo!(ctx.root, 16 * @gib, 12 * @gib)
      empty = Path.join(ctx.root, "no-cli")
      File.mkdir_p!(empty)
      {:opened, ep} = Episodes.open(ctx.db, %{host: @host, kind: "guard", since: 1, why: "t"})
      id = ep["episodeId"]
      base = %{"episodeId" => id, "host" => @host, "kind" => "guard", "key" => nil}
      {:accepted, _} = Episodes.judge(ctx.db, Map.put(base, "action", "recovery"), "r-g", @host)
      :ok = Episodes.record_outcome(ctx.db, Episodes.recovery(ctx.db, id), "failed", [])
      {:accepted, _} = Episodes.judge(ctx.db, Map.put(base, "action", "override"), "o-g", @host)
      session!(ctx, "agent:o")
      seq = queue!(ctx, "agent:o", "needs a launch")
      %{episode: id, empty: empty, seq: seq}
    end

    defp claim!(ctx, seq),
      do:
        {:ok, _} =
          DB.query(ctx.db, "UPDATE turns SET status='running', startedAt=?2 WHERE seq=?1", [
            seq,
            System.system_time(:millisecond) + 1
          ])

    test "O1 (crash 1): the admission's intent cannot be written: the launch is held, nothing applied",
         ctx do
      {:ok, _} =
        DB.query(ctx.db, """
        CREATE TRIGGER o1_intent BEFORE INSERT ON memory_guard_effects
        BEGIN SELECT RAISE(ABORT, 'injected'); END
        """)

      guard!(ctx, cli_bin: ctx.empty)
      assert {:held, ["guard_unavailable"]} = MemoryGuard.admit("agent:o")
      assert %{"applied" => false} = Episodes.override(ctx.db, ctx.episode)
    end

    test "O1 (crash 2): a restart before the claim: still only accepted; the claim then applies it once",
         ctx do
      guard!(ctx, cli_bin: ctx.empty)
      assert :ok = MemoryGuard.admit("agent:o")
      stop_supervised!(MemoryGuard)
      guard!(ctx, cli_bin: ctx.empty)
      :ok = MemoryGuard.tick()
      assert %{"applied" => false} = Episodes.override(ctx.db, ctx.episode)

      claim!(ctx, ctx.seq)
      :ok = MemoryGuard.tick()
      :ok = MemoryGuard.tick()
      assert %{"applied" => true} = Episodes.override(ctx.db, ctx.episode)
      assert [_] = events(ctx.db, "memory_guard_override_applied")
    end

    test "O1 (crash 3): a restart after the claim, before the outcome: applied once with no further admission",
         ctx do
      guard!(ctx, cli_bin: ctx.empty)
      assert :ok = MemoryGuard.admit("agent:o")
      claim!(ctx, ctx.seq)
      stop_supervised!(MemoryGuard)
      guard!(ctx, cli_bin: ctx.empty)
      :ok = MemoryGuard.tick()
      assert %{"applied" => true} = Episodes.override(ctx.db, ctx.episode)
      assert [_] = events(ctx.db, "memory_guard_override_applied")
    end

    test "O1 (crash 4): the outcome write fails: retried until written",
         ctx do
      guard!(ctx, cli_bin: ctx.empty)
      assert :ok = MemoryGuard.admit("agent:o")
      claim!(ctx, ctx.seq)

      {:ok, _} =
        DB.query(ctx.db, """
        CREATE TRIGGER o1_out BEFORE UPDATE OF applied ON memory_guard_episodes
        BEGIN SELECT RAISE(ABORT, 'injected'); END
        """)

      :ok = MemoryGuard.tick()
      assert %{"applied" => false} = Episodes.override(ctx.db, ctx.episode)
      {:ok, _} = DB.query(ctx.db, "DROP TRIGGER o1_out")
      :ok = MemoryGuard.tick()
      :ok = MemoryGuard.tick()
      assert %{"applied" => true} = Episodes.override(ctx.db, ctx.episode)
    end

    test "O1 (crash 5, D2): the turn is cancelled before its claim: not applied, and the override stays available",
         ctx do
      guard!(ctx, cli_bin: ctx.empty)
      assert :ok = MemoryGuard.admit("agent:o")
      {:ok, _} = DB.query(ctx.db, "UPDATE turns SET status='canceled' WHERE seq=?1", [ctx.seq])
      :ok = MemoryGuard.tick()
      :ok = MemoryGuard.tick()

      {:ok, [[outcome]]} =
        DB.query(
          ctx.db,
          "SELECT outcome FROM memory_guard_effects WHERE kind='override_admission'",
          []
        )

      assert %{"outcome" => "not_applied"} = JSON.decode!(outcome)
      assert %{"applied" => false} = Episodes.override(ctx.db, ctx.episode)
    end
  end

  describe "durable effects: units, publication, the inventory marker (O5/O16, O6-O8, D3)" do
    alias Tightbeam.MemoryGuard.{Publish, Watcher}

    test "O5 (crash 1/2): a unit that cannot be removed is journaled; after a restart the resolver removes it once it can",
         ctx do
      {harness, _unit, _set_mode} = enforced_with_unit!(ctx)
      unit = Path.join(harness, "session-live")
      File.write!(Path.join(unit, "cgroup.events"), "populated 0\nfrozen 0\n")
      :ok = MemoryGuard.tick()

      assert {:ok, [%{kind: "unit_remove"}]} =
               Journal.page(ctx.db, @host, "unit_remove", nil, nil, 8)

      stop_supervised!(MemoryGuard)
      guard!(ctx, probe: enforced_probe(), cgroup_fs: Path.join(ctx.root, "sys/fs/cgroup"))
      # Entering enforced writes the unit's limit files again: emptied now.
      for file <- File.ls!(unit), do: File.rm!(Path.join(unit, file))
      :ok = MemoryGuard.tick()
      refute File.dir?(unit)
      assert {:ok, []} = Journal.page(ctx.db, @host, "unit_remove", nil, nil, 8)
    end

    test "O16: at start, an empty unit no launch names (a removal lost to a restart) is removed",
         ctx do
      {harness, _unit, _set_mode} = enforced_with_unit!(ctx)
      orphan = Path.join(harness, "adapter-orphan")
      File.mkdir_p!(orphan)
      File.write!(Path.join(orphan, "cgroup.events"), "populated 0\nfrozen 0\n")
      stop_supervised!(MemoryGuard)
      guard!(ctx, probe: enforced_probe(), cgroup_fs: Path.join(ctx.root, "sys/fs/cgroup"))
      # Its files keep the stand-in directory from going: journaled, then
      # removed by the resolver once it can be.
      assert {:ok, [%{intent: %{"unit" => unit}}]} =
               Journal.page(ctx.db, @host, "unit_remove", nil, nil, 8)

      assert unit =~ "adapter-orphan"
      for file <- File.ls!(orphan), do: File.rm!(Path.join(orphan, file))
      :ok = MemoryGuard.tick()
      refute File.dir?(orphan)
    end

    defp set_mode!(ctx, value) do
      {:ok, {:ok, _}} =
        DB.transaction(
          ctx.db,
          &Settings.set_in_txn(&1, @host, "mode", value, "user:owner", 16 * @gib)
        )

      MemoryGuard.settings_changed(@host)
    end

    test "O6 (crash 2-4, D3): a mode whose step settings cannot be written is requested, not applied: held, said so, retried after a restart",
         ctx do
      meminfo!(ctx.root, 16 * @gib, 12 * @gib)
      guard!(ctx)
      assert :ok = set_mode!(ctx, "off")
      dir = Records.dir(ctx.base)
      config = Path.join(dir, "launch.json")
      assert %{"mode" => "off"} = config |> File.read!() |> JSON.decode!()

      # Back to watched, with the step's directory refusing writes.
      File.chmod!(dir, 0o555)
      on_exit(fn -> File.chmod(dir, 0o755) end)
      assert {:error, {:not_applied, why}} = set_mode!(ctx, "auto")
      assert why =~ "not yet written"
      assert MemoryGuard.read(@host).notEnforcedReason =~ "not yet applied"
      assert %{"mode" => "off"} = config |> File.read!() |> JSON.decode!()
      assert Unguarded.mode_in_force(ctx.db, @host) == nil

      # The step still reads `off`, so a launch that needs it is held.
      session!(ctx, "agent:p")
      queue!(ctx, "agent:p", "needs a launch")
      assert {:held, ["guard_unavailable"]} = MemoryGuard.admit("agent:p")

      # A restart; the directory takes writes again; the resolver publishes.
      stop_supervised!(MemoryGuard)
      File.chmod!(dir, 0o755)
      guard!(ctx)
      :ok = MemoryGuard.tick()
      assert %{"mode" => "watched"} = config |> File.read!() |> JSON.decode!()
      assert {:ok, []} = Journal.page(ctx.db, @host, "publish_config", nil, nil, 8)
      assert :ok = MemoryGuard.admit("agent:p")
    end

    test "O7 (crash 2/3/5, D3): off brought into force while the guard is down, its settings not writable: not applied, then the Watcher publishes it",
         ctx do
      fs = Path.join(ctx.root, "sys/fs/cgroup")
      File.mkdir_p!(fs)
      dir = Records.dir(ctx.base)
      File.mkdir_p!(dir)
      File.write!(Path.join(dir, "launch.json"), ~s({"v":1,"mode":"watched"}))
      File.chmod!(dir, 0o555)
      on_exit(fn -> File.chmod(dir, 0o755) end)

      assert {:not_applied, why} =
               Unguarded.bring_off_into_force(ctx.db, @host, ctx.base,
                 cgroup_fs: fs,
                 harness_candidates: fn -> {:ok, []} end
               )

      assert why =~ "recorded; the launch step's settings are not yet written"
      assert Unguarded.mode_in_force(ctx.db, @host) == nil

      File.chmod!(dir, 0o755)

      start_supervised!(
        {Watcher,
         db: ctx.db,
         base_dir: ctx.base,
         local_host: @host,
         interval_ms: :manual,
         name: :o7_watcher,
         guard_running?: fn -> false end,
         finding: fn -> strict_finding() end}
      )

      :ok = Watcher.tick(:o7_watcher)
      assert Unguarded.mode_in_force(ctx.db, @host) == "off"
      assert %{"mode" => "off"} = Path.join(dir, "launch.json") |> File.read!() |> JSON.decode!()
    end

    test "O8 (crash 1/2): an inventory whose marker cannot be written is not initialized; it is written on the next start",
         ctx do
      sessions = Path.join(Records.dir(ctx.base), "sessions")
      File.mkdir_p!(sessions)
      File.chmod!(sessions, 0o555)
      on_exit(fn -> File.chmod(sessions, 0o755) end)

      assert {:error, why} = Records.init_inventory(ctx.db, ctx.base, "boot-1", @host)
      assert why =~ "not yet initialized"

      assert {:ok, [%{kind: "publish_marker"}]} =
               Journal.page(ctx.db, @host, "publish_marker", nil, nil, 8)

      File.chmod!(sessions, 0o755)
      assert {:ok, generation} = Records.init_inventory(ctx.db, ctx.base, "boot-1", @host)

      assert File.read!(Path.join(sessions, ".generation")) == generation or
               Records.check_inventory(ctx.base, generation) == :ok

      assert {:ok, []} = Journal.page(ctx.db, @host, "publish_marker", nil, nil, 8)
    end
  end

  describe "durable effects: holds, clocks and last use (O9, O10, O17, O18)" do
    alias Tightbeam.MemoryGuard.Episodes

    test "O17/O9: a restart during a continuous hold keeps its start and place, and posts no second waiting marker",
         ctx do
      meminfo!(ctx.root, 16 * @gib, 1 * @gib)
      guard!(ctx)
      :ok = MemoryGuard.tick()
      session!(ctx, "agent:h")
      queue!(ctx, "agent:h", "needs a launch")
      assert {:held, ["memory_floor"]} = MemoryGuard.admit("agent:h")

      {:ok, [[since]]} =
        DB.query(
          ctx.db,
          "SELECT openedAt FROM memory_guard_open WHERE kind='hold' AND ref='agent:h'",
          []
        )

      assert [_] = markers(ctx.db, "agent:h")

      stop_supervised!(MemoryGuard)
      guard!(ctx)
      :ok = MemoryGuard.tick()
      assert %{since: ^since} = :sys.get_state(MemoryGuard).held["agent:h"]
      assert {:held, ["memory_floor"]} = MemoryGuard.admit("agent:h")
      assert [_] = markers(ctx.db, "agent:h")

      {:ok, [[^since]]} =
        DB.query(
          ctx.db,
          "SELECT openedAt FROM memory_guard_open WHERE kind='hold' AND ref='agent:h'",
          []
        )
    end

    test "O10: a restart 10 minutes into a stuck custody refusal opens the episode 15 minutes after the refusal began",
         ctx do
      Application.put_env(:tightbeam, :memory_guard_stuck_ms, 15 * 60_000)
      on_exit(fn -> Application.delete_env(:tightbeam, :memory_guard_stuck_ms) end)
      meminfo!(ctx.root, 16 * @gib, 12 * @gib)
      clock = :counters.new(1, [])
      t0 = System.system_time(:millisecond)
      :counters.put(clock, 1, t0)
      at = fn -> :counters.get(clock, 1) end
      insert_adapter_row!(ctx.db, "adapter-launch-1", 950)
      {:ok, _} = DB.query(ctx.db, "UPDATE harness_processes SET state='exited'")
      proc!(ctx.root, 951, 1, 951, 10 * @mib)
      launch!(ctx.base, "sl-stuck", "sid-stuck", 951, 951, 512 * @mib)
      opts = [kill_result: {:error, :harness_group_failed}, signal_works: false, clock: at]
      guard!(ctx, opts)
      session!(ctx, "agent:new", "sid-new")
      queue!(ctx, "agent:new", "needs a new adapter")
      assert {:held, ["guard_unavailable"]} = MemoryGuard.admit("agent:new", ctx.db)

      :counters.add(clock, 1, 10 * 60_000)
      :ok = MemoryGuard.tick()
      stop_supervised!(MemoryGuard)
      guard!(ctx, opts)
      :counters.add(clock, 1, 4 * 60_000)
      :ok = MemoryGuard.tick()
      assert Episodes.active(ctx.db, @host) == []

      :counters.add(clock, 1, 60_000)
      :ok = MemoryGuard.tick()
      assert [%{"kind" => "custody", "since" => ^t0}] = Episodes.active(ctx.db, @host)
    end

    test "O18 (rev 4 D4): last use is the latest started turn's activity, past a newer queued tail; none started within 256 is unknown",
         ctx do
      session!(ctx, "agent:u", "sid-u")
      old = queue!(ctx, "agent:u", "done long ago")

      {:ok, _} =
        DB.query(
          ctx.db,
          "UPDATE turns SET status='delivered', startedAt=1000, endedAt=2000 WHERE seq=?1",
          [old]
        )

      queue!(ctx, "agent:u", "queued now")
      assert MemoryGuard.durable_last_use(ctx.db, "sid-u") == 2000

      # More than 256 newer turns that never started: unknown.
      for n <- 1..257, do: queue!(ctx, "agent:u", "q#{n}")
      assert MemoryGuard.durable_last_use(ctx.db, "sid-u") == nil

      # A session whose turns never started: unknown.
      session!(ctx, "agent:v", "sid-v")
      queue!(ctx, "agent:v", "never ran")
      assert MemoryGuard.durable_last_use(ctx.db, "sid-v") == nil
    end
  end

  describe "durable effects: the bound and its liveness (rev 3 D5)" do
    test "D5: one sample acts on at most a page of a stream; a backlog drains within its bound while new rows keep arriving",
         ctx do
      guard!(ctx)
      now = System.system_time(:millisecond)

      add = fn from, count, at ->
        {:ok, _} =
          DB.transaction(ctx.db, fn txn ->
            for n <- from..(from + count - 1) do
              Journal.intend_in_txn(
                txn,
                "unit_remove",
                "u#{n}",
                @host,
                "u#{n}",
                %{unit: "/none/u#{n}", fs: Path.join(ctx.root, "no-fs")},
                at
              )
            end
          end)
      end

      add.(1, 300, now - 1_000)

      old = fn ->
        {:ok, [[n]]} =
          DB.query(
            ctx.db,
            "SELECT COUNT(*) FROM memory_guard_effects WHERE kind='unit_remove' AND phase != 'done' AND createdAt < ?1",
            [now]
          )

        n
      end

      :ok = MemoryGuard.tick()
      assert 300 - old.() <= 32

      # New rows keep arriving; every row present when the cycle began is
      # acted on within ceil(300 / 6) samples.
      for i <- 1..50 do
        add.(1000 + i * 5, 5, now + i)
        :ok = MemoryGuard.tick()
      end

      assert old.() == 0
    end

    test "D5 liveness: an eligible waiter behind more than 256 rows blocked by another reason is reached within ceil(stale / 256) + 1 evaluations",
         ctx do
      meminfo!(ctx.root, 16 * @gib, 12 * @gib)
      guard!(ctx)
      key = "claude:shared@testhost"

      {:ok, _} =
        DB.transaction(ctx.db, fn txn ->
          for n <- 1..300 do
            Tightbeam.DB.Txn.q(
              txn,
              """
              INSERT INTO memory_guard_open (kind, ref, subject, host, detail, openedAt, orderKey, adapterKey)
              VALUES ('hold', ?1, ?1, ?2, '{"details":{},"seq":0}', ?3, ?4, ?5)
              """,
              ["agent:p#{n}", @host, n, "00:" <> String.pad_leading("#{n}", 20, "0"), key]
            )
          end
        end)

      # Each of them is held by an open limit-fallback evaluation.
      for n <- 1..300 do
        session!(ctx, "agent:p#{n}")
        seq = queue!(ctx, "agent:p#{n}", "w")

        {:ok, _} =
          DB.query(
            ctx.db,
            "INSERT INTO limit_fallback_evaluations (sessionKey, turnSeq, heldAt, createdAt) VALUES (?1, ?2, 1, 1)",
            [
              "agent:p#{n}",
              seq
            ]
          )
      end

      session!(ctx, "agent:s")
      queue!(ctx, "agent:s", "eligible")

      {:ok, _} =
        DB.query(
          ctx.db,
          """
          INSERT INTO memory_guard_open (kind, ref, subject, host, detail, openedAt, orderKey, adapterKey)
          VALUES ('hold', 'agent:s', 'agent:s', ?1, '{"details":{},"seq":0}', 999, '99:0', ?2)
          """,
          [@host, key]
        )

      adapter = adapter!()
      resident!(adapter, ["sid-x"])
      refute_received {:nudged, "agent:s"}
      resident!(adapter, ["sid-y"])
      assert_received {:nudged, "agent:s"}

      {:ok, [[blocked]]} =
        DB.query(
          ctx.db,
          "SELECT COUNT(*) FROM memory_guard_open WHERE kind='hold' AND blocked IS NOT NULL",
          []
        )

      assert blocked == 300
    end
  end

  describe "bounded continuations (design rev 1/2)" do
    alias Tightbeam.MemoryGuard.State, as: GuardState

    @key "claude:shared@testhost"

    # Holds as the guard writes them: each lifetime takes a generation.
    # `turns: true` gives each session a queued turn (else the eligible walk
    # finds it gone and ends the hold through the real drop path).
    defp holds!(ctx, prefix, count, fields \\ []) do
      if Keyword.get(fields, :turns, false) do
        for n <- 1..count, do: session!(ctx, "#{prefix}#{n}") && queue!(ctx, "#{prefix}#{n}", "w")
      end

      {:ok, _} =
        DB.transaction(ctx.db, fn txn ->
          for n <- 1..count do
            Tightbeam.DB.Txn.q(
              txn,
              """
              INSERT INTO memory_guard_open
                (kind, ref, subject, host, detail, openedAt, orderKey, blocked, adapterKey, gen)
              VALUES ('hold', ?1, ?1, ?2, '{"details":{"resident_cap":1},"seq":0}', ?3, ?4, ?5, ?6, ?7)
              """,
              [
                "#{prefix}#{n}",
                @host,
                Keyword.get(fields, :opened_at, n),
                "00:" <> String.pad_leading("#{n}", 20, "0"),
                Keyword.get(fields, :blocked),
                @key,
                GuardState.next_gen_in_txn(txn)
              ]
            )
          end
        end)
    end

    defp count!(ctx, sql, params \\ []) do
      {:ok, [[n]]} = DB.query(ctx.db, sql, params)
      n
    end

    defp rows!(ctx, sql) do
      {:ok, rows} = DB.query(ctx.db, sql, [])
      rows
    end

    defp blocked(ctx),
      do:
        count!(
          ctx,
          "SELECT COUNT(*) FROM memory_guard_open WHERE kind='hold' AND blocked IS NOT NULL"
        )

    defp notes(ctx), do: events(ctx.db, "admission_hold_remaining")

    # A real host-level release: the floor breached, then clear.
    defp floor_release!(ctx) do
      meminfo!(ctx.root, 16 * @gib, div(16 * @gib * 10, 100))
      :ok = MemoryGuard.tick()
      meminfo!(ctx.root, 16 * @gib, div(16 * @gib * 50, 100))
      :ok = MemoryGuard.tick()
    end

    defp cap!(ctx) do
      {:ok, {:ok, _}} =
        DB.transaction(
          ctx.db,
          &Settings.set_in_txn(&1, @host, "residentCap", "3", "user:owner", 16 * @gib)
        )

      :ok = MemoryGuard.settings_changed(@host)
      adapter = adapter!()
      for n <- 1..2, do: session!(ctx, "agent:r#{n}", "sid-r#{n}")
      resident!(adapter, ["sid-r1", "sid-r2"])
    end

    test "unblock (§1, D1): 32 per sample; order guard; restart resumes; a re-mark behind the cursor and a later hold are not cleared",
         ctx do
      meminfo!(ctx.root, 16 * @gib, 12 * @gib)
      guard!(ctx)
      cap!(ctx)
      holds!(ctx, "agent:p", 100, blocked: "quota_park", turns: true)

      {:ok, _} =
        DB.transaction(
          ctx.db,
          &Admission.quota_released_in_txn(&1, "incident-b1", "claude", @host)
        )

      # The release writes one row, not 100; a hold opened after it in the
      # same millisecond has a later generation.
      [[at]] = rows!(ctx, "SELECT openedAt FROM memory_guard_open WHERE kind='unblock'")
      holds!(ctx, "agent:late-mark", 1, blocked: "quota_park", opened_at: at)
      assert blocked(ctx) == 101

      # One slot is free, but marked holds ahead of it may be eligible now.
      session!(ctx, "agent:late")
      queue!(ctx, "agent:late", "late")
      assert {:held, ["resident_cap"]} = MemoryGuard.admit("agent:late")

      :ok = MemoryGuard.tick()
      assert blocked(ctx) in (101 - 32)..100

      # p1 was cleared; marked again (still blocked by another reason), it is
      # behind the cursor and not chased.
      {:ok, _} =
        DB.query(ctx.db, "UPDATE memory_guard_open SET blocked='quota_park' WHERE ref='agent:p1'")

      # A restart mid-pass resumes from the durable cursor.
      stop_supervised!(MemoryGuard)
      guard!(ctx)

      for _ <- 1..40,
          count!(ctx, "SELECT COUNT(*) FROM memory_guard_open WHERE kind='unblock'") > 0,
          do: :ok = MemoryGuard.tick()

      assert count!(ctx, "SELECT COUNT(*) FROM memory_guard_open WHERE kind='unblock'") == 0

      assert [["agent:late-mark1"], ["agent:p1"]] =
               rows!(
                 ctx,
                 "SELECT ref FROM memory_guard_open WHERE kind='hold' AND blocked IS NOT NULL ORDER BY ref"
               )
    end

    test "release note (§2, D1): one record per hold open at the release, paged, across a restart; none for a hold opened after it in its millisecond",
         ctx do
      guard!(ctx)
      holds!(ctx, "agent:h", 70, turns: true)
      floor_release!(ctx)

      assert length(notes(ctx)) in 1..32
      [[at]] = rows!(ctx, "SELECT openedAt FROM memory_guard_open WHERE kind='release_note'")
      holds!(ctx, "agent:after", 1, turns: true, opened_at: at)

      stop_supervised!(MemoryGuard)
      guard!(ctx)
      for _ <- 1..30, do: :ok = MemoryGuard.tick()

      subjects = Enum.map(notes(ctx), &elem(&1, 0))
      assert Enum.sort(subjects) == Enum.sort(for n <- 1..70, do: "agent:h#{n}")

      assert Enum.all?(notes(ctx), fn {_, detail} ->
               %{"released" => "memory_floor", "remaining" => ["resident_cap"], "readAt" => t} =
                 detail

               is_integer(t)
             end)

      assert count!(ctx, "SELECT COUNT(*) FROM memory_guard_open WHERE kind='release_note'") == 0
    end

    test "release note (§2, D1): a hold ended before its page keeps its record (tombstone); notes FIFO; drop and reopen in one ms are two lifetimes",
         ctx do
      guard!(ctx)
      # No queued turns: the release's own eligible walk ends these holds.
      holds!(ctx, "agent:t", 70)
      floor_release!(ctx)
      assert count!(ctx, "SELECT COUNT(*) FROM memory_guard_open WHERE kind='hold'") == 0

      assert count!(ctx, "SELECT COUNT(*) FROM memory_guard_open WHERE kind='hold_owed'") in 38..70

      # agent:t1 opens again in the same millisecond and ends again at the
      # second release: a second lifetime, a second tombstone identity.
      holds!(ctx, "agent:t", 1, opened_at: 1)
      floor_release!(ctx)

      for _ <- 1..40, do: :ok = MemoryGuard.tick()

      records = notes(ctx)

      assert Enum.all?(records, fn {_, detail} ->
               %{"remaining" => ["resident_cap"], "resumedAt" => t} = detail
               is_integer(t)
             end)

      # The first release's 70, then the second's one (FIFO by generation).
      {first, second} = Enum.split(Enum.map(records, &elem(&1, 0)), 70)
      assert Enum.sort(first) == Enum.sort(for n <- 1..70, do: "agent:t#{n}")
      assert second == ["agent:t1"]

      assert count!(
               ctx,
               "SELECT COUNT(*) FROM memory_guard_open WHERE kind IN ('hold_owed','release_note')"
             ) == 0
    end

    test "unblock (att_660ea131 B1): a second release while the item is open starts its range again, so a hold marked again during that park is cleared",
         ctx do
      meminfo!(ctx.root, 16 * @gib, 12 * @gib)
      guard!(ctx)
      holds!(ctx, "agent:p", 100, blocked: "quota_park", turns: true)

      release = fn ->
        {:ok, _} =
          DB.transaction(
            ctx.db,
            &Admission.quota_released_in_txn(&1, "incident-b1", "claude", @host)
          )
      end

      release.()
      :ok = MemoryGuard.tick()
      assert blocked(ctx) < 100

      assert [["agent:p1", nil]] =
               rows!(ctx, "SELECT ref, blocked FROM memory_guard_open WHERE ref='agent:p1'")

      # The key parks again and p1 is marked; then that park releases.
      {:ok, _} =
        DB.query(ctx.db, "UPDATE memory_guard_open SET blocked='quota_park' WHERE ref='agent:p1'")

      release.()

      for _ <- 1..40,
          count!(ctx, "SELECT COUNT(*) FROM memory_guard_open WHERE kind='unblock'") > 0,
          do: :ok = MemoryGuard.tick()

      assert blocked(ctx) == 0
    end

    test "release note (att_660ea131 B2): a hold that resumes after a quota release, before the floor note reaches it, keeps its quota_park record",
         ctx do
      key = "claude:shared@testhost"

      {:ok, _} =
        DB.query(
          ctx.db,
          "INSERT INTO harness_park_fences (adapterKey, requestedAt, generation) VALUES (?1, 1, 9)",
          [key]
        )

      meminfo!(ctx.root, 16 * @gib, div(16 * @gib * 10, 100))
      guard!(ctx)
      :ok = MemoryGuard.tick()

      # 200 holds ahead of H, so the floor note pages for several samples.
      holds!(ctx, "agent:a", 200, turns: true)
      session!(ctx, "agent:h")
      queue!(ctx, "agent:h", "w")
      assert {:held, ["memory_floor"]} = MemoryGuard.admit("agent:h")

      [[detail]] =
        rows!(ctx, "SELECT detail FROM memory_guard_open WHERE kind='hold' AND ref='agent:h'")

      assert %{"other" => ["quota_park"]} = JSON.decode!(detail)

      # The floor releases (its note owes H a record: H stays parked).
      meminfo!(ctx.root, 16 * @gib, div(16 * @gib * 50, 100))
      :ok = MemoryGuard.tick()
      assert count!(ctx, "SELECT COUNT(*) FROM memory_guard_open WHERE kind='release_note'") == 1

      # The park releases and H resumes before the note reaches it.
      {:ok, _} = DB.query(ctx.db, "DELETE FROM harness_park_fences")

      {:ok, _} =
        DB.transaction(
          ctx.db,
          &Admission.quota_released_in_txn(&1, "incident-q", "claude", @host)
        )

      assert :ok = MemoryGuard.admit("agent:h")

      assert [_] =
               rows!(
                 ctx,
                 "SELECT ref FROM memory_guard_open WHERE kind='hold_owed' AND subject='agent:h'"
               )

      for _ <- 1..60,
          count!(ctx, "SELECT COUNT(*) FROM memory_guard_open WHERE kind='release_note'") > 0,
          do: :ok = MemoryGuard.tick()

      assert [
               {"agent:h",
                %{"released" => "memory_floor", "remaining" => ["quota_park"], "resumedAt" => _}}
             ] =
               Enum.filter(notes(ctx), &(elem(&1, 0) == "agent:h"))
    end

    test "quota source probe (att_660ea131 B3): a source's retry is found on memory_guard_retry_source, never by scanning the retry history",
         ctx do
      {:ok, plan} =
        DB.query(
          ctx.db,
          """
          EXPLAIN QUERY PLAN
          SELECT 1 FROM wake_retry_attempts retry INDEXED BY memory_guard_retry_source
          WHERE retry.sourceTurnSeq=?1 AND retry.retryWakeId IS NOT NULL
          """,
          [1]
        )

      details = Enum.map_join(plan, " ", &List.last/1)

      assert details =~
               "SEARCH retry USING COVERING INDEX memory_guard_retry_source (sourceTurnSeq=?)" or
               details =~ "SEARCH retry USING INDEX memory_guard_retry_source (sourceTurnSeq=?)"

      refute details =~ "SCAN"
    end

    test "Watcher nudges (§4): 64 per pass from a durable cursor; a restart resumes; later holds wait for the next cycle",
         ctx do
      {:ok, _} =
        DB.transaction(ctx.db, fn txn ->
          for n <- 1..150,
              do:
                GuardState.open_in_txn(
                  txn,
                  "unguarded_hold",
                  "agent:u#{n}",
                  "agent:u#{n}",
                  @host,
                  nil
                )
        end)

      cursor = fn ->
        case rows!(ctx, "SELECT detail FROM memory_guard_open WHERE kind='watcher_nudge'") do
          [[detail]] -> JSON.decode!(detail)["cursor"]
          [] -> nil
        end
      end

      assert :ok = Unguarded.nudge_pass(ctx.db, @host)
      assert [_, "agent:u" <> _] = first = cursor.()

      # A "restart": nothing in memory; the next pass reads the cursor.
      assert :ok = Unguarded.nudge_pass(ctx.db, @host)
      assert cursor.() > first

      {:ok, _} =
        DB.transaction(
          ctx.db,
          &GuardState.open_in_txn(&1, "unguarded_hold", "agent:z", "agent:z", @host, nil)
        )

      assert :ok = Unguarded.nudge_pass(ctx.db, @host)
      assert cursor.() == nil
      assert {:ok, nil} = Unguarded.held_since(ctx.db, "elsewhere")
    end

    test "user-facing class (§5, D4): a queued user carrier at any position, until claim or cancellation",
         ctx do
      carrier = fn key, posts ->
        {:ok, {:ok, seq}} =
          DB.transaction(ctx.db, fn txn ->
            Ledger.enqueue_in_txn(txn, %{
              session_key: key,
              message_id: "m-carrier-#{System.unique_integer([:positive])}",
              origin: "process:tightbeam",
              prompt: "[batched notices: 1]",
              is_batch_carrier: true,
              user_posts: posts
            })
          end)

        seq
      end

      worker = fn key ->
        {:ok, _} =
          Ledger.enqueue(ctx.db, %{
            session_key: key,
            message_id: "m-w-#{System.unique_integer([:positive])}",
            origin: "agent:other",
            prompt: "work"
          })
      end

      class = fn key -> Tightbeam.MemoryGuard.Priority.class(ctx.db, Org.get(ctx.db, key)) end

      session!(ctx, "agent:w")
      for _ <- 1..20, do: worker.("agent:w")
      _ = carrier.("agent:w", 0)
      assert class.("agent:w") == "worker"
      _ = carrier.("agent:w", 1)
      assert class.("agent:w") == "user-facing"

      # Claim: the carrier leaves the queue.
      session!(ctx, "agent:c1")
      _ = carrier.("agent:c1", 2)
      assert class.("agent:c1") == "user-facing"
      assert {:ok, _} = Ledger.claim_next(ctx.db, "agent:c1", "owner-1")
      assert class.("agent:c1") == "worker"

      # Cancellation.
      session!(ctx, "agent:c2")
      seq = carrier.("agent:c2", 1)
      {:ok, _} = DB.transaction(ctx.db, &Ledger.cancel_queued_in_txn(&1, seq, "test"))
      assert class.("agent:c2") == "worker"

      assert count!(
               ctx,
               "SELECT COUNT(*) FROM memory_guard_user_carriers WHERE sessionKey IN ('agent:c1','agent:c2')"
             ) == 0
    end
  end
end

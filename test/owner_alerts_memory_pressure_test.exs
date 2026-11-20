defmodule Tightbeam.OwnerAlertsMemoryPressureTest do
  @moduledoc """
  Alert kind G1, host memory pressure (§6A): the sampler, its episodes, the
  run marker file and the restart alert.

  Everything outside our side of the seams is injected: the procfs and
  cgroupfs roots are fixture directories, both clocks are `:atomics` cells the
  test sets before each sample, sampling is manual (`interval: :manual`, one
  sample per `MemoryPressure.sample_now/2`), and the Harklight Agent is the
  injected runner. `trace: self()` reports every file the probe reads and
  every marker write the writer applies.
  """

  use Tightbeam.TestCase, async: false

  alias Tightbeam.{
    Archetypes,
    ConditionFacts,
    DB,
    EventLog,
    Gateway,
    Model,
    Org,
    OwnerAlerts,
    Wakes
  }

  alias Tightbeam.OwnerAlerts.MemoryPressure
  alias Tightbeam.OwnerAlerts.MemoryPressure.Marker

  # T29's waiter is woken through the ordinary delivery path, which nudges
  # the lane manager; this stands in for it, as in the condition fact tests.
  defmodule LaneDoorbell do
    use GenServer

    def start_link(parent),
      do: GenServer.start_link(__MODULE__, parent, name: Tightbeam.LaneManager)

    def init(parent), do: {:ok, parent}

    def handle_call({:ensure_lane, session_key}, _from, parent) do
      send(parent, {:lane_nudged, session_key})
      {:reply, :ok, parent}
    end
  end

  @owner "george"
  @host "sirius"
  @minute 60_000
  @hour 3_600_000
  # MemTotal of every fixture: 32 GiB, in KiB.
  @gib_kib 1_048_576
  @total 32 * @gib_kib
  @mono0 1_000_000_000

  setup do
    db = world_db()
    root = Path.join(System.tmp_dir!(), "tightbeam-g1-#{System.unique_integer([:positive])}")
    proc = Path.join(root, "proc")
    cgroup = Path.join(root, "cgroup")
    state_dir = Path.join(root, "state")

    for dir <- [Path.join(proc, "pressure"), Path.join(proc, "self"), cgroup, state_dir],
        do: File.mkdir_p!(dir)

    on_exit(fn -> File.rm_rf!(root) end)

    ctx = %{
      db: db,
      proc: proc,
      cgroup: cgroup,
      state_dir: state_dir,
      clock: :atomics.new(2, signed: true),
      # A day back, so every injected wall time is in the past.
      wall0: System.system_time(:millisecond) - 24 * @hour
    }

    set_clock(ctx, 0)
    calm(ctx)
    ctx
  end

  ## M2, M4: runs and the open

  test "T21: two minutes of pressure open one episode: alert and fact together, then the marker",
       ctx do
    enable(ctx.db)
    parent = self()
    db = ctx.db

    # Runs in the writer when the marker first records the open.
    hook = fn
      {:put, %{"episodeOpenedAt" => at}, _reason} when is_integer(at) ->
        send(parent, {:at_open_write, length(memory_alerts(db)), pressure_facts(db)})
        :ok

      _command ->
        :ok
    end

    start_stack(ctx, marker_hook: hook)
    pressure(ctx)

    for t <- 0..105//15 do
      assert %{episode: false, run: true} = sample(ctx, t * 1_000)
    end

    assert memory_alerts(ctx.db) == []
    assert pressure_facts(ctx.db) == []
    assert {:marker, %{"episodeOpenedAt" => nil, "runStartedAt" => started}} = marker(ctx)
    assert started == ctx.wall0

    assert %{episode: true} = sample(ctx, 120_000)
    opened_at = ctx.wall0 + 120_000

    assert [alert] = memory_alerts(ctx.db)
    assert alert.dedupe_key == "memory-pressure:#{@host}:#{opened_at}"
    assert alert.title == "sirius is running low on memory"
    assert alert.state == "pending"
    assert alert.next_attempt_at == alert.created_at
    # A memory-pressure row names no session, turn or work item.
    assert {alert.session_key, alert.turn_seq, alert.work_item_id} == {nil, nil, nil}

    assert pressure_facts(ctx.db) == [["host-memory-pressure", @host, "process:tightbeam"]]

    # The open committed both, and only then did the marker record it.
    assert_received {:at_open_write, 1, [["host-memory-pressure", @host, "process:tightbeam"]]}
    assert {:marker, %{"episodeOpenedAt" => ^opened_at, "runStartedAt" => ^started}} = marker(ctx)
  end

  test "T21: a run that ends before 120 s opens nothing and its marker is deleted", ctx do
    enable(ctx.db)
    start_stack(ctx)
    pressure(ctx)

    for t <- 0..105//15, do: sample(ctx, t * 1_000)
    assert {:marker, _} = marker(ctx)

    memory(ctx, 50, psi: {4.0, 4.0})
    assert %{run: false, episode: false} = sample(ctx, 120_000)
    ended_at = ctx.wall0 + 120_000
    assert {:marker, %{"runEndedAt" => ^ended_at, "episodeOpenedAt" => nil}} = marker(ctx)

    # R4: the marker of a run that ended unopened is deleted after 60 s with
    # no new run.
    for t <- [135, 150, 165] do
      sample(ctx, t * 1_000)
      assert {:marker, _} = marker(ctx)
    end

    sample(ctx, 180_000)
    assert_received {:memory_pressure_marker, :delete}
    assert marker(ctx) == :none
    assert memory_alerts(ctx.db) == []
    assert pressure_facts(ctx.db) == []
  end

  test "M4: the open's alert and fact commit in one transaction, and a failed open is retried",
       ctx do
    enable(ctx.db)
    start_stack(ctx)
    pressure(ctx)

    :ok =
      DB.execute(ctx.db, """
      CREATE TRIGGER g1_fail_fact BEFORE INSERT ON condition_facts
      WHEN NEW.kind = 'host-memory-pressure'
      BEGIN SELECT RAISE(ABORT, 'injected fact failure'); END;
      """)

    log =
      ExUnit.CaptureLog.capture_log(fn ->
        for t <- 0..120//15, do: sample(ctx, t * 1_000)
      end)

    assert log =~ "memory pressure episode open was not recorded"
    # The failed fact rolled the alert back with it.
    assert memory_alerts(ctx.db) == []
    assert pressure_facts(ctx.db) == []

    :ok = DB.execute(ctx.db, "DROP TRIGGER g1_fail_fact")
    sample(ctx, 135_000)

    assert [alert] = memory_alerts(ctx.db)
    assert alert.dedupe_key == "memory-pressure:#{@host}:#{ctx.wall0 + 120_000}"
    assert pressure_facts(ctx.db) == [["host-memory-pressure", @host, "process:tightbeam"]]

    sample(ctx, 150_000)
    assert length(memory_alerts(ctx.db)) == 1
  end

  for {label, available, opts, minutes, alerts} <- [
        {"18% free with 5% of swap free", 18, [swap_free: 5], 2, 1},
        {"18% free with 40% of swap free", 18, [swap_free: 40], 2, 0},
        {"18% free with no swap", 18, [swap_total: 0], 2, 1},
        {"40% free with 0.5% of swap free", 40, [swap_free: 0.5], 60, 0}
      ] do
    @tag available: available, memory_opts: opts, minutes: minutes, alerts: alerts
    test "T22: P2, #{label}", ctx do
      enable(ctx.db)
      start_stack(ctx)
      memory(ctx, ctx.available, ctx.memory_opts)

      for t <- 0..(ctx.minutes * 60)//15, do: sample(ctx, t * 1_000)

      assert length(memory_alerts(ctx.db)) == ctx.alerts
    end
  end

  test "T23: one alert per episode, a close only after 15 unbroken clear minutes, then a new episode",
       ctx do
    enable(ctx.db)
    start_stack(ctx)
    low = fn -> memory(ctx, 15, swap_free: 1) end
    neither = fn -> memory(ctx, 24, swap_free: 1) end
    clear = fn -> memory(ctx, 40, swap_free: 1) end

    low.()
    for t <- 0..120//15, do: sample(ctx, t * 1_000)
    assert [first] = memory_alerts(ctx.db)

    # An hour swinging between 15% and 24%: 24% is not a clear sample.
    for {t, i} <- Enum.with_index(135..3_720//15) do
      if rem(i, 2) == 0, do: low.(), else: neither.()
      assert %{episode: true} = sample(ctx, t * 1_000)
    end

    assert memory_alerts(ctx.db) == [first]

    # 14 clear minutes, one sample that is neither, then 15 clear minutes.
    t1 = 3_735
    clear.()
    for t <- t1..(t1 + 840)//15, do: assert(%{episode: true} = sample(ctx, t * 1_000))
    neither.()
    assert %{episode: true} = sample(ctx, (t1 + 855) * 1_000)
    clear.()
    t2 = t1 + 870
    for t <- t2..(t2 + 885)//15, do: assert(%{episode: true} = sample(ctx, t * 1_000))
    assert {:marker, _} = marker(ctx)
    assert closed_events(ctx.db) == []

    assert %{episode: false, run: false} = sample(ctx, (t2 + 900) * 1_000)

    assert marker(ctx) == :none

    assert [%{"reason" => "cleared", "episodeOpenedAt" => opened, "endedAt" => ended}] =
             closed_events(ctx.db)

    assert opened == ctx.wall0 + 120_000
    assert ended == ctx.wall0 + (t2 + 900) * 1_000

    assert pressure_facts(ctx.db) == [
             ["host-memory-pressure", @host, "process:tightbeam"],
             ["host-memory-pressure-cleared", @host, "process:tightbeam"]
           ]

    assert memory_alerts(ctx.db) == [first]

    # New pressure opens a second episode with its own alert.
    t3 = t2 + 915
    low.()
    for t <- t3..(t3 + 105)//15, do: sample(ctx, t * 1_000)
    assert memory_alerts(ctx.db) == [first]
    sample(ctx, (t3 + 120) * 1_000)

    assert [^first, second] = memory_alerts(ctx.db)
    assert second.dedupe_key == "memory-pressure:#{@host}:#{ctx.wall0 + (t3 + 120) * 1_000}"
  end

  test "T24: a pressure sample more than 30 s late opens at once", ctx do
    enable(ctx.db)
    start_stack(ctx)

    sample(ctx, 0)
    sample(ctx, 15_000)
    pressure(ctx)
    assert %{episode: true} = sample(ctx, 46_000)
    assert [alert] = memory_alerts(ctx.db)
    assert alert.dedupe_key == "memory-pressure:#{@host}:#{ctx.wall0 + 46_000}"
  end

  test "T24: a sample 31 s late that is not a pressure sample opens nothing", ctx do
    enable(ctx.db)
    start_stack(ctx)

    sample(ctx, 0)
    sample(ctx, 15_000)
    assert %{run: false, episode: false} = sample(ctx, 46_000)
    assert memory_alerts(ctx.db) == []
    assert marker(ctx) == :none
  end

  test "T24: the wall clock jumping ten minutes with monotonic time steady opens nothing", ctx do
    enable(ctx.db)
    start_stack(ctx)
    pressure(ctx)

    sample(ctx, 0)

    for t <- [15_000, 30_000] do
      set_clock(ctx, t, ctx.wall0 + t + 10 * @minute)
      assert %{episode: false} = MemoryPressure.sample_now()
      settle()
    end

    assert memory_alerts(ctx.db) == []
  end

  test "T31: a sampler late on every tick opens at its first late pressure sample", ctx do
    enable(ctx.db)
    start_stack(ctx)
    pressure(ctx)

    assert %{episode: false} = sample(ctx, 0)
    assert %{episode: true} = sample(ctx, 40_000)

    for t <- 80..180//40, do: sample(ctx, t * 1_000)

    assert [alert] = memory_alerts(ctx.db)
    assert alert.dedupe_key == "memory-pressure:#{@host}:#{ctx.wall0 + 40_000}"
  end

  test "T31: samples 25 s apart open at the first pressure sample at or after 120 s", ctx do
    enable(ctx.db)
    start_stack(ctx)
    pressure(ctx)

    for t <- 0..100//25, do: assert(%{episode: false} = sample(ctx, t * 1_000))
    assert memory_alerts(ctx.db) == []

    assert %{episode: true} = sample(ctx, 125_000)
    for t <- 150..175//25, do: sample(ctx, t * 1_000)

    assert [alert] = memory_alerts(ctx.db)
    assert alert.dedupe_key == "memory-pressure:#{@host}:#{ctx.wall0 + 125_000}"
  end

  test "R4: a run that ends unopened keeps its marker 60 s; a new run inside it rewrites it",
       ctx do
    enable(ctx.db)
    stack = start_stack(ctx)

    pressure(ctx)
    sample(ctx, 0)

    assert_received {:memory_pressure_marker, :put, :run_start,
                     %{"runStartedAt" => first, "runEndedAt" => nil}}

    # N1: the run's end is written once, with the time it ended.
    calm(ctx)
    sample(ctx, 15_000)

    assert_received {:memory_pressure_marker, :put, :run_end,
                     %{"runStartedAt" => ^first, "runEndedAt" => ended}}

    assert ended == ctx.wall0 + 15_000
    pressure(ctx)
    sample(ctx, 30_000)

    # No delete between the two runs; the new run's first write resets the end.
    assert_received {:memory_pressure_marker, :put, :run_start,
                     %{"runStartedAt" => second, "runEndedAt" => nil}}

    refute_received {:memory_pressure_marker, :delete}
    assert {first, second} == {ctx.wall0, ctx.wall0 + 30_000}

    calm(ctx)
    for t <- [45, 60, 75, 90], do: sample(ctx, t * 1_000)
    refute_received {:memory_pressure_marker, :delete}
    second_end = ctx.wall0 + 45_000

    assert {:marker, %{"runStartedAt" => ^second, "runEndedAt" => ^second_end}} = marker(ctx)

    sample(ctx, 105_000)
    assert_received {:memory_pressure_marker, :delete}
    assert marker(ctx) == :none

    # An orderly stop does not wait out the window.
    pressure(ctx)
    sample(ctx, 120_000)
    calm(ctx)
    sample(ctx, 135_000)
    assert {:marker, _} = marker(ctx)
    :ok = stop_supervised!(stack.id)
    assert marker(ctx) == :none
    assert memory_alerts(ctx.db) == []
  end

  ## M6, A2b: surviving the conditions it reports

  test "T25: a restart with an open episode whose alert was sent reports it once", ctx do
    enable(ctx.db)
    stack = start_stack(ctx)
    pressure(ctx)
    for t <- 0..120//15, do: sample(ctx, t * 1_000)

    [first] = memory_alerts(ctx.db)
    sending = runner(self(), fn {:execute, op} -> committed(op, "send") end)
    assert OwnerAlerts.deliver_due(ctx.db, now: first.created_at, runner: sending) == 0
    assert [%{state: "sent"}] = memory_alerts(ctx.db)

    kill_stack(stack)
    assert {:marker, _} = marker(ctx)
    restarted = start_stack(ctx)

    assert [%{state: "sent"}, restart] = memory_alerts(ctx.db)
    assert restart.dedupe_key == "memory-pressure-restart:#{@host}:#{ctx.wall0}"
    assert restart.title == "sirius: Tightbeam restarted during memory pressure"

    for part <- [
          "Tightbeam restarted on sirius while memory pressure was ongoing.",
          "The pressure began at #{OwnerAlerts.format_local(ctx.wall0)}.",
          "The episode opened at #{OwnerAlerts.format_local(ctx.wall0 + 120_000)}.",
          "The last kept sample, at #{OwnerAlerts.format_local(ctx.wall0 + 120_000)}, " <>
            "showed 16.0 GiB of 32.0 GiB free (50%), with swap 0.0 of 8.0 GiB used.",
          "Programs were stalled waiting for memory 12% of the last 10 seconds and 12% of the last minute.",
          "The first alert for this episode was sent."
        ] do
      assert restart.body =~ part, "missing #{inspect(part)} in #{inspect(restart.body)}"
    end

    assert [%{"reason" => "interrupted", "episodeOpenedAt" => opened}] = closed_events(ctx.db)
    assert opened == ctx.wall0 + 120_000

    assert pressure_facts(ctx.db) == [
             ["host-memory-pressure", @host, "process:tightbeam"],
             ["host-memory-pressure-cleared", @host, "process:tightbeam"]
           ]

    assert marker(ctx) == :none

    # A second restart has no marker and reports nothing again.
    kill_stack(restarted)
    start_stack(ctx)
    assert length(memory_alerts(ctx.db)) == 2
    assert length(closed_events(ctx.db)) == 1
  end

  test "T25: a restart supersedes the episode's unsent first alert", ctx do
    enable(ctx.db)
    stack = start_stack(ctx)
    pressure(ctx)
    for t <- 0..120//15, do: sample(ctx, t * 1_000)
    [first] = memory_alerts(ctx.db)

    kill_stack(stack)
    start_stack(ctx)

    assert [%{alert_id: first_id, state: "withdrawn", withdrawn_as: "stale"}, restart] =
             memory_alerts(ctx.db)

    assert first_id == first.alert_id
    assert withdrawn_reasons(ctx.db, first_id) == ["superseded-by-restart"]
    assert restart.state == "pending"
    assert restart.body =~ "The first alert for this episode was not sent."
  end

  test "T25: a start with no run marker sends nothing", ctx do
    enable(ctx.db)
    start_stack(ctx)

    assert memory_alerts(ctx.db) == []
    assert closed_events(ctx.db) == []
    assert pressure_facts(ctx.db) == []
  end

  test "T32: a kill after the run's first pressure sample alerts once on restart", ctx do
    enable(ctx.db)
    stack = start_stack(ctx)
    pressure(ctx)
    sample(ctx, 0)
    assert {:marker, %{"episodeOpenedAt" => nil}} = marker(ctx)

    kill_stack(stack)
    start_stack(ctx)

    assert [restart] = memory_alerts(ctx.db)
    assert restart.dedupe_key == "memory-pressure-restart:#{@host}:#{ctx.wall0}"
    assert restart.body =~ "The episode had not yet opened."
    refute restart.body =~ "first alert"
    assert marker(ctx) == :none
    assert closed_events(ctx.db) == []
  end

  test "N1: a kill inside the window after a spike ended gives one restart alert saying it ended",
       ctx do
    enable(ctx.db)
    stack = start_stack(ctx)
    pressure(ctx)
    for t <- 0..45//15, do: sample(ctx, t * 1_000)
    calm(ctx)
    sample(ctx, 60_000)
    sample(ctx, 75_000)

    # Inside the 60 s window the marker still stands, now with its end.
    ended_at = ctx.wall0 + 60_000
    assert {:marker, %{"runEndedAt" => ^ended_at}} = marker(ctx)

    kill_stack(stack)
    start_stack(ctx)

    assert [restart] = memory_alerts(ctx.db)
    assert restart.dedupe_key == "memory-pressure-restart:#{@host}:#{ctx.wall0}"

    assert restart.body ==
             "Tightbeam restarted on sirius shortly after a brief memory-pressure spike that " <>
               "began at #{OwnerAlerts.format_local(ctx.wall0)} and ended at " <>
               "#{OwnerAlerts.format_local(ended_at)}, before an alert was due. " <>
               "The last kept sample, at #{OwnerAlerts.format_local(ctx.wall0 + 45_000)}, " <>
               "showed 16.0 GiB of 32.0 GiB free (50%), with swap 0.0 of 8.0 GiB used. " <>
               "Programs were stalled waiting for memory 12% of the last 10 seconds and 12% " <>
               "of the last minute. Tightbeam is only watching. It has not stopped or changed " <>
               "anything. If free memory keeps falling, the machine may stop responding."

    refute restart.body =~ "ongoing"
    assert marker(ctx) == :none
    assert closed_events(ctx.db) == []
    assert pressure_facts(ctx.db) == []
  end

  test "N1: a marker written before runEndedAt existed still parses as a standing run", ctx do
    enable(ctx.db)

    File.write!(
      Marker.path(ctx.state_dir),
      JSON.encode!(%{
        "host" => @host,
        "runStartedAt" => ctx.wall0,
        "episodeOpenedAt" => nil,
        "lastSampleAt" => ctx.wall0 + 15_000,
        "lastSample" => %{
          "memTotalKiB" => @total,
          "memAvailableKiB" => div(@total, 2),
          "swapTotalKiB" => 0,
          "swapFreeKiB" => 0,
          "someAvg10" => 12.0,
          "someAvg60" => 12.0
        }
      })
    )

    assert {:marker, marker} = marker(ctx)
    refute Map.has_key?(marker, "runEndedAt")
    start_stack(ctx)

    assert [restart] = memory_alerts(ctx.db)
    assert restart.dedupe_key == "memory-pressure-restart:#{@host}:#{ctx.wall0}"
    assert restart.body =~ "Tightbeam restarted on sirius while memory pressure was ongoing."
    assert restart.body =~ "The episode had not yet opened."
    assert marker(ctx) == :none
  end

  test "T32: an orderly stop deletes an unopened run's marker, and the next start sends nothing",
       ctx do
    enable(ctx.db)
    stack = start_stack(ctx)
    pressure(ctx)
    sample(ctx, 0)
    sample(ctx, 15_000)
    assert {:marker, _} = marker(ctx)

    :ok = stop_supervised!(stack.id)
    assert marker(ctx) == :none

    start_stack(ctx)
    assert memory_alerts(ctx.db) == []
  end

  test "T32: a restart finds a committed open the marker missed", ctx do
    enable(ctx.db)

    # The marker's episodeOpenedAt write fails; its earlier writes land.
    hook = fn
      {:put, %{"episodeOpenedAt" => at}, _reason} when is_integer(at) -> {:error, :injected}
      _command -> :ok
    end

    stack = start_stack(ctx, marker_hook: hook)
    pressure(ctx)

    ExUnit.CaptureLog.capture_log(fn ->
      for t <- 0..120//15, do: sample(ctx, t * 1_000)
    end)

    assert [first] = memory_alerts(ctx.db)
    assert {:marker, %{"episodeOpenedAt" => nil}} = marker(ctx)

    kill_stack(stack)
    start_stack(ctx)

    assert [%{state: "withdrawn", withdrawn_as: "stale"}, restart] = memory_alerts(ctx.db)

    assert restart.body =~
             "The episode opened at #{OwnerAlerts.format_local(ctx.wall0 + 120_000)}."

    assert restart.body =~ "The first alert for this episode was not sent."
    assert [%{"reason" => "interrupted"}] = closed_events(ctx.db)
    assert first.alert_id != restart.alert_id
  end

  test "T32: with the database down for the whole run the marker is still written", ctx do
    enable(ctx.db)
    down = :atomics.new(1, [])

    hook = fn _operation ->
      if :atomics.get(down, 1) == 1, do: raise("injected: database unavailable"), else: :ok
    end

    stack = start_stack(ctx, db_hook: hook)
    :atomics.put(down, 1, 1)
    pressure(ctx)

    ExUnit.CaptureLog.capture_log(fn ->
      for t <- 0..180//15, do: sample(ctx, t * 1_000)
    end)

    assert memory_alerts(ctx.db) == []
    # Written at the first sample, then at most once a minute.
    assert {:marker, %{"runStartedAt" => started, "lastSampleAt" => last}} = marker(ctx)
    assert {started, last} == {ctx.wall0, ctx.wall0 + 135_000}

    kill_stack(stack)
    start_stack(ctx)

    assert [restart] = memory_alerts(ctx.db)
    assert restart.dedupe_key == "memory-pressure-restart:#{@host}:#{ctx.wall0}"
    assert marker(ctx) == :none
  end

  test "T32: a corrupt marker at start gives one restart alert with unknown details", ctx do
    enable(ctx.db)
    File.write!(Marker.path(ctx.state_dir), "{\"host\": \"sirius\", \"runStartedAt\":")
    start_stack(ctx)

    assert [restart] = memory_alerts(ctx.db)
    assert String.starts_with?(restart.dedupe_key, "memory-pressure-restart:#{@host}:unknown-")
    assert restart.body =~ "could not be read"
    assert marker(ctx) == :none
    assert_received {:memory_pressure_marker, :delete}
  end

  # N2: the boot runs after init, and the delivery process's passes wait for
  # it, so a slow database neither blocks later children nor lets a
  # superseded first alert out.
  for gated? <- [true, false] do
    @tag gated: gated?
    test "N2: a slow boot blocks no later child; gated delivery never sends the superseded alert (gated=#{gated?})",
         ctx do
      enable(ctx.db)
      parent = self()

      # A previous run left an open episode whose first alert is unsent.
      stack = start_stack(ctx)
      pressure(ctx)
      for t <- 0..120//15, do: sample(ctx, t * 1_000)
      assert [%{state: "pending", attempts: 0} = first] = memory_alerts(ctx.db)
      kill_stack(stack)

      # The next start's boot transaction is held until the test lets it go.
      hook = fn
        :boot ->
          send(parent, {:boot_stalled, self()})

          receive do
            :release_db -> :ok
          end

        _operation ->
          :ok
      end

      start_stack(ctx, db_hook: hook, settle: false)
      assert_receive {:boot_stalled, recorder}, 5_000

      # The later child starts while the boot is still held.
      sending = runner(self(), fn {:execute, op} -> committed(op, "send") end)

      start_supervised!(
        {OwnerAlerts, db: ctx.db, send_runner: sending, await_memory_pressure: ctx.gated}
      )

      # A post-commit nudge before the boot is recorded.
      GenServer.cast(OwnerAlerts, :due)
      :sys.get_state(OwnerAlerts)

      if ctx.gated do
        refute_received {:harklight, _}

        send(recorder, :release_db)
        settle()
        :sys.get_state(OwnerAlerts)

        # Only the restart alert went out; the superseded first alert never did.
        assert_received {:harklight, ["send", "--prepare", "--op-id", op | rest]}
        assert flag(rest, "--title") == "sirius: Tightbeam restarted during memory pressure"
        refute_received {:harklight, ["send", "--prepare" | _]}

        assert [
                 %{alert_id: first_id, state: "withdrawn", withdrawn_as: "stale", attempts: 0},
                 %{state: "sent", op_id: ^op}
               ] = memory_alerts(ctx.db)

        assert first_id == first.alert_id
        assert count(ctx.db, "SELECT count(*) FROM harklight_send_operations") == 1
      else
        # Control: without the gate the superseded first alert goes out.
        assert_received {:harklight, ["send", "--prepare", "--op-id", _op | rest]}
        assert flag(rest, "--title") == "sirius is running low on memory"
        send(recorder, :release_db)
        settle()
      end
    end
  end

  # D1: the gate is bounded. A G1 boot that never succeeds holds the other
  # owner alerts back for at most the bound, then delivery resumes and the
  # missing M6 check is recorded.
  @tag capture_log: true
  test "D1: a G1 boot that never succeeds holds delivery only until the bound", ctx do
    enable(ctx.db)

    never = fn
      :boot -> raise "injected: the G1 boot keeps failing"
      _operation -> :ok
    end

    start_stack(ctx, db_hook: never, settle: false)
    sampler = MemoryPressure.names().sampler

    # A due usage-limit alert, and an item stalled for five hours.
    due_usage_limit(ctx.db)
    holder = session(ctx.db, "agent:george:idle")
    stalled_item(ctx.db, holder, System.system_time(:millisecond) - 5 * @hour)

    gate = :atomics.new(1, signed: true)
    sending = runner(self(), fn {:execute, op} -> committed(op, "send") end)
    start_gated_alerts(ctx, gate, sending)

    # Nothing goes out before the bound, whatever asks for a pass.
    GenServer.cast(OwnerAlerts, :due)
    GenServer.cast(OwnerAlerts, :stall_inputs)
    gate_at(gate, 119_999)
    refute_received {:harklight, _}
    assert lifecycle(ctx.db, "memory_pressure_restart_unrecorded") == []
    refute :sys.get_state(sampler).booted?

    # At the bound the gate lifts: both alerts are sent and the missing M6
    # check is on record. The sampler is still retrying its own boot.
    gate_at(gate, 120_000)

    titles =
      for _ <- 1..2 do
        assert_received {:harklight, ["send", "--prepare", "--op-id", _op | rest]}
        flag(rest, "--title")
      end

    assert Enum.sort(titles) == ["No progress for 5h: Item wi_d1", "Worker hit a usage limit"]
    refute_received {:harklight, ["send", "--prepare" | _]}

    assert [%{"boundMs" => 120_000, "waitedMs" => 120_000}] =
             lifecycle(ctx.db, "memory_pressure_restart_unrecorded")

    refute :sys.get_state(sampler).booted?

    assert count(ctx.db, "SELECT count(*) FROM owner_alerts WHERE state='sent'") == 2
  end

  @tag capture_log: true
  test "D1: a ready signal after the bound lifted the gate changes nothing", ctx do
    enable(ctx.db)
    parent = self()

    # A previous run left an open episode whose first alert is unsent.
    stack = start_stack(ctx)
    pressure(ctx)
    for t <- 0..120//15, do: sample(ctx, t * 1_000)
    assert [%{state: "pending"} = first] = memory_alerts(ctx.db)
    kill_stack(stack)

    hook = fn
      :boot ->
        send(parent, {:boot_stalled, self()})

        receive do
          :release_db -> :ok
        end

      _operation ->
        :ok
    end

    start_stack(ctx, db_hook: hook, settle: false)
    assert_receive {:boot_stalled, recorder}, 5_000

    gate = :atomics.new(1, signed: true)
    sending = runner(self(), fn {:execute, op} -> committed(op, "send") end)
    start_gated_alerts(ctx, gate, sending)

    # The bound lifts the gate first. The accepted consequence: the first
    # alert, which M6 would have superseded, goes out.
    gate_at(gate, 120_000)
    assert_received {:harklight, ["send", "--prepare", "--op-id", first_op | _]}
    assert [%{state: "sent", op_id: ^first_op}] = memory_alerts(ctx.db)

    # The boot then succeeds: M6 is recorded normally, and the late signal
    # adds no second boot pass.
    send(recorder, :release_db)
    settle()
    :sys.get_state(OwnerAlerts)

    assert_received {:harklight, ["send", "--prepare", "--op-id", restart_op | rest]}
    assert flag(rest, "--title") == "sirius: Tightbeam restarted during memory pressure"
    refute_received {:harklight, ["send", "--prepare" | _]}

    assert [
             %{alert_id: first_id, state: "sent", op_id: ^first_op, attempts: 1},
             %{state: "sent", op_id: ^restart_op, attempts: 1} = restart
           ] = memory_alerts(ctx.db)

    assert first_id == first.alert_id
    assert restart.body =~ "The first alert for this episode was sent."
    assert_received {:harklight, ["send", "--execute", "--op-id", ^first_op]}
    assert_received {:harklight, ["send", "--execute", "--op-id", ^restart_op]}

    # Further signals and checks are harmless.
    pid = Process.whereis(OwnerAlerts)
    GenServer.cast(OwnerAlerts, :memory_pressure_ready)
    gate_at(gate, 240_000)
    refute_received {:harklight, _}
    assert Process.whereis(OwnerAlerts) == pid
    assert count(ctx.db, "SELECT count(*) FROM harklight_send_operations") == 2
    assert length(lifecycle(ctx.db, "memory_pressure_restart_unrecorded")) == 1
  end

  test "T15: a memory-pressure alert created before a restart is sent once after it", ctx do
    enable(ctx.db)
    start_stack(ctx)
    pressure(ctx)
    for t <- 0..120//15, do: sample(ctx, t * 1_000)
    assert [%{state: "pending", attempts: 0}] = memory_alerts(ctx.db)

    runner = runner(self(), fn {:execute, op} -> committed(op, "send") end)
    start_supervised!({OwnerAlerts, db: ctx.db, send_runner: runner}, id: :first_boot)
    assert_receive {:harklight, ["send", "--prepare", "--op-id", op | _]}, 5_000
    assert_receive {:harklight, ["send", "--execute", "--op-id", ^op]}, 5_000
    :sys.get_state(OwnerAlerts)
    assert [%{state: "sent", op_id: ^op}] = memory_alerts(ctx.db)

    :ok = stop_supervised!(:first_boot)
    start_supervised!({OwnerAlerts, db: ctx.db, send_runner: runner}, id: :second_boot)
    :sys.get_state(OwnerAlerts)

    refute_received {:harklight, _}
    assert count(ctx.db, "SELECT count(*) FROM harklight_send_operations") == 1
    assert [%{state: "sent", op_id: ^op, attempts: 1}] = memory_alerts(ctx.db)
  end

  ## M9, V3: content

  test "T26: the alert names free memory, swap, stalls and the five populations", ctx do
    enable(ctx.db)
    cgroup_v2(ctx, swap: true)
    start_stack(ctx)
    memory(ctx, 19, swap_free: 0, psi: {14.0, 11.0})
    for t <- 0..120//15, do: sample(ctx, t * 1_000)

    assert [alert] = memory_alerts(ctx.db)

    assert alert.body ==
             "Since #{OwnerAlerts.format_local(ctx.wall0 + 120_000)}, sirius has had " <>
               "6.1 GiB of 32.0 GiB free (19%), with swap 8.0 of 8.0 GiB used. " <>
               "Programs were stalled waiting for memory 14% of the last 10 seconds and " <>
               "11% of the last minute. Using memory: Tightbeam and its agents 5.1 GiB, " <>
               "virtual machines 17.4 GiB, containers 3.2 GiB, your own programs 4.0 GiB, " <>
               "other services 1.6 GiB. Tightbeam is only watching. It has not stopped or " <>
               "changed anything. If free memory keeps falling, the machine may stop responding."

    assert_reads_confined(ctx)
  end

  test "M9: without swap accounting each figure is memory only and the line says so", ctx do
    enable(ctx.db)
    cgroup_v2(ctx, swap: false)
    start_stack(ctx)
    memory(ctx, 19, swap_free: 0, psi: {14.0, 11.0})
    for t <- 0..120//15, do: sample(ctx, t * 1_000)

    assert [alert] = memory_alerts(ctx.db)

    assert alert.body =~
             "Using memory: Tightbeam and its agents 5.0 GiB, virtual machines 17.0 GiB, " <>
               "containers 3.0 GiB, your own programs 3.5 GiB, other services 1.0 GiB. " <>
               "These figures are memory only, because this host does not account swap per group."

    assert_reads_confined(ctx)
  end

  test "T26: without cgroup v2 the population line is omitted", ctx do
    enable(ctx.db)
    cgroup_v2(ctx, swap: true)
    File.rm!(Path.join(ctx.cgroup, "cgroup.controllers"))
    start_stack(ctx)
    memory(ctx, 19, swap_free: 0, psi: {14.0, 11.0})
    for t <- 0..120//15, do: sample(ctx, t * 1_000)

    assert [alert] = memory_alerts(ctx.db)
    refute alert.body =~ "Using memory"
    assert alert.body =~ "11% of the last minute. Tightbeam is only watching."
    assert_reads_confined(ctx)
  end

  ## M1: the sampler never waits

  test "T27: a stalled database and a stalled Harklight send never delay a sample", ctx do
    enable(ctx.db)
    parent = self()
    stall = :atomics.new(1, [])

    hook = fn operation ->
      if :atomics.get(stall, 1) == 1 do
        send(parent, {:db_stalled, operation, self()})

        receive do
          :release_db -> :ok
        end
      end

      :ok
    end

    stalled_runner = fn args ->
      send(parent, {:harklight, args})

      receive do
        :release_runner -> {"", 1}
      end
    end

    start_supervised!({OwnerAlerts, db: ctx.db, send_runner: stalled_runner})
    start_stack(ctx, db_hook: hook)
    pressure(ctx)
    for t <- 0..105//15, do: sample(ctx, t * 1_000)
    drain_marker_writes()

    # The open's transaction stalls; sampling goes on every 15 s.
    :atomics.put(stall, 1, 1)
    latest = [fast_sample(ctx, 120_000)]
    assert_receive {:db_stalled, :open, recorder}, 5_000
    latest = latest ++ for(t <- 135..240//15, do: fast_sample(ctx, t * 1_000))

    assert memory_alerts(ctx.db) == []
    :atomics.put(stall, 1, 0)
    send(recorder, :release_db)
    settle()

    # The alert is committed, and its Harklight send is now stuck.
    assert [%{state: "pending"}] = memory_alerts(ctx.db)
    assert_receive {:harklight, ["send", "--prepare" | _]}, 5_000
    latest = latest ++ for(t <- 255..480//15, do: fast_sample(ctx, t * 1_000))

    # Latest-sample writes: at most one per 60 s of monotonic time.
    times = latest |> List.flatten()
    assert length(times) in 5..7

    for [a, b] <- Enum.chunk_every(times, 2, 1, :discard) do
      assert b - a >= 60_000
    end
  end

  test "F1: an open committed after its episode closed never brings the marker back", ctx do
    enable(ctx.db)
    parent = self()
    stall = :atomics.new(1, [])

    hook = fn operation ->
      if :atomics.get(stall, 1) == 1 and operation == :open do
        send(parent, {:db_stalled, operation, self()})

        receive do
          :release_db -> :ok
        end
      end

      :ok
    end

    start_stack(ctx, db_hook: hook)
    pressure(ctx)
    for t <- 0..105//15, do: sample(ctx, t * 1_000)

    :atomics.put(stall, 1, 1)
    fast_sample(ctx, 120_000)
    assert_receive {:db_stalled, :open, recorder}, 5_000

    # Fifteen clear minutes close the episode while its open is still stuck.
    calm(ctx)
    for t <- 135..1_035//15, do: fast_sample(ctx, t * 1_000)
    assert_received {:memory_pressure_marker, :delete}
    assert marker(ctx) == :none
    drain_marker_writes()

    :atomics.put(stall, 1, 0)
    send(recorder, :release_db)
    settle()

    # The open committed, then the close: alert, fact and cleared fact, and
    # no marker write after the delete.
    assert [_alert] = memory_alerts(ctx.db)

    assert pressure_facts(ctx.db) == [
             ["host-memory-pressure", @host, "process:tightbeam"],
             ["host-memory-pressure-cleared", @host, "process:tightbeam"]
           ]

    refute_received {:memory_pressure_marker, :put, _, _}
    assert marker(ctx) == :none
  end

  test "T30: without /proc/pressure/memory, P2 alone opens and clears episodes", ctx do
    enable(ctx.db)
    memory(ctx, 15, swap_free: 1, psi: nil)
    start_stack(ctx)
    for t <- 0..120//15, do: sample(ctx, t * 1_000)

    assert [alert] = memory_alerts(ctx.db)

    assert alert.body =~
             "This host does not report how long programs were stalled waiting for memory."

    assert [%{"pressureStallInformation" => false}] =
             lifecycle(ctx.db, "memory_pressure_sampler_started")

    memory(ctx, 40, swap_free: 1, psi: nil)
    for t <- 135..1_035//15, do: sample(ctx, t * 1_000)
    assert [%{"reason" => "cleared"}] = closed_events(ctx.db)
  end

  test "T30: with /proc/meminfo unreadable one unavailable event is recorded and nothing else",
       ctx do
    enable(ctx.db)
    File.rm!(Path.join(ctx.proc, "meminfo"))
    before = length(EventLog.lifecycle_events(ctx.db))
    start_stack(ctx)
    settle()

    assert MemoryPressure.sample_now() == :disabled
    settle()

    assert [%{"reason" => "meminfo-unreadable", "host" => @host}] =
             lifecycle(ctx.db, "memory_pressure_unavailable")

    assert length(EventLog.lifecycle_events(ctx.db)) == before + 1
    assert memory_alerts(ctx.db) == []
    assert marker(ctx) == :none
  end

  test "M1: off Linux the sampler records unavailable and reads nothing", ctx do
    enable(ctx.db)
    start_stack(ctx, os: {:unix, :darwin})
    settle()

    assert [%{"reason" => "not-linux"}] = lifecycle(ctx.db, "memory_pressure_unavailable")
    assert MemoryPressure.sample_now() == :disabled
    refute_received {:memory_pressure_read, _}
  end

  test "R2: the sampler's start event names the monotonic clock source", ctx do
    enable(ctx.db)
    start_stack(ctx, clock_source: nil)
    settle()

    info = :erlang.system_info(:os_monotonic_time_source)

    expected =
      to_string(Keyword.get(info, :clock_id) || Keyword.get(info, :function) || "unknown")

    assert [%{"clockSource" => ^expected, "host" => @host, "intervalMs" => 15_000}] =
             lifecycle(ctx.db, "memory_pressure_sampler_started")

    if match?({:unix, :linux}, :os.type()), do: assert(expected == "CLOCK_MONOTONIC")
  end

  ## §7.1 C2-off / C3-on, M8, V1, V5

  test "T28: clearing the owner withdraws the episode alert and stops sampling; re-enabling starts afresh",
       ctx do
    config = config_handler(ctx.db)

    set_owner = fn value ->
      config.(%{action: "set", setting: "owner-alerts-user", value: value})
    end

    assert %{changed: true} = set_owner.(@owner)

    start_stack(ctx)
    pressure(ctx)
    for t <- 0..120//15, do: sample(ctx, t * 1_000)
    [first] = memory_alerts(ctx.db)

    assert OwnerAlerts.deliver_due(ctx.db, now: first.created_at, runner: failing(self())) == 0
    assert_received {:harklight, ["send", "--prepare" | _]}
    assert [%{state: "pending", next_attempt_at: retry_at}] = memory_alerts(ctx.db)

    assert %{value: nil, changed: true} = set_owner.("")
    settle()

    assert [%{"reason" => "alerts-off"}] = closed_events(ctx.db)

    assert pressure_facts(ctx.db) == [
             ["host-memory-pressure", @host, "process:tightbeam"],
             ["host-memory-pressure-cleared", @host, "process:tightbeam"]
           ]

    assert marker(ctx) == :none

    assert OwnerAlerts.deliver_due(ctx.db, now: retry_at, runner: failing(self())) == 0
    refute_received {:harklight, _}
    assert [%{state: "withdrawn", withdrawn_as: "off"}] = memory_alerts(ctx.db)

    # No samples while off.
    drain_reads()
    set_clock(ctx, 135_000)
    assert MemoryPressure.sample_now() == :disabled
    refute_received {:memory_pressure_read, _}

    # Re-enabled under continuing pressure: a new episode after 2 minutes.
    assert %{changed: true} = set_owner.(@owner)
    settle()
    assert length(lifecycle(ctx.db, "memory_pressure_sampler_started")) == 2

    for t <- 600..705//15, do: sample(ctx, t * 1_000)
    assert [%{state: "withdrawn"}] = memory_alerts(ctx.db)
    sample(ctx, 720_000)

    assert [%{state: "withdrawn"}, second] = memory_alerts(ctx.db)
    assert second.dedupe_key == "memory-pressure:#{@host}:#{ctx.wall0 + 720_000}"

    sending = runner(self(), fn {:execute, op} -> committed(op, "send") end)
    assert OwnerAlerts.deliver_due(ctx.db, now: second.created_at, runner: sending) == 0
    assert [%{state: "withdrawn"}, %{state: "sent"}] = memory_alerts(ctx.db)
  end

  test "T29: a session's own fact wait fires once; G1 creates no wake or turn and the kind is reserved",
       ctx do
    enable(ctx.db)
    scheduler = :"g1_scheduler_#{System.unique_integer([:positive])}"
    parent = self()
    start_supervised!({Tightbeam.ConnRegistry, name: Tightbeam.ConnRegistry})
    start_supervised!({LaneDoorbell, parent})

    start_supervised!(
      {Wakes,
       db: ctx.db,
       name: scheduler,
       tick_ms: 60_000,
       deliver: fn wake ->
         send(parent, {:delivered, wake.wake_id})
         :ok
       end}
    )

    waiter = session(ctx.db, "agent:george:waiter")

    wake =
      Wakes.schedule(ctx.db, %{
        session_key: waiter,
        origin: "agent:owner",
        prompt: "memory is low",
        due_at: System.system_time(:millisecond) + @hour,
        condition_kind: "host-memory-pressure",
        condition_scope: @host,
        creator_session_key: "agent:owner:app"
      })

    # The waiter's own wake may go on to run a turn on the waiter (V5); any
    # other wake or turn would be G1's own.
    others = "SELECT count(*) FROM wakes WHERE sessionKey <> ?1"
    other_turns = "SELECT count(*) FROM turns WHERE sessionKey <> ?1"
    wakes_before = count(ctx.db, others, [waiter])
    turns_before = count(ctx.db, other_turns, [waiter])
    {:ok, settings} = DB.query(ctx.db, "SELECT key, value FROM org_settings ORDER BY key")

    start_stack(ctx, scheduler: scheduler)
    pressure(ctx)
    for t <- 0..120//15, do: sample(ctx, t * 1_000)

    assert [_alert] = memory_alerts(ctx.db)

    # Fired by the episode's fact. A fired condition wake stays pending only
    # while notice batching carries it; its firing is recorded now.
    assert {:ok, [[fact_id]]} =
             DB.query(ctx.db, "SELECT id FROM condition_facts WHERE kind='host-memory-pressure'")

    assert %{
             fired_by: "condition",
             fired_at: fired_at,
             recognition_evidence: %{"condition_fact" => %{"id" => ^fact_id}}
           } = Wakes.get(ctx.db, wake.wake_id)

    assert is_integer(fired_at)

    # The episode closes; the cleared fact fires nothing more.
    calm(ctx)
    for t <- 135..1_035//15, do: sample(ctx, t * 1_000)
    assert [%{"reason" => "cleared"}] = closed_events(ctx.db)

    assert count(
             ctx.db,
             "SELECT count(*) FROM wakes WHERE conditionKind='host-memory-pressure' AND firedAt IS NOT NULL"
           ) == 1

    # G1 itself created no wake or turn and changed no setting.
    assert count(ctx.db, others, [waiter]) == wakes_before
    assert count(ctx.db, other_turns, [waiter]) == turns_before
    assert {:ok, ^settings} = DB.query(ctx.db, "SELECT key, value FROM org_settings ORDER BY key")

    # V5: the sampler's code can signal, spawn or reconfigure nothing.
    source = File.read!("lib/tightbeam/owner_alerts/memory_pressure.ex")

    for forbidden <- [
          ~r/System\.cmd/,
          ~r/:os\.cmd/,
          ~r/Port\.open/,
          ~r/Process\.exit/,
          ~r/put_setting/
        ] do
      refute source =~ forbidden
    end

    # Only the process may file the pair.
    for kind <- ["host-memory-pressure", "host-memory-pressure-cleared"] do
      assert {:error, %{code: "reserved_kind"}} =
               ConditionFacts.file(ctx.db, scheduler, %{
                 kind: kind,
                 scope: @host,
                 origin: "session:" <> waiter
               })
    end
  end

  test "A2: memory-pressure is a kind of the same owner-alerts shape", ctx do
    assert {:ok, [[sql]]} =
             DB.query(
               ctx.db,
               "SELECT sql FROM sqlite_master WHERE type='table' AND name='owner_alerts'"
             )

    assert sql =~
             "CHECK (kind IN ('usage-limit','stall','model-fallback','memory-pressure','pairing-freeze-lifted','pairing-unfreeze-ignored','recovery-enrolled','admin-recovered','root-recovery-enroll','root-pairing-code','memory-guard-stuck'))"

    assert {:ok, [[0, "owner-alerts-v1-0114", _applied]]} =
             DB.query(ctx.db, "SELECT id, shape, appliedAt FROM owner_alert_migration")

    assert :ok = OwnerAlerts.ensure_schema(ctx.db)
  end

  ## Fixtures

  defp world_db do
    db = :"owner_alerts_g1_#{System.unique_integer([:positive])}"
    start_supervised!({DB, path: ":memory:", name: db}, id: db)
    :ok = ensure_all_schemas(db)

    for user <- [@owner, "other"] do
      {:ok, _} =
        DB.query(db, "INSERT INTO users(userId,isAdmin,createdAt) VALUES(?1,0,1)", [user])
    end

    Org.create(db, %{
      session_key: Org.personal_session_key(@owner),
      display_name: "Main",
      kind: "main",
      is_built_in: true,
      owner_user_id: @owner,
      origin: "user:#{@owner}",
      archetype: "default",
      host: Tightbeam.Placement.local_host_name(),
      harness: "codex",
      provider: "openai",
      model: Model.new("gpt-5.6-sol")
    })

    db
  end

  defp enable(db), do: :ok = Org.put_setting(db, "owner-alerts-user", @owner)

  defp session(db, key) do
    Org.create(db, %{
      session_key: key,
      display_name: key,
      owner_user_id: @owner,
      origin: "user:#{@owner}",
      archetype: "coder",
      host: "testhost",
      harness: "codex",
      provider: "openai",
      model: Model.new("gpt-5.6-sol")
    }).session_key
  end

  defp start_gated_alerts(ctx, gate, runner) do
    start_supervised!(
      {OwnerAlerts,
       db: ctx.db,
       send_runner: runner,
       await_memory_pressure: true,
       gate_clock: fn -> :atomics.get(gate, 1) end}
    )
  end

  # Moves the gate's monotonic clock and lets the delivery process check it.
  defp gate_at(gate, ms) do
    :atomics.put(gate, 1, ms)
    send(OwnerAlerts, :memory_pressure_gate_check)
    :sys.get_state(OwnerAlerts)
  end

  defp due_usage_limit(db) do
    now = System.system_time(:millisecond)

    {:ok, _} =
      DB.query(
        db,
        """
        INSERT INTO owner_alerts
          (alertId, kind, dedupeKey, ownerUserId, originSessionKey, sessionKey, turnSeq,
           title, body, state, createdAt, updatedAt, nextAttemptAt)
        VALUES ('oal_d1', 'usage-limit', 'usage-limit:agent:george:w:7', ?1, ?2,
                'agent:george:w', 7, 'Worker hit a usage limit', 'body', 'pending', ?3, ?3, ?3)
        """,
        [@owner, Org.personal_session_key(@owner), now]
      )
  end

  defp stalled_item(db, holder, opened_at) do
    {:ok, _} =
      DB.query(
        db,
        """
        INSERT INTO work_items (id, title, ownerUserId, state, createdByUser, createdAt)
        VALUES ('wi_d1', 'Item wi_d1', ?1, 'open', ?1, 1)
        """,
        [@owner]
      )

    {:ok, _} =
      DB.query(
        db,
        """
        INSERT INTO assignments (id, subject, holderKey, openedByUser, openedAt, state, workItemId)
        VALUES ('asg_d1', 'Work asg_d1', ?1, ?2, ?3, 'open', 'wi_d1')
        """,
        [holder, @owner, opened_at]
      )
  end

  defp start_stack(ctx, opts \\ []) do
    {settle?, opts} = Keyword.pop(opts, :settle, true)
    clock = ctx.clock

    defaults = [
      db: ctx.db,
      scheduler: :g1_no_scheduler,
      state_dir: ctx.state_dir,
      host: @host,
      proc_root: ctx.proc,
      cgroup_root: ctx.cgroup,
      clock: fn -> :atomics.get(clock, 1) end,
      wall_clock: fn -> :atomics.get(clock, 2) end,
      interval: :manual,
      os: {:unix, :linux},
      clock_source: "CLOCK_MONOTONIC",
      trace: self()
    ]

    opts =
      defaults
      |> Keyword.merge(opts)
      |> Enum.reject(fn {_key, value} -> is_nil(value) end)

    id = make_ref()

    pid =
      start_supervised!(
        Supervisor.child_spec({MemoryPressure, opts}, id: id, restart: :temporary)
      )

    if settle?, do: settle()
    %{id: id, pid: pid}
  end

  # A crash of the whole gateway: nothing runs its orderly stop.
  defp kill_stack(%{pid: pid}) do
    settle()

    refs =
      [pid | MemoryPressure.names() |> Map.values() |> Enum.map(&Process.whereis/1)]
      |> Enum.reject(&is_nil/1)
      |> Enum.map(&Process.monitor/1)

    Process.exit(pid, :kill)
    for ref <- refs, do: assert_receive({:DOWN, ^ref, :process, _, _}, 5_000)
    :ok
  end

  defp set_clock(ctx, offset), do: set_clock(ctx, offset, ctx.wall0 + offset)

  defp set_clock(ctx, offset, wall) do
    :atomics.put(ctx.clock, 1, @mono0 + offset)
    :atomics.put(ctx.clock, 2, wall)
  end

  defp sample(ctx, offset) do
    set_clock(ctx, offset)
    reply = MemoryPressure.sample_now()
    settle()
    reply
  end

  # One sample that must be answered within a second, whatever the recorder
  # and the delivery process are doing. Returns the monotonic offset when the
  # sample produced a latest-sample marker write.
  defp fast_sample(ctx, offset) do
    set_clock(ctx, offset)
    assert %{} = MemoryPressure.sample_now(MemoryPressure, 1_000)
    names = MemoryPressure.names()
    :sys.get_state(names.sampler, 1_000)
    :sys.get_state(names.marker, 1_000)

    receive do
      {:memory_pressure_marker, :put, :latest, _marker} -> [offset]
    after
      0 -> []
    end
  end

  # Every hand-off has run: the recorder's transactions, the sampler's
  # handling of their replies, what that hands back to the recorder (a close
  # after an owner change), and the marker writes that follow.
  defp settle do
    names = MemoryPressure.names()

    for _round <- 1..2 do
      :sys.get_state(names.recorder)
      :sys.get_state(names.sampler)
    end

    :sys.get_state(names.marker)
    :ok
  end

  defp marker(ctx), do: Marker.read(ctx.state_dir)

  defp pressure(ctx), do: memory(ctx, 50, psi: {12.0, 12.0})
  defp calm(ctx), do: memory(ctx, 50)

  # /proc/meminfo and /proc/pressure/memory for one sample. `available` is
  # MemAvailable in percent of the 32 GiB total; swap is 8 GiB unless set.
  defp memory(ctx, available, opts \\ []) do
    swap_total = Keyword.get(opts, :swap_total, 8 * @gib_kib)
    swap_free = round(swap_total * Keyword.get(opts, :swap_free, 100) / 100)
    available_kib = round(@total * available / 100)

    File.write!(Path.join(ctx.proc, "meminfo"), """
    MemTotal:       #{@total} kB
    MemFree:        #{div(available_kib, 2)} kB
    MemAvailable:   #{available_kib} kB
    Buffers:           1024 kB
    SwapTotal:      #{swap_total} kB
    SwapFree:       #{swap_free} kB
    """)

    psi = Path.join(ctx.proc, "pressure/memory")

    case Keyword.get(opts, :psi, {0.0, 0.0}) do
      nil ->
        _ = File.rm(psi)

      {avg10, avg60} ->
        File.write!(
          psi,
          "some avg10=#{two(avg10)} avg60=#{two(avg60)} avg300=0.00 total=0\n" <>
            "full avg10=0.00 avg60=0.00 avg300=0.00 total=0\n"
        )
    end
  end

  defp two(value), do: :erlang.float_to_binary(value * 1.0, decimals: 2)

  # cgroup v2 with the gateway in system.slice, two containers, VMs, users
  # and one other service unit, in GiB (memory, swap).
  defp cgroup_v2(ctx, swap: swap?) do
    File.write!(Path.join(ctx.cgroup, "cgroup.controllers"), "cpu io memory pids\n")
    File.write!(Path.join(ctx.proc, "self/cgroup"), "0::/system.slice/tightbeam.service\n")

    for {group, memory, swap} <- [
          {"system.slice/tightbeam.service", 5.0, 0.1},
          {"machine.slice", 17.0, 0.4},
          {"system.slice/docker-aaaa.scope", 2.0, 0.0},
          {"system.slice/docker-bbbb.scope", 1.0, 0.2},
          {"user.slice", 3.5, 0.5},
          {"system.slice", 9.0, 0.9},
          {"system.slice/sshd.service", 0.5, 0.1}
        ] do
      dir = Path.join(ctx.cgroup, group)
      File.mkdir_p!(dir)
      File.write!(Path.join(dir, "memory.current"), "#{bytes(memory)}\n")
      if swap?, do: File.write!(Path.join(dir, "memory.swap.current"), "#{bytes(swap)}\n")
    end
  end

  defp bytes(gib), do: round(gib * 1_073_741_824)

  # V3: only the four sources were read, and no other unit was walked.
  defp assert_reads_confined(ctx) do
    reads = collect_reads([])
    assert reads != []
    fixed = Enum.map(["meminfo", "pressure/memory", "self/cgroup"], &Path.join(ctx.proc, &1))

    for path <- reads do
      refute path =~ ~r{/proc/[^/]+/(cmdline|environ|status)$}

      assert path in fixed or
               (String.starts_with?(path, ctx.cgroup <> "/") and
                  Path.basename(path) in ["memory.current", "memory.swap.current"]),
             "unexpected read #{path}"

      refute path =~ "sshd.service"
    end
  end

  defp collect_reads(acc) do
    receive do
      {:memory_pressure_read, path} -> collect_reads([path | acc])
    after
      0 -> Enum.reverse(acc)
    end
  end

  defp drain_reads, do: collect_reads([]) && :ok

  defp drain_marker_writes do
    receive do
      {:memory_pressure_marker, _, _, _} -> drain_marker_writes()
      {:memory_pressure_marker, _} -> drain_marker_writes()
    after
      0 -> :ok
    end
  end

  defp config_handler(db) do
    base_dir =
      Path.join(System.tmp_dir!(), "tightbeam-g1-config-#{System.unique_integer([:positive])}")

    on_exit(fn -> File.rm_rf!(base_dir) end)
    Archetypes.load!(base_dir)
    config = Gateway.handlers(%{db: db, base_dir: base_dir, wake_tick_ms: 1_000})["config"]

    fn params ->
      config.(%{principal: {:process, "test"}, origin: "process:test", params: params})
    end
  end

  defp runner(parent, outcome) do
    fn args ->
      send(parent, {:harklight, args})

      case args do
        ["send", "--prepare", "--op-id", op | rest] -> prepared(op, rest)
        ["send", "--execute", "--op-id", op] -> outcome.({:execute, op})
        ["retry", "--op-id", op] -> outcome.({:retry, op})
      end
    end
  end

  defp prepared(op, args) do
    frame(%{
      kind: "prepared",
      op_id: op,
      files: [],
      request: %{
        type: "send",
        op_id: op,
        session_handle: op,
        route: "other",
        message: %{
          sender_id: flag(args, "--sender-id"),
          message_id: "msg-" <> op,
          title: flag(args, "--title"),
          body: flag(args, "--body"),
          supersedes: []
        }
      }
    })
  end

  defp committed(op, operation) do
    frame(%{
      kind: "committed",
      operation: operation,
      op_id: op,
      response: %{session_handle: op, sender_id: "tightbeam-alerts", message_id: "msg-" <> op}
    })
  end

  defp failing(parent) do
    fn args ->
      send(parent, {:harklight, args})
      {"harklight-agent: network unreachable", 1}
    end
  end

  defp frame(value), do: {JSON.encode!(value) <> "\n", 0}
  defp flag(args, name), do: args |> Enum.drop_while(&(&1 != name)) |> Enum.at(1)

  ## Reads

  defp memory_alerts(db) do
    {:ok, rows} =
      DB.query(
        db,
        """
        SELECT alertId, dedupeKey, title, body, state, withdrawnAs, createdAt, opId, attempts,
               nextAttemptAt, sessionKey, turnSeq, workItemId
        FROM owner_alerts WHERE kind='memory-pressure' ORDER BY createdAt, rowid
        """
      )

    Enum.map(rows, fn [
                        id,
                        dedupe_key,
                        title,
                        body,
                        state,
                        withdrawn_as,
                        created_at,
                        op_id,
                        attempts,
                        next_attempt_at,
                        session_key,
                        turn_seq,
                        work_item_id
                      ] ->
      %{
        alert_id: id,
        dedupe_key: dedupe_key,
        title: title,
        body: body,
        state: state,
        withdrawn_as: withdrawn_as,
        created_at: created_at,
        op_id: op_id,
        attempts: attempts,
        next_attempt_at: next_attempt_at,
        session_key: session_key,
        turn_seq: turn_seq,
        work_item_id: work_item_id
      }
    end)
  end

  defp pressure_facts(db) do
    {:ok, rows} =
      DB.query(
        db,
        """
        SELECT kind, scope, origin FROM condition_facts
        WHERE kind IN ('host-memory-pressure', 'host-memory-pressure-cleared') ORDER BY id
        """
      )

    rows
  end

  defp lifecycle(db, kind) do
    db
    |> EventLog.lifecycle_events()
    |> Enum.filter(&(&1.kind == kind))
    |> Enum.map(&JSON.decode!(&1.detail))
  end

  defp closed_events(db), do: lifecycle(db, "memory_pressure_episode_closed")

  defp withdrawn_reasons(db, alert_id) do
    {:ok, rows} =
      DB.query(
        db,
        "SELECT detail FROM lifecycle_events WHERE kind='owner_alert_withdrawn' AND subject=?1",
        [alert_id]
      )

    Enum.map(rows, fn [detail] -> JSON.decode!(detail)["reason"] end)
  end

  defp count(db, sql, params \\ []) do
    {:ok, [[value]]} = DB.query(db, sql, params)
    value
  end
end

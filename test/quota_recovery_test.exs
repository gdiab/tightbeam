defmodule Tightbeam.QuotaRecoveryTest do
  use Tightbeam.TestCase, async: false

  alias Tightbeam.{
    DB,
    EventLog,
    Gateway,
    HarnessHealth,
    Ledger,
    Model,
    Org,
    QuotaRecovery,
    Schema,
    SessionLane,
    TurnLifecycle
  }

  @hour 60 * 60 * 1_000

  setup do
    db = :"quota_recovery_#{System.unique_integer([:positive])}"
    start_supervised!({DB, path: ":memory:", name: db})
    :ok = Schema.ensure_all(db)

    main = Org.personal_session_key("quota-owner")

    Org.create(db, %{
      session_key: main,
      display_name: "Main",
      kind: "main",
      owner_user_id: "quota-owner",
      origin: "user:quota-owner",
      archetype: "default",
      host: "quota-host",
      harness: "codex",
      provider: "openai",
      model: Model.new("gpt-5.6-sol")
    })

    holder = "agent:quota:holder"

    Org.create(db, %{
      session_key: holder,
      display_name: "Quota holder",
      owner_user_id: "quota-owner",
      origin: "user:quota-owner",
      archetype: "coder",
      host: "quota-host",
      harness: "codex",
      provider: "openai",
      model: Model.new("gpt-5.6-sol"),
      spawned_by: main
    })

    assert {:ok, []} =
             DB.query(
               db,
               """
               INSERT INTO assignments
                 (id,subject,holderKey,openedBySession,openedAt,state,holderHarness,holderProvider)
               VALUES ('asg_quota','recover quota-stranded work',?1,?2,1,'open','codex','openai')
               """,
               [holder, main]
             )

    %{db: db, holder: holder, main: main, assignment: "asg_quota"}
  end

  test "provider quota is a public, redacted hold and the sender sees why delivery queued", ctx do
    assert {:opened, _incident} =
             open_quota(ctx, 1_000, "usageLimitExceeded credential-secret-value")

    assert %{
             state: "held",
             reason_class: "provider_quota",
             harness: "codex",
             provider: "openai",
             since: 1_000,
             release_condition: release,
             last_error_class: "rate-limit-dead",
             owner: nil,
             turn_seq: nil
           } = QuotaRecovery.held_state(ctx.db, ctx.holder)

    assert release == "later same-credential success or recorded owner/Main resume"

    assert Gateway.queued_delivery_reason(ctx.db, ctx.holder) ==
             "recipient parked (provider_quota)"

    encoded = JSON.encode!(QuotaRecovery.held_state(ctx.db, ctx.holder))
    refute encoded =~ "usageLimitExceeded"
    refute encoded =~ "credential-secret-value"
    refute encoded =~ "process"
  end

  test "declared reset parsing is truthful for Codex and Claude forms" do
    observed = DateTime.to_unix(~U[2026-08-01 00:00:00Z], :millisecond)

    assert QuotaRecovery.declared_reset_at(
             "try again at Aug 15th, 2026 8:29 PM.",
             observed
           ) == DateTime.to_unix(~U[2026-08-15 20:29:00Z], :millisecond)

    assert QuotaRecovery.declared_reset_at("resets Aug 15, 12am (UTC)", observed) ==
             DateTime.to_unix(~U[2026-08-15 00:00:00Z], :millisecond)

    december = DateTime.to_unix(~U[2026-12-31 23:00:00Z], :millisecond)

    assert QuotaRecovery.declared_reset_at("resets Jan 1, 12am (UTC)", december) ==
             DateTime.to_unix(~U[2027-01-01 00:00:00Z], :millisecond)

    assert QuotaRecovery.declared_reset_at("usage limit without a reset", observed) == nil
  end

  test "a reached declared reset resolves both the incident and its park", ctx do
    observed = DateTime.to_unix(~U[2026-08-01 00:00:00Z], :millisecond)
    reset_at = DateTime.to_unix(~U[2026-08-15 20:29:00Z], :millisecond)

    assert {:opened, incident} =
             open_quota(ctx, observed, "try again at Aug 15th, 2026 8:29 PM.")

    assert {:resolved, "codex:shared@quota-host"} =
             HarnessHealth.resolve_declared_reset(ctx.db, "codex", "quota-host", reset_at)

    assert HarnessHealth.get(ctx.db, incident.id).state == "resolved"
    assert QuotaRecovery.held_state(ctx.db, ctx.holder) == nil

    assert {:ok, [["released", "provider_declared_reset", ^reset_at]]} =
             DB.query(ctx.db, """
             SELECT state,releaseCause,releasedAt FROM quota_recovery_parks
             WHERE adapterKey='codex:shared@quota-host'
             """)

    assert {:ok, [["authoritative-provider", "provider-declared reset reached"]]} =
             DB.query(
               ctx.db,
               """
               SELECT evidenceKind,cause FROM harness_health_observations
               WHERE id=(SELECT resolutionObservationId FROM harness_health_incidents WHERE id=?1)
               """,
               [incident.id]
             )
  end

  test "the first supported release records its actor and preserves queued order", ctx do
    assert {:opened, _incident} = open_quota(ctx, 2_000, "usage limit without reset")

    seqs =
      for label <- ~w(first second third) do
        enqueue!(ctx, label)
      end

    assert :ok =
             QuotaRecovery.explicit_resume(
               ctx.db,
               "codex",
               "quota-host",
               "session:delivery-owner"
             )

    assert QuotaRecovery.held_state(ctx.db, ctx.holder) == nil

    assert {:ok, [["released", "session:delivery-owner", "explicit_resume", released_at]]} =
             DB.query(ctx.db, """
             SELECT state,releasedBy,releaseCause,releasedAt
             FROM quota_recovery_parks WHERE adapterKey='codex:shared@quota-host'
             """)

    assert is_integer(released_at)

    assert {:ok, queued} =
             DB.query(
               ctx.db,
               "SELECT seq,status FROM turns WHERE sessionKey=?1 ORDER BY seq",
               [ctx.holder]
             )

    assert queued == Enum.map(seqs, &[&1, "queued"])
  end

  test "a parked lane claims nothing, then drains the preserved queue once in order", ctx do
    assert {:opened, _incident} = open_quota(ctx, 2_500, "usage limit without reset")

    seqs = for label <- ~w(first second third), do: enqueue!(ctx, label)
    {:ok, order} = Agent.start_link(fn -> [] end)
    start_supervised!({Registry, keys: :unique, name: Tightbeam.LaneRegistry})

    task_sup =
      start_supervised!(
        {Task.Supervisor, name: :"quota_tasks_#{System.unique_integer([:positive])}"}
      )

    runner = fn turn ->
      Agent.update(order, &(&1 ++ [turn.seq]))
      {:ok, %{text: "done"}}
    end

    start_supervised!(
      {SessionLane,
       session_key: ctx.holder,
       db: ctx.db,
       task_sup: task_sup,
       runner: runner,
       cancel_harness: fn _db, _session -> :ok end}
    )

    :sys.get_state(SessionLane.via(ctx.holder))

    assert {:ok, queued_before} =
             DB.query(ctx.db, "SELECT seq,status FROM turns ORDER BY seq")

    assert queued_before == Enum.map(seqs, &[&1, "queued"])
    assert Agent.get(order, & &1) == []

    assert :ok =
             QuotaRecovery.explicit_resume(
               ctx.db,
               "codex",
               "quota-host",
               "session:delivery-owner"
             )

    assert eventually(fn -> Agent.get(order, & &1) == seqs end)
    assert eventually(fn -> Ledger.pending_sessions(ctx.db) == [] end)

    assert assignment_snapshot(ctx) == [
             ctx.assignment,
             ctx.holder,
             ctx.main,
             "open",
             "recover quota-stranded work"
           ]
  end

  test "known quota cancels only the in-flight turn once and never replays it", ctx do
    parent = self()
    started_seq = enqueue!(ctx, "started")
    queued_seq = enqueue!(ctx, "not-started")
    before_assignment = assignment_snapshot(ctx)
    start_supervised!({Registry, keys: :unique, name: Tightbeam.LaneRegistry})

    task_sup =
      start_supervised!(
        {Task.Supervisor, name: :"quota_cancel_tasks_#{System.unique_integer([:positive])}"}
      )

    runner = fn turn ->
      send(parent, {:turn_started, turn.seq})

      receive do
        :provider_finished -> {:ok, %{text: "late"}}
      end
    end

    start_supervised!(
      {SessionLane,
       session_key: ctx.holder,
       db: ctx.db,
       task_sup: task_sup,
       runner: runner,
       cancel_harness: fn _db, session_key ->
         send(parent, {:supported_cancel, session_key})
         :ok
       end}
    )

    assert_receive {:turn_started, ^started_seq}
    assert :ok = QuotaRecovery.stamp_generation(ctx.db, started_seq, 11)
    assert {:opened, _incident} = open_quota(ctx, 2_750, "usageLimitExceeded")

    assert_receive {:supported_cancel, session_key}
    assert session_key == ctx.holder
    refute_receive {:supported_cancel, _other}

    assert eventually(fn ->
             DB.query(ctx.db, "SELECT status FROM turns WHERE seq=?1", [started_seq]) ==
               {:ok, [["failed_unknown"]]}
           end)

    assert {:ok, [[^queued_seq, "queued"]]} =
             DB.query(ctx.db, "SELECT seq,status FROM turns WHERE seq=?1", [queued_seq])

    assert %{reason_class: "provider_quota"} = QuotaRecovery.held_state(ctx.db, ctx.holder)
    assert QuotaRecovery.adapter_fenced?(ctx.db, {:codex, "shared", "quota-host"}, 11)
    assert assignment_snapshot(ctx) == before_assignment
  end

  test "120 minutes without genuine progress creates the disposition hold", ctx do
    parent = self()
    started_seq = enqueue!(ctx, "started")
    queued_seq = enqueue!(ctx, "not-started")
    start_supervised!({Registry, keys: :unique, name: Tightbeam.LaneRegistry})

    task_sup =
      start_supervised!(
        {Task.Supervisor, name: :"stall_cancel_tasks_#{System.unique_integer([:positive])}"}
      )

    start_supervised!(
      {SessionLane,
       session_key: ctx.holder,
       db: ctx.db,
       task_sup: task_sup,
       runner: fn turn ->
         send(parent, {:turn_started, turn.seq})

         receive do
           :finish -> {:ok, %{text: "late"}}
         end
       end,
       cancel_harness: fn _db, session_key ->
         send(parent, {:supported_cancel, session_key})
         :ok
       end}
    )

    assert_receive {:turn_started, ^started_seq}
    [{lane, _}] = Registry.lookup(Tightbeam.LaneRegistry, ctx.holder)
    expected = System.system_time(:millisecond) - 2 * @hour

    :sys.replace_state(lane, fn state -> %{state | last_advancement_at: expected} end)

    assert {:ok, []} =
             DB.query(
               ctx.db,
               """
               UPDATE quota_recovery_turns SET lastAdvancementAt=?2 WHERE turnSeq=?1
               """,
               [started_seq, expected]
             )

    send(lane, {:quota_recovery_deadline, started_seq, expected})
    assert_receive {:supported_cancel, session_key}
    assert session_key == ctx.holder

    assert eventually(fn ->
             match?(
               %{reason_class: "blocked_other", last_error_class: "unknown_effect"},
               QuotaRecovery.held_state(ctx.db, ctx.holder)
             )
           end)

    assert {:ok, [[^started_seq, "failed_unknown"], [^queued_seq, "queued"]]} =
             DB.query(ctx.db, "SELECT seq,status FROM turns ORDER BY seq")
  end

  test "later same-credential success releases the park without probing", ctx do
    assert {:opened, incident} = open_quota(ctx, 3_000, "usage limit without reset")

    assert {:resolved, resolved} =
             HarnessHealth.resolve(ctx.db, %{
               correlation_id: "success-after-quota",
               harness: "codex",
               host: "quota-host",
               failure_class: "rate-limit-dead",
               session_key: ctx.holder,
               assignment_id: ctx.assignment,
               observed_at: 4_000,
               cause: "normal turn delivered",
               principal: "process:tightbeam"
             })

    assert resolved.id == incident.id
    assert QuotaRecovery.held_state(ctx.db, ctx.holder) == nil

    assert {:ok, [["released", "same_credential_success", "process:tightbeam"]]} =
             DB.query(ctx.db, """
             SELECT state,releaseCause,releasedBy FROM quota_recovery_parks
             WHERE adapterKey='codex:shared@quota-host'
             """)
  end

  test "six hours without a release trigger emits one owner and Main blocker", ctx do
    assert {:opened, incident} = open_quota(ctx, 5_000, "usage limit without reset")

    assert :ok = QuotaRecovery.notice_due_holds(ctx.db, 5_000 + 6 * @hour)
    assert :ok = QuotaRecovery.notice_due_holds(ctx.db, 5_000 + 12 * @hour)

    notices =
      EventLog.lifecycle_events(ctx.db)
      |> Enum.filter(&(&1.kind == "quota_park_owner_blocker" and &1.subject == incident.id))

    assert length(notices) == 1

    assert {:ok, [[notice_at]]} =
             DB.query(ctx.db, "SELECT noticeSentAt FROM quota_recovery_parks")

    assert notice_at == 5_000 + 6 * @hour
  end

  test "stall recovery restarts clocks but never lifts the adapter fence or repeats notice",
       ctx do
    holder = ctx.holder
    seq = enqueue!(ctx, "active")
    assert {:ok, turn} = Ledger.claim_next(ctx.db, ctx.holder, "lane:test")
    turn = Map.put(turn, :session_key, ctx.holder)

    started = QuotaRecovery.turn_started(ctx.db, turn, "codex", "quota-host")
    assert :ok = QuotaRecovery.stamp_generation(ctx.db, seq, 7)

    assert {:stalled, ^holder, true} =
             QuotaRecovery.enter_stall(ctx.db, seq, started + @hour)

    assert %{reason_class: "in_flight_stalled", turn_seq: ^seq} =
             QuotaRecovery.held_state(ctx.db, ctx.holder)

    assert QuotaRecovery.adapter_fenced?(ctx.db, {:codex, "shared", "quota-host"}, 7)

    assert :ok = QuotaRecovery.genuine_advancement(ctx.db, seq, started + @hour + 1)
    assert QuotaRecovery.held_state(ctx.db, ctx.holder) == nil
    assert QuotaRecovery.adapter_fenced?(ctx.db, {:codex, "shared", "quota-host"}, 7)

    assert {:stalled, ^holder, false} =
             QuotaRecovery.enter_stall(ctx.db, seq, started + 2 * @hour + 1)

    stall_notices =
      EventLog.lifecycle_events(ctx.db)
      |> Enum.filter(
        &(&1.kind == "turn_in_flight_stalled" and &1.subject == Integer.to_string(seq))
      )

    assert length(stall_notices) == 1
  end

  test "unknown effect is recorded once, never replayed, and holds only the not-started queue",
       ctx do
    started_seq = enqueue!(ctx, "started")
    queued_seqs = [enqueue!(ctx, "queued-a"), enqueue!(ctx, "queued-b")]

    assert {:ok, turn} = Ledger.claim_next(ctx.db, ctx.holder, "lane:test")
    turn = Map.put(turn, :session_key, ctx.holder)
    before_assignment = assignment_snapshot(ctx)

    started_at = QuotaRecovery.turn_started(ctx.db, turn, "codex", "quota-host")
    QuotaRecovery.stamp_generation(ctx.db, started_seq, 9)

    assert :ok =
             QuotaRecovery.record_unknown_effect(
               ctx.db,
               started_seq,
               false,
               started_at + 2 * @hour,
               turn.owner_lease
             )

    assert :stale =
             QuotaRecovery.record_unknown_effect(
               ctx.db,
               started_seq,
               false,
               started_at + 2 * @hour + 1,
               turn.owner_lease
             )

    assert :ok =
             Ledger.finish(ctx.db, started_seq, "failed_unknown", "unknown_effect",
               owner_lease: turn.owner_lease,
               cause: "no-genuine-progress",
               principal: "process:tightbeam"
             )

    assert %{
             reason_class: "blocked_other",
             last_error_class: "unknown_effect",
             owner: owner
           } =
             hold =
             QuotaRecovery.held_state(ctx.db, ctx.holder)

    assert owner == ctx.main

    assert hold.release_condition ==
             "awaiting unknown-effect disposition by holder or delivery owner"

    assert {:ok, queued} =
             DB.query(ctx.db, "SELECT seq,status FROM turns WHERE status='queued' ORDER BY seq")

    assert queued == Enum.map(queued_seqs, &[&1, "queued"])
    assert assignment_snapshot(ctx) == before_assignment

    assert :ok =
             QuotaRecovery.dispose_unknown_effect(
               ctx.db,
               started_seq,
               "session:#{ctx.holder}",
               "effects reconciled"
             )

    assert QuotaRecovery.held_state(ctx.db, ctx.holder) == nil

    assert {:ok, [["disposed", "session:" <> holder, disposition_at, "effects reconciled"]]} =
             DB.query(
               ctx.db,
               """
               SELECT state,dispositionBy,dispositionAt,disposition
               FROM quota_recovery_turns WHERE turnSeq=?1
               """,
               [started_seq]
             )

    assert holder == ctx.holder
    assert is_integer(disposition_at)

    assert {:ok, [[1]]} =
             DB.query(
               ctx.db,
               """
               SELECT COUNT(*) FROM lifecycle_events
               WHERE kind='turn_unknown_effect' AND subject=?1
               """,
               [Integer.to_string(started_seq)]
             )
  end

  test "a distinct quota hold remains after no-quota disposition", ctx do
    seq = enqueue!(ctx, "started")
    assert {:ok, turn} = Ledger.claim_next(ctx.db, ctx.holder, "lane:test")
    turn = Map.put(turn, :session_key, ctx.holder)
    QuotaRecovery.turn_started(ctx.db, turn, "codex", "quota-host")

    assert :ok =
             QuotaRecovery.record_unknown_effect(ctx.db, seq, false, 10_000, turn.owner_lease)

    assert {:opened, _incident} = open_quota(ctx, 10_001, "usage limit without reset")
    assert %{reason_class: "blocked_other"} = QuotaRecovery.held_state(ctx.db, ctx.holder)

    assert :ok = QuotaRecovery.dispose_unknown_effect(ctx.db, seq, "session:#{ctx.holder}")
    assert %{reason_class: "provider_quota"} = QuotaRecovery.held_state(ctx.db, ctx.holder)
  end

  test "later progress cannot revive a cancelled turn or erase its disposition", ctx do
    seq = enqueue!(ctx, "started")
    assert {:ok, turn} = Ledger.claim_next(ctx.db, ctx.holder, "lane:test")
    turn = Map.put(turn, :session_key, ctx.holder)
    QuotaRecovery.turn_started(ctx.db, turn, "codex", "quota-host")

    assert :ok = QuotaRecovery.record_unknown_effect(ctx.db, seq, false, 20_000, turn.owner_lease)
    assert :ok = QuotaRecovery.dispose_unknown_effect(ctx.db, seq, "session:#{ctx.holder}")
    assert :ok = QuotaRecovery.genuine_advancement(ctx.db, seq, 30_000)

    assert {:ok, [["disposed", 20_000, "session:" <> holder]]} =
             DB.query(
               ctx.db,
               """
               SELECT state,canceledAt,dispositionBy FROM quota_recovery_turns WHERE turnSeq=?1
               """,
               [seq]
             )

    assert holder == ctx.holder
  end

  test "progress identity excludes heartbeats and collapses replay metadata" do
    assert TurnLifecycle.progress_observation(%{"sessionUpdate" => "heartbeat"}) == nil

    first = %{
      "sessionUpdate" => "tool_call_update",
      "toolCallId" => "call-1",
      "status" => "running",
      "title" => "Read source",
      "transportSequence" => 10
    }

    replay = %{first | "transportSequence" => 99}
    changed = %{first | "status" => "completed"}

    assert TurnLifecycle.progress_identity(first) == TurnLifecycle.progress_identity(replay)
    refute TurnLifecycle.progress_identity(first) == TurnLifecycle.progress_identity(changed)
  end

  defp eventually(fun, tries \\ 60) do
    cond do
      fun.() ->
        true

      tries == 0 ->
        false

      true ->
        Process.sleep(25)
        eventually(fun, tries - 1)
    end
  end

  defp open_quota(ctx, observed_at, cause) do
    HarnessHealth.observe(ctx.db, %{
      correlation_id: "quota-#{observed_at}",
      harness: "codex",
      host: "quota-host",
      failure_class: "rate-limit-dead",
      evidence_kind: "authoritative-provider",
      session_key: ctx.holder,
      assignment_id: ctx.assignment,
      observed_at: observed_at,
      cause: cause,
      principal: "process:tightbeam/provider"
    })
  end

  defp enqueue!(ctx, label) do
    {:ok, seq} =
      Ledger.enqueue(ctx.db, %{
        session_key: ctx.holder,
        message_id: "quota-message-#{label}-#{System.unique_integer([:positive])}",
        origin: "session:#{ctx.main}",
        prompt: label,
        assignment_id: ctx.assignment
      })

    seq
  end

  defp assignment_snapshot(ctx) do
    {:ok, [row]} =
      DB.query(
        ctx.db,
        """
        SELECT id,holderKey,openedBySession,state,subject
        FROM assignments WHERE id=?1
        """,
        [ctx.assignment]
      )

    row
  end
end

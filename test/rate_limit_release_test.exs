defmodule Tightbeam.RateLimitReleaseTest do
  use Tightbeam.TestCase, async: false

  alias Tightbeam.{
    DB,
    HarnessHealth,
    HarnessProcess,
    LaneManager,
    Ledger,
    Org,
    QuotaRelease,
    RateLimitReset,
    Wakes
  }

  alias Tightbeam.DB.Txn

  @key {:claude, "shared", "testhost"}
  @past DateTime.to_unix(~U[2025-08-14 23:00:00Z], :millisecond)
  @error %{
    "code" => -32_603,
    "data" => %{"errorKind" => "rate_limit"},
    "message" => "Internal error: You've hit your weekly limit · resets Aug 15, 12am (UTC)"
  }

  setup do
    db = :"reset_release_#{System.unique_integer([:positive])}"
    start_supervised!({DB, path: ":memory:", name: db})
    :ok = Tightbeam.Schema.ensure_all(db)
    ensure_main_session(db, "tester")

    for key <- ["k1", "k2"] do
      Org.create(db, %{
        session_key: key,
        display_name: key,
        owner_user_id: "tester",
        origin: "user:tester",
        archetype: "coder",
        host: "testhost",
        harness: "claude",
        provider: "anthropic",
        model: Tightbeam.Model.new("claude-sonnet-5")
      })
    end

    for {key, host} <- [{"c1", "testhost"}, {"c2", "testhost"}, {"r1", "satellite"}] do
      Org.create(db, %{
        session_key: key,
        display_name: key,
        owner_user_id: "tester",
        origin: "user:tester",
        archetype: "coder",
        host: host,
        harness: "codex",
        provider: "openai",
        model: Tightbeam.Model.new("gpt-5.6-sol")
      })
    end

    # Codex states its reset in the local time of its host (companion §1).
    previous_zone = Application.get_env(:tightbeam, :local_time_zone)
    Application.put_env(:tightbeam, :local_time_zone, "America/Los_Angeles")

    on_exit(fn ->
      if previous_zone,
        do: Application.put_env(:tightbeam, :local_time_zone, previous_zone),
        else: Application.delete_env(:tightbeam, :local_time_zone)
    end)

    %{db: db}
  end

  test "terminal failure persists the stated reset before the shared incident opens", %{db: db} do
    before_failure = System.system_time(:millisecond)
    error = reset_error(before_failure + 3_600_000)
    fail_turn(db, "k1", error)
    refute HarnessProcess.parked?(db, @key)

    assert {:ok, [[first, due_at, nil]]} =
             DB.query(db, """
             SELECT w.wakeId,w.dueAt,o.incidentId FROM wakes w
             JOIN harness_health_observations o ON o.id=w.prompt
             WHERE w.consumer='rate_limit_reset'
             """)

    assert due_at == RateLimitReset.from_error(error, before_failure)
    fail_turn(db, "k2", error)
    assert HarnessProcess.parked?(db, @key)

    assert {:ok, [[2]]} =
             DB.query(db, "SELECT count(*) FROM wakes WHERE consumer='rate_limit_reset'")

    assert {:ok, [[2]]} =
             DB.query(
               db,
               "SELECT count(*) FROM harness_health_observations WHERE incidentId IS NOT NULL"
             )

    assert {:ok, {:deferred, :before_reset}} = RateLimitReset.release(db, %{wake_id: first})
    assert HarnessProcess.parked?(db, @key)
  end

  test "an overdue reset recovered on scheduler boot releases queued lanes without claiming success",
       %{db: db} do
    error = %{
      @error
      | "message" => "You've hit your weekly limit · resets Sep 21 at 11pm (America/Los_Angeles)"
    }

    observed = DateTime.to_unix(~U[2025-09-20 10:00:00Z], :millisecond)
    {incident, wake} = observe_reset(db, "old-limit", error, observed)
    assert wake.due_at == DateTime.to_unix(~U[2025-09-22 06:00:00Z], :millisecond)
    assert HarnessProcess.parked?(db, @key)
    parent = self()
    start_supervised!({Registry, keys: :unique, name: Tightbeam.LaneRegistry})
    task_sup = start_supervised!({Task.Supervisor, []})
    lane_sup = start_supervised!({DynamicSupervisor, strategy: :one_for_one})

    manager =
      start_supervised!(
        {LaneManager,
         db: db,
         lane_sup: lane_sup,
         task_sup: task_sup,
         name: Tightbeam.LaneManager,
         runner: fn turn ->
           send(parent, {:started, turn.seq, self()})

           receive do
             :finish -> {:ok, %{text: "done"}}
           end
         end}
      )

    seqs =
      for key <- ["k1", "k2"] do
        seq = enqueue(db, key)
        :ok = LaneManager.ensure_lane(manager, key)
        [{lane, _}] = Registry.lookup(Tightbeam.LaneRegistry, key)
        :sys.get_state(lane)
        assert {:ok, [["queued"]]} = DB.query(db, "SELECT status FROM turns WHERE seq=?1", [seq])
        seq
      end

    start_supervised!(
      {Wakes,
       db: db,
       name: Tightbeam.WakeScheduler,
       deliver: fn _ -> :retry end,
       internal_consumers: %{"rate_limit_reset" => &RateLimitReset.release(db, &1)}}
    )

    started =
      for _ <- seqs do
        assert_receive {:started, seq, runner}, 5_000
        {seq, runner}
      end

    assert Enum.sort(Enum.map(started, &elem(&1, 0))) == Enum.sort(seqs)
    refute HarnessProcess.parked?(db, @key)
    assert HarnessHealth.get(db, incident.id).state == "open"

    assert {:ok, [[0]]} =
             DB.query(
               db,
               "SELECT count(*) FROM harness_health_observations WHERE evidenceKind='normal-turn-success'"
             )

    assert {:ok, [["fired"]]} =
             DB.query(db, "SELECT state FROM wakes WHERE wakeId=?1", [wake.wake_id])

    assert {:ok, :already_consumed} = RateLimitReset.release(db, wake)
    Enum.each(started, fn {_, runner} -> send(runner, :finish) end)
  end

  @tag timeout: 70_000
  test "the scheduler releases at the stated reset without a poll or manual repair", %{db: db} do
    reset_at = (div(System.system_time(:millisecond), 60_000) + 1) * 60_000
    error = reset_error(reset_at)
    fail_turn(db, "k1", error)
    fail_turn(db, "k2", error)
    assert HarnessProcess.parked?(db, @key)

    assert {:ok, [[^reset_at]]} =
             DB.query(db, "SELECT DISTINCT dueAt FROM wakes WHERE consumer='rate_limit_reset'")

    parent = self()

    start_supervised!(
      {Wakes,
       db: db,
       name: Tightbeam.WakeScheduler,
       deliver: fn _ -> :retry end,
       internal_consumers: %{
         "rate_limit_reset" => fn wake ->
           result = RateLimitReset.release(db, wake)
           send(parent, {:released, System.system_time(:millisecond)})
           result
         end
       }}
    )

    assert_receive {:released, released_at}, 65_000
    assert released_at >= reset_at
    assert released_at - reset_at < 5_000
    refute HarnessProcess.parked?(db, @key)
  end

  test "an earlier reset cannot release a later stated limit in the same incident", %{db: db} do
    {incident, early} = observe_reset(db, "early", @error, @past)
    future_at = System.system_time(:millisecond)
    later_error = reset_error(future_at + 3_600_000)
    {same, later} = observe_reset(db, "later", later_error, future_at)
    assert same.id == incident.id
    assert later.due_at > future_at
    assert {:ok, :ok} = RateLimitReset.release(db, early)
    assert HarnessProcess.parked?(db, @key)

    assert {:ok, [["pending"]]} =
             DB.query(db, "SELECT state FROM wakes WHERE wakeId=?1", [later.wake_id])
  end

  test "a stale reset from a resolved incident cannot release a new hold", %{db: db} do
    {incident, old} = observe_reset(db, "old", @error, @past)

    assert {:resolved, _} =
             HarnessHealth.resolve(db, %{
               correlation_id: "success",
               harness: "claude",
               host: "testhost",
               failure_class: "rate-limit-dead",
               session_key: "k1",
               assignment_id: nil,
               observed_at: @past + 1,
               cause: "normal turn delivered",
               principal: "process:test"
             })

    {new, _} = observe_reset(db, "new", @error, @past + 2)
    refute new.id == incident.id
    assert {:ok, :ok} = RateLimitReset.release(db, old)
    assert HarnessProcess.parked?(db, @key)
  end

  test "retry limit rearms the open incident and duplicate observation does not rearm a consumed reset",
       %{db: db} do
    {incident, wake} = observe_reset(db, "first", @error, @past)
    assert {:ok, :ok} = RateLimitReset.release(db, wake)
    refute HarnessProcess.parked?(db, @key)
    {same, ^wake} = observe_reset(db, "first", @error, @past)
    assert same.id == incident.id
    refute HarnessProcess.parked?(db, @key)
    {same, retry} = observe_reset(db, "retry", @error, @past + 1)
    assert same.id == incident.id
    assert HarnessProcess.parked?(db, @key)
    assert {:ok, :ok} = RateLimitReset.release(db, retry)
    refute HarnessProcess.parked?(db, @key)
  end

  test "a typed error without a reset retains the hold without inventing a deadline", %{db: db} do
    error = %{@error | "message" => "Rate limit exceeded"}
    fail_turn(db, "k1", error)
    fail_turn(db, "k2", error)
    assert HarnessProcess.parked?(db, @key)

    assert {:ok, [[0]]} =
             DB.query(db, "SELECT count(*) FROM wakes WHERE consumer='rate_limit_reset'")
  end

  ## Codex (quota companion v1.1, B1-B5) and v3 R9(b)

  @codex_key {:codex, "shared", "testhost"}
  @nov14 DateTime.to_unix(~U[2026-11-14 16:04:00Z], :millisecond)
  # The captured Codex shape (harness_health_test's @captured_codex_rate_limit),
  # with the Nov 14 incident's reset.
  @codex_nov14 %{
    "code" => -32_603,
    "data" => %{
      "codexErrorInfo" => "usageLimitExceeded",
      "message" =>
        "You've hit your usage limit. Visit the account usage page or try again at Nov 18th, 2026 9:59 AM."
    },
    "message" => "Internal error"
  }

  test "B1: the Nov 14 Codex limit releases at its declared reset, across a restart, and the incident stays open",
       %{db: db} do
    {incident, wake} = observe_codex(db, "nov14", "c1", @codex_nov14, @nov14)
    assert wake.due_at == DateTime.to_unix(~U[2026-11-18 17:59:00Z], :millisecond)
    assert HarnessProcess.parked?(db, @codex_key)
    parent = self()
    start_supervised!({Registry, keys: :unique, name: Tightbeam.LaneRegistry})
    task_sup = start_supervised!({Task.Supervisor, []})
    lane_sup = start_supervised!({DynamicSupervisor, strategy: :one_for_one})

    manager =
      start_supervised!(
        {LaneManager,
         db: db,
         lane_sup: lane_sup,
         task_sup: task_sup,
         name: Tightbeam.LaneManager,
         runner: fn turn ->
           send(parent, {:started, turn.session_key, turn.seq, self()})

           receive do
             :finish -> {:ok, %{text: "done"}}
           end
         end}
      )

    first = enqueue(db, "c1")
    second = enqueue(db, "c1")
    other = enqueue(db, "c2")
    for key <- ["c1", "c2"], do: :ok = LaneManager.ensure_lane(manager, key)
    refute_receive {:started, _, _, _}, 100

    # The reset passed while no scheduler ran: it releases at startup, with no
    # Codex success and no repair command.
    start_supervised!(
      {Wakes,
       db: db,
       name: Tightbeam.WakeScheduler,
       deliver: fn _ -> :retry end,
       internal_consumers: %{"rate_limit_reset" => &RateLimitReset.release(db, &1)}}
    )

    assert_receive {:started, "c1", ^first, runner}, 5_000
    assert_receive {:started, "c2", ^other, other_runner}, 5_000
    refute HarnessProcess.parked?(db, @codex_key)
    assert HarnessHealth.get(db, incident.id).state == "open"

    assert [%{"cause" => "declared_reset", "resetAt" => reset_at, "releasedAt" => released_at}] =
             lifecycle(db, "rate_limit_hold_released", incident.id)

    assert reset_at == wake.due_at
    assert released_at >= reset_at

    # A session's queued turns are claimed in their original order.
    send(runner, :finish)
    assert_receive {:started, "c1", ^second, second_runner}, 5_000
    Enum.each([second_runner, other_runner], &send(&1, :finish))
  end

  test "B1: a time-only Codex reset is that day; a remote host's reset is unknown", %{db: db} do
    observed = DateTime.to_unix(~U[2026-11-18 16:10:00Z], :millisecond)
    error = codex_error("try again at 9:59 AM.")
    {_incident, wake} = observe_codex(db, "time-only", "c1", error, observed)
    assert wake.due_at == DateTime.to_unix(~U[2026-11-18 17:59:00Z], :millisecond)

    assert {:ok, %{observationId: remote}} =
             DB.transaction(db, fn txn ->
               {_, observation} =
                 result = observe_in_txn(txn, "remote", "r1", "satellite", observed)

               :ok =
                 RateLimitReset.schedule_in_txn(
                   txn,
                   %{harness: :codex, host: "satellite", session_key: "r1"},
                   result,
                   error,
                   observed
                 )

               observation
             end)

    assert {:ok, []} =
             DB.query(db, "SELECT 1 FROM wakes WHERE wakeId=?1", ["rate-limit-reset:" <> remote])

    assert HarnessProcess.parked?(db, {:codex, "shared", "satellite"})
  end

  test "B3: a Codex limit that names no reset parks, and nothing releases it on a timer",
       %{db: db} do
    error = codex_error("try again later.")
    fail_turn(db, "c1", error)
    fail_turn(db, "c2", error)
    assert HarnessProcess.parked?(db, @codex_key)

    assert {:ok, [[0]]} =
             DB.query(db, "SELECT count(*) FROM wakes WHERE consumer='rate_limit_reset'")
  end

  test "B4: a Codex limit met again after the release re-parks, with its own reset or unknown",
       %{db: db} do
    {incident, wake} = observe_codex(db, "first", "c1", @codex_nov14, @nov14)
    assert {:ok, :ok} = RateLimitReset.release(db, wake)
    refute HarnessProcess.parked?(db, @codex_key)

    later = System.system_time(:millisecond)
    {same, again} = observe_codex(db, "again", "c2", future_codex_error(later), later)
    assert same.id == incident.id
    assert HarnessProcess.parked?(db, @codex_key)
    assert again.due_at > later
    assert {:ok, {:deferred, :before_reset}} = RateLimitReset.release(db, again)

    {:ok, _} = DB.query(db, "UPDATE wakes SET dueAt=0 WHERE wakeId=?1", [again.wake_id])
    assert {:ok, :ok} = RateLimitReset.release(db, again)
    refute HarnessProcess.parked?(db, @codex_key)

    # A further limit that names no reset re-parks as well.
    assert {:ok, :ok} =
             DB.transaction(db, fn txn ->
               RateLimitReset.schedule_in_txn(
                 txn,
                 %{harness: :codex, host: "testhost", session_key: "c1"},
                 observe_in_txn(txn, "unknown-again", "c1", "testhost", later + 1),
                 codex_error("try again later."),
                 later + 1
               )
             end)

    assert HarnessProcess.parked?(db, @codex_key)
    assert HarnessHealth.get(db, incident.id).state == "open"
  end

  test "B5: a quota-failed turn that had started work is never replayed and is surfaced once",
       %{db: db} do
    error = future_codex_error(System.system_time(:millisecond))
    pre = fail_turn(db, "c1", error)
    post = fail_turn(db, "c2", error, started_work: true)
    assert HarnessProcess.parked?(db, @codex_key)

    # Only the pre-activity turn gets a redelivery row.
    assert redelivery_sources(db) == [pre]
    # A row written before this guard existed, for the post-activity turn.
    insert_legacy_redelivery!(db, "c2", post)

    {:ok, _} = DB.query(db, "UPDATE wakes SET dueAt=0 WHERE consumer='rate_limit_reset'")

    {:ok, [[wake_id] | _]} =
      DB.query(db, "SELECT wakeId FROM wakes WHERE consumer='rate_limit_reset'")

    assert {:ok, :ok} = RateLimitReset.release(db, %{wake_id: wake_id})
    refute HarnessProcess.parked?(db, @codex_key)

    assert [%{"turnSeq" => ^post, "disposition" => "unknown_effect", "cause" => "provider_quota"}] =
             lifecycle(db, "quota_failed_turn_not_replayed", "c2")

    assert lifecycle(db, "quota_failed_turn_not_replayed", "c1") == []
    main = Org.personal_session_key("tester")
    assert Enum.map(notices(db), & &1.session_key) == Enum.sort(["c2", main])

    for notice <- notices(db) do
      assert notice.prompt =~ "Turn #{post} of c2"
      assert notice.prompt =~ "NOT replayed"
    end

    # The reset release itself re-admitted the pre-activity turn, and never the
    # post-activity one.
    assert {:ok, [[^pre]]} =
             DB.query(
               db,
               "SELECT sourceTurnSeq FROM health_redelivery_attempts WHERE redeliveryTurnSeq IS NOT NULL"
             )

    # A later success is a release too (v3 R9(b)). It surfaces nothing again
    # and redelivers nothing again.
    assert {:resolved, incident} = resolve_codex(db, "c1", "testhost")
    assert length(notices(db)) == 2

    assert {:ok, 0} =
             DB.transaction(db, fn txn ->
               for key <- ["c1", "c2"], reduce: 0 do
                 count ->
                   count +
                     Wakes.redeliver_pending_health_intents_in_txn(
                       txn,
                       %{harness: :codex, host: "testhost", session_key: key},
                       %{seq: pre}
                     )
               end
             end)

    assert {:ok, [[^pre]]} =
             DB.query(
               db,
               "SELECT sourceTurnSeq FROM health_redelivery_attempts WHERE redeliveryTurnSeq IS NOT NULL"
             )

    assert HarnessHealth.get(db, incident.id).state == "resolved"
  end

  test "B5: a release adds no item for a turn a c1-applied switch already disposed of",
       %{db: db} do
    error = future_codex_error(System.system_time(:millisecond))
    fail_turn(db, "c1", error)
    # Held for its limit-fallback evaluation, which then applied the switch.
    held = fail_turn(db, "c2", error, started_work: true, held: true)

    {:ok, []} =
      DB.query(
        db,
        """
        INSERT INTO limit_fallback_evaluations (sessionKey,turnSeq,heldAt,outcome,createdAt,decidedAt)
        VALUES ('c2',?1,1,'applied',1,2)
        """,
        [held]
      )

    assert HarnessProcess.parked?(db, @codex_key)
    {:ok, _} = DB.query(db, "UPDATE wakes SET dueAt=0 WHERE consumer='rate_limit_reset'")

    {:ok, [[wake_id] | _]} =
      DB.query(db, "SELECT wakeId FROM wakes WHERE consumer='rate_limit_reset'")

    assert {:ok, :ok} = RateLimitReset.release(db, %{wake_id: wake_id})
    refute HarnessProcess.parked?(db, @codex_key)
    assert notices(db) == []
    assert lifecycle(db, "quota_failed_turn_not_replayed", "c2") == []
  end

  test "B6: a committed OpenAI activation releases the parked Codex key with a record; Claude stays",
       %{db: db} do
    pre = fail_turn(db, "c1", codex_error("try again later."))

    codex_incident = park_codex(db, "codex-park", "c2")

    {claude_incident, _} =
      observe_reset(db, "claude-park", @error, System.system_time(:millisecond))

    assert HarnessProcess.parked?(db, @codex_key)
    assert HarnessProcess.parked?(db, @key)

    assert :ok = Tightbeam.Gateway.credential_activation_hook(db, "testhost").(:openai)

    refute HarnessProcess.parked?(db, @codex_key)

    assert [
             %{
               "cause" => "credential_replacement",
               "actor" => "process:credentials",
               "releasedAt" => at
             }
           ] =
             lifecycle(db, "rate_limit_hold_released", codex_incident.id)

    assert is_integer(at)
    # B5: the pre-activity turn is re-admitted by the release.
    assert queued_messages(db) == [source_message(db, pre)]
    assert HarnessHealth.get(db, codex_incident.id).state == "open"

    # Another provider's park is untouched.
    assert HarnessProcess.parked?(db, @key)
    assert lifecycle(db, "rate_limit_hold_released", claude_incident.id) == []
  end

  test "B2 (v1.2): no unnamed path lifts a quota park; other fences still complete", %{db: db} do
    incident = park_codex(db, "held", "c1")

    assert HarnessProcess.parked?(db, @codex_key)

    # An adapter close (idle or credential-change), process-park completion,
    # launch reconciliation and proven-dead settlement all complete through
    # here; so does a gateway restart's reconciliation.
    assert :ok = HarnessProcess.complete_park(db, @codex_key)
    assert {:ok, :ok} = DB.transaction(db, &HarnessProcess.complete_park_in_txn(&1, @codex_key))
    assert :ok = HarnessProcess.reconcile(db)
    assert {:ok, _} = HarnessProcess.reconcile_failed_parks(db)

    assert HarnessProcess.parked?(db, @codex_key)
    assert HarnessHealth.get(db, incident.id).state == "open"
    assert lifecycle(db, "rate_limit_hold_released", incident.id) == []

    # A fence with no quota incident behind it completes as before.
    pi_key = {:pi, "shared", "testhost"}
    {:ok, _} = HarnessProcess.begin_park(db, pi_key)
    assert HarnessProcess.parked?(db, pi_key)
    assert :ok = HarnessProcess.complete_park(db, pi_key)
    refute HarnessProcess.parked?(db, pi_key)
  end

  test "B2: after a named release, close, shutdown and crash fences complete; only a limit met again re-parks and holds",
       %{db: db} do
    incident = park_codex(db, "held", "c1")
    assert HarnessProcess.parked?(db, @codex_key)

    assert {:ok, :released} =
             DB.transaction(db, fn txn ->
               QuotaRelease.release_named_in_txn(txn, incident.id, "codex", "testhost", %{
                 cause: "explicit_resume",
                 actor: "user:tester"
               })
             end)

    refute HarnessProcess.parked?(db, @codex_key)

    # An adapter close (idle reap, repair close or restart) fences the key and
    # completes: it is not the quota park, so the guard does not keep it.
    {:ok, _} = HarnessProcess.begin_park(db, @codex_key)
    assert HarnessProcess.parked?(db, @codex_key)
    assert :ok = HarnessProcess.complete_park(db, @codex_key)
    refute HarnessProcess.parked?(db, @codex_key)

    # A gateway shutdown fences the key; the next boot's reconciliation clears it.
    deadline = System.monotonic_time(:millisecond) + 60_000
    {:ok, _} = HarnessProcess.begin_park_many_until(db, [@codex_key], deadline)
    assert HarnessProcess.parked?(db, @codex_key)
    assert :ok = HarnessProcess.reconcile(db)
    refute HarnessProcess.parked?(db, @codex_key)

    # A proven-dead settlement fences the key and completes.
    assert HarnessProcess.settle_proven_dead(db, @codex_key) in [:ok, :already_resolved]
    refute HarnessProcess.parked?(db, @codex_key)

    # None of these resolves the incident; it waits for a later success.
    assert HarnessHealth.get(db, incident.id).state == "open"

    # B4: a limit met again after all that re-parks, and that quota park holds
    # through the same completions.
    later = System.system_time(:millisecond)

    assert {:ok, :ok} =
             DB.transaction(db, fn txn ->
               RateLimitReset.schedule_in_txn(
                 txn,
                 %{harness: :codex, host: "testhost", session_key: "c2"},
                 observe_in_txn(txn, "after-close", "c2", "testhost", later),
                 codex_error("try again later."),
                 later
               )
             end)

    assert HarnessProcess.parked?(db, @codex_key)
    {:ok, _} = HarnessProcess.begin_park(db, @codex_key)
    assert :ok = HarnessProcess.complete_park(db, @codex_key)
    assert :ok = HarnessProcess.reconcile(db)
    assert HarnessProcess.settle_proven_dead(db, @codex_key) in [:ok, :already_resolved]
    assert HarnessProcess.parked?(db, @codex_key)
  end

  test "B5: a post-activity quota failure is recorded and surfaced at once, even with no incident",
       %{db: db} do
    # One session's failure leaves its observation pending: no incident, no
    # park, and so no release would ever surface it.
    post = fail_turn(db, "c1", codex_error("try again later."), started_work: true)
    refute HarnessProcess.parked?(db, @codex_key)
    assert redelivery_sources(db) == []

    assert [%{"turnSeq" => ^post, "incidentId" => nil, "disposition" => "unknown_effect"}] =
             lifecycle(db, "quota_failed_turn_not_replayed", "c1")

    main = Org.personal_session_key("tester")
    assert Enum.map(notices(db), & &1.session_key) == Enum.sort(["c1", main])
  end

  test "B5: the reset release itself re-admits a sole pre-activity message turn, once, in seq order",
       %{db: db} do
    error = future_codex_error(System.system_time(:millisecond))
    first = fail_turn(db, "c1", error)
    second = fail_turn(db, "c1", error)

    # The incident opens without any other session's turn.
    assert {:ok, _} =
             DB.transaction(db, fn txn ->
               observe_in_txn(txn, "open", "c1", "testhost", System.system_time(:millisecond))
             end)

    assert HarnessProcess.parked?(db, @codex_key)
    assert queued_messages(db) == []

    {:ok, _} = DB.query(db, "UPDATE wakes SET dueAt=0 WHERE consumer='rate_limit_reset'")
    {:ok, wakes} = DB.query(db, "SELECT wakeId FROM wakes WHERE consumer='rate_limit_reset'")
    for [wake_id] <- wakes, do: assert({:ok, _} = RateLimitReset.release(db, %{wake_id: wake_id}))
    refute HarnessProcess.parked?(db, @codex_key)

    # Each failed turn is queued again exactly once, in its seq order, with no
    # success on the key; the release is its restoration.
    assert queued_messages(db) == [source_message(db, first), source_message(db, second)]

    assert {:ok, rows} =
             DB.query(
               db,
               "SELECT sourceTurnSeq,restorationTurnSeq,redeliveryTurnSeq FROM health_redelivery_attempts ORDER BY sourceTurnSeq"
             )

    assert [[^first, r1, r1], [^second, r2, r2]] = rows
    assert r1 < r2

    # A later success redelivers neither again.
    assert {:resolved, _} = resolve_codex(db, "c2", "testhost")

    assert {:ok, 0} =
             DB.transaction(db, fn txn ->
               Wakes.redeliver_pending_health_intents_in_txn(
                 txn,
                 %{harness: :codex, host: "testhost", session_key: "c1"},
                 %{seq: second}
               )
             end)

    assert length(queued_messages(db)) == 2
  end

  test "B5: a quota-failed wake turn that had started work gets no retry; one that had not keeps it",
       %{db: db} do
    for {key, started_work, expected} <- [{"c1", false, :retry}, {"c2", true, :not_retryable}] do
      wake =
        Wakes.schedule(db, %{
          session_key: key,
          target_role: nil,
          origin: "user:tester",
          prompt: "wake work",
          due_at: 0
        })

      seq = enqueue(db, key, wake_id: wake.wake_id)
      {:ok, turn} = Ledger.claim_next(db, key, "test-owner")
      if started_work, do: started_work!(db, key, seq)

      assert {:ok, result} =
               DB.transaction(db, fn txn ->
                 assert Ledger.finish_in_txn(txn, seq, "failed", "You've hit your usage limit.",
                          owner_lease: turn.owner_lease
                        )

                 Wakes.preserve_failed_intent_for_terminal_in_txn(txn, seq)
               end)

      assert match?({:retry, _}, result) == (expected == :retry)
      if expected == :not_retryable, do: assert(result == :not_retryable)
    end
  end

  test "R9(b): an in-flight success on the same key releases and resolves; another host's does not",
       %{db: db} do
    error = codex_error("try again later.")
    fail_turn(db, "c1", error)
    fail_turn(db, "c2", error)
    assert HarnessProcess.parked?(db, @codex_key)
    queued = enqueue(db, "c1")
    start_supervised!({__MODULE__.LaneSpy, self()})

    assert :already_healthy = resolve_codex(db, "r1", "satellite")
    assert HarnessProcess.parked?(db, @codex_key)

    assert {:resolved, incident} = resolve_codex(db, "c2", "testhost")
    refute HarnessProcess.parked?(db, @codex_key)
    assert HarnessHealth.get(db, incident.id).state == "resolved"
    assert_receive {:ensure_lane, "c1"}, 1_000
    assert {:ok, [["queued"]]} = DB.query(db, "SELECT status FROM turns WHERE seq=?1", [queued])
  end

  defmodule LaneSpy do
    use GenServer

    def start_link(parent),
      do: GenServer.start_link(__MODULE__, parent, name: Tightbeam.LaneManager)

    def init(parent), do: {:ok, parent}

    def handle_cast({:ensure_lane, key}, parent) do
      send(parent, {:ensure_lane, key})
      {:noreply, parent}
    end

    def handle_cast(_message, parent), do: {:noreply, parent}
  end

  describe "host zone" do
    test "only the gateway's own host has a known zone" do
      previous = Application.get_env(:tightbeam, :local_time_zone)
      Application.put_env(:tightbeam, :local_time_zone, "America/Los_Angeles")

      try do
        assert Tightbeam.HostZone.zone(Tightbeam.Placement.local_host_name()) ==
                 "America/Los_Angeles"

        assert Tightbeam.HostZone.zone("some-satellite") == nil
        assert Tightbeam.HostZone.zone(nil) == nil
        Application.put_env(:tightbeam, :local_time_zone, "Not/AZone")
        assert Tightbeam.HostZone.zone(Tightbeam.Placement.local_host_name()) == nil
      after
        if previous,
          do: Application.put_env(:tightbeam, :local_time_zone, previous),
          else: Application.delete_env(:tightbeam, :local_time_zone)
      end
    end
  end

  defp codex_error(text) do
    put_in(@codex_nov14, ["data", "message"], "You've hit your usage limit. " <> text)
  end

  # A Codex reset two hours after `at`, in the host's zone and Codex's format.
  defp future_codex_error(at) do
    {:ok, local} =
      (at + 2 * 3_600_000)
      |> DateTime.from_unix!(:millisecond)
      |> DateTime.shift_zone("America/Los_Angeles", Tz.TimeZoneDatabase)

    codex_error(
      "Visit the account usage page or try again at " <>
        Calendar.strftime(local, "%b %-d") <>
        ordinal(local.day) <> Calendar.strftime(local, ", %Y %-I:%M %p") <> "."
    )
  end

  defp ordinal(day) when day in [1, 21, 31], do: "st"
  defp ordinal(day) when day in [2, 22], do: "nd"
  defp ordinal(day) when day in [3, 23], do: "rd"
  defp ordinal(_day), do: "th"

  defp observe_in_txn(txn, correlation, session_key, host, at) do
    HarnessHealth.observe_in_txn(txn, %{
      correlation_id: correlation,
      harness: "codex",
      host: host,
      failure_class: "rate-limit-dead",
      evidence_kind: "authoritative-provider",
      session_key: session_key,
      assignment_id: nil,
      observed_at: at,
      cause: "usageLimitExceeded",
      principal: "process:test"
    })
  end

  defp observe_codex(db, correlation, session_key, reason, at) do
    assert {:ok, {incident, wake}} =
             DB.transaction(db, fn txn ->
               {_, incident} =
                 result = observe_in_txn(txn, correlation, session_key, "testhost", at)

               :ok =
                 RateLimitReset.schedule_in_txn(
                   txn,
                   %{harness: :codex, host: "testhost", session_key: session_key},
                   result,
                   reason,
                   at
                 )

               [[id, due_at]] =
                 Txn.q(
                   txn,
                   "SELECT wakeId,dueAt FROM wakes WHERE consumer='rate_limit_reset' AND prompt=?1",
                   [incident.observationId]
                 )

               {incident, %{wake_id: id, due_at: due_at}}
             end)

    {incident, wake}
  end

  # Opens (or joins) the Codex incident with a limit that names no reset, so
  # no reset wake exists.
  defp park_codex(db, correlation, session_key) do
    at = System.system_time(:millisecond)

    assert {:ok, {_, incident}} =
             DB.transaction(db, fn txn ->
               result = observe_in_txn(txn, correlation, session_key, "testhost", at)

               :ok =
                 RateLimitReset.schedule_in_txn(
                   txn,
                   %{harness: :codex, host: "testhost", session_key: session_key},
                   result,
                   codex_error("try again later."),
                   at
                 )

               result
             end)

    incident
  end

  defp resolve_codex(db, session_key, host) do
    HarnessHealth.resolve(db, %{
      correlation_id: "success-#{session_key}-#{System.unique_integer([:positive])}",
      harness: "codex",
      host: host,
      failure_class: "rate-limit-dead",
      session_key: session_key,
      assignment_id: nil,
      observed_at: System.system_time(:millisecond),
      cause: "normal turn delivered",
      principal: "process:test"
    })
  end

  defp lifecycle(db, kind, subject) do
    {:ok, rows} =
      DB.query(
        db,
        "SELECT detail FROM lifecycle_events WHERE kind=?1 AND subject=?2 ORDER BY id",
        [kind, subject]
      )

    Enum.map(rows, fn [detail] -> JSON.decode!(detail) end)
  end

  defp notices(db) do
    {:ok, rows} =
      DB.query(
        db,
        "SELECT sessionKey,prompt FROM wakes WHERE wakeId LIKE 'w_quota_unknown_effect_%' ORDER BY sessionKey"
      )

    Enum.map(rows, fn [session_key, prompt] -> %{session_key: session_key, prompt: prompt} end)
  end

  defp queued_messages(db) do
    {:ok, rows} =
      DB.query(db, "SELECT messageId FROM turns WHERE status='queued' ORDER BY seq")

    Enum.map(rows, &hd/1)
  end

  defp source_message(db, seq) do
    {:ok, [[message_id]]} = DB.query(db, "SELECT messageId FROM turns WHERE seq=?1", [seq])
    message_id
  end

  defp redelivery_sources(db) do
    {:ok, rows} =
      DB.query(db, "SELECT sourceTurnSeq FROM health_redelivery_attempts ORDER BY sourceTurnSeq")

    Enum.map(rows, &hd/1)
  end

  defp insert_legacy_redelivery!(db, session_key, seq) do
    {:ok, []} =
      DB.query(
        db,
        """
        INSERT INTO health_redelivery_attempts
          (idempotencyKey,sessionKey,sourceHarness,sourceHost,sourceMessageId,sourceTurnSeq,
           origin,prompt,roleFallback,failureClass,createdAt)
        SELECT 'legacy-' || seq, sessionKey, 'codex', 'testhost', messageId, seq,
               origin, prompt, 0, 'rate-limit-dead', 1
        FROM turns WHERE seq=?1 AND sessionKey=?2
        """,
        [seq, session_key]
      )
  end

  # Contract (c) R9a's post-activity evidence: the prompt was dispatched and
  # the turn recorded a tool call.
  defp started_work!(db, key, seq) do
    {:ok, _} =
      DB.query(
        db,
        """
        INSERT INTO turn_lifecycle_events
          (turnSeq, ordinal, at, eventKey, kind, stage, cause, principal, producerEventId)
        SELECT ?1, COALESCE(MAX(ordinal), 0) + 1, 1, 'dispatched-' || ?1, 'prompt_dispatched',
               'prompt', 'test', 'process:test', 'dispatched-' || ?1
        FROM turn_lifecycle_events WHERE turnSeq=?1
        """,
        [seq]
      )

    {:ok, _} =
      DB.query(
        db,
        """
        INSERT INTO tool_calls
          (id, sessionKey, turnSeq, afterMessageSeq, harnessToolCallId, title, kind, toolName,
           status, truncated, startedAt, endedAt, rowVersion)
        VALUES (?1, ?2, ?3, 0, 'tool-1', 'git push', 'execute', 'Bash', 'completed', '[]', 1, 2, 1)
        """,
        ["tc_#{System.unique_integer([:positive])}", key, seq]
      )
  end

  defp reset_error(reset_at) do
    reset = DateTime.from_unix!(reset_at, :millisecond)
    hour = rem(reset.hour + 11, 12) + 1
    period = if reset.hour < 12, do: "am", else: "pm"
    minute = reset.minute |> Integer.to_string() |> String.pad_leading(2, "0")
    %{@error | "message" => "Limit reached · resets #{hour}:#{minute}#{period} UTC"}
  end

  defp observe_reset(db, correlation, reason, at) do
    assert {:ok, {incident, wake}} =
             DB.transaction(db, fn txn ->
               result =
                 HarnessHealth.observe_in_txn(txn, %{
                   correlation_id: correlation,
                   harness: "claude",
                   host: "testhost",
                   failure_class: "rate-limit-dead",
                   evidence_kind: "authoritative-provider",
                   session_key: "k1",
                   assignment_id: nil,
                   observed_at: at,
                   cause: reason["message"],
                   principal: "process:test"
                 })

               {_, incident} = result

               RateLimitReset.schedule_in_txn(
                 txn,
                 %{harness: :claude, host: "testhost", session_key: "k1"},
                 result,
                 reason,
                 at
               )

               [[id, due_at]] =
                 Txn.q(
                   txn,
                   "SELECT wakeId,dueAt FROM wakes WHERE consumer='rate_limit_reset' AND prompt=?1",
                   [incident.observationId]
                 )

               {incident, %{wake_id: id, due_at: due_at}}
             end)

    {incident, wake}
  end

  defp enqueue(db, key, attrs \\ []) do
    {:ok, seq} =
      Ledger.enqueue(
        db,
        Map.merge(
          %{
            session_key: key,
            message_id: "message-#{System.unique_integer([:positive])}",
            origin: "user:tester",
            prompt: "queued work"
          },
          Map.new(attrs)
        )
      )

    seq
  end

  defp fail_turn(db, key, reason, opts \\ []) do
    seq = enqueue(db, key)
    {:ok, turn} = Ledger.claim_next(db, key, "test-owner")
    if Keyword.get(opts, :started_work, false), do: started_work!(db, key, seq)
    session = Org.get(db, key)

    {:ok, _} =
      DB.transaction(db, fn txn ->
        assert Ledger.finish_in_txn(txn, seq, "failed", reason["message"],
                 owner_lease: turn.owner_lease
               )

        HarnessHealth.observe_turn_failure_in_txn(
          txn,
          session,
          Map.put(turn, :session_key, key),
          :prompt,
          reason,
          defer_redelivery: Keyword.get(opts, :held, false)
        )
      end)

    seq
  end
end

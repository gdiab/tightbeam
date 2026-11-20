defmodule Tightbeam.ParkStrandingTest do
  @moduledoc """
  Quota-stranding contract v3, R11: a rate-limit park with no known reset that
  nothing releases within six hours sends exactly one blocker notice to the
  delivery owner and Main, and does nothing else.

  The six-hour clock is driven through the incident's opening time and the
  consumer's decision time, not by waiting.
  """
  use Tightbeam.TestCase, async: false

  alias Tightbeam.{
    DB,
    EventLog,
    HarnessHealth,
    HarnessProcess,
    Ledger,
    Model,
    Org,
    ParkStranding,
    QuotaRelease,
    Schema,
    Wakes
  }

  @owner "tester"
  @lead "agent:park-stranding:lead"
  @codex_key {:codex, "shared", "testhost"}
  @claude_key {:claude, "shared", "testhost"}
  # The typed Codex quota carrier (`data.codexErrorInfo`), as classified by
  # `HarnessHealth.classify_turn_failure/1`. It states no reset time.
  @codex_limit %{
    "code" => -32_603,
    "data" => %{
      "codexErrorInfo" => "usageLimitExceeded",
      "message" => "You've hit your usage limit."
    },
    "message" => "Internal error"
  }
  @claude_limit %{
    "code" => -32_603,
    "data" => %{"errorKind" => "rate_limit"},
    "message" => "Internal error: You've hit your weekly limit"
  }

  setup do
    db = :"park_stranding_#{System.unique_integer([:positive])}"
    start_supervised!({DB, path: ":memory:", name: db})
    :ok = Tightbeam.Schema.ensure_all(db)
    seed!(db)
    %{db: db}
  end

  test "a Codex park with no reset that stands for 6 hours sends one blocker notice to the delivery owner and Main",
       %{db: db} do
    incident = open_codex_park!(db)
    queued = enqueue(db, "c1", "asg_held")

    assert [stranding] = stranding_wakes(db)
    assert stranding.wake_id == episode_wake_id(db, incident)
    assert stranding.prompt == incident.id
    assert stranding.origin == "process:tightbeam"
    assert stranding.state == "pending"
    assert stranding.due_at == incident.opened_at + ParkStranding.after_ms()

    # One millisecond short of six hours nothing is decided or sent.
    assert {:ok, {:deferred, :before_deadline}} =
             ParkStranding.notify(db, stranding, stranding.due_at - 1)

    assert notices(db) == []
    assert stranding_wakes(db) |> hd() |> Map.fetch!(:state) == "pending"

    before = world(db)

    assert {:ok, {:notified, [_, _] = notice_ids}} =
             ParkStranding.notify(db, stranding, stranding.due_at)

    main = Org.personal_session_key(@owner)
    notices = notices(db)
    assert Enum.map(notices, & &1.wake_id) |> Enum.sort() == Enum.sort(notice_ids)
    assert Enum.map(notices, & &1.session_key) |> Enum.sort() == Enum.sort([@lead, main])

    for notice <- notices do
      assert notice.class == "blocker"
      assert notice.origin == "process:tightbeam"
      assert notice.consumer == "prompt"
      assert notice.state == "pending"
      assert notice.prompt =~ "The codex harness on testhost has been parked"
      assert notice.prompt =~ "rate-limit incident #{incident.id}"
      assert notice.prompt =~ "since #{iso(incident.opened_at)}"
      assert notice.prompt =~ "No reset time is known"
      assert notice.prompt =~ "nothing released it within 6 hours"
      assert notice.prompt =~ "- Codex c1 (c1)"
      assert notice.prompt =~ "- asg_held, held by Codex c1 (c1)"

      assert notice.prompt =~ HarnessHealth.repair_message("rate-limit-dead")

      assert notice.prompt =~
               "Otherwise the opener, an admin, the holder's delivery owner or Main explicitly resumes it after the limit clears."
    end

    assert [notified] = lifecycle(db, "rate_limit_park_stranding_notified")
    assert notified.subject == incident.id
    detail = JSON.decode!(notified.detail)
    assert detail["principal"] == "process:tightbeam"
    assert detail["heldSessions"] == ["c1"]
    assert detail["heldAssignments"] == ["asg_held"]
    assert lifecycle(db, "rate_limit_park_stranding_skipped") == []

    # The notices are the only automatic action: no turn was started, the
    # park and incident stand, and the assignment and its holder are unchanged.
    assert world(db) == before
    assert {:ok, [["queued"]]} = DB.query(db, "SELECT status FROM turns WHERE seq=?1", [queued])
    assert HarnessProcess.parked?(db, @codex_key)
    assert stranding_wakes(db) |> hd() |> Map.fetch!(:state) == "fired"
  end

  test "a known reset time sends no notice", %{db: db} do
    for key <- ["k1", "k2"], do: create_session(db, key, "claude")
    error = reset_error(System.system_time(:millisecond) + 7 * 3_600_000)
    fail_turn(db, "k1", error)
    fail_turn(db, "k2", error)
    assert HarnessProcess.parked?(db, @claude_key)
    incident = open_incident!(db, "claude")

    # Each failure stated the reset; both observations belong to the incident.
    assert {:ok, [[2]]} =
             DB.query(
               db,
               """
               SELECT COUNT(*) FROM wakes w JOIN harness_health_observations o ON o.id=w.prompt
               WHERE w.consumer='rate_limit_reset' AND w.state='pending' AND o.incidentId=?1
               """,
               [incident.id]
             )

    enqueue(db, "k1", nil)
    assert [stranding] = stranding_wakes(db)
    before = world(db)

    assert {:ok, {:skipped, "reset_known"}} =
             ParkStranding.notify(db, stranding, stranding.due_at)

    assert notices(db) == []
    assert [skipped] = lifecycle(db, "rate_limit_park_stranding_skipped")
    assert JSON.decode!(skipped.detail)["reason"] == "reset_known"
    assert lifecycle(db, "rate_limit_park_stranding_notified") == []
    assert world(db) == before
  end

  test "a stated reset that can no longer release the park does not count as known", %{db: db} do
    for key <- ["k1", "k2"], do: create_session(db, key, "claude")
    error = reset_error(System.system_time(:millisecond) + 7 * 3_600_000)
    fail_turn(db, "k1", error)
    fail_turn(db, "k2", error)
    assert HarnessProcess.parked?(db, @claude_key)
    incident = open_incident!(db, "claude")
    enqueue(db, "k1", nil)

    {:ok, resets} =
      DB.query(
        db,
        "SELECT wakeId FROM wakes WHERE consumer='rate_limit_reset' AND state='pending'"
      )

    assert length(resets) == 2

    assert {:ok, :ok} =
             DB.transaction(db, fn txn ->
               for [wake_id] <- resets do
                 assert Wakes.cancel_in_txn(txn, %{
                          wake_id: wake_id,
                          requester: %{kind: "process", id: "tightbeam:wake-scheduler"},
                          reason_kind: "consumer_unavailable",
                          causal_source: %{kind: "scheduler_delivery", id: wake_id},
                          outcome: %{kind: "no_replacement"}
                        })
               end

               :ok
             end)

    assert HarnessProcess.parked?(db, @claude_key)
    assert [stranding] = stranding_wakes(db)

    assert {:ok, {:notified, [_]}} = ParkStranding.notify(db, stranding, stranding.due_at)
    assert [notice] = notices(db)
    assert notice.session_key == Org.personal_session_key(@owner)
    assert notice.prompt =~ "The claude harness on testhost has been parked"
    assert notice.prompt =~ "rate-limit incident #{incident.id}"
    assert notice.prompt =~ "- Claude k1 (k1)"
  end

  test "an observed later success before 6 hours sends no notice", %{db: db} do
    incident = open_codex_park!(db)
    enqueue(db, "c1", "asg_held")

    assert {:resolved, _} =
             HarnessHealth.resolve(db, %{
               correlation_id: "park-stranding-success",
               harness: "codex",
               host: "testhost",
               failure_class: "rate-limit-dead",
               session_key: "c2",
               assignment_id: nil,
               observed_at: System.system_time(:millisecond),
               cause: "normal turn delivered",
               principal: "process:test"
             })

    refute HarnessProcess.parked?(db, @codex_key)
    assert [stranding] = stranding_wakes(db)

    assert {:ok, {:skipped, "incident_resolved"}} =
             ParkStranding.notify(db, stranding, stranding.due_at)

    assert notices(db) == []
    assert lifecycle(db, "rate_limit_park_stranding_notified") == []

    # A later limit is a new park episode with its own single check.
    fail_turn(db, "c1", @codex_limit, "asg_held")
    fail_turn(db, "c2", @codex_limit)
    assert HarnessProcess.parked?(db, @codex_key)
    next = open_incident!(db, "codex")
    refute next.id == incident.id

    assert [%{state: "fired"}, %{state: "pending"} = next_wake] =
             Enum.sort_by(stranding_wakes(db), &(&1.state == "pending"))

    assert next_wake.wake_id == episode_wake_id(db, next)
  end

  test "a park released before 6 hours with the incident still open sends no notice", %{db: db} do
    incident = open_codex_park!(db)
    enqueue(db, "c1", "asg_held")

    # An explicit resume is a named release (companion B2): it lifts the park,
    # and the incident stays open until a later success.
    resume!(db, incident)
    refute HarnessProcess.parked?(db, @codex_key)
    assert open_incident!(db, "codex").id == incident.id
    assert [stranding] = stranding_wakes(db)

    assert {:ok, {:skipped, "park_released"}} =
             ParkStranding.notify(db, stranding, stranding.due_at)

    assert notices(db) == []
    assert lifecycle(db, "rate_limit_park_stranding_notified") == []
  end

  test "a fence completion that is not a named release keeps the park, and the notice still goes out",
       %{db: db} do
    open_codex_park!(db)
    enqueue(db, "c1", "asg_held")

    # Companion B2: only named releases lift a quota park.
    :ok = HarnessProcess.complete_park(db, @codex_key)
    assert HarnessProcess.parked?(db, @codex_key)
    assert [stranding] = stranding_wakes(db)

    assert {:ok, {:notified, [_, _]}} = ParkStranding.notify(db, stranding, stranding.due_at)
  end

  test "a re-park after a release before 6 hours is a new episode: no early notice, one at its own 6 hours",
       %{db: db} do
    incident = open_codex_park!(db)
    enqueue(db, "c1", "asg_held")
    assert [first] = stranding_wakes(db)

    resume!(db, incident)
    # Companion B4: a limit met again parks the key anew under the same incident.
    fail_turn(db, "c2", @codex_limit)
    assert HarnessProcess.parked?(db, @codex_key)
    assert open_incident!(db, "codex").id == incident.id

    assert [^first, second] = stranding_wakes(db)
    assert second.wake_id == episode_wake_id(db, incident)
    refute second.wake_id == first.wake_id
    assert second.due_at >= first.due_at

    # The released episode's check sends nothing early...
    assert {:ok, {:skipped, "park_released"}} = ParkStranding.notify(db, first, first.due_at)
    assert notices(db) == []

    # ...and the new episode's check sends once, at its own six hours.
    assert {:ok, {:deferred, :before_deadline}} =
             ParkStranding.notify(db, second, second.due_at - 1)

    assert {:ok, {:notified, [_, _]}} = ParkStranding.notify(db, second, second.due_at)
    assert length(notices(db)) == 2
  end

  test "a re-park after the notice went out gets its own notice six hours later", %{db: db} do
    incident = open_codex_park!(db)
    enqueue(db, "c1", "asg_held")
    assert [first] = stranding_wakes(db)

    assert {:ok, {:notified, [_, _] = first_notices}} =
             ParkStranding.notify(db, first, first.due_at)

    resume!(db, incident)
    fail_turn(db, "c2", @codex_limit)
    assert HarnessProcess.parked?(db, @codex_key)

    assert [%{state: "fired"}, second] = stranding_wakes(db)
    assert second.wake_id == episode_wake_id(db, incident)

    assert {:ok, {:notified, [_, _] = second_notices}} =
             ParkStranding.notify(db, second, second.due_at)

    assert MapSet.disjoint?(MapSet.new(first_notices), MapSet.new(second_notices))
    assert length(notices(db)) == 4

    # The second episode's notices name when that park began, not the incident.
    for notice <- notices(db), notice.wake_id in second_notices do
      assert notice.prompt =~ "since #{iso(second.due_at - ParkStranding.after_ms())}"
    end

    assert length(lifecycle(db, "rate_limit_park_stranding_notified")) == 2
  end

  test "after a named release, a close fence completes: nothing is stranded and nothing is sent",
       %{db: db} do
    incident = open_codex_park!(db)
    enqueue(db, "c1", "asg_held")
    assert [stranding] = stranding_wakes(db)

    resume!(db, incident)
    {:ok, _} = HarnessProcess.begin_park(db, @codex_key)
    assert :ok = HarnessProcess.complete_park(db, @codex_key)
    refute HarnessProcess.parked?(db, @codex_key)

    assert {:ok, {:skipped, "park_released"}} =
             ParkStranding.notify(db, stranding, stranding.due_at)

    assert notices(db) == []
    assert stranding_wakes(db) |> length() == 1
  end

  test "a B4 re-park survives an adapter close and a boot reconcile, and is reported at its six hours",
       %{db: db} do
    incident = open_codex_park!(db)
    enqueue(db, "c1", "asg_held")

    resume!(db, incident)
    fail_turn(db, "c2", @codex_limit)
    assert [_first, second] = stranding_wakes(db)
    assert second.wake_id == episode_wake_id(db, incident)

    # The close joins the standing quota fence (same generation); its
    # completion and the boot reconcile keep the quota park.
    {:ok, _} = HarnessProcess.begin_park(db, @codex_key)
    assert :ok = HarnessProcess.complete_park(db, @codex_key)
    assert :ok = HarnessProcess.reconcile(db)
    assert HarnessProcess.parked?(db, @codex_key)
    assert second.wake_id == episode_wake_id(db, incident)

    assert {:ok, {:notified, [_, _]}} = ParkStranding.notify(db, second, second.due_at)
  end

  test "upgrade: a quota park standing before the fold survives the first boot, marked, and gets its check",
       %{db: db} do
    incident = open_codex_park!(db)
    enqueue(db, "c1", "asg_held")
    pi_key = {:pi, "shared", "testhost"}
    {:ok, _} = HarnessProcess.begin_park(db, pi_key)

    # The shape an earlier build leaves: no quotaIncidentId column, the stamp
    # before limit-fallback, and no stranding wake (that build had no R11).
    {:ok, _} = DB.query(db, "DELETE FROM wakes WHERE consumer='park_stranding'")
    :ok = DB.execute(db, "ALTER TABLE harness_park_fences DROP COLUMN quotaIncidentId")
    # The stamp before limit-fallback on the post-Part-A chain (contract v3.14 R11/C1).
    {:ok, _} = DB.query(db, "UPDATE schema_stamp SET shape='user-removal-v1-0114'")

    assert :ok = Schema.ensure_all(db)
    assert {:ok, [["limit-fallback-v1-0114"]]} = DB.query(db, "SELECT shape FROM schema_stamp")

    # The step marks the standing quota park from its key's open incident; a
    # fence with no open quota incident on its key stays unmarked.
    assert {:ok, [["codex:shared@testhost", marked], ["pi:shared@testhost", nil]]} =
             DB.query(
               db,
               "SELECT adapterKey, quotaIncidentId FROM harness_park_fences ORDER BY adapterKey"
             )

    assert marked == incident.id

    # The first boot's reconciliation keeps the quota park and completes the other.
    assert :ok = HarnessProcess.reconcile(db)
    assert HarnessProcess.parked?(db, @codex_key)
    refute HarnessProcess.parked?(db, pi_key)

    # T16 (migration contract v3.13): no release is recorded for the kept park.
    assert Enum.filter(lifecycle(db, "rate_limit_hold_released"), &(&1.subject == incident.id)) ==
             []

    # Start-up arms the carried-over park's stranding check, once.
    assert :ok = ParkStranding.arm_standing(db)
    assert :ok = ParkStranding.arm_standing(db)
    assert [stranding] = stranding_wakes(db)
    assert stranding.wake_id == episode_wake_id(db, incident)

    {:ok, [[requested_at]]} =
      DB.query(db, "SELECT requestedAt FROM harness_park_fences WHERE adapterKey=?1", [
        "codex:shared@testhost"
      ])

    assert stranding.due_at == requested_at + ParkStranding.after_ms()
    assert {:ok, {:notified, [_, _]}} = ParkStranding.notify(db, stranding, stranding.due_at)
  end

  test "a re-park of the same incident and a retried consumer do not duplicate the notice",
       %{db: db} do
    incident = open_codex_park!(db)
    enqueue(db, "c1", "asg_held")

    # A further limit observation attaches to the same open incident.
    fail_turn(db, "c2", @codex_limit)
    assert open_incident!(db, "codex").id == incident.id

    # The park hook running again for the same incident, later, adds nothing
    # and does not move the deadline.
    assert {:ok, :ok} =
             DB.transaction(db, fn txn ->
               HarnessProcess.begin_park_in_txn(txn, @codex_key)

               ParkStranding.schedule_in_txn(txn, incident.id, %{
                 harness: "codex",
                 host: "testhost",
                 session_key: "c2",
                 observed_at: incident.opened_at + 3_600_000
               })
             end)

    assert [stranding] = stranding_wakes(db)
    assert stranding.due_at == incident.opened_at + ParkStranding.after_ms()

    assert {:ok, {:notified, [_, _]}} = ParkStranding.notify(db, stranding, stranding.due_at)
    assert {:ok, :already_consumed} = ParkStranding.notify(db, stranding, stranding.due_at)

    assert {:ok, :already_consumed} =
             ParkStranding.notify(db, stranding, stranding.due_at + ParkStranding.after_ms())

    assert length(notices(db)) == 2
    assert length(lifecycle(db, "rate_limit_park_stranding_notified")) == 1
  end

  test "with no queued work under the park, only the affected owner's Main is told", %{db: db} do
    open_codex_park!(db)
    assert [stranding] = stranding_wakes(db)

    assert {:ok, {:notified, [_]}} = ParkStranding.notify(db, stranding, stranding.due_at)
    assert [notice] = notices(db)
    assert notice.session_key == Org.personal_session_key(@owner)
    assert notice.prompt =~ "No session of this harness on this host has queued work waiting."
  end

  @tag :tmp_dir
  test "a gateway restart before 6 hours still sends the notice once at 6 hours", %{
    tmp_dir: tmp
  } do
    db = :"park_stranding_restart_#{System.unique_integer([:positive])}"
    # A persistent database is admitted against an assembled payload.
    prepared = Tightbeam.GuardRuntimeFixture.prepare!(tmp, "schema_shape_runtime.exs")

    db_opts = [
      path: Path.join(prepared.base, "state.db"),
      name: db,
      guard_inputs: [],
      payload_root: prepared.payload
    ]

    spec = Supervisor.child_spec({DB, db_opts}, id: :file_db)
    start_supervised!(spec)
    :ok = Tightbeam.Schema.ensure_all(db)
    seed!(db)

    # Opened six hours ago less five seconds: the deadline is just ahead.
    opened_at = System.system_time(:millisecond) - ParkStranding.after_ms() + 5_000

    assert {:opened, incident} =
             HarnessHealth.observe(db, %{
               correlation_id: "park-stranding-restart",
               harness: "codex",
               host: "testhost",
               failure_class: "rate-limit-dead",
               evidence_kind: "authoritative-provider",
               session_key: "c1",
               assignment_id: "asg_held",
               observed_at: opened_at,
               cause: "usageLimitExceeded",
               principal: "process:test"
             })

    enqueue(db, "c1", "asg_held")
    assert [%{state: "pending"} = stranding] = stranding_wakes(db)
    assert stranding.due_at == opened_at + ParkStranding.after_ms()

    # The gateway goes down before the deadline and comes back.
    assert System.system_time(:millisecond) < stranding.due_at
    assert :ok = stop_supervised(:file_db)
    start_supervised!(spec)
    :ok = Tightbeam.Schema.ensure_all(db)
    assert [%{state: "pending"}] = stranding_wakes(db)
    assert notices(db) == []

    parent = self()

    start_supervised!(
      {Wakes,
       db: db,
       name: Tightbeam.WakeScheduler,
       deliver: fn _ -> :retry end,
       internal_consumers: %{
         "park_stranding" => fn wake ->
           result = ParkStranding.notify(db, wake)
           send(parent, {:stranding, System.system_time(:millisecond), result})
           result
         end
       }}
    )

    assert_receive {:stranding, fired_at, {:ok, {:notified, [_, _]}}}, 15_000
    assert :ok = stop_supervised(Wakes)
    assert fired_at >= stranding.due_at
    refute_received {:stranding, _, _}

    assert [%{state: "fired"}] = stranding_wakes(db)

    assert Enum.map(notices(db), & &1.session_key) |> Enum.sort() ==
             Enum.sort([@lead, Org.personal_session_key(@owner)])

    assert [notified] = lifecycle(db, "rate_limit_park_stranding_notified")
    assert notified.subject == incident.id
    assert HarnessProcess.parked?(db, @codex_key)
  end

  defp seed!(db) do
    # The owner is a real user: the delivery-owner rule resolves an
    # assignment's owner through `users`.
    {:ok, _} =
      DB.query(db, "INSERT INTO users (userId, isAdmin, createdAt) VALUES (?1, 0, 1)", [@owner])

    ensure_main_session(db, @owner)
    create_session(db, @lead, "claude")
    for key <- ["c1", "c2"], do: create_session(db, key, "codex")

    assert {:ok, []} =
             DB.query(
               db,
               """
               INSERT INTO assignments
                 (id,subject,holderKey,openedBySession,openedAt,state,holderHarness,holderProvider)
               VALUES ('asg_held','held work','c1',?1,1,'open','codex','openai')
               """,
               [@lead]
             )
  end

  defp create_session(db, key, "codex") do
    Org.create(db, %{
      session_key: key,
      display_name: "Codex #{key}",
      owner_user_id: @owner,
      origin: "user:#{@owner}",
      archetype: "coder",
      host: "testhost",
      harness: "codex",
      provider: "openai",
      model: Model.new("gpt-5")
    })
  end

  defp create_session(db, key, "claude") do
    Org.create(db, %{
      session_key: key,
      display_name: "Claude #{key}",
      owner_user_id: @owner,
      origin: "user:#{@owner}",
      archetype: "coder",
      host: "testhost",
      harness: "claude",
      provider: "anthropic",
      model: Model.new("claude-sonnet-5")
    })
  end

  # Two sessions' typed Codex quota failures open the shared incident and park
  # the key, as the terminal-turn path does in production.
  defp open_codex_park!(db) do
    fail_turn(db, "c1", @codex_limit, "asg_held")
    refute HarnessProcess.parked?(db, @codex_key)
    fail_turn(db, "c2", @codex_limit)
    assert HarnessProcess.parked?(db, @codex_key)
    open_incident!(db, "codex")
  end

  defp resume!(db, incident) do
    assert {:ok, :released} =
             DB.transaction(db, fn txn ->
               QuotaRelease.release_named_in_txn(txn, incident.id, "codex", "testhost", %{
                 cause: "explicit_resume",
                 actor: "user:#{@owner}"
               })
             end)
  end

  # The stranding wake id of the park episode now standing on the Codex key.
  defp episode_wake_id(db, incident) do
    {:ok, [[generation]]} =
      DB.query(db, "SELECT generation FROM harness_park_fences WHERE adapterKey=?1", [
        "codex:shared@testhost"
      ])

    ParkStranding.wake_id(incident.id, generation)
  end

  defp open_incident!(db, harness) do
    assert {:ok, [[id, opened_at]]} =
             DB.query(
               db,
               """
               SELECT id,openedAt FROM harness_health_incidents
               WHERE harness=?1 AND failureClass='rate-limit-dead' AND state='open'
               """,
               [harness]
             )

    %{id: id, opened_at: opened_at}
  end

  # Fails the session's next claimed turn; a turn already queued there is
  # claimed (and failed) ahead of the one enqueued here, which stays queued.
  defp fail_turn(db, key, reason, assignment_id \\ nil) do
    enqueue(db, key, assignment_id)
    {:ok, turn} = Ledger.claim_next(db, key, "test-owner")
    seq = turn.seq
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
          reason
        )
      end)
  end

  defp enqueue(db, key, assignment_id) do
    input = %{
      session_key: key,
      message_id: "message-#{System.unique_integer([:positive])}",
      origin: "user:#{@owner}",
      prompt: "queued work"
    }

    input = if assignment_id, do: Map.put(input, :assignment_id, assignment_id), else: input
    {:ok, seq} = Ledger.enqueue(db, input)
    seq
  end

  defp stranding_wakes(db) do
    {:ok, rows} =
      DB.query(
        db,
        """
        SELECT wakeId,sessionKey,origin,prompt,dueAt,state,targetGate FROM wakes
        WHERE consumer='park_stranding' ORDER BY rowid
        """
      )

    Enum.map(rows, fn [wake_id, session_key, origin, prompt, due_at, state, gate] ->
      %{
        wake_id: wake_id,
        session_key: session_key,
        origin: origin,
        prompt: prompt,
        due_at: due_at,
        state: state,
        target_gate: gate
      }
    end)
  end

  defp notices(db) do
    {:ok, rows} =
      DB.query(
        db,
        """
        SELECT wakeId,sessionKey,class,origin,consumer,state,prompt FROM wakes
        WHERE wakeId LIKE 'park-stranding-notice:%' ORDER BY rowid
        """
      )

    Enum.map(rows, fn [wake_id, session_key, class, origin, consumer, state, prompt] ->
      %{
        wake_id: wake_id,
        session_key: session_key,
        class: class,
        origin: origin,
        consumer: consumer,
        state: state,
        prompt: prompt
      }
    end)
  end

  defp lifecycle(db, kind), do: Enum.filter(EventLog.lifecycle_events(db), &(&1.kind == kind))

  # Everything an automatic action besides the notice could have touched.
  defp world(db) do
    query = fn sql ->
      {:ok, rows} = DB.query(db, sql)
      rows
    end

    %{
      turns: query.("SELECT seq,sessionKey,status FROM turns ORDER BY seq"),
      assignments: query.("SELECT id,holderKey,state,outcome FROM assignments ORDER BY id"),
      incidents: query.("SELECT id,state FROM harness_health_incidents ORDER BY id"),
      fences: query.("SELECT adapterKey FROM harness_park_fences ORDER BY adapterKey"),
      processes: query.("SELECT launchId,state FROM harness_processes ORDER BY launchId"),
      sessions: query.("SELECT sessionKey,state,harness,model FROM sessions ORDER BY sessionKey"),
      other_wakes:
        query.("""
        SELECT wakeId,state FROM wakes
        WHERE consumer<>'park_stranding' AND wakeId NOT LIKE 'park-stranding-notice:%'
        ORDER BY wakeId
        """)
    }
  end

  defp reset_error(reset_at) do
    reset = DateTime.from_unix!(reset_at, :millisecond)
    hour = rem(reset.hour + 11, 12) + 1
    period = if reset.hour < 12, do: "am", else: "pm"
    minute = reset.minute |> Integer.to_string() |> String.pad_leading(2, "0")
    %{@claude_limit | "message" => "Limit reached · resets #{hour}:#{minute}#{period} UTC"}
  end

  defp iso(ms), do: ms |> DateTime.from_unix!(:millisecond) |> DateTime.to_iso8601()
end

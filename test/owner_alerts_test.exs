defmodule Tightbeam.OwnerAlertsTest do
  @moduledoc """
  Owner alerts (b): usage-limit turn failures reach the alert owner through a
  gateway-originated Harklight send from Main, with no agent turn or wake.

  The Harklight Agent is the injected runner (`:harklight_send_runner`); it
  answers only for properties on our side of that seam. Time is injected:
  `OwnerAlerts.deliver_due/2` takes the clock as `:now`.
  """

  use Tightbeam.TestCase, async: false

  alias Tightbeam.{
    Archetypes,
    DB,
    Gateway,
    HarklightWakes,
    HarnessHealth,
    HarnessProcess,
    Ledger,
    Model,
    Org,
    OwnerAlerts,
    Placement
  }

  @owner "george"
  @minute 60_000
  @hour 3_600_000
  @codex_limit %{
    "code" => -32_603,
    "message" => "Internal error",
    "data" => %{
      "codexErrorInfo" => "usageLimitExceeded",
      "message" => "You've hit your usage limit."
    }
  }

  setup do
    db = :"owner_alerts_#{System.unique_integer([:positive])}"
    start_supervised!({DB, path: ":memory:", name: db})
    :ok = ensure_all_schemas(db)

    for user <- [@owner, "other"] do
      {:ok, _} =
        DB.query(db, "INSERT INTO users(userId,isAdmin,createdAt) VALUES(?1,0,1)", [user])
    end

    host = Placement.local_host_name()

    main =
      Org.create(db, %{
        session_key: Org.personal_session_key(@owner),
        display_name: "Main",
        kind: "main",
        is_built_in: true,
        owner_user_id: @owner,
        origin: "user:#{@owner}",
        archetype: "default",
        host: host,
        harness: "codex",
        provider: "openai",
        model: Model.new("gpt-5.6-sol")
      })

    %{db: db, main: main.session_key, host: host}
  end

  test "T1: a Codex usage-limit failure reaches Harklight from parked Main with no turn or wake",
       %{db: db, main: main, host: host} do
    enable(db)
    worker = session(db, "agent:george:worker", name: "Coder worker", host: host)

    # Main shares the parked Codex adapter: it cannot run a turn.
    assert {:ok, _} = HarnessProcess.begin_park(db, {:codex, "shared", host})
    assert HarnessProcess.parked?(db, {:codex, "shared", host})

    fail_turn(db, worker, @codex_limit)

    assert [%{kind: "usage-limit", session_key: ^worker, state: "pending"} = alert] =
             alerts(db)

    # Creating the alert gave Main neither a turn nor a wake.
    assert count(db, "SELECT count(*) FROM turns WHERE sessionKey=?1", [main]) == 0
    assert count(db, "SELECT count(*) FROM wakes WHERE sessionKey=?1", [main]) == 0

    before = record_counts(db)
    runner = runner(self(), fn {:execute, op} -> committed(op, "send") end)
    assert OwnerAlerts.deliver_due(db, now: alert.created_at, runner: runner) == 0

    assert_received {:harklight, ["send", "--prepare", "--op-id", op | _] = prepare}
    pairs = Enum.chunk_every(prepare, 2, 1, :discard)

    for pair <- [
          ["--session", "new"],
          ["--sender-id", "tightbeam-alerts"],
          ["--type", "fyi"],
          ["--kind", "blocker"],
          ["--importance", "high"],
          ["--title", "Coder worker hit a usage limit"]
        ] do
      assert pair in pairs
    end

    assert_received {:harklight, ["send", "--execute", "--op-id", ^op]}

    assert count(db, "SELECT count(*) FROM harklight_send_operations") == 1

    assert {:ok, [[^main, "bound", handle, message_id]]} =
             DB.query(
               db,
               "SELECT sessionKey,state,handle,messageId FROM harklight_send_operations WHERE opId=?1",
               [op]
             )

    assert [%{state: "sent", op_id: ^op, message_id: ^message_id}] = alerts(db)

    # Send and bind created, queued and changed no turn and no wake anywhere.
    assert record_counts(db) == before
    assert count(db, "SELECT count(*) FROM turns WHERE sessionKey=?1", [main]) == 0

    # George's Seen reaches Main through the ordinary subscription: one wake.
    seen =
      JSON.encode!(%{
        "kind" => "event",
        "session_handle" => handle,
        "event_id" => "1",
        "feed_cursor" => 1,
        "request" => %{"sender_id" => "tightbeam-alerts", "message_id" => message_id},
        "request_revision" => 1,
        "delivered" => false,
        "acted" => false,
        "entry" => %{"kind" => "terminal", "author" => "person", "content" => "Seen"}
      })

    assert :ok = HarklightWakes.capture_line(db, handle, seen)

    assert {:ok, [[^main, wake_id]]} =
             DB.query(db, "SELECT sessionKey,wakeId FROM wakes WHERE rowid>?1", [
               before.wake_rowid
             ])

    assert String.starts_with?(wake_id, "w_harklight_")
    assert count(db, "SELECT count(*) FROM turns") == before.turns
  end

  test "T2: only usage-limit failures of the owner's sessions create alerts", %{db: db} do
    enable(db)

    claude =
      session(db, "agent:george:claude",
        harness: "claude",
        provider: "anthropic",
        model: "claude-fable-5"
      )

    text = session(db, "agent:george:text")
    crash = session(db, "agent:george:crash")
    foreign = session(db, "agent:other:worker", owner: "other")

    fail_turn(db, claude, %{
      "code" => -32_603,
      "data" => %{"errorKind" => "rate_limit"},
      "message" => "Internal error: You've hit your session limit"
    })

    fail_turn(db, text, "usage limit reached")
    fail_turn(db, crash, :task_crash)
    fail_turn(db, foreign, @codex_limit)

    assert Enum.sort(Enum.map(alerts(db), & &1.session_key)) == Enum.sort([claude, text])
    assert Enum.all?(alerts(db), &(&1.kind == "usage-limit"))
  end

  test "T3: one alert per limit episode per session", %{db: db} do
    enable(db)
    s = session(db, "agent:george:s")
    t = session(db, "agent:george:t")

    first = fail_turn(db, s, @codex_limit)
    fail_turn(db, s, @codex_limit)
    assert Enum.map(alerts(db), & &1.dedupe_key) == ["usage-limit:#{s}:#{first}"]

    deliver_turn(db, s)
    second = fail_turn(db, s, @codex_limit)
    other = fail_turn(db, t, @codex_limit)

    assert Enum.sort(Enum.map(alerts(db), & &1.dedupe_key)) ==
             Enum.sort([
               "usage-limit:#{s}:#{first}",
               "usage-limit:#{s}:#{second}",
               "usage-limit:#{t}:#{other}"
             ])

    assert Enum.sort(Enum.map(alerts(db), & &1.turn_seq)) == Enum.sort([first, second, other])
  end

  describe "T4: the alert says what failed and what it was working on" do
    setup %{db: db} do
      System.put_env("TZ", "UTC")
      enable(db)
      :ok
    end

    test "Claude failure with a parsed reset, on an assignment", %{db: db} do
      claude =
        session(db, "agent:george:claude",
          name: "Coder — dispatch fix",
          harness: "claude",
          provider: "anthropic",
          model: "claude-fable-5"
        )

      :ok =
        DB.execute(db, """
        INSERT INTO work_items (id, title, ownerUserId, state, createdByUser, createdAt)
        VALUES ('wi_t4', 'Codex usage-limit failures strand session delivery', 'george', 'open', 'george', 1);
        INSERT INTO assignments (id, subject, holderKey, openedByUser, openedAt, state, workItemId)
        VALUES ('asg_t4', 'Implement quota park', '#{claude}', 'george', 2, 'open', 'wi_t4');
        """)

      reset_at = (div(System.system_time(:millisecond), @minute) + 120) * @minute
      seq = fail_turn(db, claude, claude_reset_error(reset_at), %{assignment_id: "asg_t4"})

      reset_wakes = "SELECT count(*) FROM wakes WHERE consumer='rate_limit_reset' AND dueAt=?1"
      assert count(db, reset_wakes, [reset_at]) == 1

      assert [alert] = alerts(db)
      assert alert.title == "Coder — dispatch fix hit a usage limit"
      body = alert.body

      for part <- [
            "Session 'Coder — dispatch fix' (#{claude})",
            "on Claude, provider anthropic, model claude-fable-5,",
            "hit a usage limit at #{utc_text(ended_at(db, seq))}.",
            "The limit resets at #{utc_text(reset_at)}.",
            "'Implement quota park' (asg_t4)",
            "'Codex usage-limit failures strand session delivery' (wi_t4)",
            "No reply needed. Tightbeam recorded the failure on this session."
          ] do
        assert body =~ part, "missing #{inspect(part)} in #{inspect(body)}"
      end

      refute body =~ "did not say"
      refute body =~ "direct conversation"
    end

    test "Codex failure without an assignment, on a session with none", %{db: db} do
      codex = session(db, "agent:george:codex", name: "Planner")
      seq = fail_turn(db, codex, @codex_limit)

      assert [alert] = alerts(db)
      assert alert.title == "Planner hit a usage limit"

      for part <- [
            "Session 'Planner' (#{codex})",
            "on Codex, provider openai, model gpt-5.6-sol,",
            "hit a usage limit at #{utc_text(ended_at(db, seq))}.",
            "The provider did not say when the limit resets.",
            "No assignment; this was a direct conversation.",
            "No reply needed. Tightbeam recorded the failure on this session."
          ] do
        assert alert.body =~ part, "missing #{inspect(part)} in #{inspect(alert.body)}"
      end

      refute alert.body =~ "resets at"
    end

    test "a turn without an assignment lists the session's open assignments", %{db: db} do
      codex = session(db, "agent:george:holder", name: "Holder")

      :ok =
        DB.execute(db, """
        INSERT INTO assignments (id, subject, holderKey, openedByUser, openedAt, state)
        VALUES ('asg_c1', 'First task', '#{codex}', 'george', 1, 'open'),
               ('asg_c2', 'Second task', '#{codex}', 'george', 2, 'open');
        """)

      fail_turn(db, codex, @codex_limit)
      assert [alert] = alerts(db)
      assert alert.body =~ "'First task' (asg_c1), 'Second task' (asg_c2)"
      refute alert.body =~ "direct conversation"
    end
  end

  test "T12: an uncertain send is settled by its own operation, never resent", %{
    db: db,
    main: main
  } do
    enable(db)
    fail_turn(db, session(db, "agent:george:worker"), @codex_limit)
    [alert] = alerts(db)
    markers = substrate_markers(db, main)

    runner =
      runner(self(), fn
        {:execute, op} -> unknown(op)
        {:retry, op} -> committed(op, "retry")
      end)

    assert OwnerAlerts.deliver_due(db, now: alert.created_at, runner: runner) == 0
    assert_received {:harklight, ["send", "--prepare", "--op-id", op | _]}
    assert_received {:harklight, ["send", "--execute", "--op-id", ^op]}

    assert [
             %{
               state: "pending",
               op_id: ^op,
               last_outcome: "outcome_unknown",
               next_attempt_at: next
             }
           ] = alerts(db)

    assert next == alert.created_at + 5 * @minute
    assert substrate_markers(db, main) == markers + 1

    assert OwnerAlerts.deliver_due(db, now: next - 1, runner: runner) == 0
    refute_received {:harklight, _}

    assert OwnerAlerts.deliver_due(db, now: next, runner: runner) == 0
    assert_received {:harklight, ["retry", "--op-id", ^op]}
    refute_received {:harklight, _}

    assert count(db, "SELECT count(*) FROM harklight_send_operations") == 1
    assert [%{state: "sent", op_id: ^op, message_id: message_id, attempts: 2}] = alerts(db)
    assert message_id == "msg-" <> op
  end

  test "A3: an undelivered alert adopts a later commit of its own uncertain send", %{db: db} do
    enable(db)
    fail_turn(db, session(db, "agent:george:worker"), @codex_limit)
    [alert] = alerts(db)

    uncertain =
      runner(self(), fn
        {:execute, op} -> unknown(op)
        {:retry, op} -> unknown(op)
      end)

    assert OwnerAlerts.deliver_due(db, now: alert.created_at, runner: uncertain) == 0
    assert_received {:harklight, ["send", "--prepare", "--op-id", op | _]}

    day = alert.created_at + 24 * 60 * @minute
    assert OwnerAlerts.deliver_due(db, now: day, runner: uncertain) == 0
    assert [%{state: "undelivered", op_id: ^op}] = alerts(db)

    # Boot recovery settles the pending send by its own op id.
    committing = runner(self(), fn {:retry, op} -> committed(op, "retry") end)
    :ok = Tightbeam.HarklightSend.recover_pending(db, runner: committing)
    assert_received {:harklight, ["retry", "--op-id", ^op]}

    assert OwnerAlerts.deliver_due(db, now: day + 1, runner: committing) == 0
    assert [%{state: "sent", op_id: ^op, message_id: message_id}] = alerts(db)
    assert message_id == "msg-" <> op
    assert count(db, "SELECT count(*) FROM harklight_send_operations") == 1
  end

  for variant <- [:send_fails, :origin_inactive] do
    @tag variant: variant
    test "T13: definite failures retry on schedule, then the alert is undelivered (#{variant})",
         %{db: db, main: main, variant: variant} do
      enable(db)
      fail_turn(db, session(db, "agent:george:worker"), @codex_limit)
      [alert] = alerts(db)
      created = alert.created_at

      if variant == :origin_inactive do
        :ok = DB.execute(db, "UPDATE sessions SET state='retired' WHERE sessionKey='#{main}'")
      end

      parent = self()

      runner = fn args ->
        send(parent, {:harklight, args})
        {"harklight-agent: network unreachable", 1}
      end

      markers = substrate_markers(db, main)
      before = record_counts(db)

      attempts_at = [0, 5 * @minute, 15 * @minute, @hour] ++ for(h <- 2..23, do: h * @hour)

      attempts_at
      |> Enum.zip(tl(attempts_at) ++ [24 * @hour])
      |> Enum.with_index(1)
      |> Enum.each(fn {{at, next}, attempt} ->
        assert OwnerAlerts.deliver_due(db, now: created + at - 1, runner: runner) == 0
        refute_received {:harklight, _}
        assert [%{attempts: previous}] = alerts(db)
        assert previous == attempt - 1

        assert OwnerAlerts.deliver_due(db, now: created + at, runner: runner) == 0

        if variant == :send_fails do
          assert_received {:harklight, ["send", "--prepare" | _]}
        end

        refute_received {:harklight, _}

        assert [%{state: "pending", attempts: ^attempt, next_attempt_at: due}] = alerts(db)
        assert due == created + next
      end)

      assert OwnerAlerts.deliver_due(db, now: created + 24 * @hour, runner: runner) == 0
      refute_received {:harklight, _}

      assert [%{state: "undelivered", attempts: 26, next_attempt_at: nil}] = alerts(db)
      assert count(db, "SELECT count(*) FROM harklight_send_operations") == 0

      assert [first, last] = substrate_marker_texts(db, main) |> Enum.drop(markers)
      assert first =~ "Harklight delivery of an owner alert failed"
      assert first =~ "still retrying"
      assert first =~ alert.title
      assert last =~ "undelivered"
      assert last =~ "stopped retrying"
      assert last =~ alert.title

      assert count(
               db,
               "SELECT count(*) FROM lifecycle_events WHERE kind='owner_alert_undelivered' AND subject=?1",
               [alert.alert_id]
             ) == 1

      # Attempts stop, and nothing ran a turn or filed a wake.
      assert OwnerAlerts.deliver_due(db, now: created + 30 * @hour, runner: runner) == 0
      refute_received {:harklight, _}
      assert record_counts(db) == before
    end
  end

  test "T14: the owner setting gates alerts and refuses unknown users by name", %{db: db} do
    config = config_handler(db)

    assert %{setting: "owner-alerts-user", value: nil} =
             config.(%{action: "get", setting: "owner-alerts-user"})

    fail_turn(db, session(db, "agent:george:unset"), @codex_limit)
    assert alerts(db) == []

    # "" is not a refusal: it clears the setting (§7.1, T18).
    for value <- ["nobody", nil] do
      assert %{code: "unknown_owner_alerts_user"} =
               config.(%{action: "set", setting: "owner-alerts-user", value: value})
    end

    assert Org.get_setting(db, "owner-alerts-user") == nil
    fail_turn(db, session(db, "agent:george:refused"), @codex_limit)
    assert alerts(db) == []

    assert %{setting: "owner-alerts-user", value: @owner, changed: true} =
             config.(%{action: "set", setting: "owner-alerts-user", value: @owner})

    enabled = session(db, "agent:george:enabled")
    fail_turn(db, enabled, @codex_limit)
    assert [%{session_key: ^enabled}] = alerts(db)
  end

  test "T14: a removed user is refused as the owner by name", %{db: db} do
    config = config_handler(db)

    {:ok, _} =
      DB.query(
        db,
        "INSERT INTO users(userId,isAdmin,createdAt,removedAt,removedBy) VALUES('gone',0,1,2,'admin')"
      )

    assert %{code: "user_removed"} =
             config.(%{action: "set", setting: "owner-alerts-user", value: "gone"})

    assert Org.get_setting(db, "owner-alerts-user") == nil
    fail_turn(db, session(db, "agent:george:refused-removed"), @codex_limit)
    assert alerts(db) == []
  end

  test "T14: an owner removed after it was set gets no new alerts; its unsent ones are withdrawn as off",
       %{db: db, main: main} do
    enable(db)

    # A pending alert after a definite failure, and one whose send is uncertain.
    failed_session = session(db, "agent:george:before-removal")
    fail_turn(db, failed_session, @codex_limit)
    failed = alert_for(db, failed_session)
    assert OwnerAlerts.deliver_due(db, now: failed.created_at, runner: failing(self())) == 0
    assert_received {:harklight, ["send", "--prepare" | _]}

    uncertain_session = session(db, "agent:george:uncertain-before-removal")
    fail_turn(db, uncertain_session, @codex_limit)
    uncertain = alert_for(db, uncertain_session)
    unknown_runner = runner(self(), fn {:execute, op} -> unknown(op) end)
    assert OwnerAlerts.deliver_due(db, now: uncertain.created_at, runner: unknown_runner) == 0
    assert_received {:harklight, ["send", "--prepare", "--op-id", uncertain_op | _]}
    assert_received {:harklight, ["send", "--execute", "--op-id", ^uncertain_op]}
    refute_received {:harklight, _}

    # A session of the owner with a turn under way. After the removal #622
    # refuses new rows for the user, so this is set up first.
    later = session(db, "agent:george:after-removal")
    later_session = Org.get(db, later)
    later_seq = enqueue(db, later, %{})
    assert {:ok, %{seq: ^later_seq} = later_turn} = Ledger.claim_next(db, later, "test-owner")

    # The owner is removed (#622 stamps removedAt; its own remove-user refuses
    # while the user still owns rows, so the state is written directly here).
    {:ok, _} =
      DB.query(db, "UPDATE users SET removedAt=?2, removedBy='admin' WHERE userId=?1", [
        @owner,
        System.system_time(:millisecond)
      ])

    # As if the setting were unset: a failure after the removal creates no alert.
    assert {:ok, _} =
             DB.transaction(db, fn txn ->
               assert Ledger.finish_in_txn(txn, later_seq, "failed", inspect(@codex_limit),
                        owner_lease: later_turn.owner_lease
                      )

               HarnessHealth.observe_turn_failure_in_txn(
                 txn,
                 later_session,
                 Map.put(later_turn, :session_key, later),
                 :prompt,
                 @codex_limit
               )
             end)

    assert alert_for(db, later) == nil

    due = max(failed.created_at, uncertain.created_at) + 5 * @minute

    both =
      runner(self(), fn
        {:execute, op} -> committed(op, "send")
        {:retry, op} -> committed(op, "retry")
      end)

    assert OwnerAlerts.deliver_due(db, now: due, runner: both) == 0

    # The uncertain send is still settled on its own op, from the owner's Main.
    assert_received {:harklight, ["retry", "--op-id", ^uncertain_op]}
    # The definite-failure alert gets no new operation; it is withdrawn as off.
    refute_received {:harklight, _}

    assert %{state: "withdrawn", attempts: 1, next_attempt_at: nil} =
             alert_for(db, failed_session)

    assert withdrawn_as(db, failed.alert_id) == "off"
    assert withdrawn_reasons(db, failed.alert_id) == ["alerts-off"]
    assert %{state: "sent", op_id: ^uncertain_op} = alert_for(db, uncertain_session)

    assert {:ok, [[^main]]} =
             DB.query(db, "SELECT sessionKey FROM harklight_send_operations WHERE opId=?1", [
               uncertain_op
             ])
  end

  test "T14: the stall threshold defaults to four hours and accepts only positive integers",
       %{db: db} do
    config = config_handler(db)

    assert %{setting: "owner-alert-stall-ms", value: 14_400_000} =
             config.(%{action: "get", setting: "owner-alert-stall-ms"})

    assert OwnerAlerts.stall_ms(db) == 14_400_000

    for value <- [0, -5, 1.5, "7200000", nil] do
      assert %{code: "invalid_owner_alert_stall_ms"} =
               config.(%{action: "set", setting: "owner-alert-stall-ms", value: value})
    end

    assert %{setting: "owner-alert-stall-ms", value: 7_200_000, changed: true} =
             config.(%{action: "set", setting: "owner-alert-stall-ms", value: 7_200_000})

    assert OwnerAlerts.stall_ms(db) == 7_200_000

    assert %{value: 7_200_000} = config.(%{action: "get", setting: "owner-alert-stall-ms"})
  end

  test "T18: clearing the owner setting turns usage-limit alerts off, and setting it turns them on",
       %{db: db, main: main} do
    start_supervised!({Tightbeam.Firehose.Hub, name: Tightbeam.Firehose.Hub})
    :ok = Tightbeam.Firehose.Hub.register(Tightbeam.Firehose.Hub, self(), %{mode: :all})
    config = config_handler(db)
    set = fn setting, value -> config.(%{action: "set", setting: setting, value: value}) end
    get = fn setting -> config.(%{action: "get", setting: setting}) end

    assert %{value: @owner, changed: true} = set.("owner-alerts-user", @owner)
    assert [%{"refs" => %{"key" => "owner-alerts-user"}}] = config_updates()

    # A caller without config authority is refused clearing exactly as setting.
    as_owner = config_handler(db, {:session, main})
    forbidden = as_owner.(%{action: "set", setting: "owner-alerts-user", value: "other"})
    assert %{code: "forbidden"} = forbidden
    assert as_owner.(%{action: "set", setting: "owner-alerts-user", value: ""}) == forbidden
    assert Org.get_setting(db, "owner-alerts-user") == @owner
    assert config_updates() == []

    # One usage-limit alert after a definite failure.
    failed_session = session(db, "agent:george:failed")
    fail_turn(db, failed_session, @codex_limit)
    failed = alert_for(db, failed_session)
    assert OwnerAlerts.deliver_due(db, now: failed.created_at, runner: failing(self())) == 0
    assert_received {:harklight, ["send", "--prepare" | _]}

    assert %{state: "pending", last_outcome: "failed", attempts: 1} =
             alert_for(db, failed_session)

    # One usage-limit alert whose send is uncertain.
    uncertain_session = session(db, "agent:george:uncertain")
    fail_turn(db, uncertain_session, @codex_limit)
    uncertain = alert_for(db, uncertain_session)
    unknown_runner = runner(self(), fn {:execute, op} -> unknown(op) end)
    assert OwnerAlerts.deliver_due(db, now: uncertain.created_at, runner: unknown_runner) == 0
    assert_received {:harklight, ["send", "--prepare", "--op-id", uncertain_op | _]}
    assert_received {:harklight, ["send", "--execute", "--op-id", ^uncertain_op]}
    refute_received {:harklight, _}

    assert %{state: "pending", last_outcome: "outcome_unknown", op_id: ^uncertain_op} =
             alert_for(db, uncertain_session)

    assert count(db, "SELECT count(*) FROM harklight_send_operations") == 1

    # Clear: the row is deleted and config.updated is published once.
    assert %{
             setting: "owner-alerts-user",
             value: nil,
             changed: true,
             config: %{"key" => "owner-alerts-user", "value" => nil} = cleared
           } = set.("owner-alerts-user", "")

    assert [%{"refs" => %{"key" => "owner-alerts-user"}, "payload" => ^cleared}] =
             config_updates()

    assert count(db, "SELECT count(*) FROM org_settings WHERE key='owner-alerts-user'") == 0
    assert %{setting: "owner-alerts-user", value: nil} = get.("owner-alerts-user")

    # A failure while alerts are off creates no row, then or later.
    off_session = session(db, "agent:george:off")
    fail_turn(db, off_session, @codex_limit)
    assert alert_for(db, off_session) == nil
    assert length(alerts(db)) == 2

    # Clearing again changes nothing and publishes nothing.
    assert %{setting: "owner-alerts-user", value: nil, changed: false} =
             set.("owner-alerts-user", "")

    assert config_updates() == []

    # At the next attempts: the definite failure is withdrawn without a new
    # operation; the uncertain send is settled on its own op id only.
    due = max(failed.created_at, uncertain.created_at) + 5 * @minute
    settle_runner = runner(self(), fn {:retry, op} -> committed(op, "retry") end)
    assert OwnerAlerts.deliver_due(db, now: due, runner: settle_runner) == 0
    assert_received {:harklight, ["retry", "--op-id", ^uncertain_op]}
    refute_received {:harklight, _}

    assert %{state: "withdrawn", next_attempt_at: nil, attempts: 1} =
             alert_for(db, failed_session)

    assert withdrawn_reasons(db, failed.alert_id) == ["alerts-off"]
    assert withdrawn_as(db, failed.alert_id) == "off"
    assert %{state: "sent", op_id: ^uncertain_op} = alert_for(db, uncertain_session)

    assert {:ok, [[^uncertain_op, ^main, "bound"]]} =
             DB.query(db, "SELECT opId, sessionKey, state FROM harklight_send_operations")

    # Withdrawn stays withdrawn; nothing is attempted again.
    assert OwnerAlerts.deliver_due(db, now: due + 24 * @hour, runner: settle_runner) == 0
    refute_received {:harklight, _}

    # The stall threshold clears back to its default.
    assert %{value: 7_200_000, changed: true} = set.("owner-alert-stall-ms", 7_200_000)
    assert [%{"refs" => %{"key" => "owner-alert-stall-ms"}}] = config_updates()

    assert %{setting: "owner-alert-stall-ms", value: nil, changed: true} =
             set.("owner-alert-stall-ms", "")

    assert [%{"refs" => %{"key" => "owner-alert-stall-ms"}, "payload" => %{"value" => nil}}] =
             config_updates()

    assert count(db, "SELECT count(*) FROM org_settings WHERE key='owner-alert-stall-ms'") == 0
    assert %{setting: "owner-alert-stall-ms", value: 14_400_000} = get.("owner-alert-stall-ms")
    assert OwnerAlerts.stall_ms(db) == 14_400_000
    assert %{changed: false} = set.("owner-alert-stall-ms", "")
    assert config_updates() == []

    # Any other setting refuses "" as it refuses any non-integer today.
    assert %{code: "invalid_priority"} = refused = set.("default-priority", "")
    assert set.("default-priority", "high") == refused
    assert Org.get_setting(db, "default-priority") == nil
    assert config_updates() == []

    # Setting the owner again: alerts resume for failures from then on.
    assert %{value: @owner, changed: true} = set.("owner-alerts-user", @owner)
    assert [%{"refs" => %{"key" => "owner-alerts-user"}}] = config_updates()

    resumed_session = session(db, "agent:george:resumed")
    fail_turn(db, resumed_session, @codex_limit)
    assert %{state: "pending", attempts: 0} = alert_for(db, resumed_session)
    assert owner_of(db, alert_for(db, resumed_session).alert_id) == @owner
    assert alert_for(db, off_session) == nil
  end

  test "T19: a changed owner withdraws or settles the old owner's alerts, never re-addressing them",
       %{db: db, main: main, host: host} do
    enable(db)

    {:ok, _} =
      DB.query(db, "INSERT INTO users(userId,isAdmin,createdAt) VALUES('alice',0,1)")

    alice_main =
      Org.create(db, %{
        session_key: Org.personal_session_key("alice"),
        display_name: "Alice Main",
        kind: "main",
        is_built_in: true,
        owner_user_id: "alice",
        origin: "user:alice",
        archetype: "default",
        host: host,
        harness: "codex",
        provider: "openai",
        model: Model.new("gpt-5.6-sol")
      }).session_key

    # A george alert pending after a definite failure.
    failed_session = session(db, "agent:george:failed")
    fail_turn(db, failed_session, @codex_limit)
    failed = alert_for(db, failed_session)
    assert OwnerAlerts.deliver_due(db, now: failed.created_at, runner: failing(self())) == 0
    assert_received {:harklight, ["send", "--prepare" | _]}

    # A george alert whose send is uncertain.
    uncertain_session = session(db, "agent:george:uncertain")
    fail_turn(db, uncertain_session, @codex_limit)
    uncertain = alert_for(db, uncertain_session)
    unknown_runner = runner(self(), fn {:execute, op} -> unknown(op) end)
    assert OwnerAlerts.deliver_due(db, now: uncertain.created_at, runner: unknown_runner) == 0
    assert_received {:harklight, ["send", "--prepare", "--op-id", uncertain_op | _]}
    assert_received {:harklight, ["send", "--execute", "--op-id", ^uncertain_op]}
    refute_received {:harklight, _}

    config = config_handler(db)

    assert %{setting: "owner-alerts-user", value: "alice", changed: true} =
             config.(%{action: "set", setting: "owner-alerts-user", value: "alice"})

    # A failure on an alice session alerts alice; one on a george session does not.
    alice_session = session(db, "agent:alice:worker", owner: "alice")
    fail_turn(db, alice_session, @codex_limit)
    george_session = session(db, "agent:george:late")
    fail_turn(db, george_session, @codex_limit)

    assert alert_for(db, george_session) == nil
    alice_alert = alert_for(db, alice_session)
    assert owner_of(db, alice_alert.alert_id) == "alice"
    assert alice_alert.origin == alice_main
    assert owner_of(db, failed.alert_id) == @owner
    assert owner_of(db, uncertain.alert_id) == @owner

    due = max(failed.created_at, uncertain.created_at) + 5 * @minute

    both =
      runner(self(), fn
        {:execute, op} -> committed(op, "send")
        {:retry, op} -> committed(op, "retry")
      end)

    assert OwnerAlerts.deliver_due(db, now: due, runner: both) == 0

    # The uncertain george send is settled on its own op id, from george's Main.
    assert_received {:harklight, ["retry", "--op-id", ^uncertain_op]}
    # Alice's alert is sent as a new operation from alice's Main.
    assert_received {:harklight, ["send", "--prepare", "--op-id", alice_op | _]}
    assert_received {:harklight, ["send", "--execute", "--op-id", ^alice_op]}
    # The definite-failure george alert gets no new operation.
    refute_received {:harklight, _}

    assert %{state: "withdrawn", attempts: 1, next_attempt_at: nil} =
             alert_for(db, failed_session)

    assert withdrawn_reasons(db, failed.alert_id) == ["owner-changed"]
    assert withdrawn_as(db, failed.alert_id) == "off"
    assert %{state: "sent", op_id: ^uncertain_op} = alert_for(db, uncertain_session)
    assert %{state: "sent", op_id: ^alice_op} = alert_for(db, alice_session)

    {:ok, ops} =
      DB.query(
        db,
        """
        SELECT a.ownerUserId, o.opId, o.sessionKey FROM harklight_send_operations o
        JOIN owner_alerts a ON a.opId=o.opId ORDER BY a.ownerUserId
        """
      )

    assert ops == [["alice", alice_op, alice_main], [@owner, uncertain_op, main]]
    assert count(db, "SELECT count(*) FROM harklight_send_operations") == 2
  end

  test "T20: an episode whose alert was withdrawn as off alerts once more after re-enable",
       %{db: db} do
    config = config_handler(db)
    set = fn value -> config.(%{action: "set", setting: "owner-alerts-user", value: value}) end
    sending = runner(self(), fn {:execute, op} -> committed(op, "send") end)

    assert %{value: @owner, changed: true} = set.(@owner)

    # Session S is in a limit episode; its alert is pending after a definite failure.
    s = session(db, "agent:george:s")
    first = fail_turn(db, s, @codex_limit)
    key = "usage-limit:#{s}:#{first}"
    assert [%{dedupe_key: ^key} = withdrawn] = alerts(db)
    assert OwnerAlerts.deliver_due(db, now: withdrawn.created_at, runner: failing(self())) == 0
    assert_received {:harklight, ["send", "--prepare" | _]}
    assert %{state: "pending", last_outcome: "failed"} = alert_for(db, s)

    # Clear: its next attempt withdraws it as off, with no new operation.
    assert %{value: nil, changed: true} = set.("")
    due = withdrawn.created_at + 5 * @minute
    assert OwnerAlerts.deliver_due(db, now: due, runner: sending) == 0
    refute_received {:harklight, _}
    assert [%{state: "withdrawn", attempts: 1}] = alerts(db)
    assert withdrawn_as(db, withdrawn.alert_id) == "off"
    assert withdrawn_reasons(db, withdrawn.alert_id) == ["alerts-off"]

    # First re-enable: S's next failure in the same episode alerts once, on
    # the same dedupeKey; the failure after it does not.
    assert %{value: @owner, changed: true} = set.(@owner)
    second = fail_turn(db, s, @codex_limit)
    others = fn -> Enum.reject(alerts(db), &(&1.alert_id == withdrawn.alert_id)) end

    assert [%{dedupe_key: ^key, turn_seq: ^second, state: "pending", attempts: 0} = realerted] =
             others.()

    fail_turn(db, s, @codex_limit)
    assert others.() == [realerted]

    assert OwnerAlerts.deliver_due(db, now: realerted.created_at, runner: sending) == 0
    assert_received {:harklight, ["send", "--prepare", "--op-id", op | _]}
    assert_received {:harklight, ["send", "--execute", "--op-id", ^op]}
    assert [%{state: "sent", op_id: ^op}] = others.()

    # Second cycle: the sent alert holds the episode, so nothing is alerted again.
    assert %{value: nil, changed: true} = set.("")
    assert %{value: @owner, changed: true} = set.(@owner)
    fail_turn(db, s, @codex_limit)
    assert OwnerAlerts.deliver_due(db, now: due + @hour, runner: sending) == 0
    refute_received {:harklight, _}

    assert [%{state: "sent", op_id: ^op}] = others.()
    assert %{state: "withdrawn"} = Enum.find(alerts(db), &(&1.alert_id == withdrawn.alert_id))
    assert length(alerts(db)) == 2
    assert count(db, "SELECT count(*) FROM harklight_send_operations") == 1
  end

  test "T15: an alert created before a restart is sent once after it", %{db: db} do
    enable(db)
    fail_turn(db, session(db, "agent:george:worker"), @codex_limit)
    assert [%{state: "pending", attempts: 0}] = alerts(db)

    runner = runner(self(), fn {:execute, op} -> committed(op, "send") end)

    # The boot pass finds the pending row; no event reached this process.
    start_supervised!({OwnerAlerts, db: db, send_runner: runner}, id: :first_boot)
    assert_receive {:harklight, ["send", "--prepare", "--op-id", op | _]}, 5_000
    assert_receive {:harklight, ["send", "--execute", "--op-id", ^op]}, 5_000
    :sys.get_state(OwnerAlerts)
    assert [%{state: "sent", op_id: ^op}] = alerts(db)

    :ok = stop_supervised!(:first_boot)
    start_supervised!({OwnerAlerts, db: db, send_runner: runner}, id: :second_boot)
    :sys.get_state(OwnerAlerts)

    refute_received {:harklight, _}
    assert count(db, "SELECT count(*) FROM harklight_send_operations") == 1
    assert [%{state: "sent", op_id: ^op, attempts: 1}] = alerts(db)
  end

  test "T15: a restart after an uncertain send settles the same operation", %{db: db} do
    enable(db)
    fail_turn(db, session(db, "agent:george:worker"), @codex_limit)
    [alert] = alerts(db)

    runner =
      runner(self(), fn
        {:execute, op} -> unknown(op)
        {:retry, op} -> committed(op, "retry")
      end)

    assert OwnerAlerts.deliver_due(db, now: alert.created_at, runner: runner) == 0
    assert_received {:harklight, ["send", "--prepare", "--op-id", op | _]}
    assert_received {:harklight, ["send", "--execute", "--op-id", ^op]}

    # A boot before the next attempt is due neither resends nor settles.
    start_supervised!({OwnerAlerts, db: db, send_runner: runner})
    :sys.get_state(OwnerAlerts)
    refute_received {:harklight, _}
    :ok = stop_supervised!(OwnerAlerts)

    [%{next_attempt_at: next}] = alerts(db)
    assert OwnerAlerts.deliver_due(db, now: next, runner: runner) == 0
    assert_received {:harklight, ["retry", "--op-id", ^op]}
    refute_received {:harklight, _}
    assert count(db, "SELECT count(*) FROM harklight_send_operations") == 1
    assert [%{state: "sent", op_id: ^op}] = alerts(db)
  end

  test "the alert table is created once and its stamped shape is validated", %{db: db} do
    assert {:ok, [[0, "owner-alerts-v1-0114", applied]]} =
             DB.query(db, "SELECT id, shape, appliedAt FROM owner_alert_migration")

    assert is_integer(applied)
    assert :ok = OwnerAlerts.ensure_schema(db)

    # The dedupe index is partial: a full unique index is a different shape.
    dedupe = "CREATE UNIQUE INDEX owner_alerts_dedupe ON owner_alerts (dedupeKey)"
    partial = dedupe <> " WHERE NOT (state = 'withdrawn' AND withdrawnAs = 'off')"
    :ok = DB.execute(db, "DROP INDEX owner_alerts_dedupe; " <> dedupe)

    assert_raise Tightbeam.Schema.ShapeError, ~r/incompatible_owner_alerts_schema_object/, fn ->
      OwnerAlerts.ensure_schema(db)
    end

    :ok = DB.execute(db, "DROP INDEX owner_alerts_dedupe; " <> partial)
    assert :ok = OwnerAlerts.ensure_schema(db)

    :ok = DB.execute(db, "DROP INDEX owner_alerts_pending")

    assert_raise Tightbeam.Schema.ShapeError, ~r/incompatible_owner_alerts_schema_object/, fn ->
      OwnerAlerts.ensure_schema(db)
    end
  end

  ## Fixtures

  defp enable(db), do: :ok = Org.put_setting(db, "owner-alerts-user", @owner)

  defp session(db, key, opts \\ []) do
    owner = Keyword.get(opts, :owner, @owner)

    Org.create(db, %{
      session_key: key,
      display_name: Keyword.get(opts, :name, key),
      owner_user_id: owner,
      origin: "user:#{owner}",
      archetype: "coder",
      host: Keyword.get(opts, :host, "testhost"),
      harness: Keyword.get(opts, :harness, "codex"),
      provider: Keyword.get(opts, :provider, "openai"),
      model: Model.new(Keyword.get(opts, :model, "gpt-5.6-sol"))
    }).session_key
  end

  defp enqueue(db, key, attrs) do
    {:ok, seq} =
      Ledger.enqueue(
        db,
        Map.merge(
          %{
            session_key: key,
            message_id: "message-#{System.unique_integer([:positive])}",
            origin: "user:#{@owner}",
            prompt: "work"
          },
          attrs
        )
      )

    seq
  end

  # The failed-turn transaction: the terminal row and the harness-health
  # observation commit together, as the gateway's failed-turn path does.
  defp fail_turn(db, key, reason, attrs \\ %{}) do
    seq = enqueue(db, key, attrs)
    assert {:ok, %{seq: ^seq} = turn} = Ledger.claim_next(db, key, "test-owner")
    session = Org.get(db, key)

    assert {:ok, _} =
             DB.transaction(db, fn txn ->
               assert Ledger.finish_in_txn(txn, seq, "failed", inspect(reason),
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

    seq
  end

  defp deliver_turn(db, key) do
    seq = enqueue(db, key, %{})
    assert {:ok, %{seq: ^seq} = turn} = Ledger.claim_next(db, key, "test-owner")

    assert {:ok, true} =
             DB.transaction(db, fn txn ->
               Ledger.finish_in_txn(txn, seq, "delivered", nil, owner_lease: turn.owner_lease)
             end)

    seq
  end

  defp claude_reset_error(reset_at) do
    reset = DateTime.from_unix!(reset_at, :millisecond)
    hour = rem(reset.hour + 11, 12) + 1
    period = if reset.hour < 12, do: "am", else: "pm"
    minute = reset.minute |> Integer.to_string() |> String.pad_leading(2, "0")

    %{
      "code" => -32_603,
      "data" => %{"errorKind" => "rate_limit"},
      "message" =>
        "Internal error: You've hit your session limit · resets #{hour}:#{minute}#{period} UTC"
    }
  end

  defp utc_text(ms),
    do: ms |> DateTime.from_unix!(:millisecond) |> Calendar.strftime("%b %-d, %Y %-I:%M %p UTC")

  defp ended_at(db, seq), do: count(db, "SELECT endedAt FROM turns WHERE seq=?1", [seq])

  defp config_handler(db, principal \\ {:process, "test"}) do
    base_dir =
      Path.join(System.tmp_dir!(), "tightbeam-owner-alerts-#{System.unique_integer([:positive])}")

    on_exit(fn -> File.rm_rf!(base_dir) end)
    Archetypes.load!(base_dir)
    config = Gateway.handlers(%{db: db, base_dir: base_dir, wake_tick_ms: 1_000})["config"]

    origin =
      case principal do
        {:process, name} -> "process:" <> name
        {:session, key} -> "session:" <> key
      end

    fn params -> config.(%{principal: principal, origin: origin, params: params}) end
  end

  # The config.updated notices the firehose published since the last call.
  defp config_updates do
    :sys.get_state(Tightbeam.Firehose.Hub)
    drain_config_updates([])
  end

  defp drain_config_updates(notices) do
    receive do
      {:firehose_notice, %{"class" => "config.updated"} = notice} ->
        drain_config_updates([notice | notices])
    after
      0 -> Enum.reverse(notices)
    end
  end

  # The Harklight Agent side of the seam. Prepare echoes the requested message
  # under handle = op id; execute and retry answer as `outcome` says.
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

  # Every Harklight call fails definitely: nothing is prepared or delivered.
  defp failing(parent) do
    fn args ->
      send(parent, {:harklight, args})
      {"harklight-agent: network unreachable", 1}
    end
  end

  defp unknown(op), do: {JSON.encode!(%{kind: "outcome_unknown", op_id: op}) <> "\n", 7}

  defp frame(value), do: {JSON.encode!(value) <> "\n", 0}

  defp flag(args, name), do: args |> Enum.drop_while(&(&1 != name)) |> Enum.at(1)

  ## Reads

  defp alerts(db) do
    {:ok, rows} =
      DB.query(
        db,
        """
        SELECT alertId, kind, dedupeKey, sessionKey, turnSeq, title, body, state, createdAt,
               opId, messageId, attempts, lastOutcome, nextAttemptAt, originSessionKey
        FROM owner_alerts ORDER BY createdAt, alertId
        """
      )

    Enum.map(rows, fn [
                        id,
                        kind,
                        dedupe_key,
                        session_key,
                        turn_seq,
                        title,
                        body,
                        state,
                        created_at,
                        op_id,
                        message_id,
                        attempts,
                        last_outcome,
                        next_attempt_at,
                        origin
                      ] ->
      %{
        alert_id: id,
        kind: kind,
        dedupe_key: dedupe_key,
        session_key: session_key,
        turn_seq: turn_seq,
        title: title,
        body: body,
        state: state,
        created_at: created_at,
        op_id: op_id,
        message_id: message_id,
        attempts: attempts,
        last_outcome: last_outcome,
        next_attempt_at: next_attempt_at,
        origin: origin
      }
    end)
  end

  defp alert_for(db, session_key), do: Enum.find(alerts(db), &(&1.session_key == session_key))

  defp owner_of(db, alert_id),
    do: count(db, "SELECT ownerUserId FROM owner_alerts WHERE alertId=?1", [alert_id])

  defp withdrawn_reasons(db, alert_id) do
    {:ok, rows} =
      DB.query(
        db,
        "SELECT detail FROM lifecycle_events WHERE kind='owner_alert_withdrawn' AND subject=?1",
        [alert_id]
      )

    Enum.map(rows, fn [detail] -> JSON.decode!(detail)["reason"] end)
  end

  defp withdrawn_as(db, alert_id),
    do: count(db, "SELECT withdrawnAs FROM owner_alerts WHERE alertId=?1", [alert_id])

  defp record_counts(db) do
    %{
      turns: count(db, "SELECT count(*) FROM turns"),
      turn_seq: count(db, "SELECT COALESCE(MAX(seq),0) FROM turns"),
      wakes: count(db, "SELECT count(*) FROM wakes"),
      wake_rowid: count(db, "SELECT COALESCE(MAX(rowid),0) FROM wakes"),
      pending_wakes: count(db, "SELECT count(*) FROM wakes WHERE state='pending'")
    }
  end

  defp substrate_markers(db, session_key),
    do:
      count(
        db,
        "SELECT count(*) FROM messages WHERE sessionKey=?1 AND messageType='substrate'",
        [session_key]
      )

  defp substrate_marker_texts(db, session_key) do
    {:ok, rows} =
      DB.query(
        db,
        "SELECT content FROM messages WHERE sessionKey=?1 AND messageType='substrate' ORDER BY seq",
        [session_key]
      )

    Enum.map(rows, &hd/1)
  end

  defp count(db, sql, params \\ []) do
    {:ok, [[value]]} = DB.query(db, sql, params)
    value
  end
end

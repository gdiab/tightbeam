defmodule Tightbeam.OwnerAlertsTest do
  @moduledoc """
  Owner alerts: usage-limit turn failures (b) and four-hour stalls (a) reach
  the alert owner through a gateway-originated Harklight send from Main, with
  no agent turn or wake.

  The Harklight Agent is the injected runner (`:harklight_send_runner`); it
  answers only for properties on our side of that seam. Time is injected:
  `OwnerAlerts.deliver_due/2` and `OwnerAlerts.detect_stalls/2` take the clock
  as `:now`, and stall fixtures write their record times directly.
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
    Placement,
    Supervision,
    Wakes,
    WorkItems
  }

  @owner "george"
  @minute 60_000
  @hour 3_600_000
  @stall 4 * @hour
  @codex_limit %{
    "code" => -32_603,
    "message" => "Internal error",
    "data" => %{
      "codexErrorInfo" => "usageLimitExceeded",
      "message" => "You've hit your usage limit."
    }
  }

  setup do
    db = world_db()
    %{db: db, main: Org.personal_session_key(@owner), host: Placement.local_host_name()}
  end

  # One database with the two users and the owner's Main placed on this host.
  defp world_db do
    db = :"owner_alerts_#{System.unique_integer([:positive])}"
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
      host: Placement.local_host_name(),
      harness: "codex",
      provider: "openai",
      model: Model.new("gpt-5.6-sol")
    })

    db
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

  ## (a) four-hour stall

  test "T5: an item whose only assignment has a running turn alerts at the threshold",
       %{db: db} do
    enable(db)
    holder = session(db, "agent:george:runner", name: "Runner")
    t0 = now_ms() - 2 * @stall
    item(db, "wi_t5", title: "Ship the parser")
    assignment(db, "asg_t5", "wi_t5", holder, t0, subject: "Write the parser")

    # A live turn is not progress and does not quiet the item.
    seq = enqueue(db, holder, %{assignment_id: "asg_t5"})
    assert {:ok, %{seq: ^seq}} = Ledger.claim_next(db, holder, "test-owner")

    assert %{created: 0, next_at: next} = OwnerAlerts.detect_stalls(db, now: t0 + @stall - 1)
    assert next == t0 + @stall
    assert stall_alerts(db) == []

    before = record_counts(db)
    assert %{created: 1} = OwnerAlerts.detect_stalls(db, now: t0 + @stall)

    assert [%{work_item_id: "wi_t5", anchor_at: ^t0, state: "pending"} = alert] =
             stall_alerts(db)

    assert alert.dedupe_key == "stall:wi_t5:#{t0}"
    assert alert.title == "No progress for 4h: Ship the parser"
    assert alert.body =~ "'Write the parser' (asg_t5), held by 'Runner'"
    assert alert.body =~ "running a turn since"
    assert alert.created_at == t0 + @stall

    # Creating the alert queued, started and changed no turn and no wake.
    assert record_counts(db) == before
  end

  test "T5: the process alerts at the predicted stall time with no further event",
       %{db: db} do
    enable(db)
    holder = session(db, "agent:george:idle")
    # The stall comes due a few seconds after boot; the boot pass must not
    # find it, so only the timer it arms can create the alert.
    t0 = now_ms() - @stall + 3_000
    item(db, "wi_timer")
    assignment(db, "asg_timer", "wi_timer", holder, t0)

    runner = runner(self(), fn {:execute, op} -> committed(op, "send") end)
    start_supervised!({OwnerAlerts, db: db, send_runner: runner})
    :sys.get_state(OwnerAlerts)
    assert stall_alerts(db) == []

    assert_receive {:harklight, ["send", "--prepare", "--op-id", op | _]}, 15_000
    assert_receive {:harklight, ["send", "--execute", "--op-id", ^op]}, 5_000
    :sys.get_state(OwnerAlerts)

    assert [%{work_item_id: "wi_timer", state: "sent", op_id: ^op, created_at: created}] =
             stall_alerts(db)

    assert created >= t0 + @stall
    assert created < t0 + @stall + 10 * @minute
  end

  test "S7: a stall that came due while the gateway was down alerts at boot", %{db: db} do
    enable(db)
    holder = session(db, "agent:george:idle")
    t0 = now_ms() - 3 * @stall
    item(db, "wi_down")
    assignment(db, "asg_down", "wi_down", holder, t0)

    runner = runner(self(), fn {:execute, op} -> committed(op, "send") end)
    start_supervised!({OwnerAlerts, db: db, send_runner: runner})
    assert_receive {:harklight, ["send", "--prepare", "--op-id", op | _]}, 5_000
    :sys.get_state(OwnerAlerts)

    assert [%{work_item_id: "wi_down", anchor_at: ^t0, state: "sent", op_id: ^op}] =
             stall_alerts(db)
  end

  test "S7: enabling the alert owner alerts an already-stalled item at once", %{db: db} do
    holder = session(db, "agent:george:idle")
    t0 = now_ms() - 3 * @stall
    item(db, "wi_enable")
    assignment(db, "asg_enable", "wi_enable", holder, t0)

    runner = runner(self(), fn {:execute, op} -> committed(op, "send") end)
    start_supervised!({OwnerAlerts, db: db, send_runner: runner})
    :sys.get_state(OwnerAlerts)
    assert stall_alerts(db) == []

    # With alerts off the process holds no timer; only the setting's own
    # commit can make it look again.
    config = config_handler(db)

    assert %{changed: true} =
             config.(%{action: "set", setting: "owner-alerts-user", value: @owner})

    :sys.get_state(OwnerAlerts)
    assert [%{work_item_id: "wi_enable", state: "sent"}] = stall_alerts(db)
    assert_received {:harklight, ["send", "--prepare" | _]}
  end

  test "S7: reopening an iceboxed stalled item alerts at once", %{db: db} do
    enable(db)
    holder = session(db, "agent:george:idle")
    t0 = now_ms() - 3 * @stall
    item(db, "wi_reopen", state: "iceboxed")
    assignment(db, "asg_reopen", "wi_reopen", holder, t0)

    runner = runner(self(), fn {:execute, op} -> committed(op, "send") end)
    start_supervised!({OwnerAlerts, db: db, send_runner: runner})
    :sys.get_state(OwnerAlerts)
    assert stall_alerts(db) == []

    assert %{workItem: %{state: "open"}} =
             WorkItems.__handle__(db, "work-item-reopen", %{
               verb: "work-item-reopen",
               principal: {:user, @owner},
               origin: "user:#{@owner}",
               session_key: nil,
               params: %{work_item_id: "wi_reopen"}
             })

    :sys.get_state(OwnerAlerts)
    assert [%{work_item_id: "wi_reopen", anchor_at: ^t0}] = stall_alerts(db)
  end

  test "T6: held or waiting items never alert", %{db: db} do
    enable(db)
    holder = session(db, "agent:george:holder")
    other = session(db, "agent:george:other")
    t0 = now_ms() - 20 * @stall

    for id <- ~w(wi_c1 wi_c2_fact wi_c2_dep wi_c3 wi_c4 wi_control), do: item(db, id)

    # C1: a standing cannot-proceed.
    assignment(db, "asg_c1", "wi_c1", holder, t0)
    cannot_proceed(db, "asg_c1", holder, t0)

    # C2: a condition wake, and a dependency wait, naming the assignment.
    assignment(db, "asg_c2_fact", "wi_c2_fact", holder, t0)
    wait_on(db, "asg_c2_fact", holder, t0, condition_kind: "pr-merged")
    assignment(db, "asg_c2_dep", "wi_c2_dep", holder, t0)
    wait_on(db, "asg_c2_dep", holder, t0, wait_mode: "dependency")

    # C3: an open decision request on the assignment.
    assignment(db, "asg_c3", "wi_c3", holder, t0)
    decision_request(db, "asg_c3", holder, other, t0)

    # C4 (0.1.14 form): the holder delegated a child on the same item, opened
    # no earlier than the covered assignment; the child itself waits on a fact.
    assignment(db, "asg_c4", "wi_c4", holder, t0)
    assignment(db, "asg_c4_child", "wi_c4", other, t0, opened_by_session: holder)
    wait_on(db, "asg_c4_child", other, t0, condition_kind: "pr-merged")

    assignment(db, "asg_control", "wi_control", holder, t0)

    for k <- 1..10, do: OwnerAlerts.detect_stalls(db, now: t0 + k * @stall)

    assert Enum.map(stall_alerts(db), & &1.work_item_id) == ["wi_control"]
  end

  test "T7: the alert lists only uncovered assignments and counts the covered ones",
       %{db: db} do
    enable(db)
    idle = session(db, "agent:george:idle", name: "Idle holder")
    waiting = session(db, "agent:george:waiting", name: "Waiting holder")
    t0 = now_ms() - 2 * @stall
    item(db, "wi_t7", title: "Mixed item")
    assignment(db, "asg_idle", "wi_t7", idle, t0, subject: "Idle work")
    assignment(db, "asg_wait", "wi_t7", waiting, t0, subject: "Waiting work")
    wait_on(db, "asg_wait", waiting, t0, condition_kind: "pr-merged")

    OwnerAlerts.detect_stalls(db, now: t0 + @stall)

    assert [%{work_item_id: "wi_t7", body: body}] = stall_alerts(db)
    assert body =~ "- 'Idle work' (asg_idle), held by 'Idle holder'"
    refute body =~ "Waiting work"
    refute body =~ "Waiting holder"
    assert body =~ "1 other open assignment is held or waiting."
  end

  test "S8: the body names the last progress event and each holder's visible state",
       %{db: db} do
    System.put_env("TZ", "UTC")
    enable(db)

    runner_key = session(db, "agent:george:running", name: "Runner")
    queued = session(db, "agent:george:queued", name: "Queuer")

    paused =
      session(db, "agent:george:paused",
        name: "Pauser",
        harness: "claude",
        provider: "anthropic",
        model: "claude-fable-5"
      )

    idle = session(db, "agent:george:idle", name: "Idler")

    t0 = now_ms() - 3 * @stall
    item(db, "wi_s8", title: "Content item")
    assignment(db, "asg_running", "wi_s8", runner_key, t0, subject: "Running work")
    assignment(db, "asg_queued", "wi_s8", queued, t0, subject: "Queued work")
    assignment(db, "asg_paused", "wi_s8", paused, t0, subject: "Paused work")
    assignment(db, "asg_idle", "wi_s8", idle, t0, subject: "Idle work")

    t1 = t0 + @hour
    attest(db, "asg_running", runner_key, t1)

    seq = enqueue(db, runner_key, %{})
    assert {:ok, %{seq: ^seq}} = Ledger.claim_next(db, runner_key, "test-owner")
    started = count(db, "SELECT startedAt FROM turns WHERE seq=?1", [seq])
    enqueue(db, queued, %{})
    pause(db, paused)
    ended = ended_at(db, deliver_turn(db, idle))

    OwnerAlerts.detect_stalls(db, now: t1 + @stall)

    assert [%{title: title, body: body, anchor_at: ^t1}] = stall_alerts(db)
    assert title == "No progress for 4h: Content item"

    for part <- [
          "Work item wi_s8.",
          "Last progress: a progress attest at #{utc_text(t1)} (4h 0m ago) on 'Running work' (asg_running), filed by 'Runner'.",
          "- 'Running work' (asg_running), held by 'Runner' on Codex, model gpt-5.6-sol: running a turn since #{utc_text(started)}.",
          "- 'Queued work' (asg_queued), held by 'Queuer' on Codex, model gpt-5.6-sol: queued.",
          "- 'Paused work' (asg_paused), held by 'Pauser' on Claude, model claude-fable-5: its harness is paused by a usage limit.",
          "- 'Idle work' (asg_idle), held by 'Idler' on Codex, model gpt-5.6-sol: idle since #{utc_text(ended)}.",
          "No other open assignments are held or waiting.",
          "No reply needed. This alert repeats only if the work moves and then stalls again."
        ] do
      assert body =~ part, "missing #{inspect(part)} in #{inspect(body)}"
    end
  end

  test "S8: an item with no attest says so", %{db: db} do
    enable(db)
    t0 = now_ms() - 2 * @stall
    item(db, "wi_fresh")
    assignment(db, "asg_fresh", "wi_fresh", session(db, "agent:george:idle"), t0)

    OwnerAlerts.detect_stalls(db, now: t0 + @stall)
    assert [%{body: body}] = stall_alerts(db)
    assert body =~ "Last progress: none yet."
  end

  test "T8: a stall alerts once across ten thresholds and restarts", %{db: db} do
    enable(db)
    holder = session(db, "agent:george:idle")
    t0 = now_ms() - 10 * @stall - @hour
    item(db, "wi_t8")
    assignment(db, "asg_t8", "wi_t8", holder, t0)
    runner = runner(self(), fn {:execute, op} -> committed(op, "send") end)

    for k <- 1..5, do: OwnerAlerts.detect_stalls(db, now: t0 + k * @stall)
    assert [alert] = stall_alerts(db)
    assert OwnerAlerts.deliver_due(db, now: alert.created_at, runner: runner) == 0
    assert_received {:harklight, ["send", "--prepare", "--op-id", op | _]}
    assert_received {:harklight, ["send", "--execute", "--op-id", ^op]}

    # A restart mid-way: the boot pass finds the same stall and dedupes it.
    start_supervised!({OwnerAlerts, db: db, send_runner: runner}, id: :first_boot)
    :sys.get_state(OwnerAlerts)
    :ok = stop_supervised!(:first_boot)

    for k <- 6..10, do: OwnerAlerts.detect_stalls(db, now: t0 + k * @stall)

    start_supervised!({OwnerAlerts, db: db, send_runner: runner}, id: :second_boot)
    :sys.get_state(OwnerAlerts)

    refute_received {:harklight, _}
    assert [%{state: "sent", op_id: ^op, dedupe_key: key}] = stall_alerts(db)
    assert key == "stall:wi_t8:#{t0}"
    assert count(db, "SELECT count(*) FROM harklight_send_operations") == 1
  end

  test "T9: progress moves the anchor, and the item alerts again only a threshold later",
       %{db: db} do
    enable(db)
    holder = session(db, "agent:george:idle")
    t0 = now_ms() - 20 * @stall
    item(db, "wi_t9")
    assignment(db, "asg_t9", "wi_t9", holder, t0)

    OwnerAlerts.detect_stalls(db, now: t0 + @stall)
    assert [%{anchor_at: ^t0}] = stall_alerts(db)

    t1 = t0 + 2 * @stall
    attest(db, "asg_t9", holder, t1)

    assert %{created: 0, next_at: next} = OwnerAlerts.detect_stalls(db, now: t1 + @stall - 1)
    assert next == t1 + @stall
    assert length(stall_alerts(db)) == 1

    assert %{created: 1} = OwnerAlerts.detect_stalls(db, now: t1 + @stall)
    assert [%{anchor_at: ^t0}, %{anchor_at: ^t1, dedupe_key: key}] = stall_alerts(db)
    assert key == "stall:wi_t9:#{t1}"
  end

  test "T9: a condition wait that fires after ten hours restarts the clock at its firing",
       %{db: db} do
    enable(db)
    holder = session(db, "agent:george:idle")
    t0 = now_ms() - 20 * @stall
    item(db, "wi_wait")
    assignment(db, "asg_wait", "wi_wait", holder, t0)
    wake_id = wait_on(db, "asg_wait", holder, t0, condition_kind: "pr-merged")

    fired_at = t0 + 10 * @hour

    for at <- [t0 + @stall, t0 + 2 * @stall, fired_at - 1] do
      assert %{created: 0, next_at: nil} = OwnerAlerts.detect_stalls(db, now: at)
    end

    {:ok, _} =
      DB.query(
        db,
        "UPDATE wakes SET state='fired', firedAt=?2, firedBy='condition' WHERE wakeId=?1",
        [wake_id, fired_at]
      )

    assert %{created: 0, next_at: next} =
             OwnerAlerts.detect_stalls(db, now: fired_at + @stall - 1)

    assert next == fired_at + @stall
    assert stall_alerts(db) == []

    OwnerAlerts.detect_stalls(db, now: fired_at + @stall)
    assert [%{anchor_at: ^fired_at}] = stall_alerts(db)
  end

  test "T10: other owners' items, iceboxed items and items with no open assignment never alert",
       %{db: db} do
    enable(db)
    holder = session(db, "agent:george:idle")
    foreign = session(db, "agent:other:idle", owner: "other")
    t0 = now_ms() - 20 * @stall

    item(db, "wi_foreign", owner: "other")
    assignment(db, "asg_foreign", "wi_foreign", foreign, t0)

    item(db, "wi_ice", state: "iceboxed")
    assignment(db, "asg_ice", "wi_ice", holder, t0)

    item(db, "wi_empty")
    assignment(db, "asg_done", "wi_empty", holder, t0)
    close_assignment(db, "asg_done", holder, t0 + @minute)

    item(db, "wi_control")
    assignment(db, "asg_control", "wi_control", holder, t0)

    OwnerAlerts.detect_stalls(db, now: t0 + 10 * @stall)
    assert Enum.map(stall_alerts(db), & &1.work_item_id) == ["wi_control"]
  end

  test "T11: a stall alert whose item moved before its retry is withdrawn, not sent",
       %{db: db} do
    enable(db)
    holder = session(db, "agent:george:idle")
    t0 = now_ms() - 20 * @stall
    item(db, "wi_t11")
    assignment(db, "asg_t11", "wi_t11", holder, t0)
    OwnerAlerts.detect_stalls(db, now: t0 + @stall)
    [alert] = stall_alerts(db)

    parent = self()

    failing = fn args ->
      send(parent, {:harklight, args})
      {"harklight-agent: network unreachable", 1}
    end

    assert OwnerAlerts.deliver_due(db, now: alert.created_at, runner: failing) == 0
    assert_received {:harklight, ["send", "--prepare" | _]}
    assert [%{state: "pending", attempts: 1, next_attempt_at: next}] = stall_alerts(db)

    attest(db, "asg_t11", holder, alert.created_at + @minute)

    assert OwnerAlerts.deliver_due(db, now: next, runner: failing) == 0
    refute_received {:harklight, _}
    assert [%{state: "withdrawn", attempts: 1, next_attempt_at: nil}] = stall_alerts(db)
    assert withdrawn_reasons(db, alert.alert_id) == ["work-moved"]

    assert OwnerAlerts.deliver_due(db, now: next + 2 * @hour, runner: failing) == 0
    refute_received {:harklight, _}
  end

  test "A7: a stall alert whose item became held is withdrawn before its first send",
       %{db: db} do
    enable(db)
    holder = session(db, "agent:george:idle")
    other = session(db, "agent:george:other")
    t0 = now_ms() - 20 * @stall
    item(db, "wi_held")
    assignment(db, "asg_held", "wi_held", holder, t0)
    OwnerAlerts.detect_stalls(db, now: t0 + @stall)
    [alert] = stall_alerts(db)

    # An open decision request covers the assignment without moving the anchor.
    decision_request(db, "asg_held", holder, other, alert.created_at)

    runner = runner(self(), fn {:execute, op} -> committed(op, "send") end)
    assert OwnerAlerts.deliver_due(db, now: alert.created_at, runner: runner) == 0
    refute_received {:harklight, _}
    assert [%{state: "withdrawn", attempts: 0, op_id: nil}] = stall_alerts(db)
    assert withdrawn_reasons(db, alert.alert_id) == ["held-or-waiting"]
    assert count(db, "SELECT count(*) FROM harklight_send_operations") == 0
  end

  test "T14: a two-hour threshold alerts at two hours", %{db: db} do
    enable(db)
    :ok = Org.put_setting(db, "owner-alert-stall-ms", "7200000")
    holder = session(db, "agent:george:idle")
    t0 = now_ms() - 10 * @stall
    item(db, "wi_t14", title: "Short fuse")
    assignment(db, "asg_t14", "wi_t14", holder, t0)

    assert %{created: 0, next_at: next} = OwnerAlerts.detect_stalls(db, now: t0 + 2 * @hour - 1)
    assert next == t0 + 2 * @hour
    assert stall_alerts(db) == []

    assert %{created: 1} = OwnerAlerts.detect_stalls(db, now: t0 + 2 * @hour)
    assert [%{title: "No progress for 2h: Short fuse"}] = stall_alerts(db)
  end

  test "T14: with the owner setting unset no stall alert is created", %{db: db} do
    holder = session(db, "agent:george:idle")
    t0 = now_ms() - 10 * @stall
    item(db, "wi_off")
    assignment(db, "asg_off", "wi_off", holder, t0)

    assert %{owner: nil, created: 0} = OwnerAlerts.detect_stalls(db, now: t0 + 5 * @stall)
    assert stall_alerts(db) == []
  end

  test "T18: alerts off withdraw a failed stall alert and skip new stalls; re-enabling alerts a still-stalled item once",
       %{db: db} do
    enable(db)
    config = config_handler(db)

    set_owner = fn value ->
      config.(%{action: "set", setting: "owner-alerts-user", value: value})
    end

    holder = session(db, "agent:george:idle")

    # A stall alert queued for its retry after a definite failure.
    t0 = now_ms() - 20 * @stall
    item(db, "wi_queued")
    assignment(db, "asg_queued", "wi_queued", holder, t0)
    assert %{created: 1} = OwnerAlerts.detect_stalls(db, now: t0 + @stall)
    [queued] = stall_alerts(db)
    assert OwnerAlerts.deliver_due(db, now: queued.created_at, runner: failing(self())) == 0
    assert_received {:harklight, ["send", "--prepare" | _]}
    assert [%{state: "pending", attempts: 1, next_attempt_at: retry_at}] = stall_alerts(db)

    assert %{setting: "owner-alerts-user", value: nil, changed: true} = set_owner.("")

    # An item that stalls while alerts are off gets no row.
    t1 = now_ms() - 2 * @stall
    item(db, "wi_new")
    assignment(db, "asg_new", "wi_new", holder, t1)
    assert %{owner: nil, created: 0} = OwnerAlerts.detect_stalls(db, now: t1 + @stall)
    assert [%{work_item_id: "wi_queued"}] = stall_alerts(db)

    # The queued alert's retry withdraws it instead of minting an operation,
    # although its stall is still current.
    assert OwnerAlerts.deliver_due(db, now: retry_at, runner: failing(self())) == 0
    refute_received {:harklight, _}

    assert [%{state: "withdrawn", attempts: 1, next_attempt_at: nil}] = stall_alerts(db)
    assert withdrawn_reasons(db, queued.alert_id) == ["alerts-off"]
    assert count(db, "SELECT count(*) FROM harklight_send_operations") == 0

    assert %{value: nil, changed: false} = set_owner.("")

    # The boot pass while alerts are off creates nothing either.
    runner = runner(self(), fn {:execute, op} -> committed(op, "send") end)
    start_supervised!({OwnerAlerts, db: db, send_runner: runner})
    :sys.get_state(OwnerAlerts)
    assert [%{work_item_id: "wi_queued"}] = stall_alerts(db)
    refute_received {:harklight, _}

    # Re-enabling: the setting's commit makes the process look at once. The
    # still-stalled item alerts once; the queued item's stall identity was
    # already alerted (S6), so it gets no second alert.
    enabled_at = now_ms()
    assert %{value: @owner, changed: true} = set_owner.(@owner)
    :sys.get_state(OwnerAlerts)

    assert_received {:harklight, ["send", "--prepare", "--op-id", op | _]}
    assert_received {:harklight, ["send", "--execute", "--op-id", ^op]}
    refute_received {:harklight, _}

    assert [
             %{work_item_id: "wi_queued", state: "withdrawn"},
             %{work_item_id: "wi_new", anchor_at: ^t1, state: "sent", op_id: ^op} = alert
           ] = stall_alerts(db)

    assert alert.created_at >= enabled_at
    assert alert.created_at < enabled_at + 10 * @minute
  end

  test "T15: a stall alert created before a restart is sent once after it", %{db: db} do
    enable(db)
    holder = session(db, "agent:george:idle")
    t0 = now_ms() - @stall - @minute
    item(db, "wi_t15")
    assignment(db, "asg_t15", "wi_t15", holder, t0)

    assert %{created: 1} = OwnerAlerts.detect_stalls(db)
    assert [%{state: "pending", attempts: 0}] = stall_alerts(db)

    runner = runner(self(), fn {:execute, op} -> committed(op, "send") end)
    start_supervised!({OwnerAlerts, db: db, send_runner: runner}, id: :first_boot)
    assert_receive {:harklight, ["send", "--prepare", "--op-id", op | _]}, 5_000
    assert_receive {:harklight, ["send", "--execute", "--op-id", ^op]}, 5_000
    :sys.get_state(OwnerAlerts)
    assert [%{state: "sent", op_id: ^op}] = stall_alerts(db)

    :ok = stop_supervised!(:first_boot)
    start_supervised!({OwnerAlerts, db: db, send_runner: runner}, id: :second_boot)
    :sys.get_state(OwnerAlerts)

    refute_received {:harklight, _}
    assert count(db, "SELECT count(*) FROM harklight_send_operations") == 1
    assert [%{state: "sent", op_id: ^op, attempts: 1}] = stall_alerts(db)
  end

  test "T16: the inactivity ladder runs unchanged beside a stall alert" do
    opened_at = now_ms() - 10_000
    runner = runner(self(), fn {:execute, op} -> committed(op, "send") end)

    control = ladder_run(false, opened_at, runner)
    enabled = ladder_run(true, opened_at, runner)

    assert enabled.ladder == control.ladder
    assert control.stall_alerts == []
    assert [%{work_item_id: "wi_ladder", state: "sent"}] = enabled.stall_alerts

    # The ladder really climbed: a reminder ended on the owner's Main.
    main = Org.personal_session_key(@owner)

    assert Enum.any?(control.ladder.wakes, fn
             ["prompt", ^main, _state, prompt, _ref] -> is_binary(prompt)
             _ -> false
           end)
  end

  test "T17: a child on another item neither covers the parent nor restarts its clock",
       %{db: db} do
    enable(db)
    parent = session(db, "agent:george:parent")
    child = session(db, "agent:george:child")
    t0 = now_ms() - 20 * @stall
    item(db, "wi_w")
    item(db, "wi_v")
    assignment(db, "asg_w", "wi_w", parent, t0, subject: "Parent work")

    assignment(db, "asg_v", "wi_v", child, t0 + @minute,
      opened_by_session: parent,
      subject: "Child work"
    )

    OwnerAlerts.detect_stalls(db, now: t0 + @stall - 1)
    assert w_alerts(db) == []

    OwnerAlerts.detect_stalls(db, now: t0 + @stall)
    assert [%{anchor_at: ^t0}] = w_alerts(db)

    closed_at = t0 + @stall + @hour
    close_assignment(db, "asg_v", child, closed_at)

    for at <- [closed_at + @stall, closed_at + 3 * @stall] do
      OwnerAlerts.detect_stalls(db, now: at)
      assert [%{anchor_at: ^t0}] = w_alerts(db)
    end
  end

  test "T17: the same child on the parent's item covers the parent", %{db: db} do
    enable(db)
    parent = session(db, "agent:george:parent")
    child = session(db, "agent:george:child")
    t0 = now_ms() - 20 * @stall
    item(db, "wi_w")
    assignment(db, "asg_w", "wi_w", parent, t0, subject: "Parent work")

    assignment(db, "asg_wc", "wi_w", child, t0 + @minute,
      opened_by_session: parent,
      subject: "Child work"
    )

    OwnerAlerts.detect_stalls(db, now: t0 + 10 * @stall)

    # The idle child itself still alerts; the parent waiting on it does not.
    assert [%{body: body}] = w_alerts(db)
    assert body =~ "'Child work' (asg_wc)"
    refute body =~ "Parent work"
    assert body =~ "1 other open assignment is held or waiting."
  end

  test "a stall found by a later pass after it came due is logged as a missed event",
       %{db: db} do
    enable(db)
    holder = session(db, "agent:george:idle")
    t0 = now_ms() - 20 * @stall
    item(db, "wi_missed")
    assignment(db, "asg_missed", "wi_missed", holder, t0)
    item(db, "wi_planned")
    assignment(db, "asg_planned", "wi_planned", holder, t0 + 2 * @stall)

    # The previous pass ran after wi_missed came due, so its alert now is a
    # miss; wi_planned comes due after that pass and is not.
    previous_pass = t0 + 2 * @stall
    OwnerAlerts.detect_stalls(db, now: t0 + 3 * @stall, missed_before: previous_pass)

    details =
      Map.new(stall_alerts(db), fn alert ->
        {alert.work_item_id, created_detail(db, alert.alert_id)}
      end)

    assert details["wi_missed"]["missedEvent"] == true
    refute Map.has_key?(details["wi_planned"], "missedEvent")
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

  defp now_ms, do: System.system_time(:millisecond)

  defp uid, do: System.unique_integer([:positive])

  defp item(db, id, opts \\ []) do
    owner = Keyword.get(opts, :owner, @owner)

    {:ok, _} =
      DB.query(
        db,
        """
        INSERT INTO work_items (id, title, ownerUserId, state, createdByUser, createdAt)
        VALUES (?1, ?2, ?3, ?4, ?3, 1)
        """,
        [id, Keyword.get(opts, :title, "Item #{id}"), owner, Keyword.get(opts, :state, "open")]
      )

    id
  end

  defp assignment(db, id, work_item_id, holder, opened_at, opts \\ []) do
    {by_user, by_session} =
      case Keyword.get(opts, :opened_by_session) do
        nil -> {@owner, nil}
        session_key -> {nil, session_key}
      end

    {:ok, _} =
      DB.query(
        db,
        """
        INSERT INTO assignments
          (id, subject, holderKey, openedByUser, openedBySession, openedAt, state, workItemId)
        VALUES (?1, ?2, ?3, ?4, ?5, ?6, 'open', ?7)
        """,
        [
          id,
          Keyword.get(opts, :subject, "Work #{id}"),
          holder,
          by_user,
          by_session,
          opened_at,
          work_item_id
        ]
      )

    id
  end

  defp attest(db, assignment_id, by_session, ts, kind \\ "progress") do
    id = "att_#{uid()}"

    {:ok, _} =
      DB.query(
        db,
        "INSERT INTO attests (id, assignmentId, kind, bySession, ts) VALUES (?1, ?2, ?3, ?4, ?5)",
        [id, assignment_id, kind, by_session, ts]
      )

    id
  end

  defp close_assignment(db, id, holder, closed_at) do
    attest_id = attest(db, id, holder, closed_at, "surrender")

    {:ok, _} =
      DB.query(
        db,
        """
        UPDATE assignments
        SET state='closed', outcome='surrendered', closedAt=?2, closedBySession=?3,
            closingAttestId=?4
        WHERE id=?1
        """,
        [id, closed_at, holder, attest_id]
      )
  end

  # A pending wait naming the assignment: a condition wake or a dependency wait.
  defp wait_on(db, assignment_id, session_key, created_at, opts) do
    id = "w_wait_#{uid()}"
    condition_kind = Keyword.get(opts, :condition_kind)

    {:ok, _} =
      DB.query(
        db,
        """
        INSERT INTO wakes
          (wakeId, sessionKey, origin, prompt, dueAt, state, createdAt,
           conditionKind, conditionScope, waitMode, assignmentId)
        VALUES (?1, ?2, ?3, 'resume', ?4, 'pending', ?5, ?6, ?7, ?8, ?9)
        """,
        [
          id,
          session_key,
          "session:#{session_key}",
          created_at + 1_000 * @stall,
          created_at,
          condition_kind,
          condition_kind && "pr:1",
          Keyword.get(opts, :wait_mode),
          assignment_id
        ]
      )

    id
  end

  defp cannot_proceed(db, assignment_id, holder, ts) do
    n = uid()
    attest_id = attest(db, assignment_id, holder, ts, "cannot-proceed")
    wake_id = "w_cp_#{n}"

    {:ok, _} =
      DB.query(
        db,
        """
        INSERT INTO wakes (wakeId, sessionKey, origin, prompt, dueAt, state, createdAt)
        VALUES (?1, ?2, 'process:tightbeam', 'decide', ?3, 'pending', ?3)
        """,
        [wake_id, Org.personal_session_key(@owner), ts]
      )

    {:ok, _} =
      DB.query(
        db,
        """
        INSERT INTO assignment_cannot_proceed
          (id, assignmentId, attestId, decisionRequestId, decisionWakeId, openerRef,
           disposerRef, reason, state, createdAt)
        VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, 'blocked on access', 'standing', ?8)
        """,
        [
          "cp_#{n}",
          assignment_id,
          attest_id,
          "dr_cp_#{n}",
          wake_id,
          "session:#{holder}",
          "user:#{@owner}",
          ts
        ]
      )
  end

  defp decision_request(db, assignment_id, asker, asked, raised_at) do
    {:ok, _} =
      DB.query(
        db,
        """
        INSERT INTO decision_requests
          (id, kind, raiserId, raiserSessionKey, ownerUserId, assignmentId,
           expecterSessionKey, expecterUserId, raisedAt, deadlineAt,
           question, context, status, rowSchemaRevision)
        VALUES (?1, 'agent', ?2, ?3, ?4, ?5, ?6, ?4, ?7, NULL, 'Which schema?', '{}', 'open', 2)
        """,
        ["dr_#{uid()}", "session:" <> asker, asker, @owner, assignment_id, asked, raised_at]
      )
  end

  # An open usage-limit incident the session belongs to: its harness is paused.
  defp pause(db, session_key) do
    n = uid()
    at = now_ms()

    {:ok, _} =
      DB.query(
        db,
        """
        INSERT INTO harness_health_observations
          (id, correlationId, harness, host, failureClass, evidenceKind, sessionKey,
           observedAt, cause, principal)
        VALUES (?1, ?2, 'claude', 'testhost', 'rate-limit-dead', 'terminal-failure', ?3,
                ?4, 'usage limit', 'process:tightbeam')
        """,
        ["hho_#{n}", "test-pause:#{n}", session_key, at]
      )

    {:ok, _} =
      DB.query(
        db,
        """
        INSERT INTO harness_health_incidents
          (id, harness, host, failureClass, state, openedAt, openObservationId)
        VALUES (?1, 'claude', 'testhost', 'rate-limit-dead', 'open', ?2, ?3)
        """,
        ["hhi_#{n}", at, "hho_#{n}"]
      )

    {:ok, _} =
      DB.query(
        db,
        "INSERT INTO harness_health_members (incidentId, sessionKey) VALUES (?1, ?2)",
        [
          "hhi_#{n}",
          session_key
        ]
      )
  end

  # T16: one world runs the 0.1.14 inactivity ladder for an idle assignment,
  # with the stall alert pass and delivery between every ladder step when
  # alerts are enabled. Returns what the ladder wrote, minus random ids.
  defp ladder_run(enabled?, opened_at, runner) do
    db = world_db()
    main = Org.personal_session_key(@owner)
    parent = ladder_session(db, "agent:george:parent", main)
    holder = ladder_session(db, "agent:george:holder", parent)
    :ok = Org.put_setting(db, "owner-alert-stall-ms", "5000")
    if enabled?, do: enable(db)

    item(db, "wi_ladder", title: "Ladder item")
    assignment(db, "asg_inactive", "wi_ladder", holder, opened_at, subject: "ship it")

    alerts_pass = fn ->
      if enabled? do
        OwnerAlerts.detect_stalls(db)
        assert OwnerAlerts.deliver_due(db, runner: runner) == 0
      end
    end

    interval_ms = 1_000

    assert {:ok, :ok} =
             DB.transaction(db, fn txn ->
               Supervision.assignment_opened_in_txn(txn, "asg_inactive", opened_at, interval_ms)
             end)

    alerts_pass.()

    assert {:ok, :ok} =
             Supervision.deadline(db, ladder_wake(db, "assignment_inactivity_deadline"))

    alerts_pass.()

    [first] = ladder_notices(db)

    {:ok, _} =
      DB.query(db, "UPDATE wakes SET state='fired',firedAt=?2 WHERE wakeId=?1", [first, now_ms()])

    ladder_climb(db, first, interval_ms)
    alerts_pass.()
    [^first, second] = ladder_notices(db)

    for _rung <- 1..3 do
      ladder_climb(db, second, interval_ms)
      alerts_pass.()
    end

    {:ok, wakes} =
      DB.query(db, """
      SELECT consumer, sessionKey, state,
             CASE WHEN consumer='prompt' THEN prompt END,
             CASE WHEN obligationRef IS NULL THEN NULL
                  ELSE substr(obligationRef, 1, instr(obligationRef, ':')) END
      FROM wakes ORDER BY rowid
      """)

    {:ok, reminders} = DB.query(db, "SELECT id, reminderState FROM assignments ORDER BY id")

    %{
      ladder: %{
        wakes: wakes,
        reminders: reminders,
        turns: count(db, "SELECT count(*) FROM turns")
      },
      stall_alerts: stall_alerts(db)
    }
  end

  defp ladder_session(db, key, spawned_by) do
    Org.create(db, %{
      session_key: key,
      display_name: key,
      owner_user_id: @owner,
      origin: "user:#{@owner}",
      spawned_by: spawned_by,
      kind: "custom",
      is_built_in: false,
      archetype: "default",
      harness: "claude",
      provider: "anthropic",
      model: Model.new("fable"),
      host: "testhost"
    }).session_key
  end

  defp ladder_wake(db, consumer) do
    assert {:ok, [[wake_id]]} =
             DB.query(
               db,
               """
               SELECT wakeId FROM wakes
               WHERE consumer=?1 AND assignmentId='asg_inactive' AND state='pending'
               ORDER BY dueAt, wakeId LIMIT 1
               """,
               [consumer]
             )

    Wakes.get(db, wake_id)
  end

  defp ladder_notices(db) do
    {:ok, rows} =
      DB.query(db, """
      SELECT wakeId FROM wakes
      WHERE assignmentId='asg_inactive' AND consumer='prompt'
        AND obligationRef LIKE 'assignment-inactivity-episode-v1:%'
      ORDER BY rowid
      """)

    Enum.map(rows, &hd/1)
  end

  defp ladder_climb(db, previous_wake_id, interval_ms) do
    {:ok, _} =
      DB.query(db, "UPDATE wakes SET createdAt=?2 WHERE wakeId=?1", [
        previous_wake_id,
        now_ms() - interval_ms - 1
      ])

    climb = ladder_wake(db, "assignment_inactivity_climb")
    {:ok, _} = DB.query(db, "UPDATE wakes SET dueAt=0 WHERE wakeId=?1", [climb.wake_id])
    assert {:ok, :ok} = Supervision.climb(db, Wakes.get(db, climb.wake_id))
  end

  ## Reads

  defp stall_alerts(db) do
    {:ok, rows} =
      DB.query(
        db,
        """
        SELECT alertId, workItemId, anchorAt, dedupeKey, title, body, state, createdAt,
               opId, attempts, nextAttemptAt
        FROM owner_alerts WHERE kind='stall' ORDER BY createdAt, alertId
        """
      )

    Enum.map(rows, fn [
                        id,
                        work_item_id,
                        anchor_at,
                        dedupe_key,
                        title,
                        body,
                        state,
                        created_at,
                        op_id,
                        attempts,
                        next_attempt_at
                      ] ->
      %{
        alert_id: id,
        work_item_id: work_item_id,
        anchor_at: anchor_at,
        dedupe_key: dedupe_key,
        title: title,
        body: body,
        state: state,
        created_at: created_at,
        op_id: op_id,
        attempts: attempts,
        next_attempt_at: next_attempt_at
      }
    end)
  end

  defp w_alerts(db), do: Enum.filter(stall_alerts(db), &(&1.work_item_id == "wi_w"))

  defp withdrawn_reasons(db, alert_id) do
    {:ok, rows} =
      DB.query(
        db,
        "SELECT detail FROM lifecycle_events WHERE kind='owner_alert_withdrawn' AND subject=?1",
        [alert_id]
      )

    Enum.map(rows, fn [detail] -> JSON.decode!(detail)["reason"] end)
  end

  defp created_detail(db, alert_id) do
    {:ok, [[detail]]} =
      DB.query(
        db,
        "SELECT detail FROM lifecycle_events WHERE kind='owner_alert_created' AND subject=?1",
        [alert_id]
      )

    JSON.decode!(detail)
  end

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

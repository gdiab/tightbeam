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

    for value <- ["nobody", ""] do
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

  defp config_handler(db) do
    base_dir =
      Path.join(System.tmp_dir!(), "tightbeam-owner-alerts-#{System.unique_integer([:positive])}")

    on_exit(fn -> File.rm_rf!(base_dir) end)
    Archetypes.load!(base_dir)
    config = Gateway.handlers(%{db: db, base_dir: base_dir, wake_tick_ms: 1_000})["config"]

    fn params ->
      config.(%{principal: {:process, "test"}, origin: "process:test", params: params})
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

defmodule Tightbeam.LimitFallbackSwitchTest do
  # Contract c v1.4, phase c1: the automatic per-archetype limit-fallback
  # switch, end to end through a real session lane and the gateway's own turn
  # runner. A Codex session's typed usage limit holds its lane, the evaluation
  # runs the ordinary tune harness-change path as `process:tightbeam`, and the
  # outcome's records commit with the swap (or with the withhold).
  #
  # Adapters are stubs on OUR side of the ACP seam: the typed carriers they
  # return are the recorded production shapes `HarnessHealth` classifies
  # (`codexErrorInfo: usageLimitExceeded`, `errorKind: rate_limit`).
  #
  # The fixture extracts the gateway runner ONCE. `Gateway.children/1` is the
  # gateway's start composition, which releases standing holds (R5 restart);
  # test 17b calls it again on purpose to model a restart.
  use Tightbeam.TestCase, async: false

  alias Tightbeam.{
    Archetypes,
    Assignments,
    ConnRegistry,
    DB,
    Devices,
    Gateway,
    HarnessHealth,
    Identity,
    LimitFallback,
    Model,
    Org,
    RateLimitReset,
    Schema,
    SessionLane,
    Wakes
  }

  alias Tightbeam.GatewayTurnFixture.CoordinatorStub

  @owner "synthetic-owner"
  @main "agent:main:clawline:synthetic-owner:main"
  @archetype "synthetic-switch"

  @codex_limit %{
    "code" => -32_603,
    "message" => "You've hit your usage limit.",
    "data" => %{"codexErrorInfo" => "usageLimitExceeded"}
  }

  @text_limit %{"code" => -32_603, "message" => "HTTP 429 Too Many Requests"}

  defmodule LaneDoorbell do
    # Stands in for the lane manager: a delivery's doorbell nudges the
    # session's real lane, and the tune boundary's quiet check succeeds.
    use GenServer

    def start_link(_), do: GenServer.start_link(__MODULE__, nil, name: Tightbeam.LaneManager)
    def init(state), do: {:ok, state}

    def handle_call({:ensure_lane, key}, _from, state) do
      Tightbeam.SessionLane.nudge(key)
      {:reply, :ok, state}
    end

    def handle_call(_message, _from, state), do: {:reply, :ok, state}

    def handle_cast({:ensure_lane, key}, state) do
      Tightbeam.SessionLane.nudge(key)
      {:noreply, state}
    end

    def handle_cast(_message, state), do: {:noreply, state}
  end

  defmodule ReadinessDrain do
    # Stands in for the wake scheduler's one duty these tests reach: a lane's
    # turn terminal casts `{:recipient_ready, key}`, and the scheduler admits
    # that session's ready staged sources (a post staged behind a running
    # turn) through NoticeBatcher, as `Tightbeam.Wakes` does.
    use GenServer

    def start_link(db), do: GenServer.start_link(__MODULE__, db)
    def init(db), do: {:ok, db}

    def handle_cast({:recipient_ready, key}, db) do
      Tightbeam.NoticeBatcher.recover(
        db,
        System.system_time(:millisecond),
        [conn_registry: Tightbeam.ConnRegistry, lane_manager: Tightbeam.LaneManager],
        key
      )

      {:noreply, db}
    end

    def handle_cast(_message, db), do: {:noreply, db}
  end

  defmodule CatalogStub do
    use GenServer

    def start_link(entries),
      do: GenServer.start_link(__MODULE__, entries, name: Tightbeam.ModelCatalog)

    def init(entries), do: {:ok, entries}

    def handle_call({:get, {host, harness}}, _from, entries),
      do: {:reply, {Map.get(entries, {host, harness}, []), :fresh}, entries}

    def handle_call(:get, _from, entries), do: {:reply, entries, entries}
  end

  defmodule SwitchAdapter do
    # One harness's adapter. `prompt` decides each prompt's reply in this
    # process: `fn n, text, opts -> reply end`.
    use GenServer

    def start_link(opts), do: GenServer.start_link(__MODULE__, Map.new(opts))

    def init(opts),
      do: {:ok, Map.merge(%{sessions: %{}, prompts: 0, candidate: :ok}, opts)}

    def handle_call({:knows_session?, sid}, _from, state),
      do: {:reply, Map.has_key?(state.sessions, sid), state}

    def handle_call({:new_session, model, _cwd, _mcp, _guidance}, _from, state) do
      sid = "#{state.name}-session-#{map_size(state.sessions) + 1}"
      send(state.parent, {:new_session, state.name, model})
      {:reply, {:ok, sid}, put_in(state.sessions[sid], model)}
    end

    def handle_call({:new_session, model, cwd, mcp, guidance, _timeout}, from, state),
      do: handle_call({:new_session, model, cwd, mcp, guidance}, from, state)

    def handle_call({:new_candidate_session, model, _cwd, _mcp, guidance}, _from, state) do
      send(state.parent, {:candidate, state.name, model, guidance})

      case state.candidate do
        :ok ->
          sid = "#{state.name}-candidate-#{map_size(state.sessions) + 1}"
          {:reply, {:ok, sid}, put_in(state.sessions[sid], model)}

        {:error, reason} ->
          {:reply, {:error, reason}, state}
      end
    end

    def handle_call({:current_model, sid}, _from, state) do
      case Map.fetch(state.sessions, sid) do
        {:ok, model} -> {:reply, {:ok, model}, state}
        :error -> {:reply, {:error, :unknown_session}, state}
      end
    end

    def handle_call({:apply_model, sid, model}, _from, state),
      do: {:reply, :ok, put_in(state.sessions[sid], model)}

    def handle_call({:apply_model, sid, model, _timeout}, from, state),
      do: handle_call({:apply_model, sid, model}, from, state)

    def handle_call({:prompt, _sid, text, opts}, _from, state) do
      n = state.prompts + 1
      send(state.parent, {:prompted, state.name, n, text})
      {:reply, state.prompt.(n, text, opts), %{state | prompts: n}}
    end

    def handle_call({:close_session, _sid}, _from, state), do: {:reply, :ok, state}
    def handle_call({:close_session, _sid, _opts}, _from, state), do: {:reply, :ok, state}

    def handle_call({:fast_status, _sid}, _from, state),
      do: {:reply, {:error, :fast_unsupported}, state}

    def handle_call(:conn, _from, state), do: {:reply, self(), state}

    def handle_call({:set, key, value}, _from, state),
      do: {:reply, :ok, Map.put(state, key, value)}

    def handle_call(other, _from, state),
      do: {:reply, {:error, {:unsupported_in_test, inspect(other, limit: 3)}}, state}
  end

  ## Tests

  # Tests 1, 5, 13 (c1), 14 and 16; the non-wake half of test 3.
  test "a typed Codex limit holds the lane, switches the session once and records the switch" do
    with_gateway(fn ctx ->
      key = "switch-applied"
      session!(ctx, key)
      lane = lane!(ctx, key)
      block_first_codex_prompt!(ctx)

      deliver!(ctx, key, "failed-original")
      assert_receive {:prompted, :codex, 1, _text}, 15_000

      # Posted behind the failed turn while it runs: each is staged, no turn.
      queued_tokens = ~w(queued-alpha queued-bravo queued-charlie)
      staged = for token <- queued_tokens, do: stage!(ctx, key, token)

      send(ctx.codex, :release_prompt)

      {evaluation, seq} = await_hold!(ctx, key)

      # The failed turn's terminal readies the recipient, which admits each
      # staged post as its own queued turn, in posting order.
      queued = for token <- queued_tokens, do: await_turn_seq!(ctx.db, key, token)
      assert queued == Enum.sort(queued)

      for {wake_id, turn} <- Enum.zip(staged, queued),
          do: assert(delivered_turn(ctx.db, wake_id) == turn)

      # Test 16: no park opened, and the lane claims nothing while held.
      SessionLane.nudge(key)
      assert %{task_ref: nil} = :sys.get_state(lane)
      assert Enum.all?(queued, &(turn_status(ctx.db, &1) == "queued"))
      assert LimitFallback.held?(ctx.db, key)

      first = assign!(ctx, key, "first open assignment")
      second = assign!(ctx, key, "second open assignment")
      original_messages = message_count(ctx.db, key, "failed-original")

      assert evaluation.() == :applied

      # R6/R7: same key, the configured tuple, assignments and holder unchanged.
      session = Org.get(ctx.db, key)
      assert session.harness == "claude"
      assert session.model == fallback_model()
      assert session.state == "active"

      assert session.fallback_active.trigger == "turn:#{seq}"
      assert session.fallback_active.from == %{harness: "codex", model: source_model()}
      assert evaluation_outcome(ctx.db, key, seq) == {"applied", nil}
      refute LimitFallback.held?(ctx.db, key)

      for assignment <- [first, second] do
        assert {:ok, [["open", ^key]]} =
                 DB.query(ctx.db, "SELECT state, holderKey FROM assignments WHERE id=?1", [
                   assignment.id
                 ])
      end

      assert message_count(ctx.db, key, "failed-original") == original_messages

      # R12: one process progress attest per open assignment, with readback.
      for assignment <- [first, second] do
        assert [[note]] = process_attests(ctx.db, assignment.id)
        assert note =~ "model-fallback applied session=#{key} "
        assert note =~ " from=codex/synthetic-codex/low "
        assert note =~ " to=claude/synthetic-claude/high "
        assert note =~ " readback=claude/synthetic-claude/high "
        assert note =~ " trigger=#{seq} class=rate-limit-dead evidence=usageLimitExceeded "
        assert String.ends_with?(note, " failed-turn=replayed")
      end

      # R13: both assignments have one delivery owner, so one fyi notice.
      assert [[recipient, "fyi", assignment_id, notice]] = notices(ctx.db, key)
      assert recipient == @main
      assert assignment_id in [first.id, second.id]
      assert notice =~ "is now on its limit fallback claude/synthetic-claude/high, since "
      assert notice =~ "provider openai (codex/synthetic-codex/low)"
      assert notice =~ "class rate-limit-dead"
      assert notice =~ "turn #{seq}"
      assert notice =~ "after this session's next turn that completes normally"

      assert notice =~
               "tightbeam tune --session #{key} --harness codex --model synthetic-codex --effort low"

      assert notice =~ first.id
      assert notice =~ second.id
      assert notice =~ "not staffing or a transfer"

      # R14 and R15.
      assert count(ctx.db, "condition_facts", key, "session-model-fallback-applied") == 1
      assert lifecycle_count(ctx.db, key, "session-model-fallback-applied") == 1

      assert [["model-fallback", dedupe, title, body]] = alerts(ctx.db, key)
      assert dedupe == "model-fallback:#{key}:turn:#{seq}"
      assert title == "Switch #{key} switched to its fallback model"
      assert body =~ "tightbeam tune --session #{key} --harness codex"

      # Test 13: a re-entered evaluation of the same failed turn adds nothing.
      assert evaluation.() == :duplicate

      assert Gateway.evaluate_limit_fallback(ctx.config, key, seq, "usageLimitExceeded") ==
               :duplicate

      assert length(notices(ctx.db, key)) == 1
      assert count(ctx.db, "condition_facts", key, "session-model-fallback-applied") == 1
      assert lifecycle_count(ctx.db, key, "session-model-fallback-applied") == 1
      assert length(alerts(ctx.db, key)) == 1

      for assignment <- [first, second],
          do: assert(length(process_attests(ctx.db, assignment.id)) == 1)

      # Test 5 and test 3 (message turn): the queue runs once, in order, on the
      # fallback; the replayed turn is redelivered once by its existing
      # vehicle after the first normal turn there.
      tokens = queued_tokens ++ ["failed-original"]
      assert ordered_tokens(:claude, tokens) == tokens
      await_turns_settled!(ctx.db, key)
      assert_ran_once!(ctx.db, key, queued_tokens)

      assert {:ok, [[2]]} =
               DB.query(
                 ctx.db,
                 """
                 SELECT COUNT(*) FROM turns t JOIN messages m ON m.id=t.messageId
                 WHERE t.sessionKey=?1 AND m.content='failed-original'
                 """,
                 [key]
               )

      assert {:ok, [[redelivered]]} =
               DB.query(
                 ctx.db,
                 "SELECT redeliveryTurnSeq FROM health_redelivery_attempts WHERE sourceTurnSeq=?1",
                 [seq]
               )

      assert is_integer(redelivered)

      # Test 14: no probe. The only provider requests are the failed turn,
      # the switch's own candidate session and the turns that ran after it.
      assert_received {:candidate, :claude, %Model{family: "synthetic-claude"}, _guidance}
      refute_received {:candidate, _, _, _}
      refute_received {:prompted, :codex, _, _}
      refute_received {:new_session, :claude, _}
    end)
  end

  # Test 3, wake half.
  test "a replayed wake turn keeps its rate-limit retry at the existing backoff, and nothing else" do
    with_gateway(fn ctx ->
      key = "switch-wake"
      session!(ctx, key)
      lane!(ctx, key)

      wake =
        Wakes.schedule(ctx.db, %{
          session_key: key,
          origin: "user:" <> @owner,
          prompt: "wake-original",
          due_at: System.system_time(:millisecond)
        })

      # Its delivery consumes the wake with the turn. A delivered wake left
      # pending stays a ready source, and every later post stages behind it.
      assert :appended =
               Gateway.deliver_prompt(key, "user:" <> @owner, "wake-original",
                 db: ctx.db,
                 wake_id: wake.wake_id,
                 sender: "user:" <> @owner,
                 fire_wake_in_txn: true,
                 lane_manager: Tightbeam.LaneManager,
                 conn_registry: ConnRegistry
               )

      {evaluation, seq} = await_hold!(ctx, key)

      # Deferred to the outcome: nothing replays while the hold stands.
      assert retry_rows(ctx.db, seq) == []
      assert evaluation.() == :applied

      assert [[^seq, "failed", retry_wake_id]] = retry_rows(ctx.db, seq)

      assert {:ok, [[^key, "pending", due_at, ended_at]]} =
               DB.query(
                 ctx.db,
                 """
                 SELECT w.sessionKey, w.state, w.dueAt, t.endedAt FROM wakes w, turns t
                 WHERE w.wakeId=?1 AND t.seq=?2
                 """,
                 [retry_wake_id, seq]
               )

      assert due_at == ended_at + 30_000

      [[_recipient, "fyi", _assignment, notice]] = notices(ctx.db, key)
      assert notice =~ "rate-limit retry wake #{retry_wake_id}"
      assert notice =~ iso(due_at)

      # The retry owns the replay: a normal turn on the fallback does not
      # also redeliver the failed message.
      deliver!(ctx, key, "after-switch")
      assert ordered_tokens(:claude, ["after-switch"]) == ["after-switch"]
      await_turns_settled!(ctx.db, key)

      assert {:ok, [[1]]} =
               DB.query(
                 ctx.db,
                 """
                 SELECT COUNT(*) FROM turns t JOIN messages m ON m.id=t.messageId
                 WHERE t.sessionKey=?1 AND m.content LIKE '%wake-original%'
                 """,
                 [key]
               )
    end)
  end

  # Test 4.
  test "a failed turn with a recorded tool call is not replayed and the new engine is told" do
    with_gateway(fn ctx ->
      key = "switch-unknown-effect"
      session!(ctx, key)
      lane!(ctx, key)

      prompt = fn
        1, _text, opts ->
          send(ctx.parent, :codex_blocked)

          receive do
            :release_prompt -> :ok
          end

          Keyword.fetch!(opts, :trace_dispatch).(41)
          {:error, @codex_limit}

        n, _text, _opts ->
          ok_reply(n)
      end

      :ok = GenServer.call(ctx.codex, {:set, :prompt, prompt})

      deliver!(ctx, key, "failed-original")
      assert_receive :codex_blocked, 15_000
      tokens = ~w(queued-alpha queued-bravo queued-charlie)
      for token <- tokens, do: stage!(ctx, key, token)
      send(ctx.codex, :release_prompt)

      {evaluation, seq} = await_hold!(ctx, key)
      insert_tool_call!(ctx.db, key, seq)

      assert evaluation.() == :applied
      assert Org.get(ctx.db, key).harness == "claude"

      assert_received {:candidate, :claude, _model, guidance}
      assert guidance =~ "## Limit fallback: a failed turn was not replayed"
      assert guidance =~ "after its turn #{seq} failed on a usage limit"
      assert guidance =~ "it was NOT replayed"
      assert guidance =~ "re-derive its state from the records"

      assert [[@main, "input-needed", nil, notice]] = notices(ctx.db, key)
      assert notice =~ "may have had effects and was NOT replayed"

      # No vehicle was ever written for the failed turn.
      assert retry_rows(ctx.db, seq) == []

      assert {:ok, [[0]]} =
               DB.query(
                 ctx.db,
                 "SELECT COUNT(*) FROM health_redelivery_attempts WHERE sourceTurnSeq=?1",
                 [seq]
               )

      assert ordered_tokens(:claude, tokens) == tokens
      await_turns_settled!(ctx.db, key)
      assert_ran_once!(ctx.db, key, tokens)

      assert {:ok, [[1]]} =
               DB.query(
                 ctx.db,
                 """
                 SELECT COUNT(*) FROM turns t JOIN messages m ON m.id=t.messageId
                 WHERE t.sessionKey=?1 AND m.content='failed-original'
                 """,
                 [key]
               )
    end)
  end

  # Test 9.
  test "a text-only 429 never holds or switches" do
    with_gateway(fn ctx ->
      key = "switch-text-limit"
      session!(ctx, key)
      lane!(ctx, key)

      :ok =
        GenServer.call(
          ctx.codex,
          {:set, :prompt, fn _n, _text, _opts -> {:error, @text_limit} end}
        )

      deliver!(ctx, key, "text-limited")
      assert_receive {:prompted, :codex, 1, _text}, 15_000
      await_turns_settled!(ctx.db, key)

      refute_received {:limit_fallback_evaluation, _}

      assert {:ok, []} =
               DB.query(ctx.db, "SELECT 1 FROM limit_fallback_evaluations WHERE sessionKey=?1", [
                 key
               ])

      assert Org.get(ctx.db, key).harness == "codex"
      refute_received {:candidate, _, _, _}
    end)
  end

  # Test 8 (R4.5).
  test "a fallback on the failed provider is withheld unqualified:R4.5" do
    with_gateway(
      fn ctx ->
        key = "switch-same-provider"
        session!(ctx, key)
        lane!(ctx, key)
        assignment = assign!(ctx, key, "held work")
        deliver!(ctx, key, "limited")
        {evaluation, seq} = await_hold!(ctx, key)

        assert evaluation.() == :withheld
        assert_withheld!(ctx, key, seq, "unqualified:R4.5")
        assert process_attests(ctx.db, assignment.id) == []
      end,
      claude_provider: :openai
    )
  end

  # Test 8 (R4.6).
  test "an open incident on the fallback's harness and host is withheld unqualified:R4.6" do
    with_gateway(fn ctx ->
      key = "switch-open-incident"
      session!(ctx, key)
      lane!(ctx, key)

      assert {:opened, _incident} =
               HarnessHealth.observe_provider_invalidation(
                 ctx.db,
                 "claude",
                 "testhost",
                 %{"authMode" => nil, "planType" => nil},
                 conn_registry: ConnRegistry
               )

      deliver!(ctx, key, "limited")
      {evaluation, seq} = await_hold!(ctx, key)

      assert evaluation.() == :withheld
      assert_withheld!(ctx, key, seq, "unqualified:R4.6")
    end)
  end

  # Test 8 (R4.7).
  test "a failing harness-change precheck is withheld unqualified:R4.7" do
    with_gateway(fn ctx ->
      key = "switch-precheck"
      session!(ctx, key)
      lane!(ctx, key)
      :persistent_term.put({__MODULE__, :denied_provider}, :anthropic)
      on_exit(fn -> :persistent_term.erase({__MODULE__, :denied_provider}) end)

      deliver!(ctx, key, "limited")
      {evaluation, seq} = await_hold!(ctx, key)

      assert evaluation.() == :withheld
      assert_withheld!(ctx, key, seq, "unqualified:R4.7")
    end)
  end

  # Test 8 (R1 harness).
  test "a manifest harness other than the routed one is withheld unqualified:R1-harness" do
    with_gateway(
      fn ctx ->
        key = "switch-pinned-harness"
        session!(ctx, key)
        lane!(ctx, key)
        deliver!(ctx, key, "limited")
        {evaluation, seq} = await_hold!(ctx, key)

        assert evaluation.() == :withheld
        assert_withheld!(ctx, key, seq, "unqualified:R1-harness")
      end,
      fallback_harness: "codex"
    )
  end

  # Test 11.
  test "the owner's personal Main is withheld as main" do
    with_gateway(fn ctx ->
      lane!(ctx, @main)
      deliver!(ctx, @main, "main-limited")
      {evaluation, seq} = await_hold!(ctx, @main)

      assert evaluation.() == :withheld
      assert_withheld!(ctx, @main, seq, "main")
    end)
  end

  # Test 10 (remaining parts) and R8a's second acceptance.
  test "a switched session stays on its fallback; a limit there is withheld; an owner tune re-arms it" do
    with_gateway(fn ctx ->
      key = "switch-keep"
      session!(ctx, key)
      lane!(ctx, key)

      reset_at = System.system_time(:millisecond) + 3_600_000

      :ok =
        GenServer.call(
          ctx.claude,
          {:set, :prompt,
           fn
             1, _text, _opts -> {:error, claude_limit(reset_at)}
             n, _text, _opts -> ok_reply(n)
           end}
        )

      deliver!(ctx, key, "first-limit")
      {evaluation, _seq} = await_hold!(ctx, key)
      assert evaluation.() == :applied

      # A typed Claude limit on the fallback is withheld, already-on-fallback.
      deliver!(ctx, key, "fallback-limit")
      {fallback_evaluation, fallback_seq} = await_hold!(ctx, key)
      assert fallback_evaluation.() == :withheld
      assert evaluation_outcome(ctx.db, key, fallback_seq) == {"withheld", "already-on-fallback"}
      assert Org.get(ctx.db, key).harness == "claude"

      # P2: the provider's reset releases nothing back to Codex.
      assert {:ok, [[reset_wake]]} =
               DB.query(
                 ctx.db,
                 "SELECT wakeId FROM wakes WHERE consumer='rate_limit_reset' AND sessionKey=?1",
                 [key]
               )

      {:ok, _} = DB.query(ctx.db, "UPDATE wakes SET dueAt=0 WHERE wakeId=?1", [reset_wake])
      assert {:ok, _released} = RateLimitReset.release(ctx.db, %{wake_id: reset_wake})

      session = Org.get(ctx.db, key)
      assert session.harness == "claude"
      assert session.model == fallback_model()
      assert LimitFallback.fallback_active?(session)
      refute_received {:candidate, :codex, _, _}

      # The owner's tune back clears fallback-active; the next typed limit
      # switches again.
      assert %{ok: true} =
               Gateway.handlers(ctx.config)["tune"].(%{
                 origin: "user:" <> @owner,
                 session_key: key,
                 params: %{
                   setting: "set_harness",
                   harness: "codex",
                   model: "synthetic-codex",
                   effort: "low"
                 }
               })

      session = Org.get(ctx.db, key)
      assert session.harness == "codex"
      refute LimitFallback.fallback_active?(session)

      deliver!(ctx, key, "second-limit")
      {again, again_seq} = await_hold!(ctx, key)
      assert again.() == :applied
      assert evaluation_outcome(ctx.db, key, again_seq) == {"applied", nil}
      assert Org.get(ctx.db, key).harness == "claude"
    end)
  end

  # Test 15 and R3.
  test "a published [limit_fallback] retunes nothing and the next typed limit uses it" do
    with_gateway(
      fn ctx ->
        key = "switch-published"
        session!(ctx, key)
        lane!(ctx, key)

        # Without the key, a typed limit is an ordinary failed turn (R3).
        deliver!(ctx, key, "unconfigured-limit")
        assert_receive {:prompted, :codex, 1, _text}, 15_000
        await_turns_settled!(ctx.db, key)
        refute_received {:limit_fallback_evaluation, _}

        assert {:ok, []} =
                 DB.query(
                   ctx.db,
                   "SELECT 1 FROM limit_fallback_evaluations WHERE sessionKey=?1",
                   [key]
                 )

        before = Org.get(ctx.db, key)
        write_archetype!(ctx.base, fallback: true)
        publish_identity!(ctx.base)
        Archetypes.load!(ctx.base)

        after_publish = Org.get(ctx.db, key)
        assert after_publish.harness == before.harness
        assert after_publish.model == before.model
        refute LimitFallback.fallback_active?(after_publish)

        deliver!(ctx, key, "configured-limit")
        {evaluation, _seq} = await_hold!(ctx, key)
        assert evaluation.() == :applied
        assert Org.get(ctx.db, key).harness == "claude"
      end,
      fallback: false
    )
  end

  # Test 17a.
  test "a candidate failure after the prechecks is withheld switch-failed and releases the hold" do
    with_gateway(fn ctx ->
      key = "switch-candidate-failure"
      session!(ctx, key)
      lane!(ctx, key)

      :ok =
        GenServer.call(ctx.claude, {:set, :candidate, {:error, :deliberate_candidate_failure}})

      assignment = assign!(ctx, key, "held work")

      deliver!(ctx, key, "limited")
      {evaluation, seq} = await_hold!(ctx, key)

      assert evaluation.() == :withheld
      assert_received {:candidate, :claude, _model, _guidance}
      assert_withheld!(ctx, key, seq, "switch-failed:model_apply_failed")
      assert process_attests(ctx.db, assignment.id) == []

      session = Org.get(ctx.db, key)
      assert session.model == source_model()
      refute LimitFallback.fallback_active?(session)
    end)
  end

  # Test 17b.
  test "a gateway start releases a standing hold as switch-failed:interrupted and the lane claims" do
    with_gateway(fn ctx ->
      key = "switch-interrupted"
      session!(ctx, key)
      lane = lane!(ctx, key)

      :ok =
        GenServer.call(
          ctx.codex,
          {:set, :prompt,
           fn
             1, _text, _opts -> {:error, @codex_limit}
             n, _text, _opts -> ok_reply(n)
           end}
        )

      deliver!(ctx, key, "limited")
      {_evaluation, seq} = await_hold!(ctx, key)
      waiting = deliver!(ctx, key, "queued-after-restart")
      SessionLane.nudge(key)
      assert %{task_ref: nil} = :sys.get_state(lane)
      assert turn_status(ctx.db, waiting) == "queued"

      # The gateway's start composition, as on a restart.
      _children = Gateway.children(ctx.config)

      assert_withheld!(ctx, key, seq, "switch-failed:interrupted")

      SessionLane.nudge(key)
      assert_receive {:prompted, :codex, 2, text}, 15_000
      assert text =~ "queued-after-restart"
    end)
  end

  # Test 18 (v1.4 R11, R14, R15, V5). The session fails again with no
  # delivered turn in between, as the retry lineage re-fails it; here each
  # failure is a fresh message, which ends the same way.
  test "a withheld outcome is announced once per limit episode, and an applied one still emits" do
    with_gateway(fn ctx ->
      key = "switch-episode"
      session!(ctx, key)
      lane!(ctx, key)

      {:ok, _session} =
        DB.transaction(
          ctx.db,
          &LimitFallback.set_restriction_in_txn(&1, key, :off, "user:" <> @owner, "test 18")
        )

      # Episode 1: three typed limits, no delivered turn between them.
      [first, second, third] =
        for token <- ~w(episode-one-a episode-one-b episode-one-c) do
          deliver!(ctx, key, token)
          {evaluation, seq} = await_hold!(ctx, key)
          assert evaluation.() == :withheld
          assert evaluation_outcome(ctx.db, key, seq) == {"withheld", "restricted"}
          refute LimitFallback.held?(ctx.db, key)
          seq
        end

      assert first < second and second < third
      assert Org.get(ctx.db, key).harness == "codex"

      assert [[@main, "blocker", nil, notice]] = notices(ctx.db, key)
      assert notice =~ "(reason restricted)"
      assert notice =~ "turn #{first}"
      assert count(ctx.db, "condition_facts", key, "session-model-fallback-withheld") == 1
      assert lifecycle_count(ctx.db, key, "session-model-fallback-withheld") == 3
      assert alert_keys(ctx.db, key) == ["model-fallback:#{key}:withheld:#{first}"]

      assert withheld_lifecycle(ctx.db, key) == [
               {"turn:#{first}", first, true},
               {"turn:#{second}", first, false},
               {"turn:#{third}", first, false}
             ]

      # Every failed turn keeps today's replay vehicle, announced or not.
      for seq <- [first, second, third] do
        assert {:ok, [[1]]} =
                 DB.query(
                   ctx.db,
                   "SELECT COUNT(*) FROM health_redelivery_attempts WHERE sourceTurnSeq=?1",
                   [seq]
                 )
      end

      # A delivered turn ends the episode.
      :ok = GenServer.call(ctx.codex, {:set, :prompt, fn n, _text, _opts -> ok_reply(n) end})
      delivered = deliver!(ctx, key, "episode-break")
      await_turns_settled!(ctx.db, key)
      assert turn_status(ctx.db, delivered) == "delivered"

      # Episode 2: the next typed limit is announced once more.
      :ok =
        GenServer.call(
          ctx.codex,
          {:set, :prompt, fn _n, _text, _opts -> {:error, @codex_limit} end}
        )

      fourth = deliver!(ctx, key, "episode-two-a")
      {evaluation, ^fourth} = await_hold!(ctx, key)
      assert evaluation.() == :withheld

      assert [[@main, "blocker", nil, _], [@main, "blocker", nil, notice]] =
               notices(ctx.db, key)

      assert notice =~ "turn #{fourth}"
      assert count(ctx.db, "condition_facts", key, "session-model-fallback-withheld") == 2
      assert lifecycle_count(ctx.db, key, "session-model-fallback-withheld") == 4

      assert alert_keys(ctx.db, key) ==
               Enum.sort([
                 "model-fallback:#{key}:withheld:#{first}",
                 "model-fallback:#{key}:withheld:#{fourth}"
               ])

      assert List.last(withheld_lifecycle(ctx.db, key)) == {"turn:#{fourth}", fourth, true}

      # Later in episode 2 the session qualifies: the applied outcome emits
      # as normal.
      {:ok, _session} =
        DB.transaction(
          ctx.db,
          &LimitFallback.set_restriction_in_txn(&1, key, :on, "user:" <> @owner, nil)
        )

      fifth = deliver!(ctx, key, "episode-two-b")
      {evaluation, ^fifth} = await_hold!(ctx, key)
      assert evaluation.() == :applied
      assert evaluation_outcome(ctx.db, key, fifth) == {"applied", nil}
      assert Org.get(ctx.db, key).harness == "claude"

      assert [[@main, "fyi", nil, applied_notice]] =
               Enum.filter(notices(ctx.db, key), &match?([_, "fyi", _, _], &1))

      assert applied_notice =~ "turn #{fifth}"
      assert count(ctx.db, "condition_facts", key, "session-model-fallback-applied") == 1
      assert lifecycle_count(ctx.db, key, "session-model-fallback-applied") == 1
      assert "model-fallback:#{key}:turn:#{fifth}" in alert_keys(ctx.db, key)
      assert length(alert_keys(ctx.db, key)) == 3

      # Nothing withheld moved.
      assert length(notices(ctx.db, key)) == 3
      assert count(ctx.db, "condition_facts", key, "session-model-fallback-withheld") == 2
      assert lifecycle_count(ctx.db, key, "session-model-fallback-withheld") == 4

      # The episode claim is on the evaluation record that announced it.
      assert {:ok,
              [
                [^first, ^first],
                [^second, nil],
                [^third, nil],
                [^fourth, ^fourth],
                [^fifth, nil]
              ]} =
               DB.query(
                 ctx.db,
                 """
                 SELECT turnSeq, withheldEpisode FROM limit_fallback_evaluations
                 WHERE sessionKey=?1 ORDER BY turnSeq
                 """,
                 [key]
               )
    end)
  end

  # Review residual R-a (R5, N1). The evaluation starts before the held
  # turn's health publication, in a task the lane does not own. A publication
  # that raises crashes the lane after the terminal commit; the evaluation
  # still ends the hold with exactly one outcome, and the restarted lane
  # claims again, with no gateway restart.
  test "a lane that crashes after the hold commits still gets one outcome and claims again" do
    parent = self()

    with_gateway(
      fn ctx ->
        key = "switch-lane-crash"
        session!(ctx, key)
        lane = lane!(ctx, key)
        lane_ref = Process.monitor(lane)

        # The evaluation waits inside its prechecks until the lane restarted,
        # so its tune meets the restarted lane, not a dying one.
        in_window!(:anthropic, fn ->
          send(parent, {:evaluation_running, self()})

          receive do
            :continue_evaluation -> :ok
          end
        end)

        deliver!(ctx, key, "limited")

        assert_receive {:DOWN, ^lane_ref, :process, ^lane,
                        {%RuntimeError{message: "deliberate publication failure"}, _stack}},
                       15_000

        # The evaluation started before the publication raised, and the
        # lane's crash did not stop it.
        assert_receive {:evaluation_running, evaluation}, 15_000
        refute evaluation == lane
        assert Process.alive?(evaluation)

        assert {:ok, [[seq, nil]]} =
                 DB.query(
                   ctx.db,
                   "SELECT turnSeq, outcome FROM limit_fallback_evaluations WHERE sessionKey=?1",
                   [key]
                 )

        assert turn_status(ctx.db, seq) == "failed"

        # The restarted lane claims nothing while the hold stands.
        restarted = await_restarted_lane!(key, lane)
        waiting = deliver!(ctx, key, "queued-after-crash")
        SessionLane.nudge(key)
        assert %{task_ref: nil} = :sys.get_state(restarted)
        assert turn_status(ctx.db, waiting) == "queued"
        assert LimitFallback.held?(ctx.db, key)

        send(evaluation, :continue_evaluation)

        # Exactly one outcome: the switch, which the gated evaluation reaches
        # through the restarted lane. Its commit released the hold.
        assert await_outcome!(ctx.db, key, seq) == {"applied", nil}
        refute LimitFallback.held?(ctx.db, key)

        assert {:ok, [[1]]} =
                 DB.query(
                   ctx.db,
                   "SELECT COUNT(*) FROM limit_fallback_evaluations WHERE sessionKey=?1",
                   [key]
                 )

        assert lifecycle_count(ctx.db, key, "session-model-fallback-applied") == 1
        assert lifecycle_count(ctx.db, key, "session-model-fallback-withheld") == 0
        assert Org.get(ctx.db, key).harness == "claude"

        # The restarted lane claims again, on the fallback.
        assert ordered_tokens(:claude, ["queued-after-crash"]) == ["queued-after-crash"]
        await_turns_settled!(ctx.db, key)
        assert_ran_once!(ctx.db, key, ["queued-after-crash"])
      end,
      evaluation: :task,
      on_held_failure_publication: fn -> raise "deliberate publication failure" end
    )
  end

  # Review finding (5). The evaluation reads the session's engine before the
  # tune lock. An owner tune that lands after that read and before the swap
  # changes the engine the switch would record as `from` and name in the
  # switch-back command; the interlock re-judges the read against the row the
  # swap replaces and rolls the swap back.
  test "an owner selection tune before the swap withholds the switch as switch-failed:stale" do
    with_gateway(
      fn ctx ->
        key = "switch-stale"
        session!(ctx, key)
        lane!(ctx, key)
        deliver!(ctx, key, "limited")
        {evaluation, seq} = await_hold!(ctx, key)

        %{harness_session_id: sid} = Org.current_pointer(ctx.db, key)
        owner_choice = %{source_model() | effort: "medium"}

        in_window!(:anthropic, fn ->
          # The live harness takes the new effort in place, as Codex does.
          :ok = GenServer.call(ctx.codex, {:apply_model, sid, owner_choice})

          result =
            owner_tune(ctx, key, %{setting: "set_reasoning", reasoningLevel: "medium"})

          send(ctx.parent, {:owner_tune, result})
        end)

        assert evaluation.() == :withheld
        assert_received {:owner_tune, %{ok: true}}

        # The switch reached its swap: the candidate was prepared, and the
        # interlock rolled the swap back.
        assert_received {:candidate, :claude, _model, _guidance}
        assert_withheld!(ctx, key, seq, "switch-failed:stale")

        # The owner's selection stands.
        assert Org.get(ctx.db, key).model == owner_choice
      end,
      codex_efforts: ~w(low medium)
    )
  end

  # Review finding (5), the marker half: `tune --limit-fallback off` takes no
  # tune lock, so the interlock re-checks the marker inside the swap
  # transaction and withholds as `restricted`, the reason R4.2 names.
  test "a --limit-fallback off before the swap withholds the switch as restricted" do
    with_gateway(fn ctx ->
      key = "switch-restricted-late"
      session!(ctx, key)
      lane!(ctx, key)
      deliver!(ctx, key, "limited")
      {evaluation, seq} = await_hold!(ctx, key)

      in_window!(:anthropic, fn ->
        result =
          owner_tune(ctx, key, %{
            setting: "set_limit_fallback",
            limit_fallback: "off",
            limit_fallback_reason: "landed mid-evaluation"
          })

        send(ctx.parent, {:owner_tune, result})
      end)

      assert evaluation.() == :withheld
      assert_received {:owner_tune, %{ok: true, limit_fallback: "off"}}
      assert_received {:candidate, :claude, _model, _guidance}
      assert_withheld!(ctx, key, seq, "restricted")
      assert LimitFallback.restricted?(Org.get(ctx.db, key))
    end)
  end

  ## Shared assertions

  defp assert_withheld!(ctx, key, seq, reason) do
    assert evaluation_outcome(ctx.db, key, seq) == {"withheld", reason}
    refute LimitFallback.held?(ctx.db, key)

    session = Org.get(ctx.db, key)
    assert session.harness == "codex"
    refute LimitFallback.fallback_active?(session)

    assert [[_recipient, "blocker", _assignment, notice]] = notices(ctx.db, key)
    assert notice =~ "could not switch to its limit fallback"
    assert notice =~ "(reason #{reason})"
    assert notice =~ "turn #{seq}"
    assert notice =~ "not staffing or a transfer"

    assert count(ctx.db, "condition_facts", key, "session-model-fallback-withheld") == 1
    assert count(ctx.db, "condition_facts", key, "session-model-fallback-applied") == 0
    assert lifecycle_count(ctx.db, key, "session-model-fallback-withheld") == 1

    # v1.4 R15: a withheld alert is keyed by its limit episode; this is the
    # session's only limit failure, so the episode begins at `seq`.
    assert [["model-fallback", dedupe, title, _body]] = alerts(ctx.db, key)
    assert dedupe == "model-fallback:#{key}:withheld:#{seq}"
    assert title =~ "could not switch to a fallback model"

    # The failed turn keeps today's vehicles once the session is not switched.
    assert {:ok, [[1]]} =
             DB.query(
               ctx.db,
               "SELECT COUNT(*) FROM health_redelivery_attempts WHERE sourceTurnSeq=?1",
               [seq]
             )
  end

  ## Fixture

  defp with_gateway(fun, opts \\ []) do
    parent = self()

    scratch =
      Path.join(System.tmp_dir!(), "tightbeam-limit-switch-#{System.unique_integer([:positive])}")

    runtime = Tightbeam.GuardRuntimeFixture.prepare!(scratch, "limit_switch_unused.exs")
    base = runtime.base
    db_name = :"limit_switch_db_#{System.unique_integer([:positive])}"

    db =
      start_supervised!(
        {DB,
         path: Path.join(base, "state.db"),
         payload_root: runtime.payload,
         name: db_name,
         guard_inputs: []},
        id: db_name
      )

    :ok = DB.assert_base_admitted!(db, base)
    :initialized = Identity.init!(base)
    write_archetype!(base, opts)
    publish_identity!(base)
    :ok = Schema.ensure_all(db)
    Archetypes.load!(base)
    Devices.add_user(db, @owner, false)
    :ok = Org.put_setting(db, "owner-alerts-user", @owner)
    write_harness_files!(base)

    start_supervised!(
      {CatalogStub,
       %{
         {"testhost", "codex"} => [
           catalog_entry("synthetic-codex", Keyword.get(opts, :codex_efforts, "low"), :openai)
         ],
         {"testhost", "claude"} => [
           catalog_entry(
             "synthetic-claude",
             "high",
             Keyword.get(opts, :claude_provider, :anthropic)
           )
         ]
       }}
    )

    Application.put_env(:tightbeam, :base_dir, base)
    Application.put_env(:tightbeam, :autostart, false)
    Application.put_env(:tightbeam, :local_host_name, "testhost")

    start_supervised!({ConnRegistry, name: ConnRegistry}, id: :limit_switch_registry)
    start_supervised!({Registry, keys: :unique, name: Tightbeam.LaneRegistry})
    start_supervised!({Task.Supervisor, name: Tightbeam.TurnTaskSupervisor})
    start_supervised!({LaneDoorbell, nil})
    scheduler = start_supervised!({ReadinessDrain, db})
    task_sup = start_supervised!({Task.Supervisor, []}, id: :limit_switch_lane_tasks)

    codex =
      start_supervised!(
        {SwitchAdapter,
         name: :codex, parent: parent, prompt: fn _n, _text, _opts -> {:error, @codex_limit} end},
        id: :codex_adapter
      )

    claude =
      start_supervised!(
        {SwitchAdapter,
         name: :claude, parent: parent, prompt: fn n, _text, _opts -> ok_reply(n) end},
        id: :claude_adapter
      )

    coordinator = fn
      {:codex, "shared", "testhost"} -> {:ok, codex, 1}
      {:claude, "shared", "testhost"} -> {:ok, claude, 2}
    end

    {:ok, _coordinator} = CoordinatorStub.start_link({coordinator, nil})

    config = %{
      base_dir: base,
      cwd: base,
      db: db,
      port: 0,
      default_harness: :codex,
      default_model: source_model(),
      max_live_sessions_per_user: 50,
      wake_tick_ms: 1_000,
      onboarding_lease_ms: 1_800_000,
      model_catalog: Tightbeam.ModelCatalog,
      credential_status: fn provider, _machine ->
        run_window_hook(provider)

        if :persistent_term.get({__MODULE__, :denied_provider}, nil) == provider,
          do: {:needs_onboarding, :missing},
          else: :onboarded
      end,
      patch_adapter: fn _harness, _path -> :ok end
    }

    # By default the evaluation is handed to the test; `evaluation: :task`
    # keeps the production start, a supervised task.
    config =
      case Keyword.get(opts, :evaluation, :seam) do
        :seam ->
          Map.put(config, :limit_fallback_runner, fn evaluation ->
            send(parent, {:limit_fallback_evaluation, evaluation})
          end)

        :task ->
          config
      end

    config =
      case Keyword.fetch(opts, :on_held_failure_publication) do
        {:ok, probe} -> Map.put(config, :on_held_failure_publication, probe)
        :error -> config
      end

    # The start composition also loads the law (rules) the assign verb reads.
    runner = extract_runner!(config)

    Org.create(db, %{
      session_key: @main,
      display_name: "Main",
      kind: "main",
      is_built_in: true,
      owner_user_id: @owner,
      origin: "user:" <> @owner,
      archetype: @archetype,
      host: "testhost",
      harness: "codex",
      provider: "openai",
      model: source_model()
    })

    fun.(%{
      base: base,
      db: db,
      config: config,
      runner: runner,
      task_sup: task_sup,
      scheduler: scheduler,
      codex: codex,
      claude: claude,
      parent: parent
    })
  end

  ## Stale-turn settlement v1.1 R4/R5/R9 through the real turn runner. These
  ## reuse this module's gateway harness; they involve no limit or fallback.

  describe "stale-turn v1.1 R4/R5/R9" do
    @claude_process_exit %{
      "code" => -32_603,
      "message" =>
        "Internal error: The Claude Agent process exited unexpectedly. Please start a new session."
    }

    for {label, harness, failure} <- [
          {"the adapter process dies (transport loss)", :codex,
           Macro.escape({:adapter_unavailable, "acp exited with status 137"})},
          {"the harness answers with its process-exit error", :claude,
           Macro.escape(@claude_process_exit)}
        ] do
      test "R4: a dispatched turn ended because #{label} settles unknown_effect, is surfaced once and never replayed" do
        failure = unquote(failure)
        harness = unquote(harness)

        with_gateway(fn ctx ->
          key = "s1-exit-#{harness}"
          s1_session!(ctx, key, harness)
          lane!(ctx, key)

          :ok =
            GenServer.call(
              Map.fetch!(ctx, harness),
              {:set, :prompt,
               fn
                 1, _text, opts ->
                   # The prompt reached the adapter transport, then the
                   # harness went away.
                   Keyword.fetch!(opts, :trace_dispatch).(101)
                   {:error, failure}

                 n, _text, _opts ->
                   ok_reply(n)
               end}
            )

          seq = deliver!(ctx, key, "s1-killed-prompt")
          await_turns_settled!(ctx.db, key)

          assert turn_status(ctx.db, seq) == "failed_unknown"
          assert turn_error(ctx.db, seq) == "unknown_effect"
          assert terminal_cause(ctx.db, seq) == "harness_exited"
          assert unknown_effect_notices(ctx.db) == Enum.sort([key, @main])

          # R5: no replay vehicle, and a later delivered turn on the same
          # harness and host (today's redelivery trigger) re-sends nothing.
          assert redelivery_rows(ctx.db, seq) == 0
          next = deliver!(ctx, key, "s1-next-prompt")
          await_turns_settled!(ctx.db, key)
          assert turn_status(ctx.db, next) == "delivered"
          assert same_message_turns(ctx.db, seq) == [seq]
          assert unknown_effect_notices(ctx.db) == Enum.sort([key, @main])
        end)
      end
    end

    test "R4: a turn whose prompt was never dispatched keeps its known failure" do
      with_gateway(fn ctx ->
        key = "s1-undispatched"
        session!(ctx, key)
        lane!(ctx, key)

        :ok =
          GenServer.call(
            ctx.codex,
            {:set, :prompt,
             fn _n, _text, _opts ->
               {:error, {:adapter_unavailable, "acp exited with status 137"}}
             end}
          )

        seq = deliver!(ctx, key, "s1-not-dispatched")
        await_turns_settled!(ctx.db, key)
        assert turn_status(ctx.db, seq) == "failed"
        refute turn_error(ctx.db, seq) == "unknown_effect"
        assert unknown_effect_notices(ctx.db) == []
      end)
    end
  end

  defp s1_session!(ctx, key, :codex), do: session!(ctx, key)

  defp s1_session!(ctx, key, :claude) do
    Org.create(ctx.db, %{
      session_key: key,
      display_name: "S1 " <> key,
      owner_user_id: @owner,
      origin: "user:" <> @owner,
      archetype: @archetype,
      host: "testhost",
      harness: "claude",
      provider: "anthropic",
      model: fallback_model()
    })
  end

  defp turn_error(db, seq) do
    {:ok, [[error]]} = DB.query(db, "SELECT error FROM turns WHERE seq=?1", [seq])
    error
  end

  defp terminal_cause(db, seq) do
    {:ok, [[cause]]} =
      DB.query(
        db,
        "SELECT cause FROM turn_lifecycle_events WHERE turnSeq=?1 AND kind='terminal_committed'",
        [seq]
      )

    cause
  end

  defp unknown_effect_notices(db) do
    {:ok, rows} =
      DB.query(
        db,
        "SELECT sessionKey FROM wakes WHERE wakeId LIKE 'w_turn_unknown_effect_%' ORDER BY sessionKey"
      )

    Enum.map(rows, &hd/1)
  end

  defp redelivery_rows(db, seq) do
    {:ok, [[count]]} =
      DB.query(db, "SELECT COUNT(*) FROM health_redelivery_attempts WHERE sourceTurnSeq=?1", [seq])

    count
  end

  defp same_message_turns(db, seq) do
    {:ok, rows} =
      DB.query(
        db,
        "SELECT t.seq FROM turns t JOIN turns s ON s.messageId=t.messageId WHERE s.seq=?1 ORDER BY t.seq",
        [seq]
      )

    Enum.map(rows, &hd/1)
  end

  defp extract_runner!(config) do
    {Tightbeam.LaneManager, lane_opts} =
      config
      |> Gateway.children()
      |> Enum.find(&match?({Tightbeam.LaneManager, _}, &1))

    Keyword.fetch!(lane_opts, :runner)
  end

  defp session!(ctx, key) do
    Org.create(ctx.db, %{
      session_key: key,
      display_name: "Switch " <> key,
      owner_user_id: @owner,
      origin: "user:" <> @owner,
      archetype: @archetype,
      host: "testhost",
      harness: "codex",
      provider: "openai",
      model: source_model()
    })
  end

  defp lane!(ctx, key) do
    start_supervised!(%{
      id: {:lane, key},
      start:
        {SessionLane, :start_link,
         [
           [
             session_key: key,
             db: ctx.db,
             task_sup: ctx.task_sup,
             runner: ctx.runner,
             wake_scheduler: ctx.scheduler
           ]
         ]}
    })
  end

  # The owner's client post (the `post` verb's delivery) to a session with no
  # turn in flight: appended as one turn. Returns that turn's seq.
  defp deliver!(ctx, key, text) do
    assert :appended = post(ctx, key, text)
    seq = turn_seq(ctx.db, key, text)
    assert is_integer(seq)
    seq
  end

  # The same post while the session has a turn in flight: staged as a pending
  # prompt wake behind it, with no turn yet. Returns the staged wake's id.
  defp stage!(ctx, key, text) do
    assert :queued = post(ctx, key, text)

    assert {:ok, [[wake_id, "pending", nil]]} =
             DB.query(
               ctx.db,
               """
               SELECT wakeId, state, deliveredTurnSeq FROM wakes
               WHERE sessionKey=?1 AND consumer='prompt' AND prompt=?2
               """,
               [key, text]
             )

    assert turn_seq(ctx.db, key, text) == nil
    wake_id
  end

  defp post(ctx, key, text) do
    Gateway.deliver_prompt(key, "user:" <> @owner, text,
      db: ctx.db,
      device_id: "synthetic-device",
      client_message_id: "#{key}-#{text}-#{System.unique_integer([:positive])}",
      creator_session_key: key,
      lane_manager: Tightbeam.LaneManager,
      conn_registry: ConnRegistry
    )
  end

  defp await_turn_seq!(db, key, text, attempts \\ 300) do
    case turn_seq(db, key, text) do
      seq when is_integer(seq) ->
        seq

      nil when attempts == 0 ->
        flunk("#{key} has no turn for #{text}")

      nil ->
        # Polled: the readiness drain admits staged posts on its own schedule.
        Process.sleep(50)
        await_turn_seq!(db, key, text, attempts - 1)
    end
  end

  # Each token's post ran as exactly one turn, which delivered.
  defp assert_ran_once!(db, key, tokens) do
    for token <- tokens do
      assert {:ok, [["delivered"]]} =
               DB.query(
                 db,
                 """
                 SELECT t.status FROM turns t JOIN messages m ON m.id=t.messageId
                 WHERE t.sessionKey=?1 AND m.content=?2
                 """,
                 [key, token]
               )
    end
  end

  defp block_first_codex_prompt!(ctx) do
    :ok =
      GenServer.call(
        ctx.codex,
        {:set, :prompt,
         fn
           1, _text, _opts ->
             receive do
               :release_prompt -> {:error, @codex_limit}
             end

           _n, _text, _opts ->
             {:error, @codex_limit}
         end}
      )
  end

  # Runs `hook` once, in the evaluation's process, at its first credential
  # check for `provider`: the R4.7 prechecks, after the evaluation read the
  # session and before the tune takes its lock.
  defp in_window!(provider, hook) do
    :persistent_term.put({__MODULE__, :window}, {provider, hook})
    on_exit(fn -> :persistent_term.erase({__MODULE__, :window}) end)
  end

  defp run_window_hook(provider) do
    case :persistent_term.get({__MODULE__, :window}, nil) do
      {^provider, hook} ->
        :persistent_term.erase({__MODULE__, :window})
        hook.()

      _ ->
        :ok
    end
  end

  defp owner_tune(ctx, key, params) do
    Gateway.handlers(ctx.config)["tune"].(%{
      origin: "user:" <> @owner,
      principal: {:user, @owner},
      session_key: key,
      params: params
    })
  end

  # The session's lane registered under a pid other than `old`.
  defp await_restarted_lane!(key, old, attempts \\ 300) do
    case Registry.lookup(Tightbeam.LaneRegistry, key) do
      [{pid, _}] when pid != old ->
        pid

      _ when attempts == 0 ->
        flunk("#{key}'s lane did not restart")

      _ ->
        # Polled: the supervisor restarts the lane on its own schedule.
        Process.sleep(50)
        await_restarted_lane!(key, old, attempts - 1)
    end
  end

  defp await_outcome!(db, key, seq, attempts \\ 300) do
    case evaluation_outcome(db, key, seq) do
      {nil, _reason} when attempts == 0 ->
        flunk("#{key} turn #{seq} has no limit-fallback outcome")

      {nil, _reason} ->
        # Polled: the evaluation runs in its own task.
        Process.sleep(50)
        await_outcome!(db, key, seq, attempts - 1)

      outcome ->
        outcome
    end
  end

  defp await_hold!(ctx, key) do
    assert_receive {:limit_fallback_evaluation, evaluation}, 15_000

    {:ok, [[seq]]} =
      DB.query(
        ctx.db,
        "SELECT turnSeq FROM limit_fallback_evaluations WHERE sessionKey=?1 AND outcome IS NULL",
        [key]
      )

    {evaluation, seq}
  end

  defp assign!(ctx, key, subject) do
    Assignments.__handle__(ctx.db, "assign", %{
      verb: "assign",
      origin: "user:" <> @owner,
      principal: {:user, @owner},
      session_key: key,
      target_role: nil,
      role_fallback: false,
      supervision_interval_ms: 3_600_000,
      params: %{subject: subject, idempotency_key: nil, work_item_id: nil}
    })
  end

  # Collect this adapter's prompts until every token has run, then return the
  # tokens in the order they ran (other traffic, such as assignment notices,
  # is ignored). A token that ran twice appears twice.
  defp ordered_tokens(name, tokens), do: collect_tokens(name, tokens, [])

  defp collect_tokens(name, tokens, seen) do
    if Enum.all?(tokens, &(&1 in seen)) do
      Enum.reverse(seen)
    else
      receive do
        {:prompted, ^name, _n, text} ->
          case Enum.find(tokens, &String.contains?(text, &1)) do
            nil -> collect_tokens(name, tokens, seen)
            token -> collect_tokens(name, tokens, [token | seen])
          end
      after
        15_000 -> flunk("#{name} ran only #{inspect(Enum.reverse(seen))} of #{inspect(tokens)}")
      end
    end
  end

  defp await_turns_settled!(db, key, attempts \\ 300) do
    {:ok, [[open]]} =
      DB.query(
        db,
        "SELECT COUNT(*) FROM turns WHERE sessionKey=?1 AND status IN ('queued','running')",
        [key]
      )

    cond do
      open == 0 ->
        :ok

      attempts == 0 ->
        flunk("#{key} still has #{open} queued or running turns")

      true ->
        # Polled: the lane commits each terminal on its own schedule.
        Process.sleep(50)
        await_turns_settled!(db, key, attempts - 1)
    end
  end

  defp insert_tool_call!(db, key, seq) do
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

  ## Reads

  # The latest turn carrying `text`'s message, or nil while it has none.
  defp turn_seq(db, key, text) do
    {:ok, rows} =
      DB.query(
        db,
        """
        SELECT t.seq FROM turns t JOIN messages m ON m.id=t.messageId
        WHERE t.sessionKey=?1 AND m.content LIKE '%' || ?2 || '%'
        ORDER BY t.seq DESC LIMIT 1
        """,
        [key, text]
      )

    case rows do
      [[seq]] -> seq
      [] -> nil
    end
  end

  defp turn_status(db, seq) do
    {:ok, [[status]]} = DB.query(db, "SELECT status FROM turns WHERE seq=?1", [seq])
    status
  end

  defp delivered_turn(db, wake_id) do
    {:ok, [[seq]]} =
      DB.query(db, "SELECT deliveredTurnSeq FROM wakes WHERE wakeId=?1", [wake_id])

    seq
  end

  defp message_count(db, key, content) do
    {:ok, [[count]]} =
      DB.query(
        db,
        "SELECT COUNT(*) FROM messages WHERE sessionKey=?1 AND content LIKE '%' || ?2 || '%'",
        [
          key,
          content
        ]
      )

    count
  end

  defp evaluation_outcome(db, key, seq) do
    {:ok, [[outcome, reason]]} =
      DB.query(
        db,
        "SELECT outcome, reason FROM limit_fallback_evaluations WHERE sessionKey=?1 AND turnSeq=?2",
        [key, seq]
      )

    {outcome, reason}
  end

  defp process_attests(db, assignment_id) do
    {:ok, rows} =
      DB.query(
        db,
        "SELECT note FROM attests WHERE assignmentId=?1 AND byProcess='process:tightbeam'",
        [assignment_id]
      )

    rows
  end

  defp notices(db, key) do
    {:ok, rows} =
      DB.query(
        db,
        """
        SELECT sessionKey, class, assignmentId, prompt FROM wakes
        WHERE wakeId LIKE 'w_limit_fallback_%' AND origin='process:tightbeam'
          AND instr(prompt, '(' || ?1 || ')') > 0
        ORDER BY createdAt, wakeId
        """,
        [key]
      )

    rows
  end

  defp count(db, "condition_facts", key, kind) do
    {:ok, [[count]]} =
      DB.query(
        db,
        "SELECT COUNT(*) FROM condition_facts WHERE kind=?1 AND scope=?2 AND origin='process:tightbeam'",
        [kind, key]
      )

    count
  end

  defp lifecycle_count(db, key, kind) do
    {:ok, [[count]]} =
      DB.query(db, "SELECT COUNT(*) FROM lifecycle_events WHERE kind=?1 AND subject=?2", [
        kind,
        key
      ])

    count
  end

  defp alerts(db, key) do
    {:ok, rows} =
      DB.query(
        db,
        "SELECT kind, dedupeKey, title, body FROM owner_alerts WHERE kind='model-fallback' AND sessionKey=?1",
        [key]
      )

    rows
  end

  defp alert_keys(db, key) do
    db
    |> alerts(key)
    |> Enum.map(fn [_kind, dedupe, _title, _body] -> dedupe end)
    |> Enum.sort()
  end

  # Each withheld lifecycle event of the session, in order: its trigger, the
  # first failed turn of its limit episode, and whether it announced.
  defp withheld_lifecycle(db, key) do
    {:ok, rows} =
      DB.query(
        db,
        """
        SELECT detail FROM lifecycle_events
        WHERE kind='session-model-fallback-withheld' AND subject=?1 ORDER BY id
        """,
        [key]
      )

    Enum.map(rows, fn [detail] ->
      detail = JSON.decode!(detail)
      {detail["trigger"], detail["episode"], detail["announced"]}
    end)
  end

  defp retry_rows(db, seq) do
    {:ok, rows} =
      DB.query(
        db,
        "SELECT sourceTurnSeq, outcome, retryWakeId FROM wake_retry_attempts WHERE sourceTurnSeq=?1",
        [seq]
      )

    rows
  end

  ## Values

  defp source_model, do: Model.new("synthetic-codex", effort: "low")
  defp fallback_model, do: Model.new("synthetic-claude", effort: "high")

  defp ok_reply(n) do
    {:ok,
     %{
       text: "reply #{n}",
       messages: [
         %{message_id: "reply-#{n}-#{System.unique_integer([:positive])}", text: "reply #{n}"}
       ],
       stop_reason: "end_turn"
     }}
  end

  defp claude_limit(reset_at) do
    reset = DateTime.from_unix!(reset_at, :millisecond)
    hour = rem(reset.hour + 11, 12) + 1
    period = if reset.hour < 12, do: "am", else: "pm"
    minute = reset.minute |> Integer.to_string() |> String.pad_leading(2, "0")

    %{
      "code" => -32_603,
      "data" => %{"errorKind" => "rate_limit"},
      "message" => "Limit reached · resets #{hour}:#{minute}#{period} UTC"
    }
  end

  defp catalog_entry(family, effort, provider) do
    %{
      family: family,
      context: nil,
      display_name: family,
      name: family,
      efforts: List.wrap(effort),
      provider: provider
    }
  end

  defp iso(ms), do: ms |> DateTime.from_unix!(:millisecond) |> DateTime.to_iso8601()

  ## Identity and host files

  defp write_archetype!(base, opts) do
    fallback =
      if Keyword.get(opts, :fallback, true) do
        harness =
          case Keyword.get(opts, :fallback_harness) do
            nil -> ""
            value -> "harness = \"#{value}\"\n"
          end

        """

        [limit_fallback]
        model = "synthetic-claude"
        effort = "high"
        #{harness}
        """
      else
        ""
      end

    File.write!(Path.join([base, "identity", "archetypes", "#{@archetype}.toml"]), """
    name = "#{@archetype}"
    where = ["testhost"]

    [[model_preferences]]
    model = "synthetic-codex"
    effort = "low"

    [[model_preferences]]
    model = "synthetic-claude"
    effort = "high"
    #{fallback}
    """)
  end

  defp write_harness_files!(base) do
    bin = Path.join(base, "bin")
    File.mkdir_p!(bin)

    for name <- ["claude", "codex", "cursor", "pi", "fixture"] do
      path = Path.join(bin, name)
      File.write!(path, "#!/bin/sh\necho fixture-only\n")
      File.chmod!(path, 0o755)
    end

    for {harness, credential, content, adapter} <- [
          {:codex, "auth.json", "synthetic-credential", "codex-acp"},
          {:claude, ".credentials.json", ~s({"claudeAiOauth":{"accessToken":"test-token"}}),
           "claude-agent-acp"}
        ] do
      home = Tightbeam.Homes.home_path(base, "testhost", harness)
      File.mkdir_p!(home)
      File.write!(Path.join(home, credential), content)

      adapter_path = Path.join([base, "adapters", "node_modules", ".bin", adapter])
      File.mkdir_p!(Path.dirname(adapter_path))
      File.write!(adapter_path, "#!/bin/sh\n")
      File.chmod!(adapter_path, 0o755)
    end
  end

  defp publish_identity!(base) do
    identity = Path.join(base, "identity")
    git!(identity, ["add", "-A"])
    git!(identity, ["commit", "--allow-empty", "-m", "test: synthetic limit fallback switch"])
    candidate = git!(identity, ["rev-parse", "main"])
    expected_prior = git!(identity, ["rev-parse", "tightbeam/live"])

    {:ok, _revision} =
      Identity.publish_live!(base, %{
        expected_prior: expected_prior,
        candidate_revision: candidate,
        tree_fingerprint: String.duplicate("0", 64)
      })

    :ok
  end

  defp git!(dir, args) do
    env = [
      {"GIT_AUTHOR_NAME", "limit-fallback-test"},
      {"GIT_AUTHOR_EMAIL", "limit-fallback-test@tightbeam.invalid"},
      {"GIT_COMMITTER_NAME", "limit-fallback-test"},
      {"GIT_COMMITTER_EMAIL", "limit-fallback-test@tightbeam.invalid"}
    ]

    case System.cmd("git", args, cd: dir, env: env, stderr_to_stdout: true) do
      {output, 0} -> String.trim_trailing(output)
      {output, status} -> raise "git failed #{status}: #{output}"
    end
  end
end

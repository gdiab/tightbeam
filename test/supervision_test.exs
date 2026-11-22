defmodule Tightbeam.SupervisionTest do
  use Tightbeam.TestCase, async: false

  alias Tightbeam.{Assignments, DB, Gateway, Model, Org, Supervision, Wakes}

  setup do
    db = String.to_atom("supervision_db_#{System.unique_integer([:positive])}")
    start_supervised!({DB, path: ":memory:", name: db})
    ensure_all_schemas(db)

    {:ok, _} =
      DB.query(db, "INSERT INTO users (userId,isAdmin,createdAt) VALUES ('test-owner',1,1)")

    main = ensure_main_session(db, "test-owner")
    parent = session(db, "parent", main.session_key)
    holder = session(db, "holder", parent.session_key)

    %{db: db, main: main, parent: parent, holder: holder}
  end

  test "an aged open assignment creates no inactivity reminder or escalation and remains live",
       ctx do
    assignment = assign(ctx, "quiet work")
    old_opened_at = System.system_time(:millisecond) - 31 * 60 * 1_000

    assert {:ok, _} =
             DB.query(ctx.db, "UPDATE assignments SET openedAt=?2 WHERE id=?1", [
               assignment.id,
               old_opened_at
             ])

    assert {:ok, [[0]]} =
             DB.query(
               ctx.db,
               "SELECT COUNT(*) FROM wakes WHERE assignmentId=?1 AND consumer IN ('assignment_inactivity_deadline','assignment_inactivity_climb')",
               [assignment.id]
             )

    assert {:ok, [[0]]} =
             DB.query(
               ctx.db,
               "SELECT COUNT(*) FROM wakes WHERE assignmentId=?1 AND consumer='prompt' AND obligationRef LIKE 'assignment-inactivity-episode-v1:%'",
               [assignment.id]
             )

    assert {:ok, {:ok, %{kind: "supervision_entitlement", id: assignment_id}}} =
             DB.transaction(ctx.db, fn txn ->
               Supervision.liveness_trigger_in_txn(txn, {:assignment, assignment.id})
             end)

    assert assignment_id == assignment.id
  end

  test "assignment disposition and retirement continue without inactivity wakes", ctx do
    revoked = assign(ctx, "revoke without timer")

    assert %{state: "closed", outcome: "revoked"} =
             Assignments.__handle__(ctx.db, "revoke-assignment", %{
               verb: "revoke-assignment",
               origin: "user:test-owner",
               principal: {:user, "test-owner"},
               params: %{assignment_id: revoked.id, reason: "scope ended"}
             })

    retiree = session(ctx.db, "retiree", ctx.main.session_key)
    retirement_assignment = assign(ctx, "close on retirement", retiree.session_key)

    assert {:ok, [[0]]} =
             DB.query(
               ctx.db,
               "SELECT COUNT(*) FROM wakes WHERE assignmentId=?1 AND consumer IN ('assignment_inactivity_deadline','assignment_inactivity_climb')",
               [retirement_assignment.id]
             )

    assert %{retired_session_keys: [retired_key]} =
             Gateway.handlers(%{db: ctx.db})["retire"].(%{
               origin: "user:test-owner",
               principal: {:user, "test-owner"},
               session_key: retiree.session_key,
               params: %{}
             })

    assert retired_key == retiree.session_key
    assert Org.get(ctx.db, retiree.session_key).state == "retired"

    assert {:ok, [["closed", "revoked"]]} =
             DB.query(ctx.db, "SELECT state,outcome FROM assignments WHERE id=?1", [
               retirement_assignment.id
             ])
  end

  test "startup cancels only pending undelivered legacy inactivity wakes", ctx do
    assignment = assign(ctx, "upgrade compatibility")
    future = System.system_time(:millisecond) + 60_000

    deadline =
      legacy_wake(ctx, assignment.id, "assignment_inactivity_deadline",
        obligation_ref: "assignment-inactivity-deadline-v1:" <> assignment.id,
        due_at: future
      )

    climb =
      legacy_wake(ctx, assignment.id, "assignment_inactivity_climb",
        obligation_ref: "assignment-inactivity-episode-v1:" <> assignment.id,
        due_at: future
      )

    pending_prompt =
      legacy_wake(ctx, assignment.id, "prompt",
        obligation_ref: "assignment-inactivity-episode-v1:" <> assignment.id,
        due_at: future
      )

    delivered_prompt =
      legacy_wake(ctx, assignment.id, "prompt",
        obligation_ref: "assignment-inactivity-episode-v1:" <> assignment.id,
        due_at: future
      )

    condition_wait =
      Wakes.schedule(ctx.db, %{
        session_key: ctx.holder.session_key,
        origin: "agent:holder",
        creator_session_key: ctx.holder.session_key,
        prompt: "re-read the assignment after it lands",
        due_at: future,
        assignment_id: assignment.id,
        obligation_ref: assignment.id,
        condition_kind: "assignment-landed",
        condition_scope: assignment.id
      })

    assert {:ok, _} =
             DB.query(ctx.db, "UPDATE wakes SET deliveredTurnSeq=123 WHERE wakeId=?1", [
               delivered_prompt.wake_id
             ])

    assert :ok = Supervision.drain_legacy_inactivity_wakes(ctx.db)

    for wake <- [deadline, climb, pending_prompt] do
      assert %{state: "canceled"} = Wakes.get(ctx.db, wake.wake_id)
    end

    # A queued notice has already crossed the delivery boundary and cannot be recalled.
    assert %{state: "pending", delivered_turn_seq: 123} =
             Wakes.get(ctx.db, delivered_prompt.wake_id)

    # Ordinary condition waits are outside the legacy inactivity namespace.
    assert %{state: "pending", condition_kind: "assignment-landed"} =
             Wakes.get(ctx.db, condition_wait.wake_id)
  end

  # u41's 5d6af764 carry on 0.1.16, met by #683 (ruling att_c5cf3744): on the
  # integrated target nothing creates an idle wake for a session or a standing
  # card. Option 2's ladder armed a deadline when an assignment opened, re-armed
  # it on holder activity and dated continuations, climbed holder -> parent ->
  # Main (George), and re-armed every open card at boot. Each of those paths
  # runs here, and neither the holder's lineage nor George's Main gets a wake.
  test "no idle wake for a session or a standing card on any path the ladder used", ctx do
    idler = session(ctx.db, "idler", ctx.main.session_key)
    card = assign(ctx, "standing card")
    aged = System.system_time(:millisecond) - 24 * 60 * 60 * 1_000

    assert {:ok, _} =
             DB.query(ctx.db, "UPDATE assignments SET openedAt=?2 WHERE id=?1", [card.id, aged])

    assert %{attest: %{kind: "progress"}} =
             Assignments.__handle__(ctx.db, "attest", %{
               verb: "attest",
               origin: "agent:holder",
               principal: {:session, ctx.holder.session_key},
               session_key: nil,
               params: %{assignment_id: card.id, kind: "progress", note: "still working"}
             })

    handlers = Gateway.handlers(%{db: ctx.db, wake_tick_ms: 1_000})

    continuation =
      handlers["wake"].(%{
        verb: "wake",
        origin: "agent:holder",
        principal: {:session, ctx.holder.session_key},
        session_key: ctx.holder.session_key,
        params: %{prompt: "pick the card back up", after_ms: 60_000, assignment_id: card.id}
      })

    assert is_binary(continuation.wake_id)

    assert %{} =
             handlers["wake"].(%{
               verb: "wake",
               origin: "agent:holder",
               principal: {:session, ctx.holder.session_key},
               session_key: ctx.holder.session_key,
               params: %{cancel_wake_id: continuation.wake_id}
             })

    # The boot steps that touch open cards (option 2 re-armed each one here).
    assert :ok = Supervision.close_retired_holder_assignments(ctx.db)
    assert :ok = Supervision.drain_legacy_inactivity_wakes(ctx.db)

    assert {:ok, [[0]]} =
             DB.query(
               ctx.db,
               """
               SELECT COUNT(*) FROM wakes
               WHERE consumer IN ('assignment_inactivity_deadline','assignment_inactivity_climb')
                  OR obligationRef LIKE 'assignment-inactivity-%'
               """
             )

    for target <- [ctx.parent, ctx.main, idler] do
      assert {:ok, [[0]]} =
               DB.query(ctx.db, "SELECT COUNT(*) FROM wakes WHERE sessionKey=?1", [
                 target.session_key
               ]),
             target.session_key
    end

    assert %{state: "canceled"} = Wakes.get(ctx.db, continuation.wake_id)

    assert {:ok, [["open"]]} =
             DB.query(ctx.db, "SELECT state FROM assignments WHERE id=?1", [card.id])
  end

  defp assign(ctx, subject, session_key \\ nil) do
    session_key = session_key || ctx.holder.session_key

    result =
      Assignments.__handle__(ctx.db, "assign", %{
        verb: "assign",
        origin: "user:test-owner",
        principal: {:user, "test-owner"},
        session_key: session_key,
        target_role: nil,
        role_fallback: false,
        params: %{subject: subject, brief: "exercise the unchanged assignment path"}
      })

    assert %{id: id} = result
    %{id: id}
  end

  defp legacy_wake(ctx, assignment_id, consumer, options) do
    Wakes.schedule(ctx.db, %{
      session_key: ctx.holder.session_key,
      origin: "process:tightbeam",
      consumer: consumer,
      prompt: "legacy inactivity notification",
      due_at: Keyword.fetch!(options, :due_at),
      assignment_id: assignment_id,
      obligation_ref: Keyword.fetch!(options, :obligation_ref)
    })
  end

  defp session(db, key, parent_key) do
    Org.create(db, %{
      session_key: key,
      display_name: key,
      owner_user_id: "test-owner",
      origin: "user:test-owner",
      spawned_by: parent_key,
      kind: "custom",
      is_built_in: false,
      archetype: "default",
      harness: "claude",
      provider: "anthropic",
      model: Model.new("fable"),
      host: "testhost"
    })
  end
end

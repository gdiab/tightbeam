defmodule Tightbeam.QuotaRelease do
  @moduledoc """
  What every release of a quota park does, whichever trigger released it: the
  declared reset (quota v3 R9(a)), a later success (R9(b)) or an explicit
  resume (R9(c)). Each caller removes the fence and records its own cause
  first; this then runs in the same transaction.

  - Companion v1.1 B5: each quota-failed turn of the incident is classified by
    contract (c) R9a (`LimitFallback.Outcome.classify_in_txn/2`). A
    pre-activity (`:replayed`) turn keeps its existing replay vehicle: the
    rate-limit retry wake of a wake turn, or the health redelivery row of a
    message turn, each consumed at most once. A post-activity
    (`:unknown_effect`) turn is never replayed: the vehicles are not written for
    it (`Wakes`), a retry attempt still pending is settled, the disposition is
    recorded with cause `provider_quota`, and one item goes to the holder and
    the delivery owner (v3 R16). That happens where its vehicles are withheld
    (`surface_not_replayed_in_txn/2`), so it holds even when no incident ever
    opens; a release only catches a turn recorded before this existed.
  - Companion B5 (spec writer's ruling, asg_a4d1e7d6): a release by the
    declared reset or an explicit resume re-admits the key's pending
    pre-activity message turns itself, once each in seq order (`readmit: true`).
  - v3 R12: every active session on the key with a queued turn gets its lane
    ensured, so the queue drains in its original order.
  """

  alias Tightbeam.{EventLog, LimitFallback, Org, Wakes}
  alias Tightbeam.DB.Txn

  @process "process:tightbeam"

  @spec released_in_txn(Txn.t(), String.t(), String.t(), String.t(), keyword()) :: :ok
  def released_in_txn(%Txn{} = txn, incident_id, harness, host, opts \\ [])
      when is_binary(incident_id) and is_binary(harness) and is_binary(host) do
    txn
    |> quota_failed_turns_in_txn(incident_id)
    |> Enum.each(fn turn ->
      if LimitFallback.Outcome.classify_in_txn(txn, turn.seq) == :unknown_effect,
        do: not_replayed_in_txn(txn, incident_id, turn)
    end)

    # A release by the declared reset or an explicit resume is itself the
    # restoration of the key's pending pre-activity message turns: re-admitting
    # them must not wait for an unrelated turn to succeed (v3 V1). A release by
    # a later success already redelivers them from that success.
    if Keyword.get(opts, :readmit, false),
      do: Wakes.readmit_released_quota_intents_in_txn(txn, incident_id)

    Txn.q(
      txn,
      """
      SELECT DISTINCT s.sessionKey FROM sessions s
      JOIN turns t ON t.sessionKey=s.sessionKey
      WHERE s.harness=?1 AND s.host=?2 AND s.state='active' AND t.status='queued'
      """,
      [harness, host]
    )
    |> Enum.each(fn [session_key] ->
      Txn.handoff(txn, Tightbeam.LaneManager, {:ensure_lane, session_key})
    end)

    :ok
  end

  @doc """
  Whether a failed turn's quota failure was post-activity (contract (c) R9a's
  `:unknown_effect`), so no path may replay it (companion v1.1 B5, A2(iii)).
  """
  @spec post_activity_quota_failure_in_txn?(Txn.t(), pos_integer()) :: boolean()
  def post_activity_quota_failure_in_txn?(%Txn{} = txn, turn_seq)
      when is_integer(turn_seq) and turn_seq > 0 do
    quota_failure?(txn, turn_seq) and
      LimitFallback.Outcome.classify_in_txn(txn, turn_seq) == :unknown_effect
  end

  @doc """
  Record and surface one post-activity quota-failed turn as not replayed, at
  the point its replay vehicles are withheld (companion v1.1 B5, v3 R16). Its
  incident may not exist yet; a later release finds the item and adds nothing.
  """
  @spec surface_not_replayed_in_txn(Txn.t(), pos_integer()) :: :ok
  def surface_not_replayed_in_txn(%Txn{} = txn, turn_seq)
      when is_integer(turn_seq) and turn_seq > 0 do
    case Txn.q(
           txn,
           """
           SELECT t.seq,t.sessionKey,t.assignmentId,t.messageId,t.requestRef,
                  (SELECT o.incidentId FROM harness_health_observations o
                   WHERE o.correlationId='harness-turn:' || t.seq || ':rate-limit-dead'
                     AND o.evidenceKind IN ('terminal-failure','authoritative-provider')
                   LIMIT 1)
           FROM turns t WHERE t.seq=?1
           """,
           [turn_seq]
         ) do
      [[seq, session_key, assignment_id, message_id, request_ref, incident_id]] ->
        not_replayed_in_txn(txn, incident_id, %{
          seq: seq,
          session_key: session_key,
          assignment_id: assignment_id,
          message_id: message_id,
          request_ref: request_ref
        })

      [] ->
        :ok
    end
  end

  defp quota_failure?(txn, turn_seq) do
    Txn.q(
      txn,
      """
      SELECT 1 FROM harness_health_observations
      WHERE correlationId=?1 AND evidenceKind IN ('terminal-failure','authoritative-provider') LIMIT 1
      """,
      ["harness-turn:#{turn_seq}:rate-limit-dead"]
    ) != []
  end

  defp quota_failed_turns_in_txn(txn, incident_id) do
    txn
    |> Txn.q(
      """
      SELECT DISTINCT t.seq,t.sessionKey,t.assignmentId,t.messageId,t.requestRef
      FROM harness_health_observations o
      JOIN turns t ON o.correlationId = 'harness-turn:' || t.seq || ':rate-limit-dead'
      WHERE o.incidentId=?1 AND o.evidenceKind IN ('terminal-failure','authoritative-provider')
        AND t.status='failed'
        -- A c1-applied switch already disposed of and announced its failed
        -- turn (contract c R9b, R13); no second item (stale-turn R9).
        AND NOT EXISTS (
          SELECT 1 FROM limit_fallback_evaluations e
          WHERE e.turnSeq=t.seq AND e.outcome='applied'
        )
      ORDER BY t.seq
      """,
      [incident_id]
    )
    |> Enum.map(fn [seq, session_key, assignment_id, message_id, request_ref] ->
      %{
        seq: seq,
        session_key: session_key,
        assignment_id: assignment_id,
        message_id: message_id,
        request_ref: request_ref
      }
    end)
  end

  # One disposition per turn, however many releases its incident sees: the
  # holder's notice id is the turn's, so a later release finds it and stops.
  defp not_replayed_in_txn(txn, incident_id, turn) do
    holder_notice = notice_wake_id(turn.seq, turn.session_key)

    if Txn.q(txn, "SELECT 1 FROM wakes WHERE wakeId=?1", [holder_notice]) == [] do
      :ok = Wakes.settle_unreplayed_failure_in_txn(txn, turn.seq)

      EventLog.lifecycle_in_txn(
        txn,
        "quota_failed_turn_not_replayed",
        turn.session_key,
        JSON.encode!(%{
          turnSeq: turn.seq,
          incidentId: incident_id,
          disposition: "unknown_effect",
          cause: "provider_quota"
        })
      )

      txn
      |> recipients_in_txn(turn)
      |> Enum.each(fn recipient ->
        input = %{
          wake_id: notice_wake_id(turn.seq, recipient),
          session_key: recipient,
          origin: @process,
          prompt: notice_text(turn),
          due_at: System.system_time(:millisecond),
          class: "input-needed"
        }

        input =
          if is_binary(turn.assignment_id),
            do: Map.put(input, :assignment_id, turn.assignment_id),
            else: input

        Wakes.schedule_in_txn(txn, input)
      end)
    end

    :ok
  end

  # The holder, then the delivery owner of the turn's assignment, or the
  # holder's owner's Main when the turn served none. One item each.
  defp recipients_in_txn(txn, turn) do
    owner =
      case turn.assignment_id do
        assignment_id when is_binary(assignment_id) ->
          case Wakes.delivery_owner_in_txn(txn, assignment_id) do
            {:ok, recipient} -> recipient
            {:error, _} -> main_for_in_txn(txn, turn.session_key)
          end

        _ ->
          main_for_in_txn(txn, turn.session_key)
      end

    [turn.session_key, owner]
    |> Enum.reject(&is_nil/1)
    |> Enum.uniq()
    |> Enum.filter(fn key ->
      Txn.q(txn, "SELECT 1 FROM sessions WHERE sessionKey=?1 AND state='active'", [key]) ==
        [[1]]
    end)
  end

  defp main_for_in_txn(txn, session_key) do
    case Txn.q(txn, "SELECT ownerUserId FROM sessions WHERE sessionKey=?1", [session_key]) do
      [[owner]] when is_binary(owner) -> Org.personal_session_key(owner)
      _ -> nil
    end
  end

  defp notice_wake_id(turn_seq, recipient) do
    digest =
      :crypto.hash(:sha256, JSON.encode!(["quota-unknown-effect", turn_seq, recipient]))
      |> Base.encode16(case: :lower)
      |> binary_part(0, 32)

    "w_quota_unknown_effect_" <> digest
  end

  defp notice_text(turn) do
    assignment =
      if is_binary(turn.assignment_id), do: " for assignment #{turn.assignment_id}", else: ""

    """
    ## Usage limit: a failed turn was not replayed

    Turn #{turn.seq} of #{turn.session_key}#{assignment} failed on a provider usage limit after it had started work: it recorded tool calls or replies, so it may have had effects. Its quota park has been released, and the turn was NOT replayed (outcome unknown_effect, cause provider_quota). Its original request reference is #{turn.request_ref || "none"} (message #{turn.message_id || "none"}).

    Decide whether that request must be redone. Before acting on it, re-derive its state from the records (the transcript, tool calls, assignments and attests) and check whether its effects already happened.
    """
    |> String.trim_trailing()
  end
end

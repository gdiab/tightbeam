defmodule Tightbeam.UnknownEffect do
  @moduledoc """
  A dispatched turn whose harness-side effect Tightbeam cannot establish
  (stale-turn settlement v1.1, quota v3 R16). It is recorded as turn status
  `failed_unknown`, error `unknown_effect`, with its cause on the terminal
  lifecycle row: `harness_exited` (R4), `response_missing` (R6, R7) or
  `operator_settle` (R8).

  Such a turn is never replayed (R5): no health-redelivery row (the row needs
  a `failed` turn) and no rate-limit retry (it acts only on `failed`). It is
  surfaced here, once, as one item to the holder and one to the delivery owner
  (R9; v3 R16).
  """

  alias Tightbeam.{EventLog, Org, Wakes}
  alias Tightbeam.DB.Txn

  @error "unknown_effect"
  @causes ~w(harness_exited response_missing operator_settle)
  @process "process:tightbeam"

  @doc "The turn error an unknown-effect terminal carries."
  def error, do: @error

  @doc "The causes an unknown-effect terminal records."
  def causes, do: @causes

  @doc "Whether `seq`'s prompt was written to the adapter transport."
  @spec dispatched_in_txn?(Txn.t(), pos_integer()) :: boolean()
  def dispatched_in_txn?(%Txn{} = txn, seq) when is_integer(seq) do
    Txn.q(
      txn,
      "SELECT 1 FROM turn_lifecycle_events WHERE turnSeq=?1 AND kind='prompt_dispatched' LIMIT 1",
      [seq]
    ) != []
  end

  @doc """
  Record the unknown effect of terminal `seq` and surface it, once. Call it in
  the transaction that commits the terminal.
  """
  @spec record_in_txn(Txn.t(), pos_integer(), String.t()) :: :ok
  def record_in_txn(%Txn{} = txn, seq, cause) when is_integer(seq) and cause in @causes do
    case Txn.q(
           txn,
           "SELECT sessionKey,assignmentId,messageId,requestRef FROM turns WHERE seq=?1",
           [seq]
         ) do
      [[session_key, assignment_id, message_id, request_ref]] ->
        holder_notice = notice_wake_id(seq, session_key)

        if Txn.q(txn, "SELECT 1 FROM wakes WHERE wakeId=?1", [holder_notice]) == [] do
          EventLog.lifecycle_in_txn(
            txn,
            "turn_unknown_effect",
            session_key,
            JSON.encode!(%{turnSeq: seq, disposition: @error, cause: cause})
          )

          turn = %{
            seq: seq,
            session_key: session_key,
            assignment_id: assignment_id,
            message_id: message_id,
            request_ref: request_ref
          }

          txn
          |> recipients_in_txn(turn)
          |> Enum.each(fn recipient ->
            input = %{
              wake_id: notice_wake_id(seq, recipient),
              session_key: recipient,
              origin: @process,
              prompt: notice_text(turn, cause),
              due_at: System.system_time(:millisecond),
              class: "input-needed"
            }

            input =
              if is_binary(assignment_id),
                do: Map.put(input, :assignment_id, assignment_id),
                else: input

            Wakes.schedule_in_txn(txn, input)
          end)
        end

        :ok

      [] ->
        :ok
    end
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

  defp notice_wake_id(seq, recipient) do
    digest =
      :crypto.hash(:sha256, JSON.encode!(["turn-unknown-effect", seq, recipient]))
      |> Base.encode16(case: :lower)
      |> binary_part(0, 32)

    "w_turn_unknown_effect_" <> digest
  end

  defp notice_text(turn, cause) do
    assignment =
      if is_binary(turn.assignment_id), do: " for assignment #{turn.assignment_id}", else: ""

    """
    ## A turn ended with an unknown effect and was not replayed

    Turn #{turn.seq} of #{turn.session_key}#{assignment} was sent to its harness, but it ended without an answer Tightbeam can trust (cause #{cause}: #{cause_sentence(cause)}). It may have had effects, so it was NOT replayed. Its original request reference is #{turn.request_ref || "none"} (message #{turn.message_id || "none"}).

    Decide whether that request must be redone. Before acting on it, re-derive its state from the records (the transcript, tool calls, assignments and attests) and check whether its effects already happened.
    """
    |> String.trim_trailing()
  end

  defp cause_sentence("harness_exited"), do: "the harness process or its transport ended mid-turn"

  defp cause_sentence("response_missing"),
    do: "the harness ended its turn but never answered the prompt"

  defp cause_sentence("operator_settle"), do: "an operator settled the stale turn"
end

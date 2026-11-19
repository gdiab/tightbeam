defmodule Tightbeam.UnknownEffect do
  @moduledoc """
  A dispatched turn whose harness-side effect Tightbeam cannot establish
  (stale-turn settlement v1.1, quota v3 R16). It is recorded as turn status
  `failed_unknown`, error `unknown_effect`, with its cause on the terminal
  lifecycle row: `harness_exited` (R4), `response_missing` (R6, R7),
  `operator_settle` (R8) or `memory_limit` (memory limits v1.1 R9: a memory
  kill of the tree the prompt was pending on; [ST] A5 gains the cause).

  Such a turn is never replayed (R5): no health-redelivery row (the row needs
  a `failed` turn) and no rate-limit retry (it acts only on `failed`). It is
  surfaced here, once, as one item to the holder and one to the delivery owner
  (R9; v3 R16).
  """

  alias Tightbeam.{EventLog, Org, Wakes}
  alias Tightbeam.DB.Txn

  @error "unknown_effect"
  @causes ~w(harness_exited response_missing operator_settle memory_limit)
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
  @spec record_in_txn(Txn.t(), pos_integer(), String.t(), map()) :: :ok
  def record_in_txn(%Txn{} = txn, seq, cause, facts \\ %{})
      when is_integer(seq) and cause in @causes and is_map(facts) do
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
            JSON.encode!(
              Map.merge(lifecycle_facts(facts), %{turnSeq: seq, disposition: @error, cause: cause})
            )
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
              prompt: notice_text(turn, cause, facts),
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

  # Memory limits v1.1 R10/R15: which limit and scope, the tree's memory, or
  # the exit signal and whether the host was low on memory.
  defp lifecycle_facts(facts) do
    facts
    |> Map.take([
      :limit,
      :scope,
      :bytes,
      :limit_bytes,
      :mode,
      :exitSignal,
      :exitStatus,
      :hostLowOnMemory
    ])
    |> Enum.reject(fn {_key, value} -> is_nil(value) end)
    |> Map.new(fn
      {:limit_bytes, value} -> {:limitBytes, value}
      pair -> pair
    end)
  end

  # Memory limits v1.1 R11: in plain words, the work was stopped for using
  # more memory than its limit, which limit and its size, the tree's memory
  # when stopped if known, that what the turn did is unknown, and that it will
  # not be retried automatically.
  defp notice_text(turn, "memory_limit", facts) do
    assignment =
      if is_binary(turn.assignment_id), do: " for assignment #{turn.assignment_id}", else: ""

    limit =
      case Map.get(facts, :limit) do
        "budget" -> "the memory budget for all of Tightbeam's agents on this host"
        _ -> "the memory limit for one agent"
      end

    size = size_words(Map.get(facts, :limit_bytes))
    used = Map.get(facts, :bytes)

    """
    ## An agent's work was stopped because it used more memory than its limit

    Turn #{turn.seq} of #{turn.session_key}#{assignment} was stopped because the agent's processes used more memory than #{limit}#{if size, do: " (#{size})", else: ""}.#{if is_integer(used), do: " They held #{size_words(used)} when stopped.", else: ""} What the turn had already done is unknown, and it will NOT be retried automatically. Its original request reference is #{turn.request_ref || "none"} (message #{turn.message_id || "none"}).

    Decide whether that request must be redone, perhaps in smaller steps. Before acting on it, re-derive its state from the records (the transcript, tool calls, assignments and attests) and check whether its effects already happened.
    """
    |> String.trim_trailing()
  end

  defp notice_text(turn, cause, _facts) do
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

  defp size_words(bytes) when is_integer(bytes) and bytes > 0,
    do: :erlang.float_to_binary(bytes / (1024 * 1024 * 1024), decimals: 2) <> " GiB"

  defp size_words(_bytes), do: nil
end

defmodule Tightbeam.TurnSettlementView do
  @moduledoc """
  What the supported reads show of stale-turn settlement (v1.1 R10): an
  unknown-effect terminal's cause (`harness_exited`, `response_missing` or
  `operator_settle`), and the held state of a session's latest turn:

  - `in_flight_stalled`: the turn is running and P's harness turn is not live
    (R3: no turn activity within W and no tool call open);
  - `harness_exited`: the turn was settled under R4.

  Only turn rows, lifecycle causes and the adapter's liveness answer are
  read; no credential, private field, raw payload or process inventory.
  """

  alias Tightbeam.{DB, UnknownEffect}
  alias Tightbeam.Acp.Adapter

  @doc "SQL column: the terminal lifecycle cause of the `turns` row in scope."
  def cause_column_sql,
    do:
      "(SELECT e.cause FROM turn_lifecycle_events e WHERE e.turnSeq=turns.seq AND e.kind='terminal_committed' LIMIT 1)"

  @doc "The cause to show for a turn, or nil unless it ended as an unknown effect."
  @spec shown_cause(String.t() | nil, String.t() | nil, String.t() | nil) :: String.t() | nil
  def shown_cause("failed_unknown", error, cause) do
    if error == UnknownEffect.error() and cause in UnknownEffect.causes(), do: cause
  end

  def shown_cause(_status, _error, _cause), do: nil

  @doc "The session's latest turn, with its shown cause."
  @spec latest_turn(DB.server(), String.t()) :: map() | nil
  def latest_turn(db, session_key) do
    case DB.query(
           db,
           "SELECT seq,status,error,adapterGen," <>
             cause_column_sql() <>
             " FROM turns WHERE sessionKey=?1 ORDER BY seq DESC LIMIT 1",
           [session_key]
         ) do
      {:ok, [[seq, status, error, adapter_gen, cause]]} ->
        %{
          seq: seq,
          status: status,
          error: error,
          adapter_gen: adapter_gen,
          cause: shown_cause(status, error, cause)
        }

      _ ->
        nil
    end
  end

  @doc """
  The settlement a read shows for a session, or nil when there is none: its
  latest turn's unknown-effect terminal, or a running turn that is stalled.
  `liveness` answers P's R3 liveness for a running turn (`{:ok, %{live: _}}`)
  and is called only for one.
  """
  @spec settlement(map() | nil, (map() -> term())) :: map() | nil
  def settlement(turn, liveness \\ fn _turn -> :unknown end)

  def settlement(%{status: "running"} = turn, liveness) do
    case liveness.(turn) do
      {:ok, %{live: false}} -> fields(turn, "in_flight_stalled")
      _ -> nil
    end
  end

  def settlement(%{cause: cause} = turn, _liveness) when is_binary(cause),
    do: fields(turn, if(cause == "harness_exited", do: "harness_exited"))

  def settlement(_turn, _liveness), do: nil

  @doc """
  P's R3 liveness for a running turn on `adapter` at `generation`, or
  `:unknown` when that is not the turn's adapter generation or P is not
  pending there.
  """
  @spec liveness(DB.server(), map(), pid(), integer(), String.t() | nil) :: term()
  def liveness(db, %{seq: seq, adapter_gen: generation}, adapter, generation, sid)
      when is_binary(sid) do
    with {:ok, [[request_id]]} when is_integer(request_id) <-
           DB.query(
             db,
             "SELECT acpRequestId FROM turn_lifecycle_events WHERE turnSeq=?1 AND kind='prompt_dispatched' AND adapterGen=?2",
             [seq, generation]
           ),
         {:ok, %{}} = answer <- Adapter.prompt_liveness(adapter, sid, request_id) do
      answer
    else
      _ -> :unknown
    end
  end

  def liveness(_db, _turn, _adapter, _generation, _sid), do: :unknown

  defp fields(turn, held_state) do
    %{
      turnSeq: turn.seq,
      status: turn.status,
      error: turn.error,
      cause: turn.cause,
      heldState: held_state
    }
  end
end

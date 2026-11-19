defmodule Tightbeam.MemoryGuard.Settlement do
  @moduledoc """
  The words a turn carries when a memory kill ended its tree before its
  prompt was dispatched (memory limits v1.1 R9's not-started rule). A
  dispatched turn settles as `UnknownEffect` with cause `memory_limit`.
  """

  @doc "The `turns.error` sentence for a not-started memory-killed turn."
  @spec not_started_reason(map()) :: String.t()
  def not_started_reason(kill) do
    limit =
      case Map.get(kill, :limit) do
        "budget" -> "the memory budget for Tightbeam's agents on this host"
        _ -> "its memory limit"
      end

    "memory_limit: the agent's process was stopped for using more than #{limit} " <>
      "before its prompt was sent; it is re-admitted once, and not again if that happens again"
  end
end

defmodule Tightbeam.Acp.TurnActivity do
  @moduledoc """
  Turn liveness for one dispatched prompt P (stale-turn settlement v1.1 §1,
  R3). Pure: the Adapter keeps one value per session while P is pending and
  feeds it P's session's `session/update` notifications.

  Only a **genuine turn advancement** is turn activity: new content, a new
  tool call, a tool-call update that changes status or content, a changed
  plan, compaction progress, a subagent the harness holds the turn open for,
  and the harness's turn-end report. Never: heartbeats or status kinds,
  `usage_update` that is not a turn-end report, notices (including provider
  retries), background-task (`async_task_*`) updates, and any repeat of a
  prior update with no new content or state. Any kind not listed is not turn
  activity.

  P's turn is **live** while turn activity arrived within the last W (5 min)
  or a tool call is open. Before any activity, the window runs from the
  dispatch itself, so a prompt is not quiet the moment it is sent.
  """

  @w_ms 5 * 60_000

  @content_kinds ~w(agent_message_chunk agent_thought_chunk)
  @progress_kinds ~w(compaction_update compaction_summary_chunk subagent_spawned subagent_state_update)

  @type t :: %{
          dispatched_at: integer(),
          last_activity_at: integer() | nil,
          turn_end_at: integer() | nil,
          seen: map()
        }

  @doc "Quiet bound W (§1)."
  def w_ms, do: @w_ms

  @spec new(integer()) :: t()
  def new(now), do: %{dispatched_at: now, last_activity_at: nil, turn_end_at: nil, seen: %{}}

  @doc """
  Observe one update for P's session. `turn_end?` is the harness's turn-end
  report test (`Tightbeam.Harness.turn_end_report?/1`).
  """
  @spec observe(t(), map(), integer(), (map() -> boolean())) :: t()
  def observe(%{} = activity, update, now, turn_end?) when is_map(update) do
    kind = update["sessionUpdate"]

    cond do
      kind == "usage_update" ->
        if turn_end?.(update),
          do: %{activity | last_activity_at: now, turn_end_at: now},
          else: activity

      kind in @content_kinds ->
        if new_content?(update), do: %{activity | last_activity_at: now}, else: activity

      kind == "tool_call" ->
        changed(activity, {:tool_call, update["toolCallId"]}, :seen, now)

      kind == "tool_call_update" ->
        changed(
          activity,
          {:tool_call_update, update["toolCallId"]},
          Map.take(update, ["status", "content", "rawOutput"]),
          now
        )

      kind == "plan" ->
        changed(activity, :plan, update["entries"], now)

      kind in @progress_kinds ->
        changed(activity, {kind, Map.drop(update, ["_meta"])}, :seen, now)

      true ->
        activity
    end
  end

  @doc "Whether P's harness turn is live (R3): activity within W, or a tool call open."
  @spec live?(t(), integer(), non_neg_integer(), pos_integer()) :: boolean()
  def live?(%{} = activity, now, open_tool_calls, w_ms \\ @w_ms) do
    open_tool_calls > 0 or now - last_advance(activity) < w_ms
  end

  @doc """
  Whether the missing-response rule applies (R6): a turn-end report arrived
  after dispatch, no tool call is open, and P has been quiet for W since its
  last turn activity.
  """
  @spec missing_response?(t(), integer(), non_neg_integer(), pos_integer()) :: boolean()
  def missing_response?(activity, now, open_tool_calls, w_ms \\ @w_ms)

  def missing_response?(%{turn_end_at: turn_end_at} = activity, now, open_tool_calls, w_ms)
      when is_integer(turn_end_at),
      do: open_tool_calls == 0 and now - last_advance(activity) >= w_ms

  def missing_response?(_activity, _now, _open_tool_calls, _w_ms), do: false

  @doc "When R6's W elapses for P, or nil while it cannot apply."
  @spec missing_response_at(t(), pos_integer()) :: integer() | nil
  def missing_response_at(activity, w_ms \\ @w_ms)

  def missing_response_at(%{turn_end_at: turn_end_at} = activity, w_ms)
      when is_integer(turn_end_at),
      do: last_advance(activity) + w_ms

  def missing_response_at(_activity, _w_ms), do: nil

  @spec last_advance(t()) :: integer()
  def last_advance(%{last_activity_at: nil, dispatched_at: dispatched_at}), do: dispatched_at
  def last_advance(%{last_activity_at: at}), do: at

  defp new_content?(%{"content" => %{"text" => text}}) when is_binary(text), do: text != ""
  defp new_content?(%{"content" => content}) when is_map(content), do: map_size(content) > 0
  defp new_content?(_update), do: false

  # An item's update is activity only when it differs from the last one for
  # the same item.
  defp changed(activity, item, value, now) do
    if Map.get(activity.seen, item) == value do
      activity
    else
      %{activity | last_activity_at: now, seen: Map.put(activity.seen, item, value)}
    end
  end
end

defmodule Tightbeam.Acp.TurnActivityTest do
  # Stale-turn settlement v1.1 §1 "turn activity" and R3/R6's predicates.
  use ExUnit.Case, async: true

  alias Tightbeam.Acp.TurnActivity
  alias Tightbeam.Harness.Claude

  @w 300_000
  @turn_end %{
    "sessionUpdate" => "usage_update",
    "used" => 120,
    "size" => 200_000,
    "cost" => %{"amount" => 0.01, "currency" => "USD"},
    "_meta" => %{"_claude/origin" => "task-notification"}
  }

  defp observe(activity, update, at),
    do: TurnActivity.observe(activity, update, at, &Claude.turn_end_report?/1)

  test "the §1 table: advancing kinds are turn activity" do
    for update <- [
          %{
            "sessionUpdate" => "agent_message_chunk",
            "content" => %{"type" => "text", "text" => "x"}
          },
          %{
            "sessionUpdate" => "agent_thought_chunk",
            "content" => %{"type" => "text", "text" => "y"}
          },
          %{"sessionUpdate" => "tool_call", "toolCallId" => "t1", "status" => "pending"},
          %{"sessionUpdate" => "tool_call_update", "toolCallId" => "t1", "status" => "completed"},
          %{"sessionUpdate" => "plan", "entries" => [%{"content" => "a", "status" => "pending"}]},
          %{"sessionUpdate" => "compaction_update", "status" => "running"},
          %{"sessionUpdate" => "subagent_spawned", "subagentId" => "s1"},
          @turn_end
        ] do
      activity = observe(TurnActivity.new(0), update, 10)
      assert activity.last_activity_at == 10, inspect(update)
    end
  end

  test "the §1 table: status, notices, background tasks and non-turn-end usage are not" do
    for update <- [
          %{"sessionUpdate" => "usage_update", "used" => 120, "size" => 200_000},
          %{
            "sessionUpdate" => "usage_update",
            "used" => 120,
            "size" => 200_000,
            "_meta" => %{"_claude/rateLimit" => %{}}
          },
          %{"sessionUpdate" => "available_commands_update", "availableCommands" => []},
          %{"sessionUpdate" => "current_mode_update", "currentModeId" => "default"},
          %{"sessionUpdate" => "config_option_update", "configOptions" => []},
          %{"sessionUpdate" => "session_info_update", "title" => "t"},
          %{"sessionUpdate" => "notice", "kind" => "api_retry", "attempt" => 2},
          %{"sessionUpdate" => "async_task_spawned", "taskId" => "bg1"},
          %{"sessionUpdate" => "async_task_progress", "taskId" => "bg1"},
          %{"sessionUpdate" => "async_task_state_update", "taskId" => "bg1"},
          %{
            "sessionUpdate" => "agent_message_chunk",
            "content" => %{"type" => "text", "text" => ""}
          },
          %{"sessionUpdate" => "some_future_kind"}
        ] do
      activity = observe(TurnActivity.new(0), update, 10)
      assert activity.last_activity_at == nil, inspect(update)
      assert activity.turn_end_at == nil
    end
  end

  test "a repeat with no new content or state is not activity" do
    pending = %{
      "sessionUpdate" => "tool_call_update",
      "toolCallId" => "t1",
      "status" => "in_progress"
    }

    plan = %{"sessionUpdate" => "plan", "entries" => [%{"content" => "a"}]}
    tool = %{"sessionUpdate" => "tool_call", "toolCallId" => "t2"}

    activity =
      TurnActivity.new(0)
      |> observe(pending, 1)
      |> observe(plan, 2)
      |> observe(tool, 3)

    assert activity.last_activity_at == 3
    assert activity |> observe(pending, 50) |> observe(plan, 60) |> observe(tool, 70) == activity
    assert observe(activity, %{pending | "status" => "completed"}, 80).last_activity_at == 80
  end

  test "R3: live within W of the last activity (or of dispatch), or while a tool call is open" do
    activity = TurnActivity.new(0)
    assert TurnActivity.live?(activity, @w - 1)
    refute TurnActivity.live?(activity, @w)

    open = observe(activity, %{"sessionUpdate" => "tool_call", "toolCallId" => "t1"}, 0)
    assert TurnActivity.open_tool_calls(open) == 1
    assert TurnActivity.live?(open, 10 * @w)

    closed =
      observe(
        open,
        %{"sessionUpdate" => "tool_call_update", "toolCallId" => "t1", "status" => "failed"},
        10
      )

    assert TurnActivity.open_tool_calls(closed) == 0
    refute TurnActivity.live?(closed, 10 + @w)

    done_at_once =
      observe(
        activity,
        %{"sessionUpdate" => "tool_call", "toolCallId" => "t2", "status" => "completed"},
        0
      )

    assert TurnActivity.open_tool_calls(done_at_once) == 0

    activity =
      observe(
        activity,
        %{"sessionUpdate" => "agent_message_chunk", "content" => %{"text" => "x"}},
        60_000
      )

    assert TurnActivity.live?(activity, 60_000 + @w - 1)
    refute TurnActivity.live?(activity, 60_000 + @w)
  end

  test "R3 acceptance: periodic non-advancing signals never make a quiet turn live" do
    activity =
      TurnActivity.new(0)
      |> observe(%{"sessionUpdate" => "agent_message_chunk", "content" => %{"text" => "x"}}, 0)

    activity =
      Enum.reduce(1..12, activity, fn n, acc ->
        at = n * 30_000

        acc
        |> observe(%{"sessionUpdate" => "session_info_update", "title" => "same"}, at)
        |> observe(%{"sessionUpdate" => "usage_update", "used" => 1, "size" => 2}, at)
      end)

    # Six minutes after the last activity, with no tool call open.
    refute TurnActivity.live?(activity, 360_000)
    assert TurnActivity.last_advance(activity) == 0
  end

  test "R6: missing response needs a turn-end report after dispatch, no open tool call, and W of quiet" do
    activity = TurnActivity.new(0)
    refute TurnActivity.missing_response?(activity, 10 * @w)
    assert TurnActivity.missing_response_at(activity) == nil

    activity = observe(activity, @turn_end, 1_000)
    refute TurnActivity.missing_response?(activity, 1_000 + @w - 1)
    assert TurnActivity.missing_response?(activity, 1_000 + @w)
    assert TurnActivity.missing_response_at(activity) == 1_000 + @w

    # An open tool call holds it off however long the quiet.
    open =
      activity
      |> Map.update!(:open, &MapSet.put(&1, "t9"))

    refute TurnActivity.missing_response?(open, 1_000 + 10 * @w)

    # A genuine chunk at minute 4 restarts W from that chunk.
    later =
      observe(
        activity,
        %{"sessionUpdate" => "agent_message_chunk", "content" => %{"text" => "more"}},
        241_000
      )

    refute TurnActivity.missing_response?(later, 1_000 + @w)
    assert TurnActivity.missing_response_at(later) == 241_000 + @w
  end
end

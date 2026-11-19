defmodule Tightbeam.TurnSettlementViewTest do
  # Stale-turn settlement v1.1 R10: what the reads show.
  use ExUnit.Case, async: true

  alias Tightbeam.TurnSettlementView, as: View

  test "only an unknown-effect terminal shows a cause" do
    assert View.shown_cause("failed_unknown", "unknown_effect", "response_missing") ==
             "response_missing"

    assert View.shown_cause("failed_unknown", "usageLimitExceeded", "turn:7") == nil
    assert View.shown_cause("failed_unknown", "unknown_effect", "turn:7") == nil
    assert View.shown_cause("failed", "unknown_effect", "harness_exited") == nil
  end

  test "held state: harness_exited for R4, in_flight_stalled for a running turn that is not live" do
    exited = %{seq: 4, status: "failed_unknown", error: "unknown_effect", cause: "harness_exited"}

    assert %{turnSeq: 4, cause: "harness_exited", heldState: "harness_exited"} =
             View.settlement(exited)

    settled = %{exited | cause: "operator_settle"}
    assert %{cause: "operator_settle", heldState: nil} = View.settlement(settled)

    running = %{seq: 5, status: "running", error: nil, cause: nil}

    assert %{turnSeq: 5, heldState: "in_flight_stalled"} =
             View.settlement(running, fn ^running -> {:ok, %{live: false}} end)

    assert View.settlement(running, fn _ -> {:ok, %{live: true}} end) == nil
    assert View.settlement(running, fn _ -> :unknown end) == nil
    assert View.settlement(%{running | status: "delivered"}) == nil
    assert View.settlement(nil) == nil
  end
end

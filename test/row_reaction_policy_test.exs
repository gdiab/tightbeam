defmodule Tightbeam.RowReactionPolicyTest do
  use Tightbeam.TestCase, async: false

  alias Tightbeam.Rules

  test "a settings-only reaction rail does not create a row action" do
    assert [] = Rules.reaction_plans(%{"kind" => "assignment"}, %{})
  end

  test "harness recovery defaults are seed-elected and limited to rate-limit-dead" do
    assert %{settings: settings, english: english, provenance: provenance} =
             Rules.reaction_policy("harness-health-recovery")

    assert settings["eligible_failure_classes"] == ["rate-limit-dead"]
    assert settings["interval_ms"] == 3_600_000
    assert settings["timeout_ms"] == 120_000
    assert settings["start"] == "schedule_one_cycle_for_eligible_open_hold"
    assert settings["withdraw"] == "withdraw_resolved_or_ineligible_cycle_at_delivery"
    assert settings["reschedule"] == "move_the_single_pending_cycle_in_place"
    assert settings["release"] == "resolve_only_after_all_constituent_routes_succeed"
    assert english =~ "Owning bundle: substrate base seed."
    # Companion v1.6 PR3: two minutes, doubling to an hour, 24 a day.
    assert settings["first_interval_ms"] == 120_000
    assert settings["daily_probe_cap"] == 24
    assert english =~ "first_interval_ms (two minutes) after opening"
    assert english =~ "capped at interval_ms (one hour)"
    assert provenance["source"] == "rules/harness-health-recovery.toml"
  end

  test "the removed inactivity behavior has no compiled policy fallback" do
    empty =
      Path.join(
        System.tmp_dir!(),
        "tightbeam-no-assignment-inactivity-#{System.unique_integer([:positive])}"
      )

    assert [] = Rules.load!(empty, [])
    assert is_nil(Rules.reaction_policy("assignment-inactivity"))
  end
end

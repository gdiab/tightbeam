defmodule Tightbeam.RateLimitResetTest do
  use ExUnit.Case, async: true

  alias Tightbeam.RateLimitReset

  test "session reset uses the next UTC clock time, including midnight rollover" do
    assert reset("1:30am UTC", ~U[2026-10-22 21:19:00Z]) ==
             millis(~U[2026-10-23 01:30:00Z])

    assert reset("1:40am (UTC)", ~U[2026-10-22 00:16:00Z]) ==
             millis(~U[2026-10-22 01:40:00Z])

    assert reset("12am (UTC)", ~U[2026-10-22 23:00:00Z]) ==
             millis(~U[2026-10-23 00:00:00Z])

    assert reset("12pm UTC", ~U[2026-10-22 11:00:00Z]) ==
             millis(~U[2026-10-22 12:00:00Z])
  end

  test "dated weekly reset retains the provider date and handles year rollover" do
    assert reset("Aug 15, 12am (UTC)", ~U[2026-08-09 10:00:00Z]) ==
             millis(~U[2026-08-15 00:00:00Z])

    assert reset("Jan 1, 1am (UTC)", ~U[2026-12-31 23:00:00Z]) ==
             millis(~U[2027-01-01 01:00:00Z])
  end

  test "a reset at the observation time is due immediately" do
    at = ~U[2026-10-23 01:30:00Z]
    assert reset("1:30am UTC", at) == millis(at)
    assert reset("1:30am UTC", ~U[2026-10-23 01:30:45Z]) == millis(at)
  end

  test "captured named-zone session and weekly reset formats convert to UTC" do
    for {message, observed, expected} <- [
          {"You've hit your session limit · resets 6:30pm (America/Los_Angeles)",
           ~U[2026-10-22 22:22:00Z], ~U[2026-10-23 01:30:00Z]},
          {"You've hit your weekly limit · resets Oct 23, 5pm (America/Los_Angeles)",
           ~U[2026-10-21 18:35:00Z], ~U[2026-10-24 00:00:00Z]},
          {"You've hit your weekly limit · resets Oct 23, 8pm (America/New_York)",
           ~U[2026-10-21 18:35:00Z], ~U[2026-10-24 00:00:00Z]},
          {"You've hit your weekly limit · resets Sep 21 at 11pm (America/Los_Angeles)",
           ~U[2026-09-20 10:00:00Z], ~U[2026-09-22 06:00:00Z]}
        ] do
      assert RateLimitReset.from_error(
               %{"data" => %{"errorKind" => "rate_limit"}, "message" => message},
               millis(observed)
             ) == millis(expected)
    end
  end

  test "named-zone conversion uses local dates and seasonal offsets" do
    assert reset("11pm (America/Los_Angeles)", ~U[2026-10-23 01:00:00Z]) ==
             millis(~U[2026-10-23 06:00:00Z])

    assert reset("Dec 31 at 11pm (America/Los_Angeles)", ~U[2027-01-01 01:00:00Z]) ==
             millis(~U[2027-01-01 07:00:00Z])

    assert reset("6:30pm (America/Los_Angeles)", ~U[2026-01-22 22:22:00Z]) ==
             millis(~U[2026-01-23 02:30:00Z])
  end

  test "repeated clock times choose the next occurrence and nonexistent times keep the hold" do
    assert reset("1:30am (America/Los_Angeles)", ~U[2026-11-01 08:00:00Z]) ==
             millis(~U[2026-11-01 08:30:00Z])

    assert reset("1:30am (America/Los_Angeles)", ~U[2026-11-01 08:45:00Z]) ==
             millis(~U[2026-11-01 09:30:00Z])

    assert reset("2:30am (America/Los_Angeles)", ~U[2026-03-08 08:00:00Z]) == nil
    assert reset("1:30am (Unknown/Zone)", ~U[2026-10-22 21:19:00Z]) == nil
  end

  test "only typed limits with an understood reset supply a deadline" do
    at = millis(~U[2026-10-22 21:19:00Z])
    message = "You've hit your session limit · resets 1:30am UTC"
    assert RateLimitReset.from_error(message, at) == nil
    assert RateLimitReset.from_error(%{"message" => message}, at) == nil

    for text <- ["", "1:30am", "1:30am (PDT)", "25:30am UTC", "1:99am UTC", "Feb 30, 1am UTC"] do
      assert reset(text, ~U[2026-10-22 21:19:00Z]) == nil
    end
  end

  describe "Codex declared reset (companion v1.1 §1, B1)" do
    @la "America/Los_Angeles"

    test "the Nov 14 shape: a dated reset read in the host's zone" do
      # Captured shape: harness_health_test's @captured_codex_rate_limit.
      assert codex(
               "You've hit your usage limit. Visit the account usage page or try again at Nov 18th, 2026 9:59 AM.",
               ~U[2026-11-14 16:04:00Z],
               @la
             ) == millis(~U[2026-11-18 17:59:00Z])
    end

    test "a time alone is that time on the observation's local date" do
      # 08:10 local (PST) on Nov 18.
      assert codex(
               "You've hit your usage limit. Try again at 9:59 AM.",
               ~U[2026-11-18 16:10:00Z],
               @la
             ) == millis(~U[2026-11-18 17:59:00Z])

      # The local date, not the UTC one: 17:30 local on Nov 17 is 01:30Z Nov 18.
      assert codex("try again at 11:45 PM.", ~U[2026-11-18 01:30:00Z], @la) ==
               millis(~U[2026-11-18 07:45:00Z])
    end

    test "the other ordinals and the text in the error's own message" do
      for {text, expected} <- [
            {"Dec 1st, 2026 12:05 AM", ~U[2026-12-01 08:05:00Z]},
            {"Dec 2nd, 2026 12:05 PM", ~U[2026-12-02 20:05:00Z]},
            {"Dec 3rd, 2026 1:00 PM", ~U[2026-12-03 21:00:00Z]}
          ] do
        assert codex("or try again at #{text}.", ~U[2026-11-18 16:10:00Z], @la) ==
                 millis(expected)
      end

      reason = %{
        "code" => -32_603,
        "data" => %{"codexErrorInfo" => "usageLimitExceeded"},
        "message" => "You've hit your usage limit. Try again at 9:59 AM."
      }

      assert RateLimitReset.from_error(reason, millis(~U[2026-11-18 16:10:00Z]), @la) ==
               millis(~U[2026-11-18 17:59:00Z])
    end

    test "an unknown reset is never guessed" do
      at = ~U[2026-11-18 16:10:00Z]

      for text <- [
            "You've hit your usage limit.",
            "You've hit your usage limit. Try again later.",
            "Try again at 13:59 PM.",
            "Try again at 9:75 AM.",
            "Try again at 9:59.",
            "Try again at Feb 30th, 2027 9:59 AM.",
            # Not after the observation.
            "Try again at 8:10 AM.",
            "Try again at 7:00 AM.",
            "Try again at Nov 17th, 2026 9:59 AM."
          ] do
        assert codex(text, at, @la) == nil, text
      end

      # The host's zone is unknown (a remote host).
      assert codex("Try again at 9:59 AM.", at, nil) == nil
      # A Claude-shaped reset text in a Codex error is not Codex's reset.
      assert codex("resets 9:59am (America/Los_Angeles)", at, @la) == nil
      # Untyped text is not a typed quota error.
      assert RateLimitReset.from_error(%{"message" => "Try again at 9:59 AM."}, millis(at), @la) ==
               nil
    end

    test "a repeated local hour takes the later instant; a nonexistent one is unknown" do
      # Nov 1, 2026: 1:30 AM PDT and 1:30 AM PST.
      assert codex("Try again at 1:30 AM.", ~U[2026-11-01 07:00:00Z], @la) ==
               millis(~U[2026-11-01 09:30:00Z])

      # Mar 8, 2026: 2:30 AM does not exist in Los Angeles.
      assert codex("Try again at 2:30 AM.", ~U[2026-03-08 08:00:00Z], @la) == nil
    end
  end

  defp codex(message, observed, zone) do
    RateLimitReset.from_error(
      %{
        "code" => -32_603,
        "data" => %{"codexErrorInfo" => "usageLimitExceeded", "message" => message},
        "message" => "Internal error"
      },
      millis(observed),
      zone
    )
  end

  defp reset(text, observed) do
    RateLimitReset.from_error(
      %{
        "data" => %{"errorKind" => "rate_limit"},
        "message" => "Internal error: You've hit your session limit · resets " <> text
      },
      millis(observed)
    )
  end

  defp millis(datetime), do: DateTime.to_unix(datetime, :millisecond)
end

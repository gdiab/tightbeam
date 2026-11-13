defmodule Tightbeam.HostedSmokeLifecycleTest do
  # scripts/hosted_smoke_lifecycle.sh decides two things the hosted live smoke reports:
  # whether a process is still the one it launched, and whether the run passed. A PASS
  # that ignored teardown, or an identity check that mistook a recycled pid for ours,
  # would report safety the run did not have.
  use ExUnit.Case, async: true

  @lib Path.expand("../scripts/hosted_smoke_lifecycle.sh", __DIR__)
  @linux? :os.type() == {:unix, :linux}

  defp bash(script, args \\ []) do
    {out, 0} = System.cmd("bash", ["-c", ~s(. "$0"; ) <> script, @lib | args])
    String.trim(out)
  end

  defp results(dir, lines) do
    path = Path.join(dir, "smoke-results.txt")
    File.write!(path, Enum.join(lines, "\n") <> "\n")
    path
  end

  @full [
    "feature-smoke legs: claude, codex (every registered leg — full parity)",
    "  PASS [claude] onboard registered providers interactive entry",
    "feature-smoke leg claude: 14 checks PASS",
    "feature-smoke leg codex: 14 checks PASS"
  ]

  describe "smoke_verdict" do
    @describetag :tmp_dir

    test "passes only with full assertions AND a confirmed stop AND a removed run root",
         %{tmp_dir: dir} do
      file = results(dir, @full)
      verdict = fn rc, phase, stopped, removed ->
        bash(~s(smoke_verdict "$1" "$2" "$3" "$4" "$5"), [rc, phase, stopped, removed, file])
      end

      assert verdict.("0", "done", "yes", "yes") == "PASS"
      # Every required assertion passed, but teardown could not be confirmed.
      assert verdict.("0", "done", "no", "no") == "FAIL"
      # Stopped, but the directory holding banked keys and bearers is still there.
      assert verdict.("0", "done", "yes", "no") == "FAIL"
      assert verdict.("1", "done", "yes", "yes") == "FAIL"
      assert verdict.("", "onboard", "yes", "yes") == "FAIL"
      assert verdict.("0", "smoke", "yes", "yes") == "FAIL"
    end

    test "fails when a leg's completion line or full parity is missing", %{tmp_dir: dir} do
      verdict = fn lines ->
        file = results(dir, lines)
        bash(~s(smoke_verdict 0 done yes yes "$1"), [file])
      end

      assert verdict.(List.delete(@full, "feature-smoke leg codex: 14 checks PASS")) == "FAIL"

      filtered = [
        "feature-smoke legs: codex — FILTERED, holding back claude. This run is INCOMPLETE(parity) by design"
        | tl(@full)
      ]

      assert verdict.(filtered) == "FAIL"
      assert verdict.([]) == "FAIL"
    end
  end

  if @linux? do
    describe "process identity (/proc)" do
      @describetag :tmp_dir

      test "a live process is alive; a different start time is reused; an exited one is gone" do
        out =
          bash("""
          sleep 30 & pid=$!
          start=$(proc_start "$pid")
          proc_status "$pid" "$start"
          proc_status "$pid" "$((start + 1))"
          kill "$pid"; wait "$pid" 2>/dev/null
          proc_status "$pid" "$start"
          """)

        assert String.split(out, "\n") == ["alive", "reused", "gone"]
      end

      test "fields parse after a command name containing spaces and parentheses",
           %{tmp_dir: dir} do
        odd = Path.join(dir, "x) (y")
        File.ln_s!(System.find_executable("sleep"), odd)

        out =
          bash(
            ~s("$1" 30 & pid=$!; sleep 0.2; f=$(proc_fields "$pid"); kill "$pid"; echo "$f"),
            [odd]
          )

        [state, _pgrp, _session, start] = String.split(out, " ")
        assert state in ["S", "R"]
        assert start =~ ~r/^\d+$/
      end

      test "capture_tree records every descendant with its identity" do
        out =
          bash("""
          (sleep 30 & sleep 30 & wait) & parent=$!
          sleep 0.3
          capture_tree "$parent" | wc -l
          kill -TERM -- $(ps -o pid= --ppid "$parent") "$parent" 2>/dev/null
          """)

        assert out == "2"
      end

      test "group_members finds a setsid group's members and nothing once it is gone" do
        out =
          bash("""
          setsid bash -c 'sleep 30 & sleep 30 & wait' & leader=$!
          sleep 0.3
          group_members "$leader" | wc -l
          kill -TERM -- "-$leader" 2>/dev/null
          wait "$leader" 2>/dev/null
          sleep 0.3
          group_members "$leader" | wc -l
          """)

        # The leader bash plus its two sleeps; then none.
        assert String.split(out, "\n") == ["3", "0"]
      end
    end
  end
end

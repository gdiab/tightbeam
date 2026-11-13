defmodule Tightbeam.HostedSmokeLifecycleTest do
  # The hosted live smoke reports PASS only if the gateway and everything it owned are
  # confirmed gone and the run's secret-bearing directory is removed, and it never signals
  # a process it cannot prove is its own. These cases drive the REAL supervisor
  # (scripts/hosted_smoke_supervisor.py) and the REAL stop / exit-trap code
  # (scripts/hosted_smoke_lifecycle.sh) against small fake gateways, including the
  # negative outcomes: a gateway that ignores SIGTERM, a descendant that survives, an
  # escaped (setsid) descendant, a child spawned during shutdown, an early exit, a second
  # stop request, and an interruption after the smoke's last phase.
  use ExUnit.Case, async: true

  @lib Path.expand("../scripts/hosted_smoke_lifecycle.sh", __DIR__)
  @supervisor Path.expand("../scripts/hosted_smoke_supervisor.py", __DIR__)
  @linux? :os.type() == {:unix, :linux}

  @full [
    "feature-smoke legs: claude, codex (every registered leg — full parity)",
    "  PASS [claude] onboard registered providers interactive entry",
    "feature-smoke leg claude: 14 checks PASS",
    "feature-smoke leg codex: 14 checks PASS"
  ]

  # Runs `script` in bash with the library sourced, the supervisor path and short waits
  # set, and $1 = a scratch directory. Returns {stdout, exit status}.
  defp run(dir, script) do
    prelude = """
    . "$0"
    SUPERVISOR=#{@supervisor}
    SUP_TERM_WAIT=2
    SUP_SWEEP_WAIT=3
    """

    System.cmd("bash", ["-c", prelude <> script, @lib, dir])
  end

  defp write_results(dir, lines) do
    File.mkdir_p!(Path.join(dir, "ev"))
    File.write!(Path.join([dir, "ev", "smoke-results.txt"]), Enum.join(lines, "\n") <> "\n")
  end

  defp summary(dir), do: dir |> Path.join("ev/summary.json") |> File.read!() |> JSON.decode!()

  describe "smoke_verdict" do
    @describetag :tmp_dir

    test "PASS needs a clean enclosing status, the smoke, both legs, a stop and a removal",
         %{tmp_dir: dir} do
      write_results(dir, @full)
      verdict = &verdict(dir, &1)

      assert verdict.(["0", "0", "done", "yes", "yes", ""]) == "PASS"
      # The script itself was interrupted or failed, though the smoke passed.
      assert verdict.(["130", "0", "done", "yes", "yes", "yes"]) == "FAIL"
      assert verdict.(["1", "0", "done", "yes", "yes", ""]) == "FAIL"
      # An interruption is recorded even where the status would otherwise be 0.
      assert verdict.(["0", "0", "done", "yes", "yes", "yes"]) == "FAIL"
      # Teardown not confirmed, or the run root still holds the keys and bearers.
      assert verdict.(["0", "0", "done", "no", "no", ""]) == "FAIL"
      assert verdict.(["0", "0", "done", "yes", "no", ""]) == "FAIL"
      assert verdict.(["0", "1", "done", "yes", "yes", ""]) == "FAIL"
      assert verdict.(["0", "0", "smoke", "yes", "yes", ""]) == "FAIL"
    end

    test "a missing leg or a filtered selection never passes", %{tmp_dir: dir} do
      verdict = fn lines ->
        write_results(dir, lines)
        verdict(dir, ["0", "0", "done", "yes", "yes", ""])
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

  # smoke_verdict with six fixed literal arguments and this test's results file.
  defp verdict(dir, args) do
    quoted = Enum.map_join(args, " ", &~s("#{&1}"))
    {out, 0} = run(dir, ~s(smoke_verdict #{quoted} "$1/ev/smoke-results.txt"))
    String.trim(out)
  end

  if @linux? do
    # Fake gateways. Each records the pids it creates in $DIR so the test can clean up
    # anything a deliberately failing case leaves behind (test cleanup only).
    @fakes %{
      "clean" => """
      trap 'exit 0' TERM
      sleep 1000 & echo $! >> "$1/pids"
      setsid bash -c 'sleep 1000 & echo $! >> "$0/pids"; wait' "$1" & echo $! >> "$1/pids"
      wait
      """,
      "late" => """
      trap 'sleep 1000 & echo $! >> "$1/pids"; exit 0' TERM
      sleep 1000 & echo $! >> "$1/pids"
      wait
      """,
      "stubborn" => """
      echo $$ >> "$1/pids"
      trap '' TERM
      sleep 1000 & echo $! >> "$1/pids"
      wait
      """,
      "survivor" => """
      trap 'exit 0' TERM
      (trap '' TERM; exec sleep 1000) & echo $! >> "$1/pids"
      wait
      """,
      "early" => """
      sleep 1000 & echo $! >> "$1/pids"
      exit 3
      """
    }

    defp fake!(dir, name) do
      path = Path.join(dir, "#{name}.sh")
      File.write!(path, Map.fetch!(@fakes, name))
      path
    end

    defp cleanup(dir) do
      case File.read(Path.join(dir, "pids")) do
        {:ok, pids} ->
          list = String.replace(pids, "\n", " ")
          System.cmd("bash", ["-c", "kill -KILL #{list} 2>/dev/null; true"])

        _ ->
          :ok
      end
    end

    defp supervise(dir, fake, after_start) do
      try do
        run(dir, """
        DIR="$1"
        start_gateway_supervised "$DIR/sup" "$DIR/gw.log" bash #{fake} "$DIR"
        sleep 0.5
        #{after_start}
        """)
      after
        cleanup(dir)
      end
    end

    describe "supervisor and single-attempt stop" do
      @describetag :tmp_dir

      test "a clean stop accounts for orphaned and escaped (setsid) descendants",
           %{tmp_dir: dir} do
        {out, 0} =
          supervise(dir, fake!(dir, "clean"), """
          stop_gateway; echo "rc=$? state=$SUP_STATE result=$(cat "$SUP_RESULT")"
          """)

        assert out =~ "rc=0 state=stopped result=stopped"
      end

      test "a child spawned during shutdown is still found and stopped", %{tmp_dir: dir} do
        {out, 0} =
          supervise(dir, fake!(dir, "late"), """
          stop_gateway; echo "rc=$? result=$(cat "$SUP_RESULT")"
          """)

        assert out =~ "rc=0 result=stopped"
      end

      test "a gateway that ignores SIGTERM fails the stop, and a second stop is refused",
           %{tmp_dir: dir} do
        {out, 0} =
          supervise(dir, fake!(dir, "stubborn"), """
          stop_gateway; echo "first=$? state=$SUP_STATE reason=$STOP_REASON"
          before=$(stat -c %Y "$SUP_RESULT")
          stop_gateway; echo "second=$? reason=$STOP_REASON"
          [ "$(stat -c %Y "$SUP_RESULT")" = "$before" ] && echo result-untouched
          """)

        assert out =~ ~r/first=1 state=stop_failed reason=gateway_outlived_sigterm:\d+/
        assert out =~ ~r/second=1 reason=gateway_outlived_sigterm:\d+/
        assert out =~ "result-untouched"
      end

      test "a descendant that survives its SIGTERM fails the stop", %{tmp_dir: dir} do
        {out, 0} =
          supervise(dir, fake!(dir, "survivor"), """
          stop_gateway; echo "rc=$? reason=$STOP_REASON"
          """)

        assert out =~ ~r/rc=1 reason=owned_process_survived:\d+/
      end

      test "a gateway that exits on its own is a failure even when its tree is swept",
           %{tmp_dir: dir} do
        {out, 0} =
          supervise(dir, fake!(dir, "early"), """
          while [ ! -s "$SUP_RESULT" ]; do sleep 0.1; done
          gateway_supervised || echo not-supervised
          stop_gateway; echo "rc=$? reason=$STOP_REASON"
          """)

        assert out =~ "not-supervised"
        assert out =~ "rc=1 reason=gateway_exited_early:stopped"
      end
    end

    describe "exit trap composition" do
      @describetag :tmp_dir

      defp scenario(dir, body) do
        File.mkdir_p!(Path.join(dir, "root"))

        run(dir, """
        set -euo pipefail
        DIR="$1"
        SMOKE_RUN_ROOT="$DIR/root"
        SMOKE_EVIDENCE_DIR="$DIR/ev"
        PHASE=start
        SMOKE_RC=
        install_traps
        #{body}
        """)
      end

      test "a complete run passes, exits 0 and removes the run root", %{tmp_dir: dir} do
        write_results(dir, @full)
        {_out, status} = scenario(dir, "SMOKE_RC=0\nPHASE=done\ntrue")

        assert status == 0
        assert %{"verdict" => "PASS", "run_root_removed" => "yes"} = summary(dir)
        refute File.exists?(Path.join(dir, "root"))
      end

      test "an interruption after the last phase is never reported as success",
           %{tmp_dir: dir} do
        write_results(dir, @full)
        {_out, status} = scenario(dir, "SMOKE_RC=0\nPHASE=done\nkill -INT $$\nsleep 5")

        assert status == 130
        assert %{"verdict" => "FAIL", "interrupted" => "yes", "exit_status" => "130"} =
                 summary(dir)
      end

      test "a failed stop is not retried by the exit trap and keeps the run root",
           %{tmp_dir: dir} do
        write_results(dir, @full)

        try do
          {_out, status} =
            scenario(dir, """
            start_gateway_supervised "$DIR/sup" "$DIR/gw.log" bash #{fake!(dir, "stubborn")} "$DIR"
            sleep 0.5
            PHASE=restart
            stop_gateway
            echo unreachable
            """)

          assert status == 1

          assert %{
                   "verdict" => "FAIL",
                   "gateway_stopped" => "no",
                   "run_root_removed" => "no",
                   "phase_reached" => "restart",
                   "stop_reason" => "gateway_outlived_sigterm:" <> _
                 } = summary(dir)

          assert File.dir?(Path.join(dir, "root"))
        after
          cleanup(dir)
        end
      end
    end
  end
end

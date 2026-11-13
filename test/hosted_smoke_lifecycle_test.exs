defmodule Tightbeam.HostedSmokeLifecycleTest do
  # The hosted live smoke reports PASS only if the gateway and everything it owned are
  # confirmed gone and the run's secret-bearing directory is removed; it asks for that stop
  # exactly once; and it never signals a process it cannot prove is its own. These cases
  # drive the REAL supervisor (scripts/hosted_smoke_supervisor.py) and the REAL lifecycle
  # and exit-trap code (scripts/hosted_smoke_lifecycle.sh) under `set -e`, including the
  # failure paths: control lost at launch, a pidfd operation failing after launch, a
  # supervisor crash, a gateway that ignores SIGTERM, a surviving descendant, an escaped
  # (setsid) descendant, a child spawned during shutdown, an early exit, an interruption
  # during the stop, and an interruption after the last phase.
  #
  # The fixtures are COOPERATIVE: every fake process exits by itself once $DIR/release
  # exists, so cleanup never signals anything. Faults are injected by a test-side wrapper
  # that patches the standard library before running the unmodified supervisor.
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

  # Runs `script` in bash with the library sourced and short waits, $1 = the scratch dir.
  defp run(dir, script, supervisor \\ @supervisor) do
    prelude = """
    . "$0"
    DIR="$1"
    SUPERVISOR=#{supervisor}
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

  # smoke_verdict with six fixed literal arguments and this test's results file.
  defp verdict(dir, args) do
    quoted = Enum.map_join(args, " ", &~s("#{&1}"))
    {out, 0} = run(dir, ~s(smoke_verdict #{quoted} "$DIR/ev/smoke-results.txt"))
    String.trim(out)
  end

  describe "smoke_verdict" do
    @describetag :tmp_dir

    test "PASS needs a clean enclosing status, the smoke, both legs, a stop and a removal",
         %{tmp_dir: dir} do
      write_results(dir, @full)
      verdict = &verdict(dir, &1)

      assert verdict.(["0", "0", "done", "yes", "yes", ""]) == "PASS"
      assert verdict.(["130", "0", "done", "yes", "yes", "yes"]) == "FAIL"
      assert verdict.(["1", "0", "done", "yes", "yes", ""]) == "FAIL"
      assert verdict.(["0", "0", "done", "yes", "yes", "yes"]) == "FAIL"
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

  if @linux? do
    # Interrupts the shell that started it, through a pidfd: the helper opens its parent's
    # pidfd, confirms that process is still its parent (so the pid was not reissued), and
    # only then signals it.
    @interrupt_parent ~S"""
    python3 -c 'import os, signal, time
    parent = os.getppid()
    pidfd = os.pidfd_open(parent)
    assert os.getppid() == parent
    time.sleep(0.5)
    signal.pidfd_send_signal(pidfd, signal.SIGINT)' &
    """

    # Each fake gets $1 = the scratch dir; `hold` loops until $1/release exists.
    @hold ~s|hold() { while [ ! -e "$1/release" ]; do sleep 0.1; done; }\n|

    @fakes %{
      "clean" => """
      trap 'exit 0' TERM
      hold "$1" &
      setsid bash -c 'while [ ! -e "$0/release" ]; do sleep 0.1; done' "$1" &
      hold "$1"
      """,
      "late" => """
      trap 'hold "$1" & exit 0' TERM
      hold "$1"
      """,
      "stubborn" => """
      trap '' TERM
      hold "$1"
      """,
      "survivor" => """
      trap 'exit 0' TERM
      (trap '' TERM; hold "$1") &
      hold "$1"
      """,
      "early" => """
      hold "$1" &
      exit 3
      """,
      "marker" => """
      : > "$1/started"
      trap 'exit 0' TERM
      hold "$1"
      """
    }

    defp fake!(dir, name) do
      path = Path.join(dir, "#{name}.sh")
      File.write!(path, @hold <> Map.fetch!(@fakes, name))
      path
    end

    # Cooperative cleanup: no signal is sent; every fixture exits once release exists.
    defp release(dir) do
      File.write!(Path.join(dir, "release"), "")
      Process.sleep(500)
    end

    defp with_fixtures(dir, fun) do
      try do
        fun.()
      after
        release(dir)
      end
    end

    # The unmodified supervisor, run after a standard-library function is patched.
    defp faulty_supervisor!(dir, mode) do
      path = Path.join(dir, "faulty_supervisor.py")

      File.write!(path, """
      import errno, os, runpy, select, signal, sys
      mode = #{inspect(mode)}
      if mode == "pidfd_open_at_launch":
          def failing(pid, flags=0):
              raise OSError(errno.EMFILE, "injected")
          os.pidfd_open = failing
      elif mode == "orphan_signal_fails":
          real_send = signal.pidfd_send_signal
          calls = {"n": 0}
          def flaky(pidfd, sig, *rest, **kw):
              calls["n"] += 1
              if calls["n"] > 1:
                  raise OSError(errno.EPERM, "injected")
              return real_send(pidfd, sig, *rest, **kw)
          signal.pidfd_send_signal = flaky
      elif mode == "crash_after_launch":
          def boom(*args, **kw):
              raise RuntimeError("injected")
          select.select = boom
      sys.argv = [#{inspect(@supervisor)}] + sys.argv[1:]
      runpy.run_path(#{inspect(@supervisor)}, run_name="__main__")
      """)

      path
    end

    # The supervisor's own count of "stop" lines it READ from the FIFO: the receiver-side
    # record of delivery. Absent means it never received one.
    defp received(dir) do
      case File.read(Path.join([dir, "sup", "received"])) do
        {:ok, text} -> text |> String.trim() |> String.to_integer()
        _ -> 0
      end
    end

    # Waits (bounded) for a supervisor left running by a deliberately failed stop to finish
    # on its own once the fixtures are released, so `received` holds its final total.
    defp settle(dir) do
      release(dir)
      result = Path.join([dir, "sup", "result"])
      Enum.find(1..100, fn _ -> File.exists?(result) || (Process.sleep(100) && false) end)
    end

    describe "supervisor ownership and the single stop" do
      @describetag :tmp_dir

      test "a clean stop accounts for orphaned and escaped (setsid) descendants",
           %{tmp_dir: dir} do
        with_fixtures(dir, fn ->
          {out, 0} =
            run(dir, """
            start_gateway_supervised "$DIR/sup" "$DIR/gw.log" bash #{fake!(dir, "clean")} "$DIR"
            sleep 0.5
            stop_gateway; echo "rc=$? state=$SUP_STATE result=$(cat "$DIR/sup/result")"
            """)

          assert out =~ "rc=0 state=stopped result=stopped"
          assert received(dir) == 1
        end)
      end

      test "a child spawned during shutdown is still found and stopped", %{tmp_dir: dir} do
        with_fixtures(dir, fn ->
          {out, 0} =
            run(dir, """
            start_gateway_supervised "$DIR/sup" "$DIR/gw.log" bash #{fake!(dir, "late")} "$DIR"
            sleep 0.5
            stop_gateway; echo "rc=$? result=$(cat "$DIR/sup/result")"
            """)

          assert out =~ "rc=0 result=stopped"
        end)
      end

      test "a gateway that ignores SIGTERM fails, and later calls never ask again",
           %{tmp_dir: dir} do
        with_fixtures(dir, fn ->
          {out, 0} =
            run(dir, """
            start_gateway_supervised "$DIR/sup" "$DIR/gw.log" bash #{fake!(dir, "stubborn")} "$DIR"
            sleep 0.5
            stop_gateway; echo "first=$? state=$SUP_STATE reason=$STOP_REASON"
            stop_gateway; echo "second=$? reason=$STOP_REASON"
            """)

          assert out =~
                   ~r/first=1 state=stop_failed reason=gateway_outlived_sigterm:direct_children=\d+/

          assert out =~ ~r/second=1 reason=gateway_outlived_sigterm:/
          assert received(dir) == 1
        end)
      end

      test "a descendant that survives its SIGTERM fails the stop", %{tmp_dir: dir} do
        with_fixtures(dir, fn ->
          {out, 0} =
            run(dir, """
            start_gateway_supervised "$DIR/sup" "$DIR/gw.log" bash #{fake!(dir, "survivor")} "$DIR"
            sleep 0.5
            stop_gateway; echo "rc=$? reason=$STOP_REASON"
            """)

          assert out =~ ~r/rc=1 reason=owned_process_survived:direct_children=[1-9]/
        end)
      end

      test "a gateway that exits on its own is a failure even when its tree is swept",
           %{tmp_dir: dir} do
        with_fixtures(dir, fn ->
          {out, 0} =
            run(dir, """
            start_gateway_supervised "$DIR/sup" "$DIR/gw.log" bash #{fake!(dir, "early")} "$DIR"
            while [ ! -s "$DIR/sup/result" ]; do sleep 0.1; done
            gateway_supervised || echo not-supervised
            stop_gateway; echo "rc=$? reason=$STOP_REASON"
            """)

          assert out =~ "not-supervised"
          assert out =~ "rc=1 reason=gateway_exited_early:stopped"
          assert received(dir) == 0
        end)
      end
    end

    describe "faults after launch" do
      @describetag :tmp_dir

      test "no pidfd at the handoff: the gateway never starts and nothing is owned",
           %{tmp_dir: dir} do
        supervisor = faulty_supervisor!(dir, "pidfd_open_at_launch")

        with_fixtures(dir, fn ->
          {out, 0} =
            run(
              dir,
              """
              start_gateway_supervised "$DIR/sup" "$DIR/gw.log" bash #{fake!(dir, "marker")} "$DIR"
              echo "rc=$? state=$SUP_STATE reason=$STOP_REASON"
              """,
              supervisor
            )

          assert out =~ "rc=1 state=none reason=start:control_unavailable:pidfd_open=EMFILE"
          refute File.exists?(Path.join(dir, "started"))
        end)
      end

      test "an orphan that cannot be signalled is recorded and fails the stop",
           %{tmp_dir: dir} do
        supervisor = faulty_supervisor!(dir, "orphan_signal_fails")

        with_fixtures(dir, fn ->
          {out, 0} =
            run(
              dir,
              """
              start_gateway_supervised "$DIR/sup" "$DIR/gw.log" bash #{fake!(dir, "clean")} "$DIR"
              sleep 0.5
              stop_gateway; echo "rc=$? reason=$STOP_REASON"
              """,
              supervisor
            )

          assert out =~
                   ~r/rc=1 reason=owned_process_survived:direct_children=\d+:control_error=EPERM/
        end)
      end

      test "a supervisor crash after launch stops the next phase and is never re-stopped",
           %{tmp_dir: dir} do
        supervisor = faulty_supervisor!(dir, "crash_after_launch")

        with_fixtures(dir, fn ->
          {out, 0} =
            run(
              dir,
              """
              start_gateway_supervised "$DIR/sup" "$DIR/gw.log" bash #{fake!(dir, "marker")} "$DIR"
              while [ ! -s "$DIR/sup/result" ]; do sleep 0.1; done
              require_supervised || echo "refused state=$SUP_STATE reason=$STOP_REASON"
              stop_gateway; echo "stop=$?"
              """,
              supervisor
            )

          assert out =~
                   "refused state=stop_failed reason=owner_lost:supervisor_error:RuntimeError"

          assert out =~ "stop=1"
          assert received(dir) == 0
        end)
      end
    end

    describe "exit trap composition under set -e" do
      @describetag :tmp_dir

      defp scenario(dir, body) do
        File.mkdir_p!(Path.join(dir, "root"))

        run(dir, """
        set -euo pipefail
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

      test "a failed stop unwinding under set -e is asked exactly once", %{tmp_dir: dir} do
        write_results(dir, @full)

        with_fixtures(dir, fn ->
          {_out, status} =
            scenario(dir, """
            start_gateway_supervised "$DIR/sup" "$DIR/gw.log" bash #{fake!(dir, "stubborn")} "$DIR"
            sleep 0.5
            PHASE=restart
            stop_gateway
            echo unreachable
            """)

          assert status == 1
          assert received(dir) == 1

          assert %{
                   "verdict" => "FAIL",
                   "gateway_stopped" => "no",
                   "run_root_removed" => "no",
                   "phase_reached" => "restart",
                   "stop_reason" => "gateway_outlived_sigterm:" <> _
                 } = summary(dir)

          assert File.dir?(Path.join(dir, "root"))
        end)
      end

      test "a signal inside the delivery section is deferred: one stop received, 130",
           %{tmp_dir: dir} do
        write_results(dir, @full)

        with_fixtures(dir, fn ->
          {_out, status} =
            scenario(dir, """
            start_gateway_supervised "$DIR/sup" "$DIR/gw.log" bash #{fake!(dir, "clean")} "$DIR"
            sleep 0.5
            eval "original_$(declare -f send_stop_request)"
            send_stop_request() { kill -INT $$; original_send_stop_request; }
            PHASE=restart
            stop_gateway
            echo unreachable
            """)

          assert status == 130
          assert received(dir) == 1

          assert %{"verdict" => "FAIL", "interrupted" => "yes", "gateway_stopped" => "yes"} =
                   summary(dir)
        end)
      end

      test "a signal before the delivery section leaves the one send to the EXIT trap",
           %{tmp_dir: dir} do
        write_results(dir, @full)

        with_fixtures(dir, fn ->
          {_out, status} =
            scenario(dir, """
            start_gateway_supervised "$DIR/sup" "$DIR/gw.log" bash #{fake!(dir, "clean")} "$DIR"
            sleep 0.5
            PHASE=restart
            kill -INT $$
            stop_gateway
            """)

          assert status == 130
          assert received(dir) == 1
          assert %{"verdict" => "FAIL", "gateway_stopped" => "yes"} = summary(dir)
        end)
      end

      test "a failed send is terminal at once: nothing received, nothing retried",
           %{tmp_dir: dir} do
        write_results(dir, @full)

        try do
          {_out, status} =
            scenario(dir, """
            start_gateway_supervised "$DIR/sup" "$DIR/gw.log" bash #{fake!(dir, "stubborn")} "$DIR"
            sleep 0.5
            send_stop_request() { return 1; }
            PHASE=restart
            stop_gateway
            echo unreachable
            """)

          assert status == 1

          assert %{
                   "verdict" => "FAIL",
                   "gateway_stopped" => "no",
                   "run_root_removed" => "no",
                   "stop_reason" => "request_not_delivered"
                 } = summary(dir)
        after
          settle(dir)
        end

        assert received(dir) == 0
      end

      test "a send nobody receives fails within the receipt bound, never waiting on",
           %{tmp_dir: dir} do
        write_results(dir, @full)

        try do
          {_out, status} =
            scenario(dir, """
            SUP_RECEIPT_WAIT=2
            start_gateway_supervised "$DIR/sup" "$DIR/gw.log" bash #{fake!(dir, "stubborn")} "$DIR"
            sleep 0.5
            # The supervisor keeps reading the original, now-unlinked FIFO; this write lands
            # in a new one nobody reads, so delivery cannot be confirmed.
            rm "$DIR/sup/control"
            mkfifo "$DIR/sup/control"
            PHASE=restart
            stop_gateway
            echo unreachable
            """)

          assert status == 1

          assert %{
                   "verdict" => "FAIL",
                   "gateway_stopped" => "no",
                   "stop_reason" => "request_unacknowledged"
                 } = summary(dir)
        after
          settle(dir)
        end

        assert received(dir) == 0
      end

      test "an interruption during the stop collects the outcome without asking again",
           %{tmp_dir: dir} do
        write_results(dir, @full)

        with_fixtures(dir, fn ->
          {_out, status} =
            scenario(dir, """
            start_gateway_supervised "$DIR/sup" "$DIR/gw.log" bash #{fake!(dir, "stubborn")} "$DIR"
            sleep 0.5
            PHASE=restart
            #{@interrupt_parent}
            stop_gateway
            """)

          assert status == 130
          assert received(dir) == 1

          assert %{"verdict" => "FAIL", "interrupted" => "yes", "gateway_stopped" => "no"} =
                   summary(dir)
        end)
      end
    end
  end
end

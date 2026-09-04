defmodule Tightbeam.GatewayShutdownEvidenceTest do
  # A GRACEFUL STOP MUST EXIT 0 AND SAY SO — the missing half of the exit-code seam.
  #
  # In the 2026-09 gateway incident a managed instance exited 0 with NO shutdown log at
  # all: `prep_stop` drained and stamped clean, then the VM halted silently. systemd read
  # 0 as success and did not restart, and nothing in the log distinguished "operator
  # retired the box" from "managed instance stopped by accident" — a silent 0.
  #
  # `application_refusal_test.exs` proves the OTHER direction (an abnormal termination
  # exits NONZERO with a crash dump). This proves that an intended, orderly stop:
  #   * still exits 0 cleanly (acceptance C — a legit `stop` must not be turned into a
  #     failure), and
  #   * now leaves a NOTICE naming why it stopped, so the next silent 0 is legible
  #     (acceptance D-partial).
  #
  # It boots the application IN A SUBPROCESS and reads its real exit status and log output,
  # the same honest-proof pattern as the refusal test — not an in-process assertion against
  # `prep_stop/1`, which would flip the global draining flag under the async suite.
  use ExUnit.Case, async: true

  # The notice `prep_stop` writes at the top, anchored on its stable prefix.
  @notice "gateway stopping: orderly VM stop (prep_stop)"

  @tag :shutdown_subprocess
  @tag timeout: 180_000
  test "an intended graceful stop exits 0 and logs why it is stopping" do
    # --no-halt keeps the VM up after `mix run` evaluates the trigger; the trigger asks
    # for a graceful `System.stop()` a beat later. That is the in-VM shape of an operator
    # `tightbeam-gateway stop` / `System.stop()` RPC: init:stop -> prep_stop -> clean exit.
    # MIX_ENV=test boots with autostart=false (an empty tree, no port bind, no harness
    # needed), yet OTP still calls prep_stop on the orderly stop.
    trigger = "spawn(fn -> Process.sleep(300); System.stop() end)"

    {output, status} =
      System.cmd(
        System.find_executable("elixir"),
        ["-S", "mix", "run", "--no-halt", "-e", trigger],
        cd: File.cwd!(),
        stderr_to_stdout: true,
        env: [{"MIX_ENV", "test"}]
      )

    # 1. ACCEPTANCE C: a deliberate stop is a success, not a failure. Exit 0.
    assert status == 0, "expected a clean exit 0 from a graceful stop, got #{status}.\n#{output}"

    # 2. ACCEPTANCE D-partial: the stop is no longer silent. The notice names the shape
    #    (orderly VM stop) so a future exit-0 outage reads as a graceful stop, not a
    #    swallowed fault, and carries the boot epoch for the next boot to correlate.
    assert Enum.any?(String.split(output, "\n"), &String.contains?(&1, @notice)),
           "the graceful stop left no shutdown notice — the silent-0 this fix exists to " <>
             "make legible. Output:\n#{output}"

    assert output =~ "graceful stop, not a crash"
    assert output =~ "boot_epoch="

    # 3. IT WAS CLEAN, NOT A FAULT. A graceful stop must not carry the crash shapes the
    #    refusal test pins for the abnormal direction.
    refute output =~ "Kernel pid terminated",
           "a graceful stop escalated into a kernel panic. Output:\n#{output}"

    refute output =~ "** (",
           "a graceful stop carried a stacktrace. Output:\n#{output}"
  end
end

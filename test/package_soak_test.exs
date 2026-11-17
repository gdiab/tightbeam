defmodule Tightbeam.PackageSoakTest do
  use ExUnit.Case, async: true

  test "package identity, workload evidence boundaries and sustained drift detectors" do
    python =
      System.find_executable("python3") || flunk("python3 is required for package-soak checks")

    {output, status} =
      Tightbeam.TestIsolation.run_script!("scripts/support/package_soak_checks.py", [],
        runner: [python, "-I", "-B"],
        stderr_to_stdout: true
      )

    assert status == 0, output
  end
end

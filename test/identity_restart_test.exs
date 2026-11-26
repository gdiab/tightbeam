defmodule Tightbeam.IdentityRestartTest do
  use Tightbeam.TestCase, async: false
  @moduletag tmp_dir: true

  @tag timeout: 180_000
  test "customized relearn conflict survives a real gateway restart and supported abort/resolve",
       %{
         tmp_dir: tmp
       } do
    binary = Path.expand("cli/target/release/tightbeam")

    fixture = Tightbeam.GuardRuntimeFixture.prepare!(tmp, "identity_restart.exs")
    tripwire_log = Application.fetch_env!(:tightbeam, :test_tripwire_log)
    assert {"TIGHTBEAM_TEST_ROOT", tmp} in fixture.env
    assert {"TIGHTBEAM_TEST_TRIPWIRE_LOG", tripwire_log} in fixture.env

    for phase <- ["conflict", "abort", "resolve", "normal"] do
      {output, status} =
        System.cmd(fixture.executable, fixture.args ++ [phase, binary],
          env: fixture.env,
          stderr_to_stdout: true
        )

      assert status == 0, "identity restart phase failed with status #{inspect(status)}"
      assert output =~ "identity-restart: #{phase} passed"
    end
  end
end

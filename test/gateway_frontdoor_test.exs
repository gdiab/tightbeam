defmodule Tightbeam.GatewayFrontdoorTest do
  # THE LAUNCHER SHIM MUST NEVER LET A FLAG BECOME A BOOT.
  #
  # `tightbeam-gateway --help` used to fall through the shim's `"" | -*) set -- start`
  # mapping into a full gateway boot: it bound the port, opened a boot epoch, and wrote
  # harnesses.json before any help text — the "accidental UNMANAGED live listener" of the
  # 2026-09 gateway incident. The fix is a FRONT DOOR that answers `-h`/`--help`,
  # `--version`, and unknown flags BEFORE any node name is derived and before exec, so a
  # flag can never reach the release binary that does the booting.
  #
  # This test runs the REAL shim (packaging/tightbeam-gateway) against a RECORDING STUB
  # standing in for the release binary. The stub only appends its argv to a marker file;
  # it binds nothing. So "no port bind / no boot_epochs row / no harnesses.json write" is
  # proven by the STRONGER fact that the release binary is never invoked AT ALL on the
  # pure paths — the side effects are unrepresentable, not merely absent this run.
  use ExUnit.Case, async: true

  @shim Path.expand("../packaging/tightbeam-gateway", __DIR__)

  # A package layout the shim expects: bin/tightbeam-gateway beside release/bin/
  # tightbeam_gateway. The stub records what the shim handed it (or records nothing when
  # the shim short-circuits) and never binds a port.
  defp gateway_fixture do
    root = Path.join(System.tmp_dir!(), "tb-frontdoor-#{System.unique_integer([:positive])}")
    File.mkdir_p!(Path.join(root, "bin"))
    File.mkdir_p!(Path.join(root, "release/bin"))

    shim = Path.join(root, "bin/tightbeam-gateway")
    File.cp!(@shim, shim)
    File.chmod!(shim, 0o755)

    stub = Path.join(root, "release/bin/tightbeam_gateway")

    File.write!(stub, """
    #!/bin/sh
    printf '%s\\n' "$*" >> "$TB_STUB_MARKER"
    [ "$1" = version ] && echo "tightbeam_gateway 9.9.9"
    exit 0
    """)

    File.chmod!(stub, 0o755)

    on_exit(fn -> File.rm_rf!(root) end)
    {shim, Path.join(root, "marker")}
  end

  # Run the shim; return {stdout+stderr split, exit status, list of release invocations}.
  defp run(shim, marker, args) do
    File.rm(marker)

    {out, status} =
      System.cmd(shim, args, stderr_to_stdout: true, env: [{"TB_STUB_MARKER", marker}])

    release_calls =
      case File.read(marker) do
        {:ok, body} -> body |> String.split("\n", trim: true)
        {:error, _} -> []
      end

    {out, status, release_calls}
  end

  test "-h and --help print help, exit 0, and never reach the release binary" do
    {shim, marker} = gateway_fixture()

    for flag <- ["--help", "-h"] do
      {out, status, release_calls} = run(shim, marker, [flag])

      assert status == 0, "#{flag} did not exit 0. Output:\n#{out}"
      assert out =~ "Usage:"
      assert out =~ "tightbeam-gateway"

      assert release_calls == [],
             "#{flag} reached the release binary (#{inspect(release_calls)}) — help fell " <>
               "through toward boot/bind, the defect this front door exists to prevent"
    end
  end

  test "a bare invocation maps to start and reaches the release exactly once" do
    {shim, marker} = gateway_fixture()

    {_out, status, release_calls} = run(shim, marker, [])

    assert status == 0
    assert release_calls == ["start"]
  end

  test "an explicit start subcommand reaches the release as start" do
    {shim, marker} = gateway_fixture()

    {_out, status, release_calls} = run(shim, marker, ["start"])

    assert status == 0
    assert release_calls == ["start"]
  end

  test "start --help is answered purely and never boots" do
    {shim, marker} = gateway_fixture()

    {out, status, release_calls} = run(shim, marker, ["start", "--help"])

    assert status == 0
    assert out =~ "Usage:"

    assert release_calls == [],
           "an explicit `start --help` reached the release (#{inspect(release_calls)}); the " <>
             "release start branch reads only its subcommand word and would drop --help " <>
             "into a full boot"
  end

  test "VM passthrough flags require the explicit start subcommand and reach the release" do
    {shim, marker} = gateway_fixture()

    {_out, status, release_calls} = run(shim, marker, ["start", "--erl", "+sbwt none"])

    assert status == 0
    assert release_calls == ["start --erl +sbwt none"]
  end

  test "--version execs the release version command, not a boot" do
    {shim, marker} = gateway_fixture()

    {out, status, release_calls} = run(shim, marker, ["--version"])

    assert status == 0
    assert out =~ "tightbeam_gateway 9.9.9"
    assert release_calls == ["version"]
  end

  test "an unknown flag is refused on stderr with exit 2 and never reaches the release" do
    {shim, marker} = gateway_fixture()

    {out, status, release_calls} = run(shim, marker, ["--bogus"])

    assert status == 2, "expected exit 2 for an unknown flag, got #{status}. Output:\n#{out}"
    assert out =~ "unknown option: --bogus"

    assert release_calls == [],
           "an unknown flag reached the release (#{inspect(release_calls)}) instead of being " <>
             "refused at the front door"
  end

  test "lifecycle subcommands fall through untouched to the release" do
    {shim, marker} = gateway_fixture()

    for cmd <- ["stop", "restart", "pid", "remote"] do
      {_out, status, release_calls} = run(shim, marker, [cmd])

      assert status == 0
      assert release_calls == [cmd], "#{cmd} did not reach the release as itself"
    end
  end
end

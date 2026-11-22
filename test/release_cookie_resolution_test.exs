defmodule Tightbeam.ReleaseCookieResolutionTest do
  # Option 2's cookie mode (PO att_7b3c25f9, att_98019d3a) proven against the
  # REAL mix-generated release launcher — not a model.
  #
  # The generated launcher sources releases/<vsn>/env.sh (rel/env.sh.eex) before
  # it resolves the cookie and EXPORTS RELEASE_COOKIE, so `<launcher> eval`
  # reading the exported RELEASE_COOKIE observes the EFFECTIVE cookie every
  # release command (start, rpc, remote, eval) would use — without a peer node.
  # env.sh takes it from the one file releases/COOKIE_MODE names, so an
  # inherited RELEASE_COOKIE never wins, and a missing or loose file stops the
  # command without printing the value.
  #
  # Builds the real release ONCE in setup_all (~10s), laid out as an install is:
  # <build root>/tightbeam/release, with the per-install cookie at
  # <build root>/COOKIE. Kept in the default gate on purpose: a proof against
  # reality has to actually run to count.
  use Tightbeam.TestCase, async: false

  @moduletag :release_build

  setup_all do
    mix = System.find_executable("mix") || "mix"

    build_root =
      Path.join(System.tmp_dir!(), "tb-real-build-#{System.unique_integer([:positive])}")

    release_dir = Path.join(build_root, "tightbeam/release")

    {out, status} =
      System.cmd(mix, ["release", "--overwrite", "--path", release_dir],
        env: [{"MIX_ENV", "prod"}, {"TIGHTBEAM_COOKIE_MODE", nil}],
        stderr_to_stdout: true
      )

    assert status == 0, "mix release failed:\n#{out}"
    on_exit(fn -> File.rm_rf!(build_root) end)

    baked_path = Path.join(release_dir, "releases/COOKIE")
    baked = File.read!(baked_path)

    # Unset TIGHTBEAM_COOKIE_MODE assembles per-build: a fresh owner-only cookie.
    assert File.read!(Path.join(release_dir, "releases/COOKIE_MODE")) == "per-build\n"
    assert Bitwise.band(File.stat!(baked_path).mode, 0o777) == 0o600
    assert byte_size(baked) >= 32

    %{
      launcher: Path.join(release_dir, "bin/tightbeam_gateway"),
      release_dir: release_dir,
      baked: baked,
      baked_path: baked_path,
      install_path: Path.join(build_root, "COOKIE"),
      mode_path: Path.join(release_dir, "releases/COOKIE_MODE")
    }
  end

  # Every test starts from the assembled per-build state.
  setup ctx do
    File.rm_rf!(ctx.baked_path)
    File.rm_rf!(ctx.install_path)
    write_secret!(ctx.baked_path, ctx.baked)
    File.write!(ctx.mode_path, "per-build\n")
    :ok
  end

  defp write_secret!(path, value, mode \\ 0o600) do
    File.touch!(path)
    File.chmod!(path, 0o600)
    File.write!(path, value)
    File.chmod!(path, mode)
  end

  defp run_eval(launcher, env \\ [{"RELEASE_COOKIE", nil}]) do
    expr = ~s{IO.puts("TBCOOKIE=" <> (System.get_env("RELEASE_COOKIE") || "nil"))}
    System.cmd(launcher, ["eval", expr], env: env, stderr_to_stdout: true)
  end

  # The cookie the REAL launcher resolves and exports, for the given child env.
  defp resolved_cookie(launcher, env \\ [{"RELEASE_COOKIE", nil}]) do
    {out, status} = run_eval(launcher, env)
    assert status == 0, out
    [cookie] = Regex.run(~r/^TBCOOKIE=(.*)$/m, out, capture: :all_but_first)
    cookie
  end

  defp assert_refused(ctx, reason, secret) do
    {out, status} = run_eval(ctx.launcher, [{"RELEASE_COOKIE", "synthetic-foreign-cookie"}])
    assert status == 78, out
    assert out =~ "tightbeam: refusing to run: "
    assert out =~ reason
    refute out =~ "TBCOOKIE="
    if secret, do: refute(out =~ secret)
  end

  describe "per-build" do
    test "the launcher uses the package's own releases/COOKIE", ctx do
      assert resolved_cookie(ctx.launcher) == ctx.baked
    end

    test "an inherited RELEASE_COOKIE does not win", ctx do
      assert resolved_cookie(ctx.launcher, [{"RELEASE_COOKIE", "synthetic-foreign-cookie"}]) ==
               ctx.baked
    end

    test "a loose, linked, short or missing cookie stops the command, without the value", ctx do
      File.chmod!(ctx.baked_path, 0o644)
      assert_refused(ctx, "releases/COOKIE is not mode 0600", ctx.baked)

      File.rm!(ctx.baked_path)
      target = ctx.baked_path <> ".target"
      write_secret!(target, ctx.baked)
      File.ln_s!(target, ctx.baked_path)
      assert_refused(ctx, "releases/COOKIE is a symlink", ctx.baked)
      File.rm!(ctx.baked_path)
      File.rm!(target)

      write_secret!(ctx.baked_path, "short-cookie")
      assert_refused(ctx, "releases/COOKIE is shorter than 32 bytes", "short-cookie")

      File.rm!(ctx.baked_path)
      assert_refused(ctx, "releases/COOKIE is missing", nil)
    end

    test "a per-build package never reads the build root's file", ctx do
      install = String.duplicate("i", 40)
      write_secret!(ctx.install_path, install)
      assert resolved_cookie(ctx.launcher) == ctx.baked

      File.rm!(ctx.baked_path)
      assert_refused(ctx, "releases/COOKIE is missing", install)
    end
  end

  describe "per-install" do
    setup ctx do
      File.write!(ctx.mode_path, "per-install\n")
      File.rm!(ctx.baked_path)
      :ok
    end

    test "the launcher uses the build root's COOKIE, never an inherited one", ctx do
      install = String.duplicate("k", 48)
      write_secret!(ctx.install_path, install)

      assert resolved_cookie(ctx.launcher) == install

      assert resolved_cookie(ctx.launcher, [{"RELEASE_COOKIE", "synthetic-foreign-cookie"}]) ==
               install
    end

    test "with no build-root COOKIE it refuses, even with a package cookie present", ctx do
      # The build root's file, reached from RELEASE_ROOT (symlinks resolved).
      assert_refused(ctx, "/release/../../COOKIE is missing", nil)

      write_secret!(ctx.baked_path, ctx.baked)
      assert_refused(ctx, "/release/../../COOKIE is missing", ctx.baked)
    end

    test "a loose build-root COOKIE stops the command", ctx do
      install = String.duplicate("m", 48)
      write_secret!(ctx.install_path, install, 0o640)
      assert_refused(ctx, "/release/../../COOKIE is not mode 0600", install)
    end
  end

  test "a missing or unknown COOKIE_MODE stops the command", ctx do
    File.write!(ctx.mode_path, "baked\n")
    assert_refused(ctx, "releases/COOKIE_MODE names no known cookie mode", ctx.baked)

    File.rm!(ctx.mode_path)
    assert_refused(ctx, "releases/COOKIE_MODE is missing", ctx.baked)
  end
end

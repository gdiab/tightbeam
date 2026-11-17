defmodule Tightbeam.TestIsolationTest do
  # F1 (wi_34a7be66) regression tests T1-T8 and T11, plus the reviewer's Q1(c)
  # and Q2(e) conditions. A test can never reach a gateway through an ancestor
  # .tightbeam-session or a HOME gateway.json, and it fails closed if it would.
  # Every guarded case has a positive control: the same launch done raw DOES
  # reach the decoy, so a mis-wired decoy cannot pass vacuously. The only
  # gateway anywhere is a listener this test owns; it counts TCP accepts.
  use ExUnit.Case, async: false

  alias Tightbeam.{LaunchIsolationLint, TestIsolation, TestSandboxPreflight}

  @cli_relative "cli/target/release/tightbeam"

  defp cli, do: Path.join(TestIsolation.repo(), @cli_relative)

  defp scratch!(label) do
    dir = Path.join(System.tmp_dir!(), "f1-#{label}-#{System.unique_integer([:positive])}")
    File.mkdir_p!(dir)
    on_exit(fn -> File.rm_rf!(dir) end)
    dir
  end

  defp decoy! do
    {:ok, listen} =
      :gen_tcp.listen(0, [:binary, active: false, reuseaddr: true, ip: {127, 0, 0, 1}])

    {:ok, port} = :inet.port(listen)
    counter = :counters.new(1, [])
    acceptor = spawn(fn -> accept_loop(listen, counter) end)

    on_exit(fn ->
      Process.exit(acceptor, :kill)
      :gen_tcp.close(listen)
    end)

    %{port: port, counter: counter}
  end

  defp accept_loop(listen, counter) do
    case :gen_tcp.accept(listen) do
      {:ok, socket} ->
        :counters.add(counter, 1, 1)

        :gen_tcp.send(
          socket,
          "HTTP/1.1 503 Service Unavailable\r\ncontent-length: 0\r\nconnection: close\r\n\r\n"
        )

        :gen_tcp.close(socket)
        accept_loop(listen, counter)

      {:error, _} ->
        :ok
    end
  end

  defp accepts(decoy), do: :counters.get(decoy.counter, 1)

  # A directory two levels below a .tightbeam-session that names the decoy.
  defp session_tree!(decoy, parent) do
    File.mkdir_p!(parent)
    session = Path.join(parent, ".tightbeam-session")
    File.write!(session, ~s({"url":"http://127.0.0.1:#{decoy.port}","token":"decoy-token"}))
    inner = Path.join([parent, "a", "b"])
    File.mkdir_p!(inner)
    %{session: session, inner: inner}
  end

  # The deliberately unguarded launch every guarded case is measured against.
  defp raw_cli(args, cd, home) do
    System.cmd(cli(), args, cd: cd, env: [{"HOME", home}], stderr_to_stdout: true)
  end

  defp assert_refused_reaching_nothing(decoy, fun, names) do
    error = assert_raise TestIsolation.Refusal, fun
    assert error.message =~ names
    Process.sleep(200)
    assert accepts(decoy) == 0, "a refused launch reaches nothing"
  end

  defp session_case(args) do
    decoy = decoy!()
    tree = session_tree!(decoy, scratch!("session"))

    assert_refused_reaching_nothing(
      decoy,
      fn -> TestIsolation.cmd(cli(), args, cd: tree.inner, stderr_to_stdout: true) end,
      tree.session
    )

    {output, _status} = raw_cli(args, tree.inner, scratch!("raw-home"))

    assert accepts(decoy) >= 1,
           "positive control: the raw launch must reach the decoy session gateway: #{output}"
  end

  describe "the PO's three paths cannot reach a session gateway" do
    test "T1: user creation" do
      session_case(["add-user", "synthetic-admin", "--admin"])
    end

    test "T2: any gateway call" do
      session_case(["list"])
    end

    test "T3: identity writes (edit and relearn)" do
      file = Path.join(scratch!("identity"), "coder.md")
      File.write!(file, "decoy guidance\n")
      session_case(["identity", "edit", "coder", "--file", file])
      session_case(["identity", "relearn"])
    end
  end

  test "Q1(c): a decoy session inside a repository subdirectory is refused" do
    decoy = decoy!()

    parent =
      Path.join(TestIsolation.repo(), "_build/f1-q1c-#{System.unique_integer([:positive])}")

    on_exit(fn -> File.rm_rf!(parent) end)
    tree = session_tree!(decoy, parent)

    assert_refused_reaching_nothing(
      decoy,
      fn -> TestIsolation.cmd(cli(), ["list"], cd: tree.inner, stderr_to_stdout: true) end,
      tree.session
    )

    {output, _status} = raw_cli(["list"], tree.inner, scratch!("raw-home"))
    assert accepts(decoy) >= 1, "positive control: #{output}"
  end

  test "T4: a HOME gateway.json is never the fallback" do
    decoy = decoy!()
    home = scratch!("decoy-home")
    File.mkdir_p!(Path.join(home, ".tightbeam"))

    File.write!(
      Path.join(home, ".tightbeam/gateway.json"),
      ~s({"port":#{decoy.port},"cliToken":"decoy-token"})
    )

    {output, status} =
      TestIsolation.cmd(cli(), ["list"], cd: scratch!("guarded-cwd"), stderr_to_stdout: true)

    assert status != 0
    assert accepts(decoy) == 0, "the guarded child keeps the sandbox HOME: #{output}"

    {output, _status} = raw_cli(["list"], scratch!("raw-cwd"), home)
    assert accepts(decoy) >= 1, "positive control with the decoy HOME: #{output}"
  end

  test "T5: PATH resolves tightbeam to this repository's build and no harness tool" do
    assert TestSandboxPreflight.canonical(System.find_executable("tightbeam")) ==
             TestSandboxPreflight.canonical(cli())

    for tool <- TestSandboxPreflight.forbidden_tools(),
        do: assert(System.find_executable(tool) == nil, "#{tool} must not resolve")

    {output, status} =
      TestIsolation.cmd("sh", ["-c", "tightbeam list"],
        cd: scratch!("t5"),
        stderr_to_stdout: true
      )

    assert status != 0

    assert output =~ TestIsolation.sandbox_root(),
           "the unguided CLI falls back only to a gateway.json inside the sandbox: #{output}"

    decoy_bin = scratch!("decoy-bin")
    File.write!(Path.join(decoy_bin, "tightbeam"), "#!/bin/sh\necho DECOY-TIGHTBEAM\n")
    File.chmod!(Path.join(decoy_bin, "tightbeam"), 0o755)

    {output, 0} =
      TestIsolation.cmd("sh", ["-c", "tightbeam"],
        cd: decoy_bin,
        env: [{"PATH", decoy_bin <> ":" <> System.fetch_env!("PATH")}]
      )

    assert output =~ "DECOY-TIGHTBEAM", "positive control: PATH order decides the tightbeam run"
  end

  # The preflight in a child VM that never loads test_helper.exs.
  @preflight_script ~S"""
  [repo, scratch] = System.argv()
  if scratch != "", do: Application.put_env(:tightbeam, :test_suite_tmp, scratch)
  Tightbeam.TestSandboxPreflight.enforce!(repo)
  IO.puts("PREFLIGHT-PASSED")
  """

  defp preflight_child(cd, env, scratch \\ "") do
    paths = Enum.flat_map(:code.get_path(), &["-pa", to_string(&1)])

    System.cmd(
      System.find_executable("elixir"),
      paths ++ ["-e", @preflight_script, TestIsolation.repo(), scratch],
      cd: cd,
      env: env,
      stderr_to_stdout: true
    )
  end

  describe "T6: the preflight refuses a session above each root it checks" do
    test "baseline: an unchanged child passes" do
      assert {output, 0} = preflight_child(scratch!("t6-base"), [])
      assert output =~ "PREFLIGHT-PASSED"
    end

    test "cwd" do
      decoy = decoy!()
      tree = session_tree!(decoy, scratch!("t6-cwd"))
      {output, status} = preflight_child(tree.inner, [])
      assert status == 78 and output =~ tree.session
      assert accepts(decoy) == 0

      {output, _} = raw_cli(["list"], tree.inner, scratch!("raw-home"))
      assert accepts(decoy) >= 1, "positive control: #{output}"
    end

    test "<cwd>/tmp" do
      decoy = decoy!()
      tree = session_tree!(decoy, scratch!("t6-tmp"))
      cwd = scratch!("t6-tmp-cwd")
      File.ln_s!(tree.inner, Path.join(cwd, "tmp"))
      {output, status} = preflight_child(cwd, [])
      assert status == 78 and output =~ tree.session
      assert accepts(decoy) == 0
    end

    test "the suite scratch root" do
      decoy = decoy!()
      tree = session_tree!(decoy, scratch!("t6-scratch"))
      {output, status} = preflight_child(scratch!("t6-scratch-cwd"), [], tree.inner)
      assert status == 78 and output =~ tree.session
      assert accepts(decoy) == 0
    end

    test "HOME" do
      decoy = decoy!()
      tree = session_tree!(decoy, scratch!("t6-home"))
      {output, status} = preflight_child(scratch!("t6-home-cwd"), [{"HOME", tree.inner}])
      assert status == 78 and output =~ tree.session
      assert accepts(decoy) == 0
    end
  end

  describe "T7: the preflight refuses each sandbox fault, naming it" do
    test "a missing sandbox marker" do
      {output, 78} =
        preflight_child(scratch!("t7"), [{"TIGHTBEAM_TEST_SANDBOX", scratch!("no-marker")}])

      assert output =~ "has no .tightbeam-test-sandbox marker"
    end

    test "a VM home outside the sandbox" do
      {output, 78} = preflight_child(scratch!("t7"), [{"HOME", "/"}])
      assert output =~ "is outside the sandbox"
    end

    test "an environment variable outside the allowlist" do
      {output, 78} = preflight_child(scratch!("t7"), [{"GH_TOKEN", "synthetic"}])
      assert output =~ "outside the allowlist: GH_TOKEN"
    end

    test "a forbidden tool on PATH" do
      bin = scratch!("t7-bin")
      File.write!(Path.join(bin, "gh"), "#!/bin/sh\nexit 0\n")
      File.chmod!(Path.join(bin, "gh"), 0o755)

      {output, 78} =
        preflight_child(scratch!("t7"), [{"PATH", bin <> ":" <> System.fetch_env!("PATH")}])

      assert output =~ "gh resolves to"
    end

    test "a HOME holding .tightbeam" do
      home = scratch!("t7-home")
      File.mkdir_p!(Path.join(home, ".tightbeam"))
      {output, 78} = preflight_child(scratch!("t7"), [{"HOME", home}])
      assert output =~ ".tightbeam exists"
    end
  end

  test "Q2(e): the helper refuses unsafe inherited and declared env, passes a fixture" do
    System.put_env("GH_TOKEN", "synthetic-inherited")

    try do
      error = assert_raise TestIsolation.Refusal, fn -> TestIsolation.cmd("true", []) end
      assert error.message =~ "GH_TOKEN"
    after
      System.delete_env("GH_TOKEN")
    end

    for {env, reason} <- [
          {[{"PATH", "/usr/bin:" <> TestIsolation.toolbox()}], "PATH entry /usr/bin"},
          {[{"TIGHTBEAM_URL", "http://10.1.2.3:9"}], "not a loopback address"},
          {[{"TIGHTBEAM_BASE_DIR", "/production/base"}], "outside the sandbox"},
          {[{"HOME", "/"}], "outside the sandbox"},
          {[{"TIGHTBEAM_TOKEN", "t"}], "TIGHTBEAM_TOKEN is set without"}
        ] do
      error =
        assert_raise TestIsolation.Refusal, fn -> TestIsolation.cmd("true", [], env: env) end

      assert error.message =~ reason
    end

    fixture_base = scratch!("q2-base")

    assert {_, 0} =
             TestIsolation.cmd("true", [],
               env: [
                 {"TIGHTBEAM_BASE_DIR", fixture_base},
                 {"TIGHTBEAM_URL", "http://127.0.0.1:1"},
                 {"TIGHTBEAM_TOKEN", "fixture-token"},
                 {"GH_FIXTURE_MODE", "synthetic"}
               ]
             )
  end

  describe "T8 and T11: the launch lint fails closed" do
    test "T8: every launch form outside the helper is reported; the real tree is clean" do
      source = ~S"""
      defmodule LeakTest do
        use ExUnit.Case

        test "leaks" do
          System.cmd("tightbeam", ["list"])
          System.shell("tightbeam list")
          Port.open({:spawn_executable, "/bin/sh"}, [])
          :os.cmd(~c"tightbeam list")
          :erlang.open_port({:spawn, ~c"tightbeam list"}, [])
          Tightbeam.TestIsolation.cmd("true", [])
        end
      end
      """

      violations = LaunchIsolationLint.violations_in(%{"test/leak_test.exs" => source}, [])

      for kind <- [
            "System.cmd",
            "System.shell",
            "Port.open",
            ":os.cmd",
            ":erlang.open_port",
            "{:spawn_executable, _} port",
            "{:spawn, _} port"
          ],
          do: assert(Enum.any?(violations, &(&1 =~ " #{kind} in test leaks")), kind)

      refute Enum.any?(violations, &(&1 =~ "TestIsolation.cmd"))
      assert LaunchIsolationLint.violations(TestIsolation.repo()) == []
    end

    test "T11: executed scripts join the parse set; compile-time launches cannot be listed" do
      root = scratch!("t11")
      File.mkdir_p!(Path.join(root, "test/support"))
      File.mkdir_p!(Path.join(root, "scripts"))

      File.write!(Path.join(root, "scripts/child.exs"), ~S"""
      System.cmd("tightbeam", ["list"])
      """)

      File.write!(Path.join(root, "scripts/only_read.exs"), ~S"""
      System.cmd("tightbeam", ["list"])
      """)

      File.write!(Path.join(root, "test/runner_test.exs"), ~S"""
      defmodule RunnerTest do
        use ExUnit.Case
        @launched System.cmd("true", [])
        System.cmd("true", [])

        test "runs" do
          Tightbeam.TestIsolation.run_script!("scripts/child.exs", [])
          path = "scripts/child.exs"
          Tightbeam.TestIsolation.run_script!(path, [])
          File.read!("scripts/only_read.exs")
          Tightbeam.TestIsolation.cmd("sh", ["scripts/child.exs"])
        end
      end
      """)

      assert "scripts/child.exs" in LaunchIsolationLint.parse_set(root)
      refute "scripts/only_read.exs" in LaunchIsolationLint.parse_set(root)

      violations = LaunchIsolationLint.violations(root)
      assert Enum.any?(violations, &(&1 =~ "scripts/child.exs:1 System.cmd in top level"))
      assert Enum.any?(violations, &(&1 =~ "run_script!/3 with a non-literal path"))
      assert Enum.any?(violations, &(&1 =~ "runs scripts/child.exs outside run_script!/3"))
      assert Enum.count(violations, &(&1 =~ "runs at compile time")) == 2

      sources =
        Map.new(LaunchIsolationLint.parse_set(root), &{&1, File.read!(Path.join(root, &1))})

      listed = [
        %{
          file: "test/runner_test.exs",
          function: :compile_time,
          kind: "System.cmd",
          reason: "an attempt to list a compile-time launch",
          reviewer: "fixture"
        }
      ]

      violations = LaunchIsolationLint.violations_in(sources, listed)
      assert Enum.count(violations, &(&1 =~ "runs at compile time")) == 2
      assert Enum.any?(violations, &(&1 =~ "stale"))
    end
  end
end

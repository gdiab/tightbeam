defmodule Tightbeam.TestIsolationTest do
  # F1 (wi_34a7be66) regression tests T1-T8 and T11, plus the reviewer's Q1(c)
  # and Q2(e) conditions. A test can never reach a gateway through an ancestor
  # .tightbeam-session or a HOME gateway.json, and it fails closed if it would.
  # Every guarded case has a positive control: the same launch done raw DOES
  # reach the decoy, so a mis-wired decoy cannot pass vacuously. The only
  # gateway anywhere is a listener this test owns; it counts TCP accepts.
  use Tightbeam.TestCase, async: false

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

    # Without a session the CLI needs an explicit identity before discovery runs.
    args = ["list", "--as-process", "f1-decoy"]

    {output, status} =
      TestIsolation.cmd(cli(), args, cd: scratch!("guarded-cwd"), stderr_to_stdout: true)

    assert status != 0
    assert accepts(decoy) == 0, "the guarded child keeps the sandbox HOME: #{output}"

    {output, _status} = raw_cli(args, scratch!("raw-cwd"), home)
    assert accepts(decoy) >= 1, "positive control with the decoy HOME: #{output}"
  end

  test "T5: PATH resolves tightbeam to this repository's build and no harness tool" do
    assert TestSandboxPreflight.canonical(System.find_executable("tightbeam")) ==
             TestSandboxPreflight.canonical(cli())

    for tool <- TestSandboxPreflight.forbidden_tools(),
        tool != "ssh",
        do: assert(System.find_executable(tool) == nil, "#{tool} must not resolve")

    # ssh resolves only to the launcher's tripwire, which refuses every use.
    ssh = System.find_executable("ssh")

    assert TestSandboxPreflight.canonical(ssh) ==
             TestSandboxPreflight.canonical(Path.join(TestIsolation.sandbox_root(), "bin/ssh"))

    assert File.read!(ssh) == TestSandboxPreflight.ssh_tripwire()
    assert TestSandboxPreflight.ssh_tripwire?(ssh, TestIsolation.sandbox_root())
    assert {_, 255} = TestIsolation.cmd(ssh, ["example.invalid"], stderr_to_stdout: true)

    {output, status} =
      TestIsolation.cmd("sh", ["-c", "tightbeam list --as-process f1-decoy"],
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

    env =
      if List.keymember?(env, "HOME", 0), do: env, else: [{"HOME", scratch!("child-home")} | env]

    System.cmd(
      System.find_executable("elixir"),
      paths ++ ["-e", @preflight_script, TestIsolation.repo(), scratch],
      cd: cd,
      env: env,
      stderr_to_stdout: true
    )
  end

  describe "T6: the preflight refuses a session above each root it checks" do
    # Each child gets a fresh sandbox HOME: the suite's own HOME may already hold
    # what tests wrote there, which the preflight rightly refuses.
    test "baseline: an unchanged child passes" do
      assert {output, 0} = preflight_child(scratch!("t6-base"), [{"HOME", scratch!("t6-home")}])
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
          {[{"TIGHTBEAM_TOKEN", "t"}], "TIGHTBEAM_TOKEN is set without"},
          {[
             {"GIT_CONFIG_COUNT", "1"},
             {"GIT_CONFIG_KEY_0", "credential.helper"},
             {"GIT_CONFIG_VALUE_0", "osxkeychain"}
           ], "git config credential.helper"},
          {[{"GIT_CONFIG_COUNT", "1"}, {"GIT_CONFIG_KEY_0", "http.extraHeader"}],
           "git config http.extraHeader"},
          {[{"GIT_CONFIG_COUNT", "1"}, {"GIT_CONFIG_KEY_0", "url.git@example.com:.insteadOf"}],
           "insteadOf"},
          {[{"GIT_CONFIG_COUNT", "1"}, {"GIT_CONFIG_KEY_0", "core.sshCommand"}],
           "git config core.sshCommand"},
          {[{"GIT_CONFIG_PARAMETERS", "'include.path=/etc/gitconfig'"}],
           "git config include.path"},
          {[{"GIT_ASKPASS", "/bin/echo"}], "GIT_ASKPASS=/bin/echo is not a fixture"},
          {[{"SSH_ASKPASS", "/bin/echo"}], "SSH_ASKPASS=/bin/echo is not a fixture"},
          {[{"GIT_SSH_COMMAND", "ssh -i key"}], "GIT_SSH_COMMAND=ssh -i key is not a fixture"},
          {[{"GIT_CONFIG_NOSYSTEM", "0"}], "GIT_CONFIG_NOSYSTEM must stay 1"},
          {[{"GIT_CONFIG_GLOBAL", "/etc/gitconfig"}], "GIT_CONFIG_GLOBAL=/etc/gitconfig"}
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
                 {"GH_FIXTURE_MODE", "synthetic"},
                 {"GIT_CONFIG_COUNT", "1"},
                 {"GIT_CONFIG_KEY_0", "user.name"},
                 {"GIT_CONFIG_VALUE_0", "fixture"},
                 {"GIT_SSH_COMMAND", Path.join(fixture_base, "ssh-fixture")}
               ]
             )
  end

  test "B1: an executable named by path must be a toolbox tool, a repository file or a fixture" do
    outside = "/usr/bin/yes"

    for launch <- [
          fn -> TestIsolation.cmd(outside, []) end,
          fn -> Tightbeam.TestIsolation.port_open({:spawn_executable, outside}, [:binary]) end,
          fn -> Tightbeam.TestIsolation.port_open({:spawn, "#{outside} y"}, [:binary]) end,
          fn ->
            Tightbeam.TestIsolation.run_script!("scripts/verify_mix.sh", [], runner: outside)
          end
        ] do
      error = assert_raise TestIsolation.Refusal, launch
      assert error.message =~ "is not a toolbox tool"
    end

    for forbidden <- [
          "/usr/local/bin/codex",
          "/usr/bin/ssh",
          Path.join(TestIsolation.repo(), "gh")
        ] do
      error = assert_raise TestIsolation.Refusal, fn -> TestIsolation.cmd(forbidden, []) end
      assert error.message =~ "is a forbidden tool", forbidden
    end

    repo = TestIsolation.repo()
    assert :ok = TestIsolation.executable!("/bin/sh", repo)
    assert :ok = TestIsolation.executable!(cli(), repo)
    assert :ok = TestIsolation.executable!(Path.join(TestIsolation.toolbox(), "ssh"), repo)

    fixture = Path.join(scratch!("b1"), "gh")
    File.write!(fixture, "#!/bin/sh\necho fixture-gh\n")
    File.chmod!(fixture, 0o755)
    assert {"fixture-gh\n", 0} = TestIsolation.cmd(fixture, [])
  end

  describe "T12: the passthrough carries only b0's gate values (asg_b30d5c78)" do
    # What a suite VM that got past its preflight does with these values: it
    # connects to the gateway port it was configured with and joins its gate
    # node. Each guarded child runs the preflight first and must be refused
    # with no TCP accept and no node connection; the positive control runs the
    # same contact without the preflight and must reach the test-owned decoys.
    @contact_script ~S"""
    [repo, guarded] = System.argv()
    if guarded == "1", do: Tightbeam.TestSandboxPreflight.enforce!(repo)
    port = String.to_integer(System.get_env("TIGHTBEAM_PORT", "0"))
    if port != 0, do: :gen_tcp.connect({127, 0, 0, 1}, port, [], 2_000)

    if gate = System.get_env("TIGHTBEAM_GATE_NODE") do
      [_name, host] = node() |> Atom.to_string() |> String.split("@")
      Node.connect(String.to_atom(gate <> "@" <> host))
    end

    IO.puts("CONTACT-DONE")
    """

    @decoy_node_script ~S"""
    :ok = :net_kernel.monitor_nodes(true)
    parent = self()
    spawn(fn -> IO.read(:stdio, :eof); send(parent, :stop) end)
    IO.puts("DECOY-READY")

    loop = fn loop ->
      receive do
        {:nodeup, node} -> IO.puts("NODEUP #{node}"); loop.(loop)
        {:nodedown, _node} -> loop.(loop)
        :stop -> System.halt(0)
      end
    end

    loop.(loop)
    """

    @cookie "f1-t12-decoy-cookie"

    defp distributed_args(name),
      do: ["--sname", "#{name}_#{System.unique_integer([:positive])}", "--cookie", @cookie]

    # A test-owned BEAM node standing in for a live node; it reports each
    # node that connects to it.
    defp decoy_node! do
      [_, sname, _, _] = args = distributed_args("f1_decoy")

      port =
        Tightbeam.TestIsolation.port_open(
          {:spawn_executable, System.find_executable("elixir")},
          [
            :binary,
            :exit_status,
            {:line, 1024},
            {:cd, scratch!("t12-decoy")},
            {:env, [{~c"HOME", String.to_charlist(scratch!("t12-decoy-home"))}]},
            {:args, args ++ ["-e", @decoy_node_script]}
          ]
        )

      on_exit(fn -> if Port.info(port), do: Port.close(port) end)
      assert_receive {^port, {:data, {:eol, "DECOY-READY"}}}, 30_000
      %{port: port, name: sname}
    end

    defp contact_child(env, guarded) do
      paths = Enum.flat_map(:code.get_path(), &["-pa", to_string(&1)])

      TestIsolation.cmd(
        System.find_executable("elixir"),
        distributed_args("f1_probe") ++
          paths ++ ["-e", @contact_script, TestIsolation.repo(), guarded],
        cd: scratch!("t12"),
        env: [{"HOME", scratch!("t12-home")} | env],
        stderr_to_stdout: true
      )
    end

    defp nodeups(decoy) do
      receive do
        {port, {:data, {:eol, "NODEUP " <> _}}} when port == decoy.port -> 1 + nodeups(decoy)
      after
        500 -> 0
      end
    end

    test "a fixed or production TIGHTBEAM_PORT is refused, with no accept" do
      decoy = decoy!()

      for value <- ["11373", Integer.to_string(decoy.port)] do
        {output, status} = contact_child([{"TIGHTBEAM_PORT", value}], "1")
        assert status == 78, output
        assert output =~ "TIGHTBEAM_PORT=#{value}"
        refute output =~ "CONTACT-DONE"
      end

      Process.sleep(200)
      assert accepts(decoy) == 0

      {output, 0} = contact_child([{"TIGHTBEAM_PORT", Integer.to_string(decoy.port)}], "0")
      assert output =~ "CONTACT-DONE"
      assert accepts(decoy) >= 1, "positive control: the unguarded child must reach the decoy"
    end

    test "a foreign TIGHTBEAM_GATE_NODE is refused, with no node connection" do
      decoy = decoy_node!()
      gate = [{"TIGHTBEAM_AUTHORITATIVE_GATE", "1"}, {"TIGHTBEAM_GATE_NODE", decoy.name}]

      {output, status} = contact_child(gate, "1")
      assert status == 78, output
      assert output =~ "TIGHTBEAM_GATE_NODE=#{inspect(decoy.name)} does not match"
      assert nodeups(decoy) == 0

      {output, 0} = contact_child(gate, "0")
      assert output =~ "CONTACT-DONE"

      assert nodeups(decoy) >= 1,
             "positive control: the unguarded child must reach the decoy node"
    end

    test "the gate claim and CI values must have their fixed shapes" do
      for {env, reason} <- [
            {[{"TIGHTBEAM_AUTHORITATIVE_GATE", "yes"}], "is not the gate claim"},
            {[{"TIGHTBEAM_AUTHORITATIVE_GATE", "1"}], "set without TIGHTBEAM_GATE_NODE"},
            {[{"TIGHTBEAM_GATE_NODE", "tightbeam"}], "does not match"},
            {[{"CANDIDATE_SHA", "ghp_not-a-commit"}], "not a 40-character commit id"},
            {[{"RUNNER_TEMP", "relative/tmp"}], "RUNNER_TEMP is not an absolute path"},
            {[{"RUNNER_TEMP", "/runner/tmp"}, {"DD36_DARWIN_DIAGNOSTIC_DIR", "/elsewhere"}],
             "not a directory under RUNNER_TEMP"}
          ] do
        {output, 78} = preflight_child(scratch!("t12-shape"), env)
        assert output =~ reason
      end

      gate = [
        {"TIGHTBEAM_AUTHORITATIVE_GATE", "1"},
        {"TIGHTBEAM_GATE_NODE", "tightbeam_mix_gate_AbCd1234"},
        {"TIGHTBEAM_PORT", "0"},
        {"CANDIDATE_SHA", String.duplicate("a", 40)}
      ]

      assert {output, 0} = preflight_child(scratch!("t12-shape"), gate)
      assert output =~ "PREFLIGHT-PASSED"
    end
  end

  describe "T8 and T11: the launch lint fails closed" do
    test "T8: every launch form outside the helper is reported; the real tree is clean" do
      source = ~S"""
      defmodule LeakTest do
        use ExUnit.Case, async: true

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
        use ExUnit.Case, async: true
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

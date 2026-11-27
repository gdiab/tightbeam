defmodule Tightbeam.DiscoveryPrecedenceTest do
  # F2 v6 (wi_34a7be66, spec art_c4b45e41): explicit settings win over an ambient
  # session file in CLI discovery, credential-health resolves through the same
  # selection, and no agent environment can carry an explicit endpoint or base.
  # P14/P15 and H14/H15/H23 cross the process boundary with the real CLI and
  # test-owned decoy listeners only; E1-E5 cover the product's spawn paths.
  use Tightbeam.TestCase, async: false

  import ExUnit.CaptureLog

  alias Tightbeam.{Archetypes, DB, FixtureSession, Model, Placement, Rails}

  @cli Path.expand("../cli/target/release/tightbeam", __DIR__)
  @poison "f2-poison-value-4c7d"

  setup do
    base_dir = scratch!("f2-base")
    File.write!(Path.join(base_dir, "gateway.json"), JSON.encode!(%{cliToken: "tbc_test"}))
    db = :"f2_db_#{System.unique_integer([:positive])}"
    start_supervised!({DB, path: ":memory:", name: db})
    :ok = Tightbeam.Schema.ensure_all(db)
    Archetypes.load!(base_dir)
    Rails.load!(base_dir)

    old_url = Application.get_env(:tightbeam, :advertised_url)
    Application.put_env(:tightbeam, :advertised_url, "http://gateway.example:4000")

    on_exit(fn ->
      :persistent_term.erase(Tightbeam.Rails)

      if old_url,
        do: Application.put_env(:tightbeam, :advertised_url, old_url),
        else: Application.delete_env(:tightbeam, :advertised_url)
    end)

    %{base_dir: base_dir, db: db}
  end

  defp scratch!(label) do
    dir = Path.join(System.tmp_dir!(), "#{label}-#{System.unique_integer([:positive])}")
    File.mkdir_p!(dir)
    on_exit(fn -> File.rm_rf!(dir) end)
    dir
  end

  # A test-owned gateway stand-in that counts TCP accepts and answers 503.
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

    %{port: port, counter: counter, url: "http://127.0.0.1:#{port}"}
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

  # A session file naming decoy `a` two folders above the returned working dir.
  defp session_tree!(a) do
    root = scratch!("f2-tree")
    FixtureSession.write!(Path.join(root, ".tightbeam-session"), %{url: a.url, token: "decoy-a"})
    inner = Path.join([root, "work", "nested"])
    File.mkdir_p!(inner)
    %{root: root, session: Path.join(root, ".tightbeam-session"), inner: inner}
  end

  defp gateway_host_base!(path, decoy) do
    File.mkdir_p!(path)

    File.write!(
      Path.join(path, "gateway.json"),
      JSON.encode!(%{port: decoy.port, cliToken: "decoy-b"})
    )

    path
  end

  # credential-health writes at most one stderr line, then its one JSON line.
  defp credential_health_output(output) do
    lines = String.split(output, "\n", trim: true)
    {Enum.drop(lines, -1), JSON.decode!(List.last(lines))}
  end

  @base_notice "tightbeam: notice: using TIGHTBEAM_BASE_DIR (explicit); ignoring the session file"

  describe "P14/P15: dispatch at the process boundary" do
    test "P14: an explicit base wins over the session file, which gets no connection" do
      a = decoy!()
      b = decoy!()
      tree = session_tree!(a)
      base = gateway_host_base!(scratch!("f2-explicit-base"), b)

      {output, _status} =
        FixtureSession.cmd(@cli, ["list", "--as-process", "f2-probe"],
          cd: tree.inner,
          env: [{"TIGHTBEAM_BASE_DIR", base}],
          stderr_to_stdout: true
        )

      Process.sleep(200)
      assert accepts(b) >= 1, output
      assert accepts(a) == 0, output
      assert output =~ @base_notice <> " at " <> tree.session
    end

    test "P15: with nothing explicit the session file is used, silently" do
      a = decoy!()
      tree = session_tree!(a)

      {output, _status} =
        FixtureSession.cmd(@cli, ["list"], cd: tree.inner, stderr_to_stdout: true)

      Process.sleep(200)
      assert accepts(a) >= 1, output
      refute output =~ "notice"
      refute output =~ "incomplete explicit endpoint"
    end
  end

  describe "H14/H15/H23: credential-health at the process boundary" do
    test "H14: an explicit base wins; the session's listener gets no connection" do
      a = decoy!()
      b = decoy!()
      tree = session_tree!(a)
      base = gateway_host_base!(scratch!("f2-h14-base"), b)

      {output, _status} =
        FixtureSession.cmd(@cli, ["credential-health"],
          cd: tree.inner,
          env: [{"TIGHTBEAM_BASE_DIR", base}],
          stderr_to_stdout: true
        )

      Process.sleep(200)
      assert accepts(b) >= 1, output
      assert accepts(a) == 0, output
      {stderr, stdout} = credential_health_output(output)
      assert stderr == [@base_notice]
      assert stdout["endpointSource"] == "env"
      assert stdout["endpoint"] == %{"host" => "127.0.0.1", "port" => b.port}
    end

    test "H15: with nothing explicit the session's listener is used" do
      a = decoy!()
      tree = session_tree!(a)

      {output, _status} =
        FixtureSession.cmd(@cli, ["credential-health"], cd: tree.inner, stderr_to_stdout: true)

      Process.sleep(200)
      assert accepts(a) >= 1, output
      {stderr, stdout} = credential_health_output(output)
      assert stderr == []
      assert stdout["endpointSource"] == "config"
    end

    test "H23: under a test root that excludes the session, the base is used with no notice" do
      a = decoy!()
      b = decoy!()
      tree = session_tree!(a)
      root = Path.join(tree.root, "work")
      base = gateway_host_base!(Path.join(root, "base"), b)

      {output, _status} =
        FixtureSession.cmd(@cli, ["credential-health"],
          cd: tree.inner,
          env: [{"TIGHTBEAM_BASE_DIR", base}, {"TIGHTBEAM_TEST_ROOT", root}],
          stderr_to_stdout: true
        )

      Process.sleep(200)
      assert accepts(b) >= 1, output
      assert accepts(a) == 0, output
      {stderr, stdout} = credential_health_output(output)
      assert stderr == []
      assert stdout["endpointSource"] == "env"
    end
  end

  test "E1: TIGHTBEAM_TOKEN is refused as an overlay name", %{db: db} do
    assert {:error, %{code: "reserved_env_name"}} =
             Placement.set_env_overlay(
               db,
               "testhost",
               "claude",
               "TIGHTBEAM_TOKEN",
               @poison,
               "user:operator"
             )
  end

  describe "E2: a local spawn carries no explicit endpoint or base" do
    setup do
      poison = %{
        "TIGHTBEAM_URL" => "http://127.0.0.1:9",
        "TIGHTBEAM_TOKEN" => @poison,
        "TIGHTBEAM_BASE_DIR" => "/production/org"
      }

      previous = Map.new(poison, fn {name, _} -> {name, System.get_env(name)} end)
      for {name, value} <- poison, do: System.put_env(name, value)

      on_exit(fn ->
        for {name, value} <- previous,
            do: if(value, do: System.put_env(name, value), else: System.delete_env(name))
      end)

      :ok
    end

    test "inherited TIGHTBEAM_URL, TIGHTBEAM_TOKEN and TIGHTBEAM_BASE_DIR are removed" do
      out = Path.join(scratch!("f2-e2"), "env")

      {:ok, conn} =
        Tightbeam.Acp.Conn.start_link(
          cmd: ["sh", "-c", "env > #{out}"],
          env: [{"TIGHTBEAM_HOME", "/session/home"}, {"PATH", System.fetch_env!("PATH")}],
          subscriber: self()
        )

      on_exit(fn -> if Process.alive?(conn), do: GenServer.stop(conn) end)
      assert_receive {:acp_exit, _status}, 5_000

      child_env = File.read!(out)

      for name <- ~w(TIGHTBEAM_URL TIGHTBEAM_TOKEN TIGHTBEAM_BASE_DIR) do
        refute child_env =~ ~r/^#{name}=/m, name
      end

      refute child_env =~ @poison
      assert child_env =~ ~r{^TIGHTBEAM_HOME=/session/home$}m
    end

    test "a spawned agent's CLI still resolves its own session, with no notice or refusal" do
      a = decoy!()
      tree = session_tree!(a)
      dir = scratch!("f2-e2-cli")
      stdout = Path.join(dir, "stdout")
      stderr = Path.join(dir, "stderr")
      script = "cd #{tree.inner} && #{@cli} list > #{stdout} 2> #{stderr}; exit 0"

      {:ok, conn} =
        Tightbeam.Acp.Conn.start_link(
          cmd: ["sh", "-c", script],
          env: [{"TIGHTBEAM_HOME", dir}, {"PATH", System.fetch_env!("PATH")}],
          subscriber: self()
        )

      on_exit(fn -> if Process.alive?(conn), do: GenServer.stop(conn) end)
      assert_receive {:acp_exit, _status}, 15_000

      errors = File.read!(stderr)
      assert accepts(a) >= 1, errors
      refute errors =~ "notice"
      refute errors =~ "incomplete explicit endpoint"
    end
  end

  describe "E3: every remote launch clears the explicit-tier variables first" do
    for harness <- [
          Tightbeam.Harness.Claude,
          Tightbeam.Harness.Codex,
          Tightbeam.Harness.Pi,
          Tightbeam.Harness.Fixture
        ] do
      test "#{inspect(harness)}: env -u TIGHTBEAM_TOKEN -u TIGHTBEAM_BASE_DIR right after exec" do
        harness = unquote(harness)
        vectors = harness.conformance_vectors()["prepare_launch"]

        remote =
          Enum.filter(vectors, &(&1.input.locality == :remote and &1.support == :supported))

        assert remote != []

        for vector <- remote do
          %{argv: argv} =
            Tightbeam.Harness.Support.observe_vector(harness, "prepare_launch", vector)

          exec = Enum.find_index(argv, &(&1 == "exec"))
          assert exec, inspect(argv)

          assert Enum.slice(argv, exec + 1, 5) in [
                   ["env", "-u", "TIGHTBEAM_TOKEN", "-u", "TIGHTBEAM_BASE_DIR"],
                   ["/usr/bin/env", "-u", "TIGHTBEAM_TOKEN", "-u", "TIGHTBEAM_BASE_DIR"]
                 ],
                 inspect(argv)

          # Nothing between exec and the -u options: every assignment follows them.
          after_exec = Enum.drop(argv, exec + 1)
          first_assignment = Enum.find_index(after_exec, &String.contains?(&1, "="))
          assert first_assignment == nil or first_assignment >= 5, inspect(argv)
        end
      end
    end
  end

  test "E4: the source-test scrub reads TIGHTBEAM_TOKEN from the shared list" do
    assert "TIGHTBEAM_TOKEN" in Tightbeam.ProductionIdentityEnv.exact()
    assert Tightbeam.ProductionIdentityEnv.production_identity?("TIGHTBEAM_TOKEN")

    root = Path.expand("..", __DIR__)

    assert File.read!(Path.join(root, "scripts/production-identity-env")) =~
             ~r/^exact TIGHTBEAM_TOKEN$/m

    assert File.read!(Path.join(root, "scripts/verify_mix.sh")) =~ "production-identity-env"
  end

  describe "E5: pre-seeded TIGHTBEAM_* overlay rows never reach a spawned agent" do
    setup %{db: db} do
      {:ok, _} =
        Placement.register_host(db, "worker", %{
          ssh: "codex@worker",
          base_dir: "/srv/tb",
          cli_bin: "/srv/tb/bin"
        })

      for {host, harness} <- [{Placement.local_host_name(), "claude"}, {"worker", "codex"}],
          name <- ~w(TIGHTBEAM_TOKEN TIGHTBEAM_BASE_DIR TIGHTBEAM_URL) do
        {:ok, []} =
          DB.query(
            db,
            "INSERT INTO harness_env_overlays (host, harness, name, value, setBy, setAt) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            [host, harness, name, @poison, "pre-prefix-rule", 1]
          )
      end

      :ok
    end

    defp spawn_config(base_dir, db) do
      sh = fn command ->
        if Enum.any?(command, &String.contains?(&1, "credential-harvest")) and
             Enum.any?(command, &String.contains?(&1, "cat")),
           do: {"", 42},
           else: {"", 0}
      end

      %{
        base_dir: base_dir,
        db: db,
        cwd: "/work",
        cli_bin: "/local/bin",
        default_model: Model.new("fable"),
        sh: sh,
        sh_out: &inventory_shell/1
      }
    end

    # Codex reads a skill inventory over ssh (`node -e`): it gets a synthetic one and
    # the command is kept for the F2-5c check; nothing runs.
    defp inventory_shell(command) do
      send(self(), {:inventory_command, command})

      if "node" in command and "-e" in command,
        do: {JSON.encode!(%{"bypass_hook_trust" => true, "skills" => %{"config" => []}}), 0},
        else: {"", 0}
    end

    test "local spawn", %{base_dir: base_dir, db: db} do
      log =
        capture_log(fn ->
          env =
            spawn_config(base_dir, db)
            |> Placement.adapter_opts!({:claude, "default", Placement.local_host_name()})
            |> Keyword.fetch!(:env)

          names = Enum.map(env, &elem(&1, 0))
          refute "TIGHTBEAM_TOKEN" in names
          refute "TIGHTBEAM_BASE_DIR" in names
          refute "TIGHTBEAM_URL" in names
          refute Enum.any?(env, fn {_name, value} -> value == @poison end)
        end)

      for name <- ~w(TIGHTBEAM_TOKEN TIGHTBEAM_BASE_DIR TIGHTBEAM_URL) do
        assert log =~ "dropping env overlay #{name} for claude@", log
      end

      refute log =~ @poison
    end

    test "remote spawn", %{base_dir: base_dir, db: db} do
      log =
        capture_log(fn ->
          command =
            spawn_config(base_dir, db)
            |> Placement.adapter_opts!({:codex, "default", "worker"})
            |> Keyword.fetch!(:cmd)

          refute Enum.any?(command, &String.contains?(&1, @poison)), inspect(command)
          refute Enum.any?(command, &String.starts_with?(&1, "TIGHTBEAM_TOKEN="))
          refute Enum.any?(command, &String.starts_with?(&1, "TIGHTBEAM_BASE_DIR="))

          # The one TIGHTBEAM_URL is the launch's own advertised URL.
          assert Enum.filter(command, &String.starts_with?(&1, "TIGHTBEAM_URL=")) ==
                   ["TIGHTBEAM_URL=http://gateway.example:4000"]
        end)

      for name <- ~w(TIGHTBEAM_TOKEN TIGHTBEAM_BASE_DIR TIGHTBEAM_URL) do
        assert log =~ "dropping env overlay #{name} for codex@worker", log
      end

      refute log =~ @poison

      # F2-5c on the codex inventory read over ssh: the -u options come right after env.
      assert_received {:inventory_command, inventory}
      env_at = Enum.find_index(inventory, &(&1 == "env"))
      assert env_at, inspect(inventory)

      assert Enum.slice(inventory, env_at + 1, 4) ==
               ["-u", "TIGHTBEAM_TOKEN", "-u", "TIGHTBEAM_BASE_DIR"],
             inspect(inventory)
    end
  end
end

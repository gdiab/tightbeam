defmodule Tightbeam.CredentialHealthCliTest do
  use Tightbeam.TestCase, async: false
  import ExUnit.CaptureLog

  alias Tightbeam.{ConnRegistry, DB, Devices, Model, Org}
  alias Tightbeam.Wire.Router

  @cli Path.expand("../cli/target/release/tightbeam", __DIR__)
  @token "ZXQ9V7M5N3P1C8R6"
  @instance String.duplicate("a", 64)

  defmodule Stub do
    @behaviour Plug
    import Plug.Conn

    @impl Plug
    def init(opts), do: opts

    @impl Plug
    def call(conn, opts) do
      send(opts[:parent], {
        :credential_health_request,
        conn.request_path,
        get_req_header(conn, "authorization")
      })

      if delay = opts[:delay_ms], do: Process.sleep(delay)

      conn =
        Enum.reduce(opts[:headers] || [], conn, fn {name, value}, conn ->
          put_resp_header(conn, name, value)
        end)

      send_resp(conn, opts[:status] || 200, opts[:body] || "")
    end
  end

  setup do
    root =
      Path.join(
        System.tmp_dir!(),
        "tightbeam-credential-health-cli-#{System.unique_integer([:positive])}"
      )

    home = Path.join(root, "home")
    cwd = Path.join(root, "work")
    File.mkdir_p!(home)
    File.mkdir_p!(cwd)
    suffix = System.unique_integer([:positive])
    db = String.to_atom("credential_health_cli_db_#{suffix}")
    registry = String.to_atom("credential_health_cli_registry_#{suffix}")
    start_supervised!({DB, path: ":memory:", name: db})
    start_supervised!({ConnRegistry, name: registry})
    ensure_all_schemas(db)
    Devices.add_user(db, "cli-health-owner", true)
    active = session(db, "cli-health-active")
    retired = session(db, "cli-health-retired")

    assert %{state: "retired"} =
             Org.retire(db, retired.session_key, "user:cli-health-owner", 1_000)

    {:pending, pending} =
      Devices.pair(db, %{
        device_id: "cli-health-device",
        claimed_name: "CLI Health Owner",
        platform: nil,
        model: nil
      })

    device = Devices.approve(db, pending.device_id, "cli-health-owner")
    on_exit(fn -> File.rm_rf!(root) end)

    %{
      root: root,
      home: home,
      cwd: cwd,
      db: db,
      registry: registry,
      active: active,
      retired: retired,
      device: device
    }
  end

  test "standard client reaches the real health route for every credential class", ctx do
    base = Path.join(ctx.root, "real-gateway")
    gateway = real_gateway(ctx, base)

    File.write!(
      Path.join(base, "gateway.json"),
      JSON.encode!(%{port: gateway.port, unrecognizedCanary: "CANARY_FILE_VALUE_P8T6"})
    )

    before = files(ctx.root)

    log =
      capture_log(fn ->
        for {token, expected, status} <- [
              {@token, "ok", 0},
              {ctx.active.cli_token, "ok", 0},
              {ctx.retired.cli_token, "revoked", 1},
              {"UNKNOWN_CREDENTIAL_7X9Q", "auth_failed", 1},
              {ctx.device.token, "auth_failed", 1}
            ] do
          result =
            invoke(ctx, [],
              TIGHTBEAM_URL: "http://127.0.0.1:#{gateway.port}",
              TIGHTBEAM_TOKEN: token
            )

          assert result.status == status
          assert result.json["result"] == expected
          assert result.json["endpoint"] == %{"host" => "127.0.0.1", "port" => gateway.port}
          assert result.json["instance"] == Tightbeam.CredentialHealth.instance(base)
          assert_redacted(result.output, token)
        end

        without_credential = invoke(ctx, [], TIGHTBEAM_BASE_DIR: base)
        assert without_credential.status == 1
        assert without_credential.json["result"] == "auth_failed"
      end)

    for token <- [
          @token,
          ctx.active.cli_token,
          ctx.retired.cli_token,
          "UNKNOWN_CREDENTIAL_7X9Q",
          ctx.device.token
        ] do
      assert_redacted(log, token)
    end

    refute log =~ "CANARY_FILE_VALUE_P8T6"
    assert files(ctx.root) == before
  end

  test "implicit binding compares two real gateways in one exchange", ctx do
    base_a = Path.join(ctx.root, "gateway-a")
    base_b = Path.join(ctx.root, "gateway-b")
    File.mkdir_p!(base_a)
    gateway_a = real_gateway(ctx, base_a)
    gateway_b = real_gateway(ctx, base_b)

    File.write!(
      Path.join(base_a, "gateway.json"),
      JSON.encode!(%{port: gateway_b.port, cliToken: @token})
    )

    result = invoke(ctx, [], TIGHTBEAM_BASE_DIR: base_a)
    assert result.status == 1
    assert result.json["result"] == "instance_mismatch"
    assert result.json["endpoint"] == %{"host" => "127.0.0.1", "port" => gateway_b.port}
    assert result.json["instance"] == Tightbeam.CredentialHealth.instance(base_b)
    refute result.json["instance"] == Tightbeam.CredentialHealth.instance(base_a)
    refute result.json["endpoint"]["port"] == gateway_a.port
  end

  test "validated server classes, implicit and explicit binding produce the exact public shape",
       ctx do
    for {server_class, status} <- [{"ok", 0}, {"auth_failed", 1}, {"revoked", 1}] do
      server = stub(ctx, body: valid_body(server_class))

      result =
        invoke(ctx, [],
          TIGHTBEAM_URL: "http://127.0.0.1:#{server.port}/ignored?raw=secret",
          TIGHTBEAM_TOKEN: @token
        )

      assert result.status == status
      assert result.stderr == ""

      assert result.json == %{
               "result" => server_class,
               "endpoint" => %{"host" => "127.0.0.1", "port" => server.port},
               "endpointSource" => "env",
               "instance" => %{"id" => @instance, "host" => "testhost"},
               "version" => Tightbeam.CliCompatibility.required_version()
             }

      assert_receive {:credential_health_request, "/agent/credential-health",
                      ["Bearer " <> @token]}

      assert_redacted(result.output, @token)
    end

    server = stub(ctx, body: valid_body("ok"))

    explicit =
      invoke(ctx, ["--expect-instance", String.duplicate("b", 64)],
        TIGHTBEAM_URL: "http://127.0.0.1:#{server.port}",
        TIGHTBEAM_TOKEN: @token
      )

    assert explicit.status == 1
    assert explicit.json["result"] == "instance_mismatch"
    assert explicit.json["instance"]["id"] == @instance

    base = Path.join(ctx.root, "CANARY_BASE_PATH_Q7W9")
    File.mkdir_p!(base)

    File.write!(
      Path.join(base, "gateway.json"),
      JSON.encode!(%{
        port: server.port,
        cliToken: @token,
        unrecognizedCanary: "CANARY_FILE_VALUE_P8T6"
      })
    )

    implicit = invoke(ctx, [], TIGHTBEAM_BASE_DIR: base)
    assert implicit.status == 1
    assert implicit.json["result"] == "instance_mismatch"
    assert implicit.json["endpointSource"] == "env"
    refute implicit.output =~ base
    refute implicit.output =~ "CANARY_FILE_VALUE_P8T6"
  end

  test "unavailable matrix has null server fields, one attempt and no redirect follow", ctx do
    cases = [
      {:not_found, [status: 404, body: "CANARY_RAW_ERROR"]},
      {:rate_limited, [status: 429, body: ~s({"schemaVersion":1})]},
      {:server_unavailable, [status: 503, body: ~s({"schemaVersion":1})]},
      {:malformed, [status: 200, body: "not-json CANARY_RAW_ERROR"]},
      {:oversize, [status: 200, body: String.duplicate("x", 4_097)]}
    ]

    for {_name, options} <- cases do
      server = stub(ctx, options)

      result =
        invoke(ctx, [],
          TIGHTBEAM_URL: "http://127.0.0.1:#{server.port}",
          TIGHTBEAM_TOKEN: @token
        )

      assert_unavailable(result, server.port)
      assert_receive {:credential_health_request, "/agent/credential-health", _authorization}
      refute result.output =~ "CANARY_RAW_ERROR"
    end

    target = stub(ctx, body: valid_body("ok"))

    redirect =
      stub(ctx,
        status: 302,
        headers: [{"location", "http://127.0.0.1:#{target.port}/target"}],
        body: "redirect"
      )

    result =
      invoke(ctx, [],
        TIGHTBEAM_URL: "http://127.0.0.1:#{redirect.port}",
        TIGHTBEAM_TOKEN: @token
      )

    assert_unavailable(result, redirect.port)
    assert_receive {:credential_health_request, "/agent/credential-health", _authorization}
    refute_receive {:credential_health_request, "/target", _authorization}

    unused_port = unused_loopback_port()

    result =
      invoke(ctx, [],
        TIGHTBEAM_URL: "http://127.0.0.1:#{unused_port}",
        TIGHTBEAM_TOKEN: @token
      )

    assert_unavailable(result, unused_port)

    slow = stub(ctx, body: valid_body("ok"), delay_ms: 11_000)

    result =
      invoke(ctx, [],
        TIGHTBEAM_URL: "http://127.0.0.1:#{slow.port}",
        TIGHTBEAM_TOKEN: @token
      )

    assert_unavailable(result, slow.port)
  end

  test "source classes and loopback refusal are explicit and credential absence sends no header",
       ctx do
    server = stub(ctx, body: valid_body("auth_failed"))
    default_base = Path.join(ctx.home, ".tightbeam")
    File.mkdir_p!(default_base)
    File.write!(Path.join(default_base, "gateway.json"), JSON.encode!(%{port: server.port}))
    before = files(ctx.root)
    result = invoke(ctx, [])
    assert result.json["endpointSource"] == "default"
    assert result.json["result"] in ["auth_failed", "instance_mismatch"]
    assert_receive {:credential_health_request, "/agent/credential-health", []}
    assert files(ctx.root) == before

    missing = %{ctx | home: Path.join(ctx.root, "empty-home")}
    File.mkdir_p!(missing.home)
    result = invoke(missing, [])
    assert result.status == 1
    assert result.json["result"] == "unavailable"
    assert result.json["endpoint"] == nil
    assert result.json["endpointSource"] == "default"

    malformed_base = Path.join(ctx.root, "gateway-without-port")
    File.mkdir_p!(malformed_base)
    File.write!(Path.join(malformed_base, "gateway.json"), ~s({"cliToken":"#{@token}"}))
    result = invoke(ctx, [], TIGHTBEAM_BASE_DIR: malformed_base)
    assert result.json["endpoint"] == nil
    assert result.json["endpointSource"] == "env"

    session_dir = Path.join(ctx.cwd, "nested")
    File.mkdir_p!(session_dir)

    File.write!(
      Path.join(ctx.cwd, ".tightbeam-session"),
      JSON.encode!(%{url: "ws://user:CANARY_USERINFO@127.0.0.1:#{server.port}/private"})
    )

    result = invoke(%{ctx | cwd: session_dir}, [])
    assert result.json["endpointSource"] == "config"
    assert result.json["endpoint"] == nil
    assert result.json["result"] == "unavailable"
    refute result.output =~ "CANARY_USERINFO"
    refute_receive {:credential_health_request, "/agent/credential-health", _authorization}

    File.write!(
      Path.join(ctx.cwd, ".tightbeam-session"),
      JSON.encode!(%{
        url: "ws://user:CANARY_USERINFO@127.0.0.1:#{server.port}/private",
        token: @token
      })
    )

    result = invoke(%{ctx | cwd: session_dir}, [])
    assert result.json["endpointSource"] == "config"
    assert result.json["endpoint"] == %{"host" => "127.0.0.1", "port" => server.port}
    refute result.output =~ "CANARY_USERINFO"
    assert_receive {:credential_health_request, "/agent/credential-health", ["Bearer " <> @token]}

    File.write!(
      Path.join(ctx.cwd, ".tightbeam-session"),
      JSON.encode!(%{url: "ws://127.0.0.1:#{server.port}", token: 7})
    )

    result = invoke(%{ctx | cwd: session_dir}, [])
    assert result.json["endpointSource"] == "config"
    assert result.json["endpoint"] == nil
    assert result.json["result"] == "unavailable"
    refute_receive {:credential_health_request, "/agent/credential-health", _authorization}

    File.rm!(Path.join(ctx.cwd, ".tightbeam-session"))

    for refused <- [
          "http://localhost:#{server.port}",
          "http://gateway-host.local:#{server.port}",
          "http://10.0.0.1:#{server.port}"
        ] do
      result =
        invoke(ctx, [],
          TIGHTBEAM_URL: refused,
          TIGHTBEAM_TOKEN: @token
        )

      assert result.status == 1
      assert result.json["result"] == "unavailable"
      assert result.json["endpoint"] == nil
      assert result.json["endpointSource"] == "env"
      refute_receive {:credential_health_request, _, _}
    end

    satellite_base = Path.join(ctx.root, "satellite-advertisement")
    File.mkdir_p!(satellite_base)

    File.write!(
      Path.join(satellite_base, "gateway.json"),
      JSON.encode!(%{url: "http://10.0.0.1:#{server.port}", cliToken: @token})
    )

    result = invoke(ctx, [], TIGHTBEAM_BASE_DIR: satellite_base)
    assert result.status == 1
    assert result.json["result"] == "unavailable"
    assert result.json["endpoint"] == nil
    assert result.json["endpointSource"] == "env"
    refute_receive {:credential_health_request, _, _}
  end

  test "actual loopback contact covers IPv6 and the bounded macOS 127.0.0.2 limitation", ctx do
    assert_loopback_contact(ctx, {0, 0, 0, 0, 0, 0, 0, 1}, "http://[::1]")
    assert_secondary_ipv4_contact_or_exact_macos_limitation(ctx)
  end

  defp valid_body(result) do
    JSON.encode!(%{
      schemaVersion: 1,
      result: result,
      instance: %{id: @instance, host: "testhost"},
      version: Tightbeam.CliCompatibility.required_version()
    })
  end

  defp stub(ctx, opts) do
    {:ok, loopback} = try_start_stub(ctx, opts)
    loopback
  end

  defp assert_loopback_contact(ctx, ip, url) do
    loopback = stub(ctx, body: valid_body("ok"), ip: ip)

    result =
      invoke(%{ctx | cwd: ctx.root}, [],
        TIGHTBEAM_URL: "#{url}:#{loopback.port}",
        TIGHTBEAM_TOKEN: @token
      )

    assert result.status == 0
    assert_receive {:credential_health_request, "/agent/credential-health", _authorization}
  end

  # The product accepts all of 127/8. This fixture attempts the real bind before
  # consulting the platform and records only an actual EADDRNOTAVAIL as the
  # bounded macOS contact limitation. Linux and every other bind outcome must
  # exercise the contact or fail.
  defp assert_secondary_ipv4_contact_or_exact_macos_limitation(ctx) do
    opts = [body: valid_body("ok"), ip: {127, 0, 0, 2}]

    case try_start_stub(ctx, opts) do
      {:ok, loopback} ->
        result =
          invoke(%{ctx | cwd: ctx.root}, [],
            TIGHTBEAM_URL: "http://127.0.0.2:#{loopback.port}",
            TIGHTBEAM_TOKEN: @token
          )

        assert result.status == 0
        assert_receive {:credential_health_request, "/agent/credential-health", _authorization}

        IO.puts(
          :stderr,
          "credential-health contact evidence: os=#{platform_name()} address=127.0.0.2 " <>
            "error=none skipped=0"
        )

      {:error, reason} ->
        if :os.type() == {:unix, :darwin} and contains_reason?(reason, :eaddrnotavail) do
          IO.puts(
            :stderr,
            "credential-health contact limitation: os=macos address=127.0.0.2 " <>
              "error=EADDRNOTAVAIL skipped=1; parser acceptance remains exercised separately"
          )

          assert :os.type() == {:unix, :darwin}
          assert contains_reason?(reason, :eaddrnotavail)
        else
          flunk("127.0.0.2 listener bind failed: #{inspect(reason)}")
        end
    end
  end

  # The test supervisor owns every listener and stops it after the test. Nothing links
  # it to the test process, so a failed bind comes back here as `{:error, reason}`
  # instead of an EXIT that kills the test, and no manual stop races its shutdown.
  defp try_start_stub(ctx, opts) do
    {ip, opts} = Keyword.pop(opts, :ip, {127, 0, 0, 1})
    opts = Keyword.put(opts, :parent, self())

    case start_supervised(
           {Bandit, plug: {Stub, opts}, ip: ip, port: 0, startup_log: false},
           id: make_ref()
         ) do
      {:ok, pid} ->
        {:ok, {_bound_ip, port}} = ThousandIsland.listener_info(pid)
        {:ok, %{pid: pid, port: port, root: ctx.root}}

      {:error, reason} ->
        {:error, reason}
    end
  end

  defp contains_reason?(reason, expected) when reason == expected, do: true

  defp contains_reason?(reason, expected) when is_tuple(reason) do
    reason
    |> Tuple.to_list()
    |> Enum.any?(&contains_reason?(&1, expected))
  end

  defp contains_reason?(reason, expected) when is_list(reason),
    do: Enum.any?(reason, &contains_reason?(&1, expected))

  defp contains_reason?(reason, expected) when is_map(reason),
    do:
      Enum.any?(reason, fn {key, value} ->
        contains_reason?(key, expected) or contains_reason?(value, expected)
      end)

  defp contains_reason?(_reason, _expected), do: false

  defp platform_name do
    case :os.type() do
      {:unix, :darwin} -> "macos"
      {:unix, name} -> Atom.to_string(name)
      {family, name} -> "#{family}-#{name}"
    end
  end

  defp real_gateway(ctx, base_dir) do
    File.mkdir_p!(base_dir)

    registry =
      String.to_atom("credential_health_real_registry_#{System.unique_integer([:positive])}")

    start_supervised!({ConnRegistry, name: registry}, id: registry)

    router =
      Router.init(
        db: ctx.db,
        base_dir: base_dir,
        cli_token: @token,
        conn_registry: registry,
        handlers: %{},
        credential_health_instance: Tightbeam.CredentialHealth.instance(base_dir),
        diagnostics_emit: fn _record -> :accepted end
      )

    pid =
      start_supervised!(
        {Bandit, plug: {Router, router}, ip: {127, 0, 0, 1}, port: 0, startup_log: false},
        id: make_ref()
      )

    {:ok, {_bound_ip, port}} = ThousandIsland.listener_info(pid)
    %{pid: pid, port: port, base_dir: base_dir}
  end

  defp invoke(ctx, args, overrides \\ []) do
    env = [
      {"HOME", ctx.home},
      {"TIGHTBEAM_URL", nil},
      {"TIGHTBEAM_TOKEN", nil},
      {"TIGHTBEAM_BASE_DIR", nil},
      {"TIGHTBEAM_HOME", nil},
      {"CANARY_UNRELATED_ENV", "CANARY_ENV_VALUE_R4M2"}
    ]

    env =
      Enum.reduce(overrides, env, fn {name, value}, env ->
        key = Atom.to_string(name)
        List.keystore(env, key, 0, {key, value})
      end)

    capture =
      Path.join(ctx.root, "credential-health-capture-#{System.unique_integer([:positive])}")

    stdout_path = capture <> ".stdout"
    stderr_path = capture <> ".stderr"

    {_shell_output, status} =
      System.cmd(
        "/bin/sh",
        [
          "-c",
          ~S(stdout=$1; stderr=$2; shift 2; exec "$@" >"$stdout" 2>"$stderr"),
          "credential-health-capture",
          stdout_path,
          stderr_path,
          @cli,
          "credential-health"
          | args
        ],
        cd: ctx.cwd,
        env: env
      )

    output = File.read!(stdout_path)
    stderr = File.read!(stderr_path)
    File.rm!(stdout_path)
    File.rm!(stderr_path)
    refute output <> stderr =~ "CANARY_ENV_VALUE_R4M2"
    trimmed = String.trim_trailing(output)

    %{
      status: status,
      output: output <> stderr,
      stdout: output,
      stderr: stderr,
      json: JSON.decode!(trimmed)
    }
  end

  defp assert_unavailable(result, port) do
    assert result.status == 1

    assert result.json == %{
             "result" => "unavailable",
             "endpoint" => %{"host" => "127.0.0.1", "port" => port},
             "endpointSource" => "env",
             "instance" => nil,
             "version" => nil
           }

    assert_redacted(result.output, @token)
  end

  defp assert_redacted(output, token) do
    refute output =~ token
    refute output =~ Base.encode16(:crypto.hash(:sha256, token), case: :lower)
    refute output =~ ~s("tokenLength":#{String.length(token)})
    refute output =~ ~s("credentialLength":#{String.length(token)})

    token
    |> String.graphemes()
    |> Enum.chunk_every(4, 1, :discard)
    |> Enum.each(fn chars -> refute output =~ Enum.join(chars) end)
  end

  defp files(root) do
    root
    |> Path.join("**/*")
    |> Path.wildcard(match_dot: true)
    |> Enum.filter(&File.regular?/1)
    |> Enum.map(&{Path.relative_to(&1, root), File.read!(&1)})
    |> Enum.sort()
  end

  defp unused_loopback_port do
    {:ok, socket} = :gen_tcp.listen(0, [:binary, active: false, ip: {127, 0, 0, 1}])
    {:ok, port} = :inet.port(socket)
    :ok = :gen_tcp.close(socket)
    port
  end

  defp session(db, key) do
    Org.create(db, %{
      session_key: key,
      display_name: key,
      owner_user_id: "cli-health-owner",
      origin: "user:cli-health-owner",
      archetype: "default",
      host: "testhost",
      harness: "claude",
      provider: "anthropic",
      model: Model.new("fable")
    })
  end
end

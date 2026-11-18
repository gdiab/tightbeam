defmodule Tightbeam.LimitFallbackRingDownTest do
  # Contract c R8a: while a session is fallback-active, the 0.1.14 refusal
  # ring-down does not advance its selection; a refusal on the fallback is an
  # ordinary failed turn. The unconfigured ring-down stays covered, unchanged,
  # by model_selection_ring_down_test.exs.
  use Tightbeam.TestCase, async: false

  alias Tightbeam.{
    Archetypes,
    ConnRegistry,
    DB,
    Devices,
    Gateway,
    Identity,
    Ledger,
    LimitFallback,
    Model,
    Org,
    Schema
  }

  alias Tightbeam.GatewayTurnFixture.CoordinatorStub

  @preferences [
    {"synthetic-first", "low"},
    {"synthetic-second", "high"}
  ]

  defmodule LaneDoorbell do
    use GenServer

    def start_link(parent),
      do: GenServer.start_link(__MODULE__, parent, name: Tightbeam.LaneManager)

    def init(parent), do: {:ok, parent}
    def handle_call(_message, _from, parent), do: {:reply, :ok, parent}
  end

  defmodule CatalogStub do
    use GenServer

    def start_link(entries), do: GenServer.start_link(__MODULE__, entries)
    def init(entries), do: {:ok, entries}

    def handle_call({:get, {host, harness}}, _from, entries),
      do: {:reply, {Map.get(entries, {host, harness}, []), :fresh}, entries}

    def handle_call(:get, _from, entries), do: {:reply, entries, entries}
  end

  defmodule RefusingAdapter do
    use GenServer

    def start_link(opts), do: GenServer.start_link(__MODULE__, Map.new(opts))
    def init(state), do: {:ok, state}

    def handle_call({:knows_session?, _sid}, _from, state), do: {:reply, false, state}

    def handle_call({:new_session, model, _cwd, _mcp, _guidance}, _from, state) do
      send(state.parent, {:model_attempt, model})
      {:reply, Map.fetch!(state.outcomes, model.family), state}
    end

    def handle_call({:new_session, model, cwd, mcp, guidance, _timeout}, from, state),
      do: handle_call({:new_session, model, cwd, mcp, guidance}, from, state)

    def handle_call({:current_model, sid}, _from, state),
      do: {:reply, {:ok, Map.fetch!(state.readback, sid)}, state}

    def handle_call({:apply_model, _sid, _model}, _from, state), do: {:reply, :ok, state}

    def handle_call({:apply_model, sid, model, _timeout}, from, state),
      do: handle_call({:apply_model, sid, model}, from, state)

    def handle_call({:prompt, _sid, _prompt, _opts}, _from, state) do
      {:reply,
       {:ok,
        %{
          text: "synthetic reply",
          messages: [%{message_id: "synthetic-reply", text: "synthetic reply"}],
          stop_reason: "end_turn"
        }}, state}
    end

    def handle_call({:close_session, _sid}, _from, state), do: {:reply, :ok, state}
    def handle_call(:conn, _from, state), do: {:reply, self(), state}
  end

  test "a fallback-active session's refusal fails the turn without ringing to another preference" do
    with_gateway(fn %{db: db, config: config, lane: lane} ->
      {first, second} = start_refusing_adapter!()
      session!(db, "fallback-held", first)

      {:ok, _} =
        DB.transaction(db, fn txn ->
          LimitFallback.set_fallback_active_in_txn(txn, "fallback-held", %{
            since: 1,
            from: %{harness: "fixture", model: second},
            trigger: {:turn, 1}
          })
        end)

      assert {:error, _reason} = run_turn!(db, config, lane, "fallback-held")

      assert_receive {:model_attempt, ^first}
      refute_received {:model_attempt, _}

      session = Org.get(db, "fallback-held")
      assert session.model == first
      assert LimitFallback.fallback_active?(session)
    end)
  end

  test "control: the same refusal without fallback-active rings to the next preference" do
    with_gateway(fn %{db: db, config: config, lane: lane} ->
      {first, second} = start_refusing_adapter!()
      session!(db, "ring-control", first)

      assert {:ok, _} = run_turn!(db, config, lane, "ring-control")

      assert_receive {:model_attempt, ^first}
      assert_receive {:model_attempt, ^second}
      assert Org.get(db, "ring-control").model == second
    end)
  end

  defp start_refusing_adapter! do
    first = Model.new("synthetic-first", effort: "low")
    second = Model.new("synthetic-second", effort: "high")

    {:ok, adapter} =
      RefusingAdapter.start_link(
        parent: self(),
        outcomes: %{
          first.family => {:error, :model_unavailable},
          second.family => {:ok, "synthetic-session"}
        },
        readback: %{"synthetic-session" => second}
      )

    {:ok, _coordinator} = CoordinatorStub.start_link({adapter, self()})
    {first, second}
  end

  defp session!(db, key, model) do
    Org.create(db, %{
      session_key: key,
      display_name: key,
      owner_user_id: "synthetic-owner",
      origin: "user:synthetic-owner",
      archetype: "synthetic-ring",
      host: "testhost",
      harness: "fixture",
      provider: "fixture_provider",
      model: model
    })
  end

  defp run_turn!(db, config, lane, key) do
    assert :appended =
             Gateway.deliver_prompt(key, "user:synthetic-owner", "go",
               db: db,
               lane_manager: lane,
               conn_registry: ConnRegistry,
               client_message_id: key <> "-client"
             )

    assert {:ok, turn} = Ledger.claim_next(db, key, "limit-fallback-ring-test")
    runner(config).(Map.put(turn, :session_key, key))
  end

  defp runner(config) do
    {Tightbeam.LaneManager, lane_opts} =
      config
      |> Gateway.children()
      |> Enum.find(&match?({Tightbeam.LaneManager, _}, &1))

    Keyword.fetch!(lane_opts, :runner)
  end

  defp with_gateway(fun) do
    scratch =
      Path.join(System.tmp_dir!(), "tightbeam-limit-ring-#{System.unique_integer([:positive])}")

    runtime = Tightbeam.GuardRuntimeFixture.prepare!(scratch, "limit_ring_unused.exs")
    base = runtime.base
    db_name = :"limit_ring_db_#{System.unique_integer([:positive])}"

    db =
      start_supervised!(
        {DB,
         path: Path.join(base, "state.db"),
         payload_root: runtime.payload,
         name: db_name,
         guard_inputs: []},
        id: db_name
      )

    :ok = DB.assert_base_admitted!(db, base)
    :initialized = Identity.init!(base)
    write_archetype!(base)
    publish_identity!(base)
    :ok = Schema.ensure_all(db)
    Archetypes.load!(base)
    Devices.add_user(db, "synthetic-owner", false)
    write_fixture_binaries!(base)

    {:ok, catalog} =
      CatalogStub.start_link(%{
        {"testhost", "fixture"} =>
          Enum.map(@preferences, fn {family, effort} ->
            %{family: family, context: nil, efforts: [effort], provider: :fixture_provider}
          end)
      })

    Application.put_env(:tightbeam, :base_dir, base)
    Application.put_env(:tightbeam, :autostart, false)
    Application.put_env(:tightbeam, :local_host_name, "testhost")

    _registry = start_supervised!({ConnRegistry, name: ConnRegistry}, id: :limit_ring_registry)
    lane = start_supervised!({LaneDoorbell, self()}, id: :limit_ring_lane)

    config = %{
      base_dir: base,
      cwd: base,
      db: db,
      port: 0,
      default_harness: :fixture,
      default_model: Model.new("synthetic-first", effort: "low"),
      max_live_sessions_per_user: 50,
      wake_tick_ms: 1_000,
      onboarding_lease_ms: 1_800_000,
      model_catalog: catalog,
      credential_status: fn _provider, _machine -> :onboarded end,
      patch_adapter: fn _harness, _path -> :ok end
    }

    fun.(%{base: base, db: db, config: config, lane: lane})
  end

  defp write_archetype!(base) do
    entries =
      Enum.map_join(@preferences, "\n", fn {family, effort} ->
        """
        [[model_preferences]]
        model = "#{family}"
        effort = "#{effort}"
        """
      end)

    File.write!(Path.join([base, "identity", "archetypes", "synthetic-ring.toml"]), """
    name = "synthetic-ring"
    where = ["testhost"]

    #{entries}
    """)
  end

  defp write_fixture_binaries!(base) do
    bin = Path.join(base, "bin")
    File.mkdir_p!(bin)

    for name <- ["claude", "codex", "cursor", "pi", "fixture"] do
      path = Path.join(bin, name)
      File.write!(path, "#!/bin/sh\necho fixture-only\n")
      File.chmod!(path, 0o755)
    end

    home = Tightbeam.Homes.home_path(base, "testhost", :fixture)
    File.mkdir_p!(home)
    File.write!(Path.join(home, "fixture.json"), "synthetic-credential")
    adapter_path = Path.join([base, "adapters", "node_modules", ".bin", "fixture-acp"])
    File.mkdir_p!(Path.dirname(adapter_path))
    File.write!(adapter_path, "#!/bin/sh\n")
    File.chmod!(adapter_path, 0o755)
  end

  defp publish_identity!(base) do
    identity = Path.join(base, "identity")
    git!(identity, ["add", "-A"])
    git!(identity, ["commit", "-m", "test: synthetic limit fallback ring"])
    candidate = git!(identity, ["rev-parse", "main"])
    expected_prior = git!(identity, ["rev-parse", "tightbeam/live"])

    {:ok, _revision} =
      Identity.publish_live!(base, %{
        expected_prior: expected_prior,
        candidate_revision: candidate,
        tree_fingerprint: String.duplicate("0", 64)
      })

    :ok
  end

  defp git!(dir, args) do
    env = [
      {"GIT_AUTHOR_NAME", "limit-fallback-test"},
      {"GIT_AUTHOR_EMAIL", "limit-fallback-test@tightbeam.invalid"},
      {"GIT_COMMITTER_NAME", "limit-fallback-test"},
      {"GIT_COMMITTER_EMAIL", "limit-fallback-test@tightbeam.invalid"}
    ]

    case System.cmd("git", args, cd: dir, env: env, stderr_to_stdout: true) do
      {output, 0} -> String.trim_trailing(output)
      {output, status} -> raise "git failed #{status}: #{output}"
    end
  end
end

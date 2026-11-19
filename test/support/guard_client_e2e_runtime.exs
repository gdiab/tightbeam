defmodule GuardClientWire do
  import ExUnit.Assertions
  alias Tightbeam.{Model, ConnRegistry, DB, Gateway, Org, Rules}
  alias Tightbeam.ClientE2E.{Journeys, SimClient}
  alias Tightbeam.Wire.Router

  def run(base, selected) do
    {:ok, supervisor} = Supervisor.start_link([], strategy: :one_for_one)
    Process.put(:wire_supervisor, supervisor)

    try do
      ctx = real_gateway(base)
      :ok = DB.assert_base_admitted!(ctx.db, base)
      marker = File.read!(Path.join(base, "build-owner.json"))
      run_case(selected, ctx)
      assert File.read!(Path.join(base, "build-owner.json")) == marker
      assert {:ok, [[0]]} = DB.query(ctx.db, "SELECT count(*) FROM turns")
    after
      if Process.alive?(supervisor), do: Supervisor.stop(supervisor)
    end
  end

  defp start_supervised!(spec) do
    {:ok, pid} = Supervisor.start_child(Process.get(:wire_supervisor), spec)
    pid
  end

  # Stage 1 (stage1-v8 P10): pairing is one-time-code only. George's admin device
  # exists by fixture; he issues a code by user command from it, the code reaches
  # him in one ephemeral frame (W7) and nowhere else, a new device pairs with
  # "<name> <code>", the code is spent, and the device's first sign-in delivers its
  # token before the J0 journey runs.
  @code_pattern ~r/TB-[0-9A-HJKMNP-TV-Z]{4}-[0-9A-HJKMNP-TV-Z]{4}-[0-9A-HJKMNP-TV-Z]{4}/

  defp run_case(0, ctx) do
    george =
      Tightbeam.TestDevices.paired!(ctx.db, "george", admin: true, device_id: "george-phone")

    # The socket admits coded pairings through the default-named admission server.
    start_supervised!({Tightbeam.PairingAdmission, name: Tightbeam.PairingAdmission})

    assert {:error, "pairing_code_required"} =
             SimClient.pair("127.0.0.1", ctx.port, device_id: "sim-j0", claimed_name: "Flynn")

    {code, admin} = approve_device(ctx, george)
    SimClient.disconnect(admin)

    {:ok, %{token: token}} =
      SimClient.pair("127.0.0.1", ctx.port, device_id: "sim-j0", claimed_name: "Flynn #{code}")

    assert {:error, "pairing_code_invalid"} =
             SimClient.pair("127.0.0.1", ctx.port,
               device_id: "sim-j0",
               claimed_name: "Flynn #{code}"
             )

    {:ok, client} = SimClient.connect("127.0.0.1", ctx.port, token, device_id: "sim-j0")

    {journey_ctx, rows} = Journeys.run(journey_ctx(ctx, client), "J0")
    SimClient.disconnect(journey_ctx.client)

    assert Enum.map(rows, & &1.status) == [:pass, :pass],
           "J0 rows: #{inspect(Enum.map(rows, &{&1.step, &1.status, &1.note}))}"

    assert journey_ctx.main_key =~ "main"

    assert {:ok, [[1, "Flynn"]]} =
             DB.query(
               ctx.db,
               "SELECT tokenDelivered, claimedName FROM devices WHERE deviceId = ?1",
               ["sim-j0"]
             )

    # The pairing and first sign-in recorded nothing that carries the code either.
    refute_code_persisted!(ctx.db, code)
  end

  defp run_case(1, ctx) do
    assert {:error, "auth_failed"} =
             SimClient.connect("127.0.0.1", ctx.port, "not-a-token", device_id: "sim-bad")
  end

  defp run_case(2, ctx) do
    # The device is paired by fixture; coded pairing is case 0's subject.
    %{token: token} = Tightbeam.TestDevices.paired!(ctx.db, "flynn", device_id: "sim-bad-id")

    {:ok, client} = SimClient.connect("127.0.0.1", ctx.port, token, device_id: "sim-bad-id")
    watermark = SimClient.mark(client)
    key = Org.personal_session_key(client.user_id)

    :ok =
      Tightbeam.ClientE2E.WS.send_text(
        client.ws,
        JSON.encode!(%{
          "type" => "message",
          "id" => "nope",
          "sessionKey" => key,
          "content" => "hi"
        })
      )

    assert {:ok, frame, client} =
             SimClient.await(client, watermark, &(&1["type"] == "error"), 5_000)

    assert frame["code"] == "invalid_message"
    SimClient.disconnect(client)
  end

  # George posts `/tightbeam approve-device` to his Main. W7.1: one batch on this
  # socket — ack, persisted echo, persisted outcome, then the one ephemeral frame
  # that carries the code. Returns the code and the still-connected admin client.
  defp approve_device(ctx, george) do
    {:ok, admin} =
      SimClient.connect("127.0.0.1", ctx.port, george.token, device_id: george.device_id)

    main = Org.personal_session_key("george")
    watermark = SimClient.mark(admin)
    {:ok, admin, command_id} = SimClient.post(admin, main, "/tightbeam approve-device")

    assert {:ok, _ephemeral, admin} =
             SimClient.await(admin, watermark, &(&1["ephemeral"] == true), 5_000)

    # Look a little longer so "exactly one ephemeral frame" is observed, not assumed.
    admin = SimClient.settle(admin, 250)
    frames = SimClient.frames_since(admin, watermark)

    ack_at =
      Enum.find_index(frames, &(&1["type"] == "ack" and &1["id"] == command_id)) ||
        flunk("no ack for #{command_id} in #{inspect(frames)}")

    assert [ack, echo, outcome, ephemeral] = Enum.slice(frames, ack_at, 4),
           "the W7.1 batch is incomplete: #{inspect(frames)}"

    assert ack["type"] == "ack"

    assert %{"type" => "message", "role" => "user", "sessionKey" => ^main} = echo
    assert echo["content"] == "/tightbeam approve-device"
    assert is_integer(echo["seq"])

    assert %{"type" => "message", "role" => "assistant", "sessionKey" => ^main} = outcome
    assert is_integer(outcome["seq"])

    assert outcome["content"] =~
             ~r/\ADone: approve-device\. pairing code pc_\S+ issued for george, expires \S/

    # W7.2: the shape Clawline iOS ddf31e2's ServerMessagePayload decodes and renders.
    for field <- ~w(type id role content timestamp streaming sessionKey) do
      assert Map.has_key?(ephemeral, field), "ephemeral frame lacks #{field}"
    end

    assert %{
             "type" => "message",
             "role" => "assistant",
             "sender" => "process:tightbeam",
             "sessionKey" => ^main,
             "streaming" => false,
             "attachments" => [],
             "ephemeral" => true,
             "replyToClientMessageId" => ^command_id
           } = ephemeral

    assert is_binary(ephemeral["content"])
    assert is_number(ephemeral["timestamp"])
    assert "e_" <> _ = ephemeral["id"]
    refute String.starts_with?(ephemeral["id"], "s_")
    refute Map.has_key?(ephemeral, "seq")

    assert [ephemeral] == Enum.filter(frames, &(&1["ephemeral"] == true)),
           "exactly one ephemeral frame: #{inspect(frames)}"

    [code] = Regex.run(@code_pattern, ephemeral["content"]) || flunk("no code in the frame")
    refute outcome["content"] =~ code

    # Only the ephemeral frame carries the code, on the wire and in the store.
    assert [ephemeral] == Enum.filter(frames, &(inspect(&1) =~ code))
    refute_code_persisted!(ctx.db, code)

    # The scan reads real rows: the persisted outcome, which names the code id.
    [code_id] = Regex.run(~r/pc_[^\s,.]+/, outcome["content"])

    assert {:ok, [[n]]} =
             DB.query(ctx.db, "SELECT count(*) FROM messages WHERE content LIKE ?1", [
               "%#{code_id}%"
             ])

    assert n >= 1

    {code, admin}
  end

  # S0.3: the code is in no row of the gateway DB — every table, every column,
  # messages, events and lifecycle_events among them.
  defp refute_code_persisted!(db, code) do
    {:ok, tables} =
      DB.query(db, "SELECT name FROM sqlite_master WHERE type = 'table' ORDER BY name")

    tables = List.flatten(tables)
    assert Enum.all?(~w(messages events lifecycle_events), &(&1 in tables))

    needles = Enum.uniq([code, String.upcase(code), String.downcase(code)])

    leaks =
      for table <- tables,
          row <- table_rows!(db, table),
          value <- row,
          is_binary(value),
          Enum.any?(needles, &String.contains?(value, &1)),
          do: {table, value}

    assert leaks == [], "pairing code persisted: #{inspect(leaks)}"
  end

  defp table_rows!(db, table) do
    {:ok, rows} = DB.query(db, ~s(SELECT * FROM "#{table}"))
    rows
  end

  defp journey_ctx(ctx, client) do
    %{
      base_dir: ctx.base_dir,
      host: "127.0.0.1",
      port: ctx.port,
      client: client,
      main_key: nil,
      gateway: nil,
      leg: %{harness: "claude", host: "testhost", model: "fable"},
      turn_wait_ms: 10_000,
      settle_ms: 250
    }
  end

  defp real_gateway(base_dir) do
    db = :"client_e2e_db_#{System.unique_integer([:positive])}"

    start_supervised!({DB, path: Path.join(base_dir, "state.db"), name: db, guard_inputs: []})

    :ok = Tightbeam.Schema.ensure_all(db)

    start_supervised!(%{
      id: :client_e2e_conn_registry,
      start: {ConnRegistry, :start_link, [[name: Tightbeam.ConnRegistry]]}
    })

    handlers = Gateway.handlers(%{db: db, base_dir: base_dir, port: 0})
    Rules.load!(Path.join(base_dir, "no-rules"), Map.keys(handlers))

    router_opts =
      Router.init(
        db: db,
        base_dir: base_dir,
        handlers: handlers,
        conn_registry: Tightbeam.ConnRegistry,
        cli_token: "tbc_client_e2e",
        session_status: fn _key -> nil end,
        defaults: %{
          archetype: "default",
          host: "testhost",
          harness: :claude,
          provider: fn -> :anthropic end,
          model: Model.new("fable")
        }
      )

    bandit =
      start_supervised!(
        {Bandit, plug: {Router, router_opts}, port: 0, ip: {127, 0, 0, 1}, startup_log: false}
      )

    {:ok, {_address, port}} = ThousandIsland.listener_info(bandit)

    %{db: db, base_dir: base_dir, port: port}
  end
end

[payload, base] = System.argv()
true = Path.expand(payload) == Path.expand(Application.app_dir(:tightbeam))
false = File.exists?(base)
Application.put_env(:tightbeam, :autostart, false)
Application.put_env(:tightbeam, :base_dir, base)
for app <- [:exqlite, :crypto, :bandit], do: {:ok, _} = Application.ensure_all_started(app)
selected = File.read!(Path.join(Path.dirname(base), "wire-case")) |> String.to_integer()
:ok = Tightbeam.SchedulerMisses.init()
GuardClientWire.run(base, selected)
IO.puts("guarded-client-wire-#{selected}: ok")

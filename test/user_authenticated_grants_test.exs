defmodule Tightbeam.UserAuthenticatedGrantsTest do
  @moduledoc """
  Core fix (A), spec core-v8: only George's paired device grants credentials or
  rules his decisions. Acceptance tests K1-K3, K5, K6, K9-K19 through the real
  router, socket and gateway handlers on an isolated in-memory database.

  K19: this suite seeds no statute or rules-engine rule; every refusal here is the
  gateway's own.
  """

  use Tightbeam.TestCase, async: false
  import Plug.Test
  import Plug.Conn

  alias Tightbeam.{
    ConnRegistry,
    DB,
    Devices,
    GrantAuth,
    Gateway,
    Model,
    Org,
    Roles,
    Schema,
    TestDevices
  }

  alias Tightbeam.Wire.{Router, Socket}

  @absent "/nonexistent/tightbeam-test/pairing-unfreeze"

  # Each protected act, its wire params, and the /tightbeam command its refusal names.
  @protected [
    # Stage 1 S2.1: approval issues a code for a user; S1.1 enrolment is protected too.
    {"approve-device", %{userId: "guest"}, "/tightbeam approve-device guest"},
    {"recovery-enroll", %{}, "/tightbeam recovery-enroll"},
    {"deny-device", %{deviceId: "iphone"}, "/tightbeam deny-device iphone"},
    {"revoke-device", %{deviceId: "iphone"}, "/tightbeam revoke-device iphone"},
    {"promote-user", %{userId: "guest", isAdmin: true}, "/tightbeam promote-user guest"},
    {"add-user", %{userId: "newbie"}, "/tightbeam add-user newbie"},
    {"remove-user", %{userId: "guest"}, "/tightbeam remove-user guest"},
    {"register-host", %{name: "tycho", ssh: "gd@tycho", baseDir: "/home/gd/.tightbeam"},
     "/tightbeam register-host tycho gd@tycho /home/gd/.tightbeam"}
  ]

  defmodule Sink do
    use GenServer
    def start_link(name), do: GenServer.start_link(__MODULE__, :ok, name: name)
    def init(:ok), do: {:ok, :ok}
    def handle_call(_message, _from, state), do: {:reply, :ok, state}
    def handle_cast(_message, state), do: {:noreply, state}
  end

  setup do
    db = :"grants_db_#{System.unique_integer([:positive])}"
    registry = :"grants_registry_#{System.unique_integer([:positive])}"
    scheduler = :"grants_scheduler_#{System.unique_integer([:positive])}"
    start_supervised!({DB, path: ":memory:", name: db})
    start_supervised!({ConnRegistry, name: registry})
    start_supervised!({Sink, scheduler})
    :ok = Schema.ensure_all(db)
    on_exit(fn -> Application.put_env(:tightbeam, :pairing_unfreeze_path, @absent) end)

    base_dir = Path.join(System.tmp_dir!(), "grants-#{System.unique_integer([:positive])}")
    File.mkdir_p!(base_dir)
    on_exit(fn -> File.rm_rf!(base_dir) end)

    george = TestDevices.paired!(db, "george", admin: true, device_id: "iphone")
    ipad = TestDevices.paired!(db, "george", device_id: "ipad")
    guest = TestDevices.paired!(db, "guest", device_id: "guest-phone")
    {:pending, _} = TestDevices.pair(db, %{device_id: "visitor", claimed_name: "Visitor"})

    main = session(db, Org.personal_session_key("george"), "george", "main")
    worker = session(db, "worker-1", "george", "custom")
    other = session(db, "worker-2", "george", "custom")
    Roles.create!(db, "coder:k1", "george", worker.session_key)

    parent = self()
    sh = fn command -> send(parent, {:sh, command}) && {"", 0} end

    handlers =
      %{db: db, base_dir: base_dir, wake_scheduler: scheduler, sh: sh}
      |> Gateway.handlers()
      |> Map.put("post", fn call ->
        send(parent, {:post, call})
        %{}
      end)

    opts = [
      db: db,
      base_dir: base_dir,
      handlers: handlers,
      cli_token: "tbc_test",
      session_status: fn _ -> nil end
    ]

    deps = %{
      db: db,
      conn_registry: registry,
      handlers: handlers,
      cli_token: "tbc_test",
      defaults: %{
        archetype: "default",
        host: "testhost",
        harness: :claude,
        provider: fn -> :anthropic end,
        model: Model.new("fable")
      },
      ping_interval_ms: 60_000,
      pong_timeout_ms: 60_000
    }

    %{
      db: db,
      opts: opts,
      deps: deps,
      george: george,
      ipad: ipad,
      guest: guest,
      main: main,
      worker: worker,
      other: other
    }
  end

  ## K1, K3, K5, K6: every non-device caller is refused, nothing changes

  test "K1/K3/K6: each protected act is refused to sessions and the organization credential",
       ctx do
    for {verb, params, command} <- @protected,
        {bearer, selector, class} <- [
          {ctx.worker.cli_token, %{}, "session"},
          {"tbc_test", %{asUser: "george"}, "org"},
          {"tbc_test", %{asProcess: "automation"}, "org"},
          {"tbc_test", %{as: "coder:k1"}, "org"}
        ] do
      before = business_rows(ctx.db)
      response = dispatch(ctx, bearer, Map.merge(%{verb: verb, params: params}, selector))

      assert response.status == 403, "#{verb} #{inspect(selector)}: #{response.resp_body}"

      assert %{"code" => "user_authentication_required", "message" => message} =
               JSON.decode!(response.resp_body)["error"]

      assert message =~ "#{verb} must come from"
      assert message =~ "`#{command}`"
      refute message =~ "tbc_" or message =~ "tbt_"
      assert business_rows(ctx.db) == before

      assert [%{auth_class: ^class, device_id: nil} | _] =
               events(ctx.db, verb, "denied") |> Enum.reverse()
    end

    # K3: no host row and nothing pushed anywhere.
    assert {:ok, []} = DB.query(ctx.db, "SELECT name FROM hosts")
    refute_received {:sh, _}
  end

  test "K5: a session cannot revoke or deny George's devices or demote him", ctx do
    before = business_rows(ctx.db)

    for {verb, params} <- [
          {"revoke-device", %{deviceId: "iphone"}},
          {"deny-device", %{deviceId: "ipad"}},
          {"promote-user", %{userId: "george", isAdmin: false}}
        ] do
      response = dispatch(ctx, ctx.main.cli_token, %{verb: verb, params: params})
      assert response.status == 403
      assert JSON.decode!(response.resp_body)["error"]["code"] == "user_authentication_required"
    end

    assert business_rows(ctx.db) == before
    assert Devices.by_token(ctx.db, ctx.george.token).device_id == "iphone"
    assert Devices.user(ctx.db, "george").is_admin
  end

  # Stage 1 map: K4 kept, re-stated without the frozen/lifted variants.
  test "K4: with every admin device revoked, nothing but a device approves", ctx do
    :ok = Devices.revoke(ctx.db, "iphone")
    :ok = Devices.revoke(ctx.db, "ipad")

    for _once <- [1] do
      before = business_rows(ctx.db)

      for {bearer, body} <- [
            {"tbc_test", %{verb: "approve-device", asProcess: "automation"}},
            {"tbc_test", %{verb: "approve-device", asUser: "george"}},
            {ctx.worker.cli_token, %{verb: "approve-device"}},
            {"tbc_test",
             %{verb: "promote-user", asUser: "george", params: %{userId: "guest", isAdmin: true}}}
          ] do
        body = Map.put_new(body, :params, %{deviceId: "visitor"})
        response = dispatch(ctx, bearer, body)
        assert response.status == 403

        assert JSON.decode!(response.resp_body)["error"]["code"] ==
                 "user_authentication_required"
      end

      assert business_rows(ctx.db) == before
    end
  end

  ## K2, K6, K10, K11: the admin-paired device performs every act, without a turn

  test "K2/K6/K11: George's device performs each act by user command, with no turn", ctx do
    socket = connect(ctx, ctx.george)

    # Stage 1 S2.1: approval issues a one-time code, shown only in the ephemeral frame.
    {socket, outcome, ephemeral} = command_with_ephemeral(socket, "/tightbeam approve-device")

    assert outcome =~
             ~r/Done: approve-device\. pairing code pc_[0-9a-f]{16} issued for george, expires /

    assert ephemeral["content"] =~ ~r/TB-[0-9A-Z]{4}-[0-9A-Z]{4}-[0-9A-Z]{4}/

    {socket, outcome} = command(socket, "/tightbeam promote-user guest")
    assert outcome =~ "Done: promote-user"
    assert Devices.user(ctx.db, "guest").is_admin

    {socket, outcome} = command(socket, "/tightbeam demote-user guest")
    assert outcome =~ "is not an admin"
    refute Devices.user(ctx.db, "guest").is_admin

    {socket, _} = command(socket, "/tightbeam add-user newbie")
    assert %{is_admin: false} = Devices.user(ctx.db, "newbie")

    {socket, _} = command(socket, "/tightbeam remove-user newbie")
    assert Devices.user(ctx.db, "newbie").removed_at

    {socket, outcome} = command(socket, "/tightbeam register-host testhost gd@testhost /srv/tb")
    assert outcome =~ "SSH destination gd@testhost, base directory /srv/tb"
    assert {:ok, [["testhost"]]} = DB.query(ctx.db, "SELECT name FROM hosts")

    {socket, _} = command(socket, "/tightbeam deny-device visitor")
    assert %{status: "denied"} = Devices.by_id(ctx.db, "visitor")

    {_socket, outcome} = command(socket, "/tightbeam revoke-device ipad")
    assert outcome =~ "Done: revoke-device"
    assert %{token: nil} = Devices.by_id(ctx.db, "ipad")

    # No command reached a model or queued a turn.
    refute_received {:post, _}

    for verb <-
          ~w(approve-device promote-user add-user remove-user register-host deny-device revoke-device) do
      assert Enum.any?(
               events(ctx.db, verb, "verb"),
               &match?(%{auth_class: "device", device_id: "iphone", principal: "user:george"}, &1)
             ),
             verb
    end

    # K6: the same user's organization-credential act is told apart from the device act.
    dispatch(ctx, "tbc_test", %{
      verb: "add-user",
      asUser: "george",
      params: %{userId: "orgmade"}
    })

    assert [%{auth_class: "org", principal: "user:george"}] = events(ctx.db, "add-user", "denied")
  end

  test "K2: a non-admin user's device is refused forbidden for every act", ctx do
    socket = connect(ctx, ctx.guest)
    before = business_rows(ctx.db)

    Enum.reduce(
      [
        "/tightbeam approve-device visitor",
        "/tightbeam deny-device iphone",
        "/tightbeam revoke-device iphone",
        "/tightbeam promote-user guest",
        "/tightbeam add-user newbie",
        "/tightbeam remove-user george",
        "/tightbeam register-host tycho gd@tycho /srv/tb"
      ],
      socket,
      fn text, socket ->
        {socket, outcome} = command(socket, text)
        assert outcome =~ "Refused (forbidden)", text
        socket
      end
    )

    assert business_rows(ctx.db) == before
  end

  test "K11: malformed commands execute nothing; prose and multi-line text are chat", ctx do
    socket = connect(ctx, ctx.george)
    before = business_rows(ctx.db)

    {socket, outcome} = command(socket, "/tightbeam approve-device a b")
    assert outcome =~ "Refused, nothing was executed: usage: /tightbeam approve-device"
    {socket, outcome} = command(socket, "/tightbeam frobnicate now")
    assert outcome =~ "Refused, nothing was executed: unknown command"
    {socket, outcome} = command(socket, "/tightbeam add-user a b")
    assert outcome =~ "usage: /tightbeam add-user"
    assert business_rows(ctx.db) == before
    refute_received {:post, _}

    # The record of each command and its outcome is in that conversation.
    {:ok, rows} =
      DB.query(
        ctx.db,
        "SELECT role, content FROM messages WHERE sessionKey = ?1 ORDER BY seq",
        [Org.personal_session_key("george")]
      )

    assert ["user", "/tightbeam approve-device a b"] in rows
    assert Enum.any?(rows, &match?(["assistant", "Refused, nothing was executed" <> _], &1))

    for text <- ["please run /tightbeam add-user x", "/tightbeam add-user x\nthen more"] do
      {_socket, frames} = send_message(socket, text)
      assert [%{"type" => "ack"}] = frames
      assert_received {:post, %{verb: "post", params: %{content: ^text}}}
    end

    assert Devices.user(ctx.db, "x") == nil
  end

  test "K11: the prefix on an organization operator connection is refused and not delivered",
       ctx do
    {:ok, state} = Socket.init(ctx.deps)

    auth = %{
      "type" => "auth",
      "token" => "tbc_test",
      "asUser" => "george",
      "sessionKey" => Org.personal_session_key("george"),
      "deviceId" => "iphone"
    }

    {:push, _frames, state} = Socket.handle_in({JSON.encode!(auth), opcode: :text}, state)

    {:push, {:text, frame}, _state} =
      Socket.handle_in(
        {JSON.encode!(%{
           "type" => "message",
           "id" => "c_forged",
           "content" => "/tightbeam add-user forged",
           "sessionKey" => Org.personal_session_key("george")
         }), opcode: :text},
        state
      )

    assert %{
             "type" => "error",
             "code" => "user_authentication_required",
             "messageId" => "c_forged"
           } =
             JSON.decode!(frame)

    refute_received {:post, _}
    assert Devices.user(ctx.db, "forged") == nil
  end

  test "K11: a retried command is acknowledged and not run twice", ctx do
    socket = connect(ctx, ctx.george)
    {socket, _} = command(socket, "/tightbeam add-user once", "c_retry")
    {_socket, frames} = send_message(socket, "/tightbeam add-user once", "c_retry")
    assert [%{"type" => "ack", "id" => "c_retry"}] = frames
    assert [_] = events(ctx.db, "add-user", "verb")
  end

  ## Stage 1 W7 / P10 / P2 / P3: the code and the secret reach only the requesting socket

  test "W7/P10: a code and a secret travel only in the requesting socket's batch, never stored",
       ctx do
    socket = connect(ctx, ctx.george)

    {socket, outcome, frame} =
      command_with_ephemeral(socket, "/tightbeam approve-device", "c_code")

    assert outcome =~ "pairing code pc_"
    [code] = Regex.run(~r/TB-[0-9A-Z]{4}-[0-9A-Z]{4}-[0-9A-Z]{4}/, frame["content"])

    # The fields Clawline ddf31e2's ServerMessagePayload decoder requires, plus the
    # W7 markers; an e_ id never becomes Clawline's replay cursor (only s_ ids do).
    assert %{
             "type" => "message",
             "id" => "e_" <> _,
             "role" => "assistant",
             "sender" => "process:tightbeam",
             "sessionKey" => session_key,
             "content" => _,
             "timestamp" => timestamp,
             "streaming" => false,
             "attachments" => [],
             "ephemeral" => true,
             "replyToClientMessageId" => "c_code"
           } = frame

    assert session_key == Org.personal_session_key("george")
    assert is_integer(timestamp)
    refute Map.has_key?(frame, "seq")

    {_socket, outcome, secret_frame} =
      command_with_ephemeral(socket, "/tightbeam recovery-enroll", "c_secret")

    assert outcome =~ "recovery secret enrolled for george at "

    [secret] =
      Regex.run(~r/TBR-[0-9A-Z]{5}-[0-9A-Z]{5}-[0-9A-Z]{5}-[0-9A-Z]{5}/, secret_frame["content"])

    # Nothing persisted or published carries either one.
    for table <- ~w(messages events lifecycle_events owner_alerts wakes) do
      {:ok, rows} = DB.query(ctx.db, "SELECT * FROM #{table}")
      text = inspect(rows, limit: :infinity, printable_limit: :infinity)
      refute text =~ code
      refute text =~ secret
    end

    refute_received {:push_message, _, _, %{"content" => _}}

    # A non-admin device's attempts send no ephemeral frame.
    guest = connect(ctx, ctx.guest)

    for text <- ["/tightbeam approve-device", "/tightbeam recovery-enroll"] do
      {_guest, refused} = command(guest, text)
      assert refused =~ "Refused (forbidden)"
    end
  end

  ## K9: revocation takes effect on open connections

  test "K9: revoke, deny and user removal stop an open device socket before any command",
       ctx do
    revoked_socket = connect(ctx, ctx.ipad)
    denied = TestDevices.paired!(ctx.db, "george", device_id: "watch")
    denied_socket = connect(ctx, denied)

    by_device = fn verb, id ->
      TestDevices.device_call(ctx.george, %{verb: verb, params: %{device_id: id}})
    end

    :ok = Devices.revoke_with_firehose(ctx.db, "ipad", by_device.("revoke-device", "ipad"))
    :ok = Devices.deny_with_firehose(ctx.db, "watch", by_device.("deny-device", "watch"))

    for socket <- [revoked_socket, denied_socket] do
      assert {:stop, :normal, 1000, {:text, frame}, _} =
               Socket.handle_in(
                 {message_frame("/tightbeam add-user ghost", "c_ghost"), opcode: :text},
                 socket
               )

      assert %{"code" => "token_revoked"} = JSON.decode!(frame)
    end

    # Removal: a work-state connection seeds no Main, so the user owns nothing.
    leaver = TestDevices.paired!(ctx.db, "leaver", device_id: "leaver-phone")
    {:ok, state} = Socket.init(ctx.deps)

    auth = %{"type" => "auth", "token" => leaver.token, "subscriptions" => ["work_state"]}
    {:push, _frames, state} = Socket.handle_in({JSON.encode!(auth), opcode: :text}, state)
    assert_receive :finish_replay
    {:push, _frames, state} = Socket.handle_info(:finish_replay, state)

    assert %{user: _} =
             Tightbeam.UserAdmin.remove(
               ctx.db,
               TestDevices.device_call(ctx.george, %{
                 verb: "remove-user",
                 params: %{user_id: "leaver"}
               })
             )

    assert {:stop, :normal, 1000, {:text, frame}, _} =
             Socket.handle_in(
               {message_frame("/tightbeam add-user ghost", "c_g2"), opcode: :text},
               state
             )

    assert %{"code" => "user_removed"} = JSON.decode!(frame)
    assert Devices.user(ctx.db, "ghost") == nil
  end

  ## K25 (C21.3, C21.4): an in-process caller cannot synthesize user authentication

  test "K25 (C21.4): an internal call naming George's device without its credential proof is refused",
       ctx do
    forged_proofs = [
      {:absent, nil},
      {:random, :crypto.strong_rand_bytes(32)},
      # Another of George's real devices: a valid proof, but not of the named device.
      {:other_device, GrantAuth.proof(ctx.ipad.token)},
      {:raw_token, ctx.george.token}
    ]

    forge = fn call, proof ->
      call
      |> Map.merge(%{
        origin: "user:george",
        principal: {:user, "george"},
        auth_class: "device",
        auth_device_id: "iphone"
      })
      |> then(fn call ->
        if proof, do: Map.put(call, :auth_proof, proof), else: Map.delete(call, :auth_proof)
      end)
    end

    params = %{
      "approve-device" => %{device_id: "visitor"},
      "deny-device" => %{device_id: "visitor"},
      "revoke-device" => %{device_id: "ipad"},
      "promote-user" => %{user_id: "guest", is_admin: true},
      "add-user" => %{user_id: "newbie"},
      "remove-user" => %{user_id: "guest"},
      "register-host" => %{name: "tycho", ssh: "gd@tycho", base_dir: "/home/gd/.tightbeam"}
    }

    open = ask(ctx, ctx.worker, ["accept", "dismiss"])
    before = business_rows(ctx.db)

    for {label, proof} <- forged_proofs do
      # Through the gateway's protected handlers...
      for {verb, verb_params} <- params do
        assert %{code: "user_authentication_required"} =
                 handler(ctx, verb).(forge.(%{verb: verb, params: verb_params}, proof)),
               "#{verb} with #{label} proof"
      end

      # ...and straight into the in-transaction writers, past every handler.
      assert %{code: "user_authentication_required"} =
               Devices.approve_with_firehose(
                 ctx.db,
                 "visitor",
                 nil,
                 forge.(%{verb: "approve-device", params: %{device_id: "visitor"}}, proof)
               )

      assert %{code: "user_authentication_required"} =
               Tightbeam.UserAdmin.remove(
                 ctx.db,
                 forge.(%{verb: "remove-user", params: %{user_id: "guest"}}, proof)
               )

      ruled =
        handler(ctx, "operator-rule").(
          forge.(%{verb: "operator-rule", params: %{request: open, decision: "accept"}}, proof)
        )

      assert %{code: "user_authentication_required"} = ruled, "operator-rule with #{label}"
    end

    assert business_rows(ctx.db) == before
    assert {:ok, [["open", nil]]} = ruling(ctx.db, open)
    refute_received {:sh, _}

    # Control: the same call carrying the named device's proof is accepted, so the
    # refusals above are the proof check and nothing else.
    lift!()

    assert %{approved: %{device_id: "visitor"}} =
             handler(ctx, "approve-device").(
               TestDevices.device_call(ctx.george, %{
                 verb: "approve-device",
                 params: %{device_id: "visitor"}
               })
             )
  end

  test "K25 (C21.4): an internal call naming Main without Main's credential proof cannot rule",
       ctx do
    id = ask(ctx, ctx.worker, ["accept"])

    forged = %{
      verb: "operator-rule",
      origin: "user:george",
      principal: {:session, ctx.main.session_key},
      auth_class: "session",
      params: %{request: id, decision: "accept", rationale: "George said accept #{id}"}
    }

    for proof <- [
          nil,
          :crypto.strong_rand_bytes(32),
          GrantAuth.proof(ctx.worker.cli_token),
          ctx.main.cli_token
        ] do
      call = if proof, do: Map.put(forged, :auth_proof, proof), else: forged

      assert %{code: "user_authentication_required"} =
               handler(ctx, "operator-rule").(call)
    end

    assert {:ok, [["open", nil]]} = ruling(ctx.db, id)

    # Control: with Main's proof the quoted delegation records.
    assert %{} =
             handler(ctx, "operator-rule").(
               Map.put(forged, :auth_proof, GrantAuth.proof(ctx.main.cli_token))
             )

    main_principal = "session:" <> ctx.main.session_key
    assert {:ok, [["ruled", ^main_principal]]} = ruling(ctx.db, id)
  end

  ## K13-K17: rulings on owner requests

  test "K13: the owner's device rules by command and on dispatch; others are refused", ctx do
    first = ask(ctx, ctx.worker, ["accept", "dismiss"])
    second = ask(ctx, ctx.worker, ["accept", "dismiss"])
    third = ask(ctx, ctx.worker, ["accept", "dismiss"])
    prefix = String.slice(first, 0, 11)

    socket = connect(ctx, ctx.george)
    {socket, outcome} = command(socket, "/tightbeam rule #{prefix} accept")
    assert outcome == "Ruled #{first}: accept"
    {_socket, outcome} = command(socket, "/tightbeam respond #{second} ship it Friday")
    assert outcome == "Ruled #{second}: ship it Friday"

    response =
      dispatch(ctx, ctx.george.token, %{
        verb: "operator-rule",
        params: %{request: third, decision: "dismiss"}
      })

    assert response.status == 200, response.resp_body

    for id <- [first, second, third] do
      assert {:ok, [["ruled", "user:george"]]} = ruling(ctx.db, id)

      assert %{route: "device", auth_class: "device", auth_device_id: "iphone"} =
               GrantAuth.ruling_route(ctx.db, id)
    end

    assert length(events(ctx.db, "operator-rule", "verb")) == 3
    assert Enum.all?(events(ctx.db, "operator-rule", "verb"), &(&1.auth_class == "device"))

    # Another user's device, by command and on dispatch.
    open = ask(ctx, ctx.worker, ["accept", "dismiss"])
    {_guest, outcome} = command(connect(ctx, ctx.guest), "/tightbeam rule #{open} accept")
    assert outcome =~ "Refused (user_authentication_required)"

    refused =
      dispatch(ctx, ctx.guest.token, %{
        verb: "operator-rule",
        params: %{request: open, decision: "accept"}
      })

    assert refused.status == 403
    assert {:ok, [["open", nil]]} = ruling(ctx.db, open)

    # A device token reaches no other verb on dispatch.
    assert dispatch(ctx, ctx.george.token, %{verb: "add-user", params: %{userId: "x"}}).status ==
             401
  end

  test "K14: the raiser cannot rule its own request, Main included", ctx do
    for raiser <- [ctx.main, ctx.worker] do
      id = ask(ctx, raiser, ["accept"])

      response =
        dispatch(ctx, raiser.cli_token, %{
          verb: "operator-rule",
          params: %{request: id, decision: "accept", rationale: "George said accept #{id}"}
        })

      assert response.status == 403

      assert %{"code" => "self_ruling_forbidden", "message" => message} =
               JSON.decode!(response.resp_body)["error"]

      assert message =~ "#{id} was raised by this session"
      assert {:ok, [["open", nil]]} = ruling(ctx.db, id)
    end
  end

  test "K15: Main records a quoted delegation only when the rationale names the request", ctx do
    named = ask(ctx, ctx.worker, ["accept", "dismiss"])
    prefixed = ask(ctx, ctx.worker, ["accept", "dismiss"])
    unnamed = ask(ctx, ctx.worker, ["accept", "dismiss"])

    rationale = "George in Chat: 'on #{named}, accept'"

    ok =
      dispatch(ctx, ctx.main.cli_token, %{
        verb: "operator-rule",
        params: %{request: named, decision: "accept", rationale: rationale}
      })

    assert ok.status == 200, ok.resp_body
    main_principal = "session:" <> ctx.main.session_key
    assert {:ok, [["ruled", ^main_principal]]} = ruling(ctx.db, named)

    assert {:ok, [[^rationale]]} =
             DB.query(ctx.db, "SELECT rationale FROM decision_requests WHERE id = ?1", [named])

    assert %{route: "delegated-unverified", auth_class: "session", auth_device_id: nil} =
             GrantAuth.ruling_route(ctx.db, named)

    short = String.slice(prefixed, 0, 11)

    assert dispatch(ctx, ctx.main.cli_token, %{
             verb: "operator-rule",
             params: %{
               request: prefixed,
               decision: "dismiss",
               rationale: "George: '#{short}, dismiss'"
             }
           }).status == 200

    for params <- [
          %{request: unnamed, decision: "accept", rationale: "George said accept"},
          %{request: unnamed, decision: "accept"}
        ] do
      refused = dispatch(ctx, ctx.main.cli_token, %{verb: "operator-rule", params: params})
      assert refused.status == 403

      assert JSON.decode!(refused.resp_body)["error"]["code"] ==
               "delegation_rationale_required"
    end

    assert {:ok, [["open", nil]]} = ruling(ctx.db, unnamed)
  end

  test "K16: every other ruler is refused and the request stays open", ctx do
    id = ask(ctx, ctx.worker, ["accept"])
    naming = "George said accept #{id}"

    for {bearer, extra} <- [
          {ctx.other.cli_token, %{}},
          {"tbc_test", %{asUser: "george"}},
          {"tbc_test", %{asProcess: "automation"}},
          {ctx.guest.token, %{}}
        ] do
      response =
        dispatch(
          ctx,
          bearer,
          Map.merge(
            %{
              verb: "operator-rule",
              params: %{request: id, decision: "accept", rationale: naming}
            },
            extra
          )
        )

      assert response.status == 403, inspect(extra)

      assert %{"code" => "user_authentication_required", "message" => message} =
               JSON.decode!(response.resp_body)["error"]

      assert message =~ "/tightbeam rule #{id}"
    end

    assert {:ok, [["open", nil]]} = ruling(ctx.db, id)
  end

  test "K17: operator-withdraw by the raiser is unchanged", ctx do
    id = ask(ctx, ctx.worker, ["accept"])

    withdrawn =
      dispatch(ctx, ctx.worker.cli_token, %{
        verb: "operator-withdraw",
        params: %{request: id, reason: "moot"}
      })

    assert withdrawn.status == 200, withdrawn.resp_body

    assert {:ok, [["withdrawn"]]} =
             DB.query(ctx.db, "SELECT status FROM decision_requests WHERE id = ?1", [id])
  end

  ## K18: migration and restart

  test "K18: the migration adds only the new fields; a restart keeps device commands working",
       ctx do
    db = ctx.db
    ruled = ask(ctx, ctx.worker, ["accept"])

    assert dispatch(ctx, ctx.george.token, %{
             verb: "operator-rule",
             params: %{request: ruled, decision: "accept"}
           }).status == 200

    {:ok, _} =
      DB.query(
        db,
        "INSERT INTO hosts (name, ssh, baseDir, cliBin, adapterBinDir) VALUES ('sat', 'gd@sat', '/srv', NULL, NULL)"
      )

    :ok = Devices.revoke(db, "ipad")

    # Return the database to its shape before core (A) and stage 1, as an installed
    # 0.1.14 has it (stage 1 map: K18 kept, re-stated with the S5 records).
    for sql <- [
          "DROP TABLE device_lifecycle_migration",
          "DROP TABLE recovery_secrets",
          "DROP INDEX pairing_codes_outstanding",
          "DROP TABLE pairing_codes",
          "DROP TABLE gateway_host_actions",
          "ALTER TABLE devices DROP COLUMN tokenDelivered",
          "ALTER TABLE devices DROP COLUMN deliveryDeadline",
          "ALTER TABLE devices DROP COLUMN tokenGeneration",
          "ALTER TABLE devices DROP COLUMN pairedCodeId",
          "DROP TABLE grant_auth_migration",
          "DROP TABLE decision_request_ruling_routes",
          "DROP TABLE pairing_freeze_observation",
          "ALTER TABLE events DROP COLUMN authClass",
          "ALTER TABLE events DROP COLUMN authDeviceId",
          "ALTER TABLE events DROP COLUMN pairingFreeze",
          "ALTER TABLE devices DROP COLUMN tokenCollected"
        ] do
      assert {:ok, _} = DB.query(db, sql)
    end

    before = history(db)
    :ok = GrantAuth.ensure_schema(db)
    :ok = Tightbeam.DeviceLifecycle.ensure_schema(db)
    :ok = GrantAuth.ensure_schema(db)
    :ok = Tightbeam.DeviceLifecycle.ensure_schema(db)
    after_rows = history(db)

    # Every existing token is delivered (S5); no code or secret exists yet.
    assert {:ok, [[0]]} = DB.query(db, "SELECT COUNT(*) FROM devices WHERE tokenDelivered = 0")
    assert {:ok, [[0]]} = DB.query(db, "SELECT COUNT(*) FROM pairing_codes")

    assert Map.delete(after_rows, :devices) == Map.delete(before, :devices)

    {:ok, devices} =
      DB.query(db, "SELECT deviceId, token IS NOT NULL, tokenCollected FROM devices ORDER BY 1")

    assert Enum.all?(devices, fn [_id, has_token, collected] -> has_token == collected end)

    {:ok, unchanged} =
      DB.query(
        db,
        "SELECT deviceId, userId, claimedName, status, token, platform, model, createdAt FROM devices ORDER BY 1"
      )

    assert unchanged == before.devices

    # A restart: a fresh socket on the same rows signs in with the stored token and
    # a user command works at once.
    {_socket, outcome, _ephemeral} =
      command_with_ephemeral(connect(ctx, ctx.george), "/tightbeam approve-device")

    assert outcome =~ "Done: approve-device"
  end

  ## helpers

  defp session(db, key, owner, kind) do
    Org.create(db, %{
      session_key: key,
      display_name: key,
      owner_user_id: owner,
      origin: "user:#{owner}",
      archetype: "default",
      host: "testhost",
      harness: "claude",
      provider: "anthropic",
      model: Model.new("fable"),
      is_built_in: kind == "main",
      kind: kind
    })
  end

  defp dispatch(ctx, bearer, body) do
    conn(:post, "/agent/dispatch", JSON.encode!(Map.put_new(body, :params, %{})))
    |> put_req_header("authorization", "Bearer #{bearer}")
    |> put_req_header("x-tightbeam-cli-version", Tightbeam.CliCompatibility.required_version())
    |> Router.call(Router.init(ctx.opts))
  end

  defp handler(ctx, verb), do: Map.fetch!(ctx.opts[:handlers], verb)

  defp ask(ctx, raiser, labels) do
    response =
      dispatch(ctx, raiser.cli_token, %{
        verb: "operator-ask",
        params: %{
          question: "q #{System.unique_integer([:positive])}?",
          options: Enum.map(labels, &%{label: &1})
        }
      })

    assert response.status == 200, response.resp_body
    JSON.decode!(response.resp_body)["result"]["id"]
  end

  defp ruling(db, id),
    do: DB.query(db, "SELECT status, ruledBy FROM decision_requests WHERE id = ?1", [id])

  defp business_rows(db) do
    for table <- ~w(users devices device_versions hosts) do
      {:ok, rows} = DB.query(db, "SELECT * FROM #{table} ORDER BY 1")
      {table, rows}
    end
  end

  defp history(db) do
    read = fn sql ->
      {:ok, rows} = DB.query(db, sql)
      rows
    end

    %{
      users: read.("SELECT * FROM users ORDER BY 1"),
      hosts: read.("SELECT * FROM hosts ORDER BY 1"),
      decisions: read.("SELECT * FROM decision_requests ORDER BY 1"),
      devices:
        read.(
          "SELECT deviceId, userId, claimedName, status, token, platform, model, createdAt FROM devices ORDER BY 1"
        )
    }
  end

  defp events(db, verb, kind) do
    {:ok, rows} =
      DB.query(
        db,
        "SELECT principal, authClass, authDeviceId, pairingFreeze FROM events WHERE verb = ?1 AND kind = ?2 ORDER BY id",
        [verb, kind]
      )

    Enum.map(rows, fn [principal, class, device_id, freeze] ->
      %{principal: principal, auth_class: class, device_id: device_id, freeze: freeze}
    end)
  end

  defp connect(ctx, device) do
    {:ok, state} = Socket.init(ctx.deps)

    auth = %{"type" => "auth", "token" => device.token, "deviceId" => device.device_id}
    {:push, _frames, state} = Socket.handle_in({JSON.encode!(auth), opcode: :text}, state)
    assert_receive :finish_replay
    {:push, _frames, state} = Socket.handle_info(:finish_replay, state)
    state
  end

  defp message_frame(text, id) do
    JSON.encode!(%{"type" => "message", "id" => id, "content" => text})
  end

  defp send_message(socket, text, id \\ nil) do
    id = id || "c_#{System.unique_integer([:positive])}"

    case Socket.handle_in({message_frame(text, id), opcode: :text}, socket) do
      {:push, frames, socket} when is_list(frames) ->
        {socket, Enum.map(frames, fn {:text, frame} -> JSON.decode!(frame) end)}

      {:push, {:text, frame}, socket} ->
        {socket, [JSON.decode!(frame)]}
    end
  end

  # Stage 1 W7: ack, echo, outcome, then the one ephemeral frame, in one batch.
  defp command_with_ephemeral(socket, text, id \\ nil) do
    {socket, frames} = send_message(socket, text, id)

    assert [%{"type" => "ack"}, %{"content" => ^text, "role" => "user"}, outcome, ephemeral] =
             frames,
           inspect(frames)

    assert outcome["role"] == "assistant"
    assert ephemeral["ephemeral"] == true
    {socket, outcome["content"], ephemeral}
  end

  # A user command's frames: the ack, the recorded command, and the recorded outcome.
  defp command(socket, text, id \\ nil) do
    {socket, frames} = send_message(socket, text, id)

    assert [%{"type" => "ack"}, %{"content" => ^text, "role" => "user"}, outcome] = frames,
           inspect(frames)

    assert outcome["role"] == "assistant"
    {socket, outcome["content"]}
  end
end

defmodule Tightbeam.CredentialHealthTest do
  use Tightbeam.TestCase, async: false

  import Plug.Conn
  import Plug.Test
  import ExUnit.CaptureLog

  alias Tightbeam.{
    ConditionFacts,
    ConnRegistry,
    DB,
    Devices,
    Dispatch,
    EventLog,
    Gateway,
    Mementos,
    Model,
    Org,
    RailScript,
    Rules
  }

  alias Tightbeam.Firehose.Hub
  alias Tightbeam.Firehose.Publisher
  alias Tightbeam.Wire.Router

  @org_token "ZQX8M4R7P2V9K6N3"
  @unknown_token "WJF5D8S2H7L4C9B6"

  setup do
    suffix = System.unique_integer([:positive])
    db = String.to_atom("credential_health_db_#{suffix}")
    registry = String.to_atom("credential_health_registry_#{suffix}")

    # The positive control's rail runs under containment, which refuses a write root
    # with a symlink component. macOS's temp dir sits beneath one (/var), so resolve it.
    {tmp, 0} = System.cmd("/bin/realpath", [System.tmp_dir!()])
    base_dir = Path.join(String.trim(tmp), "tightbeam-credential-health-#{suffix}")

    File.mkdir_p!(base_dir)
    start_supervised!({DB, path: ":memory:", name: db})
    start_supervised!({ConnRegistry, name: registry})
    start_supervised!({Hub, name: Hub})
    ensure_all_schemas(db)
    Devices.add_user(db, "health-owner", true)

    active = session(db, "health-active")
    retired = session(db, "health-retired")
    assert %{state: "retired"} = Org.retire(db, retired.session_key, "user:health-owner", 1_000)

    {:pending, allowlisted_pending} =
      Devices.pair(db, %{
        device_id: "health-allowlisted",
        claimed_name: "Health Owner",
        platform: nil,
        model: nil
      })

    allowlisted = Devices.approve(db, allowlisted_pending.device_id, "health-owner")

    {:pending, pending} =
      Devices.pair(db, %{
        device_id: "health-revoked",
        claimed_name: "Health Owner",
        platform: nil,
        model: nil
      })

    revoked = Devices.approve(db, pending.device_id, "health-owner")
    revoked_token = revoked.token
    assert :ok = Devices.revoke(db, revoked.device_id)

    on_exit(fn ->
      File.rm_rf!(base_dir)
      Rules.load!(Path.join(System.tmp_dir!(), "missing-credential-health-rules"), [])
    end)

    %{
      db: db,
      registry: registry,
      base_dir: base_dir,
      active: active,
      retired: retired,
      allowlisted: allowlisted,
      revoked_token: revoked_token
    }
  end

  test "server classifies only organization and retained session credentials", ctx do
    parent = self()

    diagnostics = fn record ->
      send(parent, {:health_diagnostic, record})
      :accepted
    end

    for {token, result} <- [
          {nil, "auth_failed"},
          {@org_token, "ok"},
          {ctx.active.cli_token, "ok"},
          {ctx.retired.cli_token, "revoked"},
          {@unknown_token, "auth_failed"},
          {ctx.allowlisted.token, "auth_failed"},
          {ctx.revoked_token, "auth_failed"}
        ],
        repetition <- 1..5 do
      log =
        capture_log(fn ->
          response = health(ctx, token, diagnostics_emit: diagnostics, cli_version: "0.0.0")
          assert response.status == 200
          assert get_resp_header(response, "cache-control") == ["no-store"]

          assert JSON.decode!(response.resp_body) == %{
                   "schemaVersion" => 1,
                   "result" => result,
                   "instance" => Tightbeam.CredentialHealth.instance(ctx.base_dir),
                   "version" => Tightbeam.CliCompatibility.required_version()
                 }
        end)

      diagnostics = collect_health_diagnostics()
      terminal = Enum.filter(diagnostics, &(&1.event == "http_response_terminal"))
      assert [%{result_class: ^result}] = terminal

      if token in [
           ctx.active.cli_token,
           ctx.retired.cli_token,
           @unknown_token,
           ctx.allowlisted.token,
           ctx.revoked_token
         ] do
        assert Enum.sort(Enum.map(diagnostics, & &1.event)) ==
                 ~w(db_caller_completed db_server_completed http_response_terminal)
      else
        assert Enum.map(diagnostics, & &1.event) == ["http_response_terminal"]
      end

      for canary <- Enum.reject([token, @org_token, @unknown_token], &is_nil/1) do
        refute_token_material(log <> inspect(diagnostics), canary)
      end

      assert repetition in 1..5
    end
  end

  test "the global sliding limit precedes credential and database work", ctx do
    {:ok, counter} = Agent.start_link(fn -> 0 end)

    lookup = fn _db, _token ->
      Agent.update(counter, &(&1 + 1))
      {:ok, nil}
    end

    for _ <- 1..60 do
      response = health(ctx, @unknown_token, credential_health_session_lookup: lookup)
      assert response.status == 200
      assert JSON.decode!(response.resp_body)["result"] == "auth_failed"
    end

    response = health(ctx, @unknown_token, credential_health_session_lookup: lookup)
    assert response.status == 429
    assert JSON.decode!(response.resp_body) == %{"schemaVersion" => 1}
    assert Agent.get(counter, & &1) == 60

    :sys.replace_state(ctx.registry, fn state ->
      windows =
        Map.new(state.rate_windows, fn {key, {timestamps, expires}} ->
          {key, {Enum.map(timestamps, &(&1 - 60_001)), expires - 60_001}}
        end)

      %{state | rate_windows: windows}
    end)

    response = health(ctx, @unknown_token, credential_health_session_lookup: lookup)
    assert response.status == 200
    assert Agent.get(counter, & &1) == 61
  end

  test "malformed authorization and every CLI version-header shape remain read-only", ctx do
    for authorization <- ["", "Bearer ", "Basic #{@unknown_token}", "Bearer x, Bearer y"],
        _repetition <- 1..5 do
      response = health(ctx, nil, authorization: authorization)
      assert response.status == 200
      assert JSON.decode!(response.resp_body)["result"] == "auth_failed"
    end

    before = database_snapshot(ctx.db)

    for token <- [@org_token, ctx.active.cli_token],
        cli_version <- [nil, "0.0.0", "999.999.999"],
        _repetition <- 1..5 do
      reset_rate_limit(ctx.registry)
      response = health(ctx, token, cli_version: cli_version)
      assert response.status == 200
      assert JSON.decode!(response.resp_body)["result"] == "ok"
    end

    assert database_snapshot(ctx.db) == before
  end

  test "missing limiter and failed session lookup are schema-only unavailable results", ctx do
    missing_registry = String.to_atom("missing_health_registry_#{System.unique_integer()}")
    response = health(%{ctx | registry: missing_registry}, @org_token)
    assert response.status == 503
    assert JSON.decode!(response.resp_body) == %{"schemaVersion" => 1}

    failed = fn _db, _token -> {:error, :synthetic_database_failure} end
    response = health(ctx, @unknown_token, credential_health_session_lookup: failed)
    assert response.status == 503
    assert JSON.decode!(response.resp_body) == %{"schemaVersion" => 1}

    for failed <- [
          fn _db, _token -> raise "synthetic database failure" end,
          fn _db, _token -> exit(:synthetic_database_failure) end
        ] do
      response = health(ctx, @unknown_token, credential_health_session_lookup: failed)
      assert response.status == 503
      assert JSON.decode!(response.resp_body) == %{"schemaVersion" => 1}
    end
  end

  test "diagnostic acceptance and dropping cover terminal and read timing attempts", ctx do
    parent = self()

    accepted = fn record ->
      send(parent, {:accepted_diagnostic, record})
      :accepted
    end

    dropped = fn record ->
      send(parent, {:dropped_diagnostic, record})
      :dropped
    end

    first = health(ctx, ctx.active.cli_token, diagnostics_emit: accepted)
    accepted_records = collect_tagged_diagnostics(:accepted_diagnostic)

    assert Enum.sort(Enum.map(accepted_records, & &1.event)) ==
             ~w(db_caller_completed db_server_completed http_response_terminal)

    assert Enum.find(accepted_records, &(&1.event == "http_response_terminal")).result_class ==
             "ok"

    second = health(ctx, ctx.active.cli_token, diagnostics_emit: dropped)
    dropped_records = collect_tagged_diagnostics(:dropped_diagnostic)
    assert Enum.map(dropped_records, & &1.event) == Enum.map(accepted_records, & &1.event)

    assert {first.status, first.resp_body} == {second.status, second.resp_body}

    for record <- accepted_records ++ dropped_records do
      refute_token_material(inspect(record), ctx.active.cli_token)
    end

    reset_rate_limit(ctx.registry)
    for _ <- 1..60, do: health(ctx, @org_token, diagnostics_emit: accepted)
    assert health(ctx, @org_token, diagnostics_emit: accepted).status == 429
    records = collect_tagged_diagnostics(:accepted_diagnostic)
    assert Enum.any?(records, &(&1.result_class == "rate_limited"))

    missing_registry = String.to_atom("missing_health_registry_#{System.unique_integer()}")

    assert health(%{ctx | registry: missing_registry}, @org_token, diagnostics_emit: accepted).status ==
             503

    records = collect_tagged_diagnostics(:accepted_diagnostic)
    assert Enum.any?(records, &(&1.result_class == "unavailable"))
  end

  test "health bypasses application rules, handlers, storage and firehose while dispatch proves them live",
       ctx do
    marker = Path.join(ctx.base_dir, "ordinary-dispatch.marker")
    rail_marker = Path.join(ctx.base_dir, "match-all-rail.marker")

    handlers =
      Gateway.handlers(%{db: ctx.db, base_dir: ctx.base_dir, wake_tick_ms: 1_000})
      |> Map.put("credential-health-positive", fn _call ->
        File.write!(marker, "ordinary-dispatch-ran")
        %{ok: true}
      end)

    install_match_all_rule_fixture(ctx.base_dir, rail_marker, Map.keys(handlers))
    assert length(Rules.load!(ctx.base_dir, Map.keys(handlers))) == map_size(handlers)

    # Setup committed sessions and devices, and their notices may still be queued at
    # the Hub. Drain them while no observer is registered, so only notices from the
    # measured phase can reach the subscription below.
    firehose_frontier!(ctx.db)

    # Register as a production change socket does. The Hub advances `sequence/2` only
    # for subscription frames, never for a `mode: :all` socket, so a match-all
    # subscription is what lets the sequence checks below observe any notice at all.
    :ok = Hub.register(Hub, self(), %{mode: :filtered, db: ctx.db, user_id: "health-owner"})
    :ok = Hub.subscribe(Hub, self(), "credential-health-all", %{})

    before_db = database_snapshot(ctx.db)
    before_rails = EventLog.lifecycle_events(ctx.db)
    before_firehose = Hub.sequence(Hub, self())

    {health_results, forbidden_calls, gateway_log} =
      capture_forbidden_calls(ctx, fn ->
        gateway_log =
          capture_log(fn ->
            results =
              for token <- [
                    nil,
                    @org_token,
                    ctx.active.cli_token,
                    ctx.retired.cli_token,
                    @unknown_token,
                    ctx.allowlisted.token,
                    ctx.revoked_token
                  ],
                  _repetition <- 1..5 do
                reset_rate_limit(ctx.registry)

                health(ctx, token,
                  handlers: handlers,
                  diagnostics_emit: fn _record -> :accepted end,
                  firehose_hub: Hub
                )
              end

            for authorization <- ["", "Bearer ", "Basic #{@unknown_token}", "Bearer x, Bearer y"],
                _repetition <- 1..5 do
              reset_rate_limit(ctx.registry)
              assert health(ctx, nil, authorization: authorization).status == 200
            end

            for token <- [@org_token, ctx.active.cli_token],
                cli_version <- [nil, "0.0.0", "999.999.999"],
                _repetition <- 1..5 do
              reset_rate_limit(ctx.registry)
              assert health(ctx, token, cli_version: cli_version).status == 200
            end

            reset_rate_limit(ctx.registry)
            for _ <- 1..60, do: assert(health(ctx, @org_token).status == 200)
            for _ <- 1..5, do: assert(health(ctx, @org_token).status == 429)

            missing_registry =
              String.to_atom("missing_effect_health_registry_#{System.unique_integer()}")

            for _ <- 1..5 do
              assert health(%{ctx | registry: missing_registry}, @org_token).status == 503
            end

            send(self(), {:health_effect_results, results})
          end)

        assert_receive {:health_effect_results, results}
        {results, gateway_log}
      end)

    assert Enum.all?(health_results, &(&1.status == 200))
    assert forbidden_calls == []

    for token <- [
          @org_token,
          ctx.active.cli_token,
          ctx.retired.cli_token,
          @unknown_token,
          ctx.allowlisted.token,
          ctx.revoked_token
        ] do
      refute_token_material(gateway_log, token)
    end

    assert database_snapshot(ctx.db) == before_db
    assert EventLog.lifecycle_events(ctx.db) == before_rails
    firehose_frontier!(ctx.db)
    assert Hub.sequence(Hub, self()) == before_firehose
    refute_received {:firehose_notice, _frame}
    refute File.exists?(marker)
    refute File.exists?(rail_marker)

    {dispatch_result, positive_calls, _log} =
      capture_forbidden_calls(ctx, fn ->
        result =
          Dispatch.dispatch(ctx.db, handlers, %{
            verb: "credential-health-positive",
            origin: "process:credential-health-positive-control",
            principal: {:process, "credential-health-positive-control"},
            session_key: nil,
            params: %{}
          })

        _declarations = Mementos.declarations()
        assert ConditionFacts.substrate_defined_kind?("work-blocked")

        assert {:ok, []} =
                 DB.transaction(ctx.db, fn txn -> Rules.row_commit_effects_in_txn(txn, []) end)

        result
      end)

    assert {:ok, %{ok: true}} = dispatch_result
    assert Dispatch in Enum.map(positive_calls, &elem(&1, 0))
    assert Rules in Enum.map(positive_calls, &elem(&1, 0))
    assert RailScript in Enum.map(positive_calls, &elem(&1, 0))
    assert Publisher in Enum.map(positive_calls, &elem(&1, 0))
    assert {Mementos, :declarations, 0} in positive_calls
    assert {ConditionFacts, :substrate_defined_kind?, 1} in positive_calls
    assert {Rules, :row_commit_effects_in_txn, 2} in positive_calls

    assert File.read!(marker) == "ordinary-dispatch-ran"
    assert File.read!(rail_marker) == "rail-check-ran\n"
    assert Enum.any?(EventLog.lifecycle_events(ctx.db), &(&1.kind == "rail_script"))
    firehose_frontier!(ctx.db)
    assert Hub.sequence(Hub, self()) > before_firehose
    assert_received {:firehose_notice, _frame}
  end

  # Committed handoffs reach the Hub as casts from the DB owner, and messages are
  # ordered only between one sender and one receiver. A transaction callback runs in
  # the DB owner, so a synchronous Hub call made there is ordered behind every earlier
  # handoff. Once it returns, the test's own Hub call is ordered behind any frame the
  # Hub has already sent this process, and behind anything this process cast to the
  # Hub itself. The subscription has no archetype filter, so the Hub makes no DB call
  # while the owner waits on it.
  defp firehose_frontier!(db) do
    assert {:ok, :ok} =
             DB.transaction(db, fn _txn ->
               _state = :sys.get_state(Hub)
               :ok
             end)
  end

  defp health(ctx, token, overrides \\ []) do
    options = [
      db: ctx.db,
      base_dir: ctx.base_dir,
      cli_token: @org_token,
      conn_registry: ctx.registry,
      handlers: [],
      credential_health_instance: Tightbeam.CredentialHealth.instance(ctx.base_dir),
      diagnostics_emit: fn _record -> :accepted end,
      session_status: fn _session_key -> nil end
    ]

    options =
      Keyword.merge(options, Keyword.drop(overrides, [:cli_version, :authorization]))

    conn =
      conn(:get, "/agent/credential-health")
      |> maybe_header(
        "authorization",
        Keyword.get(overrides, :authorization, token && "Bearer #{token}")
      )
      |> maybe_header("x-tightbeam-cli-version", overrides[:cli_version])

    Router.call(conn, Router.init(options))
  end

  defp maybe_header(conn, _name, nil), do: conn
  defp maybe_header(conn, name, value), do: put_req_header(conn, name, value)

  defp collect_health_diagnostics, do: collect_tagged_diagnostics(:health_diagnostic)

  defp collect_tagged_diagnostics(tag, records \\ []) do
    receive do
      {^tag, record} -> collect_tagged_diagnostics(tag, [record | records])
    after
      0 -> Enum.reverse(records)
    end
  end

  defp reset_rate_limit(registry) do
    :sys.replace_state(registry, fn state -> %{state | rate_windows: %{}} end)
  end

  defp capture_forbidden_calls(ctx, fun) do
    modules = [Dispatch, Rules, RailScript, Publisher, Mementos, ConditionFacts]
    pids = [self(), Process.whereis(ctx.db)] |> Enum.reject(&is_nil/1)
    tracer = spawn_link(fn -> trace_calls([]) end)

    # Cleanup is armed before the first trace effect. Whatever fails below, every
    # process flag, every pattern and the tracer are still removed, and the first
    # failure is the one the test reports.
    outcome =
      try do
        {:ok, trace_calls_during(ctx, fun, modules, pids, tracer)}
      catch
        kind, reason -> {:error, kind, reason, __STACKTRACE__}
      end

    cleanup_failures = stop_call_trace(pids, modules, tracer)

    case outcome do
      {:ok, captured} ->
        assert cleanup_failures == []
        captured

      {:error, kind, reason, stacktrace} ->
        if cleanup_failures != [] do
          IO.puts(:stderr, "trace cleanup also failed: #{inspect(cleanup_failures)}")
        end

        :erlang.raise(kind, reason, stacktrace)
    end
  end

  defp trace_calls_during(ctx, fun, modules, pids, tracer) do
    # A trace pattern breaks only on code that is already loaded, so a module first
    # loaded during `fun` would run untraced and an empty capture would prove nothing.
    # Load every module first and require each pattern to cover real functions.
    Enum.each(modules, fn module ->
      Code.ensure_loaded!(module)
      assert :erlang.trace_pattern({module, :_, :_}, true, [:local]) > 0
    end)

    # A separate tracer receives the calls, so the test process is traced like any
    # other process rather than tracing itself.
    Enum.each(pids, fn pid ->
      assert :erlang.trace(pid, true, [:call, {:tracer, tracer}]) == 1
    end)

    {result, log} =
      case fun.() do
        {result, log} when is_binary(log) -> {result, log}
        result -> {result, ""}
      end

    _db_barrier = :sys.get_state(ctx.db)
    await_trace_delivery!(pids)
    {result, traced_calls(tracer, modules), log}
  end

  # Every step is attempted even when an earlier one fails; each failure is returned,
  # not raised. Trace messages go only to the tracer, which is stopped last, so
  # nothing remains to drain from the test mailbox.
  defp stop_call_trace(pids, modules, tracer) do
    flag_steps =
      Enum.map(pids, fn pid ->
        {{:trace_off, pid}, fn -> :erlang.trace(pid, false, [:call]) end}
      end)

    pattern_steps =
      Enum.map(modules, fn module ->
        {{:pattern_off, module},
         fn -> :erlang.trace_pattern({module, :_, :_}, false, [:local]) end}
      end)

    tracer_steps = [
      {:tracer_unlink, fn -> Process.unlink(tracer) end},
      {:tracer_kill, fn -> Process.exit(tracer, :kill) end}
    ]

    Enum.flat_map(flag_steps ++ pattern_steps ++ tracer_steps, fn {step, cleanup} ->
      try do
        cleanup.()
        []
      catch
        kind, reason -> [{step, kind, reason}]
      end
    end)
  end

  defp trace_calls(calls) do
    receive do
      {:trace, _pid, :call, {module, function, arguments}} ->
        trace_calls([{module, function, length(arguments)} | calls])

      {:traced_calls, from, ref} ->
        send(from, {:traced_calls, ref, Enum.reverse(calls)})
        trace_calls(calls)
    end
  end

  # Called only after `await_trace_delivery!/1`: every call traced before then is
  # already in the tracer's mailbox, ahead of this request.
  defp traced_calls(tracer, modules) do
    ref = make_ref()
    send(tracer, {:traced_calls, self(), ref})
    assert_receive {:traced_calls, ^ref, calls}, 1_000
    Enum.filter(calls, fn {module, _function, _arity} -> module in modules end)
  end

  defp await_trace_delivery!(pids) do
    Enum.each(pids, fn pid ->
      ref = :erlang.trace_delivered(pid)

      assert_receive {:trace_delivered, ^pid, ^ref},
                     1_000,
                     "trace delivery acknowledgement timed out for #{inspect(pid)}"
    end)
  end

  defp refute_token_material(output, token) do
    refute output =~ token
    refute output =~ Base.encode16(:crypto.hash(:sha256, token), case: :lower)
    refute output =~ ~s("tokenLength":#{String.length(token)})
    refute output =~ ~s("credentialLength":#{String.length(token)})

    token
    |> String.graphemes()
    |> Enum.chunk_every(4, 1, :discard)
    |> Enum.each(fn chars -> refute output =~ Enum.join(chars) end)
  end

  defp session(db, key) do
    Org.create(db, %{
      session_key: key,
      display_name: key,
      owner_user_id: "health-owner",
      origin: "user:health-owner",
      archetype: "default",
      host: "testhost",
      harness: "claude",
      provider: "anthropic",
      model: Model.new("fable")
    })
  end

  defp database_snapshot(db) do
    {:ok, tables} =
      DB.query(
        db,
        "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name"
      )

    Map.new(tables, fn [table] ->
      {:ok, rows} = DB.query(db, ~s(SELECT * FROM "#{table}"))
      ordered = Enum.sort(rows)

      {table,
       %{
         row_count: length(ordered),
         ordered_digest:
           ordered
           |> :erlang.term_to_binary()
           |> then(&:crypto.hash(:sha256, &1))
           |> Base.encode16(case: :lower)
       }}
    end)
  end

  defp install_match_all_rule_fixture(base_dir, rail_marker, verbs) do
    rules = Path.join(base_dir, "identity/rules")
    scripts = Path.join(base_dir, "identity/rails/scripts")
    bin = Path.join(base_dir, "bin")
    File.mkdir_p!(rules)
    File.mkdir_p!(scripts)
    File.mkdir_p!(bin)

    File.write!(
      Path.join(scripts, "credential-health-match-all"),
      "#!/bin/sh\nprintf 'rail-check-ran\\n' >> '#{rail_marker}'\nprintf 'pass\\n'"
    )

    File.chmod!(Path.join(scripts, "credential-health-match-all"), 0o755)

    wrapper = Path.join(bin, "tightbeam")
    File.cp!(Path.expand("fixtures/rail_exec/tightbeam", __DIR__), wrapper)
    File.chmod!(wrapper, 0o755)

    rules_source =
      verbs
      |> Enum.sort()
      |> Enum.with_index(1)
      |> Enum.map_join("\n", fn {verb, index} ->
        """
        [[rule]]
        name = "credential-health-match-#{index}"
        verb = "#{verb}"
        text = "positive control: every registered dispatch verb executes its verb-edge rail"
        edges = #{if verb == "attest", do: ~s(["verb", "turn-end"]), else: ~s(["verb"])}
        [rule.check]
        script = "credential-health-match-all"
        returns = ["pass"]
        [rule.check.effects]
        pass = "allow"
        """
      end)

    File.write!(Path.join(rules, "credential-health-match-all.toml"), rules_source)
  end
end

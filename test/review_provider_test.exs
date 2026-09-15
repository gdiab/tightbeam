defmodule Tightbeam.ReviewProviderTest do
  use Tightbeam.TestCase, async: false

  alias Tightbeam.{DB, Dispatch, Gateway, Model, Org, ReviewProvider, Rules}

  setup do
    db = start_supervised!({DB, path: ":memory:", name: nil})
    :ok = Tightbeam.Schema.ensure_all(db)
    register_hosts(db, %{"testhost" => %{ssh: nil, base_dir: System.tmp_dir!(), cli_bin: nil}})

    {:ok, _} =
      DB.query(
        db,
        "INSERT INTO users (userId,isAdmin,createdAt) VALUES ('owner',1,1),('stranger',0,1)"
      )

    for {key, provider} <- [
          {"coder", "openai"},
          {"coordinator", "anthropic"},
          {"reviewer", "openai"},
          {"alternative", "anthropic"},
          {"unrelated", "anthropic"}
        ] do
      Org.create(db, %{
        session_key: key,
        display_name: key,
        owner_user_id: "owner",
        origin: "user:owner",
        archetype: "default",
        host: "testhost",
        harness: "claude",
        provider: provider,
        model: Model.new("fixture")
      })
    end

    handlers = Gateway.handlers(%{db: db, wake_tick_ms: 1_000})

    base = Path.join(System.tmp_dir!(), "provider-rail-#{System.unique_integer([:positive])}")
    File.mkdir_p!(Path.join(base, "identity/rules"))

    File.cp!(
      Path.expand("../docs/examples/review-provider.toml", __DIR__),
      Path.join(base, "identity/rules/provider.toml")
    )

    Rules.load!(base, Map.keys(handlers))
    on_exit(fn -> File.rm_rf!(base) end)
    ctx = %{db: db, handlers: handlers, base: base}
    producer = assign(ctx, "coder", %{effect_kind: "code"})

    evidence =
      attest(
        ctx,
        producer.id,
        {:session, "coder"},
        "progress",
        nil,
        "Alternative-provider startup failed; provider error recorded in the attached run report."
      )

    Map.merge(ctx, %{producer: producer, evidence: evidence.attest.id})
  end

  test "different provider passes and same provider is denied before a row is created", ctx do
    before = count(ctx)
    assert {:error, %{code: "rule_denied"}} = dispatch_review(ctx)
    assert count(ctx) == before

    assert %{holderKey: "alternative"} =
             assign(ctx, "alternative", %{reviews_assignment_id: ctx.producer.id})
  end

  test "coordinator authorization permits one scoped assignment and idempotent replay", ctx do
    approve(ctx)
    assert {:ok, first} = dispatch_review(ctx)
    assert {:ok, second} = dispatch_review(ctx)
    assert first.id == second.id
    assert count(ctx) == 2
  end

  test "concurrent retries create only one assignment", ctx do
    approve(ctx)
    tasks = for _ <- 1..4, do: Task.async(fn -> dispatch_review(ctx) end)
    results = Enum.map(tasks, &Task.await/1)
    assert Enum.all?(results, &match?({:ok, _}, &1))
    assert results |> Enum.map(fn {:ok, row} -> row.id end) |> Enum.uniq() |> length() == 1
    assert count(ctx) == 2
  end

  test "coder, proposed reviewer, and unrelated sessions cannot authorize", ctx do
    for actor <- ~w(coder reviewer unrelated) do
      # Being the opener does not let the coder or proposed reviewer approve
      # themselves. An unrelated session is not an accountable opener at all.
      opener = if actor == "unrelated", do: "coordinator", else: actor

      {:ok, _} =
        DB.query(ctx.db, "UPDATE assignments SET openedBySession=?1 WHERE id=?2", [
          opener,
          ctx.producer.id
        ])

      approve(ctx, {:session, actor})
      assert {:error, %{code: "rule_denied"}} = dispatch_review(ctx, {:session, actor})
    end

    assert {:error, _} = dispatch_review(ctx)
  end

  test "responsible human can authorize but unrelated human cannot", ctx do
    approve(ctx, {:user, "stranger"})
    assert {:error, _} = dispatch_review(ctx, {:user, "stranger"})
    approve(ctx, {:user, "owner"})
    assert {:ok, _} = dispatch_review(ctx, {:user, "owner"})
  end

  test "authorization cannot be spent by another principal or with another key", ctx do
    approve(ctx)
    assert {:error, _} = dispatch_review(ctx, {:user, "owner"})

    assert {:error, _} =
             dispatch_review(ctx, {:session, "coordinator"}, %{idempotency_key: "other-attempt"})

    assert {:error, _} = dispatch_review(ctx, {:session, "coordinator"}, %{idempotency_key: nil})
    assert {:ok, _} = dispatch_review(ctx)
  end

  test "authorization is bound to the exact coding assignment and reviewer", ctx do
    approve(ctx)
    other = assign(ctx, "coder", %{effect_kind: "code"})

    assert {:error, _} =
             dispatch_review(ctx, {:session, "coordinator"}, %{reviews_assignment_id: other.id})

    {:ok, _} =
      DB.query(ctx.db, "UPDATE sessions SET provider='openai' WHERE sessionKey='alternative'")

    assert {:error, _} = dispatch_review(ctx, {:session, "coordinator"}, %{}, "alternative")
  end

  test "latest scoped withdrawal wins; a new approval can restore authorization", ctx do
    approve(ctx)
    approve(ctx, {:session, "coordinator"}, %{}, "review-provider-fallback-withdrawn")
    assert {:error, _} = dispatch_review(ctx)
    approve(ctx)
    assert {:ok, _} = dispatch_review(ctx)
  end

  test "missing, blank, duplicate, unrelated, or future evidence cannot authorize", ctx do
    other = assign(ctx, "coder", %{effect_kind: "code"})
    unrelated = attest(ctx, other.id, {:session, "coder"}, "progress", nil, "Other work")

    for fields <- [
          %{"reason" => " "},
          %{"evidence_attest_ids" => []},
          %{"evidence_attest_ids" => ["missing"]},
          %{"evidence_attest_ids" => [ctx.evidence, ctx.evidence]},
          %{"evidence_attest_ids" => [unrelated.attest.id]}
        ] do
      approve(ctx, {:session, "coordinator"}, fields)
      assert {:error, _} = dispatch_review(ctx)
    end

    approval = approve(ctx)
    future = attest(ctx, ctx.producer.id, {:session, "coder"}, "progress", nil, "Later evidence")
    # A stored decision cannot acquire validity when its referenced evidence
    # arrives later. Mutate the fixture's pointer to stage that temporal case.
    note = JSON.encode!(body(ctx, %{"evidence_attest_ids" => [future.attest.id]}))

    {:ok, _} =
      DB.query(ctx.db, "UPDATE attests SET note=?1 WHERE id=?2", [note, approval.attest.id])

    assert {:error, _} = dispatch_review(ctx)
  end

  test "malformed note and wrong protocol version are not authorization", ctx do
    for note <- ["yes", "{}", "null", JSON.encode!(body(ctx, %{"version" => 2}))] do
      attest(
        ctx,
        ctx.producer.id,
        {:session, "coordinator"},
        "verdict",
        "review-provider-fallback-approved",
        note
      )

      assert {:error, _} = dispatch_review(ctx)
    end
  end

  test "fallback cannot authorize self review or unknown provider identity", ctx do
    approve(ctx, {:user, "owner"}, %{"reviewer_session" => "coder"})
    assert {:error, _} = dispatch_review(ctx, {:user, "owner"}, %{}, "coder")

    {:ok, _} =
      DB.query(ctx.db, "UPDATE assignments SET holderProvider=NULL WHERE id=?1", [ctx.producer.id])

    assert {:error, _} = dispatch_review(ctx, {:session, "coordinator"}, %{}, "alternative")
  end

  test "non-code reviews and ordinary assignments remain outside this policy", ctx do
    for effect <- ~w(policy release live_mutation evidence coordination) do
      producer = assign(ctx, "coder", %{effect_kind: effect})

      assert %{holderKey: "reviewer"} =
               assign(ctx, "reviewer", %{reviews_assignment_id: producer.id})
    end

    assert %{holderKey: "reviewer"} = assign(ctx, "reviewer", %{})
  end

  test "the same rule denies automatic remedy calls without coordinator authorization", ctx do
    call = review_call(ctx)

    call = %{
      call
      | principal:
          {:remedy, %{statute: "completion-requires-review", action: "assign", owner: "owner"}},
        origin: "remedy:assign:completion-requires-review"
    }

    assert {:error, %{code: "rule_denied"}} = Dispatch.dispatch(ctx.db, ctx.handlers, call)
    approve(ctx)
    assert {:error, %{code: "rule_denied"}} = Dispatch.dispatch(ctx.db, ctx.handlers, call)
    assert {:ok, _} = dispatch_review(ctx)
  end

  test "policy is opt-in and facts are absent outside linked code assignment", ctx do
    assert %{relation: nil, authorized: nil} = ReviewProvider.facts(ctx.db, %{verb: "attest"})
    Rules.load!(Path.join(ctx.base, "disabled"), Map.keys(ctx.handlers))
    assert {:ok, _} = dispatch_review(ctx)
  end

  defp assign(ctx, target, params) do
    call =
      call(
        "assign",
        {:session, "coordinator"},
        target,
        Map.merge(%{subject: "work", idempotency_key: nil}, params)
      )

    assert {:ok, row} = Dispatch.dispatch(ctx.db, ctx.handlers, call)
    row
  end

  defp approve(
         ctx,
         actor \\ {:session, "coordinator"},
         fields \\ %{},
         verdict \\ "review-provider-fallback-approved"
       ) do
    attest(ctx, ctx.producer.id, actor, "verdict", verdict, JSON.encode!(body(ctx, fields)))
  end

  defp body(ctx, fields) do
    Map.merge(
      %{
        "version" => 1,
        "reviewer_session" => "reviewer",
        "assignment_key" => "fallback-attempt",
        "reason" => "Qualified alternative-provider candidates could not run.",
        "evidence_attest_ids" => [ctx.evidence]
      },
      fields
    )
  end

  defp attest(ctx, id, actor, kind, verdict, note) do
    call =
      call("attest", actor, nil, %{
        assignment_id: id,
        kind: kind,
        verdict_kind: verdict,
        note: note
      })

    assert {:ok, result} = Dispatch.dispatch(ctx.db, ctx.handlers, call)
    result
  end

  defp dispatch_review(
         ctx,
         actor \\ {:session, "coordinator"},
         params \\ %{},
         target \\ "reviewer"
       ) do
    call = review_call(ctx)
    call = call("assign", actor, target, Map.merge(call.params, params))
    Dispatch.dispatch(ctx.db, ctx.handlers, call)
  end

  defp review_call(ctx),
    do:
      call("assign", {:session, "coordinator"}, "reviewer", %{
        subject: "review",
        reviews_assignment_id: ctx.producer.id,
        idempotency_key: "fallback-attempt"
      })

  defp call(verb, {kind, key} = actor, target, params) do
    origin = if kind == :session, do: "agent:#{key}", else: "user:#{key}"

    %{
      verb: verb,
      principal: actor,
      origin: origin,
      session_key: target,
      params: params,
      target_role: nil,
      role_fallback: false
    }
  end

  defp count(ctx) do
    {:ok, [[count]]} = DB.query(ctx.db, "SELECT count(*) FROM assignments")
    count
  end
end

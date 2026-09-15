defmodule Tightbeam.ReviewProvider do
  @moduledoc """
  Evidence for an opt-in code-review provider rail. Provider choice remains org
  policy; these facts only compare recorded identities and recognize a scoped,
  attributable fallback decision. They never infer provider availability.
  """

  alias Tightbeam.DB

  @approved "review-provider-fallback-approved"
  @withdrawn "review-provider-fallback-withdrawn"

  @doc "Snapshot the proposed linked code review and its fallback authorization."
  def facts(db, %{verb: "assign", params: params, session_key: reviewer} = call) do
    subject = params[:reviews_assignment_id] || params["reviews_assignment_id"]

    if is_binary(subject) and is_binary(reviewer) do
      DB.transaction(db, fn txn -> snapshot(txn, subject, reviewer, call) end)
      |> case do
        {:ok, facts} -> facts
        {:error, error} -> raise error
      end
    else
      %{relation: nil, authorized: nil}
    end
  end

  def facts(_db, _call), do: %{relation: nil, authorized: nil}

  defp snapshot(txn, subject, reviewer, call) do
    rows =
      DB.Txn.q(
        txn,
        """
        SELECT a.holderKey, a.holderProvider, a.openedBySession, a.openedByUser,
               p.ownerUserId, a.state, r.provider, r.state
        FROM assignments a
        JOIN sessions p ON p.sessionKey=a.holderKey
        JOIN sessions r ON r.sessionKey=?2
        LEFT JOIN assignment_effects e ON e.assignmentId=a.id
        WHERE a.id=?1 AND a.reviewsAssignmentId IS NULL
          AND COALESCE(e.effectKind, 'code')='code'
        """,
        [subject, reviewer]
      )

    case rows do
      [[holder, provider, opener, opening_user, owner, state, other, reviewer_state]] ->
        relation =
          cond do
            holder == reviewer -> "self"
            not known?(provider) or not known?(other) -> "unknown"
            provider == other -> "same"
            true -> "different"
          end

        principal = Map.get(call, :principal)

        authorized =
          relation == "same" and state == "open" and reviewer_state == "active" and
            accountable?(principal, holder, reviewer, opener, opening_user, owner) and
            decision?(txn, subject, reviewer, call, principal)

        %{relation: relation, authorized: authorized}

      [] ->
        %{relation: nil, authorized: nil}
    end
  end

  defp known?(value), do: is_binary(value) and String.trim(value) != ""

  # The opening coordinator or the responsible human can authorize. Neither
  # producer nor proposed reviewer can authorize through their session identity.
  defp accountable?({:session, key}, holder, reviewer, opener, _opening_user, _owner),
    do: key == opener and key != holder and key != reviewer

  defp accountable?({:user, user}, _holder, _reviewer, _opener, opening_user, owner),
    do: user == opening_user or user == owner

  defp accountable?(_, _, _, _, _, _), do: false

  defp decision?(txn, subject, reviewer, call, principal) do
    key = call.params[:idempotency_key] || call.params["idempotency_key"]

    if known?(key) do
      {session, user} =
        case principal do
          {:session, session} -> {session, nil}
          {:user, user} -> {nil, user}
        end

      rows =
        DB.Txn.q(
          txn,
          """
          SELECT rowid, verdictKind, note FROM attests
          WHERE assignmentId=?1 AND kind='verdict'
            AND bySession IS ?2 AND byUser IS ?3
            AND verdictKind IN (?4, ?5)
          ORDER BY rowid DESC
          """,
          [subject, session, user, @approved, @withdrawn]
        )

      # Use the latest decision for this exact reviewer and assignment key.
      # The ordinary assignment idempotency ledger makes this a single attempt,
      # including concurrent retries. Other principals cannot spend this decision.
      Enum.find_value(rows, fn [rowid, kind, note] ->
        case decode(note) do
          %{"version" => 1, "reviewer_session" => ^reviewer, "assignment_key" => ^key} = body ->
            {:decision, kind == @approved and evidence?(txn, subject, rowid, body)}

          _ ->
            nil
        end
      end) == {:decision, true}
    else
      false
    end
  end

  defp evidence?(txn, subject, decision_rowid, body) do
    ids = body["evidence_attest_ids"]

    known?(body["reason"]) and is_list(ids) and ids != [] and
      Enum.all?(ids, &known?/1) and length(Enum.uniq(ids)) == length(ids) and
      Enum.all?(ids, fn id ->
        # Evidence must predate the decision and concern this coding assignment.
        # Its truth is the coordinator's judgment, not a string-matching detector.
        DB.Txn.q(
          txn,
          """
          SELECT 1 FROM attests
          WHERE id=?1 AND assignmentId=?2 AND rowid<?3
            AND kind IN ('progress','verdict')
            AND (verdictKind IS NULL OR verdictKind NOT IN (?4, ?5))
            AND note IS NOT NULL AND length(trim(note))>0
          """,
          [id, subject, decision_rowid, @approved, @withdrawn]
        ) == [[1]]
      end)
  end

  defp decode(note) when is_binary(note) do
    case JSON.decode(note) do
      {:ok, value} -> value
      {:error, _} -> nil
    end
  end

  defp decode(_), do: nil
end

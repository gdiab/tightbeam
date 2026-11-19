defmodule Tightbeam.QuotaRelease do
  @moduledoc """
  What every release of a quota park does, whichever trigger released it: the
  declared reset (quota v3 R9(a)), a later success (R9(b)) or an explicit
  resume (R9(c)). Each caller removes the fence and records its own cause
  first; this then runs in the same transaction.

  - Companion v1.1 B5: each quota-failed turn of the incident is classified by
    contract (c) R9a (`LimitFallback.Outcome.classify_in_txn/2`). A
    pre-activity (`:replayed`) turn keeps its existing replay vehicle: the
    rate-limit retry wake of a wake turn, or the health redelivery row of a
    message turn, each consumed at most once. A post-activity
    (`:unknown_effect`) turn is never replayed: the vehicles are not written for
    it (`Wakes`), a retry attempt still pending is settled, the disposition is
    recorded with cause `provider_quota`, and one item goes to the holder and
    the delivery owner (v3 R16). That happens where its vehicles are withheld
    (`surface_not_replayed_in_txn/2`), so it holds even when no incident ever
    opens; a release only catches a turn recorded before this existed.
  - Companion B5 (spec writer's ruling, asg_a4d1e7d6): a release by the
    declared reset or an explicit resume re-admits the key's pending
    pre-activity message turns itself, once each in seq order (`readmit: true`).
  - v3 R12: every active session on the key with a queued turn gets its lane
    ensured, so the queue drains in its original order.
  """

  alias Tightbeam.{EventLog, Harness, HarnessProcess, LimitFallback, Org, Wakes}
  alias Tightbeam.DB.Txn

  @process "process:tightbeam"

  @doc """
  The one recorded release step of a quota park (companion v1.6 §7 C1). Every
  cause goes through it: `declared_reset` (B1), `later_success` (v3 R9(b)),
  `explicit_resume` / `explicit_restart` (v3 R9(c)) and `recovery_probe`
  (PR3). It records the release with its cause, actor and time, which ends
  this quota cause of the hold. The fence is removed, and admission resumes,
  only when no other standing reason still needs it:

  - another open `rate-limit-dead` incident on the key;
  - a harness-process row on the key that is being parked or failed to die;
    for a probe release also a launching or running one, as upstream's
    recovery release required.

  Admission resuming is its own record, and only then are the key's pending
  pre-activity quota turns re-admitted (B5, under C2's gate), for this
  incident and any earlier release that a standing reason held. A held
  release records the remaining reasons instead and re-admits nothing.
  Returns `:admission_resumed` or `{:held, reasons}`.
  """
  @spec release_in_txn(Txn.t(), String.t(), String.t(), String.t(), keyword()) ::
          :admission_resumed | {:held, [String.t()]}
  def release_in_txn(%Txn{} = txn, incident_id, harness, host, opts) do
    cause = Keyword.fetch!(opts, :cause)
    at = System.system_time(:millisecond)
    key = {Harness.parse!(harness).id(), "shared", host}

    EventLog.lifecycle_in_txn(
      txn,
      "rate_limit_hold_released",
      incident_id,
      opts
      |> Keyword.get(:detail, %{})
      |> Map.merge(%{cause: cause, actor: Keyword.get(opts, :actor, @process), releasedAt: at})
      |> JSON.encode!()
    )

    case standing_reasons_in_txn(txn, incident_id, harness, host, cause) do
      [] ->
        # Recorded before the fence goes, so fence_cleared_in_txn/2 does not
        # count this release as one a standing reason still held.
        EventLog.lifecycle_in_txn(
          txn,
          "rate_limit_admission_resumed",
          incident_id,
          JSON.encode!(%{harness: harness, host: host, cause: cause, resumedAt: at})
        )

        HarnessProcess.complete_park_in_txn(txn, key)

        released_in_txn(txn, incident_id, harness, host,
          readmit: Keyword.get(opts, :readmit, false)
        )

        readmit_held_releases_in_txn(txn, incident_id, harness, host)
        :admission_resumed

      reasons ->
        EventLog.lifecycle_in_txn(
          txn,
          "rate_limit_hold_remains",
          incident_id,
          JSON.encode!(%{harness: harness, host: host, cause: cause, reasons: reasons, at: at})
        )

        released_in_txn(txn, incident_id, harness, host)
        {:held, reasons}
    end
  end

  @readmitting_causes ["declared_reset", "explicit_resume", "explicit_restart", "recovery_probe"]

  @doc """
  A park fence was removed (`HarnessProcess`'s park completion or orphan-fence
  sweep). On 0.1.16 a held release's only standing reason is a harness process
  (one rate-limit incident can be open per key), and that process's own
  settlement removes the fence. For each quota release on the key that a
  standing reason held and that has not yet seen admission resume, this
  records `rate_limit_admission_resumed` (cause `standing_reason_cleared`) and
  re-admits its pending pre-activity turns once (companion v1.6 C1).
  """
  @spec fence_cleared_in_txn(Txn.t(), String.t()) :: :ok
  def fence_cleared_in_txn(%Txn{} = txn, adapter_key) when is_binary(adapter_key) do
    case {String.split(adapter_key, ":shared@", parts: 2), quota_schema?(txn)} do
      {[harness, host], true} ->
        at = System.system_time(:millisecond)

        Txn.q(
          txn,
          """
          SELECT i.id,
                 (SELECT json_extract(r.detail, '$.cause') FROM lifecycle_events r
                  WHERE r.kind='rate_limit_hold_released' AND r.subject=i.id
                  ORDER BY r.id DESC LIMIT 1)
          FROM harness_health_incidents i
          WHERE i.harness=?1 AND i.host=?2 AND i.failureClass='rate-limit-dead'
            AND EXISTS (
              SELECT 1 FROM lifecycle_events h
              WHERE h.kind='rate_limit_hold_remains' AND h.subject=i.id
                AND NOT EXISTS (
                  SELECT 1 FROM lifecycle_events a
                  WHERE a.kind='rate_limit_admission_resumed' AND a.subject=i.id AND a.id > h.id
                )
            )
          ORDER BY i.id
          """,
          [harness, host]
        )
        |> Enum.each(fn [incident_id, cause] ->
          EventLog.lifecycle_in_txn(
            txn,
            "rate_limit_admission_resumed",
            incident_id,
            JSON.encode!(%{
              harness: harness,
              host: host,
              cause: "standing_reason_cleared",
              releaseCause: cause,
              resumedAt: at
            })
          )

          released_in_txn(txn, incident_id, harness, host, readmit: cause in @readmitting_causes)
        end)

      _ ->
        :ok
    end

    :ok
  end

  # A process-only database (some harness-process tests) has no health tables.
  defp quota_schema?(txn) do
    Txn.q(
      txn,
      "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name IN ('harness_health_incidents','lifecycle_events')"
    ) == [[2]]
  end

  defp standing_reasons_in_txn(txn, incident_id, harness, host, cause) do
    adapter_key = Atom.to_string(Harness.parse!(harness).id()) <> ":shared@" <> host

    process_states =
      if cause == "recovery_probe",
        do: ["launching", "running", "park_requested", "kill_failed"],
        else: ["park_requested", "kill_failed"]

    incidents =
      Txn.q(
        txn,
        """
        SELECT id FROM harness_health_incidents
        WHERE id != ?1 AND harness=?2 AND host=?3
          AND failureClass='rate-limit-dead' AND state='open'
        ORDER BY id
        """,
        [incident_id, harness, host]
      )
      |> Enum.map(fn [id] -> "open_incident:" <> id end)

    placeholders = Enum.map_join(1..length(process_states), ",", &"?#{&1 + 1}")

    processes =
      Txn.q(
        txn,
        """
        SELECT launchId FROM harness_processes
        WHERE adapterKey=?1 AND state IN (#{placeholders}) AND resolvedAt IS NULL
        ORDER BY launchId
        """,
        [adapter_key | process_states]
      )
      |> Enum.map(fn [id] -> "harness_process:#{id}" end)

    incidents ++ processes
  end

  # A release that a standing reason held re-admitted nothing; its turns are
  # re-admitted when admission does resume, once each (the selection skips
  # rows already redelivered).
  defp readmit_held_releases_in_txn(txn, incident_id, harness, host) do
    Txn.q(
      txn,
      """
      SELECT DISTINCT i.id FROM harness_health_incidents i
      JOIN lifecycle_events e ON e.kind='rate_limit_hold_released' AND e.subject=i.id
      WHERE i.harness=?1 AND i.host=?2 AND i.failureClass='rate-limit-dead' AND i.id != ?3
        AND json_extract(e.detail, '$.cause') IN (#{Enum.map_join(@readmitting_causes, ",", &"'#{&1}'")})
      ORDER BY i.id
      """,
      [harness, host, incident_id]
    )
    |> Enum.each(fn [held] -> Wakes.readmit_released_quota_intents_in_txn(txn, held) end)
  end

  @spec released_in_txn(Txn.t(), String.t(), String.t(), String.t(), keyword()) :: :ok
  def released_in_txn(%Txn{} = txn, incident_id, harness, host, opts \\ [])
      when is_binary(incident_id) and is_binary(harness) and is_binary(host) do
    txn
    |> quota_failed_turns_in_txn(incident_id)
    |> Enum.each(fn turn ->
      if LimitFallback.Outcome.classify_in_txn(txn, turn.seq) == :unknown_effect,
        do: not_replayed_in_txn(txn, incident_id, turn)
    end)

    # A release by the declared reset or an explicit resume is itself the
    # restoration of the key's pending pre-activity message turns: re-admitting
    # them must not wait for an unrelated turn to succeed (v3 V1). A release by
    # a later success already redelivers them from that success.
    if Keyword.get(opts, :readmit, false),
      do: Wakes.readmit_released_quota_intents_in_txn(txn, incident_id)

    Txn.q(
      txn,
      """
      SELECT DISTINCT s.sessionKey FROM sessions s
      JOIN turns t ON t.sessionKey=s.sessionKey
      WHERE s.harness=?1 AND s.host=?2 AND s.state='active' AND t.status='queued'
      """,
      [harness, host]
    )
    |> Enum.each(fn [session_key] ->
      Txn.handoff(txn, Tightbeam.LaneManager, {:ensure_lane, session_key})
    end)

    :ok
  end

  @doc """
  Whether a failed turn's quota failure was post-activity (contract (c) R9a's
  `:unknown_effect`), so no path may replay it (companion v1.1 B5, A2(iii)).
  """
  @spec post_activity_quota_failure_in_txn?(Txn.t(), pos_integer()) :: boolean()
  def post_activity_quota_failure_in_txn?(%Txn{} = txn, turn_seq)
      when is_integer(turn_seq) and turn_seq > 0 do
    quota_failure?(txn, turn_seq) and
      LimitFallback.Outcome.classify_in_txn(txn, turn_seq) == :unknown_effect
  end

  @doc """
  Record and surface one post-activity quota-failed turn as not replayed, at
  the point its replay vehicles are withheld (companion v1.1 B5, v3 R16). Its
  incident may not exist yet; a later release finds the item and adds nothing.
  """
  @spec surface_not_replayed_in_txn(Txn.t(), pos_integer()) :: :ok
  def surface_not_replayed_in_txn(%Txn{} = txn, turn_seq)
      when is_integer(turn_seq) and turn_seq > 0 do
    case Txn.q(
           txn,
           """
           SELECT t.seq,t.sessionKey,t.assignmentId,t.messageId,t.requestRef,
                  (SELECT o.incidentId FROM harness_health_observations o
                   WHERE o.correlationId='harness-turn:' || t.seq || ':rate-limit-dead'
                     AND o.evidenceKind IN ('terminal-failure','authoritative-provider')
                   LIMIT 1)
           FROM turns t WHERE t.seq=?1
           """,
           [turn_seq]
         ) do
      [[seq, session_key, assignment_id, message_id, request_ref, incident_id]] ->
        not_replayed_in_txn(txn, incident_id, %{
          seq: seq,
          session_key: session_key,
          assignment_id: assignment_id,
          message_id: message_id,
          request_ref: request_ref
        })

      [] ->
        :ok
    end
  end

  defp quota_failure?(txn, turn_seq) do
    Txn.q(
      txn,
      """
      SELECT 1 FROM harness_health_observations
      WHERE correlationId=?1 AND evidenceKind IN ('terminal-failure','authoritative-provider') LIMIT 1
      """,
      ["harness-turn:#{turn_seq}:rate-limit-dead"]
    ) != []
  end

  defp quota_failed_turns_in_txn(txn, incident_id) do
    txn
    |> Txn.q(
      """
      SELECT DISTINCT t.seq,t.sessionKey,t.assignmentId,t.messageId,t.requestRef
      FROM harness_health_observations o
      JOIN turns t ON o.correlationId = 'harness-turn:' || t.seq || ':rate-limit-dead'
      WHERE o.incidentId=?1 AND o.evidenceKind IN ('terminal-failure','authoritative-provider')
        AND t.status='failed'
        -- A c1-applied switch already disposed of and announced its failed
        -- turn (contract c R9b, R13); no second item (stale-turn R9).
        AND NOT EXISTS (
          SELECT 1 FROM limit_fallback_evaluations e
          WHERE e.turnSeq=t.seq AND e.outcome='applied'
        )
      ORDER BY t.seq
      """,
      [incident_id]
    )
    |> Enum.map(fn [seq, session_key, assignment_id, message_id, request_ref] ->
      %{
        seq: seq,
        session_key: session_key,
        assignment_id: assignment_id,
        message_id: message_id,
        request_ref: request_ref
      }
    end)
  end

  # One disposition per turn, however many releases its incident sees: the
  # holder's notice id is the turn's, so a later release finds it and stops.
  defp not_replayed_in_txn(txn, incident_id, turn) do
    holder_notice = notice_wake_id(turn.seq, turn.session_key)

    if Txn.q(txn, "SELECT 1 FROM wakes WHERE wakeId=?1", [holder_notice]) == [] do
      :ok = Wakes.settle_unreplayed_failure_in_txn(txn, turn.seq)

      EventLog.lifecycle_in_txn(
        txn,
        "quota_failed_turn_not_replayed",
        turn.session_key,
        JSON.encode!(%{
          turnSeq: turn.seq,
          incidentId: incident_id,
          disposition: "unknown_effect",
          cause: "provider_quota"
        })
      )

      txn
      |> recipients_in_txn(turn)
      |> Enum.each(fn recipient ->
        input = %{
          wake_id: notice_wake_id(turn.seq, recipient),
          session_key: recipient,
          origin: @process,
          prompt: notice_text(turn),
          due_at: System.system_time(:millisecond),
          class: "input-needed"
        }

        input =
          if is_binary(turn.assignment_id),
            do: Map.put(input, :assignment_id, turn.assignment_id),
            else: input

        Wakes.schedule_in_txn(txn, input)
      end)
    end

    :ok
  end

  # The holder, then the delivery owner of the turn's assignment, or the
  # holder's owner's Main when the turn served none. One item each.
  defp recipients_in_txn(txn, turn) do
    owner =
      case turn.assignment_id do
        assignment_id when is_binary(assignment_id) ->
          case Wakes.delivery_owner_in_txn(txn, assignment_id) do
            {:ok, recipient} -> recipient
            {:error, _} -> main_for_in_txn(txn, turn.session_key)
          end

        _ ->
          main_for_in_txn(txn, turn.session_key)
      end

    [turn.session_key, owner]
    |> Enum.reject(&is_nil/1)
    |> Enum.uniq()
    |> Enum.filter(fn key ->
      Txn.q(txn, "SELECT 1 FROM sessions WHERE sessionKey=?1 AND state='active'", [key]) ==
        [[1]]
    end)
  end

  defp main_for_in_txn(txn, session_key) do
    case Txn.q(txn, "SELECT ownerUserId FROM sessions WHERE sessionKey=?1", [session_key]) do
      [[owner]] when is_binary(owner) -> Org.personal_session_key(owner)
      _ -> nil
    end
  end

  defp notice_wake_id(turn_seq, recipient) do
    digest =
      :crypto.hash(:sha256, JSON.encode!(["quota-unknown-effect", turn_seq, recipient]))
      |> Base.encode16(case: :lower)
      |> binary_part(0, 32)

    "w_quota_unknown_effect_" <> digest
  end

  defp notice_text(turn) do
    assignment =
      if is_binary(turn.assignment_id), do: " for assignment #{turn.assignment_id}", else: ""

    """
    ## Usage limit: a failed turn was not replayed

    Turn #{turn.seq} of #{turn.session_key}#{assignment} failed on a provider usage limit after it had started work: it recorded tool calls or replies, so it may have had effects. Its quota park has been released, and the turn was NOT replayed (outcome unknown_effect, cause provider_quota). Its original request reference is #{turn.request_ref || "none"} (message #{turn.message_id || "none"}).

    Decide whether that request must be redone. Before acting on it, re-derive its state from the records (the transcript, tool calls, assignments and attests) and check whether its effects already happened.
    """
    |> String.trim_trailing()
  end
end

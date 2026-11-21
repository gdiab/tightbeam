defmodule Tightbeam.MemoryGuard.Admission do
  @moduledoc """
  How this contract's holds compose with the line's other standing admission
  reasons (memory limits v1.1 R6a; companion v1.7 §7.3 C1).

  - A release ends only its own reason. A memory release never lifts a quota
    park, and a quota release never lifts a memory hold: each is checked on its
    own at the lane's pre-claim gate (`SessionLane.claim_and_start/1`).
  - No re-admission hook runs while another reason stands. A hook that would
    run at a release that leaves a memory reason in place is deferred here, as
    a recorded row, and runs once, when the last memory reason on the host
    clears: companion B5's re-admission of the key's pre-activity
    quota-failed turns, and R9's not-started re-admission.
  - Releases, remaining holds and the moment admission resumes are separate
    `lifecycle_events` rows: `memory_guard_release`,
    `admission_hold_remaining` and `admission_resumed`.
  """

  alias Tightbeam.{DB, EventLog, Harness, HarnessProcess, Ledger, LimitFallback, Wakes}
  alias Tightbeam.DB.Txn
  alias Tightbeam.MemoryGuard.State

  # Current state in `memory_guard_open` (review B7): what is pending or held
  # now, and the done markers looked up by turn, so no sample or admission
  # reads the lifecycle history.
  @quota_pending "quota_readmission"
  @unblock "unblock"
  @memory_pending "memory_readmission"
  @step_hold "step_hold"
  @readmitted "readmitted_queued"
  @readmitted_seq "readmitted_seq"
  @readmitted_source "readmitted_source"

  @doc """
  The standing reasons other than this contract's that hold `session_key`
  now: `quota_park` (a park fence on its key) and `limit_fallback` (an open
  limit-fallback evaluation).
  """
  @spec other_reasons(DB.server(), String.t()) :: [String.t()]
  def other_reasons(db, session_key) do
    case DB.query(db, "SELECT harness,host FROM sessions WHERE sessionKey=?1", [session_key]) do
      {:ok, [[harness, host]]} ->
        key = {Harness.parse!(harness).id(), "shared", host}

        Enum.filter(
          [
            HarnessProcess.parked?(db, key) && "quota_park",
            parking?(db, key) && "harness_process_parking",
            LimitFallback.held?(db, session_key) && "limit_fallback"
          ],
          & &1
        )

      _ ->
        []
    end
  end

  @doc """
  The same reasons as `other_reasons/2`, inside a transaction, so a hook and
  the check that gates it see one state (R6a).
  """
  @spec other_reasons_in_txn(Txn.t(), String.t()) :: [String.t()]
  def other_reasons_in_txn(%Txn{} = txn, session_key) do
    case Txn.q(txn, "SELECT harness,host FROM sessions WHERE sessionKey=?1", [session_key]) do
      [[harness, host]] ->
        key = {Harness.parse!(harness).id(), "shared", host}

        Enum.filter(
          [
            HarnessProcess.parked_in_txn?(txn, key) && "quota_park",
            parking_in_txn?(txn, key) && "harness_process_parking",
            fallback_open_in_txn?(txn, session_key) && "limit_fallback"
          ],
          & &1
        )

      _ ->
        []
    end
  end

  # R6a / companion C1 (matrix G4): a harness-process row of the key still
  # parking, or whose kill failed, unresolved.
  @parking_sql """
  SELECT 1 FROM harness_processes
  WHERE adapterKey=?1 AND state IN ('park_requested','kill_failed') AND resolvedAt IS NULL
  LIMIT 1
  """

  defp parking?(db, key) do
    case DB.query(db, @parking_sql, [HarnessProcess.adapter_key_name(key)]) do
      {:ok, []} -> false
      {:ok, _} -> true
      # Unknown is standing (R6a): no hook runs on a guess.
      {:error, _} -> true
    end
  end

  defp parking_in_txn?(txn, key),
    do: Txn.q(txn, @parking_sql, [HarnessProcess.adapter_key_name(key)]) != []

  defp fallback_open_in_txn?(txn, session_key) do
    Txn.q(
      txn,
      "SELECT 1 FROM limit_fallback_evaluations WHERE sessionKey=?1 AND outcome IS NULL LIMIT 1",
      [session_key]
    ) != []
  end

  # The release transaction's own share of a quota hook: as many units (one
  # observation or one evaluation examined, each a few indexed lookups) as
  # the guard's whole per-sample budget (re-review att_5f6e6736 B3).
  @release_budget 64

  # At most this many of a session's pending redeliveries are checked for an
  # incident's membership; past it the session counts as covered (held).
  @covered_rows 8

  @doc """
  At a quota-park release (companion B5), clear the blocked marks of the
  key's held sessions and run the re-admission of the incident's
  pre-activity quota-failed turns, once, when no other reason holds a
  session it covers (R6a).

  Both are bounded continuations (re-review att_5f6e6736 B1, B3):
  - the blocked marks are an `unblock` open item the guard clears 32 at a
    time;
  - the hook is a `quota_readmission` item. This transaction runs its
    first 64 units: a small incident is checked, decided and re-admitted
    here, in one step; a larger one is continued by the guard, a page per
    sample, its cursor committed with each page.

  While a memory reason stands on the host the hook waits (it is deferred).
  With no memory guard configured nothing would continue it, so the hook
  runs to the end in this transaction, as the companion's re-admission
  always has. Returns `:resumed` (decided) or `:deferred`.
  """
  @spec quota_released_in_txn(Txn.t(), String.t(), String.t(), String.t()) ::
          :deferred | :resumed
  def quota_released_in_txn(%Txn{} = txn, incident_id, harness, host) do
    key = HarnessProcess.adapter_key_name({Harness.parse!(harness).id(), "shared", host})
    State.open_in_txn(txn, @unblock, key, key, host, nil)

    item = %{
      "host" => host,
      "harness" => harness,
      "incidentId" => incident_id,
      "phase" => "check",
      "cursor" => nil,
      "mark" => nil,
      "deferred" => false
    }

    case Tightbeam.MemoryGuard.host_reasons(host) do
      [] ->
        budget = if Tightbeam.MemoryGuard.configured?(), do: @release_budget, else: :all
        {result, _units} = quota_run_in_txn(txn, item, "quota_park", budget)
        result

      remaining ->
        EventLog.lifecycle_in_txn(
          txn,
          "admission_hold_remaining",
          incident_id,
          JSON.encode!(%{
            host: host,
            harness: harness,
            released: "quota_park",
            remaining: remaining
          })
        )

        save_quota_in_txn(txn, %{item | "deferred" => true}, true)
        :deferred
    end
  end

  @doc """
  One bounded step of a deferred or continuing quota hook (a
  `quota_readmission` open item), in one transaction, with at most `budget`
  units. `memory_reasons` are the memory reasons standing on its host now: a
  hook not yet decided waits while any stands. Returns `{:ok, units}` or
  `{:error, message}`.
  """
  @spec run_quota_item(DB.server(), map(), [String.t()], pos_integer()) ::
          {:ok, pos_integer()} | {:error, String.t()}
  def run_quota_item(db, %{detail: detail}, memory_reasons, budget) do
    item = JSON.decode!(detail)

    case DB.transaction(db, fn txn ->
           if item["phase"] == "check" and memory_reasons != [],
             do: {:deferred, 1},
             else: quota_run_in_txn(txn, item, "memory", budget)
         end) do
      {:ok, {_result, units}} -> {:ok, units}
      {:error, error} -> {:error, Exception.message(error)}
    end
  catch
    :exit, reason -> {:error, inspect(reason)}
  end

  # Steps until the hook is done, waits, or the budget is spent; the item's
  # progress is saved with the step. `:all` (no guard to continue it) runs
  # the hook to its end.
  defp quota_run_in_txn(txn, item, released, budget) do
    {status, units, item} = quota_step_in_txn(txn, item, released, budget)

    case status do
      :done ->
        State.close_in_txn(txn, @quota_pending, item["incidentId"])
        {:resumed, units}

      :more when budget == :all ->
        {result, more} = quota_run_in_txn(txn, item, released, :all)
        {result, units + more}

      :more ->
        save_quota_in_txn(txn, item, false)
        {if(item["phase"] == "run", do: :resumed, else: :deferred), units}

      :deferred ->
        save_quota_in_txn(txn, item, false)
        {:deferred, units}
    end
  end

  defp save_quota_in_txn(txn, item, new_deferral?) do
    id = item["incidentId"]
    detail = JSON.encode!(item)

    unless State.open_in_txn?(txn, @quota_pending, id) do
      State.open_in_txn(txn, @quota_pending, id, id, item["host"], detail)

      if new_deferral?,
        do:
          EventLog.lifecycle_in_txn(
            txn,
            "quota_readmission_deferred",
            id,
            JSON.encode!(%{host: item["host"], harness: item["harness"], incidentId: id})
          )
    end

    State.update_detail_in_txn(txn, @quota_pending, id, detail)
  end

  # The hook is one hook covering every session of the incident: it runs
  # once, only when no session it covers is held by another standing reason
  # (R6a "no re-admission hook SHALL run … until the last standing reason
  # clears", T14; matrix G2). Paged:
  # - "check" pages the incident's observations, checking each covered
  #   session (harness parking: one probe per step; an open limit-fallback
  #   evaluation: one probe per session). A held session ends the pass: the
  #   deferral is recorded once, and the next pass starts again.
  # - At the end of a pass that took more than one step, the evaluations
  #   opened since it began (`mark`, id keyset) are checked too, so a session
  #   checked early and held later is still seen; the decision is then made
  #   in one transaction with that check: admission resumes, recorded.
  # - "run" pages the same observations and re-admits each source once.
  defp quota_step_in_txn(txn, item, released, budget) do
    key = {Harness.parse!(item["harness"]).id(), "shared", item["host"]}

    cond do
      # A key parked again is left for that park's own release.
      HarnessProcess.parked_in_txn?(txn, key) ->
        {:deferred, 1, item}

      item["phase"] == "check" ->
        quota_check_in_txn(txn, item, key, released, budget)

      true ->
        quota_readmit_in_txn(txn, item, budget, 0)
    end
  end

  defp quota_check_in_txn(txn, item, key, released, budget) do
    incident_id = item["incidentId"]
    first_step? = item["cursor"] == nil and item["mark"] == nil
    item = if item["mark"], do: item, else: Map.put(item, "mark", newest_evaluation(txn))

    {sources, examined, next} =
      Wakes.quota_intent_page_in_txn(txn, incident_id, cursor(item), page_size(budget))

    held =
      if parking_in_txn?(txn, key),
        do: {"harness_process_parking", sources |> Enum.map(&Enum.at(&1, 1)) |> Enum.uniq()},
        else: fallback_held(txn, sources)

    cond do
      held != nil ->
        {:deferred, max(examined, 1), quota_deferred_in_txn(txn, item, released, held)}

      next != nil ->
        {:more, max(examined, 1), Map.put(item, "cursor", Tuple.to_list(next))}

      first_step? ->
        quota_decide_in_txn(txn, item, released, budget, max(examined, 1))

      true ->
        quota_watermark_in_txn(txn, item, released, budget, examined)
    end
  end

  defp fallback_held(txn, sources) do
    case sources
         |> Enum.map(&Enum.at(&1, 1))
         |> Enum.uniq()
         |> Enum.filter(&fallback_open_in_txn?(txn, &1)) do
      [] -> nil
      sessions -> {"limit_fallback", sessions}
    end
  end

  # The evaluations opened since the pass began, a page at a time: an open
  # one on a covered session holds the hook; once none is left unchecked the
  # hook is decided, in this transaction.
  defp quota_watermark_in_txn(txn, item, released, budget, used) do
    limit = page_size(remaining(budget, used))

    rows =
      Txn.q(
        txn,
        "SELECT id, sessionKey, outcome FROM limit_fallback_evaluations WHERE id > ?1 ORDER BY id LIMIT ?2",
        [item["mark"], limit]
      )

    used = used + max(length(rows), 1)

    held =
      for [_id, session_key, nil] <- rows,
          covered_in_txn?(txn, session_key, item["incidentId"]),
          uniq: true,
          do: session_key

    cond do
      held != [] ->
        {:deferred, used, quota_deferred_in_txn(txn, item, released, {"limit_fallback", held})}

      length(rows) == limit ->
        [[last | _] | _] = Enum.reverse(rows)
        {:more, used, Map.put(item, "mark", last)}

      true ->
        quota_decide_in_txn(txn, item, released, budget, used)
    end
  end

  # Whether a session has a pending pre-activity redelivery of the incident:
  # at most 8 of its pending quota redeliveries are looked at (partial index
  # `memory_guard_redelivery_session`); past them, it counts as covered.
  defp covered_in_txn?(txn, session_key, incident_id) do
    rows =
      Txn.q(
        txn,
        """
        SELECT sourceTurnSeq FROM health_redelivery_attempts
          INDEXED BY memory_guard_redelivery_session
        WHERE sessionKey=?1 AND redeliveryTurnSeq IS NULL AND failureClass='rate-limit-dead'
        LIMIT ?2
        """,
        [session_key, @covered_rows + 1]
      )

    length(rows) > @covered_rows or
      Enum.any?(rows, fn [seq] ->
        Txn.q(
          txn,
          "SELECT 1 FROM harness_health_observations WHERE correlationId=?1 AND incidentId=?2",
          ["harness-turn:#{seq}:rate-limit-dead", incident_id]
        ) != []
      end)
  end

  defp quota_decide_in_txn(txn, item, released, budget, used) do
    incident_id = item["incidentId"]

    if item["deferred"],
      do:
        EventLog.lifecycle_in_txn(
          txn,
          "quota_readmission_resumed",
          incident_id,
          JSON.encode!(%{host: item["host"], harness: item["harness"]})
        )

    resumed_in_txn(txn, incident_id, item["host"], last_released(txn, incident_id, released))
    item = %{item | "phase" => "run", "cursor" => nil}

    case remaining(budget, used) do
      0 -> {:more, used, item}
      left -> quota_readmit_in_txn(txn, item, left, used)
    end
  end

  defp quota_readmit_in_txn(txn, item, budget, used) do
    {sources, examined, next} =
      Wakes.quota_intent_page_in_txn(txn, item["incidentId"], cursor(item), page_size(budget))

    for source <- sources, do: Wakes.readmit_quota_source_in_txn(txn, source)
    used = used + max(examined, 1)

    if next == nil,
      do: {:done, used, item},
      else: {:more, used, Map.put(item, "cursor", Tuple.to_list(next))}
  end

  # A held session ends the pass. Its deferral is recorded once per reason
  # (the release and each remaining hold are distinguishable records, R6a),
  # and the next pass starts from the beginning.
  defp quota_deferred_in_txn(txn, item, released, {reason, sessions}) do
    incident_id = item["incidentId"]

    unless hold_recorded?(txn, incident_id, reason),
      do:
        EventLog.lifecycle_in_txn(
          txn,
          "admission_hold_remaining",
          incident_id,
          JSON.encode!(%{
            host: item["host"],
            harness: item["harness"],
            released: released,
            remaining: [reason],
            sessions: sessions
          })
        )

    unless item["deferred"],
      do:
        EventLog.lifecycle_in_txn(
          txn,
          "quota_readmission_deferred",
          incident_id,
          JSON.encode!(%{host: item["host"], harness: item["harness"], incidentId: incident_id})
        )

    %{item | "deferred" => true, "cursor" => nil, "mark" => nil}
  end

  defp newest_evaluation(txn) do
    case Txn.q(txn, "SELECT max(id) FROM limit_fallback_evaluations", []) do
      [[id]] when is_integer(id) -> id
      _ -> 0
    end
  end

  defp cursor(%{"cursor" => [at, id]}), do: {at, id}
  defp cursor(_item), do: nil

  defp page_size(:all), do: @release_budget
  defp page_size(budget), do: max(budget, 1)

  defp remaining(:all, _used), do: @release_budget
  defp remaining(budget, used), do: max(budget - used, 0)

  defp hold_recorded?(txn, incident_id, reason) do
    Txn.q(
      txn,
      """
      SELECT 1 FROM lifecycle_events
      WHERE kind='admission_hold_remaining' AND subject=?1
        AND EXISTS (SELECT 1 FROM json_each(detail,'$.remaining') WHERE value=?2)
      LIMIT 1
      """,
      [incident_id, reason]
    ) != []
  end

  # The reason whose release let the hook run: a limit-fallback evaluation
  # when one held it last, else the release that ran it.
  defp last_released(txn, incident_id, released) do
    if hold_recorded?(txn, incident_id, "limit_fallback"), do: "limit_fallback", else: released
  end

  @doc "Record that admission resumed on a key once its last standing reason cleared."
  @spec resumed_in_txn(Txn.t(), String.t(), String.t(), String.t()) :: :ok
  def resumed_in_txn(%Txn{} = txn, subject, host, last_released) do
    EventLog.lifecycle_in_txn(
      txn,
      "admission_resumed",
      subject,
      JSON.encode!(%{host: host, after: [last_released]})
    )
  end

  @doc """
  R9's not-started rule: a turn whose session tree was memory killed before
  its prompt was dispatched is re-admitted exactly once. A turn that is itself
  such a re-admission is not re-admitted again (the load-and-kill loop stop).
  Returns `:readmitted`, `:deferred` (a standing reason, of this contract or
  another, still holds the session; it runs once the last one clears, R6a) or
  `:exhausted`.
  """
  @spec not_started_in_txn(Txn.t(), pos_integer(), String.t()) ::
          :readmitted | :deferred | :exhausted
  def not_started_in_txn(%Txn{} = txn, seq, host) do
    cond do
      readmission?(txn, seq) ->
        :exhausted

      Tightbeam.MemoryGuard.host_reasons(host) != [] or
          other_reasons_in_txn(txn, session_of(txn, seq)) != [] ->
        memory_pending_in_txn(txn, session_of(txn, seq), seq, host)

        Tightbeam.MemoryGuard.note_deferred()
        :deferred

      true ->
        readmit_in_txn(txn, seq, host)
        :readmitted
    end
  end

  @doc """
  v1.13 FS2: the launch step refused to start the session process of turn
  `seq`. The turn was not dispatched, so it is re-admitted (R9's not-started
  rule), on the same standing-reason terms. A second refusal for the session
  also holds its launches `guard_unavailable` until the guard reports the
  step's prerequisites healthy. Each refusal is recorded; none is harness
  health, incident or quota evidence (as R8).
  """
  @spec step_refused_in_txn(Txn.t(), pos_integer(), String.t(), map()) :: :readmitted | :deferred
  def step_refused_in_txn(%Txn{} = txn, seq, host, refusal) do
    session_key = session_of(txn, seq)
    earlier = step_refusals_in_txn(txn, session_key)

    EventLog.lifecycle_in_txn(
      txn,
      "memory_guard_step_refused",
      session_key,
      JSON.encode!(%{
        host: host,
        sourceSeq: seq,
        launchId: refusal.launch_id,
        reason: refusal.reason
      })
    )

    # Recorded: once this commits, the guard removes the refusal's file.
    if is_binary(refusal.launch_id),
      do: Txn.handoff(txn, Tightbeam.MemoryGuard, {:refusal_recorded, refusal.launch_id})

    if earlier >= 1 and not State.open_in_txn?(txn, @step_hold, session_key) do
      detail = JSON.encode!(%{host: host, detail: "guard_unavailable"})
      State.open_in_txn(txn, @step_hold, session_key, session_key, host, detail)
      EventLog.lifecycle_in_txn(txn, "memory_guard_step_hold", session_key, detail)
    end

    if Tightbeam.MemoryGuard.host_reasons(host) != [] or
         other_reasons_in_txn(txn, session_key) != [] do
      memory_pending_in_txn(txn, session_key, seq, host)

      Tightbeam.MemoryGuard.note_deferred()
      :deferred
    else
      readmit_in_txn(txn, seq, host)
      :readmitted
    end
  end

  # Refusals since the session's last step release, counted to 2 at most
  # (only "one before this" matters): newest first on
  # `lifecycle_events_subject_kind`.
  defp step_refusals_in_txn(txn, session_key) do
    [[count]] =
      Txn.q(
        txn,
        """
        SELECT COUNT(*) FROM (
          SELECT 1 FROM lifecycle_events r
          WHERE r.kind='memory_guard_step_refused' AND r.subject=?1
            AND r.id > COALESCE((SELECT MAX(id) FROM lifecycle_events
                                 WHERE kind='memory_guard_step_ready' AND subject=?1), 0)
          LIMIT 2)
        """,
        [session_key]
      )

    count
  end

  defp memory_pending_in_txn(txn, session_key, seq, host) do
    detail = JSON.encode!(%{host: host, sourceSeq: seq})
    State.open_in_txn(txn, @memory_pending, Integer.to_string(seq), session_key, host, detail)
    EventLog.lifecycle_in_txn(txn, "memory_readmission_pending", session_key, detail)
  end

  @doc """
  Whether the step-refusal hold of `session_key` stands (FS2). Raises when it
  cannot be read: an unread hold is not an absent one.
  """
  @spec step_held?(DB.server(), String.t()) :: boolean()
  def step_held?(db, session_key) do
    case DB.transaction(db, &State.open_in_txn?(&1, @step_hold, session_key)) do
      {:ok, held?} -> held?
      {:error, error} -> raise "the step hold cannot be read: #{Exception.message(error)}"
    end
  end

  @doc "End the step-refusal hold of `session_key`: its record and its state in one step."
  @spec step_ready(DB.server(), String.t(), String.t()) :: :ok | {:error, String.t()}
  def step_ready(db, session_key, host) do
    DB.transaction(db, fn txn ->
      State.close_in_txn(txn, @step_hold, session_key)

      EventLog.lifecycle_in_txn(
        txn,
        "memory_guard_step_ready",
        session_key,
        JSON.encode!(%{host: host, detail: "guard_unavailable"})
      )
    end)
    |> case do
      {:ok, _} -> :ok
      {:error, error} -> {:error, Exception.message(error)}
    end
  catch
    :exit, reason -> {:error, inspect(reason)}
  end

  @doc "Whether `seq` is the re-admission of a memory-killed not-started turn."
  @spec readmission?(Txn.t(), pos_integer()) :: boolean()
  def readmission?(%Txn{} = txn, seq),
    do: State.open_in_txn?(txn, @readmitted_seq, Integer.to_string(seq))

  defp readmit_in_txn(txn, seq, host) do
    case Txn.q(
           txn,
           """
           SELECT sessionKey,messageId,origin,prompt,roleRef,roleFallback,assignmentId,jobRef,requestRef
           FROM turns WHERE seq=?1
           """,
           [seq]
         ) do
      [
        [
          session_key,
          message_id,
          origin,
          prompt,
          role_ref,
          role_fallback,
          assignment_id,
          job_ref,
          request_ref
        ]
      ] ->
        ref = Integer.to_string(seq)

        # A source already re-admitted is never enqueued again; a replayed
        # deferral of it is done.
        if State.open_in_txn?(txn, @readmitted_source, ref),
          do: State.close_in_txn(txn, @memory_pending, ref)

        if not State.open_in_txn?(txn, @readmitted_source, ref) and
             Ledger.enqueueable_in_txn?(txn, session_key) do
          {:ok, readmitted} =
            Ledger.enqueue_in_txn(txn, %{
              session_key: session_key,
              message_id: message_id,
              origin: origin,
              prompt: prompt,
              role_ref: role_ref,
              role_fallback: role_fallback == 1,
              assignment_id: assignment_id,
              job_ref: job_ref,
              request_ref: request_ref
            })

          detail = JSON.encode!(%{host: host, sourceSeq: seq, readmittedSeq: readmitted})
          done_in_txn(txn, seq, session_key, host, detail)
          readmitted_ref = Integer.to_string(readmitted)
          State.open_in_txn(txn, @readmitted_seq, readmitted_ref, session_key, host, detail)
          State.open_in_txn(txn, @readmitted, readmitted_ref, session_key, host, detail)
          EventLog.lifecycle_in_txn(txn, "memory_readmission_done", session_key, detail)

          Txn.handoff(txn, Tightbeam.LaneManager, {:ensure_lane, session_key})
        else
          # A session that can take no new turn (gone, or its one turn used)
          # never will: the re-admission is done, recorded as not enqueued,
          # never left pending forever or claimed as queued.
          unless State.open_in_txn?(txn, @readmitted_source, ref) do
            detail =
              JSON.encode!(%{
                host: host,
                sourceSeq: seq,
                readmittedSeq: nil,
                notEnqueueable: true
              })

            done_in_txn(txn, seq, session_key, host, detail)
            EventLog.lifecycle_in_txn(txn, "memory_readmission_done", session_key, detail)
          end
        end

      # M2: the source turn is gone; nothing to enqueue. The done record is
      # still written, so the hook is not pending forever.
      [] ->
        detail = JSON.encode!(%{host: host, sourceSeq: seq, readmittedSeq: nil, sourceGone: true})
        done_in_txn(txn, seq, "turn:#{seq}", host, detail)
        EventLog.lifecycle_in_txn(txn, "memory_readmission_done", "turn:#{seq}", detail)
    end
  end

  # The source turn's re-admission is done: it is no longer pending, and it is
  # never re-admitted again.
  defp done_in_txn(txn, seq, subject, host, detail) do
    ref = Integer.to_string(seq)
    State.close_in_txn(txn, @memory_pending, ref)
    State.open_in_txn(txn, @readmitted_source, ref, subject, host, detail)
  end

  @doc """
  Of one page of re-admitted turns (R9 not-started, FS2 refusal), the
  sessions whose turn is still queued within the hour, to be nudged in case
  the handoff after the re-admission's commit never reached them (matrix
  M3); the others are closed. One transaction.
  """
  @spec readmitted_page(DB.server(), [map()], integer()) ::
          {:ok, [String.t()]} | {:error, String.t()}
  def readmitted_page(db, rows, now) do
    since = now - 3_600_000

    DB.transaction(db, fn txn ->
      Enum.reduce(rows, [], fn %{ref: ref, subject: session_key, opened_at: opened_at}, acc ->
        queued? =
          Txn.q(txn, "SELECT 1 FROM turns WHERE seq=?1 AND status='queued'", [
            String.to_integer(ref)
          ]) != []

        # A re-admission whose turn left the queue, or older than the hour,
        # needs no further nudge.
        if queued? and opened_at >= since do
          [session_key | acc]
        else
          State.close_in_txn(txn, @readmitted, ref)
          acc
        end
      end)
      |> Enum.uniq()
    end)
    |> case do
      {:ok, sessions} -> {:ok, sessions}
      {:error, error} -> {:error, Exception.message(error)}
    end
  catch
    :exit, reason -> {:error, inspect(reason)}
  end

  defp session_of(txn, seq) do
    case Txn.q(txn, "SELECT sessionKey FROM turns WHERE seq=?1", [seq]) do
      [[key]] -> key
      [] -> "turn:#{seq}"
    end
  end

  @doc """
  Run one deferred not-started re-admission (a `memory_readmission` open
  item), in one transaction, once no reason of any kind holds its session.
  """
  @spec run_memory_item(DB.server(), map()) :: :ok | {:error, String.t()}
  def run_memory_item(db, %{subject: session_key, host: host, detail: detail}) do
    %{"sourceSeq" => seq} = JSON.decode!(detail)

    transact(db, fn txn ->
      if other_reasons_in_txn(txn, session_key) == [], do: readmit_in_txn(txn, seq, host)
    end)
  end

  defp transact(db, fun) do
    case DB.transaction(db, fun) do
      {:ok, _} -> :ok
      {:error, error} -> {:error, Exception.message(error)}
    end
  catch
    :exit, reason -> {:error, inspect(reason)}
  end

  @doc "Whether any deferred hook, on any host, has not yet run (unknown is pending)."
  @spec pending?(DB.server()) :: boolean()
  def pending?(db) do
    case DB.transaction(db, fn txn ->
           State.any_in_txn?(txn, @quota_pending) or State.any_in_txn?(txn, @memory_pending)
         end) do
      {:ok, pending?} -> pending?
      # Unknown is pending: the next pass looks again.
      {:error, _} -> true
    end
  catch
    :exit, _ -> true
  end
end

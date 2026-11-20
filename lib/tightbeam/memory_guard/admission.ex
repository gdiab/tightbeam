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
            fallback_open_in_txn?(txn, session_key) && "limit_fallback"
          ],
          & &1
        )

      _ ->
        []
    end
  end

  defp fallback_open_in_txn?(txn, session_key) do
    Txn.q(
      txn,
      "SELECT 1 FROM limit_fallback_evaluations WHERE sessionKey=?1 AND outcome IS NULL LIMIT 1",
      [session_key]
    ) != []
  end

  @doc """
  At a quota-park release (companion B5), run the re-admission of the
  incident's pre-activity quota-failed turns for every session nothing else
  holds. When a memory reason still stands on the key's host the whole hook
  is deferred; a session under an open limit-fallback evaluation keeps its
  turns pending. Deferred work runs once, when its last reason clears
  (`run_deferred/2`). Returns `:resumed` or `:deferred`.
  """
  @spec quota_released_in_txn(Txn.t(), String.t(), String.t(), String.t()) ::
          :deferred | :resumed
  def quota_released_in_txn(%Txn{} = txn, incident_id, harness, host) do
    case Tightbeam.MemoryGuard.host_reasons(host) do
      [] ->
        readmit_quota_in_txn(txn, incident_id, harness, host, "quota_park", false)

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

        EventLog.lifecycle_in_txn(
          txn,
          "quota_readmission_deferred",
          incident_id,
          JSON.encode!(%{host: host, harness: harness, incidentId: incident_id})
        )

        Tightbeam.MemoryGuard.note_deferred()
        :deferred
    end
  end

  # The quota hook for the sessions no limit-fallback evaluation holds, in the
  # transaction that checks it. Sessions still held leave the hook pending:
  # its deferral is recorded once, and it is resumed only when none is left.
  defp readmit_quota_in_txn(txn, incident_id, harness, host, released, deferred?) do
    {_count, held} =
      Wakes.readmit_released_quota_intents_in_txn(
        txn,
        incident_id,
        &(not fallback_open_in_txn?(txn, &1))
      )

    cond do
      held == [] ->
        if deferred?,
          do:
            EventLog.lifecycle_in_txn(
              txn,
              "quota_readmission_resumed",
              incident_id,
              JSON.encode!(%{host: host, harness: harness})
            )

        resumed_in_txn(txn, incident_id, host, last_released(txn, incident_id, released))
        :resumed

      fallback_hold_recorded?(txn, incident_id) ->
        :deferred

      true ->
        EventLog.lifecycle_in_txn(
          txn,
          "admission_hold_remaining",
          incident_id,
          JSON.encode!(%{
            host: host,
            harness: harness,
            released: released,
            remaining: ["limit_fallback"],
            sessions: held
          })
        )

        unless deferred?,
          do:
            EventLog.lifecycle_in_txn(
              txn,
              "quota_readmission_deferred",
              incident_id,
              JSON.encode!(%{host: host, harness: harness, incidentId: incident_id})
            )

        Tightbeam.MemoryGuard.note_deferred()
        :deferred
    end
  end

  defp fallback_hold_recorded?(txn, incident_id) do
    Txn.q(
      txn,
      """
      SELECT 1 FROM lifecycle_events
      WHERE kind='admission_hold_remaining' AND subject=?1
        AND EXISTS (SELECT 1 FROM json_each(detail,'$.remaining') WHERE value='limit_fallback')
      LIMIT 1
      """,
      [incident_id]
    ) != []
  end

  # The reason whose release let the hook run: a limit-fallback evaluation
  # when one held it last, else the release that ran it.
  defp last_released(txn, incident_id, released) do
    if fallback_hold_recorded?(txn, incident_id), do: "limit_fallback", else: released
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
        EventLog.lifecycle_in_txn(
          txn,
          "memory_readmission_pending",
          session_of(txn, seq),
          JSON.encode!(%{host: host, sourceSeq: seq})
        )

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

    if earlier >= 1 and not step_hold_open_in_txn?(txn, session_key) do
      EventLog.lifecycle_in_txn(
        txn,
        "memory_guard_step_hold",
        session_key,
        JSON.encode!(%{host: host, detail: "guard_unavailable"})
      )
    end

    if Tightbeam.MemoryGuard.host_reasons(host) != [] or
         other_reasons_in_txn(txn, session_key) != [] do
      EventLog.lifecycle_in_txn(
        txn,
        "memory_readmission_pending",
        session_key,
        JSON.encode!(%{host: host, sourceSeq: seq})
      )

      Tightbeam.MemoryGuard.note_deferred()
      :deferred
    else
      readmit_in_txn(txn, seq, host)
      :readmitted
    end
  end

  # Refusals since the session's last step release.
  defp step_refusals_in_txn(txn, session_key) do
    [[count]] =
      Txn.q(
        txn,
        """
        SELECT COUNT(*) FROM lifecycle_events r
        WHERE r.kind='memory_guard_step_refused' AND r.subject=?1
          AND r.id > COALESCE((SELECT MAX(id) FROM lifecycle_events
                               WHERE kind='memory_guard_step_ready' AND subject=?1), 0)
        """,
        [session_key]
      )

    count
  end

  defp step_hold_open_in_txn?(txn, session_key) do
    Txn.q(
      txn,
      """
      SELECT 1 FROM lifecycle_events h
      WHERE h.kind='memory_guard_step_hold' AND h.subject=?1
        AND NOT EXISTS (SELECT 1 FROM lifecycle_events r
                        WHERE r.kind='memory_guard_step_ready' AND r.subject=?1 AND r.id>h.id)
      LIMIT 1
      """,
      [session_key]
    ) != []
  end

  @doc "Sessions whose launches the step refused twice and are held (FS2)."
  @spec step_held_sessions(DB.server()) :: [String.t()]
  def step_held_sessions(db) do
    case DB.query(
           db,
           """
           SELECT DISTINCT h.subject FROM lifecycle_events h
           WHERE h.kind='memory_guard_step_hold'
             AND NOT EXISTS (SELECT 1 FROM lifecycle_events r
                             WHERE r.kind='memory_guard_step_ready' AND r.subject=h.subject
                               AND r.id>h.id)
           """,
           []
         ) do
      {:ok, rows} -> Enum.map(rows, fn [key] -> key end)
      _ -> []
    end
  end

  @doc "Whether the step-refusal hold of `session_key` stands (FS2)."
  @spec step_held?(DB.server(), String.t()) :: boolean()
  def step_held?(db, session_key), do: session_key in step_held_sessions(db)

  @doc "Whether `seq` is the re-admission of a memory-killed not-started turn."
  @spec readmission?(Txn.t(), pos_integer()) :: boolean()
  def readmission?(%Txn{} = txn, seq) do
    Txn.q(
      txn,
      """
      SELECT 1 FROM lifecycle_events
      WHERE kind='memory_readmission_done' AND json_extract(detail,'$.readmittedSeq')=?1
      LIMIT 1
      """,
      [seq]
    ) != []
  end

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
        if Txn.q(
             txn,
             """
             SELECT 1 FROM lifecycle_events
             WHERE kind='memory_readmission_done' AND json_extract(detail,'$.sourceSeq')=?1
             LIMIT 1
             """,
             [seq]
           ) == [] and Ledger.enqueueable_in_txn?(txn, session_key) do
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

          EventLog.lifecycle_in_txn(
            txn,
            "memory_readmission_done",
            session_key,
            JSON.encode!(%{host: host, sourceSeq: seq, readmittedSeq: readmitted})
          )

          Txn.handoff(txn, Tightbeam.LaneManager, {:ensure_lane, session_key})
        end

      [] ->
        :ok
    end
  end

  defp session_of(txn, seq) do
    case Txn.q(txn, "SELECT sessionKey FROM turns WHERE seq=?1", [seq]) do
      [[key]] -> key
      [] -> "turn:#{seq}"
    end
  end

  @doc """
  No memory reason stands on `host`: run each deferred hook whose other
  reasons have cleared, once. A deferred quota re-admission whose key is
  parked again is left for that park's own release; one whose session is
  under an open limit-fallback evaluation waits for its outcome.
  """
  @spec run_deferred(DB.server(), String.t()) :: :ok | :pending
  def run_deferred(db, host) do
    DB.transaction(db, fn txn ->
      for [subject, detail] <-
            pending_in_txn(txn, "quota_readmission_deferred", "quota_readmission_resumed", host) do
        %{"harness" => harness} = JSON.decode!(detail)
        key = {Harness.parse!(harness).id(), "shared", host}

        unless HarnessProcess.parked_in_txn?(txn, key),
          do: readmit_quota_in_txn(txn, subject, harness, host, "memory", true)
      end

      # A not-started re-admission runs only when no reason of any kind
      # still holds its session (R6a); otherwise it stays pending.
      for [session_key, detail] <-
            pending_in_txn(txn, "memory_readmission_pending", "memory_readmission_done", host),
          other_reasons_in_txn(txn, session_key) == [] do
        %{"sourceSeq" => seq} = JSON.decode!(detail)
        readmit_in_txn(txn, seq, host)
      end

      pending_in_txn(txn, "quota_readmission_deferred", "quota_readmission_resumed", host) !=
        [] or
        pending_in_txn(txn, "memory_readmission_pending", "memory_readmission_done", host) !=
          []
    end)
    |> case do
      {:ok, true} -> :pending
      {:ok, false} -> :ok
    end
  end

  # Rows of `pending_kind` on `host` with no matching `done_kind` row (matched
  # by subject for the quota hook, by source turn for the not-started one).
  @doc "Whether any deferred hook, on any host, has not yet run."
  @spec pending?(DB.server()) :: boolean()
  def pending?(db) do
    case DB.query(
           db,
           """
           SELECT 1 FROM lifecycle_events p
           WHERE (p.kind='quota_readmission_deferred' AND NOT EXISTS (
                    SELECT 1 FROM lifecycle_events d
                    WHERE d.kind='quota_readmission_resumed' AND d.subject=p.subject))
              OR (p.kind='memory_readmission_pending' AND NOT EXISTS (
                    SELECT 1 FROM lifecycle_events d
                    WHERE d.kind='memory_readmission_done'
                      AND json_extract(d.detail,'$.sourceSeq')=json_extract(p.detail,'$.sourceSeq')))
           LIMIT 1
           """,
           []
         ) do
      {:ok, []} -> false
      # Unknown is pending: the next pass looks again.
      _ -> true
    end
  end

  defp pending_in_txn(txn, pending_kind, done_kind, host) do
    match =
      if pending_kind == "memory_readmission_pending",
        do: "json_extract(d.detail,'$.sourceSeq')=json_extract(p.detail,'$.sourceSeq')",
        else: "d.subject=p.subject"

    Txn.q(
      txn,
      """
      SELECT p.subject,p.detail FROM lifecycle_events p
      WHERE p.kind=?1 AND json_extract(p.detail,'$.host')=?3
        AND NOT EXISTS (SELECT 1 FROM lifecycle_events d WHERE d.kind=?2 AND #{match})
      ORDER BY p.id
      """,
      [pending_kind, done_kind, host]
    )
  end
end

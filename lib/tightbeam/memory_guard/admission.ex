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

        fallback? =
          Txn.q(
            txn,
            "SELECT 1 FROM limit_fallback_evaluations WHERE sessionKey=?1 AND outcome IS NULL LIMIT 1",
            [session_key]
          ) != []

        Enum.filter(
          [
            HarnessProcess.parked_in_txn?(txn, key) && "quota_park",
            fallback? && "limit_fallback"
          ],
          & &1
        )

      _ ->
        []
    end
  end

  @doc """
  At a quota-park release (companion B5): when a memory reason still stands
  on the key's host, record the remaining hold and defer the re-admission.
  Returns `:deferred`, or `:resume` when nothing else stands and the caller
  runs the hook now and records the resumption (`resumed_in_txn/4`).
  """
  @spec quota_released_in_txn(Txn.t(), String.t(), String.t(), String.t()) :: :deferred | :resume
  def quota_released_in_txn(%Txn{} = txn, incident_id, harness, host) do
    case Tightbeam.MemoryGuard.host_reasons(host) do
      [] ->
        :resume

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
  The last memory reason on `host` cleared: run each deferred hook once.
  A deferred quota re-admission whose key is parked again is left for that
  park's own release.
  """
  @spec run_deferred(DB.server(), String.t()) :: :ok | :pending
  def run_deferred(db, host) do
    DB.transaction(db, fn txn ->
      for [subject, detail] <-
            pending_in_txn(txn, "quota_readmission_deferred", "quota_readmission_resumed", host) do
        %{"harness" => harness} = JSON.decode!(detail)
        key = {Harness.parse!(harness).id(), "shared", host}

        unless HarnessProcess.parked_in_txn?(txn, key) do
          Wakes.readmit_released_quota_intents_in_txn(txn, subject)

          EventLog.lifecycle_in_txn(
            txn,
            "quota_readmission_resumed",
            subject,
            JSON.encode!(%{host: host, harness: harness})
          )

          resumed_in_txn(txn, subject, host, "memory")
        end
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

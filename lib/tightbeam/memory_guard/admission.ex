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
    # Agreed design rev 3 D5: the park's release clears the blocked mark of
    # the key's held sessions in its own transaction, so they re-enter the
    # eligible-holds index.
    key = HarnessProcess.adapter_key_name({Harness.parse!(harness).id(), "shared", host})

    Txn.q(
      txn,
      "UPDATE memory_guard_open SET blocked=NULL WHERE kind='hold' AND adapterKey=?1 AND blocked IS NOT NULL",
      [key]
    )

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

        quota_deferred_in_txn(txn, incident_id, harness, host)
        Tightbeam.MemoryGuard.note_deferred()
        :deferred
    end
  end

  defp quota_deferred_in_txn(txn, incident_id, harness, host) do
    detail = JSON.encode!(%{host: host, harness: harness, incidentId: incident_id})
    State.open_in_txn(txn, @quota_pending, incident_id, incident_id, host, detail)
    EventLog.lifecycle_in_txn(txn, "quota_readmission_deferred", incident_id, detail)
  end

  # The quota hook (companion B5) is one hook covering every session of the
  # incident: it runs once, only when no session it covers is held by another
  # standing reason (R6a "no re-admission hook SHALL run … until the last
  # standing reason clears", T14; matrix G2). Until then it stays pending, its
  # deferral recorded once, and nothing of it is re-admitted.
  defp readmit_quota_in_txn(txn, incident_id, harness, host, released, deferred?) do
    key = {Harness.parse!(harness).id(), "shared", host}

    parking? = parking_in_txn?(txn, key)

    held =
      txn
      |> Wakes.released_quota_intent_sessions_in_txn(incident_id)
      |> Enum.filter(&(parking? or fallback_open_in_txn?(txn, &1)))

    remaining =
      Enum.filter(
        [
          parking? && "harness_process_parking",
          Enum.any?(held, &fallback_open_in_txn?(txn, &1)) && "limit_fallback"
        ],
        & &1
      )

    cond do
      held == [] ->
        Wakes.readmit_released_quota_intents_in_txn(txn, incident_id)

        if deferred? do
          State.close_in_txn(txn, @quota_pending, incident_id)

          EventLog.lifecycle_in_txn(
            txn,
            "quota_readmission_resumed",
            incident_id,
            JSON.encode!(%{host: host, harness: harness})
          )
        end

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
            remaining: remaining,
            sessions: held
          })
        )

        unless deferred?, do: quota_deferred_in_txn(txn, incident_id, harness, host)

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

  defp memory_pending_in_txn(txn, session_key, seq, host) do
    detail = JSON.encode!(%{host: host, sourceSeq: seq})
    State.open_in_txn(txn, @memory_pending, Integer.to_string(seq), session_key, host, detail)
    EventLog.lifecycle_in_txn(txn, "memory_readmission_pending", session_key, detail)
  end

  @doc """
  Sessions on `host` whose launches the step refused twice and are held
  (FS2): `{:ok, sessions}` or `{:error, message}`. The step runs only on the
  guard's own host.
  """
  @spec step_held_sessions(DB.server(), String.t()) :: {:ok, [String.t()]} | {:error, String.t()}
  def step_held_sessions(db, host) do
    with {:ok, holds} <- State.list(db, @step_hold, host),
         do: {:ok, Enum.map(holds, & &1.subject)}
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
  No memory reason stands on `host`: run each deferred hook whose other
  reasons have cleared, once. A deferred quota re-admission whose key is
  parked again is left for that park's own release; one whose session is
  under an open limit-fallback evaluation waits for its outcome.
  """
  @spec run_deferred(DB.server(), String.t()) :: :ok | :pending
  def run_deferred(db, host) do
    DB.transaction(db, fn txn ->
      for %{subject: subject, detail: detail} <- State.list_in_txn(txn, @quota_pending, host) do
        %{"harness" => harness} = JSON.decode!(detail)
        key = {Harness.parse!(harness).id(), "shared", host}

        unless HarnessProcess.parked_in_txn?(txn, key),
          do: readmit_quota_in_txn(txn, subject, harness, host, "memory", true)
      end

      # A not-started re-admission runs only when no reason of any kind
      # still holds its session (R6a); otherwise it stays pending.
      for %{subject: session_key, detail: detail} <-
            State.list_in_txn(txn, @memory_pending, host),
          other_reasons_in_txn(txn, session_key) == [] do
        %{"sourceSeq" => seq} = JSON.decode!(detail)
        readmit_in_txn(txn, seq, host)
      end

      State.list_in_txn(txn, @quota_pending, host) != [] or
        State.list_in_txn(txn, @memory_pending, host) != []
    end)
    |> case do
      {:ok, true} -> :pending
      {:ok, false} -> :ok
      # FS7 (G5): the hook and its records are one step; a failed write means
      # nothing happened, and the next pass retries it.
      {:error, _} -> :pending
    end
  end

  @doc """
  Run one deferred quota re-admission hook (a `quota_readmission` open item),
  in one transaction, unless its key is parked again. Returns `:ok` or
  `{:error, message}`; a hook still held stays pending.
  """
  @spec run_quota_item(DB.server(), map()) :: :ok | {:error, String.t()}
  def run_quota_item(db, %{subject: incident_id, host: host, detail: detail}) do
    %{"harness" => harness} = JSON.decode!(detail)
    key = {Harness.parse!(harness).id(), "shared", host}

    transact(db, fn txn ->
      unless HarnessProcess.parked_in_txn?(txn, key),
        do: readmit_quota_in_txn(txn, incident_id, harness, host, "memory", true)
    end)
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

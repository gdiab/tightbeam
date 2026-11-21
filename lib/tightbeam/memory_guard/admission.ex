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

  # Bounded-continuations design §3 with rev 2 D2/D3. One step of a quota
  # episode does at most this many units (an observation, an evaluation or a
  # cover row examined, each a few primary-key or index lookups), in one
  # transaction: the release's own inline step and each wake run alike.
  @step_units 64
  @wait_ms 5_000
  @quota_consumer "memory_guard_quota"

  @episode_columns "episodeId, incidentId, harness, host, obsHigh, phase, cursor, passMark, passFound, watermark, deferred, parkingRecorded, fallbackRecorded, superseded"

  @doc """
  At a quota-park release (companion B5), clear the blocked marks of the
  key's held sessions and run the re-admission of the incident's
  pre-activity quota-failed turns, once, when no other reason holds a
  session it covers (R6a).

  Both are bounded continuations (bounded-continuations design rev 1 §§1,
  3, rev 2 D1–D3):
  - the marks are an `unblock` item the guard clears 32 at a time;
  - the hook is a quota *episode* of this release, its owed observations
    fixed by the incident's largest observation rowid now. This transaction
    runs its first step (64 units): a small incident is checked, decided and
    re-admitted here. A larger one, or one that waits, is continued by its
    own internal wake (`memory_guard_quota`), run by the wake scheduler
    whether or not a memory guard is configured. An earlier unfinished
    episode of the same incident is superseded: it only cleans up.

  Returns `:resumed` (decided) or `:deferred`.
  """
  @spec quota_released_in_txn(Txn.t(), String.t(), String.t(), String.t()) ::
          :deferred | :resumed
  def quota_released_in_txn(%Txn{} = txn, incident_id, harness, host) do
    key = HarnessProcess.adapter_key_name({Harness.parse!(harness).id(), "shared", host})
    unblock_in_txn(txn, key, host)

    Txn.q(
      txn,
      "UPDATE memory_guard_quota_episodes SET superseded=1, phase='cleanup', cursor=0 WHERE incidentId=?1 AND superseded=0",
      [incident_id]
    )

    [[obs_high]] =
      Txn.q(
        txn,
        "SELECT coalesce(max(rowid), 0) FROM harness_health_observations INDEXED BY memory_guard_observations_incident WHERE incidentId=?1",
        [incident_id]
      )

    Txn.q(
      txn,
      """
      INSERT INTO memory_guard_quota_episodes
        (incidentId, harness, host, obsHigh, phase, passMark, createdAt)
      VALUES (?1, ?2, ?3, ?4, 'check', ?5, ?6)
      """,
      [
        incident_id,
        harness,
        host,
        obs_high,
        newest_evaluation(txn),
        System.system_time(:millisecond)
      ]
    )

    [[id]] = Txn.q(txn, "SELECT last_insert_rowid()", [])
    ep = episode_in_txn(txn, id)

    case Tightbeam.MemoryGuard.host_reasons(host) do
      [] ->
        # The park this transaction releases is its own: not a park again.
        {status, _units, ep} = step_in_txn(txn, ep, "quota_park", [], @step_units, false)
        settle_in_txn(txn, ep, status, nil)
        if ep.phase == "check", do: :deferred, else: :resumed

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

        ep = mark_deferred_in_txn(txn, ep)
        settle_in_txn(txn, ep, :wait, nil)
        :deferred
    end
  end

  # B1 (rev 2 D1): the key's marks of lifetimes opened before this release.
  # A pending item for the key takes the newer generation and starts its
  # range again (re-review att_660ea131 B1): a hold below the old cursor,
  # marked again during this park, is this release's to clear.
  defp unblock_in_txn(txn, key, host) do
    gen = State.next_gen_in_txn(txn)

    Txn.q(
      txn,
      """
      INSERT INTO memory_guard_open (kind, ref, subject, host, detail, openedAt, gen)
      VALUES ('unblock', ?1, ?1, ?2, NULL, ?3, ?4)
      ON CONFLICT(kind, ref) DO UPDATE SET gen=excluded.gen, detail=NULL
      """,
      [key, host, System.system_time(:millisecond), gen]
    )
  end

  @doc """
  The internal consumer `memory_guard_quota` (rev 2 D3, the deferred current
  wake): one step of the episode the wake names, in one transaction with
  the wake's own update. Work left: this wake's `dueAt` moves (now, or 5 s
  while the episode waits) and `{:ok, :deferred}` keeps it pending. Done:
  the wake is consumed with the last step. A step that raises rolls back
  whole, and the scheduler retries it.
  """
  @spec quota_wake(DB.server(), map()) :: :ok | {:ok, :deferred} | {:error, String.t()}
  def quota_wake(db, %{wake_id: wake_id}) do
    DB.transaction(db, fn txn ->
      case Txn.q(
             txn,
             "SELECT prompt FROM wakes WHERE wakeId=?1 AND consumer=?2 AND state='pending'",
             [wake_id, @quota_consumer]
           ) do
        [[id]] ->
          case episode_in_txn(txn, String.to_integer(id)) do
            nil ->
              Wakes.consume_internal_in_txn(txn, wake_id)
              :ok

            ep ->
              reasons =
                if ep.phase == "check", do: Tightbeam.MemoryGuard.host_reasons(ep.host), else: []

              released = if ep.deferred == 1, do: "memory", else: "quota_park"
              {status, _units, ep} = step_in_txn(txn, ep, released, reasons, @step_units, true)
              settle_in_txn(txn, ep, status, wake_id)
          end

        [] ->
          :ok
      end
    end)
    |> case do
      {:ok, :ok} -> :ok
      {:ok, :deferred} -> {:ok, :deferred}
      {:error, error} -> {:error, Exception.message(error)}
    end
  end

  # Saves the episode after a step and arms or moves its wake, in the
  # step's transaction. Returns `:ok` (done) or `:deferred`.
  defp settle_in_txn(txn, ep, :done, wake_id) do
    Txn.q(txn, "DELETE FROM memory_guard_quota_episodes WHERE episodeId=?1", [ep.id])
    if wake_id, do: Wakes.consume_internal_in_txn(txn, wake_id)
    :ok
  end

  defp settle_in_txn(txn, ep, status, wake_id) do
    save_episode_in_txn(txn, ep)
    now = System.system_time(:millisecond)
    due = if status == :wait, do: now + @wait_ms, else: now

    if wake_id do
      Txn.q(txn, "UPDATE wakes SET dueAt=?2 WHERE wakeId=?1 AND state='pending'", [wake_id, due])
    else
      arm_wake_in_txn(txn, ep, due)
    end

    :deferred
  end

  defp arm_wake_in_txn(txn, ep, due) do
    case anchor_in_txn(txn, ep) do
      # As park_stranding: the incident names no session, so none is held
      # and no owner is affected: nothing is owed.
      nil ->
        Txn.q(txn, "DELETE FROM memory_guard_quota_episodes WHERE episodeId=?1", [ep.id])

      anchor ->
        Wakes.schedule_in_txn(txn, %{
          wake_id: "memory-guard-quota:#{ep.id}",
          session_key: anchor,
          origin: "process:tightbeam",
          consumer: @quota_consumer,
          prompt: Integer.to_string(ep.id),
          due_at: due,
          # The anchor is only where the row is filed, as park_stranding's.
          target_gate: 0
        })
    end
  end

  # Where the wake is filed, as park_stranding's: a session of the incident
  # (or one the episode covers). Each arm is an indexed probe; one row.
  defp anchor_in_txn(txn, ep) do
    case Txn.q(
           txn,
           """
           SELECT sessionKey FROM (
             SELECT sessionKey FROM harness_health_members WHERE incidentId=?1
             UNION ALL
             SELECT sessionKey FROM memory_guard_quota_cover WHERE episodeId=?2)
           LIMIT 1
           """,
           [ep.incident, ep.id]
         ) do
      [[session_key]] -> session_key
      [] -> nil
    end
  end

  defp episode_in_txn(txn, id) do
    case Txn.q(
           txn,
           "SELECT #{@episode_columns} FROM memory_guard_quota_episodes WHERE episodeId=?1",
           [id]
         ) do
      [
        [
          id,
          incident,
          harness,
          host,
          high,
          phase,
          cursor,
          mark,
          found,
          watermark,
          deferred,
          parking,
          fallback,
          superseded
        ]
      ] ->
        %{
          id: id,
          incident: incident,
          harness: harness,
          host: host,
          high: high,
          phase: phase,
          cursor: cursor,
          mark: mark,
          found: found,
          watermark: watermark,
          deferred: deferred,
          parking: parking,
          fallback: fallback,
          superseded: superseded
        }

      [] ->
        nil
    end
  end

  defp save_episode_in_txn(txn, ep) do
    Txn.q(
      txn,
      """
      UPDATE memory_guard_quota_episodes
      SET phase=?2, cursor=?3, passMark=?4, passFound=?5, watermark=?6, deferred=?7,
          parkingRecorded=?8, fallbackRecorded=?9
      WHERE episodeId=?1
      """,
      [
        ep.id,
        ep.phase,
        ep.cursor,
        ep.mark,
        ep.found,
        ep.watermark,
        ep.deferred,
        ep.parking,
        ep.fallback
      ]
    )
  end

  # One step: `{:done | :more | :wait, units, episode}`.
  # - check: a full pass over the owed observations (rowid ≤ obsHigh), each
  #   covered session recorded once (`memory_guard_quota_cover`) and each
  #   newly held (session, reason) pair recorded once. A pass that found a
  #   hold ends; the next starts after 5 s.
  # - the watermark: at the end of a clean pass, the evaluations opened since
  #   it began; an open one counts exactly when its session is covered.
  # - decide (with the last watermark page, in one transaction), then run
  #   (re-admit each source once), then cleanup (the cover rows, a page per
  #   step), then done.
  defp step_in_txn(txn, ep, released, memory_reasons, budget, park_check?) do
    key = {Harness.parse!(ep.harness).id(), "shared", ep.host}

    cond do
      ep.phase == "cleanup" ->
        cleanup_in_txn(txn, ep, budget, 0)

      ep.phase == "run" ->
        readmit_in_txn(txn, ep, budget, 0)

      # Not yet decided: it waits while a memory reason stands on its host,
      # and a key parked again is left for that park's own release.
      memory_reasons != [] or (park_check? and HarnessProcess.parked_in_txn?(txn, key)) ->
        {:wait, 1, ep}

      ep.watermark != nil ->
        watermark_in_txn(txn, ep, key, released, budget, 0)

      true ->
        check_in_txn(txn, ep, key, released, budget)
    end
  end

  defp check_in_txn(txn, ep, key, released, budget) do
    {sources, examined, next} =
      Wakes.quota_episode_page_in_txn(txn, ep.incident, ep.cursor, ep.high, budget)

    used = max(examined, 1)
    sessions = sources |> Enum.map(&Enum.at(&1, 1)) |> Enum.uniq()
    for session_key <- sessions, do: cover_in_txn(txn, ep.id, session_key)

    ep =
      if parking_in_txn?(txn, key),
        do: hold_found_in_txn(txn, ep, released, "harness_process_parking", sessions),
        else: ep

    ep =
      Enum.reduce(sessions, ep, fn session_key, ep ->
        if fallback_open_in_txn?(txn, session_key),
          do: hold_found_in_txn(txn, ep, released, "limit_fallback", [session_key]),
          else: ep
      end)

    cond do
      next != nil ->
        {:more, used, %{ep | cursor: next}}

      ep.found == 1 ->
        {:wait, used, new_pass_in_txn(txn, ep)}

      true ->
        watermark_in_txn(txn, %{ep | watermark: ep.mark}, key, released, budget, used)
    end
  end

  defp watermark_in_txn(txn, ep, key, released, budget, used) do
    limit = max(budget - used, 1)

    rows =
      Txn.q(
        txn,
        "SELECT id, sessionKey, outcome FROM limit_fallback_evaluations WHERE id > ?1 ORDER BY id LIMIT ?2",
        [ep.watermark, limit]
      )

    used = used + max(length(rows), 1)

    ep =
      for [_id, session_key, nil] <- rows, covered_in_txn?(txn, ep.id, session_key), reduce: ep do
        ep -> hold_found_in_txn(txn, ep, released, "limit_fallback", [session_key])
      end

    ep =
      if ep.found == 0 and parking_in_txn?(txn, key),
        do: hold_found_in_txn(txn, ep, released, "harness_process_parking", []),
        else: ep

    cond do
      ep.found == 1 ->
        {:wait, used, new_pass_in_txn(txn, ep)}

      length(rows) == limit ->
        [[last | _] | _] = Enum.reverse(rows)
        {:more, used, %{ep | watermark: last}}

      true ->
        decide_in_txn(txn, ep, released, budget, used)
    end
  end

  defp decide_in_txn(txn, ep, released, budget, used) do
    if ep.deferred == 1,
      do:
        EventLog.lifecycle_in_txn(
          txn,
          "quota_readmission_resumed",
          ep.incident,
          JSON.encode!(%{host: ep.host, harness: ep.harness})
        )

    last = if ep.fallback == 1, do: "limit_fallback", else: released
    resumed_in_txn(txn, ep.incident, ep.host, last)
    ep = %{ep | phase: "run", cursor: 0, watermark: nil}

    if used < budget, do: readmit_in_txn(txn, ep, budget, used), else: {:more, used, ep}
  end

  defp readmit_in_txn(txn, ep, budget, used) do
    {sources, examined, next} =
      Wakes.quota_episode_page_in_txn(txn, ep.incident, ep.cursor, ep.high, max(budget - used, 1))

    for source <- sources, do: Wakes.readmit_quota_source_in_txn(txn, source)
    used = used + max(examined, 1)

    cond do
      next != nil -> {:more, used, %{ep | cursor: next}}
      used < budget -> cleanup_in_txn(txn, %{ep | phase: "cleanup", cursor: 0}, budget, used)
      true -> {:more, used, %{ep | phase: "cleanup", cursor: 0}}
    end
  end

  defp cleanup_in_txn(txn, ep, budget, used) do
    limit = max(budget - used, 1)

    Txn.q(
      txn,
      """
      DELETE FROM memory_guard_quota_cover WHERE episodeId=?1 AND sessionKey IN (
        SELECT sessionKey FROM memory_guard_quota_cover WHERE episodeId=?1 LIMIT ?2)
      """,
      [ep.id, limit]
    )

    deleted = Txn.changes(txn)
    status = if deleted < limit, do: :done, else: :more
    {status, used + max(deleted, 1), ep}
  end

  # A held (session, reason) pair, recorded once per episode: session-level
  # pairs in the session's cover row, harness parking (key-level) once.
  defp hold_found_in_txn(txn, ep, released, "harness_process_parking", sessions) do
    if ep.parking == 0,
      do: hold_record_in_txn(txn, ep, released, "harness_process_parking", sessions)

    mark_deferred_in_txn(txn, %{ep | parking: 1, found: 1})
  end

  defp hold_found_in_txn(txn, ep, released, reason, [session_key]) do
    [[recorded]] =
      Txn.q(
        txn,
        "SELECT recorded FROM memory_guard_quota_cover WHERE episodeId=?1 AND sessionKey=?2",
        [ep.id, session_key]
      )

    recorded = JSON.decode!(recorded)

    unless reason in recorded do
      hold_record_in_txn(txn, ep, released, reason, [session_key])

      Txn.q(
        txn,
        "UPDATE memory_guard_quota_cover SET recorded=?3 WHERE episodeId=?1 AND sessionKey=?2",
        [ep.id, session_key, JSON.encode!([reason | recorded])]
      )
    end

    mark_deferred_in_txn(txn, %{ep | fallback: 1, found: 1})
  end

  defp hold_record_in_txn(txn, ep, released, reason, sessions) do
    EventLog.lifecycle_in_txn(
      txn,
      "admission_hold_remaining",
      ep.incident,
      JSON.encode!(%{
        host: ep.host,
        harness: ep.harness,
        released: released,
        remaining: [reason],
        sessions: sessions,
        episode: ep.id
      })
    )
  end

  # The episode's first wait is recorded once.
  defp mark_deferred_in_txn(_txn, %{deferred: 1} = ep), do: ep

  defp mark_deferred_in_txn(txn, ep) do
    EventLog.lifecycle_in_txn(
      txn,
      "quota_readmission_deferred",
      ep.incident,
      JSON.encode!(%{host: ep.host, harness: ep.harness, incidentId: ep.incident, episode: ep.id})
    )

    %{ep | deferred: 1}
  end

  defp new_pass_in_txn(txn, ep),
    do: %{ep | cursor: 0, found: 0, watermark: nil, mark: newest_evaluation(txn)}

  defp cover_in_txn(txn, id, session_key) do
    Txn.q(
      txn,
      "INSERT INTO memory_guard_quota_cover (episodeId, sessionKey) VALUES (?1, ?2) ON CONFLICT DO NOTHING",
      [id, session_key]
    )
  end

  # Rev 1 §3 (F3): the incident's own membership, one primary-key probe.
  defp covered_in_txn?(txn, id, session_key) do
    Txn.q(
      txn,
      "SELECT 1 FROM memory_guard_quota_cover WHERE episodeId=?1 AND sessionKey=?2",
      [id, session_key]
    ) != []
  end

  defp newest_evaluation(txn) do
    case Txn.q(txn, "SELECT max(id) FROM limit_fallback_evaluations", []) do
      [[id]] when is_integer(id) -> id
      _ -> 0
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
           Txn.q(txn, "SELECT 1 FROM memory_guard_quota_episodes LIMIT 1", []) != [] or
             State.any_in_txn?(txn, @memory_pending)
         end) do
      {:ok, pending?} -> pending?
      # Unknown is pending: the next pass looks again.
      {:error, _} -> true
    end
  catch
    :exit, _ -> true
  end
end

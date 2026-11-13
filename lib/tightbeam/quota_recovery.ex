defmodule Tightbeam.QuotaRecovery do
  @moduledoc """
  Durable, secret-free quota parks and in-flight recovery state.

  The ledger remains the queue and assignment authority.  This module records
  only admission holds, adapter-instance fences, progress clocks, and the
  attributable releases required by the quota-stranding contract.
  """

  use GenServer

  alias Tightbeam.{DB, EventLog, HarnessProcess}
  alias Tightbeam.DB.Txn

  @owner_notice_ms 6 * 60 * 60 * 1_000
  @tick_ms 30_000

  @ddl """
  CREATE TABLE IF NOT EXISTS quota_recovery_parks (
    adapterKey TEXT PRIMARY KEY,
    incidentId TEXT NOT NULL REFERENCES harness_health_incidents(id),
    harness TEXT NOT NULL,
    host TEXT NOT NULL,
    provider TEXT NOT NULL,
    model TEXT,
    since INTEGER NOT NULL,
    resetAt INTEGER,
    releaseCondition TEXT NOT NULL,
    lastErrorClass TEXT NOT NULL,
    noticeSentAt INTEGER,
    releasedAt INTEGER,
    releasedBy TEXT,
    releaseCause TEXT,
    state TEXT NOT NULL CHECK(state IN ('open','released'))
  );
  CREATE INDEX IF NOT EXISTS quota_recovery_parks_due
    ON quota_recovery_parks(state, resetAt, since);

  CREATE TABLE IF NOT EXISTS quota_recovery_turns (
    turnSeq INTEGER PRIMARY KEY REFERENCES turns(seq),
    sessionKey TEXT NOT NULL REFERENCES sessions(sessionKey),
    adapterKey TEXT NOT NULL,
    adapterGen INTEGER,
    adapterInstance TEXT,
    lastAdvancementAt INTEGER NOT NULL,
    stalledAt INTEGER,
    stallNoticeSentAt INTEGER,
    canceledAt INTEGER,
    quotaKnown INTEGER NOT NULL DEFAULT 0 CHECK(quotaKnown IN (0,1)),
    state TEXT NOT NULL CHECK(state IN
      ('running','in_flight_stalled','unknown_effect','disposed','terminal')),
    dispositionBy TEXT,
    dispositionAt INTEGER,
    disposition TEXT
  );
  CREATE INDEX IF NOT EXISTS quota_recovery_turns_session
    ON quota_recovery_turns(sessionKey, state, turnSeq);

  CREATE TABLE IF NOT EXISTS quota_recovery_adapter_fences (
    adapterKey TEXT NOT NULL,
    adapterGen INTEGER NOT NULL,
    adapterInstance TEXT NOT NULL,
    turnSeq INTEGER NOT NULL REFERENCES turns(seq),
    cause TEXT NOT NULL CHECK(cause IN ('provider_quota','in_flight_stalled')),
    fencedAt INTEGER NOT NULL,
    PRIMARY KEY(adapterKey, adapterInstance, turnSeq)
  );
  """

  def start_link(opts),
    do: GenServer.start_link(__MODULE__, opts, name: Keyword.get(opts, :name, __MODULE__))

  def ensure_schema(db \\ DB), do: DB.execute(db, @ddl)

  @impl true
  def init(opts) do
    db = Keyword.get(opts, :db, DB)
    :ok = ensure_schema(db)
    schedule_tick(Keyword.get(opts, :tick_ms, @tick_ms))
    send(self(), :recover_declared_resets)
    {:ok, %{db: db, tick_ms: Keyword.get(opts, :tick_ms, @tick_ms)}}
  end

  @impl true
  def handle_info(:tick, state) do
    now = System.system_time(:millisecond)
    emit_due_owner_notices(state.db, now)
    schedule_tick(state.tick_ms)
    {:noreply, state}
  end

  def handle_info(:recover_declared_resets, state) do
    {:ok, rows} =
      DB.query(
        state.db,
        "SELECT adapterKey,resetAt FROM quota_recovery_parks WHERE state='open' AND resetAt IS NOT NULL"
      )

    Enum.each(rows, fn [key, reset_at] -> schedule_declared_reset(key, reset_at) end)
    {:noreply, state}
  end

  def handle_info({:declared_reset, key, reset_at}, state) do
    release_declared_reset(state.db, key, reset_at)
    {:noreply, state}
  end

  @impl true
  def handle_cast({:schedule_declared_reset, key}, state) do
    case DB.query(
           state.db,
           "SELECT resetAt FROM quota_recovery_parks WHERE adapterKey=?1 AND state='open'",
           [key]
         ) do
      {:ok, [[reset_at]]} when is_integer(reset_at) -> schedule_declared_reset(key, reset_at)
      _ -> :ok
    end

    {:noreply, state}
  end

  defp schedule_tick(ms), do: Process.send_after(self(), :tick, ms)

  @doc "Record the public park projection inside the incident-opening transaction."
  def open_park_in_txn(%Txn{} = txn, input, incident_id) do
    key = key_name(input.harness, input.host)
    reset_at = declared_reset_at(input.cause, input.observed_at)

    release_condition =
      if reset_at,
        do: "provider declared reset at #{reset_at}",
        else: "later same-credential success or recorded owner/Main resume"

    Txn.q(
      txn,
      """
      INSERT INTO quota_recovery_parks
        (adapterKey,incidentId,harness,host,provider,model,since,resetAt,releaseCondition,
         lastErrorClass,state)
      VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,'open')
      ON CONFLICT(adapterKey) DO UPDATE SET
        incidentId=excluded.incidentId,harness=excluded.harness,host=excluded.host,
        provider=excluded.provider,
        model=excluded.model,since=excluded.since,resetAt=excluded.resetAt,
        releaseCondition=excluded.releaseCondition,lastErrorClass=excluded.lastErrorClass,
        noticeSentAt=NULL,releasedAt=NULL,releasedBy=NULL,releaseCause=NULL,state='open'
      """,
      [
        key,
        incident_id,
        input.harness,
        input.host,
        provider_for(input.harness),
        Map.get(input, :model),
        input.observed_at,
        reset_at,
        release_condition,
        input.failure_class
      ]
    )

    key
  end

  def park_opened(db \\ DB, key) do
    {:ok, rows} =
      DB.query(
        db,
        """
          SELECT t.seq,t.sessionKey,t.adapterGen
          FROM turns t JOIN sessions s ON s.sessionKey=t.sessionKey
          WHERE t.status='running' AND s.harness || ':shared@' || s.host=?1
        """,
        [key]
      )

    Enum.each(rows, fn [seq, session_key, generation] ->
      if is_integer(generation), do: fence_adapter(db, key, generation, seq, "provider_quota")
      mark_quota_known(db, seq)

      if Process.whereis(Tightbeam.LaneRegistry),
        do: Tightbeam.SessionLane.quota_parked(session_key, seq)
    end)

    if coordinator = GenServer.whereis(Tightbeam.AdapterCoordinator) do
      Tightbeam.AdapterCoordinator.request_close_adapter(coordinator, parse_key(key))
    end

    if Process.whereis(__MODULE__) do
      GenServer.cast(__MODULE__, {:schedule_declared_reset, key})
    end

    :ok
  end

  def release_park_in_txn(%Txn{} = txn, harness, host, actor, cause, at) do
    key = key_name(harness, host)

    Txn.q(
      txn,
      """
        UPDATE quota_recovery_parks
        SET state='released',releasedAt=?2,releasedBy=?3,releaseCause=?4
        WHERE adapterKey=?1 AND state='open'
      """,
      [key, at, actor, cause]
    )

    HarnessProcess.complete_park_in_txn(
      txn,
      {Tightbeam.Harness.parse!(harness).id(), "shared", host}
    )

    key
  end

  def explicit_resume(db \\ DB, harness, host, actor) do
    at = System.system_time(:millisecond)

    {:ok, key} =
      DB.transaction(db, &release_park_in_txn(&1, harness, host, actor, "explicit_resume", at))

    nudge_key_sessions(db, key)
    :ok
  end

  @doc false
  def notice_due_holds(db \\ DB, now), do: emit_due_owner_notices(db, now)

  @doc false
  def park_released(db \\ DB, harness, host), do: nudge_key_sessions(db, key_name(harness, host))

  def turn_started(db \\ DB, turn, harness, host) do
    at = System.system_time(:millisecond)
    key = key_name(harness, host)

    DB.query(
      db,
      """
        INSERT INTO quota_recovery_turns
          (turnSeq,sessionKey,adapterKey,adapterGen,lastAdvancementAt,state)
        VALUES (?1,?2,?3,?4,?5,'running')
        ON CONFLICT(turnSeq) DO NOTHING
      """,
      [turn.seq, turn.session_key, key, Map.get(turn, :adapter_gen), at]
    )

    at
  end

  def stamp_generation(db \\ DB, turn_seq, generation),
    do: stamp_generation(db, turn_seq, generation, nil)

  def stamp_generation(db, turn_seq, generation, instance_ref) do
    DB.query(
      db,
      "UPDATE quota_recovery_turns SET adapterGen=?2,adapterInstance=?3 WHERE turnSeq=?1 AND state IN ('running','in_flight_stalled')",
      [turn_seq, generation, instance_ref]
    )

    :ok
  end

  def genuine_advancement(db \\ DB, turn_seq),
    do: genuine_advancement(db, turn_seq, System.system_time(:millisecond))

  def genuine_advancement(db, turn_seq, at) do
    DB.query(
      db,
      """
        UPDATE quota_recovery_turns
        SET lastAdvancementAt=?2,stalledAt=NULL,state='running'
        WHERE turnSeq=?1 AND state IN ('running','in_flight_stalled')
      """,
      [turn_seq, at]
    )

    :ok
  end

  def enter_stall(db \\ DB, turn_seq, at) do
    {:ok, {result, delivery}} =
      DB.transaction(db, fn txn ->
        rows =
          Txn.q(
            txn,
            "SELECT sessionKey,adapterKey,adapterGen,stallNoticeSentAt FROM quota_recovery_turns WHERE turnSeq=?1 AND state='running'",
            [turn_seq]
          )

        case rows do
          [[session_key, key, generation, notice_at]] ->
            Txn.q(
              txn,
              "UPDATE quota_recovery_turns SET state='in_flight_stalled',stalledAt=?2,stallNoticeSentAt=COALESCE(stallNoticeSentAt,?2) WHERE turnSeq=?1",
              [turn_seq, at]
            )

            if is_integer(generation),
              do: fence_adapter_in_txn(txn, key, generation, turn_seq, "in_flight_stalled", at)

            delivery =
              if is_nil(notice_at) do
                EventLog.notice_in_txn(
                  txn,
                  "turn_in_flight_stalled",
                  Integer.to_string(turn_seq),
                  "turnSeq=#{turn_seq} cause=no_genuine_progress principal=process:tightbeam",
                  audience: {:sessions, turn_notice_sessions(txn, turn_seq, session_key)},
                  message:
                    "[turn stalled]\n\nTurn #{turn_seq} has made no genuine progress for 60 minutes. It remains valid until progress resumes or the 120-minute cancel bound is reached.",
                  attention: :high
                )
              end

            {{:stalled, session_key, is_nil(notice_at)}, delivery}

          _ ->
            {:stale, nil}
        end
      end)

    EventLog.complete_notice(delivery)
    result
  end

  def record_unknown_effect(db \\ DB, turn_seq, quota_known, at, owner_lease) do
    {:ok, {result, delivery}} =
      DB.transaction(db, fn txn ->
        record_unknown_effect_in_txn(txn, turn_seq, quota_known, at, owner_lease)
      end)

    EventLog.complete_notice(delivery)
    result
  end

  def record_unknown_effect_in_txn(%Txn{} = txn, turn_seq, quota_known, at, owner_lease) do
    case Txn.q(
           txn,
           "SELECT adapterKey,adapterGen FROM quota_recovery_turns WHERE turnSeq=?1 AND state IN ('running','in_flight_stalled')",
           [turn_seq]
         ) do
      [[key, generation]] ->
        if is_integer(generation),
          do:
            fence_adapter_in_txn(
              txn,
              key,
              generation,
              turn_seq,
              if(quota_known, do: "provider_quota", else: "in_flight_stalled"),
              at
            )

        Txn.q(
          txn,
          "UPDATE quota_recovery_turns SET state='unknown_effect',canceledAt=?2,quotaKnown=?3 WHERE turnSeq=?1",
          [turn_seq, at, if(quota_known, do: 1, else: 0)]
        )

        EventLog.lifecycle_in_txn(
          txn,
          "turn_unknown_effect",
          Integer.to_string(turn_seq),
          "turnSeq=#{turn_seq} cause=#{if(quota_known, do: "provider_quota", else: "no_genuine_progress")} principal=process:tightbeam ownerLease=#{owner_lease}"
        )

        [[session_key]] =
          Txn.q(txn, "SELECT sessionKey FROM quota_recovery_turns WHERE turnSeq=?1", [turn_seq])

        delivery =
          EventLog.notice_in_txn(
            txn,
            "turn_unknown_effect_disposition_required",
            Integer.to_string(turn_seq),
            "turnSeq=#{turn_seq} cause=#{if(quota_known, do: "provider_quota", else: "no_genuine_progress")} principal=process:tightbeam",
            audience: {:sessions, turn_notice_sessions(txn, turn_seq, session_key)},
            message:
              "[turn outcome unknown]\n\nTurn #{turn_seq} was cancelled at its recovery bound. It will not be replayed automatically; the assignment holder or delivery owner must disposition its unknown effect.",
            attention: :high
          )

        {:ok, delivery}

      _ ->
        {:stale, nil}
    end
  end

  def disposition_for_assignment(db \\ DB, assignment_id) do
    case DB.query(
           db,
           """
             SELECT q.turnSeq,q.sessionKey FROM quota_recovery_turns q
             JOIN turns t ON t.seq=q.turnSeq
             WHERE t.assignmentId=?1 AND q.state='unknown_effect' AND q.quotaKnown=0
             ORDER BY q.turnSeq DESC LIMIT 1
           """,
           [assignment_id]
         ) do
      {:ok, [[seq, session_key]]} -> %{turn_seq: seq, session_key: session_key}
      _ -> nil
    end
  end

  def dispose_unknown_effect(db \\ DB, turn_seq, actor),
    do: dispose_unknown_effect(db, turn_seq, actor, "acknowledged")

  def dispose_unknown_effect(db, turn_seq, actor, disposition) do
    at = System.system_time(:millisecond)

    DB.query(
      db,
      """
        UPDATE quota_recovery_turns
        SET state='disposed',dispositionBy=?2,dispositionAt=?3,disposition=?4
        WHERE turnSeq=?1 AND state='unknown_effect' AND quotaKnown=0
      """,
      [turn_seq, actor, at, disposition]
    )

    :ok
  end

  def terminal(db \\ DB, turn_seq) do
    DB.query(
      db,
      "UPDATE quota_recovery_turns SET state='terminal' WHERE turnSeq=?1 AND state IN ('running','in_flight_stalled')",
      [turn_seq]
    )

    :ok
  end

  def admission_held?(db \\ DB, session_key) do
    case held_state(db, session_key) do
      nil -> false
      _ -> true
    end
  end

  def held_state(db \\ DB, session_key) do
    case DB.query(
           db,
           """
             SELECT q.state,q.lastAdvancementAt,q.stalledAt,q.canceledAt,q.turnSeq,q.quotaKnown,
                    s.harness,s.provider,s.model,
                    COALESCE(a.openedBySession, CASE WHEN a.openedByUser IS NOT NULL
                      THEN 'user:' || a.openedByUser END)
             FROM quota_recovery_turns q JOIN sessions s ON s.sessionKey=q.sessionKey
             LEFT JOIN turns t ON t.seq=q.turnSeq LEFT JOIN assignments a ON a.id=t.assignmentId
             WHERE q.sessionKey=?1 AND q.state IN ('in_flight_stalled','unknown_effect')
             ORDER BY q.turnSeq DESC LIMIT 1
           """,
           [session_key]
         ) do
      {:ok, [["unknown_effect", _, _, canceled_at, seq, 0, harness, provider, model, owner]]} ->
        held(
          "blocked_other",
          harness,
          provider,
          model,
          canceled_at,
          "awaiting unknown-effect disposition by holder or delivery owner",
          "unknown_effect",
          owner,
          seq
        )

      {:ok, [["in_flight_stalled", _, stalled_at, _, seq, _, harness, provider, model, owner]]} ->
        held(
          "in_flight_stalled",
          harness,
          provider,
          model,
          stalled_at,
          "genuine progress before the 120-minute bound, or supported cancel",
          "no_genuine_progress",
          owner,
          seq
        )

      _ ->
        park_state(db, session_key)
    end
  end

  def adapter_fenced?(db \\ DB, key, generation),
    do: adapter_fenced?(db, key, generation, nil)

  def adapter_fenced?(db, key, generation, instance_ref)
      when is_integer(generation) and is_binary(instance_ref) do
    {:ok, [[count]]} =
      DB.query(
        db,
        "SELECT COUNT(*) FROM quota_recovery_adapter_fences WHERE adapterKey=?1 AND adapterGen=?2 AND adapterInstance=?3",
        [key_name(key), generation, instance_ref]
      )

    count > 0
  end

  def adapter_fenced?(db, key, generation, nil) when is_integer(generation) do
    {:ok, [[count]]} =
      DB.query(
        db,
        "SELECT COUNT(*) FROM quota_recovery_adapter_fences WHERE adapterKey=?1 AND adapterGen=?2",
        [key_name(key), generation]
      )

    count > 0
  end

  def adapter_fenced?(_db, _key, _generation, _instance_ref), do: false

  defp park_state(db, session_key) do
    case DB.query(
           db,
           """
             SELECT p.harness,p.provider,COALESCE(p.model,s.model),p.since,p.releaseCondition,p.lastErrorClass
             FROM sessions s JOIN quota_recovery_parks p
               ON p.adapterKey=s.harness || ':shared@' || s.host
             WHERE s.sessionKey=?1 AND p.state='open'
           """,
           [session_key]
         ) do
      {:ok, [[harness, provider, model, since, release, error_class]]} ->
        held("provider_quota", harness, provider, model, since, release, error_class, nil, nil)

      _ ->
        nil
    end
  end

  defp held(reason, harness, provider, model, since, release, error_class, owner, seq),
    do: %{
      state: "held",
      reason_class: reason,
      harness: harness,
      provider: provider,
      model: model,
      since: since,
      release_condition: release,
      last_error_class: error_class,
      owner: owner,
      turn_seq: seq
    }

  defp mark_quota_known(db, seq),
    do: DB.query(db, "UPDATE quota_recovery_turns SET quotaKnown=1 WHERE turnSeq=?1", [seq])

  defp fence_adapter(db, key, generation, seq, cause),
    do:
      DB.transaction(
        db,
        &fence_adapter_in_txn(&1, key, generation, seq, cause, System.system_time(:millisecond))
      )

  defp fence_adapter_in_txn(txn, key, generation, seq, cause, at) do
    instance_ref =
      case Txn.q(txn, "SELECT adapterInstance FROM quota_recovery_turns WHERE turnSeq=?1", [seq]) do
        [[value]] when is_binary(value) -> value
        _ -> "generation:#{generation}"
      end

    Txn.q(
      txn,
      "INSERT OR IGNORE INTO quota_recovery_adapter_fences(adapterKey,adapterGen,adapterInstance,turnSeq,cause,fencedAt) VALUES (?1,?2,?3,?4,?5,?6)",
      [key, generation, instance_ref, seq, cause, at]
    )
  end

  defp schedule_declared_reset(key, reset_at) do
    delay = max(reset_at - System.system_time(:millisecond), 0)
    Process.send_after(self(), {:declared_reset, key, reset_at}, delay)
  end

  defp release_declared_reset(db, key, reset_at) do
    case DB.query(
           db,
           "SELECT harness,host FROM quota_recovery_parks WHERE adapterKey=?1 AND state='open' AND resetAt=?2",
           [key, reset_at]
         ) do
      {:ok, [[harness, host]]} ->
        case Tightbeam.HarnessHealth.resolve_declared_reset(db, harness, host, reset_at) do
          {:resolved, released_key} -> nudge_key_sessions(db, released_key)
          :stale -> :ok
        end

      _ ->
        :ok
    end
  end

  defp emit_due_owner_notices(db, now) do
    {:ok, rows} =
      DB.query(
        db,
        "SELECT adapterKey,incidentId FROM quota_recovery_parks WHERE state='open' AND resetAt IS NULL AND noticeSentAt IS NULL AND since+?1<=?2",
        [@owner_notice_ms, now]
      )

    Enum.each(rows, fn [key, incident_id] ->
      {:ok, delivery} =
        DB.transaction(db, fn txn ->
          Txn.q(
            txn,
            "UPDATE quota_recovery_parks SET noticeSentAt=?2 WHERE adapterKey=?1 AND noticeSentAt IS NULL",
            [key, now]
          )

          if Txn.changes(txn) == 1 do
            EventLog.notice_in_txn(
              txn,
              "quota_park_owner_blocker",
              incident_id,
              "adapterKey=#{key} cause=no_release_trigger principal=process:tightbeam",
              audience: {:sessions, park_notice_sessions(txn, incident_id)},
              message:
                "[provider quota hold]\n\nNo declared reset or later success has released #{key} after six hours. The delivery owner or Main may use the recorded resume repair; no provider probe or retry was attempted.",
              attention: :high
            )
          end
        end)

      EventLog.complete_notice(delivery)
    end)
  end

  defp turn_notice_sessions(txn, turn_seq, holder) do
    rows =
      Txn.q(
        txn,
        """
        SELECT sessionKey FROM (
          SELECT ?2 AS sessionKey
          UNION
          SELECT a.openedBySession FROM turns t JOIN assignments a ON a.id=t.assignmentId
            WHERE t.seq=?1 AND a.openedBySession IS NOT NULL
          UNION
          SELECT s.sessionKey FROM turns t JOIN assignments a ON a.id=t.assignmentId
            JOIN sessions s ON s.kind='main' AND s.ownerUserId=a.openedByUser
            WHERE t.seq=?1 AND a.openedByUser IS NOT NULL AND s.state='active'
        ) WHERE sessionKey IS NOT NULL ORDER BY sessionKey
        """,
        [turn_seq, holder]
      )

    Enum.map(rows, &hd/1)
  end

  defp park_notice_sessions(txn, incident_id) do
    rows =
      Txn.q(
        txn,
        """
        SELECT sessionKey FROM (
          SELECT a.openedBySession AS sessionKey
          FROM harness_health_assignments h JOIN assignments a ON a.id=h.assignmentId
          WHERE h.incidentId=?1 AND a.openedBySession IS NOT NULL
          UNION
          SELECT main.sessionKey
          FROM harness_health_members m
          JOIN sessions affected ON affected.sessionKey=m.sessionKey
          JOIN sessions main ON main.kind='main' AND main.ownerUserId=affected.ownerUserId
          WHERE m.incidentId=?1 AND main.state='active'
        ) WHERE sessionKey IS NOT NULL ORDER BY sessionKey
        """,
        [incident_id]
      )

    Enum.map(rows, &hd/1)
  end

  defp nudge_key_sessions(db, key) do
    {:ok, rows} =
      DB.query(db, "SELECT sessionKey FROM sessions WHERE harness || ':shared@' || host=?1", [key])

    if Process.whereis(Tightbeam.LaneRegistry) do
      Enum.each(rows, fn [session_key] -> Tightbeam.SessionLane.nudge(session_key) end)
    end
  end

  defp provider_for("claude"), do: "anthropic"
  defp provider_for("codex"), do: "openai"
  defp provider_for(harness), do: harness

  def key_name({harness, preset, host}), do: "#{harness}:#{preset}@#{host}"
  def key_name(harness, host), do: "#{harness}:shared@#{host}"

  defp parse_key(key) do
    [harness_preset, host] = String.split(key, "@", parts: 2)
    [harness, preset] = String.split(harness_preset, ":", parts: 2)
    {String.to_existing_atom(harness), preset, host}
  end

  def declared_reset_at(cause, observed_at) when is_binary(cause) do
    case Regex.run(~r/(?:try again at|resets)\s+(.+?)(?:\.|$)/i, cause, capture: :all_but_first) do
      [text] -> parse_reset_text(String.trim(text), observed_at)
      _ -> nil
    end
  end

  def declared_reset_at(_, _), do: nil

  defp parse_reset_text(text, observed_at) do
    case DateTime.from_iso8601(text) do
      {:ok, dt, _} -> DateTime.to_unix(dt, :millisecond)
      _ -> calendar_reset(text, observed_at) || relative_reset(text, observed_at)
    end
  end

  defp calendar_reset(text, observed_at) do
    regex =
      ~r/^(Jan(?:uary)?|Feb(?:ruary)?|Mar(?:ch)?|Apr(?:il)?|May|Jun(?:e)?|Jul(?:y)?|Aug(?:ust)?|Sep(?:tember)?|Oct(?:ober)?|Nov(?:ember)?|Dec(?:ember)?)\s+(\d{1,2})(?:st|nd|rd|th)?(?:,\s*(\d{4}))?,?\s+(\d{1,2})(?::(\d{2}))?\s*(am|pm)(?:\s*\(UTC\))?$/i

    case Regex.run(regex, text, capture: :all_but_first) do
      [month, day, year, hour, minute, meridiem] ->
        observed_year = observed_at |> DateTime.from_unix!(:millisecond) |> Map.fetch!(:year)
        year_missing? = year == ""
        year = if year_missing?, do: observed_year, else: String.to_integer(year)
        hour = twelve_hour(String.to_integer(hour), String.downcase(meridiem))
        minute = if minute == "", do: 0, else: String.to_integer(minute)

        case reset_datetime(year, month, day, hour, minute) do
          value when is_integer(value) and year_missing? and value < observed_at ->
            reset_datetime(year + 1, month, day, hour, minute)

          value ->
            value
        end

      _ ->
        nil
    end
  end

  defp month_number(month) do
    ~w(jan feb mar apr may jun jul aug sep oct nov dec)
    |> Enum.find_index(&String.starts_with?(String.downcase(month), &1))
    |> Kernel.+(1)
  end

  defp twelve_hour(12, "am"), do: 0
  defp twelve_hour(12, "pm"), do: 12
  defp twelve_hour(hour, "pm"), do: hour + 12
  defp twelve_hour(hour, "am"), do: hour

  defp reset_datetime(year, month, day, hour, minute) do
    with {:ok, date} <- Date.new(year, month_number(month), String.to_integer(day)),
         {:ok, time} <- Time.new(hour, minute, 0),
         {:ok, datetime} <- DateTime.new(date, time, "Etc/UTC") do
      DateTime.to_unix(datetime, :millisecond)
    else
      _ -> nil
    end
  end

  defp relative_reset(text, observed_at) do
    case Regex.run(~r/^(\d+)\s*(minute|hour)s?$/i, text, capture: :all_but_first) do
      [amount, unit] ->
        observed_at +
          String.to_integer(amount) *
            if(String.downcase(unit) == "hour", do: 3_600_000, else: 60_000)

      _ ->
        nil
    end
  end
end

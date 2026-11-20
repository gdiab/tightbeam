defmodule Tightbeam.OwnerAlerts do
  @moduledoc """
  Owner alerts: durable records the gateway itself sends to the alert owner
  through Harklight, never through an agent turn.

  One row is one alert. A row is created in the transaction that finds its
  trigger, and its `dedupeKey` makes a second creation write nothing, unless
  the row holding that key was withdrawn as `off`: such an alert never reached
  the owner, so it does not count as alerted. Delivery
  uses the ordinary `Tightbeam.HarklightSend` operation with the owner's Main
  as the origin of record. The row carries its own next attempt time; this
  process keeps one timer for the earliest due time, so a restart resumes
  from the tables.

  An uncertain send is settled through its own operation, never resent. A
  definite failure is retried with a new operation 5, 15 and 60 minutes after
  the first failure and then hourly, until 24 hours after creation, when the
  alert becomes `undelivered`. The alert follows its operation row, so a
  settlement made by boot recovery is adopted rather than repeated.

  A `usage-limit` alert is created in the transaction that
  records a usage-limit turn failure. A `model-fallback` alert is created in
  the transaction that commits a limit-fallback switch's outcome, applied or
  withheld, and like `usage-limit` is never withdrawn as `stale`. A `stall` alert is created when an
  owner's open work item has had no progress for the stall threshold and no
  open assignment of it is held or waiting; its identity is the item and its
  anchor, the latest recorded time anything moved. Stall detection reads
  records only. The stall time of every item is computable, so the same timer
  also covers the earliest predicted stall, and a pass at least every ten
  minutes (never longer than the threshold) plans the stall times that new
  writes create. Every write that moves the work moves the anchor, which puts
  its stall time beyond the next pass; the writes that can make an item stall
  without moving its anchor (a changed setting, a reopened item) tell this
  process directly. A stall found only by a later pass that was due before the
  previous pass is a missed event: it is logged and marked on the alert's
  creation event. Before every new send of a stall alert, the stall is
  re-evaluated in the transaction that records the attempt, and an alert whose
  stall is no longer current is withdrawn as `stale` instead.

  A `memory-pressure` alert (G1) is created when the gateway's host has been
  under memory pressure long enough to open an episode, and once more, as a
  restart alert, when the gateway starts and finds the run marker a pressure
  run left behind. The sampling, the episode rules and the marker file live in
  `Tightbeam.OwnerAlerts.MemoryPressure`; this module holds the transactions
  that record them. A memory-pressure row names no session, turn or work item:
  its `dedupeKey` (`memory-pressure:<host>:<episodeOpenedAt>` or
  `memory-pressure-restart:<host>:<runStartedAt>`) identifies it.

  Each row of every kind records its owner at creation. Before any new
  operation, the owner setting is read again in the transaction that records
  the attempt: if it is cleared, names no user, or names a different user, the
  alert is withdrawn as `off` instead of sent. An uncertain send is still
  settled on its own operation.

  Nothing here creates, queues or changes a turn or a wake of any session. The
  only session records touched are the origin transcript markers for a failed
  delivery and the lifecycle events of each state change.
  """

  use GenServer
  require Logger

  alias Tightbeam.{ConditionFacts, DB, EventLog, HarklightSend, HarnessHealth, Id, Org, UserAdmin, Wakes}
  alias Tightbeam.DB.Txn

  @shape "owner-alerts-v1-0114"
  # The exact main schema stamps this additive table may be created over. On the
  # post-Part-A 0.1.14 build that is session-identity or user-removal (migration
  # contract v3.10 R10, precondition C1).
  @schema_predecessors ["session-identity-v1-0114", "user-removal-v1-0114"]

  @owner_setting "owner-alerts-user"
  @stall_setting "owner-alert-stall-ms"
  @default_stall_ms 14_400_000

  @sender_id "tightbeam-alerts"
  @retry_offsets_ms [300_000, 900_000, 3_600_000]
  @hour_ms 3_600_000
  @window_ms 86_400_000
  # After an unexpected error, wait this long before the same row is tried
  # again so a persistent fault cannot spin the process.
  @repair_delay_ms 60_000
  # S7: a stall is alerted within ten minutes. While alerts are on, a full
  # pass runs at least this often, and never less often than the threshold,
  # so a stall time created by any anchor-moving write is planned before it
  # comes due. The floor keeps a tiny threshold from spinning the process.
  @horizon_ms 600_000
  @min_horizon_ms 60_000
  @max_listed_uncovered 5
  # The delivery gate for a G1 restart (M6) lifts after this long at most, so
  # a G1 boot that keeps failing never holds the other alerts back for longer.
  @memory_pressure_gate_ms 120_000

  # A2: a row withdrawn as `off` (§7.1 C2-off) never reached the owner, so it
  # does not hold its dedupeKey (C3-on). This one predicate is the partial
  # unique index's, the creation upsert's conflict target's, and every
  # existence check's, so they cannot disagree.
  @holds_key "NOT (state = 'withdrawn' AND withdrawnAs = 'off')"

  @owner_alerts_table_ddl """
  CREATE TABLE owner_alerts (
    alertId           TEXT PRIMARY KEY,
    kind              TEXT NOT NULL CHECK (kind IN ('usage-limit','stall','model-fallback','pairing-freeze-lifted')),
    dedupeKey         TEXT NOT NULL,
    ownerUserId       TEXT NOT NULL,
    originSessionKey  TEXT NOT NULL,
    sessionKey        TEXT,
    turnSeq           INTEGER,
    workItemId        TEXT,
    anchorAt          INTEGER,
    title             TEXT NOT NULL CHECK (length(title) > 0),
    body              TEXT NOT NULL,
    state             TEXT NOT NULL CHECK (state IN ('pending','sent','withdrawn','undelivered')),
    withdrawnAs       TEXT CHECK (withdrawnAs IN ('stale','off')),
    createdAt         INTEGER NOT NULL CHECK (createdAt >= 0),
    updatedAt         INTEGER NOT NULL CHECK (updatedAt >= 0),
    opId              TEXT,
    messageId         TEXT,
    attempts          INTEGER NOT NULL DEFAULT 0 CHECK (attempts >= 0),
    firstFailureAt    INTEGER,
    lastOutcome       TEXT,
    lastFailureReason TEXT,
    nextAttemptAt     INTEGER,
    CHECK ((state = 'pending') = (nextAttemptAt IS NOT NULL)),
    CHECK ((state = 'withdrawn') = (withdrawnAs IS NOT NULL)),
    CHECK (state != 'sent' OR (opId IS NOT NULL AND messageId IS NOT NULL)),
    CHECK (kind != 'usage-limit' OR (sessionKey IS NOT NULL AND turnSeq IS NOT NULL)),
    CHECK (kind != 'stall' OR (workItemId IS NOT NULL AND anchorAt IS NOT NULL))
  )
  """

  @owner_alerts_dedupe_ddl """
  CREATE UNIQUE INDEX owner_alerts_dedupe ON owner_alerts (dedupeKey) WHERE #{@holds_key}
  """

  @owner_alerts_pending_ddl """
  CREATE INDEX owner_alerts_pending ON owner_alerts (state, nextAttemptAt)
  """

  # Every object the migration creates, in creation order. Validation of an
  # applied shape compares each one's stored SQL with exactly this text.
  @owner_alerts_objects [
    {"table", "owner_alerts", @owner_alerts_table_ddl},
    {"index", "owner_alerts_dedupe", @owner_alerts_dedupe_ddl},
    {"index", "owner_alerts_pending", @owner_alerts_pending_ddl}
  ]

  @migration_stamp_ddl """
  CREATE TABLE owner_alert_migration (
    id        INTEGER PRIMARY KEY CHECK (id = 0),
    shape     TEXT NOT NULL CHECK (shape = '#{@shape}'),
    appliedAt INTEGER NOT NULL CHECK (appliedAt >= 0)
  )
  """

  ## Schema

  @doc "Create the owner-alert table once over the exact current schema, or validate it."
  @spec ensure_schema(DB.server()) :: :ok
  def ensure_schema(db \\ DB) do
    case DB.migration_transaction(db, :owner_alerts, [], [], &migrate_in_txn/1) do
      {:ok, :applied} ->
        Logger.info("database migration owner_alerts committed shape=#{@shape}")
        :ok

      {:ok, :already_applied} ->
        :ok

      {:error, error} ->
        raise error
    end
  end

  defp migrate_in_txn(%Txn{} = txn) do
    case Txn.q(
           txn,
           "SELECT sql FROM sqlite_master WHERE type='table' AND name='owner_alert_migration'"
         ) do
      [] ->
        migrate_unstamped_in_txn(txn)

      [[sql]] ->
        unless normalize_schema_sql(sql) == normalize_schema_sql(@migration_stamp_ddl) do
          raise Tightbeam.Schema.ShapeError,
            message: "incompatible_owner_alert_migration_ddl: #{inspect(sql)}"
        end

        case Txn.q(txn, "SELECT id, shape, appliedAt FROM owner_alert_migration") do
          [[0, @shape, applied_at]] when is_integer(applied_at) and applied_at >= 0 ->
            validate_applied_shape!(txn)
            :already_applied

          rows ->
            raise Tightbeam.Schema.ShapeError,
              message: "incompatible_owner_alert_migration_stamp: #{inspect(rows)}"
        end

      rows ->
        raise Tightbeam.Schema.ShapeError,
          message: "incompatible_owner_alert_migration_table: #{inspect(rows)}"
    end
  end

  defp migrate_unstamped_in_txn(txn) do
    case Txn.q(txn, "SELECT shape FROM schema_stamp") do
      [[stamp]] when stamp in @schema_predecessors ->
        :ok

      rows ->
        raise Tightbeam.Schema.ShapeError,
          message: "incompatible_owner_alert_predecessor: #{inspect(rows)}"
    end

    # The stamp is written with the table. An unstamped table is dirt from
    # something else and is refused by name, never adopted.
    names = Enum.map(@owner_alerts_objects, fn {_type, name, _sql} -> name end)
    placeholders = Enum.map_join(1..length(names), ",", &"?#{&1}")

    case Txn.q(
           txn,
           "SELECT type, name FROM sqlite_master WHERE name IN (#{placeholders})",
           names
         ) do
      [] ->
        :ok

      rows ->
        raise Tightbeam.Schema.ShapeError,
          message: "incompatible_owner_alerts_unstamped_objects: #{inspect(rows)}"
    end

    :ok = Txn.exec(txn, @migration_stamp_ddl)
    Enum.each(@owner_alerts_objects, fn {_type, _name, sql} -> :ok = Txn.exec(txn, sql) end)

    Txn.q(
      txn,
      "INSERT INTO owner_alert_migration (id, shape, appliedAt) VALUES (0, ?1, ?2)",
      [@shape, System.system_time(:millisecond)]
    )

    if Txn.changes(txn) != 1 do
      raise Tightbeam.Schema.ShapeError,
        message: "owner-alert migration lost its exact stamp transition"
    end

    :applied
  end

  defp validate_applied_shape!(txn) do
    Enum.each(
      @owner_alerts_objects,
      fn {type, name, expected} ->
        case Txn.q(txn, "SELECT sql FROM sqlite_master WHERE type = ?1 AND name = ?2", [
               type,
               name
             ]) do
          [[sql]] when is_binary(sql) ->
            unless normalize_schema_sql(sql) == normalize_schema_sql(expected) do
              raise Tightbeam.Schema.ShapeError,
                message: "incompatible_owner_alerts_schema_object: #{inspect({type, name, sql})}"
            end

          rows ->
            raise Tightbeam.Schema.ShapeError,
              message: "incompatible_owner_alerts_schema_object: #{inspect({type, name, rows})}"
        end
      end
    )
  end

  defp normalize_schema_sql(sql),
    do:
      sql
      |> String.replace("\"", "")
      |> String.replace(~r/\s+/, " ")
      |> String.trim()
      |> String.trim_trailing(";")

  ## Settings

  @doc """
  The alert owner, or nil when alerts are off. A setting that no longer names
  an active user turns alerts off rather than addressing nobody: an unknown
  user, or one removed since it was set (§7, #622), reads as unset.
  """
  @spec owner_in_txn(Txn.t()) :: String.t() | nil
  def owner_in_txn(%Txn{} = txn), do: owner_via(in_txn(txn))

  @doc "The alert owner read outside a transaction, or nil when alerts are off."
  @spec owner(DB.server()) :: String.t() | nil
  def owner(db \\ DB), do: owner_via(reader(db))

  defp owner_via(q) do
    case q.("SELECT value FROM org_settings WHERE key=?1", [@owner_setting]) do
      [[user_id]] when is_binary(user_id) and user_id != "" ->
        # Only an active user: one removed since the setting was made reads as
        # unset (removed-user parts; every owner read goes through here).
        if q.("SELECT 1 FROM users WHERE userId=?1 AND removedAt IS NULL", [user_id]) == [[1]],
          do: user_id,
          else: nil

      _ ->
        nil
    end
  end

  @doc "The stall threshold in milliseconds (§7 default 4 hours)."
  @spec stall_ms(DB.server()) :: pos_integer()
  def stall_ms(db \\ DB), do: parse_stall_ms(Org.get_setting(db, @stall_setting))

  defp stall_ms_via(q) do
    case q.("SELECT value FROM org_settings WHERE key=?1", [@stall_setting]) do
      [[value]] -> parse_stall_ms(value)
      [] -> @default_stall_ms
    end
  end

  defp parse_stall_ms(nil), do: @default_stall_ms
  defp parse_stall_ms(value), do: String.to_integer(value)

  # One query shape for reads outside a transaction and inside one, so the
  # detection pass and the transactions that act on it evaluate the same rules.
  defp reader(db) do
    fn sql, params ->
      {:ok, rows} = DB.query(db, sql, params)
      rows
    end
  end

  defp in_txn(txn), do: fn sql, params -> Txn.q(txn, sql, params) end

  @doc "The presented value of one owner-alert setting."
  def setting_value(db, @owner_setting), do: Org.get_setting(db, @owner_setting)
  def setting_value(db, @stall_setting), do: stall_ms(db)

  @doc """
  Validate a setting value inside the transaction that stores it. Returns the
  stored text, nil for `""` (§7.1 C1-off: clear the setting to unset), or a
  named refusal.
  """
  @spec validate_setting_in_txn(Txn.t(), String.t(), term()) ::
          {:ok, String.t() | nil} | {:error, String.t(), String.t()}
  def validate_setting_in_txn(_txn, setting, "") when setting in [@owner_setting, @stall_setting],
    do: {:ok, nil}

  # §7: the alert owner must be an existing user who is not removed; each is
  # refused by its own name (#622's fixed refusal for a removed user).
  def validate_setting_in_txn(txn, @owner_setting, user_id) do
    cond do
      not (is_binary(user_id) and user_id != "" and user_exists_in_txn?(txn, user_id)) ->
        {:error, "unknown_owner_alerts_user",
         "owner-alerts-user must name an existing user; no user #{inspect(user_id)}"}

      UserAdmin.removed_in_txn?(txn, user_id) ->
        %{code: code, message: message} = UserAdmin.removed_refusal(user_id)
        {:error, code, message}

      true ->
        {:ok, user_id}
    end
  end

  def validate_setting_in_txn(_txn, @stall_setting, ms) when is_integer(ms) and ms > 0,
    do: {:ok, Integer.to_string(ms)}

  def validate_setting_in_txn(_txn, @stall_setting, ms),
    do:
      {:error, "invalid_owner_alert_stall_ms",
       "owner-alert-stall-ms must be a positive integer number of milliseconds; got #{inspect(ms)}"}

  @doc "Present a stored setting value as the config command returns it."
  def present(_setting, nil), do: nil
  def present(@owner_setting, stored), do: stored
  def present(@stall_setting, stored), do: String.to_integer(stored)

  defp user_exists_in_txn?(txn, user_id),
    do: Txn.q(txn, "SELECT 1 FROM users WHERE userId=?1", [user_id]) == [[1]]

  ## (b) usage-limit trigger

  @doc """
  Create the usage-limit alert for a failed turn, inside the transaction that
  recorded the failure's harness-health observation. Only `rate-limit-dead`
  failures of sessions owned by the alert owner create one, and only the first
  failure of a limit episode (B2) does. An episode whose only alert was
  withdrawn as `off` alerts again at its next failure while alerts are on
  (§7.1 C3-on); the new row keeps the episode's `dedupeKey`.
  """
  @spec usage_limit_failure_in_txn(Txn.t(), map(), String.t(), term(), integer()) :: :ok
  def usage_limit_failure_in_txn(%Txn{} = txn, turn, "rate-limit-dead", result, observed_at) do
    with owner when is_binary(owner) <- owner_in_txn(txn),
         [[^owner, display_name, provider, session_model]] <-
           Txn.q(
             txn,
             "SELECT ownerUserId, displayName, provider, model FROM sessions WHERE sessionKey=?1",
             [turn.session_key]
           ),
         [[harness, model, ended_at, assignment_id]] <-
           Txn.q(
             txn,
             "SELECT harness, model, endedAt, assignmentId FROM turns WHERE seq=?1",
             [turn.seq]
           ) do
      session_key = turn.session_key
      first_seq = HarnessHealth.limit_episode_first_seq_in_txn(txn, session_key, turn.seq)
      dedupe_key = "usage-limit:#{session_key}:#{first_seq}"

      if Txn.q(txn, "SELECT 1 FROM owner_alerts WHERE dedupeKey=?1 AND #{@holds_key}", [
           dedupe_key
         ]) == [] do
        failed_at = ended_at || observed_at

        facts = %{
          display_name: display_name,
          session_key: session_key,
          harness: harness,
          provider: provider,
          model: model || session_model,
          failed_at: failed_at,
          reset_at: reset_at_in_txn(txn, result),
          working_on: working_on_in_txn(txn, session_key, assignment_id)
        }

        create_in_txn(txn, %{
          kind: "usage-limit",
          dedupe_key: dedupe_key,
          owner: owner,
          session_key: session_key,
          turn_seq: turn.seq,
          title: usage_limit_title(display_name),
          body: usage_limit_body(facts)
        })
      end
    end

    :ok
  end

  def usage_limit_failure_in_txn(%Txn{}, _turn, _failure_class, _result, _observed_at), do: :ok

  ## (c) model-fallback outcome

  @doc """
  Create the `model-fallback` alert of one limit-fallback outcome (contract c
  v1.4 R15), inside the transaction that commits the outcome. Only a session
  whose owner is the alert owner gets one. An applied outcome's `dedupeKey` is
  `model-fallback:<sessionKey>:<trigger>`, so each switch alerts. A withheld
  outcome's is `model-fallback:<sessionKey>:withheld:<episode>`, where
  `episode` is the seq of the first failed turn of the session's limit
  episode, so a withheld episode alerts once however often it is evaluated.
  The shared creation path, sender, retry, undelivered and `off` rules apply
  unchanged, and like `usage-limit` it is never withdrawn as `stale`.
  """
  @spec model_fallback_in_txn(Txn.t(), %{
          required(:session_key) => String.t(),
          required(:dedupe_ref) => {:applied, String.t()} | {:withheld, pos_integer()},
          required(:title) => String.t(),
          required(:body) => String.t(),
          optional(:turn_seq) => pos_integer() | nil
        }) :: :ok
  def model_fallback_in_txn(
        %Txn{} = txn,
        %{session_key: session_key, dedupe_ref: dedupe_ref, title: title, body: body} = input
      ) do
    with owner when is_binary(owner) <- owner_in_txn(txn),
         [[^owner]] <-
           Txn.q(txn, "SELECT ownerUserId FROM sessions WHERE sessionKey=?1", [session_key]) do
      create_in_txn(txn, %{
        kind: "model-fallback",
        dedupe_key: model_fallback_dedupe_key(session_key, dedupe_ref),
        owner: owner,
        session_key: session_key,
        turn_seq: Map.get(input, :turn_seq),
        title: title,
        body: body
      })
    end

    :ok
  end

  defp model_fallback_dedupe_key(session_key, {:applied, trigger_ref})
       when is_binary(trigger_ref),
       do: "model-fallback:#{session_key}:#{trigger_ref}"

  defp model_fallback_dedupe_key(session_key, {:withheld, episode})
       when is_integer(episode) and episode > 0,
       do: "model-fallback:#{session_key}:withheld:#{episode}"

  # The provider reset Tightbeam parsed from this failure (Claude's
  # "resets …", or Codex's "try again at …" on the gateway's own host) is the
  # due time of its rate-limit-reset wake.
  defp reset_at_in_txn(txn, {_, %{observationId: observation_id}})
       when is_binary(observation_id) do
    case Txn.q(txn, "SELECT dueAt FROM wakes WHERE wakeId=?1", [
           "rate-limit-reset:" <> observation_id
         ]) do
      [[due_at]] when is_integer(due_at) -> due_at
      _ -> nil
    end
  end

  defp reset_at_in_txn(_txn, _result), do: nil

  defp working_on_in_txn(txn, session_key, assignment_id) do
    held =
      if is_binary(assignment_id) do
        Txn.q(
          txn,
          """
          SELECT a.id, a.subject, w.id, w.title FROM assignments a
          LEFT JOIN work_items w ON w.id=a.workItemId
          WHERE a.id=?1 AND a.holderKey=?2
          """,
          [assignment_id, session_key]
        )
      else
        []
      end

    case held do
      [[id, subject, work_item_id, work_item_title]] ->
        {:assignment, id, subject, work_item_id, work_item_title}

      [] ->
        case Txn.q(
               txn,
               """
               SELECT id, subject FROM assignments
               WHERE holderKey=?1 AND state='open'
               ORDER BY openedAt, id LIMIT 3
               """,
               [session_key]
             ) do
          [] -> :none
          rows -> {:open, Enum.map(rows, fn [id, subject] -> {id, subject} end)}
        end
    end
  end

  @doc false
  def usage_limit_title(display_name), do: "#{display_name} hit a usage limit"

  @doc false
  def usage_limit_body(facts) do
    harness = facts.harness |> to_string() |> String.capitalize()
    provider = facts.provider || "unknown"
    model = facts.model || "unknown"

    reset =
      case facts.reset_at do
        nil -> "The provider did not say when the limit resets."
        at -> "The limit resets at #{format_local(at)}."
      end

    working =
      case facts.working_on do
        {:assignment, id, subject, nil, _} ->
          "It was working on '#{subject}' (#{id})."

        {:assignment, id, subject, work_item_id, work_item_title} ->
          "It was working on '#{subject}' (#{id}), part of '#{work_item_title}' (#{work_item_id})."

        {:open, assignments} ->
          listed =
            Enum.map_join(assignments, ", ", fn {id, subject} -> "'#{subject}' (#{id})" end)

          "This turn had no assignment. The session holds these open assignments: #{listed}."

        :none ->
          "No assignment; this was a direct conversation."
      end

    Enum.join(
      [
        "Session '#{facts.display_name}' (#{facts.session_key}) on #{harness}, provider #{provider}, model #{model}, hit a usage limit at #{format_local(facts.failed_at)}.",
        reset,
        working,
        "No reply needed. Tightbeam recorded the failure on this session."
      ],
      " "
    )
  end

  @doc """
  A millisecond time in the gateway's local time zone, with the zone named.
  The zone is the IANA name in `TZ` or `/etc/localtime`; without one, UTC.
  """
  @spec format_local(integer()) :: String.t()
  def format_local(ms) when is_integer(ms) do
    utc = DateTime.from_unix!(ms, :millisecond)

    local =
      case DateTime.shift_zone(utc, local_zone(), Tz.TimeZoneDatabase) do
        {:ok, local} -> local
        {:error, _} -> utc
      end

    Calendar.strftime(local, "%b %-d, %Y %-I:%M %p %Z")
  end

  defp local_zone do
    zone =
      case System.get_env("TZ") do
        value when is_binary(value) and value != "" ->
          String.trim_leading(value, ":")

        _ ->
          case File.read_link("/etc/localtime") do
            {:ok, target} ->
              case String.split(target, "zoneinfo/", parts: 2) do
                [_, name] -> name
                _ -> nil
              end

            {:error, _} ->
              nil
          end
      end

    if zone in [nil, "", "UTC", "Etc/UTC", "UCT", "Zulu", "Universal"],
      do: "Etc/UTC",
      else: zone
  end

  ## Pairing freeze lifted (core fix (A) C6a)

  @doc """
  Create the `pairing-freeze-lifted` alert for one frozen-to-lifted observation,
  inside the transaction that recorded it. Its `dedupeKey` is the observation
  time, so one transition alerts once. Alerts that are off create nothing.
  """
  @spec pairing_freeze_lifted_in_txn(Txn.t(), integer(), String.t()) ::
          {:created, String.t()} | :exists | :off
  def pairing_freeze_lifted_in_txn(%Txn{} = txn, observed_at, body) do
    case owner_in_txn(txn) do
      owner when is_binary(owner) ->
        create_in_txn(txn, %{
          kind: "pairing-freeze-lifted",
          dedupe_key: "pairing-freeze-lifted:#{observed_at}",
          owner: owner,
          title: "The pairing freeze is lifted",
          body: body
        })

      _ ->
        :off
    end
  end

  ## (a) stall trigger

  # S1: the owner's open items with at least one open assignment.
  @candidates_sql """
  SELECT w.id FROM work_items w
  WHERE w.ownerUserId=?1 AND w.state='open'
    AND EXISTS (SELECT 1 FROM assignments a WHERE a.workItemId=w.id AND a.state='open')
  ORDER BY w.id
  """

  # S2: an open assignment is covered while it is held (C1, a standing
  # cannot-proceed; this line has no assignment_hold record), waits on a named
  # fact or dependency (C2), waits on a decision (C3), or waits on work it
  # delegated (C4). On this line C4 is an open assignment on the same work
  # item, opened by this assignment's holder no earlier than this assignment.
  # A condition wake whose condition already fired is held only for notice
  # batching; its firedAt is set while it is still pending, so it no longer
  # waits on anything and covers nothing.
  @open_assignments_sql """
  SELECT a.id, a.subject, a.holderKey,
    EXISTS (SELECT 1 FROM assignment_cannot_proceed c
            WHERE c.assignmentId=a.id AND c.state='standing')
    OR EXISTS (SELECT 1 FROM wakes k
               WHERE k.assignmentId=a.id AND k.state='pending' AND k.firedAt IS NULL
                 AND (k.conditionKind IS NOT NULL OR k.waitMode='dependency'))
    OR EXISTS (SELECT 1 FROM decision_requests d
               WHERE d.assignmentId=a.id AND d.status='open')
    OR EXISTS (SELECT 1 FROM assignments c
               WHERE c.workItemId=a.workItemId AND c.state='open' AND c.id<>a.id
                 AND c.openedBySession=a.holderKey AND c.openedAt>=a.openedAt)
  FROM assignments a
  WHERE a.workItemId=?1 AND a.state='open'
  ORDER BY a.openedAt, a.id
  """

  # S4: the latest of every progress event (any attest), every opening and
  # closing of the item's assignments, and the end of every coverage of an open
  # assignment that has ended. A reopening clears an assignment's closedAt and
  # keeps it, with the reopening time, on its reopening row. A C4 child is on
  # the same item on this line, so its closedAt is already an item closing. A
  # superseded operator request ends when its successor is raised; the
  # successor names it in its context.
  @anchor_sql """
  SELECT MAX(t) FROM (
    SELECT MAX(x.ts) AS t FROM attests x
      JOIN assignments a ON a.id=x.assignmentId WHERE a.workItemId=?1
    UNION ALL SELECT MAX(a.openedAt) FROM assignments a WHERE a.workItemId=?1
    UNION ALL SELECT MAX(a.closedAt) FROM assignments a WHERE a.workItemId=?1
    UNION ALL SELECT MAX(r.ts) FROM assignment_reopenings r
      JOIN assignments a ON a.id=r.assignmentId WHERE a.workItemId=?1
    UNION ALL SELECT MAX(r.priorClosedAt) FROM assignment_reopenings r
      JOIN assignments a ON a.id=r.assignmentId WHERE a.workItemId=?1
    UNION ALL SELECT MAX(c.settledAt) FROM assignment_cannot_proceed c
      JOIN assignments a ON a.id=c.assignmentId
      WHERE a.workItemId=?1 AND a.state='open' AND c.state='settled'
    UNION ALL SELECT MAX(COALESCE(k.firedAt, k.canceledAt)) FROM wakes k
      JOIN assignments a ON a.id=k.assignmentId
      WHERE a.workItemId=?1 AND a.state='open'
        AND (k.conditionKind IS NOT NULL OR k.waitMode='dependency')
    UNION ALL SELECT MAX(COALESCE(d.ruledAt, d.answeredAt, d.withdrawnAt, d.returnedAt))
      FROM decision_requests d JOIN assignments a ON a.id=d.assignmentId
      WHERE a.workItemId=?1 AND a.state='open' AND d.status<>'open'
    UNION ALL SELECT MAX(n.raisedAt) FROM decision_requests d
      JOIN assignments a ON a.id=d.assignmentId
      JOIN decision_requests n
        ON (CASE WHEN n.kind='operator' AND json_valid(n.context)
                 THEN json_extract(n.context, '$.supersedes') END)=d.id
      WHERE a.workItemId=?1 AND a.state='open' AND d.status='superseded'
  )
  """

  @last_progress_sql """
  SELECT x.kind, x.verdictKind, x.ts, a.id, a.subject, s.displayName, x.byUser
  FROM attests x
  JOIN assignments a ON a.id=x.assignmentId
  LEFT JOIN sessions s ON s.sessionKey=x.bySession
  WHERE a.workItemId=?1
  ORDER BY x.ts DESC, x.rowid DESC LIMIT 1
  """

  @doc """
  Create the stall alert of every item stalled at `now` (§6), and report the
  earliest future stall time of the items that are not stalled yet.

  Options: `:now` (milliseconds, default the system clock) and
  `:missed_before`: a stall that came due before this time was missed by the
  event path, so its creation is logged and marked as a miss. Returns the
  alert owner (nil when alerts are off), the threshold, the earliest predicted
  stall time, and counts of created alerts and failed items.
  """
  @spec detect_stalls(DB.server(), keyword()) :: %{
          owner: String.t() | nil,
          stall_ms: pos_integer() | nil,
          next_at: integer() | nil,
          created: non_neg_integer(),
          errors: non_neg_integer()
        }
  def detect_stalls(db \\ DB, opts \\ []) do
    now = Keyword.get_lazy(opts, :now, fn -> System.system_time(:millisecond) end)
    missed_before = Keyword.get(opts, :missed_before)
    q = reader(db)

    case owner_via(q) do
      nil ->
        %{owner: nil, stall_ms: nil, next_at: nil, created: 0, errors: 0}

      owner ->
        stall_ms = stall_ms_via(q)
        initial = %{owner: owner, stall_ms: stall_ms, next_at: nil, created: 0, errors: 0}

        Enum.reduce(q.(@candidates_sql, [owner]), initial, fn [work_item_id], acc ->
          try do
            case stall_status(q, work_item_id, owner, stall_ms, now) do
              # S6: one alert per stall identity, not counting one withdrawn
              # as off, which never reached the owner (§7.1 C3-on).
              {:stalled, anchor} ->
                if q.("SELECT 1 FROM owner_alerts WHERE dedupeKey=?1 AND #{@holds_key}", [
                     stall_dedupe_key(work_item_id, anchor)
                   ]) == [] and create_stall(db, work_item_id, now, missed_before) == :created,
                   do: %{acc | created: acc.created + 1},
                   else: acc

              {:due, at} ->
                %{acc | next_at: if(acc.next_at, do: min(acc.next_at, at), else: at)}

              _quiet_or_out_of_scope ->
                acc
            end
          rescue
            error ->
              if overloaded?(error), do: reraise(error, __STACKTRACE__)

              Logger.error(
                "owner alert stall check of #{work_item_id} failed: #{Exception.message(error)}"
              )

              %{acc | errors: acc.errors + 1}
          end
        end)
    end
  end

  defp overloaded?(%DB.Overloaded{}), do: true
  defp overloaded?(%MatchError{term: {:error, %DB.Overloaded{}}}), do: true
  defp overloaded?(_error), do: false

  defp stall_status(q, work_item_id, owner, stall_ms, now) do
    case evaluate(q, work_item_id, owner) do
      nil -> :out_of_scope
      %{quiet?: true} -> :quiet
      %{anchor: anchor} when now - anchor >= stall_ms -> {:stalled, anchor}
      %{anchor: anchor} -> {:due, anchor + stall_ms}
    end
  end

  # §6.1 and §6.2 for one item, from records only: nil when the item is out of
  # scope, else its anchor, its open assignments and whether it is quiet.
  defp evaluate(q, work_item_id, owner) do
    with [[title]] <-
           q.("SELECT title FROM work_items WHERE id=?1 AND ownerUserId=?2 AND state='open'", [
             work_item_id,
             owner
           ]),
         [_ | _] = rows <- q.(@open_assignments_sql, [work_item_id]) do
      [[anchor]] = q.(@anchor_sql, [work_item_id])

      open =
        Enum.map(rows, fn [id, subject, holder, covered] ->
          %{id: id, subject: subject, holder: holder, covered?: covered == 1}
        end)

      %{
        work_item_id: work_item_id,
        title: title,
        anchor: anchor,
        open: open,
        quiet?: Enum.all?(open, & &1.covered?)
      }
    else
      _ -> nil
    end
  end

  defp stall_dedupe_key(work_item_id, anchor), do: "stall:#{work_item_id}:#{anchor}"

  # A2: the row is created in the transaction that finds the stall, so the
  # stall is re-evaluated here against the committed records.
  defp create_stall(db, work_item_id, now, missed_before) do
    {:ok, result} =
      DB.transaction(db, fn txn ->
        q = in_txn(txn)

        with owner when is_binary(owner) <- owner_via(q),
             stall_ms = stall_ms_via(q),
             %{quiet?: false, anchor: anchor} = item when now - anchor >= stall_ms <-
               evaluate(q, work_item_id, owner) do
          stall_at = anchor + stall_ms
          missed? = is_integer(missed_before) and stall_at < missed_before

          lifecycle =
            if missed?,
              do: %{workItemId: work_item_id, anchorAt: anchor, missedEvent: true},
              else: %{workItemId: work_item_id, anchorAt: anchor}

          created =
            create_in_txn(txn, %{
              kind: "stall",
              dedupe_key: stall_dedupe_key(work_item_id, anchor),
              owner: owner,
              work_item_id: work_item_id,
              anchor_at: anchor,
              title: stall_title(div(now - anchor, @hour_ms), item.title),
              body: stall_body(stall_facts(q, item, now)),
              now: now,
              lifecycle: Map.put(lifecycle, :lateMs, now - stall_at)
            })

          case created do
            {:created, _alert_id} when missed? -> {:missed, anchor, now - stall_at}
            {:created, _alert_id} -> :created
            :exists -> :exists
          end
        else
          _ -> :not_stalled
        end
      end)

    case result do
      {:missed, anchor, late_ms} ->
        Logger.warning(
          "owner alert event miss: stall of work item #{work_item_id} (anchor #{anchor}) " <>
            "was found by a later pass, #{late_ms} ms after it came due"
        )

        :created

      other ->
        other
    end
  end

  defp stall_facts(q, item, now) do
    last =
      case q.(@last_progress_sql, [item.work_item_id]) do
        [[kind, verdict_kind, at, assignment_id, subject, display_name, by_user]] ->
          %{
            kind: kind,
            verdict_kind: verdict_kind,
            at: at,
            assignment_id: assignment_id,
            subject: subject,
            by:
              cond do
                is_binary(display_name) -> "'#{display_name}'"
                is_binary(by_user) -> "user #{by_user}"
                true -> "an unknown filer"
              end
          }

        [] ->
          nil
      end

    {uncovered, covered} = Enum.split_with(item.open, &(not &1.covered?))

    %{
      work_item_id: item.work_item_id,
      now: now,
      last: last,
      uncovered: uncovered |> Enum.take(@max_listed_uncovered) |> Enum.map(&holder_view(q, &1)),
      unlisted: max(length(uncovered) - @max_listed_uncovered, 0),
      covered: length(covered)
    }
  end

  defp holder_view(q, assignment) do
    [[name, harness, model, created_at]] =
      q.("SELECT displayName, harness, model, createdAt FROM sessions WHERE sessionKey=?1", [
        assignment.holder
      ])

    Map.merge(assignment, %{
      holder_name: name,
      harness: harness,
      model: model,
      state: holder_state(q, assignment.holder, created_at)
    })
  end

  # S8's visible holder state, from records only (V3). A running turn is
  # named as such, but it never covers an assignment (§2).
  defp holder_state(q, session_key, created_at) do
    case q.(
           """
           SELECT COALESCE(startedAt, createdAt) FROM turns
           WHERE sessionKey=?1 AND status='running' ORDER BY seq LIMIT 1
           """,
           [session_key]
         ) do
      [[since]] ->
        {:running, since}

      [] ->
        cond do
          q.(
            """
            SELECT 1 FROM harness_health_members m
            JOIN harness_health_incidents i ON i.id=m.incidentId
            WHERE m.sessionKey=?1 AND i.state='open' AND i.failureClass='rate-limit-dead'
            LIMIT 1
            """,
            [session_key]
          ) != [] ->
            :paused

          q.("SELECT 1 FROM turns WHERE sessionKey=?1 AND status='queued' LIMIT 1", [
            session_key
          ]) != [] ->
            :queued

          true ->
            [[ended_at]] = q.("SELECT MAX(endedAt) FROM turns WHERE sessionKey=?1", [session_key])
            {:idle, ended_at || created_at}
        end
    end
  end

  @doc false
  def stall_title(hours, work_item_title), do: "No progress for #{hours}h: #{work_item_title}"

  @doc false
  def stall_body(facts) do
    last =
      case facts.last do
        nil ->
          "Last progress: none yet."

        last ->
          kind =
            if last.kind == "verdict" and is_binary(last.verdict_kind),
              do: "verdict (#{last.verdict_kind})",
              else: last.kind

          "Last progress: a #{kind} attest at #{format_local(last.at)} " <>
            "(#{duration(facts.now - last.at)} ago) on '#{last.subject}' " <>
            "(#{last.assignment_id}), filed by #{last.by}."
      end

    uncovered =
      Enum.map(facts.uncovered, fn view ->
        harness = view.harness |> to_string() |> String.capitalize()

        "- '#{view.subject}' (#{view.id}), held by '#{view.holder_name}' on #{harness}, " <>
          "model #{view.model || "unknown"}: #{holder_state_text(view.state)}."
      end)

    unlisted =
      if facts.unlisted > 0,
        do: ["- and #{facts.unlisted} more not held or waiting."],
        else: []

    covered =
      case facts.covered do
        0 -> "No other open assignments are held or waiting."
        1 -> "1 other open assignment is held or waiting."
        n -> "#{n} other open assignments are held or waiting."
      end

    Enum.join(
      ["Work item #{facts.work_item_id}.", last, "Open assignments not held or waiting:"] ++
        uncovered ++
        unlisted ++
        [
          covered,
          "No reply needed. This alert repeats only if the work moves and then stalls again."
        ],
      "\n"
    )
  end

  defp holder_state_text({:running, since}), do: "running a turn since #{format_local(since)}"
  defp holder_state_text(:queued), do: "queued"
  defp holder_state_text({:idle, since}), do: "idle since #{format_local(since)}"
  defp holder_state_text(:paused), do: "its harness is paused by a usage limit"

  defp duration(ms) do
    ms = max(ms, 0)
    "#{div(ms, @hour_ms)}h #{div(rem(ms, @hour_ms), 60_000)}m"
  end

  @doc """
  After this transaction commits, tell the alert process that a stall input
  changed without moving any item's anchor: an alert setting, or an item
  reopened from the icebox. Every other write that can end a stall's quiet or
  start one moves the anchor, so its stall time is planned by the next pass.
  """
  @spec stall_inputs_changed_in_txn(Txn.t()) :: :ok
  def stall_inputs_changed_in_txn(%Txn{} = txn), do: Txn.handoff(txn, __MODULE__, :stall_inputs)

  # A7: a stall alert is sent only while its stall identity is current. The
  # threshold is not re-read: a setting change applies to alerts created after
  # it. Usage-limit alerts report a past event and are never withdrawn as
  # stale. The caller has already found the recorded owner still current.
  defp stale_withdrawal_in_txn(_txn, %{kind: kind}) when kind != "stall", do: nil

  defp stale_withdrawal_in_txn(txn, alert) do
    case evaluate(in_txn(txn), alert.work_item_id, alert.owner) do
      nil -> {"stale", "out-of-scope"}
      %{quiet?: true} -> {"stale", "held-or-waiting"}
      %{anchor: anchor} when anchor != alert.anchor_at -> {"stale", "work-moved"}
      _current -> nil
    end
  end

  ## G1 host memory pressure

  @memory_kind "memory-pressure"
  @pressure_fact "host-memory-pressure"
  @cleared_fact "host-memory-pressure-cleared"
  @gib_kib 1_048_576
  @gib_bytes 1_073_741_824
  @memory_closing "Tightbeam is only watching. It has not stopped or changed anything. " <>
                    "If free memory keeps falling, the machine may stop responding."

  @doc """
  M4: record one memory-pressure episode's open in one transaction: its
  `memory-pressure` alert and the standing fact `host-memory-pressure` (scope
  the host, filed by the process). The alert's commit hands it to delivery at
  once. Returns `:opened` (also when this episode's alert already exists, for a
  repeated request) or `:off` when alerts are off, in which case nothing is
  written.

  `open` carries `:host`, `:episode_opened_at` and `:run_started_at` (wall
  milliseconds), the `:sample` at the open and the cgroup `:populations`.
  """
  @spec open_memory_episode(DB.server(), GenServer.server(), map()) :: :opened | :off
  def open_memory_episode(db, scheduler, open) do
    %{host: host, episode_opened_at: opened_at} = open

    with_pressure_fact(db, scheduler, fn txn ->
      case owner_in_txn(txn) do
        nil ->
          {:off, nil}

        owner ->
          created =
            create_in_txn(txn, %{
              kind: @memory_kind,
              dedupe_key: memory_dedupe_key(host, opened_at),
              owner: owner,
              title: memory_title(host),
              body: memory_body(open),
              lifecycle: %{
                host: host,
                episodeOpenedAt: opened_at,
                runStartedAt: open.run_started_at
              }
            })

          # The fact is filed with the alert, so an existing alert means this
          # open was already recorded and the fact already stands.
          case created do
            {:created, _alert_id} ->
              {:opened, file_pressure_fact_in_txn(txn, @pressure_fact, host)}

            :exists ->
              {:opened, nil}
          end
      end
    end)
  end

  @doc """
  M5 and §7.1 C2-off: record one episode's close: a lifecycle event with its
  start, end and reason, and `host-memory-pressure-cleared` while the pressure
  fact stands, so no waiter is left standing. No alert is sent on close.
  """
  @spec close_memory_episode(DB.server(), GenServer.server(), map()) :: :closed
  def close_memory_episode(db, scheduler, close) do
    with_pressure_fact(db, scheduler, fn txn ->
      memory_episode_closed_in_txn(
        txn,
        close.host,
        close.episode_opened_at,
        close.ended_at,
        close.reason,
        Map.get(close, :detail, %{})
      )

      {:closed, cleared_fact_in_txn(txn, close.host)}
    end)
  end

  @doc """
  M6: the gateway started and found a run marker. In one transaction: create
  the restart alert (while alerts are on), withdraw the episode's unsent first
  alert as `stale`, close an open episode as `interrupted` and file
  `host-memory-pressure-cleared` while the pressure fact stands.

  `found` is `{:marker, marker}` for a parsed marker or `{:unreadable,
  marked_at}` for one that could not be parsed (a standing run with unknown
  details). The run's episode is the `memory-pressure` alert of this host
  whose episode open time, from its `dedupeKey`, is at or after the run's
  start: the same clock wrote both, and a committed open is found even when
  the marker missed its `episodeOpenedAt`.
  """
  @spec memory_restart(DB.server(), GenServer.server(), String.t(), term(), integer()) ::
          :restarted
  def memory_restart(db, scheduler, host, found, now) do
    run = restart_run(host, found, now)

    with_pressure_fact(db, scheduler, fn txn ->
      owner = owner_in_txn(txn)
      standing? = ConditionFacts.standing_in_txn?(txn, @pressure_fact, run.host)

      episode =
        if is_integer(run.run_started_at),
          do: memory_episode_in_txn(txn, run.host, run.run_started_at)

      opened_at = (episode && episode.opened_at) || run.episode_opened_at

      created =
        if owner do
          create_in_txn(txn, %{
            kind: @memory_kind,
            dedupe_key: run.dedupe_key,
            owner: owner,
            title: memory_restart_title(run.host),
            body:
              memory_restart_body(%{
                run
                | episode_opened_at: opened_at,
                  first_alert: first_alert_status(episode, opened_at)
              }),
            lifecycle: %{
              host: run.host,
              runStartedAt: run.run_started_at,
              runEndedAt: run.run_ended_at,
              episodeOpenedAt: opened_at,
              restart: true
            }
          })
        end

      # A replay (the marker survived an earlier restart's commit) changes
      # nothing more: that commit already did the rest.
      if created == :exists do
        {:restarted, nil}
      else
        if owner && episode, do: supersede_first_alert_in_txn(txn, episode, now)

        if opened_at != nil or (run.unknown? and standing?) do
          memory_episode_closed_in_txn(txn, run.host, opened_at, now, "interrupted", %{})
        end

        {:restarted, cleared_fact_in_txn(txn, run.host)}
      end
    end)
  end

  @doc "Record one memory-pressure sampler lifecycle event (best effort, handed off)."
  @spec memory_lifecycle(DB.server(), String.t(), String.t(), map()) :: :ok
  def memory_lifecycle(db, kind, host, detail),
    do: EventLog.lifecycle(db, kind, memory_subject(host), JSON.encode!(detail))

  defp restart_run(_host, {:marker, marker}, _now) do
    %{
      host: marker["host"],
      run_started_at: marker["runStartedAt"],
      run_ended_at: marker["runEndedAt"],
      episode_opened_at: marker["episodeOpenedAt"],
      last_sample_at: marker["lastSampleAt"],
      last_sample: marker["lastSample"],
      unknown?: false,
      first_alert: nil,
      dedupe_key: "memory-pressure-restart:#{marker["host"]}:#{marker["runStartedAt"]}"
    }
  end

  # A2b: an unparsable marker is a standing run with unknown details. Its
  # key uses the time the marker was last written, so a replay dedupes.
  defp restart_run(host, {:unreadable, marked_at}, now) do
    %{
      host: host,
      run_started_at: nil,
      run_ended_at: nil,
      episode_opened_at: nil,
      last_sample_at: nil,
      last_sample: nil,
      unknown?: true,
      first_alert: nil,
      dedupe_key: "memory-pressure-restart:#{host}:unknown-#{marked_at || now}"
    }
  end

  defp memory_episode_in_txn(txn, host, run_started_at) do
    prefix = "memory-pressure:#{host}:"

    case Txn.q(
           txn,
           """
           SELECT alertId, state, lastOutcome, CAST(substr(dedupeKey, ?2 + 1) AS INTEGER) AS openedAt
           FROM owner_alerts
           WHERE kind='memory-pressure' AND substr(dedupeKey, 1, ?2) = ?1
             AND CAST(substr(dedupeKey, ?2 + 1) AS INTEGER) >= ?3
           ORDER BY openedAt, (state = 'withdrawn' AND withdrawnAs = 'off'), createdAt, alertId
           LIMIT 1
           """,
           [prefix, String.length(prefix), run_started_at]
         ) do
      [[alert_id, state, last_outcome, opened_at]] ->
        %{alert_id: alert_id, state: state, last_outcome: last_outcome, opened_at: opened_at}

      [] ->
        nil
    end
  end

  defp first_alert_status(nil, nil), do: nil
  defp first_alert_status(nil, _opened_at), do: :not_sent
  defp first_alert_status(%{state: "sent"}, _opened_at), do: :sent

  defp first_alert_status(%{state: "pending", last_outcome: "outcome_unknown"}, _opened_at),
    do: :unconfirmed

  defp first_alert_status(_episode, _opened_at), do: :not_sent

  # M6: the restart alert supersedes the episode's first alert while that is
  # not yet sent.
  defp supersede_first_alert_in_txn(txn, %{state: "pending"} = episode, now) do
    withdraw_in_txn(
      txn,
      %{alert_id: episode.alert_id, kind: @memory_kind},
      {"stale", "superseded-by-restart"},
      now
    )
  end

  defp supersede_first_alert_in_txn(_txn, _episode, _now), do: :ok

  defp memory_episode_closed_in_txn(txn, host, opened_at, ended_at, reason, extra) do
    EventLog.lifecycle_in_txn(
      txn,
      "memory_pressure_episode_closed",
      memory_subject(host),
      JSON.encode!(
        Map.merge(
          %{host: host, episodeOpenedAt: opened_at, endedAt: ended_at, reason: reason},
          extra
        )
      )
    )
  end

  defp cleared_fact_in_txn(txn, host) do
    if ConditionFacts.standing_in_txn?(txn, @pressure_fact, host),
      do: file_pressure_fact_in_txn(txn, @cleared_fact, host)
  end

  # M8: the reserved standing pair, scope the host name, filed by the process.
  defp file_pressure_fact_in_txn(txn, kind, host) do
    %{fact_id: _} =
      ConditionFacts.file_in_txn(txn, %{kind: kind, scope: host, origin: "process:tightbeam"})
  end

  # A fact filed here is recognized after commit exactly as a filed condition
  # is (`ConditionFacts.file/3`), so a session's own fact wait fires at once.
  defp with_pressure_fact(db, scheduler, prepare) do
    case DB.transaction_then(
           db,
           prepare,
           fn txn, {result, fact} ->
             Wakes.row_commit_in_txn(txn, [])

             deliveries =
               if fact, do: ConditionFacts.recognize_in_txn(txn, fact.fact_id), else: []

             {result, fact, deliveries}
           end,
           fallback: fn {result, fact} -> {result, fact, []} end,
           retry_deliveries: true
         ) do
      {:ok, {result, fact, deliveries}} ->
        ConditionFacts.complete_deliveries(db, scheduler, deliveries)
        if fact, do: Wakes.nudge_matching(scheduler, fact.fact_id)
        result

      {:error, error} ->
        raise error
    end
  end

  defp memory_dedupe_key(host, opened_at), do: "memory-pressure:#{host}:#{opened_at}"
  defp memory_subject(host), do: "memory-pressure:#{host}"

  @doc false
  def memory_title(host), do: "#{host} is running low on memory"

  @doc false
  def memory_restart_title(host), do: "#{host}: Tightbeam restarted during memory pressure"

  @doc false
  def memory_body(open) do
    Enum.join(
      [
        "Since #{format_local(open.episode_opened_at)}, #{open.host} has had " <>
          "#{memory_text(open.sample)}.",
        stalled_text(open.sample)
      ] ++ population_text(open.populations) ++ [@memory_closing],
      " "
    )
  end

  @doc false
  def memory_restart_body(%{unknown?: true} = run) do
    Enum.join(
      [
        "Tightbeam restarted on #{run.host} while memory pressure was ongoing.",
        "Its record of this pressure could not be read, so when it began and how severe " <>
          "it was are unknown.",
        @memory_closing
      ],
      " "
    )
  end

  # A run that ended unopened inside the R4 window: the spike is over, so the
  # alert says so instead of calling the pressure ongoing.
  def memory_restart_body(%{run_ended_at: ended_at, episode_opened_at: nil} = run)
      when is_integer(ended_at) do
    Enum.join(
      [
        "Tightbeam restarted on #{run.host} shortly after a brief memory-pressure spike that " <>
          "began at #{format_local(run.run_started_at)} and ended at " <>
          "#{format_local(ended_at)}, before an alert was due."
      ] ++ last_sample_text(run) ++ [@memory_closing],
      " "
    )
  end

  def memory_restart_body(run) do
    opened =
      case run.episode_opened_at do
        nil -> "The episode had not yet opened."
        at -> "The episode opened at #{format_local(at)}."
      end

    first =
      case run.first_alert do
        :sent ->
          ["The first alert for this episode was sent."]

        :not_sent ->
          ["The first alert for this episode was not sent."]

        :unconfirmed ->
          [
            "Harklight never confirmed the first alert for this episode, so it may not have reached you."
          ]

        nil ->
          []
      end

    Enum.join(
      [
        "Tightbeam restarted on #{run.host} while memory pressure was ongoing.",
        "The pressure began at #{format_local(run.run_started_at)}.",
        opened
      ] ++ last_sample_text(run) ++ first ++ [@memory_closing],
      " "
    )
  end

  defp last_sample_text(run) do
    case {run.last_sample_at, run.last_sample} do
      {at, %{} = sample} when is_integer(at) ->
        [
          "The last kept sample, at #{format_local(at)}, showed #{memory_text(sample)}.",
          stalled_text(sample)
        ]

      _ ->
        []
    end
  end

  defp memory_text(sample) do
    total = sample["memTotalKiB"]
    available = sample["memAvailableKiB"]
    swap_total = sample["swapTotalKiB"]
    swap_used = swap_total - sample["swapFreeKiB"]

    "#{gib(available, @gib_kib)} GiB of #{gib(total, @gib_kib)} GiB free " <>
      "(#{round(available * 100 / total)}%), with swap #{gib(swap_used, @gib_kib)} of " <>
      "#{gib(swap_total, @gib_kib)} GiB used"
  end

  defp stalled_text(%{"someAvg10" => avg10, "someAvg60" => avg60})
       when is_number(avg10) and is_number(avg60) do
    "Programs were stalled waiting for memory #{round(avg10)}% of the last 10 seconds " <>
      "and #{round(avg60)}% of the last minute."
  end

  defp stalled_text(_sample),
    do: "This host does not report how long programs were stalled waiting for memory."

  # M9: memory by population, from cgroup v2 only; omitted without it.
  defp population_text(%{"populations" => [_ | _] = populations, "swapAccounted" => swap?}) do
    listed =
      Enum.map_join(populations, ", ", fn [label, bytes] ->
        "#{label} #{gib(bytes, @gib_bytes)} GiB"
      end)

    swap =
      if swap?,
        do: "",
        else: " These figures are memory only, because this host does not account swap per group."

    ["Using memory: #{listed}." <> swap]
  end

  defp population_text(_populations), do: []

  defp gib(amount, unit), do: :erlang.float_to_binary(amount / unit, decimals: 1)

  ## Shared record

  defp create_in_txn(txn, input) do
    now = Map.get_lazy(input, :now, fn -> System.system_time(:millisecond) end)
    alert_id = "oal_" <> Id.uuid4()

    Txn.q(
      txn,
      """
      INSERT INTO owner_alerts
        (alertId, kind, dedupeKey, ownerUserId, originSessionKey, sessionKey, turnSeq,
         workItemId, anchorAt, title, body, state, createdAt, updatedAt, nextAttemptAt)
      VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, 'pending', ?12, ?12, ?12)
      ON CONFLICT(dedupeKey) WHERE #{@holds_key} DO NOTHING
      """,
      [
        alert_id,
        input.kind,
        input.dedupe_key,
        input.owner,
        Org.personal_session_key(input.owner),
        Map.get(input, :session_key),
        Map.get(input, :turn_seq),
        Map.get(input, :work_item_id),
        Map.get(input, :anchor_at),
        input.title,
        input.body,
        now
      ]
    )

    if Txn.changes(txn) == 1 do
      lifecycle_in_txn(
        txn,
        "owner_alert_created",
        alert_id,
        input.kind,
        "pending",
        Map.merge(%{dedupeKey: input.dedupe_key}, Map.get(input, :lifecycle, %{}))
      )

      Txn.handoff(txn, __MODULE__, :due)
      {:created, alert_id}
    else
      :exists
    end
  end

  defp lifecycle_in_txn(txn, event, alert_id, kind, state, extra) do
    EventLog.lifecycle_in_txn(
      txn,
      event,
      alert_id,
      JSON.encode!(Map.merge(%{alertId: alert_id, kind: kind, state: state}, extra))
    )
  end

  ## Delivery

  @doc """
  Attempt every pending alert due at `now`. Options: `:now` (milliseconds,
  default the system clock) and `:runner` (the Harklight Agent runner hook).
  Returns the number of alerts whose attempt raised.
  """
  @spec deliver_due(DB.server(), keyword()) :: non_neg_integer()
  def deliver_due(db \\ DB, opts \\ []) do
    now = Keyword.get_lazy(opts, :now, fn -> System.system_time(:millisecond) end)
    adopt_late_commits(db, now)

    {:ok, rows} =
      DB.query(
        db,
        """
        SELECT alertId FROM owner_alerts
        WHERE state='pending' AND nextAttemptAt<=?1
        ORDER BY nextAttemptAt, createdAt, alertId
        """,
        [now]
      )

    Enum.count(rows, fn [alert_id] ->
      try do
        attempt(db, alert_id, now, opts)
        false
      rescue
        error ->
          Logger.error("owner alert #{alert_id} attempt failed: #{Exception.message(error)}")
          true
      end
    end)
  end

  # A3: the alert follows its operation row. An alert that became undelivered
  # while its last send was uncertain adopts a later definite commit (boot
  # recovery settles pending sends on its own), so the two never disagree.
  defp adopt_late_commits(db, now) do
    {:ok, rows} =
      DB.query(
        db,
        """
        SELECT a.alertId, a.kind, a.opId, s.messageId FROM owner_alerts a
        JOIN harklight_send_operations s ON s.opId=a.opId
        WHERE a.state='undelivered' AND s.state='bound'
        """
      )

    Enum.each(rows, fn [alert_id, kind, op_id, message_id] ->
      {:ok, _} =
        DB.transaction(db, fn txn ->
          Txn.q(
            txn,
            """
            UPDATE owner_alerts SET state='sent', messageId=?2, updatedAt=?3
            WHERE alertId=?1 AND state='undelivered'
            """,
            [alert_id, message_id, now]
          )

          if Txn.changes(txn) == 1 do
            lifecycle_in_txn(txn, "owner_alert_sent", alert_id, kind, "sent", %{
              opId: op_id,
              messageId: message_id,
              afterUndelivered: true
            })
          end
        end)
    end)
  end

  defp attempt(db, alert_id, now, opts) do
    case load(db, alert_id) do
      %{state: "pending", next_attempt_at: due} = alert when due <= now ->
        case operation(db, alert.op_id) do
          {:committed, message_id} ->
            finish_sent(db, alert, message_id)

          op when now >= alert.created_at + @window_ms ->
            finish_undelivered(db, alert, op, now)

          {:uncertain, message_id} ->
            settle(db, alert, message_id, now, opts)

          _definite_or_none ->
            send_new(db, alert, now, opts)
        end

      _ ->
        :ok
    end
  end

  defp load(db, alert_id) do
    {:ok, rows} =
      DB.query(
        db,
        """
        SELECT alertId, kind, originSessionKey, title, body, state, createdAt, opId,
               attempts, firstFailureAt, lastOutcome, lastFailureReason, nextAttemptAt,
               ownerUserId, workItemId, anchorAt
        FROM owner_alerts WHERE alertId=?1
        """,
        [alert_id]
      )

    case rows do
      [
        [
          id,
          kind,
          origin,
          title,
          body,
          state,
          created_at,
          op_id,
          attempts,
          first_failure_at,
          last_outcome,
          last_reason,
          next_attempt_at,
          owner,
          work_item_id,
          anchor_at
        ]
      ] ->
        %{
          alert_id: id,
          kind: kind,
          origin: origin,
          title: title,
          body: body,
          state: state,
          created_at: created_at,
          op_id: op_id,
          attempts: attempts,
          first_failure_at: first_failure_at,
          last_outcome: last_outcome,
          last_reason: last_reason,
          next_attempt_at: next_attempt_at,
          owner: owner,
          work_item_id: work_item_id,
          anchor_at: anchor_at
        }

      [] ->
        nil
    end
  end

  # The alert follows its operation row. An operation never executed or
  # refused delivered nothing, so a new one cannot duplicate; one that was
  # executed without a definite answer is settled by its own op id only.
  defp operation(_db, nil), do: :none

  defp operation(db, op_id) do
    {:ok, rows} =
      DB.query(
        db,
        """
        SELECT s.state, s.attemptedAt, s.messageId, s.payload, r.outcome
        FROM harklight_send_operations s
        LEFT JOIN harklight_command_results r ON r.opId=s.opId
        WHERE s.opId=?1
        """,
        [op_id]
      )

    case rows do
      [] ->
        :none

      [[_state, _attempted, _message, _payload, "refused"]] ->
        :refused

      [["bound", _attempted, message_id, _payload, _outcome]] ->
        {:committed, message_id}

      [["pending", nil, _message, _payload, _outcome]] ->
        :unexecuted

      [["pending", _attempted, _message, payload, _outcome]] ->
        {:uncertain, get_in(JSON.decode!(payload), ["request", "message", "message_id"])}
    end
  end

  defp origin_call(alert, params) do
    %{
      session_key: alert.origin,
      principal: {:session, alert.origin},
      transport_session_key: alert.origin,
      params: params
    }
  end

  defp send_new(db, alert, now, opts) do
    op_id = Id.uuid4()

    # The op id is recorded before anything runs, so a crash at any later
    # point leaves the alert bound to the one operation that may have run.
    # §7.1 C2-off and A7: the owner setting, and a stall alert's stall, are
    # re-evaluated in this same transaction, which records either this attempt
    # or the alert's withdrawal.
    {:ok, decision} =
      DB.transaction(db, fn txn ->
        case withdrawal_in_txn(txn, alert) do
          nil ->
            Txn.q(
              txn,
              """
              UPDATE owner_alerts SET opId=?2, attempts=attempts+1, updatedAt=?3
              WHERE alertId=?1 AND state='pending'
              """,
              [alert.alert_id, op_id, now]
            )

            if Txn.changes(txn) == 1, do: :send, else: raise("owner alert is no longer pending")

          withdrawal ->
            withdraw_in_txn(txn, alert, withdrawal, now)
            :withdrawn
        end
      end)

    if decision == :send, do: send_op(db, alert, op_id, now, opts), else: :ok
  end

  # §7.1 C2-off: a new operation is minted only while the setting still names
  # the owner this alert recorded at creation. Unset, or naming no user, is
  # off; naming another user is a changed owner. Either way the alert is
  # withdrawn, never re-addressed: every attempt's origin is the recorded
  # owner's Main. The withdrawal is recorded as `off` with its fine-grained
  # reason (A2), so the alert's key is free for the next trigger (C3-on).
  # While the owner is current, a stall alert is withdrawn as `stale` if its
  # stall is stale (A7); that row still holds its key.
  defp withdrawal_in_txn(txn, alert) do
    case owner_in_txn(txn) do
      nil -> {"off", "alerts-off"}
      owner when owner == alert.owner -> stale_withdrawal_in_txn(txn, alert)
      _other -> {"off", "owner-changed"}
    end
  end

  defp withdraw_in_txn(txn, alert, {withdrawn_as, reason}, now) do
    Txn.q(
      txn,
      """
      UPDATE owner_alerts SET state='withdrawn', withdrawnAs=?3, nextAttemptAt=NULL, updatedAt=?2
      WHERE alertId=?1 AND state='pending'
      """,
      [alert.alert_id, now, withdrawn_as]
    )

    if Txn.changes(txn) != 1, do: raise("owner alert is no longer pending")

    subject =
      if alert.kind == "stall",
        do: %{workItemId: alert.work_item_id, anchorAt: alert.anchor_at},
        else: %{}

    lifecycle_in_txn(
      txn,
      "owner_alert_withdrawn",
      alert.alert_id,
      alert.kind,
      "withdrawn",
      Map.merge(subject, %{reason: reason, withdrawnAs: withdrawn_as})
    )
  end

  defp send_op(db, alert, op_id, now, opts) do
    result =
      HarklightSend.send_request(
        db,
        origin_call(alert, %{
          harklight_session: "new",
          sender_id: @sender_id,
          title: alert.title,
          body: alert.body,
          message_type: "fyi",
          message_kind: "blocker",
          importance: "high"
        }),
        runner: Keyword.get(opts, :runner),
        op_id: op_id
      )

    record_outcome(db, %{alert | op_id: op_id}, result, now)
  end

  defp settle(db, alert, message_id, now, opts) do
    {:ok, :ok} =
      DB.transaction(db, fn txn ->
        Txn.q(
          txn,
          "UPDATE owner_alerts SET attempts=attempts+1, updatedAt=?2 WHERE alertId=?1 AND state='pending'",
          [alert.alert_id, now]
        )

        if Txn.changes(txn) == 1, do: :ok, else: raise("owner alert is no longer pending")
      end)

    result =
      HarklightSend.settle(db, origin_call(alert, %{message_id: message_id}),
        runner: Keyword.get(opts, :runner)
      )

    record_outcome(db, alert, result, now)
  end

  defp record_outcome(db, alert, result, now) do
    case operation(db, alert.op_id) do
      {:committed, message_id} ->
        finish_sent(db, alert, message_id)

      op ->
        outcome = if match?({:uncertain, _}, op), do: "outcome_unknown", else: "failed"
        finish_failed(db, alert, outcome, failure_reason(result), now)
    end
  end

  defp failure_reason(result) when is_map(result) do
    code = result[:code]
    reason = result[:reason]

    cond do
      is_binary(code) and is_binary(reason) -> "#{code}: #{reason}"
      is_binary(reason) -> reason
      is_binary(code) -> code
      true -> inspect(result, limit: 20)
    end
  end

  defp failure_reason(result), do: inspect(result, limit: 20)

  defp finish_sent(db, alert, message_id) do
    {:ok, _} =
      DB.transaction(db, fn txn ->
        Txn.q(
          txn,
          """
          UPDATE owner_alerts
          SET state='sent', messageId=?2, nextAttemptAt=NULL, updatedAt=?3
          WHERE alertId=?1 AND state='pending'
          """,
          [alert.alert_id, message_id, System.system_time(:millisecond)]
        )

        if Txn.changes(txn) == 1 do
          lifecycle_in_txn(txn, "owner_alert_sent", alert.alert_id, alert.kind, "sent", %{
            opId: alert.op_id,
            messageId: message_id
          })
        end
      end)

    :ok
  end

  defp finish_failed(db, alert, outcome, reason, now) do
    first_failure_at = alert.first_failure_at || now
    next_at = next_attempt_at(first_failure_at, now, alert.created_at)

    {:ok, plan} =
      DB.transaction(db, fn txn ->
        Txn.q(
          txn,
          """
          UPDATE owner_alerts
          SET firstFailureAt=?2, lastOutcome=?3, lastFailureReason=?4, nextAttemptAt=?5,
              updatedAt=?6
          WHERE alertId=?1 AND state='pending'
          """,
          [alert.alert_id, first_failure_at, outcome, reason, next_at, now]
        )

        # A6: one marker on the first failed or uncertain attempt.
        if Txn.changes(txn) == 1 and is_nil(alert.first_failure_at) do
          marker_in_txn(
            txn,
            alert,
            "owner_alert_delivery_failed",
            "pending",
            failed_marker(alert, outcome, reason, next_at),
            %{outcome: outcome, reason: reason, nextAttemptAt: next_at}
          )
        else
          []
        end
      end)

    EventLog.publish(plan)
    :ok
  end

  defp finish_undelivered(db, alert, op, now) do
    uncertain? = match?({:uncertain, _}, op)

    {:ok, plan} =
      DB.transaction(db, fn txn ->
        Txn.q(
          txn,
          """
          UPDATE owner_alerts SET state='undelivered', nextAttemptAt=NULL, updatedAt=?2
          WHERE alertId=?1 AND state='pending'
          """,
          [alert.alert_id, now]
        )

        if Txn.changes(txn) == 1 do
          marker_in_txn(
            txn,
            alert,
            "owner_alert_undelivered",
            "undelivered",
            undelivered_marker(alert, uncertain?),
            %{deliveryUnknown: uncertain?, lastReason: alert.last_reason}
          )
        else
          []
        end
      end)

    EventLog.publish(plan)
    :ok
  end

  # The marker's notice also records the lifecycle event naming the alert.
  defp marker_in_txn(txn, alert, event, state, message, extra) do
    EventLog.notice_in_txn(
      txn,
      event,
      alert.alert_id,
      JSON.encode!(Map.merge(%{alertId: alert.alert_id, kind: alert.kind, state: state}, extra)),
      audience: {:session, alert.origin},
      message: message,
      attention: :high
    )
  end

  defp failed_marker(alert, "outcome_unknown", reason, next_at) do
    "Harklight did not confirm delivery of an owner alert, so it may not have reached you. " <>
      "Tightbeam is settling the same send and is still retrying; next check #{format_local(next_at)}. " <>
      "Reason: #{reason}\n\n#{alert.title}\n#{alert.body}"
  end

  defp failed_marker(alert, _outcome, reason, next_at) do
    "Harklight delivery of an owner alert failed. Tightbeam is still retrying; " <>
      "next attempt #{format_local(next_at)}. Reason: #{reason}\n\n#{alert.title}\n#{alert.body}"
  end

  defp undelivered_marker(alert, true) do
    "Harklight delivery of an owner alert is unknown after 24 hours: Harklight never confirmed " <>
      "the send, so it may or may not have reached you. Tightbeam stopped retrying. " <>
      "Last reason: #{alert.last_reason}\n\n#{alert.title}\n#{alert.body}"
  end

  defp undelivered_marker(alert, false) do
    "Harklight delivery of an owner alert failed for 24 hours; the alert is undelivered and " <>
      "Tightbeam stopped retrying. Last reason: #{alert.last_reason}\n\n#{alert.title}\n#{alert.body}"
  end

  @doc """
  The next attempt after a failure at `now`: 5, 15 and 60 minutes after the
  first failure, then hourly, never later than 24 hours after creation, when
  the alert becomes undelivered.
  """
  @spec next_attempt_at(integer(), integer(), integer()) :: integer()
  def next_attempt_at(first_failure_at, now, created_at) do
    elapsed = now - first_failure_at

    next =
      case Enum.find(@retry_offsets_ms, &(&1 > elapsed)) do
        nil -> first_failure_at + (div(elapsed, @hour_ms) + 1) * @hour_ms
        offset -> first_failure_at + offset
      end

    min(next, created_at + @window_ms)
  end

  ## Process: one timer for the earliest due time

  def start_link(opts),
    do: GenServer.start_link(__MODULE__, opts, name: Keyword.get(opts, :name, __MODULE__))

  @impl true
  def init(opts) do
    # `await_memory_pressure: true` (set where the G1 sampler runs): no pass
    # runs until the sampler has recorded its boot. A restart (M6) withdraws
    # an episode's unsent first alert, and every pass delivers whatever is
    # due, so until then no pass may run, whatever asks for one.
    # The gate is bounded: whichever comes first, the sampler's signal or
    # the bound, lifts it. `:gate_clock` (monotonic milliseconds) and
    # `:memory_pressure_gate_ms` are the test seams.
    gated? = Keyword.get(opts, :await_memory_pressure, false)

    gate =
      if gated? do
        sampler =
          Keyword.get_lazy(opts, :memory_pressure, fn ->
            __MODULE__.MemoryPressure.names().sampler
          end)

        GenServer.cast(sampler, {:notify_ready, self()})
        clock = Keyword.get(opts, :gate_clock, fn -> System.monotonic_time(:millisecond) end)
        bound_ms = Keyword.get(opts, :memory_pressure_gate_ms, @memory_pressure_gate_ms)
        Process.send_after(self(), :memory_pressure_gate_check, bound_ms)
        %{clock: clock, started_at: clock.(), bound_ms: bound_ms}
      else
        # The boot pass finds every stall that came due while the gateway was
        # down (S7) and every pending delivery, from the tables alone.
        send(self(), {:pass, :boot})
        nil
      end

    {:ok,
     %{
       db: Keyword.get(opts, :db, DB),
       runner: Keyword.get(opts, :send_runner),
       timer: nil,
       last_pass_at: nil,
       ready?: not gated?,
       gate: gate
     }}
  end

  @impl true
  # Before the signal, the boot pass that follows it covers every event: it
  # works from the tables alone.
  def handle_cast(message, %{ready?: false} = state)
      when message in [:due, :stall_inputs],
      do: {:noreply, state}

  def handle_cast(:memory_pressure_ready, %{ready?: false} = state),
    do: {:noreply, run(%{state | ready?: true}, :boot)}

  def handle_cast(:memory_pressure_ready, state), do: {:noreply, state}
  def handle_cast(:due, state), do: {:noreply, run(state, :event)}
  def handle_cast(:stall_inputs, state), do: {:noreply, run(state, :inputs)}

  @impl true
  def handle_info({:pass, _reason}, %{ready?: false} = state), do: {:noreply, state}
  def handle_info({:pass, reason}, state), do: {:noreply, run(state, reason)}

  def handle_info(:memory_pressure_gate_check, %{ready?: false, gate: gate} = state) do
    elapsed = gate.clock.() - gate.started_at

    if elapsed >= gate.bound_ms do
      {:noreply, run(lift_unrecorded(state, elapsed), :boot)}
    else
      Process.send_after(self(), :memory_pressure_gate_check, max(gate.bound_ms - elapsed, 1_000))
      {:noreply, state}
    end
  end

  # The signal came first, or the gate is already lifted.
  def handle_info(:memory_pressure_gate_check, state), do: {:noreply, state}

  # The bound lifted the gate before the sampler recorded its boot. Delivery
  # resumes without M6, so an episode's first alert that a restart alert
  # would supersede may be sent; the sampler records M6 when its boot
  # succeeds. Its late signal then changes nothing.
  defp lift_unrecorded(state, elapsed) do
    Logger.warning(
      "owner alerts resumed delivery after #{elapsed} ms without the memory-pressure " <>
        "restart check (M6) recorded; a superseded memory alert may be sent"
    )

    try do
      EventLog.lifecycle(
        state.db,
        "memory_pressure_restart_unrecorded",
        "owner-alerts",
        JSON.encode!(%{boundMs: state.gate.bound_ms, waitedMs: elapsed})
      )
    rescue
      error ->
        Logger.warning(
          "memory_pressure_restart_unrecorded was not recorded: #{Exception.message(error)}"
        )
    catch
      kind, reason ->
        Logger.warning(
          "memory_pressure_restart_unrecorded was not recorded: #{inspect({kind, reason})}"
        )
    end

    %{state | ready?: true}
  end

  defp run(state, reason) do
    if state.timer, do: Process.cancel_timer(state.timer)
    now = System.system_time(:millisecond)

    # A stall that came due before the previous pass and is found only now was
    # missed by the event path. The boot pass and a pass for a changed input
    # find long-due stalls by design, so neither counts misses.
    missed_before = if reason in [:boot, :inputs], do: nil, else: state.last_pass_at

    try do
      stalls =
        DB.background_pass(
          fn -> detect_stalls(state.db, now: now, missed_before: missed_before) end,
          :deferred
        )

      {stall_dues, last_pass_at, stall_errors} =
        case stalls do
          :deferred ->
            {[now + @repair_delay_ms], state.last_pass_at, 0}

          %{owner: nil} ->
            {[], now, 0}

          %{} ->
            horizon = stalls.stall_ms |> min(@horizon_ms) |> max(@min_horizon_ms)
            {[stalls.next_at, now + horizon], now, stalls.errors}
        end

      errors = deliver_due(state.db, runner: state.runner)

      %{
        state
        | timer: arm(state.db, stall_dues, errors + stall_errors > 0),
          last_pass_at: last_pass_at
      }
    rescue
      error ->
        Logger.error("owner alert pass failed: #{Exception.message(error)}")
        %{state | timer: Process.send_after(self(), {:pass, :timer}, @repair_delay_ms)}
    end
  end

  defp arm(db, stall_dues, repair?) do
    {:ok, [[delivery_due]]} =
      DB.query(db, "SELECT MIN(nextAttemptAt) FROM owner_alerts WHERE state='pending'")

    case Enum.filter([delivery_due | stall_dues], &is_integer/1) do
      [] ->
        nil

      dues ->
        delay = max(Enum.min(dues) - System.system_time(:millisecond), 0)
        delay = if repair?, do: max(delay, @repair_delay_ms), else: delay
        Process.send_after(self(), {:pass, :timer}, delay)
    end
  end
end

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
  process keeps one timer for the earliest pending row, so a restart resumes
  from the table and nothing is polled.

  An uncertain send is settled through its own operation, never resent. A
  definite failure is retried with a new operation 5, 15 and 60 minutes after
  the first failure and then hourly, until 24 hours after creation, when the
  alert becomes `undelivered`. The alert follows its operation row, so a
  settlement made by boot recovery is adopted rather than repeated.

  Each row records its owner at creation. Before any new operation, the owner
  setting is read again in the transaction that records the attempt: if it is
  cleared, names no user, or names a different user, the alert is withdrawn
  as `off` instead of sent. An uncertain send is still settled on its own
  operation.

  Nothing here creates, queues or changes a turn or a wake of any session. The
  only session records touched are the origin transcript markers for a failed
  delivery and the lifecycle events of each state change.
  """

  use GenServer
  require Logger

  alias Tightbeam.{DB, EventLog, HarklightSend, Id, Org}
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

  # A2: a row withdrawn as `off` (§7.1 C2-off) never reached the owner, so it
  # does not hold its dedupeKey (C3-on). This one predicate is the partial
  # unique index's, the creation upsert's conflict target's, and every
  # existence check's, so they cannot disagree.
  @holds_key "NOT (state = 'withdrawn' AND withdrawnAs = 'off')"

  @owner_alerts_table_ddl """
  CREATE TABLE owner_alerts (
    alertId           TEXT PRIMARY KEY,
    kind              TEXT NOT NULL CHECK (kind IN ('usage-limit','stall','model-fallback')),
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
  a user turns alerts off rather than addressing nobody.
  """
  @spec owner_in_txn(Txn.t()) :: String.t() | nil
  def owner_in_txn(%Txn{} = txn) do
    case Txn.q(txn, "SELECT value FROM org_settings WHERE key=?1", [@owner_setting]) do
      [[user_id]] when is_binary(user_id) and user_id != "" ->
        if user_exists_in_txn?(txn, user_id), do: user_id, else: nil

      _ ->
        nil
    end
  end

  @doc "The stall threshold in milliseconds (§7 default 4 hours)."
  @spec stall_ms(DB.server()) :: pos_integer()
  def stall_ms(db \\ DB), do: parse_stall_ms(Org.get_setting(db, @stall_setting))

  defp parse_stall_ms(nil), do: @default_stall_ms
  defp parse_stall_ms(value), do: String.to_integer(value)

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

  def validate_setting_in_txn(txn, @owner_setting, user_id) do
    if is_binary(user_id) and user_id != "" and user_exists_in_txn?(txn, user_id) do
      {:ok, user_id}
    else
      {:error, "unknown_owner_alerts_user",
       "owner-alerts-user must name an existing user; no user #{inspect(user_id)}"}
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
      first_seq = episode_first_seq_in_txn(txn, session_key, turn.seq)
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

  # A session's limit episode runs from its first usage-limit failure to its
  # next delivered turn. Its first failure is the earliest rate-limit-dead
  # failure after the session's latest delivered turn. A session's lane runs
  # one turn at a time and claims the lowest queued seq, so seq order is the
  # order its turns ended.
  defp episode_first_seq_in_txn(txn, session_key, seq) do
    delivered =
      case Txn.q(
             txn,
             """
             SELECT seq FROM turns WHERE sessionKey=?1 AND status='delivered'
             ORDER BY seq DESC LIMIT 1
             """,
             [session_key]
           ) do
        [[delivered]] -> delivered
        [] -> 0
      end

    case Txn.q(
           txn,
           """
           SELECT t.seq FROM turns t
           JOIN harness_health_observations o
             ON o.correlationId = 'harness-turn:' || t.seq || ':rate-limit-dead'
           WHERE t.sessionKey=?1 AND t.seq>?2 AND t.status IN ('failed','failed_unknown')
           ORDER BY t.seq LIMIT 1
           """,
           [session_key, delivered]
         ) do
      [[first]] -> first
      [] -> seq
    end
  end

  # The Claude reset Tightbeam parsed from this failure is the due time of
  # its rate-limit-reset wake. No other provider reset is parsed on this line.
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

  ## Shared record

  defp create_in_txn(txn, input) do
    now = System.system_time(:millisecond)
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
      lifecycle_in_txn(txn, "owner_alert_created", alert_id, input.kind, "pending", %{
        dedupeKey: input.dedupe_key
      })

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
               ownerUserId
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
          owner
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
          owner: owner
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
    # §7.1 C2-off: the owner setting is re-read in this same transaction,
    # which records either this attempt or the alert's withdrawal.
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
  defp withdrawal_in_txn(txn, alert) do
    case owner_in_txn(txn) do
      nil -> {"off", "alerts-off"}
      owner when owner == alert.owner -> nil
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

    lifecycle_in_txn(txn, "owner_alert_withdrawn", alert.alert_id, alert.kind, "withdrawn", %{
      reason: reason,
      withdrawnAs: withdrawn_as
    })
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

  ## Process: one timer for the earliest due alert

  def start_link(opts),
    do: GenServer.start_link(__MODULE__, opts, name: Keyword.get(opts, :name, __MODULE__))

  @impl true
  def init(opts) do
    send(self(), :due)

    {:ok,
     %{
       db: Keyword.get(opts, :db, DB),
       runner: Keyword.get(opts, :send_runner),
       timer: nil
     }}
  end

  @impl true
  def handle_cast(:due, state), do: {:noreply, run(state)}

  @impl true
  def handle_info(:due, state), do: {:noreply, run(state)}

  defp run(state) do
    if state.timer, do: Process.cancel_timer(state.timer)

    timer =
      try do
        errors = deliver_due(state.db, runner: state.runner)
        arm(state.db, errors > 0)
      rescue
        error ->
          Logger.error("owner alert delivery pass failed: #{Exception.message(error)}")
          Process.send_after(self(), :due, @repair_delay_ms)
      end

    %{state | timer: timer}
  end

  defp arm(db, repair?) do
    {:ok, [[due]]} =
      DB.query(db, "SELECT MIN(nextAttemptAt) FROM owner_alerts WHERE state='pending'")

    if is_integer(due) do
      delay = max(due - System.system_time(:millisecond), 0)
      delay = if repair?, do: max(delay, @repair_delay_ms), else: delay
      Process.send_after(self(), :due, delay)
    end
  end
end

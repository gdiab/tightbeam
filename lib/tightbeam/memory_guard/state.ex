defmodule Tightbeam.MemoryGuard.State do
  @moduledoc """
  The memory guard's current state, kept beside its `lifecycle_events`
  history so that what each sample reads is bounded by what is open now,
  never by the history (review B7). Every write here happens in the same
  transaction as the lifecycle event that records it; the events stay the
  audit trail.

  - `memory_guard_episodes`: one row per FS9 episode. An active one is found
    through a partial index of active rows, so a read costs the number of
    active episodes of the host. Its recovery, override, alert and notice
    outcomes are columns of the row.
  - `memory_guard_root_records`: one row per judged root action record, by
    digest (a primary-key lookup).
  - `memory_guard_open`: one row per open item that a sample or an admission
    looks for (a hold, a step hold, a pending re-admission, a recent
    re-admission, a stuck clock), deleted when it closes. A read costs the
    open items of its kind.
  - `memory_guard_effects`: the durable effect journal (`Tightbeam.MemoryGuard.Journal`).
  """

  alias Tightbeam.DB
  alias Tightbeam.DB.Txn

  @ddl """
  CREATE TABLE IF NOT EXISTS memory_guard_episodes (
    episodeId TEXT PRIMARY KEY,
    host      TEXT NOT NULL,
    kind      TEXT NOT NULL CHECK (kind IN ('guard','custody')),
    key       TEXT,
    active    INTEGER NOT NULL DEFAULT 1 CHECK (active IN (0,1)),
    episode   TEXT NOT NULL,
    recovery  TEXT,
    recoveryStartedAt INTEGER,
    override  TEXT,
    applied   INTEGER NOT NULL DEFAULT 0 CHECK (applied IN (0,1)),
    alert     TEXT,
    notified  INTEGER NOT NULL DEFAULT 0 CHECK (notified IN (0,1)),
    openedAt  INTEGER NOT NULL,
    endedAt   INTEGER,
    endReason TEXT
  );
  CREATE UNIQUE INDEX IF NOT EXISTS memory_guard_episodes_active
    ON memory_guard_episodes(host, kind, ifnull(key, '')) WHERE active = 1;
  CREATE INDEX IF NOT EXISTS memory_guard_episodes_active_host
    ON memory_guard_episodes(host, openedAt, episodeId) WHERE active = 1;
  CREATE TABLE IF NOT EXISTS memory_guard_root_records (
    digest    TEXT PRIMARY KEY,
    episodeId TEXT,
    action    TEXT,
    verdict   TEXT NOT NULL CHECK (verdict IN ('accepted','rejected')),
    reason    TEXT,
    judgedAt  INTEGER NOT NULL
  );
  CREATE TABLE IF NOT EXISTS memory_guard_open (
    kind       TEXT NOT NULL,
    ref        TEXT NOT NULL,
    subject    TEXT NOT NULL,
    host       TEXT,
    detail     TEXT,
    openedAt   INTEGER NOT NULL,
    -- Holds (kind 'hold'): their place in line, the other standing reason
    -- that blocks them (NULL: eligible), and their adapter key.
    orderKey   TEXT,
    blocked    TEXT,
    adapterKey TEXT,
    PRIMARY KEY (kind, ref)
  );
  CREATE INDEX IF NOT EXISTS memory_guard_open_subject ON memory_guard_open(subject, kind);
  CREATE INDEX IF NOT EXISTS memory_guard_open_host
    ON memory_guard_open(kind, host, openedAt, ref);
  CREATE INDEX IF NOT EXISTS memory_guard_open_age
    ON memory_guard_open(kind, openedAt, ref);
  CREATE INDEX IF NOT EXISTS memory_guard_holds_order
    ON memory_guard_open(host, orderKey, ref) WHERE kind = 'hold';
  CREATE INDEX IF NOT EXISTS memory_guard_holds_eligible
    ON memory_guard_open(host, orderKey, ref) WHERE kind = 'hold' AND blocked IS NULL;
  -- A quota release's blocked marks, cleared a page at a time (re-review
  -- att_5f6e6736 B1), and probed for a still-blocked hold ahead in line.
  CREATE INDEX IF NOT EXISTS memory_guard_holds_blocked
    ON memory_guard_open(adapterKey, host, orderKey, ref) WHERE kind = 'hold' AND blocked IS NOT NULL;
  -- A session's pending quota redeliveries, for a quota hook's membership
  -- check (B3); the table is the wakes' and exists before this one.
  CREATE INDEX IF NOT EXISTS memory_guard_redelivery_session
    ON health_redelivery_attempts(sessionKey)
    WHERE redeliveryTurnSeq IS NULL AND failureClass = 'rate-limit-dead';
  -- Whether a session has a queued turn or pending prompt wake from a user
  -- (R3a's class), one probe each (the tables exist before this one).
  CREATE INDEX IF NOT EXISTS memory_guard_turns_origin
    ON turns(sessionKey, origin) WHERE status IN ('queued','running');
  CREATE INDEX IF NOT EXISTS memory_guard_wakes_origin
    ON wakes(sessionKey, origin) WHERE state = 'pending' AND consumer = 'prompt';
  CREATE TABLE IF NOT EXISTS memory_guard_effects (
    effectId   TEXT PRIMARY KEY,
    kind       TEXT NOT NULL CHECK (kind IN ('override_admission','idle_close','tree_kill',
                                             'unit_remove','publish_config','publish_marker')),
    host       TEXT NOT NULL,
    subject    TEXT,
    phase      TEXT NOT NULL CHECK (phase IN ('intended','dispatched','done')),
    intent     TEXT NOT NULL,
    dispatch   TEXT,
    outcome    TEXT,
    createdAt  INTEGER NOT NULL,
    resolvedAt INTEGER
  );
  CREATE INDEX IF NOT EXISTS memory_guard_effects_open
    ON memory_guard_effects(host, kind, createdAt, effectId) WHERE phase != 'done';
  CREATE INDEX IF NOT EXISTS memory_guard_effects_done
    ON memory_guard_effects(resolvedAt, effectId) WHERE phase = 'done';
  """

  @doc "Create the current-state tables (additive; no stamp change)."
  # The memory guard reads the live adapter launches and a key's newest
  # launch without reading the launch history (re-review att_5f6e6736). The
  # launch table is created later in the schema pass, which runs this module
  # again after it; these follow once it exists.
  @launch_indexes """
  CREATE INDEX IF NOT EXISTS harness_processes_live ON harness_processes (launchSequence)
    WHERE state IN ('launching','running','park_requested');
  CREATE INDEX IF NOT EXISTS harness_processes_key_sequence
    ON harness_processes (adapterKey, launchSequence);
  """

  @spec ensure_schema(DB.server()) :: :ok | {:error, term()}
  def ensure_schema(db \\ DB) do
    with :ok <- DB.execute(db, @ddl) do
      case DB.query(
             db,
             "SELECT 1 FROM sqlite_master WHERE type='table' AND name='harness_processes'"
           ) do
        {:ok, [_]} -> DB.execute(db, @launch_indexes)
        {:ok, []} -> :ok
        {:error, _} = error -> error
      end
    end
  end

  @doc "Record an open item, once (`ref` identifies it within `kind`)."
  @spec open_in_txn(Txn.t(), String.t(), String.t(), String.t(), String.t() | nil, String.t()) ::
          :ok
  def open_in_txn(%Txn{} = txn, kind, ref, subject, host, detail) do
    Txn.q(
      txn,
      """
      INSERT INTO memory_guard_open (kind, ref, subject, host, detail, openedAt)
      VALUES (?1, ?2, ?3, ?4, ?5, ?6) ON CONFLICT(kind, ref) DO NOTHING
      """,
      [kind, ref, subject, host, detail, System.system_time(:millisecond)]
    )

    :ok
  end

  @doc "Close an open item."
  @spec close_in_txn(Txn.t(), String.t(), String.t()) :: :ok
  def close_in_txn(%Txn{} = txn, kind, ref) do
    Txn.q(txn, "DELETE FROM memory_guard_open WHERE kind=?1 AND ref=?2", [kind, ref])
    :ok
  end

  @doc "Close every open item of `kind` for `subject`."
  @spec close_subject_in_txn(Txn.t(), String.t(), String.t()) :: :ok
  def close_subject_in_txn(%Txn{} = txn, kind, subject) do
    Txn.q(txn, "DELETE FROM memory_guard_open WHERE subject=?1 AND kind=?2", [subject, kind])
    :ok
  end

  @doc "Whether an item of `kind` is open for `subject`."
  @spec open_for_in_txn?(Txn.t(), String.t(), String.t()) :: boolean()
  def open_for_in_txn?(%Txn{} = txn, kind, subject) do
    Txn.q(
      txn,
      "SELECT 1 FROM memory_guard_open WHERE subject=?1 AND kind=?2 LIMIT 1",
      [subject, kind]
    ) != []
  end

  @doc "Whether the item `ref` of `kind` is open."
  @spec open_in_txn?(Txn.t(), String.t(), String.t()) :: boolean()
  def open_in_txn?(%Txn{} = txn, kind, ref) do
    Txn.q(txn, "SELECT 1 FROM memory_guard_open WHERE kind=?1 AND ref=?2", [kind, ref]) != []
  end

  @doc "The item `ref` of `kind`, or nil."
  @spec get_in_txn(Txn.t(), String.t(), String.t()) :: map() | nil
  def get_in_txn(%Txn{} = txn, kind, ref) do
    txn
    |> Txn.q(
      "SELECT ref, subject, host, detail, openedAt FROM memory_guard_open WHERE kind=?1 AND ref=?2",
      [kind, ref]
    )
    |> rows()
    |> List.first()
  end

  @doc "Replace the detail of the open item `ref` of `kind` (a continuation's cursor)."
  @spec update_detail_in_txn(Txn.t(), String.t(), String.t(), String.t()) :: :ok
  def update_detail_in_txn(%Txn{} = txn, kind, ref, detail) do
    Txn.q(txn, "UPDATE memory_guard_open SET detail=?3 WHERE kind=?1 AND ref=?2", [
      kind,
      ref,
      detail
    ])

    :ok
  end

  @doc """
  The oldest open item of `kind` on `host` (index `(kind, host, openedAt,
  ref)`, one row), or nil.
  """
  @spec oldest(DB.server(), String.t(), String.t()) :: {:ok, map() | nil} | {:error, String.t()}
  def oldest(db, kind, host) do
    read(db, fn txn ->
      txn
      |> Txn.q(
        """
        SELECT ref, subject, host, detail, openedAt FROM memory_guard_open
        WHERE kind=?1 AND host=?2 ORDER BY openedAt, ref LIMIT 1
        """,
        [kind, host]
      )
      |> rows()
      |> List.first()
    end)
  end

  @doc """
  A keyset page of open items of `kind`, oldest first by `(openedAt, ref)`,
  after `cursor` and not past `high` (the cycle's high-water key), at most
  `limit`. With `host` nil it pages every host (index `(kind, openedAt, ref)`);
  with a host, that host's (index `(kind, host, openedAt, ref)`).
  """
  @spec page(
          DB.server(),
          String.t(),
          String.t() | nil,
          tuple() | nil,
          tuple() | nil,
          pos_integer()
        ) ::
          {:ok, [map()]} | {:error, String.t()}
  def page(db, kind, host, cursor, high, limit) do
    {after_at, after_ref} = cursor || {-1, ""}
    {high_at, high_ref} = high || {9_223_372_036_854_775_807, "~"}

    read(db, fn txn ->
      txn
      |> Txn.q(
        """
        SELECT ref, subject, host, detail, openedAt FROM memory_guard_open
        WHERE kind=?1 AND (?2 IS NULL OR host=?2)
          AND (openedAt, ref) > (?3, ?4) AND (openedAt, ref) <= (?5, ?6)
        ORDER BY openedAt, ref LIMIT ?7
        """
        |> host_form(host),
        [kind, host, after_at, after_ref, high_at, high_ref, limit]
      )
      |> rows()
    end)
  end

  @doc "The newest `(openedAt, ref)` of `kind` (optionally of one host), or nil."
  @spec high_water(DB.server(), String.t(), String.t() | nil) ::
          {:ok, tuple() | nil} | {:error, String.t()}
  def high_water(db, kind, host) do
    read(db, fn txn ->
      case Txn.q(
             txn,
             """
             SELECT openedAt, ref FROM memory_guard_open
             WHERE kind=?1 AND (?2 IS NULL OR host=?2)
             ORDER BY openedAt DESC, ref DESC LIMIT 1
             """
             |> host_form(host),
             [kind, host]
           ) do
        [[at, ref]] -> {at, ref}
        [] -> nil
      end
    end)
  end

  # Two sargable forms, never an optional filter: with a host the predicate
  # is `host=?2`; without one the `?2` term is dropped.
  defp host_form(sql, nil),
    do: String.replace(sql, " AND (?2 IS NULL OR host=?2)", " AND ?2 IS NULL")

  defp host_form(sql, _host), do: String.replace(sql, "(?2 IS NULL OR host=?2)", "host=?2")

  defp read(db, fun) do
    case DB.transaction(db, fun) do
      {:ok, result} -> {:ok, result}
      {:error, error} -> {:error, Exception.message(error)}
    end
  catch
    :exit, reason -> {:error, inspect(reason)}
  end

  @doc """
  Whether more than `cap` items of `kind` are open (on one host, or all):
  `:within` or `:more`, a probe capped at `cap + 1` rows.
  """
  @spec backlog(DB.server(), String.t(), String.t() | nil, pos_integer()) ::
          {:ok, :within | :more} | {:error, String.t()}
  def backlog(db, kind, host, cap \\ 256) do
    read(db, fn txn ->
      [[n]] =
        Txn.q(
          txn,
          "SELECT COUNT(*) FROM (SELECT 1 FROM memory_guard_open WHERE kind=?1 AND (?2 IS NULL OR host=?2) LIMIT ?3)"
          |> host_form(host),
          [kind, host, cap + 1]
        )

      if n > cap, do: :more, else: :within
    end)
  end

  @doc "Whether any item of `kind` is open, on any host (one index probe)."
  @spec any_in_txn?(Txn.t(), String.t()) :: boolean()
  def any_in_txn?(%Txn{} = txn, kind),
    do: Txn.q(txn, "SELECT 1 FROM memory_guard_open WHERE kind=?1 LIMIT 1", [kind]) != []

  defp rows(rows) do
    Enum.map(rows, fn [ref, subject, host, detail, opened_at] ->
      %{ref: ref, subject: subject, host: host, detail: detail, opened_at: opened_at}
    end)
  end
end

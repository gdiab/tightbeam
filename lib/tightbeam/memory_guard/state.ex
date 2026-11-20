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
    re-admission), deleted when it closes. A read costs the open items of
    its kind.
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
  CREATE TABLE IF NOT EXISTS memory_guard_root_records (
    digest    TEXT PRIMARY KEY,
    episodeId TEXT,
    action    TEXT,
    verdict   TEXT NOT NULL CHECK (verdict IN ('accepted','rejected')),
    reason    TEXT,
    judgedAt  INTEGER NOT NULL
  );
  CREATE TABLE IF NOT EXISTS memory_guard_open (
    kind     TEXT NOT NULL,
    ref      TEXT NOT NULL,
    subject  TEXT NOT NULL,
    host     TEXT,
    detail   TEXT,
    openedAt INTEGER NOT NULL,
    PRIMARY KEY (kind, ref)
  );
  CREATE INDEX IF NOT EXISTS memory_guard_open_subject ON memory_guard_open(subject, kind);
  """

  @doc "Create the current-state tables (additive; no stamp change)."
  @spec ensure_schema(DB.server()) :: :ok | {:error, term()}
  def ensure_schema(db \\ DB), do: DB.execute(db, @ddl)

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

  @doc """
  The open items of `kind` (optionally of one host), oldest first:
  `[%{ref, subject, host, detail, opened_at}]`.
  """
  @spec list_in_txn(Txn.t(), String.t(), String.t() | nil) :: [map()]
  def list_in_txn(%Txn{} = txn, kind, host \\ nil) do
    txn
    |> Txn.q(
      """
      SELECT ref, subject, host, detail, openedAt FROM memory_guard_open
      WHERE kind=?1 AND (?2 IS NULL OR host=?2) ORDER BY openedAt, ref
      """,
      [kind, host]
    )
    |> Enum.map(fn [ref, subject, host, detail, opened_at] ->
      %{ref: ref, subject: subject, host: host, detail: detail, opened_at: opened_at}
    end)
  end

  @doc "`list_in_txn/3` outside a transaction: `{:ok, items}` or `{:error, message}`."
  @spec list(DB.server(), String.t(), String.t() | nil) :: {:ok, [map()]} | {:error, String.t()}
  def list(db, kind, host \\ nil) do
    case DB.transaction(db, &list_in_txn(&1, kind, host)) do
      {:ok, items} -> {:ok, items}
      {:error, error} -> {:error, Exception.message(error)}
    end
  catch
    :exit, reason -> {:error, inspect(reason)}
  end
end

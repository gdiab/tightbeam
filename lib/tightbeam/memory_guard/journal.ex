defmodule Tightbeam.MemoryGuard.Journal do
  @moduledoc """
  The memory guard's durable effect journal (agreed design rev 2 `art_10551253`,
  as amended by revs 3–5; review agreement `att_9c403160`).

  Every obligation that must survive a restart (an effect performed outside
  the database whose record follows it, or a file published from a record)
  is one row of `memory_guard_effects`, keyed by a deterministic id:

  1. **intend**: written in the transaction of the effect's precondition (a
     closing mark, a kill intent, a mode record); if that fails, the effect is
     not performed;
  2. **dispatch** (kills and closes only): written after the call that
     proves the effect was sent returns;
  3. **complete**: one transaction writes the outcome record(s), any marker,
     and `done`;
  4. **resolve**: rows not `done` are decided from durable or observable
     evidence, on start and each sample, within a fixed budget;
  5. **prune**: `done` rows go after 24 hours, a bounded page at a time.
  """

  alias Tightbeam.DB
  alias Tightbeam.DB.Txn

  @kinds ~w(override_admission idle_close tree_kill unit_remove publish_config publish_marker)
  @retention_ms 24 * 3_600_000

  @doc "The journal's kinds, one paged stream each."
  def kinds, do: @kinds

  @doc "The deterministic id of an effect."
  @spec id(String.t(), String.t(), String.t()) :: String.t()
  def id(kind, host, identity) when kind in @kinds, do: "#{kind}:#{host}:#{identity}"

  @doc "Record an effect's intent, in the precondition's transaction. Idempotent per id."
  @spec intend_in_txn(
          Txn.t(),
          String.t(),
          String.t(),
          String.t(),
          String.t() | nil,
          map(),
          integer()
        ) ::
          String.t()
  def intend_in_txn(%Txn{} = txn, kind, identity, host, subject, intent, now)
      when kind in @kinds do
    id = id(kind, host, identity)

    Txn.q(
      txn,
      """
      INSERT INTO memory_guard_effects (effectId, kind, host, subject, phase, intent, createdAt)
      VALUES (?1, ?2, ?3, ?4, 'intended', ?5, ?6) ON CONFLICT(effectId) DO NOTHING
      """,
      [id, kind, host, subject, JSON.encode!(intent), now]
    )

    id
  end

  @doc """
  Record that the effect was sent, with the evidence that proves it. Only an
  `intended` row moves to `dispatched`. `:ok` or `{:error, message}`.
  """
  @spec dispatch(DB.server(), String.t(), map()) :: :ok | {:error, String.t()}
  def dispatch(db, id, evidence) do
    transact(db, fn txn ->
      Txn.q(
        txn,
        "UPDATE memory_guard_effects SET phase='dispatched', dispatch=?2 WHERE effectId=?1 AND phase='intended'",
        [id, JSON.encode!(evidence)]
      )
    end)
  end

  @doc """
  Complete an effect inside the caller's transaction, which also writes its
  outcome records and markers. Returns whether this call completed it (a row
  already `done` is left as it is, so a retry never records twice).
  """
  @spec complete_in_txn(Txn.t(), String.t(), map(), integer()) :: boolean()
  def complete_in_txn(%Txn{} = txn, id, outcome, now) do
    Txn.q(
      txn,
      "UPDATE memory_guard_effects SET phase='done', outcome=?2, resolvedAt=?3 WHERE effectId=?1 AND phase != 'done'",
      [id, JSON.encode!(outcome), now]
    )

    Txn.changes(txn) == 1
  end

  @doc "One effect by id, or nil."
  @spec get(DB.server() | Txn.t(), String.t()) :: map() | nil
  def get(%Txn{} = txn, id) do
    case Txn.q(
           txn,
           "SELECT effectId, kind, host, subject, phase, intent, dispatch, outcome, createdAt, resolvedAt FROM memory_guard_effects WHERE effectId=?1",
           [id]
         ) do
      [row] -> row(row)
      [] -> nil
    end
  end

  def get(db, id) do
    case DB.transaction(db, &get(&1, id)) do
      {:ok, effect} -> effect
      {:error, error} -> raise "the effect journal cannot be read: #{Exception.message(error)}"
    end
  end

  @doc """
  A page of the host's unresolved effects of one kind, oldest first, after
  `cursor` (`{createdAt, effectId}` or nil) and not past `high` (the cycle's
  high-water key, or nil for none). On index `memory_guard_effects_open
  (host, kind, createdAt, effectId)`.
  """
  @spec page(DB.server(), String.t(), String.t(), tuple() | nil, tuple() | nil, pos_integer()) ::
          {:ok, [map()]} | {:error, String.t()}
  def page(db, host, kind, cursor, high, limit) do
    {after_at, after_id} = cursor || {-1, ""}
    {high_at, high_id} = high || {9_223_372_036_854_775_807, "~"}

    read(db, fn txn ->
      txn
      |> Txn.q(
        """
        SELECT effectId, kind, host, subject, phase, intent, dispatch, outcome, createdAt, resolvedAt
        FROM memory_guard_effects
        WHERE host=?1 AND kind=?2 AND phase != 'done'
          AND (createdAt, effectId) > (?3, ?4) AND (createdAt, effectId) <= (?5, ?6)
        ORDER BY createdAt, effectId LIMIT ?7
        """,
        [host, kind, after_at, after_id, high_at, high_id, limit]
      )
      |> Enum.map(&row/1)
    end)
  end

  @doc "The newest unresolved key of a host's kind (a cycle's high-water mark), or nil."
  @spec high_water(DB.server(), String.t(), String.t()) ::
          {:ok, tuple() | nil} | {:error, String.t()}
  def high_water(db, host, kind) do
    read(db, fn txn ->
      case Txn.q(
             txn,
             """
             SELECT createdAt, effectId FROM memory_guard_effects
             WHERE host=?1 AND kind=?2 AND phase != 'done'
             ORDER BY createdAt DESC, effectId DESC LIMIT 1
             """,
             [host, kind]
           ) do
        [[at, id]] -> {at, id}
        [] -> nil
      end
    end)
  end

  @doc """
  Whether more than `cap` effects of a kind are unresolved on a host
  (`:within` or `:more`), a probe capped at `cap + 1` rows.
  """
  @spec backlog(DB.server(), String.t(), String.t(), pos_integer()) ::
          {:ok, :within | :more} | {:error, String.t()}
  def backlog(db, host, kind, cap \\ 256) do
    read(db, fn txn ->
      [[n]] =
        Txn.q(
          txn,
          """
          SELECT COUNT(*) FROM (SELECT 1 FROM memory_guard_effects
            WHERE host=?1 AND kind=?2 AND phase != 'done' LIMIT ?3)
          """,
          [host, kind, cap + 1]
        )

      if n > cap, do: :more, else: :within
    end)
  end

  @doc "Whether a host has an unresolved effect of `kind` (one index probe)."
  @spec pending_in_txn?(Txn.t(), String.t(), String.t()) :: boolean()
  def pending_in_txn?(%Txn{} = txn, host, kind) do
    Txn.q(
      txn,
      "SELECT 1 FROM memory_guard_effects WHERE host=?1 AND kind=?2 AND phase != 'done' LIMIT 1",
      [host, kind]
    ) != []
  end

  @doc "`pending_in_txn?/3` outside a transaction; raises when it cannot be read."
  @spec pending?(DB.server(), String.t(), String.t()) :: boolean()
  def pending?(db, host, kind) do
    case read(db, &pending_in_txn?(&1, host, kind)) do
      {:ok, pending?} -> pending?
      {:error, message} -> raise "the effect journal cannot be read: #{message}"
    end
  end

  @doc """
  The effects of `kind` on a host created at or after `since`, in the given
  phases, newest first, at most `limit` (for rebuilding the kill attribution
  at start).
  """
  @spec recent(DB.server(), String.t(), String.t(), integer(), pos_integer()) ::
          {:ok, [map()]} | {:error, String.t()}
  def recent(db, host, kind, since, limit) do
    read(db, fn txn ->
      txn
      |> Txn.q(
        """
        SELECT effectId, kind, host, subject, phase, intent, dispatch, outcome, createdAt, resolvedAt
        FROM memory_guard_effects
        WHERE host=?1 AND kind=?2 AND createdAt >= ?3
        ORDER BY createdAt DESC LIMIT ?4
        """,
        [host, kind, since, limit]
      )
      |> Enum.map(&row/1)
    end)
  end

  @doc """
  Delete at most `limit` `done` rows resolved more than 24 hours before
  `now`, oldest first, in one transaction (index `memory_guard_effects_done`).
  """
  @spec prune(DB.server(), integer(), pos_integer()) :: :ok | {:error, String.t()}
  def prune(db, now, limit \\ 64) do
    transact(db, fn txn ->
      Txn.q(
        txn,
        """
        DELETE FROM memory_guard_effects WHERE effectId IN (
          SELECT effectId FROM memory_guard_effects
          WHERE phase='done' AND resolvedAt < ?1
          ORDER BY resolvedAt, effectId LIMIT ?2)
        """,
        [now - @retention_ms, limit]
      )
    end)
  end

  defp row([id, kind, host, subject, phase, intent, dispatch, outcome, created_at, resolved_at]) do
    %{
      id: id,
      kind: kind,
      host: host,
      subject: subject,
      phase: phase,
      intent: JSON.decode!(intent),
      dispatch: dispatch && JSON.decode!(dispatch),
      outcome: outcome && JSON.decode!(outcome),
      created_at: created_at,
      resolved_at: resolved_at
    }
  end

  defp read(db, fun) do
    case DB.transaction(db, fun) do
      {:ok, result} -> {:ok, result}
      {:error, error} -> {:error, Exception.message(error)}
    end
  catch
    :exit, reason -> {:error, inspect(reason)}
  end

  defp transact(db, fun) do
    case DB.transaction(db, fun) do
      {:ok, _} -> :ok
      {:error, error} -> {:error, Exception.message(error)}
    end
  catch
    :exit, reason -> {:error, inspect(reason)}
  end
end

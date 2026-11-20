defmodule Tightbeam.MemoryGuard.Episodes do
  @moduledoc """
  Stuck episodes (memory limits v1.13 §6.1 FS9).

  An episode is a durable record with a unique id, opened in one database
  transaction, at most one active per (host, kind, key):

  - `guard`: launches on the host have been held `guard_unavailable` (FS1)
    for 15 minutes without a break;
  - `custody`: a replacement adapter for a key has been refused for 15
    minutes, because a recorded tree of an ended adapter is not shown gone
    (R2a, FS8).

  It ends only when its underlying condition clears (the guard answers; every
  named tree is shown gone) or at the first start on a new boot identity. An
  admission or an override never ends it.

  Records are `lifecycle_events` rows, so every transition is one database
  transaction (B4): `memory_guard_episode_opened`, `…_ended`,
  `memory_guard_recovery_accepted`, `memory_guard_recovery_outcome`,
  `memory_guard_override_accepted`, `memory_guard_override_applied`, and
  `memory_guard_root_action_rejected`. No timer, Tightbeam process or route
  ends or overrides an episode.
  """

  alias Tightbeam.{DB, EventLog}
  alias Tightbeam.DB.Txn

  @stuck_ms 15 * 60_000

  @doc "How long a condition must hold, unbroken, before an episode opens."
  def stuck_ms, do: Application.get_env(:tightbeam, :memory_guard_stuck_ms, @stuck_ms)

  @doc "The active episodes, optionally of one host: `[episode]`."
  @spec active(DB.server(), String.t() | nil) :: [map()]
  def active(db, host \\ nil) do
    case DB.query(
           db,
           """
           SELECT o.detail FROM lifecycle_events o
           WHERE o.kind='memory_guard_episode_opened'
             AND (?1 IS NULL OR json_extract(o.detail,'$.host')=?1)
             AND NOT EXISTS (
               SELECT 1 FROM lifecycle_events e
               WHERE e.kind='memory_guard_episode_ended'
                 AND json_extract(e.detail,'$.episodeId')=json_extract(o.detail,'$.episodeId'))
           ORDER BY o.id
           """,
           [host]
         ) do
      {:ok, rows} -> Enum.map(rows, fn [detail] -> decode(detail) end)
      {:error, error} -> raise "episodes cannot be read: #{inspect(error)}"
    end
  end

  @doc "One episode by id (active or ended), or nil."
  @spec get(DB.server() | Txn.t(), String.t()) :: map() | nil
  def get(%Txn{} = txn, id) do
    case Txn.q(
           txn,
           "SELECT detail FROM lifecycle_events WHERE kind='memory_guard_episode_opened' AND json_extract(detail,'$.episodeId')=?1",
           [id]
         ) do
      [[detail]] -> Map.put(decode(detail), "ended", ended_in_txn?(txn, id))
      [] -> nil
    end
  end

  def get(db, id) do
    {:ok, result} = DB.transaction(db, &get(&1, id))
    result
  end

  defp ended_in_txn?(txn, id) do
    Txn.q(
      txn,
      "SELECT 1 FROM lifecycle_events WHERE kind='memory_guard_episode_ended' AND json_extract(detail,'$.episodeId')=?1 LIMIT 1",
      [id]
    ) != []
  end

  @doc """
  Open an episode for (host, kind, key) unless one is active, in one
  transaction (N1). Returns `{:opened, episode}`, `{:active, episode}` or
  `{:error, message}`; a failed write opens nothing and is retried (FS7).
  """
  @spec open(DB.server(), map()) :: {:opened, map()} | {:active, map()} | {:error, String.t()}
  def open(db, %{host: host, kind: kind} = attrs) do
    key = Map.get(attrs, :key)

    DB.transaction(db, fn txn ->
      case active_in_txn(txn, host, kind, key) do
        nil ->
          episode = %{
            "episodeId" => "ep_" <> Base.encode16(:crypto.strong_rand_bytes(8), case: :lower),
            "host" => host,
            "kind" => kind,
            "key" => key,
            "trees" => Map.get(attrs, :trees, []),
            "since" => attrs.since,
            "openedAt" => System.system_time(:millisecond),
            "boot" => Map.get(attrs, :boot),
            # Where root's commands find this episode (FS9 Step 1, 2).
            "base" => Map.get(attrs, :base),
            "why" => Map.get(attrs, :why)
          }

          EventLog.lifecycle_in_txn(
            txn,
            "memory_guard_episode_opened",
            host,
            JSON.encode!(episode)
          )

          {:opened, episode}

        episode ->
          {:active, episode}
      end
    end)
    |> case do
      {:ok, result} -> result
      {:error, error} -> {:error, inspect(error)}
    end
  end

  defp active_in_txn(txn, host, kind, key) do
    txn
    |> Txn.q(
      """
      SELECT o.detail FROM lifecycle_events o
      WHERE o.kind='memory_guard_episode_opened'
        AND json_extract(o.detail,'$.host')=?1 AND json_extract(o.detail,'$.kind')=?2
        AND (json_extract(o.detail,'$.key') IS ?3)
        AND NOT EXISTS (
          SELECT 1 FROM lifecycle_events e
          WHERE e.kind='memory_guard_episode_ended'
            AND json_extract(e.detail,'$.episodeId')=json_extract(o.detail,'$.episodeId'))
      LIMIT 1
      """,
      [host, kind, key]
    )
    |> case do
      [[detail]] -> decode(detail)
      [] -> nil
    end
  end

  @doc """
  End an episode because its condition cleared or the host rebooted (N3);
  the end is recorded in the same transaction that marks it. `:ok`, or
  `{:error, message}` (retried).
  """
  @spec finish(DB.server(), String.t(), String.t()) :: :ok | {:error, String.t()}
  def finish(db, episode_id, reason) do
    DB.transaction(db, fn txn ->
      if ended_in_txn?(txn, episode_id) do
        :ok
      else
        EventLog.lifecycle_in_txn(
          txn,
          "memory_guard_episode_ended",
          episode_id,
          JSON.encode!(%{episodeId: episode_id, reason: reason})
        )
      end
    end)
    |> case do
      {:ok, _} -> :ok
      {:error, error} -> {:error, inspect(error)}
    end
  end

  @doc "The recovery accepted for an episode and its outcome so far, or nil."
  @spec recovery(DB.server() | Txn.t(), String.t()) :: map() | nil
  def recovery(%Txn{} = txn, episode_id) do
    accepted =
      Txn.q(
        txn,
        "SELECT detail FROM lifecycle_events WHERE kind='memory_guard_recovery_accepted' AND json_extract(detail,'$.episodeId')=?1 ORDER BY id DESC LIMIT 1",
        [episode_id]
      )

    case accepted do
      [[detail]] ->
        recovery = decode(detail)

        outcome =
          Txn.q(
            txn,
            "SELECT detail FROM lifecycle_events WHERE kind='memory_guard_recovery_outcome' AND json_extract(detail,'$.digest')=?1 LIMIT 1",
            [recovery["digest"]]
          )

        case outcome do
          [[outcome]] -> Map.merge(recovery, Map.take(decode(outcome), ["outcome", "survivors"]))
          [] -> Map.put(recovery, "outcome", "pending")
        end

      [] ->
        nil
    end
  end

  def recovery(db, episode_id) do
    {:ok, result} = DB.transaction(db, &recovery(&1, episode_id))
    result
  end

  @doc "The override accepted for an episode, and whether it was applied, or nil."
  @spec override(DB.server() | Txn.t(), String.t()) :: map() | nil
  def override(%Txn{} = txn, episode_id) do
    case Txn.q(
           txn,
           "SELECT detail FROM lifecycle_events WHERE kind='memory_guard_override_accepted' AND json_extract(detail,'$.episodeId')=?1 LIMIT 1",
           [episode_id]
         ) do
      [[detail]] ->
        applied =
          Txn.q(
            txn,
            "SELECT 1 FROM lifecycle_events WHERE kind='memory_guard_override_applied' AND json_extract(detail,'$.episodeId')=?1 LIMIT 1",
            [episode_id]
          ) != []

        Map.put(decode(detail), "applied", applied)

      [] ->
        nil
    end
  end

  def override(db, episode_id) do
    {:ok, result} = DB.transaction(db, &override(&1, episode_id))
    result
  end

  @doc """
  B4: judge one root action record (`record` is its decoded content,
  `digest` the SHA-256 of its bytes) through one atomic transition. Returns
  `{:accepted, kind}` or `{:rejected, reason}`; a rejection is recorded.
  Concurrent readers produce exactly one acceptance; a digest already judged is
  never judged again.
  """
  @spec judge(DB.server(), map(), String.t(), String.t(), map()) ::
          {:accepted, String.t()} | {:rejected, String.t()} | {:error, String.t()}
  def judge(db, record, digest, host, extra \\ %{}) do
    DB.transaction(db, fn txn -> judge_in_txn(txn, record, digest, host, extra) end)
    |> case do
      {:ok, result} -> result
      {:error, error} -> {:error, inspect(error)}
    end
  end

  defp judge_in_txn(txn, record, digest, host, extra) do
    action = record["action"]
    episode_id = record["episodeId"]
    episode = is_binary(episode_id) && get(txn, episode_id)

    reason =
      cond do
        judged_in_txn?(txn, digest) ->
          "this record was already judged"

        action not in ["recovery", "override"] ->
          "unknown action"

        episode in [nil, false] ->
          "no such episode"

        episode["ended"] ->
          "the episode has ended"

        episode["host"] != host or record["host"] != host ->
          "the episode is of another host"

        record["kind"] != episode["kind"] or record["key"] != episode["key"] ->
          "the episode is of another kind or key"

        action == "recovery" and match?(%{"outcome" => "pending"}, recovery(txn, episode_id)) ->
          "a recovery of this episode is still pending"

        action == "override" and not match?(%{"outcome" => "failed"}, recovery(txn, episode_id)) ->
          "an override needs a failed recovery of this episode first"

        action == "override" and override(txn, episode_id) != nil ->
          "an override of this episode was already accepted"

        true ->
          nil
      end

    if reason do
      EventLog.lifecycle_in_txn(
        txn,
        "memory_guard_root_action_rejected",
        host,
        JSON.encode!(%{digest: digest, episodeId: episode_id, action: action, reason: reason})
      )

      {:rejected, reason}
    else
      fields =
        record
        |> Map.merge(extra)
        |> Map.merge(%{"digest" => digest, "acceptedAt" => System.system_time(:millisecond)})

      EventLog.lifecycle_in_txn(
        txn,
        "memory_guard_#{action}_accepted",
        host,
        JSON.encode!(fields)
      )

      {:accepted, action}
    end
  end

  @doc "Reject a root action record outside the transition (for example, not root-owned), once per digest."
  @spec reject(DB.server(), String.t(), map(), String.t(), String.t()) :: :ok
  def reject(db, digest, record, host, reason) do
    DB.transaction(db, fn txn ->
      unless judged_in_txn?(txn, digest) do
        EventLog.lifecycle_in_txn(
          txn,
          "memory_guard_root_action_rejected",
          host,
          JSON.encode!(%{
            digest: digest,
            episodeId: record["episodeId"],
            action: record["action"],
            reason: reason
          })
        )
      end
    end)

    :ok
  end

  @doc "Whether a record of this digest was already judged."
  @spec judged?(DB.server(), String.t()) :: boolean()
  def judged?(db, digest) do
    {:ok, judged} = DB.transaction(db, &judged_in_txn?(&1, digest))
    judged
  end

  defp judged_in_txn?(txn, digest) do
    Txn.q(
      txn,
      """
      SELECT 1 FROM lifecycle_events
      WHERE kind IN ('memory_guard_recovery_accepted','memory_guard_override_accepted',
                     'memory_guard_root_action_rejected')
        AND json_extract(detail,'$.digest')=?1 LIMIT 1
      """,
      [digest]
    ) != []
  end

  @doc "Record a recovery's terminal outcome once (`cleared` or `failed`)."
  @spec record_outcome(DB.server(), map(), String.t(), list()) :: :ok | {:error, String.t()}
  def record_outcome(db, recovery, outcome, survivors) do
    DB.transaction(db, fn txn ->
      done =
        Txn.q(
          txn,
          "SELECT 1 FROM lifecycle_events WHERE kind='memory_guard_recovery_outcome' AND json_extract(detail,'$.digest')=?1 LIMIT 1",
          [recovery["digest"]]
        ) != []

      unless done do
        EventLog.lifecycle_in_txn(
          txn,
          "memory_guard_recovery_outcome",
          recovery["episodeId"],
          JSON.encode!(%{
            episodeId: recovery["episodeId"],
            digest: recovery["digest"],
            outcome: outcome,
            survivors: survivors,
            at: System.system_time(:millisecond)
          })
        )
      end
    end)
    |> case do
      {:ok, _} -> :ok
      {:error, error} -> {:error, inspect(error)}
    end
  end

  @doc "Record that an accepted override's effect was carried out, once."
  @spec applied(DB.server(), String.t()) :: :ok | {:error, String.t()}
  def applied(db, episode_id) do
    DB.transaction(db, fn txn ->
      case override(txn, episode_id) do
        %{"applied" => false} ->
          EventLog.lifecycle_in_txn(
            txn,
            "memory_guard_override_applied",
            episode_id,
            JSON.encode!(%{episodeId: episode_id, at: System.system_time(:millisecond)})
          )

        _ ->
          :ok
      end
    end)
    |> case do
      {:ok, _} -> :ok
      {:error, error} -> {:error, inspect(error)}
    end
  end

  @doc """
  FS9's alert and notice when an episode opens: exactly one owner alert
  (dedupe `memory-guard-stuck:<id>`) through `owner_alert`, and one notice to
  the founding user's Main, under the same key. Idempotent: what was already
  delivered is not sent again, so a caller retries until `:ok`.
  """
  @spec notify(DB.server(), map(), (map(), String.t() -> term()), keyword()) ::
          :ok | {:error, term()}
  def notify(db, episode, owner_alert, opts \\ []) do
    message = message(episode, Keyword.get(opts, :finding))
    key = "memory-guard-stuck:" <> episode["episodeId"]

    alert =
      if delivered?(db, "memory_guard_stuck_alert", key) do
        :ok
      else
        case owner_alert.(episode, message) do
          {:error, _} = error ->
            error

          result ->
            EventLog.lifecycle(
              db,
              "memory_guard_stuck_alert",
              episode["host"],
              JSON.encode!(%{markerKey: key, route: inspect(result)})
            )

            :ok
        end
      end

    notice =
      case Tightbeam.MemoryGuard.Priority.reserved_main(db) do
        %{session_key: main} when is_binary(main) ->
          main_notice(db, main, episode, key, message, opts)

        _ ->
          :ok
      end

    if alert == :ok and notice == :ok, do: :ok, else: {:error, {alert, notice}}
  rescue
    error -> {:error, Exception.message(error)}
  catch
    :exit, reason -> {:error, inspect(reason)}
  end

  # The notice and its own delivery record are one transaction, so a retry
  # never sends it twice (FS7 "at most once").
  defp main_notice(db, main, episode, key, message, opts) do
    {:ok, plan} =
      DB.transaction(db, fn txn ->
        if Txn.q(
             txn,
             "SELECT 1 FROM lifecycle_events WHERE kind='memory_guard_stuck_notified' AND json_extract(detail,'$.markerKey')=?1 LIMIT 1",
             [key]
           ) != [] do
          []
        else
          plan =
            EventLog.notice_in_txn(
              txn,
              "memory_guard_stuck",
              main,
              JSON.encode!(%{
                markerKey: key,
                episodeId: episode["episodeId"],
                host: episode["host"]
              }),
              audience: {:session, main},
              message: message,
              attention: :normal
            )

          EventLog.lifecycle_in_txn(
            txn,
            "memory_guard_stuck_notified",
            main,
            JSON.encode!(%{markerKey: key, episodeId: episode["episodeId"]})
          )

          plan
        end
      end)

    EventLog.publish(plan,
      conn_registry: Keyword.get(opts, :conn_registry, Tightbeam.ConnRegistry)
    )

    :ok
  end

  defp delivered?(db, kind, key) do
    match?(
      {:ok, [[1]]},
      DB.query(
        db,
        "SELECT 1 FROM lifecycle_events WHERE kind=?1 AND json_extract(detail,'$.markerKey')=?2 LIMIT 1",
        [kind, key]
      )
    )
  end

  @doc "The alert's plain words (FS9)."
  @spec message(map(), map() | nil) :: String.t()
  def message(episode, finding \\ nil) do
    held =
      if episode["kind"] == "guard",
        do: "new agent launches",
        else: "the replacement of the #{episode["key"]} adapter"

    path =
      case finding do
        nil ->
          ""

        finding ->
          " Root-path check now: " <> Tightbeam.MemoryGuard.RootPath.statement(finding)
      end

    "Tightbeam on #{episode["host"]} has held #{held} since " <>
      "#{DateTime.from_unix!(episode["since"], :millisecond)} because #{episode["why"]}. " <>
      "No Tightbeam command, agent or session can release it. To recover, run as root on " <>
      "#{episode["host"]}: tightbeam memory-guard-recover#{base_flag(episode)} " <>
      "#{episode["episodeId"]}. An override exists only after a recovery has failed: it " <>
      "launches anyway and accepts the risk that the held processes keep using memory outside " <>
      "every limit; tightbeam memory-guard-override#{base_flag(episode)} " <>
      "#{episode["episodeId"]} explains it before acting." <> path
  end

  defp base_flag(%{"base" => base}) when is_binary(base), do: " --base #{base}"
  defp base_flag(_episode), do: ""

  @doc """
  Publish the active episodes of `host` for the root commands
  (`<base>/run/memory-guard/episodes/<id>.json`), with the recovery and
  override state, and remove the files of ended ones.
  """
  @spec publish(DB.server(), String.t(), String.t()) :: :ok
  def publish(db, base_dir, host) do
    dir = Path.join(Tightbeam.MemoryGuard.Records.dir(base_dir), "episodes")
    File.mkdir_p(dir)
    active = active(db, host)
    ids = MapSet.new(active, & &1["episodeId"])

    for episode <- active do
      body =
        episode
        |> Map.put("recovery", recovery(db, episode["episodeId"]))
        |> Map.put("override", override(db, episode["episodeId"]))
        |> JSON.encode!()

      path = Path.join(dir, episode["episodeId"] <> ".json")
      File.write(path <> ".pending", body)
      File.rename(path <> ".pending", path)
    end

    case File.ls(dir) do
      {:ok, entries} ->
        for entry <- entries,
            String.ends_with?(entry, ".json"),
            not MapSet.member?(ids, Path.rootname(entry)),
            do: File.rm(Path.join(dir, entry))

      _ ->
        :ok
    end

    :ok
  rescue
    _ -> :ok
  end

  @doc """
  The episodes of `host` for a read (R12b, R7; matrix N10): shown, open,
  until they end, whatever is overridden, with the risk an override accepted.
  A read that cannot be completed says the state is unknown, never "none".
  """
  @spec read(DB.server(), String.t()) :: [map()] | %{unknown: String.t()}
  def read(db, host) do
    for episode <- active(db, host) do
      id = episode["episodeId"]
      recovery = recovery(db, id)
      override = override(db, id)

      %{
        episodeId: id,
        kind: episode["kind"],
        key: episode["key"],
        since: episode["since"],
        why: episode["why"],
        recovery: recovery && recovery["outcome"],
        overridden: override != nil,
        risk: override && risk(episode)
      }
    end
  rescue
    error -> %{unknown: Exception.message(error)}
  catch
    :exit, reason -> %{unknown: inspect(reason)}
  end

  defp risk(%{"kind" => "guard"}),
    do: "launches ran without the memory guard: no cap, floor or per-agent limit was checked"

  defp risk(%{"trees" => trees}),
    do:
      "#{length(trees)} agent processes that could not be stopped may keep using memory " <>
        "outside every limit until they end or the machine reboots"

  defp decode(detail), do: JSON.decode!(detail)
end

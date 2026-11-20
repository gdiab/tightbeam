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
  admission or an override never ends it. A custody episode whose trees could
  not be listed names them as unknown, and unknown is never proof: it stays
  open until the trees are known and shown gone (review B6).

  The current state is a `memory_guard_episodes` row (`Tightbeam.MemoryGuard.State`),
  so reads cost the active episodes, not the history (review B7). Every
  transition is one database transaction (B4) that also writes its
  `lifecycle_events` record: `memory_guard_episode_opened`, `…_ended`,
  `memory_guard_recovery_accepted`, `memory_guard_recovery_started`,
  `memory_guard_recovery_outcome`, `memory_guard_override_accepted`,
  `memory_guard_override_applied`, `memory_guard_root_action_rejected`,
  `memory_guard_stuck_alert` and `memory_guard_stuck_notified`. No timer,
  Tightbeam process or route ends or overrides an episode.
  """

  alias Tightbeam.{DB, EventLog}
  alias Tightbeam.DB.Txn

  @stuck_ms 15 * 60_000

  @columns "episode, active, recovery, recoveryStartedAt, override, applied, alert, notified, endedAt"

  @doc "How long a condition must hold, unbroken, before an episode opens."
  def stuck_ms, do: Application.get_env(:tightbeam, :memory_guard_stuck_ms, @stuck_ms)

  @doc """
  The active episodes, optionally of one host: `[episode]`, each with its
  `"recovery"` and `"override"` (or nil). Raises when they cannot be read:
  an unread set is not an empty one.
  """
  @spec active(DB.server() | Txn.t(), String.t() | nil) :: [map()]
  def active(db, host \\ nil)

  def active(%Txn{} = txn, host) do
    txn
    |> Txn.q(
      "SELECT #{@columns} FROM memory_guard_episodes WHERE active=1 AND (?1 IS NULL OR host=?1) ORDER BY openedAt, episodeId",
      [host]
    )
    |> Enum.map(&row/1)
  end

  def active(db, host) do
    case DB.transaction(db, &active(&1, host)) do
      {:ok, episodes} -> episodes
      {:error, error} -> raise "episodes cannot be read: #{Exception.message(error)}"
    end
  end

  @doc "One episode by id (active or ended), or nil."
  @spec get(DB.server() | Txn.t(), String.t()) :: map() | nil
  def get(%Txn{} = txn, id) do
    case Txn.q(txn, "SELECT #{@columns} FROM memory_guard_episodes WHERE episodeId=?1", [id]) do
      [row] -> row(row)
      [] -> nil
    end
  end

  def get(db, id) do
    {:ok, result} = DB.transaction(db, &get(&1, id))
    result
  end

  defp row([episode, active, recovery, started_at, override, applied, alert, notified, ended_at]) do
    recovery =
      case recovery && decode(recovery) do
        nil -> nil
        recovery -> Map.put(recovery, "startedAt", started_at)
      end

    override = override && Map.put(decode(override), "applied", applied == 1)

    episode
    |> decode()
    |> Map.merge(%{
      "ended" => active == 0,
      "endedAt" => ended_at,
      "recovery" => recovery,
      "override" => override,
      "alert" => alert && decode(alert),
      "notified" => notified == 1
    })
  end

  @doc """
  Open an episode for (host, kind, key) unless one is active, in one
  transaction (N1). Returns `{:opened, episode}`, `{:active, episode}` or
  `{:error, message}`; a failed write opens nothing and is retried (FS7).
  A custody episode's `:trees` may be `:unknown` with `:trees_unknown` saying
  why; it is never read as an empty set.
  """
  @spec open(DB.server(), map()) :: {:opened, map()} | {:active, map()} | {:error, String.t()}
  def open(db, %{host: host, kind: kind} = attrs) do
    key = Map.get(attrs, :key)

    DB.transaction(db, fn txn ->
      case active_in_txn(txn, host, kind, key) do
        nil ->
          now = System.system_time(:millisecond)

          {trees, unknown} =
            case Map.get(attrs, :trees, []) do
              :unknown -> {nil, Map.get(attrs, :trees_unknown, "unknown")}
              trees -> {trees, nil}
            end

          episode = %{
            "episodeId" => "ep_" <> Base.encode16(:crypto.strong_rand_bytes(8), case: :lower),
            "host" => host,
            "kind" => kind,
            "key" => key,
            "trees" => trees,
            "treesUnknown" => unknown,
            "since" => attrs.since,
            "openedAt" => now,
            "boot" => Map.get(attrs, :boot),
            # Where root's commands find this episode (FS9 Step 1, 2).
            "base" => Map.get(attrs, :base),
            "why" => Map.get(attrs, :why)
          }

          body = JSON.encode!(episode)

          Txn.q(
            txn,
            """
            INSERT INTO memory_guard_episodes (episodeId, host, kind, key, episode, openedAt)
            VALUES (?1, ?2, ?3, ?4, ?5, ?6)
            """,
            [episode["episodeId"], host, kind, key, body, now]
          )

          EventLog.lifecycle_in_txn(txn, "memory_guard_episode_opened", host, body)
          {:opened, row([body, 1, nil, nil, nil, 0, nil, 0, nil])}

        episode ->
          {:active, episode}
      end
    end)
    |> case do
      {:ok, result} -> result
      {:error, error} -> {:error, Exception.message(error)}
    end
  catch
    :exit, reason -> {:error, inspect(reason)}
  end

  defp active_in_txn(txn, host, kind, key) do
    case Txn.q(
           txn,
           "SELECT #{@columns} FROM memory_guard_episodes WHERE active=1 AND host=?1 AND kind=?2 AND ifnull(key,'')=ifnull(?3,'')",
           [host, kind, key]
         ) do
      [row] -> row(row)
      [] -> nil
    end
  end

  @doc """
  Name the trees of a custody episode opened while they could not be listed
  (review B6), once they can. `:ok` or `{:error, message}` (retried).
  """
  @spec set_trees(DB.server(), String.t(), [map()]) :: :ok | {:error, String.t()}
  def set_trees(db, episode_id, trees) do
    transact(db, fn txn ->
      case get(txn, episode_id) do
        %{"ended" => false, "trees" => nil} = episode ->
          body =
            episode
            |> Map.take(~w(episodeId host kind key since openedAt boot base))
            |> Map.merge(%{
              "trees" => trees,
              "treesUnknown" => nil,
              "why" => "#{length(trees)} agent processes could not be confirmed stopped"
            })
            |> JSON.encode!()

          Txn.q(txn, "UPDATE memory_guard_episodes SET episode=?2 WHERE episodeId=?1", [
            episode_id,
            body
          ])

          EventLog.lifecycle_in_txn(
            txn,
            "memory_guard_episode_trees",
            episode_id,
            JSON.encode!(%{episodeId: episode_id, trees: trees})
          )

        _ ->
          :ok
      end
    end)
  end

  @doc """
  End an episode because its condition cleared or the host rebooted (N3);
  the end is recorded in the same transaction that marks it. `:ok`, or
  `{:error, message}` (retried).
  """
  @spec finish(DB.server(), String.t(), String.t()) :: :ok | {:error, String.t()}
  def finish(db, episode_id, reason) do
    transact(db, fn txn ->
      Txn.q(
        txn,
        "UPDATE memory_guard_episodes SET active=0, endedAt=?2, endReason=?3 WHERE episodeId=?1 AND active=1",
        [episode_id, System.system_time(:millisecond), reason]
      )

      if Txn.changes(txn) == 1 do
        EventLog.lifecycle_in_txn(
          txn,
          "memory_guard_episode_ended",
          episode_id,
          JSON.encode!(%{episodeId: episode_id, reason: reason})
        )
      end
    end)
  end

  @doc "The recovery accepted for an episode and its outcome so far, or nil."
  @spec recovery(DB.server() | Txn.t(), String.t()) :: map() | nil
  def recovery(db, episode_id) do
    case get(db, episode_id) do
      %{"recovery" => recovery} -> recovery
      nil -> nil
    end
  end

  @doc "The override accepted for an episode, and whether it was applied, or nil."
  @spec override(DB.server() | Txn.t(), String.t()) :: map() | nil
  def override(db, episode_id) do
    case get(db, episode_id) do
      %{"override" => override} -> override
      nil -> nil
    end
  end

  @doc """
  B4: judge one root action record (`record` is its decoded content,
  `digest` the SHA-256 of its bytes) through one atomic transition. Returns
  `{:accepted, kind}` or `{:rejected, reason}`; a rejection is recorded.
  Concurrent readers produce exactly one acceptance; a digest already judged is
  never judged again. `check` runs inside the transition with the episode and
  returns nil or a reason to reject (the override's statement, FS9 Step 2).
  """
  @spec judge(DB.server(), map(), String.t(), String.t(), map(), (map() -> String.t() | nil)) ::
          {:accepted, String.t()} | {:rejected, String.t()} | {:error, String.t()}
  def judge(db, record, digest, host, extra \\ %{}, check \\ fn _episode -> nil end) do
    DB.transaction(db, fn txn -> judge_in_txn(txn, record, digest, host, extra, check) end)
    |> case do
      {:ok, result} -> result
      {:error, error} -> {:error, Exception.message(error)}
    end
  catch
    # N7.unreadable: nothing is accepted; the record is judged afresh later.
    :exit, reason -> {:error, inspect(reason)}
  end

  defp judge_in_txn(txn, record, digest, host, extra, check) do
    action = record["action"]
    episode_id = record["episodeId"]
    episode = is_binary(episode_id) && get(txn, episode_id)

    reason =
      cond do
        judged_in_txn?(txn, digest) ->
          :judged

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

        action == "recovery" and match?(%{"outcome" => "pending"}, episode["recovery"]) ->
          "a recovery of this episode is still pending"

        action == "override" and not match?(%{"outcome" => "failed"}, episode["recovery"]) ->
          "an override needs a failed recovery of this episode first"

        action == "override" and episode["override"] != nil ->
          "an override of this episode was already accepted"

        action == "override" ->
          check.(episode)

        true ->
          nil
      end

    cond do
      reason == :judged ->
        {:rejected, "this record was already judged"}

      reason ->
        reject_in_txn(txn, digest, episode_id, action, host, reason)
        {:rejected, reason}

      true ->
        now = System.system_time(:millisecond)

        fields =
          record
          |> Map.merge(extra)
          |> Map.merge(%{"digest" => digest, "acceptedAt" => now})

        if action == "recovery" do
          Txn.q(
            txn,
            "UPDATE memory_guard_episodes SET recovery=?2, recoveryStartedAt=NULL WHERE episodeId=?1",
            [episode_id, JSON.encode!(Map.put(fields, "outcome", "pending"))]
          )
        else
          Txn.q(txn, "UPDATE memory_guard_episodes SET override=?2 WHERE episodeId=?1", [
            episode_id,
            JSON.encode!(fields)
          ])
        end

        judged_in_txn(txn, digest, episode_id, action, "accepted", nil)

        EventLog.lifecycle_in_txn(
          txn,
          "memory_guard_#{action}_accepted",
          host,
          JSON.encode!(fields)
        )

        {:accepted, action}
    end
  end

  defp reject_in_txn(txn, digest, episode_id, action, host, reason) do
    judged_in_txn(txn, digest, episode_id, action, "rejected", reason)

    EventLog.lifecycle_in_txn(
      txn,
      "memory_guard_root_action_rejected",
      host,
      JSON.encode!(%{digest: digest, episodeId: episode_id, action: action, reason: reason})
    )
  end

  defp judged_in_txn(txn, digest, episode_id, action, verdict, reason) do
    Txn.q(
      txn,
      """
      INSERT INTO memory_guard_root_records (digest, episodeId, action, verdict, reason, judgedAt)
      VALUES (?1, ?2, ?3, ?4, ?5, ?6)
      """,
      [
        digest,
        if(is_binary(episode_id), do: episode_id),
        if(is_binary(action), do: action),
        verdict,
        reason,
        System.system_time(:millisecond)
      ]
    )
  end

  @doc """
  Reject a root action record outside the transition (not root-owned,
  malformed, unreadable), once per digest. `:ok` or `{:error, message}`: a
  rejection that was not recorded is retried, never assumed.
  """
  @spec reject(DB.server(), String.t(), map(), String.t(), String.t()) ::
          :ok | {:error, String.t()}
  def reject(db, digest, record, host, reason) do
    transact(db, fn txn ->
      unless judged_in_txn?(txn, digest),
        do: reject_in_txn(txn, digest, record["episodeId"], record["action"], host, reason)
    end)
  end

  @doc "Whether a record of this digest was already judged; raises when it cannot be read."
  @spec judged?(DB.server(), String.t()) :: boolean()
  def judged?(db, digest) do
    case DB.transaction(db, &judged_in_txn?(&1, digest)) do
      {:ok, judged} -> judged
      {:error, error} -> raise "root records cannot be read: #{Exception.message(error)}"
    end
  end

  defp judged_in_txn?(txn, digest),
    do: Txn.q(txn, "SELECT 1 FROM memory_guard_root_records WHERE digest=?1", [digest]) != []

  @doc """
  B2: record that this gateway start found a guard recovery accepted before
  it; its five-minute clock runs from `started_at`. Once per recovery.
  """
  @spec recovery_started(DB.server(), map(), integer()) :: :ok | {:error, String.t()}
  def recovery_started(db, recovery, started_at) do
    transact(db, fn txn ->
      Txn.q(
        txn,
        """
        UPDATE memory_guard_episodes SET recoveryStartedAt=?3
        WHERE episodeId=?1 AND json_extract(recovery,'$.digest')=?2 AND recoveryStartedAt IS NULL
        """,
        [recovery["episodeId"], recovery["digest"], started_at]
      )

      if Txn.changes(txn) == 1 do
        EventLog.lifecycle_in_txn(
          txn,
          "memory_guard_recovery_started",
          recovery["episodeId"],
          JSON.encode!(%{
            episodeId: recovery["episodeId"],
            digest: recovery["digest"],
            startedAt: started_at
          })
        )
      end
    end)
  end

  @doc "Record a recovery's terminal outcome once (`cleared` or `failed`)."
  @spec record_outcome(DB.server(), map(), String.t(), list()) :: :ok | {:error, String.t()}
  def record_outcome(db, recovery, outcome, survivors) do
    transact(db, fn txn ->
      Txn.q(
        txn,
        """
        UPDATE memory_guard_episodes
        SET recovery=json_set(recovery, '$.outcome', ?3, '$.survivors', json(?4))
        WHERE episodeId=?1 AND json_extract(recovery,'$.digest')=?2
          AND json_extract(recovery,'$.outcome')='pending'
        """,
        [recovery["episodeId"], recovery["digest"], outcome, JSON.encode!(survivors)]
      )

      if Txn.changes(txn) == 1 do
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
  end

  @doc "Record that an accepted override's effect was carried out, once."
  @spec applied(DB.server(), String.t()) :: :ok | {:error, String.t()}
  def applied(db, episode_id) do
    transact(db, fn txn ->
      Txn.q(
        txn,
        "UPDATE memory_guard_episodes SET applied=1 WHERE episodeId=?1 AND override IS NOT NULL AND applied=0",
        [episode_id]
      )

      if Txn.changes(txn) == 1 do
        EventLog.lifecycle_in_txn(
          txn,
          "memory_guard_override_applied",
          episode_id,
          JSON.encode!(%{episodeId: episode_id, at: System.system_time(:millisecond)})
        )
      end
    end)
  end

  @doc """
  FS9's alert and notice when an episode opens: exactly one owner alert
  through the owner-alerts route (`:route`, kind `memory-guard-stuck`, dedupe
  `memory-guard-stuck:<id>`) and one notice to the founding user's Main.

  The route's outcome is recorded in the transaction that creates the alert
  row: `created`, or `off` when owner alerts are off (then only the Main
  notice goes). A route that fails (absent, broken, unwritable) records
  nothing, so it is retried; it is never recorded as sent. `:message` builds
  the text (it takes a fresh root-path finding) and is called only when
  something is still to be sent. Idempotent: callers retry until `:ok`.
  """
  @spec notify(DB.server(), map(), keyword()) :: :ok | {:error, term()}
  def notify(db, %{"episodeId" => id} = episode, opts) do
    route = Keyword.fetch!(opts, :route)
    message = Keyword.fetch!(opts, :message)

    case get(db, id) do
      nil ->
        {:error, "episode #{id} cannot be found"}

      %{"alert" => alert, "notified" => notified} ->
        body = if alert == nil or not notified, do: message.(episode)
        alert = if alert, do: :ok, else: owner_alert(db, episode, body, route)

        notice =
          if notified do
            :ok
          else
            case Tightbeam.MemoryGuard.Priority.reserved_main(db) do
              %{session_key: main} when is_binary(main) ->
                main_notice(db, main, episode, body, opts)

              _ ->
                {:error, "no Main session to notify"}
            end
          end

        if alert == :ok and notice == :ok, do: :ok, else: {:error, {alert, notice}}
    end
  rescue
    error -> {:error, Exception.message(error)}
  catch
    :exit, reason -> {:error, inspect(reason)}
  end

  defp owner_alert(db, episode, body, route) do
    id = episode["episodeId"]
    key = "memory-guard-stuck:" <> id

    transact(db, fn txn ->
      outcome =
        case route.(txn, %{
               episode_id: id,
               host: episode["host"],
               dedupe_key: key,
               title: title(episode),
               body: body
             }) do
          {:created, alert_id} -> %{outcome: "created", alertId: alert_id}
          :exists -> %{outcome: "created", alertId: nil}
          :off -> %{outcome: "off"}
        end

      outcome = Map.merge(outcome, %{markerKey: key, at: System.system_time(:millisecond)})

      Txn.q(
        txn,
        "UPDATE memory_guard_episodes SET alert=?2 WHERE episodeId=?1 AND alert IS NULL",
        [id, JSON.encode!(outcome)]
      )

      EventLog.lifecycle_in_txn(
        txn,
        "memory_guard_stuck_alert",
        episode["host"],
        JSON.encode!(outcome)
      )
    end)
  end

  # The notice and its own delivery record are one transaction, so a retry
  # never sends it twice (FS7 "at most once").
  defp main_notice(db, main, episode, message, opts) do
    key = "memory-guard-stuck:" <> episode["episodeId"]

    {:ok, plan} =
      DB.transaction(db, fn txn ->
        Txn.q(
          txn,
          "UPDATE memory_guard_episodes SET notified=1 WHERE episodeId=?1 AND notified=0",
          [episode["episodeId"]]
        )

        if Txn.changes(txn) == 1 do
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
        else
          []
        end
      end)

    EventLog.publish(plan,
      conn_registry: Keyword.get(opts, :conn_registry, Tightbeam.ConnRegistry)
    )

    :ok
  end

  @doc "The alert's title."
  @spec title(map()) :: String.t()
  def title(episode), do: "#{episode["host"]}: Tightbeam has held #{held(episode)} too long"

  defp held(%{"kind" => "guard"}), do: "new agent launches"
  defp held(episode), do: "the replacement of the #{episode["key"]} adapter"

  @doc "The alert's plain words (FS9), with the current root-path finding."
  @spec message(map(), map()) :: String.t()
  def message(episode, finding) do
    "Tightbeam on #{episode["host"]} has held #{held(episode)} since " <>
      "#{DateTime.from_unix!(episode["since"], :millisecond)} because #{episode["why"]}. " <>
      "No Tightbeam command, agent or session can release it. To recover, run as root on " <>
      "#{episode["host"]}: tightbeam memory-guard-recover#{base_flag(episode)} " <>
      "#{episode["episodeId"]}. An override exists only after a recovery has failed: it " <>
      "launches anyway and accepts the risk that the held processes keep using memory outside " <>
      "every limit; tightbeam memory-guard-override#{base_flag(episode)} " <>
      "#{episode["episodeId"]} explains it before acting. Root-path check now: " <>
      Tightbeam.MemoryGuard.RootPath.statement(finding)
  end

  defp base_flag(%{"base" => base}) when is_binary(base), do: " --base #{base}"
  defp base_flag(_episode), do: ""

  @doc """
  Publish the active episodes of `host` for the root commands
  (`<base>/run/memory-guard/episodes/<id>.json`), with the recovery and
  override state, and remove the files of ended ones. `:ok` or
  `{:error, message}`: a publication that failed is said so and retried.
  """
  @spec publish(DB.server(), String.t(), String.t()) :: :ok | {:error, String.t()}
  def publish(db, base_dir, host) do
    dir = Path.join(Tightbeam.MemoryGuard.Records.dir(base_dir), "episodes")
    active = active(db, host)
    ids = MapSet.new(active, & &1["episodeId"])

    with :ok <- File.mkdir_p(dir),
         :ok <- write_all(dir, active),
         {:ok, entries} <- File.ls(dir) do
      Enum.reduce_while(entries, :ok, fn entry, :ok ->
        if String.ends_with?(entry, ".json") and not MapSet.member?(ids, Path.rootname(entry)) do
          case File.rm(Path.join(dir, entry)) do
            result when result in [:ok, {:error, :enoent}] -> {:cont, :ok}
            {:error, reason} -> {:halt, {:error, "#{entry} cannot be removed: #{reason}"}}
          end
        else
          {:cont, :ok}
        end
      end)
    else
      {:error, reason} when is_atom(reason) -> {:error, "#{dir}: #{reason}"}
      {:error, _} = error -> error
    end
  rescue
    error -> {:error, Exception.message(error)}
  end

  defp write_all(dir, active) do
    Enum.reduce_while(active, :ok, fn episode, :ok ->
      body =
        episode
        |> Map.take(~w(episodeId host kind key trees treesUnknown since openedAt boot base why))
        |> Map.put("recovery", episode["recovery"])
        |> Map.put("override", episode["override"] && Map.delete(episode["override"], "applied"))
        |> JSON.encode!()

      path = Path.join(dir, episode["episodeId"] <> ".json")

      with :ok <- File.write(path <> ".pending", body),
           :ok <- File.rename(path <> ".pending", path) do
        {:cont, :ok}
      else
        {:error, reason} -> {:halt, {:error, "#{path}: #{reason}"}}
      end
    end)
  end

  @doc """
  The episodes of `host` for a read (R12b, R7; matrix N10): shown, open,
  until they end, whatever is overridden, with the risk an override accepted.
  A read that cannot be completed says the state is unknown, never "none".
  """
  @spec read(DB.server(), String.t()) :: [map()] | %{unknown: String.t()}
  def read(db, host) do
    for episode <- active(db, host) do
      recovery = episode["recovery"]
      override = episode["override"]

      read = %{
        episodeId: episode["episodeId"],
        kind: episode["kind"],
        key: episode["key"],
        since: episode["since"],
        why: episode["why"],
        recovery: recovery && recovery["outcome"],
        overridden: override != nil,
        risk: override && risk(episode),
        alert: episode["alert"] && episode["alert"]["outcome"],
        noticeSent: episode["notified"]
      }

      if episode["kind"] == "custody" and episode["trees"] == nil,
        do: Map.put(read, :trees, "unknown: #{episode["treesUnknown"]}"),
        else: read
    end
  rescue
    error -> %{unknown: Exception.message(error)}
  catch
    :exit, reason -> %{unknown: inspect(reason)}
  end

  defp risk(%{"kind" => "guard"}),
    do: "launches ran without the memory guard: no cap, floor or per-agent limit was checked"

  defp risk(episode),
    do:
      "#{length(episode["override"]["trees"] || episode["trees"] || [])} agent processes " <>
        "that could not be stopped may keep using memory outside every limit until they end " <>
        "or the machine reboots"

  defp transact(db, fun) do
    case DB.transaction(db, fun) do
      {:ok, _} -> :ok
      {:error, error} -> {:error, Exception.message(error)}
    end
  catch
    :exit, reason -> {:error, inspect(reason)}
  end

  defp decode(detail), do: JSON.decode!(detail)
end

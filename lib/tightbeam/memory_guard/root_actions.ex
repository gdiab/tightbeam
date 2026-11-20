defmodule Tightbeam.MemoryGuard.RootActions do
  @moduledoc """
  FS9's root actions (memory limits v1.13): recovery and override records
  that root writes on the host, under `<base>/run/memory-guard/root/`. No
  Tightbeam verb, session credential, organization token or device approval
  writes one (AS5): a record is considered only when root owns its file, and
  it is accepted only through `Episodes.judge/6`'s one atomic transition.

  Every record found is judged once and its verdict recorded, by the SHA-256
  of its bytes: a record that is not a regular file, cannot be read, is not
  a JSON object or names no kind or action is rejected with that reason, never
  skipped (matrix N11; review B3). One that cannot be read is identified by
  its name, inode, size and modification time instead.

  The directory stays root's: the gateway never writes into it. Each pass
  lists it and looks at each entry's metadata; an entry already judged (the
  `seen` set the caller keeps) is not read again, so a pass costs one listing
  and one `lstat` per entry, plus one read and one indexed lookup per new
  entry (review B7). The gateway publishes the names it has judged in
  `<base>/run/memory-guard/root-judged.json`; each root command run moves
  those records to `root/judged/`, so the directory holds only what was
  written since root last ran.

  The gateway, not the root command, judges a recovery's outcome:

  - `custody`: `cleared` when every named tree is shown gone; `failed` when,
    on a fresh check at or after 60 s past the recorded kill time, a named
    tree is still there (its identity and process state are recorded);
  - `guard`: `cleared` when the guard answers; `failed` 5 minutes after the
    first gateway start that found the pending record, if it still has not.
    Without such a start it stays `pending` (review B2).
  """

  alias Tightbeam.MemoryGuard.{Episodes, Records, RootPath}

  @custody_wait_ms 60_000
  @guard_wait_ms 5 * 60_000
  @max_record_bytes 1_048_576

  @doc "The root actions directory of a base."
  def dir(base_dir), do: Path.join(Records.dir(base_dir), "root")

  @doc "The file naming the root records the gateway has judged."
  def judged_list(base_dir), do: Path.join(Records.dir(base_dir), "root-judged.json")

  @doc """
  Judge every record in the directory not yet judged. `opts`: `:root_uid`
  (default 0), `:finding` (the root-path check, for overrides), `:kinds`
  (the episode kinds this caller judges), `:seen` (the entries a previous
  pass found judged). Returns `%{seen: seen, error: nil | message}`: `error`
  says the directory, a record or a verdict could not be read or written;
  what failed is retried on the next pass.
  """
  @spec intake(Tightbeam.DB.server(), String.t(), String.t(), keyword()) :: %{
          seen: MapSet.t(),
          error: String.t() | nil
        }
  def intake(db, base_dir, host, opts \\ []) do
    seen = Keyword.get(opts, :seen, MapSet.new())
    dir = dir(base_dir)

    case File.ls(dir) do
      {:ok, entries} ->
        {now_seen, errors} =
          entries
          |> Enum.sort()
          |> Enum.filter(&(String.ends_with?(&1, ".json") and not String.starts_with?(&1, ".")))
          |> Enum.reduce({MapSet.new(), []}, fn entry, {acc, errors} ->
            case consider(db, dir, entry, host, seen, opts) do
              {:judged, id} -> {MapSet.put(acc, id), errors}
              :later -> {acc, errors}
              {:error, message} -> {acc, ["#{entry}: #{message}" | errors]}
            end
          end)

        errors =
          case publish_judged(base_dir, now_seen) do
            :ok -> errors
            {:error, message} -> [message | errors]
          end

        %{
          seen: now_seen,
          error: if(errors != [], do: errors |> Enum.reverse() |> Enum.join("; "))
        }

      {:error, :enoent} ->
        %{seen: MapSet.new(), error: nil}

      {:error, reason} ->
        %{seen: seen, error: "#{dir} cannot be read: #{reason}"}
    end
  end

  # One entry: `{:judged, id}` once its verdict is recorded, `:later` when it
  # belongs to another caller's kinds or vanished, `{:error, message}` when
  # its verdict could not be recorded (retried).
  defp consider(db, dir, entry, host, seen, opts) do
    path = Path.join(dir, entry)

    case File.lstat(path, time: :posix) do
      {:error, :enoent} ->
        :later

      {:error, reason} ->
        reject_unreadable(db, entry, nil, host, "its metadata cannot be read: #{reason}")

      {:ok, stat} ->
        id = {entry, stat.inode, stat.size, stat.mtime}

        if MapSet.member?(seen, id),
          do: {:judged, id},
          else: judge_entry(db, path, entry, stat, id, host, opts)
    end
  end

  defp judge_entry(db, path, entry, stat, id, host, opts) do
    root_uid = Keyword.get(opts, :root_uid, 0)
    kinds = Keyword.get(opts, :kinds, ["guard", "custody"])
    finding = Keyword.get(opts, :finding, fn -> RootPath.finding() end)

    cond do
      stat.type != :regular ->
        reject_unreadable(db, entry, stat, host, "it is not a regular file (#{stat.type})")
        |> judged(id)

      stat.size > @max_record_bytes ->
        reject_unreadable(db, entry, stat, host, "it is larger than a record can be")
        |> judged(id)

      true ->
        case File.read(path) do
          {:error, :enoent} ->
            :later

          {:error, reason} ->
            reject_unreadable(db, entry, stat, host, "it cannot be read: #{reason}")
            |> judged(id)

          {:ok, bytes} ->
            digest = :crypto.hash(:sha256, bytes) |> Base.encode16(case: :lower)

            if Episodes.judged?(db, digest),
              do: {:judged, id},
              else: judge_bytes(db, bytes, digest, stat, host, root_uid, kinds, finding, id)
        end
    end
  rescue
    error -> {:error, Exception.message(error)}
  catch
    :exit, reason -> {:error, "the root records cannot be read: #{inspect(reason)}"}
  end

  defp judge_bytes(db, bytes, digest, stat, host, root_uid, kinds, finding, id) do
    case decode(bytes) do
      {:error, reason} ->
        Episodes.reject(db, digest, %{}, host, reason) |> judged(id)

      {:ok, record} ->
        cond do
          stat.uid != root_uid ->
            Episodes.reject(db, digest, record, host, "the record was not written by root")
            |> judged(id)

          record["kind"] not in kinds ->
            :later

          true ->
            case judge_record(db, record, digest, host, finding) do
              {:error, message} -> {:error, message}
              _verdict -> {:judged, id}
            end
        end
    end
  end

  defp judged(:ok, id), do: {:judged, id}
  defp judged({:error, _} = error, _id), do: error

  # The record's content: a JSON object naming its kind and action.
  defp decode(bytes) do
    case JSON.decode(bytes) do
      {:ok, %{"kind" => kind, "action" => action} = record}
      when kind in ["guard", "custody"] and is_binary(action) ->
        {:ok, record}

      {:ok, %{"kind" => kind}} when is_binary(kind) and kind not in ["guard", "custody"] ->
        {:error, "the record names an unknown kind"}

      {:ok, %{"kind" => kind, "action" => _}} when not is_binary(kind) ->
        {:error, "the record names no kind"}

      {:ok, %{"action" => action}} when is_binary(action) ->
        {:error, "the record names no kind"}

      {:ok, %{}} ->
        {:error, "the record names no kind or no action"}

      {:ok, _other} ->
        {:error, "the record is not a JSON object"}

      {:error, _} ->
        {:error, "the record is not valid JSON"}
    end
  end

  # A record whose bytes cannot be had is identified by its name and metadata
  # (stable while the file is unchanged), and rejected once with its reason.
  defp reject_unreadable(db, entry, stat, host, reason) do
    ident =
      if stat,
        do: "#{entry}:#{stat.inode}:#{stat.size}:#{stat.mtime}",
        else: entry

    digest = "unreadable:" <> (:crypto.hash(:sha256, ident) |> Base.encode16(case: :lower))

    case Episodes.reject(db, digest, %{}, host, "the record cannot be judged: " <> reason) do
      :ok -> if(stat, do: :ok, else: {:error, reason})
      error -> error
    end
  end

  defp judge_record(db, record, digest, host, finding) do
    if record["action"] == "override",
      do: judge_override(db, record, digest, host, finding.()),
      else: Episodes.judge(db, record, digest, host)
  end

  # The gateway checks the root path at each override attempt. The statement
  # recorded must be exactly the one this episode's failed recovery, the
  # recorded operator and this finding select, as the command prints it (FS9
  # Step 2; review B5): a forged or placeholder statement is refused.
  defp judge_override(db, record, digest, host, finding) do
    kind = RootPath.kind(finding)

    # N8: every recorded field present; one that cannot be established is
    # `unknown`, never omitted.
    operator =
      Map.merge(
        %{"user" => "root", "sudoUser" => "unknown", "sudoUid" => "unknown"},
        if(is_map(record["operator"]), do: record["operator"], else: %{})
      )

    known = %{
      "finding" => finding,
      "statementKind" => kind,
      "operator" => operator,
      "at" => record["at"] || "unknown"
    }

    Episodes.judge(db, record, digest, host, known, fn episode ->
      survivors = get_in(episode, ["recovery", "survivors"]) || []
      canonical = statement(episode, survivors, operator, finding)

      cond do
        record["statementKind"] != kind ->
          "the printed statement (#{inspect(record["statementKind"])}) does not match the root-path finding (#{kind})"

        record["trees"] != survivors ->
          "the record's trees are not the survivors of the failed recovery"

        record["statement"] != canonical ->
          "the printed statement is not the one this episode, its failed recovery, the operator and the current root-path finding select"

        true ->
          nil
      end
    end)
  end

  @doc """
  The override statement exactly as `tightbeam memory-guard-override` prints
  it, from the episode, the survivors of its failed recovery, the operator
  and a root-path finding (FS9 Step 2).
  """
  @spec statement(map(), [map()], map(), map()) :: String.t()
  def statement(episode, survivors, operator, finding) do
    held =
      if episode["kind"] == "guard",
        do: "new agent launches",
        else: "the replacement of the #{episode["key"] || "?"} adapter"

    risk =
      if episode["kind"] == "guard",
        do:
          "Admitting the held launches means they run without the memory guard: no cap, " <>
            "floor or per-agent limit is checked until it answers.",
        else:
          "#{length(survivors)} agent processes could not be stopped, even by root. Launching " <>
            "a replacement means they may keep using memory outside every limit until they " <>
            "end or the machine reboots."

    trees =
      for tree <- survivors do
        "  - launch record #{text(tree["launchId"], "unknown")}, process " <>
          "#{JSON.encode!(tree["pid"])} started at #{JSON.encode!(tree["start"])}, unit " <>
          "#{text(tree["unit"], "none")}, state #{text(tree["state"], "unknown")}\n"
      end

    "Episode #{episode["episodeId"]} on #{text(episode["host"], "?")}: Tightbeam holds " <>
      "#{held} because #{text(episode["why"], "?")}.\n" <>
      Enum.join(trees) <>
      "Risk accepted: #{risk}\n" <>
      "Recorded as: root, invoked by #{text(operator["sudoUser"], "unknown")} " <>
      "(uid #{text(operator["sudoUid"], "unknown")}).\n" <>
      RootPath.statement(finding) <> "\n"
  end

  defp text(value, _default) when is_binary(value), do: value
  defp text(_value, default), do: default

  # The names judged, for root's next command run to move aside. Rewritten
  # when it does not list exactly them, so a failed write is retried.
  defp publish_judged(base_dir, now) do
    path = judged_list(base_dir)
    body = JSON.encode!(%{judged: now |> Enum.map(&elem(&1, 0)) |> Enum.sort()})

    with {:ok, current} when current == body <- File.read(path) do
      :ok
    else
      _ ->
        with :ok <- File.mkdir_p(Path.dirname(path)),
             :ok <- File.write(path <> ".pending", body),
             :ok <- File.rename(path <> ".pending", path) do
          :ok
        else
          {:error, reason} -> {:error, "#{path} cannot be written: #{reason}"}
        end
    end
  end

  @doc """
  Judge the outcome of each pending `custody` recovery on `host`.
  `shown_gone?` decides one named tree; `state_of` reads its process state.
  An episode whose trees are unknown has no outcome to judge (review B6).
  """
  @spec custody_outcomes(
          Tightbeam.DB.server(),
          String.t(),
          (map() -> boolean()),
          (map() -> term()),
          integer()
        ) ::
          :ok
  def custody_outcomes(db, host, shown_gone?, state_of, now) do
    for %{"kind" => "custody", "episodeId" => id, "trees" => trees} <- Episodes.active(db, host),
        is_list(trees),
        %{"outcome" => "pending", "killedAt" => killed_at} = recovery <- [
          Episodes.recovery(db, id)
        ] do
      survivors = Enum.reject(trees, shown_gone?)

      cond do
        survivors == [] ->
          with :ok <- Episodes.record_outcome(db, recovery, "cleared", []),
               do: Episodes.finish(db, id, "recovered: every named tree is shown gone")

        is_integer(killed_at) and now >= killed_at + @custody_wait_ms ->
          Episodes.record_outcome(
            db,
            recovery,
            "failed",
            Enum.map(survivors, &Map.put(&1, "state", state_of.(&1)))
          )

        true ->
          :pending
      end
    end

    :ok
  end

  @doc """
  Judge each pending `guard` recovery on `host`: `cleared` (and the episode
  ended) when the guard answers. Otherwise its five-minute clock starts at
  `started`, this gateway's start, only if the recovery was written before
  that start (this start is the one after root's restart that found it), and
  it is `failed` five minutes later. A recovery written during this run waits,
  `pending`, for the next start (review B2).
  """
  @spec guard_outcomes(Tightbeam.DB.server(), String.t(), boolean(), integer(), integer()) :: :ok
  def guard_outcomes(db, host, guard_answers?, started, now) do
    for %{"kind" => "guard", "episodeId" => id} <- Episodes.active(db, host),
        %{"outcome" => "pending"} = recovery <- [Episodes.recovery(db, id)] do
      written = if is_integer(recovery["at"]), do: recovery["at"], else: recovery["acceptedAt"]

      cond do
        guard_answers? ->
          with :ok <- Episodes.record_outcome(db, recovery, "cleared", []),
               do: Episodes.finish(db, id, "recovered: the memory guard answers")

        is_integer(recovery["startedAt"]) ->
          if now >= recovery["startedAt"] + @guard_wait_ms,
            do: Episodes.record_outcome(db, recovery, "failed", []),
            else: :pending

        written < started ->
          Episodes.recovery_started(db, recovery, started)

        true ->
          :pending
      end
    end

    :ok
  end
end

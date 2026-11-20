defmodule Tightbeam.MemoryGuard.RootActions do
  @moduledoc """
  FS9's root actions (memory limits v1.13): recovery and override records
  that root writes on the host, under `<base>/run/memory-guard/root/`. No
  Tightbeam verb, session credential, organization token or device approval
  writes one (AS5): a record is considered only when root owns its file, and
  it is accepted only through `Episodes.judge/5`'s one atomic transition.

  The gateway, not the root command, judges a recovery's outcome:

  - `custody`: `cleared` when every named tree is shown gone; `failed` when,
    on a fresh check at or after 60 s past the recorded kill time, a named
    tree is still there (its identity and process state are recorded);
  - `guard`: `cleared` when the guard answers; `failed` 5 minutes after the
    first gateway start that found the pending record, if it still has not.
  """

  alias Tightbeam.MemoryGuard.{Episodes, Records, RootPath}

  @custody_wait_ms 60_000
  @guard_wait_ms 5 * 60_000

  @doc "The root actions directory of a base."
  def dir(base_dir), do: Path.join(Records.dir(base_dir), "root")

  @doc """
  Judge every not yet judged record in the directory. `opts`: `:root_uid`
  (default 0), `:finding` (the root-path check, for overrides), `:kinds`
  (the episode kinds this caller judges). Returns the judgements made.
  """
  @spec intake(Tightbeam.DB.server(), String.t(), String.t(), keyword()) :: [term()]
  def intake(db, base_dir, host, opts \\ []) do
    root_uid = Keyword.get(opts, :root_uid, 0)
    kinds = Keyword.get(opts, :kinds, ["guard", "custody"])
    finding = Keyword.get(opts, :finding, fn -> RootPath.finding() end)
    dir = dir(base_dir)

    case File.ls(dir) do
      {:ok, entries} ->
        for entry <- Enum.sort(entries),
            String.ends_with?(entry, ".json"),
            path = Path.join(dir, entry),
            {:ok, bytes} <- [File.read(path)],
            digest = :crypto.hash(:sha256, bytes) |> Base.encode16(case: :lower),
            not Episodes.judged?(db, digest),
            record = decode(bytes),
            record["kind"] in kinds do
          judge_file(db, path, record, digest, host, root_uid, finding)
        end

      {:error, _} ->
        []
    end
  end

  defp decode(bytes) do
    case JSON.decode(bytes) do
      {:ok, %{} = record} -> record
      _ -> %{"kind" => nil}
    end
  end

  defp judge_file(db, path, record, digest, host, root_uid, finding) do
    owner =
      case File.stat(path) do
        {:ok, %File.Stat{uid: uid}} -> uid
        _ -> nil
      end

    cond do
      owner != root_uid ->
        Episodes.reject(db, digest, record, host, "the record was not written by root")
        {:rejected, "not root"}

      record["action"] == "override" ->
        judge_override(db, record, digest, host, finding.())

      true ->
        Episodes.judge(db, record, digest, host)
    end
  end

  # The gateway checks the root path at each override attempt; the statement
  # the command printed must be the one this finding selects (FS9 Step 2).
  defp judge_override(db, record, digest, host, finding) do
    kind = RootPath.kind(finding)

    if record["statementKind"] != kind do
      Episodes.reject(
        db,
        digest,
        record,
        host,
        "the printed statement (#{inspect(record["statementKind"])}) does not match the root-path finding (#{kind})"
      )

      {:rejected, "statement mismatch"}
    else
      Episodes.judge(db, record, digest, host, %{"finding" => finding, "statementKind" => kind})
    end
  end

  @doc """
  Judge the outcome of each pending `custody` recovery on `host`.
  `shown_gone?` decides one named tree; `state_of` reads its process state.
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
        %{"outcome" => "pending", "killedAt" => killed_at} = recovery <- [
          Episodes.recovery(db, id)
        ] do
      survivors = Enum.reject(trees, shown_gone?)

      cond do
        survivors == [] ->
          Episodes.record_outcome(db, recovery, "cleared", [])
          Episodes.finish(db, id, "recovered: every named tree is shown gone")

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
  ended) when the guard answers; `failed` 5 minutes after `started` (the
  gateway's start that found the record) if it has not.
  """
  @spec guard_outcomes(Tightbeam.DB.server(), String.t(), boolean(), integer(), integer()) :: :ok
  def guard_outcomes(db, host, guard_answers?, started, now) do
    for %{"kind" => "guard", "episodeId" => id} <- Episodes.active(db, host),
        %{"outcome" => "pending"} = recovery <- [Episodes.recovery(db, id)] do
      cond do
        guard_answers? ->
          Episodes.record_outcome(db, recovery, "cleared", [])
          Episodes.finish(db, id, "recovered: the memory guard answers")

        now >= max(started, recovery["acceptedAt"] || started) + @guard_wait_ms ->
          Episodes.record_outcome(db, recovery, "failed", [])

        true ->
          :pending
      end
    end

    :ok
  end
end

defmodule Tightbeam.MemoryGuard.Records do
  @moduledoc """
  The launch records the session launch step writes before it execs the
  harness (memory limits v1.1 R10: the gateway maps each session tree to its
  harness session from a record made at launch, before harness code runs), and
  the `launch.json` the gateway publishes for the step.

  Layout under `<base>/run/memory-guard`:

  - `launch.json`: `{v: 1, mode, fs, harness, sessionLimit}`;
  - `bin/tightbeam-session-exec`: a link to the gateway's CLI binary;
  - `sessions/<launchId>.json`: one record per session process, and its
    `harness-group` identity `sessions/<launchId>.identity`.
  """

  @marker ".generation"

  @doc """
  Initialize the launch-record inventory for this boot (v1.13 FS4 scope,
  matrix B2–B4): the inventory counts as empty only when its initialization
  is durably recorded. The database keeps a `memory_guard_inventory` record
  (path, boot identity, generation), written in one step with the
  directory's own generation marker.

  - No record yet: create the directory, the marker and the record.
  - Same boot: the directory and a matching marker must exist; otherwise the
    inventory was lost, which is an error, never an empty host.
  - A new boot identity: re-initialize. A reboot ends every process (FS9).
  - Boot identity unknown: only a matching marker is accepted.

  Returns `{:ok, generation}` or `{:error, message}`.
  """
  @spec init_inventory(Tightbeam.DB.server(), String.t(), String.t() | nil) ::
          {:ok, String.t()} | {:error, String.t()}
  def init_inventory(db, base_dir, boot) do
    sessions = Path.join(dir(base_dir), "sessions")

    case last_inventory(db, sessions) do
      {:ok, nil} ->
        create_inventory(db, sessions, boot)

      {:ok, %{"boot" => recorded_boot, "generation" => generation}}
      when is_binary(boot) and recorded_boot != boot ->
        _ = generation
        create_inventory(db, sessions, boot)

      {:ok, %{"generation" => generation}} ->
        with :ok <- check_inventory(base_dir, generation), do: {:ok, generation}

      {:error, error} ->
        {:error, error}
    end
  end

  @doc """
  Whether the inventory of `generation` is still in place: its directory
  exists with a matching marker. A missing directory or marker is an error
  (the inventory was lost), never "no records".
  """
  @spec check_inventory(String.t(), String.t()) :: :ok | {:error, String.t()}
  def check_inventory(base_dir, generation) do
    marker = Path.join([dir(base_dir), "sessions", @marker])

    case File.read(marker) do
      {:ok, text} ->
        if String.trim(text) == generation,
          do: :ok,
          else: {:error, "the launch-record inventory was replaced (generation marker differs)"}

      {:error, :enoent} ->
        {:error, "the launch-record inventory is missing (no directory or generation marker)"}

      {:error, reason} ->
        {:error, "the launch-record inventory cannot be read: #{reason}"}
    end
  end

  defp last_inventory(db, sessions) do
    case Tightbeam.DB.query(
           db,
           """
           SELECT detail FROM lifecycle_events
           WHERE kind='memory_guard_inventory' AND subject=?1 ORDER BY id DESC LIMIT 1
           """,
           [sessions]
         ) do
      {:ok, []} -> {:ok, nil}
      {:ok, [[detail]]} -> {:ok, JSON.decode!(detail)}
      {:error, error} -> {:error, "the inventory record cannot be read: #{inspect(error)}"}
    end
  rescue
    error -> {:error, "the inventory record cannot be read: #{Exception.message(error)}"}
  end

  defp create_inventory(db, sessions, boot) do
    generation = Base.encode16(:crypto.strong_rand_bytes(8), case: :lower)

    Tightbeam.DB.transaction(db, fn txn ->
      Tightbeam.EventLog.lifecycle_in_txn(
        txn,
        "memory_guard_inventory",
        sessions,
        JSON.encode!(%{boot: boot, generation: generation})
      )

      # The marker and the record are one step: a failed write rolls back.
      with :ok <- File.mkdir_p(sessions),
           :ok <- File.write(Path.join(sessions, @marker), generation) do
        :ok
      else
        {:error, reason} -> raise "the launch-record inventory cannot be created: #{reason}"
      end
    end)
    |> case do
      {:ok, :ok} ->
        {:ok, generation}

      {:error, error} ->
        {:error, "the launch-record inventory cannot be created: #{inspect(error)}"}
    end
  rescue
    error -> {:error, Exception.message(error)}
  end

  @doc """
  The launch step's refusal for harness session `sid` at or after `since`
  (ms), from `<dir>/refusals` (v1.13 FS2): `%{launch_id, reason, at}`, nil
  when there is none, or `{:error, message}` when the refusals cannot be
  read: then whether the step refused is unknown, never "it did not".
  """
  @spec refusal_for(String.t(), String.t() | nil, integer()) ::
          map() | nil | {:error, String.t()}
  def refusal_for(_base_dir, nil, _since), do: nil

  def refusal_for(base_dir, sid, since) do
    refusals = Path.join(dir(base_dir), "refusals")

    case File.ls(refusals) do
      {:ok, entries} ->
        entries
        |> Enum.filter(&(String.ends_with?(&1, ".json") and not String.starts_with?(&1, ".")))
        |> Enum.reduce_while([], fn entry, found ->
          case read_refusal(Path.join(refusals, entry)) do
            {:ok, %{"sessionId" => ^sid, "at" => at} = record}
            when is_integer(at) and at >= since ->
              {:cont,
               [%{launch_id: record["launchId"], reason: record["reason"], at: at} | found]}

            {:ok, _other} ->
              {:cont, found}

            {:error, reason} ->
              {:halt, {:error, "refusal record #{entry} cannot be read: #{reason}"}}
          end
        end)
        |> case do
          {:error, _} = error -> error
          found -> Enum.max_by(found, & &1.at, fn -> nil end)
        end

      {:error, :enoent} ->
        nil

      {:error, reason} ->
        {:error, "the refusal records cannot be listed: #{reason}"}
    end
  end

  defp read_refusal(path) do
    with {:ok, text} <- File.read(path),
         {:ok, %{} = record} <- JSON.decode(text) do
      {:ok, record}
    else
      {:error, :enoent} -> {:ok, %{}}
      {:error, reason} when is_atom(reason) -> {:error, reason}
      _ -> {:error, "malformed"}
    end
  end

  @doc """
  Whether everything the launch step needs is in place (v1.13 FS2): its
  configuration reads, the launch-record directory takes a write, its refusal
  records can be read (else a refusal could not be told from a harness
  failure), and the process's own `oom_score_adj` reads. `:ok` or
  `{:error, message}`.
  """
  @spec step_prerequisites(String.t(), String.t()) :: :ok | {:error, String.t()}
  def step_prerequisites(base_dir, root) do
    sessions = Path.join(dir(base_dir), "sessions")
    probe = Path.join(sessions, ".probe-#{System.unique_integer([:positive])}")

    with {:ok, text} <- File.read(Path.join(dir(base_dir), "launch.json")),
         refusals when not is_tuple(refusals) or elem(refusals, 0) != :error <-
           refusal_for(base_dir, "", 0),
         {:ok, %{"v" => 1, "mode" => mode}} when is_binary(mode) <- JSON.decode(text),
         :ok <- File.write(probe, ""),
         :ok <- File.rm(probe),
         {:ok, oom} <- File.read(Path.join(root, "proc/self/oom_score_adj")),
         {_value, _} <- Integer.parse(String.trim(oom)) do
      :ok
    else
      other -> {:error, "the launch step's prerequisites are not in place: #{inspect(other)}"}
    end
  end

  @doc "The memory-guard runtime directory of a base."
  def dir(base_dir), do: Path.join([base_dir, "run", "memory-guard"])

  @doc "The step link path."
  def step_path(base_dir), do: Path.join([dir(base_dir), "bin", "tightbeam-session-exec"])

  @doc """
  Point the step link at `cli_bin` (the gateway's installed CLI). Returns the
  link path, or an error naming what is missing.
  """
  @spec install_step(String.t(), String.t() | nil) :: {:ok, String.t()} | {:error, String.t()}
  def install_step(_base_dir, nil), do: {:error, "the Tightbeam CLI binary is not installed"}

  def install_step(base_dir, cli_bin) do
    link = step_path(base_dir)
    target = Path.join(cli_bin, "tightbeam")

    with true <- File.regular?(target) || {:error, "#{target} is missing"},
         :ok <- File.mkdir_p(Path.dirname(link)) do
      pending = link <> ".pending"
      _ = File.rm(pending)

      with :ok <- File.ln_s(target, pending),
           :ok <- File.rename(pending, link) do
        {:ok, link}
      else
        {:error, reason} -> {:error, "#{link} could not be linked: #{reason}"}
      end
    else
      {:error, reason} when is_binary(reason) -> {:error, reason}
      {:error, reason} -> {:error, "#{link} could not be created: #{reason}"}
    end
  end

  @doc "Publish the step's configuration atomically."
  @spec publish_config(String.t(), map()) :: :ok | {:error, term()}
  def publish_config(base_dir, config) do
    path = Path.join(dir(base_dir), "launch.json")
    pending = path <> ".pending"

    with :ok <- File.mkdir_p(dir(base_dir)),
         :ok <- File.write(pending, JSON.encode!(Map.put(config, :v, 1))),
         do: File.rename(pending, path)
  end

  @doc """
  Every launch record, keyed by launch id. These records are the custody of
  live session processes (R2a), so a record that cannot be listed, read or
  decoded is an error, never an absent record. No directory yet is no records.
  (`*.pending` files are a step's write in progress, renamed when complete.)
  """
  @spec read_all(String.t()) :: {:ok, %{String.t() => map()}} | {:error, String.t()}
  def read_all(base_dir) do
    sessions = Path.join(dir(base_dir), "sessions")

    case File.ls(sessions) do
      {:ok, entries} ->
        entries
        |> Enum.filter(&String.ends_with?(&1, ".json"))
        |> Enum.reduce_while({:ok, %{}}, fn entry, {:ok, acc} ->
          path = Path.join(sessions, entry)

          # A record without its tree's identity (an integer pid) names no
          # tree that can be found or shown gone: it is unreadable, not empty.
          with {:ok, text} <- File.read(path),
               {:ok, %{"v" => 1, "launchId" => launch, "pid" => pid} = record}
               when is_binary(launch) and is_integer(pid) and pid > 0 <- JSON.decode(text) do
            {:cont, {:ok, Map.put(acc, launch, record)}}
          else
            {:error, :enoent} -> {:cont, {:ok, acc}}
            other -> {:halt, {:error, "launch record #{entry} is unreadable: #{inspect(other)}"}}
          end
        end)

      {:error, :enoent} ->
        {:ok, %{}}

      {:error, reason} ->
        {:error, "launch records cannot be listed: #{reason}"}
    end
  end

  @doc "Remove a launch record and its identity files."
  @spec remove(String.t(), String.t()) :: :ok
  def remove(base_dir, launch_id) do
    sessions = Path.join(dir(base_dir), "sessions")

    for suffix <- [".json", ".identity", ".identity.authority"],
        do: File.rm(Path.join(sessions, launch_id <> suffix))

    :ok
  end
end

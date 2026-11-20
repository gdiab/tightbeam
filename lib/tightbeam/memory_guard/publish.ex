defmodule Tightbeam.MemoryGuard.Publish do
  @moduledoc """
  Files published from durable records (agreed design rev 2 O6–O8, D3): the
  launch step's `launch.json` and the launch-record inventory's marker.

  A file is never written ahead of its record. The record and the journal
  intent (`publish_config` / `publish_marker`, carrying the exact bytes)
  commit together. The file is written after the commit, read back, and only
  then is the intent `done`.

  While an intent is not done, the record is requested, not applied:
  - launches that need the step are held;
  - `mode_in_force` does not count the mode;
  - every read says so.

  Whoever is running (the guard, or the Watcher while it is down) resolves a
  pending intent by writing the newest one's bytes. Older intents are
  `superseded`.
  """

  alias Tightbeam.DB
  alias Tightbeam.DB.Txn
  alias Tightbeam.MemoryGuard.{Journal, Records}

  @doc "The exact bytes of the step's configuration for `config`."
  @spec config_bytes(map()) :: String.t()
  def config_bytes(config), do: JSON.encode!(Map.put(config, :v, 1))

  @doc """
  Record the intent to publish `bytes` as the host's `launch.json`, in the
  transaction of the mode record that decides it. Returns the effect id, to be
  named in that record (`publish`).
  """
  @spec config_in_txn(Txn.t(), String.t(), String.t(), integer()) :: String.t()
  def config_in_txn(%Txn{} = txn, host, bytes, now) do
    digest = :crypto.hash(:sha256, bytes) |> Base.encode16(case: :lower) |> binary_part(0, 16)

    Journal.intend_in_txn(
      txn,
      "publish_config",
      "#{now}:#{digest}",
      host,
      nil,
      %{bytes: bytes},
      now
    )
  end

  @doc """
  Write a `publish_config` intent's bytes and complete it once they read back.
  `:ok` or `{:error, message}` (the intent stays and is retried).
  """
  @spec config(DB.server(), String.t(), String.t(), String.t(), integer()) ::
          :ok | {:error, String.t()}
  def config(db, base_dir, id, bytes, now) do
    path = Path.join(Records.dir(base_dir), "launch.json")

    with :ok <- write(path, bytes),
         {:ok, ^bytes} <- File.read(path),
         :ok <- complete(db, id, %{outcome: "published"}, now) do
      :ok
    else
      {:ok, _other} -> {:error, "#{path} does not read back as written"}
      {:error, reason} when is_atom(reason) -> {:error, "#{path}: #{reason}"}
      {:error, _} = error -> error
    end
  end

  @doc """
  Resolve a `publish_config` intent: superseded by a newer one of the same
  host, or published.
  """
  @spec resolve_config(DB.server(), String.t(), map(), integer()) :: :ok | {:error, String.t()}
  def resolve_config(db, base_dir, effect, now) do
    if newer?(db, effect),
      do: complete(db, effect.id, %{outcome: "superseded"}, now),
      else: config(db, base_dir, effect.id, effect.intent["bytes"], now)
  end

  @doc """
  Whether the host's published `launch.json` matches its committed record:
  no `publish_config` intent is pending. Raises when it cannot be read.
  """
  @spec config_done?(DB.server(), String.t()) :: boolean()
  def config_done?(db, host), do: not Journal.pending?(db, host, "publish_config")

  @doc "Whether a mode record's publication (`publish` effect id) is done."
  @spec done_in_txn?(Txn.t(), String.t() | nil) :: boolean()
  def done_in_txn?(_txn, nil), do: true

  def done_in_txn?(%Txn{} = txn, id) do
    case Journal.get(txn, id) do
      %{phase: "done"} -> true
      nil -> true
      _ -> false
    end
  end

  @doc "Record the intent to write the inventory marker, in the inventory record's transaction."
  @spec marker_in_txn(Txn.t(), String.t(), String.t(), String.t(), integer()) :: String.t()
  def marker_in_txn(%Txn{} = txn, host, path, generation, now) do
    Journal.intend_in_txn(
      txn,
      "publish_marker",
      generation,
      host,
      nil,
      %{path: path, generation: generation},
      now
    )
  end

  @doc "Write an inventory marker intent's file and complete it once it reads back."
  @spec marker(DB.server(), map(), integer()) :: :ok | {:error, String.t()}
  def marker(db, %{id: id, intent: %{"path" => path, "generation" => generation}}, now) do
    with :ok <- File.mkdir_p(Path.dirname(path)),
         :ok <- write(path, generation),
         {:ok, ^generation} <- File.read(path),
         :ok <- complete(db, id, %{outcome: "published"}, now) do
      :ok
    else
      {:ok, _other} -> {:error, "#{path} does not read back as written"}
      {:error, reason} when is_atom(reason) -> {:error, "#{path}: #{reason}"}
      {:error, _} = error -> error
    end
  end

  defp newer?(db, effect) do
    case DB.query(
           db,
           """
           SELECT 1 FROM memory_guard_effects
           WHERE host=?1 AND kind='publish_config' AND (createdAt, effectId) > (?2, ?3) LIMIT 1
           """,
           [effect.host, effect.created_at, effect.id]
         ) do
      {:ok, rows} -> rows != []
      {:error, error} -> raise "the effect journal cannot be read: #{inspect(error)}"
    end
  end

  defp write(path, bytes) do
    pending = path <> ".pending"

    with :ok <- File.mkdir_p(Path.dirname(path)),
         :ok <- File.write(pending, bytes),
         do: File.rename(pending, path)
  end

  defp complete(db, id, outcome, now) do
    case DB.transaction(db, &Journal.complete_in_txn(&1, id, outcome, now)) do
      {:ok, _} -> :ok
      {:error, error} -> {:error, Exception.message(error)}
    end
  catch
    :exit, reason -> {:error, inspect(reason)}
  end
end

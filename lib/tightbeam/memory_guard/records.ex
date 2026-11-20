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

  @doc "Every complete launch record, keyed by launch id."
  @spec read_all(String.t()) :: %{String.t() => map()}
  def read_all(base_dir) do
    sessions = Path.join(dir(base_dir), "sessions")

    case File.ls(sessions) do
      {:ok, entries} ->
        for entry <- entries,
            String.ends_with?(entry, ".json"),
            {:ok, text} <- [File.read(Path.join(sessions, entry))],
            {:ok, %{"v" => 1, "launchId" => launch} = record} <- [JSON.decode(text)],
            into: %{},
            do: {launch, record}

      {:error, _} ->
        %{}
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

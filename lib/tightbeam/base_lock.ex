defmodule Tightbeam.BaseLock do
  @moduledoc """
  The base-directory lock (stage1-v8 S1.2 step 1): an exclusive, non-blocking OS
  advisory lock on `<base_dir>/gateway.lock`, taken before the gateway's first write
  and held for as long as it serves. While the recovery ceremony or a root-admin
  command holds it, the gateway refuses to start; while the gateway holds it, they
  refuse. The lock prevents accidents and honest-process races only (S1.4).
  """

  use GenServer
  require Logger

  def start_link(opts), do: GenServer.start_link(__MODULE__, opts, name: __MODULE__)

  @impl true
  def init(opts) do
    path = Keyword.fetch!(opts, :path)
    File.mkdir_p!(Path.dirname(path))

    try do
      {:ok, %{path: path, lock: Tightbeam.Native.base_lock(path)}}
    rescue
      error in ErlangError ->
        Logger.error(
          "refusing to start: the base-directory lock #{path} is held (#{inspect(error.original)}); " <>
            "a recovery ceremony or root-admin command may be running"
        )

        {:stop, {:base_dir_locked, path}}
    end
  end
end

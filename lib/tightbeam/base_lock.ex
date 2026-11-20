defmodule Tightbeam.BaseLock do
  @moduledoc """
  The base-directory lock (stage1-v8 S1.2 step 1): an exclusive, non-blocking OS
  advisory lock on `<base_dir>/gateway.lock`.

  The gateway's database owner (`Tightbeam.DB`) takes it after admission and before
  it opens `state.db` for writing, and holds it in its own state, so the lock lives
  exactly as long as the process that can write the base: it cannot be lost while
  the database is open, and a refused start opens nothing. While the recovery
  ceremony or a root-admin command holds it, the gateway refuses to start; while the
  gateway holds it, they refuse. The lock prevents accidents and honest-process races
  only (S1.4).
  """

  require Logger

  @doc "Take the lock for `base_dir`; the returned resource holds it until collected."
  @spec acquire(Path.t()) :: {:ok, reference()} | {:error, {:base_dir_locked, Path.t()}}
  def acquire(base_dir) do
    path = Path.join(base_dir, "gateway.lock")

    try do
      {:ok, Tightbeam.Native.base_lock(path)}
    rescue
      error in ErlangError ->
        Logger.error(
          "refusing to start: the base-directory lock #{path} is held (#{inspect(error.original)}); " <>
            "a recovery ceremony or root-admin command may be running"
        )

        {:error, {:base_dir_locked, path}}
    end
  end
end

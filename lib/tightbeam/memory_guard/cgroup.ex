defmodule Tightbeam.MemoryGuard.Cgroup do
  @moduledoc """
  The `enforced` layout (memory limits v1.1 R12c), inside the cgroup subtree
  the host delegated to the gateway and nowhere else (M-V5):

  | Cgroup                        | Members                         | Settings                                   |
  |-------------------------------|---------------------------------|--------------------------------------------|
  | `gateway`                     | the gateway and its helpers     | none                                       |
  | `harness` (the budget group)  | no processes of its own         | `memory.max`=budget, swap 0, oom.group 0   |
  | `harness/adapter-<launchId>`  | one adapter process and helpers | swap 0, oom.group 1                        |
  | `harness/session-<sessionId>` | one session tree                | `memory.max`=sessionLimit, swap 0, group 1 |

  `memory.oom.group` on every unit and not on the budget group means every
  kernel victim is a whole unit: on a unit's own limit the unit is the OOM
  domain; on the budget the kernel kills the highest cgroup with the flag set
  between its victim process and `harness`, which is exactly the victim's
  unit. Session units are created by the session launch step
  (`tightbeam harness-session-exec`), adapter units here, before the helper
  execs the adapter.

  Paths are cgroup paths (`/system.slice/x.service/harness`); `fs` is the
  mount (`/sys/fs/cgroup`, or a fake tree in tests).
  """

  @type layout :: %{fs: String.t(), root: String.t(), harness: String.t()}

  @doc """
  Arrange the layout under `cgroup.root` with `budget` bytes. When the gateway
  must split its own cgroup (`move_self`), every process of that cgroup moves
  to `<root>/gateway` first, so the root holds no processes and can enable the
  memory controller for its children.
  """
  @spec setup(String.t(), map(), non_neg_integer()) :: {:ok, layout()} | {:error, String.t()}
  def setup(fs, %{root: root, gateway: gateway} = cgroup, budget) do
    harness = Path.join(root, "harness")

    with :ok <- if(Map.get(cgroup, :move_self), do: move_all(fs, root, gateway), else: :ok),
         :ok <- enable_memory(fs, root),
         :ok <- mkdir(fs, harness),
         :ok <- write(fs, harness, "memory.swap.max", "0"),
         :ok <- write(fs, harness, "memory.oom.group", "0"),
         :ok <- write(fs, harness, "memory.max", Integer.to_string(budget)),
         :ok <- enable_memory(fs, harness) do
      {:ok, %{fs: fs, root: root, harness: harness}}
    end
  end

  defp move_all(fs, from, to) do
    with :ok <- mkdir(fs, to),
         {:ok, text} <- read(fs, from, "cgroup.procs") do
      text
      |> String.split("\n", trim: true)
      |> Enum.reduce_while(:ok, fn pid, :ok ->
        case write(fs, to, "cgroup.procs", pid) do
          :ok ->
            {:cont, :ok}

          # A process that ended between the read and the move is not a failure.
          {:error, _} = error ->
            if File.exists?("/proc/#{pid}"), do: {:halt, error}, else: {:cont, :ok}
        end
      end)
    end
  end

  # Writing "+memory" is idempotent; the read only skips a needless write.
  defp enable_memory(fs, cgroup) do
    case read(fs, cgroup, "cgroup.subtree_control") do
      {:ok, text} ->
        if "memory" in String.split(text),
          do: :ok,
          else: write(fs, cgroup, "cgroup.subtree_control", "+memory")

      {:error, _} ->
        write(fs, cgroup, "cgroup.subtree_control", "+memory")
    end
  end

  @doc "Set the budget group's `memory.max` (R17a: applies to the next decision)."
  @spec set_budget(layout(), non_neg_integer()) :: :ok | {:error, String.t()}
  def set_budget(%{fs: fs, harness: harness}, budget),
    do: write(fs, harness, "memory.max", Integer.to_string(budget))

  @doc """
  Lift the kernel's limits from the layout when the host leaves `enforced`
  (R12, R17): `memory.max` and `memory.swap.max` to `max` and
  `memory.oom.group` to 0 on the budget group and on every unit. Processes stay
  in their units, so custody and counting are unchanged.
  """
  @spec relax(layout()) :: :ok | {:error, String.t()}
  def relax(%{fs: fs, harness: harness} = layout) do
    with {:ok, units} <- units(layout) do
      relax_all(fs, [harness | units])
    end
  end

  defp relax_all(fs, cgroups) do
    cgroups
    |> Enum.flat_map(fn cgroup ->
      [
        write(fs, cgroup, "memory.max", "max"),
        write(fs, cgroup, "memory.swap.max", "max"),
        write(fs, cgroup, "memory.oom.group", "0")
      ]
    end)
    |> Enum.find(:ok, &match?({:error, _}, &1))
  end

  @doc """
  Restore the unit settings when the host becomes `enforced` again: swap 0
  and `memory.oom.group` 1 on every unit, and each session unit's own
  `sessionLimit` from `limits` (unit => bytes), the limit it was launched with.
  """
  @spec restore_units(layout(), %{optional(String.t()) => non_neg_integer()}) ::
          :ok | {:error, String.t()}
  def restore_units(%{fs: fs} = layout, limits) do
    with {:ok, units} <- units(layout), do: restore_all(fs, units, limits)
  end

  defp restore_all(fs, units, limits) do
    units
    |> Enum.flat_map(fn unit ->
      [write(fs, unit, "memory.swap.max", "0"), write(fs, unit, "memory.oom.group", "1")] ++
        case Map.get(limits, unit) do
          bytes when is_integer(bytes) ->
            [write(fs, unit, "memory.max", Integer.to_string(bytes))]

          _ ->
            []
        end
    end)
    |> Enum.find(:ok, &match?({:error, _}, &1))
  end

  @doc """
  Whether a cgroup carries none of this contract's limits: `memory.max` and
  `memory.swap.max` read `max` and `memory.oom.group` reads 0. A file that
  cannot be read is not evidence (v1.13 FS1).
  """
  @spec lifted?(String.t(), String.t()) :: boolean()
  def lifted?(fs, cgroup) do
    Enum.all?(
      [{"memory.max", "max"}, {"memory.swap.max", "max"}, {"memory.oom.group", "0"}],
      fn {file, value} -> match?({:ok, ^value}, read_trimmed(fs, cgroup, file)) end
    )
  end

  defp read_trimmed(fs, cgroup, file) do
    with {:ok, text} <- read(fs, cgroup, file), do: {:ok, String.trim(text)}
  end

  @doc "The adapter unit path for `launch_id`."
  @spec adapter_unit(layout(), String.t()) :: String.t()
  def adapter_unit(%{harness: harness}, launch_id),
    do: Path.join(harness, "adapter-" <> launch_id)

  @doc "The session unit path for harness session `sid`."
  @spec session_unit(layout(), String.t()) :: String.t()
  def session_unit(%{harness: harness}, sid), do: Path.join(harness, "session-" <> sid)

  @doc "Create the adapter unit (no limit of its own; it shares the budget)."
  @spec create_adapter_unit(layout(), String.t()) :: {:ok, String.t()} | {:error, String.t()}
  def create_adapter_unit(%{fs: fs} = layout, launch_id) do
    unit = adapter_unit(layout, launch_id)

    with :ok <- mkdir(fs, unit),
         :ok <- write(fs, unit, "memory.swap.max", "0"),
         :ok <- write(fs, unit, "memory.oom.group", "1"),
         do: {:ok, unit}
  end

  @doc "The filesystem directory of a cgroup path."
  @spec dir(String.t(), String.t()) :: String.t()
  def dir(fs, cgroup), do: Path.join(fs, String.trim_leading(cgroup, "/"))

  @doc "`memory.current` of a cgroup in bytes."
  @spec current(String.t(), String.t()) :: {:ok, non_neg_integer()} | :error
  def current(fs, cgroup) do
    case read(fs, cgroup, "memory.current") do
      {:ok, text} ->
        case Integer.parse(String.trim(text)) do
          {bytes, _} -> {:ok, bytes}
          :error -> :error
        end

      _ ->
        :error
    end
  end

  @doc "A cgroup's local OOM counters (`memory.events.local`)."
  @spec local_events(String.t(), String.t()) :: {:ok, map()} | :error
  def local_events(fs, cgroup) do
    case read(fs, cgroup, "memory.events.local") do
      {:ok, text} -> {:ok, parse_flat_keyed(text)}
      _ -> :error
    end
  end

  @doc """
  Whether a cgroup still holds processes (`cgroup.events` populated):
  `:gone` only when the cgroup no longer exists; a file that cannot be read is
  `:unreadable`, never empty.
  """
  @spec populated?(String.t(), String.t()) :: boolean() | :gone | :unreadable
  def populated?(fs, cgroup) do
    case File.read(Path.join(dir(fs, cgroup), "cgroup.events")) do
      {:ok, text} ->
        case parse_flat_keyed(text) do
          %{"populated" => populated} -> populated == 1
          _ -> :unreadable
        end

      {:error, :enoent} ->
        if File.dir?(dir(fs, cgroup)), do: :unreadable, else: :gone

      {:error, _} ->
        :unreadable
    end
  end

  @doc """
  Kill every process of a cgroup and its descendants (`cgroup.kill`). `:ok`
  only when the write was made (the kernel then kills every member); a unit
  that is not there is `{:error, :gone}`: nothing was sent.
  """
  @spec kill(String.t(), String.t()) :: :ok | {:error, term()}
  def kill(fs, cgroup) do
    if File.dir?(dir(fs, cgroup)),
      do: write(fs, cgroup, "cgroup.kill", "1"),
      else: {:error, :gone}
  end

  @doc "Remove an empty unit. A unit still populated, or gone already, is left."
  @spec remove(String.t(), String.t()) :: :ok | {:error, String.t()}
  def remove(fs, cgroup) do
    case File.rmdir(dir(fs, cgroup)) do
      :ok -> :ok
      {:error, :enoent} -> :ok
      {:error, reason} -> {:error, "#{cgroup} could not be removed: #{reason}"}
    end
  end

  @doc """
  Whether `path` exists: `true`, `false` (absent) or `:unknown` when it cannot
  be looked at. Only absence is evidence of absence.
  """
  @spec exists?(String.t()) :: boolean() | :unknown
  def exists?(path) do
    case File.stat(path) do
      {:ok, _} -> true
      {:error, reason} when reason in [:enoent, :enotdir] -> false
      {:error, _} -> :unknown
    end
  end

  @doc "The units directly under the budget group; a listing failure is an error."
  @spec units(layout()) :: {:ok, [String.t()]} | {:error, String.t()}
  def units(%{fs: fs, harness: harness}) do
    case File.ls(dir(fs, harness)) do
      {:ok, entries} ->
        # An entry that cannot be looked at may be a unit: it is listed, and
        # whoever reads it finds it unreadable.
        units =
          for entry <- entries,
              String.starts_with?(entry, "adapter-") or String.starts_with?(entry, "session-"),
              (case File.stat(Path.join(dir(fs, harness), entry)) do
                 {:ok, %File.Stat{type: type}} -> type == :directory
                 {:error, reason} -> reason not in [:enoent, :enotdir]
               end),
              do: Path.join(harness, entry)

        {:ok, units}

      {:error, reason} ->
        {:error, "#{harness} cannot be listed: #{reason}"}
    end
  end

  defp parse_flat_keyed(text) do
    for line <- String.split(text, "\n", trim: true),
        [key, value] <- [String.split(line)],
        {number, ""} <- [Integer.parse(value)],
        into: %{},
        do: {key, number}
  end

  defp mkdir(fs, cgroup) do
    case File.mkdir(dir(fs, cgroup)) do
      :ok -> :ok
      {:error, :eexist} -> :ok
      {:error, reason} -> {:error, "#{cgroup} could not be created: #{reason}"}
    end
  end

  defp read(fs, cgroup, file) do
    case File.read(Path.join(dir(fs, cgroup), file)) do
      {:ok, text} -> {:ok, text}
      {:error, reason} -> {:error, "#{cgroup}/#{file} could not be read: #{reason}"}
    end
  end

  defp write(fs, cgroup, file, value) do
    case File.write(Path.join(dir(fs, cgroup), file), value) do
      :ok -> :ok
      {:error, reason} -> {:error, "#{cgroup}/#{file} could not be written: #{reason}"}
    end
  end
end

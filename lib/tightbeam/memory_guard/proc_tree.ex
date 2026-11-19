defmodule Tightbeam.MemoryGuard.ProcTree do
  @moduledoc """
  Tree memory in `watched` mode (memory limits v1.1 §1): the sum of `VmRSS`
  and `VmSwap` over a tree's processes, read from `<root>/proc`. The sum
  over-counts shared pages, which errs toward safety. A tree is a process and
  every process whose parent chain reaches it.
  """

  @type proc :: %{
          pid: pos_integer(),
          ppid: non_neg_integer(),
          start: non_neg_integer(),
          bytes: non_neg_integer()
        }
  @type table :: %{pos_integer() => proc()}

  @doc "Every readable process under `<root>/proc`."
  @spec snapshot(String.t()) :: {:ok, table()} | :error
  def snapshot(root) do
    proc = Path.join(root, "proc")

    case File.ls(proc) do
      {:ok, entries} ->
        table =
          for entry <- entries,
              {pid, ""} <- [Integer.parse(entry)],
              {:ok, process} <- [read(proc, pid)],
              into: %{},
              do: {pid, process}

        {:ok, table}

      {:error, _} ->
        :error
    end
  end

  @doc "One process, or :error once it has gone."
  @spec read(String.t(), pos_integer()) :: {:ok, proc()} | :error
  def read(proc, pid) do
    with {:ok, stat} <- File.read(Path.join([proc, Integer.to_string(pid), "stat"])),
         {:ok, ppid, start} <- parse_stat(stat),
         {:ok, status} <- File.read(Path.join([proc, Integer.to_string(pid), "status"])) do
      {:ok, %{pid: pid, ppid: ppid, start: start, bytes: status_bytes(status)}}
    else
      _ -> :error
    end
  end

  # `comm` may contain spaces and parentheses; the fields after the last ")"
  # are fixed: state(3) ppid(4) ... starttime(22).
  defp parse_stat(stat) do
    case :binary.matches(stat, ")") do
      [] ->
        :error

      matches ->
        {position, 1} = List.last(matches)
        rest = binary_part(stat, position + 1, byte_size(stat) - position - 1)

        case String.split(rest) do
          [_state, ppid | fields] when length(fields) >= 18 ->
            with {ppid, ""} <- Integer.parse(ppid),
                 {start, ""} <- Integer.parse(Enum.at(fields, 17)) do
              {:ok, ppid, start}
            else
              _ -> :error
            end

          _ ->
            :error
        end
    end
  end

  defp status_bytes(status) do
    for line <- String.split(status, "\n", trim: true),
        [name, value] <- [String.split(line, ":", parts: 2)],
        name in ["VmRSS", "VmSwap"],
        [kb | _] <- [String.split(String.trim(value))],
        {number, ""} <- [Integer.parse(kb)],
        reduce: 0 do
      sum -> sum + number * 1024
    end
  end

  @doc "The pids of the tree rooted at `pid` (the root included), by parent chain."
  @spec tree(table(), pos_integer()) :: MapSet.t(pos_integer())
  def tree(table, pid) do
    if Map.has_key?(table, pid) do
      children = children_index(table)
      walk([pid], children, MapSet.new())
    else
      MapSet.new()
    end
  end

  @doc "Trees for several roots at once, with one child index."
  @spec trees(table(), [pos_integer()]) :: %{pos_integer() => MapSet.t(pos_integer())}
  def trees(table, roots) do
    children = children_index(table)

    Map.new(roots, fn root ->
      {root,
       if(Map.has_key?(table, root), do: walk([root], children, MapSet.new()), else: MapSet.new())}
    end)
  end

  defp children_index(table) do
    Enum.group_by(Map.values(table), & &1.ppid, & &1.pid)
  end

  defp walk([], _children, seen), do: seen

  defp walk([pid | rest], children, seen) do
    if MapSet.member?(seen, pid) do
      walk(rest, children, seen)
    else
      walk(Map.get(children, pid, []) ++ rest, children, MapSet.put(seen, pid))
    end
  end

  @doc "The memory of a set of pids."
  @spec bytes(table(), Enumerable.t()) :: non_neg_integer()
  def bytes(table, pids) do
    Enum.reduce(pids, 0, fn pid, sum ->
      case Map.fetch(table, pid) do
        {:ok, %{bytes: bytes}} -> sum + bytes
        :error -> sum
      end
    end)
  end
end

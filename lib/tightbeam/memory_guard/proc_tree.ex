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

  @doc """
  The processes under `<root>/proc` that exist, run as this gateway's own user,
  and cannot be read. Any of them may belong to a Tightbeam tree, so a tree's
  memory cannot be shown complete while one exists (v1.13 FS4, R12a). Other
  users' processes cannot be in a Tightbeam tree unless it changed user, and
  are not counted here.
  """
  @spec unreadable_own(String.t(), table()) :: [pos_integer()]
  def unreadable_own(root, table) do
    proc = Path.join(root, "proc")
    own = own_uid()

    case File.ls(proc) do
      {:ok, entries} ->
        for entry <- entries,
            {pid, ""} <- [Integer.parse(entry)],
            not Map.has_key?(table, pid),
            {:ok, %File.Stat{uid: uid}} <- [File.stat(Path.join(proc, entry))],
            uid == own,
            read(proc, pid) == :error,
            File.dir?(Path.join(proc, entry)),
            do: pid

      {:error, _} ->
        []
    end
  end

  defp own_uid do
    case File.stat("/proc/self") do
      {:ok, %File.Stat{uid: uid}} -> uid
      _ -> nil
    end
  end

  @doc """
  Whether `pid` exists under `<root>/proc` but cannot be read: a failed read
  of a known process, never mistaken for its end.
  """
  @spec unreadable?(String.t(), pos_integer()) :: boolean()
  def unreadable?(root, pid) do
    proc = Path.join(root, "proc")
    # The existence check follows the failed read, so a process that ended in
    # between reads as gone, not unreadable.
    read(proc, pid) == :error and File.dir?(Path.join(proc, Integer.to_string(pid)))
  end

  @doc "One process, or :error once it has gone."
  @spec read(String.t(), pos_integer()) :: {:ok, proc()} | :error
  def read(proc, pid) do
    with {:ok, stat} <- File.read(Path.join([proc, Integer.to_string(pid), "stat"])),
         {:ok, state, ppid, pgrp, sid, start} <- parse_stat(stat),
         {:ok, status} <- File.read(Path.join([proc, Integer.to_string(pid), "status"])) do
      {:ok,
       %{
         pid: pid,
         ppid: ppid,
         pgrp: pgrp,
         sid: sid,
         start: start,
         state: state,
         bytes: status_bytes(status)
       }}
    else
      _ -> :error
    end
  end

  # `comm` may contain spaces and parentheses; the fields after the last ")"
  # are fixed: state(3) ppid(4) pgrp(5) session(6) ... starttime(22).
  defp parse_stat(stat) do
    case :binary.matches(stat, ")") do
      [] ->
        :error

      matches ->
        {position, 1} = List.last(matches)
        rest = binary_part(stat, position + 1, byte_size(stat) - position - 1)

        case String.split(rest) do
          [state, ppid | fields] when length(fields) >= 18 ->
            with {ppid, ""} <- Integer.parse(ppid),
                 {pgrp, ""} <- Integer.parse(Enum.at(fields, 0)),
                 {sid, ""} <- Integer.parse(Enum.at(fields, 1)),
                 {start, ""} <- Integer.parse(Enum.at(fields, 17)) do
              {:ok, state, ppid, pgrp, sid, start}
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

  @doc """
  The processes still in the process group or session the launch step's
  leader `leader` started (the step `setsid`s, so both carry its pid), other
  than the leader, started no earlier than it, and not zombies. After the
  leader has gone its descendants are found this way, without a parent chain
  (v1.13 R2a, M-V7; matrix B2.stale, D1.absent, E2.absent): a read-only
  proof, never a reason to signal them.
  """
  @spec group_survivors(table(), pos_integer(), non_neg_integer() | nil) :: [pos_integer()]
  def group_survivors(table, leader, leader_start) do
    for {pid, process} <- table,
        pid != leader,
        process.state != "Z",
        Map.get(process, :pgrp) == leader or Map.get(process, :sid) == leader,
        is_nil(leader_start) or process.start >= leader_start,
        do: pid
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

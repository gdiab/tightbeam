defmodule Tightbeam.MemoryGuard.Probe do
  @moduledoc """
  Which memory-guard mode the gateway's own host can run in (memory limits
  v1.1 R12, R12a), read from `/proc` and the cgroup v2 filesystem. Nothing here
  changes a host setting; `Tightbeam.MemoryGuard.Cgroup` arranges only the
  subtree the host has already delegated (M-V5).

  - `enforced`: Linux, cgroup v2, the memory controller available in a cgroup
    subtree the gateway may create and write, swap accounting present, and an
    OOM kill inside it will not stop the gateway (under systemd the unit's
    `OOMPolicy` must be `continue`).
  - `watched`: `/proc` is readable but `enforced` is not available.
  - `count-only`: anything else (macOS, no `/proc/meminfo`).

  Every path is read under `:root` (default `/`), so tests use a fake tree.
  """

  @type mode :: :enforced | :watched | :count_only
  @type result :: %{
          mode: mode(),
          reason: String.t() | nil,
          mem_total: non_neg_integer() | nil,
          cgroup: %{root: String.t(), gateway: String.t(), move_self: boolean()} | nil
        }

  @doc "Probe the local host. Options: `:root`, `:os`, `:systemctl`, `:self_pid`."
  @spec probe(keyword()) :: result()
  def probe(opts \\ []) do
    root = Keyword.get(opts, :root, "/")
    os = Keyword.get(opts, :os, :os.type())

    case {os, mem_total(root)} do
      {{:unix, :linux}, {:ok, total}} ->
        case delegated_cgroup(root, opts) do
          {:ok, cgroup} -> %{mode: :enforced, reason: nil, mem_total: total, cgroup: cgroup}
          {:error, reason} -> %{mode: :watched, reason: reason, mem_total: total, cgroup: nil}
        end

      {{:unix, :linux}, :error} ->
        %{
          mode: :count_only,
          reason: "host memory cannot be read: /proc/meminfo is unreadable",
          mem_total: nil,
          cgroup: nil
        }

      {_other, _} ->
        %{
          mode: :count_only,
          reason: "host memory limits need Linux; only the resident cap applies on this system",
          mem_total: Keyword.get_lazy(opts, :mem_total, fn -> other_mem_total() end),
          cgroup: nil
        }
    end
  end

  @doc "`MemTotal` in bytes from `<root>/proc/meminfo`."
  @spec mem_total(String.t()) :: {:ok, non_neg_integer()} | :error
  def mem_total(root) do
    with {:ok, meminfo} <- meminfo(root),
         {:ok, total} <- Map.fetch(meminfo, "MemTotal"),
         do: {:ok, total}
  end

  @doc "Parsed `<root>/proc/meminfo`, values in bytes."
  @spec meminfo(String.t()) :: {:ok, %{String.t() => non_neg_integer()}} | :error
  def meminfo(root) do
    case File.read(Path.join(root, "proc/meminfo")) do
      {:ok, text} ->
        fields =
          for line <- String.split(text, "\n", trim: true),
              [name, rest] <- [String.split(line, ":", parts: 2)],
              [number | unit] <- [String.split(String.trim(rest))],
              {value, ""} <- [Integer.parse(number)],
              into: %{} do
            {name, if(unit == ["kB"], do: value * 1024, else: value)}
          end

        if Map.has_key?(fields, "MemTotal") and Map.has_key?(fields, "MemAvailable"),
          do: {:ok, fields},
          else: :error

      {:error, _} ->
        :error
    end
  end

  @doc "Host available: `MemAvailable / MemTotal` as a percentage, or :error."
  @spec available_percent(String.t()) :: {:ok, float()} | :error
  def available_percent(root) do
    case meminfo(root) do
      {:ok, %{"MemTotal" => total, "MemAvailable" => available}} when total > 0 ->
        {:ok, available * 100 / total}

      _ ->
        :error
    end
  end

  defp other_mem_total do
    case System.cmd("sysctl", ["-n", "hw.memsize"], stderr_to_stdout: true) do
      {text, 0} ->
        case Integer.parse(String.trim(text)) do
          {bytes, ""} -> bytes
          _ -> nil
        end

      _ ->
        nil
    end
  rescue
    _ -> nil
  end

  ## Delegation

  # The delegated root is the cgroup that holds the gateway's own cgroup when
  # that one is named `gateway` (systemd `DelegateSubgroup=gateway`), or the
  # gateway's own cgroup when it may be split (the gateway then moves itself
  # into a `gateway` child first).
  defp delegated_cgroup(root, opts) do
    with {:ok, own} <- own_cgroup(root, Keyword.get(opts, :self_pid, "self")),
         fs = Path.join(root, "sys/fs/cgroup"),
         true <- File.exists?(Path.join(fs, "cgroup.controllers")) || {:error, no_v2()},
         {:ok, delegated, move_self} <- delegated_root(fs, own),
         :ok <- controller_available(fs, delegated),
         :ok <- swap_accounting(fs, delegated),
         :ok <- oom_policy(own, opts) do
      {:ok,
       %{
         root: delegated,
         gateway: if(move_self, do: Path.join(delegated, "gateway"), else: own),
         move_self: move_self
       }}
    end
  end

  @doc """
  Where this contract's budget group could exist, read-only: `<delegated
  root>/harness` for either delegation shape around the gateway's own cgroup.
  `:error` when the gateway's own cgroup cannot be read.
  """
  @spec harness_candidates(String.t()) :: {:ok, [String.t()]} | :error
  def harness_candidates(root \\ "/") do
    case own_cgroup(root, "self") do
      {:ok, own} ->
        parents = if Path.basename(own) == "gateway", do: [Path.dirname(own), own], else: [own]
        {:ok, Enum.map(parents, &Path.join(&1, "harness"))}

      {:error, _} ->
        :error
    end
  end

  defp no_v2,
    do:
      "per-agent memory limits are checked every second, not enforced by the kernel: " <>
        "this host has no cgroup v2"

  defp own_cgroup(root, pid) do
    case File.read(Path.join([root, "proc", to_string(pid), "cgroup"])) do
      {:ok, text} ->
        case Enum.find(String.split(text, "\n", trim: true), &String.starts_with?(&1, "0::")) do
          "0::" <> path -> {:ok, path}
          nil -> {:error, no_v2()}
        end

      {:error, _} ->
        {:error, no_v2()}
    end
  end

  defp delegated_root(fs, own) do
    parent = Path.dirname(own)

    cond do
      Path.basename(own) == "gateway" and own != "/gateway" and writable_cgroup?(fs, parent) ->
        {:ok, parent, false}

      own != "/" and writable_cgroup?(fs, own) ->
        {:ok, own, true}

      true ->
        {:error,
         "per-agent memory limits are checked every second, not enforced by the kernel: " <>
           "the Tightbeam service is not delegated a cgroup"}
    end
  end

  defp writable_cgroup?(fs, cgroup) do
    dir = Path.join(fs, String.trim_leading(cgroup, "/"))

    Enum.all?(["cgroup.procs", "cgroup.subtree_control"], fn file ->
      writable?(Path.join(dir, file))
    end) and writable?(dir)
  end

  defp writable?(path) do
    case File.stat(path) do
      {:ok, %File.Stat{access: access}} -> access in [:read_write, :write]
      _ -> false
    end
  end

  defp controller_available(fs, delegated) do
    path = Path.join([fs, String.trim_leading(delegated, "/"), "cgroup.controllers"])

    case File.read(path) do
      {:ok, text} ->
        if "memory" in String.split(text),
          do: :ok,
          else:
            {:error,
             "per-agent memory limits are checked every second, not enforced by the kernel: " <>
               "the delegated cgroup has no memory controller"}

      {:error, _} ->
        {:error,
         "per-agent memory limits are checked every second, not enforced by the kernel: " <>
           "the delegated cgroup cannot be read"}
    end
  end

  # memory.swap.max exists only with swap accounting; without it swap cannot be
  # excluded from harness units (R12c), so the kernel cannot enforce R1/R2.
  defp swap_accounting(fs, delegated) do
    probe = Path.join([fs, String.trim_leading(delegated, "/"), "memory.swap.max"])

    if File.exists?(probe) or File.exists?(Path.join(fs, "memory.swap.max")) or
         swap_file_in_children?(fs, delegated),
       do: :ok,
       else:
         {:error,
          "per-agent memory limits are checked every second, not enforced by the kernel: " <>
            "this kernel does not account swap per cgroup"}
  end

  defp swap_file_in_children?(fs, delegated) do
    dir = Path.join(fs, String.trim_leading(delegated, "/"))

    case File.ls(dir) do
      {:ok, entries} ->
        Enum.any?(entries, fn entry ->
          File.exists?(Path.join([dir, entry, "memory.swap.max"]))
        end)

      _ ->
        false
    end
  end

  # systemd's default OOMPolicy=stop ends the whole service on the first kernel
  # OOM kill inside it, which would turn one R1 kill into a gateway stop.
  defp oom_policy(own, opts) do
    case service_unit(own) do
      nil ->
        :ok

      {scope, unit} ->
        runner = Keyword.get(opts, :systemctl, &systemctl/1)
        args = if scope == :user, do: ["--user"], else: []

        case runner.(args ++ ["show", unit, "-p", "OOMPolicy", "--value"]) do
          {:ok, "continue"} ->
            :ok

          {:ok, policy} ->
            {:error,
             "per-agent memory limits are checked every second, not enforced by the kernel: " <>
               "#{unit} has OOMPolicy=#{policy}, which would stop the whole service on one agent's kill"}

          # F5: a systemctl that fails or does not answer is no evidence of
          # `continue`; the host runs watched and says why.
          _ ->
            {:error,
             "per-agent memory limits are checked every second, not enforced by the kernel: " <>
               "the OOMPolicy of #{unit} cannot be read"}
        end
    end
  end

  defp service_unit(cgroup) do
    parts = String.split(cgroup, "/", trim: true)

    case Enum.filter(parts, &String.ends_with?(&1, ".service")) do
      [] ->
        nil

      services ->
        scope = if Enum.any?(parts, &String.starts_with?(&1, "user@")), do: :user, else: :system
        {scope, List.last(services)}
    end
  end

  defp systemctl(args) do
    case System.cmd("systemctl", args, stderr_to_stdout: true) do
      {text, 0} -> {:ok, String.trim(text)}
      _ -> :error
    end
  rescue
    _ -> :error
  end
end

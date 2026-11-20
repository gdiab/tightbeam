defmodule Tightbeam.MemoryGuard.RootPath do
  @moduledoc """
  FS9 Step 2's root-path check (memory limits v1.13; PO `att_b685f272`): does
  the OS user that the gateway and every agent share have a root-equivalent
  path? Each mechanism reads `absent`, `present` or `unknown`:

  1. membership of `docker`, `lxd`, `lxc`, `libvirt`, `disk` or `kvm`;
  2. a passwordless `sudo` entry (`sudo -n -l` as that user);
  3. write access to the Docker, containerd, LXD or libvirt control socket.

  The finding chooses the override's statement: **strict** only when every
  mechanism is positively `absent`, otherwise **residual**. It never disables
  the override. Run as the gateway's own user, read-only.
  """

  @groups ~w(docker lxd lxc libvirt disk kvm)
  @sockets [
    "/var/run/docker.sock",
    "/run/docker.sock",
    "/run/containerd/containerd.sock",
    "/var/snap/lxd/common/lxd/unix.socket",
    "/var/lib/lxd/unix.socket",
    "/run/libvirt/libvirt-sock",
    "/var/run/libvirt/libvirt-sock"
  ]

  @doc """
  The finding: `%{"groups" => m, "sudo" => m, "sockets" => m}`, where each `m`
  is `%{"result" => "absent" | "present" | "unknown", "detail" => term}`.
  `runner` runs a command (`{output, status}`), injectable for tests.
  """
  @spec finding(keyword()) :: map()
  def finding(opts \\ []) do
    runner = Keyword.get(opts, :runner, &default_runner/2)

    %{
      "groups" => groups(runner),
      "sudo" => sudo(runner),
      "sockets" => sockets(runner, Keyword.get(opts, :sockets, @sockets))
    }
  end

  defp groups(runner) do
    case safe(runner, "id", ["-Gn"]) do
      {output, 0} ->
        found = output |> String.split() |> Enum.filter(&(&1 in @groups))

        if found == [],
          do: %{"result" => "absent", "detail" => []},
          else: %{"result" => "present", "detail" => found}

      other ->
        %{"result" => "unknown", "detail" => inspect(other)}
    end
  end

  # `sudo -n -l` lists the user's entries without a password only when it
  # can; a NOPASSWD entry is a passwordless path.
  defp sudo(runner) do
    case safe(runner, "sudo", ["-n", "-l"]) do
      {output, 0} ->
        if String.contains?(output, "NOPASSWD"),
          do: %{"result" => "present", "detail" => "a passwordless sudo entry"},
          else: %{"result" => "absent", "detail" => "sudo entries need a password"}

      {output, _status} when is_binary(output) ->
        cond do
          output =~ ~r/password is required|may not run sudo|not in the sudoers/ ->
            %{"result" => "absent", "detail" => "no sudo without a password"}

          true ->
            %{"result" => "unknown", "detail" => String.trim(output)}
        end

      other ->
        %{"result" => "unknown", "detail" => inspect(other)}
    end
  end

  defp sockets(runner, sockets) do
    results =
      for path <- sockets do
        cond do
          not File.exists?(path) ->
            {path, "absent"}

          true ->
            case safe(runner, "test", ["-w", path]) do
              {_, 0} -> {path, "present"}
              {_, 1} -> {path, "absent"}
              _ -> {path, "unknown"}
            end
        end
      end

    present = for {path, "present"} <- results, do: path
    unknown = for {path, "unknown"} <- results, do: path

    cond do
      present != [] -> %{"result" => "present", "detail" => present}
      unknown != [] -> %{"result" => "unknown", "detail" => unknown}
      true -> %{"result" => "absent", "detail" => []}
    end
  end

  defp safe(runner, command, args) do
    runner.(command, args)
  rescue
    error -> {:error, Exception.message(error)}
  end

  defp default_runner(command, args) do
    case System.find_executable(command) do
      nil -> {:error, "#{command} is not installed"}
      path -> System.cmd(path, args, stderr_to_stdout: true)
    end
  end

  @doc "`\"strict\"` when every mechanism is positively absent, else `\"residual\"`."
  @spec kind(map()) :: String.t()
  def kind(finding) do
    if Enum.all?(Map.values(finding), &(&1["result"] == "absent")),
      do: "strict",
      else: "residual"
  end

  @doc "The sentence the override prints and records for a finding."
  @spec statement(map()) :: String.t()
  def statement(finding) do
    case kind(finding) do
      "strict" ->
        "No agent-reachable root path was found among those checked (container, hypervisor " <>
          "and raw-device groups; passwordless sudo; container and hypervisor sockets). " <>
          "Paths that were not checked cannot be ruled out."

      "residual" ->
        paths =
          for {name, %{"result" => result} = m} <- Enum.sort(finding), result != "absent" do
            if result == "present",
              do: "#{name} (#{Enum.join(List.wrap(m["detail"]), ", ")})",
              else: "a path that could not be checked (#{name})"
          end

        "This machine's agents run as a user that can gain root, here through " <>
          Enum.join(paths, "; ") <>
          ". So a process with that access, including an agent breaking its rules, could also " <>
          "run this override."
    end
  end
end

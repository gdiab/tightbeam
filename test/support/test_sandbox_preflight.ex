defmodule Tightbeam.TestSandboxPreflight do
  @moduledoc false

  # F1 (wi_34a7be66) L2: the suite refuses to run unless scripts/test_sandbox.sh
  # built its sandbox before this VM booted. A test that can see an ancestor
  # .tightbeam-session, the real HOME, a credential variable or a real harness
  # tool can reach a live gateway or a real credential; this check makes that a
  # refusal instead of a leak. It launches nothing and has no disable switch:
  # every condition is read from the VM's own state.

  @marker ".tightbeam-test-sandbox"

  # The launcher's env -i allowlist, the named credential-free passthroughs it
  # copies only when set, and what the BEAM's own launch scripts export.
  @allowed_env ~w(
    HOME XDG_CONFIG_HOME XDG_DATA_HOME XDG_STATE_HOME XDG_CACHE_HOME PATH TMPDIR
    LANG LC_ALL LC_CTYPE TERM MIX_ENV MIX_HOME HEX_HOME HEX_OFFLINE
    GIT_CONFIG_GLOBAL GIT_CONFIG_NOSYSTEM CARGO_HOME CARGO_NET_OFFLINE
    CARGO_TARGET_DIR TIGHTBEAM_TEST_SANDBOX
    TIGHTBEAM_AUTHORITATIVE_GATE TIGHTBEAM_GATE_NODE TIGHTBEAM_PORT
    DD36_DARWIN_DIAGNOSTIC_DIR RUNNER_TEMP CANDIDATE_SHA
    BINDIR EMU PROGNAME ROOTDIR PWD OLDPWD SHLVL _ __CF_USER_TEXT_ENCODING
  )

  @forbidden_tools ~w(gh ssh scp sftp op codex claude cursor-agent pi harklight-agent)

  @doc "The allowed environment names, shared with Tightbeam.TestIsolation."
  def allowed_env, do: @allowed_env

  @doc "Tool names that must never resolve inside the sandbox."
  def forbidden_tools, do: @forbidden_tools

  @doc """
  Every reason this VM is not inside a valid test sandbox, as strings. Empty
  means the suite may run. `repo` is the repository root.
  """
  def problems(repo) do
    env = System.get_env()
    root = env["TIGHTBEAM_TEST_SANDBOX"]
    home = env["HOME"]

    sandbox_problems(root, home) ++
      session_problems(repo, home) ++
      env_problems(env) ++
      path_problems(repo, root, env["PATH"]) ++
      home_problems(home)
  end

  @doc "Halt the VM with the named problems unless the sandbox is valid."
  def enforce!(repo) do
    case problems(repo) do
      [] ->
        :ok

      problems ->
        IO.puts(:stderr, """

        This suite cannot run here: it is not inside the test sandbox.

        #{Enum.map_join(problems, "\n", &"  - #{&1}")}

        Local suites run only through scripts/test_sandbox.sh, from a checkout
        outside any Tightbeam session tree, or on hosted CI. A run outside the
        sandbox can resolve a live gateway or a real credential (wi_34a7be66).
        """)

        System.halt(78)
    end
  end

  @doc "The .tightbeam-session found in `path`'s ancestry, the way the CLI walks it."
  def session_ancestor(path) do
    path
    |> canonical()
    |> ancestors()
    |> Enum.map(&Path.join(&1, ".tightbeam-session"))
    |> Enum.find(&File.exists?/1)
  end

  @doc "Whether `path` resolves inside the sandbox `root`."
  def inside?(path, root) when is_binary(path) and is_binary(root) do
    path = canonical(path)
    root = canonical(root)
    path == root or String.starts_with?(path, root <> "/")
  end

  def inside?(_path, _root), do: false

  @doc "Resolve symlinks in every existing prefix of `path`."
  def canonical(path) do
    path
    |> Path.expand()
    |> Path.split()
    |> Enum.reduce("/", fn part, acc -> resolve(Path.join(acc, part), 0) end)
  end

  defp resolve(path, depth) when depth < 40 do
    case File.read_link(path) do
      {:ok, target} -> target |> Path.expand(Path.dirname(path)) |> canonical_depth(depth + 1)
      {:error, _} -> path
    end
  end

  defp canonical_depth(path, depth) do
    path
    |> Path.split()
    |> Enum.reduce("/", fn part, acc -> resolve(Path.join(acc, part), depth) end)
  end

  defp ancestors(path) do
    Stream.unfold(path, fn
      nil -> nil
      "/" -> {"/", nil}
      dir -> {dir, Path.dirname(dir)}
    end)
  end

  defp sandbox_problems(root, home) do
    cond do
      not is_binary(root) or root == "" ->
        ["TIGHTBEAM_TEST_SANDBOX is not set (run through scripts/test_sandbox.sh)"]

      not File.regular?(Path.join(root, @marker)) ->
        ["#{root} has no #{@marker} marker"]

      true ->
        user_home = System.user_home!()

        [
          if(user_home != home,
            do: "the VM's home #{user_home} is not $HOME #{inspect(home)}"
          ),
          if(not inside?(user_home, root),
            do: "the VM's home #{user_home} is outside the sandbox #{root}"
          )
        ]
        |> Enum.reject(&is_nil/1)
    end
  end

  defp session_problems(repo, home) do
    roots =
      [
        File.cwd!(),
        Path.join(File.cwd!(), "tmp"),
        Application.get_env(:tightbeam, :test_suite_tmp),
        home
      ]
      |> Enum.reject(&(is_nil(&1) or &1 == ""))
      |> Kernel.++([repo])

    for root <- roots, found = session_ancestor(root) do
      "#{found} is in the ancestry of #{root}; the CLI would use that session's credential"
    end
  end

  defp env_problems(env) do
    case env |> Map.keys() |> Enum.reject(&(&1 in @allowed_env)) |> Enum.sort() do
      [] -> []
      extra -> ["environment variables outside the allowlist: #{Enum.join(extra, ", ")}"]
    end
  end

  @doc """
  PATH directories a child may see besides the toolbox and the repository CLI
  build: the running VM's own OTP bin directories, which OTP's erl launcher
  prepends to PATH. They hold only OTP's executables.
  """
  def vm_bin_dirs do
    root = :code.root_dir() |> to_string()
    erts = Path.join(root, "erts-#{:erlang.system_info(:version)}/bin")
    [Path.join(root, "bin"), erts]
  end

  defp path_problems(repo, root, path) do
    allowed =
      [Path.join(root || "/nonexistent", "bin"), Path.join(repo, "cli/target/release")] ++
        vm_bin_dirs()

    entries = String.split(path || "", ":", trim: true)

    outside =
      for entry <- entries,
          not Enum.any?(allowed, &(canonical(entry) == canonical(&1))),
          do: "PATH entry #{entry} is not the sandbox toolbox or the repository CLI build"

    tightbeam =
      case System.find_executable("tightbeam") do
        nil ->
          []

        found ->
          if canonical(found) == canonical(Path.join(repo, "cli/target/release/tightbeam")),
            do: [],
            else: ["tightbeam resolves to #{found}, not this repository's build"]
      end

    exposed =
      for tool <- @forbidden_tools,
          found = System.find_executable(tool),
          do: "#{tool} resolves to #{found}"

    outside ++ tightbeam ++ exposed
  end

  defp home_problems(home) do
    if is_binary(home) and File.exists?(Path.join(home, ".tightbeam")),
      do: ["#{home}/.tightbeam exists; a test could read a gateway credential from it"],
      else: []
  end
end

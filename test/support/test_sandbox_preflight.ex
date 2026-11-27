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
    TMP TEMP RUSTUP_HOME RUSTC RUSTDOC CODEX_HOME
    TIGHTBEAM_TEST_ROOT TIGHTBEAM_BASE_DIR TIGHTBEAM_HOME TIGHTBEAM_TEST_TRIPWIRE_LOG
    TIGHTBEAM_RUST_TEST_PARENT_PID
  )

  # F1 erratum 2 C2: the suite variables the repair's config/test.exs (and the
  # Rust isolation constructor) set for themselves. Each is accepted only when it
  # lies under the sandbox root.
  @suite_paths ~w(
    TMP TEMP RUSTUP_HOME RUSTC RUSTDOC CODEX_HOME CARGO_HOME XDG_CONFIG_HOME
    GIT_CONFIG_GLOBAL TIGHTBEAM_TEST_ROOT TIGHTBEAM_BASE_DIR TIGHTBEAM_HOME
    TIGHTBEAM_TEST_TRIPWIRE_LOG
  )

  # Erratum 1 rev 4 L2 (d) adds the privilege-raising tools.
  @forbidden_tools ~w(gh ssh scp sftp op codex claude cursor-agent pi harklight-agent
                      sudo su doas pkexec)

  # The node name scripts/verify_mix.sh makes for its own run: a fixed prefix
  # and mktemp's eight-character suffix. scripts/test_sandbox.sh refuses any
  # other TIGHTBEAM_GATE_NODE with the same pattern.
  @gate_node ~r/\Atightbeam_mix_gate_[A-Za-z0-9]{8}\z/

  # The launcher's ssh stand-in: something named ssh must resolve because the
  # product resolves it for remote launch vectors, and this one only refuses.
  # The exact bytes scripts/test_sandbox.sh writes; it refuses and exits 255
  # without executing anything.
  @ssh_tripwire """
  #!/bin/sh
  # tightbeam-test-sandbox ssh tripwire (wi_34a7be66)
  echo "ssh: tripwire in the Tightbeam test sandbox; no remote access" >&2
  exit 255
  """

  @doc "The exact content of the launcher's ssh tripwire."
  def ssh_tripwire, do: @ssh_tripwire

  @doc """
  Whether `path` is the launcher's ssh tripwire: exactly `<root>/bin/ssh` with
  exactly the tripwire's bytes. Nothing else named ssh is accepted.
  """
  def ssh_tripwire?(path, root) do
    tripwire = is_binary(root) && Path.join(root, "bin/ssh")

    is_binary(tripwire) and canonical(path) == canonical(tripwire) and
      File.read(tripwire) == {:ok, @ssh_tripwire}
  end

  @doc "The sandbox root the preflight recorded for this VM, or nil."
  def recorded_root, do: :persistent_term.get({__MODULE__, :sandbox_root}, nil)

  @doc "The allowed environment names, shared with Tightbeam.TestIsolation."
  def allowed_env, do: @allowed_env

  @doc "The only TIGHTBEAM_GATE_NODE values a suite may carry."
  def gate_node_pattern, do: @gate_node

  @doc "Tool names that must never resolve inside the sandbox."
  def forbidden_tools, do: @forbidden_tools

  @doc """
  Every reason this VM is not inside a valid test sandbox, as strings. Empty
  means the suite may run. `repo` is the repository root.
  """
  #
  # `phase` is `:first` for the first check in a VM (before the repair's
  # config/test.exs has re-homed it), and `:suite` for the test_helper.exs check
  # after that setup (F1 erratum 2 C7, C9).
  def problems(repo, phase \\ :first) do
    env = System.get_env()
    root = env["TIGHTBEAM_TEST_SANDBOX"]
    home = env["HOME"]

    sandbox_problems(root, home, phase) ++
      marker_problems(root, phase) ++
      session_problems(repo, home) ++
      env_problems(env) ++
      suite_path_problems(env, root) ++
      passthrough_problems(env) ++
      path_problems(repo, root, env["PATH"], env["TIGHTBEAM_TEST_ROOT"]) ++
      home_problems(home)
  end

  @doc "Halt the VM with the named problems unless the sandbox is valid."
  def enforce!(repo, phase \\ :first) do
    case problems(repo, phase) do
      [] ->
        if phase == :first do
          :persistent_term.put(
            {__MODULE__, :sandbox_root},
            System.get_env("TIGHTBEAM_TEST_SANDBOX")
          )
        end

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
    |> Enum.find(&(file_type(&1) != nil))
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
    case :prim_file.read_link(path) do
      {:ok, target} ->
        target
        |> IO.chardata_to_string()
        |> Path.expand(Path.dirname(path))
        |> canonical_depth(depth + 1)

      {:error, _} ->
        path
    end
  end

  # Path resolution reads the filesystem through :prim_file, in the calling
  # process, rather than through the VM's single file server. Every async test
  # shares that server, and a launch check makes on the order of a hundred of
  # these reads; queued behind the async phase's file traffic they timed out a
  # test with many launches on a loaded macOS runner.
  @doc "The type File.stat/1 would report for `path` (following links), or nil."
  def file_type(path) do
    case :prim_file.read_file_info(path) do
      {:ok, info} -> elem(info, 2)
      {:error, _} -> nil
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

  defp sandbox_problems(root, home, phase) do
    cond do
      not is_binary(root) or root == "" ->
        ["TIGHTBEAM_TEST_SANDBOX is not set (run through scripts/test_sandbox.sh)"]

      not File.regular?(Path.join(root, @marker)) ->
        ["#{root} has no #{@marker} marker"]

      true ->
        user_home = System.user_home!()

        [
          # Erratum 2 C7: equality before the repair re-homes the VM; afterwards
          # both homes must still lie in the sandbox.
          if(phase == :first and user_home != home,
            do: "the VM's home #{user_home} is not $HOME #{inspect(home)}"
          ),
          if(not inside?(user_home, root),
            do: "the VM's home #{user_home} is outside the sandbox #{root}"
          ),
          if(phase == :suite and not (is_binary(home) and inside?(home, root)),
            do: "$HOME #{inspect(home)} is outside the sandbox #{root}"
          )
        ]
        |> Enum.reject(&is_nil/1)
    end
  end

  # Erratum 2 C9 (3): after the repair's scrubs the marker must still be the one
  # the first check validated and recorded.
  defp marker_problems(_root, :first), do: []

  defp marker_problems(root, :suite) do
    case recorded_root() do
      nil ->
        ["the first sandbox check did not run in this VM (config/test.exs)"]

      ^root ->
        []

      recorded ->
        ["TIGHTBEAM_TEST_SANDBOX changed after the first check (was #{recorded})"]
    end
  end

  # Erratum 2 C2: the repair's suite variables point inside the sandbox.
  defp suite_path_problems(env, root) do
    for name <- @suite_paths,
        value = env[name],
        is_binary(value),
        not (is_binary(root) and inside?(value, root)),
        do: "#{name} #{value} is outside the sandbox #{root}"
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

  # b0's conditions on the launcher's named passthrough (asg_b30d5c78): the
  # gateway port is pinned to 0 (OS-assigned), so no suite gateway takes a fixed
  # or production port such as 11373; the gate node is one verify_mix.sh made
  # for this run, never a live node's name, so the suite makes no distributed
  # Erlang contact with a live node; the gate claim is the literal "1" beside
  # such a node; the CI values have shapes that cannot carry a credential.
  defp passthrough_problems(env) do
    runner_temp = env["RUNNER_TEMP"]

    [
      if(env["TIGHTBEAM_PORT"] not in [nil, "0"],
        do:
          "TIGHTBEAM_PORT=#{env["TIGHTBEAM_PORT"]}: the sandbox pins the test gateway " <>
            "port to 0 (OS-assigned)"
      ),
      if(env["TIGHTBEAM_GATE_NODE"] && not Regex.match?(@gate_node, env["TIGHTBEAM_GATE_NODE"]),
        do:
          "TIGHTBEAM_GATE_NODE=#{inspect(env["TIGHTBEAM_GATE_NODE"])} does not match " <>
            "#{Regex.source(@gate_node)}, the node scripts/verify_mix.sh makes for its run"
      ),
      case {env["TIGHTBEAM_AUTHORITATIVE_GATE"], env["TIGHTBEAM_GATE_NODE"]} do
        {nil, _node} ->
          nil

        {"1", node} when is_binary(node) ->
          nil

        {"1", nil} ->
          "TIGHTBEAM_AUTHORITATIVE_GATE is set without TIGHTBEAM_GATE_NODE"

        {other, _node} ->
          "TIGHTBEAM_AUTHORITATIVE_GATE=#{inspect(other)} is not the gate claim \"1\""
      end,
      if(env["CANDIDATE_SHA"] && not Regex.match?(~r/\A[0-9a-f]{40}\z/, env["CANDIDATE_SHA"]),
        do: "CANDIDATE_SHA is not a 40-character commit id"
      ),
      if(runner_temp && Path.type(runner_temp) != :absolute,
        do: "RUNNER_TEMP is not an absolute path"
      ),
      if(
        env["DD36_DARWIN_DIAGNOSTIC_DIR"] &&
          not (is_binary(runner_temp) and
                 inside?(env["DD36_DARWIN_DIAGNOSTIC_DIR"], runner_temp)),
        do: "DD36_DARWIN_DIAGNOSTIC_DIR is not a directory under RUNNER_TEMP"
      )
    ]
    |> Enum.reject(&is_nil/1)
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

  @doc """
  Whether `path` is one of the repair's tripwires (config/test.exs): a file in
  `<TIGHTBEAM_TEST_ROOT>/tripwire-bin` under the sandbox root that only logs its
  name and exits 97. Erratum 2 C3, C4 accept it in place of `nil`.
  """
  def repair_tripwire?(path, _root, _test_root) when not is_binary(path), do: false

  def repair_tripwire?(path, root, test_root) do
    dir = is_binary(test_root) && Path.join(test_root, "tripwire-bin")

    is_binary(dir) and is_binary(root) and inside?(test_root, root) and
      (canonical(Path.dirname(path)) == canonical(dir) or
         enclosing_repair_dir?(Path.dirname(path), root, test_root)) and
      match?(
        {:ok, "#!/bin/sh\nif [ \"$#\" = 1 ] && [ \"$1\" = --version ]; then" <> _},
        File.read(path)
      ) and
      String.ends_with?(File.read!(path), "\nexit 97\n")
  end

  # Ruling art_1adf97db section 3 (erratum 2 C3): a nested MIX_ENV=test suite
  # inherits its enclosing suite's repair directories on PATH. One is accepted
  # only as `<A>/tripwire-bin` or `<A>/tool-bin` of an enclosing suite root A:
  # a strict ancestor of this suite's test root, inside the sandbox root, of
  # the repair's suite-root shape, holding exactly the repair's own files.
  @suite_root_shape ~r/\Atightbeam-test-\d+-[A-Za-z0-9_-]+\z/
  @tripwire_shape ~r/\A#!\/bin\/sh\nif \[ "\$#" = 1 \] && \[ "\$1" = --version \]; then printf 'synthetic 1\.0\\n'; exit 0; fi\nprintf '%s\\n' '([^'\n]+)' >> '((?:[^']|'"'"')+)'\nexit 97\n\z/
  @tool_wrapper_shape ~r/\A#!\/bin\/sh\nexec '((?:[^']|'"'"')+)' "\$@"\n\z/

  @doc "Whether `dir` is an enclosing suite's validated repair directory."
  def enclosing_repair_dir?(dir, root, test_root) do
    dir = canonical(dir)
    suite = Path.dirname(dir)

    is_binary(root) and is_binary(test_root) and inside?(test_root, root) and
      Path.basename(dir) in ["tripwire-bin", "tool-bin"] and
      suite != canonical(test_root) and suite != canonical(root) and
      inside?(test_root, suite) and inside?(suite, root) and
      Regex.match?(@suite_root_shape, Path.basename(suite)) and
      repair_dir_contents?(Path.basename(dir), dir, suite)
  end

  defp repair_dir_contents?("tripwire-bin", dir, suite) do
    log = canonical(Path.join(suite, "forbidden-execution"))

    case File.ls(dir) do
      {:ok, [_ | _] = names} ->
        Enum.all?(names, fn name ->
          path = Path.join(dir, name)

          with {:ok, %File.Stat{type: :regular}} <- File.lstat(path),
               {:ok, bytes} <- File.read(path),
               [_, ^name, quoted_log] <- Regex.run(@tripwire_shape, bytes) do
            canonical(unquote_sh(quoted_log)) == log
          else
            _ -> false
          end
        end)

      _ ->
        false
    end
  end

  defp repair_dir_contents?("tool-bin", dir, _suite) do
    case File.ls(dir) do
      {:ok, names} ->
        Enum.sort(names) == ~w(cargo rustc rustdoc) and
          Enum.all?(names, fn name ->
            path = Path.join(dir, name)

            with {:ok, %File.Stat{type: :regular}} <- File.lstat(path),
                 {:ok, bytes} <- File.read(path),
                 [_, quoted_target] <- Regex.run(@tool_wrapper_shape, bytes),
                 target = unquote_sh(quoted_target),
                 true <- Path.basename(target) == name,
                 {:ok, %File.Stat{type: :regular}} <- File.lstat(target) do
              true
            else
              _ -> false
            end
          end)

      _ ->
        false
    end
  end

  # The repair single-quotes paths for sh, writing ' as '"'"'.
  defp unquote_sh(quoted), do: String.replace(quoted, "'\"'\"'", "'")

  defp path_problems(repo, root, path, test_root) do
    # Erratum 2 C3: the repair's own PATH additions are accepted besides the
    # toolbox and the repository CLI build.
    repair_dirs =
      if is_binary(test_root) and is_binary(root) and inside?(test_root, root),
        do: [Path.join(test_root, "tripwire-bin"), Path.join(test_root, "tool-bin")],
        else: []

    allowed =
      [Path.join(root || "/nonexistent", "bin"), Path.join(repo, "cli/target/release")] ++
        [Path.join(repo, "priv/harness_cli")] ++ repair_dirs ++ vm_bin_dirs()

    entries = String.split(path || "", ":", trim: true)

    outside =
      for entry <- entries,
          not Enum.any?(allowed, &(canonical(entry) == canonical(&1))),
          not enclosing_repair_dir?(entry, root, test_root),
          do: "PATH entry #{entry} is not the sandbox toolbox or the repository CLI build"

    tightbeam =
      case System.find_executable("tightbeam") do
        nil ->
          []

        found ->
          # Erratum 2 C4: bare tightbeam never reaches an installed CLI; it is
          # this repository's build or the repair's tripwire.
          if canonical(found) == canonical(Path.join(repo, "cli/target/release/tightbeam")) or
               repair_tripwire?(found, root, test_root),
             do: [],
             else: ["tightbeam resolves to #{found}, not this repository's build or a tripwire"]
      end

    # An absent tool is the safe state: only a name that resolves is judged.
    exposed =
      for tool <- @forbidden_tools,
          found = System.find_executable(tool),
          is_binary(found),
          not (tool == "ssh" and ssh_tripwire?(found, root)),
          not repair_tripwire?(found, root, test_root),
          do: "#{tool} resolves to #{found}"

    outside ++ tightbeam ++ exposed
  end

  defp home_problems(home) do
    if is_binary(home) and File.exists?(Path.join(home, ".tightbeam")),
      do: ["#{home}/.tightbeam exists; a test could read a gateway credential from it"],
      else: []
  end
end

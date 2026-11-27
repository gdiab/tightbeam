defmodule Tightbeam.TestIsolation do
  @moduledoc false

  # F1 (wi_34a7be66) L3: every child a test launches goes through here. A child
  # that sees an ancestor .tightbeam-session, the real HOME, a credential
  # variable or a real harness tool can reach a live gateway or a real
  # credential, so each launch is checked and refused (raises, naming why)
  # before anything starts. The rules are F1 r3 L3 as amended by the reviewer's
  # Q1/Q2 answers that b0 accepted:
  #
  #   cwd  - the repository root (the default) or below, or the sandbox; the
  #          realpath is re-checked per call for any .tightbeam-session in its
  #          whole ancestry.
  #   env  - what the child would see (inherited plus declared) is validated:
  #          PATH entries only the toolbox, the repository CLI build, or dirs in
  #          the sandbox; bare tightbeam resolves to the repo build or a test
  #          fixture; TIGHTBEAM_URL loopback only; path-valued TIGHTBEAM_*, HOME
  #          and XDG_* inside the sandbox; TIGHTBEAM_TOKEN only beside such an
  #          endpoint. Variables a test inherited through System.put_env that
  #          look like credentials are refused; values a call declares in env:
  #          are the test's own synthetic fixtures.
  #   exe  - a bare name resolves through that checked PATH; a name containing
  #          "/" bypasses PATH, so it is vetted itself (reviewer finding B1).

  alias Tightbeam.TestSandboxPreflight, as: Preflight

  @repo Path.expand("../..", __DIR__)

  @credential_markers ~w(TOKEN KEY SECRET PASSWORD CREDENTIAL AUTH)
  @credential_prefixes ~w(GH_ GITHUB_ OP_ ANTHROPIC_ OPENAI_ CURSOR_ AWS_)

  defmodule Refusal do
    defexception [:message]
  end

  @doc "The repository root."
  def repo, do: @repo

  @doc """
  The sandbox root. The suite VM uses only what its preflight recorded. A
  child VM (which runs no preflight, and whose environment library code may
  have scrubbed) may locate it only from its own HOME: HOME must be
  `<root>/home` with the sandbox marker at `<root>`. Nothing else is walked.
  """
  def sandbox_root do
    case Preflight.recorded_root() do
      root when is_binary(root) ->
        root

      nil ->
        home = System.get_env("HOME")
        root = home && Path.dirname(home)

        if is_binary(home) and Path.basename(home) == "home" and
             File.regular?(Path.join(root, ".tightbeam-test-sandbox")),
           do: root,
           else: refuse!("no test sandbox found; tests run only inside scripts/test_sandbox.sh")
    end
  end

  @doc "ExUnit's tmp root (<repo>/tmp): test-owned scratch, checked per call."
  def test_tmp, do: Path.join(@repo, "tmp")

  @doc "The sandbox toolbox directory (real tools, no harness or credential tools)."
  def toolbox, do: Path.join(sandbox_root(), "bin")

  @doc "Drop-in for System.cmd/3 that refuses an unsafe launch."
  def cmd(command, args, opts \\ []) do
    cwd = cwd!(Keyword.get(opts, :cd))
    executable!(command, cwd)
    declared = Keyword.get(opts, :env, [])
    check_env!(declared)

    env =
      if List.keymember?(declared, "GIT_CONFIG_NOSYSTEM", 0),
        do: declared,
        else: [{"GIT_CONFIG_NOSYSTEM", "1"} | declared]

    System.cmd(command, args, opts |> Keyword.put(:cd, cwd) |> Keyword.put(:env, env))
  end

  @doc "Drop-in for Port.open/2 that refuses an unsafe launch."
  def port_open(name, opts) do
    cwd = cwd!(port_cd(opts))
    port_executable!(name, cwd)

    declared =
      for {key, value} <- Keyword.get(opts, :env, []),
          do: {to_string(key), if(value in [false, nil], do: nil, else: to_string(value))}

    check_env!(declared)

    env =
      with {:env, list} <- List.keyfind(opts, :env, 0), do: list

    env = env || []

    env =
      if Enum.any?(env, fn {key, _} -> to_string(key) == "GIT_CONFIG_NOSYSTEM" end),
        do: env,
        else: [{~c"GIT_CONFIG_NOSYSTEM", ~c"1"} | env]

    opts =
      opts
      |> List.keystore(:cd, 0, {:cd, String.to_charlist(cwd)})
      |> List.keystore(:env, 0, {:env, env})

    Port.open(name, opts)
  end

  @doc """
  Run a file that lives outside test/ (a literal path relative to the
  repository), with the same checks. The launch-isolation lint collects these
  literals and parses every Elixir file named.

  `runner:` keeps a call site's exact invocation: by default the extension picks
  elixir, sh or python3; `:direct` executes the file itself (its shebang);
  a string names the runner; `[runner | flags]` passes flags before the file.
  """
  def run_script!(path, args, opts \\ []) when is_binary(path) do
    script = Path.expand(path, @repo)

    unless File.regular?(script),
      do: refuse!("run_script!/3: #{path} is not a file in the repository")

    {runner, opts} = Keyword.pop(opts, :runner)

    {executable, leading} =
      case runner do
        nil -> default_runner(script)
        :direct -> {script, []}
        [exe | flags] -> {exe, flags ++ [script]}
        exe when is_binary(exe) -> {exe, [script]}
      end

    cmd(executable, leading ++ args, opts)
  end

  defp default_runner(script) do
    case Path.extname(script) do
      ".exs" -> {"elixir", [script]}
      ".sh" -> {"sh", [script]}
      ".py" -> {"python3", [script]}
      _ -> {script, []}
    end
  end

  @doc "The environment a child launched with `declared` would see, after the checks."
  def env!(declared \\ []) do
    check_env!(declared)
    effective_env(declared)
  end

  @doc """
  Raise unless `executable` may be launched from `cwd`. A bare name resolves
  through the child's PATH, which check_env!/1 vets. A name containing "/" is
  resolved as the OS would (against the VM's cwd, and the child's cwd for a
  port) and its realpath must be a toolbox tool's own target, or lie in the
  repository (cli/target included), the VM's OTP bin dirs, the sandbox or the
  test tmp root. A forbidden tool's name is refused wherever it lies, except
  the launcher's ssh tripwire or a test's scratch fixture.
  """
  def executable!(executable, cwd) do
    name = to_string(executable)

    if String.contains?(name, "/") do
      for base <- Enum.uniq([File.cwd!(), cwd]) do
        path = Path.expand(name, base)
        real = Preflight.canonical(path)

        forbidden =
          Enum.find(
            [Path.basename(path), Path.basename(real)],
            &(&1 in Preflight.forbidden_tools())
          )

        cond do
          forbidden && not acceptable_stand_in?(forbidden, path) ->
            refuse!("refusing to launch #{name}: #{forbidden} is a forbidden tool")

          not allowed_executable?(real) ->
            refuse!(
              "refusing to launch #{name}: #{real} is not a toolbox tool, a repository " <>
                "file, an OTP launcher or a sandbox fixture"
            )

          true ->
            :ok
        end
      end
    end

    :ok
  end

  @doc "executable!/2 for the program a Port.open/2 name would start."
  def port_executable!(name, cwd) do
    case name do
      {:spawn_executable, executable} -> executable!(executable, cwd)
      {:spawn, command} -> command |> to_string() |> String.split() |> hd() |> executable!(cwd)
      _ -> :ok
    end
  end

  defp allowed_executable?(real) do
    MapSet.member?(toolbox_targets(), real) or inside?(real, @repo) or
      Enum.any?(Preflight.vm_bin_dirs(), &inside?(real, &1)) or scratch?(real)
  end

  # What each toolbox entry resolves to. The launcher builds the toolbox before
  # the VM boots and nothing changes it, so this is read once per VM.
  defp toolbox_targets do
    key = {__MODULE__, :toolbox_targets, toolbox()}

    case :persistent_term.get(key, nil) do
      nil ->
        targets =
          toolbox()
          |> File.ls!()
          |> MapSet.new(&Preflight.canonical(Path.join(toolbox(), &1)))

        :persistent_term.put(key, targets)
        targets

      targets ->
        targets
    end
  end

  @doc "Raise unless `path` is an acceptable child cwd; return its realpath."
  def cwd!(nil), do: cwd!(@repo)

  def cwd!(path) do
    path = path |> to_string() |> Path.expand()
    real = Preflight.canonical(path)

    if found = Preflight.session_ancestor(real),
      do: refuse!("refusing to launch in #{path}: #{found} is in its ancestry")

    unless inside?(real, @repo) or inside?(real, sandbox_root()),
      do: refuse!("refusing to launch in #{path}: it is neither the repository nor the sandbox")

    real
  end

  defp port_cd(opts) do
    case Keyword.get(opts, :cd) do
      nil -> nil
      cd -> to_string(cd)
    end
  end

  # `real` is an already-resolved path; `root` is one of the fixed roots below.
  defp inside?(real, root) do
    root = real_root(root)
    real == root or String.starts_with?(real, root <> "/")
  end

  # The repository, the sandbox and its toolbox, the test tmp root and the VM's
  # OTP bin dirs are fixed for the VM's life, so each is resolved once. Every
  # path a launch names is still resolved on every call.
  defp real_root(path) do
    key = {__MODULE__, :real_root, path}

    case :persistent_term.get(key, nil) do
      nil ->
        real = Preflight.canonical(path)
        :persistent_term.put(key, real)
        real

      real ->
        real
    end
  end

  defp effective_env(declared) do
    Enum.reduce(declared, System.get_env(), fn
      {key, nil}, acc -> Map.delete(acc, to_string(key))
      {key, value}, acc -> Map.put(acc, to_string(key), to_string(value))
    end)
  end

  defp check_env!(declared) do
    declared = Enum.map(declared, fn {k, v} -> {to_string(k), v && to_string(v)} end)
    declared_keys = MapSet.new(declared, &elem(&1, 0))
    env = effective_env(declared)

    problems =
      Enum.flat_map(env, fn {key, value} ->
        inherited? = not MapSet.member?(declared_keys, key)
        check_var(key, value, env, inherited?)
      end) ++ tightbeam_resolution(env) ++ forbidden_resolution(env) ++ git_problems(env)

    if problems != [] do
      refuse!("refusing to launch: " <> Enum.join(problems, "; "))
    end
  end

  defp check_var("PATH", value, _env, _inherited?) do
    for entry <- String.split(value, ":", trim: true), not allowed_path_entry?(entry) do
      "PATH entry #{entry} is not the toolbox, the repository CLI build, or a sandbox dir"
    end
  end

  defp check_var("HOME", value, _env, _inherited?), do: sandbox_path("HOME", value)

  defp check_var("XDG_" <> _ = key, value, _env, _inherited?), do: sandbox_path(key, value)

  defp check_var("TIGHTBEAM_URL", value, _env, _inherited?) do
    if loopback?(value), do: [], else: ["TIGHTBEAM_URL #{value} is not a loopback address"]
  end

  defp check_var("TIGHTBEAM_TOKEN", _value, env, _inherited?) do
    if test_endpoint?(env),
      do: [],
      else: ["TIGHTBEAM_TOKEN is set without a loopback TIGHTBEAM_URL or a sandbox base dir"]
  end

  defp check_var("TIGHTBEAM_" <> _ = key, value, _env, _inherited?) do
    if path_valued?(value), do: sandbox_or_test_tmp_path(key, value), else: []
  end

  defp check_var(key, value, _env, true = _inherited?) do
    if key not in Preflight.allowed_env() and credential_name?(key) and
         not test_scoped?(key, value),
       do: ["#{key} looks like a credential and was inherited from the test VM"],
       else: []
  end

  defp check_var(_key, _value, _env, false), do: []

  # git config injected through the environment can reach real credentials
  # whatever HOME is (credential.helper=osxkeychain reads the login keychain),
  # or route traffic and prompts elsewhere. Reviewer ruling (B) on GIT_CONFIG_*.
  @git_config_refused ~r/\A(credential(\.|\z)|core\.sshcommand\z|core\.askpass\z|http\.|url\..*\.(pushinsteadof|insteadof)\z|include\.path\z|includeif\.|gpg\.|user\.signingkey\z)/i
  @git_programs ~w(GIT_ASKPASS SSH_ASKPASS GIT_SSH GIT_SSH_COMMAND)

  defp git_problems(env) do
    keys =
      for {name, value} <- env, Regex.match?(~r/\AGIT_CONFIG_KEY_\d+\z/, name), do: value

    parameter_keys =
      ~r/'([^'=]+)=/
      |> Regex.scan(env["GIT_CONFIG_PARAMETERS"] || "", capture: :all_but_first)
      |> List.flatten()

    refused_keys =
      for key <- keys ++ parameter_keys,
          Regex.match?(@git_config_refused, String.trim(key)),
          do: "git config #{key} may not be injected into a test child"

    programs =
      for name <- @git_programs,
          value = env[name],
          is_binary(value) and value != "",
          not sandbox_program?(value),
          do: "#{name}=#{value} is not a fixture inside the sandbox or the test tmp root"

    # The helper sets GIT_CONFIG_NOSYSTEM=1 on every child; a test may not
    # turn it off.
    nosystem =
      if env["GIT_CONFIG_NOSYSTEM"] in [nil, "1"],
        do: [],
        else: ["GIT_CONFIG_NOSYSTEM must stay 1 for a test child"]

    global =
      case env["GIT_CONFIG_GLOBAL"] do
        nil -> []
        path -> sandbox_or_test_tmp_path("GIT_CONFIG_GLOBAL", path)
      end

    refused_keys ++ programs ++ nosystem ++ global
  end

  defp sandbox_program?(value) do
    program = value |> String.trim() |> String.split(~r/\s+/, parts: 2) |> hd()

    path_valued?(program) and scratch?(Preflight.canonical(Path.expand(program)))
  end

  # A real harness or credential tool must never resolve for a child. The only
  # toolbox entry with such a name is the launcher's exact ssh tripwire; a test's
  # own fixture under the sandbox or the test tmp root is its synthetic stand-in.
  defp forbidden_resolution(env) do
    dirs = env |> Map.get("PATH", "") |> String.split(":", trim: true)

    for tool <- Preflight.forbidden_tools(),
        found = Enum.find_value(dirs, &executable(Path.join(&1, tool))),
        not acceptable_stand_in?(tool, found) do
      "#{tool} resolves to #{found}"
    end
  end

  defp executable(path) do
    if Preflight.file_type(path) == :regular, do: path
  end

  defp acceptable_stand_in?(tool, found) do
    real = Preflight.canonical(found)

    cond do
      String.starts_with?(real, real_root(toolbox()) <> "/") ->
        tool == "ssh" and Preflight.ssh_tripwire?(found, sandbox_root())

      true ->
        scratch?(real)
    end
  end

  # Bare tightbeam must be this repository's build or a fixture inside the sandbox.
  defp tightbeam_resolution(env) do
    found =
      env
      |> Map.get("PATH", "")
      |> String.split(":", trim: true)
      |> Enum.map(&Path.join(&1, "tightbeam"))
      |> Enum.find(&(Preflight.file_type(&1) != nil))

    real = found && Preflight.canonical(found)

    if is_nil(found) or scratch?(real) or inside?(real, Path.join(@repo, "cli/target")),
      do: [],
      else: ["tightbeam resolves to #{found}, not the repository build or a sandbox fixture"]
  end

  defp allowed_path_entry?(entry) do
    real = Preflight.canonical(Path.expand(entry))

    real == real_root(toolbox()) or
      inside?(real, Path.join(@repo, "cli/target")) or
      real in Enum.map(Preflight.vm_bin_dirs(), &real_root/1) or
      scratch?(real)
  end

  # Inside the sandbox or the test tmp root.
  defp scratch?(real), do: inside?(real, sandbox_root()) or inside?(real, test_tmp())

  defp sandbox_or_test_tmp_path(key, value) do
    real = Preflight.canonical(Path.expand(value))

    if scratch?(real),
      do: [],
      else: ["#{key}=#{value} is outside the sandbox and the test tmp root"]
  end

  defp sandbox_path(key, value) do
    if inside?(Preflight.canonical(Path.expand(value)), sandbox_root()),
      do: [],
      else: ["#{key}=#{value} is outside the sandbox"]
  end

  defp path_valued?(value), do: String.starts_with?(value, ["/", "~", "./", "../"])

  defp loopback?(url) do
    case URI.parse(url) do
      %URI{host: host} when host in ["127.0.0.1", "::1", "[::1]", "localhost"] -> true
      _ -> false
    end
  end

  defp test_endpoint?(env) do
    base = env["TIGHTBEAM_BASE_DIR"]

    (is_binary(env["TIGHTBEAM_URL"]) and loopback?(env["TIGHTBEAM_URL"])) or
      (is_binary(base) and scratch?(Preflight.canonical(base)))
  end

  # "Unless test-scoped": a value that is a path inside the sandbox, a name that
  # declares itself a fixture, git's commit identity (AUTHOR is not AUTH) or
  # git's config plumbing (GIT_CONFIG_KEY_n names a config key, not a secret;
  # the credential-reaching keys themselves are refused by git_problems/1).
  defp test_scoped?(key, value) do
    upper = String.upcase(key)

    String.contains?(upper, ["FIXTURE", "SYNTHETIC"]) or
      String.starts_with?(upper, ["GIT_AUTHOR_", "GIT_COMMITTER_", "GIT_CONFIG_"]) or
      (path_valued?(value) and scratch?(Preflight.canonical(Path.expand(value))))
  end

  defp credential_name?(key) do
    upper = String.upcase(key)

    Enum.any?(@credential_markers, &String.contains?(upper, &1)) or
      String.starts_with?(upper, @credential_prefixes)
  end

  defp refuse!(message), do: raise(Refusal, message: message <> " (wi_34a7be66)")
end

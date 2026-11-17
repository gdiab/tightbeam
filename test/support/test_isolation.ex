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
    declared = Keyword.get(opts, :env, [])
    check_env!(declared)
    System.cmd(command, args, Keyword.put(opts, :cd, cwd))
  end

  @doc "Drop-in for Port.open/2 that refuses an unsafe launch."
  def port_open(name, opts) do
    cwd = cwd!(port_cd(opts))

    declared =
      for {key, value} <- Keyword.get(opts, :env, []),
          do: {to_string(key), if(value in [false, nil], do: nil, else: to_string(value))}

    check_env!(declared)
    Port.open(name, Keyword.put(opts, :cd, String.to_charlist(cwd)))
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

  defp inside?(path, root), do: Preflight.inside?(path, Preflight.canonical(root))

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
      end) ++ tightbeam_resolution(env) ++ forbidden_resolution(env)

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
    case File.stat(path) do
      {:ok, %{type: :regular}} -> path
      _ -> nil
    end
  end

  defp acceptable_stand_in?(tool, found) do
    real = Preflight.canonical(found)

    cond do
      String.starts_with?(real, Preflight.canonical(toolbox()) <> "/") ->
        tool == "ssh" and Preflight.ssh_tripwire?(found, sandbox_root())

      true ->
        inside?(real, sandbox_root()) or inside?(real, test_tmp())
    end
  end

  # Bare tightbeam must be this repository's build or a fixture inside the sandbox.
  defp tightbeam_resolution(env) do
    found =
      env
      |> Map.get("PATH", "")
      |> String.split(":", trim: true)
      |> Enum.map(&Path.join(&1, "tightbeam"))
      |> Enum.find(&File.exists?/1)

    cond do
      is_nil(found) ->
        []

      inside?(Preflight.canonical(found), test_tmp()) ->
        []

      Preflight.canonical(found) ==
          Preflight.canonical(Path.join(@repo, "cli/target/release/tightbeam")) ->
        []

      inside?(Preflight.canonical(found), sandbox_root()) ->
        []

      true ->
        ["tightbeam resolves to #{found}, not the repository build or a sandbox fixture"]
    end
  end

  defp allowed_path_entry?(entry) do
    real = Preflight.canonical(Path.expand(entry))

    real == Preflight.canonical(toolbox()) or
      real == Preflight.canonical(Path.join(@repo, "cli/target/release")) or
      real in Enum.map(Preflight.vm_bin_dirs(), &Preflight.canonical/1) or
      inside?(real, sandbox_root()) or inside?(real, test_tmp())
  end

  defp sandbox_or_test_tmp_path(key, value) do
    real = Preflight.canonical(Path.expand(value))

    if inside?(real, sandbox_root()) or inside?(real, test_tmp()),
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
      (is_binary(base) and
         (inside?(Preflight.canonical(base), sandbox_root()) or
            inside?(Preflight.canonical(base), test_tmp())))
  end

  # "Unless test-scoped": a value that is a path inside the sandbox, a name that
  # declares itself a fixture, or git's commit identity (AUTHOR is not AUTH).
  defp test_scoped?(key, value) do
    upper = String.upcase(key)

    String.contains?(upper, ["FIXTURE", "SYNTHETIC"]) or
      String.starts_with?(upper, ["GIT_AUTHOR_", "GIT_COMMITTER_"]) or
      (path_valued?(value) and
         (inside?(Preflight.canonical(Path.expand(value)), sandbox_root()) or
            inside?(Preflight.canonical(Path.expand(value)), test_tmp())))
  end

  defp credential_name?(key) do
    upper = String.upcase(key)

    Enum.any?(@credential_markers, &String.contains?(upper, &1)) or
      String.starts_with?(upper, @credential_prefixes)
  end

  defp refuse!(message), do: raise(Refusal, message: message <> " (wi_34a7be66)")
end

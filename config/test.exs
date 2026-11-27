import Config

# F1 (wi_34a7be66) erratum 2 C6 and erratum 3: Mix evaluates this file for every
# MIX_ENV=test command, so the sandbox preflight is its first executable code,
# before the setup below copies anything or launches rustc. It refuses unless
# scripts/test_sandbox.sh built the sandbox this VM booted in, and records the
# validated marker for test_helper.exs's second check. There is no switch.
# The module is loaded from its test/support source here and unloaded again,
# so the test build compiles it afresh (the recorded marker is kept).
Code.require_file("../test/support/test_sandbox_preflight.ex", __DIR__)
Tightbeam.TestSandboxPreflight.enforce!(Path.expand("..", __DIR__), :first)
:code.delete(Tightbeam.TestSandboxPreflight)
:code.purge(Tightbeam.TestSandboxPreflight)

source_tool_home = System.fetch_env!("HOME")
source_path = System.fetch_env!("PATH")
source_cargo_home = System.get_env("CARGO_HOME", Path.join(source_tool_home, ".cargo"))

authoritative_gate_claim =
  if System.get_env("TIGHTBEAM_AUTHORITATIVE_GATE") == "1" do
    %{expected_node: System.get_env("TIGHTBEAM_GATE_NODE")}
  end

suite_nonce =
  12
  |> :crypto.strong_rand_bytes()
  |> Base.url_encode64(padding: false)

suite_tmp =
  Path.join(
    System.tmp_dir!(),
    "tightbeam-test-#{System.pid()}-#{suite_nonce}"
  )

File.mkdir_p!(suite_tmp)
System.put_env("TMPDIR", suite_tmp)

# A test process must not inherit a live Tightbeam or provider identity from the
# shell that launched it. Keep every implicit home/base lookup inside the suite
# root, and put fail-closed tripwires ahead of installed CLIs on PATH. Tripwires
# record only the executable name: arguments may contain credentials.
# F1 erratum 2 C9 (1): the scrub exempts exactly the launcher's sandbox marker,
# which test_helper.exs re-checks after this setup.
for name <- System.get_env() |> Map.keys(),
    name != "TIGHTBEAM_TEST_SANDBOX",
    String.starts_with?(name, "TIGHTBEAM_") or
      String.starts_with?(name, "RELEASE_") or
      String.ends_with?(name, "_API_KEY") or
      String.ends_with?(name, "_OAUTH_TOKEN") or
      String.ends_with?(name, "_CREDENTIALS") or
      String.ends_with?(name, "_TOKEN") or
      name in [
        "AWS_ACCESS_KEY_ID",
        "AWS_SECRET_ACCESS_KEY",
        "GIT_ASKPASS",
        "SSH_ASKPASS",
        "SSH_AUTH_SOCK"
      ],
    do: System.delete_env(name)

home = Path.join(suite_tmp, "home")
base = Path.join(suite_tmp, "app")
bin = Path.join(suite_tmp, "tripwire-bin")
tool_bin = Path.join(suite_tmp, "tool-bin")
tripwire_log = Path.join(suite_tmp, "forbidden-execution")
quoted_tripwire_log = "'" <> String.replace(tripwire_log, "'", "'\"'\"'") <> "'"
File.mkdir_p!(home)
File.mkdir_p!(bin)
File.mkdir_p!(tool_bin)

# Established tests start nested Mix builds. Seed their synthetic HOME with
# only executable build tooling and immutable package artefacts; never copy
# Hex state, Mix configuration, provider homes, or credentials from the runner.
copy_tool_dir! = fn source, target ->
  case File.cp_r(source, target) do
    {:ok, _copied} -> :ok
    {:error, _reason, _path} -> raise "test isolation could not copy build tooling"
  end

  paths = [target | Path.wildcard(Path.join(target, "**/*"), match_dot: true)]

  if Enum.any?(paths, &(File.lstat!(&1).type == :symlink)) do
    raise "test isolation refuses symlinked build tooling"
  end
end

source_hex_archives = Path.join([source_tool_home, ".mix", "archives", "hex-*"])
hex_archives = Path.wildcard(source_hex_archives)

if hex_archives == [] do
  raise "test isolation requires an installed Hex archive"
end

isolated_archives = Path.join([home, ".mix", "archives"])
File.mkdir_p!(isolated_archives)

for archive <- hex_archives do
  copy_tool_dir!.(archive, Path.join(isolated_archives, Path.basename(archive)))
end

for source <- Path.wildcard(Path.join([source_tool_home, ".mix", "elixir", "*", "rebar3"])) do
  if File.lstat!(source).type != :regular do
    raise "test isolation refuses non-regular Rebar tooling"
  end

  target = Path.join(home, Path.relative_to(source, source_tool_home))
  File.mkdir_p!(Path.dirname(target))
  File.cp!(source, target)
end

source_elixir_make_cache = Path.join([source_tool_home, ".cache", "elixir_make"])

if File.dir?(source_elixir_make_cache) do
  target = Path.join([home, ".cache", "elixir_make"])
  File.mkdir_p!(Path.dirname(target))
  copy_tool_dir!.(source_elixir_make_cache, target)
end

source_cargo_registry = Path.join(source_cargo_home, "registry")

unless File.dir?(source_cargo_registry) do
  raise "test isolation requires an installed Cargo registry cache"
end

# F1 erratum 2 C15: scripts/test_sandbox.sh provides one Cargo home per run, a
# read-only regular-file copy of the registry and git caches under the sandbox.
# Use it in place rather than copying it a second time; only a run outside the
# launcher (which the preflight refuses) would fall through to a copy.
sandbox_root = System.get_env("TIGHTBEAM_TEST_SANDBOX")

isolated_cargo_home =
  if is_binary(sandbox_root) and
       String.starts_with?(Path.expand(source_cargo_home), Path.expand(sandbox_root) <> "/") do
    Path.expand(source_cargo_home)
  else
    target = Path.join(home, ".cargo")
    File.mkdir_p!(target)
    copy_tool_dir!.(source_cargo_registry, Path.join(target, "registry"))
    target
  end

# Nested test builds use the already-installed Rust toolchain directly. The
# wrappers keep rustup and Cargo homes synthetic, and offline mode makes a
# missing local dependency an immediate refusal instead of a download.
source_rustc =
  System.find_executable("rustc") || raise "test isolation requires an installed Rust toolchain"

{rust_sysroot, 0} = System.cmd(source_rustc, ["--print", "sysroot"])
rust_sysroot = String.trim(rust_sysroot)

for name <- ~w(cargo rustc rustdoc) do
  source = Path.join([rust_sysroot, "bin", name])

  if File.lstat!(source).type != :regular do
    raise "test isolation refuses missing or non-regular Rust tooling"
  end

  quoted_source = "'" <> String.replace(source, "'", "'\"'\"'") <> "'"
  path = Path.join(tool_bin, name)
  File.write!(path, "#!/bin/sh\nexec #{quoted_source} \"$@\"\n")
  File.chmod!(path, 0o755)
end

registry = File.read!(Path.expand("../priv/harness_registry.json", __DIR__))

provider_cli_names =
  Regex.scan(~r/"cli_binary"\s*:\s*"([^"]+)"/, registry, capture: :all_but_first)
  |> List.flatten()

for name <- Enum.uniq(["tightbeam", "opencode", "npm", "ssh" | provider_cli_names]) do
  path = Path.join(bin, name)

  File.write!(
    path,
    "#!/bin/sh\nif [ \"$#\" = 1 ] && [ \"$1\" = --version ]; then printf 'synthetic 1.0\\n'; exit 0; fi\nprintf '%s\\n' '#{name}' >> #{quoted_tripwire_log}\nexit 97\n"
  )

  File.chmod!(path, 0o755)
end

git_config = Path.join(home, ".gitconfig")
File.write!(git_config, "[user]\n\tname = Tightbeam Test\n\temail = test@example.invalid\n")

System.put_env("HOME", home)
System.put_env("TMP", suite_tmp)
System.put_env("TEMP", suite_tmp)
System.put_env("XDG_CONFIG_HOME", Path.join(home, ".config"))
System.put_env("CODEX_HOME", Path.join(home, ".codex"))
System.put_env("GIT_CONFIG_GLOBAL", git_config)
System.put_env("TIGHTBEAM_TEST_ROOT", suite_tmp)
System.put_env("TIGHTBEAM_BASE_DIR", base)
System.put_env("TIGHTBEAM_HOME", base)
System.put_env("TIGHTBEAM_TEST_TRIPWIRE_LOG", tripwire_log)
System.put_env("CARGO_NET_OFFLINE", "true")
System.put_env("CARGO_HOME", isolated_cargo_home)
System.put_env("RUSTUP_HOME", Path.join(home, ".rustup"))
System.put_env("RUSTC", Path.join(tool_bin, "rustc"))
System.put_env("RUSTDOC", Path.join(tool_bin, "rustdoc"))

fixture_bin = Path.expand("../priv/harness_cli", __DIR__)
System.put_env("PATH", Enum.join([fixture_bin, tool_bin, bin, source_path], ":"))

# Keep the auto-started app off the real ~/.tightbeam during tests.
config :tightbeam,
       :base_dir,
       base

config :tightbeam, :autostart, false
config :tightbeam, :local_host_name, "testhost"
config :tightbeam, :fixture_harness, true
config :tightbeam, :test_suite_tmp, suite_tmp
config :tightbeam, :test_tripwire_log, tripwire_log
config :tightbeam, :port, 0

if authoritative_gate_claim do
  config :tightbeam, :authoritative_gate_claim, authoritative_gate_claim
end

# Core fix (A) C6a: tests point the unfreeze-file reader at fixtures. Only this
# environment compiles the override; by default the hatch reads a path that does
# not exist, so every test starts frozen and never reads the host's /etc.
config :tightbeam,
  pairing_unfreeze_path_override: true,
  pairing_unfreeze_path: "/nonexistent/tightbeam-test/pairing-unfreeze"

# Core fix (A), review B1: compile the ungated in-process writer fixtures
# (Devices.approve/3, deny/2, revoke/2, add_user/3, set_user_admin/3 and
# Placement.register_host/3) into test builds only.
config :tightbeam, test_fixtures: true

# Test builds pin the installed harklight-agent's ACK2 capabilities to the
# supporting set; the detection itself is tested against agent-shaped fakes
# (harklight_wakes_test.exs, "ACK2 fallback B"), which switch it back to :detect.
config :tightbeam,
  harklight_agent_capabilities: %{listen_ack2: true, attach_ack2: true, ack2_command: true}

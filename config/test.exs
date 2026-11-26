import Config

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
for name <- System.get_env() |> Map.keys(),
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
tripwire_log = Path.join(suite_tmp, "forbidden-execution")
quoted_tripwire_log = "'" <> String.replace(tripwire_log, "'", "'\"'\"'") <> "'"
File.mkdir_p!(home)
File.mkdir_p!(bin)

for name <- ["tightbeam", "codex", "claude", "cursor-agent", "opencode", "pi", "npm", "ssh"] do
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

fixture_bin = Path.expand("../priv/harness_cli", __DIR__)
System.put_env("PATH", Enum.join([fixture_bin, bin, System.fetch_env!("PATH")], ":"))

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

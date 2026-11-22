import Config

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

# Keep the auto-started app off the real ~/.tightbeam during tests.
config :tightbeam,
       :base_dir,
       Path.join(suite_tmp, "app")

config :tightbeam, :autostart, false
config :tightbeam, :local_host_name, "testhost"
config :tightbeam, :fixture_harness, true
config :tightbeam, :test_suite_tmp, suite_tmp
config :tightbeam, :port, 0

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
# (harklight_agent_capabilities_test.exs), which switch it back to :detect.
config :tightbeam,
  harklight_agent_capabilities: %{listen_ack2: true, attach_ack2: true, ack2_command: true}

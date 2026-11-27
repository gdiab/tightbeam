import Config

config :tightbeam, :escalation_decision_deadline_ms, 86_400_000

# Test-spawned production builds inherit only the synthetic test root. Building
# exqlite from its vendored SQLite source avoids elixir_make's precompiled-NIF
# download while leaving ordinary production compilation unchanged.
if test_root = System.get_env("TIGHTBEAM_TEST_ROOT") do
  home = System.fetch_env!("HOME")
  Code.require_file("test_root_path.exs", __DIR__)

  unless Tightbeam.TestRootPath.existing_directory_within?(home, test_root) do
    raise "test isolation refuses a production build outside its synthetic home"
  end

  config :exqlite, force_build: true
end

if config_env() == :test do
  import_config "test.exs"
end

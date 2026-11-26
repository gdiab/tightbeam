import Config

config :tightbeam, :escalation_decision_deadline_ms, 86_400_000

# Test-spawned production builds inherit only the synthetic test root. Building
# exqlite from its vendored SQLite source avoids elixir_make's precompiled-NIF
# download while leaving ordinary production compilation unchanged.
if test_root = System.get_env("TIGHTBEAM_TEST_ROOT") do
  home = System.fetch_env!("HOME")
  expanded_root = Path.expand(test_root)
  expanded_home = Path.expand(home)

  unless expanded_home == expanded_root or
           String.starts_with?(expanded_home, expanded_root <> "/") do
    raise "test isolation refuses a production build outside its synthetic home"
  end

  config :exqlite, force_build: true
end

if config_env() == :test do
  import_config "test.exs"
end

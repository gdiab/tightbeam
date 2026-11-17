# Reviewed exceptions to the launch rule (F1, wi_34a7be66, L4).
#
# Every process launch in code the suite runs goes through
# Tightbeam.TestIsolation unless it is listed here with a reason. Each entry
# names the file, the enclosing function (as the lint reports it) and the launch
# kind. An entry that matches no launch fails the lint, as does a launch that
# runs at compile time (that can never be listed). Even a listed launch runs in
# a VM that the preflight proved is inside the sandbox: empty HOME, allowlisted
# environment, toolbox PATH, no .tightbeam-session above it.
reviewer = "s_ccb14ac2 (F1 code review, pending)"

[
  # Operator scripts the suite loads into its VM. They also run standalone, where
  # the test-only helper does not exist, so they keep their own launches.
  %{
    file: "scripts/feature_smoke.exs",
    function: "defp seed_verifiable_work!/3",
    kind: "System.cmd",
    reason:
      "feature_smoke_rail_path_test compiles this module into the sandboxed test VM; runs a fixture sh script and git in the test's temp workdir",
    reviewer: reviewer
  },
  %{
    file: "scripts/feature_smoke.exs",
    function: "defp sqlite/2",
    kind: "System.cmd",
    reason: "compiled into the sandboxed test VM; sqlite3 on the test's own temp database",
    reviewer: reviewer
  },
  %{
    file: "scripts/feature_smoke.exs",
    function: "defp session_token/2",
    kind: "System.cmd",
    reason: "compiled into the sandboxed test VM; sqlite3 reads the test's own temp state.db",
    reviewer: reviewer
  },
  %{
    file: "scripts/feature_smoke.exs",
    function: "defp item_creation_columns/2",
    kind: "System.cmd",
    reason: "compiled into the sandboxed test VM; sqlite3 on the test's own temp database",
    reviewer: reviewer
  },
  %{
    file: "scripts/feature_smoke.exs",
    function: "defp post/3",
    kind: "System.cmd",
    reason:
      "compiled into the sandboxed test VM; curl posts only to http://127.0.0.1:<port>, the test's own gateway",
    reviewer: reviewer
  },
  %{
    file: "scripts/support/soak_gateway.exs",
    function: "def open/4",
    kind: "Port.open",
    reason:
      "Code.require_file into the sandboxed test VM; starts mix for the test's own gateway in its temp arena",
    reviewer: reviewer
  },
  %{
    file: "scripts/support/soak_gateway.exs",
    function: "def open/4",
    kind: "{:spawn_executable, _} port",
    reason: "the same Port.open as above",
    reviewer: reviewer
  },

  # realpath of the VM's own TMPDIR (inside the sandbox); no Tightbeam CLI.
  %{
    file: "test/conformance_test.exs",
    function: "defp temp_dir!/1",
    kind: ":os.cmd",
    reason: "realpath of System.tmp_dir!/0, which is inside the sandbox",
    reviewer: reviewer
  },
  %{
    file: "test/rail_remedy_test.exs",
    function: "setup",
    kind: ":os.cmd",
    reason: "realpath of System.tmp_dir!/0, which is inside the sandbox",
    reviewer: reviewer
  },

  # Deliberate poison: these tests pass production-shaped sentinel values that
  # the helper would refuse, to prove the product itself refuses or scrubs them.
  %{
    file: "test/execution_safety_isolation_test.exs",
    function: "test concurrent source-test runs isolate node, port, and production identity",
    kind: "System.cmd",
    reason:
      "runs scripts/verify_mix.sh with fake tools and sentinel TIGHTBEAM_BASE_DIR/RELEASE_* values to prove the gate scrubs them; the gate itself runs only inside the launcher",
    reviewer: reviewer
  },
  %{
    file: "test/execution_safety_isolation_test.exs",
    function: "script",
    kind: "runs scripts/verify_mix.sh outside run_script!/3 (cmd)",
    reason:
      "the same launch: the gate under test is passed as a variable to keep the sentinel env",
    reviewer: reviewer
  },
  %{
    file: "test/isolated_lifecycle_isolation_test.exs",
    function:
      "test R1: a poisoned TIGHTBEAM_HOME with TIGHTBEAM_BASE_DIR unset is refused, not followed",
    kind: "System.cmd",
    reason:
      "passes the nonexistent sentinel TIGHTBEAM_HOME=/production/org to prove stop refuses it",
    reviewer: reviewer
  },

  # F1's own regression tests: the positive controls that must reach the decoy
  # listener, and preflight children that must run from a decoy tree.
  %{
    file: "test/test_isolation_test.exs",
    function: "defp raw_cli/3",
    kind: "System.cmd",
    reason:
      "positive control: the unguarded CLI launch that must reach the test-owned decoy, proving each guarded case is not vacuous",
    reviewer: reviewer
  },
  %{
    file: "test/test_isolation_test.exs",
    function: "defp preflight_child/3",
    kind: "System.cmd",
    reason:
      "T6/T7: runs the preflight in a child VM from a decoy tree or with one injected fault; the helper would refuse the decoy cwd by design",
    reviewer: reviewer
  },
  %{
    file: "test/cli_integration_test.exs",
    function:
      "test session-connect composes explicit organization identity with automatic session identity",
    kind: "{:spawn_executable, _} port",
    reason:
      "the spawn tuple this test hands to Tightbeam.FixtureSession.port_open/2, which runs the checks",
    reviewer: reviewer
  },

  # Tests of the CLI's own session discovery run it from inside their fixture
  # session trees through Tightbeam.FixtureSession (reviewer ruling on
  # session_cli): the session file must be inside the sandbox, loopback, and
  # exactly the URL the test recorded for that file; then the helper's cwd and
  # env rules apply.
  %{
    file: "test/support/fixture_session.ex",
    function: "def cmd/3",
    kind: "System.cmd",
    reason: "runs the CLI inside a test's recorded fixture session tree after those checks",
    reviewer: reviewer
  },
  %{
    file: "test/support/fixture_session.ex",
    function: "def port_open/2",
    kind: "Port.open",
    reason: "the Port.open twin of cmd/3 (session-connect streams lines), same checks",
    reviewer: reviewer
  },

  # Scratch copies: the script runs from a copy the test made inside the sandbox.
  %{
    file: "test/harness_seam_test.exs",
    function: "script",
    kind: "runs scripts/check_harness_seam.sh outside run_script!/3 (cmd)",
    reason:
      "runs the copy of the scan under the test's scratch root, which the test seeds with probe files",
    reviewer: reviewer
  },
  %{
    file: "test/release_candidate_workflow_test.exs",
    function: "script",
    kind: "runs packaging/assemble.sh outside run_script!/3 (command)",
    reason:
      "runs assemble.sh inside a git-archive capture of HEAD in the sandbox, proving a clean-source package",
    reviewer: reviewer
  }
]

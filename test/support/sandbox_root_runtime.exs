[payload, _base] = System.argv()
true = Path.expand(payload) == Path.expand(Application.app_dir(:tightbeam))

# F1 (wi_34a7be66) ruling art_1adf97db section 2: a GuardRuntimeFixture child
# finds the sandbox root from the TIGHTBEAM_TEST_SANDBOX its launcher passed
# down, after validating it itself, and its own launches are checked against it.
root = Tightbeam.TestIsolation.sandbox_root()
{_, 0} = Tightbeam.TestIsolation.cmd("true", [])
IO.puts("sandbox-root: " <> root)

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::ffi::{OsStr, OsString};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

const TEST_PARENT_PID: &str = "TIGHTBEAM_RUST_TEST_PARENT_PID";
const SANDBOX_VAR: &str = "TIGHTBEAM_TEST_SANDBOX";
const MARKER: &str = ".tightbeam-test-sandbox";

#[cfg_attr(target_os = "linux", unsafe(link_section = ".init_array"))]
#[cfg_attr(target_os = "macos", unsafe(link_section = "__DATA,__mod_init_func"))]
#[used]
static INSTALL_TEST_ISOLATION: extern "C" fn() = {
    extern "C" fn install() {
        // F1 erratum 2 C9 (4): the launcher's sandbox marker is read before the scrub
        // below, and this process aborts, naming the reason, unless it is valid. An
        // established re-exec child is checked too: it runs under the same sandbox.
        if let Err(reason) = sandbox_marker() {
            eprintln!(
                "test isolation refused: {reason}. Run Rust tests only through \
                 scripts/test_sandbox.sh (wi_34a7be66)."
            );
            unsafe { libc::_exit(101) };
        }

        if established_self_reexec_child() {
            return;
        }

        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let root = std::env::temp_dir().join(format!(
            "tightbeam-rust-test-{}-{nonce}",
            std::process::id()
        ));
        let home = root.join("home");
        let base = root.join("base");
        let bin = root.join("tripwire-bin");
        fs::create_dir_all(&home).expect("create isolated Rust test home");
        fs::create_dir_all(&base).expect("create isolated Rust test base");
        fs::create_dir_all(&bin).expect("create Rust test tripwire directory");

        let log = root.join("forbidden-execution");
        let quoted_log = format!("'{}'", log.to_string_lossy().replace('\'', "'\"'\"'"));
        for name in [
            "tightbeam",
            "codex",
            "claude",
            "cursor-agent",
            "opencode",
            "pi",
            "npm",
            "ssh",
        ] {
            let path = bin.join(name);
            fs::write(
                &path,
                format!(
                    "#!/bin/sh\nif [ \"$#\" = 1 ] && [ \"$1\" = --version ]; then printf 'synthetic 1.0\\n'; exit 0; fi\nprintf '%s\\n' '{name}' >> {quoted_log}\nexit 97\n"
                ),
            )
            .expect("write Rust test tripwire");
            fs::set_permissions(&path, fs::Permissions::from_mode(0o755))
                .expect("make Rust test tripwire executable");
        }

        let git_config = home.join(".gitconfig");
        fs::write(
            &git_config,
            "[user]\n\tname = Tightbeam Test\n\temail = test@example.invalid\n",
        )
        .expect("write isolated Rust test git config");

        let inherited_path = std::env::var_os("PATH").unwrap_or_default();
        let mut path = vec![
            bin,
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../priv/harness_cli"),
        ];
        path.extend(std::env::split_paths(&inherited_path));
        let path = std::env::join_paths(path).expect("compose isolated Rust test PATH");

        let inherited: Vec<String> = std::env::vars().map(|(name, _)| name).collect();
        for name in inherited {
            // F1 erratum 2 C9 (1): the scrub exempts exactly the sandbox marker.
            if name == SANDBOX_VAR {
                continue;
            }
            if name.starts_with("TIGHTBEAM_")
                || name.starts_with("RELEASE_")
                || name.ends_with("_API_KEY")
                || name.ends_with("_OAUTH_TOKEN")
                || name.ends_with("_CREDENTIALS")
                || name.ends_with("_TOKEN")
                || [
                    "AWS_ACCESS_KEY_ID",
                    "AWS_SECRET_ACCESS_KEY",
                    "GIT_ASKPASS",
                    "SSH_ASKPASS",
                    "SSH_AUTH_SOCK",
                ]
                .contains(&name.as_str())
            {
                unsafe { std::env::remove_var(name) };
            }
        }

        unsafe {
            std::env::set_var("HOME", &home);
            std::env::set_var("XDG_CONFIG_HOME", home.join(".config"));
            std::env::set_var("CODEX_HOME", home.join(".codex"));
            std::env::set_var("GIT_CONFIG_GLOBAL", git_config);
            std::env::set_var("TMPDIR", &root);
            std::env::set_var("TMP", &root);
            std::env::set_var("TEMP", &root);
            std::env::set_var("TIGHTBEAM_TEST_ROOT", &root);
            std::env::set_var("TIGHTBEAM_BASE_DIR", &base);
            std::env::set_var("TIGHTBEAM_HOME", &base);
            std::env::set_var("TIGHTBEAM_TEST_TRIPWIRE_LOG", &log);
            std::env::set_var(TEST_PARENT_PID, std::process::id().to_string());
            std::env::set_var("PATH", path);
            libc::atexit(assert_tripwire_clean);
        }
    }

    install
};

fn established_self_reexec_child() -> bool {
    // A direct child running one of the test binary's exact, established re-exec
    // protocols keeps its parent's already-scrubbed environment and test root.
    // Every other invocation must install fresh isolation, including ordinary
    // descendants that happen to execute the same test binary.
    let parent_matches = std::env::var(TEST_PARENT_PID)
        .ok()
        .and_then(|value| value.parse::<u32>().ok())
        == Some(unsafe { libc::getppid() } as u32);
    if !parent_matches {
        return false;
    }

    let args: Vec<_> = std::env::args_os().collect();
    let Some(exact) = args
        .windows(2)
        .find(|pair| pair[0] == "--exact")
        .and_then(|pair| pair[1].to_str())
    else {
        return false;
    };

    if let Some(test) = exact.strip_prefix("child_process::tests::") {
        let control = format!("TIGHTBEAM_ISOLATED_{}", test.to_ascii_uppercase());
        return std::env::var_os(control).as_deref() == Some(std::ffi::OsStr::new("1"));
    }

    match exact {
        "transport_receipt::tests::independent_processes_share_nonwaiting_lock_and_rotation" => {
            std::env::var_os("TIGHTBEAM_RECEIPT_TEST_BASE").is_some()
                && std::env::var_os("TIGHTBEAM_RECEIPT_TEST_MODE").is_some()
        }
        "ceremonies::tests::term_during_codex_onboarding_cancels_its_exact_lease_and_keeps_the_interrupt" => {
            [
                "TIGHTBEAM_CODEX_SIGNAL_INNER",
                "TIGHTBEAM_CODEX_SIGNAL_MARKER",
                "TIGHTBEAM_CODEX_SIGNAL_STAGING",
                "TIGHTBEAM_CODEX_SIGNAL_CANCEL",
            ]
            .iter()
            .all(|name| std::env::var_os(name).is_some())
                && std::env::var_os("TIGHTBEAM_CODEX_SIGNAL_INNER").as_deref()
                    == Some(std::ffi::OsStr::new("1"))
                && std::env::var_os("TIGHTBEAM_MACHINE").as_deref()
                    == Some(std::ffi::OsStr::new("signal-fixture-host"))
        }
        "ceremonies::tests::an_inherited_sigchld_ignore_keeps_timeout_group_identity_reserved" => {
            std::env::var_os("TIGHTBEAM_SIGCHLD_CEREMONY_INNER").as_deref()
                == Some(std::ffi::OsStr::new("1"))
                && std::env::var_os("TIGHTBEAM_SIGCHLD_CEREMONY_DIR").is_some()
        }
        _ => false,
    }
}

extern "C" fn assert_tripwire_clean() {
    let Some(log) = std::env::var_os("TIGHTBEAM_TEST_TRIPWIRE_LOG").map(PathBuf::from) else {
        return;
    };

    if log.exists() {
        eprintln!("test isolation refused a forbidden executable");
        unsafe { libc::_exit(101) };
    }

    if let Some(root) = log.parent() {
        let _ = fs::remove_dir_all(root);
    }
}

// ---------------------------------------------------------------------------
// F1 (wi_34a7be66, contract r3 L1b; erratum 2 C9, C10): the sandbox guard and
// the one spawn constructor for every launch in Rust test code. `cargo test`
// runs only inside the sandbox scripts/test_sandbox.sh builds; `guard` refuses
// (panics) otherwise and has no switch. This file is included both as the
// binary's `#[cfg(test)] mod test_isolation` and by `cli/tests/support`, so it
// carries no inner attributes.
// ---------------------------------------------------------------------------

/// The sandbox root named by the marker variable, if it holds the marker file.
fn sandbox_marker() -> Result<PathBuf, String> {
    match std::env::var_os(SANDBOX_VAR).map(PathBuf::from) {
        None => Err(format!("{SANDBOX_VAR} is not set")),
        Some(root) if !root.join(MARKER).is_file() => {
            Err(format!("{} has no {MARKER} marker", root.display()))
        }
        Some(root) => Ok(root),
    }
}

/// The launcher's allowlist plus the suite variables the isolation constructor
/// above sets for itself (erratum 2 C2). The Mix preflight
/// (test/support/test_sandbox_preflight.ex) uses the same list.
#[allow(dead_code)]
pub const ALLOWED_ENV: &[&str] = &[
    "HOME",
    "XDG_CONFIG_HOME",
    "XDG_DATA_HOME",
    "XDG_STATE_HOME",
    "XDG_CACHE_HOME",
    "PATH",
    "TMPDIR",
    "TMP",
    "TEMP",
    "LANG",
    "LC_ALL",
    "LC_CTYPE",
    "TERM",
    "MIX_ENV",
    "MIX_HOME",
    "HEX_HOME",
    "HEX_OFFLINE",
    "GIT_CONFIG_GLOBAL",
    "GIT_CONFIG_NOSYSTEM",
    "CARGO_HOME",
    "CARGO_NET_OFFLINE",
    "CARGO_TARGET_DIR",
    "RUSTUP_HOME",
    "RUSTC",
    "RUSTDOC",
    "CODEX_HOME",
    "TIGHTBEAM_TEST_SANDBOX",
    "TIGHTBEAM_TEST_ROOT",
    "TIGHTBEAM_BASE_DIR",
    "TIGHTBEAM_HOME",
    "TIGHTBEAM_TEST_TRIPWIRE_LOG",
    "TIGHTBEAM_RUST_TEST_PARENT_PID",
];

/// The established self-re-exec protocols (erratum 2 C10) and the control
/// variables each may carry. A prefix entry ends in `::`.
#[allow(dead_code)]
const REEXEC_PROTOCOLS: &[(&str, &[&str])] = &[
    (
        "child_process::tests::",
        &["TIGHTBEAM_ISOLATED_*", "TB_TEST_EXPECTED_ISOLATION_ROOT"],
    ),
    (
        "transport_receipt::tests::independent_processes_share_nonwaiting_lock_and_rotation",
        &["TIGHTBEAM_RECEIPT_TEST_BASE", "TIGHTBEAM_RECEIPT_TEST_MODE"],
    ),
    (
        "ceremonies::tests::term_during_codex_onboarding_cancels_its_exact_lease_and_keeps_the_interrupt",
        &[
            "TIGHTBEAM_CODEX_SIGNAL_INNER",
            "TIGHTBEAM_CODEX_SIGNAL_MARKER",
            "TIGHTBEAM_CODEX_SIGNAL_STAGING",
            "TIGHTBEAM_CODEX_SIGNAL_CANCEL",
            "TIGHTBEAM_MACHINE",
        ],
    ),
    (
        "ceremonies::tests::an_inherited_sigchld_ignore_keeps_timeout_group_identity_reserved",
        &["TIGHTBEAM_SIGCHLD_CEREMONY_INNER", "TIGHTBEAM_SIGCHLD_CEREMONY_DIR"],
    ),
];

/// The `.tightbeam-session` in `path`'s ancestry, found the way the CLI's
/// `discover_session_from` walks it (unbounded: F1 refuses what the repair's
/// bounded walk would merely ignore).
#[allow(dead_code)]
pub fn session_ancestor(path: &Path) -> Option<PathBuf> {
    let path = std::fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf());
    path.ancestors()
        .map(|dir| dir.join(".tightbeam-session"))
        .find(|candidate| candidate.exists())
}

#[allow(dead_code)]
fn inside(path: &Path, root: &Path) -> bool {
    let path = std::fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf());
    let root = std::fs::canonicalize(root).unwrap_or_else(|_| root.to_path_buf());
    path.starts_with(&root)
}

/// Every reason this process is not inside a valid test sandbox: the marker,
/// HOME and the repair's test root inside it, no `.tightbeam` in HOME, and no
/// `.tightbeam-session` above the working directory or HOME.
#[allow(dead_code)]
pub fn problems() -> Vec<String> {
    let mut problems = Vec::new();

    match sandbox_marker() {
        Err(reason) => problems.push(format!("{reason} (run through scripts/test_sandbox.sh)")),
        Ok(root) => {
            match std::env::var_os("HOME").map(PathBuf::from) {
                Some(home) if inside(&home, &root) => {
                    if home.join(".tightbeam").exists() {
                        problems.push(format!(
                            "{}/.tightbeam exists; a test could read a gateway credential",
                            home.display()
                        ));
                    }
                }
                Some(home) => problems.push(format!(
                    "HOME {} is outside the sandbox {}",
                    home.display(),
                    root.display()
                )),
                None => problems.push("HOME is not set".into()),
            }
            match std::env::var_os("TIGHTBEAM_TEST_ROOT").map(PathBuf::from) {
                Some(test_root) if !inside(&test_root, &root) => problems.push(format!(
                    "TIGHTBEAM_TEST_ROOT {} is outside the sandbox {}",
                    test_root.display(),
                    root.display()
                )),
                _ => {}
            }
        }
    }

    let mut starts = Vec::new();
    if let Ok(cwd) = std::env::current_dir() {
        starts.push(cwd);
    }
    if let Some(home) = std::env::var_os("HOME") {
        starts.push(PathBuf::from(home));
    }
    for start in starts {
        if let Some(found) = session_ancestor(&start) {
            problems.push(format!(
                "{} is in the ancestry of {}; the CLI would use that session's credential",
                found.display(),
                start.display()
            ));
        }
    }

    problems
}

/// Refuse (panic, naming every reason) unless this process is inside the test
/// sandbox. Returns the sandbox root.
#[allow(dead_code)]
pub fn guard() -> PathBuf {
    let problems = problems();
    if !problems.is_empty() {
        panic!(
            "this test cannot run here: it is not inside the test sandbox.\n  - {}\n\
             Run Rust tests only through scripts/test_sandbox.sh, from a checkout outside \
             any Tightbeam session tree, or on hosted CI (wi_34a7be66).",
            problems.join("\n  - ")
        );
    }
    sandbox_marker().expect("checked by problems()")
}

static NEXT: AtomicU64 = AtomicU64::new(0);

/// A fresh empty directory under the sandbox root.
#[allow(dead_code)]
pub fn fresh_dir(label: &str) -> PathBuf {
    let root = guard();
    let unique = format!(
        "{label}-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    );
    let dir = root.join("rust-test").join(unique);
    std::fs::create_dir_all(&dir).expect("create a sandbox test directory");
    dir
}

/// An ordinary launch: only the allowlist, with a fresh HOME and a fresh working
/// directory under the sandbox. Callers add their fixture variables with `.env(..)`.
#[allow(dead_code)]
pub fn command(program: impl AsRef<OsStr>) -> Command {
    let cwd = fresh_dir("cwd");
    command_in(program, &cwd)
}

/// [`command`] in `dir`, which must lie inside the sandbox and have no
/// `.tightbeam-session` in its ancestry.
#[allow(dead_code)]
pub fn command_in(program: impl AsRef<OsStr>, dir: &Path) -> Command {
    let root = guard();
    refuse_unsafe_dir(dir, &root);

    let home = fresh_dir("home");
    let mut command = allowlisted(program);
    command.env("HOME", home).current_dir(dir);
    command
}

/// A launch of one established self-re-exec protocol (erratum 2 C10): the test
/// binary itself with `--exact <exact_test>`. It keeps the parent's suite values
/// (HOME, the repair's test root, base and tripwire log, TMPDIR), names this
/// process as the parent, and carries only the protocol's declared controls.
#[allow(dead_code)]
pub fn reexec(exact_test: &str, controls: &[(&str, &OsStr)]) -> Command {
    let root = guard();
    let Some((protocol, allowed)) = REEXEC_PROTOCOLS
        .iter()
        .find(|(name, _)| {
            if name.ends_with("::") {
                exact_test.starts_with(name)
            } else {
                exact_test == *name
            }
        })
    else {
        panic!("{exact_test} is not an established re-exec protocol (wi_34a7be66 erratum 2 C10)");
    };
    for (name, _) in controls {
        let declared = allowed.iter().any(|allowed| match allowed.strip_suffix('*') {
            Some(prefix) => name.starts_with(prefix),
            None => name == allowed,
        });
        if !declared {
            panic!("{name} is not a declared control of the re-exec protocol {protocol}");
        }
    }

    let cwd = fresh_dir("reexec-cwd");
    refuse_unsafe_dir(&cwd, &root);
    let mut command = allowlisted(std::env::current_exe().expect("the test binary"));
    command
        .env(TEST_PARENT_PID, std::process::id().to_string())
        .args(["--exact", exact_test])
        .current_dir(cwd);
    for (name, value) in controls {
        command.env(name, value);
    }
    command
}

#[allow(dead_code)]
fn refuse_unsafe_dir(dir: &Path, root: &Path) {
    if let Some(found) = session_ancestor(dir) {
        panic!(
            "refusing to launch in {}: {} is in its ancestry (wi_34a7be66)",
            dir.display(),
            found.display()
        );
    }
    if !inside(dir, root) {
        panic!(
            "refusing to launch in {}: it is outside the test sandbox {} (wi_34a7be66)",
            dir.display(),
            root.display()
        );
    }
}

#[allow(dead_code)]
fn allowlisted(program: impl AsRef<OsStr>) -> Command {
    let mut command = Command::new(program);
    command.env_clear();
    for (name, value) in allowed_vars() {
        command.env(name, value);
    }
    command
}

#[allow(dead_code)]
fn allowed_vars() -> Vec<(OsString, OsString)> {
    std::env::vars_os()
        .filter(|(name, _)| {
            ALLOWED_ENV
                .iter()
                .any(|allowed| name == OsStr::new(allowed))
        })
        .collect()
}

//! Test-only process isolation (F1, wi_34a7be66, L1b).
//!
//! `cargo test` runs the real CLI and other children. A child that inherits an
//! ancestor `.tightbeam-session`, the real HOME or a credential variable can
//! reach a live gateway with a real credential, so every launch in Rust test
//! code goes through this module, and [`guard`] refuses (panics) unless the run
//! is inside the sandbox `scripts/test_sandbox.sh` builds. It has no switch.
//!
//! The same file is the binary's `#[cfg(test)] mod test_isolation` and each
//! integration test's `#[path = "../src/test_isolation.rs"] mod test_isolation`.
#![allow(dead_code)]

use std::ffi::{OsStr, OsString};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};

const MARKER: &str = ".tightbeam-test-sandbox";

/// The launcher's allowlist plus its named credential-free passthroughs; the
/// Mix preflight (test/support/test_sandbox_preflight.ex) uses the same list.
pub const ALLOWED_ENV: &[&str] = &[
    "HOME",
    "XDG_CONFIG_HOME",
    "XDG_DATA_HOME",
    "XDG_STATE_HOME",
    "XDG_CACHE_HOME",
    "PATH",
    "TMPDIR",
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
    "TIGHTBEAM_TEST_SANDBOX",
    "TIGHTBEAM_AUTHORITATIVE_GATE",
    "TIGHTBEAM_GATE_NODE",
    "TIGHTBEAM_PORT",
    "DD36_DARWIN_DIAGNOSTIC_DIR",
    "RUNNER_TEMP",
    "CANDIDATE_SHA",
];

/// The `.tightbeam-session` in `path`'s ancestry, found the way the CLI's
/// `discover_session_from` walks it.
pub fn session_ancestor(path: &Path) -> Option<PathBuf> {
    let path = std::fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf());
    path.ancestors()
        .map(|dir| dir.join(".tightbeam-session"))
        .find(|candidate| candidate.exists())
}

fn inside(path: &Path, root: &Path) -> bool {
    let path = std::fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf());
    let root = std::fs::canonicalize(root).unwrap_or_else(|_| root.to_path_buf());
    path.starts_with(&root)
}

/// Every reason this process is not inside a valid test sandbox: the marker,
/// HOME inside it, and no `.tightbeam-session` above the working directory or
/// HOME. The environment allowlist itself is the launcher's `env -i`.
pub fn problems() -> Vec<String> {
    let mut problems = Vec::new();
    let root = std::env::var_os("TIGHTBEAM_TEST_SANDBOX").map(PathBuf::from);

    match &root {
        None => problems
            .push("TIGHTBEAM_TEST_SANDBOX is not set (run through scripts/test_sandbox.sh)".into()),
        Some(root) if !root.join(MARKER).is_file() => {
            problems.push(format!("{} has no {MARKER} marker", root.display()))
        }
        Some(root) => match std::env::var_os("HOME").map(PathBuf::from) {
            Some(home) if inside(&home, root) => {
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
        },
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
    PathBuf::from(std::env::var_os("TIGHTBEAM_TEST_SANDBOX").expect("checked by problems()"))
}

static NEXT: AtomicU64 = AtomicU64::new(0);

/// A fresh empty directory under the sandbox root.
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

/// A command whose environment is only the allowlist, with a fresh HOME and a
/// fresh working directory under the sandbox. Callers add their fixture
/// variables with `.env(..)`.
pub fn command(program: impl AsRef<OsStr>) -> Command {
    let cwd = fresh_dir("cwd");
    command_in(program, &cwd)
}

/// [`command`] in `dir`, which must lie inside the sandbox and have no
/// `.tightbeam-session` in its ancestry.
pub fn command_in(program: impl AsRef<OsStr>, dir: &Path) -> Command {
    let root = guard();
    if let Some(found) = session_ancestor(dir) {
        panic!(
            "refusing to launch in {}: {} is in its ancestry (wi_34a7be66)",
            dir.display(),
            found.display()
        );
    }
    if !inside(dir, &root) {
        panic!(
            "refusing to launch in {}: it is outside the test sandbox {} (wi_34a7be66)",
            dir.display(),
            root.display()
        );
    }

    let home = fresh_dir("home");
    let mut command = Command::new(program);
    command.env_clear();
    for (name, value) in allowed_vars() {
        command.env(name, value);
    }
    command.env("HOME", home).current_dir(dir);
    command
}

fn allowed_vars() -> Vec<(OsString, OsString)> {
    std::env::vars_os()
        .filter(|(name, _)| {
            ALLOWED_ENV
                .iter()
                .any(|allowed| name == OsStr::new(allowed))
        })
        .collect()
}

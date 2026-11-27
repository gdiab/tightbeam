//! F1 (wi_34a7be66) T10: Rust test launches cannot reach a gateway through an
//! ancestor `.tightbeam-session` or a HOME `gateway.json`, and the guard refuses
//! outside the sandbox. Every guarded case is paired with a raw launch of the same
//! CLI that DOES reach the decoy, so a mis-wired decoy cannot pass vacuously. The
//! only gateway anywhere here is a listener this test owns; it counts TCP accepts.
#[path = "support/test_isolation.rs"]
mod test_isolation;

use std::io::Write;
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

const CLI: &str = env!("CARGO_BIN_EXE_tightbeam");

struct Decoy {
    port: u16,
    accepts: Arc<AtomicUsize>,
}

impl Decoy {
    fn start() -> Decoy {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind the decoy listener");
        let port = listener.local_addr().unwrap().port();
        let accepts = Arc::new(AtomicUsize::new(0));
        let counter = Arc::clone(&accepts);
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                counter.fetch_add(1, Ordering::SeqCst);
                if let Ok(mut stream) = stream {
                    let _ = stream.write_all(
                        b"HTTP/1.1 503 Service Unavailable\r\ncontent-length: 0\r\nconnection: close\r\n\r\n",
                    );
                }
            }
        });
        Decoy { port, accepts }
    }

    fn accepts(&self) -> usize {
        self.accepts.load(Ordering::SeqCst)
    }

    /// A directory two levels below a `.tightbeam-session` naming this decoy.
    fn session_tree(&self) -> (PathBuf, PathBuf) {
        let root = test_isolation::fresh_dir("decoy-session");
        let session = root.join(".tightbeam-session");
        std::fs::write(
            &session,
            format!(
                r#"{{"url":"http://127.0.0.1:{}","token":"decoy-token"}}"#,
                self.port
            ),
        )
        .unwrap();
        let inner = root.join("a").join("b");
        std::fs::create_dir_all(&inner).unwrap();
        (session, inner)
    }

    /// A HOME whose `.tightbeam/gateway.json` names this decoy.
    fn decoy_home(&self) -> PathBuf {
        let home = test_isolation::fresh_dir("decoy-home");
        std::fs::create_dir_all(home.join(".tightbeam")).unwrap();
        std::fs::write(
            home.join(".tightbeam/gateway.json"),
            format!(r#"{{"port":{},"cliToken":"decoy-token"}}"#, self.port),
        )
        .unwrap();
        home
    }
}

fn run(mut command: Command) -> Output {
    let mut child = command
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("spawn the CLI");
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        if child.try_wait().unwrap().is_some() {
            return child.wait_with_output().unwrap();
        }
        if Instant::now() > deadline {
            let _ = child.kill();
            return child.wait_with_output().unwrap();
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}

/// The deliberately unguarded launch the guarded case is measured against:
/// the same CLI, a minimal environment, the given cwd and HOME.
fn raw(args: &[&str], cwd: &Path, home: &Path) -> Command {
    let mut command = Command::new(CLI);
    command
        .args(args)
        .env_clear()
        .env("PATH", std::env::var_os("PATH").unwrap_or_default())
        .env("HOME", home)
        .current_dir(cwd);
    command
}

fn refusal(dir: &Path) -> String {
    let dir = dir.to_path_buf();
    let result = std::panic::catch_unwind(move || test_isolation::command_in(CLI, &dir));
    let payload = result.expect_err("command_in must refuse a cwd under a session file");
    payload
        .downcast_ref::<String>()
        .cloned()
        .or_else(|| payload.downcast_ref::<&str>().map(|s| s.to_string()))
        .unwrap_or_default()
}

fn session_case(args: &[&str]) {
    let decoy = Decoy::start();
    let (session, inner) = decoy.session_tree();

    let message = refusal(&inner);
    assert!(
        message.contains(&session.display().to_string()),
        "the refusal names the decoy session file: {message}"
    );
    std::thread::sleep(Duration::from_millis(200));
    assert_eq!(decoy.accepts(), 0, "a refused launch reaches nothing");

    let empty_home = test_isolation::fresh_dir("raw-home");
    let output = run(raw(args, &inner, &empty_home));
    assert!(
        decoy.accepts() >= 1,
        "positive control: the raw launch must reach the decoy session gateway \
         (status {:?}, stderr {})",
        output.status,
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn t10_user_creation_cannot_reach_a_session_gateway() {
    session_case(&["add-user", "synthetic-admin", "--admin"]);
}

#[test]
fn t10_gateway_calls_cannot_reach_a_session_gateway() {
    session_case(&["list"]);
}

#[test]
fn t10_home_gateway_json_fallback_is_never_used() {
    let decoy = Decoy::start();
    let home = decoy.decoy_home();

    // Without a session the CLI needs an explicit identity before discovery runs.
    let args = ["list", "--as-process", "f1-decoy"];
    let mut guarded = test_isolation::command(CLI);
    guarded.args(args);
    let output = run(guarded);
    assert_eq!(
        decoy.accepts(),
        0,
        "the guarded launch gets a fresh HOME, never the decoy's gateway.json \
         (stderr {})",
        String::from_utf8_lossy(&output.stderr)
    );

    let cwd = test_isolation::fresh_dir("raw-cwd");
    let output = run(raw(&args, &cwd, &home));
    assert!(
        decoy.accepts() >= 1,
        "positive control: the raw launch with the decoy HOME reaches the decoy \
         (status {:?}, stderr {})",
        output.status,
        String::from_utf8_lossy(&output.stderr)
    );
}

/// Runs in a child stripped of the sandbox marker; the guard must refuse.
#[test]
fn t10_guard_child_mode() {
    if std::env::var_os("F1_GUARD_CHILD").is_none() {
        return;
    }
    test_isolation::guard();
}

#[test]
fn t10_guard_refuses_outside_the_sandbox() {
    test_isolation::guard();
    let home = test_isolation::fresh_dir("guard-home");
    let output = Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "t10_guard_child_mode", "--nocapture"])
        .env_clear()
        .env("PATH", std::env::var_os("PATH").unwrap_or_default())
        .env("HOME", home)
        .env("F1_GUARD_CHILD", "1")
        .output()
        .unwrap();
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        !output.status.success(),
        "the guard must fail the child: {text}"
    );
    assert!(
        text.contains("TIGHTBEAM_TEST_SANDBOX is not set"),
        "the refusal names the missing sandbox: {text}"
    );
}

// F1 erratum 2 C9 (4): the isolation constructor reads the marker before its
// scrub and aborts, naming the reason, when it is missing or names no marker.
#[test]
fn t7_constructor_aborts_on_a_marker_without_its_file() {
    test_isolation::guard();
    let home = test_isolation::fresh_dir("marker-home");
    let bogus = test_isolation::fresh_dir("no-marker");
    let output = Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "t10_guard_child_mode", "--nocapture"])
        .env_clear()
        .env("PATH", std::env::var_os("PATH").unwrap_or_default())
        .env("HOME", home)
        .env("TIGHTBEAM_TEST_SANDBOX", &bogus)
        .env("F1_GUARD_CHILD", "1")
        .output()
        .unwrap();
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(output.status.code(), Some(101), "the constructor aborts: {text}");
    assert!(
        text.contains("has no .tightbeam-test-sandbox marker"),
        "the refusal names the missing marker: {text}"
    );
}

// F1 erratum 2 C10: a re-exec carries only an established protocol and its
// declared controls.
#[test]
fn t7_reexec_refuses_an_unknown_protocol_or_an_undeclared_control() {
    let unknown = std::panic::catch_unwind(|| {
        test_isolation::reexec("some_module::tests::not_a_protocol", &[])
    });
    assert!(unknown.is_err(), "an unknown protocol is refused");

    let undeclared = std::panic::catch_unwind(|| {
        test_isolation::reexec(
            "child_process::tests::anything",
            &[("TIGHTBEAM_URL", std::ffi::OsStr::new("http://127.0.0.1:1"))],
        )
    });
    assert!(undeclared.is_err(), "an undeclared control is refused");

    let declared = test_isolation::reexec(
        "child_process::tests::anything",
        &[("TIGHTBEAM_ISOLATED_ANYTHING", std::ffi::OsStr::new("1"))],
    );
    let envs: Vec<_> = declared.get_envs().map(|(k, _)| k.to_owned()).collect();
    assert!(envs.iter().any(|k| k == "TIGHTBEAM_ISOLATED_ANYTHING"));
    assert!(envs.iter().any(|k| k == "TIGHTBEAM_RUST_TEST_PARENT_PID"));
    assert!(!envs.iter().any(|k| k == "TIGHTBEAM_URL"));
}

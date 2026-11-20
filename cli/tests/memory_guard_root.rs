//! The FS9 root commands, run for real (memory limits v1.13; matrix N4, N6, N8;
//! T31). They run as root on the gateway's host; here a debug-build switch
//! stands in for root, so the refusal and confirmation paths can be driven
//! without privilege. Nothing outside the test's own directory and its own
//! child process is touched.
#![cfg(target_os = "linux")]

use std::fs;
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

struct Base(PathBuf);

impl Drop for Base {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn base(name: &str, episode: serde_json::Value) -> Base {
    let dir = std::env::temp_dir().join(format!("tb-mg-root-{name}-{}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    let episodes = dir.join("run/memory-guard/episodes");
    fs::create_dir_all(&episodes).unwrap();
    let path = episodes.join(format!("{}.json", episode["episodeId"].as_str().unwrap()));
    fs::write(&path, episode.to_string()).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
    Base(dir)
}

fn run(base: &Path, command: &str, id: &str, root: bool, stdin: &str) -> std::process::Output {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_tightbeam"));
    cmd.args([command, "--base", base.to_str().unwrap(), id])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    if root {
        cmd.env("TIGHTBEAM_TEST_ASSUME_ROOT", "1");
    }
    let mut child = cmd.spawn().unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(stdin.as_bytes())
        .unwrap();
    child.wait_with_output().unwrap()
}

fn records(base: &Path) -> Vec<serde_json::Value> {
    match fs::read_dir(base.join("run/memory-guard/root")) {
        Ok(entries) => entries
            .flatten()
            .filter(|entry| entry.path().extension().is_some_and(|ext| ext == "json"))
            .map(|entry| serde_json::from_str(&fs::read_to_string(entry.path()).unwrap()).unwrap())
            .collect(),
        Err(_) => Vec::new(),
    }
}

fn custody(id: &str, trees: serde_json::Value, recovery: serde_json::Value) -> serde_json::Value {
    serde_json::json!({
        "episodeId": id, "host": "testhost", "kind": "custody", "key": "claude:shared@testhost",
        "why": "1 agent processes could not be confirmed stopped", "since": 1,
        "trees": trees, "recovery": recovery, "override": null
    })
}

fn start_of(pid: u32) -> u64 {
    let stat = fs::read_to_string(format!("/proc/{pid}/stat")).unwrap();
    let rest = &stat[stat.rfind(')').unwrap() + 1..];
    rest.split_whitespace().nth(19).unwrap().parse().unwrap()
}

#[test]
fn t31_1_without_root_nothing_happens() {
    let base = base(
        "noroot",
        custody("ep_1", serde_json::json!([]), serde_json::Value::Null),
    );
    let output = run(&base.0, "memory-guard-recover", "ep_1", false, "");
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("must run as root"));
    assert!(records(&base.0).is_empty());
}

#[test]
fn n4_t31_2_recovery_kills_the_named_tree_and_records_the_kill_time_never_a_reused_pid() {
    let mut leader = unsafe {
        Command::new("sleep")
            .arg("300")
            .pre_exec(|| {
                libc::setsid();
                Ok(())
            })
            .spawn()
            .unwrap()
    };
    let mut other = Command::new("sleep").arg("300").spawn().unwrap();
    let trees = serde_json::json!([
        {"launchId": "sl-1", "pid": leader.id(), "start": start_of(leader.id()), "unit": null},
        // A recorded start that is not this process's: a reused pid is not ours.
        {"launchId": "sl-2", "pid": other.id(), "start": start_of(other.id()) + 1, "unit": null}
    ]);
    let base = base("recover", custody("ep_2", trees, serde_json::Value::Null));

    let output = run(&base.0, "memory-guard-recover", "ep_2", true, "");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        std::os::unix::process::ExitStatusExt::signal(&leader.wait().unwrap()),
        Some(9)
    );
    assert!(
        other.try_wait().unwrap().is_none(),
        "a reused pid is never signalled"
    );
    let _ = other.kill();

    let [record] = records(&base.0).try_into().unwrap();
    assert_eq!(record["action"], "recovery");
    assert_eq!(record["episodeId"], "ep_2");
    assert!(record["killedAt"].as_u64().unwrap() > 0);
    assert_eq!(record["operator"]["user"], "root");
}

#[test]
fn n6_an_episode_file_others_can_write_is_not_the_gateways_own_record() {
    let base = base(
        "tampered",
        custody("ep_3", serde_json::json!([]), serde_json::Value::Null),
    );
    let path = base.0.join("run/memory-guard/episodes/ep_3.json");
    fs::set_permissions(&path, fs::Permissions::from_mode(0o666)).unwrap();
    let output = run(&base.0, "memory-guard-recover", "ep_3", true, "");
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("not the gateway's own record"));
    assert!(records(&base.0).is_empty());
}

#[test]
fn n7_absent_t31_4_an_override_without_a_failed_recovery_is_refused() {
    let pending = serde_json::json!({"outcome": "pending"});
    let base = base("nofail", custody("ep_4", serde_json::json!([]), pending));
    let output = run(&base.0, "memory-guard-override", "ep_4", true, "ep_4\n");
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("needs a failed recovery"));
    assert!(records(&base.0).is_empty());
}

#[test]
fn n6_timeout_t31_5_the_statement_is_printed_first_and_only_the_typed_episode_id_confirms() {
    let failed = serde_json::json!({
        "outcome": "failed",
        "survivors": [{"launchId": "sl-9", "pid": 4242, "start": 7, "unit": null, "state": "D"}]
    });
    let base = base("override", custody("ep_5", serde_json::json!([]), failed));

    for typed in ["", "yes\n", "ep_6\n"] {
        let output = run(&base.0, "memory-guard-override", "ep_5", true, typed);
        assert!(!output.status.success(), "typed {typed:?}");
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(stdout.contains("Risk accepted:"));
        assert!(stdout.contains("launch record sl-9, process 4242 started at 7"));
        assert!(String::from_utf8_lossy(&output.stderr).contains("not confirmed"));
        assert!(
            records(&base.0).is_empty(),
            "nothing is written before confirmation"
        );
    }

    let output = run(&base.0, "memory-guard-override", "ep_5", true, "ep_5\n");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let [record] = records(&base.0).try_into().unwrap();
    assert_eq!(record["action"], "override");
    let kind = record["statementKind"].as_str().unwrap();
    assert!(kind == "strict" || kind == "residual");
    // N8: every field present; what cannot be established is `unknown`.
    for field in [
        "statement",
        "finding",
        "operator",
        "trees",
        "at",
        "host",
        "kind",
    ] {
        assert!(!record[field].is_null(), "{field} recorded");
    }
    assert!(
        record["statement"]
            .as_str()
            .unwrap()
            .contains("launch record sl-9")
    );
}

#[test]
fn n6_unreadable_a_statement_that_cannot_be_printed_writes_nothing() {
    let failed = serde_json::json!({"outcome": "failed", "survivors": []});
    let base = base("noprint", custody("ep_7", serde_json::json!([]), failed));
    let mut child = Command::new(env!("CARGO_BIN_EXE_tightbeam"))
        .args([
            "memory-guard-override",
            "--base",
            base.0.to_str().unwrap(),
            "ep_7",
        ])
        .env("TIGHTBEAM_TEST_ASSUME_ROOT", "1")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    // Nobody reads the statement: the output closes before it is printed.
    drop(child.stdout.take());
    let _ = child.stdin.take().unwrap().write_all(b"ep_7\n");
    let status = child.wait().unwrap();
    assert!(
        !status.success(),
        "it does not proceed without its statement"
    );
    assert!(records(&base.0).is_empty(), "nothing is written");
}

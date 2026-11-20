//! The session launch step, run for real (memory limits v1.4 R10, R14, T10, AS2).
//!
//! An "adapter" shell is started through this binary's own `harness-exec`, as the
//! gateway starts every adapter. It starts a "session process" the way the Claude
//! adapter does: through the program named by `CLAUDE_CODE_EXECUTABLE`, here a link
//! to this binary called `tightbeam-session-exec`, with `--session-id=<id>`. The
//! session process starts a tool. Every process reports its own `oom_score_adj`.
//!
//! Regression value: dropping the step's write leaves the session at the adapter's
//! value; writing an absolute +100 instead of "inherited + 100" fails the +50
//! variant; a step that forgot to `setsid` cannot be ended by `harness-group`.
#![cfg(target_os = "linux")]

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

struct Fixture {
    dir: PathBuf,
    guard_dir: PathBuf,
    adapter: Child,
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = self.adapter.kill();
        let _ = self.adapter.wait();
        for name in ["session.pid", "tool.pid", "adapter.pid"] {
            if let Ok(pid) = fs::read_to_string(self.dir.join(name)) {
                let _ = Command::new("kill").args(["-KILL", pid.trim()]).status();
            }
        }
        let _ = fs::remove_dir_all(&self.dir);
    }
}

fn script(path: &Path, body: &str) {
    fs::write(path, format!("#!/bin/sh\n{body}")).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o755)).unwrap();
}

fn own_oom() -> i64 {
    fs::read_to_string("/proc/self/oom_score_adj")
        .unwrap()
        .trim()
        .parse()
        .unwrap()
}

fn wait_for(path: &Path) -> String {
    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        if let Ok(text) = fs::read_to_string(path) {
            if !text.trim().is_empty() {
                return text.trim().to_string();
            }
        }
        assert!(
            Instant::now() < deadline,
            "{} never appeared",
            path.display()
        );
        std::thread::sleep(Duration::from_millis(25));
    }
}

/// Start the adapter through `harness-exec`, `raise` above this test's own
/// `oom_score_adj` (the "gateway" value), with the guard in `mode`.
fn start(name: &str, raise: i64, mode: &str) -> Fixture {
    let dir = std::env::temp_dir().join(format!("tb-mg-step-{name}-{}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    let guard_dir = dir.join("memory-guard");
    fs::create_dir_all(guard_dir.join("bin")).unwrap();
    fs::write(
        guard_dir.join("launch.json"),
        format!(r#"{{"v":1,"mode":"{mode}","sessionLimit":536870912}}"#),
    )
    .unwrap();

    let binary = env!("CARGO_BIN_EXE_tightbeam");
    let step = guard_dir.join("bin/tightbeam-session-exec");
    std::os::unix::fs::symlink(binary, &step).unwrap();

    // The harness the step execs: records itself, then starts a tool.
    let claude = dir.join("fake-claude");
    script(
        &claude,
        &format!(
            "echo $$ > {d}/session.pid\n\
             cat /proc/$$/oom_score_adj > {d}/session.oom\n\
             echo \"${{TIGHTBEAM_MEMORY_GUARD_DIR:-unset}}\" > {d}/session.env\n\
             echo \"$*\" > {d}/session.args\n\
             sh -c 'echo $$ > {d}/tool.pid; cat /proc/$$/oom_score_adj > {d}/tool.oom; exec sleep 300' &\n\
             exec sleep 300\n",
            d = dir.display()
        ),
    );

    // The adapter: records itself, starts a tool of its own (a Codex-like tree
    // never goes through the step), then a session through the step.
    let adapter_script = dir.join("adapter.sh");
    script(
        &adapter_script,
        &format!(
            "echo $$ > {d}/adapter.pid\n\
             cat /proc/$$/oom_score_adj > {d}/adapter.oom\n\
             sh -c 'cat /proc/$$/oom_score_adj > {d}/adapter-tool.oom' \n\
             \"$CLAUDE_CODE_EXECUTABLE\" --output-format stream-json --session-id=sess-1 --verbose &\n\
             exec sleep 300\n",
            d = dir.display()
        ),
    );

    let gateway_value = own_oom() + raise;
    let identity = dir.join("adapter.identity");
    let adapter = Command::new("sh")
        .arg("-c")
        .arg(format!(
            "echo {gateway_value} > /proc/self/oom_score_adj && exec {binary} harness-exec {} adapter-launch-1 -- {}",
            identity.display(),
            adapter_script.display()
        ))
        .env("CLAUDE_CODE_EXECUTABLE", &step)
        .env("TIGHTBEAM_SESSION_EXEC_TARGET", &claude)
        .env("TIGHTBEAM_MEMORY_GUARD_DIR", &guard_dir)
        .env("TIGHTBEAM_ADAPTER_LAUNCH_ID", "adapter-launch-1")
        .stdin(Stdio::null())
        .spawn()
        .unwrap();

    Fixture {
        dir,
        guard_dir,
        adapter,
    }
}

fn record(fixture: &Fixture) -> serde_json::Value {
    let sessions = fixture.guard_dir.join("sessions");
    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        if let Ok(entries) = fs::read_dir(&sessions) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.extension().is_some_and(|ext| ext == "json") {
                    return serde_json::from_str(&fs::read_to_string(path).unwrap()).unwrap();
                }
            }
        }
        assert!(Instant::now() < deadline, "no launch record");
        std::thread::sleep(Duration::from_millis(25));
    }
}

fn alive(pid: &str) -> bool {
    Path::new(&format!("/proc/{pid}")).exists()
        && !fs::read_to_string(format!("/proc/{pid}/stat"))
            .map(|stat| {
                stat.rsplit(')')
                    .next()
                    .unwrap_or("")
                    .trim_start()
                    .starts_with('Z')
            })
            .unwrap_or(true)
}

#[test]
fn t10_session_trees_run_100_above_the_gateway_and_the_adapter_is_never_written() {
    for (name, raise) in [("at-zero", 0), ("at-fifty", 50)] {
        let fixture = start(name, raise, "watched");
        let gateway = own_oom() + raise;

        let adapter = wait_for(&fixture.dir.join("adapter.oom"));
        let adapter_tool = wait_for(&fixture.dir.join("adapter-tool.oom"));
        let session = wait_for(&fixture.dir.join("session.oom"));
        let tool = wait_for(&fixture.dir.join("tool.oom"));
        let expected_session = (gateway + 100).min(1000);

        assert_eq!(
            adapter,
            gateway.to_string(),
            "{name}: adapter keeps the gateway's value"
        );
        assert_eq!(
            adapter_tool,
            gateway.to_string(),
            "{name}: a tool of the adapter tree too"
        );
        assert_eq!(
            session,
            expected_session.to_string(),
            "{name}: session +100"
        );
        assert_eq!(
            tool,
            expected_session.to_string(),
            "{name}: the session's tool inherits it"
        );

        // AS2/R10: the record was made before harness code ran, with the id the
        // adapter passed; the step's own variables never reach the harness.
        let record = record(&fixture);
        assert_eq!(record["sessionId"], "sess-1");
        assert_eq!(record["adapterLaunchId"], "adapter-launch-1");
        assert_eq!(record["placement"], "watched");
        assert_eq!(record["oomScoreAdj"], expected_session);
        assert_eq!(
            record["pid"].to_string(),
            wait_for(&fixture.dir.join("session.pid"))
        );
        assert_eq!(wait_for(&fixture.dir.join("session.env")), "unset");
        assert_eq!(
            wait_for(&fixture.dir.join("session.args")),
            "--output-format stream-json --session-id=sess-1 --verbose"
        );
    }
}

#[test]
fn the_recorded_identity_ends_the_whole_session_tree_and_only_it() {
    let fixture = start("kill", 0, "watched");
    let session = wait_for(&fixture.dir.join("session.pid"));
    let tool = wait_for(&fixture.dir.join("tool.pid"));
    let adapter = wait_for(&fixture.dir.join("adapter.pid"));
    let record = record(&fixture);
    let identity = record["identity"].as_str().unwrap().to_string();
    let fields: Vec<String> = wait_for(Path::new(&identity))
        .split('\t')
        .map(str::to_string)
        .collect();
    assert_eq!(fields.len(), 4);
    assert_eq!(fields[0], session, "the step leads its own group (setsid)");
    assert_eq!(fields[0], fields[1]);

    // The same invocation HarnessProcess.kill_session_tree/2 makes.
    let status = Command::new(env!("CARGO_BIN_EXE_tightbeam"))
        .args([
            "harness-group",
            &fields[1],
            &identity,
            &fields[2],
            &fields[3],
            "tightbeam-harness-identity-v2",
        ])
        .status()
        .unwrap();
    assert!(status.success());

    let deadline = Instant::now() + Duration::from_secs(10);
    while (alive(&session) || alive(&tool)) && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(25));
    }
    assert!(!alive(&session), "session process ended");
    assert!(!alive(&tool), "its tool ended with it");
    assert!(alive(&adapter), "the adapter is untouched");
}

#[test]
fn mode_off_launches_the_harness_untouched() {
    let fixture = start("off", 0, "off");
    assert_eq!(
        wait_for(&fixture.dir.join("session.oom")),
        own_oom().to_string()
    );
    assert!(!fixture.guard_dir.join("sessions").exists());
}

/// Run the step by hand for `sid` against `guard_dir`, with `/bin/echo` as
/// the harness, and with extra environment.
fn run_step(guard_dir: &Path, sid: &str, env: &[(&str, &str)]) -> std::process::Output {
    let mut command = Command::new(guard_dir.join("bin/tightbeam-session-exec"));
    command
        .arg(format!("--session-id={sid}"))
        .env("TIGHTBEAM_SESSION_EXEC_TARGET", "/bin/echo")
        .env("TIGHTBEAM_MEMORY_GUARD_DIR", guard_dir);
    for (name, value) in env {
        command.env(name, value);
    }
    command.output().unwrap()
}

/// The step refused: no harness output, the refusal status, a refusal record
/// naming `why`, and no launch record for `sid` (v1.13 FS2, T23).
fn assert_refused(guard_dir: &Path, sid: &str, output: &std::process::Output, why: &str) {
    assert_eq!(output.status.code(), Some(75), "refusal status");
    assert!(output.stdout.is_empty(), "the harness never ran");
    assert!(String::from_utf8_lossy(&output.stderr).contains("REFUSED"));
    let refusal = fs::read_dir(guard_dir.join("refusals"))
        .unwrap()
        .flatten()
        .map(|entry| {
            serde_json::from_str::<serde_json::Value>(&fs::read_to_string(entry.path()).unwrap())
                .unwrap()
        })
        .find(|record| record["sessionId"] == sid)
        .expect("a refusal record");
    assert!(
        refusal["reason"].as_str().unwrap().contains(why),
        "{refusal}"
    );
    let recorded = fs::read_dir(guard_dir.join("sessions"))
        .map(|entries| {
            entries.flatten().any(|entry| {
                fs::read_to_string(entry.path())
                    .map(|text| text.contains(&format!("\"sessionId\":\"{sid}\"")))
                    .unwrap_or(false)
            })
        })
        .unwrap_or(false);
    assert!(!recorded, "no launch record for a refused launch");
}

#[test]
fn b5_unreadable_an_invalid_configuration_refuses_and_records_why() {
    let fixture = start("broken", 0, "watched");
    fs::write(fixture.guard_dir.join("launch.json"), "{not json").unwrap();
    let output = run_step(&fixture.guard_dir, "sess-2", &[]);
    assert_refused(
        &fixture.guard_dir,
        "sess-2",
        &output,
        "launch.json is invalid",
    );
}

#[test]
fn b5_absent_a_missing_configuration_refuses() {
    let fixture = start("missing", 0, "watched");
    fs::remove_file(fixture.guard_dir.join("launch.json")).unwrap();
    let output = run_step(&fixture.guard_dir, "sess-3", &[]);
    assert_refused(
        &fixture.guard_dir,
        "sess-3",
        &output,
        "launch.json could not be read",
    );
}

#[test]
fn b1_unreadable_a_launch_record_that_cannot_be_written_refuses() {
    let fixture = start("norecord", 0, "watched");
    let sessions = fixture.guard_dir.join("sessions");
    fs::create_dir_all(&sessions).unwrap();
    let _ = record(&fixture);
    fs::set_permissions(&sessions, fs::Permissions::from_mode(0o555)).unwrap();
    let output = run_step(&fixture.guard_dir, "sess-4", &[]);
    fs::set_permissions(&sessions, fs::Permissions::from_mode(0o755)).unwrap();
    assert_refused(
        &fixture.guard_dir,
        "sess-4",
        &output,
        "identity could not be opened",
    );
}

#[test]
fn j1_unreadable_and_absent_an_oom_score_adj_that_cannot_be_read_refuses() {
    let fixture = start("oomread", 0, "watched");
    let missing = fixture.dir.join("no-such-oom");
    let output = run_step(
        &fixture.guard_dir,
        "sess-5",
        &[(
            "TIGHTBEAM_TEST_OOM_SCORE_ADJ_PATH",
            missing.to_str().unwrap(),
        )],
    );
    assert_refused(
        &fixture.guard_dir,
        "sess-5",
        &output,
        "oom_score_adj could not be read",
    );

    let malformed = fixture.dir.join("malformed-oom");
    fs::write(&malformed, "lots\n").unwrap();
    let output = run_step(
        &fixture.guard_dir,
        "sess-6",
        &[(
            "TIGHTBEAM_TEST_OOM_SCORE_ADJ_PATH",
            malformed.to_str().unwrap(),
        )],
    );
    assert_refused(&fixture.guard_dir, "sess-6", &output, "malformed");
}

#[test]
fn j2_unreadable_an_oom_score_adj_that_cannot_be_raised_refuses() {
    let fixture = start("oomwrite", 0, "watched");
    let read_only = fixture.dir.join("read-only-oom");
    fs::write(&read_only, "0\n").unwrap();
    fs::set_permissions(&read_only, fs::Permissions::from_mode(0o444)).unwrap();
    let output = run_step(
        &fixture.guard_dir,
        "sess-7",
        &[(
            "TIGHTBEAM_TEST_OOM_SCORE_ADJ_PATH",
            read_only.to_str().unwrap(),
        )],
    );
    assert_refused(
        &fixture.guard_dir,
        "sess-7",
        &output,
        "oom_score_adj could not be raised",
    );
}

#[test]
fn count_only_launches_the_harness_untouched() {
    let fixture = start("countonly", 0, "count-only");
    assert_eq!(
        wait_for(&fixture.dir.join("session.oom")),
        own_oom().to_string()
    );
    assert!(!fixture.guard_dir.join("sessions").exists());
}

#[test]
fn c8_absent_an_enforced_launch_without_its_unit_runs_watched_and_says_why() {
    let fixture = start("nounit", 0, "enforced");
    let launched = record(&fixture);
    assert_eq!(launched["placement"], "watched");
    assert!(
        launched["errors"][0]
            .as_str()
            .unwrap()
            .contains("lacks the enforced layout")
    );
    assert_eq!(
        wait_for(&fixture.dir.join("session.oom")),
        (own_oom() + 100).min(1000).to_string()
    );
}

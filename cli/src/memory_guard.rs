//! The session launch step (memory limits v1.1 R10, R12c, R14, AS2).
//!
//! The Claude adapter starts every session process through the executable named
//! by `CLAUDE_CODE_EXECUTABLE`. On a host whose memory guard is `watched` or
//! `enforced`, the gateway points that variable at a link to this binary named
//! `tightbeam-session-exec`. Before the harness runs any code, the step:
//!
//! 1. raises its own `oom_score_adj` by +100 above the value it inherited
//!    (capped at 1000), which every descendant inherits (R14);
//! 2. leads its own session and process group, so the tree can be ended whole
//!    by the existing `harness-group` kill, which also finds detached groups;
//! 3. in `enforced` mode, joins a fresh `harness/session-<id>` cgroup with the
//!    session limit, swap 0 and `memory.oom.group` 1 (R12c);
//! 4. records the launch (harness session id, pid, start time, adapter launch,
//!    placement and limit) and an identity the kill path can verify;
//!
//! then execs the real harness with the same arguments.
//!
//! v1.13 FS2: the step fails **closed** on Tightbeam's own failures. When it
//! cannot read its configuration, raise `oom_score_adj` (R14), write the
//! identity or write the launch record, it does not exec the harness: an
//! unrecorded tree would have no custody, no per-tree limit and no attribution.
//! It leaves a refusal record (`<dir>/refusals/<launchId>.json`) so the gateway
//! can tell the refusal from a harness failure, and exits with
//! [`REFUSED_EXIT`]. Only a configuration reading `off` (or `count-only`, a
//! host without the mechanisms) execs the harness untouched. A tree that could
//! not be placed under the kernel limit still runs `watched`, recorded (R12a).

use std::collections::BTreeMap;
use std::fs;
use std::fs::OpenOptions;
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

/// The name the gateway's link to this binary carries.
pub const STEP_NAME: &str = "tightbeam-session-exec";

/// The exit status of a refusal (v1.13 FS2), distinct from the harness's own.
pub const REFUSED_EXIT: i32 = 75;

const DIR_ENV: &str = "TIGHTBEAM_MEMORY_GUARD_DIR";
const TARGET_ENV: &str = "TIGHTBEAM_SESSION_EXEC_TARGET";
const ADAPTER_LAUNCH_ENV: &str = "TIGHTBEAM_ADAPTER_LAUNCH_ID";
const STEP_ENV: [&str; 3] = [DIR_ENV, TARGET_ENV, ADAPTER_LAUNCH_ENV];

/// Whether this process was started as the session launch step.
pub fn invoked_as_step(argv0: Option<&str>) -> bool {
    argv0
        .and_then(|arg| Path::new(arg).file_name())
        .is_some_and(|name| name == STEP_NAME)
}

/// Run the step. Returns only if the harness could not be executed.
pub fn session_step(args: &[String]) -> i32 {
    let target = match std::env::var(TARGET_ENV) {
        Ok(target) if !target.is_empty() => target,
        _ => {
            eprintln!("{STEP_NAME}: {TARGET_ENV} is not set; no harness to start");
            return 127;
        }
    };

    // A session process (one named by a session flag) starts only recorded.
    // Without the guard's directory, or with a session id or adapter launch
    // that cannot be recorded, it does not start (FS2): it would run outside
    // custody. Auth probes carry no session flag and are not session processes.
    match (session_id(args), session_flag(args)) {
        (Some(sid), _) => {
            let Some(dir) = std::env::var(DIR_ENV).ok().filter(|dir| !dir.is_empty()) else {
                eprintln!(
                    "{STEP_NAME}: REFUSED to start the session process: {DIR_ENV} is not set"
                );
                return REFUSED_EXIT;
            };
            let adapter_launch = std::env::var(ADAPTER_LAUNCH_ENV).unwrap_or_default();
            let prepared = if adapter_launch.is_empty() {
                Err(Refusal {
                    launch: launch_id(&sid),
                    reason: format!("{ADAPTER_LAUNCH_ENV} is not set"),
                })
            } else {
                prepare(Path::new(&dir), &sid, &adapter_launch)
            };
            if let Err(refusal) = prepared {
                return refuse(Path::new(&dir), &sid, &adapter_launch, &refusal);
            }
        }
        (None, true) => {
            eprintln!(
                "{STEP_NAME}: REFUSED to start the session process: its session id is not valid"
            );
            return REFUSED_EXIT;
        }
        (None, false) => {}
    }

    let mut command = Command::new(&target);
    command.args(args);
    for name in STEP_ENV {
        command.env_remove(name);
    }
    let error = command.exec();
    eprintln!("{STEP_NAME}: {target} could not be executed: {error}");
    126
}

/// The harness session id the adapter passes: `--session-id` for a new or
/// forked session, `--resume` for a loaded one. Auth probes carry neither and
/// are not session processes.
pub fn session_id(args: &[String]) -> Option<String> {
    let value = |flag: &str| {
        args.iter().enumerate().find_map(|(index, arg)| {
            if let Some(value) = arg.strip_prefix(&format!("{flag}=")) {
                Some(value.to_string())
            } else if arg == flag {
                args.get(index + 1).cloned()
            } else {
                None
            }
        })
    };

    value("--session-id")
        .or_else(|| value("--resume"))
        .filter(|sid| valid_id(sid))
}

/// Whether the arguments carry a session flag at all.
fn session_flag(args: &[String]) -> bool {
    args.iter().any(|arg| {
        ["--session-id", "--resume"]
            .iter()
            .any(|flag| arg == flag || arg.starts_with(&format!("{flag}=")))
    })
}

fn valid_id(sid: &str) -> bool {
    !sid.is_empty()
        && sid.len() <= 128
        && sid
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
}

/// What the gateway publishes for the step (`<dir>/launch.json`).
#[derive(Debug, Default, PartialEq)]
pub struct LaunchConfig {
    pub mode: String,
    pub fs: Option<String>,
    pub harness: Option<String>,
    pub session_limit: Option<u64>,
}

pub fn read_config(dir: &Path) -> Result<LaunchConfig, String> {
    let text = fs::read_to_string(dir.join("launch.json"))
        .map_err(|error| format!("launch.json could not be read: {error}"))?;
    let value: serde_json::Value =
        serde_json::from_str(&text).map_err(|error| format!("launch.json is invalid: {error}"))?;
    if value.get("v").and_then(|v| v.as_u64()) != Some(1) {
        return Err("launch.json has an unknown version".into());
    }
    Ok(LaunchConfig {
        mode: value
            .get("mode")
            .and_then(|v| v.as_str())
            .ok_or("launch.json names no mode")?
            .to_string(),
        fs: value.get("fs").and_then(|v| v.as_str()).map(str::to_string),
        harness: value
            .get("harness")
            .and_then(|v| v.as_str())
            .map(str::to_string),
        session_limit: value.get("sessionLimit").and_then(|v| v.as_u64()),
    })
}

/// Why the step did not start the harness, and the launch it would have been.
#[derive(Debug)]
pub struct Refusal {
    pub launch: String,
    pub reason: String,
}

fn prepare(dir: &Path, sid: &str, adapter_launch: &str) -> Result<(), Refusal> {
    let launch = launch_id(sid);
    let refuse = |reason: String| Refusal {
        launch: launch.clone(),
        reason,
    };
    let mut errors: Vec<String> = Vec::new();

    // FS2 (B5): the guard publishes the configuration in every mode, so a
    // missing or unreadable one is a fault, never "no contract".
    let config = read_config(dir).map_err(&refuse)?;

    // `off` (an admin turned the guard off) launches the harness untouched,
    // and so does `count-only`, a host without the mechanisms (R12a). A mode
    // this step does not know is a fault, never "no contract".
    match config.mode.as_str() {
        "off" | "count-only" => return Ok(()),
        "watched" | "enforced" => {}
        other => {
            return Err(refuse(format!(
                "launch.json names an unknown mode {other:?}"
            )));
        }
    }

    // R14: the session tree runs at the value inherited from the adapter (the
    // gateway's, 0 on Sirius) plus 100, capped at 1000. Raising one's own value
    // needs no privilege. A value that cannot be read or set refuses (J1, J2).
    let inherited = read_oom_score_adj().map_err(&refuse)?;
    let oom = raised_oom(inherited);
    fs::write(oom_path(), oom.to_string())
        .map_err(|error| refuse(format!("oom_score_adj could not be raised: {error}")))?;

    let sessions = dir.join("sessions");
    fs::create_dir_all(&sessions).map_err(|error| {
        refuse(format!(
            "launch records directory could not be created: {error}"
        ))
    })?;
    let identity_path = sessions.join(format!("{launch}.identity"));
    let mut identity = OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o600)
        .open(&identity_path)
        .map_err(|error| refuse(format!("identity could not be opened: {error}")))?;
    if let Err((step, error)) =
        crate::harness_process::prepare_session_identity(&identity_path, &mut identity, &launch)
    {
        let _ = fs::remove_file(&identity_path);
        return Err(refuse(format!(
            "identity could not be written: {step}: {error}"
        )));
    }

    // R12a: a tree the kernel cannot take runs watched, recorded (C8).
    let (placement, unit) = if config.mode == "enforced" {
        match join_session_unit(&config, sid) {
            Ok(unit) => ("enforced", Some(unit)),
            Err(error) => {
                errors.push(error);
                ("watched", None)
            }
        }
    } else {
        ("watched", None)
    };

    let pid = std::process::id();
    // The start time is the tree's identity against pid reuse (D2.stale).
    let start = proc_start(pid);
    if cfg!(target_os = "linux") && start.is_none() {
        let _ = fs::remove_file(&identity_path);
        return Err(refuse(
            "the session process's start time could not be read".into(),
        ));
    }
    let mut record = BTreeMap::new();
    record.insert("v", serde_json::json!(1));
    record.insert("launchId", serde_json::json!(launch));
    record.insert("sessionId", serde_json::json!(sid));
    record.insert("pid", serde_json::json!(pid));
    record.insert("start", serde_json::json!(start));
    record.insert("adapterLaunchId", serde_json::json!(adapter_launch));
    record.insert("placement", serde_json::json!(placement));
    record.insert("unit", serde_json::json!(unit));
    record.insert(
        "identity",
        serde_json::json!(identity_path.to_string_lossy()),
    );
    record.insert("sessionLimit", serde_json::json!(config.session_limit));
    record.insert("oomScoreAdj", serde_json::json!(oom));
    record.insert("errors", serde_json::json!(errors));
    record.insert("launchedAt", serde_json::json!(now_ms()));

    let body = serde_json::to_vec(&record).map_err(|error| {
        let _ = fs::remove_file(&identity_path);
        refuse(format!("launch record could not be encoded: {error}"))
    })?;
    atomic_write(&sessions.join(format!("{launch}.json")), &body).map_err(|error| {
        let _ = fs::remove_file(&identity_path);
        refuse(format!("launch record could not be written: {error}"))
    })
}

/// R14's value: the inherited one plus 100, capped at 1000, never lowered.
pub fn raised_oom(inherited: i64) -> i64 {
    (inherited + 100).min(1000).max(inherited)
}

/// The process's own `oom_score_adj`. Debug builds (tests only) may name
/// another file, so the refusal paths can be driven without privilege.
fn oom_path() -> PathBuf {
    #[cfg(debug_assertions)]
    if let Ok(path) = std::env::var("TIGHTBEAM_TEST_OOM_SCORE_ADJ_PATH") {
        return PathBuf::from(path);
    }
    PathBuf::from("/proc/self/oom_score_adj")
}

fn read_oom_score_adj() -> Result<i64, String> {
    let text = fs::read_to_string(oom_path())
        .map_err(|error| format!("oom_score_adj could not be read: {error}"))?;
    text.trim()
        .parse::<i64>()
        .map_err(|_| format!("oom_score_adj is malformed: {:?}", text.trim()))
}

/// Record the refusal for the gateway, say it on stderr, and exit
/// [`REFUSED_EXIT`] without starting the harness (FS2).
fn refuse(dir: &Path, sid: &str, adapter_launch: &str, refusal: &Refusal) -> i32 {
    eprintln!(
        "{STEP_NAME}: REFUSED to start the session process: {}",
        refusal.reason
    );
    let refusals = dir.join("refusals");
    let mut record = BTreeMap::new();
    record.insert("v", serde_json::json!(1));
    record.insert("launchId", serde_json::json!(refusal.launch));
    record.insert("sessionId", serde_json::json!(sid));
    record.insert("adapterLaunchId", serde_json::json!(adapter_launch));
    record.insert("reason", serde_json::json!(refusal.reason));
    record.insert("at", serde_json::json!(now_ms()));
    let body = serde_json::to_vec(&record).unwrap_or_default();
    let written = fs::create_dir_all(&refusals)
        .and_then(|_| atomic_write(&refusals.join(format!("{}.json", refusal.launch)), &body));
    if let Err(error) = written {
        eprintln!("{STEP_NAME}: the refusal could not be recorded: {error}");
    }
    REFUSED_EXIT
}

/// Join a fresh `harness/session-<sid>` unit. A leftover empty unit of an
/// earlier process of the same session is removed first, so the new unit's
/// local OOM counters describe this process only (R10).
fn join_session_unit(config: &LaunchConfig, sid: &str) -> Result<String, String> {
    let (Some(fs_root), Some(harness), Some(limit)) =
        (&config.fs, &config.harness, config.session_limit)
    else {
        return Err("launch.json lacks the enforced layout".into());
    };
    let unit = format!("{}/session-{sid}", harness.trim_end_matches('/'));
    let dir = PathBuf::from(fs_root).join(unit.trim_start_matches('/'));

    if dir.exists() {
        fs::remove_dir(&dir).map_err(|error| {
            format!("session unit {unit} is still in use and could not be renewed: {error}")
        })?;
    }
    fs::create_dir(&dir)
        .map_err(|error| format!("session unit {unit} could not be created: {error}"))?;
    for (file, value) in [
        ("memory.swap.max", "0".to_string()),
        ("memory.oom.group", "1".to_string()),
        ("memory.max", limit.to_string()),
    ] {
        fs::write(dir.join(file), &value)
            .map_err(|error| format!("{unit}/{file} could not be written: {error}"))?;
    }
    fs::write(dir.join("cgroup.procs"), std::process::id().to_string())
        .map_err(|error| format!("session process could not join {unit}: {error}"))?;
    Ok(unit)
}

fn launch_id(sid: &str) -> String {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    format!("sl-{sid}-{}-{nanos}", std::process::id())
}

fn proc_start(pid: u32) -> Option<u64> {
    let stat = fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    let rest = &stat[stat.rfind(')')? + 1..];
    rest.split_whitespace().nth(19)?.parse().ok()
}

fn now_ms() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0)
}

fn atomic_write(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let mut pending = path.as_os_str().to_owned();
    pending.push(".pending");
    let pending = PathBuf::from(pending);
    let mut file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o600)
        .open(&pending)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    fs::rename(&pending, path)
}

/// Join the adapter unit named by `TIGHTBEAM_ADAPTER_CGROUP` (a cgroup
/// directory) before the helper execs the adapter (R12c). A failure leaves the
/// adapter where it is and is reported on the adapter's stderr; the gateway
/// checks each adapter's membership and samples and limits one outside its
/// unit as in watched mode, with a lifecycle record (R12a).
pub fn join_adapter_cgroup() {
    if let Ok(dir) = std::env::var("TIGHTBEAM_ADAPTER_CGROUP") {
        if !dir.is_empty() {
            if let Err(error) = fs::write(
                Path::new(&dir).join("cgroup.procs"),
                std::process::id().to_string(),
            ) {
                eprintln!("tightbeam: the adapter could not join its memory unit {dir}: {error}");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(list: &[&str]) -> Vec<String> {
        list.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn session_id_comes_from_session_id_then_resume() {
        assert_eq!(
            session_id(&args(&["--verbose", "--session-id=abc-1"])),
            Some("abc-1".into())
        );
        assert_eq!(
            session_id(&args(&[
                "--resume",
                "r-2",
                "--output-format",
                "stream-json"
            ])),
            Some("r-2".into())
        );
        assert_eq!(
            session_id(&args(&[
                "--resume=old",
                "--fork-session",
                "--session-id=new"
            ])),
            Some("new".into())
        );
        assert_eq!(session_id(&args(&["auth", "status"])), None);
        assert_eq!(session_id(&args(&["--session-id=../etc"])), None);
    }

    #[test]
    fn invoked_as_step_matches_the_link_name_only() {
        assert!(invoked_as_step(Some(
            "/x/run/memory-guard/bin/tightbeam-session-exec"
        )));
        assert!(!invoked_as_step(Some("/usr/local/bin/tightbeam")));
        assert!(!invoked_as_step(None));
    }

    #[test]
    fn j2_stale_raised_oom_is_capped_at_1000_and_never_lowered() {
        assert_eq!(raised_oom(0), 100);
        assert_eq!(raised_oom(950), 1000);
        assert_eq!(raised_oom(1000), 1000);
        assert_eq!(raised_oom(-500), -400);
    }

    #[test]
    fn b5_partial_a_configuration_without_a_mode_is_refused() {
        let dir = std::env::temp_dir().join(format!("tb-mg-nomode-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join("launch.json"), r#"{"v":1}"#).unwrap();
        assert!(read_config(&dir).unwrap_err().contains("no mode"));
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn read_config_requires_version_one() {
        let dir = std::env::temp_dir().join(format!("tb-mg-config-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join("launch.json"), r#"{"v":2,"mode":"enforced"}"#).unwrap();
        assert!(read_config(&dir).is_err());
        fs::write(
            dir.join("launch.json"),
            r#"{"v":1,"mode":"enforced","fs":"/sys/fs/cgroup","harness":"/a/harness","sessionLimit":536870912}"#,
        )
        .unwrap();
        assert_eq!(
            read_config(&dir).unwrap(),
            LaunchConfig {
                mode: "enforced".into(),
                fs: Some("/sys/fs/cgroup".into()),
                harness: Some("/a/harness".into()),
                session_limit: Some(536870912),
            }
        );
        fs::remove_dir_all(&dir).unwrap();
    }
}

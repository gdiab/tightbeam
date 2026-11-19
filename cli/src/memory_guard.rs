//! The session launch step (memory limits v1.1 R10, R12c, R14, AS2).
//!
//! The Claude adapter starts every session process through the executable named
//! by `CLAUDE_CODE_EXECUTABLE`. On a host whose memory guard is `watched` or
//! `enforced`, the gateway points that variable at a link to this binary named
//! `tightbeam-session-exec`. Before the harness runs any code, the step:
//!
//! 1. raises its own `oom_score_adj` by the host's configured amount (+100 by
//!    default) above the value it inherited, which every descendant inherits
//!    (R14);
//! 2. leads its own session and process group, so the tree can be ended whole
//!    by the existing `harness-group` kill, which also finds detached groups;
//! 3. in `enforced` mode, joins a fresh `harness/session-<id>` cgroup with the
//!    session limit, swap 0 and `memory.oom.group` 1 (R12c);
//! 4. records the launch (harness session id, pid, start time, adapter launch,
//!    placement and limit) and an identity the kill path can verify;
//!
//! then execs the real harness with the same arguments. Every step fails open:
//! the harness always starts, and a tree that could not be placed under the
//! kernel limit is recorded as `watched` (R12a) so the gateway samples it.

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

    if let (Some(sid), Ok(dir)) = (session_id(args), std::env::var(DIR_ENV)) {
        let adapter_launch = std::env::var(ADAPTER_LAUNCH_ENV).unwrap_or_default();
        prepare(Path::new(&dir), &sid, &adapter_launch);
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
    pub oom_score_adj: Option<i64>,
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
            .unwrap_or("watched")
            .to_string(),
        fs: value.get("fs").and_then(|v| v.as_str()).map(str::to_string),
        harness: value
            .get("harness")
            .and_then(|v| v.as_str())
            .map(str::to_string),
        session_limit: value.get("sessionLimit").and_then(|v| v.as_u64()),
        oom_score_adj: value.get("oomScoreAdj").and_then(|v| v.as_i64()),
    })
}

fn prepare(dir: &Path, sid: &str, adapter_launch: &str) {
    let launch = launch_id(sid);
    let mut errors: Vec<String> = Vec::new();
    let config = match read_config(dir) {
        Ok(config) => config,
        Err(error) => {
            errors.push(error);
            LaunchConfig {
                mode: "watched".into(),
                ..LaunchConfig::default()
            }
        }
    };

    // `off` (an admin turned the guard off) and `count-only` launch the harness
    // untouched; only the resident cap, counted by the gateway, applies.
    if config.mode != "watched" && config.mode != "enforced" {
        return;
    }

    // R14: the session tree runs at the value inherited from the adapter (the
    // gateway's, 0 on Sirius) plus the host's raise (+100 by default), capped
    // at 1000. Raising one's own value needs no privilege.
    let raise = config.oom_score_adj.unwrap_or(100);
    let inherited = fs::read_to_string("/proc/self/oom_score_adj")
        .ok()
        .and_then(|text| text.trim().parse::<i64>().ok())
        .unwrap_or(0);
    let oom = (inherited + raise).min(1000);
    let oom_written = match fs::write("/proc/self/oom_score_adj", oom.to_string()) {
        Ok(()) => Some(oom),
        Err(error) => {
            errors.push(format!("oom_score_adj could not be raised: {error}"));
            None
        }
    };

    let sessions = dir.join("sessions");
    if let Err(error) = fs::create_dir_all(&sessions) {
        eprintln!("{STEP_NAME}: launch records directory could not be created: {error}");
        return;
    }
    let identity_path = sessions.join(format!("{launch}.identity"));
    let identity = OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o600)
        .open(&identity_path);
    let identity_error = match identity {
        Ok(mut file) => {
            crate::harness_process::prepare_session_identity(&identity_path, &mut file, &launch)
                .err()
                .map(|(step, error)| format!("{step}: {error}"))
        }
        Err(error) => Some(format!("identity could not be opened: {error}")),
    };
    if let Some(error) = identity_error {
        errors.push(error);
    }

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
    let mut record = BTreeMap::new();
    record.insert("v", serde_json::json!(1));
    record.insert("launchId", serde_json::json!(launch));
    record.insert("sessionId", serde_json::json!(sid));
    record.insert("pid", serde_json::json!(pid));
    record.insert("start", serde_json::json!(proc_start(pid)));
    record.insert("adapterLaunchId", serde_json::json!(adapter_launch));
    record.insert("placement", serde_json::json!(placement));
    record.insert("unit", serde_json::json!(unit));
    record.insert(
        "identity",
        serde_json::json!(identity_path.to_string_lossy()),
    );
    record.insert("sessionLimit", serde_json::json!(config.session_limit));
    record.insert("oomScoreAdj", serde_json::json!(oom_written));
    record.insert("errors", serde_json::json!(errors));
    record.insert("launchedAt", serde_json::json!(now_ms()));

    let body = serde_json::to_vec(&record).unwrap_or_default();
    if let Err(error) = atomic_write(&sessions.join(format!("{launch}.json")), &body) {
        eprintln!("{STEP_NAME}: launch record could not be written: {error}");
    }
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
    fs::create_dir(&dir).map_err(|error| format!("session unit {unit} could not be created: {error}"))?;
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
/// adapter where it is; the gateway checks membership and runs that tree
/// `watched` when it is not in its unit (R12a).
pub fn join_adapter_cgroup() {
    if let Ok(dir) = std::env::var("TIGHTBEAM_ADAPTER_CGROUP") {
        if !dir.is_empty() {
            let _ = fs::write(
                Path::new(&dir).join("cgroup.procs"),
                std::process::id().to_string(),
            );
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
            session_id(&args(&["--resume", "r-2", "--output-format", "stream-json"])),
            Some("r-2".into())
        );
        assert_eq!(
            session_id(&args(&["--resume=old", "--fork-session", "--session-id=new"])),
            Some("new".into())
        );
        assert_eq!(session_id(&args(&["auth", "status"])), None);
        assert_eq!(session_id(&args(&["--session-id=../etc"])), None);
    }

    #[test]
    fn invoked_as_step_matches_the_link_name_only() {
        assert!(invoked_as_step(Some("/x/run/memory-guard/bin/tightbeam-session-exec")));
        assert!(!invoked_as_step(Some("/usr/local/bin/tightbeam")));
        assert!(!invoked_as_step(None));
    }

    #[test]
    fn read_config_requires_version_one() {
        let dir = std::env::temp_dir().join(format!("tb-mg-config-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join("launch.json"), r#"{"v":2,"mode":"enforced"}"#).unwrap();
        assert!(read_config(&dir).is_err());
        fs::write(
            dir.join("launch.json"),
            r#"{"v":1,"mode":"enforced","fs":"/sys/fs/cgroup","harness":"/a/harness","sessionLimit":536870912,"oomScoreAdj":100}"#,
        )
        .unwrap();
        assert_eq!(
            read_config(&dir).unwrap(),
            LaunchConfig {
                mode: "enforced".into(),
                fs: Some("/sys/fs/cgroup".into()),
                harness: Some("/a/harness".into()),
                session_limit: Some(536870912),
                oom_score_adj: Some(100),
            }
        );
        fs::remove_dir_all(&dir).unwrap();
    }
}

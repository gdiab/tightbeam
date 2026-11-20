//! Memory limits v1.13 FS9: the root commands for a stuck episode.
//!
//! `tightbeam memory-guard-recover --base <dir> <episodeId>` and
//! `tightbeam memory-guard-override --base <dir> <episodeId>` run as root on the
//! gateway's host. They are not Tightbeam verbs: they never call the gateway.
//! Each writes one root-owned record under `<base>/run/memory-guard/root/`, which
//! the gateway accepts only through its atomic transition (B4) and judges itself.
//!
//! - Recovery (Step 1), `custody`: SIGKILL to every process of the named trees,
//!   by `cgroup.kill` on their units or by signals sent as root, then the time it
//!   did so is recorded. Only processes owned by the gateway's own user, and whose
//!   start time matches the recorded one, are signalled, and only units under the
//!   harness subtree, so a record the gateway's user could have edited cannot
//!   aim root at anything that user could not already end. `guard`: the record
//!   is written; root then restarts the service.
//! - Override (Step 2): only after a failed recovery. It checks the root path of
//!   the gateway's user, prints the plain statement (with the strict or residual
//!   sentence) before writing anything, and proceeds only when the episode id is
//!   typed in that run. A flag given in advance is not confirmation.

use std::collections::BTreeMap;
use std::fs;
use std::io::{BufRead, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

const GROUPS: [&str; 6] = ["docker", "lxd", "lxc", "libvirt", "disk", "kvm"];
const SOCKETS: [&str; 7] = [
    "/var/run/docker.sock",
    "/run/docker.sock",
    "/run/containerd/containerd.sock",
    "/var/snap/lxd/common/lxd/unix.socket",
    "/var/lib/lxd/unix.socket",
    "/run/libvirt/libvirt-sock",
    "/var/run/libvirt/libvirt-sock",
];

/// Whether `args` names one of the root commands.
pub fn is_root_command(args: &[String]) -> bool {
    matches!(
        args.first().map(String::as_str),
        Some("memory-guard-recover") | Some("memory-guard-override")
    )
}

/// Run a root command; returns the exit status.
pub fn run(args: &[String]) -> i32 {
    let result = match parse(args) {
        Ok(parsed) => {
            if !as_root() {
                Err("this command must run as root on the gateway's host".to_string())
            } else if parsed.action == "recovery" {
                recover(&parsed)
            } else {
                override_episode(&parsed, &mut std::io::stdin().lock())
            }
        }
        Err(error) => Err(error),
    };
    match result {
        Ok(()) => 0,
        Err(error) => {
            eprintln!("tightbeam: {error}");
            1
        }
    }
}

#[derive(Debug)]
struct Parsed {
    action: &'static str,
    base: PathBuf,
    episode: String,
}

fn parse(args: &[String]) -> Result<Parsed, String> {
    let action = match args.first().map(String::as_str) {
        Some("memory-guard-recover") => "recovery",
        Some("memory-guard-override") => "override",
        _ => return Err("unknown root command".into()),
    };
    let usage = format!("usage: tightbeam {} --base <dir> <episodeId>", args[0]);
    let mut base = None;
    let mut episode = None;
    let mut rest = args[1..].iter();
    while let Some(arg) = rest.next() {
        match arg.as_str() {
            "--base" => base = rest.next().cloned(),
            flag if flag.starts_with('-') => {
                return Err(format!("unknown flag {flag}; {usage}"));
            }
            value if episode.is_none() => episode = Some(value.to_string()),
            _ => return Err(usage),
        }
    }
    let (Some(base), Some(episode)) = (base, episode) else {
        return Err(usage);
    };
    let valid = episode.starts_with("ep_")
        && episode.len() <= 64
        && episode
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_');
    if !valid {
        return Err(format!("{episode} is not an episode id"));
    }
    Ok(Parsed {
        action,
        base: PathBuf::from(base),
        episode,
    })
}

fn as_root() -> bool {
    #[cfg(debug_assertions)]
    if std::env::var("TIGHTBEAM_TEST_ASSUME_ROOT").is_ok() {
        return true;
    }
    unsafe { libc::geteuid() == 0 }
}

fn guard_dir(base: &Path) -> PathBuf {
    base.join("run").join("memory-guard")
}

/// The episode the gateway published, owned by the gateway's own user and not
/// writable by others.
fn load_episode(parsed: &Parsed) -> Result<(serde_json::Value, u32), String> {
    let gateway_uid = fs::metadata(&parsed.base)
        .map_err(|error| format!("{} cannot be read: {error}", parsed.base.display()))?
        .uid();
    let path = guard_dir(&parsed.base)
        .join("episodes")
        .join(format!("{}.json", parsed.episode));
    let meta = fs::metadata(&path)
        .map_err(|error| format!("no active episode {} ({error})", parsed.episode))?;
    if meta.uid() != gateway_uid || meta.permissions().mode() & 0o022 != 0 {
        return Err(format!(
            "{} is not the gateway's own record; nothing was done",
            path.display()
        ));
    }
    let text = fs::read_to_string(&path).map_err(|error| error.to_string())?;
    let episode: serde_json::Value =
        serde_json::from_str(&text).map_err(|error| format!("episode is unreadable: {error}"))?;
    Ok((episode, gateway_uid))
}

fn recover(parsed: &Parsed) -> Result<(), String> {
    let (episode, gateway_uid) = load_episode(parsed)?;
    let kind = episode["kind"].as_str().unwrap_or("");
    let mut record = base_record(parsed, &episode);
    if kind == "custody" {
        let trees = episode["trees"].as_array().cloned().unwrap_or_default();
        for tree in &trees {
            kill_tree(tree, gateway_uid);
        }
        record.insert("killedAt", serde_json::json!(now_ms()));
        write_record(parsed, &record)?;
        println!(
            "Sent SIGKILL to the {} agent process tree(s) of episode {}. Tightbeam now checks: the \
             episode is cleared once every one is gone, or the recovery is recorded as failed if \
             any is still there 60 seconds from now.",
            trees.len(),
            parsed.episode
        );
    } else {
        write_record(parsed, &record)?;
        println!(
            "Recorded a recovery of episode {}. Now restart the Tightbeam service on this host as \
             root. Tightbeam records it as cleared when its memory guard answers, or as failed if \
             it has not 5 minutes after that start.",
            parsed.episode
        );
    }
    Ok(())
}

fn kill_tree(tree: &serde_json::Value, gateway_uid: u32) {
    if let Some(unit) = tree["unit"].as_str() {
        if unit.contains("/harness/session-") && !unit.contains("..") {
            let path = cgroup_fs()
                .join(unit.trim_start_matches('/'))
                .join("cgroup.kill");
            let _ = fs::write(path, "1");
        }
        return;
    }
    let (Some(pid), start) = (tree["pid"].as_i64(), tree["start"].as_u64()) else {
        return;
    };
    // The recorded leader, if it is still the same process, and every process
    // of its process group or session (the step `setsid`s), owned by the
    // gateway's user and started no earlier.
    for (member, member_start, uid, pgrp, sid) in processes() {
        let ours = uid == gateway_uid
            && (member == pid || pgrp == pid || sid == pid)
            && start.map_or(true, |start| member_start >= start)
            && (member != pid || Some(member_start) == start);
        if ours {
            unsafe {
                libc::kill(member as libc::pid_t, libc::SIGKILL);
            }
        }
    }
}

/// Every readable process: (pid, start, uid, pgrp, session).
fn processes() -> Vec<(i64, u64, u32, i64, i64)> {
    let Ok(entries) = fs::read_dir("/proc") else {
        return Vec::new();
    };
    entries
        .flatten()
        .filter_map(|entry| {
            let pid: i64 = entry.file_name().to_str()?.parse().ok()?;
            let uid = entry.metadata().ok()?.uid();
            let stat = fs::read_to_string(entry.path().join("stat")).ok()?;
            let rest = &stat[stat.rfind(')')? + 1..];
            let fields: Vec<&str> = rest.split_whitespace().collect();
            let pgrp = fields.get(2)?.parse().ok()?;
            let sid = fields.get(3)?.parse().ok()?;
            let start = fields.get(19)?.parse().ok()?;
            Some((pid, start, uid, pgrp, sid))
        })
        .collect()
}

fn cgroup_fs() -> PathBuf {
    #[cfg(debug_assertions)]
    if let Ok(path) = std::env::var("TIGHTBEAM_TEST_CGROUP_FS") {
        return PathBuf::from(path);
    }
    PathBuf::from("/sys/fs/cgroup")
}

fn override_episode(parsed: &Parsed, input: &mut dyn BufRead) -> Result<(), String> {
    let (episode, gateway_uid) = load_episode(parsed)?;
    if episode["recovery"]["outcome"].as_str() != Some("failed") {
        return Err(format!(
            "an override needs a failed recovery of episode {} first; nothing was written",
            parsed.episode
        ));
    }
    if !episode["override"].is_null() {
        return Err(format!(
            "an override of episode {} was already accepted; nothing was written",
            parsed.episode
        ));
    }

    let user = user_name(gateway_uid);
    let finding = finding(&user);
    let kind = finding_kind(&finding);
    let sentence = statement(&finding, kind);
    let operator = operator();
    let survivors = episode["recovery"]["survivors"]
        .as_array()
        .cloned()
        .unwrap_or_default();
    let held = if episode["kind"] == "guard" {
        "new agent launches".to_string()
    } else {
        format!(
            "the replacement of the {} adapter",
            episode["key"].as_str().unwrap_or("?")
        )
    };
    let risk = if episode["kind"] == "guard" {
        "Admitting the held launches means they run without the memory guard: no cap, floor or \
         per-agent limit is checked until it answers."
            .to_string()
    } else {
        format!(
            "{} agent processes could not be stopped, even by root. Launching a replacement means \
             they may keep using memory outside every limit until they end or the machine reboots.",
            survivors.len()
        )
    };

    let mut statement_text = format!(
        "Episode {} on {}: Tightbeam holds {} because {}.\n",
        parsed.episode,
        episode["host"].as_str().unwrap_or("?"),
        held,
        episode["why"].as_str().unwrap_or("?")
    );
    for tree in &survivors {
        statement_text.push_str(&format!(
            "  - launch record {}, process {} started at {}, unit {}, state {}\n",
            tree["launchId"].as_str().unwrap_or("unknown"),
            tree["pid"],
            tree["start"],
            tree["unit"].as_str().unwrap_or("none"),
            tree["state"].as_str().unwrap_or("unknown")
        ));
    }
    statement_text.push_str(&format!("Risk accepted: {risk}\n"));
    statement_text.push_str(&format!(
        "Recorded as: root, invoked by {} (uid {}).\n",
        operator["sudoUser"].as_str().unwrap_or("unknown"),
        operator["sudoUid"].as_str().unwrap_or("unknown")
    ));
    statement_text.push_str(&sentence);
    statement_text.push('\n');

    print!("{statement_text}");
    print!(
        "To accept this risk, type the episode id ({}) and press Enter: ",
        parsed.episode
    );
    let _ = std::io::stdout().flush();
    let mut typed = String::new();
    let _ = input.read_line(&mut typed);
    if typed.trim() != parsed.episode {
        return Err("not confirmed; nothing was written".into());
    }

    let mut record = base_record(parsed, &episode);
    record.insert("statementKind", serde_json::json!(kind));
    record.insert("statement", serde_json::json!(statement_text));
    record.insert("finding", finding);
    record.insert("trees", serde_json::json!(survivors));
    write_record(parsed, &record)?;
    println!(
        "Override recorded for episode {}. Tightbeam applies it once it accepts the record.",
        parsed.episode
    );
    Ok(())
}

fn base_record(
    parsed: &Parsed,
    episode: &serde_json::Value,
) -> BTreeMap<&'static str, serde_json::Value> {
    let mut record = BTreeMap::new();
    record.insert("v", serde_json::json!(1));
    record.insert("action", serde_json::json!(parsed.action));
    record.insert("episodeId", serde_json::json!(parsed.episode));
    record.insert("host", episode["host"].clone());
    record.insert("kind", episode["kind"].clone());
    record.insert("key", episode["key"].clone());
    record.insert("operator", operator());
    record.insert("at", serde_json::json!(now_ms()));
    record
}

/// `root`, plus the invoking login user and uid as `sudo` reports them, or
/// `unknown`: an account, not a person.
fn operator() -> serde_json::Value {
    let env = |name: &str| std::env::var(name).unwrap_or_else(|_| "unknown".into());
    serde_json::json!({"user": "root", "sudoUser": env("SUDO_USER"), "sudoUid": env("SUDO_UID")})
}

fn write_record(
    parsed: &Parsed,
    record: &BTreeMap<&'static str, serde_json::Value>,
) -> Result<(), String> {
    let dir = guard_dir(&parsed.base).join("root");
    fs::create_dir_all(&dir)
        .map_err(|error| format!("{} cannot be created: {error}", dir.display()))?;
    let _ = fs::set_permissions(&dir, fs::Permissions::from_mode(0o755));
    let name = format!("{}-{}-{}.json", parsed.action, parsed.episode, now_nanos());
    let path = dir.join(&name);
    let pending = dir.join(format!(".{name}.pending"));
    let body = serde_json::to_vec(record).map_err(|error| error.to_string())?;
    let mut file = fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o644)
        .open(&pending)
        .map_err(|error| format!("the record cannot be written: {error}"))?;
    file.write_all(&body)
        .and_then(|_| file.sync_all())
        .and_then(|_| fs::rename(&pending, &path))
        .map_err(|error| format!("the record cannot be written: {error}"))
}

fn user_name(uid: u32) -> String {
    Command::new("id")
        .args(["-nu", &uid.to_string()])
        .output()
        .ok()
        .filter(|output| output.status.success())
        .map(|output| String::from_utf8_lossy(&output.stdout).trim().to_string())
        .unwrap_or_else(|| uid.to_string())
}

/// FS9's root-path check for the gateway's user, each mechanism `absent`,
/// `present` or `unknown` (the same rules as the gateway's own check).
fn finding(user: &str) -> serde_json::Value {
    let groups = match Command::new("id").args(["-Gn", user]).output() {
        Ok(output) if output.status.success() => {
            let text = String::from_utf8_lossy(&output.stdout).to_string();
            let found: Vec<&str> = text
                .split_whitespace()
                .filter(|group| GROUPS.contains(group))
                .collect();
            if found.is_empty() {
                serde_json::json!({"result": "absent", "detail": []})
            } else {
                serde_json::json!({"result": "present", "detail": found})
            }
        }
        other => serde_json::json!({"result": "unknown", "detail": format!("{other:?}")}),
    };

    let sudo = match Command::new("sudo").args(["-n", "-l", "-U", user]).output() {
        Ok(output) => {
            let text = format!(
                "{}{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
            if text.contains("NOPASSWD") {
                serde_json::json!({"result": "present", "detail": "a passwordless sudo entry"})
            } else if output.status.success() || text.contains("is not allowed to run sudo") {
                serde_json::json!({"result": "absent", "detail": "no passwordless sudo entry"})
            } else {
                serde_json::json!({"result": "unknown", "detail": text.trim()})
            }
        }
        Err(error) => serde_json::json!({"result": "unknown", "detail": error.to_string()}),
    };

    let mut present = Vec::new();
    let mut unknown = Vec::new();
    for path in SOCKETS {
        if !Path::new(path).exists() {
            continue;
        }
        match Command::new("sudo")
            .args(["-n", "-u", user, "test", "-w", path])
            .status()
            .map(|status| status.code())
        {
            Ok(Some(0)) => present.push(path),
            Ok(Some(1)) => {}
            _ => unknown.push(path),
        }
    }
    let sockets = if !present.is_empty() {
        serde_json::json!({"result": "present", "detail": present})
    } else if !unknown.is_empty() {
        serde_json::json!({"result": "unknown", "detail": unknown})
    } else {
        serde_json::json!({"result": "absent", "detail": []})
    };

    serde_json::json!({"groups": groups, "sudo": sudo, "sockets": sockets})
}

fn finding_kind(finding: &serde_json::Value) -> &'static str {
    let all_absent = ["groups", "sudo", "sockets"]
        .iter()
        .all(|name| finding[*name]["result"] == "absent");
    if all_absent { "strict" } else { "residual" }
}

fn statement(finding: &serde_json::Value, kind: &str) -> String {
    if kind == "strict" {
        return "No agent-reachable root path was found among those checked (container, hypervisor \
                and raw-device groups; passwordless sudo; container and hypervisor sockets). Paths \
                that were not checked cannot be ruled out."
            .into();
    }
    let paths: Vec<String> = ["groups", "sockets", "sudo"]
        .iter()
        .filter_map(|name| {
            let mechanism = &finding[*name];
            match mechanism["result"].as_str() {
                Some("present") => Some(format!("{name} ({})", detail(&mechanism["detail"]))),
                Some("absent") => None,
                _ => Some(format!("a path that could not be checked ({name})")),
            }
        })
        .collect();
    format!(
        "This machine's agents run as a user that can gain root, here through {}. So a process \
         with that access, including an agent breaking its rules, could also run this override.",
        paths.join("; ")
    )
}

fn detail(value: &serde_json::Value) -> String {
    match value {
        serde_json::Value::Array(items) => items
            .iter()
            .filter_map(|item| item.as_str())
            .collect::<Vec<_>>()
            .join(", "),
        serde_json::Value::String(text) => text.clone(),
        other => other.to_string(),
    }
}

fn now_ms() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0)
}

fn now_nanos() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(list: &[&str]) -> Vec<String> {
        list.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn n6_absent_a_flag_given_in_advance_is_not_confirmation() {
        assert!(
            parse(&args(&[
                "memory-guard-override",
                "--base",
                "/x",
                "--yes",
                "ep_1"
            ]))
            .unwrap_err()
            .contains("unknown flag --yes")
        );
        assert!(parse(&args(&["memory-guard-override", "--base", "/x", "../ep"])).is_err());
        assert!(parse(&args(&["memory-guard-recover", "ep_ab12"])).is_err());
        assert!(parse(&args(&["memory-guard-recover", "--base", "/x", "ep_ab12"])).is_ok());
    }

    #[test]
    fn n5_the_finding_chooses_strict_only_when_every_mechanism_is_absent() {
        let absent = serde_json::json!({"result": "absent", "detail": []});
        let strict = serde_json::json!({"groups": absent, "sudo": absent, "sockets": absent});
        assert_eq!(finding_kind(&strict), "strict");
        let mut residual = strict.clone();
        residual["sudo"] = serde_json::json!({"result": "unknown", "detail": "no tty"});
        assert_eq!(finding_kind(&residual), "residual");
        assert!(
            statement(&residual, "residual").contains("a path that could not be checked (sudo)")
        );
    }
}

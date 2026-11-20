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
    archive_judged(&parsed.base, gateway_uid);
    let kind = episode["kind"].as_str().unwrap_or("");
    let mut record = base_record(parsed, &episode);
    if kind == "custody" {
        let Some(trees) = episode["trees"]
            .as_array()
            .filter(|trees| !trees.is_empty())
        else {
            return Err(format!(
                "episode {} names no process tree Tightbeam could list, so there is nothing to \
                 kill; nothing was recorded",
                parsed.episode
            ));
        };
        // Every named tree is killed, or nothing is recorded: a kill time is
        // the time root sent SIGKILL to all of them (FS9 Step 1).
        let mut signalled = 0;
        let mut units = 0;
        let mut empty = 0;
        let mut failures = Vec::new();
        for tree in trees {
            match kill_tree(tree, gateway_uid) {
                Ok(Killed::Unit) => units += 1,
                Ok(Killed::Signalled(count)) => signalled += count,
                Ok(Killed::NoneLeft) => empty += 1,
                Err(error) => failures.push(format!(
                    "launch record {}: {error}",
                    tree["launchId"].as_str().unwrap_or("unknown")
                )),
            }
        }
        if !failures.is_empty() {
            return Err(format!(
                "SIGKILL could not be sent to every named tree ({}); nothing was recorded, so \
                 Tightbeam does not judge this recovery. Run the command again.",
                failures.join("; ")
            ));
        }
        record.insert("killedAt", serde_json::json!(now_ms()));
        write_record(parsed, &record)?;
        println!(
            "Sent SIGKILL to the {} named agent process tree(s) of episode {}: {units} through \
             their cgroup, {signalled} process(es) by signal, {empty} with no process left. \
             Tightbeam now checks: the episode is cleared once every one is gone, or the \
             recovery is recorded as failed if any is still there 60 seconds from now.",
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

/// What a tree's kill did.
#[derive(Debug, PartialEq)]
enum Killed {
    /// `cgroup.kill` on its unit was written: the kernel kills every member.
    Unit,
    /// This many of its processes were sent SIGKILL.
    Signalled(usize),
    /// No process of the tree is left to signal.
    NoneLeft,
}

/// SIGKILL to one named tree: by `cgroup.kill` on its unit, or, when that
/// cannot be written, by signals to the recorded leader (if it is still the
/// same process) and every process of its process group or session (the
/// step `setsid`s), owned by the gateway's user and started no earlier. An
/// error means no kill could be sent.
fn kill_tree(tree: &serde_json::Value, gateway_uid: u32) -> Result<Killed, String> {
    let mut unit_error = None;
    if let Some(unit) = tree["unit"].as_str() {
        if unit.contains("/harness/session-") && !unit.contains("..") {
            let path = cgroup_fs()
                .join(unit.trim_start_matches('/'))
                .join("cgroup.kill");
            match fs::OpenOptions::new()
                .write(true)
                .open(&path)
                .and_then(|mut file| file.write_all(b"1"))
            {
                Ok(()) => return Ok(Killed::Unit),
                Err(error) => unit_error = Some(format!("cgroup.kill of {unit}: {error}")),
            }
        } else {
            unit_error = Some(format!("{unit} is not a session unit"));
        }
    }
    let (Some(pid), start) = (tree["pid"].as_i64(), tree["start"].as_u64()) else {
        return Err(unit_error.unwrap_or_else(|| "no recorded process to signal".into()));
    };
    let processes = processes().map_err(|error| match &unit_error {
        Some(unit) => format!("{unit}; and the process table cannot be read: {error}"),
        None => format!("the process table cannot be read: {error}"),
    })?;
    let mut sent = 0;
    let mut failures = Vec::new();
    for (member, member_start, uid, pgrp, sid) in processes {
        let ours = uid == gateway_uid
            && (member == pid || pgrp == pid || sid == pid)
            && start.map_or(true, |start| member_start >= start)
            && (member != pid || Some(member_start) == start);
        if ours {
            if unsafe { libc::kill(member as libc::pid_t, libc::SIGKILL) } == 0 {
                sent += 1;
            } else {
                let error = std::io::Error::last_os_error();
                // A process that ended since the table was read needs no kill.
                if error.raw_os_error() != Some(libc::ESRCH) {
                    failures.push(format!("process {member}: {error}"));
                }
            }
        }
    }
    match (sent, failures.is_empty()) {
        (0, true) => Ok(Killed::NoneLeft),
        (sent, true) => Ok(Killed::Signalled(sent)),
        (_, false) => Err(failures.join("; ")),
    }
}

/// Every process: (pid, start, uid, pgrp, session). A process that ends
/// while it is read is not listed; an entry that cannot be read or parsed for
/// any other reason, or a table that cannot be read, is an error, never a
/// smaller table.
fn processes() -> Result<Vec<(i64, u64, u32, i64, i64)>, String> {
    let gone = |error: &std::io::Error| {
        error.kind() == std::io::ErrorKind::NotFound || error.raw_os_error() == Some(libc::ESRCH)
    };
    let mut table = Vec::new();
    for entry in fs::read_dir(proc_fs()).map_err(|error| error.to_string())? {
        let entry = entry.map_err(|error| error.to_string())?;
        let Some(pid) = entry
            .file_name()
            .to_str()
            .and_then(|name| name.parse::<i64>().ok())
        else {
            continue;
        };
        let read = entry.metadata().and_then(|meta| {
            fs::read_to_string(entry.path().join("stat")).map(|stat| (meta, stat))
        });
        let (meta, stat) = match read {
            Ok(read) => read,
            Err(error) if gone(&error) => continue,
            Err(error) => return Err(format!("process {pid} cannot be read: {error}")),
        };
        let parsed = stat.rfind(')').and_then(|close| {
            let fields: Vec<&str> = stat[close + 1..].split_whitespace().collect();
            Some((
                fields.get(19)?.parse().ok()?,
                fields.get(2)?.parse().ok()?,
                fields.get(3)?.parse().ok()?,
            ))
        });
        let Some((start, pgrp, sid)) = parsed else {
            return Err(format!("process {pid}'s stat cannot be parsed"));
        };
        table.push((pid, start, meta.uid(), pgrp, sid));
    }
    Ok(table)
}

fn proc_fs() -> PathBuf {
    #[cfg(debug_assertions)]
    if let Ok(path) = std::env::var("TIGHTBEAM_TEST_PROC") {
        return PathBuf::from(path);
    }
    PathBuf::from("/proc")
}

/// Move the records the gateway has judged (it lists them in
/// `root-judged.json`, its own file) to `root/judged/`, so the directory it
/// reads holds only what is new. Only this user's own regular files are
/// moved; what cannot be moved stays and is said so.
fn archive_judged(base: &Path, gateway_uid: u32) {
    let list = guard_dir(base).join("root-judged.json");
    let Ok(meta) = fs::metadata(&list) else {
        return;
    };
    if meta.uid() != gateway_uid || meta.permissions().mode() & 0o022 != 0 {
        eprintln!(
            "tightbeam: {} is not the gateway's own record; no record was moved",
            list.display()
        );
        return;
    }
    let names: Vec<String> = fs::read_to_string(&list)
        .ok()
        .and_then(|text| serde_json::from_str::<serde_json::Value>(&text).ok())
        .and_then(|value| value["judged"].as_array().cloned())
        .unwrap_or_default()
        .iter()
        .filter_map(|name| name.as_str().map(str::to_string))
        .collect();
    let dir = guard_dir(base).join("root");
    let judged = dir.join("judged");
    let me = unsafe { libc::geteuid() };
    for name in names {
        if name.contains('/') || name.starts_with('.') || !name.ends_with(".json") {
            continue;
        }
        let path = dir.join(&name);
        let ours = fs::symlink_metadata(&path)
            .is_ok_and(|meta| meta.file_type().is_file() && meta.uid() == me);
        if !ours {
            continue;
        }
        let moved = fs::create_dir_all(&judged)
            .and_then(|_| fs::set_permissions(&judged, fs::Permissions::from_mode(0o755)))
            .and_then(|_| fs::rename(&path, judged.join(&name)));
        if let Err(error) = moved {
            eprintln!("tightbeam: judged record {name} could not be moved aside: {error}");
        }
    }
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
    archive_judged(&parsed.base, gateway_uid);
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
    let statement_text =
        override_statement(&parsed.episode, &episode, &survivors, &operator, &sentence);

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

/// The statement the override prints before it acts, and records exactly as
/// printed (FS9 Step 2). The gateway rebuilds the same text from its own
/// state and refuses a record whose statement differs.
fn override_statement(
    episode_id: &str,
    episode: &serde_json::Value,
    survivors: &[serde_json::Value],
    operator: &serde_json::Value,
    sentence: &str,
) -> String {
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

    let mut text = format!(
        "Episode {} on {}: Tightbeam holds {} because {}.\n",
        episode_id,
        episode["host"].as_str().unwrap_or("?"),
        held,
        episode["why"].as_str().unwrap_or("?")
    );
    for tree in survivors {
        text.push_str(&format!(
            "  - launch record {}, process {} started at {}, unit {}, state {}\n",
            tree["launchId"].as_str().unwrap_or("unknown"),
            tree["pid"],
            tree["start"],
            tree["unit"].as_str().unwrap_or("none"),
            tree["state"].as_str().unwrap_or("unknown")
        ));
    }
    text.push_str(&format!("Risk accepted: {risk}\n"));
    text.push_str(&format!(
        "Recorded as: root, invoked by {} (uid {}).\n",
        operator["sudoUser"].as_str().unwrap_or("unknown"),
        operator["sudoUid"].as_str().unwrap_or("unknown")
    ));
    text.push_str(sentence);
    text.push('\n');
    text
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
    fn n5_golden_the_printed_statement_is_the_one_the_gateway_rebuilds() {
        // The same fixture and text as the gateway's "N5 golden" test.
        let episode = serde_json::json!({
            "episodeId": "ep_golden", "host": "sirius", "kind": "custody",
            "key": "claude:shared@sirius",
            "why": "1 agent processes could not be confirmed stopped"
        });
        let survivors = vec![serde_json::json!({
            "launchId": "sl-9", "pid": 4242, "start": 7,
            "unit": "/tightbeam.slice/harness/session-sl-9", "state": "D"
        })];
        let operator = serde_json::json!({"user": "root", "sudoUser": "george", "sudoUid": "1000"});
        let finding = serde_json::json!({
            "groups": {"result": "present", "detail": ["docker", "lxd"]},
            "sudo": {"result": "unknown", "detail": "no tty"},
            "sockets": {"result": "absent", "detail": []}
        });
        let sentence = statement(&finding, finding_kind(&finding));
        assert_eq!(
            override_statement("ep_golden", &episode, &survivors, &operator, &sentence),
            "Episode ep_golden on sirius: Tightbeam holds the replacement of the \
             claude:shared@sirius adapter because 1 agent processes could not be \
             confirmed stopped.\n  - launch record sl-9, process 4242 started at 7, unit \
             /tightbeam.slice/harness/session-sl-9, state D\nRisk accepted: 1 agent processes \
             could not be stopped, even by root. Launching a replacement means they may keep \
             using memory outside every limit until they end or the machine reboots.\n\
             Recorded as: root, invoked by george (uid 1000).\nThis machine's agents run as \
             a user that can gain root, here through groups (docker, lxd); a path that could \
             not be checked (sudo). So a process with that access, including an agent breaking \
             its rules, could also run this override.\n"
        );
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

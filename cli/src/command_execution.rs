use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::ffi::{CString, OsString};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

static RECEIPT_TEMP_NONCE: AtomicU64 = AtomicU64::new(0);

struct Manifest {
    execution_id: String,
    command: Vec<String>,
    cwd: PathBuf,
    claim_path: PathBuf,
    launcher_path: PathBuf,
    started_path: PathBuf,
    stdout_path: PathBuf,
    stderr_path: PathBuf,
    not_started_path: PathBuf,
    terminal_path: PathBuf,
}

pub fn run(args: &[String]) -> Result<i32, String> {
    if args.len() != 1 {
        return Err("usage: tightbeam command-exec <prepared-receipt-path>".into());
    }

    let manifest = read_manifest(Path::new(&args[0]))?;
    create_once(
        &manifest.claim_path,
        b"claimed\n",
        "execution already consumed",
    )?;

    let (read_ack, write_ack) = match pipe(false) {
        Ok(ends) => ends,
        Err(error) => {
            write_not_started(&manifest, &error)?;
            println!(
                "{}",
                json!({"executionId": manifest.execution_id, "state": "not_started"})
            );
            return Ok(10);
        }
    };
    crate::child_process::reset_sigchld_before_spawn();
    match unsafe { libc::fork() } {
        -1 => {
            let error = format!(
                "command supervisor could not fork: {}",
                std::io::Error::last_os_error()
            );
            write_not_started(&manifest, &error)?;
            println!(
                "{}",
                json!({"executionId": manifest.execution_id, "state": "not_started"})
            );
            Ok(10)
        }
        0 => {
            drop(read_ack);
            let result = supervise(&manifest, write_ack);
            if result.is_err() {
                unsafe { libc::_exit(1) };
            }
            unsafe { libc::_exit(0) };
        }
        _child => {
            drop(write_ack);
            let mut ack = String::new();
            File::from(read_ack)
                .read_to_string(&mut ack)
                .map_err(|error| format!("command supervisor acknowledgement failed: {error}"))?;
            match ack.trim() {
                "started" => {
                    println!(
                        "{}",
                        json!({"executionId": manifest.execution_id, "state": "started"})
                    );
                    Ok(0)
                }
                "not_started" => {
                    println!(
                        "{}",
                        json!({"executionId": manifest.execution_id, "state": "not_started"})
                    );
                    Ok(10)
                }
                value => Err(format!(
                    "command supervisor closed without a durable start verdict: {value}"
                )),
            }
        }
    }
}

fn supervise(manifest: &Manifest, mut acknowledgement: OwnedFd) -> Result<(), String> {
    if unsafe { libc::setsid() } == -1 {
        let error = format!(
            "command supervisor could not detach: {}",
            std::io::Error::last_os_error()
        );
        return prelaunch_refusal(manifest, &mut acknowledgement, &error);
    }

    let pid = unsafe { libc::getpid() };
    let pgid = unsafe { libc::getpgrp() };
    if let Err(error) = write_json_once(
        &manifest.launcher_path,
        &json!({
            "executionId": manifest.execution_id,
            "osPid": pid,
            "processGroupId": pgid,
            "recordedAt": now_ms()
        }),
    ) {
        return prelaunch_refusal(manifest, &mut acknowledgement, &error);
    }

    let stdout = match output_file(&manifest.stdout_path) {
        Ok(file) => file,
        Err(error) => return prelaunch_refusal(manifest, &mut acknowledgement, &error),
    };
    let stderr = match output_file(&manifest.stderr_path) {
        Ok(file) => file,
        Err(error) => return prelaunch_refusal(manifest, &mut acknowledgement, &error),
    };
    let (exec_read, exec_write) = match pipe(true) {
        Ok(ends) => ends,
        Err(error) => return prelaunch_refusal(manifest, &mut acknowledgement, &error),
    };

    match unsafe { libc::fork() } {
        -1 => {
            let error = format!(
                "command process could not fork: {}",
                std::io::Error::last_os_error()
            );
            prelaunch_refusal(manifest, &mut acknowledgement, &error)
        }
        0 => {
            drop(exec_read);
            drop(acknowledgement);
            exec_child(manifest, stdout, stderr, exec_write)
        }
        child => {
            drop(exec_write);
            drop(stdout);
            drop(stderr);
            let mut exec_error = String::new();
            File::from(exec_read)
                .read_to_string(&mut exec_error)
                .map_err(|error| format!("exec status could not be read: {error}"))?;

            if !exec_error.is_empty() {
                write_not_started(manifest, exec_error.trim())?;
                acknowledge_best_effort(&mut acknowledgement, "not_started");
                wait_child(child)?;
                return Ok(());
            }

            write_json_once(
                &manifest.started_path,
                &json!({
                    "executionId": manifest.execution_id,
                    "osPid": child,
                    "startedAt": now_ms()
                }),
            )?;
            acknowledge_best_effort(&mut acknowledgement, "started");
            drop(acknowledgement);

            let status = wait_child(child)?;
            let (stdout_bytes, stdout_sha256) = file_evidence(&manifest.stdout_path)?;
            let (stderr_bytes, stderr_sha256) = file_evidence(&manifest.stderr_path)?;
            let (exit_code, signal) = decode_status(status);

            write_json_once(
                &manifest.terminal_path,
                &json!({
                    "executionId": manifest.execution_id,
                    "finishedAt": now_ms(),
                    "exitCode": exit_code,
                    "signal": signal,
                    "stdoutBytes": stdout_bytes,
                    "stdoutSha256": stdout_sha256,
                    "stderrBytes": stderr_bytes,
                    "stderrSha256": stderr_sha256
                }),
            )
        }
    }
}

fn prelaunch_refusal(
    manifest: &Manifest,
    acknowledgement: &mut OwnedFd,
    error: &str,
) -> Result<(), String> {
    write_not_started(manifest, error)?;
    acknowledge_best_effort(acknowledgement, "not_started");
    Ok(())
}

fn exec_child(manifest: &Manifest, stdout: File, stderr: File, exec_write: OwnedFd) -> ! {
    let failure = (|| -> Result<(), String> {
        std::env::set_current_dir(&manifest.cwd)
            .map_err(|error| format!("cwd could not be entered: {error}"))?;

        let stdin = File::open("/dev/null")
            .map_err(|error| format!("detached stdin could not be opened: {error}"))?;

        if unsafe { libc::signal(libc::SIGPIPE, libc::SIG_DFL) } == libc::SIG_ERR {
            return Err(format!(
                "SIGPIPE disposition could not be restored: {}",
                std::io::Error::last_os_error()
            ));
        }

        if unsafe { libc::dup2(stdin.as_raw_fd(), libc::STDIN_FILENO) } == -1
            || unsafe { libc::dup2(stdout.as_raw_fd(), libc::STDOUT_FILENO) } == -1
            || unsafe { libc::dup2(stderr.as_raw_fd(), libc::STDERR_FILENO) } == -1
        {
            return Err(format!(
                "detached command streams could not be attached: {}",
                std::io::Error::last_os_error()
            ));
        }

        let command = manifest
            .command
            .iter()
            .map(|part| {
                CString::new(part.as_bytes()).map_err(|_| "command contains NUL".to_string())
            })
            .collect::<Result<Vec<_>, _>>()?;
        let mut argv = command.iter().map(|part| part.as_ptr()).collect::<Vec<_>>();
        argv.push(std::ptr::null());

        unsafe { libc::execvp(command[0].as_ptr(), argv.as_ptr()) };
        Err(format!("exec failed: {}", std::io::Error::last_os_error()))
    })()
    .unwrap_err();

    let _ = File::from(exec_write).write_all(failure.as_bytes());
    unsafe { libc::_exit(127) }
}

fn read_manifest(path: &Path) -> Result<Manifest, String> {
    let bytes = fs::read_to_string(path)
        .map_err(|error| format!("prepared execution receipt could not be read: {error}"))?;
    let value: Value = serde_json::from_str(&bytes)
        .map_err(|error| format!("prepared execution receipt is invalid JSON: {error}"))?;
    let field = |name: &str| {
        value[name]
            .as_str()
            .filter(|value| !value.is_empty())
            .map(str::to_owned)
            .ok_or_else(|| format!("prepared execution receipt lacks {name}"))
    };
    let command = value["command"]
        .as_array()
        .ok_or_else(|| "prepared execution receipt lacks command".to_string())?
        .iter()
        .map(|part| {
            part.as_str()
                .map(str::to_owned)
                .ok_or_else(|| "prepared command contains a non-string value".to_string())
        })
        .collect::<Result<Vec<_>, _>>()?;
    if command.first().is_none_or(|part| part.is_empty()) {
        return Err("prepared command is empty".into());
    }

    let command_json = field("commandJson")?;
    let command_sha256 = field("commandSha256")?;
    if hex_sha256(command_json.as_bytes()) != command_sha256 {
        return Err("prepared command hash does not match its exact bytes".into());
    }
    let decoded: Vec<String> = serde_json::from_str(&command_json)
        .map_err(|error| format!("exact command bytes are invalid: {error}"))?;
    if decoded != command {
        return Err("prepared command differs from its exact command bytes".into());
    }

    let pinned_host = field("host")?;
    let actual_host = current_host()?;
    if pinned_host != actual_host {
        return Err(format!(
            "prepared execution is pinned to host {pinned_host}, not {actual_host}"
        ));
    }

    Ok(Manifest {
        execution_id: field("executionId")?,
        command,
        cwd: PathBuf::from(field("cwd")?),
        claim_path: PathBuf::from(field("claimPath")?),
        launcher_path: PathBuf::from(field("launcherIdentityPath")?),
        started_path: PathBuf::from(field("startedPath")?),
        stdout_path: PathBuf::from(field("stdoutPath")?),
        stderr_path: PathBuf::from(field("stderrPath")?),
        not_started_path: PathBuf::from(field("notStartedPath")?),
        terminal_path: PathBuf::from(field("terminalPath")?),
    })
}

fn pipe(close_on_exec: bool) -> Result<(OwnedFd, OwnedFd), String> {
    let mut ends = [0; 2];
    if unsafe { libc::pipe(ends.as_mut_ptr()) } == -1 {
        return Err(format!(
            "pipe could not be created: {}",
            std::io::Error::last_os_error()
        ));
    }
    let read = unsafe { OwnedFd::from_raw_fd(ends[0]) };
    let write = unsafe { OwnedFd::from_raw_fd(ends[1]) };
    if close_on_exec {
        set_fd_cloexec(read.as_raw_fd())?;
        set_fd_cloexec(write.as_raw_fd())?;
    }
    Ok((read, write))
}

fn set_fd_cloexec(fd: libc::c_int) -> Result<(), String> {
    if unsafe { libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC) } == -1 {
        Err(format!(
            "close-on-exec could not be set: {}",
            std::io::Error::last_os_error()
        ))
    } else {
        Ok(())
    }
}

fn output_file(path: &Path) -> Result<File, String> {
    ensure_parent(path)?;
    OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o600)
        .open(path)
        .map_err(|error| {
            format!(
                "execution output could not be opened at {}: {error}",
                path.display()
            )
        })
}

fn create_once(path: &Path, bytes: &[u8], already_exists: &str) -> Result<(), String> {
    ensure_parent(path)?;
    let mut file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o600)
        .open(path)
        .map_err(|error| {
            if error.kind() == std::io::ErrorKind::AlreadyExists {
                already_exists.to_string()
            } else {
                format!("receipt could not be opened at {}: {error}", path.display())
            }
        })?;
    file.write_all(bytes)
        .and_then(|_| file.sync_all())
        .map_err(|error| {
            format!(
                "receipt could not be written at {}: {error}",
                path.display()
            )
        })?;
    sync_parent(path)
}

fn write_json_once(path: &Path, value: &Value) -> Result<(), String> {
    write_json_once_with_hook(path, value, |_| Ok(()))
}

fn write_json_once_with_hook<F>(path: &Path, value: &Value, before_publish: F) -> Result<(), String>
where
    F: FnOnce(&Path) -> Result<(), String>,
{
    let mut bytes = serde_json::to_vec(value).map_err(|error| error.to_string())?;
    bytes.push(b'\n');
    ensure_parent(path)?;
    let (temp_path, mut file) = open_receipt_temp(path)?;
    let write_result = file
        .write_all(&bytes)
        .and_then(|_| file.sync_all())
        .map_err(|error| {
            format!(
                "receipt temp file could not be written at {}: {error}",
                temp_path.display()
            )
        });
    drop(file);

    let result = write_result.and_then(|()| {
        before_publish(&temp_path)?;
        fs::hard_link(&temp_path, path).map_err(|error| {
            if error.kind() == std::io::ErrorKind::AlreadyExists {
                "execution receipt already exists".to_string()
            } else {
                format!(
                    "receipt could not be published at {}: {error}",
                    path.display()
                )
            }
        })?;
        sync_parent(path)?;
        fs::remove_file(&temp_path).map_err(|error| {
            format!(
                "receipt temp file could not be removed at {}: {error}",
                temp_path.display()
            )
        })?;
        sync_parent(path)
    });

    if result.is_err() {
        let _ = fs::remove_file(&temp_path);
    }
    result
}

fn open_receipt_temp(path: &Path) -> Result<(PathBuf, File), String> {
    let parent = path
        .parent()
        .ok_or_else(|| "receipt path has no parent".to_string())?;
    let file_name = path
        .file_name()
        .ok_or_else(|| "receipt path has no file name".to_string())?;

    loop {
        let mut temp_name = OsString::from(".");
        temp_name.push(file_name);
        temp_name.push(format!(
            ".tmp-{}-{}",
            std::process::id(),
            RECEIPT_TEMP_NONCE.fetch_add(1, Ordering::Relaxed)
        ));
        let temp_path = parent.join(temp_name);
        match OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(0o600)
            .open(&temp_path)
        {
            Ok(file) => return Ok((temp_path, file)),
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(error) => {
                return Err(format!(
                    "receipt temp file could not be opened in {}: {error}",
                    parent.display()
                ));
            }
        }
    }
}

fn write_not_started(manifest: &Manifest, error: &str) -> Result<(), String> {
    write_json_once(
        &manifest.not_started_path,
        &json!({
            "executionId": manifest.execution_id,
            "recordedAt": now_ms(),
            "error": error
        }),
    )
}

fn acknowledge(fd: &mut OwnedFd, value: &str) -> Result<(), String> {
    File::from(fd.try_clone().map_err(|error| error.to_string())?)
        .write_all(format!("{value}\n").as_bytes())
        .map_err(|error| format!("command verdict could not be acknowledged: {error}"))
}

fn acknowledge_best_effort(fd: &mut OwnedFd, value: &str) {
    if let Err(error) = acknowledge(fd, value) {
        let _ = writeln!(std::io::stderr(), "{error}");
    }
}

fn current_host() -> Result<String, String> {
    if let Ok(host) = std::env::var("TIGHTBEAM_LOCAL_HOST_NAME")
        && !host.is_empty()
    {
        return Ok(host);
    }

    let mut bytes = [0_u8; 256];
    if unsafe { libc::gethostname(bytes.as_mut_ptr().cast(), bytes.len()) } == -1 {
        return Err(format!(
            "local hostname could not be read: {}",
            std::io::Error::last_os_error()
        ));
    }
    let length = bytes
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(bytes.len());
    String::from_utf8(bytes[..length].to_vec())
        .map_err(|_| "local hostname is not valid UTF-8".to_string())
}

fn wait_child(child: libc::pid_t) -> Result<libc::c_int, String> {
    let mut status = 0;
    loop {
        let waited = unsafe { libc::waitpid(child, &mut status, 0) };
        if waited == child {
            return Ok(status);
        }
        let error = std::io::Error::last_os_error();
        if error.kind() != std::io::ErrorKind::Interrupted {
            return Err(format!("command process could not be waited: {error}"));
        }
    }
}

fn decode_status(status: libc::c_int) -> (Option<i32>, Option<i32>) {
    if libc::WIFEXITED(status) {
        (Some(libc::WEXITSTATUS(status)), None)
    } else if libc::WIFSIGNALED(status) {
        (None, Some(libc::WTERMSIG(status)))
    } else {
        (None, None)
    }
}

fn file_evidence(path: &Path) -> Result<(u64, String), String> {
    let mut file = File::open(path).map_err(|error| {
        format!(
            "execution output could not be opened at {}: {error}",
            path.display()
        )
    })?;
    file.sync_all().map_err(|error| {
        format!(
            "execution output could not be synced at {}: {error}",
            path.display()
        )
    })?;
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes).map_err(|error| {
        format!(
            "execution output could not be read at {}: {error}",
            path.display()
        )
    })?;
    Ok((bytes.len() as u64, hex_sha256(&bytes)))
}

fn hex_sha256(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn ensure_parent(path: &Path) -> Result<(), String> {
    let parent = path
        .parent()
        .ok_or_else(|| "receipt path has no parent".to_string())?;
    fs::create_dir_all(parent)
        .map_err(|error| format!("receipt directory could not be created: {error}"))
}

fn sync_parent(path: &Path) -> Result<(), String> {
    let parent = path
        .parent()
        .ok_or_else(|| "receipt path has no parent".to_string())?;
    File::open(parent)
        .and_then(|directory| directory.sync_all())
        .map_err(|error| format!("receipt directory could not be synced: {error}"))
}

fn now_ms() -> u128 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
}

#[cfg(test)]
mod tests {
    use super::{
        Manifest, current_host, decode_status, hex_sha256, pipe, run, supervise, wait_child,
        write_json_once_with_hook,
    };
    use serde_json::{Value, json};
    use std::fs;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::mpsc;
    use std::thread;
    use std::time::Duration;

    fn publication_test_root(name: &str) -> PathBuf {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let root = std::env::temp_dir().join(format!(
            "tightbeam-command-exec-publication-{name}-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir_all(&root).unwrap();
        root
    }

    #[test]
    fn hashes_exact_bytes() {
        assert_eq!(
            hex_sha256(b"out\n"),
            "54034ac5c6e9ea95734ec2b729fd6d62abf64af34a9f9ce5d466cb788191a73d"
        );
    }

    #[test]
    fn decodes_exit_and_signal_statuses() {
        assert_eq!(decode_status(7 << 8), (Some(7), None));
        assert_eq!(decode_status(libc::SIGTERM), (None, Some(libc::SIGTERM)));
    }

    #[test]
    fn json_receipt_is_not_visible_until_complete_and_flushed() {
        let root = publication_test_root("held-writer");
        let path = root.join("terminal.json");
        let value = json!({"executionId": "held-writer", "exitCode": 0});
        let expected = value.clone();
        let writer_path = path.clone();
        let (held_tx, held_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();

        let writer = thread::spawn(move || {
            write_json_once_with_hook(&writer_path, &value, |held_path| {
                held_tx.send(held_path.to_path_buf()).unwrap();
                release_rx.recv().unwrap();
                Ok(())
            })
        });

        let held_path = held_rx.recv().unwrap();
        let final_while_held = fs::read(&path);
        let staged_while_held = fs::read(&held_path);
        release_tx.send(()).unwrap();
        assert_eq!(writer.join().unwrap(), Ok(()));

        assert_ne!(held_path, path);
        assert_eq!(
            final_while_held.unwrap_err().kind(),
            std::io::ErrorKind::NotFound
        );
        let staged: Value = serde_json::from_slice(&staged_while_held.unwrap()).unwrap();
        assert_eq!(staged, expected);
        let published: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        assert_eq!(published, expected);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn json_receipt_publication_refuses_to_clobber() {
        let root = publication_test_root("no-clobber");
        let path = root.join("terminal.json");
        let original = b"{\"executionId\":\"first\"}\n";
        fs::write(&path, original).unwrap();

        let error = write_json_once_with_hook(&path, &json!({"executionId": "second"}), |_| Ok(()))
            .unwrap_err();

        assert_eq!(error, "execution receipt already exists");
        assert_eq!(fs::read(&path).unwrap(), original);
        assert_eq!(fs::read_dir(&root).unwrap().count(), 1);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn crash_leftover_temp_file_is_not_receipt_evidence() {
        let root = publication_test_root("crash-leftover");
        let path = root.join("terminal.json");
        let leftover = root.join(".terminal.json.tmp-crash");
        fs::write(&leftover, b"{\"executionId\":").unwrap();

        assert_eq!(
            fs::read(&path).unwrap_err().kind(),
            std::io::ErrorKind::NotFound
        );
        write_json_once_with_hook(&path, &json!({"executionId": "published"}), |_| Ok(())).unwrap();

        let published: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        assert_eq!(published["executionId"], "published");
        assert_eq!(fs::read(&leftover).unwrap(), b"{\"executionId\":");
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn a_missing_acknowledgement_reader_cannot_destroy_terminal_evidence() {
        let root = std::env::temp_dir().join(format!(
            "tightbeam-command-exec-ack-window-{}-{}",
            std::process::id(),
            super::now_ms()
        ));
        fs::create_dir_all(&root).unwrap();
        let path = |name: &str| root.join(name);
        let manifest = Manifest {
            execution_id: "ack-window".to_string(),
            command: vec![
                "/bin/sh".to_string(),
                "-c".to_string(),
                "printf done".to_string(),
            ],
            cwd: PathBuf::from(&root),
            claim_path: path("claim"),
            launcher_path: path("launcher.json"),
            started_path: path("started.json"),
            stdout_path: path("stdout"),
            stderr_path: path("stderr"),
            not_started_path: path("not_started.json"),
            terminal_path: path("terminal.json"),
        };
        let (reader, writer) = pipe(false).unwrap();
        drop(reader);

        match unsafe { libc::fork() } {
            -1 => panic!("test supervisor could not fork"),
            0 => {
                let code = if supervise(&manifest, writer).is_ok() {
                    0
                } else {
                    1
                };
                unsafe { libc::_exit(code) };
            }
            child => {
                drop(writer);
                assert_eq!(decode_status(wait_child(child).unwrap()), (Some(0), None));
            }
        }

        let terminal: Value =
            serde_json::from_slice(&fs::read(&manifest.terminal_path).unwrap()).unwrap();
        assert_eq!(terminal["executionId"], "ack-window");
        assert_eq!(terminal["exitCode"], 0);
        assert_eq!(terminal["signal"], Value::Null);
        assert_eq!(fs::read(&manifest.stdout_path).unwrap(), b"done");
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn inherited_sigchld_ignore_cannot_destroy_terminal_evidence() {
        let root = std::env::temp_dir().join(format!(
            "tightbeam-command-exec-sigchld-{}-{}",
            std::process::id(),
            super::now_ms()
        ));
        fs::create_dir_all(&root).unwrap();
        let path = |name: &str| root.join(name);
        let prepared_path = path("prepared.json");
        let terminal_path = path("terminal.json");
        let stdout_path = path("stdout");
        let command = vec!["/bin/sh", "-c", "printf inherited"];
        let command_json = serde_json::to_string(&command).unwrap();
        fs::write(
            &prepared_path,
            serde_json::to_vec(&serde_json::json!({
                "executionId": "inherited-sigchld",
                "host": current_host().unwrap(),
                "cwd": root,
                "command": command,
                "commandJson": command_json,
                "commandSha256": hex_sha256(command_json.as_bytes()),
                "claimPath": path("claim"),
                "launcherIdentityPath": path("launcher.json"),
                "startedPath": path("started.json"),
                "stdoutPath": stdout_path,
                "stderrPath": path("stderr"),
                "notStartedPath": path("not_started.json"),
                "terminalPath": terminal_path
            }))
            .unwrap(),
        )
        .unwrap();

        match unsafe { libc::fork() } {
            -1 => panic!("test invoker could not fork"),
            0 => {
                unsafe {
                    libc::signal(libc::SIGCHLD, libc::SIG_IGN);
                }
                let code = run(&[prepared_path.to_string_lossy().into_owned()]).unwrap();
                unsafe { libc::_exit(code) };
            }
            child => {
                assert_eq!(decode_status(wait_child(child).unwrap()), (Some(0), None));
            }
        }

        for _ in 0..200 {
            if terminal_path.exists() {
                break;
            }
            thread::sleep(Duration::from_millis(10));
        }

        let terminal: Value = serde_json::from_slice(&fs::read(&terminal_path).unwrap()).unwrap();
        assert_eq!(terminal["executionId"], "inherited-sigchld");
        assert_eq!(terminal["exitCode"], 0);
        assert_eq!(terminal["signal"], Value::Null);
        assert_eq!(fs::read(&stdout_path).unwrap(), b"inherited");
        fs::remove_dir_all(root).unwrap();
    }
}

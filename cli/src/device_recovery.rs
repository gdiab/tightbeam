//! Offline device recovery on the gateway host (stage1-v8 S1.2, S1.5).
//!
//! - `tightbeam recover-admin --user <userId>`: the full-lockout ceremony. With the
//!   gateway stopped, it checks the user's recovery secret, clears every token of the
//!   user's devices, and prints a 60-minute recovery pairing code. It never consumes
//!   the secret: the first sign-in of a device paired with the code does (S2.3), so
//!   the ceremony is resumable and idempotent.
//! - `tightbeam root-admin recovery-enroll --user <userId>` and
//!   `tightbeam root-admin pairing-code --user <userId>`: George's root-shell path,
//!   for when he has no working paired device. Root only (via `sudo` and his own
//!   password), never in a session context, only on a controlling terminal.
//!
//! All three hold the base-directory lock (`<base_dir>/gateway.lock`) throughout, so
//! the gateway must be stopped. Secrets and codes are shown only on the controlling
//! terminal and stored only as Argon2id verifiers (S0.3), with the same crate and
//! parameters as the gateway. The lock, terminal and working-directory checks prevent
//! accidents and honest-process races; they do not identify George against a process
//! running as the gateway's account (S1.4).

use std::ffi::CStr;
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::os::unix::io::AsRawFd;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use argon2::{Algorithm, Argon2, Params, Version};
use rusqlite::{Connection, OptionalExtension, Transaction, TransactionBehavior, params};

const SHAPE: &str = "device-lifecycle-stage1-v1-0114";
const CROCKFORD: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";
const CODE_TTL_MS: i64 = 3_600_000;
const MAX_OUTSTANDING: usize = 5;
const M_COST_KIB: u32 = 64 * 1024;
const T_COST: u32 = 3;
const P_COST: u32 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RootAction {
    RecoveryEnroll,
    PairingCode,
}

impl RootAction {
    fn name(self) -> &'static str {
        match self {
            RootAction::RecoveryEnroll => "recovery-enroll",
            RootAction::PairingCode => "pairing-code",
        }
    }
}

/// `tightbeam recover-admin --user <userId>` (S1.2).
pub fn recover_admin(user: &str) -> Result<(), String> {
    let base = crate::base_dir::resolve();
    let _lock = BaseLock::acquire(&base)?;
    refuse_session_context()?;
    let mut tty = Terminal::open()?;
    let account = invoking_account();
    let tty_name = tty.name();

    write!(tty.file, "Recovery secret for {user}: ").map_err(io_error)?;
    let secret = tty.read_hidden_line()?;

    let mut connection = open_database(&base)?;
    let transaction = begin(&mut connection)?;
    let at = now_ms();

    let refusal = check_secret(&transaction, user, &secret)?;
    if let Some(reason) = refusal {
        record(
            &transaction,
            "admin_recovery_refused",
            user,
            serde_json::json!({ "userId": user, "reason": reason, "account": account, "at": at }),
            at,
        )?;
        transaction.commit().map_err(db_error)?;
        return Err(format!(
            "recovery refused ({reason}); nothing changed. The attempt is recorded."
        ));
    }

    let cleared = clear_tokens(&transaction, user)?;
    transaction
        .execute(
            "UPDATE pairing_codes SET invalidatedAt = ?2 \
             WHERE userId = ?1 AND recovery = 1 AND usedAt IS NULL AND invalidatedAt IS NULL",
            params![user, at],
        )
        .map_err(db_error)?;
    let (code, code_id) = issue_code(&transaction, user, true, at)?;
    record(
        &transaction,
        "admin_recovered",
        user,
        serde_json::json!({
            "userId": user,
            "clearedDeviceIds": cleared,
            "codeId": code_id,
            "account": account,
            "at": at
        }),
        at,
    )?;
    host_action(
        &transaction,
        "admin-recovered",
        user,
        Some(&code_id),
        &account,
        &tty_name,
        at,
    )?;
    transaction.commit().map_err(db_error)?;

    writeln!(
        tty.file,
        "\nRecovery pairing code {code} for {user}, valid 60 minutes.\n\
         Start the gateway, then on your new device enter the name '<name> {code}' in the \
         pairing screen within 60 minutes. If this output is lost, run this ceremony again \
         with the same secret: that issues a fresh code and voids this one."
    )
    .map_err(io_error)?;
    Ok(())
}

/// `tightbeam root-admin <recovery-enroll|pairing-code> --user <userId>` (S1.5).
pub fn root_admin(action: RootAction, user: &str) -> Result<(), String> {
    root_admin_as(&host(), action, user)
}

fn root_admin_as(host: &impl Host, action: RootAction, user: &str) -> Result<(), String> {
    if !host.is_root() {
        return Err(format!(
            "root-admin {} needs root: run it as `sudo tightbeam root-admin {} --user {user}`, \
             with your own password. Nothing changed.",
            action.name(),
            action.name()
        ));
    }
    refuse_session_context()?;
    let mut tty = Terminal::open()?;
    let account = host.invoking_account();
    let tty_name = tty.name();
    let base = crate::base_dir::resolve();

    // Act as the database's owner from here on, so the gateway's account can still
    // open state.db, its journal files and the lock file afterwards (S1.5 (5)).
    drop_to_owner(host, &base.join("state.db"))?;
    let _lock = BaseLock::acquire(&base)?;

    let mut connection = open_database(&base)?;
    let transaction = begin(&mut connection)?;
    let at = now_ms();

    let output = match action {
        RootAction::RecoveryEnroll => {
            require_user(&transaction, user, true)?;
            let secret = new_secret();
            let salt = random_bytes::<16>();
            let verifier = argon2id(&canonical(&secret), &salt)?;
            transaction
                .execute(
                    "INSERT INTO recovery_secrets (userId, verifier, salt, enrolledAt, consumedAt) \
                     VALUES (?1, ?2, ?3, ?4, NULL) \
                     ON CONFLICT(userId) DO UPDATE SET verifier = excluded.verifier, \
                     salt = excluded.salt, enrolledAt = excluded.enrolledAt, consumedAt = NULL",
                    params![user, verifier.to_vec(), salt.to_vec(), at],
                )
                .map_err(db_error)?;
            record(
                &transaction,
                "recovery_secret_enrolled",
                user,
                serde_json::json!({ "userId": user, "enrolledAt": at }),
                at,
            )?;
            record(
                &transaction,
                "root_admin_action",
                user,
                serde_json::json!({
                    "action": "recovery-enroll", "userId": user, "at": at,
                    "account": account, "tty": tty_name
                }),
                at,
            )?;
            host_action(
                &transaction,
                "root-recovery-enroll",
                user,
                None,
                &account,
                &tty_name,
                at,
            )?;
            format!(
                "Recovery secret for {user}: {secret}\n\
                 Write it down on paper now and keep it offline. It is shown only this once."
            )
        }
        RootAction::PairingCode => {
            require_user(&transaction, user, false)?;
            let (code, code_id) = issue_code(&transaction, user, false, at)?;
            record(
                &transaction,
                "root_admin_action",
                user,
                serde_json::json!({
                    "action": "pairing-code", "userId": user, "codeId": code_id, "at": at,
                    "account": account, "tty": tty_name
                }),
                at,
            )?;
            host_action(
                &transaction,
                "root-pairing-code",
                user,
                Some(&code_id),
                &account,
                &tty_name,
                at,
            )?;
            format!(
                "Pairing code {code} for {user}, valid 60 minutes.\n\
                 Start the gateway, then on the new device enter its name, a space, and this code."
            )
        }
    };
    transaction.commit().map_err(db_error)?;
    writeln!(tty.file, "{output}").map_err(io_error)?;
    Ok(())
}

// --- checks -----------------------------------------------------------------

/// S1.2 step 2: a guard against accidental agent use, not a boundary.
fn refuse_session_context() -> Result<(), String> {
    let cwd = std::env::current_dir().map_err(io_error)?;
    if let Some(found) = session_credential_above(&cwd) {
        return Err(format!(
            "refusing: a Tightbeam session credential ({}) is discoverable from this \
             directory. Agents never run this; George runs it from his own shell, outside \
             any session directory. Nothing changed.",
            found.display()
        ));
    }
    Ok(())
}

fn session_credential_above(cwd: &Path) -> Option<PathBuf> {
    cwd.ancestors()
        .map(|directory| directory.join(".tightbeam-session"))
        .find(|path| path.exists())
}

struct BaseLock(#[allow(dead_code)] File);

impl BaseLock {
    fn acquire(base: &Path) -> Result<Self, String> {
        let path = base.join("gateway.lock");
        let file = OpenOptions::new()
            .create(true)
            .write(true)
            .mode(0o600)
            .open(&path)
            .map_err(|error| format!("cannot open {}: {error}; nothing changed", path.display()))?;
        if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
            return Err(
                "the base-directory lock is held: stop the gateway first (`sudo systemctl stop \
                 tightbeam`), and make sure no other recovery command is running. Nothing changed."
                    .to_owned(),
            );
        }
        Ok(BaseLock(file))
    }
}

struct Terminal {
    file: File,
}

impl Terminal {
    /// The controlling terminal. Standard input must be it too: a secret is never
    /// taken from arguments, the environment, or input redirected from a file.
    fn open() -> Result<Self, String> {
        if unsafe { libc::isatty(0) } != 1 {
            return Err(
                "refusing: this needs a terminal; standard input is not one (a pipe or a \
                 file). Nothing changed."
                    .to_owned(),
            );
        }
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .open("/dev/tty")
            .map_err(|_| {
                "refusing: there is no controlling terminal. Nothing changed.".to_owned()
            })?;
        Ok(Terminal { file })
    }

    fn name(&self) -> String {
        let name = unsafe { libc::ttyname(0) };
        if name.is_null() {
            "unknown".to_owned()
        } else {
            unsafe { CStr::from_ptr(name) }
                .to_string_lossy()
                .into_owned()
        }
    }

    fn read_hidden_line(&mut self) -> Result<String, String> {
        read_hidden(&TtyOps(&self.file))
    }
}

/// The terminal operations a hidden read needs, behind a seam so a test can make any
/// of them fail.
trait TermOps {
    fn fd(&self) -> i32;
    fn get(&self) -> std::io::Result<libc::termios>;
    fn set(&self, settings: &libc::termios) -> std::io::Result<()>;
    fn read_line(&self) -> std::io::Result<String>;
}

struct TtyOps<'a>(&'a File);

impl TermOps for TtyOps<'_> {
    fn fd(&self) -> i32 {
        self.0.as_raw_fd()
    }

    fn get(&self) -> std::io::Result<libc::termios> {
        let mut settings: libc::termios = unsafe { std::mem::zeroed() };
        if unsafe { libc::tcgetattr(self.fd(), &mut settings) } != 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(settings)
    }

    fn set(&self, settings: &libc::termios) -> std::io::Result<()> {
        if unsafe { libc::tcsetattr(self.fd(), libc::TCSANOW, settings) } != 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(())
    }

    /// One line, read byte by byte from the terminal itself: no buffered reader or
    /// cloned handle that could read past it or fail after echo is off.
    fn read_line(&self) -> std::io::Result<String> {
        let mut bytes = Vec::new();
        let mut byte = [0u8; 1];
        let mut file = self.0;
        loop {
            match file.read(&mut byte) {
                Ok(0) => break,
                Ok(_) if byte[0] == b'\n' => break,
                Ok(_) => bytes.push(byte[0]),
                Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(error) => return Err(error),
            }
        }
        String::from_utf8(bytes)
            .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidData, "not UTF-8"))
    }
}

/// Reads one line with echo off (S1.2), and fails closed:
/// - if echo cannot be turned off, or is still on afterwards, nothing is read;
/// - the terminal's settings are restored on every way out: a normal return, an error,
///   a panic (the guard's drop), and SIGINT, SIGTERM, SIGHUP or SIGQUIT (a handler that
///   restores, then lets the signal act). Ctrl-Z is ignored while the secret is typed,
///   so the prompt cannot be suspended and resumed with echo back on.
/// - if restoration fails, the input is discarded and the refusal says so, without it.
fn read_hidden<T: TermOps>(term: &T) -> Result<String, String> {
    let original = term.get().map_err(|_| {
        "refusing: cannot read the terminal's settings. Nothing changed.".to_owned()
    })?;
    let mut hidden = original;
    hidden.c_lflag &= !libc::ECHO;

    let guard = EchoRestore::arm(term, original);
    let echo_off = term
        .set(&hidden)
        .and_then(|_| term.get())
        .map(|now| now.c_lflag & libc::ECHO == 0);
    if !matches!(echo_off, Ok(true)) {
        return Err(
            "refusing: cannot turn terminal echo off, so the secret is not read. Nothing \
             changed."
                .to_owned(),
        );
    }

    let read = term.read_line();
    if guard.restore().is_err() {
        return Err(
            "refusing: the terminal's settings could not be restored, so the input is \
             discarded; echo may still be off (run `stty echo`). Nothing changed."
                .to_owned(),
        );
    }
    let line = read.map_err(|_| {
        "refusing: cannot read the secret from the terminal. Nothing changed.".to_owned()
    })?;
    Ok(line.trim().to_owned())
}

/// Restores the terminal's original settings when it goes out of scope, and while it
/// is armed, on the terminating signals too.
struct EchoRestore<'a, T: TermOps> {
    term: &'a T,
    original: libc::termios,
    signals: SignalRestore,
    armed: bool,
}

impl<'a, T: TermOps> EchoRestore<'a, T> {
    fn arm(term: &'a T, original: libc::termios) -> Self {
        let signals = SignalRestore::install(term.fd(), original);
        EchoRestore {
            term,
            original,
            signals,
            armed: true,
        }
    }

    fn restore(mut self) -> std::io::Result<()> {
        self.armed = false;
        let restored = self.term.set(&self.original);
        self.signals.uninstall();
        restored
    }
}

impl<T: TermOps> Drop for EchoRestore<'_, T> {
    fn drop(&mut self) {
        if self.armed {
            if self.term.set(&self.original).is_err() {
                eprintln!(
                    "tightbeam: the terminal's settings could not be restored; echo may \
                     still be off (run `stty echo`)."
                );
            }
            self.signals.uninstall();
        }
    }
}

const RESTORE_SIGNALS: [libc::c_int; 4] =
    [libc::SIGINT, libc::SIGTERM, libc::SIGHUP, libc::SIGQUIT];

static RESTORE_FD: std::sync::atomic::AtomicI32 = std::sync::atomic::AtomicI32::new(-1);
static mut RESTORE_SETTINGS: std::mem::MaybeUninit<libc::termios> = std::mem::MaybeUninit::uninit();

/// Restores the terminal (tcsetattr is async-signal-safe), then lets the signal take
/// its default action.
extern "C" fn restore_and_reraise(signal: libc::c_int) {
    let fd = RESTORE_FD.load(std::sync::atomic::Ordering::SeqCst);
    if fd >= 0 {
        unsafe {
            let settings = std::ptr::addr_of!(RESTORE_SETTINGS) as *const libc::termios;
            libc::tcsetattr(fd, libc::TCSANOW, settings);
            libc::signal(signal, libc::SIG_DFL);
            libc::raise(signal);
        }
    }
}

struct SignalRestore {
    previous: Vec<(libc::c_int, libc::sighandler_t)>,
    installed: bool,
}

impl SignalRestore {
    fn install(fd: i32, original: libc::termios) -> Self {
        // No terminal descriptor, nothing a signal could restore.
        if fd < 0 {
            return SignalRestore {
                previous: Vec::new(),
                installed: false,
            };
        }
        unsafe {
            (*std::ptr::addr_of_mut!(RESTORE_SETTINGS)).write(original);
        }
        RESTORE_FD.store(fd, std::sync::atomic::Ordering::SeqCst);
        let handler = restore_and_reraise as extern "C" fn(libc::c_int) as libc::sighandler_t;
        let mut previous: Vec<(libc::c_int, libc::sighandler_t)> = RESTORE_SIGNALS
            .iter()
            .map(|&signal| (signal, unsafe { libc::signal(signal, handler) }))
            .collect();
        previous.push((libc::SIGTSTP, unsafe {
            libc::signal(libc::SIGTSTP, libc::SIG_IGN)
        }));
        SignalRestore {
            previous,
            installed: true,
        }
    }

    fn uninstall(&mut self) {
        if self.installed {
            for &(signal, handler) in &self.previous {
                unsafe { libc::signal(signal, handler) };
            }
            RESTORE_FD.store(-1, std::sync::atomic::Ordering::SeqCst);
            self.installed = false;
        }
    }
}

// --- host identity (S1.5 items 1, 5 and 6) -----------------------------------

/// What `root-admin` asks of the host: whether this process is root, who invoked it
/// (S1.5 (6)), and becoming the database's owner (S1.5 (5)). The release CLI makes the
/// system calls (`RealHost`). Only a CLI built with the `root-admin-seam` cargo
/// feature, which the release and package builds never enable, answers from values
/// compiled into it (`SeamHost`); no argument, environment variable or file selects
/// it (F1 erratum 1 rev 4 §1c.1, stage1-v12 §6.3). Everything after these answers is
/// the same product code in both.
trait Host {
    fn is_root(&self) -> bool;
    fn invoking_account(&self) -> String;
    fn become_owner(&self, uid: u32, gid: u32) -> Result<(), String>;
}

#[cfg(not(feature = "root-admin-seam"))]
fn host() -> RealHost {
    RealHost
}

#[cfg(feature = "root-admin-seam")]
fn host() -> SeamHost {
    SeamHost
}

struct RealHost;

impl Host for RealHost {
    fn is_root(&self) -> bool {
        let euid = unsafe { libc::geteuid() };
        euid == 0
    }

    fn invoking_account(&self) -> String {
        if let Ok(user) = std::env::var("SUDO_USER") {
            if !user.is_empty() {
                return user;
            }
        }
        let pw = unsafe { libc::getpwuid(libc::getuid()) };
        if pw.is_null() {
            format!("uid {}", unsafe { libc::getuid() })
        } else {
            unsafe { CStr::from_ptr((*pw).pw_name) }
                .to_string_lossy()
                .into_owned()
        }
    }

    fn become_owner(&self, uid: u32, gid: u32) -> Result<(), String> {
        unsafe {
            if libc::setgroups(0, std::ptr::null()) != 0
                || libc::setgid(gid) != 0
                || libc::setuid(uid) != 0
            {
                return Err("cannot act as the database's owner; nothing changed".to_owned());
            }
        }
        Ok(())
    }
}

/// The marker a seam-built CLI carries, so the package check can refuse one
/// (`packaging/verify-payload.sh`). The release build does not contain it.
#[cfg(feature = "root-admin-seam")]
pub const SEAM_MARKER: &str = "tightbeam-root-admin-test-seam";

/// The account a seam-built CLI records, compiled in: never read from the
/// environment.
#[cfg(feature = "root-admin-seam")]
pub const SEAM_ACCOUNT: &str = "seam-operator";

/// Test builds only: reports root, records a fixed invoking account, and in place of
/// the owner switch writes the requested uid and gid to standard error, so a test can
/// check the switch targets exactly `state.db`'s owner before any write.
#[cfg(feature = "root-admin-seam")]
struct SeamHost;

#[cfg(feature = "root-admin-seam")]
impl Host for SeamHost {
    fn is_root(&self) -> bool {
        true
    }

    fn invoking_account(&self) -> String {
        SEAM_ACCOUNT.to_owned()
    }

    fn become_owner(&self, uid: u32, gid: u32) -> Result<(), String> {
        eprintln!("{SEAM_MARKER}: become_owner uid={uid} gid={gid}");
        Ok(())
    }
}

/// The database's owner, from `state.db` itself.
fn database_owner(database: &Path) -> Result<(u32, u32), String> {
    let meta = std::fs::metadata(database).map_err(|error| {
        format!(
            "cannot read {}: {error}; nothing changed",
            database.display()
        )
    })?;
    Ok((meta.uid(), meta.gid()))
}

fn drop_to_owner(host: &impl Host, database: &Path) -> Result<(), String> {
    let (uid, gid) = database_owner(database)?;
    host.become_owner(uid, gid)
}

fn invoking_account() -> String {
    RealHost.invoking_account()
}

// --- database ---------------------------------------------------------------

fn open_database(base: &Path) -> Result<Connection, String> {
    let path = base.join("state.db");
    if !path.is_file() {
        return Err(format!(
            "no gateway database at {}; nothing changed",
            path.display()
        ));
    }
    let connection = Connection::open(&path).map_err(db_error)?;
    connection
        .busy_timeout(std::time::Duration::from_secs(5))
        .map_err(db_error)?;
    let shape: Option<String> = connection
        .query_row(
            "SELECT shape FROM device_lifecycle_migration WHERE id = 0",
            [],
            |row| row.get(0),
        )
        .optional()
        .unwrap_or(None);
    if shape.as_deref() != Some(SHAPE) {
        return Err(
            "this gateway database has not been upgraded to device lifecycle stage 1; start \
             the upgraded gateway once first. Nothing changed."
                .to_owned(),
        );
    }
    Ok(connection)
}

fn begin(connection: &mut Connection) -> Result<Transaction<'_>, String> {
    connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(db_error)
}

fn require_user(transaction: &Transaction, user: &str, admin: bool) -> Result<(), String> {
    let row: Option<(i64, Option<i64>)> = transaction
        .query_row(
            "SELECT isAdmin, removedAt FROM users WHERE userId = ?1",
            [user],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()
        .map_err(db_error)?;
    match row {
        Some((is_admin, None)) if !admin || is_admin == 1 => Ok(()),
        Some((_, None)) => Err(format!("{user} is not an admin; nothing changed")),
        Some((_, Some(_))) => Err(format!("{user} was removed; nothing changed")),
        None => Err(format!("no user {user}; nothing changed")),
    }
}

/// S1.2 step 4: `None` when `secret` is the user's enrolled, unconsumed secret.
fn check_secret(
    transaction: &Transaction,
    user: &str,
    secret: &str,
) -> Result<Option<&'static str>, String> {
    let admin: Option<(i64, Option<i64>)> = transaction
        .query_row(
            "SELECT isAdmin, removedAt FROM users WHERE userId = ?1",
            [user],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()
        .map_err(db_error)?;
    match admin {
        Some((1, None)) => {}
        Some(_) => return Ok(Some("not_an_admin")),
        None => return Ok(Some("unknown_user")),
    }
    let stored: Option<(Vec<u8>, Vec<u8>, Option<i64>)> = transaction
        .query_row(
            "SELECT verifier, salt, consumedAt FROM recovery_secrets WHERE userId = ?1",
            [user],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .optional()
        .map_err(db_error)?;
    let Some((verifier, salt, consumed)) = stored else {
        return Ok(Some("no_enrolled_secret"));
    };
    if consumed.is_some() {
        return Ok(Some("secret_consumed"));
    }
    let salt: [u8; 16] = salt
        .try_into()
        .map_err(|_| "malformed stored salt".to_owned())?;
    let computed = argon2id(&canonical(secret), &salt)?;
    if constant_time_eq(&computed, &verifier) {
        Ok(None)
    } else {
        Ok(Some("wrong_secret"))
    }
}

fn clear_tokens(transaction: &Transaction, user: &str) -> Result<Vec<String>, String> {
    let mut statement = transaction
        .prepare("SELECT deviceId FROM devices WHERE userId = ?1 AND token IS NOT NULL ORDER BY deviceId")
        .map_err(db_error)?;
    let cleared = statement
        .query_map([user], |row| row.get::<_, String>(0))
        .map_err(db_error)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(db_error)?;
    drop(statement);
    transaction
        .execute(
            "UPDATE devices SET token = NULL, tokenGeneration = tokenGeneration + 1 \
             WHERE userId = ?1 AND token IS NOT NULL",
            [user],
        )
        .map_err(db_error)?;
    Ok(cleared)
}

/// Issue a 60-minute code for `user` and keep at most 5 outstanding (S0.3).
fn issue_code(
    transaction: &Transaction,
    user: &str,
    recovery: bool,
    at: i64,
) -> Result<(String, String), String> {
    let code = new_code();
    let code_id = format!("pc_{}", hex(&random_bytes::<8>()));
    let salt = random_bytes::<16>();
    let verifier = argon2id(&canonical(&code), &salt)?;
    transaction
        .execute(
            "INSERT INTO pairing_codes \
             (codeId, verifier, salt, userId, issuingDeviceId, recovery, issuedAt, expiresAt) \
             VALUES (?1, ?2, ?3, ?4, NULL, ?5, ?6, ?7)",
            params![
                code_id,
                verifier.to_vec(),
                salt.to_vec(),
                user,
                recovery as i64,
                at,
                at + CODE_TTL_MS
            ],
        )
        .map_err(db_error)?;
    let mut statement = transaction
        .prepare(
            "SELECT codeId FROM pairing_codes \
             WHERE usedAt IS NULL AND invalidatedAt IS NULL AND expiresAt > ?1 \
             ORDER BY issuedAt DESC, codeId DESC",
        )
        .map_err(db_error)?;
    let outstanding = statement
        .query_map([at], |row| row.get::<_, String>(0))
        .map_err(db_error)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(db_error)?;
    drop(statement);
    for old in outstanding.iter().skip(MAX_OUTSTANDING) {
        transaction
            .execute(
                "UPDATE pairing_codes SET invalidatedAt = ?2 WHERE codeId = ?1",
                params![old, at],
            )
            .map_err(db_error)?;
        record(
            transaction,
            "pairing_code_invalidated",
            old,
            serde_json::json!({ "codeId": old, "reason": "limit" }),
            at,
        )?;
    }
    record(
        transaction,
        "pairing_code_issued",
        &code_id,
        serde_json::json!({
            "codeId": code_id, "userId": user, "expiresAt": at + CODE_TTL_MS, "recovery": recovery
        }),
        at,
    )?;
    Ok((code, code_id))
}

fn record(
    transaction: &Transaction,
    kind: &str,
    subject: &str,
    detail: serde_json::Value,
    at: i64,
) -> Result<(), String> {
    transaction
        .execute(
            "INSERT INTO lifecycle_events (ts, kind, subject, detail) VALUES (?1, ?2, ?3, ?4)",
            params![at, kind, subject, detail.to_string()],
        )
        .map_err(db_error)?;
    Ok(())
}

fn host_action(
    transaction: &Transaction,
    kind: &str,
    user: &str,
    code_id: Option<&str>,
    account: &str,
    tty: &str,
    at: i64,
) -> Result<(), String> {
    transaction
        .execute(
            "INSERT INTO gateway_host_actions (kind, userId, codeId, account, tty, at) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![kind, user, code_id, account, tty, at],
        )
        .map_err(db_error)?;
    Ok(())
}

// --- secrets and codes --------------------------------------------------------

/// The Argon2id verifier, identical to the gateway's (`Tightbeam.Native.argon2id/2`).
fn argon2id(text: &str, salt: &[u8; 16]) -> Result<[u8; 32], String> {
    let params = Params::new(M_COST_KIB, T_COST, P_COST, Some(32)).map_err(|e| e.to_string())?;
    let mut out = [0u8; 32];
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
        .hash_password_into(text.as_bytes(), salt, &mut out)
        .map_err(|e| e.to_string())?;
    Ok(out)
}

fn canonical(text: &str) -> String {
    text.trim().to_uppercase()
}

fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    left.len() == right.len()
        && left
            .iter()
            .zip(right)
            .fold(0u8, |acc, (a, b)| acc | (a ^ b))
            == 0
}

fn crockford(count: usize) -> String {
    // 5 random bits per character, from a whole number of random bytes, no bias.
    let bytes = random_bytes_vec((count * 5).div_ceil(8));
    let mut out = String::with_capacity(count);
    for index in 0..count {
        let mut value = 0usize;
        for bit in 0..5 {
            let position = index * 5 + bit;
            let set = (bytes[position / 8] >> (7 - position % 8)) & 1;
            value = (value << 1) | set as usize;
        }
        out.push(CROCKFORD[value] as char);
    }
    out
}

fn new_code() -> String {
    let c = crockford(12);
    format!("TB-{}-{}-{}", &c[0..4], &c[4..8], &c[8..12])
}

fn new_secret() -> String {
    let c = crockford(20);
    format!(
        "TBR-{}-{}-{}-{}",
        &c[0..5],
        &c[5..10],
        &c[10..15],
        &c[15..20]
    )
}

fn random_bytes<const N: usize>() -> [u8; N] {
    let mut out = [0u8; N];
    File::open("/dev/urandom")
        .and_then(|mut file| file.read_exact(&mut out))
        .expect("the operating system's random source is readable");
    out
}

fn random_bytes_vec(count: usize) -> Vec<u8> {
    let mut out = vec![0u8; count];
    File::open("/dev/urandom")
        .and_then(|mut file| file.read_exact(&mut out))
        .expect("the operating system's random source is readable");
    out
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| elapsed.as_millis() as i64)
        .unwrap_or(0)
}

fn io_error(error: std::io::Error) -> String {
    format!("{error}; nothing changed")
}

fn db_error(error: rusqlite::Error) -> String {
    format!("database error: {error}; nothing changed")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn codes_and_secrets_have_the_spec_shapes() {
        let code = new_code();
        assert_eq!(code.len(), 17);
        assert!(code.starts_with("TB-"));
        assert!(
            code[3..]
                .split('-')
                .all(|g| g.len() == 4 && g.bytes().all(|b| CROCKFORD.contains(&b)))
        );
        let secret = new_secret();
        assert_eq!(secret.len(), 27);
        assert!(secret.starts_with("TBR-"));
        assert_ne!(new_code(), new_code());
    }

    #[test]
    fn verifier_matches_the_gateway_parameters_and_compares_in_constant_time() {
        let salt = [7u8; 16];
        let first = argon2id("TB-7K3M-Q9ZD-2WH8", &salt).unwrap();
        assert_eq!(
            first,
            argon2id(&canonical(" tb-7k3m-q9zd-2wh8 "), &salt).unwrap()
        );
        assert!(constant_time_eq(&first, &first));
        assert!(!constant_time_eq(
            &first,
            &argon2id("TB-7K3M-Q9ZD-2WH9", &salt).unwrap()
        ));
    }

    /// The shared test vector: the gateway's NIF must produce the same bytes
    /// (test/device_lifecycle_test.exs reads the same file).
    #[test]
    fn verifier_matches_the_shared_gateway_vector() {
        let expected = include_str!("device_recovery_vector.txt").trim();
        assert_eq!(
            hex(&argon2id("TB-7K3M-Q9ZD-2WH8", &[7u8; 16]).unwrap()),
            expected
        );
    }

    #[test]
    fn a_session_credential_above_the_directory_is_found() {
        let root = std::env::temp_dir().join(format!("tb-recover-guard-{}", std::process::id()));
        let nested = root.join("a/b");
        std::fs::create_dir_all(&nested).unwrap();
        assert_eq!(session_credential_above(&nested), None);
        std::fs::write(root.join(".tightbeam-session"), "{}").unwrap();
        assert_eq!(
            session_credential_above(&nested),
            Some(root.join(".tightbeam-session"))
        );
        std::fs::remove_dir_all(root).unwrap();
    }

    /// A terminal whose every operation can be made to fail (B3 fault injection).
    #[derive(Default)]
    struct FakeTerm {
        fail_get: bool,
        disable_fails: bool,
        disable_ignored: bool,
        read_fails: bool,
        read_panics: bool,
        restore_fails: bool,
        echo: std::cell::Cell<bool>,
        reads: std::cell::Cell<u32>,
        echo_at_read: std::cell::Cell<Option<bool>>,
    }

    impl FakeTerm {
        fn new() -> Self {
            let term = FakeTerm::default();
            term.echo.set(true);
            term
        }
    }

    impl TermOps for FakeTerm {
        fn fd(&self) -> i32 {
            -1
        }

        fn get(&self) -> std::io::Result<libc::termios> {
            if self.fail_get {
                return Err(std::io::Error::other("tcgetattr"));
            }
            let mut settings: libc::termios = unsafe { std::mem::zeroed() };
            if self.echo.get() {
                settings.c_lflag |= libc::ECHO;
            }
            Ok(settings)
        }

        fn set(&self, settings: &libc::termios) -> std::io::Result<()> {
            let wants_echo = settings.c_lflag & libc::ECHO != 0;
            if !wants_echo && self.disable_fails || wants_echo && self.restore_fails {
                return Err(std::io::Error::other("tcsetattr"));
            }
            if !(self.disable_ignored && !wants_echo) {
                self.echo.set(wants_echo);
            }
            Ok(())
        }

        fn read_line(&self) -> std::io::Result<String> {
            self.reads.set(self.reads.get() + 1);
            self.echo_at_read.set(Some(self.echo.get()));
            if self.read_panics {
                panic!("read panicked");
            }
            if self.read_fails {
                return Err(std::io::Error::other("read"));
            }
            Ok(" TBR-SECRET-INPUT \n".to_owned())
        }
    }

    #[test]
    fn a_hidden_read_reads_with_echo_off_and_restores_it() {
        let term = FakeTerm::new();
        assert_eq!(read_hidden(&term).unwrap(), "TBR-SECRET-INPUT");
        assert_eq!(term.echo_at_read.get(), Some(false));
        assert!(term.echo.get());
    }

    #[test]
    fn a_hidden_read_refuses_without_reading_when_echo_cannot_be_turned_off() {
        for term in [
            FakeTerm {
                disable_fails: true,
                ..FakeTerm::new()
            },
            FakeTerm {
                disable_ignored: true,
                ..FakeTerm::new()
            },
        ] {
            let refusal = read_hidden(&term).unwrap_err();
            assert!(
                refusal.contains("cannot turn terminal echo off"),
                "{refusal}"
            );
            assert_eq!(term.reads.get(), 0);
            assert!(term.echo.get());
        }
    }

    #[test]
    fn a_hidden_read_refuses_without_reading_when_settings_cannot_be_read() {
        let term = FakeTerm {
            fail_get: true,
            ..FakeTerm::new()
        };
        assert!(
            read_hidden(&term)
                .unwrap_err()
                .contains("terminal's settings")
        );
        assert_eq!(term.reads.get(), 0);
    }

    #[test]
    fn a_failed_read_restores_echo() {
        let term = FakeTerm {
            read_fails: true,
            ..FakeTerm::new()
        };
        assert!(
            read_hidden(&term)
                .unwrap_err()
                .contains("cannot read the secret")
        );
        assert!(term.echo.get());
    }

    #[test]
    fn a_panic_during_the_read_restores_echo() {
        let term = FakeTerm {
            read_panics: true,
            ..FakeTerm::new()
        };
        let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| read_hidden(&term)));
        assert!(outcome.is_err());
        assert!(term.echo.get());
    }

    #[test]
    fn a_failed_restore_discards_the_input_and_says_so_without_it() {
        let term = FakeTerm {
            restore_fails: true,
            ..FakeTerm::new()
        };
        let refusal = read_hidden(&term).unwrap_err();
        assert!(refusal.contains("could not be restored"), "{refusal}");
        assert!(!refusal.contains("TBR-SECRET-INPUT"));
    }

    /// An in-process host for the identity decision and the owner switch (stage1-v12
    /// §6.3: in-process injection by Rust tests). It records each switch it is asked for.
    struct RecordingHost {
        root: bool,
        switched: std::cell::RefCell<Vec<(u32, u32)>>,
    }

    impl Host for RecordingHost {
        fn is_root(&self) -> bool {
            self.root
        }

        fn invoking_account(&self) -> String {
            "recording-operator".to_owned()
        }

        fn become_owner(&self, uid: u32, gid: u32) -> Result<(), String> {
            self.switched.borrow_mut().push((uid, gid));
            Ok(())
        }
    }

    #[test]
    fn root_admin_refuses_a_non_root_host_before_anything_else() {
        let host = RecordingHost {
            root: false,
            switched: Default::default(),
        };
        let refusal = root_admin_as(&host, RootAction::PairingCode, "george").unwrap_err();
        assert!(refusal.contains("needs root"), "{refusal}");
        assert!(refusal.contains("Nothing changed"), "{refusal}");
        assert!(host.switched.borrow().is_empty());
    }

    #[test]
    fn the_owner_switch_targets_exactly_the_databases_uid_and_gid() {
        let dir = std::env::temp_dir().join(format!("tb-owner-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let database = dir.join("state.db");
        std::fs::write(&database, b"").unwrap();
        let meta = std::fs::metadata(&database).unwrap();

        let host = RecordingHost {
            root: true,
            switched: Default::default(),
        };
        drop_to_owner(&host, &database).unwrap();
        assert_eq!(*host.switched.borrow(), vec![(meta.uid(), meta.gid())]);

        // A missing state.db refuses rather than switching anywhere.
        let missing = dir.join("absent/state.db");
        assert!(
            drop_to_owner(&host, &missing)
                .unwrap_err()
                .contains("nothing changed")
        );
        assert_eq!(host.switched.borrow().len(), 1);
        std::fs::remove_dir_all(dir).unwrap();
    }

    /// The release build answers from the system: an ordinary test process is not root
    /// whatever its environment says.
    #[cfg(not(feature = "root-admin-seam"))]
    #[test]
    fn the_release_host_answers_root_from_the_effective_uid_only() {
        let euid = unsafe { libc::geteuid() };
        assert_eq!(host().is_root(), euid == 0);
    }
}

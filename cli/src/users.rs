//! User-management support for the one authorization state in which no authenticated
//! administrator can exist yet.
//!
//! Ordinary additions dispatch to the gateway. Only an existing local `state.db` with
//! zero users is written here; a remote installation has no local database to satisfy
//! that condition and therefore cannot reach the cold-start exception.

use std::path::Path;
use std::time::Duration;

use rusqlite::{Connection, OpenFlags, TransactionBehavior, params};

#[derive(Debug, PartialEq, Eq)]
pub enum FirstUser {
    Created {
        user_id: String,
        is_admin: bool,
        created_at: i64,
    },
    Dispatch,
}

pub fn create_first_if_local(user_id: &str, requested_admin: bool) -> Result<FirstUser, String> {
    create_first_in(
        &crate::base_dir::resolve().join("state.db"),
        user_id,
        requested_admin,
        now_ms(),
    )
}

fn create_first_in(
    db_path: &Path,
    user_id: &str,
    requested_admin: bool,
    created_at: i64,
) -> Result<FirstUser, String> {
    if !db_path.is_file() {
        return Ok(FirstUser::Dispatch);
    }

    let mut connection = Connection::open_with_flags(
        db_path,
        OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .map_err(|error| format!("cannot open {}: {error}", db_path.display()))?;
    connection
        .busy_timeout(Duration::from_secs(5))
        .map_err(|error| format!("cannot configure {}: {error}", db_path.display()))?;
    let transaction = connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(|error| format!("cannot begin add-user transaction: {error}"))?;

    let count: i64 = transaction
        .query_row("SELECT COUNT(*) FROM users", [], |row| row.get(0))
        .map_err(|error| format!("cannot read users from {}: {error}", db_path.display()))?;
    if count != 0 {
        return Ok(FirstUser::Dispatch);
    }

    transaction
        .execute(
            "INSERT INTO users (userId, isAdmin, createdAt) \
             VALUES (?1, CASE WHEN (SELECT COUNT(*) FROM users) = 0 THEN 1 ELSE ?2 END, ?3)",
            params![user_id, requested_admin, created_at],
        )
        .map_err(|error| format!("cannot add first user: {error}"))?;
    let is_admin: bool = transaction
        .query_row(
            "SELECT isAdmin FROM users WHERE userId = ?1",
            [user_id],
            |row| row.get(0),
        )
        .map_err(|error| format!("cannot read first user: {error}"))?;
    // Stage 1 R-c: the creation record `users` reads as this user's creation
    // provenance, written with the user or not at all.
    let detail = serde_json::json!({
        "userId": user_id,
        "via": "local-first-user",
        "isAdmin": is_admin,
        "at": created_at,
    })
    .to_string();
    transaction
        .execute(
            "INSERT INTO lifecycle_events (ts, kind, subject, detail) \
             VALUES (?1, 'user_created', ?2, ?3)",
            params![created_at, user_id, detail],
        )
        .map_err(|error| format!("cannot record the first user's creation: {error}"))?;
    transaction
        .commit()
        .map_err(|error| format!("cannot commit first user: {error}"))?;

    Ok(FirstUser::Created {
        user_id: user_id.to_owned(),
        is_admin,
        created_at,
    })
}

fn now_ms() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};

    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as i64
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{SystemTime, UNIX_EPOCH};

    static NEXT_DATABASE: AtomicU64 = AtomicU64::new(0);

    fn database() -> (std::path::PathBuf, std::path::PathBuf) {
        let root = std::env::temp_dir().join(format!(
            "tightbeam-add-user-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos()
                + u128::from(NEXT_DATABASE.fetch_add(1, Ordering::Relaxed))
        ));
        fs::create_dir_all(&root).unwrap();
        let path = root.join("state.db");
        Connection::open(&path)
            .unwrap()
            .execute_batch(
                r#"CREATE TABLE users (
                     userId TEXT PRIMARY KEY,
                     isAdmin INTEGER NOT NULL DEFAULT 0,
                     createdAt INTEGER NOT NULL
                   );
                   CREATE TABLE lifecycle_events (
                     id INTEGER PRIMARY KEY AUTOINCREMENT,
                     ts INTEGER NOT NULL,
                     kind TEXT NOT NULL,
                     subject TEXT NOT NULL,
                     detail TEXT
                   );"#,
            )
            .unwrap();
        (root, path)
    }

    #[test]
    fn local_empty_database_creates_the_first_user_as_admin() {
        let (root, path) = database();
        assert_eq!(
            create_first_in(&path, "flynn", false, 42),
            Ok(FirstUser::Created {
                user_id: "flynn".to_owned(),
                is_admin: true,
                created_at: 42
            })
        );
        fs::remove_dir_all(root).unwrap();
    }

    /// Core fix (A) K4a: on an empty local database the shortcut creates the first
    /// user and nothing else: no device row and no token, frozen pairing or not.
    #[test]
    fn local_first_user_shortcut_issues_no_device_token() {
        let (root, path) = database();
        Connection::open(&path)
            .unwrap()
            .execute_batch(
                r#"CREATE TABLE devices (
                     deviceId TEXT PRIMARY KEY,
                     userId TEXT NOT NULL,
                     token TEXT
                   );"#,
            )
            .unwrap();
        assert!(matches!(
            create_first_in(&path, "george", true, 7),
            Ok(FirstUser::Created { .. })
        ));
        let connection = Connection::open(&path).unwrap();
        let users: i64 = connection
            .query_row("SELECT COUNT(*) FROM users", [], |row| row.get(0))
            .unwrap();
        let devices: i64 = connection
            .query_row("SELECT COUNT(*) FROM devices", [], |row| row.get(0))
            .unwrap();
        assert_eq!((users, devices), (1, 0));
        fs::remove_dir_all(root).unwrap();
    }

    /// Stage 1 R-c: the first user's creation record is written in the user's own
    /// transaction; when it cannot be written, no user is created either.
    #[test]
    fn local_first_user_writes_its_creation_record_in_the_same_transaction() {
        let (root, path) = database();
        assert!(matches!(
            create_first_in(&path, "george", false, 9),
            Ok(FirstUser::Created { .. })
        ));
        let connection = Connection::open(&path).unwrap();
        let (ts, subject, detail): (i64, String, String) = connection
            .query_row(
                "SELECT ts, subject, detail FROM lifecycle_events WHERE kind = 'user_created'",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .unwrap();
        let detail: serde_json::Value = serde_json::from_str(&detail).unwrap();
        assert_eq!((ts, subject.as_str()), (9, "george"));
        assert_eq!(detail["via"], "local-first-user");
        assert_eq!(detail["userId"], "george");
        fs::remove_dir_all(&root).unwrap();

        let (root, path) = database();
        Connection::open(&path)
            .unwrap()
            .execute_batch("DROP TABLE lifecycle_events;")
            .unwrap();
        assert!(create_first_in(&path, "george", false, 9).is_err());
        let users: i64 = Connection::open(&path)
            .unwrap()
            .query_row("SELECT COUNT(*) FROM users", [], |row| row.get(0))
            .unwrap();
        assert_eq!(users, 0);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn absent_or_nonempty_local_database_dispatches() {
        let (root, path) = database();
        assert_eq!(
            create_first_in(&path, "first", false, 1).unwrap(),
            FirstUser::Created {
                user_id: "first".to_owned(),
                is_admin: true,
                created_at: 1,
            }
        );
        assert_eq!(
            create_first_in(&path, "second", false, 2),
            Ok(FirstUser::Dispatch)
        );
        assert_eq!(
            create_first_in(&root.join("absent.db"), "remote", false, 3),
            Ok(FirstUser::Dispatch)
        );
        fs::remove_dir_all(root).unwrap();
    }
}

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

const TEST_PARENT_PID: &str = "TIGHTBEAM_RUST_TEST_PARENT_PID";

#[cfg_attr(target_os = "linux", unsafe(link_section = ".init_array"))]
#[cfg_attr(target_os = "macos", unsafe(link_section = "__DATA,__mod_init_func"))]
#[used]
static INSTALL_TEST_ISOLATION: extern "C" fn() = {
    extern "C" fn install() {
        if established_self_reexec_child() {
            return;
        }

        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let root = std::env::temp_dir().join(format!(
            "tightbeam-rust-test-{}-{nonce}",
            std::process::id()
        ));
        let home = root.join("home");
        let base = root.join("base");
        let bin = root.join("tripwire-bin");
        fs::create_dir_all(&home).expect("create isolated Rust test home");
        fs::create_dir_all(&base).expect("create isolated Rust test base");
        fs::create_dir_all(&bin).expect("create Rust test tripwire directory");

        let log = root.join("forbidden-execution");
        let quoted_log = format!("'{}'", log.to_string_lossy().replace('\'', "'\"'\"'"));
        for name in [
            "tightbeam",
            "codex",
            "claude",
            "cursor-agent",
            "opencode",
            "pi",
            "npm",
            "ssh",
        ] {
            let path = bin.join(name);
            fs::write(
                &path,
                format!(
                    "#!/bin/sh\nif [ \"$#\" = 1 ] && [ \"$1\" = --version ]; then printf 'synthetic 1.0\\n'; exit 0; fi\nprintf '%s\\n' '{name}' >> {quoted_log}\nexit 97\n"
                ),
            )
            .expect("write Rust test tripwire");
            fs::set_permissions(&path, fs::Permissions::from_mode(0o755))
                .expect("make Rust test tripwire executable");
        }

        let git_config = home.join(".gitconfig");
        fs::write(
            &git_config,
            "[user]\n\tname = Tightbeam Test\n\temail = test@example.invalid\n",
        )
        .expect("write isolated Rust test git config");

        let inherited_path = std::env::var_os("PATH").unwrap_or_default();
        let mut path = vec![
            bin,
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../priv/harness_cli"),
        ];
        path.extend(std::env::split_paths(&inherited_path));
        let path = std::env::join_paths(path).expect("compose isolated Rust test PATH");

        let inherited: Vec<String> = std::env::vars().map(|(name, _)| name).collect();
        for name in inherited {
            if name.starts_with("TIGHTBEAM_")
                || name.starts_with("RELEASE_")
                || name.ends_with("_API_KEY")
                || name.ends_with("_OAUTH_TOKEN")
                || name.ends_with("_CREDENTIALS")
                || name.ends_with("_TOKEN")
                || [
                    "AWS_ACCESS_KEY_ID",
                    "AWS_SECRET_ACCESS_KEY",
                    "GIT_ASKPASS",
                    "SSH_ASKPASS",
                    "SSH_AUTH_SOCK",
                ]
                .contains(&name.as_str())
            {
                unsafe { std::env::remove_var(name) };
            }
        }

        unsafe {
            std::env::set_var("HOME", &home);
            std::env::set_var("XDG_CONFIG_HOME", home.join(".config"));
            std::env::set_var("CODEX_HOME", home.join(".codex"));
            std::env::set_var("GIT_CONFIG_GLOBAL", git_config);
            std::env::set_var("TMPDIR", &root);
            std::env::set_var("TMP", &root);
            std::env::set_var("TEMP", &root);
            std::env::set_var("TIGHTBEAM_TEST_ROOT", &root);
            std::env::set_var("TIGHTBEAM_BASE_DIR", &base);
            std::env::set_var("TIGHTBEAM_HOME", &base);
            std::env::set_var("TIGHTBEAM_TEST_TRIPWIRE_LOG", &log);
            std::env::set_var(TEST_PARENT_PID, std::process::id().to_string());
            std::env::set_var("PATH", path);
            libc::atexit(assert_tripwire_clean);
        }
    }

    install
};

fn established_self_reexec_child() -> bool {
    // A direct child running one of the test binary's exact, established re-exec
    // protocols keeps its parent's already-scrubbed environment and test root.
    // Every other invocation must install fresh isolation, including ordinary
    // descendants that happen to execute the same test binary.
    let parent_matches = std::env::var(TEST_PARENT_PID)
        .ok()
        .and_then(|value| value.parse::<u32>().ok())
        == Some(unsafe { libc::getppid() } as u32);
    if !parent_matches {
        return false;
    }

    let args: Vec<_> = std::env::args_os().collect();
    let Some(exact) = args
        .windows(2)
        .find(|pair| pair[0] == "--exact")
        .and_then(|pair| pair[1].to_str())
    else {
        return false;
    };

    if let Some(test) = exact.strip_prefix("child_process::tests::") {
        let control = format!("TIGHTBEAM_ISOLATED_{}", test.to_ascii_uppercase());
        return std::env::var_os(control).as_deref() == Some(std::ffi::OsStr::new("1"));
    }

    match exact {
        "transport_receipt::tests::independent_processes_share_nonwaiting_lock_and_rotation" => {
            std::env::var_os("TIGHTBEAM_RECEIPT_TEST_BASE").is_some()
                && std::env::var_os("TIGHTBEAM_RECEIPT_TEST_MODE").is_some()
        }
        "ceremonies::tests::term_during_codex_onboarding_cancels_its_exact_lease_and_keeps_the_interrupt" => {
            [
                "TIGHTBEAM_CODEX_SIGNAL_INNER",
                "TIGHTBEAM_CODEX_SIGNAL_MARKER",
                "TIGHTBEAM_CODEX_SIGNAL_STAGING",
                "TIGHTBEAM_CODEX_SIGNAL_CANCEL",
            ]
            .iter()
            .all(|name| std::env::var_os(name).is_some())
                && std::env::var_os("TIGHTBEAM_CODEX_SIGNAL_INNER").as_deref()
                    == Some(std::ffi::OsStr::new("1"))
                && std::env::var_os("TIGHTBEAM_MACHINE").as_deref()
                    == Some(std::ffi::OsStr::new("signal-fixture-host"))
        }
        "ceremonies::tests::an_inherited_sigchld_ignore_keeps_timeout_group_identity_reserved" => {
            std::env::var_os("TIGHTBEAM_SIGCHLD_CEREMONY_INNER").as_deref()
                == Some(std::ffi::OsStr::new("1"))
                && std::env::var_os("TIGHTBEAM_SIGCHLD_CEREMONY_DIR").is_some()
        }
        _ => false,
    }
}

extern "C" fn assert_tripwire_clean() {
    let Some(log) = std::env::var_os("TIGHTBEAM_TEST_TRIPWIRE_LOG").map(PathBuf::from) else {
        return;
    };

    if log.exists() {
        eprintln!("test isolation refused a forbidden executable");
        unsafe { libc::_exit(101) };
    }

    if let Some(root) = log.parent() {
        let _ = fs::remove_dir_all(root);
    }
}

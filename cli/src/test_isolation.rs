use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

#[cfg_attr(target_os = "linux", unsafe(link_section = ".init_array"))]
#[cfg_attr(target_os = "macos", unsafe(link_section = "__DATA,__mod_init_func"))]
#[used]
static INSTALL_TEST_ISOLATION: extern "C" fn() = {
    extern "C" fn install() {
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
                    "#!/bin/sh\nif [ \"$#\" = 1 ] && [ \"$1\" = --version ]; then printf 'synthetic 1.0\\n'; exit 0; fi\nprintf '%s\\n' '{name}' >> \"$TIGHTBEAM_TEST_TRIPWIRE_LOG\"\nexit 97\n"
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
            std::env::set_var("PATH", path);
            libc::atexit(assert_tripwire_clean);
        }
    }

    install
};

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

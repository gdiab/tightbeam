//! F1 (wi_34a7be66) L1b: every process launch and every ambient gateway
//! discovery in Rust test code goes through `test_isolation`, or is on the
//! reviewed allowlist `tests/fixtures/launch_allowlist.txt`. The lint fails on
//! anything else and on allowlist entries that no longer match code.
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

const ALLOWLIST: &str = "tests/fixtures/launch_allowlist.txt";

/// Calls that strip what `test_isolation::command` set: the sandbox HOME,
/// the toolbox PATH and the marker.
const UNDO: &[&str] = &[
    ".env_clear()",
    ".env_remove(\"HOME\")",
    ".env_remove(\"PATH\")",
];

/// A source line is a launch site when it constructs a process (any
/// `…Command::new(`, including aliases), overrides a working directory,
/// strips the environment, or resolves the gateway from the ambient
/// environment.
fn launch_patterns(line: &str) -> bool {
    let code = line.split("//").next().unwrap_or("");
    code.contains("Command::new(")
        || code.contains(".current_dir(")
        || UNDO.iter().any(|undo| code.contains(undo))
        || code.contains("discover()")
        || code.contains("dispatch::run(")
}

/// Files that `src` declares as whole test modules: `#[cfg(test)]`, optionally
/// `#[path = "…"]`, then `mod name;`. Resolved as rustc does for a module
/// declared outside an inline block.
fn test_module_files(file: &Path, source: &str) -> Vec<PathBuf> {
    let dir = file.parent().unwrap();
    let stem = file.file_stem().unwrap().to_string_lossy().into_owned();
    let own_dir = if ["main", "lib", "mod"].contains(&stem.as_str()) {
        dir.to_path_buf()
    } else {
        dir.join(&stem)
    };
    let mut files = Vec::new();
    let mut search = 0;
    while let Some(found) = source[search..].find("#[cfg(test)]") {
        let start = search + found + "#[cfg(test)]".len();
        search = start;
        let rest = &source[start..];
        let end = match (rest.find(';'), rest.find('{')) {
            (Some(semi), Some(brace)) if brace < semi => continue,
            (Some(semi), _) => semi,
            _ => continue,
        };
        let header = &rest[..end];
        let Some(name) = header
            .split_whitespace()
            .skip_while(|word| *word != "mod")
            .nth(1)
        else {
            continue;
        };
        if let Some(path) = header
            .split("#[path = \"")
            .nth(1)
            .and_then(|tail| tail.split('"').next())
        {
            files.push(dir.join(path));
        } else {
            let flat = own_dir.join(format!("{name}.rs"));
            files.push(if flat.exists() {
                flat
            } else {
                own_dir.join(name).join("mod.rs")
            });
        }
    }
    files
}

/// Byte ranges of `#[cfg(test)] mod … { … }` blocks.
fn test_regions(source: &str) -> Vec<(usize, usize)> {
    let mut regions = Vec::new();
    let mut search = 0;
    while let Some(found) = source[search..].find("#[cfg(test)]") {
        let start = search + found;
        let after = &source[start..];
        let Some(brace) = after.find('{') else { break };
        let header = &after[..brace];
        search = start + "#[cfg(test)]".len();
        if !header.contains("mod ") || header.contains(';') {
            continue;
        }
        let open = start + brace;
        let mut depth = 0usize;
        let mut end = open;
        for (offset, ch) in source[open..].char_indices() {
            match ch {
                '{' => depth += 1,
                '}' => {
                    depth -= 1;
                    if depth == 0 {
                        end = open + offset;
                        break;
                    }
                }
                _ => {}
            }
        }
        regions.push((open, end));
        search = end;
    }
    regions
}

/// (relative path, trimmed line) for every launch site in test code.
pub fn launch_sites(root: &Path) -> BTreeSet<(String, String)> {
    let mut sites = BTreeSet::new();
    let mut files = Vec::new();
    collect(&root.join("src"), &mut files);
    collect(&root.join("tests"), &mut files);
    let mut whole_test_files = BTreeSet::new();
    for file in &files {
        let source = std::fs::read_to_string(file).unwrap();
        whole_test_files.extend(test_module_files(file, &source));
    }

    for file in files {
        let relative = file
            .strip_prefix(root)
            .unwrap()
            .to_string_lossy()
            .into_owned();
        if relative == "src/test_isolation.rs" || relative == "tests/launch_isolation_lint.rs" {
            continue;
        }
        let source = std::fs::read_to_string(&file).unwrap();
        let regions: Vec<(usize, usize)> =
            if relative.starts_with("tests/") || whole_test_files.contains(&file) {
                vec![(0, source.len())]
            } else {
                test_regions(&source)
            };
        let mut offset = 0;
        for line in source.split_inclusive('\n') {
            let inside = regions.iter().any(|(a, b)| offset >= *a && offset < *b);
            if inside && launch_patterns(line) {
                sites.insert((relative.clone(), line.trim().to_owned()));
            }
            offset += line.len();
        }
    }
    sites
}

fn collect(dir: &Path, files: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            collect(&path, files);
        } else if path.extension().is_some_and(|ext| ext == "rs") {
            files.push(path);
        }
    }
}

/// Statements that build a child through `test_isolation::command` or
/// `command_in` and then strip its environment. These can never be allowlisted.
pub fn undone_isolation(root: &Path) -> Vec<String> {
    let mut files = Vec::new();
    collect(&root.join("src"), &mut files);
    collect(&root.join("tests"), &mut files);
    let mut found = Vec::new();
    for file in files {
        let relative = file
            .strip_prefix(root)
            .unwrap()
            .to_string_lossy()
            .into_owned();
        if relative == "tests/launch_isolation_lint.rs" {
            continue;
        }
        let source = std::fs::read_to_string(&file).unwrap();
        let mut search = 0;
        while let Some(at) = source[search..].find("test_isolation::command") {
            let start = search + at;
            let end = source[start..]
                .find(';')
                .map_or(source.len(), |semi| start + semi);
            let statement = &source[start..end];
            for undo in UNDO {
                if statement.contains(undo) {
                    let line = source[..start].matches('\n').count() + 1;
                    found.push(format!(
                        "{relative}:{line}: {undo} after test_isolation::command"
                    ));
                }
            }
            search = end.max(start + 1);
        }
    }
    found
}

/// Allowlist entries: `path | exact trimmed source line | reason | reviewer`.
/// Whether a reviewer field names a reviewing session and its verdict.
pub fn reviewed(reviewer: &str) -> bool {
    let token = |prefix: &str, min: usize, exact: bool| {
        reviewer.match_indices(prefix).any(|(at, _)| {
            let before_ok = reviewer[..at]
                .chars()
                .last()
                .map_or(true, |c| !c.is_ascii_alphanumeric() && c != '_');
            let hex: String = reviewer[at + prefix.len()..]
                .chars()
                .take_while(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
                .collect();
            before_ok && hex.len() >= min && (!exact || hex.len() == min)
        })
    };
    token("s_", 8, true) && token("att_", 8, false) && !reviewer.to_lowercase().contains("pending")
}

fn allowlist(root: &Path) -> BTreeSet<(String, String)> {
    std::fs::read_to_string(root.join(ALLOWLIST))
        .unwrap_or_default()
        .lines()
        .filter(|line| !line.trim().is_empty() && !line.starts_with('#'))
        .map(|line| {
            let fields: Vec<&str> = line.split(" | ").collect();
            assert!(
                fields.len() == 4 && fields.iter().all(|f| !f.trim().is_empty()),
                "malformed allowlist entry (path | line | reason | reviewer): {line}"
            );
            // The reviewer names the reviewing session (s_ and 8 hex digits)
            // and its verdict attest (att_ and at least 8 hex digits); an entry
            // still awaiting review, or an unattributable claim, is not reviewed.
            assert!(
                reviewed(fields[3]),
                "allowlist entry not attributably reviewed: {line}"
            );
            (fields[0].trim().to_owned(), fields[1].trim().to_owned())
        })
        .collect()
}

#[test]
fn every_rust_test_launch_is_isolated_or_reviewed() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let sites = launch_sites(root);
    let allowed = allowlist(root);

    let unlisted: Vec<_> = sites.difference(&allowed).collect();
    assert!(
        unlisted.is_empty(),
        "launches outside test_isolation and not on {ALLOWLIST}:\n{}",
        unlisted
            .iter()
            .map(|(file, line)| format!("  {file}: {line}"))
            .collect::<Vec<_>>()
            .join("\n")
    );

    let stale: Vec<_> = allowed.difference(&sites).collect();
    assert!(
        stale.is_empty(),
        "stale {ALLOWLIST} entries that match no code:\n{}",
        stale
            .iter()
            .map(|(file, line)| format!("  {file}: {line}"))
            .collect::<Vec<_>>()
            .join("\n")
    );
}

#[test]
fn no_test_strips_the_isolated_environment() {
    let found = undone_isolation(Path::new(env!("CARGO_MANIFEST_DIR")));
    assert!(found.is_empty(), "{}", found.join("\n"));
}

#[test]
fn the_lint_catches_a_raw_cli_launch() {
    let root = std::env::temp_dir().join(format!("launch-lint-fixture-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(root.join("tests")).unwrap();
    std::fs::create_dir_all(root.join("src")).unwrap();
    std::fs::write(
        root.join("tests/leak.rs"),
        "fn leak() { std::process::Command::new(env!(\"CARGO_BIN_EXE_tightbeam\")).arg(\"list\"); }\n",
    )
    .unwrap();
    std::fs::write(
        root.join("src/unit.rs"),
        "fn product() { let _ = Command::new(\"sh\"); }\n\
         #[cfg(test)]\nmod tests {\n    fn t() { let _ = ProcessCommand::new(\"sh\").current_dir(\"/\"); }\n}\n",
    )
    .unwrap();

    std::fs::create_dir_all(root.join("src/parent")).unwrap();
    std::fs::write(
        root.join("src/parent.rs"),
        "#[cfg(test)]\nmod file_tests;\n#[cfg(test)]\n#[path = \"other_tests.rs\"]\nmod other;\n",
    )
    .unwrap();
    std::fs::write(
        root.join("src/parent/file_tests.rs"),
        "fn t() { let _ = Command::new(std::env::current_exe().unwrap()); }\n",
    )
    .unwrap();
    std::fs::write(
        root.join("src/other_tests.rs"),
        "fn t() { let _ = Command::new(\"sh\"); }\n",
    )
    .unwrap();
    std::fs::write(
        root.join("tests/undo.rs"),
        "fn t() {\n    test_isolation::command_in(CLI, dir)\n        .arg(\"list\")\n        .env_clear()\n        .spawn();\n}\n",
    )
    .unwrap();

    let sites = launch_sites(&root);
    assert!(
        sites
            .iter()
            .any(|(file, line)| file == "src/parent/file_tests.rs" && line.contains("current_exe")),
        "a file-level #[cfg(test)] mod is a test region"
    );
    assert!(
        sites
            .iter()
            .any(|(file, line)| file == "src/other_tests.rs" && line.contains("Command::new")),
        "a #[path] test module is a test region"
    );
    assert!(sites.contains(&("tests/undo.rs".to_owned(), ".env_clear()".to_owned())));
    assert_eq!(
        undone_isolation(&root),
        vec!["tests/undo.rs:2: .env_clear() after test_isolation::command".to_owned()]
    );
    assert!(sites.contains(&(
        "tests/leak.rs".to_owned(),
        "fn leak() { std::process::Command::new(env!(\"CARGO_BIN_EXE_tightbeam\")).arg(\"list\"); }"
            .to_owned()
    )));
    assert!(
        sites
            .iter()
            .any(|(file, line)| file == "src/unit.rs" && line.contains("ProcessCommand::new"))
    );
    assert!(
        !sites
            .iter()
            .any(|(file, line)| file == "src/unit.rs" && line.contains("fn product")),
        "production code outside #[cfg(test)] is not a test launch"
    );
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn an_allowlist_reviewer_must_name_a_session_and_its_verdict() {
    for bad in [
        "fixture",
        "checked in this subject's code review",
        "s_0123abcd",
        "att_0123abcd",
        "xs_0123abcd att_0123abcd",
        "s_0123abcde att_0123abcd",
        "s_0123abcd (pending) att_0123abcd",
    ] {
        assert!(!reviewed(bad), "{bad}");
    }
    assert!(reviewed(
        "s_ccb14ac2 (F1 code review asg_fcccc59a, verdict att_b15f3a6f-6bec-4793-945e-54a7f2347ab0)"
    ));
}

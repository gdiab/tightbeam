//! F1 (wi_34a7be66) L1b: every process launch and every ambient gateway
//! discovery in Rust test code goes through `test_isolation`, or is on the
//! reviewed allowlist `tests/fixtures/launch_allowlist.txt`. The lint fails on
//! anything else and on allowlist entries that no longer match code.
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

const ALLOWLIST: &str = "tests/fixtures/launch_allowlist.txt";

/// A source line is a launch site when it constructs a process (any
/// `…Command::new(`, including aliases), overrides a working directory, or
/// resolves the gateway from the ambient environment.
fn launch_patterns(line: &str) -> bool {
    let code = line.split("//").next().unwrap_or("");
    code.contains("Command::new(")
        || code.contains(".current_dir(")
        || code.contains("discover()")
        || code.contains("dispatch::run(")
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
        let regions: Vec<(usize, usize)> = if relative.starts_with("tests/") {
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

/// Allowlist entries: `path | exact trimmed source line | reason | reviewer`.
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

    let sites = launch_sites(&root);
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

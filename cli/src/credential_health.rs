use std::cell::Cell;
use std::fs;
use std::io::{Read, Write};
use std::net::{IpAddr, Ipv6Addr};
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::time::{Duration, Instant};

use serde_json::{Value, json};
use sha2::{Digest, Sha256};

const USAGE: &str = "usage: tightbeam credential-health [--expect-instance <id>]";
const BODY_LIMIT: u64 = 4_096;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum EndpointSource {
    Env,
    Config,
    Default,
}

impl EndpointSource {
    fn wire_name(self) -> &'static str {
        match self {
            Self::Env => "env",
            Self::Config => "config",
            Self::Default => "default",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct ResolvedEndpoint {
    base: String,
    host: String,
    port: u16,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct Discovery {
    endpoint: Option<ResolvedEndpoint>,
    source: EndpointSource,
    token: Option<String>,
    implicit_instance: Option<String>,
}

#[derive(Debug)]
struct ServerResponse {
    result: String,
    instance: Value,
    version: String,
}

pub fn run(args: &[String]) -> i32 {
    #[allow(deprecated)]
    let home = std::env::home_dir().unwrap_or_default();
    let cwd = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
    run_with(
        args,
        |name| std::env::var(name).ok(),
        &cwd,
        &home,
        exchange,
        &mut std::io::stdout(),
        &mut std::io::stderr(),
    )
}

/// The whole command over an injected environment, directories, exchange and output
/// streams: the seam the F2-7 tests drive (wi_34a7be66). `exchange` is called at most
/// once, only when discovery found an endpoint.
fn run_with<F, X>(
    args: &[String],
    get_env: F,
    cwd: &Path,
    home: &Path,
    mut exchange: X,
    stdout: &mut impl Write,
    stderr: &mut impl Write,
) -> i32
where
    F: Fn(&str) -> Option<String>,
    X: FnMut(ResolvedEndpoint, Option<String>) -> Option<ServerResponse>,
{
    let expect_instance = match parse_args(args) {
        Ok(expect_instance) => expect_instance,
        Err(()) => {
            writeln!(stderr, "{USAGE}").expect("failed printing to stderr");
            return 2;
        }
    };

    let (discovery, line) = discover_with(get_env, cwd, home);
    // F2-7d/F2-7e: at most one fixed line (a refusal or the override notice), before
    // any request. It names variables only.
    if let Some(line) = line {
        writeln!(stderr, "{line}").expect("failed printing to stderr");
    }
    let response = discovery
        .endpoint
        .as_ref()
        .and_then(|endpoint| exchange(endpoint.clone(), discovery.token.clone()));
    let (result, instance, version) = outcome(&discovery, expect_instance.as_deref(), response);

    // As println!/eprintln! did: a failed write to either stream panics.
    writeln!(stdout, "{}", report(&discovery, &result, instance, version))
        .expect("failed printing to stdout");
    exit_status(&result)
}

/// The R10.1 result object: exactly five keys.
fn report(discovery: &Discovery, result: &str, instance: Value, version: Value) -> Value {
    let endpoint = discovery.endpoint.as_ref().map(|endpoint| {
        json!({
            "host": endpoint.host,
            "port": endpoint.port,
        })
    });
    json!({
        "result": result,
        "endpoint": endpoint,
        "endpointSource": discovery.source.wire_name(),
        "instance": instance,
        "version": version,
    })
}

fn exit_status(result: &str) -> i32 {
    if result == "ok" { 0 } else { 1 }
}

fn outcome(
    discovery: &Discovery,
    expect_instance: Option<&str>,
    response: Option<ServerResponse>,
) -> (String, Value, Value) {
    let Some(response) = response else {
        return ("unavailable".to_owned(), Value::Null, Value::Null);
    };
    let ServerResponse {
        result: server_result,
        instance,
        version,
    } = response;
    let mismatch = discovery
        .implicit_instance
        .as_deref()
        .is_some_and(|expected| instance["id"] != expected)
        || expect_instance.is_some_and(|expected| instance["id"] != expected);
    let result = if mismatch {
        "instance_mismatch".to_owned()
    } else {
        server_result
    };
    (result, instance, Value::String(version))
}

fn parse_args(args: &[String]) -> Result<Option<String>, ()> {
    match args {
        [] => Ok(None),
        [flag, value] if flag == "--expect-instance" && !value.is_empty() => {
            Ok(Some(value.clone()))
        }
        _ => Err(()),
    }
}

/// The discovery and the one stderr line, if any, for F2-7c's outcome. Which F2-1 row
/// applies, the agreement rule, refusals (i)-(iii), no fallback and the override all
/// come from `dispatch`'s selection (F2-7a), whose session walk and base carry F1's
/// test-root bound; this command only reads the source chosen, under its own contract
/// (F2-7b). Its output is decided by the kind of outcome: no selection error text,
/// which may carry a path, reaches it (F2-7e).
fn discover_with<F>(get_env: F, cwd: &Path, home: &Path) -> (Discovery, Option<String>)
where
    F: Fn(&str) -> Option<String>,
{
    use crate::dispatch::Selection;

    match crate::dispatch::select(&get_env, cwd, home) {
        Selection::ExplicitPair {
            url,
            token,
            overridden,
        } => (
            discovery_from_url(&url, Some(token), EndpointSource::Env, None),
            overridden.map(|overridden| overridden.notice_without_path()),
        ),
        // No fallback: a base whose gateway.json is missing or unusable is
        // `unavailable`, with no notice.
        Selection::ExplicitBase {
            base_dir,
            overridden,
        } => match usable_gateway_discovery(&base_dir, EndpointSource::Env) {
            Some(discovery) => (
                discovery,
                overridden.map(|overridden| overridden.notice_without_path()),
            ),
            None => (unavailable(EndpointSource::Env), None),
        },
        Selection::Refused(incomplete) => (
            unavailable(EndpointSource::Env),
            Some(incomplete.line().to_owned()),
        ),
        Selection::Session { read, .. } => match read {
            Ok(pair) => (
                discovery_from_url(&pair.url, Some(pair.token), EndpointSource::Config, None),
                None,
            ),
            Err(_) => (unavailable(EndpointSource::Config), None),
        },
        Selection::Fallthrough => {
            let (base_dir, source) = resolve_gateway_base(&get_env, home);
            (gateway_discovery(&base_dir, source), None)
        }
    }
}

// Only crate::base_dir reads the base-dir variables. Under its current contract it
// selects from the environment exactly when a variable it consults is present, so the
// source class is observed from its own lookups rather than decided by a second
// reading here.
fn resolve_gateway_base<F>(get_env: &F, home: &Path) -> (PathBuf, EndpointSource)
where
    F: Fn(&str) -> Option<String>,
{
    let selected_from_env = Cell::new(false);
    let base_dir = crate::base_dir::resolve_with(
        &|name: &str| {
            let value = get_env(name);
            if value.is_some() && matches!(name, "TIGHTBEAM_BASE_DIR" | "TIGHTBEAM_HOME") {
                selected_from_env.set(true);
            }
            value
        },
        home,
    );
    let source = if selected_from_env.get() {
        EndpointSource::Env
    } else {
        EndpointSource::Default
    };
    (base_dir, source)
}

fn gateway_discovery(base_dir: &Path, source: EndpointSource) -> Discovery {
    usable_gateway_discovery(base_dir, source).unwrap_or_else(|| unavailable(source))
}

/// The base's `gateway.json` as this command reads it, or `None` when it is missing,
/// unreadable, malformed or without a usable `url` or port (F2-7c's no-request row).
/// A `url` that is not loopback is still usable here: it yields no endpoint (R2.1).
fn usable_gateway_discovery(base_dir: &Path, source: EndpointSource) -> Option<Discovery> {
    let config = fs::read_to_string(base_dir.join("gateway.json"))
        .ok()
        .and_then(|encoded| serde_json::from_str::<Value>(&encoded).ok())?;
    let token = config
        .get("cliToken")
        .and_then(Value::as_str)
        .filter(|token| !token.is_empty())
        .map(str::to_owned);

    if let Some(url) = config
        .get("url")
        .and_then(Value::as_str)
        .filter(|url| !url.is_empty())
    {
        return Some(discovery_from_url(url, token, source, None));
    }

    let port = config
        .get("port")
        .and_then(Value::as_u64)
        .and_then(|port| u16::try_from(port).ok())?;
    let canonical = fs::canonicalize(base_dir).ok()?;
    let implicit_instance = instance_id(&canonical)?;
    Some(discovery_from_url(
        &format!("http://127.0.0.1:{port}"),
        token,
        source,
        Some(implicit_instance),
    ))
}

fn discovery_from_url(
    url: &str,
    token: Option<String>,
    source: EndpointSource,
    implicit_instance: Option<String>,
) -> Discovery {
    Discovery {
        endpoint: parse_loopback_endpoint(url),
        source,
        token,
        implicit_instance,
    }
}

fn unavailable(source: EndpointSource) -> Discovery {
    Discovery {
        endpoint: None,
        source,
        token: None,
        implicit_instance: None,
    }
}

fn parse_loopback_endpoint(url: &str) -> Option<ResolvedEndpoint> {
    let (scheme, rest) = url.split_once("://")?;
    let scheme = match scheme {
        "http" | "ws" => "http",
        "https" | "wss" => "https",
        _ => return None,
    };
    let authority_end = rest
        .find(|character| matches!(character, '/' | '?' | '#'))
        .unwrap_or(rest.len());
    let authority = &rest[..authority_end];
    let host_port = authority
        .rsplit_once('@')
        .map_or(authority, |(_, tail)| tail);
    let default_port = if scheme == "https" { 443 } else { 80 };

    let (host, port) = if let Some(bracketed) = host_port.strip_prefix('[') {
        let close = bracketed.find(']')?;
        let host = &bracketed[..close];
        let suffix = &bracketed[close + 1..];
        let port = match suffix.strip_prefix(':') {
            Some(port) => port.parse::<u16>().ok()?,
            None if suffix.is_empty() => default_port,
            None => return None,
        };
        (host, port)
    } else {
        match host_port.rsplit_once(':') {
            Some((host, port)) if !host.contains(':') => (host, port.parse::<u16>().ok()?),
            _ => (host_port, default_port),
        }
    };

    let ip = IpAddr::from_str(host).ok()?;
    let loopback = match ip {
        IpAddr::V4(address) => address.is_loopback(),
        IpAddr::V6(address) => address == Ipv6Addr::LOCALHOST,
    };
    if !loopback {
        return None;
    }
    let host = ip.to_string();
    let authority = match ip {
        IpAddr::V4(_) => format!("{host}:{port}"),
        IpAddr::V6(_) => format!("[{host}]:{port}"),
    };
    Some(ResolvedEndpoint {
        base: format!("{scheme}://{authority}"),
        host,
        port,
    })
}

fn exchange(endpoint: ResolvedEndpoint, token: Option<String>) -> Option<ServerResponse> {
    let deadline = Instant::now() + Duration::from_secs(10);
    crate::lease::until(deadline, move |remaining| {
        exchange_with_timeout(&endpoint, token.as_deref(), remaining)
    })
    .ok()
    .flatten()
}

fn exchange_with_timeout(
    endpoint: &ResolvedEndpoint,
    token: Option<&str>,
    timeout: Duration,
) -> Option<ServerResponse> {
    let agent = ureq::AgentBuilder::new()
        .redirects(0)
        .timeout_connect(timeout)
        .timeout_read(timeout)
        .build();
    let url = format!("{}/agent/credential-health", endpoint.base);
    let request = agent.get(&url);
    let request = match token {
        Some(token) => request.set("authorization", &format!("Bearer {token}")),
        None => request,
    };
    let response = request.call().ok()?;
    if response.status() != 200 {
        return None;
    }
    let mut encoded = String::new();
    response
        .into_reader()
        .take(BODY_LIMIT + 1)
        .read_to_string(&mut encoded)
        .ok()?;
    if encoded.len() as u64 > BODY_LIMIT {
        return None;
    }
    validate_response(&encoded)
}

fn validate_response(encoded: &str) -> Option<ServerResponse> {
    let (mut top_keys, mut instance_keys) = strict_object_keys(encoded)?;
    top_keys.sort_unstable();
    instance_keys.sort_unstable();
    if top_keys != ["instance", "result", "schemaVersion", "version"]
        || instance_keys != ["host", "id"]
    {
        return None;
    }
    let body: Value = serde_json::from_str(encoded).ok()?;
    let object = body.as_object()?;
    if object.len() != 4
        || !object.contains_key("schemaVersion")
        || !object.contains_key("result")
        || !object.contains_key("instance")
        || !object.contains_key("version")
        || object["schemaVersion"].as_u64() != Some(1)
    {
        return None;
    }
    let result = object["result"].as_str()?;
    if !matches!(result, "ok" | "auth_failed" | "revoked") {
        return None;
    }
    let instance = object["instance"].as_object()?;
    if instance.len() != 2 || !instance.contains_key("id") || !instance.contains_key("host") {
        return None;
    }
    let id = instance["id"].as_str()?;
    if id.len() != 64
        || !id
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return None;
    }
    let host = instance["host"].as_str()?;
    let version = object["version"].as_str()?;
    if !printable_ascii(host, 255) || !printable_ascii(version, 64) {
        return None;
    }
    Some(ServerResponse {
        result: result.to_owned(),
        instance: object["instance"].clone(),
        version: version.to_owned(),
    })
}

fn strict_object_keys(encoded: &str) -> Option<(Vec<&str>, Vec<&str>)> {
    let bytes = encoded.as_bytes();
    let mut depth = 0usize;
    let mut index = 0usize;
    let mut top = Vec::new();
    let mut nested = Vec::new();

    while index < bytes.len() {
        match bytes[index] {
            b'{' => {
                depth += 1;
                index += 1;
            }
            b'}' => {
                depth = depth.checked_sub(1)?;
                index += 1;
            }
            b'"' => {
                let start = index + 1;
                index += 1;
                let mut escaped = false;
                while index < bytes.len() && bytes[index] != b'"' {
                    if bytes[index] == b'\\' {
                        escaped = true;
                        index += 1;
                        if index >= bytes.len() {
                            return None;
                        }
                    }
                    index += 1;
                }
                if index >= bytes.len() {
                    return None;
                }
                let end = index;
                index += 1;
                let mut next = index;
                while next < bytes.len() && bytes[next].is_ascii_whitespace() {
                    next += 1;
                }
                if next < bytes.len() && bytes[next] == b':' {
                    if escaped {
                        return None;
                    }
                    let key = &encoded[start..end];
                    match depth {
                        1 => top.push(key),
                        2 => nested.push(key),
                        _ => return None,
                    }
                }
            }
            _ => index += 1,
        }
    }

    (depth == 0).then_some((top, nested))
}

fn printable_ascii(value: &str, max: usize) -> bool {
    !value.is_empty()
        && value.len() <= max
        && value.bytes().all(|byte| (0x20..=0x7e).contains(&byte))
}

fn instance_id(base_dir: &Path) -> Option<String> {
    let mut digest = Sha256::new();
    digest.update(b"tightbeam-instance-v1\n");
    digest.update(base_dir.to_str()?.as_bytes());
    Some(format!("{:x}", digest.finalize()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    #[test]
    fn only_the_bound_argument_shape_is_accepted() {
        assert_eq!(parse_args(&[]), Ok(None));
        assert_eq!(
            parse_args(&["--expect-instance".to_owned(), "expected".to_owned()]),
            Ok(Some("expected".to_owned()))
        );
        assert_eq!(parse_args(&["token".to_owned()]), Err(()));
        assert_eq!(parse_args(&["--expect-instance".to_owned()]), Err(()));
    }

    #[test]
    fn endpoint_parser_accepts_only_loopback_literals_and_strips_every_other_part() {
        assert_eq!(
            parse_loopback_endpoint("http://user:secret@127.0.0.2:11400/private?q=x#f"),
            Some(ResolvedEndpoint {
                base: "http://127.0.0.2:11400".to_owned(),
                host: "127.0.0.2".to_owned(),
                port: 11400,
            })
        );
        assert_eq!(
            parse_loopback_endpoint("wss://[::1]/ws"),
            Some(ResolvedEndpoint {
                base: "https://[::1]:443".to_owned(),
                host: "::1".to_owned(),
                port: 443,
            })
        );
        for refused in [
            "http://localhost:11400",
            "http://10.0.0.1:11400",
            "http://gateway-host.local:11400",
        ] {
            assert_eq!(parse_loopback_endpoint(refused), None);
        }
    }

    // M11 (F2 v6 §5): the pre-F2 tests `discovery_order_and_source_classes_match_the_
    // standard_client` (a session beat an explicit pair) and `malformed_nearest_session_
    // file_stops_discovery_without_env_fallback` (a malformed session beat an explicit
    // pair) asserted the order F2-7a removes. H1/H2 and H10a/H10b below replace them.

    #[test]
    fn gateway_host_discovery_binds_the_canonical_base_without_disclosing_it() {
        let root = std::env::temp_dir().join(format!(
            "tightbeam-credential-health-gateway-{}",
            std::process::id()
        ));
        fs::create_dir_all(&root).unwrap();
        fs::write(
            root.join("gateway.json"),
            r#"{"port":11400,"cliToken":"organization-token"}"#,
        )
        .unwrap();

        let (discovery, stderr) = discover_with(
            |name| (name == "TIGHTBEAM_BASE_DIR").then(|| root.display().to_string()),
            &root,
            &root,
        );
        assert_eq!(stderr, None);
        assert_eq!(discovery.source, EndpointSource::Env);
        assert_eq!(discovery.endpoint.unwrap().host, "127.0.0.1");
        assert_eq!(discovery.token.as_deref(), Some("organization-token"));
        assert_eq!(
            discovery.implicit_instance,
            instance_id(&fs::canonicalize(&root).unwrap())
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn the_canonical_resolver_picks_the_gateway_and_its_choice_is_the_source_class() {
        let root = std::env::temp_dir().join(format!(
            "tightbeam-credential-health-precedence-{}",
            std::process::id()
        ));
        let base = root.join("base");
        let home_var = root.join("home-var");
        fs::create_dir_all(&base).unwrap();
        fs::create_dir_all(&home_var).unwrap();
        fs::write(
            base.join("gateway.json"),
            r#"{"port":11401,"cliToken":"base-token"}"#,
        )
        .unwrap();
        fs::write(
            home_var.join("gateway.json"),
            r#"{"port":11402,"cliToken":"home-token"}"#,
        )
        .unwrap();

        // These call the resolution seam and then gateway discovery on the directory it
        // chose, so only fixture-owned gateway files are read: no session-file walk up
        // from a working directory, and no relative path.

        // Both set: the base-dir variable wins, as crate::base_dir orders them.
        let both = HashMap::from([
            ("TIGHTBEAM_BASE_DIR", base.display().to_string()),
            ("TIGHTBEAM_HOME", home_var.display().to_string()),
        ]);
        let env = |name: &str| both.get(name).cloned();
        let (base_dir, source) = resolve_gateway_base(&env, &root);
        assert_eq!(base_dir, base);
        assert_eq!(source, EndpointSource::Env);
        let discovery = gateway_discovery(&base_dir, source);
        assert_eq!(discovery.source, EndpointSource::Env);
        assert_eq!(discovery.endpoint.unwrap().port, 11401);
        assert_eq!(discovery.token.as_deref(), Some("base-token"));
        assert_eq!(
            discovery.implicit_instance,
            instance_id(&fs::canonicalize(&base).unwrap())
        );

        // Only the home variable: it is the environment selection.
        let home_only = HashMap::from([("TIGHTBEAM_HOME", home_var.display().to_string())]);
        let env = |name: &str| home_only.get(name).cloned();
        let (base_dir, source) = resolve_gateway_base(&env, &root);
        assert_eq!(base_dir, home_var);
        assert_eq!(source, EndpointSource::Env);
        let discovery = gateway_discovery(&base_dir, source);
        assert_eq!(discovery.source, EndpointSource::Env);
        assert_eq!(discovery.endpoint.unwrap().port, 11402);
        assert_eq!(discovery.token.as_deref(), Some("home-token"));
        assert_eq!(
            discovery.implicit_instance,
            instance_id(&fs::canonicalize(&home_var).unwrap())
        );

        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn without_either_variable_the_default_directory_is_used_and_reported() {
        let root = std::env::temp_dir().join(format!(
            "tightbeam-credential-health-default-{}",
            std::process::id()
        ));
        let default_dir = root.join(".tightbeam");
        fs::create_dir_all(&default_dir).unwrap();
        fs::write(
            default_dir.join("gateway.json"),
            r#"{"port":11403,"cliToken":"default-token"}"#,
        )
        .unwrap();

        let env = |_: &str| None::<String>;
        let (base_dir, source) = resolve_gateway_base(&env, &root);
        assert_eq!(base_dir, default_dir);
        assert_eq!(source, EndpointSource::Default);
        let discovery = gateway_discovery(&base_dir, source);
        assert_eq!(discovery.source, EndpointSource::Default);
        assert_eq!(discovery.endpoint.unwrap().port, 11403);
        assert_eq!(discovery.token.as_deref(), Some("default-token"));
        assert_eq!(
            discovery.implicit_instance,
            instance_id(&fs::canonicalize(&default_dir).unwrap())
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn test_root_bounds_the_default_without_changing_its_source_class() {
        let unique = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!("tightbeam_credential_root_{unique}"));
        let home = root.join("home");
        let default = home.join(".tightbeam");
        fs::create_dir_all(&default).unwrap();
        let env = |name: &str| match name {
            "TIGHTBEAM_TEST_ROOT" => Some(root.display().to_string()),
            _ => None,
        };

        let (base_dir, source) = resolve_gateway_base(&env, &home);
        assert_eq!(base_dir, default);
        assert_eq!(source, EndpointSource::Default);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn a_set_but_empty_variable_is_still_the_environment_selection() {
        // crate::base_dir lets a set-but-empty variable win and resolves it to an empty
        // path, so the selection came from the environment. Only the seam is exercised:
        // discovery on an empty path would read relative to the working directory.
        let env = |name: &str| match name {
            "TIGHTBEAM_BASE_DIR" => Some(String::new()),
            "TIGHTBEAM_HOME" => Some("/fixture-home-var".to_owned()),
            _ => None,
        };
        let (base_dir, source) = resolve_gateway_base(&env, Path::new("/fixture-home"));
        assert_eq!(base_dir, PathBuf::new());
        assert_eq!(source, EndpointSource::Env);
    }

    #[test]
    fn session_token_must_be_a_string_and_preserves_the_existing_empty_string() {
        let root = std::env::temp_dir().join(format!(
            "tightbeam-credential-health-session-token-{}",
            std::process::id()
        ));
        let work = root.join("work");
        fs::create_dir_all(&work).unwrap();

        for encoded in [
            r#"{"url":"http://127.0.0.1:12000"}"#,
            r#"{"url":"http://127.0.0.1:12000","token":7}"#,
        ] {
            fs::write(root.join(".tightbeam-session"), encoded).unwrap();
            let (discovery, stderr) = discover_with(|_| None, &work, &root);
            assert_eq!(stderr, None);
            assert_eq!(discovery.source, EndpointSource::Config);
            assert_eq!(discovery.endpoint, None);
            assert_eq!(discovery.token, None);
        }

        fs::write(
            root.join(".tightbeam-session"),
            r#"{"url":"http://127.0.0.1:12000","token":""}"#,
        )
        .unwrap();
        let (discovery, _) = discover_with(|_| None, &work, &root);
        assert_eq!(discovery.endpoint.unwrap().port, 12000);
        assert_eq!(discovery.token.as_deref(), Some(""));
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn unavailable_wins_and_instance_mismatch_overrides_every_server_class() {
        let id = "a".repeat(64);
        let response = || ServerResponse {
            result: "revoked".to_owned(),
            instance: json!({"id": id.clone(), "host": "testhost"}),
            version: "0.1.16".to_owned(),
        };
        let discovery = Discovery {
            endpoint: parse_loopback_endpoint("http://127.0.0.1:11400"),
            source: EndpointSource::Default,
            token: None,
            implicit_instance: Some("b".repeat(64)),
        };

        assert_eq!(outcome(&discovery, None, None).0, "unavailable");
        assert_eq!(
            outcome(&discovery, None, Some(response())).0,
            "instance_mismatch"
        );
        let explicit = Discovery {
            implicit_instance: None,
            ..discovery
        };
        assert_eq!(
            outcome(&explicit, Some("b"), Some(response())).0,
            "instance_mismatch"
        );
    }

    #[test]
    fn response_validation_rejects_extra_keys_and_noncanonical_fields() {
        let valid = r#"{"schemaVersion":1,"result":"revoked","instance":{"id":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","host":"testhost"},"version":"0.1.16"}"#;
        assert_eq!(validate_response(valid).unwrap().result, "revoked");
        let extra = r#"{"schemaVersion":1,"result":"revoked","instance":{"id":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","host":"testhost"},"version":"0.1.16","extra":1}"#;
        assert!(validate_response(extra).is_none());
        let duplicate = r#"{"schemaVersion":1,"result":"ok","result":"revoked","instance":{"id":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","host":"testhost"},"version":"0.1.16"}"#;
        assert!(validate_response(duplicate).is_none());
        assert!(validate_response(&valid.replace("aaaaaaaa", "AAAAAAAA")).is_none());
        assert!(validate_response(&valid.replace("testhost", "testhost\nsecret")).is_none());
    }

    // F2 v6, F2-7 (wi_34a7be66): credential-health resolves through dispatch's shared
    // selection. Every H case runs the whole command (`run_with`) with a recording
    // exchange and asserts the complete five-key stdout object, the exact stderr lines,
    // the exit status, and the exact requests made (zero or one), with the token sent.

    const ID: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

    fn fixture(label: &str) -> PathBuf {
        let unique = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!("tightbeam-f2-{label}-{unique}"));
        fs::create_dir_all(&root).unwrap();
        fs::canonicalize(root).unwrap()
    }

    fn session_file(dir: &Path, url: &str, token: &str) {
        fs::create_dir_all(dir).unwrap();
        fs::write(
            dir.join(".tightbeam-session"),
            json!({"url": url, "token": token}).to_string(),
        )
        .unwrap();
    }

    fn gateway_json(dir: &Path, contents: &str) {
        fs::create_dir_all(dir).unwrap();
        fs::write(dir.join("gateway.json"), contents).unwrap();
    }

    fn env_of(pairs: Vec<(&'static str, String)>) -> impl Fn(&str) -> Option<String> {
        let map: HashMap<&'static str, String> = pairs.into_iter().collect();
        move |name: &str| map.get(name).cloned()
    }

    /// What one command run observably did.
    #[derive(Debug, PartialEq)]
    struct Run {
        status: i32,
        stdout: Value,
        stderr: Vec<String>,
        /// Each request made: host, port and the bearer token sent.
        requests: Vec<(String, u16, Option<String>)>,
    }

    /// Run the command; every request is recorded and answered `ok` for instance
    /// `answer_id` (an instance the case does or does not expect).
    fn run_command<F>(args: &[&str], get_env: F, cwd: &Path, home: &Path, answer_id: &str) -> Run
    where
        F: Fn(&str) -> Option<String>,
    {
        let args: Vec<String> = args.iter().map(|arg| (*arg).to_owned()).collect();
        let mut requests = Vec::new();
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let status = run_with(
            &args,
            get_env,
            cwd,
            home,
            |endpoint: ResolvedEndpoint, token: Option<String>| {
                requests.push((endpoint.host.clone(), endpoint.port, token));
                Some(ServerResponse {
                    result: "ok".to_owned(),
                    instance: json!({"id": answer_id, "host": "fixture"}),
                    version: "0.1.16".to_owned(),
                })
            },
            &mut stdout,
            &mut stderr,
        );
        let stdout = String::from_utf8(stdout).unwrap();
        let stdout = match stdout.lines().collect::<Vec<_>>()[..] {
            [] => Value::Null,
            [line] => serde_json::from_str(line).unwrap(),
            _ => panic!("more than one stdout line: {stdout}"),
        };
        let stderr = String::from_utf8(stderr)
            .unwrap()
            .lines()
            .map(str::to_owned)
            .collect();
        Run {
            status,
            stdout,
            stderr,
            requests,
        }
    }

    /// The `ok` object for an answered request to `127.0.0.1:port`.
    fn ok(port: u16, source: &str, id: &str) -> Value {
        json!({
            "result": "ok",
            "endpoint": {"host": "127.0.0.1", "port": port},
            "endpointSource": source,
            "instance": {"id": id, "host": "fixture"},
            "version": "0.1.16",
        })
    }

    fn unavailable(source: &str) -> Value {
        json!({
            "result": "unavailable",
            "endpoint": null,
            "endpointSource": source,
            "instance": null,
            "version": null,
        })
    }

    /// One request, to `127.0.0.1:port`, carrying `token`.
    fn one(port: u16, token: &str) -> Vec<(String, u16, Option<String>)> {
        vec![("127.0.0.1".to_owned(), port, Some(token.to_owned()))]
    }

    fn lines(line: &str) -> Vec<String> {
        vec![line.to_owned()]
    }

    const NOTICE_PAIR: &str = "tightbeam: notice: using TIGHTBEAM_URL and TIGHTBEAM_TOKEN (explicit); ignoring the session file";
    const NOTICE_BASE: &str =
        "tightbeam: notice: using TIGHTBEAM_BASE_DIR (explicit); ignoring the session file";

    #[test]
    fn f2_h1_an_explicit_pair_wins_over_a_different_session_with_one_notice() {
        let root = fixture("h1");
        session_file(&root, "http://127.0.0.1:12001", "session-token");
        let work = root.join("a/b");
        fs::create_dir_all(&work).unwrap();
        let env = env_of(vec![
            ("TIGHTBEAM_URL", "http://127.0.0.1:12002".to_owned()),
            ("TIGHTBEAM_TOKEN", "pair-token".to_owned()),
        ]);
        assert_eq!(
            run_command(&[], env, &work, &root, ID),
            Run {
                status: 0,
                stdout: ok(12002, "env", ID),
                stderr: lines(NOTICE_PAIR),
                requests: one(12002, "pair-token"),
            }
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn f2_h2_a_pair_equal_to_the_session_keeps_the_session_silently() {
        let root = fixture("h2");
        session_file(&root, "ws://127.0.0.1:12003/", "same-token");
        let env = env_of(vec![
            ("TIGHTBEAM_URL", "http://127.0.0.1:12003".to_owned()),
            ("TIGHTBEAM_TOKEN", "same-token".to_owned()),
        ]);
        assert_eq!(
            run_command(&[], env, &root, &root, ID),
            Run {
                status: 0,
                stdout: ok(12003, "config", ID),
                stderr: vec![],
                requests: one(12003, "same-token"),
            }
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn f2_h3_an_explicit_base_wins_with_its_implicit_instance_and_a_notice() {
        let root = fixture("h3");
        let work = root.join("tree");
        session_file(&work, "http://127.0.0.1:12004", "session-token");
        let base = root.join("base");
        gateway_json(&base, r#"{"port":12005,"cliToken":"base-token"}"#);
        let implicit = instance_id(&base).unwrap();
        let env = || env_of(vec![("TIGHTBEAM_BASE_DIR", base.display().to_string())]);
        assert_eq!(
            run_command(&[], env(), &work, &root, &implicit),
            Run {
                status: 0,
                stdout: ok(12005, "env", &implicit),
                stderr: lines(NOTICE_BASE),
                requests: one(12005, "base-token"),
            }
        );
        // A foreign instance at that port is a mismatch.
        let foreign = "f".repeat(64);
        let mut mismatch = ok(12005, "env", &foreign);
        mismatch["result"] = json!("instance_mismatch");
        assert_eq!(
            run_command(&[], env(), &work, &root, &foreign),
            Run {
                status: 1,
                stdout: mismatch,
                stderr: lines(NOTICE_BASE),
                requests: one(12005, "base-token"),
            }
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn f2_h4_and_h4b_an_unusable_explicit_base_is_unavailable_without_fallback() {
        // H4b (N3), verbatim: "malformed/port-less gateway.json under an explicit base".
        let root = fixture("h4");
        let work = root.join("tree");
        session_file(&work, "http://127.0.0.1:12006", "session-token");
        for (label, contents) in [
            ("missing", None),
            ("malformed", Some("{")),
            ("portless", Some(r#"{"cliToken":"base-token"}"#)),
        ] {
            let base = root.join(label);
            fs::create_dir_all(&base).unwrap();
            if let Some(contents) = contents {
                gateway_json(&base, contents);
            }
            let env = env_of(vec![("TIGHTBEAM_BASE_DIR", base.display().to_string())]);
            assert_eq!(
                run_command(&[], env, &work, &root, ID),
                Run {
                    status: 1,
                    stdout: unavailable("env"),
                    stderr: vec![],
                    requests: vec![],
                },
                "{label}"
            );
        }
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn f2_h5_the_pair_wins_over_the_base_and_the_session() {
        let root = fixture("h5");
        let work = root.join("tree");
        session_file(&work, "http://127.0.0.1:12007", "session-token");
        let base = root.join("base");
        gateway_json(&base, r#"{"port":12008,"cliToken":"base-token"}"#);
        let env = env_of(vec![
            ("TIGHTBEAM_URL", "http://127.0.0.1:12009".to_owned()),
            ("TIGHTBEAM_TOKEN", "pair-token".to_owned()),
            ("TIGHTBEAM_BASE_DIR", base.display().to_string()),
        ]);
        assert_eq!(
            run_command(&[], env, &work, &root, ID),
            Run {
                status: 0,
                stdout: ok(12009, "env", ID),
                stderr: lines(NOTICE_PAIR),
                requests: one(12009, "pair-token"),
            }
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn f2_h6_h7a_h7e_h8_non_explicit_settings_keep_the_session() {
        let root = fixture("h6");
        for (session_url, lone_url, port) in [
            // H6 and H8: only gateway-injected variables, or none.
            ("http://127.0.0.1:12010", None, 12010),
            // H7a: a lone URL equal to the session's.
            (
                "http://127.0.0.1:12010",
                Some("http://127.0.0.1:12010"),
                12010,
            ),
            // H7e: websocket session URLs with the injected http(s) form.
            ("ws://127.0.0.1:1/", Some("http://127.0.0.1:1"), 1),
            ("wss://127.0.0.1:1", Some("https://127.0.0.1:1/"), 1),
        ] {
            session_file(&root, session_url, "session-token");
            for injected in [true, false] {
                let mut vars = vec![];
                if injected {
                    vars.push(("TIGHTBEAM_HOME", root.join("home").display().to_string()));
                    vars.push(("TIGHTBEAM_MACHINE", "m".to_owned()));
                    vars.push(("TIGHTBEAM_LINEAGE", "l".to_owned()));
                }
                if let Some(url) = lone_url {
                    vars.push(("TIGHTBEAM_URL", url.to_owned()));
                }
                assert_eq!(
                    run_command(&[], env_of(vars), &root, &root, ID),
                    Run {
                        status: 0,
                        stdout: ok(port, "config", ID),
                        stderr: vec![],
                        requests: one(port, "session-token"),
                    },
                    "{session_url} {lone_url:?} injected={injected}"
                );
            }
        }
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn f2_h7b_h7c_h7d_h11_incomplete_explicit_settings_beside_a_session_are_refused() {
        use crate::dispatch::Incomplete;
        let root = fixture("h7");
        session_file(&root, "http://127.0.0.1:12011", "session-token");
        let different = || ("TIGHTBEAM_URL", "http://127.0.0.1:12012".to_owned());
        for (vars, refusal) in [
            (vec![different()], Incomplete::UrlWithoutToken),
            (
                vec![("TIGHTBEAM_TOKEN", "lone".to_owned())],
                Incomplete::TokenWithoutUrl,
            ),
            (
                vec![("TIGHTBEAM_TOKEN", String::new())],
                Incomplete::TokenWithoutUrl,
            ),
            (
                vec![different(), ("TIGHTBEAM_TOKEN", String::new())],
                Incomplete::UrlWithoutToken,
            ),
            (
                vec![("TIGHTBEAM_BASE_DIR", String::new())],
                Incomplete::EmptyBaseDir,
            ),
        ] {
            // Also with --expect-instance (H7b): the outcome is only `unavailable`.
            for args in [&[][..], &["--expect-instance", "x"][..]] {
                assert_eq!(
                    run_command(args, env_of(vars.clone()), &root, &root, ID),
                    Run {
                        status: 1,
                        stdout: unavailable("env"),
                        stderr: lines(refusal.line()),
                        requests: vec![],
                    },
                    "{refusal:?} {args:?}"
                );
            }
        }
        assert_eq!(
            Incomplete::TokenWithoutUrl.line(),
            "tightbeam: incomplete explicit endpoint: TIGHTBEAM_TOKEN is set but TIGHTBEAM_URL is not; set both, or unset TIGHTBEAM_TOKEN"
        );
        assert_eq!(
            Incomplete::UrlWithoutToken.line(),
            "tightbeam: incomplete explicit endpoint: TIGHTBEAM_URL is set but TIGHTBEAM_TOKEN is empty or unset; set both, or unset TIGHTBEAM_URL"
        );
        assert_eq!(
            Incomplete::EmptyBaseDir.line(),
            "tightbeam: incomplete explicit endpoint: TIGHTBEAM_BASE_DIR is set but empty; set it to a directory, or unset it"
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn f2_h7f_h9_h11b_without_a_session_incomplete_settings_keep_todays_row_4() {
        let root = fixture("h7f");
        let home_var = root.join("home-var");
        gateway_json(&home_var, r#"{"port":12013,"cliToken":"home-token"}"#);
        let default_dir = root.join(".tightbeam");
        gateway_json(&default_dir, r#"{"port":12014,"cliToken":"default-token"}"#);
        let home_id = instance_id(&home_var).unwrap();
        let default_id = instance_id(&default_dir).unwrap();
        for lone in [
            vec![("TIGHTBEAM_URL", "http://127.0.0.1:12015".to_owned())],
            vec![("TIGHTBEAM_TOKEN", "lone".to_owned())],
            vec![
                ("TIGHTBEAM_URL", "http://127.0.0.1:12015".to_owned()),
                ("TIGHTBEAM_TOKEN", String::new()),
            ],
            // H9: nothing explicit, no session.
            vec![],
        ] {
            let mut with_home = lone.clone();
            with_home.push(("TIGHTBEAM_HOME", home_var.display().to_string()));
            assert_eq!(
                run_command(&[], env_of(with_home), &root, &root, &home_id),
                Run {
                    status: 0,
                    stdout: ok(12013, "env", &home_id),
                    stderr: vec![],
                    requests: one(12013, "home-token"),
                },
                "{lone:?}"
            );
            assert_eq!(
                run_command(&[], env_of(lone.clone()), &root, &root, &default_id),
                Run {
                    status: 0,
                    stdout: ok(12014, "default", &default_id),
                    stderr: vec![],
                    requests: one(12014, "default-token"),
                },
                "{lone:?}"
            );
        }
        // H11b: an empty base-dir variable with no session file is today's environment
        // selection of the empty path (resolved against the process directory, which
        // holds no gateway.json here): `env`, unavailable, no request.
        let env = || env_of(vec![("TIGHTBEAM_BASE_DIR", String::new())]);
        assert_eq!(
            crate::dispatch::select(&env(), &root, &root),
            crate::dispatch::Selection::Fallthrough
        );
        assert_eq!(resolve_gateway_base(&env(), &root).1, EndpointSource::Env);
        assert!(!Path::new("gateway.json").exists());
        assert_eq!(
            run_command(&[], env(), &root, &root, ID),
            Run {
                status: 1,
                stdout: unavailable("env"),
                stderr: vec![],
                requests: vec![],
            }
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn f2_h10a_h10b_h10c_a_malformed_session() {
        let root = fixture("h10");
        fs::write(root.join(".tightbeam-session"), "not-json").unwrap();
        // H10a: an explicit pair is used, with the "unreadable" notice.
        let env = env_of(vec![
            ("TIGHTBEAM_URL", "http://127.0.0.1:12016".to_owned()),
            ("TIGHTBEAM_TOKEN", "pair-token".to_owned()),
        ]);
        assert_eq!(
            run_command(&[], env, &root, &root, ID),
            Run {
                status: 0,
                stdout: ok(12016, "env", ID),
                stderr: lines(
                    "tightbeam: notice: using TIGHTBEAM_URL and TIGHTBEAM_TOKEN (explicit); ignoring the unreadable session file"
                ),
                requests: one(12016, "pair-token"),
            }
        );
        // H10b: nothing explicit; H10c (N1), verbatim: "add H10c (lone URL + malformed
        // session -> unavailable/config/no stderr)".
        for vars in [
            vec![],
            vec![("TIGHTBEAM_URL", "http://127.0.0.1:12017".to_owned())],
        ] {
            assert_eq!(
                run_command(&[], env_of(vars), &root, &root, ID),
                Run {
                    status: 1,
                    stdout: unavailable("config"),
                    stderr: vec![],
                    requests: vec![],
                }
            );
        }
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn f2_h12_the_command_has_no_identity_flag() {
        let root = fixture("h12");
        session_file(&root, "http://127.0.0.1:12018", "session-token");
        let env = || {
            env_of(vec![
                ("TIGHTBEAM_URL", "http://127.0.0.1:12019".to_owned()),
                ("TIGHTBEAM_TOKEN", "pair-token".to_owned()),
            ])
        };
        assert_eq!(
            run_command(&[], env(), &root, &root, ID),
            Run {
                status: 0,
                stdout: ok(12019, "env", ID),
                stderr: lines(NOTICE_PAIR),
                requests: one(12019, "pair-token"),
            }
        );
        // `--as x` is a usage error: exit 2, the usage line, no output, no request.
        assert_eq!(
            run_command(&["--as", "x"], env(), &root, &root, ID),
            Run {
                status: 2,
                stdout: Value::Null,
                stderr: lines(USAGE),
                requests: vec![],
            }
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn f2_h13_no_value_or_session_path_reaches_stdout_or_stderr() {
        let root = fixture("h13-CANARY_ROOT");
        let work = root.join("CANARY_SESSION_DIR/inner");
        session_file(
            &root.join("CANARY_SESSION_DIR"),
            "http://127.0.0.1:12020/CANARY_SESSION_URL",
            "CANARY_SESSION_TOKEN",
        );
        fs::create_dir_all(&work).unwrap();
        let base = root.join("CANARY_BASE");
        gateway_json(
            &base,
            r#"{"port":12021,"cliToken":"CANARY_BASE_TOKEN","note":"CANARY_GATEWAY_JSON"}"#,
        );
        let implicit = instance_id(&base).unwrap();
        let refused = |incomplete: crate::dispatch::Incomplete| Run {
            status: 1,
            stdout: unavailable("env"),
            stderr: lines(incomplete.line()),
            requests: vec![],
        };
        let cases: Vec<(Vec<(&'static str, String)>, &str, Run)> = vec![
            (
                vec![
                    (
                        "TIGHTBEAM_URL",
                        "http://127.0.0.1:12022/CANARY_PAIR_URL".to_owned(),
                    ),
                    ("TIGHTBEAM_TOKEN", "CANARY_PAIR_TOKEN".to_owned()),
                ],
                ID,
                Run {
                    status: 0,
                    stdout: ok(12022, "env", ID),
                    stderr: lines(NOTICE_PAIR),
                    requests: one(12022, "CANARY_PAIR_TOKEN"),
                },
            ),
            (
                vec![("TIGHTBEAM_BASE_DIR", base.display().to_string())],
                &implicit,
                Run {
                    status: 0,
                    stdout: ok(12021, "env", &implicit),
                    stderr: lines(NOTICE_BASE),
                    requests: one(12021, "CANARY_BASE_TOKEN"),
                },
            ),
            (
                vec![(
                    "TIGHTBEAM_BASE_DIR",
                    root.join("CANARY_MISSING").display().to_string(),
                )],
                ID,
                Run {
                    status: 1,
                    stdout: unavailable("env"),
                    stderr: vec![],
                    requests: vec![],
                },
            ),
            (
                vec![(
                    "TIGHTBEAM_URL",
                    "http://127.0.0.1:1/CANARY_LONE_URL".to_owned(),
                )],
                ID,
                refused(crate::dispatch::Incomplete::UrlWithoutToken),
            ),
            (
                vec![("TIGHTBEAM_TOKEN", "CANARY_LONE_TOKEN".to_owned())],
                ID,
                refused(crate::dispatch::Incomplete::TokenWithoutUrl),
            ),
            (
                vec![("TIGHTBEAM_BASE_DIR", String::new())],
                ID,
                refused(crate::dispatch::Incomplete::EmptyBaseDir),
            ),
            (
                vec![],
                ID,
                Run {
                    status: 0,
                    stdout: ok(12020, "config", ID),
                    stderr: vec![],
                    requests: one(12020, "CANARY_SESSION_TOKEN"),
                },
            ),
        ];
        for (vars, answer_id, expected) in cases {
            let run = run_command(&[], env_of(vars), &work, &root, answer_id);
            for printed in [run.stdout.to_string(), run.stderr.join("\n")] {
                assert!(!printed.contains("CANARY"), "{printed}");
                assert!(!printed.contains(".tightbeam-session"), "{printed}");
            }
            assert_eq!(run, expected);
        }
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn f2_h16_h17_outside_the_test_root_there_is_no_ambient_session() {
        let fixture_dir = fixture("h16");
        let root = fixture_dir.join("root");
        let home = root.join("home");
        let default_dir = home.join(".tightbeam");
        gateway_json(&default_dir, r#"{"port":12023,"cliToken":"root-default"}"#);
        let default_id = instance_id(&default_dir).unwrap();
        let outside = fixture_dir.join("outside");
        session_file(&outside, "http://127.0.0.1:12024", "outside-session");
        let work = outside.join("work");
        fs::create_dir_all(&work).unwrap();
        for vars in [
            // H16: nothing explicit.
            vec![],
            // H17: a lone URL different from that session's is no refusal (ii).
            vec![("TIGHTBEAM_URL", "http://127.0.0.1:12025".to_owned())],
        ] {
            let mut vars = vars;
            vars.push(("TIGHTBEAM_TEST_ROOT", root.display().to_string()));
            assert_eq!(
                run_command(&[], env_of(vars), &work, &home, &default_id),
                Run {
                    status: 0,
                    stdout: ok(12023, "default", &default_id),
                    stderr: vec![],
                    requests: one(12023, "root-default"),
                }
            );
        }
        fs::remove_dir_all(fixture_dir).unwrap();
    }

    #[test]
    fn f2_h18_h19_h20_explicit_sources_and_the_test_root() {
        let fixture_dir = fixture("h18");
        let root = fixture_dir.join("root");
        fs::create_dir_all(&root).unwrap();
        session_file(&fixture_dir, "http://127.0.0.1:12026", "above-root");
        let work = root.join("work");
        fs::create_dir_all(&work).unwrap();
        let root_var = || ("TIGHTBEAM_TEST_ROOT", root.display().to_string());

        // H18: the session file is outside the root, so there is nothing to override.
        let env = env_of(vec![
            ("TIGHTBEAM_URL", "http://127.0.0.1:12027".to_owned()),
            ("TIGHTBEAM_TOKEN", "pair-token".to_owned()),
            root_var(),
        ]);
        assert_eq!(
            run_command(&[], env, &work, &root, ID),
            Run {
                status: 0,
                stdout: ok(12027, "env", ID),
                stderr: vec![],
                requests: one(12027, "pair-token"),
            }
        );

        // H20: the test root alone is not explicit: a session inside it is used.
        session_file(&root, "http://127.0.0.1:12028", "inside-root");
        assert_eq!(
            run_command(&[], env_of(vec![root_var()]), &work, &root, ID),
            Run {
                status: 0,
                stdout: ok(12028, "config", ID),
                stderr: vec![],
                requests: one(12028, "inside-root"),
            }
        );

        // H19: a base outside the root is F1's refused path: unavailable, no fallback.
        let outside_base = fixture_dir.join("outside-base");
        gateway_json(&outside_base, r#"{"port":12029,"cliToken":"outside-base"}"#);
        let env = env_of(vec![
            ("TIGHTBEAM_BASE_DIR", outside_base.display().to_string()),
            root_var(),
        ]);
        assert_eq!(
            run_command(&[], env, &work, &root, ID),
            Run {
                status: 1,
                stdout: unavailable("env"),
                stderr: vec![],
                requests: vec![],
            }
        );
        fs::remove_dir_all(fixture_dir).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn f2_n3_a_session_reached_through_a_symlink_out_of_the_root_is_not_ambient() {
        // Review att_ea3769db N3 (PO-required, att_824b22b5): a session reached through a
        // symlink inside the root that points outside it. The shared selection applies
        // F1's canonical containment, so it is not ambient.
        use std::os::unix::fs::symlink;
        let fixture_dir = fixture("n3");
        let root = fixture_dir.join("root");
        let outside = fixture_dir.join("outside");
        session_file(&outside, "http://127.0.0.1:12030", "outside-session");
        fs::create_dir_all(outside.join("work")).unwrap();
        fs::create_dir_all(&root).unwrap();
        symlink(&outside, root.join("link")).unwrap();
        let work = root.join("link/work");
        let root_var = ("TIGHTBEAM_TEST_ROOT", root.display().to_string());

        let env = env_of(vec![root_var.clone()]);
        assert_eq!(
            crate::dispatch::select(&env, &work, &root),
            crate::dispatch::Selection::Fallthrough
        );
        // Not ambient, so neither a capture nor a refusal (ii) nor a notice.
        let (discovery, stderr) = discover_with(
            env_of(vec![
                ("TIGHTBEAM_URL", "http://127.0.0.1:12031".to_owned()),
                root_var,
            ]),
            &work,
            &root,
        );
        assert_ne!(discovery.token.as_deref(), Some("outside-session"));
        assert_ne!(discovery.source, EndpointSource::Config);
        assert_eq!(stderr, None);
        fs::remove_dir_all(fixture_dir).unwrap();
    }

    #[test]
    fn f2_h21_h22_non_loopback_explicit_sources_are_never_contacted() {
        // H21 and H22 (N2), verbatim: "non-loopback pair and base-url cases".
        let root = fixture("h21");
        let work = root.join("tree");
        fs::create_dir_all(&work).unwrap();
        let satellite = root.join("satellite");
        gateway_json(
            &satellite,
            r#"{"url":"ws://10.0.0.1:1","cliToken":"base-token"}"#,
        );
        let pair = || {
            vec![
                ("TIGHTBEAM_URL", "http://10.0.0.1:1".to_owned()),
                ("TIGHTBEAM_TOKEN", "pair-token".to_owned()),
            ]
        };
        let base = || vec![("TIGHTBEAM_BASE_DIR", satellite.display().to_string())];
        for with_session in [false, true] {
            if with_session {
                session_file(&root, "http://127.0.0.1:12032", "session-token");
            }
            for (vars, notice) in [(pair(), NOTICE_PAIR), (base(), NOTICE_BASE)] {
                assert_eq!(
                    run_command(&[], env_of(vars), &work, &root, ID),
                    Run {
                        status: 1,
                        stdout: unavailable("env"),
                        stderr: if with_session { lines(notice) } else { vec![] },
                        requests: vec![],
                    },
                    "session={with_session} {notice}"
                );
            }
        }
        fs::remove_dir_all(root).unwrap();
    }
}

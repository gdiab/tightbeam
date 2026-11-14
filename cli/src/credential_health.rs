use std::fs;
use std::io::Read;
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
    let expect_instance = match parse_args(args) {
        Ok(expect_instance) => expect_instance,
        Err(()) => {
            eprintln!("{USAGE}");
            return 2;
        }
    };

    let discovery = discover();
    let response = discovery
        .endpoint
        .as_ref()
        .and_then(|endpoint| exchange(endpoint.clone(), discovery.token.clone()));
    let (result, instance, version) = outcome(&discovery, expect_instance.as_deref(), response);

    let endpoint = discovery.endpoint.map(|endpoint| {
        json!({
            "host": endpoint.host,
            "port": endpoint.port,
        })
    });

    println!(
        "{}",
        json!({
            "result": result,
            "endpoint": endpoint,
            "endpointSource": discovery.source.wire_name(),
            "instance": instance,
            "version": version,
        })
    );

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

fn discover() -> Discovery {
    #[allow(deprecated)]
    let home = std::env::home_dir().unwrap_or_default();
    let cwd = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
    discover_with(|name| std::env::var(name).ok(), &cwd, &home)
}

fn discover_with<F>(get_env: F, cwd: &Path, home: &Path) -> Discovery
where
    F: Fn(&str) -> Option<String>,
{
    if let Some(discovery) = session_discovery(cwd) {
        return discovery;
    }

    let url = get_env("TIGHTBEAM_URL").filter(|value| !value.is_empty());
    let token = get_env("TIGHTBEAM_TOKEN").filter(|value| !value.is_empty());
    if let (Some(url), Some(token)) = (url, token) {
        return discovery_from_url(&url, Some(token), EndpointSource::Env, None);
    }

    let source = if get_env("TIGHTBEAM_BASE_DIR").is_some() || get_env("TIGHTBEAM_HOME").is_some() {
        EndpointSource::Env
    } else {
        EndpointSource::Default
    };
    let base_dir = crate::base_dir::resolve_with(&get_env, home);
    gateway_discovery(&base_dir, source)
}

fn session_discovery(cwd: &Path) -> Option<Discovery> {
    for directory in cwd.ancestors() {
        let path = directory.join(".tightbeam-session");
        match fs::symlink_metadata(&path) {
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(_) => return Some(unavailable(EndpointSource::Config)),
        }
        let config = fs::read_to_string(path)
            .ok()
            .and_then(|encoded| serde_json::from_str::<Value>(&encoded).ok());
        return Some(match config {
            Some(config) => match (
                config.get("url").and_then(Value::as_str),
                config.get("token").and_then(Value::as_str),
            ) {
                (Some(url), Some(token)) => {
                    discovery_from_url(url, Some(token.to_owned()), EndpointSource::Config, None)
                }
                _ => unavailable(EndpointSource::Config),
            },
            None => unavailable(EndpointSource::Config),
        });
    }
    None
}

fn gateway_discovery(base_dir: &Path, source: EndpointSource) -> Discovery {
    let config = fs::read_to_string(base_dir.join("gateway.json"))
        .ok()
        .and_then(|encoded| serde_json::from_str::<Value>(&encoded).ok());
    let Some(config) = config else {
        return unavailable(source);
    };
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
        return discovery_from_url(url, token, source, None);
    }

    let Some(port) = config
        .get("port")
        .and_then(Value::as_u64)
        .and_then(|port| u16::try_from(port).ok())
    else {
        return unavailable(source);
    };
    let Ok(canonical) = fs::canonicalize(base_dir) else {
        return unavailable(source);
    };
    let Some(implicit_instance) = instance_id(&canonical) else {
        return unavailable(source);
    };
    discovery_from_url(
        &format!("http://127.0.0.1:{port}"),
        token,
        source,
        Some(implicit_instance),
    )
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

    #[test]
    fn discovery_order_and_source_classes_match_the_standard_client() {
        let root = std::env::temp_dir().join(format!(
            "tightbeam-credential-health-{}",
            std::process::id()
        ));
        let work = root.join("work/session");
        fs::create_dir_all(&work).unwrap();
        fs::write(
            work.parent().unwrap().join(".tightbeam-session"),
            r#"{"url":"http://127.0.0.2:12000/path","token":"session-token"}"#,
        )
        .unwrap();
        let vars = HashMap::from([
            ("TIGHTBEAM_URL", "http://127.0.0.1:13000"),
            ("TIGHTBEAM_TOKEN", "env-token"),
        ]);
        let discovery = discover_with(
            |name| vars.get(name).map(|value| (*value).to_owned()),
            &work,
            &root,
        );
        assert_eq!(discovery.source, EndpointSource::Config);
        assert_eq!(discovery.endpoint.unwrap().port, 12000);
        assert_eq!(discovery.token.as_deref(), Some("session-token"));
        fs::remove_dir_all(root).unwrap();
    }

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

        let discovery = discover_with(
            |name| (name == "TIGHTBEAM_BASE_DIR").then(|| root.display().to_string()),
            &root,
            &root,
        );
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
    fn malformed_nearest_session_file_stops_discovery_without_env_fallback() {
        let root = std::env::temp_dir().join(format!(
            "tightbeam-credential-health-shadow-{}",
            std::process::id()
        ));
        let work = root.join("work");
        fs::create_dir_all(&work).unwrap();
        fs::write(root.join(".tightbeam-session"), "not-json").unwrap();

        let discovery = discover_with(
            |name| match name {
                "TIGHTBEAM_URL" => Some("http://127.0.0.1:12000".to_owned()),
                "TIGHTBEAM_TOKEN" => Some("must-not-be-used".to_owned()),
                _ => None,
            },
            &work,
            &root,
        );
        assert_eq!(discovery.source, EndpointSource::Config);
        assert_eq!(discovery.endpoint, None);
        assert_eq!(discovery.token, None);
        fs::remove_dir_all(root).unwrap();
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
            let discovery = discover_with(|_| None, &work, &root);
            assert_eq!(discovery.source, EndpointSource::Config);
            assert_eq!(discovery.endpoint, None);
            assert_eq!(discovery.token, None);
        }

        fs::write(
            root.join(".tightbeam-session"),
            r#"{"url":"http://127.0.0.1:12000","token":""}"#,
        )
        .unwrap();
        let discovery = discover_with(|_| None, &work, &root);
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
}

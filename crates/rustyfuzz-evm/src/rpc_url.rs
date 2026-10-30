use reqwest::Url;
use std::net::{IpAddr, SocketAddr, ToSocketAddrs};

pub fn validate_production_rpc_url(raw: &str) -> Result<Url, String> {
    validate_rpc_url(raw, false)
}

pub fn validate_rpc_url_for_argv(raw: &str) -> Result<Url, String> {
    let (url, _) = resolve_rpc_url(raw, false)?;
    if url.path() != "/" || url.query().is_some() || url.fragment().is_some() {
        return Err(
            "RPC URLs with paths or query data must be supplied through the child environment"
                .to_string(),
        );
    }
    Ok(url)
}

pub fn validate_rpc_url(raw: &str, allow_loopback: bool) -> Result<Url, String> {
    let url = Url::parse(raw).map_err(|_| "URL is invalid".to_string())?;
    if !matches!(url.scheme(), "http" | "https") {
        return Err("URL must use HTTP or HTTPS".to_string());
    }
    if url.scheme() == "http" && !allow_loopback {
        return Err("production RPC and explorer URLs must use HTTPS".to_string());
    }
    if !url.username().is_empty() || url.password().is_some() {
        return Err("URL must not contain embedded credentials".to_string());
    }
    let host = normalized_host(&url)?;
    if url.scheme() == "http" && !is_loopback_host(&host) {
        return Err("HTTP is allowed only for explicit loopback test endpoints".to_string());
    }
    if allow_loopback && is_loopback_host(&host) {
        return Ok(url);
    }
    if is_forbidden_host(&host) {
        return Err("URL host is private, loopback, link-local, or metadata".to_string());
    }
    Ok(url)
}

pub fn resolve_rpc_url(raw: &str, allow_loopback: bool) -> Result<(Url, Vec<SocketAddr>), String> {
    let url = validate_rpc_url(raw, allow_loopback)?;
    let host = normalized_host(&url)?;
    let port = match url.port() {
        Some(port) => port,
        None if url.scheme() == "http" => 80,
        None if url.scheme() == "https" => 443,
        None => return Err("URL must use HTTP or HTTPS".to_string()),
    };
    let mut addresses = (host.as_str(), port)
        .to_socket_addrs()
        .map_err(|_| "URL host could not be resolved".to_string())?
        .collect::<Vec<_>>();
    addresses.sort_by_key(|address| address.ip());
    addresses.dedup();
    ensure_resolved_addresses_allowed(&addresses, allow_loopback)?;
    Ok((url, addresses))
}

fn ensure_resolved_addresses_allowed(
    addresses: &[SocketAddr],
    allow_loopback: bool,
) -> Result<(), String> {
    if addresses.is_empty() {
        return Err("URL host resolved to no addresses".to_string());
    }
    for address in addresses {
        if allow_loopback {
            if !is_loopback_address(address.ip()) {
                return Err("test endpoint must resolve only to loopback".to_string());
            }
        } else if is_forbidden_address(address.ip()) {
            return Err(
                "URL resolved to a private, loopback, link-local, or metadata address".to_string(),
            );
        }
    }
    Ok(())
}

pub fn resolve_rpc_url_for_current_process(raw: &str) -> Result<(Url, Vec<SocketAddr>), String> {
    resolve_rpc_url(raw, test_loopback_allowed())
}

pub fn rpc_api_key_allowed_origins() -> Result<Vec<String>, String> {
    let raw = std::env::var("RUSTYFUZZ_RPC_API_KEY_ALLOWED_ORIGINS").unwrap_or_default();
    parse_allowed_origins(&raw)
}

/// Whether a URL already carries its credential in the path.
///
/// Providers like Alchemy, Infura and Ankr embed the key as the final path segment
/// (`/v2/<key>`). For those, sending it again as `Authorization: Bearer` is not merely
/// redundant: Alchemy answers **HTTP 401**, so the request fails even though the URL alone
/// works. Verified against eth-mainnet.g.alchemy.com — no header returns `0x1`, a Bearer
/// header returns 401.
///
/// The test is deliberately structural rather than a provider allowlist: a hardcoded list
/// would silently break the next provider that adopts the same scheme. A path segment of 20+
/// characters with no separators is not a version or a method name, and treating it as a
/// credential is the conservative reading — the failure mode of guessing wrong here is a
/// request that works without the header and fails with it.
fn url_carries_credential(raw_url: &str) -> bool {
    let Ok(url) = Url::parse(raw_url) else {
        return false;
    };
    url.path_segments()
        .map(|segments| {
            segments
                .filter(|segment| !segment.is_empty())
                .any(|segment| {
                    segment.len() >= 20
                        // Real keys contain `-` and `_` (Alchemy's do: `MWeRBkXLW6AyDjL-f6hpO`),
                        // so excluding them was a bug that made this test fail and would have
                        // let a header be added to exactly the endpoint that rejects it.
                        && segment
                            .chars()
                            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
                })
        })
        .unwrap_or(false)
}

pub fn rpc_api_key_header(
    raw_url: &str,
    api_key: Option<&str>,
    allowed_origins: &[String],
) -> Result<Option<String>, String> {
    let Some(api_key) = api_key.filter(|value| !value.trim().is_empty()) else {
        // The common case, and the one that used to fail confusingly: `RUSTYFUZZ_RPC_API_KEY`
        // is set in `.env`, so `dotenvy` restores it in the process even after `unset` in the
        // shell, and the URL already authenticates. Silently sending no header is correct
        // here, and is what the caller needs rather than an allowlist complaint.
        return Ok(None);
    };
    if url_carries_credential(raw_url) {
        // Refuse to add a header that is known to break such endpoints. Importing the key
        // from elsewhere is the caller's choice; overriding the URL's own credential is not
        // something this function should do on the caller's behalf.
        return Ok(None);
    }
    let origin = request_origin(raw_url)?;
    if !allowed_origins.iter().any(|allowed| allowed == &origin) {
        return Err(format!(
            "RPC API key origin is not explicitly allowlisted: set \
             RUSTYFUZZ_RPC_API_KEY_ALLOWED_ORIGINS={origin} (the key is present in the \
             environment, or imported from .env, but this origin was not reviewed)"
        ));
    }
    Ok(Some(format!("Bearer {api_key}")))
}

fn parse_allowed_origins(raw: &str) -> Result<Vec<String>, String> {
    raw.split(',')
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(|value| {
            let url = Url::parse(value)
                .map_err(|_| "invalid RPC API key allowlist origin".to_string())?;
            if !(matches!(url.scheme(), "http" | "https")
                && url.host_str().is_some()
                && url.username().is_empty()
                && url.password().is_none()
                && url.path() == "/"
                && url.query().is_none()
                && url.fragment().is_none())
            {
                return Err(
                    "RPC API key allowlist entries must be origins without paths or credentials"
                        .to_string(),
                );
            }
            Ok(origin_from_url(&url))
        })
        .collect()
}

fn request_origin(raw_url: &str) -> Result<String, String> {
    let url = Url::parse(raw_url).map_err(|_| "RPC URL is invalid".to_string())?;
    Ok(origin_from_url(&url))
}

fn origin_from_url(url: &Url) -> String {
    let scheme = url.scheme().to_ascii_lowercase();
    let raw_host = url
        .host_str()
        .unwrap_or_default()
        .trim_start_matches('[')
        .trim_end_matches(']')
        .to_ascii_lowercase();
    let host = if raw_host.contains(':') {
        format!("[{raw_host}]")
    } else {
        raw_host
    };
    let default_port = matches!(
        (scheme.as_str(), url.port()),
        ("http", Some(80)) | ("https", Some(443))
    );
    let mut origin = format!("{scheme}://{host}");
    if let Some(port) = url.port() {
        if !default_port {
            origin.push(':');
            origin.push_str(&port.to_string());
        }
    }
    origin
}

pub fn test_loopback_allowed() -> bool {
    cfg!(test)
        || matches!(
            std::env::var("RUSTYFUZZ_TEST_ALLOW_LOOPBACK")
                .ok()
                .as_deref(),
            Some("1" | "true" | "TRUE" | "yes" | "YES")
        )
}

pub fn redact_url_query_credentials(raw: &str) -> String {
    let Ok(mut url) = Url::parse(raw) else {
        return "<redacted-url>".to_string();
    };
    let _ = url.set_username("");
    let _ = url.set_password(None);
    url.set_query(None);
    url.set_fragment(None);
    url.to_string()
}

pub fn redact_rpc_error(message: &str) -> String {
    let mut output = String::new();
    let mut remaining = message;
    loop {
        let Some((start, scheme_len)) = find_http_url(remaining) else {
            output.push_str(remaining);
            break;
        };
        output.push_str(&remaining[..start]);
        output.push_str("<rpc-url>");
        let tail = &remaining[start + scheme_len..];
        let end = tail
            .find(|character: char| {
                character.is_whitespace() || matches!(character, '"' | '\'' | ')' | '(' | ']' | '[')
            })
            .unwrap_or(tail.len());
        remaining = &tail[end..];
    }
    output
}

fn find_http_url(value: &str) -> Option<(usize, usize)> {
    value.char_indices().find_map(|(index, _)| {
        let tail = &value[index..];
        if tail
            .as_bytes()
            .get(..7)
            .is_some_and(|scheme| scheme.eq_ignore_ascii_case(b"http://"))
        {
            Some((index, 7))
        } else if tail
            .as_bytes()
            .get(..8)
            .is_some_and(|scheme| scheme.eq_ignore_ascii_case(b"https://"))
        {
            Some((index, 8))
        } else {
            None
        }
    })
}

fn normalized_host(url: &Url) -> Result<String, String> {
    Ok(url
        .host_str()
        .ok_or_else(|| "URL must contain a host".to_string())?
        .trim_end_matches('.')
        .trim_start_matches('[')
        .trim_end_matches(']')
        .to_ascii_lowercase())
}

fn is_loopback_host(host: &str) -> bool {
    host == "localhost"
        || host.ends_with(".localhost")
        || host
            .parse::<IpAddr>()
            .map(is_loopback_address)
            .unwrap_or(false)
}

fn is_forbidden_host(host: &str) -> bool {
    if is_loopback_host(host)
        || host == "metadata.google.internal"
        || host == "metadata"
        || host == "instance-data"
    {
        return true;
    }
    host.parse::<IpAddr>()
        .map(is_forbidden_address)
        .unwrap_or(false)
}

fn is_loopback_address(address: IpAddr) -> bool {
    address.is_loopback()
}

fn is_forbidden_address(address: IpAddr) -> bool {
    match address {
        IpAddr::V4(address) => is_forbidden_ipv4(address),
        IpAddr::V6(address) => {
            if let Some(address) = address.to_ipv4() {
                is_forbidden_ipv4(address)
            } else {
                address.is_loopback()
                    || address.is_unspecified()
                    || address.is_unique_local()
                    || address.is_unicast_link_local()
                    || address.is_multicast()
            }
        }
    }
}

fn is_forbidden_ipv4(address: std::net::Ipv4Addr) -> bool {
    let [a, b, c, _] = address.octets();
    a == 0
        || a == 10
        || a == 127
        || (a == 100 && (64..=127).contains(&b))
        || (a == 169 && b == 254)
        || (a == 172 && (16..=31).contains(&b))
        || (a == 192 && b == 0 && c == 0)
        || (a == 192 && b == 168)
        || (a == 198 && (b == 18 || b == 19))
        || a >= 224
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn production_urls_reject_credentials_non_public_hosts_and_http() {
        for raw in [
            "ftp://example.com",
            "http://rpc.example.com",
            "https://user:pass@example.com",
            "https://127.0.0.1",
            "https://localhost",
            "https://10.0.0.1",
            "https://169.254.169.254",
            "https://metadata.google.internal",
            "https://[::1]",
            "https://[fe80::1]",
            "https://[fc00::1]",
            "https://[ff02::1]",
            "https://224.0.0.1",
            "https://[::ffff:127.0.0.1]",
        ] {
            assert!(validate_production_rpc_url(raw).is_err(), "{raw}");
        }
        assert!(validate_production_rpc_url("https://rpc.example.com/path?apikey=secret").is_ok());
    }

    #[test]
    fn argv_rpc_policy_allows_only_origin_urls() {
        assert!(validate_rpc_url_for_argv("https://8.8.8.8").is_ok());
        for raw in [
            "https://user:pass@rpc.example.com/v1",
            "https://rpc.example.com/v1?apikey=secret",
            "https://rpc.example.com/v1/super-secret-api-key",
            "https://rpc.example.com/v1/0123456789abcdef0123456789abcdef",
            "http://rpc.example.com/v1",
        ] {
            assert!(validate_rpc_url_for_argv(raw).is_err(), "{raw}");
        }
    }

    #[test]
    fn argv_rpc_policy_rejects_private_and_mixed_dns_answers() {
        let private = SocketAddr::from(([10, 0, 0, 1], 443));
        let public = SocketAddr::from(([8, 8, 8, 8], 443));
        assert!(ensure_resolved_addresses_allowed(&[private], false).is_err());
        assert!(ensure_resolved_addresses_allowed(&[public, private], false).is_err());
        assert!(ensure_resolved_addresses_allowed(&[public], false).is_ok());
    }

    #[test]
    fn explicit_test_allowance_accepts_only_resolved_loopback() {
        let (_, addresses) = resolve_rpc_url("http://localhost:8545", true).expect("loopback DNS");
        assert!(!addresses.is_empty());
        assert!(addresses.iter().all(|address| address.ip().is_loopback()));
        assert!(validate_rpc_url("http://rpc.example.com", true).is_err());
        assert!(resolve_rpc_url("http://localhost:8545", false).is_err());
        assert!(resolve_rpc_url("http://169.254.169.254", true).is_err());
    }

    #[test]
    fn a_credential_in_the_url_path_is_recognised_across_key_shapes() {
        // Alchemy keys contain '-', so a charset of alphanumerics only misses them and the
        // worst case follows: a Bearer header gets added to the one endpoint that 401s on it.
        assert!(url_carries_credential(
            "https://eth-mainnet.g.alchemy.com/v2/MWeRBkXLW6AyDjL-f6hpO"
        ));
        assert!(url_carries_credential(
            "https://mainnet.infura.io/v3/0123456789abcdef0123456789abcdef"
        ));
        assert!(url_carries_credential(
            "https://rpc.ankr.com/eth_0123456789abcdef0123456789abcdef"
        ));
        // Not credentials: short version segments, ordinary paths, empty paths.
        assert!(!url_carries_credential("https://rpc.example.com/v1"));
        assert!(!url_carries_credential("https://rpc.example.com"));
        assert!(!url_carries_credential("https://rpc.example.com/api/v2"));
        // A long segment with separators is a path, not a key.
        assert!(!url_carries_credential(
            "https://rpc.example.com/some/very/long/path/segment/name"
        ));
        assert!(!url_carries_credential("not a url"));
    }

    #[test]
    fn rpc_api_key_requires_an_explicit_origin_allowlist() {
        let allowed = vec!["https://rpc.example.com".to_string()];
        assert_eq!(
            rpc_api_key_header("https://rpc.example.com/v1", Some("secret"), &allowed,),
            Ok(Some("Bearer secret".to_string()))
        );
        // A URL that already carries its credential in the path must NOT get a header.
        // Alchemy answers 401 when the key is sent both ways, so adding one turns a working
        // request into a failure.
        assert_eq!(
            rpc_api_key_header(
                "https://eth-mainnet.g.alchemy.com/v2/MWeRBkXLW6AyDjL-f6hpO",
                Some("secret"),
                &["https://eth-mainnet.g.alchemy.com".to_string()],
            ),
            Ok(None)
        );
        // And it needs no allowlist, because no header will be sent.
        assert_eq!(
            rpc_api_key_header(
                "https://eth-mainnet.g.alchemy.com/v2/MWeRBkXLW6AyDjL-f6hpO",
                Some("secret"),
                &[],
            ),
            Ok(None)
        );
        // A short path segment is a version, not a credential, so the header still applies.
        assert_eq!(
            rpc_api_key_header("https://rpc.example.com/v2", Some("secret"), &allowed),
            Ok(Some("Bearer secret".to_string()))
        );
        let rejected = rpc_api_key_header("https://user.example.com/v1", Some("secret"), &allowed)
            .unwrap_err();
        // The message must say what to set. "not allowlisted" alone sent a user hunting
        // through source when the fix was one environment variable.
        assert!(
            rejected.contains("RUSTYFUZZ_RPC_API_KEY_ALLOWED_ORIGINS=https://user.example.com"),
            "the error must name the exact variable and origin: {rejected}"
        );
        assert_eq!(
            rpc_api_key_header("https://rpc.example.com/v1", None, &[]),
            Ok(None)
        );
        assert!(
            parse_allowed_origins("https://rpc.example.com, https://other.example.com:443").is_ok()
        );
        assert_eq!(
            parse_allowed_origins("https://[2001:db8::1]:8545").unwrap(),
            vec!["https://[2001:db8::1]:8545".to_string()]
        );
        assert_eq!(
            rpc_api_key_header(
                "https://[2001:db8::1]:8545/v1",
                Some("secret"),
                &["https://[2001:db8::1]:8545".to_string()],
            ),
            Ok(Some("Bearer secret".to_string()))
        );
        assert!(parse_allowed_origins("https://rpc.example.com/v1").is_err());
    }
    #[test]
    fn redaction_removes_userinfo_query_and_fragment() {
        let redacted = redact_url_query_credentials(
            "https://user:pass@example.com/path?apikey=secret#fragment",
        );
        assert_eq!(redacted, "https://example.com/path");
        let error = redact_rpc_error(
            "request failed for HTTPS://user:pass@example.com/rpc?access_key=secret while retrying",
        );
        assert_eq!(error, "request failed for <rpc-url> while retrying");
        assert!(!error.contains("secret"));
        for raw in [
            "HTTP://example.com/rpc?key=secret",
            "HtTpS://example.com/rpc?access_key=secret",
            "https://example.com/rpc?pass=secret",
        ] {
            assert!(!redact_rpc_error(raw).contains("secret"), "{raw}");
        }
    }
}

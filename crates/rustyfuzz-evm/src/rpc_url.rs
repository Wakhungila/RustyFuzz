use reqwest::Url;
use std::net::{IpAddr, SocketAddr, ToSocketAddrs};

pub fn validate_production_rpc_url(raw: &str) -> Result<Url, String> {
    validate_rpc_url(raw, false)
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
    if addresses.is_empty() {
        return Err("URL host resolved to no addresses".to_string());
    }
    for address in &addresses {
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
    Ok((url, addresses))
}

pub fn resolve_rpc_url_for_current_process(raw: &str) -> Result<(Url, Vec<SocketAddr>), String> {
    resolve_rpc_url(raw, test_loopback_allowed())
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
        let http = remaining.find("http://").map(|index| (index, 7));
        let https = remaining.find("https://").map(|index| (index, 8));
        let next = match (http, https) {
            (Some(left), Some(right)) => Some(if left.0 <= right.0 { left } else { right }),
            (Some(value), None) | (None, Some(value)) => Some(value),
            (None, None) => None,
        };
        let Some((start, scheme_len)) = next else {
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
    fn explicit_test_allowance_accepts_only_resolved_loopback() {
        let (_, addresses) = resolve_rpc_url("http://localhost:8545", true).expect("loopback DNS");
        assert!(!addresses.is_empty());
        assert!(addresses.iter().all(|address| address.ip().is_loopback()));
        assert!(validate_rpc_url("http://rpc.example.com", true).is_err());
        assert!(resolve_rpc_url("http://localhost:8545", false).is_err());
        assert!(resolve_rpc_url("http://169.254.169.254", true).is_err());
    }

    #[test]
    fn redaction_removes_userinfo_query_and_fragment() {
        let redacted = redact_url_query_credentials(
            "https://user:pass@example.com/path?apikey=secret#fragment",
        );
        assert_eq!(redacted, "https://example.com/path");
        let error = redact_rpc_error(
            "request failed for https://user:pass@example.com/rpc?apikey=secret while retrying",
        );
        assert_eq!(error, "request failed for <rpc-url> while retrying");
        assert!(!error.contains("secret"));
    }
}

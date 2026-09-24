//! Gate 4 live-RPC behavior scenarios: reorg, rate limit, retry, archive
//! gap, and timeout against a deterministic mock JSON-RPC endpoint.
//!
//! These tests exercise `rustyfuzz_evm::fork_db` fail-closed classification
//! without touching a real provider.

use rustyfuzz_evm::fork_db::{
    is_live_rpc_failure, CacheStaleReason, ForkDb, ForkDbCacheSnapshot, ForkDbError, RpcFailureKind,
};
use serde_json::{json, Value};
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

/// Handler decides HTTP status + JSON body for each request (0-based index).
type MockHandler = Arc<dyn Fn(usize, &Value) -> (u16, Value) + Send + Sync>;

fn spawn_mock_rpc(handler: MockHandler) -> (String, Arc<AtomicUsize>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind mock rpc");
    let addr = listener.local_addr().expect("mock rpc addr");
    let hits = Arc::new(AtomicUsize::new(0));
    let hits_bg = Arc::clone(&hits);
    thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { break };
            let hits = Arc::clone(&hits_bg);
            let handler = Arc::clone(&handler);
            let _ = handle_connection(&mut stream, hits, handler);
        }
    });
    (format!("http://{addr}"), hits)
}

fn handle_connection(
    stream: &mut TcpStream,
    hits: Arc<AtomicUsize>,
    handler: MockHandler,
) -> std::io::Result<()> {
    stream.set_read_timeout(Some(Duration::from_secs(5)))?;
    let mut buf = Vec::new();
    let mut chunk = [0u8; 4096];
    let content_length = loop {
        let n = stream.read(&mut chunk)?;
        if n == 0 {
            return Ok(());
        }
        buf.extend_from_slice(&chunk[..n]);
        if let Some(header_end) = find_subslice(&buf, b"\r\n\r\n") {
            let headers = String::from_utf8_lossy(&buf[..header_end]);
            let mut len = 0usize;
            for line in headers.lines() {
                if let Some(rest) = line
                    .strip_prefix("Content-Length:")
                    .or_else(|| line.strip_prefix("content-length:"))
                {
                    len = rest.trim().parse().unwrap_or(0);
                }
            }
            let body_start = header_end + 4;
            if buf.len() >= body_start + len {
                break len;
            }
        }
    };
    let header_end = find_subslice(&buf, b"\r\n\r\n").expect("headers");
    let body_start = header_end + 4;
    let body = &buf[body_start..body_start + content_length];
    let request: Value = serde_json::from_slice(body)
        .map_err(|err| std::io::Error::new(std::io::ErrorKind::InvalidData, err))?;
    let idx = hits.fetch_add(1, Ordering::SeqCst);
    let (status, response_body) = handler(idx, &request);
    let body_str = response_body.to_string();
    let reason = match status {
        200 => "OK",
        429 => "Too Many Requests",
        500 => "Internal Server Error",
        _ => "Error",
    };
    let response = format!(
        "HTTP/1.1 {status} {reason}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body_str}",
        body_str.len()
    );
    stream.write_all(response.as_bytes())?;
    stream.flush()
}

fn read_http_request(stream: &mut TcpStream) -> Vec<u8> {
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    let mut buf = Vec::new();
    let content_length = loop {
        let mut chunk = [0u8; 4096];
        let n = stream.read(&mut chunk).unwrap();
        assert!(n > 0);
        buf.extend_from_slice(&chunk[..n]);
        if let Some(header_end) = find_subslice(&buf, b"\r\n\r\n") {
            let headers = String::from_utf8_lossy(&buf[..header_end]);
            if let Some(len) = headers.lines().find_map(|line| {
                let (name, value) = line.split_once(':')?;
                if name.eq_ignore_ascii_case("content-length") {
                    value.trim().parse::<usize>().ok()
                } else {
                    None
                }
            }) {
                if buf.len() >= header_end + 4 + len {
                    break len;
                }
            }
        }
    };
    buf.truncate(content_length + find_subslice(&buf, b"\r\n\r\n").unwrap() + 4);
    buf
}

fn spawn_partial_body_rpc() -> (String, thread::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind partial body rpc");
    let addr = listener.local_addr().expect("partial body rpc addr");
    let worker = thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("accept partial body request");
        let _ = read_http_request(&mut stream);
        let response = "HTTP/1.1 200 OK\r\nContent-Length: 128\r\nConnection: close\r\n\r\n{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":";
        stream
            .write_all(response.as_bytes())
            .expect("write partial response");
        stream.flush().expect("flush partial response");
        thread::sleep(Duration::from_secs(3));
    });
    (format!("http://{addr}"), worker)
}

fn spawn_redirect_rpc() -> (String, Arc<AtomicUsize>, thread::JoinHandle<()>) {
    let target = TcpListener::bind("127.0.0.1:0").expect("bind redirect target");
    let target_addr = target.local_addr().expect("redirect target addr");
    let target_hits = Arc::new(AtomicUsize::new(0));
    let target_hits_bg = Arc::clone(&target_hits);
    let _target_worker = thread::spawn(move || {
        let (mut stream, _) = target.accept().expect("accept redirect target request");
        let _ = read_http_request(&mut stream);
        let body = rpc_result(&json!({"jsonrpc": "2.0", "id": 1}), json!("0x1")).to_string();
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        );
        target_hits_bg.fetch_add(1, Ordering::SeqCst);
        stream
            .write_all(response.as_bytes())
            .expect("write redirect target response");
    });

    let source = TcpListener::bind("127.0.0.1:0").expect("bind redirect source");
    let source_addr = source.local_addr().expect("redirect source addr");
    let source_worker = thread::spawn(move || {
        let (mut stream, _) = source.accept().expect("accept redirect source request");
        let _ = read_http_request(&mut stream);
        let response = format!(
            "HTTP/1.1 302 Found\r\nLocation: http://{target_addr}/redirected\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
        );
        stream
            .write_all(response.as_bytes())
            .expect("write redirect source response");
    });
    (format!("http://{source_addr}"), target_hits, source_worker)
}

fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

fn rpc_result(request: &Value, result: Value) -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": request.get("id").cloned().unwrap_or(json!(1)),
        "result": result,
    })
}

fn block_with_hash(hash: &str) -> Value {
    json!({ "hash": hash, "number": "0x10" })
}

#[test]
fn reorg_detected_when_block_hash_changes() {
    // First fetch pins hash A; after a reorg the chain reports hash B and
    // cache validation must refuse the snapshot.
    let expected_hash = "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    let reorged_hash = "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    let (url, _hits) = spawn_mock_rpc(Arc::new(move |_idx, req| {
        let method = req.get("method").and_then(Value::as_str).unwrap_or("");
        let result = match method {
            "eth_chainId" => json!("0x1"),
            "eth_getBlockByNumber" => block_with_hash(expected_hash),
            _ => Value::Null,
        };
        (200, rpc_result(req, result))
    }));

    let db = ForkDb::new_for_test(url, 16, Duration::from_secs(3), 1);
    let prov = db.refresh_remote_provenance().expect("first refresh");
    assert_eq!(prov.block_hash.as_deref(), Some(expected_hash));
    assert_eq!(prov.chain_id, Some(1));

    let snap = db.cache_snapshot();
    assert_eq!(snap.provenance.block_hash.as_deref(), Some(expected_hash));

    // Chain reorged: observed hash no longer matches the cached snapshot.
    let err = snap
        .ensure_consistent(Some(16), Some(reorged_hash), None, None, true)
        .expect_err("reorg must invalidate cache");
    assert_eq!(
        err,
        CacheStaleReason::BlockHashMismatch {
            expected: expected_hash.to_string(),
            found: reorged_hash.to_string(),
        }
    );

    // Same hash still validates.
    assert!(snap
        .ensure_consistent(Some(16), Some(expected_hash), None, None, true)
        .is_ok());
}

#[test]
fn refresh_requires_a_block_hash() {
    let (url, _hits) = spawn_mock_rpc(Arc::new(|_idx, req| {
        let result = match req.get("method").and_then(Value::as_str) {
            Some("eth_chainId") => json!("0x1"),
            Some("eth_getBlockByNumber") => json!({ "number": "0x10" }),
            _ => Value::Null,
        };
        (200, rpc_result(req, result))
    }));

    let error = ForkDb::new_for_test(url, 16, Duration::from_secs(3), 1)
        .refresh_remote_provenance()
        .expect_err("missing block hash must fail closed");
    assert_eq!(error.failure_kind(), RpcFailureKind::Decode);
}

#[test]
fn refresh_rejects_a_malformed_block_hash() {
    let (url, _hits) = spawn_mock_rpc(Arc::new(|_idx, req| {
        let result = match req.get("method").and_then(Value::as_str) {
            Some("eth_chainId") => json!("0x1"),
            Some("eth_getBlockByNumber") => {
                block_with_hash("0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
            }
            _ => Value::Null,
        };
        (200, rpc_result(req, result))
    }));

    let error = ForkDb::new_for_test(url, 16, Duration::from_secs(3), 1)
        .refresh_remote_provenance()
        .expect_err("31-byte block hash must fail closed");
    assert_eq!(error.failure_kind(), RpcFailureKind::Decode);
}

#[test]
fn rate_limit_is_terminal_and_fails_closed() {
    let (url, hits) = spawn_mock_rpc(Arc::new(|_idx, req| {
        (
            429,
            json!({
                "jsonrpc": "2.0",
                "id": req.get("id").cloned().unwrap_or(json!(1)),
                "error": { "code": -32005, "message": "rate limit exceeded" },
            }),
        )
    }));

    let db = ForkDb::new_for_test(url, 16, Duration::from_secs(3), 3);
    let err = db
        .refresh_remote_provenance()
        .expect_err("429 must fail closed");
    assert_eq!(err.failure_kind(), RpcFailureKind::RateLimited);
    assert!(is_live_rpc_failure(&err));
    // Rate limits are terminal: no silent retry (single request observed).
    assert_eq!(hits.load(Ordering::SeqCst), 1);
}

#[test]
fn provider_error_body_and_query_api_key_are_not_returned() {
    let (base_url, _hits) = spawn_mock_rpc(Arc::new(|_idx, req| {
        (
            200,
            json!({
                "jsonrpc": "2.0",
                "id": req.get("id").cloned().unwrap_or(json!(1)),
                "error": {
                    "code": -32000,
                    "message": "secret-provider-body at https://user:pass@example.com/?apikey=secret-query"
                },
            }),
        )
    }));
    let separator = if base_url.contains('?') { '&' } else { '?' };
    let db = ForkDb::new_for_test(
        format!("{base_url}{separator}apikey=secret-query"),
        16,
        Duration::from_secs(3),
        1,
    );
    let error = db.refresh_remote_provenance().expect_err("provider error");
    let rendered = error.to_string();
    assert!(rendered.contains("provider details redacted"));
    assert!(!rendered.contains("secret-provider-body"));
    assert!(!rendered.contains("secret-query"));
    assert!(!rendered.contains("user:pass"));
}

#[test]
fn retry_recovers_from_transient_provider_error() {
    let ok_hash = "0x1111111111111111111111111111111111111111111111111111111111111111";
    let (url, hits) = spawn_mock_rpc(Arc::new(move |idx, req| {
        if idx == 0 {
            // Transient 500 → classified ProviderError → retryable.
            return (
                500,
                json!({
                    "jsonrpc": "2.0",
                    "id": req.get("id").cloned().unwrap_or(json!(1)),
                    "error": { "code": -32000, "message": "internal error" },
                }),
            );
        }
        let method = req.get("method").and_then(Value::as_str).unwrap_or("");
        let result = match method {
            "eth_chainId" => json!("0x1"),
            "eth_getBlockByNumber" => block_with_hash(ok_hash),
            _ => Value::Null,
        };
        (200, rpc_result(req, result))
    }));

    let db = ForkDb::new_for_test(url, 16, Duration::from_secs(3), 3);
    let prov = db
        .refresh_remote_provenance()
        .expect("retry must recover from transient 500");
    assert_eq!(prov.block_hash.as_deref(), Some(ok_hash));
    assert!(
        hits.load(Ordering::SeqCst) >= 2,
        "expected at least one retry, got {} hits",
        hits.load(Ordering::SeqCst)
    );
}

#[test]
fn archive_gap_on_null_block_fails_closed() {
    let (url, _hits) = spawn_mock_rpc(Arc::new(|_idx, req| {
        let method = req.get("method").and_then(Value::as_str).unwrap_or("");
        let result = match method {
            "eth_chainId" => json!("0x1"),
            // Pinned block missing → archive gap (not a soft miss).
            "eth_getBlockByNumber" => Value::Null,
            _ => Value::Null,
        };
        (200, rpc_result(req, result))
    }));

    let db = ForkDb::new_for_test(url, 16, Duration::from_secs(3), 1);
    let err = db
        .refresh_remote_provenance()
        .expect_err("null pinned block must fail closed");
    match &err {
        ForkDbError::Classified { kind, message } => {
            assert_eq!(*kind, RpcFailureKind::ArchiveGap);
            assert!(message.contains("archive gap"), "message={message}");
        }
        other => panic!("expected Classified ArchiveGap, got {other:?}"),
    }
    assert!(is_live_rpc_failure(&err));
}

#[test]
fn timeout_fails_closed_after_deadline() {
    let (url, hits) = spawn_mock_rpc(Arc::new(|_idx, req| {
        // Sleep past the 1s client deadline on every attempt.
        thread::sleep(Duration::from_secs(3));
        let method = req.get("method").and_then(Value::as_str).unwrap_or("");
        let result = match method {
            "eth_chainId" => json!("0x1"),
            _ => block_with_hash(
                "0x2222222222222222222222222222222222222222222222222222222222222222",
            ),
        };
        (200, rpc_result(req, result))
    }));

    let db = ForkDb::new_for_test(url, 16, Duration::from_secs(1), 3);
    let err = db
        .refresh_remote_provenance()
        .expect_err("hanging provider must fail closed on timeout");
    assert_eq!(err.failure_kind(), RpcFailureKind::Timeout);
    assert!(is_live_rpc_failure(&err));
    // Timeout is retryable under Gate 4 policy: multiple attempts expected.
    assert!(
        hits.load(Ordering::SeqCst) >= 1,
        "expected at least one timed-out attempt"
    );
}

#[test]
fn rpc_redirects_are_not_followed() {
    let (url, target_hits, source_worker) = spawn_redirect_rpc();
    let db = ForkDb::new_for_test(url, 16, Duration::from_secs(3), 1);
    let error = db
        .refresh_remote_provenance()
        .expect_err("redirect must not be followed");
    source_worker.join().expect("redirect source exited");
    assert_eq!(target_hits.load(Ordering::SeqCst), 0);
    assert_eq!(error.failure_kind(), RpcFailureKind::ProviderError);
}

#[test]
fn response_body_timeout_is_classified_as_timeout() {
    let (url, worker) = spawn_partial_body_rpc();
    let db = ForkDb::new_for_test(url, 16, Duration::from_secs(1), 1);
    let err = db
        .refresh_remote_provenance()
        .expect_err("stalled response body must fail closed on timeout");
    assert_eq!(err.failure_kind(), RpcFailureKind::Timeout);
    worker.join().expect("partial body server exited");
}

#[test]
fn missing_provenance_fails_closed_until_reprobed() {
    // Online snapshot with no provenance is unknown, not fresh.
    let mut snap = ForkDbCacheSnapshot {
        block_tag: "0x10".to_string(),
        accounts: vec![],
        code_by_hash: vec![],
        storage: vec![],
        block_hashes: vec![],
        provenance: Default::default(),
        content_digest: String::new(),
    };
    let err = snap
        .ensure_consistent(Some(16), None, None, None, true)
        .expect_err("missing provenance must fail closed");
    assert_eq!(err, CacheStaleReason::MissingProvenance);

    // After a successful live refresh the same shape validates.
    let (url, _hits) = spawn_mock_rpc(Arc::new(|_idx, req| {
        let method = req.get("method").and_then(Value::as_str).unwrap_or("");
        let result = match method {
            "eth_chainId" => json!("0x1"),
            "eth_getBlockByNumber" => block_with_hash(
                "0x3333333333333333333333333333333333333333333333333333333333333333",
            ),
            _ => Value::Null,
        };
        (200, rpc_result(req, result))
    }));
    let db = ForkDb::new_for_test(url, 16, Duration::from_secs(3), 1);
    let prov = db.refresh_remote_provenance().expect("reprobe");
    snap.provenance = prov;
    assert!(snap
        .ensure_consistent(Some(16), None, None, None, true)
        .is_ok());
}

#[test]
fn fork_provenance_round_trips_positional_checkpoint_encoding() {
    use rustyfuzz_evm::fork_db::ForkCacheProvenance;
    for value in [
        ForkCacheProvenance::default(),
        ForkCacheProvenance {
            provider_sanitized: "https://rpc.invalid".into(),
            block_number: Some(123),
            chain_id: Some(1),
            ..Default::default()
        },
    ] {
        let bytes = postcard::to_stdvec(&(value.clone(), 0x1234u64)).unwrap();
        let decoded: (ForkCacheProvenance, u64) = postcard::from_bytes(&bytes).unwrap();
        assert_eq!(decoded, (value, 0x1234));
    }
}

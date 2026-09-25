//! Startup must fail before execution when provenance cannot be persisted.
use std::{fs, path::PathBuf, process::Command};

use sha2::{Digest, Sha256};

struct Fixture(PathBuf);

impl Fixture {
    fn new(name: &str) -> Self {
        let root = std::env::temp_dir().join(format!(
            "rustyfuzz-cli-{name}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(&root).unwrap();
        fs::write(
            root.join("config.toml"),
            r#"
rpc_url = "not-a-url"
chain = "evm"
timeout_secs = 1
corpus_dir = "corpus"
report_dir = "reports"
llm_enabled = false
"#,
        )
        .unwrap();
        Self(root)
    }

    fn assert_startup_failure(&self, expected: &str) {
        let output = Command::new(env!("CARGO_BIN_EXE_rusty-fuzz"))
            .current_dir(&self.0)
            .args([
                "fuzz",
                "--contract",
                "0x1111111111111111111111111111111111111111",
                "--max-execs",
                "1",
                "--campaign-id",
                "test",
            ])
            .output()
            .unwrap();
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(!output.status.success(), "startup unexpectedly succeeded");
        assert!(stderr.contains(expected), "unexpected failure: {stderr}");
        assert!(
            !self.0.join("corpus").exists(),
            "engine started before manifest was persisted"
        );
        assert!(!self.0.join("reports").exists());
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

#[test]
fn unwritable_run_layout_stops_campaign() {
    let fixture = Fixture::new("layout");
    fs::write(fixture.0.join(".rustyfuzz"), b"blocking file").unwrap();
    fixture.assert_startup_failure("cannot acquire campaign ownership");
}

#[test]
fn existing_canonical_campaign_id_is_rejected_without_replacing_terminal_state() {
    let fixture = Fixture::new("reused-id");
    let run_root = fixture.0.join(".rustyfuzz/runs/test");
    fs::create_dir_all(&run_root).unwrap();
    let terminal = run_root.join("terminal_status.json");
    fs::write(
        &terminal,
        br#"{"schema_version":1,"terminal":true,"state":"failed","run_id":"test"}"#,
    )
    .unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_rusty-fuzz"))
        .current_dir(&fixture.0)
        .args([
            "fuzz",
            "--contract",
            "0x1111111111111111111111111111111111111111",
            "--max-execs",
            "1",
            "--campaign-id",
            "test",
        ])
        .output()
        .unwrap();
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(!output.status.success());
    assert!(
        stderr.contains("cannot create run artifacts"),
        "unexpected failure: {stderr}"
    );
    assert!(!run_root.join("config.json").exists());
    assert!(fs::read_to_string(&terminal)
        .unwrap()
        .contains("\"state\":\"failed\""));
}

#[test]
fn startup_failure_transitions_incomplete_run_to_failed() {
    let fixture = Fixture::new("startup-failed");
    let output = Command::new(env!("CARGO_BIN_EXE_rusty-fuzz"))
        .current_dir(&fixture.0)
        .args([
            "fuzz",
            "--contract",
            "0x1111111111111111111111111111111111111111",
            "--max-execs",
            "1",
            "--campaign-id",
            "startup-failed",
        ])
        .output()
        .unwrap();
    assert!(!output.status.success());

    let terminal = fixture
        .0
        .join(".rustyfuzz/runs/startup-failed/terminal_status.json");
    let raw = fs::read_to_string(&terminal).unwrap_or_else(|error| {
        panic!(
            "terminal status was not persisted: {error}; command error: {}",
            String::from_utf8_lossy(&output.stderr)
        )
    });
    assert!(
        raw.contains("\"state\": \"failed\""),
        "unexpected terminal state: {raw}"
    );
}

#[test]
fn persisted_config_allows_independent_hash_recomputation_and_binds_source_identity() {
    let fixture = Fixture::new("reviewable-config");
    fs::write(
        fixture.0.join("config.toml"),
        r#"
rpc_url = "https://user:rpc-secret@rpc.example.test/v2/private?token=query-secret"
chain = "evm"
timeout_secs = 1
corpus_dir = "/work/api_key=path-secret/corpus"
report_dir = "/work/api_key=path-secret/reports"
llm_enabled = false
"#,
    )
    .unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_rusty-fuzz"))
        .current_dir(&fixture.0)
        .args([
            "fuzz",
            "--contract",
            "0x1111111111111111111111111111111111111111",
            "--max-execs",
            "1",
            "--campaign-id",
            "reviewable-config",
        ])
        .env("RUSTYFUZZ_GIT_REV", "0123456789abcdef")
        .env("RUSTYFUZZ_SOURCE_DIRTY", "true")
        .env("RUSTYFUZZ_SOURCE_DIFF_SHA256", "ab".repeat(32))
        .env("RUSTYFUZZ_BINARY_SHA256", "cd".repeat(32))
        .output()
        .unwrap();
    assert!(!output.status.success());

    let manifest_path = fixture
        .0
        .join(".rustyfuzz/runs/reviewable-config/config.json");
    let raw = fs::read_to_string(&manifest_path).unwrap();
    let manifest: rustyfuzz_artifacts::RunManifest = serde_json::from_str(&raw).unwrap();
    let canonical = serde_json::to_vec(
        manifest
            .canonical_effective_config
            .as_ref()
            .expect("canonical effective config must be persisted"),
    )
    .unwrap();
    let recomputed = format!("sha256:{}", hex::encode(Sha256::digest(canonical)));

    assert_eq!(manifest.config_hash, recomputed);
    assert!(manifest
        .canonical_effective_config
        .as_ref()
        .is_some_and(|value| {
            value
                .get("schema_version")
                .and_then(serde_json::Value::as_u64)
                == Some(1)
        }));
    assert_eq!(manifest.source_identity.git_revision, "0123456789abcdef");
    assert_eq!(manifest.source_identity.source_dirty, "dirty");
    assert_eq!(
        manifest.source_identity.source_diff_sha256,
        format!("sha256:{}", "ab".repeat(32))
    );
    assert_eq!(
        manifest.source_identity.binary_sha256,
        format!("sha256:{}", "cd".repeat(32))
    );
    for forbidden in [
        "rpc-secret",
        "query-secret",
        "path-secret",
        "/v2/private",
        "api_key",
    ] {
        assert!(
            !raw.contains(forbidden),
            "config.json leaked {forbidden}: {raw}"
        );
    }
}

#[test]
fn failed_manifest_publish_stops_campaign() {
    let fixture = Fixture::new("manifest");
    let manifest = fixture.0.join(".rustyfuzz/runs/test/config.json");
    fs::create_dir_all(&manifest).unwrap();
    fixture.assert_startup_failure("cannot create run artifacts");
    assert!(manifest.is_dir());
}

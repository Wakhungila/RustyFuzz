//! Startup must fail before execution when provenance cannot be persisted.
use std::{fs, path::PathBuf, process::Command};

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
    fixture.assert_startup_failure("cannot create run artifacts");
}

#[test]
fn failed_manifest_publish_stops_campaign() {
    let fixture = Fixture::new("manifest");
    let manifest = fixture.0.join(".rustyfuzz/runs/test/config.json");
    fs::create_dir_all(&manifest).unwrap();
    fixture.assert_startup_failure("cannot persist run manifest");
    assert!(manifest.is_dir());
}

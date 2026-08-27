//! Versioned run manifest.
//!
//! Global invariant #7: the manifest records *provenance* (tool versions,
//! configuration, target, chain/fork identity) so a run can be interpreted
//! later. Secrets are deliberately excluded (`Environment` carries sanitized
//! key names only).

use crate::fsutil::write_json_atomic;
use serde::{Deserialize, Serialize};
use std::path::Path;

/// Current manifest schema version. Bump on any breaking field change and
/// document the migration in `docs/ARTIFACT_FORMAT.md`.
pub const RUN_MANIFEST_SCHEMA_VERSION: u32 = 1;

/// Sanitized environment provenance: variable NAMES relevant to the run,
/// never values (secret-leakage policy).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Environment {
    /// Names of environment variables that influenced this run (e.g.
    /// `RUSTYFUZZ_CAMPAIGN_SHUTDOWN_GRACE_SECS`). Values are not recorded.
    pub env_var_names: Vec<String>,
}

/// Versioned run manifest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RunManifest {
    pub schema_version: u32,
    /// Assigned human-readable/correlatable run identifier.
    pub run_id: String,
    /// RustyFuzz crate version that produced this run.
    pub rustyfuzz_version: String,
    /// Optional VCS revision of the producing build (if embedded at compile
    /// time); kept free-form so CI can inject it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub git_revision: Option<String>,
    /// Hash of the effective configuration document.
    pub config_hash: String,
    /// Fuzzing mode label (e.g. `exploration`, `proof`).
    pub mode: String,
    /// Execution backend identity (`evm`; svm/sgx are unsupported).
    pub backend: String,
    /// Chain id when known from fork provenance.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub chain_id: Option<u64>,
    /// Fork block when forking.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fork_block: Option<u64>,
    /// RPC origin WITHOUT credentials/query — `scheme://host` or
    /// `scheme://host:port` only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rpc_endpoint_sanitized: Option<String>,
    /// Hashes of ABI / bytecode material used.
    #[serde(default)]
    pub abi_hash: Option<String>,
    #[serde(default)]
    pub bytecode_hash: Option<String>,
    /// RNG seed if determinism was requested.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rng_seed: Option<u64>,
    /// Documented execution assumptions (e.g. synthetic fallback allowed).
    #[serde(default)]
    pub assumptions: Vec<String>,
    /// Sanitized environment provenance.
    #[serde(default)]
    pub environment: Environment,
}

impl RunManifest {
    /// Builds a v1 manifest.
    #[allow(clippy::too_many_arguments)]
    pub fn v1(
        run_id: impl Into<String>,
        rustyfuzz_version: impl Into<String>,
        config_hash: impl Into<String>,
        mode: impl Into<String>,
    ) -> Self {
        Self {
            schema_version: RUN_MANIFEST_SCHEMA_VERSION,
            run_id: run_id.into(),
            rustyfuzz_version: rustyfuzz_version.into(),
            git_revision: None,
            config_hash: config_hash.into(),
            mode: mode.into(),
            backend: "evm".to_string(),
            chain_id: None,
            fork_block: None,
            rpc_endpoint_sanitized: None,
            abi_hash: None,
            bytecode_hash: None,
            rng_seed: None,
            assumptions: Vec::new(),
            environment: Environment::default(),
        }
    }

    /// Persists the manifest atomically as JSON at `path`.
    pub fn persist(&self, path: &Path) -> Result<(), crate::FsUtilError> {
        write_json_atomic(path, self)
    }

    /// Loads a manifest, rejecting unknown future schema versions rather than
    /// guessing field semantics.
    pub fn load(path: &Path) -> Result<Self, ManifestError> {
        let bytes = std::fs::read(path)?;
        let manifest: Self = serde_json::from_slice(&bytes)
            .map_err(|err| ManifestError::Malformed(err.to_string()))?;
        if manifest.schema_version > RUN_MANIFEST_SCHEMA_VERSION {
            return Err(ManifestError::UnsupportedSchema {
                found: manifest.schema_version,
                supported_max: RUN_MANIFEST_SCHEMA_VERSION,
            });
        }
        Ok(manifest)
    }
}

/// Manifest load failures.
#[derive(Debug)]
pub enum ManifestError {
    Io(std::io::Error),
    Malformed(String),
    UnsupportedSchema { found: u32, supported_max: u32 },
}

impl std::fmt::Display for ManifestError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ManifestError::Io(err) => write!(f, "io error: {err}"),
            ManifestError::Malformed(detail) => write!(f, "malformed manifest: {detail}"),
            ManifestError::UnsupportedSchema {
                found,
                supported_max,
            } => write!(
                f,
                "manifest schema v{found} unsupported (max supported v{supported_max})"
            ),
        }
    }
}

impl std::error::Error for ManifestError {}

impl From<std::io::Error> for ManifestError {
    fn from(err: std::io::Error) -> Self {
        ManifestError::Io(err)
    }
}

/// Strips credentials, query strings, and paths from an RPC URL, keeping only
/// `scheme://host[:port]`.
///
/// Used for provenance that must not leak API keys embedded in URLs.
pub fn sanitize_rpc_endpoint(rpc_url: &str) -> String {
    let (scheme, rest) = match rpc_url.split_once("://") {
        Some((scheme, rest)) => (scheme, rest),
        None => ("", rpc_url),
    };
    let authority = rest.split(['/', '?', '#']).next().unwrap_or(rest);
    // Drop userinfo (`user:pass@host`) keeping host[:port].
    let host = authority.rsplit('@').next().unwrap_or(authority);
    if scheme.is_empty() {
        host.to_string()
    } else {
        format!("{scheme}://{host}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> RunManifest {
        let mut m = RunManifest::v1(
            "run-1",
            env!("CARGO_PKG_VERSION"),
            "cfg-hash",
            "exploration",
        );
        m.fork_block = Some(19_123_456);
        m.rpc_endpoint_sanitized = Some(sanitize_rpc_endpoint(
            "https://key@eth.llamarpc.com/v2/abc?k=secret",
        ));
        m.rng_seed = Some(7);
        m.assumptions.push("synthetic_fallback=false".to_string());
        m.environment
            .env_var_names
            .push("RUSTYFUZZ_STARTUP_RPC_TIMEOUT_SECS".to_string());
        m
    }

    #[test]
    fn manifest_round_trips_and_carries_schema_version() {
        let dir = std::env::temp_dir().join(format!("rustyfuzz-manifest-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("manifest.json");
        let manifest = sample();
        manifest.persist(&path).unwrap();

        let raw = std::fs::read_to_string(&path).unwrap();
        assert!(raw.contains("\"schema_version\": 1"));

        let loaded = RunManifest::load(&path).unwrap();
        assert_eq!(loaded, manifest);

        // No secrets leaked into the persisted file.
        assert!(!raw.contains("secret"));
        assert!(!raw.contains("/v2/abc"));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn future_schema_versions_are_rejected_not_guessed() {
        let dir =
            std::env::temp_dir().join(format!("rustyfuzz-manifest-future-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("manifest.json");
        let mut future = sample();
        future.schema_version = RUN_MANIFEST_SCHEMA_VERSION + 5;
        future.persist(&path).unwrap();

        assert!(matches!(
            RunManifest::load(&path),
            Err(ManifestError::UnsupportedSchema { .. })
        ));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn sanitizes_credentials_paths_and_queries_from_rpc_urls() {
        assert_eq!(
            sanitize_rpc_endpoint("https://APIKEY@api.example.com/v2/xyz?token=sekret"),
            "https://api.example.com"
        );
        assert_eq!(
            sanitize_rpc_endpoint("http://user:pass@127.0.0.1:8545"),
            "http://127.0.0.1:8545"
        );
        assert_eq!(
            sanitize_rpc_endpoint("https://example.com"),
            "https://example.com"
        );
    }
}

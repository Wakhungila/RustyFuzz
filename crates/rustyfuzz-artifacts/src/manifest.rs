//! Versioned run manifest.
//!
//! Global invariant #7: the manifest records *provenance* (tool versions,
//! configuration, target, chain/fork identity) so a run can be interpreted
//! later. Secrets are deliberately excluded (`Environment` carries sanitized
//! key names only).

use crate::fsutil::write_json_atomic;
use serde::{Deserialize, Serialize};
use std::fs::{self, OpenOptions};
use std::io::Read;
use std::path::Path;

/// Current manifest schema version. Bump on any breaking field change and
/// document the migration in `docs/ARTIFACT_FORMAT.md`.
pub const RUN_MANIFEST_SCHEMA_VERSION: u32 = 2;
const MAX_MANIFEST_BYTES: u64 = 16 * 1024 * 1024;

/// Privacy-safe identity of the source and executable that produced a run.
///
/// Values are read from explicit environment inputs only; normal execution
/// never invokes a VCS command. Missing or invalid values are represented by
/// the literal `unknown` so absence is not mistaken for a clean source tree.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SourceIdentity {
    pub git_revision: String,
    pub source_dirty: String,
    pub source_diff_sha256: String,
    pub binary_sha256: String,
}

impl Default for SourceIdentity {
    fn default() -> Self {
        Self::unknown()
    }
}

impl SourceIdentity {
    pub fn unknown() -> Self {
        Self {
            git_revision: "unknown".to_string(),
            source_dirty: "unknown".to_string(),
            source_diff_sha256: "unknown".to_string(),
            binary_sha256: "unknown".to_string(),
        }
    }

    /// Reads source identity from explicit, privacy-safe runtime inputs.
    pub fn from_environment() -> Self {
        Self::from_environment_with(|name| std::env::var(name).ok())
    }

    pub fn is_resume_bindable(&self) -> bool {
        let revision_valid =
            validate_revision(&self.git_revision).as_deref() == Some(self.git_revision.as_str());
        let binary_valid =
            validate_sha256(&self.binary_sha256).as_deref() == Some(self.binary_sha256.as_str());
        let source_valid = match self.source_dirty.as_str() {
            "clean" => {
                self.source_diff_sha256 == "unknown"
                    || validate_sha256(&self.source_diff_sha256).as_deref()
                        == Some(self.source_diff_sha256.as_str())
            }
            "dirty" => {
                validate_sha256(&self.source_diff_sha256).as_deref()
                    == Some(self.source_diff_sha256.as_str())
            }
            _ => false,
        };
        revision_valid && binary_valid && source_valid
    }

    /// Environment parser exposed for deterministic tests and alternate hosts.
    pub fn from_environment_with(lookup: impl Fn(&str) -> Option<String>) -> Self {
        let revision = lookup("RUSTYFUZZ_GIT_REV")
            .or_else(|| option_env!("RUSTYFUZZ_GIT_REV").map(str::to_string))
            .and_then(|value| validate_revision(&value));
        let source_dirty = lookup("RUSTYFUZZ_SOURCE_DIRTY").and_then(|value| match value.trim() {
            "true" | "1" | "dirty" => Some("dirty".to_string()),
            "false" | "0" | "clean" => Some("clean".to_string()),
            _ => None,
        });
        let source_diff_sha256 =
            lookup("RUSTYFUZZ_SOURCE_DIFF_SHA256").and_then(|value| validate_sha256(&value));
        let binary_sha256 =
            lookup("RUSTYFUZZ_BINARY_SHA256").and_then(|value| validate_sha256(&value));

        Self {
            git_revision: revision.unwrap_or_else(|| "unknown".to_string()),
            source_dirty: source_dirty.unwrap_or_else(|| "unknown".to_string()),
            source_diff_sha256: source_diff_sha256.unwrap_or_else(|| "unknown".to_string()),
            binary_sha256: binary_sha256.unwrap_or_else(|| "unknown".to_string()),
        }
    }
}

fn validate_revision(value: &str) -> Option<String> {
    let value = value.trim();
    let valid = (1..=128).contains(&value.len())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'));
    valid.then(|| value.to_string())
}

fn validate_sha256(value: &str) -> Option<String> {
    let value = value.trim();
    let digest = value.strip_prefix("sha256:").unwrap_or(value);
    (digest.len() == 64 && digest.bytes().all(|byte| byte.is_ascii_hexdigit()))
        .then(|| format!("sha256:{}", digest.to_ascii_lowercase()))
}

/// Effective, non-secret runtime controls selected from the environment.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuntimeEnvironmentFingerprint {
    pub core_selection: String,
    pub execution_timeout_secs: u64,
    pub startup_rpc_timeout_secs: u64,
    pub require_rpc_fork_override: Option<bool>,
    pub require_rpc_fork_effective: bool,
    pub per_input_rpc_budget: usize,
}

/// Sanitized environment provenance: secret-bearing variable values are never
/// recorded; only relevant names and explicitly non-secret runtime controls are
/// retained.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Environment {
    /// Names of environment variables that influenced this run (e.g.
    /// `RUSTYFUZZ_CAMPAIGN_SHUTDOWN_GRACE_SECS`). Values are not recorded.
    pub env_var_names: Vec<String>,
    /// Effective values of non-secret controls that materially affect runs.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub runtime: Option<RuntimeEnvironmentFingerprint>,
}

/// Effective corpus startup source recorded in run provenance.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StartupMode {
    #[default]
    Unknown,
    MainnetSeedBundle,
    HistoricalSeeds,
    AbiDerivedSeeds,
    MixedTrustedSeeds,
    SyntheticFallback,
    DeterministicLiveStateProbe,
    NoTrustedSeeds,
}

impl StartupMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Unknown => "unknown",
            Self::MainnetSeedBundle => "mainnet_seed_bundle",
            Self::HistoricalSeeds => "historical_seeds",
            Self::AbiDerivedSeeds => "abi_derived_seeds",
            Self::MixedTrustedSeeds => "mixed_trusted_seeds",
            Self::SyntheticFallback => "synthetic_fallback",
            Self::DeterministicLiveStateProbe => "deterministic_live_state_probe",
            Self::NoTrustedSeeds => "no_trusted_seeds",
        }
    }
}

/// Seed material used to initialize a campaign. Identities are non-secret
/// bundle ids or file paths; `digest` is always a SHA-256 content digest when
/// the source could be read.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SeedSourceProvenance {
    pub source: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub identity: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub digest: Option<String>,
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
    /// Hash of `canonical_effective_config`, which is persisted verbatim so a
    /// reviewer can independently recompute it.
    pub config_hash: String,
    /// Canonical, sanitized effective-config identity used to compute
    /// `config_hash`. It contains only bounded scalar/configuration identities,
    /// never RPC credentials, URL paths/queries, or raw filesystem paths.
    #[serde(default)]
    pub canonical_effective_config: Option<serde_json::Value>,
    /// Source revision, dirty state, source diff, and executable identity.
    #[serde(default)]
    pub source_identity: SourceIdentity,
    /// Fuzzing mode label (e.g. `exploration`, `proof`).
    pub mode: String,
    /// Effective corpus startup mode, such as `historical_seeds`,
    /// `abi_derived_seeds`, or `deterministic_live_state_probe`.
    #[serde(default)]
    pub startup_mode: StartupMode,
    /// Seed source identities and content digests used by the effective config.
    #[serde(default)]
    pub seed_sources: Vec<SeedSourceProvenance>,
    /// Execution backend identity (`evm`; svm/sgx are unsupported).
    pub backend: String,
    /// Chain id when known from fork provenance.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub chain_id: Option<u64>,
    /// Fork block when forking.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fork_block: Option<u64>,
    /// Block hash at fetch time (reorg detection; Gate 4).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fork_block_hash: Option<String>,
    /// Unix seconds when chain/fork state was first fetched (Gate 4).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rpc_fetched_at_unix: Option<u64>,
    /// Opaque fork-cache identity when a cache snapshot was used (Gate 4).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fork_cache_id: Option<String>,
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
            canonical_effective_config: None,
            source_identity: SourceIdentity::unknown(),
            mode: mode.into(),
            startup_mode: StartupMode::Unknown,
            seed_sources: Vec::new(),
            backend: "evm".to_string(),
            chain_id: None,
            fork_block: None,
            fork_block_hash: None,
            rpc_fetched_at_unix: None,
            fork_cache_id: None,
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
        let metadata = fs::symlink_metadata(path)?;
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            return Err(ManifestError::Malformed(
                "manifest path is not a regular file".to_string(),
            ));
        }
        if metadata.len() > MAX_MANIFEST_BYTES {
            return Err(ManifestError::Malformed(
                "manifest exceeds the size limit".to_string(),
            ));
        }
        let mut options = OpenOptions::new();
        options.read(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
        }
        let mut file = options.open(path)?;
        let opened_metadata = file.metadata()?;
        if !opened_metadata.is_file() || opened_metadata.len() > MAX_MANIFEST_BYTES {
            return Err(ManifestError::Malformed(
                "manifest changed while being read".to_string(),
            ));
        }
        let mut bytes = Vec::with_capacity(opened_metadata.len() as usize);
        file.by_ref()
            .take(MAX_MANIFEST_BYTES + 1)
            .read_to_end(&mut bytes)?;
        if bytes.len() as u64 > MAX_MANIFEST_BYTES {
            return Err(ManifestError::Malformed(
                "manifest exceeds the size limit".to_string(),
            ));
        }
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

/// Redacts credential-like path components before a path is persisted.
///
/// This intentionally errs on the side of redaction: a component that looks
/// like a key, token, password, bearer credential, or query assignment is
/// replaced rather than copied. File contents are still represented by a
/// digest where the caller has one.
pub fn sanitize_path_for_persistence(path: impl AsRef<Path>) -> String {
    let raw = path.as_ref().to_string_lossy();
    let keywords = [
        "api_key",
        "apikey",
        "access_key",
        "secret",
        "password",
        "passwd",
        "token",
        "credential",
        "private_key",
        "authorization",
        "bearer",
    ];
    raw.split('/')
        .map(|component| {
            let lower = component.to_ascii_lowercase();
            let credential_like = keywords.iter().any(|keyword| lower.contains(keyword))
                || (component.contains('=') && component.contains(':'))
                || (component.contains('@') && component.contains(':'));
            if credential_like {
                "[redacted]".to_string()
            } else {
                component.to_string()
            }
        })
        .collect::<Vec<_>>()
        .join("/")
}

/// Strips credentials, query strings, and paths from an RPC URL, keeping only
/// `scheme://host[:port]`.
///
/// Used for provenance that must not leak API keys embedded in URLs.
pub fn sanitize_rpc_endpoint(rpc_url: &str) -> String {
    const INVALID_RPC_URL: &str = "<invalid-rpc-url>";
    if rpc_url.is_empty()
        || rpc_url
            .bytes()
            .any(|byte| byte <= b' ' || byte == 0x7f || byte == b'\\')
    {
        return INVALID_RPC_URL.to_string();
    }
    let Some((scheme, rest)) = rpc_url.split_once("://") else {
        return INVALID_RPC_URL.to_string();
    };
    if !matches!(scheme, "http" | "https") {
        return INVALID_RPC_URL.to_string();
    }
    let authority = rest.split(['/', '?', '#']).next().unwrap_or_default();
    let host = authority.rsplit('@').next().unwrap_or_default();
    if host.is_empty()
        || !host.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b':' | b'[' | b']')
        })
    {
        return INVALID_RPC_URL.to_string();
    }
    format!("{scheme}://{host}")
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
        assert!(raw.contains("\"schema_version\": 2"));

        let loaded = RunManifest::load(&path).unwrap();
        assert_eq!(loaded, manifest);

        // No secrets leaked into the persisted file.
        assert!(!raw.contains("secret"));
        assert!(!raw.contains("/v2/abc"));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn manifest_persists_explicit_effective_config_provenance() {
        let mut manifest = sample();
        manifest.config_hash = format!("sha256:{}", "ab".repeat(32));
        manifest.startup_mode = StartupMode::DeterministicLiveStateProbe;
        manifest.seed_sources = vec![SeedSourceProvenance {
            source: "historical_seed_file".to_string(),
            identity: Some("seeds/history.json".to_string()),
            digest: Some(format!("sha256:{}", "cd".repeat(32))),
        }];
        manifest.abi_hash = Some(format!("sha256:{}", "ef".repeat(32)));
        manifest.bytecode_hash = Some(format!("sha256:{}", "12".repeat(32)));

        let encoded = serde_json::to_vec(&manifest).unwrap();
        let decoded: RunManifest = serde_json::from_slice(&encoded).unwrap();

        assert_eq!(decoded, manifest);
        assert_eq!(
            decoded.startup_mode,
            StartupMode::DeterministicLiveStateProbe
        );
        assert_eq!(decoded.seed_sources[0].source, "historical_seed_file");
    }

    #[test]
    fn source_identity_uses_validated_runtime_inputs_and_explicit_unknowns() {
        let supplied = SourceIdentity::from_environment_with(|name| match name {
            "RUSTYFUZZ_GIT_REV" => Some("abc123".to_string()),
            "RUSTYFUZZ_SOURCE_DIRTY" => Some("dirty".to_string()),
            "RUSTYFUZZ_SOURCE_DIFF_SHA256" => Some("ab".repeat(32)),
            "RUSTYFUZZ_BINARY_SHA256" => Some("cd".repeat(32)),
            _ => None,
        });

        assert_eq!(supplied.git_revision, "abc123");
        assert_eq!(supplied.source_dirty, "dirty");
        assert_eq!(
            supplied.source_diff_sha256,
            format!("sha256:{}", "ab".repeat(32))
        );
        assert_eq!(
            supplied.binary_sha256,
            format!("sha256:{}", "cd".repeat(32))
        );
        assert!(supplied.is_resume_bindable());

        let unknown = SourceIdentity::from_environment_with(|_| None);
        assert_eq!(unknown, SourceIdentity::unknown());
        assert!(!unknown.is_resume_bindable());
        let unsafe_revision = SourceIdentity::from_environment_with(|name| match name {
            "RUSTYFUZZ_GIT_REV" => Some("revision/with/a/secret".to_string()),
            _ => None,
        });
        assert_eq!(unsafe_revision.git_revision, "unknown");
        let mut incomplete = supplied.clone();
        incomplete.source_diff_sha256 = "unknown".to_string();
        assert!(!incomplete.is_resume_bindable());
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
    fn redacts_credential_like_path_components_before_persistence() {
        let sanitized = sanitize_path_for_persistence("/workspace/api_key=super-secret/token.json");
        assert!(!sanitized.contains("super-secret"));
        assert!(sanitized.contains("[redacted]"));
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

    #[test]
    fn malformed_rpc_values_are_replaced_instead_of_persisted() {
        for value in [
            "Bearer super-secret-credential",
            "opaque:super-secret-credential",
            "https://",
            "https://example.com/\nAuthorization: Bearer super-secret-credential",
            "://example.com",
        ] {
            let sanitized = sanitize_rpc_endpoint(value);
            assert_eq!(sanitized, "<invalid-rpc-url>");
            assert!(!sanitized.contains("super-secret-credential"));
        }
    }
}

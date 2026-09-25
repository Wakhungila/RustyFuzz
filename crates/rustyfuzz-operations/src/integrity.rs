use crate::error::{
    json_path, read_bounded_regular, safe_relative_path, verify_digest, OperationsError,
};
use crate::models::{VerificationFailure, VerificationResult};
use rustyfuzz_artifacts::{RunLayout, RunManifest, RunTerminalStatus};
use serde_json::Value;
use std::collections::HashSet;
use std::fs;
use std::path::Path;

pub fn verify_campaign(
    config: &crate::models::OperationConfig,
    campaign_id: &str,
) -> Result<VerificationResult, OperationsError> {
    verify_run_root(&config.runs_root(), campaign_id, config.max_file_bytes)
}

pub fn verify_run_root(
    runs_root: &Path,
    campaign_id: &str,
    max_file_bytes: u64,
) -> Result<VerificationResult, OperationsError> {
    let mut result = VerificationResult {
        schema_version: crate::models::OPERATIONS_SCHEMA_VERSION,
        verified: false,
        known: false,
        checked_files: 0,
        failures: Vec::new(),
    };
    rustyfuzz_artifacts::validate_run_id(campaign_id)
        .map_err(|error| OperationsError::InvalidData(error.to_string()))?;
    let run_root = runs_root.join(campaign_id);
    let layout = RunLayout::at_root(&run_root);
    let manifest = match RunManifest::load(&layout.config_file()) {
        Ok(manifest) => manifest,
        Err(error) => {
            result.failures.push(failure(
                "manifest_unavailable",
                Some(run_root.join("config.json")),
                error.to_string(),
            ));
            return Ok(result);
        }
    };
    if manifest.schema_version > rustyfuzz_artifacts::RUN_MANIFEST_SCHEMA_VERSION {
        result.failures.push(failure(
            "manifest_schema_unsupported",
            Some(run_root.join("config.json")),
            "future manifest schema".to_string(),
        ));
        return Ok(result);
    }
    if manifest.run_id != campaign_id {
        result.failures.push(failure(
            "manifest_campaign_mismatch",
            Some(run_root.join("config.json")),
            "manifest run id does not match directory".to_string(),
        ));
        result.known = true;
        return Ok(result);
    }
    let config_path = layout.config_file();
    let _config_bytes = match read_bounded_regular(&config_path, max_file_bytes) {
        Ok(bytes) => bytes,
        Err(error) => {
            result.failures.push(failure(
                "config_unavailable",
                Some(config_path),
                error.to_string(),
            ));
            return Ok(result);
        }
    };
    result.checked_files += 1;
    let Some(canonical_config) = manifest.canonical_effective_config.as_ref() else {
        result.known = true;
        result.failures.push(failure(
            "canonical_config_missing",
            Some(config_path),
            "manifest has no canonical effective configuration".to_string(),
        ));
        return Ok(result);
    };
    let canonical_bytes = serde_json::to_vec(canonical_config).unwrap_or_default();
    if !verify_digest(&canonical_bytes, &manifest.config_hash) {
        result.known = true;
        result.failures.push(failure(
            "config_digest_mismatch",
            Some(config_path),
            "canonical configuration digest does not match manifest".to_string(),
        ));
    }
    let terminal_path = layout.terminal_status_path();
    let terminal: RunTerminalStatus = match json_path(&terminal_path, max_file_bytes) {
        Ok(status) => status,
        Err(error) => {
            result.failures.push(failure(
                "terminal_unavailable",
                Some(terminal_path.clone()),
                error.to_string(),
            ));
            return Ok(result);
        }
    };
    if let Err(error) = terminal.validate_for_run_id(campaign_id) {
        result.known = true;
        result
            .failures
            .push(failure("terminal_invalid", Some(terminal_path), error));
        return Ok(result);
    }
    if terminal.terminal != terminal.state.is_terminal() {
        result.known = true;
        result.failures.push(failure(
            "terminal_flag_mismatch",
            Some(terminal_path.clone()),
            "terminal flag does not match state".to_string(),
        ));
    }
    result.checked_files += 1;
    if !terminal.state.is_terminal() {
        result.known = true;
        result.failures.push(failure(
            "terminal_pending",
            Some(terminal_path.clone()),
            "run is still incomplete".to_string(),
        ));
        return Ok(result);
    }
    let Some(summary_path) = terminal.final_summary_path.as_deref() else {
        result.known = true;
        result.failures.push(failure(
            "summary_reference_missing",
            Some(terminal_path.clone()),
            "terminal state has no summary reference".to_string(),
        ));
        return Ok(result);
    };
    let summary_relative = match safe_relative_path(summary_path) {
        Ok(path) => path,
        Err(error) => {
            result.known = true;
            result.failures.push(failure(
                "summary_path_invalid",
                Some(terminal_path.clone()),
                error.to_string(),
            ));
            return Ok(result);
        }
    };
    let summary_path = run_root.join(&summary_relative);
    let summary_bytes = match read_bounded_regular(&summary_path, max_file_bytes) {
        Ok(bytes) => bytes,
        Err(error) => {
            result.failures.push(failure(
                "summary_unavailable",
                Some(summary_path.clone()),
                error.to_string(),
            ));
            return Ok(result);
        }
    };
    if let Some(expected) = terminal.final_summary_digest.as_deref() {
        if !verify_digest(&summary_bytes, expected) {
            result.known = true;
            result.failures.push(failure(
                "summary_digest_mismatch",
                Some(summary_path.clone()),
                "summary digest does not match terminal".to_string(),
            ));
        }
    } else {
        result.known = true;
        result.failures.push(failure(
            "summary_digest_missing",
            Some(terminal_path.clone()),
            "terminal state has no summary digest".to_string(),
        ));
    }
    let summary: Value = match serde_json::from_slice(&summary_bytes) {
        Ok(value) => value,
        Err(error) => {
            result.failures.push(failure(
                "summary_malformed",
                Some(summary_path.clone()),
                error.to_string(),
            ));
            return Ok(result);
        }
    };
    match summary.get("campaign_id").and_then(Value::as_str) {
        Some(value) if value == campaign_id => {}
        Some(_) => {
            result.known = true;
            result.failures.push(failure(
                "summary_campaign_mismatch",
                Some(summary_path.clone()),
                "summary campaign id does not match run".to_string(),
            ));
        }
        None => {
            result.known = true;
            result.failures.push(failure(
                "summary_campaign_unknown",
                Some(summary_path.clone()),
                "summary has no campaign id".to_string(),
            ));
        }
    }
    let Some(Value::Array(entries)) = summary.get("evidence_inventory") else {
        result.known = true;
        result.failures.push(failure(
            "evidence_unknown",
            Some(summary_path),
            "summary has no explicit evidence inventory".to_string(),
        ));
        return Ok(result);
    };
    if entries.is_empty() {
        result.known = true;
        result.failures.push(failure(
            "evidence_empty",
            Some(summary_path.clone()),
            "summary has no evidence inventory entries".to_string(),
        ));
    }
    let mut seen = HashSet::new();
    for entry in entries {
        let (path_text, digest) = match entry {
            Value::String(_) => {
                result.known = true;
                result.failures.push(failure(
                    "evidence_digest_missing",
                    Some(summary_path.clone()),
                    "evidence inventory entry has no digest".to_string(),
                ));
                continue;
            }
            Value::Object(entry) => match (
                entry.get("path").and_then(Value::as_str),
                entry.get("digest").and_then(Value::as_str),
            ) {
                (Some(path), Some(digest)) => (path, digest),
                (Some(_), None) => {
                    result.known = true;
                    result.failures.push(failure(
                        "evidence_digest_missing",
                        Some(summary_path.clone()),
                        "evidence inventory entry has no digest".to_string(),
                    ));
                    continue;
                }
                _ => {
                    result.known = true;
                    result.failures.push(failure(
                        "evidence_entry_invalid",
                        Some(summary_path.clone()),
                        "evidence inventory entry is malformed".to_string(),
                    ));
                    continue;
                }
            },
            _ => {
                result.known = true;
                result.failures.push(failure(
                    "evidence_entry_invalid",
                    Some(summary_path.clone()),
                    "evidence inventory entry is malformed".to_string(),
                ));
                continue;
            }
        };
        let path = match safe_relative_path(path_text) {
            Ok(path) => path,
            Err(_) => {
                result.known = true;
                result.failures.push(failure(
                    "evidence_path_invalid",
                    Some(summary_path.clone()),
                    "evidence path is not a safe relative path".to_string(),
                ));
                continue;
            }
        };
        let normalized = path.to_string_lossy().replace('\\', "/");
        if !seen.insert(normalized) {
            result.known = true;
            result.failures.push(failure(
                "evidence_path_duplicate",
                Some(summary_path.clone()),
                "evidence inventory contains a duplicate path".to_string(),
            ));
            continue;
        }
        let evidence_path = run_root.join(path);
        match read_bounded_regular(&evidence_path, max_file_bytes) {
            Ok(bytes) => {
                result.checked_files += 1;
                if !verify_digest(&bytes, digest) {
                    result.known = true;
                    result.failures.push(failure(
                        "evidence_digest_mismatch",
                        Some(evidence_path),
                        "evidence digest does not match the inventory".to_string(),
                    ));
                }
            }
            Err(error) => {
                result.known = true;
                result.failures.push(failure(
                    "evidence_unavailable",
                    Some(evidence_path),
                    error.to_string(),
                ));
            }
        }
    }
    match current_evidence_files(&run_root, &summary_relative) {
        Ok(current) => {
            for path in current.difference(&seen) {
                result.known = true;
                result.failures.push(failure(
                    "evidence_unlisted",
                    Some(run_root.join(path)),
                    "canonical evidence file is missing from the inventory".to_string(),
                ));
            }
        }
        Err(error) => {
            result.known = true;
            result.failures.push(failure(
                "evidence_scan_failed",
                Some(run_root.clone()),
                error,
            ));
        }
    }
    result.known = true;
    result.verified = result.known && result.failures.is_empty();
    Ok(result)
}

fn current_evidence_files(root: &Path, summary_relative: &Path) -> Result<HashSet<String>, String> {
    fn collect(
        root: &Path,
        directory: &Path,
        summary_relative: &Path,
        depth: usize,
        files: &mut HashSet<String>,
    ) -> Result<(), String> {
        if depth > 64 {
            return Err("evidence path depth limit exceeded".to_string());
        }
        for entry in fs::read_dir(directory)
            .map_err(|error| format!("cannot read evidence directory: {error}"))?
        {
            let entry = entry.map_err(|error| format!("cannot read evidence entry: {error}"))?;
            let path = entry.path();
            let metadata = fs::symlink_metadata(&path)
                .map_err(|error| format!("cannot inspect evidence entry: {error}"))?;
            if metadata.file_type().is_symlink() {
                return Err("canonical evidence contains a symlink".to_string());
            }
            if metadata.is_dir() {
                collect(root, &path, summary_relative, depth + 1, files)?;
                continue;
            }
            if !metadata.is_file() {
                return Err("canonical evidence contains a special file".to_string());
            }
            let relative = path
                .strip_prefix(root)
                .map_err(|_| "canonical evidence path escaped the run root".to_string())?;
            if relative == Path::new("config.json")
                || relative == Path::new("campaign_status.json")
                || relative == Path::new("terminal_status.json")
                || relative == Path::new(".terminal_status.lock")
                || relative == summary_relative
            {
                continue;
            }
            if files.len() >= 100_000 {
                return Err("canonical evidence file limit exceeded".to_string());
            }
            files.insert(relative.to_string_lossy().replace('\\', "/"));
        }
        Ok(())
    }

    let mut files = HashSet::new();
    collect(root, root, summary_relative, 0, &mut files)?;
    Ok(files)
}

fn failure(
    code: &str,
    path: Option<impl AsRef<Path>>,
    detail: impl Into<String>,
) -> VerificationFailure {
    VerificationFailure {
        code: code.to_string(),
        path: path.map(|path| path.as_ref().to_string_lossy().into_owned()),
        detail: detail.into(),
    }
}

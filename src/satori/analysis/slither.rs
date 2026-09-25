use crate::satori::error::SatoriResult;
use crate::satori::fsutil::{
    ensure_dir, redact_external_output, run_bounded_command, write_atomic_under,
    MAX_EXTERNAL_ARTIFACT_BYTES, MAX_EXTERNAL_COMMAND_TIMEOUT, MAX_EXTERNAL_OUTPUT_BYTES,
};
use crate::satori::types::{ProjectModel, ToolRun};
use std::io::Read;
use std::path::Path;
use std::process::Command;
use uuid::Uuid;

pub fn run_slither_tool(
    project: &ProjectModel,
    run_dir: &Path,
    external_opt_in: bool,
) -> SatoriResult<ToolRun> {
    if !external_opt_in {
        return Ok(ToolRun {
            tool: "slither".to_string(),
            command: "slither . --json <run>/analysis/slither.json".to_string(),
            available: false,
            success: false,
            exit_code: None,
            stdout_snippet: String::new(),
            stderr_snippet: "skipped: Slither external analysis requires explicit operator opt-in"
                .to_string(),
            artifact: None,
        });
    }
    let mut version_command = Command::new("slither");
    version_command.arg("--version");
    if !run_bounded_command(&mut version_command, MAX_EXTERNAL_COMMAND_TIMEOUT)
        .map(|output| output.status.success() && !output.timed_out)
        .unwrap_or(false)
    {
        return Ok(ToolRun {
            tool: "slither".to_string(),
            command: "slither . --json <run>/analysis/slither.json".to_string(),
            available: false,
            success: false,
            exit_code: None,
            stdout_snippet: String::new(),
            stderr_snippet: "slither is not installed or not on PATH".to_string(),
            artifact: None,
        });
    }
    let analysis_dir = run_dir.join("analysis");
    ensure_dir(&analysis_dir)?;
    let artifact = analysis_dir.join("slither.json");
    let temporary = analysis_dir.join(format!(".slither.{}.tmp", Uuid::new_v4().simple()));
    std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&temporary)?;
    let mut command = Command::new("slither");
    command
        .arg(".")
        .arg("--json")
        .arg(&temporary)
        .current_dir(&project.root);
    let output = with_temporary_cleanup(
        run_bounded_command(&mut command, MAX_EXTERNAL_COMMAND_TIMEOUT).map_err(anyhow::Error::msg),
        || cleanup_slither_temporary(&temporary),
    )?;
    let persisted = with_temporary_cleanup(
        (|| -> SatoriResult<bool> {
            if !output.status.success() {
                return Ok(false);
            }
            let mut bytes = Vec::new();
            let mut file = std::fs::File::open(&temporary)?;
            file.by_ref()
                .take((MAX_EXTERNAL_ARTIFACT_BYTES + 1) as u64)
                .read_to_end(&mut bytes)?;
            if bytes.len() > MAX_EXTERNAL_ARTIFACT_BYTES {
                return Ok(false);
            }
            let value = serde_json::from_slice::<serde_json::Value>(&bytes)
                .ok()
                .map(sanitize_json_value);
            let Some(sanitized) = value
                .and_then(|value| serde_json::to_vec(&value).ok())
                .filter(|bytes| bytes.len() <= MAX_EXTERNAL_ARTIFACT_BYTES)
            else {
                return Ok(false);
            };
            write_atomic_under(run_dir, &artifact, &sanitized)?;
            Ok(true)
        })(),
        || cleanup_slither_temporary(&temporary),
    )?;
    let mut stderr_snippet = redact_external_output(&output.stderr, MAX_EXTERNAL_OUTPUT_BYTES);
    if output.status.success() && !persisted {
        stderr_snippet.push_str("\n[slither artifact omitted: invalid or oversized output]");
    }
    if output.timed_out {
        stderr_snippet.push_str("\n[slither timed out]");
    }
    Ok(ToolRun {
        tool: "slither".to_string(),
        command: format!("slither . --json {}", artifact.display()),
        available: true,
        success: output.status.success() && !output.timed_out && persisted,

        exit_code: output.status.code(),
        stdout_snippet: redact_external_output(&output.stdout, MAX_EXTERNAL_OUTPUT_BYTES),
        stderr_snippet,
        artifact: persisted.then_some(artifact),
    })
}

fn with_temporary_cleanup<T>(
    result: SatoriResult<T>,
    cleanup: impl FnOnce() -> SatoriResult<()>,
) -> SatoriResult<T> {
    match result {
        Ok(value) => {
            cleanup()?;
            Ok(value)
        }
        Err(operation_error) => match cleanup() {
            Ok(()) => Err(operation_error),
            Err(_) => Err(anyhow::anyhow!(
                "Satori operation failed and temporary artifact cleanup failed"
            )),
        },
    }
}

fn cleanup_slither_temporary(path: &Path) -> SatoriResult<()> {
    match std::fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(_) => Err(anyhow::anyhow!("Slither temporary artifact cleanup failed")),
    }
}

fn is_sensitive_key(key: &str) -> bool {
    let key = key.to_ascii_lowercase();
    [
        "authorization",
        "bearer",
        "access_key",
        "access-key",
        "api_key",
        "api-key",
        "apikey",
        "key",
        "pass",
        "password",
        "private_key",
        "private-key",
        "privatekey",
        "secret",
        "token",
    ]
    .into_iter()
    .any(|marker| key.contains(marker))
}

fn sanitize_json_value(value: serde_json::Value) -> serde_json::Value {
    match value {
        serde_json::Value::String(value) => serde_json::Value::String(redact_external_output(
            value.as_bytes(),
            MAX_EXTERNAL_OUTPUT_BYTES,
        )),
        serde_json::Value::Array(values) => {
            serde_json::Value::Array(values.into_iter().map(sanitize_json_value).collect())
        }
        serde_json::Value::Object(values) => serde_json::Value::Object(
            values
                .into_iter()
                .map(|(key, value)| {
                    let value = if is_sensitive_key(&key) {
                        serde_json::Value::String("<redacted>".to_string())
                    } else {
                        sanitize_json_value(value)
                    };
                    (key, value)
                })
                .collect(),
        ),
        value => value,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sanitizes_sensitive_keys_recursively() {
        let value = serde_json::json!({
            "key": "key-value",
            "nested": {
                "pass": "password-value",
                "access_key": "access-value",
                "private_key": "private-value",
                "secret": "secret-value",
                "safe": "visible"
            },
            "items": [{"secret": "nested-secret"}]
        });
        let sanitized = sanitize_json_value(value);
        assert_eq!(sanitized["key"], "<redacted>");
        assert_eq!(sanitized["nested"]["pass"], "<redacted>");
        assert_eq!(sanitized["nested"]["access_key"], "<redacted>");
        assert_eq!(sanitized["nested"]["private_key"], "<redacted>");
        assert_eq!(sanitized["nested"]["secret"], "<redacted>");
        assert_eq!(sanitized["nested"]["safe"], "visible");
        assert_eq!(sanitized["items"][0]["secret"], "<redacted>");
    }

    #[test]
    fn sanitizes_oversized_sensitive_and_regular_values() {
        let oversized = "x".repeat(MAX_EXTERNAL_OUTPUT_BYTES + 1);
        let sanitized = sanitize_json_value(serde_json::json!({
            "secret": oversized,
            "description": oversized,
        }));
        assert_eq!(sanitized["secret"], "<redacted>");
        assert!(sanitized["description"].as_str().unwrap().len() <= MAX_EXTERNAL_OUTPUT_BYTES);
    }

    #[test]
    fn temporary_cleanup_treats_already_removed_files_as_clean() {
        let path =
            std::env::temp_dir().join(format!("satori-slither-test-{}", Uuid::new_v4().simple()));
        std::fs::write(&path, b"temporary").unwrap();
        std::fs::remove_file(&path).unwrap();

        cleanup_slither_temporary(&path).unwrap();
    }

    #[test]
    fn temporary_cleanup_failure_is_sanitized_and_preserves_cleanup_requirement() {
        let path =
            std::env::temp_dir().join(format!("satori-slither-test-{}", Uuid::new_v4().simple()));
        std::fs::create_dir(&path).unwrap();

        let error = with_temporary_cleanup(
            Err::<(), _>(anyhow::anyhow!("external command failed")),
            || cleanup_slither_temporary(&path),
        )
        .unwrap_err();
        let rendered = error.to_string();
        assert!(rendered.contains("temporary artifact cleanup failed"));
        assert!(!rendered.contains(&path.to_string_lossy().to_string()));
        assert!(path.exists());
        std::fs::remove_dir(&path).unwrap();
    }
}

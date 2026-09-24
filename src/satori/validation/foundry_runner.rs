use crate::common::fs_security::contained_path;
use crate::satori::error::SatoriResult;
use crate::satori::types::ToolRun;
use std::path::Path;
use std::process::Command;

pub fn foundry_assertion_failure(tool_run: &ToolRun) -> bool {
    let output = format!("{}\n{}", tool_run.stdout_snippet, tool_run.stderr_snippet);
    let normalized = output.to_ascii_lowercase();
    normalized.contains("assertion failed")
        || normalized.contains("assertionerror")
        || (normalized.contains("test result: failed")
            && !normalized.contains("compiler run failed")
            && !normalized.contains("parsererror")
            && !normalized.contains("typeerror"))
}

pub fn maybe_run_forge_test(project_root: &Path, test_path: &Path) -> SatoriResult<ToolRun> {
    crate::satori::fsutil::reject_symlink_components(project_root)?;
    let project_root = project_root.canonicalize()?;
    let candidate = if test_path.is_absolute() {
        test_path.to_path_buf()
    } else {
        project_root.join(test_path)
    };
    let test_path = contained_path(&project_root, &candidate).map_err(anyhow::Error::msg)?;
    anyhow::ensure!(
        std::fs::symlink_metadata(&test_path)?.is_file(),
        "Foundry test path is not a regular file"
    );
    let match_path = test_path
        .strip_prefix(&project_root)
        .unwrap_or(&test_path)
        .display()
        .to_string();
    if Command::new("forge").arg("--version").output().is_err() {
        return Ok(ToolRun {
            tool: "forge".to_string(),
            command: format!("forge test --match-path {match_path}"),
            available: false,
            success: false,
            exit_code: None,
            stdout_snippet: String::new(),
            stderr_snippet: "forge is not installed or not on PATH".to_string(),
            artifact: None,
        });
    }
    let output = Command::new("forge")
        .arg("test")
        .arg("--match-path")
        .arg(&match_path)
        .current_dir(&project_root)
        .output()?;
    Ok(ToolRun {
        tool: "forge".to_string(),
        command: format!("forge test --match-path {match_path}"),
        available: true,
        success: output.status.success(),
        exit_code: output.status.code(),
        stdout_snippet: String::from_utf8_lossy(&output.stdout)
            .chars()
            .take(2_000)
            .collect(),
        stderr_snippet: String::from_utf8_lossy(&output.stderr)
            .chars()
            .take(2_000)
            .collect(),
        artifact: Some(
            test_path
                .strip_prefix(&project_root)
                .unwrap_or(&test_path)
                .to_path_buf(),
        ),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tool_run(stdout: &str, stderr: &str) -> ToolRun {
        ToolRun {
            tool: "forge".to_string(),
            command: "forge test".to_string(),
            available: true,
            success: false,
            exit_code: Some(1),
            stdout_snippet: stdout.to_string(),
            stderr_snippet: stderr.to_string(),
            artifact: None,
        }
    }

    #[test]
    fn assertion_failure_is_not_classified_as_compile_failure() {
        assert!(foundry_assertion_failure(&tool_run(
            "assertion failed",
            "assertion failed"
        )));
        assert!(!foundry_assertion_failure(&tool_run(
            "",
            "Compiler run failed: ParserError"
        )));
    }
}

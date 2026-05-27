use crate::satori::error::SatoriResult;
use crate::satori::types::ToolRun;
use std::path::Path;
use std::process::Command;

pub fn maybe_run_forge_test(project_root: &Path, test_path: &Path) -> SatoriResult<ToolRun> {
    if Command::new("forge").arg("--version").output().is_err() {
        return Ok(ToolRun {
            tool: "forge".to_string(),
            command: format!("forge test --match-path {}", test_path.display()),
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
        .arg(test_path)
        .current_dir(project_root)
        .output()?;
    Ok(ToolRun {
        tool: "forge".to_string(),
        command: format!("forge test --match-path {}", test_path.display()),
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
        artifact: Some(test_path.to_path_buf()),
    })
}

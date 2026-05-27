use crate::satori::error::SatoriResult;
use crate::satori::types::{ProjectModel, ToolRun};
use std::path::Path;
use std::process::Command;

pub fn run_slither_tool(project: &ProjectModel, run_dir: &Path) -> SatoriResult<ToolRun> {
    if Command::new("slither").arg("--version").output().is_err() {
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
    std::fs::create_dir_all(&analysis_dir)?;
    let artifact = analysis_dir.join("slither.json");
    let output = Command::new("slither")
        .arg(".")
        .arg("--json")
        .arg(&artifact)
        .current_dir(&project.root)
        .output()?;
    Ok(ToolRun {
        tool: "slither".to_string(),
        command: format!("slither . --json {}", artifact.display()),
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
        artifact: artifact.exists().then_some(artifact),
    })
}

use crate::satori::error::SatoriResult;
use crate::satori::types::{ProjectModel, ProjectType, ToolRun};
use std::path::Path;
use std::process::Command;

pub fn run_foundry_tools(project: &ProjectModel, _run_dir: &Path) -> SatoriResult<Vec<ToolRun>> {
    if !matches!(
        project.project_type,
        ProjectType::Foundry | ProjectType::Mixed
    ) {
        return Ok(vec![ToolRun {
            tool: "forge".to_string(),
            command: "forge build".to_string(),
            available: false,
            success: false,
            exit_code: None,
            stdout_snippet: String::new(),
            stderr_snippet: "project is not Foundry-compatible".to_string(),
            artifact: None,
        }]);
    }
    if !tool_available("forge") {
        return Ok(vec![ToolRun {
            tool: "forge".to_string(),
            command: "forge build".to_string(),
            available: false,
            success: false,
            exit_code: None,
            stdout_snippet: String::new(),
            stderr_snippet: "forge is not installed or not on PATH".to_string(),
            artifact: None,
        }]);
    }
    Ok(vec![run_tool("forge", &["build"], &project.root)?])
}

fn tool_available(tool: &str) -> bool {
    Command::new(tool).arg("--version").output().is_ok()
}

fn run_tool(tool: &str, args: &[&str], cwd: &Path) -> SatoriResult<ToolRun> {
    let output = Command::new(tool).args(args).current_dir(cwd).output()?;
    Ok(ToolRun {
        tool: tool.to_string(),
        command: format!("{} {}", tool, args.join(" ")),
        available: true,
        success: output.status.success(),
        exit_code: output.status.code(),
        stdout_snippet: snippet(&output.stdout),
        stderr_snippet: snippet(&output.stderr),
        artifact: None,
    })
}

fn snippet(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).chars().take(2_000).collect()
}

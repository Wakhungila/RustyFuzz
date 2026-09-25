use crate::satori::error::SatoriResult;
use crate::satori::fsutil::{
    redact_external_output, run_bounded_external_command, BoundedCommandOutput,
    MAX_EXTERNAL_COMMAND_TIMEOUT, MAX_EXTERNAL_OUTPUT_BYTES,
};
use crate::satori::types::{ProjectModel, ProjectType, ToolRun};
use std::path::Path;
use std::process::Command;

pub fn run_foundry_tools(
    project: &ProjectModel,
    _run_dir: &Path,
    external_opt_in: bool,
) -> SatoriResult<Vec<ToolRun>> {
    if !external_opt_in {
        return Ok(vec![skipped_tool_run(
            "forge",
            "forge build",
            "skipped: Foundry external analysis requires explicit operator opt-in",
        )]);
    }
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

fn skipped_tool_run(tool: &str, command: &str, reason: &str) -> ToolRun {
    ToolRun {
        tool: tool.to_string(),
        command: command.to_string(),
        available: false,
        success: false,
        exit_code: None,
        stdout_snippet: String::new(),
        stderr_snippet: reason.to_string(),
        artifact: None,
    }
}

fn tool_available(tool: &str) -> bool {
    let mut command = Command::new(tool);
    command.arg("--version");
    run_bounded_external_command(&mut command, MAX_EXTERNAL_COMMAND_TIMEOUT)
        .map(|output| output.status.success() && !output.timed_out)
        .unwrap_or(false)
}

fn run_tool(tool: &str, args: &[&str], cwd: &Path) -> SatoriResult<ToolRun> {
    let mut command = Command::new(tool);
    command
        .args(args)
        .current_dir(cwd)
        .env("RUSTYFUZZ_SATORI_WRITABLE_ROOT", cwd);
    let output = run_bounded_external_command(&mut command, MAX_EXTERNAL_COMMAND_TIMEOUT)?;
    Ok(ToolRun {
        tool: tool.to_string(),
        command: format!("{} {}", tool, args.join(" ")),
        available: true,
        success: output.status.success() && !output.timed_out,
        exit_code: output.status.code(),
        stdout_snippet: snippet(&output.stdout),
        stderr_snippet: timeout_snippet(output),
        artifact: None,
    })
}

fn timeout_snippet(output: BoundedCommandOutput) -> String {
    let mut snippet = snippet(&output.stderr);
    if output.timed_out {
        if !snippet.is_empty() {
            snippet.push('\n');
        }
        snippet.push_str("[external command timed out]");
    }
    snippet
}

fn snippet(bytes: &[u8]) -> String {
    redact_external_output(bytes, MAX_EXTERNAL_OUTPUT_BYTES)
}

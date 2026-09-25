use crate::common::fs_security::contained_path;
use crate::satori::error::SatoriResult;
use crate::satori::fsutil::{
    redact_external_output, run_bounded_command, BoundedCommandOutput,
    MAX_EXTERNAL_COMMAND_TIMEOUT, MAX_EXTERNAL_OUTPUT_BYTES,
};
use crate::satori::types::ToolRun;
use std::fs;
use std::io::{Read, Write};
use std::net::{Shutdown, SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::Duration;
use uuid::Uuid;

struct ForgeRpcEndpoint {
    url: String,
    proxy: PinnedRpcProxy,
}

struct PinnedRpcProxy {
    local_addr: SocketAddr,
    stop: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
}

impl PinnedRpcProxy {
    fn start(
        pinned: SocketAddr,
        expected_host: String,
        expected_port: u16,
    ) -> std::io::Result<Self> {
        let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))?;
        let local_addr = listener.local_addr()?;
        let stop = Arc::new(AtomicBool::new(false));
        let thread_stop = Arc::clone(&stop);
        let thread = thread::spawn(move || {
            for incoming in listener.incoming() {
                if thread_stop.load(Ordering::Acquire) {
                    break;
                }
                let Ok(client) = incoming else {
                    continue;
                };
                let pinned = pinned;
                let expected_host = expected_host.clone();
                thread::spawn(move || {
                    proxy_connection(client, pinned, &expected_host, expected_port);
                });
            }
        });
        Ok(Self {
            local_addr,
            stop,
            thread: Some(thread),
        })
    }

    fn url(&self) -> String {
        format!("http://{}", self.local_addr)
    }
}

impl Drop for PinnedRpcProxy {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        let _ = TcpStream::connect_timeout(&self.local_addr, Duration::from_millis(100));
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

fn prepare_forge_rpc(raw: &str) -> anyhow::Result<ForgeRpcEndpoint> {
    let (url, addresses) =
        rustyfuzz_evm::rpc_url::resolve_rpc_url(raw, false).map_err(anyhow::Error::msg)?;
    let pinned = *addresses
        .first()
        .ok_or_else(|| anyhow::anyhow!("RPC endpoint did not resolve to an address"))?;
    let host = url
        .host_str()
        .ok_or_else(|| anyhow::anyhow!("RPC endpoint has no host"))?
        .trim_start_matches('[')
        .trim_end_matches(']')
        .to_ascii_lowercase();
    let port = url
        .port()
        .unwrap_or_else(|| if url.scheme() == "http" { 80 } else { 443 });
    let proxy = PinnedRpcProxy::start(pinned, host, port)?;
    Ok(ForgeRpcEndpoint {
        url: url.to_string(),
        proxy,
    })
}

fn configure_forge_rpc(command: &mut Command, endpoint: &ForgeRpcEndpoint) {
    let proxy_url = endpoint.proxy.url();
    command
        .env("ETH_RPC_URL", &endpoint.url)
        .env("RUSTYFUZZ_RPC_URL", &endpoint.url)
        .env("HTTPS_PROXY", &proxy_url)
        .env("https_proxy", &proxy_url)
        .env("HTTP_PROXY", &proxy_url)
        .env("http_proxy", &proxy_url)
        .env("ALL_PROXY", "")
        .env("all_proxy", "")
        .env("NO_PROXY", "")
        .env("no_proxy", "");
}

fn proxy_connection(
    mut client: TcpStream,
    pinned: SocketAddr,
    expected_host: &str,
    expected_port: u16,
) {
    let _ = client.set_read_timeout(Some(Duration::from_secs(5)));
    let mut request = Vec::with_capacity(1024);
    let mut chunk = [0_u8; 1024];
    while !request.windows(4).any(|window| window == b"\r\n\r\n") {
        let Ok(read) = client.read(&mut chunk) else {
            return;
        };
        if read == 0 || request.len().saturating_add(read) > 8192 {
            return;
        }
        request.extend_from_slice(&chunk[..read]);
    }
    let Some(request_line) = request.split(|byte| *byte == b'\r').next() else {
        return;
    };
    let request_line = String::from_utf8_lossy(request_line);
    let mut parts = request_line.split_whitespace();
    if parts.next() != Some("CONNECT")
        || !proxy_target_matches(parts.next(), expected_host, expected_port)
    {
        return;
    }
    let Ok(upstream) = TcpStream::connect_timeout(&pinned, Duration::from_secs(5)) else {
        return;
    };
    let _ = upstream.set_read_timeout(Some(Duration::from_secs(5)));
    let _ = upstream.set_write_timeout(Some(Duration::from_secs(5)));
    if client
        .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        .is_err()
    {
        return;
    }
    let client_for_upstream = client.try_clone().ok();
    let upstream_for_client = upstream.try_clone().ok();
    let (Some(client_for_upstream), Some(upstream_for_client)) =
        (client_for_upstream, upstream_for_client)
    else {
        return;
    };
    let upload = thread::spawn(move || relay(client_for_upstream, upstream));
    let download = thread::spawn(move || relay(upstream_for_client, client));
    let _ = upload.join();
    let _ = download.join();
}

fn proxy_target_matches(target: Option<&str>, expected_host: &str, expected_port: u16) -> bool {
    let Some(target) = target else {
        return false;
    };
    let Some((host, port)) = target.rsplit_once(':') else {
        return false;
    };
    let host = host
        .trim_start_matches('[')
        .trim_end_matches(']')
        .to_ascii_lowercase();
    host == expected_host && port.parse::<u16>().ok() == Some(expected_port)
}

fn relay(mut from: TcpStream, mut to: TcpStream) {
    let mut chunk = [0_u8; 16 * 1024];
    loop {
        let read = match from.read(&mut chunk) {
            Ok(0) | Err(_) => break,
            Ok(read) => read,
        };
        if to.write_all(&chunk[..read]).is_err() {
            break;
        }
    }
    let _ = to.shutdown(Shutdown::Write);
}

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

fn forge_version_is_unavailable(version: &std::io::Result<BoundedCommandOutput>) -> bool {
    match version {
        Ok(output) => output.timed_out,
        Err(_) => true,
    }
}

pub fn maybe_run_forge_test(
    project_root: &Path,
    run_dir: &Path,
    test_path: &Path,
    rpc_url: Option<&str>,
) -> SatoriResult<ToolRun> {
    crate::satori::fsutil::reject_symlink_components(project_root)?;
    let project_root = project_root.canonicalize()?;
    let run_dir = crate::satori::fsutil::canonical_run_dir_path(run_dir)?;
    let candidate = resolve_test_path(&project_root, &run_dir, test_path)?;
    let test_path = candidate;
    anyhow::ensure!(
        fs::symlink_metadata(&test_path)?.is_file(),
        "Foundry test path is not a regular file"
    );
    let match_path = test_path
        .strip_prefix(&run_dir)
        .unwrap_or(&test_path)
        .display()
        .to_string();
    let rpc_endpoint = match rpc_url.filter(|value| !value.trim().is_empty()) {
        Some(raw) => match prepare_forge_rpc(raw) {
            Ok(endpoint) => Some(endpoint),
            Err(error) => {
                return Ok(ToolRun {
                    tool: "forge".to_string(),
                    command: forge_display_command(Path::new(&match_path), None),
                    available: false,
                    success: false,
                    exit_code: None,
                    stdout_snippet: String::new(),
                    stderr_snippet: redact_external_output(
                        error.to_string().as_bytes(),
                        MAX_EXTERNAL_OUTPUT_BYTES,
                    ),
                    artifact: Some(match_path.into()),
                });
            }
        },
        None => None,
    };
    let command = forge_display_command(Path::new(&match_path), rpc_url);
    let mut version_command = Command::new("forge");
    version_command.arg("--version").current_dir(&project_root);
    let version = run_bounded_command(&mut version_command, MAX_EXTERNAL_COMMAND_TIMEOUT);
    if forge_version_is_unavailable(&version) {
        let stderr_snippet = match &version {
            Ok(output) if output.timed_out => {
                let mut snippet = redact_external_output(&output.stderr, MAX_EXTERNAL_OUTPUT_BYTES);
                if !snippet.is_empty() {
                    snippet.push('\n');
                }
                snippet.push_str("[Forge version timed out]");
                snippet
            }
            Ok(_) => String::new(),
            Err(error) => {
                redact_external_output(error.to_string().as_bytes(), MAX_EXTERNAL_OUTPUT_BYTES)
            }
        };
        return Ok(ToolRun {
            tool: "forge".to_string(),
            command,
            available: false,
            success: false,
            exit_code: None,
            stdout_snippet: String::new(),
            stderr_snippet,
            artifact: None,
        });
    }

    let stage_dir = project_root.join(format!(".rustyfuzz-satori-{}", Uuid::new_v4().simple()));
    fs::create_dir(&stage_dir)?;
    let tool_run = (|| -> SatoriResult<ToolRun> {
        crate::satori::fsutil::reject_symlink_components(&stage_dir)?;
        let staged_path = stage_dir.join(
            test_path
                .file_name()
                .ok_or_else(|| anyhow::anyhow!("Foundry test path has no file name"))?,
        );
        let copy_result = fs::copy(&test_path, &staged_path).map(|_| ());
        match copy_result {
            Ok(()) => {
                let staged_match_path = staged_path
                    .strip_prefix(&project_root)
                    .map_err(|_| anyhow::anyhow!("staged Foundry path escaped project root"))?;
                let mut command_builder = Command::new("forge");
                command_builder
                    .arg("test")
                    .arg("--match-path")
                    .arg(staged_match_path)
                    .current_dir(&project_root);
                if let Some(rpc_endpoint) = rpc_endpoint.as_ref() {
                    configure_forge_rpc(&mut command_builder, rpc_endpoint);
                }
                match run_bounded_command(&mut command_builder, MAX_EXTERNAL_COMMAND_TIMEOUT) {
                    Ok(output) => Ok(ToolRun {
                        tool: "forge".to_string(),
                        command,
                        available: true,
                        success: output.status.success() && !output.timed_out,
                        exit_code: output.status.code(),
                        stdout_snippet: redact_external_output(
                            &output.stdout,
                            MAX_EXTERNAL_OUTPUT_BYTES,
                        ),
                        stderr_snippet: timeout_snippet(output),
                        artifact: Some(match_path.into()),
                    }),
                    Err(error) => Ok(ToolRun {
                        tool: "forge".to_string(),
                        command,
                        available: true,
                        success: false,
                        exit_code: None,
                        stdout_snippet: String::new(),
                        stderr_snippet: redact_external_output(
                            error.to_string().as_bytes(),
                            MAX_EXTERNAL_OUTPUT_BYTES,
                        ),
                        artifact: Some(match_path.into()),
                    }),
                }
            }
            Err(error) => Ok(ToolRun {
                tool: "forge".to_string(),
                command,
                available: false,
                success: false,
                exit_code: None,
                stdout_snippet: String::new(),
                stderr_snippet: redact_external_output(
                    error.to_string().as_bytes(),
                    MAX_EXTERNAL_OUTPUT_BYTES,
                ),
                artifact: Some(match_path.into()),
            }),
        }
    })();
    with_stage_cleanup(&stage_dir, tool_run)
}

fn with_stage_cleanup<T>(stage_dir: &Path, result: SatoriResult<T>) -> SatoriResult<T> {
    match result {
        Ok(value) => {
            cleanup_stage_dir(stage_dir)?;
            Ok(value)
        }
        Err(operation_error) => match cleanup_stage_dir(stage_dir) {
            Ok(()) => Err(operation_error),
            Err(_) => Err(anyhow::anyhow!(
                "Satori operation failed and staged Foundry directory cleanup failed"
            )),
        },
    }
}

fn cleanup_stage_dir(path: &Path) -> SatoriResult<()> {
    match fs::remove_dir_all(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(_) => Err(anyhow::anyhow!("staged Foundry directory cleanup failed")),
    }
}

fn resolve_test_path(
    project_root: &Path,
    run_dir: &Path,
    test_path: &Path,
) -> SatoriResult<PathBuf> {
    let candidates = if test_path.is_absolute() {
        vec![(test_path.to_path_buf(), run_dir)]
    } else {
        vec![
            (run_dir.join(test_path), run_dir),
            (project_root.join(test_path), project_root),
        ]
    };
    for (candidate, containment_root) in candidates {
        match fs::symlink_metadata(&candidate) {
            Ok(metadata) => {
                anyhow::ensure!(
                    !metadata.file_type().is_symlink(),
                    "Foundry test path must not contain symlink components"
                );
                let safe_path =
                    contained_path(containment_root, &candidate).map_err(anyhow::Error::msg)?;
                anyhow::ensure!(
                    metadata.is_file(),
                    "Foundry test path is not a regular file"
                );
                return Ok(safe_path);
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => return Err(error.into()),
        }
    }
    anyhow::bail!("Foundry test path does not exist in the run or project layout")
}

fn timeout_snippet(output: BoundedCommandOutput) -> String {
    let mut snippet = redact_external_output(&output.stderr, MAX_EXTERNAL_OUTPUT_BYTES);
    if output.timed_out {
        if !snippet.is_empty() {
            snippet.push('\n');
        }
        snippet.push_str("[Forge timed out]");
    }
    snippet
}

fn forge_display_command(match_path: &Path, _rpc_url: Option<&str>) -> String {
    format!("forge test --match-path {}", match_path.display())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(unix)]
    use std::ffi::OsString;
    #[cfg(unix)]
    use std::fs;
    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;
    #[cfg(unix)]
    use std::sync::{Mutex, MutexGuard, OnceLock};
    #[cfg(unix)]
    static FAKE_FORGE_ENV_LOCK: OnceLock<Mutex<()>> = OnceLock::new();

    #[cfg(unix)]
    struct TestWorkspace {
        project_root: PathBuf,
        run_dir: PathBuf,
        test_path: PathBuf,
    }

    #[cfg(unix)]
    impl TestWorkspace {
        fn new() -> SatoriResult<Self> {
            let project_root = std::env::temp_dir().join(format!(
                "rustyfuzz-satori-forge-project-{}",
                Uuid::new_v4().simple()
            ));
            let run_dir = crate::satori::fsutil::canonical_run_root()?
                .join(format!("forge-runner-test-{}", Uuid::new_v4().simple()));
            let test_path = run_dir.join("foundry_poc/Test.t.sol");
            fs::create_dir_all(&project_root)?;
            fs::create_dir_all(test_path.parent().expect("test path has a parent"))?;
            fs::write(&test_path, b"contract SatoriPoC {}")?;
            Ok(Self {
                project_root,
                run_dir,
                test_path,
            })
        }
    }

    #[cfg(unix)]
    impl Drop for TestWorkspace {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.run_dir);
            let _ = fs::remove_dir_all(&self.project_root);
        }
    }

    #[cfg(unix)]
    struct FakeForge {
        bin_dir: PathBuf,
        args_log: PathBuf,
        cwd_log: PathBuf,
        old_path: Option<OsString>,
        old_args_log: Option<OsString>,
        old_cwd_log: Option<OsString>,
        old_mode: Option<OsString>,
        _lock: MutexGuard<'static, ()>,
    }

    #[cfg(unix)]
    impl FakeForge {
        fn install() -> SatoriResult<Self> {
            let lock = FAKE_FORGE_ENV_LOCK
                .get_or_init(|| Mutex::new(()))
                .lock()
                .map_err(|_| anyhow::anyhow!("fake forge environment lock poisoned"))?;
            let bin_dir = std::env::temp_dir().join(format!(
                "rustyfuzz-satori-fake-forge-{}",
                Uuid::new_v4().simple()
            ));
            let args_log = bin_dir.join("args.log");
            let cwd_log = bin_dir.join("cwd.log");
            let executable = bin_dir.join("forge");
            fs::create_dir_all(&bin_dir)?;
            fs::write(
                &executable,
                r#"#!/bin/sh
set -eu
printf '%s\n' "$@" >> "$FAKE_FORGE_ARGS_LOG"
printf 'eth-rpc-configured\n' >> "$FAKE_FORGE_ARGS_LOG"
printf 'proxy:%s\n' "${HTTPS_PROXY:-}" >> "$FAKE_FORGE_ARGS_LOG"
printf '%s\n' "$(pwd)" >> "$FAKE_FORGE_CWD_LOG"
if [ "${1:-}" = "--version" ]; then
    exit 0
fi
if [ "${1:-}" = "test" ]; then
    printf 'staged-match-path:%s\n' "${3:-}" >> "$FAKE_FORGE_ARGS_LOG"
    if [ -f "${3:-}" ]; then
        printf 'staged-file:present\n' >> "$FAKE_FORGE_ARGS_LOG"
    fi
fi
case "${FAKE_FORGE_MODE:-success}" in
    failure)
        printf 'Compiler run failed: ParserError\n' >&2
        exit 7
        ;;
    assertion)
        printf 'assertion failed\n' >&2
        exit 1
        ;;
    success)
        printf 'Authorization: Bearer super-secret\n'
        printf '%2400s\n' ''
        exit 0
        ;;
    *)
        exit 0
        ;;
esac
"#,
            )?;
            let mut permissions = fs::metadata(&executable)?.permissions();
            permissions.set_mode(0o755);
            fs::set_permissions(&executable, permissions)?;

            let old_path = std::env::var_os("PATH");
            let old_args_log = std::env::var_os("FAKE_FORGE_ARGS_LOG");
            let old_cwd_log = std::env::var_os("FAKE_FORGE_CWD_LOG");
            let old_mode = std::env::var_os("FAKE_FORGE_MODE");
            let mut path_entries = vec![bin_dir.clone()];
            if let Some(old_path) = old_path.as_ref() {
                path_entries.extend(std::env::split_paths(old_path));
            }
            std::env::set_var("PATH", std::env::join_paths(path_entries)?);
            std::env::set_var("FAKE_FORGE_ARGS_LOG", &args_log);
            std::env::set_var("FAKE_FORGE_CWD_LOG", &cwd_log);
            std::env::set_var("FAKE_FORGE_MODE", "success");
            Ok(Self {
                bin_dir,
                args_log,
                cwd_log,
                old_path,
                old_args_log,
                old_cwd_log,
                old_mode,
                _lock: lock,
            })
        }

        fn set_mode(&self, mode: &str) {
            std::env::set_var("FAKE_FORGE_MODE", mode);
        }

        fn args(&self) -> SatoriResult<String> {
            Ok(fs::read_to_string(&self.args_log)?)
        }

        fn cwd(&self) -> SatoriResult<String> {
            Ok(fs::read_to_string(&self.cwd_log)?)
        }
    }

    #[cfg(unix)]
    impl Drop for FakeForge {
        fn drop(&mut self) {
            let restore = |name: &str, old_value: Option<OsString>| match old_value {
                Some(value) => std::env::set_var(name, value),
                None => std::env::remove_var(name),
            };
            restore("PATH", self.old_path.take());
            restore("FAKE_FORGE_ARGS_LOG", self.old_args_log.take());
            restore("FAKE_FORGE_CWD_LOG", self.old_cwd_log.take());
            restore("FAKE_FORGE_MODE", self.old_mode.take());
            let _ = fs::remove_dir_all(&self.bin_dir);
        }
    }

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
    fn generated_relative_poc_path_resolves_in_external_project_run_layout() -> SatoriResult<()> {
        let project_root = std::env::temp_dir().join(format!(
            "rustyfuzz-satori-project-{}",
            Uuid::new_v4().simple()
        ));
        let run_dir = crate::satori::fsutil::canonical_run_root()?
            .join(format!("path-resolution-{}", Uuid::new_v4().simple()));
        std::fs::create_dir_all(&project_root)?;
        std::fs::create_dir_all(run_dir.join("foundry_poc"))?;
        let test_path = run_dir.join("foundry_poc/Test.t.sol");
        std::fs::write(&test_path, b"contract Test {}")?;

        let resolved =
            resolve_test_path(&project_root, &run_dir, Path::new("foundry_poc/Test.t.sol"))?;
        assert_eq!(resolved, test_path);
        assert!(resolved.starts_with(&run_dir));

        let _ = std::fs::remove_dir_all(&run_dir);
        let _ = std::fs::remove_dir_all(&project_root);
        Ok(())
    }

    #[test]
    fn project_root_relative_test_files_resolve_with_project_containment() -> SatoriResult<()> {
        let project_root = std::env::temp_dir().join(format!(
            "rustyfuzz-satori-project-path-{}",
            Uuid::new_v4().simple()
        ));
        let run_dir = crate::satori::fsutil::canonical_run_root()?
            .join(format!("project-path-{}", Uuid::new_v4().simple()));
        std::fs::create_dir_all(project_root.join("test"))?;
        std::fs::create_dir_all(&run_dir)?;
        let test_path = project_root.join("test/Project.t.sol");
        std::fs::write(&test_path, b"contract ProjectTest {}")?;

        let resolved = resolve_test_path(&project_root, &run_dir, Path::new("test/Project.t.sol"))?;
        assert_eq!(resolved, test_path.canonicalize()?);
        assert!(resolved.starts_with(&project_root.canonicalize()?));

        let _ = std::fs::remove_dir_all(&run_dir);
        let _ = std::fs::remove_dir_all(&project_root);
        Ok(())
    }

    #[test]
    fn run_relative_test_files_cannot_escape_run_dir() -> SatoriResult<()> {
        let project_root = std::env::temp_dir().join(format!(
            "rustyfuzz-satori-project-escape-{}",
            Uuid::new_v4().simple()
        ));
        let run_dir = crate::satori::fsutil::canonical_run_root()?
            .join(format!("escape-path-{}", Uuid::new_v4().simple()));
        std::fs::create_dir_all(&project_root)?;
        std::fs::create_dir_all(&run_dir)?;
        let outside = run_dir.parent().expect("run parent").join("outside.t.sol");
        std::fs::write(&outside, b"contract Outside {}")?;

        assert!(resolve_test_path(&project_root, &run_dir, Path::new("../outside.t.sol")).is_err());

        let _ = std::fs::remove_file(outside);
        let _ = std::fs::remove_dir_all(&run_dir);
        let _ = std::fs::remove_dir_all(&project_root);
        Ok(())
    }

    #[test]
    fn forge_output_snippets_are_bounded_and_redacted() {
        let output = redact_external_output(
            b"Authorization: Bearer super-secret\nassertion failed",
            MAX_EXTERNAL_OUTPUT_BYTES,
        );
        assert!(!output.contains("super-secret"));
        assert!(output.contains("assertion failed"));
    }

    #[test]
    fn forge_fork_url_is_validated_before_any_forge_spawn() {
        assert!(rustyfuzz_evm::rpc_url::validate_rpc_url_for_argv("https://8.8.8.8").is_ok());
        assert!(rustyfuzz_evm::rpc_url::validate_rpc_url_for_argv("https://8.8.8.8/v1").is_err());
        assert!(rustyfuzz_evm::rpc_url::validate_rpc_url_for_argv("https://10.0.0.1/v1").is_err());
        assert!(rustyfuzz_evm::rpc_url::validate_rpc_url_for_argv(
            "https://8.8.8.8/v1?apikey=secret"
        )
        .is_err());
    }

    #[test]
    fn forge_rpc_is_environment_only_and_proxy_pinned() -> anyhow::Result<()> {
        let endpoint = prepare_forge_rpc("https://8.8.8.8/v1?apikey=secret")?;
        let mut command = Command::new("forge");
        configure_forge_rpc(&mut command, &endpoint);
        let envs = command
            .get_envs()
            .map(|(key, value)| {
                (
                    key.to_string_lossy().into_owned(),
                    value.map(|value| value.to_string_lossy().into_owned()),
                )
            })
            .collect::<std::collections::HashMap<_, _>>();
        assert_eq!(
            envs.get("ETH_RPC_URL").and_then(|value| value.as_deref()),
            Some("https://8.8.8.8/v1?apikey=secret")
        );
        assert!(envs
            .get("HTTPS_PROXY")
            .and_then(|value| value.as_deref())
            .is_some_and(|value| value.starts_with("http://127.0.0.1:")));
        assert!(envs
            .get("NO_PROXY")
            .and_then(|value| value.as_deref())
            .is_some_and(str::is_empty));
        assert!(proxy_target_matches(Some("8.8.8.8:443"), "8.8.8.8", 443));
        assert!(!proxy_target_matches(
            Some("other.example:443"),
            "8.8.8.8",
            443
        ));
        Ok(())
    }

    #[test]
    fn pinned_proxy_forwards_only_to_the_validated_socket() -> anyhow::Result<()> {
        let upstream = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))?;
        let pinned = upstream.local_addr()?;
        let upstream_thread = thread::spawn(move || {
            let (mut stream, _) = upstream.accept().expect("upstream accept");
            let mut request = [0_u8; 4];
            stream.read_exact(&mut request).expect("upstream request");
            assert_eq!(&request, b"ping");
            stream.write_all(b"pong").expect("upstream response");
            stream.shutdown(Shutdown::Write).ok();
        });
        let proxy = PinnedRpcProxy::start(pinned, "rpc.example.com".to_string(), pinned.port())?;
        let mut client = TcpStream::connect(proxy.local_addr)?;
        client.set_read_timeout(Some(Duration::from_secs(5)))?;
        client.write_all(
            format!(
                "CONNECT rpc.example.com:{} HTTP/1.1\r\nHost: rpc.example.com\r\n\r\n",
                pinned.port()
            )
            .as_bytes(),
        )?;
        let mut response = Vec::new();
        let mut response_chunk = [0_u8; 256];
        while !response.windows(4).any(|window| window == b"\r\n\r\n") {
            let read = client.read(&mut response_chunk)?;
            if read == 0 {
                break;
            }
            response.extend_from_slice(&response_chunk[..read]);
        }
        assert!(response.starts_with(b"HTTP/1.1 200 Connection Established"));
        client.write_all(b"ping")?;
        let mut echoed = [0_u8; 4];
        client.read_exact(&mut echoed)?;
        assert_eq!(&echoed, b"pong");
        drop(client);
        upstream_thread.join().expect("upstream thread");
        Ok(())
    }

    #[test]
    fn forge_command_never_contains_rpc_url_or_credential() {
        let command = forge_display_command(
            Path::new("foundry_poc/Test.t.sol"),
            Some("https://8.8.8.8/v1?apikey=secret"),
        );
        assert!(!command.contains("8.8.8.8"));
        assert!(!command.contains("secret"));
        assert!(!command.contains("--fork-url"));
    }
    #[cfg(unix)]
    #[test]
    fn fake_forge_executes_staged_poc_from_project_cwd_and_bounds_redacts_output(
    ) -> SatoriResult<()> {
        let workspace = TestWorkspace::new()?;
        let fake = FakeForge::install()?;
        fake.set_mode("success");

        let result = maybe_run_forge_test(
            &workspace.project_root,
            &workspace.run_dir,
            Path::new("foundry_poc/Test.t.sol"),
            Some("https://8.8.8.8/v1"),
        )?;

        assert!(result.available);
        assert!(result.success);
        assert_eq!(result.exit_code, Some(0));
        assert!(result.command.contains("foundry_poc/Test.t.sol"));
        assert!(!result.command.contains("8.8.8.8"));
        assert!(!result.command.contains("--fork-url"));
        assert!(result.stdout_snippet.contains("<redacted>"));
        assert!(!result.stdout_snippet.contains("super-secret"));
        assert!(result.stdout_snippet.len() <= MAX_EXTERNAL_OUTPUT_BYTES);
        assert!(result.stderr_snippet.is_empty());

        let args = fake.args()?;
        assert!(args.contains("--version"));
        assert!(args.contains("test\n"));
        assert!(args.contains("--match-path\n"));
        assert!(args.contains(".rustyfuzz-satori-"));
        assert!(args.contains("staged-match-path:"));
        assert!(args.contains("staged-file:present"));
        assert!(args.contains("eth-rpc-configured"));
        assert!(args.contains("proxy:http://127.0.0.1:"));
        assert!(!args.contains("super-secret"));

        let cwd = fake.cwd()?;
        let expected_cwd = workspace.project_root.canonicalize()?;
        assert_eq!(cwd.lines().count(), 2);
        assert!(cwd.lines().all(|line| Path::new(line) == expected_cwd));

        let stage_dirs = fs::read_dir(&workspace.project_root)?
            .filter_map(Result::ok)
            .filter(|entry| {
                entry
                    .file_name()
                    .to_str()
                    .is_some_and(|name| name.starts_with(".rustyfuzz-satori-"))
            })
            .count();
        assert_eq!(stage_dirs, 0, "staged forge directory was not cleaned up");
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn fake_forge_failure_is_available_but_not_successful() -> SatoriResult<()> {
        let workspace = TestWorkspace::new()?;
        let fake = FakeForge::install()?;
        fake.set_mode("failure");

        let result = maybe_run_forge_test(
            &workspace.project_root,
            &workspace.run_dir,
            &workspace.test_path,
            None,
        )?;

        assert!(result.available);
        assert!(!result.success);
        assert_eq!(result.exit_code, Some(7));
        assert!(result
            .stderr_snippet
            .contains("Compiler run failed: ParserError"));
        assert!(!foundry_assertion_failure(&result));
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn fake_forge_assertion_failure_is_classified_separately_from_compile_failure(
    ) -> SatoriResult<()> {
        let workspace = TestWorkspace::new()?;
        let fake = FakeForge::install()?;
        fake.set_mode("assertion");

        let result = maybe_run_forge_test(
            &workspace.project_root,
            &workspace.run_dir,
            &workspace.test_path,
            None,
        )?;

        assert!(result.available);
        assert!(!result.success);
        assert!(foundry_assertion_failure(&result));
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn credential_bearing_fork_url_is_supplied_only_through_child_environment() -> SatoriResult<()>
    {
        let workspace = TestWorkspace::new()?;
        let fake = FakeForge::install()?;

        let result = maybe_run_forge_test(
            &workspace.project_root,
            &workspace.run_dir,
            &workspace.test_path,
            Some("https://8.8.8.8/v1?apikey=secret"),
        )?;

        assert!(result.available);
        assert!(result.success);
        assert!(!result.command.contains("secret"));
        assert!(!result.command.contains("--fork-url"));
        let args = fake.args()?;
        assert!(args.contains("eth-rpc-configured"));
        assert!(!args.contains("secret"));
        Ok(())
    }

    #[test]
    fn forge_version_timeout_is_unavailable() -> SatoriResult<()> {
        let status = Command::new("sh").args(["-c", "exit 0"]).status()?;
        let timed_out = BoundedCommandOutput {
            status,
            timed_out: true,
            stdout: Vec::new(),
            stderr: Vec::new(),
            stdout_truncated: false,
            stderr_truncated: false,
        };
        assert!(forge_version_is_unavailable(&Ok(timed_out)));
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn forge_timeout_is_classified_without_waiting_for_the_production_timeout() -> SatoriResult<()>
    {
        let mut command = Command::new("sh");
        command.args(["-c", "exit 1"]);
        let status = command.status()?;
        let snippet = timeout_snippet(BoundedCommandOutput {
            status,
            timed_out: true,
            stdout: Vec::new(),
            stderr: b"partial forge output".to_vec(),
            stdout_truncated: false,
            stderr_truncated: false,
        });
        assert!(snippet.contains("partial forge output"));
        assert!(snippet.ends_with("[Forge timed out]"));
        assert!(!status.success());
        Ok(())
    }

    #[test]
    fn external_forge_execution_is_opt_in_by_default() {
        let config = crate::satori::types::SatoriConfig::default();
        assert!(!config.run_forge_tests);
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

    #[test]
    fn stage_cleanup_treats_already_removed_directories_as_clean() {
        let path = std::env::temp_dir().join(format!(
            "satori-foundry-stage-test-{}",
            Uuid::new_v4().simple()
        ));
        std::fs::create_dir(&path).unwrap();
        std::fs::remove_dir(&path).unwrap();

        cleanup_stage_dir(&path).unwrap();
    }

    #[test]
    fn stage_cleanup_failure_is_sanitized_and_preserves_cleanup_requirement() {
        let path = std::env::temp_dir().join(format!(
            "satori-foundry-stage-test-{}",
            Uuid::new_v4().simple()
        ));
        std::fs::write(&path, b"not a directory").unwrap();

        let error =
            with_stage_cleanup(&path, Err::<(), _>(anyhow::anyhow!("forge command failed")))
                .unwrap_err();
        let rendered = error.to_string();
        assert!(rendered.contains("staged Foundry directory cleanup failed"));
        assert!(!rendered.contains(&path.to_string_lossy().to_string()));
        assert!(path.exists());
        std::fs::remove_file(&path).unwrap();
    }
}

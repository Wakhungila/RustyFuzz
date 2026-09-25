use crate::common::fs_security::{contained_path, identifier_path, validate_filesystem_identifier};
use crate::satori::error::SatoriResult;
use chrono::Utc;
use serde::de::DeserializeOwned;
use serde::Serialize;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::{Mutex, OnceLock};
use std::thread;
use std::time::{Duration, Instant};
use uuid::Uuid;

static MEMORY_APPEND_LOCK: OnceLock<Mutex<()>> = OnceLock::new();

pub fn new_run_id(prefix: &str) -> String {
    let safe_prefix: String = prefix
        .chars()
        .filter(|character| {
            character.is_ascii_alphanumeric() || matches!(character, '-' | '_' | '.')
        })
        .take(100)
        .collect();
    let safe_prefix = if safe_prefix.is_empty() {
        "run"
    } else {
        safe_prefix.as_str()
    };
    format!(
        "{safe_prefix}-{}-{}",
        Utc::now().format("%Y%m%d-%H%M%S"),
        Uuid::new_v4()
    )
}

pub fn new_run_id_checked(prefix: &str) -> SatoriResult<String> {
    let run_id = format!(
        "{}-{}-{}",
        prefix,
        Utc::now().format("%Y%m%d-%H%M%S"),
        Uuid::new_v4()
    );
    validate_filesystem_identifier(&run_id).map_err(anyhow::Error::msg)?;
    Ok(run_id)
}

pub fn validate_identifier(identifier: &str) -> SatoriResult<()> {
    validate_filesystem_identifier(identifier).map_err(anyhow::Error::msg)
}

pub fn safe_identifier_path(root: &Path, identifier: &str) -> SatoriResult<PathBuf> {
    identifier_path(root, identifier).map_err(anyhow::Error::msg)
}

pub fn ensure_dir(path: impl AsRef<Path>) -> SatoriResult<()> {
    let path = path.as_ref();
    reject_symlink_components(path)?;
    fs::create_dir_all(path)?;
    reject_symlink_components(path)?;
    Ok(())
}

pub fn canonical_run_root() -> SatoriResult<PathBuf> {
    let root = PathBuf::from("satori/runs");
    if root.exists() {
        anyhow::ensure!(
            !fs::symlink_metadata(&root)?.file_type().is_symlink(),
            "Satori run root must not be a symlink"
        );
    }
    ensure_dir(&root)?;
    let canonical = fs::canonicalize(&root)?;
    anyhow::ensure!(
        fs::symlink_metadata(&canonical)?.is_dir(),
        "Satori run root is not a directory"
    );
    Ok(canonical)
}

pub fn canonical_run_dir(run_id: &str) -> SatoriResult<PathBuf> {
    validate_identifier(run_id)?;
    let root = canonical_run_root()?;
    let run_dir = identifier_path(&root, run_id).map_err(anyhow::Error::msg)?;
    anyhow::ensure!(
        run_dir.starts_with(&root) && run_dir.is_dir(),
        "Satori run directory is not contained beneath the canonical run root"
    );
    Ok(run_dir)
}

pub fn canonical_run_dir_path(run_dir: &Path) -> SatoriResult<PathBuf> {
    let root = canonical_run_root()?;
    let run_dir = contained_path(&root, run_dir).map_err(anyhow::Error::msg)?;
    let metadata = fs::symlink_metadata(&run_dir)?;
    anyhow::ensure!(
        metadata.is_dir() && !metadata.file_type().is_symlink(),
        "Satori run directory is not a regular directory"
    );
    Ok(run_dir)
}

pub fn write_json<T: Serialize>(path: impl AsRef<Path>, value: &T) -> SatoriResult<()> {
    let redacted = redact_serialized_value(value)?;
    rustyfuzz_artifacts::fsutil::write_json_atomic(path.as_ref(), &redacted)?;
    Ok(())
}

pub fn write_json_under<T: Serialize>(root: &Path, path: &Path, value: &T) -> SatoriResult<()> {
    let safe_path = contained_path(root, path).map_err(anyhow::Error::msg)?;
    let redacted = redact_serialized_value(value)?;
    rustyfuzz_artifacts::fsutil::write_json_atomic(&safe_path, &redacted)?;
    Ok(())
}

pub fn write_json_in_run<T: Serialize>(
    run_dir: &Path,
    relative_path: &Path,
    value: &T,
) -> SatoriResult<()> {
    let run_dir = canonical_run_dir_path(run_dir)?;
    write_json_under(&canonical_run_root()?, &run_dir.join(relative_path), value)
}

pub fn write_text_under(root: &Path, path: &Path, value: &str) -> SatoriResult<()> {
    let safe_path = contained_path(root, path).map_err(anyhow::Error::msg)?;
    let redacted = redact_source_text(value);
    rustyfuzz_artifacts::fsutil::write_atomic(&safe_path, redacted.as_bytes())?;
    Ok(())
}

pub fn write_text_in_run(run_dir: &Path, relative_path: &Path, value: &str) -> SatoriResult<()> {
    let run_dir = canonical_run_dir_path(run_dir)?;
    write_text_under(&canonical_run_root()?, &run_dir.join(relative_path), value)
}

pub fn write_atomic_under(root: &Path, path: &Path, bytes: &[u8]) -> SatoriResult<()> {
    let safe_path = contained_path(root, path).map_err(anyhow::Error::msg)?;
    rustyfuzz_artifacts::fsutil::write_atomic(&safe_path, bytes)?;
    Ok(())
}

pub fn read_json_under<T: DeserializeOwned>(root: &Path, path: &Path) -> SatoriResult<T> {
    Ok(serde_json::from_slice(&read_bytes_under(root, path)?)?)
}

pub fn read_json_in_run<T: DeserializeOwned>(
    run_dir: &Path,
    relative_path: &Path,
) -> SatoriResult<T> {
    let run_dir = canonical_run_dir_path(run_dir)?;
    read_json_under(&canonical_run_root()?, &run_dir.join(relative_path))
}

pub fn read_bytes_under(root: &Path, path: &Path) -> SatoriResult<Vec<u8>> {
    let canonical_root = fs::canonicalize(root)?;
    let safe_path = contained_path(&canonical_root, path).map_err(anyhow::Error::msg)?;
    let metadata = fs::symlink_metadata(&safe_path)?;
    anyhow::ensure!(
        metadata.is_file() && !metadata.file_type().is_symlink(),
        "Satori run artifact is not a regular file: {}",
        safe_path.display()
    );
    anyhow::ensure!(
        metadata.len() <= MAX_PERSISTED_JSON_BYTES,
        "Satori persisted JSON artifact exceeds the {MAX_PERSISTED_JSON_BYTES} byte limit"
    );
    let file = fs::File::open(&safe_path)?;
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    let read = file
        .take(MAX_PERSISTED_JSON_BYTES + 1)
        .read_to_end(&mut bytes)?;
    anyhow::ensure!(
        bytes.len() as u64 <= MAX_PERSISTED_JSON_BYTES
            && read as u64 <= MAX_PERSISTED_JSON_BYTES + 1,
        "Satori persisted JSON artifact exceeds the {MAX_PERSISTED_JSON_BYTES} byte limit"
    );
    Ok(bytes)
}

pub fn append_bytes_under(path: &Path, bytes: &[u8]) -> SatoriResult<()> {
    let _guard = MEMORY_APPEND_LOCK
        .get_or_init(|| Mutex::new(()))
        .lock()
        .map_err(|_| anyhow::anyhow!("Satori memory append lock is poisoned"))?;
    reject_symlink_components(path)?;
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    ensure_dir(parent)?;
    let canonical_parent = fs::canonicalize(parent)?;
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| anyhow::anyhow!("Satori memory path has no valid file name"))?;
    let safe_path = canonical_parent.join(file_name);
    let mut existing = Vec::new();
    if safe_path.exists() {
        existing = read_bytes_under(&canonical_parent, &safe_path)?;
    }
    let separator_len = usize::from(!existing.is_empty() && !existing.ends_with(b"\n"));
    let trailing_newline_len = usize::from(!bytes.ends_with(b"\n"));
    let projected_len = existing
        .len()
        .checked_add(bytes.len())
        .and_then(|length| length.checked_add(separator_len + trailing_newline_len))
        .ok_or_else(|| anyhow::anyhow!("Satori memory size calculation overflow"))?;
    anyhow::ensure!(
        projected_len as u64 <= MAX_PERSISTED_JSON_BYTES,
        "Satori memory append would exceed the {MAX_PERSISTED_JSON_BYTES} byte persisted size limit"
    );
    if separator_len != 0 {
        existing.push(b'\n');
    }
    existing.extend_from_slice(bytes);
    if !bytes.ends_with(b"\n") {
        existing.push(b'\n');
    }
    rustyfuzz_artifacts::fsutil::write_atomic(&safe_path, existing)?;
    Ok(())
}

pub fn read_dir_under(root: &Path, path: &Path) -> SatoriResult<std::fs::ReadDir> {
    let safe_path = contained_path(root, path).map_err(anyhow::Error::msg)?;
    let metadata = fs::symlink_metadata(&safe_path)?;
    anyhow::ensure!(
        metadata.is_dir() && !metadata.file_type().is_symlink(),
        "Satori directory is not a regular directory: {}",
        safe_path.display()
    );
    Ok(fs::read_dir(safe_path)?)
}

pub fn reject_symlink_components(path: &Path) -> SatoriResult<()> {
    let mut current = Some(path.to_path_buf());
    while let Some(candidate) = current {
        if let Ok(metadata) = fs::symlink_metadata(&candidate) {
            anyhow::ensure!(
                !metadata.file_type().is_symlink(),
                "Satori artifact path contains a symlink"
            );
        }
        current = candidate.parent().map(Path::to_path_buf);
    }
    Ok(())
}

pub fn write_text(path: impl AsRef<Path>, value: &str) -> SatoriResult<()> {
    let redacted = redact_source_text(value);
    rustyfuzz_artifacts::fsutil::write_atomic(path.as_ref(), redacted.as_bytes())?;
    Ok(())
}

pub fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

pub const MAX_INGEST_FILES: usize = 10_000;
pub const MAX_INGEST_DEPTH: usize = 64;
pub const MAX_INGEST_TOTAL_BYTES: u64 = 512 * 1024 * 1024;
pub const MAX_INGEST_FILE_BYTES: u64 = 8 * 1024 * 1024;
pub const MAX_PERSISTED_JSON_BYTES: u64 = 64 * 1024 * 1024;
pub const MAX_EXTERNAL_OUTPUT_BYTES: usize = 2_000;
pub const MAX_EXTERNAL_ARTIFACT_BYTES: usize = 4 * 1024 * 1024;
pub const MAX_EXTERNAL_COMMAND_TIMEOUT: Duration = Duration::from_secs(120);
const PROCESS_TERMINATION_TIMEOUT: Duration = Duration::from_secs(1);
const READER_POLL_INTERVAL: Duration = Duration::from_millis(10);

#[derive(Debug)]
pub struct BoundedCommandOutput {
    pub status: ExitStatus,
    pub timed_out: bool,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    pub stdout_truncated: bool,
    pub stderr_truncated: bool,
}

pub fn run_bounded_command(
    command: &mut Command,
    timeout: Duration,
) -> std::io::Result<BoundedCommandOutput> {
    run_bounded_command_with_output_limit(command, timeout, MAX_EXTERNAL_OUTPUT_BYTES)
}

struct CommandOutputFile {
    path: PathBuf,
    file: Option<fs::File>,
}

impl CommandOutputFile {
    fn new() -> std::io::Result<Self> {
        for _ in 0..8 {
            let path = std::env::temp_dir().join(format!(
                "rustyfuzz-satori-command-{}-{}",
                std::process::id(),
                Uuid::new_v4()
            ));
            match fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&path)
            {
                Ok(file) => {
                    return Ok(Self {
                        path,
                        file: Some(file),
                    })
                }
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(error) => return Err(error),
            }
        }
        Err(std::io::Error::other(
            "could not allocate a temporary external-command output file",
        ))
    }
}

impl Drop for CommandOutputFile {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
    }
}

pub fn run_bounded_command_with_output_limit(
    command: &mut Command,
    timeout: Duration,
    max_output_bytes: usize,
) -> std::io::Result<BoundedCommandOutput> {
    // Regular files avoid a reader thread and a pipe whose EOF can be held by an
    // escaped descendant. This works on Unix systems without /proc, while the
    // output read itself remains bounded.
    let mut stdout = CommandOutputFile::new()?;
    let mut stderr = CommandOutputFile::new()?;
    command
        .stdout(Stdio::from(stdout.file.take().ok_or_else(|| {
            std::io::Error::other("external command stdout file was already moved")
        })?))
        .stderr(Stdio::from(stderr.file.take().ok_or_else(|| {
            std::io::Error::other("external command stderr file was already moved")
        })?));
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        command.process_group(0);
    }
    let mut child = command.spawn()?;

    let deadline = Instant::now() + timeout;
    let (status, timed_out, output_limit_exceeded) = loop {
        if output_files_exceed(&stdout.path, &stderr.path, max_output_bytes)? {
            let status = stop_child(&mut child)?;
            break (status, false, true);
        }
        if let Some(status) = child.try_wait()? {
            terminate_process_group(&mut child)?;
            break (status, false, false);
        }
        if Instant::now() >= deadline {
            let status = stop_child(&mut child)?;
            break (status, true, false);
        }
        thread::sleep(READER_POLL_INTERVAL);
    };

    let stdout_result = read_output_file(&stdout.path, max_output_bytes);
    let stderr_result = read_output_file(&stderr.path, max_output_bytes);
    let (stdout, stdout_truncated) = stdout_result?;
    let (stderr, stderr_truncated) = stderr_result?;
    Ok(BoundedCommandOutput {
        status,
        timed_out,
        stdout,
        stderr,
        stdout_truncated: stdout_truncated || output_limit_exceeded,
        stderr_truncated: stderr_truncated || output_limit_exceeded,
    })
}

fn output_files_exceed(stdout: &Path, stderr: &Path, max_bytes: usize) -> std::io::Result<bool> {
    Ok(fs::metadata(stdout)?.len() > max_bytes as u64
        || fs::metadata(stderr)?.len() > max_bytes as u64)
}

fn stop_child(child: &mut Child) -> std::io::Result<ExitStatus> {
    if let Err(error) = terminate_process_group(child) {
        let _ = child.kill();
        return Err(error);
    }
    if child.try_wait()?.is_none() {
        child.kill().map_err(|error| {
            std::io::Error::other(format!("external command termination failed: {error}"))
        })?;
    }
    wait_for_child_until(child, Instant::now() + PROCESS_TERMINATION_TIMEOUT)?
        .ok_or_else(|| std::io::Error::other("external command did not terminate after timeout"))
}

fn read_output_file(path: &Path, max_bytes: usize) -> std::io::Result<(Vec<u8>, bool)> {
    let file = fs::File::open(path)?;
    let mut output = Vec::with_capacity(max_bytes.min(64 * 1024));
    let read = file
        .take(max_bytes.saturating_add(1) as u64)
        .read_to_end(&mut output)?;
    let truncated = read > max_bytes || output.len() > max_bytes;
    output.truncate(max_bytes);
    Ok((output, truncated))
}

fn wait_for_child_until(
    child: &mut Child,
    deadline: Instant,
) -> std::io::Result<Option<ExitStatus>> {
    loop {
        if let Some(status) = child.try_wait()? {
            return Ok(Some(status));
        }
        if Instant::now() >= deadline {
            return Ok(None);
        }
        thread::sleep(READER_POLL_INTERVAL);
    }
}

fn terminate_process_group(child: &mut Child) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        let process_group = -(child.id() as i32);
        // SAFETY: the child was started in its own process group, so the
        // negative PID targets that group and the signal argument is valid.
        let result = unsafe { libc::kill(process_group, libc::SIGKILL) };
        if result == 0 {
            return Ok(());
        }
        let error = std::io::Error::last_os_error();
        if error.raw_os_error() == Some(libc::ESRCH) {
            Ok(())
        } else {
            Err(std::io::Error::other(format!(
                "external command process-group termination failed: {error}"
            )))
        }
    }
    #[cfg(not(unix))]
    {
        if child.try_wait()?.is_none() {
            child.kill()?;
        }
        Ok(())
    }
}

pub fn collect_files(root: &Path) -> SatoriResult<Vec<PathBuf>> {
    let root = fs::canonicalize(root)?;
    let mut files = Vec::new();
    let mut total_bytes = 0u64;
    collect_files_inner(&root, &root, 0, &mut files, &mut total_bytes)?;
    files.sort();
    Ok(files)
}

fn collect_files_inner(
    root: &Path,
    path: &Path,
    depth: usize,
    files: &mut Vec<PathBuf>,
    total_bytes: &mut u64,
) -> SatoriResult<()> {
    anyhow::ensure!(
        depth <= MAX_INGEST_DEPTH,
        "Satori project exceeds the {MAX_INGEST_DEPTH} directory-depth budget"
    );
    if should_ignore(path) {
        return Ok(());
    }
    for entry in fs::read_dir(path)? {
        let entry = entry?;
        let entry_path = entry.path();
        let metadata = fs::symlink_metadata(&entry_path)?;
        anyhow::ensure!(
            !metadata.file_type().is_symlink(),
            "Satori project contains symlink entry: {}",
            entry_path.display()
        );
        if should_ignore(&entry_path) {
            continue;
        }
        if metadata.is_dir() {
            collect_files_inner(root, &entry_path, depth + 1, files, total_bytes)?;
        } else {
            anyhow::ensure!(
                metadata.is_file(),
                "Satori project entry is not a regular file: {}",
                entry_path.display()
            );
            anyhow::ensure!(
                metadata.len() <= MAX_INGEST_FILE_BYTES,
                "Satori project file exceeds the {MAX_INGEST_FILE_BYTES} byte budget: {}",
                entry_path.display()
            );
            anyhow::ensure!(
                files.len() < MAX_INGEST_FILES,
                "Satori project exceeds the {MAX_INGEST_FILES} file-count budget"
            );
            *total_bytes = total_bytes
                .checked_add(metadata.len())
                .ok_or_else(|| anyhow::anyhow!("Satori project byte budget overflow"))?;
            anyhow::ensure!(
                *total_bytes <= MAX_INGEST_TOTAL_BYTES,
                "Satori project exceeds the {MAX_INGEST_TOTAL_BYTES} total-byte budget"
            );
            let canonical = fs::canonicalize(&entry_path)?;
            anyhow::ensure!(
                canonical.starts_with(root),
                "Satori project file escapes canonical root: {}",
                entry_path.display()
            );
            files.push(canonical);
        }
    }
    Ok(())
}

pub fn redact_external_output(bytes: &[u8], max_bytes: usize) -> String {
    let truncated = bytes.len() > max_bytes;
    let bounded = String::from_utf8_lossy(&bytes[..bytes.len().min(max_bytes)]);
    let mut redacted = bounded
        .split_inclusive('\n')
        .map(redact_external_line)
        .collect::<String>();
    if truncated {
        redacted.push_str(&format!("\n[output truncated at {max_bytes} bytes]"));
    }
    truncate_utf8_to_bytes(&mut redacted, max_bytes);
    redacted
}

pub(crate) fn redact_external_line(line: &str) -> String {
    let url_redacted = if contains_http_url(line) {
        rustyfuzz_evm::rpc_url::redact_rpc_error(line)
    } else {
        line.to_string()
    };
    let lower = url_redacted.to_ascii_lowercase();
    credential_marker_start(&lower)
        .into_iter()
        .chain(composite_credential_marker_start(&lower))
        .min()
        .map_or_else(
            || url_redacted.clone(),
            |marker_start| {
                let prefix = url_redacted.get(..marker_start).unwrap_or("");
                format!("{prefix}<redacted>")
            },
        )
}

const SENSITIVE_KEY_WORDS: &[&str] = &[
    "apikey",
    "accesskey",
    "authorization",
    "bearer",
    "credential",
    "mnemonic",
    "passphrase",
    "passwd",
    "password",
    "private",
    "privatekey",
    "refresh",
    "secret",
    "seed",
    "signing",
    "signingkey",
    "token",
];

const SENSITIVE_KEY_PREFIXES: &[&str] = &[
    "access",
    "api",
    "client",
    "encryption",
    "private",
    "refresh",
    "signing",
];

const SENSITIVE_COMPOUND_KEYS: &[&str] = &[
    "apitoken",
    "passwordhash",
    "secretvalue",
    "accesskey",
    "privatekey",
    "signingkey",
    "encryptionkey",
    "clientsecret",
    "accesstoken",
    "refreshtoken",
    "seedphrase",
];

/// Redacts source text while preserving ordinary prose and surrounding source structure.
pub fn redact_source_text(text: &str) -> String {
    let text = if contains_http_url(text) {
        rustyfuzz_evm::rpc_url::redact_rpc_error(text)
    } else {
        text.to_string()
    };
    let text = text.as_str();
    let lower = text.to_ascii_lowercase();
    if lower.contains("-----begin") {
        if let Some(marker) = lower.find("private key-----") {
            let end = marker + "private key-----".len();
            return format!("{}<redacted>", &text[..end]);
        }
    }
    if let Ok(value) = serde_json::from_str::<Value>(text) {
        if let Ok(redacted) = serde_json::to_string(&redact_json_value(value)) {
            return redacted;
        }
    }
    redact_source_assignments(text)
}

fn redact_serialized_value<T: Serialize>(value: &T) -> SatoriResult<Value> {
    Ok(redact_json_value(serde_json::to_value(value)?))
}

fn redact_json_value(value: Value) -> Value {
    match value {
        Value::Object(mut object) => {
            let sensitive_keys = object
                .keys()
                .filter(|key| is_sensitive_key_name(key))
                .cloned()
                .collect::<Vec<_>>();
            for key in &sensitive_keys {
                object.insert(key.clone(), Value::String("<redacted>".to_string()));
            }
            for (key, child) in object.iter_mut() {
                if !sensitive_keys.iter().any(|sensitive| sensitive == key) {
                    *child = redact_json_value(child.take());
                }
            }
            Value::Object(object)
        }
        Value::Array(values) => Value::Array(values.into_iter().map(redact_json_value).collect()),
        Value::String(value) => Value::String(redact_source_text(&value)),
        value => value,
    }
}

fn is_sensitive_key_name(name: &str) -> bool {
    let words = split_key_words(name);
    let normalized = words.concat();
    words
        .iter()
        .any(|word| SENSITIVE_KEY_WORDS.contains(&word.as_str()))
        || SENSITIVE_COMPOUND_KEYS.contains(&normalized.as_str())
        || words.last().is_some_and(|word| {
            word == "key"
                && words
                    .iter()
                    .any(|word| SENSITIVE_KEY_PREFIXES.contains(&word.as_str()))
        })
        || words.as_slice() == ["key"]
}

fn split_key_words(name: &str) -> Vec<String> {
    let mut words = Vec::new();
    let mut current = String::new();
    let mut previous_lower = false;
    for character in name
        .trim_matches(|character| character == '"' || character == '\'')
        .chars()
    {
        if !character.is_ascii_alphanumeric() {
            if !current.is_empty() {
                words.push(std::mem::take(&mut current));
            }
            previous_lower = false;
            continue;
        }
        if character.is_ascii_uppercase() && previous_lower && !current.is_empty() {
            words.push(std::mem::take(&mut current));
        }
        current.push(character.to_ascii_lowercase());
        previous_lower = character.is_ascii_lowercase() || character.is_ascii_digit();
    }
    if !current.is_empty() {
        words.push(current);
    }
    words
}

fn redact_source_assignments(text: &str) -> String {
    let mut output = String::with_capacity(text.len());
    let mut copied_until = 0;
    let mut search = 0;
    while let Some((key_start, key_end, value_start, quoted_key)) =
        find_sensitive_assignment(text, search)
    {
        let (replacement, end) = redact_value(text, value_start, quoted_key);
        output.push_str(&text[copied_until..key_start]);
        output.push_str(&text[key_start..value_start]);
        output.push_str(&replacement);
        copied_until = end;
        search = end.max(key_end).max(value_start + 1);
        if search >= text.len() {
            break;
        }
    }
    output.push_str(&text[copied_until..]);
    output
}

fn find_sensitive_assignment(text: &str, search: usize) -> Option<(usize, usize, usize, bool)> {
    let bytes = text.as_bytes();
    let mut index = search;
    while index < bytes.len() {
        if let Some((key_start, key_end, key, quoted)) = quoted_key_at(text, index) {
            if is_sensitive_key_name(key) {
                if let Some(value_start) = assignment_value_start(bytes, key_end) {
                    return Some((key_start, key_end, value_start, quoted));
                }
            }
            // A quoted ordinary string can contain an escaped quoted key. Do
            // not skip over its contents when the outer quote is not a key.
            index = if assignment_value_start(bytes, key_end).is_some() {
                key_end
            } else {
                index + 1
            };
            continue;
        }
        if is_key_start(bytes[index]) {
            let key_start = index;
            while index < bytes.len() && is_key_char(bytes[index]) {
                index += 1;
            }
            let key_end = index;
            if is_sensitive_key_name(&text[key_start..key_end]) {
                if let Some(value_start) = assignment_value_start(bytes, key_end) {
                    return Some((key_start, key_end, value_start, false));
                }
            }
            continue;
        }
        index += 1;
    }
    None
}

fn quoted_key_at(text: &str, index: usize) -> Option<(usize, usize, &str, bool)> {
    let bytes = text.as_bytes();
    if index + 1 < bytes.len() && bytes[index] == b'\\' && bytes[index + 1] == b'"' {
        let mut end = index + 2;
        while end + 1 < bytes.len() {
            if bytes[end] == b'\\' && bytes[end + 1] == b'"' {
                return Some((index, end + 2, &text[index + 2..end], true));
            }
            end += 1;
        }
        return None;
    }
    let quote = *bytes.get(index)?;
    if quote != b'"' && quote != b'\'' {
        return None;
    }
    let mut escaped = false;
    let mut end = index + 1;
    while end < bytes.len() {
        if escaped {
            escaped = false;
        } else if bytes[end] == b'\\' {
            escaped = true;
        } else if bytes[end] == quote {
            return Some((index, end + 1, &text[index + 1..end], true));
        }
        end += 1;
    }
    None
}

fn is_key_start(byte: u8) -> bool {
    byte.is_ascii_alphabetic() || byte == b'_'
}

fn is_key_char(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'-'
}

fn assignment_value_start(bytes: &[u8], key_end: usize) -> Option<usize> {
    let mut value_start = key_end;
    while value_start < bytes.len() && bytes[value_start].is_ascii_whitespace() {
        value_start += 1;
    }
    if bytes.get(value_start) == Some(&b'=') {
        value_start += 1;
        if bytes.get(value_start) == Some(&b'>') {
            value_start += 1;
        }
    } else if bytes.get(value_start) == Some(&b':') {
        value_start += 1;
    } else {
        return None;
    }
    while value_start < bytes.len() && bytes[value_start].is_ascii_whitespace() {
        value_start += 1;
    }
    (value_start < bytes.len()).then_some(value_start)
}

fn redact_value(text: &str, value_start: usize, quoted_key: bool) -> (String, usize) {
    let bytes = text.as_bytes();
    let first = bytes[value_start];
    if first == b'"' || first == b'\'' {
        let quote = first;
        let mut escaped = false;
        let mut end = value_start + 1;
        while end < bytes.len() {
            if escaped {
                escaped = false;
            } else if bytes[end] == b'\\' {
                escaped = true;
            } else if bytes[end] == quote {
                return (
                    format!("{}<redacted>{}", quote as char, quote as char),
                    end + 1,
                );
            }
            end += 1;
        }
        return (format!("{}<redacted>", quote as char), text.len());
    }
    if first == b'[' || first == b'{' {
        let open = first as char;
        let close = matching_delimiter(open);
        let mut stack = vec![open];
        let mut quote = None;
        let mut escaped = false;
        let mut end = value_start + 1;
        while end < bytes.len() {
            let byte = bytes[end];
            if let Some(active_quote) = quote {
                if escaped {
                    escaped = false;
                } else if byte == b'\\' {
                    escaped = true;
                } else if byte == active_quote {
                    quote = None;
                }
                end += 1;
                continue;
            }
            if byte == b'"' || byte == b'\'' {
                quote = Some(byte);
            } else if byte == b'[' || byte == b'{' {
                stack.push(byte as char);
            } else if (byte == b']' || byte == b'}')
                && stack
                    .last()
                    .is_some_and(|open| matching_delimiter(*open) == byte as char)
            {
                stack.pop();
                if stack.is_empty() {
                    return (format!("{open}<redacted>{close}"), end + 1);
                }
            }
            end += 1;
        }
        return ("<redacted>".to_string(), text.len());
    }
    let mut end = value_start;
    while end < bytes.len() {
        let byte = bytes[end];
        if byte == b'\n' || byte == b'\r' || byte == b';' || (quoted_key && byte == b',') {
            break;
        }
        end += 1;
    }
    if end == value_start {
        end += 1;
    }
    ("<redacted>".to_string(), end)
}

fn matching_delimiter(open: char) -> char {
    match open {
        '[' => ']',
        '{' => '}',
        _ => '\0',
    }
}

fn contains_http_url(value: &str) -> bool {
    value
        .as_bytes()
        .windows(7)
        .any(|window| window.eq_ignore_ascii_case(b"http://"))
        || value
            .as_bytes()
            .windows(8)
            .any(|window| window.eq_ignore_ascii_case(b"https://"))
}

fn credential_marker_start(value: &str) -> Option<usize> {
    let markers = [
        "authorization",
        "bearer",
        "access_key",
        "api_key",
        "api-key",
        "apikey",
        "password",
        "private_key",
        "privatekey",
        "credential",
        "secret",
        "token",
        "pass",
        "key",
    ];
    for marker in markers {
        let mut start = 0;
        while let Some(relative) = value[start..].find(marker) {
            let index = start + relative;
            let before_ok = index == 0
                || !value[..index]
                    .chars()
                    .next_back()
                    .is_some_and(|character| character.is_ascii_alphanumeric() || character == '_');
            let after = value[index + marker.len()..].chars().next();
            let after_ok = after
                .is_none_or(|character| matches!(character, '=' | ':' | ' ' | '\t' | '\r' | '\n'));
            if before_ok && after_ok {
                return Some(index);
            }
            start = index + marker.len();
        }
    }
    None
}

fn composite_credential_marker_start(lower: &str) -> Option<usize> {
    SENSITIVE_COMPOUND_KEYS
        .iter()
        .filter_map(|marker| {
            let index = lower.find(marker)?;
            let before_ok = index == 0
                || !lower[..index]
                    .chars()
                    .next_back()
                    .is_some_and(|character| character.is_ascii_alphanumeric() || character == '_');
            before_ok.then_some(index)
        })
        .min()
}

fn truncate_utf8_to_bytes(value: &mut String, max_bytes: usize) {
    if value.len() <= max_bytes {
        return;
    }
    let mut end = max_bytes;
    while !value.is_char_boundary(end) {
        end -= 1;
    }
    value.truncate(end);
}

pub fn should_ignore(path: &Path) -> bool {
    path.file_name()
        .and_then(|name| name.to_str())
        .map(|name| {
            matches!(
                name,
                ".git"
                    | "node_modules"
                    | "out"
                    | "cache"
                    | "broadcast"
                    | "target"
                    | "artifacts"
                    | "typechain"
                    | ".forge-snapshots"
            )
        })
        .unwrap_or(false)
}

pub const MAX_EVIDENCE_BYTES: usize = 8 * 1024 * 1024;

pub fn read_evidence_file(root: &Path, path: &Path) -> SatoriResult<Vec<u8>> {
    let canonical_root = fs::canonicalize(root)?;
    let candidate = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()?.join(path)
    };
    let safe_path = contained_path(&canonical_root, &candidate).map_err(anyhow::Error::msg)?;
    let metadata = fs::symlink_metadata(&safe_path)?;
    anyhow::ensure!(
        metadata.is_file() && !metadata.file_type().is_symlink(),
        "Satori evidence path is not a regular file: {}",
        safe_path.display()
    );
    anyhow::ensure!(
        metadata.len() <= MAX_EVIDENCE_BYTES as u64,
        "Satori evidence file exceeds the {MAX_EVIDENCE_BYTES} byte limit"
    );
    Ok(fs::read(safe_path)?)
}

pub fn read_lossy_limited(path: &Path, max_bytes: usize) -> SatoriResult<String> {
    let file = fs::File::open(path)?;
    let mut reader = file.take(max_bytes as u64);
    let mut bytes = Vec::with_capacity(max_bytes.min(64 * 1024));
    reader.read_to_end(&mut bytes)?;
    Ok(String::from_utf8_lossy(&bytes).to_string())
}

pub fn verify_source_file_binding(
    root: &Path,
    path: &Path,
    relative_path: &Path,
    expected_hash: &str,
) -> SatoriResult<()> {
    let canonical_root = fs::canonicalize(root)?;
    let metadata = fs::symlink_metadata(path)?;
    anyhow::ensure!(
        !metadata.file_type().is_symlink() && metadata.is_file(),
        "Satori source identity is not a regular file: {}",
        path.display()
    );
    let canonical_path = contained_path(&canonical_root, path).map_err(anyhow::Error::msg)?;
    let actual_relative = canonical_path
        .strip_prefix(&canonical_root)
        .map_err(|_| anyhow::anyhow!("Satori source identity has no relative path"))?;
    anyhow::ensure!(
        actual_relative == relative_path,
        "Satori source identity path does not match its run identity"
    );
    let bytes = read_bytes_under(&canonical_root, &canonical_path)?;
    anyhow::ensure!(
        sha256_hex(&bytes) == expected_hash,
        "Satori source identity changed after ingestion: {}",
        path.display()
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn evidence_reader_rejects_escape_symlink_and_oversized_files() -> SatoriResult<()> {
        let root =
            std::env::temp_dir().join(format!("rustyfuzz-satori-evidence-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root)?;
        let findings = root.join("findings");
        fs::create_dir_all(&findings)?;
        let evidence = findings.join("evidence.json");
        fs::write(&evidence, b"ok")?;
        assert_eq!(read_evidence_file(&findings, &evidence)?, b"ok");

        let outside = root.join("outside");
        fs::write(&outside, b"secret")?;
        assert!(read_evidence_file(&findings, &outside).is_err());

        #[cfg(unix)]
        {
            let link = findings.join("link");
            std::os::unix::fs::symlink(&outside, &link)?;
            assert!(read_evidence_file(&findings, &link).is_err());
        }

        fs::write(&evidence, vec![b'x'; MAX_EVIDENCE_BYTES + 1])?;
        assert!(read_evidence_file(&findings, &evidence).is_err());
        let _ = fs::remove_dir_all(root);
        Ok(())
    }

    #[test]
    fn lossy_reader_honors_requested_byte_limit() -> SatoriResult<()> {
        let path = std::env::temp_dir().join(format!(
            "rustyfuzz-satori-limited-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::write(&path, b"0123456789")?;
        assert_eq!(read_lossy_limited(&path, 4)?, "0123");
        fs::remove_file(path)?;
        Ok(())
    }

    #[test]
    fn contained_json_reader_rejects_symlink_artifacts() -> SatoriResult<()> {
        let root =
            std::env::temp_dir().join(format!("rustyfuzz-satori-contained-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root)?;
        fs::write(root.join("run.json"), br#"{"run_id":"ok"}"#)?;
        #[cfg(unix)]
        {
            std::os::unix::fs::symlink(root.join("run.json"), root.join("linked.json"))?;
            assert!(
                read_json_under::<serde_json::Value>(&root, &root.join("linked.json")).is_err()
            );
        }
        let value: serde_json::Value = read_json_under(&root, &root.join("run.json"))?;
        assert_eq!(value["run_id"], "ok");
        let _ = fs::remove_dir_all(root);
        Ok(())
    }

    #[test]
    fn memory_append_preserves_lines_and_rejects_destination_symlink() -> SatoriResult<()> {
        let root =
            std::env::temp_dir().join(format!("rustyfuzz-satori-append-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root)?;
        let path = root.join("events.jsonl");
        append_bytes_under(&path, b"{\"id\":1}")?;
        append_bytes_under(&path, b"{\"id\":2}\n")?;
        assert_eq!(fs::read(&path)?, b"{\"id\":1}\n{\"id\":2}\n");
        #[cfg(unix)]
        {
            let victim = root.join("victim");
            fs::write(&victim, b"untouched")?;
            fs::remove_file(&path)?;
            std::os::unix::fs::symlink(&victim, &path)?;
            assert!(append_bytes_under(&path, b"{\"id\":3}").is_err());
            assert_eq!(fs::read(victim)?, b"untouched");
        }
        let _ = fs::remove_dir_all(root);
        Ok(())
    }

    #[test]
    fn memory_append_rejects_prospective_persisted_size_overflow() -> SatoriResult<()> {
        let root = std::env::temp_dir().join(format!(
            "rustyfuzz-satori-append-limit-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)?
                .as_nanos()
        ));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root)?;
        let path = root.join("events.jsonl");
        let file = fs::File::create(&path)?;
        file.set_len(MAX_PERSISTED_JSON_BYTES - 1)?;
        assert!(append_bytes_under(&path, b"x\n").is_err());
        assert_eq!(fs::metadata(&path)?.len(), MAX_PERSISTED_JSON_BYTES - 1);
        let _ = fs::remove_dir_all(root);
        Ok(())
    }

    #[test]
    fn ingestion_enforces_depth_file_count_and_byte_budgets() -> SatoriResult<()> {
        let base = std::env::temp_dir().join(format!(
            "rustyfuzz-satori-budgets-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)?
                .as_nanos()
        ));
        let deep = base.join("deep");
        let deep_dir = (0..=MAX_INGEST_DEPTH + 1).fold(deep.clone(), |path, _| path.join("nested"));
        fs::create_dir_all(&deep_dir)?;
        fs::write(deep_dir.join("source.sol"), b"contract Source {}")?;
        assert!(collect_files(&deep).is_err());

        let oversized = base.join("oversized");
        fs::create_dir_all(&oversized)?;
        let file = fs::File::create(oversized.join("large.bin"))?;
        file.set_len(MAX_INGEST_FILE_BYTES + 1)?;
        assert!(collect_files(&oversized).is_err());

        let total = base.join("total");
        fs::create_dir_all(&total)?;
        let file = fs::File::create(total.join("large.bin"))?;
        file.set_len(MAX_INGEST_TOTAL_BYTES + 1)?;
        assert!(collect_files(&total).is_err());

        let count = base.join("count");
        fs::create_dir_all(&count)?;
        for index in 0..=MAX_INGEST_FILES {
            fs::write(count.join(format!("{index}.txt")), b"")?;
        }
        assert!(collect_files(&count).is_err());
        let _ = fs::remove_dir_all(base);
        Ok(())
    }
    #[test]
    fn external_tool_output_is_bounded_and_redacted() {
        let output = b"Authorization: Bearer super-secret\napikey=also-secret\nhttps://rpc.example/v1?apikey=url-secret\nnormal output";
        let redacted = redact_external_output(output, 80);
        assert!(!redacted.contains("super-secret"));
        assert!(!redacted.contains("also-secret"));
        assert!(!redacted.contains("url-secret"));
        assert!(redacted.contains("<redacted>"));
        let bounded = redact_external_output(&[b'x'; 100], 10);
        assert!(bounded.len() <= 10);
    }

    #[test]
    fn external_line_redaction_composes_url_and_credential_markers() {
        let redacted = redact_external_line(
            "HTTPS://user:pass@rpc.example/v1?access_key=url-secret Authorization: Bearer line-secret",
        );
        assert!(!redacted.contains("user:pass"));
        assert!(!redacted.contains("url-secret"));
        assert!(!redacted.contains("line-secret"));
        assert!(redacted.contains("<rpc-url>"));
        assert!(redacted.contains("<redacted>"));
        for marker in [
            "key=short-secret",
            "access_key=short-secret",
            "pass=short-secret",
            "clientSecret=client-short-secret",
            "accessToken=access-short-secret",
            "refreshToken=refresh-short-secret",
            "apiToken=api-token-secret",
            "passwordHash=password-hash-secret",
            "secretValue=secret-value-secret",
        ] {
            let redacted = redact_external_line(&format!("prefix {marker} suffix"));
            assert!(!redacted.contains("short-secret"), "{marker}");
        }
    }

    #[test]
    fn source_redaction_covers_json_keys_camel_case_and_structured_assignments() {
        let source = r#"The seed phrase is ordinary prose and the key is discussed below.
{"privateKey":"json-private","signingKey":"json-signing","encryptionKey":["json-encryption"],"seedPhrase":"json-seed-phrase","mnemonic":"json-mnemonic","seed":"json-seed"}
string signingKey = "camel-signing";
string encryptionKey = 'camel-encryption';
seed_phrase = ["camel", "seed-phrase"];
mnemonic: "camel-mnemonic";
seed = 123456789;
escaped = "{\"privateKey\":\"escaped-secret\"}";
"#;
        let redacted = redact_source_text(source);
        for secret in [
            "json-private",
            "json-signing",
            "json-encryption",
            "json-seed-phrase",
            "json-mnemonic",
            "json-seed",
            "camel-signing",
            "camel-encryption",
            "camel-seed-phrase",
            "camel-mnemonic",
            "123456789",
            "escaped-secret",
        ] {
            assert!(
                !redacted.contains(secret),
                "{secret} remained in redacted source"
            );
        }
        assert!(redacted.contains("privateKey"));
        assert!(redacted.contains("signingKey"));
        assert!(redacted.contains("encryptionKey"));
        assert!(redacted.contains("seedPhrase"));
        assert!(redacted.contains("ordinary prose"));
    }

    #[test]
    fn compound_sensitive_keys_are_redacted_without_hiding_prose() {
        let source = r#"The key is discussed in ordinary prose.
apiToken = "api-token-secret";
passwordHash: 'password-hash-secret'
secretValue = {"inner": "secret-value-secret"};
apitoken = "lowercase-api-token-secret";
clientsecret: 'lowercase-client-secret';
passwordhash = "lowercase-password-hash";
seedphrase = 'lowercase-seed-phrase';
An apitoken, clientsecret, passwordhash, and seedphrase are discussed in ordinary prose.
"#;
        let redacted = redact_source_text(source);
        for secret in [
            "api-token-secret",
            "password-hash-secret",
            "secret-value-secret",
            "lowercase-api-token-secret",
            "lowercase-client-secret",
            "lowercase-password-hash",
            "lowercase-seed-phrase",
        ] {
            assert!(
                !redacted.contains(secret),
                "{secret} remained in redacted source"
            );
        }
        assert!(redacted.contains("ordinary prose"));
        assert!(redacted.contains("An apitoken, clientsecret, passwordhash, and seedphrase"));
        for key in [
            "apiToken",
            "passwordHash",
            "secretValue",
            "apitoken",
            "clientsecret",
            "passwordhash",
            "seedphrase",
        ] {
            assert!(redacted.contains(key), "{key} was not preserved");
        }
    }

    #[test]
    fn json_boundary_redacts_lowercase_compound_keys_but_preserves_prose() {
        let source = r#"{
            "apitoken": "json-api-token-secret",
            "clientsecret": "json-client-secret",
            "passwordhash": "json-password-hash",
            "seedphrase": "json-seed-phrase",
            "description": "An apitoken, clientsecret, passwordhash, and seedphrase are ordinary prose."
        }"#;
        let redacted = redact_source_text(source);
        for secret in [
            "json-api-token-secret",
            "json-client-secret",
            "json-password-hash",
            "json-seed-phrase",
        ] {
            assert!(!redacted.contains(secret), "{secret} remained in JSON");
        }
        assert!(redacted.contains("An apitoken, clientsecret, passwordhash, and seedphrase"));
        for key in ["apitoken", "clientsecret", "passwordhash", "seedphrase"] {
            assert!(redacted.contains(key), "{key} was not preserved");
        }
    }

    #[test]
    fn structured_redaction_ignores_delimiters_inside_quoted_values() {
        let source = r#"apiToken = {"message":"secret with { [ } ] delimiters", "nested":{"value":"nested-secret"}}; ordinary prose remains."#;
        let redacted = redact_source_text(source);
        assert!(!redacted.contains("secret with"));
        assert!(!redacted.contains("nested-secret"));
        assert!(redacted.contains("ordinary prose remains"));
    }

    #[test]
    fn persisted_json_redacts_sensitive_object_keys_and_source_strings() -> SatoriResult<()> {
        let root =
            std::env::temp_dir().join(format!("satori-redacted-json-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root)?;
        let value = serde_json::json!({
            "privateKey": "persisted-private",
            "source_snippet": r#"string mnemonic = "persisted-mnemonic";"#,
            "description": "The seed phrase is ordinary prose.",
        });
        let path = root.join("artifact.json");
        write_json_under(&root, &path, &value)?;
        let serialized = fs::read_to_string(path)?;
        assert!(!serialized.contains("persisted-private"));
        assert!(!serialized.contains("persisted-mnemonic"));
        assert!(serialized.contains("ordinary prose"));
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    #[cfg(unix)]
    fn external_command_timeout_is_bounded_when_an_escaped_descendant_holds_pipes() {
        let mut command = Command::new("/bin/sh");
        command.args(["-c", "setsid sh -c 'sleep 5' & wait"]);
        let started = std::time::Instant::now();
        let result = run_bounded_command(&mut command, Duration::from_millis(100));
        assert!(started.elapsed() < Duration::from_secs(5));
        assert!(result.is_err() || result.expect("bounded result").timed_out);
    }

    #[test]
    fn persisted_json_reader_rejects_files_before_full_allocation() -> SatoriResult<()> {
        let root = std::env::temp_dir().join(format!(
            "rustyfuzz-satori-json-limit-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root)?;
        let path = root.join("large.json");
        let file = fs::File::create(&path)?;
        file.set_len(MAX_PERSISTED_JSON_BYTES + 1)?;
        assert!(read_json_under::<serde_json::Value>(&root, &path).is_err());
        let _ = fs::remove_dir_all(root);
        Ok(())
    }

    #[test]
    fn generated_run_ids_and_job_identifiers_are_safe_segments() {
        let first = new_run_id("satori");
        let second = new_run_id("satori");
        assert_ne!(first, second);
        assert!(validate_identifier(&first).is_ok());
        assert!(validate_identifier(&second).is_ok());
        assert!(new_run_id_checked("../satori").is_err());
        assert!(validate_identifier("job-abc_1").is_ok());
        for value in ["../job", "/tmp/job", "job/name", "job\\name"] {
            assert!(validate_identifier(value).is_err(), "{value}");
        }
    }
}

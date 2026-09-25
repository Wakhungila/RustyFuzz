use std::fs;
#[cfg(target_os = "linux")]
use std::fs::OpenOptions;
use std::io;
#[cfg(target_os = "linux")]
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::Command;

#[cfg(target_os = "linux")]
use std::os::unix::ffi::OsStrExt;
#[cfg(target_os = "linux")]
use std::os::unix::process::CommandExt;

pub(crate) const EXTERNAL_MEMORY_LIMIT_BYTES: u64 = 2 * 1024 * 1024 * 1024;
pub(crate) const EXTERNAL_MAX_PROCESSES: u64 = 256;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ExternalContainmentLimits {
    pub(crate) memory_bytes: u64,
    pub(crate) max_processes: u64,
    pub(crate) output_bytes: u64,
}

impl Default for ExternalContainmentLimits {
    fn default() -> Self {
        Self {
            memory_bytes: EXTERNAL_MEMORY_LIMIT_BYTES,
            max_processes: EXTERNAL_MAX_PROCESSES,
            output_bytes: 4 * 1024 * 1024,
        }
    }
}

pub(crate) enum ExternalContainment {
    #[cfg(target_os = "linux")]
    Cgroup(CgroupGuard),
    #[cfg(target_os = "linux")]
    Bwrap(Option<CgroupGuard>),
    #[cfg(test)]
    Launcher,
}

impl ExternalContainment {
    pub(crate) fn prepare(
        command: &mut Command,
        limits: ExternalContainmentLimits,
    ) -> io::Result<Self> {
        let launcher = configured_launcher()?;
        #[cfg(not(target_os = "linux"))]
        let _ = limits;
        #[cfg(target_os = "linux")]
        {
            let cgroup = CgroupGuard::create(limits);
            if let Some(launcher) = launcher.as_ref() {
                if is_bwrap(launcher) {
                    wrap_with_bwrap(command, launcher.clone(), limits)?;
                    if let Some(cgroup) = cgroup.as_ref() {
                        attach_to_cgroup(command, cgroup)?;
                    }
                    return Ok(Self::Bwrap(cgroup));
                }
                #[cfg(test)]
                {
                    wrap_with_launcher(command, launcher.clone())?;
                    if let Some(cgroup) = cgroup.as_ref() {
                        attach_to_cgroup(command, cgroup)?;
                    }
                    return Ok(match cgroup {
                        Some(cgroup) => Self::Cgroup(cgroup),
                        None => Self::Launcher,
                    });
                }
            }
            if cfg!(test) {
                if let Some(cgroup) = cgroup {
                    return Ok(Self::Cgroup(cgroup));
                }
            }
            return Err(io::Error::other(
                "refusing to run an external analyzer: bubblewrap is unavailable; process groups and cgroups are not security boundaries",
            ));
        }
        #[allow(unreachable_code)]
        if let Some(launcher) = launcher {
            #[cfg(test)]
            {
                wrap_with_launcher(command, launcher)?;
                return Ok(Self::Launcher);
            }
        }
        #[allow(unreachable_code)]
        Err(io::Error::other(
            "refusing to run an external analyzer: no supported sandbox is available",
        ))
    }

    pub(crate) fn terminate(&mut self) -> io::Result<()> {
        match self {
            #[cfg(target_os = "linux")]
            Self::Cgroup(cgroup) => cgroup.terminate(),
            #[cfg(target_os = "linux")]
            Self::Bwrap(cgroup) => match cgroup {
                Some(cgroup) => cgroup.terminate(),
                None => Ok(()),
            },
            #[cfg(test)]
            Self::Launcher => Ok(()),
        }
    }
}

fn configured_launcher() -> io::Result<Option<PathBuf>> {
    if let Some(value) = std::env::var_os("RUSTYFUZZ_SATORI_SANDBOX_LAUNCHER") {
        let path = validate_launcher(PathBuf::from(value))?;
        if !cfg!(test) && !is_bwrap(&path) {
            return Err(io::Error::other(
                "RUSTYFUZZ_SATORI_SANDBOX_LAUNCHER must reference bubblewrap outside tests",
            ));
        }
        return Ok(Some(path));
    }
    for path in [PathBuf::from("/usr/bin/bwrap"), PathBuf::from("/bin/bwrap")] {
        if path.exists() {
            return validate_launcher(path).map(Some);
        }
    }
    Ok(None)
}

fn is_bwrap(path: &Path) -> bool {
    path.file_name().and_then(|name| name.to_str()) == Some("bwrap")
}

fn validate_launcher(path: PathBuf) -> io::Result<PathBuf> {
    if !path.is_absolute() {
        return Err(io::Error::other(
            "RUSTYFUZZ_SATORI_SANDBOX_LAUNCHER must be an absolute executable path",
        ));
    }
    let metadata = fs::symlink_metadata(&path).map_err(|_| io::Error::last_os_error())?;
    if metadata.file_type().is_symlink() {
        return Err(io::Error::other(
            "RUSTYFUZZ_SATORI_SANDBOX_LAUNCHER must not be a symlink",
        ));
    }
    if !metadata.is_file() {
        return Err(io::Error::other(
            "RUSTYFUZZ_SATORI_SANDBOX_LAUNCHER is not a regular executable file",
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o111 == 0 {
            return Err(io::Error::other(
                "RUSTYFUZZ_SATORI_SANDBOX_LAUNCHER is not executable",
            ));
        }
    }
    Ok(path)
}

#[cfg(target_os = "linux")]
fn attach_to_cgroup(command: &mut Command, cgroup: &CgroupGuard) -> io::Result<()> {
    let procs_path = std::ffi::CString::new(cgroup.procs_path().as_os_str().as_bytes())
        .map_err(|_| io::Error::other("cgroup process path contains a NUL byte"))?;
    unsafe {
        command.pre_exec(move || {
            let fd = libc::open(procs_path.as_ptr(), libc::O_WRONLY | libc::O_CLOEXEC);
            if fd < 0 {
                return Err(io::Error::last_os_error());
            }
            let mut pid = std::process::id();
            let mut digits = [0_u8; 20];
            let mut start = digits.len();
            loop {
                start -= 1;
                digits[start] = u8::try_from(pid % 10)
                    .map_err(|_| io::Error::from_raw_os_error(libc::EINVAL))?;
                pid /= 10;
                if pid == 0 {
                    break;
                }
            }
            let length = digits.len() - start;
            let written = libc::write(
                fd,
                digits.as_ptr().add(start) as *const libc::c_void,
                length,
            );
            if written != length as isize {
                let error = io::Error::last_os_error();
                libc::close(fd);
                return Err(error);
            }
            if libc::close(fd) != 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        });
    }
    Ok(())
}

fn wrap_with_bwrap(
    command: &mut Command,
    launcher: PathBuf,
    limits: ExternalContainmentLimits,
) -> io::Result<()> {
    let program = command.get_program().to_os_string();
    let args: Vec<_> = command
        .get_args()
        .map(std::ffi::OsStr::to_os_string)
        .collect();
    let current_dir = command.get_current_dir().map(Path::to_path_buf);
    let writable_root = command
        .get_envs()
        .find(|(key, _)| *key == std::ffi::OsStr::new("RUSTYFUZZ_SATORI_WRITABLE_ROOT"))
        .and_then(|(_, value)| value)
        .map(PathBuf::from);
    let environment: Vec<_> = command
        .get_envs()
        .map(|(key, value)| (key.to_os_string(), value.map(std::ffi::OsStr::to_os_string)))
        .collect();

    let mut wrapped = Command::new(launcher);
    wrapped
        .arg("--die-with-parent")
        .arg("--unshare-user")
        .arg("--unshare-pid")
        .arg("--unshare-uts")
        .arg("--unshare-ipc")
        .arg("--unshare-cgroup")
        .arg("--unshare-net")
        .arg("--dir")
        .arg("/home")
        .arg("--dir")
        .arg("/root")
        .arg("--dir")
        .arg("/tmp")
        .arg("--dir")
        .arg("/run")
        .arg("--dir")
        .arg("/var")
        .arg("--dir")
        .arg("/opt")
        .arg("--dir")
        .arg("/mnt")
        .arg("--dir")
        .arg("/media")
        .arg("--ro-bind")
        .arg("/usr")
        .arg("/usr")
        .arg("--dir")
        .arg("/etc")
        .arg("--ro-bind")
        .arg("/etc/ssl")
        .arg("/etc/ssl")
        .arg("--ro-bind")
        .arg("/etc/alternatives")
        .arg("/etc/alternatives")
        .arg("--ro-bind")
        .arg("/etc/passwd")
        .arg("/etc/passwd")
        .arg("--ro-bind")
        .arg("/etc/group")
        .arg("/etc/group")
        .arg("--ro-bind")
        .arg("/etc/nsswitch.conf")
        .arg("/etc/nsswitch.conf")
        .arg("--ro-bind")
        .arg("/etc/ld.so.cache")
        .arg("/etc/ld.so.cache")
        .arg("--ro-bind")
        .arg("/etc/ld.so.conf")
        .arg("/etc/ld.so.conf")
        .arg("--symlink")
        .arg("usr/bin")
        .arg("/bin")
        .arg("--symlink")
        .arg("usr/lib")
        .arg("/lib")
        .arg("--symlink")
        .arg("usr/lib64")
        .arg("/lib64")
        .arg("--proc")
        .arg("/proc")
        .arg("--dev")
        .arg("/dev");
    if let Some(current_dir) = current_dir.as_ref() {
        wrapped.arg("--ro-bind").arg(current_dir).arg(current_dir);
        if let Some(writable_root) = writable_root.as_ref() {
            let metadata = fs::symlink_metadata(writable_root)?;
            if metadata.file_type().is_symlink() || !metadata.is_dir() {
                return Err(io::Error::other(
                    "sandbox writable root must be a regular directory",
                ));
            }
            wrapped.arg("--bind").arg(writable_root).arg(writable_root);
        }
    }
    wrapped
        .arg("--")
        .arg("/usr/bin/prlimit")
        .arg(format!("--as={}", limits.memory_bytes))
        .arg(format!("--nproc={}", limits.max_processes))
        .arg(format!("--fsize={}", limits.output_bytes))
        .arg("--")
        .arg(program)
        .args(args);
    if let Some(current_dir) = current_dir {
        wrapped.current_dir(current_dir);
    }
    configure_sandbox_environment(&mut wrapped, environment);
    *command = wrapped;
    Ok(())
}

fn configure_sandbox_environment(
    command: &mut Command,
    explicit_environment: Vec<(std::ffi::OsString, Option<std::ffi::OsString>)>,
) {
    command.env_clear();
    for name in [
        "PATH",
        "HOME",
        "TMPDIR",
        "USER",
        "LOGNAME",
        "LANG",
        "LC_ALL",
        "LC_CTYPE",
        "TERM",
        "SSL_CERT_FILE",
        "SSL_CERT_DIR",
    ] {
        if let Some(value) = std::env::var_os(name) {
            command.env(name, value);
        }
    }
    #[cfg(test)]
    for (name, value) in std::env::vars_os() {
        if name.to_string_lossy().starts_with("FAKE_") {
            command.env(name, value);
        }
    }
    for (key, value) in explicit_environment {
        match value {
            Some(value) => {
                command.env(key, value);
            }
            None => {
                command.env_remove(key);
            }
        }
    }
}

#[cfg(test)]
fn wrap_with_launcher(command: &mut Command, launcher: PathBuf) -> io::Result<()> {
    let program = command.get_program().to_os_string();
    let args: Vec<_> = command
        .get_args()
        .map(std::ffi::OsStr::to_os_string)
        .collect();
    let current_dir = command.get_current_dir().map(Path::to_path_buf);
    let environment: Vec<_> = command
        .get_envs()
        .map(|(key, value)| (key.to_os_string(), value.map(std::ffi::OsStr::to_os_string)))
        .collect();

    let mut wrapped = Command::new(launcher);
    wrapped.arg("--").arg(program).args(args);
    if let Some(current_dir) = current_dir {
        wrapped.current_dir(current_dir);
    }
    configure_sandbox_environment(&mut wrapped, environment);
    *command = wrapped;
    Ok(())
}

#[cfg(target_os = "linux")]
pub(crate) struct CgroupGuard {
    path: PathBuf,
    terminated: bool,
}

#[cfg(target_os = "linux")]
impl CgroupGuard {
    fn create(limits: ExternalContainmentLimits) -> Option<Self> {
        if limits.memory_bytes == 0 || limits.max_processes == 0 {
            return None;
        }
        let root = Path::new("/sys/fs/cgroup");
        let controllers = fs::read_to_string(root.join("cgroup.controllers")).ok()?;
        if !has_word(&controllers, "memory") || !has_word(&controllers, "pids") {
            return None;
        }
        let parent = current_cgroup_directory(root).ok()?;
        let subtree_control = parent.join("cgroup.subtree_control");
        let enabled = fs::read_to_string(&subtree_control).ok()?;
        if !has_word(&enabled, "memory") || !has_word(&enabled, "pids") {
            let requested = if has_word(&enabled, "memory") {
                "+pids"
            } else if has_word(&enabled, "pids") {
                "+memory"
            } else {
                "+memory +pids"
            };
            if write_control(&subtree_control, requested).is_err() {
                return None;
            }
        }

        let path = parent.join(format!(
            "rustyfuzz-satori-{}-{}",
            std::process::id(),
            uuid::Uuid::new_v4().simple()
        ));
        if fs::create_dir(&path).is_err() {
            return None;
        }
        let guard = Self {
            path: path.clone(),
            terminated: false,
        };
        let configured = write_control(&path.join("memory.max"), &limits.memory_bytes.to_string())
            .and_then(|()| {
                write_control(&path.join("pids.max"), &limits.max_processes.to_string())
            });
        if configured.is_err() {
            drop(guard);
            return None;
        }
        // These are best-effort hardening controls; memory.max and pids.max are
        // mandatory and are the limits that make the backend usable.
        let _ = write_control(&path.join("memory.swap.max"), "0");
        let _ = write_control(&path.join("memory.oom.group"), "1");
        Some(guard)
    }

    fn procs_path(&self) -> PathBuf {
        self.path.join("cgroup.procs")
    }

    fn terminate(&mut self) -> io::Result<()> {
        if self.terminated {
            return Ok(());
        }
        match write_control(&self.path.join("cgroup.kill"), "1") {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                self.terminated = true;
                return Ok(());
            }
            Err(error) => return Err(error),
        }
        let events = self.path.join("cgroup.events");
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(1);
        loop {
            if fs::read_to_string(&events)
                .map(|events| has_word(&events, "populated 0"))
                .unwrap_or(true)
            {
                break;
            }
            if std::time::Instant::now() >= deadline {
                return Err(io::Error::other(
                    "external analyzer cgroup did not become empty after termination",
                ));
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        for _ in 0..10 {
            match fs::remove_dir(&self.path) {
                Ok(()) => {
                    self.terminated = true;
                    return Ok(());
                }
                Err(error) if error.kind() == io::ErrorKind::NotFound => {
                    self.terminated = true;
                    return Ok(());
                }
                Err(error) if error.kind() == io::ErrorKind::DirectoryNotEmpty => {
                    std::thread::sleep(std::time::Duration::from_millis(10));
                }
                Err(error) => return Err(error),
            }
        }
        Err(io::Error::other(
            "external analyzer cgroup could not be removed after termination",
        ))
    }
}

#[cfg(target_os = "linux")]
impl Drop for CgroupGuard {
    fn drop(&mut self) {
        let _ = self.terminate();
    }
}

#[cfg(target_os = "linux")]
fn current_cgroup_directory(root: &Path) -> io::Result<PathBuf> {
    let cgroup = fs::read_to_string("/proc/self/cgroup")?;
    let relative = cgroup
        .lines()
        .find_map(|line| line.strip_prefix("0::"))
        .ok_or_else(|| io::Error::other("Linux unified cgroup v2 membership was not found"))?;
    let relative = relative.trim_start_matches('/');
    if relative.is_empty() {
        return Ok(root.to_path_buf());
    }
    let mut path = root.to_path_buf();
    for component in Path::new(relative).components() {
        match component {
            std::path::Component::Normal(component) => path.push(component),
            _ => {
                return Err(io::Error::other(
                    "Linux cgroup membership contained an unsafe path component",
                ));
            }
        }
    }
    Ok(path)
}

#[cfg(target_os = "linux")]
fn has_word(value: &str, word: &str) -> bool {
    value
        .split_ascii_whitespace()
        .any(|candidate| candidate == word)
}

#[cfg(target_os = "linux")]
fn write_control(path: &Path, value: &str) -> io::Result<()> {
    let mut file = OpenOptions::new().write(true).open(path)?;
    file.write_all(value.as_bytes())?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_limits_are_bounded() {
        let limits = ExternalContainmentLimits::default();
        assert!(limits.memory_bytes > 0);
        assert!(limits.memory_bytes <= 4 * 1024 * 1024 * 1024);
        assert!(limits.max_processes > 0);
        assert!(limits.max_processes <= 1024);
    }

    #[test]
    fn sandbox_launcher_must_be_absolute() {
        assert!(validate_launcher(PathBuf::from("relative-sandbox")).is_err());
    }
}

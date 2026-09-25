#![cfg(unix)]
use fs2::FileExt;
use rustyfuzz_artifacts::fsutil::write_atomic;
use rustyfuzz_artifacts::layout::RunLayout;
use std::{
    fs,
    os::unix::process::ExitStatusExt,
    process::{Child, Command, Stdio},
    time::{Duration, Instant},
};
const SIZE: usize = 128 * 1024 * 1024;

#[test]
fn terminal_lock_child() {
    let Some(root) = std::env::var_os("RUSTYFUZZ_TERMINAL_LOCK_ROOT") else {
        return;
    };
    let Some(ready) = std::env::var_os("RUSTYFUZZ_TERMINAL_LOCK_READY") else {
        return;
    };
    let root = std::path::PathBuf::from(root);
    let lock_path = root.join(".terminal_status.lock");
    let lock = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(lock_path)
        .unwrap();
    lock.lock_exclusive().unwrap();
    fs::write(ready, b"locked").unwrap();
    loop {
        std::thread::sleep(Duration::from_secs(1));
    }
}

#[test]
fn atomic_writer_child() {
    let Some(path) = std::env::var_os("RUSTYFUZZ_ATOMIC_KILL_PATH") else {
        return;
    };
    write_atomic(std::path::Path::new(&path), vec![b'x'; SIZE]).unwrap();
}

struct Process(Child);
impl Drop for Process {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[test]
fn sigkill_mid_write_keeps_previous_checkpoint() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("checkpoint.json");
    let previous = br#"{"schema_version":1,"budget_consumed":8}"#;
    write_atomic(&path, previous).unwrap();
    let mut child = Process(
        Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "atomic_writer_child", "--nocapture"])
            .env("RUSTYFUZZ_ATOMIC_KILL_PATH", &path)
            .stdout(Stdio::null())
            .spawn()
            .unwrap(),
    );
    let deadline = Instant::now() + Duration::from_secs(20);
    let temporary = loop {
        let found = fs::read_dir(dir.path())
            .unwrap()
            .filter_map(Result::ok)
            .map(|entry| entry.path())
            .find(|p| {
                p.extension().is_some_and(|ext| ext == "tmp")
                    && p.metadata()
                        .is_ok_and(|m| m.len() > 0 && m.len() < SIZE as u64)
            });
        if let Some(tmp) = found {
            break tmp;
        }
        assert!(
            child.0.try_wait().unwrap().is_none(),
            "writer finished before fault injection"
        );
        assert!(Instant::now() < deadline, "no partial write observed");
        std::thread::sleep(Duration::from_micros(100));
    };
    child.0.kill().unwrap();
    let status = child.0.wait().unwrap();
    assert_eq!(status.signal(), Some(9));
    let partial_len = temporary.metadata().unwrap().len();
    assert!(
        partial_len > 0 && partial_len < SIZE as u64,
        "fault injection did not interrupt a partial write: {partial_len}"
    );
    assert_eq!(fs::read(&path).unwrap(), previous);
    println!("SIGKILL signal=9; interrupted temporary file={partial_len}/{SIZE} bytes; committed checkpoint still budget_consumed=8");
    // The next real publication ignores the orphan and commits normally.
    let next = br#"{"schema_version":1,"budget_consumed":12}"#;
    write_atomic(&path, next).unwrap();
    assert_eq!(fs::read(&path).unwrap(), next);
    println!("subsequent atomic publication succeeded: budget_consumed=12");
}

#[test]
fn sigkill_releases_terminal_lock_for_restart() {
    let dir = tempfile::tempdir().unwrap();
    let base = dir.path().join("artifacts");
    let run_id = "lock-restart";
    let layout = RunLayout::new(&base, run_id);
    layout.materialize().unwrap();
    layout.mark_incomplete(run_id).unwrap();
    let ready = dir.path().join("ready");
    let mut child = Process(
        Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "terminal_lock_child", "--nocapture"])
            .env("RUSTYFUZZ_TERMINAL_LOCK_ROOT", layout.root())
            .env("RUSTYFUZZ_TERMINAL_LOCK_READY", &ready)
            .stdout(Stdio::null())
            .spawn()
            .unwrap(),
    );
    let deadline = Instant::now() + Duration::from_secs(10);
    while !ready.exists() {
        assert!(child.0.try_wait().unwrap().is_none());
        assert!(Instant::now() < deadline, "lock child did not become ready");
        std::thread::sleep(Duration::from_millis(10));
    }
    child.0.kill().unwrap();
    let status = child.0.wait().unwrap();
    assert_eq!(status.signal(), Some(9));
    let started = Instant::now();
    layout
        .write_terminal_status(
            run_id,
            rustyfuzz_artifacts::RunTerminalState::Failed,
            None,
            None,
        )
        .unwrap();
    assert!(started.elapsed() < Duration::from_secs(2));
    assert!(layout.root().join(".terminal_status.lock").exists());
}

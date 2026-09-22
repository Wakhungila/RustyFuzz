#![cfg(unix)]
use rustyfuzz_artifacts::fsutil::write_atomic;
use std::{
    fs,
    os::unix::process::ExitStatusExt,
    process::{Child, Command, Stdio},
    time::{Duration, Instant},
};
const SIZE: usize = 128 * 1024 * 1024;

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

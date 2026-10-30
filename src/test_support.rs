//! Test-only helpers shared by the library and the binary target.
//!
//! Included by both crate roots via `#[path]` rather than duplicated, so the
//! locking discipline has exactly one definition.

use std::sync::{Mutex, MutexGuard, OnceLock};

/// Serializes tests that read or mutate process environment variables.
///
/// The runtime environment is process-global, but cargo runs tests on multiple
/// threads. Several tests set and clear the same `RUSTYFUZZ_*` variables, and
/// the configuration fingerprint deliberately hashes the *presence* of those
/// variables — so two tests touching them concurrently produce a
/// nondeterministic config hash and a spurious failure that only appears under a
/// full parallel run.
///
/// Any test that touches these variables must hold this lock for its whole
/// duration. It is one lock per test process on purpose: per-module locks would
/// not exclude each other.
pub fn env_lock() -> MutexGuard<'static, ()> {
    static ENV_LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    ENV_LOCK
        .get_or_init(|| Mutex::new(()))
        .lock()
        // A panicking test poisons the lock; the guard only protects environment
        // variables, which the panic unwinds out of anyway, so recovering keeps
        // later tests running instead of cascading failures.
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

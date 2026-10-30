//! Global allocator selection.
//!
//! The fuzzing workload is allocation-dominated: every transaction builds a
//! journal, clones cached accounts, and churns `Vec`/`HashMap` temporaries in
//! the inspector. The system allocator serializes these badly across the
//! campaign's worker threads, so the default path is mimalloc, which is
//! designed for exactly this short-lived, high-rate, multi-threaded pattern.
//!
//! Feature-gated rather than unconditional so the crate still builds on
//! platforms where mimalloc is unavailable.

#[cfg(feature = "mimalloc-allocator")]
mod imp {
    use mimalloc::MiMalloc;

    #[global_allocator]
    static GLOBAL: MiMalloc = MiMalloc;
}

// When the feature is disabled the platform allocator is used unchanged; no
// declaration is needed, and no silent behavioural difference is introduced.
#[cfg(not(feature = "mimalloc-allocator"))]
mod imp {}

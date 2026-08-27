# Stage 4D: CLI Thinning

Status: COMPLETE for review.

## What Changed

`src/main.rs` reduced from ~2000 lines to a **27-line thin entry point**:

- `src/cli/commands.rs` — clap `Args` / `Command` / `JobCommand` definitions
  (verbatim move).
- `src/cli/handlers.rs` — the per-command dispatch body (`cli::handlers::run`),
  one arm per command, unchanged logic.
- `src/cli/helpers.rs` — shared helpers (replay loading, campaign bounds,
  watchdog, block env, run-manifest fingerprinting, prove-live pipeline) and
  their existing tests.

Satori remains dispatched exactly as before (early return before config load,
delegating to `rusty_fuzz::satori::cli`).

## Verification

- `cargo run -- --help` enumerates all commands as before.
- Stable gates green (fmt/check/clippy `-D warnings`=0/test/release
  benchmarks 38+1 ign).
- No behavioral change: same commands, flags, exit paths.

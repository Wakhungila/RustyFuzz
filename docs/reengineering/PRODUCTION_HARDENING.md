# Production hardening — 2026-09-22

This change improves campaign limits and artifact persistence. It does not
establish production readiness or comparative bug-finding performance.

## Execution admission

Broker workers receive deterministic quotas by their index in the selected core
list. For limit `L` and `N` workers, each receives `L / N` executions, and the
first `L % N` workers receive one additional execution. The total is exactly `L`;
workers may receive zero. Atomic reservation prevents threads sharing a budget
from exceeding it. The legacy constructor without worker identity uses floor
division and leaves the remainder unused.

Quotas are process-local. They do not persist across worker restarts. Launcher
fallback and restarts therefore still need campaign-wide durable accounting
before the execution limit can be advertised as strict across failures.

## Persistence

`rustyfuzz-artifacts::fsutil::write_atomic` creates a unique, exclusively opened
temporary file beside the destination, writes and syncs it, then renames it over
the destination. Successful concurrent writers use last-publication-wins
semantics. Readers observe complete old or new files. Ordinary error paths clean
up the writer's temporary file. A killed process can leave an orphan temporary
file; later writers do not reuse or delete files they do not own.

The helper is used for corpus inputs, metadata, fork caches, seed bundles, crash
records, snapshot manifests, campaign records/indexes, and reproduction reports.
The CLI refuses to start a fuzz campaign if run layout creation or manifest
publication fails. Campaign artifact locks are released on ordinary error paths.

These are per-file guarantees. Related files are not a filesystem transaction.
Parent-directory syncing remains best effort; this is not a guarantee against
all power-loss scenarios. Abrupt termination can leave stale campaign lock files.
Existing run identifiers can still be reused, replacing their manifest.

## Regression coverage

- Simultaneous writers and readers reject torn artifact content.
- A pre-existing predictable temporary symlink cannot redirect publication.
- Failed rename leaves the destination intact and removes the owned temporary file.
- Injected fork-cache write failure releases the campaign lock so a retry succeeds.
- CLI filesystem failures return a nonzero status before engine artifacts appear.
- Worker partitions cover zero, limits smaller than worker count, remainders,
  invalid topology, and `u64::MAX`; concurrent reservations respect the quota.

CI's main test job now runs the whole workspace with `--locked`, so extracted
crate regressions participate in the regular test gate.

## Remaining release work

Failure-safe restart accounting, multi-file artifact recovery, run identity
isolation, and complete effective execution provenance remain necessary work.
This patch does not change oracle validity or proof policy. Release confidence
also needs independently reproducible real-contract benchmarks, false-positive
measurement, and sustained live-RPC testing; passing synthetic fixtures alone
does not demonstrate those properties.

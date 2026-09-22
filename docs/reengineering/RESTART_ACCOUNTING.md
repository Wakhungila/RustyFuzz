# Restart accounting contract and uncovered paths

## In-memory state inventory

The following are the execution/corpus/coverage/budget owners in the active EVM
campaign and adjacent runners. The two harnesses in `src/engine/fuzz_engine.rs`
instantiate separate copies of these objects. Before this change none had a
coordinated on-disk record at a particular execution boundary. Individual
findings, snapshot manifests, and final summaries were not sufficient to restore
them.

| Owner | State | Current checkpoint disposition |
| --- | --- | --- |
| `fuzz_engine::EvmCampaignState` / `StdState` | LibAFL execution count, RNG, in-memory corpus and solution corpus, testcase metadata/scheduling counts, stage progress | Entire serialized state in `state` |
| `fuzz_engine` shared-memory `edges` observer | Current per-input coverage/hit counts, including novelty/score reward slots | `raw_coverage` |
| `evm::feedback::EvmCoverageFeedback` | Cumulative hit buckets (`virgin`), touched addresses, observer name | `feedback`; cumulative map also in envelope `coverage` |
| `evm::feedback::EvmStateNoveltyFeedback` | Seen transitions, slots, reads, call edges, contracts | `novelty` |
| `evm::corpus::SnapshotCorpus` | EVM CacheDB accounts/storage/code/logs, fork cache, coverage, parent/child graph, metadata/scores/visits, read hotspots, priority gap map | `snapshots`, including all REVM caches and offline backing caches |
| `rustyfuzz-engine::CampaignBudget` | Atomic reserved executions, execution limit, monotonic deadline | `budget`: consumed, max_execs, remaining duration |
| `rustyfuzz-engine::CampaignTelemetry` | Executions, mutations, seed replays, artifact count, findings, novelty, best score, max coverage, mutation mix, concolic counters | `telemetry`; wall-clock throughput timers restart with the process |
| `rustyfuzz-engine::RustyFuzzScheduler` | Queue cycles, runs in cycle; pending score shared with harness | `scheduler`, `pending_score`; testcase scheduling data lives in `state` |
| `rustyfuzz-engine::EvmTestcaseMetadataStore` | Mutation provenance and waypoint sidecar indexed by semantic input ID | `metadata` |
| `evm::fuzz::EvmMutator` | Strategy counts, hint queue, account registry, ABI type/decoded-calldata caches | `strategies`, `hints`, `accounts`; deterministic lookup caches rebuilt |
| `rustyfuzz-evm::DataflowRegistry` | Influenced slots, storage taints/expressions | `dataflow` |
| `rustyfuzz-evm::CoverageInspector` and REVM stack | In-flight instruction counter, call stack, memory/transient taints, intermediate state and transaction coverage | Not checkpointed mid-instruction; lost on kill |
| `engine::PromotionCampaignStats` | Promotion dedup IDs, counters, proof/minimization results and external Foundry side effects | Unsupported; checkpoint mode rejects promotion-enabled configs |
| `rustyfuzz-engine::EventSink` | In-memory notification queue and dropped-event count | Not replayed; not authoritative campaign state |
| `engine::CorpusMinimizationStage` | `exec_count` and temporary coverage verification | Not instantiated by either current campaign loop; no checkpoint support if used separately |
| `engine::benchmark::ValidationRunner`, `bin/benchmark` | Per-case execution statistics and report aggregates | Reports persist completed results; no coordinated interrupted-validation resume |
| Brokered `Launcher` / `LlmpRestartingEventManager` | Worker StdState may transfer through restart shared memory, plus fresh harness counters/snapshots/coverage | No disk checkpoint; checkpoint mode rejects brokered configs |

SVM is compile-blocked and SGX is an unsupported shim; neither implements
campaign restart accounting.

## Configuration and supported path

Checkpoint mode is opt-in through `HardenedDefiConfig` (also TOML):

```toml
[hardened_defi]
single_process = true
deterministic = true
rng_seed = 42

[hardened_defi.checkpoint]
directory = ".rustyfuzz/checkpoints/my-campaign"
every_execs = 1000
resume = false
```

Run with `--no-promote-findings`; set `resume = true` for the subsequent process.
An existing checkpoint is never silently overwritten by a fresh start. The
checkpoint directory has an OS advisory lock held throughout the campaign;
SIGKILL releases that lock, unlike a create-and-delete sentinel file.

Only offline single-process campaigns are supported by this implementation.
Live-RPC campaigns are explicitly rejected because restoring their backing cache
as an offline database would change cache-miss semantics. Brokered campaigns and
promotion are explicitly rejected. Uncheckpointed execution remains available
and still has no restart accounting.

## On-disk format, v1

`<directory>/checkpoint.json` is a JSON object with these exact fields:

- `schema_version`: integer 1.
- `producer_version`: package version string.
- `config_digest`: Keccak-256 of the effective engine config's debug encoding,
  excluding checkpoint options, plus length-prefixed contents of configured ABI,
  invariant, and historical seed files. RPC credentials are hashed, never written.
- `budget_consumed`: number of reserved input executions at the stage boundary.
- `completed_execs`: telemetry's fully evaluated sequence count. Failed/early-exit
  attempts may consume budget without incrementing this counter.
- `corpus_ids`: ordered semantic input IDs from the live LibAFL corpus.
- `coverage`: byte array copied from live cumulative coverage feedback.
- `payload_digest`: Keccak-256 of decoded payload bytes.
- `payload_hex`: hex-encoded postcard serialization of `Checkpoint`.

`Checkpoint` fields are `state`, `feedback`, `raw_coverage`, `snapshots`, `novelty`,
`dataflow`, `accounts`, `metadata`, `hints`, `scheduler`, `pending_score`,
`strategies`, `budget`, `telemetry`, and `block_env`. `state` itself holds postcard
bytes for the complete LibAFL StdState. The definitions are in
`src/engine/checkpoint.rs`, with budget/telemetry DTOs in the engine crate.

All referenced runtime state is embedded in one file; restoration does not read
independently updated input, snapshot, or fork-cache files. Unsupported schema,
producer/config mismatch, malformed data, payload checksum mismatch, or coverage
summary mismatch causes startup to fail. No fallback to zero is attempted.

On resume, `<directory>/resume.json` records a fresh capture of the restored live
objects before the first resumed mutation. It is a verification receipt, not a
second source of truth for restoration.

## Cadence and publication

Capture occurs initially and after a completed `fuzz_one` when reserved execution
count advanced by at least `every_execs`, plus at budget exhaustion. Capture is
outside the harness after LibAFL coverage feedback and corpus insertion. Bounded
campaigns use a maximum of one mutation per stage. Unbounded stages may execute
up to 128 mutations, so their cadence can overshoot the requested interval by a
stage. A skipped mutation consumes no execution and does not trigger a checkpoint.

The entire JSON document is serialized before publication. The filesystem helper
exclusively creates a unique sibling temporary file, writes it, syncs its contents,
and atomically renames it over `checkpoint.json`. Checkpoint publication then
requires a successful parent-directory fsync. A SIGKILL before rename leaves the
previous checkpoint; after rename the reader sees the complete new checkpoint.
The first publication has no predecessor: if killed before that rename, resume
fails with a missing-checkpoint error. Orphan temporary files are ignored. This
relies on local filesystem atomic rename/fsync semantics; network filesystems and
power-loss behavior have not been tested here.

## In-flight accounting

The durable accounting unit is a completed checkpoint epoch, not a physical CPU
execution. Work since the last published checkpoint—including partially executed
transactions and fully executed but not yet checkpointed stages—is discarded on
resume. The stored RNG and corpus are restored, but exact replay of the same
uncommitted sequence is NOT guaranteed: hash-map iteration and timing-dependent
solver decisions can affect subsequent mutations.

Thus logical committed counters resume without resetting or double-counting the
committed prefix. Physical execution attempts can exceed `max_execs` across kills,
because rolled-back work can run again. There is no write-ahead admission ledger
that charges interrupted executions permanently. This implementation does not
claim an exactly-once execution guarantee or a hard physical-attempt cap across
crashes. The kill point does not reveal how many instructions/transactions of
uncommitted work physically completed.

Duration checkpoints preserve remaining active-run budget; time while the process
is dead is not charged. Other report/finding files written after the checkpoint
are not rolled back. Their coordinated recovery is still unimplemented.

## Multi-file artifact recovery

An indexed campaign artifact is the recovery unit for persistent corpus data:
the input, input metadata, fork cache, artifact record, markdown summary, and
discovery index. The index is published last. On corpus startup every indexed
bundle is checked for existence and valid JSON/input decoding; a missing or
truncated member fails startup with the artifact id and member name. Repair is
not attempted automatically; orphan temporary files and unindexed partial
files are not committed artifacts.

`evm::corpus::artifact_tests::truncated_published_artifact_fails_next_corpus_start`
publishes a real bundle, truncates its fork cache, and verifies the next corpus
construction fails loudly.

## Execution provenance

Before this change telemetry retained only aggregate counters. It did not retain
the input, transaction result, per-execution coverage, score, findings, or
mutation origin needed to reproduce one execution. Each completed execution
now publishes `<corpus_dir>/execution_provenance/<execution_index>.json` using
the same atomic writer. Schema v1 records `execution_index`, `budget_consumed`,
the full executable input and semantic `input_id`, the full sequence result and
transaction results, coverage edges, state novelty, campaign score, findings,
and mutation strategies. A persistence failure returns `ExitKind::Crash` so a
campaign cannot continue while silently losing provenance.

## SIGKILL test

`tests/checkpoint_restart.rs::sigkill_resumes_real_campaign_from_checkpoint`
starts the actual campaign engine against local SSTORE/SLOAD/RETURN bytecode,
waits for at least eight executions, calls `Child::kill`, and asserts Unix exit
signal 9. It reads the committed checkpoint after death, starts a new process
with resume enabled, compares a recapture of live state to the checkpoint, then
requires additional executions, retained coverage, and retained corpus IDs.
It SIGKILLs that process as well and verifies signal 9.

This campaign test does not synchronize the kill to a temporary-file write.
`crates/rustyfuzz-artifacts/tests/atomic_sigkill.rs` separately launches the
production atomic writer in a subprocess, observes a partial 128 MiB temporary
file, sends SIGKILL, asserts the temporary file is still partial after death,
checks the previous checkpoint bytes remain intact, and publishes a subsequent
checkpoint despite the orphan. It checks the filesystem primitive, not a second
campaign engine. Its injected payload is arbitrary bytes; the previous and
subsequent committed checkpoint markers are JSON.

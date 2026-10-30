# Committed storage observations and original campaign state

## Status

Accepted and implemented for new root-based campaigns, 2026-10-20.

## Context

Attempted SSTORE telemetry included reverted and intermediate writes, and
cache-only original-value lookup missed cold fork state. Delegatecall storage
was attributed to the code account. Campaign startup also injected balances
into root snapshots subsequently used as proof inputs.

## Decision

`TxExecutionResult.storage_diffs` contains one before/after delta per committed
address/slot, sorted by address and slot. REVM finalized state supplies original
and present values; reverted writes and writes back to the original value do
not produce a delta. `storage_writes` and waypoints continue to record attempted
operations, including reverted frames. A diff's `pc` is best-effort telemetry
and is zero when bounded waypoint collection did not retain a matching write.
These observations do not model all account-level effects such as destruction
or code changes.

Storage reads, writes, transient storage, and symbolic slot identities use the
interpreter's storage/context address. Code identity is separate: delegatecall
does not transfer ownership of proxy storage to the implementation.

Execution operates on a transaction-local cache clone. Caller nonce and account
attributes are loaded before exploration funding. Validation/database errors
leave the original outer execution cache intact. Successful execution commits
REVM state; an EVM revert still commits protocol-defined gas and nonce effects.

Campaign root snapshots no longer receive synthetic fuzzer or actor balances.
Funding happens only in exploration execution overlays. Artifact base caches
for inputs starting at the root therefore preserve the original baseline.
This does not authenticate old imported artifacts, make arbitrary mutated
snapshots original fork state, or implement proof of snapshot ancestry. Before
enabling non-root snapshot selection, proof must reconstruct the complete
transaction lineage from an immutable original fork.

## Alternatives Considered

Filtering waypoints by transaction success cannot handle reverted nested
frames, missing telemetry, or multiple writes. Comparing two outer caches does
not reliably capture lazily loaded original values. Finalized REVM state is the
source used by the database commit itself and avoids those ambiguities.

## Consequences

Detailed operation traces remain useful for guidance but are not committed
state evidence. Multiple SSTORE operations may correspond to one or no deltas.
Original campaign roots remain unfunded while exploration can still fund its
transaction-local overlay. Downstream oracle controls must remain green under
the corrected observations before detection behavior is accepted.

## Migration Notes

Execution provenance schema v4 identifies the committed-delta interpretation;
v3 and older observations must be regenerated before being used as evidence
under these semantics. Input identity and transaction encoding are unchanged.

Checkpoint schema v4 rejects all earlier checkpoint envelopes. Older snapshots
can embed synthetic root funding and observation-dependent feedback; there is
no safe automatic migration. Start a new campaign and checkpoint directory.
Existing checkpoint data is not deleted or overwritten by resume rejection.

## Verification

Executable backend regressions compare observed deltas with actual state for
cold slots, repeated writes, top-level revert/halt, and caught child reverts.
CALL, DELEGATECALL, nested delegation and transient storage have storage-context
tests. Account tests cover uncached nonzero nonces, caller code, target account
attributes, nonexistent callers and a failed transaction followed by retry.
A real campaign/checkpoint test checks an unfunded original root; an artifact
roundtrip test checks that exploration funding does not become proof funding.

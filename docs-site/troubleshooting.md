---
title: "Troubleshooting"
section: "Reference"
nav_order: 15
description: "Diagnose the stage that failed before changing execution or proof requirements."
---

## Fork startup fails

Check the target address, block number, chain, and whether the endpoint can serve historical code and storage. A target deployed after the selected block will not have the expected code. Provider throttling and archive gaps are different from an empty contract.

Review startup logs and `RUSTYFUZZ_STARTUP_RPC_TIMEOUT_SECS`. Increasing a timeout can help a slow provider; it cannot supply unavailable state. Do not enable synthetic fallback to make a real-fork proof appear successful.

## The seed bundle is missing or empty

Confirm the configured bundle ID and input paths, then inspect the seed discovery manifest. Check the scan range and whether the transactions actually call the target. `--require-seed-bundle` intentionally stops a campaign when required seed input is unavailable.

An ABI can supply structured starting calls, but that does not reproduce the same preconditions as a historical seed sequence.

## The campaign finds nothing

Check that code loaded, meaningful functions are being exercised, and budgets permit useful state exploration. Review ABI quality, actor roles, state reachability, and the oracle assumptions for the target. More executions cannot compensate for an incorrect target or unreachable preconditions.

A zero-finding run is a bounded negative observation, not evidence of complete security.

## Replay or promotion fails

Compare input identity, base snapshot, fork provenance, required cache entries, and execution assumptions. Read rejection details and distinguish replay mismatch from missing PoC tooling or failed assertions.

`prove-live` requires strict validation by default. Ensure `forge` is available and the generated project can execute in its intended environment. Preserve failed validation artifacts instead of relabeling them as confirmed findings.

## Verification fails after moving a run

Use `ops verify --run-id "$RUN_ID" --json` from the project containing the restored `.rustyfuzz` directory. Check that the move retained referenced evidence and did not change files. Review operation inventory limits and supported schemas.

Prefer the authenticated backup/restore workflow when transferring evidence. A partial copy is not a verified backup.

## A process stopped but the run is incomplete

Inspect `terminal_status.json`, the summary, and events. Process termination can interrupt finalization; cancellation, failure, and completion are different states. Preserve the incomplete run for diagnosis and use a fresh campaign ID for a separate attempt.

## Documentation changes do not appear

Rebuild the Jekyll site after changing Markdown, assets, or configuration. Serve only the generated `_site` directory. Restart a watch process after changing `_config.yml`; browser favicon caches may require a hard refresh.

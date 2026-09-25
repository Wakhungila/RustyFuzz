---
title: "CI integration"
section: "Run & operate"
nav_order: 9
description: "Capture campaign outcomes without confusing findings, incomplete evidence, and infrastructure failures."
---

## Make the run reproducible

Build from a pinned revision with the lockfile. Select a fixed target/fork context, use bounded execution, and inject RPC credentials from your CI secret store. Keep live RPC campaigns separate from tests intended to run without external services.

The following shell example assumes `rusty-fuzz` and `forge` are installed, `RPC_URL`, `TARGET`, and `FORK_BLOCK` are set, a valid local `config.toml` is present, and `RUN_ID` is a fresh safe campaign identifier.

## Preserve the exit status

```bash
set -u
status=0
rusty-fuzz prove-live \
  --target "$TARGET" \
  --rpc-url "$RPC_URL" \
  --block "$FORK_BLOCK" \
  --campaign-id "$RUN_ID" \
  --duration-secs 300 \
  --max-execs 100000 \
  --deterministic --rng-seed 42 || status=$?

integrity=0
rusty-fuzz ops verify --run-id "$RUN_ID" --json \
  > integrity.json || integrity=$?

printf 'Campaign exit: %s; integrity exit: %s\n' "$status" "$integrity"
if [ "$integrity" -ne 0 ]; then
  exit 1
fi
case "$status" in
  0) exit 0 ;;
  10) echo "Confirmed finding: review evidence"; exit 1 ;;
  11) echo "Unproven candidates: triage required"; exit 1 ;;
  20) echo "Promotion failure or rejection: review required"; exit 1 ;;
  *) echo "Campaign failed"; exit 1 ;;
esac
```

This is a conservative example policy: only a clean summary and successful integrity verification pass. Your organization may choose a different triage policy for leads, but should keep their classification visible.

## Upload evidence even on failure

Configure artifact upload as an always-run step in your CI system. Retain the canonical run directory, `integrity.json`, and relevant logs, subject to your secrecy and retention policy. If initialization failed before creating a run, keep the error output instead of fabricating a summary.

Do not publish `.env`, credential-bearing local configuration, or unreviewed research artifacts. An encrypted backup is appropriate when evidence must cross a storage boundary.

## Separate two kinds of validation

Repository tests check the RustyFuzz implementation. A target campaign investigates one contract under selected inputs and state. Neither substitutes for the other, and a campaign with zero findings does not demonstrate complete target security.

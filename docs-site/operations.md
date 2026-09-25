---
title: "Operations and recovery"
section: "Run & operate"
nav_order: 8
description: "Inspect campaign health, verify evidence, and test recovery using the local operations CLI."
---

## Inspect campaign state

Run operations commands from the project directory containing `.rustyfuzz`:

```bash
rusty-fuzz ops status --json
rusty-fuzz ops campaigns --json
rusty-fuzz ops events --run-id "$RUN_ID" --limit 20 --json
rusty-fuzz ops alerts --active --json
```

Use `--run-id` to inspect one campaign where supported. JSON output is available on status, campaigns, events, alerts, and verify; it is not a global option on every operations command.

## Verify evidence integrity

```bash
rusty-fuzz ops verify --run-id "$RUN_ID" --json
```

Treat verification failure as a distinct operational problem. Check missing files, changed evidence, unsupported records, and inventory limits before consuming the results downstream.

## Export metrics

```bash
rusty-fuzz ops metrics > operations.prom
```

Metrics are emitted as Prometheus exposition on stdout. This command does not start an HTTP metrics endpoint. Arrange collection through your own monitoring or CI artifact workflow.

## Create and inspect an encrypted backup

```bash
rusty-fuzz ops backup create \
  --run-id "$RUN_ID" \
  --output campaign-backup.bin \
  --strict

rusty-fuzz ops backup list
rusty-fuzz ops backup verify campaign-backup.bin
```

Backup encryption uses Argon2id-derived keys and XChaCha20-Poly1305 authenticated encryption. Commands read a hidden passphrase interactively, or use `RUSTYFUZZ_OPS_BACKUP_PASSPHRASE` for automation. Supply that variable through the CI secret store and avoid echoing it.

Verification authenticates and preflights the backup. There is no `backup preflight` CLI subcommand; use `backup verify`.

## Restore to an isolated location

```bash
rusty-fuzz ops backup restore campaign-backup.bin \
  --target /tmp/rustyfuzz-restored
```

Use a fresh isolated target outside the source project. Keep the original backup until restored evidence has been checked. Restore is not an instruction to overwrite your active campaign directory.

## Exercise the recovery path

```bash
rusty-fuzz ops drill restore campaign-backup.bin \
  --target /tmp/rustyfuzz-recovery-drill
```

A recovery drill runs the backup/restore verification path against an isolated target. Use `--keep-payload` only when you want to retain the restored payload for inspection. Test the path with the same credentials and storage process your team will rely on during recovery.

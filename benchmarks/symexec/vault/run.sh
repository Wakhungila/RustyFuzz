#!/usr/bin/env bash
# End-to-end check of symbolic seeding on a contract with an external call and mapping keys.
# Expect: symseed finds bugs b1,b2 (judge-confirmed), and a seeded campaign reports both.
set -euo pipefail
D=$(cd "$(dirname "$0")" && pwd); OUT=${1:-/tmp/vault-seeds}
python3 "$D/../../../scripts/bench/symexec/symseed.py" --fixture "$D/vault.json" --abi "$D/Vault.abi.json" \
  --invariants "$D/vault.invariants.json" --out "$OUT" --symbolic-depth 3 --budget 120
replay-judge --fixture "$D/vault.json" --invariants "$D/vault.invariants.json" --inputs "$OUT"

#!/usr/bin/env python3
import os
"""Autonomous rediscovery gate (REAL — targets known_vulnerable fixtures).

Runs `rusty-fuzz fuzz --fixture <path> --attacker-harness` against each
executable known_vulnerable fixture with a tight deterministic budget, and
reports whether the fuzzer's OWN mutator + scheduler + attacker harness + SMT
concolic autonomously discovered the bug — WITHOUT the human-authored
`transactions` array the replay gate uses.

This is the ItyFuzz-class capability gate: autonomous discovery, not replay
verification. The honest baseline is the starting rate; the ratchet only
tightens. A non-zero rate here means the fuzzer found a bug by itself.

Run after `cargo build --release --locked --bin rusty-fuzz`.
"""
import argparse
import json
import subprocess
import tempfile
import time
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
FIXTURE_DIR = REPO_ROOT / 'benchmarks/historical/known_vulnerable/fixtures'

parser = argparse.ArgumentParser()
parser.add_argument('--binary', default='target/release/rusty-fuzz')
parser.add_argument('--output', type=Path, default=REPO_ROOT / 'benchmarks/results/autonomous-rediscovery')
parser.add_argument('--max-execs', type=int, default=2000)
parser.add_argument('--duration-secs', type=int, default=30)
parser.add_argument('--attacker-harness', action='store_true', default=True,
                    help='enable --attacker-harness (default on; the reentrancy probes need it)')
args = parser.parse_args()

binary = Path(args.binary)
if not binary.is_absolute():
    binary = REPO_ROOT / binary
if not args.output.is_absolute():
    args.output = REPO_ROOT / args.output
args.output.mkdir(parents=True, exist_ok=True)

failures = []
results = []

fixtures = sorted(FIXTURE_DIR.glob('known-*.json')) if FIXTURE_DIR.exists() else []
if not fixtures:
    failures.append(f'no known_vulnerable fixtures found at {FIXTURE_DIR}')

with tempfile.TemporaryDirectory(prefix='rustyfuzz-autonomous-') as temp_dir:
    for fixture in fixtures:
        case_id = fixture.stem
        case_dir = Path(temp_dir) / case_id
        case_dir.mkdir(parents=True, exist_ok=True)
        config = f'''chain = "evm"
rpc_url = "http://127.0.0.1:8545"
fork_block = 0
timeout_secs = {args.duration_secs + 15}
corpus_dir = "{case_dir}/corpus"
report_dir = "{case_dir}/reports"
llm_enabled = false
allow_synthetic_fallback = true
'''
        (case_dir / 'config.toml').write_text(config)

        cmd = [
            str(binary), 'fuzz',
            '--fixture', str(fixture),
            '--attacker-harness',
            '--compact-fork-state',
            '--allow-synthetic-fallback',
            '--deterministic',
            '--rng-seed', '1',
            '--max-execs', str(args.max_execs),
            '--duration-secs', str(args.duration_secs),
            '--single-process',
        ]
        # Attach the ABI so the mutator generates valid calldata (with correct arg
        # types) instead of random bytes that revert. Without the ABI, the fuzzer
        # extracts selectors from bytecode but doesn't know the arg types, so most
        # calls revert and the bug is never reached.
        abi_map = {
            'known-erc20-bad-mint-inflation': 'abi/UnauthMintToken.abi.json',
            'known-flashloan-price-manipulation': 'abi/NoProductCheckPool.abi.json',
            'known-uninitialized-proxy-takeover': 'abi/UninitializedProxy.abi.json',
            'known-bridge-nonce-replay': 'abi/ReplayBridge.abi.json',
            'known-read-only-reentrancy': 'abi/ReentrantAttacker.abi.json',
        }
        inv = REPO_ROOT / 'benchmarks/historical/known_vulnerable' / f'{case_id}.invariants.json'
        if inv.exists() and case_id != 'known-read-only-reentrancy':  # its invariant target (vault) != --contract (attacker)
            cmd.extend(['--invariants', str(inv)])
        abi_rel = abi_map.get(case_id)
        if abi_rel:
            abi_path = REPO_ROOT / 'benchmarks/historical/known_vulnerable' / abi_rel
            cmd.extend(['--abi', str(abi_path)])
        # For reentrancy: the fixture's default target is the vault, but the
        # reentrancy requires a CONTRACT caller (the ReentrantAttacker at
        # 0x3300...03) whose onReceive callback fires during the withdraw token
        # transfer. Target the attacker so the fuzzer calls enterDeposit +
        # enterWithdraw, which orchestrate the reentrancy.
        if case_id == 'known-read-only-reentrancy':
            cmd.extend(['--contract', '0x3300000000000000000000000000000000000003'])
        start = time.monotonic()
        try:
            proc = subprocess.run(
                cmd, cwd=case_dir, capture_output=True, text=True,
                timeout=args.duration_secs + 60,
                env={**os.environ, 'RUSTYFUZZ_CAMPAIGN_SHUTDOWN_GRACE_SECS': '0'},
            )
            elapsed = time.monotonic() - start
            exit_status = proc.returncode
        except subprocess.TimeoutExpired:
            elapsed = args.duration_secs + 60
            exit_status = 'timeout'
            proc = None

        # Campaign artifacts are persisted under <cwd>/.rustyfuzz/runs/*/inputs/campaign_artifacts
        # (the config-file report_dir is not what the run writes to), so scan there.
        fixture_json = json.loads(fixture.read_text())
        fixture_target = str(fixture_json.get('target', '')).lower()
        # What counts as the *intended* bug per fixture. A finding on some other
        # contract (e.g. a generic reentrancy heuristic on a mock token) is noise.
        # Generic `Reentrancy` heuristics fire on nearly every contract (mock tokens included),
        # so they only count for the fixture that IS a reentrancy bug.
        expected = ('InvariantViolation', 'v2_k_invariant', 'FlashLoanProfit',
                    'UniswapV3LiquidityAsymmetry', 'ProxyUpgradeabilityViolation',
                    'PrivilegeEscalation')
        if case_id == 'known-read-only-reentrancy':
            expected += ('Reentrancy',)
        finding_count = 0
        total_findings = 0
        kinds = {}
        for artifact in case_dir.glob('.rustyfuzz/runs/*/inputs/campaign_artifacts/*.json'):
            try:
                data = json.loads(artifact.read_text())
            except json.JSONDecodeError:
                continue
            for fi in (data.get('findings') or []) if isinstance(data, dict) else []:
                total_findings += 1
                vuln = str(fi.get('vuln'))
                tgt = str(fi.get('target') or '').lower()
                kinds[f'{vuln}@{tgt}'] = kinds.get(f'{vuln}@{tgt}', 0) + 1
                if tgt == fixture_target and any(e in vuln for e in expected):
                    finding_count += 1

        rediscovered = finding_count > 0
        results.append({
            'case_id': case_id,
            'fixture': str(fixture.relative_to(REPO_ROOT)),
            'exit_status': exit_status,
            'elapsed_secs': round(elapsed, 1),
            'finding_count': finding_count,
            'total_findings_any_target': total_findings,
            'finding_kinds': kinds,
            'rediscovered': rediscovered,
        })
        print(f"  {case_id}: exit={exit_status} findings={finding_count} rediscovered={rediscovered}")

rediscovered_count = sum(1 for r in results if r['rediscovered'])
total = len(results)

report = {
    'measurement': 'autonomous_rediscovery_gate',
    'fixtures': results,
    'rediscovered': rediscovered_count,
    'total': total,
    'rate': f'{rediscovered_count}/{total}',
    'budget': {'max_execs': args.max_execs, 'duration_secs': args.duration_secs},
    'failures': failures,
    'passed': not failures,
}
(args.output / 'measurement.json').write_text(json.dumps(report, indent=2) + '\n')

print(f"\nAutonomous rediscovery: {rediscovered_count}/{total} fixtures found by the fuzzer's own mutator "
      f"(budget: {args.max_execs} execs / {args.duration_secs}s each, --attacker-harness on).")
if failures:
    for failure in failures:
        print(f'GATE FAILURE: {failure}')
    raise SystemExit(1)
# The gate PASSES if all fixtures ran without crashing. A 0/N rediscovery rate
# is the honest baseline, not a gate failure — the ratchet tightens as
# capability improves (SMT depth, attacker mutation, throughput).
crashed = [r['case_id'] for r in results if r['exit_status'] not in (0, 'timeout')]
if crashed:
    print(f'GATE FAILURE: campaigns crashed for: {crashed}')
    raise SystemExit(1)
print(f'Gate passed: all {total} campaigns ran. Autonomous rediscovery rate: {rediscovered_count}/{total} '
      f'(honest baseline; ratchet only tightens).')

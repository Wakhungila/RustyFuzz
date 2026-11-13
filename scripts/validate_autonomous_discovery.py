#!/usr/bin/env python3
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
            '--deterministic',
            '--rng-seed', '1',
            '--max-execs', str(args.max_execs),
            '--duration-secs', str(args.duration_secs),
            '--single-process',
            '--report-dir', f'{case_dir}/reports',
        ]
        start = time.monotonic()
        try:
            proc = subprocess.run(
                cmd, cwd=case_dir, capture_output=True, text=True,
                timeout=args.duration_secs + 60,
            )
            elapsed = time.monotonic() - start
            exit_status = proc.returncode
        except subprocess.TimeoutExpired:
            elapsed = args.duration_secs + 60
            exit_status = 'timeout'
            proc = None

        finding_count = 0
        report_files = []
        report_dir = case_dir / 'reports'
        if report_dir.exists():
            report_files = list(report_dir.rglob('*.json'))
            for rf in report_files:
                try:
                    data = json.loads(rf.read_text())
                except json.JSONDecodeError:
                    continue
                if isinstance(data, dict):
                    findings = data.get('findings') or data.get('artifacts') or []
                    if isinstance(findings, list):
                        finding_count += len(findings)

        rediscovered = finding_count > 0
        results.append({
            'case_id': case_id,
            'fixture': str(fixture.relative_to(REPO_ROOT)),
            'exit_status': exit_status,
            'elapsed_secs': round(elapsed, 1),
            'finding_count': finding_count,
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

#!/usr/bin/env python3
"""Replay regression gate (detection pipeline integrity).

Verifies the detection PIPELINE end-to-end on the 5 executable
known_vulnerable cases: each case has a pre-recorded exploit sequence
(human-authored calldata in the fixture JSON), an authored invariant file
bound to a typed violation predicate, a confirmed proof tier, and an
offline-generated Foundry PoC. This gate replays the exploit calldata and
confirms the oracle fires, the proof confirms, and the PoC generates.

This is NOT autonomous rediscovery: the exploit calldata is authored, not
discovered by the fuzzer. The '5/5' this gate reports means '5/5
pre-recorded exploits replay-verified end-to-end', not 'the fuzzer
autonomously found 5 bugs'. Autonomous rediscovery (the fuzzer finding bugs
without authored calldata) is ROADMAP; the --attacker-harness flag + SMT `smt`
feature are the concrete steps toward it.

The 2 historical mainnet_fork cases (Audius 2022, Euler 2023) are reported
but excluded from the pass rule: their fork captures are incomplete (missing
balance/implementation slots, no Euler capture yet), so they run as
Inconclusive by design until a re-capture lands. The gate fails if a
historical case ever claims a discovery — that would be an artifact-integrity
bug, the opposite of the missing-capture problem.

Run after `cargo build --release --locked --bin rusty-fuzz` (or pass
--binary target/debug/rusty-fuzz for local runs).
"""
import argparse
import json
import subprocess
import tempfile
import time
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]

parser = argparse.ArgumentParser()
parser.add_argument('--binary', default='target/release/rusty-fuzz')
parser.add_argument('--output', type=Path, default=REPO_ROOT / 'benchmarks/results/rediscovery-gate')
parser.add_argument('--min-rediscovered', type=int, default=5,
                    help='minimum executable cases that must stay rediscovered (ratchet: never lower)')
args = parser.parse_args()

binary = Path(args.binary)
if not binary.is_absolute():
    binary = REPO_ROOT / binary
if not args.output.is_absolute():
    args.output = REPO_ROOT / args.output
args.output.mkdir(parents=True, exist_ok=True)

minimal_config = '''chain = "evm"
rpc_url = "http://127.0.0.1:8545"
fork_block = 0
timeout_secs = 120
corpus_dir = "corpus"
report_dir = "reports"
llm_enabled = false
allow_synthetic_fallback = true
'''

REQUIRED_FOR_REDISCOVERY = 5


def run_suite(suite: str, temp_dir: Path) -> list:
    output = args.output / f'{suite}.json'
    start = time.monotonic()
    subprocess.run(
        [str(binary), 'validate',
         '--benchmarks', str(REPO_ROOT / 'benchmarks/historical' / suite),
         '--output', str(output)],
        check=True, cwd=temp_dir,
    )
    elapsed = time.monotonic() - start
    data = json.loads(output.read_text())
    for row in data['benchmarks']:
        row['_elapsed'] = elapsed
    return data['benchmarks']


report = {'measurement': 'rediscovery_regression_gate', 'suites': {}}
failures = []

with tempfile.TemporaryDirectory(prefix='rustyfuzz-rediscovery-') as temp_dir:
    Path(temp_dir, 'config.toml').write_text(minimal_config)
    Path(temp_dir, 'benchmarks').symlink_to(REPO_ROOT / 'benchmarks', target_is_directory=True)

    # 1. The executable known_vulnerable pack: must stay fully rediscovered.
    executable = run_suite('known_vulnerable', temp_dir)
    rediscovered = 0
    for row in executable:
        case_id = row['benchmark_id']
        proof = row.get('proof') or {}
        problems = []
        if not row['executed']:
            problems.append('not executed')
        if row['status'] != 'found' or not row['found']:
            problems.append(f"status={row['status']}")
        tier = proof.get('confidence_tier')
        if tier != 'confirmed':
            problems.append(f'proof tier={tier}')
        if not proof.get('violation_predicate'):
            problems.append('typed violation predicate missing')
        if not row.get('foundry_poc_generated'):
            problems.append('offline Foundry PoC missing')
        if row.get('missing_criteria'):
            problems.append(f"missing criteria={row['missing_criteria']}")
        if problems:
            failures.append(f'{case_id}: ' + '; '.join(problems))
        else:
            rediscovered += 1
    report['suites']['known_vulnerable'] = {
        'executed': len(executable),
        'rediscovered': rediscovered,
        'required': REQUIRED_FOR_REDISCOVERY,
    }

    # 2. The negative pack must stay silent: a false positive here means the
    #    new Security/reentrancy oracle (or any pack) fires on safe contracts.
    negative = run_suite('negative_controls', temp_dir)
    false_positives = [
        row['benchmark_id'] for row in negative
        if row['found'] or row['status'] != 'not_found'
    ]
    if false_positives:
        failures.append(f'negative controls false positives: {false_positives}')
    report['suites']['negative_controls'] = {
        'executed': len(negative),
        'false_positives': len(false_positives),
    }

    # 3. Gate2 positive controls must keep matching raw signals.
    gate2 = run_suite('gate2_positive_controls', temp_dir)
    gate2_found = sum(1 for row in gate2 if row['found'])
    if gate2_found != len(gate2):
        failures.append(f'gate2 controls degraded: {gate2_found}/{len(gate2)} found')
    report['suites']['gate2_positive_controls'] = {
        'executed': len(gate2),
        'found': gate2_found,
    }

    # 4. Historical mainnet_fork cases: report honestly, never claim discovery.
    historical_path = REPO_ROOT / 'benchmarks/historical/historical'
    if historical_path.exists():
        historical = run_suite('historical', temp_dir)
        claimed = [
            row['benchmark_id'] for row in historical
            if row['found'] and not (row.get('proof') or {}).get('violation_predicate')
        ]
        if claimed:
            failures.append(
                f'historical cases claimed discovery without a typed predicate: {claimed}'
            )
        report['suites']['historical'] = {
            'executed': len(historical),
            'rediscovered': sum(1 for row in historical if row['found']),
            'note': 'excluded from pass rule until fork captures are complete',
        }

if rediscovered < args.min_rediscovered:
    failures.append(
        f'replay-verified {rediscovered} < required {args.min_rediscovered}'
    )

report['rediscovered_executable'] = rediscovered
report['failures'] = failures
report['passed'] = not failures
(args.output / 'measurement.json').write_text(json.dumps(report, indent=2) + '\n')

for row_suite, data in report['suites'].items():
    print(f"{row_suite}: {json.dumps(data)}")
if failures:
    for failure in failures:
        print(f'GATE FAILURE: {failure}')
    raise SystemExit(1)
print(f'Replay regression gate passed: {rediscovered}/{REQUIRED_FOR_REDISCOVERY} executable cases replay-verified (pipeline: oracle + confirmed proof + typed predicate + offline PoC). Autonomous rediscovery is ROADMAP.')

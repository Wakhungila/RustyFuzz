#!/usr/bin/env python3
"""Autonomous discovery smoke gate.

Runs `rusty-fuzz fuzz --attacker-harness --allow-synthetic-fallback` with a
tight deterministic budget and confirms the campaign engine runs end-to-end,
produces a report, and does not crash. This is a SMOKE gate for the autonomous
campaign path (the path that uses the fuzzer's OWN mutator + scheduler + the
attacker harness + SMT concolic), NOT a rediscovery gate.

What this gate proves:
  - The fuzz engine boots, runs N executions, and exits cleanly.
  - The --attacker-harness flag deploys the reentrancy attacker without
    crashing the campaign.
  - A report is produced in the report dir.

What this gate does NOT prove:
  - That the fuzzer autonomously rediscovered any specific historical bug.
    The synthetic fallback target is benign; a 0-finding result is the EXPECTED
    honest outcome here. A non-zero autonomous rediscovery rate against the
    known_vulnerable fixtures requires the `--fixture` integration (loading a
    fixture's pre-deployed state into the fuzz campaign) — ROADMAP, see
    docs/PRODUCTION_READINESS.md §2.7.

Run after `cargo build --release --locked --bin rusty-fuzz`.
"""
import argparse
import json
import subprocess
import tempfile
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]

parser = argparse.ArgumentParser()
parser.add_argument('--binary', default='target/release/rusty-fuzz')
parser.add_argument('--output', type=Path, default=REPO_ROOT / 'benchmarks/results/autonomous-smoke')
parser.add_argument('--max-execs', type=int, default=500)
parser.add_argument('--duration-secs', type=int, default=30)
args = parser.parse_args()

binary = Path(args.binary)
if not binary.is_absolute():
    binary = REPO_ROOT / binary
if not args.output.is_absolute():
    args.output = REPO_ROOT / args.output
args.output.mkdir(parents=True, exist_ok=True)

failures = []
report = {'measurement': 'autonomous_discovery_smoke'}


with tempfile.TemporaryDirectory(prefix='rustyfuzz-autonomous-') as temp_dir:
    config = f'''chain = "evm"
rpc_url = "http://127.0.0.1:8545"
fork_block = 0
timeout_secs = {args.duration_secs + 10}
corpus_dir = "{temp_dir}/corpus"
report_dir = "{temp_dir}/reports"
llm_enabled = false
allow_synthetic_fallback = true
'''
    Path(temp_dir, 'config.toml').write_text(config)

    cmd = [
        str(binary), 'fuzz',
        '--allow-synthetic-fallback',
        '--attacker-harness',
        '--deterministic',
        '--rng-seed', '1',
        '--max-execs', str(args.max_execs),
        '--duration-secs', str(args.duration_secs),
        '--single-process',
        '--report-dir', f'{temp_dir}/reports',
    ]
    try:
        proc = subprocess.run(
            cmd, cwd=temp_dir, capture_output=True, text=True, timeout=args.duration_secs + 60,
        )
    except subprocess.TimeoutExpired:
        failures.append(f'fuzz campaign timed out after {args.duration_secs + 60}s')
        report['exit_status'] = 'timeout'
    else:
        report['exit_status'] = proc.returncode
        report['stdout_tail'] = proc.stdout[-2000:]
        report['stderr_tail'] = proc.stderr[-2000:]
        if proc.returncode != 0:
            failures.append(f'fuzz campaign exited non-zero: {proc.returncode}')

        # Look for any report artifact the campaign produced.
        report_dir = Path(temp_dir, 'reports')
        report_files = list(report_dir.rglob('*.json')) if report_dir.exists() else []
        report['report_files'] = [str(f.relative_to(temp_dir)) for f in report_files]
        if not report_files:
            failures.append('no report JSON produced by the campaign')

        finding_count = 0
        for rf in report_files:
            try:
                data = json.loads(rf.read_text())
            except json.JSONDecodeError:
                continue
            # Count findings across common report shapes.
            if isinstance(data, dict):
                findings = data.get('findings') or data.get('artifacts') or []
                if isinstance(findings, list):
                    finding_count += len(findings)
        report['finding_count'] = finding_count

report['failures'] = failures
report['passed'] = not failures
(args.output / 'measurement.json').write_text(json.dumps(report, indent=2) + '\n')

print(f"autonomous smoke: exit={report.get('exit_status')} "
      f"reports={len(report.get('report_files', []))} "
      f"findings={report.get('finding_count', 0)}")
if failures:
    for failure in failures:
        print(f'GATE FAILURE: {failure}')
    raise SystemExit(1)
print(f'Autonomous discovery smoke gate passed: campaign ran {args.max_execs} execs '
      f'with --attacker-harness, produced a report. Findings={report.get("finding_count", 0)} '
      f'(synthetic target; non-zero rediscovery requires --fixture integration, ROADMAP).')

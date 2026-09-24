#!/usr/bin/env python3
"""Gate real EVM fixture detection. This is not a discovery-speed benchmark."""
import argparse
import json
import subprocess
import tempfile
import time
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]

parser = argparse.ArgumentParser()
parser.add_argument('--binary', default='target/release/rusty-fuzz')
parser.add_argument('--output', type=Path, default=REPO_ROOT / 'benchmarks/results/oracle-controls')
args = parser.parse_args()
binary = Path(args.binary)
if not binary.is_absolute():
    binary = REPO_ROOT / binary
if not args.output.is_absolute():
    args.output = REPO_ROOT / args.output
args.output.mkdir(parents=True, exist_ok=True)
report = {'measurement': 'deterministic_fixture_replay', 'suites': {}}
minimal_config = '''chain = "evm"
rpc_url = "http://127.0.0.1:8545"
fork_block = 0
timeout_secs = 1
corpus_dir = "corpus"
report_dir = "reports"
llm_enabled = false
allow_synthetic_fallback = true
'''
with tempfile.TemporaryDirectory(prefix='rustyfuzz-oracle-') as temp_dir:
    Path(temp_dir, 'config.toml').write_text(minimal_config)
    Path(temp_dir, 'benchmarks').symlink_to(REPO_ROOT / 'benchmarks', target_is_directory=True)
    for suite, count, expected_found in [('negative_controls', 10, False), ('gate2_positive_controls', 5, True)]:
        output = args.output / (suite + '.json')
        start = time.monotonic()
        subprocess.run([str(binary), 'validate', '--benchmarks', str(REPO_ROOT / 'benchmarks/historical' / suite),
                        '--output', str(output)], check=True, cwd=temp_dir)
        elapsed = time.monotonic() - start
        data = json.loads(output.read_text())
        rows = data['benchmarks']
        assert len(rows) == count, (suite, len(rows))
        families = {}
        for row in rows:
            assert row['executed'] and row['status'] == ('found' if expected_found else 'not_found'), row
            assert row['found'] == expected_found, row
            runtime = row['runtime']
            assert bool(runtime['matching_signals']) == expected_found, row
            assert runtime['transactions'] and all(t['coverage_edges'] > 0 for t in runtime['transactions']), row
            assert row['proof'] is None and row['proof_status'] is None and row['artifact_path'] is None, row
            assert not row['foundry_poc_generated'], row
            families.setdefault(row['class'], []).append(row)
        assert len(families) == 5 and all(len(v) == (2 if not expected_found else 1) for v in families.values())
        report['suites'][suite] = {
            'executed': count, 'matching_controls': sum(r['found'] for r in rows),
            'unmatched_signals': sum(len(r['runtime']['unmatched_signals']) for r in rows),
            'process_wall_seconds': elapsed,
            'families': {k: {'executed': len(v), 'matching_controls': sum(r['found'] for r in v)} for k,v in families.items()}}
(args.output / 'measurement.json').write_text(json.dumps(report, indent=2) + '\n')
print(json.dumps(report, indent=2))

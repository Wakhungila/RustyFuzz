#!/usr/bin/env python3
"""Determinism gate: two identical-seed single-process runs must produce identical results.

Fails if coverage edges, artifact count or the multiset of finding kinds differ. Guards
against hash-iteration-order dependence (e.g. indexing into a HashSet), which once made the
flashloan finding appear in only some runs.
"""
import json, os, subprocess, sys, tempfile, pathlib, collections

ROOT = pathlib.Path(__file__).resolve().parent.parent
BIN = ROOT / 'target/release/rusty-fuzz'
FIX = ROOT / 'benchmarks/historical/known_vulnerable'
CASE = 'known-flashloan-price-manipulation'
EXECS = os.environ.get('RF_DET_EXECS', '3000')


def run_once(tag):
    d = pathlib.Path(tempfile.mkdtemp(prefix=f'rf-det-{tag}-'))
    (d / 'config.toml').write_text(
        'chain = "evm"\nrpc_url = "http://127.0.0.1:8545"\nfork_block = 0\ntimeout_secs = 60\n'
        'corpus_dir = "corpus"\nreport_dir = "reports"\nllm_enabled = false\nallow_synthetic_fallback = true\n')
    cmd = [str(BIN), 'fuzz', '--fixture', str(FIX / f'fixtures/{CASE}.json'),
           '--abi', str(FIX / 'abi/NoProductCheckPool.abi.json'),
           '--invariants', str(FIX / f'{CASE}.invariants.json'),
           '--attacker-harness', '--compact-fork-state', '--allow-synthetic-fallback',
           '--deterministic', '--rng-seed', '1', '--max-execs', EXECS,
           '--duration-secs', '60', '--single-process']
    subprocess.run(cmd, cwd=d, capture_output=True, timeout=180,
                   env={**os.environ, 'RUSTYFUZZ_CAMPAIGN_SHUTDOWN_GRACE_SECS': '0'})
    kinds = collections.Counter()
    for f in d.glob('.rustyfuzz/runs/*/inputs/campaign_artifacts/*.json'):
        for fi in (json.loads(f.read_text()).get('findings') or []):
            kinds[json.dumps(fi.get('vuln'), sort_keys=True)] += 1
    summary = json.loads(next(d.glob('.rustyfuzz/runs/*/reports/campaign_summary.json')).read_text())
    return {'coverage_edges': summary['coverage_edges'], 'total_artifacts': summary['total_artifacts'],
            'kinds': dict(sorted(kinds.items()))}


a, b = run_once('a'), run_once('b')
print('run a:', a)
print('run b:', b)
if a != b:
    print('Determinism gate FAILED: identical seed produced different campaigns')
    sys.exit(1)
print('Determinism gate passed.')

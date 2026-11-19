#!/usr/bin/env python3
"""Throughput regression gate.

Runs a fixed-duration single-process campaign on committed fixtures and fails if
executions/second drops below a floor. Floors are deliberately conservative
(~50% of the measured rate on the reference sandbox) so noise doesn't flake,
but a re-introduced O(corpus)-per-exec path or per-exec fsync will trip them.

Run after `cargo build --release --bin rusty-fuzz`.
"""
import argparse, json, os, subprocess, tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
FIX = ROOT / 'benchmarks/historical/known_vulnerable'
CASES = {
    # case -> (abi, floor exec/s)
    'known-erc20-bad-mint-inflation': ('abi/UnauthMintToken.abi.json', int(os.environ.get('RF_FLOOR_ERC20', 60))),
    'known-flashloan-price-manipulation': ('abi/NoProductCheckPool.abi.json', int(os.environ.get('RF_FLOOR_FLASH', 60))),
}
ap = argparse.ArgumentParser()
ap.add_argument('--binary', default=str(ROOT / 'target/release/rusty-fuzz'))
ap.add_argument('--duration-secs', type=int, default=30)
args = ap.parse_args()

failures, rows = [], []
for case, (abi, floor) in CASES.items():
    with tempfile.TemporaryDirectory(prefix='rf-throughput-') as d:
        d = Path(d)
        (d / 'config.toml').write_text(
            'chain = "evm"\nrpc_url = "http://127.0.0.1:8545"\nfork_block = 0\n'
            f'timeout_secs = {args.duration_secs + 30}\ncorpus_dir = "corpus"\nreport_dir = "reports"\n'
            'llm_enabled = false\nallow_synthetic_fallback = true\n')
        cmd = [args.binary, 'fuzz', '--fixture', str(FIX / 'fixtures' / f'{case}.json'),
               '--abi', str(FIX / abi), '--attacker-harness', '--compact-fork-state',
               '--allow-synthetic-fallback', '--deterministic', '--rng-seed', '1',
               '--max-execs', '100000', '--duration-secs', str(args.duration_secs), '--single-process']
        subprocess.run(cmd, cwd=d, capture_output=True, text=True, timeout=args.duration_secs + 90,
                       env={**os.environ, 'RUSTYFUZZ_CAMPAIGN_SHUTDOWN_GRACE_SECS': '0'})
        execs = 0
        for f in d.glob('.rustyfuzz/runs/*/reports/campaign_summary*.json'):
            execs = max(execs, json.loads(f.read_text()).get('total_executions', 0))
        rate = execs / args.duration_secs
        ok = rate >= floor
        rows.append({'case': case, 'executions': execs, 'exec_per_sec': round(rate, 1), 'floor': floor, 'ok': ok})
        print(f"  {case}: {execs} execs, {rate:.1f}/s (floor {floor}) {'ok' if ok else 'REGRESSION'}")
        if not ok:
            failures.append(case)
out = ROOT / 'benchmarks/results/throughput'
out.mkdir(parents=True, exist_ok=True)
(out / 'measurement.json').write_text(json.dumps({'cases': rows, 'passed': not failures}, indent=2) + '\n')
if failures:
    raise SystemExit(f'THROUGHPUT REGRESSION: {failures}')
print('Throughput gate passed.')

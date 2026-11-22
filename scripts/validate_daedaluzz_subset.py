#!/usr/bin/env python3
"""CI gate: Daedaluzz subset scored by the oracle-independent replay judge.

Runs RustyFuzz on prebuilt mazes (benchmarks/daedaluzz/maze-{0,3}) for several seeds, then
  1. replays every stored input with `replay-judge` (reads __bugs[N] straight from storage), and
  2. FAILS if RustyFuzz's own oracle claimed a bug the judge could not reproduce (false positive), and
  3. FAILS if the judge-confirmed union falls below the floor (capability regression; the floor is
     deliberately far below the measured value because CI runners are slower and per-seed variance is 3-5).
Prints per-seed confirmed ids so variance is visible.
"""
import argparse, json, os, re, shutil, subprocess, sys, tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ap = argparse.ArgumentParser()
ap.add_argument('--mazes', default='0,3')
ap.add_argument('--seeds', default='1,2')
ap.add_argument('--secs', type=int, default=60)
ap.add_argument('--floor', type=int, default=int(os.environ.get('RF_DZ_FLOOR', '3')))
ap.add_argument('--bin', default=str(ROOT / 'target/release/rusty-fuzz'))
ap.add_argument('--judge', default=str(ROOT / 'target/release/replay-judge'))
args = ap.parse_args()
CFG = ('chain = "evm"\nrpc_url = "http://127.0.0.1:8545"\nfork_block = 0\ntimeout_secs = %d\n'
       'corpus_dir = "corpus"\nreport_dir = "reports"\nllm_enabled = false\nallow_synthetic_fallback = true\n')
union, false_positives, rows = set(), [], []
for m in args.mazes.split(','):
    base = ROOT / f'benchmarks/daedaluzz/maze-{m}'
    for seed in args.seeds.split(','):
        w = Path(tempfile.mkdtemp(prefix=f'dz{m}-{seed}-'))
        (w / 'config.toml').write_text(CFG % (args.secs + 40))
        subprocess.run([args.bin, 'fuzz', '--fixture', f'{base}.json', '--abi', f'{base}.abi.json',
                        '--invariants', f'{base}.invariants.json', '--attacker-harness', '--compact-fork-state',
                        '--allow-synthetic-fallback', '--deterministic', '--rng-seed', seed,
                        '--max-execs', '100000', '--duration-secs', str(args.secs), '--single-process'],
                       cwd=w, capture_output=True, text=True, timeout=args.secs + 180,
                       env={**os.environ, 'RUSTYFUZZ_CAMPAIGN_SHUTDOWN_GRACE_SECS': '0'})
        claimed = set()
        for f in w.glob('.rustyfuzz/runs/*/inputs/campaign_artifacts/*.json'):
            for fi in json.loads(f.read_text()).get('findings', []):
                mm = re.search(r'sum\(b(\d+)\) <= 0', json.dumps(fi))
                if mm:
                    claimed.add(int(mm.group(1)))
        confirmed = set()
        for inp in w.glob('.rustyfuzz/runs/*/inputs/inputs'):
            j = subprocess.run([args.judge, '--fixture', f'{base}.json', '--invariants', f'{base}.invariants.json',
                                '--inputs', str(inp)], capture_output=True, text=True)
            mm = re.search(r'ids=\{([^}]*)\}', j.stdout)
            if j.returncode != 0 or not mm:
                sys.exit(f'replay-judge failed: {j.stderr[-300:]}')
            confirmed |= {int(x) for x in mm.group(1).split(',') if x.strip()}
        fp = sorted(claimed - confirmed)
        false_positives += [(m, seed, i) for i in fp]
        union |= {(m, i) for i in confirmed}
        rows.append({'maze': m, 'seed': seed, 'judge_confirmed': sorted(confirmed), 'oracle_claimed': sorted(claimed),
                     'oracle_not_reproduced': fp})
        print(json.dumps(rows[-1]), flush=True)
        shutil.rmtree(w, ignore_errors=True)
out = ROOT / 'benchmarks/results/daedaluzz-subset'; out.mkdir(parents=True, exist_ok=True)
(out / 'measurement.json').write_text(json.dumps({'rows': rows, 'union': len(union), 'floor': args.floor}, indent=2) + '\n')
print(f'judge-confirmed union: {len(union)} (floor {args.floor}); oracle false positives: {len(false_positives)}')
if false_positives:
    sys.exit(f'FAIL: oracle claimed bugs the judge could not reproduce: {false_positives}')
if len(union) < args.floor:
    sys.exit(f'FAIL: judge-confirmed union {len(union)} < floor {args.floor}')
print('Daedaluzz subset gate passed')

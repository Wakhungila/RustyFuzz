#!/usr/bin/env python3
"""Daedaluzz head-to-head: RustyFuzz vs ItyFuzz, distinct bug ids found per maze.

Both tools run on the SAME instrumented maze (instrument_maze.py), one core, same wall-clock
budget, sequentially. A bug id counts as found when:
  - ItyFuzz prints `Invariant "N" violated` (typed-bug event), or
  - RustyFuzz: ONLY if `replay-judge` (src/bin/replay-judge.rs) confirms it: every stored input is
    replayed on pristine fixture state and `__bugs[N]` is read straight from contract storage.
    RustyFuzz's own oracle/findings are reported as `oracle_claimed` but never counted.
Needs: node + `npm i solc@0.8.28` (NODE_PATH), the Daedaluzz repo, an ItyFuzz binary.
"""
import argparse, json, os, re, shutil, subprocess, sys, time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
ap = argparse.ArgumentParser()
ap.add_argument('--daedaluzz', required=True, help='path to a clone of github.com/fuzzland/daedaluzz')
ap.add_argument('--ityfuzz', required=True)
ap.add_argument('--rustyfuzz', default=str(ROOT / 'target/release/rusty-fuzz'))
ap.add_argument('--work', required=True)
ap.add_argument('--solcjs-dir', required=True, help='dir containing node_modules/solc')
ap.add_argument('--mazes', default='0,1,2,3,4')
ap.add_argument('--secs', type=int, default=120)
ap.add_argument('--seed', type=int, default=1)
ap.add_argument('--seeds', default='', help='comma list; overrides --seed; reports per-seed and union')
ap.add_argument('--judge', default=str(ROOT / 'target/release/replay-judge'))
args = ap.parse_args()
work = Path(args.work); work.mkdir(parents=True, exist_ok=True)
env = {**os.environ, 'NODE_PATH': str(Path(args.solcjs_dir) / 'node_modules')}
solcjs = Path(args.solcjs_dir) / 'node_modules/.bin/solcjs'
CFG = ('chain = "evm"\nrpc_url = "http://127.0.0.1:8545"\nfork_block = 0\ntimeout_secs = %d\n'
       'corpus_dir = "corpus"\nreport_dir = "reports"\nllm_enabled = false\nallow_synthetic_fallback = true\n')

results = []
for i in [int(x) for x in args.mazes.split(',')]:
    d = work / f'maze-{i}'; d.mkdir(exist_ok=True)
    subprocess.run([sys.executable, str(ROOT / 'scripts/bench/instrument_maze.py'),
                    f'{args.daedaluzz}/generated-mazes/maze-{i}.sol', str(d / 'Maze.sol')], check=True)
    subprocess.run(['node', str(ROOT / 'scripts/bench/maze_prepare.js'), str(d)], check=True, env=env, cwd=work)
    subprocess.run([str(solcjs), '--bin', '--abi', '--optimize', 'Maze.sol'], cwd=d, env=env,
                   capture_output=True)
    (d / 'b').mkdir(exist_ok=True)
    for f in d.glob('Maze_sol_Maze.*'):
        shutil.move(str(f), d / 'b' / f.name)
    total = len(json.loads((d.with_suffix('.invariants.json')).read_text())['invariants'])

    # ItyFuzz
    w = d / 'ity-work'; shutil.rmtree(w, ignore_errors=True)
    t0 = time.monotonic()
    try:
        p = subprocess.run([args.ityfuzz, 'evm', '-t', 'b/*', '-d', 'typed_bug', '--run-forever',
                            '--work-dir', str(w)], cwd=d, capture_output=True, text=True, timeout=args.secs)
        out = p.stdout + p.stderr
    except subprocess.TimeoutExpired as e:
        out = (e.stdout or b'').decode(errors='ignore') + (e.stderr or b'').decode(errors='ignore')
    ity = sorted({int(m) for m in re.findall(r'Invariant "(\d+)" violated', re.sub(r'\x1b\[[0-9;]*m', '', out))})
    shutil.rmtree(w, ignore_errors=True)

    # RustyFuzz (one run per seed; counted only when the replay judge confirms the bug id)
    seeds = [int(x) for x in args.seeds.split(',')] if args.seeds else [args.seed]
    rf, claimed, per_seed, execs = set(), set(), {}, 0
    for seed in seeds:
        r = d / 'rf'; shutil.rmtree(r, ignore_errors=True); r.mkdir()
        (r / 'config.toml').write_text(CFG % (args.secs + 40))
        subprocess.run([args.rustyfuzz, 'fuzz', '--fixture', str(d) + '.json', '--abi', str(d) + '.abi.json',
                        '--invariants', str(d) + '.invariants.json', '--attacker-harness', '--compact-fork-state',
                        '--allow-synthetic-fallback', '--deterministic', '--rng-seed', str(seed),
                        '--max-execs', '100000', '--duration-secs', str(args.secs), '--single-process'],
                       cwd=r, capture_output=True, text=True, timeout=args.secs + 120,
                       env={**os.environ, 'RUSTYFUZZ_CAMPAIGN_SHUTDOWN_GRACE_SECS': '0'})
        for f in r.glob('.rustyfuzz/runs/*/inputs/campaign_artifacts/*.json'):
            for fi in json.loads(f.read_text()).get('findings', []):
                m = re.search(r'sum\(b(\d+)\) <= 0', json.dumps(fi))
                if m:
                    claimed.add(int(m.group(1)))
        confirmed = set()
        for inp in r.glob('.rustyfuzz/runs/*/inputs/inputs'):
            j = subprocess.run([args.judge, '--fixture', str(d) + '.json', '--invariants', str(d) + '.invariants.json',
                                '--inputs', str(inp)], capture_output=True, text=True)
            m = re.search(r'ids=\{([^}]*)\}', j.stdout)
            if j.returncode != 0 or not m:
                sys.exit(f'replay-judge failed for maze {i} seed {seed}: {j.stderr[-300:]}')
            confirmed |= {int(x) for x in m.group(1).split(',') if x.strip()}
        per_seed[seed] = sorted(confirmed)
        rf |= confirmed
        for f in r.glob('.rustyfuzz/runs/*/reports/campaign_summary*.json'):
            execs = max(execs, json.loads(f.read_text()).get('total_executions', 0))
        shutil.rmtree(r, ignore_errors=True)
    row = {'maze': i, 'total_bugs': total, 'ityfuzz': len(ity), 'rustyfuzz': len(rf),
           'both': len(set(ity) & rf), 'only_ityfuzz': sorted(set(ity) - rf), 'only_rustyfuzz': sorted(rf - set(ity)),
           'rustyfuzz_execs': execs, 'oracle_claimed': sorted(claimed), 'per_seed': per_seed}
    results.append(row)
    print(json.dumps(row), flush=True)

summary = {'secs': args.secs, 'seeds': [int(x) for x in args.seeds.split(',')] if args.seeds else [args.seed], 'rustyfuzz_counting': 'replay-judge confirmed (union over seeds)', 'mazes': results,
           'ityfuzz_total': sum(r['ityfuzz'] for r in results),
           'rustyfuzz_total': sum(r['rustyfuzz'] for r in results),
           'bugs_total': sum(r['total_bugs'] for r in results)}
out = ROOT / 'benchmarks/results/daedaluzz'; out.mkdir(parents=True, exist_ok=True)
(out / 'measurement.json').write_text(json.dumps(summary, indent=2) + '\n')
print(f"ItyFuzz {summary['ityfuzz_total']}/{summary['bugs_total']}  RustyFuzz {summary['rustyfuzz_total']}/{summary['bugs_total']}")

#!/usr/bin/env python3
"""Symbolically explore a Daedaluzz maze from bytecode only; emit replay-judge inputs."""
import json, sys, os, time
sys.path.insert(0, os.path.dirname(__file__))
from symexec import *
fx, outdir = sys.argv[1], sys.argv[2]
budget = int(sys.argv[3]) if len(sys.argv) > 3 else 600
j = json.load(open(fx.replace('.json', '') + '.json'))
inv = json.load(open(fx.replace('.json', '') + '.invariants.json'))
tgt = j['target'].lower()
code = bytes.fromhex(next(a for a in j['accounts'] if a['address'].lower() == tgt)['runtime_bytecode'][2:])
ids = sorted(int(k[1:], ) for k in inv['symbols'] if k[0] == 'b' and k[1:].isdigit())
watch = {int.from_bytes(k256(i.to_bytes(32, 'big') + (0).to_bytes(32, 'big')), 'big'): i for i in ids}
dirs = ['moveNorth', 'moveEast', 'moveSouth', 'moveWest']
sigs = [f'{d}(uint64,uint64,uint64,uint64,uint64,uint64,uint64,uint64)' for d in dirs]
found, seen, stats = explore(code, sigs, 8, {}, watch, budget_s=budget)
print('FOUND', len(found), sorted(found), stats, 'states', len(seen))
os.makedirs(outdir, exist_ok=True)
for b, seq in found.items():
    txs = []
    for s, args in seq:
        data = list(selector(s) + b''.join(a.to_bytes(32, 'big') for a in args))
        txs.append({'input': data, 'caller': '0x' + '13' * 20, 'to': j['target'], 'value': '0x0', 'is_victim': False})
    json.dump({'txs': txs, 'base_snapshot_id': 0}, open(f'{outdir}/bug{b}.json', 'w'))

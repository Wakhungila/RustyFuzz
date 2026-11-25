import json, sys, os, re
from collections import deque
from Crypto.Hash import keccak
sol = json.load(open(sys.argv[1])); src = open(sys.argv[2]).read(); outdir = sys.argv[3]; os.makedirs(outdir, exist_ok=True)
walls = {(int(a), int(b)) for a, b in re.findall(r'if \(x == (\d+) && y == (\d+)\) \{\s*require\(false\);', src)}
DIRS = {'moveNorth': (0, 1), 'moveSouth': (0, -1), 'moveEast': (1, 0), 'moveWest': (-1, 0)}
def sel(name):
    k = keccak.new(digest_bits=256); k.update(f'{name}(uint64,uint64,uint64,uint64,uint64,uint64,uint64,uint64)'.encode()); return k.digest()[:4]
def call(name, args): return list(sel(name) + b''.join(a.to_bytes(32, 'big') for a in args))
def path(goal):
    q = deque([((0, 0), [])]); seen = {(0, 0)}
    while q:
        c, p = q.popleft()
        if c == goal: return p
        for n, (dx, dy) in DIRS.items():
            nx, ny = c[0] + dx, c[1] + dy
            if 0 <= nx < 7 and 0 <= ny < 7 and (nx, ny) not in walls and (nx, ny) not in seen:
                seen.add((nx, ny)); q.append(((nx, ny), p + [n]))
    return None
n = 0
for bug, v in sol.items():
    if 'args' not in v: continue
    moves = path(tuple(v['cell']))
    if moves is None: v['unreachable_cell'] = True; continue
    txs = [{'input': call(m, v['args'] if i == len(moves) - 1 else [0] * 8), 'caller': '0x1313131313131313131313131313131313131313',
            'to': '0x6200000000000000000000000000000000000001', 'value': '0x0', 'is_victim': False} for i, m in enumerate(moves)]
    json.dump({'txs': txs, 'base_snapshot_id': 0}, open(f'{outdir}/bug{bug}.json', 'w')); n += 1
print('walls', len(walls), 'inputs', n)

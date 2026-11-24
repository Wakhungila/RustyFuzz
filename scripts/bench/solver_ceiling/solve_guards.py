import re, sys, json, z3
src = open(sys.argv[1]).read()
P = [z3.BitVec(f'p{i}', 64) for i in range(8)]
def parse_expr(s):
    toks = re.findall(r'uint64|p\d|\d+|[()+*]', s)
    pos = 0
    def peek(): return toks[pos] if pos < len(toks) else None
    def eat(): 
        nonlocal pos; pos += 1; return toks[pos-1]
    def atom():
        t = eat()
        if t == 'uint64':
            assert eat() == '('; e = expr(); assert eat() == ')'; return e
        if t == '(':
            e = expr(); assert eat() == ')'; return e
        if t.startswith('p'): return P[int(t[1:])]
        return z3.BitVecVal(int(t), 64)
    def term():
        e = atom()
        while peek() == '*': eat(); e = e * atom()
        return e
    def expr():
        e = term()
        while peek() == '+': eat(); e = e + term()
        return e
    return expr()
OPS = {'==': lambda a,b: a==b, '!=': lambda a,b: a!=b, '<': z3.ULT, '<=': z3.ULE, '>': z3.UGT, '>=': z3.UGE}
cells = re.finditer(r'if \(x == (\d+) && y == (\d+)\) \{(.*?)\n      \}\n', src, re.S)
out = {}
for m in cells:
    x, y, body = int(m.group(1)), int(m.group(2)), m.group(3)
    bug = re.search(r'bug\((\d+)\)', body)
    if not bug: continue
    conds = re.findall(r'if \((.*?)\) \{', body)
    cs = []
    for c in conds:
        mm = re.match(r'^(.*?)\s*(==|!=|<=|>=|<|>)\s*(.*)$', c)
        cs.append(OPS[mm.group(2)](parse_expr(mm.group(1)), parse_expr(mm.group(3))))
    s = z3.Solver(); s.set('timeout', 20000); s.add(cs)
    r = s.check()
    if r == z3.sat:
        mdl = s.model()
        out[int(bug.group(1))] = {'cell': [x, y], 'args': [mdl.eval(p, model_completion=True).as_long() for p in P], 'depth': len(conds)}
    else:
        out[int(bug.group(1))] = {'cell': [x, y], 'result': str(r), 'depth': len(conds)}
json.dump(out, open(sys.argv[2], 'w'), indent=1)
sat = [k for k, v in out.items() if 'args' in v]
print('bugs', len(out), 'sat', len(sat), 'unsat/unknown', [(k, v['result'], v['depth']) for k, v in out.items() if 'args' not in v])

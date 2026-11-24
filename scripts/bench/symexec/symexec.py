#!/usr/bin/env python3
"""Bytecode symbolic executor (z3) for RustyFuzz.

Executes EVM *runtime bytecode* with symbolic calldata and a concrete starting
storage, forks on every symbolic JUMPI, and returns for each completed path:
exact path condition, final storage and the model (calldata words) reaching it.
`explore()` chains this over concrete storage states (multi-tx BFS), recording
the shortest tx sequence that first sets every storage slot of interest.

No source or ABI parsing: only bytecode, selectors and a fixture.
"""
import json, sys, time
import z3
from Crypto.Hash import keccak

M = (1 << 256) - 1
BV = lambda v: z3.BitVecVal(v & M, 256)


def k256(b):
    k = keccak.new(digest_bits=256); k.update(bytes(b)); return k.digest()


class Giveup(Exception):
    pass


def disasm_jumpdests(code):
    jd, i = set(), 0
    while i < len(code):
        op = code[i]
        if op == 0x5B: jd.add(i)
        i += 1 + (op - 0x5F if 0x60 <= op <= 0x7F else 0)
    return jd


class Path:
    __slots__ = ("pc", "stack", "mem", "store", "cons", "steps", "writes", "giveup_reason")

    def __init__(self, store):
        self.pc, self.stack, self.mem, self.cons, self.steps = 0, [], {}, [], 0
        self.store, self.writes = dict(store), []

    def fork(self):
        p = Path.__new__(Path)
        p.pc, p.stack, p.mem, p.cons, p.steps = self.pc, list(self.stack), dict(self.mem), list(self.cons), self.steps
        p.store, p.writes = dict(self.store), list(self.writes)
        return p


def conc(e):
    e = z3.simplify(e)
    return e.as_long() if z3.is_bv_value(e) else None


def need(e, what):
    v = conc(e)
    if v is None: raise Giveup(what)
    return v


class Exec:
    def __init__(self, code, calldata_words, selector, caller=int('13' * 20, 16), timeout_ms=3000, max_steps=200000):
        self.code, self.jd = code, disasm_jumpdests(code)
        self.sel = selector
        self.W = calldata_words
        self.cdsize = 4 + 32 * len(calldata_words)
        self.caller = caller
        self.timeout, self.max_steps = timeout_ms, max_steps

    # ---- calldata ----
    def cdbyte(self, i):
        if i < 4: return z3.BitVecVal(self.sel[i], 8)
        if i >= self.cdsize: return z3.BitVecVal(0, 8)
        w, o = divmod(i - 4, 32)
        return z3.Extract(255 - 8 * o, 248 - 8 * o, self.W[w])

    def cdload(self, off):
        if (off - 4) % 32 == 0 and 4 <= off < self.cdsize: return self.W[(off - 4) // 32]
        return z3.Concat(*[self.cdbyte(off + j) for j in range(32)])

    # ---- memory ----
    def mload(self, p, off):
        return z3.simplify(z3.Concat(*[p.mem.get(off + j, z3.BitVecVal(0, 8)) for j in range(32)]))

    def mstore(self, p, off, v):
        for j in range(32): p.mem[off + j] = z3.simplify(z3.Extract(255 - 8 * j, 248 - 8 * j, v))

    lazy = True  # skip solver calls at forks; only completed non-revert paths are solved

    def feasible(self, cons):
        if self.lazy: return True
        s = z3.Solver(); s.set("timeout", self.timeout); s.add(*cons)
        r = s.check()
        return r != z3.unsat  # treat unknown as feasible

    def feasible_real(self, cons):
        s = z3.Solver(); s.set("timeout", 5000); s.add(*cons)
        return s.check() != z3.unsat

    def run(self, store):
        done, work = [], [Path(store)]
        while work:
            p = work.pop()
            try:
                res = self.step_until_fork(p, work)
            except Giveup as g:
                if not self.feasible_real(p.cons): continue  # dead path, not a real giveup
                res = "giveup"; p.giveup_reason = str(g)
            if res is not None: done.append((p, res))
        return done

    def step_until_fork(self, p, work):
        code = self.code
        st = p.stack
        while True:
            p.steps += 1
            if p.steps > self.max_steps: raise Giveup("steps")
            if p.pc >= len(code): return "stop"
            op = code[p.pc]
            if 0x60 <= op <= 0x7F:
                n = op - 0x5F
                st.append(BV(int.from_bytes(code[p.pc + 1:p.pc + 1 + n].ljust(n, b"\0"), "big"))); p.pc += 1 + n; continue
            if 0x80 <= op <= 0x8F: st.append(st[-(op - 0x7F)]); p.pc += 1; continue
            if 0x90 <= op <= 0x9F:
                n = op - 0x8F; st[-1], st[-1 - n] = st[-1 - n], st[-1]; p.pc += 1; continue
            p.pc += 1
            if op == 0x00: return "stop"
            elif op == 0x01: b, a = st.pop(), st.pop(); st.append(a + b)
            elif op == 0x02: b, a = st.pop(), st.pop(); st.append(a * b)
            elif op == 0x03: a, b = st.pop(), st.pop(); st.append(a - b)
            elif op == 0x04: a, b = st.pop(), st.pop(); st.append(z3.If(b == 0, BV(0), z3.UDiv(a, b)))
            elif op == 0x05: a, b = st.pop(), st.pop(); st.append(z3.If(b == 0, BV(0), a / b))
            elif op == 0x06: a, b = st.pop(), st.pop(); st.append(z3.If(b == 0, BV(0), z3.URem(a, b)))
            elif op == 0x07: a, b = st.pop(), st.pop(); st.append(z3.If(b == 0, BV(0), z3.SRem(a, b)))
            elif op == 0x0A:
                b, e = st.pop(), st.pop()
                bv, ev = conc(b), conc(e)
                if bv is None or ev is None: raise Giveup("symbolic exp")
                st.append(BV(pow(bv, ev, 1 << 256)))
            elif op == 0x0B:
                b, x = st.pop(), st.pop(); bv = need(b, "signextend")
                if bv >= 31: st.append(x)
                else:
                    bits = 8 * (bv + 1); st.append(z3.SignExt(256 - bits, z3.Extract(bits - 1, 0, x)))
            elif op == 0x10: a, b = st.pop(), st.pop(); st.append(z3.If(z3.ULT(a, b), BV(1), BV(0)))
            elif op == 0x11: a, b = st.pop(), st.pop(); st.append(z3.If(z3.UGT(a, b), BV(1), BV(0)))
            elif op == 0x12: a, b = st.pop(), st.pop(); st.append(z3.If(a < b, BV(1), BV(0)))
            elif op == 0x13: a, b = st.pop(), st.pop(); st.append(z3.If(a > b, BV(1), BV(0)))
            elif op == 0x14: a, b = st.pop(), st.pop(); st.append(z3.If(a == b, BV(1), BV(0)))
            elif op == 0x15: a = st.pop(); st.append(z3.If(a == 0, BV(1), BV(0)))
            elif op == 0x16: a, b = st.pop(), st.pop(); st.append(a & b)
            elif op == 0x17: a, b = st.pop(), st.pop(); st.append(a | b)
            elif op == 0x18: a, b = st.pop(), st.pop(); st.append(a ^ b)
            elif op == 0x19: a = st.pop(); st.append(~a)
            elif op == 0x1A:
                i, x = st.pop(), st.pop(); iv = need(i, "byte")
                st.append(z3.ZeroExt(248, z3.Extract(255 - 8 * iv, 248 - 8 * iv, x)) if iv < 32 else BV(0))
            elif op == 0x1B: s, x = st.pop(), st.pop(); st.append(x << s)
            elif op == 0x1C: s, x = st.pop(), st.pop(); st.append(z3.LShR(x, s))
            elif op == 0x1D: s, x = st.pop(), st.pop(); st.append(x >> s)
            elif op == 0x20:
                o, n = st.pop(), st.pop(); ov, nv = need(o, "sha3 off"), need(n, "sha3 len")
                bs = []
                for j in range(nv):
                    e = z3.simplify(p.mem.get(ov + j, z3.BitVecVal(0, 8)))
                    if not z3.is_bv_value(e): raise Giveup("symbolic sha3 input")
                    bs.append(e.as_long())
                st.append(BV(int.from_bytes(k256(bs), "big")))
            elif op == 0x30: st.append(BV(0x6200000000000000000000000000000000000001))
            elif op == 0x32 or op == 0x33: st.append(BV(self.caller))
            elif op == 0x34: st.append(BV(0))
            elif op == 0x35: st.append(self.cdload(need(st.pop(), "calldataload off")))
            elif op == 0x36: st.append(BV(self.cdsize))
            elif op == 0x37:
                d, o, n = st.pop(), st.pop(), st.pop(); dv, ov, nv = need(d, "cdcopy"), need(o, "cdcopy"), need(n, "cdcopy")
                for j in range(nv): p.mem[dv + j] = self.cdbyte(ov + j)
            elif op == 0x38: st.append(BV(len(code)))
            elif op == 0x39:
                d, o, n = st.pop(), st.pop(), st.pop(); dv, ov, nv = need(d, "codecopy"), need(o, "codecopy"), need(n, "codecopy")
                for j in range(nv): p.mem[dv + j] = z3.BitVecVal(code[ov + j] if ov + j < len(code) else 0, 8)
            elif op == 0x3A: st.append(BV(0))
            elif op == 0x41 or op == 0x42 or op == 0x43 or op == 0x44 or op == 0x45 or op == 0x46 or op == 0x48:
                st.append(BV({0x42: 1000, 0x43: 1, 0x45: 30000000, 0x46: 1}.get(op, 0)))
            elif op == 0x47 or op == 0x31: st.pop() if op == 0x31 else None; st.append(BV(0))
            elif op == 0x50: st.pop()
            elif op == 0x51: st.append(self.mload(p, need(st.pop(), "mload off")))
            elif op == 0x52: o, v = st.pop(), st.pop(); self.mstore(p, need(o, "mstore off"), v)
            elif op == 0x53:
                o, v = st.pop(), st.pop(); p.mem[need(o, "mstore8 off")] = z3.simplify(z3.Extract(7, 0, v))
            elif op == 0x54:
                k = need(st.pop(), "sload key"); st.append(p.store.get(k, BV(0)))
            elif op == 0x55:
                k, v = st.pop(), st.pop(); kv = need(k, "sstore key")
                p.store[kv] = v; p.writes.append((kv, v))
            elif op == 0x56:
                t = need(st.pop(), "jump target")
                if t not in self.jd: return "invalid"
                p.pc = t
            elif op == 0x57:
                t, c = st.pop(), st.pop(); tv = need(t, "jumpi target")
                cv = conc(c)
                if cv is not None:
                    if cv != 0:
                        if tv not in self.jd: return "invalid"
                        p.pc = tv
                    continue
                cond = z3.simplify(c != 0)
                taken_c, fall_c = p.cons + [cond], p.cons + [z3.Not(cond)]
                tk = tv in self.jd and self.feasible(taken_c)
                fl = self.feasible(fall_c)
                if tk and fl:
                    q = p.fork(); q.cons = taken_c; q.pc = tv; work.append(q)
                    p.cons = fall_c
                elif tk: p.cons = taken_c; p.pc = tv
                elif fl: p.cons = fall_c
                else: return "infeasible"
            elif op == 0x58: st.append(BV(p.pc - 1))
            elif op == 0x59: st.append(BV((max(p.mem) // 32 + 1) * 32 if p.mem else 0))
            elif op == 0x5A: st.append(BV(10 ** 7))
            elif op == 0x5B: pass
            elif op == 0x5E:
                d, o, n = st.pop(), st.pop(), st.pop(); dv, ov, nv = need(d, "mcopy"), need(o, "mcopy"), need(n, "mcopy")
                tmp = [p.mem.get(ov + j, z3.BitVec if False else z3.BitVecVal(0, 8)) for j in range(nv)]
                for j in range(nv): p.mem[dv + j] = tmp[j]
            elif op == 0x5F: st.append(BV(0))
            elif 0xA0 <= op <= 0xA4:
                for _ in range(2 + op - 0xA0): st.pop()
            elif op == 0xF3: return "return"
            elif op == 0xFD: return "revert"
            elif op == 0xFE: return "invalid"
            else:
                raise Giveup(f"opcode 0x{op:02x} at {p.pc - 1}")


def selector(sig): return k256(sig.encode())[:4]


def solve_path(p, W):
    s = z3.Solver(); s.set("timeout", 20000); s.add(*p.cons)
    if s.check() != z3.sat: return None
    m = s.model()
    return [m.eval(w, model_completion=True).as_long() for w in W], m


def freeze(store, m=None):
    out = {}
    for k, v in store.items():
        e = m.eval(v, model_completion=True) if m is not None else z3.simplify(v)
        if not z3.is_bv_value(e): raise Giveup("symbolic storage")
        if e.as_long() != 0: out[k] = e.as_long()
    return tuple(sorted(out.items()))


def explore(code, sigs, nargs, init_store, watch, max_states=100000, budget_s=600, log=print):
    """BFS over concrete storage states. watch: {slot -> label}. Returns {label: [(sig,args),...]}."""
    t0 = time.time()
    W = [z3.BitVec(f"a{i}", 256) for i in range(nargs)]
    sels = {s: selector(s) for s in sigs}
    start = tuple(sorted((k, v) for k, v in init_store.items() if v))
    seen = {start: []}
    frontier = [start]
    found = {}
    stats = dict(paths=0, giveup=0, sat=0, unsat=0)
    while frontier and len(seen) < max_states and time.time() - t0 < budget_s:
        nxt = []
        for stt in frontier:
            for s, sel in sels.items():
                ex = Exec(code, W, sel)
                for p, res in ex.run({k: BV(v) for k, v in stt}):
                    stats["paths"] += 1
                    if res == "giveup":
                        stats["giveup"] += 1
                        if p.writes and any(sl in watch for sl, _ in p.writes):
                            r = solve_path(p, W)
                            if r:
                                for slot, val in p.writes:
                                    if slot in watch and watch[slot] not in found:
                                        found[watch[slot]] = seen[stt] + [(s, r[0])]
                        continue
                    if res not in ("stop", "return"): continue
                    r = solve_path(p, W)
                    if r is None: stats["unsat"] += 1; continue
                    stats["sat"] += 1
                    args, m = r
                    try: new = tuple(kv for kv in freeze(p.store, m) if kv[0] not in watch)
                    except Giveup: stats["giveup"] += 1; continue
                    seq = seen[stt] + [(s, args)]
                    for slot, val in p.writes:
                        sv = conc(val)
                        sv = m.eval(val, model_completion=True).as_long() if sv is None else sv
                        if slot in watch and sv != 0 and watch[slot] not in found:
                            found[watch[slot]] = seq
                    if new not in seen:
                        seen[new] = seq; nxt.append(new)
        frontier = nxt
        log(f"depth frontier={len(frontier)} states={len(seen)} found={len(found)} {stats} t={time.time()-t0:.0f}s")
    return found, seen, stats

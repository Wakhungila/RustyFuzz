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


# Concrete keccak preimages seen so far, by length: {n: {hash: preimage bytes}}. Used to tie the
# uninterpreted keccak applied to symbolic input to the real hashes already in storage.
KNOWN_HASHES = {}


def register_known_hash(preimage: bytes):
    """Tells the symbolic SHA3 model that `preimage` is a real preimage, so a symbolic input
    forced equal to `keccak(preimage)` is also forced equal to `preimage` (see the keccak axiom
    in `Exec.step_until_fork`'s SHA3 case). Without this, a mapping key named only in the
    invariants file (never passed as *concrete* calldata during the symbolic run) has no axiom,
    and z3 can satisfy "write lands on this slot" by picking an arbitrary, unconstrained symbolic
    key whose uninterpreted hash it is merely free to set equal to the target slot — a modeling
    artifact, not a real path. Call this for every key a predicate/watch dict names, before
    exploring, so results they produce reproduce on the real EVM."""
    KNOWN_HASHES.setdefault(len(preimage), {})[int.from_bytes(k256(preimage), "big")] = preimage


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
    __slots__ = ("pc", "stack", "mem", "init", "wlog", "cons", "steps", "giveup_reason", "calls", "rd", "nfresh")

    def __init__(self, store):
        self.pc, self.stack, self.mem, self.cons, self.steps = 0, [], {}, [], 0
        self.init, self.wlog, self.calls, self.rd, self.nfresh = dict(store), [], [], [], 0

    def fork(self):
        p = Path.__new__(Path)
        p.pc, p.stack, p.mem, p.cons, p.steps = self.pc, list(self.stack), dict(self.mem), list(self.cons), self.steps
        p.init, p.wlog, p.calls, p.rd, p.nfresh = self.init, list(self.wlog), list(self.calls), list(self.rd), self.nfresh
        return p

    @property
    def writes(self):  # (slot expr, value expr) in program order
        return self.wlog


def conc(e):
    e = z3.simplify(e)
    return e.as_long() if z3.is_bv_value(e) else None


def need(e, what):
    v = conc(e)
    if v is None: raise Giveup(what)
    return v


def read_storage(p, k):
    """Value at symbolic/concrete slot `k` in path `p`'s storage (init overridden by wlog, in order)."""
    kc = conc(k)
    if kc is not None: base = BV(p.init.get(kc, 0))
    else:
        base = BV(0)
        for ik, iv in p.init.items(): base = z3.If(k == BV(ik), BV(iv), base)
    for wk, wv in p.wlog:
        wc = conc(wk)
        if kc is not None and wc is not None:
            if kc == wc: base = wv
        else: base = z3.If(k == wk, wv, base)
    return z3.simplify(base)


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

    def sload(self, p, k):
        return read_storage(p, k)

    lazy = True  # skip solver calls at forks; only completed non-revert paths are solved

    def feasible(self, cons):
        if self.lazy: return True
        s = z3.Solver(); s.set("timeout", self.timeout); s.add(*cons)
        r = s.check()
        return r != z3.unsat  # treat unknown as feasible

    def feasible_real(self, cons):
        s = z3.Solver(); s.set("timeout", 5000); s.add(*cons)
        return s.check() != z3.unsat

    def run(self, store, base=None):
        """Execute one transaction. With `base`, continue symbolically from a previous
        transaction's path (its storage writes, path condition, calls) instead of concrete storage."""
        p0 = Path(store)
        if base is not None:
            p0.init, p0.wlog, p0.cons, p0.calls, p0.nfresh = base.init, list(base.wlog), list(base.cons), list(base.calls), base.nfresh
        done, work = [], [p0]
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
                es = [z3.simplify(p.mem.get(ov + j, z3.BitVecVal(0, 8))) for j in range(nv)]
                if all(z3.is_bv_value(e) for e in es):
                    pre = bytes(e.as_long() for e in es); h = int.from_bytes(k256(pre), "big")
                    KNOWN_HASHES.setdefault(nv, {})[h] = pre
                    st.append(BV(h))
                elif nv == 0: raise Giveup("empty symbolic sha3")
                else:
                    # Symbolic preimage: uninterpreted per-length function. Equal inputs give equal
                    # slots (what mapping lookups need); collisions with concrete hashes are ignored.
                    f = z3.Function(f"keccak{nv}", z3.BitVecSort(8 * nv), z3.BitVecSort(256))
                    x = es[0] if nv == 1 else z3.Concat(*es)
                    # Axioms: for every known real preimage, UF(x)==hash  <=>  x==preimage.
                    for h, pre in list(KNOWN_HASHES.get(nv, {}).items())[:64]:
                        p.cons.append((x == z3.BitVecVal(int.from_bytes(pre, "big"), 8 * nv)) == (f(x) == BV(h)))
                    st.append(f(x))
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
            elif op == 0x31 or op == 0x47:
                if op == 0x31: st.pop()
                p.nfresh += 1; st.append(z3.BitVec(f"bal{p.nfresh}", 256))
            elif op == 0x3B: st.pop(); st.append(BV(1))  # assume callees have code
            elif op == 0x3D: st.append(BV(len(p.rd)))
            elif op == 0x3E:
                d, o, n = st.pop(), st.pop(), st.pop(); dv, ov, nv = need(d, "rdcopy"), need(o, "rdcopy"), need(n, "rdcopy")
                if ov + nv > len(p.rd): return "revert"
                for j in range(nv): p.mem[dv + j] = p.rd[ov + j]
            elif op in (0xF1, 0xF2, 0xF4, 0xFA):
                st.pop()  # gas
                to = st.pop()
                val = st.pop() if op in (0xF1, 0xF2) else BV(0)
                io, isz, oo, osz = st.pop(), st.pop(), st.pop(), st.pop()
                iov, isv, oov, osv = need(io, "call in"), need(isz, "call insize"), need(oo, "call out"), need(osz, "call outsize")
                p.nfresh += 1; n = p.nfresh
                ok = z3.BitVec(f"callok{n}", 256)
                p.cons.append(z3.Or(ok == 0, ok == 1))
                data = [p.mem.get(iov + j, z3.BitVecVal(0, 8)) for j in range(isv)]
                p.calls.append(dict(kind=op, to=z3.simplify(to), value=z3.simplify(val), data=data, ok=ok))
                # Havoc the callee: success is a free bit, returned bytes are free (the callee's
                # own state effects, e.g. re-entry, are NOT modeled).
                p.rd = [z3.BitVec(f"rd{n}_{j}", 8) for j in range(osv)]
                for j in range(osv): p.mem[oov + j] = p.rd[j]
                st.append(ok)
            elif op == 0x50: st.pop()
            elif op == 0x51: st.append(self.mload(p, need(st.pop(), "mload off")))
            elif op == 0x52: o, v = st.pop(), st.pop(); self.mstore(p, need(o, "mstore off"), v)
            elif op == 0x53:
                o, v = st.pop(), st.pop(); p.mem[need(o, "mstore8 off")] = z3.simplify(z3.Extract(7, 0, v))
            elif op == 0x54: st.append(self.sload(p, st.pop()))
            elif op == 0x55:
                k, v = st.pop(), st.pop(); p.wlog.append((z3.simplify(k), z3.simplify(v)))
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


def solve_path_with(p, W, extra):
    s = z3.Solver(); s.set("timeout", 20000); s.add(*p.cons); s.add(extra)
    if s.check() != z3.sat: return None
    m = s.model()
    return [m.eval(w, model_completion=True).as_long() for w in W], m


def final_store(p, m):
    """Concrete storage after the path under model m (symbolic keys/values evaluated)."""
    d = dict(p.init)
    for k, v in p.wlog:
        d[m.eval(k, model_completion=True).as_long()] = m.eval(v, model_completion=True).as_long()
    return d


def freeze(p, m):
    return tuple(sorted((k, v) for k, v in final_store(p, m).items() if v))


def explore(code, sigs, nargs, init_store, watch, max_states=100000, max_frontier=40, budget_s=600, caller=int('13' * 20, 16), log=print):
    """BFS over concrete storage states.

    sigs: list of signatures (each takes `nargs` words) or {sig: nargs}.
    watch: {slot -> label}; the shortest tx sequence that first writes a non-zero value
    to a watched slot is returned in `found`. `seen` maps every distinct (non-watched)
    storage state to the shortest sequence reaching it, so callers can also seed from states.
    """
    t0 = time.time()
    widths = sigs if isinstance(sigs, dict) else {s: nargs for s in sigs}
    Ws = {s: [z3.BitVec(f"a{i}", 256) for i in range(n)] for s, n in widths.items()}
    sels = {s: selector(s) for s in widths}
    start = tuple(sorted((k, v) for k, v in init_store.items() if v and k not in watch))
    seen, frontier, found = {start: []}, [start], {}
    stats = dict(paths=0, giveup=0, sat=0, unsat=0, calls=0)
    reasons = {}

    def harvest(p, m, seq):
        for slot, val in p.wlog:
            sl = m.eval(slot, model_completion=True).as_long()
            if sl in watch and watch[sl] not in found and m.eval(val, model_completion=True).as_long() != 0:
                found[watch[sl]] = seq

    while frontier and len(seen) < max_states and time.time() - t0 < budget_s:
        nxt = []
        for stt in frontier[:max_frontier]:
            if time.time() - t0 > budget_s: break
            for s, sel in sels.items():
                W = Ws[s]
                ex = Exec(code, W, sel, caller=caller)
                for p, res in ex.run(dict(stt)):
                    stats["paths"] += 1
                    stats["calls"] += len(p.calls)
                    if res == "giveup":
                        stats["giveup"] += 1
                        reasons[p.giveup_reason] = reasons.get(p.giveup_reason, 0) + 1
                        if p.wlog:  # still harvest bug writes made before the unsupported construct
                            r = solve_path(p, W)
                            if r: harvest(p, r[1], seen[stt] + [(s, r[0])])
                        continue
                    if res not in ("stop", "return"): continue
                    r = solve_path(p, W)
                    if r is None: stats["unsat"] += 1; continue
                    stats["sat"] += 1
                    args, m = r
                    if p.wlog and freeze(p, m) == tuple(kv for kv in stt):
                        # The arbitrary model made the call a no-op on storage (e.g. amount=0). Ask for
                        # one that changes some slot, so the state machine actually advances.
                        base = Path(dict(stt))
                        diff = z3.Or(*[v != ex.sload(base, k) for k, v in p.wlog])
                        r2 = solve_path_with(p, W, diff)
                        if r2: args, m = r2
                    seq = seen[stt] + [(s, args)]
                    harvest(p, m, seq)
                    new = tuple(kv for kv in freeze(p, m) if kv[0] not in watch)
                    if new not in seen:
                        seen[new] = seq; nxt.append(new)
        frontier = nxt
        log(f"depth frontier={len(frontier)} states={len(seen)} found={len(found)} {stats} t={time.time()-t0:.0f}s")
    if reasons: log(f"giveup reasons: {sorted(reasons.items(), key=lambda x: -x[1])[:5]}")
    return found, seen, stats


def explore_sym(code, widths, init_store, watch=None, invariants=None, depth=3, max_paths=300,
                 budget_s=600, caller=int('13' * 20, 16), log=print):
    """Multi-transaction symbolic execution: storage stays symbolic across `depth` transactions, so a
    value chosen in tx1 (e.g. a deposit amount) is solved jointly with the guard in tx3. Returns
    ({label: [(sig, args), ...]}, stats).

    Pass exactly one of:
      watch:      {slot -> label} (Daedaluzz-style: label found once that slot is written non-zero)
      invariants: (symbols, preds) from `invariants.load_invariants` — the general case, usable on any
                  contract: label found once some invariant's predicate is reachably false.
    """
    import random
    assert (watch is None) != (invariants is None), "pass exactly one of watch=, invariants="
    t0, rnd = time.time(), random.Random(0)
    sels = {s: selector(s) for s in widths}
    found, stats = {}, dict(paths=0, giveup=0, sat=0, calls=0)
    layer = [(Path(init_store), [])]  # (path after k txs, [(sig, arg exprs)])
    all_labels = set(watch.values()) if watch is not None else {name for name, _ in invariants[1]}
    for t in range(depth):
        nxt = []
        for base, trail in layer:
            for sig, sel in sels.items():
                if time.time() - t0 > budget_s: break
                W = [z3.BitVec(f"a{t}_{i}", 256) for i in range(widths[sig])]
                for p, res in Exec(code, W, sel, caller=caller).run(init_store, base=base):
                    stats["paths"] += 1; stats["calls"] += len(p.calls)
                    if res == "giveup": stats["giveup"] += 1; continue
                    if res not in ("stop", "return"): continue
                    tr = trail + [(sig, W)]
                    nxt.append((p, tr))
        rnd.shuffle(nxt)
        # keep feasible paths only, capped, preferring those that wrote storage
        keep = []
        for p, tr in sorted(nxt, key=lambda x: -len(x[0].wlog))[: max_paths * 3]:
            s_ = z3.Solver(); s_.set("timeout", 5000); s_.add(*p.cons)
            if s_.check() == z3.sat:
                stats["sat"] += 1; keep.append((p, tr))
                if len(keep) >= max_paths: break
        for p, tr in keep:
            if watch is not None:
                wl = set(watch)
                hit = [z3.And(k == BV(h), v != 0) for k, v in p.wlog for h in wl]
                if not hit: continue
                checks = []
                for label_h in list(wl):
                    lab = watch[label_h]
                    if lab in found: continue
                    c = [z3.And(k == BV(label_h), v != 0) for k, v in p.wlog]
                    checks.append((lab, z3.Or(*c) if c else z3.BoolVal(False)))
            else:
                import invariants as invariants_mod  # local: invariants.py imports from this module
                symbols, preds = invariants
                checks = [(name, cond) for name, cond in invariants_mod.violations_at(p, symbols, preds)
                          if name not in found]
            for lab, cond in checks:
                s_ = z3.Solver(); s_.set("timeout", 10000); s_.add(*p.cons); s_.add(cond)
                if s_.check() == z3.sat:
                    m = s_.model()
                    found[lab] = [(sg, [m.eval(w, model_completion=True).as_long() for w in Wt]) for sg, Wt in tr]
        layer = keep
        log(f"sym depth {t+1}: layer={len(layer)} found={len(found)} {stats} t={time.time()-t0:.0f}s")
        if len(found) == len(all_labels) or time.time() - t0 > budget_s: break
    return found, stats

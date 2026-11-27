#!/usr/bin/env python3
"""Symbolic seeding for RustyFuzz: bytecode + ABI + invariants -> replay-format seed inputs.

    symseed.py --fixture F.json --abi F.abi.json --invariants F.invariants.json --out DIR
    rusty-fuzz fuzz ... --seed-inputs DIR

Explores the target's state machine with z3 (see symexec.py), writes the shortest tx sequence that
violates each watched mapping invariant (`bug<id>.json`) and, with --emit-states N, the sequences
reaching the N shallowest distinct storage states (`state<i>.json`) as general-purpose seeds.
Supported: functions with static word-sized params; in --symbolic-depth mode, also `bytes`/`string`
and single-level `T[]` params with a concretely-chosen length and symbolic content (abi_dynamic.py) —
one variant per tried length, so e.g. a `bytes calldata` param is tried both empty and non-empty.
Concrete/symbolic storage keys, mappings via keccak. In --symbolic-depth mode, a CALL/STATICCALL
whose target and 4-byte selector are concrete and whose target is another account IN THE FIXTURE
with real bytecode is actually dispatched into that callee's code (real effects, real success/
revert, real return data) rather than havoced; depth is capped at one real hop (a callee's own
calls are still havoced), and anything outside that (an unknown/symbolic target, DELEGATECALL/
CALLCODE, a call back into the target's OWN address, or a callee path this can't finish) still
falls back to the old havoc model (free success bit, free return bytes, callee effects not
modeled). Not supported (path is dropped and counted as a giveup): tuple/nested-array/more-than-
two-dynamic-param functions, CREATE, loops past the step cap, symbolic memory offsets/lengths.
"""
import argparse, json, os, re, sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from symexec import *
from invariants import load_invariants
import abi_dynamic

STATIC = re.compile(r"^(u?int\d*|address|bool|bytes\d+)$")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--fixture", required=True); ap.add_argument("--abi", required=True)
    ap.add_argument("--invariants"); ap.add_argument("--out", required=True)
    ap.add_argument("--budget", type=int, default=600); ap.add_argument("--symbolic-depth", type=int, default=0, help="multi-tx symbolic execution depth (storage kept symbolic); 0 = concrete-state BFS"); ap.add_argument("--emit-states", type=int, default=0)
    a = ap.parse_args()
    fx = json.load(open(a.fixture)); abi = json.load(open(a.abi))
    tgt = fx["target"].lower()
    acct = next(x for x in fx["accounts"] if x["address"].lower() == tgt)
    code = bytes.fromhex(acct["runtime_bytecode"][2:])
    init = {int(s["slot"], 16): int(s["value"], 16) for s in acct.get("storage", [])}
    # Real external-call dispatch (symexec.Exec.dispatch_call, --symbolic-depth only): every OTHER
    # account in the fixture that actually has bytecode is a callee the target's own CALL/
    # STATICCALLs can be run into for real, instead of havoced. Accounts with no code (EOAs) are
    # left out, so a call to one still falls back to the old havoc path (correctly — a real "call"
    # to an EOA always just succeeds with empty returndata, which havoc already approximates fine).
    code_map, callee_storage = {}, {}
    for acc in fx["accounts"]:
        if acc["address"].lower() == tgt: continue
        rb = acc.get("runtime_bytecode", "0x")
        if len(rb) <= 2: continue
        addr_i = int(acc["address"], 16)
        code_map[addr_i] = bytes.fromhex(rb[2:])
        callee_storage[addr_i] = {int(s["slot"], 16): int(s["value"], 16) for s in acc.get("storage", [])}
    widths, skipped, dyn_variants = {}, [], 0
    for f in abi:
        if f.get("type") != "function" or f.get("stateMutability") in ("view", "pure"): continue
        types = [i["type"] for i in f["inputs"]]
        if all(STATIC.match(t) for t in types):
            widths[f"{f['name']}({','.join(types)})"] = len(types)
        elif a.symbolic_depth and all(abi_dynamic.supported(t) for t in types):
            for label, spec in abi_dynamic.variants_for(f["name"], types):
                widths[label] = spec
            dyn_variants += 1
        else:
            skipped.append(f["name"])
    # Legacy watch-dict: every mapping-kind symbol's enumerated keys, used by `explore()` (the
    # concrete-state BFS, validated on Daedaluzz) and as `explore_sym`'s fallback when the invariants
    # file has no `invariants` predicate list (just bare `symbols`, as Daedaluzz's do).
    watch, inv_doc = {}, None
    if a.invariants:
        inv_doc = json.load(open(a.invariants))
        for name, sym in inv_doc.get("symbols", {}).items():
            if sym.get("kind") != "mapping": continue
            for key in sym.get("keys", []):
                slot = int(sym["slot"], 16).to_bytes(32, "big")
                preimage = bytes.fromhex(key[2:]).rjust(32, b"\0") + slot
                # Needed for `explore_sym` (storage/calldata stay symbolic across txs); a no-op
                # for `explore` (the concrete-state BFS), which never carries a symbolic key
                # across the SHA3 that derives a mapping slot in the first place.
                register_known_hash(preimage)
                h = int.from_bytes(k256(preimage), "big")
                watch[h] = name
    caller = int(fx["attacker"], 16)
    print(f"target={tgt} funcs/variants={len(widths)} (dynamic-type functions expanded: {dyn_variants}) "
          f"skipped(unsupported params)={skipped} watched={len(watch)}")
    if a.symbolic_depth:
        # General invariant predicates (any comparison over `sum(mapping)` / masked `slot` symbols,
        # not just "some mapping entry became non-zero") are only usable in the symbolic-depth mode,
        # because checking one needs the whole-path storage model, not a single write.
        if inv_doc and inv_doc.get("invariants"):
            symbols, preds = load_invariants(inv_doc)
            found, stats = explore_sym(code, widths, init, invariants=(symbols, preds),
                                        depth=a.symbolic_depth, budget_s=a.budget, caller=caller,
                                        code_map=code_map, callee_storage=callee_storage, self_addr=int(tgt, 16))
        else:
            found, stats = explore_sym(code, widths, init, watch=watch, depth=a.symbolic_depth,
                                        budget_s=a.budget, caller=caller,
                                        code_map=code_map, callee_storage=callee_storage, self_addr=int(tgt, 16))
        seen = {}
    else:
        found, seen, stats = explore(code, widths, 0, init, watch, budget_s=a.budget, caller=caller)

    def dump(seq, name):
        txs = []
        for sig, args in seq:
            data = list(selector(sig) + b"".join(x.to_bytes(32, "big") for x in args))
            txs.append({"input": data, "caller": fx["attacker"], "to": fx["target"], "value": "0x0", "is_victim": False})
        json.dump({"txs": txs, "base_snapshot_id": 0}, open(os.path.join(a.out, name), "w"))

    os.makedirs(a.out, exist_ok=True)
    for label, seq in found.items(): dump(seq, f"bug_{label}.json")
    n = 0
    if a.emit_states:
        for st, seq in sorted(seen.items(), key=lambda kv: len(kv[1])):
            if not seq or n >= a.emit_states: continue
            dump(seq, f"state{n}.json"); n += 1
    denom = len(inv_doc["invariants"]) if (a.symbolic_depth and inv_doc and inv_doc.get("invariants")) else len(watch)
    print(f"SYMSEED found={len(found)}/{denom} states_seen={len(seen)} state_seeds={n} stats={stats}")


if __name__ == "__main__":
    main()

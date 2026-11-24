#!/usr/bin/env python3
"""Symbolic seeding for RustyFuzz: bytecode + ABI + invariants -> replay-format seed inputs.

    symseed.py --fixture F.json --abi F.abi.json --invariants F.invariants.json --out DIR
    rusty-fuzz fuzz ... --seed-inputs DIR

Explores the target's state machine with z3 (see symexec.py), writes the shortest tx sequence that
violates each watched mapping invariant (`bug<id>.json`) and, with --emit-states N, the sequences
reaching the N shallowest distinct storage states (`state<i>.json`) as general-purpose seeds.
Supported: functions with static word-sized params, concrete/symbolic storage keys, mappings via
keccak, external calls (havoced: free success bit and return bytes, callee effects not modeled).
Not supported (path is dropped and counted as a giveup): dynamic params, CREATE, loops past the step
cap, symbolic memory offsets/lengths.
"""
import argparse, json, os, re, sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from symexec import *

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
    widths, skipped = {}, []
    for f in abi:
        if f.get("type") != "function" or f.get("stateMutability") in ("view", "pure"): continue
        if all(STATIC.match(i["type"]) for i in f["inputs"]):
            widths[f"{f['name']}({','.join(i['type'] for i in f['inputs'])})"] = len(f["inputs"])
        else: skipped.append(f["name"])
    watch = {}
    if a.invariants:
        for name, sym in json.load(open(a.invariants))["symbols"].items():
            if sym.get("kind") != "mapping": continue
            for key in sym.get("keys", []):
                slot = int(sym["slot"], 16).to_bytes(32, "big")
                h = int.from_bytes(k256(bytes.fromhex(key[2:]).rjust(32, b"\0") + slot), "big")
                watch[h] = name
    caller = int(fx["attacker"], 16)
    print(f"target={tgt} funcs={len(widths)} skipped(dynamic params)={skipped} watched={len(watch)}")
    if a.symbolic_depth:
        found, stats = explore_sym(code, widths, init, watch, depth=a.symbolic_depth, budget_s=a.budget, caller=caller)
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
    print(f"SYMSEED found={len(found)}/{len(watch)} states_seen={len(seen)} state_seeds={n} stats={stats}")


if __name__ == "__main__":
    main()

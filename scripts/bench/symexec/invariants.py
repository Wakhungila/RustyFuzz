#!/usr/bin/env python3
"""Evaluates RustyFuzz invariant-file predicates (the `symbols` + `invariants` shape shared by
Daedaluzz mazes and the historical real-protocol fixtures) as z3 expressions over a path's storage,
so the symbolic executor can search for a transaction sequence that makes a predicate false —
without any contract-specific logic.

Predicate grammar (matches what's observed in the repo's own `*.invariants.json` files):
    predicate := or_expr
    or_expr   := and_expr ('||' and_expr)*
    and_expr  := cmp ('&&' cmp)*
    cmp       := expr (cmpop expr)?
    expr      := term (('+' | '-') term)*
    term      := factor ('*' factor)*
    factor    := '(' expr ')' | NUMBER | 'sum' '(' IDENT ')' | IDENT
    cmpop     := '==' | '!=' | '<=' | '>=' | '<' | '>'
NUMBER is decimal or 0x-hex. A bare cmp with no cmpop evaluates to "expr != 0", so `&&`/`||` can
combine either comparisons or bare truthiness checks.
"""
import re
import z3

from symexec import BV, M, k256, read_storage, register_known_hash


class Symbol:
    __slots__ = ("name", "kind", "slot", "offset_bits", "width_bits", "keys", "value_cache")

    def __init__(self, name, spec):
        self.name = name
        self.kind = spec["kind"]  # "slot" | "mapping"
        self.slot = int(spec["slot"], 16)
        self.offset_bits = spec.get("offset_bits", 0)
        self.width_bits = spec.get("width_bits", 256)
        self.keys = spec.get("keys", [])  # mapping: explicit enumerated keys, each a hex string

    def mapping_slot(self, key_hex):
        key_bytes = bytes.fromhex(key_hex[2:]).rjust(32, b"\0")[-32:]
        slot_bytes = self.slot.to_bytes(32, "big")
        preimage = key_bytes + slot_bytes
        register_known_hash(preimage)  # so a symbolic write that truly lands here is solvable
        return int.from_bytes(k256(preimage), "big")

    def value(self, p):
        """This symbol's current z3 value in path `p` (post sum/mask as the invariant file defines it)."""
        if self.kind == "mapping":
            total = BV(0)
            for key_hex in self.keys:
                total = total + read_storage(p, BV(self.mapping_slot(key_hex)))
            return z3.simplify(total)
        raw = read_storage(p, BV(self.slot))
        if self.offset_bits == 0 and self.width_bits == 256:
            return raw
        mask = BV((1 << self.width_bits) - 1)
        return z3.simplify(z3.LShR(raw, self.offset_bits) & mask)


TOKEN_RE = re.compile(r"\s*(0x[0-9a-fA-F]+|\d+|==|!=|<=|>=|&&|\|\||<|>|[()+\-*]|[A-Za-z_][A-Za-z0-9_]*)")


def tokenize(text):
    toks, i = [], 0
    while i < len(text):
        m = TOKEN_RE.match(text, i)
        if not m or m.end() == i:
            if text[i:].strip() == "":
                break
            raise ValueError(f"cannot tokenize {text!r} at {i}")
        if m.group(1):
            toks.append(m.group(1))
        i = m.end()
    return toks


class Predicate:
    """Parses once; `violated(p, symbols)` evaluates against a path's storage every call."""

    def __init__(self, text):
        self.text = text
        self.toks = tokenize(text)
        self.i = 0

    def _peek(self):
        return self.toks[self.i] if self.i < len(self.toks) else None

    def _eat(self, tok=None):
        t = self._peek()
        if tok is not None and t != tok:
            raise ValueError(f"expected {tok!r} in {self.text!r}, got {t!r}")
        self.i += 1
        return t

    def parse(self, symbols):
        self.i = 0
        v = self._or(symbols)
        if self.i != len(self.toks):
            raise ValueError(f"trailing tokens in {self.text!r}: {self.toks[self.i:]}")
        return v

    def _or(self, symbols):
        v = self._and(symbols)
        while self._peek() == "||":
            self._eat(); v = z3.Or(v, self._and(symbols))
        return v

    def _and(self, symbols):
        v = self._cmp(symbols)
        while self._peek() == "&&":
            self._eat(); v = z3.And(v, self._cmp(symbols))
        return v

    def _cmp(self, symbols):
        lhs = self._expr(symbols)
        cmp = self._peek()
        if cmp in ("==", "!=", "<=", ">=", "<", ">"):
            self._eat()
            rhs = self._expr(symbols)
            return {"==": lhs == rhs, "!=": lhs != rhs, "<=": z3.ULE(lhs, rhs), ">=": z3.UGE(lhs, rhs),
                    "<": z3.ULT(lhs, rhs), ">": z3.UGT(lhs, rhs)}[cmp]
        return lhs != BV(0)

    def _expr(self, symbols):
        v = self._term(symbols)
        while self._peek() in ("+", "-"):
            op = self._eat()
            rhs = self._term(symbols)
            v = v + rhs if op == "+" else v - rhs
        return v

    def _term(self, symbols):
        v = self._factor(symbols)
        while self._peek() == "*":
            self._eat()
            v = v * self._factor(symbols)
        return v

    def _factor(self, symbols):
        t = self._peek()
        if t == "(":
            self._eat("(")
            v = self._expr(symbols)
            self._eat(")")
            return v
        if t == "sum":
            self._eat("sum"); self._eat("("); name = self._eat(); self._eat(")")
            return symbols[name].value_cache
        if re.fullmatch(r"0x[0-9a-fA-F]+", t or ""):
            self._eat(); return BV(int(t, 16))
        if re.fullmatch(r"\d+", t or ""):
            self._eat(); return BV(int(t))
        self._eat()
        return symbols[t].value_cache


def load_invariants(doc):
    """doc: parsed `*.invariants.json`. Returns (symbols: {name: Symbol}, predicates: [(name, Predicate)])."""
    symbols = {name: Symbol(name, spec) for name, spec in doc.get("symbols", {}).items()}
    preds = [(inv["name"], Predicate(inv["predicate"])) for inv in doc.get("invariants", [])]
    return symbols, preds


def violations_at(p, symbols, preds, solver_extra=None):
    """For path `p`, returns [(name, z3 BoolRef condition-for-violation)] — one entry per invariant
    whose negation (the invariant failing) is not syntactically impossible; caller `z3.Solver`-checks
    each alongside `p.cons` (and `solver_extra`, e.g. output-arg bindings) to see if it's reachable."""
    for sym in symbols.values():
        sym.value_cache = sym.value(p)
    out = []
    for name, pred in preds:
        held = pred.parse(symbols)
        out.append((name, z3.Not(held)))
    return out

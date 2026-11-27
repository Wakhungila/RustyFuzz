#!/usr/bin/env python3
"""ABI calldata-word encoding for functions with dynamic-type parameters (`bytes`, `string`,
`T[]` dynamic arrays of a static element type `T`), for use with `explore_sym`'s `(sig_text,
words_factory)` spec.

Scope, deliberately: one level of dynamicness (no `T[][]`, no dynamic-array-of-struct, no tuples),
and every dynamic parameter's *length* is chosen up front, concretely, from a small fixed set of
candidates — not solved for. Only a dynamic parameter's *content* (its bytes/elements) stays
symbolic. This is enough to reach code that branches on "is this calldata empty or not" and
"what's in the contents" (the overwhelmingly common dynamic-type uses: flash-loan callback data,
`permit`-style signatures, batch arrays), without needing a length-indexed induction over
arbitrary-size loops, which bytecode-level symbolic execution can't do soundly without widening.
Each candidate length is a separate labeled variant, so the calling code gets several `(sig_text,
words_factory)` entries for the one real function and whichever variant actually reaches a bug (or
an invariant violation) is the one `explore_sym` keeps.
"""
import re
import z3

STATIC = re.compile(r"^(u?int\d*|address|bool|bytes\d+)$")
DYN_ARRAY = re.compile(r"^(.+)\[\]$")


def supported(t):
    """True if `encode` can build calldata for this single type (used to decide whether a whole
    function is buildable; a function with an unsupported param, e.g. a tuple or nested array, is
    left out of the variant set entirely rather than risk silently wrong layout)."""
    if STATIC.match(t):
        return True
    if t in ("bytes", "string"):
        return True
    m = DYN_ARRAY.match(t)
    return bool(m) and STATIC.match(m.group(1))


def build_words(types, lengths, prefix):
    """types: ABI type strings. lengths: {param_index: chosen length} for every dynamic param
    (bytes/string: length in bytes; T[]: length in elements). Returns the full calldata word list
    (head, with concrete offset pointers for dynamic params, followed by each dynamic param's tail:
    a concrete length word then symbolic content words)."""
    nhead = len(types)
    head = [None] * nhead
    tail = []
    for i, t in enumerate(types):
        if STATIC.match(t):
            head[i] = z3.BitVec(f"{prefix}{i}", 256)
            continue
        offset = 32 * nhead + 32 * len(tail)
        head[i] = z3.BitVecVal(offset, 256)
        n = lengths[i]
        if t in ("bytes", "string"):
            tail.append(z3.BitVecVal(n, 256))  # length, in bytes
            nwords = (n + 31) // 32
            for j in range(nwords):
                w = z3.BitVec(f"{prefix}{i}_c{j}", 256)
                if j == nwords - 1 and n % 32:
                    # Zero-pad the trailing partial word so unused tail bytes read as 0, matching
                    # what a real ABI-encoded call would have there (padding, not arbitrary bytes).
                    # The content occupies the high-order (first, MSB) bytes of a big-endian EVM
                    # word; ZeroExt would instead pad on the high side, so this is Concat, not ZeroExt.
                    valid_bits = (n % 32) * 8
                    w = z3.Concat(z3.Extract(255, 256 - valid_bits, w), z3.BitVecVal(0, 256 - valid_bits))
                tail.append(w)
        else:
            tail.append(z3.BitVecVal(n, 256))  # element count
            for j in range(n):
                tail.append(z3.BitVec(f"{prefix}{i}_e{j}", 256))
    return head + tail


def variants_for(sig_name, types, length_choices=(0, 1, 32)):
    """Every (label, (sig_text, words_factory)) pair for one ABI function, one per combination of
    length choices across its dynamic params (capped to keep the product small). sig_text is the
    same real signature for every variant, so they all hash to the real selector."""
    sig_text = f"{sig_name}({','.join(types)})"
    dyn_idx = [i for i, t in enumerate(types) if not STATIC.match(t)]
    if not dyn_idx:
        return [(sig_text, (sig_text, len(types)))]
    if len(dyn_idx) > 2:
        dyn_idx = dyn_idx[:2]  # keep the combinatorial product small; rare in practice
    combos = [()]
    for _ in dyn_idx:
        combos = [c + (ln,) for c in combos for ln in length_choices]
    out = []
    for combo in combos:
        lengths = dict(zip(dyn_idx, combo))
        label = f"{sig_text}#{'_'.join(str(n) for n in combo)}"
        out.append((label, (sig_text, lambda prefix, types=types, lengths=lengths: build_words(types, lengths, prefix))))
    return out

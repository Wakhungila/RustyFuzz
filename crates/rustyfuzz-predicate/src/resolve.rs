//! Value resolution: turning a symbol into a value at a point in a sequence (§4.2),
//! with evidence strength (§4.3) and on-demand re-read.
//!
//! # The rule this module enforces
//!
//! `Stale` evidence is `Unknown` for **both** satisfaction and violation. An earlier
//! design allowed stale values to prove satisfaction; that was rejected because a
//! stale `True` is as dangerous as a stale `False` — it makes the search stop looking.
//! The fix is not a looser evidence model but a cheap re-read, so this module takes a
//! [`StateReader`] and re-reads when the trace is not authoritative.
//!
//! # Deliberately type-neutral
//!
//! The resolver consumes abstract slot reads/writes rather than `rustyfuzz-evm`
//! types, so the predicate crate does not depend on the EVM crate and can be tested
//! without building a chain.

use crate::binding::{extract_bits, Binding};
use crate::{Int256, Symbol};
use std::collections::BTreeMap;

/// One committed write observed during the sequence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WriteRecord {
    pub tx_index: usize,
    pub address: [u8; 20],
    pub slot: [u8; 32],
    pub old_value: [u8; 32],
    pub new_value: [u8; 32],
}

/// One slot load observed during the sequence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReadRecord {
    pub tx_index: usize,
    pub address: [u8; 20],
    pub slot: [u8; 32],
    pub value: [u8; 32],
}

/// One successful **top-level** call output observed during the sequence.
///
/// This is what makes a `return_value` binding resolvable from recorded evidence: the
/// return data of the transaction the sequence itself issued. Internal calls are
/// deliberately excluded — a single transaction can call the same function many times
/// internally, so an internal record would make "the value the call returned"
/// ambiguous. A top-level call is unique per transaction by construction.
///
/// `selector` is stored as a 32-byte word with the 4-byte selector in the last four
/// bytes, matching how a `return_value` binding encodes it in its `slot` field.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CallOutputRecord {
    pub tx_index: usize,
    pub address: [u8; 20],
    pub selector: [u8; 32],
    /// Raw ABI-encoded return data of the successful call.
    pub output: Vec<u8>,
}

impl CallOutputRecord {
    /// Builds the record from one observed top-level call. Callers filter for success
    /// and top-level shape; this only normalises the encoding.
    pub fn new(tx_index: usize, address: [u8; 20], input: &[u8], output: &[u8]) -> Self {
        Self {
            tx_index,
            address,
            selector: selector_word(input),
            output: output.to_vec(),
        }
    }
}

/// Packs a call's 4-byte selector into the 32-byte word shape a `return_value`
/// binding compares against. Input shorter than four bytes yields the zero word,
/// which no real selector matches.
pub fn selector_word(input: &[u8]) -> [u8; 32] {
    let mut word = [0u8; 32];
    if input.len() >= 4 {
        word[28..32].copy_from_slice(&input[..4]);
    }
    word
}

/// The `word_index`-th 32-byte word of ABI-encoded return data, or `None` when the
/// output is shorter. A `return_value` binding names one word; a function returning
/// several (or a dynamic array) is read one word at a time.
pub fn return_word_at(output: &[u8], word_index: u16) -> Option<[u8; 32]> {
    let start = usize::from(word_index) * 32;
    let end = start.checked_add(32)?;
    let word = output.get(start..end)?;
    let mut out = [0u8; 32];
    out.copy_from_slice(word);
    Some(out)
}

/// Where a resolved value came from. This is part of the finding evidence, so a
/// reviewer can tell a trace observation from a re-read (§4.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Provenance {
    /// A committed write at or before the evaluation point.
    Write,
    /// A read at exactly the evaluation point with no later write to that slot.
    ObservedRead,
    /// Re-read from post-sequence state.
    ReRead,
    /// The value immediately before the current transaction, from a write's old value.
    PreValue,
    /// The return word of the current transaction's own successful call.
    CallOutput,
}

/// Why a symbol could not be resolved.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum Unresolved {
    #[error("symbol `{symbol}` is not bound in the manifest")]
    Unbound { symbol: String },
    #[error("no read or write of {address}[{slot}] and the re-read failed")]
    NoEvidence { address: String, slot: String },
    #[error("only stale evidence for {address}[{slot}] and the re-read failed")]
    StaleOnly { address: String, slot: String },
    #[error("no write at transaction {tx_index}, so old()/delta() is undefined")]
    NoWriteAtTx { tx_index: usize },
    #[error("{observed} of {total} mapping keys were observed; the rest were not")]
    UnobservedKeys { observed: usize, total: usize },
    #[error("bit range {offset}..{width} does not fit the slot word")]
    BadBitRange { offset: u16, width: u16 },
    #[error("re-read budget exhausted")]
    ReReadBudgetExhausted,
    #[error("no return value for {selector} at {address}")]
    NoReturnValue { address: String, selector: String },
    #[error(
        "return value at {address} for {selector} is {output_bytes} bytes; word {word_index} needs 32"
    )]
    ReturnValueTooShort {
        address: String,
        selector: String,
        word_index: u16,
        output_bytes: usize,
    },
}

impl Unresolved {
    /// Whether this failure is "no signal" for the scheduler (§5.1).
    ///
    /// Always true: every `Unresolved` is an absence of evidence, never a verdict.
    pub fn is_no_signal(&self) -> bool {
        true
    }
}

/// Counts mapping keys the resolver could and could not observe (§9 item 4).
///
/// Reported together so "checked 3 keys" is distinguishable from "checked 3,000".
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct KeyCoverage {
    pub observed_keys: usize,
    pub unobserved_keys: usize,
}

impl KeyCoverage {
    pub fn total(&self) -> usize {
        self.observed_keys + self.unobserved_keys
    }

    pub fn is_complete(&self) -> bool {
        self.unobserved_keys == 0
    }
}

/// Reads current storage for the on-demand re-read (§4.3).
///
/// Implementors must not perform blocking network I/O on the finding path; the
/// campaign's own budget rules apply (§5 item 9b).
pub trait StateReader {
    /// Current value of `slot` at `address`, or `None` if unavailable.
    fn read_slot(&mut self, address: [u8; 20], slot: [u8; 32]) -> Option<[u8; 32]>;

    /// Return word of the function identified by `selector` at `address`.
    ///
    /// Defaults to `None` so a storage-only reader keeps compiling; a caller that
    /// binds a `return_value` symbol must supply an implementation, and a missing one
    /// surfaces as `Unresolved` rather than as a wrong value.
    fn read_return(&mut self, _address: [u8; 20], _selector: [u8; 4]) -> Option<[u8; 32]> {
        None
    }

    /// Return word `word_index` of a call that returns several words.
    ///
    /// Basin's `getReserves()` returns `uint256[]`, so a predicate reads one element at
    /// a time and must name which. Defaults to [`StateReader::read_return`] with index
    /// zero, so a single-word reader keeps working unchanged.
    fn read_return_word(
        &mut self,
        address: [u8; 20],
        selector: [u8; 4],
        word_index: u16,
    ) -> Option<[u8; 32]> {
        if word_index == 0 {
            self.read_return(address, selector)
        } else {
            None
        }
    }
}

/// A reader that refuses every read, for tests and for offline replay of a trace that
/// already contains everything needed.
pub struct NoReRead;

impl StateReader for NoReRead {
    fn read_slot(&mut self, _address: [u8; 20], _slot: [u8; 32]) -> Option<[u8; 32]> {
        None
    }
}

/// Bounded re-read budget, so a predicate over many slots cannot turn evaluation into
/// unbounded work (§5 item 9b).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReReadBudget {
    remaining: usize,
}

impl ReReadBudget {
    pub fn new(limit: usize) -> Self {
        Self { remaining: limit }
    }

    fn take(&mut self) -> bool {
        if self.remaining == 0 {
            return false;
        }
        self.remaining -= 1;
        true
    }

    pub fn remaining(&self) -> usize {
        self.remaining
    }
}

/// One resolved value plus where it came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Resolved {
    pub value: Int256,
    pub provenance: Provenance,
}

/// Resolves symbols against a sequence's observed storage activity.
pub struct Resolver<'a> {
    bindings: &'a BTreeMap<String, Binding>,
    writes: &'a [WriteRecord],
    reads: &'a [ReadRecord],
    call_outputs: &'a [CallOutputRecord],
    tx_index: usize,
}

impl<'a> Resolver<'a> {
    pub fn new(
        bindings: &'a BTreeMap<String, Binding>,
        writes: &'a [WriteRecord],
        reads: &'a [ReadRecord],
        tx_index: usize,
    ) -> Self {
        Self {
            bindings,
            writes,
            reads,
            call_outputs: &[],
            tx_index,
        }
    }

    /// Binds the observed call outputs, so `return_value` symbols resolve from the
    /// sequence's own recorded transactions.
    ///
    /// Optional, and defaulted to empty, because most predicates are over storage:
    /// a resolver without call outputs leaves `return_value` symbols `Unknown`
    /// rather than inventing a value, and existing callers keep working unchanged.
    pub fn with_call_outputs(mut self, call_outputs: &'a [CallOutputRecord]) -> Self {
        self.call_outputs = call_outputs;
        self
    }

    fn binding_for(&self, symbol: &Symbol) -> Result<&Binding, Unresolved> {
        self.bindings
            .get(&symbol.to_string())
            .or_else(|| self.bindings.get(symbol.root()))
            .ok_or_else(|| Unresolved::Unbound {
                symbol: symbol.to_string(),
            })
    }

    /// Latest committed write to `(address, slot)` at or before the evaluation point.
    fn latest_write(&self, address: [u8; 20], slot: [u8; 32]) -> Option<&WriteRecord> {
        self.writes
            .iter()
            .filter(|w| w.address == address && w.slot == slot && w.tx_index <= self.tx_index)
            .max_by_key(|w| w.tx_index)
    }

    /// Whether any write to the slot happened after the given transaction.
    fn written_after(&self, address: [u8; 20], slot: [u8; 32], tx_index: usize) -> bool {
        self.writes
            .iter()
            .any(|w| w.address == address && w.slot == slot && w.tx_index > tx_index)
    }

    fn read_at(&self, address: [u8; 20], slot: [u8; 32], tx_index: usize) -> Option<&ReadRecord> {
        self.reads
            .iter()
            .rfind(|r| r.address == address && r.slot == slot && r.tx_index == tx_index)
    }

    /// Resolves a plain (non-mapping) symbol.
    ///
    /// The four steps of §4.2, in order. Each step either yields authoritative
    /// evidence or falls through; nothing returns a weaker value silently.
    pub fn resolve(
        &self,
        symbol: &Symbol,
        reader: &mut dyn StateReader,
        budget: &mut ReReadBudget,
    ) -> Result<Resolved, Unresolved> {
        let binding = self.binding_for(symbol)?;
        if binding.is_mapping() {
            return Err(Unresolved::Unbound {
                symbol: format!("{symbol} (a mapping must be used via sum/count)"),
            });
        }

        // A return-value symbol is the word a call returns. Two authoritative
        // sources exist, in trust order:
        //
        // 1. The current transaction's own recorded call output. This is what a
        //    proof replay can re-derive with no network (the replay gate evaluates
        //    with `NoReRead`), and what makes the ERC-4626 zero-share deposit
        //    provable without a false start: a deposit happens at exactly one tx,
        //    and that tx's output is the only observation the predicate consults.
        // 2. A live re-read of the function against current state. This serves
        //    predicates over *dependent* contracts (Basin's
        //    `balanceOf(well) >= reserves` calls the token, not the Well): there is
        //    no transaction that "called balanceOf", so recorded outputs cannot
        //    answer it and a fresh call must.
        //
        // A transaction that made neither the bound call nor a re-read leaves the
        // symbol Unknown — never a fabricated pass or fail.
        if binding.is_return_value() {
            if let Some(record) = self.call_outputs.iter().find(|record| {
                record.tx_index == self.tx_index
                    && record.address == binding.address
                    && record.selector == binding.slot
            }) {
                let word = return_word_at(&record.output, binding.word_index).ok_or_else(|| {
                    Unresolved::ReturnValueTooShort {
                        address: crate::binding::hex(&binding.address),
                        selector: crate::binding::hex(&selector_from_slot(&binding.slot)),
                        word_index: binding.word_index,
                        output_bytes: record.output.len(),
                    }
                })?;
                return self.extract_from(binding, &word, Provenance::CallOutput);
            }
            if !budget.take() {
                return Err(Unresolved::ReReadBudgetExhausted);
            }
            let selector = selector_from_slot(&binding.slot);
            return match reader.read_return_word(binding.address, selector, binding.word_index) {
                Some(word) => self.extract_from(binding, &word, Provenance::ReRead),
                None => Err(Unresolved::NoReturnValue {
                    address: crate::binding::hex(&binding.address),
                    selector: crate::binding::hex(&selector),
                }),
            };
        }

        let (address, slot) = (binding.address, binding.slot);

        // Step 1: a committed write at or before this point is authoritative.
        if let Some(write) = self.latest_write(address, slot) {
            return self.extract_from(binding, &write.new_value, Provenance::Write);
        }

        // Step 2: a read at exactly this point is authoritative only if nothing wrote
        // the slot afterwards; otherwise it is stale and must not be trusted.
        if let Some(read) = self.read_at(address, slot, self.tx_index) {
            if !self.written_after(address, slot, self.tx_index) {
                return self.extract_from(binding, &read.value, Provenance::ObservedRead);
            }
        }

        // Step 3: re-read from post-sequence state. Authoritative when it succeeds.
        if budget.take() {
            if let Some(word) = reader.read_slot(address, slot) {
                return self.extract_from(binding, &word, Provenance::ReRead);
            }
        } else {
            return Err(Unresolved::ReReadBudgetExhausted);
        }

        // Nothing authoritative exists. Distinguish stale-only from nothing-at-all so
        // the metric says which gap it hit.
        if self
            .reads
            .iter()
            .any(|r| r.address == address && r.slot == slot && r.tx_index <= self.tx_index)
        {
            return Err(Unresolved::StaleOnly {
                address: crate::binding::hex(&address),
                slot: crate::binding::hex(&slot),
            });
        }
        Err(Unresolved::NoEvidence {
            address: crate::binding::hex(&address),
            slot: crate::binding::hex(&slot),
        })
    }

    /// `old(symbol)`: the value before the current transaction.
    ///
    /// Cannot be re-read — "the value immediately before transaction i" is not a
    /// property of current state — so a missing write at `tx_index` is `Unknown`.
    pub fn resolve_old(&self, symbol: &Symbol) -> Result<Resolved, Unresolved> {
        let binding = self.binding_for(symbol)?;
        if binding.is_mapping() {
            return Err(Unresolved::Unbound {
                symbol: format!("{symbol} (old() of a mapping is not defined)"),
            });
        }
        let write = self
            .writes
            .iter()
            .filter(|w| {
                w.address == binding.address
                    && w.slot == binding.slot
                    && w.tx_index == self.tx_index
            })
            .max_by_key(|w| w.tx_index)
            .ok_or(Unresolved::NoWriteAtTx {
                tx_index: self.tx_index,
            })?;
        self.extract_from(binding, &write.old_value, Provenance::PreValue)
    }

    /// Sums a mapping's declared keys, reporting coverage.
    ///
    /// Keys that cannot be observed make the result `Unresolved::UnobservedKeys`
    /// rather than `0`: a partial sum that silently omits a key would understate the
    /// total and could turn a real violation into a pass (§9 item 4).
    pub fn resolve_sum(
        &self,
        symbol: &Symbol,
        reader: &mut dyn StateReader,
        budget: &mut ReReadBudget,
    ) -> Result<(Resolved, KeyCoverage), Unresolved> {
        let binding = self.binding_for(symbol)?;
        if !binding.is_mapping() {
            return Err(Unresolved::Unbound {
                symbol: format!("{symbol} (sum requires a mapping binding)"),
            });
        }
        let mut total = Int256::ZERO;
        let mut coverage = KeyCoverage::default();
        // Every key shares the provenance of the least authoritative term, because a
        // sum is only as trustworthy as its weakest input.
        let mut provenance = Provenance::Write;

        for key in &binding.keys {
            let slot = binding.slot_for_key(key);
            match self.resolve_mapping_entry(binding, &slot, reader, budget) {
                Ok(resolved) => {
                    coverage.observed_keys += 1;
                    total = total.wrapping_add(resolved.value);
                    provenance = weaker(provenance, resolved.provenance);
                }
                Err(_) => coverage.unobserved_keys += 1,
            }
        }

        if !coverage.is_complete() {
            return Err(Unresolved::UnobservedKeys {
                observed: coverage.observed_keys,
                total: coverage.total(),
            });
        }
        Ok((
            Resolved {
                value: total,
                provenance,
            },
            coverage,
        ))
    }

    /// `count(mapping)`: how many declared keys are observable.
    pub fn resolve_count(
        &self,
        symbol: &Symbol,
        reader: &mut dyn StateReader,
        budget: &mut ReReadBudget,
    ) -> Result<(Resolved, KeyCoverage), Unresolved> {
        let binding = self.binding_for(symbol)?;
        if !binding.is_mapping() {
            return Err(Unresolved::Unbound {
                symbol: format!("{symbol} (count requires a mapping binding)"),
            });
        }
        let mut coverage = KeyCoverage::default();
        for key in &binding.keys {
            let slot = binding.slot_for_key(key);
            match self.resolve_mapping_entry(binding, &slot, reader, budget) {
                Ok(_) => coverage.observed_keys += 1,
                Err(_) => coverage.unobserved_keys += 1,
            }
        }
        if !coverage.is_complete() {
            return Err(Unresolved::UnobservedKeys {
                observed: coverage.observed_keys,
                total: coverage.total(),
            });
        }
        Ok((
            Resolved {
                value: Int256::from_u64(coverage.observed_keys as u64),
                provenance: Provenance::Write,
            },
            coverage,
        ))
    }

    fn resolve_mapping_entry(
        &self,
        binding: &Binding,
        slot: &[u8; 32],
        reader: &mut dyn StateReader,
        budget: &mut ReReadBudget,
    ) -> Result<Resolved, Unresolved> {
        if let Some(write) = self.latest_write(binding.address, *slot) {
            return self.extract_from(binding, &write.new_value, Provenance::Write);
        }
        if let Some(read) = self.read_at(binding.address, *slot, self.tx_index) {
            if !self.written_after(binding.address, *slot, self.tx_index) {
                return self.extract_from(binding, &read.value, Provenance::ObservedRead);
            }
        }
        if budget.take() {
            if let Some(word) = reader.read_slot(binding.address, *slot) {
                return self.extract_from(binding, &word, Provenance::ReRead);
            }
        } else {
            return Err(Unresolved::ReReadBudgetExhausted);
        }
        Err(Unresolved::NoEvidence {
            address: crate::binding::hex(&binding.address),
            slot: crate::binding::hex(slot),
        })
    }

    fn extract_from(
        &self,
        binding: &Binding,
        word: &[u8; 32],
        provenance: Provenance,
    ) -> Result<Resolved, Unresolved> {
        let value = extract_bits(word, binding.offset_bits, binding.width_bits).ok_or(
            Unresolved::BadBitRange {
                offset: binding.offset_bits,
                width: binding.width_bits,
            },
        )?;
        Ok(Resolved { value, provenance })
    }
}

/// Reads the 4-byte selector carried in a `return_value` binding's word.
///
/// The manifest writes it as a short hex quantity (`0xdeadbeef`), and `parse_word`
/// left-pads short quantities, so the selector occupies the **last** four bytes.
/// Reading the first four silently yielded a zero selector, which looked like a
/// missing function rather than a bug.
fn selector_from_slot(word: &[u8; 32]) -> [u8; 4] {
    [word[28], word[29], word[30], word[31]]
}

/// Orders provenance by descending trust, so a sum can report its weakest term.
fn weaker(a: Provenance, b: Provenance) -> Provenance {
    let rank = |p: Provenance| match p {
        Provenance::Write => 0,
        Provenance::PreValue => 1,
        Provenance::ObservedRead => 2,
        Provenance::ReRead => 3,
        Provenance::CallOutput => 4,
    };
    if rank(a) >= rank(b) {
        a
    } else {
        b
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::binding::{BindingKind, BindingManifest};

    fn addr(last: u8) -> [u8; 20] {
        let mut a = [0u8; 20];
        a[19] = last;
        a
    }

    fn slot_of(value: u8) -> [u8; 32] {
        let mut s = [0u8; 32];
        s[31] = value;
        s
    }

    fn word_of(value: u64) -> [u8; 32] {
        let mut w = [0u8; 32];
        w[24..].copy_from_slice(&value.to_be_bytes());
        w
    }

    fn manifest_for(json: &str) -> BTreeMap<String, Binding> {
        BindingManifest::from_json(json)
            .expect("parses")
            .resolve()
            .expect("resolves")
    }

    const ONE_SLOT: &str = r#"{
        "target": "0x00000000000000000000000000000000000000aa",
        "symbols": {
            "totalSupply": { "kind": "slot", "slot": "0x3",
                             "offset_bits": 0, "width_bits": 256 }
        }
    }"#;

    /// A reader holding a fixed current state, for testing the re-read path.
    struct FixedState(BTreeMap<([u8; 20], [u8; 32]), [u8; 32]>);

    impl StateReader for FixedState {
        fn read_slot(&mut self, address: [u8; 20], slot: [u8; 32]) -> Option<[u8; 32]> {
            self.0.get(&(address, slot)).copied()
        }
    }

    fn sym(name: &str) -> Symbol {
        Symbol(vec![name.to_string()])
    }

    // ---- step 1: a write is authoritative ------------------------------

    #[test]
    fn a_committed_write_resolves_without_any_re_read() {
        let bindings = manifest_for(ONE_SLOT);
        let writes = vec![WriteRecord {
            tx_index: 0,
            address: addr(0xaa),
            slot: slot_of(3),
            old_value: word_of(100),
            new_value: word_of(40),
        }];
        let resolver = Resolver::new(&bindings, &writes, &[], 1);
        let mut reader = NoReRead;
        let mut budget = ReReadBudget::new(4);

        let resolved = resolver
            .resolve(&sym("totalSupply"), &mut reader, &mut budget)
            .expect("resolves from the write");
        assert_eq!(resolved.value, Int256::from_u64(40));
        assert_eq!(resolved.provenance, Provenance::Write);
        assert_eq!(budget.remaining(), 4, "no re-read was needed");
    }

    // ---- §4.3: stale is not usable, but the re-read saves it -----------

    #[test]
    fn a_stale_read_alone_is_unresolved_without_a_reader() {
        // A read at tx 0, then a write at tx 1, evaluated at tx 1: the tx-0 read is
        // stale and must not be trusted.
        let bindings = manifest_for(ONE_SLOT);
        let reads = vec![ReadRecord {
            tx_index: 0,
            address: addr(0xaa),
            slot: slot_of(3),
            value: word_of(100),
        }];
        let resolver = Resolver::new(&bindings, &[], &reads, 1);
        let mut reader = NoReRead;
        let mut budget = ReReadBudget::new(4);

        let error = resolver
            .resolve(&sym("totalSupply"), &mut reader, &mut budget)
            .unwrap_err();
        assert!(matches!(error, Unresolved::StaleOnly { .. }));
        assert!(error.is_no_signal());
    }

    #[test]
    fn a_stale_read_is_recovered_by_the_re_read() {
        let bindings = manifest_for(ONE_SLOT);
        let reads = vec![ReadRecord {
            tx_index: 0,
            address: addr(0xaa),
            slot: slot_of(3),
            value: word_of(100),
        }];
        let resolver = Resolver::new(&bindings, &[], &reads, 1);
        let mut reader = FixedState(BTreeMap::from([((addr(0xaa), slot_of(3)), word_of(40))]));
        let mut budget = ReReadBudget::new(4);

        let resolved = resolver
            .resolve(&sym("totalSupply"), &mut reader, &mut budget)
            .expect("re-read resolves it");
        assert_eq!(
            resolved.value,
            Int256::from_u64(40),
            "must use the re-read value"
        );
        assert_eq!(resolved.provenance, Provenance::ReRead);
        assert_eq!(budget.remaining(), 3, "one re-read consumed");
    }

    #[test]
    fn a_read_at_the_same_point_with_no_later_write_is_authoritative() {
        let bindings = manifest_for(ONE_SLOT);
        let reads = vec![ReadRecord {
            tx_index: 2,
            address: addr(0xaa),
            slot: slot_of(3),
            value: word_of(77),
        }];
        let resolver = Resolver::new(&bindings, &[], &reads, 2);
        let mut reader = NoReRead;
        let mut budget = ReReadBudget::new(4);

        let resolved = resolver
            .resolve(&sym("totalSupply"), &mut reader, &mut budget)
            .expect("same-point read is authoritative");
        assert_eq!(resolved.value, Int256::from_u64(77));
        assert_eq!(resolved.provenance, Provenance::ObservedRead);
    }

    // ---- §5 item 9b: bounded re-reads ---------------------------------

    #[test]
    fn an_exhausted_re_read_budget_is_a_typed_error_not_a_panic() {
        let bindings = manifest_for(ONE_SLOT);
        let resolver = Resolver::new(&bindings, &[], &[], 0);
        let mut reader = NoReRead;
        let mut budget = ReReadBudget::new(0);

        let error = resolver
            .resolve(&sym("totalSupply"), &mut reader, &mut budget)
            .unwrap_err();
        assert!(matches!(error, Unresolved::ReReadBudgetExhausted));
    }

    // ---- old() / delta() ----------------------------------------------

    #[test]
    fn old_requires_a_write_at_the_current_transaction() {
        let bindings = manifest_for(ONE_SLOT);
        let writes = vec![WriteRecord {
            tx_index: 0,
            address: addr(0xaa),
            slot: slot_of(3),
            old_value: word_of(100),
            new_value: word_of(40),
        }];
        // Evaluated at tx 1: no write at tx 1, so old() is undefined even though a
        // write exists at tx 0.
        let resolver = Resolver::new(&bindings, &writes, &[], 1);
        assert!(matches!(
            resolver.resolve_old(&sym("totalSupply")).unwrap_err(),
            Unresolved::NoWriteAtTx { tx_index: 1 }
        ));

        let resolver = Resolver::new(&bindings, &writes, &[], 0);
        let resolved = resolver.resolve_old(&sym("totalSupply")).expect("resolves");
        assert_eq!(resolved.value, Int256::from_u64(100));
        assert_eq!(resolved.provenance, Provenance::PreValue);
    }

    // ---- §9 item 4: mapping sums and key coverage ---------------------

    const MAPPING: &str = r#"{
        "target": "0x00000000000000000000000000000000000000aa",
        "symbols": {
            "balances": {
                "kind": "mapping", "slot": "0x4", "key_type": "address",
                "keys": [
                    "0x00000000000000000000000000000000000A11ce",
                    "0x0000000000000000000000000000000000000B0b"
                ],
                "offset_bits": 0, "width_bits": 256
            }
        }
    }"#;

    fn mapping_binding() -> BTreeMap<String, Binding> {
        manifest_for(MAPPING)
    }

    #[test]
    fn sum_over_all_observed_keys_is_exact() {
        let bindings = mapping_binding();
        let binding = &bindings["balances"];
        assert_eq!(binding.kind, BindingKind::Mapping);
        let key0 = binding.slot_for_key(&binding.keys[0]);
        let key1 = binding.slot_for_key(&binding.keys[1]);

        let writes = vec![
            WriteRecord {
                tx_index: 0,
                address: addr(0xaa),
                slot: key0,
                old_value: word_of(0),
                new_value: word_of(40),
            },
            WriteRecord {
                tx_index: 0,
                address: addr(0xaa),
                slot: key1,
                old_value: word_of(0),
                new_value: word_of(60),
            },
        ];
        let resolver = Resolver::new(&bindings, &writes, &[], 1);
        let mut reader = NoReRead;
        let mut budget = ReReadBudget::new(4);

        let (resolved, coverage) = resolver
            .resolve_sum(&sym("balances"), &mut reader, &mut budget)
            .expect("both keys observed");
        assert_eq!(resolved.value, Int256::from_u64(100));
        assert_eq!(coverage.observed_keys, 2);
        assert_eq!(coverage.unobserved_keys, 0);
        assert!(coverage.is_complete());
    }

    #[test]
    fn sum_with_an_unobserved_key_is_unresolved_and_reports_coverage() {
        // §9 item 4: a partial sum must not silently become a smaller total, because
        // that could turn a real violation into a pass.
        let bindings = mapping_binding();
        let binding = &bindings["balances"];
        let key0 = binding.slot_for_key(&binding.keys[0]);

        let writes = vec![WriteRecord {
            tx_index: 0,
            address: addr(0xaa),
            slot: key0,
            old_value: word_of(0),
            new_value: word_of(40),
        }];
        let resolver = Resolver::new(&bindings, &writes, &[], 1);
        let mut reader = NoReRead;
        let mut budget = ReReadBudget::new(4);

        match resolver
            .resolve_sum(&sym("balances"), &mut reader, &mut budget)
            .unwrap_err()
        {
            Unresolved::UnobservedKeys { observed, total } => {
                assert_eq!(observed, 1);
                assert_eq!(total, 2);
            }
            other => panic!("expected UnobservedKeys, got {other}"),
        }
    }

    #[test]
    fn a_mapping_sum_is_rescued_by_a_full_re_read() {
        let bindings = mapping_binding();
        let binding = &bindings["balances"];
        let key0 = binding.slot_for_key(&binding.keys[0]);
        let key1 = binding.slot_for_key(&binding.keys[1]);

        let resolver = Resolver::new(&bindings, &[], &[], 1);
        let mut reader = FixedState(BTreeMap::from([
            ((addr(0xaa), key0), word_of(40)),
            ((addr(0xaa), key1), word_of(60)),
        ]));
        let mut budget = ReReadBudget::new(4);

        let (resolved, coverage) = resolver
            .resolve_sum(&sym("balances"), &mut reader, &mut budget)
            .expect("re-read covers both keys");
        assert_eq!(resolved.value, Int256::from_u64(100));
        assert_eq!(coverage.observed_keys, 2);
        assert_eq!(resolved.provenance, Provenance::ReRead);
    }

    #[test]
    fn count_reports_observable_keys_only_when_complete() {
        let bindings = mapping_binding();
        let binding = &bindings["balances"];
        let key0 = binding.slot_for_key(&binding.keys[0]);
        let key1 = binding.slot_for_key(&binding.keys[1]);

        let resolver = Resolver::new(&bindings, &[], &[], 1);
        let mut reader = FixedState(BTreeMap::from([
            ((addr(0xaa), key0), word_of(1)),
            ((addr(0xaa), key1), word_of(2)),
        ]));
        let mut budget = ReReadBudget::new(4);
        let (resolved, coverage) = resolver
            .resolve_count(&sym("balances"), &mut reader, &mut budget)
            .expect("both observable");
        assert_eq!(resolved.value, Int256::from_u64(2));
        assert_eq!(coverage.total(), 2);
    }

    // ---- packed slots through the resolver ----------------------------

    #[test]
    fn a_packed_bool_does_not_see_the_neighbouring_address() {
        // The reason bit ranges are mandatory: this slot holds both a bool at bit 0
        // and an address above bit 96.
        let json = r#"{
            "target": "0x00000000000000000000000000000000000000aa",
            "symbols": {
                "initialized": { "kind": "slot", "slot": "0x0",
                                 "offset_bits": 0, "width_bits": 8 }
            }
        }"#;
        let bindings = manifest_for(json);
        let mut word = [0u8; 32];
        word[0..20].copy_from_slice(&[0xab; 20]);
        word[31] = 1;

        let writes = vec![WriteRecord {
            tx_index: 0,
            address: addr(0xaa),
            slot: [0u8; 32],
            old_value: [0u8; 32],
            new_value: word,
        }];
        let resolver = Resolver::new(&bindings, &writes, &[], 0);
        let mut reader = NoReRead;
        let mut budget = ReReadBudget::new(2);
        let resolved = resolver
            .resolve(&sym("initialized"), &mut reader, &mut budget)
            .expect("resolves");
        assert_eq!(resolved.value, Int256::from_u64(1));
    }

    // ---- unbound symbols ----------------------------------------------

    #[test]
    fn an_unbound_symbol_fails_with_its_name() {
        let bindings = manifest_for(ONE_SLOT);
        let resolver = Resolver::new(&bindings, &[], &[], 0);
        let mut reader = NoReRead;
        let mut budget = ReReadBudget::new(2);
        match resolver
            .resolve(&sym("absent"), &mut reader, &mut budget)
            .unwrap_err()
        {
            Unresolved::Unbound { symbol } => assert_eq!(symbol, "absent"),
            other => panic!("expected Unbound, got {other}"),
        }
    }

    #[test]
    fn a_mapping_cannot_be_resolved_as_a_plain_symbol() {
        let bindings = mapping_binding();
        let resolver = Resolver::new(&bindings, &[], &[], 0);
        let mut reader = NoReRead;
        let mut budget = ReReadBudget::new(2);
        assert!(resolver
            .resolve(&sym("balances"), &mut reader, &mut budget)
            .is_err());
    }

    // ---- return values resolve from the transaction's own call output ----

    const DEPOSIT_SELECTOR: [u8; 4] = [0x6e, 0x55, 0x3f, 0x65];

    const RETURN_BINDING: &str = r#"{
        "target": "0x00000000000000000000000000000000000000aa",
        "symbols": {
            "depositShares": { "kind": "return_value", "slot": "0x6e553f65",
                               "offset_bits": 0, "width_bits": 256, "word_index": 0 }
        }
    }"#;

    fn deposit_call(tx_index: usize, shares: u64) -> CallOutputRecord {
        let mut input = DEPOSIT_SELECTOR.to_vec();
        input.extend_from_slice(&word_of(1000));
        input.extend_from_slice(&word_of(0xbb));
        CallOutputRecord::new(tx_index, addr(0xaa), &input, &word_of(shares))
    }

    /// Calls the *same* selector at a different address, to prove address matching.
    fn deposit_call_at(tx_index: usize, target: u8, shares: u64) -> CallOutputRecord {
        let mut input = DEPOSIT_SELECTOR.to_vec();
        input.extend_from_slice(&word_of(1000));
        CallOutputRecord::new(tx_index, addr(target), &input, &word_of(shares))
    }

    #[test]
    fn a_return_value_resolves_from_the_current_transactions_call_output() {
        let bindings = manifest_for(RETURN_BINDING);
        let outputs = vec![deposit_call(0, 1), deposit_call(1, 0)];
        let resolver = Resolver::new(&bindings, &[], &[], 1).with_call_outputs(&outputs);
        let mut reader = NoReRead;
        let mut budget = ReReadBudget::new(4);

        let resolved = resolver
            .resolve(&sym("depositShares"), &mut reader, &mut budget)
            .expect("the deposit's own output is authoritative");
        // Zero shares for a nonzero deposit is exactly the ERC-4626 bug shape.
        assert_eq!(resolved.value, Int256::ZERO);
        assert_eq!(resolved.provenance, Provenance::CallOutput);
        assert_eq!(
            budget.remaining(),
            4,
            "resolving a recorded output must not spend the re-read budget"
        );
    }

    #[test]
    fn an_earlier_transactions_output_is_never_used_for_a_later_one() {
        // Same function, same address, but only tx 0 called it. Evaluating at tx 1
        // must be Unknown: reusing tx 0's word would make a stale value look current.
        let bindings = manifest_for(RETURN_BINDING);
        let outputs = vec![deposit_call(0, 1)];
        let resolver = Resolver::new(&bindings, &[], &[], 1).with_call_outputs(&outputs);
        let mut reader = NoReRead;
        let mut budget = ReReadBudget::new(4);

        let error = resolver
            .resolve(&sym("depositShares"), &mut reader, &mut budget)
            .unwrap_err();
        assert!(matches!(error, Unresolved::NoReturnValue { .. }));
        assert!(
            error.is_no_signal(),
            "absence of a call must not be a verdict"
        );
    }

    #[test]
    fn a_tx_that_never_called_the_function_is_unknown_not_a_violation() {
        // This is what removes the false start: the very first transaction in a
        // sequence may not be a deposit at all, and that must be no signal.
        let bindings = manifest_for(RETURN_BINDING);
        let resolver = Resolver::new(&bindings, &[], &[], 0);
        let mut reader = NoReRead;
        let mut budget = ReReadBudget::new(4);
        assert!(resolver
            .resolve(&sym("depositShares"), &mut reader, &mut budget)
            .is_err());
    }

    #[test]
    fn the_same_selector_at_another_address_does_not_resolve() {
        // A return-value symbol names a contract as well as a function; a call to a
        // different contract that happens to share a selector is a different call.
        let bindings = manifest_for(RETURN_BINDING);
        let outputs = vec![deposit_call_at(0, 0xcc, 0)];
        let resolver = Resolver::new(&bindings, &[], &[], 0).with_call_outputs(&outputs);
        let mut reader = NoReRead;
        let mut budget = ReReadBudget::new(4);

        assert!(matches!(
            resolver
                .resolve(&sym("depositShares"), &mut reader, &mut budget)
                .unwrap_err(),
            Unresolved::NoReturnValue { .. }
        ));
    }

    #[test]
    fn a_failed_call_contributes_no_output() {
        // `call_outputs_from` drops failed calls; a reader must therefore treat a
        // reverted deposit as unobserved rather than as "returned zero".
        let bindings = manifest_for(RETURN_BINDING);
        let resolver = Resolver::new(&bindings, &[], &[], 0);
        let mut reader = NoReRead;
        let mut budget = ReReadBudget::new(4);
        assert!(resolver
            .resolve(&sym("depositShares"), &mut reader, &mut budget)
            .is_err());
    }

    #[test]
    fn an_output_shorter_than_the_named_word_is_unresolved() {
        // A function returning no data cannot satisfy a word-indexed binding; the
        // failure must name the gap instead of zero-padding the word.
        let bindings = manifest_for(
            r#"{
                "target": "0x00000000000000000000000000000000000000aa",
                "symbols": {
                    "second": { "kind": "return_value", "slot": "0x6e553f65",
                                "offset_bits": 0, "width_bits": 256, "word_index": 1 }
                }
            }"#,
        );
        let output = word_of(7); // one word only
        let mut input = DEPOSIT_SELECTOR.to_vec();
        input.extend_from_slice(&word_of(1000));
        let outputs = vec![CallOutputRecord::new(0, addr(0xaa), &input, &output)];
        let resolver = Resolver::new(&bindings, &[], &[], 0).with_call_outputs(&outputs);
        let mut reader = NoReRead;
        let mut budget = ReReadBudget::new(4);

        match resolver
            .resolve(&sym("second"), &mut reader, &mut budget)
            .unwrap_err()
        {
            Unresolved::ReturnValueTooShort {
                word_index,
                output_bytes,
                ..
            } => {
                assert_eq!(word_index, 1);
                assert_eq!(output_bytes, 32);
            }
            other => panic!("expected ReturnValueTooShort, got {other}"),
        }
    }

    #[test]
    fn a_second_return_word_is_read_at_its_own_index() {
        // Dynamic-array returns (Basin's `getReserves`) are read one word at a time;
        // the index must select the named word, not always the first.
        let bindings = manifest_for(
            r#"{
                "target": "0x00000000000000000000000000000000000000aa",
                "symbols": {
                    "second": { "kind": "return_value", "slot": "0x6e553f65",
                                "offset_bits": 0, "width_bits": 256, "word_index": 1 }
                }
            }"#,
        );
        let mut output = [0u8; 64];
        output[..32].copy_from_slice(&word_of(11));
        output[32..].copy_from_slice(&word_of(22));
        let mut input = DEPOSIT_SELECTOR.to_vec();
        input.extend_from_slice(&word_of(1000));
        let outputs = vec![CallOutputRecord::new(0, addr(0xaa), &input, &output)];
        let resolver = Resolver::new(&bindings, &[], &[], 0).with_call_outputs(&outputs);
        let mut reader = NoReRead;
        let mut budget = ReReadBudget::new(4);

        let resolved = resolver
            .resolve(&sym("second"), &mut reader, &mut budget)
            .expect("word 1 exists");
        assert_eq!(resolved.value, Int256::from_u64(22));
    }

    #[test]
    fn a_narrow_bit_range_applies_to_a_return_word_too() {
        let bindings = manifest_for(
            r#"{
                "target": "0x00000000000000000000000000000000000000aa",
                "symbols": {
                    "flag": { "kind": "return_value", "slot": "0x6e553f65",
                              "offset_bits": 0, "width_bits": 8, "word_index": 0 }
                }
            }"#,
        );
        let output = word_of(0x104);
        let mut input = DEPOSIT_SELECTOR.to_vec();
        input.extend_from_slice(&word_of(1000));
        let outputs = vec![CallOutputRecord::new(0, addr(0xaa), &input, &output)];
        let resolver = Resolver::new(&bindings, &[], &[], 0).with_call_outputs(&outputs);
        let mut reader = NoReRead;
        let mut budget = ReReadBudget::new(4);

        let resolved = resolver
            .resolve(&sym("flag"), &mut reader, &mut budget)
            .expect("resolves");
        assert_eq!(resolved.value, Int256::from_u64(4));
    }
}

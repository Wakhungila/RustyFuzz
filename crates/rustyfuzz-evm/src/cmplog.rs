//! Comparison-operand log (RedQueen-style input-to-state).
//!
//! The inspector records the two operands of every `LT/GT/SLT/SGT/EQ` it executes. After a
//! sequence the harness drains the per-thread buffer into a process-wide table mapping each
//! operand to the values it was compared against. The mutator then looks for calldata words
//! equal to a logged operand and replaces them with the partner, which solves `x == CONST`
//! style guards without symbolic execution or taint tracking.

use revm::primitives::U256;
use std::cell::RefCell;
use std::collections::HashMap;
use std::sync::{LazyLock, Mutex};

const THREAD_BUF_CAP: usize = 512;
const MAX_KEYS: usize = 8192;
const MAX_PARTNERS: usize = 8;
const MAX_VALUES: usize = 4096;

thread_local! {
    static BUF: RefCell<Vec<(U256, U256)>> = const { RefCell::new(Vec::new()) };
}

/// Records one comparison's operands on this thread (cheap; bounded).
#[inline]
pub fn record(a: U256, b: U256) {
    if a == b {
        return;
    }
    BUF.with(|buf| {
        let mut buf = buf.borrow_mut();
        if buf.len() < THREAD_BUF_CAP {
            buf.push((a, b));
        }
    });
}

#[derive(Default)]
struct Table {
    partners: HashMap<U256, Vec<U256>>,
    values: Vec<U256>,
    seen_values: std::collections::HashSet<U256>,
    tick: u64,
}

static TABLE: LazyLock<Mutex<Table>> = LazyLock::new(|| Mutex::new(Table::default()));

fn insert(table: &mut Table, key: U256, partner: U256) {
    table.tick = table.tick.wrapping_add(1);
    if table.partners.len() >= MAX_KEYS && !table.partners.contains_key(&key) {
        return;
    }
    let entry = table.partners.entry(key).or_default();
    if entry.contains(&partner) {
        return;
    }
    if entry.len() < MAX_PARTNERS {
        entry.push(partner);
    } else {
        let slot = (table.tick as usize) % MAX_PARTNERS;
        entry[slot] = partner;
    }
    if table.values.len() < MAX_VALUES && table.seen_values.insert(partner) {
        table.values.push(partner);
    }
}

/// Moves this thread's buffered comparisons into the shared table.
pub fn drain_into_table() {
    let drained: Vec<(U256, U256)> = BUF.with(|buf| std::mem::take(&mut *buf.borrow_mut()));
    if drained.is_empty() {
        return;
    }
    let mut table = TABLE.lock().unwrap_or_else(|e| e.into_inner());
    for (a, b) in drained {
        insert(&mut table, a, b);
        insert(&mut table, b, a);
    }
}

/// Discards this thread's buffered comparisons (e.g. before a re-execution).
pub fn clear_thread_buffer() {
    BUF.with(|buf| buf.borrow_mut().clear());
}

/// Values observed as comparison partners for `word`, if any.
pub fn partners_of(word: &U256) -> Option<Vec<U256>> {
    let table = TABLE.lock().unwrap_or_else(|e| e.into_inner());
    table.partners.get(word).cloned()
}

/// A pseudo-randomly chosen logged operand (for dictionary splicing).
pub fn pick_value(selector: u64) -> Option<U256> {
    let table = TABLE.lock().unwrap_or_else(|e| e.into_inner());
    if table.values.is_empty() {
        None
    } else {
        Some(table.values[(selector as usize) % table.values.len()])
    }
}

pub fn is_empty() -> bool {
    TABLE
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .values
        .is_empty()
}

/// Test helper: clears the shared table.
pub fn reset_for_tests() {
    *TABLE.lock().unwrap_or_else(|e| e.into_inner()) = Table::default();
    clear_thread_buffer();
}

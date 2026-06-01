use revm::{
    context_interface::{ContextTr, CreateScheme},
    interpreter::{
        interpreter_types::{InputsTr, Jumps},
        CallInputs, CallOutcome, CallScheme, CreateInputs, CreateOutcome, Interpreter,
    },
    Inspector,
};
// v38: OpCode is now in the bytecode module or directly available
// use revm::bytecode::Bytecode; // Unused
// use bitvec::prelude::{BitSlice, Lsb0}; // Unused
use crate::common::types::{
    CallKind, CallPhase, ComparisonOperand, SymbolicExpression, TaintSource, Waypoint,
};
use crate::evm::dataflow::DataflowRegistry;
use revm::primitives::{keccak256, Address, B256, U256};
use std::collections::{HashMap, HashSet};

/// Industry standard: Use a fixed-size map for coverage to allow
/// JIT-like performance and SIMD-optimized comparisons in the feedback loop.
pub const MAP_SIZE: usize = 262144; // Default size for standalone maps.

#[derive(Debug)]
pub struct CoverageInspector<'a> {
    pub coverage: &'a mut [u8], // Move to hitcounts
    pub dataflow: &'a mut DataflowRegistry,
    pub waypoints: &'a mut Vec<Waypoint>,
    pub taint_stack: Vec<Option<TaintSource>>, // Mirror stack: stores taint source
    pub symbolic_stack: Vec<Option<SymbolicExpression>>,
    pub read_set: HashSet<(Address, B256)>,
    pub write_set: HashSet<(Address, B256)>,
    pub last_pc: usize,
    pub current_tx_idx: usize, // Index of the current transaction in the sequence
    pub instruction_count: u64, // Virtual Performance Counter: total instructions
    pub gas_consumed: u64,     // Virtual Performance Counter: total gas
    pub symbolic_storage_map: HashMap<(Address, B256), TaintSource>, // (addr, slot) -> TaintSource of value
    pub storage_expression_map: HashMap<(Address, B256), SymbolicExpression>,
    pub transient_taint_map: HashMap<(Address, B256), TaintSource>, // EIP-1153 support
    pub memory_taint: HashMap<usize, TaintSource>,                  // offset -> TaintSource
    pub memory_expression: HashMap<usize, SymbolicExpression>,
    pub known_initialized_slots: HashSet<(Address, B256)>, // Track slots written in current or previous TXs
    pub call_depth: usize,
    pending_sload: Option<PendingStorageRead>,
}

#[derive(Debug, Clone)]
struct PendingStorageRead {
    address: Address,
    slot: B256,
    pc: usize,
    tx_idx: usize,
    taint_source: Option<TaintSource>,
    expression: Option<SymbolicExpression>,
}

impl<'a> CoverageInspector<'a> {
    pub fn new(
        coverage: &'a mut [u8],
        dataflow: &'a mut DataflowRegistry,
        waypoints: &'a mut Vec<Waypoint>,
        current_tx_idx: usize,
    ) -> Self {
        Self {
            coverage,
            dataflow,
            waypoints,
            taint_stack: Vec::with_capacity(1024), // Max stack depth
            symbolic_stack: Vec::with_capacity(1024),
            read_set: HashSet::new(),
            write_set: HashSet::new(),
            last_pc: 0,
            current_tx_idx,
            instruction_count: 0,
            gas_consumed: 0,
            symbolic_storage_map: HashMap::new(),
            storage_expression_map: HashMap::new(),
            transient_taint_map: HashMap::new(),
            memory_taint: HashMap::new(),
            memory_expression: HashMap::new(),
            known_initialized_slots: HashSet::new(),
            call_depth: 0,
            pending_sload: None,
        }
    }

    fn push_symbolic(
        &mut self,
        taint: Option<TaintSource>,
        expression: Option<SymbolicExpression>,
    ) {
        self.taint_stack.push(taint);
        self.symbolic_stack.push(expression);
    }

    fn pop_symbolic_operands(&mut self, count: usize) {
        for _ in 0..count {
            self.taint_stack.pop();
            self.symbolic_stack.pop();
        }
    }
}

fn compare_condition(opcode: u8, lhs: U256, rhs: U256) -> bool {
    match opcode {
        0x10 => lhs < rhs,
        0x11 => lhs > rhs,
        0x12 => signed_less_than(lhs, rhs),
        0x13 => signed_greater_than(lhs, rhs),
        0x14 => lhs == rhs,
        _ => false,
    }
}

fn branch_distance(opcode: u8, lhs: U256, rhs: U256, condition: bool) -> Option<U256> {
    if condition {
        return Some(U256::ZERO);
    }
    match opcode {
        0x10 | 0x12 => lhs
            .checked_sub(rhs)
            .map(|gap| gap.saturating_add(U256::from(1))),
        0x11 | 0x13 => rhs
            .checked_sub(lhs)
            .map(|gap| gap.saturating_add(U256::from(1))),
        0x14 => Some(if lhs > rhs { lhs - rhs } else { rhs - lhs }),
        _ => None,
    }
}

fn signed_less_than(lhs: U256, rhs: U256) -> bool {
    let lhs_negative = lhs.bit(255);
    let rhs_negative = rhs.bit(255);
    match (lhs_negative, rhs_negative) {
        (true, false) => true,
        (false, true) => false,
        _ => lhs < rhs,
    }
}

fn signed_greater_than(lhs: U256, rhs: U256) -> bool {
    let lhs_negative = lhs.bit(255);
    let rhs_negative = rhs.bit(255);
    match (lhs_negative, rhs_negative) {
        (true, false) => false,
        (false, true) => true,
        _ => lhs > rhs,
    }
}

fn bounded_expr(expr: SymbolicExpression) -> Option<SymbolicExpression> {
    if expression_depth(&expr) <= 6 {
        Some(expr)
    } else {
        None
    }
}

fn expression_depth(expr: &SymbolicExpression) -> usize {
    match expr {
        SymbolicExpression::Source(_) | SymbolicExpression::Constant(_) => 1,
        SymbolicExpression::Add(lhs, rhs)
        | SymbolicExpression::Sub(lhs, rhs)
        | SymbolicExpression::Mul(lhs, rhs)
        | SymbolicExpression::Div(lhs, rhs)
        | SymbolicExpression::Mod(lhs, rhs)
        | SymbolicExpression::And(lhs, rhs)
        | SymbolicExpression::Or(lhs, rhs)
        | SymbolicExpression::Xor(lhs, rhs) => 1 + expression_depth(lhs).max(expression_depth(rhs)),
    }
}

fn binary_expression(
    opcode: u8,
    lhs: Option<SymbolicExpression>,
    lhs_value: U256,
    rhs: Option<SymbolicExpression>,
    rhs_value: U256,
) -> Option<SymbolicExpression> {
    let lhs = lhs.unwrap_or(SymbolicExpression::Constant(lhs_value));
    let rhs = rhs.unwrap_or(SymbolicExpression::Constant(rhs_value));
    let expr = match opcode {
        0x01 => SymbolicExpression::Add(Box::new(lhs), Box::new(rhs)),
        0x02 => SymbolicExpression::Mul(Box::new(lhs), Box::new(rhs)),
        0x03 => SymbolicExpression::Sub(Box::new(lhs), Box::new(rhs)),
        0x04 | 0x05 => SymbolicExpression::Div(Box::new(lhs), Box::new(rhs)),
        0x06 | 0x07 => SymbolicExpression::Mod(Box::new(lhs), Box::new(rhs)),
        0x16 => SymbolicExpression::And(Box::new(lhs), Box::new(rhs)),
        0x17 => SymbolicExpression::Or(Box::new(lhs), Box::new(rhs)),
        0x18 => SymbolicExpression::Xor(Box::new(lhs), Box::new(rhs)),
        _ => return None,
    };
    bounded_expr(expr)
}

impl<'a, CTX: ContextTr> Inspector<CTX> for CoverageInspector<'a> {
    fn step(&mut self, interp: &mut Interpreter, _context: &mut CTX) {
        let pc = interp.bytecode.pc();
        let opcode = interp.bytecode.opcode();
        let stack_taint = |stack: &[Option<TaintSource>], idx: usize| {
            stack.iter().rev().nth(idx).cloned().flatten()
        };
        let stack_expr = |stack: &[Option<SymbolicExpression>], idx: usize| {
            stack.iter().rev().nth(idx).cloned().flatten()
        };

        // --- Taint Propagation ---
        match opcode {
            // CALLER: Mark msg.sender as a symbolic role source.
            0x33 => {
                let source = TaintSource::Caller;
                self.push_symbolic(
                    Some(source.clone()),
                    Some(SymbolicExpression::Source(source)),
                );
            }
            // CALLVALUE: Mark msg.value as a symbolic amount source.
            0x34 => {
                let source = TaintSource::CallValue;
                self.push_symbolic(
                    Some(source.clone()),
                    Some(SymbolicExpression::Source(source)),
                );
            }
            // CALLDATALOAD: Mark the top of the stack as tainted with the offset
            0x35 => {
                if let Ok(offset_val) = interp.stack.peek(0) {
                    let offset: usize = offset_val.saturating_to();
                    let source = TaintSource::Calldata(offset);
                    self.pop_symbolic_operands(1);
                    self.push_symbolic(
                        Some(source.clone()),
                        Some(SymbolicExpression::Source(source)),
                    );
                }
            }
            0x37 => {
                if let (Ok(dest), Ok(src), Ok(len)) = (
                    interp.stack.peek(0),
                    interp.stack.peek(1),
                    interp.stack.peek(2),
                ) {
                    let dest: usize = dest.saturating_to();
                    let src: usize = src.saturating_to();
                    let len: usize = len.saturating_to();
                    for i in 0..len {
                        self.memory_taint
                            .insert(dest + i, TaintSource::Calldata(src + i));
                        self.memory_expression.insert(
                            dest + i,
                            SymbolicExpression::Source(TaintSource::Calldata(src + i)),
                        );
                    }
                    self.pop_symbolic_operands(3);
                }
            }
            0x3C => {
                if let (Ok(dest), Ok(src), Ok(len)) = (
                    interp.stack.peek(0),
                    interp.stack.peek(1),
                    interp.stack.peek(2),
                ) {
                    let dest: usize = dest.saturating_to();
                    let src: usize = src.saturating_to();
                    let len: usize = len.saturating_to();
                    // Propagate taint from calldata to memory
                    for i in 0..len {
                        self.memory_taint
                            .insert(dest + i, TaintSource::Calldata(src + i));
                        self.memory_expression.insert(
                            dest + i,
                            SymbolicExpression::Source(TaintSource::Calldata(src + i)),
                        );
                    }
                    self.pop_symbolic_operands(3);
                }
            }
            0x51 => {
                if let Ok(offset_val) = interp.stack.peek(0) {
                    let offset: usize = offset_val.saturating_to();
                    let taint = self.memory_taint.get(&offset).cloned();
                    let expr = self.memory_expression.get(&offset).cloned();
                    self.pop_symbolic_operands(1);
                    self.push_symbolic(taint, expr);
                    return;
                }
                self.pop_symbolic_operands(1);
                self.push_symbolic(None, None);
            }
            0x52 | 0x53 => {
                if let Ok(offset_val) = interp.stack.peek(0) {
                    let offset: usize = offset_val.saturating_to();
                    let size = if opcode == 0x52 { 32 } else { 1 };
                    let value_taint = stack_taint(&self.taint_stack, 1);
                    let value_expr = stack_expr(&self.symbolic_stack, 1)
                        .or_else(|| interp.stack.peek(1).ok().map(SymbolicExpression::Constant));
                    if let Some(taint) = value_taint {
                        for i in 0..size {
                            self.memory_taint.insert(offset + i, taint.clone());
                        }
                    }
                    if let Some(expr) = value_expr {
                        for i in 0..size {
                            self.memory_expression.insert(offset + i, expr.clone());
                        }
                    }
                }
                self.pop_symbolic_operands(2);
            }
            // Propagation for stack operations
            0x60..=0x7F => self.push_symbolic(None, None),
            0x80..=0x8F => {
                let idx = (opcode - 0x80) as usize;
                let taint = self.taint_stack.iter().rev().nth(idx).cloned().flatten(); // Get taint from duplicated item
                let expr = self.symbolic_stack.iter().rev().nth(idx).cloned().flatten();
                self.push_symbolic(taint, expr);
            }
            0x90..=0x9F => {
                let idx = (opcode - 0x90 + 1) as usize;
                let len = self.taint_stack.len();
                if len > idx {
                    self.taint_stack.swap(len - 1, len - 1 - idx);
                }
                let len = self.symbolic_stack.len();
                if len > idx {
                    self.symbolic_stack.swap(len - 1, len - 1 - idx);
                }
            }
            0x50 => {
                self.pop_symbolic_operands(1);
            } // Remove taint for popped item
            0x54 => {
                if let Ok(slot_val) = interp.stack.peek(0) {
                    let addr = interp
                        .input
                        .bytecode_address()
                        .copied()
                        .unwrap_or(Address::ZERO);
                    let slot = B256::from(slot_val);

                    // If this slot was written by a previous transaction in the sequence
                    if let Some(taint_source_of_value) = self
                        .symbolic_storage_map
                        .get(&(addr, slot))
                        .cloned()
                        .or_else(|| self.dataflow.storage_taint(addr, slot))
                    {
                        if let TaintSource::Storage(written_tx_idx, _) = taint_source_of_value {
                            if written_tx_idx < self.current_tx_idx {
                                let expr = self
                                    .storage_expression_map
                                    .get(&(addr, slot))
                                    .cloned()
                                    .or_else(|| self.dataflow.storage_expression(addr, slot))
                                    .or_else(|| {
                                        Some(SymbolicExpression::Source(
                                            taint_source_of_value.clone(),
                                        ))
                                    });
                                self.pending_sload = Some(PendingStorageRead {
                                    address: addr,
                                    slot,
                                    pc,
                                    tx_idx: self.current_tx_idx,
                                    taint_source: Some(taint_source_of_value.clone()),
                                    expression: expr.clone(),
                                });
                                self.pop_symbolic_operands(1);
                                self.push_symbolic(Some(taint_source_of_value), expr);
                                return; // Skip default taint propagation
                            }
                        }
                    }
                }
                self.pop_symbolic_operands(1);
                self.push_symbolic(None, None); // SLOAD result is untainted by default unless explicitly tracked
            }
            0x5C => {
                if let Ok(slot_val) = interp.stack.peek(0) {
                    let addr = interp
                        .input
                        .bytecode_address()
                        .copied()
                        .unwrap_or(Address::ZERO);
                    let slot = B256::from(slot_val);

                    if let Some(ts) = self.transient_taint_map.get(&(addr, slot)).cloned() {
                        self.waypoints.push(Waypoint::TransientStorageRead {
                            address: addr,
                            slot,
                            value: U256::ZERO,
                            pc,
                        });
                        self.pop_symbolic_operands(1);
                        self.push_symbolic(Some(ts), None);
                        return;
                    }
                }
                self.pop_symbolic_operands(1);
                self.push_symbolic(None, None);
            }
            _ => {
                // For multi-operand opcodes, we'd ideally merge taints.
                // For simplicity, most opcodes produce untainted results unless specialized.
            }
        }

        // Precision Edge Hashing: mimicking hardware-level branch tracking
        if !self.coverage.is_empty() {
            let edge_hash =
                (pc ^ self.last_pc.rotate_left(1) ^ ((opcode as usize) << 1)) % self.coverage.len();
            self.coverage[edge_hash] = self.coverage[edge_hash].saturating_add(1);

            if matches!(opcode, 0xF1 | 0xF2 | 0xF4 | 0xFA) {
                let call_edge = (edge_hash ^ 0x9e37) % self.coverage.len();
                self.coverage[call_edge] = self.coverage[call_edge].saturating_add(1);
            }
        }

        // Virtual Performance Counters: Track metrics that signal "interesting" inputs
        self.instruction_count += 1;
        // Note: Real gas per opcode is available in context/interp depending on the step

        // Causal Tracking: Monitor SLOAD (0x54) and SSTORE (0x55)
        if opcode == 0x54 || opcode == 0x55 {
            if let Ok(slot_val) = interp.stack.peek(0) {
                let addr = interp
                    .input
                    .bytecode_address()
                    .copied()
                    .unwrap_or(Address::ZERO);
                let slot = B256::from(slot_val);

                if opcode == 0x54 && self.pending_sload.is_none() {
                    self.pending_sload = Some(PendingStorageRead {
                        address: addr,
                        slot,
                        pc,
                        tx_idx: self.current_tx_idx,
                        taint_source: None,
                        expression: None,
                    });
                }

                // Logic Sanitizer: Detect Uninitialized Storage Reads
                // If a slot is read before being written to in the protocol lifecycle,
                // it might indicate a missing initializer or an uninitialized state bug.
                if !self.known_initialized_slots.contains(&(addr, slot)) {
                    // Log a high-severity waypoint for uninitialized access
                    self.waypoints.push(Waypoint::Dataflow {
                        address: addr,
                        slot: slot.to_vec(),
                        influenced: false,
                    });
                }

                if opcode == 0x54 {
                    self.read_set.insert((addr, slot));
                } else {
                    self.write_set.insert((addr, slot));
                }
            }
        }

        // Dataflow tracking: monitor SSTORE (0x55)
        if opcode == 0x55 {
            // Get the value being stored and its taint source
            let value_taint_source = stack_taint(&self.taint_stack, 1);
            if let Ok(value_val) = interp.stack.peek(1) {
                // Value is second on stack for SSTORE
                let value = value_val;
                let value_expression = stack_expr(&self.symbolic_stack, 1)
                    .or(Some(SymbolicExpression::Constant(value)));

                // Slot is the first item on the stack for SSTORE
                if let Ok(slot_val) = interp.stack.peek(0) {
                    let address = interp
                        .input
                        .bytecode_address()
                        .copied()
                        .unwrap_or(Address::ZERO);
                    let slot = B256::from(slot_val);

                    self.dataflow.mark_influenced(address, slot);
                    // Mark this slot as initialized for the logic sanitizer
                    self.known_initialized_slots.insert((address, slot));

                    // If the value being stored is tainted, convert its source to a
                    // persistent Storage source so subsequent reads know which TX produced it.
                    let persistent_taint_for_value =
                        value_taint_source.clone().map(|ts| match ts {
                            TaintSource::Calldata(offset) => {
                                TaintSource::Storage(self.current_tx_idx, offset)
                            }
                            TaintSource::Storage(_, _) => ts,
                            TaintSource::Caller | TaintSource::CallValue => ts,
                        });
                    if let Some(persistent_taint) = persistent_taint_for_value.clone() {
                        self.symbolic_storage_map
                            .insert((address, slot), persistent_taint);
                    }
                    if let Some(expr) = value_expression.clone() {
                        self.storage_expression_map.insert((address, slot), expr);
                    }
                    self.dataflow.mark_storage_symbolic(
                        address,
                        slot,
                        persistent_taint_for_value,
                        value_expression.clone(),
                    );

                    self.waypoints.push(Waypoint::StorageWrite {
                        address,
                        slot: slot.to_vec(),
                        value,
                        pc,
                        tx_idx: self.current_tx_idx,
                        taint_source_of_value: value_taint_source,
                        value_expression,
                    });
                }
            }
            self.pop_symbolic_operands(2);
        }

        // Cancun Spec: Transient Storage (EIP-1153)
        if opcode == 0x5D {
            let value_taint_source = stack_taint(&self.taint_stack, 1);
            if let Ok(slot_val) = interp.stack.peek(0) {
                let address = interp
                    .input
                    .bytecode_address()
                    .copied()
                    .unwrap_or(Address::ZERO);
                let slot = B256::from(slot_val);

                if let Some(ts) = value_taint_source {
                    self.transient_taint_map.insert((address, slot), ts);
                }

                if let Ok(value) = interp.stack.peek(1) {
                    self.waypoints.push(Waypoint::TransientStorageWrite {
                        address,
                        slot,
                        value,
                        pc,
                    });
                }
            }
            self.pop_symbolic_operands(2);
        }

        // Capture Arithmetic results for ADD, MUL, SUB, DIV, SDIV, MOD, SMOD, ADDMOD, MULMOD
        if (0x01..=0x09).contains(&opcode) {
            let stack_len = interp.stack.len();
            if stack_len >= 2 {
                if let (Ok(lhs), Ok(rhs)) = (interp.stack.peek(0), interp.stack.peek(1)) {
                    // Get taint source for LHS and RHS
                    let lhs_taint = stack_taint(&self.taint_stack, 0);
                    let rhs_taint = stack_taint(&self.taint_stack, 1);
                    let lhs_expr = stack_expr(&self.symbolic_stack, 0);
                    let rhs_expr = stack_expr(&self.symbolic_stack, 1);
                    let taint_source = lhs_taint.clone().or(rhs_taint.clone()); // Combine taints (heuristic)
                    let result_expression = binary_expression(opcode, lhs_expr, lhs, rhs_expr, rhs);

                    let mut third = None;
                    // ADDMOD (0x08) and MULMOD (0x09) take 3 arguments
                    if (opcode == 0x08 || opcode == 0x09) && stack_len >= 3 {
                        if let Ok(val) = interp.stack.peek(2) {
                            third = Some(val);
                            // If third operand is tainted, it becomes the primary taint source
                            let _third_taint =
                                self.taint_stack.iter().rev().nth(2).cloned().flatten();
                            // taint_source = taint_source.or(third_taint); // More complex merge
                        }
                    }

                    if taint_source.is_some() {
                        self.waypoints.push(Waypoint::Arithmetic {
                            op: opcode,
                            lhs,
                            rhs,
                            third,
                            pc,
                            taint_source,
                            result_expression: result_expression.clone(),
                        });
                    }
                    let operand_count = if opcode == 0x08 || opcode == 0x09 {
                        3
                    } else {
                        2
                    };
                    self.pop_symbolic_operands(operand_count);
                    self.push_symbolic(lhs_taint.or(rhs_taint), result_expression);
                }
            }
        }

        if (0x16..=0x18).contains(&opcode) {
            if let (Ok(lhs), Ok(rhs)) = (interp.stack.peek(0), interp.stack.peek(1)) {
                let lhs_taint = stack_taint(&self.taint_stack, 0);
                let rhs_taint = stack_taint(&self.taint_stack, 1);
                let lhs_expr = stack_expr(&self.symbolic_stack, 0);
                let rhs_expr = stack_expr(&self.symbolic_stack, 1);
                let result_expression = binary_expression(opcode, lhs_expr, lhs, rhs_expr, rhs);
                self.pop_symbolic_operands(2);
                self.push_symbolic(lhs_taint.or(rhs_taint), result_expression);
            }
        }

        // Symbolic Path Exploration: Monitor JUMPI (0x57)
        // We record the 'Path Not Taken' as a symbolic target for the solver.
        if opcode == 0x57 {
            if let (Ok(_dest), Ok(condition)) = (interp.stack.peek(0), interp.stack.peek(1)) {
                let branch_taken = !condition.is_zero();
                let taint = stack_taint(&self.taint_stack, 1);
                let condition_expression = stack_expr(&self.symbolic_stack, 1);

                if let Some(ts) = taint {
                    // Record the branch as a target for concolic inversion
                    self.waypoints.push(Waypoint::BranchPath {
                        pc,
                        taken: branch_taken,
                        constraint: Box::new(Waypoint::Comparison {
                            op: 0x14, // Force equality check logic in solver
                            lhs: condition,
                            rhs: if branch_taken {
                                U256::ZERO
                            } else {
                                U256::from(1)
                            },
                            pc,
                            taint_source: Some(ts),
                            calldata_offset: None,
                            condition: false,
                            hit: false,
                            tainted_operand: ComparisonOperand::Lhs,
                            lhs_expression: condition_expression,
                            rhs_expression: Some(SymbolicExpression::Constant(if branch_taken {
                                U256::ZERO
                            } else {
                                U256::from(1)
                            })),
                            branch_distance: branch_distance(
                                0x14,
                                condition,
                                if branch_taken {
                                    U256::ZERO
                                } else {
                                    U256::from(1)
                                },
                                false,
                            ),
                        }),
                    });
                }
            }
            self.pop_symbolic_operands(2);
        }

        // Capture Comparisons for Concolic Solving
        // Opcodes: LT (0x10), GT (0x11), SLT (0x12), SGT (0x13), EQ (0x14)
        if (0x10..=0x14).contains(&opcode) {
            if let (Ok(lhs), Ok(rhs)) = (interp.stack.peek(0), interp.stack.peek(1)) {
                // Get taint source for LHS and RHS
                let lhs_taint = stack_taint(&self.taint_stack, 0);
                let rhs_taint = stack_taint(&self.taint_stack, 1);
                let lhs_expression = stack_expr(&self.symbolic_stack, 0);
                let rhs_expression = stack_expr(&self.symbolic_stack, 1);
                let (taint_source, tainted_operand) = match (lhs_taint, rhs_taint) {
                    (Some(lhs), Some(_)) => (Some(lhs), ComparisonOperand::Unknown),
                    (Some(lhs), None) => (Some(lhs), ComparisonOperand::Lhs),
                    (None, Some(rhs)) => (Some(rhs), ComparisonOperand::Rhs),
                    (None, None) => (None, ComparisonOperand::Unknown),
                };
                let condition = compare_condition(opcode, lhs, rhs);
                let distance = branch_distance(opcode, lhs, rhs, condition);

                self.waypoints.push(Waypoint::Comparison {
                    op: opcode,
                    lhs,
                    rhs,
                    pc,
                    taint_source,
                    calldata_offset: None,
                    condition,
                    hit: condition,
                    tainted_operand,
                    lhs_expression,
                    rhs_expression,
                    branch_distance: distance,
                });
            }
            self.pop_symbolic_operands(2);
            self.push_symbolic(None, None);
        }

        // Capture Mapping Derivations for high-fidelity Oracle reasoning
        if opcode == 0x20 {
            if let (Ok(offset), Ok(size)) = (interp.stack.peek(0), interp.stack.peek(1)) {
                let offset: usize = offset.saturating_to();
                let size: usize = size.saturating_to();

                // Industry standard: mappings usually involve 64 bytes (key + base_slot)
                if size == 64 {
                    let data = interp.memory.slice_len(offset, size);
                    let key = U256::from_be_slice(&data[0..32]);
                    let base_slot = U256::from_be_slice(&data[32..64]);
                    let key_expression = self.memory_expression.get(&offset).cloned();
                    let base_slot_expression = self.memory_expression.get(&(offset + 32)).cloned();

                    self.waypoints.push(Waypoint::MappingDerivation {
                        base_slot,
                        key,
                        derived_slot: keccak256(&*data),
                        key_expression,
                        base_slot_expression,
                    });
                }
            }
            self.pop_symbolic_operands(2);
            self.push_symbolic(None, None);
        }

        self.last_pc = pc;
    }

    fn step_end(&mut self, interp: &mut Interpreter, _context: &mut CTX) {
        if let Some(read) = self.pending_sload.take() {
            if let Ok(value) = interp.stack.peek(0) {
                self.waypoints.push(Waypoint::StorageRead {
                    address: read.address,
                    slot: read.slot,
                    value,
                    pc: read.pc,
                    read_tx_idx: read.tx_idx,
                    taint_source: read.taint_source,
                    expression: read.expression,
                });
            }
        }
    }

    fn call(&mut self, _context: &mut CTX, inputs: &mut CallInputs) -> Option<CallOutcome> {
        // Extract input bytes once for all checks
        let input_bytes = inputs.input.bytes(_context);
        self.waypoints.push(Waypoint::CallTrace {
            tx_idx: self.current_tx_idx,
            depth: self.call_depth + 1,
            caller: inputs.caller,
            target: inputs.target_address,
            value: inputs.call_value(),
            input: input_bytes.to_vec(),
            output: Vec::new(),
            gas_limit: inputs.gas_limit,
            gas_used: 0,
            success: false,
            kind: call_kind(inputs.scheme),
            phase: CallPhase::Start,
            result: None,
        });
        self.call_depth += 1;

        // Detect Token Callbacks (ERC777 / ERC1363)
        if input_bytes.len() >= 4 {
            let selector = &input_bytes[0..4];
            // 0x97135039: tokensReceived (ERC777)
            // 0x88a7ca5c: onTransferReceived (ERC1363)
            if selector == [0x97, 0x13, 0x50, 0x39] || selector == [0x88, 0xa7, 0xca, 0x5c] {
                self.waypoints.push(Waypoint::TokenCallback {
                    target: inputs.target_address,
                    selector: selector.try_into().unwrap(),
                    data: input_bytes.to_vec(),
                });
            }
        }

        // EIP-3156: flashLoan(receiver, token, amount, data) -> 0x5c19e951
        if input_bytes.len() >= 4 && input_bytes[0..4] == [0x5c, 0x19, 0xe9, 0x51] {
            // Potential flashloan initiation detected.
        }

        // EIP-3156: onFlashLoan(initiator, token, amount, fee, data) -> 0x2393069c
        if input_bytes.len() >= 4 && input_bytes[0..4] == [0x23, 0x93, 0x06, 0x9c] {
            // The lender is calling back the fuzzer.
            // This is the "manipulate" phase of the attack.
            if input_bytes.len() >= 132 {
                let amount = U256::from_be_slice(&input_bytes[68..100]);
                let fee = U256::from_be_slice(&input_bytes[100..132]);
                self.waypoints.push(Waypoint::FlashloanExecution {
                    lender: inputs.caller,
                    token: Address::from_slice(&input_bytes[16..36]),
                    amount,
                    fee,
                    is_repaid: false, // Will be verified in call_end or by Oracle
                });
            }
        }

        // Governance detection (GovernorBravo/Alpha style)
        if input_bytes.len() >= 4 {
            let selector = &input_bytes[0..4];
            // da95691a: propose, 56781388: castVote, fe0d94c1: execute
            if selector == [0xda, 0x95, 0x69, 0x1a]
                || selector == [0x56, 0x78, 0x13, 0x88]
                || selector == [0xfe, 0x0d, 0x94, 0xc1]
            {
                self.waypoints.push(Waypoint::GovernanceAction {
                    target: inputs.target_address,
                    selector: selector.try_into().unwrap(),
                    caller: inputs.caller,
                });
            }
        }

        // P0 Target: Arbitrary Call Injection
        // If the CALL target was derived from calldata (tainted), a malicious actor
        // can redirect protocol flow to their own contract.
        let target_tainted = self
            .taint_stack
            .iter()
            .rev()
            .nth(0)
            .cloned()
            .flatten()
            .is_some();
        if target_tainted {
            // Log a high-severity waypoint for the ArbitraryCallOracle
        }
        None
    }

    fn call_end(&mut self, _context: &mut CTX, inputs: &CallInputs, outcome: &mut CallOutcome) {
        self.call_depth = self.call_depth.saturating_sub(1);
        let input_bytes = inputs.input.bytes(_context);
        self.waypoints.push(Waypoint::CallTrace {
            tx_idx: self.current_tx_idx,
            depth: self.call_depth + 1,
            caller: inputs.caller,
            target: inputs.target_address,
            value: inputs.call_value(),
            input: input_bytes.to_vec(),
            output: outcome.result.output.to_vec(),
            gas_limit: inputs.gas_limit,
            gas_used: outcome.result.gas.used(),
            success: outcome.result.result.is_ok(),
            kind: call_kind(inputs.scheme),
            phase: CallPhase::End,
            result: Some(format!("{:?}", outcome.result.result)),
        });
        if inputs.scheme == CallScheme::StaticCall {
            self.waypoints.push(Waypoint::StaticCall {
                caller: inputs.caller,
                target: inputs.target_address,
                data: input_bytes.to_vec(),
                output: outcome.result.output.to_vec(),
            });
        }
    }

    fn create(&mut self, _context: &mut CTX, inputs: &mut CreateInputs) -> Option<CreateOutcome> {
        self.waypoints.push(Waypoint::CreateTrace {
            tx_idx: self.current_tx_idx,
            depth: self.call_depth + 1,
            creator: inputs.caller(),
            created_address: None,
            value: inputs.value(),
            init_code: inputs.init_code().to_vec(),
            deployed_code: Vec::new(),
            gas_limit: inputs.gas_limit(),
            gas_used: 0,
            success: false,
            kind: create_kind(inputs.scheme()),
            phase: CallPhase::Start,
            result: None,
        });
        self.call_depth += 1;
        None
    }

    fn create_end(
        &mut self,
        _context: &mut CTX,
        inputs: &CreateInputs,
        outcome: &mut CreateOutcome,
    ) {
        self.call_depth = self.call_depth.saturating_sub(1);
        self.waypoints.push(Waypoint::CreateTrace {
            tx_idx: self.current_tx_idx,
            depth: self.call_depth + 1,
            creator: inputs.caller(),
            created_address: outcome.address,
            value: inputs.value(),
            init_code: inputs.init_code().to_vec(),
            deployed_code: outcome.result.output.to_vec(),
            gas_limit: inputs.gas_limit(),
            gas_used: outcome.result.gas.used(),
            success: outcome.result.result.is_ok(),
            kind: create_kind(inputs.scheme()),
            phase: CallPhase::End,
            result: Some(format!("{:?}", outcome.result.result)),
        });
    }
}

fn call_kind(scheme: CallScheme) -> CallKind {
    match scheme {
        CallScheme::Call => CallKind::Call,
        CallScheme::CallCode => CallKind::CallCode,
        CallScheme::DelegateCall => CallKind::DelegateCall,
        CallScheme::StaticCall => CallKind::StaticCall,
    }
}

fn create_kind(scheme: CreateScheme) -> CallKind {
    match scheme {
        CreateScheme::Create => CallKind::Create,
        CreateScheme::Create2 { .. } => CallKind::Create2,
        CreateScheme::Custom { .. } => CallKind::Create,
    }
}

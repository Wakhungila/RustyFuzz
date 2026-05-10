use revm::{
    interpreter::{CallInputs, CallOutcome, CallScheme, Interpreter, interpreter_types::{Jumps, InputsTr, MemoryTr}},
    Database, Inspector,
};
// v38: OpCode is now in the bytecode module or directly available
// use revm::bytecode::Bytecode; // Unused
// use bitvec::prelude::{BitSlice, Lsb0}; // Unused
use crate::common::types::{TaintSource, Waypoint};
use crate::evm::dataflow::DataflowRegistry;
use revm::primitives::{keccak256, Address, B256, U256};
use std::collections::{HashMap, HashSet};

/// Industry standard: Use a fixed-size map for coverage to allow
/// JIT-like performance and SIMD-optimized comparisons in the feedback loop.
pub const MAP_SIZE: usize = 262144; // Increased to 256KB to reduce collisions (Honggfuzz-style precision)

#[derive(Debug)]
pub struct CoverageInspector<'a> {
    pub coverage: &'a mut [u8], // Move to hitcounts
    pub dataflow: &'a mut DataflowRegistry,
    pub waypoints: &'a mut Vec<Waypoint>,
    pub taint_stack: Vec<Option<TaintSource>>, // Mirror stack: stores taint source
    pub read_set: HashSet<(Address, B256)>,
    pub write_set: HashSet<(Address, B256)>,
    pub last_pc: usize,
    pub current_tx_idx: usize, // Index of the current transaction in the sequence
    pub instruction_count: u64, // Virtual Performance Counter: total instructions
    pub gas_consumed: u64,         // Virtual Performance Counter: total gas
    pub symbolic_storage_map: HashMap<(Address, B256), TaintSource>, // (addr, slot) -> TaintSource of value
    pub transient_taint_map: HashMap<(Address, B256), TaintSource>, // EIP-1153 support
    pub memory_taint: HashMap<usize, TaintSource>, // offset -> TaintSource
    pub known_initialized_slots: HashSet<(Address, B256)>, // Track slots written in current or previous TXs
}

impl<'a> CoverageInspector<'a> {
    pub fn new(
        coverage: &'a mut [u8],
        dataflow: &'a mut DataflowRegistry,
        waypoints: &'a mut Vec<Waypoint>,
        current_tx_idx: usize,
    ) -> Self {
        Self { 
            coverage, dataflow, waypoints,
            taint_stack: Vec::with_capacity(1024), // Max stack depth
            read_set: HashSet::new(), write_set: HashSet::new(),
            last_pc: 0,
            current_tx_idx,
            instruction_count: 0,
            gas_consumed: 0,
            symbolic_storage_map: HashMap::new(),
            transient_taint_map: HashMap::new(),
            memory_taint: HashMap::new(),
            known_initialized_slots: HashSet::new(),
        }
    }
}

impl<'a, DB: Database> Inspector<DB> for CoverageInspector<'a> {
    fn step(&mut self, interp: &mut Interpreter, _context: &mut DB) {
        let pc = interp.bytecode.pc();
        let opcode = interp.bytecode.opcode();

        // --- Taint Propagation ---
        match opcode {
            // CALLDATALOAD: Mark the top of the stack as tainted with the offset
            0x35 => {
                if let Ok(offset_val) = interp.stack.peek(0) {
                    let offset: usize = offset_val.saturating_to();
                    self.taint_stack.push(Some(TaintSource::Calldata(offset)));
                }
            }
            0x3C => {
                if let (Ok(dest), Ok(src), Ok(len)) = (interp.stack.peek(0), interp.stack.peek(1), interp.stack.peek(2)) {
                    let dest: usize = dest.saturating_to();
                    let src: usize = src.saturating_to();
                    let len: usize = len.saturating_to();
                    // Propagate taint from calldata to memory
                    for i in 0..len {
                        self.memory_taint.insert(dest + i, TaintSource::Calldata(src + i));
                    }
                }
            }
            0x51 => {
                if let Ok(offset_val) = interp.stack.peek(0) {
                    let offset: usize = offset_val.saturating_to();
                    let taint = self.memory_taint.get(&offset).cloned();
                    self.taint_stack.push(taint);
                    return;
                }
                self.taint_stack.push(None);
            }
            0x52 | 0x53 => {
                if let (Ok(offset_val), Some(taint)) = (interp.stack.peek(0), self.taint_stack.last().cloned().flatten()) {
                    let offset: usize = offset_val.saturating_to();
                    let size = if opcode == 0x52 { 32 } else { 1 };
                    for i in 0..size {
                        self.memory_taint.insert(offset + i, taint.clone());
                    }
                }
            }
            // Propagation for stack operations
            0x60..=0x7F => self.taint_stack.push(None),
            0x80..=0x8F => {
                let idx = (opcode - 0x80) as usize;
                let taint = self.taint_stack.iter().rev().nth(idx).cloned().flatten(); // Get taint from duplicated item
                self.taint_stack.push(taint);
            }
            0x90..=0x9F => {
                let idx = (opcode - 0x90 + 1) as usize;
                let len = self.taint_stack.len();
                if len > idx {
                    self.taint_stack.swap(len - 1, len - 1 - idx);
                }
            }
            0x50 => { self.taint_stack.pop(); } // Remove taint for popped item
            0x54 => {
                if let Ok(slot_val) = interp.stack.peek(0) {
                    let addr = interp.input.bytecode_address().copied().unwrap_or(Address::ZERO);
                    let slot = B256::from(slot_val);
                    
                    // If this slot was written by a previous transaction in the sequence
                    if let Some(taint_source_of_value) = self.symbolic_storage_map.get(&(addr, slot)).cloned() {
                        if let TaintSource::Storage(written_tx_idx, _) = taint_source_of_value {
                            if written_tx_idx < self.current_tx_idx {
                                self.waypoints.push(Waypoint::StorageRead {
                                    address: addr, slot, value: U256::ZERO, // Value will be known after SLOAD
                                    pc, read_tx_idx: self.current_tx_idx, taint_source: Some(taint_source_of_value.clone()),
                                });
                                self.taint_stack.push(Some(taint_source_of_value)); // Propagate taint from storage read
                                return; // Skip default taint propagation
                            }
                        }
                    }
                }
                self.taint_stack.push(None); // SLOAD result is untainted by default unless explicitly tracked
            }
            0x5C => {
                if let Ok(slot_val) = interp.stack.peek(0) {
                    let addr = interp.input.bytecode_address().copied().unwrap_or(Address::ZERO);
                    let slot = B256::from(slot_val);
                    
                    if let Some(ts) = self.transient_taint_map.get(&(addr, slot)).cloned() {
                        self.waypoints.push(Waypoint::TransientStorageRead {
                            address: addr, slot, value: U256::ZERO, pc,
                        });
                        self.taint_stack.push(Some(ts));
                        return;
                    }
                }
                self.taint_stack.push(None);
            }
            _ => {
                // For multi-operand opcodes, we'd ideally merge taints.
                // For simplicity, most opcodes produce untainted results unless specialized.
            }
        }

        // Precision Edge Hashing: mimicking hardware-level branch tracking
        if opcode == 0xF1 || opcode == 0xF2 || opcode == 0xF4 || opcode == 0xFA {
            let edge_hash = (pc ^ (self.last_pc.rotate_left(1))) % MAP_SIZE;
            self.coverage[edge_hash] = self.coverage[edge_hash].saturating_add(1);
        }

        // Virtual Performance Counters: Track metrics that signal "interesting" inputs
        self.instruction_count += 1;
        // Note: Real gas per opcode is available in context/interp depending on the step

        // Causal Tracking: Monitor SLOAD (0x54) and SSTORE (0x55)
        if opcode == 0x54 || opcode == 0x55 {
            if let Ok(slot_val) = interp.stack.peek(0) {
                let addr = interp.input.bytecode_address().copied().unwrap_or(Address::ZERO);
                let slot = B256::from(slot_val);

                // Logic Sanitizer: Detect Uninitialized Storage Reads
                // If a slot is read before being written to in the protocol lifecycle,
                // it might indicate a missing initializer or an uninitialized state bug.
                if !self.known_initialized_slots.contains(&(addr, slot)) {
                    // Log a high-severity waypoint for uninitialized access
                    self.waypoints.push(Waypoint::Dataflow { address: addr, slot: slot.to_vec(), influenced: false });
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
            let value_taint_source = self.taint_stack.last().cloned().flatten();
            if let Ok(value_val) = interp.stack.peek(1) { // Value is second on stack for SSTORE
                let value = value_val;

            // Slot is the first item on the stack for SSTORE
            if let Ok(slot_val) = interp.stack.peek(0) {
                let address = interp.input.bytecode_address().copied().unwrap_or(Address::ZERO);
                let slot = B256::from(slot_val);

                self.dataflow.mark_influenced(address, slot);
                // Mark this slot as initialized for the logic sanitizer
                self.known_initialized_slots.insert((address, slot));

                // If the value being stored is tainted, convert its source to a 
                // persistent Storage source so subsequent reads know which TX produced it.
                if let Some(ts) = value_taint_source.clone() {
                    let persistent_taint = match ts {
                        TaintSource::Calldata(offset) => TaintSource::Storage(self.current_tx_idx, offset),
                        TaintSource::Storage(_, _) => ts,
                    };
                    self.symbolic_storage_map.insert((address, slot), persistent_taint);
                }

                self.waypoints.push(Waypoint::StorageWrite {
                    address,
                    slot: slot.to_vec(),
                    value,
                    pc,
                    tx_idx: self.current_tx_idx,
                    taint_source_of_value: value_taint_source,
                });
            }
            }
        }

        // Cancun Spec: Transient Storage (EIP-1153)
        if opcode == 0x5D {
            let value_taint_source = self.taint_stack.last().cloned().flatten();
            if let Ok(slot_val) = interp.stack.peek(0) {
                let address = interp.input.bytecode_address().copied().unwrap_or(Address::ZERO);
                let slot = B256::from(slot_val);
                
                if let Some(ts) = value_taint_source {
                    self.transient_taint_map.insert((address, slot), ts);
                }
                
                if let Ok(value) = interp.stack.peek(1) {
                    self.waypoints.push(Waypoint::TransientStorageWrite {
                        address, slot, value, pc,
                    });
                }
            }
        }

        // Capture Arithmetic results for ADD, MUL, SUB, DIV, SDIV, MOD, SMOD, ADDMOD, MULMOD
        if opcode >= 0x01 && opcode <= 0x09 {
            let stack_len = interp.stack.len();
            if stack_len >= 2 {
                if let (Ok(lhs), Ok(rhs)) = (interp.stack.peek(0), interp.stack.peek(1)) {
                    // Get taint source for LHS and RHS
                    let lhs_taint = self.taint_stack.iter().rev().nth(0).cloned().flatten();
                    let rhs_taint = self.taint_stack.iter().rev().nth(1).cloned().flatten();
                    let taint_source = lhs_taint.or(rhs_taint); // Combine taints (heuristic)
                    
                    let mut third = None;
                    // ADDMOD (0x08) and MULMOD (0x09) take 3 arguments
                    if (opcode == 0x08 || opcode == 0x09) && stack_len >= 3 {
                        if let Ok(val) = interp.stack.peek(2) {
                            third = Some(val);
                            // If third operand is tainted, it becomes the primary taint source
                            let third_taint = self.taint_stack.iter().rev().nth(2).cloned().flatten();
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
                        });
                    }
                }
            }
        }

        // Symbolic Path Exploration: Monitor JUMPI (0x57)
        // We record the 'Path Not Taken' as a symbolic target for the solver.
        if opcode == 0x57 {
            if let (Ok(dest), Ok(condition)) = (interp.stack.peek(0), interp.stack.peek(1)) {
                let branch_taken = !condition.is_zero();
                let taint = self.taint_stack.iter().rev().nth(1).cloned().flatten();
                
                if let Some(ts) = taint {
                    // Record the branch as a target for concolic inversion
                    self.waypoints.push(Waypoint::BranchPath {
                        pc,
                        taken: branch_taken,
                        constraint: Box::new(Waypoint::Comparison {
                            op: 0x14, // Force equality check logic in solver
                            lhs: condition,
                            rhs: if branch_taken { U256::ZERO } else { U256::from(1) },
                            pc,
                            taint_source: Some(ts),
                            calldata_offset: None,
                            condition: false,
                            hit: false,
                        }),
                    });
                }
            }
        }

        // Capture Comparisons for Concolic Solving
        // Opcodes: LT (0x10), GT (0x11), SLT (0x12), SGT (0x13), EQ (0x14)
        if opcode >= 0x10 && opcode <= 0x14 {
            if let (Ok(lhs), Ok(rhs)) = (interp.stack.peek(0), interp.stack.peek(1)) {
                // Get taint source for LHS and RHS
                let lhs_taint = self.taint_stack.iter().rev().nth(0).cloned().flatten();
                let rhs_taint = self.taint_stack.iter().rev().nth(1).cloned().flatten();
                let taint_source = lhs_taint.or(rhs_taint); // Combine taints (heuristic)

                self.waypoints.push(Waypoint::Comparison {
                    op: opcode,
                    lhs,
                    rhs,
                    pc,
                    taint_source,
                    calldata_offset: None,
                    condition: false,
                    hit: false,
                });
            }
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
                    
                    self.waypoints.push(Waypoint::MappingDerivation {
                        base_slot,
                        key,
                        derived_slot: keccak256(&*data),
                    });
                }
            }
        }

        self.last_pc = pc;
    }

    fn call(&mut self, _context: &mut DB, inputs: &mut CallInputs) -> Option<CallOutcome> {
        // Extract input bytes once for all checks
        let input_bytes = match &inputs.input {
            revm::interpreter::CallInput::Bytes(b) => b.clone(),
            revm::interpreter::CallInput::SharedBuffer(_) => {
                // Can't access shared buffer without context, skip for now
                return None;
            }
        };
        
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
        if input_bytes.len() >= 4 && &input_bytes[0..4] == &[0x5c, 0x19, 0xe9, 0x51] {
             // Potential flashloan initiation detected.
        }

        // EIP-3156: onFlashLoan(initiator, token, amount, fee, data) -> 0x2393069c
        if input_bytes.len() >= 4 && &input_bytes[0..4] == &[0x23, 0x93, 0x06, 0x9c] {
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
            if selector == [0xda, 0x95, 0x69, 0x1a] || 
               selector == [0x56, 0x78, 0x13, 0x88] || 
               selector == [0xfe, 0x0d, 0x94, 0xc1] 
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
        let target_tainted = self.taint_stack.iter().rev().nth(0).cloned().flatten().is_some();
        if target_tainted {
            // Log a high-severity waypoint for the ArbitraryCallOracle
        }
        None
    }

    fn call_end(
        &mut self,
        _context: &mut DB,
        inputs: &CallInputs,
        outcome: &mut CallOutcome,
    ) {
        if inputs.scheme == CallScheme::StaticCall {
            let input_bytes = match &inputs.input {
                revm::interpreter::CallInput::Bytes(b) => b.clone(),
                revm::interpreter::CallInput::SharedBuffer(_) => {
                    // Can't access without context
                    return;
                }
            };
            self.waypoints.push(Waypoint::StaticCall {
                caller: inputs.caller,
                target: inputs.target_address,
                data: input_bytes.to_vec(),
                output: outcome.result.output.to_vec(),
            });
        }
    }
}
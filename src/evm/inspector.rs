use revm::{
    interpreter::{Interpreter, CallInputs, CallOutcome, CallScheme, opcode},
    Database, Inspector, EvmContext,
};
use bitvec::prelude::{BitSlice, Lsb0};
use crate::evm::dataflow::DataflowRegistry;
use crate::common::types::{Waypoint, TaintSource};
use revm::primitives::{U256, B256, Address};
use std::collections::{HashSet, HashMap};

/// Industry standard: Use a fixed-size map for coverage to allow
/// JIT-like performance and SIMD-optimized comparisons in the feedback loop.
pub const MAP_SIZE: usize = 65536;

#[derive(Debug)]
pub struct CoverageInspector<'a> {
    pub coverage: &'a mut BitSlice<u8, Lsb0>,
    pub dataflow: &'a mut DataflowRegistry,
    pub waypoints: &'a mut Vec<Waypoint>,
    pub taint_stack: Vec<Option<TaintSource>>, // Mirror stack: stores taint source
    pub read_set: HashSet<(Address, B256)>,
    pub write_set: HashSet<(Address, B256)>,
    pub last_pc: usize,
    pub current_tx_idx: usize, // Index of the current transaction in the sequence
    pub symbolic_storage_map: HashMap<(Address, B256), TaintSource>, // (addr, slot) -> TaintSource of value
    pub transient_taint_map: HashMap<(Address, B256), TaintSource>, // EIP-1153 support
}

impl<'a> CoverageInspector<'a> {
    pub fn new(
        coverage: &'a mut BitSlice<u8, Lsb0>,
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
            symbolic_storage_map: HashMap::new(),
            transient_taint_map: HashMap::new(),
        }
    }
}

impl<'a, DB: Database> Inspector<DB> for CoverageInspector<'a> {
    fn step(&mut self, interp: &mut Interpreter, _context: &mut EvmContext<'_, DB>) {
        let pc = interp.program_counter;
        let opcode = interp.current_opcode;

        // --- Taint Propagation ---
        match opcode {
            // CALLDATALOAD: Mark the top of the stack as tainted with the offset
            opcode::CALLDATALOAD => {
                if let Ok(offset_val) = interp.stack.peek(0) {
                    let offset = offset_val.to::<usize>();
                    self.taint_stack.push(Some(TaintSource::Calldata(offset)));
                }
            }
            // Propagation for stack operations
            opcode::PUSH1..=opcode::PUSH32 => self.taint_stack.push(None),
            opcode::DUP1..=opcode::DUP16 => {
                let idx = (opcode - opcode::DUP1) as usize;
                let taint = self.taint_stack.iter().rev().nth(idx).cloned().flatten(); // Get taint from duplicated item
                self.taint_stack.push(taint);
            }
            opcode::SWAP1..=opcode::SWAP16 => {
                let idx = (opcode - opcode::SWAP1 + 1) as usize;
                let len = self.taint_stack.len();
                if len > idx {
                    self.taint_stack.swap(len - 1, len - 1 - idx);
                }
            }
            opcode::POP => { self.taint_stack.pop(); } // Remove taint for popped item
            opcode::SLOAD => {
                if let Ok(slot_val) = interp.stack.peek(0) {
                    let addr = interp.contract.address;
                    let slot = B256::from(slot_val.to_be_bytes::<32>());
                    
                    // If this slot was written by a previous transaction in the sequence
                    if let Some(taint_source_of_value) = self.symbolic_storage_map.get(&(addr, slot)).cloned() {
                        if let TaintSource::Storage(written_tx_idx, _) = taint_source_of_value {
                            if written_tx_idx < self.current_tx_idx {
                                self.waypoints.push(Waypoint::StorageRead {
                                    address: addr, slot, value: U256::ZERO, // Value will be known after SLOAD
                                    pc, read_tx_idx: self.current_tx_idx, taint_source: Some(taint_source_of_value),
                                });
                                self.taint_stack.push(Some(taint_source_of_value)); // Propagate taint from storage read
                                return; // Skip default taint propagation
                            }
                        }
                    }
                }
                self.taint_stack.push(None); // SLOAD result is untainted by default unless explicitly tracked
            }
            opcode::TLOAD => {
                if let Ok(slot_val) = interp.stack.peek(0) {
                    let addr = interp.contract.address;
                    let slot = B256::from(slot_val.to_be_bytes::<32>());
                    
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

        // Industry standard: Use edge hashing (prev_pc XOR curr_pc)
        if opcode == 0x56 || opcode == 0x57 {
            let edge_hash = (pc ^ (self.last_pc >> 1)) % self.coverage.len();
            
            // Instead of just setting a bit, we increment a hitcount (represented as 1 in bitvec for now)
            // In a production fuzzer, use a [u8; MAP_SIZE] for hitcounts
            if !self.coverage.get(edge_hash).unwrap() {
                self.coverage.set(edge_hash, true);
            }
        }

        // Causal Tracking: Monitor SLOAD (0x54) and SSTORE (0x55)
        if opcode == 0x54 || opcode == 0x55 {
            if let Ok(slot_val) = interp.stack.peek(0) {
                let addr = interp.contract.address;
                let slot = B256::from(slot_val.to_be_bytes::<32>());
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
                let address = interp.contract.address;
                let slot = B256::from(slot_val.to_be_bytes::<32>());

                self.dataflow.mark_influenced(address, slot);

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
        if opcode == opcode::TSTORE {
            let value_taint_source = self.taint_stack.last().cloned().flatten();
            if let Ok(slot_val) = interp.stack.peek(0) {
                let address = interp.contract.address;
                let slot = B256::from(slot_val.to_be_bytes::<32>());
                
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
                        constraint: Waypoint::Comparison {
                            op: 0x14, // Force equality check logic in solver
                            lhs: condition,
                            rhs: if branch_taken { U256::ZERO } else { U256::from(1) },
                            pc,
                            taint_source: Some(ts),
                        },
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
                });
            }
        }

        // Capture Mapping Derivations for high-fidelity Oracle reasoning
        if opcode == opcode::SHA3 {
            if let (Ok(offset), Ok(size)) = (interp.stack.peek(0), interp.stack.peek(1)) {
                let offset = offset.to::<usize>();
                let size = size.to::<usize>();
                
                // Industry standard: mappings usually involve 64 bytes (key + base_slot)
                if size == 64 {
                    let data = interp.shared_memory.slice(offset, size);
                    let key = U256::from_be_slice(&data[0..32]);
                    let base_slot = U256::from_be_slice(&data[32..64]);
                    
                    self.waypoints.push(Waypoint::MappingDerivation {
                        base_slot,
                        key,
                        derived_slot: keccak256(data),
                    });
                }
            }
        }

        self.last_pc = pc;
    }

    fn call(&mut self, _context: &mut EvmContext<'_, DB>, inputs: &mut CallInputs) -> Option<CallOutcome> {
        // Detect Token Callbacks (ERC777 / ERC1363)
        if inputs.input.len() >= 4 {
            let selector = &inputs.input[0..4];
            // 0x97135039: tokensReceived (ERC777)
            // 0x88a7ca5c: onTransferReceived (ERC1363)
            if selector == [0x97, 0x13, 0x50, 0x39] || selector == [0x88, 0xa7, 0xca, 0x5c] {
                self.waypoints.push(Waypoint::TokenCallback {
                    target: inputs.target_address,
                    selector: selector.try_into().unwrap(),
                    data: inputs.input.to_vec(),
                });
            }
        }

        // EIP-3156: flashLoan(receiver, token, amount, data) -> 0x5c19e951
        if inputs.input.len() >= 4 && inputs.input[0..4] == [0x5c, 0x19, 0xe9, 0x51] {
             // Potential flashloan initiation detected.
        }

        // EIP-3156: onFlashLoan(initiator, token, amount, fee, data) -> 0x2393069c
        if inputs.input.len() >= 4 && inputs.input[0..4] == [0x23, 0x93, 0x06, 0x9c] {
            // The lender is calling back the fuzzer. 
            // This is the "manipulate" phase of the attack.
            if let Ok(amount) = U256::abi_decode(&inputs.input[68..100], true) {
                if let Ok(fee) = U256::abi_decode(&inputs.input[100..132], true) {
                    self.waypoints.push(Waypoint::FlashloanExecution {
                        lender: inputs.context.caller,
                        token: Address::from_slice(&inputs.input[16..36]),
                        amount,
                        fee,
                        is_repaid: false, // Will be verified in call_end or by Oracle
                    });
                }
            }
        }

        // Governance detection (GovernorBravo/Alpha style)
        if inputs.input.len() >= 4 {
            let selector = &inputs.input[0..4];
            // da95691a: propose, 56781388: castVote, fe0d94c1: execute
            if selector == [0xda, 0x95, 0x69, 0x1a] || 
               selector == [0x56, 0x78, 0x13, 0x88] || 
               selector == [0xfe, 0x0d, 0x94, 0xc1] 
            {
                self.waypoints.push(Waypoint::GovernanceAction {
                    target: inputs.target_address,
                    selector: selector.try_into().unwrap(),
                    caller: inputs.context.caller,
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

    fn call_end(&mut self, _context: &mut EvmContext<'_, DB>, inputs: &CallInputs, outcome: CallOutcome) -> CallOutcome {
        // Read-only reentrancy typically involves a staticcall returning inconsistent state.
        // We record the outcome of all staticcalls to check for divergences later.
        if inputs.context.scheme == CallScheme::StaticCall {
            self.waypoints.push(Waypoint::StaticCall {
                caller: inputs.context.caller,
                target: inputs.context.address,
                data: inputs.input.to_vec(),
                output: outcome.result.output.to_vec(),
            });
        }
        outcome
    }
}
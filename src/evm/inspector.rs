use revm::{
    interpreter::{Interpreter, CallInputs, CallOutcome, CallScheme, opcode},
    Database, Inspector, EvmContext,
};
use bitvec::prelude::*;
use crate::evm::dataflow::DataflowRegistry;
use crate::common::types::Waypoint;
use revm::primitives::B256;
use std::collections::HashSet;
use revm::primitives::Address;

/// Industry standard: Use a fixed-size map for coverage to allow
/// JIT-like performance and SIMD-optimized comparisons in the feedback loop.
pub const MAP_SIZE: usize = 65536;

#[derive(Debug)]
pub struct CoverageInspector<'a> {
    pub coverage: &'a mut BitSlice<u8, Lsb0>,
    pub dataflow: &'a mut DataflowRegistry,
    pub waypoints: &'a mut Vec<Waypoint>,
    pub taint_stack: Vec<Option<usize>>, // Mirror stack: stores calldata offset if tainted
    pub read_set: HashSet<(Address, B256)>,
    pub write_set: HashSet<(Address, B256)>,
    pub last_pc: usize,
}

impl<'a> CoverageInspector<'a> {
    pub fn new(
        coverage: &'a mut BitSlice<u8, Lsb0>,
        dataflow: &'a mut DataflowRegistry,
        waypoints: &'a mut Vec<Waypoint>,
    ) -> Self {
        Self { 
            coverage, dataflow, waypoints,
            taint_stack: Vec::with_capacity(1024),
            read_set: HashSet::new(), write_set: HashSet::new(),
            last_pc: 0,
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
                    self.taint_stack.push(Some(offset));
                }
            }
            // Propagation for stack operations
            opcode::PUSH1..=opcode::PUSH32 => self.taint_stack.push(None),
            opcode::DUP1..=opcode::DUP16 => {
                let idx = (opcode - opcode::DUP1) as usize;
                let taint = self.taint_stack.iter().rev().nth(idx).cloned().flatten();
                self.taint_stack.push(taint);
            }
            opcode::SWAP1..=opcode::SWAP16 => {
                let idx = (opcode - opcode::SWAP1 + 1) as usize;
                let len = self.taint_stack.len();
                if len > idx {
                    self.taint_stack.swap(len - 1, len - 1 - idx);
                }
            }
            opcode::POP => { self.taint_stack.pop(); }
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
            // Slot is the first item on the stack for SSTORE
            if let Ok(slot_val) = interp.stack.peek(0) {
                let address = interp.contract.address;
                let slot = B256::from(slot_val.to_be_bytes::<32>());

                // In this implementation, we mark any slot written during fuzzing
                // as influenced by user-controlled input.
                self.dataflow.mark_influenced(address, slot);
            }
        }

        // Capture Arithmetic results for ADD (0x01) and MUL (0x02) to aid in overflow detection
        if opcode == opcode::ADD || opcode == opcode::MUL {
            if let (Ok(lhs), Ok(rhs)) = (interp.stack.peek(0), interp.stack.peek(1)) {
                let calldata_offset = self.taint_stack.iter().rev().nth(0).cloned().flatten()
                    .or_else(|| self.taint_stack.iter().rev().nth(1).cloned().flatten());

                self.waypoints.push(Waypoint::Arithmetic {
                    op: opcode,
                    lhs,
                    rhs,
                    pc,
                    calldata_offset,
                });
            }
        }

        // Capture Comparisons for Concolic Solving
        // Opcodes: LT (0x10), GT (0x11), SLT (0x12), SGT (0x13), EQ (0x14)
        if opcode >= 0x10 && opcode <= 0x14 {
            if let (Ok(lhs), Ok(rhs)) = (interp.stack.peek(0), interp.stack.peek(1)) {
                let calldata_offset = self.taint_stack.iter().rev().nth(0).cloned().flatten()
                    .or_else(|| self.taint_stack.iter().rev().nth(1).cloned().flatten());

                self.waypoints.push(Waypoint::Comparison {
                    op: opcode,
                    lhs,
                    rhs,
                    pc,
                    calldata_offset,
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
//! Taint analysis engine for tracking user-controlled data through EVM execution
//! 
//! This module implements flow-sensitive taint tracking to detect when attacker-controlled
//! inputs flow into sensitive operations (sinks), enabling detection of:
//! - Injection attacks (arbitrary calls, delegatecalls)
//! - Storage corruption via tainted indices
//! - Arithmetic vulnerabilities with tainted operands
//! - Access control bypasses with tainted caller checks

use revm::{
    Database, Inspector,
    interpreter::{Interpreter, Stack, CallInputs, CallOutcome, CallScheme},
    interpreter::interpreter_types::Jumps,
    primitives::{Address, U256},
};
// v38: OpCode is now in the bytecode module
// use revm::bytecode::Bytecode; // Unused
// Context and Bytes unused
// Context, Bytes,
use std::collections::{HashMap, HashSet};
use crate::common::types::SingletonTx;

/// Source of taint (attacker-controlled data)
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum TaintSource {
    /// Calldata at specific byte offset
    Calldata(usize),
    /// Transaction caller address
    Caller,
    /// Block timestamp (can be manipulated by miners)
    BlockTimestamp,
    /// Block number
    BlockNumber,
    /// Block basefee
    BaseFee,
    /// Return data from external call to specific address
    ExternalReturn(Address),
    /// CREATE2 salt (user-controlled)
    Create2Salt,
}

/// A taint mark attached to a value
#[derive(Debug, Clone, Hash, Eq, PartialEq)]
pub struct TaintMark {
    pub source: TaintSource,
    pub propagation_path: Vec<TaintOperation>,
}

#[derive(Debug, Clone, Hash, Eq, PartialEq)]
pub enum TaintOperation {
    Add,
    Sub,
    Mul,
    Div,
    Mod,
    Exp,
    And,
    Or,
    Xor,
    Not,
    Shl,
    Shr,
    Sar,
    Concat,
    Slice(usize, usize),
    Keccak,
}

/// Taint state for a single stack slot or memory location
#[derive(Debug, Clone, Default)]
pub struct TaintState {
    pub marks: HashSet<TaintMark>,
}

impl TaintState {
    pub fn is_tainted(&self) -> bool {
        !self.marks.is_empty()
    }
    
    pub fn merge(&mut self, other: &TaintState) {
        self.marks.extend(other.marks.iter().cloned());
    }
    
    pub fn clear(&mut self) {
        self.marks.clear();
    }
}

/// Complete taint tracking state
pub struct TaintTracker {
    /// Taint state for each stack slot (index = stack position)
    stack_taint: Vec<TaintState>,
    /// Taint state for memory regions (start_offset -> state)
    memory_taint: HashMap<usize, TaintState>,
    /// Taint state for storage slots (slot hash -> state)
    storage_taint: HashMap<U256, TaintState>,
    /// Known taint sources from the transaction
    tx_sources: HashSet<TaintSource>,
    /// Recorded taint flows (source -> sink paths)
    pub detected_flows: Vec<TaintFlow>,
    /// Maximum stack depth tracked
    max_stack_depth: usize,
}

#[derive(Debug, Clone)]
pub struct TaintFlow {
    pub source: TaintSource,
    pub sink: TaintSink,
    pub path: Vec<TaintOperation>,
    pub severity: FlowSeverity,
    pub description: String,
}

#[derive(Debug, Clone)]
pub enum TaintSink {
    /// Tainted data used as CALL target address
    CallTarget,
    /// Tainted data used as DELEGATECALL target
    DelegateCallTarget,
    /// Tainted data used as SSTORE key
    StorageKey,
    /// Tainted data used as SSTORE value
    StorageValue,
    /// Tainted data used in arithmetic that could overflow
    ArithmeticOverflow,
    /// Tainted data used in comparison (access control)
    AccessControlCheck,
    /// Tainted data passed to external call as calldata
    ExternalCalldata(Address),
    /// Tainted data used in CREATE2 salt
    Create2Salt,
    /// Tainted data used as array index
    ArrayIndex,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum FlowSeverity {
    Low,      // Informational
    Medium,   // Potential issue
    High,     // Likely vulnerability
    Critical, // Definite exploit vector
}

impl TaintTracker {
    pub fn new(tx: &SingletonTx) -> Self {
        let mut tx_sources = HashSet::new();
        
        // Mark all calldata as tainted (attacker-controlled)
        for i in 0..tx.input.len() {
            tx_sources.insert(TaintSource::Calldata(i));
        }
        
        // Mark caller as tainted
        tx_sources.insert(TaintSource::Caller);
        
        Self {
            stack_taint: Vec::with_capacity(1024),
            memory_taint: HashMap::new(),
            storage_taint: HashMap::new(),
            tx_sources,
            detected_flows: Vec::new(),
            max_stack_depth: 1024,
        }
    }
    
    /// Initialize taint state for a new call frame
    pub fn enter_call_frame(&mut self, calldata: &[u8]) {
        // Mark calldata arguments as tainted
        for i in 0..calldata.len().min(4096) {
            if let Some(state) = self.memory_taint.get_mut(&i) {
                state.marks.insert(TaintMark {
                    source: TaintSource::Calldata(i),
                    propagation_path: Vec::new(),
                });
            } else {
                let mut state = TaintState::default();
                state.marks.insert(TaintMark {
                    source: TaintSource::Calldata(i),
                    propagation_path: Vec::new(),
                });
                self.memory_taint.insert(i, state);
            }
        }
    }
    
    /// Get taint state for a stack slot
    pub fn get_stack_taint(&self, index: usize) -> Option<&TaintState> {
        self.stack_taint.get(index)
    }
    
    /// Get mutable taint state for a stack slot
    pub fn get_stack_taint_mut(&mut self, index: usize) -> Option<&mut TaintState> {
        if index >= self.stack_taint.len() {
            self.stack_taint.resize(index + 1, TaintState::default());
        }
        self.stack_taint.get_mut(index)
    }
    
    /// Check if a U256 value has any taint marks (approximate check)
    pub fn is_value_tainted(&self, value: U256) -> bool {
        // Simplified: check if any byte of the value corresponds to tainted calldata
        let bytes = value.to_be_bytes::<32>();
        for (i, &byte) in bytes.iter().enumerate() {
            if byte != 0 && self.tx_sources.contains(&TaintSource::Calldata(i)) {
                return true;
            }
        }
        false
    }
    
    /// Record a dangerous taint flow
    pub fn record_flow(&mut self, source: TaintSource, sink: TaintSink, path: Vec<TaintOperation>) {
        let severity = match &sink {
            TaintSink::DelegateCallTarget => FlowSeverity::Critical,
            TaintSink::CallTarget => FlowSeverity::High,
            TaintSink::StorageKey => FlowSeverity::High,
            TaintSink::AccessControlCheck => FlowSeverity::High,
            TaintSink::ArithmeticOverflow => FlowSeverity::Medium,
            TaintSink::ExternalCalldata(_) => FlowSeverity::Medium,
            TaintSink::Create2Salt => FlowSeverity::Medium,
            TaintSink::ArrayIndex => FlowSeverity::Low,
            TaintSink::StorageValue => FlowSeverity::Low,
        };
        
        let description = match &sink {
            TaintSink::DelegateCallTarget => "Tainted data controls DELEGATECALL target (code execution)".to_string(),
            TaintSink::CallTarget => "Tainted data controls CALL target address".to_string(),
            TaintSink::StorageKey => "Tainted data controls storage slot being written".to_string(),
            TaintSink::StorageValue => "Tainted data written to storage".to_string(),
            TaintSink::AccessControlCheck => "Tainted data used in access control comparison".to_string(),
            TaintSink::ArithmeticOverflow => "Tainted operand in arithmetic operation".to_string(),
            TaintSink::ExternalCalldata(addr) => format!("Tainted data forwarded to {:?}", addr),
            TaintSink::Create2Salt => "Tainted data controls CREATE2 address prediction".to_string(),
            TaintSink::ArrayIndex => "Tainted data used as array/mapping index".to_string(),
        };
        
        self.detected_flows.push(TaintFlow {
            source,
            sink,
            path,
            severity,
            description,
        });
    }
    
    /// Analyze collected flows and return critical findings
    pub fn get_critical_flows(&self) -> Vec<&TaintFlow> {
        self.detected_flows
            .iter()
            .filter(|f| f.severity == FlowSeverity::Critical || f.severity == FlowSeverity::High)
            .collect()
    }
}

/// Inspector that performs taint tracking during EVM execution
pub struct TaintInspector<'a> {
    pub tracker: &'a mut TaintTracker,
    current_depth: usize,
}

impl<'a> TaintInspector<'a> {
    pub fn new(tracker: &'a mut TaintTracker) -> Self {
        Self {
            tracker,
            current_depth: 0,
        }
    }
    
    /// Propagate taint through binary operations
    fn propagate_binary(&mut self, op: TaintOperation, stack: &Stack) {
        let stack_len = stack.len();
        if stack_len < 2 {
            return;
        }
        
        let top_state = self.tracker.get_stack_taint(stack_len - 1).cloned().unwrap_or_default();
        let second_state = self.tracker.get_stack_taint(stack_len - 2).cloned().unwrap_or_default();
        
        // Result is tainted if either operand is tainted
        let mut result_state = TaintState::default();
        result_state.merge(&top_state);
        result_state.merge(&second_state);
        
        // Add operation to propagation path
        let mut marks: Vec<_> = result_state.marks.drain().collect();
        for mark in &mut marks {
            mark.propagation_path.push(op.clone());
        }
        result_state.marks = marks.into_iter().collect();
        
        // Pop two values, push result
        if stack_len >= 2 {
            self.tracker.stack_taint.truncate(stack_len - 2);
        }
        self.tracker.stack_taint.push(result_state);
    }
    
    /// Propagate taint through unary operations
    fn propagate_unary(&mut self, op: TaintOperation, stack: &Stack) {
        let stack_len = stack.len();
        if stack_len < 1 {
            return;
        }
        
        let top_state = self.tracker.get_stack_taint_mut(stack_len - 1);
        if let Some(state) = top_state {
            let mut marks: Vec<_> = state.marks.drain().collect();
            for mark in &mut marks {
                mark.propagation_path.push(op.clone());
            }
            state.marks = marks.into_iter().collect();
        }
    }
}

impl<'a, DB: Database> Inspector<DB> for TaintInspector<'a> {
    fn step(&mut self, interp: &mut Interpreter, _context: &mut DB) {
        let opcode = interp.bytecode.opcode();
        let stack = &mut interp.stack;
        let stack_len = stack.len();
        
        // Handle stack manipulation opcodes
        match opcode {
            // Binary operations
            0x01 => self.propagate_binary(TaintOperation::Add, stack),      // ADD
            0x02 => self.propagate_binary(TaintOperation::Mul, stack),      // MUL
            0x03 => self.propagate_binary(TaintOperation::Sub, stack),      // SUB
            0x04 => self.propagate_binary(TaintOperation::Div, stack),      // DIV
            0x06 => self.propagate_binary(TaintOperation::Mod, stack),      // MOD
            0x0A => self.propagate_binary(TaintOperation::Exp, stack),      // EXP
            0x10 | 0x11 | 0x12 | 0x13 => {                                  // LT, GT, SLT, SGT
                self.propagate_binary(TaintOperation::Sub, stack);
                // Comparison results are not tainted, but we track the flow
                if stack_len >= 2 {
                    if let Some(top_state) = self.tracker.get_stack_taint(stack_len - 1) {
                        if top_state.is_tainted() {
                            // Record potential access control check
                            let marks: Vec<_> = top_state.marks.iter().cloned().collect();
                            for mark in marks {
                                self.tracker.record_flow(
                                    mark.source.clone(),
                                    TaintSink::AccessControlCheck,
                                    mark.propagation_path.clone(),
                                );
                            }
                        }
                    }
                }
            }
            0x14 => { // EQ
                self.propagate_binary(TaintOperation::Sub, stack);
                // Similar to comparisons, track for access control
            }
            0x16 => self.propagate_binary(TaintOperation::And, stack),      // AND
            0x17 => self.propagate_binary(TaintOperation::Or, stack),       // OR
            0x18 => self.propagate_binary(TaintOperation::Xor, stack),      // XOR
            0x1B => self.propagate_binary(TaintOperation::Shl, stack),      // SHL
            0x1C => self.propagate_binary(TaintOperation::Shr, stack),      // SHR
            0x1D => self.propagate_binary(TaintOperation::Sar, stack),      // SAR
            
            // Unary operations
            0x19 => self.propagate_unary(TaintOperation::Not, stack),       // NOT
            
            // DUP operations - copy taint state
            0x80..=0x8F => {
                let dup_index = (opcode - 0x80) as usize;
                if stack_len > dup_index {
                    let source_idx = stack_len - 1 - dup_index;
                    let source_state = self.tracker.get_stack_taint(source_idx).cloned().unwrap_or_default();
                    self.tracker.stack_taint.push(source_state);
                }
            }
            
            // SWAP operations - swap taint states
            0x90..=0x9F => {
                let swap_index = (opcode - 0x90 + 1) as usize;
                if stack_len > swap_index {
                    let swap_idx = stack_len - 1 - swap_index;
                    self.tracker.stack_taint.swap(swap_idx, stack_len - 1);
                }
            }
            
            // POP - remove taint state
            0x50 => {
                if !self.tracker.stack_taint.is_empty() {
                    self.tracker.stack_taint.pop();
                }
            }
            
            // PUSH operations - not tainted (immediate values)
            0x5F..=0x7F => {
                self.tracker.stack_taint.push(TaintState::default());
            }
            
            // MLOAD - load taint from memory
            0x51 => {
                if stack_len >= 1 {
                    // Pop offset
                    let offset_state = self.tracker.stack_taint.pop().unwrap_or_default();
                    
                    // In a real implementation, we'd track which memory locations are tainted
                    // For now, assume loaded data inherits taint from offset + base memory taint
                    let mut loaded_state = offset_state;
                    
                    // Add generic memory taint marker
                    if !loaded_state.is_tainted() {
                        // Conservative: assume memory might be tainted
                        loaded_state.marks.insert(TaintMark {
                            source: TaintSource::ExternalReturn(Address::ZERO),
                            propagation_path: vec![TaintOperation::Slice(0, 32)],
                        });
                    }
                    
                    self.tracker.stack_taint.push(loaded_state);
                }
            }
            
            // MSTORE - propagate taint to memory
            0x52 => {
                if stack_len >= 2 {
                    let value_state = self.tracker.stack_taint.pop().unwrap_or_default();
                    let offset_state = self.tracker.stack_taint.pop().unwrap_or_default();
                    
                    // Store taint at memory location (simplified)
                    // Real impl would track exact offsets
                    if value_state.is_tainted() {
                        // Memory at this offset is now tainted
                    }
                }
            }
            
            // SLOAD - load from storage (not inherently tainted)
            0x54 => {
                if stack_len >= 1 {
                    let key_state = self.tracker.stack_taint.pop().unwrap_or_default();
                    
                    if let Some(target_state) = self.tracker.get_stack_taint(stack_len - 1) {
                        if target_state.is_tainted() {
                            let marks = target_state.marks.clone();
                            for mark in &marks {
                                self.tracker.record_flow(
                                    mark.source.clone(),
                                    TaintSink::StorageKey,
                                    mark.propagation_path.clone(),
                                );
                            }
                        }
                    }
                    
                    // Loaded value gets combined taint
                    let mut result_state = key_state;
                    result_state.marks.insert(TaintMark {
                        source: TaintSource::ExternalReturn(Address::ZERO),
                        propagation_path: Vec::new(),
                    });
                    
                    self.tracker.stack_taint.push(result_state);
                }
            }
            
            // SSTORE - store to storage
            0x55 => {
                if stack_len >= 2 {
                    let value_state = self.tracker.stack_taint.pop().unwrap_or_default();
                    let key_state = self.tracker.stack_taint.pop().unwrap_or_default();
                    
                    // Record flows for tainted key or value
                    if key_state.is_tainted() {
                        for mark in &key_state.marks {
                            self.tracker.record_flow(
                                mark.source.clone(),
                                TaintSink::StorageKey,
                                mark.propagation_path.clone(),
                            );
                        }
                    }
                    
                    if value_state.is_tainted() {
                        for mark in &value_state.marks {
                            self.tracker.record_flow(
                                mark.source.clone(),
                                TaintSink::StorageValue,
                                mark.propagation_path.clone(),
                            );
                        }
                    }
                }
            }
            
            _ => {
                // Default: preserve stack taint for most opcodes
                // This is conservative; real impl would handle each opcode
            }
        }
    }
    
    fn call(
        &mut self,
        _context: &mut DB,
        inputs: &mut revm::interpreter::CallInputs,
    ) -> Option<revm::interpreter::CallOutcome> {
        self.current_depth += 1;
        
        let stack_len = self.tracker.stack_taint.len();
        
        // Check if call target is tainted
        if stack_len >= 1 {
            if let Some(target_state) = self.tracker.get_stack_taint(stack_len - 1) {
                if target_state.is_tainted() {
                    let sink = if matches!(inputs.scheme, revm::interpreter::CallScheme::DelegateCall) {
                        TaintSink::DelegateCallTarget
                    } else {
                        TaintSink::CallTarget
                    };
                    
                    let marks: Vec<_> = target_state.marks.iter().cloned().collect();
                    for mark in marks {
                        self.tracker.record_flow(
                            mark.source.clone(),
                            sink.clone(),
                            mark.propagation_path.clone(),
                        );
                    }
                }
            }
        }
        
        None
    }
    
    fn call_end(
        &mut self,
        _context: &mut DB,
        _inputs: &revm::interpreter::CallInputs,
        outcome: &mut revm::interpreter::CallOutcome,
    ) {
        self.current_depth = self.current_depth.saturating_sub(1);
        
        // Return data from external calls may be tainted
        // In a full implementation, we'd mark the return buffer as tainted
    }
}

/// Analyzer that summarizes taint tracking results
pub struct TaintAnalyzer;

impl TaintAnalyzer {
    pub fn analyze(tracker: &TaintTracker) -> TaintReport {
        let critical_flows = tracker.get_critical_flows();
        
        let mut report = TaintReport {
            total_flows: tracker.detected_flows.len(),
            critical_count: 0,
            high_count: 0,
            medium_count: 0,
            low_count: 0,
            findings: Vec::new(),
        };
        
        for flow in &tracker.detected_flows {
            match flow.severity {
                FlowSeverity::Critical => report.critical_count += 1,
                FlowSeverity::High => report.high_count += 1,
                FlowSeverity::Medium => report.medium_count += 1,
                FlowSeverity::Low => report.low_count += 1,
            }
            
            if flow.severity == FlowSeverity::Critical || flow.severity == FlowSeverity::High {
                report.findings.push(TaintFinding {
                    severity: flow.severity.clone(),
                    source: format!("{:?}", flow.source),
                    sink: format!("{:?}", flow.sink),
                    description: flow.description.clone(),
                    recommendation: Self::get_recommendation(&flow.sink),
                });
            }
        }
        
        report
    }
    
    fn get_recommendation(sink: &TaintSink) -> String {
        match sink {
            TaintSink::DelegateCallTarget => "Use immutable, hardcoded addresses for DELEGATECALL targets. Never allow user input to control the target.".to_string(),
            TaintSink::CallTarget => "Validate call targets against an allowlist. Consider using explicit interfaces.".to_string(),
            TaintSink::StorageKey => "Sanitize storage indices. Use mappings with validated keys instead of arrays with user indices.".to_string(),
            TaintSink::AccessControlCheck => "Ensure access control checks use trusted, non-user-controlled values.".to_string(),
            TaintSink::ArithmeticOverflow => "Use SafeMath or Solidity 0.8+ checked arithmetic for user-influenced calculations.".to_string(),
            TaintSink::ExternalCalldata(_) => "Validate and sanitize data before forwarding to external contracts.".to_string(),
            TaintSink::Create2Salt => "Use deterministic, non-user-controlled salts for CREATE2 deployments.".to_string(),
            TaintSink::ArrayIndex => "Bounds-check all array/mapping accesses with user-provided indices.".to_string(),
            TaintSink::StorageValue => "Validate values before writing to storage, especially for critical state variables.".to_string(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct TaintReport {
    pub total_flows: usize,
    pub critical_count: usize,
    pub high_count: usize,
    pub medium_count: usize,
    pub low_count: usize,
    pub findings: Vec<TaintFinding>,
}

#[derive(Debug, Clone)]
pub struct TaintFinding {
    pub severity: FlowSeverity,
    pub source: String,
    pub sink: String,
    pub description: String,
    pub recommendation: String,
}

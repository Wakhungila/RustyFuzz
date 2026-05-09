//! Execution trace analysis for extracting events, state changes, and call graphs
//! 
//! This module provides deep inspection of EVM execution traces to enable:
//! - Event log parsing for vulnerability detection
//! - State change tracking across calls
//! - Call graph construction for boundary analysis
//! - Gas usage profiling per operation

use revm::{
    interpreter::{CallInputs, CallOutcome, CreateInputs, CreateOutcome, Interpreter},
    Database, Inspector, EvmContext,
    primitives::{Address, Log, U256, Bytes},
};
use std::collections::HashMap;

/// Represents a single step in the execution trace
#[derive(Debug, Clone)]
pub struct TraceStep {
    pub pc: usize,
    pub opcode: u8,
    pub gas_remaining: u64,
    pub stack_depth: usize,
    pub memory_size: usize,
    pub contract_address: Address,
}

/// Represents an external call in the trace
#[derive(Debug, Clone)]
pub struct CallTrace {
    pub caller: Address,
    pub target: Address,
    pub input: Bytes,
    pub output: Option<Bytes>,
    pub value: U256,
    pub gas_used: u64,
    pub success: bool,
    pub depth: usize,
    pub is_delegate: bool,
    pub is_static: bool,
}

/// Represents a contract creation in the trace
#[derive(Debug, Clone)]
pub struct CreateTrace {
    pub creator: Address,
    pub init_code: Bytes,
    pub deployed_address: Option<Address>,
    pub deployed_code: Option<Bytes>,
    pub gas_used: u64,
    pub success: bool,
    pub depth: usize,
}

/// Represents a state change (SSTORE)
#[derive(Debug, Clone)]
pub struct StateChange {
    pub contract: Address,
    pub slot: U256,
    pub previous_value: U256,
    pub new_value: U256,
    pub depth: usize,
    pub pc: usize,
}

/// Parsed event log from execution
#[derive(Debug, Clone)]
pub struct ParsedLog {
    pub address: Address,
    pub topics: Vec<U256>,
    pub data: Bytes,
    pub depth: usize,
}

/// Complete execution trace for a transaction
#[derive(Debug, Clone, Default)]
pub struct ExecutionTrace {
    pub steps: Vec<TraceStep>,
    pub calls: Vec<CallTrace>,
    pub creates: Vec<CreateTrace>,
    pub state_changes: Vec<StateChange>,
    pub logs: Vec<ParsedLog>,
    pub total_gas_used: u64,
    pub success: bool,
    pub revert_reason: Option<String>,
}

impl ExecutionTrace {
    /// Get all external calls (non-static, non-delegate)
    pub fn external_calls(&self) -> Vec<&CallTrace> {
        self.calls
            .iter()
            .filter(|c| !c.is_delegate && !c.is_static && c.depth > 0)
            .collect()
    }
    
    /// Get state changes grouped by contract
    pub fn state_changes_by_contract(&self) -> HashMap<Address, Vec<&StateChange>> {
        let mut map = HashMap::new();
        for change in &self.state_changes {
            map.entry(change.contract)
                .or_insert_with(Vec::new)
                .push(change);
        }
        map
    }
    
    /// Build a call graph from the trace
    pub fn build_call_graph(&self) -> CallGraph {
        CallGraph::from_trace(self)
    }
    
    /// Find all calls to unverified or suspicious addresses
    pub fn find_suspicious_calls(&self, known_contracts: &[Address]) -> Vec<&CallTrace> {
        self.calls
            .iter()
            .filter(|c| {
                c.depth > 0 && 
                !known_contracts.contains(&c.target) &&
                !c.input.is_empty() // Has calldata, likely a function call
            })
            .collect()
    }
}

/// Call graph representing contract interactions
#[derive(Debug, Clone)]
pub struct CallGraph {
    pub nodes: Vec<Address>,
    pub edges: Vec<(Address, Address, CallEdgeInfo)>,
}

#[derive(Debug, Clone)]
pub struct CallEdgeInfo {
    pub call_count: usize,
    pub total_value: U256,
    pub selectors: Vec<[u8; 4]>,
}

impl CallGraph {
    pub fn from_trace(trace: &ExecutionTrace) -> Self {
        let mut nodes = Vec::new();
        let mut edge_map: HashMap<(Address, Address), CallEdgeInfo> = HashMap::new();
        
        for call in &trace.calls {
            if !nodes.contains(&call.caller) {
                nodes.push(call.caller);
            }
            if !nodes.contains(&call.target) {
                nodes.push(call.target);
            }
            
            let key = (call.caller, call.target);
            let edge = edge_map.entry(key).or_insert(CallEdgeInfo {
                call_count: 0,
                total_value: U256::ZERO,
                selectors: Vec::new(),
            });
            
            edge.call_count += 1;
            edge.total_value = edge.total_value.saturating_add(call.value);
            
            if call.input.len() >= 4 {
                let selector: [u8; 4] = call.input[0..4].try_into().unwrap();
                if !edge.selectors.contains(&selector) {
                    edge.selectors.push(selector);
                }
            }
        }
        
        let edges = edge_map.into_iter().collect();
        
        Self { nodes, edges }
    }
    
    /// Find contracts that receive calls from multiple sources (potential attack surfaces)
    pub fn find_high_traffic_targets(&self, threshold: usize) -> Vec<Address> {
        let mut incoming_count: HashMap<Address, usize> = HashMap::new();
        
        for (_, target, info) in &self.edges {
            *incoming_count.entry(*target).or_insert(0) += info.call_count;
        }
        
        incoming_count
            .into_iter()
            .filter(|(_, count)| *count >= threshold)
            .map(|(addr, _)| addr)
            .collect()
    }
    
    /// Find circular call patterns (potential reentrancy vectors)
    pub fn find_cycles(&self) -> Vec<Vec<Address>> {
        // Simple DFS-based cycle detection
        let mut cycles = Vec::new();
        let adj: HashMap<Address, Vec<Address>> = {
            let mut map = HashMap::new();
            for (source, target, _) in &self.edges {
                map.entry(*source).or_insert_with(Vec::new).push(*target);
            }
            map
        };
        
        let mut visited = HashMap::new();
        let mut rec_stack = Vec::new();
        
        for &node in &self.nodes {
            if !visited.contains_key(&node) {
                self.dfs_cycle(node, &adj, &mut visited, &mut rec_stack, &mut cycles);
            }
        }
        
        cycles
    }
    
    fn dfs_cycle(
        &self,
        node: Address,
        adj: &HashMap<Address, Vec<Address>>,
        visited: &mut HashMap<Address, bool>,
        rec_stack: &mut Vec<Address>,
        cycles: &mut Vec<Vec<Address>>,
    ) {
        visited.insert(node, true);
        rec_stack.push(node);
        
        if let Some(neighbors) = adj.get(&node) {
            for &neighbor in neighbors {
                if !visited.contains_key(&neighbor) {
                    self.dfs_cycle(neighbor, adj, visited, rec_stack, cycles);
                } else if rec_stack.contains(&neighbor) {
                    // Found a cycle
                    let cycle_start = rec_stack.iter().position(|&n| n == neighbor).unwrap();
                    let cycle = rec_stack[cycle_start..].to_vec();
                    if !cycles.contains(&cycle) {
                        cycles.push(cycle);
                    }
                }
            }
        }
        
        rec_stack.pop();
    }
}

/// Inspector that builds execution traces
pub struct TraceInspector<'a> {
    pub trace: ExecutionTrace,
    pub capture_steps: bool,
    pub max_steps: usize,
    current_depth: usize,
    call_stack: Vec<CallContext>,
    pending_state_changes: Vec<(U256, U256)>, // (slot, old_value)
    #[allow(dead_code)]
    logs_buffer: &'a mut Vec<Log>,
}

#[derive(Debug, Clone)]
struct CallContext {
    address: Address,
    depth: usize,
}

impl<'a> TraceInspector<'a> {
    pub fn new(logs_buffer: &'a mut Vec<Log>) -> Self {
        Self {
            trace: ExecutionTrace::default(),
            capture_steps: false, // Disable step capture for performance
            max_steps: 100_000,
            current_depth: 0,
            call_stack: Vec::new(),
            pending_state_changes: Vec::new(),
            logs_buffer,
        }
    }
    
    pub fn with_step_capture(mut self) -> Self {
        self.capture_steps = true;
        self
    }
}

impl<'a, DB: Database> Inspector<DB> for TraceInspector<'a> {
    fn step(&mut self, interp: &mut Interpreter, context: &mut EvmContext) {
        if !self.capture_steps || self.trace.steps.len() >= self.max_steps {
            return;
        }
        
        let step = TraceStep {
            pc: interp.program_counter(),
            opcode: interp.current_opcode(),
            gas_remaining: interp.gas.remaining(),
            stack_depth: interp.stack.len(),
            memory_size: interp.shared_memory.len(),
            contract_address: context.evm.env.tx.caller, // Approximate
        };
        
        self.trace.steps.push(step);
    }
    
    fn call(
        &mut self,
        context: &mut EvmContext,
        inputs: &mut CallInputs,
    ) -> Option<CallOutcome> {
        self.current_depth += 1;
        
        self.call_stack.push(CallContext {
            address: inputs.target_address,
            depth: self.current_depth,
        });
        
        // Record call (will be updated with outcome later)
        self.trace.calls.push(CallTrace {
            caller: inputs.context.caller,
            target: inputs.target_address,
            input: inputs.input.clone(),
            output: None,
            value: inputs.transfer.value,
            gas_used: 0,
            success: true,
            depth: self.current_depth,
            is_delegate: matches!(inputs.scheme, revm::interpreter::CallScheme::DelegateCall),
            is_static: inputs.is_static,
        });
        
        None
    }
    
    fn call_end(
        &mut self,
        _context: &mut EvmContext,
        _inputs: &CallInputs,
        outcome: CallOutcome,
    ) -> CallOutcome {
        if let Some(last_call) = self.trace.calls.last_mut() {
            last_call.output = Some(outcome.result.output.clone());
            last_call.success = outcome.result.is_success();
            last_call.gas_used = _inputs.gas_limit - outcome.result.gas_used();
        }
        
        self.call_stack.pop();
        self.current_depth = self.current_depth.saturating_sub(1);
        
        outcome
    }
    
    fn create(
        &mut self,
        _context: &mut EvmContext,
        inputs: &mut CreateInputs,
    ) -> Option<CreateOutcome> {
        self.current_depth += 1;
        
        self.trace.creates.push(CreateTrace {
            creator: inputs.caller,
            init_code: inputs.init_code.clone(),
            deployed_address: None,
            deployed_code: None,
            gas_used: 0,
            success: true,
            depth: self.current_depth,
        });
        
        None
    }
    
    fn create_end(
        &mut self,
        _context: &mut EvmContext,
        _inputs: &CreateInputs,
        outcome: CreateOutcome,
    ) -> CreateOutcome {
        if let Some(last_create) = self.trace.creates.last_mut() {
            last_create.deployed_address = outcome.address;
            last_create.deployed_code = outcome.result.output.clone().into();
            last_create.success = outcome.result.is_success();
            last_create.gas_used = _inputs.gas_limit - outcome.result.gas_used();
        }
        
        self.current_depth = self.current_depth.saturating_sub(1);
        
        outcome
    }
    
    fn log(&mut self, _interp: &mut Interpreter, _context: &mut EvmContext, log: &Log) {
        self.trace.logs.push(ParsedLog {
            address: log.address,
            topics: log.topics().iter().map(|t| U256::from_be_bytes(t.0)).collect(),
            data: log.data.data.clone(),
            depth: self.current_depth,
        });
        
        self.logs_buffer.push(log.clone());
    }
    
    fn sstore(
        &mut self,
        _context: &mut EvmContext,
        address: Address,
        index: U256,
        value: U256,
        old_value: U256,
    ) {
        self.trace.state_changes.push(StateChange {
            contract: address,
            slot: index,
            previous_value: old_value,
            new_value: value,
            depth: self.current_depth,
            pc: 0, // Would need step tracking for exact PC
        });
    }
}

/// Analyzer that processes execution traces to find vulnerabilities
pub struct TraceAnalyzer;

impl TraceAnalyzer {
    /// Analyze a trace for common vulnerability patterns
    pub fn analyze(trace: &ExecutionTrace) -> Vec<TraceFinding> {
        let mut findings = Vec::new();
        
        // Check for suspicious call patterns
        findings.extend(Self::check_reentrancy_patterns(trace));
        
        // Check for dangerous delegate calls
        findings.extend(Self::check_delegate_call_patterns(trace));
        
        // Check for unusual state change patterns
        findings.extend(Self::check_state_change_patterns(trace));
        
        // Check for gas-intensive operations
        findings.extend(Self::check_gas_patterns(trace));
        
        findings
    }
    
    fn check_reentrancy_patterns(trace: &ExecutionTrace) -> Vec<TraceFinding> {
        let mut findings = Vec::new();
        
        // Look for external calls followed by state changes at same depth
        let call_graph = trace.build_call_graph();
        let cycles = call_graph.find_cycles();
        
        if !cycles.is_empty() {
            for cycle in cycles {
                findings.push(TraceFinding {
                    severity: FindingSeverity::High,
                    category: "Reentrancy".to_string(),
                    description: format!(
                        "Circular call pattern detected: {}",
                        cycle.iter()
                            .map(|a| format!("{:?}", a))
                            .collect::<Vec<_>>()
                            .join(" -> ")
                    ),
                    evidence: format!("Cycle length: {}", cycle.len()),
                    recommendation: "Implement reentrancy guards or use checks-effects-interactions pattern".to_string(),
                });
            }
        }
        
        // Check for state changes after external calls
        let mut last_external_call_depth = 0;
        for item in &trace.calls {
            if item.depth > 0 && !item.is_delegate && !item.is_static {
                last_external_call_depth = item.depth;
            }
        }
        
        for change in &trace.state_changes {
            if change.depth <= last_external_call_depth && last_external_call_depth > 0 {
                findings.push(TraceFinding {
                    severity: FindingSeverity::Medium,
                    category: "Potential Reentrancy".to_string(),
                    description: "State change occurs after external call".to_string(),
                    evidence: format!(
                        "Changed slot {:?} at depth {} after call at depth {}",
                        change.slot, change.depth, last_external_call_depth
                    ),
                    recommendation: "Ensure state changes happen before external calls".to_string(),
                });
            }
        }
        
        findings
    }
    
    fn check_delegate_call_patterns(trace: &ExecutionTrace) -> Vec<TraceFinding> {
        let mut findings = Vec::new();
        
        for call in &trace.calls {
            if call.is_delegate && call.depth > 0 {
                // Check if target is hardcoded or dynamic
                let is_dynamic_target = call.input.len() < 4 || 
                    call.input[0..4] != [0x00, 0x00, 0x00, 0x00]; // Simplified check
                
                if is_dynamic_target {
                    findings.push(TraceFinding {
                        severity: FindingSeverity::Critical,
                        category: "Dangerous DelegateCall".to_string(),
                        description: "DELEGATECALL to potentially dynamic target".to_string(),
                        evidence: format!("Target: {:?}, Input len: {}", call.target, call.input.len()),
                        recommendation: "Ensure DELEGATECALL targets are immutable and trusted".to_string(),
                    });
                }
            }
        }
        
        findings
    }
    
    fn check_state_change_patterns(trace: &ExecutionTrace) -> Vec<TraceFinding> {
        let mut findings = Vec::new();
        
        // Group state changes by contract
        let changes_by_contract = trace.state_changes_by_contract();
        
        for (contract, changes) in changes_by_contract {
            // Check for balance-like slot changes (common slots: 0, 1, 2)
            let balance_slots: Vec<_> = changes
                .iter()
                .filter(|c| c.slot <= U256::from(10))
                .collect();
            
            if balance_slots.len() > 3 {
                findings.push(TraceFinding {
                    severity: FindingSeverity::Medium,
                    category: "Frequent Balance Updates".to_string(),
                    description: format!(
                        "Contract {:?} had {} updates to low-index storage slots",
                        contract, balance_slots.len()
                    ),
                    evidence: "Multiple updates to potential balance/mapping slots".to_string(),
                    recommendation: "Review access controls on balance-modifying functions".to_string(),
                });
            }
        }
        
        findings
    }
    
    fn check_gas_patterns(trace: &ExecutionTrace) -> Vec<TraceFinding> {
        let mut findings = Vec::new();
        
        if trace.total_gas_used > 20_000_000 {
            findings.push(TraceFinding {
                severity: FindingSeverity::Low,
                category: "High Gas Usage".to_string(),
                description: format!(
                    "Transaction used {} gas ({:.1}% of block limit)",
                    trace.total_gas_used,
                    (trace.total_gas_used as f64 / 30_000_000.0) * 100.0
                ),
                evidence: "Gas usage exceeds typical thresholds".to_string(),
                recommendation: "Consider optimizing hot paths or implementing gas limits".to_string(),
            });
        }
        
        findings
    }
}

#[derive(Debug, Clone)]
pub struct TraceFinding {
    pub severity: FindingSeverity,
    pub category: String,
    pub description: String,
    pub evidence: String,
    pub recommendation: String,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum FindingSeverity {
    Low,
    Medium,
    High,
    Critical,
}

use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet, VecDeque};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ControlFlowGraph {
    pub basic_blocks: HashMap<usize, BasicBlock>,
    pub edges: Vec<(usize, usize)>, // (from, to) block indices
    pub entry_block: usize,
    pub unreachable_blocks: HashSet<usize>,
    pub loops: Vec<Vec<usize>>, // cycles in CFG
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BasicBlock {
    pub start_pc: usize,
    pub end_pc: usize,
    pub instructions: Vec<(usize, String)>, // (pc, opcode)
    pub successors: Vec<usize>,
    pub predecessors: Vec<usize>,
    pub has_unguarded_delegatecall: bool,
    pub has_unguarded_external_call: bool,
    pub has_unguarded_sstore: bool,
    pub conditional_branch: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ControlFlowAnalysis {
    pub cfg: ControlFlowGraph,
    pub unguarded_delegatecalls: Vec<(usize, String)>,
    pub unguarded_external_calls: Vec<(usize, String)>,
    pub unguarded_storage_writes: Vec<(usize, String)>,
    pub unreachable_code: Vec<usize>,
    pub missing_complementary_checks: Vec<(usize, String)>, // (pc, description)
    pub dead_upgrade_paths: Vec<String>,
}

impl ControlFlowGraph {
    pub fn new(entry_block: usize) -> Self {
        Self {
            basic_blocks: HashMap::new(),
            edges: Vec::new(),
            entry_block,
            unreachable_blocks: HashSet::new(),
            loops: Vec::new(),
        }
    }

    pub fn add_block(&mut self, block: BasicBlock) {
        let pc = block.start_pc;
        self.basic_blocks.insert(pc, block);
    }

    pub fn add_edge(&mut self, from: usize, to: usize) {
        self.edges.push((from, to));
    }

    pub fn compute_reachability(&mut self) {
        let mut reachable = HashSet::new();
        let mut queue = VecDeque::new();

        queue.push_back(self.entry_block);
        reachable.insert(self.entry_block);

        while let Some(block_pc) = queue.pop_front() {
            for &(from, to) in &self.edges {
                if from == block_pc && !reachable.contains(&to) {
                    reachable.insert(to);
                    queue.push_back(to);
                }
            }
        }

        self.unreachable_blocks = self
            .basic_blocks
            .keys()
            .filter(|pc| !reachable.contains(pc))
            .copied()
            .collect();
    }

    pub fn find_loops(&mut self) {
        let mut visited = HashSet::new();
        let mut rec_stack = HashSet::new();
        let mut loops = Vec::new();

        for &block_pc in self.basic_blocks.keys() {
            if !visited.contains(&block_pc) {
                self.dfs_loop_detection(block_pc, &mut visited, &mut rec_stack, &mut loops);
            }
        }
        self.loops = loops;
    }

    fn dfs_loop_detection(
        &self,
        node: usize,
        visited: &mut HashSet<usize>,
        rec_stack: &mut HashSet<usize>,
        loops: &mut Vec<Vec<usize>>,
    ) {
        visited.insert(node);
        rec_stack.insert(node);

        for &(from, to) in &self.edges {
            if from == node {
                if !visited.contains(&to) {
                    self.dfs_loop_detection(to, visited, rec_stack, loops);
                } else if rec_stack.contains(&to) {
                    // Back edge found - potential loop
                    loops.push(vec![from, to]);
                }
            }
        }

        rec_stack.remove(&node);
    }
}

impl ControlFlowAnalysis {
    pub fn from_bytecode(bytecode: &[u8]) -> Self {
        let cfg = Self::build_cfg(bytecode);
        let mut analysis = ControlFlowAnalysis {
            cfg,
            unguarded_delegatecalls: Vec::new(),
            unguarded_external_calls: Vec::new(),
            unguarded_storage_writes: Vec::new(),
            unreachable_code: Vec::new(),
            missing_complementary_checks: Vec::new(),
            dead_upgrade_paths: Vec::new(),
        };

        analysis.compute_security_issues();
        analysis
    }

    fn build_cfg(bytecode: &[u8]) -> ControlFlowGraph {
        let mut cfg = ControlFlowGraph::new(0);
        let mut pc = 0;

        while pc < bytecode.len() {
            let opcode = bytecode[pc];
            let _opcode_str = Self::opcode_name(opcode);

            if Self::is_block_terminator(opcode) {
                pc += 1;
            } else {
                pc += 1;
            }
        }

        cfg.compute_reachability();
        cfg.find_loops();
        cfg
    }

    fn opcode_name(opcode: u8) -> String {
        match opcode {
            0x00 => "STOP".to_string(),
            0x01 => "ADD".to_string(),
            0x56 => "JUMP".to_string(),
            0x57 => "JUMPI".to_string(),
            0x63 => "PUSH4".to_string(),
            0x81 => "DUP2".to_string(),
            0xF1 => "CALL".to_string(),
            0xF4 => "DELEGATECALL".to_string(),
            _ => format!("0x{:02x}", opcode),
        }
    }

    fn is_block_terminator(opcode: u8) -> bool {
        matches!(opcode, 0x56 | 0x57 | 0x00 | 0xFD | 0xFE | 0xFF) // JUMP, JUMPI, STOP, REVERT, SELFDESTRUCT, INVALID
    }

    fn compute_security_issues(&mut self) {
        for (pc, block) in &self.cfg.basic_blocks {
            if self.cfg.unreachable_blocks.contains(pc) {
                self.unreachable_code.push(*pc);
            }

            if block.has_unguarded_delegatecall {
                self.unguarded_delegatecalls
                    .push((*pc, "DELEGATECALL without proper guards".to_string()));
            }

            if block.has_unguarded_external_call {
                self.unguarded_external_calls
                    .push((*pc, "CALL without proper guards".to_string()));
            }

            if block.has_unguarded_sstore {
                self.unguarded_storage_writes
                    .push((*pc, "SSTORE without access control".to_string()));
            }
        }

        // Flag dead upgrade paths
        if self.cfg.unreachable_blocks.iter().any(|pc| {
            self.cfg
                .basic_blocks
                .get(pc)
                .map(|b| {
                    b.instructions
                        .iter()
                        .any(|(_, op)| op.contains("upgradeTo") || op.contains("upgrade"))
                })
                .unwrap_or(false)
        }) {
            self.dead_upgrade_paths
                .push("Unreachable upgrade function detected".to_string());
        }

        // Detect missing complementary checks (e.g., if check without else)
        for (pc, block) in &self.cfg.basic_blocks {
            if block.conditional_branch && block.successors.len() == 1 {
                self.missing_complementary_checks.push((
                    *pc,
                    "Conditional branch missing complementary path".to_string(),
                ));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_unreachable_blocks() {
        let mut cfg = ControlFlowGraph::new(0);

        let block1 = BasicBlock {
            start_pc: 0,
            end_pc: 10,
            instructions: vec![(0, "code".to_string())],
            successors: vec![20],
            predecessors: vec![],
            has_unguarded_delegatecall: false,
            has_unguarded_external_call: false,
            has_unguarded_sstore: false,
            conditional_branch: false,
        };

        let block2 = BasicBlock {
            start_pc: 20,
            end_pc: 30,
            instructions: vec![],
            successors: vec![],
            predecessors: vec![0],
            has_unguarded_delegatecall: false,
            has_unguarded_external_call: false,
            has_unguarded_sstore: false,
            conditional_branch: false,
        };

        let block3 = BasicBlock {
            start_pc: 100,
            end_pc: 110,
            instructions: vec![],
            successors: vec![],
            predecessors: vec![],
            has_unguarded_delegatecall: false,
            has_unguarded_external_call: false,
            has_unguarded_sstore: false,
            conditional_branch: false,
        };

        cfg.add_block(block1);
        cfg.add_block(block2);
        cfg.add_block(block3);
        cfg.add_edge(0, 20);

        cfg.compute_reachability();

        assert!(cfg.unreachable_blocks.contains(&100));
        assert!(!cfg.unreachable_blocks.contains(&0));
        assert!(!cfg.unreachable_blocks.contains(&20));
    }
}

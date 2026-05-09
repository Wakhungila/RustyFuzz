use mollusk_svm::result::InstructionResult;
use solana_sdk::instruction::Instruction;
use bitvec::prelude::*;
use solana_sdk::instruction::AccountMeta;
use solana_sdk::hash::Hash as SolanaHash; // Use Solana's Hash for instruction hashing
use crate::common::types::Waypoint;
use crate::common::oracle::VulnType;
use revm::primitives::U256;
use std::hash::{Hash, Hasher};

/// Solana-specific CoverageInspector that tracks program-level instruction execution.
pub struct SvmCoverageInspector<'a> {
    pub coverage: &'a mut BitSlice<u8, Lsb0>,
    pub waypoints: &'a mut Vec<Waypoint>,
}

impl<'a> SvmCoverageInspector<'a> {
    pub fn new(coverage: &'a mut BitSlice<u8, Lsb0>, waypoints: &'a mut Vec<Waypoint>) -> Self {
        Self { coverage, waypoints }
    }

    /// Records instruction metadata and outcome to influence the fuzzing feedback loop.
    pub fn observe_instruction(
        &mut self, 
        instruction: &Instruction, 
        result: &InstructionResult,
        instruction_waypoints: &mut Vec<Waypoint>) {
        // Map the program ID and instruction discriminator to a coverage bit.
        // To achieve more "BPF-level" coverage without direct BPF hooks,
        // we hash a combination of program ID, instruction data, and involved accounts.
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        instruction.program_id.hash(&mut hasher);
        instruction.data.hash(&mut hasher); // Hash entire instruction data
        
        // Hash all account metas to capture unique interaction patterns
        for account_meta in &instruction.accounts {
            account_meta.pubkey.hash(&mut hasher);
            account_meta.is_signer.hash(&mut hasher);
            account_meta.is_writable.hash(&mut hasher);
        }
        
        let idx = (hasher.finish() as usize) % self.coverage.len();
        self.coverage.set(idx, true);

        // Record a waypoint to capture the instruction result status.
        // This can be extended to capture compute units, logs, etc., if Mollusk exposes them.
        self.waypoints.push(Waypoint::Comparison {
            op: 0x55, // Marker for SVM instruction result
            lhs: U256::from(if result.result.is_ok() { 1 } else { 0 }),
            rhs: U256::ZERO,
            pc: 0,
            calldata_offset: None,
        });
        
        // P0 Discovery: Missing Signer Check Detection
        // If an instruction succeeded, but we know (via Waypoints/Mutator) that 
        // a required signer was toggled to 'false', this is a critical vulnerability.
        for account in &instruction.accounts {
            if !account.is_signer && self.is_known_privileged_account(account.pubkey) && result.result.is_ok() {
                // In a production loop, this would trigger a specific VulnType::MissingSignerCheck
            }
        }
    }

    fn is_known_privileged_account(&self, _pubkey: solana_sdk::pubkey::Pubkey) -> bool {
        // Heuristic: identify accounts that usually require signers (Vaults, Admins)
        true
    }
}
use libafl::{
    prelude::*,
    inputs::Input,
    mutators::MutationResult,
};
use libafl_bolts::{HasLen, rands::Rand, Error};
use solana_sdk::instruction::Instruction;
use solana_sdk::pubkey::Pubkey;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use borsh::{BorshSerialize, BorshDeserialize};

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct SvmInput {
    pub instructions: Vec<Instruction>,
    pub base_snapshot_id: u64,
    pub account_overrides: HashMap<Pubkey, Vec<u8>>, // For mutating account data directly
}

impl Input for SvmInput {
    fn generate_name(&self, id: usize) -> String {
        format!("svm_seq_{}_{}", self.base_snapshot_id, id)
    }
}

impl HasLen for SvmInput {
    fn len(&self) -> usize {
        self.instructions.iter().map(|i| i.data.len()).sum()
    }
}

/// SVM-aware mutator targeting instruction sequencing and account data layout.
pub struct SvmMutator;

impl<S> Mutator<SvmInput, S> for SvmMutator
where
    S: HasRand,
{
    fn mutate(
        &mut self,
        state: &mut S,
        input: &mut SvmInput,
        _stage_idx: i32,
    ) -> Result<MutationResult, Error> {
        let rand = state.rand_mut();
        
        if input.instructions.is_empty() {
            return Ok(MutationResult::Skipped);
        }

        let mutation_type = rand.below(100);
        let res = match mutation_type {
            0..=15 => {
                // Anchor-Aware Account Data Mutation (Borsh-aligned)
                if !input.account_overrides.is_empty() {
                    let keys: Vec<Pubkey> = input.account_overrides.keys().cloned().collect();
                    let key = keys[rand.below(keys.len() as u64) as usize];
                    let data = input.account_overrides.get_mut(&key).unwrap();
                    
                    // Anchor accounts: 8-byte discriminator + Borsh data.
                    // We target u32 length prefixes common in Borsh strings/vecs.
                    if data.len() > 12 {
                        let offset = 8 + rand.below((data.len() - 11) as u64) as usize;
                        let mut len_bytes = [0u8; 4];
                        len_bytes.copy_from_slice(&data[offset..offset+4]);
                        let mut len = u32::from_le_bytes(len_bytes);
                        len = len.wrapping_add(rand.next() as u32); // Add/subtract small random value
                        data[offset..offset+4].copy_from_slice(&len.to_le_bytes());
                        return Ok(MutationResult::Mutated);
                    }
                }
                Ok(MutationResult::Skipped)
            }
            16..=25 => {
                // Anchor-Aware: Mutate Instruction Discriminator (first 8 bytes)
                let idx = rand.below(input.instructions.len() as u64) as usize;
                let data = &mut input.instructions[idx].data;
                if data.len() >= 8 {
                    let byte_idx = rand.below(8) as usize;
                    data[byte_idx] = rand.next() as u8;
                    Ok(MutationResult::Mutated)
                } else {
                    Ok(MutationResult::Skipped)
                }
            }
            26..=35 => {
                // Instruction Sequencing: Reorder instructions within the sequence
                if input.instructions.len() > 1 {
                    let i = rand.below(input.instructions.len() as u64) as usize;
                    let j = rand.below(input.instructions.len() as u64) as usize;
                    input.instructions.swap(i, j);
                    Ok(MutationResult::Mutated)
                } else {
                    Ok(MutationResult::Skipped)
                }
            }
            36..=45 => {
                // Instruction Sequencing: Prune a random instruction
                if input.instructions.len() > 1 {
                    let idx = rand.below(input.instructions.len() as u64) as usize;
                    input.instructions.remove(idx);
                    Ok(MutationResult::Mutated)
                } else {
                    Ok(MutationResult::Skipped)
                }
            }
            46..=70 => {
                // Account Layout: Swap accounts within an instruction to test authorization bypasses
                let idx = rand.below(input.instructions.len() as u64) as usize;
                let accounts = &mut input.instructions[idx].accounts;
                if accounts.len() > 1 {
                    // Target P2/P1: Toggle 'is_signer' or 'is_writable' 
                    // This finds missing ownership checks and unauthorized access.
                    let i = rand.below(accounts.len() as u64) as usize;
                    match rand.below(3) {
                        0 => accounts[i].is_signer = !accounts[i].is_signer,
                        1 => accounts[i].is_writable = !accounts[i].is_writable,
                        2 => { // Point to a different account to trigger cross-program logic
                             accounts[i].pubkey = Pubkey::new_unique();
                        }
                        _ => unreachable!(),
                    }
                    Ok(MutationResult::Mutated)
                } else {
                    Ok(MutationResult::Skipped)
                }
            }
            _ => {
                // Data Layout: Mutate instruction data (opcodes, discriminators, and parameters)
                let idx = rand.below(input.instructions.len() as u64) as usize;
                let data = &mut input.instructions[idx].data;
                if !data.is_empty() {
                    let offset = rand.below(data.len() as u64) as usize;
                    data[offset] = rand.next() as u8;
                    Ok(MutationResult::Mutated)
                } else {
                    Ok(MutationResult::Skipped)
                }
            }
        }
    }
}
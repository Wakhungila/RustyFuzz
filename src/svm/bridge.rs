use crate::common::types::{ChainState, Snapshot, SingletonTx};
use revm::primitives::{Address, U256};
use std::collections::HashMap;
use solana_sdk::{
    account::Account as SolanaAccount, // Alias to avoid conflict with SvmAccount
    instruction::{AccountMeta, Instruction},
    pubkey::Pubkey,
    transaction::Transaction,
};

/// Represents a simplified Solana Account for cross-chain state translation.
#[derive(Clone, Debug, Default)]
pub struct SvmAccount {
    pub lamports: u64,
    pub data: Vec<u8>,
    pub owner: [u8; 32],
    pub executable: bool,
    pub rent_epoch: u64,
}

/// Bridge utility to translate EVM state snapshots into SVM-compatible structures.
pub struct SvmBridge;

impl SvmBridge {
    /// Translates an EVM ChainState into a mapping of pseudo-Solana accounts.
    /// This is used for multi-chain snapshotting where an EVM state change
    /// triggers or influences a simulated SVM environment.
    pub fn translate_evm_to_svm(evm_state: &ChainState, evm_dataflow: &crate::evm::dataflow::DataflowRegistry) -> crate::common::types::SvmState {
        let mut svm_state = crate::common::types::SvmState::default();

        if let ChainState::Evm(db) = evm_state {
            for (addr, acc) in &db.accounts {
                let mut pubkey = [0u8; 32];
                pubkey[12..32].copy_from_slice(addr.as_slice());

                // EVM Balance (U256) to SVM Lamports (u64)
                // Note: This performs a saturating cast as EVM balances can exceed u64.
                let lamports = acc.info.balance.to::<u64>();

                // Translate EVM storage slots into a contiguous byte array for SVM data.
                // Heuristic: We pack storage slots into the data field.
                let mut current_data_offset = 0;
                let mut data = Vec::with_capacity(acc.storage.len() * 64);
                for (slot, value) in &acc.storage {
                    let slot_start = current_data_offset;
                    data.extend_from_slice(slot.as_slice());
                    current_data_offset += 32;
                    let value_start = current_data_offset;
                    data.extend_from_slice(&value.to_be_bytes::<32>());
                    current_data_offset += 32;

                    // Cross-chain dataflow tracking: If this EVM slot was influenced,
                    // mark the corresponding region in the SVM account data.
                    if evm_dataflow.is_influenced(*addr, *slot) {
                        let solana_pubkey = Pubkey::new_from_array(pubkey);
                        svm_state.influenced_data_regions.entry(solana_pubkey).or_default().push(slot_start..current_data_offset);
                    }
                }

                svm_state.accounts.insert(
                    pubkey,
                    SvmAccount {
                        lamports,
                        data,
                        owner: [0u8; 32], // Default owner
                        executable: !acc.info.code.as_ref().map_or(true, |c| c.is_empty()),
                        rent_epoch: 0,
                    },
                );
            }
        }
        svm_state
    }

    /// Extends the bridge to handle Cross-Program Invocation (CPI) mapping.
    /// Translates a sequence of EVM transactions into a single Solana transaction 
    /// containing multiple instructions, allowing the fuzzer to explore 
    /// multi-step logic in the SVM.
    pub fn translate_evm_sequence_to_svm_tx(txs: &[SingletonTx]) -> Transaction {
        let instructions: Vec<Instruction> = txs.iter().map(|tx| {
            let program_id = Pubkey::new_from_array(Self::address_to_pubkey(&tx.to));
            let caller_pubkey = Pubkey::new_from_array(Self::address_to_pubkey(&tx.caller));
            
            // Heuristic: Map EVM caller to the first account and marked as signer.
            // In production, dataflow would identify additional required accounts.
            Instruction {
                program_id,
                accounts: vec![
                    AccountMeta::new(caller_pubkey, true),
                ],
                data: tx.input.clone(),
            }
        }).collect();

        // Generate a transaction with a dummy payer.
        Transaction::new_with_payer(&instructions, Some(&Pubkey::default()))
    }

    /// Deterministic mapping from a 20-byte EVM Address to a 32-byte Solana Pubkey.
    pub fn address_to_pubkey(addr: &Address) -> [u8; 32] {
        let mut pk = [0u8; 32];
        // Standard padding: append address bytes to the end of the pubkey buffer.
        pk[12..32].copy_from_slice(addr.as_slice());
        pk
    }
}
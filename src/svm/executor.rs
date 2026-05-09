#[cfg(feature = "svm")]
use mollusk_svm::Mollusk;
#[cfg(feature = "svm")]
use solana_sdk::transaction::Transaction;
#[cfg(feature = "svm")]
use solana_sdk::account::Account;
#[cfg(feature = "svm")]
use solana_sdk::pubkey::Pubkey;
use crate::svm::fuzz::SvmInput;
use crate::common::types::{SvmState, ChainState, Waypoint};
use crate::svm::bridge::SvmAccount;
#[cfg(feature = "svm")]
use crate::svm::inspector::SvmCoverageInspector;
#[cfg(feature = "svm")]
use bitvec::prelude::*;

pub struct SvmExecutor;

impl SvmExecutor {
    #[cfg(feature = "svm")]
    pub fn execute_transaction(
        initial_state: &SvmState, // Use initial_state to clone for isolation
        input: &SvmInput,
        coverage: &mut BitSlice<u8, Lsb0>,
        waypoints: &mut Vec<Waypoint>,
    ) -> anyhow::Result<()> {
        let mut state = initial_state.clone(); // Clone the state for isolated execution
        let mollusk = Mollusk::default();
        let mut inspector = SvmCoverageInspector::new(coverage, waypoints);

        // Initialize Mollusk context with the current snapshot's accounts
        let mut accounts_to_process: Vec<(Pubkey, Account)> = state.accounts.iter().map(|(pk, acc)| {
            (Pubkey::new_from_array(*pk), Account {
                lamports: acc.lamports,
                data: acc.data.clone(),
                owner: Pubkey::new_from_array(acc.owner),
                executable: acc.executable,
                rent_epoch: acc.rent_epoch,
            })
        }).collect();

        // Apply account overrides from the fuzzer input
        for (pubkey, data) in &input.account_overrides {
            if let Some(account) = accounts_to_process.iter_mut().find(|(pk, _)| pk == pubkey) {
                account.1.data = data.clone();
            }
        }

        // Execute each instruction in the translated transaction
        for instruction in input.instructions.iter() {
            let result = mollusk.process_instruction(instruction, &accounts_to_process);
            inspector.observe_instruction(instruction, &result);
        }

        // Update the SvmState with the resulting account changes.
        // This ensures the fuzzer can branch from the new state in subsequent rounds.
        for (pk, acc) in accounts_to_process {
            state.accounts.insert(pk.to_bytes(), SvmAccount {
                lamports: acc.lamports,
                data: acc.data,
                owner: acc.owner.to_bytes(),
                executable: acc.executable,
                rent_epoch: acc.rent_epoch,
            });
        }

        Ok(())
    }
    #[cfg(not(feature = "svm"))]
    pub fn execute_transaction( // Placeholder for when SVM feature is not enabled
        _state: &mut crate::common::types::SvmState, 
        _input: &crate::svm::fuzz::SvmInput,
        _coverage: &mut bitvec::prelude::BitSlice<u8, bitvec::prelude::Lsb0>,
        _waypoints: &mut Vec<crate::common::types::Waypoint>,
    ) -> anyhow::Result<()> {
        anyhow::bail!("SVM feature not enabled. Cannot execute SVM instructions.")
    }
}
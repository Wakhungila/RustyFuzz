use crate::common::types::{SvmState, VulnType, Snapshot};
use crate::svm::executor::SvmExecutor;
use solana_client::rpc_client::RpcClient;
use solana_sdk::transaction::Transaction;
use solana_sdk::pubkey::Pubkey;
use bitvec::prelude::*;
use crate::svm::fuzz::SvmInput;
use anyhow::Result;
use rayon::prelude::*;

/// Differential fuzzer comparing local Mollusk execution against live Solana RPC.
pub struct SvmDifferentialFuzzer {
    pub rpc_client: RpcClient,
}

impl SvmDifferentialFuzzer {
    pub fn new(rpc_url: &str) -> Self {
        Self {
            rpc_client: RpcClient::new(rpc_url.to_string()),
        }
    }

    /// Compares a batch of transactions in parallel using a thread pool.
    /// Local execution is compared against RPC simulation results for each transaction.
    pub fn check_divergence_batch(
        &self,
        initial_state: &SvmState, // The base state to clone for each parallel execution
        inputs: &[SvmInput], // Batch of fuzzer inputs
    ) -> Vec<Result<Option<VulnType>>> {
        inputs.par_iter().map(|input| {
            let mut local_state = initial_state.clone();
            
            // 1. Execute locally via Mollusk
            let mut local_coverage = bitvec![u8, Lsb0; 0; 65536];
            let mut local_waypoints = Vec::new();
            
            SvmExecutor::execute_transaction( // Pass the cloned state and input
                &mut local_state, 
                input, 
                local_coverage.as_mut_bitslice(), 
                &mut local_waypoints
            )?;

            // 2. Execute via RPC simulation
            // Construct a valid Solana transaction from the fuzzed instructions
            let tx = Transaction::new_with_payer(&input.instructions, Some(&Pubkey::default()));
            let simulation_result = self.rpc_client.simulate_transaction(&tx)?;

            if let Some(err) = simulation_result.value.err {
                return Ok(Some(VulnType::DifferentialDivergence(format!(
                    "RPC simulation error: {:?}", err
                ))));
            }

            // 3. Structural Divergence: Compare account states
            if let Some(accounts) = simulation_result.value.accounts {
                for (i, rpc_acc) in accounts.into_iter().enumerate() {
                    if let Some(rpc_acc) = rpc_acc { // RPC account data
                        let pubkey = tx.message.account_keys[i];
                        if let Some(local_acc) = local_state.accounts.get(&pubkey.to_bytes()) {
                            if local_acc.lamports != rpc_acc.lamports {
                                return Ok(Some(VulnType::DifferentialDivergence(format!(
                                    "Lamport mismatch for account {}: Local {} vs RPC {}",
                                    pubkey, local_acc.lamports, rpc_acc.lamports
                                ))));
                            }
                            
                            if local_acc.data != rpc_acc.data {
                                return Ok(Some(VulnType::DifferentialDivergence(format!(
                                    "Data mismatch for account {}", pubkey
                                ))));
                            }
                        }
                    }
                }
            }
            Ok(None)
        }).collect()
    }
}
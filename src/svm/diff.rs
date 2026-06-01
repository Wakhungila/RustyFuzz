use crate::common::types::{SvmState, VulnType, Snapshot};
use crate::evm::inspector::MAP_SIZE;
use crate::svm::executor::SvmExecutor;
use solana_client::rpc_client::RpcClient;
use solana_sdk::transaction::Transaction;
use solana_sdk::pubkey::Pubkey;
use bitvec::prelude::*;
use anyhow::Result;

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

    /// Compares local execution state against RPC simulation results.
    pub fn check_divergence(
        &self,
        local_state: &mut SvmState,
        transaction: &Transaction,
    ) -> Result<Option<VulnType>> {
        // 1. Execute locally via Mollusk
        let mut local_coverage = bitvec![u8, Lsb0; 0; MAP_SIZE];
        let mut local_waypoints = Vec::new();
        
        SvmExecutor::execute_transaction(
            local_state, 
            transaction, 
            local_coverage.as_mut_bitslice(), 
            &mut local_waypoints
        )?;

        // 2. Execute via RPC simulation
        let simulation_result = self.rpc_client.simulate_transaction(transaction)?;

        if let Some(err) = simulation_result.value.err {
            // If RPC failed but local succeeded, or vice-versa, we have a divergence.
            return Ok(Some(VulnType::DifferentialDivergence(format!(
                "RPC simulation error: {:?}", err
            ))));
        }

        // 3. Structural Divergence: Compare account states
        // Note: This requires the RPC to return post-simulation account data,
        // which typically involves specific configuration in the simulation request.
        if let Some(accounts) = simulation_result.value.accounts {
            for (i, rpc_acc) in accounts.into_iter().enumerate() {
                if let Some(rpc_acc) = rpc_acc {
                    let pubkey = transaction.message.account_keys[i];
                    if let Some(local_acc) = local_state.accounts.get(&pubkey.to_bytes()) {
                        if local_acc.lamports != rpc_acc.lamports {
                            return Ok(Some(VulnType::DifferentialDivergence(format!(
                                "Lamport mismatch for account {}: Local {} vs RPC {}",
                                pubkey, local_acc.lamports, rpc_acc.lamports
                            ))));
                        }
                        
                        if local_acc.data != rpc_acc.data {
                            return Ok(Some(VulnType::DifferentialDivergence(format!(
                                "Data mismatch for account {}: LocalDataLen={} vs RPCDataLen={}", 
                                pubkey, local_acc.data.len(), rpc_acc.data.len()
                            ))));
                        }
                    }
                }
            }
        }

        Ok(None)
    }
}

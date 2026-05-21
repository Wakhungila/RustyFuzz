use crate::common::types::{EvmInput, SingletonTx};
use alloy::consensus::Transaction;
use alloy::providers::Provider;
use alloy::rpc::types::eth::BlockTransactions;
use anyhow::Context;
use revm::primitives::Address;
use std::sync::Arc;

/// SeedIngester pulls real-world transaction data from a mainnet RPC
/// to provide the fuzzer with high-fidelity starting points.
pub struct SeedIngester<P> {
    provider: Arc<P>,
}

impl<P: Provider> SeedIngester<P> {
    pub fn new(provider: P) -> Self {
        Self {
            provider: Arc::new(provider),
        }
    }

    /// Fetches transactions from recent blocks that interacted with the target contract.
    pub async fn ingest_from_target(
        &self,
        target: Address,
        max_seeds: usize,
    ) -> anyhow::Result<Vec<EvmInput>> {
        let mut seeds = Vec::new();

        // v38/Alloy 2026: Block numbers are returned as u64 directly from most providers
        let latest_block = self
            .provider
            .get_block_number()
            .await
            .context("Failed to fetch latest block number")?;

        // Search depth for protocol interactions
        let search_depth = 100;

        for i in 0..search_depth {
            if seeds.len() >= max_seeds {
                break;
            }

            let block_num = latest_block.saturating_sub(i);

            // Alloy 0.2: get_block_by_number returns an Option<Block>
            // We use 'true' to get full transaction objects rather than just hashes
            let block = self
                .provider
                .get_block_by_number(block_num.into())
                .await
                .context(format!("Failed to fetch block {}", block_num))?;

            if let Some(b) = block {
                match b.transactions {
                    BlockTransactions::Full(txs) => {
                        for t in txs {
                            // Check if the transaction was directed at our target contract
                            // Dereference Recovered to get the envelope
                            let envelope = &*t.inner;
                            let tx_to = envelope.to();
                            if tx_to == Some(target) {
                                let input = EvmInput {
                                    txs: vec![SingletonTx {
                                        // Conversion to revm::primitives::Bytes
                                        input: envelope.input().to_vec(),
                                        caller: Address::from(*t.inner.signer()),
                                        to: target,
                                        value: envelope.value(),
                                        is_victim: false, // Default for seeds
                                    }],
                                    base_snapshot_id: 0,   // Root snapshot
                                    waypoints: Vec::new(), // No waypoints for seeds
                                };
                                seeds.push(input);
                            }
                            if seeds.len() >= max_seeds {
                                break;
                            }
                        }
                    }
                    _ => continue, // Skip if block only contains hashes
                }
            }
        }

        log::info!("Ingested {} seeds for target {}", seeds.len(), target);
        Ok(seeds)
    }
}

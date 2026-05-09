use alloy::providers::Provider;
use alloy::rpc::types::eth::BlockNumberOrTag;
use crate::common::types::{SingletonTx, EvmInput};
use revm::primitives::{Address, U256};
use std::sync::Arc;

/// SeedIngester pulls real-world transaction data from a mainnet RPC
/// to provide the fuzzer with high-fidelity starting points.
pub struct SeedIngester<P> {
    provider: Arc<P>,
}

impl<P: Provider> SeedIngester<P> {
    pub fn new(provider: P) -> Self {
        Self { provider: Arc::new(provider) }
    }

    /// Fetches transactions from recent blocks that interacted with the target contract.
    pub async fn ingest_from_target(&self, target: Address, max_seeds: usize) -> anyhow::Result<Vec<EvmInput>> {
        let mut seeds = Vec::new();
        let latest_block = self.provider.get_block_number().await?;
        
        // Look back 10 blocks for relevant activity
        for i in 0..10 {
            if seeds.len() >= max_seeds { break; }
            
            let block_num = latest_block.saturating_sub(i);
            let block = self.provider.get_block_by_number(block_num.into(), true).await?;
            
            if let Some(b) = block {
                for tx in b.transactions.hashes() {
                    let full_tx = self.provider.get_transaction_by_hash(*tx).await?;
                    if let Some(t) = full_tx {
                        // Filter for transactions targeting our contract
                        if t.to == Some(target) {
                            let input = EvmInput {
                                txs: vec![SingletonTx {
                                    input: t.input.to_vec(),
                                    caller: t.from,
                                    to: t.to.unwrap_or_default(),
                                    value: t.value,
                                }],
                                base_snapshot_id: 0,
                                waypoints: vec![],
                            };
                            seeds.push(input);
                        }
                    }
                    if seeds.len() >= max_seeds { break; }
                }
            }
        }

        log::info!("Ingested {} high-quality seeds from mainnet blocks", seeds.len());
        Ok(seeds)
    }
}
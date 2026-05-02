use async_trait::async_trait;
use crate::common::types::SingletonTx;

#[async_trait]
pub trait ChainInterface {
    async fn get_mempool_txs(&self) -> Vec<SingletonTx>;
    async fn simulate_tx(&self, tx: &SingletonTx) -> anyhow::Result<()>;
}
//! Recorded execution assumptions, shared by discovery and independent validation.

use anyhow::{ensure, Result};
use revm::context::BlockEnv;
use rustyfuzz_evm::{environment::EnvironmentPolicy, fork_db::ForkDb, time_warp::TimeWarp};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ReplayContext {
    pub schema_version: u32,
    pub initial_block: BlockEnv,
    pub time_warp: TimeWarp,
    pub environment_policy: EnvironmentPolicy,
    pub chain_id: Option<u64>,
    pub fork_block: Option<u64>,
    pub fork_block_hash: Option<String>,
}

impl ReplayContext {
    pub fn new(db: &ForkDb, initial_block: &BlockEnv, time_warp: TimeWarp) -> Result<Self> {
        let provenance = db.provenance();
        Ok(Self {
            schema_version: 1,
            initial_block: initial_block.clone(),
            time_warp,
            environment_policy: EnvironmentPolicy::resolve(db, initial_block)?,
            chain_id: provenance.chain_id,
            fork_block: provenance.block_number,
            fork_block_hash: provenance.block_hash.map(|hash| hash.to_ascii_lowercase()),
        })
    }

    pub fn validate(&self, db: &ForkDb) -> Result<()> {
        ensure!(self.schema_version == 1, "unsupported replay context schema");
        ensure!(
            self.time_warp == TimeWarp::from_seconds(
                self.time_warp.seconds_per_tx,
                self.time_warp.blocks_per_tx,
            ),
            "invalid recorded time-warp policy"
        );
        let observed = Self::new(db, &self.initial_block, self.time_warp)?;
        ensure!(self == &observed, "replay context differs from fork provenance or execution policy");
        Ok(())
    }

    pub fn block_at(&self, tx_index: usize) -> BlockEnv {
        let mut block = self.initial_block.clone();
        self.time_warp.apply(&mut block, tx_index);
        block
    }
}

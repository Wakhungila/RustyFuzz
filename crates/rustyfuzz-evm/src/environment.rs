//! Versioned execution policy. Live forks use Ethereum mainnet's verified
//! activation schedule; unpinned fixtures deliberately use synthetic Osaka.
use anyhow::{bail, ensure, Context, Result};
use revm::{
    context::{BlockEnv, CfgEnv},
    primitives::hardfork::SpecId,
};
use serde::{Deserialize, Serialize};

use crate::fork_db::{ForkCacheProvenance, ForkDb};

pub const ENVIRONMENT_POLICY_VERSION: u32 = 1;

/// Where the executing block is allowed to sit relative to the pinned fork.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BlockPosition {
    /// Proof semantics: the block must be the pinned one exactly.
    ExactlyPinned,
    /// Exploration semantics: the block may be the pin or any real later block.
    AtOrAfterPin,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnvironmentPolicy {
    pub version: u32,
    pub source: String,
    pub chain_id: u64,
    pub spec_id: String,
    pub tx_gas_limit: u64,
    pub tx_gas_price: u128,
    pub fee_strategy: String,
    pub blob_base_fee_update_fraction: Option<u64>,
}

impl EnvironmentPolicy {
    pub fn resolve(db: &ForkDb, block: &BlockEnv) -> Result<Self> {
        Self::from_provenance(&db.provenance(), block)
    }

    /// Resolves the policy for a transaction that is allowed to advance within
    /// the block range at or after the pinned fork.
    ///
    /// Only exploration should use this. Proof and verification paths must use
    /// [`EnvironmentPolicy::resolve`], which requires the executing block to be
    /// exactly the pinned block: a finding is only evidence if it reproduces on
    /// the state that was actually verified, not on a hypothetical later block.
    pub fn resolve_advancing(db: &ForkDb, block: &BlockEnv) -> Result<Self> {
        Self::from_provenance_with_policy(&db.provenance(), block, BlockPosition::AtOrAfterPin)
    }

    pub fn from_provenance(provenance: &ForkCacheProvenance, block: &BlockEnv) -> Result<Self> {
        Self::from_provenance_with_policy(provenance, block, BlockPosition::ExactlyPinned)
    }

    fn from_provenance_with_policy(
        provenance: &ForkCacheProvenance,
        block: &BlockEnv,
        position: BlockPosition,
    ) -> Result<Self> {
        // Offline cache imports retaining a chain identity are historical forks,
        // too. Only fixtures without chain identity receive synthetic semantics.
        let synthetic = provenance.chain_id.is_none() && provenance.provider_sanitized.is_empty();
        let (chain_id, spec, fraction) = if synthetic {
            (1, SpecId::OSAKA, Some(5_007_716))
        } else {
            let chain_id = provenance
                .chain_id
                .context("fork execution requires a chain id")?;
            // The profile decides which semantics apply, and refuses chains it does not
            // cover rather than executing them with mainnet rules. Previously this was a
            // bare `chain_id == 1` check, which produced "unsupported chain" only after a
            // successful fork and gave no hint that a profile was missing.
            let profile = crate::chain_profile::ChainProfile::for_chain(chain_id)
                .map_err(|message| anyhow::anyhow!(message))?;
            let Some(pinned) = provenance.block_number else {
                bail!("pinned fork execution requires a block number");
            };
            let executing = u64::try_from(block.number).context("block number exceeds u64")?;
            match position {
                BlockPosition::ExactlyPinned => ensure!(
                    executing == pinned,
                    "execution block number differs from pinned fork provenance \
                     (executing {executing}, pinned {pinned})"
                ),
                // Historical execution at a *later* block is legitimate during
                // exploration: a fuzzed sequence advances blocks so timelocks,
                // vesting and accrual become reachable, and every post-fork
                // block up to the present is real chain history. Executing at an
                // *earlier* block would read pre-state the verified pin never
                // saw; jumping wildly past the present would demand headers that
                // do not exist yet. Both fail closed.
                BlockPosition::AtOrAfterPin => {
                    ensure!(
                        executing >= pinned,
                        "execution block {executing} precedes pinned fork block {pinned}; \
                         earlier state cannot be reconstructed from this fork"
                    );
                    const MAX_BLOCKS_PAST_PINNED: u64 = 100_000;
                    ensure!(
                        executing.saturating_sub(pinned) <= MAX_BLOCKS_PAST_PINNED,
                        "execution block {executing} is more than {MAX_BLOCKS_PAST_PINNED} \
                         blocks past pinned fork block {pinned}; advance the fork instead of \
                         time-warping"
                    );
                }
            }
            let hash = provenance
                .block_hash
                .as_deref()
                .context("pinned fork execution requires a block hash")?;
            crate::fork_db::validate_block_hash(hash)?;
            let number = u64::try_from(block.number)?;
            let timestamp =
                u64::try_from(block.timestamp).context("block timestamp exceeds u64")?;
            let spec = profile.spec_for(number, timestamp);
            if spec >= SpecId::MERGE && profile.header.prevrandao {
                ensure!(
                    block.prevrandao.is_some(),
                    "post-Merge header is missing prevrandao"
                );
            }
            if spec >= SpecId::CANCUN && profile.header.excess_blob_gas {
                ensure!(
                    block.blob_excess_gas_and_price.is_some(),
                    "post-Cancun header is missing excess blob gas"
                );
            }
            (chain_id, spec, profile.blob_fraction(timestamp))
        };
        ensure!(
            block.gas_limit >= 21_000,
            "block gas limit cannot accommodate a transaction"
        );
        Ok(Self {
            version: ENVIRONMENT_POLICY_VERSION,
            source: if synthetic {
                "synthetic-osaka"
            } else {
                "pinned-ethereum-mainnet"
            }
            .into(),
            chain_id,
            spec_id: spec.to_string(),
            tx_gas_limit: 10_000_000.min(block.gas_limit),
            tx_gas_price: 1_000_000_000u128.max(u128::from(block.basefee)),
            fee_strategy: "legacy-max-1gwei-or-header-basefee".into(),
            blob_base_fee_update_fraction: fraction,
        })
    }

    pub fn cfg(&self) -> Result<CfgEnv> {
        let spec = self
            .spec_id
            .parse::<SpecId>()
            .map_err(|error| anyhow::anyhow!("invalid environment hardfork: {error:?}"))?;
        let mut cfg = CfgEnv::new_with_spec(spec);
        cfg.chain_id = self.chain_id;
        cfg.blob_base_fee_update_fraction = self.blob_base_fee_update_fraction;
        Ok(cfg)
    }

    pub fn block(&self, block: &BlockEnv) -> BlockEnv {
        let mut block = block.clone();
        if let (Some(blob), Some(fraction)) = (
            &block.blob_excess_gas_and_price,
            self.blob_base_fee_update_fraction,
        ) {
            block.set_blob_excess_gas_and_price(blob.excess_blob_gas, fraction);
        }
        block
    }
}

/// Ethereum mainnet activation parameters from go-ethereum's chain specification:
/// https://github.com/ethereum/go-ethereum/blob/master/params/chainspecs/mainnet.json
/// Merge's first PoS block is 15_537_394. Later forks activate by timestamp.
pub fn mainnet_spec(number: u64, timestamp: u64) -> SpecId {
    if number >= 15_537_394 {
        return match timestamp {
            1_764_798_551.. => SpecId::OSAKA,
            1_746_612_311.. => SpecId::PRAGUE,
            1_710_338_135.. => SpecId::CANCUN,
            1_681_338_455.. => SpecId::SHANGHAI,
            _ => SpecId::MERGE,
        };
    }
    match number {
        12_965_000.. => SpecId::LONDON,
        12_244_000.. => SpecId::BERLIN,
        9_069_000.. => SpecId::ISTANBUL,
        7_280_000.. => SpecId::PETERSBURG,
        4_370_000.. => SpecId::BYZANTIUM,
        2_675_000.. => SpecId::SPURIOUS_DRAGON,
        2_463_000.. => SpecId::TANGERINE,
        1_150_000.. => SpecId::HOMESTEAD,
        _ => SpecId::FRONTIER,
    }
}

/// BPO forks change blob pricing independently of the EVM instruction set.
pub fn mainnet_blob_fraction(timestamp: u64) -> Option<u64> {
    match timestamp {
        1_767_747_671.. => Some(11_684_671),
        1_765_290_071.. => Some(8_346_193),
        1_746_612_311.. => Some(5_007_716),
        1_710_338_135.. => Some(3_338_477),
        _ => None,
    }
}

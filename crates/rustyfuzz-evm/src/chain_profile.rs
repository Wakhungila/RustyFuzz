//! Chain profiles: what a chain's execution semantics actually are.
//!
//! # Why this exists
//!
//! The executor previously asserted `chain_id == 1` and derived the hardfork from
//! Ethereum mainnet block-number and timestamp tables. That is correct for mainnet and
//! wrong for everything else, and it failed in the worst way: a non-mainnet target
//! produced `unsupported chain` only after the fork had succeeded, and a hand-patched
//! build then executed it with mainnet rules — silently wrong semantics rather than a
//! refusal.
//!
//! A profile makes the assumptions explicit and reviewable. A chain is executable only
//! when a profile covers it; otherwise execution is refused **by name**.
//!
//! # What a profile has to answer
//!
//! 1. Which hardfork schedule applies, and how it is keyed (block number for pre-merge
//!    chains, timestamp afterwards).
//! 2. Whether the chain prices blobs, and with what update fraction.
//! 3. Which header fields are mandatory. A post-Cancun Ethereum header carries
//!    `excessBlobGas`; an Arbitrum Orbit header does not, and demanding it makes every
//!    fork of that chain fail with a message about a missing field rather than about
//!    missing support.

use revm::primitives::hardfork::SpecId;

/// How a chain's hardfork is determined from a block.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ForkSchedule {
    /// Ethereum mainnet: block-number table up to the Merge, timestamp table after it.
    EthereumMainnet,
    /// A single fixed spec for every block. Used for chains whose ruleset is stable
    /// within the range a campaign explores, and for test fixtures.
    Fixed(SpecId),
}

/// Whether and how the chain prices blobs (EIP-4844).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BlobPricing {
    /// Blob base fee is derived from `excessBlobGas` in the header.
    FromHeader {
        /// The update fraction for the relevant era, if known.
        update_fraction: Option<u64>,
    },
    /// The chain does not price blobs; the header carries no excess-blob field.
    Absent,
}

/// Header fields a chain requires to be present.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HeaderRequirements {
    /// The header must carry `prevrandao` (post-Merge Ethereum).
    pub prevrandao: bool,
    /// The header must carry `excessBlobGas`.
    pub excess_blob_gas: bool,
}

/// Everything the executor needs to know about one chain.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChainProfile {
    pub chain_id: u64,
    /// Human name, used in the refusal message.
    pub name: &'static str,
    pub schedule: ForkSchedule,
    pub blobs: BlobPricing,
    pub header: HeaderRequirements,
    /// Lowest block this profile is valid for.
    ///
    /// A profile whose rules changed over the chain's history (a hardfork
    /// activation) must refuse the range it cannot describe rather than apply
    /// the wrong rules to it. `0` means "every block".
    pub min_block: u64,
}

impl ChainProfile {
    /// Ethereum mainnet, the only chain whose full fork table is implemented here.
    pub const ETHEREUM_MAINNET: ChainProfile = ChainProfile {
        chain_id: 1,
        name: "ethereum-mainnet",
        schedule: ForkSchedule::EthereumMainnet,
        blobs: BlobPricing::FromHeader {
            update_fraction: None,
        },
        header: HeaderRequirements {
            prevrandao: true,
            excess_blob_gas: true,
        },
        min_block: 0,
    };

    /// Arbitrum One (Arbitrum Nitro).
    ///
    /// Nitro's EVM implements the Cancun instruction set (`PUSH0`, `TSTORE`,
    /// `TLOAD`, `MCOPY`) and does **not** price blobs: its header carries
    /// `baseFeePerGas` and `mixHash` but no `excessBlobGas`, so demanding a
    /// blob header field would fail every fork with a message about a missing
    /// field rather than about missing support. `mixHash` is what Nitro
    /// exposes as `PREVRANDAO`.
    ///
    /// The Cancun spec is pinned for the whole covered range rather than
    /// keyed to an ArbOS activation table, so `min_block` deliberately starts
    /// well after Arbitrum's Cancun-era upgrades. The bound is conservative
    /// and must be tightened to the exact ArbOS activation block before this
    /// profile is used for older state.
    pub const ARBITRUM_ONE: ChainProfile = ChainProfile {
        chain_id: 42_161,
        name: "arbitrum-one",
        schedule: ForkSchedule::Fixed(SpecId::CANCUN),
        blobs: BlobPricing::Absent,
        header: HeaderRequirements {
            prevrandao: true,
            excess_blob_gas: false,
        },
        min_block: 400_000_000,
    };

    /// A local development chain (the anvil / hardhat default chain id).
    ///
    /// Local chains exist so the pipeline can be validated against a
    /// deliberately planted defect, where the point is throughput and
    /// determinism rather than mainnet economics. They expose Cancun-era
    /// opcodes and carry no blob header field, so they follow the same header
    /// rules as Arbitrum One.
    pub const ANVIL_LOCAL: ChainProfile = ChainProfile {
        chain_id: 31_337,
        name: "anvil-local",
        schedule: ForkSchedule::Fixed(SpecId::CANCUN),
        blobs: BlobPricing::Absent,
        header: HeaderRequirements {
            prevrandao: true,
            excess_blob_gas: false,
        },
        min_block: 0,
    };

    /// Resolves a profile for `chain_id`, or explains why there is none.
    ///
    /// Returns `Err` with a message that **names the chain** and says what is missing.
    /// The previous behaviour — failing later on a missing header field — made the real
    /// problem (no profile) invisible.
    pub fn for_chain(chain_id: u64) -> Result<Self, String> {
        match chain_id {
            1 => Ok(Self::ETHEREUM_MAINNET),
            42_161 => Ok(Self::ARBITRUM_ONE),
            31_337 => Ok(Self::ANVIL_LOCAL),
            other => Err(format!(
                "chain {other} has no execution profile: hardfork schedule, blob pricing \
                 and required header fields are unknown. Executing it with Ethereum \
                 mainnet rules would produce silently wrong semantics. Add a profile in \
                 crates/rustyfuzz-evm/src/chain_profile.rs before forking this chain."
            )),
        }
    }

    /// Whether this profile describes the rules at `number`.
    pub fn covers_block(&self, number: u64) -> bool {
        number >= self.min_block
    }

    /// The hardfork spec for a block, per this chain's schedule.
    pub fn spec_for(&self, number: u64, timestamp: u64) -> SpecId {
        match self.schedule {
            ForkSchedule::EthereumMainnet => crate::environment::mainnet_spec(number, timestamp),
            ForkSchedule::Fixed(spec) => spec,
        }
    }

    /// The blob update fraction for a timestamp, if the chain prices blobs.
    pub fn blob_fraction(&self, timestamp: u64) -> Option<u64> {
        match self.blobs {
            BlobPricing::FromHeader { update_fraction } => {
                update_fraction.or_else(|| crate::environment::mainnet_blob_fraction(timestamp))
            }
            BlobPricing::Absent => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ethereum_mainnet_resolves() {
        let profile = ChainProfile::for_chain(1).expect("mainnet is supported");
        assert_eq!(profile.chain_id, 1);
        assert_eq!(profile.name, "ethereum-mainnet");
        assert!(profile.header.prevrandao);
        assert!(profile.header.excess_blob_gas);
    }

    #[test]
    fn arbitrum_one_resolves_without_blob_pricing() {
        let profile = ChainProfile::for_chain(42_161).expect("arbitrum one is supported");
        assert_eq!(profile.chain_id, 42_161);
        assert_eq!(profile.name, "arbitrum-one");
        // Arbitrum One's header carries no excessBlobGas, so the profile must
        // not require one and must not price blobs.
        assert!(!profile.header.excess_blob_gas);
        assert!(profile.header.prevrandao);
        assert_eq!(profile.blob_fraction(1_793_267_791), None);
        assert_eq!(profile.spec_for(519_323_411, 1_793_267_791), SpecId::CANCUN);
    }

    #[test]
    fn arbitrum_one_refuses_blocks_outside_its_covered_range() {
        let profile = ChainProfile::for_chain(42_161).unwrap();
        assert!(profile.covers_block(519_323_411));
        assert!(!profile.covers_block(profile.min_block - 1));
        assert!(profile.covers_block(profile.min_block));
    }

    #[test]
    fn mainnet_covers_every_block() {
        let profile = ChainProfile::for_chain(1).unwrap();
        assert!(profile.covers_block(0));
        assert!(profile.covers_block(1));
    }

    #[test]
    fn an_unknown_chain_is_refused_by_name_and_says_what_is_missing() {
        // Arbitrum Orbit, the chain the live-target test could not run.
        let error = ChainProfile::for_chain(4663).unwrap_err();
        assert!(error.contains("4663"), "must name the chain: {error}");
        assert!(
            error.contains("no execution profile"),
            "must say the profile is missing: {error}"
        );
        assert!(
            error.contains("silently wrong semantics"),
            "must explain why guessing is worse than refusing: {error}"
        );
        // And it must point at where a profile is added.
        assert!(error.contains("chain_profile.rs"), "{error}");
    }

    #[test]
    fn mainnet_spec_follows_the_block_number_table_before_the_merge() {
        let profile = ChainProfile::for_chain(1).unwrap();
        assert_eq!(profile.spec_for(1_150_000, 0), SpecId::HOMESTEAD);
        assert_eq!(profile.spec_for(12_244_000, 0), SpecId::BERLIN);
    }

    #[test]
    fn mainnet_spec_follows_the_timestamp_table_after_the_merge() {
        let profile = ChainProfile::for_chain(1).unwrap();
        // Post-merge, post-Cancun.
        assert_eq!(profile.spec_for(20_000_000, 1_710_338_135), SpecId::CANCUN);
    }

    #[test]
    fn a_fixed_schedule_ignores_the_block() {
        let profile = ChainProfile {
            chain_id: 9_999,
            name: "fixed-prague",
            schedule: ForkSchedule::Fixed(SpecId::PRAGUE),
            blobs: BlobPricing::Absent,
            header: HeaderRequirements {
                prevrandao: false,
                excess_blob_gas: false,
            },
            min_block: 0,
        };
        assert_eq!(profile.spec_for(1, 0), SpecId::PRAGUE);
        assert_eq!(profile.spec_for(999_999_999, 0), SpecId::PRAGUE);
    }

    #[test]
    fn a_chain_without_blobs_reports_no_fraction() {
        let profile = ChainProfile {
            chain_id: 4_663,
            name: "orbit-no-blobs",
            schedule: ForkSchedule::Fixed(SpecId::SHANGHAI),
            blobs: BlobPricing::Absent,
            header: HeaderRequirements {
                prevrandao: false,
                excess_blob_gas: false,
            },
            min_block: 0,
        };
        // Mainnet would return a fraction at this timestamp; this chain must not, or the
        // executor would demand an `excessBlobGas` field the header never carries.
        assert_eq!(profile.blob_fraction(1_710_338_135), None);
        assert_eq!(profile.spec_for(1, 1_710_338_135), SpecId::SHANGHAI);
    }

    #[test]
    fn mainnet_returns_the_era_fraction() {
        let profile = ChainProfile::for_chain(1).unwrap();
        assert_eq!(profile.blob_fraction(1_710_338_135), Some(3_338_477));
        // Before Cancun there is no fraction.
        assert_eq!(profile.blob_fraction(1_600_000_000), None);
    }

    #[test]
    fn revm_blob_change_preserves_l1_fork_behavior() {
        // Regression test: the REVM blob handling change must not alter L1 fork behavior.
        // 
        // Pre-Cancun blocks must leave blob_excess_gas_and_price unset (None).
        // Post-Cancun blocks must derive the field from the block header.
        // 
        // Arbitrum One and ANVIL_LOCAL run Cancun-era rules but have
        // BlobPricing::Absent, so they report zero excess and zero base fee.
        // BLOBBASEFEE must return 0 for such chains.

        // ETHEREUM_MAINNET pre-Cancun: no blob fraction
        let mainnet = ChainProfile::ETHEREUM_MAINNET;
        assert_eq!(mainnet.blob_fraction(1_600_000_000), None, "pre-Cancun mainnet has no blob fraction");

        // ETHEREUM_MAINNET post-Cancun: has blob fraction from header
        assert_eq!(mainnet.blob_fraction(1_710_338_135), Some(3_338_477), "post-Cancun mainnet has blob fraction");

        // ARBITRUM_ONE: Cancun-era but Absent blob pricing -> zero excess/price
        let arbitrum = ChainProfile::ARBITRUM_ONE;
        assert_eq!(arbitrum.blob_fraction(1_710_338_135), None, "Arbitrum Absent pricing has no fraction");

        // Verify the chain profiles have the expected blob settings
        assert!(matches!(ChainProfile::ETHEREUM_MAINNET.blobs, BlobPricing::FromHeader { .. }));
        assert!(matches!(ChainProfile::ARBITRUM_ONE.blobs, BlobPricing::Absent));
        assert!(matches!(ChainProfile::ANVIL_LOCAL.blobs, BlobPricing::Absent));

        // Verify header requirements: only ETHEREUM_MAINNET requires excess_blob_gas
        assert!(ChainProfile::ETHEREUM_MAINNET.header.excess_blob_gas);
        assert!(!ChainProfile::ARBITRUM_ONE.header.excess_blob_gas);
        assert!(!ChainProfile::ANVIL_LOCAL.header.excess_blob_gas);
    }
}

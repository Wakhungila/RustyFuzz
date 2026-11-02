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
    };

    /// Resolves a profile for `chain_id`, or explains why there is none.
    ///
    /// Returns `Err` with a message that **names the chain** and says what is missing.
    /// The previous behaviour — failing later on a missing header field — made the real
    /// problem (no profile) invisible.
    pub fn for_chain(chain_id: u64) -> Result<Self, String> {
        match chain_id {
            1 => Ok(Self::ETHEREUM_MAINNET),
            other => Err(format!(
                "chain {other} has no execution profile: hardfork schedule, blob pricing \
                 and required header fields are unknown. Executing it with Ethereum \
                 mainnet rules would produce silently wrong semantics. Add a profile in \
                 crates/rustyfuzz-evm/src/chain_profile.rs before forking this chain."
            )),
        }
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
}

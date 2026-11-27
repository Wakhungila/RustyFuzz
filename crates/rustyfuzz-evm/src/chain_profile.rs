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
    /// Ascending `(activation_unix_timestamp, spec)` table. The spec of the last
    /// entry whose activation is `<= timestamp` applies; before the first entry the
    /// profile does not describe the chain (see [`ChainProfile::min_timestamp`]).
    ByTimestamp(&'static [(u64, SpecId)]),
    /// Ascending `(activation_block_number, spec)` table, for chains whose client
    /// keys forks by block height (Polygon PoS / Bor).
    ByBlock(&'static [(u64, SpecId)]),
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
    /// Lowest block timestamp (unix seconds) this profile is valid for. Checked
    /// once the block header is known, because several clients key their forks by
    /// time rather than height. `0` means "every timestamp".
    pub min_timestamp: u64,
    /// Known semantic gaps a reader must be told about before trusting a finding
    /// on this chain (chain-specific precompiles, system contracts). Empty when
    /// the chain is plain-EVM equivalent over the covered range.
    pub caveats: &'static str,
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
        min_timestamp: 0,
        caveats: "",
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
        min_timestamp: 0,
        caveats:
            "ArbOS precompiles (ArbSys, ArbInfo, ...) and L1-pricing semantics are not modeled",
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
        min_timestamp: 0,
        caveats: "",
    };

    /// BNB Smart Chain (chain id 56).
    ///
    /// Activation times are `BSCChainConfig` from bnb-chain/bsc `params/config.go`.
    /// Shanghai (and Kepler) activate together, Cancun with Haber, Prague with
    /// Pascal, and Osaka with Mendel. The covered range starts at Shanghai because
    /// earlier BSC blocks predate `PUSH0` and are not described by any table here.
    /// BSC has no beacon randomness (`difficulty`/`mixHash` are not `PREVRANDAO`)
    /// and its headers carry no blob fields.
    pub const BSC: ChainProfile = ChainProfile {
        chain_id: 56,
        name: "bsc",
        schedule: ForkSchedule::ByTimestamp(&[
            (1_705_996_800, SpecId::SHANGHAI),
            (1_718_863_500, SpecId::CANCUN),
            (1_742_436_600, SpecId::PRAGUE),
            (1_777_343_400, SpecId::OSAKA),
        ]),
        blobs: BlobPricing::Absent,
        header: HeaderRequirements {
            prevrandao: false,
            excess_blob_gas: false,
        },
        min_block: 0,
        min_timestamp: 1_705_996_800,
        caveats: "BSC-specific precompiles (tendermint/iavl/cometbft light-client verification, \
                  double-sign evidence) and the system-contract hooks are not modeled; \
                  contracts depending on them will revert",
    };

    /// Polygon PoS (chain id 137).
    ///
    /// Block heights are `BorMainnetChainConfig` from 0xPolygon/bor
    /// `params/config.go`: Shanghai 50_523_000, Cancun 54_876_000, Prague
    /// 73_440_256 (Bhilai). Bor has no beacon randomness.
    pub const POLYGON_POS: ChainProfile = ChainProfile {
        chain_id: 137,
        name: "polygon-pos",
        schedule: ForkSchedule::ByBlock(&[
            (50_523_000, SpecId::SHANGHAI),
            (54_876_000, SpecId::CANCUN),
            (73_440_256, SpecId::PRAGUE),
        ]),
        blobs: BlobPricing::Absent,
        header: HeaderRequirements {
            prevrandao: false,
            excess_blob_gas: false,
        },
        min_block: 50_523_000,
        min_timestamp: 0,
        caveats: "Bor state-sync, the MATIC/POL system contracts and Polygon-specific \
                  precompiles are not modeled",
    };

    /// OP Mainnet (chain id 10). Superchain-wide activation timestamps from the
    /// Optimism network-upgrades registry: Ecotone (Cancun) 1710374401.
    /// Isthmus (Prague) is deliberately not modeled: it adds precompiles and
    /// EIP-7702 but no opcodes, and treating it as Cancun is the conservative error.
    pub const OP_MAINNET: ChainProfile = ChainProfile {
        chain_id: 10,
        name: "op-mainnet",
        schedule: ForkSchedule::ByTimestamp(&[(1_710_374_401, SpecId::CANCUN)]),
        blobs: BlobPricing::Absent,
        header: HeaderRequirements {
            prevrandao: true,
            excess_blob_gas: false,
        },
        min_block: 0,
        min_timestamp: 1_710_374_401,
        caveats: "OP Stack L1-fee accounting, the L1Block/GasPriceOracle predeploys and \
                  deposit transactions are not modeled; Isthmus precompiles (BLS12-381, \
                  EIP-7702) are not enabled",
    };

    /// Base (chain id 8453). Ecotone (Cancun) activated at 1710374401, per the
    /// Base upgrade documentation. Same caveats as OP Mainnet.
    pub const BASE: ChainProfile = ChainProfile {
        chain_id: 8_453,
        name: "base",
        schedule: ForkSchedule::ByTimestamp(&[(1_710_374_401, SpecId::CANCUN)]),
        blobs: BlobPricing::Absent,
        header: HeaderRequirements {
            prevrandao: true,
            excess_blob_gas: false,
        },
        min_block: 0,
        min_timestamp: 1_710_374_401,
        caveats: "OP Stack L1-fee accounting, the L1Block/GasPriceOracle predeploys and \
                  deposit transactions are not modeled; Isthmus precompiles (BLS12-381, \
                  EIP-7702) are not enabled",
    };

    /// Avalanche C-Chain (chain id 43114). Activation times from avalanchego
    /// `upgrade/upgrade.go`: Durango (Shanghai) 1709740800, Etna (the Cancun EIPs
    /// of ACP-131, without blob transactions) 1734368400. No beacon randomness.
    pub const AVALANCHE_C: ChainProfile = ChainProfile {
        chain_id: 43_114,
        name: "avalanche-c",
        schedule: ForkSchedule::ByTimestamp(&[
            (1_709_740_800, SpecId::SHANGHAI),
            (1_734_368_400, SpecId::CANCUN),
        ]),
        blobs: BlobPricing::Absent,
        header: HeaderRequirements {
            prevrandao: false,
            excess_blob_gas: false,
        },
        min_block: 0,
        min_timestamp: 1_709_740_800,
        caveats: "Warp messaging and the deprecated native-asset-call precompiles are not \
                  modeled",
    };

    /// Every profile this build can execute.
    pub const ALL: [ChainProfile; 8] = [
        Self::ETHEREUM_MAINNET,
        Self::BSC,
        Self::POLYGON_POS,
        Self::OP_MAINNET,
        Self::BASE,
        Self::AVALANCHE_C,
        Self::ARBITRUM_ONE,
        Self::ANVIL_LOCAL,
    ];

    /// Resolves a CLI `--chain` name (`evm`, `bsc`, `polygon`, `base`, ...) to a
    /// chain id. `evm` and the empty name mean "decided by the RPC", returned as
    /// `Ok(None)`. Unknown names are refused with the list of accepted ones.
    pub fn id_for_cli_name(name: &str) -> Result<Option<u64>, String> {
        let id = match name.trim().to_ascii_lowercase().as_str() {
            "evm" | "" => return Ok(None),
            "eth" | "ethereum" | "mainnet" => 1,
            "bsc" | "bnb" | "bnb-chain" => 56,
            "polygon" | "polygon-pos" | "matic" => 137,
            "optimism" | "op" | "op-mainnet" => 10,
            "base" => 8_453,
            "avalanche" | "avax" | "avalanche-c" => 43_114,
            "arbitrum" | "arbitrum-one" | "arb" => 42_161,
            other => {
                return Err(format!(
                    "unsupported --chain `{other}`; expected evm, eth, bsc, polygon, optimism, \
                     base, avalanche or arbitrum"
                ))
            }
        };
        Ok(Some(id))
    }

    /// Resolves a profile for `chain_id`, or explains why there is none.
    ///
    /// Returns `Err` with a message that **names the chain** and says what is missing.
    /// The previous behaviour — failing later on a missing header field — made the real
    /// problem (no profile) invisible.
    pub fn for_chain(chain_id: u64) -> Result<Self, String> {
        match Self::ALL
            .iter()
            .find(|profile| profile.chain_id == chain_id)
        {
            Some(profile) => Ok(*profile),
            None => {
                let other = chain_id;
                Err(format!(
                    "chain {other} has no execution profile: hardfork schedule, blob pricing \
                 and required header fields are unknown. Executing it with Ethereum \
                 mainnet rules would produce silently wrong semantics. Add a profile in \
                 crates/rustyfuzz-evm/src/chain_profile.rs before forking this chain."
                ))
            }
        }
    }

    /// Whether this profile describes the rules at `number`.
    pub fn covers_block(&self, number: u64) -> bool {
        number >= self.min_block
    }

    /// Whether this profile describes the rules at a block timestamp. Chains whose
    /// forks are keyed by time cannot be checked from the block number alone, so
    /// this is evaluated once the header is known.
    pub fn covers_timestamp(&self, timestamp: u64) -> bool {
        timestamp >= self.min_timestamp
    }

    /// The hardfork spec for a block, per this chain's schedule.
    pub fn spec_for(&self, number: u64, timestamp: u64) -> SpecId {
        match self.schedule {
            ForkSchedule::EthereumMainnet => crate::environment::mainnet_spec(number, timestamp),
            ForkSchedule::Fixed(spec) => spec,
            ForkSchedule::ByTimestamp(table) => spec_from_table(table, timestamp),
            ForkSchedule::ByBlock(table) => spec_from_table(table, number),
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

/// The spec of the last table entry whose activation key is `<= key`. A key before
/// the first entry resolves to that first entry: the profile's `min_block` /
/// `min_timestamp` is what refuses such inputs, so the table never has to guess.
fn spec_from_table(table: &[(u64, SpecId)], key: u64) -> SpecId {
    table
        .iter()
        .rev()
        .find(|(activation, _)| key >= *activation)
        .or_else(|| table.first())
        .map(|(_, spec)| *spec)
        .expect("a fork table has at least one entry")
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
            min_timestamp: 0,
            caveats: "",
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
            min_timestamp: 0,
            caveats: "",
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
    // The assertions below intentionally pin constants: they fail loudly if a
    // chain profile's blob header flags ever drift, which is exactly the
    // regression this test guards.
    #[allow(clippy::assertions_on_constants)]
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
        assert_eq!(
            mainnet.blob_fraction(1_600_000_000),
            None,
            "pre-Cancun mainnet has no blob fraction"
        );

        // ETHEREUM_MAINNET post-Cancun: has blob fraction from header
        assert_eq!(
            mainnet.blob_fraction(1_710_338_135),
            Some(3_338_477),
            "post-Cancun mainnet has blob fraction"
        );

        // ARBITRUM_ONE: Cancun-era but Absent blob pricing -> zero excess/price
        let arbitrum = ChainProfile::ARBITRUM_ONE;
        assert_eq!(
            arbitrum.blob_fraction(1_710_338_135),
            None,
            "Arbitrum Absent pricing has no fraction"
        );

        // Verify the chain profiles have the expected blob settings
        assert!(matches!(
            ChainProfile::ETHEREUM_MAINNET.blobs,
            BlobPricing::FromHeader { .. }
        ));
        assert!(matches!(
            ChainProfile::ARBITRUM_ONE.blobs,
            BlobPricing::Absent
        ));
        assert!(matches!(
            ChainProfile::ANVIL_LOCAL.blobs,
            BlobPricing::Absent
        ));

        // Verify header requirements: only ETHEREUM_MAINNET requires excess_blob_gas
        assert!(ChainProfile::ETHEREUM_MAINNET.header.excess_blob_gas);
        assert!(!ChainProfile::ARBITRUM_ONE.header.excess_blob_gas);
        assert!(!ChainProfile::ANVIL_LOCAL.header.excess_blob_gas);
    }

    #[test]
    fn every_profile_is_resolvable_by_its_own_chain_id() {
        for profile in ChainProfile::ALL {
            let resolved = ChainProfile::for_chain(profile.chain_id).expect("listed profile");
            assert_eq!(resolved, profile);
        }
        let mut ids: Vec<u64> = ChainProfile::ALL.iter().map(|p| p.chain_id).collect();
        ids.sort_unstable();
        ids.dedup();
        assert_eq!(
            ids.len(),
            ChainProfile::ALL.len(),
            "duplicate chain id in ALL"
        );
    }

    #[test]
    fn bsc_follows_its_timestamp_table_and_has_no_prevrandao_or_blobs() {
        let p = ChainProfile::for_chain(56).unwrap();
        assert!(!p.header.prevrandao && !p.header.excess_blob_gas);
        assert_eq!(p.blob_fraction(1_718_863_500), None);
        assert!(!p.covers_timestamp(1_705_996_799));
        assert!(p.covers_timestamp(1_705_996_800));
        assert_eq!(p.spec_for(40_000_000, 1_705_996_800), SpecId::SHANGHAI);
        assert_eq!(p.spec_for(40_000_000, 1_718_863_499), SpecId::SHANGHAI);
        assert_eq!(p.spec_for(40_000_000, 1_718_863_500), SpecId::CANCUN);
        assert_eq!(p.spec_for(50_000_000, 1_742_436_600), SpecId::PRAGUE);
        assert_eq!(p.spec_for(60_000_000, 1_777_343_400), SpecId::OSAKA);
        assert!(
            !p.caveats.is_empty(),
            "BSC precompile gap must be disclosed"
        );
    }

    #[test]
    fn polygon_is_keyed_by_block_height() {
        let p = ChainProfile::for_chain(137).unwrap();
        assert!(!p.covers_block(50_522_999));
        assert!(p.covers_block(50_523_000));
        assert_eq!(p.spec_for(50_523_000, 0), SpecId::SHANGHAI);
        assert_eq!(p.spec_for(54_875_999, 0), SpecId::SHANGHAI);
        assert_eq!(p.spec_for(54_876_000, 0), SpecId::CANCUN);
        assert_eq!(p.spec_for(73_440_255, 0), SpecId::CANCUN);
        assert_eq!(p.spec_for(73_440_256, 0), SpecId::PRAGUE);
        // Timestamps are irrelevant to a height-keyed chain.
        assert_eq!(p.spec_for(54_876_000, u64::MAX), SpecId::CANCUN);
    }

    #[test]
    fn op_stack_chains_share_ecotone_and_stay_conservative_on_isthmus() {
        for id in [10, 8_453] {
            let p = ChainProfile::for_chain(id).unwrap();
            assert!(p.header.prevrandao && !p.header.excess_blob_gas);
            assert!(!p.covers_timestamp(1_710_374_400));
            assert!(p.covers_timestamp(1_710_374_401));
            assert_eq!(p.spec_for(1, 1_710_374_401), SpecId::CANCUN);
            // Isthmus (1_746_806_401) adds no opcodes; Cancun stays the modeled spec.
            assert_eq!(p.spec_for(1, 1_800_000_000), SpecId::CANCUN);
        }
    }

    #[test]
    fn avalanche_c_chain_gains_cancun_with_etna() {
        let p = ChainProfile::for_chain(43_114).unwrap();
        assert!(!p.header.prevrandao);
        assert!(!p.covers_timestamp(1_709_740_799));
        assert_eq!(p.spec_for(1, 1_709_740_800), SpecId::SHANGHAI);
        assert_eq!(p.spec_for(1, 1_734_368_399), SpecId::SHANGHAI);
        assert_eq!(p.spec_for(1, 1_734_368_400), SpecId::CANCUN);
    }

    #[test]
    fn cli_names_map_to_chain_ids_and_unknown_names_list_the_accepted_ones() {
        assert_eq!(ChainProfile::id_for_cli_name("evm"), Ok(None));
        assert_eq!(ChainProfile::id_for_cli_name("BSC"), Ok(Some(56)));
        assert_eq!(ChainProfile::id_for_cli_name("matic"), Ok(Some(137)));
        assert_eq!(ChainProfile::id_for_cli_name("op"), Ok(Some(10)));
        assert_eq!(ChainProfile::id_for_cli_name("base"), Ok(Some(8_453)));
        assert_eq!(ChainProfile::id_for_cli_name("avax"), Ok(Some(43_114)));
        let error = ChainProfile::id_for_cli_name("solana").unwrap_err();
        assert!(
            error.contains("solana") && error.contains("polygon"),
            "{error}"
        );
    }

    #[test]
    fn a_table_never_resolves_below_its_first_entry_to_something_invented() {
        // Refusal is the job of min_block / min_timestamp; the table itself must
        // not pick a spec the profile never described.
        let p = ChainProfile::for_chain(56).unwrap();
        assert_eq!(p.spec_for(1, 0), SpecId::SHANGHAI);
        assert!(!p.covers_timestamp(0));
    }
}

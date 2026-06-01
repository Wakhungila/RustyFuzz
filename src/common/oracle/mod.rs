use crate::common::types::Snapshot;
use serde::{Deserialize, Serialize};

pub trait VulnerabilityOracle {
    fn check(&self, before: &Snapshot, after: &Snapshot) -> Option<VulnType>;
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum VulnType {
    Reentrancy,
    FlashLoanProfit,
    IntegerOverflow,
    ReadOnlyReentrancy,
    TokenCallbackReentrancy,
    VaultDonationAttack,
    VaultInflation,
    SvmCpiPrivilegeEscalation,
    PrivilegeEscalation,
    FlashLoanAttack,
    PriceManipulation,
    PrecisionLossExploit,
    RoundingLeakage,
    MissingSignerCheck,
    UniswapV3LiquidityAsymmetry,
    AccountingDesync,
    GovernanceTakeover,
    PriceOracleManipulation,
    SystemicStateCorruption,
    InvariantViolation(String),
    UnintendedPanic(u64),
    GovernanceParameterManipulation,
    ProxyUpgradeabilityViolation,
    PersistenceFailure,
    RebalanceValueLoss,
    MevSandwichExploit,
    CrossContractDesync,
    SvmPdaCollision,
    DifferentialDivergence(String),
    Other(String),
}

impl std::fmt::Display for VulnType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}

/// CustomInvariant trait: Allows researchers to define their own protocol-specific
/// economic or logical invariants.
pub trait CustomInvariant: Send + Sync + 'static {
    fn name(&self) -> &str;
    fn check_invariant(&self, before: &Snapshot, after: &Snapshot) -> Option<VulnType>;
}

// Re-export oracle modules
pub mod defi;
pub mod governance;
pub mod mev;
pub mod packs;
pub mod protocol_invariants;
pub mod security;
pub mod svm;

// Re-export common oracle implementations
pub use defi::*;
pub use governance::*;
pub use mev::*;
pub use packs::*;
pub use protocol_invariants::*;
pub use security::*;
pub use svm::*;

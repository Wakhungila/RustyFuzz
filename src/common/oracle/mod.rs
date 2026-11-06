use crate::common::types::Snapshot;
use serde::{Deserialize, Serialize};

pub trait VulnerabilityOracle {
    fn check(&self, before: &Snapshot, after: &Snapshot) -> Option<VulnType>;
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum FindingStatus {
    #[default]
    Lead,
    Replayed,
    Minimized,
    Proved,
    Rejected,
}

impl FindingStatus {
    /// Maps the legacy status onto the canonical Stage 2D lifecycle.
    ///
    /// TODO(stage-4): retire this compatibility mapping once callers consume
    /// `rustyfuzz_core::FindingLifecycle` directly.
    pub fn canonical(&self) -> rustyfuzz_core::FindingLifecycle {
        match self {
            FindingStatus::Lead => rustyfuzz_core::FindingLifecycle::Signal,
            FindingStatus::Replayed => rustyfuzz_core::FindingLifecycle::Replayed,
            FindingStatus::Minimized => rustyfuzz_core::FindingLifecycle::Minimized,
            FindingStatus::Proved => rustyfuzz_core::FindingLifecycle::Proved,
            FindingStatus::Rejected => rustyfuzz_core::FindingLifecycle::Rejected,
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum EvidenceGrade {
    #[default]
    Heuristic,
    DeterministicReplay,
    RealisticForkProof,
    RegressionTested,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum RejectionReason {
    SyntheticFundingRequired,
    MissingAllowance,
    MissingBalance,
    PrivilegedRoleRequired,
    NonDeterministic,
    OracleWeakness,
    ReplayFailed,
    MinimizedAway,
    OutOfScope,
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
    BridgeInvariantViolation,
    SvmPdaCollision,
    DifferentialDivergence(String),
    Other(String),
}

impl std::fmt::Display for VulnType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}

/// The meaning of Solidity's `Panic(uint256)` codes.
///
/// A panic is a *revert*, not a state change: the transaction is rolled back
/// atomically, so the code says what the contract rejected, never that state
/// was corrupted. The distinction matters for triage — an out-of-bounds index
/// can be an unchecked index (a real defect) or a rejected garbage argument
/// (a failed call with an unfriendly error), and only the source can say
/// which.
pub fn describe_panic_code(code: u64) -> &'static str {
    match code {
        0x01 => "failed assertion or invariant check",
        0x11 => "arithmetic overflow or underflow",
        0x12 => "division or modulo by zero",
        0x21 => "invalid enum value converted to an integer",
        0x22 => "invalid storage byte array encoding",
        0x31 => "pop() on an empty array",
        0x32 => "array index out of bounds",
        0x41 => "too much memory allocated or array too large",
        0x51 => "call to a zero-initialized internal function pointer",
        _ => "unknown panic code",
    }
}

/// Whether a panic code can indicate a logic defect rather than a rejected
/// argument.
///
/// The codes below `0x20` are Solidity's own input and arithmetic guards: the
/// contract did exactly what it is supposed to do when it rejected the call.
/// A broken invariant, an unchecked index, or a call through an
/// uninitialised function pointer can each be a genuine defect, but even those
/// are only a *lead*: the revert is atomic, so proving harm needs a replay
/// that shows funds stuck, a path blocked, or accounting corrupted.
pub fn panic_code_can_indicate_defect(code: u64) -> bool {
    matches!(code, 0x01 | 0x31 | 0x32 | 0x51)
}

#[cfg(test)]
mod panic_code_tests {
    use super::*;

    #[test]
    fn panic_codes_are_described_by_their_real_meaning() {
        // The codes that are routinely confused: 0x01 is an assertion, 0x32 is
        // an out-of-bounds array index.
        assert_eq!(
            describe_panic_code(0x01),
            "failed assertion or invariant check"
        );
        assert_eq!(describe_panic_code(0x32), "array index out of bounds");
        assert_eq!(describe_panic_code(0x11), "arithmetic overflow or underflow");
        assert_eq!(describe_panic_code(0x12), "division or modulo by zero");
        assert_eq!(describe_panic_code(0x31), "pop() on an empty array");
        assert_eq!(describe_panic_code(0x51), "call to a zero-initialized internal function pointer");
        assert_eq!(describe_panic_code(0xdead), "unknown panic code");
    }

    #[test]
    fn only_codes_that_can_reveal_a_defect_are_rated_above_input_guards() {
        // A broken invariant, an unchecked index, an empty pop and a call
        // through an uninitialised pointer can each be a real defect.
        for code in [0x01u64, 0x31, 0x32, 0x51] {
            assert!(
                panic_code_can_indicate_defect(code),
                "0x{code:x} should be treated as a possible defect"
            );
        }
        // Solidity's own input and arithmetic guards are the contract working
        // as intended, not evidence of a defect.
        for code in [0x11u64, 0x12, 0x21, 0x22, 0x41, 0x99] {
            assert!(
                !panic_code_can_indicate_defect(code),
                "0x{code:x} must not be treated as a possible defect"
            );
        }
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

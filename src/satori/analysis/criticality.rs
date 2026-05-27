use crate::satori::types::{DetectorSignal, FunctionSummary};

pub fn score_function(function: &FunctionSummary) -> f64 {
    let mut score: f64 = 0.0;
    if matches!(function.visibility.as_str(), "public" | "external") {
        score += 0.25;
    }
    if !matches!(function.mutability.as_str(), "view" | "pure") {
        score += 0.20;
    }
    if has_signal(&function.detector_signals, "token-transfer") {
        score += 0.15;
    }
    if touches_accounting(&function.source_snippet) {
        score += 0.15;
    }
    if has_signal(&function.detector_signals, "oracle-read") {
        score += 0.10;
    }
    if has_signal(&function.detector_signals, "access-control") {
        score += 0.10;
    }
    if has_signal(&function.detector_signals, "upgradeability-init") {
        score += 0.05;
    }
    if has_signal(&function.detector_signals, "low-level-call") {
        score += 0.05;
    }
    score += name_boost(&function.name);
    if matches!(function.mutability.as_str(), "view" | "pure") {
        score -= 0.15;
    }
    if matches!(function.visibility.as_str(), "internal" | "private") {
        score -= 0.10;
    }
    score.clamp(0.0, 1.0)
}

fn has_signal(signals: &[DetectorSignal], tag: &str) -> bool {
    signals.iter().any(|signal| signal.tag == tag)
}

fn touches_accounting(snippet: &str) -> bool {
    let lower = snippet.to_ascii_lowercase();
    [
        "balance",
        "shares",
        "totalsupply",
        "totalassets",
        "reserve",
        "debt",
        "collateral",
        "allowance",
    ]
    .iter()
    .any(|needle| lower.contains(needle))
}

fn name_boost(name: &str) -> f64 {
    let lower = name.to_ascii_lowercase();
    [
        "deposit",
        "withdraw",
        "redeem",
        "mint",
        "burn",
        "borrow",
        "repay",
        "liquidate",
        "swap",
        "claim",
        "harvest",
        "rebalance",
        "execute",
        "initialize",
        "upgradeto",
        "setoracle",
        "setprice",
        "setcollateralfactor",
        "setreservefactor",
        "setstrategy",
        "sync",
        "skim",
        "vote",
        "queue",
        "executeproposal",
    ]
    .iter()
    .filter(|needle| lower.contains(**needle))
    .count() as f64
        * 0.06
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::satori::types::{ExternalCallSummary, StateAccess};
    use std::path::PathBuf;

    fn function(name: &str, mutability: &str) -> FunctionSummary {
        FunctionSummary {
            id: name.to_string(),
            contract: "Vault".to_string(),
            name: name.to_string(),
            signature: format!("{name}()"),
            selector: None,
            file: PathBuf::from("Vault.sol"),
            visibility: "external".to_string(),
            mutability: mutability.to_string(),
            modifiers: Vec::new(),
            source_snippet: "shares += assets; totalAssets();".to_string(),
            reads: Vec::<StateAccess>::new(),
            writes: Vec::<StateAccess>::new(),
            internal_calls: Vec::new(),
            external_calls: Vec::<ExternalCallSummary>::new(),
            detector_signals: Vec::new(),
            criticality_score: 0.0,
        }
    }

    #[test]
    fn criticality_scores_state_changing_flows_above_getters() {
        assert!(
            score_function(&function("deposit", "nonpayable"))
                > score_function(&function("asset", "view"))
        );
    }
}

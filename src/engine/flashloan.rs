use crate::engine::economic_delta::EconomicDeltaReport;
use crate::evm::fuzz::EvmInput;
use revm::primitives::{Address, U256};
use serde::{Deserialize, Serialize};

pub const EIP3156_FLASHLOAN_SELECTOR: [u8; 4] = [0x5c, 0x19, 0xe9, 0x51];

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FlashLoanTemplate {
    pub lender: Address,
    pub receiver: Address,
    pub token: Address,
    pub amount: U256,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FlashLoanValidation {
    pub attempted: bool,
    pub repaid: bool,
    pub net_profit: U256,
    pub confirmed: bool,
    pub reason: String,
}

impl FlashLoanTemplate {
    pub fn wrap_sequence(&self, mut input: EvmInput) -> EvmInput {
        let payload = postcard::to_allocvec(&input.txs).unwrap_or_default();
        let mut calldata = EIP3156_FLASHLOAN_SELECTOR.to_vec();
        calldata.extend_from_slice(&[0u8; 12]);
        calldata.extend_from_slice(self.receiver.as_slice());
        calldata.extend_from_slice(&[0u8; 12]);
        calldata.extend_from_slice(self.token.as_slice());
        calldata.extend_from_slice(&self.amount.to_be_bytes::<32>());
        calldata.extend_from_slice(&U256::from(128).to_be_bytes::<32>());
        calldata.extend_from_slice(&U256::from(payload.len()).to_be_bytes::<32>());
        calldata.extend_from_slice(&payload);

        input.txs = vec![crate::common::types::SingletonTx {
            input: calldata,
            caller: self.receiver,
            to: self.lender,
            value: U256::ZERO,
            is_victim: false,
        }];
        input
    }
}

pub fn validate_flashloan_profit(report: &EconomicDeltaReport) -> FlashLoanValidation {
    let attempted = report.flashloan_pressure || !report.flashloan_signals.is_empty();
    let net_profit = report.estimated_profit;
    let repaid = attempted
        && report
            .flashloan_signals
            .iter()
            .all(|signal| signal.is_repaid || signal.net_unrepaid <= net_profit);
    let confirmed = attempted
        && repaid
        && report.suspicious_value_extraction
        && report.normalized_profit.is_some()
        && !net_profit.is_zero();
    FlashLoanValidation {
        attempted,
        repaid,
        net_profit,
        confirmed,
        reason: if confirmed {
            "flash-loan sequence repaid and retained positive normalized profit".to_string()
        } else if attempted {
            "flash-loan pressure observed but repayment/profit proof is incomplete".to_string()
        } else {
            "no flash-loan-shaped path observed".to_string()
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::economic_delta::{FlashLoanSignal, NormalizedProfit};

    #[test]
    fn flashloan_calldata_round_trips_postcard_transaction_payload() {
        let input = EvmInput {
            txs: vec![crate::common::types::SingletonTx {
                input: vec![0xde, 0xad],
                caller: Address::repeat_byte(0x11),
                to: Address::repeat_byte(0x22),
                value: U256::from(3),
                is_victim: false,
            }],
            base_snapshot_id: 0,
        };
        let template = FlashLoanTemplate {
            lender: Address::repeat_byte(0x33),
            receiver: Address::repeat_byte(0x44),
            token: Address::repeat_byte(0x55),
            amount: U256::from(7),
        };

        let wrapped = template.wrap_sequence(input.clone());
        let payload = &wrapped.txs[0].input[164..];
        let decoded: Vec<crate::common::types::SingletonTx> =
            postcard::from_bytes(payload).unwrap();
        assert_eq!(decoded, input.txs);
    }

    #[test]
    fn flashloan_validation_requires_repayment_and_profit() {
        let report = EconomicDeltaReport {
            estimated_profit: U256::from(10),
            suspicious_value_extraction: true,
            flashloan_pressure: true,
            flashloan_signals: vec![FlashLoanSignal {
                tx_index: 0,
                lender: Address::new([1; 20]),
                token: Address::new([2; 20]),
                amount: U256::from(5),
                fee: U256::ZERO,
                is_repaid: true,
                net_unrepaid: U256::ZERO,
                confidence: 90,
            }],
            normalized_profit: Some(NormalizedProfit {
                raw_profit: U256::from(10),
                denominator: U256::from(100),
                profit_bps: 1000,
                confidence: 90,
                method: "test".to_string(),
            }),
            ..EconomicDeltaReport::default()
        };
        let validation = validate_flashloan_profit(&report);
        assert!(validation.confirmed);
        assert_eq!(validation.net_profit, U256::from(10));
    }
}

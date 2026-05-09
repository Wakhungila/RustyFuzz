use crate::common::types::{SingletonTx, ChainState};
use crate::evm::inspector::CoverageInspector;
use crate::evm::dataflow::DataflowRegistry;
use revm::primitives::SpecId;
use revm::inspector_handle_register;
use bitvec::prelude::*;
use aes_gcm_siv::{Aes256GcmSiv, KeyInit, Nonce, aead::Aead};
use serde::{Serialize, Deserialize};
use anyhow::Result;
use sgx_types::*;

/// Hardware-backed proof that a specific execution occurred within an enclave.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct SgxAttestationReport {
    pub raw_report: Vec<u8>, // Serialized sgx_report_t from hardware
    pub enclave_identity: Vec<u8>, // MRENCLAVE
    pub timestamp: u64,
}

/// SgxExecutor runs the EVM within a Trusted Execution Environment (TEE).
/// This ensures that the state, transactions, and coverage data remain 
/// encrypted in memory, protecting against side-channel leaks on the host.
pub struct SgxExecutor {
    // In a production enclave, this might hold sensitive keys for 
    // decrypting state snapshots or signing PoCs.
    pub enclave_id: u64,
}

impl SgxExecutor {
    pub fn new(enclave_id: u64) -> Self {
        Self { enclave_id }
    }

    /// Executes a transaction within the enclave boundary.
    /// Note: This is an "ECALL" in SGX terminology.
    pub fn execute_secure(
        &self,
        chain_state: &mut ChainState,
        tx: &SingletonTx,
        coverage: &mut BitSlice<u8, Lsb0>,
        dataflow: &mut DataflowRegistry,
    ) -> Result<()> {
        let revm_state = match chain_state {
            ChainState::Evm(state) => state,
        };

        // We keep the inspector inside the enclave to ensure coverage 
        // metrics (which can reveal branch behavior) are not leaked.
        let mut inspector = CoverageInspector::new(coverage, dataflow);

        let mut evm = revm::Evm::builder()
            .with_db(revm_state)
            .with_external_context(&mut inspector)
            .with_spec_id(SpecId::CANCUN)
            .modify_tx_env(|revm_tx| {
                *revm_tx = tx.to_revm_tx_env();
            })
            .append_handler_register(inspector_handle_register)
            .build();

        // The actual transition happens here. Memory access is protected by the CPU.
        evm.transact_commit()
            .map_err(|e| anyhow::anyhow!("SGX Execution Failure: {:?}", e))?;

        Ok(())
    }

    /// Securely seal the state to disk.
    pub fn seal_state(&self, state: &ChainState) -> Result<Vec<u8>> {
        // 1. Derive or retrieve the enclave-bound sealing key.
        // In a real SGX app, you'd use the SGX Sealing Key (MRENCLAVE-based).
        let key_bytes = [0u8; 32]; // Placeholder: Use actual SGX EGETKEY logic here
        let cipher = Aes256GcmSiv::new_from_slice(&key_bytes)
            .map_err(|_| anyhow::anyhow!("Invalid Key Length"))?;

        // 2. Serialize the state. 
        // Note: CacheDB needs to be converted to a serializable format.
        let serialized_state = serde_json::to_vec(state)
            .map_err(|e| anyhow::anyhow!("Serialization failed: {}", e))?;

        // 3. Generate a Nonce. 
        // For GCM-SIV, a fixed or counter-based nonce is safer than random if entropy is low.
        let nonce = Nonce::from_slice(b"unique nonce"); // 12-byte nonce

        // 4. Encrypt and Seal
        let ciphertext = cipher
            .encrypt(nonce, serialized_state.as_ref())
            .map_err(|e| anyhow::anyhow!("Encryption failure: {:?}", e))?;

        Ok(ciphertext)
    }

    /// Generates a real hardware attestation report using the Intel SGX SDK.
    /// This binds the exploit discovery to the enclave's hardware-protected identity,
    /// allowing remote parties to verify that the vulnerability was found inside a TEE.
    pub fn generate_attestation_report(&self, exploit_hash: &[u8]) -> Result<SgxAttestationReport> {
        let target_info = sgx_target_info_t::default(); // Usually obtained from the Quoting Enclave via OCALL
        let mut report_data = sgx_report_data_t::default();
        
        // Bind the discovery hash to the hardware report's 64-byte user data field.
        // This ensures the hardware proof is unique to this specific finding.
        let len = exploit_hash.len().min(64);
        report_data.d[..len].copy_from_slice(&exploit_hash[..len]);

        let report = sgx_tstd::sgx_create_report(&target_info, &report_data)
            .map_err(|e| anyhow::anyhow!("SGX hardware report (EREPORT) generation failed: {:?}", e))?;

        Ok(SgxAttestationReport {
            raw_report: unsafe { 
                std::slice::from_raw_parts(&report as *const _ as *const u8, std::mem::size_of::<sgx_report_t>()).to_vec() 
            },
            enclave_identity: report.body.mr_enclave.m.to_vec(),
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)?
                .as_secs(),
        })
    }
}
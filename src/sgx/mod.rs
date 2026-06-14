#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SgxSupportStatus {
    Unsupported,
}

pub fn support_status() -> SgxSupportStatus {
    SgxSupportStatus::Unsupported
}

pub fn ensure_supported() -> anyhow::Result<()> {
    anyhow::bail!(
        "SGX execution is not implemented in RustyFuzz; use the EVM engine or add a tested SGX executor"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sgx_reports_unsupported() {
        assert_eq!(support_status(), SgxSupportStatus::Unsupported);
        assert!(ensure_supported().is_err());
    }
}

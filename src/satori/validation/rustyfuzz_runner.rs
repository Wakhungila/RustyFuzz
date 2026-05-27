use crate::satori::types::RustyFuzzJobSpec;

pub fn has_direct_rustyfuzz_context(job: &RustyFuzzJobSpec) -> bool {
    job.target_contract.is_some() && job.fork_rpc_url.is_some() && job.fork_block.is_some()
}

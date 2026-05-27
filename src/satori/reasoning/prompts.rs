use std::path::PathBuf;

pub fn load_prompt(name: &str) -> String {
    let path = PathBuf::from("prompts/satori").join(format!("{name}.md"));
    std::fs::read_to_string(&path).unwrap_or_else(|_| fallback_prompt(name).to_string())
}

fn fallback_prompt(name: &str) -> &'static str {
    match name {
        "system" => {
            "You are Satori, an authorized local DeFi audit harness. Use only supplied context. Return strict JSON. A hypothesis is not a finding."
        }
        "function_audit" => {
            "Audit the supplied function packet. Return JSON matching FunctionAuditResult."
        }
        "rustyfuzz_job" => {
            "Convert the supplied hypothesis into a RustyFuzzJobSpec JSON object."
        }
        _ => "Return strict JSON using only supplied context.",
    }
}

use crate::satori::types::FunctionSummary;

pub fn functions_touching_accounting(functions: &[FunctionSummary]) -> Vec<FunctionSummary> {
    functions
        .iter()
        .filter(|function| {
            function
                .reads
                .iter()
                .chain(function.writes.iter())
                .any(|access| {
                    matches!(
                        access.name.as_str(),
                        "balance"
                            | "shares"
                            | "totalsupply"
                            | "totalassets"
                            | "reserve"
                            | "debt"
                            | "collateral"
                            | "allowance"
                    )
                })
        })
        .cloned()
        .collect()
}

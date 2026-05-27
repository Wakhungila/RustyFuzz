pub type SatoriResult<T> = anyhow::Result<T>;

pub fn llm_feature_required() -> anyhow::Error {
    anyhow::anyhow!("Satori model calls require cargo run --features llm -- ...")
}

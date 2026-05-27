use crate::satori::error::SatoriResult;
use serde::de::DeserializeOwned;

pub fn parse_strict_json<T: DeserializeOwned>(text: &str) -> SatoriResult<T> {
    let trimmed = text.trim();
    anyhow::ensure!(
        trimmed.starts_with('{') || trimmed.starts_with('['),
        "model output is not strict JSON"
    );
    Ok(serde_json::from_str(trimmed)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::Deserialize;

    #[derive(Debug, Deserialize)]
    struct X {
        value: u64,
    }

    #[test]
    fn parser_rejects_malformed_json() {
        assert!(parse_strict_json::<X>("not json").is_err());
    }

    #[test]
    fn parser_accepts_json() {
        assert_eq!(parse_strict_json::<X>("{\"value\":1}").unwrap().value, 1);
    }
}

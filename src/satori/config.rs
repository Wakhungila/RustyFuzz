use crate::satori::error::SatoriResult;
use crate::satori::types::SatoriConfig;
use std::path::Path;

impl SatoriConfig {
    pub fn from_file_or_default(path: impl AsRef<Path>) -> SatoriResult<Self> {
        let path = path.as_ref();
        if !path.exists() {
            return Ok(Self::default());
        }
        Ok(toml::from_str(&std::fs::read_to_string(path)?)?)
    }
}

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

    pub fn external_foundry_opt_in(&self) -> bool {
        self.run_forge_tests
            || env_opt_in("RUSTYFUZZ_ALLOW_EXTERNAL_ANALYZERS")
            || env_opt_in("RUSTYFUZZ_RUN_FORGE_TESTS")
    }

    pub fn external_slither_opt_in(&self) -> bool {
        self.run_slither
            || env_opt_in("RUSTYFUZZ_ALLOW_EXTERNAL_ANALYZERS")
            || env_opt_in("RUSTYFUZZ_RUN_SLITHER")
    }
}

fn env_opt_in(name: &str) -> bool {
    matches!(
        std::env::var(name).ok().as_deref().map(str::trim),
        Some("1" | "true" | "yes" | "on")
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    static ENV_LOCK: std::sync::OnceLock<std::sync::Mutex<()>> = std::sync::OnceLock::new();

    #[test]
    fn external_analyzers_are_off_by_default() {
        let _lock = ENV_LOCK
            .get_or_init(|| std::sync::Mutex::new(()))
            .lock()
            .expect("environment lock");
        let foundry = std::env::var_os("RUSTYFUZZ_RUN_FORGE_TESTS");
        let analyzers = std::env::var_os("RUSTYFUZZ_ALLOW_EXTERNAL_ANALYZERS");
        let slither = std::env::var_os("RUSTYFUZZ_RUN_SLITHER");
        std::env::remove_var("RUSTYFUZZ_RUN_FORGE_TESTS");
        std::env::remove_var("RUSTYFUZZ_ALLOW_EXTERNAL_ANALYZERS");
        std::env::remove_var("RUSTYFUZZ_RUN_SLITHER");
        let config = SatoriConfig::default();
        assert!(!config.external_foundry_opt_in());
        assert!(!config.external_slither_opt_in());
        if let Some(value) = foundry {
            std::env::set_var("RUSTYFUZZ_RUN_FORGE_TESTS", value);
        }
        if let Some(value) = analyzers {
            std::env::set_var("RUSTYFUZZ_ALLOW_EXTERNAL_ANALYZERS", value);
        }
        if let Some(value) = slither {
            std::env::set_var("RUSTYFUZZ_RUN_SLITHER", value);
        }
    }

    #[test]
    fn explicit_config_opts_in_each_external_analyzer() {
        let config = SatoriConfig {
            run_forge_tests: true,
            run_slither: true,
            ..SatoriConfig::default()
        };
        assert!(config.external_foundry_opt_in());
        assert!(config.external_slither_opt_in());
    }

    #[test]
    fn external_analyzer_environment_opt_in_is_explicit() {
        let _lock = ENV_LOCK
            .get_or_init(|| std::sync::Mutex::new(()))
            .lock()
            .expect("environment lock");
        let foundry_env = "RUSTYFUZZ_RUN_FORGE_TESTS";
        let slither_env = "RUSTYFUZZ_RUN_SLITHER";
        std::env::set_var(foundry_env, "1");
        std::env::set_var(slither_env, "yes");
        let config = SatoriConfig::default();
        assert!(config.external_foundry_opt_in());
        assert!(config.external_slither_opt_in());
        std::env::remove_var(foundry_env);
        std::env::remove_var(slither_env);
    }
}

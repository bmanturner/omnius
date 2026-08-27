use std::sync::atomic::{AtomicU64, Ordering};

use config::ValueKind;
use garde::Validate;
use omnius_config::{ConfigLoadError, ConfigLoader, DeploymentEnvironment, LoadedConfig};
use serde::de::DeserializeOwned;

static NEXT_NAMESPACE: AtomicU64 = AtomicU64::new(0);

/// Builds typed test configuration through the production precedence loader.
pub struct TestConfigBuilder {
    loader: ConfigLoader,
}

impl TestConfigBuilder {
    /// Creates a test-deployment loader with a process-unique environment prefix.
    ///
    /// The unique prefix prevents ambient service environment variables from
    /// contaminating a test. Values should be supplied as defaults or explicit
    /// overrides instead of mutating the process environment.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigLoadError`] if the generated loader prefix is rejected.
    pub fn new() -> Result<Self, ConfigLoadError> {
        let sequence = NEXT_NAMESPACE.fetch_add(1, Ordering::Relaxed);
        let prefix = format!("OMNIUS_TEST_{}_{}", std::process::id(), sequence);
        Ok(Self {
            loader: ConfigLoader::new(prefix, DeploymentEnvironment::Test)?,
        })
    }

    /// Adds a lowest-precedence compiled default.
    #[must_use]
    pub fn with_default(mut self, key: impl Into<String>, value: impl Into<ValueKind>) -> Self {
        self.loader = self.loader.with_default(key, value);
        self
    }

    /// Adds an explicit highest-precedence test override.
    #[must_use]
    pub fn with_override(mut self, key: impl Into<String>, value: impl Into<ValueKind>) -> Self {
        self.loader = self.loader.with_override(key, value);
        self
    }

    /// Strictly deserializes and validates the typed configuration.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigLoadError`] with the same safe classification as the
    /// production loader.
    pub fn load<T>(self) -> Result<LoadedConfig<T>, ConfigLoadError>
    where
        T: DeserializeOwned + Validate<Context = ()>,
    {
        self.loader.load()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::Deserialize;

    #[derive(Debug, Deserialize, Validate)]
    #[serde(deny_unknown_fields)]
    struct Settings {
        #[garde(ascii, length(min = 1, max = 32))]
        environment: String,
        #[garde(range(min = 1, max = 65_535))]
        port: u16,
    }

    #[test]
    fn explicit_overrides_win_without_files_or_process_environment()
    -> Result<(), Box<dyn std::error::Error>> {
        let loaded = TestConfigBuilder::new()?
            .with_default("environment", "test")
            .with_default("port", 8000_i64)
            .with_override("port", 9000_i64)
            .load::<Settings>()?;

        assert_eq!(loaded.value().environment, "test");
        assert_eq!(loaded.value().port, 9000);
        assert_eq!(loaded.layers().len(), 3);
        Ok(())
    }

    #[test]
    fn strict_validation_matches_production_loader() -> Result<(), Box<dyn std::error::Error>> {
        let result = TestConfigBuilder::new()?
            .with_override("environment", "test")
            .with_override("port", 0_i64)
            .load::<Settings>();
        assert!(result.is_err());
        Ok(())
    }
}

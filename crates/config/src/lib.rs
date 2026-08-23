//! Deterministic layered configuration with redacted secret values.

use std::{
    error::Error,
    fmt,
    path::{Path, PathBuf},
};

use config::{Config, Environment, File, ValueKind};
use garde::Validate;
use serde::{Serialize, de::DeserializeOwned};
use thiserror::Error;

pub use secrecy::{ExposeSecret, SecretString};

/// The deployment class controlling development-only configuration behavior.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum DeploymentEnvironment {
    /// Local developer execution.
    Development,
    /// Hermetic automated test execution.
    Test,
    /// Production or production-like execution.
    Production,
}

/// A non-secret description of a configuration layer that contributed values.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct LayerInfo {
    /// Layer type in precedence order.
    pub kind: LayerKind,
    /// File location for file-backed layers.
    pub path: Option<PathBuf>,
}

/// Configuration source classes, ordered from lowest to highest precedence.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum LayerKind {
    /// Compiled defaults.
    Defaults,
    /// Required base configuration file.
    BaseFile,
    /// Optional environment-specific configuration file.
    EnvironmentFile,
    /// Optional uncommitted local development file.
    LocalFile,
    /// Process environment variables.
    Environment,
    /// Explicit process-mode or CLI overrides.
    Override,
}

/// A validated typed configuration and its safe source diagnostics.
pub struct LoadedConfig<T> {
    value: T,
    layers: Vec<LayerInfo>,
}

impl<T> LoadedConfig<T> {
    /// Borrows the validated typed value.
    #[must_use]
    pub const fn value(&self) -> &T {
        &self.value
    }

    /// Consumes the result and returns the typed value.
    #[must_use]
    pub fn into_value(self) -> T {
        self.value
    }

    /// Returns non-secret source diagnostics in precedence order.
    #[must_use]
    pub fn layers(&self) -> &[LayerInfo] {
        &self.layers
    }
}

/// Builds the fixed configuration precedence chain.
pub struct ConfigLoader {
    service_prefix: String,
    deployment: DeploymentEnvironment,
    defaults: Vec<(String, ValueKind)>,
    base_file: Option<PathBuf>,
    environment_file: Option<PathBuf>,
    local_file: Option<PathBuf>,
    overrides: Vec<(String, ValueKind)>,
}

impl ConfigLoader {
    /// Creates a loader for `<SERVICE>__SECTION__FIELD` environment keys.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigLoadError`] when the service prefix is not an uppercase
    /// ASCII identifier.
    pub fn new(
        service_prefix: impl Into<String>,
        deployment: DeploymentEnvironment,
    ) -> Result<Self, ConfigLoadError> {
        let service_prefix = service_prefix.into();
        let valid = !service_prefix.is_empty()
            && service_prefix.len() <= 64
            && service_prefix
                .bytes()
                .next()
                .is_some_and(|byte| byte.is_ascii_uppercase())
            && service_prefix
                .bytes()
                .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit() || byte == b'_');
        if !valid {
            return Err(ConfigLoadError::without_source(
                ConfigErrorKind::InvalidPrefix,
            ));
        }
        Ok(Self {
            service_prefix,
            deployment,
            defaults: Vec::new(),
            base_file: None,
            environment_file: None,
            local_file: None,
            overrides: Vec::new(),
        })
    }

    /// Adds a compiled default value.
    #[must_use]
    pub fn with_default(mut self, key: impl Into<String>, value: impl Into<ValueKind>) -> Self {
        self.defaults.push((key.into(), value.into()));
        self
    }

    /// Selects the required base configuration file.
    #[must_use]
    pub fn with_base_file(mut self, path: impl Into<PathBuf>) -> Self {
        self.base_file = Some(path.into());
        self
    }

    /// Selects an optional environment-specific configuration file.
    #[must_use]
    pub fn with_environment_file(mut self, path: impl Into<PathBuf>) -> Self {
        self.environment_file = Some(path.into());
        self
    }

    /// Selects an optional local development configuration file.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigLoadError`] in production so `.env` or local files can
    /// never be enabled implicitly by a production composition.
    pub fn with_local_file(mut self, path: impl Into<PathBuf>) -> Result<Self, ConfigLoadError> {
        if self.deployment == DeploymentEnvironment::Production {
            return Err(ConfigLoadError::without_source(
                ConfigErrorKind::LocalFileInProduction,
            ));
        }
        self.local_file = Some(path.into());
        Ok(self)
    }

    /// Adds an explicit highest-precedence override.
    #[must_use]
    pub fn with_override(mut self, key: impl Into<String>, value: impl Into<ValueKind>) -> Self {
        self.overrides.push((key.into(), value.into()));
        self
    }

    /// Loads, strictly deserializes, and semantically validates a typed config.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigLoadError`] for missing or malformed sources, unknown
    /// fields rejected by the target type, or a `garde` validation failure.
    pub fn load<T>(self) -> Result<LoadedConfig<T>, ConfigLoadError>
    where
        T: DeserializeOwned + Validate<Context = ()>,
    {
        let mut builder = Config::builder();
        let mut layers = Vec::with_capacity(6);
        if !self.defaults.is_empty() {
            layers.push(LayerInfo {
                kind: LayerKind::Defaults,
                path: None,
            });
        }
        for (key, value) in self.defaults {
            builder = builder
                .set_default(key, value)
                .map_err(|source| ConfigLoadError::from_source(ConfigErrorKind::Build, source))?;
        }
        if let Some(path) = self.base_file {
            layers.push(file_layer(LayerKind::BaseFile, &path));
            builder = builder.add_source(File::from(path).required(true));
        }
        if let Some(path) = self.environment_file {
            if path.exists() {
                layers.push(file_layer(LayerKind::EnvironmentFile, &path));
            }
            builder = builder.add_source(File::from(path).required(false));
        }
        if let Some(path) = self.local_file {
            if path.exists() {
                layers.push(file_layer(LayerKind::LocalFile, &path));
            }
            builder = builder.add_source(File::from(path).required(false));
        }
        layers.push(LayerInfo {
            kind: LayerKind::Environment,
            path: None,
        });
        builder = builder.add_source(
            Environment::with_prefix(&self.service_prefix)
                .prefix_separator("__")
                .separator("__")
                .try_parsing(true),
        );
        if !self.overrides.is_empty() {
            layers.push(LayerInfo {
                kind: LayerKind::Override,
                path: None,
            });
        }
        for (key, value) in self.overrides {
            builder = builder
                .set_override(key, value)
                .map_err(|source| ConfigLoadError::from_source(ConfigErrorKind::Build, source))?;
        }
        let raw = builder
            .build()
            .map_err(|source| ConfigLoadError::from_source(ConfigErrorKind::Build, source))?;
        let value: T = raw
            .try_deserialize()
            .map_err(|source| ConfigLoadError::from_source(ConfigErrorKind::Deserialize, source))?;
        value
            .validate()
            .map_err(|source| ConfigLoadError::from_source(ConfigErrorKind::Validation, source))?;
        Ok(LoadedConfig { value, layers })
    }
}

fn file_layer(kind: LayerKind, path: &Path) -> LayerInfo {
    LayerInfo {
        kind,
        path: Some(path.to_path_buf()),
    }
}

/// A safe classification of a configuration loading failure.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum ConfigErrorKind {
    /// The environment prefix is malformed.
    #[error("invalid configuration service prefix")]
    InvalidPrefix,
    /// A local development file was requested in production.
    #[error("local configuration files are disabled in production")]
    LocalFileInProduction,
    /// A source could not be read or merged.
    #[error("configuration source loading failed")]
    Build,
    /// The merged value could not be strictly deserialized.
    #[error("configuration deserialization failed")]
    Deserialize,
    /// Typed semantic validation failed.
    #[error("configuration validation failed")]
    Validation,
}

/// A redacted configuration failure with an internal diagnostic source.
#[derive(Error)]
#[error("{kind}")]
pub struct ConfigLoadError {
    kind: ConfigErrorKind,
    diagnostic: Option<Box<dyn Error + Send + Sync + 'static>>,
}

impl ConfigLoadError {
    fn without_source(kind: ConfigErrorKind) -> Self {
        Self {
            kind,
            diagnostic: None,
        }
    }

    fn from_source(kind: ConfigErrorKind, source: impl Error + Send + Sync + 'static) -> Self {
        Self {
            kind,
            diagnostic: Some(Box::new(source)),
        }
    }

    /// Returns the safe error classification.
    #[must_use]
    pub const fn kind(&self) -> ConfigErrorKind {
        self.kind
    }
}

impl fmt::Debug for ConfigLoadError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ConfigLoadError")
            .field("kind", &self.kind)
            .field(
                "diagnostic",
                &self.diagnostic.as_ref().map(|_| "[REDACTED]"),
            )
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use std::{
        fs,
        process::Command,
        sync::atomic::{AtomicU64, Ordering},
    };

    use serde::Deserialize;

    use super::*;

    static DIRECTORY_SEQUENCE: AtomicU64 = AtomicU64::new(0);

    #[derive(Deserialize, garde::Validate)]
    #[serde(deny_unknown_fields)]
    struct Settings {
        #[garde(range(min = 1, max = 65_535))]
        port: u16,
        #[garde(skip)]
        token: SecretString,
    }

    struct TestDirectory(PathBuf);

    impl TestDirectory {
        fn new() -> Result<Self, Box<dyn Error>> {
            let sequence = DIRECTORY_SEQUENCE.fetch_add(1, Ordering::Relaxed);
            let path =
                std::env::temp_dir().join(format!("rsk-config-{}-{sequence}", std::process::id()));
            fs::create_dir_all(&path)?;
            Ok(Self(path))
        }

        fn write(&self, name: &str, contents: &str) -> Result<PathBuf, Box<dyn Error>> {
            let path = self.0.join(name);
            fs::write(&path, contents)?;
            Ok(path)
        }
    }

    impl Drop for TestDirectory {
        fn drop(&mut self) {
            let _result = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn precedence_is_deterministic_and_sources_are_reported() -> Result<(), Box<dyn Error>> {
        let directory = TestDirectory::new()?;
        let base = directory.write("base.toml", "port = 2\ntoken = \"base-secret\"\n")?;
        let environment = directory.write("test.toml", "port = 3\n")?;
        let local = directory.write("local.toml", "port = 4\n")?;
        let loaded = ConfigLoader::new("RSK_TEST_UNUSED", DeploymentEnvironment::Test)?
            .with_default("port", 1_i64)
            .with_base_file(base)
            .with_environment_file(environment)
            .with_local_file(local)?
            .with_override("port", 6_i64)
            .load::<Settings>()?;

        assert_eq!(loaded.value().port, 6);
        assert_eq!(
            loaded
                .layers()
                .iter()
                .map(|layer| layer.kind)
                .collect::<Vec<_>>(),
            vec![
                LayerKind::Defaults,
                LayerKind::BaseFile,
                LayerKind::EnvironmentFile,
                LayerKind::LocalFile,
                LayerKind::Environment,
                LayerKind::Override,
            ]
        );
        assert!(!format!("{:?}", loaded.value().token).contains("base-secret"));
        assert_eq!(loaded.value().token.expose_secret(), "base-secret");
        Ok(())
    }
    #[test]
    fn environment_precedes_local_and_yields_to_override() -> Result<(), Box<dyn Error>> {
        const CHILD_MARKER: &str = "RSK_CONFIG_ENV_CHILD";
        const LOCAL_PATH: &str = "RSK_CONFIG_ENV_LOCAL_PATH";
        if std::env::var_os(CHILD_MARKER).is_some() {
            let local =
                PathBuf::from(std::env::var_os(LOCAL_PATH).ok_or("child local path is missing")?);
            let environment_value =
                ConfigLoader::new("RSK_LAYERED_CONFIG", DeploymentEnvironment::Test)?
                    .with_local_file(&local)?
                    .load::<Settings>()?;
            assert_eq!(environment_value.value().port, 5);

            let override_value =
                ConfigLoader::new("RSK_LAYERED_CONFIG", DeploymentEnvironment::Test)?
                    .with_local_file(local)?
                    .with_override("port", 6_i64)
                    .load::<Settings>()?;
            assert_eq!(override_value.value().port, 6);
            return Ok(());
        }

        let directory = TestDirectory::new()?;
        let local = directory.write("local.toml", "port = 4\ntoken = \"child-secret\"\n")?;
        let status = Command::new(std::env::current_exe()?)
            .args([
                "--exact",
                "tests::environment_precedes_local_and_yields_to_override",
                "--nocapture",
            ])
            .env(CHILD_MARKER, "1")
            .env(LOCAL_PATH, local)
            .env("RSK_LAYERED_CONFIG__PORT", "5")
            .status()?;
        assert!(status.success());
        Ok(())
    }

    #[test]
    fn production_rejects_local_files() -> Result<(), ConfigLoadError> {
        let result = ConfigLoader::new("EXAMPLE", DeploymentEnvironment::Production)?
            .with_local_file("config/local.toml");
        let Err(error) = result else {
            panic!("production local file was accepted");
        };
        assert_eq!(error.kind(), ConfigErrorKind::LocalFileInProduction);
        Ok(())
    }

    #[test]
    fn unknown_fields_and_invalid_values_fail_safely() -> Result<(), Box<dyn Error>> {
        let directory = TestDirectory::new()?;
        let base = directory.write("base.toml", "port = 2\ntoken = \"secret-value\"\n")?;
        let unknown = ConfigLoader::new("RSK_TEST_UNUSED", DeploymentEnvironment::Test)?
            .with_base_file(&base)
            .with_override("unknown_security_key", true)
            .load::<Settings>();
        let Err(unknown_error) = unknown else {
            panic!("unknown field was accepted");
        };
        assert_eq!(unknown_error.kind(), ConfigErrorKind::Deserialize);
        assert!(!format!("{unknown_error:?}").contains("secret-value"));
        assert!(Error::source(&unknown_error).is_none());

        let invalid = ConfigLoader::new("RSK_TEST_UNUSED", DeploymentEnvironment::Test)?
            .with_base_file(base)
            .with_override("port", 0_i64)
            .load::<Settings>();
        let Err(invalid_error) = invalid else {
            panic!("invalid port was accepted");
        };
        assert_eq!(invalid_error.kind(), ConfigErrorKind::Validation);
        assert_eq!(invalid_error.to_string(), "configuration validation failed");
        Ok(())
    }
}

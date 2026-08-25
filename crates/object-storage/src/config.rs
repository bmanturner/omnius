use std::{fmt, path::PathBuf, time::Duration};

use rsk_config::{DeploymentEnvironment, ExposeSecret as _, SecretString};
use serde::Deserialize;
use url::{Host, Url};

use crate::error::BlobStoreError;

const MAX_ENDPOINT_BYTES: usize = 2_048;
const MAX_CREDENTIAL_BYTES: usize = 65_536;
const MAX_NAME_BYTES: usize = 255;
const MAX_ROOT_BYTES: usize = 4_096;
const MIN_PART_SIZE: u64 = 8 * 1024 * 1024;
const MAX_PART_SIZE: u64 = 512 * 1024 * 1024;
const MAX_OBJECT_SIZE: u64 = 5 * 1024 * 1024 * 1024 * 1024;
const MAX_OPERATION_TIMEOUT: Duration = Duration::from_mins(10);
const MAX_SIGNED_URL_EXPIRY: Duration = Duration::from_mins(15);

/// Strict runtime configuration for one object-storage provider and its resource bounds.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObjectStorageConfig {
    /// Provider-specific configuration.
    #[serde(flatten)]
    pub provider: ProviderConfig,
    /// Adapter-owned object, metadata, pagination, retry, and deadline bounds.
    #[serde(default)]
    pub limits: ObjectStorageLimits,
}

impl ObjectStorageConfig {
    /// Validates provider policy and every adapter-owned resource bound.
    ///
    /// # Errors
    ///
    /// Returns [`BlobStoreError::Config`] when a field or provider is unsafe for the selected
    /// deployment environment.
    pub fn validate(&self, environment: DeploymentEnvironment) -> Result<(), BlobStoreError> {
        self.limits.validate()?;
        self.provider.validate(environment)
    }
}

impl fmt::Debug for ObjectStorageConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ObjectStorageConfig")
            .field("provider", &self.provider.kind())
            .field("limits", &self.limits)
            .finish()
    }
}

/// Strict tagged configuration for the supported provider set.
#[derive(Deserialize)]
#[serde(tag = "provider", rename_all = "kebab-case", deny_unknown_fields)]
pub enum ProviderConfig {
    /// Process-local storage permitted only in the test deployment environment.
    Memory,
    /// Filesystem storage rooted at one canonical directory in development or tests.
    Local {
        /// Existing directory that becomes the provider root after canonicalization.
        root: PathBuf,
    },
    /// AWS S3 or an S3-compatible service such as `MinIO`, using path-style requests.
    S3Compatible {
        /// Explicit service endpoint.
        endpoint: Url,
        /// Signing region.
        region: String,
        /// Private bucket name.
        bucket: String,
        /// Static access-key identifier.
        access_key_id: SecretString,
        /// Static secret access key.
        secret_access_key: SecretString,
        /// Optional temporary session token.
        #[serde(default)]
        session_token: Option<SecretString>,
        /// Explicit opt-in to loopback HTTP in non-production environments.
        #[serde(default)]
        allow_http: bool,
    },
    /// Google Cloud Storage using a serialized service-account key.
    Gcs {
        /// Private bucket name.
        bucket: String,
        /// Serialized service-account JSON.
        service_account_json: SecretString,
        /// Optional explicit service endpoint.
        #[serde(default)]
        endpoint: Option<Url>,
        /// Explicit opt-in to loopback HTTP in non-production environments.
        #[serde(default)]
        allow_http: bool,
    },
    /// Azure Blob Storage using an account access key.
    Azure {
        /// Storage account name.
        account: String,
        /// Private container name.
        container: String,
        /// Account access key.
        access_key: SecretString,
        /// Optional explicit service endpoint.
        #[serde(default)]
        endpoint: Option<Url>,
        /// Explicit opt-in to loopback HTTP in non-production environments.
        #[serde(default)]
        allow_http: bool,
    },
}

impl ProviderConfig {
    pub(crate) const fn kind(&self) -> crate::ProviderKind {
        match self {
            Self::Memory => crate::ProviderKind::Memory,
            Self::Local { .. } => crate::ProviderKind::Local,
            Self::S3Compatible { .. } => crate::ProviderKind::S3Compatible,
            Self::Gcs { .. } => crate::ProviderKind::Gcs,
            Self::Azure { .. } => crate::ProviderKind::Azure,
        }
    }

    fn validate(&self, environment: DeploymentEnvironment) -> Result<(), BlobStoreError> {
        match self {
            Self::Memory if environment != DeploymentEnvironment::Test => {
                Err(BlobStoreError::Config)
            }
            Self::Memory => Ok(()),
            Self::Local { root } => {
                if environment == DeploymentEnvironment::Production
                    || root.as_os_str().is_empty()
                    || root.as_os_str().len() > MAX_ROOT_BYTES
                    || !root.is_absolute()
                {
                    return Err(BlobStoreError::Config);
                }
                Ok(())
            }
            Self::S3Compatible {
                endpoint,
                region,
                bucket,
                access_key_id,
                secret_access_key,
                session_token,
                allow_http,
            } => {
                validate_endpoint(endpoint, *allow_http, environment)?;
                validate_ascii_value(region, 1, 128)?;
                validate_bucket(bucket)?;
                validate_secret(access_key_id, 3)?;
                validate_secret(secret_access_key, 8)?;
                if let Some(token) = session_token {
                    validate_secret(token, 8)?;
                }
                Ok(())
            }
            Self::Gcs {
                bucket,
                service_account_json,
                endpoint,
                allow_http,
            } => {
                validate_bucket(bucket)?;
                validate_gcs_service_account(service_account_json)?;
                if let Some(endpoint) = endpoint {
                    validate_endpoint(endpoint, *allow_http, environment)?;
                } else if *allow_http {
                    return Err(BlobStoreError::Config);
                }
                Ok(())
            }
            Self::Azure {
                account,
                container,
                access_key,
                endpoint,
                allow_http,
            } => {
                validate_azure_account(account)?;
                validate_azure_name(container)?;
                validate_secret(access_key, 8)?;
                if let Some(endpoint) = endpoint {
                    validate_endpoint(endpoint, *allow_http, environment)?;
                } else if *allow_http {
                    return Err(BlobStoreError::Config);
                }
                Ok(())
            }
        }
    }
}

impl fmt::Debug for ProviderConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProviderConfig")
            .field("kind", &self.kind())
            .finish_non_exhaustive()
    }
}

/// Bounded resource and deadline policy applied uniformly to all providers.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(default, deny_unknown_fields)]
pub struct ObjectStorageLimits {
    /// Maximum declared bytes accepted for one object.
    pub max_object_size: u64,
    /// Fixed non-final multipart part size.
    pub multipart_part_size: u64,
    /// Maximum multipart part count.
    pub max_multipart_parts: u16,
    /// Maximum user-metadata field count.
    pub max_metadata_fields: u16,
    /// Maximum bytes in one metadata key.
    pub max_metadata_key_bytes: u16,
    /// Maximum bytes in one metadata value.
    pub max_metadata_value_bytes: u16,
    /// Maximum aggregate metadata bytes.
    pub max_metadata_bytes: u32,
    /// Maximum objects returned by one list page.
    pub max_list_page_size: u16,
    /// Total deadline for one adapter operation or stream.
    #[serde(with = "humantime_serde")]
    pub operation_timeout: Duration,
    /// Provider connection-establishment deadline.
    #[serde(with = "humantime_serde")]
    pub connect_timeout: Duration,
    /// Longest presigned URL expiry accepted by the adapter.
    #[serde(with = "humantime_serde")]
    pub max_signed_url_expiry: Duration,
    /// Maximum provider retry count for provider-classified safe requests.
    pub max_retries: u8,
    /// Total provider retry budget, contained by the operation deadline.
    #[serde(with = "humantime_serde")]
    pub retry_timeout: Duration,
}

impl Default for ObjectStorageLimits {
    fn default() -> Self {
        Self {
            max_object_size: 5 * 1024 * 1024 * 1024,
            multipart_part_size: MIN_PART_SIZE,
            max_multipart_parts: 10_000,
            max_metadata_fields: 32,
            max_metadata_key_bytes: 128,
            max_metadata_value_bytes: 1_024,
            max_metadata_bytes: 16 * 1024,
            max_list_page_size: 1_000,
            operation_timeout: Duration::from_secs(30),
            connect_timeout: Duration::from_secs(5),
            max_signed_url_expiry: Duration::from_mins(5),
            max_retries: 3,
            retry_timeout: Duration::from_secs(10),
        }
    }
}

impl ObjectStorageLimits {
    fn validate(self) -> Result<(), BlobStoreError> {
        let part_capacity = self
            .multipart_part_size
            .checked_mul(u64::from(self.max_multipart_parts))
            .ok_or(BlobStoreError::Config)?;
        if self.max_object_size == 0
            || self.max_object_size > MAX_OBJECT_SIZE
            || self.multipart_part_size < MIN_PART_SIZE
            || self.multipart_part_size > MAX_PART_SIZE
            || self.max_multipart_parts == 0
            || self.max_multipart_parts > 10_000
            || part_capacity < self.max_object_size
            || self.max_metadata_fields == 0
            || self.max_metadata_fields > 128
            || self.max_metadata_key_bytes == 0
            || self.max_metadata_key_bytes > 256
            || self.max_metadata_value_bytes == 0
            || self.max_metadata_value_bytes > 4_096
            || self.max_metadata_bytes == 0
            || self.max_metadata_bytes > 64 * 1024
            || self.max_list_page_size == 0
            || self.max_list_page_size > 1_000
            || self.operation_timeout.is_zero()
            || self.operation_timeout > MAX_OPERATION_TIMEOUT
            || self.connect_timeout.is_zero()
            || self.connect_timeout > self.operation_timeout
            || self.max_signed_url_expiry < Duration::from_secs(1)
            || self.max_signed_url_expiry > MAX_SIGNED_URL_EXPIRY
            || self.max_signed_url_expiry.subsec_nanos() != 0
            || self.max_retries > 5
            || self.retry_timeout.is_zero()
            || self.retry_timeout > self.operation_timeout
        {
            return Err(BlobStoreError::Config);
        }
        Ok(())
    }
}

fn validate_endpoint(
    endpoint: &Url,
    allow_http: bool,
    environment: DeploymentEnvironment,
) -> Result<(), BlobStoreError> {
    let path_is_root = endpoint.path().is_empty() || endpoint.path() == "/";
    if endpoint.as_str().len() > MAX_ENDPOINT_BYTES
        || !endpoint.username().is_empty()
        || endpoint.password().is_some()
        || endpoint.query().is_some()
        || endpoint.fragment().is_some()
        || !path_is_root
        || endpoint.host().is_none()
    {
        return Err(BlobStoreError::Config);
    }

    match endpoint.scheme() {
        "https" if !allow_http => Ok(()),
        "http"
            if allow_http
                && environment != DeploymentEnvironment::Production
                && endpoint.host().as_ref().is_some_and(is_loopback_host) =>
        {
            Ok(())
        }
        _ => Err(BlobStoreError::Config),
    }
}

fn is_loopback_host(host: &Host<&str>) -> bool {
    match host {
        Host::Domain(name) => name.eq_ignore_ascii_case("localhost"),
        Host::Ipv4(address) => address.is_loopback(),
        Host::Ipv6(address) => address.is_loopback(),
    }
}

fn validate_ascii_value(value: &str, min: usize, max: usize) -> Result<(), BlobStoreError> {
    if value.len() < min
        || value.len() > max.min(MAX_NAME_BYTES)
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_graphic() && !byte.is_ascii_control())
    {
        return Err(BlobStoreError::Config);
    }
    Ok(())
}

fn validate_secret(value: &SecretString, min: usize) -> Result<(), BlobStoreError> {
    let exposed = value.expose_secret();
    if exposed.len() < min || exposed.len() > MAX_CREDENTIAL_BYTES || exposed.contains('\0') {
        return Err(BlobStoreError::Config);
    }
    Ok(())
}

fn validate_gcs_service_account(value: &SecretString) -> Result<(), BlobStoreError> {
    validate_secret(value, 2)?;
    let fields = serde_json::from_str::<serde_json::Value>(value.expose_secret())
        .map_err(|_| BlobStoreError::Config)?;
    let Some(fields) = fields.as_object() else {
        return Err(BlobStoreError::Config);
    };
    if fields.contains_key("gcs_base_url") || fields.contains_key("disable_oauth") {
        return Err(BlobStoreError::Config);
    }
    Ok(())
}

fn validate_bucket(value: &str) -> Result<(), BlobStoreError> {
    if value.len() < 3
        || value.len() > 63
        || !value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'-' | b'.')
        })
        || !value
            .as_bytes()
            .first()
            .is_some_and(u8::is_ascii_alphanumeric)
        || !value
            .as_bytes()
            .last()
            .is_some_and(u8::is_ascii_alphanumeric)
        || value.contains("..")
    {
        return Err(BlobStoreError::Config);
    }
    Ok(())
}

fn validate_azure_account(value: &str) -> Result<(), BlobStoreError> {
    if value.len() < 3
        || value.len() > 24
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
    {
        return Err(BlobStoreError::Config);
    }
    Ok(())
}

fn validate_azure_name(value: &str) -> Result<(), BlobStoreError> {
    if value.len() < 3
        || value.len() > 63
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        || !value
            .as_bytes()
            .first()
            .is_some_and(u8::is_ascii_alphanumeric)
        || !value
            .as_bytes()
            .last()
            .is_some_and(u8::is_ascii_alphanumeric)
        || value.contains("--")
    {
        return Err(BlobStoreError::Config);
    }
    Ok(())
}

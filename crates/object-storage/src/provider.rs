use std::{fs, sync::Arc};

use object_store::{
    BackoffConfig, ClientOptions, ObjectStore, RetryConfig, aws::AmazonS3Builder,
    azure::MicrosoftAzureBuilder, gcp::GoogleCloudStorageBuilder, local::LocalFileSystem,
    memory::InMemory, signer::Signer,
};
use rsk_config::{DeploymentEnvironment, ExposeSecret as _, SecretString};
use rsk_outbound_http::{ApprovedUrl, OutboundUrlPolicy};

use crate::{
    BlobStoreError, ObjectStorageConfig, ObjectStorageLimits, ProviderConfig, ProviderKind,
    store::BlobStore,
};

pub(crate) struct StoreBackend {
    pub(crate) store: Arc<dyn ObjectStore>,
    pub(crate) signer: Option<Arc<dyn Signer>>,
    pub(crate) kind: ProviderKind,
    pub(crate) capabilities: crate::ProviderCapabilities,
}

pub(crate) async fn build(
    config: ObjectStorageConfig,
    environment: DeploymentEnvironment,
    url_policy: &OutboundUrlPolicy,
) -> Result<BlobStore, BlobStoreError> {
    config.validate(environment)?;
    let limits = config.limits;
    let backend = match config.provider {
        ProviderConfig::Memory => memory_backend(),
        ProviderConfig::Local { root } => {
            let canonical = fs::canonicalize(root).map_err(|_| BlobStoreError::Config)?;
            if !canonical.is_dir() || !canonical.is_absolute() {
                return Err(BlobStoreError::Config);
            }
            let store =
                LocalFileSystem::new_with_prefix(canonical).map_err(|_| BlobStoreError::Config)?;
            StoreBackend {
                store: Arc::new(store),
                signer: None,
                kind: ProviderKind::Local,
                capabilities: crate::ProviderCapabilities::local(),
            }
        }
        ProviderConfig::S3Compatible {
            endpoint,
            region,
            bucket,
            access_key_id,
            secret_access_key,
            session_token,
            allow_http,
        } => {
            let endpoint = approve_endpoint(url_policy, endpoint).await?;
            let mut builder = AmazonS3Builder::new()
                .with_region(region)
                .with_bucket_name(bucket)
                .with_access_key_id(access_key_id.expose_secret())
                .with_secret_access_key(secret_access_key.expose_secret())
                .with_endpoint(endpoint.as_url().as_str())
                .with_allow_http(allow_http)
                .with_virtual_hosted_style_request(false)
                .with_retry(retry_config(limits))
                .with_client_options(client_options(limits, allow_http));
            if let Some(token) = session_token {
                builder = builder.with_token(token.expose_secret());
            }
            let provider = Arc::new(builder.build().map_err(|_| BlobStoreError::Config)?);
            StoreBackend {
                store: Arc::clone(&provider) as Arc<dyn ObjectStore>,
                signer: Some(provider as Arc<dyn Signer>),
                kind: ProviderKind::S3Compatible,
                capabilities: s3_capabilities(),
            }
        }
        ProviderConfig::Gcs {
            bucket,
            service_account_json,
            endpoint,
            allow_http,
        } => {
            gcs_backend(
                bucket,
                service_account_json,
                endpoint,
                allow_http,
                limits,
                url_policy,
            )
            .await?
        }
        ProviderConfig::Azure {
            account,
            container,
            access_key,
            endpoint,
            allow_http,
        } => {
            let endpoint = match endpoint {
                Some(endpoint) => Some(approve_endpoint(url_policy, endpoint).await?),
                None => None,
            };
            let mut builder = MicrosoftAzureBuilder::new()
                .with_account(account)
                .with_container_name(container)
                .with_access_key(access_key.expose_secret())
                .with_allow_http(allow_http)
                .with_retry(retry_config(limits))
                .with_client_options(client_options(limits, allow_http));
            if let Some(endpoint) = endpoint {
                builder = builder.with_endpoint(endpoint.as_url().as_str().to_owned());
            }
            let provider = Arc::new(builder.build().map_err(|_| BlobStoreError::Config)?);
            StoreBackend {
                store: Arc::clone(&provider) as Arc<dyn ObjectStore>,
                signer: Some(provider as Arc<dyn Signer>),
                kind: ProviderKind::Azure,
                capabilities: crate::ProviderCapabilities::cloud(false),
            }
        }
    };
    Ok(BlobStore::from_backend(backend, limits))
}

async fn gcs_backend(
    bucket: String,
    service_account_json: SecretString,
    endpoint: Option<url::Url>,
    allow_http: bool,
    limits: ObjectStorageLimits,
    url_policy: &OutboundUrlPolicy,
) -> Result<StoreBackend, BlobStoreError> {
    let endpoint = match endpoint {
        Some(endpoint) => Some(approve_endpoint(url_policy, endpoint).await?),
        None => None,
    };
    let mut builder = GoogleCloudStorageBuilder::new()
        .with_bucket_name(bucket)
        .with_service_account_key(service_account_json.expose_secret())
        .with_retry(retry_config(limits))
        .with_client_options(client_options(limits, allow_http));
    if let Some(endpoint) = endpoint {
        builder = builder.with_base_url(endpoint.as_url().as_str());
    }
    let provider = Arc::new(builder.build().map_err(|_| BlobStoreError::Config)?);
    Ok(StoreBackend {
        store: Arc::clone(&provider) as Arc<dyn ObjectStore>,
        signer: Some(provider as Arc<dyn Signer>),
        kind: ProviderKind::Gcs,
        capabilities: crate::ProviderCapabilities::cloud(true),
    })
}

async fn approve_endpoint(
    policy: &OutboundUrlPolicy,
    endpoint: url::Url,
) -> Result<ApprovedUrl, BlobStoreError> {
    policy
        .approve(endpoint)
        .await
        .map_err(|_| BlobStoreError::Config)
}

fn s3_capabilities() -> crate::ProviderCapabilities {
    let mut capabilities = crate::ProviderCapabilities::cloud(true);
    capabilities.conditional_copy = false;
    capabilities
}

fn memory_backend() -> StoreBackend {
    StoreBackend {
        store: Arc::new(InMemory::new()),
        signer: None,
        kind: ProviderKind::Memory,
        capabilities: crate::ProviderCapabilities::memory(),
    }
}

fn retry_config(limits: ObjectStorageLimits) -> RetryConfig {
    RetryConfig {
        backoff: BackoffConfig::default(),
        max_retries: usize::from(limits.max_retries),
        retry_timeout: limits.retry_timeout,
    }
}

fn client_options(limits: ObjectStorageLimits, allow_http: bool) -> ClientOptions {
    ClientOptions::new()
        .with_allow_http(allow_http)
        .with_connect_timeout(limits.connect_timeout)
        .with_timeout(limits.operation_timeout)
        .with_read_timeout(limits.operation_timeout)
}

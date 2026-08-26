use std::{collections::BTreeMap, fmt, future::Future, time::Duration};

use futures::future::BoxFuture;
use meilisearch_sdk::{
    client::{Client, SwapIndexes},
    errors::{Error as MeilisearchError, ErrorCode},
    search::Selectors,
    settings::Settings,
    task_info::TaskInfo,
    tasks::Task,
};
use rsk_auth_core::TenantId;
use rsk_config::ExposeSecret as _;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use thiserror::Error;
use tokio::time::timeout;

use crate::{
    ActivationOutcome, IndexAlias, IndexSchema, ProjectionMutation, ProjectionTarget, ProviderPage,
    SearchCandidate, SearchMeilisearchConfig, SearchProvider, SearchProviderError, SourceId,
    SourceRevision, TenantScopedQuery,
    config::SearchConfigError,
    model::{document_id, validate_index_uid},
};

const PRIMARY_KEY: &str = "id";
const SCHEMA_MARKER_ID: &str = "rsk_schema_marker";
const TENANT_FIELD: &str = "_tenant_id";
const SOURCE_ID_FIELD: &str = "_source_id";
const SOURCE_REVISION_FIELD: &str = "_source_revision";
const SEARCH_ATTRIBUTES: [&str; 3] = [TENANT_FIELD, SOURCE_ID_FIELD, SOURCE_REVISION_FIELD];

/// Maintained-SDK Meilisearch adapter with redacted errors and end-to-end deadlines.
#[derive(Clone)]
pub struct MeilisearchAdapter {
    client: Client,
    index_prefix: String,
    provider_timeout: Duration,
    task_poll_interval: Duration,
    max_document_bytes: usize,
}

impl fmt::Debug for MeilisearchAdapter {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MeilisearchAdapter")
            .field("client", &"[REDACTED]")
            .field("index_prefix", &self.index_prefix)
            .field("provider_timeout", &self.provider_timeout)
            .field("task_poll_interval", &self.task_poll_interval)
            .field("max_document_bytes", &self.max_document_bytes)
            .finish()
    }
}

impl MeilisearchAdapter {
    /// Constructs the adapter after validating configuration and the SDK authorization header.
    ///
    /// # Errors
    ///
    /// Returns [`MeilisearchAdapterError`] without retaining endpoint or provider diagnostics.
    pub fn new(config: &SearchMeilisearchConfig) -> Result<Self, MeilisearchAdapterError> {
        config
            .validate()
            .map_err(MeilisearchAdapterError::Configuration)?;
        let client = Client::new(
            config.endpoint_without_trailing_slash(),
            Some(config.api_key.expose_secret()),
        )
        .map_err(|_| MeilisearchAdapterError::Provider(SearchProviderError::Rejected))?;
        Ok(Self {
            client,
            index_prefix: config.index_prefix.clone(),
            provider_timeout: config.provider_timeout,
            task_poll_interval: config.task_poll_interval,
            max_document_bytes: config.limits.max_document_bytes,
        })
    }

    async fn deadline<T, F>(&self, future: F) -> Result<T, SearchProviderError>
    where
        F: Future<Output = Result<T, SearchProviderError>>,
    {
        timeout(self.provider_timeout, future)
            .await
            .map_err(|_| SearchProviderError::Timeout)?
    }

    async fn wait_task(&self, task: TaskInfo) -> Result<(), SearchProviderError> {
        let task = task
            .wait_for_completion(
                &self.client,
                Some(self.task_poll_interval),
                Some(self.provider_timeout),
            )
            .await
            .map_err(map_sdk_error)?;
        if matches!(task, Task::Succeeded { .. }) {
            Ok(())
        } else {
            Err(SearchProviderError::Rejected)
        }
    }

    fn stable_uid(&self, schema: &IndexSchema) -> Result<String, SearchProviderError> {
        let uid = schema.stable_uid(&self.index_prefix);
        validate_index_uid(&uid).map_err(|_| SearchProviderError::Rejected)?;
        Ok(uid)
    }

    fn stable_alias_uid(&self, alias: &IndexAlias) -> Result<String, SearchProviderError> {
        let uid = format!("{}__{alias}", self.index_prefix);
        validate_index_uid(&uid).map_err(|_| SearchProviderError::Rejected)?;
        Ok(uid)
    }

    fn version_uid(&self, schema: &IndexSchema) -> Result<String, SearchProviderError> {
        let uid = schema.version_uid(&self.index_prefix);
        validate_index_uid(&uid).map_err(|_| SearchProviderError::Rejected)?;
        Ok(uid)
    }

    async fn marker(&self, uid: &str) -> Result<SchemaMarker, SearchProviderError> {
        self.client
            .index(uid)
            .get_document::<SchemaMarker>(SCHEMA_MARKER_ID)
            .await
            .map_err(map_sdk_error)
    }

    async fn verify_marker(
        &self,
        uid: &str,
        schema: &IndexSchema,
    ) -> Result<(), SearchProviderError> {
        let marker = self.marker(uid).await?;
        if marker.id == SCHEMA_MARKER_ID
            && marker.schema_version == schema.version()
            && marker.schema_digest == hex_digest(schema.digest())
        {
            Ok(())
        } else {
            Err(SearchProviderError::SchemaConflict)
        }
    }

    async fn index_exists(&self, uid: &str) -> Result<bool, SearchProviderError> {
        match self.client.get_index(uid).await {
            Ok(_) => Ok(true),
            Err(error) if sdk_not_found(&error) => Ok(false),
            Err(error) => Err(map_sdk_error(error)),
        }
    }

    async fn prepare_inner(&self, schema: &IndexSchema) -> Result<(), SearchProviderError> {
        let uid = self.version_uid(schema)?;
        if self.index_exists(&uid).await? {
            return match self.verify_marker(&uid, schema).await {
                Ok(()) => Ok(()),
                Err(SearchProviderError::NotFound) => self.configure_index(&uid, schema).await,
                Err(error) => Err(error),
            };
        }

        let task = self
            .client
            .create_index(&uid, Some(PRIMARY_KEY))
            .await
            .map_err(map_sdk_error)?;
        self.wait_task(task).await?;
        self.configure_index(&uid, schema).await
    }

    async fn configure_index(
        &self,
        uid: &str,
        schema: &IndexSchema,
    ) -> Result<(), SearchProviderError> {
        let searchable: Vec<&str> = schema
            .searchable_fields()
            .iter()
            .map(crate::FieldName::as_str)
            .collect();
        let mut filterable = Vec::with_capacity(schema.filterable_fields().len() + 1);
        filterable.push(TENANT_FIELD);
        filterable.extend(
            schema
                .filterable_fields()
                .iter()
                .map(crate::FieldName::as_str),
        );
        let settings = Settings::new()
            .with_searchable_attributes(searchable)
            .with_filterable_attributes(filterable);
        let index = self.client.index(uid);
        let task = index.set_settings(&settings).await.map_err(map_sdk_error)?;
        self.wait_task(task).await?;

        let marker = SchemaMarker {
            id: SCHEMA_MARKER_ID.to_owned(),
            schema_version: schema.version(),
            schema_digest: hex_digest(schema.digest()),
        };
        let task = index
            .add_or_replace(&[marker], Some(PRIMARY_KEY))
            .await
            .map_err(map_sdk_error)?;
        self.wait_task(task).await
    }

    async fn activate_inner(
        &self,
        schema: &IndexSchema,
    ) -> Result<ActivationOutcome, SearchProviderError> {
        let stable_uid = self.stable_uid(schema)?;
        let stable_exists = match self.verify_marker(&stable_uid, schema).await {
            Ok(()) => return Ok(ActivationOutcome::AlreadyActive),
            Err(SearchProviderError::SchemaConflict) => true,
            Err(SearchProviderError::NotFound) => {
                if self.index_exists(&stable_uid).await? {
                    return Err(SearchProviderError::SchemaConflict);
                }
                false
            }
            Err(error) => return Err(error),
        };

        let version_uid = self.version_uid(schema)?;
        self.verify_marker(&version_uid, schema).await?;
        let swap = SwapIndexes {
            indexes: (version_uid, stable_uid.clone()),
            rename: if stable_exists { None } else { Some(true) },
        };
        let task = self
            .client
            .swap_indexes([&swap])
            .await
            .map_err(map_sdk_error)?;
        self.wait_task(task).await?;
        self.verify_marker(&stable_uid, schema).await?;
        Ok(ActivationOutcome::Activated)
    }

    async fn search_inner(
        &self,
        alias: &IndexAlias,
        query: &TenantScopedQuery,
    ) -> Result<ProviderPage, SearchProviderError> {
        let uid = self.stable_alias_uid(alias)?;
        let index = self.client.index(uid);
        let mut request = index.search();
        request
            .with_query(query.query())
            .with_filter(query.rendered_filter())
            .with_attributes_to_retrieve(Selectors::Some(&SEARCH_ATTRIBUTES[..]))
            .with_limit(query.limit())
            .with_offset(query.offset());
        let response = request
            .execute::<IndexedProjectionIdentity>()
            .await
            .map_err(map_sdk_error)?;
        if response.hits.len() > query.limit() {
            return Err(SearchProviderError::InvalidResponse);
        }
        let expected_tenant = query.tenant_id().to_string();
        let mut hits = Vec::with_capacity(response.hits.len());
        for hit in response.hits {
            if hit.result.tenant_id != expected_tenant {
                return Err(SearchProviderError::InvalidResponse);
            }
            let source_id = SourceId::new(hit.result.source_id)
                .map_err(|_| SearchProviderError::InvalidResponse)?;
            let revision = SourceRevision::new(hit.result.source_revision)
                .map_err(|_| SearchProviderError::InvalidResponse)?;
            hits.push(SearchCandidate::new(source_id, revision));
        }
        Ok(ProviderPage::new(hits))
    }

    async fn apply_inner(
        &self,
        target: &ProjectionTarget,
        tenant_id: TenantId,
        mutation: &ProjectionMutation,
    ) -> Result<(), SearchProviderError> {
        let schema = match target {
            ProjectionTarget::Active(schema) | ProjectionTarget::Version(schema) => schema,
        };
        let uid = match target {
            ProjectionTarget::Active(_) => self.stable_uid(schema)?,
            ProjectionTarget::Version(_) => self.version_uid(schema)?,
        };
        match mutation {
            ProjectionMutation::Upsert(document) => {
                let indexed = IndexedProjectionDocument {
                    id: document_id(tenant_id, document.source_id()),
                    tenant_id: tenant_id.to_string(),
                    source_id: document.source_id().as_str(),
                    source_revision: document.revision().get(),
                    schema_version: schema.version(),
                    fields: document.fields(),
                };
                let encoded_len = serde_json::to_vec(&indexed)
                    .map_err(|_| SearchProviderError::Rejected)?
                    .len();
                if encoded_len > self.max_document_bytes {
                    return Err(SearchProviderError::Rejected);
                }
                self.verify_marker(&uid, schema).await?;
                let index = self.client.index(uid);
                let task = index
                    .add_or_replace(&[indexed], Some(PRIMARY_KEY))
                    .await
                    .map_err(map_sdk_error)?;
                self.wait_task(task).await
            }
            ProjectionMutation::Delete {
                source_id,
                revision: _,
            } => {
                self.verify_marker(&uid, schema).await?;
                let index = self.client.index(uid);
                let task = index
                    .delete_document(document_id(tenant_id, source_id))
                    .await
                    .map_err(map_sdk_error)?;
                self.wait_task(task).await
            }
            ProjectionMutation::Ignore => Ok(()),
        }
    }

    async fn health_inner(&self, schema: &IndexSchema) -> Result<(), SearchProviderError> {
        let health = self.client.health().await.map_err(map_sdk_error)?;
        if health.status != "available" {
            return Err(SearchProviderError::Unavailable);
        }
        self.verify_marker(&self.stable_uid(schema)?, schema).await
    }
}

impl SearchProvider for MeilisearchAdapter {
    fn search<'a>(
        &'a self,
        alias: &'a IndexAlias,
        query: &'a TenantScopedQuery,
    ) -> BoxFuture<'a, Result<ProviderPage, SearchProviderError>> {
        Box::pin(async move { self.deadline(self.search_inner(alias, query)).await })
    }

    fn apply<'a>(
        &'a self,
        target: &'a ProjectionTarget,
        tenant_id: TenantId,
        mutation: &'a ProjectionMutation,
    ) -> BoxFuture<'a, Result<(), SearchProviderError>> {
        Box::pin(async move {
            self.deadline(self.apply_inner(target, tenant_id, mutation))
                .await
        })
    }

    fn prepare_index<'a>(
        &'a self,
        schema: &'a IndexSchema,
    ) -> BoxFuture<'a, Result<(), SearchProviderError>> {
        Box::pin(async move { self.deadline(self.prepare_inner(schema)).await })
    }

    fn activate_index<'a>(
        &'a self,
        schema: &'a IndexSchema,
    ) -> BoxFuture<'a, Result<ActivationOutcome, SearchProviderError>> {
        Box::pin(async move { self.deadline(self.activate_inner(schema)).await })
    }

    fn health<'a>(
        &'a self,
        schema: &'a IndexSchema,
    ) -> BoxFuture<'a, Result<(), SearchProviderError>> {
        Box::pin(async move { self.deadline(self.health_inner(schema)).await })
    }
}

/// Adapter construction failure with redacted configuration/provider detail.
#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum MeilisearchAdapterError {
    /// Configuration failed validation.
    #[error(transparent)]
    Configuration(SearchConfigError),
    /// SDK client construction failed.
    #[error(transparent)]
    Provider(SearchProviderError),
}

#[derive(Deserialize, Serialize)]
struct SchemaMarker {
    id: String,
    #[serde(rename = "_schema_version")]
    schema_version: u32,
    #[serde(rename = "_schema_digest")]
    schema_digest: String,
}

#[derive(Deserialize)]
struct IndexedProjectionIdentity {
    #[serde(rename = "_tenant_id")]
    tenant_id: String,
    #[serde(rename = "_source_id")]
    source_id: String,
    #[serde(rename = "_source_revision")]
    source_revision: u64,
}

#[derive(Serialize)]
struct IndexedProjectionDocument<'a> {
    id: String,
    #[serde(rename = "_tenant_id")]
    tenant_id: String,
    #[serde(rename = "_source_id")]
    source_id: &'a str,
    #[serde(rename = "_source_revision")]
    source_revision: u64,
    #[serde(rename = "_schema_version")]
    schema_version: u32,
    #[serde(flatten)]
    fields: &'a BTreeMap<String, Value>,
}

fn map_sdk_error(error: MeilisearchError) -> SearchProviderError {
    match error {
        MeilisearchError::Timeout => SearchProviderError::Timeout,
        MeilisearchError::Meilisearch(error)
            if matches!(
                error.error_code,
                ErrorCode::IndexNotFound | ErrorCode::DocumentNotFound
            ) =>
        {
            SearchProviderError::NotFound
        }
        MeilisearchError::Meilisearch(error)
            if matches!(
                error.error_code,
                ErrorCode::InvalidApiKey
                    | ErrorCode::MissingAuthorizationHeader
                    | ErrorCode::InvalidIndexUid
                    | ErrorCode::InvalidSearchFilter
                    | ErrorCode::InvalidSearchLimit
                    | ErrorCode::InvalidSearchOffset
                    | ErrorCode::InvalidSettingsFilterableAttributes
                    | ErrorCode::InvalidSettingsSearchableAttributes
                    | ErrorCode::InvalidSwapIndexes
            ) =>
        {
            SearchProviderError::Rejected
        }
        MeilisearchError::ParseError(_) => SearchProviderError::InvalidResponse,
        _ => SearchProviderError::Unavailable,
    }
}

fn sdk_not_found(error: &MeilisearchError) -> bool {
    matches!(
        error,
        MeilisearchError::Meilisearch(error)
            if matches!(
                &error.error_code,
                ErrorCode::IndexNotFound | ErrorCode::DocumentNotFound
            )
    )
}

fn hex_digest(digest: [u8; 32]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(64);
    for byte in digest {
        output.push(char::from(HEX[usize::from(byte >> 4)]));
        output.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    output
}

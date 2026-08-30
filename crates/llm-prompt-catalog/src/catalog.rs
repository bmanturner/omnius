use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
};

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use thiserror::Error;

use crate::{
    ContentDigest, DataClassification, EvaluationSetId, OwnerId, PromptId, PromptRevisionNumber,
    RouteId, ToolId,
};

const MAX_SCHEMA_BYTES: usize = 65_536;
const MAX_SCHEMA_DEPTH: usize = 32;
const MAX_SCHEMA_NODES: usize = 4_096;
const MAX_TEMPLATE_BYTES: usize = 65_536;
const MAX_COLLECTION_ITEMS: usize = 256;
const MAX_METADATA_VALUE_BYTES: usize = 2_048;

/// The lifecycle state of one immutable prompt revision.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PromptStatus {
    /// A revision that may still be replaced through an optimistic write.
    Draft,
    /// An immutable revision admitted for production use.
    Published,
    /// An immutable published revision no longer admitted for new production use.
    Deprecated,
}

/// Separately retained privileged templates and an untrusted-data template.
#[derive(Clone, Eq, PartialEq, Serialize)]
pub struct PromptTemplates {
    system: Option<String>,
    developer: Option<String>,
    user: String,
}

impl PromptTemplates {
    /// Creates separated template channels under fixed source-size limits.
    ///
    /// Privileged templates are compiled without an untrusted variable context. The user template
    /// is the only channel in which schema-backed variables are rendered.
    ///
    /// # Errors
    ///
    /// Returns [`CatalogError::TemplateLimit`] when a source is oversized, contains NUL, or all
    /// sources are empty.
    pub fn new(
        system: Option<String>,
        developer: Option<String>,
        user: String,
    ) -> Result<Self, CatalogError> {
        let sources = [system.as_deref(), developer.as_deref(), Some(user.as_str())];
        if sources.iter().flatten().all(|source| source.is_empty())
            || sources
                .iter()
                .flatten()
                .any(|source| source.len() > MAX_TEMPLATE_BYTES || source.contains('\0'))
        {
            return Err(CatalogError::TemplateLimit);
        }
        Ok(Self {
            system,
            developer,
            user,
        })
    }

    /// Borrows the optional trusted system template source.
    #[must_use]
    pub fn system(&self) -> Option<&str> {
        self.system.as_deref()
    }

    /// Borrows the optional trusted developer template source.
    #[must_use]
    pub fn developer(&self) -> Option<&str> {
        self.developer.as_deref()
    }

    /// Borrows the untrusted-data template source.
    #[must_use]
    pub fn user(&self) -> &str {
        &self.user
    }
}

impl fmt::Debug for PromptTemplates {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PromptTemplates")
            .field("system", &self.system.as_ref().map(|_| "[REDACTED]"))
            .field("developer", &self.developer.as_ref().map(|_| "[REDACTED]"))
            .field("user", &"[REDACTED]")
            .finish()
    }
}

/// Catalog ownership, routing, tool, classification, evaluation, and rollout metadata.
#[derive(Clone, Eq, PartialEq, Serialize)]
pub struct PromptAccess {
    owner: OwnerId,
    allowed_routes: BTreeSet<RouteId>,
    allowed_tools: BTreeSet<ToolId>,
    data_classification: DataClassification,
    evaluation_sets: BTreeSet<EvaluationSetId>,
    rollout_metadata: BTreeMap<String, String>,
}

impl PromptAccess {
    /// Validates and owns prompt admission metadata.
    ///
    /// # Errors
    ///
    /// Returns [`CatalogError::MetadataLimit`] for oversized collections, malformed keys, or
    /// values that exceed storage boundaries.
    pub fn new(
        owner: OwnerId,
        allowed_routes: BTreeSet<RouteId>,
        allowed_tools: BTreeSet<ToolId>,
        data_classification: DataClassification,
        evaluation_sets: BTreeSet<EvaluationSetId>,
        rollout_metadata: BTreeMap<String, String>,
    ) -> Result<Self, CatalogError> {
        if allowed_routes.len() > MAX_COLLECTION_ITEMS
            || allowed_tools.len() > MAX_COLLECTION_ITEMS
            || evaluation_sets.len() > MAX_COLLECTION_ITEMS
            || rollout_metadata.len() > MAX_COLLECTION_ITEMS
            || rollout_metadata.iter().any(|(key, value)| {
                key.is_empty()
                    || key.len() > 128
                    || !key.bytes().all(|byte| {
                        byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-')
                    })
                    || value.len() > MAX_METADATA_VALUE_BYTES
                    || value.contains('\0')
            })
        {
            return Err(CatalogError::MetadataLimit);
        }
        Ok(Self {
            owner,
            allowed_routes,
            allowed_tools,
            data_classification,
            evaluation_sets,
            rollout_metadata,
        })
    }

    /// Borrows the prompt owner.
    #[must_use]
    pub const fn owner(&self) -> &OwnerId {
        &self.owner
    }

    /// Borrows the allowed logical routes.
    #[must_use]
    pub const fn allowed_routes(&self) -> &BTreeSet<RouteId> {
        &self.allowed_routes
    }

    /// Borrows the allowed tool identifiers.
    #[must_use]
    pub const fn allowed_tools(&self) -> &BTreeSet<ToolId> {
        &self.allowed_tools
    }

    /// Returns the highest data classification admitted for the prompt.
    #[must_use]
    pub const fn data_classification(&self) -> DataClassification {
        self.data_classification
    }

    /// Borrows the evaluation-set identifiers.
    #[must_use]
    pub const fn evaluation_sets(&self) -> &BTreeSet<EvaluationSetId> {
        &self.evaluation_sets
    }

    /// Borrows bounded rollout metadata.
    #[must_use]
    pub const fn rollout_metadata(&self) -> &BTreeMap<String, String> {
        &self.rollout_metadata
    }
}

impl fmt::Debug for PromptAccess {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PromptAccess")
            .field("owner", &self.owner)
            .field("route_count", &self.allowed_routes.len())
            .field("tool_count", &self.allowed_tools.len())
            .field("data_classification", &self.data_classification)
            .field("evaluation_set_count", &self.evaluation_sets.len())
            .field("rollout_metadata_count", &self.rollout_metadata.len())
            .finish()
    }
}

/// Immutable content shared by all lifecycle states of one prompt revision.
#[derive(Clone, PartialEq, Serialize)]
pub struct PromptBody {
    input_schema: Value,
    templates: PromptTemplates,
    access: PromptAccess,
}

impl PromptBody {
    /// Validates the JSON Schema and owns immutable prompt content.
    ///
    /// # Errors
    ///
    /// Returns a value-free [`CatalogError`] for oversized, excessively nested, remote-referencing,
    /// or invalid Draft 2020-12 schemas.
    pub fn new(
        input_schema: Value,
        templates: PromptTemplates,
        access: PromptAccess,
    ) -> Result<Self, CatalogError> {
        validate_input_schema(&input_schema)?;
        Ok(Self {
            input_schema: canonicalize_json(input_schema),
            templates,
            access,
        })
    }

    /// Borrows the canonical input schema.
    #[must_use]
    pub const fn input_schema(&self) -> &Value {
        &self.input_schema
    }

    /// Borrows separated prompt template channels.
    #[must_use]
    pub const fn templates(&self) -> &PromptTemplates {
        &self.templates
    }

    /// Borrows catalog admission metadata.
    #[must_use]
    pub const fn access(&self) -> &PromptAccess {
        &self.access
    }
}

impl fmt::Debug for PromptBody {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PromptBody")
            .field("input_schema", &"[REDACTED]")
            .field("templates", &self.templates)
            .field("access", &self.access)
            .finish()
    }
}

/// One stable, digest-bound prompt revision and its lifecycle status.
#[derive(Clone, PartialEq, Serialize)]
pub struct PromptRevision {
    id: PromptId,
    revision: PromptRevisionNumber,
    status: PromptStatus,
    body: PromptBody,
    content_digest: ContentDigest,
}

impl PromptRevision {
    /// Creates a draft and binds its complete immutable content to a canonical digest.
    ///
    /// # Errors
    ///
    /// Returns [`CatalogError::InvalidDefinition`] if canonical serialization fails.
    pub fn new_draft(
        id: PromptId,
        revision: PromptRevisionNumber,
        body: PromptBody,
    ) -> Result<Self, CatalogError> {
        let content_digest = digest_definition(&id, revision, &body)?;
        Ok(Self {
            id,
            revision,
            status: PromptStatus::Draft,
            body,
            content_digest,
        })
    }

    /// Rehydrates a persisted revision while verifying its canonical content digest.
    ///
    /// # Errors
    ///
    /// Returns [`CatalogError::InvalidDefinition`] when persisted content and digest differ.
    pub fn from_persisted(
        id: PromptId,
        revision: PromptRevisionNumber,
        status: PromptStatus,
        body: PromptBody,
        content_digest: ContentDigest,
    ) -> Result<Self, CatalogError> {
        if digest_definition(&id, revision, &body)? != content_digest {
            return Err(CatalogError::InvalidDefinition);
        }
        Ok(Self {
            id,
            revision,
            status,
            body,
            content_digest,
        })
    }

    /// Returns the same immutable content in the next legal lifecycle state.
    ///
    /// Persistence adapters use this after winning the atomic compare-and-set. This method never
    /// changes content or its digest.
    ///
    /// # Errors
    ///
    /// Returns [`CatalogError::InvalidTransition`] unless the transition is `Draft -> Published`
    /// or `Published -> Deprecated`.
    pub fn transitioned(&self, target: PromptStatus) -> Result<Self, CatalogError> {
        if !matches!(
            (self.status, target),
            (PromptStatus::Draft, PromptStatus::Published)
                | (PromptStatus::Published, PromptStatus::Deprecated)
        ) {
            return Err(CatalogError::InvalidTransition);
        }
        let mut transitioned = self.clone();
        transitioned.status = target;
        Ok(transitioned)
    }

    /// Borrows the stable prompt identifier.
    #[must_use]
    pub const fn id(&self) -> &PromptId {
        &self.id
    }

    /// Returns the immutable revision number.
    #[must_use]
    pub const fn revision(&self) -> PromptRevisionNumber {
        self.revision
    }

    /// Returns the lifecycle status.
    #[must_use]
    pub const fn status(&self) -> PromptStatus {
        self.status
    }

    /// Borrows immutable prompt content.
    #[must_use]
    pub const fn body(&self) -> &PromptBody {
        &self.body
    }

    /// Returns the canonical content digest, which does not change across status transitions.
    #[must_use]
    pub const fn content_digest(&self) -> ContentDigest {
        self.content_digest
    }
}

impl fmt::Debug for PromptRevision {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PromptRevision")
            .field("id", &self.id)
            .field("revision", &self.revision)
            .field("status", &self.status)
            .field("content", &"[REDACTED]")
            .finish_non_exhaustive()
    }
}

/// Stable persistence failures returned by a prompt catalog adapter.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum PromptStoreError {
    /// The stable prompt or revision was not found.
    #[error("prompt revision was not found")]
    NotFound,
    /// A first revision or the same revision already exists.
    #[error("prompt revision already exists")]
    AlreadyExists,
    /// The expected latest revision, status, or content digest lost an optimistic race.
    #[error("prompt revision conflict")]
    RevisionConflict,
    /// A write attempted to replace published or deprecated content.
    #[error("published prompt content is immutable")]
    Immutable,
    /// Persistence was unavailable.
    #[error("prompt persistence is unavailable")]
    Unavailable,
}

/// Atomic persistence boundary for the immutable prompt lifecycle.
#[async_trait]
pub trait PromptCatalogStore: Send + Sync {
    /// Inserts a draft only if the stable prompt's latest revision equals `expected_latest`.
    ///
    /// Adapters MUST compare and insert atomically, require revision one when `expected_latest` is
    /// absent, and retain every published/deprecated revision.
    async fn insert_draft(
        &self,
        draft: PromptRevision,
        expected_latest: Option<PromptRevisionNumber>,
    ) -> Result<PromptRevision, PromptStoreError>;

    /// Replaces draft content only when the stored digest matches `expected_content_digest`.
    ///
    /// Adapters MUST require both stored and replacement status to be `Draft`, and reject any
    /// published or deprecated side as [`PromptStoreError::Immutable`].
    async fn replace_draft(
        &self,
        replacement: PromptRevision,
        expected_content_digest: ContentDigest,
    ) -> Result<PromptRevision, PromptStoreError>;

    /// Atomically changes only lifecycle state under status and content-digest preconditions.
    ///
    /// Adapters MUST reject content changes and permit only `Draft -> Published` or
    /// `Published -> Deprecated`.
    async fn compare_and_set_status(
        &self,
        id: &PromptId,
        revision: PromptRevisionNumber,
        expected_content_digest: ContentDigest,
        expected_status: PromptStatus,
        target_status: PromptStatus,
    ) -> Result<PromptRevision, PromptStoreError>;

    /// Loads one exact retained revision.
    async fn get_revision(
        &self,
        id: &PromptId,
        revision: PromptRevisionNumber,
    ) -> Result<PromptRevision, PromptStoreError>;
}

/// Lifecycle validation over an atomic persistence adapter.
#[derive(Debug)]
pub struct PromptCatalog<S> {
    store: S,
}

impl<S> PromptCatalog<S>
where
    S: PromptCatalogStore,
{
    /// Creates a catalog around a persistence adapter.
    #[must_use]
    pub const fn new(store: S) -> Self {
        Self { store }
    }

    /// Inserts the first or next draft under an optimistic latest-revision check.
    ///
    /// # Errors
    ///
    /// Returns [`PromptStoreError::RevisionConflict`] for a non-contiguous revision, or the
    /// adapter's value-free persistence failure.
    pub async fn create_draft(
        &self,
        draft: PromptRevision,
        expected_latest: Option<PromptRevisionNumber>,
    ) -> Result<PromptRevision, PromptStoreError> {
        if draft.status() != PromptStatus::Draft
            || match expected_latest {
                Some(current) => current.checked_next() != Some(draft.revision()),
                None => draft.revision().get() != 1,
            }
        {
            return Err(PromptStoreError::RevisionConflict);
        }
        self.store.insert_draft(draft, expected_latest).await
    }

    /// Replaces only draft content under an optimistic digest check.
    ///
    /// # Errors
    ///
    /// Returns the adapter's value-free conflict, immutability, or availability failure.
    pub async fn replace_draft(
        &self,
        replacement: PromptRevision,
        expected_content_digest: ContentDigest,
    ) -> Result<PromptRevision, PromptStoreError> {
        if replacement.status() != PromptStatus::Draft {
            return Err(PromptStoreError::Immutable);
        }
        self.store
            .replace_draft(replacement, expected_content_digest)
            .await
    }

    /// Publishes a draft under exact revision and content preconditions.
    ///
    /// # Errors
    ///
    /// Returns the adapter's value-free conflict, immutability, or availability failure.
    pub async fn publish(
        &self,
        id: &PromptId,
        revision: PromptRevisionNumber,
        expected_content_digest: ContentDigest,
    ) -> Result<PromptRevision, PromptStoreError> {
        self.store
            .compare_and_set_status(
                id,
                revision,
                expected_content_digest,
                PromptStatus::Draft,
                PromptStatus::Published,
            )
            .await
    }

    /// Deprecates a published revision without modifying its content.
    ///
    /// # Errors
    ///
    /// Returns the adapter's value-free conflict, immutability, or availability failure.
    pub async fn deprecate(
        &self,
        id: &PromptId,
        revision: PromptRevisionNumber,
        expected_content_digest: ContentDigest,
    ) -> Result<PromptRevision, PromptStoreError> {
        self.store
            .compare_and_set_status(
                id,
                revision,
                expected_content_digest,
                PromptStatus::Published,
                PromptStatus::Deprecated,
            )
            .await
    }

    /// Loads an exact retained revision.
    ///
    /// # Errors
    ///
    /// Returns the adapter's value-free persistence failure.
    pub async fn get_revision(
        &self,
        id: &PromptId,
        revision: PromptRevisionNumber,
    ) -> Result<PromptRevision, PromptStoreError> {
        self.store.get_revision(id, revision).await
    }
}

/// A value-free prompt-definition validation failure.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum CatalogError {
    /// The input schema was not a bounded valid Draft 2020-12 object schema.
    #[error("prompt input schema is invalid")]
    InvalidSchema,
    /// A template source was not representable, exceeded its boundary, or all sources were empty.
    #[error("prompt template source is invalid")]
    TemplateLimit,
    /// Prompt metadata exceeded fixed count, byte, or storage boundaries.
    #[error("prompt metadata exceeds its limit")]
    MetadataLimit,
    /// The immutable prompt definition could not be canonically encoded.
    #[error("prompt definition is invalid")]
    InvalidDefinition,
    /// A requested lifecycle transition skipped or repeated a state.
    #[error("prompt lifecycle transition is invalid")]
    InvalidTransition,
}

fn validate_input_schema(schema: &Value) -> Result<(), CatalogError> {
    let Some(object) = schema.as_object() else {
        return Err(CatalogError::InvalidSchema);
    };
    if object.get("type").and_then(Value::as_str) != Some("object")
        || object
            .get("properties")
            .is_some_and(|properties| !properties.is_object())
    {
        return Err(CatalogError::InvalidSchema);
    }
    let encoded = serde_json::to_vec(schema).map_err(|_| CatalogError::InvalidSchema)?;
    if encoded.len() > MAX_SCHEMA_BYTES {
        return Err(CatalogError::InvalidSchema);
    }
    let mut nodes = 0_usize;
    validate_schema_node(schema, 0, &mut nodes)?;
    jsonschema::draft202012::options()
        .build(schema)
        .map_err(|_| CatalogError::InvalidSchema)?;
    Ok(())
}

fn validate_schema_node(
    value: &Value,
    depth: usize,
    nodes: &mut usize,
) -> Result<(), CatalogError> {
    *nodes = nodes.checked_add(1).ok_or(CatalogError::InvalidSchema)?;
    if depth > MAX_SCHEMA_DEPTH || *nodes > MAX_SCHEMA_NODES {
        return Err(CatalogError::InvalidSchema);
    }
    match value {
        Value::Object(object) => {
            if object.keys().any(|key| key.contains('\0')) {
                return Err(CatalogError::InvalidSchema);
            }
            if object
                .get("$ref")
                .and_then(Value::as_str)
                .is_some_and(|reference| !reference.starts_with("#/"))
            {
                return Err(CatalogError::InvalidSchema);
            }
            for child in object.values() {
                validate_schema_node(child, depth + 1, nodes)?;
            }
        }
        Value::Array(array) => {
            for child in array {
                validate_schema_node(child, depth + 1, nodes)?;
            }
        }
        Value::String(value) if value.contains('\0') => return Err(CatalogError::InvalidSchema),
        Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) => {}
    }
    Ok(())
}

fn canonicalize_json(value: Value) -> Value {
    match value {
        Value::Object(object) => {
            let ordered = object
                .into_iter()
                .map(|(key, value)| (key, canonicalize_json(value)))
                .collect::<BTreeMap<_, _>>();
            Value::Object(Map::from_iter(ordered))
        }
        Value::Array(values) => Value::Array(values.into_iter().map(canonicalize_json).collect()),
        scalar => scalar,
    }
}

#[derive(Serialize)]
struct DigestDefinition<'a> {
    id: &'a PromptId,
    revision: PromptRevisionNumber,
    body: &'a PromptBody,
}

fn digest_definition(
    id: &PromptId,
    revision: PromptRevisionNumber,
    body: &PromptBody,
) -> Result<ContentDigest, CatalogError> {
    let encoded = serde_json::to_vec(&DigestDefinition { id, revision, body })
        .map_err(|_| CatalogError::InvalidDefinition)?;
    Ok(ContentDigest::of(&encoded))
}

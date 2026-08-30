use std::{fmt, sync::Arc};

use omnius_agent_capability_registry::{
    JSON_SCHEMA_DRAFT_2020_12, MAX_SCHEMA_BYTES, MAX_SCHEMA_DEPTH, MAX_SCHEMA_NODES,
};
use omnius_validation::{
    JsonPayloadError, JsonSchemaAdapter, JsonValidationLimits, SchemaAdapterError,
};
use serde::{Serialize, Serializer};
use serde_json::Value;
use thiserror::Error;

struct CompiledSchema {
    document: Value,
    validator: JsonSchemaAdapter,
}

/// A bounded JSON Schema Draft 2020-12 document with local references only.
///
/// Both boolean schemas and object schemas are accepted. Instances may be any JSON value.
#[derive(Clone)]
pub struct JsonSchemaDocument(Arc<CompiledSchema>);

impl JsonSchemaDocument {
    /// Compiles a bounded Draft 2020-12 schema document.
    ///
    /// An omitted `$schema` is interpreted as Draft 2020-12. When present, the dialect must be the
    /// canonical Draft 2020-12 URI. Network and file reference retrieval are never enabled.
    ///
    /// # Errors
    ///
    /// Returns [`SchemaDocumentError`] without retaining or rendering the rejected document.
    pub fn compile(document: Value) -> Result<Self, SchemaDocumentError> {
        if !matches!(document, Value::Bool(_) | Value::Object(_)) {
            return Err(SchemaDocumentError::InvalidRoot);
        }
        if let Value::Object(object) = &document
            && let Some(dialect) = object.get("$schema")
            && dialect.as_str() != Some(JSON_SCHEMA_DRAFT_2020_12)
        {
            return Err(SchemaDocumentError::UnsupportedDialect);
        }

        let canonical = serde_json::to_vec(&document)
            .map_err(|_| SchemaDocumentError::InvalidDocument)?
            .into_boxed_slice();
        let limits = JsonValidationLimits {
            max_schema_bytes: MAX_SCHEMA_BYTES,
            max_depth: MAX_SCHEMA_DEPTH,
            max_nodes: MAX_SCHEMA_NODES,
            ..JsonValidationLimits::default()
        };
        let validator = JsonSchemaAdapter::compile(&canonical, limits)
            .map_err(SchemaDocumentError::from_adapter)?;
        Ok(Self(Arc::new(CompiledSchema {
            document,
            validator,
        })))
    }

    /// Borrows the immutable schema document.
    #[must_use]
    pub fn document(&self) -> &Value {
        &self.0.document
    }

    /// Validates one bounded arbitrary JSON instance.
    ///
    /// # Errors
    ///
    /// Returns a fixed [`SchemaValidationError`] category without instance or schema details.
    pub fn validate(&self, instance: &Value) -> Result<(), SchemaValidationError> {
        let encoded = serde_json::to_vec(instance).map_err(|_| SchemaValidationError::Rejected)?;
        self.0
            .validator
            .validate_bytes(&encoded)
            .map(|_| ())
            .map_err(|error| SchemaValidationError::from_payload(&error))
    }
}

impl PartialEq for JsonSchemaDocument {
    fn eq(&self, other: &Self) -> bool {
        self.0.document == other.0.document
    }
}

impl Eq for JsonSchemaDocument {}

impl fmt::Debug for JsonSchemaDocument {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("JsonSchemaDocument([redacted])")
    }
}

impl Serialize for JsonSchemaDocument {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        self.0.document.serialize(serializer)
    }
}

/// A fixed, value-free schema compilation failure.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum SchemaDocumentError {
    /// A JSON Schema document was neither a boolean nor an object.
    #[error("JSON Schema document must be a boolean or object")]
    InvalidRoot,
    /// An explicit dialect was not Draft 2020-12.
    #[error("JSON Schema dialect is unsupported")]
    UnsupportedDialect,
    /// The schema exceeded a fixed byte or structural bound.
    #[error("JSON Schema document exceeds a fixed bound")]
    BoundsExceeded,
    /// A reference attempted network, file, or other non-local resolution.
    #[error("JSON Schema contains a non-local reference")]
    NonLocalReference,
    /// The document was not a valid Draft 2020-12 schema.
    #[error("JSON Schema document is invalid")]
    InvalidDocument,
}

impl SchemaDocumentError {
    fn from_adapter(error: SchemaAdapterError) -> Self {
        match error {
            SchemaAdapterError::TooLarge | SchemaAdapterError::Structure(_) => Self::BoundsExceeded,
            SchemaAdapterError::NonLocalReference => Self::NonLocalReference,
            SchemaAdapterError::InvalidLimits(_)
            | SchemaAdapterError::Malformed
            | SchemaAdapterError::InvalidSchema => Self::InvalidDocument,
        }
    }
}

/// A fixed, value-free JSON instance validation failure.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum SchemaValidationError {
    /// The encoded instance exceeded its fixed byte limit.
    #[error("JSON instance exceeds a fixed byte limit")]
    TooLarge,
    /// The instance exceeded a fixed structural limit.
    #[error("JSON instance exceeds a fixed structural limit")]
    Structure,
    /// The instance did not satisfy the compiled schema.
    #[error("JSON instance was rejected")]
    Rejected,
}

impl SchemaValidationError {
    fn from_payload(error: &JsonPayloadError) -> Self {
        match error {
            JsonPayloadError::TooLarge => Self::TooLarge,
            JsonPayloadError::Structure(_) => Self::Structure,
            JsonPayloadError::Malformed | JsonPayloadError::Validation(_) => Self::Rejected,
        }
    }
}

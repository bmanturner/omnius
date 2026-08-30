use omnius_llm_core::SchemaDefinition;
use schemars::{JsonSchema, generate::SchemaSettings};
use thiserror::Error;

/// Failure to convert a Rust-owned Schemars schema into the canonical contract.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[error("Rust-owned JSON Schema could not be generated")]
pub struct SchemaGenerationError;

/// Generates the canonical JSON Schema Draft 2020-12 definition for an owned Rust type.
///
/// The generated definition still passes through [`crate::PreparedStructuredOutput::prepare`]
/// so provider use remains subject to the same schema byte and structure bounds.
///
/// # Errors
///
/// Returns a value-free [`SchemaGenerationError`] when the generated schema cannot be
/// represented by the canonical object-or-boolean schema contract.
pub fn schema_definition_for<T>() -> Result<SchemaDefinition, SchemaGenerationError>
where
    T: JsonSchema + ?Sized,
{
    let schema = SchemaSettings::draft2020_12()
        .into_generator()
        .into_root_schema_for::<T>();
    let value = serde_json::to_value(schema).map_err(|_| SchemaGenerationError)?;
    serde_json::from_value(value).map_err(|_| SchemaGenerationError)
}

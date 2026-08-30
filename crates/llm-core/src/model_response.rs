use std::{collections::BTreeSet, fmt};

use schemars::{JsonSchema, Schema, SchemaGenerator};
use serde::{Deserialize, Deserializer, Serialize, Serializer, de::Error as _};
use serde_json::{Number, Value, value::RawValue};
use time::OffsetDateTime;

use crate::extended_content::{
    ContentLimits, validate_base64_decoded_len, validate_bounded_json,
    validate_bounded_json_object, validate_bounded_string, validate_content_depth,
    validate_nested_content_collection,
};
use crate::request::BinarySource;
use crate::response::{CompletionStatus, LlmResponse};
use crate::value::{
    ContractError, JsonObject, LlmRequestId, SchemaVersion, UtcTimestamp,
    deserialize_optional_non_null, deserialize_without_field, validate_identifier,
    validate_mime_type, validate_name,
};

/// The discriminator for a specialized canonical model operation response.
#[derive(Clone, Copy, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ModelOperation {
    /// Vector embedding generation.
    Embeddings,
    /// Document reranking.
    Rerank,
    /// Audio transcription.
    Transcription,
    /// Speech synthesis.
    Speech,
    /// Image, audio, video, file, or resource generation.
    MediaGeneration,
    /// Input classification.
    Classification,
}

fn embeddings_operation_schema(_generator: &mut SchemaGenerator) -> Schema {
    schemars::json_schema!({"type": "string", "const": "embeddings"})
}

fn rerank_operation_schema(_generator: &mut SchemaGenerator) -> Schema {
    schemars::json_schema!({"type": "string", "const": "rerank"})
}

fn transcription_operation_schema(_generator: &mut SchemaGenerator) -> Schema {
    schemars::json_schema!({"type": "string", "const": "transcription"})
}

fn speech_operation_schema(_generator: &mut SchemaGenerator) -> Schema {
    schemars::json_schema!({"type": "string", "const": "speech"})
}

fn media_generation_operation_schema(_generator: &mut SchemaGenerator) -> Schema {
    schemars::json_schema!({"type": "string", "const": "media_generation"})
}

fn classification_operation_schema(_generator: &mut SchemaGenerator) -> Schema {
    schemars::json_schema!({"type": "string", "const": "classification"})
}

/// Usage counters shared by all specialized model operations.
///
/// Completion responses intentionally retain their distinct [`crate::response::Usage`]
/// contract through [`LlmResponse`].
#[derive(Clone, Debug, Default, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ModelUsage {
    input_tokens: Option<u64>,
    output_tokens: Option<u64>,
    total_tokens: Option<u64>,
    input_units: Option<u64>,
    output_units: Option<u64>,
    cache_read_tokens: Option<u64>,
    cache_write_tokens: Option<u64>,
    estimated_cost_microunits: Option<u64>,
    actual_cost_microunits: Option<u64>,
    #[serde(
        default,
        deserialize_with = "deserialize_optional_non_null",
        skip_serializing_if = "Option::is_none"
    )]
    #[schemars(with = "JsonObject")]
    provider_units: Option<JsonObject>,
}

impl ModelUsage {
    /// Creates an empty specialized usage object.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            input_tokens: None,
            output_tokens: None,
            total_tokens: None,
            input_units: None,
            output_units: None,
            cache_read_tokens: None,
            cache_write_tokens: None,
            estimated_cost_microunits: None,
            actual_cost_microunits: None,
            provider_units: None,
        }
    }

    /// Adds provider token counters.
    #[must_use]
    pub const fn with_tokens(
        mut self,
        input_tokens: Option<u64>,
        output_tokens: Option<u64>,
        total_tokens: Option<u64>,
    ) -> Self {
        self.input_tokens = input_tokens;
        self.output_tokens = output_tokens;
        self.total_tokens = total_tokens;
        self
    }

    /// Adds provider input and output unit counters.
    #[must_use]
    pub const fn with_units(mut self, input_units: Option<u64>, output_units: Option<u64>) -> Self {
        self.input_units = input_units;
        self.output_units = output_units;
        self
    }

    /// Adds provider cache token counters.
    #[must_use]
    pub const fn with_cache_tokens(
        mut self,
        cache_read_tokens: Option<u64>,
        cache_write_tokens: Option<u64>,
    ) -> Self {
        self.cache_read_tokens = cache_read_tokens;
        self.cache_write_tokens = cache_write_tokens;
        self
    }

    /// Adds cost counters and namespaced provider units.
    #[must_use]
    pub fn with_costs(
        mut self,
        estimated_cost_microunits: Option<u64>,
        actual_cost_microunits: Option<u64>,
        provider_units: Option<JsonObject>,
    ) -> Self {
        self.estimated_cost_microunits = estimated_cost_microunits;
        self.actual_cost_microunits = actual_cost_microunits;
        self.provider_units = provider_units;
        self
    }

    /// Returns input tokens.
    #[must_use]
    pub const fn input_tokens(&self) -> Option<u64> {
        self.input_tokens
    }

    /// Returns output tokens.
    #[must_use]
    pub const fn output_tokens(&self) -> Option<u64> {
        self.output_tokens
    }

    /// Returns total tokens.
    #[must_use]
    pub const fn total_tokens(&self) -> Option<u64> {
        self.total_tokens
    }

    /// Returns input units.
    #[must_use]
    pub const fn input_units(&self) -> Option<u64> {
        self.input_units
    }

    /// Returns output units.
    #[must_use]
    pub const fn output_units(&self) -> Option<u64> {
        self.output_units
    }

    /// Returns cache-read tokens.
    #[must_use]
    pub const fn cache_read_tokens(&self) -> Option<u64> {
        self.cache_read_tokens
    }

    /// Returns cache-write tokens.
    #[must_use]
    pub const fn cache_write_tokens(&self) -> Option<u64> {
        self.cache_write_tokens
    }

    /// Returns estimated cost in microunits.
    #[must_use]
    pub const fn estimated_cost_microunits(&self) -> Option<u64> {
        self.estimated_cost_microunits
    }

    /// Returns actual cost in microunits.
    #[must_use]
    pub const fn actual_cost_microunits(&self) -> Option<u64> {
        self.actual_cost_microunits
    }

    /// Borrows namespaced provider units.
    #[must_use]
    pub const fn provider_units(&self) -> Option<&JsonObject> {
        self.provider_units.as_ref()
    }
}

/// The wire encoding used by a binary embedding vector.
#[derive(Clone, Copy, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum BinaryEmbeddingEncoding {
    /// Little-endian IEEE 754 32-bit floats.
    Float32Le,
    /// Little-endian IEEE 754 16-bit floats.
    Float16Le,
    /// Signed eight-bit integers.
    Int8,
    /// Unsigned eight-bit integers.
    Uint8,
    /// One packed bit per dimension.
    BitPacked,
    /// Provider-defined binary representation.
    Provider,
}

/// A dense floating-point embedding.
#[derive(Clone, Debug, Deserialize, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DenseEmbedding {
    values: Vec<f64>,
    dimensions: u64,
    normalization: Option<String>,
}

impl DenseEmbedding {
    /// Creates a dense embedding whose declared dimension matches its values.
    ///
    /// # Errors
    ///
    /// Returns [`ContractError::InvalidContent`] for a zero or mismatched dimension or a
    /// non-finite value.
    pub fn new(values: Vec<f64>, dimensions: u64) -> Result<Self, ContractError> {
        let embedding = Self {
            values,
            dimensions,
            normalization: None,
        };
        embedding.validate()?;
        Ok(embedding)
    }

    /// Adds the provider's nullable normalization name.
    #[must_use]
    pub fn with_normalization(mut self, normalization: Option<String>) -> Self {
        self.normalization = normalization;
        self
    }

    /// Borrows vector values.
    #[must_use]
    pub fn values(&self) -> &[f64] {
        &self.values
    }

    /// Returns the declared dimensions.
    #[must_use]
    pub const fn dimensions(&self) -> u64 {
        self.dimensions
    }

    /// Borrows the optional normalization name.
    #[must_use]
    pub fn normalization(&self) -> Option<&str> {
        self.normalization.as_deref()
    }

    fn validate(&self) -> Result<(), ContractError> {
        validate_vector(&self.values, self.dimensions)
    }
}

/// A sparse floating-point embedding.
#[derive(Clone, Debug, Deserialize, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SparseEmbedding {
    indices: Vec<u64>,
    values: Vec<f64>,
    dimensions: u64,
}

impl SparseEmbedding {
    /// Creates a sparse embedding with aligned, unique indices and values.
    ///
    /// # Errors
    ///
    /// Returns [`ContractError::InvalidContent`] when dimensions are zero, indices and values
    /// are misaligned, an index is duplicated or out of bounds, or a value is not finite.
    pub fn new(
        indices: Vec<u64>,
        values: Vec<f64>,
        dimensions: u64,
    ) -> Result<Self, ContractError> {
        let embedding = Self {
            indices,
            values,
            dimensions,
        };
        embedding.validate()?;
        Ok(embedding)
    }

    /// Borrows sparse indices.
    #[must_use]
    pub fn indices(&self) -> &[u64] {
        &self.indices
    }

    /// Borrows sparse values aligned with [`Self::indices`].
    #[must_use]
    pub fn values(&self) -> &[f64] {
        &self.values
    }

    /// Returns the full vector dimensions.
    #[must_use]
    pub const fn dimensions(&self) -> u64 {
        self.dimensions
    }

    fn validate(&self) -> Result<(), ContractError> {
        if self.dimensions == 0 || self.indices.len() != self.values.len() {
            return Err(ContractError::InvalidContent);
        }
        let mut retained = BTreeSet::new();
        for (&index, value) in self.indices.iter().zip(&self.values) {
            if index >= self.dimensions || !retained.insert(index) || !value.is_finite() {
                return Err(ContractError::InvalidContent);
            }
        }
        Ok(())
    }
}

/// A base64-encoded binary embedding.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BinaryEmbedding {
    data_base64: String,
    encoding: BinaryEmbeddingEncoding,
    dimensions: u64,
}

impl BinaryEmbedding {
    /// Creates a dimensioned binary embedding.
    ///
    /// # Errors
    ///
    /// Returns [`ContractError::InvalidContent`] for invalid base64, zero dimensions, or a
    /// byte length inconsistent with a fixed-width encoding.
    pub fn new(
        data_base64: String,
        encoding: BinaryEmbeddingEncoding,
        dimensions: u64,
    ) -> Result<Self, ContractError> {
        let embedding = Self {
            data_base64,
            encoding,
            dimensions,
        };
        embedding.validate()?;
        Ok(embedding)
    }

    /// Borrows the exact base64 representation.
    #[must_use]
    pub fn data_base64(&self) -> &str {
        &self.data_base64
    }

    /// Returns the binary encoding.
    #[must_use]
    pub const fn encoding(&self) -> BinaryEmbeddingEncoding {
        self.encoding
    }

    /// Returns the declared dimensions.
    #[must_use]
    pub const fn dimensions(&self) -> u64 {
        self.dimensions
    }

    fn validate(&self) -> Result<(), ContractError> {
        if self.dimensions == 0 {
            return Err(ContractError::InvalidContent);
        }
        let decoded_len = validate_base64_decoded_len(&self.data_base64)?;
        let dimensions =
            usize::try_from(self.dimensions).map_err(|_| ContractError::InvalidContent)?;
        let expected = match self.encoding {
            BinaryEmbeddingEncoding::Float32Le => dimensions.checked_mul(4),
            BinaryEmbeddingEncoding::Float16Le => dimensions.checked_mul(2),
            BinaryEmbeddingEncoding::Int8 | BinaryEmbeddingEncoding::Uint8 => Some(dimensions),
            BinaryEmbeddingEncoding::BitPacked => dimensions.checked_add(7).map(|value| value / 8),
            BinaryEmbeddingEncoding::Provider => return Ok(()),
        }
        .ok_or(ContractError::InvalidContent)?;
        if decoded_len == expected {
            Ok(())
        } else {
            Err(ContractError::InvalidContent)
        }
    }
}

/// One named vector in a multi-vector embedding.
#[derive(Clone, Debug, Deserialize, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EmbeddingVector {
    name: Option<String>,
    values: Vec<f64>,
    dimensions: u64,
}

impl EmbeddingVector {
    /// Creates one dimensioned vector.
    ///
    /// # Errors
    ///
    /// Returns [`ContractError::InvalidContent`] for zero or mismatched dimensions or a
    /// non-finite value.
    pub fn new(values: Vec<f64>, dimensions: u64) -> Result<Self, ContractError> {
        let vector = Self {
            name: None,
            values,
            dimensions,
        };
        vector.validate()?;
        Ok(vector)
    }

    /// Adds a nullable provider vector name.
    #[must_use]
    pub fn with_name(mut self, name: Option<String>) -> Self {
        self.name = name;
        self
    }

    /// Borrows the optional vector name.
    #[must_use]
    pub fn name(&self) -> Option<&str> {
        self.name.as_deref()
    }

    /// Borrows vector values.
    #[must_use]
    pub fn values(&self) -> &[f64] {
        &self.values
    }

    /// Returns the declared dimensions.
    #[must_use]
    pub const fn dimensions(&self) -> u64 {
        self.dimensions
    }

    fn validate(&self) -> Result<(), ContractError> {
        validate_vector(&self.values, self.dimensions)
    }
}

/// A non-empty provider multi-vector embedding.
#[derive(Clone, Debug, Deserialize, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct MultiVectorEmbedding {
    vectors: Vec<EmbeddingVector>,
}

impl MultiVectorEmbedding {
    /// Creates a non-empty multi-vector embedding.
    ///
    /// # Errors
    ///
    /// Returns [`ContractError::InvalidContent`] when no vectors are retained or a nested
    /// vector is invalid.
    pub fn new(vectors: Vec<EmbeddingVector>) -> Result<Self, ContractError> {
        let embedding = Self { vectors };
        embedding.validate()?;
        Ok(embedding)
    }

    /// Borrows the retained vectors in provider order.
    #[must_use]
    pub fn vectors(&self) -> &[EmbeddingVector] {
        &self.vectors
    }

    fn validate(&self) -> Result<(), ContractError> {
        if self.vectors.is_empty() {
            return Err(ContractError::InvalidContent);
        }
        self.vectors.iter().try_for_each(EmbeddingVector::validate)
    }
}

/// A lossless embedding representation.
#[derive(Clone, Debug, JsonSchema, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum EmbeddingValue {
    /// A dense floating-point vector.
    Dense(DenseEmbedding),
    /// A sparse floating-point vector.
    Sparse(SparseEmbedding),
    /// An encoded binary vector.
    Binary(BinaryEmbedding),
    /// Multiple named or unnamed dense vectors.
    MultiVector(MultiVectorEmbedding),
}

impl<'de> Deserialize<'de> for EmbeddingValue {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct KindProbe {
            kind: String,
        }

        let raw = Box::<RawValue>::deserialize(deserializer)?;
        let probe: KindProbe = serde_json::from_str(raw.get()).map_err(D::Error::custom)?;
        let embedding = match probe.kind.as_str() {
            "dense" => {
                Self::Dense(deserialize_without_field(&raw, "kind").map_err(D::Error::custom)?)
            }
            "sparse" => {
                Self::Sparse(deserialize_without_field(&raw, "kind").map_err(D::Error::custom)?)
            }
            "binary" => {
                Self::Binary(deserialize_without_field(&raw, "kind").map_err(D::Error::custom)?)
            }
            "multi-vector" => Self::MultiVector(
                deserialize_without_field(&raw, "kind").map_err(D::Error::custom)?,
            ),
            _ => return Err(D::Error::custom(ContractError::InvalidContent)),
        };
        embedding.validate().map_err(D::Error::custom)?;
        Ok(embedding)
    }
}

impl EmbeddingValue {
    fn validate(&self) -> Result<(), ContractError> {
        match self {
            Self::Dense(value) => value.validate(),
            Self::Sparse(value) => value.validate(),
            Self::Binary(value) => value.validate(),
            Self::MultiVector(value) => value.validate(),
        }
    }
}

/// One indexed embedding result.
#[derive(Clone, Debug, Deserialize, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EmbeddingItem {
    index: u64,
    input_id: Option<String>,
    embedding: EmbeddingValue,
    #[serde(
        default,
        deserialize_with = "deserialize_optional_non_null",
        skip_serializing_if = "Option::is_none"
    )]
    #[schemars(with = "JsonObject")]
    provider_metadata: Option<JsonObject>,
}

impl EmbeddingItem {
    /// Creates one indexed embedding result.
    ///
    /// # Errors
    ///
    /// Returns [`ContractError::InvalidContent`] when the embedding is invalid.
    pub fn new(index: u64, embedding: EmbeddingValue) -> Result<Self, ContractError> {
        let item = Self {
            index,
            input_id: None,
            embedding,
            provider_metadata: None,
        };
        item.validate()?;
        Ok(item)
    }

    /// Adds nullable input identity and namespaced provider metadata.
    ///
    /// # Errors
    ///
    /// Returns a value-free [`ContractError`] when a supplied input identifier is empty.
    pub fn with_details(
        mut self,
        input_id: Option<String>,
        provider_metadata: Option<JsonObject>,
    ) -> Result<Self, ContractError> {
        validate_optional_identifier(input_id.as_deref())?;
        self.input_id = input_id;
        self.provider_metadata = provider_metadata;
        Ok(self)
    }

    /// Returns the stable input index.
    #[must_use]
    pub const fn index(&self) -> u64 {
        self.index
    }

    /// Borrows the nullable input identifier.
    #[must_use]
    pub fn input_id(&self) -> Option<&str> {
        self.input_id.as_deref()
    }

    /// Borrows the lossless embedding representation.
    #[must_use]
    pub const fn embedding(&self) -> &EmbeddingValue {
        &self.embedding
    }

    /// Borrows namespaced provider metadata.
    #[must_use]
    pub const fn provider_metadata(&self) -> Option<&JsonObject> {
        self.provider_metadata.as_ref()
    }

    fn validate(&self) -> Result<(), ContractError> {
        validate_optional_identifier(self.input_id())?;
        self.embedding.validate()
    }
}

/// One strongly typed document-reranking result.
#[derive(Clone, Debug, Deserialize, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RerankResult {
    document_index: u64,
    document_id: Option<String>,
    rank: u64,
    relevance_score: f64,
    document: Option<Value>,
    explanation: Option<String>,
    #[serde(
        default,
        deserialize_with = "deserialize_optional_non_null",
        skip_serializing_if = "Option::is_none"
    )]
    #[schemars(with = "JsonObject")]
    metadata: Option<JsonObject>,
    #[serde(
        default,
        deserialize_with = "deserialize_optional_non_null",
        skip_serializing_if = "Option::is_none"
    )]
    #[schemars(with = "JsonObject")]
    provider_metadata: Option<JsonObject>,
}

impl RerankResult {
    /// Creates a ranked document result.
    ///
    /// # Errors
    ///
    /// Returns [`ContractError::InvalidContent`] for rank zero or a non-finite score.
    pub fn new(
        document_index: u64,
        rank: u64,
        relevance_score: f64,
    ) -> Result<Self, ContractError> {
        let result = Self {
            document_index,
            document_id: None,
            rank,
            relevance_score,
            document: None,
            explanation: None,
            metadata: None,
            provider_metadata: None,
        };
        result.validate()?;
        Ok(result)
    }

    /// Adds the complete optional reranking context without coercing document JSON.
    ///
    /// # Errors
    ///
    /// Returns a value-free [`ContractError`] when a supplied document identifier is empty.
    pub fn with_details(
        mut self,
        document_id: Option<String>,
        document: Option<Value>,
        explanation: Option<String>,
        metadata: Option<JsonObject>,
        provider_metadata: Option<JsonObject>,
    ) -> Result<Self, ContractError> {
        validate_optional_identifier(document_id.as_deref())?;
        self.document_id = document_id;
        self.document = document;
        self.explanation = explanation;
        self.metadata = metadata;
        self.provider_metadata = provider_metadata;
        Ok(self)
    }

    /// Returns the original document index.
    #[must_use]
    pub const fn document_index(&self) -> u64 {
        self.document_index
    }

    /// Borrows the nullable document identifier.
    #[must_use]
    pub fn document_id(&self) -> Option<&str> {
        self.document_id.as_deref()
    }

    /// Returns the one-based provider rank.
    #[must_use]
    pub const fn rank(&self) -> u64 {
        self.rank
    }

    /// Returns the provider relevance score.
    #[must_use]
    pub const fn relevance_score(&self) -> f64 {
        self.relevance_score
    }

    /// Borrows arbitrary document JSON with full number precision.
    #[must_use]
    pub const fn document(&self) -> Option<&Value> {
        self.document.as_ref()
    }

    /// Borrows the nullable explanation.
    #[must_use]
    pub fn explanation(&self) -> Option<&str> {
        self.explanation.as_deref()
    }

    /// Borrows deterministic application metadata.
    #[must_use]
    pub const fn metadata(&self) -> Option<&JsonObject> {
        self.metadata.as_ref()
    }

    /// Borrows namespaced provider metadata.
    #[must_use]
    pub const fn provider_metadata(&self) -> Option<&JsonObject> {
        self.provider_metadata.as_ref()
    }

    fn validate(&self) -> Result<(), ContractError> {
        validate_optional_identifier(self.document_id())?;
        if self.rank == 0 || !self.relevance_score.is_finite() {
            Err(ContractError::InvalidContent)
        } else {
            Ok(())
        }
    }
}

/// One timed word in a transcript segment.
#[derive(Clone, Debug, Deserialize, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TranscriptWord {
    text: String,
    start_ms: u64,
    end_ms: u64,
    confidence: Option<f64>,
    speaker: Option<String>,
    channel: Option<u64>,
}

impl TranscriptWord {
    /// Creates a timed transcript word or phrase.
    ///
    /// # Errors
    ///
    /// Returns [`ContractError::InvalidContent`] when the timestamp interval is reversed.
    pub fn new(text: String, start_ms: u64, end_ms: u64) -> Result<Self, ContractError> {
        let word = Self {
            text,
            start_ms,
            end_ms,
            confidence: None,
            speaker: None,
            channel: None,
        };
        word.validate()?;
        Ok(word)
    }

    /// Adds nullable recognition details.
    ///
    /// # Errors
    ///
    /// Returns [`ContractError::InvalidContent`] for a non-finite confidence outside zero to
    /// one.
    pub fn with_details(
        mut self,
        confidence: Option<f64>,
        speaker: Option<String>,
        channel: Option<u64>,
    ) -> Result<Self, ContractError> {
        validate_optional_probability(confidence)?;
        self.confidence = confidence;
        self.speaker = speaker;
        self.channel = channel;
        Ok(self)
    }

    /// Borrows recognized text.
    #[must_use]
    pub fn text(&self) -> &str {
        &self.text
    }

    /// Returns the inclusive start timestamp in milliseconds.
    #[must_use]
    pub const fn start_ms(&self) -> u64 {
        self.start_ms
    }

    /// Returns the end timestamp in milliseconds.
    #[must_use]
    pub const fn end_ms(&self) -> u64 {
        self.end_ms
    }

    /// Returns nullable recognition confidence.
    #[must_use]
    pub const fn confidence(&self) -> Option<f64> {
        self.confidence
    }

    /// Borrows the nullable speaker label.
    #[must_use]
    pub fn speaker(&self) -> Option<&str> {
        self.speaker.as_deref()
    }

    /// Returns the nullable audio channel.
    #[must_use]
    pub const fn channel(&self) -> Option<u64> {
        self.channel
    }

    fn validate(&self) -> Result<(), ContractError> {
        validate_interval(self.start_ms, self.end_ms)?;
        validate_optional_probability(self.confidence)
    }
}

/// One indexed, timed transcription segment.
#[derive(Clone, Debug, Deserialize, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TranscriptSegment {
    index: u64,
    text: String,
    start_ms: u64,
    end_ms: u64,
    confidence: Option<f64>,
    speaker: Option<String>,
    channel: Option<u64>,
    #[serde(
        default,
        deserialize_with = "deserialize_optional_non_null",
        skip_serializing_if = "Option::is_none"
    )]
    #[schemars(with = "Vec<TranscriptWord>")]
    words: Option<Vec<TranscriptWord>>,
    #[serde(
        default,
        deserialize_with = "deserialize_optional_non_null",
        skip_serializing_if = "Option::is_none"
    )]
    #[schemars(with = "JsonObject")]
    provider_metadata: Option<JsonObject>,
}

impl TranscriptSegment {
    /// Creates an indexed transcript segment.
    ///
    /// # Errors
    ///
    /// Returns [`ContractError::InvalidContent`] when the timestamp interval is reversed.
    pub fn new(
        index: u64,
        text: String,
        start_ms: u64,
        end_ms: u64,
    ) -> Result<Self, ContractError> {
        let segment = Self {
            index,
            text,
            start_ms,
            end_ms,
            confidence: None,
            speaker: None,
            channel: None,
            words: None,
            provider_metadata: None,
        };
        segment.validate()?;
        Ok(segment)
    }

    /// Adds recognition details, aligned words, and provider metadata.
    ///
    /// # Errors
    ///
    /// Returns [`ContractError::InvalidContent`] for invalid confidence, word timestamps, or
    /// word order.
    pub fn with_details(
        mut self,
        confidence: Option<f64>,
        speaker: Option<String>,
        channel: Option<u64>,
        words: Option<Vec<TranscriptWord>>,
        provider_metadata: Option<JsonObject>,
    ) -> Result<Self, ContractError> {
        self.confidence = confidence;
        self.speaker = speaker;
        self.channel = channel;
        self.words = words;
        self.provider_metadata = provider_metadata;
        self.validate()?;
        Ok(self)
    }

    /// Returns the stable segment index.
    #[must_use]
    pub const fn index(&self) -> u64 {
        self.index
    }

    /// Borrows segment text.
    #[must_use]
    pub fn text(&self) -> &str {
        &self.text
    }

    /// Returns the segment start timestamp in milliseconds.
    #[must_use]
    pub const fn start_ms(&self) -> u64 {
        self.start_ms
    }

    /// Returns the segment end timestamp in milliseconds.
    #[must_use]
    pub const fn end_ms(&self) -> u64 {
        self.end_ms
    }

    /// Returns nullable recognition confidence.
    #[must_use]
    pub const fn confidence(&self) -> Option<f64> {
        self.confidence
    }

    /// Borrows the nullable speaker label.
    #[must_use]
    pub fn speaker(&self) -> Option<&str> {
        self.speaker.as_deref()
    }

    /// Returns the nullable audio channel.
    #[must_use]
    pub const fn channel(&self) -> Option<u64> {
        self.channel
    }

    /// Borrows optional timed words.
    #[must_use]
    pub fn words(&self) -> Option<&[TranscriptWord]> {
        self.words.as_deref()
    }

    /// Borrows namespaced provider metadata.
    #[must_use]
    pub const fn provider_metadata(&self) -> Option<&JsonObject> {
        self.provider_metadata.as_ref()
    }

    fn validate(&self) -> Result<(), ContractError> {
        validate_interval(self.start_ms, self.end_ms)?;
        validate_optional_probability(self.confidence)?;
        if let Some(words) = &self.words {
            validate_monotonic_times(words.iter().map(|word| (word.start_ms, word.end_ms)))?;
            for word in words {
                word.validate()?;
                if word.start_ms < self.start_ms || word.end_ms > self.end_ms {
                    return Err(ContractError::InvalidContent);
                }
            }
        }
        Ok(())
    }
}

/// A provider speech timing-mark kind.
#[derive(Clone, Copy, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SpeechTimingKind {
    /// One spoken word.
    Word,
    /// One sentence.
    Sentence,
    /// A visual mouth-shape cue.
    Viseme,
    /// A phonetic cue.
    Phoneme,
    /// A provider bookmark.
    Bookmark,
    /// A provider-defined timing mark.
    Provider,
}

/// One speech timing mark.
#[derive(Clone, Debug, Deserialize, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SpeechTimingMark {
    kind: SpeechTimingKind,
    value: String,
    start_ms: u64,
    end_ms: Option<u64>,
    #[serde(
        default,
        deserialize_with = "deserialize_optional_non_null",
        skip_serializing_if = "Option::is_none"
    )]
    #[schemars(with = "JsonObject")]
    provider_metadata: Option<JsonObject>,
}

impl SpeechTimingMark {
    /// Creates a speech timing mark.
    #[must_use]
    pub fn new(kind: SpeechTimingKind, value: String, start_ms: u64) -> Self {
        Self {
            kind,
            value,
            start_ms,
            end_ms: None,
            provider_metadata: None,
        }
    }

    /// Adds a nullable end timestamp and namespaced metadata.
    ///
    /// # Errors
    ///
    /// Returns [`ContractError::InvalidContent`] when the end precedes the start.
    pub fn with_details(
        mut self,
        end_ms: Option<u64>,
        provider_metadata: Option<JsonObject>,
    ) -> Result<Self, ContractError> {
        self.end_ms = end_ms;
        self.provider_metadata = provider_metadata;
        self.validate()?;
        Ok(self)
    }

    /// Returns the timing-mark kind.
    #[must_use]
    pub const fn kind(&self) -> SpeechTimingKind {
        self.kind
    }

    /// Borrows the provider value.
    #[must_use]
    pub fn value(&self) -> &str {
        &self.value
    }

    /// Returns the start timestamp in milliseconds.
    #[must_use]
    pub const fn start_ms(&self) -> u64 {
        self.start_ms
    }

    /// Returns the nullable end timestamp in milliseconds.
    #[must_use]
    pub const fn end_ms(&self) -> Option<u64> {
        self.end_ms
    }

    /// Borrows namespaced provider metadata.
    #[must_use]
    pub const fn provider_metadata(&self) -> Option<&JsonObject> {
        self.provider_metadata.as_ref()
    }

    fn validate(&self) -> Result<(), ContractError> {
        if self.end_ms.is_some_and(|end_ms| end_ms < self.start_ms) {
            Err(ContractError::InvalidContent)
        } else {
            Ok(())
        }
    }
}

/// The generated audio payload of a speech response.
#[derive(Clone, Debug, Deserialize, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SpeechAudio {
    mime_type: String,
    codec: Option<String>,
    source: BinarySource,
    voice: Option<String>,
    duration_ms: Option<u64>,
    sample_rate_hz: Option<u64>,
    channels: Option<u64>,
    transcript: Option<String>,
    subtitles: Option<String>,
    #[serde(
        default,
        deserialize_with = "deserialize_optional_non_null",
        skip_serializing_if = "Option::is_none"
    )]
    #[schemars(with = "Vec<SpeechTimingMark>")]
    timing_marks: Option<Vec<SpeechTimingMark>>,
    #[serde(
        default,
        deserialize_with = "deserialize_optional_non_null",
        skip_serializing_if = "Option::is_none"
    )]
    #[schemars(with = "JsonObject")]
    provider_metadata: Option<JsonObject>,
}

impl SpeechAudio {
    /// Creates generated speech with a validated binary source.
    ///
    /// # Errors
    ///
    /// Returns a value-free [`ContractError`] for an empty MIME type or invalid binary source.
    pub fn new(mime_type: String, source: BinarySource) -> Result<Self, ContractError> {
        let audio = Self {
            mime_type,
            codec: None,
            source,
            voice: None,
            duration_ms: None,
            sample_rate_hz: None,
            channels: None,
            transcript: None,
            subtitles: None,
            timing_marks: None,
            provider_metadata: None,
        };
        audio.validate()?;
        Ok(audio)
    }

    /// Adds nullable codec and voice identities.
    #[must_use]
    pub fn with_encoding(mut self, codec: Option<String>, voice: Option<String>) -> Self {
        self.codec = codec;
        self.voice = voice;
        self
    }

    /// Adds nullable duration, sample rate, and channel count.
    ///
    /// # Errors
    ///
    /// Returns [`ContractError::InvalidContent`] for zero sample rate or channels.
    pub fn with_audio_properties(
        mut self,
        duration_ms: Option<u64>,
        sample_rate_hz: Option<u64>,
        channels: Option<u64>,
    ) -> Result<Self, ContractError> {
        self.duration_ms = duration_ms;
        self.sample_rate_hz = sample_rate_hz;
        self.channels = channels;
        self.validate()?;
        Ok(self)
    }

    /// Adds nullable transcript and subtitle text.
    #[must_use]
    pub fn with_text(mut self, transcript: Option<String>, subtitles: Option<String>) -> Self {
        self.transcript = transcript;
        self.subtitles = subtitles;
        self
    }

    /// Adds ordered timing marks and namespaced provider metadata.
    ///
    /// # Errors
    ///
    /// Returns [`ContractError::InvalidContent`] for invalid or out-of-order timing marks.
    pub fn with_timing_marks(
        mut self,
        timing_marks: Option<Vec<SpeechTimingMark>>,
        provider_metadata: Option<JsonObject>,
    ) -> Result<Self, ContractError> {
        self.timing_marks = timing_marks;
        self.provider_metadata = provider_metadata;
        self.validate()?;
        Ok(self)
    }

    /// Borrows the MIME type.
    #[must_use]
    pub fn mime_type(&self) -> &str {
        &self.mime_type
    }

    /// Borrows the nullable codec.
    #[must_use]
    pub fn codec(&self) -> Option<&str> {
        self.codec.as_deref()
    }

    /// Borrows the generated binary source.
    #[must_use]
    pub const fn source(&self) -> &BinarySource {
        &self.source
    }

    /// Borrows the nullable voice identity.
    #[must_use]
    pub fn voice(&self) -> Option<&str> {
        self.voice.as_deref()
    }

    /// Returns nullable duration in milliseconds.
    #[must_use]
    pub const fn duration_ms(&self) -> Option<u64> {
        self.duration_ms
    }

    /// Returns nullable sample rate in hertz.
    #[must_use]
    pub const fn sample_rate_hz(&self) -> Option<u64> {
        self.sample_rate_hz
    }

    /// Returns nullable channel count.
    #[must_use]
    pub const fn channels(&self) -> Option<u64> {
        self.channels
    }

    /// Borrows nullable transcript text.
    #[must_use]
    pub fn transcript(&self) -> Option<&str> {
        self.transcript.as_deref()
    }

    /// Borrows nullable subtitle text.
    #[must_use]
    pub fn subtitles(&self) -> Option<&str> {
        self.subtitles.as_deref()
    }

    /// Borrows optional timing marks.
    #[must_use]
    pub fn timing_marks(&self) -> Option<&[SpeechTimingMark]> {
        self.timing_marks.as_deref()
    }

    /// Borrows namespaced provider metadata.
    #[must_use]
    pub const fn provider_metadata(&self) -> Option<&JsonObject> {
        self.provider_metadata.as_ref()
    }

    fn validate(&self) -> Result<(), ContractError> {
        self.validate_properties()?;
        validate_binary_source(&self.source)
    }

    fn validate_properties(&self) -> Result<(), ContractError> {
        validate_mime_type(&self.mime_type)?;
        if self.sample_rate_hz == Some(0) || self.channels == Some(0) {
            return Err(ContractError::InvalidContent);
        }
        if let Some(marks) = &self.timing_marks {
            let mut previous_start = None;
            for mark in marks {
                mark.validate()?;
                if previous_start.is_some_and(|start| mark.start_ms < start)
                    || self.duration_ms.is_some_and(|duration| {
                        mark.start_ms > duration || mark.end_ms.is_some_and(|end| end > duration)
                    })
                {
                    return Err(ContractError::InvalidContent);
                }
                previous_start = Some(mark.start_ms);
            }
        }
        Ok(())
    }
}

/// One normalized classification or safety label.
#[derive(Clone, Debug, Deserialize, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ClassificationLabel {
    label: String,
    score: f64,
    disposition: Option<String>,
    threshold: Option<f64>,
    explanation: Option<String>,
    #[serde(
        default,
        deserialize_with = "deserialize_optional_non_null",
        skip_serializing_if = "Option::is_none"
    )]
    #[schemars(with = "JsonObject")]
    metadata: Option<JsonObject>,
}

impl ClassificationLabel {
    /// Creates a classification label with a finite provider score.
    ///
    /// # Errors
    ///
    /// Returns a value-free [`ContractError`] for an empty label or non-finite score.
    pub fn new(label: String, score: f64) -> Result<Self, ContractError> {
        let classification = Self {
            label,
            score,
            disposition: None,
            threshold: None,
            explanation: None,
            metadata: None,
        };
        classification.validate()?;
        Ok(classification)
    }

    /// Adds nullable disposition, threshold, explanation, and deterministic metadata.
    ///
    /// # Errors
    ///
    /// Returns [`ContractError::InvalidContent`] for a non-finite threshold.
    pub fn with_details(
        mut self,
        disposition: Option<String>,
        threshold: Option<f64>,
        explanation: Option<String>,
        metadata: Option<JsonObject>,
    ) -> Result<Self, ContractError> {
        self.disposition = disposition;
        self.threshold = threshold;
        self.explanation = explanation;
        self.metadata = metadata;
        self.validate()?;
        Ok(self)
    }

    /// Borrows the stable label.
    #[must_use]
    pub fn label(&self) -> &str {
        &self.label
    }

    /// Returns the finite provider score.
    #[must_use]
    pub const fn score(&self) -> f64 {
        self.score
    }

    /// Borrows the nullable disposition.
    #[must_use]
    pub fn disposition(&self) -> Option<&str> {
        self.disposition.as_deref()
    }

    /// Returns the nullable decision threshold.
    #[must_use]
    pub const fn threshold(&self) -> Option<f64> {
        self.threshold
    }

    /// Borrows the nullable explanation.
    #[must_use]
    pub fn explanation(&self) -> Option<&str> {
        self.explanation.as_deref()
    }

    /// Borrows deterministic label metadata.
    #[must_use]
    pub const fn metadata(&self) -> Option<&JsonObject> {
        self.metadata.as_ref()
    }

    fn validate(&self) -> Result<(), ContractError> {
        validate_name(&self.label)?;
        validate_finite(self.score)?;
        self.threshold.map_or(Ok(()), validate_finite)
    }
}

/// A generated media asset kind.
#[derive(Clone, Copy, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum GeneratedAssetKind {
    /// An image asset.
    Image,
    /// An audio asset.
    Audio,
    /// A video asset.
    Video,
    /// A generic file asset.
    File,
    /// A provider or application resource.
    Resource,
}

/// A lossless integer or string generation seed.
#[derive(Clone, Debug, PartialEq)]
pub enum GenerationSeed {
    /// An arbitrary-precision JSON integer.
    Integer(Number),
    /// A provider-defined string seed.
    String(String),
}

impl Serialize for GenerationSeed {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match self {
            Self::Integer(value) => value.serialize(serializer),
            Self::String(value) => value.serialize(serializer),
        }
    }
}

impl<'de> Deserialize<'de> for GenerationSeed {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        match Value::deserialize(deserializer)? {
            Value::Number(value) if number_is_integer(&value) => Ok(Self::Integer(value)),
            Value::String(value) => Ok(Self::String(value)),
            _ => Err(D::Error::custom(ContractError::InvalidContent)),
        }
    }
}

impl JsonSchema for GenerationSeed {
    fn schema_name() -> std::borrow::Cow<'static, str> {
        "GenerationSeed".into()
    }

    fn schema_id() -> std::borrow::Cow<'static, str> {
        concat!(module_path!(), "::GenerationSeed").into()
    }

    fn json_schema(_generator: &mut SchemaGenerator) -> Schema {
        schemars::json_schema!({"type": ["integer", "string"]})
    }
}

/// One generated media asset with provenance and safety results.
#[derive(Clone, Debug, Deserialize, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct GeneratedAsset {
    asset_id: String,
    kind: GeneratedAssetKind,
    mime_type: String,
    source: BinarySource,
    filename: Option<String>,
    width: Option<u64>,
    height: Option<u64>,
    duration_ms: Option<u64>,
    sample_rate_hz: Option<u64>,
    channels: Option<u64>,
    seed: Option<GenerationSeed>,
    revised_prompt: Option<String>,
    sha256: Option<String>,
    #[serde(
        default,
        deserialize_with = "deserialize_optional_non_null",
        skip_serializing_if = "Option::is_none"
    )]
    #[schemars(with = "Vec<ClassificationLabel>")]
    safety: Option<Vec<ClassificationLabel>>,
    #[serde(
        default,
        deserialize_with = "deserialize_optional_non_null",
        skip_serializing_if = "Option::is_none"
    )]
    #[schemars(with = "JsonObject")]
    provenance: Option<JsonObject>,
    #[serde(
        default,
        deserialize_with = "deserialize_optional_non_null",
        skip_serializing_if = "Option::is_none"
    )]
    #[schemars(with = "JsonObject")]
    provider_metadata: Option<JsonObject>,
}

impl GeneratedAsset {
    /// Creates a generated asset with a validated source.
    ///
    /// # Errors
    ///
    /// Returns a value-free [`ContractError`] for invalid identity, MIME type, or binary source.
    pub fn new(
        asset_id: String,
        kind: GeneratedAssetKind,
        mime_type: String,
        source: BinarySource,
    ) -> Result<Self, ContractError> {
        let asset = Self {
            asset_id,
            kind,
            mime_type,
            source,
            filename: None,
            width: None,
            height: None,
            duration_ms: None,
            sample_rate_hz: None,
            channels: None,
            seed: None,
            revised_prompt: None,
            sha256: None,
            safety: None,
            provenance: None,
            provider_metadata: None,
        };
        asset.validate()?;
        Ok(asset)
    }

    /// Adds nullable filename and SHA-256 digest.
    ///
    /// # Errors
    ///
    /// Returns [`ContractError::InvalidContent`] unless a supplied digest is 64 lowercase
    /// hexadecimal characters.
    pub fn with_file_details(
        mut self,
        filename: Option<String>,
        sha256: Option<String>,
    ) -> Result<Self, ContractError> {
        self.filename = filename;
        self.sha256 = sha256;
        self.validate()?;
        Ok(self)
    }

    /// Adds nullable dimensional and audio properties.
    ///
    /// # Errors
    ///
    /// Returns [`ContractError::InvalidContent`] for zero width, height, sample rate, or
    /// channels.
    pub fn with_dimensions(
        mut self,
        width: Option<u64>,
        height: Option<u64>,
        duration_ms: Option<u64>,
        sample_rate_hz: Option<u64>,
        channels: Option<u64>,
    ) -> Result<Self, ContractError> {
        self.width = width;
        self.height = height;
        self.duration_ms = duration_ms;
        self.sample_rate_hz = sample_rate_hz;
        self.channels = channels;
        self.validate()?;
        Ok(self)
    }

    /// Adds generation details, safety labels, provenance, and provider metadata.
    ///
    /// # Errors
    ///
    /// Returns [`ContractError::InvalidContent`] when a safety label is invalid.
    pub fn with_generation_details(
        mut self,
        seed: Option<GenerationSeed>,
        revised_prompt: Option<String>,
        safety: Option<Vec<ClassificationLabel>>,
        provenance: Option<JsonObject>,
        provider_metadata: Option<JsonObject>,
    ) -> Result<Self, ContractError> {
        self.seed = seed;
        self.revised_prompt = revised_prompt;
        self.safety = safety;
        self.provenance = provenance;
        self.provider_metadata = provider_metadata;
        self.validate()?;
        Ok(self)
    }

    /// Borrows the stable asset identifier.
    #[must_use]
    pub fn asset_id(&self) -> &str {
        &self.asset_id
    }

    /// Returns the generated asset kind.
    #[must_use]
    pub const fn kind(&self) -> GeneratedAssetKind {
        self.kind
    }

    /// Borrows the MIME type.
    #[must_use]
    pub fn mime_type(&self) -> &str {
        &self.mime_type
    }

    /// Borrows the binary source.
    #[must_use]
    pub const fn source(&self) -> &BinarySource {
        &self.source
    }

    /// Borrows the nullable filename.
    #[must_use]
    pub fn filename(&self) -> Option<&str> {
        self.filename.as_deref()
    }

    /// Returns nullable width in pixels.
    #[must_use]
    pub const fn width(&self) -> Option<u64> {
        self.width
    }

    /// Returns nullable height in pixels.
    #[must_use]
    pub const fn height(&self) -> Option<u64> {
        self.height
    }

    /// Returns nullable duration in milliseconds.
    #[must_use]
    pub const fn duration_ms(&self) -> Option<u64> {
        self.duration_ms
    }

    /// Returns nullable sample rate in hertz.
    #[must_use]
    pub const fn sample_rate_hz(&self) -> Option<u64> {
        self.sample_rate_hz
    }

    /// Returns nullable channel count.
    #[must_use]
    pub const fn channels(&self) -> Option<u64> {
        self.channels
    }

    /// Borrows the lossless nullable seed.
    #[must_use]
    pub const fn seed(&self) -> Option<&GenerationSeed> {
        self.seed.as_ref()
    }

    /// Borrows the nullable revised prompt.
    #[must_use]
    pub fn revised_prompt(&self) -> Option<&str> {
        self.revised_prompt.as_deref()
    }

    /// Borrows the nullable lowercase SHA-256 digest.
    #[must_use]
    pub fn sha256(&self) -> Option<&str> {
        self.sha256.as_deref()
    }

    /// Borrows optional safety labels.
    #[must_use]
    pub fn safety(&self) -> Option<&[ClassificationLabel]> {
        self.safety.as_deref()
    }

    /// Borrows deterministic provenance.
    #[must_use]
    pub const fn provenance(&self) -> Option<&JsonObject> {
        self.provenance.as_ref()
    }

    /// Borrows namespaced provider metadata.
    #[must_use]
    pub const fn provider_metadata(&self) -> Option<&JsonObject> {
        self.provider_metadata.as_ref()
    }

    fn validate(&self) -> Result<(), ContractError> {
        self.validate_properties()?;
        validate_binary_source(&self.source)
    }

    fn validate_properties(&self) -> Result<(), ContractError> {
        validate_identifier(&self.asset_id)?;
        validate_mime_type(&self.mime_type)?;
        if self.width == Some(0)
            || self.height == Some(0)
            || self.sample_rate_hz == Some(0)
            || self.channels == Some(0)
            || self.sha256.as_deref().is_some_and(|digest| {
                digest.len() != 64
                    || !digest
                        .as_bytes()
                        .iter()
                        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(byte))
            })
        {
            return Err(ContractError::InvalidContent);
        }
        if let Some(labels) = &self.safety {
            labels.iter().try_for_each(ClassificationLabel::validate)?;
        }
        Ok(())
    }
}

/// One classified input and its labels.
#[derive(Clone, Debug, Deserialize, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ClassificationResult {
    input_index: u64,
    input_id: Option<String>,
    labels: Vec<ClassificationLabel>,
    overall_disposition: Option<String>,
    #[serde(
        default,
        deserialize_with = "deserialize_optional_non_null",
        skip_serializing_if = "Option::is_none"
    )]
    #[schemars(with = "JsonObject")]
    provider_metadata: Option<JsonObject>,
}

impl ClassificationResult {
    /// Creates one indexed classification result.
    ///
    /// # Errors
    ///
    /// Returns [`ContractError::InvalidContent`] for invalid or duplicate labels.
    pub fn new(input_index: u64, labels: Vec<ClassificationLabel>) -> Result<Self, ContractError> {
        let result = Self {
            input_index,
            input_id: None,
            labels,
            overall_disposition: None,
            provider_metadata: None,
        };
        result.validate()?;
        Ok(result)
    }

    /// Adds nullable input identity, disposition, and provider metadata.
    ///
    /// # Errors
    ///
    /// Returns a value-free [`ContractError`] when a supplied input identifier is empty.
    pub fn with_details(
        mut self,
        input_id: Option<String>,
        overall_disposition: Option<String>,
        provider_metadata: Option<JsonObject>,
    ) -> Result<Self, ContractError> {
        validate_optional_identifier(input_id.as_deref())?;
        self.input_id = input_id;
        self.overall_disposition = overall_disposition;
        self.provider_metadata = provider_metadata;
        Ok(self)
    }

    /// Returns the stable input index.
    #[must_use]
    pub const fn input_index(&self) -> u64 {
        self.input_index
    }

    /// Borrows the nullable input identifier.
    #[must_use]
    pub fn input_id(&self) -> Option<&str> {
        self.input_id.as_deref()
    }

    /// Borrows ordered classification labels.
    #[must_use]
    pub fn labels(&self) -> &[ClassificationLabel] {
        &self.labels
    }

    /// Borrows the nullable overall disposition.
    #[must_use]
    pub fn overall_disposition(&self) -> Option<&str> {
        self.overall_disposition.as_deref()
    }

    /// Borrows namespaced provider metadata.
    #[must_use]
    pub const fn provider_metadata(&self) -> Option<&JsonObject> {
        self.provider_metadata.as_ref()
    }

    fn validate(&self) -> Result<(), ContractError> {
        validate_optional_identifier(self.input_id())?;
        let mut labels = BTreeSet::new();
        for label in &self.labels {
            label.validate()?;
            if !labels.insert(label.label()) {
                return Err(ContractError::InvalidContent);
            }
        }
        Ok(())
    }
}

macro_rules! common_response_methods {
    () => {
        /// Adds nullable provider-native response and request identifiers.
        ///
        /// # Errors
        ///
        /// Returns a value-free [`ContractError`] when a supplied identifier is empty.
        pub fn with_provider_ids(
            mut self,
            provider_response_id: Option<String>,
            provider_request_id: Option<String>,
        ) -> Result<Self, ContractError> {
            validate_optional_identifier(provider_response_id.as_deref())?;
            validate_optional_identifier(provider_request_id.as_deref())?;
            self.provider_response_id = provider_response_id;
            self.provider_request_id = provider_request_id;
            Ok(self)
        }

        /// Adds ordered warnings and namespaced provider metadata.
        #[must_use]
        pub fn with_metadata(
            mut self,
            warnings: Option<Vec<String>>,
            provider_metadata: Option<JsonObject>,
        ) -> Self {
            self.warnings = warnings;
            self.provider_metadata = provider_metadata;
            self
        }

        /// Returns the fixed schema version.
        #[must_use]
        pub const fn schema_version(&self) -> SchemaVersion {
            self.schema_version
        }

        /// Returns the specialized operation discriminator.
        #[must_use]
        pub const fn operation(&self) -> ModelOperation {
            self.operation
        }

        /// Borrows the original request identifier.
        #[must_use]
        pub const fn request_id(&self) -> &LlmRequestId {
            &self.request_id
        }

        /// Borrows the canonical response identifier.
        #[must_use]
        pub fn response_id(&self) -> &str {
            &self.response_id
        }

        /// Borrows the nullable provider response identifier.
        #[must_use]
        pub fn provider_response_id(&self) -> Option<&str> {
            self.provider_response_id.as_deref()
        }

        /// Borrows the nullable provider request identifier.
        #[must_use]
        pub fn provider_request_id(&self) -> Option<&str> {
            self.provider_request_id.as_deref()
        }

        /// Borrows the provider identity.
        #[must_use]
        pub fn provider(&self) -> &str {
            &self.provider
        }

        /// Borrows the provider model identity.
        #[must_use]
        pub fn model(&self) -> &str {
            &self.model
        }

        /// Returns the operation status.
        #[must_use]
        pub const fn status(&self) -> CompletionStatus {
            self.status
        }

        /// Borrows specialized usage counters.
        #[must_use]
        pub const fn usage(&self) -> &ModelUsage {
            &self.usage
        }

        /// Borrows optional ordered warnings.
        #[must_use]
        pub fn warnings(&self) -> Option<&[String]> {
            self.warnings.as_deref()
        }

        /// Borrows namespaced provider metadata.
        #[must_use]
        pub const fn provider_metadata(&self) -> Option<&JsonObject> {
            self.provider_metadata.as_ref()
        }

        /// Returns the normalized UTC creation instant.
        #[must_use]
        pub const fn created_at(&self) -> UtcTimestamp {
            self.created_at
        }

        /// Checks all invariants against the default serialization limits.
        ///
        /// # Errors
        ///
        /// Returns a value-free [`ContractError`] for the first invalid invariant or limit.
        pub fn validate(&self) -> Result<(), ContractError> {
            self.validate_with_limits(&ContentLimits::default())
        }

        /// Checks all invariants against explicit serialization limits.
        ///
        /// # Errors
        ///
        /// Returns a value-free [`ContractError`] for the first invalid invariant or limit.
        pub fn validate_with_limits(&self, limits: &ContentLimits) -> Result<(), ContractError> {
            self.validate_invariants()?;
            <Self as ValidateSpecializedBounds>::validate_bounds(self, limits)
        }
    };
}

/// A complete canonical embeddings response.
#[derive(Clone, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EmbeddingResponse {
    schema_version: SchemaVersion,
    #[schemars(schema_with = "embeddings_operation_schema")]
    operation: ModelOperation,
    request_id: LlmRequestId,
    response_id: String,
    provider_response_id: Option<String>,
    provider_request_id: Option<String>,
    provider: String,
    model: String,
    status: CompletionStatus,
    #[serde(
        default,
        deserialize_with = "deserialize_optional_non_null",
        skip_serializing_if = "Option::is_none"
    )]
    #[schemars(with = "Vec<String>")]
    warnings: Option<Vec<String>>,
    usage: ModelUsage,
    #[serde(
        default,
        deserialize_with = "deserialize_optional_non_null",
        skip_serializing_if = "Option::is_none"
    )]
    #[schemars(with = "JsonObject")]
    provider_metadata: Option<JsonObject>,
    created_at: UtcTimestamp,
    items: Vec<EmbeddingItem>,
}

impl EmbeddingResponse {
    /// Creates a complete embeddings response.
    ///
    /// # Errors
    ///
    /// Returns a value-free [`ContractError`] for invalid common fields, duplicate indices, or
    /// invalid embedding content.
    #[expect(
        clippy::too_many_arguments,
        reason = "the fixed response retains every independent envelope field"
    )]
    pub fn new(
        request_id: impl Into<LlmRequestId>,
        response_id: String,
        provider: String,
        model: String,
        status: CompletionStatus,
        usage: ModelUsage,
        created_at: OffsetDateTime,
        items: Vec<EmbeddingItem>,
    ) -> Result<Self, ContractError> {
        let response = Self {
            schema_version: SchemaVersion::CURRENT,
            operation: ModelOperation::Embeddings,
            request_id: request_id.into(),
            response_id,
            provider_response_id: None,
            provider_request_id: None,
            provider,
            model,
            status,
            warnings: None,
            usage,
            provider_metadata: None,
            created_at: UtcTimestamp::new(created_at),
            items,
        };
        response.validate()?;
        Ok(response)
    }

    common_response_methods!();

    /// Borrows indexed embedding results.
    #[must_use]
    pub fn items(&self) -> &[EmbeddingItem] {
        &self.items
    }

    /// Checks every embeddings response invariant.
    ///
    /// # Errors
    ///
    /// Returns a value-free [`ContractError`] for the first invalid invariant.
    fn validate_invariants(&self) -> Result<(), ContractError> {
        validate_common_response(
            self.operation,
            ModelOperation::Embeddings,
            &self.response_id,
            self.provider_response_id(),
            self.provider_request_id(),
            &self.provider,
            &self.model,
        )?;
        let mut indices = BTreeSet::new();
        for item in &self.items {
            item.validate()?;
            if !indices.insert(item.index) {
                return Err(ContractError::InvalidContent);
            }
        }
        Ok(())
    }
}

/// A complete canonical reranking response.
#[derive(Clone, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RerankResponse {
    schema_version: SchemaVersion,
    #[schemars(schema_with = "rerank_operation_schema")]
    operation: ModelOperation,
    request_id: LlmRequestId,
    response_id: String,
    provider_response_id: Option<String>,
    provider_request_id: Option<String>,
    provider: String,
    model: String,
    status: CompletionStatus,
    #[serde(
        default,
        deserialize_with = "deserialize_optional_non_null",
        skip_serializing_if = "Option::is_none"
    )]
    #[schemars(with = "Vec<String>")]
    warnings: Option<Vec<String>>,
    usage: ModelUsage,
    #[serde(
        default,
        deserialize_with = "deserialize_optional_non_null",
        skip_serializing_if = "Option::is_none"
    )]
    #[schemars(with = "JsonObject")]
    provider_metadata: Option<JsonObject>,
    created_at: UtcTimestamp,
    results: Vec<RerankResult>,
}

impl RerankResponse {
    /// Creates a complete reranking response.
    ///
    /// # Errors
    ///
    /// Returns a value-free [`ContractError`] for invalid common fields or duplicate document
    /// indices or ranks.
    #[expect(
        clippy::too_many_arguments,
        reason = "the fixed response retains every independent envelope field"
    )]
    pub fn new(
        request_id: impl Into<LlmRequestId>,
        response_id: String,
        provider: String,
        model: String,
        status: CompletionStatus,
        usage: ModelUsage,
        created_at: OffsetDateTime,
        results: Vec<RerankResult>,
    ) -> Result<Self, ContractError> {
        let response = Self {
            schema_version: SchemaVersion::CURRENT,
            operation: ModelOperation::Rerank,
            request_id: request_id.into(),
            response_id,
            provider_response_id: None,
            provider_request_id: None,
            provider,
            model,
            status,
            warnings: None,
            usage,
            provider_metadata: None,
            created_at: UtcTimestamp::new(created_at),
            results,
        };
        response.validate()?;
        Ok(response)
    }

    common_response_methods!();

    /// Borrows ranked document results.
    #[must_use]
    pub fn results(&self) -> &[RerankResult] {
        &self.results
    }

    /// Checks every reranking response invariant.
    ///
    /// # Errors
    ///
    /// Returns a value-free [`ContractError`] for the first invalid invariant.
    fn validate_invariants(&self) -> Result<(), ContractError> {
        validate_common_response(
            self.operation,
            ModelOperation::Rerank,
            &self.response_id,
            self.provider_response_id(),
            self.provider_request_id(),
            &self.provider,
            &self.model,
        )?;
        let mut document_indices = BTreeSet::new();
        let mut ranks = BTreeSet::new();
        for result in &self.results {
            result.validate()?;
            if !document_indices.insert(result.document_index) || !ranks.insert(result.rank) {
                return Err(ContractError::InvalidContent);
            }
        }
        Ok(())
    }
}

/// A complete canonical transcription response.
#[derive(Clone, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TranscriptionResponse {
    schema_version: SchemaVersion,
    #[schemars(schema_with = "transcription_operation_schema")]
    operation: ModelOperation,
    request_id: LlmRequestId,
    response_id: String,
    provider_response_id: Option<String>,
    provider_request_id: Option<String>,
    provider: String,
    model: String,
    status: CompletionStatus,
    #[serde(
        default,
        deserialize_with = "deserialize_optional_non_null",
        skip_serializing_if = "Option::is_none"
    )]
    #[schemars(with = "Vec<String>")]
    warnings: Option<Vec<String>>,
    usage: ModelUsage,
    #[serde(
        default,
        deserialize_with = "deserialize_optional_non_null",
        skip_serializing_if = "Option::is_none"
    )]
    #[schemars(with = "JsonObject")]
    provider_metadata: Option<JsonObject>,
    created_at: UtcTimestamp,
    text: String,
    language: Option<String>,
    duration_ms: Option<u64>,
    segments: Vec<TranscriptSegment>,
}

impl TranscriptionResponse {
    /// Creates a complete transcription response.
    ///
    /// # Errors
    ///
    /// Returns a value-free [`ContractError`] for invalid common fields, duplicate segment
    /// indices, or invalid segment timestamps.
    #[expect(
        clippy::too_many_arguments,
        reason = "the fixed response retains every independent envelope field"
    )]
    pub fn new(
        request_id: impl Into<LlmRequestId>,
        response_id: String,
        provider: String,
        model: String,
        status: CompletionStatus,
        usage: ModelUsage,
        created_at: OffsetDateTime,
        text: String,
        segments: Vec<TranscriptSegment>,
    ) -> Result<Self, ContractError> {
        let response = Self {
            schema_version: SchemaVersion::CURRENT,
            operation: ModelOperation::Transcription,
            request_id: request_id.into(),
            response_id,
            provider_response_id: None,
            provider_request_id: None,
            provider,
            model,
            status,
            warnings: None,
            usage,
            provider_metadata: None,
            created_at: UtcTimestamp::new(created_at),
            text,
            language: None,
            duration_ms: None,
            segments,
        };
        response.validate()?;
        Ok(response)
    }

    common_response_methods!();

    /// Adds nullable language and duration.
    ///
    /// # Errors
    ///
    /// Returns [`ContractError::InvalidContent`] when a segment exceeds the duration.
    pub fn with_transcript_details(
        mut self,
        language: Option<String>,
        duration_ms: Option<u64>,
    ) -> Result<Self, ContractError> {
        self.language = language;
        self.duration_ms = duration_ms;
        self.validate()?;
        Ok(self)
    }

    /// Borrows the complete transcript text.
    #[must_use]
    pub fn text(&self) -> &str {
        &self.text
    }

    /// Borrows the nullable language tag.
    #[must_use]
    pub fn language(&self) -> Option<&str> {
        self.language.as_deref()
    }

    /// Returns nullable audio duration in milliseconds.
    #[must_use]
    pub const fn duration_ms(&self) -> Option<u64> {
        self.duration_ms
    }

    /// Borrows timed transcript segments.
    #[must_use]
    pub fn segments(&self) -> &[TranscriptSegment] {
        &self.segments
    }

    /// Checks every transcription response invariant.
    ///
    /// # Errors
    ///
    /// Returns a value-free [`ContractError`] for the first invalid invariant.
    fn validate_invariants(&self) -> Result<(), ContractError> {
        validate_common_response(
            self.operation,
            ModelOperation::Transcription,
            &self.response_id,
            self.provider_response_id(),
            self.provider_request_id(),
            &self.provider,
            &self.model,
        )?;
        let mut indices = BTreeSet::new();
        let mut previous_start = None;
        for segment in &self.segments {
            segment.validate()?;
            if !indices.insert(segment.index)
                || previous_start.is_some_and(|start| segment.start_ms < start)
                || self
                    .duration_ms
                    .is_some_and(|duration| segment.end_ms > duration)
            {
                return Err(ContractError::InvalidContent);
            }
            previous_start = Some(segment.start_ms);
        }
        Ok(())
    }
}

/// A complete canonical speech response.
#[derive(Clone, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SpeechResponse {
    schema_version: SchemaVersion,
    #[schemars(schema_with = "speech_operation_schema")]
    operation: ModelOperation,
    request_id: LlmRequestId,
    response_id: String,
    provider_response_id: Option<String>,
    provider_request_id: Option<String>,
    provider: String,
    model: String,
    status: CompletionStatus,
    #[serde(
        default,
        deserialize_with = "deserialize_optional_non_null",
        skip_serializing_if = "Option::is_none"
    )]
    #[schemars(with = "Vec<String>")]
    warnings: Option<Vec<String>>,
    usage: ModelUsage,
    #[serde(
        default,
        deserialize_with = "deserialize_optional_non_null",
        skip_serializing_if = "Option::is_none"
    )]
    #[schemars(with = "JsonObject")]
    provider_metadata: Option<JsonObject>,
    created_at: UtcTimestamp,
    audio: SpeechAudio,
}

impl SpeechResponse {
    /// Creates a complete speech response.
    ///
    /// # Errors
    ///
    /// Returns a value-free [`ContractError`] for invalid common or audio fields.
    #[expect(
        clippy::too_many_arguments,
        reason = "the fixed response retains every independent envelope field"
    )]
    pub fn new(
        request_id: impl Into<LlmRequestId>,
        response_id: String,
        provider: String,
        model: String,
        status: CompletionStatus,
        usage: ModelUsage,
        created_at: OffsetDateTime,
        audio: SpeechAudio,
    ) -> Result<Self, ContractError> {
        let response = Self {
            schema_version: SchemaVersion::CURRENT,
            operation: ModelOperation::Speech,
            request_id: request_id.into(),
            response_id,
            provider_response_id: None,
            provider_request_id: None,
            provider,
            model,
            status,
            warnings: None,
            usage,
            provider_metadata: None,
            created_at: UtcTimestamp::new(created_at),
            audio,
        };
        response.validate()?;
        Ok(response)
    }

    common_response_methods!();

    /// Borrows generated speech audio.
    #[must_use]
    pub const fn audio(&self) -> &SpeechAudio {
        &self.audio
    }

    /// Checks every speech response invariant.
    ///
    /// # Errors
    ///
    /// Returns a value-free [`ContractError`] for the first invalid invariant.
    fn validate_invariants(&self) -> Result<(), ContractError> {
        validate_common_response(
            self.operation,
            ModelOperation::Speech,
            &self.response_id,
            self.provider_response_id(),
            self.provider_request_id(),
            &self.provider,
            &self.model,
        )?;
        self.audio.validate_properties()
    }
}

/// A complete canonical media-generation response.
#[derive(Clone, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct MediaGenerationResponse {
    schema_version: SchemaVersion,
    #[schemars(schema_with = "media_generation_operation_schema")]
    operation: ModelOperation,
    request_id: LlmRequestId,
    response_id: String,
    provider_response_id: Option<String>,
    provider_request_id: Option<String>,
    provider: String,
    model: String,
    status: CompletionStatus,
    #[serde(
        default,
        deserialize_with = "deserialize_optional_non_null",
        skip_serializing_if = "Option::is_none"
    )]
    #[schemars(with = "Vec<String>")]
    warnings: Option<Vec<String>>,
    usage: ModelUsage,
    #[serde(
        default,
        deserialize_with = "deserialize_optional_non_null",
        skip_serializing_if = "Option::is_none"
    )]
    #[schemars(with = "JsonObject")]
    provider_metadata: Option<JsonObject>,
    created_at: UtcTimestamp,
    generation_id: Option<String>,
    assets: Vec<GeneratedAsset>,
    #[serde(
        default,
        deserialize_with = "deserialize_optional_non_null",
        skip_serializing_if = "Option::is_none"
    )]
    #[schemars(with = "JsonObject")]
    parameters: Option<JsonObject>,
    #[serde(
        default,
        deserialize_with = "deserialize_optional_non_null",
        skip_serializing_if = "Option::is_none"
    )]
    #[schemars(with = "Vec<JsonObject>")]
    provider_execution: Option<Vec<JsonObject>>,
    #[serde(
        default,
        deserialize_with = "deserialize_optional_non_null",
        skip_serializing_if = "Option::is_none"
    )]
    #[schemars(with = "Vec<ClassificationLabel>")]
    overall_safety: Option<Vec<ClassificationLabel>>,
}

impl MediaGenerationResponse {
    /// Creates a complete media-generation response with at least one asset.
    ///
    /// # Errors
    ///
    /// Returns a value-free [`ContractError`] for invalid common fields, empty assets,
    /// duplicate asset identifiers, or invalid asset content.
    #[expect(
        clippy::too_many_arguments,
        reason = "the fixed response retains every independent envelope field"
    )]
    pub fn new(
        request_id: impl Into<LlmRequestId>,
        response_id: String,
        provider: String,
        model: String,
        status: CompletionStatus,
        usage: ModelUsage,
        created_at: OffsetDateTime,
        assets: Vec<GeneratedAsset>,
    ) -> Result<Self, ContractError> {
        let response = Self {
            schema_version: SchemaVersion::CURRENT,
            operation: ModelOperation::MediaGeneration,
            request_id: request_id.into(),
            response_id,
            provider_response_id: None,
            provider_request_id: None,
            provider,
            model,
            status,
            warnings: None,
            usage,
            provider_metadata: None,
            created_at: UtcTimestamp::new(created_at),
            generation_id: None,
            assets,
            parameters: None,
            provider_execution: None,
            overall_safety: None,
        };
        response.validate()?;
        Ok(response)
    }

    common_response_methods!();

    /// Adds generation identity, parameters, provider execution records, and overall safety.
    ///
    /// # Errors
    ///
    /// Returns a value-free [`ContractError`] for an empty generation identifier or invalid
    /// safety label.
    pub fn with_generation_details(
        mut self,
        generation_id: Option<String>,
        parameters: Option<JsonObject>,
        provider_execution: Option<Vec<JsonObject>>,
        overall_safety: Option<Vec<ClassificationLabel>>,
    ) -> Result<Self, ContractError> {
        validate_optional_identifier(generation_id.as_deref())?;
        self.generation_id = generation_id;
        self.parameters = parameters;
        self.provider_execution = provider_execution;
        self.overall_safety = overall_safety;
        self.validate()?;
        Ok(self)
    }

    /// Borrows the nullable generation identifier.
    #[must_use]
    pub fn generation_id(&self) -> Option<&str> {
        self.generation_id.as_deref()
    }

    /// Borrows generated assets.
    #[must_use]
    pub fn assets(&self) -> &[GeneratedAsset] {
        &self.assets
    }

    /// Borrows deterministic generation parameters.
    #[must_use]
    pub const fn parameters(&self) -> Option<&JsonObject> {
        self.parameters.as_ref()
    }

    /// Borrows ordered provider execution records.
    #[must_use]
    pub fn provider_execution(&self) -> Option<&[JsonObject]> {
        self.provider_execution.as_deref()
    }

    /// Borrows optional overall safety labels.
    #[must_use]
    pub fn overall_safety(&self) -> Option<&[ClassificationLabel]> {
        self.overall_safety.as_deref()
    }

    /// Checks every media-generation response invariant.
    ///
    /// # Errors
    ///
    /// Returns a value-free [`ContractError`] for the first invalid invariant.
    fn validate_invariants(&self) -> Result<(), ContractError> {
        validate_common_response(
            self.operation,
            ModelOperation::MediaGeneration,
            &self.response_id,
            self.provider_response_id(),
            self.provider_request_id(),
            &self.provider,
            &self.model,
        )?;
        validate_optional_identifier(self.generation_id())?;
        if self.assets.is_empty() {
            return Err(ContractError::InvalidContent);
        }
        let mut asset_ids = BTreeSet::new();
        for asset in &self.assets {
            asset.validate_properties()?;
            if !asset_ids.insert(asset.asset_id()) {
                return Err(ContractError::InvalidContent);
            }
        }
        if let Some(labels) = &self.overall_safety {
            labels.iter().try_for_each(ClassificationLabel::validate)?;
        }
        Ok(())
    }
}

/// A complete canonical classification response.
#[derive(Clone, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ClassificationResponse {
    schema_version: SchemaVersion,
    #[schemars(schema_with = "classification_operation_schema")]
    operation: ModelOperation,
    request_id: LlmRequestId,
    response_id: String,
    provider_response_id: Option<String>,
    provider_request_id: Option<String>,
    provider: String,
    model: String,
    status: CompletionStatus,
    #[serde(
        default,
        deserialize_with = "deserialize_optional_non_null",
        skip_serializing_if = "Option::is_none"
    )]
    #[schemars(with = "Vec<String>")]
    warnings: Option<Vec<String>>,
    usage: ModelUsage,
    #[serde(
        default,
        deserialize_with = "deserialize_optional_non_null",
        skip_serializing_if = "Option::is_none"
    )]
    #[schemars(with = "JsonObject")]
    provider_metadata: Option<JsonObject>,
    created_at: UtcTimestamp,
    policy_id: Option<String>,
    results: Vec<ClassificationResult>,
}

impl ClassificationResponse {
    /// Creates a complete classification response.
    ///
    /// # Errors
    ///
    /// Returns a value-free [`ContractError`] for invalid common fields, duplicate input
    /// indices, or invalid labels.
    #[expect(
        clippy::too_many_arguments,
        reason = "the fixed response retains every independent envelope field"
    )]
    pub fn new(
        request_id: impl Into<LlmRequestId>,
        response_id: String,
        provider: String,
        model: String,
        status: CompletionStatus,
        usage: ModelUsage,
        created_at: OffsetDateTime,
        results: Vec<ClassificationResult>,
    ) -> Result<Self, ContractError> {
        let response = Self {
            schema_version: SchemaVersion::CURRENT,
            operation: ModelOperation::Classification,
            request_id: request_id.into(),
            response_id,
            provider_response_id: None,
            provider_request_id: None,
            provider,
            model,
            status,
            warnings: None,
            usage,
            provider_metadata: None,
            created_at: UtcTimestamp::new(created_at),
            policy_id: None,
            results,
        };
        response.validate()?;
        Ok(response)
    }

    common_response_methods!();

    /// Adds the nullable classification policy identity.
    ///
    /// # Errors
    ///
    /// Returns a value-free [`ContractError`] when a supplied policy identifier is empty.
    pub fn with_policy_id(mut self, policy_id: Option<String>) -> Result<Self, ContractError> {
        validate_optional_identifier(policy_id.as_deref())?;
        self.policy_id = policy_id;
        Ok(self)
    }

    /// Borrows the nullable policy identifier.
    #[must_use]
    pub fn policy_id(&self) -> Option<&str> {
        self.policy_id.as_deref()
    }

    /// Borrows classified input results.
    #[must_use]
    pub fn results(&self) -> &[ClassificationResult] {
        &self.results
    }

    /// Checks every classification response invariant.
    ///
    /// # Errors
    ///
    /// Returns a value-free [`ContractError`] for the first invalid invariant.
    fn validate_invariants(&self) -> Result<(), ContractError> {
        validate_common_response(
            self.operation,
            ModelOperation::Classification,
            &self.response_id,
            self.provider_response_id(),
            self.provider_request_id(),
            &self.provider,
            &self.model,
        )?;
        validate_optional_identifier(self.policy_id())?;
        let mut indices = BTreeSet::new();
        for result in &self.results {
            result.validate()?;
            if !indices.insert(result.input_index) {
                return Err(ContractError::InvalidContent);
            }
        }
        Ok(())
    }
}

macro_rules! response_wire {
    ($name:ident { $($extra:tt)* }) => {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct $name {
            schema_version: SchemaVersion,
            operation: ModelOperation,
            request_id: LlmRequestId,
            response_id: String,
            provider_response_id: Option<String>,
            provider_request_id: Option<String>,
            provider: String,
            model: String,
            status: CompletionStatus,
            #[serde(default, deserialize_with = "deserialize_optional_non_null")]
            warnings: Option<Vec<String>>,
            usage: ModelUsage,
            #[serde(default, deserialize_with = "deserialize_optional_non_null")]
            provider_metadata: Option<JsonObject>,
            created_at: UtcTimestamp,
            $($extra)*
        }
    };
}

response_wire!(EmbeddingResponseWire {
    items: Vec<EmbeddingItem>,
});
response_wire!(RerankResponseWire {
    results: Vec<RerankResult>,
});
response_wire!(TranscriptionResponseWire {
    text: String,
    language: Option<String>,
    duration_ms: Option<u64>,
    segments: Vec<TranscriptSegment>,
});
response_wire!(SpeechResponseWire { audio: SpeechAudio });
response_wire!(MediaGenerationResponseWire {
    generation_id: Option<String>,
    assets: Vec<GeneratedAsset>,
    #[serde(default, deserialize_with = "deserialize_optional_non_null")]
    parameters: Option<JsonObject>,
    #[serde(default, deserialize_with = "deserialize_optional_non_null")]
    provider_execution: Option<Vec<JsonObject>>,
    #[serde(default, deserialize_with = "deserialize_optional_non_null")]
    overall_safety: Option<Vec<ClassificationLabel>>,
});
response_wire!(ClassificationResponseWire {
    policy_id: Option<String>,
    results: Vec<ClassificationResult>,
});

macro_rules! validated_response_deserialize {
    ($response:ident, $wire:ident { $($extra:ident),* $(,)? }) => {
        impl<'de> Deserialize<'de> for $response {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: Deserializer<'de>,
            {
                let wire = $wire::deserialize(deserializer)?;
                let response = Self {
                    schema_version: wire.schema_version,
                    operation: wire.operation,
                    request_id: wire.request_id,
                    response_id: wire.response_id,
                    provider_response_id: wire.provider_response_id,
                    provider_request_id: wire.provider_request_id,
                    provider: wire.provider,
                    model: wire.model,
                    status: wire.status,
                    warnings: wire.warnings,
                    usage: wire.usage,
                    provider_metadata: wire.provider_metadata,
                    created_at: wire.created_at,
                    $($extra: wire.$extra),*
                };
                response.validate().map_err(D::Error::custom)?;
                Ok(response)
            }
        }
    };
}

validated_response_deserialize!(EmbeddingResponse, EmbeddingResponseWire { items });
validated_response_deserialize!(RerankResponse, RerankResponseWire { results });
validated_response_deserialize!(
    TranscriptionResponse,
    TranscriptionResponseWire {
        text,
        language,
        duration_ms,
        segments,
    }
);
validated_response_deserialize!(SpeechResponse, SpeechResponseWire { audio });
validated_response_deserialize!(
    MediaGenerationResponse,
    MediaGenerationResponseWire {
        generation_id,
        assets,
        parameters,
        provider_execution,
        overall_safety,
    }
);
validated_response_deserialize!(
    ClassificationResponse,
    ClassificationResponseWire { policy_id, results }
);

/// The seven-branch canonical model-operation response union.
#[derive(Clone, JsonSchema, PartialEq, Serialize)]
#[serde(untagged)]
pub enum ModelResponse {
    /// A canonical completion response owned by the foundational response module.
    Completion(LlmResponse),
    /// A vector embeddings response.
    Embeddings(EmbeddingResponse),
    /// A document-reranking response.
    Rerank(RerankResponse),
    /// An audio-transcription response.
    Transcription(TranscriptionResponse),
    /// A speech-synthesis response.
    Speech(SpeechResponse),
    /// A media-generation response.
    MediaGeneration(MediaGenerationResponse),
    /// An input-classification response.
    Classification(ClassificationResponse),
}

impl<'de> Deserialize<'de> for ModelResponse {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct OperationProbe {
            operation: Option<String>,
        }

        let raw = Box::<RawValue>::deserialize(deserializer)?;
        let probe: OperationProbe = serde_json::from_str(raw.get()).map_err(D::Error::custom)?;
        let response = match probe.operation.as_deref() {
            None => Self::Completion(serde_json::from_str(raw.get()).map_err(D::Error::custom)?),
            Some("embeddings") => {
                Self::Embeddings(serde_json::from_str(raw.get()).map_err(D::Error::custom)?)
            }
            Some("rerank") => {
                Self::Rerank(serde_json::from_str(raw.get()).map_err(D::Error::custom)?)
            }
            Some("transcription") => {
                Self::Transcription(serde_json::from_str(raw.get()).map_err(D::Error::custom)?)
            }
            Some("speech") => {
                Self::Speech(serde_json::from_str(raw.get()).map_err(D::Error::custom)?)
            }
            Some("media_generation") => {
                Self::MediaGeneration(serde_json::from_str(raw.get()).map_err(D::Error::custom)?)
            }
            Some("classification") => {
                Self::Classification(serde_json::from_str(raw.get()).map_err(D::Error::custom)?)
            }
            Some(_) => return Err(D::Error::custom(ContractError::InvalidContent)),
        };
        response.validate().map_err(D::Error::custom)?;
        Ok(response)
    }
}

impl ModelResponse {
    /// Returns the specialized operation discriminator, or `None` for completion.
    #[must_use]
    pub const fn operation(&self) -> Option<ModelOperation> {
        match self {
            Self::Completion(_) => None,
            Self::Embeddings(response) => Some(response.operation()),
            Self::Rerank(response) => Some(response.operation()),
            Self::Transcription(response) => Some(response.operation()),
            Self::Speech(response) => Some(response.operation()),
            Self::MediaGeneration(response) => Some(response.operation()),
            Self::Classification(response) => Some(response.operation()),
        }
    }

    /// Borrows the original request identifier for any response family.
    #[must_use]
    pub const fn request_id(&self) -> &LlmRequestId {
        match self {
            Self::Completion(response) => response.request_id(),
            Self::Embeddings(response) => response.request_id(),
            Self::Rerank(response) => response.request_id(),
            Self::Transcription(response) => response.request_id(),
            Self::Speech(response) => response.request_id(),
            Self::MediaGeneration(response) => response.request_id(),
            Self::Classification(response) => response.request_id(),
        }
    }

    /// Borrows the canonical response identifier for any response family.
    #[must_use]
    pub fn response_id(&self) -> &str {
        match self {
            Self::Completion(response) => response.response_id(),
            Self::Embeddings(response) => response.response_id(),
            Self::Rerank(response) => response.response_id(),
            Self::Transcription(response) => response.response_id(),
            Self::Speech(response) => response.response_id(),
            Self::MediaGeneration(response) => response.response_id(),
            Self::Classification(response) => response.response_id(),
        }
    }

    /// Borrows the provider identity for any response family.
    #[must_use]
    pub fn provider(&self) -> &str {
        match self {
            Self::Completion(response) => response.provider(),
            Self::Embeddings(response) => response.provider(),
            Self::Rerank(response) => response.provider(),
            Self::Transcription(response) => response.provider(),
            Self::Speech(response) => response.provider(),
            Self::MediaGeneration(response) => response.provider(),
            Self::Classification(response) => response.provider(),
        }
    }

    /// Borrows the model identity for any response family.
    #[must_use]
    pub fn model(&self) -> &str {
        match self {
            Self::Completion(response) => response.model(),
            Self::Embeddings(response) => response.model(),
            Self::Rerank(response) => response.model(),
            Self::Transcription(response) => response.model(),
            Self::Speech(response) => response.model(),
            Self::MediaGeneration(response) => response.model(),
            Self::Classification(response) => response.model(),
        }
    }

    /// Returns the lifecycle status for any response family.
    #[must_use]
    pub const fn status(&self) -> CompletionStatus {
        match self {
            Self::Completion(response) => response.status(),
            Self::Embeddings(response) => response.status(),
            Self::Rerank(response) => response.status(),
            Self::Transcription(response) => response.status(),
            Self::Speech(response) => response.status(),
            Self::MediaGeneration(response) => response.status(),
            Self::Classification(response) => response.status(),
        }
    }

    /// Borrows a completion response when this is the completion branch.
    #[must_use]
    pub const fn as_completion(&self) -> Option<&LlmResponse> {
        if let Self::Completion(response) = self {
            Some(response)
        } else {
            None
        }
    }

    /// Borrows an embeddings response when this is the embeddings branch.
    #[must_use]
    pub const fn as_embeddings(&self) -> Option<&EmbeddingResponse> {
        if let Self::Embeddings(response) = self {
            Some(response)
        } else {
            None
        }
    }

    /// Borrows a reranking response when this is the reranking branch.
    #[must_use]
    pub const fn as_rerank(&self) -> Option<&RerankResponse> {
        if let Self::Rerank(response) = self {
            Some(response)
        } else {
            None
        }
    }

    /// Borrows a transcription response when this is the transcription branch.
    #[must_use]
    pub const fn as_transcription(&self) -> Option<&TranscriptionResponse> {
        if let Self::Transcription(response) = self {
            Some(response)
        } else {
            None
        }
    }

    /// Borrows a speech response when this is the speech branch.
    #[must_use]
    pub const fn as_speech(&self) -> Option<&SpeechResponse> {
        if let Self::Speech(response) = self {
            Some(response)
        } else {
            None
        }
    }

    /// Borrows a media-generation response when this is that branch.
    #[must_use]
    pub const fn as_media_generation(&self) -> Option<&MediaGenerationResponse> {
        if let Self::MediaGeneration(response) = self {
            Some(response)
        } else {
            None
        }
    }

    /// Borrows a classification response when this is the classification branch.
    #[must_use]
    pub const fn as_classification(&self) -> Option<&ClassificationResponse> {
        if let Self::Classification(response) = self {
            Some(response)
        } else {
            None
        }
    }

    /// Checks all invariants with the default serialization limits.
    ///
    /// # Errors
    ///
    /// Returns a value-free [`ContractError`] for the first invalid invariant or limit.
    pub fn validate(&self) -> Result<(), ContractError> {
        self.validate_with_limits(&ContentLimits::default())
    }

    /// Checks all invariants against explicit serialization limits.
    ///
    /// # Errors
    ///
    /// Returns a value-free [`ContractError`] for the first invalid invariant or limit.
    pub fn validate_with_limits(&self, limits: &ContentLimits) -> Result<(), ContractError> {
        match self {
            Self::Completion(response) => response.validate_with_limits(limits),
            Self::Embeddings(response) => response.validate_with_limits(limits),
            Self::Rerank(response) => response.validate_with_limits(limits),
            Self::Transcription(response) => response.validate_with_limits(limits),
            Self::Speech(response) => response.validate_with_limits(limits),
            Self::MediaGeneration(response) => response.validate_with_limits(limits),
            Self::Classification(response) => response.validate_with_limits(limits),
        }
    }
}

macro_rules! redacted_response_debug {
    ($response:ident, $name:literal, $count_name:literal, $field:ident) => {
        impl fmt::Debug for $response {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter
                    .debug_struct($name)
                    .field("operation", &self.operation)
                    .field("status", &self.status)
                    .field($count_name, &self.$field.len())
                    .finish_non_exhaustive()
            }
        }
    };
}

redacted_response_debug!(EmbeddingResponse, "EmbeddingResponse", "item_count", items);
redacted_response_debug!(RerankResponse, "RerankResponse", "result_count", results);
redacted_response_debug!(
    TranscriptionResponse,
    "TranscriptionResponse",
    "segment_count",
    segments
);
redacted_response_debug!(
    MediaGenerationResponse,
    "MediaGenerationResponse",
    "asset_count",
    assets
);
redacted_response_debug!(
    ClassificationResponse,
    "ClassificationResponse",
    "result_count",
    results
);

impl fmt::Debug for SpeechResponse {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SpeechResponse")
            .field("operation", &self.operation)
            .field("status", &self.status)
            .field(
                "timing_mark_count",
                &self.audio.timing_marks.as_ref().map_or(0, Vec::len),
            )
            .finish_non_exhaustive()
    }
}

impl fmt::Debug for ModelResponse {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Completion(response) => formatter
                .debug_struct("ModelResponse")
                .field("operation", &"completion")
                .field("status", &response.status())
                .field("output_part_count", &response.output().len())
                .finish_non_exhaustive(),
            Self::Embeddings(response) => fmt::Debug::fmt(response, formatter),
            Self::Rerank(response) => fmt::Debug::fmt(response, formatter),
            Self::Transcription(response) => fmt::Debug::fmt(response, formatter),
            Self::Speech(response) => fmt::Debug::fmt(response, formatter),
            Self::MediaGeneration(response) => fmt::Debug::fmt(response, formatter),
            Self::Classification(response) => fmt::Debug::fmt(response, formatter),
        }
    }
}

trait ValidateSpecializedBounds {
    fn validate_bounds(&self, limits: &ContentLimits) -> Result<(), ContractError>;
}

impl ValidateSpecializedBounds for EmbeddingResponse {
    fn validate_bounds(&self, limits: &ContentLimits) -> Result<(), ContractError> {
        validate_common_bounds(
            &self.request_id,
            &self.response_id,
            self.provider_response_id(),
            self.provider_request_id(),
            &self.provider,
            &self.model,
            self.warnings(),
            &self.usage,
            self.provider_metadata(),
            limits,
        )?;
        let item_depth = validate_nested_content_collection(self.items.len(), limits, 0)?;
        for item in &self.items {
            validate_content_depth(item_depth, limits)?;
            validate_optional_bounded_string(item.input_id(), limits)?;
            validate_optional_object_at(
                item.provider_metadata(),
                limits,
                next_model_depth(item_depth)?,
            )?;
            validate_embedding_bounds(item.embedding(), limits, next_model_depth(item_depth)?)?;
        }
        Ok(())
    }
}

impl ValidateSpecializedBounds for RerankResponse {
    fn validate_bounds(&self, limits: &ContentLimits) -> Result<(), ContractError> {
        validate_common_bounds(
            &self.request_id,
            &self.response_id,
            self.provider_response_id(),
            self.provider_request_id(),
            &self.provider,
            &self.model,
            self.warnings(),
            &self.usage,
            self.provider_metadata(),
            limits,
        )?;
        let result_depth = validate_nested_content_collection(self.results.len(), limits, 0)?;
        for result in &self.results {
            validate_content_depth(result_depth, limits)?;
            validate_optional_bounded_string(result.document_id(), limits)?;
            validate_optional_bounded_string(result.explanation(), limits)?;
            let value_depth = next_model_depth(result_depth)?;
            if let Some(document) = result.document() {
                validate_bounded_json(document, limits, value_depth)?;
            }
            validate_optional_object_at(result.metadata(), limits, value_depth)?;
            validate_optional_object_at(result.provider_metadata(), limits, value_depth)?;
        }
        Ok(())
    }
}

impl ValidateSpecializedBounds for TranscriptionResponse {
    fn validate_bounds(&self, limits: &ContentLimits) -> Result<(), ContractError> {
        validate_common_bounds(
            &self.request_id,
            &self.response_id,
            self.provider_response_id(),
            self.provider_request_id(),
            &self.provider,
            &self.model,
            self.warnings(),
            &self.usage,
            self.provider_metadata(),
            limits,
        )?;
        validate_bounded_string(&self.text, limits)?;
        validate_optional_bounded_string(self.language(), limits)?;
        let segment_depth = validate_nested_content_collection(self.segments.len(), limits, 0)?;
        for segment in &self.segments {
            validate_content_depth(segment_depth, limits)?;
            validate_bounded_string(segment.text(), limits)?;
            validate_optional_bounded_string(segment.speaker(), limits)?;
            let field_depth = next_model_depth(segment_depth)?;
            validate_optional_object_at(segment.provider_metadata(), limits, field_depth)?;
            if let Some(words) = segment.words() {
                let word_depth =
                    validate_nested_content_collection(words.len(), limits, segment_depth)?;
                for word in words {
                    validate_content_depth(word_depth, limits)?;
                    validate_bounded_string(word.text(), limits)?;
                    validate_optional_bounded_string(word.speaker(), limits)?;
                }
            }
        }
        Ok(())
    }
}

impl ValidateSpecializedBounds for SpeechResponse {
    fn validate_bounds(&self, limits: &ContentLimits) -> Result<(), ContractError> {
        validate_common_bounds(
            &self.request_id,
            &self.response_id,
            self.provider_response_id(),
            self.provider_request_id(),
            &self.provider,
            &self.model,
            self.warnings(),
            &self.usage,
            self.provider_metadata(),
            limits,
        )?;
        let audio_depth = next_model_depth(0)?;
        validate_content_depth(audio_depth, limits)?;
        validate_bounded_string(self.audio.mime_type(), limits)?;
        validate_optional_bounded_string(self.audio.codec(), limits)?;
        validate_optional_bounded_string(self.audio.voice(), limits)?;
        validate_optional_bounded_string(self.audio.transcript(), limits)?;
        validate_optional_bounded_string(self.audio.subtitles(), limits)?;
        validate_content_depth(next_model_depth(audio_depth)?, limits)?;
        self.audio.source().validate_with_limits(limits)?;
        validate_optional_object_at(
            self.audio.provider_metadata(),
            limits,
            next_model_depth(audio_depth)?,
        )?;
        if let Some(marks) = self.audio.timing_marks() {
            let mark_depth = validate_nested_content_collection(marks.len(), limits, audio_depth)?;
            for mark in marks {
                validate_content_depth(mark_depth, limits)?;
                validate_bounded_string(mark.value(), limits)?;
                validate_optional_object_at(
                    mark.provider_metadata(),
                    limits,
                    next_model_depth(mark_depth)?,
                )?;
            }
        }
        Ok(())
    }
}

impl ValidateSpecializedBounds for MediaGenerationResponse {
    fn validate_bounds(&self, limits: &ContentLimits) -> Result<(), ContractError> {
        validate_common_bounds(
            &self.request_id,
            &self.response_id,
            self.provider_response_id(),
            self.provider_request_id(),
            &self.provider,
            &self.model,
            self.warnings(),
            &self.usage,
            self.provider_metadata(),
            limits,
        )?;
        validate_optional_bounded_string(self.generation_id(), limits)?;
        let asset_depth = validate_nested_content_collection(self.assets.len(), limits, 0)?;
        for asset in &self.assets {
            validate_content_depth(asset_depth, limits)?;
            validate_bounded_string(asset.asset_id(), limits)?;
            validate_bounded_string(asset.mime_type(), limits)?;
            validate_optional_bounded_string(asset.filename(), limits)?;
            validate_optional_bounded_string(asset.revised_prompt(), limits)?;
            validate_optional_bounded_string(asset.sha256(), limits)?;
            if let Some(GenerationSeed::String(seed)) = asset.seed() {
                validate_bounded_string(seed, limits)?;
            }
            validate_content_depth(next_model_depth(asset_depth)?, limits)?;
            asset.source().validate_with_limits(limits)?;
            let field_depth = next_model_depth(asset_depth)?;
            validate_optional_object_at(asset.provenance(), limits, field_depth)?;
            validate_optional_object_at(asset.provider_metadata(), limits, field_depth)?;
            if let Some(labels) = asset.safety() {
                let label_depth =
                    validate_nested_content_collection(labels.len(), limits, asset_depth)?;
                for label in labels {
                    validate_classification_label_bounds(label, limits, label_depth)?;
                }
            }
        }
        let response_field_depth = next_model_depth(0)?;
        validate_optional_object_at(self.parameters(), limits, response_field_depth)?;
        if let Some(execution) = self.provider_execution() {
            let execution_depth = validate_nested_content_collection(execution.len(), limits, 0)?;
            for record in execution {
                validate_bounded_json_object(record, limits, execution_depth)?;
            }
        }
        if let Some(labels) = self.overall_safety() {
            let label_depth = validate_nested_content_collection(labels.len(), limits, 0)?;
            for label in labels {
                validate_classification_label_bounds(label, limits, label_depth)?;
            }
        }
        Ok(())
    }
}

impl ValidateSpecializedBounds for ClassificationResponse {
    fn validate_bounds(&self, limits: &ContentLimits) -> Result<(), ContractError> {
        validate_common_bounds(
            &self.request_id,
            &self.response_id,
            self.provider_response_id(),
            self.provider_request_id(),
            &self.provider,
            &self.model,
            self.warnings(),
            &self.usage,
            self.provider_metadata(),
            limits,
        )?;
        validate_optional_bounded_string(self.policy_id(), limits)?;
        let result_depth = validate_nested_content_collection(self.results.len(), limits, 0)?;
        for result in &self.results {
            validate_content_depth(result_depth, limits)?;
            validate_optional_bounded_string(result.input_id(), limits)?;
            validate_optional_bounded_string(result.overall_disposition(), limits)?;
            validate_optional_object_at(
                result.provider_metadata(),
                limits,
                next_model_depth(result_depth)?,
            )?;
            let label_depth =
                validate_nested_content_collection(result.labels.len(), limits, result_depth)?;
            for label in &result.labels {
                validate_classification_label_bounds(label, limits, label_depth)?;
            }
        }
        Ok(())
    }
}

#[expect(
    clippy::too_many_arguments,
    reason = "the fixed envelope retains independent bounded fields"
)]
fn validate_common_bounds(
    request_id: &LlmRequestId,
    response_id: &str,
    provider_response_id: Option<&str>,
    provider_request_id: Option<&str>,
    provider: &str,
    model: &str,
    warnings: Option<&[String]>,
    usage: &ModelUsage,
    provider_metadata: Option<&JsonObject>,
    limits: &ContentLimits,
) -> Result<(), ContractError> {
    validate_content_depth(0, limits)?;
    validate_bounded_string(request_id.as_str(), limits)?;
    validate_bounded_string(response_id, limits)?;
    validate_optional_bounded_string(provider_response_id, limits)?;
    validate_optional_bounded_string(provider_request_id, limits)?;
    validate_bounded_string(provider, limits)?;
    validate_bounded_string(model, limits)?;
    if let Some(warnings) = warnings {
        validate_nested_content_collection(warnings.len(), limits, 0)?;
        warnings
            .iter()
            .try_for_each(|warning| validate_bounded_string(warning, limits))?;
    }
    let field_depth = next_model_depth(0)?;
    validate_optional_object_at(usage.provider_units(), limits, field_depth)?;
    validate_optional_object_at(provider_metadata, limits, field_depth)
}

fn validate_embedding_bounds(
    embedding: &EmbeddingValue,
    limits: &ContentLimits,
    depth: usize,
) -> Result<(), ContractError> {
    validate_content_depth(depth, limits)?;
    match embedding {
        EmbeddingValue::Dense(embedding) => {
            validate_nested_content_collection(embedding.values.len(), limits, depth)?;
            validate_optional_bounded_string(embedding.normalization(), limits)
        }
        EmbeddingValue::Sparse(embedding) => {
            validate_nested_content_collection(embedding.indices.len(), limits, depth)?;
            validate_nested_content_collection(embedding.values.len(), limits, depth)?;
            Ok(())
        }
        EmbeddingValue::Binary(embedding) => {
            validate_bounded_string(embedding.data_base64(), limits)?;
            let decoded_len = validate_base64_decoded_len(embedding.data_base64())?;
            if decoded_len > limits.max_inline_binary_bytes() {
                Err(ContractError::InvalidContent)
            } else {
                Ok(())
            }
        }
        EmbeddingValue::MultiVector(embedding) => {
            let vector_depth =
                validate_nested_content_collection(embedding.vectors.len(), limits, depth)?;
            for vector in &embedding.vectors {
                validate_content_depth(vector_depth, limits)?;
                validate_optional_bounded_string(vector.name(), limits)?;
                validate_nested_content_collection(vector.values.len(), limits, vector_depth)?;
            }
            Ok(())
        }
    }
}

fn validate_classification_label_bounds(
    label: &ClassificationLabel,
    limits: &ContentLimits,
    depth: usize,
) -> Result<(), ContractError> {
    validate_content_depth(depth, limits)?;
    validate_bounded_string(label.label(), limits)?;
    validate_optional_bounded_string(label.disposition(), limits)?;
    validate_optional_bounded_string(label.explanation(), limits)?;
    validate_optional_object_at(label.metadata(), limits, next_model_depth(depth)?)
}

fn validate_optional_bounded_string(
    value: Option<&str>,
    limits: &ContentLimits,
) -> Result<(), ContractError> {
    value.map_or(Ok(()), |value| validate_bounded_string(value, limits))
}

fn validate_optional_object_at(
    value: Option<&JsonObject>,
    limits: &ContentLimits,
    depth: usize,
) -> Result<(), ContractError> {
    value.map_or(Ok(()), |value| {
        validate_bounded_json_object(value, limits, depth)
    })
}

fn next_model_depth(depth: usize) -> Result<usize, ContractError> {
    depth.checked_add(1).ok_or(ContractError::InvalidContent)
}

fn validate_common_response(
    operation: ModelOperation,
    expected_operation: ModelOperation,
    response_id: &str,
    provider_response_id: Option<&str>,
    provider_request_id: Option<&str>,
    provider: &str,
    model: &str,
) -> Result<(), ContractError> {
    if operation != expected_operation {
        return Err(ContractError::InvalidContent);
    }
    validate_identifier(response_id)?;
    validate_optional_identifier(provider_response_id)?;
    validate_optional_identifier(provider_request_id)?;
    validate_name(provider)?;
    validate_name(model)
}

fn validate_optional_identifier(value: Option<&str>) -> Result<(), ContractError> {
    value.map_or(Ok(()), validate_identifier)
}

fn validate_vector(values: &[f64], dimensions: u64) -> Result<(), ContractError> {
    if dimensions == 0
        || usize::try_from(dimensions).ok() != Some(values.len())
        || values.iter().any(|value| !value.is_finite())
    {
        Err(ContractError::InvalidContent)
    } else {
        Ok(())
    }
}

fn validate_probability(value: f64) -> Result<(), ContractError> {
    if value.is_finite() && (0.0..=1.0).contains(&value) {
        Ok(())
    } else {
        Err(ContractError::InvalidContent)
    }
}

fn validate_optional_probability(value: Option<f64>) -> Result<(), ContractError> {
    value.map_or(Ok(()), validate_probability)
}

fn validate_finite(value: f64) -> Result<(), ContractError> {
    if value.is_finite() {
        Ok(())
    } else {
        Err(ContractError::InvalidContent)
    }
}

fn validate_interval(start_ms: u64, end_ms: u64) -> Result<(), ContractError> {
    if start_ms <= end_ms {
        Ok(())
    } else {
        Err(ContractError::InvalidContent)
    }
}

fn validate_monotonic_times(
    times: impl IntoIterator<Item = (u64, u64)>,
) -> Result<(), ContractError> {
    let mut previous_start = None;
    for (start_ms, end_ms) in times {
        validate_interval(start_ms, end_ms)?;
        if previous_start.is_some_and(|start| start_ms < start) {
            return Err(ContractError::InvalidContent);
        }
        previous_start = Some(start_ms);
    }
    Ok(())
}

fn validate_binary_source(source: &BinarySource) -> Result<(), ContractError> {
    source.validate()
}

fn number_is_integer(number: &Number) -> bool {
    !number
        .to_string()
        .as_bytes()
        .iter()
        .any(|byte| matches!(byte, b'.' | b'e' | b'E'))
}

impl fmt::Display for ModelOperation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Embeddings => "embeddings",
            Self::Rerank => "rerank",
            Self::Transcription => "transcription",
            Self::Speech => "speech",
            Self::MediaGeneration => "media_generation",
            Self::Classification => "classification",
        })
    }
}

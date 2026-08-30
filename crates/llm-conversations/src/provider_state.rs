use std::fmt;

use omnius_llm_core::{ReasoningOutputPart, ReasoningRepresentation};
use serde::{Deserialize, Deserializer, Serialize, de::Error as _};
use time::OffsetDateTime;

use crate::{
    ConversationContractError, ConversationId, ConversationRevision, ProviderStateId,
    ProviderStateRevision,
    value::{validate_timeline, validate_utc},
};

const MAX_REASONING_SUMMARY_BYTES: usize = 16 * 1024;
const MAX_REASONING_SIGNATURE_BYTES: usize = 4 * 1024;
const MAX_ENCRYPTED_REFERENCE_BYTES: usize = 512;
const MAX_KEY_ID_BYTES: usize = 128;

fn valid_portable_identifier(value: &str, max_bytes: usize) -> bool {
    !value.is_empty()
        && value.len() <= max_bytes
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b':' | b'/' | b'.' | b'_' | b'-')
        })
}

/// A provider-returned signature for a sanctioned reasoning summary.
///
/// The signature is opaque but bounded and never rendered through [`Debug`].
#[derive(Clone, Eq, PartialEq, Serialize)]
#[serde(transparent)]
pub struct ReasoningSignature(String);

impl ReasoningSignature {
    /// Admits only a canonical provider-returned reasoning signature.
    ///
    /// # Errors
    ///
    /// Returns [`ConversationContractError::InvalidProviderState`] unless `part` is the
    /// canonical `signature` representation with bounded portable signature material.
    pub fn from_canonical(part: &ReasoningOutputPart) -> Result<Self, ConversationContractError> {
        if part.representation() != ReasoningRepresentation::Signature {
            return Err(ConversationContractError::InvalidProviderState);
        }
        Self::restore(part.data().to_owned())
    }

    fn restore(value: String) -> Result<Self, ConversationContractError> {
        let is_portable = value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'/' | b'-' | b'_' | b'=')
        });
        if value.is_empty() || value.len() > MAX_REASONING_SIGNATURE_BYTES || !is_portable {
            Err(ConversationContractError::InvalidProviderState)
        } else {
            Ok(Self(value))
        }
    }

    /// Borrows the opaque signature for encrypted persistence or provider continuation.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for ReasoningSignature {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ReasoningSignature([REDACTED])")
    }
}

/// A bounded, provider-sanctioned summary suitable for user-visible persistence.
///
/// This type is not a container for provider wire payloads or hidden chain of thought.
#[derive(Clone, Eq, PartialEq, Serialize)]
pub struct SanctionedReasoningSummary {
    summary: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    signature: Option<ReasoningSignature>,
}

impl SanctionedReasoningSummary {
    /// Admits one canonical provider-returned safe summary and optional canonical signature.
    ///
    /// # Errors
    ///
    /// Returns [`ConversationContractError::InvalidProviderState`] unless `summary` is the
    /// canonical `summary` representation, the optional part is the canonical `signature`
    /// representation, and both values satisfy fixed persistence bounds.
    pub fn from_canonical(
        summary: &ReasoningOutputPart,
        signature: Option<&ReasoningOutputPart>,
    ) -> Result<Self, ConversationContractError> {
        if summary.representation() != ReasoningRepresentation::Summary {
            return Err(ConversationContractError::InvalidProviderState);
        }
        let signature = signature
            .map(ReasoningSignature::from_canonical)
            .transpose()?;
        Self::restore(summary.data().to_owned(), signature)
    }

    fn restore(
        summary: String,
        signature: Option<ReasoningSignature>,
    ) -> Result<Self, ConversationContractError> {
        if summary.trim().is_empty()
            || summary.len() > MAX_REASONING_SUMMARY_BYTES
            || summary.chars().any(char::is_control)
        {
            return Err(ConversationContractError::InvalidProviderState);
        }
        Ok(Self { summary, signature })
    }

    /// Borrows the sanctioned user-visible summary.
    #[must_use]
    pub fn summary(&self) -> &str {
        &self.summary
    }

    /// Borrows the optional opaque provider signature.
    #[must_use]
    pub const fn signature(&self) -> Option<&ReasoningSignature> {
        self.signature.as_ref()
    }
}

impl fmt::Debug for SanctionedReasoningSummary {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SanctionedReasoningSummary")
            .field("summary", &"[REDACTED]")
            .field("has_signature", &self.signature.is_some())
            .finish()
    }
}

/// Approved envelope-encryption algorithm for an opaque continuation object.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ContinuationEncryptionAlgorithm {
    /// AES-256 in Galois/counter mode.
    Aes256Gcm,
    /// `XChaCha20` with Poly1305 authentication.
    XChaCha20Poly1305,
}

/// A fixed digest of encrypted continuation ciphertext.
#[derive(Clone, Copy, Eq, PartialEq, Serialize)]
#[serde(transparent)]
pub struct CiphertextDigest([u8; 32]);

impl CiphertextDigest {
    /// Creates a non-zero ciphertext digest.
    ///
    /// # Errors
    ///
    /// Returns [`ConversationContractError::InvalidProviderState`] for an all-zero digest.
    pub const fn new(bytes: [u8; 32]) -> Result<Self, ConversationContractError> {
        let mut index = 0;
        while index < bytes.len() {
            if bytes[index] != 0 {
                return Ok(Self(bytes));
            }
            index += 1;
        }
        Err(ConversationContractError::InvalidProviderState)
    }

    /// Returns the fixed digest bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Debug for CiphertextDigest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("CiphertextDigest([REDACTED])")
    }
}

impl<'de> Deserialize<'de> for CiphertextDigest {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        Self::new(<[u8; 32]>::deserialize(deserializer)?).map_err(D::Error::custom)
    }
}

/// An opaque reference to envelope-encrypted provider continuation state.
///
/// Only an `encrypted://` object reference, non-secret key identity, algorithm, and ciphertext
/// digest are retained. Ciphertext, plaintext, and provider response payloads have no field in
/// this contract.
#[derive(Clone, Eq, PartialEq, Serialize)]
pub struct EncryptedContinuationReference {
    reference: String,
    key_id: String,
    key_revision: u32,
    algorithm: ContinuationEncryptionAlgorithm,
    ciphertext_digest: CiphertextDigest,
}

impl EncryptedContinuationReference {
    /// Creates an approved encrypted continuation object reference.
    ///
    /// # Errors
    ///
    /// Returns [`ConversationContractError::InvalidProviderState`] unless the reference uses
    /// the closed `encrypted://` scheme with portable characters, the key identity is bounded
    /// and portable, and the key revision is non-zero.
    pub fn new(
        reference: impl Into<String>,
        key_id: impl Into<String>,
        key_revision: u32,
        algorithm: ContinuationEncryptionAlgorithm,
        ciphertext_digest: CiphertextDigest,
    ) -> Result<Self, ConversationContractError> {
        let reference = reference.into();
        let key_id = key_id.into();
        if reference.len() == "encrypted://".len()
            || !reference.starts_with("encrypted://")
            || !valid_portable_identifier(&reference, MAX_ENCRYPTED_REFERENCE_BYTES)
            || !valid_portable_identifier(&key_id, MAX_KEY_ID_BYTES)
            || key_revision == 0
        {
            return Err(ConversationContractError::InvalidProviderState);
        }
        Ok(Self {
            reference,
            key_id,
            key_revision,
            algorithm,
            ciphertext_digest,
        })
    }

    /// Borrows the opaque encrypted-object reference.
    #[must_use]
    pub fn reference(&self) -> &str {
        &self.reference
    }

    /// Borrows the non-secret encryption-key identity.
    #[must_use]
    pub fn key_id(&self) -> &str {
        &self.key_id
    }

    /// Returns the encryption-key revision.
    #[must_use]
    pub const fn key_revision(&self) -> u32 {
        self.key_revision
    }

    /// Returns the closed envelope-encryption algorithm.
    #[must_use]
    pub const fn algorithm(&self) -> ContinuationEncryptionAlgorithm {
        self.algorithm
    }

    /// Returns the ciphertext digest.
    #[must_use]
    pub const fn ciphertext_digest(&self) -> CiphertextDigest {
        self.ciphertext_digest
    }
}

impl fmt::Debug for EncryptedContinuationReference {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("EncryptedContinuationReference")
            .field("reference", &"[REDACTED]")
            .field("key_id", &"[REDACTED]")
            .field("key_revision", &self.key_revision)
            .field("algorithm", &self.algorithm)
            .field("ciphertext_digest", &self.ciphertext_digest)
            .finish()
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct EncryptedContinuationReferenceWire {
    reference: String,
    key_id: String,
    key_revision: u32,
    algorithm: ContinuationEncryptionAlgorithm,
    ciphertext_digest: CiphertextDigest,
}

impl<'de> Deserialize<'de> for EncryptedContinuationReference {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wire = EncryptedContinuationReferenceWire::deserialize(deserializer)?;
        Self::new(
            wire.reference,
            wire.key_id,
            wire.key_revision,
            wire.algorithm,
            wire.ciphertext_digest,
        )
        .map_err(D::Error::custom)
    }
}

/// The complete closed set of provider continuation state allowed in durable storage.
#[derive(Clone, PartialEq, Serialize)]
#[serde(tag = "kind", content = "value", rename_all = "snake_case")]
pub enum ProviderStateValue {
    /// A user-visible provider-sanctioned reasoning summary and optional signature.
    ReasoningSummary(SanctionedReasoningSummary),
    /// An opaque reference to an envelope-encrypted continuation object.
    EncryptedContinuation(EncryptedContinuationReference),
}

impl fmt::Debug for ProviderStateValue {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ReasoningSummary(value) => formatter
                .debug_tuple("ReasoningSummary")
                .field(value)
                .finish(),
            Self::EncryptedContinuation(value) => formatter
                .debug_tuple("EncryptedContinuation")
                .field(value)
                .finish(),
        }
    }
}

/// An immutable snapshot of one sanctioned provider-state record.
#[derive(Clone, PartialEq, Serialize)]
pub struct ProviderStateRecord {
    conversation_id: ConversationId,
    state_id: ProviderStateId,
    revision: ProviderStateRevision,
    value: ProviderStateValue,
    created_at: OffsetDateTime,
    updated_at: OffsetDateTime,
}

impl ProviderStateRecord {
    /// Materializes an initial provider-state snapshot from a validated save command.
    ///
    /// # Errors
    ///
    /// Returns [`ConversationContractError::InvalidRevision`] when the command expected an
    /// existing provider-state revision.
    pub fn from_save(command: &SaveProviderState) -> Result<Self, ConversationContractError> {
        if command.expected_state_revision.is_some() {
            return Err(ConversationContractError::InvalidRevision);
        }
        Ok(Self {
            conversation_id: command.conversation_id,
            state_id: command.state_id,
            revision: ProviderStateRevision::INITIAL,
            value: command.value.clone(),
            created_at: command.updated_at,
            updated_at: command.updated_at,
        })
    }

    /// Restores a persisted provider-state snapshot.
    ///
    /// # Errors
    ///
    /// Returns [`ConversationContractError::InvalidTimeline`] for a non-UTC or decreasing
    /// timeline.
    pub fn restore(
        conversation_id: ConversationId,
        state_id: ProviderStateId,
        revision: ProviderStateRevision,
        value: ProviderStateValue,
        created_at: OffsetDateTime,
        updated_at: OffsetDateTime,
    ) -> Result<Self, ConversationContractError> {
        validate_timeline(created_at, updated_at)?;
        Ok(Self {
            conversation_id,
            state_id,
            revision,
            value,
            created_at,
            updated_at,
        })
    }

    /// Produces the next immutable provider-state snapshot.
    ///
    /// # Errors
    ///
    /// Returns a content-free error for a mismatched identity/revision, revision exhaustion,
    /// or invalid timeline.
    pub fn revise(&self, command: &SaveProviderState) -> Result<Self, ConversationContractError> {
        if command.conversation_id != self.conversation_id
            || command.state_id != self.state_id
            || command.expected_state_revision != Some(self.revision)
        {
            return Err(ConversationContractError::InvalidRevision);
        }
        validate_timeline(self.updated_at, command.updated_at)?;
        Ok(Self {
            revision: self.revision.next()?,
            value: command.value.clone(),
            updated_at: command.updated_at,
            ..self.clone()
        })
    }

    /// Returns the containing conversation identity.
    #[must_use]
    pub const fn conversation_id(&self) -> ConversationId {
        self.conversation_id
    }

    /// Returns the stable provider-state identity.
    #[must_use]
    pub const fn state_id(&self) -> ProviderStateId {
        self.state_id
    }

    /// Returns the immutable provider-state revision.
    #[must_use]
    pub const fn revision(&self) -> ProviderStateRevision {
        self.revision
    }

    /// Borrows the sanctioned provider-state value.
    #[must_use]
    pub const fn value(&self) -> &ProviderStateValue {
        &self.value
    }

    /// Returns the UTC creation instant.
    #[must_use]
    pub const fn created_at(&self) -> OffsetDateTime {
        self.created_at
    }

    /// Returns the UTC last-update instant.
    #[must_use]
    pub const fn updated_at(&self) -> OffsetDateTime {
        self.updated_at
    }
}

impl fmt::Debug for ProviderStateRecord {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProviderStateRecord")
            .field("conversation_id", &self.conversation_id)
            .field("state_id", &self.state_id)
            .field("revision", &self.revision)
            .field("value", &"[REDACTED]")
            .finish_non_exhaustive()
    }
}

/// A version-checked command to create or replace sanctioned provider state.
#[derive(Clone, PartialEq)]
pub struct SaveProviderState {
    conversation_id: ConversationId,
    state_id: ProviderStateId,
    expected_conversation_revision: ConversationRevision,
    expected_state_revision: Option<ProviderStateRevision>,
    value: ProviderStateValue,
    updated_at: OffsetDateTime,
}

impl SaveProviderState {
    /// Creates a provider-state save command.
    ///
    /// An absent provider-state revision means create; a present revision means replace.
    ///
    /// # Errors
    ///
    /// Returns [`ConversationContractError::InvalidTimeline`] for a non-UTC timestamp.
    pub fn new(
        conversation_id: ConversationId,
        state_id: ProviderStateId,
        expected_conversation_revision: ConversationRevision,
        expected_state_revision: Option<ProviderStateRevision>,
        value: ProviderStateValue,
        updated_at: OffsetDateTime,
    ) -> Result<Self, ConversationContractError> {
        validate_utc(updated_at)?;
        Ok(Self {
            conversation_id,
            state_id,
            expected_conversation_revision,
            expected_state_revision,
            value,
            updated_at,
        })
    }

    /// Returns the containing conversation identity.
    #[must_use]
    pub const fn conversation_id(&self) -> ConversationId {
        self.conversation_id
    }

    /// Returns the stable provider-state identity.
    #[must_use]
    pub const fn state_id(&self) -> ProviderStateId {
        self.state_id
    }

    /// Returns the expected conversation revision.
    #[must_use]
    pub const fn expected_conversation_revision(&self) -> ConversationRevision {
        self.expected_conversation_revision
    }

    /// Returns the expected provider-state revision, or `None` for create.
    #[must_use]
    pub const fn expected_state_revision(&self) -> Option<ProviderStateRevision> {
        self.expected_state_revision
    }

    /// Borrows the sanctioned provider-state value.
    #[must_use]
    pub const fn value(&self) -> &ProviderStateValue {
        &self.value
    }

    /// Returns the UTC save instant.
    #[must_use]
    pub const fn updated_at(&self) -> OffsetDateTime {
        self.updated_at
    }
}

impl fmt::Debug for SaveProviderState {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SaveProviderState")
            .field("conversation_id", &self.conversation_id)
            .field("state_id", &self.state_id)
            .field(
                "expected_conversation_revision",
                &self.expected_conversation_revision,
            )
            .field("expected_state_revision", &self.expected_state_revision)
            .field("value", &"[REDACTED]")
            .finish_non_exhaustive()
    }
}

/// A version-checked command to delete one sanctioned provider-state record.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DeleteProviderState {
    conversation_id: ConversationId,
    state_id: ProviderStateId,
    expected_conversation_revision: ConversationRevision,
    expected_state_revision: ProviderStateRevision,
    deleted_at: OffsetDateTime,
}

impl DeleteProviderState {
    /// Creates a provider-state deletion command.
    ///
    /// # Errors
    ///
    /// Returns [`ConversationContractError::InvalidTimeline`] for a non-UTC timestamp.
    pub fn new(
        conversation_id: ConversationId,
        state_id: ProviderStateId,
        expected_conversation_revision: ConversationRevision,
        expected_state_revision: ProviderStateRevision,
        deleted_at: OffsetDateTime,
    ) -> Result<Self, ConversationContractError> {
        validate_utc(deleted_at)?;
        Ok(Self {
            conversation_id,
            state_id,
            expected_conversation_revision,
            expected_state_revision,
            deleted_at,
        })
    }

    /// Returns the containing conversation identity.
    #[must_use]
    pub const fn conversation_id(&self) -> ConversationId {
        self.conversation_id
    }

    /// Returns the stable provider-state identity.
    #[must_use]
    pub const fn state_id(&self) -> ProviderStateId {
        self.state_id
    }

    /// Returns the expected conversation revision.
    #[must_use]
    pub const fn expected_conversation_revision(&self) -> ConversationRevision {
        self.expected_conversation_revision
    }

    /// Returns the expected provider-state revision.
    #[must_use]
    pub const fn expected_state_revision(&self) -> ProviderStateRevision {
        self.expected_state_revision
    }

    /// Returns the UTC deletion instant.
    #[must_use]
    pub const fn deleted_at(&self) -> OffsetDateTime {
        self.deleted_at
    }
}

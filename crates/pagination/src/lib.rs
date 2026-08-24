//! Bounded opaque cursor pagination contracts.
//!
//! Cursors are authenticated, versioned, URL-safe values. Their contents and signing keys are
//! redacted from formatting, while request and response types provide strict serde contracts.

use std::fmt;

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use hmac::{Hmac, Mac, digest::InvalidLength};
use serde::{Deserialize, Deserializer, Serialize, Serializer, de::Error as _};
use sha2::Sha256;
use thiserror::Error;

/// Maximum application payload accepted by [`CursorCodec::encode`].
pub const MAX_CURSOR_PAYLOAD_BYTES: usize = 128;
/// Maximum encoded length accepted for an [`OpaqueCursor`].
pub const MAX_ENCODED_CURSOR_BYTES: usize = 256;

const CURSOR_VERSION: u8 = 1;
const CURSOR_VERSION_BYTES: usize = 1;
const AUTHENTICATION_TAG_BYTES: usize = 32;
const SIGNING_KEY_BYTES: usize = 32;

type HmacSha256 = Hmac<Sha256>;

/// An exact 32-byte key used only to authenticate opaque cursors.
///
/// Formatting is always redacted, and this type intentionally provides no accessor for the key
/// material.
#[derive(Clone)]
pub struct CursorSigningKey([u8; SIGNING_KEY_BYTES]);

impl CursorSigningKey {
    /// Required signing-key length in bytes.
    pub const BYTE_LENGTH: usize = SIGNING_KEY_BYTES;

    /// Creates a signing key from an exact-size byte array.
    #[must_use]
    pub const fn new(bytes: [u8; SIGNING_KEY_BYTES]) -> Self {
        Self(bytes)
    }

    /// Copies an exact-size byte slice into a signing key.
    ///
    /// # Errors
    ///
    /// Returns [`CursorSigningKeyError`] unless `bytes` contains exactly 32 bytes.
    pub fn from_slice(bytes: &[u8]) -> Result<Self, CursorSigningKeyError> {
        <[u8; SIGNING_KEY_BYTES]>::try_from(bytes)
            .map(Self)
            .map_err(|_| CursorSigningKeyError::InvalidLength)
    }
}

impl From<[u8; SIGNING_KEY_BYTES]> for CursorSigningKey {
    fn from(bytes: [u8; SIGNING_KEY_BYTES]) -> Self {
        Self::new(bytes)
    }
}

impl TryFrom<&[u8]> for CursorSigningKey {
    type Error = CursorSigningKeyError;

    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        Self::from_slice(bytes)
    }
}

impl fmt::Debug for CursorSigningKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("CursorSigningKey([REDACTED])")
    }
}

impl fmt::Display for CursorSigningKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("CursorSigningKey([REDACTED])")
    }
}

/// Signing-key construction failures.
#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum CursorSigningKeyError {
    /// A signing key did not contain exactly 32 bytes.
    #[error("cursor signing key must be exactly 32 bytes")]
    InvalidLength,
}

/// A bounded encoded cursor whose contents are redacted from formatting.
///
/// Deserialization validates only the non-empty encoded-size bound. Authentication and envelope
/// validation happen in [`CursorCodec::decode`], which reports one uniform error for every invalid
/// cursor form.
#[derive(Clone, Eq, Hash, PartialEq)]
pub struct OpaqueCursor(String);

impl OpaqueCursor {
    /// Validates and owns a non-empty encoded cursor of at most 256 bytes.
    ///
    /// # Errors
    ///
    /// Returns [`OpaqueCursorError`] when the string is empty or exceeds the encoded bound.
    pub fn new(encoded: String) -> Result<Self, OpaqueCursorError> {
        if encoded.is_empty() {
            return Err(OpaqueCursorError::Empty);
        }
        if encoded.len() > MAX_ENCODED_CURSOR_BYTES {
            return Err(OpaqueCursorError::TooLong);
        }
        Ok(Self(encoded))
    }
}

impl TryFrom<String> for OpaqueCursor {
    type Error = OpaqueCursorError;

    fn try_from(encoded: String) -> Result<Self, Self::Error> {
        Self::new(encoded)
    }
}

impl TryFrom<&str> for OpaqueCursor {
    type Error = OpaqueCursorError;

    fn try_from(encoded: &str) -> Result<Self, Self::Error> {
        Self::new(encoded.to_owned())
    }
}

impl fmt::Debug for OpaqueCursor {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("OpaqueCursor([REDACTED])")
    }
}

impl fmt::Display for OpaqueCursor {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("OpaqueCursor([REDACTED])")
    }
}

impl Serialize for OpaqueCursor {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for OpaqueCursor {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let encoded = String::deserialize(deserializer)?;
        Self::new(encoded).map_err(D::Error::custom)
    }
}

/// Encoded cursor validation failures.
#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum OpaqueCursorError {
    /// The encoded cursor was empty.
    #[error("opaque cursor must not be empty")]
    Empty,
    /// The encoded cursor exceeded 256 bytes.
    #[error("opaque cursor must not exceed 256 bytes")]
    TooLong,
}

/// A cloneable HMAC-SHA256 cursor encoder and verifier.
///
/// The authenticated envelope contains the payload, a format version, and a 32-byte tag. It is
/// encoded with URL-safe base64 without padding. Clones contain the same redacted signing key.
#[derive(Clone)]
pub struct CursorCodec {
    key: CursorSigningKey,
}

impl CursorCodec {
    /// Creates a codec using `key` for both encoding and verification.
    #[must_use]
    pub const fn new(key: CursorSigningKey) -> Self {
        Self { key }
    }

    /// Authenticates and encodes an application cursor payload.
    ///
    /// # Errors
    ///
    /// Returns [`CursorEncodeError::PayloadTooLarge`] when `payload` exceeds 128 bytes. A stable
    /// signing failure is returned if the HMAC implementation rejects the validated key.
    pub fn encode(&self, payload: &[u8]) -> Result<OpaqueCursor, CursorEncodeError> {
        self.encode_version(payload, CURSOR_VERSION)
    }

    /// Verifies and decodes an opaque cursor payload.
    ///
    /// Authentication uses the constant-time verification supplied by the `hmac` crate. Invalid
    /// base64, bounds, envelope versions, truncation, and authentication tags all return the same
    /// stable error.
    ///
    /// # Errors
    ///
    /// Returns [`CursorDecodeError::InvalidCursor`] for every invalid cursor form.
    pub fn decode(&self, cursor: &OpaqueCursor) -> Result<Vec<u8>, CursorDecodeError> {
        if cursor.0.len() > MAX_ENCODED_CURSOR_BYTES {
            return Err(CursorDecodeError::InvalidCursor);
        }

        let mut envelope = URL_SAFE_NO_PAD
            .decode(cursor.0.as_bytes())
            .map_err(|_| CursorDecodeError::InvalidCursor)?;
        let signed_bytes = envelope
            .len()
            .checked_sub(AUTHENTICATION_TAG_BYTES)
            .ok_or(CursorDecodeError::InvalidCursor)?;
        let payload_bytes = signed_bytes
            .checked_sub(CURSOR_VERSION_BYTES)
            .ok_or(CursorDecodeError::InvalidCursor)?;
        if payload_bytes > MAX_CURSOR_PAYLOAD_BYTES {
            return Err(CursorDecodeError::InvalidCursor);
        }

        let mut mac = self
            .new_mac()
            .map_err(|_| CursorDecodeError::InvalidCursor)?;
        mac.update(&envelope[..signed_bytes]);
        mac.verify_slice(&envelope[signed_bytes..])
            .map_err(|_| CursorDecodeError::InvalidCursor)?;
        if envelope[payload_bytes] != CURSOR_VERSION {
            return Err(CursorDecodeError::InvalidCursor);
        }

        envelope.truncate(payload_bytes);
        Ok(envelope)
    }

    fn encode_version(
        &self,
        payload: &[u8],
        version: u8,
    ) -> Result<OpaqueCursor, CursorEncodeError> {
        if payload.len() > MAX_CURSOR_PAYLOAD_BYTES {
            return Err(CursorEncodeError::PayloadTooLarge);
        }

        let mut envelope =
            Vec::with_capacity(payload.len() + CURSOR_VERSION_BYTES + AUTHENTICATION_TAG_BYTES);
        envelope.extend_from_slice(payload);
        envelope.push(version);

        let mut mac = self
            .new_mac()
            .map_err(|_| CursorEncodeError::SigningFailed)?;
        mac.update(&envelope);
        envelope.extend_from_slice(&mac.finalize().into_bytes());

        let encoded = URL_SAFE_NO_PAD.encode(envelope);
        Ok(OpaqueCursor(encoded))
    }

    fn new_mac(&self) -> Result<HmacSha256, InvalidLength> {
        HmacSha256::new_from_slice(&self.key.0)
    }
}

impl fmt::Debug for CursorCodec {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("CursorCodec([REDACTED])")
    }
}

/// Cursor encoding failures that never include a payload or key.
#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum CursorEncodeError {
    /// The application payload exceeded 128 bytes.
    #[error("cursor payload must not exceed 128 bytes")]
    PayloadTooLarge,
    /// The authentication implementation rejected the validated signing key.
    #[error("cursor signing failed")]
    SigningFailed,
}

/// Uniform cursor decoding failures that never include cursor or payload bytes.
#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum CursorDecodeError {
    /// The encoded cursor was malformed, oversized, unsupported, or unauthenticated.
    #[error("cursor is invalid")]
    InvalidCursor,
}

/// A validated page size in the inclusive range 1–100.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize)]
#[serde(transparent)]
pub struct PageLimit(u16);

impl PageLimit {
    /// Smallest valid page size.
    pub const MIN: u16 = 1;
    /// Largest valid page size.
    pub const MAX: u16 = 100;
    /// Default page size when a request omits `limit`.
    pub const DEFAULT: u16 = 20;

    /// Validates a page size without clamping it.
    ///
    /// # Errors
    ///
    /// Returns [`PageLimitError`] when `value` is outside 1–100.
    pub const fn new(value: u16) -> Result<Self, PageLimitError> {
        if value < Self::MIN || value > Self::MAX {
            return Err(PageLimitError::OutOfRange);
        }
        Ok(Self(value))
    }

    /// Returns the validated page size.
    #[must_use]
    pub const fn get(self) -> u16 {
        self.0
    }
}

impl Default for PageLimit {
    fn default() -> Self {
        Self(Self::DEFAULT)
    }
}

impl TryFrom<u16> for PageLimit {
    type Error = PageLimitError;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl From<PageLimit> for u16 {
    fn from(limit: PageLimit) -> Self {
        limit.get()
    }
}

impl<'de> Deserialize<'de> for PageLimit {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = u16::deserialize(deserializer)?;
        Self::new(value).map_err(D::Error::custom)
    }
}

/// Page-size validation failures.
#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum PageLimitError {
    /// The page size was outside the inclusive 1–100 range.
    #[error("page limit must be between 1 and 100")]
    OutOfRange,
}

/// Strict cursor-pagination query parameters.
///
/// Missing fields use [`PageRequest::default`]. Unknown fields are rejected during deserialization.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct PageRequest {
    /// Validated number of items requested.
    pub limit: PageLimit,
    /// Cursor after which the page begins.
    pub cursor: Option<OpaqueCursor>,
}

impl PageRequest {
    /// Creates a request from an already validated limit and optional cursor.
    #[must_use]
    pub const fn new(limit: PageLimit, cursor: Option<OpaqueCursor>) -> Self {
        Self { limit, cursor }
    }
}

/// A serializable cursor page.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct CursorPage<T> {
    /// Items in stable keyset order.
    pub items: Vec<T>,
    /// Cursor for the next page, or `None` when no later page exists.
    pub next_cursor: Option<OpaqueCursor>,
}

impl<T> CursorPage<T> {
    /// Creates a page from its items and optional continuation cursor.
    #[must_use]
    pub const fn new(items: Vec<T>, next_cursor: Option<OpaqueCursor>) -> Self {
        Self { items, next_cursor }
    }
}

#[cfg(test)]
mod tests {
    use std::error::Error;

    use proptest::{collection::vec, prelude::*, test_runner::TestCaseError};
    use serde::de::value::{
        Error as ValueError, MapDeserializer, StrDeserializer, U16Deserializer,
    };

    use super::*;

    fn codec() -> CursorCodec {
        CursorCodec::new(CursorSigningKey::new([0x5a; CursorSigningKey::BYTE_LENGTH]))
    }

    proptest! {
        #[test]
        fn valid_payloads_round_trip(
            payload in vec(any::<u8>(), 0..=MAX_CURSOR_PAYLOAD_BYTES),
        ) {
            let codec = codec();
            let cursor = codec
                .encode(&payload)
                .map_err(|error| TestCaseError::fail(error.to_string()))?;

            prop_assert_eq!(codec.decode(&cursor), Ok(payload));
        }

        #[test]
        fn tampered_cursors_never_decode(
            payload in vec(any::<u8>(), 0..=MAX_CURSOR_PAYLOAD_BYTES),
        ) {
            let codec = codec();
            let cursor = codec
                .encode(&payload)
                .map_err(|error| TestCaseError::fail(error.to_string()))?;
            let mut encoded = cursor.0.into_bytes();
            encoded[0] = if encoded[0] == b'A' { b'B' } else { b'A' };
            let encoded = String::from_utf8(encoded)
                .map_err(|error| TestCaseError::fail(error.to_string()))?;
            let tampered = OpaqueCursor::new(encoded)
                .map_err(|error| TestCaseError::fail(error.to_string()))?;

            prop_assert_eq!(
                codec.decode(&tampered),
                Err(CursorDecodeError::InvalidCursor),
            );
        }

        #[test]
        fn truncated_cursors_never_decode(
            payload in vec(any::<u8>(), 0..=MAX_CURSOR_PAYLOAD_BYTES),
        ) {
            let codec = codec();
            let cursor = codec
                .encode(&payload)
                .map_err(|error| TestCaseError::fail(error.to_string()))?;
            let mut encoded = cursor.0;
            prop_assert!(encoded.pop().is_some());
            let truncated = OpaqueCursor::new(encoded)
                .map_err(|error| TestCaseError::fail(error.to_string()))?;

            prop_assert_eq!(
                codec.decode(&truncated),
                Err(CursorDecodeError::InvalidCursor),
            );
        }
    }

    #[test]
    fn unsupported_version_and_bad_signature_share_decode_error() -> Result<(), Box<dyn Error>> {
        let codec = codec();
        let unsupported = codec.encode_version(b"payload", CURSOR_VERSION + 1)?;
        let signed = codec.encode(b"payload")?;
        let mut bad_tag = URL_SAFE_NO_PAD.decode(signed.0.as_bytes())?;
        let tag_byte = bad_tag
            .last_mut()
            .ok_or("encoded cursor unexpectedly had no authentication tag")?;
        *tag_byte ^= 1;
        let bad_tag = OpaqueCursor::new(URL_SAFE_NO_PAD.encode(bad_tag))?;

        assert_eq!(
            codec.decode(&unsupported),
            Err(CursorDecodeError::InvalidCursor)
        );
        assert_eq!(
            codec.decode(&bad_tag),
            Err(CursorDecodeError::InvalidCursor)
        );
        Ok(())
    }

    #[test]
    fn malformed_and_oversized_values_share_decode_error() -> Result<(), OpaqueCursorError> {
        let codec = codec();
        let malformed = OpaqueCursor::new("not+base64".to_owned())?;
        let oversized = OpaqueCursor("x".repeat(MAX_ENCODED_CURSOR_BYTES + 1));

        assert_eq!(
            codec.decode(&malformed),
            Err(CursorDecodeError::InvalidCursor)
        );
        assert_eq!(
            codec.decode(&oversized),
            Err(CursorDecodeError::InvalidCursor)
        );
        Ok(())
    }

    #[test]
    fn payload_and_cursor_bounds_are_enforced() -> Result<(), Box<dyn Error>> {
        let codec = codec();
        let cursor = codec.encode(&[0; MAX_CURSOR_PAYLOAD_BYTES])?;

        assert!(cursor.0.len() <= MAX_ENCODED_CURSOR_BYTES);
        assert_eq!(
            codec.encode(&[0; MAX_CURSOR_PAYLOAD_BYTES + 1]),
            Err(CursorEncodeError::PayloadTooLarge)
        );
        assert_eq!(
            OpaqueCursor::new("x".repeat(MAX_ENCODED_CURSOR_BYTES + 1)),
            Err(OpaqueCursorError::TooLong)
        );
        Ok(())
    }

    #[test]
    fn page_limits_validate_without_clamping() {
        assert_eq!(PageLimit::new(0), Err(PageLimitError::OutOfRange));
        assert_eq!(PageLimit::new(1).map(PageLimit::get), Ok(1));
        assert_eq!(PageLimit::default().get(), PageLimit::DEFAULT);
        assert_eq!(PageLimit::new(100).map(PageLimit::get), Ok(100));
        assert_eq!(PageLimit::new(101), Err(PageLimitError::OutOfRange));
    }

    #[test]
    fn page_limit_deserialization_validates_bounds() {
        let zero = PageLimit::deserialize(U16Deserializer::<ValueError>::new(0));
        let maximum = PageLimit::deserialize(U16Deserializer::<ValueError>::new(100));
        let too_large = PageLimit::deserialize(U16Deserializer::<ValueError>::new(101));

        assert!(zero.is_err());
        assert_eq!(maximum.map(PageLimit::get), Ok(100));
        assert!(too_large.is_err());
    }

    #[test]
    fn page_request_defaults_missing_fields_and_rejects_unknown_fields() -> Result<(), ValueError> {
        let empty = std::iter::empty::<(&str, &str)>();
        let request = PageRequest::deserialize(MapDeserializer::<_, ValueError>::new(empty))?;
        let unknown = PageRequest::deserialize(MapDeserializer::<_, ValueError>::new(
            [("unexpected", "value")].into_iter(),
        ));

        assert_eq!(request, PageRequest::default());
        assert!(unknown.is_err());
        Ok(())
    }

    #[test]
    fn opaque_cursor_serde_string_round_trips() -> Result<(), Box<dyn Error>> {
        let codec = codec();
        let cursor = codec.encode(b"serde-payload")?;
        let deserialized =
            OpaqueCursor::deserialize(StrDeserializer::<ValueError>::new(&cursor.0))?;

        assert_eq!(deserialized, cursor);
        Ok(())
    }

    #[test]
    fn secrets_and_cursor_bytes_are_redacted_from_formatting() -> Result<(), Box<dyn Error>> {
        let key = CursorSigningKey::new([0x5a; CursorSigningKey::BYTE_LENGTH]);
        let codec = CursorCodec::new(key.clone());
        let cursor = codec.encode(b"private-payload")?;
        let encoded = cursor.0.clone();
        let formatted = format!(
            "{key:?} {key} {codec:?} {cursor:?} {cursor} {}",
            CursorDecodeError::InvalidCursor,
        );

        assert!(!formatted.contains("private-payload"));
        assert!(!formatted.contains(&encoded));
        assert!(!formatted.contains("5a5a5a5a"));
        Ok(())
    }
}

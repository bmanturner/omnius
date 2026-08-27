use std::{fmt, str::FromStr};

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use object_store::path::Path;
use omnius_auth_core::TenantId;
use uuid::{Uuid, Variant, Version};

use crate::BlobStoreError;

const PROVIDER_ROOT: &str = "omnius/objects/v1";
const CURSOR_PREFIX: &[u8] = b"omnius-list-v1:";
const UUID_TEXT_BYTES: usize = 36;

/// Opaque server-generated object identifier.
///
/// The accepted representation is a canonical lowercase RFC-compatible `UUIDv7`. It cannot
/// contain path separators, relative segments, or control characters.
#[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ObjectKey(String);

impl ObjectKey {
    /// Generates a new time-ordered, server-owned object key.
    #[must_use]
    pub fn new() -> Self {
        Self(Uuid::now_v7().hyphenated().to_string())
    }

    /// Validates and restores a canonical `UUIDv7` object key.
    ///
    /// # Errors
    ///
    /// Returns [`BlobStoreError::Invalid`] for non-canonical `UUIDv7` input, including path-like,
    /// control-containing, dot-segment, uppercase, or overlength values.
    pub fn parse(value: impl Into<String>) -> Result<Self, BlobStoreError> {
        let value = value.into();
        if value.len() != UUID_TEXT_BYTES
            || value.bytes().any(|byte| {
                byte.is_ascii_control() || byte == b'/' || byte == b'\\' || byte == b'.'
            })
        {
            return Err(BlobStoreError::Invalid);
        }
        let uuid = Uuid::parse_str(&value).map_err(|_| BlobStoreError::Invalid)?;
        if uuid.get_version() != Some(Version::SortRand)
            || uuid.get_variant() != Variant::RFC4122
            || uuid.hyphenated().to_string() != value
        {
            return Err(BlobStoreError::Invalid);
        }
        Ok(Self(value))
    }

    /// Returns the canonical opaque identifier for persistence or API serialization.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Default for ObjectKey {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for ObjectKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ObjectKey(REDACTED)")
    }
}

impl fmt::Display for ObjectKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl FromStr for ObjectKey {
    type Err = BlobStoreError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::parse(value)
    }
}

/// Opaque provider-neutral continuation token for a bounded tenant list page.
#[derive(Clone, Eq, PartialEq)]
pub struct ListCursor(String);

impl ListCursor {
    /// Parses and validates an adapter-issued list cursor.
    ///
    /// # Errors
    ///
    /// Returns [`BlobStoreError::Invalid`] if the cursor is malformed, oversized, or does not
    /// contain one canonical [`ObjectKey`].
    pub fn parse(value: impl Into<String>) -> Result<Self, BlobStoreError> {
        let value = value.into();
        if value.len() > 128 || value.is_empty() {
            return Err(BlobStoreError::Invalid);
        }
        decode_cursor(&value)?;
        Ok(Self(value))
    }

    /// Returns the opaque token for transport to the next list request.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub(crate) fn from_key(key: &ObjectKey) -> Self {
        let mut bytes = Vec::with_capacity(CURSOR_PREFIX.len() + UUID_TEXT_BYTES);
        bytes.extend_from_slice(CURSOR_PREFIX);
        bytes.extend_from_slice(key.as_str().as_bytes());
        Self(URL_SAFE_NO_PAD.encode(bytes))
    }

    pub(crate) fn key(&self) -> Result<ObjectKey, BlobStoreError> {
        decode_cursor(&self.0)
    }
}

impl fmt::Debug for ListCursor {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ListCursor(REDACTED)")
    }
}

impl FromStr for ListCursor {
    type Err = BlobStoreError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::parse(value)
    }
}

fn decode_cursor(value: &str) -> Result<ObjectKey, BlobStoreError> {
    let bytes = URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|_| BlobStoreError::Invalid)?;
    let encoded_key = bytes
        .strip_prefix(CURSOR_PREFIX)
        .ok_or(BlobStoreError::Invalid)?;
    let key = std::str::from_utf8(encoded_key).map_err(|_| BlobStoreError::Invalid)?;
    ObjectKey::parse(key)
}

pub(crate) fn namespace_path(tenant_id: TenantId) -> Path {
    Path::from(format!("{PROVIDER_ROOT}/{tenant_id}"))
}

pub(crate) fn object_path(tenant_id: TenantId, key: &ObjectKey) -> Path {
    namespace_path(tenant_id).join(key.as_str())
}

pub(crate) fn key_from_location(
    tenant_id: TenantId,
    location: &Path,
) -> Result<ObjectKey, BlobStoreError> {
    let prefix = format!("{}/", namespace_path(tenant_id));
    let value = location
        .as_ref()
        .strip_prefix(&prefix)
        .ok_or(BlobStoreError::Invalid)?;
    ObjectKey::parse(value)
}

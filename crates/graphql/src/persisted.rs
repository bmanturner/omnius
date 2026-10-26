use std::collections::BTreeMap;

use async_graphql::{Request, Value};
use serde::Deserialize;
use sha2::{Digest as _, Sha256};
use thiserror::Error;

use crate::RequestRejection;
/// Largest number of persisted operations in one allowlist.
pub const MAX_PERSISTED_OPERATIONS: usize = 10_000;
/// Largest UTF-8 query text accepted in one persisted operation.
pub const MAX_PERSISTED_OPERATION_BYTES: usize = 64 * 1024;

/// A validated SHA-256 persisted-operation allowlist.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(transparent)]
pub struct PersistedOperationAllowlist(BTreeMap<String, String>);

impl PersistedOperationAllowlist {
    /// Builds an allowlist and calculates the lowercase SHA-256 identifier for each operation.
    ///
    /// # Errors
    ///
    /// Returns [`PersistedOperationError`] for an empty or excessive allowlist, an empty query,
    /// an excessive query, or a SHA-256 collision between distinct query texts.
    pub fn new<I, S>(operations: I) -> Result<Self, PersistedOperationError>
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        let mut entries = BTreeMap::new();
        for (index, operation) in operations.into_iter().enumerate() {
            if index >= MAX_PERSISTED_OPERATIONS {
                return Err(PersistedOperationError::TooManyOperations);
            }
            let operation = operation.into();
            validate_operation_text(&operation)?;
            let hash = operation_hash(&operation);
            if let Some(previous) = entries.insert(hash, operation.clone())
                && previous != operation
            {
                return Err(PersistedOperationError::HashCollision);
            }
        }
        let allowlist = Self(entries);
        allowlist.validate()?;
        Ok(allowlist)
    }

    /// Returns the operation registered for `sha256_hash`.
    #[must_use]
    pub fn get(&self, sha256_hash: &str) -> Option<&str> {
        self.0.get(sha256_hash).map(String::as_str)
    }

    /// Returns the number of allowlisted operations.
    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Returns whether the allowlist contains no operations.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    fn validate(&self) -> Result<(), PersistedOperationError> {
        if self.0.is_empty() {
            return Err(PersistedOperationError::EmptyAllowlist);
        }
        if self.0.len() > MAX_PERSISTED_OPERATIONS {
            return Err(PersistedOperationError::TooManyOperations);
        }
        for (hash, operation) in &self.0 {
            validate_operation_text(operation)?;
            if !valid_sha256_hash(hash) {
                return Err(PersistedOperationError::InvalidHash);
            }
            if operation_hash(operation) != *hash {
                return Err(PersistedOperationError::HashMismatch);
            }
        }
        Ok(())
    }
}

/// Optional persisted-operation enforcement.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case", tag = "mode", content = "operations")]
pub enum PersistedOperationPolicy {
    /// Accept bounded ad hoc `GraphQL` documents.
    #[default]
    Disabled,
    /// Require a known SHA-256 operation identifier.
    Allowlist(PersistedOperationAllowlist),
}

impl PersistedOperationPolicy {
    /// Creates an allowlist policy from canonical operation texts.
    ///
    /// # Errors
    ///
    /// Returns [`PersistedOperationError`] when the allowlist is invalid.
    pub fn allowlist<I, S>(operations: I) -> Result<Self, PersistedOperationError>
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        PersistedOperationAllowlist::new(operations).map(Self::Allowlist)
    }

    pub(crate) fn validate(&self) -> Result<(), PersistedOperationError> {
        match self {
            Self::Disabled => Ok(()),
            Self::Allowlist(allowlist) => allowlist.validate(),
        }
    }

    pub(crate) fn resolve(&self, request: &mut Request) -> Result<(), RequestRejection> {
        match self {
            Self::Disabled => {
                if request.query.trim().is_empty() {
                    Err(RequestRejection::InvalidRequest)
                } else {
                    Ok(())
                }
            }
            Self::Allowlist(allowlist) => {
                let hash = persisted_operation_hash(request)?
                    .ok_or(RequestRejection::PersistedOperationRequired)?;
                let operation = allowlist
                    .get(&hash)
                    .ok_or(RequestRejection::PersistedOperationNotAllowed)?;
                if !request.query.is_empty() && request.query != operation {
                    return Err(RequestRejection::PersistedOperationNotAllowed);
                }
                operation.clone_into(&mut request.query);
                Ok(())
            }
        }
    }
}

/// Failure to construct a persisted-operation allowlist.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum PersistedOperationError {
    /// The allowlist had no operations.
    #[error("persisted-operation allowlist must not be empty")]
    EmptyAllowlist,
    /// The allowlist exceeded its fixed operation bound.
    #[error("persisted-operation allowlist exceeds its operation limit")]
    TooManyOperations,
    /// An operation had no query text.
    #[error("persisted operation must not be empty")]
    EmptyOperation,
    /// An operation exceeded its fixed byte bound.
    #[error("persisted operation exceeds its byte limit")]
    OperationTooLong,
    /// A configured operation identifier was not lowercase SHA-256 hexadecimal.
    #[error("persisted-operation identifier is invalid")]
    InvalidHash,
    /// A configured identifier did not match its operation text.
    #[error("persisted-operation identifier does not match its operation")]
    HashMismatch,
    /// Distinct operation texts produced the same identifier.
    #[error("persisted-operation identifier collision")]
    HashCollision,
}

/// Calculates the lowercase SHA-256 identifier used by persisted operations.
#[must_use]
pub fn operation_hash(operation: &str) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let digest = Sha256::digest(operation.as_bytes());
    let mut encoded = String::with_capacity(64);
    for byte in digest {
        encoded.push(char::from(HEX[usize::from(byte >> 4)]));
        encoded.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    encoded
}
fn persisted_operation_hash(request: &Request) -> Result<Option<String>, RequestRejection> {
    let Some(value) = request.extensions.get("persistedQuery") else {
        return Ok(None);
    };
    let Value::Object(fields) = value else {
        return Err(RequestRejection::PersistedOperationNotAllowed);
    };
    let valid_version = matches!(
        fields.get("version"),
        Some(Value::Number(version)) if version.as_u64() == Some(1)
    );
    let Some(Value::String(hash)) = fields.get("sha256Hash") else {
        return Err(RequestRejection::PersistedOperationNotAllowed);
    };
    if !valid_version || !valid_sha256_hash(hash) {
        return Err(RequestRejection::PersistedOperationNotAllowed);
    }
    Ok(Some(hash.clone()))
}

fn validate_operation_text(operation: &str) -> Result<(), PersistedOperationError> {
    if operation.trim().is_empty() {
        return Err(PersistedOperationError::EmptyOperation);
    }
    if operation.len() > MAX_PERSISTED_OPERATION_BYTES {
        return Err(PersistedOperationError::OperationTooLong);
    }
    Ok(())
}

fn valid_sha256_hash(hash: &str) -> bool {
    hash.len() == 64
        && hash
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

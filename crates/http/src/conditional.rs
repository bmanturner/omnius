use std::fmt;

use axum::http::HeaderValue;
use thiserror::Error;

/// Strong entity tag derived from a positive persisted resource revision.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct VersionEtag(u64);

impl VersionEtag {
    /// Creates a strong tag for a positive persisted revision.
    ///
    /// # Errors
    ///
    /// Returns [`ConditionalHeaderError::InvalidVersion`] for revision zero.
    pub const fn new(version: u64) -> Result<Self, ConditionalHeaderError> {
        if version == 0 {
            Err(ConditionalHeaderError::InvalidVersion)
        } else {
            Ok(Self(version))
        }
    }

    /// Returns the represented resource revision.
    #[must_use]
    pub const fn version(self) -> u64 {
        self.0
    }

    /// Encodes the canonical strong `ETag` header value (`"v<revision>"`).
    ///
    /// # Errors
    ///
    /// Returns [`ConditionalHeaderError::InvalidHeader`] if the generated
    /// header cannot be represented, which indicates an internal invariant
    /// violation.
    pub fn to_header_value(self) -> Result<HeaderValue, ConditionalHeaderError> {
        HeaderValue::from_str(&self.to_string()).map_err(|_| ConditionalHeaderError::InvalidHeader)
    }

    /// Parses one canonical strong entity tag.
    ///
    /// Weak tags, lists, wildcard tags, zero, and non-canonical revisions are
    /// rejected so callers cannot accidentally weaken an update precondition.
    ///
    /// # Errors
    ///
    /// Returns [`ConditionalHeaderError`] when the header is not a canonical
    /// `"v<positive integer>"` tag.
    pub fn from_header_value(value: &HeaderValue) -> Result<Self, ConditionalHeaderError> {
        let value = value
            .to_str()
            .map_err(|_| ConditionalHeaderError::InvalidHeader)?;
        parse_version_tag(value)
    }
}

impl fmt::Display for VersionEtag {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "\"v{}\"", self.0)
    }
}

/// Parsed `If-Match` precondition for one versioned resource.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IfMatch {
    /// Match any existing representation.
    Any,
    /// Match one exact strong resource revision.
    Exact(VersionEtag),
}

impl IfMatch {
    /// Parses `*` or one canonical strong version tag.
    ///
    /// Multiple tags are intentionally rejected: mutation handlers in this kit
    /// operate on one current persisted revision, not a cache validator set.
    ///
    /// # Errors
    ///
    /// Returns [`ConditionalHeaderError::InvalidHeader`] for malformed, weak,
    /// or multi-value preconditions.
    pub fn from_header_value(value: &HeaderValue) -> Result<Self, ConditionalHeaderError> {
        let value = value
            .to_str()
            .map_err(|_| ConditionalHeaderError::InvalidHeader)?
            .trim();
        if value == "*" {
            return Ok(Self::Any);
        }
        parse_version_tag(value).map(Self::Exact)
    }

    /// Reports whether this precondition accepts an existing revision.
    #[must_use]
    pub const fn matches(self, version: u64) -> bool {
        match self {
            Self::Any => true,
            Self::Exact(tag) => tag.version() == version,
        }
    }
}

/// Invalid version `ETag` or conditional request header.
#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum ConditionalHeaderError {
    /// Persisted revisions start at one.
    #[error("resource version must be positive")]
    InvalidVersion,
    /// The conditional header was malformed or unsupported.
    #[error("conditional request header is invalid")]
    InvalidHeader,
}

fn parse_version_tag(value: &str) -> Result<VersionEtag, ConditionalHeaderError> {
    let digits = value
        .strip_prefix("\"v")
        .and_then(|value| value.strip_suffix('"'))
        .ok_or(ConditionalHeaderError::InvalidHeader)?;
    if digits.is_empty()
        || (digits.len() > 1 && digits.starts_with('0'))
        || !digits.bytes().all(|byte| byte.is_ascii_digit())
    {
        return Err(ConditionalHeaderError::InvalidHeader);
    }
    let version = digits
        .parse::<u64>()
        .map_err(|_| ConditionalHeaderError::InvalidHeader)?;
    VersionEtag::new(version).map_err(|_| ConditionalHeaderError::InvalidHeader)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strong_version_tag_round_trips() -> Result<(), ConditionalHeaderError> {
        let tag = VersionEtag::new(42)?;
        let header = tag.to_header_value()?;
        assert_eq!(header, "\"v42\"");
        assert_eq!(VersionEtag::from_header_value(&header)?, tag);
        assert_eq!(IfMatch::from_header_value(&header)?, IfMatch::Exact(tag));
        assert!(IfMatch::Exact(tag).matches(42));
        assert!(!IfMatch::Exact(tag).matches(41));
        Ok(())
    }

    #[test]
    fn wildcard_is_explicit_and_weak_or_noncanonical_tags_fail() {
        assert_eq!(
            IfMatch::from_header_value(&HeaderValue::from_static("*")),
            Ok(IfMatch::Any)
        );
        for invalid in ["W/\"v1\"", "\"v0\"", "\"v01\"", "\"v1\", \"v2\""] {
            assert_eq!(
                IfMatch::from_header_value(&HeaderValue::from_static(invalid)),
                Err(ConditionalHeaderError::InvalidHeader)
            );
        }
    }
}

use std::cmp::Ordering;
use std::fmt;
use std::str::FromStr;

use thiserror::Error;
use unic_langid::LanguageIdentifier;

const MAX_LOCALE_BYTES: usize = 63;

/// A validated, canonicalized, Fluent-compatible BCP 47 language tag.
///
/// Fluent consumes Unicode language identifiers, so extensions, private-use-only tags, underscores,
/// whitespace, and path-like input are rejected. Catalog configuration is the allow-list of locales
/// that can be selected at runtime.
#[derive(Clone, Eq, Hash, PartialEq)]
pub struct Locale {
    canonical: Box<str>,
    language_id: LanguageIdentifier,
}

impl Locale {
    /// Parses a strict Fluent-compatible BCP 47 language tag.
    ///
    /// The returned value uses canonical BCP 47 casing. The parser never includes the rejected input
    /// in its error.
    ///
    /// # Errors
    ///
    /// Returns [`LocaleError`] when the tag is empty, oversized, path-like, malformed, or outside
    /// the Unicode language identifier subset supported by Fluent.
    pub fn parse(value: &str) -> Result<Self, LocaleError> {
        if value.is_empty()
            || value.len() > MAX_LOCALE_BYTES
            || value.starts_with('-')
            || value.ends_with('-')
            || value.contains("--")
            || !value
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        {
            return Err(LocaleError);
        }

        let language_id = value
            .parse::<LanguageIdentifier>()
            .map_err(|_| LocaleError)?;
        let canonical = language_id.to_string().into_boxed_str();
        Ok(Self {
            canonical,
            language_id,
        })
    }

    /// Returns the canonical BCP 47 representation.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.canonical
    }

    pub(crate) fn language_id(&self) -> &LanguageIdentifier {
        &self.language_id
    }

    pub(crate) fn language(&self) -> &str {
        self.language_id.language.as_str()
    }
}

impl FromStr for Locale {
    type Err = LocaleError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::parse(value)
    }
}

impl fmt::Display for Locale {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl fmt::Debug for Locale {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("Locale")
            .field(&self.as_str())
            .finish()
    }
}

impl Ord for Locale {
    fn cmp(&self, other: &Self) -> Ordering {
        self.canonical.cmp(&other.canonical)
    }
}

impl PartialOrd for Locale {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

/// A redacted locale parsing error.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[error("invalid locale")]
pub struct LocaleError;

/// A redacted locale negotiation error.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[error("too many requested locales")]
pub struct NegotiationError;

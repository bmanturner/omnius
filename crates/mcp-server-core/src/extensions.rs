//! Explicit, request-scoped MCP extension negotiation.

use std::{collections::BTreeSet, fmt};

use thiserror::Error;

use crate::{MAX_EXTENSIONS, MAX_METADATA_IDENTIFIER_BYTES};

/// A bounded exact MCP extension identifier.
#[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct McpExtensionId(String);

impl McpExtensionId {
    /// Validates and owns one extension identifier.
    ///
    /// # Errors
    ///
    /// Returns a redacted error for an empty, oversized, whitespace-containing,
    /// control-containing, or prohibited deprecated-surface identifier.
    pub fn new(value: impl Into<String>) -> Result<Self, McpExtensionError> {
        let value = value.into();
        if !crate::metadata::is_bounded_graphic(&value, MAX_METADATA_IDENTIFIER_BYTES)
            || is_deprecated_surface(&value)
        {
            return Err(McpExtensionError);
        }
        Ok(Self(value))
    }

    /// Borrows the exact extension identifier.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for McpExtensionId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("McpExtensionId([redacted])")
    }
}

/// The immutable set of extensions implemented by one server profile.
#[derive(Clone, Default, Eq, PartialEq)]
pub struct McpExtensionCatalog(BTreeSet<McpExtensionId>);

impl McpExtensionCatalog {
    /// Creates an explicitly empty baseline catalog.
    #[must_use]
    pub const fn empty() -> Self {
        Self(BTreeSet::new())
    }

    /// Creates a bounded, duplicate-free extension catalog.
    ///
    /// # Errors
    ///
    /// Returns a redacted error for invalid identifiers, duplicates, or excessive cardinality.
    pub fn new(
        extensions: impl IntoIterator<Item = McpExtensionId>,
    ) -> Result<Self, McpExtensionError> {
        let mut exact = BTreeSet::new();
        for extension in extensions {
            if !exact.insert(extension) || exact.len() > MAX_EXTENSIONS {
                return Err(McpExtensionError);
            }
        }
        Ok(Self(exact))
    }

    /// Borrows supported extension identifiers in deterministic order.
    #[must_use]
    pub const fn extensions(&self) -> &BTreeSet<McpExtensionId> {
        &self.0
    }

    /// Negotiates the exact intersection of server support and extensions requested by a client.
    #[must_use]
    pub fn negotiate(&self, requested: &BTreeSet<String>) -> McpNegotiatedExtensions {
        McpNegotiatedExtensions(
            self.0
                .iter()
                .filter(|extension| requested.contains(extension.as_str()))
                .cloned()
                .collect(),
        )
    }
}

impl fmt::Debug for McpExtensionCatalog {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("McpExtensionCatalog([redacted])")
    }
}

/// Extensions activated for one request after exact client/server negotiation.
#[derive(Clone, Default, Eq, PartialEq)]
pub struct McpNegotiatedExtensions(BTreeSet<McpExtensionId>);

impl McpNegotiatedExtensions {
    /// Borrows activated extension identifiers in deterministic order.
    #[must_use]
    pub const fn extensions(&self) -> &BTreeSet<McpExtensionId> {
        &self.0
    }

    /// Returns whether an exact extension identifier was activated.
    #[must_use]
    pub fn contains(&self, extension: &McpExtensionId) -> bool {
        self.0.contains(extension)
    }
}

impl fmt::Debug for McpNegotiatedExtensions {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("McpNegotiatedExtensions([redacted])")
    }
}

/// Redacted extension catalog or identifier validation failure.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[error("MCP extension declaration is invalid")]
pub struct McpExtensionError;

fn is_deprecated_surface(value: &str) -> bool {
    matches!(
        value,
        "roots"
            | "sampling"
            | "logging"
            | "http-sse"
            | "http+sse"
            | "io.modelcontextprotocol/roots"
            | "io.modelcontextprotocol/sampling"
            | "io.modelcontextprotocol/logging"
            | "io.modelcontextprotocol/http-sse"
            | "io.modelcontextprotocol/http+sse"
    )
}

//! Exact request-scoped MCP extension negotiation.

use std::{collections::BTreeSet, fmt};

use serde::Serialize;
use thiserror::Error;

use crate::{MAX_EXTENSIONS, MAX_METADATA_IDENTIFIER_BYTES};

/// Maximum bytes in one exact extension revision.
pub const MAX_EXTENSION_REVISION_BYTES: usize = 64;
/// Canonical property carrying an extension's exact revision on the MCP wire.
pub const MCP_EXTENSION_REVISION_KEY: &str = "revision";

/// A bounded exact MCP extension identifier.
#[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
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

/// A bounded exact MCP extension revision.
#[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct McpExtensionRevision(String);

impl McpExtensionRevision {
    /// Validates and owns one extension revision.
    ///
    /// # Errors
    ///
    /// Returns a redacted error for an empty, oversized, whitespace-containing, or
    /// control-containing revision.
    pub fn new(value: impl Into<String>) -> Result<Self, McpExtensionError> {
        let value = value.into();
        if !crate::metadata::is_bounded_graphic(&value, MAX_EXTENSION_REVISION_BYTES) {
            return Err(McpExtensionError);
        }
        Ok(Self(value))
    }

    /// Borrows the exact extension revision.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for McpExtensionRevision {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("McpExtensionRevision([redacted])")
    }
}

/// One exact extension identifier and revision unit.
#[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
pub struct McpExtension {
    id: McpExtensionId,
    revision: McpExtensionRevision,
}

impl McpExtension {
    /// Creates one exact extension unit from validated components.
    #[must_use]
    pub const fn new(id: McpExtensionId, revision: McpExtensionRevision) -> Self {
        Self { id, revision }
    }

    /// Borrows the exact identifier.
    #[must_use]
    pub const fn id(&self) -> &McpExtensionId {
        &self.id
    }

    /// Borrows the exact revision.
    #[must_use]
    pub const fn revision(&self) -> &McpExtensionRevision {
        &self.revision
    }
}

impl fmt::Debug for McpExtension {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("McpExtension([redacted])")
    }
}

/// The immutable set of exact extensions implemented by one server profile.
#[derive(Clone, Default, Eq, PartialEq)]
pub struct McpExtensionCatalog(BTreeSet<McpExtension>);

impl McpExtensionCatalog {
    /// Creates an explicitly empty baseline catalog.
    #[must_use]
    pub const fn empty() -> Self {
        Self(BTreeSet::new())
    }

    /// Creates a bounded extension catalog with one revision per identifier.
    ///
    /// # Errors
    ///
    /// Returns a redacted error for duplicate exact units, conflicting revisions, or excessive
    /// cardinality.
    pub fn new(
        extensions: impl IntoIterator<Item = McpExtension>,
    ) -> Result<Self, McpExtensionError> {
        let mut exact = BTreeSet::new();
        let mut identifiers = BTreeSet::new();
        for extension in extensions {
            if !identifiers.insert(extension.id.clone())
                || !exact.insert(extension)
                || exact.len() > MAX_EXTENSIONS
            {
                return Err(McpExtensionError);
            }
        }
        Ok(Self(exact))
    }

    /// Borrows supported exact extension units in deterministic order.
    #[must_use]
    pub const fn extensions(&self) -> &BTreeSet<McpExtension> {
        &self.0
    }

    /// Negotiates the exact identifier-and-revision intersection of server and client support.
    #[must_use]
    pub fn negotiate(&self, requested: &BTreeSet<McpExtension>) -> McpNegotiatedExtensions {
        McpNegotiatedExtensions(self.0.intersection(requested).cloned().collect())
    }
}

impl fmt::Debug for McpExtensionCatalog {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("McpExtensionCatalog([redacted])")
    }
}

/// Exact extensions activated for one request after client/server negotiation.
#[derive(Clone, Default, Eq, PartialEq)]
pub struct McpNegotiatedExtensions(BTreeSet<McpExtension>);

impl McpNegotiatedExtensions {
    /// Borrows activated exact extension units in deterministic order.
    #[must_use]
    pub const fn extensions(&self) -> &BTreeSet<McpExtension> {
        &self.0
    }

    /// Returns whether an exact extension identifier and revision was activated.
    #[must_use]
    pub fn contains(&self, extension: &McpExtension) -> bool {
        self.0.contains(extension)
    }
}

impl fmt::Debug for McpNegotiatedExtensions {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("McpNegotiatedExtensions([redacted])")
    }
}

/// Redacted extension catalog, identifier, or revision validation failure.
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

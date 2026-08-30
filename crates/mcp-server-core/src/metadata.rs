//! Validated, SDK-free metadata carried by every stateless MCP request.

use std::{collections::BTreeSet, fmt};

use thiserror::Error;

use crate::MCP_PROTOCOL_REVISION;

/// Maximum bytes in a client implementation name.
pub const MAX_CLIENT_NAME_BYTES: usize = 128;
/// Maximum bytes in a client implementation version.
pub const MAX_CLIENT_VERSION_BYTES: usize = 64;
/// Maximum number of client capability identifiers on one request.
pub const MAX_CLIENT_CAPABILITIES: usize = 64;
/// Maximum number of extension identifiers requested on one request.
pub const MAX_EXTENSIONS: usize = 64;
/// Maximum bytes in one capability or extension identifier.
pub const MAX_METADATA_IDENTIFIER_BYTES: usize = 128;

/// A bounded client implementation identity supplied on one request.
#[derive(Clone, Eq, PartialEq)]
pub struct McpClientIdentity {
    name: String,
    version: String,
}

impl McpClientIdentity {
    /// Creates a bounded printable client identity.
    ///
    /// # Errors
    ///
    /// Returns a redacted error when either component is empty, oversized, or contains
    /// whitespace or control bytes.
    pub fn new(
        name: impl Into<String>,
        version: impl Into<String>,
    ) -> Result<Self, McpMetadataError> {
        let name = name.into();
        let version = version.into();
        if !is_bounded_graphic(&name, MAX_CLIENT_NAME_BYTES)
            || !is_bounded_graphic(&version, MAX_CLIENT_VERSION_BYTES)
        {
            return Err(McpMetadataError::InvalidClientIdentity);
        }
        Ok(Self { name, version })
    }

    /// Borrows the validated implementation name.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Borrows the validated implementation version.
    #[must_use]
    pub fn version(&self) -> &str {
        &self.version
    }
}

impl fmt::Debug for McpClientIdentity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("McpClientIdentity([redacted])")
    }
}

/// Optional client-requested logging threshold carried without activating legacy Logging.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum McpLogLevel {
    /// Debug diagnostics.
    Debug,
    /// Informational diagnostics.
    Info,
    /// Normal but significant diagnostics.
    Notice,
    /// Warning diagnostics.
    Warning,
    /// Error diagnostics.
    Error,
    /// Critical diagnostics.
    Critical,
    /// Action-required diagnostics.
    Alert,
    /// System-unusable diagnostics.
    Emergency,
}

/// Complete protocol metadata for one stateless MCP request.
///
/// Construction validates the fixed protocol baseline and every bounded collection. The type owns
/// its values so no transport or session state is needed after adaptation.
#[derive(Clone, Eq, PartialEq)]
pub struct McpRequestMetadata {
    client: McpClientIdentity,
    client_capabilities: BTreeSet<String>,
    requested_extensions: BTreeSet<String>,
    requested_log_level: Option<McpLogLevel>,
}

impl McpRequestMetadata {
    /// Creates complete metadata for the fixed current MCP protocol revision.
    ///
    /// # Errors
    ///
    /// Returns a redacted error for another revision, duplicates, excessive cardinality, or an
    /// empty, oversized, whitespace-containing, or control-containing identifier.
    pub fn new(
        protocol_revision: impl AsRef<str>,
        client: McpClientIdentity,
        client_capabilities: impl IntoIterator<Item = String>,
        requested_extensions: impl IntoIterator<Item = String>,
        requested_log_level: Option<McpLogLevel>,
    ) -> Result<Self, McpMetadataError> {
        if protocol_revision.as_ref() != MCP_PROTOCOL_REVISION {
            return Err(McpMetadataError::UnsupportedProtocolRevision);
        }
        Ok(Self {
            client,
            client_capabilities: bounded_set(
                client_capabilities,
                MAX_CLIENT_CAPABILITIES,
                McpMetadataError::InvalidClientCapabilities,
            )?,
            requested_extensions: bounded_set(
                requested_extensions,
                MAX_EXTENSIONS,
                McpMetadataError::InvalidRequestedExtensions,
            )?,
            requested_log_level,
        })
    }

    /// Returns the only accepted protocol revision.
    #[must_use]
    pub const fn protocol_revision(&self) -> &'static str {
        MCP_PROTOCOL_REVISION
    }

    /// Borrows the request-scoped client identity.
    #[must_use]
    pub const fn client(&self) -> &McpClientIdentity {
        &self.client
    }

    /// Borrows sorted, exact client capability identifiers.
    #[must_use]
    pub const fn client_capabilities(&self) -> &BTreeSet<String> {
        &self.client_capabilities
    }

    /// Borrows sorted extension identifiers explicitly requested by the client.
    #[must_use]
    pub const fn requested_extensions(&self) -> &BTreeSet<String> {
        &self.requested_extensions
    }

    /// Returns the optional request-scoped logging threshold.
    #[must_use]
    pub const fn requested_log_level(&self) -> Option<McpLogLevel> {
        self.requested_log_level
    }
}

impl fmt::Debug for McpRequestMetadata {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("McpRequestMetadata([redacted])")
    }
}

/// Redacted validation failure for stateless MCP request metadata.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum McpMetadataError {
    /// The request selected a protocol revision other than the fixed baseline.
    #[error("MCP request protocol revision is unsupported")]
    UnsupportedProtocolRevision,
    /// Client identity was missing or malformed.
    #[error("MCP request client identity is invalid")]
    InvalidClientIdentity,
    /// Client capability identifiers were malformed or excessive.
    #[error("MCP request client capabilities are invalid")]
    InvalidClientCapabilities,
    /// Requested extension identifiers were malformed or excessive.
    #[error("MCP request extensions are invalid")]
    InvalidRequestedExtensions,
}

fn bounded_set(
    values: impl IntoIterator<Item = String>,
    maximum_items: usize,
    error: McpMetadataError,
) -> Result<BTreeSet<String>, McpMetadataError> {
    let values = values.into_iter();
    let (minimum, maximum) = values.size_hint();
    if minimum > maximum_items || maximum.is_some_and(|maximum| maximum > maximum_items) {
        return Err(error);
    }

    let mut exact = BTreeSet::new();
    for value in values {
        if !is_bounded_graphic(&value, MAX_METADATA_IDENTIFIER_BYTES)
            || !exact.insert(value)
            || exact.len() > maximum_items
        {
            return Err(error);
        }
    }
    Ok(exact)
}

pub(crate) fn is_bounded_graphic(value: &str, maximum_bytes: usize) -> bool {
    !value.is_empty()
        && value.len() <= maximum_bytes
        && value.as_bytes().iter().all(u8::is_ascii_graphic)
}

use std::collections::BTreeSet;

use omnius_agent_capability_registry::CapabilityKey;
use omnius_authz_basic::Decision;
use omnius_mcp_server_core::McpRequestContext;
use sha2::{Digest, Sha256};
use thiserror::Error;
use url::Url;

use crate::lifecycle::{AppLifecycleKey, AppLifecycleRepository};
use crate::manifest::{
    APP_HTML_MEDIA_TYPE, AdmittedUiManifest, ClientAppSupport, is_sha256_digest,
    validate_client_support,
};

/// Immutable bounded object-storage lookup bound to complete App installation scope.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UiArtifactLocator<'a> {
    /// Exact tenant, principal, server, installation, and resource identity.
    pub lifecycle_key: &'a AppLifecycleKey,
    /// Enabled lifecycle revision that must remain current at the read boundary.
    pub lifecycle_revision: u64,
    /// Immutable resource version.
    pub version: &'a str,
    /// Expected content digest.
    pub digest: &'a str,
    /// Exact registry capability revisions admitted with the asset.
    pub capability_keys: &'a BTreeSet<CapabilityKey>,
    /// Exact signed resource size; the destination buffer has precisely this length.
    pub expected_size: u64,
    /// Absolute allocation ceiling the repository must check before reading the source.
    pub hard_max_size: u64,
}

/// Typed outcome of a bounded exact App artifact read.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum UiArtifactRead {
    /// The exact-size destination was filled with an object of this authoritative media type.
    Complete {
        /// Authoritative media type for the complete object.
        media_type: String,
    },
    /// The source size differed; no partial or truncated object was accepted.
    SizeMismatch,
    /// The enabled lifecycle revision changed before the atomic read boundary.
    StaleLifecycle,
}

/// Object-storage boundary coordinated with the authoritative App lifecycle repository.
pub trait UiArtifactRepository {
    /// Fills an exact-size caller-owned buffer without allocating from untrusted source length.
    ///
    /// The adapter must atomically verify `lifecycle_revision` is still enabled before reading and
    /// reject a source exceeding `hard_max_size` or differing from `expected_size`.
    ///
    /// # Errors
    ///
    /// Returns [`ArtifactRepositoryError`] when authoritative lifecycle verification or the
    /// bounded exact object read cannot be completed.
    fn read_exact(
        &self,
        locator: &UiArtifactLocator<'_>,
        destination: &mut [u8],
    ) -> Result<UiArtifactRead, ArtifactRepositoryError>;
}

/// Redacted object-storage failure.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[error("UI artifact repository operation failed")]
pub struct ArtifactRepositoryError;

/// Bound locator suitable for `_meta.ui.resourceUri` correlation by a trusted adapter.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UiResourceLocator {
    key: AppLifecycleKey,
    uri: Url,
    version: String,
    digest: String,
    capability_keys: BTreeSet<CapabilityKey>,
    lifecycle_revision: u64,
    byte_len: u64,
}

impl UiResourceLocator {
    /// Returns the complete canonical installation scope.
    #[must_use]
    pub const fn key(&self) -> &AppLifecycleKey {
        &self.key
    }

    /// Returns the immutable `ui://` URI.
    #[must_use]
    pub const fn uri(&self) -> &Url {
        &self.uri
    }

    /// Returns the immutable App version.
    #[must_use]
    pub fn version(&self) -> &str {
        &self.version
    }

    /// Returns the immutable content digest.
    #[must_use]
    pub fn digest(&self) -> &str {
        &self.digest
    }

    /// Returns exact capability revisions correlated with this locator.
    #[must_use]
    pub const fn capability_keys(&self) -> &BTreeSet<CapabilityKey> {
        &self.capability_keys
    }
    /// Returns the exact immutable resource byte length.
    #[must_use]
    pub const fn byte_len(&self) -> u64 {
        self.byte_len
    }

    /// Returns the enabled lifecycle revision observed when this locator was issued.
    #[must_use]
    pub const fn lifecycle_revision(&self) -> u64 {
        self.lifecycle_revision
    }
}

/// MCP resource content with no channel for host headers, bearer tokens, or capability handles.
#[derive(Clone, Eq, PartialEq)]
pub struct UiResourceContents {
    /// Complete trusted correlation locator.
    pub locator: UiResourceLocator,
    /// Exact Apps media type.
    pub media_type: String,
    /// Verified UTF-8 HTML.
    pub text: String,
}

impl std::fmt::Debug for UiResourceContents {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("UiResourceContents([redacted])")
    }
}

/// Verifies lifecycle, identity, object type, size, digest, encoding, and leak invariants.
pub struct UiResourceService<R, L> {
    repository: R,
    lifecycle_repository: L,
}

impl<R, L> UiResourceService<R, L>
where
    R: UiArtifactRepository,
    L: AppLifecycleRepository,
{
    /// Creates a resource service backed by object storage and authoritative lifecycle state.
    #[must_use]
    pub const fn new(repository: R, lifecycle_repository: L) -> Self {
        Self {
            repository,
            lifecycle_repository,
        }
    }

    /// Reads a freshly loaded, enabled, immutable App resource in the exact request scope.
    ///
    /// # Errors
    ///
    /// Returns [`ResourceError`] when request scope, client isolation, enabled lifecycle,
    /// repository availability, immutable size/type/digest, UTF-8, or credential-leak checks fail.
    pub fn read(
        &self,
        admitted: &AdmittedUiManifest,
        context: &McpRequestContext,
        server_id: &str,
        installation_id: &str,
        client: &ClientAppSupport,
    ) -> Result<UiResourceContents, ResourceError> {
        validate_client_support(client).map_err(|_| ResourceError::Disabled)?;
        admitted
            .binding()
            .require_request(context, server_id, installation_id)
            .map_err(|_| ResourceError::Disabled)?;
        if context.canonical().invocation().authorization() != Decision::Allow {
            return Err(ResourceError::Disabled);
        }
        let key = AppLifecycleKey::from_admitted(admitted);
        let lifecycle = self
            .lifecycle_repository
            .load(&key)
            .map_err(|_| ResourceError::Unavailable)?
            .ok_or(ResourceError::Disabled)?;
        lifecycle
            .require_enabled(admitted, context, server_id, installation_id)
            .map_err(|_| ResourceError::Disabled)?;
        let manifest = admitted.manifest();
        let metadata = &manifest.resource;
        if !is_sha256_digest(&metadata.digest) {
            return Err(ResourceError::IntegrityMismatch);
        }
        if metadata.byte_len == 0 || metadata.byte_len > crate::manifest::MAX_UI_RESOURCE_BYTES {
            return Err(ResourceError::IntegrityMismatch);
        }
        let exact_size =
            usize::try_from(metadata.byte_len).map_err(|_| ResourceError::IntegrityMismatch)?;
        let mut bytes = vec![0; exact_size];
        let read = self
            .repository
            .read_exact(
                &UiArtifactLocator {
                    lifecycle_key: &key,
                    lifecycle_revision: lifecycle.revision,
                    version: &manifest.version,
                    digest: &metadata.digest,
                    capability_keys: admitted.capability_keys(),
                    expected_size: metadata.byte_len,
                    hard_max_size: crate::manifest::MAX_UI_RESOURCE_BYTES,
                },
                &mut bytes,
            )
            .map_err(|_| ResourceError::Unavailable)?;
        let media_type = match read {
            UiArtifactRead::Complete { media_type } => media_type,
            UiArtifactRead::SizeMismatch => return Err(ResourceError::IntegrityMismatch),
            UiArtifactRead::StaleLifecycle => return Err(ResourceError::Disabled),
        };
        if media_type != APP_HTML_MEDIA_TYPE
            || media_type != metadata.media_type
            || u64::try_from(bytes.len()).ok() != Some(metadata.byte_len)
            || sha256_digest(&bytes) != metadata.digest
        {
            return Err(ResourceError::IntegrityMismatch);
        }
        let text = String::from_utf8(bytes).map_err(|_| ResourceError::InvalidEncoding)?;
        if contains_host_secret_marker(&text) {
            return Err(ResourceError::CredentialLeak);
        }
        Ok(UiResourceContents {
            locator: UiResourceLocator {
                key,
                uri: metadata.uri.clone(),
                version: manifest.version.clone(),
                digest: metadata.digest.clone(),
                capability_keys: admitted.capability_keys().clone(),
                byte_len: metadata.byte_len,
                lifecycle_revision: lifecycle.revision,
            },
            media_type: metadata.media_type.clone(),
            text,
        })
    }
}

/// Fail-closed resource delivery error.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum ResourceError {
    /// The durable artifact repository was unavailable.
    #[error("UI artifact unavailable")]
    Unavailable,
    /// Negotiation, identity, client support, or authoritative lifecycle state denied delivery.
    #[error("UI resource is disabled")]
    Disabled,
    /// Declared and stored size, type, or digest differs.
    #[error("UI artifact integrity mismatch")]
    IntegrityMismatch,
    /// HTML was not valid UTF-8.
    #[error("UI artifact is not valid UTF-8")]
    InvalidEncoding,
    /// HTML contained a host credential or capability marker.
    #[error("UI artifact contains forbidden host credential material")]
    CredentialLeak,
}

/// Returns a lowercase SHA-256 content address.
#[must_use]
pub fn sha256_digest(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";

    let digest = Sha256::digest(bytes);
    let mut encoded = String::with_capacity("sha256:".len() + digest.len() * 2);
    encoded.push_str("sha256:");
    for byte in digest {
        encoded.push(char::from(HEX[usize::from(byte >> 4)]));
        encoded.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    encoded
}

fn contains_host_secret_marker(text: &str) -> bool {
    let lowercase = text.to_ascii_lowercase();
    [
        "authorization: bearer ",
        "mcp-host-capability",
        "x-api-key",
        "document.cookie",
    ]
    .iter()
    .any(|marker| lowercase.contains(marker))
}

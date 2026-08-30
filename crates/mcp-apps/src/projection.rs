use omnius_agent_capability_registry::{
    CapabilityDocument, CapabilityKey, CapabilityRegistry, Exposure,
};
use omnius_authz_basic::Decision;
use omnius_mcp_server_core::McpRequestContext;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use url::Url;

use crate::lifecycle::{AppLifecycleKey, AppLifecycleRepository};
use crate::manifest::{AdmittedUiManifest, ClientAppSupport, validate_client_support};

/// Apps visibility projected into MCP tool metadata.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ToolVisibility {
    /// Tool remains visible to the model and may also be invoked by its App.
    #[default]
    ModelAndApp,
    /// Tool is omitted from model discovery and is callable only through the App host path.
    AppOnly,
}

/// Complete authority-boundary input for one App tool projection.
pub struct AppToolProjectionInput<'a> {
    /// Canonical registry used to resolve the exact capability revision.
    pub registry: &'a CapabilityRegistry,
    /// Previously admitted manifest that declares the capability ceiling.
    pub admitted: &'a AdmittedUiManifest,
    /// Authoritative durable lifecycle reader.
    pub lifecycle_repository: &'a dyn AppLifecycleRepository,
    /// Fresh canonical MCP request context.
    pub context: &'a McpRequestContext,
    /// Bound MCP server identity.
    pub server_id: &'a str,
    /// Bound App installation identity.
    pub installation_id: &'a str,
    /// Client isolation and host-messaging support.
    pub client: &'a ClientAppSupport,
    /// Exact registry capability revision to project.
    pub capability: CapabilityKey,
    /// Requested model-facing visibility.
    pub visibility: ToolVisibility,
}

/// Registry-authoritative tool projection bound to one exact App installation and lifecycle read.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AppToolProjection {
    capability: CapabilityKey,
    lifecycle_key: AppLifecycleKey,
    lifecycle_revision: u64,
    resource_uri: Url,
    visibility: ToolVisibility,
}

impl AppToolProjection {
    /// Binds an exact compiled registry capability to a freshly enabled App resource.
    ///
    /// # Errors
    ///
    /// Returns [`ProjectionError`] when client isolation, identity, authorization, declaration,
    /// registry exposure, or freshly loaded enabled lifecycle state denies projection.
    pub fn bind(input: AppToolProjectionInput<'_>) -> Result<Self, ProjectionError> {
        let AppToolProjectionInput {
            registry,
            admitted,
            lifecycle_repository,
            context,
            server_id,
            installation_id,
            client,
            capability,
            visibility,
        } = input;
        validate_client_support(client).map_err(|_| ProjectionError::Disabled)?;
        admitted
            .binding()
            .require_request(context, server_id, installation_id)
            .map_err(|_| ProjectionError::Disabled)?;
        if context.canonical().invocation().authorization() != Decision::Allow {
            return Err(ProjectionError::Disabled);
        }
        if !admitted.capability_keys().contains(&capability) {
            return Err(ProjectionError::CapabilityDenied);
        }
        require_browser_document(registry, &capability)?;
        let lifecycle_key = AppLifecycleKey::from_admitted(admitted);
        let lifecycle = lifecycle_repository
            .load(&lifecycle_key)
            .map_err(|_| ProjectionError::Disabled)?
            .ok_or(ProjectionError::Disabled)?;
        lifecycle
            .require_enabled(admitted, context, server_id, installation_id)
            .map_err(|_| ProjectionError::Disabled)?;
        Ok(Self {
            capability,
            lifecycle_key,
            lifecycle_revision: lifecycle.revision,
            resource_uri: admitted.manifest().resource.uri.clone(),
            visibility,
        })
    }

    /// Returns the exact registry capability revision; adapters fetch all metadata from registry.
    #[must_use]
    pub const fn capability(&self) -> &CapabilityKey {
        &self.capability
    }

    /// Returns the complete canonical installation and resource scope.
    #[must_use]
    pub const fn lifecycle_key(&self) -> &AppLifecycleKey {
        &self.lifecycle_key
    }

    /// Returns the enabled lifecycle revision observed during projection.
    #[must_use]
    pub const fn lifecycle_revision(&self) -> u64 {
        self.lifecycle_revision
    }

    /// Returns the immutable App resource URI.
    #[must_use]
    pub const fn resource_uri(&self) -> &Url {
        &self.resource_uri
    }

    /// Returns whether the tool belongs in the model-facing `tools/list` projection.
    #[must_use]
    pub const fn model_visible(&self) -> bool {
        matches!(self.visibility, ToolVisibility::ModelAndApp)
    }
}

/// Tool/resource projection failure.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum ProjectionError {
    /// Negotiation, identity, client support, or lifecycle state denied projection.
    #[error("App tool projection is disabled")]
    Disabled,
    /// The key was absent, stale, deprecated, undeclared by the App, or not browser-exposed.
    #[error("App capability projection denied by registry")]
    CapabilityDenied,
}

fn require_browser_document<'a>(
    registry: &'a CapabilityRegistry,
    capability: &CapabilityKey,
) -> Result<&'a CapabilityDocument, ProjectionError> {
    let document = registry
        .document(capability)
        .ok_or(ProjectionError::CapabilityDenied)?;
    if document.deprecated
        || document
            .exposures
            .binary_search(&Exposure::Browser)
            .is_err()
    {
        return Err(ProjectionError::CapabilityDenied);
    }
    Ok(document)
}

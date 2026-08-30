use std::fmt;

use omnius_auth_core::{Principal, TenantId};
use omnius_authz_basic::Decision;
use thiserror::Error;

use crate::McpAuthenticatedIdentity;

/// MCP operation class presented to ordinary application authorization.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum McpOperation {
    /// Enumerate visible resources.
    ListResources,
    /// Read one resource.
    ReadResource,
    /// Enumerate visible prompts.
    ListPrompts,
    /// Resolve one prompt.
    GetPrompt,
    /// Enumerate visible tools.
    ListTools,
    /// Invoke one tool.
    CallTool,
}

/// Visibility facts supplied by the canonical capability registry.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CapabilityVisibility {
    /// The capability is not tenant-private.
    Public,
    /// The capability belongs exclusively to the named tenant.
    TenantPrivate(TenantId),
}

/// Tenant or ordinary policy authorization was denied without enumeration detail.
#[derive(Clone, Copy, Eq, Error, PartialEq)]
#[error("MCP operation was rejected")]
pub struct OperationDenied;

impl fmt::Debug for OperationDenied {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("OperationDenied([REDACTED])")
    }
}

/// Explicit tenant-equality guard for an authenticated MCP identity.
#[derive(Clone, Copy, Debug, Default)]
pub struct TenantGuard;

impl TenantGuard {
    /// Requires any supplied tenant context to equal the principal's active tenant.
    ///
    /// An absent tenant remains absent; this mirrors the canonical invocation
    /// context contract. Tenant-private operations separately require an explicit
    /// equal tenant through [`OperationGuard`].
    ///
    /// # Errors
    ///
    /// Returns the same value-free [`OperationDenied`] used for private-capability
    /// and ordinary-policy denials.
    pub fn authorize(
        self,
        identity: &McpAuthenticatedIdentity,
        requested_tenant: Option<TenantId>,
    ) -> Result<TenantAuthorized<'_>, OperationDenied> {
        if requested_tenant.is_some() && identity.principal().tenant_id != requested_tenant {
            return Err(OperationDenied);
        }
        Ok(TenantAuthorized {
            identity,
            tenant_id: requested_tenant,
        })
    }
}

/// Typed authenticated identity proven equal to the supplied tenant context.
#[derive(Clone, Copy)]
pub struct TenantAuthorized<'a> {
    identity: &'a McpAuthenticatedIdentity,
    tenant_id: Option<TenantId>,
}

impl TenantAuthorized<'_> {
    /// Returns the authenticated identity and its verified OAuth evidence.
    #[must_use]
    pub const fn identity(&self) -> &McpAuthenticatedIdentity {
        self.identity
    }

    /// Returns the canonical authenticated principal.
    #[must_use]
    pub const fn principal(&self) -> &Principal {
        self.identity.principal()
    }

    /// Returns the explicitly established tenant context.
    #[must_use]
    pub const fn tenant_id(&self) -> Option<TenantId> {
        self.tenant_id
    }
}

impl fmt::Debug for TenantAuthorized<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("TenantAuthorized([REDACTED])")
    }
}

/// Exact authenticated and canonical facts presented to ordinary MCP authorization.
pub struct OperationAuthorizationRequest<'a, T: ?Sized> {
    identity: &'a McpAuthenticatedIdentity,
    tenant_id: Option<TenantId>,
    operation: McpOperation,
    target: &'a T,
}

impl<T: ?Sized> OperationAuthorizationRequest<'_, T> {
    /// Returns the authenticated identity and independently verified OAuth evidence.
    #[must_use]
    pub const fn identity(&self) -> &McpAuthenticatedIdentity {
        self.identity
    }

    /// Returns the canonical authenticated principal.
    #[must_use]
    pub const fn principal(&self) -> &Principal {
        self.identity.principal()
    }

    /// Returns the tenant already validated by [`TenantGuard`].
    #[must_use]
    pub const fn tenant_id(&self) -> Option<TenantId> {
        self.tenant_id
    }

    /// Returns the exact MCP operation being authorized.
    #[must_use]
    pub const fn operation(&self) -> McpOperation {
        self.operation
    }

    /// Returns authoritative application target facts chosen by the caller.
    #[must_use]
    pub const fn target(&self) -> &T {
        self.target
    }
}

impl<T: ?Sized> fmt::Debug for OperationAuthorizationRequest<'_, T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("OperationAuthorizationRequest([REDACTED])")
    }
}

/// Ordinary application-policy port for one typed MCP operation target.
///
/// Implementations map the supplied operation, authoritative target, canonical
/// principal, and separately verified OAuth client evidence into the same
/// authorization service used by non-MCP transports. Model and tool claims are
/// intentionally absent.
pub trait McpOperationAuthorizer<T: ?Sized>: Send + Sync {
    /// Returns the fail-closed ordinary authorization decision.
    fn authorize(&self, request: OperationAuthorizationRequest<'_, T>) -> Decision;
}

/// Explicit guard requiring both tenant visibility and ordinary policy authorization.
#[derive(Clone, Copy, Debug, Default)]
pub struct OperationGuard;

impl OperationGuard {
    /// Produces operation evidence only after private visibility and a fresh call
    /// to the ordinary application authorization port both allow access.
    ///
    /// Verified OAuth client evidence is available to ordinary policy but remains
    /// distinct from the canonical principal. Model identities, tool-provided
    /// claims, and catalog existence cannot authorize the operation.
    ///
    /// # Errors
    ///
    /// Returns one indistinguishable [`OperationDenied`] for tenant-private,
    /// missing-capability policy, and all other ordinary authorization failures.
    pub fn authorize<'a, T, A>(
        self,
        tenant: TenantAuthorized<'a>,
        operation: McpOperation,
        visibility: CapabilityVisibility,
        target: &T,
        authorizer: &A,
    ) -> Result<OperationAuthorized<'a>, OperationDenied>
    where
        T: ?Sized,
        A: McpOperationAuthorizer<T> + ?Sized,
    {
        if let CapabilityVisibility::TenantPrivate(owner_tenant) = visibility
            && (tenant.tenant_id != Some(owner_tenant)
                || tenant.identity.principal().tenant_id != Some(owner_tenant))
        {
            return Err(OperationDenied);
        }
        if authorizer.authorize(OperationAuthorizationRequest {
            identity: tenant.identity,
            tenant_id: tenant.tenant_id,
            operation,
            target,
        }) != Decision::Allow
        {
            return Err(OperationDenied);
        }
        Ok(OperationAuthorized {
            identity: tenant.identity,
            tenant_id: tenant.tenant_id,
            operation,
        })
    }
}

/// Evidence that authentication, tenant equality, visibility, and ordinary policy passed.
#[derive(Clone, Copy)]
pub struct OperationAuthorized<'a> {
    identity: &'a McpAuthenticatedIdentity,
    tenant_id: Option<TenantId>,
    operation: McpOperation,
}

impl OperationAuthorized<'_> {
    /// Returns the authenticated identity and independently verified OAuth evidence.
    #[must_use]
    pub const fn identity(&self) -> &McpAuthenticatedIdentity {
        self.identity
    }

    /// Returns the canonical principal safe to place in an invocation context.
    #[must_use]
    pub const fn principal(&self) -> &Principal {
        self.identity.principal()
    }

    /// Returns the validated tenant context.
    #[must_use]
    pub const fn tenant_id(&self) -> Option<TenantId> {
        self.tenant_id
    }

    /// Returns the operation class authorized by ordinary policy.
    #[must_use]
    pub const fn operation(&self) -> McpOperation {
        self.operation
    }
}

impl fmt::Debug for OperationAuthorized<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("OperationAuthorized([REDACTED])")
    }
}

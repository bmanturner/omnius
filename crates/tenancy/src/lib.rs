//! Explicit PostgreSQL tenant isolation for organizations, memberships, and invitations.
//!
//! [`TenancyStore`] applies an `organization_id` predicate to every tenant-owned query and treats
//! suspended, removed, and deleted state as inactive. [`TenantContext`] is created only after an
//! authoritative membership lookup and binds a cloned canonical authentication principal to the
//! resolved tenant. PostgreSQL constraints remain the final authority for direct-SQL invariants,
//! including the requirement that every active organization retain an active owner at commit.

mod config;
mod store;
mod types;

pub use config::{TenancyConfig, TenancyConfigError};
pub use store::{TenancyStore, TenancyStoreError, TenantContext};
pub use types::{
    CreatedOrganization, Invitation, InvitationId, InvitationIdError, InvitationRole,
    InvitationStatus, MAX_ORGANIZATION_NAME_BYTES, Membership, MembershipRole, MembershipStatus,
    Organization, OrganizationName, OrganizationNameError, OrganizationStatus, OwnershipTransfer,
    TenancyStateError,
};

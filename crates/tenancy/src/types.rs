//! Validated organization, membership, and invitation value types.

use std::{fmt, str::FromStr};

use rsk_auth_core::{SubjectId, TenantId};
use serde::{Deserialize, Deserializer, Serialize, de::Error as _};
use thiserror::Error;
use time::{OffsetDateTime, UtcOffset};
use uuid::{Uuid, Variant, Version};

/// Maximum UTF-8 byte length of an organization name.
pub const MAX_ORGANIZATION_NAME_BYTES: usize = 255;

/// A validated organization name.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct OrganizationName(String);

impl OrganizationName {
    /// Validates and owns an organization name.
    ///
    /// Names must be nonblank, free of leading or trailing whitespace and control characters,
    /// and no longer than 255 UTF-8 bytes.
    ///
    /// # Errors
    ///
    /// Returns a value-free classification when `value` violates a name invariant.
    pub fn new(value: impl Into<String>) -> Result<Self, OrganizationNameError> {
        let value = value.into();
        if value.is_empty() || value.trim().is_empty() {
            return Err(OrganizationNameError::Blank);
        }
        if value.trim() != value {
            return Err(OrganizationNameError::NotTrimmed);
        }
        if value.len() > MAX_ORGANIZATION_NAME_BYTES {
            return Err(OrganizationNameError::TooLong);
        }
        if value.chars().any(char::is_control) {
            return Err(OrganizationNameError::ControlCharacter);
        }
        Ok(Self(value))
    }

    /// Returns the validated name.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for OrganizationName {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl FromStr for OrganizationName {
    type Err = OrganizationNameError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::new(value)
    }
}

impl<'de> Deserialize<'de> for OrganizationName {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        Self::new(String::deserialize(deserializer)?).map_err(D::Error::custom)
    }
}

/// Organization-name validation failures.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum OrganizationNameError {
    /// The name was empty or contained only whitespace.
    #[error("organization name must not be blank")]
    Blank,
    /// The name had leading or trailing whitespace.
    #[error("organization name must not have leading or trailing whitespace")]
    NotTrimmed,
    /// The UTF-8 representation exceeded 255 bytes.
    #[error("organization name exceeds 255 bytes")]
    TooLong,
    /// The name contained a control character.
    #[error("organization name contains a control character")]
    ControlCharacter,
}

/// A validated `UUIDv7` invitation identifier.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct InvitationId(Uuid);

impl InvitationId {
    /// Generates a new time-ordered invitation identifier.
    #[must_use]
    pub fn new() -> Self {
        Self(Uuid::now_v7())
    }

    /// Restores an invitation identifier after validating its UUID version and variant.
    ///
    /// # Errors
    ///
    /// Returns [`InvitationIdError`] unless `value` is an RFC-compatible `UUIDv7` value.
    pub fn from_uuid(value: Uuid) -> Result<Self, InvitationIdError> {
        if value.get_version() == Some(Version::SortRand) && value.get_variant() == Variant::RFC4122
        {
            Ok(Self(value))
        } else {
            Err(InvitationIdError)
        }
    }

    /// Returns the underlying UUID.
    #[must_use]
    pub const fn as_uuid(self) -> Uuid {
        self.0
    }
}

impl Default for InvitationId {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for InvitationId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

impl FromStr for InvitationId {
    type Err = InvitationIdError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let uuid = Uuid::parse_str(value).map_err(|_| InvitationIdError)?;
        Self::from_uuid(uuid)
    }
}

impl<'de> Deserialize<'de> for InvitationId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        Self::from_uuid(Uuid::deserialize(deserializer)?).map_err(D::Error::custom)
    }
}

/// An invitation identifier was not an RFC-compatible `UUIDv7` value.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[error("invitation identifier must be a UUIDv7 value")]
pub struct InvitationIdError;

macro_rules! string_enum {
    (
        $(#[$meta:meta])*
        pub enum $name:ident {
            $($(#[$variant_meta:meta])* $variant:ident => $value:literal),+ $(,)?
        }
    ) => {
        $(#[$meta])*
        #[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
        #[serde(rename_all = "snake_case")]
        pub enum $name {
            $($(#[$variant_meta])* $variant),+
        }

        impl $name {
            /// Returns the stable PostgreSQL and wire representation.
            #[must_use]
            pub const fn as_str(self) -> &'static str {
                match self {
                    $(Self::$variant => $value),+
                }
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str(self.as_str())
            }
        }

        impl FromStr for $name {
            type Err = TenancyStateError;

            fn from_str(value: &str) -> Result<Self, Self::Err> {
                match value {
                    $($value => Ok(Self::$variant)),+,
                    _ => Err(TenancyStateError),
                }
            }
        }
    };
}

string_enum! {
    /// Organization lifecycle state.
    pub enum OrganizationStatus {
        /// The organization may be used as an active tenant.
        Active => "active",
        /// Tenant access is suspended and fails closed.
        Suspended => "suspended",
        /// The organization is soft-deleted and cannot be restored by the store.
        Deleted => "deleted",
    }
}

string_enum! {
    /// Authoritative organization membership role.
    pub enum MembershipRole {
        /// May administer the organization and is counted by the active-owner invariant.
        Owner => "owner",
        /// May administer invitations and inspect organization membership.
        Admin => "admin",
        /// Has ordinary organization membership.
        Member => "member",
    }
}

string_enum! {
    /// Organization membership lifecycle state.
    pub enum MembershipStatus {
        /// The grant is authoritative for tenant access.
        Active => "active",
        /// The grant is retained but fails closed.
        Suspended => "suspended",
        /// The grant is logically removed and fails closed.
        Removed => "removed",
    }
}

string_enum! {
    /// Role that an invitation may grant.
    ///
    /// Ownership is deliberately absent: ownership changes use an atomic transfer.
    pub enum InvitationRole {
        /// Grants an administrator membership.
        Admin => "admin",
        /// Grants an ordinary membership.
        Member => "member",
    }
}

impl From<InvitationRole> for MembershipRole {
    fn from(role: InvitationRole) -> Self {
        match role {
            InvitationRole::Admin => Self::Admin,
            InvitationRole::Member => Self::Member,
        }
    }
}

string_enum! {
    /// Invitation lifecycle state.
    pub enum InvitationStatus {
        /// The invitation can be accepted before its expiry.
        Pending => "pending",
        /// The invited user accepted the invitation.
        Accepted => "accepted",
        /// An organization administrator revoked the invitation.
        Revoked => "revoked",
        /// Acceptance observed the invitation after its expiry.
        Expired => "expired",
    }
}

/// A persisted tenancy state string was outside the closed state set.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[error("persisted tenancy state is invalid")]
pub struct TenancyStateError;

/// Safe organization lifecycle data.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct Organization {
    /// Canonical tenant and organization identifier.
    pub id: TenantId,
    /// Validated display name.
    pub name: OrganizationName,
    /// Current lifecycle state.
    pub status: OrganizationStatus,
    /// Monotonic organization mutation version.
    pub version: i64,
    /// Creation instant normalized to UTC.
    pub created_at: OffsetDateTime,
    /// Last mutation instant normalized to UTC.
    pub updated_at: OffsetDateTime,
    /// Soft-deletion instant, present exactly when status is deleted.
    pub deleted_at: Option<OffsetDateTime>,
}

/// An authoritative organization membership grant.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct Membership {
    /// Owning organization.
    pub organization_id: TenantId,
    /// Existing user receiving the grant.
    pub user_id: SubjectId,
    /// Authoritative role.
    pub role: MembershipRole,
    /// Grant lifecycle state.
    pub status: MembershipStatus,
    /// Monotonic grant mutation version.
    pub grant_version: i64,
    /// Creation instant normalized to UTC.
    pub created_at: OffsetDateTime,
    /// Last grant mutation instant normalized to UTC.
    pub updated_at: OffsetDateTime,
}

/// An invitation bound to one existing authenticated user.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct Invitation {
    /// Invitation row identifier.
    pub id: InvitationId,
    /// Organization the invitation may join.
    pub organization_id: TenantId,
    /// Existing user allowed to accept the invitation.
    pub invited_user_id: SubjectId,
    /// Existing user that created the invitation.
    pub invited_by_user_id: SubjectId,
    /// Non-owner role granted on acceptance.
    pub role: InvitationRole,
    /// Current invitation lifecycle state.
    pub status: InvitationStatus,
    /// Absolute acceptance deadline normalized to UTC.
    pub expires_at: OffsetDateTime,
    /// Creation instant normalized to UTC.
    pub created_at: OffsetDateTime,
    /// Last mutation instant normalized to UTC.
    pub updated_at: OffsetDateTime,
    /// Acceptance instant, present exactly for accepted invitations.
    pub accepted_at: Option<OffsetDateTime>,
    /// Revocation instant, present exactly for revoked invitations.
    pub revoked_at: Option<OffsetDateTime>,
}

/// Organization and initial owner grant committed by one transaction.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CreatedOrganization {
    /// Newly created active organization.
    pub organization: Organization,
    /// Newly created active owner membership.
    pub owner_membership: Membership,
}
/// Membership grants returned by one committed ownership transfer.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OwnershipTransfer {
    /// Former owner's updated administrator grant.
    pub previous_owner: Membership,
    /// New owner's updated owner grant.
    pub new_owner: Membership,
    /// Organization version after the transfer.
    pub organization_version: i64,
}

pub(crate) fn utc(value: OffsetDateTime) -> OffsetDateTime {
    value.to_offset(UtcOffset::UTC)
}

//! Canonical identity value types shared by authentication mechanisms.
//!
//! Authentication adapters translate mechanism-specific inputs into [`Principal`].
//! Domain and application code can therefore depend on one stable identity contract.

use std::{fmt, str::FromStr};

use serde::{Deserialize, Deserializer, Serialize, Serializer, de::Error as _};
use thiserror::Error;
use time::{OffsetDateTime, UtcOffset};
use uuid::{Uuid, Variant, Version};

const MAX_SCOPE_BYTES: usize = 128;
const MAX_PRINCIPAL_SCOPES: usize = 128;

/// An identity identifier was malformed or was not a `UUIDv7` value.
///
/// The error deliberately carries none of the rejected identifier value.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum IdentityIdError {
    /// The input was not a syntactically valid UUID.
    #[error("identity identifier is not a valid UUID")]
    InvalidUuid,
    /// The UUID was not an RFC-compatible version 7 UUID.
    #[error("identity identifier must be a UUIDv7 value")]
    NotVersion7,
}

macro_rules! uuid_v7_id {
    ($name:ident, $description:literal) => {
        #[doc = $description]
        #[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
        #[serde(transparent)]
        pub struct $name(Uuid);

        impl $name {
            /// Generates a new time-ordered `UUIDv7` identifier.
            #[must_use]
            pub fn new() -> Self {
                Self(Uuid::now_v7())
            }

            /// Restores an identifier from an existing UUID after validating its version.
            ///
            /// # Errors
            ///
            /// Returns [`IdentityIdError::NotVersion7`] unless `value` is an
            /// RFC-compatible version 7 UUID.
            pub fn from_uuid(value: Uuid) -> Result<Self, IdentityIdError> {
                if value.get_version() == Some(Version::SortRand)
                    && value.get_variant() == Variant::RFC4122
                {
                    Ok(Self(value))
                } else {
                    Err(IdentityIdError::NotVersion7)
                }
            }

            /// Returns the underlying UUID value.
            #[must_use]
            pub const fn as_uuid(self) -> Uuid {
                self.0
            }
        }

        impl Default for $name {
            fn default() -> Self {
                Self::new()
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                self.0.fmt(formatter)
            }
        }

        impl FromStr for $name {
            type Err = IdentityIdError;

            fn from_str(value: &str) -> Result<Self, Self::Err> {
                let uuid = Uuid::parse_str(value).map_err(|_| IdentityIdError::InvalidUuid)?;
                Self::from_uuid(uuid)
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: Deserializer<'de>,
            {
                let uuid = Uuid::deserialize(deserializer)?;
                Self::from_uuid(uuid).map_err(D::Error::custom)
            }
        }
    };
}

uuid_v7_id!(
    SubjectId,
    "The canonical identifier of an authenticated subject."
);
uuid_v7_id!(TenantId, "The canonical identifier of a tenant context.");

/// The class of subject represented by a [`Principal`].
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PrincipalKind {
    /// A human user.
    User,
    /// A non-human service account.
    ServiceAccount,
}

/// The mechanism that authenticated a [`Principal`].
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthMethod {
    /// A password authentication exchange.
    Password,
    /// A server-side session.
    Session,
    /// A JSON Web Token.
    Jwt,
    /// An `OpenID Connect` authentication exchange.
    Oidc,
    /// An API key.
    ApiKey,
    /// A `WebAuthn` assertion.
    WebAuthn,
    /// A time-based one-time password.
    Totp,
}

/// The authentication assurance level established for a [`Principal`].
///
/// Ordering follows increasing assurance: `Aal1 < Aal2 < Aal3`.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AssuranceLevel {
    /// Authentication assurance level 1.
    Aal1,
    /// Authentication assurance level 2.
    Aal2,
    /// Authentication assurance level 3.
    Aal3,
}

/// A scope token was empty, too long, or contained a character forbidden by RFC 6749.
///
/// The error deliberately carries none of the rejected scope value.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum ScopeError {
    /// A scope token must contain at least one byte.
    #[error("scope token must not be empty")]
    Empty,
    /// A scope token must not exceed 128 bytes.
    #[error("scope token exceeds 128 bytes")]
    TooLong,
    /// A scope token contained a byte outside the RFC 6749 `scope-token` grammar.
    #[error("scope token contains a forbidden character")]
    InvalidCharacter,
}

/// One bounded RFC 6749 `scope-token`.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Scope(String);

impl Scope {
    /// Validates and owns one scope token.
    ///
    /// Validation accepts only `%x21`, `%x23-5B`, and `%x5D-7E`, and limits the
    /// encoded token to 128 bytes.
    ///
    /// # Errors
    ///
    /// Returns [`ScopeError`] when the token is empty, too long, or contains a
    /// forbidden byte.
    pub fn new(value: impl Into<String>) -> Result<Self, ScopeError> {
        let value = value.into();
        let bytes = value.as_bytes();

        if bytes.is_empty() {
            return Err(ScopeError::Empty);
        }
        if bytes.len() > MAX_SCOPE_BYTES {
            return Err(ScopeError::TooLong);
        }
        if !bytes
            .iter()
            .copied()
            .all(|byte| matches!(byte, b'!' | b'#'..=b'[' | b']'..=b'~'))
        {
            return Err(ScopeError::InvalidCharacter);
        }

        Ok(Self(value))
    }

    /// Returns the scope token as a string slice.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for Scope {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl FromStr for Scope {
    type Err = ScopeError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::new(value)
    }
}

impl Serialize for Scope {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for Scope {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::new(value).map_err(D::Error::custom)
    }
}

/// A principal contained more than 128 distinct scopes.
///
/// The error deliberately carries none of the rejected principal data.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[error("principal exceeds 128 distinct scopes")]
pub struct PrincipalError;

/// The canonical identity produced by every authentication mechanism.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct Principal {
    /// The authenticated subject's canonical identifier.
    pub subject_id: SubjectId,
    /// Whether the subject is a user or service account.
    pub kind: PrincipalKind,
    /// The tenant context established during authentication, when present.
    pub tenant_id: Option<TenantId>,
    /// The mechanism that authenticated the subject.
    pub auth_method: AuthMethod,
    /// The instant at which authentication completed, normalized to UTC.
    pub authenticated_at: OffsetDateTime,
    /// The assurance level established by the authentication mechanism.
    pub assurance: AssuranceLevel,
    /// The sorted, duplicate-free scopes granted to the principal.
    pub scopes: Vec<Scope>,
}

impl Principal {
    /// Creates a canonical principal.
    ///
    /// The authentication time is normalized to UTC. Scopes are sorted and
    /// deduplicated before the 128-scope limit is enforced.
    ///
    /// # Errors
    ///
    /// Returns [`PrincipalError`] when more than 128 distinct scopes remain.
    pub fn new(
        subject_id: SubjectId,
        kind: PrincipalKind,
        tenant_id: Option<TenantId>,
        auth_method: AuthMethod,
        authenticated_at: OffsetDateTime,
        assurance: AssuranceLevel,
        mut scopes: Vec<Scope>,
    ) -> Result<Self, PrincipalError> {
        scopes.sort_unstable();
        scopes.dedup();
        if scopes.len() > MAX_PRINCIPAL_SCOPES {
            return Err(PrincipalError);
        }

        Ok(Self {
            subject_id,
            kind,
            tenant_id,
            auth_method,
            authenticated_at: authenticated_at.to_offset(UtcOffset::UTC),
            assurance,
            scopes,
        })
    }
}

/// Deterministic principal fixtures for adapter and conformance tests.
#[cfg(feature = "test-support")]
pub mod testing;

#[cfg(test)]
mod tests {
    use super::*;

    const SUBJECT_UUID: Uuid = Uuid::from_u128(0x0189_0f2a_0000_7000_8000_0000_0000_0001);
    const TENANT_UUID: Uuid = Uuid::from_u128(0x0189_0f2a_0000_7000_8000_0000_0000_0002);
    const V4_UUID: Uuid = Uuid::from_u128(0x550e_8400_e29b_41d4_a716_4466_5544_0000);

    fn subject_id() -> Result<SubjectId, IdentityIdError> {
        SubjectId::from_uuid(SUBJECT_UUID)
    }

    fn tenant_id() -> Result<TenantId, IdentityIdError> {
        TenantId::from_uuid(TENANT_UUID)
    }

    #[test]
    fn identity_ids_reject_malformed_and_non_v7_values() {
        assert_eq!(
            "not-a-uuid".parse::<SubjectId>(),
            Err(IdentityIdError::InvalidUuid)
        );
        assert_eq!(
            SubjectId::from_uuid(V4_UUID),
            Err(IdentityIdError::NotVersion7)
        );
        assert_eq!(
            TenantId::from_uuid(Uuid::nil()),
            Err(IdentityIdError::NotVersion7)
        );
    }

    #[test]
    fn identity_id_serde_rejects_non_v7_restoration() -> Result<(), Box<dyn std::error::Error>> {
        let encoded = serde_json::to_string(&subject_id()?)?;
        let restored: SubjectId = serde_json::from_str(&encoded)?;
        assert_eq!(restored.as_uuid(), SUBJECT_UUID);

        let non_v7 = format!("\"{V4_UUID}\"");
        assert!(serde_json::from_str::<SubjectId>(&non_v7).is_err());
        Ok(())
    }

    #[test]
    fn scope_enforces_byte_boundaries() -> Result<(), Box<dyn std::error::Error>> {
        assert_eq!(Scope::new(""), Err(ScopeError::Empty));
        assert_eq!(
            Scope::new("a".repeat(MAX_SCOPE_BYTES + 1)),
            Err(ScopeError::TooLong)
        );

        let boundary = Scope::new("a".repeat(MAX_SCOPE_BYTES))?;
        assert_eq!(boundary.as_str().len(), MAX_SCOPE_BYTES);
        Ok(())
    }

    #[test]
    fn scope_accepts_only_rfc6749_scope_token_characters() -> Result<(), Box<dyn std::error::Error>>
    {
        let valid = Scope::new("!#$%&'()*+,-./09:;<=>?@AZ[]^_`az{|}~")?;
        assert_eq!(valid.as_str(), "!#$%&'()*+,-./09:;<=>?@AZ[]^_`az{|}~");

        for invalid in ["contains space", "\"", "\\", "line\nbreak", "café"] {
            assert_eq!(Scope::new(invalid), Err(ScopeError::InvalidCharacter));
        }
        Ok(())
    }

    #[test]
    fn principal_canonicalizes_scopes_and_enforces_distinct_scope_cap()
    -> Result<(), Box<dyn std::error::Error>> {
        let repeated = Scope::new("read")?;
        let principal = Principal::new(
            subject_id()?,
            PrincipalKind::User,
            Some(tenant_id()?),
            AuthMethod::Session,
            OffsetDateTime::UNIX_EPOCH,
            AssuranceLevel::Aal1,
            vec![Scope::new("write")?, repeated.clone(), repeated],
        )?;
        assert_eq!(
            principal.scopes,
            vec![Scope::new("read")?, Scope::new("write")?]
        );

        let too_many = (0..=MAX_PRINCIPAL_SCOPES)
            .map(|index| Scope::new(format!("scope-{index:03}")))
            .collect::<Result<Vec<_>, _>>()?;
        assert_eq!(
            Principal::new(
                subject_id()?,
                PrincipalKind::User,
                None,
                AuthMethod::Jwt,
                OffsetDateTime::UNIX_EPOCH,
                AssuranceLevel::Aal1,
                too_many,
            ),
            Err(PrincipalError)
        );
        Ok(())
    }

    #[test]
    fn principal_normalizes_authentication_time_to_utc() -> Result<(), Box<dyn std::error::Error>> {
        let source = OffsetDateTime::from_unix_timestamp(1_700_000_000)?
            .to_offset(UtcOffset::from_hms(5, 30, 0)?);
        let principal = Principal::new(
            subject_id()?,
            PrincipalKind::User,
            None,
            AuthMethod::Password,
            source,
            AssuranceLevel::Aal1,
            Vec::new(),
        )?;

        assert_eq!(principal.authenticated_at.offset(), UtcOffset::UTC);
        assert_eq!(principal.authenticated_at.unix_timestamp(), 1_700_000_000);
        Ok(())
    }

    #[test]
    fn enums_use_stable_snake_case_serde_and_assurance_ordering()
    -> Result<(), Box<dyn std::error::Error>> {
        assert_eq!(
            serde_json::to_string(&PrincipalKind::ServiceAccount)?,
            "\"service_account\""
        );
        assert_eq!(serde_json::to_string(&AuthMethod::ApiKey)?, "\"api_key\"");
        assert_eq!(
            serde_json::to_string(&AuthMethod::WebAuthn)?,
            "\"web_authn\""
        );
        assert_eq!(serde_json::to_string(&AssuranceLevel::Aal3)?, "\"aal3\"");
        assert!(AssuranceLevel::Aal1 < AssuranceLevel::Aal2);
        assert!(AssuranceLevel::Aal2 < AssuranceLevel::Aal3);
        Ok(())
    }
}

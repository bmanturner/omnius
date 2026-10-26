//! Atomic PostgreSQL persistence for OAuth and `OpenID` Connect protocol state.

use crate::types::{
    ApplicationType, ClientId, GrantId, GrantType, RedirectUri, ResourceUri, ResponseType,
    TokenEndpointAuthMethod,
};
use omnius_auth_core::{AssuranceLevel, AuthMethod, Scope, SubjectId, TenantId};
use omnius_postgres::{PostgresPool, RetryableSqlState, RetryableTransactionError};
use sqlx::Row as _;
use sqlx::postgres::PgRow;
use sqlx::{Postgres, Transaction};
use std::fmt;
use thiserror::Error;
use uuid::{Uuid, Variant, Version};

mod authorization;
mod client;
mod grant;
mod revocation;
mod token;

pub use authorization::{
    AuthorizationDecision, AuthorizationInteractionRequirement, AuthorizationInteractionScope,
    AuthorizationRequestCreate, AuthorizationRequestLoad, AuthorizationRequestRecord,
    AuthorizationRequestStatus, AuthorizationTransition,
};
pub use client::{
    ClientAssertionRecord, ClientAuthentication, ClientDisableOutcome, ClientMetadataCache,
    ClientSource, ClientStatus, ClientUpsert, RegisteredClient,
};
pub use grant::{
    AccessTokenLiveCheck, AuthorizedSubjectState, ConnectedGrant, ConnectedGrantPage, GrantCreate,
    GrantCursor, LiveAccessIdentity, LiveGrant, OAuthSubject, VerifiedEmail,
};
pub use revocation::{AccessRevocationReason, AccessTokenRevocation};
pub use token::{
    AuthorizationCodeBinding, AuthorizationCodeCreate, AuthorizationCodeExchange,
    AuthorizationCodeRejection, ConsumedAuthorizationCode, IssuedRefreshToken, RefreshFamilyIssue,
    RefreshRejection, RefreshRotation, RotatedRefreshToken,
};

const MAX_NONCE_BYTES: usize = 255;
const PUBLIC_SUBJECT_BYTES: usize = 43;
const MAX_RESOURCES: usize = 16;
const MAX_SCOPES: usize = 128;

macro_rules! uuid_v7_id {
    ($name:ident, $doc:literal) => {
        #[doc = $doc]
        #[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
        pub struct $name(Uuid);

        impl $name {
            /// Generates a new `UUIDv7` identifier.
            #[must_use]
            pub fn new() -> Self {
                Self(Uuid::now_v7())
            }

            /// Restores an identifier after validating UUID version and variant.
            ///
            /// # Errors
            ///
            /// Returns [`OAuthStoreError::CorruptData`] when `value` is not a canonical
            /// RFC 9562 version 7 UUID.
            pub fn from_uuid(value: Uuid) -> Result<Self, OAuthStoreError> {
                valid_uuid_v7(value)?;
                Ok(Self(value))
            }

            /// Returns the database UUID.
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
    };
}

uuid_v7_id!(
    OAuthClientRecordId,
    "Internal durable OAuth client row identifier."
);

uuid_v7_id!(
    AuthorizationRequestId,
    "Durable authorization request identifier."
);

uuid_v7_id!(
    OAuthSubjectId,
    "Issuer-local durable subject row identifier."
);

uuid_v7_id!(RefreshFamilyId, "Refresh-token family identifier.");

uuid_v7_id!(RefreshTokenId, "Refresh-token row identifier.");

/// Stable random public subject identifier exposed by this issuer.
#[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct PublicSubject(String);

impl PublicSubject {
    /// Validates a canonical 32-byte unpadded base64url subject value.
    ///
    /// # Errors
    ///
    /// Returns [`OAuthStoreError::InvalidInput`] when `value` is not a canonical
    /// 32-byte unpadded base64url subject.
    pub fn parse(value: impl Into<String>) -> Result<Self, OAuthStoreError> {
        let value = value.into();
        if value.len() != PUBLIC_SUBJECT_BYTES
            || !value
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
        {
            return Err(OAuthStoreError::InvalidInput);
        }
        Ok(Self(value))
    }

    /// Returns the exact public subject.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for PublicSubject {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("PublicSubject([REDACTED])")
    }
}

/// PostgreSQL-backed OAuth protocol store.
#[derive(Clone, Debug)]
pub struct OAuthPostgresStore {
    pool: PostgresPool,
}

impl OAuthPostgresStore {
    /// Creates a store from the shared managed PostgreSQL pool.
    #[must_use]
    pub const fn new(pool: PostgresPool) -> Self {
        Self { pool }
    }

    /// Borrows the shared pool for composition and supervised cleanup.
    #[must_use]
    pub const fn pool(&self) -> &PostgresPool {
        &self.pool
    }
}

/// Stable, value-free OAuth persistence failures.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[non_exhaustive]
pub enum OAuthStoreError {
    /// A caller violated a bounded persistence input contract.
    #[error("OAuth persistence input is invalid")]
    InvalidInput,
    /// A unique or exact-state transition conflicted.
    #[error("OAuth persistence transition conflicts with existing state")]
    Conflict,
    /// Required durable state does not exist.
    #[error("OAuth persistence state was not found")]
    NotFound,
    /// A required user, client, grant, or tenant binding is inactive.
    #[error("OAuth persistence state is inactive")]
    Inactive,
    /// Durable state violated the module schema contract.
    #[error("OAuth persistence state is corrupt")]
    CorruptData,
    /// PostgreSQL is unavailable.
    #[error("OAuth persistence is unavailable")]
    Unavailable,
    /// A retry-safe SQL conflict occurred.
    #[error("OAuth persistence encountered a transient conflict")]
    Transient(RetryableSqlState),
}

impl RetryableTransactionError for OAuthStoreError {
    fn retryable_sql_state(&self) -> Option<RetryableSqlState> {
        match self {
            Self::Transient(state) => Some(*state),
            _ => None,
        }
    }
}

async fn load_live_grant(
    transaction: &mut Transaction<'_, Postgres>,
    grant_id: GrantId,
) -> Result<Option<LiveGrant>, OAuthStoreError> {
    let row = sqlx::query(
        "SELECT grant_row.id, subject.public_subject, subject.user_id, grant_row.tenant_id, \
                client.client_id, grant_row.resources, grant_row.granted_scopes, \
                grant_row.authenticated_at, grant_row.assurance_level, \
                grant_row.authentication_methods, grant_row.consented_at, grant_row.version \
         FROM oauth_grants grant_row \
         JOIN oauth_subjects subject ON subject.id = grant_row.subject_id \
         JOIN users user_account ON user_account.id = subject.user_id \
         JOIN oauth_clients client ON client.id = grant_row.client_id \
         WHERE grant_row.id = $1 AND grant_row.revoked_at IS NULL \
           AND user_account.status = 'active' AND client.status = 'active' \
           AND (grant_row.tenant_id IS NULL OR EXISTS ( \
               SELECT 1 FROM organizations organization \
               JOIN memberships membership ON membership.organization_id = organization.id \
               WHERE organization.id = grant_row.tenant_id AND organization.status = 'active' \
                 AND membership.user_id = subject.user_id AND membership.status = 'active'))",
    )
    .bind(grant_id.as_uuid())
    .fetch_optional(&mut **transaction)
    .await
    .map_err(|error| map_db(&error))?;
    row.as_ref().map(live_grant_from_row).transpose()
}

async fn load_client_by_internal_id(
    transaction: &mut Transaction<'_, Postgres>,
    id: OAuthClientRecordId,
) -> Result<RegisteredClient, OAuthStoreError> {
    let row = sqlx::query(
        "SELECT id, client_id, source, status, display_name, client_uri, logo_uri, \
                application_type, token_endpoint_auth_method, response_types, grant_types, \
                allowed_scopes, public_jwks, metadata_cache_expires_at, created_at, updated_at, \
                disabled_at FROM oauth_clients WHERE id = $1",
    )
    .bind(id.as_uuid())
    .fetch_one(&mut **transaction)
    .await
    .map_err(|error| map_db(&error))?;
    let redirect_rows = sqlx::query(
        "SELECT redirect_uri FROM oauth_client_redirect_uris WHERE client_id = $1 \
         ORDER BY redirect_uri COLLATE \"C\"",
    )
    .bind(id.as_uuid())
    .fetch_all(&mut **transaction)
    .await
    .map_err(|error| map_db(&error))?;
    let logout_rows = sqlx::query(
        "SELECT redirect_uri FROM oauth_client_post_logout_redirect_uris WHERE client_id = $1 \
         ORDER BY redirect_uri COLLATE \"C\"",
    )
    .bind(id.as_uuid())
    .fetch_all(&mut **transaction)
    .await
    .map_err(|error| map_db(&error))?;
    registered_client_from_rows(&row, &redirect_rows, &logout_rows)
}

fn registered_client_from_rows(
    row: &PgRow,
    redirect_rows: &[PgRow],
    logout_rows: &[PgRow],
) -> Result<RegisteredClient, OAuthStoreError> {
    let response_types: Vec<String> = row
        .try_get("response_types")
        .map_err(|_| OAuthStoreError::CorruptData)?;
    let grant_types: Vec<String> = row
        .try_get("grant_types")
        .map_err(|_| OAuthStoreError::CorruptData)?;
    let allowed_scopes: Vec<String> = row
        .try_get("allowed_scopes")
        .map_err(|_| OAuthStoreError::CorruptData)?;
    Ok(RegisteredClient {
        id: oauth_client_id(
            row.try_get("id")
                .map_err(|_| OAuthStoreError::CorruptData)?,
        )?,
        client_id: ClientId::parse(
            row.try_get::<String, _>("client_id")
                .map_err(|_| OAuthStoreError::CorruptData)?,
        )
        .map_err(|_| OAuthStoreError::CorruptData)?,
        source: ClientSource::from_db(
            &row.try_get::<String, _>("source")
                .map_err(|_| OAuthStoreError::CorruptData)?,
        )?,
        status: ClientStatus::from_db(
            &row.try_get::<String, _>("status")
                .map_err(|_| OAuthStoreError::CorruptData)?,
        )?,
        display_name: row
            .try_get("display_name")
            .map_err(|_| OAuthStoreError::CorruptData)?,
        client_uri: row
            .try_get("client_uri")
            .map_err(|_| OAuthStoreError::CorruptData)?,
        logo_uri: row
            .try_get("logo_uri")
            .map_err(|_| OAuthStoreError::CorruptData)?,
        application_type: parse_application_type(
            &row.try_get::<String, _>("application_type")
                .map_err(|_| OAuthStoreError::CorruptData)?,
        )?,
        token_endpoint_auth_method: parse_token_auth_method(
            &row.try_get::<String, _>("token_endpoint_auth_method")
                .map_err(|_| OAuthStoreError::CorruptData)?,
        )?,
        response_types: response_types
            .into_iter()
            .map(|value| parse_response_type(&value))
            .collect::<Result<Vec<_>, _>>()?,
        grant_types: grant_types
            .into_iter()
            .map(|value| parse_grant_type(&value))
            .collect::<Result<Vec<_>, _>>()?,
        allowed_scopes: allowed_scopes
            .into_iter()
            .map(|value| Scope::new(value).map_err(|_| OAuthStoreError::CorruptData))
            .collect::<Result<Vec<_>, _>>()?,
        public_jwks: row
            .try_get("public_jwks")
            .map_err(|_| OAuthStoreError::CorruptData)?,
        redirect_uris: redirect_rows
            .iter()
            .map(|redirect| {
                RedirectUri::parse(
                    redirect
                        .try_get::<String, _>("redirect_uri")
                        .map_err(|_| OAuthStoreError::CorruptData)?,
                )
                .map_err(|_| OAuthStoreError::CorruptData)
            })
            .collect::<Result<Vec<_>, _>>()?,
        post_logout_redirect_uris: logout_rows
            .iter()
            .map(|redirect| {
                RedirectUri::parse(
                    redirect
                        .try_get::<String, _>("redirect_uri")
                        .map_err(|_| OAuthStoreError::CorruptData)?,
                )
                .map_err(|_| OAuthStoreError::CorruptData)
            })
            .collect::<Result<Vec<_>, _>>()?,
        metadata_cache_expires_at: row
            .try_get("metadata_cache_expires_at")
            .map_err(|_| OAuthStoreError::CorruptData)?,
        created_at: row
            .try_get("created_at")
            .map_err(|_| OAuthStoreError::CorruptData)?,
        updated_at: row
            .try_get("updated_at")
            .map_err(|_| OAuthStoreError::CorruptData)?,
        disabled_at: row
            .try_get("disabled_at")
            .map_err(|_| OAuthStoreError::CorruptData)?,
    })
}

fn live_grant_from_row(row: &PgRow) -> Result<LiveGrant, OAuthStoreError> {
    Ok(LiveGrant {
        id: grant_id(
            row.try_get("id")
                .map_err(|_| OAuthStoreError::CorruptData)?,
        )?,
        public_subject: PublicSubject::parse(
            row.try_get::<String, _>("public_subject")
                .map_err(|_| OAuthStoreError::CorruptData)?,
        )?,
        user_id: subject_id(
            row.try_get("user_id")
                .map_err(|_| OAuthStoreError::CorruptData)?,
        )?,
        tenant_id: row
            .try_get::<Option<Uuid>, _>("tenant_id")
            .map_err(|_| OAuthStoreError::CorruptData)?
            .map(tenant_id)
            .transpose()?,
        client_id: ClientId::parse(
            row.try_get::<String, _>("client_id")
                .map_err(|_| OAuthStoreError::CorruptData)?,
        )
        .map_err(|_| OAuthStoreError::CorruptData)?,
        resources: parse_resources(
            row.try_get("resources")
                .map_err(|_| OAuthStoreError::CorruptData)?,
        )?,
        granted_scopes: parse_scopes(
            row.try_get("granted_scopes")
                .map_err(|_| OAuthStoreError::CorruptData)?,
        )?,
        authenticated_at: row
            .try_get("authenticated_at")
            .map_err(|_| OAuthStoreError::CorruptData)?,
        assurance_level: parse_assurance(
            &row.try_get::<String, _>("assurance_level")
                .map_err(|_| OAuthStoreError::CorruptData)?,
        )?,
        authentication_methods: parse_auth_methods(
            row.try_get("authentication_methods")
                .map_err(|_| OAuthStoreError::CorruptData)?,
        )?,
        consented_at: row
            .try_get("consented_at")
            .map_err(|_| OAuthStoreError::CorruptData)?,
        version: row
            .try_get("version")
            .map_err(|_| OAuthStoreError::CorruptData)?,
    })
}

fn valid_trimmed_text(value: &str, maximum: usize) -> bool {
    !value.is_empty()
        && value.len() <= maximum
        && value.trim() == value
        && value.chars().any(|character| !character.is_whitespace())
        && !value.chars().any(char::is_control)
}

fn valid_visible_text(value: &str, maximum: usize) -> bool {
    !value.is_empty() && value.len() <= maximum && value.bytes().all(|byte| byte.is_ascii_graphic())
}

fn resource_values(values: &[ResourceUri]) -> Result<Vec<String>, OAuthStoreError> {
    if values.len() > MAX_RESOURCES {
        return Err(OAuthStoreError::InvalidInput);
    }
    let result = values
        .iter()
        .map(|value| value.as_str().to_owned())
        .collect::<Vec<_>>();
    if result.windows(2).any(|pair| pair[0] >= pair[1]) {
        return Err(OAuthStoreError::InvalidInput);
    }
    Ok(result)
}

fn scope_values(values: &[Scope]) -> Result<Vec<String>, OAuthStoreError> {
    if values.len() > MAX_SCOPES {
        return Err(OAuthStoreError::InvalidInput);
    }
    let result = values
        .iter()
        .map(|value| value.as_str().to_owned())
        .collect::<Vec<_>>();
    if result.windows(2).any(|pair| pair[0] >= pair[1]) {
        return Err(OAuthStoreError::InvalidInput);
    }
    Ok(result)
}

const fn response_type_value(value: ResponseType) -> &'static str {
    match value {
        ResponseType::Code => "code",
    }
}

const fn assurance_value(value: AssuranceLevel) -> &'static str {
    match value {
        AssuranceLevel::Aal1 => "aal1",
        AssuranceLevel::Aal2 => "aal2",
        AssuranceLevel::Aal3 => "aal3",
    }
}

fn parse_application_type(value: &str) -> Result<ApplicationType, OAuthStoreError> {
    match value {
        "web" => Ok(ApplicationType::Web),
        "native" => Ok(ApplicationType::Native),
        _ => Err(OAuthStoreError::CorruptData),
    }
}

fn parse_token_auth_method(value: &str) -> Result<TokenEndpointAuthMethod, OAuthStoreError> {
    match value {
        "none" => Ok(TokenEndpointAuthMethod::None),
        "client_secret_basic" => Ok(TokenEndpointAuthMethod::ClientSecretBasic),
        "private_key_jwt" => Ok(TokenEndpointAuthMethod::PrivateKeyJwt),
        _ => Err(OAuthStoreError::CorruptData),
    }
}

fn parse_response_type(value: &str) -> Result<ResponseType, OAuthStoreError> {
    match value {
        "code" => Ok(ResponseType::Code),
        _ => Err(OAuthStoreError::CorruptData),
    }
}

fn parse_grant_type(value: &str) -> Result<GrantType, OAuthStoreError> {
    match value {
        "authorization_code" => Ok(GrantType::AuthorizationCode),
        "refresh_token" => Ok(GrantType::RefreshToken),
        _ => Err(OAuthStoreError::CorruptData),
    }
}

fn parse_assurance(value: &str) -> Result<AssuranceLevel, OAuthStoreError> {
    match value {
        "aal1" => Ok(AssuranceLevel::Aal1),
        "aal2" => Ok(AssuranceLevel::Aal2),
        "aal3" => Ok(AssuranceLevel::Aal3),
        _ => Err(OAuthStoreError::CorruptData),
    }
}

fn parse_auth_methods(values: Vec<String>) -> Result<Vec<AuthMethod>, OAuthStoreError> {
    values
        .into_iter()
        .map(|value| match value.as_str() {
            "password" => Ok(AuthMethod::Password),
            "session" => Ok(AuthMethod::Session),
            "jwt" => Ok(AuthMethod::Jwt),
            "oidc" => Ok(AuthMethod::Oidc),
            "api_key" => Ok(AuthMethod::ApiKey),
            "web_authn" => Ok(AuthMethod::WebAuthn),
            "totp" => Ok(AuthMethod::Totp),
            _ => Err(OAuthStoreError::CorruptData),
        })
        .collect()
}

fn parse_resources(values: Vec<String>) -> Result<Vec<ResourceUri>, OAuthStoreError> {
    values
        .into_iter()
        .map(|value| ResourceUri::parse(value, false).map_err(|_| OAuthStoreError::CorruptData))
        .collect()
}

fn parse_scopes(values: Vec<String>) -> Result<Vec<Scope>, OAuthStoreError> {
    values
        .into_iter()
        .map(|value| Scope::new(value).map_err(|_| OAuthStoreError::CorruptData))
        .collect()
}

fn valid_uuid_v7(value: Uuid) -> Result<(), OAuthStoreError> {
    if value.get_version() == Some(Version::SortRand) && value.get_variant() == Variant::RFC4122 {
        Ok(())
    } else {
        Err(OAuthStoreError::CorruptData)
    }
}

fn oauth_client_id(value: Uuid) -> Result<OAuthClientRecordId, OAuthStoreError> {
    OAuthClientRecordId::from_uuid(value)
}

fn grant_id(value: Uuid) -> Result<GrantId, OAuthStoreError> {
    GrantId::from_uuid(value).map_err(|_| OAuthStoreError::CorruptData)
}

fn subject_id(value: Uuid) -> Result<SubjectId, OAuthStoreError> {
    SubjectId::from_uuid(value).map_err(|_| OAuthStoreError::CorruptData)
}

fn tenant_id(value: Uuid) -> Result<TenantId, OAuthStoreError> {
    TenantId::from_uuid(value).map_err(|_| OAuthStoreError::CorruptData)
}

async fn finish<T>(
    transaction: Transaction<'_, Postgres>,
    result: Result<T, OAuthStoreError>,
) -> Result<T, OAuthStoreError> {
    match result {
        Ok(value) => {
            transaction.commit().await.map_err(|error| map_db(&error))?;
            Ok(value)
        }
        Err(error) => {
            transaction
                .rollback()
                .await
                .map_err(|rollback| map_db(&rollback))?;
            Err(error)
        }
    }
}

fn map_db(error: &sqlx::Error) -> OAuthStoreError {
    if let Some(state) = RetryableSqlState::from_sqlx(error) {
        return OAuthStoreError::Transient(state);
    }
    match error
        .as_database_error()
        .and_then(sqlx::error::DatabaseError::code)
    {
        Some(code) if matches!(code.as_ref(), "23503" | "23505") => OAuthStoreError::Conflict,
        Some(code) if matches!(code.as_ref(), "23502" | "23514" | "22001") => {
            OAuthStoreError::InvalidInput
        }
        _ => OAuthStoreError::Unavailable,
    }
}

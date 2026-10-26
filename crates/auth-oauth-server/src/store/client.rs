//! Client registration, authentication, and assertion persistence.

use super::{
    OAuthClientRecordId, OAuthPostgresStore, OAuthStoreError, finish, load_client_by_internal_id,
    map_db, oauth_client_id, parse_token_auth_method, response_type_value, scope_values,
    valid_trimmed_text, valid_visible_text,
};
use crate::crypto::BearerDigest;
use crate::types::{
    ApplicationType, ClientId, GrantType, RedirectUri, ResponseType, TokenEndpointAuthMethod,
};
use omnius_auth_core::Scope;
use serde_json::Value;
use sqlx::Connection as _;
use sqlx::Row as _;
use sqlx::postgres::PgRow;
use sqlx::{Postgres, Transaction};
use std::fmt;
use time::{Duration, OffsetDateTime};
use uuid::Uuid;

const MAX_ASSERTION_JTI_BYTES: usize = 255;

const MAX_DISPLAY_NAME_BYTES: usize = 255;

const MAX_CLIENT_URI_BYTES: usize = 2_048;

/// Origin of one registered OAuth client.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ClientSource {
    /// Administrator-managed registration.
    PreRegistered,
    /// HTTPS Client ID Metadata Document.
    ClientIdMetadata,
    /// Optional dynamic client registration.
    Dynamic,
}

impl ClientSource {
    const fn as_str(self) -> &'static str {
        match self {
            Self::PreRegistered => "pre_registered",
            Self::ClientIdMetadata => "client_id_metadata",
            Self::Dynamic => "dynamic",
        }
    }

    pub(super) fn from_db(value: &str) -> Result<Self, OAuthStoreError> {
        match value {
            "pre_registered" => Ok(Self::PreRegistered),
            "client_id_metadata" => Ok(Self::ClientIdMetadata),
            "dynamic" => Ok(Self::Dynamic),
            _ => Err(OAuthStoreError::CorruptData),
        }
    }
}

/// Current client lifecycle state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ClientStatus {
    /// The client may initiate and use grants.
    Active,
    /// The client and all its grants are disabled.
    Disabled,
}

impl ClientStatus {
    pub(super) fn from_db(value: &str) -> Result<Self, OAuthStoreError> {
        match value {
            "active" => Ok(Self::Active),
            "disabled" => Ok(Self::Disabled),
            _ => Err(OAuthStoreError::CorruptData),
        }
    }
}

/// Cached, already-validated Client ID Metadata Document state.
#[derive(Clone, Debug)]
pub struct ClientMetadataCache {
    /// Strict validated JSON object.
    pub body: Value,
    /// HTTP entity tag retained for conditional revalidation.
    pub etag: Option<String>,
    /// HTTP Last-Modified value retained for conditional revalidation.
    pub last_modified: Option<String>,
    /// Time the response became the accepted cache entry.
    pub cached_at: OffsetDateTime,
    /// Hard cache expiry.
    pub expires_at: OffsetDateTime,
}

/// Complete validated client state accepted by the persistence boundary.
pub struct ClientUpsert {
    /// Stable protocol client identifier.
    pub client_id: ClientId,
    /// Registration source.
    pub source: ClientSource,
    /// Safe human-readable display name.
    pub display_name: String,
    /// Optional client home page.
    pub client_uri: Option<String>,
    /// Optional logo URL.
    pub logo_uri: Option<String>,
    /// Web or native application class.
    pub application_type: ApplicationType,
    /// Token endpoint authentication method.
    pub token_endpoint_auth_method: TokenEndpointAuthMethod,
    /// Exact HMAC digest for a confidential client secret.
    pub client_secret_digest: Option<BearerDigest>,
    /// Supported response types.
    pub response_types: Vec<ResponseType>,
    /// Supported grant types.
    pub grant_types: Vec<GrantType>,
    /// Optional client-declared scope allow-list; empty means provider policy decides.
    pub allowed_scopes: Vec<Scope>,
    /// Public assertion keys.
    pub public_jwks: Option<Value>,
    /// Exact registered authorization redirects.
    pub redirect_uris: Vec<RedirectUri>,
    /// Exact registered post-logout redirects.
    pub post_logout_redirect_uris: Vec<RedirectUri>,
    /// CIMD document URL; necessarily identical to a CIMD client ID.
    pub metadata_document_uri: Option<String>,
    /// Optional validated metadata cache.
    pub metadata_cache: Option<ClientMetadataCache>,
    /// Mutation timestamp.
    pub now: OffsetDateTime,
}

impl fmt::Debug for ClientUpsert {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ClientUpsert")
            .field("client_id", &self.client_id)
            .field("source", &self.source)
            .field("display_name", &self.display_name)
            .field("application_type", &self.application_type)
            .field(
                "token_endpoint_auth_method",
                &self.token_endpoint_auth_method,
            )
            .field("client_secret_digest", &"[REDACTED]")
            .field("redirect_uri_count", &self.redirect_uris.len())
            .field(
                "post_logout_redirect_uri_count",
                &self.post_logout_redirect_uris.len(),
            )
            .finish_non_exhaustive()
    }
}

/// Safe registered-client metadata. Secret digests and cache bodies are excluded.
#[derive(Clone, Debug)]
pub struct RegisteredClient {
    /// Internal durable row identifier.
    pub id: OAuthClientRecordId,
    /// Protocol client identifier.
    pub client_id: ClientId,
    /// Registration source.
    pub source: ClientSource,
    /// Lifecycle state.
    pub status: ClientStatus,
    /// Safe display name.
    pub display_name: String,
    /// Optional client home page.
    pub client_uri: Option<String>,
    /// Optional logo URL.
    pub logo_uri: Option<String>,
    /// Application class.
    pub application_type: ApplicationType,
    /// Client authentication method.
    pub token_endpoint_auth_method: TokenEndpointAuthMethod,
    /// Supported response types.
    pub response_types: Vec<ResponseType>,
    /// Supported grant types.
    pub grant_types: Vec<GrantType>,
    /// Optional client-declared scope allow-list; empty means provider policy decides.
    pub allowed_scopes: Vec<Scope>,
    /// Public assertion keys.
    pub public_jwks: Option<Value>,
    /// Exact authorization redirects.
    pub redirect_uris: Vec<RedirectUri>,
    /// Exact post-logout redirects.
    pub post_logout_redirect_uris: Vec<RedirectUri>,
    /// CIMD cache expiry used to force metadata revalidation.
    pub metadata_cache_expires_at: Option<OffsetDateTime>,
    /// Creation time.
    pub created_at: OffsetDateTime,
    /// Last mutation time.
    pub updated_at: OffsetDateTime,
    /// Disable time.
    pub disabled_at: Option<OffsetDateTime>,
}

/// Authentication material loaded separately from safe client metadata.
#[derive(Clone)]
#[non_exhaustive]
pub struct ClientAuthentication {
    /// Internal client row identifier.
    pub id: OAuthClientRecordId,
    /// Protocol client identifier.
    pub client_id: ClientId,
    /// Authentication method.
    pub method: TokenEndpointAuthMethod,
    /// Exact stored client-secret digest, when applicable.
    pub client_secret_digest: Option<BearerDigest>,
    /// Public keys for private-key JWT, when applicable.
    pub public_jwks: Option<Value>,
}

impl fmt::Debug for ClientAuthentication {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ClientAuthentication")
            .field("id", &self.id)
            .field("client_id", &self.client_id)
            .field("method", &self.method)
            .field("client_secret_digest", &"[REDACTED]")
            .field("has_public_jwks", &self.public_jwks.is_some())
            .finish()
    }
}

/// Atomic disable result.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ClientDisableOutcome {
    /// Whether this call changed the client from active to disabled.
    pub newly_disabled: bool,
    /// Grants newly revoked by this call.
    pub grants_revoked: u64,
    /// Refresh families newly revoked by this call.
    pub refresh_families_revoked: u64,
}

/// Result of recording a private-key JWT assertion replay key.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ClientAssertionRecord {
    /// This `(client, jti)` was accepted and persisted.
    Accepted,
    /// The assertion was already recorded.
    Replay,
    /// The client is missing or disabled.
    ClientUnavailable,
}

impl OAuthPostgresStore {
    /// Atomically upserts a client and replaces its exact redirect sets.
    ///
    /// # Errors
    ///
    /// Returns [`OAuthStoreError`] if input validation or invariant checks fail, or if
    /// PostgreSQL cannot complete the transaction.
    pub async fn upsert_client(
        &self,
        input: &ClientUpsert,
    ) -> Result<RegisteredClient, OAuthStoreError> {
        let mut connection = self
            .pool
            .acquire()
            .await
            .map_err(|_| OAuthStoreError::Unavailable)?;
        let mut transaction = connection.begin().await.map_err(|error| map_db(&error))?;
        let result = self.upsert_client_with(&mut transaction, input).await;
        finish(transaction, result).await
    }

    /// Caller-owned transaction variant of [`Self::upsert_client`].
    ///
    /// # Errors
    ///
    /// Returns [`OAuthStoreError`] if input validation or invariant checks fail, or if
    /// PostgreSQL cannot complete the caller-owned transaction.
    pub async fn upsert_client_with(
        &self,
        transaction: &mut Transaction<'_, Postgres>,
        input: &ClientUpsert,
    ) -> Result<RegisteredClient, OAuthStoreError> {
        validate_client_upsert(input)?;
        let response_types = response_type_values(&input.response_types);
        let grant_types = grant_type_values(&input.grant_types);
        let allowed_scopes = scope_values(&input.allowed_scopes)?;
        let cache = client_metadata_bindings(input.metadata_cache.as_ref());
        let id = OAuthClientRecordId::new();
        let client_secret_digest = input
            .client_secret_digest
            .as_ref()
            .map(|digest| digest.as_bytes().as_slice());
        let row = sqlx::query(
            "INSERT INTO oauth_clients (id, client_id, source, status, display_name, client_uri, \
             logo_uri, application_type, token_endpoint_auth_method, client_secret_digest, \
             response_types, grant_types, allowed_scopes, public_jwks, metadata_document_uri, \
             metadata_cache_body, metadata_cache_etag, metadata_cache_last_modified, \
             metadata_cached_at, metadata_cache_expires_at, created_at, updated_at, disabled_at) \
             VALUES ($1, $2, $3, 'active', $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, \
                     $14, $15, $16, $17, $18, $19, $20, $20, NULL) \
             ON CONFLICT (client_id) DO UPDATE SET source = EXCLUDED.source, \
                 display_name = EXCLUDED.display_name, client_uri = EXCLUDED.client_uri, \
                 logo_uri = EXCLUDED.logo_uri, application_type = EXCLUDED.application_type, \
                 token_endpoint_auth_method = EXCLUDED.token_endpoint_auth_method, \
                 client_secret_digest = EXCLUDED.client_secret_digest, \
                 response_types = EXCLUDED.response_types, grant_types = EXCLUDED.grant_types, \
                 allowed_scopes = EXCLUDED.allowed_scopes, public_jwks = EXCLUDED.public_jwks, \
                 metadata_document_uri = EXCLUDED.metadata_document_uri, \
                 metadata_cache_body = EXCLUDED.metadata_cache_body, \
                 metadata_cache_etag = EXCLUDED.metadata_cache_etag, \
                 metadata_cache_last_modified = EXCLUDED.metadata_cache_last_modified, \
                 metadata_cached_at = EXCLUDED.metadata_cached_at, \
                 metadata_cache_expires_at = EXCLUDED.metadata_cache_expires_at, \
                 updated_at = EXCLUDED.updated_at \
             WHERE oauth_clients.source <> 'dynamic' AND EXCLUDED.source <> 'dynamic' \
             RETURNING id",
        )
        .bind(id.as_uuid())
        .bind(input.client_id.as_str())
        .bind(input.source.as_str())
        .bind(&input.display_name)
        .bind(input.client_uri.as_deref())
        .bind(input.logo_uri.as_deref())
        .bind(application_type_value(input.application_type))
        .bind(token_auth_method_value(input.token_endpoint_auth_method))
        .bind(client_secret_digest)
        .bind(&response_types)
        .bind(&grant_types)
        .bind(&allowed_scopes)
        .bind(input.public_jwks.as_ref())
        .bind(input.metadata_document_uri.as_deref())
        .bind(cache.body)
        .bind(cache.etag)
        .bind(cache.last_modified)
        .bind(cache.cached_at)
        .bind(cache.expires_at)
        .bind(input.now)
        .fetch_one(&mut **transaction)
        .await
        .map_err(|error| map_db(&error))?;
        let persisted_id = oauth_client_id(
            row.try_get("id")
                .map_err(|_| OAuthStoreError::CorruptData)?,
        )?;

        replace_redirect_set(
            transaction,
            persisted_id,
            &input.redirect_uris,
            input.now,
            "INSERT INTO oauth_client_redirect_uris \
             (id, client_id, redirect_uri, created_at) VALUES ($1, $2, $3, $4) \
             ON CONFLICT (client_id, redirect_uri) DO NOTHING",
            "DELETE FROM oauth_client_redirect_uris WHERE client_id = $1 \
             AND NOT (redirect_uri = ANY($2))",
        )
        .await?;
        replace_redirect_set(
            transaction,
            persisted_id,
            &input.post_logout_redirect_uris,
            input.now,
            "INSERT INTO oauth_client_post_logout_redirect_uris \
             (id, client_id, redirect_uri, created_at) VALUES ($1, $2, $3, $4) \
             ON CONFLICT (client_id, redirect_uri) DO NOTHING",
            "DELETE FROM oauth_client_post_logout_redirect_uris WHERE client_id = $1 \
             AND NOT (redirect_uri = ANY($2))",
        )
        .await?;

        load_client_by_internal_id(transaction, persisted_id).await
    }

    /// Loads active or disabled safe client metadata by exact client ID.
    ///
    /// # Errors
    ///
    /// Returns [`OAuthStoreError`] if stored client data violates its invariants or
    /// PostgreSQL is unavailable.
    pub async fn load_client(
        &self,
        client_id: &ClientId,
    ) -> Result<Option<RegisteredClient>, OAuthStoreError> {
        let mut connection = self
            .pool
            .acquire()
            .await
            .map_err(|_| OAuthStoreError::Unavailable)?;
        let mut transaction = connection.begin().await.map_err(|error| map_db(&error))?;
        let result = load_client_by_protocol_id(&mut transaction, client_id).await;
        finish(transaction, result).await
    }

    /// Loads authentication material only for an active exact client ID.
    ///
    /// # Errors
    ///
    /// Returns [`OAuthStoreError`] if stored authentication data is corrupt or PostgreSQL
    /// is unavailable.
    pub async fn load_client_authentication(
        &self,
        client_id: &ClientId,
    ) -> Result<Option<ClientAuthentication>, OAuthStoreError> {
        let mut connection = self
            .pool
            .acquire()
            .await
            .map_err(|_| OAuthStoreError::Unavailable)?;
        let mut transaction = connection.begin().await.map_err(|error| map_db(&error))?;
        let result = self
            .load_client_authentication_with(&mut transaction, client_id)
            .await;
        finish(transaction, result).await
    }

    /// Loads active authentication material while holding a shared client-row lock.
    ///
    /// # Errors
    ///
    /// Returns [`OAuthStoreError`] if stored authentication data is corrupt or PostgreSQL
    /// cannot complete the caller-owned transaction.
    pub async fn load_client_authentication_with(
        &self,
        transaction: &mut Transaction<'_, Postgres>,
        client_id: &ClientId,
    ) -> Result<Option<ClientAuthentication>, OAuthStoreError> {
        let row = sqlx::query(
            "SELECT id, client_id, token_endpoint_auth_method, client_secret_digest, public_jwks \
             FROM oauth_clients WHERE client_id = $1 AND status = 'active' FOR SHARE",
        )
        .bind(client_id.as_str())
        .fetch_optional(&mut **transaction)
        .await
        .map_err(|error| map_db(&error))?;
        row.as_ref().map(client_authentication_from_row).transpose()
    }

    /// Disables a client and atomically revokes every live grant and refresh family.
    ///
    /// # Errors
    ///
    /// Returns [`OAuthStoreError`] if stored client state violates its invariants or
    /// PostgreSQL cannot complete the transaction.
    pub async fn disable_client(
        &self,
        client_id: &ClientId,
        now: OffsetDateTime,
    ) -> Result<Option<ClientDisableOutcome>, OAuthStoreError> {
        let mut connection = self
            .pool
            .acquire()
            .await
            .map_err(|_| OAuthStoreError::Unavailable)?;
        let mut transaction = connection.begin().await.map_err(|error| map_db(&error))?;
        let result = self
            .disable_client_with(&mut transaction, client_id, now)
            .await;
        finish(transaction, result).await
    }

    /// Caller-owned transaction variant of [`Self::disable_client`].
    ///
    /// # Errors
    ///
    /// Returns [`OAuthStoreError`] if stored client state violates its invariants or
    /// PostgreSQL cannot complete the caller-owned transaction.
    pub async fn disable_client_with(
        &self,
        transaction: &mut Transaction<'_, Postgres>,
        client_id: &ClientId,
        now: OffsetDateTime,
    ) -> Result<Option<ClientDisableOutcome>, OAuthStoreError> {
        let row =
            sqlx::query("SELECT id, status FROM oauth_clients WHERE client_id = $1 FOR UPDATE")
                .bind(client_id.as_str())
                .fetch_optional(&mut **transaction)
                .await
                .map_err(|error| map_db(&error))?;
        let Some(row) = row else {
            return Ok(None);
        };
        let id = oauth_client_id(
            row.try_get("id")
                .map_err(|_| OAuthStoreError::CorruptData)?,
        )?;
        let status = ClientStatus::from_db(
            &row.try_get::<String, _>("status")
                .map_err(|_| OAuthStoreError::CorruptData)?,
        )?;
        let newly_disabled = status == ClientStatus::Active;
        if newly_disabled {
            sqlx::query(
                "UPDATE oauth_clients SET status = 'disabled', disabled_at = $2, updated_at = $2 \
                 WHERE id = $1",
            )
            .bind(id.as_uuid())
            .bind(now)
            .execute(&mut **transaction)
            .await
            .map_err(|error| map_db(&error))?;
        }
        let grants = sqlx::query(
            "UPDATE oauth_grants SET revoked_at = $2, updated_at = $2, version = version + 1 \
             WHERE client_id = $1 AND revoked_at IS NULL",
        )
        .bind(id.as_uuid())
        .bind(now)
        .execute(&mut **transaction)
        .await
        .map_err(|error| map_db(&error))?
        .rows_affected();
        let families = sqlx::query(
            "UPDATE oauth_refresh_token_families SET revoked_at = $2, \
             revocation_reason = 'client_disabled', version = version + 1 \
             WHERE client_id = $1 AND revoked_at IS NULL",
        )
        .bind(id.as_uuid())
        .bind(now)
        .execute(&mut **transaction)
        .await
        .map_err(|error| map_db(&error))?
        .rows_affected();
        Ok(Some(ClientDisableOutcome {
            newly_disabled,
            grants_revoked: grants,
            refresh_families_revoked: families,
        }))
    }

    /// Atomically records one client assertion replay key before accepting it.
    ///
    /// # Errors
    ///
    /// Returns [`OAuthStoreError`] if the assertion fields are invalid or PostgreSQL cannot
    /// complete the transaction.
    pub async fn record_client_assertion(
        &self,
        client_id: &ClientId,
        jti: &str,
        issued_at: OffsetDateTime,
        expires_at: OffsetDateTime,
    ) -> Result<ClientAssertionRecord, OAuthStoreError> {
        let mut connection = self
            .pool
            .acquire()
            .await
            .map_err(|_| OAuthStoreError::Unavailable)?;
        let mut transaction = connection.begin().await.map_err(|error| map_db(&error))?;
        let result = self
            .record_client_assertion_with(&mut transaction, client_id, jti, issued_at, expires_at)
            .await;
        finish(transaction, result).await
    }

    /// Caller-owned transaction variant of [`Self::record_client_assertion`].
    ///
    /// # Errors
    ///
    /// Returns [`OAuthStoreError`] if the assertion fields are invalid or PostgreSQL cannot
    /// complete the caller-owned transaction.
    pub async fn record_client_assertion_with(
        &self,
        transaction: &mut Transaction<'_, Postgres>,
        client_id: &ClientId,
        jti: &str,
        issued_at: OffsetDateTime,
        expires_at: OffsetDateTime,
    ) -> Result<ClientAssertionRecord, OAuthStoreError> {
        if !valid_visible_text(jti, MAX_ASSERTION_JTI_BYTES)
            || expires_at <= issued_at
            || expires_at > issued_at + Duration::minutes(10)
        {
            return Err(OAuthStoreError::InvalidInput);
        }
        let result = sqlx::query(
            "INSERT INTO oauth_client_assertions (id, client_id, jti, issued_at, expires_at) \
             SELECT $1, id, $3, $4, $5 FROM oauth_clients \
             WHERE client_id = $2 AND status = 'active' \
             ON CONFLICT (client_id, jti) DO NOTHING",
        )
        .bind(Uuid::now_v7())
        .bind(client_id.as_str())
        .bind(jti)
        .bind(issued_at)
        .bind(expires_at)
        .execute(&mut **transaction)
        .await
        .map_err(|error| map_db(&error))?;
        if result.rows_affected() == 1 {
            return Ok(ClientAssertionRecord::Accepted);
        }
        let active =
            sqlx::query("SELECT 1 FROM oauth_clients WHERE client_id = $1 AND status = 'active'")
                .bind(client_id.as_str())
                .fetch_optional(&mut **transaction)
                .await
                .map_err(|error| map_db(&error))?
                .is_some();
        Ok(if active {
            ClientAssertionRecord::Replay
        } else {
            ClientAssertionRecord::ClientUnavailable
        })
    }
}

struct ClientMetadataBindings<'a> {
    body: Option<&'a Value>,
    etag: Option<&'a str>,
    last_modified: Option<&'a str>,
    cached_at: Option<OffsetDateTime>,
    expires_at: Option<OffsetDateTime>,
}

fn client_metadata_bindings(cache: Option<&ClientMetadataCache>) -> ClientMetadataBindings<'_> {
    cache.map_or(
        ClientMetadataBindings {
            body: None,
            etag: None,
            last_modified: None,
            cached_at: None,
            expires_at: None,
        },
        |cache| ClientMetadataBindings {
            body: Some(&cache.body),
            etag: cache.etag.as_deref(),
            last_modified: cache.last_modified.as_deref(),
            cached_at: Some(cache.cached_at),
            expires_at: Some(cache.expires_at),
        },
    )
}

async fn replace_redirect_set(
    transaction: &mut Transaction<'_, Postgres>,
    client_id: OAuthClientRecordId,
    redirects: &[RedirectUri],
    now: OffsetDateTime,
    insert_query: &str,
    prune_query: &str,
) -> Result<(), OAuthStoreError> {
    for redirect in redirects {
        sqlx::query(insert_query)
            .bind(Uuid::now_v7())
            .bind(client_id.as_uuid())
            .bind(redirect.as_str())
            .bind(now)
            .execute(&mut **transaction)
            .await
            .map_err(|error| map_db(&error))?;
    }
    let values = redirect_values(redirects);
    sqlx::query(prune_query)
        .bind(client_id.as_uuid())
        .bind(&values)
        .execute(&mut **transaction)
        .await
        .map_err(|error| map_db(&error))?;
    Ok(())
}

async fn load_client_by_protocol_id(
    transaction: &mut Transaction<'_, Postgres>,
    client_id: &ClientId,
) -> Result<Option<RegisteredClient>, OAuthStoreError> {
    let row = sqlx::query("SELECT id FROM oauth_clients WHERE client_id = $1")
        .bind(client_id.as_str())
        .fetch_optional(&mut **transaction)
        .await
        .map_err(|error| map_db(&error))?;
    let Some(row) = row else {
        return Ok(None);
    };
    let id = oauth_client_id(
        row.try_get("id")
            .map_err(|_| OAuthStoreError::CorruptData)?,
    )?;
    load_client_by_internal_id(transaction, id).await.map(Some)
}

fn client_authentication_from_row(row: &PgRow) -> Result<ClientAuthentication, OAuthStoreError> {
    let digest: Option<Vec<u8>> = row
        .try_get("client_secret_digest")
        .map_err(|_| OAuthStoreError::CorruptData)?;
    Ok(ClientAuthentication {
        id: oauth_client_id(
            row.try_get("id")
                .map_err(|_| OAuthStoreError::CorruptData)?,
        )?,
        client_id: ClientId::parse(
            row.try_get::<String, _>("client_id")
                .map_err(|_| OAuthStoreError::CorruptData)?,
        )
        .map_err(|_| OAuthStoreError::CorruptData)?,
        method: parse_token_auth_method(
            &row.try_get::<String, _>("token_endpoint_auth_method")
                .map_err(|_| OAuthStoreError::CorruptData)?,
        )?,
        client_secret_digest: digest.map(digest_from_vec).transpose()?,
        public_jwks: row
            .try_get("public_jwks")
            .map_err(|_| OAuthStoreError::CorruptData)?,
    })
}

fn validate_client_upsert(input: &ClientUpsert) -> Result<(), OAuthStoreError> {
    if !valid_trimmed_text(&input.display_name, MAX_DISPLAY_NAME_BYTES)
        || input.redirect_uris.is_empty()
        || input.redirect_uris.len() > 32
        || input.post_logout_redirect_uris.len() > 16
        || input.response_types != [ResponseType::Code]
    {
        return Err(OAuthStoreError::InvalidInput);
    }
    validate_https_optional(input.client_uri.as_deref())?;
    validate_https_optional(input.logo_uri.as_deref())?;
    let response_types = response_type_values(&input.response_types);
    if !canonical_strings(&response_types, 1) {
        return Err(OAuthStoreError::InvalidInput);
    }
    let grant_types = grant_type_values(&input.grant_types);
    if !canonical_strings(&grant_types, 2)
        || !grant_types
            .iter()
            .any(|value| value == "authorization_code")
    {
        return Err(OAuthStoreError::InvalidInput);
    }
    if !canonical_redirects(&input.redirect_uris)
        || !canonical_redirects(&input.post_logout_redirect_uris)
    {
        return Err(OAuthStoreError::InvalidInput);
    }
    scope_values(&input.allowed_scopes)?;
    match input.token_endpoint_auth_method {
        TokenEndpointAuthMethod::None if input.client_secret_digest.is_none() => {}
        TokenEndpointAuthMethod::ClientSecretBasic if input.client_secret_digest.is_some() => {}
        TokenEndpointAuthMethod::PrivateKeyJwt
            if input.client_secret_digest.is_none() && input.public_jwks.is_some() => {}
        _ => return Err(OAuthStoreError::InvalidInput),
    }
    match input.source {
        ClientSource::ClientIdMetadata
            if input.metadata_document_uri.as_deref() == Some(input.client_id.as_str()) => {}
        ClientSource::ClientIdMetadata => return Err(OAuthStoreError::InvalidInput),
        ClientSource::PreRegistered | ClientSource::Dynamic
            if input.metadata_document_uri.is_none() && input.metadata_cache.is_none() => {}
        ClientSource::PreRegistered | ClientSource::Dynamic => {
            return Err(OAuthStoreError::InvalidInput);
        }
    }
    if let Some(cache) = input.metadata_cache.as_ref()
        && (!cache.body.is_object() || cache.expires_at <= cache.cached_at)
    {
        return Err(OAuthStoreError::InvalidInput);
    }
    Ok(())
}

fn validate_https_optional(value: Option<&str>) -> Result<(), OAuthStoreError> {
    if value.is_some_and(|value| {
        value.len() < 8
            || value.len() > MAX_CLIENT_URI_BYTES
            || !value.starts_with("https://")
            || !value.bytes().all(|byte| byte.is_ascii_graphic())
            || value.contains('"')
            || value.contains('\\')
    }) {
        Err(OAuthStoreError::InvalidInput)
    } else {
        Ok(())
    }
}

fn canonical_redirects(values: &[RedirectUri]) -> bool {
    values.windows(2).all(|pair| pair[0] < pair[1])
}

fn canonical_strings(values: &[String], maximum: usize) -> bool {
    !values.is_empty() && values.len() <= maximum && values.windows(2).all(|pair| pair[0] < pair[1])
}

fn redirect_values(values: &[RedirectUri]) -> Vec<String> {
    values
        .iter()
        .map(|value| value.as_str().to_owned())
        .collect()
}

fn response_type_values(values: &[ResponseType]) -> Vec<String> {
    values
        .iter()
        .copied()
        .map(response_type_value)
        .map(str::to_owned)
        .collect()
}

fn grant_type_values(values: &[GrantType]) -> Vec<String> {
    values
        .iter()
        .copied()
        .map(grant_type_value)
        .map(str::to_owned)
        .collect()
}

const fn application_type_value(value: ApplicationType) -> &'static str {
    match value {
        ApplicationType::Web => "web",
        ApplicationType::Native => "native",
    }
}

const fn token_auth_method_value(value: TokenEndpointAuthMethod) -> &'static str {
    match value {
        TokenEndpointAuthMethod::None => "none",
        TokenEndpointAuthMethod::ClientSecretBasic => "client_secret_basic",
        TokenEndpointAuthMethod::PrivateKeyJwt => "private_key_jwt",
    }
}

const fn grant_type_value(value: GrantType) -> &'static str {
    match value {
        GrantType::AuthorizationCode => "authorization_code",
        GrantType::RefreshToken => "refresh_token",
    }
}

fn digest_from_vec(value: Vec<u8>) -> Result<BearerDigest, OAuthStoreError> {
    let bytes: [u8; 32] = value.try_into().map_err(|_| OAuthStoreError::CorruptData)?;
    Ok(BearerDigest::from_bytes(bytes))
}

//! Authorization request persistence and state transitions.

use super::{
    AuthorizationRequestId, ClientStatus, MAX_NONCE_BYTES, OAuthPostgresStore, OAuthStoreError,
    RegisteredClient, assurance_value, finish, load_client_by_internal_id, map_db, oauth_client_id,
    parse_assurance, parse_resources, parse_response_type, parse_scopes, resource_values,
    response_type_value, scope_values, valid_trimmed_text, valid_visible_text,
};
use crate::crypto::BearerDigest;
use crate::types::{
    ClientId, IssuerUri, PkceChallenge, Prompt, RedirectUri, ResourceUri, ResponseMode,
    ResponseType,
};
use omnius_auth_core::{AssuranceLevel, Scope};
use sqlx::Connection as _;
use sqlx::Row as _;
use sqlx::postgres::PgRow;
use sqlx::{Postgres, Transaction};
use std::fmt;
use time::{Duration, OffsetDateTime};
use uuid::Uuid;

const MAX_STATE_BYTES: usize = 2_048;

const MAX_RESOURCE_NAME_BYTES: usize = 128;

const MAX_RESOURCE_DESCRIPTION_BYTES: usize = 1_024;

const MAX_SCOPE_DESCRIPTION_BYTES: usize = 512;

/// Durable browser interaction state retained without protocol secrets.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuthorizationInteractionRequirement {
    /// Authentication or fresh reauthentication is required.
    Login,
    /// Explicit consent is required.
    Consent,
    /// The existing grant covers the request.
    Ready,
}

impl AuthorizationInteractionRequirement {
    const fn as_db(self) -> &'static str {
        match self {
            Self::Login => "login",
            Self::Consent => "consent",
            Self::Ready => "ready",
        }
    }

    fn from_db(value: &str) -> Result<Self, OAuthStoreError> {
        match value {
            "login" => Ok(Self::Login),
            "consent" => Ok(Self::Consent),
            "ready" => Ok(Self::Ready),
            _ => Err(OAuthStoreError::CorruptData),
        }
    }
}

/// One safe scope display row retained in canonical requested-scope order.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthorizationInteractionScope {
    /// Exact requested scope.
    pub name: Scope,
    /// Safe provider-authored description.
    pub description: String,
    /// Whether the scope extends beyond an existing grant.
    pub newly_requested: bool,
}

/// Durable pending authorization request input.
pub struct AuthorizationRequestCreate {
    /// Exact digest of the browser handle.
    pub handle_digest: BearerDigest,
    /// Validated client identifier.
    pub client_id: ClientId,
    /// Exact registered redirect URI.
    pub redirect_uri: RedirectUri,
    /// Response type.
    pub response_type: ResponseType,
    /// Response mode.
    pub response_mode: ResponseMode,
    /// Opaque client state.
    pub client_state: Option<String>,
    /// Requested scopes.
    pub requested_scopes: Vec<Scope>,
    /// Requested resources.
    pub resource_uris: Vec<ResourceUri>,
    /// S256 PKCE challenge.
    pub pkce_code_challenge: PkceChallenge,
    /// OIDC nonce.
    pub nonce: Option<String>,
    /// Prompt values.
    pub prompt_values: Vec<Prompt>,
    /// Maximum authentication age.
    pub max_age_seconds: Option<u64>,
    /// Exact expected issuer.
    pub expected_issuer: IssuerUri,
    /// Safe configured resource display name.
    pub interaction_resource_name: String,
    /// Safe configured resource display description.
    pub interaction_resource_description: String,
    /// Configured minimum resource assurance.
    pub interaction_minimum_assurance: AssuranceLevel,
    /// Safe scope descriptions and existing-grant delta.
    pub interaction_scopes: Vec<AuthorizationInteractionScope>,
    /// Exact browser interaction requirement.
    pub interaction_requirement: AuthorizationInteractionRequirement,
    /// Creation time.
    pub created_at: OffsetDateTime,
    /// Expiry time.
    pub expires_at: OffsetDateTime,
}

impl fmt::Debug for AuthorizationRequestCreate {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AuthorizationRequestCreate")
            .field("handle_digest", &"[REDACTED]")
            .field("client_id", &self.client_id)
            .field("redirect_uri", &"[REDACTED]")
            .field("scope_count", &self.requested_scopes.len())
            .field("resource_count", &self.resource_uris.len())
            .finish_non_exhaustive()
    }
}

/// Authorization request lifecycle state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuthorizationRequestStatus {
    /// Awaiting user interaction.
    Pending,
    /// User approved the request.
    Approved,
    /// User denied the request.
    Denied,
    /// Request expired before a decision.
    Expired,
}

impl AuthorizationRequestStatus {
    fn from_db(value: &str) -> Result<Self, OAuthStoreError> {
        match value {
            "pending" => Ok(Self::Pending),
            "approved" => Ok(Self::Approved),
            "denied" => Ok(Self::Denied),
            "expired" => Ok(Self::Expired),
            _ => Err(OAuthStoreError::CorruptData),
        }
    }
}

/// Loaded authorization request. Its bearer digest is deliberately excluded.
#[derive(Clone)]
pub struct AuthorizationRequestRecord {
    /// Durable request identifier.
    pub id: AuthorizationRequestId,
    /// Safe client metadata.
    pub client: RegisteredClient,
    /// Exact validated redirect.
    pub redirect_uri: RedirectUri,
    /// Response type.
    pub response_type: ResponseType,
    /// Response mode.
    pub response_mode: ResponseMode,
    /// Opaque client state required only at the redirect boundary.
    pub client_state: Option<String>,
    /// Requested scopes.
    pub requested_scopes: Vec<Scope>,
    /// Requested resources.
    pub resource_uris: Vec<ResourceUri>,
    /// S256 challenge.
    pub pkce_code_challenge: PkceChallenge,
    /// OIDC nonce.
    pub nonce: Option<String>,
    /// Prompt values.
    pub prompt_values: Vec<Prompt>,
    /// Maximum authentication age.
    pub max_age_seconds: Option<u64>,
    /// Expected issuer.
    pub expected_issuer: IssuerUri,
    /// Safe configured resource display name.
    pub interaction_resource_name: String,
    /// Safe configured resource display description.
    pub interaction_resource_description: String,
    /// Configured minimum resource assurance.
    pub interaction_minimum_assurance: AssuranceLevel,
    /// Safe scope descriptions and existing-grant delta.
    pub interaction_scopes: Vec<AuthorizationInteractionScope>,
    /// Exact browser interaction requirement.
    pub interaction_requirement: AuthorizationInteractionRequirement,
    /// Lifecycle state.
    pub status: AuthorizationRequestStatus,
    /// Creation time.
    pub created_at: OffsetDateTime,
    /// Expiry time.
    pub expires_at: OffsetDateTime,
    /// Terminal transition time.
    pub completed_at: Option<OffsetDateTime>,
}

impl fmt::Debug for AuthorizationRequestRecord {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AuthorizationRequestRecord")
            .field("id", &self.id)
            .field("client_id", &self.client.client_id)
            .field("status", &self.status)
            .field("scope_count", &self.requested_scopes.len())
            .field("resource_count", &self.resource_uris.len())
            .finish_non_exhaustive()
    }
}

/// Result of loading a recognized authorization request handle.
#[derive(Clone, Debug)]
pub enum AuthorizationRequestLoad {
    /// Pending, live request.
    Pending(Box<AuthorizationRequestRecord>),
    /// Recognized request that was atomically marked expired.
    Expired,
    /// Unknown, terminal, or client-disabled request.
    Unavailable,
}

/// Terminal browser decision.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuthorizationDecision {
    /// Consent approved.
    Approve,
    /// Consent denied.
    Deny,
}

impl AuthorizationDecision {
    const fn status(self) -> &'static str {
        match self {
            Self::Approve => "approved",
            Self::Deny => "denied",
        }
    }
}

/// Result of a terminal authorization-request transition.
#[derive(Clone, Debug)]
pub enum AuthorizationTransition {
    /// The request moved to its requested terminal state.
    Completed(Box<AuthorizationRequestRecord>),
    /// The request expired and was atomically marked expired.
    Expired,
    /// The request is unknown, already terminal, or belongs to a disabled client.
    Unavailable,
}

impl OAuthPostgresStore {
    /// Persists a pending authorization request using only the handle digest.
    ///
    /// # Errors
    ///
    /// Returns [`OAuthStoreError`] if the request violates protocol invariants or PostgreSQL
    /// cannot complete the transaction.
    pub async fn create_authorization_request(
        &self,
        input: &AuthorizationRequestCreate,
    ) -> Result<AuthorizationRequestId, OAuthStoreError> {
        let mut connection = self
            .pool
            .acquire()
            .await
            .map_err(|_| OAuthStoreError::Unavailable)?;
        let mut transaction = connection.begin().await.map_err(|error| map_db(&error))?;
        let result = self
            .create_authorization_request_with(&mut transaction, input)
            .await;
        finish(transaction, result).await
    }

    /// Caller-owned transaction variant of [`Self::create_authorization_request`].
    ///
    /// # Errors
    ///
    /// Returns [`OAuthStoreError`] if the request violates protocol invariants or PostgreSQL
    /// cannot complete the caller-owned transaction.
    pub async fn create_authorization_request_with(
        &self,
        transaction: &mut Transaction<'_, Postgres>,
        input: &AuthorizationRequestCreate,
    ) -> Result<AuthorizationRequestId, OAuthStoreError> {
        validate_authorization_request(input)?;
        let requested_scopes = scope_values(&input.requested_scopes)?;
        let resources = resource_values(&input.resource_uris)?;
        let prompts = prompt_values(&input.prompt_values)?;
        let interaction_scope_descriptions = input
            .interaction_scopes
            .iter()
            .map(|scope| scope.description.as_str())
            .collect::<Vec<_>>();
        let interaction_scope_newly_requested = input
            .interaction_scopes
            .iter()
            .map(|scope| scope.newly_requested)
            .collect::<Vec<_>>();
        let id = AuthorizationRequestId::new();
        let max_age = input
            .max_age_seconds
            .map(i64::try_from)
            .transpose()
            .map_err(|_| OAuthStoreError::InvalidInput)?;
        let result = sqlx::query(
            "INSERT INTO oauth_authorization_requests \
             (id, request_handle_digest, client_id, redirect_uri, response_type, response_mode, \
              client_state, requested_scopes, resource_uris, pkce_code_challenge, nonce, \
              prompt_values, max_age_seconds, expected_issuer, interaction_resource_name, \
              interaction_resource_description, interaction_minimum_assurance, \
              interaction_scope_descriptions, interaction_scope_newly_requested, \
              interaction_requirement, status, created_at, expires_at, completed_at) \
             SELECT $1, $2, client.id, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, \
                    $15, $16, $17, $18, $19, $20, 'pending', $21, $22, NULL \
             FROM oauth_clients client JOIN oauth_client_redirect_uris redirect \
               ON redirect.client_id = client.id AND redirect.redirect_uri = $4 \
             WHERE client.client_id = $3 AND client.status = 'active'",
        )
        .bind(id.as_uuid())
        .bind(input.handle_digest.as_bytes().as_slice())
        .bind(input.client_id.as_str())
        .bind(input.redirect_uri.as_str())
        .bind(response_type_value(input.response_type))
        .bind(response_mode_value(input.response_mode))
        .bind(input.client_state.as_deref())
        .bind(&requested_scopes)
        .bind(&resources)
        .bind(input.pkce_code_challenge.as_str())
        .bind(input.nonce.as_deref())
        .bind(&prompts)
        .bind(max_age)
        .bind(input.expected_issuer.as_str())
        .bind(&input.interaction_resource_name)
        .bind(&input.interaction_resource_description)
        .bind(assurance_value(input.interaction_minimum_assurance))
        .bind(&interaction_scope_descriptions)
        .bind(&interaction_scope_newly_requested)
        .bind(input.interaction_requirement.as_db())
        .bind(input.created_at)
        .bind(input.expires_at)
        .execute(&mut **transaction)
        .await
        .map_err(|error| map_db(&error))?;
        if result.rows_affected() == 1 {
            Ok(id)
        } else {
            Err(OAuthStoreError::Inactive)
        }
    }

    /// Loads a live pending authorization request, atomically expiring it when necessary.
    ///
    /// # Errors
    ///
    /// Returns [`OAuthStoreError`] if stored request data is corrupt or PostgreSQL cannot
    /// complete the transaction.
    pub async fn load_authorization_request(
        &self,
        digest: &BearerDigest,
        now: OffsetDateTime,
    ) -> Result<AuthorizationRequestLoad, OAuthStoreError> {
        let mut connection = self
            .pool
            .acquire()
            .await
            .map_err(|_| OAuthStoreError::Unavailable)?;
        let mut transaction = connection.begin().await.map_err(|error| map_db(&error))?;
        let result = load_authorization_request_with(&mut transaction, digest, now).await;
        finish(transaction, result).await
    }

    /// Caller-owned transaction variant of [`Self::load_authorization_request`].
    ///
    /// # Errors
    ///
    /// Returns [`OAuthStoreError`] if stored request data is corrupt or PostgreSQL cannot
    /// complete the caller-owned transaction.
    pub async fn load_authorization_request_with(
        &self,
        transaction: &mut Transaction<'_, Postgres>,
        digest: &BearerDigest,
        now: OffsetDateTime,
    ) -> Result<AuthorizationRequestLoad, OAuthStoreError> {
        load_authorization_request_with(transaction, digest, now).await
    }

    /// Atomically applies an approve/deny transition once.
    ///
    /// # Errors
    ///
    /// Returns [`OAuthStoreError`] if stored request data is corrupt or PostgreSQL cannot
    /// complete the transaction.
    pub async fn transition_authorization_request(
        &self,
        digest: &BearerDigest,
        decision: AuthorizationDecision,
        now: OffsetDateTime,
    ) -> Result<AuthorizationTransition, OAuthStoreError> {
        let mut connection = self
            .pool
            .acquire()
            .await
            .map_err(|_| OAuthStoreError::Unavailable)?;
        let mut transaction = connection.begin().await.map_err(|error| map_db(&error))?;
        let result =
            transition_authorization_request_with(&mut transaction, digest, decision, now).await;
        finish(transaction, result).await
    }

    /// Caller-owned transaction variant of [`Self::transition_authorization_request`].
    ///
    /// # Errors
    ///
    /// Returns [`OAuthStoreError`] if stored request data is corrupt or PostgreSQL cannot
    /// complete the caller-owned transaction.
    pub async fn transition_authorization_request_with(
        &self,
        transaction: &mut Transaction<'_, Postgres>,
        digest: &BearerDigest,
        decision: AuthorizationDecision,
        now: OffsetDateTime,
    ) -> Result<AuthorizationTransition, OAuthStoreError> {
        transition_authorization_request_with(transaction, digest, decision, now).await
    }
}

async fn load_authorization_request_with(
    transaction: &mut Transaction<'_, Postgres>,
    digest: &BearerDigest,
    now: OffsetDateTime,
) -> Result<AuthorizationRequestLoad, OAuthStoreError> {
    let row = sqlx::query(
        "SELECT request.id, request.client_id AS internal_client_id, request.redirect_uri, \
                request.response_type, request.response_mode, request.client_state, \
                request.requested_scopes, request.resource_uris, request.pkce_code_challenge, \
                request.nonce, request.prompt_values, request.max_age_seconds, \
                request.expected_issuer, request.interaction_resource_name, \
                request.interaction_resource_description, request.interaction_minimum_assurance, \
                request.interaction_scope_descriptions, request.interaction_scope_newly_requested, \
                request.interaction_requirement, request.status, request.created_at, \
                request.expires_at, request.completed_at, client.status AS client_status \
         FROM oauth_authorization_requests request \
         JOIN oauth_clients client ON client.id = request.client_id \
         WHERE request.request_handle_digest = $1 FOR UPDATE OF request",
    )
    .bind(digest.as_bytes().as_slice())
    .fetch_optional(&mut **transaction)
    .await
    .map_err(|error| map_db(&error))?;
    let Some(row) = row else {
        return Ok(AuthorizationRequestLoad::Unavailable);
    };
    let status = AuthorizationRequestStatus::from_db(
        &row.try_get::<String, _>("status")
            .map_err(|_| OAuthStoreError::CorruptData)?,
    )?;
    let client_status = ClientStatus::from_db(
        &row.try_get::<String, _>("client_status")
            .map_err(|_| OAuthStoreError::CorruptData)?,
    )?;
    if status != AuthorizationRequestStatus::Pending || client_status != ClientStatus::Active {
        return Ok(AuthorizationRequestLoad::Unavailable);
    }
    let expires_at: OffsetDateTime = row
        .try_get("expires_at")
        .map_err(|_| OAuthStoreError::CorruptData)?;
    if now >= expires_at {
        sqlx::query(
            "UPDATE oauth_authorization_requests SET status = 'expired', completed_at = $2 \
             WHERE id = $1 AND status = 'pending'",
        )
        .bind(
            row.try_get::<Uuid, _>("id")
                .map_err(|_| OAuthStoreError::CorruptData)?,
        )
        .bind(now)
        .execute(&mut **transaction)
        .await
        .map_err(|error| map_db(&error))?;
        return Ok(AuthorizationRequestLoad::Expired);
    }
    let internal_id = oauth_client_id(
        row.try_get("internal_client_id")
            .map_err(|_| OAuthStoreError::CorruptData)?,
    )?;
    let client = load_client_by_internal_id(transaction, internal_id).await?;
    Ok(AuthorizationRequestLoad::Pending(Box::new(
        authorization_request_from_row(&row, client)?,
    )))
}

async fn transition_authorization_request_with(
    transaction: &mut Transaction<'_, Postgres>,
    digest: &BearerDigest,
    decision: AuthorizationDecision,
    now: OffsetDateTime,
) -> Result<AuthorizationTransition, OAuthStoreError> {
    match load_authorization_request_with(transaction, digest, now).await? {
        AuthorizationRequestLoad::Expired => Ok(AuthorizationTransition::Expired),
        AuthorizationRequestLoad::Unavailable => Ok(AuthorizationTransition::Unavailable),
        AuthorizationRequestLoad::Pending(mut request) => {
            let result = sqlx::query(
                "UPDATE oauth_authorization_requests SET status = $2, completed_at = $3 \
                 WHERE id = $1 AND status = 'pending'",
            )
            .bind(request.id.as_uuid())
            .bind(decision.status())
            .bind(now)
            .execute(&mut **transaction)
            .await
            .map_err(|error| map_db(&error))?;
            if result.rows_affected() != 1 {
                return Ok(AuthorizationTransition::Unavailable);
            }
            request.status = match decision {
                AuthorizationDecision::Approve => AuthorizationRequestStatus::Approved,
                AuthorizationDecision::Deny => AuthorizationRequestStatus::Denied,
            };
            request.completed_at = Some(now);
            Ok(AuthorizationTransition::Completed(request))
        }
    }
}

fn authorization_interaction_scopes_from_row(
    row: &PgRow,
    requested_scopes: &[Scope],
) -> Result<Vec<AuthorizationInteractionScope>, OAuthStoreError> {
    let descriptions: Vec<String> = row
        .try_get("interaction_scope_descriptions")
        .map_err(|_| OAuthStoreError::CorruptData)?;
    let newly_requested: Vec<bool> = row
        .try_get("interaction_scope_newly_requested")
        .map_err(|_| OAuthStoreError::CorruptData)?;
    if descriptions.len() != requested_scopes.len()
        || newly_requested.len() != requested_scopes.len()
    {
        return Err(OAuthStoreError::CorruptData);
    }
    Ok(requested_scopes
        .iter()
        .cloned()
        .zip(descriptions)
        .zip(newly_requested)
        .map(
            |((name, description), newly_requested)| AuthorizationInteractionScope {
                name,
                description,
                newly_requested,
            },
        )
        .collect())
}

fn authorization_request_from_row(
    row: &PgRow,
    client: RegisteredClient,
) -> Result<AuthorizationRequestRecord, OAuthStoreError> {
    let max_age: Option<i64> = row
        .try_get("max_age_seconds")
        .map_err(|_| OAuthStoreError::CorruptData)?;
    let requested_scopes = parse_scopes(
        row.try_get("requested_scopes")
            .map_err(|_| OAuthStoreError::CorruptData)?,
    )?;
    let interaction_scopes = authorization_interaction_scopes_from_row(row, &requested_scopes)?;
    Ok(AuthorizationRequestRecord {
        id: authorization_request_id(
            row.try_get("id")
                .map_err(|_| OAuthStoreError::CorruptData)?,
        )?,
        client,
        redirect_uri: RedirectUri::parse(
            row.try_get::<String, _>("redirect_uri")
                .map_err(|_| OAuthStoreError::CorruptData)?,
        )
        .map_err(|_| OAuthStoreError::CorruptData)?,
        response_type: parse_response_type(
            &row.try_get::<String, _>("response_type")
                .map_err(|_| OAuthStoreError::CorruptData)?,
        )?,
        response_mode: parse_response_mode(
            &row.try_get::<String, _>("response_mode")
                .map_err(|_| OAuthStoreError::CorruptData)?,
        )?,
        client_state: row
            .try_get("client_state")
            .map_err(|_| OAuthStoreError::CorruptData)?,
        requested_scopes,
        resource_uris: parse_resources(
            row.try_get("resource_uris")
                .map_err(|_| OAuthStoreError::CorruptData)?,
        )?,
        pkce_code_challenge: PkceChallenge::parse(
            row.try_get::<String, _>("pkce_code_challenge")
                .map_err(|_| OAuthStoreError::CorruptData)?,
        )
        .map_err(|_| OAuthStoreError::CorruptData)?,
        nonce: row
            .try_get("nonce")
            .map_err(|_| OAuthStoreError::CorruptData)?,
        prompt_values: parse_prompts(
            row.try_get("prompt_values")
                .map_err(|_| OAuthStoreError::CorruptData)?,
        )?,
        max_age_seconds: max_age
            .map(u64::try_from)
            .transpose()
            .map_err(|_| OAuthStoreError::CorruptData)?,
        expected_issuer: IssuerUri::parse(
            row.try_get::<String, _>("expected_issuer")
                .map_err(|_| OAuthStoreError::CorruptData)?,
            false,
        )
        .map_err(|_| OAuthStoreError::CorruptData)?,
        interaction_resource_name: row
            .try_get("interaction_resource_name")
            .map_err(|_| OAuthStoreError::CorruptData)?,
        interaction_resource_description: row
            .try_get("interaction_resource_description")
            .map_err(|_| OAuthStoreError::CorruptData)?,
        interaction_minimum_assurance: parse_assurance(
            &row.try_get::<String, _>("interaction_minimum_assurance")
                .map_err(|_| OAuthStoreError::CorruptData)?,
        )?,
        interaction_scopes,
        interaction_requirement: AuthorizationInteractionRequirement::from_db(
            &row.try_get::<String, _>("interaction_requirement")
                .map_err(|_| OAuthStoreError::CorruptData)?,
        )?,
        status: AuthorizationRequestStatus::from_db(
            &row.try_get::<String, _>("status")
                .map_err(|_| OAuthStoreError::CorruptData)?,
        )?,
        created_at: row
            .try_get("created_at")
            .map_err(|_| OAuthStoreError::CorruptData)?,
        expires_at: row
            .try_get("expires_at")
            .map_err(|_| OAuthStoreError::CorruptData)?,
        completed_at: row
            .try_get("completed_at")
            .map_err(|_| OAuthStoreError::CorruptData)?,
    })
}

fn validate_authorization_request(
    input: &AuthorizationRequestCreate,
) -> Result<(), OAuthStoreError> {
    if input.expires_at <= input.created_at
        || input.expires_at > input.created_at + Duration::minutes(15)
        || input.client_state.as_ref().is_some_and(|value| {
            value.is_empty() || value.len() > MAX_STATE_BYTES || value.chars().any(char::is_control)
        })
        || input
            .nonce
            .as_ref()
            .is_some_and(|value| !valid_visible_text(value, MAX_NONCE_BYTES))
        || input
            .max_age_seconds
            .is_some_and(|value| value > 31_536_000)
        || !valid_trimmed_text(&input.interaction_resource_name, MAX_RESOURCE_NAME_BYTES)
        || !valid_trimmed_text(
            &input.interaction_resource_description,
            MAX_RESOURCE_DESCRIPTION_BYTES,
        )
        || input.interaction_scopes.len() != input.requested_scopes.len()
        || input
            .interaction_scopes
            .iter()
            .zip(&input.requested_scopes)
            .any(|(interaction, requested)| {
                &interaction.name != requested
                    || !valid_trimmed_text(&interaction.description, MAX_SCOPE_DESCRIPTION_BYTES)
            })
    {
        return Err(OAuthStoreError::InvalidInput);
    }
    scope_values(&input.requested_scopes)?;
    resource_values(&input.resource_uris)?;
    prompt_values(&input.prompt_values)?;
    Ok(())
}

fn prompt_values(values: &[Prompt]) -> Result<Vec<String>, OAuthStoreError> {
    let result = values
        .iter()
        .copied()
        .map(prompt_value)
        .map(str::to_owned)
        .collect::<Vec<_>>();
    if result.len() > 3
        || result.windows(2).any(|pair| pair[0] >= pair[1])
        || result.iter().any(|value| value == "none") && result.len() != 1
    {
        return Err(OAuthStoreError::InvalidInput);
    }
    Ok(result)
}

const fn response_mode_value(value: ResponseMode) -> &'static str {
    match value {
        ResponseMode::Query => "query",
    }
}

const fn prompt_value(value: Prompt) -> &'static str {
    match value {
        Prompt::None => "none",
        Prompt::Login => "login",
        Prompt::Consent => "consent",
    }
}

fn parse_response_mode(value: &str) -> Result<ResponseMode, OAuthStoreError> {
    match value {
        "query" => Ok(ResponseMode::Query),
        _ => Err(OAuthStoreError::CorruptData),
    }
}

fn parse_prompts(values: Vec<String>) -> Result<Vec<Prompt>, OAuthStoreError> {
    values
        .into_iter()
        .map(|value| match value.as_str() {
            "none" => Ok(Prompt::None),
            "login" => Ok(Prompt::Login),
            "consent" => Ok(Prompt::Consent),
            _ => Err(OAuthStoreError::CorruptData),
        })
        .collect()
}

fn authorization_request_id(value: Uuid) -> Result<AuthorizationRequestId, OAuthStoreError> {
    AuthorizationRequestId::from_uuid(value)
}

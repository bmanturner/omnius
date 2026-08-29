//! Production bridge between the transport-neutral OAuth state machines and PostgreSQL.

use std::{future::Future, pin::Pin, sync::Arc};

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode, decode_header};
use omnius_auth_core::{AssuranceLevel, AuthMethod, Principal, PrincipalKind, Scope, SubjectId};
use serde::Deserialize;
use sqlx::{Connection as _, Postgres, Transaction};
use thiserror::Error;
use time::OffsetDateTime;
use url::Url;

use crate::{
    Clock, EntropySource,
    client::{ClientMetadataResolver, ClientMetadataResolverError, ResolvedClientMetadata},
    crypto::{BearerDigestDomain, RsaPublicJwk, TokenPepper, issue_bearer, verify_bearer_digest},
    service::{
        AuthorizationInteraction, AuthorizationStore, AuthorizationSubject,
        CommitAuthorizationDecision, CommitDecisionOutcome, ConnectedGrant, ConsentDecision,
        ConsumeAuthorizationCode, ConsumeCodeOutcome, CoveringGrantQuery, CreateAuthorization,
        ExistingGrant, InteractionRequirement, InteractionScope, LogoutSession,
        PrivateKeyJwtAssertion, ResolvedClient, RevocationTarget, RotateRefreshOutcome,
        RotateRefreshToken, SessionCandidate, StoredAuthorization, TokenGrantContext,
    },
    store::{
        AccessTokenLiveCheck as StoreAccessTokenLiveCheck, AuthorizationCodeBinding,
        AuthorizationCodeCreate, AuthorizationCodeExchange, AuthorizationDecision,
        AuthorizationInteractionRequirement as StoreInteractionRequirement,
        AuthorizationInteractionScope as StoreInteractionScope, AuthorizationRequestCreate,
        AuthorizationRequestLoad, AuthorizationRequestRecord, AuthorizationTransition,
        ClientAssertionRecord, ClientDisableOutcome, ClientMetadataCache, ClientSource,
        ClientStatus, ClientUpsert, ConnectedGrant as StoreConnectedGrant, GrantCreate, LiveGrant,
        OAuthPostgresStore, PublicSubject, RefreshFamilyIssue, RefreshRotation, RegisteredClient,
    },
    types::{
        AuthorizationRequestInput, AuthorizationRequestParts, ClientId, ClientMetadata,
        ClientMetadataInput, IssuerUri, OpaqueBearer, Prompt, ResourceUri, ResponseMode,
        ResponseType, TokenEndpointAuthMethod,
    },
    verifier::{
        AccessTokenIdentity, AccessTokenLiveCheck, AccessTokenStateStore,
        OAuthStoreError as StateStoreError,
    },
};

const TOKEN_PATH: &str = "/oauth/token";
const USERINFO_PATH: &str = "/oauth/userinfo";
const PUBLIC_SUBJECT_BYTES: usize = 32;
const MAX_CONNECTED_GRANTS: u16 = 100;
const MAX_ASSERTION_LIFETIME_SECONDS: i64 = 300;
const MAX_CLIENT_METADATA_BYTES: usize = 256 * 1_024;

/// A session identity revalidated by the application-owned browser-session authority.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthorizedBrowserSession {
    /// Canonical current principal, including assurance and tenant context.
    pub principal: Principal,
    /// Authentication methods established for the browser session.
    pub authentication_methods: Vec<AuthMethod>,
}

/// Value-free browser-session authority failure.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[error("browser session authority is unavailable")]
pub struct SessionAuthorityError;

/// Narrow port that keeps provider session IDs and cookie mutation outside this crate.
pub trait OAuthSessionAuthority: Send + Sync {
    /// Revalidates the exact browser-session candidate and returns its current assurance.
    fn authorize_session(
        &self,
        candidate: SessionCandidate,
    ) -> Pin<
        Box<
            dyn Future<Output = Result<Option<AuthorizedBrowserSession>, SessionAuthorityError>>
                + Send
                + '_,
        >,
    >;

    /// Proves that the current opaque application session remains bound to this subject.
    fn validate_logout_binding(
        &self,
        command: LogoutSession,
    ) -> Pin<Box<dyn Future<Output = Result<bool, SessionAuthorityError>> + Send + '_>>;
}

/// Injectable CIMD resolution port; production uses [`ClientMetadataResolver`].
pub trait OAuthClientMetadataResolver: Send + Sync {
    /// Resolves one URL-form client identifier under the implementation's SSRF policy.
    fn resolve<'a>(
        &'a self,
        client_id: &'a ClientId,
    ) -> Pin<
        Box<
            dyn Future<Output = Result<ResolvedClientMetadata, ClientMetadataResolverError>>
                + Send
                + 'a,
        >,
    >;
}

impl OAuthClientMetadataResolver for ClientMetadataResolver {
    fn resolve<'a>(
        &'a self,
        client_id: &'a ClientId,
    ) -> Pin<
        Box<
            dyn Future<Output = Result<ResolvedClientMetadata, ClientMetadataResolverError>>
                + Send
                + 'a,
        >,
    > {
        Box::pin(ClientMetadataResolver::resolve(self, client_id))
    }
}

/// Safe typed events appended by the application audit adapter on the caller transaction.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum OAuthAuditEvent {
    /// A validated authorization interaction was persisted.
    AuthorizationRequestCreated {
        /// Resolved client owning the interaction.
        client_id: ClientId,
    },
    /// Consent was approved and a code was persisted.
    AuthorizationApproved {
        /// Stable public subject that approved access.
        subject_id: SubjectId,
        /// Client receiving the authorization.
        client_id: ClientId,
        /// Durable grant created or reused.
        grant_id: crate::types::GrantId,
    },
    /// Consent was denied.
    AuthorizationDenied {
        /// Stable public subject that denied access.
        subject_id: SubjectId,
        /// Client whose request was denied.
        client_id: ClientId,
    },
    /// A private-key assertion replay key was accepted.
    ClientAssertionAccepted {
        /// Client whose assertion replay key was recorded.
        client_id: ClientId,
    },
    /// A code was consumed successfully.
    AuthorizationCodeExchanged {
        /// Subject bound to the exchanged code.
        subject_id: SubjectId,
        /// Client that exchanged the code.
        client_id: ClientId,
        /// Grant authorizing the issued tokens.
        grant_id: crate::types::GrantId,
    },
    /// A refresh member was rotated.
    RefreshRotated {
        /// Subject bound to the refresh family.
        subject_id: SubjectId,
        /// Client that rotated the refresh token.
        client_id: ClientId,
        /// Grant authorizing the refreshed tokens.
        grant_id: crate::types::GrantId,
    },
    /// Refresh-token reuse revoked its family and grant.
    RefreshReuseDetected {
        /// Grant revoked after refresh-token reuse.
        grant_id: crate::types::GrantId,
    },
    /// RFC 7009 changed known durable state.
    TokenRevoked {
        /// Authenticated client that submitted the token.
        client_id: ClientId,
        /// Grant revoked when the token identified one.
        grant_id: Option<crate::types::GrantId>,
    },
    /// A user revoked a connected grant.
    ConnectedGrantRevoked {
        /// Subject that revoked the connected application.
        subject_id: SubjectId,
        /// Grant revoked by the subject.
        grant_id: crate::types::GrantId,
    },
    /// An administrator or DCR path persisted validated client metadata.
    ClientRegistered {
        /// Newly registered client identifier.
        client_id: ClientId,
    },
    /// A valid HTTPS Client ID Metadata Document was persisted.
    ClientMetadataAccepted,
    /// A Client ID Metadata Document was rejected without retaining its contents.
    ClientMetadataRejected,
    /// An administrator disabled a client and its derived authority.
    ClientDisabled {
        /// Disabled client identifier.
        client_id: ClientId,
    },
}

/// Value-free audit append failure.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[error("OAuth audit append failed")]
pub struct OAuthAuditError;

/// Caller-owned transaction audit port.
pub trait OAuthAuditSink: Send + Sync {
    /// Appends one safe event using the exact transaction that owns the protected mutation.
    fn append<'a>(
        &'a self,
        transaction: &'a mut Transaction<'_, Postgres>,
        event: OAuthAuditEvent,
    ) -> Pin<Box<dyn Future<Output = Result<(), OAuthAuditError>> + Send + 'a>>;
}

/// Value-free adapter configuration rejection.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[error("OAuth PostgreSQL adapter configuration is invalid")]
pub struct PostgresAdapterConfigError;

/// Value-free record mapping rejection.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[error("OAuth PostgreSQL record cannot be mapped safely")]
pub struct PostgresRecordMappingError;

/// Safe durable registration result plus an optional one-time confidential secret.
pub struct OnboardedClient {
    /// Registered safe client metadata.
    pub client: RegisteredClient,
    /// Generated confidential secret, absent for public and private-key clients.
    pub client_secret: Option<OpaqueBearer>,
}

impl std::fmt::Debug for OnboardedClient {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("OnboardedClient")
            .field("client", &self.client)
            .field(
                "client_secret",
                &self.client_secret.as_ref().map(|_| "[REDACTED]"),
            )
            .finish()
    }
}

/// Cloneable production implementation of both OAuth state-store contracts.
pub struct PostgresOAuthAdapter<C, E, A, S, M = ClientMetadataResolver> {
    store: OAuthPostgresStore,
    pepper: Arc<TokenPepper>,
    issuer: IssuerUri,
    client_metadata: Arc<M>,
    dynamic_client_registration_enabled: bool,
    local_identity_provider: Arc<str>,
    clock: Arc<C>,
    entropy: Arc<E>,
    audit: Arc<A>,
    sessions: Arc<S>,
}

impl<C, E, A, S, M> Clone for PostgresOAuthAdapter<C, E, A, S, M> {
    fn clone(&self) -> Self {
        Self {
            store: self.store.clone(),
            pepper: Arc::clone(&self.pepper),
            issuer: self.issuer.clone(),
            client_metadata: Arc::clone(&self.client_metadata),
            dynamic_client_registration_enabled: self.dynamic_client_registration_enabled,
            local_identity_provider: Arc::clone(&self.local_identity_provider),
            clock: Arc::clone(&self.clock),
            entropy: Arc::clone(&self.entropy),
            audit: Arc::clone(&self.audit),
            sessions: Arc::clone(&self.sessions),
        }
    }
}

impl<C, E, A, S, M> std::fmt::Debug for PostgresOAuthAdapter<C, E, A, S, M> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PostgresOAuthAdapter")
            .field("issuer", &self.issuer)
            .field("local_identity_provider", &"[REDACTED]")
            .finish_non_exhaustive()
    }
}

impl<C, E, A, S, M> PostgresOAuthAdapter<C, E, A, S, M>
where
    C: Clock,
    E: EntropySource,
    A: OAuthAuditSink,
    S: OAuthSessionAuthority,
    M: OAuthClientMetadataResolver,
{
    /// Builds the production adapter from explicit protocol-neutral authorities.
    pub fn new(
        store: OAuthPostgresStore,
        pepper: TokenPepper,
        issuer: IssuerUri,
        client_metadata: Arc<M>,
        dynamic_client_registration_enabled: bool,
        local_identity_provider: String,
        clock: Arc<C>,
        entropy: Arc<E>,
        audit: Arc<A>,
        sessions: Arc<S>,
    ) -> Result<Self, PostgresAdapterConfigError> {
        if local_identity_provider.is_empty()
            || local_identity_provider.len() > 255
            || local_identity_provider.chars().any(char::is_control)
        {
            return Err(PostgresAdapterConfigError);
        }
        Ok(Self {
            store,
            pepper: Arc::new(pepper),
            issuer,
            client_metadata,
            local_identity_provider: local_identity_provider.into(),
            dynamic_client_registration_enabled,
            clock,
            entropy,
            audit,
            sessions,
        })
    }

    /// Borrows the durable store for administrative composition and supervised cleanup.
    #[must_use]
    pub const fn store(&self) -> &OAuthPostgresStore {
        &self.store
    }

    /// Parses strict administrator metadata JSON containing its required `client_id`.
    pub async fn register_pre_registered_json(
        &self,
        input: &[u8],
        max_bytes: usize,
    ) -> Result<OnboardedClient, StateStoreError> {
        if input.is_empty()
            || max_bytes == 0
            || max_bytes > MAX_CLIENT_METADATA_BYTES
            || input.len() > max_bytes
        {
            return Err(StateStoreError);
        }
        let mut raw: ClientMetadataInput =
            serde_json::from_slice(input).map_err(|_| StateStoreError)?;
        let client_id = raw.client_id.take().ok_or(StateStoreError)?;
        let metadata = ClientMetadata::validate(raw, None).map_err(|_| StateStoreError)?;
        self.register_pre_registered_client(client_id, metadata)
            .await
    }

    /// Registers validated administrator-provided metadata and reveals a generated secret once.
    pub async fn register_pre_registered_client(
        &self,
        client_id: ClientId,
        metadata: ClientMetadata,
    ) -> Result<OnboardedClient, StateStoreError> {
        self.register_validated_client(client_id, metadata, ClientSource::PreRegistered)
            .await
    }

    /// Performs optional DCR onboarding from validated metadata and a server-generated client ID.
    pub async fn register_dynamic_client(
        &self,
        metadata: ClientMetadata,
    ) -> Result<OnboardedClient, StateStoreError> {
        if !self.dynamic_client_registration_enabled {
            return Err(StateStoreError);
        }
        let mut bytes = [0_u8; PUBLIC_SUBJECT_BYTES];
        self.entropy
            .try_fill(&mut bytes)
            .map_err(|_| StateStoreError)?;
        let client_id = ClientId::parse(format!("omnius_{}", URL_SAFE_NO_PAD.encode(bytes)))
            .map_err(|_| StateStoreError)?;
        self.register_validated_client(client_id, metadata, ClientSource::Dynamic)
            .await
    }

    async fn register_validated_client(
        &self,
        client_id: ClientId,
        metadata: ClientMetadata,
        source: ClientSource,
    ) -> Result<OnboardedClient, StateStoreError> {
        if metadata.client_id().is_some() || source == ClientSource::ClientIdMetadata {
            return Err(StateStoreError);
        }
        let issued_secret = if metadata.token_endpoint_auth_method()
            == TokenEndpointAuthMethod::ClientSecretBasic
        {
            Some(
                issue_bearer(
                    self.entropy.as_ref(),
                    &self.pepper,
                    BearerDigestDomain::ClientSecret,
                )
                .map_err(|_| StateStoreError)?,
            )
        } else {
            None
        };
        let input = client_upsert_from_metadata(
            client_id.clone(),
            &metadata,
            source,
            issued_secret.as_ref().map(|issued| issued.digest.clone()),
            self.clock.now_utc(),
        );
        let mut connection = self
            .store
            .pool()
            .acquire()
            .await
            .map_err(|_| StateStoreError)?;
        let mut transaction = connection.begin().await.map_err(|_| StateStoreError)?;
        let result = async {
            let registered = self
                .store
                .upsert_client_with(&mut transaction, &input)
                .await
                .map_err(|_| AdapterOperationError)?;
            self.audit
                .append(
                    &mut transaction,
                    OAuthAuditEvent::ClientRegistered { client_id },
                )
                .await
                .map_err(|_| AdapterOperationError)?;
            Ok(registered)
        }
        .await;
        let client = finish_operation(transaction, result).await?;
        Ok(OnboardedClient {
            client,
            client_secret: issued_secret.map(|issued| issued.presentation),
        })
    }

    /// Disables a client and audits all resulting revocation state atomically.
    pub async fn disable_client(
        &self,
        client_id: &ClientId,
    ) -> Result<Option<ClientDisableOutcome>, StateStoreError> {
        let now = self.clock.now_utc();
        let mut connection = self
            .store
            .pool()
            .acquire()
            .await
            .map_err(|_| StateStoreError)?;
        let mut transaction = connection.begin().await.map_err(|_| StateStoreError)?;
        let result = async {
            let outcome = self
                .store
                .disable_client_with(&mut transaction, client_id, now)
                .await
                .map_err(|_| AdapterOperationError)?;
            if outcome.is_some_and(|value| value.newly_disabled) {
                self.audit
                    .append(
                        &mut transaction,
                        OAuthAuditEvent::ClientDisabled {
                            client_id: client_id.clone(),
                        },
                    )
                    .await
                    .map_err(|_| AdapterOperationError)?;
            }
            Ok(outcome)
        }
        .await;
        finish_operation(transaction, result).await
    }

    fn next_public_subject(&self) -> Result<PublicSubject, StateStoreError> {
        let mut bytes = [0_u8; PUBLIC_SUBJECT_BYTES];
        self.entropy
            .try_fill(&mut bytes)
            .map_err(|_| StateStoreError)?;
        PublicSubject::parse(URL_SAFE_NO_PAD.encode(bytes)).map_err(|_| StateStoreError)
    }

    fn token_endpoint(&self) -> String {
        self.issuer.endpoint(TOKEN_PATH)
    }

    fn effective_resource(
        &self,
        record: &AuthorizationRequestRecord,
    ) -> Result<ResourceUri, PostgresRecordMappingError> {
        match record.resource_uris.as_slice() {
            [resource] => Ok(resource.clone()),
            [] if record
                .requested_scopes
                .iter()
                .any(|scope| scope.as_str() == "openid") =>
            {
                ResourceUri::parse(self.issuer.endpoint(USERINFO_PATH), false)
                    .map_err(|_| PostgresRecordMappingError)
            }
            _ => Err(PostgresRecordMappingError),
        }
    }

    fn token_context(
        &self,
        grant: LiveGrant,
        resource: ResourceUri,
        scopes: Vec<Scope>,
        nonce: Option<String>,
        verified_email: Option<crate::store::VerifiedEmail>,
        refresh_allowed: bool,
    ) -> Result<TokenGrantContext, AdapterOperationError> {
        if !grant.resources.contains(&resource)
            || scopes
                .iter()
                .any(|scope| grant.granted_scopes.binary_search(scope).is_err())
        {
            return Err(AdapterOperationError);
        }
        Ok(TokenGrantContext {
            grant_id: grant.id,
            client_id: grant.client_id,
            public_subject: grant.public_subject.as_str().to_owned(),
            resource,
            scopes,
            auth_time: grant.authenticated_at,
            acr: assurance_name(grant.assurance_level).to_owned(),
            amr: grant
                .authentication_methods
                .iter()
                .copied()
                .map(auth_method_name)
                .map(str::to_owned)
                .collect(),
            nonce,
            verified_email: verified_email.map(|email| email.as_str().to_owned()),
            refresh_allowed,
        })
    }

    async fn resolve_client_metadata(
        &self,
        client_id: &ClientId,
    ) -> Result<Option<ResolvedClient>, StateStoreError> {
        let resolved = match self.client_metadata.resolve(client_id).await {
            Ok(resolved) => resolved,
            Err(error) => {
                self.audit_metadata_decision(OAuthAuditEvent::ClientMetadataRejected)
                    .await?;
                return if permanent_metadata_rejection(error) {
                    Ok(None)
                } else {
                    Err(StateStoreError)
                };
            }
        };
        let input = self
            .client_metadata_upsert(client_id, &resolved)
            .map_err(|_| StateStoreError)?;
        let mut connection = self
            .store
            .pool()
            .acquire()
            .await
            .map_err(|_| StateStoreError)?;
        let mut transaction = connection.begin().await.map_err(|_| StateStoreError)?;
        let result = async {
            let registered = self
                .store
                .upsert_client_with(&mut transaction, &input)
                .await
                .map_err(|_| AdapterOperationError)?;
            self.audit
                .append(&mut transaction, OAuthAuditEvent::ClientMetadataAccepted)
                .await
                .map_err(|_| AdapterOperationError)?;
            map_registered_client(registered).map_err(|_| AdapterOperationError)
        }
        .await;
        finish_operation(transaction, result).await.map(Some)
    }

    fn client_metadata_upsert(
        &self,
        client_id: &ClientId,
        resolved: &ResolvedClientMetadata,
    ) -> Result<ClientUpsert, PostgresRecordMappingError> {
        let metadata = resolved.metadata();
        if metadata.client_id() != Some(client_id) {
            return Err(PostgresRecordMappingError);
        }
        let metadata_cache = if resolved.is_cacheable() {
            Some(ClientMetadataCache {
                body: serde_json::from_slice(resolved.document_bytes())
                    .map_err(|_| PostgresRecordMappingError)?,
                etag: resolved.validators().etag().map(str::to_owned),
                last_modified: resolved.validators().last_modified().map(str::to_owned),
                cached_at: self.clock.now_utc(),
                expires_at: resolved.expires_at(),
            })
        } else {
            None
        };
        Ok(ClientUpsert {
            client_id: client_id.clone(),
            source: ClientSource::ClientIdMetadata,
            display_name: metadata.client_name().to_owned(),
            client_uri: None,
            logo_uri: None,
            application_type: metadata.application_type(),
            token_endpoint_auth_method: metadata.token_endpoint_auth_method(),
            client_secret_digest: None,
            response_types: metadata.response_types().to_vec(),
            grant_types: metadata.grant_types().to_vec(),
            allowed_scopes: metadata.scopes().to_vec(),
            public_jwks: metadata.jwks().cloned(),
            redirect_uris: metadata.redirect_uris().to_vec(),
            post_logout_redirect_uris: metadata.post_logout_redirect_uris().to_vec(),
            metadata_document_uri: Some(client_id.as_str().to_owned()),
            metadata_cache,
            now: self.clock.now_utc(),
        })
    }

    async fn audit_metadata_decision(&self, event: OAuthAuditEvent) -> Result<(), StateStoreError> {
        let mut connection = self
            .store
            .pool()
            .acquire()
            .await
            .map_err(|_| StateStoreError)?;
        let mut transaction = connection.begin().await.map_err(|_| StateStoreError)?;
        let result = self
            .audit
            .append(&mut transaction, event)
            .await
            .map_err(|_| AdapterOperationError);
        finish_operation(transaction, result).await
    }

    async fn verify_private_assertion(
        &self,
        transaction: &mut Transaction<'_, Postgres>,
        client_id: &ClientId,
        assertion: &PrivateKeyJwtAssertion,
    ) -> Result<bool, AdapterOperationError> {
        let authentication = self
            .store
            .load_client_authentication_with(transaction, client_id)
            .await
            .map_err(|_| AdapterOperationError)?;
        let Some(authentication) = authentication else {
            return Ok(false);
        };
        if authentication.method != TokenEndpointAuthMethod::PrivateKeyJwt {
            return Ok(false);
        }
        let Some(jwks_value) = authentication.public_jwks else {
            return Ok(false);
        };
        let header = match decode_header(assertion.token()) {
            Ok(header) => header,
            Err(_) => return Ok(false),
        };
        let Some(kid) = header.kid.as_deref() else {
            return Ok(false);
        };
        if header.alg != Algorithm::RS256
            || header.typ.as_deref() != Some("JWT")
            || header.cty.is_some()
            || header.jku.is_some()
            || header.jwk.is_some()
            || header.x5u.is_some()
            || header.x5c.is_some()
            || header.x5t.is_some()
            || header.x5t_s256.is_some()
            || header.crit.is_some()
            || header.enc.is_some()
            || header.zip.is_some()
            || header.url.is_some()
            || header.nonce.is_some()
            || !header.extras.inner().is_empty()
        {
            return Ok(false);
        }
        let document: ClientJwks = match serde_json::from_value(jwks_value) {
            Ok(document) => document,
            Err(_) => return Ok(false),
        };
        if document.keys.is_empty() || document.keys.len() > 8 {
            return Ok(false);
        }
        let mut matching = document.keys.iter().filter(|key| key.kid == kid);
        let Some(key) = matching.next() else {
            return Ok(false);
        };
        if matching.next().is_some() || key.validate_for_kid(kid).is_err() {
            return Ok(false);
        }
        let decoding_key = match DecodingKey::from_rsa_components(&key.n, &key.e) {
            Ok(key) => key,
            Err(_) => return Ok(false),
        };
        let mut validation = Validation::new(Algorithm::RS256);
        validation.algorithms = vec![Algorithm::RS256];
        validation.set_required_spec_claims(&["iss", "sub", "aud", "jti", "iat", "exp"]);
        validation.validate_exp = false;
        validation.validate_nbf = false;
        validation.validate_aud = false;
        let signed =
            match decode::<PrivateAssertionClaims>(assertion.token(), &decoding_key, &validation) {
                Ok(token) => token.claims,
                Err(_) => return Ok(false),
            };
        let issued_at = match OffsetDateTime::from_unix_timestamp(signed.iat) {
            Ok(value) => value,
            Err(_) => return Ok(false),
        };
        let expires_at = match OffsetDateTime::from_unix_timestamp(signed.exp) {
            Ok(value) => value,
            Err(_) => return Ok(false),
        };
        let now = self.clock.now_utc();
        let audience_matches = signed.aud.matches_exact(&self.token_endpoint());
        if signed.iss != client_id.as_str()
            || signed.sub != client_id.as_str()
            || signed.jti != assertion.jwt_id
            || issued_at != assertion.issued_at
            || expires_at != assertion.expires_at
            || &assertion.issuer != client_id
            || &assertion.subject != client_id
            || assertion.audience != self.token_endpoint()
            || !audience_matches
            || issued_at > now
            || expires_at <= now
            || expires_at - issued_at > time::Duration::seconds(MAX_ASSERTION_LIFETIME_SECONDS)
        {
            return Ok(false);
        }
        let recorded = self
            .store
            .record_client_assertion_with(
                transaction,
                client_id,
                &signed.jti,
                issued_at,
                expires_at,
            )
            .await
            .map_err(|_| AdapterOperationError)?;
        if recorded != ClientAssertionRecord::Accepted {
            return Ok(false);
        }
        self.audit
            .append(
                transaction,
                OAuthAuditEvent::ClientAssertionAccepted {
                    client_id: client_id.clone(),
                },
            )
            .await
            .map_err(|_| AdapterOperationError)?;
        Ok(true)
    }
}

impl<C, E, A, S, M> AccessTokenStateStore for PostgresOAuthAdapter<C, E, A, S, M>
where
    C: Clock + Send + Sync,
    E: EntropySource + Send + Sync,
    A: OAuthAuditSink,
    S: OAuthSessionAuthority,
    M: OAuthClientMetadataResolver,
{
    async fn authorize_access_token(
        &self,
        check: AccessTokenLiveCheck,
    ) -> Result<Option<AccessTokenIdentity>, StateStoreError> {
        let public_subject =
            PublicSubject::parse(check.public_subject).map_err(|_| StateStoreError)?;
        let identity = self
            .store
            .verify_access_token_live_identity(
                &StoreAccessTokenLiveCheck {
                    jti: check.jwt_id,
                    grant_id: check.grant_id,
                    public_subject,
                    client_id: check.client_id,
                    tenant_id: None,
                    resource: check.audience,
                    scopes: check.scopes,
                },
                &self.local_identity_provider,
                self.clock.now_utc(),
            )
            .await
            .map_err(|_| StateStoreError)?;
        Ok(identity.map(|identity| AccessTokenIdentity {
            subject_id: identity.grant.user_id,
            kind: PrincipalKind::User,
            tenant_id: identity.grant.tenant_id,
            authenticated_at: identity.grant.authenticated_at,
            assurance: identity.grant.assurance_level,
            public_subject: identity.grant.public_subject.as_str().to_owned(),
            verified_email: identity
                .verified_email
                .map(|email| email.as_str().to_owned()),
        }))
    }
}

impl<C, E, A, S, M> AuthorizationStore for PostgresOAuthAdapter<C, E, A, S, M>
where
    C: Clock + Send + Sync,
    E: EntropySource + Send + Sync,
    A: OAuthAuditSink,
    S: OAuthSessionAuthority,
    M: OAuthClientMetadataResolver,
{
    async fn resolve_client(
        &self,
        client_id: &ClientId,
    ) -> Result<Option<ResolvedClient>, StateStoreError> {
        if let Some(client) = self
            .store
            .load_client(client_id)
            .await
            .map_err(|_| StateStoreError)?
        {
            if client.status != ClientStatus::Active {
                return Ok(None);
            }
            if client.source != ClientSource::ClientIdMetadata
                || client
                    .metadata_cache_expires_at
                    .is_some_and(|expires_at| expires_at > self.clock.now_utc())
            {
                return map_registered_client(client)
                    .map(Some)
                    .map_err(|_| StateStoreError);
            }
        }
        self.resolve_client_metadata(client_id).await
    }

    async fn authorize_session(
        &self,
        candidate: SessionCandidate,
    ) -> Result<Option<AuthorizationSubject>, StateStoreError> {
        let authorized = self
            .sessions
            .authorize_session(candidate)
            .await
            .map_err(|_| StateStoreError)?;
        let Some(mut authorized) = authorized else {
            return Ok(None);
        };
        if authorized.principal.subject_id != candidate.subject_id
            || authorized.principal.authenticated_at != candidate.authenticated_at
            || authorized.principal.kind != PrincipalKind::User
            || authorized.principal.auth_method != AuthMethod::Session
            || authorized.authentication_methods.is_empty()
        {
            return Ok(None);
        }
        authorized
            .authentication_methods
            .sort_unstable_by_key(|method| auth_method_name(*method));
        authorized.authentication_methods.dedup();
        let state = self
            .store
            .authorize_subject(
                candidate.subject_id,
                self.next_public_subject()?,
                &self.local_identity_provider,
                self.clock.now_utc(),
            )
            .await
            .map_err(|_| StateStoreError)?;
        let assurance = authorized.principal.assurance;
        let amr = authorized
            .authentication_methods
            .into_iter()
            .map(auth_method_name)
            .map(str::to_owned)
            .collect();
        Ok(Some(AuthorizationSubject {
            principal: authorized.principal,
            public_subject: state.subject.public_subject.as_str().to_owned(),
            verified_email: state.verified_email.map(|email| email.as_str().to_owned()),
            acr: assurance_name(assurance).to_owned(),
            amr,
        }))
    }

    async fn find_covering_grant(
        &self,
        query: CoveringGrantQuery,
    ) -> Result<Option<ExistingGrant>, StateStoreError> {
        let grant = self
            .store
            .find_reusable_grant(
                query.subject_id,
                query.tenant_id,
                &query.client_id,
                std::slice::from_ref(&query.resource),
                &query.scopes,
            )
            .await
            .map_err(|_| StateStoreError)?;
        Ok(grant.map(|grant| ExistingGrant {
            grant_id: grant.id,
            resource: query.resource,
            offline_access_consented: grant
                .granted_scopes
                .iter()
                .any(|scope| scope.as_str() == "offline_access"),
            scopes: grant.granted_scopes,
        }))
    }
    async fn create_authorization(
        &self,
        command: CreateAuthorization,
    ) -> Result<(), StateStoreError> {
        let now = self.clock.now_utc();
        let request = &command.authorization.request;
        let interaction = &command.authorization.interaction;
        let input = AuthorizationRequestCreate {
            handle_digest: command.handle_digest,
            client_id: request.client_id().clone(),
            redirect_uri: request.redirect_uri().clone(),
            response_type: ResponseType::Code,
            response_mode: ResponseMode::Query,
            client_state: request.state().map(str::to_owned),
            requested_scopes: request.scopes().to_vec(),
            resource_uris: request.resources().to_vec(),
            pkce_code_challenge: request.pkce_challenge().clone(),
            nonce: request.nonce().map(str::to_owned),
            prompt_values: request.prompt().into_iter().collect(),
            max_age_seconds: request.max_age_seconds(),
            expected_issuer: request
                .expected_issuer()
                .cloned()
                .unwrap_or_else(|| self.issuer.clone()),
            interaction_resource_name: interaction.resource_name.clone(),
            interaction_resource_description: interaction.resource_description.clone(),
            interaction_minimum_assurance: interaction.minimum_assurance,
            interaction_scopes: interaction
                .scopes
                .iter()
                .map(|scope| StoreInteractionScope {
                    name: scope.name.clone(),
                    description: scope.description.clone(),
                    newly_requested: scope.newly_requested,
                })
                .collect(),
            interaction_requirement: store_interaction_requirement(interaction.requirement),
            created_at: now,
            expires_at: command.authorization.expires_at,
        };
        let mut connection = self
            .store
            .pool()
            .acquire()
            .await
            .map_err(|_| StateStoreError)?;
        let mut transaction = connection.begin().await.map_err(|_| StateStoreError)?;
        let result = async {
            self.store
                .create_authorization_request_with(&mut transaction, &input)
                .await
                .map_err(|_| AdapterOperationError)?;
            self.audit
                .append(
                    &mut transaction,
                    OAuthAuditEvent::AuthorizationRequestCreated {
                        client_id: input.client_id.clone(),
                    },
                )
                .await
                .map_err(|_| AdapterOperationError)?;
            Ok(())
        }
        .await;
        finish_operation(transaction, result).await
    }

    async fn load_authorization(
        &self,
        handle_digest: crate::crypto::BearerDigest,
        now: OffsetDateTime,
    ) -> Result<Option<StoredAuthorization>, StateStoreError> {
        match self
            .store
            .load_authorization_request(&handle_digest, now)
            .await
            .map_err(|_| StateStoreError)?
        {
            AuthorizationRequestLoad::Pending(record) => {
                map_stored_authorization(&self.issuer, record)
                    .map(Some)
                    .map_err(|_| StateStoreError)
            }
            AuthorizationRequestLoad::Expired | AuthorizationRequestLoad::Unavailable => Ok(None),
        }
    }

    async fn commit_authorization_decision(
        &self,
        command: CommitAuthorizationDecision,
    ) -> Result<CommitDecisionOutcome, StateStoreError> {
        let approve = command.decision == ConsentDecision::Approve;
        if approve != command.code_digest.is_some()
            || approve != command.code_expires_at.is_some()
            || command.subject.principal.kind != PrincipalKind::User
        {
            return Err(StateStoreError);
        }
        let now = self.clock.now_utc();
        let mut connection = self
            .store
            .pool()
            .acquire()
            .await
            .map_err(|_| StateStoreError)?;
        let mut transaction = connection.begin().await.map_err(|_| StateStoreError)?;
        let result = async {
            let decision = if approve {
                AuthorizationDecision::Approve
            } else {
                AuthorizationDecision::Deny
            };
            let transition = self
                .store
                .transition_authorization_request_with(
                    &mut transaction,
                    &command.handle_digest,
                    decision,
                    now,
                )
                .await
                .map_err(|_| AdapterOperationError)?;
            let record = match transition {
                AuthorizationTransition::Completed(record) => record,
                AuthorizationTransition::Expired | AuthorizationTransition::Unavailable => {
                    return Ok(CommitDecisionOutcome::Unavailable);
                }
            };
            if !approve {
                self.audit
                    .append(
                        &mut transaction,
                        OAuthAuditEvent::AuthorizationDenied {
                            subject_id: command.subject.principal.subject_id,
                            client_id: record.client.client_id,
                        },
                    )
                    .await
                    .map_err(|_| AdapterOperationError)?;
                return Ok(CommitDecisionOutcome::Denied);
            }
            let offline_requested = record
                .requested_scopes
                .iter()
                .any(|scope| scope.as_str() == "offline_access");
            if offline_requested != command.explicit_offline_consent {
                return Err(AdapterOperationError);
            }
            let resource = self
                .effective_resource(&record)
                .map_err(|_| AdapterOperationError)?;
            let resources = vec![resource];
            let reusable = if record.prompt_values.contains(&Prompt::Consent) {
                None
            } else {
                self.store
                    .find_reusable_grant_with(
                        &mut transaction,
                        command.subject.principal.subject_id,
                        command.subject.principal.tenant_id,
                        &record.client.client_id,
                        &resources,
                        &record.requested_scopes,
                    )
                    .await
                    .map_err(|_| AdapterOperationError)?
            };
            if command.require_existing_grant && reusable.is_none() {
                return Err(AdapterOperationError);
            }
            let grant = match reusable {
                Some(grant) => grant,
                None => self
                    .store
                    .create_grant_with(
                        &mut transaction,
                        &GrantCreate {
                            user_id: command.subject.principal.subject_id,
                            tenant_id: command.subject.principal.tenant_id,
                            client_id: record.client.client_id.clone(),
                            resources: resources.clone(),
                            granted_scopes: record.requested_scopes.clone(),
                            authenticated_at: command.subject.principal.authenticated_at,
                            assurance_level: command.subject.principal.assurance,
                            authentication_methods: parse_amr(&command.subject.amr)
                                .ok_or(AdapterOperationError)?,
                            consented_at: now,
                        },
                    )
                    .await
                    .map_err(|_| AdapterOperationError)?,
            };
            if grant.public_subject.as_str() != command.subject.public_subject {
                return Err(AdapterOperationError);
            }
            self.store
                .persist_authorization_code_with(
                    &mut transaction,
                    &AuthorizationCodeCreate {
                        code_digest: command.code_digest.ok_or(AdapterOperationError)?,
                        grant_id: grant.id,
                        client_id: record.client.client_id.clone(),
                        redirect_uri: record.redirect_uri,
                        resource_uris: resources,
                        granted_scopes: record.requested_scopes,
                        pkce_code_challenge: record.pkce_code_challenge,
                        nonce: record.nonce,
                        issued_at: now,
                        expires_at: command.code_expires_at.ok_or(AdapterOperationError)?,
                    },
                )
                .await
                .map_err(|_| AdapterOperationError)?;
            self.audit
                .append(
                    &mut transaction,
                    OAuthAuditEvent::AuthorizationApproved {
                        subject_id: command.subject.principal.subject_id,
                        client_id: record.client.client_id,
                        grant_id: grant.id,
                    },
                )
                .await
                .map_err(|_| AdapterOperationError)?;
            Ok(CommitDecisionOutcome::Approved)
        }
        .await;
        finish_operation(transaction, result).await
    }

    async fn authenticate_client_secret(
        &self,
        client_id: &ClientId,
        secret: &str,
    ) -> Result<bool, StateStoreError> {
        let mut connection = self
            .store
            .pool()
            .acquire()
            .await
            .map_err(|_| StateStoreError)?;
        let mut transaction = connection.begin().await.map_err(|_| StateStoreError)?;
        let result = async {
            let authentication = self
                .store
                .load_client_authentication_with(&mut transaction, client_id)
                .await
                .map_err(|_| AdapterOperationError)?;
            let Some(authentication) = authentication else {
                return Ok(false);
            };
            if authentication.method != TokenEndpointAuthMethod::ClientSecretBasic {
                return Ok(false);
            }
            let Some(expected) = authentication.client_secret_digest else {
                return Ok(false);
            };
            let bearer = match crate::types::OpaqueBearer::parse(secret) {
                Ok(bearer) => bearer,
                Err(_) => return Ok(false),
            };
            Ok(verify_bearer_digest(
                &bearer,
                &expected,
                &self.pepper,
                BearerDigestDomain::ClientSecret,
            )
            .is_ok())
        }
        .await;
        finish_operation(transaction, result).await
    }

    async fn accept_private_key_assertion(
        &self,
        client_id: &ClientId,
        assertion: &PrivateKeyJwtAssertion,
    ) -> Result<bool, StateStoreError> {
        let mut connection = self
            .store
            .pool()
            .acquire()
            .await
            .map_err(|_| StateStoreError)?;
        let mut transaction = connection.begin().await.map_err(|_| StateStoreError)?;
        let result = self
            .verify_private_assertion(&mut transaction, client_id, assertion)
            .await;
        finish_operation(transaction, result).await
    }

    async fn consume_authorization_code(
        &self,
        command: ConsumeAuthorizationCode,
    ) -> Result<ConsumeCodeOutcome, StateStoreError> {
        let mut connection = self
            .store
            .pool()
            .acquire()
            .await
            .map_err(|_| StateStoreError)?;
        let mut transaction = connection.begin().await.map_err(|_| StateStoreError)?;
        let result = async {
            let exchange = self
                .store
                .consume_authorization_code_with(
                    &mut transaction,
                    &command.code_digest,
                    &AuthorizationCodeBinding {
                        client_id: command.client_id.clone(),
                        redirect_uri: command.redirect_uri.clone(),
                        resource_uris: vec![command.resource.clone()],
                        pkce_verifier: command.pkce_verifier.clone(),
                    },
                    command.now,
                )
                .await
                .map_err(|_| AdapterOperationError)?;
            let AuthorizationCodeExchange::Issued(consumed) = exchange else {
                return Ok(ConsumeCodeOutcome::Unavailable);
            };
            let refresh_allowed = consumed
                .granted_scopes
                .iter()
                .any(|scope| scope.as_str() == "offline_access");
            if refresh_allowed {
                self.store
                    .issue_refresh_family_with(
                        &mut transaction,
                        &RefreshFamilyIssue {
                            grant_id: consumed.grant.id,
                            client_id: command.client_id.clone(),
                            resource: command.resource.clone(),
                            granted_scopes: consumed.granted_scopes.clone(),
                            token_digest: command.refresh_digest,
                            issued_at: command.now,
                            expires_at: command.refresh_expires_at,
                        },
                    )
                    .await
                    .map_err(|_| AdapterOperationError)?;
            }
            let verified_email = self
                .store
                .verified_email_with(
                    &mut transaction,
                    consumed.grant.user_id,
                    &self.local_identity_provider,
                )
                .await
                .map_err(|_| AdapterOperationError)?;
            let context = self.token_context(
                consumed.grant.clone(),
                command.resource.clone(),
                consumed.granted_scopes,
                consumed.nonce,
                verified_email,
                refresh_allowed,
            )?;
            self.audit
                .append(
                    &mut transaction,
                    OAuthAuditEvent::AuthorizationCodeExchanged {
                        subject_id: consumed.grant.user_id,
                        client_id: command.client_id.clone(),
                        grant_id: consumed.grant.id,
                    },
                )
                .await
                .map_err(|_| AdapterOperationError)?;
            Ok(ConsumeCodeOutcome::Consumed(
                crate::service::ConsumedAuthorizationCode {
                    client_id: command.client_id,
                    redirect_uri: command.redirect_uri,
                    resource: command.resource,
                    pkce_challenge: command.pkce_verifier.challenge(),
                    context,
                },
            ))
        }
        .await;
        finish_operation(transaction, result).await
    }

    async fn rotate_refresh_token(
        &self,
        command: RotateRefreshToken,
    ) -> Result<RotateRefreshOutcome, StateStoreError> {
        let mut connection = self
            .store
            .pool()
            .acquire()
            .await
            .map_err(|_| StateStoreError)?;
        let mut transaction = connection.begin().await.map_err(|_| StateStoreError)?;
        let rotation = self
            .store
            .rotate_refresh_token_with(
                &mut transaction,
                &command.presented_digest,
                &command.client_id,
                &command.replacement_digest,
                command.now,
                command.replacement_expires_at,
            )
            .await
            .map_err(|_| StateStoreError)?;
        match rotation {
            RefreshRotation::ReuseDetected { grant_id, .. } => {
                if self
                    .audit
                    .append(
                        &mut transaction,
                        OAuthAuditEvent::RefreshReuseDetected { grant_id },
                    )
                    .await
                    .is_err()
                {
                    let _ = transaction.rollback().await;
                    return Err(StateStoreError);
                }
                transaction.commit().await.map_err(|_| StateStoreError)?;
                Ok(RotateRefreshOutcome::ReuseDetected)
            }
            RefreshRotation::Rejected(_) => {
                transaction.commit().await.map_err(|_| StateStoreError)?;
                Ok(RotateRefreshOutcome::Unavailable)
            }
            RefreshRotation::Rotated(rotated) => {
                let resource = match command.resource {
                    Some(resource) if resource == rotated.resource => resource,
                    Some(_) => {
                        let _ = transaction.rollback().await;
                        return Ok(RotateRefreshOutcome::Unavailable);
                    }
                    None => rotated.resource,
                };
                let scopes = command
                    .scopes
                    .unwrap_or_else(|| rotated.granted_scopes.clone());
                if scopes.is_empty()
                    || scopes
                        .iter()
                        .any(|scope| rotated.granted_scopes.binary_search(scope).is_err())
                {
                    let _ = transaction.rollback().await;
                    return Ok(RotateRefreshOutcome::Unavailable);
                }
                let verified_email = self
                    .store
                    .verified_email_with(
                        &mut transaction,
                        rotated.grant.user_id,
                        &self.local_identity_provider,
                    )
                    .await
                    .map_err(|_| StateStoreError)?;
                let context = self
                    .token_context(
                        rotated.grant.clone(),
                        resource,
                        scopes,
                        None,
                        verified_email,
                        true,
                    )
                    .map_err(|_| StateStoreError)?;
                if self
                    .audit
                    .append(
                        &mut transaction,
                        OAuthAuditEvent::RefreshRotated {
                            subject_id: rotated.grant.user_id,
                            client_id: command.client_id,
                            grant_id: rotated.grant.id,
                        },
                    )
                    .await
                    .is_err()
                {
                    let _ = transaction.rollback().await;
                    return Err(StateStoreError);
                }
                transaction.commit().await.map_err(|_| StateStoreError)?;
                Ok(RotateRefreshOutcome::Rotated(context))
            }
        }
    }

    async fn revoke_token(
        &self,
        client_id: &ClientId,
        target: RevocationTarget,
        now: OffsetDateTime,
    ) -> Result<(), StateStoreError> {
        let mut connection = self
            .store
            .pool()
            .acquire()
            .await
            .map_err(|_| StateStoreError)?;
        let mut transaction = connection.begin().await.map_err(|_| StateStoreError)?;
        let result = async {
            let (changed, grant_id) = match target {
                RevocationTarget::AccessToken { jwt_id, grant_id } => (
                    self.store
                        .revoke_access_token_jti_with(
                            &mut transaction,
                            jwt_id,
                            grant_id,
                            client_id,
                            now,
                        )
                        .await
                        .map_err(|_| AdapterOperationError)?,
                    Some(grant_id),
                ),
                RevocationTarget::RefreshToken(digest) => (
                    self.store
                        .revoke_refresh_token_for_client_with(
                            &mut transaction,
                            &digest,
                            client_id,
                            now,
                        )
                        .await
                        .map_err(|_| AdapterOperationError)?,
                    None,
                ),
            };
            if changed {
                self.audit
                    .append(
                        &mut transaction,
                        OAuthAuditEvent::TokenRevoked {
                            client_id: client_id.clone(),
                            grant_id,
                        },
                    )
                    .await
                    .map_err(|_| AdapterOperationError)?;
            }
            Ok(())
        }
        .await;
        finish_operation(transaction, result).await
    }

    async fn list_connected_grants(
        &self,
        subject_id: SubjectId,
    ) -> Result<Vec<ConnectedGrant>, StateStoreError> {
        let page = self
            .store
            .list_connected_grants(subject_id, None, MAX_CONNECTED_GRANTS)
            .await
            .map_err(|_| StateStoreError)?;
        page.grants
            .into_iter()
            .map(map_connected_grant)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| StateStoreError)
    }

    async fn revoke_connected_grant(
        &self,
        subject_id: SubjectId,
        grant_id: crate::types::GrantId,
    ) -> Result<bool, StateStoreError> {
        let mut connection = self
            .store
            .pool()
            .acquire()
            .await
            .map_err(|_| StateStoreError)?;
        let mut transaction = connection.begin().await.map_err(|_| StateStoreError)?;
        let result = async {
            let revoked = self
                .store
                .revoke_grant_with(&mut transaction, subject_id, grant_id, self.clock.now_utc())
                .await
                .map_err(|_| AdapterOperationError)?;
            if revoked {
                self.audit
                    .append(
                        &mut transaction,
                        OAuthAuditEvent::ConnectedGrantRevoked {
                            subject_id,
                            grant_id,
                        },
                    )
                    .await
                    .map_err(|_| AdapterOperationError)?;
            }
            Ok(revoked)
        }
        .await;
        finish_operation(transaction, result).await
    }

    async fn logout_session(&self, command: LogoutSession) -> Result<bool, StateStoreError> {
        if let Some(public_subject) = command.public_subject.as_deref()
            && !self
                .store
                .public_subject_matches(command.subject_id, public_subject)
                .await
                .map_err(|_| StateStoreError)?
        {
            return Ok(false);
        }
        self.sessions
            .validate_logout_binding(command)
            .await
            .map_err(|_| StateStoreError)
    }
}
fn client_upsert_from_metadata(
    client_id: ClientId,
    metadata: &ClientMetadata,
    source: ClientSource,
    client_secret_digest: Option<crate::crypto::BearerDigest>,
    now: OffsetDateTime,
) -> ClientUpsert {
    ClientUpsert {
        client_id,
        source,
        display_name: metadata.client_name().to_owned(),
        client_uri: None,
        logo_uri: None,
        application_type: metadata.application_type(),
        token_endpoint_auth_method: metadata.token_endpoint_auth_method(),
        client_secret_digest,
        response_types: metadata.response_types().to_vec(),
        grant_types: metadata.grant_types().to_vec(),
        allowed_scopes: metadata.scopes().to_vec(),
        public_jwks: metadata.jwks().cloned(),
        redirect_uris: metadata.redirect_uris().to_vec(),
        post_logout_redirect_uris: metadata.post_logout_redirect_uris().to_vec(),
        metadata_document_uri: None,
        metadata_cache: None,
        now,
    }
}

/// Maps safe registered-client metadata without loading secret authentication material.
pub fn map_registered_client(
    client: RegisteredClient,
) -> Result<ResolvedClient, PostgresRecordMappingError> {
    if client.status != ClientStatus::Active || client.redirect_uris.is_empty() {
        return Err(PostgresRecordMappingError);
    }
    let display_origin = client
        .client_uri
        .as_deref()
        .and_then(url_origin)
        .or_else(|| url_origin(client.client_id.as_str()))
        .or_else(|| {
            client
                .redirect_uris
                .first()
                .and_then(|uri| url_origin(uri.as_str()))
        })
        .ok_or(PostgresRecordMappingError)?;
    Ok(ResolvedClient {
        client_id: client.client_id,
        display_name: client.display_name,
        display_origin,
        redirect_uris: client.redirect_uris,
        post_logout_redirect_uris: client.post_logout_redirect_uris,
        token_endpoint_auth_method: client.token_endpoint_auth_method,
        grant_types: client.grant_types,
        scopes: client.allowed_scopes,
        resources: Vec::new(),
    })
}

/// Maps a durable request into the complete transport-neutral authorization snapshot.
pub fn map_stored_authorization(
    issuer: &IssuerUri,
    record: AuthorizationRequestRecord,
) -> Result<StoredAuthorization, PostgresRecordMappingError> {
    if &record.expected_issuer != issuer {
        return Err(PostgresRecordMappingError);
    }
    let client = map_registered_client(record.client.clone())?;
    let prompt = match record.prompt_values.as_slice() {
        [] => None,
        [prompt] => Some(*prompt),
        _ => return Err(PostgresRecordMappingError),
    };
    let request = AuthorizationRequestInput::new(AuthorizationRequestParts {
        client_id: record.client.client_id.clone(),
        redirect_uri: record.redirect_uri.clone(),
        response_type: record.response_type,
        response_mode: record.response_mode,
        state: record.client_state.clone(),
        scopes: record.requested_scopes.clone(),
        resources: record.resource_uris.clone(),
        pkce_challenge: record.pkce_code_challenge.clone(),
        pkce_method: "S256".to_owned(),
        nonce: record.nonce.clone(),
        prompt,
        max_age_seconds: record.max_age_seconds,
        expected_issuer: Some(record.expected_issuer.clone()),
    })
    .map_err(|_| PostgresRecordMappingError)?;
    let resource = match record.resource_uris.as_slice() {
        [resource] => resource.clone(),
        [] if record
            .requested_scopes
            .iter()
            .any(|scope| scope.as_str() == "openid") =>
        {
            ResourceUri::parse(issuer.endpoint(USERINFO_PATH), false)
                .map_err(|_| PostgresRecordMappingError)?
        }
        _ => return Err(PostgresRecordMappingError),
    };
    let redirect_host = Url::parse(record.redirect_uri.as_str())
        .ok()
        .and_then(|url| url.host_str().map(str::to_owned))
        .ok_or(PostgresRecordMappingError)?;
    let requirement = interaction_requirement(record.interaction_requirement);
    let scopes = record
        .interaction_scopes
        .into_iter()
        .map(|scope| InteractionScope {
            name: scope.name,
            description: scope.description,
            newly_requested: scope.newly_requested,
        })
        .collect();
    Ok(StoredAuthorization {
        request,
        client: client.clone(),
        resource: resource.clone(),
        interaction: AuthorizationInteraction {
            client_name: client.display_name,
            client_origin: client.display_origin,
            redirect_host,
            resource_name: record.interaction_resource_name,
            resource_description: record.interaction_resource_description,
            resource,
            minimum_assurance: record.interaction_minimum_assurance,
            scopes,
            requirement,
        },
        authentication_time_before_login: (requirement == InteractionRequirement::Login)
            .then_some(record.created_at),
        expires_at: record.expires_at,
    })
}

/// Maps one safe connected-grant record, rejecting impossible multi-resource state.
pub fn map_connected_grant(
    grant: StoreConnectedGrant,
) -> Result<ConnectedGrant, PostgresRecordMappingError> {
    let [resource] = grant.resources.as_slice() else {
        return Err(PostgresRecordMappingError);
    };
    Ok(ConnectedGrant {
        grant_id: grant.grant_id,
        client_name: grant.client_name,
        resource: resource.clone(),
        scopes: grant.granted_scopes,
        consented_at: grant.consented_at,
    })
}

#[derive(Clone, Copy, Debug)]
struct AdapterOperationError;

async fn finish_operation<T>(
    transaction: Transaction<'_, Postgres>,
    result: Result<T, AdapterOperationError>,
) -> Result<T, StateStoreError> {
    match result {
        Ok(value) => {
            transaction.commit().await.map_err(|_| StateStoreError)?;
            Ok(value)
        }
        Err(_) => {
            let _ = transaction.rollback().await;
            Err(StateStoreError)
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ClientJwks {
    keys: Vec<RsaPublicJwk>,
}

#[derive(Deserialize)]
struct PrivateAssertionClaims {
    iss: String,
    sub: String,
    aud: AssertionAudience,
    jti: String,
    iat: i64,
    exp: i64,
}
fn permanent_metadata_rejection(error: ClientMetadataResolverError) -> bool {
    matches!(
        error,
        ClientMetadataResolverError::InvalidClientIdentifier
            | ClientMetadataResolverError::DestinationRejected
            | ClientMetadataResolverError::RedirectRejected
            | ClientMetadataResolverError::InvalidStatus
            | ClientMetadataResolverError::InvalidContentType
            | ClientMetadataResolverError::ResponseTooLarge
            | ClientMetadataResolverError::InvalidDocument
            | ClientMetadataResolverError::ForbiddenCredentialMaterial
    )
}

#[derive(Deserialize)]
#[serde(untagged)]
enum AssertionAudience {
    One(String),
    Many(Vec<String>),
}

impl AssertionAudience {
    fn matches_exact(&self, expected: &str) -> bool {
        match self {
            Self::One(value) => value == expected,
            Self::Many(values) => values.as_slice() == [expected],
        }
    }
}

fn url_origin(value: &str) -> Option<String> {
    let origin = Url::parse(value).ok()?.origin().ascii_serialization();
    (origin != "null").then_some(origin)
}

const fn assurance_name(assurance: AssuranceLevel) -> &'static str {
    match assurance {
        AssuranceLevel::Aal1 => "aal1",
        AssuranceLevel::Aal2 => "aal2",
        AssuranceLevel::Aal3 => "aal3",
    }
}

const fn auth_method_name(method: AuthMethod) -> &'static str {
    match method {
        AuthMethod::Password => "pwd",
        AuthMethod::Session => "session",
        AuthMethod::Jwt => "jwt",
        AuthMethod::Oidc => "oidc",
        AuthMethod::ApiKey => "api_key",
        AuthMethod::WebAuthn => "webauthn",
        AuthMethod::Totp => "otp",
    }
}

const fn store_auth_method_name(method: AuthMethod) -> &'static str {
    match method {
        AuthMethod::Password => "password",
        AuthMethod::Session => "session",
        AuthMethod::Jwt => "jwt",
        AuthMethod::Oidc => "oidc",
        AuthMethod::ApiKey => "api_key",
        AuthMethod::WebAuthn => "web_authn",
        AuthMethod::Totp => "totp",
    }
}

fn parse_amr(values: &[String]) -> Option<Vec<AuthMethod>> {
    let mut methods = values
        .iter()
        .map(|value| match value.as_str() {
            "pwd" => Some(AuthMethod::Password),
            "session" => Some(AuthMethod::Session),
            "jwt" => Some(AuthMethod::Jwt),
            "oidc" => Some(AuthMethod::Oidc),
            "api_key" => Some(AuthMethod::ApiKey),
            "webauthn" => Some(AuthMethod::WebAuthn),
            "otp" => Some(AuthMethod::Totp),
            _ => None,
        })
        .collect::<Option<Vec<_>>>()?;
    methods.sort_unstable_by_key(|method| store_auth_method_name(*method));
    methods.dedup();
    (!methods.is_empty()).then_some(methods)
}

const fn store_interaction_requirement(
    requirement: InteractionRequirement,
) -> StoreInteractionRequirement {
    match requirement {
        InteractionRequirement::Login => StoreInteractionRequirement::Login,
        InteractionRequirement::Consent => StoreInteractionRequirement::Consent,
        InteractionRequirement::Ready => StoreInteractionRequirement::Ready,
    }
}

const fn interaction_requirement(
    requirement: StoreInteractionRequirement,
) -> InteractionRequirement {
    match requirement {
        StoreInteractionRequirement::Login => InteractionRequirement::Login,
        StoreInteractionRequirement::Consent => InteractionRequirement::Consent,
        StoreInteractionRequirement::Ready => InteractionRequirement::Ready,
    }
}

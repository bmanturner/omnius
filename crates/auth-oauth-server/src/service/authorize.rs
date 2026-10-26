//! Authorization request, interaction, and consent flow.

use super::{
    AuthorizationServer, AuthorizationStore, MAX_STATE_BYTES, OAuthErrorCode, ProtocolError,
    REDACTED, ResolvedClient, ResponseSensitivity, add_std, bounded_text, has_scope,
};
use crate::Clock;
use crate::crypto::{BearerDigest, BearerDigestDomain, issue_bearer};
use crate::types::{
    AuthorizationRequestInput, ClientId, EntropySource, GrantId, GrantType, IssuerUri, Prompt,
    RedirectUri, ResourceUri,
};
use omnius_auth_core::{AssuranceLevel, Principal, Scope, SubjectId};
use serde::Serialize;
use time::{Duration, OffsetDateTime};

/// A redirectable OAuth error after client and redirect validation succeeded.
#[derive(Clone, Eq, PartialEq)]
#[non_exhaustive]
pub struct AuthorizationErrorRedirect {
    /// Exact registered redirect supplied by the validated request.
    pub redirect_uri: RedirectUri,
    /// Client state echoed byte-for-byte when supplied.
    pub state: Option<String>,
    /// Exact issuer added under RFC 9207.
    pub issuer: IssuerUri,
}

impl std::fmt::Debug for AuthorizationErrorRedirect {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("AuthorizationErrorRedirect")
            .field("redirect_uri", &REDACTED)
            .field("state", &self.state.as_ref().map(|_| REDACTED))
            .field("issuer", &REDACTED)
            .finish()
    }
}

/// Minimal browser-session identity that must be revalidated by the store.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SessionCandidate {
    /// Canonical internal user identifier.
    pub subject_id: SubjectId,
    /// Authentication time recorded by the browser session.
    pub authenticated_at: OffsetDateTime,
}

/// Live authorization subject returned by one store revalidation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthorizationSubject {
    /// Canonical internal principal.
    pub principal: Principal,
    /// Stable issuer-public subject.
    pub public_subject: String,
    /// Verified local email, when present.
    pub verified_email: Option<String>,
    /// Authentication context class reference.
    pub acr: String,
    /// Authentication method references.
    pub amr: Vec<String>,
}

/// Existing live grant potentially covering an authorization request.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct ExistingGrant {
    /// Durable grant identifier.
    pub grant_id: GrantId,
    /// Exact granted resource.
    pub resource: ResourceUri,
    /// Sorted granted scopes.
    pub scopes: Vec<Scope>,
    /// Whether offline access was explicitly consented.
    pub offline_access_consented: bool,
}

/// Query for a covering, currently live consent grant.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct CoveringGrantQuery {
    /// Canonical subject.
    pub subject_id: SubjectId,
    /// Tenant context resolved by the current browser session, when present.
    pub tenant_id: Option<omnius_auth_core::TenantId>,
    /// Exact client.
    pub client_id: ClientId,
    /// Exact effective resource.
    pub resource: ResourceUri,
    /// Requested scopes.
    pub scopes: Vec<Scope>,
}

/// Why the browser interaction cannot be completed silently.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub enum InteractionRequirement {
    /// Authentication or fresh reauthentication is required.
    Login,
    /// Explicit consent is required.
    Consent,
    /// A covering grant can be reused without displaying consent.
    Ready,
}

/// One safe scope description displayed by the consent UI.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct InteractionScope {
    /// Exact scope token.
    pub name: Scope,
    /// Safe provider-authored description.
    pub description: String,
    /// Whether this scope is newly requested beyond an existing grant.
    pub newly_requested: bool,
}

/// Safe display data retained with an opaque authorization interaction.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct AuthorizationInteraction {
    /// Safe client name.
    pub client_name: String,
    /// Safe client origin.
    pub client_origin: String,
    /// Host of the already validated exact redirect URI.
    pub redirect_host: String,
    /// Exact target resource.
    pub resource: ResourceUri,
    /// Safe target resource name.
    pub resource_name: String,
    /// Safe target resource description.
    pub resource_description: String,
    /// Minimum resource assurance.
    pub minimum_assurance: AssuranceLevel,
    /// Requested scopes and existing-grant delta.
    pub scopes: Vec<InteractionScope>,
    /// Current interaction requirement.
    pub requirement: InteractionRequirement,
}

/// Durable authorization transaction content addressed only by a digest.
#[derive(Clone, Debug)]
pub struct StoredAuthorization {
    /// Validated protocol request.
    pub request: AuthorizationRequestInput,
    /// Resolved client snapshot.
    pub client: ResolvedClient,
    /// Effective resource, including the OIDC `UserInfo` audience default.
    pub resource: ResourceUri,
    /// Safe interaction display data.
    pub interaction: AuthorizationInteraction,
    /// Authentication time observed before a required reauthentication.
    pub authentication_time_before_login: Option<OffsetDateTime>,
    /// Expiry instant.
    pub expires_at: OffsetDateTime,
}

/// Atomic authorization transaction insertion.
#[derive(Clone, Debug)]
pub struct CreateAuthorization {
    /// HMAC digest of the opaque browser handle.
    pub handle_digest: BearerDigest,
    /// Durable transaction content.
    pub authorization: StoredAuthorization,
}

/// Opaque browser handle returned after persistence.
#[derive(Clone, Eq, PartialEq)]
pub struct AuthorizationHandle(String);

impl AuthorizationHandle {
    /// Borrows the exact canonical handle for an immediate response boundary.
    #[must_use]
    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Debug for AuthorizationHandle {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_tuple("AuthorizationHandle")
            .field(&REDACTED)
            .finish()
    }
}

/// Successful start of a persisted authorization interaction.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct BegunAuthorization {
    /// Opaque handle whose digest alone is stored.
    pub handle: AuthorizationHandle,
    /// Requirement used by the browser application to select login or consent.
    pub requirement: InteractionRequirement,
    /// Interaction handles are sensitive and must not be cached.
    pub sensitivity: ResponseSensitivity,
}

/// Result of beginning authorization: either a browser interaction or direct grant reuse.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BeginAuthorizationResult {
    /// Login or explicit consent must be completed using the opaque handle.
    Interaction(BegunAuthorization),
    /// A covering live grant was reused without displaying user interface.
    Redirect(AuthorizationRedirect),
}

/// User decision received from a same-origin, CSRF-protected transport.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConsentDecision {
    /// Approve exactly the validated requested scope set.
    Approve,
    /// Deny the authorization request.
    Deny,
}

/// Atomic terminal authorization decision.
#[derive(Clone, Debug)]
pub struct CommitAuthorizationDecision {
    /// Authorization-request handle digest.
    pub handle_digest: BearerDigest,
    /// Live authorizing subject.
    pub subject: AuthorizationSubject,
    /// Approval or denial.
    pub decision: ConsentDecision,
    /// Generated authorization-code digest for approvals only.
    pub code_digest: Option<BearerDigest>,
    /// Authorization-code expiry for approvals only.
    pub code_expires_at: Option<OffsetDateTime>,
    /// Whether offline access was explicitly displayed and approved.
    pub explicit_offline_consent: bool,
    /// Whether approval is valid only while a covering grant remains live.
    pub require_existing_grant: bool,
}

/// Result of the atomic decision operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CommitDecisionOutcome {
    /// The request became terminal and its approval code was stored.
    Approved,
    /// The request became terminal as denied.
    Denied,
    /// The handle was missing, expired, or already terminal.
    Unavailable,
}

/// Server-owned authorization redirect response.
#[derive(Clone, Eq, PartialEq)]
pub struct AuthorizationRedirect {
    /// Exact already validated redirect URI.
    pub redirect_uri: RedirectUri,
    /// Client state echoed byte-for-byte when supplied.
    pub state: Option<String>,
    /// Exact RFC 9207 issuer value.
    pub issuer: IssuerUri,
    /// Authorization code only on approval.
    pub code: Option<String>,
    /// Standard error only on denial.
    pub error: Option<OAuthErrorCode>,
}

impl std::fmt::Debug for AuthorizationRedirect {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("AuthorizationRedirect")
            .field("redirect_uri", &REDACTED)
            .field("state", &self.state.as_ref().map(|_| REDACTED))
            .field("issuer", &REDACTED)
            .field("has_code", &self.code.is_some())
            .field("error", &self.error)
            .finish()
    }
}

struct AuthorizationPreparation {
    now: OffsetDateTime,
    client: ResolvedClient,
    subject: Option<AuthorizationSubject>,
    resource: ResourceUri,
    existing_grant: Option<ExistingGrant>,
    requirement: InteractionRequirement,
    requires_login: bool,
}

impl<S, C, E> AuthorizationServer<S, C, E>
where
    S: AuthorizationStore,
    C: Clock,
    E: EntropySource,
{
    /// Builds a redirect-bound protocol error only after resolving the client and
    /// exact registered redirect URI.
    pub async fn authorization_request_error(
        &self,
        client_id: &ClientId,
        redirect_uri: &RedirectUri,
        state: Option<&str>,
        code: OAuthErrorCode,
    ) -> ProtocolError {
        let client = match self.store.resolve_client(client_id).await {
            Ok(Some(client)) if client.is_well_formed() => client,
            Ok(None | Some(_)) => {
                return ProtocolError::endpoint(OAuthErrorCode::InvalidClient);
            }
            Err(_) => return ProtocolError::endpoint(OAuthErrorCode::ServerError),
        };
        if !client.matches_redirect(redirect_uri) {
            return ProtocolError::endpoint(OAuthErrorCode::InvalidRequest);
        }
        let state = state
            .filter(|value| bounded_text(value, MAX_STATE_BYTES))
            .map(str::to_owned);
        ProtocolError::authorization_redirect(
            code,
            redirect_uri.clone(),
            state,
            self.config.issuer().clone(),
        )
    }

    /// Validates redirect safety first and persists an opaque authorization interaction.
    ///
    /// # Errors
    ///
    /// Returns a protocol error when the client, redirect, issuer, scopes, resource,
    /// prompt, or session cannot be accepted, or when secure issuance or persistence fails.
    pub async fn begin_authorization(
        &self,
        request: AuthorizationRequestInput,
        session: Option<SessionCandidate>,
    ) -> Result<BeginAuthorizationResult, ProtocolError> {
        let AuthorizationPreparation {
            now,
            client,
            subject,
            resource,
            existing_grant,
            requirement,
            requires_login,
        } = self.prepare_authorization(&request, session).await?;
        let interaction = self.interaction_display(
            &request,
            &client,
            &resource,
            existing_grant.as_ref(),
            requirement,
        )?;
        let issued = issue_bearer(
            self.entropy.as_ref(),
            self.config.token_pepper(),
            BearerDigestDomain::AuthorizationRequest,
        )
        .map_err(|_| self.authorization_error(OAuthErrorCode::ServerError, &request))?;
        let expires_at = add_std(now, self.config.authorization_request_ttl())
            .ok_or_else(|| self.authorization_error(OAuthErrorCode::ServerError, &request))?;
        let handle_digest = issued.digest;
        self.store
            .create_authorization(CreateAuthorization {
                handle_digest: handle_digest.clone(),
                authorization: StoredAuthorization {
                    request: request.clone(),
                    client,
                    resource,
                    interaction,
                    authentication_time_before_login: if requires_login {
                        subject
                            .as_ref()
                            .map(|value| value.principal.authenticated_at)
                    } else {
                        None
                    },
                    expires_at,
                },
            })
            .await
            .map_err(|_| ProtocolError::endpoint(OAuthErrorCode::ServerError))?;
        if requirement == InteractionRequirement::Ready {
            let subject = subject
                .ok_or_else(|| self.authorization_error(OAuthErrorCode::ServerError, &request))?;
            return self
                .complete_ready_authorization(&request, subject, handle_digest, now)
                .await;
        }
        Ok(BeginAuthorizationResult::Interaction(BegunAuthorization {
            handle: AuthorizationHandle(issued.presentation.expose_once()),
            requirement,
            sensitivity: ResponseSensitivity::NoStore,
        }))
    }

    async fn prepare_authorization(
        &self,
        request: &AuthorizationRequestInput,
        session: Option<SessionCandidate>,
    ) -> Result<AuthorizationPreparation, ProtocolError> {
        let client = self
            .store
            .resolve_client(request.client_id())
            .await
            .map_err(|_| ProtocolError::endpoint(OAuthErrorCode::ServerError))?
            .filter(ResolvedClient::is_well_formed)
            .ok_or_else(|| ProtocolError::endpoint(OAuthErrorCode::InvalidClient))?;
        if !client.matches_redirect(request.redirect_uri()) {
            return Err(ProtocolError::endpoint(OAuthErrorCode::InvalidRequest));
        }
        if request
            .expected_issuer()
            .is_some_and(|issuer| issuer != self.config.issuer())
        {
            return Err(self.authorization_error(OAuthErrorCode::InvalidRequest, request));
        }
        self.validate_authorization_request(request, &client)?;
        let now = self.clock.now_utc();
        let subject = match session {
            Some(candidate) => self
                .store
                .authorize_session(candidate)
                .await
                .map_err(|_| self.authorization_error(OAuthErrorCode::ServerError, request))?,
            None => None,
        };
        let resource = self.effective_resource(request)?;
        let minimum_assurance = self.minimum_assurance(&resource);
        let requires_login = subject.as_ref().is_none_or(|subject| {
            request.prompt() == Some(Prompt::Login)
                || subject.principal.assurance < minimum_assurance
                || request.max_age_seconds().is_some_and(|max_age| {
                    max_age == 0
                        || now - subject.principal.authenticated_at > duration_seconds(max_age)
                })
        });
        let existing_grant = if requires_login {
            None
        } else {
            let subject_id = subject
                .as_ref()
                .map(|value| value.principal.subject_id)
                .ok_or_else(|| self.authorization_error(OAuthErrorCode::ServerError, request))?;
            self.store
                .find_covering_grant(CoveringGrantQuery {
                    subject_id,
                    tenant_id: subject.as_ref().and_then(|value| value.principal.tenant_id),
                    client_id: client.client_id.clone(),
                    resource: resource.clone(),
                    scopes: request.scopes().to_vec(),
                })
                .await
                .map_err(|_| self.authorization_error(OAuthErrorCode::ServerError, request))?
        };
        let explicit_consent = request.prompt() == Some(Prompt::Consent)
            || has_scope(request.scopes(), "offline_access");
        let requirement = if requires_login {
            InteractionRequirement::Login
        } else if explicit_consent || existing_grant.is_none() {
            InteractionRequirement::Consent
        } else {
            InteractionRequirement::Ready
        };
        if request.prompt() == Some(Prompt::None) && requirement != InteractionRequirement::Ready {
            let code = if requirement == InteractionRequirement::Login {
                OAuthErrorCode::LoginRequired
            } else {
                OAuthErrorCode::ConsentRequired
            };
            return Err(self.authorization_error(code, request));
        }
        Ok(AuthorizationPreparation {
            now,
            client,
            subject,
            resource,
            existing_grant,
            requirement,
            requires_login,
        })
    }

    async fn complete_ready_authorization(
        &self,
        request: &AuthorizationRequestInput,
        subject: AuthorizationSubject,
        handle_digest: BearerDigest,
        now: OffsetDateTime,
    ) -> Result<BeginAuthorizationResult, ProtocolError> {
        let code = issue_bearer(
            self.entropy.as_ref(),
            self.config.token_pepper(),
            BearerDigestDomain::AuthorizationCode,
        )
        .map_err(|_| self.authorization_error(OAuthErrorCode::ServerError, request))?;
        let code_expires_at = add_std(now, self.config.authorization_code_ttl())
            .ok_or_else(|| self.authorization_error(OAuthErrorCode::ServerError, request))?;
        let outcome = self
            .store
            .commit_authorization_decision(CommitAuthorizationDecision {
                handle_digest,
                subject,
                decision: ConsentDecision::Approve,
                code_digest: Some(code.digest),
                code_expires_at: Some(code_expires_at),
                explicit_offline_consent: false,
                require_existing_grant: true,
            })
            .await
            .map_err(|_| self.authorization_error(OAuthErrorCode::ServerError, request))?;
        if outcome != CommitDecisionOutcome::Approved {
            return Err(self.authorization_error(OAuthErrorCode::ServerError, request));
        }
        Ok(BeginAuthorizationResult::Redirect(AuthorizationRedirect {
            redirect_uri: request.redirect_uri().clone(),
            state: request.state().map(str::to_owned),
            issuer: self.config.issuer().clone(),
            code: Some(code.presentation.expose_once()),
            error: None,
        }))
    }

    /// Returns only provider-validated display data for an opaque interaction handle.
    ///
    /// # Errors
    ///
    /// Returns `invalid_request` for a malformed, unknown, expired, or terminal handle,
    /// and `server_error` when digesting or loading the interaction fails.
    pub async fn interaction(
        &self,
        handle: &str,
    ) -> Result<AuthorizationInteraction, ProtocolError> {
        let (_, digest) = self.parse_bearer(handle, BearerDigestDomain::AuthorizationRequest)?;
        self.store
            .load_authorization(digest, self.clock.now_utc())
            .await
            .map_err(|_| ProtocolError::endpoint(OAuthErrorCode::ServerError))?
            .map(|authorization| authorization.interaction)
            .ok_or_else(|| ProtocolError::endpoint(OAuthErrorCode::InvalidRequest))
    }

    /// Revalidates the session and atomically approves or denies one interaction.
    ///
    /// # Errors
    ///
    /// Returns a protocol error when the handle is invalid or unavailable, the session
    /// cannot satisfy the interaction, issuance fails, or the decision cannot be committed.
    pub async fn decide(
        &self,
        handle: &str,
        session: SessionCandidate,
        decision: ConsentDecision,
    ) -> Result<AuthorizationRedirect, ProtocolError> {
        let (_, handle_digest) =
            self.parse_bearer(handle, BearerDigestDomain::AuthorizationRequest)?;
        let now = self.clock.now_utc();
        let authorization = self
            .store
            .load_authorization(handle_digest.clone(), now)
            .await
            .map_err(|_| ProtocolError::endpoint(OAuthErrorCode::ServerError))?
            .ok_or_else(|| ProtocolError::endpoint(OAuthErrorCode::InvalidRequest))?;
        let subject = self
            .store
            .authorize_session(session)
            .await
            .map_err(|_| {
                self.authorization_error(OAuthErrorCode::ServerError, &authorization.request)
            })?
            .ok_or_else(|| {
                self.authorization_error(OAuthErrorCode::LoginRequired, &authorization.request)
            })?;
        let stale_login = authorization
            .authentication_time_before_login
            .is_some_and(|before| subject.principal.authenticated_at <= before);
        let stale_max_age = authorization
            .request
            .max_age_seconds()
            .is_some_and(|max_age| {
                max_age != 0 && now - subject.principal.authenticated_at > duration_seconds(max_age)
            });
        if stale_login
            || stale_max_age
            || subject.principal.assurance < self.minimum_assurance(&authorization.resource)
        {
            return Err(
                self.authorization_error(OAuthErrorCode::LoginRequired, &authorization.request)
            );
        }
        let code = if decision == ConsentDecision::Approve {
            Some(
                issue_bearer(
                    self.entropy.as_ref(),
                    self.config.token_pepper(),
                    BearerDigestDomain::AuthorizationCode,
                )
                .map_err(|_| {
                    self.authorization_error(OAuthErrorCode::ServerError, &authorization.request)
                })?,
            )
        } else {
            None
        };
        let command = CommitAuthorizationDecision {
            handle_digest,
            subject,
            decision,
            code_digest: code.as_ref().map(|issued| issued.digest.clone()),
            code_expires_at: if code.is_some() {
                add_std(now, self.config.authorization_code_ttl())
            } else {
                None
            },
            explicit_offline_consent: decision == ConsentDecision::Approve
                && has_scope(authorization.request.scopes(), "offline_access")
                && authorization.request.prompt() == Some(Prompt::Consent),
            require_existing_grant: false,
        };
        if code.is_some() && command.code_expires_at.is_none() {
            return Err(
                self.authorization_error(OAuthErrorCode::ServerError, &authorization.request)
            );
        }
        let outcome = self
            .store
            .commit_authorization_decision(command)
            .await
            .map_err(|_| {
                self.authorization_error(OAuthErrorCode::ServerError, &authorization.request)
            })?;
        let (code, error) = match (decision, outcome, code) {
            (ConsentDecision::Approve, CommitDecisionOutcome::Approved, Some(code)) => {
                (Some(code.presentation.expose_once()), None)
            }
            (ConsentDecision::Deny, CommitDecisionOutcome::Denied, None) => {
                (None, Some(OAuthErrorCode::AccessDenied))
            }
            _ => return Err(ProtocolError::endpoint(OAuthErrorCode::InvalidRequest)),
        };
        Ok(AuthorizationRedirect {
            redirect_uri: authorization.request.redirect_uri().clone(),
            state: authorization.request.state().map(str::to_owned),
            issuer: self.config.issuer().clone(),
            code,
            error,
        })
    }

    fn validate_authorization_request(
        &self,
        request: &AuthorizationRequestInput,
        client: &ResolvedClient,
    ) -> Result<(), ProtocolError> {
        if request.client_id() != &client.client_id
            || !client.grant_types.contains(&GrantType::AuthorizationCode)
        {
            return Err(self.authorization_error(OAuthErrorCode::UnauthorizedClient, request));
        }
        if !client.scopes.is_empty()
            && request
                .scopes()
                .iter()
                .any(|scope| client.scopes.binary_search(scope).is_err())
        {
            return Err(self.authorization_error(OAuthErrorCode::InvalidScope, request));
        }
        if (has_scope(request.scopes(), "email") && !has_scope(request.scopes(), "openid"))
            || (has_scope(request.scopes(), "offline_access")
                && (!has_scope(request.scopes(), "openid")
                    || request.prompt() != Some(Prompt::Consent)))
        {
            return Err(self.authorization_error(OAuthErrorCode::InvalidScope, request));
        }
        let resource = self.effective_resource(request)?;
        if !client.resources.is_empty() && client.resources.binary_search(&resource).is_err() {
            return Err(self.authorization_error(OAuthErrorCode::InvalidTarget, request));
        }
        Ok(())
    }

    fn effective_resource(
        &self,
        request: &AuthorizationRequestInput,
    ) -> Result<ResourceUri, ProtocolError> {
        match request.resources() {
            [resource] => {
                let declaration = self.resource(resource).ok_or_else(|| {
                    self.authorization_error(OAuthErrorCode::InvalidTarget, request)
                })?;
                if request.scopes().iter().any(|scope| {
                    !is_reserved_scope(scope)
                        && declaration
                            .scopes()
                            .iter()
                            .all(|described| described.name() != scope)
                }) {
                    return Err(self.authorization_error(OAuthErrorCode::InvalidScope, request));
                }
                Ok(resource.clone())
            }
            [] if has_scope(request.scopes(), "openid")
                && request.scopes().iter().all(is_reserved_scope) =>
            {
                self.userinfo_audience()
            }
            _ => Err(self.authorization_error(OAuthErrorCode::InvalidTarget, request)),
        }
    }

    fn interaction_display(
        &self,
        request: &AuthorizationRequestInput,
        client: &ResolvedClient,
        resource: &ResourceUri,
        existing: Option<&ExistingGrant>,
        requirement: InteractionRequirement,
    ) -> Result<AuthorizationInteraction, ProtocolError> {
        let (resource_name, resource_description, minimum_assurance) =
            if let Some(declaration) = self.resource(resource) {
                (
                    declaration.name().to_owned(),
                    declaration.description().to_owned(),
                    declaration.minimum_assurance(),
                )
            } else {
                (
                    "OpenID UserInfo".to_owned(),
                    "Claims approved for this OpenID Connect client.".to_owned(),
                    AssuranceLevel::Aal1,
                )
            };
        let redirect_host = url::Url::parse(request.redirect_uri().as_str())
            .ok()
            .and_then(|url| url.host_str().map(str::to_owned))
            .ok_or_else(|| self.authorization_error(OAuthErrorCode::ServerError, request))?;
        let scopes = request
            .scopes()
            .iter()
            .map(|requested| InteractionScope {
                name: requested.clone(),
                description: self.scope_description(resource, requested),
                newly_requested: existing
                    .is_none_or(|grant| grant.scopes.binary_search(requested).is_err()),
            })
            .collect();
        Ok(AuthorizationInteraction {
            client_name: client.display_name.clone(),
            client_origin: client.display_origin.clone(),
            redirect_host,
            resource: resource.clone(),
            resource_name,
            resource_description,
            minimum_assurance,
            scopes,
            requirement,
        })
    }

    fn scope_description(&self, resource: &ResourceUri, requested: &Scope) -> String {
        match requested.as_str() {
            "openid" => "Sign in and identify your account.".to_owned(),
            "email" => "Read your verified email address.".to_owned(),
            "offline_access" => "Keep access after this browser session ends.".to_owned(),
            _ => self
                .resource(resource)
                .and_then(|declaration| {
                    declaration
                        .scopes()
                        .iter()
                        .find(|scope| scope.name() == requested)
                })
                .map_or_else(String::new, |scope| scope.description().to_owned()),
        }
    }
}

fn is_reserved_scope(scope: &Scope) -> bool {
    matches!(scope.as_str(), "openid" | "email" | "offline_access")
}

fn duration_seconds(seconds: u64) -> Duration {
    i64::try_from(seconds).map_or(Duration::MAX, Duration::seconds)
}

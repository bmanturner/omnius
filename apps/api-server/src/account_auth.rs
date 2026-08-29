//! Local account registration, verification, recovery, password, session, and invitation HTTP integration.

use std::{collections::BTreeSet, sync::Arc, time::Duration};

use axum::{
    Extension, Json, Router,
    extract::{
        Path, Query, State,
        rejection::{JsonRejection, QueryRejection},
    },
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::{IntoResponse as _, Response},
    routing::{delete, get, post},
};
use axum_login::AuthnBackend as _;
use omnius_auth_core::{
    AssuranceLevel, Principal, Scope, SessionConfig, SessionMetadata, SessionRegistration,
    hash_user_agent,
};
use omnius_auth_password::{
    IdentityTokenRequest, InvitationIssueRequest, InvitationIssuer, InvitationListRequest,
    InvitationMutation, InvitationToken, InvitationTokenPepper, OsInvitationTokenGenerator,
    OsTokenGenerator, PasswordInput, PasswordStoreError, PasswordVerification, PasswordWorker,
    PostgresPasswordStore, RegistrationInvitationMetadata, RegistrationMode, RegistrationPolicy,
    RegistrationRequest, TokenConsumption, TokenDispatch, TokenPurpose, VerificationToken,
};
use omnius_auth_session_postgres::{PostgresSessionLifecycle, SessionStoreError};
use omnius_authz_basic::{
    Action, AuthorizationContext, AuthorizationService, BasicPolicy, Decision, Grant, PolicyMatrix,
    PolicyRule, Resource, ResourceKind,
};
use omnius_config::{DeploymentEnvironment, SecretString};
use omnius_core::RequestId;
use omnius_email::{
    ClientMessageId, EmailAddress, EmailError, EmailService, EmailSubject, MailSender as _,
    MailboxAddress, RecipientSet, SendEmailRequest, TemplateContext, TemplateName,
};
use omnius_jobs_core::IdempotencyKey;
use omnius_postgres::PostgresPool;
use serde::{Deserialize, Serialize};
use serde_json::json;
use time::{OffsetDateTime, format_description::well_known::Rfc3339};
use uuid::Uuid;

use crate::browser_auth::{
    BrowserAuthBuildError, BrowserAuthSession, BrowserAuthState, protected_browser_router,
};
use crate::{ApiError, map_json_rejection, resolve_request_id};

/// Enumeration-safe local registration endpoint.
pub const REGISTER_PATH: &str = "/auth/register";
/// Enumeration-safe verification-message request endpoint.
pub const VERIFICATION_REQUEST_PATH: &str = "/auth/email/verification/request";
/// Single-use email verification completion endpoint.
pub const VERIFICATION_COMPLETE_PATH: &str = "/auth/email/verification/complete";
/// Enumeration-safe password recovery-message request endpoint.
pub const PASSWORD_RESET_REQUEST_PATH: &str = "/auth/password/reset/request";
/// Single-use password recovery completion endpoint.
pub const PASSWORD_RESET_COMPLETE_PATH: &str = "/auth/password/reset/complete";
/// Authenticated password change endpoint.
pub const PASSWORD_CHANGE_PATH: &str = "/auth/password/change";
/// Authenticated safe session inventory endpoint.
pub const SESSIONS_PATH: &str = "/auth/sessions";
/// Authenticated device revocation endpoint.
pub const SESSION_DEVICE_PATH: &str = "/auth/sessions/{device_id}";
/// AAL2 invitation management collection endpoint.
pub const INVITATIONS_PATH: &str = "/auth/registration-invitations";
/// AAL2 invitation management item endpoint.
pub const INVITATION_PATH: &str = "/auth/registration-invitations/{invitation_id}";

const INVITATION_PERMISSION: &str = "auth.registration-invitations.manage";
const VERIFICATION_TEMPLATE: &str = "account-email-verification";
const RECOVERY_TEMPLATE: &str = "account-password-recovery";
const INVITATION_TEMPLATE: &str = "account-registration-invitation";
const MAX_EMAIL_BYTES: usize = 320;
const DEFAULT_INVITATION_PAGE_SIZE: u16 = 50;
const MAX_ACCOUNT_MAIL_DELIVERIES: usize = 16;

/// Exact account email presentation configured by the application.
#[derive(Clone)]
pub struct AccountMailPresentation {
    from: MailboxAddress,
    verification_template: TemplateName,
    recovery_template: TemplateName,
    invitation_template: TemplateName,
    verification_subject: EmailSubject,
    recovery_subject: EmailSubject,
    invitation_subject: EmailSubject,
}

impl AccountMailPresentation {
    /// Builds the fixed account template and subject vocabulary.
    ///
    /// # Errors
    ///
    /// Returns a value-free email validation failure if a compiled constant is invalid.
    pub fn new(from: MailboxAddress) -> Result<Self, EmailError> {
        Ok(Self {
            from,
            verification_template: TemplateName::try_from(VERIFICATION_TEMPLATE)?,
            recovery_template: TemplateName::try_from(RECOVERY_TEMPLATE)?,
            invitation_template: TemplateName::try_from(INVITATION_TEMPLATE)?,
            verification_subject: EmailSubject::try_from("Verify your email address")?,
            recovery_subject: EmailSubject::try_from("Reset your password")?,
            invitation_subject: EmailSubject::try_from("You are invited to Omnius")?,
        })
    }

    /// Exact template names that must be allowlisted at startup.
    #[must_use]
    pub const fn required_templates() -> [&'static str; 3] {
        [
            VERIFICATION_TEMPLATE,
            RECOVERY_TEMPLATE,
            INVITATION_TEMPLATE,
        ]
    }
}

/// Shared local-account HTTP and delivery state.
#[derive(Clone)]
pub struct AccountAuthState {
    pool: PostgresPool,
    session_config: SessionConfig,
    password_worker: PasswordWorker,
    registration: RegistrationPolicy,
    invitation_pepper: Arc<InvitationTokenPepper>,
    response_floor: Duration,
    email: EmailService,
    mail: AccountMailPresentation,
    mail_delivery_permits: Arc<tokio::sync::Semaphore>,
    invitation_authorizer: omnius_authz_basic::BasicAuthorizer,
    invitation_action: Action,
    invitation_resource: ResourceKind,
}

impl AccountAuthState {
    /// Assembles validated application-owned account runtime state.
    ///
    /// # Errors
    ///
    /// Returns the existing authorization identifier or policy error when the fixed policy cannot
    /// be constructed.
    pub fn new(
        pool: PostgresPool,
        session_config: SessionConfig,
        password_worker: PasswordWorker,
        registration: RegistrationPolicy,
        invitation_pepper: InvitationTokenPepper,
        response_floor: Duration,
        email: EmailService,
        mail: AccountMailPresentation,
    ) -> Result<Self, AccountAuthBuildError> {
        if !(Duration::from_millis(500)..=Duration::from_secs(5)).contains(&response_floor) {
            return Err(AccountAuthBuildError::ResponseFloor);
        }
        let invitation_action = Action::new(INVITATION_PERMISSION)?;
        let invitation_resource = ResourceKind::new("registration_invitation")?;
        let required_scope = Scope::new(INVITATION_PERMISSION)
            .map_err(|_| AccountAuthBuildError::AuthorizationIdentifier)?;
        let rule = PolicyRule::new(
            invitation_action.clone(),
            invitation_resource.clone(),
            vec![Grant::Owner],
        )?
        .with_required_scopes(vec![required_scope])?
        .with_minimum_assurance(AssuranceLevel::Aal2);
        let invitation_authorizer =
            AuthorizationService::new(BasicPolicy::new(PolicyMatrix::new(vec![rule])?));
        Ok(Self {
            pool,
            session_config,
            password_worker,
            registration,
            invitation_pepper: Arc::new(invitation_pepper),
            response_floor,
            email,
            mail,
            mail_delivery_permits: Arc::new(tokio::sync::Semaphore::new(
                MAX_ACCOUNT_MAIL_DELIVERIES,
            )),
            invitation_authorizer,
            invitation_action,
            invitation_resource,
        })
    }

    /// Validated registration policy used by route and CLI composition.
    #[must_use]
    pub const fn registration(&self) -> &RegistrationPolicy {
        &self.registration
    }

    /// Validated invitation digest key retained only inside account runtime state.
    #[must_use]
    pub fn invitation_pepper(&self) -> &InvitationTokenPepper {
        &self.invitation_pepper
    }

    fn may_manage_invitations(&self, principal: &Principal) -> bool {
        let resource =
            Resource::new(self.invitation_resource.clone()).owned_by(principal.subject_id);
        self.invitation_authorizer.authorize(
            principal,
            &self.invitation_action,
            &resource,
            &AuthorizationContext::default(),
        ) == Decision::Allow
    }

    async fn send_verification(
        &self,
        recipient: &str,
        dispatch: &TokenDispatch,
    ) -> Result<(), AccountMailError> {
        if dispatch.purpose != TokenPurpose::EmailVerification {
            return Err(AccountMailError);
        }
        let link = self
            .registration
            .email_verification_link(&dispatch.token)
            .map_err(|_| AccountMailError)?;
        self.send_account_mail(
            recipient,
            self.mail.verification_template.clone(),
            self.mail.verification_subject.clone(),
            link.expose_for_delivery(),
            "verification",
        )
        .await
    }

    async fn send_recovery(
        &self,
        recipient: &str,
        dispatch: &TokenDispatch,
    ) -> Result<(), AccountMailError> {
        if dispatch.purpose != TokenPurpose::PasswordRecovery {
            return Err(AccountMailError);
        }
        let link = self
            .registration
            .password_reset_link(&dispatch.token)
            .map_err(|_| AccountMailError)?;
        self.send_account_mail(
            recipient,
            self.mail.recovery_template.clone(),
            self.mail.recovery_subject.clone(),
            link.expose_for_delivery(),
            "recovery",
        )
        .await
    }

    fn spawn_identity_mail(&self, recipient: String, dispatch: TokenDispatch) {
        let kind = match dispatch.purpose {
            TokenPurpose::EmailVerification => "verification",
            TokenPurpose::PasswordRecovery => "recovery",
        };
        let Ok(permit) = Arc::clone(&self.mail_delivery_permits).try_acquire_owned() else {
            tracing::warn!(
                mail_kind = kind,
                "account mail delivery skipped because the bounded delivery pool is full"
            );
            return;
        };
        let state = self.clone();
        let _delivery = tokio::spawn(async move {
            let _permit = permit;
            let result = match dispatch.purpose {
                TokenPurpose::EmailVerification => {
                    state.send_verification(&recipient, &dispatch).await
                }
                TokenPurpose::PasswordRecovery => state.send_recovery(&recipient, &dispatch).await,
            };
            if result.is_err() {
                tracing::warn!(
                    mail_kind = kind,
                    "account mail delivery failed after commit"
                );
            }
        });
    }

    /// Delivers one already-committed registration invitation through the configured provider.
    ///
    /// # Errors
    ///
    /// Returns a value-free delivery error. Neither the recipient nor bearer appears in it.
    pub async fn deliver_invitation(
        &self,
        recipient: &str,
        token: &InvitationToken,
    ) -> Result<(), AccountMailError> {
        let link = self
            .registration
            .invitation_link(token)
            .map_err(|_| AccountMailError)?;
        self.send_account_mail(
            recipient,
            self.mail.invitation_template.clone(),
            self.mail.invitation_subject.clone(),
            link.expose_for_delivery(),
            "invitation",
        )
        .await
    }

    async fn send_account_mail(
        &self,
        recipient: &str,
        template: TemplateName,
        subject: EmailSubject,
        action_url: &str,
        kind: &'static str,
    ) -> Result<(), AccountMailError> {
        let address = EmailAddress::try_from(recipient.to_owned()).map_err(|_| AccountMailError)?;
        let recipients = RecipientSet::new(
            vec![MailboxAddress::new(address, None)],
            Vec::new(),
            Vec::new(),
        )
        .map_err(|_| AccountMailError)?;
        let context = TemplateContext::new(json!({ "action_url": action_url }))
            .map_err(|_| AccountMailError)?;
        let idempotency = IdempotencyKey::try_from(format!("account-{kind}-{}", Uuid::now_v7()))
            .map_err(|_| AccountMailError)?;
        let request = SendEmailRequest::new(
            idempotency,
            ClientMessageId::new_random(),
            self.mail.from.clone(),
            recipients,
            subject,
            template,
            context,
        );
        self.email
            .send(request)
            .await
            .map_err(|_| AccountMailError)?;
        Ok(())
    }
}

/// Account route composition failure.
#[derive(Clone, Copy, Debug, thiserror::Error, Eq, PartialEq)]
pub enum AccountAuthBuildError {
    /// Fixed policy identifiers were invalid.
    #[error("account authorization identifier is invalid")]
    AuthorizationIdentifier,
    /// Fixed policy construction failed.
    #[error("account authorization policy is invalid: {0}")]
    Policy(#[from] omnius_authz_basic::PolicyError),
    /// Account discovery response floor was outside 500ms through five seconds.
    #[error("account discovery response floor is invalid")]
    ResponseFloor,
    /// Browser session layer construction failed.
    #[error("account browser session composition failed: {0}")]
    Browser(#[from] BrowserAuthBuildError),
}

impl From<omnius_authz_basic::IdentifierError> for AccountAuthBuildError {
    fn from(_value: omnius_authz_basic::IdentifierError) -> Self {
        Self::AuthorizationIdentifier
    }
}

/// Value-free account email delivery failure.
#[derive(Clone, Copy, Debug, thiserror::Error, Eq, PartialEq)]
#[error("account email delivery failed")]
pub struct AccountMailError;

/// Builds public and browser-session account lifecycle routes.
///
/// Public request endpoints always use the same accepted response for every syntactically valid
/// identity. Password changes and session inventory retain the maintained browser session layers.
/// Invitation management is returned separately by [`account_invitation_router`] so the common
/// principal boundary can accept revalidated AAL2 bearer authorities without weakening its gate.
///
/// # Errors
///
/// Returns the canonical browser session composition error.
pub fn account_auth_router(
    state: AccountAuthState,
    browser: &BrowserAuthState,
    deployment: DeploymentEnvironment,
) -> Result<Router, AccountAuthBuildError> {
    let mut public = Router::new()
        .route(VERIFICATION_REQUEST_PATH, post(request_email_verification))
        .route(
            VERIFICATION_COMPLETE_PATH,
            post(complete_email_verification),
        )
        .route(PASSWORD_RESET_REQUEST_PATH, post(request_password_reset))
        .route(PASSWORD_RESET_COMPLETE_PATH, post(complete_password_reset));
    if state.registration.mode() != RegistrationMode::Disabled {
        public = public.route(REGISTER_PATH, post(register));
    }
    let protected = Router::new()
        .route(PASSWORD_CHANGE_PATH, post(change_password))
        .route(SESSIONS_PATH, get(list_sessions))
        .route(SESSION_DEVICE_PATH, delete(revoke_device));
    let protected =
        protected_browser_router(browser, deployment, protected.with_state(state.clone()))?;
    Ok(public.with_state(state).merge(protected))
}

/// Builds AAL2 and scope-gated invitation routes for the common principal boundary.
#[must_use]
pub fn account_invitation_router(state: AccountAuthState) -> Router {
    if state.registration.mode() != RegistrationMode::InviteOnly {
        Router::new()
    } else {
        Router::new()
            .route(
                INVITATIONS_PATH,
                post(issue_invitation).get(list_invitations),
            )
            .route(INVITATION_PATH, delete(revoke_invitation))
            .with_state(state)
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RegisterRequest {
    email: String,
    password: SecretString,
    #[serde(default)]
    invitation: Option<SecretString>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct IdentityRequest {
    email: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct TokenCompletionRequest {
    token: SecretString,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PasswordResetCompletionRequest {
    token: SecretString,
    new_password: SecretString,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PasswordChangeRequest {
    current_password: SecretString,
    new_password: SecretString,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct InvitationIssueBody {
    email: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct InvitationListQuery {
    #[serde(default = "default_invitation_page_size")]
    limit: u16,
    #[serde(default)]
    before_created_at: Option<String>,
    #[serde(default)]
    before_id: Option<Uuid>,
}

const fn default_invitation_page_size() -> u16 {
    DEFAULT_INVITATION_PAGE_SIZE
}

#[derive(Serialize)]
struct AcceptedResponse {
    status: &'static str,
}

fn accepted_response() -> Response {
    let mut response = (
        StatusCode::ACCEPTED,
        Json(AcceptedResponse { status: "accepted" }),
    )
        .into_response();
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}

async fn register(
    State(state): State<AccountAuthState>,
    request_id: Option<Extension<RequestId>>,
    payload: Result<Json<RegisterRequest>, JsonRejection>,
) -> Result<Response, AccountHttpError> {
    let request_id = resolve_request_id(request_id);
    let Json(payload) =
        payload.map_err(|error| AccountHttpError(map_json_rejection(&error, request_id)))?;
    let not_before = tokio::time::Instant::now() + state.response_floor;
    let canonical_email = canonical_email(&payload.email)
        .map_err(|()| AccountHttpError::invalid_request(request_id))?;
    let invitation = match (state.registration.mode(), payload.invitation) {
        (RegistrationMode::SelfService, None) => None,
        (RegistrationMode::InviteOnly, Some(token)) => Some(
            InvitationToken::parse(token)
                .map_err(|_| AccountHttpError::invalid_request(request_id))?,
        ),
        _ => return Err(AccountHttpError::invalid_request(request_id)),
    };
    let password = PasswordInput::new(payload.password)
        .map_err(|_| AccountHttpError::invalid_password(request_id))?;
    let credential = state
        .password_worker
        .hash_password(password)
        .await
        .map_err(|_| AccountHttpError::internal(request_id))?;
    let now = OffsetDateTime::now_utc();
    let mut transaction = state
        .pool
        .sqlx_pool()
        .begin()
        .await
        .map_err(|_| AccountHttpError::unavailable(request_id))?;
    let outcome = PostgresPasswordStore
        .register_with(
            &mut transaction,
            &state.registration,
            RegistrationRequest {
                canonical_email: &canonical_email,
                credential: &credential,
                invitation: invitation.as_ref(),
                now,
            },
            &state.invitation_pepper,
            &OsTokenGenerator,
        )
        .await
        .map_err(|error| map_password_store_error(error, request_id))?;
    transaction
        .commit()
        .await
        .map_err(|_| AccountHttpError::unavailable(request_id))?;
    if let Some(dispatch) = outcome.into_post_commit_dispatch() {
        state.spawn_identity_mail(canonical_email, dispatch);
    }
    tokio::time::sleep_until(not_before).await;
    Ok(accepted_response())
}

async fn request_email_verification(
    State(state): State<AccountAuthState>,
    request_id: Option<Extension<RequestId>>,
    payload: Result<Json<IdentityRequest>, JsonRejection>,
) -> Result<Response, AccountHttpError> {
    request_identity_token(state, request_id, payload, TokenPurpose::EmailVerification).await
}

async fn request_password_reset(
    State(state): State<AccountAuthState>,
    request_id: Option<Extension<RequestId>>,
    payload: Result<Json<IdentityRequest>, JsonRejection>,
) -> Result<Response, AccountHttpError> {
    request_identity_token(state, request_id, payload, TokenPurpose::PasswordRecovery).await
}

async fn request_identity_token(
    state: AccountAuthState,
    request_id: Option<Extension<RequestId>>,
    payload: Result<Json<IdentityRequest>, JsonRejection>,
    purpose: TokenPurpose,
) -> Result<Response, AccountHttpError> {
    let request_id = resolve_request_id(request_id);
    let Json(payload) =
        payload.map_err(|error| AccountHttpError(map_json_rejection(&error, request_id)))?;
    let canonical_email = canonical_email(&payload.email)
        .map_err(|()| AccountHttpError::invalid_request(request_id))?;
    let ttl = match purpose {
        TokenPurpose::EmailVerification => state.registration.verification_ttl(),
        TokenPurpose::PasswordRecovery => state.registration.recovery_ttl(),
    };
    let mut transaction = state
        .pool
        .sqlx_pool()
        .begin()
        .await
        .map_err(|_| AccountHttpError::unavailable(request_id))?;
    let outcome = PostgresPasswordStore
        .request_for_identity_with(
            &mut transaction,
            IdentityTokenRequest {
                provider: state.registration.local_identity_provider(),
                provider_subject: &canonical_email,
                purpose,
                now: OffsetDateTime::now_utc(),
                ttl,
                response_floor: state.response_floor,
            },
            &OsTokenGenerator,
        )
        .await
        .map_err(|error| map_password_store_error(error, request_id))?;
    transaction
        .commit()
        .await
        .map_err(|_| AccountHttpError::unavailable(request_id))?;
    let completed = outcome.complete_after_commit().await;
    if let Some(dispatch) = completed.into_post_commit_dispatch() {
        state.spawn_identity_mail(canonical_email, dispatch);
    }
    Ok(accepted_response())
}

async fn complete_email_verification(
    State(state): State<AccountAuthState>,
    request_id: Option<Extension<RequestId>>,
    payload: Result<Json<TokenCompletionRequest>, JsonRejection>,
) -> Result<Response, AccountHttpError> {
    let request_id = resolve_request_id(request_id);
    let Json(payload) =
        payload.map_err(|error| AccountHttpError(map_json_rejection(&error, request_id)))?;
    let token = VerificationToken::parse(payload.token)
        .map_err(|_| AccountHttpError::token_rejected(request_id))?;
    let mut transaction = state
        .pool
        .sqlx_pool()
        .begin()
        .await
        .map_err(|_| AccountHttpError::unavailable(request_id))?;
    let consumed = PostgresPasswordStore
        .complete_email_verification_with(
            &mut transaction,
            &token,
            state.registration.local_identity_provider(),
            OffsetDateTime::now_utc(),
        )
        .await
        .map_err(|error| map_password_store_error(error, request_id))?;
    if consumed == TokenConsumption::Rejected {
        transaction
            .rollback()
            .await
            .map_err(|_| AccountHttpError::unavailable(request_id))?;
        return Err(AccountHttpError::token_rejected(request_id));
    }
    transaction
        .commit()
        .await
        .map_err(|_| AccountHttpError::unavailable(request_id))?;
    Ok(no_content_response())
}

async fn complete_password_reset(
    State(state): State<AccountAuthState>,
    request_id: Option<Extension<RequestId>>,
    payload: Result<Json<PasswordResetCompletionRequest>, JsonRejection>,
) -> Result<Response, AccountHttpError> {
    let request_id = resolve_request_id(request_id);
    let Json(payload) =
        payload.map_err(|error| AccountHttpError(map_json_rejection(&error, request_id)))?;
    let token = VerificationToken::parse(payload.token)
        .map_err(|_| AccountHttpError::token_rejected(request_id))?;
    let password = PasswordInput::new(payload.new_password)
        .map_err(|_| AccountHttpError::invalid_password(request_id))?;
    let credential = state
        .password_worker
        .hash_password(password)
        .await
        .map_err(|_| AccountHttpError::internal(request_id))?;
    let now = OffsetDateTime::now_utc();
    let mut transaction = state
        .pool
        .sqlx_pool()
        .begin()
        .await
        .map_err(|_| AccountHttpError::unavailable(request_id))?;
    let consumed = PostgresPasswordStore
        .recover_password_with(&mut transaction, &token, &credential, now)
        .await
        .map_err(|error| map_password_store_error(error, request_id))?;
    let TokenConsumption::Consumed(subject_id) = consumed else {
        transaction
            .rollback()
            .await
            .map_err(|_| AccountHttpError::unavailable(request_id))?;
        return Err(AccountHttpError::token_rejected(request_id));
    };
    PostgresSessionLifecycle
        .revoke_all_with(&mut transaction, subject_id, now)
        .await
        .map_err(|error| map_session_store_error(error, request_id))?;
    transaction
        .commit()
        .await
        .map_err(|_| AccountHttpError::unavailable(request_id))?;
    Ok(no_content_response())
}

async fn change_password(
    State(state): State<AccountAuthState>,
    request_id: Option<Extension<RequestId>>,
    Extension(principal): Extension<Principal>,
    Extension(current): Extension<SessionMetadata>,
    headers: HeaderMap,
    mut auth: BrowserAuthSession,
    payload: Result<Json<PasswordChangeRequest>, JsonRejection>,
) -> Result<Response, AccountHttpError> {
    let request_id = resolve_request_id(request_id);
    let Json(payload) =
        payload.map_err(|error| AccountHttpError(map_json_rejection(&error, request_id)))?;
    let current_password = PasswordInput::new(payload.current_password)
        .map_err(|_| AccountHttpError::current_password_rejected(request_id))?;
    let new_password = PasswordInput::new(payload.new_password)
        .map_err(|_| AccountHttpError::invalid_password(request_id))?;
    let replacement = state
        .password_worker
        .hash_password(new_password)
        .await
        .map_err(|_| AccountHttpError::internal(request_id))?;
    let now = OffsetDateTime::now_utc();
    let mut transaction = state
        .pool
        .sqlx_pool()
        .begin()
        .await
        .map_err(|_| AccountHttpError::unavailable(request_id))?;
    let verification = PostgresPasswordStore
        .verify_password_with(
            &mut transaction,
            principal.subject_id,
            current_password,
            &state.password_worker,
            now,
        )
        .await
        .map_err(|error| map_password_store_error(error, request_id))?;
    if !matches!(verification, PasswordVerification::Verified { .. }) {
        transaction
            .rollback()
            .await
            .map_err(|_| AccountHttpError::unavailable(request_id))?;
        return Err(AccountHttpError::current_password_rejected(request_id));
    }
    let active_sessions = PostgresSessionLifecycle
        .list_active_with(&mut transaction, principal.subject_id, &auth.session, now)
        .await
        .map_err(|error| map_session_store_error(error, request_id))?;
    let sibling_devices: BTreeSet<Uuid> = active_sessions
        .into_iter()
        .filter(|session| !session.current)
        .map(|session| session.device_id)
        .collect();
    for device_id in sibling_devices {
        PostgresSessionLifecycle
            .revoke_device_with(&mut transaction, principal.subject_id, device_id, now)
            .await
            .map_err(|error| map_session_store_error(error, request_id))?;
    }
    PostgresPasswordStore
        .replace_password_with(&mut transaction, principal.subject_id, &replacement, now)
        .await
        .map_err(|error| map_password_store_error(error, request_id))?;
    transaction
        .commit()
        .await
        .map_err(|_| AccountHttpError::unavailable(request_id))?;

    let user = auth
        .backend
        .get_user(&principal.subject_id)
        .await
        .map_err(|_| AccountHttpError::unavailable(request_id))?
        .ok_or_else(|| AccountHttpError::authentication_required(request_id))?;
    auth.login(&user)
        .await
        .map_err(|_| AccountHttpError::internal(request_id))?;
    let user_agent_hash = headers
        .get(header::USER_AGENT)
        .map(|value| hash_user_agent(value.as_bytes()));
    PostgresSessionLifecycle
        .rotate_after_security_change(
            &state.pool,
            &auth.session,
            principal.subject_id,
            &SessionRegistration {
                subject_id: principal.subject_id,
                device_id: current.device_id,
                created_at: now,
                user_agent_hash,
                ip_prefix: None,
            },
            &state.session_config,
            now,
        )
        .await
        .map_err(|error| map_session_store_error(error, request_id))?;
    Ok(no_content_response())
}

async fn list_sessions(
    State(state): State<AccountAuthState>,
    request_id: Option<Extension<RequestId>>,
    Extension(principal): Extension<Principal>,
    auth: BrowserAuthSession,
) -> Result<Response, AccountHttpError> {
    let request_id = resolve_request_id(request_id);
    let mut connection = state
        .pool
        .acquire()
        .await
        .map_err(|_| AccountHttpError::unavailable(request_id))?;
    let sessions = PostgresSessionLifecycle
        .list_active_with(
            &mut connection,
            principal.subject_id,
            &auth.session,
            OffsetDateTime::now_utc(),
        )
        .await
        .map_err(|error| map_session_store_error(error, request_id))?;
    let sessions = sessions
        .into_iter()
        .map(SessionResponse::try_from)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|()| AccountHttpError::internal(request_id))?;
    Ok(no_store_json(SessionListResponse { sessions }))
}

async fn revoke_device(
    State(state): State<AccountAuthState>,
    request_id: Option<Extension<RequestId>>,
    Extension(principal): Extension<Principal>,
    Extension(current): Extension<SessionMetadata>,
    Path(device_id): Path<String>,
    mut auth: BrowserAuthSession,
) -> Result<Response, AccountHttpError> {
    let request_id = resolve_request_id(request_id);
    let device_id =
        Uuid::parse_str(&device_id).map_err(|_| AccountHttpError::invalid_path(request_id))?;
    let now = OffsetDateTime::now_utc();
    let mut transaction = state
        .pool
        .sqlx_pool()
        .begin()
        .await
        .map_err(|_| AccountHttpError::unavailable(request_id))?;
    let revoked = PostgresSessionLifecycle
        .revoke_device_with(&mut transaction, principal.subject_id, device_id, now)
        .await
        .map_err(|error| map_session_store_error(error, request_id))?;
    transaction
        .commit()
        .await
        .map_err(|_| AccountHttpError::unavailable(request_id))?;
    if current.device_id == device_id {
        auth.logout()
            .await
            .map_err(|_| AccountHttpError::internal(request_id))?;
    }
    if revoked == 0 {
        return Err(AccountHttpError::session_not_found(request_id));
    }
    Ok(no_content_response())
}

async fn issue_invitation(
    State(state): State<AccountAuthState>,
    request_id: Option<Extension<RequestId>>,
    Extension(principal): Extension<Principal>,
    payload: Result<Json<InvitationIssueBody>, JsonRejection>,
) -> Result<Response, AccountHttpError> {
    let request_id = resolve_request_id(request_id);
    require_invitation_permission(&state, &principal, request_id)?;
    let Json(payload) =
        payload.map_err(|error| AccountHttpError(map_json_rejection(&error, request_id)))?;
    let canonical_email = canonical_email(&payload.email)
        .map_err(|()| AccountHttpError::invalid_request(request_id))?;
    let mut transaction = state
        .pool
        .sqlx_pool()
        .begin()
        .await
        .map_err(|_| AccountHttpError::unavailable(request_id))?;
    let issued = PostgresPasswordStore
        .issue_invitation_with(
            &mut transaction,
            InvitationIssueRequest {
                identity_provider: state.registration.local_identity_provider(),
                canonical_email: &canonical_email,
                issuer: InvitationIssuer::User(principal.subject_id),
                now: OffsetDateTime::now_utc(),
                ttl: state.registration.invitation_ttl(),
            },
            &state.invitation_pepper,
            &OsInvitationTokenGenerator,
        )
        .await
        .map_err(|error| map_password_store_error(error, request_id))?;
    transaction
        .commit()
        .await
        .map_err(|_| AccountHttpError::unavailable(request_id))?;
    state
        .deliver_invitation(&canonical_email, &issued.token)
        .await
        .map_err(|_| AccountHttpError::delivery_unavailable(request_id))?;
    let response = InvitationResponse::try_from(&issued.metadata)
        .map_err(|()| AccountHttpError::internal(request_id))?;
    Ok(created_json(response))
}

async fn list_invitations(
    State(state): State<AccountAuthState>,
    request_id: Option<Extension<RequestId>>,
    Extension(principal): Extension<Principal>,
    query: Result<Query<InvitationListQuery>, QueryRejection>,
) -> Result<Response, AccountHttpError> {
    let request_id = resolve_request_id(request_id);
    require_invitation_permission(&state, &principal, request_id)?;
    let Query(query) = query.map_err(|_| AccountHttpError::invalid_request(request_id))?;
    let mut request = InvitationListRequest::new(query.limit)
        .map_err(|_| AccountHttpError::invalid_request(request_id))?;
    match (query.before_created_at, query.before_id) {
        (None, None) => {}
        (Some(created_at), Some(id)) => {
            let created_at = OffsetDateTime::parse(&created_at, &Rfc3339)
                .map_err(|_| AccountHttpError::invalid_request(request_id))?;
            request = request.before(created_at, id);
        }
        _ => return Err(AccountHttpError::invalid_request(request_id)),
    }
    let mut connection = state
        .pool
        .acquire()
        .await
        .map_err(|_| AccountHttpError::unavailable(request_id))?;
    let invitations = PostgresPasswordStore
        .list_invitations_with(&mut connection, request)
        .await
        .map_err(|error| map_password_store_error(error, request_id))?
        .iter()
        .map(InvitationResponse::try_from)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|()| AccountHttpError::internal(request_id))?;
    Ok(no_store_json(InvitationListResponse { invitations }))
}

async fn revoke_invitation(
    State(state): State<AccountAuthState>,
    request_id: Option<Extension<RequestId>>,
    Extension(principal): Extension<Principal>,
    Path(invitation_id): Path<String>,
) -> Result<Response, AccountHttpError> {
    let request_id = resolve_request_id(request_id);
    require_invitation_permission(&state, &principal, request_id)?;
    let invitation_id =
        Uuid::parse_str(&invitation_id).map_err(|_| AccountHttpError::invalid_path(request_id))?;
    let mut connection = state
        .pool
        .acquire()
        .await
        .map_err(|_| AccountHttpError::unavailable(request_id))?;
    let mutation = PostgresPasswordStore
        .revoke_invitation_with(&mut connection, invitation_id, OffsetDateTime::now_utc())
        .await
        .map_err(|error| map_password_store_error(error, request_id))?;
    if mutation == InvitationMutation::Rejected {
        return Err(AccountHttpError::invitation_not_found(request_id));
    }
    Ok(no_content_response())
}

fn require_invitation_permission(
    state: &AccountAuthState,
    principal: &Principal,
    request_id: RequestId,
) -> Result<(), AccountHttpError> {
    if state.may_manage_invitations(principal) {
        Ok(())
    } else {
        Err(AccountHttpError::permission_denied(request_id))
    }
}

/// Validates and canonicalizes one bounded email identity for account persistence.
///
/// The error intentionally carries no rejected value.
///
/// # Errors
///
/// Returns `()` for padded, oversized, control-bearing, or syntactically invalid input.
pub fn canonical_email(value: &str) -> Result<String, ()> {
    if value.is_empty()
        || value.len() > MAX_EMAIL_BYTES
        || value.trim() != value
        || value.chars().any(char::is_control)
    {
        return Err(());
    }
    let canonical = value.to_ascii_lowercase();
    EmailAddress::try_from(canonical.clone()).map_err(|_| ())?;
    Ok(canonical)
}

#[derive(Serialize)]
struct SessionListResponse {
    sessions: Vec<SessionResponse>,
}

#[derive(Serialize)]
struct SessionResponse {
    device_id: Uuid,
    created_at: String,
    last_seen_at: String,
    absolute_expires_at: String,
    current: bool,
}

impl TryFrom<SessionMetadata> for SessionResponse {
    type Error = ();

    fn try_from(value: SessionMetadata) -> Result<Self, Self::Error> {
        Ok(Self {
            device_id: value.device_id,
            created_at: value.created_at.format(&Rfc3339).map_err(|_| ())?,
            last_seen_at: value.last_seen_at.format(&Rfc3339).map_err(|_| ())?,
            absolute_expires_at: value.absolute_expires_at.format(&Rfc3339).map_err(|_| ())?,
            current: value.current,
        })
    }
}

#[derive(Serialize)]
struct InvitationListResponse {
    invitations: Vec<InvitationResponse>,
}

#[derive(Serialize)]
struct InvitationResponse {
    id: Uuid,
    email: String,
    issuer_kind: &'static str,
    issuer_id: Option<String>,
    created_at: String,
    expires_at: String,
    consumed_at: Option<String>,
    revoked_at: Option<String>,
}

impl TryFrom<&RegistrationInvitationMetadata> for InvitationResponse {
    type Error = ();

    fn try_from(value: &RegistrationInvitationMetadata) -> Result<Self, Self::Error> {
        let (issuer_kind, issuer_id) = match value.issuer {
            InvitationIssuer::System => ("system", None),
            InvitationIssuer::User(id) => ("user", Some(id.to_string())),
            InvitationIssuer::ServiceAccount(id) => ("service_account", Some(id.to_string())),
        };
        Ok(Self {
            id: value.id,
            email: value.canonical_email().to_owned(),
            issuer_kind,
            issuer_id,
            created_at: value.created_at.format(&Rfc3339).map_err(|_| ())?,
            expires_at: value.expires_at.format(&Rfc3339).map_err(|_| ())?,
            consumed_at: value
                .consumed_at
                .map(|time| time.format(&Rfc3339).map_err(|_| ()))
                .transpose()?,
            revoked_at: value
                .revoked_at
                .map(|time| time.format(&Rfc3339).map_err(|_| ()))
                .transpose()?,
        })
    }
}

fn no_content_response() -> Response {
    let mut response = StatusCode::NO_CONTENT.into_response();
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}

fn no_store_json(value: impl Serialize) -> Response {
    let mut response = Json(value).into_response();
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}

fn created_json(value: impl Serialize) -> Response {
    let mut response = (StatusCode::CREATED, Json(value)).into_response();
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}

#[derive(Clone, Copy, Debug)]
struct AccountHttpError(ApiError);

impl AccountHttpError {
    const fn invalid_request(request_id: RequestId) -> Self {
        Self(ApiError::new(
            StatusCode::BAD_REQUEST,
            "INVALID_ACCOUNT_REQUEST",
            "account request is invalid",
            request_id,
        ))
    }

    const fn invalid_path(request_id: RequestId) -> Self {
        Self(ApiError::new(
            StatusCode::BAD_REQUEST,
            "INVALID_PATH_PARAMETER",
            "path parameter is invalid",
            request_id,
        ))
    }

    const fn invalid_password(request_id: RequestId) -> Self {
        Self(ApiError::new(
            StatusCode::UNPROCESSABLE_ENTITY,
            "PASSWORD_POLICY_REJECTED",
            "the supplied password does not satisfy policy",
            request_id,
        ))
    }

    const fn token_rejected(request_id: RequestId) -> Self {
        Self(ApiError::new(
            StatusCode::BAD_REQUEST,
            "ACCOUNT_TOKEN_REJECTED",
            "the account token is invalid or no longer active",
            request_id,
        ))
    }

    const fn current_password_rejected(request_id: RequestId) -> Self {
        Self(ApiError::new(
            StatusCode::UNAUTHORIZED,
            "CURRENT_PASSWORD_REJECTED",
            "the current password was rejected",
            request_id,
        ))
    }

    const fn authentication_required(request_id: RequestId) -> Self {
        Self(ApiError::new(
            StatusCode::UNAUTHORIZED,
            "AUTHENTICATION_REQUIRED",
            "a valid browser session is required",
            request_id,
        ))
    }

    const fn permission_denied(request_id: RequestId) -> Self {
        Self(ApiError::new(
            StatusCode::FORBIDDEN,
            "PERMISSION_DENIED",
            "the authenticated principal is not permitted to perform this operation",
            request_id,
        ))
    }

    const fn session_not_found(request_id: RequestId) -> Self {
        Self(ApiError::new(
            StatusCode::NOT_FOUND,
            "SESSION_NOT_FOUND",
            "the active device session was not found",
            request_id,
        ))
    }

    const fn invitation_not_found(request_id: RequestId) -> Self {
        Self(ApiError::new(
            StatusCode::NOT_FOUND,
            "INVITATION_NOT_FOUND",
            "the active registration invitation was not found",
            request_id,
        ))
    }

    const fn delivery_unavailable(request_id: RequestId) -> Self {
        Self(ApiError::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "EMAIL_DELIVERY_UNAVAILABLE",
            "account email delivery is temporarily unavailable",
            request_id,
        ))
    }

    const fn unavailable(request_id: RequestId) -> Self {
        Self(ApiError::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "ACCOUNT_SERVICE_UNAVAILABLE",
            "account service is temporarily unavailable",
            request_id,
        ))
    }

    const fn internal(request_id: RequestId) -> Self {
        Self(ApiError::internal(request_id))
    }
}

impl axum::response::IntoResponse for AccountHttpError {
    fn into_response(self) -> Response {
        self.0.into_response()
    }
}

const fn map_password_store_error(
    error: PasswordStoreError,
    request_id: RequestId,
) -> AccountHttpError {
    match error {
        PasswordStoreError::Unavailable | PasswordStoreError::Transient(_) => {
            AccountHttpError::unavailable(request_id)
        }
        PasswordStoreError::Conflict => AccountHttpError(ApiError::new(
            StatusCode::CONFLICT,
            "ACCOUNT_CONFLICT",
            "account state changed concurrently",
            request_id,
        )),
        PasswordStoreError::InvalidRequest => AccountHttpError::invalid_request(request_id),
        _ => AccountHttpError::internal(request_id),
    }
}

const fn map_session_store_error(
    error: SessionStoreError,
    request_id: RequestId,
) -> AccountHttpError {
    match error {
        SessionStoreError::Unavailable | SessionStoreError::Transient(_) => {
            AccountHttpError::unavailable(request_id)
        }
        SessionStoreError::Inactive => AccountHttpError::authentication_required(request_id),
        _ => AccountHttpError::internal(request_id),
    }
}

#[cfg(test)]
mod tests {
    use omnius_auth_core::{AuthMethod, PrincipalKind, SubjectId};

    use super::*;

    #[test]
    fn canonical_email_is_bounded_and_normalized() {
        assert_eq!(
            canonical_email("Person@Example.COM").as_deref(),
            Ok("person@example.com")
        );
        assert!(canonical_email(" person@example.com").is_err());
        assert!(canonical_email("not-an-address").is_err());
    }

    #[test]
    fn invitation_permission_requires_scope_and_aal2() -> Result<(), Box<dyn std::error::Error>> {
        let action = Action::new(INVITATION_PERMISSION)?;
        let kind = ResourceKind::new("registration_invitation")?;
        let rule = PolicyRule::new(action.clone(), kind.clone(), vec![Grant::Owner])?
            .with_required_scopes(vec![Scope::new(INVITATION_PERMISSION)?])?
            .with_minimum_assurance(AssuranceLevel::Aal2);
        let authorizer =
            AuthorizationService::new(BasicPolicy::new(PolicyMatrix::new(vec![rule])?));
        let subject_id = SubjectId::new();
        let resource = Resource::new(kind).owned_by(subject_id);
        let principal = Principal {
            subject_id,
            kind: PrincipalKind::User,
            tenant_id: None,
            auth_method: AuthMethod::Session,
            authenticated_at: OffsetDateTime::UNIX_EPOCH,
            assurance: AssuranceLevel::Aal1,
            scopes: vec![Scope::new(INVITATION_PERMISSION)?],
        };
        assert_ne!(
            authorizer.authorize(
                &principal,
                &action,
                &resource,
                &AuthorizationContext::default()
            ),
            Decision::Allow
        );
        let mut aal2 = principal;
        aal2.assurance = AssuranceLevel::Aal2;
        aal2.scopes.clear();
        assert_ne!(
            authorizer.authorize(&aal2, &action, &resource, &AuthorizationContext::default()),
            Decision::Allow
        );
        Ok(())
    }

    #[test]
    fn accepted_discovery_shape_contains_no_identity() -> Result<(), serde_json::Error> {
        let body = serde_json::to_value(AcceptedResponse { status: "accepted" })?;
        assert_eq!(body, json!({ "status": "accepted" }));
        Ok(())
    }
}

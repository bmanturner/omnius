use std::{
    fmt,
    sync::Arc,
    time::{Duration, Instant},
};

use rsk_auth_core::{AssuranceLevel, AuthMethod, Principal, PrincipalKind, SubjectId};
use rsk_config::DeploymentEnvironment;
use rsk_core::{Clock, SystemClock};
use rsk_postgres::{PostgresPool, RetryableSqlState};
use serde_json::Value;
use sqlx::{Connection as _, Postgres, Row as _, Transaction};
use time::{Duration as TimeDuration, OffsetDateTime, UtcOffset};
use uuid::{Uuid, Variant, Version};
use webauthn_rs::prelude::{
    Credential, CredentialID, DiscoverableAuthentication, DiscoverableKey, Passkey,
    PasskeyAuthentication, PasskeyRegistration, PublicKeyCredential, RegisterPublicKeyCredential,
    Webauthn, WebauthnBuilder,
};

use crate::{
    AuthenticationStart, CeremonyHandle, PasskeyMetadata, RegistrationStart, WebAuthnConfig,
    WebAuthnServiceError,
};

const MAX_NAME_BYTES: usize = 255;
const MAX_TRANSPORTS: usize = 7;
const MAX_CREDENTIAL_ID_BYTES: usize = 1_024;
const AUTHENTICATED_CEREMONY_CAPACITY_LOCK_ID: i64 = 2_026_082_309;
const DISCOVERABLE_CEREMONY_CAPACITY_LOCK_ID: i64 = 2_026_082_310;

const KIND_REGISTRATION: &str = "registration";
const KIND_AUTHENTICATION: &str = "authentication";
const KIND_DISCOVERABLE: &str = "discoverable_authentication";

/// Complete PostgreSQL-backed `WebAuthn` relying-party service.
///
/// Ceremony state is always held server-side behind a hashed, random, one-use handle. Protocol
/// inputs and outputs remain official `webauthn-rs` types so origin, RP, challenge, signature, and
/// user-verification validation cannot be bypassed by application parsing.
#[derive(Clone)]
pub struct WebAuthnService {
    pool: PostgresPool,
    webauthn: Arc<Webauthn>,
    clock: Arc<dyn Clock>,
    ceremony_ttl: TimeDuration,
    recent_auth_age: TimeDuration,
    max_credentials_per_user: usize,
    max_pending_ceremonies: usize,
    max_pending_discoverable_ceremonies: usize,
    max_pending_ceremonies_per_user: usize,
}

impl fmt::Debug for WebAuthnService {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("WebAuthnService")
            .field("relying_party", &"[REDACTED]")
            .field("ceremony_ttl", &self.ceremony_ttl)
            .field("recent_auth_age", &self.recent_auth_age)
            .field("max_credentials_per_user", &self.max_credentials_per_user)
            .field("max_pending_ceremonies", &self.max_pending_ceremonies)
            .field(
                "max_pending_discoverable_ceremonies",
                &self.max_pending_discoverable_ceremonies,
            )
            .field(
                "max_pending_ceremonies_per_user",
                &self.max_pending_ceremonies_per_user,
            )
            .finish_non_exhaustive()
    }
}

impl WebAuthnService {
    /// Builds an enabled service using the system UTC clock.
    ///
    /// # Errors
    ///
    /// Returns a stable error when the capability is disabled or its exact-origin policy is invalid.
    pub fn new(
        pool: PostgresPool,
        config: &WebAuthnConfig,
        deployment: DeploymentEnvironment,
    ) -> Result<Self, WebAuthnServiceError> {
        Self::with_clock(pool, config, deployment, Arc::new(SystemClock))
    }

    /// Builds an enabled service with an injected deterministic UTC clock.
    ///
    /// # Errors
    ///
    /// Returns a stable error when the capability is disabled, configuration is invalid, or a
    /// standard-library duration cannot be represented by the service clock.
    pub fn with_clock(
        pool: PostgresPool,
        config: &WebAuthnConfig,
        deployment: DeploymentEnvironment,
        clock: Arc<dyn Clock>,
    ) -> Result<Self, WebAuthnServiceError> {
        if !config.enabled {
            return Err(WebAuthnServiceError::Disabled);
        }
        let origins = config
            .parsed_origins(deployment)
            .map_err(|_| WebAuthnServiceError::InvalidConfiguration)?;
        let first = origins
            .first()
            .ok_or(WebAuthnServiceError::InvalidConfiguration)?;
        let mut builder = WebauthnBuilder::new(&config.rp_id, first)
            .map_err(|_| WebAuthnServiceError::InvalidConfiguration)?
            .rp_name(&config.rp_name)
            .timeout(config.ceremony_ttl)
            .allow_subdomains(false)
            .allow_any_port(false);
        for origin in origins.iter().skip(1) {
            builder = builder.append_allowed_origin(origin);
        }
        let webauthn = builder
            .build()
            .map_err(|_| WebAuthnServiceError::InvalidConfiguration)?;
        let ceremony_ttl = TimeDuration::try_from(config.ceremony_ttl)
            .map_err(|_| WebAuthnServiceError::InvalidConfiguration)?;
        let recent_auth_age = TimeDuration::try_from(config.recent_auth_age)
            .map_err(|_| WebAuthnServiceError::InvalidConfiguration)?;
        Ok(Self {
            pool,
            webauthn: Arc::new(webauthn),
            clock,
            ceremony_ttl,
            recent_auth_age,
            max_credentials_per_user: config.max_credentials_per_user,
            max_pending_ceremonies: config.max_pending_ceremonies,
            max_pending_discoverable_ceremonies: config.max_pending_discoverable_ceremonies,
            max_pending_ceremonies_per_user: config.max_pending_ceremonies_per_user,
        })
    }

    /// Starts registration after proving that the user principal authenticated recently.
    ///
    /// Existing credential IDs are loaded into the official exclusion list. The returned handle
    /// references durable server-side [`PasskeyRegistration`] state and is never itself persisted.
    ///
    /// # Errors
    ///
    /// Returns a stable recent-authentication, user, limit, protocol, or persistence error.
    pub async fn start_registration(
        &self,
        principal: &Principal,
        user_name: &str,
        user_display_name: &str,
        credential_name: &str,
    ) -> Result<RegistrationStart, WebAuthnServiceError> {
        let started = Instant::now();
        let result = self
            .start_registration_inner(principal, user_name, user_display_name, credential_name)
            .await;
        record(
            "start_registration",
            label(&result, "started"),
            started.elapsed(),
        );
        result
    }

    async fn start_registration_inner(
        &self,
        principal: &Principal,
        user_name: &str,
        user_display_name: &str,
        credential_name: &str,
    ) -> Result<RegistrationStart, WebAuthnServiceError> {
        valid_name(user_name)?;
        valid_name(user_display_name)?;
        valid_name(credential_name)?;

        let user_id = principal.subject_id;
        let mut connection = self
            .pool
            .acquire()
            .await
            .map_err(|_| WebAuthnServiceError::Unavailable)?;
        let mut tx = connection.begin().await.map_err(|error| map_db(&error))?;
        let result = async {
            if !lock_user(&mut tx, user_id).await? {
                return Err(WebAuthnServiceError::UserNotFound);
            }
            let now = self.now();
            self.require_recent_user(principal, now)?;
            reserve_ceremony_capacity(
                &mut tx,
                Some(user_id),
                now,
                self.max_pending_ceremonies,
                self.max_pending_discoverable_ceremonies,
                self.max_pending_ceremonies_per_user,
            )
            .await?;
            let rows = sqlx::query(
                "SELECT credential_id FROM webauthn_credentials \
                 WHERE user_id = $1 ORDER BY created_at, id FOR KEY SHARE",
            )
            .bind(user_id.as_uuid())
            .fetch_all(&mut *tx)
            .await
            .map_err(|error| map_db(&error))?;
            if rows.len() >= self.max_credentials_per_user {
                return Err(WebAuthnServiceError::CredentialLimitReached);
            }
            let excluded = rows
                .into_iter()
                .map(|row| {
                    let bytes: Vec<u8> = row
                        .try_get("credential_id")
                        .map_err(|_| WebAuthnServiceError::CorruptData)?;
                    valid_credential_id(&bytes)?;
                    Ok(CredentialID::from(bytes))
                })
                .collect::<Result<Vec<_>, WebAuthnServiceError>>()?;
            let excluded = (!excluded.is_empty()).then_some(excluded);
            let (public_key, state) = self
                .webauthn
                .start_passkey_registration(
                    user_id.as_uuid(),
                    user_name,
                    user_display_name,
                    excluded,
                )
                .map_err(|_| WebAuthnServiceError::VerificationFailed)?;
            let state =
                serde_json::to_value(state).map_err(|_| WebAuthnServiceError::CorruptData)?;
            let handle = CeremonyHandle::generate();
            insert_ceremony(
                &mut tx,
                &handle,
                KIND_REGISTRATION,
                Some(user_id),
                Some(credential_name),
                state,
                now,
                self.expires_at(now)?,
            )
            .await?;
            Ok(RegistrationStart {
                public_key,
                ceremony_handle: handle,
            })
        }
        .await;
        finish(tx, result).await
    }

    /// Starts username/account-bound authentication for all active credentials of one user.
    ///
    /// # Errors
    ///
    /// Returns a stable missing-user, no-active-credential, protocol, or persistence error.
    pub async fn start_authentication(
        &self,
        user_id: SubjectId,
    ) -> Result<AuthenticationStart, WebAuthnServiceError> {
        let started = Instant::now();
        let result = self.start_authentication_inner(user_id).await;
        record(
            "start_authentication",
            label(&result, "started"),
            started.elapsed(),
        );
        result
    }

    async fn start_authentication_inner(
        &self,
        user_id: SubjectId,
    ) -> Result<AuthenticationStart, WebAuthnServiceError> {
        let mut connection = self
            .pool
            .acquire()
            .await
            .map_err(|_| WebAuthnServiceError::Unavailable)?;
        let mut tx = connection.begin().await.map_err(|error| map_db(&error))?;
        let result = async {
            if !lock_user(&mut tx, user_id).await? {
                return Err(WebAuthnServiceError::UserNotFound);
            }
            let now = self.now();
            reserve_ceremony_capacity(
                &mut tx,
                Some(user_id),
                now,
                self.max_pending_ceremonies,
                self.max_pending_discoverable_ceremonies,
                self.max_pending_ceremonies_per_user,
            )
            .await?;
            let credentials =
                load_active_passkeys(&mut tx, user_id, self.max_credentials_per_user).await?;
            if credentials.is_empty() {
                return Err(WebAuthnServiceError::NoActiveCredentials);
            }
            let (public_key, state) = self
                .webauthn
                .start_passkey_authentication(&credentials)
                .map_err(|_| WebAuthnServiceError::VerificationFailed)?;
            let state =
                serde_json::to_value(state).map_err(|_| WebAuthnServiceError::CorruptData)?;
            let handle = CeremonyHandle::generate();
            insert_ceremony(
                &mut tx,
                &handle,
                KIND_AUTHENTICATION,
                Some(user_id),
                None,
                state,
                now,
                self.expires_at(now)?,
            )
            .await?;
            Ok(AuthenticationStart {
                public_key,
                ceremony_handle: handle,
            })
        }
        .await;
        finish(tx, result).await
    }

    /// Starts an opportunistic discoverable conditional-UI authentication ceremony.
    ///
    /// The official crate emits an empty allow-list and conditional mediation. Account-bound
    /// authentication remains available because discoverability is not guaranteed for passkeys.
    ///
    /// # Errors
    ///
    /// Returns a stable protocol or persistence error.
    pub async fn start_discoverable_authentication(
        &self,
    ) -> Result<AuthenticationStart, WebAuthnServiceError> {
        let started = Instant::now();
        let result = self.start_discoverable_inner().await;
        record(
            "start_discoverable_authentication",
            label(&result, "started"),
            started.elapsed(),
        );
        result
    }

    async fn start_discoverable_inner(&self) -> Result<AuthenticationStart, WebAuthnServiceError> {
        let (public_key, state) = self
            .webauthn
            .start_discoverable_authentication()
            .map_err(|_| WebAuthnServiceError::VerificationFailed)?;
        let state = serde_json::to_value(state).map_err(|_| WebAuthnServiceError::CorruptData)?;
        let handle = CeremonyHandle::generate();
        let mut connection = self
            .pool
            .acquire()
            .await
            .map_err(|_| WebAuthnServiceError::Unavailable)?;
        let mut tx = connection.begin().await.map_err(|error| map_db(&error))?;
        let now = self.now();
        reserve_ceremony_capacity(
            &mut tx,
            None,
            now,
            self.max_pending_ceremonies,
            self.max_pending_discoverable_ceremonies,
            self.max_pending_ceremonies_per_user,
        )
        .await?;
        let result = insert_ceremony(
            &mut tx,
            &handle,
            KIND_DISCOVERABLE,
            None,
            None,
            state,
            now,
            self.expires_at(now)?,
        )
        .await
        .map(|()| AuthenticationStart {
            public_key,
            ceremony_handle: handle,
        });
        finish(tx, result).await
    }

    /// Finishes registration after irreversibly consuming its server-side ceremony state.
    ///
    /// The official crate validates the challenge, exact origin, RP ID hash, attestation,
    /// credential exclusion, and user verification before the returned passkey is persisted.
    ///
    /// # Errors
    ///
    /// Returns a stable one-use-state, verification, limit, conflict, or persistence error.
    pub async fn finish_registration(
        &self,
        ceremony_handle: &CeremonyHandle,
        response: &RegisterPublicKeyCredential,
    ) -> Result<PasskeyMetadata, WebAuthnServiceError> {
        let started = Instant::now();
        let result = self
            .finish_registration_inner(ceremony_handle, response)
            .await;
        record(
            "finish_registration",
            label(&result, "registered"),
            started.elapsed(),
        );
        result
    }

    async fn finish_registration_inner(
        &self,
        ceremony_handle: &CeremonyHandle,
        response: &RegisterPublicKeyCredential,
    ) -> Result<PasskeyMetadata, WebAuthnServiceError> {
        let consumed = consume_ceremony(&self.pool, ceremony_handle, self.clock.as_ref()).await?;
        if consumed.kind != KIND_REGISTRATION {
            return Err(WebAuthnServiceError::WrongCeremonyType);
        }
        let user_id = consumed.user_id.ok_or(WebAuthnServiceError::CorruptData)?;
        let name = consumed
            .credential_name
            .ok_or(WebAuthnServiceError::CorruptData)?;
        valid_name(&name).map_err(|_| WebAuthnServiceError::CorruptData)?;
        let state: PasskeyRegistration = serde_json::from_value(consumed.state)
            .map_err(|_| WebAuthnServiceError::CorruptData)?;
        let passkey = self
            .webauthn
            .finish_passkey_registration(response, &state)
            .map_err(|_| WebAuthnServiceError::VerificationFailed)?;
        let passkey_json =
            serde_json::to_value(&passkey).map_err(|_| WebAuthnServiceError::CorruptData)?;
        let parts = passkey_parts(passkey)?;

        let mut connection = self
            .pool
            .acquire()
            .await
            .map_err(|_| WebAuthnServiceError::Unavailable)?;
        let mut tx = connection.begin().await.map_err(|error| map_db(&error))?;
        let result = async {
            if !lock_user(&mut tx, user_id).await? {
                return Err(WebAuthnServiceError::UserNotFound);
            }
            let persisted_at = self.now();
            let retained: i64 =
                sqlx::query_scalar("SELECT count(*) FROM webauthn_credentials WHERE user_id = $1")
                    .bind(user_id.as_uuid())
                    .fetch_one(&mut *tx)
                    .await
                    .map_err(|error| map_db(&error))?;
            if usize::try_from(retained).map_err(|_| WebAuthnServiceError::CorruptData)?
                >= self.max_credentials_per_user
            {
                return Err(WebAuthnServiceError::CredentialLimitReached);
            }
            let row = sqlx::query(
                "INSERT INTO webauthn_credentials \
                 (id, user_id, credential_id, passkey, name, transports, sign_count, \
                  user_verified, backup_eligible, backup_state, created_at, updated_at, \
                  last_used_at, disabled_at) \
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $11, NULL, NULL) \
                 RETURNING id, user_id, name, transports, sign_count, user_verified, \
                           backup_eligible, backup_state, created_at, updated_at, \
                           last_used_at, disabled_at",
            )
            .bind(Uuid::now_v7())
            .bind(user_id.as_uuid())
            .bind(&parts.credential_id)
            .bind(passkey_json)
            .bind(&name)
            .bind(&parts.transports)
            .bind(i64::from(parts.sign_count))
            .bind(parts.user_verified)
            .bind(parts.backup_eligible)
            .bind(parts.backup_state)
            .bind(persisted_at)
            .fetch_one(&mut *tx)
            .await
            .map_err(|error| map_credential_insert(&error))?;
            let metadata = metadata_from_row(&row)?;
            advance_authentication_version(&mut tx, user_id).await?;
            Ok(metadata)
        }
        .await;
        finish(tx, result).await
    }

    /// Finishes account-bound authentication and returns a canonical AAL2 user principal.
    ///
    /// Ceremony state is committed as consumed before validation. The matching credential is then
    /// row-locked, its counter is checked against current durable state, and official metadata
    /// updates are persisted before the principal is returned.
    ///
    /// # Errors
    ///
    /// Returns a stable one-use-state, verification, replay, credential, or persistence error.
    pub async fn finish_authentication(
        &self,
        ceremony_handle: &CeremonyHandle,
        response: &PublicKeyCredential,
    ) -> Result<Principal, WebAuthnServiceError> {
        let started = Instant::now();
        let result = self
            .finish_account_authentication_inner(ceremony_handle, response)
            .await;
        record(
            "finish_authentication",
            label(&result, "authenticated"),
            started.elapsed(),
        );
        result
    }

    async fn finish_account_authentication_inner(
        &self,
        ceremony_handle: &CeremonyHandle,
        response: &PublicKeyCredential,
    ) -> Result<Principal, WebAuthnServiceError> {
        let consumed = consume_ceremony(&self.pool, ceremony_handle, self.clock.as_ref()).await?;
        if consumed.kind != KIND_AUTHENTICATION {
            return Err(WebAuthnServiceError::WrongCeremonyType);
        }
        let user_id = consumed.user_id.ok_or(WebAuthnServiceError::CorruptData)?;
        let state: PasskeyAuthentication = serde_json::from_value(consumed.state)
            .map_err(|_| WebAuthnServiceError::CorruptData)?;
        self.finish_locked_authentication(
            user_id,
            response.get_credential_id(),
            AuthenticationState::AccountBound(state),
            response,
        )
        .await
    }

    /// Finishes conditional discoverable authentication and returns a canonical AAL2 user principal.
    ///
    /// `webauthn-rs` identifies the user handle and credential ID. The service then loads only that
    /// user's matching active credential and supplies it to official discoverable verification.
    ///
    /// # Errors
    ///
    /// Returns a stable one-use-state, verification, replay, credential, or persistence error.
    pub async fn finish_discoverable_authentication(
        &self,
        ceremony_handle: &CeremonyHandle,
        response: &PublicKeyCredential,
    ) -> Result<Principal, WebAuthnServiceError> {
        let started = Instant::now();
        let result = self
            .finish_discoverable_authentication_inner(ceremony_handle, response)
            .await;
        record(
            "finish_discoverable_authentication",
            label(&result, "authenticated"),
            started.elapsed(),
        );
        result
    }

    async fn finish_discoverable_authentication_inner(
        &self,
        ceremony_handle: &CeremonyHandle,
        response: &PublicKeyCredential,
    ) -> Result<Principal, WebAuthnServiceError> {
        let consumed = consume_ceremony(&self.pool, ceremony_handle, self.clock.as_ref()).await?;
        if consumed.kind != KIND_DISCOVERABLE {
            return Err(WebAuthnServiceError::WrongCeremonyType);
        }
        let state: DiscoverableAuthentication = serde_json::from_value(consumed.state)
            .map_err(|_| WebAuthnServiceError::CorruptData)?;
        let (user_uuid, credential_id) = self
            .webauthn
            .identify_discoverable_authentication(response)
            .map_err(|_| WebAuthnServiceError::VerificationFailed)?;
        let user_id = SubjectId::from_uuid(user_uuid)
            .map_err(|_| WebAuthnServiceError::VerificationFailed)?;
        self.finish_locked_authentication(
            user_id,
            credential_id,
            AuthenticationState::Discoverable(state),
            response,
        )
        .await
    }

    async fn finish_locked_authentication(
        &self,
        user_id: SubjectId,
        credential_id: &[u8],
        state: AuthenticationState,
        response: &PublicKeyCredential,
    ) -> Result<Principal, WebAuthnServiceError> {
        valid_credential_id(credential_id).map_err(|_| WebAuthnServiceError::VerificationFailed)?;
        let mut connection = self
            .pool
            .acquire()
            .await
            .map_err(|_| WebAuthnServiceError::Unavailable)?;
        let mut tx = connection.begin().await.map_err(|error| map_db(&error))?;
        let result = async {
            let row = sqlx::query(
                "SELECT id, user_id, credential_id, passkey, name, transports, sign_count, \
                        user_verified, backup_eligible, backup_state, created_at, updated_at, \
                        last_used_at, disabled_at \
                 FROM webauthn_credentials \
                 WHERE user_id = $1 AND credential_id = $2 AND disabled_at IS NULL \
                 FOR UPDATE",
            )
            .bind(user_id.as_uuid())
            .bind(credential_id)
            .fetch_optional(&mut *tx)
            .await
            .map_err(|error| map_db(&error))?
            .ok_or(WebAuthnServiceError::CredentialNotFound)?;
            let current = metadata_from_row(&row)?;
            let passkey_json: Value = row
                .try_get("passkey")
                .map_err(|_| WebAuthnServiceError::CorruptData)?;
            let mut passkey: Passkey = serde_json::from_value(passkey_json)
                .map_err(|_| WebAuthnServiceError::CorruptData)?;
            if passkey.cred_id().as_ref() != credential_id {
                return Err(WebAuthnServiceError::CorruptData);
            }
            let authentication = match state {
                AuthenticationState::AccountBound(state) => self
                    .webauthn
                    .finish_passkey_authentication(response, &state),
                AuthenticationState::Discoverable(state) => {
                    let discoverable = [DiscoverableKey::from(&passkey)];
                    self.webauthn
                        .finish_discoverable_authentication(response, state, &discoverable)
                }
            }
            .map_err(|_| WebAuthnServiceError::VerificationFailed)?;
            if authentication.cred_id().as_ref() != credential_id || !authentication.user_verified()
            {
                return Err(WebAuthnServiceError::VerificationFailed);
            }
            if !counter_is_acceptable(current.sign_count, authentication.counter()) {
                return Err(WebAuthnServiceError::CounterReplay);
            }
            if authentication.backup_state() && !authentication.backup_eligible() {
                return Err(WebAuthnServiceError::VerificationFailed);
            }
            passkey
                .update_credential(&authentication)
                .ok_or(WebAuthnServiceError::CorruptData)?;
            let passkey_json =
                serde_json::to_value(&passkey).map_err(|_| WebAuthnServiceError::CorruptData)?;
            let updated = passkey_parts(passkey)?;
            let authenticated_at = self.now();
            let row = sqlx::query(
                "UPDATE webauthn_credentials \
                 SET passkey = $2, sign_count = $3, user_verified = $4, \
                     backup_eligible = $5, backup_state = $6, updated_at = $7, last_used_at = $7 \
                 WHERE id = $1 \
                 RETURNING id, user_id, name, transports, sign_count, user_verified, \
                           backup_eligible, backup_state, created_at, updated_at, \
                           last_used_at, disabled_at",
            )
            .bind(current.id)
            .bind(passkey_json)
            .bind(i64::from(updated.sign_count))
            .bind(updated.user_verified)
            .bind(updated.backup_eligible)
            .bind(updated.backup_state)
            .bind(authenticated_at)
            .fetch_one(&mut *tx)
            .await
            .map_err(|error| map_db(&error))?;
            metadata_from_row(&row)?;
            Ok(authenticated_at)
        }
        .await;
        let authenticated_at = finish(tx, result).await?;
        Principal::new(
            user_id,
            PrincipalKind::User,
            None,
            AuthMethod::WebAuthn,
            authenticated_at,
            AssuranceLevel::Aal2,
            Vec::new(),
        )
        .map_err(|_| WebAuthnServiceError::CorruptData)
    }

    /// Lists safe lifecycle metadata for every retained credential belonging to a user.
    ///
    /// Raw credential IDs, public keys, and serialized passkeys are deliberately excluded.
    ///
    /// # Errors
    ///
    /// Returns a stable persistence or corrupt-data error.
    pub async fn list_credentials(
        &self,
        user_id: SubjectId,
    ) -> Result<Vec<PasskeyMetadata>, WebAuthnServiceError> {
        let started = Instant::now();
        let result = self.list_credentials_inner(user_id).await;
        record(
            "list_credentials",
            label(&result, "listed"),
            started.elapsed(),
        );
        result
    }

    async fn list_credentials_inner(
        &self,
        user_id: SubjectId,
    ) -> Result<Vec<PasskeyMetadata>, WebAuthnServiceError> {
        let mut connection = self
            .pool
            .acquire()
            .await
            .map_err(|_| WebAuthnServiceError::Unavailable)?;
        let rows = sqlx::query(
            "SELECT id, user_id, name, transports, sign_count, user_verified, \
                    backup_eligible, backup_state, created_at, updated_at, \
                    last_used_at, disabled_at \
             FROM webauthn_credentials WHERE user_id = $1 ORDER BY created_at, id",
        )
        .bind(user_id.as_uuid())
        .fetch_all(&mut *connection)
        .await
        .map_err(|error| map_db(&error))?;
        if rows.len() > self.max_credentials_per_user {
            return Err(WebAuthnServiceError::CorruptData);
        }
        rows.iter().map(metadata_from_row).collect()
    }

    /// Disables one credential after recent authentication by its owning user.
    ///
    /// Disable is durable, immediate, and idempotent. Disabled credentials remain visible in safe
    /// lifecycle listings but are excluded from all subsequent authentication challenges.
    ///
    /// # Errors
    ///
    /// Returns a stable recent-authentication, missing-credential, or persistence error.
    pub async fn disable_credential(
        &self,
        principal: &Principal,
        credential_id: Uuid,
    ) -> Result<PasskeyMetadata, WebAuthnServiceError> {
        let started = Instant::now();
        let result = self
            .disable_credential_inner(principal, credential_id)
            .await;
        record(
            "disable_credential",
            label(&result, "disabled"),
            started.elapsed(),
        );
        result
    }

    async fn disable_credential_inner(
        &self,
        principal: &Principal,
        credential_id: Uuid,
    ) -> Result<PasskeyMetadata, WebAuthnServiceError> {
        if !is_uuid_v7(credential_id) {
            return Err(WebAuthnServiceError::CredentialNotFound);
        }
        let mut connection = self
            .pool
            .acquire()
            .await
            .map_err(|_| WebAuthnServiceError::Unavailable)?;
        let mut tx = connection.begin().await.map_err(|error| map_db(&error))?;
        let result = async {
            let row = sqlx::query(
                "SELECT id, user_id, name, transports, sign_count, user_verified, \
                        backup_eligible, backup_state, created_at, updated_at, \
                        last_used_at, disabled_at \
                 FROM webauthn_credentials WHERE id = $1 AND user_id = $2 FOR UPDATE",
            )
            .bind(credential_id)
            .bind(principal.subject_id.as_uuid())
            .fetch_optional(&mut *tx)
            .await
            .map_err(|error| map_db(&error))?
            .ok_or(WebAuthnServiceError::CredentialNotFound)?;
            let current = metadata_from_row(&row)?;
            let now = self.now();
            self.require_recent_user(principal, now)?;
            if current.disabled_at.is_some() {
                return Ok(current);
            }
            let row = sqlx::query(
                "UPDATE webauthn_credentials SET disabled_at = $2, updated_at = $2 \
                 WHERE id = $1 \
                 RETURNING id, user_id, name, transports, sign_count, user_verified, \
                           backup_eligible, backup_state, created_at, updated_at, \
                           last_used_at, disabled_at",
            )
            .bind(credential_id)
            .bind(now)
            .fetch_one(&mut *tx)
            .await
            .map_err(|error| map_db(&error))?;
            let metadata = metadata_from_row(&row)?;
            advance_authentication_version(&mut tx, principal.subject_id).await?;
            Ok(metadata)
        }
        .await;
        finish(tx, result).await
    }

    fn require_recent_user(
        &self,
        principal: &Principal,
        now: OffsetDateTime,
    ) -> Result<(), WebAuthnServiceError> {
        require_recent_user(principal, now, self.recent_auth_age)
    }

    fn expires_at(&self, now: OffsetDateTime) -> Result<OffsetDateTime, WebAuthnServiceError> {
        now.checked_add(self.ceremony_ttl)
            .ok_or(WebAuthnServiceError::InvalidConfiguration)
    }

    fn now(&self) -> OffsetDateTime {
        self.clock.now_utc().to_offset(UtcOffset::UTC)
    }
}

enum AuthenticationState {
    AccountBound(PasskeyAuthentication),
    Discoverable(DiscoverableAuthentication),
}

struct ConsumedCeremony {
    kind: String,
    user_id: Option<SubjectId>,
    credential_name: Option<String>,
    state: Value,
}

struct PasskeyParts {
    credential_id: Vec<u8>,
    transports: Vec<String>,
    sign_count: u32,
    user_verified: bool,
    backup_eligible: bool,
    backup_state: bool,
}

async fn reserve_ceremony_capacity(
    tx: &mut Transaction<'_, Postgres>,
    user_id: Option<SubjectId>,
    now: OffsetDateTime,
    global_maximum: usize,
    discoverable_maximum: usize,
    per_user_maximum: usize,
) -> Result<(), WebAuthnServiceError> {
    let lock_id = if user_id.is_some() {
        AUTHENTICATED_CEREMONY_CAPACITY_LOCK_ID
    } else {
        DISCOVERABLE_CEREMONY_CAPACITY_LOCK_ID
    };
    sqlx::query("SELECT pg_advisory_xact_lock($1)")
        .bind(lock_id)
        .execute(&mut **tx)
        .await
        .map_err(|error| map_db(&error))?;
    sqlx::query("DELETE FROM webauthn_ceremonies WHERE expires_at <= $1")
        .bind(now)
        .execute(&mut **tx)
        .await
        .map_err(|error| map_db(&error))?;

    let (partition_query, partition_maximum) = if user_id.is_some() {
        (
            "SELECT count(*) FROM webauthn_ceremonies WHERE user_id IS NOT NULL",
            global_maximum - discoverable_maximum,
        )
    } else {
        (
            "SELECT count(*) FROM webauthn_ceremonies WHERE user_id IS NULL",
            discoverable_maximum,
        )
    };
    let partition_count: i64 = sqlx::query_scalar(partition_query)
        .fetch_one(&mut **tx)
        .await
        .map_err(|error| map_db(&error))?;
    if usize::try_from(partition_count).map_err(|_| WebAuthnServiceError::CorruptData)?
        >= partition_maximum
    {
        return Err(WebAuthnServiceError::CeremonyCapacityReached);
    }
    if let Some(user_id) = user_id {
        let user_count: i64 =
            sqlx::query_scalar("SELECT count(*) FROM webauthn_ceremonies WHERE user_id = $1")
                .bind(user_id.as_uuid())
                .fetch_one(&mut **tx)
                .await
                .map_err(|error| map_db(&error))?;
        if usize::try_from(user_count).map_err(|_| WebAuthnServiceError::CorruptData)?
            >= per_user_maximum
        {
            return Err(WebAuthnServiceError::CeremonyCapacityReached);
        }
    }
    Ok(())
}

#[expect(
    clippy::too_many_arguments,
    reason = "one durable ceremony row has an explicit fixed schema"
)]
async fn insert_ceremony(
    tx: &mut Transaction<'_, Postgres>,
    handle: &CeremonyHandle,
    kind: &'static str,
    user_id: Option<SubjectId>,
    credential_name: Option<&str>,
    state: Value,
    created_at: OffsetDateTime,
    expires_at: OffsetDateTime,
) -> Result<(), WebAuthnServiceError> {
    let digest = handle.digest();
    sqlx::query(
        "INSERT INTO webauthn_ceremonies \
         (id, handle_hash, kind, user_id, credential_name, state, created_at, expires_at) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
    )
    .bind(Uuid::now_v7())
    .bind(digest.as_slice())
    .bind(kind)
    .bind(user_id.map(SubjectId::as_uuid))
    .bind(credential_name)
    .bind(state)
    .bind(created_at)
    .bind(expires_at)
    .execute(&mut **tx)
    .await
    .map_err(|error| map_ceremony_insert(&error))?;
    Ok(())
}

async fn consume_ceremony(
    pool: &PostgresPool,
    handle: &CeremonyHandle,
    clock: &dyn Clock,
) -> Result<ConsumedCeremony, WebAuthnServiceError> {
    let digest = handle.digest();
    let mut connection = pool
        .acquire()
        .await
        .map_err(|_| WebAuthnServiceError::Unavailable)?;
    // A single autocommitted DELETE makes replay impossible even when subsequent protocol
    // verification or credential persistence fails.
    let row = sqlx::query(
        "DELETE FROM webauthn_ceremonies WHERE handle_hash = $1 \
         RETURNING kind, user_id, credential_name, state, expires_at",
    )
    .bind(digest.as_slice())
    .fetch_optional(&mut *connection)
    .await
    .map_err(|error| map_db(&error))?
    .ok_or(WebAuthnServiceError::CeremonyNotFound)?;
    let consumed_at = clock.now_utc().to_offset(UtcOffset::UTC);
    let expires_at = utc(row
        .try_get("expires_at")
        .map_err(|_| WebAuthnServiceError::CorruptData)?);
    if expires_at <= consumed_at {
        return Err(WebAuthnServiceError::CeremonyExpired);
    }
    let kind: String = row
        .try_get("kind")
        .map_err(|_| WebAuthnServiceError::CorruptData)?;
    if !matches!(
        kind.as_str(),
        KIND_REGISTRATION | KIND_AUTHENTICATION | KIND_DISCOVERABLE
    ) {
        return Err(WebAuthnServiceError::CorruptData);
    }
    let user_id = row
        .try_get::<Option<Uuid>, _>("user_id")
        .map_err(|_| WebAuthnServiceError::CorruptData)?
        .map(|value| SubjectId::from_uuid(value).map_err(|_| WebAuthnServiceError::CorruptData))
        .transpose()?;
    let credential_name = row
        .try_get("credential_name")
        .map_err(|_| WebAuthnServiceError::CorruptData)?;
    let state = row
        .try_get("state")
        .map_err(|_| WebAuthnServiceError::CorruptData)?;
    Ok(ConsumedCeremony {
        kind,
        user_id,
        credential_name,
        state,
    })
}

async fn advance_authentication_version(
    tx: &mut Transaction<'_, Postgres>,
    user_id: SubjectId,
) -> Result<(), WebAuthnServiceError> {
    let updated = sqlx::query(
        "UPDATE users SET authentication_version = authentication_version + 1 \
         WHERE id = $1 AND authentication_version < 9223372036854775807",
    )
    .bind(user_id.as_uuid())
    .execute(&mut **tx)
    .await
    .map_err(|error| map_db(&error))?;
    if updated.rows_affected() == 1 {
        Ok(())
    } else {
        Err(WebAuthnServiceError::Conflict)
    }
}

async fn lock_user(
    tx: &mut Transaction<'_, Postgres>,
    user_id: SubjectId,
) -> Result<bool, WebAuthnServiceError> {
    sqlx::query("SELECT 1 FROM users WHERE id = $1 FOR UPDATE")
        .bind(user_id.as_uuid())
        .fetch_optional(&mut **tx)
        .await
        .map(|row| row.is_some())
        .map_err(|error| map_db(&error))
}

async fn load_active_passkeys(
    tx: &mut Transaction<'_, Postgres>,
    user_id: SubjectId,
    maximum: usize,
) -> Result<Vec<Passkey>, WebAuthnServiceError> {
    let rows = sqlx::query(
        "SELECT credential_id, passkey FROM webauthn_credentials \
         WHERE user_id = $1 AND disabled_at IS NULL ORDER BY created_at, id FOR KEY SHARE",
    )
    .bind(user_id.as_uuid())
    .fetch_all(&mut **tx)
    .await
    .map_err(|error| map_db(&error))?;
    if rows.len() > maximum {
        return Err(WebAuthnServiceError::CorruptData);
    }
    rows.into_iter()
        .map(|row| {
            let credential_id: Vec<u8> = row
                .try_get("credential_id")
                .map_err(|_| WebAuthnServiceError::CorruptData)?;
            valid_credential_id(&credential_id)?;
            let passkey: Passkey = serde_json::from_value(
                row.try_get("passkey")
                    .map_err(|_| WebAuthnServiceError::CorruptData)?,
            )
            .map_err(|_| WebAuthnServiceError::CorruptData)?;
            if passkey.cred_id().as_ref() != credential_id.as_slice() {
                return Err(WebAuthnServiceError::CorruptData);
            }
            Ok(passkey)
        })
        .collect()
}

fn passkey_parts(passkey: Passkey) -> Result<PasskeyParts, WebAuthnServiceError> {
    let credential: Credential = passkey.into();
    let credential_id = credential.cred_id.as_ref().to_vec();
    valid_credential_id(&credential_id)?;
    let mut transports = credential
        .transports
        .as_ref()
        .map(|values| {
            values
                .iter()
                .map(|transport| transport.as_ref().to_owned())
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    transports.sort_unstable();
    transports.dedup();
    valid_transports(&transports)?;
    if credential.backup_state && !credential.backup_eligible {
        return Err(WebAuthnServiceError::CorruptData);
    }
    Ok(PasskeyParts {
        credential_id,
        transports,
        sign_count: credential.counter,
        user_verified: credential.user_verified,
        backup_eligible: credential.backup_eligible,
        backup_state: credential.backup_state,
    })
}

fn metadata_from_row(row: &sqlx::postgres::PgRow) -> Result<PasskeyMetadata, WebAuthnServiceError> {
    let id: Uuid = row
        .try_get("id")
        .map_err(|_| WebAuthnServiceError::CorruptData)?;
    if !is_uuid_v7(id) {
        return Err(WebAuthnServiceError::CorruptData);
    }
    let user_id = SubjectId::from_uuid(
        row.try_get("user_id")
            .map_err(|_| WebAuthnServiceError::CorruptData)?,
    )
    .map_err(|_| WebAuthnServiceError::CorruptData)?;
    let name: String = row
        .try_get("name")
        .map_err(|_| WebAuthnServiceError::CorruptData)?;
    valid_name(&name).map_err(|_| WebAuthnServiceError::CorruptData)?;
    let transports: Vec<String> = row
        .try_get("transports")
        .map_err(|_| WebAuthnServiceError::CorruptData)?;
    valid_transports(&transports)?;
    let raw_sign_count: i64 = row
        .try_get("sign_count")
        .map_err(|_| WebAuthnServiceError::CorruptData)?;
    let sign_count =
        u32::try_from(raw_sign_count).map_err(|_| WebAuthnServiceError::CorruptData)?;
    let user_verified: bool = row
        .try_get("user_verified")
        .map_err(|_| WebAuthnServiceError::CorruptData)?;
    let backup_eligible: bool = row
        .try_get("backup_eligible")
        .map_err(|_| WebAuthnServiceError::CorruptData)?;
    let backup_state: bool = row
        .try_get("backup_state")
        .map_err(|_| WebAuthnServiceError::CorruptData)?;
    if backup_state && !backup_eligible {
        return Err(WebAuthnServiceError::CorruptData);
    }
    let created_at = utc(row
        .try_get("created_at")
        .map_err(|_| WebAuthnServiceError::CorruptData)?);
    let updated_at = utc(row
        .try_get("updated_at")
        .map_err(|_| WebAuthnServiceError::CorruptData)?);
    let last_used_at = row
        .try_get::<Option<OffsetDateTime>, _>("last_used_at")
        .map_err(|_| WebAuthnServiceError::CorruptData)?
        .map(utc);
    let disabled_at = row
        .try_get::<Option<OffsetDateTime>, _>("disabled_at")
        .map_err(|_| WebAuthnServiceError::CorruptData)?
        .map(utc);
    if updated_at < created_at
        || last_used_at.is_some_and(|value| value < created_at)
        || disabled_at.is_some_and(|value| value < created_at)
        || matches!((last_used_at, disabled_at), (Some(last), Some(disabled)) if last > disabled)
    {
        return Err(WebAuthnServiceError::CorruptData);
    }
    Ok(PasskeyMetadata {
        id,
        user_id,
        name,
        transports,
        sign_count,
        user_verified,
        backup_eligible,
        backup_state,
        created_at,
        updated_at,
        last_used_at,
        disabled_at,
    })
}

fn require_recent_user(
    principal: &Principal,
    now: OffsetDateTime,
    maximum_age: TimeDuration,
) -> Result<(), WebAuthnServiceError> {
    let authenticated_at = principal.authenticated_at.to_offset(UtcOffset::UTC);
    if principal.kind != PrincipalKind::User
        || authenticated_at > now
        || now - authenticated_at > maximum_age
    {
        Err(WebAuthnServiceError::RecentAuthenticationRequired)
    } else {
        Ok(())
    }
}

const fn counter_is_acceptable(stored: u32, presented: u32) -> bool {
    stored == 0 || presented > stored
}

fn valid_name(value: &str) -> Result<(), WebAuthnServiceError> {
    if value.is_empty()
        || value.len() > MAX_NAME_BYTES
        || value.trim() != value
        || value.chars().any(char::is_control)
    {
        Err(WebAuthnServiceError::InvalidName)
    } else {
        Ok(())
    }
}

fn valid_credential_id(value: &[u8]) -> Result<(), WebAuthnServiceError> {
    if value.is_empty() || value.len() > MAX_CREDENTIAL_ID_BYTES {
        Err(WebAuthnServiceError::CorruptData)
    } else {
        Ok(())
    }
}

fn valid_transports(values: &[String]) -> Result<(), WebAuthnServiceError> {
    const ALLOWED: [&str; MAX_TRANSPORTS] =
        ["ble", "hybrid", "internal", "nfc", "test", "unknown", "usb"];
    if values.len() > MAX_TRANSPORTS
        || values
            .iter()
            .any(|value| ALLOWED.binary_search(&value.as_str()).is_err())
        || values.windows(2).any(|pair| pair[0] >= pair[1])
    {
        Err(WebAuthnServiceError::CorruptData)
    } else {
        Ok(())
    }
}

fn is_uuid_v7(value: Uuid) -> bool {
    value.get_version() == Some(Version::SortRand) && value.get_variant() == Variant::RFC4122
}

fn utc(value: OffsetDateTime) -> OffsetDateTime {
    value.to_offset(UtcOffset::UTC)
}

async fn finish<T>(
    tx: Transaction<'_, Postgres>,
    result: Result<T, WebAuthnServiceError>,
) -> Result<T, WebAuthnServiceError> {
    match result {
        Ok(value) => {
            tx.commit().await.map_err(|error| map_db(&error))?;
            Ok(value)
        }
        Err(operation) => {
            tx.rollback().await.map_err(|error| map_db(&error))?;
            Err(operation)
        }
    }
}

fn map_ceremony_insert(error: &sqlx::Error) -> WebAuthnServiceError {
    if error
        .as_database_error()
        .and_then(sqlx::error::DatabaseError::constraint)
        == Some("webauthn_ceremonies_handle_hash_key")
    {
        WebAuthnServiceError::CeremonyHandleCollision
    } else {
        map_db(error)
    }
}

fn map_credential_insert(error: &sqlx::Error) -> WebAuthnServiceError {
    if error
        .as_database_error()
        .and_then(sqlx::error::DatabaseError::constraint)
        == Some("webauthn_credentials_credential_id_key")
    {
        WebAuthnServiceError::Conflict
    } else {
        map_db(error)
    }
}

fn map_db(error: &sqlx::Error) -> WebAuthnServiceError {
    if let Some(state) = RetryableSqlState::from_sqlx(error) {
        return WebAuthnServiceError::Transient(state);
    }
    match error
        .as_database_error()
        .and_then(sqlx::error::DatabaseError::code)
    {
        Some(code) if matches!(code.as_ref(), "23502" | "23503" | "23505" | "23514") => {
            WebAuthnServiceError::Conflict
        }
        _ => WebAuthnServiceError::Unavailable,
    }
}

fn label<T>(result: &Result<T, WebAuthnServiceError>, success: &'static str) -> &'static str {
    match result {
        Ok(_) => success,
        Err(error) => (*error).metric_label(),
    }
}

fn record(operation: &'static str, result: &'static str, elapsed: Duration) {
    metrics::counter!(
        "rsk_auth_webauthn_operations_total",
        "operation" => operation,
        "result" => result
    )
    .increment(1);
    metrics::histogram!(
        "rsk_auth_webauthn_operation_duration_seconds",
        "operation" => operation
    )
    .record(elapsed.as_secs_f64());
}

#[cfg(test)]
mod tests {
    use super::*;

    const USER_UUID: Uuid = Uuid::from_u128(0x0189_0f2a_0000_7000_8000_0000_0000_0001);

    fn principal(
        kind: PrincipalKind,
        authenticated_at: OffsetDateTime,
    ) -> Result<Principal, Box<dyn std::error::Error>> {
        Ok(Principal::new(
            SubjectId::from_uuid(USER_UUID)?,
            kind,
            None,
            AuthMethod::Password,
            authenticated_at,
            AssuranceLevel::Aal1,
            Vec::new(),
        )?)
    }

    #[test]
    fn recent_authentication_has_deterministic_inclusive_boundary()
    -> Result<(), Box<dyn std::error::Error>> {
        let now = OffsetDateTime::from_unix_timestamp(1_700_000_000)?;
        let maximum_age = TimeDuration::minutes(15);
        assert_eq!(
            require_recent_user(
                &principal(PrincipalKind::User, now - maximum_age)?,
                now,
                maximum_age,
            ),
            Ok(())
        );
        assert_eq!(
            require_recent_user(
                &principal(
                    PrincipalKind::User,
                    now - maximum_age - TimeDuration::SECOND
                )?,
                now,
                maximum_age,
            ),
            Err(WebAuthnServiceError::RecentAuthenticationRequired)
        );
        assert_eq!(
            require_recent_user(
                &principal(PrincipalKind::ServiceAccount, now)?,
                now,
                maximum_age,
            ),
            Err(WebAuthnServiceError::RecentAuthenticationRequired)
        );
        assert_eq!(
            require_recent_user(
                &principal(PrincipalKind::User, now + TimeDuration::SECOND)?,
                now,
                maximum_age,
            ),
            Err(WebAuthnServiceError::RecentAuthenticationRequired)
        );
        Ok(())
    }

    #[test]
    fn counter_rule_allows_unsupported_zero_and_requires_advancement_after_activation() {
        assert!(counter_is_acceptable(0, 0));
        assert!(counter_is_acceptable(0, 1));
        assert!(counter_is_acceptable(7, 8));
        assert!(!counter_is_acceptable(7, 7));
        assert!(!counter_is_acceptable(7, 0));
    }
}

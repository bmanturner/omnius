//! PostgreSQL service-account and API-key lifecycle persistence.

use std::{
    fmt,
    time::{Duration, Instant},
};

use omnius_auth_core::{
    AssuranceLevel, AuthMethod, Principal, PrincipalKind, Scope, SubjectId, TenantId,
};
use omnius_config::SecretString;
use omnius_postgres::{PostgresPool, RetryableSqlState, RetryableTransactionError};
use sqlx::{Connection as _, PgConnection, Postgres, Row as _, Transaction};
use thiserror::Error;
use time::{Duration as TimeDuration, OffsetDateTime, UtcOffset};
use uuid::{Uuid, Variant, Version};

use crate::{
    config::ApiKeyConfig,
    token::{ApiKeyCredential, ApiKeyGenerator, IssuedApiKey, OsApiKeyGenerator},
};

const MAX_NAME_BYTES: usize = 255;
const MAX_SCOPES: usize = 128;
const DIGEST_BYTES: usize = 32;

/// Safe service-account lifecycle metadata.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ServiceAccountMetadata {
    /// Canonical service-account subject.
    pub id: SubjectId,
    /// Operator-facing name.
    pub name: String,
    /// Permanently bound tenant context, when present.
    pub tenant_id: Option<TenantId>,
    /// Human user that created the account.
    pub created_by_user_id: SubjectId,
    /// Creation time.
    pub created_at: OffsetDateTime,
    /// Disable time, when disabled.
    pub disabled_at: Option<OffsetDateTime>,
}

/// Safe API-key lifecycle metadata; it deliberately excludes the secret and digest.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ApiKeyMetadata {
    /// Key row identifier.
    pub id: Uuid,
    /// Service account authenticated by the key.
    pub service_account_id: SubjectId,
    /// Non-secret lookup prefix.
    pub key_prefix: String,
    /// Operator-facing name.
    pub name: String,
    /// Sorted, duplicate-free scopes.
    pub scopes: Vec<Scope>,
    /// Optional absolute expiry.
    pub expires_at: Option<OffsetDateTime>,
    /// Creation time.
    pub created_at: OffsetDateTime,
    /// Last bounded successful-use write.
    pub last_used_at: Option<OffsetDateTime>,
    /// Revocation time, when revoked.
    pub revoked_at: Option<OffsetDateTime>,
    /// Previous key in an overlapping rotation.
    pub rotated_from_id: Option<Uuid>,
}

/// A committed key and its credential for one explicit delivery.
pub struct CreatedApiKey {
    metadata: ApiKeyMetadata,
    credential: ApiKeyCredential,
}

impl CreatedApiKey {
    /// Borrows safe lifecycle metadata.
    #[must_use]
    pub const fn metadata(&self) -> &ApiKeyMetadata {
        &self.metadata
    }

    /// Consumes this value and exposes the plaintext credential once.
    #[must_use]
    pub fn expose_once(self) -> SecretString {
        self.credential.expose_once()
    }
}

impl fmt::Debug for CreatedApiKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CreatedApiKey")
            .field("metadata", &self.metadata)
            .field("credential", &"[REDACTED]")
            .finish()
    }
}

/// PostgreSQL-backed API-key lifecycle store.
#[derive(Clone)]
pub struct ApiKeyStore<G = OsApiKeyGenerator> {
    pool: PostgresPool,
    pepper: SecretString,
    generator: G,
    max_scopes: usize,
    max_key_lifetime: Duration,
    last_used_write_interval: Duration,
}

impl<G> fmt::Debug for ApiKeyStore<G> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ApiKeyStore")
            .field("pepper", &"[REDACTED]")
            .field("max_scopes", &self.max_scopes)
            .field("max_key_lifetime", &self.max_key_lifetime)
            .field("last_used_write_interval", &self.last_used_write_interval)
            .finish_non_exhaustive()
    }
}

impl ApiKeyStore<OsApiKeyGenerator> {
    /// Creates an enabled store using operating-system cryptographic randomness.
    ///
    /// # Errors
    /// Returns a stable error when the configuration is disabled or invalid.
    pub fn new(pool: PostgresPool, config: &ApiKeyConfig) -> Result<Self, ApiKeyStoreError> {
        Self::with_generator(pool, config, OsApiKeyGenerator)
    }
}

impl<G: ApiKeyGenerator> ApiKeyStore<G> {
    /// Creates an enabled store with an injectable credential generator.
    ///
    /// # Errors
    /// Returns a stable error when the configuration is disabled or invalid.
    pub fn with_generator(
        pool: PostgresPool,
        config: &ApiKeyConfig,
        generator: G,
    ) -> Result<Self, ApiKeyStoreError> {
        config
            .validate()
            .map_err(|_| ApiKeyStoreError::InvalidConfiguration)?;
        if !config.enabled {
            return Err(ApiKeyStoreError::Disabled);
        }
        Ok(Self {
            pool,
            pepper: config.pepper.clone(),
            generator,
            max_scopes: config.max_scopes,
            max_key_lifetime: config.max_key_lifetime,
            last_used_write_interval: config.last_used_write_interval,
        })
    }

    /// Creates a tenant-bound or tenantless service account owned by an existing user.
    ///
    /// # Errors
    /// Returns a stable validation, missing-owner, conflict, or persistence error.
    pub async fn create_service_account(
        &self,
        name: &str,
        tenant_id: Option<TenantId>,
        created_by_user_id: SubjectId,
    ) -> Result<ServiceAccountMetadata, ApiKeyStoreError> {
        let started = Instant::now();
        let result = self
            .create_account_inner(name, tenant_id, created_by_user_id)
            .await;
        record(
            "create_service_account",
            label(&result, "created"),
            started.elapsed(),
        );
        result
    }

    /// Disables an account and all of its keys immediately and idempotently.
    ///
    /// # Errors
    /// Returns a stable missing-account or persistence error.
    pub async fn disable_service_account(
        &self,
        id: SubjectId,
    ) -> Result<ServiceAccountMetadata, ApiKeyStoreError> {
        let started = Instant::now();
        let result = self.disable_inner(id).await;
        record(
            "disable_service_account",
            label(&result, "disabled"),
            started.elapsed(),
        );
        result
    }

    /// Issues and durably persists a key before making its credential available.
    ///
    /// # Errors
    /// Returns a stable input, lifecycle, collision, generation, or persistence error.
    pub async fn issue(
        &self,
        account_id: SubjectId,
        name: &str,
        scopes: &[Scope],
        expires_at: Option<OffsetDateTime>,
    ) -> Result<CreatedApiKey, ApiKeyStoreError> {
        let started = Instant::now();
        let result = self.issue_inner(account_id, name, scopes, expires_at).await;
        record("issue", label(&result, "issued"), started.elapsed());
        result
    }

    /// Creates an overlapping replacement while leaving the old key usable.
    ///
    /// # Errors
    /// Returns a stable input, lifecycle, collision, generation, or persistence error.
    pub async fn rotate(
        &self,
        key_id: Uuid,
        expires_at: Option<OffsetDateTime>,
    ) -> Result<CreatedApiKey, ApiKeyStoreError> {
        let started = Instant::now();
        let result = self.rotate_inner(key_id, expires_at).await;
        record("rotate", label(&result, "rotated"), started.elapsed());
        result
    }

    /// Revokes a key immediately and idempotently.
    ///
    /// # Errors
    /// Returns a stable missing-key, identifier, or persistence error.
    pub async fn revoke(&self, key_id: Uuid) -> Result<ApiKeyMetadata, ApiKeyStoreError> {
        let started = Instant::now();
        let result = self.revoke_inner(key_id).await;
        record("revoke", label(&result, "revoked"), started.elapsed());
        result
    }

    /// Authenticates by prefix and constant-time digest verification.
    ///
    /// Missing, mismatched, expired, revoked, and disabled credentials share one error.
    ///
    /// # Errors
    /// Returns a stable authentication, corrupt-data, configuration, or persistence error.
    pub async fn authenticate(
        &self,
        credential: &ApiKeyCredential,
    ) -> Result<Principal, ApiKeyStoreError> {
        let started = Instant::now();
        let result = self.authenticate_inner(credential).await;
        record(
            "authenticate",
            label(&result, "authenticated"),
            started.elapsed(),
        );
        result
    }

    /// Reads safe account lifecycle metadata.
    ///
    /// # Errors
    /// Returns a stable corrupt-data or persistence error.
    pub async fn service_account_metadata(
        &self,
        id: SubjectId,
    ) -> Result<Option<ServiceAccountMetadata>, ApiKeyStoreError> {
        let started = Instant::now();
        let result = self.account_metadata_inner(id).await;
        record(
            "read_service_account",
            option_label(&result),
            started.elapsed(),
        );
        result
    }

    /// Reads safe key lifecycle metadata without selecting its digest.
    ///
    /// # Errors
    /// Returns a stable identifier, corrupt-data, or persistence error.
    pub async fn api_key_metadata(
        &self,
        id: Uuid,
    ) -> Result<Option<ApiKeyMetadata>, ApiKeyStoreError> {
        let started = Instant::now();
        let result = self.key_metadata_inner(id).await;
        record("read_api_key", option_label(&result), started.elapsed());
        result
    }

    async fn create_account_inner(
        &self,
        name: &str,
        tenant_id: Option<TenantId>,
        owner: SubjectId,
    ) -> Result<ServiceAccountMetadata, ApiKeyStoreError> {
        valid_name(name)?;
        let mut connection = self
            .pool
            .acquire()
            .await
            .map_err(|_| ApiKeyStoreError::Unavailable)?;
        let mut tx = connection.begin().await.map_err(|error| map_db(&error))?;
        let result = async {
            if sqlx::query("SELECT 1 FROM users WHERE id = $1 FOR KEY SHARE")
                .bind(owner.as_uuid()).fetch_optional(&mut *tx).await.map_err(|error| map_db(&error))?.is_none()
            { return Err(ApiKeyStoreError::CreatorNotFound); }
            if let Some(tenant_id) = tenant_id
                && sqlx::query(
                    "SELECT 1 FROM organizations o \
                     JOIN memberships m ON m.organization_id = o.id \
                     WHERE o.id = $1 AND m.organization_id = $1 AND m.user_id = $2 \
                       AND o.status = 'active' AND m.status = 'active' \
                     FOR KEY SHARE OF o, m",
                )
                .bind(tenant_id.as_uuid())
                .bind(owner.as_uuid())
                .fetch_optional(&mut *tx)
                .await
                .map_err(|error| map_db(&error))?
                .is_none()
            {
                return Err(ApiKeyStoreError::TenantUnavailable);
            }
            let row = sqlx::query(
                "INSERT INTO service_accounts (id, name, tenant_id, created_by_user_id, created_at, disabled_at) \
                 VALUES ($1, $2, $3, $4, $5, NULL) \
                 RETURNING id, name, tenant_id, created_by_user_id, created_at, disabled_at")
                .bind(SubjectId::new().as_uuid()).bind(name).bind(tenant_id.map(TenantId::as_uuid))
                .bind(owner.as_uuid()).bind(OffsetDateTime::now_utc())
                .fetch_one(&mut *tx).await.map_err(|error| map_db(&error))?;
            account_from_row(&row)
        }.await;
        finish(tx, result).await
    }

    async fn disable_inner(
        &self,
        id: SubjectId,
    ) -> Result<ServiceAccountMetadata, ApiKeyStoreError> {
        let mut connection = self
            .pool
            .acquire()
            .await
            .map_err(|_| ApiKeyStoreError::Unavailable)?;
        let mut tx = connection.begin().await.map_err(|error| map_db(&error))?;
        let result = async {
            let account = lock_account(&mut tx, id)
                .await?
                .ok_or(ApiKeyStoreError::ServiceAccountNotFound)?;
            if account.disabled_at.is_some() {
                return Ok(account);
            }
            let row = sqlx::query(
                "UPDATE service_accounts SET disabled_at = $2 WHERE id = $1 \
                 RETURNING id, name, tenant_id, created_by_user_id, created_at, disabled_at",
            )
            .bind(id.as_uuid())
            .bind(OffsetDateTime::now_utc())
            .fetch_one(&mut *tx)
            .await
            .map_err(|error| map_db(&error))?;
            account_from_row(&row)
        }
        .await;
        finish(tx, result).await
    }

    async fn issue_inner(
        &self,
        account_id: SubjectId,
        name: &str,
        scopes: &[Scope],
        expires_at: Option<OffsetDateTime>,
    ) -> Result<CreatedApiKey, ApiKeyStoreError> {
        valid_name(name)?;
        let scopes = normalized_scopes(scopes, self.max_scopes)?;
        let issued = self
            .generator
            .generate(&self.pepper)
            .map_err(|_| ApiKeyStoreError::CredentialGeneration)?;
        let metadata = self
            .persist_key(account_id, name, &scopes, expires_at, &issued)
            .await?;
        Ok(CreatedApiKey {
            metadata,
            credential: issued.credential,
        })
    }

    async fn persist_key(
        &self,
        account_id: SubjectId,
        name: &str,
        scopes: &[Scope],
        expires_at: Option<OffsetDateTime>,
        issued: &IssuedApiKey,
    ) -> Result<ApiKeyMetadata, ApiKeyStoreError> {
        let mut connection = self
            .pool
            .acquire()
            .await
            .map_err(|_| ApiKeyStoreError::Unavailable)?;
        let mut tx = connection.begin().await.map_err(|error| map_db(&error))?;
        let values = scope_values(scopes);
        let result = async {
            let account = lock_account(&mut tx, account_id)
                .await?
                .ok_or(ApiKeyStoreError::ServiceAccountNotFound)?;
            if account.disabled_at.is_some() {
                return Err(ApiKeyStoreError::ServiceAccountDisabled);
            }
            if !tenant_is_active(&mut tx, account.tenant_id).await? {
                return Err(ApiKeyStoreError::TenantUnavailable);
            }
            let created_at = OffsetDateTime::now_utc();
            let expires_at = valid_expiry(expires_at, created_at, self.max_key_lifetime)?;
            let row = insert_key(
                &mut tx,
                Uuid::now_v7(),
                account_id,
                issued.credential.prefix(),
                issued.digest.as_bytes(),
                name,
                &values,
                expires_at,
                created_at,
                None,
            )
            .await?;
            key_from_row(&row)
        }
        .await;
        finish(tx, result).await
    }

    async fn rotate_inner(
        &self,
        key_id: Uuid,
        expires_at: Option<OffsetDateTime>,
    ) -> Result<CreatedApiKey, ApiKeyStoreError> {
        valid_uuid(key_id)?;
        let issued = self
            .generator
            .generate(&self.pepper)
            .map_err(|_| ApiKeyStoreError::CredentialGeneration)?;
        let mut connection = self
            .pool
            .acquire()
            .await
            .map_err(|_| ApiKeyStoreError::Unavailable)?;
        let mut tx = connection.begin().await.map_err(|error| map_db(&error))?;
        let result = async {
            let locator = sqlx::query("SELECT service_account_id FROM api_keys WHERE id = $1")
                .bind(key_id)
                .fetch_optional(&mut *tx)
                .await
                .map_err(|error| map_db(&error))?
                .ok_or(ApiKeyStoreError::ApiKeyNotFound)?;
            let account_id = subject(
                locator
                    .try_get("service_account_id")
                    .map_err(|_| ApiKeyStoreError::CorruptData)?,
            )?;
            let account = lock_account(&mut tx, account_id)
                .await?
                .ok_or(ApiKeyStoreError::CorruptData)?;
            if account.disabled_at.is_some() {
                return Err(ApiKeyStoreError::ServiceAccountDisabled);
            }
            if !tenant_is_active(&mut tx, account.tenant_id).await? {
                return Err(ApiKeyStoreError::TenantUnavailable);
            }
            let old = lock_key(&mut tx, key_id, account_id)
                .await?
                .ok_or(ApiKeyStoreError::ApiKeyNotFound)?;
            let old = key_from_row(&old)?;
            let created_at = OffsetDateTime::now_utc();
            let expires_at = valid_expiry(expires_at, created_at, self.max_key_lifetime)?;
            if old.revoked_at.is_some() || old.expires_at.is_some_and(|value| value <= created_at) {
                return Err(ApiKeyStoreError::ApiKeyInactive);
            }
            let scopes = scope_values(&old.scopes);
            let row = insert_key(
                &mut tx,
                Uuid::now_v7(),
                account_id,
                issued.credential.prefix(),
                issued.digest.as_bytes(),
                &old.name,
                &scopes,
                expires_at,
                created_at,
                Some(old.id),
            )
            .await?;
            key_from_row(&row)
        }
        .await;
        let metadata = finish(tx, result).await?;
        Ok(CreatedApiKey {
            metadata,
            credential: issued.credential,
        })
    }

    async fn revoke_inner(&self, key_id: Uuid) -> Result<ApiKeyMetadata, ApiKeyStoreError> {
        valid_uuid(key_id)?;
        let mut connection = self
            .pool
            .acquire()
            .await
            .map_err(|_| ApiKeyStoreError::Unavailable)?;
        let mut tx = connection.begin().await.map_err(|error| map_db(&error))?;
        let result = async {
            let locator = sqlx::query("SELECT service_account_id FROM api_keys WHERE id = $1")
                .bind(key_id).fetch_optional(&mut *tx).await.map_err(|error| map_db(&error))?
                .ok_or(ApiKeyStoreError::ApiKeyNotFound)?;
            let account_id = subject(locator.try_get("service_account_id").map_err(|_| ApiKeyStoreError::CorruptData)?)?;
            lock_account(&mut tx, account_id).await?.ok_or(ApiKeyStoreError::CorruptData)?;
            let row = lock_key(&mut tx, key_id, account_id).await?.ok_or(ApiKeyStoreError::ApiKeyNotFound)?;
            let metadata = key_from_row(&row)?;
            if metadata.revoked_at.is_some() { return Ok(metadata); }
            let row = sqlx::query(
                "UPDATE api_keys SET revoked_at = $2 WHERE id = $1 \
                 RETURNING id, service_account_id, key_prefix, name, scopes, expires_at, created_at, last_used_at, revoked_at, rotated_from_id")
                .bind(key_id).bind(OffsetDateTime::now_utc()).fetch_one(&mut *tx).await.map_err(|error| map_db(&error))?;
            key_from_row(&row)
        }.await;
        finish(tx, result).await
    }

    async fn authenticate_inner(
        &self,
        credential: &ApiKeyCredential,
    ) -> Result<Principal, ApiKeyStoreError> {
        let mut connection = self
            .pool
            .acquire()
            .await
            .map_err(|_| ApiKeyStoreError::Unavailable)?;
        let locator = sqlx::query(
            "SELECT id, service_account_id, secret_hash FROM api_keys WHERE key_prefix = $1",
        )
        .bind(credential.prefix())
        .fetch_optional(&mut *connection)
        .await
        .map_err(|error| map_db(&error))?
        .ok_or(ApiKeyStoreError::AuthenticationFailed)?;
        let key_id: Uuid = locator
            .try_get("id")
            .map_err(|_| ApiKeyStoreError::CorruptData)?;
        valid_uuid(key_id).map_err(|_| ApiKeyStoreError::CorruptData)?;
        let account_id = subject(
            locator
                .try_get("service_account_id")
                .map_err(|_| ApiKeyStoreError::CorruptData)?,
        )?;
        let digest: Vec<u8> = locator
            .try_get("secret_hash")
            .map_err(|_| ApiKeyStoreError::CorruptData)?;
        if digest.len() != DIGEST_BYTES {
            return Err(ApiKeyStoreError::CorruptData);
        }
        if !credential
            .matches_digest(&self.pepper, &digest)
            .map_err(|_| ApiKeyStoreError::InvalidConfiguration)?
        {
            return Err(ApiKeyStoreError::AuthenticationFailed);
        }

        let mut tx = connection.begin().await.map_err(|error| map_db(&error))?;
        let result = async {
            let account = share_account(&mut tx, account_id)
                .await?
                .ok_or(ApiKeyStoreError::CorruptData)?;
            if !tenant_is_active(&mut tx, account.tenant_id).await? {
                return Err(ApiKeyStoreError::AuthenticationFailed);
            }
            let row = share_key_with_digest(&mut tx, key_id, account_id, credential.prefix())
                .await?
                .ok_or(ApiKeyStoreError::AuthenticationFailed)?;
            let locked_digest: Vec<u8> = row
                .try_get("secret_hash")
                .map_err(|_| ApiKeyStoreError::CorruptData)?;
            if locked_digest.len() != DIGEST_BYTES {
                return Err(ApiKeyStoreError::CorruptData);
            }
            if !credential
                .matches_digest(&self.pepper, &locked_digest)
                .map_err(|_| ApiKeyStoreError::InvalidConfiguration)?
            {
                return Err(ApiKeyStoreError::AuthenticationFailed);
            }
            let key = key_from_row(&row)?;
            let now = OffsetDateTime::now_utc();
            if account.disabled_at.is_some()
                || key.revoked_at.is_some()
                || key.expires_at.is_some_and(|value| value <= now)
            {
                return Err(ApiKeyStoreError::AuthenticationFailed);
            }
            if key.created_at > now {
                return Err(ApiKeyStoreError::CorruptData);
            }
            let threshold = last_used_threshold(now, self.last_used_write_interval)?;
            let principal = Principal::new(
                account.id,
                PrincipalKind::ServiceAccount,
                account.tenant_id,
                AuthMethod::ApiKey,
                now,
                AssuranceLevel::Aal1,
                key.scopes,
            )
            .map_err(|_| ApiKeyStoreError::CorruptData)?;
            Ok((principal, key.id, account.id, now, threshold))
        }
        .await;
        let (principal, key_id, account_id, authenticated_at, threshold) =
            finish(tx, result).await?;

        record_last_used(
            &mut connection,
            key_id,
            account_id,
            authenticated_at,
            threshold,
        )
        .await;
        Ok(principal)
    }

    async fn account_metadata_inner(
        &self,
        id: SubjectId,
    ) -> Result<Option<ServiceAccountMetadata>, ApiKeyStoreError> {
        let mut connection = self
            .pool
            .acquire()
            .await
            .map_err(|_| ApiKeyStoreError::Unavailable)?;
        let row = sqlx::query("SELECT id, name, tenant_id, created_by_user_id, created_at, disabled_at FROM service_accounts WHERE id = $1")
            .bind(id.as_uuid()).fetch_optional(&mut *connection).await.map_err(|error| map_db(&error))?;
        row.as_ref().map(account_from_row).transpose()
    }

    async fn key_metadata_inner(
        &self,
        id: Uuid,
    ) -> Result<Option<ApiKeyMetadata>, ApiKeyStoreError> {
        valid_uuid(id)?;
        let mut connection = self
            .pool
            .acquire()
            .await
            .map_err(|_| ApiKeyStoreError::Unavailable)?;
        let row = sqlx::query(
            "SELECT id, service_account_id, key_prefix, name, scopes, expires_at, created_at, last_used_at, revoked_at, rotated_from_id FROM api_keys WHERE id = $1")
            .bind(id).fetch_optional(&mut *connection).await.map_err(|error| map_db(&error))?;
        row.as_ref().map(key_from_row).transpose()
    }
}

async fn record_last_used(
    connection: &mut PgConnection,
    key_id: Uuid,
    account_id: SubjectId,
    authenticated_at: OffsetDateTime,
    threshold: OffsetDateTime,
) {
    let started = Instant::now();
    let update = sqlx::query(
        "UPDATE api_keys SET last_used_at = $2 \
         WHERE id = $1 AND service_account_id = $4 AND revoked_at IS NULL \
           AND (expires_at IS NULL OR expires_at > $2) \
           AND (last_used_at IS NULL OR last_used_at <= $3) \
           AND EXISTS (SELECT 1 FROM service_accounts \
                       WHERE id = $4 AND disabled_at IS NULL)",
    )
    .bind(key_id)
    .bind(authenticated_at)
    .bind(threshold)
    .bind(account_id.as_uuid())
    .execute(connection)
    .await;
    let outcome = match update {
        Ok(result) if result.rows_affected() == 1 => "recorded",
        Ok(_) => "skipped",
        Err(ref error) => map_db(error).metric_label(),
    };
    record("record_last_used", outcome, started.elapsed());
}

async fn lock_account(
    tx: &mut Transaction<'_, Postgres>,
    id: SubjectId,
) -> Result<Option<ServiceAccountMetadata>, ApiKeyStoreError> {
    let row = sqlx::query("SELECT id, name, tenant_id, created_by_user_id, created_at, disabled_at FROM service_accounts WHERE id = $1 FOR UPDATE")
        .bind(id.as_uuid()).fetch_optional(&mut **tx).await.map_err(|error| map_db(&error))?;
    row.as_ref().map(account_from_row).transpose()
}

async fn share_account(
    tx: &mut Transaction<'_, Postgres>,
    id: SubjectId,
) -> Result<Option<ServiceAccountMetadata>, ApiKeyStoreError> {
    let row = sqlx::query(
        "SELECT id, name, tenant_id, created_by_user_id, created_at, disabled_at \
         FROM service_accounts WHERE id = $1 FOR SHARE",
    )
    .bind(id.as_uuid())
    .fetch_optional(&mut **tx)
    .await
    .map_err(|error| map_db(&error))?;
    row.as_ref().map(account_from_row).transpose()
}

async fn tenant_is_active(
    tx: &mut Transaction<'_, Postgres>,
    tenant_id: Option<TenantId>,
) -> Result<bool, ApiKeyStoreError> {
    let Some(tenant_id) = tenant_id else {
        return Ok(true);
    };
    sqlx::query("SELECT 1 FROM organizations WHERE id = $1 AND status = 'active' FOR SHARE")
        .bind(tenant_id.as_uuid())
        .fetch_optional(&mut **tx)
        .await
        .map(|row| row.is_some())
        .map_err(|error| map_db(&error))
}
async fn lock_key(
    tx: &mut Transaction<'_, Postgres>,
    id: Uuid,
    account: SubjectId,
) -> Result<Option<sqlx::postgres::PgRow>, ApiKeyStoreError> {
    sqlx::query("SELECT id, service_account_id, key_prefix, name, scopes, expires_at, created_at, last_used_at, revoked_at, rotated_from_id FROM api_keys WHERE id = $1 AND service_account_id = $2 FOR UPDATE")
        .bind(id).bind(account.as_uuid()).fetch_optional(&mut **tx).await.map_err(|error| map_db(&error))
}

async fn share_key_with_digest(
    tx: &mut Transaction<'_, Postgres>,
    id: Uuid,
    account: SubjectId,
    prefix: &str,
) -> Result<Option<sqlx::postgres::PgRow>, ApiKeyStoreError> {
    sqlx::query("SELECT id, service_account_id, key_prefix, secret_hash, name, scopes, expires_at, created_at, last_used_at, revoked_at, rotated_from_id FROM api_keys WHERE id = $1 AND service_account_id = $2 AND key_prefix = $3 FOR SHARE")
        .bind(id).bind(account.as_uuid()).bind(prefix).fetch_optional(&mut **tx).await.map_err(|error| map_db(&error))
}

#[expect(clippy::too_many_arguments, reason = "one fixed schema record")]
async fn insert_key(
    tx: &mut Transaction<'_, Postgres>,
    id: Uuid,
    account: SubjectId,
    prefix: &str,
    digest: &[u8; DIGEST_BYTES],
    name: &str,
    scopes: &[String],
    expires_at: Option<OffsetDateTime>,
    created_at: OffsetDateTime,
    rotated_from: Option<Uuid>,
) -> Result<sqlx::postgres::PgRow, ApiKeyStoreError> {
    sqlx::query(
        "INSERT INTO api_keys (id, service_account_id, key_prefix, secret_hash, name, scopes, expires_at, created_at, last_used_at, revoked_at, rotated_from_id) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, NULL, NULL, $9) \
         RETURNING id, service_account_id, key_prefix, name, scopes, expires_at, created_at, last_used_at, revoked_at, rotated_from_id")
        .bind(id).bind(account.as_uuid()).bind(prefix).bind(digest.as_slice()).bind(name).bind(scopes)
        .bind(expires_at).bind(created_at).bind(rotated_from).fetch_one(&mut **tx).await.map_err(|error| map_insert(&error))
}

fn account_from_row(
    row: &sqlx::postgres::PgRow,
) -> Result<ServiceAccountMetadata, ApiKeyStoreError> {
    let id = subject(
        row.try_get("id")
            .map_err(|_| ApiKeyStoreError::CorruptData)?,
    )?;
    let name: String = row
        .try_get("name")
        .map_err(|_| ApiKeyStoreError::CorruptData)?;
    valid_name(&name).map_err(|_| ApiKeyStoreError::CorruptData)?;
    let tenant_id = row
        .try_get::<Option<Uuid>, _>("tenant_id")
        .map_err(|_| ApiKeyStoreError::CorruptData)?
        .map(|value| TenantId::from_uuid(value).map_err(|_| ApiKeyStoreError::CorruptData))
        .transpose()?;
    let created_by_user_id = subject(
        row.try_get("created_by_user_id")
            .map_err(|_| ApiKeyStoreError::CorruptData)?,
    )?;
    let created_at = utc(row
        .try_get("created_at")
        .map_err(|_| ApiKeyStoreError::CorruptData)?);
    let disabled_at = row
        .try_get::<Option<OffsetDateTime>, _>("disabled_at")
        .map_err(|_| ApiKeyStoreError::CorruptData)?
        .map(utc);
    if disabled_at.is_some_and(|value| value < created_at) {
        return Err(ApiKeyStoreError::CorruptData);
    }
    Ok(ServiceAccountMetadata {
        id,
        name,
        tenant_id,
        created_by_user_id,
        created_at,
        disabled_at,
    })
}

fn key_from_row(row: &sqlx::postgres::PgRow) -> Result<ApiKeyMetadata, ApiKeyStoreError> {
    let id: Uuid = row
        .try_get("id")
        .map_err(|_| ApiKeyStoreError::CorruptData)?;
    valid_uuid(id).map_err(|_| ApiKeyStoreError::CorruptData)?;
    let service_account_id = subject(
        row.try_get("service_account_id")
            .map_err(|_| ApiKeyStoreError::CorruptData)?,
    )?;
    let key_prefix: String = row
        .try_get("key_prefix")
        .map_err(|_| ApiKeyStoreError::CorruptData)?;
    if !valid_prefix(&key_prefix) {
        return Err(ApiKeyStoreError::CorruptData);
    }
    let name: String = row
        .try_get("name")
        .map_err(|_| ApiKeyStoreError::CorruptData)?;
    valid_name(&name).map_err(|_| ApiKeyStoreError::CorruptData)?;
    let scopes = persisted_scopes(
        row.try_get("scopes")
            .map_err(|_| ApiKeyStoreError::CorruptData)?,
    )?;
    let expires_at = row
        .try_get::<Option<OffsetDateTime>, _>("expires_at")
        .map_err(|_| ApiKeyStoreError::CorruptData)?
        .map(utc);
    let created_at = utc(row
        .try_get("created_at")
        .map_err(|_| ApiKeyStoreError::CorruptData)?);
    let last_used_at = row
        .try_get::<Option<OffsetDateTime>, _>("last_used_at")
        .map_err(|_| ApiKeyStoreError::CorruptData)?
        .map(utc);
    let revoked_at = row
        .try_get::<Option<OffsetDateTime>, _>("revoked_at")
        .map_err(|_| ApiKeyStoreError::CorruptData)?
        .map(utc);
    let rotated_from_id: Option<Uuid> = row
        .try_get("rotated_from_id")
        .map_err(|_| ApiKeyStoreError::CorruptData)?;
    if expires_at.is_some_and(|value| value <= created_at)
        || last_used_at.is_some_and(|value| value < created_at)
        || revoked_at.is_some_and(|value| value < created_at)
        || matches!((last_used_at, expires_at), (Some(last), Some(expiry)) if last >= expiry)
        || matches!((last_used_at, revoked_at), (Some(last), Some(revoked)) if last > revoked)
        || rotated_from_id == Some(id)
        || rotated_from_id.is_some_and(|value| valid_uuid(value).is_err())
    {
        return Err(ApiKeyStoreError::CorruptData);
    }
    Ok(ApiKeyMetadata {
        id,
        service_account_id,
        key_prefix,
        name,
        scopes,
        expires_at,
        created_at,
        last_used_at,
        revoked_at,
        rotated_from_id,
    })
}

fn persisted_scopes(values: Vec<String>) -> Result<Vec<Scope>, ApiKeyStoreError> {
    if values.len() > MAX_SCOPES {
        return Err(ApiKeyStoreError::CorruptData);
    }
    let scopes = values
        .into_iter()
        .map(|value| Scope::new(value).map_err(|_| ApiKeyStoreError::CorruptData))
        .collect::<Result<Vec<_>, _>>()?;
    if scopes.windows(2).any(|pair| pair[0] >= pair[1]) {
        return Err(ApiKeyStoreError::CorruptData);
    }
    Ok(scopes)
}

fn normalized_scopes(scopes: &[Scope], max: usize) -> Result<Vec<Scope>, ApiKeyStoreError> {
    let mut result = scopes.to_vec();
    result.sort_unstable();
    result.dedup();
    if result.len() > max || result.len() > MAX_SCOPES {
        return Err(ApiKeyStoreError::TooManyScopes);
    }
    Ok(result)
}

fn scope_values(scopes: &[Scope]) -> Vec<String> {
    scopes
        .iter()
        .map(|scope| scope.as_str().to_owned())
        .collect()
}

fn valid_name(name: &str) -> Result<(), ApiKeyStoreError> {
    if name.is_empty() || name.len() > MAX_NAME_BYTES || name.trim() != name || name.contains('\0')
    {
        Err(ApiKeyStoreError::InvalidName)
    } else {
        Ok(())
    }
}

fn valid_expiry(
    expires_at: Option<OffsetDateTime>,
    created_at: OffsetDateTime,
    max: Duration,
) -> Result<Option<OffsetDateTime>, ApiKeyStoreError> {
    let Some(expires_at) = expires_at.map(utc) else {
        return Ok(None);
    };
    let lifetime =
        TimeDuration::try_from(max).map_err(|_| ApiKeyStoreError::InvalidConfiguration)?;
    let latest = created_at
        .checked_add(lifetime)
        .ok_or(ApiKeyStoreError::InvalidConfiguration)?;
    if expires_at <= created_at || expires_at > latest {
        Err(ApiKeyStoreError::InvalidExpiry)
    } else {
        Ok(Some(expires_at))
    }
}

fn last_used_threshold(
    now: OffsetDateTime,
    interval: Duration,
) -> Result<OffsetDateTime, ApiKeyStoreError> {
    now.checked_sub(
        TimeDuration::try_from(interval).map_err(|_| ApiKeyStoreError::InvalidConfiguration)?,
    )
    .ok_or(ApiKeyStoreError::InvalidConfiguration)
}

fn subject(value: Uuid) -> Result<SubjectId, ApiKeyStoreError> {
    SubjectId::from_uuid(value).map_err(|_| ApiKeyStoreError::CorruptData)
}
fn utc(value: OffsetDateTime) -> OffsetDateTime {
    value.to_offset(UtcOffset::UTC)
}
fn valid_uuid(value: Uuid) -> Result<(), ApiKeyStoreError> {
    if value.get_version() == Some(Version::SortRand) && value.get_variant() == Variant::RFC4122 {
        Ok(())
    } else {
        Err(ApiKeyStoreError::InvalidIdentifier)
    }
}
fn valid_prefix(value: &str) -> bool {
    value.strip_prefix("omnius_").is_some_and(|part| {
        part.len() == 12
            && part
                .as_bytes()
                .iter()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
    })
}

async fn finish<T>(
    tx: Transaction<'_, Postgres>,
    result: Result<T, ApiKeyStoreError>,
) -> Result<T, ApiKeyStoreError> {
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

/// Stable, value-free API-key lifecycle errors.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[non_exhaustive]
pub enum ApiKeyStoreError {
    /// Capability disabled.
    #[error("API-key authentication is disabled")]
    Disabled,
    /// Invalid configuration.
    #[error("API-key persistence configuration is invalid")]
    InvalidConfiguration,
    /// PostgreSQL unavailable.
    #[error("API-key persistence is unavailable")]
    Unavailable,
    /// Safe-to-retry transaction conflict.
    #[error("API-key transaction encountered a transient conflict")]
    Transient(RetryableSqlState),
    /// Constraint conflict.
    #[error("API-key state conflicts with persisted state")]
    Conflict,
    /// Generated prefix collision.
    #[error("API-key prefix collided with persisted state")]
    KeyCollision,
    /// Credential generation failed.
    #[error("API-key credential generation failed")]
    CredentialGeneration,
    /// Invalid name.
    #[error("API-key name is invalid")]
    InvalidName,
    /// Invalid expiry.
    #[error("API-key expiration is invalid")]
    InvalidExpiry,
    /// Excessive scopes.
    #[error("API-key scope set is too large")]
    TooManyScopes,
    /// Invalid public identifier.
    #[error("API-key identifier is invalid")]
    InvalidIdentifier,
    /// Creating user missing.
    #[error("API-key service-account creator was not found")]
    CreatorNotFound,
    /// Requested tenant is missing or inactive.
    #[error("API-key service-account tenant is unavailable")]
    TenantUnavailable,
    /// Service account missing.
    #[error("API-key service account was not found")]
    ServiceAccountNotFound,
    /// Key missing.
    #[error("API key was not found")]
    ApiKeyNotFound,
    /// Service account disabled.
    #[error("API-key service account is disabled")]
    ServiceAccountDisabled,
    /// Key inactive.
    #[error("API key is inactive")]
    ApiKeyInactive,
    /// Credential rejected.
    #[error("API-key authentication failed")]
    AuthenticationFailed,
    /// Persisted state invalid.
    #[error("API-key persistence contains invalid state")]
    CorruptData,
}

impl RetryableTransactionError for ApiKeyStoreError {
    fn retryable_sql_state(&self) -> Option<RetryableSqlState> {
        match self {
            Self::Transient(state) => Some(*state),
            _ => None,
        }
    }
}

impl ApiKeyStoreError {
    const fn metric_label(self) -> &'static str {
        match self {
            Self::Disabled => "disabled",
            Self::InvalidConfiguration => "invalid_configuration",
            Self::Unavailable => "unavailable",
            Self::Transient(_) => "transient",
            Self::Conflict => "conflict",
            Self::KeyCollision => "key_collision",
            Self::CredentialGeneration => "credential_generation",
            Self::InvalidName => "invalid_name",
            Self::InvalidExpiry => "invalid_expiry",
            Self::TooManyScopes => "too_many_scopes",
            Self::InvalidIdentifier => "invalid_identifier",
            Self::CreatorNotFound => "creator_not_found",
            Self::TenantUnavailable => "tenant_unavailable",
            Self::ServiceAccountNotFound => "service_account_not_found",
            Self::ApiKeyNotFound => "api_key_not_found",
            Self::ServiceAccountDisabled => "service_account_disabled",
            Self::ApiKeyInactive => "api_key_inactive",
            Self::AuthenticationFailed => "authentication_failed",
            Self::CorruptData => "corrupt_data",
        }
    }
}

fn map_insert(error: &sqlx::Error) -> ApiKeyStoreError {
    if error
        .as_database_error()
        .and_then(sqlx::error::DatabaseError::constraint)
        == Some("api_keys_key_prefix_key")
    {
        ApiKeyStoreError::KeyCollision
    } else {
        map_db(error)
    }
}

fn map_db(error: &sqlx::Error) -> ApiKeyStoreError {
    if let Some(state) = RetryableSqlState::from_sqlx(error) {
        return ApiKeyStoreError::Transient(state);
    }
    match error
        .as_database_error()
        .and_then(sqlx::error::DatabaseError::code)
    {
        Some(code) if matches!(code.as_ref(), "23502" | "23503" | "23505" | "23514") => {
            ApiKeyStoreError::Conflict
        }
        _ => ApiKeyStoreError::Unavailable,
    }
}

fn label<T>(result: &Result<T, ApiKeyStoreError>, success: &'static str) -> &'static str {
    match result {
        Ok(_) => success,
        Err(error) => (*error).metric_label(),
    }
}
fn option_label<T>(result: &Result<Option<T>, ApiKeyStoreError>) -> &'static str {
    match result {
        Ok(Some(_)) => "found",
        Ok(None) => "not_found",
        Err(error) => (*error).metric_label(),
    }
}
fn record(operation: &'static str, result: &'static str, elapsed: Duration) {
    metrics::counter!("omnius_auth_api_key_operations_total", "operation" => operation, "result" => result).increment(1);
    metrics::histogram!("omnius_auth_api_key_operation_duration_seconds", "operation" => operation)
        .record(elapsed.as_secs_f64());
}

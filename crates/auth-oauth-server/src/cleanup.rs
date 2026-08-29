//! Bounded, contention-safe cleanup passes for OAuth protocol tombstones.

use omnius_postgres::{PostgresPool, RetryableSqlState, RetryableTransactionError};
use thiserror::Error;
use time::OffsetDateTime;

const MAX_CLEANUP_BATCH: u32 = 10_000;

/// Deletion counts for expired authorization requests and codes.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct AuthorizationArtifactCleanup {
    /// Expired authorization requests deleted.
    pub requests: u64,
    /// Expired authorization codes deleted.
    pub codes: u64,
}

/// Mutation counts for expired client-owned replay and metadata state.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ClientStateCleanup {
    /// Expired client assertion replay records deleted.
    pub assertions: u64,
    /// Expired metadata cache entries cleared in place.
    pub metadata_caches: u64,
}

/// Counts returned by one bounded run of all four cleanup passes.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct OAuthCleanupReport {
    /// Authorization request/code cleanup.
    pub authorization_artifacts: AuthorizationArtifactCleanup,
    /// Assertion replay and metadata-cache cleanup.
    pub client_state: ClientStateCleanup,
    /// Expired refresh-token tombstones deleted.
    pub refresh_tombstones: u64,
    /// Expired access-token revocations deleted.
    pub access_revocations: u64,
}

/// Supervised PostgreSQL OAuth cleanup worker.
#[derive(Clone, Debug)]
pub struct OAuthCleanup {
    pool: PostgresPool,
}

impl OAuthCleanup {
    /// Creates cleanup passes over the shared managed PostgreSQL pool.
    #[must_use]
    pub const fn new(pool: PostgresPool) -> Self {
        Self { pool }
    }

    /// Runs each independent bounded cleanup pass once.
    ///
    /// A batch limit applies independently to each table. Every mutation selects rows in stable
    /// expiry/key order and uses `FOR UPDATE SKIP LOCKED`, so concurrent supervisors make progress
    /// without waiting on protocol traffic or each other.
    pub async fn run_bounded(
        &self,
        now: OffsetDateTime,
        batch_limit: u32,
    ) -> Result<OAuthCleanupReport, OAuthCleanupError> {
        validate_batch(batch_limit)?;
        Ok(OAuthCleanupReport {
            authorization_artifacts: self
                .cleanup_authorization_artifacts(now, batch_limit)
                .await?,
            client_state: self.cleanup_client_state(now, batch_limit).await?,
            refresh_tombstones: self.cleanup_refresh_tombstones(now, batch_limit).await?,
            access_revocations: self.cleanup_access_revocations(now, batch_limit).await?,
        })
    }

    /// Deletes bounded expired authorization requests and codes.
    pub async fn cleanup_authorization_artifacts(
        &self,
        now: OffsetDateTime,
        batch_limit: u32,
    ) -> Result<AuthorizationArtifactCleanup, OAuthCleanupError> {
        validate_batch(batch_limit)?;
        let limit = i64::from(batch_limit);
        let mut connection = self
            .pool
            .acquire()
            .await
            .map_err(|_| OAuthCleanupError::Unavailable)?;
        let requests = sqlx::query(
            "WITH expired AS ( \
                 SELECT id FROM oauth_authorization_requests \
                 WHERE expires_at <= $1 ORDER BY expires_at, id LIMIT $2 \
                 FOR UPDATE SKIP LOCKED \
             ) \
             DELETE FROM oauth_authorization_requests request USING expired \
             WHERE request.id = expired.id",
        )
        .bind(now)
        .bind(limit)
        .execute(&mut *connection)
        .await
        .map_err(|error| map_db(&error))?
        .rows_affected();
        let codes = sqlx::query(
            "WITH expired AS ( \
                 SELECT id FROM oauth_authorization_codes \
                 WHERE expires_at <= $1 ORDER BY expires_at, id LIMIT $2 \
                 FOR UPDATE SKIP LOCKED \
             ) \
             DELETE FROM oauth_authorization_codes code USING expired \
             WHERE code.id = expired.id",
        )
        .bind(now)
        .bind(limit)
        .execute(&mut *connection)
        .await
        .map_err(|error| map_db(&error))?
        .rows_affected();
        Ok(AuthorizationArtifactCleanup { requests, codes })
    }

    /// Deletes expired client-assertion replay keys and clears expired metadata cache entries.
    pub async fn cleanup_client_state(
        &self,
        now: OffsetDateTime,
        batch_limit: u32,
    ) -> Result<ClientStateCleanup, OAuthCleanupError> {
        validate_batch(batch_limit)?;
        let limit = i64::from(batch_limit);
        let mut connection = self
            .pool
            .acquire()
            .await
            .map_err(|_| OAuthCleanupError::Unavailable)?;
        let assertions = sqlx::query(
            "WITH expired AS ( \
                 SELECT id FROM oauth_client_assertions \
                 WHERE expires_at <= $1 ORDER BY expires_at, id LIMIT $2 \
                 FOR UPDATE SKIP LOCKED \
             ) \
             DELETE FROM oauth_client_assertions assertion USING expired \
             WHERE assertion.id = expired.id",
        )
        .bind(now)
        .bind(limit)
        .execute(&mut *connection)
        .await
        .map_err(|error| map_db(&error))?
        .rows_affected();
        let metadata_caches = sqlx::query(
            "WITH expired AS ( \
                 SELECT id FROM oauth_clients \
                 WHERE source = 'client_id_metadata' AND metadata_cache_expires_at <= $1 \
                 ORDER BY metadata_cache_expires_at, id LIMIT $2 \
                 FOR UPDATE SKIP LOCKED \
             ) \
             UPDATE oauth_clients client SET metadata_cache_body = NULL, \
                 metadata_cache_etag = NULL, metadata_cache_last_modified = NULL, \
                 metadata_cached_at = NULL, metadata_cache_expires_at = NULL, \
                 updated_at = GREATEST(client.updated_at, $1) \
             FROM expired WHERE client.id = expired.id",
        )
        .bind(now)
        .bind(limit)
        .execute(&mut *connection)
        .await
        .map_err(|error| map_db(&error))?
        .rows_affected();
        Ok(ClientStateCleanup {
            assertions,
            metadata_caches,
        })
    }

    /// Deletes a bounded batch of expired refresh-token rows.
    ///
    /// Expired presentations no longer authorize a request, so retaining their HMAC tombstones
    /// after expiry provides no replay protection. Only chain roots are selected; deleting a root
    /// never violates another token's replacement foreign key, and later passes advance the chain.
    pub async fn cleanup_refresh_tombstones(
        &self,
        now: OffsetDateTime,
        batch_limit: u32,
    ) -> Result<u64, OAuthCleanupError> {
        validate_batch(batch_limit)?;
        let mut connection = self
            .pool
            .acquire()
            .await
            .map_err(|_| OAuthCleanupError::Unavailable)?;
        let result = sqlx::query(
            "WITH expired AS ( \
                 SELECT token.id FROM oauth_refresh_tokens token \
                 WHERE token.expires_at <= $1 AND NOT EXISTS ( \
                     SELECT 1 FROM oauth_refresh_tokens predecessor \
                     WHERE predecessor.replaced_by_id = token.id) \
                 ORDER BY token.expires_at, token.id LIMIT $2 \
                 FOR UPDATE OF token SKIP LOCKED \
             ) \
             DELETE FROM oauth_refresh_tokens token USING expired \
             WHERE token.id = expired.id",
        )
        .bind(now)
        .bind(i64::from(batch_limit))
        .execute(&mut *connection)
        .await
        .map_err(|error| map_db(&error))?;
        Ok(result.rows_affected())
    }

    /// Deletes a bounded batch of access-token revocations after their JWTs expire.
    pub async fn cleanup_access_revocations(
        &self,
        now: OffsetDateTime,
        batch_limit: u32,
    ) -> Result<u64, OAuthCleanupError> {
        validate_batch(batch_limit)?;
        let mut connection = self
            .pool
            .acquire()
            .await
            .map_err(|_| OAuthCleanupError::Unavailable)?;
        let result = sqlx::query(
            "WITH expired AS ( \
                 SELECT jti FROM oauth_access_token_revocations \
                 WHERE expires_at <= $1 ORDER BY expires_at, jti LIMIT $2 \
                 FOR UPDATE SKIP LOCKED \
             ) \
             DELETE FROM oauth_access_token_revocations revocation USING expired \
             WHERE revocation.jti = expired.jti",
        )
        .bind(now)
        .bind(i64::from(batch_limit))
        .execute(&mut *connection)
        .await
        .map_err(|error| map_db(&error))?;
        Ok(result.rows_affected())
    }
}

/// Stable cleanup failures.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[non_exhaustive]
pub enum OAuthCleanupError {
    /// Batch size was zero or above the supervised hard limit.
    #[error("OAuth cleanup batch is invalid")]
    InvalidBatch,
    /// PostgreSQL is unavailable.
    #[error("OAuth cleanup storage is unavailable")]
    Unavailable,
    /// A retry-safe SQL conflict occurred.
    #[error("OAuth cleanup encountered a transient conflict")]
    Transient(RetryableSqlState),
}

impl RetryableTransactionError for OAuthCleanupError {
    fn retryable_sql_state(&self) -> Option<RetryableSqlState> {
        match self {
            Self::Transient(state) => Some(*state),
            _ => None,
        }
    }
}

fn validate_batch(batch_limit: u32) -> Result<(), OAuthCleanupError> {
    if batch_limit == 0 || batch_limit > MAX_CLEANUP_BATCH {
        Err(OAuthCleanupError::InvalidBatch)
    } else {
        Ok(())
    }
}

fn map_db(error: &sqlx::Error) -> OAuthCleanupError {
    RetryableSqlState::from_sqlx(error)
        .map_or(OAuthCleanupError::Unavailable, OAuthCleanupError::Transient)
}

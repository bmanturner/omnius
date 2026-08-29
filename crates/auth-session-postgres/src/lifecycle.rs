use omnius_auth_core::{
    SessionCleanup, SessionConfig, SessionMetadata, SessionRegistration, SessionValidation,
    SubjectId,
};
use omnius_postgres::{PostgresPool, RetryableSqlState, RetryableTransactionError};
use sqlx::{PgConnection, Postgres, Row as _, Transaction};
use thiserror::Error;
use time::OffsetDateTime;
use tower_sessions::Session;
use uuid::Uuid;
/// PostgreSQL lifecycle adapter layered beside the maintained provider store.
#[derive(Clone, Copy, Debug, Default)]
pub struct PostgresSessionLifecycle;

impl PostgresSessionLifecycle {
    /// Persists the rotated login session and its lifecycle metadata before the
    /// response exposes the new cookie.
    ///
    /// This deliberately saves through the maintained provider first so its
    /// generated ID is available, then linearizes the login by registering
    /// metadata under the subject lock. The response cannot expose the ID before
    /// registration completes. If metadata persistence or commit fails, the new
    /// provider session is flushed before returning.
    ///
    /// # Errors
    ///
    /// Returns a stable session-data, input, conflict, or persistence failure.
    pub async fn register_after_login(
        &self,
        pool: &PostgresPool,
        session: &Session,
        registration: &SessionRegistration<'_>,
        config: &SessionConfig,
    ) -> Result<(), SessionStoreError> {
        if session.save().await.is_err() {
            return Err(fail_closed(session, SessionStoreError::SessionData).await);
        }
        let raw_pool = pool.sqlx_pool();
        let mut transaction = match raw_pool.begin().await {
            Ok(transaction) => transaction,
            Err(error) => {
                return Err(fail_closed(session, map_sqlx_error(&error)).await);
            }
        };
        if let Err(error) = lock_subject(&mut transaction, registration.subject_id).await {
            let _ = transaction.rollback().await;
            return Err(fail_closed(session, error).await);
        }
        if let Err(error) = self
            .register_with(&mut transaction, session, registration, config)
            .await
        {
            let _ = transaction.rollback().await;
            return Err(fail_closed(session, error).await);
        }
        if let Err(error) = transaction.commit().await {
            let failure = map_sqlx_error(&error);
            return Err(fail_closed(session, failure).await);
        }
        Ok(())
    }

    async fn register_with(
        &self,
        transaction: &mut Transaction<'_, Postgres>,
        session: &Session,
        registration: &SessionRegistration<'_>,
        config: &SessionConfig,
    ) -> Result<(), SessionStoreError> {
        let session_id = current_session_id(session)?;
        let absolute_timeout = time::Duration::try_from(config.absolute_timeout)
            .map_err(|_| SessionStoreError::InvalidInput)?;
        let absolute_expires_at = registration
            .created_at
            .checked_add(absolute_timeout)
            .ok_or(SessionStoreError::InvalidInput)?;
        let inserted = sqlx::query(
            "INSERT INTO sessions (session_id, user_id, device_id, created_at, last_seen_at, \
             absolute_expires_at, user_agent_hash, ip_prefix) \
             SELECT $1, $2, $3, $4, $4, $5, $6, $7::inet \
             FROM users u WHERE u.id = $2 AND u.status = 'active'",
        )
        .bind(session_id)
        .bind(registration.subject_id.as_uuid())
        .bind(registration.device_id)
        .bind(registration.created_at)
        .bind(absolute_expires_at)
        .bind(
            registration
                .user_agent_hash
                .as_ref()
                .map(<[u8; 32]>::as_slice),
        )
        .bind(registration.ip_prefix)
        .execute(&mut **transaction)
        .await
        .map_err(|error| map_sqlx_error(&error))?;
        if inserted.rows_affected() != 1 {
            return Err(SessionStoreError::Inactive);
        }
        Ok(())
    }

    /// Validates absolute lifetime, advances activity, and slides the provider's
    /// idle expiry without allowing it to pass the absolute cap.
    ///
    /// # Errors
    ///
    /// Returns a stable input or persistence failure.
    pub async fn validate_and_touch_with(
        &self,
        connection: &mut PgConnection,
        session: &Session,
        subject_id: SubjectId,
        config: &SessionConfig,
        now: OffsetDateTime,
    ) -> Result<SessionValidation, SessionStoreError> {
        let Some(session_id) = session.id().map(|id| id.to_string()) else {
            return Ok(SessionValidation::Rejected);
        };
        let idle_timeout = time::Duration::try_from(config.idle_timeout)
            .map_err(|_| SessionStoreError::InvalidInput)?;
        let idle_expires_at = now
            .checked_add(idle_timeout)
            .ok_or(SessionStoreError::InvalidInput)?;
        let row = sqlx::query(
            "WITH eligible AS ( \
               SELECT m.device_id, m.created_at, m.absolute_expires_at \
               FROM sessions m JOIN users u ON u.id = m.user_id \
               WHERE m.session_id = $1 AND m.user_id = $2 AND m.revoked_at IS NULL \
                 AND u.status = 'active' AND m.absolute_expires_at > $3 \
             ), live_provider AS ( \
               UPDATE tower_sessions.session p \
               SET expiry_date = LEAST($4, eligible.absolute_expires_at) \
               FROM eligible \
               WHERE p.id = $1 AND p.expiry_date > $3 \
               RETURNING eligible.device_id, eligible.created_at, \
                         eligible.absolute_expires_at \
             ) \
             UPDATE sessions m SET last_seen_at = $3 \
             FROM live_provider WHERE m.session_id = $1 \
             RETURNING live_provider.device_id, live_provider.created_at, \
                       m.last_seen_at, live_provider.absolute_expires_at",
        )
        .bind(&session_id)
        .bind(subject_id.as_uuid())
        .bind(now)
        .bind(idle_expires_at)
        .fetch_optional(&mut *connection)
        .await
        .map_err(|error| map_sqlx_error(&error))?;
        match row {
            Some(row) => Ok(SessionValidation::Active(metadata_from_row(&row, true)?)),
            None => Ok(SessionValidation::Rejected),
        }
    }

    /// Lists active provider-backed sessions without exposing bearer session IDs.
    ///
    /// # Errors
    ///
    /// Returns a stable persistence failure.
    pub async fn list_active_with(
        &self,
        connection: &mut PgConnection,
        subject_id: SubjectId,
        current: &Session,
        now: OffsetDateTime,
    ) -> Result<Vec<SessionMetadata>, SessionStoreError> {
        let current_id = current.id().map(|id| id.to_string());
        let rows = sqlx::query(
            "SELECT m.session_id, m.device_id, m.created_at, m.last_seen_at, \
                    m.absolute_expires_at \
             FROM sessions m JOIN tower_sessions.session p ON p.id = m.session_id \
             JOIN users u ON u.id = m.user_id \
             WHERE m.user_id = $1 AND m.revoked_at IS NULL AND u.status = 'active' \
               AND m.absolute_expires_at > $2 AND p.expiry_date > $2 \
             ORDER BY m.created_at DESC, m.session_id ASC",
        )
        .bind(subject_id.as_uuid())
        .bind(now)
        .fetch_all(&mut *connection)
        .await
        .map_err(|error| map_sqlx_error(&error))?;
        rows.into_iter()
            .map(|row| {
                let session_id: String = row
                    .try_get("session_id")
                    .map_err(|_| SessionStoreError::CorruptData)?;
                metadata_from_row(&row, current_id.as_deref() == Some(session_id.as_str()))
            })
            .collect()
    }

    /// Rotates the provider ID after a committed security-sensitive transition.
    ///
    /// Call this only after committing the domain change. The old provider row is
    /// durably deleted before cycling and saving the new ID. Registration then
    /// linearizes under the same subject advisory lock as subject/device
    /// revocation, before the response exposes the ID. Any later failure flushes
    /// the new provider session.
    ///
    /// # Errors
    ///
    /// Returns a stable session-data, input, conflict, or persistence failure.
    pub async fn rotate_after_security_change(
        &self,
        pool: &PostgresPool,
        session: &Session,
        subject_id: SubjectId,
        registration: &SessionRegistration<'_>,
        config: &SessionConfig,
        now: OffsetDateTime,
    ) -> Result<bool, SessionStoreError> {
        if registration.subject_id != subject_id {
            return Err(SessionStoreError::InvalidInput);
        }
        let mut connection = pool
            .acquire()
            .await
            .map_err(|_| SessionStoreError::Unavailable)?;
        let validation = self
            .validate_and_touch_with(&mut connection, session, subject_id, config, now)
            .await?;
        drop(connection);
        if validation == SessionValidation::Rejected {
            return Err(fail_closed(session, SessionStoreError::Inactive).await);
        }
        let old_session_id = current_session_id(session)?;
        let raw_pool = pool.sqlx_pool();
        if let Err(error) = sqlx::query("DELETE FROM tower_sessions.session WHERE id = $1")
            .bind(&old_session_id)
            .execute(&raw_pool)
            .await
        {
            return Err(fail_closed(session, map_sqlx_error(&error)).await);
        }
        if session.cycle_id().await.is_err() {
            return Err(fail_closed(session, SessionStoreError::SessionData).await);
        }
        if session.save().await.is_err() {
            return Err(fail_closed(session, SessionStoreError::SessionData).await);
        }
        let mut transaction = match raw_pool.begin().await {
            Ok(transaction) => transaction,
            Err(error) => {
                return Err(fail_closed(session, map_sqlx_error(&error)).await);
            }
        };
        if let Err(error) = lock_subject(&mut transaction, subject_id).await {
            let _ = transaction.rollback().await;
            return Err(fail_closed(session, error).await);
        }
        let result = async {
            self.register_with(&mut transaction, session, registration, config)
                .await?;
            revoke_current(&mut transaction, &old_session_id, subject_id, now).await
        }
        .await;
        let revoked = match result {
            Ok(revoked) => revoked,
            Err(error) => {
                let _ = transaction.rollback().await;
                return Err(fail_closed(session, error).await);
            }
        };
        if !revoked {
            let _ = transaction.rollback().await;
            return Err(fail_closed(session, SessionStoreError::Conflict).await);
        }
        if let Err(error) = transaction.commit().await {
            let failure = map_sqlx_error(&error);
            return Err(fail_closed(session, failure).await);
        }
        Ok(revoked)
    }

    /// Revokes the current session in the caller-owned transaction.
    ///
    /// Callers must also call `AuthSession::logout` after commit to clear the cookie.
    ///
    /// # Errors
    ///
    /// Returns a stable persistence failure.
    pub async fn revoke_current_with(
        &self,
        transaction: &mut Transaction<'_, Postgres>,
        session: &Session,
        subject_id: SubjectId,
        now: OffsetDateTime,
    ) -> Result<bool, SessionStoreError> {
        lock_subject(transaction, subject_id).await?;
        let Some(session_id) = session.id().map(|id| id.to_string()) else {
            return Ok(false);
        };
        revoke_current(transaction, &session_id, subject_id, now).await
    }

    /// Revokes every active session for one device.
    ///
    /// # Errors
    ///
    /// Returns a stable persistence failure.
    pub async fn revoke_device_with(
        &self,
        transaction: &mut Transaction<'_, Postgres>,
        subject_id: SubjectId,
        device_id: Uuid,
        now: OffsetDateTime,
    ) -> Result<u64, SessionStoreError> {
        lock_subject(transaction, subject_id).await?;
        let row = sqlx::query(
            "WITH revoked AS ( \
               UPDATE sessions m SET revoked_at = $3 \
               FROM users u \
               WHERE m.user_id = $1 AND m.device_id = $2 AND m.revoked_at IS NULL \
                 AND u.id = m.user_id AND u.status = 'active' \
               RETURNING m.session_id \
             ), deleted AS ( \
               DELETE FROM tower_sessions.session p USING revoked r \
               WHERE p.id = r.session_id RETURNING p.id \
             ) SELECT count(*)::bigint AS count FROM deleted",
        )
        .bind(subject_id.as_uuid())
        .bind(device_id)
        .bind(now)
        .fetch_one(&mut **transaction)
        .await
        .map_err(|error| map_sqlx_error(&error))?;
        persisted_count(&row)
    }

    /// Revokes every active session for one subject.
    ///
    /// # Errors
    ///
    /// Returns a stable persistence failure.
    pub async fn revoke_all_with(
        &self,
        transaction: &mut Transaction<'_, Postgres>,
        subject_id: SubjectId,
        now: OffsetDateTime,
    ) -> Result<u64, SessionStoreError> {
        lock_subject(transaction, subject_id).await?;
        let row = sqlx::query(
            "WITH revoked AS ( \
               UPDATE sessions m SET revoked_at = $2 \
               FROM users u \
               WHERE m.user_id = $1 AND m.revoked_at IS NULL \
                 AND u.id = m.user_id AND u.status = 'active' \
               RETURNING m.session_id \
             ), deleted AS ( \
               DELETE FROM tower_sessions.session p USING revoked r \
               WHERE p.id = r.session_id RETURNING p.id \
             ) SELECT count(*)::bigint AS count FROM deleted",
        )
        .bind(subject_id.as_uuid())
        .bind(now)
        .fetch_one(&mut **transaction)
        .await
        .map_err(|error| map_sqlx_error(&error))?;
        persisted_count(&row)
    }

    /// Runs one transaction-owned cleanup pass suitable for a supervised interval task.
    ///
    /// Revoked, expired, and orphaned metadata remains as a one-day tombstone so
    /// the response guard can reject any late save from an in-flight request.
    ///
    /// # Errors
    ///
    /// Returns a stable persistence failure.
    pub async fn cleanup_with(
        &self,
        transaction: &mut Transaction<'_, Postgres>,
        now: OffsetDateTime,
    ) -> Result<SessionCleanup, SessionStoreError> {
        let provider = sqlx::query(
            "DELETE FROM tower_sessions.session p USING sessions m \
             WHERE p.id = m.session_id AND (m.revoked_at IS NOT NULL OR m.absolute_expires_at <= $1)",
        )
        .bind(now)
        .execute(&mut **transaction)
        .await
        .map_err(|error| map_sqlx_error(&error))?
        .rows_affected();
        let expired_provider = sqlx::query(
            "WITH expired AS ( \
               DELETE FROM tower_sessions.session WHERE expiry_date <= $1 RETURNING id \
             ), tombstoned AS ( \
               UPDATE sessions m SET revoked_at = COALESCE(m.revoked_at, $1) \
               FROM expired e WHERE m.session_id = e.id RETURNING m.session_id \
             ) SELECT count(*)::bigint AS count FROM expired",
        )
        .bind(now)
        .fetch_one(&mut **transaction)
        .await
        .map_err(|error| map_sqlx_error(&error))
        .and_then(|row| persisted_count(&row))?;
        let metadata = sqlx::query(
            "DELETE FROM sessions m \
             WHERE m.revoked_at <= $1 - INTERVAL '1 day' \
                OR m.absolute_expires_at <= $1 - INTERVAL '1 day' \
                OR (m.last_seen_at <= $1 - INTERVAL '1 day' \
                    AND NOT EXISTS ( \
                      SELECT 1 FROM tower_sessions.session p WHERE p.id = m.session_id \
                    ))",
        )
        .bind(now)
        .execute(&mut **transaction)
        .await
        .map_err(|error| map_sqlx_error(&error))?
        .rows_affected();
        Ok(SessionCleanup {
            provider_rows: provider.saturating_add(expired_provider),
            metadata_rows: metadata,
        })
    }
}

async fn fail_closed(session: &Session, failure: SessionStoreError) -> SessionStoreError {
    if session.flush().await.is_err() {
        SessionStoreError::SessionData
    } else {
        failure
    }
}

async fn lock_subject(
    transaction: &mut Transaction<'_, Postgres>,
    subject_id: SubjectId,
) -> Result<(), SessionStoreError> {
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1::text, 0))")
        .bind(subject_id.as_uuid())
        .execute(&mut **transaction)
        .await
        .map(|_| ())
        .map_err(|error| map_sqlx_error(&error))
}

async fn revoke_current(
    transaction: &mut Transaction<'_, Postgres>,
    session_id: &str,
    subject_id: SubjectId,
    now: OffsetDateTime,
) -> Result<bool, SessionStoreError> {
    let row = sqlx::query(
        "WITH revoked AS ( \
           UPDATE sessions m SET revoked_at = $3 \
           FROM users u \
           WHERE m.session_id = $1 AND m.user_id = $2 AND m.revoked_at IS NULL \
             AND u.id = m.user_id AND u.status = 'active' \
           RETURNING session_id \
         ), deleted AS ( \
           DELETE FROM tower_sessions.session p USING revoked r \
           WHERE p.id = r.session_id RETURNING p.id \
         ) SELECT EXISTS(SELECT 1 FROM revoked) AS revoked",
    )
    .bind(session_id)
    .bind(subject_id.as_uuid())
    .bind(now)
    .fetch_one(&mut **transaction)
    .await
    .map_err(|error| map_sqlx_error(&error))?;
    row.try_get("revoked")
        .map_err(|_| SessionStoreError::CorruptData)
}

fn current_session_id(session: &Session) -> Result<String, SessionStoreError> {
    session
        .id()
        .map(|id| id.to_string())
        .ok_or(SessionStoreError::MissingSessionId)
}

fn metadata_from_row(
    row: &sqlx::postgres::PgRow,
    current: bool,
) -> Result<SessionMetadata, SessionStoreError> {
    Ok(SessionMetadata {
        device_id: row
            .try_get("device_id")
            .map_err(|_| SessionStoreError::CorruptData)?,
        created_at: row
            .try_get("created_at")
            .map_err(|_| SessionStoreError::CorruptData)?,
        last_seen_at: row
            .try_get("last_seen_at")
            .map_err(|_| SessionStoreError::CorruptData)?,
        absolute_expires_at: row
            .try_get("absolute_expires_at")
            .map_err(|_| SessionStoreError::CorruptData)?,
        current,
    })
}

fn persisted_count(row: &sqlx::postgres::PgRow) -> Result<u64, SessionStoreError> {
    let count: i64 = row
        .try_get("count")
        .map_err(|_| SessionStoreError::CorruptData)?;
    u64::try_from(count).map_err(|_| SessionStoreError::CorruptData)
}

/// Stable, value-free session persistence failures.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[non_exhaustive]
pub enum SessionStoreError {
    /// Provider session data could not be read or updated.
    #[error("session data operation failed")]
    SessionData,
    /// Session metadata requires an ID produced by login rotation.
    #[error("session identifier is unavailable")]
    MissingSessionId,
    /// Metadata input or time arithmetic was invalid.
    #[error("session metadata input is invalid")]
    InvalidInput,
    /// Session metadata conflicts with persisted state.
    #[error("session metadata conflicts with persisted state")]
    Conflict,
    /// The credential is missing, revoked, or expired.
    #[error("session is inactive")]
    Inactive,
    /// PostgreSQL is unavailable.
    #[error("session persistence is unavailable")]
    Unavailable,
    /// The complete caller-owned transaction may be replayed after this transient.
    #[error("session transaction encountered a transient conflict")]
    Transient(RetryableSqlState),
    /// Persisted session metadata violated its schema contract.
    #[error("session persistence contains invalid state")]
    CorruptData,
}

impl RetryableTransactionError for SessionStoreError {
    fn retryable_sql_state(&self) -> Option<RetryableSqlState> {
        match self {
            Self::Transient(state) => Some(*state),
            _ => None,
        }
    }
}

fn map_sqlx_error(error: &sqlx::Error) -> SessionStoreError {
    if let Some(state) = RetryableSqlState::from_sqlx(error) {
        return SessionStoreError::Transient(state);
    }
    match error
        .as_database_error()
        .and_then(sqlx::error::DatabaseError::code)
    {
        Some(code)
            if matches!(
                code.as_ref(),
                "22P02" | "23503" | "23505" | "23514" | "23502"
            ) =>
        {
            SessionStoreError::Conflict
        }
        _ => SessionStoreError::Unavailable,
    }
}

use std::fmt;

use futures::future::BoxFuture;
use omnius_jobs_apalis_redis::{RedisAdminError, RedisJobProvider, RedisReplayIdentity};
use omnius_jobs_core::Job;
use omnius_jobs_pgmq::{PgmqAdminError, PgmqJobProvider, PgmqReplayIdentity};

use crate::{
    BackendId, ControlStatus, DeadRecord, JobProviderStatus, PgmqJobStatus, RedisJobStatus,
    ReplayReceipt, WorkerDiagnosticsBuildError, WorkerOperationError, status::JobOperations,
};

/// Worker-boundary Redis/Apalis diagnostics and administrative adapter.
pub struct RedisWorkerJob<J> {
    backend_id: BackendId,
    provider: RedisJobProvider<J>,
}

impl<J: Job> RedisWorkerJob<J> {
    /// Binds a provider under `redis:<logical-job-name>` without exposing its physical namespace.
    ///
    /// # Errors
    ///
    /// Returns [`WorkerDiagnosticsBuildError`] only if the validated job declaration cannot form a
    /// bounded logical identifier.
    pub fn new(provider: RedisJobProvider<J>) -> Result<Self, WorkerDiagnosticsBuildError> {
        let backend_id =
            BackendId::new(format!("redis:{}", provider.definition().name().as_str()))?;
        Ok(Self {
            backend_id,
            provider,
        })
    }

    /// Returns the cloneable provider for task composition.
    #[must_use]
    pub const fn provider(&self) -> &RedisJobProvider<J> {
        &self.provider
    }

    /// Returns the safe logical backend identifier.
    #[must_use]
    pub const fn backend_id(&self) -> &BackendId {
        &self.backend_id
    }
}

impl<J> Clone for RedisWorkerJob<J> {
    fn clone(&self) -> Self {
        Self {
            backend_id: self.backend_id.clone(),
            provider: self.provider.clone(),
        }
    }
}

impl<J> fmt::Debug for RedisWorkerJob<J> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RedisWorkerJob")
            .field("backend_id", &self.backend_id)
            .field("provider", &"[REDACTED]")
            .finish()
    }
}

impl<J: Job> JobOperations for RedisWorkerJob<J> {
    fn backend_id(&self) -> &BackendId {
        &self.backend_id
    }

    fn status(&self) -> BoxFuture<'_, Result<JobProviderStatus, WorkerOperationError>> {
        Box::pin(async move {
            let status = self
                .provider
                .diagnostics()
                .await
                .map_err(|_| WorkerOperationError::Unavailable)?;
            Ok(JobProviderStatus::Redis(RedisJobStatus {
                backend_id: self.backend_id.clone(),
                queued: status.queued(),
                scheduled: status.scheduled(),
                completed: status.completed(),
                dead_lettered: status.dead_lettered(),
                oldest_outstanding_age_ms: status.oldest_outstanding_age().map(duration_millis),
                oldest_outstanding_age_complete: status.oldest_outstanding_age_complete(),
                paused: status.paused(),
                control_revision: revision(status.revision())?,
            }))
        })
    }

    fn set_paused(
        &self,
        paused: bool,
        expected_revision: u64,
    ) -> BoxFuture<'_, Result<ControlStatus, WorkerOperationError>> {
        Box::pin(async move {
            let expected_revision = native_revision(expected_revision)?;
            let state = self
                .provider
                .set_paused(paused, expected_revision)
                .await
                .map_err(map_redis_admin)?;
            Ok(ControlStatus {
                paused: state.paused(),
                revision: revision(state.revision())?,
            })
        })
    }

    fn dead_records(
        &self,
        limit: u16,
    ) -> BoxFuture<'_, Result<Vec<DeadRecord>, WorkerOperationError>> {
        Box::pin(async move {
            self.provider
                .dead_records(usize::from(limit))
                .await
                .map_err(map_redis_admin)?
                .into_iter()
                .map(|record| {
                    Ok(DeadRecord::Redis {
                        record_id: record.record_id().to_owned(),
                        job_id: record.job_id().to_string(),
                        created_at: record.created_at(),
                        failed_at: record.failed_at(),
                        attempt: record.attempt(),
                        envelope_bytes: record.envelope_bytes(),
                    })
                })
                .collect()
        })
    }

    fn replay_dead(
        &self,
        record_id: &str,
        expected_revision: u64,
    ) -> BoxFuture<'_, Result<ReplayReceipt, WorkerOperationError>> {
        let record_id = record_id.to_owned();
        Box::pin(async move {
            let receipt = self
                .provider
                .replay_dead(&record_id, native_revision(expected_revision)?)
                .await
                .map_err(map_redis_admin)?;
            match receipt.identity() {
                RedisReplayIdentity::SameJobSameMessage => {
                    Ok(ReplayReceipt::RedisSameJobSameMessage {
                        job_id: receipt.job_id().to_string(),
                        record_id: receipt.record_id().to_owned(),
                    })
                }
            }
        })
    }
}

/// Worker-boundary PGMQ diagnostics and administrative adapter.
pub struct PgmqWorkerJob<J> {
    backend_id: BackendId,
    provider: PgmqJobProvider<J>,
}

impl<J: Job> PgmqWorkerJob<J> {
    /// Binds a provider under `pgmq:<logical-job-name>` without exposing physical tables.
    ///
    /// # Errors
    ///
    /// Returns [`WorkerDiagnosticsBuildError`] only if the validated job declaration cannot form a
    /// bounded logical identifier.
    pub fn new(provider: PgmqJobProvider<J>) -> Result<Self, WorkerDiagnosticsBuildError> {
        let backend_id = BackendId::new(format!("pgmq:{}", provider.definition().name().as_str()))?;
        Ok(Self {
            backend_id,
            provider,
        })
    }

    /// Returns the cloneable provider for task composition.
    #[must_use]
    pub const fn provider(&self) -> &PgmqJobProvider<J> {
        &self.provider
    }

    /// Returns the safe logical backend identifier.
    #[must_use]
    pub const fn backend_id(&self) -> &BackendId {
        &self.backend_id
    }
}

impl<J> Clone for PgmqWorkerJob<J> {
    fn clone(&self) -> Self {
        Self {
            backend_id: self.backend_id.clone(),
            provider: self.provider.clone(),
        }
    }
}

impl<J> fmt::Debug for PgmqWorkerJob<J> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PgmqWorkerJob")
            .field("backend_id", &self.backend_id)
            .field("provider", &"[REDACTED]")
            .finish()
    }
}

impl<J: Job> JobOperations for PgmqWorkerJob<J> {
    fn backend_id(&self) -> &BackendId {
        &self.backend_id
    }

    fn status(&self) -> BoxFuture<'_, Result<JobProviderStatus, WorkerOperationError>> {
        Box::pin(async move {
            let status = self
                .provider
                .diagnostics()
                .await
                .map_err(|_| WorkerOperationError::Unavailable)?;
            Ok(JobProviderStatus::Pgmq(PgmqJobStatus {
                backend_id: self.backend_id.clone(),
                source_total: status.source_total(),
                source_visible: status.source_visible(),
                source_leased: status.source_leased(),
                source_delayed: status.source_delayed(),
                dead_total: status.dead_total(),
                dead_visible: status.dead_visible(),
                archived_completed: status.completed(),
                oldest_source_age_ms: status.oldest_age().map(duration_millis),
                paused: status.paused(),
                control_revision: revision(status.control_revision())?,
            }))
        })
    }

    fn set_paused(
        &self,
        paused: bool,
        expected_revision: u64,
    ) -> BoxFuture<'_, Result<ControlStatus, WorkerOperationError>> {
        Box::pin(async move {
            let state = self
                .provider
                .set_paused(paused, native_revision(expected_revision)?)
                .await
                .map_err(map_pgmq_admin)?;
            Ok(ControlStatus {
                paused: state.paused(),
                revision: revision(state.revision())?,
            })
        })
    }

    fn dead_records(
        &self,
        limit: u16,
    ) -> BoxFuture<'_, Result<Vec<DeadRecord>, WorkerOperationError>> {
        Box::pin(async move {
            self.provider
                .dead_records(usize::from(limit))
                .await
                .map_err(map_pgmq_admin)?
                .into_iter()
                .map(|record| {
                    Ok(DeadRecord::Pgmq {
                        record_id: record.record_id(),
                        job_id: record.job_id().to_string(),
                        created_at: record.created_at(),
                        failed_at: record.failed_at(),
                        attempt: record.attempt(),
                        envelope_bytes: record.envelope_bytes(),
                    })
                })
                .collect()
        })
    }

    fn replay_dead(
        &self,
        record_id: &str,
        expected_revision: u64,
    ) -> BoxFuture<'_, Result<ReplayReceipt, WorkerOperationError>> {
        let record_id = record_id.parse::<i64>();
        Box::pin(async move {
            let record_id = record_id.map_err(|_| WorkerOperationError::InvalidRequest)?;
            let receipt = self
                .provider
                .replay_dead(record_id, native_revision(expected_revision)?)
                .await
                .map_err(map_pgmq_admin)?;
            match receipt.identity() {
                PgmqReplayIdentity::SameJobNewMessage => Ok(ReplayReceipt::PgmqSameJobNewMessage {
                    job_id: receipt.job_id().to_string(),
                    prior_dead_message_id: receipt.prior_dead_message_id(),
                    new_source_message_id: receipt.new_source_message_id(),
                }),
            }
        })
    }
}

fn duration_millis(duration: std::time::Duration) -> u64 {
    u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
}

fn revision(value: i64) -> Result<u64, WorkerOperationError> {
    u64::try_from(value).map_err(|_| WorkerOperationError::Unavailable)
}

fn native_revision(value: u64) -> Result<i64, WorkerOperationError> {
    i64::try_from(value).map_err(|_| WorkerOperationError::InvalidRequest)
}

fn map_redis_admin(error: RedisAdminError) -> WorkerOperationError {
    match error {
        RedisAdminError::InvalidLimit | RedisAdminError::CorruptRecord => {
            WorkerOperationError::InvalidRequest
        }
        RedisAdminError::RevisionConflict => WorkerOperationError::Conflict,
        RedisAdminError::NotPaused => WorkerOperationError::NotPaused,
        RedisAdminError::RecordNotFound => WorkerOperationError::NotFound,
        RedisAdminError::Unavailable => WorkerOperationError::Unavailable,
    }
}

fn map_pgmq_admin(error: PgmqAdminError) -> WorkerOperationError {
    match error {
        PgmqAdminError::InvalidLimit | PgmqAdminError::CorruptRecord => {
            WorkerOperationError::InvalidRequest
        }
        PgmqAdminError::RevisionConflict => WorkerOperationError::Conflict,
        PgmqAdminError::NotPaused => WorkerOperationError::NotPaused,
        PgmqAdminError::RecordNotFound => WorkerOperationError::NotFound,
        PgmqAdminError::Unavailable => WorkerOperationError::Unavailable,
    }
}

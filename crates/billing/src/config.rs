use std::time::Duration;

use serde::Deserialize;
use thiserror::Error;

const MAX_LEASE: Duration = Duration::from_mins(5);
const MAX_RETRY_DELAY: Duration = Duration::from_hours(1);
const MAX_GRACE: Duration = Duration::from_hours(30 * 24);
const MIN_DATABASE_DURATION: Duration = Duration::from_micros(1);
const LEASE_PUBLICATION_MARGIN: Duration = Duration::from_secs(1);
const MAX_SCANNER_INTERVAL: Duration = Duration::from_mins(5);
const MAX_SCANNER_SHUTDOWN: Duration = Duration::from_mins(1);

/// Bounded local billing reconciliation and grace policy.
///
/// Provider credentials and signature secrets deliberately do not live here: an exact provider
/// adapter owns API semantics and `rsk-webhooks-inbound` owns raw-body verification.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(default, deny_unknown_fields)]
pub struct BillingConfig {
    /// Whether billing composition is selected.
    pub enabled: bool,
    /// PostgreSQL lease duration for one provider API reconciliation.
    #[serde(with = "humantime_serde")]
    pub reconciliation_lease: Duration,
    /// Maximum provider call duration; must be strictly shorter than the database lease.
    #[serde(with = "humantime_serde")]
    pub provider_timeout: Duration,
    /// Delay before a retryable provider or persistence failure is eligible again.
    #[serde(with = "humantime_serde")]
    pub retry_delay: Duration,
    /// Maximum tasks returned from one database claim.
    pub claim_batch: u16,
    /// Maximum reconciliation attempts before durable dead-letter state.
    pub max_attempts: u16,
    /// Interval between mandatory durable reconciliation and usage recovery scans.
    #[serde(with = "humantime_serde")]
    pub scanner_interval: Duration,
    /// Supervisor deadline for stopping the mandatory recovery scanner.
    #[serde(with = "humantime_serde")]
    pub scanner_shutdown_timeout: Duration,
    /// Application grace following the provider adapter's exact delinquency transition.
    #[serde(with = "humantime_serde")]
    pub delinquent_grace: Duration,
}

impl Default for BillingConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            reconciliation_lease: Duration::from_secs(30),
            provider_timeout: Duration::from_secs(20),
            retry_delay: Duration::from_secs(5),
            claim_batch: 16,
            max_attempts: 10,
            scanner_interval: Duration::from_secs(5),
            scanner_shutdown_timeout: Duration::from_secs(10),
            delinquent_grace: Duration::from_hours(3 * 24),
        }
    }
}

impl BillingConfig {
    /// Validates every execution and policy bound.
    ///
    /// # Errors
    ///
    /// Returns [`BillingConfigError`] when a duration, batch, or attempt limit is unsafe.
    pub fn validate(&self) -> Result<(), BillingConfigError> {
        if self.reconciliation_lease < MIN_DATABASE_DURATION
            || self.reconciliation_lease > MAX_LEASE
        {
            return Err(BillingConfigError::Lease);
        }
        if self.retry_delay < MIN_DATABASE_DURATION || self.retry_delay > MAX_RETRY_DELAY {
            return Err(BillingConfigError::RetryDelay);
        }
        if self.provider_timeout < MIN_DATABASE_DURATION
            || self
                .provider_timeout
                .checked_add(LEASE_PUBLICATION_MARGIN)
                .is_none_or(|deadline| deadline > self.reconciliation_lease)
        {
            return Err(BillingConfigError::ProviderTimeout);
        }
        if self.claim_batch == 0 || self.claim_batch > 100 {
            return Err(BillingConfigError::ClaimBatch);
        }
        if self.max_attempts == 0 || self.max_attempts > 20 {
            return Err(BillingConfigError::Attempts);
        }
        if self.scanner_interval < MIN_DATABASE_DURATION
            || self.scanner_interval > MAX_SCANNER_INTERVAL
        {
            return Err(BillingConfigError::ScannerInterval);
        }
        if self.scanner_shutdown_timeout < MIN_DATABASE_DURATION
            || self.scanner_shutdown_timeout > MAX_SCANNER_SHUTDOWN
        {
            return Err(BillingConfigError::ScannerShutdown);
        }
        if self.delinquent_grace > MAX_GRACE
            || (!self.delinquent_grace.is_zero() && self.delinquent_grace < MIN_DATABASE_DURATION)
        {
            return Err(BillingConfigError::Grace);
        }
        Ok(())
    }
}

/// Billing reconciliation policy is outside its fixed safety bounds.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum BillingConfigError {
    /// Lease duration is below PostgreSQL microsecond precision or greater than five minutes.
    #[error("billing reconciliation lease is invalid")]
    Lease,
    /// Retry delay is below PostgreSQL microsecond precision or greater than one hour.
    #[error("billing retry delay is invalid")]
    RetryDelay,
    /// Provider timeout is below PostgreSQL precision or leaves less than one second in the lease.
    #[error("billing provider timeout is invalid")]
    ProviderTimeout,
    /// Claim batch is outside 1 through 100.
    #[error("billing claim batch is invalid")]
    ClaimBatch,
    /// Attempt limit is outside 1 through 20.
    #[error("billing attempt limit is invalid")]
    Attempts,
    /// Scanner interval is zero, below database precision, or greater than five minutes.
    #[error("billing scanner interval is invalid")]
    ScannerInterval,
    /// Scanner shutdown timeout is zero, below database precision, or greater than one minute.
    #[error("billing scanner shutdown timeout is invalid")]
    ScannerShutdown,
    /// Grace period is greater than 30 days.
    #[error("billing grace period is invalid")]
    Grace,
}

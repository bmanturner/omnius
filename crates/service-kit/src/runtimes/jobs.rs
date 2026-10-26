//! Application-owned job, inbox, outbox, and scheduler runtime wrappers.

#[cfg(any(feature = "inbox", test))]
use crate::ports::InboxConsumersPort;
#[cfg(any(feature = "outbox", test))]
use crate::ports::OutboxPublisherPort;
#[cfg(any(feature = "scheduler", test))]
use crate::ports::SchedulerEnvelopeFactoryPort;
use std::error::Error;
use std::fmt;

/// Failure to construct a bounded concrete job-handler registry.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum JobsRuntimeError {
    /// The registry reached its fixed handler cardinality.
    CapacityExceeded,
    /// A handler with the same stable name and version was already registered.
    DuplicateHandler {
        /// Stable job name.
        job_name: &'static str,
        /// Exact wire version.
        version: u16,
    },
}

impl fmt::Display for JobsRuntimeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::CapacityExceeded => formatter.write_str("job handler registry capacity exceeded"),
            Self::DuplicateHandler { job_name, version } => {
                write!(
                    formatter,
                    "duplicate job handler `{job_name}` version {version}"
                )
            }
        }
    }
}

impl Error for JobsRuntimeError {}

/// Application-owned bounded registry of concrete job handlers.
#[derive(Default)]
#[cfg(any(feature = "jobs-core", test))]
pub struct JobsRuntime {
    pub(crate) handlers: std::collections::BTreeMap<
        &'static str,
        std::collections::BTreeMap<u16, std::sync::Arc<dyn omnius_jobs_core::JobHandler>>,
    >,
    pub(crate) handler_count: usize,
}

#[cfg(any(feature = "jobs-core", test))]
impl JobsRuntime {
    /// Maximum number of concrete handlers in one service.
    pub const MAX_HANDLERS: usize = 128;

    /// Adds one concrete handler after validating capacity and identity uniqueness.
    ///
    /// # Errors
    ///
    /// Returns [`JobsRuntimeError`] when the registry is full or already owns
    /// the handler's `(job_name, version)` identity.
    pub fn with_handler(
        mut self,
        handler: std::sync::Arc<dyn omnius_jobs_core::JobHandler>,
    ) -> Result<Self, JobsRuntimeError> {
        if self.handler_count == Self::MAX_HANDLERS {
            return Err(JobsRuntimeError::CapacityExceeded);
        }
        let job_name = handler.job_name();
        let version = handler.job_version();
        let versions = self.handlers.entry(job_name).or_default();
        if versions.contains_key(&version) {
            return Err(JobsRuntimeError::DuplicateHandler { job_name, version });
        }
        versions.insert(version, handler);
        self.handler_count += 1;
        Ok(self)
    }

    /// Registers the real typed email adapter owned by authenticated HTTP.
    ///
    /// # Errors
    ///
    /// Returns [`JobsRuntimeError`] when the bounded registry is full or already contains
    /// the email handler identity.
    #[cfg(feature = "auth-http")]
    pub fn with_authenticated_email(
        self,
        runtime: &omnius_auth_http::AuthenticatedHttpRuntime,
    ) -> Result<Self, JobsRuntimeError> {
        self.with_handler(runtime.email_job_handler())
    }

    /// Returns the concrete handler for an exact stable identity.
    #[must_use]
    pub fn handler(
        &self,
        job_name: &str,
        version: u16,
    ) -> Option<std::sync::Arc<dyn omnius_jobs_core::JobHandler>> {
        self.handlers
            .get(job_name)
            .and_then(|versions| versions.get(&version))
            .map(std::sync::Arc::clone)
    }

    /// Dispatches an encoded envelope to its exact registered handler.
    pub async fn dispatch(
        &self,
        envelope: omnius_jobs_core::EncodedJobEnvelope,
        context: omnius_jobs_core::DeliveryContext,
    ) -> Option<omnius_jobs_core::HandlerOutcome> {
        let handler = self.handler(envelope.job_name().as_str(), envelope.version().get())?;
        Some(handler.handle(envelope, context).await)
    }

    #[must_use]
    pub(crate) fn is_empty(&self) -> bool {
        self.handler_count == 0
    }
}

/// Application-owned durable inbox contract.
#[derive(Default)]
#[cfg(any(feature = "inbox", test))]
pub struct InboxRuntime {
    pub(crate) consumers: Option<std::sync::Arc<dyn InboxConsumersPort>>,
}

#[cfg(any(feature = "inbox", test))]
impl InboxRuntime {
    port_setter!(with_consumers, consumers, dyn InboxConsumersPort);
}

/// Application-owned outbox contract.
#[derive(Default)]
#[cfg(any(feature = "outbox", test))]
pub struct OutboxRuntime {
    pub(crate) publisher: Option<std::sync::Arc<dyn OutboxPublisherPort>>,
}

#[cfg(any(feature = "outbox", test))]
impl OutboxRuntime {
    port_setter!(with_publisher, publisher, dyn OutboxPublisherPort);
}

/// Application-owned scheduler contract.
#[derive(Default)]
#[cfg(any(feature = "scheduler", test))]
pub struct SchedulerRuntime {
    pub(crate) envelope_factory: Option<std::sync::Arc<dyn SchedulerEnvelopeFactoryPort>>,
}

#[cfg(any(feature = "scheduler", test))]
impl SchedulerRuntime {
    port_setter!(
        with_envelope_factory,
        envelope_factory,
        dyn SchedulerEnvelopeFactoryPort
    );
}

/// Connected Redis/Apalis worker outputs.
#[cfg(feature = "jobs-apalis-redis")]
pub struct JobsApalisRedisRuntime {
    pub(crate) readiness: omnius_health::HealthCheckSpec,
    pub(crate) worker: omnius_runtime::TaskSpec,
}

#[cfg(feature = "jobs-apalis-redis")]
impl JobsApalisRedisRuntime {
    /// Creates provider outputs after a typed handler is bound.
    #[must_use]
    pub fn new(
        readiness: omnius_health::HealthCheckSpec,
        worker: omnius_runtime::TaskSpec,
    ) -> Self {
        Self { readiness, worker }
    }
}

/// Verified PGMQ worker outputs.
#[cfg(feature = "jobs-pgmq")]
pub struct JobsPgmqRuntime {
    pub(crate) readiness: omnius_health::HealthCheckSpec,
    pub(crate) worker: omnius_runtime::TaskSpec,
}

#[cfg(feature = "jobs-pgmq")]
impl JobsPgmqRuntime {
    /// Creates provider outputs after a typed handler is bound.
    #[must_use]
    pub fn new(
        readiness: omnius_health::HealthCheckSpec,
        worker: omnius_runtime::TaskSpec,
    ) -> Self {
        Self { readiness, worker }
    }
}

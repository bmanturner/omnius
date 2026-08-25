use std::{collections::HashMap, fmt, sync::Arc, time::Duration};

use futures::{StreamExt as _, TryStreamExt as _, future::BoxFuture, stream};
use metrics::counter;
use rsk_core::{ErrorCode, InvalidErrorCode, ServiceError};
use rsk_runtime::{Criticality, RestartPolicy, TaskSpec};
use thiserror::Error;
use tokio::time;
use tokio_util::sync::CancellationToken;

use crate::{
    ClaimedReceipt, FailureClass, PostgresReceiptStore, ProcessorConfig, ProviderId,
    ReceiptStoreError, WebhookConfigError,
};
const MAX_HANDLER_ROUTES: usize = 1_024;

/// Idempotent asynchronous domain handler for a verified durable receipt.
///
/// Implementations may be invoked again after cancellation, timeout, process crash, or lease loss.
/// Every external effect must therefore use [`ClaimedReceipt::id`] as its idempotency fence. A
/// successful return means all intended effects are durably complete.
pub trait WebhookHandler: Send + Sync + 'static {
    /// Handles one live receipt lease cooperatively with cancellation.
    ///
    /// # Errors
    ///
    /// Returns a bounded [`HandlerError`] selecting retry or terminal dead-letter behavior.
    fn handle<'a>(
        &'a self,
        receipt: &'a ClaimedReceipt,
        cancellation: &'a CancellationToken,
    ) -> BoxFuture<'a, Result<(), HandlerError>>;
}

/// Safe handler outcome controlling retry or terminal dead-letter behavior.
#[derive(Clone, Eq, Error, PartialEq)]
pub enum HandlerError {
    /// A bounded transient failure eligible for retry.
    #[error("webhook handler failed transiently")]
    Retryable(FailureClass),
    /// A bounded permanent failure requiring dead-lettering.
    #[error("webhook handler failed permanently")]
    Permanent(FailureClass),
}

impl fmt::Debug for HandlerError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Retryable(class) => formatter.debug_tuple("Retryable").field(class).finish(),
            Self::Permanent(class) => formatter.debug_tuple("Permanent").field(class).finish(),
        }
    }
}

/// Exact provider event version owned by one handler.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct HandlerRoute {
    provider: ProviderId,
    event_type: String,
    event_version: u16,
}

impl HandlerRoute {
    /// Creates a bounded exact dispatch route.
    ///
    /// # Errors
    ///
    /// Returns [`HandlerRegistryError::InvalidRoute`] for malformed type or zero version.
    pub fn new(
        provider: ProviderId,
        event_type: impl Into<String>,
        event_version: u16,
    ) -> Result<Self, HandlerRegistryError> {
        let event_type = event_type.into();
        let mut bytes = event_type.bytes();
        let valid = event_type.len() <= 128
            && bytes.next().is_some_and(|byte| byte.is_ascii_lowercase())
            && bytes.all(|byte| {
                byte.is_ascii_lowercase()
                    || byte.is_ascii_digit()
                    || matches!(byte, b'.' | b'_' | b'-')
            });
        if !valid || event_version == 0 {
            return Err(HandlerRegistryError::InvalidRoute);
        }
        Ok(Self {
            provider,
            event_type,
            event_version,
        })
    }
}

type VersionHandlers = HashMap<u16, Arc<dyn WebhookHandler>>;
type EventHandlers = HashMap<String, VersionHandlers>;
type ProviderHandlers = HashMap<ProviderId, EventHandlers>;

/// Immutable exact-version handler registry.
#[derive(Clone, Default)]
pub struct HandlerRegistry {
    handlers: Arc<ProviderHandlers>,
    route_count: usize,
}

impl HandlerRegistry {
    /// Builds a registry and rejects duplicate exact routes.
    ///
    /// # Errors
    ///
    /// Returns [`HandlerRegistryError`] when the route set is oversized or duplicated.
    pub fn new(
        handlers: impl IntoIterator<Item = (HandlerRoute, Arc<dyn WebhookHandler>)>,
    ) -> Result<Self, HandlerRegistryError> {
        let mut registered: ProviderHandlers = HashMap::new();
        for (index, (route, handler)) in handlers.into_iter().enumerate() {
            if index >= MAX_HANDLER_ROUTES {
                return Err(HandlerRegistryError::TooManyRoutes);
            }
            let versions = registered
                .entry(route.provider)
                .or_default()
                .entry(route.event_type)
                .or_default();
            if versions.insert(route.event_version, handler).is_some() {
                return Err(HandlerRegistryError::DuplicateRoute);
            }
        }
        let route_count = registered
            .values()
            .flat_map(|events| events.values())
            .map(HashMap::len)
            .sum();
        Ok(Self {
            handlers: Arc::new(registered),
            route_count,
        })
    }

    /// Returns the number of exact provider/type/version routes.
    #[must_use]
    pub const fn route_count(&self) -> usize {
        self.route_count
    }

    /// Returns whether no domain handler can own a verified receipt.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.route_count == 0
    }
}

impl fmt::Debug for HandlerRegistry {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let handler_count = self.route_count();
        formatter
            .debug_struct("HandlerRegistry")
            .field("handler_count", &handler_count)
            .finish()
    }
}

impl WebhookHandler for HandlerRegistry {
    fn handle<'a>(
        &'a self,
        receipt: &'a ClaimedReceipt,
        cancellation: &'a CancellationToken,
    ) -> BoxFuture<'a, Result<(), HandlerError>> {
        if let Some(handler) = self
            .handlers
            .get(receipt.provider())
            .and_then(|events| events.get(receipt.event_type()))
            .and_then(|versions| versions.get(&receipt.event_version()))
        {
            handler.handle(receipt, cancellation)
        } else {
            Box::pin(async { Err(HandlerError::Permanent(FailureClass::unsupported_event())) })
        }
    }
}

/// Handler registry construction failed.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum HandlerRegistryError {
    /// The route set exceeds the fixed dispatch bound.
    #[error("webhook handler registry is too large")]
    TooManyRoutes,
    /// A route event type or version is invalid.
    #[error("webhook handler route is invalid")]
    InvalidRoute,
    /// Two handlers own the same provider/type/version route.
    #[error("webhook handler route is duplicated")]
    DuplicateRoute,
}

/// Bounded polling processor for durable webhook receipt leases.
#[derive(Clone)]
pub struct WebhookProcessor {
    store: PostgresReceiptStore,
    handler: Arc<dyn WebhookHandler>,
    config: ProcessorConfig,
}

impl WebhookProcessor {
    /// Creates a processor after revalidating all processing bounds.
    ///
    /// # Errors
    ///
    /// Returns [`WebhookConfigError`] when a processing bound is invalid.
    pub fn new(
        store: PostgresReceiptStore,
        handler: Arc<dyn WebhookHandler>,
        config: ProcessorConfig,
    ) -> Result<Self, WebhookConfigError> {
        config.validate()?;
        Ok(Self {
            store,
            handler,
            config,
        })
    }

    /// Runs recovery, ready claims, fenced handling, and retention until cancellation.
    ///
    /// # Errors
    ///
    /// Returns [`ProcessorError::Store`] when durable state cannot be read or fenced.
    pub async fn run(&self, cancellation: &CancellationToken) -> Result<(), ProcessorError> {
        loop {
            if cancellation.is_cancelled() {
                return Ok(());
            }
            match self.process_once(cancellation).await {
                Err(ProcessorError::Cancelled) => return Ok(()),
                Err(error) => return Err(error),
                Ok(()) => {}
            }
            tokio::select! {
                () = cancellation.cancelled() => return Ok(()),
                () = time::sleep(self.config.poll_interval) => {}
            }
        }
    }

    /// Executes one bounded recovery, claim, handler, and cleanup cycle.
    ///
    /// # Errors
    ///
    /// Returns [`ProcessorError::Cancelled`] for cooperative cancellation or
    /// [`ProcessorError::Store`] for durable state failures.
    pub async fn process_once(
        &self,
        cancellation: &CancellationToken,
    ) -> Result<(), ProcessorError> {
        if cancellation.is_cancelled() {
            return Err(ProcessorError::Cancelled);
        }
        let capped = self
            .store
            .dead_letter_pending_over_attempt_cap(self.config.batch_size, self.config.max_attempts)
            .await?;
        if capped != 0 {
            counter!(
                "rsk_webhooks_inbound_processor_total",
                "outcome" => "attempt_cap_dead_letter"
            )
            .increment(capped);
        }
        let recovered = self
            .store
            .recover_expired(self.config.batch_size, self.config.max_attempts)
            .await?;
        if recovered != 0 {
            counter!("rsk_webhooks_inbound_processor_total", "outcome" => "recovered")
                .increment(recovered);
        }
        let receipts = self
            .store
            .claim_ready(
                self.config.batch_size,
                self.config.max_attempts,
                self.config.lease_duration,
            )
            .await?;
        let processor = self;
        stream::iter(receipts)
            .map(move |receipt| async move {
                if cancellation.is_cancelled() {
                    return Err(ProcessorError::Cancelled);
                }
                processor.process_receipt(&receipt, cancellation).await
            })
            .buffer_unordered(usize::from(self.config.batch_size))
            .try_collect::<Vec<()>>()
            .await?;
        let removed = self
            .store
            .cleanup_retained(self.config.cleanup_batch_size)
            .await?;
        if removed != 0 {
            counter!("rsk_webhooks_inbound_processor_total", "outcome" => "retained_removed")
                .increment(removed);
        }
        Ok(())
    }

    async fn process_receipt(
        &self,
        receipt: &ClaimedReceipt,
        cancellation: &CancellationToken,
    ) -> Result<(), ProcessorError> {
        let handler_cancellation = cancellation.child_token();
        let execution = self.handler.handle(receipt, &handler_cancellation);
        tokio::pin!(execution);
        let outcome = tokio::select! {
            biased;
            () = cancellation.cancelled() => {
                handler_cancellation.cancel();
                return Err(ProcessorError::Cancelled);
            }
            outcome = time::timeout(self.config.handler_timeout, &mut execution) => outcome,
        };
        match outcome {
            Ok(Ok(())) => {
                Self::settle(
                    self.store.complete(receipt).await,
                    receipt.provider().as_str(),
                    "processed",
                )?;
            }
            Ok(Err(HandlerError::Permanent(class))) => {
                Self::settle(
                    self.store.dead_letter(receipt, &class).await,
                    receipt.provider().as_str(),
                    "dead_letter",
                )?;
            }
            Ok(Err(HandlerError::Retryable(class))) => {
                self.retry_or_dead_letter(receipt, &class).await?;
            }
            Err(_) => {
                handler_cancellation.cancel();
                self.retry_or_dead_letter(receipt, &FailureClass::handler_timeout())
                    .await?;
            }
        }
        Ok(())
    }

    async fn retry_or_dead_letter(
        &self,
        receipt: &ClaimedReceipt,
        class: &FailureClass,
    ) -> Result<(), ProcessorError> {
        if receipt.attempt_count() >= self.config.max_attempts {
            Self::settle(
                self.store.dead_letter(receipt, class).await,
                receipt.provider().as_str(),
                "dead_letter",
            )
        } else {
            Self::settle(
                self.store
                    .retry(receipt, class, self.retry_delay(receipt.attempt_count()))
                    .await,
                receipt.provider().as_str(),
                "retry",
            )
        }
    }

    fn settle(
        result: Result<(), ReceiptStoreError>,
        provider: &str,
        outcome: &'static str,
    ) -> Result<(), ProcessorError> {
        match result {
            Ok(()) => {
                record_processing(provider, outcome);
                Ok(())
            }
            Err(ReceiptStoreError::LostLease) => {
                record_processing(provider, "lost_lease");
                Ok(())
            }
            Err(error) => Err(ProcessorError::Store(error)),
        }
    }

    fn retry_delay(&self, attempt_count: u16) -> Duration {
        let exponent = u32::from(attempt_count.saturating_sub(1).min(31));
        self.config
            .retry_base_delay
            .saturating_mul(1_u32 << exponent)
            .min(self.config.retry_max_delay)
    }
}

impl fmt::Debug for WebhookProcessor {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("WebhookProcessor")
            .field("store", &"[DURABLE STORE]")
            .field("handler", &"[HANDLER]")
            .field("config", &self.config)
            .finish()
    }
}

/// Creates the degraded supervised `inbound-webhook-processor` task.
///
/// # Errors
///
/// Returns [`InvalidErrorCode`] only if the compiled static processor code is invalid.
pub fn processor_task(processor: WebhookProcessor) -> Result<TaskSpec, InvalidErrorCode> {
    let code = ErrorCode::try_new("WEBHOOK_PROCESSOR_FAILED")?;
    Ok(TaskSpec::new(
        "inbound-webhook-processor",
        "webhooks-inbound",
        Criticality::Degraded,
        processor.config.shutdown_timeout,
        move |context| {
            let processor = processor.clone();
            async move {
                let cancellation = CancellationToken::new();
                let drain_cancellation = cancellation.clone();
                let execution = processor.run(&cancellation);
                tokio::pin!(execution);
                tokio::select! {
                    result = &mut execution => result.map_err(|error| {
                        ServiceError::new(code, "inbound webhook processor failed")
                            .with_source(error)
                    }),
                    () = context.draining() => {
                        drain_cancellation.cancel();
                        execution.await.map_err(|error| {
                            ServiceError::new(code, "inbound webhook processor failed")
                                .with_source(error)
                        })
                    }
                }
            }
        },
    )
    .with_restart_policy(RestartPolicy::on_failure(
        5,
        Duration::from_secs(1),
        Duration::from_secs(30),
        20,
    )))
}

/// Safe processor failure.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum ProcessorError {
    /// Cooperative cancellation stopped claiming new work.
    #[error("webhook processor was cancelled")]
    Cancelled,
    /// Durable receipt state is unavailable or inconsistent.
    #[error("webhook processor persistence failed")]
    Store(#[from] ReceiptStoreError),
}

fn record_processing(provider: &str, outcome: &'static str) {
    counter!(
        "rsk_webhooks_inbound_processor_total",
        "provider" => provider.to_owned(),
        "outcome" => outcome
    )
    .increment(1);
}

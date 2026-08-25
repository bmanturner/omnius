use std::{
    fmt,
    fmt::Write as _,
    future::Future,
    sync::{
        Arc, RwLock,
        atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
    },
    time::{Duration, Instant},
};

use ::time::format_description::well_known::Rfc3339;
use futures::{FutureExt as _, future::BoxFuture};
use js_option::JsOption;
use metrics::{counter, gauge, histogram};
use rsk_config::SecretString;
use rsk_outbox::{
    FailureClass as OutboxFailureClass, LeasedOutboxEvent, OutboxPublisher, PublishError,
};
use serde_json::{Value, value::RawValue};
use sha2::{Digest as _, Sha256};
use svix::{
    api::{
        ApplicationCreateOptions, ApplicationIn, BackgroundTaskStatus, BulkReplayIn,
        EndpointBulkReplayOptions, EndpointCreateOptions, EndpointIn, EndpointPatch,
        EndpointRecoverOptions, EndpointReplayMissingOptions, EndpointRotateSecretOptions,
        EndpointSecretRotateIn, EndpointSendExampleOptions, EventExampleIn,
        MessageAttemptListByMsgOptions, MessageCreateOptions, MessageGetOptions, MessageIn,
        MessageStatus, RecoverIn, ReplayIn, Svix, SvixOptions,
    },
    error::Error as SdkError,
};
use tokio::{sync::Notify, time};
use tokio_util::sync::CancellationToken;

use crate::{
    ApplicationId, ApplicationRecord, ApplicationSpec, AttemptState, ConfigError, DeliveryAttempt,
    DeliveryStatus, Destination, EndpointId, EndpointRecord, EndpointSpec, EventType, FailureClass,
    IdempotencyKey, MessageId, ProviderError, ProviderFailureFacts, ProviderOperation,
    PublishReceipt, PublishRequest, ReplayAdmission, ReplayAdmissionRequest, ReplayCompletion,
    ReplayFingerprint, ReplayMode, ReplayRequest, ReplayState, ReplayTask, ReplayTaskId,
    SigningSecret, SvixConfig, SvixToken, ValueError, WebhookProvider, classify_provider_failure,
};

const MAX_SECRET_GRACE_PERIOD: Duration = Duration::from_hours(168);

#[derive(Clone)]
struct RuntimeConfig {
    application_id: ApplicationId,
    destination: Destination,
    request_timeout: Duration,
    drain_timeout: Duration,
    replay_poll_interval: Duration,
    replay_wait_timeout: Duration,
    replay_max_polls: u16,
    max_status_attempts: u16,
    max_payload_bytes: usize,
}

#[derive(Clone)]
struct OutboxFailureClasses {
    timeout: OutboxFailureClass,
    rate_limited: OutboxFailureClass,
    unavailable: OutboxFailureClass,
    server: OutboxFailureClass,
    rejected: OutboxFailureClass,
    destination: OutboxFailureClass,
}

impl OutboxFailureClasses {
    fn new() -> Result<Self, ConfigError> {
        Ok(Self {
            timeout: outbox_class("timeout")?,
            rate_limited: outbox_class("rate_limited")?,
            unavailable: outbox_class("provider_unavailable")?,
            server: outbox_class("provider_5xx")?,
            rejected: outbox_class("provider_rejected")?,
            destination: outbox_class("destination_mismatch")?,
        })
    }

    fn provider(&self, class: FailureClass) -> OutboxFailureClass {
        match class {
            FailureClass::Timeout => self.timeout.clone(),
            FailureClass::RateLimited => self.rate_limited.clone(),
            FailureClass::Unavailable
            | FailureClass::Cancelled
            | FailureClass::Draining
            | FailureClass::Capacity => self.unavailable.clone(),
            FailureClass::Server => self.server.clone(),
            FailureClass::Rejected
            | FailureClass::NotFound
            | FailureClass::Unauthorized
            | FailureClass::Conflict => self.rejected.clone(),
        }
    }
}

fn outbox_class(value: &'static str) -> Result<OutboxFailureClass, ConfigError> {
    OutboxFailureClass::try_from(value).map_err(|_| ConfigError::InvalidValue)
}

struct State {
    client: RwLock<Svix>,
    config: RuntimeConfig,
    outbox_failures: OutboxFailureClasses,
    replay_admission: Arc<dyn ReplayAdmission>,
    accepting: AtomicBool,
    in_flight: AtomicUsize,
    token_generation: AtomicU64,
    cancellation: CancellationToken,
    drained: Notify,
}

/// Production outbound-webhook provider backed by the exact Svix 1.99.1 SDK.
///
/// The SDK client is a deliberate provider edge: SDK 1.99.1 exposes no transport injection seam,
/// separate connect timeout, response-size cap, TLS-policy hook, or fail-closed proxy validation.
///
/// Replay admission and task authorization are delegated to the required durable
/// [`ReplayAdmission`] port so cross-replica exclusion, restart recovery, budgets, and cooldown are
/// enforced outside this process.
/// This adapter therefore does not pretend to use `rsk-outbound-http`. It enforces HTTPS (with an
/// explicit loopback development exception), an outer total deadline, cancellation, and
/// `num_retries = 0`; proxy configuration is absent and rejected by strict config.
#[derive(Clone)]
pub struct SvixWebhookProvider {
    state: Arc<State>,
}

impl SvixWebhookProvider {
    /// Builds the concrete SDK client with retries disabled and an explicit total timeout.
    ///
    /// The admission port is mandatory; this crate intentionally has no process-local production
    /// default.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError`] when configuration violates an adapter safety bound.
    pub fn new(
        config: &SvixConfig,
        replay_admission: Arc<dyn ReplayAdmission>,
    ) -> Result<Self, ConfigError> {
        config.validate()?;
        let client = Svix::new(
            config.token().expose().to_owned(),
            Some(SvixOptions {
                debug: false,
                server_url: config.server_url_string(),
                timeout: Some(config.request_timeout()),
                num_retries: Some(0),
                retry_schedule: None,
                proxy_address: None,
            }),
        );
        let runtime = RuntimeConfig {
            application_id: config.application_id().clone(),
            destination: config.destination().clone(),
            request_timeout: config.request_timeout(),
            drain_timeout: config.drain_timeout(),
            replay_poll_interval: config.replay_poll_interval(),
            replay_wait_timeout: config.replay_wait_timeout(),
            replay_max_polls: config.replay_max_polls(),
            max_status_attempts: config.max_status_attempts(),
            max_payload_bytes: config.max_payload_bytes(),
        };
        Ok(Self {
            state: Arc::new(State {
                client: RwLock::new(client),
                config: runtime,
                outbox_failures: OutboxFailureClasses::new()?,
                replay_admission,
                accepting: AtomicBool::new(true),
                in_flight: AtomicUsize::new(0),
                token_generation: AtomicU64::new(0),
                cancellation: CancellationToken::new(),
                drained: Notify::new(),
            }),
        })
    }

    /// Returns a new provider using the SDK's transport-reusing `with_token` operation.
    ///
    /// In-flight requests on the original provider retain their original credential. New work on
    /// the returned provider uses only the replacement credential.
    ///
    /// # Errors
    ///
    /// Returns [`ProviderError`] when the current SDK client state is unavailable.
    pub fn with_token(&self, token: &SvixToken) -> Result<Self, ProviderError> {
        let current = self.client()?;
        let client = current.with_token(token.expose().to_owned());
        let generation = self
            .state
            .token_generation
            .load(Ordering::Acquire)
            .saturating_add(1);
        Ok(Self {
            state: Arc::new(State {
                client: RwLock::new(client),
                config: self.state.config.clone(),
                outbox_failures: self.state.outbox_failures.clone(),
                replay_admission: Arc::clone(&self.state.replay_admission),
                accepting: AtomicBool::new(true),
                in_flight: AtomicUsize::new(0),
                token_generation: AtomicU64::new(generation),
                cancellation: CancellationToken::new(),
                drained: Notify::new(),
            }),
        })
    }

    /// Atomically rotates the credential used by subsequent calls while reusing SDK transport.
    ///
    /// # Errors
    ///
    /// Returns [`ProviderError`] while draining or when SDK client state is unavailable.
    pub fn rotate_token(&self, token: &SvixToken) -> Result<(), ProviderError> {
        if !self.state.accepting.load(Ordering::Acquire) {
            return Err(ProviderError::new(FailureClass::Draining));
        }
        let replacement = self.client()?.with_token(token.expose().to_owned());
        let mut client = self
            .state
            .client
            .write()
            .map_err(|_| ProviderError::new(FailureClass::Unavailable))?;
        *client = replacement;
        self.state.token_generation.fetch_add(1, Ordering::AcqRel);
        counter!(
            "rsk_webhooks_svix_token_rotations_total",
            "result" => "ok"
        )
        .increment(1);
        Ok(())
    }

    /// Returns a non-secret monotonic rotation generation for lifecycle observation and tests.
    #[must_use]
    pub fn token_generation(&self) -> u64 {
        self.state.token_generation.load(Ordering::Acquire)
    }

    /// Stops accepting work and cancels every in-flight operation.
    pub fn begin_shutdown(&self) {
        self.state.accepting.store(false, Ordering::Release);
        self.state.cancellation.cancel();
    }

    /// Cancels work and waits for all operation guards to leave within the configured deadline.
    ///
    /// # Errors
    ///
    /// Returns [`ProviderError`] when the bounded drain deadline elapses.
    pub async fn shutdown(&self) -> Result<(), ProviderError> {
        self.begin_shutdown();
        let wait = async {
            loop {
                let notified = self.state.drained.notified();
                if self.state.in_flight.load(Ordering::Acquire) == 0 {
                    return;
                }
                notified.await;
            }
        };
        time::timeout(self.state.config.drain_timeout, wait)
            .await
            .map_err(|_| ProviderError::new(FailureClass::Timeout))?;
        Ok(())
    }

    /// Polls an already-started replay task until it reaches a terminal state or a hard bound.
    ///
    /// # Errors
    ///
    /// Returns [`ProviderError`] for cancellation, provider failure, or a polling bound.
    pub async fn wait_for_replay(
        &self,
        task_id: &ReplayTaskId,
    ) -> Result<ReplayTask, ProviderError> {
        let wait = async {
            for poll in 0..self.state.config.replay_max_polls {
                let task = self
                    .replay_status(&self.state.config.application_id, task_id)
                    .await?;
                if task.state != ReplayState::Running {
                    return Ok(task);
                }
                if poll + 1 < self.state.config.replay_max_polls {
                    tokio::select! {
                        () = self.state.cancellation.cancelled() => {
                            return Err(ProviderError::new(FailureClass::Cancelled));
                        }
                        () = time::sleep(self.state.config.replay_poll_interval) => {}
                    }
                }
            }
            Err(ProviderError::new(FailureClass::Timeout))
        };
        time::timeout(self.state.config.replay_wait_timeout, wait)
            .await
            .map_err(|_| ProviderError::new(FailureClass::Timeout))?
    }

    fn ensure_application(&self, application_id: &ApplicationId) -> Result<(), ProviderError> {
        if application_id != &self.state.config.application_id {
            return Err(ProviderError::new(FailureClass::Unauthorized));
        }
        Ok(())
    }

    fn replay_admission_request(
        request: &ReplayRequest,
    ) -> Result<ReplayAdmissionRequest, ProviderError> {
        let since = format_time(request.window.since())?;
        let until = format_time(request.window.until())?;
        let fingerprint = ReplayFingerprint::new(stable_idempotency_key(
            "replay",
            &[
                request.application_id.as_str(),
                request.endpoint_id.as_str(),
                request.mode.as_str(),
                &since,
                &until,
            ],
        ))
        .map_err(|_| ProviderError::new(FailureClass::Rejected))?;
        Ok(ReplayAdmissionRequest::new(
            request.application_id.clone(),
            request.endpoint_id.clone(),
            request.mode,
            request.window,
            fingerprint,
        ))
    }

    async fn start_replay_sdk(
        &self,
        request: &ReplayRequest,
        fingerprint: &ReplayFingerprint,
    ) -> Result<ReplayTask, ProviderError> {
        let since = format_time(request.window.since())?;
        let until = Some(format_time(request.window.until())?);
        let app_id = request.application_id.as_str().to_owned();
        let endpoint_id = request.endpoint_id.as_str().to_owned();
        let key = fingerprint.as_str().to_owned();
        let client = self.client()?;
        let (id, status) = match request.mode {
            ReplayMode::Missing => {
                let input = ReplayIn { since, until };
                let output = self
                    .execute(ProviderOperation::ReplayStart, async move {
                        client
                            .endpoint()
                            .replay_missing(
                                app_id,
                                endpoint_id,
                                input,
                                Some(EndpointReplayMissingOptions {
                                    idempotency_key: Some(key),
                                }),
                            )
                            .await
                    })
                    .await?;
                (output.id, output.status)
            }
            ReplayMode::All => {
                let mut input = BulkReplayIn::new(since);
                input.until = until;
                let output = self
                    .execute(ProviderOperation::ReplayStart, async move {
                        client
                            .endpoint()
                            .bulk_replay(
                                app_id,
                                endpoint_id,
                                input,
                                Some(EndpointBulkReplayOptions {
                                    idempotency_key: Some(key),
                                }),
                            )
                            .await
                    })
                    .await?;
                (output.id, output.status)
            }
            ReplayMode::Failed => {
                let input = RecoverIn { since, until };
                let output = self
                    .execute(ProviderOperation::ReplayStart, async move {
                        client
                            .endpoint()
                            .recover(
                                app_id,
                                endpoint_id,
                                input,
                                Some(EndpointRecoverOptions {
                                    idempotency_key: Some(key),
                                }),
                            )
                            .await
                    })
                    .await?;
                (output.id, output.status)
            }
        };
        Ok(ReplayTask {
            id: replay_task_id(id)?,
            state: replay_state(status),
        })
    }

    fn client(&self) -> Result<Svix, ProviderError> {
        self.state
            .client
            .read()
            .map(|client| client.clone())
            .map_err(|_| ProviderError::new(FailureClass::Unavailable))
    }

    fn begin_operation(&self) -> Result<InFlight, ProviderError> {
        if !self.state.accepting.load(Ordering::Acquire) {
            return Err(ProviderError::new(FailureClass::Draining));
        }
        self.state.in_flight.fetch_add(1, Ordering::AcqRel);
        gauge!("rsk_webhooks_svix_in_flight", "provider" => "svix")
            .set(metric_count(self.state.in_flight.load(Ordering::Acquire)));
        if !self.state.accepting.load(Ordering::Acquire) {
            self.finish_operation();
            return Err(ProviderError::new(FailureClass::Draining));
        }
        Ok(InFlight {
            state: Arc::clone(&self.state),
        })
    }

    fn finish_operation(&self) {
        finish_operation(&self.state);
    }

    async fn execute<T, F>(
        &self,
        operation: ProviderOperation,
        future: F,
    ) -> Result<T, ProviderError>
    where
        T: Send,
        F: Future<Output = Result<T, SdkError>> + Send,
    {
        let guard = self.begin_operation()?;
        let started = Instant::now();
        let result = tokio::select! {
            () = self.state.cancellation.cancelled() => {
                Err(ProviderError::new(FailureClass::Cancelled))
            }
            result = time::timeout(self.state.config.request_timeout, future) => {
                match result {
                    Ok(Ok(value)) => Ok(value),
                    Ok(Err(error)) => Err(map_sdk_error(error)),
                    Err(_) => Err(ProviderError::new(FailureClass::Timeout)),
                }
            }
        };
        drop(guard);
        record_operation(operation, started.elapsed(), &result);
        result
    }
}

impl fmt::Debug for SvixWebhookProvider {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SvixWebhookProvider")
            .field("provider", &"svix")
            .field("accepting", &self.state.accepting.load(Ordering::Acquire))
            .field("in_flight", &self.state.in_flight.load(Ordering::Acquire))
            .field("token_generation", &self.token_generation())
            .finish()
    }
}

struct InFlight {
    state: Arc<State>,
}

impl Drop for InFlight {
    fn drop(&mut self) {
        finish_operation(&self.state);
    }
}

fn finish_operation(state: &State) {
    let previous = state.in_flight.fetch_sub(1, Ordering::AcqRel);
    gauge!("rsk_webhooks_svix_in_flight", "provider" => "svix")
        .set(metric_count(previous.saturating_sub(1)));
    if previous == 1 {
        state.drained.notify_waiters();
    }
}

fn metric_count(value: usize) -> f64 {
    f64::from(u32::try_from(value).unwrap_or(u32::MAX))
}

fn record_operation<T>(
    operation: ProviderOperation,
    elapsed: Duration,
    result: &Result<T, ProviderError>,
) {
    let result_label = result
        .as_ref()
        .map_or_else(|error| error.class().as_str(), |_| "ok");
    counter!(
        "rsk_webhooks_svix_operations_total",
        "operation" => operation.as_str(),
        "result" => result_label,
        "provider" => "svix"
    )
    .increment(1);
    histogram!(
        "rsk_webhooks_svix_operation_duration_seconds",
        "operation" => operation.as_str(),
        "provider" => "svix"
    )
    .record(elapsed.as_secs_f64());
}

fn map_sdk_error(error: SdkError) -> ProviderError {
    let facts = match error {
        SdkError::Timeout { .. } => ProviderFailureFacts::Timeout,
        SdkError::Generic(_) => ProviderFailureFacts::Transport,
        SdkError::Http(content) => ProviderFailureFacts::Http(content.status.as_u16()),
        SdkError::Validation(_) => ProviderFailureFacts::Validation,
    };
    ProviderError::new(classify_provider_failure(facts))
}

fn stable_idempotency_key(namespace: &str, components: &[&str]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(namespace.as_bytes());
    for component in components {
        hasher.update([0]);
        hasher.update(component.as_bytes());
    }
    let digest = hasher.finalize();
    let mut key = String::with_capacity(namespace.len() + 1 + digest.len() * 2);
    key.push_str(namespace);
    key.push('_');
    for byte in digest {
        let _ = write!(&mut key, "{byte:02x}");
    }
    key
}

fn application_record(
    uid: Option<&str>,
    name: &str,
    spec: &ApplicationSpec,
) -> Result<ApplicationRecord, ProviderError> {
    if uid != Some(spec.id.as_str()) || name != spec.name.as_str() {
        return Err(ProviderError::new(FailureClass::Conflict));
    }
    Ok(ApplicationRecord {
        id: spec.id.clone(),
    })
}

fn endpoint_record(id: String, disabled: Option<bool>) -> Result<EndpointRecord, ProviderError> {
    Ok(EndpointRecord {
        id: EndpointId::new(id).map_err(invalid_provider_value)?,
        enabled: !disabled.unwrap_or(false),
    })
}

fn invalid_provider_value(_: ValueError) -> ProviderError {
    ProviderError::new(FailureClass::Rejected)
}

fn message_id(id: String) -> Result<MessageId, ProviderError> {
    MessageId::new(id).map_err(invalid_provider_value)
}

fn replay_task_id(id: String) -> Result<ReplayTaskId, ProviderError> {
    ReplayTaskId::new(id).map_err(invalid_provider_value)
}

fn replay_state(status: BackgroundTaskStatus) -> ReplayState {
    match status {
        BackgroundTaskStatus::Running => ReplayState::Running,
        BackgroundTaskStatus::Finished => ReplayState::Finished,
        BackgroundTaskStatus::Failed => ReplayState::Failed,
    }
}

const fn replay_completion(state: ReplayState) -> Option<ReplayCompletion> {
    match state {
        ReplayState::Running => None,
        ReplayState::Finished => Some(ReplayCompletion::Finished),
        ReplayState::Failed => Some(ReplayCompletion::Failed),
    }
}

const fn is_definitive_replay_rejection(class: FailureClass) -> bool {
    matches!(
        class,
        FailureClass::Rejected
            | FailureClass::NotFound
            | FailureClass::Unauthorized
            | FailureClass::Draining
    )
}

fn format_time(value: ::time::OffsetDateTime) -> Result<String, ProviderError> {
    value
        .to_offset(::time::UtcOffset::UTC)
        .format(&Rfc3339)
        .map_err(|_| ProviderError::new(FailureClass::Rejected))
}

fn sdk_payload(payload: &RawValue) -> Result<Value, ProviderError> {
    // Svix 1.99.1 requires `serde_json::Value`. This crate enables `arbitrary_precision` and
    // `preserve_order`, so parsing and the SDK's serialization retain canonical number spellings
    // and member order rather than rounding through `f64` or reordering the stable envelope.
    serde_json::from_str(payload.get()).map_err(|_| ProviderError::new(FailureClass::Rejected))
}
fn sdk_endpoint_input(spec: &EndpointSpec) -> EndpointIn {
    let mut input = EndpointIn::new(spec.approved_url().as_url().as_str().to_owned());
    input.uid = Some(spec.id.as_str().to_owned());
    input.description = Some(spec.description.as_str().to_owned());
    input.filter_types = (!spec.filter_types().is_empty()).then(|| {
        spec.filter_types()
            .iter()
            .map(|event_type| event_type.as_str().to_owned())
            .collect()
    });
    input
}

fn sdk_endpoint_patch(spec: &EndpointSpec) -> EndpointPatch {
    let mut patch = EndpointPatch::new();
    patch.url = Some(spec.approved_url().as_url().as_str().to_owned());
    patch.description = Some(spec.description.as_str().to_owned());
    patch.filter_types = JsOption::from_option((!spec.filter_types().is_empty()).then(|| {
        spec.filter_types()
            .iter()
            .map(|event_type| event_type.as_str().to_owned())
            .collect()
    }));
    patch
}

impl WebhookProvider for SvixWebhookProvider {
    fn publish<'a>(
        &'a self,
        request: PublishRequest<'a>,
    ) -> BoxFuture<'a, Result<PublishReceipt, ProviderError>> {
        async move {
            self.ensure_application(request.application_id)?;
            if request.payload.get().len() > self.state.config.max_payload_bytes {
                return Err(ProviderError::new(FailureClass::Rejected));
            }
            EventType::new(request.event_type).map_err(invalid_provider_value)?;
            IdempotencyKey::new(request.event_id).map_err(invalid_provider_value)?;
            let payload = sdk_payload(request.payload)?;
            let event_id = request.event_id.to_owned();
            let event_type = request.event_type.to_owned();
            let mut message = MessageIn::new(event_type.clone(), payload);
            message.event_id = Some(event_id.clone());
            let application_id = request.application_id.as_str().to_owned();
            let lookup_application_id = application_id.clone();
            let query_event_id = event_id.clone();
            let expected_event_id = event_id.clone();
            let expected_event_type = event_type.clone();
            let client = self.client()?;
            let lookup_client = client.clone();
            let output = match self
                .execute(ProviderOperation::Publish, async move {
                    client
                        .message()
                        .create(
                            application_id,
                            message,
                            Some(MessageCreateOptions {
                                with_content: Some(false),
                                idempotency_key: Some(event_id),
                            }),
                        )
                        .await
                })
                .await
            {
                Ok(output) => output,
                Err(error) if error.class() == FailureClass::Conflict => {
                    let existing = self
                        .execute(ProviderOperation::Publish, async move {
                            lookup_client
                                .message()
                                .get(
                                    lookup_application_id,
                                    query_event_id,
                                    Some(MessageGetOptions {
                                        with_content: Some(true),
                                    }),
                                )
                                .await
                        })
                        .await?;
                    let expected_payload = sdk_payload(request.payload)?;
                    if existing.event_id.as_deref() != Some(expected_event_id.as_str())
                        || existing.event_type != expected_event_type
                        || existing.payload != expected_payload
                    {
                        return Err(error);
                    }
                    existing
                }
                Err(error) => return Err(error),
            };
            Ok(PublishReceipt {
                message_id: message_id(output.id)?,
            })
        }
        .boxed()
    }

    fn application_get_or_create<'a>(
        &'a self,
        spec: &'a ApplicationSpec,
    ) -> BoxFuture<'a, Result<ApplicationRecord, ProviderError>> {
        async move {
            self.ensure_application(&spec.id)?;
            let mut input = ApplicationIn::new(spec.name.as_str().to_owned());
            input.uid = Some(spec.id.as_str().to_owned());
            let key = stable_idempotency_key("application", &[spec.id.as_str()]);
            let client = self.client()?;
            let output = self
                .execute(ProviderOperation::ApplicationGetOrCreate, async move {
                    client
                        .application()
                        .get_or_create(
                            input,
                            Some(ApplicationCreateOptions {
                                idempotency_key: Some(key),
                            }),
                        )
                        .await
                })
                .await?;
            application_record(output.uid.as_deref(), &output.name, spec)
        }
        .boxed()
    }

    fn endpoint_create<'a>(
        &'a self,
        application_id: &'a ApplicationId,
        spec: EndpointSpec,
    ) -> BoxFuture<'a, Result<EndpointRecord, ProviderError>> {
        async move {
            self.ensure_application(application_id)?;
            let input = sdk_endpoint_input(&spec);
            let key =
                stable_idempotency_key("endpoint", &[application_id.as_str(), spec.id.as_str()]);
            let client = self.client()?;
            let output = self
                .execute(ProviderOperation::EndpointCreate, async move {
                    client
                        .endpoint()
                        .create(
                            application_id.as_str().to_owned(),
                            input,
                            Some(EndpointCreateOptions {
                                idempotency_key: Some(key),
                            }),
                        )
                        .await
                })
                .await?;
            endpoint_record(output.id, output.disabled)
        }
        .boxed()
    }

    fn endpoint_update<'a>(
        &'a self,
        application_id: &'a ApplicationId,
        spec: EndpointSpec,
    ) -> BoxFuture<'a, Result<EndpointRecord, ProviderError>> {
        async move {
            self.ensure_application(application_id)?;
            let endpoint_id = spec.id.as_str().to_owned();
            let patch = sdk_endpoint_patch(&spec);
            let client = self.client()?;
            let output = self
                .execute(ProviderOperation::EndpointUpdate, async move {
                    client
                        .endpoint()
                        .patch(application_id.as_str().to_owned(), endpoint_id, patch)
                        .await
                })
                .await?;
            endpoint_record(output.id, output.disabled)
        }
        .boxed()
    }

    fn endpoint_status<'a>(
        &'a self,
        application_id: &'a ApplicationId,
        endpoint_id: &'a EndpointId,
    ) -> BoxFuture<'a, Result<EndpointRecord, ProviderError>> {
        async move {
            self.ensure_application(application_id)?;
            let client = self.client()?;
            let output = self
                .execute(ProviderOperation::EndpointStatus, async move {
                    client
                        .endpoint()
                        .get(
                            application_id.as_str().to_owned(),
                            endpoint_id.as_str().to_owned(),
                        )
                        .await
                })
                .await?;
            endpoint_record(output.id, output.disabled)
        }
        .boxed()
    }

    fn endpoint_set_enabled<'a>(
        &'a self,
        application_id: &'a ApplicationId,
        endpoint_id: &'a EndpointId,
        enabled: bool,
    ) -> BoxFuture<'a, Result<EndpointRecord, ProviderError>> {
        async move {
            self.ensure_application(application_id)?;
            let patch = EndpointPatch {
                disabled: Some(!enabled),
                ..EndpointPatch::default()
            };
            let client = self.client()?;
            let output = self
                .execute(ProviderOperation::EndpointSetEnabled, async move {
                    client
                        .endpoint()
                        .patch(
                            application_id.as_str().to_owned(),
                            endpoint_id.as_str().to_owned(),
                            patch,
                        )
                        .await
                })
                .await?;
            endpoint_record(output.id, output.disabled)
        }
        .boxed()
    }

    fn endpoint_delete<'a>(
        &'a self,
        application_id: &'a ApplicationId,
        endpoint_id: &'a EndpointId,
    ) -> BoxFuture<'a, Result<(), ProviderError>> {
        async move {
            self.ensure_application(application_id)?;
            let client = self.client()?;
            self.execute(ProviderOperation::EndpointDelete, async move {
                client
                    .endpoint()
                    .delete(
                        application_id.as_str().to_owned(),
                        endpoint_id.as_str().to_owned(),
                    )
                    .await
            })
            .await
        }
        .boxed()
    }

    fn signing_secret<'a>(
        &'a self,
        application_id: &'a ApplicationId,
        endpoint_id: &'a EndpointId,
    ) -> BoxFuture<'a, Result<SigningSecret, ProviderError>> {
        async move {
            self.ensure_application(application_id)?;
            let client = self.client()?;
            let output = self
                .execute(ProviderOperation::SecretGet, async move {
                    client
                        .endpoint()
                        .get_secret(
                            application_id.as_str().to_owned(),
                            endpoint_id.as_str().to_owned(),
                        )
                        .await
                })
                .await?;
            SigningSecret::new(SecretString::from(output.key)).map_err(invalid_provider_value)
        }
        .boxed()
    }

    fn rotate_signing_secret<'a>(
        &'a self,
        application_id: &'a ApplicationId,
        endpoint_id: &'a EndpointId,
        grace_period: Duration,
        idempotency_key: &'a IdempotencyKey,
    ) -> BoxFuture<'a, Result<(), ProviderError>> {
        async move {
            self.ensure_application(application_id)?;
            if grace_period > MAX_SECRET_GRACE_PERIOD || grace_period.subsec_nanos() != 0 {
                return Err(ProviderError::new(FailureClass::Rejected));
            }
            let grace_period_seconds = i32::try_from(grace_period.as_secs())
                .map_err(|_| ProviderError::new(FailureClass::Rejected))?;
            let input = EndpointSecretRotateIn {
                grace_period_seconds: Some(grace_period_seconds),
                key: None,
            };
            let key = idempotency_key.as_str().to_owned();
            let client = self.client()?;
            self.execute(ProviderOperation::SecretRotate, async move {
                client
                    .endpoint()
                    .rotate_secret(
                        application_id.as_str().to_owned(),
                        endpoint_id.as_str().to_owned(),
                        input,
                        Some(EndpointRotateSecretOptions {
                            idempotency_key: Some(key),
                        }),
                    )
                    .await
            })
            .await
        }
        .boxed()
    }

    fn delivery_status<'a>(
        &'a self,
        application_id: &'a ApplicationId,
        message_id_value: &'a MessageId,
    ) -> BoxFuture<'a, Result<DeliveryStatus, ProviderError>> {
        async move {
            self.ensure_application(application_id)?;
            let limit = i32::from(self.state.config.max_status_attempts);
            let client = self.client()?;
            let output = self
                .execute(ProviderOperation::DeliveryStatus, async move {
                    client
                        .message_attempt()
                        .list_by_msg(
                            application_id.as_str().to_owned(),
                            message_id_value.as_str().to_owned(),
                            Some(MessageAttemptListByMsgOptions {
                                limit: Some(limit),
                                with_content: Some(false),
                                expanded_statuses: Some(true),
                                ..MessageAttemptListByMsgOptions::default()
                            }),
                        )
                        .await
                })
                .await?;
            let attempts = output
                .data
                .into_iter()
                .take(usize::from(self.state.config.max_status_attempts))
                .map(|attempt| DeliveryAttempt {
                    state: match attempt.status {
                        MessageStatus::Success => AttemptState::Succeeded,
                        MessageStatus::Pending => AttemptState::Pending,
                        MessageStatus::Fail => AttemptState::Failed,
                        MessageStatus::Sending => AttemptState::Sending,
                        MessageStatus::Canceled => AttemptState::Cancelled,
                    },
                    response_status: u16::try_from(attempt.response_status_code)
                        .ok()
                        .filter(|status| *status != 0),
                    response_duration_ms: u32::try_from(attempt.response_duration_ms)
                        .unwrap_or_default(),
                })
                .collect();
            Ok(DeliveryStatus::new(message_id_value.clone(), attempts))
        }
        .boxed()
    }

    fn replay_start<'a>(
        &'a self,
        request: &'a ReplayRequest,
    ) -> BoxFuture<'a, Result<ReplayTask, ProviderError>> {
        async move {
            self.ensure_application(&request.application_id)?;
            let admission_request = Self::replay_admission_request(request)?;
            let lease = self
                .state
                .replay_admission
                .reserve(&admission_request)
                .await?;
            if lease.request() != &admission_request {
                return Err(ProviderError::new(FailureClass::Rejected));
            }
            let replay_result = self
                .start_replay_sdk(request, admission_request.fingerprint())
                .await;
            match replay_result {
                Ok(task) => {
                    let binding = self
                        .state
                        .replay_admission
                        .bind_task(&lease, &task.id)
                        .await?;
                    if binding.lease() != &lease || binding.task_id() != &task.id {
                        return Err(ProviderError::new(FailureClass::Rejected));
                    }
                    if let Some(completion) = replay_completion(task.state) {
                        self.state
                            .replay_admission
                            .complete(&binding, completion)
                            .await?;
                    }
                    Ok(task)
                }
                Err(error) => {
                    if is_definitive_replay_rejection(error.class()) {
                        self.state.replay_admission.release_rejected(&lease).await?;
                    }
                    Err(error)
                }
            }
        }
        .boxed()
    }

    fn replay_status<'a>(
        &'a self,
        application_id: &'a ApplicationId,
        task_id: &'a ReplayTaskId,
    ) -> BoxFuture<'a, Result<ReplayTask, ProviderError>> {
        async move {
            self.ensure_application(application_id)?;
            let binding = self
                .state
                .replay_admission
                .authorize_task(application_id, task_id)
                .await?;
            if binding.task_id() != task_id
                || binding.lease().request().application_id() != application_id
            {
                return Err(ProviderError::new(FailureClass::Unauthorized));
            }
            let client = self.client()?;
            let output = self
                .execute(ProviderOperation::ReplayStatus, async move {
                    client
                        .background_task()
                        .get(task_id.as_str().to_owned())
                        .await
                })
                .await;
            let output = match output {
                Ok(output) => output,
                Err(error) if error.class() == FailureClass::NotFound => {
                    self.state
                        .replay_admission
                        .complete(&binding, ReplayCompletion::Missing)
                        .await?;
                    return Err(error);
                }
                Err(error) => return Err(error),
            };
            if output.id != task_id.as_str() {
                self.state
                    .replay_admission
                    .complete(&binding, ReplayCompletion::Failed)
                    .await?;
                return Err(ProviderError::new(FailureClass::Rejected));
            }
            let task = ReplayTask {
                id: task_id.clone(),
                state: replay_state(output.status),
            };
            if let Some(completion) = replay_completion(task.state) {
                self.state
                    .replay_admission
                    .complete(&binding, completion)
                    .await?;
            }
            Ok(task)
        }
        .boxed()
    }

    fn send_test_event<'a>(
        &'a self,
        application_id: &'a ApplicationId,
        endpoint_id: &'a EndpointId,
        event_type: &'a EventType,
        idempotency_key: &'a IdempotencyKey,
    ) -> BoxFuture<'a, Result<PublishReceipt, ProviderError>> {
        async move {
            self.ensure_application(application_id)?;
            let input = EventExampleIn::new(event_type.as_str().to_owned());
            let key = idempotency_key.as_str().to_owned();
            let client = self.client()?;
            let output = self
                .execute(ProviderOperation::TestEvent, async move {
                    client
                        .endpoint()
                        .send_example(
                            application_id.as_str().to_owned(),
                            endpoint_id.as_str().to_owned(),
                            input,
                            Some(EndpointSendExampleOptions {
                                idempotency_key: Some(key),
                            }),
                        )
                        .await
                })
                .await?;
            Ok(PublishReceipt {
                message_id: message_id(output.id)?,
            })
        }
        .boxed()
    }

    fn health(&self) -> BoxFuture<'_, Result<(), ProviderError>> {
        async move {
            let client = self.client()?;
            self.execute(ProviderOperation::Health, async move {
                client.health().get().await
            })
            .await
        }
        .boxed()
    }
}

trait OutboxEventView {
    fn stable_id(&self) -> String;
    fn event_type(&self) -> &str;
    fn payload(&self) -> &RawValue;
    fn destination(&self) -> &str;
}

impl OutboxEventView for LeasedOutboxEvent {
    fn stable_id(&self) -> String {
        self.id().to_string()
    }

    fn event_type(&self) -> &str {
        self.event_type()
    }

    fn payload(&self) -> &RawValue {
        self.payload_json()
    }

    fn destination(&self) -> &str {
        self.destination()
    }
}

struct MappedOutboxEvent<'a> {
    event_id: String,
    event_type: &'a str,
    payload: &'a RawValue,
}

fn map_outbox_event<'a, E: OutboxEventView>(
    event: &'a E,
    destination: &Destination,
    max_payload_bytes: usize,
) -> Result<MappedOutboxEvent<'a>, FailureClass> {
    if event.destination() != destination.as_str() {
        return Err(FailureClass::Rejected);
    }
    if event.payload().get().len() > max_payload_bytes {
        return Err(FailureClass::Rejected);
    }
    let event_id = event.stable_id();
    IdempotencyKey::new(event_id.as_str()).map_err(|_| FailureClass::Rejected)?;
    EventType::new(event.event_type()).map_err(|_| FailureClass::Rejected)?;
    Ok(MappedOutboxEvent {
        event_id,
        event_type: event.event_type(),
        payload: event.payload(),
    })
}

impl OutboxPublisher for SvixWebhookProvider {
    fn publish<'event>(
        &'event self,
        event: &'event LeasedOutboxEvent,
    ) -> BoxFuture<'event, Result<(), PublishError>> {
        async move {
            let mapped = match map_outbox_event(
                event,
                &self.state.config.destination,
                self.state.config.max_payload_bytes,
            ) {
                Ok(mapped) => mapped,
                Err(_) if event.destination() != self.state.config.destination.as_str() => {
                    return Err(PublishError::new(
                        self.state.outbox_failures.destination.clone(),
                    ));
                }
                Err(_) => {
                    return Err(PublishError::new(
                        self.state.outbox_failures.rejected.clone(),
                    ));
                }
            };
            WebhookProvider::publish(
                self,
                PublishRequest {
                    application_id: &self.state.config.application_id,
                    event_id: &mapped.event_id,
                    event_type: mapped.event_type,
                    payload: mapped.payload,
                },
            )
            .await
            .map(|_| ())
            .map_err(|error| PublishError::new(self.state.outbox_failures.provider(error.class())))
        }
        .boxed()
    }
}

#[cfg(test)]
mod tests {
    use serde_json::value::RawValue;

    use super::*;

    struct EventFixture {
        id: String,
        event_type: String,
        payload: Box<RawValue>,
        destination: String,
    }

    impl OutboxEventView for EventFixture {
        fn stable_id(&self) -> String {
            self.id.clone()
        }

        fn event_type(&self) -> &str {
            &self.event_type
        }

        fn payload(&self) -> &RawValue {
            &self.payload
        }

        fn destination(&self) -> &str {
            &self.destination
        }
    }

    #[test]
    fn outbox_mapping_preserves_payload_and_stable_identifiers()
    -> Result<(), Box<dyn std::error::Error>> {
        let payload = RawValue::from_string(
            r#"{"id":"018f0000-0000-7000-8000-000000000001","type":"account.created","data":{"order":[3,2,1]}}"#.to_owned(),
        )?;
        let fixture = EventFixture {
            id: "018f0000-0000-7000-8000-000000000001".to_owned(),
            event_type: "account.created".to_owned(),
            payload,
            destination: "svix".to_owned(),
        };
        let destination = Destination::new("svix")?;

        let mapped = map_outbox_event(&fixture, &destination, 1024).map_err(|_| ValueError)?;

        assert_eq!(mapped.event_id, fixture.id);
        assert_eq!(mapped.event_type, fixture.event_type);
        assert_eq!(mapped.payload.get(), fixture.payload.get());
        Ok(())
    }

    #[test]
    fn sdk_payload_preserves_canonical_high_precision_numbers()
    -> Result<(), Box<dyn std::error::Error>> {
        let raw = RawValue::from_string(
            r#"{"decimal":1.234567890123456789,"nested":{"value":9007199254740993}}"#.to_owned(),
        )?;
        let parsed = sdk_payload(&raw)?;
        assert_eq!(serde_json::to_string(&parsed)?, raw.get());
        Ok(())
    }

    #[test]
    fn replay_time_idempotency_components_are_normalized_to_utc()
    -> Result<(), Box<dyn std::error::Error>> {
        let instant = ::time::OffsetDateTime::from_unix_timestamp(1_700_000_000)?;
        let shifted = instant.to_offset(::time::UtcOffset::from_hms(5, 30, 0)?);
        assert_eq!(format_time(instant)?, format_time(shifted)?);
        Ok(())
    }

    #[test]
    fn application_reconciliation_rejects_changed_bound_spec()
    -> Result<(), Box<dyn std::error::Error>> {
        let spec = ApplicationSpec {
            id: ApplicationId::new("tenant_demo")?,
            name: crate::ApplicationName::new("Demo tenant")?,
        };
        let Err(error) = application_record(Some("tenant_demo"), "Changed tenant", &spec) else {
            return Err("changed application was accepted".into());
        };
        assert_eq!(error.class(), FailureClass::Conflict);
        Ok(())
    }

    #[test]
    fn provider_failure_classification_discards_sdk_values() {
        assert_eq!(
            classify_provider_failure(ProviderFailureFacts::Http(429)),
            FailureClass::RateLimited
        );
        assert_eq!(
            classify_provider_failure(ProviderFailureFacts::Http(503)),
            FailureClass::Server
        );
        assert!(!classify_provider_failure(ProviderFailureFacts::Http(422)).is_retryable());
    }

    #[test]
    fn replay_admission_releases_only_definitive_non_ambiguous_rejections() {
        assert!(is_definitive_replay_rejection(FailureClass::Rejected));
        assert!(is_definitive_replay_rejection(FailureClass::NotFound));
        assert!(is_definitive_replay_rejection(FailureClass::Unauthorized));
        assert!(is_definitive_replay_rejection(FailureClass::Draining));
        assert!(!is_definitive_replay_rejection(FailureClass::Conflict));
        assert!(!is_definitive_replay_rejection(FailureClass::RateLimited));
        assert!(!is_definitive_replay_rejection(FailureClass::Timeout));
        assert!(!is_definitive_replay_rejection(FailureClass::Server));
        assert!(!is_definitive_replay_rejection(FailureClass::Unavailable));
        assert!(!is_definitive_replay_rejection(FailureClass::Cancelled));
        assert!(!is_definitive_replay_rejection(FailureClass::Capacity));
    }
}

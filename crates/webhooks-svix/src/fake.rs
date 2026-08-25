use std::{
    collections::{BTreeMap, VecDeque},
    fmt,
    fmt::Write as _,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    time::{Duration, Instant},
};

use futures::{FutureExt as _, future::BoxFuture};
use metrics::{counter, gauge, histogram};
use rsk_config::SecretString;
use serde_json::value::RawValue;
use sha2::{Digest as _, Sha256};
use tokio::{sync::Notify, time};
use tokio_util::sync::CancellationToken;

use crate::{
    ApplicationId, ApplicationRecord, ApplicationSpec, DeliveryAttempt, DeliveryStatus, EndpointId,
    EndpointRecord, EndpointSpec, EventType, FailureClass, FakeError, IdempotencyKey, MessageId,
    ProviderError, ProviderOperation, PublishReceipt, PublishRequest, ReplayRequest, ReplayState,
    ReplayTask, ReplayTaskId, SigningSecret, WebhookProvider,
};

const MAX_FAKE_CAPACITY: usize = 4_096;
const MAX_FAKE_ATTEMPTS: usize = 100;
const MAX_FAKE_PAYLOAD_BYTES: usize = 1_048_576;

/// Strict fixed-capacity semantic fake configuration.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FakeConfig {
    capture_capacity: usize,
    resource_capacity: usize,
    failure_plan_capacity: usize,
    active_replay_capacity: usize,
    max_attempts: usize,
    max_payload_bytes: usize,
    drain_timeout: Duration,
}

impl FakeConfig {
    /// Creates bounded defaults around the supplied capture capacity.
    ///
    /// # Errors
    ///
    /// Returns [`FakeError::Capacity`] when the capture capacity is outside its hard bounds.
    pub fn new(capture_capacity: usize) -> Result<Self, FakeError> {
        let config = Self {
            capture_capacity,
            resource_capacity: capture_capacity.max(1),
            failure_plan_capacity: capture_capacity.max(1),
            active_replay_capacity: capture_capacity.max(1),
            max_attempts: 50,
            max_payload_bytes: 256 * 1024,
            drain_timeout: Duration::from_secs(2),
        };
        config.validate()?;
        Ok(config)
    }

    /// Replaces all independent capacity bounds.
    ///
    /// # Errors
    ///
    /// Returns [`FakeError::Capacity`] when any supplied bound is invalid.
    pub fn with_bounds(
        mut self,
        resource_capacity: usize,
        failure_plan_capacity: usize,
        max_attempts: usize,
        max_payload_bytes: usize,
    ) -> Result<Self, FakeError> {
        self.resource_capacity = resource_capacity;
        self.failure_plan_capacity = failure_plan_capacity;
        self.max_attempts = max_attempts;
        self.max_payload_bytes = max_payload_bytes;
        self.validate()?;
        Ok(self)
    }

    /// Replaces the maximum number of simultaneously active endpoint replays.
    ///
    /// # Errors
    ///
    /// Returns [`FakeError::Capacity`] when the capacity is zero or above its hard ceiling.
    pub fn with_active_replay_capacity(
        mut self,
        active_replay_capacity: usize,
    ) -> Result<Self, FakeError> {
        self.active_replay_capacity = active_replay_capacity;
        self.validate()?;
        Ok(self)
    }

    /// Replaces the bounded drain timeout.
    ///
    /// # Errors
    ///
    /// Returns [`FakeError::Capacity`] when the timeout is zero or exceeds its ceiling.
    pub fn with_drain_timeout(mut self, timeout: Duration) -> Result<Self, FakeError> {
        self.drain_timeout = timeout;
        self.validate()?;
        Ok(self)
    }

    fn validate(self) -> Result<(), FakeError> {
        if self.capture_capacity == 0
            || self.capture_capacity > MAX_FAKE_CAPACITY
            || self.resource_capacity == 0
            || self.resource_capacity > MAX_FAKE_CAPACITY
            || self.failure_plan_capacity == 0
            || self.failure_plan_capacity > MAX_FAKE_CAPACITY
            || self.active_replay_capacity == 0
            || self.active_replay_capacity > MAX_FAKE_CAPACITY
            || self.max_attempts == 0
            || self.max_attempts > MAX_FAKE_ATTEMPTS
            || self.max_payload_bytes == 0
            || self.max_payload_bytes > MAX_FAKE_PAYLOAD_BYTES
            || self.drain_timeout.is_zero()
            || self.drain_timeout > Duration::from_secs(30)
        {
            return Err(FakeError::Capacity);
        }
        Ok(())
    }
}

/// One deterministic fake behavior consumed by a matching operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FakeBehavior {
    /// Return the supplied safe failure class.
    Fail(FailureClass),
    /// Remain pending until adapter cancellation is requested.
    WaitForCancellation,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct FailurePlan {
    operation: ProviderOperation,
    behavior: FakeBehavior,
}

/// One bounded fake publish capture. Debug deliberately omits the body.
#[derive(Clone)]
pub struct CapturedPublish {
    application_id: ApplicationId,
    event_id: IdempotencyKey,
    event_type: EventType,
    payload: Box<RawValue>,
    receipt: PublishReceipt,
}

impl CapturedPublish {
    /// Returns the captured application mapping.
    #[must_use]
    pub const fn application_id(&self) -> &ApplicationId {
        &self.application_id
    }

    /// Returns the exact event ID and idempotency key.
    #[must_use]
    pub const fn event_id(&self) -> &IdempotencyKey {
        &self.event_id
    }

    /// Returns the stable event type.
    #[must_use]
    pub const fn event_type(&self) -> &EventType {
        &self.event_type
    }

    /// Returns the exact canonical JSON captured from the adapter boundary.
    #[must_use]
    pub fn payload_json(&self) -> &RawValue {
        &self.payload
    }

    /// Returns the deterministic fake provider receipt.
    #[must_use]
    pub const fn receipt(&self) -> &PublishReceipt {
        &self.receipt
    }
}

impl fmt::Debug for CapturedPublish {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CapturedPublish")
            .field("application_id", &self.application_id)
            .field("event_id", &self.event_id)
            .field("event_type", &self.event_type)
            .field("payload", &"[REDACTED]")
            .field("receipt", &self.receipt)
            .finish()
    }
}

struct FakeEndpoint {
    spec: EndpointSpec,
    enabled: bool,
    secret: SigningSecret,
}

#[derive(Clone)]
struct FakeMessage {
    capture: CapturedPublish,
    attempts: Vec<DeliveryAttempt>,
}

#[derive(Clone)]
struct FakeReplay {
    request: ReplayRequest,
    task: ReplayTask,
}

struct Inner {
    healthy: bool,
    applications: BTreeMap<String, ApplicationSpec>,
    endpoints: BTreeMap<(String, String), FakeEndpoint>,
    messages: BTreeMap<(String, String), FakeMessage>,
    replays: BTreeMap<String, FakeReplay>,
    captures: VecDeque<CapturedPublish>,
    failures: VecDeque<FailurePlan>,
}

struct State {
    config: FakeConfig,
    application_id: ApplicationId,
    inner: Mutex<Inner>,
    accepting: AtomicBool,
    in_flight: AtomicUsize,
    cancellation: CancellationToken,
    drained: Notify,
}

/// Fixed-capacity, deterministic semantic fake for tests and development only.
#[derive(Clone)]
pub struct FakeWebhookProvider {
    state: Arc<State>,
}

impl FakeWebhookProvider {
    /// Creates an empty healthy fake bound to one application.
    ///
    /// # Errors
    ///
    /// Returns [`FakeError`] when the fake configuration is invalid.
    pub fn new(config: FakeConfig, application_id: ApplicationId) -> Result<Self, FakeError> {
        config.validate()?;
        Ok(Self {
            state: Arc::new(State {
                config,
                application_id,
                inner: Mutex::new(Inner {
                    healthy: true,
                    applications: BTreeMap::new(),
                    endpoints: BTreeMap::new(),
                    messages: BTreeMap::new(),
                    replays: BTreeMap::new(),
                    captures: VecDeque::with_capacity(config.capture_capacity),
                    failures: VecDeque::with_capacity(config.failure_plan_capacity),
                }),
                accepting: AtomicBool::new(true),
                in_flight: AtomicUsize::new(0),
                cancellation: CancellationToken::new(),
                drained: Notify::new(),
            }),
        })
    }

    /// Queues a one-shot deterministic behavior for the matching operation.
    ///
    /// # Errors
    ///
    /// Returns [`FakeError`] when the plan queue is full or its lock is unavailable.
    pub fn plan(
        &self,
        operation: ProviderOperation,
        behavior: FakeBehavior,
    ) -> Result<(), FakeError> {
        let mut inner = self
            .state
            .inner
            .lock()
            .map_err(|_| FakeError::InvalidTransition)?;
        if inner.failures.len() >= self.state.config.failure_plan_capacity {
            return Err(FakeError::Capacity);
        }
        inner.failures.push_back(FailurePlan {
            operation,
            behavior,
        });
        Ok(())
    }

    /// Returns a bounded snapshot of captures in publication order.
    ///
    /// # Errors
    ///
    /// Returns [`FakeError`] when the bounded capture state is unavailable.
    pub fn captures(&self) -> Result<Box<[CapturedPublish]>, FakeError> {
        let inner = self
            .state
            .inner
            .lock()
            .map_err(|_| FakeError::InvalidTransition)?;
        Ok(inner.captures.iter().cloned().collect())
    }

    /// Sets the fake provider health outcome.
    ///
    /// # Errors
    ///
    /// Returns [`FakeError`] when the bounded fake state is unavailable.
    pub fn set_healthy(&self, healthy: bool) -> Result<(), FakeError> {
        let mut inner = self
            .state
            .inner
            .lock()
            .map_err(|_| FakeError::InvalidTransition)?;
        inner.healthy = healthy;
        Ok(())
    }

    /// Replaces one message's bounded attempt summaries.
    ///
    /// # Errors
    ///
    /// Returns [`FakeError`] when the message is absent, state is unavailable, or attempts exceed the cap.
    pub fn set_delivery_attempts(
        &self,
        application_id: &ApplicationId,
        message_id: &MessageId,
        attempts: Vec<DeliveryAttempt>,
    ) -> Result<(), FakeError> {
        if attempts.len() > self.state.config.max_attempts {
            return Err(FakeError::Capacity);
        }
        let mut inner = self
            .state
            .inner
            .lock()
            .map_err(|_| FakeError::InvalidTransition)?;
        let Some(message) = inner.messages.values_mut().find(|message| {
            message.capture.application_id == *application_id
                && message.capture.receipt.message_id == *message_id
        }) else {
            return Err(FakeError::NotFound);
        };
        message.attempts = attempts;
        Ok(())
    }

    /// Advances an existing replay task deterministically.
    ///
    /// # Errors
    ///
    /// Returns [`FakeError`] when the task is absent or fake state is unavailable.
    pub fn set_replay_state(
        &self,
        task_id: &ReplayTaskId,
        state: ReplayState,
    ) -> Result<(), FakeError> {
        let mut inner = self
            .state
            .inner
            .lock()
            .map_err(|_| FakeError::InvalidTransition)?;
        let Some(replay) = inner.replays.get_mut(task_id.as_str()) else {
            return Err(FakeError::NotFound);
        };
        replay.task.state = state;
        Ok(())
    }

    /// Returns the current non-secret in-flight count for deterministic lifecycle observation.
    #[must_use]
    pub fn in_flight(&self) -> usize {
        self.state.in_flight.load(Ordering::Acquire)
    }

    /// Stops accepting work and releases cancellation-blocked plans.
    pub fn begin_shutdown(&self) {
        self.state.accepting.store(false, Ordering::Release);
        self.state.cancellation.cancel();
    }

    /// Cancels and waits for every fake operation to leave its guard.
    ///
    /// # Errors
    ///
    /// Returns [`ProviderError`] when bounded drain times out.
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

    fn ensure_application(&self, application_id: &ApplicationId) -> Result<(), ProviderError> {
        if application_id != &self.state.application_id {
            return Err(ProviderError::new(FailureClass::Unauthorized));
        }
        Ok(())
    }

    fn begin_operation(&self) -> Result<FakeInFlight, ProviderError> {
        if !self.state.accepting.load(Ordering::Acquire) {
            return Err(ProviderError::new(FailureClass::Draining));
        }
        self.state.in_flight.fetch_add(1, Ordering::AcqRel);
        gauge!("rsk_webhooks_svix_in_flight", "provider" => "fake")
            .set(metric_count(self.state.in_flight.load(Ordering::Acquire)));
        if !self.state.accepting.load(Ordering::Acquire) {
            finish_operation(&self.state);
            return Err(ProviderError::new(FailureClass::Draining));
        }
        Ok(FakeInFlight {
            state: Arc::clone(&self.state),
        })
    }

    async fn run<T, F>(&self, operation: ProviderOperation, action: F) -> Result<T, ProviderError>
    where
        T: Send,
        F: FnOnce(&mut Inner) -> Result<T, ProviderError> + Send,
    {
        let guard = self.begin_operation()?;
        let started = Instant::now();
        let behavior = {
            let mut inner = self
                .state
                .inner
                .lock()
                .map_err(|_| ProviderError::new(FailureClass::Unavailable))?;
            let position = inner
                .failures
                .iter()
                .position(|plan| plan.operation == operation);
            position.and_then(|index| inner.failures.remove(index).map(|plan| plan.behavior))
        };
        let result = match behavior {
            Some(FakeBehavior::Fail(class)) => Err(ProviderError::new(class)),
            Some(FakeBehavior::WaitForCancellation) => {
                self.state.cancellation.cancelled().await;
                Err(ProviderError::new(FailureClass::Cancelled))
            }
            None => {
                let mut inner = self
                    .state
                    .inner
                    .lock()
                    .map_err(|_| ProviderError::new(FailureClass::Unavailable))?;
                action(&mut inner)
            }
        };
        drop(guard);
        let result_label = result
            .as_ref()
            .map_or_else(|error| error.class().as_str(), |_| "ok");
        counter!(
            "rsk_webhooks_svix_operations_total",
            "operation" => operation.as_str(),
            "result" => result_label,
            "provider" => "fake"
        )
        .increment(1);
        histogram!(
            "rsk_webhooks_svix_operation_duration_seconds",
            "operation" => operation.as_str(),
            "provider" => "fake"
        )
        .record(started.elapsed().as_secs_f64());
        result
    }
}

impl fmt::Debug for FakeWebhookProvider {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let counts = self.state.inner.lock().ok().map(|inner| {
            (
                inner.applications.len(),
                inner.endpoints.len(),
                inner.messages.len(),
                inner.replays.len(),
                inner.captures.len(),
                inner.failures.len(),
            )
        });
        formatter
            .debug_struct("FakeWebhookProvider")
            .field("provider", &"fake")
            .field("accepting", &self.state.accepting.load(Ordering::Acquire))
            .field("in_flight", &self.state.in_flight.load(Ordering::Acquire))
            .field("bounded_counts", &counts)
            .finish()
    }
}

struct FakeInFlight {
    state: Arc<State>,
}

impl Drop for FakeInFlight {
    fn drop(&mut self) {
        finish_operation(&self.state);
    }
}

fn finish_operation(state: &State) {
    let previous = state.in_flight.fetch_sub(1, Ordering::AcqRel);
    gauge!("rsk_webhooks_svix_in_flight", "provider" => "fake")
        .set(metric_count(previous.saturating_sub(1)));
    if previous == 1 {
        state.drained.notify_waiters();
    }
}

fn metric_count(value: usize) -> f64 {
    f64::from(u32::try_from(value).unwrap_or(u32::MAX))
}

fn ensure_capacity(current: usize, maximum: usize) -> Result<(), ProviderError> {
    if current >= maximum {
        return Err(ProviderError::new(FailureClass::Capacity));
    }
    Ok(())
}

fn deterministic_id(prefix: &str, components: &[&str]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(prefix.as_bytes());
    for component in components {
        hasher.update([0]);
        hasher.update(component.as_bytes());
    }
    let digest = hasher.finalize();
    let mut value = String::with_capacity(prefix.len() + digest.len() * 2 + 1);
    value.push_str(prefix);
    value.push('_');
    for byte in digest {
        let _ = write!(&mut value, "{byte:02x}");
    }
    value
}

impl WebhookProvider for FakeWebhookProvider {
    fn publish<'a>(
        &'a self,
        request: PublishRequest<'a>,
    ) -> BoxFuture<'a, Result<PublishReceipt, ProviderError>> {
        async move {
            self.ensure_application(request.application_id)?;
            if request.payload.get().len() > self.state.config.max_payload_bytes {
                return Err(ProviderError::new(FailureClass::Rejected));
            }
            let application_id = request.application_id.clone();
            let event_id = IdempotencyKey::new(request.event_id)
                .map_err(|_| ProviderError::new(FailureClass::Rejected))?;
            let event_type = EventType::new(request.event_type)
                .map_err(|_| ProviderError::new(FailureClass::Rejected))?;
            let payload = request.payload.to_owned();
            self.run(ProviderOperation::Publish, move |inner| {
                if !inner.applications.contains_key(application_id.as_str()) {
                    return Err(ProviderError::new(FailureClass::NotFound));
                }
                let key = (
                    application_id.as_str().to_owned(),
                    event_id.as_str().to_owned(),
                );
                if let Some(existing) = inner.messages.get(&key) {
                    if existing.capture.event_type == event_type
                        && existing.capture.payload.get() == payload.get()
                    {
                        return Ok(existing.capture.receipt.clone());
                    }
                    return Err(ProviderError::new(FailureClass::Conflict));
                }
                ensure_capacity(inner.messages.len(), self.state.config.resource_capacity)?;
                ensure_capacity(inner.captures.len(), self.state.config.capture_capacity)?;
                let message_id = MessageId::new(deterministic_id(
                    "msg",
                    &[application_id.as_str(), event_id.as_str()],
                ))
                .map_err(|_| ProviderError::new(FailureClass::Rejected))?;
                let receipt = PublishReceipt { message_id };
                let capture = CapturedPublish {
                    application_id,
                    event_id,
                    event_type,
                    payload,
                    receipt: receipt.clone(),
                };
                inner.captures.push_back(capture.clone());
                inner.messages.insert(
                    key,
                    FakeMessage {
                        capture,
                        attempts: Vec::new(),
                    },
                );
                Ok(receipt)
            })
            .await
        }
        .boxed()
    }

    fn application_get_or_create<'a>(
        &'a self,
        spec: &'a ApplicationSpec,
    ) -> BoxFuture<'a, Result<ApplicationRecord, ProviderError>> {
        let spec = spec.clone();
        async move {
            self.ensure_application(&spec.id)?;
            self.run(ProviderOperation::ApplicationGetOrCreate, move |inner| {
                if let Some(existing) = inner.applications.get(spec.id.as_str()) {
                    if existing == &spec {
                        return Ok(ApplicationRecord {
                            id: existing.id.clone(),
                        });
                    }
                    return Err(ProviderError::new(FailureClass::Conflict));
                }
                ensure_capacity(
                    inner.applications.len(),
                    self.state.config.resource_capacity,
                )?;
                let record = ApplicationRecord {
                    id: spec.id.clone(),
                };
                inner.applications.insert(spec.id.as_str().to_owned(), spec);
                Ok(record)
            })
            .await
        }
        .boxed()
    }

    fn endpoint_create<'a>(
        &'a self,
        application_id: &'a ApplicationId,
        spec: EndpointSpec,
    ) -> BoxFuture<'a, Result<EndpointRecord, ProviderError>> {
        let application_id = application_id.clone();
        async move {
            self.ensure_application(&application_id)?;
            self.run(ProviderOperation::EndpointCreate, move |inner| {
                if !inner.applications.contains_key(application_id.as_str()) {
                    return Err(ProviderError::new(FailureClass::NotFound));
                }
                let key = (
                    application_id.as_str().to_owned(),
                    spec.id.as_str().to_owned(),
                );
                if let Some(existing) = inner.endpoints.get(&key) {
                    if existing.spec.equivalent(&spec) {
                        return Ok(EndpointRecord {
                            id: existing.spec.id.clone(),
                            enabled: existing.enabled,
                        });
                    }
                    return Err(ProviderError::new(FailureClass::Conflict));
                }
                ensure_capacity(inner.endpoints.len(), self.state.config.resource_capacity)?;
                let secret = SigningSecret::new(SecretString::from(format!(
                    "whsec_fake_{}",
                    spec.id.as_str()
                )))
                .map_err(|_| ProviderError::new(FailureClass::Rejected))?;
                let record = EndpointRecord {
                    id: spec.id.clone(),
                    enabled: true,
                };
                inner.endpoints.insert(
                    key,
                    FakeEndpoint {
                        spec,
                        enabled: true,
                        secret,
                    },
                );
                Ok(record)
            })
            .await
        }
        .boxed()
    }

    fn endpoint_update<'a>(
        &'a self,
        application_id: &'a ApplicationId,
        spec: EndpointSpec,
    ) -> BoxFuture<'a, Result<EndpointRecord, ProviderError>> {
        let application_id = application_id.clone();
        async move {
            self.ensure_application(&application_id)?;
            self.run(ProviderOperation::EndpointUpdate, move |inner| {
                let key = (
                    application_id.as_str().to_owned(),
                    spec.id.as_str().to_owned(),
                );
                let Some(endpoint) = inner.endpoints.get_mut(&key) else {
                    return Err(ProviderError::new(FailureClass::NotFound));
                };
                endpoint.spec = spec;
                Ok(EndpointRecord {
                    id: endpoint.spec.id.clone(),
                    enabled: endpoint.enabled,
                })
            })
            .await
        }
        .boxed()
    }

    fn endpoint_status<'a>(
        &'a self,
        application_id: &'a ApplicationId,
        endpoint_id: &'a EndpointId,
    ) -> BoxFuture<'a, Result<EndpointRecord, ProviderError>> {
        let application_id = application_id.clone();
        let endpoint_id = endpoint_id.clone();
        async move {
            self.ensure_application(&application_id)?;
            self.run(ProviderOperation::EndpointStatus, move |inner| {
                let key = (
                    application_id.as_str().to_owned(),
                    endpoint_id.as_str().to_owned(),
                );
                let endpoint = inner
                    .endpoints
                    .get(&key)
                    .ok_or_else(|| ProviderError::new(FailureClass::NotFound))?;
                Ok(EndpointRecord {
                    id: endpoint.spec.id.clone(),
                    enabled: endpoint.enabled,
                })
            })
            .await
        }
        .boxed()
    }

    fn endpoint_set_enabled<'a>(
        &'a self,
        application_id: &'a ApplicationId,
        endpoint_id: &'a EndpointId,
        enabled: bool,
    ) -> BoxFuture<'a, Result<EndpointRecord, ProviderError>> {
        let application_id = application_id.clone();
        let endpoint_id = endpoint_id.clone();
        async move {
            self.ensure_application(&application_id)?;
            self.run(ProviderOperation::EndpointSetEnabled, move |inner| {
                let key = (
                    application_id.as_str().to_owned(),
                    endpoint_id.as_str().to_owned(),
                );
                let endpoint = inner
                    .endpoints
                    .get_mut(&key)
                    .ok_or_else(|| ProviderError::new(FailureClass::NotFound))?;
                endpoint.enabled = enabled;
                Ok(EndpointRecord {
                    id: endpoint.spec.id.clone(),
                    enabled,
                })
            })
            .await
        }
        .boxed()
    }

    fn endpoint_delete<'a>(
        &'a self,
        application_id: &'a ApplicationId,
        endpoint_id: &'a EndpointId,
    ) -> BoxFuture<'a, Result<(), ProviderError>> {
        let application_id = application_id.clone();
        let endpoint_id = endpoint_id.clone();
        async move {
            self.ensure_application(&application_id)?;
            self.run(ProviderOperation::EndpointDelete, move |inner| {
                let key = (
                    application_id.as_str().to_owned(),
                    endpoint_id.as_str().to_owned(),
                );
                inner
                    .endpoints
                    .remove(&key)
                    .map(|_| ())
                    .ok_or_else(|| ProviderError::new(FailureClass::NotFound))
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
        let application_id = application_id.clone();
        let endpoint_id = endpoint_id.clone();
        async move {
            self.ensure_application(&application_id)?;
            self.run(ProviderOperation::SecretGet, move |inner| {
                let key = (
                    application_id.as_str().to_owned(),
                    endpoint_id.as_str().to_owned(),
                );
                inner
                    .endpoints
                    .get(&key)
                    .map(|endpoint| endpoint.secret.clone())
                    .ok_or_else(|| ProviderError::new(FailureClass::NotFound))
            })
            .await
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
        let application_id = application_id.clone();
        let endpoint_id = endpoint_id.clone();
        let idempotency_key = idempotency_key.clone();
        async move {
            self.ensure_application(&application_id)?;
            if grace_period > Duration::from_hours(168) || grace_period.subsec_nanos() != 0 {
                return Err(ProviderError::new(FailureClass::Rejected));
            }
            self.run(ProviderOperation::SecretRotate, move |inner| {
                let key = (
                    application_id.as_str().to_owned(),
                    endpoint_id.as_str().to_owned(),
                );
                let endpoint = inner
                    .endpoints
                    .get_mut(&key)
                    .ok_or_else(|| ProviderError::new(FailureClass::NotFound))?;
                endpoint.secret = SigningSecret::new(SecretString::from(format!(
                    "whsec_rotated_{}_{}",
                    endpoint_id.as_str(),
                    idempotency_key.as_str()
                )))
                .map_err(|_| ProviderError::new(FailureClass::Rejected))?;
                Ok(())
            })
            .await
        }
        .boxed()
    }

    fn delivery_status<'a>(
        &'a self,
        application_id: &'a ApplicationId,
        message_id: &'a MessageId,
    ) -> BoxFuture<'a, Result<DeliveryStatus, ProviderError>> {
        let application_id = application_id.clone();
        let message_id = message_id.clone();
        async move {
            self.ensure_application(&application_id)?;
            self.run(ProviderOperation::DeliveryStatus, move |inner| {
                let message = inner
                    .messages
                    .values()
                    .find(|message| {
                        message.capture.application_id == application_id
                            && message.capture.receipt.message_id == message_id
                    })
                    .ok_or_else(|| ProviderError::new(FailureClass::NotFound))?;
                Ok(DeliveryStatus::new(message_id, message.attempts.clone()))
            })
            .await
        }
        .boxed()
    }

    fn replay_start<'a>(
        &'a self,
        request: &'a ReplayRequest,
    ) -> BoxFuture<'a, Result<ReplayTask, ProviderError>> {
        let request = request.clone();
        async move {
            self.ensure_application(&request.application_id)?;
            self.run(ProviderOperation::ReplayStart, move |inner| {
                let endpoint_key = (
                    request.application_id.as_str().to_owned(),
                    request.endpoint_id.as_str().to_owned(),
                );
                if !inner.endpoints.contains_key(&endpoint_key) {
                    return Err(ProviderError::new(FailureClass::NotFound));
                }
                if inner.replays.values().any(|replay| {
                    replay.task.state == ReplayState::Running
                        && replay.request.endpoint_id == request.endpoint_id
                }) {
                    return Err(ProviderError::new(FailureClass::Conflict));
                }
                let active_replays = inner
                    .replays
                    .values()
                    .filter(|replay| replay.task.state == ReplayState::Running)
                    .count();
                if active_replays >= self.state.config.active_replay_capacity {
                    return Err(ProviderError::new(FailureClass::Capacity));
                }
                let since = request.window.since().unix_timestamp_nanos().to_string();
                let until = request.window.until().unix_timestamp_nanos().to_string();
                let task_id = ReplayTaskId::new(deterministic_id(
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
                if let Some(existing) = inner.replays.get(task_id.as_str()) {
                    if existing.request == request {
                        return Ok(existing.task.clone());
                    }
                    return Err(ProviderError::new(FailureClass::Conflict));
                }
                ensure_capacity(inner.replays.len(), self.state.config.resource_capacity)?;
                let task = ReplayTask {
                    id: task_id.clone(),
                    state: ReplayState::Running,
                };
                inner.replays.insert(
                    task_id.as_str().to_owned(),
                    FakeReplay {
                        request,
                        task: task.clone(),
                    },
                );
                Ok(task)
            })
            .await
        }
        .boxed()
    }

    fn replay_status<'a>(
        &'a self,
        application_id: &'a ApplicationId,
        task_id: &'a ReplayTaskId,
    ) -> BoxFuture<'a, Result<ReplayTask, ProviderError>> {
        let application_id = application_id.clone();
        let task_id = task_id.clone();
        async move {
            self.ensure_application(&application_id)?;
            self.run(ProviderOperation::ReplayStatus, move |inner| {
                inner
                    .replays
                    .get(task_id.as_str())
                    .map(|replay| replay.task.clone())
                    .ok_or_else(|| ProviderError::new(FailureClass::NotFound))
            })
            .await
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
        let application_id = application_id.clone();
        let endpoint_id = endpoint_id.clone();
        let event_type = event_type.clone();
        let idempotency_key = idempotency_key.clone();
        async move {
            self.ensure_application(&application_id)?;
            self.run(ProviderOperation::TestEvent, move |inner| {
                let endpoint_key = (
                    application_id.as_str().to_owned(),
                    endpoint_id.as_str().to_owned(),
                );
                if !inner.endpoints.contains_key(&endpoint_key) {
                    return Err(ProviderError::new(FailureClass::NotFound));
                }
                let id = deterministic_id(
                    "testmsg",
                    &[
                        application_id.as_str(),
                        endpoint_id.as_str(),
                        event_type.as_str(),
                        idempotency_key.as_str(),
                    ],
                );
                Ok(PublishReceipt {
                    message_id: MessageId::new(id)
                        .map_err(|_| ProviderError::new(FailureClass::Rejected))?,
                })
            })
            .await
        }
        .boxed()
    }

    fn health(&self) -> BoxFuture<'_, Result<(), ProviderError>> {
        async move {
            self.run(ProviderOperation::Health, |inner| {
                if inner.healthy {
                    Ok(())
                } else {
                    Err(ProviderError::new(FailureClass::Unavailable))
                }
            })
            .await
        }
        .boxed()
    }
}

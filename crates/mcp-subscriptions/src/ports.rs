use std::{
    fmt,
    sync::{
        Arc,
        atomic::{AtomicU8, Ordering},
    },
};

use async_trait::async_trait;
use thiserror::Error;
use tokio::sync::Notify;
use tokio_util::sync::CancellationToken;

use crate::{
    DeliveryFrame, DrainOutcome, EventPosition, PrincipalId, SubscriptionHandle, SubscriptionId,
    SubscriptionStart, TaskCursor, TaskId, TaskSnapshot, TenantId,
};

/// Authorization operation evaluated against principal, tenant, and task.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuthorizationAction {
    /// Initial subscription admission.
    Subscribe,
    /// Re-authorization immediately before a task snapshot or gap is delivered.
    Deliver,
}

/// Complete authorization input. Routing metadata is never authority evidence.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthorizationCheck {
    /// Authenticated principal.
    pub principal_id: PrincipalId,
    /// Authoritative tenant.
    pub tenant_id: TenantId,
    /// Explicit task.
    pub task_id: TaskId,
    /// Operation being authorized.
    pub action: AuthorizationAction,
}

/// Typed task-subscription authorization port.
#[async_trait]
pub trait SubscriptionAuthorizer: Send + Sync {
    /// Returns whether this exact principal, tenant, task, and operation is permitted.
    ///
    /// # Errors
    ///
    /// Returns [`AuthorizationError`] when the policy dependency cannot make an authoritative
    /// decision.
    async fn authorize(&self, check: &AuthorizationCheck) -> Result<bool, AuthorizationError>;
}

/// Safe authorization dependency failure.
#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum AuthorizationError {
    /// The policy dependency could not make an authoritative decision.
    #[error("subscription authorization is unavailable")]
    Unavailable,
}

/// Durable subscription claim passed to the authoritative repository.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BeginSubscription {
    /// New JSON-RPC request identifier.
    pub subscription_id: SubscriptionId,
    /// Bound principal.
    pub principal_id: PrincipalId,
    /// Bound tenant.
    pub tenant_id: TenantId,
    /// Authorized task filter.
    pub task_ids: Vec<TaskId>,
    /// Absolute finite expiry.
    pub expires_at_ms: u64,
    /// Explicit initial-subscription or closed-stream replacement intent.
    pub start: SubscriptionStart,
}

/// Durable result of claiming a never-before-used subscription identifier.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BeginSubscriptionResult {
    /// Server-minted handle bound to principal, tenant, task set, and subscription.
    pub subscription_handle: SubscriptionHandle,
    /// Authoritative per-task cursors resolved from the reconnect proof.
    pub resume_cursors: Vec<TaskCursor>,
}

/// Repository replay result bounded per page by the service-requested limit.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ReplayResult {
    /// Strictly ordered authoritative snapshots after the requested cursor.
    Events {
        /// One bounded replay page.
        snapshots: Vec<TaskSnapshot>,
        /// Whether another page exists after the final returned position.
        has_more: bool,
    },
    /// Requested cursor fell before the retained replay window.
    Gap(ReplayWindow),
}

/// Retained repository replay window for one task.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReplayWindow {
    /// Oldest retained event.
    pub oldest_available: EventPosition,
    /// Newest retained event.
    pub newest_available: EventPosition,
}

/// Durable delivery checkpoint.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SubscriptionCheckpoint {
    /// Durable subscription handle.
    pub subscription_handle: SubscriptionHandle,
    /// Last delivered position for the task.
    pub cursor: TaskCursor,
}

/// Durable close update.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FinishSubscription {
    /// Durable subscription handle.
    pub subscription_handle: SubscriptionHandle,
    /// Last accepted cursors.
    pub cursors: Vec<TaskCursor>,
    /// Close timestamp.
    pub closed_at_ms: u64,
}

/// Typed authoritative persistence port for subscription claims and task event history.
#[async_trait]
pub trait SubscriptionRepository: Send + Sync {
    /// Atomically claims a fresh request ID and enforces initial-versus-replacement semantics.
    ///
    /// An `Initial` claim must not replace a previously closed claim for the exact principal,
    /// tenant, and task set. A `Replacement` must match a closed claim and validate either the
    /// original idempotency key or every supplied task handle against that exact scope. Failed
    /// claims must not consume the fresh request ID.
    ///
    /// # Errors
    ///
    /// Returns [`RepositoryError`] when persistence is unavailable, the request identifier was
    /// already used, reconnect proof is invalid, or stored state is inconsistent.
    async fn begin(
        &self,
        begin: &BeginSubscription,
    ) -> Result<BeginSubscriptionResult, RepositoryError>;

    /// Loads the current complete authoritative snapshot for an exact tenant and task.
    ///
    /// # Errors
    ///
    /// Returns [`RepositoryError`] when persistence is unavailable or stored state is
    /// inconsistent.
    async fn current_snapshot(
        &self,
        tenant_id: &TenantId,
        task_id: &TaskId,
    ) -> Result<Option<TaskSnapshot>, RepositoryError>;

    /// Loads at most `limit` ordered authoritative snapshots after a cursor.
    ///
    /// # Errors
    ///
    /// Returns [`RepositoryError`] when persistence is unavailable or stored replay state is
    /// inconsistent.
    async fn replay_after(
        &self,
        tenant_id: &TenantId,
        task_id: &TaskId,
        after: EventPosition,
        limit: usize,
    ) -> Result<ReplayResult, RepositoryError>;

    /// Advances a durable subscription checkpoint monotonically.
    ///
    /// # Errors
    ///
    /// Returns [`RepositoryError`] when persistence is unavailable or the checkpoint conflicts
    /// with stored state.
    async fn checkpoint(&self, checkpoint: &SubscriptionCheckpoint) -> Result<(), RepositoryError>;

    /// Records final cursors for the durable subscription claim.
    ///
    /// # Errors
    ///
    /// Returns [`RepositoryError`] when persistence is unavailable or the final cursors conflict
    /// with stored state.
    async fn finish(&self, finish: &FinishSubscription) -> Result<(), RepositoryError>;
}

/// Safe authoritative-repository failure.
#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum RepositoryError {
    /// Repository is unavailable.
    #[error("subscription repository is unavailable")]
    Unavailable,
    /// A JSON-RPC subscription request identifier was already used.
    #[error("subscription identifier was already used")]
    IdentifierReused,
    /// Explicit reconnect proof was invalid or belonged to a different scope.
    #[error("reconnect proof is invalid")]
    InvalidReconnect,
    /// Repository returned inconsistent authoritative state.
    #[error("subscription repository state is inconsistent")]
    Inconsistent,
}

/// Synchronous signal raised when the sole response-stream receiver is dropped.
///
/// Clones observe the same cancellation edge. The runtime supervisor must convert it into a call
/// to [`crate::TaskSubscriptionService::disconnect`] so durable finish and lifecycle disarm happen
/// without waiting for another task event.
#[derive(Clone)]
pub struct DeliveryDisconnectSignal {
    cancellation: CancellationToken,
}

impl DeliveryDisconnectSignal {
    /// Creates one shared response-disconnect edge.
    #[must_use]
    pub fn new() -> Self {
        Self {
            cancellation: CancellationToken::new(),
        }
    }

    /// Raises the edge synchronously from a response-stream `Drop` implementation.
    pub fn notify_disconnect(&self) {
        self.cancellation.cancel();
    }

    /// Waits until the response transport drops its sole receiver.
    pub async fn cancelled(&self) {
        self.cancellation.cancelled().await;
    }

    /// Returns whether the response transport has already disconnected.
    #[must_use]
    pub fn is_cancelled(&self) -> bool {
        self.cancellation.is_cancelled()
    }
}

impl Default for DeliveryDisconnectSignal {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for DeliveryDisconnectSignal {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DeliveryDisconnectSignal")
            .field("cancelled", &self.is_cancelled())
            .finish()
    }
}
const ATTACHMENT_PENDING: u8 = 0;
const ATTACHMENT_ATTACHED: u8 = 1;
const ATTACHMENT_READY: u8 = 2;
const ATTACHMENT_CLOSED: u8 = 3;

/// Observable state of the sole response transport initialization edge.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DeliveryAttachmentState {
    /// Delivery is open, but no response transport has attached yet.
    Pending,
    /// The sole response transport attached but has not consumed the acknowledgement.
    Attached,
    /// The transport consumed the mandatory acknowledgement and can receive initialization frames.
    Ready,
    /// Delivery closed before or after attachment.
    Closed,
}

#[derive(Debug)]
struct DeliveryAttachmentInner {
    state: AtomicU8,
    changed: Notify,
}

/// Shared typed edge that prevents initialization from racing response-stream attachment.
#[derive(Clone, Debug)]
pub struct DeliveryAttachmentSignal {
    inner: Arc<DeliveryAttachmentInner>,
}

impl DeliveryAttachmentSignal {
    /// Creates an unattached delivery edge.
    #[must_use]
    pub fn pending() -> Self {
        Self {
            inner: Arc::new(DeliveryAttachmentInner {
                state: AtomicU8::new(ATTACHMENT_PENDING),
                changed: Notify::new(),
            }),
        }
    }

    /// Creates an explicitly ready edge for synchronous test adapters.
    #[must_use]
    pub fn attached() -> Self {
        Self {
            inner: Arc::new(DeliveryAttachmentInner {
                state: AtomicU8::new(ATTACHMENT_READY),
                changed: Notify::new(),
            }),
        }
    }

    /// Reports that the sole response transport attached.
    ///
    /// Returns `false` if delivery had already attached or closed.
    #[must_use]
    pub fn notify_attached(&self) -> bool {
        let attached = self
            .inner
            .state
            .compare_exchange(
                ATTACHMENT_PENDING,
                ATTACHMENT_ATTACHED,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_ok();
        if attached {
            self.inner.changed.notify_waiters();
        }
        attached
    }

    /// Reports that the attached transport consumed the mandatory acknowledgement.
    ///
    /// Returns `false` if the acknowledgement was already consumed or delivery closed.
    #[must_use]
    pub fn notify_ready(&self) -> bool {
        let ready = self
            .inner
            .state
            .compare_exchange(
                ATTACHMENT_ATTACHED,
                ATTACHMENT_READY,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_ok();
        if ready {
            self.inner.changed.notify_waiters();
        }
        ready
    }

    /// Reports that delivery closed and wakes pending initialization.
    pub fn notify_closed(&self) {
        self.inner.state.store(ATTACHMENT_CLOSED, Ordering::Release);
        self.inner.changed.notify_waiters();
    }

    /// Returns the current typed transport initialization state.
    #[must_use]
    pub fn state(&self) -> DeliveryAttachmentState {
        match self.inner.state.load(Ordering::Acquire) {
            ATTACHMENT_PENDING => DeliveryAttachmentState::Pending,
            ATTACHMENT_ATTACHED => DeliveryAttachmentState::Attached,
            ATTACHMENT_READY => DeliveryAttachmentState::Ready,
            _ => DeliveryAttachmentState::Closed,
        }
    }

    /// Waits until the transport consumes the acknowledgement or delivery closes.
    pub async fn wait(&self) -> DeliveryAttachmentState {
        loop {
            let notified = self.inner.changed.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            let state = self.state();
            if matches!(
                state,
                DeliveryAttachmentState::Ready | DeliveryAttachmentState::Closed
            ) {
                return state;
            }
            notified.await;
        }
    }
}

/// Signals returned after opening a bounded delivery stream.
#[derive(Clone, Debug)]
pub struct DeliveryOpen {
    /// Response-stream drop edge used by the runtime supervisor.
    pub disconnect: DeliveryDisconnectSignal,
    /// Typed response-transport attachment edge.
    pub attachment: DeliveryAttachmentSignal,
}

impl DeliveryOpen {
    /// Creates signals for a synchronous adapter that is already attached.
    #[must_use]
    pub fn attached(disconnect: DeliveryDisconnectSignal) -> Self {
        Self {
            disconnect,
            attachment: DeliveryAttachmentSignal::attached(),
        }
    }
}

/// Finite lifecycle registration delegated to the runtime supervisor.
#[derive(Clone, Debug)]
pub struct RuntimeLease {
    /// Subscription to expire or finish on response disconnect.
    pub subscription_id: SubscriptionId,
    /// Absolute expiry in Unix milliseconds.
    pub expires_at_ms: u64,
    /// Drop signal the supervisor converts into authoritative disconnect cleanup.
    pub disconnect: DeliveryDisconnectSignal,
}

/// Typed runtime port for expiry and disconnect scheduling and teardown.
#[async_trait]
pub trait SubscriptionRuntime: Send + Sync {
    /// Arms expiry and response-disconnect callbacks before the subscription is acknowledged.
    ///
    /// A disconnect callback invokes [`crate::TaskSubscriptionService::disconnect`]; an expiry
    /// callback invokes [`crate::TaskSubscriptionService::expire`].
    ///
    /// # Errors
    ///
    /// Returns [`RuntimeError`] when the runtime supervisor cannot establish the finite lease.
    async fn arm(&self, lease: &RuntimeLease) -> Result<(), RuntimeError>;

    /// Returns the canonical live Unix-millisecond runtime clock.
    ///
    /// # Errors
    ///
    /// Returns [`RuntimeError`] when the runtime supervisor cannot provide its authoritative
    /// clock.
    async fn now_ms(&self) -> Result<u64, RuntimeError>;

    /// Removes all lifecycle registrations after terminal teardown.
    ///
    /// # Errors
    ///
    /// Returns [`RuntimeError`] when the runtime supervisor cannot remove the lifecycle
    /// registration.
    async fn disarm(&self, subscription_id: &SubscriptionId) -> Result<(), RuntimeError>;
}

/// Safe runtime-supervisor dependency failure.
#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum RuntimeError {
    /// The supervisor could not establish or remove the finite lease.
    #[error("subscription runtime is unavailable")]
    Unavailable,
}

/// Bounds every transport delivery queue.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DeliveryLimits {
    /// Maximum queued frames.
    pub max_frames: usize,
    /// Maximum retained encoded bytes.
    pub max_bytes: usize,
}

/// Result of non-blocking bounded admission to a transport response stream.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DeliveryAdmission {
    /// Frame was admitted.
    Accepted,
    /// Frame exceeded the finite queue or byte budget.
    SlowConsumer,
    /// Response transport is no longer connected.
    Disconnected,
}

/// Queue close behavior.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DeliveryCloseMode {
    /// Retain admitted frames for at most this finite interval before emitting the close record.
    Drain {
        /// Maximum drain interval in milliseconds.
        timeout_ms: u64,
    },
    /// Drop queued frames and close immediately.
    Abort,
}

/// Transport-neutral bounded response-stream delivery port.
#[async_trait]
pub trait SubscriptionDelivery: Send + Sync {
    /// Opens exactly one bounded stream before acknowledgement and returns its lifecycle signals.
    ///
    /// Production adapters report a pending attachment and raise it only when the sole response
    /// transport attaches. A synchronous test adapter must explicitly return an attached signal.
    ///
    /// # Errors
    ///
    /// Returns [`DeliveryError`] when the limits are invalid, the identifier is already open, or
    /// the delivery adapter is unavailable.
    async fn open(
        &self,
        subscription_id: &SubscriptionId,
        limits: DeliveryLimits,
    ) -> Result<DeliveryOpen, DeliveryError>;

    /// Attempts to admit a frame without unbounded waiting.
    ///
    /// # Errors
    ///
    /// Returns [`DeliveryError`] when the stream is closed or the delivery adapter is
    /// unavailable.
    async fn deliver(
        &self,
        subscription_id: &SubscriptionId,
        frame: DeliveryFrame,
    ) -> Result<DeliveryAdmission, DeliveryError>;

    /// Applies explicit abort or finite drain semantics and emits the supplied close record.
    ///
    /// # Errors
    ///
    /// Returns [`DeliveryError`] when the stream is closed or the delivery adapter cannot apply
    /// the requested close behavior.
    async fn close(
        &self,
        subscription_id: &SubscriptionId,
        mode: DeliveryCloseMode,
        close: DeliveryFrame,
    ) -> Result<DrainOutcome, DeliveryError>;
}

/// Safe transport delivery failure.
#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum DeliveryError {
    /// A stream already exists for the request identifier.
    #[error("subscription delivery stream already exists")]
    AlreadyOpen,
    /// The stream was not open or has disconnected.
    #[error("subscription delivery stream is closed")]
    Closed,
    /// Delivery adapter could not make progress.
    #[error("subscription delivery is unavailable")]
    Unavailable,
}

/// Selectable backplane family.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum BackplaneKind {
    /// Bounded single-process development backplane.
    Local,
    /// Ephemeral Redis Pub/Sub adapter.
    Redis,
    /// Ephemeral NATS Core adapter. This is never a `JetStream` durability claim.
    NatsCore,
}

/// Honest event guarantee advertised by an adapter.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BackplaneGuarantee {
    /// Notifications can be lost around readiness, disconnect, or overflow.
    Ephemeral,
}

/// Task-only wake-up record carried by a backplane.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BackplaneHint {
    /// Authoritative tenant routing key.
    pub tenant_id: TenantId,
    /// Explicit task routing key.
    pub task_id: TaskId,
    /// Position observed by the publisher. Repository state remains authoritative.
    pub observed_position: EventPosition,
}

/// Backplane receive result.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BackplaneRecord {
    /// Task snapshot changed.
    TaskChanged(BackplaneHint),
    /// Bounded ingress lost records; subscribers must reconcile from the repository.
    IngressGap,
}

/// A selected provider receiver.
#[async_trait]
pub trait BackplaneReceiver: Send {
    /// Receives the next task-only record.
    ///
    /// # Errors
    ///
    /// Returns [`BackplaneError`] when the provider disconnects, overflows, supplies an invalid
    /// record, or the selected receiver is unavailable.
    async fn receive(&mut self) -> Result<BackplaneRecord, BackplaneError>;
}

/// Provider-neutral task subscription publisher and readiness view.
///
/// Receiver ownership is deliberately absent. Composition supplies the sole receiver separately
/// through [`BackplaneRegistration`] to the supervised service loop.
#[async_trait]
pub trait TaskSubscriptionBackplane: Send + Sync {
    /// Returns the selectable provider kind.
    fn kind(&self) -> BackplaneKind;

    /// Returns the provider's honest delivery guarantee.
    fn guarantee(&self) -> BackplaneGuarantee;

    /// Returns point-in-time provider listener readiness.
    fn is_ready(&self) -> bool;

    /// Publishes a task-only wake-up hint.
    ///
    /// # Errors
    ///
    /// Returns [`BackplaneError`] when the provider is not ready, disconnects, overflows, or
    /// cannot encode the task hint as a valid provider record.
    async fn publish(&self, hint: BackplaneHint) -> Result<(), BackplaneError>;
}

/// Safe backplane dependency failure.
#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum BackplaneError {
    /// Selected provider is not ready.
    #[error("subscription backplane is not ready")]
    NotReady,
    /// Bounded ingress overflowed.
    #[error("subscription backplane ingress overflowed")]
    Overflow,
    /// Provider disconnected.
    #[error("subscription backplane disconnected")]
    Disconnected,
    /// Provider record was invalid for this task-only channel.
    #[error("subscription backplane record is invalid")]
    InvalidRecord,
    /// The composition-provided sole receiver was absent, already consumed, or has stopped.
    #[error("subscription backplane receiver is unavailable")]
    ReceiverUnavailable,
}

/// Error selecting the sole active backplane.
#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum BackplaneSelectionError {
    /// No provider was configured.
    #[error("exactly one subscription backplane is required")]
    NoneSelected,
    /// More than one provider was configured.
    #[error("subscription backplanes are mutually exclusive")]
    MultipleSelected,
}

/// One application-owned publisher/readiness view paired with its sole provider receiver.
pub struct BackplaneRegistration {
    provider: Arc<dyn TaskSubscriptionBackplane>,
    receiver: Box<dyn BackplaneReceiver>,
}

impl BackplaneRegistration {
    /// Pairs one provider with the only receiver composition may supervise.
    #[must_use]
    pub fn new(
        provider: Arc<dyn TaskSubscriptionBackplane>,
        receiver: Box<dyn BackplaneReceiver>,
    ) -> Self {
        Self { provider, receiver }
    }
}

impl fmt::Debug for BackplaneRegistration {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BackplaneRegistration")
            .field("kind", &self.provider.kind())
            .field("guarantee", &self.provider.guarantee())
            .finish_non_exhaustive()
    }
}

const RECEIVER_SUPPLIED: u8 = 0;
const RECEIVER_RUNNING: u8 = 1;
const RECEIVER_STOPPED: u8 = 2;

/// Exactly one selected application-owned local, Redis, or NATS Core provider.
#[derive(Clone)]
pub struct SelectedBackplane {
    provider: Arc<dyn TaskSubscriptionBackplane>,
    receiver_state: Arc<std::sync::atomic::AtomicU8>,
}

/// Sole receiver consumed by the supervised subscription service.
pub struct SelectedBackplaneReceiver {
    inner: Box<dyn BackplaneReceiver>,
    state: Arc<std::sync::atomic::AtomicU8>,
}

impl SelectedBackplaneReceiver {
    pub(crate) fn start(&self) -> Result<(), BackplaneError> {
        self.state
            .compare_exchange(
                RECEIVER_SUPPLIED,
                RECEIVER_RUNNING,
                std::sync::atomic::Ordering::AcqRel,
                std::sync::atomic::Ordering::Acquire,
            )
            .map(|_| ())
            .map_err(|_| BackplaneError::ReceiverUnavailable)
    }

    pub(crate) async fn receive(&mut self) -> Result<BackplaneRecord, BackplaneError> {
        if self.state.load(std::sync::atomic::Ordering::Acquire) != RECEIVER_RUNNING {
            return Err(BackplaneError::ReceiverUnavailable);
        }
        self.inner.receive().await
    }

    pub(crate) fn belongs_to(&self, selected: &SelectedBackplane) -> bool {
        Arc::ptr_eq(&self.state, &selected.receiver_state)
    }
    pub(crate) fn stop(&self) {
        self.state
            .store(RECEIVER_STOPPED, std::sync::atomic::Ordering::Release);
    }
}

impl fmt::Debug for SelectedBackplaneReceiver {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SelectedBackplaneReceiver(..)")
    }
}

impl Drop for SelectedBackplaneReceiver {
    fn drop(&mut self) {
        self.stop();
    }
}

/// Selected application and supervised receiver halves.
pub struct SelectedBackplaneParts {
    /// Cloneable publisher and admission-readiness view.
    pub backplane: SelectedBackplane,
    /// Sole receiver to move into the supervised service task.
    pub receiver: SelectedBackplaneReceiver,
}

impl SelectedBackplane {
    /// Selects exactly one provider registration and rejects zero or multiple registrations.
    ///
    /// # Errors
    ///
    /// Returns [`BackplaneSelectionError::NoneSelected`] when no registration is supplied, or
    /// [`BackplaneSelectionError::MultipleSelected`] when more than one is supplied.
    pub fn exactly_one(
        providers: impl IntoIterator<Item = BackplaneRegistration>,
    ) -> Result<SelectedBackplaneParts, BackplaneSelectionError> {
        let mut providers = providers.into_iter();
        let Some(registration) = providers.next() else {
            return Err(BackplaneSelectionError::NoneSelected);
        };
        if providers.next().is_some() {
            return Err(BackplaneSelectionError::MultipleSelected);
        }
        let receiver_state = Arc::new(std::sync::atomic::AtomicU8::new(RECEIVER_SUPPLIED));
        Ok(SelectedBackplaneParts {
            backplane: Self {
                provider: registration.provider,
                receiver_state: Arc::clone(&receiver_state),
            },
            receiver: SelectedBackplaneReceiver {
                inner: registration.receiver,
                state: receiver_state,
            },
        })
    }

    /// Returns the selected provider kind.
    #[must_use]
    pub fn kind(&self) -> BackplaneKind {
        self.provider.kind()
    }

    /// Returns the selected provider's honest delivery guarantee.
    #[must_use]
    pub fn guarantee(&self) -> BackplaneGuarantee {
        self.provider.guarantee()
    }

    /// Publishes only while the provider and supervised sole receiver are ready.
    ///
    /// # Errors
    ///
    /// Returns [`BackplaneError::NotReady`] unless both the provider and its supervised receiver
    /// are ready, or propagates the selected provider's publication error.
    pub async fn publish(&self, hint: BackplaneHint) -> Result<(), BackplaneError> {
        if !self.is_ready() {
            return Err(BackplaneError::NotReady);
        }
        self.provider.publish(hint).await
    }
    /// Returns whether the listener is ready and the supervised sole receiver is running.
    #[must_use]
    pub fn is_ready(&self) -> bool {
        self.provider.is_ready()
            && self
                .receiver_state
                .load(std::sync::atomic::Ordering::Acquire)
                == RECEIVER_RUNNING
    }
}

impl fmt::Debug for SelectedBackplane {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SelectedBackplane")
            .field("kind", &self.provider.kind())
            .field("guarantee", &self.provider.guarantee())
            .field("ready", &self.is_ready())
            .finish_non_exhaustive()
    }
}

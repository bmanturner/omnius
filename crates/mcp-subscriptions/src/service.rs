use std::{
    collections::{BTreeMap, BTreeSet, HashMap, HashSet, hash_map::Entry},
    sync::{
        Arc, Mutex as SyncMutex, MutexGuard as SyncMutexGuard,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};

use omnius_mcp_server_core::McpRequestContext;
use thiserror::Error;
use tokio::sync::{Mutex, watch};

use crate::{
    AuthorizationAction, AuthorizationCheck, BackplaneHint, BackplaneRecord, BeginSubscription,
    CloseReason, DeliveryAdmission, DeliveryAttachmentSignal, DeliveryAttachmentState,
    DeliveryCloseMode, DeliveryError, DeliveryFrame, DeliveryLimits, DeliveryOpen, DrainOutcome,
    EventPosition, FinishSubscription, PrincipalId, ReplayGap, ReplayGapReason, ReplayResult,
    RepositoryError, RequestedEventClass, RuntimeLease, SelectedBackplane,
    SelectedBackplaneReceiver, SubscribeRequest, SubscriptionAcknowledgement,
    SubscriptionAuthorizer, SubscriptionCheckpoint, SubscriptionClosed, SubscriptionDelivery,
    SubscriptionHandle, SubscriptionId, SubscriptionRepository, SubscriptionRuntime, TaskCursor,
    TaskId, TaskSnapshot, TenantId,
};
/// Exact official MCP Tasks extension identifier required on every subscription request.
pub const TASKS_EXTENSION_ID: &str = "io.modelcontextprotocol/tasks";
/// Exact official MCP Tasks extension revision required on every subscription request.
pub const TASKS_EXTENSION_REVISION: &str = "2026-07-28";
const MAX_DRAIN_TIMEOUT_MS: u64 = 60_000;

/// Finite subscription-domain bounds.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SubscriptionConfig {
    /// Maximum pending and active subscriptions in this process.
    pub max_active_subscriptions: usize,
    /// Maximum pending and active subscriptions for one tenant.
    pub max_subscriptions_per_tenant: usize,
    /// Maximum pending and active subscriptions for one principal.
    pub max_subscriptions_per_principal: usize,
    /// Maximum tasks in one explicit filter.
    pub max_tasks: usize,
    /// Maximum snapshots loaded in one repository replay operation.
    pub max_replay_events: usize,
    /// Maximum replay pages processed before converging with an explicit gap.
    pub max_replay_pages: usize,
    /// Maximum subscription lifetime.
    pub max_ttl_ms: u64,
    /// Maximum finite graceful-drain interval.
    pub drain_timeout_ms: u64,
    /// Per-response-stream queue limits.
    pub delivery: DeliveryLimits,
}

impl Default for SubscriptionConfig {
    fn default() -> Self {
        Self {
            max_tasks: 32,
            max_replay_events: 128,
            max_replay_pages: 4,
            max_active_subscriptions: 10_000,
            max_subscriptions_per_tenant: 10_000,
            max_subscriptions_per_principal: 10_000,
            max_ttl_ms: 15 * 60 * 1_000,
            drain_timeout_ms: 5_000,
            delivery: DeliveryLimits {
                max_frames: 64,
                max_bytes: 1024 * 1024,
            },
        }
    }
}

impl SubscriptionConfig {
    fn validate(self) -> Result<Self, SubscriptionError> {
        if self.max_active_subscriptions == 0
            || self.max_subscriptions_per_tenant == 0
            || self.max_subscriptions_per_principal == 0
            || self.max_tasks == 0
            || self.max_replay_events == 0
            || self.max_replay_pages == 0
            || self.max_ttl_ms == 0
            || self.drain_timeout_ms == 0
            || self.drain_timeout_ms > MAX_DRAIN_TIMEOUT_MS
            || self.delivery.max_frames == 0
            || self.delivery.max_bytes == 0
        {
            return Err(SubscriptionError::InvalidConfiguration);
        }
        Ok(self)
    }
}

/// Active subscription metadata returned to protocol dispatch.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SubscriptionLease {
    /// JSON-RPC request identifier used as the subscription identifier.
    pub subscription_id: SubscriptionId,
    /// Absolute finite expiry.
    pub expires_at_ms: u64,
}

/// Result of an authoritative runtime expiry callback.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExpireOutcome {
    /// Subscription was already terminal or unknown.
    NotFound,
    /// Runtime callback arrived before the finite deadline.
    NotDue,
    /// Due subscription was closed with this drain result.
    Closed(DrainOutcome),
}

/// Safe subscription-domain failure.
#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum SubscriptionError {
    /// The exact official Tasks extension identifier and revision was not negotiated.
    #[error("the exact MCP Tasks extension was not negotiated")]
    NotNegotiated,
    /// Canonical request identity or tenant evidence was not suitable for a tenant subscription.
    #[error("canonical task subscription request context is invalid")]
    InvalidRequestContext,
    /// The selected provider listener or supervised sole receiver is not ready.
    #[error("task subscription backplane is unavailable")]
    BackplaneUnavailable,
    /// The request contained no supported task-snapshot filter.
    #[error("subscription has no supported event class")]
    NoSupportedEventClass,
    /// Explicit task filter was empty or exceeded its bound.
    #[error("task subscription filter is invalid")]
    InvalidTaskFilter,
    /// Requested finite lifetime was invalid.
    #[error("task subscription lifetime is invalid")]
    InvalidTtl,
    /// Finite lease elapsed while authoritative setup was in progress.
    #[error("subscription expired during setup")]
    ExpiredDuringSetup,
    /// Active finite lease has elapsed.
    #[error("subscription lease expired")]
    Expired,
    /// Principal is not authorized for every exact tenant/task filter.
    #[error("task subscription is not authorized")]
    Unauthorized,
    /// An authorized task was not found.
    #[error("task snapshot was not found")]
    TaskNotFound,
    /// The subscription identifier is already active.
    #[error("subscription identifier is already active")]
    AlreadyActive,
    /// Durable request identifier was previously used.
    #[error("subscription identifier must be new")]
    IdentifierReused,
    /// Reconnect proof was invalid or crossed a principal, tenant, or task boundary.
    #[error("subscription reconnect proof is invalid")]
    InvalidReconnect,
    /// Authoritative repository failed or returned inconsistent state.
    #[error("subscription repository failed")]
    Repository,
    /// Authorization dependency could not decide.
    #[error("subscription authorization failed")]
    Authorization,
    /// Runtime could not establish the finite lifecycle.
    #[error("subscription runtime failed")]
    Runtime,
    /// Response stream could not be opened or admitted.
    #[error("subscription delivery failed")]
    Delivery,
    /// Consumer exceeded a finite queue or retained-byte bound.
    #[error("subscription consumer is too slow")]
    SlowConsumer,
    /// Response transport disconnected.
    #[error("subscription response transport disconnected")]
    Disconnected,
    /// Domain bounds were invalid.
    #[error("subscription configuration is invalid")]
    InvalidConfiguration,
    /// Global, tenant, or principal pending-plus-active bound was reached.
    #[error("subscription capacity is exhausted")]
    CapacityExceeded,
}

fn capacity_lock(mutex: &SyncMutex<CapacityState>) -> SyncMutexGuard<'_, CapacityState> {
    mutex
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

#[derive(Debug, Default)]
struct CapacityState {
    subscription_ids: HashSet<SubscriptionId>,
    tenants: HashMap<TenantId, usize>,
    principals: HashMap<PrincipalId, usize>,
}

#[derive(Debug)]
struct CapacityReservation {
    capacity: Arc<SyncMutex<CapacityState>>,
    subscription_id: SubscriptionId,
    principal_id: PrincipalId,
    tenant_id: TenantId,
}

impl Drop for CapacityReservation {
    fn drop(&mut self) {
        let mut capacity = capacity_lock(&self.capacity);
        capacity.subscription_ids.remove(&self.subscription_id);
        let remove_tenant = if let Some(count) = capacity.tenants.get_mut(&self.tenant_id) {
            *count = count.saturating_sub(1);
            *count == 0
        } else {
            false
        };
        if remove_tenant {
            capacity.tenants.remove(&self.tenant_id);
        }
        let remove_principal = if let Some(count) = capacity.principals.get_mut(&self.principal_id)
        {
            *count = count.saturating_sub(1);
            *count == 0
        } else {
            false
        };
        if remove_principal {
            capacity.principals.remove(&self.principal_id);
        }
    }
}

#[derive(Clone, Debug)]
struct CapacityTracker {
    state: Arc<SyncMutex<CapacityState>>,
    global_limit: usize,
    tenant_limit: usize,
    principal_limit: usize,
}

impl CapacityTracker {
    fn new(config: SubscriptionConfig) -> Self {
        Self {
            state: Arc::new(SyncMutex::new(CapacityState::default())),
            global_limit: config.max_active_subscriptions,
            tenant_limit: config.max_subscriptions_per_tenant,
            principal_limit: config.max_subscriptions_per_principal,
        }
    }

    fn reserve(
        &self,
        subscription_id: SubscriptionId,
        principal_id: PrincipalId,
        tenant_id: TenantId,
    ) -> Result<CapacityReservation, SubscriptionError> {
        let mut capacity = capacity_lock(&self.state);
        if capacity.subscription_ids.contains(&subscription_id) {
            return Err(SubscriptionError::AlreadyActive);
        }
        let tenant_count = capacity.tenants.get(&tenant_id).copied().unwrap_or(0);
        let principal_count = capacity.principals.get(&principal_id).copied().unwrap_or(0);
        if capacity.subscription_ids.len() >= self.global_limit
            || tenant_count >= self.tenant_limit
            || principal_count >= self.principal_limit
        {
            return Err(SubscriptionError::CapacityExceeded);
        }
        capacity.subscription_ids.insert(subscription_id.clone());
        *capacity.tenants.entry(tenant_id.clone()).or_insert(0) += 1;
        *capacity.principals.entry(principal_id.clone()).or_insert(0) += 1;
        drop(capacity);
        Ok(CapacityReservation {
            capacity: Arc::clone(&self.state),
            subscription_id,
            principal_id,
            tenant_id,
        })
    }
}

#[derive(Debug)]
enum SubscriptionPhase {
    Initializing,
    Ready,
    Closing {
        completion: watch::Receiver<Option<DrainOutcome>>,
    },
}

impl SubscriptionPhase {
    fn is_closing(&self) -> bool {
        matches!(self, Self::Closing { .. })
    }

    fn is_ready(&self) -> bool {
        matches!(self, Self::Ready)
    }
}

#[derive(Debug)]
struct ActiveSubscription {
    principal_id: PrincipalId,
    tenant_id: TenantId,
    task_ids: BTreeSet<TaskId>,
    cursors: BTreeMap<TaskId, EventPosition>,
    handle: SubscriptionHandle,
    expires_at_ms: u64,
    phase: SubscriptionPhase,
    _capacity: CapacityReservation,
}

type ActiveMap = HashMap<SubscriptionId, Arc<Mutex<ActiveSubscription>>>;

/// Authorized task-subscription domain service.
#[derive(Clone)]
pub struct TaskSubscriptionService {
    config: SubscriptionConfig,
    repository: Arc<dyn SubscriptionRepository>,
    authorizer: Arc<dyn SubscriptionAuthorizer>,
    runtime: Arc<dyn SubscriptionRuntime>,
    delivery: Arc<dyn SubscriptionDelivery>,
    backplane: SelectedBackplane,
    active: Arc<Mutex<ActiveMap>>,
    capacity: CapacityTracker,
    last_safe_now_ms: Arc<AtomicU64>,
}

impl TaskSubscriptionService {
    /// Creates a service from typed authoritative ports and one selected backplane.
    ///
    /// # Errors
    ///
    /// Returns [`SubscriptionError::InvalidConfiguration`] when any configured capacity,
    /// lifetime, drain interval, or delivery bound is outside its supported finite range.
    pub fn new(
        config: SubscriptionConfig,
        repository: Arc<dyn SubscriptionRepository>,
        authorizer: Arc<dyn SubscriptionAuthorizer>,
        runtime: Arc<dyn SubscriptionRuntime>,
        delivery: Arc<dyn SubscriptionDelivery>,
        backplane: SelectedBackplane,
    ) -> Result<Self, SubscriptionError> {
        let config = config.validate()?;
        Ok(Self {
            capacity: CapacityTracker::new(config),
            config,
            repository,
            authorizer,
            runtime,
            delivery,
            backplane,
            active: Arc::new(Mutex::new(HashMap::new())),
            last_safe_now_ms: Arc::new(AtomicU64::new(0)),
        })
    }

    /// Negotiates, authorizes, durably claims, and acknowledges a subscription.
    ///
    /// The exact Tasks extension, JSON-RPC request identifier, authenticated principal, tenant, and
    /// cancellation evidence come only from `context`. Acknowledgement is admitted before the lease
    /// is returned. Production initialization starts only after response-stream attachment; an
    /// adapter that explicitly reports itself attached is initialized synchronously.
    ///
    /// # Errors
    ///
    /// Returns [`SubscriptionError`] when negotiation or canonical request evidence is invalid,
    /// the request exceeds a configured bound, authorization or a required dependency fails,
    /// durable reconnect state is invalid, setup expires, or bounded delivery cannot admit the
    /// acknowledgement or synchronous attached-adapter initialization.
    #[expect(
        clippy::too_many_lines,
        reason = "subscription setup keeps durable claim, delivery admission, runtime arming, and compensating cleanup in one auditable order"
    )]
    pub async fn subscribe(
        &self,
        context: &McpRequestContext,
        request: SubscribeRequest,
    ) -> Result<SubscriptionLease, SubscriptionError> {
        if !tasks_extension_negotiated(context) {
            return Err(SubscriptionError::NotNegotiated);
        }
        if !self.backplane.is_ready() {
            return Err(SubscriptionError::BackplaneUnavailable);
        }
        let (subscription_id, principal_id, tenant_id) = canonical_scope(context)?;
        let SubscribeRequest {
            task_ids,
            event_classes,
            ttl_ms,
            start,
        } = request;
        if !event_classes.contains(&RequestedEventClass::TaskSnapshots) {
            return Err(SubscriptionError::NoSupportedEventClass);
        }
        if task_ids.is_empty() || task_ids.len() > self.config.max_tasks {
            return Err(SubscriptionError::InvalidTaskFilter);
        }
        if ttl_ms == 0 || ttl_ms > self.config.max_ttl_ms {
            return Err(SubscriptionError::InvalidTtl);
        }
        let context_remaining_ms = u64::try_from(
            context
                .canonical()
                .invocation()
                .remaining_duration()
                .as_millis(),
        )
        .map_err(|_| SubscriptionError::InvalidTtl)?;
        if ttl_ms > context_remaining_ms {
            return Err(SubscriptionError::InvalidTtl);
        }
        let task_ids = task_ids
            .into_iter()
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect::<Vec<_>>();
        if task_ids.len() > self.config.max_tasks {
            return Err(SubscriptionError::InvalidTaskFilter);
        }
        let capacity = self.capacity.reserve(
            subscription_id.clone(),
            principal_id.clone(),
            tenant_id.clone(),
        )?;
        let subscribed_at_ms = self.live_now(0).await?;
        let expires_at_ms = subscribed_at_ms
            .checked_add(ttl_ms)
            .ok_or(SubscriptionError::InvalidTtl)?;
        for task_id in &task_ids {
            self.authorize(
                &principal_id,
                &tenant_id,
                task_id,
                AuthorizationAction::Subscribe,
            )
            .await?;
        }
        if !self.backplane.is_ready() {
            return Err(SubscriptionError::BackplaneUnavailable);
        }

        let durable = self
            .repository
            .begin(&BeginSubscription {
                subscription_id: subscription_id.clone(),
                principal_id: principal_id.clone(),
                tenant_id: tenant_id.clone(),
                task_ids: task_ids.clone(),
                expires_at_ms,
                start,
            })
            .await
            .map_err(map_repository_error)?;
        let state = Arc::new(Mutex::new(ActiveSubscription {
            principal_id,
            tenant_id,
            task_ids: task_ids.iter().cloned().collect(),
            cursors: BTreeMap::new(),
            handle: durable.subscription_handle,
            expires_at_ms,
            phase: SubscriptionPhase::Initializing,
            _capacity: capacity,
        }));
        {
            let mut active = self.active.lock().await;
            let Entry::Vacant(entry) = active.entry(subscription_id.clone()) else {
                return Err(SubscriptionError::Repository);
            };
            entry.insert(Arc::clone(&state));
        }
        let resume_cursors = match validate_resume_cursors(&task_ids, durable.resume_cursors) {
            Ok(cursors) => cursors,
            Err(error) => {
                let _ = self
                    .start_close(
                        &subscription_id,
                        CloseReason::Failed,
                        subscribed_at_ms,
                        false,
                    )
                    .await;
                return Err(error);
            }
        };
        state.lock().await.cursors = resume_cursors;

        let setup_now_ms = match self.live_now(subscribed_at_ms).await {
            Ok(now_ms) => now_ms,
            Err(error) => {
                let _ = self
                    .start_close(
                        &subscription_id,
                        CloseReason::Failed,
                        subscribed_at_ms,
                        false,
                    )
                    .await;
                return Err(error);
            }
        };
        if setup_now_ms >= expires_at_ms {
            let _ = self
                .start_close(&subscription_id, CloseReason::Expired, setup_now_ms, false)
                .await;
            return Err(SubscriptionError::ExpiredDuringSetup);
        }
        let Ok(DeliveryOpen {
            disconnect,
            attachment,
        }) = self
            .delivery
            .open(&subscription_id, self.config.delivery)
            .await
        else {
            let _ = self
                .start_close(&subscription_id, CloseReason::Failed, setup_now_ms, false)
                .await;
            return Err(SubscriptionError::Delivery);
        };

        if self
            .runtime
            .arm(&RuntimeLease {
                subscription_id: subscription_id.clone(),
                expires_at_ms,
                disconnect,
            })
            .await
            .is_err()
        {
            let _ = self
                .start_close(&subscription_id, CloseReason::Failed, setup_now_ms, false)
                .await;
            return Err(SubscriptionError::Runtime);
        }
        let acknowledgement_now_ms = match self.live_now(setup_now_ms).await {
            Ok(now_ms) => now_ms,
            Err(error) => {
                let _ = self
                    .start_close(&subscription_id, CloseReason::Failed, setup_now_ms, false)
                    .await;
                return Err(error);
            }
        };
        if acknowledgement_now_ms >= expires_at_ms {
            let _ = self
                .start_close(
                    &subscription_id,
                    CloseReason::Expired,
                    acknowledgement_now_ms,
                    false,
                )
                .await;
            return Err(SubscriptionError::ExpiredDuringSetup);
        }
        if !self.backplane.is_ready() {
            let _ = self
                .start_close(
                    &subscription_id,
                    CloseReason::Failed,
                    acknowledgement_now_ms,
                    false,
                )
                .await;
            return Err(SubscriptionError::BackplaneUnavailable);
        }

        let acknowledgement = DeliveryFrame::Acknowledged(SubscriptionAcknowledgement {
            subscription_id: subscription_id.clone(),
            task_ids: task_ids.clone(),
            event_classes: vec![RequestedEventClass::TaskSnapshots],
            expires_at_ms,
        });
        if let Err(error) = self.admit(&subscription_id, acknowledgement).await {
            let _ = self
                .start_close(
                    &subscription_id,
                    close_reason(error),
                    acknowledgement_now_ms,
                    false,
                )
                .await;
            return Err(error);
        }

        if attachment.state() == DeliveryAttachmentState::Ready {
            if let Err(error) = self
                .initialize_after_attachment(
                    subscription_id.clone(),
                    state,
                    task_ids,
                    attachment,
                    acknowledgement_now_ms,
                )
                .await
            {
                self.close_failed_initialization(&subscription_id, error, acknowledgement_now_ms)
                    .await;
                return Err(error);
            }
        } else {
            let initializer = self.clone();
            let initialization_id = subscription_id.clone();
            tokio::spawn(async move {
                if let Err(error) = initializer
                    .initialize_after_attachment(
                        initialization_id.clone(),
                        state,
                        task_ids,
                        attachment,
                        acknowledgement_now_ms,
                    )
                    .await
                {
                    initializer
                        .close_failed_initialization(
                            &initialization_id,
                            error,
                            acknowledgement_now_ms,
                        )
                        .await;
                }
            });
        }

        Ok(SubscriptionLease {
            subscription_id,
            expires_at_ms,
        })
    }
    async fn initialize_after_attachment(
        &self,
        subscription_id: SubscriptionId,
        state: Arc<Mutex<ActiveSubscription>>,
        task_ids: Vec<TaskId>,
        attachment: DeliveryAttachmentSignal,
        acknowledged_at_ms: u64,
    ) -> Result<(), SubscriptionError> {
        if attachment.wait().await != DeliveryAttachmentState::Ready {
            return Err(SubscriptionError::Disconnected);
        }
        let initialization_now_ms = self.live_now(acknowledged_at_ms).await?;
        let expires_at_ms = state.lock().await.expires_at_ms;
        if initialization_now_ms >= expires_at_ms {
            return Err(SubscriptionError::ExpiredDuringSetup);
        }
        if !self.backplane.is_ready() {
            return Err(SubscriptionError::BackplaneUnavailable);
        }

        for task_id in &task_ids {
            if let Some(after) = {
                let state = state.lock().await;
                state.cursors.get(task_id).copied()
            } {
                self.replay_task(
                    &subscription_id,
                    &state,
                    task_id,
                    after,
                    true,
                    initialization_now_ms,
                )
                .await?;
            } else {
                self.deliver_current(
                    &subscription_id,
                    &state,
                    task_id,
                    false,
                    None,
                    initialization_now_ms,
                )
                .await?;
            }
        }
        {
            let mut state = state.lock().await;
            if state.phase.is_closing() {
                return Err(SubscriptionError::Disconnected);
            }
            state.phase = SubscriptionPhase::Ready;
        }

        for task_id in &task_ids {
            let after = {
                let state = state.lock().await;
                state.cursors.get(task_id).copied()
            }
            .ok_or(SubscriptionError::Repository)?;
            self.replay_task(
                &subscription_id,
                &state,
                task_id,
                after,
                false,
                initialization_now_ms,
            )
            .await?;
        }
        let ready_now_ms = self.live_now(initialization_now_ms).await?;
        if ready_now_ms >= expires_at_ms {
            return Err(SubscriptionError::ExpiredDuringSetup);
        }
        Ok(())
    }

    async fn close_failed_initialization(
        &self,
        subscription_id: &SubscriptionId,
        error: SubscriptionError,
        now_ms: u64,
    ) {
        let _ = self
            .start_close(subscription_id, close_reason(error), now_ms, false)
            .await;
    }

    /// Processes a task-only backplane record and converges against authoritative repository state.
    pub async fn handle_backplane_record(&self, record: BackplaneRecord, now_ms: u64) {
        match record {
            BackplaneRecord::TaskChanged(hint) => self.handle_hint(&hint, now_ms).await,
            BackplaneRecord::IngressGap => self.reconcile_all(now_ms).await,
        }
    }

    /// Returns the service runtime's monotonic-safe current Unix time.
    ///
    /// # Errors
    ///
    /// Returns [`SubscriptionError::Runtime`] when the runtime clock is unavailable.
    pub async fn now_ms(&self) -> Result<u64, SubscriptionError> {
        self.live_now(0).await
    }

    /// Cancels or disconnects an exact explicit subscription identifier.
    pub async fn cancel(
        &self,
        subscription_id: &SubscriptionId,
        reason: CloseReason,
        now_ms: u64,
        drain: bool,
    ) -> DrainOutcome {
        self.remove_and_close(subscription_id, reason, now_ms, drain)
            .await
    }
    /// Handles a runtime-supervised response-stream drop with authoritative cleanup.
    pub async fn disconnect(&self, subscription_id: &SubscriptionId, now_ms: u64) -> DrainOutcome {
        self.remove_and_close(subscription_id, CloseReason::Disconnected, now_ms, false)
            .await
    }

    /// Expires an exact lease when invoked by the runtime callback.
    pub async fn expire(&self, subscription_id: &SubscriptionId, now_ms: u64) -> ExpireOutcome {
        let due = {
            let active = self.active.lock().await;
            let Some(state) = active.get(subscription_id).cloned() else {
                return ExpireOutcome::NotFound;
            };
            drop(active);
            let expires_at_ms = state.lock().await.expires_at_ms;
            expires_at_ms <= now_ms
        };
        if !due {
            return ExpireOutcome::NotDue;
        }
        ExpireOutcome::Closed(
            self.remove_and_close(subscription_id, CloseReason::Expired, now_ms, true)
                .await,
        )
    }

    /// Gracefully drains all active response streams during server shutdown.
    pub async fn drain_all(&self, now_ms: u64) {
        self.close_all(CloseReason::ServerDrain, now_ms, true).await;
    }

    /// Runs the composition-provided sole receiver until graceful shutdown or provider failure.
    ///
    /// This future is intended to be owned by the application supervisor. It marks the receiver
    /// running before admission can succeed, reconciles every bounded ingress gap, closes active
    /// subscriptions if intake dies, and performs finite graceful drain on shutdown.
    ///
    /// # Errors
    ///
    /// Returns [`crate::BackplaneError::ReceiverUnavailable`] when the supplied receiver does not
    /// belong to this service's selected backplane or cannot start. Returns
    /// [`crate::BackplaneError::Disconnected`] when the runtime clock fails, and propagates
    /// provider receive failures after closing active subscriptions.
    pub async fn run_backplane(
        &self,
        mut receiver: SelectedBackplaneReceiver,
        cancellation: &tokio_util::sync::CancellationToken,
    ) -> Result<(), crate::BackplaneError> {
        if !receiver.belongs_to(&self.backplane) {
            return Err(crate::BackplaneError::ReceiverUnavailable);
        }
        receiver.start()?;
        loop {
            tokio::select! {
                () = cancellation.cancelled() => {
                    receiver.stop();
                    if let Ok(now_ms) = self.live_now(0).await {
                        self.drain_all(now_ms).await;
                        return Ok(());
                    }
                    self.fence_all(
                        CloseReason::Failed,
                        self.last_safe_now(0),
                    ).await;
                    return Err(crate::BackplaneError::Disconnected);
                }
                record = receiver.receive() => {
                    match record {
                        Ok(record) => {
                            let Ok(now_ms) = self.live_now(0).await else {
                                receiver.stop();
                                self.fence_all(
                                    CloseReason::Failed,
                                    self.last_safe_now(0),
                                ).await;
                                return Err(crate::BackplaneError::Disconnected);
                            };
                            self.handle_backplane_record(record, now_ms).await;
                        }
                        Err(error) => {
                            receiver.stop();
                            let now_ms = self.live_now(0).await.unwrap_or_else(|_| {
                                self.last_safe_now(0)
                            });
                            self.fence_all(CloseReason::Failed, now_ms).await;
                            return Err(error);
                        }
                    }
                }
            }
        }
    }

    async fn handle_hint(&self, hint: &BackplaneHint, now_ms: u64) {
        let candidates = {
            let active = self.active.lock().await;
            active
                .iter()
                .map(|(subscription_id, state)| (subscription_id.clone(), Arc::clone(state)))
                .collect::<Vec<_>>()
        };
        for (subscription_id, state) in candidates {
            let after = {
                let state = state.lock().await;
                if !state.phase.is_ready()
                    || state.tenant_id != hint.tenant_id
                    || !state.task_ids.contains(&hint.task_id)
                    || state.expires_at_ms <= now_ms
                {
                    None
                } else {
                    state.cursors.get(&hint.task_id).copied()
                }
            };
            let Some(after) = after else {
                continue;
            };
            if !hint.observed_position.strictly_follows(after) {
                continue;
            }
            if let Err(error) = self
                .replay_task(
                    &subscription_id,
                    &state,
                    &hint.task_id,
                    after,
                    false,
                    now_ms,
                )
                .await
            {
                self.remove_and_close(&subscription_id, close_reason(error), now_ms, false)
                    .await;
            }
        }
    }

    async fn reconcile_all(&self, now_ms: u64) {
        let candidates = {
            let active = self.active.lock().await;
            active
                .iter()
                .map(|(subscription_id, state)| (subscription_id.clone(), Arc::clone(state)))
                .collect::<Vec<_>>()
        };
        for (subscription_id, state) in candidates {
            let tasks = {
                let state = state.lock().await;
                if !state.phase.is_ready() || state.expires_at_ms <= now_ms {
                    Vec::new()
                } else {
                    state
                        .task_ids
                        .iter()
                        .filter_map(|task_id| {
                            state
                                .cursors
                                .get(task_id)
                                .copied()
                                .map(|cursor| (task_id.clone(), cursor))
                        })
                        .collect::<Vec<_>>()
                }
            };
            for (task_id, after) in tasks {
                if let Err(error) = self
                    .replay_task(&subscription_id, &state, &task_id, after, false, now_ms)
                    .await
                {
                    self.remove_and_close(&subscription_id, close_reason(error), now_ms, false)
                        .await;
                    break;
                }
            }
        }
    }

    #[expect(
        clippy::too_many_lines,
        reason = "paged replay keeps repository validation, gap convergence, ordered delivery, and checkpoints contiguous"
    )]
    async fn replay_task(
        &self,
        subscription_id: &SubscriptionId,
        state: &Arc<Mutex<ActiveSubscription>>,
        task_id: &TaskId,
        after: EventPosition,
        replayed: bool,
        now_ms: u64,
    ) -> Result<(), SubscriptionError> {
        let (principal_id, tenant_id) = {
            let state = state.lock().await;
            (state.principal_id.clone(), state.tenant_id.clone())
        };
        self.authorize(
            &principal_id,
            &tenant_id,
            task_id,
            AuthorizationAction::Deliver,
        )
        .await?;
        let mut page_after = after;
        let mut replay_pages = 0_usize;
        loop {
            let replay = self
                .repository
                .replay_after(
                    &tenant_id,
                    task_id,
                    page_after,
                    self.config.max_replay_events,
                )
                .await
                .map_err(map_repository_error)?;
            match replay {
                ReplayResult::Events {
                    snapshots,
                    has_more,
                } => {
                    replay_pages = replay_pages.saturating_add(1);
                    if snapshots.len() > self.config.max_replay_events
                        || (has_more && snapshots.is_empty())
                    {
                        return Err(SubscriptionError::Repository);
                    }
                    let mut previous = page_after;
                    for snapshot in snapshots {
                        validate_snapshot(&snapshot, &tenant_id, task_id, Some(previous))?;
                        previous = snapshot.position();
                        self.emit_snapshot(subscription_id, state, snapshot, replayed, now_ms)
                            .await?;
                    }
                    if !has_more {
                        break;
                    }
                    if replay_pages >= self.config.max_replay_pages {
                        let snapshot = self
                            .repository
                            .current_snapshot(&tenant_id, task_id)
                            .await
                            .map_err(map_repository_error)?
                            .ok_or(SubscriptionError::TaskNotFound)?;
                        validate_snapshot(&snapshot, &tenant_id, task_id, Some(previous))?;
                        let current_position = snapshot.position();
                        self.emit_gap(
                            subscription_id,
                            state,
                            ReplayGap {
                                task_id: task_id.clone(),
                                requested_after: previous,
                                reason: ReplayGapReason::ServiceReplayBound,
                                oldest_available: None,
                                newest_available: current_position,
                            },
                            now_ms,
                        )
                        .await?;
                        self.emit_snapshot(subscription_id, state, snapshot, replayed, now_ms)
                            .await?;
                        break;
                    }
                    page_after = previous;
                }
                ReplayResult::Gap(window) => {
                    if !window.oldest_available.strictly_follows(page_after)
                        || (window.newest_available != window.oldest_available
                            && !window
                                .newest_available
                                .strictly_follows(window.oldest_available))
                    {
                        return Err(SubscriptionError::Repository);
                    }
                    self.emit_gap(
                        subscription_id,
                        state,
                        ReplayGap {
                            task_id: task_id.clone(),
                            requested_after: page_after,
                            reason: ReplayGapReason::RetentionWindow,
                            oldest_available: Some(window.oldest_available),
                            newest_available: window.newest_available,
                        },
                        now_ms,
                    )
                    .await?;
                    self.deliver_current(
                        subscription_id,
                        state,
                        task_id,
                        replayed,
                        Some(window.newest_available),
                        now_ms,
                    )
                    .await?;
                    break;
                }
            }
        }
        Ok(())
    }

    async fn deliver_current(
        &self,
        subscription_id: &SubscriptionId,
        state: &Arc<Mutex<ActiveSubscription>>,
        task_id: &TaskId,
        replayed: bool,
        minimum_position: Option<EventPosition>,
        now_ms: u64,
    ) -> Result<(), SubscriptionError> {
        let tenant_id = {
            let state = state.lock().await;
            state.tenant_id.clone()
        };
        let snapshot = self
            .repository
            .current_snapshot(&tenant_id, task_id)
            .await
            .map_err(map_repository_error)?
            .ok_or(SubscriptionError::TaskNotFound)?;
        validate_snapshot(&snapshot, &tenant_id, task_id, None)?;
        if minimum_position.is_some_and(|minimum| {
            snapshot.position() != minimum && !snapshot.position().strictly_follows(minimum)
        }) {
            return Err(SubscriptionError::Repository);
        }
        self.emit_snapshot(subscription_id, state, snapshot, replayed, now_ms)
            .await
    }

    async fn emit_gap(
        &self,
        subscription_id: &SubscriptionId,
        state: &Arc<Mutex<ActiveSubscription>>,
        gap: ReplayGap,
        now_ms: u64,
    ) -> Result<(), SubscriptionError> {
        let live_now_ms = self.live_now(now_ms).await?;
        let state = state.lock().await;
        if state.phase.is_closing() || state.expires_at_ms <= live_now_ms {
            return Err(SubscriptionError::Expired);
        }
        self.authorize(
            &state.principal_id,
            &state.tenant_id,
            &gap.task_id,
            AuthorizationAction::Deliver,
        )
        .await?;
        let authorized_now_ms = self.live_now(live_now_ms).await?;
        if state.expires_at_ms <= authorized_now_ms {
            return Err(SubscriptionError::Expired);
        }
        let admission = self
            .delivery
            .deliver(
                subscription_id,
                DeliveryFrame::ReplayGap {
                    subscription_id: subscription_id.clone(),
                    gap,
                },
            )
            .await
            .map_err(map_delivery_error)?;
        match admission {
            DeliveryAdmission::Accepted => Ok(()),
            DeliveryAdmission::SlowConsumer => Err(SubscriptionError::SlowConsumer),
            DeliveryAdmission::Disconnected => Err(SubscriptionError::Disconnected),
        }
    }

    async fn emit_snapshot(
        &self,
        subscription_id: &SubscriptionId,
        state: &Arc<Mutex<ActiveSubscription>>,
        snapshot: TaskSnapshot,
        replayed: bool,
        now_ms: u64,
    ) -> Result<(), SubscriptionError> {
        let live_now_ms = self.live_now(now_ms).await?;
        let mut state = state.lock().await;
        if state.phase.is_closing() || state.expires_at_ms <= live_now_ms {
            return Err(SubscriptionError::Expired);
        }
        if snapshot.tenant_id() != &state.tenant_id || !state.task_ids.contains(snapshot.task_id())
        {
            return Err(SubscriptionError::Repository);
        }
        if let Some(previous) = state.cursors.get(snapshot.task_id()).copied() {
            if snapshot.position() == previous {
                return Ok(());
            }
            if !snapshot.position().strictly_follows(previous) {
                return Err(SubscriptionError::Repository);
            }
        }
        self.authorize(
            &state.principal_id,
            &state.tenant_id,
            snapshot.task_id(),
            AuthorizationAction::Deliver,
        )
        .await?;
        let authorized_now_ms = self.live_now(live_now_ms).await?;
        if state.expires_at_ms <= authorized_now_ms {
            return Err(SubscriptionError::Expired);
        }
        let task_id = snapshot.task_id().clone();
        let position = snapshot.position();
        let admission = self
            .delivery
            .deliver(
                subscription_id,
                DeliveryFrame::TaskSnapshot {
                    subscription_id: subscription_id.clone(),
                    replayed,
                    snapshot,
                },
            )
            .await
            .map_err(map_delivery_error)?;
        match admission {
            DeliveryAdmission::Accepted => {}
            DeliveryAdmission::SlowConsumer => return Err(SubscriptionError::SlowConsumer),
            DeliveryAdmission::Disconnected => return Err(SubscriptionError::Disconnected),
        }
        state.cursors.insert(task_id.clone(), position);
        let checkpoint = SubscriptionCheckpoint {
            subscription_handle: state.handle.clone(),
            cursor: TaskCursor { task_id, position },
        };
        drop(state);
        self.repository
            .checkpoint(&checkpoint)
            .await
            .map_err(map_repository_error)
    }

    async fn live_now(&self, floor_ms: u64) -> Result<u64, SubscriptionError> {
        let now_ms = self
            .runtime
            .now_ms()
            .await
            .map_err(|_| SubscriptionError::Runtime)?
            .max(floor_ms);
        self.last_safe_now_ms.fetch_max(now_ms, Ordering::AcqRel);
        Ok(now_ms)
    }

    fn last_safe_now(&self, floor_ms: u64) -> u64 {
        self.last_safe_now_ms.load(Ordering::Acquire).max(floor_ms)
    }

    async fn authorize(
        &self,
        principal_id: &PrincipalId,
        tenant_id: &TenantId,
        task_id: &TaskId,
        action: AuthorizationAction,
    ) -> Result<(), SubscriptionError> {
        let authorized = self
            .authorizer
            .authorize(&AuthorizationCheck {
                principal_id: principal_id.clone(),
                tenant_id: tenant_id.clone(),
                task_id: task_id.clone(),
                action,
            })
            .await
            .map_err(|_| SubscriptionError::Authorization)?;
        if !authorized {
            return Err(SubscriptionError::Unauthorized);
        }
        Ok(())
    }

    async fn admit(
        &self,
        subscription_id: &SubscriptionId,
        frame: DeliveryFrame,
    ) -> Result<(), SubscriptionError> {
        match self
            .delivery
            .deliver(subscription_id, frame)
            .await
            .map_err(map_delivery_error)?
        {
            DeliveryAdmission::Accepted => Ok(()),
            DeliveryAdmission::SlowConsumer => Err(SubscriptionError::SlowConsumer),
            DeliveryAdmission::Disconnected => Err(SubscriptionError::Disconnected),
        }
    }
    async fn close_all(&self, reason: CloseReason, now_ms: u64, drain: bool) {
        let subscriptions = {
            let active = self.active.lock().await;
            active.keys().cloned().collect::<Vec<_>>()
        };
        let mut closures = tokio::task::JoinSet::new();
        for subscription_id in subscriptions {
            let service = self.clone();
            closures.spawn(async move {
                service
                    .remove_and_close(&subscription_id, reason, now_ms, drain)
                    .await
            });
        }
        while closures.join_next().await.is_some() {}
    }

    async fn fence_all(&self, reason: CloseReason, now_ms: u64) {
        let subscriptions = {
            let active = self.active.lock().await;
            active.keys().cloned().collect::<Vec<_>>()
        };
        for subscription_id in subscriptions {
            let _ = self
                .start_close(&subscription_id, reason, now_ms, false)
                .await;
        }
    }

    async fn remove_and_close(
        &self,
        subscription_id: &SubscriptionId,
        reason: CloseReason,
        now_ms: u64,
        drain: bool,
    ) -> DrainOutcome {
        let Some(mut completion) = self
            .start_close(subscription_id, reason, now_ms, drain)
            .await
        else {
            return DrainOutcome::Disconnected;
        };
        loop {
            if let Some(outcome) = *completion.borrow() {
                return outcome;
            }
            if completion.changed().await.is_err() {
                return DrainOutcome::Disconnected;
            }
        }
    }

    async fn start_close(
        &self,
        subscription_id: &SubscriptionId,
        reason: CloseReason,
        now_ms: u64,
        drain: bool,
    ) -> Option<watch::Receiver<Option<DrainOutcome>>> {
        let state = {
            let active = self.active.lock().await;
            active.get(subscription_id).cloned()
        }?;
        let (handle, cursors, sender, completion) = {
            let mut state_guard = state.lock().await;
            if let SubscriptionPhase::Closing { completion } = &state_guard.phase {
                return Some(completion.clone());
            }
            let cursors = state_guard
                .cursors
                .iter()
                .map(|(task_id, position)| TaskCursor {
                    task_id: task_id.clone(),
                    position: *position,
                })
                .collect::<Vec<_>>();
            let handle = state_guard.handle.clone();
            let (sender, completion) = watch::channel(None);
            state_guard.phase = SubscriptionPhase::Closing {
                completion: completion.clone(),
            };
            (handle, cursors, sender, completion)
        };
        let worker = self.clone();
        let worker_subscription_id = subscription_id.clone();
        tokio::spawn(async move {
            worker
                .finish_close_worker(
                    worker_subscription_id,
                    state,
                    handle,
                    cursors,
                    reason,
                    now_ms,
                    drain,
                    sender,
                )
                .await;
        });
        Some(completion)
    }

    #[expect(
        clippy::too_many_arguments,
        reason = "the detached close worker owns one immutable durable close claim"
    )]
    async fn finish_close_worker(
        &self,
        subscription_id: SubscriptionId,
        state: Arc<Mutex<ActiveSubscription>>,
        handle: SubscriptionHandle,
        cursors: Vec<TaskCursor>,
        reason: CloseReason,
        now_ms: u64,
        drain: bool,
        completion: watch::Sender<Option<DrainOutcome>>,
    ) {
        let finish = FinishSubscription {
            subscription_handle: handle,
            cursors: cursors.clone(),
            closed_at_ms: now_ms,
        };
        let mut retry_delay = Duration::from_millis(10);
        let durably_finished = loop {
            match self.repository.finish(&finish).await {
                Ok(()) => break true,
                Err(RepositoryError::Unavailable) => {
                    tokio::time::sleep(retry_delay).await;
                    retry_delay = retry_delay.saturating_mul(2).min(Duration::from_secs(1));
                }
                Err(
                    RepositoryError::IdentifierReused
                    | RepositoryError::InvalidReconnect
                    | RepositoryError::Inconsistent,
                ) => break false,
            }
        };

        let _ = self.runtime.disarm(&subscription_id).await;
        let mode = if drain {
            DeliveryCloseMode::Drain {
                timeout_ms: self.config.drain_timeout_ms,
            }
        } else {
            DeliveryCloseMode::Abort
        };
        let close = DeliveryFrame::Closed(SubscriptionClosed {
            subscription_id: subscription_id.clone(),
            reason: if durably_finished {
                reason
            } else {
                CloseReason::Failed
            },
            drain: if drain {
                DrainOutcome::Drained
            } else {
                DrainOutcome::DeadlineExceeded
            },
            cursors,
        });
        let outcome = self
            .delivery
            .close(&subscription_id, mode, close)
            .await
            .unwrap_or(DrainOutcome::Disconnected);
        let removed = {
            let mut active = self.active.lock().await;
            if active
                .get(&subscription_id)
                .is_some_and(|current| Arc::ptr_eq(current, &state))
            {
                active.remove(&subscription_id)
            } else {
                None
            }
        };
        drop(removed);
        let _ = completion.send(Some(outcome));
    }
}
/// Returns whether the exact official Tasks extension was negotiated for this request.
#[must_use]
pub fn tasks_extension_negotiated(context: &McpRequestContext) -> bool {
    context
        .negotiated_extensions()
        .extensions()
        .iter()
        .any(|extension| {
            extension.id().as_str() == TASKS_EXTENSION_ID
                && extension.revision().as_str() == TASKS_EXTENSION_REVISION
        })
}

fn canonical_scope(
    context: &McpRequestContext,
) -> Result<(SubscriptionId, PrincipalId, TenantId), SubscriptionError> {
    let invocation = context.canonical().invocation();
    if invocation.cancellation_token().is_cancelled() || invocation.remaining_duration().is_zero() {
        return Err(SubscriptionError::InvalidRequestContext);
    }
    let tenant_id = invocation
        .tenant_id()
        .ok_or(SubscriptionError::InvalidRequestContext)?;
    let subscription_id = SubscriptionId::new(invocation.request_id().to_string())
        .map_err(|_| SubscriptionError::InvalidRequestContext)?;
    let principal_id = PrincipalId::new(invocation.principal().subject_id.to_string())
        .map_err(|_| SubscriptionError::InvalidRequestContext)?;
    let tenant_id = TenantId::new(tenant_id.to_string())
        .map_err(|_| SubscriptionError::InvalidRequestContext)?;
    Ok((subscription_id, principal_id, tenant_id))
}

fn map_repository_error(error: RepositoryError) -> SubscriptionError {
    match error {
        RepositoryError::IdentifierReused => SubscriptionError::IdentifierReused,
        RepositoryError::InvalidReconnect => SubscriptionError::InvalidReconnect,
        RepositoryError::Unavailable | RepositoryError::Inconsistent => {
            SubscriptionError::Repository
        }
    }
}

fn close_reason(error: SubscriptionError) -> CloseReason {
    match error {
        SubscriptionError::Unauthorized => CloseReason::AuthorizationRevoked,
        SubscriptionError::SlowConsumer => CloseReason::SlowConsumer,
        SubscriptionError::Disconnected => CloseReason::Disconnected,
        SubscriptionError::Expired | SubscriptionError::ExpiredDuringSetup => CloseReason::Expired,
        _ => CloseReason::Failed,
    }
}

fn map_delivery_error(error: DeliveryError) -> SubscriptionError {
    match error {
        DeliveryError::Closed => SubscriptionError::Disconnected,
        DeliveryError::AlreadyOpen | DeliveryError::Unavailable => SubscriptionError::Delivery,
    }
}
fn validate_resume_cursors(
    tasks: &[TaskId],
    cursors: Vec<TaskCursor>,
) -> Result<BTreeMap<TaskId, EventPosition>, SubscriptionError> {
    let task_set = tasks.iter().cloned().collect::<BTreeSet<_>>();
    let mut result = BTreeMap::new();
    for cursor in cursors {
        if !task_set.contains(&cursor.task_id)
            || result.insert(cursor.task_id, cursor.position).is_some()
        {
            return Err(SubscriptionError::InvalidReconnect);
        }
    }
    Ok(result)
}

fn validate_snapshot(
    snapshot: &TaskSnapshot,
    tenant_id: &TenantId,
    task_id: &TaskId,
    previous: Option<EventPosition>,
) -> Result<(), SubscriptionError> {
    if snapshot.tenant_id() != tenant_id || snapshot.task_id() != task_id {
        return Err(SubscriptionError::Repository);
    }
    if previous.is_some_and(|position| !snapshot.position().strictly_follows(position)) {
        return Err(SubscriptionError::Repository);
    }
    Ok(())
}

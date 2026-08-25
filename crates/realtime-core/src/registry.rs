use std::{
    collections::{BTreeSet, HashMap},
    fmt,
    ops::Bound::{Excluded, Unbounded},
    sync::{Arc, Mutex, MutexGuard},
};

use rsk_auth_core::{Principal, SubjectId, TenantId};
use thiserror::Error;

use crate::protocol::{
    ConnectionId, ControlOutput, OpaqueCursor, RevocationReason, SubscriptionId, Topic,
};

/// Hard ceiling for configured concurrent connections.
pub const MAX_CONNECTIONS: usize = 65_536;
/// Hard ceiling for configured subscriptions across the registry.
pub const MAX_SUBSCRIPTIONS: usize = 262_144;
/// Hard ceiling for configured subscriptions on one connection.
pub const MAX_SUBSCRIPTIONS_PER_CONNECTION: usize = 4_096;

/// Invalid registry capacity configuration.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum RegistryConfigError {
    /// Every capacity must be greater than zero.
    #[error("realtime registry capacities must be non-zero")]
    ZeroCapacity,
    /// A capacity exceeded its compile-time hard ceiling.
    #[error("realtime registry capacity exceeds its hard limit")]
    ExceedsHardLimit,
    /// The per-connection subscription capacity exceeded the total capacity.
    #[error("per-connection subscription capacity exceeds total capacity")]
    PerConnectionExceedsTotal,
}

/// Validated fixed capacities for a [`ConnectionRegistry`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[allow(clippy::struct_field_names)]
pub struct RegistryConfig {
    max_connections: usize,
    max_subscriptions: usize,
    max_subscriptions_per_connection: usize,
}

impl RegistryConfig {
    /// Validates registry capacities against fixed hard ceilings.
    ///
    /// # Errors
    ///
    /// Returns [`RegistryConfigError`] for zero, excessive, or internally inconsistent limits.
    pub const fn new(
        max_connections: usize,
        max_subscriptions: usize,
        max_subscriptions_per_connection: usize,
    ) -> Result<Self, RegistryConfigError> {
        if max_connections == 0 || max_subscriptions == 0 || max_subscriptions_per_connection == 0 {
            return Err(RegistryConfigError::ZeroCapacity);
        }
        if max_connections > MAX_CONNECTIONS
            || max_subscriptions > MAX_SUBSCRIPTIONS
            || max_subscriptions_per_connection > MAX_SUBSCRIPTIONS_PER_CONNECTION
        {
            return Err(RegistryConfigError::ExceedsHardLimit);
        }
        if max_subscriptions_per_connection > max_subscriptions {
            return Err(RegistryConfigError::PerConnectionExceedsTotal);
        }
        Ok(Self {
            max_connections,
            max_subscriptions,
            max_subscriptions_per_connection,
        })
    }

    /// Returns the maximum number of registered, active, or closing connections.
    #[must_use]
    pub const fn max_connections(self) -> usize {
        self.max_connections
    }

    /// Returns the maximum number of active or revoked subscriptions.
    #[must_use]
    pub const fn max_subscriptions(self) -> usize {
        self.max_subscriptions
    }

    /// Returns the maximum subscriptions retained by one connection.
    #[must_use]
    pub const fn max_subscriptions_per_connection(self) -> usize {
        self.max_subscriptions_per_connection
    }
}

impl Default for RegistryConfig {
    fn default() -> Self {
        Self {
            max_connections: 1_024,
            max_subscriptions: 16_384,
            max_subscriptions_per_connection: 128,
        }
    }
}

/// The lifecycle state of a connection.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConnectionState {
    /// The immutable principal is bound but commands are not yet accepted.
    Registered,
    /// Validated and authorized commands may be handled.
    Active,
    /// New commands are rejected while an adapter finishes closure.
    Closing,
    /// Terminal state returned by close; the record and all indexes are removed.
    Closed,
}

/// The lifecycle state of a subscription.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SubscriptionState {
    /// The subscription is eligible in its authoritative tenant/topic index.
    Active,
    /// The subscription is no longer eligible but remains attached until removal or close.
    Revoked,
    /// Terminal state returned by removal; the record and every index entry are removed.
    Removed,
}

/// A stable, redacted registry failure.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum RegistryError {
    /// The connection capacity was reached.
    #[error("realtime connection capacity is exhausted")]
    ConnectionCapacity,
    /// The registry-wide subscription capacity was reached.
    #[error("realtime subscription capacity is exhausted")]
    SubscriptionCapacity,
    /// The connection's subscription capacity was reached.
    #[error("realtime per-connection subscription capacity is exhausted")]
    PerConnectionSubscriptionCapacity,
    /// The connection does not exist.
    #[error("realtime connection was not found")]
    ConnectionNotFound,
    /// The subscription does not exist for the selected connection or registry operation.
    #[error("realtime subscription was not found")]
    SubscriptionNotFound,
    /// The requested transition is not valid from the current lifecycle state.
    #[error("realtime registry state does not permit this operation")]
    InvalidState,
    /// A duplicate subscription command repeated the already-recorded definition.
    #[error("realtime subscription already exists")]
    DuplicateSubscription,
    /// A subscription identifier conflicts with a different recorded definition.
    #[error("realtime subscription identifier conflicts with existing state")]
    SubscriptionConflict,
    /// The authoritative subscription tenant does not match the connection's active tenant.
    #[error("realtime subscription tenant does not match the connection")]
    TenantMismatch,
    /// The registry lock was poisoned and state cannot be trusted safely.
    #[error("realtime registry is unavailable")]
    Unavailable,
}

#[derive(Debug)]
struct ConnectionRecord {
    id: ConnectionId,
    principal: Arc<Principal>,
    state: ConnectionState,
    subscriptions: BTreeSet<SubscriptionId>,
}

impl ConnectionRecord {
    fn snapshot(&self) -> ConnectionSnapshot {
        ConnectionSnapshot {
            id: self.id,
            principal: Arc::clone(&self.principal),
            state: self.state,
            subscription_count: self.subscriptions.len(),
        }
    }
}

#[derive(Clone, Debug)]
struct SubscriptionRecord {
    id: SubscriptionId,
    connection_id: ConnectionId,
    subject_id: SubjectId,
    tenant_id: TenantId,
    topic: Topic,
    cursor: Option<OpaqueCursor>,
    generation: u64,
    state: SubscriptionState,
}

impl SubscriptionRecord {
    fn snapshot(&self) -> SubscriptionSnapshot {
        SubscriptionSnapshot {
            id: self.id,
            connection_id: self.connection_id,
            subject_id: self.subject_id,
            tenant_id: self.tenant_id,
            topic: self.topic.clone(),
            cursor: self.cursor.clone(),
            generation: self.generation,
            state: self.state,
        }
    }
}

#[derive(Debug, Default)]
struct RegistryState {
    connections: HashMap<ConnectionId, ConnectionRecord>,
    subscriptions: HashMap<SubscriptionId, SubscriptionRecord>,
    tenant_topics: HashMap<TenantId, HashMap<Topic, BTreeSet<SubscriptionId>>>,
    next_subscription_generation: u64,
}

/// A read-only connection snapshot with an immutable shared principal binding.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConnectionSnapshot {
    id: ConnectionId,
    principal: Arc<Principal>,
    state: ConnectionState,
    subscription_count: usize,
}

impl ConnectionSnapshot {
    /// Returns the connection identifier.
    #[must_use]
    pub const fn id(&self) -> ConnectionId {
        self.id
    }

    /// Returns the principal immutably bound at registration.
    #[must_use]
    pub fn principal(&self) -> &Principal {
        &self.principal
    }

    /// Returns the lifecycle state observed under the registry lock.
    #[must_use]
    pub const fn state(&self) -> ConnectionState {
        self.state
    }

    /// Returns the active plus revoked subscriptions retained by this connection.
    #[must_use]
    pub const fn subscription_count(&self) -> usize {
        self.subscription_count
    }
}

/// A read-only tenant-scoped subscription snapshot.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SubscriptionSnapshot {
    id: SubscriptionId,
    connection_id: ConnectionId,
    subject_id: SubjectId,
    tenant_id: TenantId,
    topic: Topic,
    cursor: Option<OpaqueCursor>,
    generation: u64,
    state: SubscriptionState,
}

impl SubscriptionSnapshot {
    /// Returns the subscription identifier.
    #[must_use]
    pub const fn id(&self) -> SubscriptionId {
        self.id
    }

    /// Returns the owning connection.
    #[must_use]
    pub const fn connection_id(&self) -> ConnectionId {
        self.connection_id
    }

    /// Returns the immutable principal subject recorded at creation.
    #[must_use]
    pub const fn subject_id(&self) -> SubjectId {
        self.subject_id
    }

    /// Returns the authoritative active tenant recorded at creation.
    #[must_use]
    pub const fn tenant_id(&self) -> TenantId {
        self.tenant_id
    }

    /// Returns the validated routing topic. It carries no authorization meaning.
    #[must_use]
    pub const fn topic(&self) -> &Topic {
        &self.topic
    }

    /// Returns the opaque cursor without interpreting it.
    #[must_use]
    pub const fn cursor(&self) -> Option<&OpaqueCursor> {
        self.cursor.as_ref()
    }

    /// Returns the immutable registry generation assigned at creation.
    #[must_use]
    pub const fn generation(&self) -> u64 {
        self.generation
    }

    /// Returns the subscription lifecycle state.
    #[must_use]
    pub const fn state(&self) -> SubscriptionState {
        self.state
    }
}
/// Incremental tenant/topic traversal that retains at most one subscription snapshot.
///
/// Each call to [`Self::next_subscription`] briefly locks the registry and advances by
/// subscription identifier. Concurrent removals are skipped, and every yielded snapshot still
/// requires a current-generation check before delivery.
pub struct TopicSubscriptionCursor {
    state: Arc<Mutex<RegistryState>>,
    tenant_id: TenantId,
    topic: Topic,
    after: Option<SubscriptionId>,
    exhausted: bool,
}

impl TopicSubscriptionCursor {
    /// Advances to the next active subscription without materializing the full topic membership.
    ///
    /// # Errors
    ///
    /// Returns [`RegistryError::Unavailable`] if registry state cannot be trusted.
    pub fn next_subscription(&mut self) -> Result<Option<SubscriptionSnapshot>, RegistryError> {
        if self.exhausted {
            return Ok(None);
        }

        let state = self.state.lock().map_err(|_| RegistryError::Unavailable)?;
        loop {
            let Some(ids) = state
                .tenant_topics
                .get(&self.tenant_id)
                .and_then(|topics| topics.get(&self.topic))
            else {
                self.exhausted = true;
                return Ok(None);
            };
            let next_id = match self.after {
                Some(after) => ids.range((Excluded(after), Unbounded)).next().copied(),
                None => ids.first().copied(),
            };
            let Some(next_id) = next_id else {
                self.exhausted = true;
                return Ok(None);
            };
            self.after = Some(next_id);
            if let Some(subscription) = state
                .subscriptions
                .get(&next_id)
                .filter(|subscription| subscription.state == SubscriptionState::Active)
            {
                return Ok(Some(subscription.snapshot()));
            }
        }
    }
}

impl fmt::Debug for TopicSubscriptionCursor {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TopicSubscriptionCursor")
            .field("exhausted", &self.exhausted)
            .finish_non_exhaustive()
    }
}

/// A transport-neutral control intent produced by a server-side revocation transition.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ControlIntent {
    connection_id: ConnectionId,
    subscription_id: SubscriptionId,
    subscription_generation: u64,
    output: ControlOutput,
}

impl ControlIntent {
    /// Returns the adapter connection that should receive the control output.
    #[must_use]
    pub const fn connection_id(&self) -> ConnectionId {
        self.connection_id
    }

    /// Returns the exact revoked subscription generation.
    #[must_use]
    pub const fn subscription_generation(&self) -> u64 {
        self.subscription_generation
    }

    /// Returns the exact revoked subscription identifier.
    #[must_use]
    pub const fn subscription_id(&self) -> SubscriptionId {
        self.subscription_id
    }

    /// Returns the structured control output.
    #[must_use]
    pub const fn output(&self) -> &ControlOutput {
        &self.output
    }

    /// Consumes the intent and returns its structured control output.
    #[must_use]
    pub fn into_output(self) -> ControlOutput {
        self.output
    }
}

/// A bounded, concurrency-safe connection and subscription registry.
///
/// One mutex protects connections, subscriptions, and tenant/topic indexes so every transition is
/// atomic. The registry deliberately owns no outbound queue, fan-out loop, or transport handle.
#[derive(Clone, Debug)]
pub struct ConnectionRegistry {
    config: RegistryConfig,
    state: Arc<Mutex<RegistryState>>,
}

impl ConnectionRegistry {
    /// Creates an empty registry with validated fixed capacities.
    #[must_use]
    pub fn new(config: RegistryConfig) -> Self {
        Self {
            config,
            state: Arc::new(Mutex::new(RegistryState::default())),
        }
    }

    fn lock(&self) -> Result<MutexGuard<'_, RegistryState>, RegistryError> {
        self.state.lock().map_err(|_| RegistryError::Unavailable)
    }

    /// Returns the fixed capacities used by this registry.
    #[must_use]
    pub const fn config(&self) -> RegistryConfig {
        self.config
    }

    /// Registers a connection and immutably binds a principal after checking capacity.
    ///
    /// # Errors
    ///
    /// Returns [`RegistryError::ConnectionCapacity`] when the configured bound is reached, or
    /// [`RegistryError::Unavailable`] if registry state cannot be trusted.
    pub fn register(&self, principal: Principal) -> Result<ConnectionSnapshot, RegistryError> {
        let mut state = self.lock()?;
        if state.connections.len() >= self.config.max_connections {
            return Err(RegistryError::ConnectionCapacity);
        }
        let id = ConnectionId::new();
        if state.connections.contains_key(&id) {
            return Err(RegistryError::Unavailable);
        }
        let record = ConnectionRecord {
            id,
            principal: Arc::new(principal),
            state: ConnectionState::Registered,
            subscriptions: BTreeSet::new(),
        };
        let snapshot = record.snapshot();
        state.connections.insert(id, record);
        Ok(snapshot)
    }

    /// Transitions `Registered -> Active`. Repeating activation while active is idempotent.
    ///
    /// # Errors
    ///
    /// Returns a redacted error for an unknown, closing, or unavailable connection.
    pub fn activate(
        &self,
        connection_id: ConnectionId,
    ) -> Result<ConnectionSnapshot, RegistryError> {
        let mut state = self.lock()?;
        let connection = state
            .connections
            .get_mut(&connection_id)
            .ok_or(RegistryError::ConnectionNotFound)?;
        match connection.state {
            ConnectionState::Registered => connection.state = ConnectionState::Active,
            ConnectionState::Active => {}
            ConnectionState::Closing | ConnectionState::Closed => {
                return Err(RegistryError::InvalidState);
            }
        }
        Ok(connection.snapshot())
    }

    /// Transitions a registered or active connection to `Closing`.
    ///
    /// Repeating the transition while closing is idempotent.
    ///
    /// # Errors
    ///
    /// Returns [`RegistryError::ConnectionNotFound`] for an unknown connection.
    pub fn begin_close(
        &self,
        connection_id: ConnectionId,
    ) -> Result<ConnectionSnapshot, RegistryError> {
        let mut state = self.lock()?;
        let connection = state
            .connections
            .get_mut(&connection_id)
            .ok_or(RegistryError::ConnectionNotFound)?;
        match connection.state {
            ConnectionState::Registered | ConnectionState::Active => {
                connection.state = ConnectionState::Closing;
            }
            ConnectionState::Closing => {}
            ConnectionState::Closed => return Err(RegistryError::InvalidState),
        }
        Ok(connection.snapshot())
    }

    /// Atomically closes a connection and removes all subscription and topic indexes.
    ///
    /// Closing an already-removed connection succeeds without mutation.
    ///
    /// # Errors
    ///
    /// Returns [`RegistryError::Unavailable`] if registry state cannot be trusted.
    pub fn close(&self, connection_id: ConnectionId) -> Result<ConnectionState, RegistryError> {
        let mut state = self.lock()?;
        let Some(connection) = state.connections.remove(&connection_id) else {
            return Ok(ConnectionState::Closed);
        };
        for subscription_id in connection.subscriptions {
            if let Some(subscription) = state.subscriptions.remove(&subscription_id) {
                remove_topic_index(
                    &mut state.tenant_topics,
                    subscription.tenant_id,
                    &subscription.topic,
                    subscription.id,
                );
            }
        }
        Ok(ConnectionState::Closed)
    }

    /// Returns a connection snapshot, or `None` after terminal close.
    ///
    /// # Errors
    ///
    /// Returns [`RegistryError::Unavailable`] if registry state cannot be trusted.
    pub fn connection(
        &self,
        connection_id: ConnectionId,
    ) -> Result<Option<ConnectionSnapshot>, RegistryError> {
        let state = self.lock()?;
        Ok(state
            .connections
            .get(&connection_id)
            .map(ConnectionRecord::snapshot))
    }

    /// Adds one tenant-scoped subscription atomically across all indexes.
    ///
    /// Capacity, connection state, duplicate identifiers, and the immutable principal tenant are
    /// checked before an index is mutated.
    ///
    /// # Errors
    ///
    /// Returns a stable [`RegistryError`] when the connection is inactive, a capacity is reached,
    /// the subscription conflicts, or `tenant_id` differs from the bound principal's active tenant.
    pub fn add_subscription(
        &self,
        connection_id: ConnectionId,
        subscription_id: SubscriptionId,
        tenant_id: TenantId,
        topic: Topic,
        cursor: Option<OpaqueCursor>,
    ) -> Result<SubscriptionSnapshot, RegistryError> {
        let mut state = self.lock()?;

        if let Some(existing) = state.subscriptions.get(&subscription_id) {
            return if existing.connection_id == connection_id
                && existing.tenant_id == tenant_id
                && existing.topic == topic
                && existing.cursor == cursor
            {
                Err(RegistryError::DuplicateSubscription)
            } else {
                Err(RegistryError::SubscriptionConflict)
            };
        }
        if state.subscriptions.len() >= self.config.max_subscriptions {
            return Err(RegistryError::SubscriptionCapacity);
        }

        let connection = state
            .connections
            .get(&connection_id)
            .ok_or(RegistryError::ConnectionNotFound)?;
        if connection.state != ConnectionState::Active {
            return Err(RegistryError::InvalidState);
        }
        if connection.principal.tenant_id != Some(tenant_id) {
            return Err(RegistryError::TenantMismatch);
        }
        if connection.subscriptions.len() >= self.config.max_subscriptions_per_connection {
            return Err(RegistryError::PerConnectionSubscriptionCapacity);
        }
        let subject_id = connection.principal.subject_id;
        let generation = state
            .next_subscription_generation
            .checked_add(1)
            .ok_or(RegistryError::Unavailable)?;
        state.next_subscription_generation = generation;

        let record = SubscriptionRecord {
            id: subscription_id,
            connection_id,
            subject_id,
            tenant_id,
            topic: topic.clone(),
            cursor,
            generation,
            state: SubscriptionState::Active,
        };
        let snapshot = record.snapshot();
        state.subscriptions.insert(subscription_id, record);
        if let Some(connection) = state.connections.get_mut(&connection_id) {
            connection.subscriptions.insert(subscription_id);
        }
        state
            .tenant_topics
            .entry(tenant_id)
            .or_default()
            .entry(topic)
            .or_default()
            .insert(subscription_id);
        Ok(snapshot)
    }

    /// Returns a subscription only when it belongs to `connection_id`.
    ///
    /// This ownership-filtered lookup prevents callers from distinguishing another connection's
    /// subscription identifier from a missing identifier.
    ///
    /// # Errors
    ///
    /// Returns [`RegistryError::Unavailable`] if registry state cannot be trusted.
    pub fn subscription_for_connection(
        &self,
        connection_id: ConnectionId,
        subscription_id: SubscriptionId,
    ) -> Result<Option<SubscriptionSnapshot>, RegistryError> {
        let state = self.lock()?;
        Ok(state
            .subscriptions
            .get(&subscription_id)
            .filter(|subscription| subscription.connection_id == connection_id)
            .map(SubscriptionRecord::snapshot))
    }

    /// Returns a trusted lifecycle view of a subscription by identifier.
    ///
    /// Application command paths should prefer [`Self::subscription_for_connection`].
    ///
    /// # Errors
    ///
    /// Returns [`RegistryError::Unavailable`] if registry state cannot be trusted.
    pub fn subscription(
        &self,
        subscription_id: SubscriptionId,
    ) -> Result<Option<SubscriptionSnapshot>, RegistryError> {
        let state = self.lock()?;
        Ok(state
            .subscriptions
            .get(&subscription_id)
            .map(SubscriptionRecord::snapshot))
    }

    /// Atomically checks that a subscription generation and its connection remain active.
    ///
    /// A missing, replaced, revoked, or connection-inactive subscription returns `false`.
    ///
    /// # Errors
    ///
    /// Returns [`RegistryError::Unavailable`] if registry state cannot be trusted.
    pub fn is_subscription_current_active(
        &self,
        subscription_id: SubscriptionId,
        generation: u64,
    ) -> Result<bool, RegistryError> {
        let state = self.lock()?;
        let Some(subscription) = state.subscriptions.get(&subscription_id) else {
            return Ok(false);
        };
        if subscription.generation != generation || subscription.state != SubscriptionState::Active
        {
            return Ok(false);
        }
        Ok(state
            .connections
            .get(&subscription.connection_id)
            .is_some_and(|connection| connection.state == ConnectionState::Active))
    }

    /// Checks that a subscription identifier still names the exact generation, regardless of
    /// whether that generation is active or revoked.
    ///
    /// A missing or replaced generation returns `false`.
    ///
    /// # Errors
    ///
    /// Returns [`RegistryError::Unavailable`] if registry state cannot be trusted.
    pub fn is_subscription_current_generation(
        &self,
        subscription_id: SubscriptionId,
        generation: u64,
    ) -> Result<bool, RegistryError> {
        let state = self.lock()?;
        Ok(state
            .subscriptions
            .get(&subscription_id)
            .is_some_and(|subscription| subscription.generation == generation))
    }

    /// Atomically removes one subscription from the connection and tenant/topic indexes.
    ///
    /// # Errors
    ///
    /// Returns [`RegistryError::SubscriptionNotFound`] for a missing or foreign subscription.
    pub fn remove_subscription(
        &self,
        connection_id: ConnectionId,
        subscription_id: SubscriptionId,
    ) -> Result<SubscriptionSnapshot, RegistryError> {
        let mut state = self.lock()?;
        remove_subscription_locked(&mut state, connection_id, subscription_id)
    }

    /// Removes a subscription only if it is the same registry generation as `expected`.
    ///
    /// This binds application-service authorization to the record removed under the registry lock,
    /// preventing a concurrently deleted and recreated identifier from being removed under stale
    /// authorization facts.
    ///
    /// # Errors
    ///
    /// Returns [`RegistryError::SubscriptionNotFound`] for a missing or foreign subscription and
    /// [`RegistryError::SubscriptionConflict`] when the identifier now names a newer record.
    pub fn remove_subscription_if_current(
        &self,
        connection_id: ConnectionId,
        expected: &SubscriptionSnapshot,
    ) -> Result<SubscriptionSnapshot, RegistryError> {
        let mut state = self.lock()?;
        let current = state
            .subscriptions
            .get(&expected.id)
            .ok_or(RegistryError::SubscriptionNotFound)?;
        if current.connection_id != connection_id || expected.connection_id != connection_id {
            return Err(RegistryError::SubscriptionNotFound);
        }
        if current.generation != expected.generation {
            return Err(RegistryError::SubscriptionConflict);
        }
        remove_subscription_locked(&mut state, connection_id, expected.id)
    }

    /// Atomically transitions an active subscription to `Revoked` and removes eligibility indexes.
    ///
    /// The returned intent contains no transport handle or queue operation. An adapter may encode
    /// the control output and decide how to terminate or reauthenticate the connection.
    ///
    /// # Errors
    ///
    /// Returns [`RegistryError::InvalidState`] when already revoked and
    /// [`RegistryError::SubscriptionNotFound`] when absent.
    pub fn revoke_subscription(
        &self,
        subscription_id: SubscriptionId,
        reason: RevocationReason,
    ) -> Result<ControlIntent, RegistryError> {
        let mut state = self.lock()?;
        revoke_subscription_locked(&mut state, subscription_id, None, reason)
    }

    /// Revokes a subscription only if it is the same active registry generation as `expected`.
    ///
    /// This prevents an authorization decision made for a removed subscription from revoking a
    /// replacement that reused its identifier.
    ///
    /// # Errors
    ///
    /// Returns [`RegistryError::SubscriptionNotFound`] when absent,
    /// [`RegistryError::SubscriptionConflict`] when replaced, or
    /// [`RegistryError::InvalidState`] when the current generation is already inactive.
    pub fn revoke_subscription_if_current(
        &self,
        expected: &SubscriptionSnapshot,
        reason: RevocationReason,
    ) -> Result<ControlIntent, RegistryError> {
        let mut state = self.lock()?;
        revoke_subscription_locked(&mut state, expected.id, Some(expected.generation), reason)
    }

    /// Creates an incremental traversal for an authoritative tenant/topic key.
    ///
    /// Topic text without `tenant_id` can never select registry entries. The cursor retains no
    /// topic-wide snapshot and each call to [`TopicSubscriptionCursor::next_subscription`] returns
    /// at most one active subscription.
    #[must_use]
    pub fn subscriptions_for_topic(
        &self,
        tenant_id: TenantId,
        topic: &Topic,
    ) -> TopicSubscriptionCursor {
        TopicSubscriptionCursor {
            state: Arc::clone(&self.state),
            tenant_id,
            topic: topic.clone(),
            after: None,
            exhausted: false,
        }
    }

    /// Returns the number of retained connections.
    ///
    /// # Errors
    ///
    /// Returns [`RegistryError::Unavailable`] if registry state cannot be trusted.
    pub fn connection_count(&self) -> Result<usize, RegistryError> {
        Ok(self.lock()?.connections.len())
    }

    /// Returns the number of active plus revoked subscriptions.
    ///
    /// # Errors
    ///
    /// Returns [`RegistryError::Unavailable`] if registry state cannot be trusted.
    pub fn subscription_count(&self) -> Result<usize, RegistryError> {
        Ok(self.lock()?.subscriptions.len())
    }
}

fn revoke_subscription_locked(
    state: &mut RegistryState,
    subscription_id: SubscriptionId,
    expected_generation: Option<u64>,
    reason: RevocationReason,
) -> Result<ControlIntent, RegistryError> {
    let (connection_id, subscription_generation, tenant_id, topic) = {
        let subscription = state
            .subscriptions
            .get_mut(&subscription_id)
            .ok_or(RegistryError::SubscriptionNotFound)?;
        if expected_generation.is_some_and(|generation| generation != subscription.generation) {
            return Err(RegistryError::SubscriptionConflict);
        }
        if subscription.state != SubscriptionState::Active {
            return Err(RegistryError::InvalidState);
        }
        subscription.state = SubscriptionState::Revoked;
        (
            subscription.connection_id,
            subscription.generation,
            subscription.tenant_id,
            subscription.topic.clone(),
        )
    };
    remove_topic_index(&mut state.tenant_topics, tenant_id, &topic, subscription_id);
    Ok(ControlIntent {
        connection_id,
        subscription_generation,
        subscription_id,
        output: ControlOutput::subscription_revoked(subscription_id, reason),
    })
}

fn remove_subscription_locked(
    state: &mut RegistryState,
    connection_id: ConnectionId,
    subscription_id: SubscriptionId,
) -> Result<SubscriptionSnapshot, RegistryError> {
    let existing = state
        .subscriptions
        .get(&subscription_id)
        .ok_or(RegistryError::SubscriptionNotFound)?;
    if existing.connection_id != connection_id {
        return Err(RegistryError::SubscriptionNotFound);
    }

    let mut subscription = state
        .subscriptions
        .remove(&subscription_id)
        .ok_or(RegistryError::SubscriptionNotFound)?;
    if let Some(connection) = state.connections.get_mut(&connection_id) {
        connection.subscriptions.remove(&subscription_id);
    }
    remove_topic_index(
        &mut state.tenant_topics,
        subscription.tenant_id,
        &subscription.topic,
        subscription.id,
    );
    subscription.state = SubscriptionState::Removed;
    Ok(subscription.snapshot())
}

fn remove_topic_index(
    tenant_topics: &mut HashMap<TenantId, HashMap<Topic, BTreeSet<SubscriptionId>>>,
    tenant_id: TenantId,
    topic: &Topic,
    subscription_id: SubscriptionId,
) {
    let remove_tenant = if let Some(topics) = tenant_topics.get_mut(&tenant_id) {
        let remove_topic = if let Some(subscriptions) = topics.get_mut(topic) {
            subscriptions.remove(&subscription_id);
            subscriptions.is_empty()
        } else {
            false
        };
        if remove_topic {
            topics.remove(topic);
        }
        topics.is_empty()
    } else {
        false
    };
    if remove_tenant {
        tenant_topics.remove(&tenant_id);
    }
}

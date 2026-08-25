//! Authenticated, bounded Axum WebSocket transport for realtime commands.
//!
//! Application composition supplies the shared session/bearer identity implementation. This
//! crate validates the upgrade boundary, binds a canonical [`Principal`], and sends command
//! replies synchronously through [`RealtimeService`]. It intentionally owns no provider ingress,
//! fan-out source, outbound queue, replay path, slow-consumer policy, or drain protocol.

#![forbid(unsafe_code)]

use std::{
    collections::HashMap,
    error::Error as _,
    future::Future,
    net::{IpAddr, SocketAddr},
    pin::Pin,
    sync::{
        Arc, Mutex, MutexGuard,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

use axum::{
    Router,
    body::Body,
    extract::{
        ConnectInfo, FromRequestParts, State, WebSocketUpgrade,
        ws::{CloseFrame, Message, WebSocket},
    },
    http::{
        HeaderMap, HeaderValue, Request, StatusCode,
        header::{ORIGIN, SEC_WEBSOCKET_PROTOCOL},
    },
    response::{IntoResponse, Response},
    routing::get,
};
use futures::SinkExt as _;
use rsk_auth_core::{Principal, SubjectId, TenantId};
use rsk_authz_basic::AuthorizationProvider;
use rsk_core::{ErrorCode, RequestId, ServiceError};
use rsk_http::ProblemDetails;
use rsk_realtime_core::{
    CommandAuthorizationResolver, ConnectionId, ConnectionRegistry, InboundCommand,
    MAX_CONNECTIONS, MAX_ENVELOPE_BYTES, RealtimeService,
};
use thiserror::Error;
use tokio::time::{Instant, MissedTickBehavior};
use tokio_tungstenite::tungstenite::{Error as TungsteniteError, error::CapacityError};
use url::Url;

/// Exact public WebSocket endpoint.
pub const WEBSOCKET_PATH: &str = "/realtime/ws";
/// Required versioned WebSocket subprotocol.
pub const WEBSOCKET_PROTOCOL: &str = "rsk.realtime.v1";
/// Default aggregate request-header byte limit.
pub const DEFAULT_MAX_HEADER_BYTES: usize = 64 * 1024;
/// Default request-header entry limit.
pub const DEFAULT_MAX_HEADER_COUNT: usize = 100;
/// Default deadline for initial session or bearer authentication.
pub const DEFAULT_AUTHENTICATION_TIMEOUT: Duration = Duration::from_secs(5);
/// Default interval between WebSocket Ping frames.
pub const DEFAULT_HEARTBEAT_INTERVAL: Duration = Duration::from_secs(15);
/// Default deadline for the matching WebSocket Pong frame.
pub const DEFAULT_PONG_DEADLINE: Duration = Duration::from_secs(10);
/// Default cadence for authoritative identity revalidation.
pub const DEFAULT_REVALIDATION_INTERVAL: Duration = Duration::from_secs(60);
/// Default maximum accepted WebSocket lifetime.
pub const DEFAULT_MAXIMUM_LIFETIME: Duration = Duration::from_hours(12);
/// Default concurrent connections accepted from one immediate peer IP.
pub const DEFAULT_MAX_CONNECTIONS_PER_IP: usize = 64;
/// Default concurrent connections accepted for one principal.
pub const DEFAULT_MAX_CONNECTIONS_PER_PRINCIPAL: usize = 8;
/// Default concurrent connections accepted for one tenant.
pub const DEFAULT_MAX_CONNECTIONS_PER_TENANT: usize = 256;
/// Default pending authentication attempts accepted from one immediate peer IP.
pub const DEFAULT_MAX_PENDING_UPGRADES_PER_IP: usize = 8;

const MAX_TRUSTED_ORIGINS: usize = 64;
const MAX_ORIGIN_BYTES: usize = 2 * 1024;
const HARD_MAX_HEADER_BYTES: usize = 1024 * 1024;
const HARD_MAX_HEADER_COUNT: usize = 1024;
const MIN_AUTHENTICATION_TIMEOUT: Duration = Duration::from_millis(10);
const MAX_AUTHENTICATION_TIMEOUT: Duration = Duration::from_secs(30);
const MIN_LIVENESS_INTERVAL: Duration = Duration::from_millis(10);
const MAX_HEARTBEAT_INTERVAL: Duration = Duration::from_mins(5);
const MAX_REVALIDATION_INTERVAL: Duration = Duration::from_hours(1);
const MINIMUM_LIFETIME: Duration = Duration::from_millis(20);
const MAXIMUM_LIFETIME: Duration = Duration::from_hours(24);
const CLOSE_SEND_TIMEOUT: Duration = Duration::from_secs(1);

const CLOSE_UNSUPPORTED_DATA: u16 = 1003;
const CLOSE_GOING_AWAY: u16 = 1001;
const CLOSE_PROTOCOL_ERROR: u16 = 1002;
const CLOSE_POLICY_VIOLATION: u16 = 1008;
const CLOSE_MESSAGE_TOO_BIG: u16 = 1009;
const CLOSE_INTERNAL_ERROR: u16 = 1011;

/// Invalid bounded WebSocket transport configuration.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum WebSocketConfigError {
    /// At least one exact trusted HTTP(S) origin is required.
    #[error("WebSocket trusted origins must not be empty")]
    EmptyTrustedOrigins,
    /// The trusted-origin allowlist exceeds its fixed entry bound.
    #[error("WebSocket trusted-origin allowlist exceeds its limit")]
    TooManyTrustedOrigins,
    /// A trusted origin is malformed, non-canonical, duplicated, or too long.
    #[error("invalid trusted WebSocket origin")]
    InvalidTrustedOrigin,
    /// A request-header limit is zero or exceeds its hard ceiling.
    #[error("invalid WebSocket request-header limits")]
    InvalidHeaderLimits,
    /// The initial authentication deadline falls outside its fixed bounds.
    #[error("invalid WebSocket authentication timeout")]
    InvalidAuthenticationTimeout,
    /// The message limit is zero or exceeds the realtime envelope limit.
    #[error("invalid WebSocket message limit")]
    InvalidMessageLimit,
    /// The Ping interval falls outside its fixed transport bounds.
    #[error("invalid WebSocket heartbeat interval")]
    InvalidHeartbeatInterval,
    /// The Pong deadline is invalid or exceeds the Ping interval.
    #[error("invalid WebSocket Pong deadline")]
    InvalidPongDeadline,
    /// The identity revalidation cadence falls outside its fixed bounds.
    #[error("invalid WebSocket identity revalidation interval")]
    InvalidRevalidationInterval,
    /// The maximum connection lifetime falls outside its fixed bounds.
    #[error("invalid WebSocket maximum lifetime")]
    InvalidMaximumLifetime,
    /// A per-scope connection limit is zero or exceeds the registry hard ceiling.
    #[error("invalid WebSocket per-scope connection limits")]
    InvalidConnectionLimits,
}

/// Validated concurrent-connection ceilings for every authoritative scope.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ConnectionLimitConfig {
    ip: usize,
    principal: usize,
    tenant: usize,
    pending_ip: usize,
}

impl ConnectionLimitConfig {
    /// Creates validated per-IP, per-principal, and per-tenant ceilings.
    ///
    /// # Errors
    ///
    /// Returns [`WebSocketConfigError::InvalidConnectionLimits`] if a limit is zero or exceeds
    /// the registry's fixed hard connection ceiling.
    pub const fn new(
        max_per_ip: usize,
        max_per_principal: usize,
        max_per_tenant: usize,
    ) -> Result<Self, WebSocketConfigError> {
        if max_per_ip == 0
            || max_per_principal == 0
            || max_per_tenant == 0
            || max_per_ip > MAX_CONNECTIONS
            || max_per_principal > MAX_CONNECTIONS
            || max_per_tenant > MAX_CONNECTIONS
        {
            return Err(WebSocketConfigError::InvalidConnectionLimits);
        }
        Ok(Self {
            ip: max_per_ip,
            principal: max_per_principal,
            tenant: max_per_tenant,
            pending_ip: max_per_ip,
        })
    }

    /// Replaces the pending-authentication ceiling for one immediate peer IP.
    ///
    /// # Errors
    ///
    /// Returns [`WebSocketConfigError::InvalidConnectionLimits`] for zero or excessive limits.
    pub const fn with_max_pending_per_ip(
        mut self,
        max_pending_per_ip: usize,
    ) -> Result<Self, WebSocketConfigError> {
        if max_pending_per_ip == 0 || max_pending_per_ip > MAX_CONNECTIONS {
            return Err(WebSocketConfigError::InvalidConnectionLimits);
        }
        self.pending_ip = max_pending_per_ip;
        Ok(self)
    }

    /// Returns the immediate-peer IP ceiling.
    #[must_use]
    pub const fn max_per_ip(self) -> usize {
        self.ip
    }

    /// Returns the principal ceiling.
    #[must_use]
    pub const fn max_per_principal(self) -> usize {
        self.principal
    }

    /// Returns the tenant ceiling.
    #[must_use]
    pub const fn max_per_tenant(self) -> usize {
        self.tenant
    }

    /// Returns the pending-authentication ceiling for one immediate peer IP.
    #[must_use]
    pub const fn max_pending_per_ip(self) -> usize {
        self.pending_ip
    }
}

impl Default for ConnectionLimitConfig {
    fn default() -> Self {
        Self {
            ip: DEFAULT_MAX_CONNECTIONS_PER_IP,
            principal: DEFAULT_MAX_CONNECTIONS_PER_PRINCIPAL,
            tenant: DEFAULT_MAX_CONNECTIONS_PER_TENANT,
            pending_ip: DEFAULT_MAX_PENDING_UPGRADES_PER_IP,
        }
    }
}

/// Validated WebSocket upgrade, message, liveness, and lifetime configuration.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WebSocketConfig {
    trusted_origins: Box<[HeaderValue]>,
    max_header_bytes: usize,
    max_header_count: usize,
    authentication_timeout: Duration,
    max_message_bytes: usize,
    heartbeat_interval: Duration,
    pong_deadline: Duration,
    revalidation_interval: Duration,
    maximum_lifetime: Duration,
    connection_limits: ConnectionLimitConfig,
}

impl WebSocketConfig {
    /// Creates default bounded transport settings for a nonempty exact origin allowlist.
    ///
    /// Each origin must be a canonical serialized HTTP(S) origin such as
    /// `https://app.example.com`; paths, credentials, query strings, fragments, opaque origins,
    /// duplicates, and a trailing slash are rejected.
    ///
    /// # Errors
    ///
    /// Returns [`WebSocketConfigError`] when the origin allowlist is empty or invalid.
    pub fn new<I, S>(trusted_origins: I) -> Result<Self, WebSocketConfigError>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let mut origins = Vec::new();
        for origin in trusted_origins {
            if origins.len() == MAX_TRUSTED_ORIGINS {
                return Err(WebSocketConfigError::TooManyTrustedOrigins);
            }
            let origin = origin.as_ref();
            if origin.is_empty() || origin.len() > MAX_ORIGIN_BYTES {
                return Err(WebSocketConfigError::InvalidTrustedOrigin);
            }
            let parsed =
                Url::parse(origin).map_err(|_| WebSocketConfigError::InvalidTrustedOrigin)?;
            if !matches!(parsed.scheme(), "http" | "https")
                || parsed.host().is_none()
                || !parsed.username().is_empty()
                || parsed.password().is_some()
                || parsed.path() != "/"
                || parsed.query().is_some()
                || parsed.fragment().is_some()
                || parsed.origin().ascii_serialization() != origin
            {
                return Err(WebSocketConfigError::InvalidTrustedOrigin);
            }
            let header = HeaderValue::from_str(origin)
                .map_err(|_| WebSocketConfigError::InvalidTrustedOrigin)?;
            if origins
                .iter()
                .any(|existing: &HeaderValue| existing.as_bytes() == header.as_bytes())
            {
                return Err(WebSocketConfigError::InvalidTrustedOrigin);
            }
            origins.push(header);
        }
        if origins.is_empty() {
            return Err(WebSocketConfigError::EmptyTrustedOrigins);
        }
        Ok(Self {
            trusted_origins: origins.into_boxed_slice(),
            authentication_timeout: DEFAULT_AUTHENTICATION_TIMEOUT,
            max_header_bytes: DEFAULT_MAX_HEADER_BYTES,
            max_header_count: DEFAULT_MAX_HEADER_COUNT,
            max_message_bytes: MAX_ENVELOPE_BYTES,
            heartbeat_interval: DEFAULT_HEARTBEAT_INTERVAL,
            pong_deadline: DEFAULT_PONG_DEADLINE,
            revalidation_interval: DEFAULT_REVALIDATION_INTERVAL,
            maximum_lifetime: DEFAULT_MAXIMUM_LIFETIME,
            connection_limits: ConnectionLimitConfig::default(),
        })
    }

    /// Replaces the aggregate request-header limits.
    ///
    /// # Errors
    ///
    /// Returns [`WebSocketConfigError::InvalidHeaderLimits`] for zero or excessive limits.
    pub fn with_header_limits(
        mut self,
        max_header_count: usize,
        max_header_bytes: usize,
    ) -> Result<Self, WebSocketConfigError> {
        if max_header_count == 0
            || max_header_count > HARD_MAX_HEADER_COUNT
            || max_header_bytes == 0
            || max_header_bytes > HARD_MAX_HEADER_BYTES
        {
            return Err(WebSocketConfigError::InvalidHeaderLimits);
        }
        self.max_header_count = max_header_count;
        self.max_header_bytes = max_header_bytes;
        Ok(self)
    }

    /// Replaces the deadline for initial session or bearer authentication.
    ///
    /// # Errors
    ///
    /// Returns [`WebSocketConfigError::InvalidAuthenticationTimeout`] outside fixed bounds.
    pub fn with_authentication_timeout(
        mut self,
        authentication_timeout: Duration,
    ) -> Result<Self, WebSocketConfigError> {
        if !(MIN_AUTHENTICATION_TIMEOUT..=MAX_AUTHENTICATION_TIMEOUT)
            .contains(&authentication_timeout)
        {
            return Err(WebSocketConfigError::InvalidAuthenticationTimeout);
        }
        self.authentication_timeout = authentication_timeout;
        Ok(self)
    }

    /// Replaces the maximum reassembled inbound message size.
    ///
    /// # Errors
    ///
    /// Returns [`WebSocketConfigError::InvalidMessageLimit`] unless the limit is within the core
    /// envelope bound.
    pub fn with_max_message_bytes(
        mut self,
        max_message_bytes: usize,
    ) -> Result<Self, WebSocketConfigError> {
        if max_message_bytes == 0 || max_message_bytes > MAX_ENVELOPE_BYTES {
            return Err(WebSocketConfigError::InvalidMessageLimit);
        }
        self.max_message_bytes = max_message_bytes;
        Ok(self)
    }

    /// Replaces all independently enforced liveness and lifetime durations.
    ///
    /// The Pong deadline also caps each identity-revalidation and socket-write await; the
    /// absolute lifetime and any active Pong deadline remain the earlier hard stop.
    ///
    /// # Errors
    ///
    /// Returns a duration-specific [`WebSocketConfigError`] when a duration is outside its fixed
    /// bounds or when `pong_deadline` exceeds `heartbeat_interval`.
    pub fn with_liveness(
        mut self,
        heartbeat_interval: Duration,
        pong_deadline: Duration,
        revalidation_interval: Duration,
        maximum_lifetime: Duration,
    ) -> Result<Self, WebSocketConfigError> {
        if !(MIN_LIVENESS_INTERVAL..=MAX_HEARTBEAT_INTERVAL).contains(&heartbeat_interval) {
            return Err(WebSocketConfigError::InvalidHeartbeatInterval);
        }
        if !(MIN_LIVENESS_INTERVAL..=heartbeat_interval).contains(&pong_deadline) {
            return Err(WebSocketConfigError::InvalidPongDeadline);
        }
        if !(MIN_LIVENESS_INTERVAL..=MAX_REVALIDATION_INTERVAL).contains(&revalidation_interval) {
            return Err(WebSocketConfigError::InvalidRevalidationInterval);
        }
        if !(MINIMUM_LIFETIME..=MAXIMUM_LIFETIME).contains(&maximum_lifetime) {
            return Err(WebSocketConfigError::InvalidMaximumLifetime);
        }
        self.heartbeat_interval = heartbeat_interval;
        self.pong_deadline = pong_deadline;
        self.revalidation_interval = revalidation_interval;
        self.maximum_lifetime = maximum_lifetime;
        Ok(self)
    }

    /// Replaces the validated per-scope connection ceilings.
    #[must_use]
    pub const fn with_connection_limits(mut self, limits: ConnectionLimitConfig) -> Self {
        self.connection_limits = limits;
        self
    }

    /// Returns the exact trusted Origin values.
    #[must_use]
    pub fn trusted_origins(&self) -> &[HeaderValue] {
        &self.trusted_origins
    }

    /// Returns the aggregate request-header byte limit.
    #[must_use]
    pub const fn max_header_bytes(&self) -> usize {
        self.max_header_bytes
    }

    /// Returns the request-header entry limit.
    #[must_use]
    pub const fn max_header_count(&self) -> usize {
        self.max_header_count
    }

    /// Returns the initial session or bearer authentication deadline.
    #[must_use]
    pub const fn authentication_timeout(&self) -> Duration {
        self.authentication_timeout
    }

    /// Returns the maximum reassembled inbound message size.
    #[must_use]
    pub const fn max_message_bytes(&self) -> usize {
        self.max_message_bytes
    }

    /// Returns the WebSocket Ping interval.
    #[must_use]
    pub const fn heartbeat_interval(&self) -> Duration {
        self.heartbeat_interval
    }

    /// Returns the matching Pong deadline.
    #[must_use]
    pub const fn pong_deadline(&self) -> Duration {
        self.pong_deadline
    }

    /// Returns the authoritative identity revalidation cadence.
    #[must_use]
    pub const fn revalidation_interval(&self) -> Duration {
        self.revalidation_interval
    }

    /// Returns the maximum connection lifetime.
    #[must_use]
    pub const fn maximum_lifetime(&self) -> Duration {
        self.maximum_lifetime
    }

    /// Returns the per-scope connection ceilings.
    #[must_use]
    pub const fn connection_limits(&self) -> ConnectionLimitConfig {
        self.connection_limits
    }
}

/// Stable initial-authentication failure classification.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum WebSocketAuthenticationError {
    /// No supported session or bearer credential was supplied.
    #[error("WebSocket authentication is required")]
    Missing,
    /// The selected credential was rejected without exposing the reason.
    #[error("WebSocket authentication was rejected")]
    Rejected,
    /// Authoritative authentication state could not be established safely.
    #[error("WebSocket authentication is unavailable")]
    Unavailable,
}

/// Authoritative status returned for an already-bound principal.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IdentityRevalidation {
    /// The principal remains active.
    Active,
    /// The principal expired, was revoked, or is otherwise no longer active.
    Revoked,
    /// Authoritative identity state could not be established safely.
    Unavailable,
}

/// Future returned by initial WebSocket authentication.
pub type AuthenticationFuture<'a> =
    Pin<Box<dyn Future<Output = Result<Principal, WebSocketAuthenticationError>> + Send + 'a>>;
/// Future returned by authoritative identity revalidation.
pub type RevalidationFuture<'a> = Pin<Box<dyn Future<Output = IdentityRevalidation> + Send + 'a>>;

/// Shared application identity boundary for the WebSocket adapter.
///
/// Implementations must reuse the application's canonical session and bearer authentication logic,
/// including bearer precedence when both mechanisms are present. They must not include raw
/// credentials, session identifiers, or provider errors in returned classifications.
pub trait WebSocketIdentity: Send + Sync + 'static {
    /// Authenticates request headers into the canonical principal before Origin or subprotocol
    /// validation can disclose WebSocket-specific policy.
    fn authenticate<'a>(&'a self, headers: &'a HeaderMap) -> AuthenticationFuture<'a>;

    /// Revalidates the immutable principal against authoritative expiry and revocation state.
    fn revalidate<'a>(&'a self, principal: &'a Principal) -> RevalidationFuture<'a>;
}

/// Stable atomic connection-limiter failure.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum ConnectionLimitError {
    /// Realtime WebSocket connections require an authenticated tenant context.
    #[error("WebSocket principal has no tenant context")]
    TenantRequired,
    /// At least one authoritative scope has reached its configured ceiling.
    #[error("WebSocket connection limit is reached")]
    Capacity,
    /// Limiter state cannot be trusted safely.
    #[error("WebSocket connection limiter is unavailable")]
    Unavailable,
}

/// Current counts for one authoritative peer/principal/tenant tuple.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ConnectionLimitUsage {
    /// Active leases for the immediate peer IP.
    pub peer_ip: usize,
    /// Active leases for the principal.
    pub principal: usize,
    /// Active leases for the tenant.
    pub tenant: usize,
}

#[derive(Debug, Default)]
struct ConnectionCounts {
    ips: HashMap<IpAddr, usize>,
    principals: HashMap<SubjectId, usize>,
    tenants: HashMap<TenantId, usize>,
    pending_ips: HashMap<IpAddr, usize>,
}

#[derive(Debug)]
struct ConnectionLimiterInner {
    config: ConnectionLimitConfig,
    counts: Mutex<ConnectionCounts>,
}

/// Bounded atomic per-IP, per-principal, and per-tenant connection limiter.
#[derive(Clone, Debug)]
pub struct ConnectionLimiter {
    inner: Arc<ConnectionLimiterInner>,
}

impl ConnectionLimiter {
    /// Creates an empty limiter with validated fixed ceilings.
    #[must_use]
    pub fn new(config: ConnectionLimitConfig) -> Self {
        Self {
            inner: Arc::new(ConnectionLimiterInner {
                config,
                counts: Mutex::new(ConnectionCounts::default()),
            }),
        }
    }

    /// Acquires one bounded pending-authentication slot for the immediate peer.
    ///
    /// # Errors
    ///
    /// Returns [`ConnectionLimitError::Capacity`] when the peer's pending ceiling is reached, or
    /// [`ConnectionLimitError::Unavailable`] if limiter state cannot be trusted.
    pub fn acquire_pending(
        &self,
        peer_ip: IpAddr,
    ) -> Result<PendingUpgradeLease, ConnectionLimitError> {
        let mut counts = self
            .inner
            .counts
            .lock()
            .map_err(|_| ConnectionLimitError::Unavailable)?;
        if counts
            .pending_ips
            .get(&peer_ip)
            .copied()
            .unwrap_or_default()
            >= self.inner.config.pending_ip
        {
            return Err(ConnectionLimitError::Capacity);
        }
        *counts.pending_ips.entry(peer_ip).or_default() += 1;
        drop(counts);
        Ok(PendingUpgradeLease {
            inner: Arc::clone(&self.inner),
            peer_ip,
            held: true,
        })
    }

    /// Atomically acquires all three authoritative scopes.
    ///
    /// The peer IP must come from the immediate socket peer, never a client-forwarded header.
    /// No count is changed when any scope is already full.
    ///
    /// # Errors
    ///
    /// Returns a stable error for a missing tenant, exhausted scope, or unavailable limiter.
    pub fn acquire(
        &self,
        peer_ip: IpAddr,
        principal: &Principal,
    ) -> Result<ConnectionLease, ConnectionLimitError> {
        let tenant_id = principal
            .tenant_id
            .ok_or(ConnectionLimitError::TenantRequired)?;
        let mut counts = self
            .inner
            .counts
            .lock()
            .map_err(|_| ConnectionLimitError::Unavailable)?;
        let ip_count = counts.ips.get(&peer_ip).copied().unwrap_or_default();
        let principal_count = counts
            .principals
            .get(&principal.subject_id)
            .copied()
            .unwrap_or_default();
        let tenant_count = counts.tenants.get(&tenant_id).copied().unwrap_or_default();
        if ip_count >= self.inner.config.ip
            || principal_count >= self.inner.config.principal
            || tenant_count >= self.inner.config.tenant
        {
            return Err(ConnectionLimitError::Capacity);
        }
        *counts.ips.entry(peer_ip).or_default() += 1;
        *counts.principals.entry(principal.subject_id).or_default() += 1;
        *counts.tenants.entry(tenant_id).or_default() += 1;
        drop(counts);
        Ok(ConnectionLease {
            inner: Arc::clone(&self.inner),
            peer_ip,
            subject_id: principal.subject_id,
            tenant_id,
            held: true,
        })
    }

    /// Returns counts for one authoritative tuple without changing limiter state.
    ///
    /// # Errors
    ///
    /// Returns a stable error when the principal lacks a tenant or limiter state is unavailable.
    pub fn usage(
        &self,
        peer_ip: IpAddr,
        principal: &Principal,
    ) -> Result<ConnectionLimitUsage, ConnectionLimitError> {
        let tenant_id = principal
            .tenant_id
            .ok_or(ConnectionLimitError::TenantRequired)?;
        let counts = self
            .inner
            .counts
            .lock()
            .map_err(|_| ConnectionLimitError::Unavailable)?;
        Ok(ConnectionLimitUsage {
            peer_ip: counts.ips.get(&peer_ip).copied().unwrap_or_default(),
            principal: counts
                .principals
                .get(&principal.subject_id)
                .copied()
                .unwrap_or_default(),
            tenant: counts.tenants.get(&tenant_id).copied().unwrap_or_default(),
        })
    }

    /// Returns pending authentication attempts retained for one immediate peer IP.
    ///
    /// # Errors
    ///
    /// Returns [`ConnectionLimitError::Unavailable`] if limiter state cannot be trusted.
    pub fn pending_for_ip(&self, peer_ip: IpAddr) -> Result<usize, ConnectionLimitError> {
        let counts = self
            .inner
            .counts
            .lock()
            .map_err(|_| ConnectionLimitError::Unavailable)?;
        Ok(counts
            .pending_ips
            .get(&peer_ip)
            .copied()
            .unwrap_or_default())
    }
}

/// RAII ownership of one pending initial-authentication slot.
#[derive(Debug)]
#[must_use = "dropping the pending lease releases its immediate-peer slot"]
pub struct PendingUpgradeLease {
    inner: Arc<ConnectionLimiterInner>,
    peer_ip: IpAddr,
    held: bool,
}

impl PendingUpgradeLease {
    /// Atomically replaces the pending slot with active IP, principal, and tenant scopes.
    ///
    /// # Errors
    ///
    /// Returns a stable error for a missing tenant, exhausted active scope, or unavailable
    /// limiter. On error, dropping `self` releases the pending slot.
    pub fn promote(
        mut self,
        principal: &Principal,
    ) -> Result<ConnectionLease, ConnectionLimitError> {
        let tenant_id = principal
            .tenant_id
            .ok_or(ConnectionLimitError::TenantRequired)?;
        let mut counts = self
            .inner
            .counts
            .lock()
            .map_err(|_| ConnectionLimitError::Unavailable)?;
        let ip_count = counts.ips.get(&self.peer_ip).copied().unwrap_or_default();
        let principal_count = counts
            .principals
            .get(&principal.subject_id)
            .copied()
            .unwrap_or_default();
        let tenant_count = counts.tenants.get(&tenant_id).copied().unwrap_or_default();
        if ip_count >= self.inner.config.ip
            || principal_count >= self.inner.config.principal
            || tenant_count >= self.inner.config.tenant
        {
            return Err(ConnectionLimitError::Capacity);
        }
        decrement_or_remove(&mut counts.pending_ips, &self.peer_ip);
        *counts.ips.entry(self.peer_ip).or_default() += 1;
        *counts.principals.entry(principal.subject_id).or_default() += 1;
        *counts.tenants.entry(tenant_id).or_default() += 1;
        self.held = false;
        drop(counts);
        Ok(ConnectionLease {
            inner: Arc::clone(&self.inner),
            peer_ip: self.peer_ip,
            subject_id: principal.subject_id,
            tenant_id,
            held: true,
        })
    }

    /// Releases the pending slot immediately. Repeated release is idempotent.
    pub fn release(&mut self) {
        if !self.held {
            return;
        }
        let mut counts = lock_even_if_poisoned(&self.inner.counts);
        decrement_or_remove(&mut counts.pending_ips, &self.peer_ip);
        self.held = false;
    }
}

impl Drop for PendingUpgradeLease {
    fn drop(&mut self) {
        self.release();
    }
}

/// RAII ownership of one atomically acquired connection-limit tuple.
#[derive(Debug)]
#[must_use = "dropping the connection lease releases every acquired scope"]
pub struct ConnectionLease {
    inner: Arc<ConnectionLimiterInner>,
    peer_ip: IpAddr,
    subject_id: SubjectId,
    tenant_id: TenantId,
    held: bool,
}

impl ConnectionLease {
    /// Releases every scope immediately. Repeated release is idempotent.
    pub fn release(&mut self) {
        if !self.held {
            return;
        }
        let mut counts = lock_even_if_poisoned(&self.inner.counts);
        decrement_or_remove(&mut counts.ips, &self.peer_ip);
        decrement_or_remove(&mut counts.principals, &self.subject_id);
        decrement_or_remove(&mut counts.tenants, &self.tenant_id);
        self.held = false;
    }
}

impl Drop for ConnectionLease {
    fn drop(&mut self) {
        self.release();
    }
}

fn lock_even_if_poisoned<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    match mutex.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    }
}

fn decrement_or_remove<K>(counts: &mut HashMap<K, usize>, key: &K)
where
    K: Eq + std::hash::Hash,
{
    if counts.get(key).copied().is_some_and(|count| count > 1) {
        if let Some(count) = counts.get_mut(key) {
            *count -= 1;
        }
    } else {
        counts.remove(key);
    }
}

/// Shared state for the exact WebSocket route.
pub struct WebSocketState<P, R, I> {
    service: Arc<RealtimeService<P, R>>,
    identity: Arc<I>,
    limiter: ConnectionLimiter,
    config: WebSocketConfig,
}

impl<P, R, I> WebSocketState<P, R, I> {
    /// Creates route state and one shared atomic limiter from validated configuration.
    #[must_use]
    pub fn new(
        service: Arc<RealtimeService<P, R>>,
        identity: Arc<I>,
        config: WebSocketConfig,
    ) -> Self {
        let limiter = ConnectionLimiter::new(config.connection_limits());
        Self {
            service,
            identity,
            limiter,
            config,
        }
    }

    /// Returns the validated transport configuration.
    #[must_use]
    pub const fn config(&self) -> &WebSocketConfig {
        &self.config
    }

    /// Returns the shared connection limiter for bounded observability.
    #[must_use]
    pub const fn limiter(&self) -> &ConnectionLimiter {
        &self.limiter
    }
}

impl<P, R, I> Clone for WebSocketState<P, R, I> {
    fn clone(&self) -> Self {
        Self {
            service: Arc::clone(&self.service),
            identity: Arc::clone(&self.identity),
            limiter: self.limiter.clone(),
            config: self.config.clone(),
        }
    }
}

/// Builds a router exposing exactly authenticated `GET /realtime/ws`.
///
/// The serving Axum adapter must use `into_make_service_with_connect_info::<SocketAddr>()` so the
/// limiter receives the immediate socket peer. Application composition must supply a
/// [`WebSocketIdentity`] backed by its shared session/bearer service; this router is intentionally
/// not attached to any application profile by this crate.
pub fn websocket_router<P, R, I>(state: WebSocketState<P, R, I>) -> Router
where
    P: AuthorizationProvider + Send + Sync + 'static,
    R: CommandAuthorizationResolver + Send + Sync + 'static,
    I: WebSocketIdentity,
{
    Router::new()
        .route(WEBSOCKET_PATH, get(websocket::<P, R, I>))
        .with_state(state)
}

async fn websocket<P, R, I>(
    State(state): State<WebSocketState<P, R, I>>,
    request: Request<Body>,
) -> Response
where
    P: AuthorizationProvider + Send + Sync + 'static,
    R: CommandAuthorizationResolver + Send + Sync + 'static,
    I: WebSocketIdentity,
{
    let (mut parts, _) = request.into_parts();
    let request_id = parts
        .extensions
        .get::<RequestId>()
        .copied()
        .unwrap_or_else(RequestId::new);

    if !headers_within_bounds(&parts.headers, &state.config) {
        return problem_response(
            StatusCode::REQUEST_HEADER_FIELDS_TOO_LARGE,
            "WEBSOCKET_REQUEST_HEADERS_TOO_LARGE",
            "WebSocket request headers exceed configured limits",
            request_id,
        );
    }

    let prepared = match prepare_upgrade(&state, &mut parts, request_id).await {
        Ok(prepared) => prepared,
        Err(response) => return response,
    };
    let PreparedUpgrade {
        upgrade,
        principal,
        lease,
    } = prepared;
    let registry = state.service.registry().clone();
    let principal_for_revalidation = principal.clone();
    let Ok(connection) = registry.register(principal) else {
        return unavailable_problem(request_id);
    };
    let lifecycle = Arc::new(RegisteredConnection::new(registry, connection.id(), lease));
    let failed_upgrade_lifecycle = Arc::clone(&lifecycle);
    let service = Arc::clone(&state.service);
    let identity = Arc::clone(&state.identity);
    let config = state.config.clone();

    upgrade
        .protocols([WEBSOCKET_PROTOCOL])
        .read_buffer_size(config.max_message_bytes())
        .write_buffer_size(0)
        .max_write_buffer_size(MAX_ENVELOPE_BYTES + 1)
        .max_frame_size(config.max_message_bytes())
        .max_message_size(config.max_message_bytes())
        .on_failed_upgrade(move |_| failed_upgrade_lifecycle.close())
        .on_upgrade(move |socket| async move {
            run_socket(
                socket,
                service,
                identity,
                principal_for_revalidation,
                config,
                lifecycle,
            )
            .await;
        })
}

struct PreparedUpgrade {
    upgrade: WebSocketUpgrade,
    principal: Principal,
    lease: ConnectionLease,
}

#[expect(
    clippy::result_large_err,
    reason = "rejected upgrades return their complete Axum response directly"
)]
async fn prepare_upgrade<P, R, I>(
    state: &WebSocketState<P, R, I>,
    parts: &mut axum::http::request::Parts,
    request_id: RequestId,
) -> Result<PreparedUpgrade, Response>
where
    P: AuthorizationProvider + Send + Sync + 'static,
    R: CommandAuthorizationResolver + Send + Sync + 'static,
    I: WebSocketIdentity,
{
    let Some(peer_ip) = parts
        .extensions
        .get::<ConnectInfo<SocketAddr>>()
        .map(|connect_info| connect_info.0.ip())
    else {
        return Err(unavailable_problem(request_id));
    };
    let pending = state
        .limiter
        .acquire_pending(peer_ip)
        .map_err(|error| connection_limit_problem(error, request_id))?;
    let principal = authenticate_principal(
        state.identity.as_ref(),
        &parts.headers,
        state.config.authentication_timeout(),
        request_id,
    )
    .await?;
    let upgrade = validate_upgrade_request(parts, state, &state.config, request_id).await?;
    let lease = pending
        .promote(&principal)
        .map_err(|error| connection_limit_problem(error, request_id))?;
    Ok(PreparedUpgrade {
        upgrade,
        principal,
        lease,
    })
}

fn connection_limit_problem(error: ConnectionLimitError, request_id: RequestId) -> Response {
    match error {
        ConnectionLimitError::Capacity => problem_response(
            StatusCode::TOO_MANY_REQUESTS,
            "WEBSOCKET_CONNECTION_LIMIT_REACHED",
            "WebSocket connection capacity is exhausted",
            request_id,
        ),
        ConnectionLimitError::TenantRequired | ConnectionLimitError::Unavailable => {
            unavailable_problem(request_id)
        }
    }
}

#[expect(
    clippy::result_large_err,
    reason = "rejected upgrades return their complete Axum response directly"
)]
async fn validate_upgrade_request<S>(
    parts: &mut axum::http::request::Parts,
    state: &S,
    config: &WebSocketConfig,
    request_id: RequestId,
) -> Result<WebSocketUpgrade, Response>
where
    S: Send + Sync,
{
    if !origin_is_allowed(&parts.headers, config) {
        return Err(problem_response(
            StatusCode::FORBIDDEN,
            "WEBSOCKET_ORIGIN_FORBIDDEN",
            "WebSocket Origin is not allowed",
            request_id,
        ));
    }
    if !required_subprotocol_offered(&parts.headers) {
        return Err(problem_response(
            StatusCode::BAD_REQUEST,
            "WEBSOCKET_SUBPROTOCOL_REQUIRED",
            "the required WebSocket subprotocol was not offered",
            request_id,
        ));
    }
    let Ok(upgrade) = WebSocketUpgrade::from_request_parts(parts, state).await else {
        return Err(problem_response(
            StatusCode::BAD_REQUEST,
            "WEBSOCKET_UPGRADE_INVALID",
            "the WebSocket upgrade request is invalid",
            request_id,
        ));
    };
    Ok(upgrade)
}

#[expect(
    clippy::result_large_err,
    reason = "authentication failures return their complete Axum response directly"
)]
async fn authenticate_principal<I>(
    identity: &I,
    headers: &HeaderMap,
    authentication_timeout: Duration,
    request_id: RequestId,
) -> Result<Principal, Response>
where
    I: WebSocketIdentity,
{
    let authentication =
        tokio::time::timeout(authentication_timeout, identity.authenticate(headers)).await;
    let principal = match authentication {
        Ok(Ok(principal)) => principal,
        Ok(Err(WebSocketAuthenticationError::Missing)) => {
            return Err(problem_response(
                StatusCode::UNAUTHORIZED,
                "WEBSOCKET_AUTHENTICATION_REQUIRED",
                "WebSocket authentication is required",
                request_id,
            ));
        }
        Ok(Err(WebSocketAuthenticationError::Rejected)) => {
            return Err(problem_response(
                StatusCode::UNAUTHORIZED,
                "WEBSOCKET_AUTHENTICATION_REJECTED",
                "WebSocket authentication was rejected",
                request_id,
            ));
        }
        Ok(Err(WebSocketAuthenticationError::Unavailable)) | Err(_) => {
            return Err(unavailable_problem(request_id));
        }
    };
    if principal.tenant_id.is_none() {
        return Err(problem_response(
            StatusCode::FORBIDDEN,
            "WEBSOCKET_TENANT_REQUIRED",
            "WebSocket access requires a tenant context",
            request_id,
        ));
    }
    Ok(principal)
}

fn headers_within_bounds(headers: &HeaderMap, config: &WebSocketConfig) -> bool {
    if headers.len() > config.max_header_count() {
        return false;
    }
    headers
        .iter()
        .try_fold(0_usize, |total, (name, value)| {
            total
                .checked_add(name.as_str().len())?
                .checked_add(value.as_bytes().len())
        })
        .is_some_and(|bytes| bytes <= config.max_header_bytes())
}

fn origin_is_allowed(headers: &HeaderMap, config: &WebSocketConfig) -> bool {
    let mut origins = headers.get_all(ORIGIN).iter();
    let Some(origin) = origins.next() else {
        return false;
    };
    if origins.next().is_some() {
        return false;
    }
    config
        .trusted_origins()
        .iter()
        .any(|trusted| trusted.as_bytes() == origin.as_bytes())
}

fn required_subprotocol_offered(headers: &HeaderMap) -> bool {
    let mut offered = false;
    let mut saw_value = false;
    for value in headers.get_all(SEC_WEBSOCKET_PROTOCOL) {
        let Ok(value) = value.to_str() else {
            return false;
        };
        saw_value = true;
        for protocol in value.split(',') {
            let protocol = protocol.trim_matches([' ', '\t']);
            if protocol.is_empty() || !protocol.bytes().all(is_http_token_byte) {
                return false;
            }
            offered |= protocol == WEBSOCKET_PROTOCOL;
        }
    }
    saw_value && offered
}

const fn is_http_token_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric()
        || matches!(
            byte,
            b'!' | b'#'
                | b'$'
                | b'%'
                | b'&'
                | b'\''
                | b'*'
                | b'+'
                | b'-'
                | b'.'
                | b'^'
                | b'_'
                | b'`'
                | b'|'
                | b'~'
        )
}

fn problem_response(
    status: StatusCode,
    code: &'static str,
    detail: &'static str,
    request_id: RequestId,
) -> Response {
    let Ok(code) = ErrorCode::try_new(code) else {
        return fallback_problem(request_id);
    };
    let error = ServiceError::new(code, detail);
    match ProblemDetails::from_service_error(status, &error, request_id) {
        Ok(problem) => problem.into_response(),
        Err(_) => fallback_problem(request_id),
    }
}

fn unavailable_problem(request_id: RequestId) -> Response {
    problem_response(
        StatusCode::SERVICE_UNAVAILABLE,
        "WEBSOCKET_UNAVAILABLE",
        "the WebSocket service is unavailable",
        request_id,
    )
}

fn fallback_problem(request_id: RequestId) -> Response {
    match ProblemDetails::try_for_status(StatusCode::INTERNAL_SERVER_ERROR, request_id) {
        Ok(problem) => problem.into_response(),
        Err(_) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    }
}

#[derive(Debug)]
struct RegisteredConnection {
    registry: ConnectionRegistry,
    connection_id: ConnectionId,
    lease: Mutex<Option<ConnectionLease>>,
    closed: AtomicBool,
}

impl RegisteredConnection {
    fn new(
        registry: ConnectionRegistry,
        connection_id: ConnectionId,
        lease: ConnectionLease,
    ) -> Self {
        Self {
            registry,
            connection_id,
            lease: Mutex::new(Some(lease)),
            closed: AtomicBool::new(false),
        }
    }

    fn begin_close(&self) {
        if !self.closed.load(Ordering::Acquire) {
            let _ = self.registry.begin_close(self.connection_id);
        }
    }

    fn close(&self) {
        if self.closed.swap(true, Ordering::AcqRel) {
            return;
        }
        let _ = self.registry.begin_close(self.connection_id);
        let _ = self.registry.close(self.connection_id);
        let mut lease = lock_even_if_poisoned(&self.lease);
        lease.take();
    }
}

impl Drop for RegisteredConnection {
    fn drop(&mut self) {
        self.close();
    }
}

#[derive(Clone, Copy, Debug)]
struct CloseSpec {
    code: u16,
    reason: &'static str,
}

impl CloseSpec {
    const fn new(code: u16, reason: &'static str) -> Self {
        Self { code, reason }
    }

    fn into_frame(self) -> CloseFrame {
        CloseFrame {
            code: self.code,
            reason: self.reason.into(),
        }
    }
}

enum SocketTermination {
    Close(CloseSpec),
    PeerClose,
    Eof,
    SendFailed,
}

async fn run_socket<P, R, I>(
    mut socket: WebSocket,
    service: Arc<RealtimeService<P, R>>,
    identity: Arc<I>,
    principal: Principal,
    config: WebSocketConfig,
    lifecycle: Arc<RegisteredConnection>,
) where
    P: AuthorizationProvider + Send + Sync + 'static,
    R: CommandAuthorizationResolver + Send + Sync + 'static,
    I: WebSocketIdentity,
{
    if service
        .registry()
        .activate(lifecycle.connection_id)
        .is_err()
    {
        finish_socket(
            &mut socket,
            &lifecycle,
            SocketTermination::Close(CloseSpec::new(CLOSE_INTERNAL_ERROR, "realtime unavailable")),
        )
        .await;
        return;
    }

    let context = SocketContext {
        service: &service,
        identity: identity.as_ref(),
        principal: &principal,
        config: &config,
        connection_id: lifecycle.connection_id,
        lifetime_deadline: Instant::now() + config.maximum_lifetime(),
    };
    let termination = socket_loop(&mut socket, &context).await;
    finish_socket(&mut socket, &lifecycle, termination).await;
}

struct SocketContext<'a, P, R, I> {
    service: &'a RealtimeService<P, R>,
    identity: &'a I,
    principal: &'a Principal,
    config: &'a WebSocketConfig,
    connection_id: ConnectionId,
    lifetime_deadline: Instant,
}

async fn socket_loop<P, R, I>(
    socket: &mut WebSocket,
    context: &SocketContext<'_, P, R, I>,
) -> SocketTermination
where
    P: AuthorizationProvider,
    R: CommandAuthorizationResolver,
    I: WebSocketIdentity,
{
    let now = Instant::now();
    let mut heartbeat = tokio::time::interval_at(
        now + context.config.heartbeat_interval(),
        context.config.heartbeat_interval(),
    );
    heartbeat.set_missed_tick_behavior(MissedTickBehavior::Delay);
    let mut revalidation = tokio::time::interval_at(
        now + context.config.revalidation_interval(),
        context.config.revalidation_interval(),
    );
    revalidation.set_missed_tick_behavior(MissedTickBehavior::Delay);
    let lifetime = tokio::time::sleep_until(context.lifetime_deadline);
    let pong_timer = tokio::time::sleep_until(context.lifetime_deadline);
    tokio::pin!(lifetime);
    tokio::pin!(pong_timer);

    let mut heartbeat_sequence = 0_u64;
    let mut awaited_pong: Option<[u8; 8]> = None;
    let mut pong_deadline = None;

    loop {
        tokio::select! {
            biased;
            () = &mut lifetime => {
                return lifetime_termination();
            }
            () = &mut pong_timer, if pong_deadline.is_some() => {
                return heartbeat_termination();
            }
            _ = heartbeat.tick() => {
                if awaited_pong.is_some() {
                    return heartbeat_termination();
                }
                heartbeat_sequence = heartbeat_sequence.wrapping_add(1);
                let payload = heartbeat_sequence.to_be_bytes();
                if let Err(termination) = bounded_send(
                    socket,
                    Message::Ping(payload.to_vec().into()),
                    context.config,
                    context.lifetime_deadline,
                    pong_deadline,
                )
                .await
                {
                    return termination;
                }
                awaited_pong = Some(payload);
                let deadline = Instant::now() + context.config.pong_deadline();
                pong_timer.as_mut().reset(deadline);
                pong_deadline = Some(deadline);
            }
            _ = revalidation.tick() => {
                if let Err(termination) = require_active_identity(
                    bounded_revalidation(
                        context.identity,
                        context.principal,
                        context.config,
                        context.lifetime_deadline,
                        pong_deadline,
                    )
                    .await,
                ) {
                    return termination;
                }
            }
            message = socket.recv() => {
                if let Err(termination) = handle_received_message(
                    socket,
                    message,
                    context,
                    &mut awaited_pong,
                    &mut pong_deadline,
                )
                .await
                {
                    return termination;
                }
            }
        }
    }
}

async fn handle_received_message<P, R, I>(
    socket: &mut WebSocket,
    message: Option<Result<Message, axum::Error>>,
    context: &SocketContext<'_, P, R, I>,
    awaited_pong: &mut Option<[u8; 8]>,
    pong_deadline: &mut Option<Instant>,
) -> Result<(), SocketTermination>
where
    P: AuthorizationProvider,
    R: CommandAuthorizationResolver,
    I: WebSocketIdentity,
{
    match message {
        None => Err(SocketTermination::Eof),
        Some(Ok(Message::Close(_))) => Err(SocketTermination::PeerClose),
        Some(Err(error)) => Err(SocketTermination::Close(receive_error_close(&error))),
        Some(Ok(Message::Binary(_))) => Err(SocketTermination::Close(CloseSpec::new(
            CLOSE_UNSUPPORTED_DATA,
            "binary messages unsupported",
        ))),
        Some(Ok(Message::Text(text))) => {
            handle_text_message(socket, text.as_str(), context, *pong_deadline).await
        }
        Some(Ok(Message::Pong(payload))) => {
            if awaited_pong
                .as_ref()
                .is_some_and(|expected| payload.as_ref() == expected)
            {
                if pong_deadline.is_some_and(|deadline| Instant::now() >= deadline) {
                    return Err(heartbeat_termination());
                }
                *awaited_pong = None;
                *pong_deadline = None;
            }
            Ok(())
        }
        Some(Ok(Message::Ping(_))) => Ok(()),
    }
}

async fn handle_text_message<P, R, I>(
    socket: &mut WebSocket,
    text: &str,
    context: &SocketContext<'_, P, R, I>,
    pong_deadline: Option<Instant>,
) -> Result<(), SocketTermination>
where
    P: AuthorizationProvider,
    R: CommandAuthorizationResolver,
    I: WebSocketIdentity,
{
    if text.len() > context.config.max_message_bytes() {
        return Err(SocketTermination::Close(CloseSpec::new(
            CLOSE_MESSAGE_TOO_BIG,
            "message too large",
        )));
    }
    let Ok(command) = InboundCommand::parse(text.as_bytes()) else {
        return Err(SocketTermination::Close(CloseSpec::new(
            CLOSE_PROTOCOL_ERROR,
            "invalid protocol message",
        )));
    };
    require_active_identity(
        bounded_revalidation(
            context.identity,
            context.principal,
            context.config,
            context.lifetime_deadline,
            pong_deadline,
        )
        .await,
    )?;
    enforce_socket_deadlines(context.lifetime_deadline, pong_deadline)?;
    let Ok(encoded) = context
        .service
        .handle(context.connection_id, command)
        .encode()
    else {
        return Err(SocketTermination::Close(CloseSpec::new(
            CLOSE_INTERNAL_ERROR,
            "realtime unavailable",
        )));
    };
    let Ok(text) = String::from_utf8(encoded) else {
        return Err(SocketTermination::Close(CloseSpec::new(
            CLOSE_INTERNAL_ERROR,
            "realtime unavailable",
        )));
    };
    bounded_send(
        socket,
        Message::Text(text.into()),
        context.config,
        context.lifetime_deadline,
        pong_deadline,
    )
    .await
}

fn enforce_socket_deadlines(
    lifetime_deadline: Instant,
    pong_deadline: Option<Instant>,
) -> Result<(), SocketTermination> {
    let now = Instant::now();
    if now >= lifetime_deadline {
        Err(lifetime_termination())
    } else if pong_deadline.is_some_and(|deadline| now >= deadline) {
        Err(heartbeat_termination())
    } else {
        Ok(())
    }
}

fn require_active_identity(
    status: Result<IdentityRevalidation, SocketTermination>,
) -> Result<(), SocketTermination> {
    match status {
        Ok(IdentityRevalidation::Active) => Ok(()),
        Ok(IdentityRevalidation::Revoked) => Err(identity_revoked_termination()),
        Ok(IdentityRevalidation::Unavailable) => Err(identity_unavailable_termination()),
        Err(termination) => Err(termination),
    }
}

async fn bounded_revalidation<I>(
    identity: &I,
    principal: &Principal,
    config: &WebSocketConfig,
    lifetime_deadline: Instant,
    pong_deadline: Option<Instant>,
) -> Result<IdentityRevalidation, SocketTermination>
where
    I: WebSocketIdentity,
{
    let deadline = operation_deadline(config, lifetime_deadline, pong_deadline);
    match tokio::time::timeout_at(deadline, identity.revalidate(principal)).await {
        Ok(status) => Ok(status),
        Err(_) => Err(expired_operation_termination(
            lifetime_deadline,
            pong_deadline,
            identity_unavailable_termination(),
        )),
    }
}

async fn bounded_send(
    socket: &mut WebSocket,
    message: Message,
    config: &WebSocketConfig,
    lifetime_deadline: Instant,
    pong_deadline: Option<Instant>,
) -> Result<(), SocketTermination> {
    let deadline = operation_deadline(config, lifetime_deadline, pong_deadline);
    match tokio::time::timeout_at(deadline, socket.send(message)).await {
        Ok(Ok(())) => Ok(()),
        Ok(Err(_)) => Err(SocketTermination::SendFailed),
        Err(_) => Err(expired_operation_termination(
            lifetime_deadline,
            pong_deadline,
            SocketTermination::SendFailed,
        )),
    }
}

fn operation_deadline(
    config: &WebSocketConfig,
    lifetime_deadline: Instant,
    pong_deadline: Option<Instant>,
) -> Instant {
    let mut deadline = Instant::now() + config.pong_deadline();
    if lifetime_deadline < deadline {
        deadline = lifetime_deadline;
    }
    if let Some(pong_deadline) = pong_deadline
        && pong_deadline < deadline
    {
        deadline = pong_deadline;
    }
    deadline
}

fn expired_operation_termination(
    lifetime_deadline: Instant,
    pong_deadline: Option<Instant>,
    otherwise: SocketTermination,
) -> SocketTermination {
    let now = Instant::now();
    if now >= lifetime_deadline {
        lifetime_termination()
    } else if pong_deadline.is_some_and(|deadline| now >= deadline) {
        heartbeat_termination()
    } else {
        otherwise
    }
}

fn lifetime_termination() -> SocketTermination {
    SocketTermination::Close(CloseSpec::new(
        CLOSE_GOING_AWAY,
        "connection lifetime reached",
    ))
}

fn heartbeat_termination() -> SocketTermination {
    SocketTermination::Close(CloseSpec::new(CLOSE_GOING_AWAY, "heartbeat timeout"))
}

fn identity_revoked_termination() -> SocketTermination {
    SocketTermination::Close(CloseSpec::new(
        CLOSE_POLICY_VIOLATION,
        "identity no longer active",
    ))
}

fn identity_unavailable_termination() -> SocketTermination {
    SocketTermination::Close(CloseSpec::new(CLOSE_INTERNAL_ERROR, "identity unavailable"))
}

fn receive_error_close(error: &axum::Error) -> CloseSpec {
    let too_large = error
        .source()
        .and_then(|source| source.downcast_ref::<TungsteniteError>())
        .is_some_and(|error| {
            matches!(
                error,
                TungsteniteError::Capacity(CapacityError::MessageTooLong { .. })
            )
        });
    if too_large {
        CloseSpec::new(CLOSE_MESSAGE_TOO_BIG, "message too large")
    } else {
        CloseSpec::new(CLOSE_INTERNAL_ERROR, "realtime unavailable")
    }
}

async fn finish_socket(
    socket: &mut WebSocket,
    lifecycle: &RegisteredConnection,
    termination: SocketTermination,
) {
    lifecycle.begin_close();
    lifecycle.close();
    match termination {
        SocketTermination::Close(close) => {
            let _ = tokio::time::timeout(
                CLOSE_SEND_TIMEOUT,
                socket.send(Message::Close(Some(close.into_frame()))),
            )
            .await;
        }
        SocketTermination::PeerClose => {
            let _ = tokio::time::timeout(CLOSE_SEND_TIMEOUT, async {
                socket.flush().await?;
                socket.close().await
            })
            .await;
        }
        SocketTermination::Eof | SocketTermination::SendFailed => {}
    }
}

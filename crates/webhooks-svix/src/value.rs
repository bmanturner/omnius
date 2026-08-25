use std::{fmt, net::IpAddr};

use rsk_config::{ExposeSecret as _, SecretString};
use rsk_outbound_http::ApprovedUrl;
use serde::{Deserialize, Deserializer};
use serde_json::value::RawValue;
use time::{Duration, OffsetDateTime};
use url::Url;

use crate::ValueError;

const MAX_ID_BYTES: usize = 256;
const MAX_EVENT_TYPE_BYTES: usize = 128;
const MAX_NAME_BYTES: usize = 128;
const MAX_DESCRIPTION_BYTES: usize = 512;
const MAX_DESTINATION_BYTES: usize = 64;
const MAX_IDEMPOTENCY_KEY_BYTES: usize = 256;
const MAX_TOKEN_BYTES: usize = 16 * 1024;
const MAX_SIGNING_SECRET_BYTES: usize = 16 * 1024;
const MAX_FILTER_TYPES: usize = 128;
const MAX_REPLAY_WINDOW: Duration = Duration::days(90);

fn valid_portable(value: &str, maximum: usize) -> bool {
    !value.is_empty()
        && value.len() <= maximum
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':' | b'/')
        })
}

fn valid_text(value: &str, maximum: usize) -> bool {
    !value.trim().is_empty() && value.len() <= maximum && !value.chars().any(char::is_control)
}

fn valid_secret(value: &str, maximum: usize) -> bool {
    !value.is_empty()
        && value.len() <= maximum
        && value.bytes().all(|byte| (0x21..=0x7e).contains(&byte))
}
macro_rules! portable_value {
    ($name:ident, $maximum:expr, $documentation:literal) => {
        #[doc = $documentation]
        #[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
        pub struct $name(String);

        impl $name {
            #[doc = "Creates a validated bounded value."]
            #[doc = ""]
            #[doc = "# Errors"]
            #[doc = ""]
            #[doc = "Returns [`ValueError`] when the value is empty, oversized, or not portable ASCII."]
            pub fn new(value: impl Into<String>) -> Result<Self, ValueError> {
                let value = value.into();
                if !valid_portable(&value, $maximum) {
                    return Err(ValueError);
                }
                Ok(Self(value))
            }

            #[doc = "Borrows the validated value."]
            #[must_use]
            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter
                    .debug_tuple(stringify!($name))
                    .field(&self.0)
                    .finish()
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str(&self.0)
            }
        }

        impl TryFrom<String> for $name {
            type Error = ValueError;

            fn try_from(value: String) -> Result<Self, Self::Error> {
                Self::new(value)
            }
        }

        impl TryFrom<&str> for $name {
            type Error = ValueError;

            fn try_from(value: &str) -> Result<Self, Self::Error> {
                Self::new(value)
            }
        }
    };
}

portable_value!(
    ApplicationId,
    MAX_ID_BYTES,
    "Stable local or provider application identifier."
);
portable_value!(
    EndpointId,
    MAX_ID_BYTES,
    "Stable local or provider endpoint identifier."
);
portable_value!(
    MessageId,
    MAX_ID_BYTES,
    "Stable provider delivery-message identifier."
);
portable_value!(
    ReplayTaskId,
    MAX_ID_BYTES,
    "Stable provider background replay-task identifier."
);
portable_value!(
    EventType,
    MAX_EVENT_TYPE_BYTES,
    "Stable semver-governed public event type."
);
portable_value!(
    IdempotencyKey,
    MAX_IDEMPOTENCY_KEY_BYTES,
    "Caller-supplied deterministic idempotency key."
);
portable_value!(
    ReplayFingerprint,
    MAX_IDEMPOTENCY_KEY_BYTES,
    "Bounded deterministic replay-admission fingerprint."
);
portable_value!(
    ReplayLeaseId,
    MAX_ID_BYTES,
    "Opaque durable replay-admission lease identifier."
);
portable_value!(
    Destination,
    MAX_DESTINATION_BYTES,
    "Outbox destination routed to this adapter."
);

/// Bounded application display name.
#[derive(Clone, Eq, PartialEq)]
pub struct ApplicationName(String);

impl ApplicationName {
    /// Creates a bounded, control-character-free application name.
    ///
    /// # Errors
    ///
    /// Returns [`ValueError`] when the name is empty, oversized, or contains controls.
    pub fn new(value: impl Into<String>) -> Result<Self, ValueError> {
        let value = value.into();
        if !valid_text(&value, MAX_NAME_BYTES) {
            return Err(ValueError);
        }
        Ok(Self(value))
    }

    /// Borrows the validated name.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for ApplicationName {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ApplicationName([REDACTED])")
    }
}

/// Bounded endpoint description.
#[derive(Clone, Eq, PartialEq)]
pub struct EndpointDescription(String);

impl EndpointDescription {
    /// Creates a bounded, control-character-free description.
    ///
    /// # Errors
    ///
    /// Returns [`ValueError`] when the description is empty, oversized, or contains controls.
    pub fn new(value: impl Into<String>) -> Result<Self, ValueError> {
        let value = value.into();
        if !valid_text(&value, MAX_DESCRIPTION_BYTES) {
            return Err(ValueError);
        }
        Ok(Self(value))
    }

    /// Borrows the validated description.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for EndpointDescription {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("EndpointDescription([REDACTED])")
    }
}

pub(crate) fn validate_server_url(
    url: &Url,
    allow_insecure_loopback: bool,
) -> Result<(), ValueError> {
    validate_url(url, allow_insecure_loopback)
}

fn validate_url(url: &Url, allow_insecure_loopback: bool) -> Result<(), ValueError> {
    if !url.username().is_empty()
        || url.password().is_some()
        || url.fragment().is_some()
        || url.query().is_some()
        || url.host_str().is_none()
    {
        return Err(ValueError);
    }
    if url.scheme() == "https" {
        return Ok(());
    }
    if url.scheme() != "http" || !allow_insecure_loopback || !is_loopback_host(url) {
        return Err(ValueError);
    }
    Ok(())
}

fn is_loopback_host(url: &Url) -> bool {
    url.host_str()
        .map(|host| {
            host.strip_prefix('[')
                .and_then(|value| value.strip_suffix(']'))
                .unwrap_or(host)
        })
        .and_then(|host| host.parse::<IpAddr>().ok())
        .is_some_and(|address| address.is_loopback())
}

/// Redacted Svix API credential.
pub struct SvixToken(SecretString);

impl SvixToken {
    /// Creates a non-empty bounded visible-ASCII token.
    ///
    /// # Errors
    ///
    /// Returns [`ValueError`] when the token is empty, oversized, or not visible ASCII.
    pub fn new(value: SecretString) -> Result<Self, ValueError> {
        if !valid_secret(value.expose_secret(), MAX_TOKEN_BYTES) {
            return Err(ValueError);
        }
        Ok(Self(value))
    }

    pub(crate) fn expose(&self) -> &str {
        self.0.expose_secret()
    }
}

impl Clone for SvixToken {
    fn clone(&self) -> Self {
        Self(SecretString::from(self.expose().to_owned()))
    }
}

impl fmt::Debug for SvixToken {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SvixToken([REDACTED])")
    }
}

impl<'de> Deserialize<'de> for SvixToken {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::new(SecretString::from(value)).map_err(serde::de::Error::custom)
    }
}

/// Endpoint signing secret with redacted formatting.
pub struct SigningSecret(SecretString);

impl SigningSecret {
    /// Wraps a bounded visible-ASCII provider signing secret.
    ///
    /// # Errors
    ///
    /// Returns [`ValueError`] when the secret is empty, oversized, or not visible ASCII.
    pub fn new(value: SecretString) -> Result<Self, ValueError> {
        if !valid_secret(value.expose_secret(), MAX_SIGNING_SECRET_BYTES) {
            return Err(ValueError);
        }
        Ok(Self(value))
    }

    /// Deliberately exposes the secret only for consumer-side signature verification or storage.
    #[must_use]
    pub fn expose_for_verification(&self) -> &str {
        self.0.expose_secret()
    }
}

impl Clone for SigningSecret {
    fn clone(&self) -> Self {
        Self(SecretString::from(
            self.expose_for_verification().to_owned(),
        ))
    }
}

impl fmt::Debug for SigningSecret {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SigningSecret([REDACTED])")
    }
}

/// Application creation data independent of provider models.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ApplicationSpec {
    /// Stable local application mapping.
    pub id: ApplicationId,
    /// Human-readable application name.
    pub name: ApplicationName,
}

/// Bounded endpoint creation/update data independent of provider models.
pub struct EndpointSpec {
    /// Stable local endpoint mapping.
    pub id: EndpointId,
    approved_url: ApprovedUrl,
    /// Operator-facing description.
    pub description: EndpointDescription,
    /// Optional bounded event-type filter.
    filter_types: Box<[EventType]>,
}

impl EndpointSpec {
    /// Creates a bounded endpoint specification from a centrally approved URL capability.
    ///
    /// `ApprovedUrl` is opaque and can only be produced by
    /// `rsk_outbound_http::OutboundUrlPolicy::approve`; raw URLs cannot bypass resolved-address
    /// SSRF policy at this lifecycle boundary.
    ///
    /// # Errors
    ///
    /// Returns [`ValueError`] when the event-type filter exceeds its fixed capacity.
    pub fn new(
        id: EndpointId,
        approved_url: ApprovedUrl,
        description: EndpointDescription,
        filter_types: Vec<EventType>,
    ) -> Result<Self, ValueError> {
        if filter_types.len() > MAX_FILTER_TYPES {
            return Err(ValueError);
        }
        Ok(Self {
            id,
            approved_url,
            description,
            filter_types: filter_types.into_boxed_slice(),
        })
    }

    /// Borrows the event-type filter.
    #[must_use]
    pub fn filter_types(&self) -> &[EventType] {
        &self.filter_types
    }

    pub(crate) fn approved_url(&self) -> &ApprovedUrl {
        &self.approved_url
    }

    pub(crate) fn equivalent(&self, other: &Self) -> bool {
        self.id == other.id
            && self.approved_url.as_url() == other.approved_url.as_url()
            && self.description == other.description
            && self.filter_types == other.filter_types
    }
}

impl fmt::Debug for EndpointSpec {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("EndpointSpec")
            .field("id", &self.id)
            .field("approved_url", &"[REDACTED]")
            .field("description", &"[REDACTED]")
            .field("filter_type_count", &self.filter_types.len())
            .finish()
    }
}

/// Borrowed outbound provider message that preserves the canonical raw JSON envelope.
pub struct PublishRequest<'a> {
    /// Provider application mapping.
    pub application_id: &'a ApplicationId,
    /// Stable event ID and idempotency key.
    pub event_id: &'a str,
    /// Stable public event type.
    pub event_type: &'a str,
    /// Exact canonical JSON envelope from the transactional outbox.
    pub payload: &'a RawValue,
}

impl fmt::Debug for PublishRequest<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PublishRequest")
            .field("application_id", self.application_id)
            .field("event_id", &self.event_id)
            .field("event_type", &self.event_type)
            .field("payload", &"[REDACTED]")
            .finish()
    }
}

/// Safe application lifecycle result.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ApplicationRecord {
    /// Application identifier bound to this provider instance.
    pub id: ApplicationId,
}

/// Safe endpoint lifecycle/status result. Delivery URLs are deliberately omitted.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EndpointRecord {
    /// Provider endpoint identifier.
    pub id: EndpointId,
    /// Whether Svix currently accepts delivery for this endpoint.
    pub enabled: bool,
}

/// Safe publish receipt.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PublishReceipt {
    /// Provider message identifier.
    pub message_id: MessageId,
}

/// Safe delivery attempt state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AttemptState {
    /// Delivery succeeded.
    Succeeded,
    /// Delivery is pending.
    Pending,
    /// Delivery failed.
    Failed,
    /// Delivery is in progress.
    Sending,
    /// Delivery was cancelled.
    Cancelled,
}

/// Bounded, response-body-free delivery attempt summary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DeliveryAttempt {
    /// Provider attempt state.
    pub state: AttemptState,
    /// HTTP status when Svix exposed a non-zero valid status.
    pub response_status: Option<u16>,
    /// Non-negative bounded response duration in milliseconds.
    pub response_duration_ms: u32,
}

/// Bounded message delivery status.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DeliveryStatus {
    /// Message whose attempts were queried.
    pub message_id: MessageId,
    attempts: Box<[DeliveryAttempt]>,
}

impl DeliveryStatus {
    /// Creates a bounded delivery status from adapter-controlled attempts.
    pub(crate) fn new(message_id: MessageId, attempts: Vec<DeliveryAttempt>) -> Self {
        Self {
            message_id,
            attempts: attempts.into_boxed_slice(),
        }
    }

    /// Borrows the bounded attempt summaries.
    #[must_use]
    pub fn attempts(&self) -> &[DeliveryAttempt] {
        &self.attempts
    }
}

/// Replay selection supported by Svix.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReplayMode {
    /// Replay messages never attempted for the endpoint.
    Missing,
    /// Replay successful and failed messages.
    All,
    /// Recover only failed messages.
    Failed,
}

impl ReplayMode {
    /// Returns the canonical storage and fingerprint label.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Missing => "missing",
            Self::All => "all",
            Self::Failed => "failed",
        }
    }
}

/// Validated ordered replay time window, always bounded to 90 days.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReplayWindow {
    since: OffsetDateTime,
    until: OffsetDateTime,
}

impl ReplayWindow {
    /// Creates an ordered replay window no wider than 90 days.
    ///
    /// # Errors
    ///
    /// Returns [`ValueError`] unless both bounds are whole UTC minutes in order and at most 90 days apart.
    pub fn new(since: OffsetDateTime, until: OffsetDateTime) -> Result<Self, ValueError> {
        if since.unix_timestamp() % 60 != 0
            || since.nanosecond() != 0
            || until.unix_timestamp() % 60 != 0
            || until.nanosecond() != 0
            || until < since
            || until - since > MAX_REPLAY_WINDOW
        {
            return Err(ValueError);
        }
        Ok(Self { since, until })
    }

    /// Returns the inclusive canonical whole-minute lower bound.
    #[must_use]
    pub const fn since(self) -> OffsetDateTime {
        self.since
    }

    /// Returns the inclusive canonical whole-minute upper bound.
    #[must_use]
    pub const fn until(self) -> OffsetDateTime {
        self.until
    }
}

/// Replay task creation fields used to derive provider idempotency internally.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReplayRequest {
    /// Application identifier bound to this provider instance.
    pub application_id: ApplicationId,
    /// Provider endpoint identifier.
    pub endpoint_id: EndpointId,
    /// Replay selection.
    pub mode: ReplayMode,
    /// Replay time window.
    pub window: ReplayWindow,
}

/// Canonical bounded identity durably admitted before a provider replay call.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReplayAdmissionRequest {
    application_id: ApplicationId,
    endpoint_id: EndpointId,
    mode: ReplayMode,
    window: ReplayWindow,
    fingerprint: ReplayFingerprint,
}

impl ReplayAdmissionRequest {
    /// Creates an admission identity from already validated bounded values.
    #[must_use]
    pub const fn new(
        application_id: ApplicationId,
        endpoint_id: EndpointId,
        mode: ReplayMode,
        window: ReplayWindow,
        fingerprint: ReplayFingerprint,
    ) -> Self {
        Self {
            application_id,
            endpoint_id,
            mode,
            window,
            fingerprint,
        }
    }

    /// Returns the tenant/application scope.
    #[must_use]
    pub const fn application_id(&self) -> &ApplicationId {
        &self.application_id
    }

    /// Returns the endpoint scope.
    #[must_use]
    pub const fn endpoint_id(&self) -> &EndpointId {
        &self.endpoint_id
    }

    /// Returns the replay selection.
    #[must_use]
    pub const fn mode(&self) -> ReplayMode {
        self.mode
    }

    /// Returns the canonical whole-minute replay window.
    #[must_use]
    pub const fn window(&self) -> ReplayWindow {
        self.window
    }

    /// Returns the stable request fingerprint.
    #[must_use]
    pub const fn fingerprint(&self) -> &ReplayFingerprint {
        &self.fingerprint
    }
}

/// Safe replay task state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReplayState {
    /// Task is still running.
    Running,
    /// Task finished successfully.
    Finished,
    /// Task failed at the provider.
    Failed,
}

/// Definitive durable replay completion recorded for cooldown and audit.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReplayCompletion {
    /// Provider task finished successfully.
    Finished,
    /// Provider task finished unsuccessfully.
    Failed,
    /// Provider reported that the bound task no longer exists.
    Missing,
}

/// Opaque durable admission lease returned by [`crate::ReplayAdmission::reserve`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReplayLease {
    id: ReplayLeaseId,
    request: ReplayAdmissionRequest,
}

impl ReplayLease {
    /// Creates a lease value for a durable admission implementation.
    #[must_use]
    pub const fn new(id: ReplayLeaseId, request: ReplayAdmissionRequest) -> Self {
        Self { id, request }
    }

    /// Returns the opaque durable lease ID.
    #[must_use]
    pub const fn id(&self) -> &ReplayLeaseId {
        &self.id
    }

    /// Returns the canonical request held by this lease.
    #[must_use]
    pub const fn request(&self) -> &ReplayAdmissionRequest {
        &self.request
    }
}

/// Opaque durable binding between an admitted lease and a provider task.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReplayTaskBinding {
    lease: ReplayLease,
    task_id: ReplayTaskId,
}

impl ReplayTaskBinding {
    /// Creates a binding value after atomically persisting a provider task ID.
    #[must_use]
    pub const fn new(lease: ReplayLease, task_id: ReplayTaskId) -> Self {
        Self { lease, task_id }
    }

    /// Returns the durable admission lease.
    #[must_use]
    pub const fn lease(&self) -> &ReplayLease {
        &self.lease
    }

    /// Returns the bound provider task ID.
    #[must_use]
    pub const fn task_id(&self) -> &ReplayTaskId {
        &self.task_id
    }
}

/// Safe replay lifecycle result.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReplayTask {
    /// Provider background task ID.
    pub id: ReplayTaskId,
    /// Current task state.
    pub state: ReplayState,
}

/// Fixed low-cardinality operation identity for metrics and deterministic fake plans.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[non_exhaustive]
pub enum ProviderOperation {
    /// Publish one canonical event envelope.
    Publish,
    /// Get or create an application.
    ApplicationGetOrCreate,
    /// Create an endpoint.
    EndpointCreate,
    /// Update an endpoint.
    EndpointUpdate,
    /// Read endpoint status.
    EndpointStatus,
    /// Enable or disable an endpoint.
    EndpointSetEnabled,
    /// Delete an endpoint.
    EndpointDelete,
    /// Retrieve an endpoint signing secret.
    SecretGet,
    /// Rotate an endpoint signing secret.
    SecretRotate,
    /// Read delivery attempts.
    DeliveryStatus,
    /// Start a replay task.
    ReplayStart,
    /// Read a replay task.
    ReplayStatus,
    /// Send a provider-managed schema example.
    TestEvent,
    /// Probe provider health.
    Health,
}

impl ProviderOperation {
    /// Returns the fixed metrics label.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Publish => "publish",
            Self::ApplicationGetOrCreate => "application_get_or_create",
            Self::EndpointCreate => "endpoint_create",
            Self::EndpointUpdate => "endpoint_update",
            Self::EndpointStatus => "endpoint_status",
            Self::EndpointSetEnabled => "endpoint_set_enabled",
            Self::EndpointDelete => "endpoint_delete",
            Self::SecretGet => "secret_get",
            Self::SecretRotate => "secret_rotate",
            Self::DeliveryStatus => "delivery_status",
            Self::ReplayStart => "replay_start",
            Self::ReplayStatus => "replay_status",
            Self::TestEvent => "test_event",
            Self::Health => "health",
        }
    }
}

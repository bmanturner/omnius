use std::fmt;

use serde::Serialize;
use thiserror::Error;

const ID_BYTES: usize = 256;
const HANDLE_BYTES: usize = 512;
const IDEMPOTENCY_KEY_BYTES: usize = 128;
const STATUS_MESSAGE_BYTES: usize = 1_024;

/// Error returned when a bounded subscription-domain value is invalid.
#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum ValueError {
    /// The supplied value was empty.
    #[error("value is empty")]
    Empty,
    /// The supplied value exceeded its byte ceiling.
    #[error("value exceeds its byte ceiling")]
    TooLong,
    /// The supplied value contained non-portable characters.
    #[error("value contains invalid characters")]
    InvalidCharacters,
    /// An event position was not valid.
    #[error("event position is invalid")]
    InvalidPosition,
    /// A task snapshot lifetime was not valid.
    #[error("task snapshot lifetime is invalid")]
    InvalidLifetime,
}

fn validate_id(value: &str, max: usize) -> Result<(), ValueError> {
    if value.is_empty() {
        return Err(ValueError::Empty);
    }
    if value.len() > max {
        return Err(ValueError::TooLong);
    }
    if !value.is_ascii() || !value.bytes().all(|byte| byte.is_ascii_graphic()) {
        return Err(ValueError::InvalidCharacters);
    }
    Ok(())
}

fn json_escaped_len(value: &str) -> usize {
    value.bytes().fold(0_usize, |total, byte| {
        let byte_len = match byte {
            b'"' | b'\\' | b'\x08' | b'\t' | b'\n' | b'\x0c' | b'\r' => 2,
            b'\x00'..=b'\x1f' => 6,
            _ => 1,
        };
        total.saturating_add(byte_len)
    })
}

fn json_string_len(value: &str) -> usize {
    2_usize.saturating_add(json_escaped_len(value))
}

fn u64_json_len(mut value: u64) -> usize {
    let mut len = 1_usize;
    while value >= 10 {
        value /= 10;
        len += 1;
    }
    len
}

fn json_array_len(lengths: impl Iterator<Item = usize>) -> usize {
    lengths
        .enumerate()
        .fold(2_usize, |total, (index, item_len)| {
            total
                .saturating_add(usize::from(index != 0))
                .saturating_add(item_len)
        })
}

macro_rules! bounded_id {
    ($name:ident, $doc:literal) => {
        #[doc = $doc]
        #[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
        #[serde(transparent)]
        pub struct $name(String);

        impl $name {
            /// Validates and owns an identifier.
            ///
            /// # Errors
            ///
            /// Returns [`ValueError::Empty`] for an empty identifier,
            /// [`ValueError::TooLong`] when it exceeds the identifier byte ceiling, or
            /// [`ValueError::InvalidCharacters`] when it contains non-portable characters.
            pub fn new(value: impl Into<String>) -> Result<Self, ValueError> {
                let value = value.into();
                validate_id(&value, ID_BYTES)?;
                Ok(Self(value))
            }

            /// Borrows the validated identifier.
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
    };
}

bounded_id!(PrincipalId, "Authenticated principal identifier.");
bounded_id!(TenantId, "Authoritative tenant identifier.");
bounded_id!(TaskId, "Authoritative task identifier.");
bounded_id!(
    SubscriptionId,
    "JSON-RPC request identifier used for one subscription."
);

macro_rules! opaque_handle {
    ($name:ident, $max:expr, $doc:literal) => {
        #[doc = $doc]
        #[derive(Clone, Eq, Hash, PartialEq, Serialize)]
        #[serde(transparent)]
        pub struct $name(String);

        impl $name {
            /// Validates and owns an opaque value.
            ///
            /// # Errors
            ///
            /// Returns [`ValueError::Empty`] for an empty value, [`ValueError::TooLong`] when it
            /// exceeds this handle's byte ceiling, or [`ValueError::InvalidCharacters`] when it
            /// contains non-portable characters.
            pub fn new(value: impl Into<String>) -> Result<Self, ValueError> {
                let value = value.into();
                validate_id(&value, $max)?;
                Ok(Self(value))
            }

            /// Borrows the opaque value for a wire adapter.
            #[must_use]
            pub fn expose_for_transport(&self) -> &str {
                &self.0
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str(concat!(stringify!($name), "([REDACTED])"))
            }
        }
    };
}

opaque_handle!(
    SubscriptionHandle,
    HANDLE_BYTES,
    "Durable, opaque repository handle for one subscription claim."
);
opaque_handle!(
    TaskHandle,
    HANDLE_BYTES,
    "Durable, opaque handle for one task."
);
opaque_handle!(
    IdempotencyKey,
    IDEMPOTENCY_KEY_BYTES,
    "A bounded explicit subscription idempotency key."
);

/// Confidential repository status text that is never serialized or exposed through `Debug`.
#[derive(Clone, Eq, PartialEq)]
pub struct ConfidentialStatusMessage(String);

impl ConfidentialStatusMessage {
    /// Validates bounded confidential status text for the built-in public projector.
    ///
    /// # Errors
    ///
    /// Returns [`ValueError::Empty`] when the text is blank, [`ValueError::TooLong`] when it
    /// exceeds the status byte ceiling, or [`ValueError::InvalidCharacters`] when it contains a
    /// disallowed control character.
    pub fn new(value: impl Into<String>) -> Result<Self, ValueError> {
        let value = value.into();
        if value.trim().is_empty() {
            return Err(ValueError::Empty);
        }
        if value.len() > STATUS_MESSAGE_BYTES {
            return Err(ValueError::TooLong);
        }
        if value
            .chars()
            .any(|character| character.is_control() && character != '\n')
        {
            return Err(ValueError::InvalidCharacters);
        }
        Ok(Self(value))
    }

    fn into_public(self) -> PublicStatusMessage {
        let normalized = self.0.trim().to_ascii_lowercase();
        let fixed = matches!(
            normalized.as_str(),
            "queued"
                | "working"
                | "waiting"
                | "retrying"
                | "input required"
                | "cancellation requested"
                | "completed"
                | "failed"
                | "cancelled"
                | "indeterminate"
        );
        let mut words = normalized.split_ascii_whitespace();
        let step = matches!(
            (words.next(), words.next(), words.next(), words.next(), words.next()),
            (Some("step"), Some(current), Some("of"), Some(total), None)
                if current.bytes().all(|byte| byte.is_ascii_digit())
                    && total.bytes().all(|byte| byte.is_ascii_digit())
        );
        if fixed || step {
            PublicStatusMessage(normalized)
        } else {
            PublicStatusMessage("[REDACTED]".to_owned())
        }
    }
}

impl fmt::Debug for ConfidentialStatusMessage {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ConfidentialStatusMessage([REDACTED])")
    }
}

/// Allow-listed or redacted status text safe for task notifications.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(transparent)]
pub struct PublicStatusMessage(String);

impl PublicStatusMessage {
    /// Borrows the public message.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Monotonic position of an authoritative task event.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
pub struct EventPosition {
    sequence: u64,
    revision: u64,
}

impl EventPosition {
    /// Creates a non-zero event position.
    ///
    /// # Errors
    ///
    /// Returns [`ValueError::InvalidPosition`] when either monotonic dimension is zero.
    pub fn new(sequence: u64, revision: u64) -> Result<Self, ValueError> {
        if sequence == 0 || revision == 0 {
            return Err(ValueError::InvalidPosition);
        }
        Ok(Self { sequence, revision })
    }

    /// Returns the task-local event sequence.
    #[must_use]
    pub const fn sequence(self) -> u64 {
        self.sequence
    }

    /// Returns the authoritative snapshot revision.
    #[must_use]
    pub const fn revision(self) -> u64 {
        self.revision
    }

    /// Returns whether this position strictly advances both monotonic dimensions.
    #[must_use]
    pub const fn strictly_follows(self, previous: Self) -> bool {
        self.sequence > previous.sequence && self.revision > previous.revision
    }
}

/// Public task lifecycle state.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum TaskStatus {
    /// Task is waiting to execute.
    Pending,
    /// Task is executing.
    Working,
    /// Task needs explicit additional input.
    InputRequired,
    /// Task completed successfully.
    Completed,
    /// Task failed.
    Failed,
    /// Task was cancelled authoritatively.
    Cancelled,
    /// Task outcome could not be determined.
    Indeterminate,
}

/// Fields used to create a complete public task snapshot.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TaskSnapshotData {
    /// Task identifier.
    pub task_id: TaskId,
    /// Authoritative tenant identifier.
    pub tenant_id: TenantId,
    /// Monotonic event position.
    pub position: EventPosition,
    /// Current task status.
    pub status: TaskStatus,
    /// Optional confidential status text projected through the built-in allow-list.
    pub status_message: Option<ConfidentialStatusMessage>,
    /// Creation time in Unix milliseconds.
    pub created_at_ms: u64,
    /// Last update time in Unix milliseconds.
    pub last_updated_at_ms: u64,
    /// Remaining authoritative task lifetime in milliseconds.
    pub ttl_ms: u64,
}

/// Complete, public, authoritative task snapshot delivered to a subscriber.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TaskSnapshot {
    task_id: TaskId,
    tenant_id: TenantId,
    position: EventPosition,
    status: TaskStatus,
    status_message: Option<PublicStatusMessage>,
    created_at_ms: u64,
    last_updated_at_ms: u64,
    ttl_ms: u64,
}

impl TaskSnapshot {
    /// Creates a complete public task snapshot.
    ///
    /// # Errors
    ///
    /// Returns [`ValueError::InvalidLifetime`] when the lifetime is zero or the last-update time
    /// precedes the creation time.
    pub fn new(data: TaskSnapshotData) -> Result<Self, ValueError> {
        if data.ttl_ms == 0 || data.last_updated_at_ms < data.created_at_ms {
            return Err(ValueError::InvalidLifetime);
        }
        Ok(Self {
            task_id: data.task_id,
            tenant_id: data.tenant_id,
            position: data.position,
            status: data.status,
            status_message: data
                .status_message
                .map(ConfidentialStatusMessage::into_public),
            created_at_ms: data.created_at_ms,
            last_updated_at_ms: data.last_updated_at_ms,
            ttl_ms: data.ttl_ms,
        })
    }

    /// Returns the task identifier.
    #[must_use]
    pub const fn task_id(&self) -> &TaskId {
        &self.task_id
    }

    /// Returns the authoritative tenant identifier.
    #[must_use]
    pub const fn tenant_id(&self) -> &TenantId {
        &self.tenant_id
    }

    /// Returns the event position.
    #[must_use]
    pub const fn position(&self) -> EventPosition {
        self.position
    }

    /// Returns the task status.
    #[must_use]
    pub const fn status(&self) -> TaskStatus {
        self.status
    }

    /// Returns the optional redacted public status message.
    #[must_use]
    pub fn status_message(&self) -> Option<&PublicStatusMessage> {
        self.status_message.as_ref()
    }
}

/// Subscription event class requested during negotiation.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum RequestedEventClass {
    /// Complete task snapshots.
    TaskSnapshots,
    /// Request-scoped progress, which is never accepted for task subscriptions.
    RequestProgress,
    /// Request-scoped messages, which are never accepted for task subscriptions.
    RequestMessage,
}

/// Non-empty validated task-handle reconnect proof.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TaskReconnectHandles(Vec<TaskHandle>);

impl TaskReconnectHandles {
    /// Validates that at least one already-validated task handle was supplied.
    ///
    /// # Errors
    ///
    /// Returns [`ValueError::Empty`] when no task handle is supplied.
    pub fn new(handles: Vec<TaskHandle>) -> Result<Self, ValueError> {
        if handles.is_empty() {
            return Err(ValueError::Empty);
        }
        Ok(Self(handles))
    }

    /// Borrows the task handles for authoritative repository validation.
    #[must_use]
    pub fn as_slice(&self) -> &[TaskHandle] {
        &self.0
    }
}

/// Explicit durable replacement proof; protocol sessions and prior request IDs are never proof.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ReconnectProof {
    /// Retry the original subscription operation with its explicit idempotency key.
    Idempotency(IdempotencyKey),
    /// Re-establish observation through explicit server-minted task handles.
    Tasks(TaskReconnectHandles),
}

/// Whether this claim starts a new subscription or replaces a closed stream.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SubscriptionStart {
    /// Starts a new subscription, optionally binding a key for a later durable replacement.
    Initial {
        /// Client-supplied key which a later replacement must repeat exactly.
        idempotency_key: Option<IdempotencyKey>,
    },
    /// Replaces a closed stream using proof validated by the authoritative repository.
    Replacement(ReconnectProof),
}

/// Explicit task subscription request.
///
/// Identity, tenant scope, extension negotiation, and the JSON-RPC request identifier come only
/// from the canonical MCP request context supplied to the service.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SubscribeRequest {
    /// Explicit bounded task filter.
    pub task_ids: Vec<TaskId>,
    /// Requested event classes; only task snapshots are supported.
    pub event_classes: Vec<RequestedEventClass>,
    /// Requested finite lifetime.
    pub ttl_ms: u64,
    /// Explicit new-subscription or closed-stream replacement intent.
    pub start: SubscriptionStart,
}

/// Monotonic cursor for one explicitly filtered task.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TaskCursor {
    /// Task identifier.
    pub task_id: TaskId,
    /// Last accepted task event position.
    pub position: EventPosition,
}

/// Why contiguous replay could not continue.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum ReplayGapReason {
    /// Requested cursor predates retained authoritative history.
    RetentionWindow,
    /// Service reached its finite replay-page work bound and converged to current state.
    ServiceReplayBound,
}

/// Bounded replay gap reported before an authoritative current snapshot.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ReplayGap {
    /// Task whose event history no longer covers the requested cursor.
    pub task_id: TaskId,
    /// Requested cursor.
    pub requested_after: EventPosition,
    /// Gap cause.
    pub reason: ReplayGapReason,
    /// Oldest retained position when the repository retention window caused the gap.
    pub oldest_available: Option<EventPosition>,
    /// Newest authoritative position available during gap resolution.
    pub newest_available: EventPosition,
}

/// Complete acknowledged subscription metadata.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SubscriptionAcknowledgement {
    /// JSON-RPC request identifier used as the subscription identifier.
    pub subscription_id: SubscriptionId,
    /// Only supported, authorized task IDs.
    pub task_ids: Vec<TaskId>,
    /// Supported event classes accepted from negotiation.
    pub event_classes: Vec<RequestedEventClass>,
    /// Finite absolute expiry in Unix milliseconds.
    pub expires_at_ms: u64,
}

/// Why a task subscription ended.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum CloseReason {
    /// Client cancelled the request.
    Cancelled,
    /// Response transport disconnected.
    Disconnected,
    /// Finite subscription lifetime expired.
    Expired,
    /// Per-delivery authorization was revoked.
    AuthorizationRevoked,
    /// Consumer failed bounded backpressure admission.
    SlowConsumer,
    /// Server is draining.
    ServerDrain,
    /// Persistence or backplane state was inconsistent.
    Failed,
}

/// Result of graceful delivery draining.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum DrainOutcome {
    /// Every already-admitted frame was retained ahead of the close record.
    Drained,
    /// The close deadline elapsed and queued frames were discarded.
    DeadlineExceeded,
    /// The transport had already disconnected.
    Disconnected,
}

/// Final transport-neutral close record.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SubscriptionClosed {
    /// Subscription identifier repeated on the close record.
    pub subscription_id: SubscriptionId,
    /// Close cause.
    pub reason: CloseReason,
    /// Drain result.
    pub drain: DrainOutcome,
    /// Final authoritative per-task cursors, in deterministic task order.
    pub cursors: Vec<TaskCursor>,
}

/// Transport-neutral subscription output.
///
/// No variant can represent `notifications/progress` or `notifications/message`.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", content = "payload", rename_all = "camelCase")]
pub enum DeliveryFrame {
    /// Mandatory first frame.
    Acknowledged(SubscriptionAcknowledgement),
    /// Complete authoritative task snapshot.
    TaskSnapshot {
        /// Subscription identifier repeated on every delivery.
        subscription_id: SubscriptionId,
        /// Whether the event came from repository replay.
        replayed: bool,
        /// Complete snapshot.
        snapshot: TaskSnapshot,
    },
    /// Explicit replay-window gap signal.
    ReplayGap {
        /// Subscription identifier repeated on every delivery.
        subscription_id: SubscriptionId,
        /// Gap metadata.
        gap: ReplayGap,
    },
    /// Final graceful or forced close record.
    Closed(SubscriptionClosed),
}

fn event_position_json_len(position: EventPosition) -> usize {
    b"{\"sequence\":"
        .len()
        .saturating_add(u64_json_len(position.sequence()))
        .saturating_add(b",\"revision\":".len())
        .saturating_add(u64_json_len(position.revision()))
        .saturating_add(1)
}

fn task_status_json_len(status: TaskStatus) -> usize {
    json_string_len(match status {
        TaskStatus::Pending => "pending",
        TaskStatus::Working => "working",
        TaskStatus::InputRequired => "inputRequired",
        TaskStatus::Completed => "completed",
        TaskStatus::Failed => "failed",
        TaskStatus::Cancelled => "cancelled",
        TaskStatus::Indeterminate => "indeterminate",
    })
}

fn requested_event_class_json_len(event_class: RequestedEventClass) -> usize {
    json_string_len(match event_class {
        RequestedEventClass::TaskSnapshots => "taskSnapshots",
        RequestedEventClass::RequestProgress => "requestProgress",
        RequestedEventClass::RequestMessage => "requestMessage",
    })
}

fn replay_gap_reason_json_len(reason: ReplayGapReason) -> usize {
    json_string_len(match reason {
        ReplayGapReason::RetentionWindow => "retentionWindow",
        ReplayGapReason::ServiceReplayBound => "serviceReplayBound",
    })
}

fn close_reason_json_len(reason: CloseReason) -> usize {
    json_string_len(match reason {
        CloseReason::Cancelled => "cancelled",
        CloseReason::Disconnected => "disconnected",
        CloseReason::Expired => "expired",
        CloseReason::AuthorizationRevoked => "authorizationRevoked",
        CloseReason::SlowConsumer => "slowConsumer",
        CloseReason::ServerDrain => "serverDrain",
        CloseReason::Failed => "failed",
    })
}

fn drain_outcome_json_len(outcome: DrainOutcome) -> usize {
    json_string_len(match outcome {
        DrainOutcome::Drained => "drained",
        DrainOutcome::DeadlineExceeded => "deadlineExceeded",
        DrainOutcome::Disconnected => "disconnected",
    })
}

fn task_cursor_json_len(cursor: &TaskCursor) -> usize {
    b"{\"taskId\":"
        .len()
        .saturating_add(json_string_len(cursor.task_id.as_str()))
        .saturating_add(b",\"position\":".len())
        .saturating_add(event_position_json_len(cursor.position))
        .saturating_add(1)
}

fn acknowledgement_json_len(value: &SubscriptionAcknowledgement) -> usize {
    b"{\"subscriptionId\":"
        .len()
        .saturating_add(json_string_len(value.subscription_id.as_str()))
        .saturating_add(b",\"taskIds\":".len())
        .saturating_add(json_array_len(
            value
                .task_ids
                .iter()
                .map(|task_id| json_string_len(task_id.as_str())),
        ))
        .saturating_add(b",\"eventClasses\":".len())
        .saturating_add(json_array_len(
            value
                .event_classes
                .iter()
                .copied()
                .map(requested_event_class_json_len),
        ))
        .saturating_add(b",\"expiresAtMs\":".len())
        .saturating_add(u64_json_len(value.expires_at_ms))
        .saturating_add(1)
}

fn task_snapshot_json_len(snapshot: &TaskSnapshot) -> usize {
    b"{\"taskId\":"
        .len()
        .saturating_add(json_string_len(snapshot.task_id.as_str()))
        .saturating_add(b",\"tenantId\":".len())
        .saturating_add(json_string_len(snapshot.tenant_id.as_str()))
        .saturating_add(b",\"position\":".len())
        .saturating_add(event_position_json_len(snapshot.position))
        .saturating_add(b",\"status\":".len())
        .saturating_add(task_status_json_len(snapshot.status))
        .saturating_add(b",\"statusMessage\":".len())
        .saturating_add(
            snapshot
                .status_message
                .as_ref()
                .map_or(b"null".len(), |message| json_string_len(message.as_str())),
        )
        .saturating_add(b",\"createdAtMs\":".len())
        .saturating_add(u64_json_len(snapshot.created_at_ms))
        .saturating_add(b",\"lastUpdatedAtMs\":".len())
        .saturating_add(u64_json_len(snapshot.last_updated_at_ms))
        .saturating_add(b",\"ttlMs\":".len())
        .saturating_add(u64_json_len(snapshot.ttl_ms))
        .saturating_add(1)
}

fn replay_gap_json_len(gap: &ReplayGap) -> usize {
    b"{\"taskId\":"
        .len()
        .saturating_add(json_string_len(gap.task_id.as_str()))
        .saturating_add(b",\"requestedAfter\":".len())
        .saturating_add(event_position_json_len(gap.requested_after))
        .saturating_add(b",\"reason\":".len())
        .saturating_add(replay_gap_reason_json_len(gap.reason))
        .saturating_add(b",\"oldestAvailable\":".len())
        .saturating_add(
            gap.oldest_available
                .map_or(b"null".len(), event_position_json_len),
        )
        .saturating_add(b",\"newestAvailable\":".len())
        .saturating_add(event_position_json_len(gap.newest_available))
        .saturating_add(1)
}

fn subscription_closed_json_len(value: &SubscriptionClosed) -> usize {
    b"{\"subscriptionId\":"
        .len()
        .saturating_add(json_string_len(value.subscription_id.as_str()))
        .saturating_add(b",\"reason\":".len())
        .saturating_add(close_reason_json_len(value.reason))
        .saturating_add(b",\"drain\":".len())
        .saturating_add(drain_outcome_json_len(value.drain))
        .saturating_add(b",\"cursors\":".len())
        .saturating_add(json_array_len(
            value.cursors.iter().map(task_cursor_json_len),
        ))
        .saturating_add(1)
}

impl DeliveryFrame {
    /// Returns the subscription identifier carried by every frame.
    #[must_use]
    pub const fn subscription_id(&self) -> &SubscriptionId {
        match self {
            Self::Acknowledged(value) => &value.subscription_id,
            Self::TaskSnapshot {
                subscription_id, ..
            }
            | Self::ReplayGap {
                subscription_id, ..
            } => subscription_id,
            Self::Closed(value) => &value.subscription_id,
        }
    }
    pub(crate) fn set_drain_outcome(&mut self, outcome: DrainOutcome) {
        if let Self::Closed(closed) = self {
            closed.drain = outcome;
        }
    }

    /// Computes the exact compact JSON encoded size without allocating or serializing the frame.
    #[must_use]
    pub fn encoded_len(&self) -> usize {
        match self {
            Self::Acknowledged(value) => b"{\"kind\":\"acknowledged\",\"payload\":"
                .len()
                .saturating_add(acknowledgement_json_len(value))
                .saturating_add(1),
            Self::TaskSnapshot {
                subscription_id,
                replayed,
                snapshot,
            } => b"{\"kind\":\"taskSnapshot\",\"payload\":{\"subscription_id\":"
                .len()
                .saturating_add(json_string_len(subscription_id.as_str()))
                .saturating_add(b",\"replayed\":".len())
                .saturating_add(if *replayed {
                    b"true".len()
                } else {
                    b"false".len()
                })
                .saturating_add(b",\"snapshot\":".len())
                .saturating_add(task_snapshot_json_len(snapshot))
                .saturating_add(2),
            Self::ReplayGap {
                subscription_id,
                gap,
            } => b"{\"kind\":\"replayGap\",\"payload\":{\"subscription_id\":"
                .len()
                .saturating_add(json_string_len(subscription_id.as_str()))
                .saturating_add(b",\"gap\":".len())
                .saturating_add(replay_gap_json_len(gap))
                .saturating_add(2),
            Self::Closed(value) => b"{\"kind\":\"closed\",\"payload\":"
                .len()
                .saturating_add(subscription_closed_json_len(value))
                .saturating_add(1),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id(value: &str) -> TaskId {
        TaskId::new(value).unwrap_or_else(|error| panic!("task id: {error}"))
    }

    fn subscription_id(value: &str) -> SubscriptionId {
        SubscriptionId::new(value).unwrap_or_else(|error| panic!("subscription id: {error}"))
    }

    fn position(sequence: u64, revision: u64) -> EventPosition {
        EventPosition::new(sequence, revision)
            .unwrap_or_else(|error| panic!("event position: {error}"))
    }

    fn assert_encoded_len(frame: &DeliveryFrame) {
        let serialized =
            serde_json::to_vec(frame).unwrap_or_else(|error| panic!("serialize frame: {error}"));
        assert_eq!(frame.encoded_len(), serialized.len());
    }

    #[test]
    fn json_string_len_matches_serde_json_for_every_escape_class_and_utf8() {
        let value = "\"\\\u{0008}\t\n\u{000c}\r\u{0000}\u{0001}\u{001f} ordinary café 雪 🙂";
        let serialized =
            serde_json::to_vec(value).unwrap_or_else(|error| panic!("serialize string: {error}"));

        assert_eq!(json_string_len(value), serialized.len());
    }

    #[test]
    fn encoded_len_matches_serde_json_for_every_delivery_frame_shape() {
        let escaped_status = PublicStatusMessage(
            "\"\\\u{0008}\t\n\u{000c}\r\u{0000}\u{0001}\u{001f} café 雪 🙂".to_owned(),
        );
        let snapshot = TaskSnapshot {
            task_id: id("task-\"\\"),
            tenant_id: TenantId::new("tenant-\"\\")
                .unwrap_or_else(|error| panic!("tenant id: {error}")),
            position: position(u64::MAX, 10),
            status: TaskStatus::InputRequired,
            status_message: Some(escaped_status),
            created_at_ms: 0,
            last_updated_at_ms: u64::MAX,
            ttl_ms: 10,
        };
        let frames = [
            DeliveryFrame::Acknowledged(SubscriptionAcknowledgement {
                subscription_id: subscription_id("subscription-\"\\"),
                task_ids: vec![id("task-\"\\"), id("second")],
                event_classes: vec![
                    RequestedEventClass::TaskSnapshots,
                    RequestedEventClass::RequestProgress,
                    RequestedEventClass::RequestMessage,
                ],
                expires_at_ms: u64::MAX,
            }),
            DeliveryFrame::TaskSnapshot {
                subscription_id: subscription_id("subscription-\"\\"),
                replayed: false,
                snapshot,
            },
            DeliveryFrame::ReplayGap {
                subscription_id: subscription_id("subscription-\"\\"),
                gap: ReplayGap {
                    task_id: id("task-\"\\"),
                    requested_after: position(1, 9),
                    reason: ReplayGapReason::ServiceReplayBound,
                    oldest_available: Some(position(10, 99)),
                    newest_available: position(u64::MAX, u64::MAX),
                },
            },
            DeliveryFrame::Closed(SubscriptionClosed {
                subscription_id: subscription_id("subscription-\"\\"),
                reason: CloseReason::AuthorizationRevoked,
                drain: DrainOutcome::DeadlineExceeded,
                cursors: vec![
                    TaskCursor {
                        task_id: id("task-\"\\"),
                        position: position(1, 1),
                    },
                    TaskCursor {
                        task_id: id("second"),
                        position: position(u64::MAX, u64::MAX),
                    },
                ],
            }),
        ];

        for frame in &frames {
            assert_encoded_len(frame);
        }
    }

    #[test]
    fn encoded_len_matches_serde_json_for_nulls_and_empty_arrays() {
        let frames = [
            DeliveryFrame::Acknowledged(SubscriptionAcknowledgement {
                subscription_id: subscription_id("subscription"),
                task_ids: Vec::new(),
                event_classes: Vec::new(),
                expires_at_ms: 0,
            }),
            DeliveryFrame::TaskSnapshot {
                subscription_id: subscription_id("subscription"),
                replayed: true,
                snapshot: TaskSnapshot {
                    task_id: id("task"),
                    tenant_id: TenantId::new("tenant")
                        .unwrap_or_else(|error| panic!("tenant id: {error}")),
                    position: position(1, 1),
                    status: TaskStatus::Pending,
                    status_message: None,
                    created_at_ms: 0,
                    last_updated_at_ms: 0,
                    ttl_ms: 1,
                },
            },
            DeliveryFrame::ReplayGap {
                subscription_id: subscription_id("subscription"),
                gap: ReplayGap {
                    task_id: id("task"),
                    requested_after: position(1, 1),
                    reason: ReplayGapReason::RetentionWindow,
                    oldest_available: None,
                    newest_available: position(1, 1),
                },
            },
            DeliveryFrame::Closed(SubscriptionClosed {
                subscription_id: subscription_id("subscription"),
                reason: CloseReason::Cancelled,
                drain: DrainOutcome::Drained,
                cursors: Vec::new(),
            }),
        ];

        for frame in &frames {
            assert_encoded_len(frame);
        }
    }
}

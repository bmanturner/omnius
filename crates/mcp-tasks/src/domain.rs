use std::{collections::BTreeMap, fmt, str::FromStr, time::Duration};

use omnius_agent_capability_registry::{
    BudgetBounds, CapabilityKey, ConfirmationEvidence, IdempotencyKey, TenantMode,
};
use omnius_auth_core::{Principal, SubjectId, TenantId};
use omnius_core::{CausationId, CorrelationId, RequestId};
use omnius_jobs_core::JobId;
use omnius_mcp_tools::{
    CanonicalToolResult, CurrentResultAdapter, InputRequiredToolResult, MAX_REQUEST_STATE_BYTES,
    ToolResultAdapter,
};
use rmcp::model::{CallToolResponse, CallToolResult, ServerResult};
use serde::{Deserialize, Deserializer, Serialize, Serializer, de::Error as _};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use thiserror::Error;
use time::OffsetDateTime;
use uuid::{Uuid, Variant, Version};

/// Maximum serialized bytes accepted for one task input or input-response batch.
pub const MAX_TASK_INPUT_BYTES: usize = 1_048_576;
/// Maximum serialized bytes accepted for one canonical terminal task result.
pub const MAX_TASK_RESULT_BYTES: usize = 16 * 1_024 * 1_024 + 4_096;
/// Maximum outstanding input requests in one round.
pub const MAX_INPUT_REQUESTS: usize = 64;
const MAX_INPUT_KEY_BYTES: usize = 128;
const MAX_RESERVATION_REF_BYTES: usize = 256;

/// A task identifier was malformed.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum TaskIdError {
    /// The value was not a UUID.
    #[error("task identifier is not a valid UUID")]
    Invalid,
    /// The value was not an RFC-compatible `UUIDv7`.
    #[error("task identifier must be UUID version 7")]
    NotVersion7,
}

/// Stable server-generated task identity.
#[derive(Clone, Copy, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct TaskId(Uuid);

impl TaskId {
    /// Generates a time-ordered `UUIDv7` task identifier.
    #[must_use]
    pub fn new() -> Self {
        Self(Uuid::now_v7())
    }

    /// Restores an existing `UUIDv7` identifier.
    ///
    /// # Errors
    ///
    /// Returns [`TaskIdError::NotVersion7`] for any other UUID version or variant.
    pub fn from_uuid(value: Uuid) -> Result<Self, TaskIdError> {
        if value.get_version() == Some(Version::SortRand) && value.get_variant() == Variant::RFC4122
        {
            Ok(Self(value))
        } else {
            Err(TaskIdError::NotVersion7)
        }
    }

    /// Returns the underlying UUID.
    #[must_use]
    pub const fn as_uuid(self) -> Uuid {
        self.0
    }
}

impl Default for TaskId {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for TaskId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

impl fmt::Debug for TaskId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_tuple("TaskId").field(&self.0).finish()
    }
}

impl FromStr for TaskId {
    type Err = TaskIdError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let value = Uuid::parse_str(value).map_err(|_| TaskIdError::Invalid)?;
        Self::from_uuid(value)
    }
}

impl Serialize for TaskId {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.collect_str(self)
    }
}

impl<'de> Deserialize<'de> for TaskId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        Self::from_str(&String::deserialize(deserializer)?).map_err(D::Error::custom)
    }
}

/// Canonical task owner boundary used by every repository query.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TaskOwner {
    subject_id: SubjectId,
    tenant_id: Option<TenantId>,
}

impl TaskOwner {
    /// Derives owner identity only from the authenticated principal.
    #[must_use]
    pub const fn from_principal(principal: &Principal) -> Self {
        Self {
            subject_id: principal.subject_id,
            tenant_id: principal.tenant_id,
        }
    }

    /// Creates an owner identity from an already canonical boundary.
    #[must_use]
    pub const fn new(subject_id: SubjectId, tenant_id: Option<TenantId>) -> Self {
        Self {
            subject_id,
            tenant_id,
        }
    }

    /// Returns the authenticated subject.
    #[must_use]
    pub const fn subject_id(self) -> SubjectId {
        self.subject_id
    }

    /// Returns the authenticated tenant scope.
    #[must_use]
    pub const fn tenant_id(self) -> Option<TenantId> {
        self.tenant_id
    }
}

/// A bounded task value was malformed.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum TaskValueError {
    /// The value was empty.
    #[error("task value must not be empty")]
    Empty,
    /// The value exceeded its byte ceiling.
    #[error("task value exceeds its byte limit")]
    TooLong,
    /// The value contained a forbidden character or shape.
    #[error("task value has an invalid format")]
    Invalid,
}

/// Opaque budget reservation retained for worker accounting.
#[derive(Clone, Eq, Hash, PartialEq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct BudgetReservationRef(String);

impl BudgetReservationRef {
    /// Validates and owns an opaque printable reservation reference.
    ///
    /// # Errors
    ///
    /// Returns [`TaskValueError`] when the reference is empty, excessive, or non-printable.
    pub fn new(value: String) -> Result<Self, TaskValueError> {
        validate_graphic(&value, MAX_RESERVATION_REF_BYTES)?;
        Ok(Self(value))
    }

    /// Borrows the reservation reference.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for BudgetReservationRef {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("BudgetReservationRef([redacted])")
    }
}

/// Immutable digest of canonical invocation arguments.
#[derive(Clone, Copy, Eq, Hash, PartialEq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct RequestFingerprint([u8; 32]);

impl RequestFingerprint {
    /// Hashes the capability revision and normalized JSON input.
    ///
    /// # Errors
    ///
    /// Returns [`TaskValueError::TooLong`] when the serialized input exceeds the task ceiling.
    pub fn for_invocation(
        capability: &CapabilityKey,
        normalized_input: &Value,
    ) -> Result<Self, TaskValueError> {
        let input = serde_json::to_vec(normalized_input).map_err(|_| TaskValueError::Invalid)?;
        if input.len() > MAX_TASK_INPUT_BYTES {
            return Err(TaskValueError::TooLong);
        }
        let mut hasher = Sha256::new();
        hash_segment(&mut hasher, capability.id().as_str().as_bytes());
        hash_segment(&mut hasher, capability.version().as_str().as_bytes());
        hash_segment(&mut hasher, &input);
        Ok(Self(hasher.finalize().into()))
    }

    /// Returns the digest bytes for equality/index storage.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Debug for RequestFingerprint {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("RequestFingerprint([redacted])")
    }
}

/// Durable create identity scoped by owner and capability revision in the repository.
#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TaskIdempotency {
    key: IdempotencyKey,
    fingerprint: RequestFingerprint,
}

impl TaskIdempotency {
    /// Creates the durable idempotency identity.
    #[must_use]
    pub const fn new(key: IdempotencyKey, fingerprint: RequestFingerprint) -> Self {
        Self { key, fingerprint }
    }

    /// Returns the canonical client idempotency key.
    #[must_use]
    pub const fn key(&self) -> &IdempotencyKey {
        &self.key
    }

    /// Returns the normalized invocation fingerprint.
    #[must_use]
    pub const fn fingerprint(&self) -> RequestFingerprint {
        self.fingerprint
    }
}

impl fmt::Debug for TaskIdempotency {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("TaskIdempotency([redacted])")
    }
}

/// Immutable budget and accounting reservation attached to a task.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TaskBudget {
    bounds: BudgetBounds,
    reservation: BudgetReservationRef,
}

impl TaskBudget {
    /// Creates retained budget identity.
    #[must_use]
    pub const fn new(bounds: BudgetBounds, reservation: BudgetReservationRef) -> Self {
        Self {
            bounds,
            reservation,
        }
    }

    /// Returns immutable resource ceilings.
    #[must_use]
    pub const fn bounds(&self) -> BudgetBounds {
        self.bounds
    }

    /// Returns the accounting reservation reference.
    #[must_use]
    pub const fn reservation(&self) -> &BudgetReservationRef {
        &self.reservation
    }
}

/// Durable execution context needed to re-enter the canonical capability registry.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TaskExecution {
    capability: CapabilityKey,
    tenant_mode: TenantMode,
    confirmation: ConfirmationEvidence,
    input: Value,
    idempotency_key: IdempotencyKey,
    budget: TaskBudget,
}

impl TaskExecution {
    /// Creates a durable registry execution request.
    ///
    /// # Errors
    ///
    /// Returns [`TaskValueError`] unless input is a bounded JSON object.
    pub fn new(
        capability: CapabilityKey,
        tenant_mode: TenantMode,
        confirmation: ConfirmationEvidence,
        input: Value,
        idempotency_key: IdempotencyKey,
        budget: TaskBudget,
    ) -> Result<Self, TaskValueError> {
        validate_json_object(&input, MAX_TASK_INPUT_BYTES)?;
        Ok(Self {
            capability,
            tenant_mode,
            confirmation,
            input,
            idempotency_key,
            budget,
        })
    }

    /// Returns the targeted capability revision.
    #[must_use]
    pub const fn capability(&self) -> &CapabilityKey {
        &self.capability
    }

    /// Returns the selected canonical tenant mode.
    #[must_use]
    pub const fn tenant_mode(&self) -> TenantMode {
        self.tenant_mode
    }

    /// Returns retained confirmation evidence.
    #[must_use]
    pub const fn confirmation(&self) -> ConfirmationEvidence {
        self.confirmation
    }

    /// Borrows the original normalized input.
    #[must_use]
    pub const fn input(&self) -> &Value {
        &self.input
    }

    /// Returns the canonical capability idempotency key.
    #[must_use]
    pub const fn idempotency_key(&self) -> &IdempotencyKey {
        &self.idempotency_key
    }

    /// Returns retained budget identity.
    #[must_use]
    pub const fn budget(&self) -> &TaskBudget {
        &self.budget
    }
}

impl fmt::Debug for TaskExecution {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TaskExecution")
            .field("capability", &self.capability)
            .field("tenant_mode", &self.tenant_mode)
            .field("input", &"[REDACTED]")
            .field("idempotency_key", &"[REDACTED]")
            .field("budget", &self.budget)
            .finish_non_exhaustive()
    }
}

/// Immutable identifiers and timestamps retained by the authoritative task row.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[expect(
    clippy::struct_field_names,
    reason = "the suffix distinguishes three semantically different distributed trace identifiers"
)]
pub struct TaskIdentity {
    request_id: RequestId,
    correlation_id: CorrelationId,
    causation_id: Option<CausationId>,
}

impl TaskIdentity {
    /// Creates cross-transport task identity.
    #[must_use]
    pub const fn new(
        request_id: RequestId,
        correlation_id: CorrelationId,
        causation_id: Option<CausationId>,
    ) -> Self {
        Self {
            request_id,
            correlation_id,
            causation_id,
        }
    }

    /// Returns the originating request identifier.
    #[must_use]
    pub const fn request_id(&self) -> RequestId {
        self.request_id
    }

    /// Returns the cross-transport correlation identifier.
    #[must_use]
    pub const fn correlation_id(&self) -> CorrelationId {
        self.correlation_id
    }

    /// Returns the optional causation identifier.
    #[must_use]
    pub const fn causation_id(&self) -> Option<CausationId> {
        self.causation_id
    }
}

/// Monotonic task execution generation.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(transparent)]
pub struct TaskGeneration(u64);

impl TaskGeneration {
    /// Initial task generation.
    pub const INITIAL: Self = Self(1);

    /// Creates a non-zero generation.
    ///
    /// # Errors
    ///
    /// Returns [`TaskValueError::Invalid`] for zero.
    pub const fn new(value: u64) -> Result<Self, TaskValueError> {
        if value == 0 {
            Err(TaskValueError::Invalid)
        } else {
            Ok(Self(value))
        }
    }

    /// Returns the generation number.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }

    /// Returns the next generation, or `None` on integer exhaustion.
    #[must_use]
    pub const fn next(self) -> Option<Self> {
        match self.0.checked_add(1) {
            Some(value) => Some(Self(value)),
            None => None,
        }
    }
}

/// Monotonic optimistic-lock version.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(transparent)]
pub struct TaskVersion(u64);

impl TaskVersion {
    /// Initial persisted version.
    pub const INITIAL: Self = Self(1);

    /// Restores a non-zero version.
    ///
    /// # Errors
    ///
    /// Returns [`TaskValueError::Invalid`] for zero.
    pub const fn new(value: u64) -> Result<Self, TaskValueError> {
        if value == 0 {
            Err(TaskValueError::Invalid)
        } else {
            Ok(Self(value))
        }
    }

    /// Returns the version number.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }
}

/// Validated lifetime and polling policy for durable tasks.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TaskConfig {
    ttl: Duration,
    poll_interval: Duration,
    expiry_batch_size: usize,
}

impl TaskConfig {
    /// Validates finite task lifetime, bounded poll interval, and expiry batch size.
    ///
    /// # Errors
    ///
    /// Returns [`TaskValueError`] for zero, excessive, or sub-millisecond durations.
    pub fn new(
        ttl: Duration,
        poll_interval: Duration,
        expiry_batch_size: usize,
    ) -> Result<Self, TaskValueError> {
        const MAX_TTL: Duration = Duration::from_hours(8_760);
        const MAX_POLL: Duration = Duration::from_secs(60);
        if ttl < Duration::from_millis(1)
            || ttl > MAX_TTL
            || poll_interval < Duration::from_millis(100)
            || poll_interval > MAX_POLL
            || expiry_batch_size == 0
            || expiry_batch_size > 1_000
        {
            return Err(TaskValueError::Invalid);
        }
        Ok(Self {
            ttl,
            poll_interval,
            expiry_batch_size,
        })
    }

    /// Returns the finite authoritative lifetime.
    #[must_use]
    pub const fn ttl(self) -> Duration {
        self.ttl
    }

    /// Returns the bounded client polling hint.
    #[must_use]
    pub const fn poll_interval(self) -> Duration {
        self.poll_interval
    }

    /// Returns the maximum expiry rows claimed per transaction.
    #[must_use]
    pub const fn expiry_batch_size(self) -> usize {
        self.expiry_batch_size
    }
}
/// Bounded opaque continuation binding retained with one task input round.
#[derive(Clone, Eq, PartialEq, Serialize)]
#[serde(transparent)]
pub struct TaskRequestState(String);

impl TaskRequestState {
    /// Validates and owns canonical synchronous input-required request state.
    ///
    /// # Errors
    ///
    /// Returns a fixed redacted error for empty, oversized, or non-printable state.
    pub fn new(value: String) -> Result<Self, TaskValueError> {
        if value.is_empty()
            || value.len() > MAX_REQUEST_STATE_BYTES
            || !value.is_ascii()
            || !value.bytes().all(|byte| matches!(byte, b'!'..=b'~'))
        {
            return Err(TaskValueError::Invalid);
        }
        Ok(Self(value))
    }

    /// Borrows the opaque continuation state.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl<'de> Deserialize<'de> for TaskRequestState {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        Self::new(String::deserialize(deserializer)?).map_err(D::Error::custom)
    }
}

impl fmt::Debug for TaskRequestState {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("TaskRequestState([redacted])")
    }
}

/// Unique key for one input request over the lifetime of a task.
#[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(transparent)]
pub struct InputKey(String);

impl InputKey {
    /// Validates and owns an input request key.
    ///
    /// # Errors
    ///
    /// Returns [`TaskValueError`] when the key is empty, excessive, or non-printable.
    pub fn new(value: String) -> Result<Self, TaskValueError> {
        validate_graphic(&value, MAX_INPUT_KEY_BYTES)?;
        Ok(Self(value))
    }

    /// Borrows the key.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for InputKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("InputKey([redacted])")
    }
}

/// One protected server-to-client request and its optional durable response.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InputExchange {
    request: Value,
    response: Option<Value>,
}

impl InputExchange {
    /// Creates one outstanding canonical MCP input request.
    ///
    /// # Errors
    ///
    /// Returns [`TaskValueError`] unless the request is a bounded exact official input-request
    /// object.
    pub fn pending(request: Value) -> Result<Self, TaskValueError> {
        validate_json_object(&request, MAX_TASK_INPUT_BYTES)?;
        let decoded: rmcp::model::InputRequest =
            serde_json::from_value(request.clone()).map_err(|_| TaskValueError::Invalid)?;
        let normalized = serde_json::to_value(decoded).map_err(|_| TaskValueError::Invalid)?;
        if normalized != request {
            return Err(TaskValueError::Invalid);
        }
        Ok(Self {
            request,
            response: None,
        })
    }

    /// Borrows the request object.
    #[must_use]
    pub const fn request(&self) -> &Value {
        &self.request
    }

    /// Borrows the response when it has been durably accepted.
    #[must_use]
    pub const fn response(&self) -> Option<&Value> {
        self.response.as_ref()
    }

    /// Reports whether the key is still outstanding.
    #[must_use]
    pub const fn is_pending(&self) -> bool {
        self.response.is_none()
    }
}

impl fmt::Debug for InputExchange {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("InputExchange")
            .field("request", &"[REDACTED]")
            .field("answered", &self.response.is_some())
            .finish()
    }
}

/// Durable, monotonically numbered input round.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InputRound {
    number: u64,
    request_state: TaskRequestState,
    exchanges: BTreeMap<InputKey, InputExchange>,
}

impl InputRound {
    /// Creates a non-empty, bounded round of unique lifetime keys.
    ///
    /// # Errors
    ///
    /// Returns [`TaskValueError`] for round zero, an empty/excessive set, or excessive JSON.
    pub fn new(
        number: u64,
        request_state: TaskRequestState,
        exchanges: BTreeMap<InputKey, InputExchange>,
    ) -> Result<Self, TaskValueError> {
        if number == 0 || exchanges.is_empty() || exchanges.len() > MAX_INPUT_REQUESTS {
            return Err(TaskValueError::Invalid);
        }
        validate_serialized(&exchanges, MAX_TASK_INPUT_BYTES)?;
        Ok(Self {
            number,
            request_state,
            exchanges,
        })
    }
    /// Projects canonical synchronous input-required output into a durable task round.
    ///
    /// # Errors
    ///
    /// Returns a fixed redacted error when adaptation fails, the round is invalid, or its exact
    /// official input requests exceed task bounds.
    pub fn from_tool_input_required(
        number: u64,
        result: InputRequiredToolResult,
    ) -> Result<Self, TaskValueError> {
        let request_state = TaskRequestState::new(result.request_state().as_str().to_owned())?;
        let response = CurrentResultAdapter
            .adapt(CanonicalToolResult::input_required(result))
            .map_err(|_| TaskValueError::Invalid)?;
        if !matches!(&response, CallToolResponse::InputRequired(_)) {
            return Err(TaskValueError::Invalid);
        }
        let value = serde_json::to_value(ServerResult::from(response))
            .map_err(|_| TaskValueError::Invalid)?;
        let Value::Object(mut wire) = value else {
            return Err(TaskValueError::Invalid);
        };
        if wire.get("resultType").and_then(Value::as_str) != Some("input_required") {
            return Err(TaskValueError::Invalid);
        }
        let Some(Value::Object(requests)) = wire.remove("inputRequests") else {
            return Err(TaskValueError::Invalid);
        };
        let mut exchanges = BTreeMap::new();
        for (key, request) in requests {
            exchanges.insert(InputKey::new(key)?, InputExchange::pending(request)?);
        }
        Self::new(number, request_state, exchanges)
    }

    /// Returns the monotonic round number.
    #[must_use]
    pub const fn number(&self) -> u64 {
        self.number
    }
    /// Returns the opaque continuation binding for this round.
    #[must_use]
    pub const fn request_state(&self) -> &TaskRequestState {
        &self.request_state
    }

    /// Iterates only currently outstanding requests.
    pub fn pending(&self) -> impl Iterator<Item = (&InputKey, &InputExchange)> {
        self.exchanges
            .iter()
            .filter(|(_, exchange)| exchange.is_pending())
    }

    /// Returns every exchange for durable worker resumption.
    #[must_use]
    pub const fn exchanges(&self) -> &BTreeMap<InputKey, InputExchange> {
        &self.exchanges
    }

    /// Applies only currently outstanding keys and ignores unknown or replayed keys.
    ///
    /// A changed response for an already answered key is also ignored, preserving the
    /// first durable response and exactly-once logical input semantics.
    #[must_use]
    pub fn apply(&self, responses: &InputResponses) -> InputRoundUpdate {
        let mut round = self.clone();
        let mut changed = false;
        for (key, response) in responses.as_map() {
            let Some(exchange) = round.exchanges.get_mut(key) else {
                continue;
            };
            if exchange.response.is_none() {
                exchange.response = Some(response.clone());
                changed = true;
            }
        }
        let complete = round
            .exchanges
            .values()
            .all(|exchange| !exchange.is_pending());
        InputRoundUpdate {
            round,
            changed,
            complete,
        }
    }

    fn is_response_successor(&self, next: &Self) -> bool {
        self.number == next.number
            && self.request_state == next.request_state
            && self.exchanges.len() == next.exchanges.len()
            && self.exchanges.iter().all(|(key, current)| {
                next.exchanges.get(key).is_some_and(|candidate| {
                    current.request == candidate.request
                        && match &current.response {
                            Some(response) => candidate.response.as_ref() == Some(response),
                            None => true,
                        }
                })
            })
    }
}

impl fmt::Debug for InputRound {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("InputRound")
            .field("number", &self.number)
            .field("exchange_count", &self.exchanges.len())
            .field("content", &"[REDACTED]")
            .finish_non_exhaustive()
    }
}

/// Validated client response batch for `tasks/update`.
#[derive(Clone, Serialize, Deserialize)]
#[serde(transparent)]
pub struct InputResponses(BTreeMap<InputKey, Value>);

impl InputResponses {
    /// Validates response keys, object shapes, count, and serialized byte budget.
    ///
    /// # Errors
    ///
    /// Returns [`TaskValueError`] for an empty/excessive batch or malformed response.
    pub fn new(responses: BTreeMap<String, Value>) -> Result<Self, TaskValueError> {
        if responses.is_empty() || responses.len() > MAX_INPUT_REQUESTS {
            return Err(TaskValueError::Invalid);
        }
        let mut validated = BTreeMap::new();
        for (key, response) in responses {
            validate_json_object(&response, MAX_TASK_INPUT_BYTES)?;
            validated.insert(InputKey::new(key)?, response);
        }
        validate_serialized(&validated, MAX_TASK_INPUT_BYTES)?;
        Ok(Self(validated))
    }

    /// Borrows the validated responses.
    #[must_use]
    pub const fn as_map(&self) -> &BTreeMap<InputKey, Value> {
        &self.0
    }
}

impl fmt::Debug for InputResponses {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("InputResponses")
            .field("count", &self.0.len())
            .field("content", &"[REDACTED]")
            .finish()
    }
}

/// Pure application result for one client input-response batch.
#[derive(Clone, Debug)]
pub struct InputRoundUpdate {
    round: InputRound,
    changed: bool,
    complete: bool,
}

impl InputRoundUpdate {
    /// Returns the updated protected round.
    #[must_use]
    pub const fn round(&self) -> &InputRound {
        &self.round
    }

    /// Reports whether at least one current outstanding key was accepted.
    #[must_use]
    pub const fn changed(&self) -> bool {
        self.changed
    }

    /// Reports whether every request in this round now has exactly one response.
    #[must_use]
    pub const fn complete(&self) -> bool {
        self.complete
    }

    /// Consumes the update into the protected round.
    #[must_use]
    pub fn into_round(self) -> InputRound {
        self.round
    }
}

/// Exact authoritative task lifecycle status.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TaskStatus {
    /// Capability execution is eligible or active.
    Working,
    /// The current generation is waiting for client input.
    InputRequired,
    /// The canonical capability result committed.
    Completed,
    /// Execution ended with a safe terminal failure.
    Failed,
    /// Cooperative cancellation converged before completion.
    Cancelled,
}

impl TaskStatus {
    /// Reports whether the state is immutable except for retention cleanup.
    #[must_use]
    pub const fn is_terminal(self) -> bool {
        matches!(self, Self::Completed | Self::Failed | Self::Cancelled)
    }
}

/// Bounded final task result in the exact synchronous MCP tool-result representation.
///
/// Construction accepts only the bounded canonical tool-result algebra and projects it through the
/// same current RMCP adapter as synchronous tool execution before persistence.
#[derive(Clone, PartialEq, Serialize)]
#[serde(transparent)]
pub struct CanonicalTaskResult(Map<String, Value>);

impl CanonicalTaskResult {
    /// Projects one complete canonical tool result to its exact current MCP wire object.
    ///
    /// Input-required outcomes belong in [`TaskState::InputRequired`] and are rejected here so
    /// they cannot be persisted as terminal completion.
    ///
    /// # Errors
    ///
    /// Returns a fixed redacted error for input-required, unrepresentable, malformed, or
    /// oversized results.
    pub fn from_tool_result(result: CanonicalToolResult) -> Result<Self, TaskValueError> {
        let response = CurrentResultAdapter
            .adapt(result)
            .map_err(|_| TaskValueError::Invalid)?;
        if !matches!(&response, CallToolResponse::Complete(_)) {
            return Err(TaskValueError::Invalid);
        }
        let value = serde_json::to_value(ServerResult::from(response))
            .map_err(|_| TaskValueError::Invalid)?;
        let Value::Object(result) = value else {
            return Err(TaskValueError::Invalid);
        };
        Self::validated_projected(result)
    }

    /// Borrows the exact flattened MCP result object.
    #[must_use]
    pub const fn as_map(&self) -> &Map<String, Value> {
        &self.0
    }

    fn validated_projected(result: Map<String, Value>) -> Result<Self, TaskValueError> {
        validate_serialized(&result, MAX_TASK_RESULT_BYTES)?;
        let Some(is_error) = result.get("isError").and_then(Value::as_bool) else {
            return Err(TaskValueError::Invalid);
        };
        let Some(content) = result.get("content").and_then(Value::as_array) else {
            return Err(TaskValueError::Invalid);
        };
        let has_structured = result.contains_key("structuredContent");
        if result.get("resultType").and_then(Value::as_str) != Some("complete")
            || (is_error && (has_structured || content.is_empty()))
            || (!is_error && content.is_empty() && !has_structured)
            || result.keys().any(|key| {
                !matches!(
                    key.as_str(),
                    "resultType" | "content" | "structuredContent" | "isError"
                )
            })
        {
            return Err(TaskValueError::Invalid);
        }
        Ok(Self(result))
    }

    fn validated_persisted(result: Map<String, Value>) -> Result<Self, TaskValueError> {
        serde_json::from_value::<CallToolResult>(Value::Object(result.clone()))
            .map_err(|_| TaskValueError::Invalid)?;
        Self::validated_projected(result)
    }
}

impl<'de> Deserialize<'de> for CanonicalTaskResult {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let result = Map::<String, Value>::deserialize(deserializer)?;
        Self::validated_persisted(result).map_err(D::Error::custom)
    }
}

impl fmt::Debug for CanonicalTaskResult {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("CanonicalTaskResult([redacted])")
    }
}

/// Safe failure categories persisted and exposed without provider content.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TaskFailureCode {
    /// Registry admission or authorization rejected execution.
    CapabilityRejected,
    /// The execution deadline elapsed.
    DeadlineExceeded,
    /// The canonical handler failed.
    ExecutionFailed,
    /// A canonical result could not form a bounded synchronous MCP result.
    InvalidResult,
    /// The authoritative finite TTL elapsed.
    Expired,
    /// An external effect could not be authoritatively classified.
    Indeterminate,
}

impl TaskFailureCode {
    /// Builds the fixed JSON-RPC error object for `tasks/get`.
    #[must_use]
    pub fn json_rpc_error(self) -> Map<String, Value> {
        let (code, message) = match self {
            Self::CapabilityRejected => (-32_003, "capability execution was rejected"),
            Self::DeadlineExceeded => (-32_008, "task execution deadline was exceeded"),
            Self::ExecutionFailed => (-32_003, "task execution failed"),
            Self::InvalidResult => (-32_603, "task result was invalid"),
            Self::Expired => (-32_008, "task expired"),
            Self::Indeterminate => (-32_603, "task outcome is indeterminate"),
        };
        Map::from_iter([
            ("code".to_owned(), Value::from(code)),
            ("message".to_owned(), Value::from(message)),
        ])
    }
}

/// One repository-authorized state transition.
pub enum TaskTransition {
    /// Pause the current generation for a durable input round.
    RequireInput(InputRound),
    /// Persist a partial set of first responses while remaining input-required.
    RecordInput(InputRound),
    /// Resume execution with a fully answered round and newly outboxed job generation.
    Resume {
        /// Fully answered current round retained in protected history.
        answered_round: InputRound,
        /// Newly generated durable job identity.
        job_id: JobId,
        /// Next execution generation.
        generation: TaskGeneration,
    },
    /// Retain the state while recording cooperative cancellation intent.
    RequestCancellation,
    /// Commit one bounded canonical synchronous MCP result object.
    Complete(CanonicalTaskResult),
    /// Commit a fixed safe terminal failure.
    Fail(TaskFailureCode),
    /// Commit cooperative cancellation.
    Cancel,
}

impl fmt::Debug for TaskTransition {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::RequireInput(round) => formatter
                .debug_tuple("TaskTransition::RequireInput")
                .field(&round.number())
                .finish(),
            Self::RecordInput(round) => formatter
                .debug_tuple("TaskTransition::RecordInput")
                .field(&round.number())
                .finish(),
            Self::Resume {
                answered_round,
                job_id,
                generation,
            } => formatter
                .debug_struct("TaskTransition::Resume")
                .field("round", &answered_round.number())
                .field("job_id", job_id)
                .field("generation", generation)
                .finish(),
            Self::RequestCancellation => formatter.write_str("TaskTransition::RequestCancellation"),
            Self::Complete(_) => formatter.write_str("TaskTransition::Complete([redacted])"),
            Self::Fail(failure) => formatter
                .debug_tuple("TaskTransition::Fail")
                .field(failure)
                .finish(),
            Self::Cancel => formatter.write_str("TaskTransition::Cancel"),
        }
    }
}

/// A repository attempted an invalid or stale state transition.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum TaskTransitionError {
    /// The optimistic-lock version was stale.
    #[error("task transition version is stale")]
    StaleVersion,
    /// A terminal task cannot transition.
    #[error("terminal task state is immutable")]
    Terminal,
    /// The transition is not legal from the current state.
    #[error("task state transition is invalid")]
    Invalid,
    /// The mutation time did not advance monotonically.
    #[error("task update time must advance")]
    NonMonotonicTime,
    /// A monotonic counter was exhausted.
    #[error("task monotonic counter is exhausted")]
    Exhausted,
}

/// Status-specific authoritative task payload.
#[derive(Clone, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case", deny_unknown_fields)]
pub enum TaskState {
    /// Capability execution is eligible or active.
    Working,
    /// A durable input round is outstanding.
    InputRequired {
        /// Current durable round.
        round: InputRound,
    },
    /// Canonical synchronous MCP capability result committed unchanged.
    Completed {
        /// Bounded exact flattened result object.
        result: CanonicalTaskResult,
    },
    /// Safe JSON-RPC failure category.
    Failed {
        /// Fixed redacted failure category.
        failure: TaskFailureCode,
    },
    /// Cooperative cancellation converged.
    Cancelled,
}

impl TaskState {
    /// Returns the exact status discriminator.
    #[must_use]
    pub const fn status(&self) -> TaskStatus {
        match self {
            Self::Working => TaskStatus::Working,
            Self::InputRequired { .. } => TaskStatus::InputRequired,
            Self::Completed { .. } => TaskStatus::Completed,
            Self::Failed { .. } => TaskStatus::Failed,
            Self::Cancelled => TaskStatus::Cancelled,
        }
    }

    /// Reports terminal immutability.
    #[must_use]
    pub const fn is_terminal(&self) -> bool {
        self.status().is_terminal()
    }
}

impl fmt::Debug for TaskState {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Working => formatter.write_str("TaskState::Working"),
            Self::InputRequired { round } => formatter
                .debug_struct("TaskState::InputRequired")
                .field("round", &round.number())
                .field("content", &"[REDACTED]")
                .finish(),
            Self::Completed { .. } => formatter.write_str("TaskState::Completed([redacted])"),
            Self::Failed { failure } => formatter
                .debug_tuple("TaskState::Failed")
                .field(failure)
                .finish(),
            Self::Cancelled => formatter.write_str("TaskState::Cancelled"),
        }
    }
}

/// Authoritative task snapshot returned by repository operations.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TaskSnapshot {
    task_id: TaskId,
    owner: TaskOwner,
    capability: CapabilityKey,
    identity: TaskIdentity,
    idempotency: TaskIdempotency,
    budget: TaskBudget,
    current_job_id: JobId,
    generation: TaskGeneration,
    version: TaskVersion,
    state: TaskState,
    cancellation_requested: bool,
    #[serde(with = "time::serde::rfc3339")]
    created_at: OffsetDateTime,
    #[serde(with = "time::serde::rfc3339")]
    updated_at: OffsetDateTime,
    #[serde(with = "time::serde::rfc3339")]
    expires_at: OffsetDateTime,
    poll_interval_ms: u64,
}

impl TaskSnapshot {
    /// Creates the initial immediately resolvable working snapshot.
    #[expect(
        clippy::too_many_arguments,
        reason = "the task row deliberately retains every independent durable identity"
    )]
    #[must_use]
    pub fn initial(
        task_id: TaskId,
        owner: TaskOwner,
        capability: CapabilityKey,
        identity: TaskIdentity,
        idempotency: TaskIdempotency,
        budget: TaskBudget,
        current_job_id: JobId,
        created_at: OffsetDateTime,
        config: TaskConfig,
    ) -> Self {
        let ttl = time::Duration::try_from(config.ttl()).unwrap_or(time::Duration::MAX);
        Self {
            task_id,
            owner,
            capability,
            identity,
            idempotency,
            budget,
            current_job_id,
            generation: TaskGeneration::INITIAL,
            version: TaskVersion::INITIAL,
            state: TaskState::Working,
            cancellation_requested: false,
            created_at,
            updated_at: created_at,
            expires_at: created_at.saturating_add(ttl),
            poll_interval_ms: duration_millis(config.poll_interval()),
        }
    }
    /// Replaces caller-observed initial timestamps with one authoritative repository time.
    pub(crate) fn with_authoritative_creation_time(
        mut self,
        now: OffsetDateTime,
    ) -> Result<Self, TaskValueError> {
        if self.generation != TaskGeneration::INITIAL
            || self.version != TaskVersion::INITIAL
            || !matches!(self.state, TaskState::Working)
            || self.cancellation_requested
            || self.created_at != self.updated_at
        {
            return Err(TaskValueError::Invalid);
        }
        let ttl = self.expires_at - self.created_at;
        if ttl <= time::Duration::ZERO {
            return Err(TaskValueError::Invalid);
        }
        let expires_at = now.checked_add(ttl).ok_or(TaskValueError::Invalid)?;
        self.created_at = now;
        self.updated_at = now;
        self.expires_at = expires_at;
        Ok(self)
    }
    #[expect(
        clippy::too_many_arguments,
        reason = "durable restoration validates every independently persisted task field"
    )]
    pub(crate) fn restore(
        task_id: TaskId,
        owner: TaskOwner,
        capability: CapabilityKey,
        identity: TaskIdentity,
        idempotency: TaskIdempotency,
        budget: TaskBudget,
        current_job_id: JobId,
        generation: TaskGeneration,
        version: TaskVersion,
        state: TaskState,
        cancellation_requested: bool,
        created_at: OffsetDateTime,
        updated_at: OffsetDateTime,
        expires_at: OffsetDateTime,
        poll_interval_ms: u64,
    ) -> Result<Self, TaskValueError> {
        const MAX_TTL_MILLIS: i128 = 365 * 24 * 60 * 60 * 1_000;
        const MIN_POLL_MILLIS: u64 = 100;
        const MAX_POLL_MILLIS: u64 = 60_000;

        let state = validate_restored_state(state)?;
        let ttl_millis = (expires_at - created_at).whole_milliseconds();
        let expiry_timing_is_valid = match &state {
            TaskState::Failed {
                failure: TaskFailureCode::Expired,
            } => updated_at >= expires_at,
            _ => updated_at < expires_at,
        };
        if created_at > updated_at
            || ttl_millis <= 0
            || ttl_millis > MAX_TTL_MILLIS
            || !(MIN_POLL_MILLIS..=MAX_POLL_MILLIS).contains(&poll_interval_ms)
            || generation.get() > version.get()
            || matches!(state, TaskState::Cancelled) && !cancellation_requested
            || !expiry_timing_is_valid
        {
            return Err(TaskValueError::Invalid);
        }

        Ok(Self {
            task_id,
            owner,
            capability,
            identity,
            idempotency,
            budget,
            current_job_id,
            generation,
            version,
            state,
            cancellation_requested,
            created_at,
            updated_at,
            expires_at,
            poll_interval_ms,
        })
    }

    /// Returns the stable task identifier.
    #[must_use]
    pub const fn task_id(&self) -> TaskId {
        self.task_id
    }

    /// Returns the canonical owner boundary.
    #[must_use]
    pub const fn owner(&self) -> TaskOwner {
        self.owner
    }

    /// Returns the immutable capability revision.
    #[must_use]
    pub const fn capability(&self) -> &CapabilityKey {
        &self.capability
    }

    /// Returns cross-transport identity.
    #[must_use]
    pub const fn identity(&self) -> &TaskIdentity {
        &self.identity
    }

    /// Returns the create idempotency identity.
    #[must_use]
    pub const fn idempotency(&self) -> &TaskIdempotency {
        &self.idempotency
    }

    /// Returns retained budget identity.
    #[must_use]
    pub const fn budget(&self) -> &TaskBudget {
        &self.budget
    }

    /// Returns the currently fenced job identifier.
    #[must_use]
    pub const fn current_job_id(&self) -> JobId {
        self.current_job_id
    }

    /// Returns the current execution generation.
    #[must_use]
    pub const fn generation(&self) -> TaskGeneration {
        self.generation
    }

    /// Returns the optimistic-lock version.
    #[must_use]
    pub const fn version(&self) -> TaskVersion {
        self.version
    }

    /// Returns the status-specific state.
    #[must_use]
    pub const fn state(&self) -> &TaskState {
        &self.state
    }

    /// Returns whether durable cancellation has been requested.
    #[must_use]
    pub const fn cancellation_requested(&self) -> bool {
        self.cancellation_requested
    }

    /// Returns creation time.
    #[must_use]
    pub const fn created_at(&self) -> OffsetDateTime {
        self.created_at
    }

    /// Returns last mutation time.
    #[must_use]
    pub const fn updated_at(&self) -> OffsetDateTime {
        self.updated_at
    }

    /// Returns authoritative expiry time.
    #[must_use]
    pub const fn expires_at(&self) -> OffsetDateTime {
        self.expires_at
    }

    /// Returns finite TTL from creation in milliseconds.
    #[must_use]
    pub fn ttl_ms(&self) -> u64 {
        u64::try_from((self.expires_at - self.created_at).whole_milliseconds()).unwrap_or(u64::MAX)
    }

    /// Returns the bounded client polling hint.
    #[must_use]
    pub const fn poll_interval_ms(&self) -> u64 {
        self.poll_interval_ms
    }

    /// Applies one repository-authorized optimistic transition.
    ///
    /// # Errors
    ///
    /// Returns [`TaskTransitionError`] for stale versions, terminal mutation,
    /// illegal state/generation changes, non-monotonic time, or counter exhaustion.
    pub fn transitioned(
        &self,
        expected_version: TaskVersion,
        transition: TaskTransition,
        now: OffsetDateTime,
    ) -> Result<Self, TaskTransitionError> {
        if self.version != expected_version {
            return Err(TaskTransitionError::StaleVersion);
        }
        if self.state.is_terminal() {
            return Err(TaskTransitionError::Terminal);
        }
        if now <= self.updated_at {
            return Err(TaskTransitionError::NonMonotonicTime);
        }
        let next_version = self
            .version
            .get()
            .checked_add(1)
            .and_then(|value| TaskVersion::new(value).ok())
            .ok_or(TaskTransitionError::Exhausted)?;
        let mut next = self.clone();
        next.version = next_version;
        next.updated_at = now;
        match transition {
            TaskTransition::RequireInput(round) => {
                if !matches!(self.state, TaskState::Working) || now >= self.expires_at {
                    return Err(TaskTransitionError::Invalid);
                }
                next.state = TaskState::InputRequired { round };
            }
            TaskTransition::RecordInput(round) => {
                let TaskState::InputRequired {
                    round: current_round,
                } = &self.state
                else {
                    return Err(TaskTransitionError::Invalid);
                };
                if !current_round.is_response_successor(&round)
                    || round.pending().next().is_none()
                    || now >= self.expires_at
                {
                    return Err(TaskTransitionError::Invalid);
                }
                next.state = TaskState::InputRequired { round };
            }
            TaskTransition::Resume {
                answered_round,
                job_id,
                generation,
            } => {
                let Some(expected_generation) = self.generation.next() else {
                    return Err(TaskTransitionError::Exhausted);
                };
                let TaskState::InputRequired {
                    round: current_round,
                } = &self.state
                else {
                    return Err(TaskTransitionError::Invalid);
                };
                if !current_round.is_response_successor(&answered_round)
                    || answered_round.pending().next().is_some()
                    || generation != expected_generation
                    || now >= self.expires_at
                {
                    return Err(TaskTransitionError::Invalid);
                }
                next.current_job_id = job_id;
                next.generation = generation;
                next.state = TaskState::Working;
                next.cancellation_requested = false;
            }
            TaskTransition::RequestCancellation => {
                if self.cancellation_requested {
                    return Ok(self.clone());
                }
                if now >= self.expires_at {
                    return Err(TaskTransitionError::Invalid);
                }
                next.cancellation_requested = true;
            }
            TaskTransition::Complete(result) => {
                if now >= self.expires_at {
                    return Err(TaskTransitionError::Invalid);
                }
                next.state = TaskState::Completed { result };
            }
            TaskTransition::Fail(failure) => {
                if (failure == TaskFailureCode::Expired && now < self.expires_at)
                    || (failure != TaskFailureCode::Expired && now >= self.expires_at)
                {
                    return Err(TaskTransitionError::Invalid);
                }
                next.state = TaskState::Failed { failure };
            }
            TaskTransition::Cancel => {
                if now >= self.expires_at {
                    return Err(TaskTransitionError::Invalid);
                }
                next.cancellation_requested = true;
                next.state = TaskState::Cancelled;
            }
        }
        Ok(next)
    }
}
impl fmt::Debug for TaskSnapshot {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TaskSnapshot")
            .field("task_id", &self.task_id)
            .field("owner", &self.owner)
            .field("capability", &self.capability)
            .field("job_id", &self.current_job_id)
            .field("generation", &self.generation)
            .field("version", &self.version)
            .field("state", &self.state)
            .field("cancellation_requested", &self.cancellation_requested)
            .field("created_at", &self.created_at)
            .field("updated_at", &self.updated_at)
            .field("expires_at", &self.expires_at)
            .field("sensitive_content", &"[REDACTED]")
            .finish_non_exhaustive()
    }
}

/// Full authoritative row material required for durable execution.
///
/// Repository adapters must store the execution portion through the platform's
/// protected sensitive-payload policy. Its [`Debug`] implementation never emits
/// arguments, client responses, idempotency keys, tokens, or credentials.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StoredTask {
    snapshot: TaskSnapshot,
    execution: TaskExecution,
}

impl StoredTask {
    /// Joins public task state with its protected execution material.
    #[must_use]
    pub const fn new(snapshot: TaskSnapshot, execution: TaskExecution) -> Self {
        Self {
            snapshot,
            execution,
        }
    }

    /// Returns the client-visible authoritative snapshot.
    #[must_use]
    pub const fn snapshot(&self) -> &TaskSnapshot {
        &self.snapshot
    }

    /// Returns protected execution material.
    #[must_use]
    pub const fn execution(&self) -> &TaskExecution {
        &self.execution
    }

    /// Splits the persisted row.
    #[must_use]
    pub fn into_parts(self) -> (TaskSnapshot, TaskExecution) {
        (self.snapshot, self.execution)
    }
}

impl fmt::Debug for StoredTask {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("StoredTask")
            .field("snapshot", &self.snapshot)
            .field("execution", &"[REDACTED]")
            .finish()
    }
}

fn validate_restored_state(state: TaskState) -> Result<TaskState, TaskValueError> {
    let TaskState::InputRequired { round } = state else {
        return Ok(state);
    };

    let request_state = TaskRequestState::new(round.request_state().as_str().to_owned())?;
    let mut exchanges = BTreeMap::new();
    for (key, exchange) in round.exchanges() {
        let key = InputKey::new(key.as_str().to_owned())?;
        let mut restored = InputExchange::pending(exchange.request().clone())?;
        if let Some(response) = exchange.response() {
            validate_json_object(response, MAX_TASK_INPUT_BYTES)?;
            restored.response = Some(response.clone());
        }
        exchanges.insert(key, restored);
    }
    Ok(TaskState::InputRequired {
        round: InputRound::new(round.number(), request_state, exchanges)?,
    })
}

fn validate_graphic(value: &str, max: usize) -> Result<(), TaskValueError> {
    if value.is_empty() {
        return Err(TaskValueError::Empty);
    }
    if value.len() > max {
        return Err(TaskValueError::TooLong);
    }
    if !value.bytes().all(|byte| byte.is_ascii_graphic()) {
        return Err(TaskValueError::Invalid);
    }
    Ok(())
}

fn validate_json_object(value: &Value, max: usize) -> Result<(), TaskValueError> {
    if !value.is_object() {
        return Err(TaskValueError::Invalid);
    }
    validate_serialized(value, max)
}

fn validate_serialized<T: Serialize + ?Sized>(value: &T, max: usize) -> Result<(), TaskValueError> {
    let encoded = serde_json::to_vec(value).map_err(|_| TaskValueError::Invalid)?;
    if encoded.len() > max {
        Err(TaskValueError::TooLong)
    } else {
        Ok(())
    }
}

fn hash_segment(hasher: &mut Sha256, bytes: &[u8]) {
    hasher.update((bytes.len() as u64).to_be_bytes());
    hasher.update(bytes);
}

fn duration_millis(duration: Duration) -> u64 {
    u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
}

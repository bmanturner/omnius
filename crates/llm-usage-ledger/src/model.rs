use std::fmt;

use omnius_llm_core::Usage;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{
    ArithmeticError, BudgetScope, CostMicrounits, DimensionSet, IdempotencyKey, LedgerVersion,
    RequestFingerprint, ReservationId, UsageAmount, UsageBreakdown, UsageDelta, UsageVector,
    VersionOverflow,
};

/// A hard-budget aggregation dimension in deterministic evaluation order.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BudgetDimension {
    /// All work for the tenant.
    Tenant,
    /// Work for one tenant principal.
    Principal,
    /// Work authenticated by one tenant API key.
    ApiKey,
    /// Work sent to one provider.
    Provider,
    /// Work sent to one model.
    Model,
    /// Work selected through one route revision.
    Route,
    /// Work associated with one tool.
    Tool,
    /// Work associated with one generic operation.
    Operation,
    /// Work associated with one durable job.
    Job,
}

/// A quota metric in deterministic exhaustion order.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BudgetMetric {
    /// Dispatched requests.
    Requests,
    /// Simultaneously reserved streams.
    ConcurrentStreams,
    /// Aggregate tokens.
    Tokens,
    /// Provider-neutral non-token units.
    Units,
    /// Tool calls.
    ToolCalls,
    /// Media bytes.
    MediaBytes,
    /// Exact monetary microunits.
    CostMicrounits,
}

/// A typed value reported for an exhausted budget.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BudgetValue {
    /// A usage counter.
    Usage(UsageAmount),
    /// A monetary microunit amount.
    Cost(CostMicrounits),
}

/// Optional hard ceilings for every supported quota metric.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BudgetCeilings {
    requests: Option<UsageAmount>,
    concurrent_streams: Option<UsageAmount>,
    tokens: Option<UsageAmount>,
    units: Option<UsageAmount>,
    tool_calls: Option<UsageAmount>,
    media_bytes: Option<UsageAmount>,
    cost_microunits: Option<CostMicrounits>,
}

impl BudgetCeilings {
    /// Creates ceilings with no limited metrics.
    #[must_use]
    pub const fn none() -> Self {
        Self {
            requests: None,
            concurrent_streams: None,
            tokens: None,
            units: None,
            tool_calls: None,
            media_bytes: None,
            cost_microunits: None,
        }
    }

    /// Limits dispatched requests.
    #[must_use]
    pub const fn with_requests(mut self, value: UsageAmount) -> Self {
        self.requests = Some(value);
        self
    }

    /// Limits simultaneously reserved streams.
    #[must_use]
    pub const fn with_concurrent_streams(mut self, value: UsageAmount) -> Self {
        self.concurrent_streams = Some(value);
        self
    }

    /// Limits aggregate tokens.
    #[must_use]
    pub const fn with_tokens(mut self, value: UsageAmount) -> Self {
        self.tokens = Some(value);
        self
    }

    /// Limits provider-neutral non-token units.
    #[must_use]
    pub const fn with_units(mut self, value: UsageAmount) -> Self {
        self.units = Some(value);
        self
    }

    /// Limits tool calls.
    #[must_use]
    pub const fn with_tool_calls(mut self, value: UsageAmount) -> Self {
        self.tool_calls = Some(value);
        self
    }

    /// Limits media bytes.
    #[must_use]
    pub const fn with_media_bytes(mut self, value: UsageAmount) -> Self {
        self.media_bytes = Some(value);
        self
    }

    /// Limits exact monetary microunits.
    #[must_use]
    pub const fn with_cost(mut self, value: CostMicrounits) -> Self {
        self.cost_microunits = Some(value);
        self
    }

    /// Returns whether no metric has a ceiling.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.requests.is_none()
            && self.concurrent_streams.is_none()
            && self.tokens.is_none()
            && self.units.is_none()
            && self.tool_calls.is_none()
            && self.media_bytes.is_none()
            && self.cost_microunits.is_none()
    }

    /// Returns the first exceeded metric in canonical order.
    ///
    /// Addition overflow is exhaustion rather than saturation or an accounting downgrade.
    #[must_use]
    pub fn first_exhaustion(
        &self,
        dimension: BudgetDimension,
        current: &UsageVector,
        requested: &UsageVector,
    ) -> Option<BudgetExhaustion> {
        macro_rules! usage_limit {
            ($limit:expr, $metric:expr, $getter:ident) => {
                if let Some(maximum) = $limit {
                    let current_value = current.$getter();
                    let requested_value = requested.$getter();
                    if exceeds(current_value.get(), requested_value.get(), maximum.get()) {
                        return Some(BudgetExhaustion {
                            dimension,
                            metric: $metric,
                            current: BudgetValue::Usage(current_value),
                            requested: BudgetValue::Usage(requested_value),
                            maximum: BudgetValue::Usage(maximum),
                        });
                    }
                }
            };
        }

        usage_limit!(self.requests, BudgetMetric::Requests, requests);
        usage_limit!(
            self.concurrent_streams,
            BudgetMetric::ConcurrentStreams,
            concurrent_streams
        );
        usage_limit!(self.tokens, BudgetMetric::Tokens, tokens);
        usage_limit!(self.units, BudgetMetric::Units, units);
        usage_limit!(self.tool_calls, BudgetMetric::ToolCalls, tool_calls);
        usage_limit!(self.media_bytes, BudgetMetric::MediaBytes, media_bytes);
        if let Some(maximum) = self.cost_microunits {
            let current_value = current.cost();
            let requested_value = requested.cost();
            if exceeds(current_value.get(), requested_value.get(), maximum.get()) {
                return Some(BudgetExhaustion {
                    dimension,
                    metric: BudgetMetric::CostMicrounits,
                    current: BudgetValue::Cost(current_value),
                    requested: BudgetValue::Cost(requested_value),
                    maximum: BudgetValue::Cost(maximum),
                });
            }
        }
        None
    }
}

/// One dimension and its hard ceilings.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BudgetPolicy {
    dimension: BudgetDimension,
    ceilings: BudgetCeilings,
}

impl BudgetPolicy {
    /// Creates a dimension policy.
    #[must_use]
    pub const fn new(dimension: BudgetDimension, ceilings: BudgetCeilings) -> Self {
        Self {
            dimension,
            ceilings,
        }
    }

    /// Returns the aggregation dimension.
    #[must_use]
    pub const fn dimension(&self) -> BudgetDimension {
        self.dimension
    }

    /// Returns the hard ceilings.
    #[must_use]
    pub const fn ceilings(&self) -> &BudgetCeilings {
        &self.ceilings
    }
}

/// A deterministic hard-ceiling rejection with no sensitive scope values.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BudgetExhaustion {
    dimension: BudgetDimension,
    metric: BudgetMetric,
    current: BudgetValue,
    requested: BudgetValue,
    maximum: BudgetValue,
}

impl BudgetExhaustion {
    /// Returns the exhausted dimension class.
    #[must_use]
    pub const fn dimension(&self) -> BudgetDimension {
        self.dimension
    }

    /// Returns the first exhausted metric.
    #[must_use]
    pub const fn metric(&self) -> BudgetMetric {
        self.metric
    }

    /// Returns current accounted usage.
    #[must_use]
    pub const fn current(&self) -> BudgetValue {
        self.current
    }

    /// Returns requested usage.
    #[must_use]
    pub const fn requested(&self) -> BudgetValue {
        self.requested
    }

    /// Returns the hard maximum.
    #[must_use]
    pub const fn maximum(&self) -> BudgetValue {
        self.maximum
    }
}

/// Classified provider usage retained after dispatch.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum UsageEvidence {
    /// Complete provider actual usage.
    Actual(UsageBreakdown),
    /// Provider usage was absent; the estimate remains accounted.
    Missing,
    /// Provider usage was incomplete or ambiguous; observed values and the estimate are retained.
    Ambiguous(UsageBreakdown),
}

impl UsageEvidence {
    /// Classifies the canonical provider usage without treating absent counters as zero.
    ///
    /// Complete input/output counters plus provider actual cost produce [`Self::Actual`]. Any
    /// partial observation produces [`Self::Ambiguous`], and a wholly absent observation produces
    /// [`Self::Missing`].
    ///
    /// # Errors
    ///
    /// Returns [`ArithmeticError`] when canonical counters cannot be summed exactly.
    pub fn from_provider_usage(usage: &Usage) -> Result<Self, ArithmeticError> {
        let input = usage.input_tokens();
        let output = usage.output_tokens();
        let actual_cost = usage.actual_cost_microunits();
        let input_details = [
            usage.cached_input_tokens(),
            usage.cache_read_tokens(),
            usage.cache_write_tokens(),
            usage.audio_input_tokens(),
        ];
        let output_details = [usage.reasoning_tokens(), usage.audio_output_tokens()];
        let detailed_tokens_observed =
            input_details.iter().any(Option::is_some) || output_details.iter().any(Option::is_some);
        let input_tokens = input.map_or_else(|| max_known(input_details), UsageAmount::new);
        let output_tokens = output.map_or_else(|| max_known(output_details), UsageAmount::new);
        let tokens = input_tokens.checked_add(output_tokens)?;
        let unit_values = [
            usage.image_input_units(),
            usage.image_output_units(),
            usage.video_input_units(),
            usage.video_output_units(),
            usage.tool_execution_units(),
        ];
        let units_observed = unit_values.iter().any(Option::is_some);
        let units = sum_known(unit_values)?;
        let any_observed = input.is_some()
            || output.is_some()
            || actual_cost.is_some()
            || detailed_tokens_observed
            || units_observed;
        if !any_observed {
            return Ok(Self::Missing);
        }
        let observed = UsageBreakdown::primary(
            UsageVector::zero()
                .with_requests(UsageAmount::ONE)
                .with_tokens(tokens)
                .with_units(units)
                .with_cost(CostMicrounits::new(actual_cost.unwrap_or(0))),
        );
        if input.is_some() && output.is_some() && actual_cost.is_some() {
            Ok(Self::Actual(observed))
        } else {
            Ok(Self::Ambiguous(observed))
        }
    }

    /// Returns the safe evidence classification.
    #[must_use]
    pub const fn status(&self) -> UsageStatus {
        match self {
            Self::Actual(_) => UsageStatus::Actual,
            Self::Missing => UsageStatus::Missing,
            Self::Ambiguous(_) => UsageStatus::Ambiguous,
        }
    }
}

/// Safe provider-usage classification for ledger and audit events.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum UsageStatus {
    /// Pre-dispatch estimate only.
    Estimated,
    /// Complete provider actual usage.
    Actual,
    /// Provider usage absent.
    Missing,
    /// Provider usage incomplete or ambiguous.
    Ambiguous,
}

/// A validated request for an atomic pre-dispatch reservation.
#[derive(Clone, Eq, PartialEq, Serialize)]
pub struct ReservationRequest {
    id: ReservationId,
    idempotency_key: IdempotencyKey,
    fingerprint: RequestFingerprint,
    scope: BudgetScope,
    estimate: UsageBreakdown,
    policies: Vec<BudgetPolicy>,
}

impl ReservationRequest {
    /// Creates a canonical reservation request and sorts policies by dimension.
    ///
    /// # Errors
    ///
    /// Returns [`RequestError`] for zero estimates, empty ceiling sets, duplicate dimensions,
    /// missing scope dimensions, or an overflowing attributed estimate.
    pub fn new(
        id: ReservationId,
        idempotency_key: IdempotencyKey,
        fingerprint: RequestFingerprint,
        scope: BudgetScope,
        estimate: UsageBreakdown,
        mut policies: Vec<BudgetPolicy>,
    ) -> Result<Self, RequestError> {
        let total = estimate.checked_total().map_err(|_| RequestError)?;
        if total.is_zero() || total.requests().get() == 0 {
            return Err(RequestError);
        }
        policies.sort_unstable_by_key(BudgetPolicy::dimension);
        let mut prior = None;
        for policy in &policies {
            if policy.ceilings().is_empty()
                || !scope.contains_dimension(policy.dimension())
                || prior == Some(policy.dimension())
            {
                return Err(RequestError);
            }
            prior = Some(policy.dimension());
        }
        Ok(Self {
            id,
            idempotency_key,
            fingerprint,
            scope,
            estimate,
            policies,
        })
    }

    /// Borrows the requested reservation identifier.
    #[must_use]
    pub const fn id(&self) -> &ReservationId {
        &self.id
    }

    /// Borrows the tenant-scoped idempotency key.
    #[must_use]
    pub const fn idempotency_key(&self) -> &IdempotencyKey {
        &self.idempotency_key
    }

    /// Returns the request fingerprint.
    #[must_use]
    pub const fn fingerprint(&self) -> RequestFingerprint {
        self.fingerprint
    }

    /// Borrows the tenant-owned dimensions.
    #[must_use]
    pub const fn scope(&self) -> &BudgetScope {
        &self.scope
    }

    /// Returns the conservative pre-dispatch estimate.
    #[must_use]
    pub const fn estimate(&self) -> &UsageBreakdown {
        &self.estimate
    }

    /// Borrows canonical hard-budget policies.
    #[must_use]
    pub fn policies(&self) -> &[BudgetPolicy] {
        &self.policies
    }
}

impl fmt::Debug for ReservationRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ReservationRequest")
            .field("id", &self.id)
            .field("scope", &self.scope)
            .field("estimate", &self.estimate)
            .field("policy_count", &self.policies.len())
            .finish_non_exhaustive()
    }
}

/// A reservation request violated a closed accounting invariant.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[error("invalid usage reservation request")]
pub struct RequestError;

/// Persisted reservation lifecycle state.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReservationState {
    /// Estimate held before provider dispatch.
    Reserved,
    /// Dispatch finished but usage remains missing or ambiguous.
    Committed(UsageEvidence),
    /// Complete provider actual usage replaced the estimate.
    Reconciled(UsageBreakdown),
    /// Dispatch did not occur and the estimate was released.
    Released,
}

impl ReservationState {
    /// Returns a payload-free state class.
    #[must_use]
    pub const fn kind(&self) -> ReservationStateKind {
        match self {
            Self::Reserved => ReservationStateKind::Reserved,
            Self::Committed(_) => ReservationStateKind::Committed,
            Self::Reconciled(_) => ReservationStateKind::Reconciled,
            Self::Released => ReservationStateKind::Released,
        }
    }

    /// Returns the safe provider-usage status, when dispatch finished.
    #[must_use]
    pub const fn usage_status(&self) -> UsageStatus {
        match self {
            Self::Reserved | Self::Released => UsageStatus::Estimated,
            Self::Committed(evidence) => evidence.status(),
            Self::Reconciled(_) => UsageStatus::Actual,
        }
    }
}

/// Payload-free reservation state for audit events.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReservationStateKind {
    /// Held before dispatch.
    Reserved,
    /// Finished with missing or ambiguous provider usage.
    Committed,
    /// Replaced by provider actual usage.
    Reconciled,
    /// Released before dispatch.
    Released,
}

/// A versioned tenant-scoped reservation.
#[derive(Clone, Eq, PartialEq, Serialize)]
pub struct Reservation {
    id: ReservationId,
    idempotency_key: IdempotencyKey,
    fingerprint: RequestFingerprint,
    scope: BudgetScope,
    estimate: UsageBreakdown,
    policies: Vec<BudgetPolicy>,
    state: ReservationState,
    version: LedgerVersion,
}

impl Reservation {
    fn from_request(request: &ReservationRequest) -> Self {
        Self {
            id: request.id.clone(),
            idempotency_key: request.idempotency_key.clone(),
            fingerprint: request.fingerprint,
            scope: request.scope.clone(),
            estimate: request.estimate.clone(),
            policies: request.policies.clone(),
            state: ReservationState::Reserved,
            version: LedgerVersion::INITIAL,
        }
    }

    /// Creates a version-zero reservation and its matching redacted event.
    ///
    /// Repository adapters call this only inside the atomic reserve transaction after
    /// tenant-scoped idempotency and hard-ceiling checks.
    ///
    /// # Errors
    ///
    /// Returns [`ArithmeticError`] if exact event accounting cannot be represented.
    pub fn initial(request: &ReservationRequest) -> Result<(Self, LedgerEvent), ArithmeticError> {
        let reservation = Self::from_request(request);
        let empty = UsageBreakdown::default();
        let event = LedgerEvent::for_transition(LedgerEventKind::Reserved, &empty, &reservation)?;
        Ok((reservation, event))
    }

    /// Restores a validated persisted snapshot without bypassing request invariants.
    ///
    /// Adapters first rebuild [`ReservationRequest`] with its validating constructor, then pass
    /// the stored state and compare-and-set version here.
    ///
    /// # Errors
    ///
    /// Returns [`ReservationRestoreError`] for impossible state/version pairs, committed actual
    /// evidence, or an overflowing effective breakdown.
    pub fn restore(
        request: ReservationRequest,
        state: ReservationState,
        version: LedgerVersion,
    ) -> Result<Self, ReservationRestoreError> {
        let valid_state = match &state {
            ReservationState::Reserved => version == LedgerVersion::INITIAL,
            ReservationState::Committed(UsageEvidence::Actual(_)) => false,
            ReservationState::Committed(UsageEvidence::Missing | UsageEvidence::Ambiguous(_))
            | ReservationState::Released => version.get() == 1,
            ReservationState::Reconciled(_) => matches!(version.get(), 1 | 2),
        };
        if !valid_state {
            return Err(ReservationRestoreError);
        }
        let reservation = Self {
            id: request.id,
            idempotency_key: request.idempotency_key,
            fingerprint: request.fingerprint,
            scope: request.scope,
            estimate: request.estimate,
            policies: request.policies,
            state,
            version,
        };
        reservation
            .effective_usage()
            .checked_total()
            .map_err(|_| ReservationRestoreError)?;
        Ok(reservation)
    }

    /// Borrows the reservation identifier.
    #[must_use]
    pub const fn id(&self) -> &ReservationId {
        &self.id
    }

    /// Borrows the tenant-scoped idempotency key.
    #[must_use]
    pub const fn idempotency_key(&self) -> &IdempotencyKey {
        &self.idempotency_key
    }

    /// Returns the request fingerprint.
    #[must_use]
    pub const fn fingerprint(&self) -> RequestFingerprint {
        self.fingerprint
    }

    /// Borrows the tenant-owned budget scope.
    #[must_use]
    pub const fn scope(&self) -> &BudgetScope {
        &self.scope
    }

    /// Returns the pre-dispatch estimate.
    #[must_use]
    pub const fn estimate(&self) -> &UsageBreakdown {
        &self.estimate
    }

    /// Borrows the immutable hard-ceiling snapshot used at reservation time.
    #[must_use]
    pub fn policies(&self) -> &[BudgetPolicy] {
        &self.policies
    }

    /// Returns the lifecycle state.
    #[must_use]
    pub const fn state(&self) -> &ReservationState {
        &self.state
    }

    /// Returns the compare-and-set version.
    #[must_use]
    pub const fn version(&self) -> LedgerVersion {
        self.version
    }

    /// Computes conservatively accounted usage for quota aggregation.
    #[must_use]
    pub fn effective_usage(&self) -> UsageBreakdown {
        match &self.state {
            ReservationState::Reserved => self.estimate.clone(),
            ReservationState::Committed(UsageEvidence::Missing) => {
                self.estimate.without_concurrency()
            }
            ReservationState::Committed(UsageEvidence::Ambiguous(observed)) => self
                .estimate
                .conservative_max(observed)
                .without_concurrency(),
            ReservationState::Committed(UsageEvidence::Actual(actual))
            | ReservationState::Reconciled(actual) => actual.without_concurrency(),
            ReservationState::Released => UsageBreakdown::primary(UsageVector::zero()),
        }
    }

    /// Returns whether a tenant-scoped idempotent reserve exactly replays stored input.
    #[must_use]
    pub fn is_replay_of(&self, request: &ReservationRequest) -> bool {
        self.idempotency_key == request.idempotency_key
            && self.fingerprint == request.fingerprint
            && self.scope == request.scope
            && self.estimate == request.estimate
            && self.policies == request.policies
    }

    pub(crate) fn transition(&self, state: ReservationState) -> Result<Self, VersionOverflow> {
        let mut next = self.clone();
        next.state = state;
        next.version = self.version.checked_next()?;
        Ok(next)
    }
}

impl fmt::Debug for Reservation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Reservation")
            .field("id", &self.id)
            .field("scope", &self.scope)
            .field("estimate", &self.estimate)
            .field("policy_count", &self.policies.len())
            .field("state", &self.state.kind())
            .field("usage_status", &self.state.usage_status())
            .field("version", &self.version)
            .finish_non_exhaustive()
    }
}

/// A persisted reservation snapshot violated lifecycle or exact-accounting invariants.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[error("persisted LLM reservation snapshot is invalid")]
pub struct ReservationRestoreError;

/// A durable ledger mutation class.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LedgerEventKind {
    /// Pre-dispatch estimate reserved.
    Reserved,
    /// Dispatch result committed.
    Committed,
    /// Missing or ambiguous usage replaced by provider actual usage.
    Reconciled,
    /// Pre-dispatch estimate released.
    Released,
}

/// Redacted append-only ledger event safe for audit forwarding.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LedgerEvent {
    version: LedgerVersion,
    kind: LedgerEventKind,
    state: ReservationStateKind,
    usage_status: UsageStatus,
    dimensions: DimensionSet,
    effective_usage: UsageBreakdown,
    adjustment: UsageDelta,
}

impl LedgerEvent {
    pub(crate) fn for_transition(
        kind: LedgerEventKind,
        previous: &UsageBreakdown,
        reservation: &Reservation,
    ) -> Result<Self, ArithmeticError> {
        let effective_usage = reservation.effective_usage();
        Ok(Self {
            version: reservation.version,
            kind,
            state: reservation.state.kind(),
            usage_status: reservation.state.usage_status(),
            dimensions: reservation.scope.dimensions(),
            adjustment: UsageDelta::between(&effective_usage, previous)?,
            effective_usage,
        })
    }

    /// Returns the mutation version.
    #[must_use]
    pub const fn version(&self) -> LedgerVersion {
        self.version
    }

    /// Returns the event class.
    #[must_use]
    pub const fn kind(&self) -> LedgerEventKind {
        self.kind
    }

    /// Returns the resulting payload-free state.
    #[must_use]
    pub const fn state(&self) -> ReservationStateKind {
        self.state
    }

    /// Returns the provider-usage classification.
    #[must_use]
    pub const fn usage_status(&self) -> UsageStatus {
        self.usage_status
    }

    /// Returns only the scope dimension presence bitmap.
    #[must_use]
    pub const fn dimensions(&self) -> DimensionSet {
        self.dimensions
    }

    /// Returns conservatively accounted attributed usage after the mutation.
    #[must_use]
    pub const fn effective_usage(&self) -> &UsageBreakdown {
        &self.effective_usage
    }

    /// Returns the exact signed total adjustment.
    #[must_use]
    pub const fn adjustment(&self) -> &UsageDelta {
        &self.adjustment
    }

    /// Produces the smaller redacted audit projection.
    #[must_use]
    pub const fn audit_projection(&self) -> AuditLedgerEvent {
        AuditLedgerEvent {
            action: match self.kind {
                LedgerEventKind::Reserved => AuditAction::Reserve,
                LedgerEventKind::Committed => AuditAction::Commit,
                LedgerEventKind::Reconciled => AuditAction::Reconcile,
                LedgerEventKind::Released => AuditAction::Release,
            },
            outcome: AuditOutcome::Succeeded,
            state: self.state,
            usage_status: self.usage_status,
            dimensions: self.dimensions,
            version: self.version,
        }
    }
}

/// A minimal audit action without identifiers or provider data.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditAction {
    /// Reserve before provider dispatch.
    Reserve,
    /// Commit dispatch outcome.
    Commit,
    /// Reconcile provider actual usage.
    Reconcile,
    /// Release before dispatch.
    Release,
}

/// Closed audit outcome classification.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditOutcome {
    /// Mutation succeeded.
    Succeeded,
    /// Hard budget rejected dispatch.
    BudgetExhausted,
    /// Idempotency or state conflict rejected the mutation.
    Conflict,
}

/// Identifier-free audit projection suitable for existing audit sinks.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AuditLedgerEvent {
    action: AuditAction,
    outcome: AuditOutcome,
    state: ReservationStateKind,
    usage_status: UsageStatus,
    dimensions: DimensionSet,
    version: LedgerVersion,
}

impl AuditLedgerEvent {
    /// Returns the audit action.
    #[must_use]
    pub const fn action(self) -> AuditAction {
        self.action
    }

    /// Returns the closed audit outcome.
    #[must_use]
    pub const fn outcome(self) -> AuditOutcome {
        self.outcome
    }

    /// Returns the payload-free state.
    #[must_use]
    pub const fn state(self) -> ReservationStateKind {
        self.state
    }

    /// Returns the provider-usage status.
    #[must_use]
    pub const fn usage_status(self) -> UsageStatus {
        self.usage_status
    }

    /// Returns the identifier-free dimension bitmap.
    #[must_use]
    pub const fn dimensions(self) -> DimensionSet {
        self.dimensions
    }

    /// Returns the persisted mutation version.
    #[must_use]
    pub const fn version(self) -> LedgerVersion {
        self.version
    }
}

/// Outcome of an idempotent ledger operation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LedgerOperation {
    reservation: Reservation,
    event: LedgerEvent,
    replayed: bool,
}

impl LedgerOperation {
    pub(crate) fn new(reservation: Reservation, event: LedgerEvent, replayed: bool) -> Self {
        Self {
            reservation,
            event,
            replayed,
        }
    }

    /// Borrows the resulting reservation.
    #[must_use]
    pub const fn reservation(&self) -> &Reservation {
        &self.reservation
    }

    /// Borrows the durable ledger event for the resulting version.
    #[must_use]
    pub const fn event(&self) -> &LedgerEvent {
        &self.event
    }

    /// Returns whether an earlier exact operation was replayed.
    #[must_use]
    pub const fn replayed(&self) -> bool {
        self.replayed
    }
}

/// A tenant key is required for every repository lookup and mutation.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[error("reservation does not belong to the requested tenant boundary")]
pub struct TenantBoundaryError;

#[cfg(any(test, feature = "test-support"))]
pub(crate) fn ensure_tenant(
    tenant: &crate::TenantId,
    reservation: &Reservation,
) -> Result<(), TenantBoundaryError> {
    if tenant == reservation.scope().tenant() {
        Ok(())
    } else {
        Err(TenantBoundaryError)
    }
}

fn exceeds(current: u64, requested: u64, maximum: u64) -> bool {
    current
        .checked_add(requested)
        .is_none_or(|total| total > maximum)
}

fn max_known<const N: usize>(values: [Option<u64>; N]) -> UsageAmount {
    UsageAmount::new(values.into_iter().flatten().max().unwrap_or_default())
}

fn sum_known<const N: usize>(values: [Option<u64>; N]) -> Result<UsageAmount, ArithmeticError> {
    values
        .into_iter()
        .flatten()
        .try_fold(UsageAmount::ZERO, |sum, value| {
            sum.checked_add(UsageAmount::new(value))
        })
}

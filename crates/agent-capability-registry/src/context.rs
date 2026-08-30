use std::{fmt, time::Duration};

use omnius_auth_core::{Principal, TenantId};
use omnius_authz_basic::Decision;
use omnius_core::RequestId;
use schemars::JsonSchema;
use serde::{Deserialize, Deserializer, Serialize, de::Error as _};
use serde_json::Value;
use thiserror::Error;
use time::{OffsetDateTime, UtcOffset};
use tokio_util::sync::CancellationToken;

use crate::value::{DataPolicyRef, TraceContext};

/// Maximum input budget accepted by [`BudgetBounds`].
pub const MAX_INPUT_BUDGET_BYTES: u64 = 16 * 1_024 * 1_024;
/// Maximum output budget accepted by [`BudgetBounds`].
pub const MAX_OUTPUT_BUDGET_BYTES: u64 = 16 * 1_024 * 1_024;
/// Maximum abstract work-unit budget accepted by [`BudgetBounds`].
pub const MAX_WORK_UNITS: u64 = 1_000_000_000;

/// Immutable resource ceilings retained across every capability projection.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
#[expect(
    clippy::struct_field_names,
    reason = "the `max_*` names are the fixed serialized budget contract"
)]
pub struct BudgetBounds {
    max_input_bytes: u64,
    max_output_bytes: u64,
    max_work_units: u64,
}

impl BudgetBounds {
    /// Creates positive, fixed-ceiling invocation budgets.
    ///
    /// # Errors
    ///
    /// Returns [`BudgetError`] if a limit is zero or exceeds its crate-wide ceiling.
    pub const fn new(
        max_input_bytes: u64,
        max_output_bytes: u64,
        max_work_units: u64,
    ) -> Result<Self, BudgetError> {
        if max_input_bytes == 0 || max_output_bytes == 0 || max_work_units == 0 {
            return Err(BudgetError::Zero);
        }
        if max_input_bytes > MAX_INPUT_BUDGET_BYTES
            || max_output_bytes > MAX_OUTPUT_BUDGET_BYTES
            || max_work_units > MAX_WORK_UNITS
        {
            return Err(BudgetError::TooLarge);
        }
        Ok(Self {
            max_input_bytes,
            max_output_bytes,
            max_work_units,
        })
    }

    /// Returns the maximum serialized input bytes.
    #[must_use]
    pub const fn max_input_bytes(self) -> u64 {
        self.max_input_bytes
    }

    /// Returns the maximum serialized output bytes.
    #[must_use]
    pub const fn max_output_bytes(self) -> u64 {
        self.max_output_bytes
    }

    /// Returns the maximum handler-defined work units.
    #[must_use]
    pub const fn max_work_units(self) -> u64 {
        self.max_work_units
    }
}

impl<'de> Deserialize<'de> for BudgetBounds {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value =
            Value::deserialize(deserializer).map_err(|_| D::Error::custom(BudgetDecodeError))?;
        let Value::Object(object) = &value else {
            return Err(D::Error::custom(BudgetDecodeError));
        };
        if object.keys().any(|key| {
            !matches!(
                key.as_str(),
                "max_input_bytes" | "max_output_bytes" | "max_work_units"
            )
        }) {
            return Err(D::Error::custom(BudgetDecodeError));
        }
        let wire: BudgetBoundsWire =
            serde_json::from_value(value).map_err(|_| D::Error::custom(BudgetDecodeError))?;
        Self::new(
            wire.max_input_bytes,
            wire.max_output_bytes,
            wire.max_work_units,
        )
        .map_err(|_| D::Error::custom(BudgetDecodeError))
    }
}

#[derive(Deserialize)]
#[expect(
    clippy::struct_field_names,
    reason = "the wire fields must exactly match the fixed `max_*` contract"
)]
struct BudgetBoundsWire {
    max_input_bytes: u64,
    max_output_bytes: u64,
    max_work_units: u64,
}

/// An invocation budget was zero or exceeded a fixed ceiling.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum BudgetError {
    /// Every budget dimension must be positive.
    #[error("budget bounds must be positive")]
    Zero,
    /// A budget dimension exceeded its fixed ceiling.
    #[error("budget bounds exceed a fixed ceiling")]
    TooLarge,
}

#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[error("budget bounds are malformed")]
struct BudgetDecodeError;

/// Canonical security, policy, lifecycle, and resource context for one invocation.
///
/// All fields are owned so adapters can terminate their wire types before this boundary.
#[derive(Clone)]
pub struct InvocationContext {
    request_id: RequestId,
    trace_context: TraceContext,
    principal: Principal,
    tenant_id: Option<TenantId>,
    authorization: Decision,
    data_policy: DataPolicyRef,
    budget: BudgetBounds,
    deadline: OffsetDateTime,
    cancellation: CancellationToken,
}

impl InvocationContext {
    /// Creates a canonical invocation context.
    ///
    /// The deadline is normalized to UTC. A supplied tenant must equal the
    /// tenant established on the canonical principal.
    ///
    /// # Errors
    ///
    /// Returns [`ContextError::TenantMismatch`] for a cross-tenant context and
    /// [`ContextError::ExpiredDeadline`] unless the deadline is still in the future.
    #[expect(
        clippy::too_many_arguments,
        reason = "the canonical context deliberately retains every independent policy field"
    )]
    pub fn new(
        request_id: RequestId,
        trace_context: TraceContext,
        principal: Principal,
        tenant_id: Option<TenantId>,
        authorization: Decision,
        data_policy: DataPolicyRef,
        budget: BudgetBounds,
        deadline: OffsetDateTime,
        cancellation: CancellationToken,
    ) -> Result<Self, ContextError> {
        Self::new_at(
            request_id,
            trace_context,
            principal,
            tenant_id,
            authorization,
            data_policy,
            budget,
            deadline,
            cancellation,
            OffsetDateTime::now_utc(),
        )
    }

    #[expect(
        clippy::too_many_arguments,
        reason = "deterministic construction adds only an explicit clock instant"
    )]
    pub(crate) fn new_at(
        request_id: RequestId,
        trace_context: TraceContext,
        principal: Principal,
        tenant_id: Option<TenantId>,
        authorization: Decision,
        data_policy: DataPolicyRef,
        budget: BudgetBounds,
        deadline: OffsetDateTime,
        cancellation: CancellationToken,
        now: OffsetDateTime,
    ) -> Result<Self, ContextError> {
        if let Some(tenant_id) = tenant_id
            && principal.tenant_id != Some(tenant_id)
        {
            return Err(ContextError::TenantMismatch);
        }
        if deadline <= now {
            return Err(ContextError::ExpiredDeadline);
        }
        Ok(Self {
            request_id,
            trace_context,
            principal,
            tenant_id,
            authorization,
            data_policy,
            budget,
            deadline: deadline.to_offset(UtcOffset::UTC),
            cancellation,
        })
    }

    /// Returns the shared request correlation identifier.
    #[must_use]
    pub const fn request_id(&self) -> RequestId {
        self.request_id
    }

    /// Returns the validated W3C trace context.
    #[must_use]
    pub const fn trace_context(&self) -> &TraceContext {
        &self.trace_context
    }

    /// Returns the canonical authenticated principal.
    #[must_use]
    pub const fn principal(&self) -> &Principal {
        &self.principal
    }

    /// Returns the canonical tenant scope, when present.
    #[must_use]
    pub const fn tenant_id(&self) -> Option<TenantId> {
        self.tenant_id
    }

    /// Returns the authorization decision supplied by the service boundary.
    #[must_use]
    pub const fn authorization(&self) -> Decision {
        self.authorization
    }

    /// Returns the authoritative data-policy reference.
    #[must_use]
    pub const fn data_policy(&self) -> &DataPolicyRef {
        &self.data_policy
    }

    /// Returns immutable invocation budget ceilings.
    #[must_use]
    pub const fn budget(&self) -> BudgetBounds {
        self.budget
    }

    /// Returns the absolute UTC deadline.
    #[must_use]
    pub const fn deadline(&self) -> OffsetDateTime {
        self.deadline
    }

    /// Returns the shared cooperative cancellation token.
    #[must_use]
    pub const fn cancellation_token(&self) -> &CancellationToken {
        &self.cancellation
    }

    /// Returns the duration remaining before the absolute deadline.
    ///
    /// Expired contexts return [`Duration::ZERO`].
    #[must_use]
    pub fn remaining_duration(&self) -> Duration {
        remaining_duration_at(self.deadline, OffsetDateTime::now_utc())
    }
}

impl fmt::Debug for InvocationContext {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("InvocationContext([redacted])")
    }
}

/// A canonical invocation context was inconsistent or already expired.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum ContextError {
    /// The explicit tenant did not agree with the authenticated principal.
    #[error("invocation tenant does not agree with the canonical principal")]
    TenantMismatch,
    /// The absolute deadline was not in the future.
    #[error("invocation deadline has expired")]
    ExpiredDeadline,
}

fn remaining_duration_at(deadline: OffsetDateTime, now: OffsetDateTime) -> Duration {
    let remaining = deadline - now;
    if remaining.is_positive() {
        remaining.unsigned_abs()
    } else {
        Duration::ZERO
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use omnius_auth_core::{AssuranceLevel, AuthMethod, PrincipalKind, SubjectId};

    fn principal(
        tenant_id: Option<TenantId>,
    ) -> Result<Principal, omnius_auth_core::PrincipalError> {
        Principal::new(
            SubjectId::new(),
            PrincipalKind::User,
            tenant_id,
            AuthMethod::Session,
            OffsetDateTime::UNIX_EPOCH,
            AssuranceLevel::Aal1,
            Vec::new(),
        )
    }

    #[test]
    fn remaining_duration_saturates_at_zero() -> Result<(), Box<dyn std::error::Error>> {
        let tenant_id = TenantId::new();
        let now = OffsetDateTime::UNIX_EPOCH + time::Duration::hours(1);
        let context = InvocationContext::new_at(
            RequestId::new(),
            TraceContext::new(
                "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01".parse()?,
                None,
            ),
            principal(Some(tenant_id))?,
            Some(tenant_id),
            Decision::Allow,
            "policy.default".parse()?,
            BudgetBounds::new(1, 1, 1)?,
            now + time::Duration::seconds(1),
            CancellationToken::new(),
            now,
        )?;

        assert_eq!(
            remaining_duration_at(context.deadline(), now + time::Duration::seconds(2)),
            Duration::ZERO
        );
        Ok(())
    }

    #[test]
    fn remaining_duration_preserves_far_future_deadlines() {
        let now = OffsetDateTime::UNIX_EPOCH;
        let far_future = now + time::Duration::days(365_000);

        assert_eq!(
            remaining_duration_at(far_future, now),
            (far_future - now).unsigned_abs()
        );
    }
}

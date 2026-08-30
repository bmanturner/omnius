use std::time::Duration;

use omnius_llm_core::LlmRequest;
use thiserror::Error;

/// Required loser-cancellation behavior for an admitted hedge.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LoserCancellationPolicy {
    /// Abort the provider request when another attempt wins.
    AbortProviderRequest,
    /// Use a provider cancellation operation verified by the adapter.
    ProviderCancellation,
}

/// Explicit accounting behavior for duplicated hedge attempts.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HedgeBillingPolicy {
    /// The provider contract bills only the winning request.
    WinnerOnly,
    /// Duplicate charges are explicitly accepted within the route budget.
    DuplicateChargeWithinBudget,
}

/// Hedge configuration. The default is disabled.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HedgePolicy {
    enabled: bool,
    delay: Duration,
    loser_cancellation: Option<LoserCancellationPolicy>,
    billing: Option<HedgeBillingPolicy>,
}

impl HedgePolicy {
    /// Returns a disabled hedge policy.
    #[must_use]
    pub const fn disabled() -> Self {
        Self {
            enabled: false,
            delay: Duration::ZERO,
            loser_cancellation: None,
            billing: None,
        }
    }

    /// Creates an enabled policy for later request-specific admission.
    ///
    /// Optional policies are retained so admission can reject incomplete configuration without
    /// silently supplying cancellation or billing semantics.
    ///
    /// # Errors
    ///
    /// Returns [`HedgePolicyError::InvalidDelay`] when the hedge delay is zero.
    pub const fn enabled(
        delay: Duration,
        loser_cancellation: Option<LoserCancellationPolicy>,
        billing: Option<HedgeBillingPolicy>,
    ) -> Result<Self, HedgePolicyError> {
        if delay.is_zero() {
            return Err(HedgePolicyError::InvalidDelay);
        }
        Ok(Self {
            enabled: true,
            delay,
            loser_cancellation,
            billing,
        })
    }

    /// Reports whether the route explicitly enables hedging.
    #[must_use]
    pub const fn is_enabled(self) -> bool {
        self.enabled
    }
}

impl Default for HedgePolicy {
    fn default() -> Self {
        Self::disabled()
    }
}

/// Successful request-specific hedge admission.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HedgeAdmission {
    delay: Duration,
    loser_cancellation: LoserCancellationPolicy,
    billing: HedgeBillingPolicy,
}

impl HedgeAdmission {
    /// Returns the delay before starting a duplicate attempt.
    #[must_use]
    pub const fn delay(self) -> Duration {
        self.delay
    }

    /// Returns the mandatory loser-cancellation policy.
    #[must_use]
    pub const fn loser_cancellation(self) -> LoserCancellationPolicy {
        self.loser_cancellation
    }

    /// Returns the mandatory duplicate-attempt billing policy.
    #[must_use]
    pub const fn billing(self) -> HedgeBillingPolicy {
        self.billing
    }
}

/// Stable reason hedge admission was denied.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HedgeRejectionReason {
    /// Hedging remains at its default-off setting.
    Disabled,
    /// The request contains tool semantics that could duplicate side effects.
    ToolRequest,
    /// The caller did not prove the complete request idempotent.
    NonIdempotent,
    /// Enabled configuration omitted loser cancellation.
    MissingLoserCancellation,
    /// Enabled configuration omitted duplicate-attempt billing policy.
    MissingBillingPolicy,
}

/// Applies the default-off and side-effect safety guard to one canonical request.
///
/// # Errors
///
/// Returns a stable [`HedgeRejectionReason`] when any admissibility rule fails.
pub fn admit_hedge(
    policy: HedgePolicy,
    request: &LlmRequest,
    idempotent: bool,
) -> Result<HedgeAdmission, HedgeRejectionReason> {
    if !policy.enabled {
        return Err(HedgeRejectionReason::Disabled);
    }
    if request.tools().is_some_and(|tools| !tools.is_empty()) || request.tool_policy().is_some() {
        return Err(HedgeRejectionReason::ToolRequest);
    }
    if !idempotent {
        return Err(HedgeRejectionReason::NonIdempotent);
    }
    let loser_cancellation = policy
        .loser_cancellation
        .ok_or(HedgeRejectionReason::MissingLoserCancellation)?;
    let billing = policy
        .billing
        .ok_or(HedgeRejectionReason::MissingBillingPolicy)?;
    Ok(HedgeAdmission {
        delay: policy.delay,
        loser_cancellation,
        billing,
    })
}

/// Value-free hedge configuration failure.
#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum HedgePolicyError {
    /// An enabled hedge has no positive start delay.
    #[error("hedge delay is invalid")]
    InvalidDelay,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::{request_with_tools, text_request};

    #[test]
    fn default_policy_should_reject_hedging() {
        let request = text_request("route-a", 1);

        assert_eq!(
            admit_hedge(HedgePolicy::default(), &request, true),
            Err(HedgeRejectionReason::Disabled)
        );
    }

    #[test]
    fn tool_request_should_be_rejected_even_with_complete_policy() {
        let policy = HedgePolicy::enabled(
            Duration::from_millis(25),
            Some(LoserCancellationPolicy::AbortProviderRequest),
            Some(HedgeBillingPolicy::DuplicateChargeWithinBudget),
        )
        .expect("test hedge policy should be valid");
        let request = request_with_tools("route-a", 1);

        assert_eq!(
            admit_hedge(policy, &request, true),
            Err(HedgeRejectionReason::ToolRequest)
        );
    }

    #[test]
    fn incomplete_policy_should_be_rejected() {
        let policy = HedgePolicy::enabled(Duration::from_millis(25), None, None)
            .expect("test hedge policy should be valid");
        let request = text_request("route-a", 1);

        assert_eq!(
            admit_hedge(policy, &request, true),
            Err(HedgeRejectionReason::MissingLoserCancellation)
        );
    }
}

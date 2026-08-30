use std::time::Duration;

use omnius_llm_core::{LlmRequest, ProviderError, RetryClass};
use thiserror::Error;

/// Separate bounded deadlines for every LLM execution phase.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DeadlinePolicy {
    connect: Duration,
    first_byte: Duration,
    idle_stream: Duration,
    total: Duration,
    tool_turn: Duration,
}

impl DeadlinePolicy {
    /// Creates execution phase deadlines.
    ///
    /// # Errors
    ///
    /// Returns [`RetryPolicyError::InvalidDeadline`] when a deadline is zero or a phase exceeds
    /// the total deadline.
    pub fn new(
        connect: Duration,
        first_byte: Duration,
        idle_stream: Duration,
        total: Duration,
        tool_turn: Duration,
    ) -> Result<Self, RetryPolicyError> {
        if connect.is_zero()
            || first_byte.is_zero()
            || idle_stream.is_zero()
            || total.is_zero()
            || tool_turn.is_zero()
            || connect > total
            || first_byte > total
            || idle_stream > total
            || tool_turn > total
        {
            return Err(RetryPolicyError::InvalidDeadline);
        }
        Ok(Self {
            connect,
            first_byte,
            idle_stream,
            total,
            tool_turn,
        })
    }

    /// Returns the provider connection deadline.
    #[must_use]
    pub const fn connect(self) -> Duration {
        self.connect
    }

    /// Returns the time-to-first-byte deadline.
    #[must_use]
    pub const fn first_byte(self) -> Duration {
        self.first_byte
    }

    /// Returns the maximum idle interval between stream events.
    #[must_use]
    pub const fn idle_stream(self) -> Duration {
        self.idle_stream
    }

    /// Returns the complete request deadline.
    #[must_use]
    pub const fn total(self) -> Duration {
        self.total
    }

    /// Returns the deadline for one tool turn.
    #[must_use]
    pub const fn tool_turn(self) -> Duration {
        self.tool_turn
    }
}

impl Default for DeadlinePolicy {
    fn default() -> Self {
        Self {
            connect: Duration::from_secs(2),
            first_byte: Duration::from_secs(10),
            idle_stream: Duration::from_secs(30),
            total: Duration::from_secs(60),
            tool_turn: Duration::from_secs(30),
        }
    }
}

/// Immutable retry budget and jittered exponential backoff policy.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RetryPolicy {
    max_attempts: u32,
    base_backoff: Duration,
    max_backoff: Duration,
    jitter_basis_points: u16,
    deadlines: DeadlinePolicy,
}

impl RetryPolicy {
    /// Creates a retry policy. `max_attempts` includes the initial call.
    ///
    /// # Errors
    ///
    /// Returns [`RetryPolicyError::InvalidRetryPolicy`] for zero attempts/backoff, a maximum below
    /// the base backoff, or jitter above 10,000 basis points.
    pub fn new(
        max_attempts: u32,
        base_backoff: Duration,
        max_backoff: Duration,
        jitter_basis_points: u16,
        deadlines: DeadlinePolicy,
    ) -> Result<Self, RetryPolicyError> {
        if max_attempts == 0
            || base_backoff.is_zero()
            || max_backoff < base_backoff
            || jitter_basis_points > 10_000
        {
            return Err(RetryPolicyError::InvalidRetryPolicy);
        }
        Ok(Self {
            max_attempts,
            base_backoff,
            max_backoff,
            jitter_basis_points,
            deadlines,
        })
    }

    /// Returns the total attempt budget, including the initial attempt.
    #[must_use]
    pub const fn max_attempts(self) -> u32 {
        self.max_attempts
    }

    /// Returns all execution phase deadlines.
    #[must_use]
    pub const fn deadlines(self) -> DeadlinePolicy {
        self.deadlines
    }
}

impl Default for RetryPolicy {
    fn default() -> Self {
        Self {
            max_attempts: 3,
            base_backoff: Duration::from_millis(100),
            max_backoff: Duration::from_secs(2),
            jitter_basis_points: 5_000,
            deadlines: DeadlinePolicy::default(),
        }
    }
}

/// A deterministic bounded jitter sample supplied by the execution runtime.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct JitterSample(u16);

impl JitterSample {
    /// Creates a sample in the inclusive range 0..=10,000.
    ///
    /// # Errors
    ///
    /// Returns [`RetryPolicyError::InvalidJitterSample`] for a larger value.
    pub const fn new(basis_points: u16) -> Result<Self, RetryPolicyError> {
        if basis_points > 10_000 {
            return Err(RetryPolicyError::InvalidJitterSample);
        }
        Ok(Self(basis_points))
    }
}

/// Runtime facts needed for one retry decision.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RetryContext {
    attempts_started: u32,
    elapsed: Duration,
    full_deadline: Duration,
    idempotent: bool,
    visible_stream_output: bool,
    jitter: JitterSample,
}

impl RetryContext {
    /// Creates explicit retry-decision context.
    #[must_use]
    pub const fn new(
        attempts_started: u32,
        elapsed: Duration,
        full_deadline: Duration,
        idempotent: bool,
        visible_stream_output: bool,
        jitter: JitterSample,
    ) -> Self {
        Self {
            attempts_started,
            elapsed,
            full_deadline,
            idempotent,
            visible_stream_output,
            jitter,
        }
    }

    /// Creates context bounded by both route policy and the canonical request deadline.
    #[must_use]
    pub fn for_request(
        policy: RetryPolicy,
        request: &LlmRequest,
        attempts_started: u32,
        elapsed: Duration,
        idempotent: bool,
        visible_stream_output: bool,
        jitter: JitterSample,
    ) -> Self {
        let request_deadline = Duration::from_millis(request.limits().deadline_ms());
        Self::new(
            attempts_started,
            elapsed,
            policy.deadlines.total.min(request_deadline),
            idempotent,
            visible_stream_output,
            jitter,
        )
    }
}

/// Typed reason automatic retry stopped.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RetryStopReason {
    /// The provider explicitly classified the operation as non-retryable.
    ProviderClassNever,
    /// A retry-after-classified failure omitted its required delay.
    MissingRetryAfter,
    /// The operation is not declared idempotent.
    NonIdempotent,
    /// Output has already crossed the stream consumer boundary.
    VisibleStreamOutput,
    /// The route attempt budget is exhausted.
    AttemptBudgetExhausted,
    /// Backoff and a minimum next-attempt window do not fit the full deadline.
    DeadlineExhausted,
}

/// Result of applying retry class, attempt budget, backoff, and the full deadline.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RetryDecision {
    /// Retry after the exact policy delay.
    RetryAfter {
        /// Jittered backoff with any provider retry-after floor applied.
        delay: Duration,
    },
    /// Do not retry automatically.
    Stop(RetryStopReason),
}

/// Applies typed provider retry metadata without inspecting provider bodies.
#[must_use]
pub fn decide_retry(
    policy: RetryPolicy,
    error: &ProviderError,
    context: RetryContext,
) -> RetryDecision {
    if context.visible_stream_output {
        return RetryDecision::Stop(RetryStopReason::VisibleStreamOutput);
    }
    if !context.idempotent {
        return RetryDecision::Stop(RetryStopReason::NonIdempotent);
    }
    if context.attempts_started >= policy.max_attempts {
        return RetryDecision::Stop(RetryStopReason::AttemptBudgetExhausted);
    }
    match error.retry_class() {
        RetryClass::Never => return RetryDecision::Stop(RetryStopReason::ProviderClassNever),
        RetryClass::AfterRetryAfter if error.retry_after().is_none() => {
            return RetryDecision::Stop(RetryStopReason::MissingRetryAfter);
        }
        RetryClass::Safe | RetryClass::AfterRetryAfter => {}
    }

    let exponential = exponential_backoff(policy, context.attempts_started, context.jitter);
    let delay = error
        .retry_after()
        .map_or(exponential, |retry_after| exponential.max(retry_after));
    let full_deadline = context.full_deadline.min(policy.deadlines.total);
    let remaining = full_deadline.saturating_sub(context.elapsed);
    let minimum_attempt_window = policy.deadlines.connect.min(policy.deadlines.first_byte);
    if delay.saturating_add(minimum_attempt_window) > remaining {
        return RetryDecision::Stop(RetryStopReason::DeadlineExhausted);
    }
    RetryDecision::RetryAfter { delay }
}

fn exponential_backoff(
    policy: RetryPolicy,
    attempts_started: u32,
    jitter: JitterSample,
) -> Duration {
    let exponent = attempts_started.saturating_sub(1).min(31);
    let multiplier = 1_u32 << exponent;
    let capped = policy
        .base_backoff
        .saturating_mul(multiplier)
        .min(policy.max_backoff);
    let spread = scale_duration(capped, policy.jitter_basis_points);
    let floor = capped.saturating_sub(spread);
    floor.saturating_add(scale_duration(spread, jitter.0))
}

fn scale_duration(duration: Duration, basis_points: u16) -> Duration {
    const NANOS_PER_SECOND: u128 = 1_000_000_000;
    let nanos = duration.as_nanos().saturating_mul(u128::from(basis_points)) / 10_000;
    let seconds = nanos / NANOS_PER_SECOND;
    let Ok(seconds) = u64::try_from(seconds) else {
        return Duration::MAX;
    };
    let Ok(subsecond_nanos) = u32::try_from(nanos % NANOS_PER_SECOND) else {
        return Duration::MAX;
    };
    Duration::new(seconds, subsecond_nanos)
}

/// Value-free retry policy validation failure.
#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum RetryPolicyError {
    /// A deadline is zero or exceeds the total deadline.
    #[error("routing deadline policy is invalid")]
    InvalidDeadline,
    /// An attempt/backoff/jitter policy is invalid.
    #[error("routing retry policy is invalid")]
    InvalidRetryPolicy,
    /// A runtime jitter sample exceeds 10,000 basis points.
    #[error("routing jitter sample is invalid")]
    InvalidJitterSample,
}

#[cfg(test)]
mod tests {
    use omnius_llm_core::{ProviderErrorKind, RetryClass};

    use super::*;

    fn policy() -> RetryPolicy {
        let deadlines = DeadlinePolicy::new(
            Duration::from_millis(100),
            Duration::from_millis(200),
            Duration::from_secs(1),
            Duration::from_secs(10),
            Duration::from_secs(2),
        )
        .expect("test deadlines should be valid");
        RetryPolicy::new(
            3,
            Duration::from_millis(100),
            Duration::from_secs(1),
            0,
            deadlines,
        )
        .expect("test retry policy should be valid")
    }

    fn context(deadline: Duration) -> RetryContext {
        RetryContext::new(
            1,
            Duration::ZERO,
            deadline,
            true,
            false,
            JitterSample::new(5_000).expect("test jitter should be valid"),
        )
    }

    #[test]
    fn retry_after_should_be_a_hard_delay_floor() {
        let error = ProviderError::new(
            "provider-a".to_owned(),
            ProviderErrorKind::Throttling,
            RetryClass::AfterRetryAfter,
        )
        .with_transport_metadata(
            Some(429),
            Some(Duration::from_secs(3)),
            None,
            omnius_llm_core::RetainedRaw::discarded(),
        );

        assert_eq!(
            decide_retry(policy(), &error, context(Duration::from_secs(10))),
            RetryDecision::RetryAfter {
                delay: Duration::from_secs(3)
            }
        );
    }

    #[test]
    fn retry_after_class_should_stop_when_provider_omits_delay() {
        let error = ProviderError::new(
            "provider-a".to_owned(),
            ProviderErrorKind::Throttling,
            RetryClass::AfterRetryAfter,
        );

        assert_eq!(
            decide_retry(policy(), &error, context(Duration::from_secs(10))),
            RetryDecision::Stop(RetryStopReason::MissingRetryAfter)
        );
    }

    #[test]
    fn non_retryable_class_should_stop() {
        let error = ProviderError::new(
            "provider-a".to_owned(),
            ProviderErrorKind::Provider,
            RetryClass::Never,
        );

        assert_eq!(
            decide_retry(policy(), &error, context(Duration::from_secs(10))),
            RetryDecision::Stop(RetryStopReason::ProviderClassNever)
        );
    }

    #[test]
    fn retry_should_stop_when_full_deadline_cannot_fit_delay_and_attempt() {
        let error = ProviderError::new(
            "provider-a".to_owned(),
            ProviderErrorKind::Transport,
            RetryClass::Safe,
        );

        assert_eq!(
            decide_retry(policy(), &error, context(Duration::from_millis(150))),
            RetryDecision::Stop(RetryStopReason::DeadlineExhausted)
        );
    }
    #[test]
    fn explicit_context_is_still_clamped_to_route_total_deadline() {
        let error = ProviderError::new(
            "provider-a".to_owned(),
            ProviderErrorKind::Transport,
            RetryClass::Safe,
        );
        let context = RetryContext::new(
            1,
            Duration::from_millis(9_950),
            Duration::from_secs(60),
            true,
            false,
            JitterSample::new(5_000).expect("test jitter should be valid"),
        );

        assert_eq!(
            decide_retry(policy(), &error, context),
            RetryDecision::Stop(RetryStopReason::DeadlineExhausted)
        );
    }

    #[test]
    fn visible_stream_output_should_disable_transparent_retry() {
        let error = ProviderError::new(
            "provider-a".to_owned(),
            ProviderErrorKind::Transport,
            RetryClass::Safe,
        );
        let retry_context = RetryContext::new(
            1,
            Duration::ZERO,
            Duration::from_secs(10),
            true,
            true,
            JitterSample::new(5_000).expect("test jitter should be valid"),
        );

        assert_eq!(
            decide_retry(policy(), &error, retry_context),
            RetryDecision::Stop(RetryStopReason::VisibleStreamOutput)
        );
    }
    #[test]
    fn default_backoff_should_apply_bounded_deterministic_jitter() {
        let low = exponential_backoff(
            RetryPolicy::default(),
            1,
            JitterSample::new(0).expect("test jitter should be valid"),
        );
        let high = exponential_backoff(
            RetryPolicy::default(),
            1,
            JitterSample::new(10_000).expect("test jitter should be valid"),
        );

        assert_eq!(low, Duration::from_millis(50));
        assert_eq!(high, Duration::from_millis(100));
    }
}

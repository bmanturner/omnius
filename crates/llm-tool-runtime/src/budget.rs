use std::sync::{
    Mutex,
    atomic::{AtomicUsize, Ordering},
};

use thiserror::Error;
use time::{Duration, OffsetDateTime};

/// Every independently enforced agent-loop budget dimension.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LoopBudgetDimension {
    /// Model turn count.
    ModelTurns,
    /// Tool call count.
    ToolCalls,
    /// Absolute wall-clock duration.
    WallClock,
    /// Total input and output tokens.
    Tokens,
    /// Total cost in integer microunits.
    Cost,
    /// Simultaneous model or tool work.
    Concurrency,
}

/// Immutable ceilings for one request-local agent loop.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LoopBudgetLimits {
    /// Maximum model turns.
    pub max_model_turns: u32,
    /// Maximum complete tool calls.
    pub max_tool_calls: u32,
    /// Maximum elapsed wall-clock duration.
    pub max_wall_clock: Duration,
    /// Maximum total tokens.
    pub max_tokens: u64,
    /// Maximum cost in integer microunits.
    pub max_cost_microunits: u64,
    /// Maximum simultaneous model or tool work.
    pub max_concurrency: usize,
}

impl LoopBudgetLimits {
    /// Creates loop limits. Zero is retained as an already-exhausted budget.
    ///
    /// # Errors
    ///
    /// Returns [`LoopBudgetBuildError::NegativeWallClock`] for a negative duration.
    pub const fn new(
        max_model_turns: u32,
        max_tool_calls: u32,
        max_wall_clock: Duration,
        max_tokens: u64,
        max_cost_microunits: u64,
        max_concurrency: usize,
    ) -> Result<Self, LoopBudgetBuildError> {
        if max_wall_clock.is_negative() {
            return Err(LoopBudgetBuildError::NegativeWallClock);
        }
        Ok(Self {
            max_model_turns,
            max_tool_calls,
            max_wall_clock,
            max_tokens,
            max_cost_microunits,
            max_concurrency,
        })
    }
}

/// Request-local, thread-safe deterministic agent-loop accounting.
pub struct AgentLoopBudget {
    limits: LoopBudgetLimits,
    started_at: OffsetDateTime,
    deadline: OffsetDateTime,
    state: Mutex<LoopBudgetState>,
    active: AtomicUsize,
}

impl AgentLoopBudget {
    /// Creates empty accounting at an explicit clock instant.
    ///
    /// An explicit start makes budget boundary tests deterministic. Production
    /// callers normally pass `OffsetDateTime::now_utc()`.
    ///
    /// # Errors
    ///
    /// Returns [`LoopBudgetBuildError::DeadlineOverflow`] if the wall-clock
    /// ceiling cannot be represented.
    pub fn new(
        limits: LoopBudgetLimits,
        started_at: OffsetDateTime,
    ) -> Result<Self, LoopBudgetBuildError> {
        let deadline = started_at
            .checked_add(limits.max_wall_clock)
            .ok_or(LoopBudgetBuildError::DeadlineOverflow)?;
        Ok(Self {
            limits,
            started_at,
            deadline,
            state: Mutex::new(LoopBudgetState::default()),
            active: AtomicUsize::new(0),
        })
    }

    /// Returns the immutable ceilings.
    #[must_use]
    pub const fn limits(&self) -> LoopBudgetLimits {
        self.limits
    }

    /// Returns the absolute wall-clock deadline.
    #[must_use]
    pub const fn deadline(&self) -> OffsetDateTime {
        self.deadline
    }

    /// Checks whether a new loop step may begin at an explicit instant.
    ///
    /// # Errors
    ///
    /// Returns wall-clock exhaustion first, followed deterministically by model
    /// turns, tool calls, tokens, cost, and concurrency.
    pub fn check_at(&self, now: OffsetDateTime) -> Result<(), LoopBudgetError> {
        if now >= self.deadline {
            return Err(LoopBudgetError::Exhausted(LoopBudgetDimension::WallClock));
        }
        let state = self
            .state
            .lock()
            .map_err(|_| LoopBudgetError::InternalState)?;
        if state.model_turns >= self.limits.max_model_turns {
            return Err(LoopBudgetError::Exhausted(LoopBudgetDimension::ModelTurns));
        }
        if state.tool_calls >= self.limits.max_tool_calls {
            return Err(LoopBudgetError::Exhausted(LoopBudgetDimension::ToolCalls));
        }
        check_usage_capacity(&state, self.limits)?;
        if self.limits.max_concurrency == 0 {
            return Err(LoopBudgetError::Exhausted(LoopBudgetDimension::Concurrency));
        }
        Ok(())
    }

    /// Atomically reserves one model turn at an explicit instant.
    ///
    /// # Errors
    ///
    /// Returns the exhausted dimension without changing counters.
    pub fn reserve_model_turn_at(&self, now: OffsetDateTime) -> Result<(), LoopBudgetError> {
        self.check_wall_and_static(now)?;
        let mut state = self
            .state
            .lock()
            .map_err(|_| LoopBudgetError::InternalState)?;
        check_usage_capacity(&state, self.limits)?;
        if state.model_turns >= self.limits.max_model_turns {
            return Err(LoopBudgetError::Exhausted(LoopBudgetDimension::ModelTurns));
        }
        state.model_turns = state
            .model_turns
            .checked_add(1)
            .ok_or(LoopBudgetError::Exhausted(LoopBudgetDimension::ModelTurns))?;
        Ok(())
    }

    /// Atomically reserves one complete tool call at an explicit instant.
    ///
    /// # Errors
    ///
    /// Returns the exhausted dimension without changing counters.
    pub fn reserve_tool_call_at(&self, now: OffsetDateTime) -> Result<(), LoopBudgetError> {
        self.check_wall_and_static(now)?;
        let mut state = self
            .state
            .lock()
            .map_err(|_| LoopBudgetError::InternalState)?;
        check_usage_capacity(&state, self.limits)?;
        if state.tool_calls >= self.limits.max_tool_calls {
            return Err(LoopBudgetError::Exhausted(LoopBudgetDimension::ToolCalls));
        }
        state.tool_calls = state
            .tool_calls
            .checked_add(1)
            .ok_or(LoopBudgetError::Exhausted(LoopBudgetDimension::ToolCalls))?;
        Ok(())
    }

    /// Charges observed tokens and cost atomically at an explicit instant.
    ///
    /// A rejected charge leaves both dimensions unchanged.
    ///
    /// # Errors
    ///
    /// Returns wall-clock, token, or cost exhaustion without partial mutation.
    pub fn charge_usage_at(
        &self,
        tokens: u64,
        cost_microunits: u64,
        now: OffsetDateTime,
    ) -> Result<(), LoopBudgetError> {
        if now >= self.deadline {
            return Err(LoopBudgetError::Exhausted(LoopBudgetDimension::WallClock));
        }
        let mut state = self
            .state
            .lock()
            .map_err(|_| LoopBudgetError::InternalState)?;
        let next_tokens = state
            .tokens
            .checked_add(tokens)
            .ok_or(LoopBudgetError::Exhausted(LoopBudgetDimension::Tokens))?;
        if next_tokens > self.limits.max_tokens {
            return Err(LoopBudgetError::Exhausted(LoopBudgetDimension::Tokens));
        }
        let next_cost = state
            .cost_microunits
            .checked_add(cost_microunits)
            .ok_or(LoopBudgetError::Exhausted(LoopBudgetDimension::Cost))?;
        if next_cost > self.limits.max_cost_microunits {
            return Err(LoopBudgetError::Exhausted(LoopBudgetDimension::Cost));
        }
        state.tokens = next_tokens;
        state.cost_microunits = next_cost;
        Ok(())
    }

    /// Reserves one concurrent-work slot at an explicit instant.
    ///
    /// The returned permit releases its slot on drop, including cancellation and
    /// early error paths.
    ///
    /// # Errors
    ///
    /// Returns wall-clock or concurrency exhaustion without waiting.
    pub fn try_reserve_concurrency_at(
        &self,
        now: OffsetDateTime,
    ) -> Result<LoopConcurrencyPermit<'_>, LoopBudgetError> {
        if now >= self.deadline {
            return Err(LoopBudgetError::Exhausted(LoopBudgetDimension::WallClock));
        }
        let max = self.limits.max_concurrency;
        if max == 0 {
            return Err(LoopBudgetError::Exhausted(LoopBudgetDimension::Concurrency));
        }

        let mut current = self.active.load(Ordering::Acquire);
        loop {
            if current >= max {
                return Err(LoopBudgetError::Exhausted(LoopBudgetDimension::Concurrency));
            }
            match self.active.compare_exchange_weak(
                current,
                current + 1,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => return Ok(LoopConcurrencyPermit { budget: self }),
                Err(observed) => current = observed,
            }
        }
    }

    /// Returns a consistent counter snapshot.
    ///
    /// # Errors
    ///
    /// Returns [`LoopBudgetError::InternalState`] if accounting is unavailable.
    pub fn snapshot(&self) -> Result<LoopBudgetSnapshot, LoopBudgetError> {
        let state = self
            .state
            .lock()
            .map_err(|_| LoopBudgetError::InternalState)?;
        Ok(LoopBudgetSnapshot {
            model_turns: state.model_turns,
            tool_calls: state.tool_calls,
            tokens: state.tokens,
            cost_microunits: state.cost_microunits,
            active_concurrency: self.active.load(Ordering::Acquire),
        })
    }

    fn check_wall_and_static(&self, now: OffsetDateTime) -> Result<(), LoopBudgetError> {
        if now >= self.deadline {
            return Err(LoopBudgetError::Exhausted(LoopBudgetDimension::WallClock));
        }
        if self.limits.max_concurrency == 0 {
            return Err(LoopBudgetError::Exhausted(LoopBudgetDimension::Concurrency));
        }
        Ok(())
    }
}

impl std::fmt::Debug for AgentLoopBudget {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("AgentLoopBudget")
            .field("limits", &self.limits)
            .field("started_at", &self.started_at)
            .field("deadline", &self.deadline)
            .field("active_concurrency", &self.active.load(Ordering::Acquire))
            .finish_non_exhaustive()
    }
}

/// RAII ownership of one loop concurrency slot.
#[must_use = "dropping the permit immediately releases the reserved concurrency slot"]
pub struct LoopConcurrencyPermit<'a> {
    budget: &'a AgentLoopBudget,
}

impl Drop for LoopConcurrencyPermit<'_> {
    fn drop(&mut self) {
        self.budget.active.fetch_sub(1, Ordering::AcqRel);
    }
}

impl std::fmt::Debug for LoopConcurrencyPermit<'_> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("LoopConcurrencyPermit")
    }
}

/// Observable loop usage without mutable access to accounting.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LoopBudgetSnapshot {
    /// Reserved model turns.
    pub model_turns: u32,
    /// Reserved complete tool calls.
    pub tool_calls: u32,
    /// Charged total tokens.
    pub tokens: u64,
    /// Charged integer cost microunits.
    pub cost_microunits: u64,
    /// Currently held concurrency permits.
    pub active_concurrency: usize,
}

#[derive(Default)]
struct LoopBudgetState {
    model_turns: u32,
    tool_calls: u32,
    tokens: u64,
    cost_microunits: u64,
}

/// A loop budget could not be constructed.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum LoopBudgetBuildError {
    /// Wall-clock limits cannot be negative; zero is an exhausted budget.
    #[error("loop wall-clock budget is negative")]
    NegativeWallClock,
    /// The absolute deadline cannot be represented.
    #[error("loop wall-clock deadline is outside the representable range")]
    DeadlineOverflow,
}

/// A fixed, value-free loop accounting failure.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum LoopBudgetError {
    /// One exact dimension is exhausted.
    #[error("agent loop budget is exhausted")]
    Exhausted(LoopBudgetDimension),
    /// Shared accounting became unavailable.
    #[error("agent loop budget accounting is unavailable")]
    InternalState,
}

fn check_usage_capacity(
    state: &LoopBudgetState,
    limits: LoopBudgetLimits,
) -> Result<(), LoopBudgetError> {
    if state.tokens >= limits.max_tokens {
        return Err(LoopBudgetError::Exhausted(LoopBudgetDimension::Tokens));
    }
    if state.cost_microunits >= limits.max_cost_microunits {
        return Err(LoopBudgetError::Exhausted(LoopBudgetDimension::Cost));
    }
    Ok(())
}

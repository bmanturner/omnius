use std::str::FromStr as _;

use chrono::{DateTime, Utc};
use croner::Cron;
use time::OffsetDateTime;

use crate::{MisfirePolicy, ScheduleDefinition, SchedulerError};

/// Bounded deterministic result of evaluating one claimed schedule.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OccurrencePlan {
    occurrences: Vec<OffsetDateTime>,
    next_run_at: OffsetDateTime,
}

impl OccurrencePlan {
    /// Exact UTC instants to materialize in order.
    #[must_use]
    pub fn occurrences(&self) -> &[OffsetDateTime] {
        &self.occurrences
    }

    /// Exact next cursor persisted on the schedule.
    #[must_use]
    pub const fn next_run_at(&self) -> OffsetDateTime {
        self.next_run_at
    }
}

/// Returns the first Croner occurrence strictly after an exact UTC instant.
///
/// Croner performs the wall-clock evaluation in the definition's IANA time zone. The returned
/// zoned value is converted to UTC without collapsing daylight-saving overlap instants.
///
/// # Errors
///
/// Returns [`SchedulerError::Calendar`] for parser, search, or timestamp conversion failure.
pub fn next_occurrence(
    definition: &ScheduleDefinition,
    after: OffsetDateTime,
) -> Result<OffsetDateTime, SchedulerError> {
    let cron = Cron::from_str(definition.expression()).map_err(|_| SchedulerError::Calendar)?;
    let after = to_chrono(after)?;
    let zoned = after.with_timezone(&definition.timezone_value());
    let found = cron
        .find_next_occurrence(&zoned, false)
        .map_err(|_| SchedulerError::Calendar)?;
    from_chrono(found.with_timezone(&Utc))
}

/// Applies the schedule's deterministic misfire policy at a PostgreSQL-clock boundary.
///
/// `Skip` advances directly beyond `now`. `FireOnce` emits the cursor once and advances directly
/// beyond `now`. `CatchUp` emits at most its configured batch of exact instants and intentionally
/// leaves `next_run_at <= now` when missed work remains, making the next bounded claim continue it.
///
/// # Errors
///
/// Returns [`SchedulerError::Calendar`] when the cursor is not due or evaluation fails.
pub fn evaluate_occurrences(
    definition: &ScheduleDefinition,
    cursor: OffsetDateTime,
    now: OffsetDateTime,
) -> Result<OccurrencePlan, SchedulerError> {
    if cursor > now {
        return Err(SchedulerError::Calendar);
    }
    match definition.misfire_policy() {
        MisfirePolicy::Skip => Ok(OccurrencePlan {
            occurrences: Vec::new(),
            next_run_at: next_occurrence(definition, now)?,
        }),
        MisfirePolicy::FireOnce => Ok(OccurrencePlan {
            occurrences: vec![cursor],
            next_run_at: next_occurrence(definition, now)?,
        }),
        MisfirePolicy::CatchUp { max_runs } => {
            let mut occurrences = Vec::with_capacity(usize::from(max_runs.get()));
            let mut next = cursor;
            while next <= now && occurrences.len() < usize::from(max_runs.get()) {
                occurrences.push(next);
                next = next_occurrence(definition, next)?;
            }
            Ok(OccurrencePlan {
                occurrences,
                next_run_at: next,
            })
        }
    }
}

fn to_chrono(value: OffsetDateTime) -> Result<DateTime<Utc>, SchedulerError> {
    DateTime::from_timestamp(value.unix_timestamp(), value.nanosecond())
        .ok_or(SchedulerError::Calendar)
}

fn from_chrono(value: DateTime<Utc>) -> Result<OffsetDateTime, SchedulerError> {
    let nanos = i128::from(value.timestamp())
        .checked_mul(1_000_000_000)
        .and_then(|seconds| seconds.checked_add(i128::from(value.timestamp_subsec_nanos())))
        .ok_or(SchedulerError::Calendar)?;
    OffsetDateTime::from_unix_timestamp_nanos(nanos).map_err(|_| SchedulerError::Calendar)
}

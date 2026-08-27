use std::sync::{Arc, RwLock, RwLockReadGuard, RwLockWriteGuard};

use omnius_core::Clock;
use thiserror::Error;
use time::{Duration, OffsetDateTime, UtcOffset};

/// A cloneable clock whose copies share one explicitly controlled instant.
#[derive(Clone, Debug)]
pub struct TestClock {
    now: Arc<RwLock<OffsetDateTime>>,
}

impl TestClock {
    /// Creates a clock at the supplied instant, normalized to UTC.
    #[must_use]
    pub fn at(now: OffsetDateTime) -> Self {
        Self {
            now: Arc::new(RwLock::new(now.to_offset(UtcOffset::UTC))),
        }
    }

    /// Returns the current controlled UTC instant.
    #[must_use]
    pub fn now(&self) -> OffsetDateTime {
        *read(&self.now)
    }

    /// Replaces the shared instant, normalized to UTC.
    pub fn set(&self, now: OffsetDateTime) {
        *write(&self.now) = now.to_offset(UtcOffset::UTC);
    }

    /// Advances the shared instant without reading wall time.
    ///
    /// # Errors
    ///
    /// Returns [`TestClockError::Overflow`] when the duration is outside the
    /// representable timestamp range. The clock remains unchanged on failure.
    pub fn advance(&self, duration: Duration) -> Result<OffsetDateTime, TestClockError> {
        let mut now = write(&self.now);
        let advanced = now.checked_add(duration).ok_or(TestClockError::Overflow)?;
        *now = advanced;
        Ok(advanced)
    }
}

impl Clock for TestClock {
    fn now_utc(&self) -> OffsetDateTime {
        self.now()
    }
}

/// A deterministic clock operation exceeded the timestamp range.
#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum TestClockError {
    /// The requested advance cannot be represented by `OffsetDateTime`.
    #[error("test clock advance exceeds timestamp range")]
    Overflow,
}

fn read<T>(lock: &RwLock<T>) -> RwLockReadGuard<'_, T> {
    lock.read()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

fn write<T>(lock: &RwLock<T>) -> RwLockWriteGuard<'_, T> {
    lock.write()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clones_share_explicit_utc_time_without_wall_clock_access() -> Result<(), TestClockError> {
        let initial = OffsetDateTime::from_unix_timestamp(1_787_443_200)
            .map_err(|_| TestClockError::Overflow)?;
        let clock = TestClock::at(initial);
        let clone = clock.clone();

        let advanced = clock.advance(Duration::minutes(5))?;
        assert_eq!(clone.now_utc(), advanced);
        assert_eq!(advanced.offset(), UtcOffset::UTC);
        Ok(())
    }

    #[test]
    fn overflow_does_not_mutate_the_clock() {
        let maximum = time::Date::MAX.with_time(time::Time::MAX).assume_utc();
        let clock = TestClock::at(maximum);
        assert_eq!(
            clock.advance(Duration::SECOND),
            Err(TestClockError::Overflow)
        );
        assert_eq!(clock.now(), maximum);
    }
}

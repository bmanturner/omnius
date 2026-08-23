use time::OffsetDateTime;

/// Supplies wall-clock time to application code.
///
/// Production composition uses [`SystemClock`]. Tests provide deterministic
/// implementations without changing application services.
pub trait Clock: Send + Sync {
    /// Returns the current UTC instant.
    fn now_utc(&self) -> OffsetDateTime;
}

/// A clock backed by the operating system wall clock.
#[derive(Clone, Copy, Debug, Default)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now_utc(&self) -> OffsetDateTime {
        OffsetDateTime::now_utc()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn system_clock_returns_a_utc_instant() {
        let instant = SystemClock.now_utc();
        assert_eq!(instant.offset(), time::UtcOffset::UTC);
    }
}

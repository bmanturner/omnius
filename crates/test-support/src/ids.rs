use std::sync::{
    Arc,
    atomic::{AtomicU64, Ordering},
};

use omnius_core::{CausationId, CorrelationId, RequestId};
use thiserror::Error;
use uuid::Uuid;

const DEFAULT_TIMESTAMP_MILLIS: u64 = 1_787_443_200_000;
const MAX_TIMESTAMP_MILLIS: u64 = (1_u64 << 48) - 1;
const MAX_SEQUENCE: u64 = (1_u64 << 62) - 1;

/// A cloneable deterministic sequence of valid UUIDv7-shaped identifiers.
#[derive(Clone, Debug)]
pub struct TestIds {
    timestamp_millis: u64,
    next: Arc<AtomicU64>,
}

impl TestIds {
    /// Creates a sequence for a fixed Unix timestamp and starting counter.
    ///
    /// # Errors
    ///
    /// Returns [`TestIdError`] when the `UUIDv7` timestamp or sequence does not
    /// fit its wire representation.
    pub fn at(timestamp_millis: u64, sequence: u64) -> Result<Self, TestIdError> {
        if timestamp_millis > MAX_TIMESTAMP_MILLIS {
            return Err(TestIdError::TimestampOutOfRange);
        }
        if sequence >= MAX_SEQUENCE {
            return Err(TestIdError::SequenceExhausted);
        }
        Ok(Self {
            timestamp_millis,
            next: Arc::new(AtomicU64::new(sequence)),
        })
    }

    /// Returns the next deterministic `UUIDv7` value.
    ///
    /// Clones draw from the same sequence. Concurrent callers receive distinct
    /// values, while the order among concurrent callers is intentionally not
    /// specified.
    ///
    /// # Errors
    ///
    /// Returns [`TestIdError::SequenceExhausted`] rather than wrapping.
    pub fn uuid_v7(&self) -> Result<Uuid, TestIdError> {
        let sequence = self
            .next
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
                (current < MAX_SEQUENCE).then_some(current + 1)
            })
            .map_err(|_| TestIdError::SequenceExhausted)?;
        let mut bytes = [0_u8; 16];
        let timestamp = self.timestamp_millis.to_be_bytes();
        bytes[..6].copy_from_slice(&timestamp[2..]);
        bytes[6] = 0x70;
        bytes[7] = 0;
        bytes[8..].copy_from_slice(&sequence.to_be_bytes());
        bytes[8] = (bytes[8] & 0x3f) | 0x80;
        Ok(Uuid::from_bytes(bytes))
    }

    /// Returns the next deterministic request identifier.
    ///
    /// # Errors
    ///
    /// Returns [`TestIdError::SequenceExhausted`] rather than wrapping.
    pub fn request_id(&self) -> Result<RequestId, TestIdError> {
        self.uuid_v7().map(RequestId::from_uuid)
    }

    /// Returns the next deterministic correlation identifier.
    ///
    /// # Errors
    ///
    /// Returns [`TestIdError::SequenceExhausted`] rather than wrapping.
    pub fn correlation_id(&self) -> Result<CorrelationId, TestIdError> {
        self.uuid_v7().map(CorrelationId::from_uuid)
    }

    /// Returns the next deterministic causation identifier.
    ///
    /// # Errors
    ///
    /// Returns [`TestIdError::SequenceExhausted`] rather than wrapping.
    pub fn causation_id(&self) -> Result<CausationId, TestIdError> {
        self.uuid_v7().map(CausationId::from_uuid)
    }
}

impl Default for TestIds {
    fn default() -> Self {
        Self {
            timestamp_millis: DEFAULT_TIMESTAMP_MILLIS,
            next: Arc::new(AtomicU64::new(0)),
        }
    }
}

/// Invalid or exhausted deterministic identifier state.
#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum TestIdError {
    /// `UUIDv7` stores Unix milliseconds in 48 bits.
    #[error("test identifier timestamp exceeds UUIDv7 range")]
    TimestampOutOfRange,
    /// The deterministic 62-bit sequence cannot advance without repetition.
    #[error("test identifier sequence is exhausted")]
    SequenceExhausted,
}

#[cfg(test)]
mod tests {
    use super::*;
    use uuid::{Variant, Version};

    #[test]
    fn independent_sequences_replay_exact_uuid_v7_values() -> Result<(), TestIdError> {
        let left = TestIds::default();
        let right = TestIds::default();

        for _ in 0..3 {
            let left_id = left.uuid_v7()?;
            let right_id = right.uuid_v7()?;
            assert_eq!(left_id, right_id);
            assert_eq!(left_id.get_version(), Some(Version::SortRand));
            assert_eq!(left_id.get_variant(), Variant::RFC4122);
        }
        Ok(())
    }

    #[test]
    fn clones_share_one_non_repeating_sequence() -> Result<(), TestIdError> {
        let ids = TestIds::default();
        let clone = ids.clone();
        assert_ne!(ids.request_id()?, clone.request_id()?);
        Ok(())
    }

    #[test]
    fn rejects_unrepresentable_state_without_wrapping() {
        assert!(matches!(
            TestIds::at(MAX_TIMESTAMP_MILLIS + 1, 0),
            Err(TestIdError::TimestampOutOfRange)
        ));
        assert!(matches!(
            TestIds::at(0, MAX_SEQUENCE),
            Err(TestIdError::SequenceExhausted)
        ));
    }
}

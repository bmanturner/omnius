use std::sync::{Arc, Mutex, MutexGuard};

const DEFAULT_SEED: u64 = 0x7273_6b2d_7465_7374;
const GAMMA: u64 = 0x9e37_79b9_7f4a_7c15;

/// A replayable byte source for tests that never substitutes for secure entropy.
///
/// Clones share one sequence. Concurrent calls remain memory-safe and unique by
/// call order, but tests requiring exact replay should make calls sequentially.
#[derive(Clone, Debug)]
pub struct DeterministicRandom {
    state: Arc<Mutex<u64>>,
}

impl DeterministicRandom {
    /// Creates a replayable sequence from an explicit seed.
    #[must_use]
    pub fn seeded(seed: u64) -> Self {
        Self {
            state: Arc::new(Mutex::new(seed)),
        }
    }

    /// Returns the next deterministic 64-bit value.
    #[must_use]
    pub fn next_u64(&self) -> u64 {
        let mut state = lock(&self.state);
        *state = state.wrapping_add(GAMMA);
        let mut value = *state;
        value = (value ^ (value >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        value = (value ^ (value >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        value ^ (value >> 31)
    }

    /// Fills a buffer with deterministic bytes without allocation.
    pub fn fill_bytes(&self, output: &mut [u8]) {
        for chunk in output.chunks_mut(size_of::<u64>()) {
            let bytes = self.next_u64().to_le_bytes();
            chunk.copy_from_slice(&bytes[..chunk.len()]);
        }
    }
}

impl Default for DeterministicRandom {
    fn default() -> Self {
        Self::seeded(DEFAULT_SEED)
    }
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn equal_seeds_replay_values_and_partial_chunks() {
        let left = DeterministicRandom::seeded(42);
        let right = DeterministicRandom::seeded(42);
        let mut left_bytes = [0_u8; 19];
        let mut right_bytes = [0_u8; 19];

        left.fill_bytes(&mut left_bytes);
        right.fill_bytes(&mut right_bytes);
        assert_eq!(left_bytes, right_bytes);
        assert_ne!(left_bytes, [0_u8; 19]);
    }

    #[test]
    fn clones_advance_one_shared_sequence() {
        let source = DeterministicRandom::seeded(7);
        let clone = source.clone();
        assert_ne!(source.next_u64(), clone.next_u64());
    }
}

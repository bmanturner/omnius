use std::num::NonZeroUsize;

use thiserror::Error;

/// A pre-sequencing text coalescer with a fixed UTF-8 byte ceiling.
///
/// Each instance belongs to one text part. It never combines text across part
/// identities and must be flushed before any non-text event is sequenced.
pub struct BoundedTextCoalescer {
    max_bytes: NonZeroUsize,
    buffered: String,
}

impl BoundedTextCoalescer {
    /// Creates an empty coalescer with a positive byte ceiling.
    #[must_use]
    pub fn new(max_bytes: NonZeroUsize) -> Self {
        Self {
            max_bytes,
            buffered: String::new(),
        }
    }

    /// Buffers one complete UTF-8 fragment.
    ///
    /// If adding the fragment would exceed the ceiling, the previous buffer is
    /// returned for emission and the new fragment becomes the buffer. Returning
    /// `None` means no event needs to be emitted yet.
    ///
    /// # Errors
    ///
    /// Returns [`TextCoalesceError::FragmentTooLarge`] when one fragment alone
    /// exceeds the configured ceiling.
    pub fn push(&mut self, fragment: &str) -> Result<Option<String>, TextCoalesceError> {
        if fragment.len() > self.max_bytes.get() {
            return Err(TextCoalesceError::FragmentTooLarge);
        }
        if fragment.is_empty() {
            return Ok(None);
        }
        if self
            .buffered
            .len()
            .checked_add(fragment.len())
            .is_some_and(|combined| combined <= self.max_bytes.get())
        {
            self.buffered.push_str(fragment);
            return Ok(None);
        }

        let ready = std::mem::replace(&mut self.buffered, fragment.to_owned());
        Ok(Some(ready))
    }

    /// Returns buffered text for sequencing, leaving the coalescer empty.
    #[must_use]
    pub fn flush(&mut self) -> Option<String> {
        if self.buffered.is_empty() {
            None
        } else {
            Some(std::mem::take(&mut self.buffered))
        }
    }

    /// Returns the current buffered UTF-8 byte count.
    #[must_use]
    pub fn buffered_bytes(&self) -> usize {
        self.buffered.len()
    }
}

impl std::fmt::Debug for BoundedTextCoalescer {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("BoundedTextCoalescer")
            .field("max_bytes", &self.max_bytes)
            .field("buffered_bytes", &self.buffered.len())
            .finish()
    }
}

/// A fixed, content-free coalescing failure.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum TextCoalesceError {
    /// One provider fragment exceeded the configured coalescing ceiling.
    #[error("text fragment exceeds the coalescing byte ceiling")]
    FragmentTooLarge,
}

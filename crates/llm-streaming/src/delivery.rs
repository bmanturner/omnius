use std::{num::NonZeroUsize, time::Duration};

use thiserror::Error;
use time::OffsetDateTime;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use crate::LlmStreamEvent;

/// Which component retains ownership when the channel consumer disconnects.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConsumerOwnership {
    /// The connected consumer owns the request; disconnect cancels upstream work.
    Interactive,
    /// A durable job owns the request; disconnect closes delivery but not job work.
    DurableJob,
}

/// Creates one finite request-local delivery channel.
///
/// The absolute deadline and cancellation token must be inherited from the
/// request context. Capacity is positive by construction.
#[must_use]
pub fn bounded_stream(
    capacity: NonZeroUsize,
    deadline: OffsetDateTime,
    cancellation: CancellationToken,
    ownership: ConsumerOwnership,
) -> (StreamSender, StreamReceiver) {
    let (sender, receiver) = mpsc::channel(capacity.get());
    (
        StreamSender {
            sender,
            deadline,
            cancellation: cancellation.clone(),
            ownership,
        },
        StreamReceiver {
            receiver,
            deadline,
            cancellation,
            ownership,
            terminal_received: false,
        },
    )
}

/// The single-producer side of a finite canonical event channel.
pub struct StreamSender {
    sender: mpsc::Sender<LlmStreamEvent>,
    deadline: OffsetDateTime,
    cancellation: CancellationToken,
    ownership: ConsumerOwnership,
}

impl StreamSender {
    /// Sends one event while honoring finite capacity, cancellation, and deadline.
    ///
    /// A full channel applies backpressure without allocating another queue.
    /// Interactive consumer disconnect cancels the inherited token; durable
    /// disconnect returns an error without cancelling job-owned work.
    ///
    /// # Errors
    ///
    /// Returns a fixed [`DeliveryError`] on cancellation, deadline, or disconnect.
    pub async fn send(&self, event: LlmStreamEvent) -> Result<(), DeliveryError> {
        if self.cancellation.is_cancelled() {
            return Err(DeliveryError::Cancelled);
        }
        let remaining = remaining(self.deadline);
        if remaining.is_zero() {
            self.cancellation.cancel();
            return Err(DeliveryError::DeadlineExceeded);
        }

        let deadline = tokio::time::sleep(remaining);
        tokio::pin!(deadline);
        let result = tokio::select! {
            biased;
            () = self.cancellation.cancelled() => return Err(DeliveryError::Cancelled),
            () = &mut deadline => {
                self.cancellation.cancel();
                return Err(DeliveryError::DeadlineExceeded);
            }
            result = self.sender.send(event) => result,
        };

        result.map_err(|_| {
            if self.ownership == ConsumerOwnership::Interactive {
                self.cancellation.cancel();
            }
            DeliveryError::ConsumerDisconnected
        })
    }

    /// Returns unused channel slots at this instant.
    #[must_use]
    pub fn remaining_capacity(&self) -> usize {
        self.sender.capacity()
    }

    /// Returns the inherited cancellation token.
    #[must_use]
    pub const fn cancellation_token(&self) -> &CancellationToken {
        &self.cancellation
    }
}

impl std::fmt::Debug for StreamSender {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("StreamSender")
            .field("remaining_capacity", &self.sender.capacity())
            .field("ownership", &self.ownership)
            .finish_non_exhaustive()
    }
}

/// The consumer side of a finite canonical event channel.
pub struct StreamReceiver {
    receiver: mpsc::Receiver<LlmStreamEvent>,
    deadline: OffsetDateTime,
    cancellation: CancellationToken,
    ownership: ConsumerOwnership,
    terminal_received: bool,
}

impl StreamReceiver {
    /// Receives the next event under the inherited lifecycle controls.
    ///
    /// # Errors
    ///
    /// Returns a fixed [`DeliveryError`] when cancellation or deadline wins.
    /// A clean producer close returns `Ok(None)`.
    pub async fn recv(&mut self) -> Result<Option<LlmStreamEvent>, DeliveryError> {
        if self.terminal_received {
            return Ok(None);
        }
        if self.cancellation.is_cancelled() {
            return Err(DeliveryError::Cancelled);
        }
        let remaining = remaining(self.deadline);
        if remaining.is_zero() {
            self.cancellation.cancel();
            return Err(DeliveryError::DeadlineExceeded);
        }

        let deadline = tokio::time::sleep(remaining);
        tokio::pin!(deadline);
        let event = tokio::select! {
            biased;
            () = self.cancellation.cancelled() => return Err(DeliveryError::Cancelled),
            () = &mut deadline => {
                self.cancellation.cancel();
                return Err(DeliveryError::DeadlineExceeded);
            }
            event = self.receiver.recv() => event,
        };
        if event
            .as_ref()
            .is_some_and(|event| event.terminal().is_some())
        {
            self.terminal_received = true;
            self.receiver.close();
        }
        Ok(event)
    }

    /// Closes the receiving side without changing durable ownership semantics.
    pub fn close(&mut self) {
        self.receiver.close();
        if self.ownership == ConsumerOwnership::Interactive && !self.terminal_received {
            self.cancellation.cancel();
        }
    }
}

impl Drop for StreamReceiver {
    fn drop(&mut self) {
        if self.ownership == ConsumerOwnership::Interactive && !self.terminal_received {
            self.cancellation.cancel();
        }
    }
}

impl std::fmt::Debug for StreamReceiver {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("StreamReceiver")
            .field("ownership", &self.ownership)
            .field("terminal_received", &self.terminal_received)
            .finish_non_exhaustive()
    }
}

/// A fixed, payload-free delivery failure.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum DeliveryError {
    /// The inherited cooperative cancellation token was cancelled.
    #[error("stream delivery was cancelled")]
    Cancelled,
    /// The inherited absolute deadline elapsed.
    #[error("stream delivery deadline elapsed")]
    DeadlineExceeded,
    /// The bounded channel consumer disconnected.
    #[error("stream consumer disconnected")]
    ConsumerDisconnected,
}

fn remaining(deadline: OffsetDateTime) -> Duration {
    let remaining = deadline - OffsetDateTime::now_utc();
    if remaining.is_positive() {
        remaining.unsigned_abs()
    } else {
        Duration::ZERO
    }
}

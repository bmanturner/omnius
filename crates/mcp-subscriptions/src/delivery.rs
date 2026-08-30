use std::{
    collections::{HashMap, VecDeque},
    sync::{Arc, Mutex, MutexGuard, Weak},
    time::Duration,
};

use async_trait::async_trait;
use tokio::sync::Notify;

use crate::{
    DeliveryAdmission, DeliveryAttachmentSignal, DeliveryCloseMode, DeliveryDisconnectSignal,
    DeliveryError, DeliveryFrame, DeliveryLimits, DeliveryOpen, DrainOutcome, SubscriptionDelivery,
    SubscriptionId,
};

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

#[derive(Debug)]
struct QueueState {
    limits: DeliveryLimits,
    frames: VecDeque<DeliveryFrame>,
    retained_bytes: usize,
    receiver_taken: bool,
    receiver_dropped: bool,
    terminal: Option<DeliveryFrame>,
}

#[derive(Debug)]
struct Queue {
    state: Mutex<QueueState>,
    changed: Notify,
    disconnected: DeliveryDisconnectSignal,
    attachment: DeliveryAttachmentSignal,
}

impl Queue {
    fn new(limits: DeliveryLimits) -> Self {
        Self {
            state: Mutex::new(QueueState {
                limits,
                frames: VecDeque::new(),
                retained_bytes: 0,
                receiver_taken: false,
                receiver_dropped: false,
                terminal: None,
            }),
            changed: Notify::new(),
            disconnected: DeliveryDisconnectSignal::new(),
            attachment: DeliveryAttachmentSignal::pending(),
        }
    }
}

/// Bounded transport-neutral delivery adapter.
///
/// It holds no durable state. A response transport takes exactly one [`DeliveryStream`] and maps
/// frames to its own wire format. Queue count and retained bytes are enforced before admission.
#[derive(Clone, Debug, Default)]
pub struct BoundedDeliveryQueue {
    queues: Arc<Mutex<HashMap<SubscriptionId, Arc<Queue>>>>,
}

impl BoundedDeliveryQueue {
    /// Takes the sole consumer for an opened subscription.
    ///
    /// # Errors
    ///
    /// Returns [`DeliveryError::Closed`] when the subscription has no open stream, its receiver
    /// was already taken, or its receiver was dropped.
    pub fn take_stream(
        &self,
        subscription_id: &SubscriptionId,
    ) -> Result<DeliveryStream, DeliveryError> {
        let queue = {
            let queues = lock(&self.queues);
            queues
                .get(subscription_id)
                .cloned()
                .ok_or(DeliveryError::Closed)?
        };
        {
            let mut state = lock(&queue.state);
            if state.receiver_taken || state.receiver_dropped {
                return Err(DeliveryError::Closed);
            }
            state.receiver_taken = true;
            if !queue.attachment.notify_attached() {
                return Err(DeliveryError::Closed);
            }
        }
        Ok(DeliveryStream {
            subscription_id: subscription_id.clone(),
            queue: Arc::clone(&queue),
            queues: Arc::downgrade(&self.queues),
            terminated: false,
        })
    }
}

#[async_trait]
impl SubscriptionDelivery for BoundedDeliveryQueue {
    async fn open(
        &self,
        subscription_id: &SubscriptionId,
        limits: DeliveryLimits,
    ) -> Result<DeliveryOpen, DeliveryError> {
        if limits.max_frames == 0 || limits.max_bytes == 0 {
            return Err(DeliveryError::Unavailable);
        }
        let mut queues = lock(&self.queues);
        if queues.contains_key(subscription_id) {
            return Err(DeliveryError::AlreadyOpen);
        }
        let queue = Arc::new(Queue::new(limits));
        let signals = DeliveryOpen {
            disconnect: queue.disconnected.clone(),
            attachment: queue.attachment.clone(),
        };
        queues.insert(subscription_id.clone(), queue);
        Ok(signals)
    }

    async fn deliver(
        &self,
        subscription_id: &SubscriptionId,
        frame: DeliveryFrame,
    ) -> Result<DeliveryAdmission, DeliveryError> {
        let queue = {
            let queues = lock(&self.queues);
            queues.get(subscription_id).cloned()
        };
        let Some(queue) = queue else {
            return Ok(DeliveryAdmission::Disconnected);
        };
        let encoded_len = frame.encoded_len();
        {
            let mut state = lock(&queue.state);
            if state.receiver_dropped || state.terminal.is_some() {
                return Ok(DeliveryAdmission::Disconnected);
            }
            let retained_bytes = state.retained_bytes.saturating_add(encoded_len);
            if state.frames.len() >= state.limits.max_frames
                || retained_bytes > state.limits.max_bytes
            {
                return Ok(DeliveryAdmission::SlowConsumer);
            }
            state.retained_bytes = retained_bytes;
            state.frames.push_back(frame);
        }
        queue.changed.notify_waiters();
        Ok(DeliveryAdmission::Accepted)
    }

    async fn close(
        &self,
        subscription_id: &SubscriptionId,
        mode: DeliveryCloseMode,
        mut close: DeliveryFrame,
    ) -> Result<DrainOutcome, DeliveryError> {
        let queue = {
            let mut queues = lock(&self.queues);
            queues.remove(subscription_id)
        };
        let Some(queue) = queue else {
            return Ok(DrainOutcome::Disconnected);
        };
        queue.attachment.notify_closed();

        let outcome = match mode {
            DeliveryCloseMode::Abort => {
                let mut state = lock(&queue.state);
                state.frames.clear();
                state.retained_bytes = 0;
                if state.receiver_dropped || !state.receiver_taken {
                    DrainOutcome::Disconnected
                } else {
                    DrainOutcome::DeadlineExceeded
                }
            }
            DeliveryCloseMode::Drain { timeout_ms } => {
                let deadline = tokio::time::Instant::now() + Duration::from_millis(timeout_ms);
                loop {
                    let notified = queue.changed.notified();
                    tokio::pin!(notified);
                    notified.as_mut().enable();
                    {
                        let state = lock(&queue.state);
                        if state.receiver_dropped || !state.receiver_taken {
                            break DrainOutcome::Disconnected;
                        }
                        if state.frames.is_empty() {
                            break DrainOutcome::Drained;
                        }
                    }
                    if tokio::time::timeout_at(deadline, notified).await.is_err() {
                        let mut state = lock(&queue.state);
                        state.frames.clear();
                        state.retained_bytes = 0;
                        break DrainOutcome::DeadlineExceeded;
                    }
                }
            }
        };

        close.set_drain_outcome(outcome);
        {
            let mut state = lock(&queue.state);
            if !state.receiver_dropped && state.receiver_taken {
                state.terminal = Some(close);
            }
        }
        queue.changed.notify_waiters();
        Ok(outcome)
    }
}

/// Sole bounded receiver for one transport response stream.
#[derive(Debug)]
pub struct DeliveryStream {
    subscription_id: SubscriptionId,
    queue: Arc<Queue>,
    queues: Weak<Mutex<HashMap<SubscriptionId, Arc<Queue>>>>,
    terminated: bool,
}

impl DeliveryStream {
    /// Waits for the next already-bounded frame or terminal transport loss.
    pub async fn next(&mut self) -> Option<DeliveryFrame> {
        if self.terminated {
            return None;
        }
        loop {
            let notified = self.queue.changed.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            {
                let mut state = lock(&self.queue.state);
                if let Some(frame) = state.frames.pop_front() {
                    state.retained_bytes = state.retained_bytes.saturating_sub(frame.encoded_len());
                    let acknowledged = matches!(frame, DeliveryFrame::Acknowledged(_));
                    drop(state);
                    if acknowledged {
                        let _ = self.queue.attachment.notify_ready();
                    }
                    self.queue.changed.notify_waiters();
                    return Some(frame);
                }
                if let Some(frame) = state.terminal.take() {
                    self.terminated = true;
                    return Some(frame);
                }
                if state.receiver_dropped {
                    return None;
                }
            }
            notified.await;
        }
    }
}

impl Drop for DeliveryStream {
    fn drop(&mut self) {
        {
            let mut state = lock(&self.queue.state);
            state.receiver_dropped = true;
            state.frames.clear();
            state.retained_bytes = 0;
            state.terminal = None;
        }
        if let Some(queues) = self.queues.upgrade() {
            let mut queues = lock(&queues);
            if queues
                .get(&self.subscription_id)
                .is_some_and(|queue| Arc::ptr_eq(queue, &self.queue))
            {
                queues.remove(&self.subscription_id);
            }
        }
        self.queue.disconnected.notify_disconnect();
        self.queue.attachment.notify_closed();
        self.queue.changed.notify_waiters();
    }
}

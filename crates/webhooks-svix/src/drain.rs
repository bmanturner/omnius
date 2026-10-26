//! Admission and bounded-drain gate shared by the SDK and fake webhook providers.

use std::{
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    time::Duration,
};

use metrics::gauge;
use tokio::{sync::Notify, time};
use tokio_util::sync::CancellationToken;

use crate::{FailureClass, ProviderError};

/// Tracks admitted operations so a provider can stop accepting work, cancel it, and wait for it.
pub(crate) struct DrainGate {
    provider: &'static str,
    accepting: AtomicBool,
    in_flight: AtomicUsize,
    cancellation: CancellationToken,
    drained: Notify,
}

impl DrainGate {
    /// Creates an open gate whose in-flight gauge is labelled with `provider`.
    pub(crate) fn new(provider: &'static str) -> Arc<Self> {
        Arc::new(Self {
            provider,
            accepting: AtomicBool::new(true),
            in_flight: AtomicUsize::new(0),
            cancellation: CancellationToken::new(),
            drained: Notify::new(),
        })
    }

    pub(crate) fn is_accepting(&self) -> bool {
        self.accepting.load(Ordering::Acquire)
    }

    pub(crate) fn in_flight(&self) -> usize {
        self.in_flight.load(Ordering::Acquire)
    }

    pub(crate) const fn cancellation(&self) -> &CancellationToken {
        &self.cancellation
    }

    /// Stops admitting work and cancels every in-flight operation.
    pub(crate) fn begin_shutdown(&self) {
        self.accepting.store(false, Ordering::Release);
        self.cancellation.cancel();
    }

    /// Waits until every admitted operation has left its guard, or `timeout` elapses.
    pub(crate) async fn drain(&self, timeout: Duration) -> Result<(), ProviderError> {
        let wait = async {
            loop {
                let notified = self.drained.notified();
                if self.in_flight() == 0 {
                    return;
                }
                notified.await;
            }
        };
        time::timeout(timeout, wait)
            .await
            .map_err(|_| ProviderError::new(FailureClass::Timeout))
    }

    /// Admits one operation, or fails with [`FailureClass::Draining`] once shutdown has begun.
    pub(crate) fn admit(self: &Arc<Self>) -> Result<InFlight, ProviderError> {
        if !self.is_accepting() {
            return Err(ProviderError::new(FailureClass::Draining));
        }
        self.in_flight.fetch_add(1, Ordering::AcqRel);
        gauge!("omnius_webhooks_svix_in_flight", "provider" => self.provider)
            .set(metric_count(self.in_flight()));
        let guard = InFlight {
            gate: Arc::clone(self),
        };
        // Shutdown may have begun between the first check and the increment; the guard's drop
        // then releases the slot.
        if !self.is_accepting() {
            return Err(ProviderError::new(FailureClass::Draining));
        }
        Ok(guard)
    }

    fn finish(&self) {
        let previous = self.in_flight.fetch_sub(1, Ordering::AcqRel);
        gauge!("omnius_webhooks_svix_in_flight", "provider" => self.provider)
            .set(metric_count(previous.saturating_sub(1)));
        if previous == 1 {
            self.drained.notify_waiters();
        }
    }
}

/// Guard for one admitted operation; dropping it releases the slot.
pub(crate) struct InFlight {
    gate: Arc<DrainGate>,
}

impl Drop for InFlight {
    fn drop(&mut self) {
        self.gate.finish();
    }
}

fn metric_count(value: usize) -> f64 {
    f64::from(u32::try_from(value).unwrap_or(u32::MAX))
}

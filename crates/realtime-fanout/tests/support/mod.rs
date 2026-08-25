use std::{
    future::{Future, ready},
    sync::{Arc, Mutex},
};

use rsk_realtime_core::{
    FanoutDeliveryIntent, FanoutIntentReservation, FanoutIntentSink, MAX_ENVELOPE_BYTES,
};
use thiserror::Error;

const MAX_COLLECTED_INTENTS: usize = 8;
const MAX_COLLECTED_BYTES: usize = MAX_COLLECTED_INTENTS * MAX_ENVELOPE_BYTES;

#[derive(Default)]
struct CollectingState {
    intents: Vec<FanoutDeliveryIntent>,
    reservations: usize,
    reserved_bytes: usize,
}

#[derive(Clone, Default)]
pub(crate) struct CollectingSink {
    state: Arc<Mutex<CollectingState>>,
}

impl CollectingSink {
    pub(crate) fn intents(&self) -> Vec<FanoutDeliveryIntent> {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .intents
            .clone()
    }
}

#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[error("test fan-out sink capacity is exhausted")]
pub(crate) struct CollectingSinkError;

pub(crate) struct CollectingReservation {
    state: Arc<Mutex<CollectingState>>,
    reserved_bytes: usize,
    released: bool,
}

impl Drop for CollectingReservation {
    fn drop(&mut self) {
        if !self.released {
            let mut state = self
                .state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            state.reservations = state.reservations.saturating_sub(1);
            state.reserved_bytes = state.reserved_bytes.saturating_sub(self.reserved_bytes);
        }
    }
}

impl FanoutIntentReservation for CollectingReservation {
    type Error = CollectingSinkError;

    fn admit(
        mut self,
        intent: FanoutDeliveryIntent,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send {
        let result = {
            let mut state = self
                .state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            state.reservations = state.reservations.saturating_sub(1);
            state.reserved_bytes = state.reserved_bytes.saturating_sub(self.reserved_bytes);
            if state.intents.len() >= MAX_COLLECTED_INTENTS {
                Err(CollectingSinkError)
            } else {
                state.intents.push(intent);
                Ok(())
            }
        };
        self.released = true;
        ready(result)
    }
}

impl FanoutIntentSink for CollectingSink {
    type Error = CollectingSinkError;
    type Reservation = CollectingReservation;

    fn reserve(
        &self,
        maximum_encoded_bytes: usize,
    ) -> impl Future<Output = Result<Self::Reservation, Self::Error>> + Send {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let next_bytes = state.reserved_bytes.saturating_add(maximum_encoded_bytes);
        if state.intents.len() + state.reservations >= MAX_COLLECTED_INTENTS
            || next_bytes > MAX_COLLECTED_BYTES
        {
            return ready(Err(CollectingSinkError));
        }
        state.reservations += 1;
        state.reserved_bytes = next_bytes;
        ready(Ok(CollectingReservation {
            state: Arc::clone(&self.state),
            reserved_bytes: maximum_encoded_bytes,
            released: false,
        }))
    }
}

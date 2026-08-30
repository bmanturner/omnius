//! Canonical request-local LLM stream state and bounded consumer delivery.
//!
//! Provider adapters emit typed payloads through [`LlmStreamAssembler`]. The
//! assembler owns sequence allocation, part correlation, terminal state, and
//! the public-content snapshot retained by interrupted streams. [`bounded_stream`]
//! provides the finite delivery boundary and propagates inherited cancellation
//! and absolute deadlines without treating durable consumer disconnects as job
//! cancellation.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

mod coalesce;
mod delivery;
mod event;

pub use coalesce::{BoundedTextCoalescer, TextCoalesceError};
pub use delivery::{
    ConsumerOwnership, DeliveryError, StreamReceiver, StreamSender, bounded_stream,
};
pub use event::{
    AcceptedPublicContent, LlmStreamAssembler, LlmStreamEvent, LlmStreamEventData,
    LlmStreamPayload, LlmStreamValidator, StreamBudgetDimension, StreamFailureKind,
    StreamInterruption, StreamInvariantError, StreamLimits, StreamMedia, StreamPartKind,
    StreamTerminal, StreamTerminalState, StreamToolCallDelta, StreamWarningCode,
    ValidatedStructuredComplete, ValidatedStructuredFinal,
};

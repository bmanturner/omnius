use std::{fmt, io, sync::Arc};

use bytes::Bytes;
use omnius_jobs_core::{
    EventId, EventMetadata, EventName, Source, Subject, TenantId, Traceparent, Version,
};
use omnius_outbox::LeasedOutboxEvent;
use serde::{Deserialize, Serialize};
use serde_json::value::RawValue;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::error::NatsEventsError;

#[derive(Deserialize)]
struct WireEvent {
    id: EventId,
    #[serde(rename = "type")]
    event_type: EventName,
    version: Version,
    source: Source,
    subject: Subject,
    tenant_id: Option<TenantId>,
    #[serde(with = "time::serde::rfc3339")]
    occurred_at: OffsetDateTime,
    correlation_id: Uuid,
    causation_id: Option<Uuid>,
    traceparent: Option<Traceparent>,
    data: Box<RawValue>,
    #[serde(default)]
    metadata: EventMetadata,
}

/// Validated immutable canonical event bytes and safe typed metadata.
#[derive(Clone)]
pub struct RawEvent(Arc<RawEventInner>);

struct RawEventInner {
    bytes: Bytes,
    id: EventId,
    event_type: EventName,
    version: Version,
    source: Source,
    subject: Subject,
    tenant_id: Option<TenantId>,
    occurred_at: OffsetDateTime,
    correlation_id: Uuid,
    causation_id: Option<Uuid>,
    traceparent: Option<Traceparent>,
    metadata: EventMetadata,
}

impl RawEvent {
    /// Validates bounded canonical event JSON received from `JetStream`.
    ///
    /// # Errors
    ///
    /// Returns a value-free error for oversized, malformed, non-object, or invalid envelope data.
    pub fn decode(bytes: Bytes, max_bytes: usize) -> Result<Self, NatsEventsError> {
        if bytes.is_empty() || bytes.len() > max_bytes {
            return Err(NatsEventsError::InvalidEvent);
        }
        let wire: WireEvent =
            serde_json::from_slice(&bytes).map_err(|_| NatsEventsError::InvalidEvent)?;
        validate_wire(&wire)?;
        Ok(Self::from_validated_wire(bytes, wire))
    }

    pub(crate) fn from_leased(
        event: &LeasedOutboxEvent,
        max_bytes: usize,
    ) -> Result<Self, NatsEventsError> {
        let stored_json = event.payload_json().get();
        if stored_json.len() > max_bytes {
            return Err(NatsEventsError::InvalidEvent);
        }
        let stored: WireEvent =
            serde_json::from_str(stored_json).map_err(|_| NatsEventsError::InvalidEvent)?;
        validate_wire(&stored)?;
        validate_stored_matches_lease(&stored, event)?;
        Ok(Self::from_validated_wire(
            Bytes::copy_from_slice(stored_json.as_bytes()),
            stored,
        ))
    }

    fn from_validated_wire(bytes: Bytes, wire: WireEvent) -> Self {
        Self(Arc::new(RawEventInner {
            bytes,
            id: wire.id,
            event_type: wire.event_type,
            version: wire.version,
            source: wire.source,
            subject: wire.subject,
            tenant_id: wire.tenant_id,
            occurred_at: wire.occurred_at,
            correlation_id: wire.correlation_id,
            causation_id: wire.causation_id,
            traceparent: wire.traceparent,
            metadata: wire.metadata,
        }))
    }

    /// Event identifier used for idempotency.
    #[must_use]
    pub fn id(&self) -> EventId {
        self.0.id
    }

    /// Stable event name.
    #[must_use]
    pub fn event_name(&self) -> &EventName {
        &self.0.event_type
    }

    /// Event schema version.
    #[must_use]
    pub fn version(&self) -> Version {
        self.0.version
    }

    /// Validated producer identity.
    #[must_use]
    pub fn source(&self) -> &Source {
        &self.0.source
    }

    /// Validated aggregate or resource subject metadata, distinct from the NATS route.
    #[must_use]
    pub fn subject(&self) -> &Subject {
        &self.0.subject
    }

    /// Optional validated tenant metadata.
    #[must_use]
    pub fn tenant_id(&self) -> Option<&TenantId> {
        self.0.tenant_id.as_ref()
    }

    /// Domain occurrence time.
    #[must_use]
    pub fn occurred_at(&self) -> OffsetDateTime {
        self.0.occurred_at
    }

    /// Correlation identifier.
    #[must_use]
    pub fn correlation_id(&self) -> Uuid {
        self.0.correlation_id
    }

    /// Optional causation identifier.
    #[must_use]
    pub fn causation_id(&self) -> Option<Uuid> {
        self.0.causation_id
    }

    /// Optional validated W3C trace context.
    #[must_use]
    pub fn traceparent(&self) -> Option<&Traceparent> {
        self.0.traceparent.as_ref()
    }

    /// Validated additive event metadata.
    #[must_use]
    pub fn metadata(&self) -> &EventMetadata {
        &self.0.metadata
    }

    /// Exact canonical event bytes.
    #[must_use]
    pub fn canonical_bytes(&self) -> &[u8] {
        &self.0.bytes
    }

    pub(crate) fn bytes(&self) -> Bytes {
        self.0.bytes.clone()
    }

    pub(crate) fn raw_json(&self) -> Result<&RawValue, NatsEventsError> {
        serde_json::from_slice(&self.0.bytes).map_err(|_| NatsEventsError::InvalidEvent)
    }
}

impl fmt::Debug for RawEvent {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RawEvent")
            .field("id", &self.0.id)
            .field("event_type", &self.0.event_type)
            .field("version", &self.0.version)
            .field("byte_len", &self.0.bytes.len())
            .field("payload", &"[REDACTED]")
            .finish_non_exhaustive()
    }
}

fn validate_wire(wire: &WireEvent) -> Result<(), NatsEventsError> {
    if wire.data.get().as_bytes().first() != Some(&b'{')
        || wire.correlation_id.get_version_num() != 7
        || wire
            .causation_id
            .is_some_and(|value| value.get_version_num() != 7)
    {
        return Err(NatsEventsError::InvalidEvent);
    }
    Ok(())
}

fn validate_stored_matches_lease(
    stored: &WireEvent,
    leased: &LeasedOutboxEvent,
) -> Result<(), NatsEventsError> {
    let tenant_matches = match (&stored.tenant_id, leased.tenant_id()) {
        (None, None) => true,
        (Some(stored), Some(leased)) => stored.as_str() == leased.to_string(),
        _ => false,
    };
    let trace_matches =
        stored.traceparent.as_ref().map(Traceparent::as_str) == leased.traceparent();
    let timestamp_difference = (stored.occurred_at.unix_timestamp_nanos()
        - leased.occurred_at().unix_timestamp_nanos())
    .unsigned_abs();
    if stored.id != leased.id()
        || stored.event_type.as_str() != leased.event_type()
        || stored.version.get() != leased.event_version()
        || stored.source.as_str() != leased.source()
        || stored.subject.as_str() != leased.subject()
        || !tenant_matches
        || timestamp_difference > 999
        || stored.correlation_id != leased.correlation_id()
        || stored.causation_id != leased.causation_id()
        || !trace_matches
    {
        return Err(NatsEventsError::InvalidEvent);
    }
    Ok(())
}

pub(crate) fn encode_bounded<T: Serialize>(
    value: &T,
    maximum: usize,
) -> Result<Vec<u8>, NatsEventsError> {
    let mut writer = BoundedWriter {
        bytes: Vec::with_capacity(maximum.min(4_096)),
        maximum,
    };
    serde_json::to_writer(&mut writer, value).map_err(|_| NatsEventsError::InvalidEvent)?;
    Ok(writer.bytes)
}

struct BoundedWriter {
    bytes: Vec<u8>,
    maximum: usize,
}

impl io::Write for BoundedWriter {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        let next = self
            .bytes
            .len()
            .checked_add(buffer.len())
            .ok_or_else(|| io::Error::other("bounded event encoding failed"))?;
        if next > self.maximum {
            return Err(io::Error::other("bounded event encoding failed"));
        }
        self.bytes.extend_from_slice(buffer);
        Ok(buffer.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

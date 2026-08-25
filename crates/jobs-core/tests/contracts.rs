//! Observable contracts for typed at-least-once jobs and versioned domain events.

use std::{
    error::Error,
    io,
    sync::{Arc, Mutex},
};

use futures::{FutureExt as _, executor::block_on, future::BoxFuture};
use rsk_jobs_core::{
    CapturingJobEnqueuer, CompatibilityPolicy, DeadLetterPolicy, DeliveryContext, DomainEvent,
    EncodedJobEnvelope, EnqueueError, EnqueueReceipt, EnvelopeError, EventEnvelope,
    EventEnvelopeOptions, EventLimits, EventMetadata, HandlerOutcome, IdempotencyKey,
    IdempotencyRequirement, Jitter, Job, JobEnqueuerExt as _, JobEnvelope, JobEnvelopeOptions,
    JobHandler as _, JobId, JobPolicy, MetadataKey, QueueName, Source, Subject, TenantId,
    TypedJobHandler, TypedJobHandlerAdapter,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use time::{Duration, OffsetDateTime};
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

const TEST_POLICY: JobPolicy = match JobPolicy::new(
    IdempotencyRequirement::Required,
    3,
    10,
    1_000,
    2,
    Jitter::Full,
    30,
    4,
    Some(120),
    "critical",
    5,
    86_400,
    DeadLetterPolicy::Retain,
    CompatibilityPolicy::Exact,
    1_024,
) {
    Ok(policy) => policy,
    Err(_) => panic!("test policy must be valid"),
};

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
struct SendEmail {
    account_id: Uuid,
    body: String,
}

impl Job for SendEmail {
    const NAME: &'static str = "email.send";
    const VERSION: u16 = 1;
    const POLICY: JobPolicy = TEST_POLICY;
    const METRICS_PREFIX: &'static str = "rsk_job_email_send";
    const RUNBOOK: &'static str = "runbooks/email-send";
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
struct EmailVerified {
    account_id: Uuid,
}

impl DomainEvent for EmailVerified {
    const NAME: &'static str = "account.email_verified.v1";
    const VERSION: u16 = 1;
}

fn job() -> Result<JobEnvelope<SendEmail>, Box<dyn Error>> {
    let options = JobEnvelopeOptions::new(Uuid::now_v7())?
        .with_idempotency_key(IdempotencyKey::try_from("account-email-verification-1")?);
    Ok(JobEnvelope::new(
        SendEmail {
            account_id: Uuid::now_v7(),
            body: "sensitive body".to_owned(),
        },
        options,
    )?)
}

#[test]
fn typed_job_round_trips_and_rejects_declaration_mismatch() -> Result<(), Box<dyn Error>> {
    let envelope = job()?;
    let encoded = envelope.encode()?;
    assert_eq!(encoded.decode::<SendEmail>()?.payload(), envelope.payload());

    let mut oversized_wire: Value = serde_json::from_slice(encoded.bytes())?;
    oversized_wire["payload"]["ignored"] = json!("x".repeat(2_000));
    assert!(JobEnvelope::<SendEmail>::decode(&serde_json::to_vec(&oversized_wire)?).is_err());

    let mut wire: Value = serde_json::from_slice(encoded.bytes())?;
    wire["type"] = json!("email.other");
    assert!(JobEnvelope::<SendEmail>::decode(&serde_json::to_vec(&wire)?).is_err());

    let diagnostics = format!("{envelope:?} {encoded:?}");
    assert!(!diagnostics.contains("sensitive body"));
    assert!(diagnostics.contains("REDACTED"));
    Ok(())
}

#[test]
fn canonical_event_wire_preserves_bounded_metadata_and_ignores_additions()
-> Result<(), Box<dyn Error>> {
    let mut metadata = EventMetadata::new();
    metadata.insert(MetadataKey::try_from("schema")?, json!(EmailVerified::NAME))?;
    let options = EventEnvelopeOptions::new(
        Source::try_from("example-service")?,
        Subject::try_from(format!("account/{}", Uuid::now_v7()))?,
        Uuid::now_v7(),
    )?
    .with_metadata(metadata);
    let event = EventEnvelope::new(
        EmailVerified {
            account_id: Uuid::now_v7(),
        },
        options,
        EventLimits::default(),
    )?;
    let mut wire: Value = serde_json::from_slice(&event.encode(EventLimits::default())?)?;

    assert_eq!(wire["type"], EmailVerified::NAME);
    assert_eq!(wire["version"], 1);
    assert!(wire.get("id").is_some());
    assert!(wire.get("occurred_at").is_some());
    assert!(wire.get("correlation_id").is_some());
    assert_eq!(wire["metadata"]["schema"], EmailVerified::NAME);
    wire["future_optional_field"] = json!({"ignored": true});

    let decoded = EventEnvelope::<EmailVerified>::decode(
        &serde_json::to_vec(&wire)?,
        EventLimits::default(),
    )?;
    assert_eq!(decoded.data(), event.data());
    assert_eq!(decoded.metadata(), event.metadata());

    wire.as_object_mut()
        .ok_or_else(|| io::Error::other("event wire must be an object"))?
        .remove("metadata");
    let without_metadata = EventEnvelope::<EmailVerified>::decode(
        &serde_json::to_vec(&wire)?,
        EventLimits::default(),
    )?;
    assert!(without_metadata.metadata().is_empty());
    Ok(())
}

#[test]
fn invalid_policy_and_unbounded_metadata_are_rejected() -> Result<(), Box<dyn Error>> {
    assert!(
        JobPolicy::new(
            IdempotencyRequirement::Optional,
            0,
            10,
            100,
            2,
            Jitter::Equal,
            30,
            1,
            None,
            "default",
            0,
            60,
            DeadLetterPolicy::Retain,
            CompatibilityPolicy::Exact,
            10,
        )
        .is_err()
    );

    let mut metadata = EventMetadata::new();
    let oversized = "x".repeat(rsk_jobs_core::limits::METADATA_BYTES + 1);
    assert!(
        metadata
            .insert(MetadataKey::try_from("too_large")?, json!(oversized))
            .is_err()
    );
    assert!(metadata.is_empty());

    let mut nested = Value::Null;
    for _ in 0..=rsk_jobs_core::limits::METADATA_DEPTH {
        nested = json!([nested]);
    }
    assert!(
        metadata
            .insert(MetadataKey::try_from("too_deep")?, nested)
            .is_err()
    );
    assert!(metadata.is_empty());
    Ok(())
}

#[test]
fn tenant_id_requires_canonical_uuid_v7_wire_shape() {
    let uuid_v7 = Uuid::now_v7().to_string();
    assert!(TenantId::try_from(uuid_v7.as_str()).is_ok());
    assert!(TenantId::try_from("tenant-1").is_err());
    assert!(TenantId::try_from(Uuid::nil().to_string()).is_err());
    assert!(TenantId::try_from(uuid_v7.to_uppercase()).is_err());
    assert!(TenantId::try_from(uuid_v7.replace('-', "")).is_err());
}

#[test]
fn provider_can_construct_enqueue_receipt() -> Result<(), Box<dyn Error>> {
    let job_id = JobId::new();
    let queue = QueueName::try_from("critical")?;
    let accepted_at = OffsetDateTime::now_utc();
    let receipt = EnqueueReceipt::new(job_id, queue.clone(), accepted_at);

    assert_eq!(receipt.job_id(), job_id);
    assert_eq!(receipt.queue(), &queue);
    assert_eq!(receipt.accepted_at(), accepted_at);
    Ok(())
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ObservedContext {
    tenant: TenantId,
    correlation: Uuid,
    causation: Option<Uuid>,
}

#[derive(Clone)]
struct ContextRecordingHandler {
    observed: Arc<Mutex<Option<ObservedContext>>>,
}

impl TypedJobHandler<SendEmail> for ContextRecordingHandler {
    fn handle(&self, _job: SendEmail, context: DeliveryContext) -> BoxFuture<'_, HandlerOutcome> {
        async move {
            let Some(tenant_id) = context.tenant_id().cloned() else {
                return HandlerOutcome::Cancelled;
            };
            let Ok(mut observed) = self.observed.lock() else {
                return HandlerOutcome::Cancelled;
            };
            *observed = Some(ObservedContext {
                tenant: tenant_id,
                correlation: context.correlation_id(),
                causation: context.causation_id(),
            });
            HandlerOutcome::Succeeded
        }
        .boxed()
    }
}

#[test]
fn durable_restore_preserves_identity_policy_tenant_and_causal_context()
-> Result<(), Box<dyn Error>> {
    let tenant_id = TenantId::try_from(Uuid::now_v7().to_string())?;
    let correlation_id = Uuid::now_v7();
    let causation_id = Uuid::now_v7();
    let not_before = OffsetDateTime::now_utc() + Duration::seconds(5);
    let options = JobEnvelopeOptions::new(correlation_id)?
        .with_tenant(tenant_id.clone())
        .with_not_before(not_before)
        .with_causation(causation_id)?
        .with_idempotency_key(IdempotencyKey::try_from("durable-email-1")?);
    let encoded = JobEnvelope::new(
        SendEmail {
            account_id: Uuid::now_v7(),
            body: "sensitive durable body".to_owned(),
        },
        options,
    )?
    .encode()?;
    let restored = EncodedJobEnvelope::restore(encoded.bytes(), encoded.queue().clone())?;

    assert_eq!(restored.bytes(), encoded.bytes());
    assert_eq!(restored.id(), encoded.id());
    assert_eq!(restored.job_name(), encoded.job_name());
    assert_eq!(restored.version(), encoded.version());
    assert_eq!(restored.queue(), encoded.queue());
    assert_eq!(restored.tenant_id(), Some(&tenant_id));
    assert_eq!(restored.created_at(), encoded.created_at());
    assert_eq!(restored.not_before(), Some(not_before));
    assert_eq!(restored.correlation_id(), correlation_id);
    assert_eq!(restored.causation_id(), Some(causation_id));
    assert_eq!(restored.idempotency_key(), encoded.idempotency_key());
    assert_eq!(restored.attempt_policy(), encoded.attempt_policy());
    assert_eq!(restored.attempt_policy().max_attempts(), 3);
    assert_eq!(restored.attempt_policy().timeout().as_secs(), 30);

    let deadline = OffsetDateTime::now_utc() + Duration::seconds(30);
    let original_context =
        DeliveryContext::from_envelope(&encoded, 1, CancellationToken::new(), deadline)?;
    let restored_context =
        DeliveryContext::from_envelope(&restored, 1, CancellationToken::new(), deadline)?;
    assert_eq!(
        restored_context.effect_identity(),
        original_context.effect_identity()
    );
    assert_eq!(restored_context.tenant_id(), Some(&tenant_id));
    assert_eq!(restored_context.correlation_id(), correlation_id);
    assert_eq!(restored_context.causation_id(), Some(causation_id));
    assert!(
        DeliveryContext::from_envelope(&restored, 4, CancellationToken::new(), deadline,).is_err()
    );

    let observed = Arc::new(Mutex::new(None));
    let handler = TypedJobHandlerAdapter::<SendEmail, _>::new(ContextRecordingHandler {
        observed: Arc::clone(&observed),
    });
    assert_eq!(
        block_on(handler.handle(restored, restored_context)),
        HandlerOutcome::Succeeded
    );
    assert_eq!(
        *observed
            .lock()
            .map_err(|_| io::Error::other("context handler state poisoned"))?,
        Some(ObservedContext {
            tenant: tenant_id,
            correlation: correlation_id,
            causation: Some(causation_id),
        })
    );
    Ok(())
}

#[test]
fn durable_restore_rejects_malformed_or_unbounded_headers() -> Result<(), Box<dyn Error>> {
    let encoded = job()?.encode()?;
    let queue = encoded.queue().clone();
    let mut wire: Value = serde_json::from_slice(encoded.bytes())?;

    wire["attempt_policy"]["max_attempts"] = json!(0);
    assert!(EncodedJobEnvelope::restore(&serde_json::to_vec(&wire)?, queue.clone()).is_err());

    wire["attempt_policy"]["max_attempts"] = json!(3);
    wire["correlation_id"] = json!(Uuid::nil());
    assert!(EncodedJobEnvelope::restore(&serde_json::to_vec(&wire)?, queue.clone()).is_err());

    wire["correlation_id"] = json!(Uuid::now_v7());
    wire["causation_id"] = json!(Uuid::nil());
    assert!(EncodedJobEnvelope::restore(&serde_json::to_vec(&wire)?, queue.clone()).is_err());

    wire["causation_id"] = Value::Null;
    wire["id"] = json!(Uuid::nil());
    assert!(EncodedJobEnvelope::restore(&serde_json::to_vec(&wire)?, queue.clone()).is_err());

    wire["id"] = json!(Uuid::now_v7());
    wire["type"] = json!("Invalid Name");
    assert!(EncodedJobEnvelope::restore(&serde_json::to_vec(&wire)?, queue.clone()).is_err());

    wire["type"] = json!(SendEmail::NAME);
    wire["version"] = json!(0);
    assert!(EncodedJobEnvelope::restore(&serde_json::to_vec(&wire)?, queue.clone()).is_err());

    wire["version"] = json!(SendEmail::VERSION);
    wire["tenant_id"] = json!("tenant-1");
    assert!(EncodedJobEnvelope::restore(&serde_json::to_vec(&wire)?, queue.clone()).is_err());

    wire["tenant_id"] = Value::Null;
    wire["idempotency_key"] = json!("");
    assert!(EncodedJobEnvelope::restore(&serde_json::to_vec(&wire)?, queue.clone()).is_err());

    wire["idempotency_key"] = json!("account-email-verification-1");
    wire.as_object_mut()
        .ok_or_else(|| io::Error::other("job wire must be an object"))?
        .remove("payload");
    assert!(EncodedJobEnvelope::restore(&serde_json::to_vec(&wire)?, queue.clone()).is_err());

    let oversized = vec![b' '; rsk_jobs_core::limits::ENVELOPE_BYTES + 1];
    assert!(matches!(
        EncodedJobEnvelope::restore(&oversized, queue),
        Err(EnvelopeError::EnvelopeTooLarge)
    ));
    Ok(())
}

#[test]
fn capturing_enqueuer_is_bounded_and_preserves_acceptance_order() -> Result<(), Box<dyn Error>> {
    let first = job()?;
    let second = job()?;
    let capture = CapturingJobEnqueuer::new(1)?;
    let first_id = first.id();

    let receipt = block_on(capture.enqueue_typed(&first))?;
    assert_eq!(receipt.job_id(), first_id);
    assert_eq!(capture.len()?, 1);
    assert_eq!(
        block_on(capture.enqueue_typed(&second)),
        Err(EnqueueError::Capacity)
    );
    assert_eq!(capture.drain()?[0].id(), first_id);
    assert!(capture.is_empty()?);
    Ok(())
}

#[derive(Clone, Default)]
struct RecordingHandler {
    identities: Arc<Mutex<Vec<rsk_jobs_core::EffectIdentity>>>,
}

impl TypedJobHandler<SendEmail> for RecordingHandler {
    fn handle(&self, _job: SendEmail, context: DeliveryContext) -> BoxFuture<'_, HandlerOutcome> {
        async move {
            let Ok(mut identities) = self.identities.lock() else {
                return HandlerOutcome::Cancelled;
            };
            identities.push(context.effect_identity().clone());
            HandlerOutcome::Succeeded
        }
        .boxed()
    }
}

#[test]
fn redelivery_reuses_effect_identity_and_cancellation_is_explicit() -> Result<(), Box<dyn Error>> {
    let encoded = job()?.encode()?;
    let identities = Arc::new(Mutex::new(Vec::new()));
    let handler = TypedJobHandlerAdapter::<SendEmail, _>::new(RecordingHandler {
        identities: Arc::clone(&identities),
    });
    let deadline = OffsetDateTime::now_utc() + Duration::seconds(30);
    let first = DeliveryContext::from_envelope(&encoded, 1, CancellationToken::new(), deadline)?;
    let second = DeliveryContext::from_envelope(&encoded, 2, CancellationToken::new(), deadline)?;

    assert_eq!(
        block_on(handler.handle(encoded.clone(), first)),
        HandlerOutcome::Succeeded
    );
    assert_eq!(
        block_on(handler.handle(encoded.clone(), second)),
        HandlerOutcome::Succeeded
    );
    let identities = identities
        .lock()
        .map_err(|_| io::Error::other("recording handler state poisoned"))?
        .clone();
    assert_eq!(identities.len(), 2);
    assert_eq!(identities[0], identities[1]);

    let independently_enqueued = job()?.encode()?;
    assert_ne!(encoded.id(), independently_enqueued.id());
    let independent_context = DeliveryContext::from_envelope(
        &independently_enqueued,
        1,
        CancellationToken::new(),
        deadline,
    )?;
    assert_eq!(&identities[0], independent_context.effect_identity());

    let cancelled = CancellationToken::new();
    cancelled.cancel();
    let context = DeliveryContext::from_envelope(&encoded, 3, cancelled, deadline)?;
    assert_eq!(
        block_on(handler.handle(encoded, context)),
        HandlerOutcome::Cancelled
    );
    Ok(())
}

use std::{
    fmt,
    str::FromStr as _,
    sync::{
        Arc, Mutex, MutexGuard,
        atomic::{AtomicU8, AtomicUsize, Ordering},
    },
};

use futures::future::BoxFuture;
use lettre::{
    Address, Message,
    message::{
        Attachment as LettreAttachment, Mailbox, MultiPart, SinglePart,
        header::{ContentType, HeaderName, HeaderValue},
    },
};
use rsk_config::DeploymentEnvironment;
use rsk_jobs_core::IdempotencyKey;
use serde::{Deserialize, Serialize};
use tokio::sync::Semaphore;
use tokio_util::sync::CancellationToken;

use crate::{
    CapturingMailSink, ClientMessageId, DeliveryFailureClass, EmailConfig, EmailError, EmailLimits,
    MailboxAddress, ProviderKind, ProviderMessageId, RenderedEmail, SendEmailRequest,
    TemplateRegistry,
    transport::{MailTransport, PreparedMessage, build_transport},
    value::SendEmailParts,
};

const READY: u8 = 0;
const DEGRADED: u8 = 1;
const DRAINING: u8 = 2;
const SHUTDOWN: u8 = 3;

/// Honest SMTP delivery guarantee. A caller idempotency key cannot make SMTP exactly-once.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum DeliveryGuarantee {
    /// An accepted attempt may be repeated after an ambiguous at-least-once job failure.
    AtLeastOnce,
}

/// Successful submission identity returned to the caller.
#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SendReceipt {
    idempotency_key: IdempotencyKey,
    client_message_id: ClientMessageId,
    provider_message_id: Option<ProviderMessageId>,
    guarantee: DeliveryGuarantee,
}

impl SendReceipt {
    /// Caller-supplied key used to correlate duplicate-safe application state.
    #[must_use]
    pub const fn idempotency_key(&self) -> &IdempotencyKey {
        &self.idempotency_key
    }

    /// Persisted opaque RFC Message-ID supplied when the durable effect was created.
    #[must_use]
    pub const fn client_message_id(&self) -> &ClientMessageId {
        &self.client_message_id
    }

    /// Provider-issued message ID when the SMTP response supplied one in a safe structured form.
    #[must_use]
    pub const fn provider_message_id(&self) -> Option<&ProviderMessageId> {
        self.provider_message_id.as_ref()
    }

    /// Explicit at-least-once delivery guarantee.
    #[must_use]
    pub const fn guarantee(&self) -> DeliveryGuarantee {
        self.guarantee
    }

    /// Builds an accepted typed delivery event without bodies, addresses, headers, or context.
    #[must_use]
    pub fn delivery_event(&self) -> DeliveryEvent {
        DeliveryEvent {
            idempotency_key: self.idempotency_key.clone(),
            client_message_id: Some(self.client_message_id.clone()),
            provider_message_id: self.provider_message_id.clone(),
            outcome: DeliveryEventOutcome::Accepted,
        }
    }
}

impl fmt::Debug for SendReceipt {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SendReceipt")
            .field("idempotency_key", &"[REDACTED]")
            .field("client_message_id", &"[REDACTED]")
            .field(
                "has_provider_message_id",
                &self.provider_message_id.is_some(),
            )
            .field("guarantee", &self.guarantee)
            .finish_non_exhaustive()
    }
}

/// Fixed-cardinality delivery-event outcome.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum DeliveryEventOutcome {
    /// Provider accepted the submission.
    Accepted,
    /// The attempt failed and can be retried within caller policy.
    RetryableFailure,
    /// The attempt failed permanently.
    PermanentFailure,
    /// Delivery was cooperatively cancelled.
    Cancelled,
}

/// Safe delivery event for durable publication by caller-owned outbox composition.
#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DeliveryEvent {
    idempotency_key: IdempotencyKey,
    client_message_id: Option<ClientMessageId>,
    provider_message_id: Option<ProviderMessageId>,
    outcome: DeliveryEventOutcome,
}

impl DeliveryEvent {
    /// Creates a failed event without retaining error text or message data.
    #[must_use]
    pub fn failed(idempotency_key: IdempotencyKey, error: EmailError) -> Self {
        let outcome = match error {
            EmailError::Cancelled => DeliveryEventOutcome::Cancelled,
            EmailError::Timeout
            | EmailError::Capacity
            | EmailError::AdmissionClosed
            | EmailError::Delivery(
                DeliveryFailureClass::Transient
                | DeliveryFailureClass::Timeout
                | DeliveryFailureClass::Unavailable,
            ) => DeliveryEventOutcome::RetryableFailure,
            _ => DeliveryEventOutcome::PermanentFailure,
        };
        Self {
            idempotency_key,
            client_message_id: None,
            provider_message_id: None,
            outcome,
        }
    }

    /// Caller idempotency identity.
    #[must_use]
    pub const fn idempotency_key(&self) -> &IdempotencyKey {
        &self.idempotency_key
    }

    /// Client message identity, available after message construction and successful submission.
    #[must_use]
    pub const fn client_message_id(&self) -> Option<&ClientMessageId> {
        self.client_message_id.as_ref()
    }

    /// Provider message identity, when supplied by the provider.
    #[must_use]
    pub const fn provider_message_id(&self) -> Option<&ProviderMessageId> {
        self.provider_message_id.as_ref()
    }

    /// Fixed event outcome.
    #[must_use]
    pub const fn outcome(&self) -> DeliveryEventOutcome {
        self.outcome
    }
}

impl fmt::Debug for DeliveryEvent {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DeliveryEvent")
            .field("idempotency_key", &"[REDACTED]")
            .field("client_message_id", &"[REDACTED]")
            .field("provider_message_id", &"[REDACTED]")
            .field("outcome", &self.outcome)
            .finish_non_exhaustive()
    }
}

/// Provider bounce retry meaning as supplied by a verified callback adapter.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum ProviderBounceClass {
    /// A later retry may succeed.
    Transient,
    /// The provider considers the recipient failure terminal.
    Permanent,
    /// The provider did not supply a trustworthy retry classification.
    Undetermined,
}

/// Typed asynchronous provider outcome, distinct from SMTP submission acceptance.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "event", rename_all = "kebab-case", deny_unknown_fields)]
pub enum ProviderDeliveryEventKind {
    /// The provider reports final delivery.
    Delivered,
    /// The provider reports a bounce.
    Bounce {
        /// Provider-supplied retry meaning.
        classification: ProviderBounceClass,
    },
    /// The provider reports a recipient complaint.
    Complaint,
}

/// Value-safe event produced by a provider callback adapter after signature verification.
#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderDeliveryEvent {
    event_id: ProviderMessageId,
    provider_message_id: ProviderMessageId,
    occurred_at_unix_ms: i64,
    kind: ProviderDeliveryEventKind,
}

impl ProviderDeliveryEvent {
    /// Creates a verified provider event without provider response text or recipient data.
    #[must_use]
    pub const fn new(
        event_id: ProviderMessageId,
        provider_message_id: ProviderMessageId,
        occurred_at_unix_ms: i64,
        kind: ProviderDeliveryEventKind,
    ) -> Self {
        Self {
            event_id,
            provider_message_id,
            occurred_at_unix_ms,
            kind,
        }
    }

    /// Provider event identity for callback deduplication.
    #[must_use]
    pub const fn event_id(&self) -> &ProviderMessageId {
        &self.event_id
    }

    /// Provider message identity correlated with the submission receipt.
    #[must_use]
    pub const fn provider_message_id(&self) -> &ProviderMessageId {
        &self.provider_message_id
    }

    /// Provider occurrence time as Unix epoch milliseconds.
    #[must_use]
    pub const fn occurred_at_unix_ms(&self) -> i64 {
        self.occurred_at_unix_ms
    }

    /// Typed provider outcome.
    #[must_use]
    pub const fn kind(&self) -> ProviderDeliveryEventKind {
        self.kind
    }
}

impl fmt::Debug for ProviderDeliveryEvent {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProviderDeliveryEvent")
            .field("event_id", &"[REDACTED]")
            .field("provider_message_id", &"[REDACTED]")
            .field("occurred_at_unix_ms", &self.occurred_at_unix_ms)
            .field("kind", &self.kind)
            .finish_non_exhaustive()
    }
}

/// Narrow async application port for one validated template delivery.
pub trait MailSender: Send + Sync {
    /// Renders, builds, and submits one email.
    ///
    /// # Errors
    ///
    /// Returns only stable, value-free validation, rendering, lifecycle, deadline, or provider
    /// errors. The future owns the request so dropping it cancels the attempt.
    fn send(&self, request: SendEmailRequest) -> BoxFuture<'_, Result<SendReceipt, EmailError>>;
}

/// Safe provider lifecycle state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProviderLifecycle {
    /// Provider is operational and accepting new sends.
    Ready,
    /// A provider attempt failed but new sends are still admitted.
    Degraded,
    /// New sends are rejected while admitted attempts finish or cancel.
    Draining,
    /// Provider transport is terminally shut down.
    Shutdown,
}

/// Value-free provider status with only fixed-cardinality fields.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EmailStatus {
    /// Configured provider kind.
    pub provider: ProviderKind,
    /// Current lifecycle state.
    pub lifecycle: ProviderLifecycle,
    /// Attempts currently admitted by this service instance.
    pub active_sends: usize,
}

struct Inner {
    transport: Arc<dyn MailTransport>,
    capture: Option<CapturingMailSink>,
    templates: TemplateRegistry,
    limits: EmailLimits,
    provider: ProviderKind,
    custom_headers: crate::CustomHeaderPolicy,
    admission: Mutex<()>,
    capacity: Arc<Semaphore>,
    lifecycle: AtomicU8,
    active_sends: Arc<AtomicUsize>,
    shutdown: CancellationToken,
}

/// Concrete bounded template-and-provider email service.
#[derive(Clone)]
pub struct EmailService {
    inner: Arc<Inner>,
}

impl EmailService {
    /// Validates configuration, eagerly loads trusted templates, and builds the selected provider.
    ///
    /// SMTP construction exclusively uses lettre's implicit-TLS or required-STARTTLS builders.
    /// The capture provider is rejected outside [`DeploymentEnvironment::Test`].
    ///
    /// # Errors
    ///
    /// Returns a stable configuration or template-registry failure.
    pub fn build(
        config: EmailConfig,
        environment: DeploymentEnvironment,
    ) -> Result<Self, EmailError> {
        config.validate(environment)?;
        let templates = TemplateRegistry::load(&config.templates, config.limits)?;
        let max_in_flight = usize::from(config.limits.max_in_flight);
        let custom_headers = config.custom_headers;
        let bundle = build_transport(config.provider)?;
        Ok(Self {
            inner: Arc::new(Inner {
                transport: bundle.transport,
                capture: bundle.capture,
                templates,
                limits: config.limits,
                provider: bundle.kind,
                custom_headers,
                admission: Mutex::new(()),
                capacity: Arc::new(Semaphore::new(max_in_flight)),
                lifecycle: AtomicU8::new(READY),
                active_sends: Arc::new(AtomicUsize::new(0)),
                shutdown: CancellationToken::new(),
            }),
        })
    }

    /// Safe current provider status.
    #[must_use]
    pub fn status(&self) -> EmailStatus {
        let lifecycle = match self.inner.lifecycle.load(Ordering::Acquire) {
            READY => ProviderLifecycle::Ready,
            DEGRADED => ProviderLifecycle::Degraded,
            DRAINING => ProviderLifecycle::Draining,
            _ => ProviderLifecycle::Shutdown,
        };
        EmailStatus {
            provider: self.inner.provider,
            lifecycle,
            active_sends: self.inner.active_sends.load(Ordering::Acquire),
        }
    }

    /// Immutable eager template registry used by preview and lint tooling.
    #[must_use]
    pub fn templates(&self) -> &TemplateRegistry {
        &self.inner.templates
    }

    /// Returns the semantic capture fixture only for a capture-configured test service.
    #[must_use]
    pub fn capturing_sink(&self) -> Option<CapturingMailSink> {
        self.inner.capture.clone()
    }

    /// Stops admission of new sends while already admitted attempts retain their deadline.
    pub fn begin_drain(&self) {
        let _admission = lock_admission(&self.inner);
        self.inner.lifecycle.fetch_max(DRAINING, Ordering::AcqRel);
        self.inner.capacity.close();
    }

    /// Cancels admitted attempts, terminally closes admission, and shuts down the provider pool.
    pub async fn shutdown(&self) {
        {
            let _admission = lock_admission(&self.inner);
            self.inner.lifecycle.fetch_max(SHUTDOWN, Ordering::AcqRel);
            self.inner.capacity.close();
        }
        self.inner.shutdown.cancel();
        self.inner.transport.shutdown().await;
    }

    /// Runs a bounded value-free provider connection probe.
    ///
    /// # Errors
    ///
    /// Returns stable lifecycle, timeout, cancellation, or provider classification only.
    pub async fn test_connection(&self) -> Result<(), EmailError> {
        if self.inner.lifecycle.load(Ordering::Acquire) >= DRAINING {
            return Err(EmailError::AdmissionClosed);
        }
        let result = tokio::select! {
            () = self.inner.shutdown.cancelled() => Err(EmailError::Cancelled),
            result = tokio::time::timeout(
                self.inner.limits.operation_timeout,
                self.inner.transport.test_connection(),
            ) => match result {
                Ok(Ok(())) => Ok(()),
                Ok(Err(error)) => Err(EmailError::Delivery(error.class)),
                Err(_) => Err(EmailError::Timeout),
            },
        };
        self.record(
            "health",
            match &result {
                Ok(()) => Ok(()),
                Err(error) => Err(*error),
            },
        );
        result
    }

    async fn send_inner(&self, request: SendEmailRequest) -> Result<SendReceipt, EmailError> {
        let (permit, active) = {
            let _admission = lock_admission(&self.inner);
            if self.inner.lifecycle.load(Ordering::Acquire) >= DRAINING {
                return Err(EmailError::AdmissionClosed);
            }
            let permit = Arc::clone(&self.inner.capacity)
                .try_acquire_owned()
                .map_err(|_| EmailError::Capacity)?;
            self.inner.active_sends.fetch_add(1, Ordering::AcqRel);
            let active = ActiveSend(Arc::clone(&self.inner.active_sends));
            (permit, active)
        };
        let preparation_cancellation = CancellationToken::new();
        let _cancel_preparation = CancelPreparationOnDrop(preparation_cancellation.clone());

        let templates = self.inner.templates.clone();
        let limits = self.inner.limits;
        let operation_timeout = limits.operation_timeout;
        let transport = Arc::clone(&self.inner.transport);
        let custom_headers = self.inner.custom_headers.clone();
        let shutdown_wait = self.inner.shutdown.clone();
        let preparation_shutdown = self.inner.shutdown.clone();
        let preparation_attempt_cancellation = preparation_cancellation.clone();
        let operation_shutdown = self.inner.shutdown.clone();
        let operation = async move {
            let (prepared, permit, active) = tokio::task::spawn_blocking(move || {
                let prepared = if preparation_shutdown.is_cancelled()
                    || preparation_attempt_cancellation.is_cancelled()
                {
                    Err(EmailError::Cancelled)
                } else {
                    prepare_message(&templates, limits, &custom_headers, request)
                };
                let prepared = if preparation_shutdown.is_cancelled()
                    || preparation_attempt_cancellation.is_cancelled()
                {
                    Err(EmailError::Cancelled)
                } else {
                    prepared
                };
                (prepared, permit, active)
            })
            .await
            .map_err(|_| EmailError::Delivery(DeliveryFailureClass::Unavailable))?;
            let (idempotency_key, client_message_id, message) = prepared?;
            if operation_shutdown.is_cancelled() {
                return Err(EmailError::Cancelled);
            }
            let prepared = PreparedMessage {
                message,
                client_message_id: client_message_id.clone(),
            };
            let provider = transport
                .send(prepared)
                .await
                .map_err(|error| EmailError::Delivery(error.class))?;
            let receipt = SendReceipt {
                idempotency_key,
                client_message_id,
                provider_message_id: provider.provider_message_id,
                guarantee: DeliveryGuarantee::AtLeastOnce,
            };
            drop((permit, active));
            Ok(receipt)
        };

        tokio::select! {
            () = shutdown_wait.cancelled() => Err(EmailError::Cancelled),
            result = tokio::time::timeout(operation_timeout, operation) => {
                result.map_err(|_| EmailError::Timeout)?
            },
        }
    }

    fn record(&self, operation: &'static str, result: Result<(), EmailError>) {
        let (outcome, next) = match result {
            Ok(()) => ("success", READY),
            Err(EmailError::Cancelled) => ("cancelled", DEGRADED),
            Err(EmailError::Timeout) => ("timeout", DEGRADED),
            Err(EmailError::Capacity) => ("capacity", READY),
            Err(EmailError::AdmissionClosed) => ("closed", DRAINING),
            Err(EmailError::Delivery(class)) => (class.label(), DEGRADED),
            Err(_) => ("invalid", READY),
        };
        transition_operational_lifecycle(&self.inner.lifecycle, next);
        metrics::counter!(
            "rsk_email_operations_total",
            "provider" => self.inner.provider.label(),
            "operation" => operation,
            "outcome" => outcome,
        )
        .increment(1);
    }
}

impl MailSender for EmailService {
    fn send(&self, request: SendEmailRequest) -> BoxFuture<'_, Result<SendReceipt, EmailError>> {
        Box::pin(async move {
            let result = self.send_inner(request).await;
            self.record("send", result.as_ref().map(|_| ()).map_err(|error| *error));
            result
        })
    }
}

impl fmt::Debug for EmailService {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("EmailService")
            .field("provider", &self.inner.provider)
            .field("status", &self.status())
            .field("templates", &self.inner.templates)
            .field("transport", &"[REDACTED]")
            .finish_non_exhaustive()
    }
}

struct CancelPreparationOnDrop(CancellationToken);

impl Drop for CancelPreparationOnDrop {
    fn drop(&mut self) {
        self.0.cancel();
    }
}

struct ActiveSend(Arc<AtomicUsize>);

impl Drop for ActiveSend {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::AcqRel);
    }
}

fn lock_admission(inner: &Inner) -> MutexGuard<'_, ()> {
    match inner.admission.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    }
}

fn transition_operational_lifecycle(lifecycle: &AtomicU8, next: u8) {
    let mut current = lifecycle.load(Ordering::Acquire);
    while current < DRAINING {
        match lifecycle.compare_exchange_weak(current, next, Ordering::AcqRel, Ordering::Acquire) {
            Ok(_) => return,
            Err(observed) => current = observed,
        }
    }
}

fn prepare_message(
    templates: &TemplateRegistry,
    limits: EmailLimits,
    custom_headers: &crate::CustomHeaderPolicy,
    request: SendEmailRequest,
) -> Result<(IdempotencyKey, ClientMessageId, Message), EmailError> {
    request.validate_limits(&limits)?;
    request.validate_custom_headers(custom_headers)?;
    let idempotency_key = request.idempotency_key().clone();
    let client_message_id = request.client_message_id().clone();
    let parts = request.into_parts();
    let rendered = templates.preview(&parts.template, &parts.context)?;
    let message = build_message(parts, rendered, &client_message_id)?;
    Ok((idempotency_key, client_message_id, message))
}

fn build_message(
    parts: SendEmailParts,
    rendered: RenderedEmail,
    client_message_id: &ClientMessageId,
) -> Result<Message, EmailError> {
    let SendEmailParts {
        from,
        reply_to,
        recipients,
        subject,
        headers,
        attachments,
        ..
    } = parts;
    let mut builder = Message::builder()
        .from(to_lettre_mailbox(from)?)
        .subject(subject.as_str().to_owned())
        .message_id(Some(client_message_id.as_str().to_owned()));
    if let Some(reply_to) = reply_to {
        builder = builder.reply_to(to_lettre_mailbox(reply_to)?);
    }
    let (to, cc, bcc) = recipients.into_parts();
    for mailbox in to {
        builder = builder.to(to_lettre_mailbox(mailbox)?);
    }
    for mailbox in cc {
        builder = builder.cc(to_lettre_mailbox(mailbox)?);
    }
    for mailbox in bcc {
        builder = builder.bcc(to_lettre_mailbox(mailbox)?);
    }
    for header in headers {
        let (name, value) = header.into_parts();
        let name = HeaderName::new_from_ascii(name.as_str().to_owned())
            .map_err(|_| EmailError::InvalidHeader)?;
        builder = builder.raw_header(HeaderValue::new(name, value.as_str().to_owned()));
    }

    let (text, html) = rendered.into_parts();
    let alternative = MultiPart::alternative()
        .singlepart(SinglePart::plain(text))
        .singlepart(SinglePart::html(html));
    if attachments.is_empty() {
        return builder
            .multipart(alternative)
            .map_err(|_| EmailError::InvalidHeader);
    }

    let mut mixed = MultiPart::mixed().multipart(alternative);
    for attachment in attachments {
        let (name, media_type, data) = attachment.into_parts();
        let content_type =
            ContentType::parse(media_type.as_str()).map_err(|_| EmailError::InvalidAttachment)?;
        mixed = mixed
            .singlepart(LettreAttachment::new(name.as_str().to_owned()).body(data, content_type));
    }
    builder
        .multipart(mixed)
        .map_err(|_| EmailError::InvalidHeader)
}

fn to_lettre_mailbox(mailbox: MailboxAddress) -> Result<Mailbox, EmailError> {
    let (address, display_name) = mailbox.into_parts();
    let address = Address::from_str(address.as_str()).map_err(|_| EmailError::InvalidAddress)?;
    Ok(Mailbox::new(
        display_name.map(|name| name.as_str().to_owned()),
        address,
    ))
}

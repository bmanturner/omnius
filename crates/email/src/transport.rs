use std::{
    collections::VecDeque,
    fmt,
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, Ordering},
    },
};

use futures::future::BoxFuture;
use lettre::{
    AsyncSmtpTransport, AsyncTransport as _, Message, Tokio1Executor,
    transport::smtp::{PoolConfig, authentication::Credentials},
};
use rsk_config::ExposeSecret as _;
use thiserror::Error;

use crate::{
    ClientMessageId, DeliveryFailureClass, EmailError, EmailProviderConfig, ProviderKind,
    ProviderMessageId, SmtpFailureFacts, SmtpTlsMode, classify_smtp_failure,
};

pub(crate) struct PreparedMessage {
    pub message: Message,
    pub client_message_id: ClientMessageId,
}

pub(crate) struct ProviderReceipt {
    pub provider_message_id: Option<ProviderMessageId>,
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct TransportFailure {
    pub class: DeliveryFailureClass,
}

pub(crate) trait MailTransport: Send + Sync {
    fn send(
        &self,
        message: PreparedMessage,
    ) -> BoxFuture<'_, Result<ProviderReceipt, TransportFailure>>;

    fn test_connection(&self) -> BoxFuture<'_, Result<(), TransportFailure>>;

    fn shutdown(&self) -> BoxFuture<'_, ()>;
}

pub(crate) struct TransportBundle {
    pub transport: Arc<dyn MailTransport>,
    pub capture: Option<CapturingMailSink>,
    pub kind: ProviderKind,
}

pub(crate) fn build_transport(
    provider: EmailProviderConfig,
) -> Result<TransportBundle, EmailError> {
    match provider {
        EmailProviderConfig::Capturing { capacity } => {
            let capture = CapturingMailSink::new(capacity).map_err(|_| EmailError::Config)?;
            Ok(TransportBundle {
                transport: Arc::new(capture.clone()),
                capture: Some(capture),
                kind: ProviderKind::Capturing,
            })
        }
        EmailProviderConfig::Smtp {
            relay,
            port,
            tls,
            username,
            password,
            pool,
        } => {
            let builder = match tls {
                SmtpTlsMode::Implicit => AsyncSmtpTransport::<Tokio1Executor>::relay(&relay),
                SmtpTlsMode::RequiredStartTls => {
                    AsyncSmtpTransport::<Tokio1Executor>::starttls_relay(&relay)
                }
            }
            .map_err(|_| EmailError::Config)?;
            let credentials = Credentials::new(
                username.expose_secret().to_owned(),
                password.expose_secret().to_owned(),
            );
            let pool_config = PoolConfig::new()
                .min_idle(pool.min_idle)
                .max_size(pool.max_size)
                .idle_timeout(pool.idle_timeout);
            let transport = builder
                .port(port)
                .credentials(credentials)
                .timeout(Some(pool.command_timeout))
                .pool_config(pool_config)
                .build::<Tokio1Executor>();
            Ok(TransportBundle {
                transport: Arc::new(SmtpMailTransport { transport }),
                capture: None,
                kind: ProviderKind::Smtp,
            })
        }
    }
}

struct SmtpMailTransport {
    transport: AsyncSmtpTransport<Tokio1Executor>,
}

impl MailTransport for SmtpMailTransport {
    fn send(
        &self,
        message: PreparedMessage,
    ) -> BoxFuture<'_, Result<ProviderReceipt, TransportFailure>> {
        Box::pin(async move {
            self.transport
                .send(message.message)
                .await
                .map(|response| ProviderReceipt {
                    provider_message_id: response.first_line().and_then(provider_message_id),
                })
                .map_err(|error| classify_lettre_error(&error))
        })
    }

    fn test_connection(&self) -> BoxFuture<'_, Result<(), TransportFailure>> {
        Box::pin(async move {
            match self.transport.test_connection().await {
                Ok(true) => Ok(()),
                Ok(false) => Err(TransportFailure {
                    class: DeliveryFailureClass::Unavailable,
                }),
                Err(error) => Err(classify_lettre_error(&error)),
            }
        })
    }

    fn shutdown(&self) -> BoxFuture<'_, ()> {
        Box::pin(async move {
            self.transport.shutdown().await;
        })
    }
}

impl fmt::Debug for SmtpMailTransport {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SmtpMailTransport")
            .field("transport", &"[REDACTED SMTP TRANSPORT]")
            .finish_non_exhaustive()
    }
}

fn classify_lettre_error(error: &lettre::transport::smtp::Error) -> TransportFailure {
    let facts = if error.is_timeout() {
        SmtpFailureFacts::Timeout
    } else if error.is_tls() {
        SmtpFailureFacts::Tls
    } else if error.is_transient() {
        SmtpFailureFacts::Transient
    } else if error.is_permanent() {
        SmtpFailureFacts::Permanent
    } else if let Some(status) = error.status() {
        SmtpFailureFacts::Status(u16::from(status))
    } else {
        SmtpFailureFacts::Unavailable
    };
    TransportFailure {
        class: classify_smtp_failure(facts),
    }
}

fn provider_message_id(line: &str) -> Option<ProviderMessageId> {
    if line.len() > 1_024 || !line.is_ascii() {
        return None;
    }
    let mut use_next_token = false;
    for token in line.split_ascii_whitespace() {
        let direct = token
            .split_once('=')
            .filter(|(key, _)| key.eq_ignore_ascii_case("id"))
            .map(|(_, value)| value);
        let candidate = if use_next_token { Some(token) } else { direct };
        if let Some(candidate) = candidate {
            let candidate = candidate.trim_matches(|character: char| {
                matches!(character, '[' | ']' | '(' | ')' | ',' | ';')
            });
            if let Ok(identifier) = ProviderMessageId::try_from(candidate) {
                return Some(identifier);
            }
        }
        use_next_token = token.eq_ignore_ascii_case("as") || token.eq_ignore_ascii_case("id");
    }
    None
}

/// Safe fixture-state errors that never retain captured content.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum CaptureError {
    /// Capacity is outside 1 through 64.
    #[error("mail capture capacity is invalid")]
    InvalidCapacity,
    /// The fixture mutex is unavailable.
    #[error("mail capture state is unavailable")]
    Unavailable,
    /// A formatted captured message was unexpectedly not UTF-8.
    #[error("captured mail is not UTF-8")]
    Utf8,
}

struct CapturingState {
    messages: VecDeque<CapturedMessage>,
    shutdown: bool,
}

struct CapturingInner {
    capacity: usize,
    state: Mutex<CapturingState>,
    next_id: AtomicU64,
}

/// Fixed-capacity concurrency-safe semantic mail sink for tests.
///
/// It captures already-built lettre messages rather than imitating an SMTP server. Whole messages
/// are reachable only through the explicit snapshot/drain test-facing methods.
#[derive(Clone)]
pub struct CapturingMailSink {
    inner: Arc<CapturingInner>,
}

impl CapturingMailSink {
    /// Creates a fixed-capacity sink.
    ///
    /// # Errors
    ///
    /// Returns [`CaptureError::InvalidCapacity`] outside 1 through 64.
    pub fn new(capacity: usize) -> Result<Self, CaptureError> {
        if !(1..=64).contains(&capacity) {
            return Err(CaptureError::InvalidCapacity);
        }
        Ok(Self {
            inner: Arc::new(CapturingInner {
                capacity,
                state: Mutex::new(CapturingState {
                    messages: VecDeque::with_capacity(capacity),
                    shutdown: false,
                }),
                next_id: AtomicU64::new(1),
            }),
        })
    }

    /// Fixed retention capacity.
    #[must_use]
    pub fn capacity(&self) -> usize {
        self.inner.capacity
    }

    /// Retained message count.
    ///
    /// # Errors
    ///
    /// Returns [`CaptureError::Unavailable`] when fixture state is poisoned.
    pub fn len(&self) -> Result<usize, CaptureError> {
        self.inner
            .state
            .lock()
            .map(|state| state.messages.len())
            .map_err(|_| CaptureError::Unavailable)
    }

    /// Whether no messages are retained.
    ///
    /// # Errors
    ///
    /// Returns [`CaptureError::Unavailable`] when fixture state is poisoned.
    pub fn is_empty(&self) -> Result<bool, CaptureError> {
        Ok(self.len()? == 0)
    }

    /// Non-destructive acceptance-order snapshot.
    ///
    /// # Errors
    ///
    /// Returns [`CaptureError::Unavailable`] when fixture state is poisoned.
    pub fn snapshot(&self) -> Result<Vec<CapturedMessage>, CaptureError> {
        self.inner
            .state
            .lock()
            .map(|state| state.messages.iter().cloned().collect())
            .map_err(|_| CaptureError::Unavailable)
    }

    /// Acceptance-order drain.
    ///
    /// # Errors
    ///
    /// Returns [`CaptureError::Unavailable`] when fixture state is poisoned.
    pub fn drain(&self) -> Result<Vec<CapturedMessage>, CaptureError> {
        self.inner
            .state
            .lock()
            .map(|mut state| state.messages.drain(..).collect())
            .map_err(|_| CaptureError::Unavailable)
    }
}

impl MailTransport for CapturingMailSink {
    fn send(
        &self,
        message: PreparedMessage,
    ) -> BoxFuture<'_, Result<ProviderReceipt, TransportFailure>> {
        Box::pin(async move {
            let mut state = self.inner.state.lock().map_err(|_| TransportFailure {
                class: DeliveryFailureClass::Unavailable,
            })?;
            if state.shutdown || state.messages.len() == self.inner.capacity {
                return Err(TransportFailure {
                    class: DeliveryFailureClass::Unavailable,
                });
            }
            let sequence = self
                .inner
                .next_id
                .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
                    current.checked_add(1)
                })
                .map_err(|_| TransportFailure {
                    class: DeliveryFailureClass::Unavailable,
                })?;
            let provider_message_id = ProviderMessageId::try_from(format!("capture-{sequence}"))
                .map_err(|_| TransportFailure {
                    class: DeliveryFailureClass::Unavailable,
                })?;
            state.messages.push_back(CapturedMessage {
                provider_message_id: provider_message_id.clone(),
                client_message_id: message.client_message_id,
                message: message.message,
            });
            drop(state);
            Ok(ProviderReceipt {
                provider_message_id: Some(provider_message_id),
            })
        })
    }

    fn test_connection(&self) -> BoxFuture<'_, Result<(), TransportFailure>> {
        Box::pin(async move {
            let state = self.inner.state.lock().map_err(|_| TransportFailure {
                class: DeliveryFailureClass::Unavailable,
            })?;
            if state.shutdown {
                Err(TransportFailure {
                    class: DeliveryFailureClass::Unavailable,
                })
            } else {
                Ok(())
            }
        })
    }

    fn shutdown(&self) -> BoxFuture<'_, ()> {
        Box::pin(async move {
            if let Ok(mut state) = self.inner.state.lock() {
                state.shutdown = true;
            }
        })
    }
}

impl fmt::Debug for CapturingMailSink {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let state = self.inner.state.lock().ok();
        formatter
            .debug_struct("CapturingMailSink")
            .field("capacity", &self.inner.capacity)
            .field(
                "retained",
                &state.as_ref().map(|state| state.messages.len()),
            )
            .field("messages", &"[REDACTED]")
            .field("shutdown", &state.as_ref().map(|state| state.shutdown))
            .finish_non_exhaustive()
    }
}

/// One whole captured message, available only from explicit test-fixture APIs.
#[derive(Clone)]
pub struct CapturedMessage {
    provider_message_id: ProviderMessageId,
    client_message_id: ClientMessageId,
    message: Message,
}

impl CapturedMessage {
    /// Provider fixture identifier in acceptance order.
    #[must_use]
    pub const fn provider_message_id(&self) -> &ProviderMessageId {
        &self.provider_message_id
    }

    /// Persisted opaque RFC Message-ID supplied when the durable effect was created.
    #[must_use]
    pub const fn client_message_id(&self) -> &ClientMessageId {
        &self.client_message_id
    }

    /// Formats a private copy of the complete RFC message for explicit test inspection.
    #[must_use]
    pub fn formatted(&self) -> Vec<u8> {
        self.message.formatted()
    }

    /// Formats the complete RFC message as UTF-8 for explicit test inspection.
    ///
    /// # Errors
    ///
    /// Returns [`CaptureError::Utf8`] if the formatted message is unexpectedly not UTF-8.
    pub fn formatted_utf8(&self) -> Result<String, CaptureError> {
        String::from_utf8(self.formatted()).map_err(|_| CaptureError::Utf8)
    }
}

impl fmt::Debug for CapturedMessage {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CapturedMessage")
            .field("provider_message_id", &"[REDACTED]")
            .field("client_message_id", &"[REDACTED]")
            .field("message", &"[REDACTED]")
            .finish_non_exhaustive()
    }
}

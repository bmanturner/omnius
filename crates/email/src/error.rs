use thiserror::Error;

/// Stable delivery-failure classes. No variant retains a provider response or input value.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum DeliveryFailureClass {
    /// The provider explicitly reported a retryable failure.
    Transient,
    /// The provider explicitly reported a terminal failure.
    Permanent,
    /// The provider operation exceeded its deadline.
    Timeout,
    /// Establishing or using the authenticated TLS channel failed.
    Tls,
    /// The provider returned a status without a recognized retry class.
    Status(u16),
    /// The provider was unavailable without a more specific classification.
    Unavailable,
}

impl DeliveryFailureClass {
    /// Whether the failure is safe to retry within the caller's at-least-once policy.
    #[must_use]
    pub const fn is_retryable(self) -> bool {
        matches!(self, Self::Transient | Self::Timeout | Self::Unavailable)
    }

    pub(crate) const fn label(self) -> &'static str {
        match self {
            Self::Transient => "transient",
            Self::Permanent => "permanent",
            Self::Timeout => "timeout",
            Self::Tls => "tls",
            Self::Status(_) => "status",
            Self::Unavailable => "unavailable",
        }
    }
}

/// Value-free SMTP failure fact used by the pure retry-classification path.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[non_exhaustive]
pub enum SmtpFailureFacts {
    /// No more specific provider fact is available.
    #[default]
    Unavailable,
    /// Lettre classified the response as transient.
    Transient,
    /// Lettre classified the response as permanent.
    Permanent,
    /// An I/O source in the error chain timed out.
    Timeout,
    /// The TLS channel failed.
    Tls,
    /// Numeric SMTP status without a recognized retry class.
    Status(u16),
}

/// Classifies only stable SMTP facts and never accepts or returns provider response text.
#[must_use]
pub const fn classify_smtp_failure(facts: SmtpFailureFacts) -> DeliveryFailureClass {
    match facts {
        SmtpFailureFacts::Transient => DeliveryFailureClass::Transient,
        SmtpFailureFacts::Permanent => DeliveryFailureClass::Permanent,
        SmtpFailureFacts::Timeout => DeliveryFailureClass::Timeout,
        SmtpFailureFacts::Tls => DeliveryFailureClass::Tls,
        SmtpFailureFacts::Status(status) => DeliveryFailureClass::Status(status),
        SmtpFailureFacts::Unavailable => DeliveryFailureClass::Unavailable,
    }
}

/// Stable email failure classes that never retain addresses, headers, bodies, context, secrets,
/// or provider response strings.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[non_exhaustive]
pub enum EmailError {
    /// Runtime configuration violates an adapter safety invariant.
    #[error("email configuration is invalid")]
    Config,
    /// A mailbox address is invalid or exceeds its fixed bound.
    #[error("email address is invalid")]
    InvalidAddress,
    /// A display name, subject, or custom header is invalid.
    #[error("email header is invalid")]
    InvalidHeader,
    /// A template identifier is invalid.
    #[error("email template identifier is invalid")]
    InvalidTemplateName,
    /// A provider or client submission identifier violates its safe token grammar.
    #[error("email message identifier is invalid")]
    InvalidMessageId,
    /// The selected registered text/HTML pair does not exist.
    #[error("email template is not registered")]
    TemplateNotFound,
    /// A trusted template pair could not be safely loaded or compiled.
    #[error("email template registry is invalid")]
    TemplateRegistry,
    /// Template context exceeds a structural or serialized-size bound.
    #[error("email template context exceeds its limit")]
    ContextLimit,
    /// Strict template evaluation failed.
    #[error("email template rendering failed")]
    TemplateRender,
    /// Rendered text or HTML exceeded its configured output bound.
    #[error("rendered email exceeds its limit")]
    RenderLimit,
    /// Recipient count exceeds the configured bound or no recipient was provided.
    #[error("email recipient set is invalid")]
    RecipientLimit,
    /// A custom header set exceeds its configured count or byte bound.
    #[error("email header set exceeds its limit")]
    HeaderLimit,
    /// An attachment name, media type, or encoding is invalid.
    #[error("email attachment is invalid")]
    InvalidAttachment,
    /// Attachment count or bytes exceed the configured bound.
    #[error("email attachments exceed their limit")]
    AttachmentLimit,
    /// Configured concurrent render-and-send capacity is full.
    #[error("email delivery capacity is full")]
    Capacity,
    /// The provider no longer admits new deliveries.
    #[error("email provider is not accepting deliveries")]
    AdmissionClosed,
    /// Delivery was cooperatively cancelled.
    #[error("email delivery was cancelled")]
    Cancelled,
    /// The adapter operation deadline elapsed.
    #[error("email delivery timed out")]
    Timeout,
    /// The provider rejected or failed the delivery with a stable classification.
    #[error("email delivery failed")]
    Delivery(DeliveryFailureClass),
}

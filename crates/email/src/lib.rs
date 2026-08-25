//! Bounded email templates and TLS-safe delivery over `lettre` and `MiniJinja`.
//!
//! The crate eagerly loads deployment-controlled text/HTML template pairs, renders through strict
//! finite `MiniJinja` execution into bounded writers, builds safe internationalized MIME messages,
//! and submits through required TLS or a fixed-capacity semantic test sink. Public errors, Debug
//! implementations, status, metrics, and health diagnostics never retain or expose credentials,
//! addresses, headers, template context, rendered bodies, or provider response strings.
//!
//! SMTP and the jobs-core integration are explicitly at-least-once. Caller idempotency keys and
//! provider/client message IDs make duplicate reconciliation possible; they do not claim an
//! exactly-once guarantee that SMTP cannot provide.

#![forbid(unsafe_code)]

mod config;
mod error;
mod health;
mod job;
mod service;
mod template;
mod transport;
mod value;

pub use config::{
    CustomHeaderPolicy, EmailConfig, EmailLimits, EmailProviderConfig, ProviderKind,
    SmtpPoolConfig, SmtpTlsMode, TemplateConfig,
};
pub use error::{DeliveryFailureClass, EmailError, SmtpFailureFacts, classify_smtp_failure};
pub use health::email_provider_health_check;
pub use job::{SendEmailHandler, SendEmailJob};
pub use service::{
    DeliveryEvent, DeliveryEventOutcome, DeliveryGuarantee, EmailService, EmailStatus, MailSender,
    ProviderBounceClass, ProviderDeliveryEvent, ProviderDeliveryEventKind, ProviderLifecycle,
    SendReceipt,
};
pub use template::{RenderedEmail, TemplateLintEntry, TemplateLintReport, TemplateRegistry};
pub use transport::{CaptureError, CapturedMessage, CapturingMailSink};
pub use value::{
    AttachmentMediaType, AttachmentName, ClientMessageId, CustomHeader, CustomHeaderName,
    CustomHeaderValue, DisplayName, EmailAddress, EmailAttachment, EmailSubject, MailboxAddress,
    ProviderMessageId, RecipientSet, SendEmailRequest, TemplateContext, TemplateName,
};

//! PostgreSQL-authoritative notification orchestration, optional preferences, and unsubscribe.
//!
//! Scheduling persists immutable delivery identity and the exact `notifications.send_email` v1
//! envelope before any queue call. The job provider and SMTP remain at-least-once; tenant-fenced
//! dedupe keys, persisted client message IDs, effect-identity checks, and fenced state transitions
//! support reconciliation without claiming exactly-once delivery. Optional preferences are checked
//! at send time. Mandatory, security, and transactional classifications never consult an opt-out.
//! Unsubscribe presentations are opaque 256-bit capabilities; only purpose-bound HMAC digests are
//! persisted, and consumption, preference mutation, and audit append share one transaction.

#![forbid(unsafe_code)]

mod error;
mod job;
mod orchestrator;
mod preferences;
mod repository;
mod token;
mod types;

pub use error::NotificationError;
pub use job::{NotificationEmailHandler, NotificationEmailJob};
pub use orchestrator::{
    DispatchReport, NotificationOrchestrator, ScheduleOutcome, ScheduledDelivery,
    is_pending_dispatch,
};
pub use preferences::{
    AuthenticatedPreferenceChange, IssuedUnsubscribe, PreferenceChangeOutcome, PreferenceService,
    UnsubscribeTarget,
};
pub use repository::PostgresNotificationRepository;
pub use token::{
    GeneratedUnsubscribeToken, OsUnsubscribeTokenGenerator, UnsubscribeToken,
    UnsubscribeTokenDigest, UnsubscribeTokenError, UnsubscribeTokenGenerator,
};
pub use types::{
    DedupeKey, DeliveryId, DeliveryMode, DeliveryRecord, DeliveryStatus, DigestKey, DigestSpec,
    EmailPresentation, Locale, NotificationChannel, NotificationClass, NotificationRequest,
    NotificationTemplate, NotificationValidationError, PreferenceCategory, PreferenceScope,
    ProductEvent, ProviderEventOutcome, ProviderScope, TimeZone,
};

pub(crate) use job::{build_envelope, effect_key};
pub(crate) use repository::ClaimOutcome;

use std::{fmt, num::NonZeroU32, str::FromStr, time::Duration};

use rsk_auth_core::{SubjectId, TenantId};
use rsk_core::{CausationId, CorrelationId};
use rsk_email::{EmailSubject, MailboxAddress, TemplateContext, TemplateName};
use serde::{Deserialize, Deserializer, Serialize};
use sha2::{Digest as _, Sha256};
use thiserror::Error;
use time::OffsetDateTime;
use uuid::{Uuid, Variant, Version};

const MAX_DIGEST_MEMBERS: u16 = 256;
const MIN_DIGEST_WINDOW_SECONDS: u32 = 60;
const MAX_DIGEST_WINDOW_SECONDS: u32 = 7 * 24 * 60 * 60;

/// A notification value failed bounded, value-free validation.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[non_exhaustive]
pub enum NotificationValidationError {
    /// A product event name was invalid.
    #[error("notification event is invalid")]
    Event,
    /// An optional preference category was invalid.
    #[error("notification preference category is invalid")]
    Category,
    /// A locale was not a bounded language tag.
    #[error("notification locale is invalid")]
    Locale,
    /// A time zone was not a bounded portable zone identifier.
    #[error("notification time zone is invalid")]
    TimeZone,
    /// A deduplication key was invalid.
    #[error("notification deduplication key is invalid")]
    DedupeKey,
    /// A digest key was invalid.
    #[error("notification digest key is invalid")]
    DigestKey,
    /// A provider account namespace was invalid.
    #[error("notification provider scope is invalid")]
    ProviderScope,
    /// The digest window was outside one minute through seven days.
    #[error("notification digest window is invalid")]
    DigestWindow,
    /// The template version was zero or exceeded the PostgreSQL integer bound.
    #[error("notification template version is invalid")]
    TemplateVersion,
    /// No channel, a duplicate channel, or too many channels were supplied.
    #[error("notification channels are invalid")]
    Channels,
    /// Digest delivery was requested for a mandatory classification.
    #[error("notification delivery mode is invalid")]
    DeliveryMode,
    /// Correlation or causation identity was not `UUIDv7`.
    #[error("notification work identity is invalid")]
    WorkIdentity,
    /// A persisted UUID was not `UUIDv7`.
    #[error("notification identifier is invalid")]
    Identifier,
    /// A persisted status was not part of the closed notification state machine.
    #[error("notification status is invalid")]
    Status,
}

macro_rules! bounded_string {
    ($name:ident, $validator:ident, $error:expr, $doc:literal) => {
        #[doc = $doc]
        #[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
        #[serde(transparent)]
        pub struct $name(String);

        impl $name {
            /// Borrows the validated value.
            #[must_use]
            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl TryFrom<&str> for $name {
            type Error = NotificationValidationError;

            fn try_from(value: &str) -> Result<Self, Self::Error> {
                $validator(value)?;
                Ok(Self(value.to_owned()))
            }
        }

        impl TryFrom<String> for $name {
            type Error = NotificationValidationError;

            fn try_from(value: String) -> Result<Self, Self::Error> {
                $validator(&value)?;
                Ok(Self(value))
            }
        }

        impl FromStr for $name {
            type Err = NotificationValidationError;

            fn from_str(value: &str) -> Result<Self, Self::Err> {
                Self::try_from(value)
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: Deserializer<'de>,
            {
                Self::try_from(String::deserialize(deserializer)?)
                    .map_err(|_| serde::de::Error::custom($error))
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter
                    .debug_struct(stringify!($name))
                    .field("value", &"[REDACTED]")
                    .field("byte_len", &self.0.len())
                    .finish_non_exhaustive()
            }
        }
    };
}

fn validate_event(value: &str) -> Result<(), NotificationValidationError> {
    validate_lower_identifier(value, 128).map_err(|()| NotificationValidationError::Event)
}

fn validate_category(value: &str) -> Result<(), NotificationValidationError> {
    validate_lower_identifier(value, 64).map_err(|()| NotificationValidationError::Category)
}

fn validate_provider_scope(value: &str) -> Result<(), NotificationValidationError> {
    validate_lower_identifier(value, 64).map_err(|()| NotificationValidationError::ProviderScope)
}

fn validate_locale(value: &str) -> Result<(), NotificationValidationError> {
    let mut parts = value.split('-');
    let language = parts.next().unwrap_or_default();
    if value.len() > 35
        || !(2..=8).contains(&language.len())
        || !language.bytes().all(|byte| byte.is_ascii_alphabetic())
        || parts.any(|part| {
            part.is_empty()
                || part.len() > 8
                || !part.bytes().all(|byte| byte.is_ascii_alphanumeric())
        })
    {
        return Err(NotificationValidationError::Locale);
    }
    Ok(())
}

fn validate_time_zone(value: &str) -> Result<(), NotificationValidationError> {
    let valid_part = |part: &str| {
        !part.is_empty()
            && part != "."
            && part != ".."
            && part.bytes().all(|byte| {
                byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'+' | b'-' | b'.')
            })
    };
    if value.len() > 64 || !value.split('/').all(valid_part) {
        return Err(NotificationValidationError::TimeZone);
    }
    Ok(())
}

fn validate_dedupe_key(value: &str) -> Result<(), NotificationValidationError> {
    if value.is_empty() || value.len() > 255 || !value.bytes().all(|byte| byte.is_ascii_graphic()) {
        return Err(NotificationValidationError::DedupeKey);
    }
    Ok(())
}

fn validate_digest_key(value: &str) -> Result<(), NotificationValidationError> {
    if value.is_empty()
        || value.len() > 128
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'.' | b':' | b'-'))
    {
        return Err(NotificationValidationError::DigestKey);
    }
    Ok(())
}

fn validate_lower_identifier(value: &str, maximum: usize) -> Result<(), ()> {
    if value.is_empty()
        || value.len() > maximum
        || !value.as_bytes().first().is_some_and(u8::is_ascii_lowercase)
        || !value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'_' | b'.' | b'-')
        })
    {
        return Err(());
    }
    Ok(())
}

bounded_string!(
    ProductEvent,
    validate_event,
    "notification event is invalid",
    "A bounded product-controlled notification event name."
);
bounded_string!(
    PreferenceCategory,
    validate_category,
    "notification preference category is invalid",
    "A bounded product-controlled optional preference category."
);
bounded_string!(
    ProviderScope,
    validate_provider_scope,
    "notification provider scope is invalid",
    "A bounded application-selected namespace for one provider account."
);
bounded_string!(
    Locale,
    validate_locale,
    "notification locale is invalid",
    "A bounded syntactic BCP-47 language tag selected by the product."
);
bounded_string!(
    TimeZone,
    validate_time_zone,
    "notification time zone is invalid",
    "A bounded portable IANA-style time-zone identifier."
);
bounded_string!(
    DedupeKey,
    validate_dedupe_key,
    "notification deduplication key is invalid",
    "A caller-defined duplicate identity scoped by tenant, channel, and digest window."
);
bounded_string!(
    DigestKey,
    validate_digest_key,
    "notification digest key is invalid",
    "A bounded identity selecting events that may be coalesced in one digest window."
);

/// A time-ordered notification delivery identity.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct DeliveryId(Uuid);

impl DeliveryId {
    /// Generates a `UUIDv7` delivery identity.
    #[must_use]
    pub fn new() -> Self {
        Self(Uuid::now_v7())
    }

    /// Restores a `UUIDv7` delivery identity.
    ///
    /// # Errors
    ///
    /// Returns [`NotificationValidationError::Identifier`] unless `value` is an RFC-compatible
    /// `UUIDv7`.
    pub fn from_uuid(value: Uuid) -> Result<Self, NotificationValidationError> {
        if is_uuid_v7(value) {
            Ok(Self(value))
        } else {
            Err(NotificationValidationError::Identifier)
        }
    }

    /// Returns the underlying UUID.
    #[must_use]
    pub const fn as_uuid(self) -> Uuid {
        self.0
    }
}

impl Default for DeliveryId {
    fn default() -> Self {
        Self::new()
    }
}
impl<'de> Deserialize<'de> for DeliveryId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        Self::from_uuid(Uuid::deserialize(deserializer)?)
            .map_err(|_| serde::de::Error::custom("notification delivery identifier is invalid"))
    }
}
impl fmt::Display for DeliveryId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

/// A supported notification delivery channel.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum NotificationChannel {
    /// Deliver through `rsk-email`.
    Email,
}
impl NotificationChannel {
    /// Stable database representation.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Email => "email",
        }
    }
}

/// Product classification and its relationship to optional preferences.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum NotificationClass {
    /// A category that recipients may disable.
    Optional(PreferenceCategory),
    /// Product-defined mandatory traffic that no optional preference can suppress.
    Mandatory,
    /// Security traffic that no optional preference can suppress.
    Security,
    /// Transactional traffic that no optional preference can suppress.
    Transactional,
}
impl NotificationClass {
    /// Stable classification label.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Optional(_) => "optional",
            Self::Mandatory => "mandatory",
            Self::Security => "security",
            Self::Transactional => "transactional",
        }
    }
    /// Optional preference category.
    #[must_use]
    pub const fn preference_category(&self) -> Option<&PreferenceCategory> {
        match self {
            Self::Optional(category) => Some(category),
            _ => None,
        }
    }
    /// Whether a preference lookup may suppress delivery.
    #[must_use]
    pub const fn is_optional(&self) -> bool {
        matches!(self, Self::Optional(_))
    }
}

/// Immutable versioned template selection.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NotificationTemplate {
    base: TemplateName,
    versioned_name: TemplateName,
    version: NonZeroU32,
}
impl NotificationTemplate {
    /// Creates a product template base and derives its immutable registered version key.
    ///
    /// # Errors
    ///
    /// Returns [`NotificationValidationError::TemplateVersion`] when `version` is zero or exceeds
    /// the PostgreSQL integer range.
    pub fn new(base: TemplateName, version: u32) -> Result<Self, NotificationValidationError> {
        let version = NonZeroU32::new(version)
            .filter(|value| i32::try_from(value.get()).is_ok())
            .ok_or(NotificationValidationError::TemplateVersion)?;
        let versioned_name =
            TemplateName::try_from(format!("{}-v{}", base.as_str(), version.get()))
                .map_err(|_| NotificationValidationError::TemplateVersion)?;
        Ok(Self {
            base,
            versioned_name,
            version,
        })
    }
    /// Product template base, retained with the version as immutable delivery identity.
    #[must_use]
    pub const fn base(&self) -> &TemplateName {
        &self.base
    }

    /// Deterministic immutable registry key in `<base>-v<version>` form.
    #[must_use]
    pub const fn name(&self) -> &TemplateName {
        &self.versioned_name
    }
    /// Positive historical version.
    #[must_use]
    pub const fn version(&self) -> u32 {
        self.version.get()
    }
}

/// Sensitive presentation fields needed to create one exact `SendEmailRequest` on every retry.
#[derive(Clone, Eq, PartialEq)]
pub struct EmailPresentation {
    recipient: MailboxAddress,
    from: MailboxAddress,
    subject: EmailSubject,
    template: NotificationTemplate,
    context: TemplateContext,
}
impl EmailPresentation {
    /// Creates an immutable validated email presentation.
    #[must_use]
    pub const fn new(
        recipient: MailboxAddress,
        from: MailboxAddress,
        subject: EmailSubject,
        template: NotificationTemplate,
        context: TemplateContext,
    ) -> Self {
        Self {
            recipient,
            from,
            subject,
            template,
            context,
        }
    }
    /// Destination mailbox.
    #[must_use]
    pub const fn recipient(&self) -> &MailboxAddress {
        &self.recipient
    }
    /// Sender mailbox.
    #[must_use]
    pub const fn from(&self) -> &MailboxAddress {
        &self.from
    }
    /// Product-controlled subject.
    #[must_use]
    pub const fn subject(&self) -> &EmailSubject {
        &self.subject
    }
    /// Versioned template selection.
    #[must_use]
    pub const fn template(&self) -> &NotificationTemplate {
        &self.template
    }
    /// Bounded rendering context.
    #[must_use]
    pub const fn context(&self) -> &TemplateContext {
        &self.context
    }
}
impl fmt::Debug for EmailPresentation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("EmailPresentation")
            .field("recipient", &"[REDACTED]")
            .field("from", &"[REDACTED]")
            .field("subject", &"[REDACTED]")
            .field("template", &"[REDACTED]")
            .field("template_version", &self.template.version())
            .field("context", &"[REDACTED]")
            .finish_non_exhaustive()
    }
}

/// Bounded digest coalescing policy.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DigestSpec {
    key: DigestKey,
    window_seconds: u32,
}
impl DigestSpec {
    /// Creates a digest window from one minute through seven days.
    ///
    /// # Errors
    ///
    /// Returns [`NotificationValidationError::DigestWindow`] unless `window` is an exact
    /// whole-second duration from one minute through seven days.
    pub fn new(key: DigestKey, window: Duration) -> Result<Self, NotificationValidationError> {
        let seconds = u32::try_from(window.as_secs())
            .map_err(|_| NotificationValidationError::DigestWindow)?;
        if !(MIN_DIGEST_WINDOW_SECONDS..=MAX_DIGEST_WINDOW_SECONDS).contains(&seconds)
            || Duration::from_secs(u64::from(seconds)) != window
        {
            return Err(NotificationValidationError::DigestWindow);
        }
        Ok(Self {
            key,
            window_seconds: seconds,
        })
    }
    /// Digest identity.
    #[must_use]
    pub const fn key(&self) -> &DigestKey {
        &self.key
    }
    /// Exact whole-second window.
    #[must_use]
    pub const fn window_seconds(&self) -> u32 {
        self.window_seconds
    }
    /// Maximum members accepted into one bucket.
    #[must_use]
    pub const fn maximum_members(&self) -> u16 {
        MAX_DIGEST_MEMBERS
    }
}

/// Immediate or bounded digest delivery.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DeliveryMode {
    /// Create a durable send job immediately.
    Immediate,
    /// Coalesce optional notifications until the selected window closes.
    Digest(DigestSpec),
}

/// A complete validated product notification intent.
#[derive(Clone)]
pub struct NotificationRequest {
    tenant_id: TenantId,
    recipient_id: SubjectId,
    event: ProductEvent,
    channels: Vec<NotificationChannel>,
    classification: NotificationClass,
    locale: Locale,
    time_zone: TimeZone,
    email: EmailPresentation,
    dedupe_key: DedupeKey,
    delivery_mode: DeliveryMode,
    correlation_id: CorrelationId,
    causation_id: Option<CausationId>,
}
impl NotificationRequest {
    /// Validates one durable product notification intent.
    ///
    /// # Errors
    ///
    /// Returns [`NotificationValidationError::Channels`] for an empty, duplicate, or oversized
    /// channel set; [`NotificationValidationError::WorkIdentity`] for non-`UUIDv7` work IDs; or
    /// [`NotificationValidationError::DeliveryMode`] when a mandatory classification requests a
    /// digest.
    #[expect(
        clippy::too_many_arguments,
        reason = "every normative orchestration field is explicit"
    )]
    pub fn new(
        tenant_id: TenantId,
        recipient_id: SubjectId,
        event: ProductEvent,
        channels: Vec<NotificationChannel>,
        classification: NotificationClass,
        locale: Locale,
        time_zone: TimeZone,
        email: EmailPresentation,
        dedupe_key: DedupeKey,
        delivery_mode: DeliveryMode,
        correlation_id: CorrelationId,
        causation_id: Option<CausationId>,
    ) -> Result<Self, NotificationValidationError> {
        if channels.is_empty()
            || channels.len() > 4
            || channels
                .iter()
                .enumerate()
                .any(|(index, channel)| channels[..index].contains(channel))
        {
            return Err(NotificationValidationError::Channels);
        }
        if !correlation_id.is_v7() || causation_id.is_some_and(|id| !id.is_v7()) {
            return Err(NotificationValidationError::WorkIdentity);
        }
        if matches!(delivery_mode, DeliveryMode::Digest(_)) && !classification.is_optional() {
            return Err(NotificationValidationError::DeliveryMode);
        }
        Ok(Self {
            tenant_id,
            recipient_id,
            event,
            channels,
            classification,
            locale,
            time_zone,
            email,
            dedupe_key,
            delivery_mode,
            correlation_id,
            causation_id,
        })
    }
    /// Tenant fence.
    #[must_use]
    pub const fn tenant_id(&self) -> TenantId {
        self.tenant_id
    }
    /// Recipient subject.
    #[must_use]
    pub const fn recipient_id(&self) -> SubjectId {
        self.recipient_id
    }
    /// Product event.
    #[must_use]
    pub const fn event(&self) -> &ProductEvent {
        &self.event
    }
    /// Requested channels.
    #[must_use]
    pub fn channels(&self) -> &[NotificationChannel] {
        &self.channels
    }
    /// Preference and mandatory classification.
    #[must_use]
    pub const fn classification(&self) -> &NotificationClass {
        &self.classification
    }
    /// Locale.
    #[must_use]
    pub const fn locale(&self) -> &Locale {
        &self.locale
    }
    /// Time zone.
    #[must_use]
    pub const fn time_zone(&self) -> &TimeZone {
        &self.time_zone
    }
    /// Email presentation.
    #[must_use]
    pub const fn email(&self) -> &EmailPresentation {
        &self.email
    }
    /// Tenant/channel/window-scoped duplicate key.
    #[must_use]
    pub const fn dedupe_key(&self) -> &DedupeKey {
        &self.dedupe_key
    }
    /// Immediate or digest policy.
    #[must_use]
    pub const fn delivery_mode(&self) -> &DeliveryMode {
        &self.delivery_mode
    }
    /// Cross-transport correlation identity.
    #[must_use]
    pub const fn correlation_id(&self) -> CorrelationId {
        self.correlation_id
    }
    /// Optional causing work identity.
    #[must_use]
    pub const fn causation_id(&self) -> Option<CausationId> {
        self.causation_id
    }

    pub(crate) fn presentation_fingerprint(&self) -> [u8; 32] {
        let mut digest = Sha256::new();
        update_fingerprint(
            &mut digest,
            self.email.recipient.address().as_str().as_bytes(),
        );
        update_fingerprint(
            &mut digest,
            self.email
                .recipient
                .display_name()
                .map_or(&[][..], |value| value.as_str().as_bytes()),
        );
        update_fingerprint(&mut digest, self.email.from.address().as_str().as_bytes());
        update_fingerprint(
            &mut digest,
            self.email
                .from
                .display_name()
                .map_or(&[][..], |value| value.as_str().as_bytes()),
        );
        update_fingerprint(&mut digest, self.email.subject.as_str().as_bytes());
        update_fingerprint(&mut digest, self.email.template.base().as_str().as_bytes());
        update_fingerprint(&mut digest, self.email.template.name().as_str().as_bytes());
        update_fingerprint(&mut digest, &self.email.template.version().to_be_bytes());
        update_fingerprint(&mut digest, self.locale.as_str().as_bytes());
        update_fingerprint(&mut digest, self.time_zone.as_str().as_bytes());
        digest.finalize().into()
    }
}
impl fmt::Debug for NotificationRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("NotificationRequest")
            .field("tenant_id", &self.tenant_id)
            .field("recipient_id", &self.recipient_id)
            .field("event", &"[REDACTED]")
            .field("channels", &self.channels)
            .field("classification", &self.classification.as_str())
            .field("locale", &"[REDACTED]")
            .field("time_zone", &"[REDACTED]")
            .field("email", &"[REDACTED]")
            .field("dedupe_key", &"[REDACTED]")
            .field("delivery_mode", &self.delivery_mode)
            .field("correlation_id", &self.correlation_id)
            .field("causation_id", &self.causation_id)
            .finish_non_exhaustive()
    }
}
fn update_fingerprint(digest: &mut Sha256, value: &[u8]) {
    digest.update(u64::try_from(value.len()).unwrap_or(u64::MAX).to_be_bytes());
    digest.update(value);
}

/// Global or tenant-scoped optional preference target.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PreferenceScope {
    /// Default across tenants.
    Global,
    /// Preference effective only inside one tenant.
    Tenant(TenantId),
}
impl PreferenceScope {
    /// Stable database scope label.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Global => "global",
            Self::Tenant(_) => "tenant",
        }
    }
    /// Optional tenant fence.
    #[must_use]
    pub const fn tenant_id(self) -> Option<TenantId> {
        match self {
            Self::Global => None,
            Self::Tenant(value) => Some(value),
        }
    }
}

/// Closed durable delivery state machine.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DeliveryStatus {
    /// Waiting for the digest window to close.
    DigestPending,
    /// Persisted in the PostgreSQL job outbox but not yet accepted by its provider.
    PendingDispatch,
    /// Accepted by the durable job provider.
    Queued,
    /// Owned by one fenced handler attempt.
    Sending,
    /// A prior attempt failed transiently and may run again.
    Retryable,
    /// The email provider accepted the at-least-once submission.
    Accepted,
    /// A verified provider event reported final delivery.
    Delivered,
    /// Automatic attempts must not continue.
    PermanentFailed,
    /// An optional preference prevented delivery.
    Suppressed,
    /// The delivery content is represented by its digest leader.
    Coalesced,
    /// Cooperative cancellation ended delivery.
    Cancelled,
    /// A verified provider event reported a terminal bounce.
    Bounced,
    /// A verified provider event reported a complaint.
    Complained,
}
impl DeliveryStatus {
    /// Stable database label.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::DigestPending => "digest_pending",
            Self::PendingDispatch => "pending_dispatch",
            Self::Queued => "queued",
            Self::Sending => "sending",
            Self::Retryable => "retryable",
            Self::Accepted => "accepted",
            Self::Delivered => "delivered",
            Self::PermanentFailed => "permanent_failed",
            Self::Suppressed => "suppressed",
            Self::Coalesced => "coalesced",
            Self::Cancelled => "cancelled",
            Self::Bounced => "bounced",
            Self::Complained => "complained",
        }
    }
    /// Whether the state is terminal for automatic job processing.
    #[must_use]
    pub const fn is_terminal(self) -> bool {
        matches!(
            self,
            Self::Accepted
                | Self::Delivered
                | Self::PermanentFailed
                | Self::Suppressed
                | Self::Coalesced
                | Self::Cancelled
                | Self::Bounced
                | Self::Complained
        )
    }
}
impl FromStr for DeliveryStatus {
    type Err = NotificationValidationError;
    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "digest_pending" => Ok(Self::DigestPending),
            "pending_dispatch" => Ok(Self::PendingDispatch),
            "queued" => Ok(Self::Queued),
            "sending" => Ok(Self::Sending),
            "retryable" => Ok(Self::Retryable),
            "accepted" => Ok(Self::Accepted),
            "delivered" => Ok(Self::Delivered),
            "permanent_failed" => Ok(Self::PermanentFailed),
            "suppressed" => Ok(Self::Suppressed),
            "coalesced" => Ok(Self::Coalesced),
            "cancelled" => Ok(Self::Cancelled),
            "bounced" => Ok(Self::Bounced),
            "complained" => Ok(Self::Complained),
            _ => Err(NotificationValidationError::Status),
        }
    }
}

/// Result of applying one tenant-fenced, idempotent provider delivery event.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProviderEventOutcome {
    /// The event advanced the delivery from provider acceptance to a final outcome.
    Applied(DeliveryStatus),
    /// This provider event identity was already recorded.
    Duplicate(DeliveryStatus),
    /// The event was recorded without advancing the delivery state.
    Ignored(DeliveryStatus),
}

/// Non-sensitive delivery state returned by repository and orchestration APIs.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DeliveryRecord {
    /// Durable delivery identity.
    pub id: DeliveryId,
    /// Tenant fence for every read and transition.
    pub tenant_id: TenantId,
    /// Canonical recipient subject.
    pub recipient_id: SubjectId,
    /// Selected delivery channel.
    pub channel: NotificationChannel,
    /// Current durable state.
    pub status: DeliveryStatus,
    /// Number of fenced handler claims.
    pub attempt_count: u16,
    /// Historical product template version.
    pub template_version: u32,
    /// Database-authoritative creation instant.
    pub created_at: OffsetDateTime,
    /// Database-authoritative last transition instant.
    pub updated_at: OffsetDateTime,
}

pub(crate) fn is_uuid_v7(value: Uuid) -> bool {
    value.get_version() == Some(Version::SortRand) && value.get_variant() == Variant::RFC4122
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use rsk_auth_core::{SubjectId, TenantId};
    use rsk_core::CorrelationId;
    use rsk_email::{EmailAddress, EmailSubject, MailboxAddress, TemplateContext, TemplateName};
    use serde_json::json;

    use super::{
        DedupeKey, DeliveryMode, DigestKey, DigestSpec, EmailPresentation, Locale,
        NotificationChannel, NotificationClass, NotificationRequest, NotificationTemplate,
        NotificationValidationError, ProductEvent, TimeZone,
    };

    fn presentation() -> Result<EmailPresentation, Box<dyn std::error::Error>> {
        Ok(EmailPresentation::new(
            MailboxAddress::new(
                EmailAddress::try_from("recipient-sensitive@example.test")?,
                None,
            ),
            MailboxAddress::new(EmailAddress::try_from("sender@example.test")?, None),
            EmailSubject::try_from("Sensitive subject")?,
            NotificationTemplate::new(TemplateName::try_from("notice")?, 1)?,
            TemplateContext::new(json!({"secret": "context-sensitive"}))?,
        ))
    }

    #[test]
    fn mandatory_classification_rejects_digest_delivery() -> Result<(), Box<dyn std::error::Error>>
    {
        let result = NotificationRequest::new(
            TenantId::new(),
            SubjectId::new(),
            ProductEvent::try_from("security.alert")?,
            vec![NotificationChannel::Email],
            NotificationClass::Security,
            Locale::try_from("en-US")?,
            TimeZone::try_from("UTC")?,
            presentation()?,
            DedupeKey::try_from("security:one")?,
            DeliveryMode::Digest(DigestSpec::new(
                DigestKey::try_from("security")?,
                Duration::from_secs(60),
            )?),
            CorrelationId::new(),
            None,
        );
        assert!(matches!(
            result,
            Err(NotificationValidationError::DeliveryMode)
        ));
        Ok(())
    }

    #[test]
    fn request_debug_redacts_addresses_subject_context_and_dedupe()
    -> Result<(), Box<dyn std::error::Error>> {
        let request = NotificationRequest::new(
            TenantId::new(),
            SubjectId::new(),
            ProductEvent::try_from("product.update")?,
            vec![NotificationChannel::Email],
            NotificationClass::Mandatory,
            Locale::try_from("en-US")?,
            TimeZone::try_from("UTC")?,
            presentation()?,
            DedupeKey::try_from("sensitive-dedupe")?,
            DeliveryMode::Immediate,
            CorrelationId::new(),
            None,
        )?;
        let debug = format!("{request:?}");
        assert!(!debug.contains("recipient-sensitive"));
        assert!(!debug.contains("Sensitive subject"));
        assert!(!debug.contains("context-sensitive"));
        assert!(!debug.contains("sensitive-dedupe"));
        Ok(())
    }
}

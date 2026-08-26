use std::borrow::Cow;
use std::fmt;
use std::mem::size_of;
use std::sync::{Arc, PoisonError, RwLock};

use fluent_bundle::{FluentArgs, FluentValue};
use thiserror::Error;

use crate::catalog::{CatalogConfig, CatalogLoader, CatalogSnapshot};
use crate::{
    CatalogError, CurrencyAmount, DateTimeStyle, Locale, MessageArg, MessageArgs, MessageId,
    NegotiationError, ZonedDateTime,
};

const MAX_EXACT_FLUENT_INTEGER: u64 = 9_007_199_254_740_991;

/// Receives a missing-message event containing only a bounded configured locale.
pub trait MissingMessageObserver: Send + Sync {
    /// Records a lookup that exhausted its explicit fallback chain.
    fn record_missing(&self, locale: &Locale);
}

/// Emits the standard low-cardinality missing-message counter.
#[derive(Clone, Copy, Debug, Default)]
pub struct MetricsMissingMessageObserver;

impl MissingMessageObserver for MetricsMissingMessageObserver {
    fn record_missing(&self, locale: &Locale) {
        metrics::counter!(
            "rsk_localization_missing_messages_total",
            "locale" => locale.as_str().to_owned()
        )
        .increment(1);
    }
}

/// A thread-safe localization service with whole-snapshot atomic reload.
pub struct Localizer {
    snapshot: RwLock<Arc<CatalogSnapshot>>,
    missing_messages: Arc<dyn MissingMessageObserver>,
}

impl Localizer {
    /// Creates a service that reports missing messages through the standard metrics recorder.
    #[must_use]
    pub fn new(snapshot: CatalogSnapshot) -> Self {
        Self::with_missing_message_observer(snapshot, Arc::new(MetricsMissingMessageObserver))
    }

    /// Creates a service with an injected missing-message observer.
    #[must_use]
    pub fn with_missing_message_observer(
        snapshot: CatalogSnapshot,
        missing_messages: Arc<dyn MissingMessageObserver>,
    ) -> Self {
        Self {
            snapshot: RwLock::new(Arc::new(snapshot)),
            missing_messages,
        }
    }

    /// Negotiates a locale once and captures one immutable catalog snapshot.
    ///
    /// Reusing the returned context keeps an email subject/body or notification title/body on the
    /// same snapshot while a concurrent reload occurs.
    ///
    /// # Errors
    ///
    /// Returns [`NegotiationError`] before allocation when preferences exceed the configured
    /// catalog-count bound.
    pub fn context(&self, requested: &[Locale]) -> Result<RenderContext, NegotiationError> {
        let snapshot = self.current_snapshot();
        let primary_index = snapshot.negotiate(requested)?;
        Ok(RenderContext {
            snapshot,
            primary_index,
            missing_messages: Arc::clone(&self.missing_messages),
        })
    }

    /// Loads and validates a complete candidate before atomically publishing it.
    ///
    /// Any error leaves the previous snapshot available to all current and future render contexts.
    ///
    /// # Errors
    ///
    /// Returns [`CatalogError`] without changing the current snapshot when candidate loading or
    /// validation fails.
    pub fn reload(
        &self,
        loader: &CatalogLoader,
        config: &CatalogConfig,
    ) -> Result<(), CatalogError> {
        let candidate = Arc::new(loader.load(config)?);
        let mut snapshot = self
            .snapshot
            .write()
            .unwrap_or_else(PoisonError::into_inner);
        *snapshot = candidate;
        Ok(())
    }

    fn current_snapshot(&self) -> Arc<CatalogSnapshot> {
        let snapshot = self.snapshot.read().unwrap_or_else(PoisonError::into_inner);
        Arc::clone(&snapshot)
    }
}

/// A negotiated locale and immutable snapshot used for one or more related renders.
pub struct RenderContext {
    snapshot: Arc<CatalogSnapshot>,
    primary_index: usize,
    missing_messages: Arc<dyn MissingMessageObserver>,
}

impl RenderContext {
    /// Returns the negotiated primary locale before message-level fallback.
    #[must_use]
    pub fn locale(&self) -> &Locale {
        &self.snapshot.catalogs[self.primary_index].locale
    }

    /// Renders one message through the negotiated locale's explicit fallback chain.
    ///
    /// # Errors
    ///
    /// Returns [`RenderError`] for exceeded argument/output bounds, missing messages, or any Fluent
    /// formatting error.
    pub fn render(
        &self,
        message_id: &MessageId,
        arguments: &MessageArgs,
    ) -> Result<LocalizedText, RenderError> {
        self.validate_arguments(arguments)?;
        let Some(index) = self.find_catalog(&[message_id]) else {
            self.missing_messages.record_missing(self.locale());
            return Err(RenderError::MissingMessage);
        };
        let value = self.format_at(index, message_id, arguments)?;
        Ok(LocalizedText {
            locale: self.snapshot.catalogs[index].locale.clone(),
            value,
        })
    }

    /// Renders a subject and text body from one fallback locale for email delivery.
    ///
    /// # Errors
    ///
    /// Returns [`RenderError`] unless both parts exist in one fallback catalog and format within
    /// all configured bounds.
    pub fn render_email(
        &self,
        message_ids: &EmailMessageIds,
        arguments: &MessageArgs,
    ) -> Result<RenderedEmail, RenderError> {
        let (locale, subject, body) =
            self.render_pair(&message_ids.subject, &message_ids.body, arguments)?;
        Ok(RenderedEmail {
            locale,
            subject,
            text_body: body,
        })
    }

    /// Renders a title and body from one fallback locale for notification delivery.
    ///
    /// # Errors
    ///
    /// Returns [`RenderError`] unless both parts exist in one fallback catalog and format within
    /// all configured bounds.
    pub fn render_notification(
        &self,
        message_ids: &NotificationMessageIds,
        arguments: &MessageArgs,
    ) -> Result<RenderedNotification, RenderError> {
        let (locale, title, body) =
            self.render_pair(&message_ids.title, &message_ids.body, arguments)?;
        Ok(RenderedNotification {
            locale,
            title,
            body,
        })
    }

    fn render_pair(
        &self,
        first_id: &MessageId,
        second_id: &MessageId,
        arguments: &MessageArgs,
    ) -> Result<(Locale, String, String), RenderError> {
        self.validate_arguments(arguments)?;
        let Some(index) = self.find_catalog(&[first_id, second_id]) else {
            self.missing_messages.record_missing(self.locale());
            return Err(RenderError::MissingMessage);
        };
        let first = self.format_at(index, first_id, arguments)?;
        let second = self.format_at(index, second_id, arguments)?;
        Ok((self.snapshot.catalogs[index].locale.clone(), first, second))
    }

    fn find_catalog(&self, message_ids: &[&MessageId]) -> Option<usize> {
        self.snapshot.chains[self.primary_index]
            .iter()
            .copied()
            .find(|&index| {
                message_ids.iter().all(|message_id| {
                    self.snapshot.catalogs[index]
                        .bundle
                        .get_message(message_id.as_str())
                        .and_then(|message| message.value())
                        .is_some()
                })
            })
    }

    fn validate_arguments(&self, arguments: &MessageArgs) -> Result<(), RenderError> {
        if arguments.len() > self.snapshot.limits.arguments() {
            return Err(RenderError::ArgumentsTooLarge);
        }
        if arguments.iter().any(|(_name, value)| {
            matches!(value, MessageArg::Text(text) if Self::contains_bidi_control(text))
        }) {
            return Err(RenderError::UnsafeTextDirectionControl);
        }
        if arguments.iter().any(|(_name, value)| {
            matches!(
                value,
                MessageArg::Count(count) if count.unsigned_abs() > MAX_EXACT_FLUENT_INTEGER
            )
        }) {
            return Err(RenderError::ArgumentOutOfRange);
        }
        let total_bytes = arguments.iter().try_fold(0_usize, |total, (name, value)| {
            let value_bytes = match value {
                MessageArg::Text(value) => value.len(),
                MessageArg::Count(_) => size_of::<i64>(),
                MessageArg::Currency(_) | MessageArg::DateTime(_) => 64,
            };
            total
                .checked_add(name.as_str().len())?
                .checked_add(value_bytes)
        });
        if total_bytes.is_none_or(|bytes| bytes > self.snapshot.limits.argument_bytes()) {
            return Err(RenderError::ArgumentsTooLarge);
        }
        Ok(())
    }

    fn contains_bidi_control(value: &str) -> bool {
        value.chars().any(|character| {
            matches!(
                character,
                '\u{061c}'
                    | '\u{200e}'
                    | '\u{200f}'
                    | '\u{202a}'..='\u{202e}'
                    | '\u{2066}'..='\u{2069}'
            )
        })
    }

    fn format_at(
        &self,
        index: usize,
        message_id: &MessageId,
        arguments: &MessageArgs,
    ) -> Result<String, RenderError> {
        let catalog = &self.snapshot.catalogs[index];
        let pattern = catalog
            .bundle
            .get_message(message_id.as_str())
            .and_then(|message| message.value())
            .ok_or(RenderError::MissingMessage)?;
        let fluent_arguments = fluent_arguments(arguments, &catalog.locale);
        let mut errors = Vec::new();
        let mut rendered = BoundedWriter::new(self.snapshot.limits.rendered_bytes());
        let write_result = catalog.bundle.write_pattern(
            &mut rendered,
            pattern,
            Some(&fluent_arguments),
            &mut errors,
        );
        if rendered.exceeded {
            return Err(RenderError::RenderedMessageTooLarge);
        }
        if write_result.is_err() || rendered.allocation_failed || !errors.is_empty() {
            return Err(RenderError::FormattingFailed);
        }
        Ok(rendered.output)
    }
}

struct BoundedWriter {
    output: String,
    limit: usize,
    exceeded: bool,
    allocation_failed: bool,
}

impl BoundedWriter {
    const fn new(limit: usize) -> Self {
        Self {
            output: String::new(),
            limit,
            exceeded: false,
            allocation_failed: false,
        }
    }
}

impl fmt::Write for BoundedWriter {
    fn write_str(&mut self, value: &str) -> fmt::Result {
        let Some(required) = self.output.len().checked_add(value.len()) else {
            self.exceeded = true;
            return Err(fmt::Error);
        };
        if required > self.limit {
            self.exceeded = true;
            return Err(fmt::Error);
        }
        if required > self.output.capacity() {
            let grown = self
                .output
                .capacity()
                .max(64)
                .saturating_mul(2)
                .min(self.limit);
            let target = required.max(grown);
            let additional = target.saturating_sub(self.output.len());
            if self.output.try_reserve_exact(additional).is_err() {
                self.allocation_failed = true;
                return Err(fmt::Error);
            }
        }
        self.output.push_str(value);
        Ok(())
    }
}

fn fluent_arguments<'a>(arguments: &'a MessageArgs, locale: &Locale) -> FluentArgs<'a> {
    let mut fluent = FluentArgs::with_capacity(arguments.len());
    for (name, value) in arguments.iter() {
        let value = match value {
            MessageArg::Text(value) => FluentValue::String(Cow::Borrowed(value.as_str())),
            MessageArg::Count(value) => FluentValue::from(*value),
            MessageArg::Currency(value) => {
                FluentValue::String(Cow::Owned(format_currency(locale, *value)))
            }
            MessageArg::DateTime(value) => {
                FluentValue::String(Cow::Owned(format_date_time(locale, value)))
            }
        };
        fluent.set(name.as_str(), value);
    }
    fluent
}

fn format_currency(locale: &Locale, amount: CurrencyAmount) -> String {
    let digits = amount.code().minor_digits();
    let scale = 10_u64.pow(digits);
    let absolute = amount.minor_units().unsigned_abs();
    let integer = absolute / scale;
    let fraction = absolute % scale;
    let language = locale.language();
    let decimal_comma = matches!(
        language,
        "cs" | "da"
            | "de"
            | "es"
            | "fi"
            | "fr"
            | "hu"
            | "it"
            | "nl"
            | "no"
            | "pl"
            | "pt"
            | "ro"
            | "ru"
            | "sk"
            | "sv"
            | "tr"
            | "uk"
    );
    let grouping = if language == "fr" {
        '\u{202f}'
    } else if decimal_comma {
        '.'
    } else {
        ','
    };
    let decimal = if decimal_comma { ',' } else { '.' };
    let grouped = group_integer(integer, grouping);
    let sign = if amount.minor_units().is_negative() {
        "-"
    } else {
        ""
    };
    let number = if digits == 0 {
        format!("{sign}{grouped}")
    } else {
        let width = usize::try_from(digits).unwrap_or(4);
        format!("{sign}{grouped}{decimal}{fraction:0width$}")
    };
    if decimal_comma {
        format!("{number} {}", amount.code())
    } else {
        format!("{} {number}", amount.code())
    }
}

fn group_integer(integer: u64, separator: char) -> String {
    let digits = integer.to_string();
    let separator_count = digits.len().saturating_sub(1) / 3;
    let mut grouped = String::with_capacity(digits.len().saturating_add(separator_count));
    for (index, character) in digits.chars().enumerate() {
        if index > 0 && (digits.len() - index).is_multiple_of(3) {
            grouped.push(separator);
        }
        grouped.push(character);
    }
    grouped
}

fn format_date_time(locale: &Locale, value: &ZonedDateTime) -> String {
    let local = value
        .instant()
        .value()
        .with_timezone(&value.time_zone().value());
    let format = match value.style() {
        DateTimeStyle::Long => "%Y-%m-%dT%H:%M:%S%:z %Z",
        DateTimeStyle::Short if matches!(locale.language(), "ja" | "ko" | "zh") => {
            "%Y/%m/%d %H:%M %Z"
        }
        DateTimeStyle::Short if locale.language() == "en" => "%m/%d/%Y %H:%M %Z",
        DateTimeStyle::Short => "%d/%m/%Y %H:%M %Z",
    };
    local.format(format).to_string()
}

/// The localized value and the catalog locale that produced it.
pub struct LocalizedText {
    locale: Locale,
    value: String,
}

impl LocalizedText {
    /// Returns the catalog locale that produced the value.
    #[must_use]
    pub const fn locale(&self) -> &Locale {
        &self.locale
    }

    /// Returns the localized text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.value
    }

    /// Consumes the result and returns the localized text.
    #[must_use]
    pub fn into_string(self) -> String {
        self.value
    }
}

impl fmt::Display for LocalizedText {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.value)
    }
}

/// Message identifiers for a plain-text localized email.
#[derive(Clone)]
pub struct EmailMessageIds {
    subject: MessageId,
    body: MessageId,
}

impl EmailMessageIds {
    /// Creates an email message identifier pair.
    #[must_use]
    pub const fn new(subject: MessageId, body: MessageId) -> Self {
        Self { subject, body }
    }
}

/// A consistently localized plain-text email ready for an email template/delivery boundary.
pub struct RenderedEmail {
    locale: Locale,
    subject: String,
    text_body: String,
}

impl RenderedEmail {
    /// Returns the catalog locale used for both parts.
    #[must_use]
    pub const fn locale(&self) -> &Locale {
        &self.locale
    }

    /// Returns the email subject.
    #[must_use]
    pub fn subject(&self) -> &str {
        &self.subject
    }

    /// Returns the plain-text email body.
    #[must_use]
    pub fn text_body(&self) -> &str {
        &self.text_body
    }
}

/// Message identifiers for a localized notification.
#[derive(Clone)]
pub struct NotificationMessageIds {
    title: MessageId,
    body: MessageId,
}

impl NotificationMessageIds {
    /// Creates a notification message identifier pair.
    #[must_use]
    pub const fn new(title: MessageId, body: MessageId) -> Self {
        Self { title, body }
    }
}

/// A consistently localized notification ready for orchestration or delivery.
pub struct RenderedNotification {
    locale: Locale,
    title: String,
    body: String,
}

impl RenderedNotification {
    /// Returns the catalog locale used for both parts.
    #[must_use]
    pub const fn locale(&self) -> &Locale {
        &self.locale
    }

    /// Returns the notification title.
    #[must_use]
    pub fn title(&self) -> &str {
        &self.title
    }

    /// Returns the notification body.
    #[must_use]
    pub fn body(&self) -> &str {
        &self.body
    }
}

/// A redacted rendering failure.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum RenderError {
    /// No catalog in the explicit fallback chain contains the requested message or pair.
    #[error("localized message is missing")]
    MissingMessage,
    /// The argument count or total byte size exceeds configured limits.
    #[error("localized message arguments exceed limits")]
    ArgumentsTooLarge,
    /// Text contains a Unicode bidi control that could escape Fluent's directional isolation.
    #[error("localized text argument contains an unsafe direction control")]
    UnsafeTextDirectionControl,
    /// A numeric argument cannot retain exact Fluent plural or display semantics.
    #[error("localized numeric argument is out of range")]
    ArgumentOutOfRange,
    /// Fluent reported a resolver or formatting error. Diagnostics and values are redacted.
    #[error("localized message formatting failed")]
    FormattingFailed,
    /// The formatted output exceeds its configured byte limit.
    #[error("localized message exceeds output limit")]
    RenderedMessageTooLarge,
}

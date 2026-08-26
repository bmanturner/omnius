//! Bounded Project Fluent localization for service messages, email, and notifications.
//!
//! Catalog files are trusted deployment artifacts named by canonical locale under one flat,
//! non-symlink directory. A [`CatalogLoader`] rejects unsafe paths, oversized or non-UTF-8 input,
//! Fluent syntax failures, duplicate identifiers, invalid fallback graphs, and partial snapshots.
//! Multi-locale reload stages a new immutable catalog directory and loader. [`Localizer::reload`]
//! validates that complete candidate before one atomic swap; an existing [`RenderContext`] remains
//! pinned to its original snapshot.
//!
//! Runtime locale input is parsed as a strict Fluent-compatible BCP 47 language identifier and
//! negotiated only against configured catalogs. Each non-default catalog declares a finite fallback
//! chain ending in the default locale. Typed parameters preserve Fluent plural behavior, exact ISO
//! 4217 minor units, and UTC storage with database-validated geographic IANA time-zone rendering.
//! Errors, `Debug` output, and missing-message metrics never contain message identifiers, argument
//! names, values, catalog source, paths, or parser diagnostics.

mod catalog;
mod locale;
mod render;
mod value;

pub use catalog::{
    CatalogConfig, CatalogError, CatalogLimits, CatalogLoader, CatalogSnapshot, LimitsError,
    LocaleCatalog,
};
pub use locale::{Locale, LocaleError, NegotiationError};
pub use render::{
    EmailMessageIds, LocalizedText, Localizer, MetricsMissingMessageObserver,
    MissingMessageObserver, NotificationMessageIds, RenderContext, RenderError, RenderedEmail,
    RenderedNotification,
};
pub use value::{
    ArgumentError, ArgumentName, CurrencyAmount, CurrencyCode, CurrencyError, DateTimeStyle,
    InstantError, MessageArg, MessageArgs, MessageId, MessageIdError, TimeZone, TimeZoneError,
    UtcInstant, ZonedDateTime,
};

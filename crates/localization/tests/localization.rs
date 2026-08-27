//! Integration coverage for bounded locale negotiation, catalog loading, rendering, and reload.

use std::error::Error;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use chrono::{DateTime, Utc};
use omnius_localization::{
    CatalogConfig, CatalogError, CatalogLimits, CatalogLoader, CurrencyAmount, CurrencyCode,
    DateTimeStyle, EmailMessageIds, Locale, LocaleCatalog, Localizer, MessageArg, MessageArgs,
    MessageId, MissingMessageObserver, NotificationMessageIds, RenderError, TimeZone, UtcInstant,
    ZonedDateTime,
};

static NEXT_TEST_DIRECTORY: AtomicU64 = AtomicU64::new(1);

type TestResult = Result<(), Box<dyn Error>>;

struct TestDirectory(PathBuf);

impl TestDirectory {
    fn create() -> io::Result<Self> {
        let suffix = NEXT_TEST_DIRECTORY.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "omnius-localization-test-{}-{suffix}",
            std::process::id()
        ));
        fs::create_dir(&path)?;
        Ok(Self(path))
    }

    fn path(&self) -> &Path {
        &self.0
    }

    fn write(&self, name: &str, contents: &str) -> io::Result<()> {
        fs::write(self.0.join(name), contents)
    }
}

impl Drop for TestDirectory {
    fn drop(&mut self) {
        let _ignored = fs::remove_dir_all(&self.0);
    }
}

fn locale(value: &str) -> Result<Locale, Box<dyn Error>> {
    Ok(Locale::parse(value)?)
}

fn message_id(value: &str) -> Result<MessageId, Box<dyn Error>> {
    Ok(MessageId::parse(value)?)
}

fn bilingual_config() -> Result<CatalogConfig, Box<dyn Error>> {
    let english = locale("en-US")?;
    let french = locale("fr")?;
    Ok(CatalogConfig::new(
        english.clone(),
        vec![
            LocaleCatalog::new(english.clone(), vec![]),
            LocaleCatalog::new(french, vec![english]),
        ],
    ))
}

#[test]
fn negotiation_and_explicit_fallback_keep_related_parts_on_one_locale() -> TestResult {
    let directory = TestDirectory::create()?;
    directory.write(
        "en-US.ftl",
        "greeting = Hello\nfallback-only = Default copy\nemail-subject = Account notice\nemail-body = Hello, { $name }\nnotification-title = Ready\nnotification-body = Your export is ready",
    )?;
    directory.write(
        "fr.ftl",
        "greeting = Bonjour\nemail-subject = Avis du compte\nnotification-title = Prêt\nnotification-body = Votre export est prêt",
    )?;
    let loader = CatalogLoader::new(directory.path(), CatalogLimits::default())?;
    let localizer = Localizer::new(loader.load(&bilingual_config()?)?);
    let context = localizer.context(&[locale("fr-CA")?])?;

    let greeting = context.render(&message_id("greeting")?, &MessageArgs::new())?;
    assert_eq!(greeting.locale(), &locale("fr")?);
    assert_eq!(greeting.as_str(), "Bonjour");

    let fallback = context.render(&message_id("fallback-only")?, &MessageArgs::new())?;
    assert_eq!(fallback.locale(), &locale("en-US")?);
    assert_eq!(fallback.as_str(), "Default copy");

    let mut arguments = MessageArgs::new();
    arguments.try_insert("name", MessageArg::Text("Ada".to_owned()))?;
    let email = context.render_email(
        &EmailMessageIds::new(message_id("email-subject")?, message_id("email-body")?),
        &arguments,
    )?;
    assert_eq!(email.locale(), &locale("en-US")?);
    assert_eq!(email.subject(), "Account notice");
    assert!(email.text_body().contains("Ada"));

    let notification = context.render_notification(
        &NotificationMessageIds::new(
            message_id("notification-title")?,
            message_id("notification-body")?,
        ),
        &MessageArgs::new(),
    )?;
    assert_eq!(notification.locale(), &locale("fr")?);
    assert_eq!(notification.title(), "Prêt");
    assert_eq!(notification.body(), "Votre export est prêt");
    Ok(())
}

#[test]
fn plural_currency_and_time_zone_parameters_render_with_locale_semantics() -> TestResult {
    let directory = TestDirectory::create()?;
    directory.write(
        "en-US.ftl",
        "items = { $count ->\n    [one] One item\n   *[other] { $count } items\n}\nprice = { $price }\nappointment = { $when }",
    )?;
    directory.write("fr.ftl", "price = { $price }")?;
    let loader = CatalogLoader::new(directory.path(), CatalogLimits::default())?;
    let localizer = Localizer::new(loader.load(&bilingual_config()?)?);

    let mut one = MessageArgs::new();
    one.try_insert("count", MessageArg::Count(1))?;
    let singular = localizer
        .context(&[locale("en-US")?])?
        .render(&message_id("items")?, &one)?;
    assert_eq!(singular.as_str(), "One item");

    let mut many = MessageArgs::new();
    many.try_insert("count", MessageArg::Count(2))?;
    let plural = localizer
        .context(&[locale("en-US")?])?
        .render(&message_id("items")?, &many)?;
    assert!(plural.as_str().contains('2'));
    assert!(plural.as_str().ends_with(" items"));

    let mut inexact = MessageArgs::new();
    inexact.try_insert("count", MessageArg::Count(i64::MAX))?;
    let error = localizer
        .context(&[locale("en-US")?])?
        .render(&message_id("items")?, &inexact)
        .err()
        .ok_or("inexact plural count was accepted")?;
    assert_eq!(error, RenderError::ArgumentOutOfRange);

    let amount = CurrencyAmount::new(CurrencyCode::parse("USD")?, 123_456);
    let mut currency = MessageArgs::new();
    currency.try_insert("price", MessageArg::Currency(amount))?;
    let english_price = localizer
        .context(&[locale("en-US")?])?
        .render(&message_id("price")?, &currency)?;
    assert!(english_price.as_str().contains("USD 1,234.56"));
    let french_price = localizer
        .context(&[locale("fr")?])?
        .render(&message_id("price")?, &currency)?;
    assert!(french_price.as_str().contains("1\u{202f}234,56 USD"));

    let parsed = DateTime::parse_from_rfc3339("2026-01-15T15:00:00Z")?.with_timezone(&Utc);
    let date_time = ZonedDateTime::new(
        UtcInstant::new(parsed),
        TimeZone::parse("America/New_York")?,
        DateTimeStyle::Short,
    );
    let mut time = MessageArgs::new();
    time.try_insert("when", MessageArg::DateTime(date_time))?;
    let appointment = localizer
        .context(&[locale("en-US")?])?
        .render(&message_id("appointment")?, &time)?;
    assert!(appointment.as_str().contains("01/15/2026 10:00 EST"));
    Ok(())
}

#[test]
fn locale_currency_and_time_zone_parsers_reject_unsafe_or_unvalidated_input() -> TestResult {
    assert!(Locale::parse("../en-US").is_err());
    assert!(Locale::parse("en_US").is_err());
    assert!(Locale::parse(" en-US").is_err());
    assert!(CurrencyCode::parse("usd").is_err());
    assert!(CurrencyCode::parse("ZZZ").is_err());
    assert!(CurrencyCode::parse("XAU").is_err());
    assert!(CurrencyCode::parse("CUC").is_err());
    assert!(CurrencyCode::parse("HRK").is_err());
    assert!(CurrencyCode::parse("SLL").is_err());
    let currency = CurrencyCode::parse("ZWG")?;
    assert_eq!(currency.to_string(), "ZWG");
    assert!(!format!("{currency:?}").contains("ZWG"));
    assert!(TimeZone::parse("+02:00").is_err());
    assert!(TimeZone::parse("US/Eastern").is_err());
    assert!(TimeZone::parse("../../UTC").is_err());
    let time_zone = TimeZone::parse("UTC")?;
    assert_eq!(time_zone.name(), "UTC");
    assert!(!format!("{time_zone:?}").contains("UTC"));
    Ok(())
}

#[cfg(unix)]
#[test]
fn catalog_loader_rejects_symlink_catalogs() -> TestResult {
    use std::os::unix::fs::symlink;

    let catalog_root = TestDirectory::create()?;
    let outside = TestDirectory::create()?;
    outside.write("outside.ftl", "greeting = stolen")?;
    symlink(
        outside.path().join("outside.ftl"),
        catalog_root.path().join("en-US.ftl"),
    )?;
    let loader = CatalogLoader::new(catalog_root.path(), CatalogLimits::default())?;
    let english = locale("en-US")?;
    let config = CatalogConfig::new(english.clone(), vec![LocaleCatalog::new(english, vec![])]);

    let error = loader.load(&config).err().ok_or("symlink was accepted")?;
    assert_eq!(error, CatalogError::FileAccess);
    Ok(())
}

#[cfg(unix)]
#[test]
fn catalog_loader_rejects_hard_linked_catalogs() -> TestResult {
    let catalog_root = TestDirectory::create()?;
    let outside = TestDirectory::create()?;
    outside.write("outside.ftl", "greeting = linked")?;
    fs::hard_link(
        outside.path().join("outside.ftl"),
        catalog_root.path().join("en-US.ftl"),
    )?;
    let loader = CatalogLoader::new(catalog_root.path(), CatalogLimits::default())?;
    let english = locale("en-US")?;
    let config = CatalogConfig::new(english.clone(), vec![LocaleCatalog::new(english, vec![])]);

    let error = loader.load(&config).err().ok_or("hard link was accepted")?;
    assert_eq!(error, CatalogError::UnsafePath);
    Ok(())
}

#[test]
fn catalog_loader_rejects_syntax_and_duplicate_identifiers_without_diagnostics() -> TestResult {
    let directory = TestDirectory::create()?;
    let english = locale("en-US")?;
    let config = CatalogConfig::new(english.clone(), vec![LocaleCatalog::new(english, vec![])]);
    let loader = CatalogLoader::new(directory.path(), CatalogLimits::default())?;

    directory.write("en-US.ftl", "secret-message = { broken-user-text")?;
    let syntax = loader.load(&config).err().ok_or("syntax was accepted")?;
    assert_eq!(syntax, CatalogError::InvalidSyntax);
    assert!(!format!("{syntax:?}").contains("broken-user-text"));

    directory.write("en-US.ftl", "same-id = first\nsame-id = second")?;
    let duplicate = loader.load(&config).err().ok_or("duplicate was accepted")?;
    assert_eq!(duplicate, CatalogError::DuplicateIdentifier);
    assert!(!format!("{duplicate:?}").contains("same-id"));
    Ok(())
}

#[test]
fn catalog_and_argument_bounds_fail_closed() -> TestResult {
    let directory = TestDirectory::create()?;
    directory.write("en-US.ftl", "message = this catalog is over sixteen bytes")?;
    let small_catalog_limits = CatalogLimits::new(16, 2, 2, 4, 32, 64)?;
    let loader = CatalogLoader::new(directory.path(), small_catalog_limits)?;
    let english = locale("en-US")?;
    let config = CatalogConfig::new(
        english.clone(),
        vec![LocaleCatalog::new(english.clone(), vec![])],
    );
    let error = loader
        .load(&config)
        .err()
        .ok_or("large catalog was accepted")?;
    assert_eq!(error, CatalogError::CatalogTooLarge);

    directory.write("en-US.ftl", "message = { $text }")?;
    let small_argument_limits = CatalogLimits::new(1_024, 2, 2, 4, 8, 64)?;
    let loader = CatalogLoader::new(directory.path(), small_argument_limits)?;
    let localizer = Localizer::new(loader.load(&config)?);
    let excessive_preferences = vec![english.clone(), english.clone(), english.clone()];
    assert!(localizer.context(&excessive_preferences).is_err());
    let mut arguments = MessageArgs::new();
    arguments.try_insert("text", MessageArg::Text("sensitive-value".to_owned()))?;
    let error = localizer
        .context(std::slice::from_ref(&english))?
        .render(&message_id("message")?, &arguments)
        .err()
        .ok_or("large argument was accepted")?;
    assert_eq!(error, RenderError::ArgumentsTooLarge);
    assert!(!format!("{arguments:?}").contains("sensitive-value"));

    directory.write(
        "en-US.ftl",
        "message = prefix-{ $text }\nboundary = 12345678",
    )?;

    let output_limits = CatalogLimits::new(1_024, 2, 2, 4, 32, 8)?;
    let loader = CatalogLoader::new(directory.path(), output_limits)?;
    let localizer = Localizer::new(loader.load(&config)?);
    let context = localizer.context(std::slice::from_ref(&english))?;
    let boundary = context.render(&message_id("boundary")?, &MessageArgs::new())?;
    assert_eq!(boundary.as_str().len(), 8);

    let mut bounded_output = MessageArgs::new();
    bounded_output.try_insert("text", MessageArg::Text("1234".to_owned()))?;
    let error = context
        .render(&message_id("message")?, &bounded_output)
        .err()
        .ok_or("large rendered message was accepted")?;
    assert_eq!(error, RenderError::RenderedMessageTooLarge);
    Ok(())
}

#[test]
fn bidi_controls_in_text_arguments_fail_closed_without_rejecting_unicode() -> TestResult {
    let directory = TestDirectory::create()?;
    directory.write("en-US.ftl", "message = { $text }")?;
    let english = locale("en-US")?;
    let config = CatalogConfig::new(
        english.clone(),
        vec![LocaleCatalog::new(english.clone(), vec![])],
    );
    let loader = CatalogLoader::new(directory.path(), CatalogLimits::default())?;
    let localizer = Localizer::new(loader.load(&config)?);
    let context = localizer.context(std::slice::from_ref(&english))?;

    for unsafe_text in [
        "embedded\u{2069}pdi",
        "override\u{202e}payload",
        "isolation\u{2066}payload",
    ] {
        let mut arguments = MessageArgs::new();
        arguments.try_insert("text", MessageArg::Text(unsafe_text.to_owned()))?;
        let error = context
            .render(&message_id("message")?, &arguments)
            .err()
            .ok_or("bidi control was accepted")?;
        assert_eq!(error, RenderError::UnsafeTextDirectionControl);
        assert!(!format!("{error:?}").contains(unsafe_text));
    }

    let ordinary_text = "مرحبا 世界 👋";
    let mut arguments = MessageArgs::new();
    arguments.try_insert("text", MessageArg::Text(ordinary_text.to_owned()))?;
    let rendered = context.render(&message_id("message")?, &arguments)?;
    assert!(rendered.as_str().contains(ordinary_text));
    Ok(())
}

#[derive(Default)]
struct CapturingObserver(Mutex<Vec<String>>);

impl MissingMessageObserver for CapturingObserver {
    fn record_missing(&self, locale: &Locale) {
        if let Ok(mut locales) = self.0.lock() {
            locales.push(locale.as_str().to_owned());
        }
    }
}

#[test]
fn missing_and_fluent_errors_are_redacted_and_metrics_have_bounded_labels() -> TestResult {
    let directory = TestDirectory::create()?;
    directory.write("en-US.ftl", "broken = Hello, { $secret }")?;
    let english = locale("en-US")?;
    let config = CatalogConfig::new(
        english.clone(),
        vec![LocaleCatalog::new(english.clone(), vec![])],
    );
    let loader = CatalogLoader::new(directory.path(), CatalogLimits::default())?;
    let observer = Arc::new(CapturingObserver::default());
    let observer_sink: Arc<dyn MissingMessageObserver> = observer.clone();
    let localizer = Localizer::with_missing_message_observer(loader.load(&config)?, observer_sink);
    let context = localizer.context(&[english])?;

    let missing = context
        .render(&message_id("user-secret-message")?, &MessageArgs::new())
        .err()
        .ok_or("missing message rendered")?;
    assert_eq!(missing, RenderError::MissingMessage);
    assert!(!format!("{missing:?}").contains("user-secret-message"));
    let captured_missing = observer
        .0
        .lock()
        .map_err(|_| io::Error::other("observer lock poisoned"))?;
    assert_eq!(captured_missing.as_slice(), ["en-US"]);
    drop(captured_missing);

    let formatting = context
        .render(&message_id("broken")?, &MessageArgs::new())
        .err()
        .ok_or("missing argument was accepted")?;
    assert_eq!(formatting, RenderError::FormattingFailed);
    assert!(!format!("{formatting:?}").contains("secret"));
    Ok(())
}

#[test]
fn failed_reload_keeps_previous_snapshot_and_contexts_are_consistent() -> TestResult {
    let directory = TestDirectory::create()?;
    directory.write("en-US.ftl", "status = old")?;
    let english = locale("en-US")?;
    let config = CatalogConfig::new(
        english.clone(),
        vec![LocaleCatalog::new(english.clone(), vec![])],
    );
    let loader = CatalogLoader::new(directory.path(), CatalogLimits::default())?;
    let localizer = Localizer::new(loader.load(&config)?);
    let old_context = localizer.context(std::slice::from_ref(&english))?;

    directory.write("en-US.ftl", "status = { invalid")?;
    assert_eq!(
        localizer.reload(&loader, &config),
        Err(CatalogError::InvalidSyntax)
    );
    let after_failure = localizer
        .context(std::slice::from_ref(&english))?
        .render(&message_id("status")?, &MessageArgs::new())?;
    assert_eq!(after_failure.as_str(), "old");

    directory.write("en-US.ftl", "status = new")?;
    localizer.reload(&loader, &config)?;
    let old_render = old_context.render(&message_id("status")?, &MessageArgs::new())?;
    let new_render = localizer
        .context(&[english])?
        .render(&message_id("status")?, &MessageArgs::new())?;
    assert_eq!(old_render.as_str(), "old");
    assert_eq!(new_render.as_str(), "new");
    Ok(())
}

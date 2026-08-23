use std::{collections::BTreeMap, fmt};

use serde_json::Value;
use time::{OffsetDateTime, format_description::well_known::Rfc3339};
use tracing::{
    Event, Subscriber,
    field::{Field, Visit},
};
use tracing_subscriber::{
    field::RecordFields,
    fmt::{
        FmtContext, FormattedFields,
        format::{FormatEvent, FormatFields, Writer},
    },
    registry::LookupSpan,
};

const REDACTED: &str = "[REDACTED]";
const SENSITIVE_PARTS: &[&str] = &[
    "authorization",
    "body",
    "cookie",
    "credential",
    "email",
    "password",
    "query",
    "secret",
    "sql",
    "token",
    "uri",
    "url",
];
const SENSITIVE_NAMES: &[&str] = &[
    "api_key",
    "apikey",
    "email_content",
    "error_message",
    "set_cookie",
];

/// JSON field formatter that replaces forbidden values before serialization.
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct RedactingJsonFields;

impl<'writer> tracing_subscriber::fmt::FormatFields<'writer> for RedactingJsonFields {
    fn format_fields<R: RecordFields>(&self, mut writer: Writer<'_>, fields: R) -> fmt::Result {
        let mut visitor = RedactingVisitor::default();
        fields.record(&mut visitor);
        let encoded = serde_json::to_string(&visitor.values).map_err(|_| fmt::Error)?;
        writer.write_str(&encoded)
    }

    fn add_fields(
        &self,
        current: &'writer mut FormattedFields<Self>,
        fields: &tracing::span::Record<'_>,
    ) -> fmt::Result {
        let mut visitor = RedactingVisitor {
            values: serde_json::from_str(&current.fields).map_err(|_| fmt::Error)?,
        };
        fields.record(&mut visitor);
        current.fields = serde_json::to_string(&visitor.values).map_err(|_| fmt::Error)?;
        Ok(())
    }
}

/// JSON event formatter that applies [`RedactingJsonFields`] to event values.
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct RedactingJsonEvent;

impl<S, N> FormatEvent<S, N> for RedactingJsonEvent
where
    S: Subscriber + for<'lookup> LookupSpan<'lookup>,
    N: for<'writer> FormatFields<'writer> + 'static,
{
    fn format_event(
        &self,
        context: &FmtContext<'_, S, N>,
        mut writer: Writer<'_>,
        event: &Event<'_>,
    ) -> fmt::Result {
        let metadata = event.metadata();
        let mut visitor = RedactingVisitor::default();
        event.record(&mut visitor);
        let mut document = BTreeMap::new();
        document.insert(
            "timestamp".to_owned(),
            Value::String(
                OffsetDateTime::now_utc()
                    .format(&Rfc3339)
                    .map_err(|_| fmt::Error)?,
            ),
        );
        document.insert(
            "level".to_owned(),
            Value::String(metadata.level().to_string()),
        );
        document.insert(
            "fields".to_owned(),
            Value::Object(visitor.values.into_iter().collect()),
        );
        document.insert(
            "target".to_owned(),
            Value::String(metadata.target().to_owned()),
        );

        let mut spans = Vec::new();
        if let Some(scope) = context.event_scope() {
            for span in scope.from_root() {
                let extensions = span.extensions();
                let mut fields: serde_json::Map<String, Value> = extensions
                    .get::<FormattedFields<N>>()
                    .filter(|fields| !fields.is_empty())
                    .map(|fields| serde_json::from_str(&fields.fields))
                    .transpose()
                    .map_err(|_| fmt::Error)?
                    .unwrap_or_default();
                fields.insert("name".to_owned(), Value::String(span.name().to_owned()));
                spans.push(Value::Object(fields));
            }
        }
        if let Some(current) = spans.last().cloned() {
            document.insert("span".to_owned(), current);
        }
        if !spans.is_empty() {
            document.insert("spans".to_owned(), Value::Array(spans));
        }
        let encoded = serde_json::to_string(&document).map_err(|_| fmt::Error)?;
        writeln!(writer, "{encoded}")
    }
}

#[derive(Default)]

struct RedactingVisitor {
    values: BTreeMap<String, Value>,
}

impl RedactingVisitor {
    fn insert(&mut self, field: &Field, value: Value) {
        let name = field.name().strip_prefix("r#").unwrap_or(field.name());
        self.values.insert(
            name.to_owned(),
            if is_sensitive(name) {
                Value::String(REDACTED.to_owned())
            } else {
                value
            },
        );
    }
}

impl Visit for RedactingVisitor {
    fn record_f64(&mut self, field: &Field, value: f64) {
        self.insert(field, Value::from(value));
    }

    fn record_i64(&mut self, field: &Field, value: i64) {
        self.insert(field, Value::from(value));
    }

    fn record_u64(&mut self, field: &Field, value: u64) {
        self.insert(field, Value::from(value));
    }

    fn record_bool(&mut self, field: &Field, value: bool) {
        self.insert(field, Value::from(value));
    }

    fn record_str(&mut self, field: &Field, value: &str) {
        self.insert(field, Value::from(value));
    }

    fn record_bytes(&mut self, field: &Field, value: &[u8]) {
        self.insert(field, Value::from(value));
    }

    fn record_error(&mut self, field: &Field, value: &(dyn std::error::Error + 'static)) {
        self.insert(field, Value::from(value.to_string()));
    }

    fn record_debug(&mut self, field: &Field, value: &dyn fmt::Debug) {
        if field.name().starts_with("log.") {
            return;
        }
        self.insert(field, Value::from(format!("{value:?}")));
    }
}

fn is_sensitive(name: &str) -> bool {
    SENSITIVE_NAMES
        .iter()
        .any(|candidate| name.eq_ignore_ascii_case(candidate))
        || name.split(['.', '_', '-']).any(|part| {
            SENSITIVE_PARTS
                .iter()
                .any(|candidate| part.eq_ignore_ascii_case(candidate))
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classifies_forbidden_fields_without_hiding_safe_codes() {
        for name in [
            "token",
            "access_token",
            "http.cookie",
            "password_hash",
            "request_body",
            "database.sql",
            "target_url",
            "user_email",
            "api_key",
        ] {
            assert!(is_sensitive(name), "{name} should be redacted");
        }
        for name in ["request_id", "error_code", "http.route", "tenant_class"] {
            assert!(!is_sensitive(name), "{name} should remain observable");
        }
    }
}

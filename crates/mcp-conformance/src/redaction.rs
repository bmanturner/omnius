use serde::{Deserialize, Serialize};

/// Maximum diagnostic payload retained by the default harness policy.
pub const DEFAULT_DIAGNOSTIC_BYTES: usize = 1_024;
const REDACTED: &str = "[REDACTED]";
const TRUNCATED: &str = "[truncated]";

/// A diagnostic whose message has been scrubbed and clipped before retention.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RedactedDiagnostic {
    code: String,
    message: String,
}

impl RedactedDiagnostic {
    /// Scrubs a diagnostic and retains at most `max_bytes` of its message.
    #[must_use]
    pub fn new(code: impl AsRef<str>, message: &str, max_bytes: usize) -> Self {
        Self {
            code: sanitize_code(code.as_ref()),
            message: redact_diagnostic(message, max_bytes),
        }
    }

    /// Returns the stable machine-readable diagnostic code.
    #[must_use]
    pub fn code(&self) -> &str {
        &self.code
    }

    /// Returns the already-redacted message.
    #[must_use]
    pub fn message(&self) -> &str {
        &self.message
    }

    pub(crate) fn validate(&self, max_bytes: usize) -> bool {
        !self.code.is_empty()
            && !self.message.trim().is_empty()
            && self.message.len() <= max_bytes
            && redact_diagnostic(&self.message, max_bytes) == self.message
    }
}

/// Redacts credentials, sensitive query values, URL user info, and clips the result.
#[must_use]
pub fn redact_diagnostic(input: &str, max_bytes: usize) -> String {
    let mut output = input.replace(['\r', '\0'], " ");
    redact_flexible_key_values(&mut output);
    redact_flexible_bearer_values(&mut output);

    redact_values_after(
        &mut output,
        &[
            "bearer ",
            "access_token=",
            "refresh_token=",
            "id_token=",
            "api_key=",
            "apikey=",
            "client_secret=",
            "authorization=",
            "token=",
            "secret=",
            "password=",
        ],
        &['&', ',', ';', ' ', '\t', '\n', '\"', '\''],
    );
    redact_header_values(&mut output);
    redact_json_values(&mut output);
    redact_url_user_info(&mut output);
    clip_utf8(output, max_bytes)
}

fn sanitize_code(code: &str) -> String {
    let filtered: String = code
        .chars()
        .filter(|character| character.is_ascii_alphanumeric() || matches!(character, '_' | '-'))
        .take(64)
        .collect();
    if filtered.is_empty() {
        "diagnostic".to_owned()
    } else {
        filtered
    }
}

fn redact_flexible_key_values(output: &mut String) {
    for key in [
        "authorization",
        "proxy-authorization",
        "x-api-key",
        "aws_secret_access_key",
        "aws_session_token",
        "azure_openai_api_key",
        "github_token",
        "gitlab_token",
        "openai_api_key",
        "anthropic_api_key",
        "access_token",
        "refresh_token",
        "id_token",
        "api_key",
        "apikey",
        "client_secret",
        "token",
        "secret",
        "password",
    ] {
        let mut search_from = 0;
        while search_from < output.len() {
            let lowercase = output[search_from..].to_ascii_lowercase();
            let Some(relative_key_start) = lowercase.find(key) else {
                break;
            };
            let key_start = search_from + relative_key_start;
            let key_end = key_start + key.len();
            let has_identifier_prefix =
                key_start > 0 && output.as_bytes()[key_start - 1].is_ascii_alphanumeric();
            if has_identifier_prefix {
                search_from = key_end;
                continue;
            }

            let mut cursor = key_end;
            if output.as_bytes().get(cursor) == Some(&b'"') {
                cursor += 1;
            }
            cursor = skip_ascii_whitespace(output, cursor);
            let Some(separator) = output.as_bytes().get(cursor).copied() else {
                break;
            };
            if !matches!(separator, b'=' | b':') {
                search_from = key_end;
                continue;
            }
            cursor = skip_ascii_whitespace(output, cursor + 1);
            let quote = output
                .as_bytes()
                .get(cursor)
                .copied()
                .filter(|byte| matches!(byte, b'"' | b'\''));
            if quote.is_some() {
                cursor += 1;
            }
            cursor = skip_ascii_whitespace(output, cursor);
            let value_start = cursor;
            let value_end = quote.map_or_else(
                || unquoted_value_end(output, value_start, separator, key),
                |quote| quoted_value_end(output, value_start, quote),
            );
            if value_start < value_end && &output[value_start..value_end] != REDACTED {
                output.replace_range(value_start..value_end, REDACTED);
                search_from = value_start + REDACTED.len();
            } else {
                search_from = value_end.max(key_end);
            }
        }
    }
}

fn redact_flexible_bearer_values(output: &mut String) {
    let mut search_from = 0;
    while search_from < output.len() {
        let lowercase = output[search_from..].to_ascii_lowercase();
        let Some(relative_marker_start) = lowercase.find("bearer") else {
            break;
        };
        let marker_start = search_from + relative_marker_start;
        let marker_end = marker_start + "bearer".len();
        let bounded =
            marker_start == 0 || !output.as_bytes()[marker_start - 1].is_ascii_alphanumeric();
        let value_start = skip_ascii_whitespace(output, marker_end);
        if !bounded || value_start == marker_end {
            search_from = marker_end;
            continue;
        }
        let value_end = output[value_start..]
            .find(|character: char| {
                character.is_ascii_whitespace() || matches!(character, '&' | ',' | ';' | '"' | '\'')
            })
            .map_or(output.len(), |relative_end| value_start + relative_end);
        if value_start < value_end && &output[value_start..value_end] != REDACTED {
            output.replace_range(value_start..value_end, REDACTED);
            search_from = value_start + REDACTED.len();
        } else {
            search_from = value_end.max(marker_end);
        }
    }
}

fn skip_ascii_whitespace(value: &str, mut cursor: usize) -> usize {
    while value
        .as_bytes()
        .get(cursor)
        .is_some_and(u8::is_ascii_whitespace)
    {
        cursor += 1;
    }
    cursor
}

fn unquoted_value_end(value: &str, value_start: usize, separator: u8, key: &str) -> usize {
    let line_value =
        separator == b':' || matches!(key, "authorization" | "proxy-authorization" | "x-api-key");
    value[value_start..]
        .find(|character: char| {
            matches!(character, '\r' | '\n' | ',' | ';' | '&' | '}' | ']')
                || (!line_value && character.is_ascii_whitespace())
        })
        .map_or(value.len(), |relative_end| value_start + relative_end)
}

fn quoted_value_end(value: &str, value_start: usize, quote: u8) -> usize {
    let mut escaped = false;
    for (relative_index, byte) in value.as_bytes()[value_start..].iter().copied().enumerate() {
        if byte == quote && !escaped {
            return value_start + relative_index;
        }
        escaped = byte == b'\\' && !escaped;
        if byte != b'\\' {
            escaped = false;
        }
    }
    value.len()
}

fn redact_values_after(output: &mut String, markers: &[&str], terminators: &[char]) {
    for marker in markers {
        let mut search_from = 0;
        loop {
            let lowercase = output[search_from..].to_ascii_lowercase();
            let Some(relative_start) = lowercase.find(marker) else {
                break;
            };
            let value_start = search_from + relative_start + marker.len();
            let value_end = output[value_start..]
                .find(|character| terminators.contains(&character))
                .map_or(output.len(), |relative_end| value_start + relative_end);
            if value_start == value_end || &output[value_start..value_end] == REDACTED {
                search_from = value_end;
                if search_from >= output.len() {
                    break;
                }
                continue;
            }
            output.replace_range(value_start..value_end, REDACTED);
            search_from = value_start + REDACTED.len();
        }
    }
}

fn redact_header_values(output: &mut String) {
    for marker in ["authorization:", "proxy-authorization:", "x-api-key:"] {
        redact_values_after(output, &[marker], &['\n', ',', ';']);
    }
}

fn redact_json_values(output: &mut String) {
    for key in [
        "authorization",
        "access_token",
        "refresh_token",
        "id_token",
        "api_key",
        "client_secret",
        "token",
        "secret",
        "password",
    ] {
        let compact = format!("\"{key}\":\"");
        redact_values_after(output, &[&compact], &['\"']);
        let spaced = format!("\"{key}\": \"");
        redact_values_after(output, &[&spaced], &['\"']);
    }
}

fn redact_url_user_info(output: &mut String) {
    let mut search_from = 0;
    while let Some(relative_scheme) = output[search_from..].find("://") {
        let authority_start = search_from + relative_scheme + 3;
        let authority_end = output[authority_start..]
            .find(['/', '?', '#', ' ', '\t', '\n'])
            .map_or(output.len(), |relative_end| authority_start + relative_end);
        if let Some(relative_at) = output[authority_start..authority_end].rfind('@') {
            let user_info_end = authority_start + relative_at;
            output.replace_range(authority_start..user_info_end, REDACTED);
            search_from = authority_start + REDACTED.len() + 1;
        } else {
            search_from = authority_end;
        }
        if search_from >= output.len() {
            break;
        }
    }
}

fn clip_utf8(mut value: String, max_bytes: usize) -> String {
    if value.len() <= max_bytes {
        return value;
    }
    if max_bytes == 0 {
        return String::new();
    }
    if max_bytes <= TRUNCATED.len() {
        return TRUNCATED[..max_bytes].to_owned();
    }
    let mut boundary = max_bytes - TRUNCATED.len();
    while !value.is_char_boundary(boundary) {
        boundary -= 1;
    }
    value.truncate(boundary);
    value.push_str(TRUNCATED);
    value
}

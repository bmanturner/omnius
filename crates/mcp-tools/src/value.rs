use std::{fmt, str::FromStr};

use serde::Serialize;
use thiserror::Error;

/// Maximum UTF-8 byte length of a stable public tool name.
pub const MAX_TOOL_NAME_BYTES: usize = 128;
/// Maximum UTF-8 byte length of a public tool title.
pub const MAX_TOOL_TITLE_BYTES: usize = 256;
/// Maximum UTF-8 byte length of a public tool description.
pub const MAX_TOOL_DESCRIPTION_BYTES: usize = 2_048;
/// Maximum byte length of an opaque catalog or schema revision.
pub const MAX_REVISION_BYTES: usize = 128;

/// A bounded public-value construction failure.
///
/// Rejected values are deliberately absent from every variant and rendering.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum PublicValueError {
    /// A required value was empty.
    #[error("public value must not be empty")]
    Empty,
    /// A value exceeded its fixed byte limit.
    #[error("public value exceeds its fixed byte limit")]
    TooLong,
    /// A value did not satisfy its fixed public grammar.
    #[error("public value has an invalid format")]
    InvalidFormat,
}

macro_rules! bounded_public_value {
    ($name:ident, $doc:literal, $max:expr, $validator:expr) => {
        #[doc = $doc]
        #[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
        #[serde(transparent)]
        pub struct $name(String);

        impl $name {
            #[doc = concat!("Creates a validated [`", stringify!($name), "`].")]
            ///
            /// # Errors
            ///
            /// Returns [`PublicValueError`] without retaining or rendering the rejected value.
            pub fn new(value: impl Into<String>) -> Result<Self, PublicValueError> {
                let value = value.into();
                validate_bounded(&value, $max, $validator)?;
                Ok(Self(value))
            }

            /// Borrows the validated public value.
            #[must_use]
            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl FromStr for $name {
            type Err = PublicValueError;

            fn from_str(value: &str) -> Result<Self, Self::Err> {
                Self::new(value)
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str(concat!(stringify!($name), "([redacted])"))
            }
        }
    };
}

bounded_public_value!(
    ToolName,
    "A stable, explicitly versioned public MCP tool name.",
    MAX_TOOL_NAME_BYTES,
    valid_tool_name
);
bounded_public_value!(
    ToolTitle,
    "A bounded human-readable public tool title.",
    MAX_TOOL_TITLE_BYTES,
    valid_single_line_text
);
bounded_public_value!(
    ToolDescription,
    "A bounded human-readable public tool description.",
    MAX_TOOL_DESCRIPTION_BYTES,
    valid_description
);
bounded_public_value!(
    SchemaRevision,
    "A bounded opaque tool schema revision.",
    MAX_REVISION_BYTES,
    valid_opaque_revision
);
bounded_public_value!(
    CatalogRevision,
    "A bounded opaque immutable catalog revision.",
    MAX_REVISION_BYTES,
    valid_opaque_revision
);

fn validate_bounded(
    value: &str,
    maximum: usize,
    validator: fn(&str) -> bool,
) -> Result<(), PublicValueError> {
    if value.is_empty() {
        return Err(PublicValueError::Empty);
    }
    if value.len() > maximum {
        return Err(PublicValueError::TooLong);
    }
    if !validator(value) {
        return Err(PublicValueError::InvalidFormat);
    }
    Ok(())
}

fn valid_tool_name(value: &str) -> bool {
    if !value.is_ascii() || value.contains("::") {
        return false;
    }
    let mut segments = value.split('.').peekable();
    let mut prefix_count = 0_usize;
    while let Some(segment) = segments.next() {
        if segments.peek().is_none() {
            let Some(version) = segment.strip_prefix('v') else {
                return false;
            };
            return prefix_count >= 2
                && !version.is_empty()
                && !version.starts_with('0')
                && version.bytes().all(|byte| byte.is_ascii_digit());
        }
        if !valid_name_segment(segment) {
            return false;
        }
        prefix_count += 1;
    }
    false
}

fn valid_name_segment(segment: &str) -> bool {
    let mut bytes = segment.bytes();
    bytes.next().is_some_and(|byte| byte.is_ascii_lowercase())
        && bytes.all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'_' | b'-')
        })
}

fn valid_single_line_text(value: &str) -> bool {
    !value.chars().any(char::is_control)
}

fn valid_description(value: &str) -> bool {
    !value
        .chars()
        .any(|character| character.is_control() && !matches!(character, '\n' | '\t'))
}

fn valid_opaque_revision(value: &str) -> bool {
    value.is_ascii()
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-' | b':' | b'+')
        })
}

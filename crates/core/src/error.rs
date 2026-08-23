use std::{borrow::Cow, error::Error, fmt};

use serde::Serialize;
use thiserror::Error;

/// A stable, machine-readable application error code.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize)]
#[serde(transparent)]
pub struct ErrorCode(&'static str);

impl ErrorCode {
    /// Creates a code after enforcing the public code syntax.
    ///
    /// Codes are 1–64 ASCII uppercase letters, digits, or underscores and must
    /// start with an uppercase letter.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidErrorCode`] when the code is empty, too long, starts
    /// with a non-uppercase character, or contains unsupported characters.
    pub fn try_new(code: &'static str) -> Result<Self, InvalidErrorCode> {
        let mut bytes = code.bytes();
        let valid = code.len() <= 64
            && bytes.next().is_some_and(|byte| byte.is_ascii_uppercase())
            && bytes.all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit() || byte == b'_');
        if valid {
            Ok(Self(code))
        } else {
            Err(InvalidErrorCode)
        }
    }

    /// Returns the stable wire representation.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        self.0
    }
}

impl fmt::Display for ErrorCode {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.0)
    }
}

/// An error code does not satisfy the stable public syntax.
#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
#[error("invalid application error code")]
pub struct InvalidErrorCode;

/// A service failure with a stable code and explicitly safe message.
#[derive(Debug, Error)]
#[error("{code}: {safe_message}")]
pub struct ServiceError {
    code: ErrorCode,
    safe_message: Cow<'static, str>,
    source: Option<Box<dyn Error + Send + Sync + 'static>>,
}

impl ServiceError {
    /// Creates an error without an internal cause.
    #[must_use]
    pub fn new(code: ErrorCode, safe_message: impl Into<Cow<'static, str>>) -> Self {
        Self {
            code,
            safe_message: safe_message.into(),
            source: None,
        }
    }

    /// Attaches an internal cause for operator diagnostics.
    ///
    /// Transport adapters must expose only [`Self::safe_message`] and never
    /// serialize the source chain.
    #[must_use]
    pub fn with_source(mut self, source: impl Error + Send + Sync + 'static) -> Self {
        self.source = Some(Box::new(source));
        self
    }

    /// Returns the stable application code.
    #[must_use]
    pub const fn code(&self) -> ErrorCode {
        self.code
    }

    /// Returns the message approved for a client-facing error mapping.
    #[must_use]
    pub fn safe_message(&self) -> &str {
        &self.safe_message
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug, Error)]
    #[error("database password=secret")]
    struct SensitiveCause;

    #[test]
    fn validates_error_code_syntax() -> Result<(), InvalidErrorCode> {
        let code = ErrorCode::try_new("VALIDATION_FAILED")?;
        assert_eq!(code.as_str(), "VALIDATION_FAILED");
        assert!(ErrorCode::try_new("invalid-code").is_err());
        Ok(())
    }

    #[test]
    fn display_does_not_expose_internal_source() -> Result<(), InvalidErrorCode> {
        let error = ServiceError::new(
            ErrorCode::try_new("DATABASE_UNAVAILABLE")?,
            "service unavailable",
        )
        .with_source(SensitiveCause);
        assert_eq!(
            error.to_string(),
            "DATABASE_UNAVAILABLE: service unavailable"
        );
        assert!(!error.to_string().contains("secret"));
        assert!(Error::source(&error).is_some());
        Ok(())
    }
}

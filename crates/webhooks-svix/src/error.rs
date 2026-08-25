use thiserror::Error;

/// Stable, low-cardinality provider failure classes.
///
/// No class retains a provider body, URL, token, identifier, or SDK diagnostic string.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[non_exhaustive]
pub enum FailureClass {
    /// The bounded total request deadline elapsed.
    Timeout,
    /// The provider applied rate limiting.
    RateLimited,
    /// The provider or its transport was unavailable.
    Unavailable,
    /// The provider returned a server-side failure.
    Server,
    /// The provider rejected a request.
    Rejected,
    /// The requested resource was not found.
    NotFound,
    /// Provider authentication or authorization failed.
    Unauthorized,
    /// A deterministic idempotency or resource conflict occurred.
    Conflict,
    /// The operation was cancelled during shutdown.
    Cancelled,
    /// The adapter is no longer accepting work.
    Draining,
    /// A configured fixed-capacity boundary was reached.
    Capacity,
}

impl FailureClass {
    /// Whether an idempotent caller may retry this class.
    #[must_use]
    pub const fn is_retryable(self) -> bool {
        matches!(
            self,
            Self::Timeout
                | Self::RateLimited
                | Self::Unavailable
                | Self::Server
                | Self::Cancelled
                | Self::Draining
        )
    }

    /// Returns the stable metrics label for this class.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Timeout => "timeout",
            Self::RateLimited => "rate_limited",
            Self::Unavailable => "unavailable",
            Self::Server => "server",
            Self::Rejected => "rejected",
            Self::NotFound => "not_found",
            Self::Unauthorized => "unauthorized",
            Self::Conflict => "conflict",
            Self::Cancelled => "cancelled",
            Self::Draining => "draining",
            Self::Capacity => "capacity",
        }
    }
}

/// Value-free facts accepted by the pure provider failure classifier.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum ProviderFailureFacts {
    /// The SDK reported its stable timeout variant.
    Timeout,
    /// The SDK reported a generic transport failure. Its string is discarded.
    Transport,
    /// The SDK exposed an HTTP status code.
    Http(u16),
    /// The SDK reported structured validation failure. Its payload is discarded.
    Validation,
}

/// Classifies only stable SDK facts, never provider response content.
#[must_use]
pub const fn classify_provider_failure(facts: ProviderFailureFacts) -> FailureClass {
    match facts {
        ProviderFailureFacts::Timeout | ProviderFailureFacts::Http(408 | 425) => {
            FailureClass::Timeout
        }
        ProviderFailureFacts::Transport => FailureClass::Unavailable,
        ProviderFailureFacts::Http(401 | 403) => FailureClass::Unauthorized,
        ProviderFailureFacts::Http(404) => FailureClass::NotFound,
        ProviderFailureFacts::Http(409) => FailureClass::Conflict,
        ProviderFailureFacts::Http(429) => FailureClass::RateLimited,
        ProviderFailureFacts::Http(status) if status >= 500 && status <= 599 => {
            FailureClass::Server
        }
        ProviderFailureFacts::Validation | ProviderFailureFacts::Http(_) => FailureClass::Rejected,
    }
}

/// Safe adapter failure containing only a stable class.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[error("Svix webhook operation failed with class {class:?}")]
pub struct ProviderError {
    class: FailureClass,
}

impl ProviderError {
    /// Creates a value-safe provider failure.
    #[must_use]
    pub const fn new(class: FailureClass) -> Self {
        Self { class }
    }

    /// Returns the stable failure class.
    #[must_use]
    pub const fn class(self) -> FailureClass {
        self.class
    }

    /// Whether an idempotent caller may retry the operation.
    #[must_use]
    pub const fn is_retryable(self) -> bool {
        self.class.is_retryable()
    }
}

/// Strict adapter configuration failure.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[non_exhaustive]
pub enum ConfigError {
    /// The API token is empty or exceeds its fixed maximum.
    #[error("Svix token is invalid")]
    InvalidToken,
    /// A configured provider API URL is not an allowed HTTPS or loopback-development URL.
    #[error("Svix server URL is invalid")]
    InvalidServerUrl,
    /// An operation or drain timeout is zero or exceeds its hard ceiling.
    #[error("Svix timeout is invalid")]
    InvalidTimeout,
    /// Replay polling bounds are invalid.
    #[error("Svix replay polling bounds are invalid")]
    InvalidReplayBounds,
    /// A fixed capacity or payload limit is invalid.
    #[error("Svix capacity bound is invalid")]
    InvalidCapacity,
    /// An application, destination, or other bounded value is invalid.
    #[error("Svix configured value is invalid")]
    InvalidValue,
    /// The SDK configuration requested a proxy, which cannot be fail-closed in SDK 1.99.1.
    #[error("Svix SDK proxy configuration is unsupported")]
    UnsupportedProxy,
}

/// Rejected bounded public value.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[error("Svix adapter value is invalid")]
pub struct ValueError;

/// Fixed-capacity fake control failure.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[non_exhaustive]
pub enum FakeError {
    /// The configured fake capacity was reached.
    #[error("Svix fake capacity reached")]
    Capacity,
    /// The requested fake record does not exist.
    #[error("Svix fake record was not found")]
    NotFound,
    /// A deterministic fake transition was invalid.
    #[error("Svix fake transition is invalid")]
    InvalidTransition,
}

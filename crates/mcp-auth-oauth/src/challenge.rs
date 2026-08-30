use std::fmt;

use http::StatusCode;
use thiserror::Error;

use crate::{McpProtectedResource, OperationRequirements};

/// A deterministic RFC 6750/RFC 9728 `WWW-Authenticate` header value.
#[derive(Clone, Eq, PartialEq)]
pub struct WwwAuthenticate(String);

impl WwwAuthenticate {
    /// Returns the complete header value without a header name.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for WwwAuthenticate {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("WwwAuthenticate(Bearer [parameters redacted])")
    }
}

impl fmt::Display for WwwAuthenticate {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

/// A fail-closed MCP authentication or scope rejection ready for HTTP projection.
#[derive(Clone, Eq, PartialEq)]
pub struct McpAuthRejection {
    status: StatusCode,
    www_authenticate: WwwAuthenticate,
}

impl McpAuthRejection {
    pub(crate) fn missing(
        profile: &McpProtectedResource,
        requirements: &OperationRequirements,
    ) -> Self {
        Self::new(StatusCode::UNAUTHORIZED, None, profile, requirements)
    }

    pub(crate) fn invalid_request(
        profile: &McpProtectedResource,
        requirements: &OperationRequirements,
    ) -> Self {
        Self::new(
            StatusCode::BAD_REQUEST,
            Some("invalid_request"),
            profile,
            requirements,
        )
    }

    pub(crate) fn invalid_token(
        profile: &McpProtectedResource,
        requirements: &OperationRequirements,
    ) -> Self {
        Self::new(
            StatusCode::UNAUTHORIZED,
            Some("invalid_token"),
            profile,
            requirements,
        )
    }

    pub(crate) fn insufficient_scope(
        profile: &McpProtectedResource,
        requirements: &OperationRequirements,
    ) -> Self {
        Self::new(
            StatusCode::FORBIDDEN,
            Some("insufficient_scope"),
            profile,
            requirements,
        )
    }

    fn new(
        status: StatusCode,
        error: Option<&str>,
        profile: &McpProtectedResource,
        requirements: &OperationRequirements,
    ) -> Self {
        let metadata_url = profile.identity().protected_resource_metadata_url();
        let required_scope_bytes = requirements
            .required_scopes()
            .iter()
            .map(|scope| scope.as_str().len())
            .sum::<usize>()
            + requirements.required_scopes().len().saturating_sub(1);
        let mut value =
            String::with_capacity("Bearer".len() + metadata_url.len() + required_scope_bytes + 96);
        value.push_str("Bearer");
        if let Some(error) = error {
            value.push_str(" error=\"");
            value.push_str(error);
            value.push_str("\", ");
        } else {
            value.push(' ');
        }
        value.push_str("resource_metadata=\"");
        value.push_str(metadata_url);
        value.push_str("\", scope=\"");
        for (index, scope) in requirements.required_scopes().iter().enumerate() {
            if index != 0 {
                value.push(' ');
            }
            value.push_str(scope.as_str());
        }
        value.push('"');
        Self {
            status,
            www_authenticate: WwwAuthenticate(value),
        }
    }

    /// Returns the exact HTTP status required by the Bearer challenge.
    #[must_use]
    pub const fn status(&self) -> StatusCode {
        self.status
    }

    /// Returns the deterministic Bearer challenge.
    #[must_use]
    pub const fn www_authenticate(&self) -> &WwwAuthenticate {
        &self.www_authenticate
    }
}

impl fmt::Debug for McpAuthRejection {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("McpAuthRejection")
            .field("status", &self.status)
            .field("www_authenticate", &"[redacted]")
            .finish()
    }
}

impl fmt::Display for McpAuthRejection {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("MCP bearer request rejected")
    }
}

impl std::error::Error for McpAuthRejection {}

/// A bearer credential could not be authenticated.
///
/// The error intentionally does not distinguish cryptographic, issuer, audience,
/// expiry, revocation, or live-state failures at the resource-server boundary.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[error("MCP bearer token is invalid")]
pub struct BearerAuthenticationError;

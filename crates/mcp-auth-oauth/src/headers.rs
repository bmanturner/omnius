use std::fmt;

use http::{HeaderMap, HeaderName, HeaderValue, header::AUTHORIZATION};
use thiserror::Error;

/// Maximum capability-approved outbound header names.
pub const MAX_MCP_HEADER_NAMES: usize = 32;
/// Maximum bytes in one approved outbound header value.
pub const MAX_MCP_HEADER_VALUE_BYTES: usize = 8 * 1024;

/// An `x-mcp-header` allowlist or projection violated a fixed security rule.
///
/// The error contains neither the rejected name nor value so provider credentials
/// and attacker-controlled input cannot enter logs through error formatting.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum McpHeaderError {
    /// A name or value was not syntactically valid HTTP header data.
    #[error("MCP header input is malformed")]
    Malformed,
    /// A fixed header count or value-size bound was exceeded.
    #[error("MCP header input exceeds a fixed bound")]
    CollectionLimit,
    /// A header was repeated after case-insensitive name normalization.
    #[error("MCP header input contains a duplicate name")]
    Duplicate,
    /// A header can control credentials, routing, framing, proxies, or tracing.
    #[error("MCP header input contains a forbidden control header")]
    Forbidden,
    /// A capability did not explicitly allow the requested header.
    #[error("MCP header input is not allowed for this capability")]
    NotAllowed,
}

/// Capability-specific, case-insensitive allowlist for `x-mcp-header` projections.
#[derive(Clone, Eq, PartialEq)]
pub struct McpHeaderAllowlist {
    allowed: Vec<HeaderName>,
}

impl McpHeaderAllowlist {
    /// Validates a capability's complete outbound header allowlist.
    ///
    /// Unsafe control names cannot be allowed, including Authorization, Host,
    /// cookies, hop-by-hop/framing, forwarding/proxy, request-correlation, and
    /// distributed-tracing headers.
    ///
    /// # Errors
    ///
    /// Returns [`McpHeaderError`] for malformed, unsafe, duplicate, or oversized
    /// allowlist input.
    pub fn new<I, N>(names: I) -> Result<Self, McpHeaderError>
    where
        I: IntoIterator<Item = N>,
        N: AsRef<str>,
    {
        let mut allowed = Vec::new();
        for name in names {
            if allowed.len() == MAX_MCP_HEADER_NAMES {
                return Err(McpHeaderError::CollectionLimit);
            }
            let name = HeaderName::from_bytes(name.as_ref().as_bytes())
                .map_err(|_| McpHeaderError::Malformed)?;
            if forbidden_header(&name) {
                return Err(McpHeaderError::Forbidden);
            }
            allowed.push(name);
        }
        allowed.sort_unstable_by(|left, right| left.as_str().cmp(right.as_str()));
        if allowed.windows(2).any(|pair| pair[0] == pair[1]) {
            return Err(McpHeaderError::Duplicate);
        }
        Ok(Self { allowed })
    }

    /// Validates requested name/value pairs and constructs an outbound-only projection.
    ///
    /// Inputs are logical `x-mcp-header` parameters, not an inbound [`HeaderMap`].
    /// Consequently this API has no path that can copy an inbound Authorization
    /// credential. All projected values are marked sensitive for downstream debug
    /// formatting.
    ///
    /// # Errors
    ///
    /// Returns [`McpHeaderError`] when any name/value is malformed, duplicated,
    /// forbidden, not explicitly allowed, or exceeds a fixed bound.
    pub fn validate<'a, I>(&self, requested: I) -> Result<OutboundHeaderProjection, McpHeaderError>
    where
        I: IntoIterator<Item = (&'a str, &'a str)>,
    {
        let mut headers = HeaderMap::new();
        let mut count = 0_usize;
        for (name, value) in requested {
            count += 1;
            if count > MAX_MCP_HEADER_NAMES {
                return Err(McpHeaderError::CollectionLimit);
            }
            let name =
                HeaderName::from_bytes(name.as_bytes()).map_err(|_| McpHeaderError::Malformed)?;
            if forbidden_header(&name) {
                return Err(McpHeaderError::Forbidden);
            }
            if self
                .allowed
                .binary_search_by(|candidate| candidate.as_str().cmp(name.as_str()))
                .is_err()
            {
                return Err(McpHeaderError::NotAllowed);
            }
            if headers.contains_key(&name) {
                return Err(McpHeaderError::Duplicate);
            }
            if value.len() > MAX_MCP_HEADER_VALUE_BYTES {
                return Err(McpHeaderError::CollectionLimit);
            }
            let mut value =
                HeaderValue::from_bytes(value.as_bytes()).map_err(|_| McpHeaderError::Malformed)?;
            value.set_sensitive(true);
            headers.insert(name, value);
        }
        debug_assert!(!headers.contains_key(AUTHORIZATION));
        Ok(OutboundHeaderProjection { headers })
    }

    /// Returns the normalized allowlisted names in deterministic order.
    #[must_use]
    pub fn allowed_names(&self) -> &[HeaderName] {
        &self.allowed
    }
}

impl fmt::Debug for McpHeaderAllowlist {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("McpHeaderAllowlist")
            .field("allowed", &self.allowed)
            .finish()
    }
}

/// Validated outbound headers that cannot contain an inbound Bearer credential.
#[derive(Clone, Eq, PartialEq)]
pub struct OutboundHeaderProjection {
    headers: HeaderMap,
}

impl OutboundHeaderProjection {
    /// Borrows the validated outbound header map.
    #[must_use]
    pub const fn headers(&self) -> &HeaderMap {
        &self.headers
    }

    /// Consumes the projection for direct use on a newly constructed outbound request.
    #[must_use]
    pub fn into_headers(self) -> HeaderMap {
        self.headers
    }
}

impl fmt::Debug for OutboundHeaderProjection {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let names = self
            .headers
            .keys()
            .map(HeaderName::as_str)
            .collect::<Vec<_>>();
        formatter
            .debug_struct("OutboundHeaderProjection")
            .field("names", &names)
            .field("values", &"[REDACTED]")
            .finish()
    }
}

fn forbidden_header(name: &HeaderName) -> bool {
    let name = name.as_str();
    matches!(
        name,
        "authorization"
            | "authentication-info"
            | "www-authenticate"
            | "cookie"
            | "set-cookie"
            | "host"
            | "connection"
            | "content-length"
            | "expect"
            | "http2-settings"
            | "keep-alive"
            | "te"
            | "trailer"
            | "transfer-encoding"
            | "upgrade"
            | "forwarded"
            | "proxy"
            | "via"
            | "x-forwarded"
            | "x-real-ip"
            | "x-original-url"
            | "x-original-host"
            | "x-original-proto"
            | "x-original-scheme"
            | "x-rewrite-url"
            | "front-end-https"
            | "x-url-scheme"
            | "cf-connecting-ip"
            | "true-client-ip"
            | "traceparent"
            | "tracestate"
            | "baggage"
            | "b3"
            | "sentry-trace"
            | "uber-trace-id"
            | "x-amzn-trace-id"
            | "x-cloud-trace-context"
            | "grpc-trace-bin"
            | "x-request-id"
            | "x-correlation-id"
            | "x-mcp-header"
    ) || name.starts_with("proxy-")
        || name.starts_with("x-forwarded-")
        || name.starts_with("x-proxy-")
        || name.starts_with("x-envoy-")
        || name.starts_with("x-b3-")
        || name.starts_with("x-ot-")
        || name.starts_with("x-datadog-")
}

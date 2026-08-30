use std::fmt;

use omnius_agent_capability_registry::CapabilityKey;
use omnius_llm_core::{ProviderStreamEvent, ToolCallOutputPart};
use serde_json::Value;
use thiserror::Error;

const MAX_CALL_ID_BYTES: usize = 256;

/// The two provider identities that make one tool call request-local and unique.
#[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ToolCallIdentity {
    call_id: String,
    correlation_id: String,
}

impl ToolCallIdentity {
    fn new(call_id: String, correlation_id: String) -> Result<Self, CompleteToolCallError> {
        validate_identity(&call_id)?;
        validate_identity(&correlation_id)?;
        Ok(Self {
            call_id,
            correlation_id,
        })
    }

    /// Borrows the provider call identity.
    #[must_use]
    pub fn call_id(&self) -> &str {
        &self.call_id
    }

    /// Borrows the request-local stream correlation identity.
    #[must_use]
    pub fn correlation_id(&self) -> &str {
        &self.correlation_id
    }
}

impl fmt::Debug for ToolCallIdentity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ToolCallIdentity([redacted])")
    }
}

/// A complete canonical tool call accepted by the execution runtime.
///
/// Public construction is available only from the provider's distinct complete
/// stream event or from an already complete [`ToolCallOutputPart`]. Argument
/// fragments have no conversion into this type.
pub struct CompleteToolCall {
    identity: ToolCallIdentity,
    name: String,
    arguments: Value,
}

impl CompleteToolCall {
    /// Converts an already complete canonical output part into an executable call.
    ///
    /// # Errors
    ///
    /// Returns [`CompleteToolCallError::InvalidIdentity`] when the correlation
    /// or canonical call identity violates fixed request-local bounds.
    pub fn from_output_part(
        correlation_id: String,
        part: &ToolCallOutputPart,
    ) -> Result<Self, CompleteToolCallError> {
        let identity = ToolCallIdentity::new(part.call_id().to_owned(), correlation_id)?;
        Ok(Self {
            identity,
            name: part.name().to_owned(),
            arguments: part.arguments().clone(),
        })
    }

    /// Borrows the complete call identity.
    #[must_use]
    pub const fn identity(&self) -> &ToolCallIdentity {
        &self.identity
    }

    /// Borrows the catalog tool name.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Borrows the complete parsed JSON arguments.
    #[must_use]
    pub const fn arguments(&self) -> &Value {
        &self.arguments
    }
}

impl TryFrom<ProviderStreamEvent> for CompleteToolCall {
    type Error = CompleteToolCallError;

    fn try_from(event: ProviderStreamEvent) -> Result<Self, Self::Error> {
        let ProviderStreamEvent::ToolCall {
            correlation_id,
            call_id,
            name,
            arguments,
            ..
        } = event
        else {
            return Err(CompleteToolCallError::NotComplete);
        };
        Ok(Self {
            identity: ToolCallIdentity::new(call_id, correlation_id)?,
            name,
            arguments,
        })
    }
}

impl fmt::Debug for CompleteToolCall {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CompleteToolCall")
            .field("identity", &self.identity)
            .field("name_bytes", &self.name.len())
            .field("arguments", &"[redacted]")
            .finish()
    }
}

/// Successful registry execution with exact call and capability revision provenance.
pub struct ExecutedToolResult {
    identity: ToolCallIdentity,
    capability: CapabilityKey,
    output: Value,
}

impl ExecutedToolResult {
    pub(crate) fn new(
        identity: ToolCallIdentity,
        capability: CapabilityKey,
        output: Value,
    ) -> Self {
        Self {
            identity,
            capability,
            output,
        }
    }

    /// Borrows the original complete call identity.
    #[must_use]
    pub const fn identity(&self) -> &ToolCallIdentity {
        &self.identity
    }

    /// Borrows the exact executed capability revision.
    #[must_use]
    pub const fn capability(&self) -> &CapabilityKey {
        &self.capability
    }

    /// Borrows the locally validated, bounded handler output.
    #[must_use]
    pub const fn output(&self) -> &Value {
        &self.output
    }

    /// Consumes the result and returns the locally validated output.
    #[must_use]
    pub fn into_output(self) -> Value {
        self.output
    }
}

impl fmt::Debug for ExecutedToolResult {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ExecutedToolResult")
            .field("identity", &self.identity)
            .field("capability", &self.capability)
            .field("output", &"[redacted]")
            .finish()
    }
}

/// A fixed, argument-free failure to establish a complete call.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum CompleteToolCallError {
    /// The provider event was a fragment or another non-complete event.
    #[error("provider event is not a complete tool call")]
    NotComplete,
    /// A provider call or correlation identity was empty, excessive, or contained controls.
    #[error("complete tool call identity is invalid")]
    InvalidIdentity,
}

fn validate_identity(value: &str) -> Result<(), CompleteToolCallError> {
    if value.is_empty() || value.len() > MAX_CALL_ID_BYTES || value.chars().any(char::is_control) {
        Err(CompleteToolCallError::InvalidIdentity)
    } else {
        Ok(())
    }
}

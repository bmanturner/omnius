//! AWS Bedrock completion and streaming behind canonical Omnius contracts.
//!
//! AWS and Rig SDK clients, models, responses, errors, and streams remain
//! private. Callers configure the AWS credential chain or a protected named
//! profile and use [`omnius_llm_core::LlmProvider`].

#![forbid(unsafe_code)]
#![deny(missing_docs)]

mod capability;
mod config;
mod provider;

pub use capability::{BEDROCK_CAPABILITY_REGISTRY_REVISION, capability_declaration};
pub use config::{BedrockCredentialMode, BedrockProviderConfig};
pub use provider::{BedrockProvider, BedrockProviderDiagnostics};

/// The exact Rig Bedrock contract revision targeted by this adapter.
pub const RIG_BEDROCK_COMPATIBILITY_VERSION: &str = "0.42.0";

//! Google Vertex AI companion adapter behind canonical Omnius LLM contracts.
//!
//! Rig, Google authentication, and Vertex SDK values remain private. Callers
//! configure protected credentials and execute through [`omnius_llm_core::LlmProvider`].

#![forbid(unsafe_code)]
#![deny(missing_docs)]

mod capability;
mod config;
mod provider;

pub use capability::{VERTEX_CAPABILITY_REGISTRY_REVISION, capability_declaration};
pub use config::{VertexCredentialMode, VertexProviderConfig};
pub use provider::{VertexProvider, VertexProviderDiagnostics};

/// The exact Rig Vertex AI companion revision targeted by this adapter.
pub const RIG_VERTEXAI_COMPATIBILITY_VERSION: &str = "0.42.0";

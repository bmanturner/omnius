//! Rig-backed direct provider adapters with an owned canonical boundary.
//!
//! Rig clients, models, messages, responses, errors, and streams stay private
//! to this crate. Callers use canonical [`omnius_llm_core::LlmRequest`] values
//! through the owned [`omnius_llm_core::LlmProvider`] port.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

mod catalog;
mod config;
mod driver;
mod http;
mod normalize;
mod raw;
mod request;

pub use catalog::{CatalogProvider, DirectProvider};
pub use config::{RigProviderConfig, RigProviderDiagnostics};
pub use driver::RigProvider;
/// The exact Rig contract revision this adapter family targets.
pub const RIG_COMPATIBILITY_VERSION: &str = "0.42.0";

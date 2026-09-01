//! Provider-neutral immutable LLM composition, reliability, execution, and live streaming.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

mod config;
mod registry;
mod runtime;

pub use config::{
    CircuitConfig, DirectProviderConfig, LlmRuntimeConfig, RawRetentionConfig,
    RigProviderRegistration, RigProvidersConfig, RoutingConfig, StreamingConfig,
    StructuredOutputConfig,
};
pub use registry::{
    ProviderBinding, ProviderRegistry, ProviderRegistryError, build_rig_provider_registry,
};
pub use runtime::{
    LlmRuntime, RuntimeApplicationPorts, RuntimeBuildError, RuntimeCompletion, RuntimeDefinition,
    RuntimeDispatch, RuntimeError, RuntimeEventStream, RuntimeMetering, RuntimeStream,
    RuntimeStreamSettlement, StreamPolicy, StructuredPolicy,
};

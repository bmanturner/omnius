//! Bounded product feature-flag evaluation with fail-safe defaults.
//!
//! This optional module separates product rollout decisions from authorization, entitlements,
//! capabilities, migrations, and schema compatibility. [`FlagPurpose`] cannot represent those
//! decisions, and [`FlagKey`] rejects their reserved namespaces. Application composition injects
//! a [`FeatureFlagProvider`] and [`ExposureRecorder`] into [`FeatureFlagEvaluator`]; every call then
//! applies a bounded deadline, complete-context cache scoping, the typed flag default on failure,
//! a redacted exposure record, and low-cardinality `rsk_feature_flags_*` metrics.
//!
//! [`OpenFeatureProvider`] adapts the official `open-feature` 0.3.0 provider trait directly. It
//! intentionally does not use an `OpenFeature` client, global evaluation context, or hooks, because
//! those SDK layers can add fields outside this module's strict context allowlist. [`StaticProvider`]
//! supports tests and bounded small deployments.
//!
//! # Composition
//!
//! ```no_run
//! use std::{sync::Arc, time::Duration};
//! use rsk_feature_flags::{
//!     EvaluationContext, EvaluationPolicy, FeatureFlagEvaluator, Flag, FlagPurpose,
//!     MemoryExposureRecorder, StaticProvider,
//! };
//!
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! let flag = Flag::permanent("checkout.compact", false, FlagPurpose::ProductRollout)?;
//! let mut provider = StaticProvider::new();
//! provider.set(&flag, true)?;
//! let exposures = Arc::new(MemoryExposureRecorder::new(256)?);
//! let policy = EvaluationPolicy::new(
//!     Duration::from_millis(100),
//!     Duration::from_secs(30),
//!     1_024,
//! )?;
//! let flags = FeatureFlagEvaluator::with_static_provider(provider, exposures, policy);
//! let context = EvaluationContext::new("production", None)?;
//! let enabled = flags.evaluate(&flag, &context).await.into_value();
//! assert!(enabled);
//! # Ok(())
//! # }
//! ```

mod context;
mod evaluator;
mod exposure;
mod flag;
mod provider;

pub use context::{
    ContextAttribute, ContextError, ContextValue, ContextValueError, EvaluationContext,
    MAX_CONTEXT_ATTRIBUTES, MAX_CONTEXT_BYTES, MAX_CONTEXT_VALUE_BYTES,
};
pub use evaluator::{
    Evaluation, EvaluationPolicy, EvaluationPolicyError, FeatureFlagEvaluator, MAX_CACHE_ENTRIES,
    MAX_CACHE_TTL, MAX_PROVIDER_TIMEOUT,
};
pub use exposure::{
    EvaluationSource, ExposureCapacityError, ExposureChannelRecorder, ExposureReceiver,
    ExposureRecord, ExposureRecordError, ExposureRecorder, FailureDefaultReason,
    MAX_EXPOSURE_QUEUE, MAX_MEMORY_EXPOSURES, MemoryExposureRecorder,
};
pub use flag::{
    Flag, FlagDefinitionError, FlagKey, FlagKeyError, FlagLifecycle, FlagObject, FlagObjectError,
    FlagOwner, FlagOwnerError, FlagPurpose, FlagPurposeError, FlagString, FlagStringError,
    FlagValue, FlagValueError, FlagValueKind, FlagValueType, MAX_FLAG_KEY_BYTES,
    MAX_FLAG_OBJECT_BYTES, MAX_FLAG_OBJECT_FIELDS, MAX_FLAG_OBJECT_KEY_BYTES, MAX_FLAG_OWNER_BYTES,
    MAX_FLAG_STRING_BYTES,
};
pub use provider::{
    FeatureFlagProvider, MAX_STATIC_FLAGS, MAX_VARIANT_BYTES, OpenFeatureProvider, ProviderError,
    ProviderEvaluation, ProviderFuture, ProviderKind, ProviderReason, ProviderRequest,
    ProviderResponseError, StaticProvider, StaticProviderError, Variant,
};

//! Integration coverage for bounded feature-flag policy and provider adapters.

use std::{
    collections::HashMap,
    str::FromStr,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

use open_feature::{
    EvaluationContext as SdkContext, EvaluationError, EvaluationErrorCode,
    EvaluationResult as SdkResult, StructValue, Value as SdkValue,
    provider::{FeatureProvider as SdkProvider, ProviderMetadata, ResolutionDetails},
};
use rsk_auth_core::{AssuranceLevel, AuthMethod, Principal, PrincipalKind, SubjectId, TenantId};
use rsk_feature_flags::{
    ContextAttribute, ContextError, ContextValue, EvaluationContext, EvaluationPolicy,
    EvaluationSource, ExposureChannelRecorder, FailureDefaultReason, FeatureFlagEvaluator,
    FeatureFlagProvider, Flag, FlagKey, FlagKeyError, FlagLifecycle, FlagObject, FlagObjectError,
    FlagPurpose, FlagString, FlagValue, FlagValueKind, MemoryExposureRecorder, OpenFeatureProvider,
    ProviderError, ProviderEvaluation, ProviderFuture, ProviderKind, ProviderReason,
    ProviderRequest, StaticProvider,
};
use time::{Date, Month, OffsetDateTime};

struct FailingProvider;

impl FeatureFlagProvider for FailingProvider {
    fn kind(&self) -> ProviderKind {
        ProviderKind::Custom
    }

    fn evaluate<'request>(
        &'request self,
        _request: ProviderRequest<'request>,
    ) -> ProviderFuture<'request> {
        Box::pin(async { Err(ProviderError::Unavailable) })
    }
}

struct SlowProvider;

impl FeatureFlagProvider for SlowProvider {
    fn kind(&self) -> ProviderKind {
        ProviderKind::Custom
    }

    fn evaluate<'request>(
        &'request self,
        _request: ProviderRequest<'request>,
    ) -> ProviderFuture<'request> {
        Box::pin(async {
            tokio::time::sleep(Duration::from_secs(1)).await;
            Ok(ProviderEvaluation::new(
                rsk_feature_flags::FlagValue::boolean(true),
            ))
        })
    }
}

struct EnvironmentProvider {
    calls: AtomicUsize,
}

impl FeatureFlagProvider for EnvironmentProvider {
    fn kind(&self) -> ProviderKind {
        ProviderKind::Custom
    }

    fn evaluate<'request>(
        &'request self,
        request: ProviderRequest<'request>,
    ) -> ProviderFuture<'request> {
        Box::pin(async move {
            self.calls.fetch_add(1, Ordering::Relaxed);
            let enabled = request
                .context()
                .get(ContextAttribute::Environment)
                .and_then(ContextValue::as_str)
                == Some("production");
            Ok(
                ProviderEvaluation::new(rsk_feature_flags::FlagValue::boolean(enabled))
                    .with_reason(ProviderReason::TargetingMatch),
            )
        })
    }
}
fn principal(subject: &str, tenant: &str) -> Result<Principal, Box<dyn std::error::Error>> {
    Ok(Principal::new(
        subject.parse::<SubjectId>()?,
        PrincipalKind::User,
        Some(tenant.parse::<TenantId>()?),
        AuthMethod::Session,
        OffsetDateTime::UNIX_EPOCH,
        AssuranceLevel::Aal1,
        Vec::new(),
    )?)
}

fn policy_without_cache(timeout: Duration) -> Result<EvaluationPolicy, Box<dyn std::error::Error>> {
    Ok(EvaluationPolicy::without_cache(timeout)?)
}

#[test]
fn evaluation_policy_rejects_unbounded_or_inconsistent_settings() {
    assert!(EvaluationPolicy::without_cache(Duration::ZERO).is_err());
    assert!(EvaluationPolicy::new(Duration::from_millis(50), Duration::from_secs(30), 0,).is_err());
    assert!(EvaluationPolicy::new(Duration::from_secs(11), Duration::ZERO, 0,).is_err());
}

#[tokio::test]
async fn provider_failure_uses_typed_default() -> Result<(), Box<dyn std::error::Error>> {
    let flag = Flag::permanent("checkout.compact", false, FlagPurpose::ProductRollout)?;
    let exposures = Arc::new(MemoryExposureRecorder::new(8)?);
    let evaluator = FeatureFlagEvaluator::new(
        Arc::new(FailingProvider),
        exposures.clone(),
        policy_without_cache(Duration::from_millis(50))?,
    );
    let context = EvaluationContext::new("test", None)?;

    let evaluation = evaluator.evaluate(&flag, &context).await;

    assert_eq!(evaluation.value(), &false);
    assert_eq!(
        evaluation.source(),
        EvaluationSource::FailureDefault(FailureDefaultReason::Unavailable)
    );
    assert_eq!(exposures.records()?.len(), 1);
    Ok(())
}

#[tokio::test]
async fn timeout_uses_typed_default() -> Result<(), Box<dyn std::error::Error>> {
    let flag = Flag::permanent("checkout.compact", false, FlagPurpose::ProductRollout)?;
    let exposures = Arc::new(MemoryExposureRecorder::new(8)?);
    let evaluator = FeatureFlagEvaluator::new(
        Arc::new(SlowProvider),
        exposures,
        policy_without_cache(Duration::from_millis(1))?,
    );
    let context = EvaluationContext::new("test", None)?;

    let evaluation = evaluator.evaluate(&flag, &context).await;

    assert_eq!(evaluation.value(), &false);
    assert_eq!(
        evaluation.source(),
        EvaluationSource::FailureDefault(FailureDefaultReason::Timeout)
    );
    Ok(())
}

#[test]
fn context_rejects_unknown_duplicate_and_unbounded_fields() -> Result<(), Box<dyn std::error::Error>>
{
    let context = EvaluationContext::new("test", None)?;
    let unknown = context
        .clone()
        .with_raw_attribute("email", ContextValue::string("person@example.test")?);
    assert_eq!(unknown, Err(ContextError::AttributeNotAllowed));

    let duplicate = context.with_attribute(
        ContextAttribute::Environment,
        ContextValue::string("other")?,
    );
    assert_eq!(duplicate, Err(ContextError::DuplicateAttribute));

    assert!(ContextValue::string("x".repeat(257)).is_err());
    Ok(())
}

#[test]
fn context_enforces_aggregate_bound() -> Result<(), Box<dyn std::error::Error>> {
    let value = || ContextValue::string("x".repeat(200));
    let context = EvaluationContext::new("x".repeat(200), None)?
        .with_attribute(ContextAttribute::Cohort, value()?)?
        .with_attribute(ContextAttribute::Locale, value()?)?
        .with_attribute(ContextAttribute::AppVersion, value()?)?;

    let result = context.with_attribute(ContextAttribute::Region, value()?);

    assert_eq!(result, Err(ContextError::AggregateTooLarge));
    Ok(())
}

#[tokio::test]
async fn cache_is_scoped_by_complete_context() -> Result<(), Box<dyn std::error::Error>> {
    let flag = Flag::permanent("checkout.compact", false, FlagPurpose::ProductRollout)?;
    let provider = Arc::new(EnvironmentProvider {
        calls: AtomicUsize::new(0),
    });
    let exposures = Arc::new(MemoryExposureRecorder::new(8)?);
    let evaluator = FeatureFlagEvaluator::new(
        provider.clone(),
        exposures,
        EvaluationPolicy::new(Duration::from_millis(50), Duration::from_secs(30), 8)?,
    );
    let production = EvaluationContext::new("production", None)?;
    let staging = EvaluationContext::new("staging", None)?;

    let first = evaluator.evaluate(&flag, &production).await;
    let cached = evaluator.evaluate(&flag, &production).await;
    let other_scope = evaluator.evaluate(&flag, &staging).await;

    assert_eq!(first.value(), &true);
    assert_eq!(cached.source(), EvaluationSource::Cache);
    assert_eq!(other_scope.value(), &false);

    assert_eq!(provider.calls.load(Ordering::Relaxed), 2);
    Ok(())
}
#[tokio::test]
async fn cache_never_crosses_canonical_subject_or_tenant_scope()
-> Result<(), Box<dyn std::error::Error>> {
    let flag = Flag::permanent("checkout.compact", false, FlagPurpose::ProductRollout)?;
    let provider = Arc::new(EnvironmentProvider {
        calls: AtomicUsize::new(0),
    });
    let exposures = Arc::new(MemoryExposureRecorder::new(8)?);
    let evaluator = FeatureFlagEvaluator::new(
        provider.clone(),
        exposures,
        EvaluationPolicy::new(Duration::from_millis(50), Duration::from_secs(30), 8)?,
    );
    let first_principal = principal(
        "01890f2a-0000-7000-8000-000000000001",
        "01890f2a-0000-7000-8000-000000000101",
    )?;
    let second_principal = principal(
        "01890f2a-0000-7000-8000-000000000002",
        "01890f2a-0000-7000-8000-000000000102",
    )?;
    let first_context = EvaluationContext::new("production", Some(&first_principal))?;
    let second_context = EvaluationContext::new("production", Some(&second_principal))?;

    let first = evaluator.evaluate(&flag, &first_context).await;
    let second = evaluator.evaluate(&flag, &second_context).await;
    let cached_first = evaluator.evaluate(&flag, &first_context).await;

    assert_eq!(first.source(), EvaluationSource::Provider);
    assert_eq!(second.source(), EvaluationSource::Provider);
    assert_eq!(cached_first.source(), EvaluationSource::Cache);
    assert_eq!(provider.calls.load(Ordering::Relaxed), 2);
    Ok(())
}

#[tokio::test]
async fn exposure_recorder_is_bounded_and_redacted() -> Result<(), Box<dyn std::error::Error>> {
    let flag = Flag::permanent("checkout.compact", false, FlagPurpose::ProductRollout)?;
    let mut provider = StaticProvider::new();
    provider.set(&flag, true)?;
    let exposures = Arc::new(MemoryExposureRecorder::new(2)?);
    let evaluator = FeatureFlagEvaluator::with_static_provider(
        provider,
        exposures.clone(),
        policy_without_cache(Duration::from_millis(50))?,
    );

    for environment in ["first", "second", "third"] {
        let context = EvaluationContext::new(environment, None)?;
        evaluator.evaluate(&flag, &context).await;
    }

    let records = exposures.records()?;
    assert_eq!(records.len(), 2);
    assert!(format!("{records:?}").contains("checkout.compact"));
    assert!(!format!("{records:?}").contains("third"));
    Ok(())
}

#[tokio::test]
async fn saturated_exposure_channel_never_blocks_evaluation()
-> Result<(), Box<dyn std::error::Error>> {
    let flag = Flag::permanent("checkout.compact", false, FlagPurpose::ProductRollout)?;
    let mut provider = StaticProvider::new();
    provider.set(&flag, true)?;
    let (recorder, _receiver) = ExposureChannelRecorder::new(1)?;
    let recorder = Arc::new(recorder);
    let evaluator = FeatureFlagEvaluator::with_static_provider(
        provider,
        recorder.clone(),
        policy_without_cache(Duration::from_millis(50))?,
    );
    let context = EvaluationContext::new("test", None)?;

    let first = tokio::time::timeout(
        Duration::from_millis(50),
        evaluator.evaluate(&flag, &context),
    )
    .await?;
    assert_eq!(first.source(), EvaluationSource::Provider);
    assert_eq!(recorder.remaining_capacity(), 0);

    let saturated = tokio::time::timeout(
        Duration::from_millis(50),
        evaluator.evaluate(&flag, &context),
    )
    .await?;
    assert_eq!(saturated.source(), EvaluationSource::Provider);
    assert_eq!(saturated.value(), &true);
    assert_eq!(recorder.remaining_capacity(), 0);
    Ok(())
}

#[tokio::test]
async fn static_provider_supports_typed_small_deployments() -> Result<(), Box<dyn std::error::Error>>
{
    let bool_flag = Flag::permanent("checkout.compact", false, FlagPurpose::ProductRollout)?;
    let string_flag = Flag::permanent(
        "checkout.layout",
        FlagString::new("classic")?,
        FlagPurpose::Experiment,
    )?;
    let mut provider = StaticProvider::new();
    provider.set(&bool_flag, true)?;
    provider.set(&string_flag, FlagString::new("compact")?)?;
    let exposures = Arc::new(MemoryExposureRecorder::new(8)?);
    let evaluator = FeatureFlagEvaluator::with_static_provider(
        provider,
        exposures,
        policy_without_cache(Duration::from_millis(50))?,
    );
    let context = EvaluationContext::new("test", None)?;

    let bool_evaluation = evaluator.evaluate(&bool_flag, &context).await;
    let string_evaluation = evaluator.evaluate(&string_flag, &context).await;

    assert_eq!(bool_evaluation.value(), &true);
    assert_eq!(string_evaluation.value().as_str(), "compact");
    assert_eq!(
        bool_evaluation.provider_reason(),
        Some(ProviderReason::Static)
    );
    Ok(())
}

#[test]
fn provider_variants_are_bounded_before_exposure() {
    let result = ProviderEvaluation::new(FlagValue::boolean(true)).with_variant("x".repeat(65));
    assert!(result.is_err());
}

#[test]
fn typed_keys_and_defaults_enforce_bounds() {
    assert!(Flag::<bool>::permanent("x".repeat(129), false, FlagPurpose::ProductRollout,).is_err());
    assert!(FlagString::new("x".repeat(1_025)).is_err());
    assert!(Flag::permanent("checkout.ratio", f64::NAN, FlagPurpose::OperationalTuning,).is_err());
}

#[test]
fn temporary_flags_require_owner_and_removal_metadata() -> Result<(), Box<dyn std::error::Error>> {
    let remove_after = Date::from_calendar_date(2026, Month::December, 1)?;
    let flag = Flag::temporary(
        "checkout.compact",
        false,
        FlagPurpose::ProductRollout,
        "team-checkout",
        remove_after,
    )?;

    let FlagLifecycle::Temporary {
        owner,
        remove_after: actual,
    } = flag.lifecycle()
    else {
        return Err("temporary lifecycle missing".into());
    };
    assert_eq!(owner.as_str(), "team-checkout");
    assert_eq!(*actual, remove_after);
    Ok(())
}

#[test]
fn reserved_purpose_bypass_attempts_are_rejected() {
    for key in [
        "auth.rollout",
        "auth2.rollout",
        "auth_rollout.enabled",
        "auth-rollout.enabled",
        "authentication.mfa",
        "securitycritical.rollout",
        "schemaevolution.v2",
        "entitlementpreview.banner",
        "product.authz.override",
        "checkout.schema_compatibility",
        "permissions.rollout",
    ] {
        assert_eq!(FlagKey::new(key), Err(FlagKeyError::ReservedNamespace));
    }
    for near_miss in [
        "account.login_banner",
        "capstone.progress",
        "entertainment.home",
        "migrate.assistant",
        "permissive.layout",
        "polish.theme",
        "scheme.editor",
        "secure.checkout",
    ] {
        assert!(FlagKey::new(near_miss).is_ok(), "{near_miss}");
    }
    assert!(FlagPurpose::from_str("authorization").is_err());
    assert!(FlagPurpose::from_str("schema_compatibility").is_err());
    assert!(FlagPurpose::from_str("entitlement").is_err());
}

#[test]
fn structured_values_reject_secrets_and_nesting() -> Result<(), Box<dyn std::error::Error>> {
    for key in ["api_token", "api-key", "private-key"] {
        let sensitive = FlagObject::new([(
            key,
            FlagValue::string(FlagString::new("not-a-secret-value")?),
        )]);
        assert_eq!(sensitive, Err(FlagObjectError::SensitiveKey));
    }

    let nested = FlagObject::new([("layout", FlagValue::object(FlagObject::empty()))]);
    assert_eq!(nested, Err(FlagObjectError::NestedValue));
    Ok(())
}

struct SecretFailingSdkProvider {
    metadata: ProviderMetadata,
    structured_value: Option<StructValue>,
}

impl SecretFailingSdkProvider {
    fn error<T>() -> SdkResult<ResolutionDetails<T>> {
        Err(EvaluationError {
            code: EvaluationErrorCode::General("credential=super-secret".to_owned()),
            message: Some("token=super-secret".to_owned()),
        })
    }
}

#[open_feature::async_trait]
impl SdkProvider for SecretFailingSdkProvider {
    fn metadata(&self) -> &ProviderMetadata {
        &self.metadata
    }

    async fn resolve_bool_value(
        &self,
        _flag_key: &str,
        _evaluation_context: &SdkContext,
    ) -> SdkResult<ResolutionDetails<bool>> {
        Self::error()
    }

    async fn resolve_int_value(
        &self,
        _flag_key: &str,
        _evaluation_context: &SdkContext,
    ) -> SdkResult<ResolutionDetails<i64>> {
        Self::error()
    }

    async fn resolve_float_value(
        &self,
        _flag_key: &str,
        _evaluation_context: &SdkContext,
    ) -> SdkResult<ResolutionDetails<f64>> {
        Self::error()
    }

    async fn resolve_string_value(
        &self,
        _flag_key: &str,
        _evaluation_context: &SdkContext,
    ) -> SdkResult<ResolutionDetails<String>> {
        Self::error()
    }

    async fn resolve_struct_value(
        &self,
        _flag_key: &str,
        _evaluation_context: &SdkContext,
    ) -> SdkResult<ResolutionDetails<StructValue>> {
        self.structured_value
            .clone()
            .map(ResolutionDetails::new)
            .map_or_else(Self::error, Ok)
    }
}

#[tokio::test]
async fn openfeature_diagnostics_are_redacted_before_defaulting()
-> Result<(), Box<dyn std::error::Error>> {
    let flag = Flag::permanent("checkout.compact", false, FlagPurpose::ProductRollout)?;
    let sdk_provider = Arc::new(SecretFailingSdkProvider {
        metadata: ProviderMetadata::new("secret-provider"),
        structured_value: None,
    });
    let provider = Arc::new(OpenFeatureProvider::new(sdk_provider));
    let exposures = Arc::new(MemoryExposureRecorder::new(8)?);
    let evaluator = FeatureFlagEvaluator::new(
        provider,
        exposures,
        policy_without_cache(Duration::from_millis(50))?,
    );
    let context = EvaluationContext::new("test", None)?;

    let evaluation = evaluator.evaluate(&flag, &context).await;
    let debug = format!("{evaluation:?}");

    assert_eq!(
        evaluation.source(),
        EvaluationSource::FailureDefault(FailureDefaultReason::Unavailable)
    );
    assert!(!debug.contains("super-secret"));
    Ok(())
}

#[tokio::test]
async fn openfeature_structured_values_are_bounded_and_typed()
-> Result<(), Box<dyn std::error::Error>> {
    let flag = Flag::permanent(
        "checkout.configuration",
        FlagObject::empty(),
        FlagPurpose::Experiment,
    )?;
    let sdk_provider = Arc::new(SecretFailingSdkProvider {
        metadata: ProviderMetadata::new("structured-provider"),
        structured_value: Some(StructValue {
            fields: HashMap::from([("layout".to_owned(), SdkValue::String("compact".to_owned()))]),
        }),
    });
    let exposures = Arc::new(MemoryExposureRecorder::new(8)?);
    let evaluator = FeatureFlagEvaluator::with_open_feature_provider(
        sdk_provider,
        exposures,
        policy_without_cache(Duration::from_millis(50))?,
    );
    let context = EvaluationContext::new("test", None)?;

    let evaluation = evaluator.evaluate(&flag, &context).await;

    assert_eq!(evaluation.source(), EvaluationSource::Provider);
    assert_eq!(
        evaluation.value().get("layout").map(FlagValue::kind),
        Some(FlagValueKind::String)
    );
    Ok(())
}

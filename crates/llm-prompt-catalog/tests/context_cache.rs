//! Authorized context assembly and exact cache-boundary contracts.

use std::{
    collections::{BTreeMap, BTreeSet},
    error::Error,
    sync::{Arc, Mutex},
};

use async_trait::async_trait;
use futures::executor::block_on;
use omnius_llm_core::{
    CapabilityEvidence, CapabilityEvidenceSource, ModelCapability, ModelCapabilityDeclaration,
    ModelCapabilityKey,
};
use omnius_llm_prompt_catalog::{
    AdmittedCacheValue, ApplicationCache, ApplicationCacheDescriptor, ApplicationCacheKey,
    ApplicationCachePolicy, ApplicationCacheStore, AuthorizationId, AuthorizedContextRequest,
    CacheContentKind, CacheDependencies, CacheFence, CacheModelSemantics, CachePolicyError,
    CachePromptSemantics, CacheSecurityScope, CacheStoreError, CacheWriteOutcome, ContentDigest,
    ContextAssembler, ContextAssemblyError, ContextAuthorizationDecision,
    ContextAuthorizationError, ContextAuthorizationPort, ContextAuthorizationRequest,
    ContextBudget, ContextIdentity, ContextProvenance, ContextRecord, ContextRetrievalError,
    ContextRetrievalPort, ContextSourceKind, DataClassification, ModelRevisionId, PolicyRevisionId,
    PrincipalId, PromptRevisionNumber, ProviderCacheAdmission, ProviderCacheBreakpoint,
    ProviderCacheError, ProviderCacheMode, ProviderCachePolicy, RetrievedContextBatch, RouteId,
    SchemaRevisionId, SourceId, SourceRevisionId, TenantId, ToolRevisionId, TruncationReason,
    TrustDomain, UntrustedText, admit_provider_cache,
};

#[derive(Clone)]
struct RecordingAuthorizer {
    events: Arc<Mutex<Vec<&'static str>>>,
    decision: ContextAuthorizationDecision,
}

#[async_trait]
impl ContextAuthorizationPort for RecordingAuthorizer {
    async fn authorize(
        &self,
        _request: &ContextAuthorizationRequest,
    ) -> Result<ContextAuthorizationDecision, ContextAuthorizationError> {
        self.events
            .lock()
            .map_err(|_| ContextAuthorizationError::Unavailable)?
            .push("authorize");
        Ok(self.decision.clone())
    }
}

#[derive(Clone)]
struct RecordSpec {
    source: &'static str,
    revision: &'static str,
    kind: ContextSourceKind,
    priority: i32,
    content: &'static str,
}

#[derive(Clone)]
struct RecordingRetriever {
    events: Arc<Mutex<Vec<&'static str>>>,
    records: Vec<RecordSpec>,
}

#[async_trait]
impl ContextRetrievalPort for RecordingRetriever {
    async fn retrieve(
        &self,
        request: &AuthorizedContextRequest,
    ) -> Result<RetrievedContextBatch, ContextRetrievalError> {
        self.events
            .lock()
            .map_err(|_| ContextRetrievalError::Unavailable)?
            .push("retrieve");
        let records = self
            .records
            .iter()
            .map(|record| {
                let content = UntrustedText::new(record.content)
                    .map_err(|_| ContextRetrievalError::Unavailable)?;
                let provenance = ContextProvenance::new(
                    record.kind,
                    SourceId::new(record.source).map_err(|_| ContextRetrievalError::Unavailable)?,
                    SourceRevisionId::new(record.revision)
                        .map_err(|_| ContextRetrievalError::Unavailable)?,
                    ContentDigest::of(content.as_str().as_bytes()),
                    request.authorization_id().clone(),
                    request.identity().policy_revision().clone(),
                    request.scope_digest(),
                );
                ContextRecord::new(
                    provenance,
                    DataClassification::Confidential,
                    record.priority,
                    content,
                )
                .map_err(|_| ContextRetrievalError::Unavailable)
            })
            .collect::<Result<Vec<_>, _>>()?;
        RetrievedContextBatch::new(records).map_err(|_| ContextRetrievalError::Unavailable)
    }
}

fn authorization_request() -> Result<ContextAuthorizationRequest, Box<dyn Error>> {
    let identity = ContextIdentity::new(
        TenantId::new("tenant-red")?,
        PrincipalId::new("principal-alice")?,
        PolicyRevisionId::new("policy-7")?,
        DataClassification::Confidential,
    );
    Ok(ContextAuthorizationRequest::new(
        identity,
        UntrustedText::new("find relevant documents")?,
        1_900_000_000_000,
    )?)
}

fn allow_decision() -> Result<ContextAuthorizationDecision, Box<dyn Error>> {
    Ok(ContextAuthorizationDecision::Allowed {
        authorization_id: AuthorizationId::new("authz-123")?,
        grant_revision: PolicyRevisionId::new("grant-9")?,
    })
}

fn specs() -> Vec<RecordSpec> {
    vec![
        RecordSpec {
            source: "source-b",
            revision: "rev-1",
            kind: ContextSourceKind::Document,
            priority: 10,
            content: "bbbb",
        },
        RecordSpec {
            source: "source-c",
            revision: "rev-1",
            kind: ContextSourceKind::Web,
            priority: 1,
            content: "cccc",
        },
        RecordSpec {
            source: "source-a",
            revision: "rev-2",
            kind: ContextSourceKind::Document,
            priority: 10,
            content: "aaaa",
        },
    ]
}

#[test]
fn authorization_denial_prevents_retrieval() -> Result<(), Box<dyn Error>> {
    block_on(async {
        let events = Arc::new(Mutex::new(Vec::new()));
        let assembler = ContextAssembler::new(
            RecordingAuthorizer {
                events: Arc::clone(&events),
                decision: ContextAuthorizationDecision::Denied,
            },
            RecordingRetriever {
                events: Arc::clone(&events),
                records: specs(),
            },
        );
        let result = assembler
            .assemble(
                authorization_request()?,
                ContextBudget::new(2, 100, 100, 100)?,
            )
            .await;
        assert_eq!(result, Err(ContextAssemblyError::Denied));
        assert_eq!(
            events.lock().map_err(|_| "events unavailable")?.as_slice(),
            ["authorize"]
        );
        Ok::<(), Box<dyn Error>>(())
    })
}

#[test]
fn assembly_order_truncation_and_provenance_are_deterministic() -> Result<(), Box<dyn Error>> {
    block_on(async {
        let first_events = Arc::new(Mutex::new(Vec::new()));
        let second_events = Arc::new(Mutex::new(Vec::new()));
        let first = ContextAssembler::new(
            RecordingAuthorizer {
                events: Arc::clone(&first_events),
                decision: allow_decision()?,
            },
            RecordingRetriever {
                events: Arc::clone(&first_events),
                records: specs(),
            },
        );
        let mut reversed = specs();
        reversed.reverse();
        let second = ContextAssembler::new(
            RecordingAuthorizer {
                events: Arc::clone(&second_events),
                decision: allow_decision()?,
            },
            RecordingRetriever {
                events: Arc::clone(&second_events),
                records: reversed,
            },
        );
        let budget = ContextBudget::new(2, 100, 100, 100)?;
        let first = first.assemble(authorization_request()?, budget).await?;
        let second = second.assemble(authorization_request()?, budget).await?;

        let first_ids = first
            .records()
            .iter()
            .map(|record| record.provenance().source_id().as_str())
            .collect::<Vec<_>>();
        let second_ids = second
            .records()
            .iter()
            .map(|record| record.provenance().source_id().as_str())
            .collect::<Vec<_>>();
        assert_eq!(first_ids, ["source-a", "source-b"]);
        assert_eq!(first_ids, second_ids);
        assert_eq!(
            first.manifest().truncation_reason(),
            Some(TruncationReason::RecordCount)
        );
        assert_eq!(first.manifest().omitted_records(), 1);
        assert_eq!(
            first.manifest().semantic_digest(),
            second.manifest().semantic_digest()
        );
        assert_eq!(first.trust_domain(), TrustDomain::UntrustedData);
        assert!(
            first
                .records()
                .iter()
                .all(|record| record.trust_domain() == TrustDomain::UntrustedData)
        );
        assert_eq!(
            first_events
                .lock()
                .map_err(|_| "events unavailable")?
                .as_slice(),
            ["authorize", "retrieve"]
        );
        Ok::<(), Box<dyn Error>>(())
    })
}

#[derive(Default)]
struct ScopeCacheState {
    fence: Option<CacheFence>,
    values: BTreeMap<String, AdmittedCacheValue>,
}

#[derive(Default)]
struct MemoryCacheStore {
    scopes: Mutex<BTreeMap<CacheSecurityScope, ScopeCacheState>>,
}

#[async_trait]
impl ApplicationCacheStore for MemoryCacheStore {
    async fn current_fence(
        &self,
        scope: &CacheSecurityScope,
    ) -> Result<CacheFence, CacheStoreError> {
        Ok(self
            .scopes
            .lock()
            .map_err(|_| CacheStoreError::Unavailable)?
            .get(scope)
            .and_then(|state| state.fence)
            .unwrap_or(CacheFence::new(0, 0)))
    }

    async fn get_if_current(
        &self,
        scope: &CacheSecurityScope,
        key: &ApplicationCacheKey,
        expected_fence: CacheFence,
    ) -> Result<Option<AdmittedCacheValue>, CacheStoreError> {
        let scopes = self
            .scopes
            .lock()
            .map_err(|_| CacheStoreError::Unavailable)?;
        let Some(state) = scopes.get(scope) else {
            return Ok(None);
        };
        if state.fence.unwrap_or(CacheFence::new(0, 0)) != expected_fence {
            return Ok(None);
        }
        let value = state.values.get(key.as_str()).cloned();
        if value.as_ref().is_some_and(|value| {
            value.classification() != scope.classification()
                || value.is_sensitive() != scope.is_sensitive()
        }) {
            return Err(CacheStoreError::ScopeMismatch);
        }
        Ok(value)
    }

    async fn put_if_current(
        &self,
        scope: &CacheSecurityScope,
        key: &ApplicationCacheKey,
        expected_fence: CacheFence,
        value: AdmittedCacheValue,
    ) -> Result<CacheWriteOutcome, CacheStoreError> {
        if value.classification() != scope.classification()
            || value.is_sensitive() != scope.is_sensitive()
        {
            return Err(CacheStoreError::ScopeMismatch);
        }
        let mut scopes = self
            .scopes
            .lock()
            .map_err(|_| CacheStoreError::Unavailable)?;
        let state = scopes.entry(scope.clone()).or_default();
        if state.fence.unwrap_or(CacheFence::new(0, 0)) != expected_fence {
            return Ok(CacheWriteOutcome::Fenced);
        }
        state.values.insert(key.as_str().to_owned(), value);
        Ok(CacheWriteOutcome::Stored)
    }

    async fn advance_fence_and_delete(
        &self,
        scope: &CacheSecurityScope,
        expected_fence: CacheFence,
        next_fence: CacheFence,
    ) -> Result<CacheFence, CacheStoreError> {
        let mut scopes = self
            .scopes
            .lock()
            .map_err(|_| CacheStoreError::Unavailable)?;
        let state = scopes.entry(scope.clone()).or_default();
        if state.fence.unwrap_or(CacheFence::new(0, 0)) != expected_fence
            || !next_fence.strictly_advances(expected_fence)
        {
            return Err(CacheStoreError::FenceConflict);
        }
        state.fence = Some(next_fence);
        state.values.clear();
        Ok(next_fence)
    }
}

fn cache_scope(
    tenant: &str,
    principal: &str,
    policy: &str,
) -> Result<CacheSecurityScope, Box<dyn Error>> {
    Ok(CacheSecurityScope::new(
        TenantId::new(tenant)?,
        PrincipalId::new(principal)?,
        PolicyRevisionId::new(policy)?,
        PolicyRevisionId::new("grant-3")?,
        RouteId::new("assistant.default")?,
        DataClassification::Confidential,
        false,
    ))
}

fn cache_descriptor() -> Result<ApplicationCacheDescriptor, Box<dyn Error>> {
    Ok(ApplicationCacheDescriptor::new(
        CacheModelSemantics::new(
            ModelRevisionId::new("model-2026-08")?,
            ContentDigest::of(b"generation-options"),
            ContentDigest::of(b"output-contract"),
        ),
        CachePromptSemantics::new(
            PromptRevisionNumber::new(4)?,
            ContentDigest::of(b"prompt-source"),
            ContentDigest::of(b"variables"),
            ContentDigest::of(b"rendered-prompt"),
        ),
        CacheDependencies::new(
            BTreeSet::from([ToolRevisionId::new("search@5")?]),
            BTreeSet::from([SchemaRevisionId::new("answer@2")?]),
            ContentDigest::of(b"ordered-context-and-truncation"),
        )?,
        CacheContentKind::Response,
    ))
}

#[test]
fn cache_keys_isolate_complete_security_scope() -> Result<(), Box<dyn Error>> {
    let descriptor = cache_descriptor()?;
    let fence = CacheFence::new(7, 2);
    let base = ApplicationCacheKey::derive(
        &cache_scope("tenant-a", "principal-a", "policy-1")?,
        &descriptor,
        fence,
    );
    let other_tenant = ApplicationCacheKey::derive(
        &cache_scope("tenant-b", "principal-a", "policy-1")?,
        &descriptor,
        fence,
    );
    let other_principal = ApplicationCacheKey::derive(
        &cache_scope("tenant-a", "principal-b", "policy-1")?,
        &descriptor,
        fence,
    );
    let other_policy = ApplicationCacheKey::derive(
        &cache_scope("tenant-a", "principal-a", "policy-2")?,
        &descriptor,
        fence,
    );
    let other_grant = ApplicationCacheKey::derive(
        &CacheSecurityScope::new(
            TenantId::new("tenant-a")?,
            PrincipalId::new("principal-a")?,
            PolicyRevisionId::new("policy-1")?,
            PolicyRevisionId::new("grant-4")?,
            RouteId::new("assistant.default")?,
            DataClassification::Confidential,
            false,
        ),
        &descriptor,
        fence,
    );
    let other_route = ApplicationCacheKey::derive(
        &CacheSecurityScope::new(
            TenantId::new("tenant-a")?,
            PrincipalId::new("principal-a")?,
            PolicyRevisionId::new("policy-1")?,
            PolicyRevisionId::new("grant-3")?,
            RouteId::new("assistant.other")?,
            DataClassification::Confidential,
            false,
        ),
        &descriptor,
        fence,
    );
    let other_classification = ApplicationCacheKey::derive(
        &CacheSecurityScope::new(
            TenantId::new("tenant-a")?,
            PrincipalId::new("principal-a")?,
            PolicyRevisionId::new("policy-1")?,
            PolicyRevisionId::new("grant-3")?,
            RouteId::new("assistant.default")?,
            DataClassification::Restricted,
            false,
        ),
        &descriptor,
        fence,
    );
    let other_sensitivity = ApplicationCacheKey::derive(
        &CacheSecurityScope::new(
            TenantId::new("tenant-a")?,
            PrincipalId::new("principal-a")?,
            PolicyRevisionId::new("policy-1")?,
            PolicyRevisionId::new("grant-3")?,
            RouteId::new("assistant.default")?,
            DataClassification::Confidential,
            true,
        ),
        &descriptor,
        fence,
    );
    assert_ne!(base, other_tenant);
    assert_ne!(base, other_principal);
    assert_ne!(base, other_policy);
    assert_ne!(base, other_grant);
    assert_ne!(base, other_route);
    assert_ne!(base, other_classification);
    assert_ne!(base, other_sensitivity);
    assert_eq!(base.as_str().len(), 71);
    Ok(())
}

#[test]
fn cache_write_requires_exact_classification_and_sensitivity_scope() -> Result<(), Box<dyn Error>> {
    block_on(async {
        let cache = ApplicationCache::new(MemoryCacheStore::default());
        let public_scope = CacheSecurityScope::new(
            TenantId::new("tenant-a")?,
            PrincipalId::new("principal-a")?,
            PolicyRevisionId::new("policy-1")?,
            PolicyRevisionId::new("grant-3")?,
            RouteId::new("assistant.default")?,
            DataClassification::Public,
            false,
        );
        let lease = cache.lease(public_scope, &cache_descriptor()?).await?;
        let policy =
            ApplicationCachePolicy::new(true, DataClassification::Confidential, false, 1_024)?;
        let confidential = policy.admit(
            b"confidential".to_vec(),
            DataClassification::Confidential,
            false,
        )?;
        assert_eq!(
            cache.put(&lease, confidential).await,
            Err(CacheStoreError::ScopeMismatch)
        );
        Ok::<(), Box<dyn Error>>(())
    })
}

#[test]
fn deletion_fence_rejects_stale_inflight_write() -> Result<(), Box<dyn Error>> {
    block_on(async {
        let cache = ApplicationCache::new(MemoryCacheStore::default());
        let scope = cache_scope("tenant-a", "principal-a", "policy-1")?;
        let descriptor = cache_descriptor()?;
        let old_lease = cache.lease(scope.clone(), &descriptor).await?;
        let next = old_lease.fence().next_deletion().ok_or("fence exhausted")?;
        cache.invalidate(&scope, old_lease.fence(), next).await?;

        let policy =
            ApplicationCachePolicy::new(true, DataClassification::Confidential, false, 1_024)?;
        let value = policy.admit(
            b"normalized-response".to_vec(),
            DataClassification::Confidential,
            false,
        )?;
        assert_eq!(
            cache.put(&old_lease, value).await?,
            CacheWriteOutcome::Fenced
        );
        let new_lease = cache.lease(scope, &descriptor).await?;
        assert_ne!(old_lease.key(), new_lease.key());
        assert_eq!(new_lease.fence(), next);
        Ok::<(), Box<dyn Error>>(())
    })
}

#[test]
fn deletion_fence_is_exact_to_tenant_principal_and_policy_scope() -> Result<(), Box<dyn Error>> {
    block_on(async {
        let cache = ApplicationCache::new(MemoryCacheStore::default());
        let descriptor = cache_descriptor()?;
        let deleted_scope = cache_scope("tenant-a", "principal-a", "policy-1")?;
        let deleted_lease = cache.lease(deleted_scope.clone(), &descriptor).await?;
        let policy =
            ApplicationCachePolicy::new(true, DataClassification::Confidential, false, 1_024)?;
        cache
            .put(
                &deleted_lease,
                policy.admit(
                    b"deleted-scope-value".to_vec(),
                    DataClassification::Confidential,
                    false,
                )?,
            )
            .await?;

        let mut retained = Vec::with_capacity(3);
        for scope in [
            cache_scope("tenant-b", "principal-a", "policy-1")?,
            cache_scope("tenant-a", "principal-b", "policy-1")?,
            cache_scope("tenant-a", "principal-a", "policy-2")?,
        ] {
            let lease = cache.lease(scope.clone(), &descriptor).await?;
            cache
                .put(
                    &lease,
                    policy.admit(
                        b"retained-scope-value".to_vec(),
                        DataClassification::Confidential,
                        false,
                    )?,
                )
                .await?;
            retained.push((scope, lease));
        }

        let next = deleted_lease
            .fence()
            .next_deletion()
            .ok_or("fence exhausted")?;
        cache
            .invalidate(&deleted_scope, deleted_lease.fence(), next)
            .await?;

        for (scope, lease) in retained {
            assert_eq!(
                cache
                    .get(&lease)
                    .await?
                    .ok_or("retained scope was deleted")?
                    .as_bytes(),
                b"retained-scope-value"
            );
            assert_eq!(
                cache.lease(scope, &descriptor).await?.fence(),
                lease.fence()
            );
        }
        assert_eq!(
            cache
                .put(
                    &deleted_lease,
                    policy.admit(
                        b"stale-value".to_vec(),
                        DataClassification::Confidential,
                        false,
                    )?,
                )
                .await?,
            CacheWriteOutcome::Fenced
        );
        Ok::<(), Box<dyn Error>>(())
    })
}

#[test]
fn provider_cache_required_mode_never_silently_downgrades() -> Result<(), Box<dyn Error>> {
    let policy = ProviderCachePolicy::new(
        ProviderCacheMode::Required,
        300,
        BTreeSet::from([ProviderCacheBreakpoint::System]),
    )?;
    let key = ModelCapabilityKey::new("provider", "model", "model-rev")?;
    let missing = ModelCapabilityDeclaration::new(
        key.clone(),
        "registry-1",
        BTreeMap::new(),
        BTreeSet::from(["us-east".to_owned()]),
        None,
        None,
    )?;
    assert_eq!(
        admit_provider_cache(&policy, &missing),
        Err(ProviderCacheError::RequiredCapabilityMissing)
    );

    let evidence = BTreeMap::from([
        (
            ModelCapability::PromptCaching,
            CapabilityEvidence::new(CapabilityEvidenceSource::Cassette, "cache-cassette-4")?,
        ),
        (
            ModelCapability::CacheControls,
            CapabilityEvidence::new(
                CapabilityEvidenceSource::ProviderDocumentation,
                "provider-docs-7",
            )?,
        ),
    ]);
    let admitted = ModelCapabilityDeclaration::new(
        key,
        "registry-2",
        evidence,
        BTreeSet::from(["us-east".to_owned()]),
        None,
        None,
    )?;
    let ProviderCacheAdmission::Enabled(controls) = admit_provider_cache(&policy, &admitted)?
    else {
        return Err("expected evidence-backed provider controls".into());
    };
    assert_eq!(controls.ttl_seconds(), 300);
    assert_eq!(controls.model_key(), admitted.key());
    assert_eq!(
        controls.breakpoints(),
        &BTreeSet::from([ProviderCacheBreakpoint::System])
    );
    Ok(())
}

#[test]
fn provider_capability_does_not_override_sensitive_application_cache_policy()
-> Result<(), Box<dyn Error>> {
    let application =
        ApplicationCachePolicy::new(true, DataClassification::Restricted, false, 1_024)?;
    assert_eq!(
        application.admit(
            b"sensitive-response".to_vec(),
            DataClassification::Confidential,
            true,
        ),
        Err(CachePolicyError::Sensitive)
    );
    Ok(())
}

#[test]
fn debug_output_redacts_context_cache_content_and_security_scope() -> Result<(), Box<dyn Error>> {
    block_on(async {
        let events = Arc::new(Mutex::new(Vec::new()));
        let secret = "context-redaction-sentinel";
        let context_assembler = ContextAssembler::new(
            RecordingAuthorizer {
                events: Arc::clone(&events),
                decision: allow_decision()?,
            },
            RecordingRetriever {
                events,
                records: vec![RecordSpec {
                    source: "private-source",
                    revision: "private-revision",
                    kind: ContextSourceKind::ModelOutput,
                    priority: 1,
                    content: secret,
                }],
            },
        );
        let assembled_context = context_assembler
            .assemble(
                authorization_request()?,
                ContextBudget::new(2, 100, 100, 100)?,
            )
            .await?;
        let scope = cache_scope(
            "tenant-redaction",
            "principal-redaction",
            "policy-redaction",
        )?;
        let policy =
            ApplicationCachePolicy::new(true, DataClassification::Confidential, false, 1_024)?;
        let value = policy.admit(
            b"cache-redaction-sentinel".to_vec(),
            DataClassification::Confidential,
            false,
        )?;
        let output = format!("{assembled_context:?} {scope:?} {value:?}");
        assert!(!output.contains(secret));
        assert!(!output.contains("tenant-redaction"));
        assert!(!output.contains("principal-redaction"));
        assert!(!output.contains("cache-redaction-sentinel"));
        Ok::<(), Box<dyn Error>>(())
    })
}

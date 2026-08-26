//! Provider-neutral privacy value, inventory, redaction, and retry-policy contracts.

use rsk_auth_core::PrincipalKind;
use std::{error::Error, num::NonZeroU16, sync::Arc};

use rsk_privacy::{
    AdapterEvidence, AdapterFuture, AdapterName, AdapterWork, ArtifactId, ConsentDocumentKind,
    ConsentEvidenceFormat, ConsentPolicy, ConsentPolicyError, ConsentRule, ConsentSource,
    ConsentTransport, DataInventoryAdapter, EvidenceDigest, InventoryCategory, InventoryDescriptor,
    InventoryEffect, InventoryRegistry, InventoryRegistryError, InventoryRequirement, Jurisdiction,
    LifecycleKind, ObjectReference, PolicyVersion, RequiredInventoryManifest, RetryPolicy,
};

struct NoopAdapter {
    descriptor: InventoryDescriptor,
}

impl NoopAdapter {
    fn shared(
        name: &str,
        category: InventoryCategory,
    ) -> Result<Arc<dyn DataInventoryAdapter>, rsk_privacy::PrivacyValueError> {
        Ok(Arc::new(Self {
            descriptor: InventoryDescriptor::new(AdapterName::new(name)?, category),
        }))
    }
}

impl DataInventoryAdapter for NoopAdapter {
    fn descriptor(&self) -> &InventoryDescriptor {
        &self.descriptor
    }

    fn reconcile<'a>(&'a self, _work: &'a AdapterWork) -> AdapterFuture<'a> {
        Box::pin(async {
            Ok(AdapterEvidence::new(
                InventoryEffect::NoData,
                0,
                EvidenceDigest::hash(b"no-data"),
            ))
        })
    }
}
fn requirement(
    name: &str,
    category: InventoryCategory,
) -> Result<InventoryRequirement, rsk_privacy::PrivacyValueError> {
    Ok(InventoryRequirement::new(
        AdapterName::new(name)?,
        category,
        NonZeroU16::MIN,
    ))
}

#[test]
fn registry_supports_every_closed_inventory_category() -> Result<(), Box<dyn Error>> {
    let manifest = RequiredInventoryManifest::new([
        requirement("primary-db", InventoryCategory::PostgreSql)?,
        requirement("tenant-objects", InventoryCategory::Object)?,
        requirement("derived-search", InventoryCategory::Search)?,
        requirement("durable-queue", InventoryCategory::Queue)?,
        requirement("approved-provider", InventoryCategory::Provider)?,
    ])?;
    let registry = InventoryRegistry::new(
        manifest,
        [
            NoopAdapter::shared("primary-db", InventoryCategory::PostgreSql)?,
            NoopAdapter::shared("tenant-objects", InventoryCategory::Object)?,
            NoopAdapter::shared("derived-search", InventoryCategory::Search)?,
            NoopAdapter::shared("durable-queue", InventoryCategory::Queue)?,
            NoopAdapter::shared("approved-provider", InventoryCategory::Provider)?,
        ],
    )?;

    assert_eq!(registry.len(), 5);
    Ok(())
}

#[test]
fn registry_rejects_incomplete_unexpected_or_duplicate_inventory() -> Result<(), Box<dyn Error>> {
    assert!(matches!(
        RequiredInventoryManifest::new(Vec::<InventoryRequirement>::new()),
        Err(InventoryRegistryError::Empty)
    ));

    let required = RequiredInventoryManifest::new([requirement(
        "primary-db",
        InventoryCategory::PostgreSql,
    )?])?;
    assert!(matches!(
        InventoryRegistry::new(
            required.clone(),
            Vec::<Arc<dyn DataInventoryAdapter>>::new()
        ),
        Err(InventoryRegistryError::MissingRequiredAdapter)
    ));
    assert!(matches!(
        InventoryRegistry::new(
            required.clone(),
            [
                NoopAdapter::shared("primary-db", InventoryCategory::PostgreSql)?,
                NoopAdapter::shared("unexpected", InventoryCategory::Object)?,
            ],
        ),
        Err(InventoryRegistryError::UnexpectedAdapter)
    ));
    assert!(matches!(
        InventoryRegistry::new(
            required,
            [
                NoopAdapter::shared("primary-db", InventoryCategory::PostgreSql)?,
                NoopAdapter::shared("primary-db", InventoryCategory::PostgreSql)?,
            ],
        ),
        Err(InventoryRegistryError::DuplicateAdapter)
    ));
    Ok(())
}
#[test]
fn withdrawable_grant_requires_a_matching_withdrawal_ceremony() -> Result<(), Box<dyn Error>> {
    let policy = ConsentPolicy::new(
        vec![ConsentRule {
            document_kind: ConsentDocumentKind::Marketing,
            document_version: PolicyVersion::new("marketing-4")?,
            jurisdiction: Jurisdiction::new("US-CA")?,
            actor_kind: PrincipalKind::User,
            transport: ConsentTransport::Web,
            source: ConsentSource::Web,
            evidence_format: ConsentEvidenceFormat::Checkbox,
            withdrawal_permitted: true,
        }],
        Vec::new(),
    );
    assert!(matches!(
        policy,
        Err(ConsentPolicyError::MissingWithdrawalRule)
    ));
    Ok(())
}

#[test]
fn evidence_and_object_debug_output_never_contains_raw_values() -> Result<(), Box<dyn Error>> {
    let evidence = EvidenceDigest::hash(b"raw-evidence-that-must-not-be-logged");
    let reference = ObjectReference::new("tenant/private/moderation/object-123")?;

    assert_eq!(format!("{evidence:?}"), "EvidenceDigest([SHA-256])");
    assert_eq!(format!("{reference:?}"), "ObjectReference([REDACTED])");
    Ok(())
}

#[test]
fn operation_effect_contract_distinguishes_exports_from_mutations() {
    let export = AdapterEvidence::new(
        InventoryEffect::Exported(ArtifactId::new()),
        3,
        EvidenceDigest::hash(b"export-manifest"),
    );
    let mutation = AdapterEvidence::new(
        InventoryEffect::Mutated,
        3,
        EvidenceDigest::hash(b"mutation-receipt"),
    );

    assert!(matches!(export.effect(), InventoryEffect::Exported(_)));
    assert_eq!(mutation.effect(), InventoryEffect::Mutated);
    assert!(LifecycleKind::Delete.is_destructive());
    assert!(!LifecycleKind::Export.is_destructive());
}

#[test]
fn retry_policy_rejects_deadlines_longer_than_the_lease() {
    let policy = RetryPolicy::new(
        4,
        std::time::Duration::from_secs(10),
        std::time::Duration::from_secs(11),
        std::time::Duration::from_secs(1),
        std::time::Duration::from_secs(5),
    );

    assert!(policy.is_err());
}

//! Deterministic tenant-fencing, reauthorization, redaction, timeout, and SDK HTTP contracts.

use std::{collections::BTreeMap, error::Error, sync::Arc, time::Duration};

use omnius_auth_core::{TenantId, testing::TestPrincipalFactory};
use omnius_config::SecretString;
use omnius_search_meilisearch::{
    FieldName, FilterValue, IndexAlias, IndexSchema, MeilisearchAdapter, ProjectionDocument,
    ProjectionMutation, ProjectionTarget, SearchError, SearchFilter, SearchInput,
    SearchMeilisearchConfig, SearchModelError, SearchProvider, SearchProviderError, SearchService,
    SourceId, SourceRevision,
    testing::{FakeBatchReauthorizer, FakeSearchProvider},
};
use serde_json::json;
use url::Url;
use wiremock::{
    Mock, MockServer, ResponseTemplate,
    matchers::{body_json, header, method, path},
};

fn config(endpoint: Url) -> SearchMeilisearchConfig {
    SearchMeilisearchConfig {
        endpoint,
        api_key: SecretString::from("contract-test-key".to_owned()),
        index_prefix: "contract".to_owned(),
        provider_timeout: Duration::from_secs(2),
        task_poll_interval: Duration::from_millis(20),
        stale_after: Duration::from_secs(60),
        projection_lease: Duration::from_secs(3),
        limits: omnius_search_meilisearch::SearchLimits::default(),
    }
}

fn schema() -> Result<IndexSchema, SearchModelError> {
    IndexSchema::new(
        IndexAlias::new("records")?,
        3,
        vec![FieldName::new("title")?],
        vec![FieldName::new("status")?],
    )
}

#[tokio::test]
async fn service_always_tenant_filters_and_removes_missing_stale_or_unauthorized_ids()
-> Result<(), Box<dyn Error>> {
    let principal = TestPrincipalFactory::default().build()?;
    let tenant = principal.tenant_id.ok_or("fixture tenant missing")?;
    let visible = SourceId::new("record-visible")?;
    let stale = SourceId::new("record-stale")?;
    let missing = SourceId::new("record-missing")?;
    let revision_one = SourceRevision::new(1)?;
    let revision_two = SourceRevision::new(2)?;
    let provider = Arc::new(FakeSearchProvider::default());
    provider.enqueue_hits(vec![
        (visible.clone(), revision_one),
        (stale.clone(), revision_one),
        (missing, revision_one),
    ])?;
    let reauthorizer = Arc::new(FakeBatchReauthorizer::default());
    reauthorizer.authorize(visible.clone(), revision_one)?;
    reauthorizer.authorize(stale, revision_two)?;
    let service = SearchService::new(
        provider.clone(),
        reauthorizer.clone(),
        schema()?,
        config(Url::parse("http://127.0.0.1:7700")?),
    )?;
    let input = SearchInput::new(
        "bounded words",
        vec![SearchFilter::equal(
            FieldName::new("status")?,
            FilterValue::text("active")?,
        )],
        10,
        0,
    )?;

    let response = service.search(&principal, input).await?;

    assert_eq!(response.hits().len(), 1);
    assert_eq!(response.hits()[0].source_id(), &visible);
    assert_eq!(reauthorizer.call_count()?, 1);
    let searches = provider.searches()?;
    assert_eq!(searches.len(), 1);
    assert_eq!(searches[0].tenant_id(), tenant);
    assert_eq!(
        searches[0].rendered_filter(),
        format!("_tenant_id = \"{tenant}\" AND status = \"active\"")
    );
    Ok(())
}

#[tokio::test]
async fn configured_query_bound_rejects_before_provider_access() -> Result<(), Box<dyn Error>> {
    let principal = TestPrincipalFactory::default().build()?;
    let provider = Arc::new(FakeSearchProvider::default());
    let reauthorizer = Arc::new(FakeBatchReauthorizer::default());
    let service = SearchService::new(
        provider.clone(),
        reauthorizer,
        schema()?,
        config(Url::parse("http://127.0.0.1:7700")?),
    )?;
    let input = SearchInput::new("x".repeat(513), Vec::new(), 10, 0)?;

    assert_eq!(
        service.search(&principal, input).await,
        Err(SearchError::InvalidInput(SearchModelError::QueryTooLarge))
    );
    assert!(provider.searches()?.is_empty());
    Ok(())
}

#[tokio::test]
async fn principal_without_tenant_never_reaches_provider() -> Result<(), Box<dyn Error>> {
    let principal = TestPrincipalFactory::default()
        .with_tenant_id(None)
        .build()?;
    let provider = Arc::new(FakeSearchProvider::default());
    let service = SearchService::new(
        provider.clone(),
        Arc::new(FakeBatchReauthorizer::default()),
        schema()?,
        config(Url::parse("http://127.0.0.1:7700")?),
    )?;

    assert_eq!(
        service
            .search(&principal, SearchInput::new("query", Vec::new(), 10, 0)?)
            .await,
        Err(SearchError::TenantRequired)
    );
    assert!(provider.searches()?.is_empty());
    Ok(())
}

#[test]
fn projection_document_rejects_reserved_and_unbounded_fields() -> Result<(), Box<dyn Error>> {
    let source_id = SourceId::new("record-one")?;
    let revision = SourceRevision::new(1)?;
    let mut reserved = BTreeMap::new();
    reserved.insert("_tenant_id".to_owned(), json!("forged"));
    assert_eq!(
        ProjectionDocument::new(source_id.clone(), revision, reserved),
        Err(SearchModelError::InvalidField)
    );

    let mut unbounded = BTreeMap::new();
    unbounded.insert("title".to_owned(), json!("x".repeat(16_385)));
    assert_eq!(
        ProjectionDocument::new(source_id, revision, unbounded),
        Err(SearchModelError::UnboundedJson)
    );
    Ok(())
}

#[test]
fn debug_output_redacts_provider_secret_and_query_values() -> Result<(), Box<dyn Error>> {
    let config = config(Url::parse("http://127.0.0.1:7700")?);
    let input = SearchInput::new(
        "private search terms",
        vec![SearchFilter::equal(
            FieldName::new("status")?,
            FilterValue::text("private-filter-value")?,
        )],
        5,
        0,
    )?;
    let rendered = format!("{config:?} {input:?}");
    assert!(!rendered.contains("contract-test-key"));
    assert!(!rendered.contains("private search terms"));
    assert!(!rendered.contains("private-filter-value"));
    Ok(())
}

#[tokio::test]
async fn maintained_sdk_search_request_contains_mandatory_tenant_filter()
-> Result<(), Box<dyn Error>> {
    let server = MockServer::start().await;
    let principal = TestPrincipalFactory::default().build()?;
    let tenant = principal.tenant_id.ok_or("fixture tenant missing")?;
    let source = SourceId::new("record-one")?;
    let revision = SourceRevision::new(1)?;
    Mock::given(method("POST"))
        .and(path("/indexes/contract__records/search"))
        .and(header("authorization", "Bearer contract-test-key"))
        .and(body_json(json!({
            "q": "needle",
            "offset": 0,
            "limit": 5,
            "filter": format!("_tenant_id = \"{tenant}\""),
            "attributesToRetrieve": ["_tenant_id", "_source_id", "_source_revision"]
        })))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "hits": [{
                "_tenant_id": tenant.to_string(),
                "_source_id": source.as_str(),
                "_source_revision": revision.get()
            }],
            "processingTimeMs": 1,
            "query": "needle"
        })))
        .expect(1)
        .mount(&server)
        .await;
    let adapter = Arc::new(MeilisearchAdapter::new(&config(Url::parse(
        &server.uri(),
    )?))?);
    let reauthorizer = Arc::new(FakeBatchReauthorizer::default());
    reauthorizer.authorize(source.clone(), revision)?;
    let service = SearchService::new(
        adapter,
        reauthorizer,
        schema()?,
        config(Url::parse(&server.uri())?),
    )?;

    let response = service
        .search(&principal, SearchInput::new("needle", Vec::new(), 5, 0)?)
        .await?;

    assert_eq!(response.hits()[0].source_id(), &source);
    Ok(())
}

#[tokio::test]
async fn maintained_sdk_request_is_cancelled_at_provider_deadline() -> Result<(), Box<dyn Error>> {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/indexes/contract__records/search"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_delay(Duration::from_millis(200))
                .set_body_json(json!({
                    "hits": [],
                    "processingTimeMs": 1,
                    "query": "needle"
                })),
        )
        .expect(1)
        .mount(&server)
        .await;
    let mut bounded_config = config(Url::parse(&server.uri())?);
    bounded_config.provider_timeout = Duration::from_millis(20);
    bounded_config.task_poll_interval = Duration::from_millis(5);
    bounded_config.projection_lease = Duration::from_secs(2);
    let adapter = Arc::new(MeilisearchAdapter::new(&bounded_config)?);
    let service = SearchService::new(
        adapter,
        Arc::new(FakeBatchReauthorizer::default()),
        schema()?,
        bounded_config,
    )?;

    assert_eq!(
        service
            .search(
                &TestPrincipalFactory::default().build()?,
                SearchInput::new("needle", Vec::new(), 5, 0)?,
            )
            .await,
        Err(SearchError::Provider(SearchProviderError::Timeout))
    );
    Ok(())
}

#[tokio::test]
async fn active_upsert_and_delete_reject_a_swapped_schema_marker() -> Result<(), Box<dyn Error>> {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path(
            "/indexes/contract__records/documents/omnius_schema_marker",
        ))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": "omnius_schema_marker",
            "_schema_version": 999,
            "_schema_digest": "swapped"
        })))
        .expect(2)
        .mount(&server)
        .await;
    let adapter = MeilisearchAdapter::new(&config(Url::parse(&server.uri())?))?;
    let schema = schema()?;
    let source_id = SourceId::new("record-swapped")?;
    let revision = SourceRevision::new(1)?;
    let mut fields = BTreeMap::new();
    fields.insert("title".to_owned(), json!("must not write"));
    let mutations = [
        ProjectionMutation::Upsert(ProjectionDocument::new(
            source_id.clone(),
            revision,
            fields,
        )?),
        ProjectionMutation::delete(source_id, revision),
    ];
    let target = ProjectionTarget::Active(schema);
    let tenant = TenantId::new();

    for mutation in &mutations {
        assert_eq!(
            adapter.apply(&target, tenant, mutation).await,
            Err(SearchProviderError::SchemaConflict)
        );
    }
    Ok(())
}

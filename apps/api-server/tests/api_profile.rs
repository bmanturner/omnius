//! Black-box reference API behavior against a migrated PostgreSQL database.

use std::{collections::HashSet, error::Error, sync::Arc, time::Duration};

use axum::{
    Extension, Router,
    body::{Body, to_bytes},
    http::{
        HeaderMap, Method, Request, StatusCode,
        header::{CONTENT_TYPE, ETAG},
    },
};
use omnius_api_server::{ReferenceApiState, reference_router};
use omnius_config::DeploymentEnvironment;
use omnius_core::RequestId;
use omnius_idempotency::{IdempotencyConfig, PostgresIdempotencyStore};
use omnius_migrations::{MIGRATOR, MigrationConfig, MigrationRunner, SchemaVersionRange};
use omnius_pagination::{CursorCodec, CursorSigningKey};
use omnius_postgres::{
    PostgresConfig, PostgresPool, PostgresTlsMode, TransactionIsolation, TransactionRetryConfig,
};
use omnius_test_support::{PostgresFixture, TestClock};
use serde_json::Value;
use time::OffsetDateTime;
use tower::ServiceExt as _;

const REFERENCE_SCHEMA_MINIMUM: i64 = 2_026_082_301;
const RESPONSE_BODY_LIMIT: usize = 64 * 1024;
const JSON: &str = "application/json";
const PROBLEM_JSON: &str = "application/problem+json";

struct CapturedResponse {
    status: StatusCode,
    headers: HeaderMap,
    body: Vec<u8>,
}

fn postgres_config(fixture: &PostgresFixture) -> PostgresConfig {
    PostgresConfig {
        url: fixture.database_url().clone(),
        tls_mode: PostgresTlsMode::Disable,
        min_connections: 1,
        max_connections: 4,
        connect_timeout: Duration::from_secs(5),
        acquire_timeout: Duration::from_secs(1),
        idle_timeout: Duration::from_secs(30),
        max_lifetime: Duration::from_secs(60),
        max_lifetime_jitter: Duration::from_secs(10),
        application_name: "omnius-api-profile-test".to_owned(),
        initialization_sql: Vec::new(),
        statement_timeout: Duration::from_secs(5),
        lock_timeout: Duration::from_secs(1),
        health_timeout: Duration::from_secs(2),
        shutdown_timeout: Duration::from_secs(3),
        transaction_retry: TransactionRetryConfig {
            max_attempts: 3,
            base_delay: Duration::from_millis(5),
            max_delay: Duration::from_millis(50),
            max_jitter: Duration::from_millis(5),
            isolation: TransactionIsolation::Serializable,
        },
    }
}

fn json_request(
    method: Method,
    uri: &str,
    body: &str,
    idempotency_key: Option<&str>,
    if_match: Option<&str>,
) -> Result<Request<Body>, axum::http::Error> {
    let mut builder = Request::builder()
        .method(method)
        .uri(uri)
        .header(CONTENT_TYPE, JSON);
    if let Some(key) = idempotency_key {
        builder = builder.header("idempotency-key", key);
    }
    if let Some(etag) = if_match {
        builder = builder.header("if-match", etag);
    }
    builder.body(Body::from(body.to_owned()))
}

fn empty_request(method: Method, uri: &str) -> Result<Request<Body>, axum::http::Error> {
    Request::builder()
        .method(method)
        .uri(uri)
        .body(Body::empty())
}

async fn send(app: &Router, request: Request<Body>) -> Result<CapturedResponse, Box<dyn Error>> {
    let response = app.clone().oneshot(request).await?;
    let (parts, body) = response.into_parts();
    let body = to_bytes(body, RESPONSE_BODY_LIMIT).await?.to_vec();
    Ok(CapturedResponse {
        status: parts.status,
        headers: parts.headers,
        body,
    })
}

fn assert_content_type(response: &CapturedResponse, expected: &str) {
    assert_eq!(
        response
            .headers
            .get(CONTENT_TYPE)
            .and_then(|value| value.to_str().ok()),
        Some(expected)
    );
}

fn json_body(response: &CapturedResponse) -> Result<Value, serde_json::Error> {
    serde_json::from_slice(&response.body)
}

fn assert_problem(
    response: &CapturedResponse,
    expected_status: StatusCode,
    expected_code: &str,
    request_id: RequestId,
) -> Result<(), Box<dyn Error>> {
    assert_eq!(response.status, expected_status);
    assert_content_type(response, PROBLEM_JSON);

    let problem = json_body(response)?;
    assert_eq!(
        problem["status"].as_u64(),
        Some(u64::from(expected_status.as_u16()))
    );
    assert_eq!(problem["code"].as_str(), Some(expected_code));
    assert_eq!(
        problem["request_id"].as_str(),
        Some(request_id.to_string().as_str())
    );
    let expected_type = format!(
        "https://errors.omnius.invalid/{}",
        expected_code.to_ascii_lowercase()
    );
    assert_eq!(problem["type"].as_str(), Some(expected_type.as_str()));
    assert!(
        problem["title"]
            .as_str()
            .is_some_and(|title| !title.is_empty())
    );
    assert!(
        problem["detail"]
            .as_str()
            .is_some_and(|detail| !detail.is_empty())
    );
    Ok(())
}

#[expect(
    clippy::too_many_lines,
    reason = "one end-to-end test deliberately exercises the complete public API profile"
)]
#[tokio::test]
async fn reference_api_profile_enforces_http_persistence_and_concurrency_contracts()
-> Result<(), Box<dyn Error>> {
    let fixture = PostgresFixture::start().await?;
    let pool =
        PostgresPool::connect(&postgres_config(&fixture), DeploymentEnvironment::Test).await?;
    let migration_runner = MigrationRunner::new(
        pool.clone(),
        &MIGRATOR,
        SchemaVersionRange::new(
            REFERENCE_SCHEMA_MINIMUM,
            omnius_migrations::CURRENT_SCHEMA_VERSION,
        )?,
        MigrationConfig {
            run_on_startup: false,
            operation_timeout: Duration::from_secs(10),
        },
        DeploymentEnvironment::Test,
    )?;
    let migration_status = migration_runner.run().await?;
    assert_eq!(
        migration_status.current_version,
        Some(omnius_migrations::CURRENT_SCHEMA_VERSION)
    );
    assert!(migration_status.pending_versions.is_empty());
    drop(migration_runner);

    let state = ReferenceApiState::new(
        pool.clone(),
        CursorCodec::new(CursorSigningKey::new([0x5a; CursorSigningKey::BYTE_LENGTH])),
        PostgresIdempotencyStore::new(IdempotencyConfig::default())?,
        Arc::new(TestClock::at(OffsetDateTime::from_unix_timestamp(
            1_777_000_000,
        )?)),
    );
    let request_id = RequestId::new();
    let app = reference_router(state).layer(Extension(request_id));

    let behavior: Result<(), Box<dyn Error>> = async {
        let missing_key = send(
            &app,
            json_request(
                Method::POST,
                "/reference-records",
                r#"{"name":"Alpha"}"#,
                None,
                None,
            )?,
        )
        .await?;
        assert_problem(
            &missing_key,
            StatusCode::BAD_REQUEST,
            "INVALID_IDEMPOTENCY_KEY",
            request_id,
        )?;

        let malformed_json = send(
            &app,
            json_request(
                Method::POST,
                "/reference-records",
                r#"{"name":"#,
                Some("malformed-json"),
                None,
            )?,
        )
        .await?;
        assert_problem(
            &malformed_json,
            StatusCode::BAD_REQUEST,
            "INVALID_JSON",
            request_id,
        )?;

        let unknown_json = send(
            &app,
            json_request(
                Method::POST,
                "/reference-records",
                r#"{"name":"Alpha","unknown":true}"#,
                Some("unknown-json"),
                None,
            )?,
        )
        .await?;
        assert_problem(
            &unknown_json,
            StatusCode::BAD_REQUEST,
            "INVALID_JSON",
            request_id,
        )?;

        let invalid_name = send(
            &app,
            json_request(
                Method::POST,
                "/reference-records",
                r#"{"name":"   "}"#,
                Some("invalid-name"),
                None,
            )?,
        )
        .await?;
        assert_problem(
            &invalid_name,
            StatusCode::UNPROCESSABLE_ENTITY,
            "VALIDATION_FAILED",
            request_id,
        )?;
        let invalid_name_problem = json_body(&invalid_name)?;
        assert_eq!(
            invalid_name_problem["errors"][0]["pointer"].as_str(),
            Some("/name")
        );
        assert_eq!(
            invalid_name_problem["errors"][0]["code"].as_str(),
            Some("invalid")
        );

        let create_body = r#"{"name":"Alpha"}"#;
        let created = send(
            &app,
            json_request(
                Method::POST,
                "/reference-records",
                create_body,
                Some("create-alpha"),
                None,
            )?,
        )
        .await?;
        assert_eq!(created.status, StatusCode::CREATED);
        assert_content_type(&created, JSON);
        let created_bytes = created.body.clone();
        let created_record = json_body(&created)?;
        let alpha_id = created_record["id"]
            .as_str()
            .ok_or("created response omitted id")?
            .to_owned();
        assert_eq!(created_record["name"].as_str(), Some("Alpha"));
        assert_eq!(created_record["version"].as_u64(), Some(1));

        let replay = send(
            &app,
            json_request(
                Method::POST,
                "/reference-records",
                create_body,
                Some("create-alpha"),
                None,
            )?,
        )
        .await?;
        assert_eq!(replay.status, StatusCode::CREATED);
        assert_content_type(&replay, JSON);
        assert_eq!(replay.body, created_bytes);

        let conflicting_replay = send(
            &app,
            json_request(
                Method::POST,
                "/reference-records",
                r#"{"name":"Different"}"#,
                Some("create-alpha"),
                None,
            )?,
        )
        .await?;
        assert_problem(
            &conflicting_replay,
            StatusCode::CONFLICT,
            "IDEMPOTENCY_CONFLICT",
            request_id,
        )?;

        let after_replay = send(
            &app,
            empty_request(Method::GET, "/reference-records?limit=100")?,
        )
        .await?;
        assert_eq!(after_replay.status, StatusCode::OK);
        assert_content_type(&after_replay, JSON);
        let after_replay_page = json_body(&after_replay)?;
        let replay_items = after_replay_page["items"]
            .as_array()
            .ok_or("list response omitted items")?;
        assert_eq!(
            replay_items.len(),
            1,
            "idempotent replay created a duplicate"
        );
        assert_eq!(replay_items[0]["id"].as_str(), Some(alpha_id.as_str()));

        let fetched = send(
            &app,
            empty_request(Method::GET, &format!("/reference-records/{alpha_id}"))?,
        )
        .await?;
        assert_eq!(fetched.status, StatusCode::OK);
        assert_content_type(&fetched, JSON);
        let original_etag = fetched
            .headers
            .get(ETAG)
            .ok_or("GET response omitted ETag")?
            .to_str()?
            .to_owned();
        assert_eq!(original_etag, r#""v1""#);
        assert_eq!(json_body(&fetched)?["id"].as_str(), Some(alpha_id.as_str()));

        let missing_if_match = send(
            &app,
            json_request(
                Method::PUT,
                &format!("/reference-records/{alpha_id}"),
                r#"{"name":"Alpha updated"}"#,
                None,
                None,
            )?,
        )
        .await?;
        assert_problem(
            &missing_if_match,
            StatusCode::PRECONDITION_REQUIRED,
            "PRECONDITION_REQUIRED",
            request_id,
        )?;

        let updated = send(
            &app,
            json_request(
                Method::PUT,
                &format!("/reference-records/{alpha_id}"),
                r#"{"name":"Alpha updated"}"#,
                None,
                Some(&original_etag),
            )?,
        )
        .await?;
        assert_eq!(updated.status, StatusCode::OK);
        assert_content_type(&updated, JSON);
        let updated_etag = updated
            .headers
            .get(ETAG)
            .ok_or("PUT response omitted ETag")?
            .to_str()?
            .to_owned();
        assert_eq!(updated_etag, r#""v2""#);
        assert_ne!(updated_etag, original_etag);
        let updated_record = json_body(&updated)?;
        assert_eq!(updated_record["id"].as_str(), Some(alpha_id.as_str()));
        assert_eq!(updated_record["name"].as_str(), Some("Alpha updated"));
        assert_eq!(updated_record["version"].as_u64(), Some(2));

        let stale_update = send(
            &app,
            json_request(
                Method::PUT,
                &format!("/reference-records/{alpha_id}"),
                r#"{"name":"Stale update"}"#,
                None,
                Some(&original_etag),
            )?,
        )
        .await?;
        assert_problem(
            &stale_update,
            StatusCode::PRECONDITION_FAILED,
            "PRECONDITION_FAILED",
            request_id,
        )?;

        let mut expected_ids = HashSet::from([alpha_id.clone()]);
        for (name, key) in [("Beta", "create-beta"), ("Gamma", "create-gamma")] {
            let response = send(
                &app,
                json_request(
                    Method::POST,
                    "/reference-records",
                    &format!(r#"{{"name":"{name}"}}"#),
                    Some(key),
                    None,
                )?,
            )
            .await?;
            assert_eq!(response.status, StatusCode::CREATED);
            assert_content_type(&response, JSON);
            let record = json_body(&response)?;
            assert_eq!(record["name"].as_str(), Some(name));
            expected_ids.insert(
                record["id"]
                    .as_str()
                    .ok_or("create response omitted id")?
                    .to_owned(),
            );
        }

        let filtered = send(
            &app,
            empty_request(Method::GET, "/reference-records?limit=1&name=GAM")?,
        )
        .await?;
        assert_eq!(filtered.status, StatusCode::OK);
        assert_content_type(&filtered, JSON);
        let filtered_page = json_body(&filtered)?;
        let filtered_items = filtered_page["items"]
            .as_array()
            .ok_or("filtered list response omitted items")?;
        assert_eq!(filtered_items.len(), 1);
        assert_eq!(filtered_items[0]["name"].as_str(), Some("Gamma"));
        assert!(filtered_page["next_cursor"].is_null());

        let invalid_filter = send(
            &app,
            empty_request(Method::GET, "/reference-records?name=%20%20%20")?,
        )
        .await?;
        assert_problem(
            &invalid_filter,
            StatusCode::BAD_REQUEST,
            "INVALID_FILTER",
            request_id,
        )?;

        let mut seen_ids = HashSet::new();
        let mut cursor: Option<String> = None;
        let mut first_cursor: Option<String> = None;
        for page_index in 0..expected_ids.len() {
            let uri = match &cursor {
                Some(cursor) => format!("/reference-records?limit=1&cursor={cursor}"),
                None => "/reference-records?limit=1".to_owned(),
            };
            let response = send(&app, empty_request(Method::GET, &uri)?).await?;
            assert_eq!(response.status, StatusCode::OK);
            assert_content_type(&response, JSON);
            let page = json_body(&response)?;
            let items = page["items"]
                .as_array()
                .ok_or("page response omitted items")?;
            assert_eq!(items.len(), 1);
            let id = items[0]["id"]
                .as_str()
                .ok_or("page item omitted id")?
                .to_owned();
            assert!(seen_ids.insert(id), "cursor traversal returned a duplicate");

            let next_cursor = page["next_cursor"].as_str().map(ToOwned::to_owned);
            if page_index + 1 < expected_ids.len() {
                assert!(next_cursor.is_some(), "cursor traversal ended early");
            } else {
                assert!(next_cursor.is_none(), "final cursor page did not terminate");
            }
            if first_cursor.is_none() {
                first_cursor.clone_from(&next_cursor);
            }
            cursor = next_cursor;
        }
        assert_eq!(seen_ids, expected_ids);

        let malformed_cursor = send(
            &app,
            empty_request(
                Method::GET,
                "/reference-records?limit=1&cursor=not-a-valid-cursor",
            )?,
        )
        .await?;
        assert_problem(
            &malformed_cursor,
            StatusCode::BAD_REQUEST,
            "INVALID_CURSOR",
            request_id,
        )?;

        let mut tampered_cursor = first_cursor
            .ok_or("paginated response omitted a continuation cursor")?
            .into_bytes();
        tampered_cursor[0] = if tampered_cursor[0] == b'A' {
            b'B'
        } else {
            b'A'
        };
        let tampered_cursor = String::from_utf8(tampered_cursor)?;
        let tampered_cursor = send(
            &app,
            empty_request(
                Method::GET,
                &format!("/reference-records?limit=1&cursor={tampered_cursor}"),
            )?,
        )
        .await?;
        assert_problem(
            &tampered_cursor,
            StatusCode::BAD_REQUEST,
            "INVALID_CURSOR",
            request_id,
        )?;

        let deleted = send(
            &app,
            empty_request(Method::DELETE, &format!("/reference-records/{alpha_id}"))?,
        )
        .await?;
        assert_eq!(deleted.status, StatusCode::NO_CONTENT);
        assert!(deleted.body.is_empty());

        let after_delete = send(
            &app,
            empty_request(Method::GET, &format!("/reference-records/{alpha_id}"))?,
        )
        .await?;
        assert_problem(
            &after_delete,
            StatusCode::NOT_FOUND,
            "REFERENCE_RECORD_NOT_FOUND",
            request_id,
        )?;

        let repeated_delete = send(
            &app,
            empty_request(Method::DELETE, &format!("/reference-records/{alpha_id}"))?,
        )
        .await?;
        assert_problem(
            &repeated_delete,
            StatusCode::NOT_FOUND,
            "REFERENCE_RECORD_NOT_FOUND",
            request_id,
        )?;

        Ok(())
    }
    .await;

    drop(app);
    let close_result = pool.close().await;
    let cleanup_result = fixture.cleanup().await;
    behavior?;
    close_result?;
    cleanup_result?;
    Ok(())
}

//! Real Redis session rotation, disabled-mode, and required-readiness contracts.

use std::{error::Error, time::Duration};

use axum::{
    Router,
    extract::State,
    http::StatusCode,
    routing::{get, post},
};
use rsk_auth_core::{
    SessionConfig, SessionRegistration, SessionStoreKind, SessionValidation, SubjectId,
};
use rsk_auth_session_redis::{
    RedisSessionError, RedisSessionIsolation, RedisSessionLifecycle, RedisSessionStore,
};
use rsk_config::{DeploymentEnvironment, ExposeSecret as _, SecretString};
use rsk_core::{BuildMetadata, BuildMetadataInput, SchemaCompatibility};
use rsk_health::{HealthBuilder, HealthConfig};
use rsk_redis_core::{RedisConfig, RedisReconnectConfig};
use rsk_test_support::RedisFixture;
use time::OffsetDateTime;
use tower::ServiceExt as _;
use tower_sessions::{Session, session::Id};
use uuid::Uuid;

fn redis_config(fixture: &RedisFixture) -> RedisConfig {
    RedisConfig {
        enabled: true,
        url: Some(fixture.redis_url().clone()),
        connection_timeout: Duration::from_secs(2),
        startup_timeout: Duration::from_secs(5),
        command_timeout: Duration::from_millis(500),
        health_timeout: Duration::from_secs(1),
        client_name: "rsk-session-integration".to_owned(),
        key_prefix: fixture.namespace().replace(':', "-"),
        schema_version: "v1".to_owned(),
        max_value_bytes: 16 * 1024,
        reconnect: RedisReconnectConfig::default(),
    }
}

fn session_config() -> SessionConfig {
    SessionConfig {
        store: SessionStoreKind::Redis,
        secure: false,
        cookie_name: "test_session".to_owned(),
        ..SessionConfig::default()
    }
}

fn metadata() -> Result<BuildMetadata, rsk_core::InvalidBuildMetadata> {
    BuildMetadata::current(BuildMetadataInput {
        service: "redis-session-test",
        profile: "authenticated-api",
        modules: &["auth-core", "auth-session-redis", "health", "redis-core"],
        schema: SchemaCompatibility {
            minimum: "0",
            maximum: "0",
        },
    })
}

fn cookie_pair(response: &axum::response::Response) -> Result<String, Box<dyn Error>> {
    let value = response
        .headers()
        .get("set-cookie")
        .ok_or_else(|| std::io::Error::other("session response did not set a cookie"))?
        .to_str()?;
    Ok(value
        .split(';')
        .next()
        .ok_or_else(|| std::io::Error::other("session cookie is empty"))?
        .to_owned())
}
fn cookie_session_id(cookie: &str) -> Result<&str, Box<dyn Error>> {
    cookie
        .split_once('=')
        .map(|(_, value)| value)
        .ok_or_else(|| std::io::Error::other("session cookie has no value").into())
}

fn request(
    method: &str,
    path: &str,
    cookie: Option<&str>,
) -> Result<axum::http::Request<axum::body::Body>, axum::http::Error> {
    let mut builder = axum::http::Request::builder().method(method).uri(path);
    if let Some(cookie) = cookie {
        builder = builder.header("cookie", cookie);
    }
    builder.body(axum::body::Body::empty())
}

async fn seed(session: Session) -> StatusCode {
    if session.insert("state", "anonymous").await.is_ok() {
        StatusCode::NO_CONTENT
    } else {
        StatusCode::INTERNAL_SERVER_ERROR
    }
}

async fn login(session: Session) -> StatusCode {
    if session.cycle_id().await.is_err() || session.insert("state", "authenticated").await.is_err()
    {
        StatusCode::INTERNAL_SERVER_ERROR
    } else {
        StatusCode::NO_CONTENT
    }
}

async fn read_state(session: Session) -> String {
    session
        .get::<String>("state")
        .await
        .ok()
        .flatten()
        .unwrap_or_else(|| "none".to_owned())
}
#[derive(Clone)]
struct LifecycleState {
    lifecycle: RedisSessionLifecycle,
    subject_id: SubjectId,
    device_a: Uuid,
    device_b: Uuid,
}

async fn lifecycle_login(
    State(state): State<LifecycleState>,
    session: Session,
    device_id: Uuid,
) -> StatusCode {
    if session.cycle_id().await.is_err() || session.insert("state", "authenticated").await.is_err()
    {
        return StatusCode::INTERNAL_SERVER_ERROR;
    }
    let registration = SessionRegistration {
        subject_id: state.subject_id,
        device_id,
        created_at: OffsetDateTime::now_utc(),
        user_agent_hash: None,
        ip_prefix: None,
    };
    match state
        .lifecycle
        .register_after_login(&session, &registration)
        .await
    {
        Ok(()) => StatusCode::NO_CONTENT,
        Err(_) => StatusCode::INTERNAL_SERVER_ERROR,
    }
}

async fn lifecycle_login_a(State(state): State<LifecycleState>, session: Session) -> StatusCode {
    let device_id = state.device_a;
    lifecycle_login(State(state), session, device_id).await
}

async fn lifecycle_login_b(State(state): State<LifecycleState>, session: Session) -> StatusCode {
    let device_id = state.device_b;
    lifecycle_login(State(state), session, device_id).await
}

async fn lifecycle_validate(State(state): State<LifecycleState>, session: Session) -> StatusCode {
    match state
        .lifecycle
        .validate_and_touch(&session, state.subject_id, OffsetDateTime::now_utc())
        .await
    {
        Ok(SessionValidation::Active(_)) => StatusCode::NO_CONTENT,
        Ok(SessionValidation::Rejected) => StatusCode::UNAUTHORIZED,
        Err(_) => StatusCode::SERVICE_UNAVAILABLE,
    }
}

async fn lifecycle_metadata(State(state): State<LifecycleState>, session: Session) -> StatusCode {
    match state
        .lifecycle
        .list_active(state.subject_id, &session, OffsetDateTime::now_utc())
        .await
    {
        Ok(metadata)
            if metadata
                .iter()
                .any(|entry| entry.current && entry.device_id == state.device_a) =>
        {
            StatusCode::NO_CONTENT
        }
        Ok(_) => StatusCode::UNAUTHORIZED,
        Err(_) => StatusCode::SERVICE_UNAVAILABLE,
    }
}

async fn lifecycle_rotate(State(state): State<LifecycleState>, session: Session) -> StatusCode {
    let registration = SessionRegistration {
        subject_id: state.subject_id,
        device_id: state.device_a,
        created_at: OffsetDateTime::now_utc(),
        user_agent_hash: None,
        ip_prefix: None,
    };
    match state
        .lifecycle
        .rotate_after_security_change(
            &session,
            state.subject_id,
            &registration,
            OffsetDateTime::now_utc(),
        )
        .await
    {
        Ok(true) => StatusCode::NO_CONTENT,
        _ => StatusCode::INTERNAL_SERVER_ERROR,
    }
}

async fn lifecycle_revoke_current(
    State(state): State<LifecycleState>,
    session: Session,
) -> StatusCode {
    match state
        .lifecycle
        .revoke_current(&session, state.subject_id)
        .await
    {
        Ok(true) => StatusCode::NO_CONTENT,
        Ok(false) => StatusCode::NOT_FOUND,
        Err(_) => StatusCode::SERVICE_UNAVAILABLE,
    }
}

async fn lifecycle_revoke_device(State(state): State<LifecycleState>) -> StatusCode {
    match state
        .lifecycle
        .revoke_device(state.subject_id, state.device_a)
        .await
    {
        Ok(_) => StatusCode::NO_CONTENT,
        Err(_) => StatusCode::SERVICE_UNAVAILABLE,
    }
}

async fn lifecycle_revoke_all(State(state): State<LifecycleState>) -> StatusCode {
    match state.lifecycle.revoke_all(state.subject_id).await {
        Ok(_) => StatusCode::NO_CONTENT,
        Err(_) => StatusCode::SERVICE_UNAVAILABLE,
    }
}

#[tokio::test]
async fn redis_provider_rotates_fixated_session_and_expires_with_required_health()
-> Result<(), Box<dyn Error>> {
    let fixture = RedisFixture::start().await?;
    assert!(matches!(
        RedisSessionStore::connect(
            &session_config(),
            &redis_config(&fixture),
            RedisSessionIsolation::Database(1),
            DeploymentEnvironment::Test,
        )
        .await,
        Err(RedisSessionError::IsolationMismatch)
    ));
    let Some(store) = RedisSessionStore::connect(
        &session_config(),
        &redis_config(&fixture),
        RedisSessionIsolation::DedicatedInstance,
        DeploymentEnvironment::Test,
    )
    .await?
    else {
        return Err(std::io::Error::other("enabled Redis sessions unexpectedly disabled").into());
    };
    let app = Router::new()
        .route("/seed", post(seed))
        .route("/login", post(login))
        .route("/state", get(read_state))
        .layer(store.session_manager_layer()?);

    let seeded = app.clone().oneshot(request("POST", "/seed", None)?).await?;
    assert_eq!(seeded.status(), StatusCode::NO_CONTENT);
    let old_cookie = cookie_pair(&seeded)?;
    let logged_in = app
        .clone()
        .oneshot(request("POST", "/login", Some(&old_cookie))?)
        .await?;
    assert_eq!(logged_in.status(), StatusCode::NO_CONTENT);
    let new_cookie = cookie_pair(&logged_in)?;
    assert_ne!(new_cookie, old_cookie);

    let old_state = app
        .clone()
        .oneshot(request("GET", "/state", Some(&old_cookie))?)
        .await?;
    assert_eq!(
        axum::body::to_bytes(old_state.into_body(), 64).await?,
        "none"
    );
    let new_state = app
        .oneshot(request("GET", "/state", Some(&new_cookie))?)
        .await?;
    assert_eq!(
        axum::body::to_bytes(new_state.into_body(), 64).await?,
        "authenticated"
    );

    let mut health_builder = HealthBuilder::new(metadata()?, HealthConfig::default())?;
    health_builder.register(store.health_check())?;
    let health = health_builder.build();
    health.mark_started();
    health.refresh_once().await;
    assert!(health.is_ready());

    fixture.cleanup().await?;
    health.refresh_once().await;
    assert!(!health.is_ready());
    store.shutdown().await;
    Ok(())
}

#[tokio::test]
async fn lifecycle_acl_without_expiry_commands_fails_readiness() -> Result<(), Box<dyn Error>> {
    const USERNAME: &str = "no_expiry_sessions";
    const PASSWORD: &str = "no-expiry-test-password";

    let fixture = RedisFixture::start().await?;
    let admin = redis::Client::open(fixture.redis_url().expose_secret())?;
    let mut connection = admin.get_multiplexed_async_connection().await?;
    redis::cmd("ACL")
        .arg("SETUSER")
        .arg(USERNAME)
        .arg("on")
        .arg(format!(">{PASSWORD}"))
        .arg("~*")
        .arg("+ping")
        .arg("+client|setname")
        .arg("+get")
        .arg("+set")
        .arg("+del")
        .arg("+eval")
        .arg("+type")
        .arg("+exists")
        .arg("+incr")
        .arg("+sadd")
        .arg("+scard")
        .arg("+sismember")
        .arg("+smembers")
        .arg("+srem")
        .query_async::<()>(&mut connection)
        .await?;

    let mut restricted_url = redis::parse_redis_url(fixture.redis_url().expose_secret())
        .ok_or_else(|| std::io::Error::other("fixture returned an invalid Redis URL"))?;
    restricted_url
        .set_username(USERNAME)
        .map_err(|()| std::io::Error::other("Redis username was invalid"))?;
    restricted_url
        .set_password(Some(PASSWORD))
        .map_err(|()| std::io::Error::other("Redis password was invalid"))?;
    let mut restricted = redis_config(&fixture);
    restricted.url = Some(SecretString::from(restricted_url.to_string()));
    let restricted_client = redis::Client::open(restricted_url.to_string())?;
    let mut restricted_connection = restricted_client.get_multiplexed_async_connection().await?;
    assert_eq!(
        redis::cmd("PING")
            .query_async::<String>(&mut restricted_connection)
            .await?,
        "PONG"
    );

    assert!(matches!(
        RedisSessionStore::connect(
            &session_config(),
            &restricted,
            RedisSessionIsolation::DedicatedInstance,
            DeploymentEnvironment::Test,
        )
        .await,
        Err(RedisSessionError::Connect)
    ));
    fixture.cleanup().await?;
    Ok(())
}

#[tokio::test]
async fn disabled_and_wrong_provider_outcomes_are_explicit() -> Result<(), Box<dyn Error>> {
    let disabled = SessionConfig {
        enabled: false,
        ..SessionConfig::default()
    };
    assert!(
        RedisSessionStore::connect(
            &disabled,
            &RedisConfig::default(),
            RedisSessionIsolation::DedicatedInstance,
            DeploymentEnvironment::Production,
        )
        .await?
        .is_none()
    );
    assert!(matches!(
        RedisSessionStore::connect(
            &SessionConfig::default(),
            &RedisConfig::default(),
            RedisSessionIsolation::DedicatedInstance,
            DeploymentEnvironment::Test,
        )
        .await,
        Err(RedisSessionError::SessionConfig)
    ));
    Ok(())
}

async fn lifecycle_fixture()
-> Result<(RedisFixture, RedisSessionStore, LifecycleState, Router), Box<dyn Error>> {
    let fixture = RedisFixture::start().await?;
    let config = SessionConfig {
        idle_timeout: Duration::from_secs(3),
        absolute_timeout: Duration::from_secs(5),
        ..session_config()
    };
    let store = RedisSessionStore::connect(
        &config,
        &redis_config(&fixture),
        RedisSessionIsolation::DedicatedInstance,
        DeploymentEnvironment::Test,
    )
    .await?
    .ok_or_else(|| std::io::Error::other("enabled Redis sessions unexpectedly disabled"))?;
    let state = LifecycleState {
        lifecycle: store.lifecycle(),
        subject_id: SubjectId::new(),
        device_a: Uuid::now_v7(),
        device_b: Uuid::now_v7(),
    };
    let app = Router::new()
        .route("/login/a", post(lifecycle_login_a))
        .route("/login/b", post(lifecycle_login_b))
        .route("/validate", get(lifecycle_validate))
        .route("/metadata", get(lifecycle_metadata))
        .route("/rotate", post(lifecycle_rotate))
        .route("/revoke/current", post(lifecycle_revoke_current))
        .route("/revoke/device", post(lifecycle_revoke_device))
        .route("/revoke/all", post(lifecycle_revoke_all))
        .with_state(state.clone())
        .layer(store.session_manager_layer()?);
    Ok((fixture, store, state, app))
}

async fn provider_key_count(
    connection: &mut redis::aio::MultiplexedConnection,
) -> Result<usize, redis::RedisError> {
    Ok(redis::cmd("KEYS")
        .arg("*")
        .query_async::<Vec<String>>(connection)
        .await?
        .into_iter()
        .filter(|key| !key.starts_with("__rsk:"))
        .count())
}

#[tokio::test]
async fn lifecycle_caps_absolute_expiry_and_rotates_provider_id() -> Result<(), Box<dyn Error>> {
    let (fixture, store, _state, app) = lifecycle_fixture().await?;
    let login = app
        .clone()
        .oneshot(request("POST", "/login/a", None)?)
        .await?;
    let cookie = cookie_pair(&login)?;
    for _ in 0..2 {
        tokio::time::sleep(Duration::from_secs(1)).await;
        assert_eq!(
            app.clone()
                .oneshot(request("GET", "/validate", Some(&cookie))?)
                .await?
                .status(),
            StatusCode::NO_CONTENT
        );
    }
    tokio::time::sleep(Duration::from_millis(3_200)).await;
    assert_eq!(
        app.clone()
            .oneshot(request("GET", "/validate", Some(&cookie))?)
            .await?
            .status(),
        StatusCode::UNAUTHORIZED
    );

    let old = app
        .clone()
        .oneshot(request("POST", "/login/a", None)?)
        .await?;
    let old_cookie = cookie_pair(&old)?;
    let rotated = app
        .clone()
        .oneshot(request("POST", "/rotate", Some(&old_cookie))?)
        .await?;
    let new_cookie = cookie_pair(&rotated)?;
    assert_ne!(new_cookie, old_cookie);
    assert_eq!(
        app.clone()
            .oneshot(request("GET", "/validate", Some(&old_cookie))?)
            .await?
            .status(),
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        app.oneshot(request("GET", "/metadata", Some(&new_cookie))?)
            .await?
            .status(),
        StatusCode::NO_CONTENT
    );
    fixture.cleanup().await?;
    store.shutdown().await;
    Ok(())
}

#[tokio::test]
async fn concurrent_security_rotations_create_exactly_one_successor() -> Result<(), Box<dyn Error>>
{
    let (fixture, store, _state, app) = lifecycle_fixture().await?;
    let login = app
        .clone()
        .oneshot(request("POST", "/login/a", None)?)
        .await?;
    let old_cookie = cookie_pair(&login)?;
    let first = app
        .clone()
        .oneshot(request("POST", "/rotate", Some(&old_cookie))?);
    let second = app
        .clone()
        .oneshot(request("POST", "/rotate", Some(&old_cookie))?);
    let (first, second) = tokio::join!(first, second);
    let first = first?;
    let second = second?;
    let (success, conflict) = if first.status() == StatusCode::NO_CONTENT {
        (first, second)
    } else {
        (second, first)
    };
    assert_eq!(success.status(), StatusCode::NO_CONTENT);
    assert_eq!(conflict.status(), StatusCode::INTERNAL_SERVER_ERROR);
    let successor_cookie = cookie_pair(&success)?;
    assert_ne!(successor_cookie, old_cookie);

    let admin = redis::Client::open(fixture.redis_url().expose_secret())?;
    let mut connection = admin.get_multiplexed_async_connection().await?;
    assert_eq!(provider_key_count(&mut connection).await?, 1);
    assert_eq!(
        app.clone()
            .oneshot(request("GET", "/validate", Some(&old_cookie))?)
            .await?
            .status(),
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        app.oneshot(request("GET", "/validate", Some(&successor_cookie))?)
            .await?
            .status(),
        StatusCode::NO_CONTENT
    );

    fixture.cleanup().await?;
    store.shutdown().await;
    Ok(())
}

#[tokio::test]
async fn lifecycle_revokes_current_device_and_subject_provider_rows() -> Result<(), Box<dyn Error>>
{
    let (fixture, store, _state, app) = lifecycle_fixture().await?;
    let current = app
        .clone()
        .oneshot(request("POST", "/login/a", None)?)
        .await?;
    let current_cookie = cookie_pair(&current)?;
    let second_a = app
        .clone()
        .oneshot(request("POST", "/login/a", None)?)
        .await?;
    let second_a_cookie = cookie_pair(&second_a)?;
    let first_b = app
        .clone()
        .oneshot(request("POST", "/login/b", None)?)
        .await?;
    let first_b_cookie = cookie_pair(&first_b)?;
    let admin = redis::Client::open(fixture.redis_url().expose_secret())?;
    let mut connection = admin.get_multiplexed_async_connection().await?;
    let before = provider_key_count(&mut connection).await?;

    assert_eq!(
        app.clone()
            .oneshot(request("POST", "/revoke/current", Some(&current_cookie))?)
            .await?
            .status(),
        StatusCode::NO_CONTENT
    );
    assert_eq!(provider_key_count(&mut connection).await? + 1, before);
    for (cookie, expected) in [
        (&current_cookie, StatusCode::UNAUTHORIZED),
        (&second_a_cookie, StatusCode::NO_CONTENT),
    ] {
        assert_eq!(
            app.clone()
                .oneshot(request("GET", "/validate", Some(cookie))?)
                .await?
                .status(),
            expected
        );
    }

    assert_eq!(
        app.clone()
            .oneshot(request("POST", "/revoke/device", None)?)
            .await?
            .status(),
        StatusCode::NO_CONTENT
    );
    for (cookie, expected) in [
        (&second_a_cookie, StatusCode::UNAUTHORIZED),
        (&first_b_cookie, StatusCode::NO_CONTENT),
    ] {
        assert_eq!(
            app.clone()
                .oneshot(request("GET", "/validate", Some(cookie))?)
                .await?
                .status(),
            expected
        );
    }

    let replacement = app
        .clone()
        .oneshot(request("POST", "/login/a", None)?)
        .await?;
    let replacement_cookie = cookie_pair(&replacement)?;
    assert_eq!(
        app.clone()
            .oneshot(request("POST", "/revoke/all", None)?)
            .await?
            .status(),
        StatusCode::NO_CONTENT
    );
    assert_eq!(provider_key_count(&mut connection).await?, 0);
    for cookie in [&first_b_cookie, &replacement_cookie] {
        assert_eq!(
            app.clone()
                .oneshot(request("GET", "/validate", Some(cookie))?)
                .await?
                .status(),
            StatusCode::UNAUTHORIZED
        );
    }
    fixture.cleanup().await?;
    store.shutdown().await;
    Ok(())
}

#[tokio::test]
async fn corrupt_subject_member_never_deletes_the_foreign_provider() -> Result<(), Box<dyn Error>> {
    let (fixture, store, state, app) = lifecycle_fixture().await?;
    let current = app
        .clone()
        .oneshot(request("POST", "/login/a", None)?)
        .await?;
    let current_cookie = cookie_pair(&current)?;
    let foreign = app
        .clone()
        .oneshot(request("POST", "/login/b", None)?)
        .await?;
    let foreign_cookie = cookie_pair(&foreign)?;
    let foreign_raw = cookie_session_id(&foreign_cookie)?;

    let subject_token = state.subject_id.as_uuid().to_string();
    let subject_index = format!("__rsk:lifecycle:v1:subject:{subject_token}");
    let corrupt_member = format!("{}:{}:{foreign_raw}", Uuid::now_v7(), Uuid::now_v7());
    let admin = redis::Client::open(fixture.redis_url().expose_secret())?;
    let mut connection = admin.get_multiplexed_async_connection().await?;
    assert_eq!(
        redis::cmd("SADD")
            .arg(&subject_index)
            .arg(&corrupt_member)
            .query_async::<i64>(&mut connection)
            .await?,
        1
    );

    assert_eq!(
        app.clone()
            .oneshot(request("GET", "/metadata", Some(&current_cookie))?)
            .await?
            .status(),
        StatusCode::NO_CONTENT
    );
    assert_eq!(
        redis::cmd("SISMEMBER")
            .arg(&subject_index)
            .arg(&corrupt_member)
            .query_async::<i64>(&mut connection)
            .await?,
        0
    );
    assert_eq!(
        app.oneshot(request("GET", "/validate", Some(&foreign_cookie))?)
            .await?
            .status(),
        StatusCode::NO_CONTENT
    );

    fixture.cleanup().await?;
    store.shutdown().await;
    Ok(())
}

#[tokio::test]
async fn lifecycle_cleans_stale_indexes_and_expired_tombstones() -> Result<(), Box<dyn Error>> {
    let (fixture, store, state, _app) = lifecycle_fixture().await?;
    let lifecycle = store.lifecycle();
    let admin = redis::Client::open(fixture.redis_url().expose_secret())?;
    let mut connection = admin.get_multiplexed_async_connection().await?;
    let tombstone_device = Uuid::now_v7();
    let tombstone_token = format!("{}:{tombstone_device}", state.subject_id.as_uuid());
    let tombstone_index = format!("__rsk:lifecycle:v1:device:{tombstone_token}");
    let tombstone_epoch = format!("__rsk:lifecycle:v1:device-epoch:{tombstone_token}");
    assert_eq!(
        lifecycle
            .revoke_device(state.subject_id, tombstone_device)
            .await?,
        0
    );
    lifecycle.cleanup(OffsetDateTime::now_utc()).await?;
    assert_eq!(
        redis::cmd("SISMEMBER")
            .arg("__rsk:lifecycle:v1:devices")
            .arg(&tombstone_token)
            .query_async::<i64>(&mut connection)
            .await?,
        1
    );
    redis::cmd("PEXPIREAT")
        .arg(&tombstone_epoch)
        .arg(0)
        .query_async::<i64>(&mut connection)
        .await?;
    lifecycle.cleanup(OffsetDateTime::now_utc()).await?;
    assert_eq!(
        redis::cmd("EXISTS")
            .arg(&tombstone_index)
            .arg(&tombstone_epoch)
            .query_async::<i64>(&mut connection)
            .await?,
        0
    );
    assert_eq!(
        redis::cmd("SISMEMBER")
            .arg("__rsk:lifecycle:v1:devices")
            .arg(&tombstone_token)
            .query_async::<i64>(&mut connection)
            .await?,
        0
    );
    let subject_token = state.subject_id.as_uuid().to_string();
    let device_token = format!("{subject_token}:{}", state.device_a);
    let subject_index = format!("__rsk:lifecycle:v1:subject:{subject_token}");
    let device_index = format!("__rsk:lifecycle:v1:device:{device_token}");
    let stale_lineage = Uuid::now_v7();
    let lineage_token = format!("{subject_token}:{stale_lineage}");
    let lineage_index = format!("__rsk:lifecycle:v1:lineage:{lineage_token}");
    let stale_raw = Id::default().to_string();
    for (index, member) in [
        ("__rsk:lifecycle:v1:subjects", subject_token.clone()),
        ("__rsk:lifecycle:v1:devices", device_token.clone()),
        ("__rsk:lifecycle:v1:lineages", lineage_token.clone()),
        (
            subject_index.as_str(),
            format!("{}:{stale_lineage}:{stale_raw}", state.device_a),
        ),
        (
            device_index.as_str(),
            format!("{stale_lineage}:{stale_raw}"),
        ),
        (
            lineage_index.as_str(),
            format!("{}:{stale_raw}", state.device_a),
        ),
    ] {
        redis::cmd("SADD")
            .arg(index)
            .arg(member)
            .query_async::<i64>(&mut connection)
            .await?;
    }
    assert!(
        lifecycle
            .cleanup(OffsetDateTime::now_utc())
            .await?
            .metadata_rows
            >= 3
    );
    assert_eq!(
        redis::cmd("EXISTS")
            .arg(&subject_index)
            .arg(&device_index)
            .arg(&lineage_index)
            .query_async::<i64>(&mut connection)
            .await?,
        0
    );

    fixture.cleanup().await?;
    store.shutdown().await;
    Ok(())
}

#[tokio::test]
async fn lifecycle_fails_closed_on_provider_outage() -> Result<(), Box<dyn Error>> {
    let (fixture, store, _state, app) = lifecycle_fixture().await?;
    let login = app
        .clone()
        .oneshot(request("POST", "/login/b", None)?)
        .await?;
    let cookie = cookie_pair(&login)?;
    fixture.cleanup().await?;
    assert_ne!(
        app.oneshot(request("GET", "/validate", Some(&cookie))?)
            .await?
            .status(),
        StatusCode::NO_CONTENT
    );
    store.shutdown().await;
    Ok(())
}

//! Real Redis session rotation, disabled-mode, and required-readiness contracts.

use std::{error::Error, time::Duration};

use axum::{
    Router,
    http::StatusCode,
    routing::{get, post},
};
use rsk_auth_core::{SessionConfig, SessionStoreKind};
use rsk_auth_session_redis::{RedisSessionError, RedisSessionIsolation, RedisSessionStore};
use rsk_config::{DeploymentEnvironment, ExposeSecret as _, SecretString};
use rsk_core::{BuildMetadata, BuildMetadataInput, SchemaCompatibility};
use rsk_health::{HealthBuilder, HealthConfig};
use rsk_redis_core::{RedisConfig, RedisReconnectConfig};
use rsk_test_support::RedisFixture;
use tower::ServiceExt as _;
use tower_sessions::Session;

fn redis_config(fixture: &RedisFixture) -> RedisConfig {
    RedisConfig {
        enabled: true,
        url: Some(fixture.redis_url().clone()),
        connection_timeout: Duration::from_secs(2),
        startup_timeout: Duration::from_secs(5),
        command_timeout: Duration::from_millis(100),
        health_timeout: Duration::from_millis(200),
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
async fn ping_only_acl_cannot_pass_authoritative_startup() -> Result<(), Box<dyn Error>> {
    const USERNAME: &str = "ping_only_sessions";
    const PASSWORD: &str = "ping-only-test-password";

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

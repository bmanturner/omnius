//! Real HTTP and PostgreSQL proof for fixation, cookie, CSRF, and lifecycle behavior.

use std::{error::Error, sync::Arc, time::Duration};

use axum::{
    Extension, Router,
    body::{Body, to_bytes},
    extract::State,
    http::{Request, Response, StatusCode, header},
    middleware,
    routing::{get, post},
};
use axum_login::{AuthManagerLayerBuilder, AuthSession, AuthnBackend as _};
use omnius_auth_core::{SessionConfig, SessionRegistration, SessionValidation, SubjectId};
use omnius_auth_session_postgres::{
    PostgresSessionLifecycle, SessionBackend, SessionRevocationGuard, SessionUser,
    guard_revoked_session, session_manager_layer,
};
use omnius_config::{DeploymentEnvironment, SecretString};
use omnius_http::{HttpShell, HttpShellConfig};
use omnius_migrations::{MIGRATOR, MigrationConfig, MigrationRunner, SchemaVersionRange};
use omnius_postgres::{
    PostgresConfig, PostgresPool, PostgresTlsMode, TransactionIsolation, TransactionRetryConfig,
};
use omnius_test_support::PostgresFixture;
use time::OffsetDateTime;
use tokio::sync::Notify;
use tower::ServiceExt as _;
use tower_sessions::Session;
use uuid::Uuid;

const FIRST_MIGRATION: i64 = 2_026_082_301;
const TRUSTED_ORIGIN: &str = "https://app.example.test";

type BrowserAuthSession = AuthSession<SessionBackend>;

#[derive(Clone)]
struct AppState {
    pool: PostgresPool,
    subject_id: SubjectId,
    device_id: Uuid,
    config: SessionConfig,
    slow_loaded: Arc<Notify>,
    slow_release: Arc<Notify>,
}

fn postgres_config(url: SecretString) -> PostgresConfig {
    PostgresConfig {
        url,
        tls_mode: PostgresTlsMode::Disable,
        min_connections: 1,
        max_connections: 1,
        connect_timeout: Duration::from_secs(5),
        acquire_timeout: Duration::from_secs(1),
        idle_timeout: Duration::from_secs(30),
        max_lifetime: Duration::from_secs(60),
        max_lifetime_jitter: Duration::from_secs(10),
        application_name: "omnius-session-flow-test".to_owned(),
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

const fn migration_config() -> MigrationConfig {
    MigrationConfig {
        run_on_startup: false,
        operation_timeout: Duration::from_secs(10),
    }
}

async fn seed(Extension(session): Extension<Session>) -> Result<StatusCode, StatusCode> {
    session
        .insert("pre_login", true)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(StatusCode::NO_CONTENT)
}

async fn login(
    State(state): State<AppState>,
    mut auth: BrowserAuthSession,
) -> Result<StatusCode, StatusCode> {
    let user = auth
        .backend
        .get_user(&state.subject_id)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .ok_or(StatusCode::UNAUTHORIZED)?;
    auth.login(&user)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let registration = SessionRegistration {
        subject_id: state.subject_id,
        device_id: state.device_id,
        created_at: OffsetDateTime::now_utc(),
        user_agent_hash: None,
        ip_prefix: None,
    };
    PostgresSessionLifecycle
        .register_after_login(&state.pool, &auth.session, &registration, &state.config)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(StatusCode::NO_CONTENT)
}

async fn active(
    State(state): State<AppState>,
    mut auth: BrowserAuthSession,
) -> Result<StatusCode, StatusCode> {
    let Some(subject_id) = auth.user.as_ref().map(SessionUser::subject_id) else {
        return Ok(StatusCode::UNAUTHORIZED);
    };
    let now = OffsetDateTime::now_utc();
    let mut connection = state
        .pool
        .acquire()
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let validation = PostgresSessionLifecycle
        .validate_and_touch_with(
            &mut connection,
            &auth.session,
            subject_id,
            &state.config,
            now,
        )
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    drop(connection);

    match validation {
        SessionValidation::Active(metadata) => {
            let Some(user) = auth.user.as_ref() else {
                return Ok(StatusCode::UNAUTHORIZED);
            };
            let principal = user.principal(metadata.created_at);
            Ok(if principal.subject_id == state.subject_id {
                StatusCode::OK
            } else {
                StatusCode::UNAUTHORIZED
            })
        }
        SessionValidation::Rejected => {
            auth.logout()
                .await
                .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
            Ok(StatusCode::UNAUTHORIZED)
        }
    }
}

async fn passive(
    State(state): State<AppState>,
    auth: BrowserAuthSession,
) -> Result<StatusCode, StatusCode> {
    state.slow_loaded.notify_one();
    state.slow_release.notified().await;
    auth.session
        .insert("in_flight_mutation", true)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(StatusCode::OK)
}

async fn rotate(
    State(state): State<AppState>,
    auth: BrowserAuthSession,
) -> Result<StatusCode, StatusCode> {
    let Some(subject_id) = auth.user.as_ref().map(SessionUser::subject_id) else {
        return Ok(StatusCode::UNAUTHORIZED);
    };
    let registration = SessionRegistration {
        subject_id,
        device_id: state.device_id,
        created_at: OffsetDateTime::now_utc(),
        user_agent_hash: None,
        ip_prefix: None,
    };
    PostgresSessionLifecycle
        .rotate_after_security_change(
            &state.pool,
            &auth.session,
            subject_id,
            &registration,
            &state.config,
            OffsetDateTime::now_utc(),
        )
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(StatusCode::NO_CONTENT)
}

async fn rotate_then_fail(
    State(state): State<AppState>,
    auth: BrowserAuthSession,
) -> Result<StatusCode, StatusCode> {
    let Some(subject_id) = auth.user.as_ref().map(SessionUser::subject_id) else {
        return Ok(StatusCode::UNAUTHORIZED);
    };
    let registration = SessionRegistration {
        subject_id,
        device_id: state.device_id,
        created_at: OffsetDateTime::now_utc(),
        user_agent_hash: None,
        ip_prefix: Some("not-an-inet"),
    };
    match PostgresSessionLifecycle
        .rotate_after_security_change(
            &state.pool,
            &auth.session,
            subject_id,
            &registration,
            &state.config,
            OffsetDateTime::now_utc(),
        )
        .await
    {
        Ok(_) => Ok(StatusCode::NO_CONTENT),
        Err(_) => Ok(StatusCode::INTERNAL_SERVER_ERROR),
    }
}

async fn logout(
    State(state): State<AppState>,
    mut auth: BrowserAuthSession,
) -> Result<StatusCode, StatusCode> {
    let Some(user) = auth.user.as_ref() else {
        return Ok(StatusCode::NO_CONTENT);
    };
    let raw_pool = state.pool.sqlx_pool();
    let mut transaction = raw_pool
        .begin()
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    PostgresSessionLifecycle
        .revoke_current_with(
            &mut transaction,
            &auth.session,
            user.subject_id(),
            OffsetDateTime::now_utc(),
        )
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    transaction
        .commit()
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    auth.logout()
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(StatusCode::NO_CONTENT)
}

fn cookie_pair(response: &Response<Body>) -> Result<String, Box<dyn Error>> {
    let value = response
        .headers()
        .get(header::SET_COOKIE)
        .ok_or("response did not set a session cookie")?
        .to_str()?;
    Ok(value
        .split(';')
        .next()
        .ok_or("set-cookie did not contain a cookie pair")?
        .to_owned())
}

fn cookie_value(cookie_pair: &str) -> Result<&str, Box<dyn Error>> {
    cookie_pair
        .split_once('=')
        .map(|(_, value)| value)
        .ok_or_else(|| "session cookie did not contain a value".into())
}

fn request(method: &str, uri: &str, cookie: Option<&str>) -> Result<Request<Body>, Box<dyn Error>> {
    let mut builder = Request::builder().method(method).uri(uri);
    if let Some(cookie) = cookie {
        builder = builder.header(header::COOKIE, cookie);
    }
    Ok(builder.body(Body::empty())?)
}

fn csrf_request(
    method: &str,
    uri: &str,
    cookie: &str,
    origin: &str,
) -> Result<Request<Body>, Box<dyn Error>> {
    Ok(Request::builder()
        .method(method)
        .uri(uri)
        .header(header::COOKIE, cookie)
        .header(header::ORIGIN, origin)
        .header("sec-fetch-site", "cross-site")
        .body(Body::empty())?)
}

async fn establish_session(app: &Router) -> Result<String, Box<dyn Error>> {
    let seeded = app.clone().oneshot(request("GET", "/seed", None)?).await?;
    let pre_login = cookie_pair(&seeded)?;
    let logged_in = app
        .clone()
        .oneshot(csrf_request("POST", "/login", &pre_login, TRUSTED_ORIGIN)?)
        .await?;
    if logged_in.status() != StatusCode::NO_CONTENT {
        return Err("session login failed".into());
    }
    cookie_pair(&logged_in)
}

#[expect(
    clippy::too_many_lines,
    reason = "one real browser flow keeps fixation, cookie, CSRF, and invalidation evidence together"
)]
#[tokio::test]
async fn login_rotates_fixated_id_and_enforces_cookie_csrf_and_invalidation()
-> Result<(), Box<dyn Error>> {
    let fixture = PostgresFixture::start().await?;
    let pool = PostgresPool::connect(
        &postgres_config(fixture.database_url().clone()),
        DeploymentEnvironment::Test,
    )
    .await?;
    MigrationRunner::new(
        pool.clone(),
        &MIGRATOR,
        SchemaVersionRange::new(FIRST_MIGRATION, omnius_migrations::CURRENT_SCHEMA_VERSION)?,
        migration_config(),
        DeploymentEnvironment::Test,
    )?
    .run()
    .await?;
    let subject_id = SubjectId::from_uuid(Uuid::now_v7())?;
    let mut connection = pool.acquire().await?;
    sqlx::query("INSERT INTO users (id, created_at) VALUES ($1, $2)")
        .bind(subject_id.as_uuid())
        .bind(OffsetDateTime::now_utc())
        .execute(&mut *connection)
        .await?;
    drop(connection);

    let config = SessionConfig::default();
    let state = AppState {
        pool: pool.clone(),
        subject_id,
        device_id: Uuid::now_v7(),
        config: config.clone(),
        slow_loaded: Arc::new(Notify::new()),
        slow_release: Arc::new(Notify::new()),
    };
    let auth_layer = AuthManagerLayerBuilder::new(
        SessionBackend::new(pool.clone()),
        session_manager_layer(&pool, &config, DeploymentEnvironment::Production)?,
    )
    .build();
    let routes = Router::new()
        .route("/seed", get(seed))
        .route("/login", post(login))
        .route("/active", get(active))
        .route("/passive", get(passive))
        .route("/rotate", post(rotate))
        .route("/rotate-failure", post(rotate_then_fail))
        .route("/logout", post(logout))
        .with_state(state.clone())
        .layer(auth_layer);
    let shell = HttpShell::new(HttpShellConfig {
        trusted_origins: vec![TRUSTED_ORIGIN.to_owned()],
        ..HttpShellConfig::default()
    })?;
    let app = shell.apply(routes)?.layer(middleware::from_fn_with_state(
        SessionRevocationGuard::new(pool.clone(), &config)?,
        guard_revoked_session,
    ));

    let seed_response = app.clone().oneshot(request("GET", "/seed", None)?).await?;
    assert_eq!(seed_response.status(), StatusCode::NO_CONTENT);
    let pre_login_cookie = cookie_pair(&seed_response)?;
    let pre_login_id = cookie_value(&pre_login_cookie)?.to_owned();
    assert_eq!(pre_login_id.len(), 22);

    let rejected = app
        .clone()
        .oneshot(csrf_request(
            "POST",
            "/login",
            &pre_login_cookie,
            "https://evil.example.test",
        )?)
        .await?;
    assert_eq!(rejected.status(), StatusCode::FORBIDDEN);

    let login_response = app
        .clone()
        .oneshot(csrf_request(
            "POST",
            "/login",
            &pre_login_cookie,
            TRUSTED_ORIGIN,
        )?)
        .await?;
    assert_eq!(login_response.status(), StatusCode::NO_CONTENT);
    let set_cookie = login_response
        .headers()
        .get(header::SET_COOKIE)
        .ok_or("login did not set a cookie")?
        .to_str()?;
    assert!(set_cookie.starts_with("__Host-omnius_session="));
    assert!(set_cookie.contains("HttpOnly"));
    assert!(set_cookie.contains("SameSite=Lax"));
    assert!(set_cookie.contains("Secure"));
    assert!(set_cookie.contains("Path=/"));
    assert!(!set_cookie.contains("Domain="));
    let authenticated_cookie = cookie_pair(&login_response)?;
    let authenticated_id = cookie_value(&authenticated_cookie)?.to_owned();
    assert_ne!(authenticated_id, pre_login_id);

    let mut connection = pool.acquire().await?;
    let old_exists: bool =
        sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM tower_sessions.session WHERE id = $1)")
            .bind(pre_login_id)
            .fetch_one(&mut *connection)
            .await?;
    let new_exists: bool =
        sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM tower_sessions.session WHERE id = $1)")
            .bind(&authenticated_id)
            .fetch_one(&mut *connection)
            .await?;
    assert!(!old_exists);
    assert!(new_exists);
    drop(connection);

    let active_response = app
        .clone()
        .oneshot(request("GET", "/active", Some(&authenticated_cookie))?)
        .await?;
    if active_response.status() != StatusCode::OK {
        let status = active_response.status();
        let body = to_bytes(active_response.into_body(), 64 * 1024).await?;
        return Err(std::io::Error::other(format!(
            "active session returned {status}: {}",
            String::from_utf8_lossy(&body)
        ))
        .into());
    }
    assert_eq!(cookie_pair(&active_response)?, authenticated_cookie);
    assert!(
        active_response
            .headers()
            .get(header::SET_COOKIE)
            .ok_or("active session did not refresh its idle cookie")?
            .to_str()?
            .contains("Max-Age=43200")
    );

    let rotation = app
        .clone()
        .oneshot(csrf_request(
            "POST",
            "/rotate",
            &authenticated_cookie,
            TRUSTED_ORIGIN,
        )?)
        .await?;
    assert_eq!(rotation.status(), StatusCode::NO_CONTENT);
    let security_cookie = cookie_pair(&rotation)?;
    let security_id = cookie_value(&security_cookie)?;
    assert_ne!(security_id, authenticated_id);
    let mut connection = pool.acquire().await?;
    let rotated_old_exists: bool =
        sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM tower_sessions.session WHERE id = $1)")
            .bind(&authenticated_id)
            .fetch_one(&mut *connection)
            .await?;
    assert!(!rotated_old_exists);
    drop(connection);
    assert_eq!(
        app.clone()
            .oneshot(request("GET", "/active", Some(&security_cookie))?)
            .await?
            .status(),
        StatusCode::OK
    );

    let mut connection = pool.acquire().await?;
    sqlx::query(
        "UPDATE users SET authentication_version = authentication_version + 1 WHERE id = $1",
    )
    .bind(subject_id.as_uuid())
    .execute(&mut *connection)
    .await?;
    drop(connection);
    let invalidated = app
        .clone()
        .oneshot(request("GET", "/active", Some(&security_cookie))?)
        .await?;
    assert_eq!(invalidated.status(), StatusCode::UNAUTHORIZED);
    let removal = invalidated
        .headers()
        .get(header::SET_COOKIE)
        .ok_or("invalidated auth hash did not clear the cookie")?
        .to_str()?;
    assert!(removal.contains("Max-Age=0"));

    let second_seed = app.clone().oneshot(request("GET", "/seed", None)?).await?;
    let second_pre_login_cookie = cookie_pair(&second_seed)?;
    let second_login = app
        .clone()
        .oneshot(csrf_request(
            "POST",
            "/login",
            &second_pre_login_cookie,
            TRUSTED_ORIGIN,
        )?)
        .await?;
    let second_cookie = cookie_pair(&second_login)?;
    let logout_response = app
        .clone()
        .oneshot(csrf_request(
            "POST",
            "/logout",
            &second_cookie,
            TRUSTED_ORIGIN,
        )?)
        .await?;
    assert_eq!(logout_response.status(), StatusCode::NO_CONTENT);
    assert!(
        logout_response
            .headers()
            .get(header::SET_COOKIE)
            .ok_or("logout did not clear the cookie")?
            .to_str()?
            .contains("Max-Age=0")
    );

    let device_cookie = establish_session(&app).await?;
    let registered_device = app
        .clone()
        .oneshot(request("GET", "/active", Some(&device_cookie))?)
        .await?;
    assert_eq!(registered_device.status(), StatusCode::OK);
    let raw_pool = pool.sqlx_pool();
    let mut transaction = raw_pool.begin().await?;
    assert_eq!(
        PostgresSessionLifecycle
            .revoke_device_with(
                &mut transaction,
                subject_id,
                state.device_id,
                OffsetDateTime::now_utc(),
            )
            .await?,
        1
    );
    transaction.commit().await?;
    let device_revoked = app
        .clone()
        .oneshot(request("GET", "/active", Some(&device_cookie))?)
        .await?;
    assert_eq!(device_revoked.status(), StatusCode::UNAUTHORIZED);

    let all_cookie = establish_session(&app).await?;
    assert_eq!(
        app.clone()
            .oneshot(request("GET", "/active", Some(&all_cookie))?)
            .await?
            .status(),
        StatusCode::OK
    );
    let mut transaction = raw_pool.begin().await?;
    assert_eq!(
        PostgresSessionLifecycle
            .revoke_all_with(&mut transaction, subject_id, OffsetDateTime::now_utc())
            .await?,
        1
    );
    transaction.commit().await?;
    assert_eq!(
        app.clone()
            .oneshot(request("GET", "/active", Some(&all_cookie))?)
            .await?
            .status(),
        StatusCode::UNAUTHORIZED
    );

    let idle_cookie = establish_session(&app).await?;
    let idle_id = cookie_value(&idle_cookie)?.to_owned();
    let mut connection = pool.acquire().await?;
    let idle_last_seen: OffsetDateTime =
        sqlx::query_scalar("SELECT last_seen_at FROM sessions WHERE session_id = $1")
            .bind(&idle_id)
            .fetch_one(&mut *connection)
            .await?;
    sqlx::query(
        "UPDATE tower_sessions.session SET expiry_date = $2 - INTERVAL '1 second' WHERE id = $1",
    )
    .bind(&idle_id)
    .bind(OffsetDateTime::now_utc())
    .execute(&mut *connection)
    .await?;
    drop(connection);
    assert_eq!(
        app.clone()
            .oneshot(request("GET", "/active", Some(&idle_cookie))?)
            .await?
            .status(),
        StatusCode::UNAUTHORIZED
    );
    let mut connection = pool.acquire().await?;
    let expired_provider: bool =
        sqlx::query_scalar("SELECT expiry_date <= $2 FROM tower_sessions.session WHERE id = $1")
            .bind(&idle_id)
            .bind(OffsetDateTime::now_utc())
            .fetch_one(&mut *connection)
            .await?;
    let untouched_last_seen: OffsetDateTime =
        sqlx::query_scalar("SELECT last_seen_at FROM sessions WHERE session_id = $1")
            .bind(&idle_id)
            .fetch_one(&mut *connection)
            .await?;
    drop(connection);
    assert!(expired_provider);
    assert_eq!(untouched_last_seen, idle_last_seen);

    let absolute_cookie = establish_session(&app).await?;
    assert_eq!(
        app.clone()
            .oneshot(request("GET", "/active", Some(&absolute_cookie))?)
            .await?
            .status(),
        StatusCode::OK
    );
    let absolute_id = cookie_value(&absolute_cookie)?;
    let mut connection = pool.acquire().await?;
    sqlx::query(
        "UPDATE sessions SET created_at = $2 - INTERVAL '2 hours', \
         last_seen_at = $2 - INTERVAL '2 hours', absolute_expires_at = $2 - INTERVAL '1 hour' \
         WHERE session_id = $1",
    )
    .bind(absolute_id)
    .bind(OffsetDateTime::now_utc())
    .execute(&mut *connection)
    .await?;
    drop(connection);
    let absolute_expired = app
        .clone()
        .oneshot(request("GET", "/active", Some(&absolute_cookie))?)
        .await?;
    assert_eq!(absolute_expired.status(), StatusCode::UNAUTHORIZED);

    let failed_rotation_cookie = establish_session(&app).await?;
    assert_eq!(
        app.clone()
            .oneshot(request("GET", "/active", Some(&failed_rotation_cookie))?)
            .await?
            .status(),
        StatusCode::OK
    );
    let failed_rotation_old_id = cookie_value(&failed_rotation_cookie)?.to_owned();
    let failed_rotation = app
        .clone()
        .oneshot(csrf_request(
            "POST",
            "/rotate-failure",
            &failed_rotation_cookie,
            TRUSTED_ORIGIN,
        )?)
        .await?;
    assert_eq!(failed_rotation.status(), StatusCode::INTERNAL_SERVER_ERROR);
    assert!(
        failed_rotation
            .headers()
            .get(header::SET_COOKIE)
            .ok_or("failed security rotation did not clear the cookie")?
            .to_str()?
            .contains("Max-Age=0")
    );
    let mut connection = pool.acquire().await?;
    let failed_rotation_old_exists: bool =
        sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM tower_sessions.session WHERE id = $1)")
            .bind(&failed_rotation_old_id)
            .fetch_one(&mut *connection)
            .await?;
    drop(connection);
    assert!(!failed_rotation_old_exists);
    assert_eq!(
        app.clone()
            .oneshot(request("GET", "/active", Some(&failed_rotation_cookie))?)
            .await?
            .status(),
        StatusCode::UNAUTHORIZED
    );

    let in_flight_cookie = establish_session(&app).await?;
    assert_eq!(
        app.clone()
            .oneshot(request("GET", "/active", Some(&in_flight_cookie))?)
            .await?
            .status(),
        StatusCode::OK
    );
    let in_flight_id = cookie_value(&in_flight_cookie)?.to_owned();
    let passive_request = request("GET", "/passive", Some(&in_flight_cookie))?;
    let passive_app = app.clone();
    let in_flight = tokio::spawn(async move { passive_app.oneshot(passive_request).await });
    state.slow_loaded.notified().await;
    let mut transaction = raw_pool.begin().await?;
    let revoked = PostgresSessionLifecycle
        .revoke_all_with(&mut transaction, subject_id, OffsetDateTime::now_utc())
        .await?;
    assert!(revoked >= 1);
    transaction.commit().await?;
    state.slow_release.notify_one();
    let guarded_response = in_flight.await??;
    assert_eq!(guarded_response.status(), StatusCode::OK);
    assert!(
        guarded_response
            .headers()
            .get(header::SET_COOKIE)
            .ok_or("response revocation guard did not clear the cookie")?
            .to_str()?
            .contains("Max-Age=0")
    );
    let mut connection = pool.acquire().await?;
    let resurrected: bool =
        sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM tower_sessions.session WHERE id = $1)")
            .bind(&in_flight_id)
            .fetch_one(&mut *connection)
            .await?;
    drop(connection);
    assert!(!resurrected);

    let mut transaction = raw_pool.begin().await?;
    let cleanup = PostgresSessionLifecycle
        .cleanup_with(
            &mut transaction,
            OffsetDateTime::now_utc() + time::Duration::days(2),
        )
        .await?;
    transaction.commit().await?;
    assert!(cleanup.metadata_rows >= 3);

    pool.close().await?;
    fixture.cleanup().await?;
    Ok(())
}

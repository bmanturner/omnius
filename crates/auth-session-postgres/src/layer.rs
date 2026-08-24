use rsk_auth_core::{SessionConfig, SessionConfigError, SessionSameSite, SessionStoreKind};
use rsk_config::DeploymentEnvironment;
use rsk_postgres::PostgresPool;
use tower_sessions::{SessionManagerLayer, cookie::SameSite, session::Expiry};
use tower_sessions_sqlx_store::PostgresStore;

/// Builds the maintained PostgreSQL session layer with explicit cookie policy.
///
/// The returned layer always uses path `/`, never sets `Domain`, saves only
/// modified records, and does not run provider migrations. Lifecycle validation
/// performs the idle-expiry slide without response-time upserts.
///
/// # Errors
///
/// Returns [`SessionConfigError`] when sessions are disabled, configuration is
/// invalid, or the idle timeout cannot be represented by `time`.
pub fn session_manager_layer(
    pool: &PostgresPool,
    config: &SessionConfig,
    deployment: DeploymentEnvironment,
) -> Result<SessionManagerLayer<PostgresStore>, SessionConfigError> {
    if !config.enabled {
        return Err(SessionConfigError::Disabled);
    }
    if config.store != SessionStoreKind::Postgres {
        return Err(SessionConfigError::WrongStore);
    }
    config.validate_for(deployment)?;
    let idle_timeout = time::Duration::try_from(config.idle_timeout)
        .map_err(|_| SessionConfigError::InvalidIdleTimeout)?;
    let store = PostgresStore::new(pool.sqlx_pool());

    Ok(SessionManagerLayer::new(store)
        .with_name(config.cookie_name.clone())
        .with_http_only(config.http_only)
        .with_same_site(match config.same_site {
            SessionSameSite::Lax => SameSite::Lax,
            SessionSameSite::Strict => SameSite::Strict,
        })
        .with_expiry(Expiry::OnInactivity(idle_timeout))
        .with_secure(config.secure)
        .with_path("/")
        .with_always_save(false))
}

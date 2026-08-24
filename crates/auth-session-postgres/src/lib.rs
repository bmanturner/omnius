//! PostgreSQL-backed browser authentication sessions.
//!
//! The capability combines the maintained `axum-login` and `tower-sessions`
//! stack with canonical principals and transaction-bound session lifecycle
//! metadata. Applications must gate authenticated principal creation on
//! [`PostgresSessionLifecycle::validate_and_touch_with`] and apply
//! [`guard_revoked_session`] outside the session manager. Together they enforce
//! idle/absolute expiry and close response-save revocation races. Public failures
//! and values never expose provider IDs.

mod backend;
mod config;
mod guard;
mod health;
mod layer;
mod lifecycle;

pub use backend::{SessionBackend, SessionBackendError, SessionCredentials, SessionUser};
pub use config::{SessionConfig, SessionConfigError, SessionSameSite, SessionStoreKind};
pub use guard::{SessionGuardError, SessionRevocationGuard, guard_revoked_session};
pub use health::session_store_health_check;
pub use layer::session_manager_layer;
pub use lifecycle::{
    PostgresSessionLifecycle, SessionCleanup, SessionMetadata, SessionRegistration,
    SessionStoreError, SessionValidation, hash_user_agent,
};

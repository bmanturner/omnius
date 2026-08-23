//! Proves the Axum login and PostgreSQL/Redis session-store compatibility family.

use std::{convert::Infallible, future::ready};

use axum_login::{AuthManagerLayerBuilder, AuthUser, AuthnBackend, UserId};
use fred::{clients::Pool, prelude::Config};
use serde::{Deserialize, Serialize};
use sqlx::postgres::PgPoolOptions;
use tower_sessions::{Expiry, SessionManagerLayer};
use tower_sessions_redis_store::RedisStore;
use tower_sessions_sqlx_store::PostgresStore;

#[derive(Clone, Debug, Deserialize, Serialize)]
struct User {
    id: i64,
    session_hash: [u8; 32],
}

impl AuthUser for User {
    type Id = i64;

    fn id(&self) -> Self::Id {
        self.id
    }

    fn session_auth_hash(&self) -> &[u8] {
        &self.session_hash
    }
}

#[derive(Clone)]
struct Backend;

impl AuthnBackend for Backend {
    type User = User;
    type Credentials = i64;
    type Error = Infallible;

    fn authenticate(
        &self,
        _credentials: Self::Credentials,
    ) -> impl Future<Output = Result<Option<Self::User>, Self::Error>> + Send {
        ready(Ok(None))
    }

    fn get_user(
        &self,
        _user_id: &UserId<Self>,
    ) -> impl Future<Output = Result<Option<Self::User>, Self::Error>> + Send {
        ready(Ok(None))
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let postgres_pool = PgPoolOptions::new()
        .max_connections(1)
        .connect_lazy("postgres://session:phase0-test-only@localhost/session")?;
    let postgres_store = PostgresStore::new(postgres_pool);
    let sessions = SessionManagerLayer::new(postgres_store)
        .with_secure(true)
        .with_expiry(Expiry::OnInactivity(time::Duration::minutes(30)));
    let _auth_layer = AuthManagerLayerBuilder::new(Backend, sessions).build();

    let redis_config = Config::from_url("rediss://localhost:6379")?;
    let redis_pool = Pool::new(redis_config, None, None, None, 1)?;
    let _redis_store = RedisStore::new(redis_pool);

    println!("session compatibility stack constructed");
    Ok(())
}

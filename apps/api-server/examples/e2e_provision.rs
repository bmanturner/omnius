//! Provisions one disposable browser identity and tenant for the local Playwright fixture.

use std::{env, error::Error, num::NonZeroUsize};

use omnius_auth_core::SubjectId;
use omnius_auth_password::{
    PasswordEngine, PasswordInput, PasswordPepper, PasswordPolicy, PasswordPolicyConfig,
    PasswordWorker, PostgresPasswordStore,
};
use omnius_config::SecretString;
use sqlx::{Connection as _, PgConnection};
use time::OffsetDateTime;
use uuid::Uuid;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let database_url = required_environment("DATABASE_URL")?;
    let pepper = SecretString::from(required_environment("OMNIUS_E2E_PASSWORD_PEPPER")?);
    let identifier = env::var("OMNIUS_E2E_LOGIN_IDENTIFIER")
        .unwrap_or_else(|_| "person@example.test".to_owned());
    let password = env::var("OMNIUS_E2E_LOGIN_PASSWORD")
        .unwrap_or_else(|_| "correct horse battery staple".to_owned());

    let subject_id = SubjectId::new();
    let tenant_id = Uuid::now_v7();
    let now = OffsetDateTime::now_utc();
    let worker = PasswordWorker::new(
        PasswordEngine::new(PasswordPolicy::new(
            PasswordPolicyConfig::default(),
            PasswordPepper::new(1, pepper)?,
            Vec::new(),
        )?)?,
        NonZeroUsize::MIN,
    );
    let credential = worker
        .hash_password(PasswordInput::new(SecretString::from(password))?)
        .await?;

    let mut connection = PgConnection::connect(&database_url).await?;
    let mut transaction = connection.begin().await?;
    sqlx::query("INSERT INTO users (id, created_at) VALUES ($1, $2)")
        .bind(subject_id.as_uuid())
        .bind(now)
        .execute(&mut *transaction)
        .await?;
    sqlx::query(
        "INSERT INTO identities (id, user_id, provider, provider_subject, created_at) \
         VALUES ($1, $2, 'email', $3, $4)",
    )
    .bind(Uuid::now_v7())
    .bind(subject_id.as_uuid())
    .bind(identifier)
    .bind(now)
    .execute(&mut *transaction)
    .await?;
    PostgresPasswordStore
        .replace_password_with(&mut transaction, subject_id, &credential, now)
        .await?;
    sqlx::query(
        "INSERT INTO organizations \
         (id, name, status, version, owner_guard_version, created_at, updated_at) \
         VALUES ($1, 'Playwright workspace', 'active', 1, 0, $2, $2)",
    )
    .bind(tenant_id)
    .bind(now)
    .execute(&mut *transaction)
    .await?;
    sqlx::query(
        "INSERT INTO memberships \
         (organization_id, user_id, role, status, grant_version, created_at, updated_at) \
         VALUES ($1, $2, 'owner', 'active', 1, $3, $3)",
    )
    .bind(tenant_id)
    .bind(subject_id.as_uuid())
    .bind(now)
    .execute(&mut *transaction)
    .await?;
    transaction.commit().await?;

    println!("subject_id={subject_id} tenant_id={tenant_id}");
    Ok(())
}

fn required_environment(name: &'static str) -> Result<String, Box<dyn Error>> {
    let value = env::var(name)?;
    if value.is_empty() {
        return Err(format!("{name} must not be empty").into());
    }
    Ok(value)
}

//! Provisions one disposable browser identity with two tenants for the local Playwright fixture.

use std::{env, error::Error, num::NonZeroUsize};

use omnius_auth_core::{SubjectId, TenantId};
use omnius_auth_password::{
    PasswordEngine, PasswordInput, PasswordPepper, PasswordPolicy, PasswordPolicyConfig,
    PasswordWorker, PostgresPasswordStore,
};
use omnius_config::SecretString;
use sqlx::{Connection as _, PgConnection};
use time::OffsetDateTime;
use uuid::Uuid;

const E2E_SUBJECT_ID: &str = "01890f2a-0000-7000-8000-000000000001";
const E2E_PRIMARY_TENANT_ID: &str = "01890f2a-0000-7000-8000-000000000002";
const E2E_SECONDARY_TENANT_ID: &str = "01890f2a-0000-7000-8000-000000000003";

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let database_url = required_environment("DATABASE_URL")?;
    let pepper = SecretString::from(required_environment("OMNIUS_E2E_PASSWORD_PEPPER")?);
    let identifier = env::var("OMNIUS_E2E_LOGIN_IDENTIFIER")
        .unwrap_or_else(|_| "person@example.test".to_owned());
    let password = env::var("OMNIUS_E2E_LOGIN_PASSWORD")
        .unwrap_or_else(|_| "correct horse battery staple".to_owned());

    let subject_id = E2E_SUBJECT_ID.parse::<SubjectId>()?;
    let primary_tenant_id = E2E_PRIMARY_TENANT_ID.parse::<TenantId>()?;
    let secondary_tenant_id = E2E_SECONDARY_TENANT_ID.parse::<TenantId>()?;
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
         VALUES \
         ($1, 'Playwright workspace', 'suspended', 1, 0, $3, $3), \
         ($2, 'Playwright secondary workspace', 'suspended', 1, 0, $3, $3)",
    )
    .bind(primary_tenant_id.as_uuid())
    .bind(secondary_tenant_id.as_uuid())
    .bind(now)
    .execute(&mut *transaction)
    .await?;
    sqlx::query(
        "INSERT INTO memberships \
         (organization_id, user_id, role, status, grant_version, created_at, updated_at) \
         VALUES \
         ($1, $3, 'owner', 'active', 1, $4, $4), \
         ($2, $3, 'owner', 'active', 1, $4, $4)",
    )
    .bind(primary_tenant_id.as_uuid())
    .bind(secondary_tenant_id.as_uuid())
    .bind(subject_id.as_uuid())
    .bind(now)
    .execute(&mut *transaction)
    .await?;
    sqlx::query(
        "UPDATE organizations SET status = 'active', updated_at = $3 \
         WHERE id IN ($1, $2)",
    )
    .bind(primary_tenant_id.as_uuid())
    .bind(secondary_tenant_id.as_uuid())
    .bind(now)
    .execute(&mut *transaction)
    .await?;
    transaction.commit().await?;

    println!(
        "subject_id={subject_id} tenant_id={primary_tenant_id} secondary_tenant_id={secondary_tenant_id}"
    );
    Ok(())
}

fn required_environment(name: &'static str) -> Result<String, Box<dyn Error>> {
    let value = env::var(name)?;
    if value.is_empty() {
        return Err(format!("{name} must not be empty").into());
    }
    Ok(value)
}

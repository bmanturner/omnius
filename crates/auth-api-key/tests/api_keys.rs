//! PostgreSQL proof for service-account and API-key authentication lifecycle behavior.

use std::{error::Error, time::Duration};

use omnius_auth_api_key::{
    ApiKeyConfig, ApiKeyCredential, ApiKeyListCursor, ApiKeyListRequest, ApiKeyStore,
    ApiKeyStoreError, ServiceAccountListRequest, ServiceAccountListScope,
};
use omnius_auth_core::{AssuranceLevel, AuthMethod, PrincipalKind, Scope, SubjectId, TenantId};
use omnius_config::{DeploymentEnvironment, ExposeSecret as _, SecretString};
use omnius_migrations::{MIGRATOR, MigrationConfig, MigrationRunner, SchemaVersionRange};
use omnius_postgres::{
    PostgresConfig, PostgresPool, PostgresTlsMode, TransactionIsolation, TransactionRetryConfig,
};
use omnius_test_support::PostgresFixture;
use sqlx::Connection as _;
use time::{Duration as TimeDuration, OffsetDateTime};

const FIRST_MIGRATION: i64 = 2_026_082_301;

struct TestDatabase {
    pool: PostgresPool,
    _fixture: PostgresFixture,
}

fn postgres_config(url: SecretString) -> PostgresConfig {
    PostgresConfig {
        url,
        tls_mode: PostgresTlsMode::Disable,
        min_connections: 1,
        max_connections: 2,
        connect_timeout: Duration::from_secs(5),
        acquire_timeout: Duration::from_secs(1),
        idle_timeout: Duration::from_secs(30),
        max_lifetime: Duration::from_secs(60),
        max_lifetime_jitter: Duration::from_secs(10),
        application_name: "omnius-auth-api-key-test".to_owned(),
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

fn api_key_config() -> ApiKeyConfig {
    ApiKeyConfig {
        enabled: true,
        pepper: SecretString::from(
            "api-key-integration-test-pepper-with-more-than-32-bytes".to_owned(),
        ),
        max_scopes: 32,
        max_key_lifetime: Duration::from_secs(3_600),
        last_used_write_interval: Duration::from_secs(60),
    }
}

async fn test_database() -> Result<TestDatabase, Box<dyn Error>> {
    let fixture = PostgresFixture::start().await?;
    let pool = PostgresPool::connect(
        &postgres_config(fixture.database_url().clone()),
        DeploymentEnvironment::Test,
    )
    .await?;
    let runner = MigrationRunner::new(
        pool.clone(),
        &MIGRATOR,
        SchemaVersionRange::new(FIRST_MIGRATION, omnius_migrations::CURRENT_SCHEMA_VERSION)?,
        migration_config(),
        DeploymentEnvironment::Test,
    )?;
    runner.run().await?;

    Ok(TestDatabase {
        _fixture: fixture,
        pool,
    })
}

async fn seed_owner(pool: &PostgresPool) -> Result<SubjectId, Box<dyn Error>> {
    let owner = SubjectId::new();
    let mut connection = pool.acquire().await?;
    sqlx::query("INSERT INTO users (id, created_at) VALUES ($1, $2)")
        .bind(owner.as_uuid())
        .bind(OffsetDateTime::now_utc())
        .execute(&mut *connection)
        .await?;
    Ok(owner)
}

async fn seed_tenant(
    pool: &PostgresPool,
    tenant: TenantId,
    owner: SubjectId,
) -> Result<(), Box<dyn Error>> {
    let now = OffsetDateTime::now_utc();
    let mut connection = pool.acquire().await?;
    let mut transaction = connection.begin().await?;
    sqlx::query(
        "INSERT INTO organizations \
         (id, name, status, version, created_at, updated_at, deleted_at) \
         VALUES ($1, 'API key test tenant', 'active', 1, $2, $2, NULL)",
    )
    .bind(tenant.as_uuid())
    .bind(now)
    .execute(&mut *transaction)
    .await?;
    sqlx::query(
        "INSERT INTO memberships \
         (organization_id, user_id, role, status, grant_version, created_at, updated_at) \
         VALUES ($1, $2, 'owner', 'active', 1, $3, $3)",
    )
    .bind(tenant.as_uuid())
    .bind(owner.as_uuid())
    .bind(now)
    .execute(&mut *transaction)
    .await?;
    transaction.commit().await?;
    Ok(())
}

async fn seed_tenant_member(
    pool: &PostgresPool,
    tenant: TenantId,
    member: SubjectId,
) -> Result<(), Box<dyn Error>> {
    let now = OffsetDateTime::now_utc();
    let mut connection = pool.acquire().await?;
    sqlx::query(
        "INSERT INTO memberships \
         (organization_id, user_id, role, status, grant_version, created_at, updated_at) \
         VALUES ($1, $2, 'member', 'active', 1, $3, $3)",
    )
    .bind(tenant.as_uuid())
    .bind(member.as_uuid())
    .bind(now)
    .execute(&mut *connection)
    .await?;
    Ok(())
}

fn wrong_secret(presentation: &str) -> Result<String, Box<dyn Error>> {
    let last_index = presentation
        .char_indices()
        .next_back()
        .map(|(index, _)| index)
        .ok_or("generated API-key presentation must not be empty")?;
    let replacement = if presentation.ends_with('A') {
        "Q"
    } else {
        "A"
    };
    let mut wrong = presentation.to_owned();
    wrong.replace_range(last_index.., replacement);
    Ok(wrong)
}

fn operation_error<T>(
    result: &Result<T, ApiKeyStoreError>,
) -> Result<ApiKeyStoreError, Box<dyn Error>> {
    match result {
        Ok(_) => Err("operation unexpectedly succeeded".into()),
        Err(error) => Ok(*error),
    }
}

#[expect(
    clippy::too_many_lines,
    reason = "one fixture proves the complete API-key lifecycle and its state transitions"
)]
#[tokio::test]
async fn api_key_lifecycle_is_hashed_scoped_rotatable_and_immediately_invalidated()
-> Result<(), Box<dyn Error>> {
    let database = test_database().await?;
    let owner = seed_owner(&database.pool).await?;
    let tenant = TenantId::new();
    seed_tenant(&database.pool, tenant, owner).await?;
    let config = api_key_config();
    let store = ApiKeyStore::new(database.pool.clone(), &config)?;

    let unavailable_tenant = store
        .create_service_account("unbound tenant automation", Some(TenantId::new()), owner)
        .await;
    assert_eq!(
        operation_error(&unavailable_tenant)?,
        ApiKeyStoreError::TenantUnavailable
    );

    let nonmember = seed_owner(&database.pool).await?;
    let cross_tenant = store
        .create_service_account("cross-tenant automation", Some(tenant), nonmember)
        .await;
    assert_eq!(
        operation_error(&cross_tenant)?,
        ApiKeyStoreError::TenantUnavailable
    );

    let account = store
        .create_service_account("deployment automation", Some(tenant), owner)
        .await?;
    assert_eq!(
        (
            account.name.as_str(),
            account.tenant_id,
            account.created_by_user_id,
            account.disabled_at,
        ),
        ("deployment automation", Some(tenant), owner, None)
    );
    assert_eq!(
        store.service_account_metadata(account.id).await?,
        Some(account.clone())
    );

    let requested_scopes = [
        Scope::new("deploy:write")?,
        Scope::new("deploy:read")?,
        Scope::new("deploy:read")?,
    ];
    let expected_scopes = vec![Scope::new("deploy:read")?, Scope::new("deploy:write")?];
    let created = store
        .issue(
            account.id,
            "primary deployment key",
            &requested_scopes,
            None,
        )
        .await?;
    let first_metadata = created.metadata().clone();
    assert_eq!(first_metadata.scopes, expected_scopes);
    assert!(first_metadata.last_used_at.is_none());

    let redacted_debug = format!("{created:?}");
    let one_time_presentation = created.expose_once();
    let presentation = one_time_presentation.expose_secret().to_owned();
    assert!(redacted_debug.contains("credential: \"[REDACTED]\""));
    assert!(!redacted_debug.contains(&presentation));

    let credential = ApiKeyCredential::parse(one_time_presentation)?;
    let expected_digest = credential.digest(&config.pepper)?;
    let mut connection = database.pool.acquire().await?;
    let (stored_prefix, stored_hash, stored_hash_length): (String, Vec<u8>, i32) = sqlx::query_as(
        "SELECT key_prefix, secret_hash, octet_length(secret_hash) \
             FROM api_keys WHERE id = $1",
    )
    .bind(first_metadata.id)
    .fetch_one(&mut *connection)
    .await?;
    drop(connection);
    assert_eq!(stored_prefix, credential.prefix());
    assert_eq!(stored_hash_length, 32);
    assert_eq!(stored_hash.as_slice(), expected_digest.as_bytes());
    assert_ne!(stored_hash.as_slice(), presentation.as_bytes());

    let principal = store.authenticate(&credential).await?;
    let after_authentication = OffsetDateTime::now_utc();
    assert_eq!(
        (
            principal.subject_id,
            principal.kind,
            principal.tenant_id,
            principal.auth_method,
            principal.assurance,
            principal.scopes.as_slice(),
        ),
        (
            account.id,
            PrincipalKind::ServiceAccount,
            Some(tenant),
            AuthMethod::ApiKey,
            AssuranceLevel::Aal1,
            expected_scopes.as_slice(),
        )
    );

    let mut connection = database.pool.acquire().await?;
    sqlx::query(
        "UPDATE organizations \
         SET status = 'suspended', version = version + 1, updated_at = $2 \
         WHERE id = $1",
    )
    .bind(tenant.as_uuid())
    .bind(OffsetDateTime::now_utc())
    .execute(&mut *connection)
    .await?;
    drop(connection);
    assert_eq!(
        operation_error(&store.authenticate(&credential).await)?,
        ApiKeyStoreError::AuthenticationFailed
    );
    assert_eq!(
        operation_error(
            &store
                .issue(account.id, "suspended tenant key", &[], None)
                .await
        )?,
        ApiKeyStoreError::TenantUnavailable
    );
    assert_eq!(
        operation_error(&store.rotate(first_metadata.id, None).await)?,
        ApiKeyStoreError::TenantUnavailable
    );
    let mut connection = database.pool.acquire().await?;
    sqlx::query(
        "UPDATE organizations \
         SET status = 'active', version = version + 1, updated_at = $2 \
         WHERE id = $1",
    )
    .bind(tenant.as_uuid())
    .bind(OffsetDateTime::now_utc())
    .execute(&mut *connection)
    .await?;
    drop(connection);
    let used_metadata = store
        .api_key_metadata(first_metadata.id)
        .await?
        .ok_or("issued API key metadata must exist")?;
    let last_used_at = used_metadata
        .last_used_at
        .ok_or("successful authentication must record last use")?;
    assert!(last_used_at >= first_metadata.created_at);
    assert!(last_used_at <= after_authentication);

    let replacement = store.rotate(first_metadata.id, None).await?;
    let replacement_metadata = replacement.metadata().clone();
    assert_eq!(
        replacement_metadata.rotated_from_id,
        Some(first_metadata.id)
    );
    assert_eq!(replacement_metadata.scopes, expected_scopes);
    let replacement_credential = ApiKeyCredential::parse(replacement.expose_once())?;

    assert!(store.authenticate(&credential).await.is_ok());
    assert!(store.authenticate(&replacement_credential).await.is_ok());

    let revoked = store.revoke(first_metadata.id).await?;
    assert!(revoked.revoked_at.is_some());
    assert_eq!(
        operation_error(&store.authenticate(&credential).await)?,
        ApiKeyStoreError::AuthenticationFailed
    );
    assert!(store.authenticate(&replacement_credential).await.is_ok());

    let disabled = store.disable_service_account(account.id).await?;
    assert!(disabled.disabled_at.is_some());
    assert_eq!(
        operation_error(&store.authenticate(&replacement_credential).await)?,
        ApiKeyStoreError::AuthenticationFailed
    );

    Ok(())
}

#[tokio::test]
async fn wrong_and_expired_secrets_are_rejected_without_reflection() -> Result<(), Box<dyn Error>> {
    let database = test_database().await?;
    let owner = seed_owner(&database.pool).await?;
    let config = api_key_config();
    let store = ApiKeyStore::new(database.pool.clone(), &config)?;
    let account = store
        .create_service_account("validation automation", None, owner)
        .await?;

    let created = store.issue(account.id, "active key", &[], None).await?;
    let presentation = created.expose_once().expose_secret().to_owned();
    let credential = ApiKeyCredential::parse(SecretString::from(presentation.clone()))?;
    let wrong_presentation = wrong_secret(&presentation)?;
    let wrong_credential = ApiKeyCredential::parse(SecretString::from(wrong_presentation.clone()))?;
    assert_eq!(wrong_credential.prefix(), credential.prefix());
    assert!(store.authenticate(&credential).await.is_ok());

    let wrong_error = operation_error(&store.authenticate(&wrong_credential).await)?;
    assert_eq!(wrong_error, ApiKeyStoreError::AuthenticationFailed);
    let rendered_error = format!("{wrong_error:?}\n{wrong_error}");
    assert_eq!(
        rendered_error,
        "AuthenticationFailed\nAPI-key authentication failed"
    );
    assert!(!rendered_error.contains(&wrong_presentation));

    let expiring = store
        .issue(
            account.id,
            "expiring key",
            &[],
            Some(OffsetDateTime::now_utc() + TimeDuration::minutes(1)),
        )
        .await?;
    let expiring_id = expiring.metadata().id;
    let expiring_credential = ApiKeyCredential::parse(expiring.expose_once())?;
    let mut connection = database.pool.acquire().await?;
    sqlx::query(
        "UPDATE api_keys SET expires_at = created_at + INTERVAL '1 microsecond' WHERE id = $1",
    )
    .bind(expiring_id)
    .execute(&mut *connection)
    .await?;
    drop(connection);

    assert_eq!(
        operation_error(&store.authenticate(&expiring_credential).await)?,
        ApiKeyStoreError::AuthenticationFailed
    );

    Ok(())
}

#[tokio::test]
async fn wrong_secret_with_public_prefix_does_not_wait_on_lifecycle_locks()
-> Result<(), Box<dyn Error>> {
    let database = test_database().await?;
    let owner = seed_owner(&database.pool).await?;
    let store = ApiKeyStore::new(database.pool.clone(), &api_key_config())?;
    let account = store
        .create_service_account("nonblocking rejection automation", None, owner)
        .await?;
    let created = store
        .issue(account.id, "nonblocking rejection key", &[], None)
        .await?;
    let key_id = created.metadata().id;
    let presentation = created.expose_once().expose_secret().to_owned();
    let wrong = ApiKeyCredential::parse(SecretString::from(wrong_secret(&presentation)?))?;

    let mut lock_connection = database.pool.acquire().await?;
    let mut lifecycle_lock = lock_connection.begin().await?;
    sqlx::query("SELECT id FROM service_accounts WHERE id = $1 FOR UPDATE")
        .bind(account.id.as_uuid())
        .fetch_one(&mut *lifecycle_lock)
        .await?;
    sqlx::query("SELECT id FROM api_keys WHERE id = $1 FOR UPDATE")
        .bind(key_id)
        .fetch_one(&mut *lifecycle_lock)
        .await?;

    let rejection = tokio::time::timeout(Duration::from_millis(200), store.authenticate(&wrong))
        .await
        .map_err(|_| "wrong secret waited on lifecycle locks")?;
    assert_eq!(
        operation_error(&rejection)?,
        ApiKeyStoreError::AuthenticationFailed
    );
    lifecycle_lock.commit().await?;

    Ok(())
}

#[tokio::test]
async fn issuance_revalidates_expiry_after_account_lock() -> Result<(), Box<dyn Error>> {
    let database = test_database().await?;
    let owner = seed_owner(&database.pool).await?;
    let store = ApiKeyStore::new(database.pool.clone(), &api_key_config())?;
    let account = store
        .create_service_account("issuance lock expiry automation", None, owner)
        .await?;

    let mut lock_connection = database.pool.acquire().await?;
    let mut account_lock = lock_connection.begin().await?;
    sqlx::query("SELECT id FROM service_accounts WHERE id = $1 FOR UPDATE")
        .bind(account.id.as_uuid())
        .fetch_one(&mut *account_lock)
        .await?;

    let issue_store = store.clone();
    let issuance = tokio::spawn(async move {
        issue_store
            .issue(
                account.id,
                "locked issuance expiry",
                &[],
                Some(OffsetDateTime::now_utc() + TimeDuration::milliseconds(300)),
            )
            .await
    });
    tokio::time::sleep(Duration::from_millis(500)).await;
    account_lock.commit().await?;
    assert_eq!(
        operation_error(&issuance.await?)?,
        ApiKeyStoreError::InvalidExpiry
    );

    Ok(())
}

#[tokio::test]
async fn expiry_crossing_while_locked_rejects_authentication_and_rotation()
-> Result<(), Box<dyn Error>> {
    let database = test_database().await?;
    let owner = seed_owner(&database.pool).await?;
    let store = ApiKeyStore::new(database.pool.clone(), &api_key_config())?;
    let account = store
        .create_service_account("lock expiry automation", None, owner)
        .await?;

    let authenticating = store
        .issue(
            account.id,
            "authentication lock expiry",
            &[],
            Some(OffsetDateTime::now_utc() + TimeDuration::milliseconds(300)),
        )
        .await?;
    let authenticating_id = authenticating.metadata().id;
    let authenticating_credential = ApiKeyCredential::parse(authenticating.expose_once())?;
    let mut authentication_connection = database.pool.acquire().await?;
    let mut authentication_lock = authentication_connection.begin().await?;
    sqlx::query("SELECT id FROM api_keys WHERE id = $1 FOR UPDATE")
        .bind(authenticating_id)
        .fetch_one(&mut *authentication_lock)
        .await?;

    let authentication_store = store.clone();
    let authentication = tokio::spawn(async move {
        authentication_store
            .authenticate(&authenticating_credential)
            .await
    });
    tokio::time::sleep(Duration::from_millis(500)).await;
    authentication_lock.commit().await?;
    assert_eq!(
        operation_error(&authentication.await?)?,
        ApiKeyStoreError::AuthenticationFailed
    );
    drop(authentication_connection);

    let rotating = store
        .issue(
            account.id,
            "rotation lock expiry",
            &[],
            Some(OffsetDateTime::now_utc() + TimeDuration::milliseconds(300)),
        )
        .await?;
    let rotating_id = rotating.metadata().id;
    let mut rotation_connection = database.pool.acquire().await?;
    let mut rotation_lock = rotation_connection.begin().await?;
    sqlx::query("SELECT id FROM api_keys WHERE id = $1 FOR UPDATE")
        .bind(rotating_id)
        .fetch_one(&mut *rotation_lock)
        .await?;

    let rotation_store = store.clone();
    let rotation = tokio::spawn(async move { rotation_store.rotate(rotating_id, None).await });
    tokio::time::sleep(Duration::from_millis(500)).await;
    rotation_lock.commit().await?;
    assert_eq!(
        operation_error(&rotation.await?)?,
        ApiKeyStoreError::ApiKeyInactive
    );

    Ok(())
}

#[test]
fn list_requests_reject_empty_unbounded_and_malformed_windows() {
    let owner = SubjectId::new();
    let account = SubjectId::new();

    assert_eq!(
        ServiceAccountListRequest::new(ServiceAccountListScope::CreatedBy(owner), 0),
        Err(ApiKeyStoreError::InvalidListLimit)
    );
    assert_eq!(
        ServiceAccountListRequest::new(ServiceAccountListScope::CreatedBy(owner), 101),
        Err(ApiKeyStoreError::InvalidListLimit)
    );
    assert!(ServiceAccountListRequest::new(ServiceAccountListScope::CreatedBy(owner), 100).is_ok());
    assert_eq!(
        ApiKeyListRequest::new(account, 0),
        Err(ApiKeyStoreError::InvalidListLimit)
    );
    assert_eq!(
        ApiKeyListRequest::new(account, 101),
        Err(ApiKeyStoreError::InvalidListLimit)
    );
    assert_eq!(
        ApiKeyListCursor::new(OffsetDateTime::now_utc(), uuid::Uuid::nil()),
        Err(ApiKeyStoreError::InvalidIdentifier)
    );
}

#[expect(
    clippy::too_many_lines,
    reason = "one fixture proves every service-account list scope and page boundary"
)]
#[tokio::test]
async fn service_account_listing_is_scoped_bounded_and_stably_paginated()
-> Result<(), Box<dyn Error>> {
    let database = test_database().await?;
    let first_owner = seed_owner(&database.pool).await?;
    let second_owner = seed_owner(&database.pool).await?;
    let tenant = TenantId::new();
    seed_tenant(&database.pool, tenant, first_owner).await?;
    seed_tenant_member(&database.pool, tenant, second_owner).await?;
    let store = ApiKeyStore::new(database.pool.clone(), &api_key_config())?;

    let first_tenant_account = store
        .create_service_account("first tenant account", Some(tenant), first_owner)
        .await?;
    let second_tenant_account = store
        .create_service_account("second tenant account", Some(tenant), first_owner)
        .await?;
    let tenantless_account = store
        .create_service_account("tenantless account", None, first_owner)
        .await?;
    let other_owner_tenant_account = store
        .create_service_account("other owner tenant account", Some(tenant), second_owner)
        .await?;
    let other_owner_tenantless_account = store
        .create_service_account("other owner tenantless account", None, second_owner)
        .await?;

    let shared_created_at = OffsetDateTime::now_utc() - TimeDuration::minutes(5);
    let account_ids = [
        first_tenant_account.id.as_uuid(),
        second_tenant_account.id.as_uuid(),
        tenantless_account.id.as_uuid(),
        other_owner_tenant_account.id.as_uuid(),
        other_owner_tenantless_account.id.as_uuid(),
    ];
    let mut connection = database.pool.acquire().await?;
    sqlx::query("UPDATE service_accounts SET created_at = $1 WHERE id = ANY($2)")
        .bind(shared_created_at)
        .bind(account_ids.as_slice())
        .execute(&mut *connection)
        .await?;
    drop(connection);
    let disabled = store
        .disable_service_account(first_tenant_account.id)
        .await?;
    assert!(disabled.disabled_at.is_some());

    let first_page = store
        .list_service_accounts(ServiceAccountListRequest::new(
            ServiceAccountListScope::CreatedBy(first_owner),
            2,
        )?)
        .await?;
    assert_eq!(first_page.items.len(), 2);
    let cursor = first_page
        .next_cursor
        .ok_or("a third owner-scoped account must produce a cursor")?;
    let second_page = store
        .list_service_accounts(
            ServiceAccountListRequest::new(ServiceAccountListScope::CreatedBy(first_owner), 2)?
                .before(cursor),
        )
        .await?;
    assert_eq!(second_page.items.len(), 1);
    assert!(second_page.next_cursor.is_none());

    let mut listed_owner_ids = first_page
        .items
        .iter()
        .chain(&second_page.items)
        .map(|item| item.id)
        .collect::<Vec<_>>();
    let mut expected_owner_ids = vec![
        first_tenant_account.id,
        second_tenant_account.id,
        tenantless_account.id,
    ];
    expected_owner_ids.sort_unstable_by(|left, right| right.as_uuid().cmp(&left.as_uuid()));
    assert_eq!(listed_owner_ids, expected_owner_ids);
    listed_owner_ids.sort_unstable();
    listed_owner_ids.dedup();
    assert_eq!(listed_owner_ids.len(), 3);
    assert!(
        first_page
            .items
            .iter()
            .chain(&second_page.items)
            .find(|item| item.id == first_tenant_account.id)
            .is_some_and(|item| item.disabled_at.is_some())
    );

    let tenant_page = store
        .list_service_accounts(ServiceAccountListRequest::new(
            ServiceAccountListScope::Tenant(tenant),
            100,
        )?)
        .await?;
    assert_eq!(tenant_page.items.len(), 3);
    assert!(
        tenant_page
            .items
            .iter()
            .all(|item| item.tenant_id == Some(tenant))
    );
    assert!(
        tenant_page
            .items
            .iter()
            .any(|item| item.created_by_user_id == second_owner)
    );

    let tenant_owner_page = store
        .list_service_accounts(ServiceAccountListRequest::new(
            ServiceAccountListScope::TenantCreatedBy {
                tenant_id: tenant,
                created_by_user_id: first_owner,
            },
            100,
        )?)
        .await?;
    assert_eq!(tenant_owner_page.items.len(), 2);
    assert!(
        tenant_owner_page.items.iter().all(|item| {
            item.tenant_id == Some(tenant) && item.created_by_user_id == first_owner
        })
    );

    let other_owner_page = store
        .list_service_accounts(ServiceAccountListRequest::new(
            ServiceAccountListScope::CreatedBy(second_owner),
            100,
        )?)
        .await?;
    assert_eq!(other_owner_page.items.len(), 2);
    assert!(
        other_owner_page
            .items
            .iter()
            .any(|item| item.id == other_owner_tenantless_account.id)
    );

    let tenantless_page = store
        .list_service_accounts(ServiceAccountListRequest::new(
            ServiceAccountListScope::TenantlessCreatedBy(first_owner),
            100,
        )?)
        .await?;
    assert_eq!(tenantless_page.items.len(), 1);
    assert_eq!(tenantless_page.items[0].id, tenantless_account.id);

    Ok(())
}

#[expect(
    clippy::too_many_lines,
    reason = "one fixture proves pagination, lifecycle visibility, parent scope, and redaction"
)]
#[tokio::test]
async fn api_key_listing_is_parent_scoped_lifecycle_complete_and_secret_free()
-> Result<(), Box<dyn Error>> {
    let database = test_database().await?;
    let owner = seed_owner(&database.pool).await?;
    let store = ApiKeyStore::new(database.pool.clone(), &api_key_config())?;
    let account = store
        .create_service_account("listed key account", None, owner)
        .await?;
    let other_account = store
        .create_service_account("other key account", None, owner)
        .await?;

    let active = store.issue(account.id, "active key", &[], None).await?;
    let active_metadata = active.metadata().clone();
    let active_presentation = active.expose_once().expose_secret().to_owned();

    let revocable = store.issue(account.id, "revoked key", &[], None).await?;
    let revocable_metadata = revocable.metadata().clone();
    let revoked_presentation = revocable.expose_once().expose_secret().to_owned();
    store.revoke(revocable_metadata.id).await?;

    let expiring = store
        .issue(
            account.id,
            "expired key",
            &[],
            Some(OffsetDateTime::now_utc() + TimeDuration::minutes(30)),
        )
        .await?;
    let expiring_metadata = expiring.metadata().clone();
    let expired_presentation = expiring.expose_once().expose_secret().to_owned();

    let replacement = store.rotate(active_metadata.id, None).await?;
    let replacement_metadata = replacement.metadata().clone();
    let replacement_presentation = replacement.expose_once().expose_secret().to_owned();

    let isolated = store
        .issue(other_account.id, "isolated key", &[], None)
        .await?;
    let isolated_metadata = isolated.metadata().clone();
    let isolated_presentation = isolated.expose_once().expose_secret().to_owned();

    let now = OffsetDateTime::now_utc();
    let shared_created_at = now - TimeDuration::hours(2);
    let expired_at = now - TimeDuration::hours(1);
    let account_key_ids = [
        active_metadata.id,
        revocable_metadata.id,
        expiring_metadata.id,
        replacement_metadata.id,
    ];
    let mut connection = database.pool.acquire().await?;
    sqlx::query("UPDATE api_keys SET created_at = $1 WHERE id = ANY($2)")
        .bind(shared_created_at)
        .bind(account_key_ids.as_slice())
        .execute(&mut *connection)
        .await?;
    sqlx::query("UPDATE api_keys SET expires_at = $1 WHERE id = $2")
        .bind(expired_at)
        .bind(expiring_metadata.id)
        .execute(&mut *connection)
        .await?;
    drop(connection);
    store.disable_service_account(account.id).await?;

    let first_page = store
        .list_api_keys(ApiKeyListRequest::new(account.id, 2)?)
        .await?;
    assert_eq!(first_page.items.len(), 2);
    let cursor = first_page
        .next_cursor
        .ok_or("a third account key must produce a cursor")?;
    let second_page = store
        .list_api_keys(ApiKeyListRequest::new(account.id, 2)?.before(cursor))
        .await?;
    assert_eq!(second_page.items.len(), 2);
    assert!(second_page.next_cursor.is_none());

    let listed = first_page
        .items
        .iter()
        .chain(&second_page.items)
        .cloned()
        .collect::<Vec<_>>();
    let mut listed_ids = listed.iter().map(|item| item.id).collect::<Vec<_>>();
    let mut expected_ids = account_key_ids.to_vec();
    expected_ids.sort_unstable_by(|left, right| right.cmp(left));
    assert_eq!(listed_ids, expected_ids);
    listed_ids.sort_unstable();
    listed_ids.dedup();
    assert_eq!(listed_ids.len(), account_key_ids.len());
    assert!(
        listed
            .iter()
            .all(|item| item.service_account_id == account.id)
    );
    assert!(
        listed
            .iter()
            .find(|item| item.id == revocable_metadata.id)
            .is_some_and(|item| item.revoked_at.is_some())
    );
    assert!(
        listed
            .iter()
            .find(|item| item.id == expiring_metadata.id)
            .is_some_and(|item| item.expires_at.is_some_and(|expiry| expiry < now))
    );
    assert!(
        listed
            .iter()
            .find(|item| item.id == replacement_metadata.id)
            .is_some_and(|item| item.rotated_from_id == Some(active_metadata.id))
    );

    let isolated_page = store
        .list_api_keys(ApiKeyListRequest::new(other_account.id, 100)?)
        .await?;
    assert_eq!(isolated_page.items.len(), 1);
    assert_eq!(isolated_page.items[0].id, isolated_metadata.id);

    let serialized = serde_json::to_string(&listed)?;
    let debugged = format!("{listed:?}");
    for forbidden_field in ["secret", "digest", "hash", "credential"] {
        assert!(!serialized.contains(forbidden_field));
        assert!(!debugged.contains(forbidden_field));
    }
    for presentation in [
        active_presentation,
        revoked_presentation,
        expired_presentation,
        replacement_presentation,
        isolated_presentation,
    ] {
        assert!(!serialized.contains(&presentation));
        assert!(!debugged.contains(&presentation));
    }

    let mut connection = database.pool.acquire().await?;
    let stored_hashes = sqlx::query_scalar::<_, Vec<u8>>(
        "SELECT secret_hash FROM api_keys WHERE service_account_id = $1",
    )
    .bind(account.id.as_uuid())
    .fetch_all(&mut *connection)
    .await?;
    for stored_hash in stored_hashes {
        let hash_debug = format!("{stored_hash:?}");
        let hash_serialized = serde_json::to_string(&stored_hash)?;
        assert!(!serialized.contains(&hash_serialized));
        assert!(!serialized.contains(&hash_debug));
        assert!(!debugged.contains(&hash_debug));
    }

    Ok(())
}

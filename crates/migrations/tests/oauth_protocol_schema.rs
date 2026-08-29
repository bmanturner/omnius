//! OAuth Authorization Server and `OpenID` Provider durable-state schema contracts.

use std::{error::Error, fs, time::Duration};

use omnius_config::{DeploymentEnvironment, SecretString};
use omnius_migrations::{MIGRATOR, MigrationConfig, MigrationRunner, SchemaVersionRange};
use omnius_postgres::{
    PostgresConfig, PostgresPool, PostgresTlsMode, TransactionIsolation, TransactionRetryConfig,
};
use omnius_test_support::{CleanDirectory, PostgresFixture};
use sqlx::{migrate::Migrator, postgres::PgQueryResult};
use uuid::Uuid;

const FIRST_MIGRATION: i64 = 2_026_082_301;
const CREATED_AT: &str = "2026-08-28 00:00:00+00";
const CLIENT_ID: &str = "client-application";
const REDIRECT_URI: &str = "https://client.example/callback";
const RESOURCE_URI: &str = "https://issuer.example";
const PKCE_CHALLENGE: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
const PUBLIC_SUBJECT: &str = "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB";

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
        application_name: "omnius-oauth-schema-test".to_owned(),
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

fn assert_database_constraint(
    result: Result<PgQueryResult, sqlx::Error>,
    expected_code: &str,
    expected_constraint: &str,
) -> Result<(), Box<dyn Error>> {
    let Err(error) = result else {
        return Err(format!("constraint {expected_constraint} accepted an invalid row").into());
    };
    let sqlx::Error::Database(database_error) = error else {
        return Err(format!("constraint {expected_constraint} returned {error}").into());
    };

    assert_eq!(database_error.code().as_deref(), Some(expected_code));
    assert_eq!(database_error.constraint(), Some(expected_constraint));
    Ok(())
}

#[expect(
    clippy::too_many_lines,
    reason = "one fixture makes the cross-table OAuth protocol invariants explicit"
)]
#[tokio::test]
async fn oauth_protocol_schema_enforces_digest_rotation_and_revocation_invariants()
-> Result<(), Box<dyn Error>> {
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
    let status = runner.run().await?;
    assert_eq!(
        status.current_version,
        Some(omnius_migrations::CURRENT_SCHEMA_VERSION)
    );
    let mut connection = pool.acquire().await?;

    let tables: Vec<String> = sqlx::query_scalar(
        "SELECT table_name FROM information_schema.tables \
         WHERE table_schema = current_schema() AND table_name LIKE 'oauth_%' \
         ORDER BY table_name",
    )
    .fetch_all(&mut *connection)
    .await?;
    assert_eq!(
        tables,
        [
            "oauth_access_token_revocations",
            "oauth_authorization_codes",
            "oauth_authorization_requests",
            "oauth_client_assertions",
            "oauth_client_post_logout_redirect_uris",
            "oauth_client_redirect_uris",
            "oauth_clients",
            "oauth_grants",
            "oauth_refresh_token_families",
            "oauth_refresh_tokens",
            "oauth_subjects",
        ]
    );

    let presentation_columns: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM information_schema.columns \
         WHERE table_schema = current_schema() AND table_name LIKE 'oauth_%' \
           AND column_name IN ('authorization_code', 'client_secret', 'request_handle', \
                               'refresh_token', 'token', 'token_presentation')",
    )
    .fetch_one(&mut *connection)
    .await?;
    assert_eq!(presentation_columns, 0);

    let foreign_key_delete_actions: Vec<String> = sqlx::query_scalar(
        "SELECT DISTINCT constraint_type.confdeltype::text \
         FROM pg_constraint AS constraint_type \
         JOIN pg_class AS relation ON relation.oid = constraint_type.conrelid \
         WHERE relation.relname LIKE 'oauth_%' AND constraint_type.contype = 'f' \
         ORDER BY constraint_type.confdeltype::text",
    )
    .fetch_all(&mut *connection)
    .await?;
    assert_eq!(foreign_key_delete_actions, ["r"]);

    let required_partial_indexes: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM pg_index AS idx \
         JOIN pg_class AS relation ON relation.oid = idx.indexrelid \
         WHERE relation.relname IN ( \
             'oauth_authorization_requests_active_expiry_idx', \
             'oauth_authorization_codes_active_expiry_idx', \
             'oauth_refresh_token_families_active_expiry_idx', \
             'oauth_refresh_tokens_active_expiry_idx') \
           AND idx.indpred IS NOT NULL",
    )
    .fetch_one(&mut *connection)
    .await?;
    assert_eq!(required_partial_indexes, 4);

    let user_id = Uuid::now_v7();
    let client_row_id = Uuid::now_v7();
    let redirect_id = Uuid::now_v7();
    let subject_id = Uuid::now_v7();
    let grant_id = Uuid::now_v7();

    sqlx::query("INSERT INTO users (id, created_at) VALUES ($1, $2::timestamptz)")
        .bind(user_id)
        .bind(CREATED_AT)
        .execute(&mut *connection)
        .await?;
    sqlx::query(
        "INSERT INTO oauth_clients \
         (id, client_id, source, status, display_name, application_type, \
          token_endpoint_auth_method, client_secret_digest, response_types, grant_types, \
          allowed_scopes, created_at, updated_at) \
         VALUES ($1, $2, 'pre_registered', 'active', 'Client application', 'web', \
                 'client_secret_basic', $3, ARRAY['code'], \
                 ARRAY['authorization_code', 'refresh_token'], \
                 ARRAY['openid', 'records:read'], \
                 TIMESTAMPTZ '2026-08-28 00:00:00+00', \
                 TIMESTAMPTZ '2026-08-28 00:00:00+00')",
    )
    .bind(client_row_id)
    .bind(CLIENT_ID)
    .bind(vec![1_u8; 32])
    .execute(&mut *connection)
    .await?;
    sqlx::query(
        "INSERT INTO oauth_client_redirect_uris (id, client_id, redirect_uri, created_at) \
         VALUES ($1, $2, $3, TIMESTAMPTZ '2026-08-28 00:00:00+00')",
    )
    .bind(redirect_id)
    .bind(client_row_id)
    .bind(REDIRECT_URI)
    .execute(&mut *connection)
    .await?;
    sqlx::query(
        "INSERT INTO oauth_client_post_logout_redirect_uris \
         (id, client_id, redirect_uri, created_at) \
         VALUES ($1, $2, 'https://client.example/logged-out', \
                 TIMESTAMPTZ '2026-08-28 00:00:00+00')",
    )
    .bind(Uuid::now_v7())
    .bind(client_row_id)
    .execute(&mut *connection)
    .await?;

    let assertion_client_id = Uuid::now_v7();
    sqlx::query(
        "INSERT INTO oauth_clients \
         (id, client_id, source, status, display_name, application_type, \
          token_endpoint_auth_method, response_types, grant_types, allowed_scopes, public_jwks, \
          created_at, updated_at) \
         VALUES ($1, 'jwt-client', 'pre_registered', 'active', 'JWT client', 'web', \
                 'private_key_jwt', ARRAY['code'], ARRAY['authorization_code'], \
                 ARRAY[]::text[], \
                 '{\"keys\":[{\"kty\":\"RSA\",\"kid\":\"client-key\",\"e\":\"AQAB\",\"n\":\"abc\"}]}'::jsonb, \
                 TIMESTAMPTZ '2026-08-28 00:00:00+00', \
                 TIMESTAMPTZ '2026-08-28 00:00:00+00')",
    )
    .bind(assertion_client_id)
    .execute(&mut *connection)
    .await?;
    sqlx::query(
        "INSERT INTO oauth_client_assertions \
         (id, client_id, jti, issued_at, expires_at) \
         VALUES ($1, $2, 'assertion-jti', TIMESTAMPTZ '2026-08-28 00:01:00+00', \
                 TIMESTAMPTZ '2026-08-28 00:06:00+00')",
    )
    .bind(Uuid::now_v7())
    .bind(assertion_client_id)
    .execute(&mut *connection)
    .await?;
    let replayed_assertion = sqlx::query(
        "INSERT INTO oauth_client_assertions \
         (id, client_id, jti, issued_at, expires_at) \
         VALUES ($1, $2, 'assertion-jti', TIMESTAMPTZ '2026-08-28 00:01:00+00', \
                 TIMESTAMPTZ '2026-08-28 00:06:00+00')",
    )
    .bind(Uuid::now_v7())
    .bind(assertion_client_id)
    .execute(&mut *connection)
    .await;
    assert_database_constraint(
        replayed_assertion,
        "23505",
        "oauth_client_assertions_client_jti_key",
    )?;
    sqlx::query(
        "INSERT INTO oauth_subjects (id, user_id, public_subject, created_at) \
         VALUES ($1, $2, $3, TIMESTAMPTZ '2026-08-28 00:01:00+00')",
    )
    .bind(subject_id)
    .bind(user_id)
    .bind(PUBLIC_SUBJECT)
    .execute(&mut *connection)
    .await?;

    let unsorted_scopes = sqlx::query(
        "INSERT INTO oauth_grants \
         (id, subject_id, client_id, resources, granted_scopes, authenticated_at, \
          assurance_level, authentication_methods, consented_at, created_at, updated_at, version) \
         VALUES ($1, $2, $3, ARRAY[$4], ARRAY['records:read', 'openid'], \
                 TIMESTAMPTZ '2026-08-28 00:01:00+00', 'aal1', ARRAY['pwd'], \
                 TIMESTAMPTZ '2026-08-28 00:02:00+00', \
                 TIMESTAMPTZ '2026-08-28 00:02:00+00', \
                 TIMESTAMPTZ '2026-08-28 00:02:00+00', 1)",
    )
    .bind(Uuid::now_v7())
    .bind(subject_id)
    .bind(client_row_id)
    .bind(RESOURCE_URI)
    .execute(&mut *connection)
    .await;
    assert_database_constraint(unsorted_scopes, "23514", "oauth_grants_scopes_canonical")?;

    sqlx::query(
        "INSERT INTO oauth_grants \
         (id, subject_id, client_id, resources, granted_scopes, authenticated_at, \
          assurance_level, authentication_methods, consented_at, created_at, updated_at, version) \
         VALUES ($1, $2, $3, ARRAY[$4], ARRAY['offline_access', 'openid', 'records:read'], \
                 TIMESTAMPTZ '2026-08-28 00:01:00+00', 'aal1', ARRAY['pwd'], \
                 TIMESTAMPTZ '2026-08-28 00:02:00+00', \
                 TIMESTAMPTZ '2026-08-28 00:02:00+00', \
                 TIMESTAMPTZ '2026-08-28 00:02:00+00', 1)",
    )
    .bind(grant_id)
    .bind(subject_id)
    .bind(client_row_id)
    .bind(RESOURCE_URI)
    .execute(&mut *connection)
    .await?;

    let invalid_request_digest = sqlx::query(
        "INSERT INTO oauth_authorization_requests \
         (id, request_handle_digest, client_id, redirect_uri, response_type, response_mode, \
          requested_scopes, resource_uris, pkce_code_challenge, prompt_values, expected_issuer, \
          interaction_resource_name, interaction_resource_description, \
          interaction_minimum_assurance, interaction_scope_descriptions, \
          interaction_scope_newly_requested, interaction_requirement, status, created_at, expires_at) \
         VALUES ($1, $2, $3, $4, 'code', 'query', ARRAY['openid'], ARRAY[$5], $6, \
                 ARRAY[]::text[], $5, 'Root API', 'Root API resource', 'aal1', \
                 ARRAY['Identify your account'], ARRAY[true], 'consent', 'pending', \
                 TIMESTAMPTZ '2026-08-28 00:03:00+00', \
                 TIMESTAMPTZ '2026-08-28 00:13:00+00')",
    )
    .bind(Uuid::now_v7())
    .bind(vec![2_u8; 31])
    .bind(client_row_id)
    .bind(REDIRECT_URI)
    .bind(RESOURCE_URI)
    .bind(PKCE_CHALLENGE)
    .execute(&mut *connection)
    .await;
    assert_database_constraint(
        invalid_request_digest,
        "23514",
        "oauth_authorization_requests_digest_length",
    )?;

    let mismatched_interaction_scopes = sqlx::query(
        "INSERT INTO oauth_authorization_requests \
         (id, request_handle_digest, client_id, redirect_uri, response_type, response_mode, \
          requested_scopes, resource_uris, pkce_code_challenge, prompt_values, expected_issuer, \
          interaction_resource_name, interaction_resource_description, \
          interaction_minimum_assurance, interaction_scope_descriptions, \
          interaction_scope_newly_requested, interaction_requirement, status, created_at, expires_at) \
         VALUES ($1, $2, $3, $4, 'code', 'query', ARRAY['openid'], ARRAY[$5], $6, \
                 ARRAY[]::text[], $5, 'Root API', 'Root API resource', 'aal1', \
                 ARRAY['Identify your account'], ARRAY[false, true], 'login', 'pending', \
                 TIMESTAMPTZ '2026-08-28 00:03:00+00', \
                 TIMESTAMPTZ '2026-08-28 00:13:00+00')",
    )
    .bind(Uuid::now_v7())
    .bind(vec![12_u8; 32])
    .bind(client_row_id)
    .bind(REDIRECT_URI)
    .bind(RESOURCE_URI)
    .bind(PKCE_CHALLENGE)
    .execute(&mut *connection)
    .await;
    assert_database_constraint(
        mismatched_interaction_scopes,
        "23514",
        "oauth_authorization_requests_interaction_scopes_valid",
    )?;

    let unregistered_redirect = sqlx::query(
        "INSERT INTO oauth_authorization_requests \
         (id, request_handle_digest, client_id, redirect_uri, response_type, response_mode, \
          requested_scopes, resource_uris, pkce_code_challenge, prompt_values, expected_issuer, \
          interaction_resource_name, interaction_resource_description, \
          interaction_minimum_assurance, interaction_scope_descriptions, \
          interaction_scope_newly_requested, interaction_requirement, status, created_at, expires_at) \
         VALUES ($1, $2, $3, 'https://client.example/unregistered', 'code', 'query', \
                 ARRAY['openid'], ARRAY[$4], $5, ARRAY[]::text[], $4, \
                 'Root API', 'Root API resource', 'aal1', ARRAY['Identify your account'], \
                 ARRAY[true], 'consent', 'pending', \
                 TIMESTAMPTZ '2026-08-28 00:03:00+00', \
                 TIMESTAMPTZ '2026-08-28 00:13:00+00')",
    )
    .bind(Uuid::now_v7())
    .bind(vec![3_u8; 32])
    .bind(client_row_id)
    .bind(RESOURCE_URI)
    .bind(PKCE_CHALLENGE)
    .execute(&mut *connection)
    .await;
    assert_database_constraint(
        unregistered_redirect,
        "23503",
        "oauth_authorization_requests_registered_redirect_fkey",
    )?;

    let authorization_request_id = Uuid::now_v7();
    sqlx::query(
        "INSERT INTO oauth_authorization_requests \
         (id, request_handle_digest, client_id, redirect_uri, response_type, response_mode, \
          requested_scopes, resource_uris, pkce_code_challenge, nonce, prompt_values, \
          expected_issuer, interaction_resource_name, interaction_resource_description, \
          interaction_minimum_assurance, interaction_scope_descriptions, \
          interaction_scope_newly_requested, interaction_requirement, status, created_at, expires_at) \
         VALUES ($1, $2, $3, $4, 'code', 'query', \
                 ARRAY['offline_access', 'openid', 'records:read'], ARRAY[$5], $6, \
                 'nonce-1', ARRAY['consent'], $5, 'Root API', 'Root API resource', 'aal2', \
                 ARRAY['Keep access', 'Identify your account', 'Read records'], \
                 ARRAY[false, false, true], 'consent', 'pending', \
                 TIMESTAMPTZ '2026-08-28 00:03:00+00', \
                 TIMESTAMPTZ '2026-08-28 00:13:00+00')",
    )
    .bind(authorization_request_id)
    .bind(vec![4_u8; 32])
    .bind(client_row_id)
    .bind(REDIRECT_URI)
    .bind(RESOURCE_URI)
    .bind(PKCE_CHALLENGE)
    .execute(&mut *connection)
    .await?;
    sqlx::query(
        "UPDATE oauth_authorization_requests \
         SET status = 'approved', completed_at = TIMESTAMPTZ '2026-08-28 00:03:30+00' \
         WHERE id = $1",
    )
    .bind(authorization_request_id)
    .execute(&mut *connection)
    .await?;

    let code_id = Uuid::now_v7();
    sqlx::query(
        "INSERT INTO oauth_authorization_codes \
         (id, code_digest, grant_id, client_id, redirect_uri, resource_uris, granted_scopes, \
          pkce_code_challenge, nonce, issued_at, expires_at) \
         VALUES ($1, $2, $3, $4, $5, ARRAY[$6], ARRAY['offline_access', 'openid', 'records:read'], $7, \
                 'nonce-1', TIMESTAMPTZ '2026-08-28 00:04:00+00', \
                 TIMESTAMPTZ '2026-08-28 00:06:00+00')",
    )
    .bind(code_id)
    .bind(vec![5_u8; 32])
    .bind(grant_id)
    .bind(client_row_id)
    .bind(REDIRECT_URI)
    .bind(RESOURCE_URI)
    .bind(PKCE_CHALLENGE)
    .execute(&mut *connection)
    .await?;

    let consumed_without_outcome = sqlx::query(
        "UPDATE oauth_authorization_codes SET consumed_at = \
         TIMESTAMPTZ '2026-08-28 00:05:00+00' WHERE id = $1",
    )
    .bind(code_id)
    .execute(&mut *connection)
    .await;
    assert_database_constraint(
        consumed_without_outcome,
        "23514",
        "oauth_authorization_codes_one_use_state",
    )?;
    sqlx::query(
        "UPDATE oauth_authorization_codes SET consumed_at = \
         TIMESTAMPTZ '2026-08-28 00:05:00+00', exchange_outcome = 'rejected' WHERE id = $1",
    )
    .bind(code_id)
    .execute(&mut *connection)
    .await?;

    let family_id = Uuid::now_v7();
    let first_token_id = Uuid::now_v7();
    let second_token_id = Uuid::now_v7();
    sqlx::query(
        "INSERT INTO oauth_refresh_token_families \
         (id, grant_id, client_id, resource_uri, granted_scopes, created_at, expires_at, version) \
         VALUES ($1, $2, $3, $4, ARRAY['openid', 'records:read'], \
                 TIMESTAMPTZ '2026-08-28 00:04:00+00', \
                 TIMESTAMPTZ '2026-09-27 00:04:00+00', 1)",
    )
    .bind(family_id)
    .bind(grant_id)
    .bind(client_row_id)
    .bind(RESOURCE_URI)
    .execute(&mut *connection)
    .await?;
    for (id, digest_byte, sequence, issued_at) in [
        (first_token_id, 6_u8, 0_i64, "2026-08-28 00:04:00+00"),
        (second_token_id, 7_u8, 1_i64, "2026-08-28 00:05:00+00"),
    ] {
        sqlx::query(
            "INSERT INTO oauth_refresh_tokens \
             (id, family_id, grant_id, token_digest, rotation_sequence, issued_at, expires_at) \
             VALUES ($1, $2, $3, $4, $5, $6::timestamptz, \
                     TIMESTAMPTZ '2026-09-27 00:04:00+00')",
        )
        .bind(id)
        .bind(family_id)
        .bind(grant_id)
        .bind(vec![digest_byte; 32])
        .bind(sequence)
        .bind(issued_at)
        .execute(&mut *connection)
        .await?;
    }

    let rotation_without_replacement = sqlx::query(
        "UPDATE oauth_refresh_tokens SET consumed_at = \
         TIMESTAMPTZ '2026-08-28 00:06:00+00' WHERE id = $1",
    )
    .bind(first_token_id)
    .execute(&mut *connection)
    .await;
    assert_database_constraint(
        rotation_without_replacement,
        "23514",
        "oauth_refresh_tokens_rotation_state",
    )?;
    sqlx::query(
        "UPDATE oauth_refresh_tokens SET consumed_at = \
         TIMESTAMPTZ '2026-08-28 00:06:00+00', replaced_by_id = $2 WHERE id = $1",
    )
    .bind(first_token_id)
    .bind(second_token_id)
    .execute(&mut *connection)
    .await?;
    sqlx::query(
        "UPDATE oauth_refresh_tokens SET reuse_detected_at = \
         TIMESTAMPTZ '2026-08-28 00:07:00+00' WHERE id = $1",
    )
    .bind(first_token_id)
    .execute(&mut *connection)
    .await?;

    let reuse_without_family_revocation = sqlx::query(
        "UPDATE oauth_refresh_token_families SET reuse_detected_at = \
         TIMESTAMPTZ '2026-08-28 00:07:00+00' WHERE id = $1",
    )
    .bind(family_id)
    .execute(&mut *connection)
    .await;
    assert_database_constraint(
        reuse_without_family_revocation,
        "23514",
        "oauth_refresh_token_families_revocation_state",
    )?;
    sqlx::query(
        "UPDATE oauth_refresh_token_families \
         SET revoked_at = TIMESTAMPTZ '2026-08-28 00:07:00+00', \
             revocation_reason = 'refresh_reuse', \
             reuse_detected_at = TIMESTAMPTZ '2026-08-28 00:07:00+00', version = 2 \
         WHERE id = $1",
    )
    .bind(family_id)
    .execute(&mut *connection)
    .await?;
    sqlx::query(
        "UPDATE oauth_grants \
         SET revoked_at = TIMESTAMPTZ '2026-08-28 00:07:00+00', \
             updated_at = TIMESTAMPTZ '2026-08-28 00:07:00+00', version = 2 \
         WHERE id = $1",
    )
    .bind(grant_id)
    .execute(&mut *connection)
    .await?;

    let expired_access_revocation = sqlx::query(
        "INSERT INTO oauth_access_token_revocations \
         (jti, grant_id, client_id, issued_at, expires_at, revoked_at, reason) \
         VALUES ($1, $2, $3, TIMESTAMPTZ '2026-08-28 00:04:00+00', \
                 TIMESTAMPTZ '2026-08-28 00:06:00+00', \
                 TIMESTAMPTZ '2026-08-28 00:07:00+00', 'token_revoked')",
    )
    .bind(Uuid::now_v7())
    .bind(grant_id)
    .bind(client_row_id)
    .execute(&mut *connection)
    .await;
    assert_database_constraint(
        expired_access_revocation,
        "23514",
        "oauth_access_token_revocations_timeline_valid",
    )?;

    sqlx::query(
        "INSERT INTO oauth_access_token_revocations \
         (jti, grant_id, client_id, issued_at, expires_at, revoked_at, reason) \
         VALUES ($1, $2, $3, TIMESTAMPTZ '2026-08-28 00:04:00+00', \
                 TIMESTAMPTZ '2026-08-28 00:14:00+00', \
                 TIMESTAMPTZ '2026-08-28 00:07:00+00', 'token_revoked')",
    )
    .bind(Uuid::now_v7())
    .bind(grant_id)
    .bind(client_row_id)
    .execute(&mut *connection)
    .await?;

    let stored_digest_lengths: Vec<i32> = sqlx::query_scalar(
        "SELECT octet_length(digest) FROM ( \
             SELECT request_handle_digest AS digest FROM oauth_authorization_requests \
             UNION ALL SELECT code_digest FROM oauth_authorization_codes \
             UNION ALL SELECT token_digest FROM oauth_refresh_tokens \
         ) AS durable_digests ORDER BY octet_length(digest)",
    )
    .fetch_all(&mut *connection)
    .await?;
    assert_eq!(stored_digest_lengths, [32, 32, 32, 32]);

    drop(connection);
    pool.close().await?;
    fixture.cleanup().await?;
    Ok(())
}

#[tokio::test]
async fn oauth_protocol_migration_preserves_existing_users() -> Result<(), Box<dyn Error>> {
    let fixture = PostgresFixture::start().await?;
    let pool = PostgresPool::connect(
        &postgres_config(fixture.database_url().clone()),
        DeploymentEnvironment::Test,
    )
    .await?;
    let previous_source = CleanDirectory::new("oauth-protocol-previous-migrations")?;
    for entry in fs::read_dir(concat!(env!("CARGO_MANIFEST_DIR"), "/../../migrations"))? {
        let entry = entry?;
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if name.ends_with(".sql") && name.as_ref() < "2026082802_" {
            fs::copy(entry.path(), previous_source.path().join(name.as_ref()))?;
        }
    }
    let previous_migrator = Migrator::new(previous_source.path()).await?;
    let previous_runner = MigrationRunner::new(
        pool.clone(),
        &previous_migrator,
        SchemaVersionRange::new(FIRST_MIGRATION, 2_026_082_801)?,
        migration_config(),
        DeploymentEnvironment::Test,
    )?;
    previous_runner.run().await?;

    let user_id = Uuid::now_v7();
    let mut connection = pool.acquire().await?;
    sqlx::query(
        "INSERT INTO users (id, created_at, status) \
         VALUES ($1, TIMESTAMPTZ '2026-08-27 00:00:00+00', 'active')",
    )
    .bind(user_id)
    .execute(&mut *connection)
    .await?;
    drop(connection);

    let current_runner = MigrationRunner::new(
        pool.clone(),
        &MIGRATOR,
        SchemaVersionRange::new(FIRST_MIGRATION, omnius_migrations::CURRENT_SCHEMA_VERSION)?,
        migration_config(),
        DeploymentEnvironment::Test,
    )?;
    current_runner.run().await?;
    let mut connection = pool.acquire().await?;
    let preserved: (String, String) =
        sqlx::query_as("SELECT status, created_at::text FROM users WHERE id = $1")
            .bind(user_id)
            .fetch_one(&mut *connection)
            .await?;
    assert_eq!(preserved.0, "active");
    assert!(preserved.1.starts_with("2026-08-27 00:00:00"));

    drop(connection);
    pool.close().await?;
    fixture.cleanup().await?;
    Ok(())
}

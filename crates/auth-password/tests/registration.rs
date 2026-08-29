//! End-to-end local registration, invitation, activation, and account-state contract.

use std::{error::Error, num::NonZeroUsize, time::Duration};

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use omnius_auth_password::{
    InvitationConsumption, InvitationIssueRequest, InvitationIssuer, InvitationListRequest,
    InvitationMutation, InvitationToken, InvitationTokenGenerator as _, InvitationTokenPepper,
    OsInvitationTokenGenerator, OsTokenGenerator, PasswordEngine, PasswordInput, PasswordPolicy,
    PasswordVerification, PasswordWorker, PostgresPasswordStore, RegistrationMode,
    RegistrationPolicy, RegistrationPolicyConfig, RegistrationRequest, TokenConsumption,
    TokenPurpose, UserStatus, VerificationToken,
};
use omnius_config::{DeploymentEnvironment, SecretString};
use omnius_migrations::{MIGRATOR, MigrationConfig, MigrationRunner, SchemaVersionRange};
use omnius_postgres::{
    PostgresConfig, PostgresPool, PostgresTlsMode, TransactionIsolation, TransactionRetryConfig,
};
use omnius_test_support::PostgresFixture;
use sqlx::Connection as _;
use time::OffsetDateTime;
use url::Url;

const FIRST_MIGRATION: i64 = 2_026_082_301;
const NOW_UNIX: i64 = 1_787_529_600;

fn postgres_config(url: SecretString) -> PostgresConfig {
    PostgresConfig {
        url,
        tls_mode: PostgresTlsMode::Disable,
        min_connections: 1,
        max_connections: 4,
        connect_timeout: Duration::from_secs(5),
        acquire_timeout: Duration::from_secs(2),
        idle_timeout: Duration::from_secs(30),
        max_lifetime: Duration::from_secs(60),
        max_lifetime_jitter: Duration::from_secs(10),
        application_name: "omnius-auth-password-registration-test".to_owned(),
        initialization_sql: Vec::new(),
        statement_timeout: Duration::from_secs(5),
        lock_timeout: Duration::from_secs(2),
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

fn policy(mode: RegistrationMode) -> Result<RegistrationPolicy, Box<dyn Error>> {
    Ok(RegistrationPolicyConfig {
        mode: Some(mode),
        local_identity_provider: "email".to_owned(),
        invitation_ttl: Duration::from_secs(86_400 * 7),
        public_app_url: Some(Url::parse("https://accounts.example.test/app")?),
    }
    .validate_for(
        DeploymentEnvironment::Test,
        &PasswordPolicy::default_unpeppered()?,
    )?)
}

fn password(value: &str) -> Result<PasswordInput, Box<dyn Error>> {
    Ok(PasswordInput::new(SecretString::from(value.to_owned()))?)
}

async fn complete_verification(
    pool: PostgresPool,
    token: VerificationToken,
    now: OffsetDateTime,
) -> Result<TokenConsumption, omnius_auth_password::PasswordStoreError> {
    let mut connection = pool
        .acquire()
        .await
        .map_err(|_| omnius_auth_password::PasswordStoreError::Unavailable)?;
    let mut transaction = connection
        .begin()
        .await
        .map_err(|_| omnius_auth_password::PasswordStoreError::Unavailable)?;
    let result = PostgresPasswordStore
        .complete_email_verification_with(&mut transaction, &token, "email", now)
        .await?;
    transaction
        .commit()
        .await
        .map_err(|_| omnius_auth_password::PasswordStoreError::Unavailable)?;
    Ok(result)
}

#[test]
fn registration_config_is_strict_and_links_keep_secrets_in_fragments() -> Result<(), Box<dyn Error>>
{
    let password_policy = PasswordPolicy::default_unpeppered()?;
    let omitted = RegistrationPolicyConfig::default();
    assert!(
        omitted
            .validate_for(DeploymentEnvironment::Production, &password_policy)
            .is_err()
    );

    let insecure = RegistrationPolicyConfig {
        mode: Some(RegistrationMode::Disabled),
        public_app_url: Some(Url::parse("http://accounts.example.test/app")?),
        ..RegistrationPolicyConfig::default()
    };
    assert!(
        insecure
            .validate_for(DeploymentEnvironment::Production, &password_policy)
            .is_err()
    );

    let policy = policy(RegistrationMode::SelfService)?;
    let verification =
        VerificationToken::parse(SecretString::from(URL_SAFE_NO_PAD.encode([8; 32])))?;
    let link = policy.email_verification_link(&verification)?;
    let parsed = Url::parse(link.expose_for_delivery())?;
    assert_eq!(parsed.path(), "/app/verify-email");
    assert!(parsed.query().is_none());
    let expected_fragment = format!("token={}", verification.expose_for_delivery());
    assert_eq!(parsed.fragment(), Some(expected_fragment.as_str()));
    assert_eq!(format!("{link:?}"), "SecretAccountLink([REDACTED])");

    let defaulted = omitted.validate_for(DeploymentEnvironment::Development, &password_policy)?;
    assert_eq!(defaulted.mode(), RegistrationMode::Disabled);
    assert_eq!(defaulted.invitation_ttl(), Duration::from_secs(86_400 * 7));
    assert_eq!(
        defaulted.verification_ttl(),
        password_policy.config().verification_ttl
    );
    Ok(())
}

#[expect(
    clippy::too_many_lines,
    reason = "one disposable database proves the cross-table registration and invitation invariants"
)]
#[tokio::test]
async fn registration_invitation_verification_and_status_are_atomic_and_single_use()
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

    let store = PostgresPasswordStore;
    let token_generator = OsTokenGenerator;
    let invitation_generator = OsInvitationTokenGenerator;
    let pepper = InvitationTokenPepper::parse(SecretString::from(URL_SAFE_NO_PAD.encode([7; 32])))?;
    let now = OffsetDateTime::from_unix_timestamp(NOW_UNIX)?;
    let engine = PasswordEngine::new(PasswordPolicy::default_unpeppered()?)?;
    let worker = PasswordWorker::new(
        engine,
        NonZeroUsize::new(2).ok_or("password worker concurrency must be nonzero")?,
    );
    let credential = worker
        .hash_password(password("registration correct horse battery staple")?)
        .await?;
    let mut connection = pool.acquire().await?;

    let mut transaction = connection.begin().await?;
    let disabled = store
        .register_with(
            &mut transaction,
            &policy(RegistrationMode::Disabled)?,
            RegistrationRequest {
                canonical_email: "disabled@example.test",
                credential: &credential,
                invitation: None,
                now,
            },
            &pepper,
            &token_generator,
        )
        .await?;
    transaction.commit().await?;
    assert!(disabled.accepted());
    assert!(disabled.into_post_commit_dispatch().is_none());
    let user_count: i64 = sqlx::query_scalar("SELECT count(*) FROM users")
        .fetch_one(&mut *connection)
        .await?;
    assert_eq!(user_count, 0);

    let stray_invitation = invitation_generator.generate(&pepper)?.token;
    let mut transaction = connection.begin().await?;
    let rejected_self_service_invite = store
        .register_with(
            &mut transaction,
            &policy(RegistrationMode::SelfService)?,
            RegistrationRequest {
                canonical_email: "self@example.test",
                credential: &credential,
                invitation: Some(&stray_invitation),
                now,
            },
            &pepper,
            &token_generator,
        )
        .await?;
    transaction.commit().await?;
    assert!(
        rejected_self_service_invite
            .into_post_commit_dispatch()
            .is_none()
    );

    let mut transaction = connection.begin().await?;
    let registered = store
        .register_with(
            &mut transaction,
            &policy(RegistrationMode::SelfService)?,
            RegistrationRequest {
                canonical_email: "self@example.test",
                credential: &credential,
                invitation: None,
                now,
            },
            &pepper,
            &token_generator,
        )
        .await?;
    transaction.commit().await?;
    let verification = registered
        .into_post_commit_dispatch()
        .ok_or("self-service registration did not dispatch verification")?;
    assert_eq!(
        store
            .load_user_status_with(&mut connection, verification.subject_id)
            .await?,
        Some(UserStatus::PendingVerification)
    );
    assert!(
        store
            .load_active_user_with(&mut connection, verification.subject_id)
            .await?
            .is_none()
    );
    assert!(matches!(
        store
            .verify_password_with(
                &mut connection,
                verification.subject_id,
                password("registration correct horse battery staple")?,
                &worker,
                now,
            )
            .await?,
        PasswordVerification::Rejected
    ));

    let raw_verification = verification.token.expose_for_delivery().to_owned();
    let persisted_verification: Vec<u8> =
        sqlx::query_scalar("SELECT token_hash FROM verification_tokens WHERE user_id = $1")
            .bind(verification.subject_id.as_uuid())
            .fetch_one(&mut *connection)
            .await?;
    assert_ne!(persisted_verification, raw_verification.as_bytes());

    let token_one = VerificationToken::parse(SecretString::from(raw_verification.clone()))?;
    let token_two = VerificationToken::parse(SecretString::from(raw_verification))?;
    drop(connection);
    let (first, second) = tokio::join!(
        complete_verification(pool.clone(), token_one, now + time::Duration::minutes(1)),
        complete_verification(pool.clone(), token_two, now + time::Duration::minutes(1)),
    );
    let results = [first?, second?];
    assert_eq!(
        results
            .iter()
            .filter(|result| matches!(result, TokenConsumption::Consumed(_)))
            .count(),
        1
    );
    assert_eq!(
        results
            .iter()
            .filter(|result| **result == TokenConsumption::Rejected)
            .count(),
        1
    );
    let mut connection = pool.acquire().await?;
    assert!(
        store
            .load_active_user_with(&mut connection, verification.subject_id)
            .await?
            .is_some()
    );

    let users_before_duplicate: i64 = sqlx::query_scalar("SELECT count(*) FROM users")
        .fetch_one(&mut *connection)
        .await?;
    let mut transaction = connection.begin().await?;
    let duplicate = store
        .register_with(
            &mut transaction,
            &policy(RegistrationMode::SelfService)?,
            RegistrationRequest {
                canonical_email: "self@example.test",
                credential: &credential,
                invitation: None,
                now,
            },
            &pepper,
            &token_generator,
        )
        .await?;
    transaction.commit().await?;
    assert!(duplicate.into_post_commit_dispatch().is_none());
    let users_after_duplicate: i64 = sqlx::query_scalar("SELECT count(*) FROM users")
        .fetch_one(&mut *connection)
        .await?;
    assert_eq!(users_before_duplicate, users_after_duplicate);

    let invite_policy = policy(RegistrationMode::InviteOnly)?;
    let mut transaction = connection.begin().await?;
    let invitation = store
        .issue_invitation_with(
            &mut transaction,
            InvitationIssueRequest {
                identity_provider: invite_policy.local_identity_provider(),
                canonical_email: "invited@example.test",
                issuer: InvitationIssuer::System,
                now,
                ttl: invite_policy.invitation_ttl(),
            },
            &pepper,
            &invitation_generator,
        )
        .await?;
    transaction.commit().await?;
    let raw_invitation = invitation.token.expose_for_delivery().to_owned();
    let persisted_invitation: Vec<u8> =
        sqlx::query_scalar("SELECT token_digest FROM registration_invitations WHERE id = $1")
            .bind(invitation.metadata.id)
            .fetch_one(&mut *connection)
            .await?;
    assert_ne!(persisted_invitation, raw_invitation.as_bytes());

    let parsed_invitation = InvitationToken::parse(SecretString::from(raw_invitation.clone()))?;
    let mut transaction = connection.begin().await?;
    let mismatched = store
        .register_with(
            &mut transaction,
            &invite_policy,
            RegistrationRequest {
                canonical_email: "other@example.test",
                credential: &credential,
                invitation: Some(&parsed_invitation),
                now,
            },
            &pepper,
            &token_generator,
        )
        .await?;
    transaction.commit().await?;
    assert!(mismatched.into_post_commit_dispatch().is_none());

    let parsed_invitation = InvitationToken::parse(SecretString::from(raw_invitation.clone()))?;
    let mut transaction = connection.begin().await?;
    let invited_registration = store
        .register_with(
            &mut transaction,
            &invite_policy,
            RegistrationRequest {
                canonical_email: "invited@example.test",
                credential: &credential,
                invitation: Some(&parsed_invitation),
                now,
            },
            &pepper,
            &token_generator,
        )
        .await?;
    transaction.commit().await?;
    assert!(invited_registration.into_post_commit_dispatch().is_some());
    let consumed_at: Option<OffsetDateTime> =
        sqlx::query_scalar("SELECT consumed_at FROM registration_invitations WHERE id = $1")
            .bind(invitation.metadata.id)
            .fetch_one(&mut *connection)
            .await?;
    assert_eq!(consumed_at, Some(now));

    let replay = InvitationToken::parse(SecretString::from(raw_invitation))?;
    let mut transaction = connection.begin().await?;
    let replayed = store
        .register_with(
            &mut transaction,
            &invite_policy,
            RegistrationRequest {
                canonical_email: "invited@example.test",
                credential: &credential,
                invitation: Some(&replay),
                now,
            },
            &pepper,
            &token_generator,
        )
        .await?;
    transaction.commit().await?;
    assert!(replayed.into_post_commit_dispatch().is_none());

    let mut transaction = connection.begin().await?;
    let expired_invitation = store
        .issue_invitation_with(
            &mut transaction,
            InvitationIssueRequest {
                identity_provider: "email",
                canonical_email: "expired@example.test",
                issuer: InvitationIssuer::System,
                now,
                ttl: Duration::from_hours(1),
            },
            &pepper,
            &invitation_generator,
        )
        .await?;
    transaction.commit().await?;
    let expired_token = InvitationToken::parse(SecretString::from(
        expired_invitation.token.expose_for_delivery().to_owned(),
    ))?;
    let mut transaction = connection.begin().await?;
    let expired_registration = store
        .register_with(
            &mut transaction,
            &invite_policy,
            RegistrationRequest {
                canonical_email: "expired@example.test",
                credential: &credential,
                invitation: Some(&expired_token),
                now: now + time::Duration::hours(1),
            },
            &pepper,
            &token_generator,
        )
        .await?;
    transaction.commit().await?;
    assert!(expired_registration.into_post_commit_dispatch().is_none());
    let mut transaction = connection.begin().await?;
    assert_eq!(
        store
            .cleanup_expired_invitations_with(&mut transaction, now + time::Duration::hours(1), 10,)
            .await?,
        1
    );
    transaction.commit().await?;

    let mut transaction = connection.begin().await?;
    let consumable = store
        .issue_invitation_with(
            &mut transaction,
            InvitationIssueRequest {
                identity_provider: "email",
                canonical_email: "consume@example.test",
                issuer: InvitationIssuer::System,
                now,
                ttl: Duration::from_hours(2),
            },
            &pepper,
            &invitation_generator,
        )
        .await?;
    transaction.commit().await?;
    let consumable_token = InvitationToken::parse(SecretString::from(
        consumable.token.expose_for_delivery().to_owned(),
    ))?;
    assert_eq!(
        store
            .consume_invitation_with(
                &mut connection,
                &consumable_token,
                &pepper,
                "email",
                "wrong@example.test",
                now,
            )
            .await?,
        InvitationConsumption::Rejected
    );
    assert_eq!(
        store
            .consume_invitation_with(
                &mut connection,
                &consumable_token,
                &pepper,
                "email",
                "consume@example.test",
                now,
            )
            .await?,
        InvitationConsumption::Consumed(consumable.metadata.id)
    );
    assert_eq!(
        store
            .consume_invitation_with(
                &mut connection,
                &consumable_token,
                &pepper,
                "email",
                "consume@example.test",
                now,
            )
            .await?,
        InvitationConsumption::Rejected
    );

    let mut transaction = connection.begin().await?;
    let revocable = store
        .issue_invitation_with(
            &mut transaction,
            InvitationIssueRequest {
                identity_provider: "email",
                canonical_email: "revoke@example.test",
                issuer: InvitationIssuer::System,
                now,
                ttl: Duration::from_hours(2),
            },
            &pepper,
            &invitation_generator,
        )
        .await?;
    transaction.commit().await?;
    let listed = store
        .list_invitations_with(&mut connection, InvitationListRequest::new(100)?)
        .await?;
    assert!(listed.iter().any(|item| item.id == revocable.metadata.id));
    assert_eq!(
        store
            .revoke_invitation_with(&mut connection, revocable.metadata.id, now)
            .await?,
        InvitationMutation::Applied
    );
    assert_eq!(
        store
            .revoke_invitation_with(&mut connection, revocable.metadata.id, now)
            .await?,
        InvitationMutation::Rejected
    );

    let mut transaction = connection.begin().await?;
    let recovery = store
        .issue_for_subject_with(
            &mut transaction,
            verification.subject_id,
            TokenPurpose::PasswordRecovery,
            now + time::Duration::minutes(2),
            Duration::from_mins(15),
            &token_generator,
        )
        .await?;
    transaction.commit().await?;
    let active_version = store
        .load_active_user_with(&mut connection, verification.subject_id)
        .await?
        .ok_or("verified user was not active")?
        .authentication_version;
    let mut transaction = connection.begin().await?;
    assert_eq!(
        store
            .disable_user_with(&mut transaction, verification.subject_id)
            .await?,
        InvitationMutation::Applied
    );
    transaction.commit().await?;
    assert_eq!(
        store
            .load_user_status_with(&mut connection, verification.subject_id)
            .await?,
        Some(UserStatus::Disabled)
    );
    let disabled_version: i64 =
        sqlx::query_scalar("SELECT authentication_version FROM users WHERE id = $1")
            .bind(verification.subject_id.as_uuid())
            .fetch_one(&mut *connection)
            .await?;
    assert_eq!(disabled_version, active_version + 1);
    assert!(matches!(
        store
            .verify_password_with(
                &mut connection,
                verification.subject_id,
                password("registration correct horse battery staple")?,
                &worker,
                now,
            )
            .await?,
        PasswordVerification::Rejected
    ));
    let replacement = worker
        .hash_password(password("replacement correct horse battery staple")?)
        .await?;
    let mut transaction = connection.begin().await?;
    assert_eq!(
        store
            .recover_password_with(
                &mut transaction,
                &recovery.token,
                &replacement,
                now + time::Duration::minutes(3),
            )
            .await?,
        TokenConsumption::Rejected
    );
    transaction.commit().await?;
    let mut transaction = connection.begin().await?;
    let recovery_request = store
        .request_for_identity_with(
            &mut transaction,
            omnius_auth_password::IdentityTokenRequest {
                provider: "email",
                provider_subject: "self@example.test",
                purpose: TokenPurpose::PasswordRecovery,
                now: now + time::Duration::minutes(3),
                ttl: Duration::from_mins(15),
                response_floor: Duration::from_millis(500),
            },
            &token_generator,
        )
        .await?;
    transaction.commit().await?;
    assert!(
        recovery_request
            .complete_after_commit()
            .await
            .into_post_commit_dispatch()
            .is_none()
    );

    drop(connection);
    pool.close().await?;
    fixture.cleanup().await?;
    Ok(())
}

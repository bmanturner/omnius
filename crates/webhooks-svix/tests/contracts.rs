//! Deterministic outbound Svix adapter contracts with no live provider operations.

#![expect(
    clippy::expect_used,
    reason = "integration-test assertions require explicit panic diagnostics"
)]

use std::{error::Error, sync::Arc, time::Duration};

use futures::future::BoxFuture;
use omnius_config::SecretString;
use omnius_outbound_http::{OutboundUrlPolicy, OutboundUrlPolicyConfig, Url};
use omnius_webhooks_svix::{
    ApplicationId, ApplicationName, ApplicationSpec, AttemptState, DeliveryAttempt, Destination,
    EndpointDescription, EndpointId, EndpointSpec, EventType, FailureClass, FakeBehavior,
    FakeConfig, FakeError, FakeWebhookProvider, IdempotencyKey, ProviderError,
    ProviderFailureFacts, ProviderOperation, PublishRequest, ReplayAdmission,
    ReplayAdmissionRequest, ReplayCompletion, ReplayLease, ReplayMode, ReplayRequest, ReplayState,
    ReplayTaskBinding, ReplayTaskId, ReplayWindow, SvixConfig, SvixToken, SvixWebhookProvider,
    WebhookProvider, classify_provider_failure,
};
use serde_json::{json, value::RawValue};
use time::OffsetDateTime;

struct RejectingReplayAdmission;

impl ReplayAdmission for RejectingReplayAdmission {
    fn reserve<'a>(
        &'a self,
        _request: &'a ReplayAdmissionRequest,
    ) -> BoxFuture<'a, Result<ReplayLease, ProviderError>> {
        Box::pin(async { Err(ProviderError::new(FailureClass::Unauthorized)) })
    }

    fn bind_task<'a>(
        &'a self,
        _lease: &'a ReplayLease,
        _task_id: &'a ReplayTaskId,
    ) -> BoxFuture<'a, Result<ReplayTaskBinding, ProviderError>> {
        Box::pin(async { Err(ProviderError::new(FailureClass::Unauthorized)) })
    }

    fn authorize_task<'a>(
        &'a self,
        _application_id: &'a ApplicationId,
        _task_id: &'a ReplayTaskId,
    ) -> BoxFuture<'a, Result<ReplayTaskBinding, ProviderError>> {
        Box::pin(async { Err(ProviderError::new(FailureClass::Unauthorized)) })
    }

    fn release_rejected<'a>(
        &'a self,
        _lease: &'a ReplayLease,
    ) -> BoxFuture<'a, Result<(), ProviderError>> {
        Box::pin(async { Ok(()) })
    }

    fn complete<'a>(
        &'a self,
        _binding: &'a ReplayTaskBinding,
        _completion: ReplayCompletion,
    ) -> BoxFuture<'a, Result<(), ProviderError>> {
        Box::pin(async { Ok(()) })
    }
}

fn application_spec() -> Result<ApplicationSpec, Box<dyn Error + Send + Sync>> {
    Ok(ApplicationSpec {
        id: ApplicationId::new("tenant_demo")?,
        name: ApplicationName::new("Demo tenant")?,
    })
}

async fn endpoint_spec(url: &str) -> Result<EndpointSpec, Box<dyn Error + Send + Sync>> {
    endpoint_spec_with_id("billing_endpoint", url).await
}

async fn endpoint_spec_with_id(
    endpoint_id: &str,
    url: &str,
) -> Result<EndpointSpec, Box<dyn Error + Send + Sync>> {
    let policy = OutboundUrlPolicy::new(OutboundUrlPolicyConfig {
        allowed_https_ports: vec![443],
        allow_development_loopback_http: true,
        ..OutboundUrlPolicyConfig::default()
    })?;
    let approved = policy.approve(Url::parse(url)?).await?;
    Ok(EndpointSpec::new(
        EndpointId::new(endpoint_id)?,
        approved,
        EndpointDescription::new("Billing endpoint")?,
        vec![EventType::new("invoice.created")?],
    )?)
}

fn fake() -> Result<FakeWebhookProvider, Box<dyn Error + Send + Sync>> {
    Ok(FakeWebhookProvider::new(
        FakeConfig::new(16)?.with_bounds(16, 16, 16, 64 * 1024)?,
        ApplicationId::new("tenant_demo")?,
    )?)
}

async fn provision(
    fake: &FakeWebhookProvider,
) -> Result<(ApplicationSpec, EndpointId), Box<dyn Error + Send + Sync>> {
    let application = application_spec()?;
    let endpoint = endpoint_spec("http://127.0.0.1:8071/billing").await?;
    let endpoint_id = endpoint.id.clone();
    fake.application_get_or_create(&application).await?;
    fake.endpoint_create(&application.id, endpoint).await?;
    Ok((application, endpoint_id))
}

#[tokio::test]
async fn publish_preserves_canonical_payload_and_is_idempotent()
-> Result<(), Box<dyn Error + Send + Sync>> {
    let fake = fake()?;
    let (application, _) = provision(&fake).await?;
    let payload = RawValue::from_string(
        r#"{"id":"018f0000-0000-7000-8000-000000000001","type":"invoice.created","version":1,"data":{"amount":1200,"currency":"USD"}}"#.to_owned(),
    )?;
    let event_id = "018f0000-0000-7000-8000-000000000001";

    let first = fake
        .publish(PublishRequest {
            application_id: &application.id,
            event_id,
            event_type: "invoice.created",
            payload: &payload,
        })
        .await?;
    let duplicate = fake
        .publish(PublishRequest {
            application_id: &application.id,
            event_id,
            event_type: "invoice.created",
            payload: &payload,
        })
        .await?;
    let captures = fake.captures()?;

    assert_eq!(first, duplicate);
    assert_eq!(captures.len(), 1);
    assert_eq!(captures[0].event_id().as_str(), event_id);
    assert_eq!(captures[0].event_type().as_str(), "invoice.created");
    assert_eq!(captures[0].payload_json().get(), payload.get());
    Ok(())
}

#[tokio::test]
async fn duplicate_event_id_with_different_envelope_is_rejected()
-> Result<(), Box<dyn Error + Send + Sync>> {
    let fake = fake()?;
    let (application, _) = provision(&fake).await?;
    let first = RawValue::from_string(r#"{"value":1}"#.to_owned())?;
    let second = RawValue::from_string(r#"{"value":2}"#.to_owned())?;
    fake.publish(PublishRequest {
        application_id: &application.id,
        event_id: "018f0000-0000-7000-8000-000000000002",
        event_type: "invoice.created",
        payload: &first,
    })
    .await?;
    let error = fake
        .publish(PublishRequest {
            application_id: &application.id,
            event_id: "018f0000-0000-7000-8000-000000000002",
            event_type: "invoice.created",
            payload: &second,
        })
        .await
        .expect_err("conflict expected");

    assert_eq!(error.class(), FailureClass::Conflict);
    assert_eq!(fake.captures()?.len(), 1);
    Ok(())
}

#[tokio::test]
async fn application_endpoint_and_secret_lifecycle_is_deterministic()
-> Result<(), Box<dyn Error + Send + Sync>> {
    let fake = fake()?;
    let application = application_spec()?;
    let created_application = fake.application_get_or_create(&application).await?;
    let duplicate_application = fake.application_get_or_create(&application).await?;
    let changed_application = ApplicationSpec {
        id: application.id.clone(),
        name: ApplicationName::new("Changed tenant name")?,
    };
    let changed_error = fake
        .application_get_or_create(&changed_application)
        .await
        .expect_err("changed bound application must conflict");
    assert_eq!(changed_error.class(), FailureClass::Conflict);
    assert_eq!(created_application, duplicate_application);

    let endpoint = endpoint_spec("http://127.0.0.1:8071/first").await?;
    let endpoint_id = endpoint.id.clone();
    let created = fake.endpoint_create(&application.id, endpoint).await?;
    assert!(created.enabled);
    let disabled = fake
        .endpoint_set_enabled(&application.id, &endpoint_id, false)
        .await?;
    assert!(!disabled.enabled);

    let updated = endpoint_spec("http://127.0.0.1:8071/replacement").await?;
    let update_status = fake.endpoint_update(&application.id, updated).await?;
    assert!(!update_status.enabled);
    let before = fake.signing_secret(&application.id, &endpoint_id).await?;
    fake.rotate_signing_secret(
        &application.id,
        &endpoint_id,
        Duration::from_secs(60),
        &IdempotencyKey::new("rotate_001")?,
    )
    .await?;
    let after = fake.signing_secret(&application.id, &endpoint_id).await?;
    assert_ne!(
        before.expose_for_verification(),
        after.expose_for_verification()
    );
    assert!(!format!("{after:?}").contains(after.expose_for_verification()));

    fake.endpoint_delete(&application.id, &endpoint_id).await?;
    let deleted = fake
        .endpoint_status(&application.id, &endpoint_id)
        .await
        .expect_err("deleted endpoint must be absent");
    assert_eq!(deleted.class(), FailureClass::NotFound);
    Ok(())
}

#[tokio::test]
async fn provider_scope_rejects_foreign_application_ids() -> Result<(), Box<dyn Error + Send + Sync>>
{
    let fake = fake()?;
    let (_, endpoint_id) = provision(&fake).await?;
    let foreign = ApplicationSpec {
        id: ApplicationId::new("tenant_foreign")?,
        name: ApplicationName::new("Foreign tenant")?,
    };
    let application_error = fake
        .application_get_or_create(&foreign)
        .await
        .expect_err("foreign application must be rejected");
    assert_eq!(application_error.class(), FailureClass::Unauthorized);

    let secret_error = fake
        .signing_secret(&foreign.id, &endpoint_id)
        .await
        .expect_err("foreign secret access must be rejected");
    assert_eq!(secret_error.class(), FailureClass::Unauthorized);
    let payload = RawValue::from_string(r#"{"scope":"foreign"}"#.to_owned())?;
    let publish_error = fake
        .publish(PublishRequest {
            application_id: &foreign.id,
            event_id: "evt_foreign",
            event_type: "invoice.created",
            payload: &payload,
        })
        .await
        .expect_err("foreign publish must be rejected");
    assert_eq!(publish_error.class(), FailureClass::Unauthorized);

    let replay_error = fake
        .replay_start(&ReplayRequest {
            application_id: foreign.id,
            endpoint_id,
            mode: ReplayMode::All,
            window: ReplayWindow::new(
                OffsetDateTime::from_unix_timestamp(1_699_999_980)?,
                OffsetDateTime::from_unix_timestamp(1_700_000_040)?,
            )?,
        })
        .await
        .expect_err("foreign replay must be rejected");
    assert_eq!(replay_error.class(), FailureClass::Unauthorized);
    Ok(())
}

#[tokio::test]
async fn delivery_status_and_replay_lifecycle_are_bounded()
-> Result<(), Box<dyn Error + Send + Sync>> {
    let fake = fake()?;
    let (application, endpoint) = provision(&fake).await?;
    let payload = RawValue::from_string(r#"{"id":"evt_status"}"#.to_owned())?;
    let receipt = fake
        .publish(PublishRequest {
            application_id: &application.id,
            event_id: "evt_status",
            event_type: "invoice.created",
            payload: &payload,
        })
        .await?;
    let attempts = vec![
        DeliveryAttempt {
            state: AttemptState::Failed,
            response_status: Some(503),
            response_duration_ms: 25,
        },
        DeliveryAttempt {
            state: AttemptState::Succeeded,
            response_status: Some(204),
            response_duration_ms: 10,
        },
    ];
    fake.set_delivery_attempts(&application.id, &receipt.message_id, attempts.clone())?;
    let status = fake
        .delivery_status(&application.id, &receipt.message_id)
        .await?;
    assert_eq!(status.attempts(), attempts);

    let request = ReplayRequest {
        application_id: application.id.clone(),
        endpoint_id: endpoint.clone(),
        mode: ReplayMode::Failed,
        window: ReplayWindow::new(
            OffsetDateTime::from_unix_timestamp(1_699_999_980)?,
            OffsetDateTime::from_unix_timestamp(1_700_003_580)?,
        )?,
    };
    let (first, concurrent) =
        tokio::join!(fake.replay_start(&request), fake.replay_start(&request));
    let ((Ok(replay), Err(rejected)) | (Err(rejected), Ok(replay))) = (first, concurrent) else {
        return Err("concurrent replay admission did not produce one winner".into());
    };
    assert_eq!(rejected.class(), FailureClass::Conflict);
    assert_eq!(replay.state, ReplayState::Running);
    fake.set_replay_state(&replay.id, ReplayState::Finished)?;
    assert_eq!(
        fake.replay_status(&application.id, &replay.id).await?.state,
        ReplayState::Finished
    );
    Ok(())
}

#[tokio::test]
async fn replay_capacity_never_evicts_active_tasks_and_terminal_state_releases_capacity()
-> Result<(), Box<dyn Error + Send + Sync>> {
    let application = application_spec()?;
    let fake = FakeWebhookProvider::new(
        FakeConfig::new(8)?
            .with_bounds(8, 8, 8, 64 * 1024)?
            .with_active_replay_capacity(1)?,
        application.id.clone(),
    )?;
    fake.application_get_or_create(&application).await?;
    let first_endpoint = endpoint_spec_with_id("endpoint_one", "http://127.0.0.1:8071/one").await?;
    let first_endpoint_id = first_endpoint.id.clone();
    fake.endpoint_create(&application.id, first_endpoint)
        .await?;
    let second_endpoint =
        endpoint_spec_with_id("endpoint_two", "http://127.0.0.1:8071/two").await?;
    let second_endpoint_id = second_endpoint.id.clone();
    fake.endpoint_create(&application.id, second_endpoint)
        .await?;
    let window = ReplayWindow::new(
        OffsetDateTime::from_unix_timestamp(1_699_999_980)?,
        OffsetDateTime::from_unix_timestamp(1_700_000_040)?,
    )?;
    let first = fake
        .replay_start(&ReplayRequest {
            application_id: application.id.clone(),
            endpoint_id: first_endpoint_id,
            mode: ReplayMode::Missing,
            window,
        })
        .await?;
    let second_request = ReplayRequest {
        application_id: application.id.clone(),
        endpoint_id: second_endpoint_id,
        mode: ReplayMode::Missing,
        window,
    };
    let capacity = fake
        .replay_start(&second_request)
        .await
        .expect_err("active replay capacity must fail closed");
    assert_eq!(capacity.class(), FailureClass::Capacity);
    assert_eq!(
        fake.replay_status(&application.id, &first.id).await?.state,
        ReplayState::Running
    );
    fake.set_replay_state(&first.id, ReplayState::Finished)?;
    assert_eq!(
        fake.replay_start(&second_request).await?.state,
        ReplayState::Running
    );
    Ok(())
}

#[tokio::test]
async fn deterministic_provider_failures_and_health_are_value_safe()
-> Result<(), Box<dyn Error + Send + Sync>> {
    let fake = fake()?;
    fake.plan(
        ProviderOperation::ApplicationGetOrCreate,
        FakeBehavior::Fail(FailureClass::RateLimited),
    )?;
    let error = fake
        .application_get_or_create(&application_spec()?)
        .await
        .expect_err("planned failure expected");
    assert_eq!(error.class(), FailureClass::RateLimited);
    assert!(error.is_retryable());

    fake.set_healthy(false)?;
    let health = fake.health().await.expect_err("unhealthy fake expected");
    assert_eq!(health.class(), FailureClass::Unavailable);
    assert_eq!(
        classify_provider_failure(ProviderFailureFacts::Http(429)),
        FailureClass::RateLimited
    );
    assert_eq!(
        classify_provider_failure(ProviderFailureFacts::Http(503)),
        FailureClass::Server
    );
    assert_eq!(
        classify_provider_failure(ProviderFailureFacts::Validation),
        FailureClass::Rejected
    );
    Ok(())
}

#[tokio::test]
async fn shutdown_cancels_in_flight_work_and_rejects_new_work()
-> Result<(), Box<dyn Error + Send + Sync>> {
    let fake = fake()?;
    fake.plan(ProviderOperation::Health, FakeBehavior::WaitForCancellation)?;
    let pending_fake = fake.clone();
    let pending = tokio::spawn(async move { pending_fake.health().await });
    tokio::time::timeout(Duration::from_secs(1), async {
        while fake.in_flight() == 0 {
            tokio::task::yield_now().await;
        }
    })
    .await?;
    fake.shutdown().await?;
    let cancelled = pending.await?.expect_err("cancellation expected");
    assert_eq!(cancelled.class(), FailureClass::Cancelled);
    let draining = fake.health().await.expect_err("new work must be rejected");
    assert_eq!(draining.class(), FailureClass::Draining);
    Ok(())
}

#[test]
fn config_enforces_bounds_tls_unknown_fields_and_redaction()
-> Result<(), Box<dyn Error + Send + Sync>> {
    let valid: SvixConfig = serde_json::from_value(json!({
        "token": "test_token_do_not_log",
        "application_id": "tenant_demo",
        "destination": "svix",
        "server_url": "https://svix.example.test",
        "request_timeout": "5s",
        "drain_timeout": "2s",
        "replay_poll_interval": "50ms",
        "replay_wait_timeout": "10s",
        "replay_max_polls": 20,
        "max_status_attempts": 10,
        "max_payload_bytes": 65536
    }))?;
    let debug = format!("{valid:?}");
    assert!(!debug.contains("test_token_do_not_log"));
    assert!(!debug.contains("svix.example.test"));
    assert!(debug.contains("[REDACTED]"));

    let loopback: Result<SvixConfig, _> = serde_json::from_value(json!({
        "token": "test_token",
        "application_id": "tenant_demo",
        "destination": "svix",
        "server_url": "http://127.0.0.1:8071",
        "allow_insecure_loopback": true
    }));
    assert!(loopback.is_ok());
    let ipv6_loopback: Result<SvixConfig, _> = serde_json::from_value(json!({
        "token": "test_token",
        "application_id": "tenant_demo",
        "destination": "svix",
        "server_url": "http://[::1]:8071",
        "allow_insecure_loopback": true
    }));
    assert!(ipv6_loopback.is_ok());
    let loopback_hostname: Result<SvixConfig, _> = serde_json::from_value(json!({
        "token": "test_token",
        "application_id": "tenant_demo",
        "destination": "svix",
        "server_url": "http://localhost:8071",
        "allow_insecure_loopback": true
    }));
    assert!(loopback_hostname.is_err());
    let public_http: Result<SvixConfig, _> = serde_json::from_value(json!({
        "token": "test_token",
        "application_id": "tenant_demo",
        "destination": "svix",
        "server_url": "http://svix.example.test"
    }));
    assert!(public_http.is_err());
    let sdk_retries: Result<SvixConfig, _> = serde_json::from_value(json!({
        "token": "test_token",
        "application_id": "tenant_demo",
        "destination": "svix",
        "num_retries": 2
    }));
    assert!(sdk_retries.is_err());
    let proxy: Result<SvixConfig, _> = serde_json::from_value(json!({
        "token": "test_token",
        "application_id": "tenant_demo",
        "destination": "svix",
        "proxy_address": "http://proxy.example.test"
    }));
    assert!(proxy.is_err());
    let excessive_timeout: Result<SvixConfig, _> = serde_json::from_value(json!({
        "token": "test_token",
        "application_id": "tenant_demo",
        "destination": "svix",
        "request_timeout": "121s"
    }));
    assert!(excessive_timeout.is_err());
    Ok(())
}

#[tokio::test]
async fn endpoint_capability_and_replay_values_enforce_hard_bounds()
-> Result<(), Box<dyn Error + Send + Sync>> {
    let endpoint = endpoint_spec("http://127.0.0.1:8071/hook").await?;
    assert!(format!("{endpoint:?}").contains("[REDACTED]"));
    let production_policy = OutboundUrlPolicy::new(OutboundUrlPolicyConfig::default())?;
    assert!(
        production_policy
            .approve(Url::parse("http://127.0.0.1:8071/hook")?)
            .await
            .is_err()
    );
    assert!(
        ReplayWindow::new(
            OffsetDateTime::from_unix_timestamp(1_699_999_980)?,
            OffsetDateTime::from_unix_timestamp(1_699_999_980 + 91 * 86_400)?,
        )
        .is_err()
    );
    assert!(
        ReplayWindow::new(
            OffsetDateTime::from_unix_timestamp(1_699_999_980)?,
            OffsetDateTime::from_unix_timestamp(1_699_999_981)?,
        )
        .is_err()
    );
    assert_eq!(FakeConfig::new(0), Err(FakeError::Capacity));
    Ok(())
}

#[tokio::test]
async fn token_rotation_uses_transport_reusing_sdk_path_without_network()
-> Result<(), Box<dyn Error + Send + Sync>> {
    let config = SvixConfig::new(
        SvixToken::new(SecretString::from("test_old_token".to_owned()))?,
        ApplicationId::new("tenant_demo")?,
        Destination::new("svix")?,
    )?;
    let provider = SvixWebhookProvider::new(&config, Arc::new(RejectingReplayAdmission))?;
    let new_token = SvixToken::new(SecretString::from("test_new_token".to_owned()))?;
    let rebound = provider.with_token(&new_token)?;
    assert_eq!(provider.token_generation(), 0);
    assert_eq!(rebound.token_generation(), 1);
    let rotated_token = SvixToken::new(SecretString::from("test_rotated_token".to_owned()))?;
    provider.rotate_token(&rotated_token)?;
    assert_eq!(provider.token_generation(), 1);
    let debug = format!("{provider:?}");
    assert!(!debug.contains("test_rotated_token"));
    let unknown_task = omnius_webhooks_svix::ReplayTaskId::new("task_from_other_application")?;
    let Err(error) = provider
        .replay_status(config.application_id(), &unknown_task)
        .await
    else {
        return Err("untracked replay task was accepted".into());
    };
    assert_eq!(error.class(), FailureClass::Unauthorized);
    Ok(())
}

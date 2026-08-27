//! Observable contracts for bounded email rendering, delivery, events, and diagnostics.

use std::{error::Error, io, path::PathBuf, sync::Arc};

use omnius_config::DeploymentEnvironment;
use omnius_email::{
    AttachmentMediaType, AttachmentName, CapturingMailSink, ClientMessageId, CustomHeader,
    CustomHeaderName, CustomHeaderPolicy, CustomHeaderValue, DeliveryEventOutcome,
    DeliveryFailureClass, DeliveryGuarantee, DisplayName, EmailAddress, EmailAttachment,
    EmailConfig, EmailError, EmailLimits, EmailProviderConfig, EmailService, EmailSubject,
    MailSender as _, MailboxAddress, ProviderBounceClass, ProviderDeliveryEvent,
    ProviderDeliveryEventKind, ProviderLifecycle, ProviderMessageId, RecipientSet,
    SendEmailHandler, SendEmailJob, SendEmailRequest, SmtpFailureFacts, TemplateConfig,
    TemplateContext, TemplateName, classify_smtp_failure,
};
use omnius_jobs_core::{
    DeliveryContext, HandlerOutcome, IdempotencyKey, JobEnvelope, JobEnvelopeOptions,
    TypedJobHandler as _,
};
use serde_json::json;
use time::{Duration, OffsetDateTime};
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

fn template_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/templates")
}

fn config(limits: EmailLimits, capacity: usize) -> Result<EmailConfig, EmailError> {
    Ok(EmailConfig {
        provider: EmailProviderConfig::Capturing { capacity },
        templates: TemplateConfig {
            directory: template_root(),
            allowed_templates: vec![TemplateName::try_from("welcome")?],
        },
        custom_headers: CustomHeaderPolicy::default(),
        limits,
    })
}

fn mailbox(address: &str, display_name: Option<&str>) -> Result<MailboxAddress, EmailError> {
    Ok(MailboxAddress::new(
        EmailAddress::try_from(address)?,
        display_name.map(DisplayName::try_from).transpose()?,
    ))
}

fn request(idempotency: &str, name: &str) -> Result<SendEmailRequest, Box<dyn Error>> {
    request_for_template(idempotency, name, "welcome")
}

fn request_for_template(
    idempotency: &str,
    name: &str,
    template: &str,
) -> Result<SendEmailRequest, Box<dyn Error>> {
    let recipients = RecipientSet::new(
        vec![mailbox("recipient@example.com", Some("受信者"))?],
        Vec::new(),
        Vec::new(),
    )?;
    Ok(SendEmailRequest::new(
        IdempotencyKey::try_from(idempotency)?,
        ClientMessageId::new_random(),
        mailbox("sender@example.com", Some("送信者"))?,
        recipients,
        EmailSubject::try_from("ようこそ")?,
        TemplateName::try_from(template)?,
        TemplateContext::new(json!({ "name": name }))?,
    ))
}

fn capture(service: &EmailService) -> Result<CapturingMailSink, io::Error> {
    service
        .capturing_sink()
        .ok_or_else(|| io::Error::other("test service must expose its capture sink"))
}

#[tokio::test]
async fn renders_strict_text_and_html_with_context_appropriate_escaping()
-> Result<(), Box<dyn Error>> {
    let service = EmailService::build(
        config(EmailLimits::default(), 4)?,
        DeploymentEnvironment::Test,
    )?;
    let receipt = service
        .send(request("mail-render-1", "<Admin & team>")?)
        .await?;
    assert_eq!(
        receipt.provider_message_id().map(ProviderMessageId::as_str),
        Some("capture-1")
    );
    assert_eq!(receipt.guarantee(), DeliveryGuarantee::AtLeastOnce);
    let event = receipt.delivery_event();
    assert_eq!(event.outcome(), DeliveryEventOutcome::Accepted);
    assert_eq!(
        event.provider_message_id().map(ProviderMessageId::as_str),
        Some("capture-1"),
    );

    let messages = capture(&service)?.snapshot()?;
    assert_eq!(messages.len(), 1);
    let formatted = messages[0].formatted_utf8()?;
    assert!(formatted.contains("multipart/alternative"));
    assert!(formatted.contains("Hello <Admin & team>!"));
    assert!(formatted.contains("<p>Hello &lt;Admin &amp; team&gt;!</p>"));
    assert!(formatted.contains("=?utf-8?b?"));
    Ok(())
}

#[tokio::test]
async fn strict_missing_variable_fails_before_capture() -> Result<(), Box<dyn Error>> {
    let service = EmailService::build(
        config(EmailLimits::default(), 2)?,
        DeploymentEnvironment::Test,
    )?;
    let recipients = RecipientSet::new(
        vec![mailbox("recipient@example.com", None)?],
        Vec::new(),
        Vec::new(),
    )?;
    let request = SendEmailRequest::new(
        IdempotencyKey::try_from("mail-missing-1")?,
        ClientMessageId::new_random(),
        mailbox("sender@example.com", None)?,
        recipients,
        EmailSubject::try_from("subject")?,
        TemplateName::try_from("welcome")?,
        TemplateContext::empty(),
    );
    assert_eq!(service.send(request).await, Err(EmailError::TemplateRender));
    assert!(capture(&service)?.is_empty()?);
    Ok(())
}

#[test]
fn fuel_and_output_writers_enforce_independent_bounds() -> Result<(), Box<dyn Error>> {
    let fuel_limits = EmailLimits {
        render_fuel: 1,
        ..EmailLimits::default()
    };
    let fuel_service = EmailService::build(config(fuel_limits, 1)?, DeploymentEnvironment::Test)?;
    let context = TemplateContext::new(json!({ "name": "Ada" }))?;
    let template = TemplateName::try_from("welcome")?;
    assert_eq!(
        fuel_service.templates().preview(&template, &context),
        Err(EmailError::TemplateRender),
    );

    let output_limits = EmailLimits {
        max_rendered_text_bytes: 8,
        max_rendered_html_bytes: 8,
        ..EmailLimits::default()
    };
    let output_service =
        EmailService::build(config(output_limits, 1)?, DeploymentEnvironment::Test)?;
    assert_eq!(
        output_service.templates().preview(&template, &context),
        Err(EmailError::RenderLimit),
    );
    Ok(())
}

#[tokio::test]
async fn addresses_headers_and_attachments_reject_injection_and_excess()
-> Result<(), Box<dyn Error>> {
    assert_eq!(
        EmailAddress::try_from("victim@example.com\r\nBcc: attacker@example.com"),
        Err(EmailError::InvalidAddress),
    );
    assert_eq!(
        EmailSubject::try_from("safe\r\nBcc: attacker@example.com"),
        Err(EmailError::InvalidHeader),
    );
    assert_eq!(
        CustomHeaderName::try_from("Subject"),
        Err(EmailError::InvalidHeader),
    );
    assert_eq!(
        CustomHeaderValue::try_from("value\nX-Evil: yes"),
        Err(EmailError::InvalidHeader),
    );
    assert_eq!(
        EmailAttachment::new(
            AttachmentName::try_from("large.bin")?,
            AttachmentMediaType::try_from("application/octet-stream")?,
            vec![0_u8; 512 * 1024 + 1],
        ),
        Err(EmailError::AttachmentLimit),
    );

    let limits = EmailLimits {
        max_attachments: 1,
        ..EmailLimits::default()
    };
    let service = EmailService::build(config(limits, 2)?, DeploymentEnvironment::Test)?;
    let attachments = vec![
        EmailAttachment::new(
            AttachmentName::try_from("first.txt")?,
            AttachmentMediaType::try_from("text/plain")?,
            b"one".to_vec(),
        )?,
        EmailAttachment::new(
            AttachmentName::try_from("second.txt")?,
            AttachmentMediaType::try_from("text/plain")?,
            b"two".to_vec(),
        )?,
    ];
    let request = request("mail-attachment-1", "Ada")?.with_attachments(attachments)?;
    assert_eq!(
        service.send(request).await,
        Err(EmailError::AttachmentLimit)
    );
    assert!(capture(&service)?.is_empty()?);
    Ok(())
}

#[tokio::test]
async fn custom_headers_are_default_deny_case_insensitive_and_unique() -> Result<(), Box<dyn Error>>
{
    let denied = EmailService::build(
        config(EmailLimits::default(), 2)?,
        DeploymentEnvironment::Test,
    )?;
    let header = CustomHeader::new(
        CustomHeaderName::try_from("X-Trace")?,
        CustomHeaderValue::try_from("safe-value")?,
    );
    let denied_request =
        request("mail-header-denied", "Ada")?.with_headers(vec![header.clone()])?;
    assert_eq!(
        denied.send(denied_request).await,
        Err(EmailError::InvalidHeader)
    );

    let mut allowed_config = config(EmailLimits::default(), 2)?;
    allowed_config.custom_headers = CustomHeaderPolicy {
        allowed: vec![CustomHeaderName::try_from("x-trace")?],
    };
    let allowed = EmailService::build(allowed_config, DeploymentEnvironment::Test)?;
    allowed
        .send(request("mail-header-allowed", "Ada")?.with_headers(vec![header.clone()])?)
        .await?;
    let duplicate = CustomHeader::new(
        CustomHeaderName::try_from("x-TRACE")?,
        CustomHeaderValue::try_from("second-safe-value")?,
    );
    let duplicate_request =
        request("mail-header-duplicate", "Ada")?.with_headers(vec![header, duplicate])?;
    assert_eq!(
        allowed.send(duplicate_request).await,
        Err(EmailError::InvalidHeader)
    );
    assert_eq!(capture(&allowed)?.len()?, 1);
    let mut invalid_config = config(EmailLimits::default(), 2)?;
    invalid_config.custom_headers = CustomHeaderPolicy {
        allowed: vec![
            CustomHeaderName::try_from("X-Trace")?,
            CustomHeaderName::try_from("x-trace")?,
        ],
    };
    assert!(matches!(
        EmailService::build(invalid_config, DeploymentEnvironment::Test),
        Err(EmailError::Config)
    ));
    Ok(())
}

#[tokio::test]
async fn capturing_sink_is_fixed_capacity_fifo() -> Result<(), Box<dyn Error>> {
    let service = EmailService::build(
        config(EmailLimits::default(), 2)?,
        DeploymentEnvironment::Test,
    )?;
    service.send(request("mail-order-1", "first")?).await?;
    service.send(request("mail-order-2", "second")?).await?;
    assert_eq!(
        service.send(request("mail-order-3", "third")?).await,
        Err(EmailError::Delivery(DeliveryFailureClass::Unavailable)),
    );

    let sink = capture(&service)?;
    let snapshot = sink.snapshot()?;
    let ids: Vec<&str> = snapshot
        .iter()
        .map(|message| message.provider_message_id().as_str())
        .collect();
    assert_eq!(ids, ["capture-1", "capture-2"]);
    let first = snapshot[0].formatted_utf8()?;
    let second = snapshot[1].formatted_utf8()?;
    assert!(first.contains("Hello first!"));
    assert!(second.contains("Hello second!"));
    assert_eq!(sink.drain()?.len(), 2);
    assert!(sink.is_empty()?);
    Ok(())
}
#[tokio::test]
async fn max_in_flight_rejects_excess_admission() -> Result<(), Box<dyn Error>> {
    let limits = EmailLimits {
        max_in_flight: 1,
        render_fuel: 10_000_000,
        operation_timeout: std::time::Duration::from_secs(120),
        ..EmailLimits::default()
    };
    let mut email_config = config(limits, 2)?;
    email_config
        .templates
        .allowed_templates
        .push(TemplateName::try_from("busy")?);
    let service = EmailService::build(email_config, DeploymentEnvironment::Test)?;
    let first_request = request_for_template("mail-capacity-first", "busy", "busy")?;
    let first_service = service.clone();
    let first = tokio::spawn(async move { first_service.send(first_request).await });
    let mut admitted = false;
    for _ in 0..1_000 {
        if service.status().active_sends == 1 {
            admitted = true;
            break;
        }
        tokio::task::yield_now().await;
    }
    if !admitted {
        return Err(io::Error::other("first send was not admitted").into());
    }
    assert_eq!(
        service.send(request("mail-capacity-second", "Ada")?).await,
        Err(EmailError::Capacity)
    );
    service.shutdown().await;
    let _first_result = first.await?;
    Ok(())
}

#[tokio::test]
async fn persisted_client_message_id_survives_serialization_and_service_changes()
-> Result<(), Box<dyn Error>> {
    let original = request("stable-retry-key", "durable effect")?;
    let expected = original.client_message_id().clone();
    assert_eq!(expected.as_str().as_bytes().get(15), Some(&b'7'));
    assert!(expected.as_str().ends_with("@omnius.invalid>"));
    for malformed in [
        "provider-message-id",
        "<550e8400-e29b-41d4-a716-446655440000@omnius.invalid>",
        "<0190f47d-4d2f-7b3a-8d19-0123456789ab@example.com>",
        "<0190F47D-4D2F-7B3A-8D19-0123456789AB@omnius.invalid>",
    ] {
        assert_eq!(
            ClientMessageId::try_from(malformed),
            Err(EmailError::InvalidMessageId)
        );
    }
    let serialized = serde_json::to_vec(&original)?;
    let wire: serde_json::Value = serde_json::from_slice(&serialized)?;
    assert_eq!(wire["client_message_id"].as_str(), Some(expected.as_str()));
    assert!(!format!("{original:?}").contains(expected.as_str()));

    let first_attempt: SendEmailRequest = serde_json::from_slice(&serialized)?;
    let retry_attempt: SendEmailRequest = serde_json::from_slice(&serialized)?;
    assert_eq!(first_attempt.client_message_id(), &expected);
    assert_eq!(retry_attempt.client_message_id(), &expected);

    let first_service = EmailService::build(
        config(EmailLimits::default(), 1)?,
        DeploymentEnvironment::Test,
    )?;
    first_service.send(first_attempt).await?;
    let retry_service = EmailService::build(
        config(EmailLimits::default(), 2)?,
        DeploymentEnvironment::Test,
    )?;
    retry_service.send(retry_attempt).await?;

    let first_messages = capture(&first_service)?.snapshot()?;
    let retry_messages = capture(&retry_service)?.snapshot()?;
    assert_eq!(first_messages[0].client_message_id(), &expected);
    assert_eq!(retry_messages[0].client_message_id(), &expected);
    assert!(
        !first_messages[0]
            .formatted_utf8()?
            .contains("stable-retry-key")
    );

    let mut missing_identifier = wire;
    missing_identifier
        .as_object_mut()
        .ok_or_else(|| io::Error::other("request wire must be an object"))?
        .remove("client_message_id");
    assert!(serde_json::from_value::<SendEmailRequest>(missing_identifier).is_err());
    Ok(())
}

#[test]
fn provider_callback_events_are_typed_and_redacted() -> Result<(), Box<dyn Error>> {
    let event = ProviderDeliveryEvent::new(
        ProviderMessageId::try_from("provider-event-1")?,
        ProviderMessageId::try_from("provider-message-1")?,
        1_750_000_000_000,
        ProviderDeliveryEventKind::Bounce {
            classification: ProviderBounceClass::Permanent,
        },
    );
    let encoded = serde_json::to_vec(&event)?;
    let decoded: ProviderDeliveryEvent = serde_json::from_slice(&encoded)?;
    assert_eq!(decoded, event);
    assert!(!format!("{event:?}").contains("provider-message-1"));
    assert_eq!(
        event.kind(),
        ProviderDeliveryEventKind::Bounce {
            classification: ProviderBounceClass::Permanent,
        }
    );
    Ok(())
}

#[test]
fn smtp_classification_uses_only_stable_facts() {
    let cases = [
        (SmtpFailureFacts::Timeout, DeliveryFailureClass::Timeout),
        (SmtpFailureFacts::Tls, DeliveryFailureClass::Tls),
        (SmtpFailureFacts::Transient, DeliveryFailureClass::Transient),
        (SmtpFailureFacts::Permanent, DeliveryFailureClass::Permanent),
        (
            SmtpFailureFacts::Status(399),
            DeliveryFailureClass::Status(399),
        ),
        (
            SmtpFailureFacts::Unavailable,
            DeliveryFailureClass::Unavailable,
        ),
    ];
    for (facts, expected) in cases {
        assert_eq!(classify_smtp_failure(facts), expected);
    }
}

#[tokio::test]
async fn drain_and_shutdown_close_admission_without_network() -> Result<(), Box<dyn Error>> {
    let service = EmailService::build(
        config(EmailLimits::default(), 2)?,
        DeploymentEnvironment::Test,
    )?;
    service.begin_drain();
    assert_eq!(service.status().lifecycle, ProviderLifecycle::Draining);
    assert_eq!(
        service.send(request("mail-drain-1", "Ada")?).await,
        Err(EmailError::AdmissionClosed),
    );
    service.shutdown().await;
    assert_eq!(service.status().lifecycle, ProviderLifecycle::Shutdown);
    assert_eq!(
        service.test_connection().await,
        Err(EmailError::AdmissionClosed)
    );
    Ok(())
}

#[tokio::test]
async fn typed_handler_enforces_effect_identity_deadline_and_cancellation()
-> Result<(), Box<dyn Error>> {
    let service = EmailService::build(
        config(EmailLimits::default(), 4)?,
        DeploymentEnvironment::Test,
    )?;
    let handler = SendEmailHandler::new(Arc::new(service.clone()));
    let key = IdempotencyKey::try_from("mail-handler-1")?;
    let envelope = JobEnvelope::new(
        SendEmailJob::new(request("mail-handler-1", "handler")?),
        JobEnvelopeOptions::new(Uuid::now_v7())?.with_idempotency_key(key),
    )?;
    let encoded = envelope.encode()?;
    let context = DeliveryContext::from_envelope(
        &encoded,
        1,
        CancellationToken::new(),
        OffsetDateTime::now_utc() + Duration::seconds(30),
    )?;
    let job = encoded.decode::<SendEmailJob>()?.into_payload();
    assert_eq!(
        handler.handle(job, context).await,
        HandlerOutcome::Succeeded
    );
    assert_eq!(capture(&service)?.len()?, 1);
    let mismatch_key = IdempotencyKey::try_from("mail-handler-envelope")?;
    let mismatch_envelope = JobEnvelope::new(
        SendEmailJob::new(request("mail-handler-payload", "mismatch")?),
        JobEnvelopeOptions::new(Uuid::now_v7())?.with_idempotency_key(mismatch_key),
    )?;
    let mismatch_encoded = mismatch_envelope.encode()?;
    let mismatch_context = DeliveryContext::from_envelope(
        &mismatch_encoded,
        1,
        CancellationToken::new(),
        OffsetDateTime::now_utc() + Duration::seconds(30),
    )?;
    let mismatch_job = mismatch_encoded.decode::<SendEmailJob>()?.into_payload();
    assert!(matches!(
        handler.handle(mismatch_job, mismatch_context).await,
        HandlerOutcome::Permanent(_),
    ));
    let cancelled_key = IdempotencyKey::try_from("mail-handler-cancelled")?;
    let cancelled_envelope = JobEnvelope::new(
        SendEmailJob::new(request("mail-handler-cancelled", "cancelled")?),
        JobEnvelopeOptions::new(Uuid::now_v7())?.with_idempotency_key(cancelled_key),
    )?;
    let cancelled_encoded = cancelled_envelope.encode()?;
    let cancellation = CancellationToken::new();
    cancellation.cancel();
    let cancelled_context = DeliveryContext::from_envelope(
        &cancelled_encoded,
        1,
        cancellation,
        OffsetDateTime::now_utc() + Duration::seconds(30),
    )?;
    let cancelled_job = cancelled_encoded.decode::<SendEmailJob>()?.into_payload();
    assert_eq!(
        handler.handle(cancelled_job, cancelled_context).await,
        HandlerOutcome::Cancelled,
    );
    assert_eq!(capture(&service)?.len()?, 1);
    Ok(())
}

#[test]
fn config_is_strict_tls_only_and_capture_is_test_only() -> Result<(), Box<dyn Error>> {
    let strict = json!({
        "provider": {
            "provider": "capturing",
            "capacity": 2
        },
        "templates": {
            "directory": template_root(),
            "allowed_templates": ["welcome"],
            "unexpected": true
        },
    });
    assert!(serde_json::from_value::<EmailConfig>(strict).is_err());

    let capture_config = config(EmailLimits::default(), 2)?;
    assert_eq!(
        capture_config.validate(DeploymentEnvironment::Development),
        Err(EmailError::Config),
    );
    let zero_capacity_limits = EmailLimits {
        max_in_flight: 0,
        ..EmailLimits::default()
    };
    assert_eq!(
        config(zero_capacity_limits, 1)?.validate(DeploymentEnvironment::Test),
        Err(EmailError::Config)
    );

    let smtp: EmailConfig = serde_json::from_value(json!({
        "provider": {
            "provider": "smtp",
            "relay": "smtp.example.com",
            "port": 587,
            "tls": "required-start-tls",
            "username": "mailer-user",
            "password": "secret-password-value"
        },
        "templates": {
            "directory": template_root(),
            "allowed_templates": ["welcome"]
        },
    }))?;
    smtp.validate(DeploymentEnvironment::Production)?;
    let debug = format!("{smtp:?}");
    assert!(!debug.contains("mailer-user"));
    assert!(!debug.contains("secret-password-value"));
    assert!(!debug.contains("smtp.example.com"));
    Ok(())
}
#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
fn trusted_template_open_rejects_symlink_leaf() -> Result<(), Box<dyn Error>> {
    use std::os::unix::fs::symlink;

    let root = std::env::temp_dir().join(format!("omnius-email-symlink-{}", Uuid::now_v7()));
    std::fs::create_dir_all(&root)?;
    std::fs::write(root.join("actual.txt"), "Hello {{ name }}!")?;
    std::fs::write(root.join("welcome.html"), "<p>Hello {{ name }}!</p>")?;
    symlink("actual.txt", root.join("welcome.txt"))?;
    let email_config = EmailConfig {
        provider: EmailProviderConfig::Capturing { capacity: 1 },
        templates: TemplateConfig {
            directory: root.clone(),
            allowed_templates: vec![TemplateName::try_from("welcome")?],
        },
        custom_headers: CustomHeaderPolicy::default(),
        limits: EmailLimits::default(),
    };
    let result = EmailService::build(email_config, DeploymentEnvironment::Test);
    std::fs::remove_dir_all(root)?;
    assert!(matches!(result, Err(EmailError::TemplateRegistry)));
    Ok(())
}

#[tokio::test]
async fn diagnostics_redact_request_job_preview_and_capture() -> Result<(), Box<dyn Error>> {
    let service = EmailService::build(
        config(EmailLimits::default(), 1)?,
        DeploymentEnvironment::Test,
    )?;
    let email_request = request("sensitive-idempotency-key", "sensitive-context-value")?;
    let debug = format!(
        "{email_request:?} {:?}",
        SendEmailJob::new(request("other-sensitive-key", "other-sensitive-value")?)
    );
    for sensitive in [
        "sensitive-idempotency-key",
        "sensitive-context-value",
        "recipient@example.com",
        "sender@example.com",
        "other-sensitive-key",
        "other-sensitive-value",
    ] {
        assert!(!debug.contains(sensitive));
    }

    let preview = service.templates().preview(
        &TemplateName::try_from("welcome")?,
        &TemplateContext::new(json!({ "name": "preview-secret" }))?,
    )?;
    assert!(!format!("{preview:?}").contains("preview-secret"));
    service.send(email_request).await?;
    let sink = capture(&service)?;
    let captured = sink.snapshot()?;
    let capture_debug = format!("{service:?} {sink:?} {captured:?}");
    for sensitive in [
        "sensitive-idempotency-key",
        "sensitive-context-value",
        "recipient@example.com",
        "sender@example.com",
    ] {
        assert!(!capture_debug.contains(sensitive));
    }
    Ok(())
}

#[test]
fn lint_and_preview_have_deterministic_inline_snapshots() -> Result<(), Box<dyn Error>> {
    let service = EmailService::build(
        config(EmailLimits::default(), 1)?,
        DeploymentEnvironment::Test,
    )?;
    let report = service.templates().lint();
    assert_eq!(report.len(), 1);
    let entry = &report.entries()[0];
    let lint_snapshot = format!("{}:{:?}", entry.template().as_str(), entry.variables());
    assert_eq!(lint_snapshot, "welcome:[\"name\"]");

    let preview = service.templates().preview(
        &TemplateName::try_from("welcome")?,
        &TemplateContext::new(json!({ "name": "Ada & Bob" }))?,
    )?;
    let preview_snapshot = format!("TEXT\n{}HTML\n{}", preview.text(), preview.html());
    assert_eq!(
        preview_snapshot,
        "TEXT\nHello Ada & Bob!\nHTML\n<p>Hello Ada &amp; Bob!</p>\n",
    );
    Ok(())
}

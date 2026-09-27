//! Development-only plaintext SMTP transport boundaries.

use std::{error::Error, io, path::PathBuf, sync::Arc, time::Duration};

use omnius_config::DeploymentEnvironment;
use omnius_email::{
    ClientMessageId, CustomHeaderPolicy, DeliveryFailureClass, DisplayName, EmailAddress,
    EmailConfig, EmailError, EmailLimits, EmailProviderConfig, EmailService, EmailSubject,
    MailSender as _, MailboxAddress, RecipientSet, SendEmailRequest, TemplateConfig,
    TemplateContext, TemplateName,
};
use omnius_jobs_core::IdempotencyKey;
use serde_json::json;
use tokio::{
    io::{AsyncBufReadExt as _, AsyncWriteExt as _, BufReader},
    net::TcpListener,
    sync::oneshot,
    task::JoinHandle,
};

fn template_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/templates")
}

fn config(port: u16, limits: EmailLimits) -> Result<EmailConfig, Box<dyn Error>> {
    Ok(EmailConfig {
        provider: serde_json::from_value(json!({
            "provider": "development-smtp",
            "relay": "127.0.0.1",
            "port": port
        }))?,
        templates: TemplateConfig {
            directory: template_root(),
            allowed_templates: vec![TemplateName::try_from("welcome")?],
        },
        custom_headers: CustomHeaderPolicy::default(),
        limits,
    })
}

fn request(idempotency: &str) -> Result<SendEmailRequest, Box<dyn Error>> {
    let sender = MailboxAddress::new(
        EmailAddress::try_from("sender@example.com")?,
        Some(DisplayName::try_from("Sender")?),
    );
    let recipient = MailboxAddress::new(
        EmailAddress::try_from("recipient@example.com")?,
        Some(DisplayName::try_from("Recipient")?),
    );
    Ok(SendEmailRequest::new(
        IdempotencyKey::try_from(idempotency)?,
        ClientMessageId::new_random(),
        sender,
        RecipientSet::new(vec![recipient], Vec::new(), Vec::new())?,
        EmailSubject::try_from("Development SMTP")?,
        TemplateName::try_from("welcome")?,
        TemplateContext::new(json!({ "name": "loopback" }))?,
    ))
}

async fn spawn_smtp(
    final_response: &'static str,
) -> io::Result<(u16, JoinHandle<io::Result<String>>)> {
    let listener = TcpListener::bind(("127.0.0.1", 0)).await?;
    let port = listener.local_addr()?.port();
    let task = tokio::spawn(async move {
        let (stream, _) = listener.accept().await?;
        let (reader, mut writer) = stream.into_split();
        writer.write_all(b"220 loopback ESMTP ready\r\n").await?;
        let mut lines = BufReader::new(reader).lines();
        let mut transcript = String::new();
        let mut reading_data = false;
        while let Some(line) = lines.next_line().await? {
            transcript.push_str(&line);
            transcript.push('\n');
            if reading_data {
                if line == "." {
                    writer.write_all(final_response.as_bytes()).await?;
                    break;
                }
                continue;
            }
            let command = line
                .split_ascii_whitespace()
                .next()
                .unwrap_or_default()
                .to_ascii_uppercase();
            match command.as_str() {
                "EHLO" | "HELO" => writer.write_all(b"250-loopback\r\n250 OK\r\n").await?,
                "MAIL" | "RCPT" | "RSET" | "NOOP" => writer.write_all(b"250 OK\r\n").await?,
                "DATA" => {
                    writer
                        .write_all(b"354 End data with <CR><LF>.<CR><LF>\r\n")
                        .await?;
                    reading_data = true;
                }
                "QUIT" => {
                    writer.write_all(b"221 Bye\r\n").await?;
                    break;
                }
                _ => writer.write_all(b"500 Unsupported\r\n").await?,
            }
        }
        Ok(transcript)
    });
    Ok((port, task))
}

async fn spawn_stalled_smtp() -> io::Result<(u16, oneshot::Receiver<()>, JoinHandle<io::Result<()>>)>
{
    let listener = TcpListener::bind(("127.0.0.1", 0)).await?;
    let port = listener.local_addr()?.port();
    let (accepted_tx, accepted_rx) = oneshot::channel();
    let task = tokio::spawn(async move {
        let (_stream, _) = listener.accept().await?;
        let _ = accepted_tx.send(());
        std::future::pending::<io::Result<()>>().await
    });
    Ok((port, accepted_rx, task))
}

#[tokio::test]
async fn development_smtp_delivers_plaintext_without_authentication() -> Result<(), Box<dyn Error>>
{
    let (port, smtp) = spawn_smtp("250 2.0.0 queued id=development-fixture\r\n").await?;
    let service = EmailService::build(
        config(port, EmailLimits::default())?,
        DeploymentEnvironment::Development,
    )?;

    let receipt = service.send(request("development-delivery")?).await?;
    let transcript = smtp.await??;
    service.shutdown().await;

    assert_eq!(
        receipt
            .provider_message_id()
            .map(omnius_email::ProviderMessageId::as_str),
        Some("development-fixture")
    );
    assert!(transcript.contains("MAIL FROM:"));
    assert!(transcript.contains("RCPT TO:"));
    assert!(transcript.contains("Hello loopback!"));
    assert!(!transcript.contains("AUTH"));
    assert!(!transcript.contains("STARTTLS"));
    Ok(())
}

#[test]
fn development_smtp_is_rejected_in_production() -> Result<(), Box<dyn Error>> {
    assert_eq!(
        config(1025, EmailLimits::default())?.validate(DeploymentEnvironment::Production),
        Err(EmailError::Config)
    );
    Ok(())
}

#[test]
fn development_smtp_is_admitted_in_test() -> Result<(), Box<dyn Error>> {
    config(1025, EmailLimits::default())?.validate(DeploymentEnvironment::Test)?;
    Ok(())
}

#[test]
fn secure_smtp_still_requires_tls_and_credentials() {
    let plaintext = serde_json::from_value::<EmailProviderConfig>(json!({
        "provider": "smtp",
        "relay": "smtp.example.com",
        "port": 25,
        "tls": "plaintext",
        "username": "mailer",
        "password": "secret-password"
    }));
    assert!(plaintext.is_err());

    let unauthenticated = serde_json::from_value::<EmailProviderConfig>(json!({
        "provider": "smtp",
        "relay": "smtp.example.com",
        "port": 587,
        "tls": "required-start-tls"
    }));
    assert!(unauthenticated.is_err());
}

#[test]
fn development_smtp_rejects_invalid_relay_and_port() -> Result<(), Box<dyn Error>> {
    let invalid_relays = [String::new(), "bad..relay".to_owned(), "a".repeat(254)];
    for relay in invalid_relays {
        let provider = serde_json::from_value::<EmailProviderConfig>(json!({
            "provider": "development-smtp",
            "relay": relay,
            "port": 1025
        }))?;
        let config = EmailConfig {
            provider,
            templates: TemplateConfig {
                directory: template_root(),
                allowed_templates: vec![TemplateName::try_from("welcome")?],
            },
            custom_headers: CustomHeaderPolicy::default(),
            limits: EmailLimits::default(),
        };
        assert_eq!(
            config.validate(DeploymentEnvironment::Development),
            Err(EmailError::Config)
        );
    }

    assert_eq!(
        config(0, EmailLimits::default())?.validate(DeploymentEnvironment::Development),
        Err(EmailError::Config)
    );
    assert!(
        serde_json::from_value::<EmailProviderConfig>(json!({
            "provider": "development-smtp",
            "relay": "relay.example",
            "port": 65_536
        }))
        .is_err()
    );
    Ok(())
}

#[tokio::test]
async fn development_smtp_discards_upstream_diagnostic_text() -> Result<(), Box<dyn Error>> {
    let sensitive = "upstream-secret-response";
    let provider: EmailProviderConfig = serde_json::from_value(json!({
        "provider": "development-smtp",
        "relay": "sensitive-relay.example",
        "port": 1025
    }))?;
    assert!(!format!("{provider:?}").contains("sensitive-relay.example"));
    let (port, smtp) = spawn_smtp("550 5.7.1 upstream-secret-response\r\n").await?;
    let service = EmailService::build(
        config(port, EmailLimits::default())?,
        DeploymentEnvironment::Development,
    )?;

    let Err(error) = service.send(request("development-redaction")?).await else {
        return Err("development SMTP failure was unexpectedly accepted".into());
    };
    let _ = smtp.await??;
    service.shutdown().await;

    assert_eq!(error, EmailError::Delivery(DeliveryFailureClass::Permanent));
    assert!(!format!("{error:?} {error}").contains(sensitive));
    Ok(())
}

#[tokio::test]
async fn development_smtp_send_obeys_operation_timeout() -> Result<(), Box<dyn Error>> {
    let (port, accepted, smtp) = spawn_stalled_smtp().await?;
    let limits = EmailLimits {
        operation_timeout: Duration::from_millis(100),
        ..EmailLimits::default()
    };
    let service = EmailService::build(config(port, limits)?, DeploymentEnvironment::Development)?;

    let send_request = request("development-timeout")?;
    let sending_service = service.clone();
    let send = tokio::spawn(async move { sending_service.send(send_request).await });
    accepted.await?;
    assert_eq!(send.await?, Err(EmailError::Timeout));
    smtp.abort();
    service.shutdown().await;
    Ok(())
}

#[tokio::test]
async fn development_smtp_send_is_cancelled_by_shutdown() -> Result<(), Box<dyn Error>> {
    let (port, accepted, smtp) = spawn_stalled_smtp().await?;
    let service = Arc::new(EmailService::build(
        config(port, EmailLimits::default())?,
        DeploymentEnvironment::Development,
    )?);
    let sending_service = Arc::clone(&service);
    let send_request = request("development-cancellation")?;
    let send = tokio::spawn(async move { sending_service.send(send_request).await });

    accepted.await?;
    service.shutdown().await;
    assert_eq!(send.await?, Err(EmailError::Cancelled));
    smtp.abort();
    Ok(())
}

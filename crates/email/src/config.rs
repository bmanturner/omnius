use std::{collections::HashSet, fmt, path::PathBuf, time::Duration};

use rsk_config::{DeploymentEnvironment, ExposeSecret as _, SecretString};
use serde::{Deserialize, Deserializer};

use crate::{CustomHeaderName, EmailError, TemplateName, value::BoundedVec};

const MAX_RELAY_BYTES: usize = 253;
const MAX_CREDENTIAL_BYTES: usize = 16 * 1024;
const MAX_TEMPLATE_ROOT_BYTES: usize = 4_096;
const MAX_TEMPLATES: usize = 128;
const MAX_OPERATION_TIMEOUT: Duration = Duration::from_secs(120);
const MAX_SMTP_TIMEOUT: Duration = Duration::from_secs(60);
const MAX_POOL_IDLE_TIMEOUT: Duration = Duration::from_secs(600);

/// Strict email configuration for one TLS-protected provider and trusted template registry.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EmailConfig {
    /// Provider-specific configuration.
    pub provider: EmailProviderConfig,
    /// Trusted paired template registry.
    pub templates: TemplateConfig,
    /// Deployment-controlled custom-header allowlist. Empty denies every custom header.
    #[serde(default)]
    pub custom_headers: CustomHeaderPolicy,
    /// Fixed adapter resource and operation bounds.
    #[serde(default)]
    pub limits: EmailLimits,
}

impl EmailConfig {
    /// Validates provider policy, template selection, and every adapter-owned resource bound.
    ///
    /// # Errors
    ///
    /// Returns [`EmailError::Config`] when any field is unsafe for the deployment environment.
    pub fn validate(&self, environment: DeploymentEnvironment) -> Result<(), EmailError> {
        self.limits.validate()?;
        self.templates.validate(&self.limits)?;
        self.custom_headers.validate()?;
        self.provider.validate(environment)
    }
}

impl fmt::Debug for EmailConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("EmailConfig")
            .field("provider", &self.provider.kind())
            .field("templates", &self.templates)
            .field("custom_headers", &self.custom_headers)
            .field("limits", &self.limits)
            .finish()
    }
}

/// Strict tagged email provider configuration.
#[derive(Deserialize)]
#[serde(tag = "provider", rename_all = "kebab-case", deny_unknown_fields)]
pub enum EmailProviderConfig {
    /// Bounded semantic capture fixture, admitted only in the test deployment environment.
    Capturing {
        /// Maximum whole messages retained in acceptance order.
        capacity: usize,
    },
    /// Remote SMTP submission over implicit TLS or required STARTTLS.
    Smtp {
        /// DNS relay name used for certificate verification.
        relay: String,
        /// Submission port paired with the selected TLS mode.
        port: u16,
        /// TLS is always implicit or required STARTTLS; plaintext is not representable.
        tls: SmtpTlsMode,
        /// Authentication username stored as a redacted secret.
        username: SecretString,
        /// Authentication password stored as a redacted secret.
        password: SecretString,
        /// Bounded connection-pool and SMTP command policy.
        #[serde(default)]
        pool: SmtpPoolConfig,
    },
}

impl EmailProviderConfig {
    /// Provider kind without configuration or secret values.
    #[must_use]
    pub const fn kind(&self) -> ProviderKind {
        match self {
            Self::Capturing { .. } => ProviderKind::Capturing,
            Self::Smtp { .. } => ProviderKind::Smtp,
        }
    }

    fn validate(&self, environment: DeploymentEnvironment) -> Result<(), EmailError> {
        match self {
            Self::Capturing { capacity }
                if environment == DeploymentEnvironment::Test && (1..=64).contains(capacity) =>
            {
                Ok(())
            }
            Self::Capturing { .. } => Err(EmailError::Config),
            Self::Smtp {
                relay,
                port,
                username,
                password,
                pool,
                ..
            } => {
                validate_relay(relay)?;
                if *port == 0 {
                    return Err(EmailError::Config);
                }
                validate_secret(username, 1)?;
                validate_secret(password, 8)?;
                pool.validate()
            }
        }
    }
}

impl fmt::Debug for EmailProviderConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("EmailProviderConfig")
            .field("kind", &self.kind())
            .finish_non_exhaustive()
    }
}

/// Fixed low-cardinality provider identity.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProviderKind {
    /// Test-only capturing provider.
    Capturing,
    /// TLS-protected SMTP provider.
    Smtp,
}

impl ProviderKind {
    pub(crate) const fn label(self) -> &'static str {
        match self {
            Self::Capturing => "capturing",
            Self::Smtp => "smtp",
        }
    }
}

/// TLS-safe remote SMTP connection mode. Plaintext and opportunistic TLS are not variants.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "kebab-case")]
pub enum SmtpTlsMode {
    /// TLS wraps the connection from its first byte, normally on port 465.
    Implicit,
    /// The relay must successfully upgrade with STARTTLS before authentication or mail transfer.
    RequiredStartTls,
}

/// Bounded SMTP connection pool and command timeouts.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(default, deny_unknown_fields)]
pub struct SmtpPoolConfig {
    /// Minimum idle connection count.
    pub min_idle: u32,
    /// Maximum pooled connection count.
    pub max_size: u32,
    /// Idle connection lifetime.
    #[serde(with = "humantime_serde")]
    pub idle_timeout: Duration,
    /// Per-command/connect timeout configured on lettre.
    #[serde(with = "humantime_serde")]
    pub command_timeout: Duration,
}

impl Default for SmtpPoolConfig {
    fn default() -> Self {
        Self {
            min_idle: 0,
            max_size: 8,
            idle_timeout: Duration::from_secs(60),
            command_timeout: Duration::from_secs(10),
        }
    }
}

impl SmtpPoolConfig {
    fn validate(self) -> Result<(), EmailError> {
        if self.max_size == 0
            || self.max_size > 32
            || self.min_idle > self.max_size
            || self.idle_timeout.is_zero()
            || self.idle_timeout > MAX_POOL_IDLE_TIMEOUT
            || self.command_timeout.is_zero()
            || self.command_timeout > MAX_SMTP_TIMEOUT
        {
            return Err(EmailError::Config);
        }
        Ok(())
    }
}

/// Deployment-controlled template directory and explicit, path-free allowlist.
#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TemplateConfig {
    /// Existing absolute directory opened once with no symlink following.
    pub directory: PathBuf,
    /// Explicit base names for required `<name>.txt` and `<name>.html` pairs.
    #[serde(deserialize_with = "deserialize_template_names")]
    pub allowed_templates: Vec<TemplateName>,
}
fn deserialize_template_names<'de, D>(deserializer: D) -> Result<Vec<TemplateName>, D::Error>
where
    D: Deserializer<'de>,
{
    BoundedVec::<TemplateName, MAX_TEMPLATES>::deserialize(deserializer).map(BoundedVec::into_inner)
}

impl TemplateConfig {
    pub(crate) fn validate(&self, limits: &EmailLimits) -> Result<(), EmailError> {
        if !self.directory.is_absolute()
            || self.directory.as_os_str().is_empty()
            || self.directory.as_os_str().len() > MAX_TEMPLATE_ROOT_BYTES
            || self.allowed_templates.is_empty()
            || self.allowed_templates.len() > MAX_TEMPLATES
            || self.allowed_templates.len() > usize::from(limits.max_templates)
        {
            return Err(EmailError::Config);
        }
        let mut unique = HashSet::with_capacity(self.allowed_templates.len());
        if self
            .allowed_templates
            .iter()
            .any(|name| !unique.insert(name.as_str()))
        {
            return Err(EmailError::Config);
        }
        Ok(())
    }
}

impl fmt::Debug for TemplateConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TemplateConfig")
            .field("directory", &"[TRUSTED TEMPLATE ROOT]")
            .field("template_count", &self.allowed_templates.len())
            .finish_non_exhaustive()
    }
}

/// Case-insensitive deployment allowlist for custom extension headers.
#[derive(Clone, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct CustomHeaderPolicy {
    /// Allowed `X-` header names. Empty is the secure default-deny policy.
    #[serde(deserialize_with = "deserialize_custom_header_names")]
    pub allowed: Vec<CustomHeaderName>,
}

impl CustomHeaderPolicy {
    fn validate(&self) -> Result<(), EmailError> {
        if self.allowed.len() > 64 {
            return Err(EmailError::Config);
        }
        for (index, name) in self.allowed.iter().enumerate() {
            if self.allowed[..index]
                .iter()
                .any(|prior| prior.as_str().eq_ignore_ascii_case(name.as_str()))
            {
                return Err(EmailError::Config);
            }
        }
        Ok(())
    }

    #[must_use]
    pub(crate) fn allows(&self, name: &CustomHeaderName) -> bool {
        self.allowed
            .iter()
            .any(|allowed| allowed.as_str().eq_ignore_ascii_case(name.as_str()))
    }
}

impl fmt::Debug for CustomHeaderPolicy {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CustomHeaderPolicy")
            .field("allowed_count", &self.allowed.len())
            .finish_non_exhaustive()
    }
}

fn deserialize_custom_header_names<'de, D>(
    deserializer: D,
) -> Result<Vec<CustomHeaderName>, D::Error>
where
    D: Deserializer<'de>,
{
    BoundedVec::<CustomHeaderName, 64>::deserialize(deserializer).map(BoundedVec::into_inner)
}

/// Configurable limits constrained by non-configurable absolute safety ceilings.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(default, deny_unknown_fields)]
pub struct EmailLimits {
    /// Maximum simultaneously admitted render-and-send attempts.
    pub max_in_flight: u16,
    /// Maximum aggregate To/Cc/Bcc recipients.
    pub max_recipients: u16,
    /// Maximum UTF-8 subject bytes.
    pub max_subject_bytes: u16,
    /// Maximum extension-header count.
    pub max_headers: u16,
    /// Maximum aggregate extension-header name/value bytes.
    pub max_header_bytes: u32,
    /// Maximum attachment count.
    pub max_attachments: u16,
    /// Maximum bytes in one attachment.
    pub max_attachment_bytes: u32,
    /// Maximum aggregate attachment bytes.
    pub max_attachment_total_bytes: u32,
    /// Maximum serialized template-context bytes.
    pub max_context_bytes: u32,
    /// Maximum bytes in one trusted template source file.
    pub max_template_source_bytes: u32,
    /// Maximum registered text/HTML pairs.
    pub max_templates: u16,
    /// Maximum rendered plain-text bytes.
    pub max_rendered_text_bytes: u32,
    /// Maximum rendered HTML bytes.
    pub max_rendered_html_bytes: u32,
    /// `MiniJinja` instruction budget for each text or HTML render.
    pub render_fuel: u64,
    /// Total send or provider-health operation deadline.
    #[serde(with = "humantime_serde")]
    pub operation_timeout: Duration,
}

impl Default for EmailLimits {
    fn default() -> Self {
        Self {
            max_in_flight: 16,
            max_recipients: 20,
            max_subject_bytes: 255,
            max_headers: 16,
            max_header_bytes: 8 * 1024,
            max_attachments: 8,
            max_attachment_bytes: 256 * 1024,
            max_attachment_total_bytes: 512 * 1024,
            max_context_bytes: 64 * 1024,
            max_template_source_bytes: 128 * 1024,
            max_templates: 64,
            max_rendered_text_bytes: 256 * 1024,
            max_rendered_html_bytes: 512 * 1024,
            render_fuel: 100_000,
            operation_timeout: Duration::from_secs(30),
        }
    }
}

impl EmailLimits {
    pub(crate) fn validate(self) -> Result<(), EmailError> {
        if self.max_in_flight == 0
            || self.max_in_flight > 256
            || self.max_recipients == 0
            || self.max_recipients > 100
            || self.max_subject_bytes == 0
            || self.max_subject_bytes > 998
            || self.max_headers > 64
            || self.max_header_bytes > 32 * 1024
            || self.max_attachments > 16
            || self.max_attachment_bytes == 0
            || self.max_attachment_bytes > 512 * 1024
            || self.max_attachment_total_bytes == 0
            || self.max_attachment_total_bytes > 512 * 1024
            || self.max_attachment_bytes > self.max_attachment_total_bytes
            || self.max_context_bytes == 0
            || self.max_context_bytes > 128 * 1024
            || self.max_template_source_bytes == 0
            || self.max_template_source_bytes > 512 * 1024
            || self.max_templates == 0
            || usize::from(self.max_templates) > MAX_TEMPLATES
            || self.max_rendered_text_bytes == 0
            || self.max_rendered_text_bytes > 1024 * 1024
            || self.max_rendered_html_bytes == 0
            || self.max_rendered_html_bytes > 1024 * 1024
            || self.render_fuel == 0
            || self.render_fuel > 10_000_000
            || self.operation_timeout.is_zero()
            || self.operation_timeout > MAX_OPERATION_TIMEOUT
        {
            return Err(EmailError::Config);
        }
        Ok(())
    }
}

fn validate_relay(value: &str) -> Result<(), EmailError> {
    if value.is_empty()
        || value.len() > MAX_RELAY_BYTES
        || !value.is_ascii()
        || value.starts_with('.')
        || value.ends_with('.')
        || value.contains("..")
    {
        return Err(EmailError::Config);
    }
    for label in value.split('.') {
        if label.is_empty()
            || label.len() > 63
            || !label
                .as_bytes()
                .first()
                .is_some_and(u8::is_ascii_alphanumeric)
            || !label
                .as_bytes()
                .last()
                .is_some_and(u8::is_ascii_alphanumeric)
            || !label
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        {
            return Err(EmailError::Config);
        }
    }
    Ok(())
}

fn validate_secret(value: &SecretString, minimum: usize) -> Result<(), EmailError> {
    let exposed = value.expose_secret();
    if exposed.len() < minimum
        || exposed.len() > MAX_CREDENTIAL_BYTES
        || exposed.chars().any(char::is_control)
    {
        return Err(EmailError::Config);
    }
    Ok(())
}

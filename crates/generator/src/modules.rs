use std::{
    collections::{BTreeMap, BTreeSet},
    error::Error,
    fmt,
};

use serde::{Deserialize, Serialize};

use crate::state::validate_relative_path;

const MODULE_CATALOG_SCHEMA_VERSION: u32 = 1;
const EXTENSION_SCHEMA_VERSION: &str = "1.0.0";
const BASE_CATALOG_SOURCE: &str = include_str!("../../../specs/machine/module-catalog.yaml");
const WEB_CATALOG_SOURCE: &str =
    include_str!("../../../specs/machine/extensions/web-application-suite/module-catalog.yaml");
const AI_CATALOG_SOURCE: &str =
    include_str!("../../../specs/machine/extensions/llm-mcp-suite/module-catalog.yaml");
const WORKSPACE_MANIFEST_SOURCE: &str = include_str!("../../../Cargo.toml");

/// Authoritative module catalog used by pure selection planning.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ModuleCatalog {
    /// Catalog serialization version.
    pub schema_version: u32,
    /// Version shared by module descriptors.
    pub bundle_version: String,
    /// Module descriptors in authoritative catalog order.
    pub modules: Vec<ModuleDefinition>,
    /// Closed runtime dependency descriptors referenced by module IDs.
    #[serde(default)]
    pub runtime_dependencies: Vec<RuntimeDependencyDescriptor>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ModuleCatalogExtension {
    schema_version: String,
    extension_version: String,
    base_bundle_version: String,
    #[serde(default)]
    web_extension_version: Option<String>,
    #[serde(default)]
    runtime_dependencies: Vec<RuntimeDependencyDescriptor>,
    modules: Vec<ModuleDefinition>,
}

/// Generator-relevant module descriptor plus validated catalog metadata.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ModuleDefinition {
    /// Stable module identifier.
    pub id: String,
    /// Human-readable title.
    pub title: String,
    /// Module version.
    pub version: String,
    /// Owning kit component.
    pub owner: String,
    /// Normative specification identifier.
    pub spec: String,
    /// Module kind.
    pub kind: String,
    /// Direct module prerequisites.
    pub requires: Vec<String>,
    /// Explicitly incompatible module identifiers.
    pub conflicts_with: Vec<String>,
    /// Mutually exclusive provider capability.
    #[serde(default)]
    pub provider_slot: Option<String>,
    /// Runtime criticality classification.
    pub criticality: String,
    /// Whether runtime configuration may disable the compiled module.
    pub runtime_toggle: bool,
    /// Closed runtime dependencies required by this module.
    #[serde(default)]
    pub runtime_dependencies: Vec<RuntimeDependencyId>,
    /// Primary upstream crates.
    pub primary_crates: Vec<String>,
    /// Compile-time application composition owned by the generator.
    pub composition: ModuleComposition,
    /// Acceptance criterion identifiers.
    pub acceptance: Vec<String>,
    /// Durable resources that removal must preserve.
    pub persistence: Vec<String>,
    /// Configuration contract.
    pub configuration: ModuleConfiguration,
    /// Registered HTTP routes.
    pub routes: Vec<String>,
    /// Registered background tasks.
    pub background_tasks: Vec<String>,
    /// Registered health checks.
    pub health_checks: Vec<String>,
    /// Metrics prefix.
    pub metrics_prefix: String,
    /// Test fixtures.
    pub test_fixtures: Vec<String>,
    /// Generator-owned outputs.
    pub generator_ownership: GeneratorOwnership,
    /// Human-readable safe removal behavior.
    pub removal_behavior: String,
}
/// Runtime contract family that owns one or more application requirements.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum ApplicationRequirementProviderFamily {
    /// Administrative authority and operation handling.
    Admin,
    /// Authentication, session, identity-provider, and second-factor runtimes.
    Auth,
    /// Billing provider integration.
    Billing,
    /// Feature-flag evaluation and exposure recording.
    FeatureFlags,
    /// GraphQL schema and request context.
    Graphql,
    /// gRPC services, authentication, and method policies.
    Grpc,
    /// Durable inbox consumers.
    Inbox,
    /// Background job handlers.
    Jobs,
    /// LLM authorization, audit, media, and evaluation ports.
    Llm,
    /// MCP Apps protocol ports.
    McpApps,
    /// MCP bearer authentication.
    McpAuth,
    /// MCP capability registry.
    McpCore,
    /// Enterprise MCP authorization ports.
    McpEnterprise,
    /// MCP subscription persistence, policy, runtime, and delivery.
    McpSubscriptions,
    /// Durable MCP task protection, cancellation, and execution.
    McpTasks,
    /// Transactional outbox publishing.
    Outbox,
    /// Privacy inventory, authorization, lifecycle, consent, and moderation.
    Privacy,
    /// Realtime authorization, identity revalidation, and event handling.
    Realtime,
    /// Scheduled envelope construction.
    Scheduler,
    /// Search schema, reauthorization, and projection.
    Search,
    /// Upload workflow and authorization.
    Uploads,
    /// Inbound webhook adapters and handlers.
    WebhooksInbound,
    /// Svix webhook replay admission.
    WebhooksSvix,
}

impl ApplicationRequirementProviderFamily {
    /// Every provider family accepted by the application contract boundary.
    pub const ALL: &[Self] = &[
        Self::Admin,
        Self::Auth,
        Self::Billing,
        Self::FeatureFlags,
        Self::Graphql,
        Self::Grpc,
        Self::Inbox,
        Self::Jobs,
        Self::Llm,
        Self::McpApps,
        Self::McpAuth,
        Self::McpCore,
        Self::McpEnterprise,
        Self::McpSubscriptions,
        Self::McpTasks,
        Self::Outbox,
        Self::Privacy,
        Self::Realtime,
        Self::Scheduler,
        Self::Search,
        Self::Uploads,
        Self::WebhooksInbound,
        Self::WebhooksSvix,
    ];
}

macro_rules! application_requirements {
    ($($variant:ident => ($id:literal, $provider:ident),)+) => {
        /// Closed application-owned requirements accepted by bundled module catalogs.
        #[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
        pub enum ApplicationRequirement {
            $(
                #[doc = concat!("Application requirement `", $id, "`.")]
                #[serde(rename = $id)]
                $variant,
            )+
        }

        impl ApplicationRequirement {
            /// Every application requirement accepted by the catalog parser and generated runtime.
            pub const ALL: &[Self] = &[$(Self::$variant,)+];

            /// Returns the canonical diagnostic identifier.
            pub const fn as_str(&self) -> &'static str {
                match self {
                    $(Self::$variant => $id,)+
                }
            }

            /// Returns the one runtime contract family that must provide this requirement.
            pub const fn provider_family(&self) -> ApplicationRequirementProviderFamily {
                match self {
                    $(Self::$variant => ApplicationRequirementProviderFamily::$provider,)+
                }
            }

            pub(crate) const fn rust_variant(&self) -> &'static str {
                match self {
                    $(Self::$variant => stringify!($variant),)+
                }
            }
        }

        impl std::str::FromStr for ApplicationRequirement {
            type Err = CatalogError;

            fn from_str(value: &str) -> Result<Self, Self::Err> {
                match value {
                    $($id => Ok(Self::$variant),)+
                    _ => Err(CatalogError::new(format!(
                        "unknown application requirement `{value}`"
                    ))),
                }
            }
        }
        impl<'de> Deserialize<'de> for ApplicationRequirement {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: serde::Deserializer<'de>,
            {
                struct RequirementVisitor;

                impl<'visit> serde::de::Visitor<'visit> for RequirementVisitor {
                    type Value = ApplicationRequirement;

                    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                        formatter.write_str("a canonical application requirement ID")
                    }

                    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
                    where
                        E: serde::de::Error,
                    {
                        value.parse().map_err(E::custom)
                    }
                }

                deserializer.deserialize_str(RequirementVisitor)
            }
        }



        impl fmt::Display for ApplicationRequirement {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str(self.as_str())
            }
        }
    };
}

application_requirements! {
    AdminAuthorityResolver => ("admin.authority-resolver", Admin),
    AdminOperationHandler => ("admin.operation-handler", Admin),
    AuthAuthenticatedRuntime => ("auth.authenticated-runtime", Auth),
    AuthRedisSessionRuntime => ("auth.redis-session-runtime", Auth),
    AuthOidcRuntime => ("auth-oidc.runtime", Auth),
    AuthOauthRuntime => ("auth.oauth-runtime", Auth),
    AuthWebAuthnRuntime => ("auth-webauthn.runtime", Auth),
    AuthTotpRuntime => ("auth-totp.runtime", Auth),
    BillingProvider => ("billing.provider", Billing),
    FeatureFlagsExposureRecorder => ("feature-flags.exposure-recorder", FeatureFlags),
    FeatureFlagsProvider => ("feature-flags.provider", FeatureFlags),
    GraphqlRequestDataInjector => ("graphql.request-data-injector", Graphql),
    GraphqlSchema => ("graphql.schema", Graphql),
    GrpcApplicationService => ("grpc.application-service", Grpc),
    GrpcAuthenticator => ("grpc.authenticator", Grpc),
    GrpcMethodPolicies => ("grpc.method-policies", Grpc),
    InboxConsumers => ("inbox.consumers", Inbox),
    JobsHandlers => ("jobs.handlers", Jobs),
    LlmEvaluationRepository => ("llm.evaluation-repository", Llm),
    LlmMediaAuthorization => ("llm.media-authorization", Llm),
    LlmMediaScanner => ("llm.media-scanner", Llm),
    LlmToolAudit => ("llm.tool-audit", Llm),
    LlmToolAuthorization => ("llm.tool-authorization", Llm),
    McpAppsPorts => ("mcp.apps-ports", McpApps),
    McpBearerAuthenticator => ("mcp.bearer-authenticator", McpAuth),
    McpCancellationRuntime => ("mcp.cancellation-runtime", McpTasks),
    McpCapabilityExecutor => ("mcp.capability-executor", McpTasks),
    McpCapabilityRegistry => ("mcp.capability-registry", McpCore),
    McpEnterprisePorts => ("mcp.enterprise-ports", McpEnterprise),
    McpSubscriptionAuthorizer => ("mcp.subscription-authorizer", McpSubscriptions),
    McpSubscriptionDelivery => ("mcp.subscription-delivery", McpSubscriptions),
    McpSubscriptionRepository => ("mcp.subscription-repository", McpSubscriptions),
    McpSubscriptionRuntime => ("mcp.subscription-runtime", McpSubscriptions),
    McpTaskPayloadProtector => ("mcp.task-payload-protector", McpTasks),
    OutboxPublisher => ("outbox.publisher", Outbox),
    PrivacyAuthorizer => ("privacy.authorizer", Privacy),
    PrivacyConsentPolicy => ("privacy.consent-policy", Privacy),
    PrivacyInventoryAdapters => ("privacy.inventory-adapters", Privacy),
    PrivacyInventoryManifest => ("privacy.inventory-manifest", Privacy),
    PrivacyLifecycleHandler => ("privacy.lifecycle-handler", Privacy),
    PrivacyModerationPolicy => ("privacy.moderation-policy", Privacy),
    RealtimeEventHandler => ("realtime.event-handler", Realtime),
    RealtimeFanoutAuthorizer => ("realtime.fanout-authorizer", Realtime),
    RealtimeIdentityRevalidator => ("realtime.identity-revalidator", Realtime),
    SchedulerEnvelopeFactory => ("scheduler.envelope-factory", Scheduler),
    SearchIndexSchema => ("search.index-schema", Search),
    SearchProjectionResolver => ("search.projection-resolver", Search),
    SearchReauthorizer => ("search.reauthorizer", Search),
    UploadsAuthorization => ("uploads.authorization", Uploads),
    UploadsWorkflow => ("uploads.workflow", Uploads),
    WebhooksInboundHandlers => ("webhooks-inbound.handlers", WebhooksInbound),
    WebhooksInboundProviderAdapters => ("webhooks-inbound.provider-adapters", WebhooksInbound),
    WebhooksSvixReplayAdmission => ("webhooks-svix.replay-admission", WebhooksSvix),
}

/// Static composition metadata for one selectable module.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ModuleComposition {
    /// Workspace crates that the generated composition layer imports.
    pub crates: Vec<CompositionCrate>,
    /// Whether generated code calls a built-in static registrar.
    pub registrar: bool,
    /// Application-owned contributions required before assembly can succeed.
    pub application_requirements: Vec<ApplicationRequirement>,
}

/// One exact workspace dependency used by a generated registrar.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CompositionCrate {
    /// Dependency key from the root workspace dependency table.
    pub dependency: String,
    /// Additive Cargo features enabled for this dependency.
    pub features: Vec<String>,
}

/// Configuration metadata retained from the catalog.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ModuleConfiguration {
    /// Primary configuration namespace.
    pub prefix: String,
    /// Optional external schema path for application-owned configuration.
    pub schema: Option<String>,
    /// Secret-bearing configuration fields.
    pub secret_fields: Vec<String>,
    /// Closed field schema for framework-owned generated configuration.
    #[serde(default)]
    pub fields: Vec<ConfigurationField>,
}

/// One typed framework-owned configuration field.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ConfigurationField {
    /// Fully qualified dotted configuration path.
    pub path: String,
    /// TOML value type accepted by the selected runtime schema.
    #[serde(rename = "type")]
    pub value_type: ConfigurationValueType,
    /// Whether deserialization requires this field.
    pub required: bool,
    /// Safe value written to `config/reference.toml`.
    #[serde(default)]
    pub reference_default: Option<ConfigurationValue>,
    /// Exact hierarchical environment key required at runtime.
    #[serde(default)]
    pub environment: Option<String>,
}

/// Supported generated TOML scalar and array types.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "kebab-case")]
pub enum ConfigurationValueType {
    /// UTF-8 TOML string.
    String,
    /// Signed TOML integer.
    Integer,
    /// TOML boolean.
    Boolean,
    /// TOML array containing only strings.
    StringArray,
    /// TOML array containing only integers.
    IntegerArray,
}

/// A typed, secret-free value eligible for the checked-in reference overlay.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(untagged)]
pub enum ConfigurationValue {
    /// UTF-8 TOML string.
    String(String),
    /// Signed TOML integer.
    Integer(i64),
    /// TOML boolean.
    Boolean(bool),
    /// TOML array containing only strings.
    StringArray(Vec<String>),
    /// TOML array containing only integers.
    IntegerArray(Vec<i64>),
}

/// Paths and regions the catalog permits the generator to change.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GeneratorOwnership {
    /// Files replaceable only from a matching kit baseline.
    pub kit_owned: Vec<String>,
    /// `path#region-id` managed region references.
    pub managed_regions: Vec<String>,
    /// Files regenerated entirely from selected modules.
    pub derived: Vec<String>,
}

/// Closed identifiers for infrastructure required by generated runtimes.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum RuntimeDependencyId {
    /// Repository-owned pinned PostgreSQL development topology.
    Postgresql,
    /// Redis or Valkey endpoint supplied by the application operator.
    RedisOrValkey,
    /// `OpenID Connect` provider endpoints and credentials.
    OidcProvider,
    /// NATS `JetStream` endpoint and credentials.
    NatsJetstream,
    /// Object storage endpoint and credentials.
    ObjectStore,
    /// SMTP or hosted email provider endpoint and credentials.
    SmtpOrEmailProvider,
    /// Svix webhook provider endpoint and credential.
    Svix,
    /// Feature flag provider endpoint and credential.
    FlagProvider,
    /// Meilisearch endpoint and credential.
    Meilisearch,
    /// Application-selected LLM provider endpoints and credentials.
    ConfiguredLlmProviderApis,
    /// AWS Bedrock Runtime credentials.
    AwsBedrockRuntime,
    /// Google Vertex AI endpoint and credentials.
    GoogleVertexAi,
}

/// One closed runtime dependency descriptor.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
pub enum RuntimeDependencyDescriptor {
    /// Repository-owned, pinned, health-checked local development service.
    Compose {
        /// Closed dependency identifier.
        id: RuntimeDependencyId,
        /// Stable Compose service name.
        service: String,
        /// Digest-pinned development image.
        image: String,
        /// Named volume retained after module removal.
        volume: String,
        /// Absolute container path where the named volume is mounted.
        volume_mount: String,
        /// Health contract gating application startup. Catalog loading pays one
        /// heap allocation so this payload does not inflate every enum value.
        healthcheck: Box<ComposeHealthcheck>,
        /// Environment supplied to the infrastructure service.
        #[serde(default)]
        service_environment: Vec<ComposeEnvironmentBinding>,
        /// Environment supplied to generated application containers.
        #[serde(default)]
        application_environment: Vec<ComposeEnvironmentBinding>,
        /// Optional one-shot migration ownership.
        #[serde(default)]
        migration: Option<ComposeMigration>,
    },
    /// Operator-supplied dependency with no pretend local container.
    External {
        /// Closed dependency identifier.
        id: RuntimeDependencyId,
        /// Exact required endpoint and credential environment names.
        bindings: Vec<ExternalEnvironmentBinding>,
    },
}

/// Health check for a repository-owned Compose dependency.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ComposeHealthcheck {
    /// Exact Compose health command vector.
    pub test: Vec<String>,
    /// Probe interval.
    pub interval: String,
    /// Individual probe timeout.
    pub timeout: String,
    /// Failed probes allowed before unhealthy.
    pub retries: u32,
}

/// One literal binding used only by a repository-owned development topology.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ComposeEnvironmentBinding {
    /// Exact environment name.
    pub name: String,
    /// Exact development value.
    pub value: String,
    /// Whether the value is credential material.
    #[serde(default)]
    pub secret: bool,
    /// Explicit acknowledgement that this value is development-only.
    #[serde(default)]
    pub development_only: bool,
}

/// One required operator-supplied environment binding.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ExternalEnvironmentBinding {
    /// Exact environment name.
    pub name: String,
    /// Human-readable fail-closed Compose interpolation diagnostic.
    pub message: String,
    /// Whether the binding carries credentials rather than an endpoint.
    pub credential: bool,
}

/// One-shot Compose migration owner.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ComposeMigration {
    /// Module that supplies the generated migration command.
    pub required_module: String,
    /// Arguments passed to the generated service entrypoint.
    pub command: Vec<String>,
}

impl RuntimeDependencyDescriptor {
    /// Returns the closed dependency identifier.
    #[must_use]
    pub const fn id(&self) -> RuntimeDependencyId {
        match self {
            Self::Compose { id, .. } | Self::External { id, .. } => *id,
        }
    }
}

impl RuntimeDependencyId {
    /// Returns the canonical kebab-case identifier.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Postgresql => "postgresql",
            Self::RedisOrValkey => "redis-or-valkey",
            Self::OidcProvider => "oidc-provider",
            Self::NatsJetstream => "nats-jetstream",
            Self::ObjectStore => "object-store",
            Self::SmtpOrEmailProvider => "smtp-or-email-provider",
            Self::Svix => "svix",
            Self::FlagProvider => "flag-provider",
            Self::Meilisearch => "meilisearch",
            Self::ConfiguredLlmProviderApis => "configured-llm-provider-apis",
            Self::AwsBedrockRuntime => "aws-bedrock-runtime",
            Self::GoogleVertexAi => "google-vertex-ai",
        }
    }
}

/// Deterministic module selection or catalog validation failure.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CatalogError {
    message: String,
}

impl CatalogError {
    fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

impl fmt::Display for CatalogError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl Error for CatalogError {}

impl ModuleCatalog {
    /// Loads the base, web, and AI extension module catalogs bundled into the generator binary.
    ///
    /// # Errors
    ///
    /// Returns [`CatalogError`] if any checked-in catalog is not strict,
    /// version-compatible, collision-free, and internally consistent.
    pub fn bundled() -> Result<Self, CatalogError> {
        let mut catalog = Self::from_yaml(BASE_CATALOG_SOURCE)?;
        let web_extension_version = catalog.append_extension("web", WEB_CATALOG_SOURCE, None)?;
        catalog.append_extension(
            "AI",
            AI_CATALOG_SOURCE,
            Some(web_extension_version.as_str()),
        )?;
        catalog.validate()?;
        Ok(catalog)
    }

    fn append_extension(
        &mut self,
        label: &str,
        source: &str,
        required_web_extension_version: Option<&str>,
    ) -> Result<String, CatalogError> {
        let mut extension: ModuleCatalogExtension =
            decode_catalog(&format!("{label} module catalog extension"), source)?;
        if extension.schema_version != EXTENSION_SCHEMA_VERSION {
            return Err(CatalogError::new(format!(
                "unsupported {label} module catalog schema version {}; expected {EXTENSION_SCHEMA_VERSION}",
                extension.schema_version
            )));
        }
        if extension.extension_version.is_empty() {
            return Err(CatalogError::new(format!(
                "{label} module catalog extension_version is empty"
            )));
        }
        if extension.base_bundle_version != self.bundle_version {
            return Err(CatalogError::new(format!(
                "{label} module catalog requires base bundle {}; bundled base is {}",
                extension.base_bundle_version, self.bundle_version
            )));
        }
        if let Some(required_version) = required_web_extension_version {
            let actual_version = extension.web_extension_version.as_deref().ok_or_else(|| {
                CatalogError::new(format!(
                    "{label} module catalog must declare web_extension_version"
                ))
            })?;
            if actual_version != required_version {
                return Err(CatalogError::new(format!(
                    "{label} module catalog requires web extension {actual_version}; bundled web extension is {required_version}"
                )));
            }
        }
        for descriptor in extension.runtime_dependencies {
            if let Some(existing) = self
                .runtime_dependencies
                .iter()
                .find(|existing| existing.id() == descriptor.id())
            {
                if existing != &descriptor {
                    return Err(CatalogError::new(format!(
                        "{label} module catalog defines a conflicting inherited runtime dependency `{}`",
                        descriptor.id().as_str()
                    )));
                }
                continue;
            }
            self.runtime_dependencies.push(descriptor);
        }
        extension
            .modules
            .sort_by(|left, right| left.id.cmp(&right.id));
        self.modules.extend(extension.modules);
        Ok(extension.extension_version)
    }

    /// Decodes and validates a strict base module catalog.
    ///
    /// # Errors
    ///
    /// Returns [`CatalogError`] for YAML, schema, dependency, ownership, or
    /// uniqueness violations.
    pub fn from_yaml(source: &str) -> Result<Self, CatalogError> {
        validate_base_wire_shape(source)?;
        let catalog: Self = decode_catalog("base module catalog", source)?;
        catalog.validate()?;
        Ok(catalog)
    }

    /// Decodes and validates a deterministic base-plus-extension overlay.
    ///
    /// Unlike [`Self::from_yaml`], this accepts extension entries that omit
    /// base-only wire fields whose semantic default is `None`. The resulting
    /// catalog still passes the complete dependency, collision, and ownership
    /// validation.
    ///
    /// # Errors
    ///
    /// Returns [`CatalogError`] for YAML, dependency, ownership, or uniqueness
    /// violations.
    pub fn from_overlay_yaml(source: &str) -> Result<Self, CatalogError> {
        let catalog: Self = decode_catalog("module catalog overlay", source)?;
        catalog.validate()?;
        Ok(catalog)
    }

    /// Validates catalog-wide constraints without filesystem access.
    ///
    /// # Errors
    ///
    /// Returns [`CatalogError`] for the first deterministic violation.
    pub fn validate(&self) -> Result<(), CatalogError> {
        if self.schema_version != MODULE_CATALOG_SCHEMA_VERSION {
            return Err(CatalogError::new(format!(
                "unsupported module catalog schema version {}; expected {}",
                self.schema_version, MODULE_CATALOG_SCHEMA_VERSION
            )));
        }
        if self.bundle_version.is_empty() {
            return Err(CatalogError::new("module catalog bundle_version is empty"));
        }
        let dependency_registry = validate_runtime_dependency_registry(&self.runtime_dependencies)?;
        let workspace_dependencies = workspace_dependency_keys()?;
        let mut ids = BTreeSet::new();
        for module in &self.modules {
            validate_id(&module.id)?;
            if !ids.insert(module.id.as_str()) {
                return Err(CatalogError::new(format!(
                    "duplicate module id `{}`",
                    module.id
                )));
            }
            if module.version.is_empty() {
                return Err(CatalogError::new(format!(
                    "module `{}` has an empty version",
                    module.id
                )));
            }
            validate_unique_list(&module.requires, &module.id, "requires")?;
            validate_unique_list(&module.conflicts_with, &module.id, "conflicts_with")?;
            if module.requires.contains(&module.id) {
                return Err(CatalogError::new(format!(
                    "module `{}` requires itself",
                    module.id
                )));
            }
            if module.conflicts_with.contains(&module.id) {
                return Err(CatalogError::new(format!(
                    "module `{}` conflicts with itself",
                    module.id
                )));
            }
            if module.provider_slot.as_deref().is_some_and(str::is_empty) {
                return Err(CatalogError::new(format!(
                    "module `{}` has an empty provider slot",
                    module.id
                )));
            }
            validate_ownership(module)?;
            validate_composition(module, &workspace_dependencies)?;
            validate_configuration(module)?;
            let mut runtime_dependencies = BTreeSet::new();
            for dependency in &module.runtime_dependencies {
                if !runtime_dependencies.insert(*dependency) {
                    return Err(CatalogError::new(format!(
                        "module `{}` has duplicate runtime dependency `{}`",
                        module.id,
                        dependency.as_str()
                    )));
                }
                if !dependency_registry.contains_key(dependency) {
                    return Err(CatalogError::new(format!(
                        "module `{}` references unknown runtime dependency `{}`",
                        module.id,
                        dependency.as_str()
                    )));
                }
            }
        }
        for module in &self.modules {
            for required in &module.requires {
                if !ids.contains(required.as_str()) {
                    return Err(CatalogError::new(format!(
                        "module `{}` requires unknown module `{required}`",
                        module.id
                    )));
                }
            }
            for conflict in &module.conflicts_with {
                if !ids.contains(conflict.as_str()) {
                    return Err(CatalogError::new(format!(
                        "module `{}` conflicts with unknown module `{conflict}`",
                        module.id
                    )));
                }
            }
        }
        validate_migration_ownership(self, &dependency_registry)?;
        for module in &self.modules {
            let mut visiting = BTreeSet::new();
            self.collect_dependencies(&module.id, &mut visiting, &mut BTreeSet::new())?;
        }
        Ok(())
    }

    /// Returns one module descriptor by stable ID.
    #[must_use]
    pub fn module(&self, id: &str) -> Option<&ModuleDefinition> {
        self.modules.iter().find(|module| module.id == id)
    }

    /// Returns one closed runtime dependency descriptor by ID.
    #[must_use]
    pub fn runtime_dependency(
        &self,
        id: RuntimeDependencyId,
    ) -> Option<&RuntimeDependencyDescriptor> {
        self.runtime_dependencies
            .iter()
            .find(|descriptor| descriptor.id() == id)
    }

    /// Returns selected runtime dependencies in deterministic registry order.
    ///
    /// # Errors
    ///
    /// Returns [`CatalogError`] if the selection or registry is invalid.
    pub fn selected_runtime_dependencies(
        &self,
        selected: &BTreeSet<String>,
    ) -> Result<Vec<&RuntimeDependencyDescriptor>, CatalogError> {
        self.validate_selection(selected)?;
        let required = selected.iter().try_fold(
            BTreeSet::new(),
            |mut dependencies, id| -> Result<_, CatalogError> {
                let module = self
                    .module(id)
                    .ok_or_else(|| CatalogError::new(format!("unknown module `{id}`")))?;
                dependencies.extend(module.runtime_dependencies.iter().copied());
                Ok(dependencies)
            },
        )?;
        Ok(self
            .runtime_dependencies
            .iter()
            .filter(|descriptor| required.contains(&descriptor.id()))
            .collect())
    }

    /// Resolves a requested module and all transitive prerequisites, then checks
    /// explicit conflicts and provider-slot exclusivity for the full selection.
    ///
    /// # Errors
    ///
    /// Returns [`CatalogError`] for an unknown module or incompatible selection.
    pub fn resolve_add(
        &self,
        selected: &BTreeSet<String>,
        requested: &str,
    ) -> Result<BTreeSet<String>, CatalogError> {
        if self.module(requested).is_none() {
            return Err(CatalogError::new(format!(
                "unknown module `{requested}`; select an id from the module catalog"
            )));
        }
        let mut resolved = selected.clone();
        self.collect_dependencies(requested, &mut BTreeSet::new(), &mut resolved)?;
        resolved.insert(requested.to_owned());
        self.validate_selection(&resolved)?;
        Ok(resolved)
    }

    /// Removes one selected module only when no remaining module depends on it.
    /// Repeating removal of an absent module is an idempotent no-op.
    ///
    /// # Errors
    ///
    /// Returns [`CatalogError`] for an unknown module or reverse dependencies.
    pub fn resolve_remove(
        &self,
        selected: &BTreeSet<String>,
        requested: &str,
    ) -> Result<BTreeSet<String>, CatalogError> {
        if self.module(requested).is_none() {
            return Err(CatalogError::new(format!(
                "unknown module `{requested}`; select an id from the module catalog"
            )));
        }
        if !selected.contains(requested) {
            return Ok(selected.clone());
        }
        let mut blockers = Vec::new();
        for id in selected {
            if id != requested && self.depends_on(id, requested, &mut BTreeSet::new())? {
                blockers.push(id.as_str());
            }
        }
        if !blockers.is_empty() {
            return Err(CatalogError::new(format!(
                "cannot remove module `{requested}`; selected dependents: {}",
                blockers.join(", ")
            )));
        }
        let mut resolved = selected.clone();
        resolved.remove(requested);
        self.validate_selection(&resolved)?;
        Ok(resolved)
    }
    /// Returns selected modules in prerequisite-first catalog order.
    ///
    /// # Errors
    ///
    /// Returns [`CatalogError`] if the selection is invalid or cannot be
    /// topologically ordered.
    pub fn composition_order(
        &self,
        selected: &BTreeSet<String>,
    ) -> Result<Vec<&ModuleDefinition>, CatalogError> {
        self.validate_selection(selected)?;
        let mut ordered = Vec::with_capacity(selected.len());
        let mut emitted = BTreeSet::new();
        while ordered.len() < selected.len() {
            let before = ordered.len();
            for module in &self.modules {
                if !selected.contains(&module.id) || emitted.contains(&module.id) {
                    continue;
                }
                if module
                    .requires
                    .iter()
                    .all(|required| emitted.contains(required))
                {
                    emitted.insert(module.id.clone());
                    ordered.push(module);
                }
            }
            if ordered.len() == before {
                return Err(CatalogError::new(
                    "selected modules cannot be ordered by prerequisites",
                ));
            }
        }
        Ok(ordered)
    }

    /// Checks dependency closure, conflicts, and provider slots for a selection.
    ///
    /// # Errors
    ///
    /// Returns [`CatalogError`] with an actionable deterministic diagnostic.
    pub fn validate_selection(&self, selected: &BTreeSet<String>) -> Result<(), CatalogError> {
        for id in selected {
            let module = self.module(id).ok_or_else(|| {
                CatalogError::new(format!("project state selects unknown module `{id}`"))
            })?;
            for required in &module.requires {
                if !selected.contains(required) {
                    return Err(CatalogError::new(format!(
                        "selected module `{id}` requires missing module `{required}`"
                    )));
                }
            }
        }

        let selected_ids: Vec<&str> = selected.iter().map(String::as_str).collect();
        for (index, left_id) in selected_ids.iter().enumerate() {
            let left = self
                .module(left_id)
                .ok_or_else(|| CatalogError::new(format!("unknown module `{left_id}`")))?;
            for right_id in &selected_ids[index + 1..] {
                let right = self
                    .module(right_id)
                    .ok_or_else(|| CatalogError::new(format!("unknown module `{right_id}`")))?;
                if left.conflicts_with.iter().any(|id| id == right.id.as_str())
                    || right.conflicts_with.iter().any(|id| id == left.id.as_str())
                {
                    return Err(CatalogError::new(format!(
                        "module conflict: `{}` cannot be selected with `{}`",
                        left.id, right.id
                    )));
                }
                if left.provider_slot.is_some() && left.provider_slot == right.provider_slot {
                    return Err(CatalogError::new(format!(
                        "provider slot `{}` has multiple selected providers: `{}` and `{}`",
                        left.provider_slot.as_deref().unwrap_or_default(),
                        left.id,
                        right.id
                    )));
                }
            }
        }
        validate_configuration_conflicts(self, selected)?;
        Ok(())
    }

    fn collect_dependencies(
        &self,
        id: &str,
        visiting: &mut BTreeSet<String>,
        collected: &mut BTreeSet<String>,
    ) -> Result<(), CatalogError> {
        if collected.contains(id) {
            return Ok(());
        }
        if !visiting.insert(id.to_owned()) {
            return Err(CatalogError::new(format!(
                "module dependency cycle contains `{id}`"
            )));
        }
        let module = self
            .module(id)
            .ok_or_else(|| CatalogError::new(format!("unknown module `{id}`")))?;
        for required in &module.requires {
            self.collect_dependencies(required, visiting, collected)?;
            collected.insert(required.clone());
        }
        visiting.remove(id);
        Ok(())
    }

    fn depends_on(
        &self,
        id: &str,
        target: &str,
        visiting: &mut BTreeSet<String>,
    ) -> Result<bool, CatalogError> {
        if !visiting.insert(id.to_owned()) {
            return Err(CatalogError::new(format!(
                "module dependency cycle contains `{id}`"
            )));
        }
        let module = self
            .module(id)
            .ok_or_else(|| CatalogError::new(format!("unknown module `{id}`")))?;
        for required in &module.requires {
            if required == target || self.depends_on(required, target, visiting)? {
                visiting.remove(id);
                return Ok(true);
            }
        }
        visiting.remove(id);
        Ok(false)
    }
}

fn decode_catalog<T: for<'de> Deserialize<'de>>(
    label: &str,
    source: &str,
) -> Result<T, CatalogError> {
    serde_yaml::from_str(source)
        .map_err(|error| CatalogError::new(format!("invalid {label}: {error}")))
}
fn workspace_dependency_keys() -> Result<BTreeSet<String>, CatalogError> {
    let manifest: toml::Value = toml::from_str(WORKSPACE_MANIFEST_SOURCE)
        .map_err(|error| CatalogError::new(format!("invalid workspace manifest: {error}")))?;
    let dependencies = manifest
        .get("workspace")
        .and_then(|workspace| workspace.get("dependencies"))
        .and_then(toml::Value::as_table)
        .ok_or_else(|| CatalogError::new("workspace manifest lacks workspace.dependencies"))?;
    Ok(dependencies.keys().cloned().collect())
}

fn validate_base_wire_shape(source: &str) -> Result<(), CatalogError> {
    let value: serde_yaml::Value = decode_catalog("base module catalog", source)?;
    for module in wire_modules(&value, "base module catalog")? {
        if !module.contains_key(serde_yaml::Value::String("provider_slot".to_owned())) {
            return Err(CatalogError::new(
                "base module catalog entries must explicitly declare provider_slot",
            ));
        }
        validate_wire_managed_regions(module, true)?;
    }
    Ok(())
}

fn wire_modules<'a>(
    value: &'a serde_yaml::Value,
    label: &str,
) -> Result<Vec<&'a serde_yaml::Mapping>, CatalogError> {
    let root = value
        .as_mapping()
        .ok_or_else(|| CatalogError::new(format!("{label} root must be a mapping")))?;
    let modules = root
        .get(serde_yaml::Value::String("modules".to_owned()))
        .and_then(serde_yaml::Value::as_sequence)
        .ok_or_else(|| CatalogError::new(format!("{label} modules must be a sequence")))?;
    modules
        .iter()
        .map(|module| {
            module
                .as_mapping()
                .ok_or_else(|| CatalogError::new(format!("{label} module must be a mapping")))
        })
        .collect()
}

fn validate_wire_managed_regions(
    module: &serde_yaml::Mapping,
    require_path_reference: bool,
) -> Result<(), CatalogError> {
    let regions = module
        .get(serde_yaml::Value::String("generator_ownership".to_owned()))
        .and_then(serde_yaml::Value::as_mapping)
        .and_then(|ownership| {
            ownership.get(serde_yaml::Value::String("managed_regions".to_owned()))
        })
        .and_then(serde_yaml::Value::as_sequence)
        .ok_or_else(|| CatalogError::new("module managed_regions must be a sequence"))?;
    for region in regions {
        let declaration = region
            .as_str()
            .ok_or_else(|| CatalogError::new("module managed region must be a string"))?;
        if declaration.trim().is_empty()
            || declaration.bytes().any(|byte| byte.is_ascii_control())
            || (require_path_reference && !declaration.contains('#'))
        {
            return Err(CatalogError::new(format!(
                "invalid managed region declaration `{declaration}`"
            )));
        }
    }
    Ok(())
}

fn validate_runtime_dependency_registry(
    descriptors: &[RuntimeDependencyDescriptor],
) -> Result<BTreeMap<RuntimeDependencyId, &RuntimeDependencyDescriptor>, CatalogError> {
    let mut registry = BTreeMap::new();
    let mut migration_owners = 0_u8;
    for descriptor in descriptors {
        let id = descriptor.id();
        if registry.insert(id, descriptor).is_some() {
            return Err(CatalogError::new(format!(
                "duplicate runtime dependency descriptor `{}`",
                id.as_str()
            )));
        }
        match descriptor {
            RuntimeDependencyDescriptor::Compose {
                service,
                image,
                volume,
                volume_mount,
                healthcheck,
                service_environment,
                application_environment,
                migration,
                ..
            } => {
                validate_compose_topology(id, service, image, volume, volume_mount, healthcheck)?;
                validate_compose_environment(id, service_environment, false)?;
                validate_compose_environment(id, application_environment, true)?;
                if let Some(migration) = migration {
                    migration_owners = migration_owners.saturating_add(1);
                    validate_id(&migration.required_module)?;
                    if migration.command.is_empty()
                        || migration.command.iter().any(|part| part.trim().is_empty())
                    {
                        return Err(CatalogError::new(format!(
                            "runtime dependency `{}` has an empty migration command",
                            id.as_str()
                        )));
                    }
                }
            }
            RuntimeDependencyDescriptor::External { bindings, .. } => {
                if bindings.is_empty() {
                    return Err(CatalogError::new(format!(
                        "external runtime dependency `{}` has no required bindings",
                        id.as_str()
                    )));
                }
                let mut names = BTreeSet::new();
                for binding in bindings {
                    if !valid_environment_name(&binding.name)
                        || !names.insert(binding.name.as_str())
                        || binding.message.trim().is_empty()
                        || binding.message.contains("${")
                    {
                        return Err(CatalogError::new(format!(
                            "external runtime dependency `{}` has an invalid environment binding",
                            id.as_str()
                        )));
                    }
                }
            }
        }
    }
    if migration_owners > 1 {
        return Err(CatalogError::new(
            "runtime dependency registry defines multiple Compose migration owners",
        ));
    }
    Ok(registry)
}

fn validate_compose_topology(
    id: RuntimeDependencyId,
    service: &str,
    image: &str,
    volume: &str,
    volume_mount: &str,
    healthcheck: &ComposeHealthcheck,
) -> Result<(), CatalogError> {
    if !valid_compose_name(service)
        || !valid_compose_name(volume)
        || !volume_mount.starts_with('/')
        || volume_mount.bytes().any(|byte| byte.is_ascii_control())
    {
        return Err(CatalogError::new(format!(
            "runtime dependency `{}` has an invalid Compose service or volume name",
            id.as_str()
        )));
    }
    let Some((_, digest)) = image.rsplit_once("@sha256:") else {
        return Err(CatalogError::new(format!(
            "runtime dependency `{}` Compose image must be digest pinned",
            id.as_str()
        )));
    };
    if digest.len() != 64
        || !digest
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(CatalogError::new(format!(
            "runtime dependency `{}` Compose image has an invalid sha256 digest",
            id.as_str()
        )));
    }
    if healthcheck.test.is_empty()
        || healthcheck.test.iter().any(|part| part.trim().is_empty())
        || healthcheck.interval.trim().is_empty()
        || healthcheck.timeout.trim().is_empty()
        || healthcheck.retries == 0
    {
        return Err(CatalogError::new(format!(
            "runtime dependency `{}` has an incomplete Compose health check",
            id.as_str()
        )));
    }
    Ok(())
}

fn validate_compose_environment(
    id: RuntimeDependencyId,
    bindings: &[ComposeEnvironmentBinding],
    application: bool,
) -> Result<(), CatalogError> {
    let mut names = BTreeSet::new();
    for binding in bindings {
        if !valid_environment_name(&binding.name)
            || !names.insert(binding.name.as_str())
            || binding.value.is_empty()
            || binding.value.contains("${")
            || (application && !binding.name.starts_with("OMNIUS__"))
        {
            return Err(CatalogError::new(format!(
                "runtime dependency `{}` has an invalid Compose environment binding",
                id.as_str()
            )));
        }
        if binding.secret && !binding.development_only {
            return Err(CatalogError::new(format!(
                "runtime dependency `{}` secret default `{}` must be explicitly development-only",
                id.as_str(),
                binding.name
            )));
        }
    }
    Ok(())
}

fn validate_migration_ownership(
    catalog: &ModuleCatalog,
    registry: &BTreeMap<RuntimeDependencyId, &RuntimeDependencyDescriptor>,
) -> Result<(), CatalogError> {
    let declared_configuration = catalog
        .modules
        .iter()
        .flat_map(|module| &module.configuration.fields)
        .map(|field| hierarchical_environment_key(&field.path))
        .collect::<BTreeSet<_>>();
    for descriptor in registry.values() {
        let RuntimeDependencyDescriptor::Compose {
            id,
            application_environment,
            migration,
            ..
        } = descriptor
        else {
            continue;
        };
        for binding in application_environment {
            if !declared_configuration.contains(&binding.name) {
                return Err(CatalogError::new(format!(
                    "runtime dependency `{}` binds undeclared application configuration `{}`",
                    id.as_str(),
                    binding.name
                )));
            }
        }
        let Some(migration) = migration else {
            continue;
        };
        if migration.required_module != "migrations" {
            return Err(CatalogError::new(format!(
                "runtime dependency `{}` migration ownership must require the `migrations` module",
                id.as_str()
            )));
        }
        let owner = catalog.module(&migration.required_module).ok_or_else(|| {
            CatalogError::new(format!(
                "runtime dependency `{}` owns migrations without the migrations module",
                id.as_str()
            ))
        })?;
        if !owner.runtime_dependencies.contains(id) {
            return Err(CatalogError::new(format!(
                "migrations module does not reference runtime dependency `{}`",
                id.as_str()
            )));
        }
    }
    Ok(())
}

fn valid_compose_name(value: &str) -> bool {
    value.len() <= 63
        && value
            .bytes()
            .next()
            .is_some_and(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
        && value
            .bytes()
            .last()
            .is_some_and(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
}

fn valid_environment_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 256
        && value
            .bytes()
            .next()
            .is_some_and(|byte| byte.is_ascii_uppercase() || byte == b'_')
        && value
            .bytes()
            .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit() || byte == b'_')
}

fn validate_composition(
    module: &ModuleDefinition,
    workspace_dependencies: &BTreeSet<String>,
) -> Result<(), CatalogError> {
    let mut dependencies = BTreeSet::new();
    for composition_crate in &module.composition.crates {
        validate_id(&composition_crate.dependency)?;
        if !workspace_dependencies.contains(&composition_crate.dependency) {
            return Err(CatalogError::new(format!(
                "module `{}` references unknown workspace dependency `{}`",
                module.id, composition_crate.dependency
            )));
        }
        if !dependencies.insert(composition_crate.dependency.as_str()) {
            return Err(CatalogError::new(format!(
                "module `{}` has duplicate composition dependency `{}`",
                module.id, composition_crate.dependency
            )));
        }
        validate_unique_list(
            &composition_crate.features,
            &module.id,
            "composition.crates.features",
        )?;
        for feature in &composition_crate.features {
            validate_id(feature)?;
        }
    }
    validate_unique_list(
        &module.composition.application_requirements,
        &module.id,
        "composition.application_requirements",
    )?;
    let declares_runtime_contract = !module.routes.is_empty()
        || !module.background_tasks.is_empty()
        || !module.health_checks.is_empty();
    if declares_runtime_contract
        && !module.composition.registrar
        && module.composition.application_requirements.is_empty()
    {
        return Err(CatalogError::new(format!(
            "module `{}` declares a route, task, or health contract without a registrar or application requirement",
            module.id
        )));
    }
    Ok(())
}

fn validate_configuration(module: &ModuleDefinition) -> Result<(), CatalogError> {
    validate_id(&module.configuration.prefix)?;
    if let Some(schema) = &module.configuration.schema {
        validate_relative_path(schema).map_err(|error| {
            CatalogError::new(format!(
                "module `{}` configuration schema: {error}",
                module.id
            ))
        })?;
    }
    validate_unique_list(
        &module.configuration.secret_fields,
        &module.id,
        "configuration.secret_fields",
    )?;
    for secret in &module.configuration.secret_fields {
        validate_configuration_path(secret, true).map_err(|message| {
            CatalogError::new(format!(
                "module `{}` has invalid secret field `{secret}`: {message}",
                module.id
            ))
        })?;
    }

    let mut paths = BTreeSet::new();
    for field in &module.configuration.fields {
        validate_configuration_path(&field.path, false).map_err(|message| {
            CatalogError::new(format!(
                "module `{}` has invalid configuration field `{}`: {message}",
                module.id, field.path
            ))
        })?;
        if !paths.insert(field.path.as_str()) {
            return Err(CatalogError::new(format!(
                "module `{}` has duplicate configuration field `{}`",
                module.id, field.path
            )));
        }
        if field
            .reference_default
            .as_ref()
            .is_some_and(|value| !value.matches(field.value_type))
        {
            return Err(CatalogError::new(format!(
                "module `{}` configuration default for `{}` does not match declared type",
                module.id, field.path
            )));
        }
        if field.reference_default.is_some()
            && configuration_path_is_secret(&field.path, &module.configuration.secret_fields)
        {
            return Err(CatalogError::new(format!(
                "module `{}` secret configuration field `{}` cannot have a reference default",
                module.id, field.path
            )));
        }
        if field.reference_default.is_some() && field.environment.is_some() {
            return Err(CatalogError::new(format!(
                "module `{}` configuration field `{}` cannot have both a reference default and a required environment binding",
                module.id, field.path
            )));
        }
        if field.required && field.reference_default.is_none() && field.environment.is_none() {
            return Err(CatalogError::new(format!(
                "module `{}` required configuration field `{}` needs a reference default or environment binding",
                module.id, field.path
            )));
        }
        if !field.required && field.environment.is_some() {
            return Err(CatalogError::new(format!(
                "module `{}` optional configuration field `{}` cannot declare a required environment binding",
                module.id, field.path
            )));
        }
        if let Some(environment) = &field.environment {
            let expected = hierarchical_environment_key(&field.path);
            if environment != &expected {
                return Err(CatalogError::new(format!(
                    "module `{}` configuration field `{}` must bind exact environment key `{expected}`",
                    module.id, field.path
                )));
            }
        }
        if let Some(ConfigurationValue::String(value)) = &field.reference_default
            && has_unsupported_placeholder(value)
        {
            return Err(CatalogError::new(format!(
                "module `{}` configuration default for `{}` contains an unsupported placeholder",
                module.id, field.path
            )));
        }
    }
    Ok(())
}

fn has_unsupported_placeholder(value: &str) -> bool {
    if value.contains("${") {
        return true;
    }
    let without_service_name = value.replace("{{service-name}}", "");
    without_service_name.contains("{{") || without_service_name.contains("}}")
}

fn validate_configuration_conflicts(
    catalog: &ModuleCatalog,
    selected: &BTreeSet<String>,
) -> Result<(), CatalogError> {
    let mut configured: BTreeMap<&str, (&str, &ConfigurationField, bool)> = BTreeMap::new();
    for id in selected {
        let module = catalog
            .module(id)
            .ok_or_else(|| CatalogError::new(format!("unknown module `{id}`")))?;
        for field in &module.configuration.fields {
            let secret =
                configuration_path_is_secret(&field.path, &module.configuration.secret_fields);
            let Some((owner, existing, existing_secret)) =
                configured.insert(field.path.as_str(), (&module.id, field, secret))
            else {
                continue;
            };
            if existing != field || existing_secret != secret {
                return Err(CatalogError::new(format!(
                    "selected modules `{owner}` and `{}` define conflicting configuration for `{}`",
                    module.id, field.path
                )));
            }
        }
    }
    Ok(())
}

fn validate_configuration_path(path: &str, allow_wildcard: bool) -> Result<(), &'static str> {
    if path.len() > 256 {
        return Err("path exceeds 256 bytes");
    }
    let mut components = path.split('.');
    let Some(first) = components.next() else {
        return Err("path is empty");
    };
    if !valid_configuration_component(first, allow_wildcard) {
        return Err("path contains an invalid component");
    }
    let mut count = 1;
    for component in components {
        count += 1;
        if !valid_configuration_component(component, allow_wildcard) {
            return Err("path contains an invalid component");
        }
    }
    if count < 2 {
        return Err("path must contain a table and field");
    }
    Ok(())
}

fn valid_configuration_component(component: &str, allow_wildcard: bool) -> bool {
    let canonical = if allow_wildcard {
        component.strip_suffix("[]").unwrap_or(component)
    } else {
        component
    };
    (allow_wildcard && canonical == "*")
        || (!canonical.is_empty()
            && canonical
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_'))
}

fn configuration_path_is_secret(path: &str, secret_fields: &[String]) -> bool {
    secret_fields.iter().any(|secret| {
        let path_components = path.split('.');
        let secret_components = secret.split('.');
        path_components
            .zip(secret_components)
            .all(|(actual, expected)| {
                let actual = actual.strip_suffix("[]").unwrap_or(actual);
                let expected = expected.strip_suffix("[]").unwrap_or(expected);
                expected == "*" || actual == expected
            })
            && path.split('.').count() == secret.split('.').count()
    })
}

fn hierarchical_environment_key(path: &str) -> String {
    let mut key = String::from("OMNIUS");
    for component in path.split('.') {
        key.push_str("__");
        key.extend(
            component
                .chars()
                .map(|character| character.to_ascii_uppercase()),
        );
    }
    key
}

impl ConfigurationValue {
    const fn matches(&self, expected: ConfigurationValueType) -> bool {
        matches!(
            (self, expected),
            (Self::String(_), ConfigurationValueType::String)
                | (Self::Integer(_), ConfigurationValueType::Integer)
                | (Self::Boolean(_), ConfigurationValueType::Boolean)
                | (Self::StringArray(_), ConfigurationValueType::StringArray)
                | (Self::IntegerArray(_), ConfigurationValueType::IntegerArray)
        )
    }
}

fn validate_ownership(module: &ModuleDefinition) -> Result<(), CatalogError> {
    validate_unique_list(
        &module.generator_ownership.kit_owned,
        &module.id,
        "generator_ownership.kit_owned",
    )?;
    validate_unique_list(
        &module.generator_ownership.managed_regions,
        &module.id,
        "generator_ownership.managed_regions",
    )?;
    validate_unique_list(
        &module.generator_ownership.derived,
        &module.id,
        "generator_ownership.derived",
    )?;
    for path in module
        .generator_ownership
        .kit_owned
        .iter()
        .chain(&module.generator_ownership.derived)
    {
        validate_relative_path(path).map_err(|error| {
            CatalogError::new(format!("module `{}` ownership: {error}", module.id))
        })?;
    }
    for reference in &module.generator_ownership.managed_regions {
        let Some((path, id)) = reference.rsplit_once('#') else {
            if reference.trim().is_empty() || reference.bytes().any(|byte| byte.is_ascii_control())
            {
                return Err(CatalogError::new(format!(
                    "module `{}` has invalid operational ownership declaration `{reference}`",
                    module.id
                )));
            }
            continue;
        };
        let wildcard_components = path
            .split('/')
            .filter(|component| *component == "*")
            .count();
        if wildcard_components > 1
            || path
                .split('/')
                .any(|component| component.contains('*') && component != "*")
        {
            return Err(CatalogError::new(format!(
                "module `{}` has unsupported managed path pattern `{path}`",
                module.id
            )));
        }
        let wildcard_free = path.replace('*', "placeholder");
        validate_relative_path(&wildcard_free).map_err(|error| {
            CatalogError::new(format!("module `{}` ownership: {error}", module.id))
        })?;
        validate_id(id)?;
    }
    Ok(())
}

fn validate_unique_list<T>(values: &[T], module: &str, field: &str) -> Result<(), CatalogError>
where
    T: Ord + fmt::Display,
{
    let mut unique = BTreeSet::new();
    for value in values {
        if !unique.insert(value) {
            return Err(CatalogError::new(format!(
                "module `{module}` has duplicate `{value}` in {field}"
            )));
        }
    }
    Ok(())
}

fn validate_id(value: &str) -> Result<(), CatalogError> {
    if value.is_empty()
        || value.len() > 128
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
    {
        return Err(CatalogError::new(format!(
            "invalid module or region id `{value}`"
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn assert_error<T>(result: Result<T, CatalogError>) -> CatalogError {
        let Err(error) = result else {
            panic!("expected catalog composition to fail");
        };
        error
    }

    fn base_with_web() -> Result<(ModuleCatalog, String), CatalogError> {
        let mut catalog = ModuleCatalog::from_yaml(BASE_CATALOG_SOURCE)?;
        let web_version = catalog.append_extension("web", WEB_CATALOG_SOURCE, None)?;
        Ok((catalog, web_version))
    }
    #[test]
    fn application_requirement_ids_are_unique_and_round_trip_strictly() -> Result<(), CatalogError>
    {
        let ids = ApplicationRequirement::ALL
            .iter()
            .map(ApplicationRequirement::as_str)
            .collect::<BTreeSet<_>>();
        assert_eq!(ids.len(), ApplicationRequirement::ALL.len());
        for requirement in ApplicationRequirement::ALL {
            assert_eq!(
                requirement.as_str().parse::<ApplicationRequirement>()?,
                *requirement
            );
        }
        assert!(
            "Auth.Authenticated-Runtime"
                .parse::<ApplicationRequirement>()
                .is_err()
        );
        Ok(())
    }

    #[test]
    fn bundled_catalog_requirements_match_the_closed_runtime_set() -> Result<(), CatalogError> {
        let catalog = ModuleCatalog::bundled()?;
        let catalog_requirements = catalog
            .modules
            .iter()
            .flat_map(|module| module.composition.application_requirements.iter().copied())
            .collect::<BTreeSet<_>>();
        let runtime_requirements = ApplicationRequirement::ALL
            .iter()
            .copied()
            .collect::<BTreeSet<_>>();

        assert_eq!(catalog_requirements, runtime_requirements);
        Ok(())
    }

    #[test]
    fn every_requirement_has_exactly_one_provider_family() {
        let mappings = ApplicationRequirement::ALL
            .iter()
            .map(|requirement| (*requirement, requirement.provider_family()))
            .collect::<BTreeMap<_, _>>();
        assert_eq!(mappings.len(), ApplicationRequirement::ALL.len());
        let mapped_families = mappings.into_values().collect::<BTreeSet<_>>();
        let provider_families = ApplicationRequirementProviderFamily::ALL
            .iter()
            .copied()
            .collect::<BTreeSet<_>>();

        assert_eq!(mapped_families, provider_families);
    }

    #[test]
    fn ai_extension_rejects_wrong_web_extension_version() -> Result<(), CatalogError> {
        let (mut catalog, web_version) = base_with_web()?;
        let required = format!("web_extension_version: {web_version}");
        let incompatible =
            AI_CATALOG_SOURCE.replacen(&required, "web_extension_version: incompatible", 1);

        let error =
            assert_error(catalog.append_extension("AI", &incompatible, Some(web_version.as_str())));

        assert!(
            error
                .to_string()
                .contains("requires web extension incompatible")
        );
        Ok(())
    }

    #[test]
    fn composed_catalog_rejects_duplicate_ai_module_ids() -> Result<(), CatalogError> {
        let (mut catalog, web_version) = base_with_web()?;
        let duplicate =
            AI_CATALOG_SOURCE.replacen("- id: llm-core", "- id: agent-capability-registry", 1);
        catalog.append_extension("AI", &duplicate, Some(web_version.as_str()))?;

        let error = assert_error(catalog.validate());

        assert!(
            error
                .to_string()
                .contains("duplicate module id `agent-capability-registry`")
        );
        Ok(())
    }
    #[test]
    fn composition_rejects_unknown_workspace_dependency() {
        let invalid = BASE_CATALOG_SOURCE.replacen(
            "  composition:\n    crates: []\n    registrar: true",
            "  composition:\n    crates:\n    - dependency: omnius-missing\n      features: []\n    registrar: true",
            1,
        );
        let error = assert_error(ModuleCatalog::from_yaml(&invalid));
        assert!(error.to_string().contains("unknown workspace dependency"));
    }
    #[test]
    fn composition_rejects_unknown_application_requirement() {
        let invalid = BASE_CATALOG_SOURCE.replacen(
            "    - admin.authority-resolver",
            "    - admin.unknown-authority-resolver",
            1,
        );
        let error = assert_error(ModuleCatalog::from_yaml(&invalid));

        assert!(
            error
                .to_string()
                .contains("unknown application requirement `admin.unknown-authority-resolver`")
        );
    }

    #[test]
    fn composition_rejects_duplicate_crates_features_and_requirements() {
        let duplicate_crate = BASE_CATALOG_SOURCE.replacen(
            "    - dependency: omnius-config\n      features: []",
            "    - dependency: omnius-config\n      features: []\n    - dependency: omnius-config\n      features: []",
            1,
        );
        assert!(
            assert_error(ModuleCatalog::from_yaml(&duplicate_crate))
                .to_string()
                .contains("duplicate composition dependency")
        );

        let duplicate_feature = BASE_CATALOG_SOURCE.replacen(
            "    - dependency: omnius-config\n      features: []",
            "    - dependency: omnius-config\n      features: [testing, testing]",
            1,
        );
        assert!(
            assert_error(ModuleCatalog::from_yaml(&duplicate_feature))
                .to_string()
                .contains("composition.crates.features")
        );

        let duplicate_requirement = BASE_CATALOG_SOURCE.replacen(
            "    - admin.authority-resolver\n    - admin.operation-handler",
            "    - admin.authority-resolver\n    - admin.operation-handler\n    - admin.operation-handler",
            1,
        );
        assert!(
            assert_error(ModuleCatalog::from_yaml(&duplicate_requirement))
                .to_string()
                .contains("composition.application_requirements")
        );
    }

    #[test]
    fn composition_rejects_unowned_runtime_contract() {
        let invalid = BASE_CATALOG_SOURCE.replacen(
            "    registrar: true\n    application_requirements: []\n  acceptance:\n  - AC-OBS-004",
            "    registrar: false\n    application_requirements: []\n  acceptance:\n  - AC-OBS-004",
            1,
        );
        let error = assert_error(ModuleCatalog::from_yaml(&invalid));
        assert!(
            error
                .to_string()
                .contains("without a registrar or application requirement")
        );
    }

    #[test]
    fn configuration_rejects_wrong_types_secret_defaults_and_missing_sources()
    -> Result<(), CatalogError> {
        let mut wrong_type = ModuleCatalog::from_yaml(BASE_CATALOG_SOURCE)?;
        let telemetry = wrong_type
            .modules
            .iter_mut()
            .find(|module| module.id == "telemetry")
            .ok_or_else(|| CatalogError::new("telemetry module missing"))?;
        telemetry.configuration.fields[0].value_type = ConfigurationValueType::Boolean;
        assert!(
            assert_error(wrong_type.validate())
                .to_string()
                .contains("does not match declared type")
        );

        let mut secret_default = ModuleCatalog::from_yaml(BASE_CATALOG_SOURCE)?;
        let telemetry = secret_default
            .modules
            .iter_mut()
            .find(|module| module.id == "telemetry")
            .ok_or_else(|| CatalogError::new("telemetry module missing"))?;
        telemetry
            .configuration
            .secret_fields
            .push("telemetry.service".to_owned());
        assert!(
            assert_error(secret_default.validate())
                .to_string()
                .contains("cannot have a reference default")
        );

        let mut missing_source = ModuleCatalog::from_yaml(BASE_CATALOG_SOURCE)?;
        let telemetry = missing_source
            .modules
            .iter_mut()
            .find(|module| module.id == "telemetry")
            .ok_or_else(|| CatalogError::new("telemetry module missing"))?;
        telemetry.configuration.fields[0].reference_default = None;
        assert!(
            assert_error(missing_source.validate())
                .to_string()
                .contains("needs a reference default or environment binding")
        );
        Ok(())
    }

    #[test]
    fn configuration_rejects_inexact_environment_keys_and_selected_conflicts()
    -> Result<(), CatalogError> {
        let mut inexact_environment = ModuleCatalog::from_yaml(BASE_CATALOG_SOURCE)?;
        let postgres = inexact_environment
            .modules
            .iter_mut()
            .find(|module| module.id == "postgres")
            .ok_or_else(|| CatalogError::new("postgres module missing"))?;
        postgres.configuration.fields[0].environment = Some("OMNIUS_POSTGRES_URL".to_owned());
        assert!(
            assert_error(inexact_environment.validate())
                .to_string()
                .contains("must bind exact environment key `OMNIUS__POSTGRES__URL`")
        );

        let mut conflict = ModuleCatalog::from_yaml(BASE_CATALOG_SOURCE)?;
        let mut duplicate = conflict
            .module("telemetry")
            .and_then(|module| module.configuration.fields.first())
            .cloned()
            .ok_or_else(|| CatalogError::new("telemetry service field missing"))?;
        duplicate.reference_default = Some(ConfigurationValue::String("other-service".to_owned()));
        let config = conflict
            .modules
            .iter_mut()
            .find(|module| module.id == "config")
            .ok_or_else(|| CatalogError::new("config module missing"))?;
        config.configuration.fields.push(duplicate);
        conflict.validate()?;
        let error = assert_error(conflict.resolve_add(&BTreeSet::new(), "telemetry"));
        assert!(error.to_string().contains("conflicting configuration"));
        Ok(())
    }

    #[test]
    fn configuration_secret_paths_accept_canonical_array_suffixes() {
        let array_path = "webhooks_inbound.fixture_hmac_providers[].secrets[]";
        assert!(validate_configuration_path(array_path, true).is_ok());
        assert!(validate_configuration_path(array_path, false).is_err());
        assert!(configuration_path_is_secret(
            "webhooks_inbound.fixture_hmac_providers.secrets",
            &[array_path.to_owned()]
        ));
        assert!(validate_configuration_path("table.entries[][]", true).is_err());
    }

    #[test]
    fn runtime_dependencies_reject_unknown_ids_and_invalid_compose_contracts()
    -> Result<(), CatalogError> {
        let unknown = BASE_CATALOG_SOURCE.replacen("  - postgresql\n", "  - unknown-topology\n", 1);
        assert!(
            assert_error(ModuleCatalog::from_yaml(&unknown))
                .to_string()
                .contains("unknown variant")
        );

        let mut invalid_name = ModuleCatalog::from_yaml(BASE_CATALOG_SOURCE)?;
        let RuntimeDependencyDescriptor::Compose { service, .. } =
            &mut invalid_name.runtime_dependencies[0]
        else {
            return Err(CatalogError::new("PostgreSQL descriptor is not Compose"));
        };
        *service = "Invalid_Service".to_owned();
        assert!(
            assert_error(invalid_name.validate())
                .to_string()
                .contains("invalid Compose service or volume name")
        );

        let mut secret_default = ModuleCatalog::from_yaml(BASE_CATALOG_SOURCE)?;
        let RuntimeDependencyDescriptor::Compose {
            service_environment,
            ..
        } = &mut secret_default.runtime_dependencies[0]
        else {
            return Err(CatalogError::new("PostgreSQL descriptor is not Compose"));
        };
        let password = service_environment
            .iter_mut()
            .find(|binding| binding.name == "POSTGRES_PASSWORD")
            .ok_or_else(|| CatalogError::new("PostgreSQL password binding is missing"))?;
        password.development_only = false;
        assert!(
            assert_error(secret_default.validate())
                .to_string()
                .contains("must be explicitly development-only")
        );

        let mut migration_owner = ModuleCatalog::from_yaml(BASE_CATALOG_SOURCE)?;
        let RuntimeDependencyDescriptor::Compose {
            migration: Some(migration),
            ..
        } = &mut migration_owner.runtime_dependencies[0]
        else {
            return Err(CatalogError::new("PostgreSQL migration owner is missing"));
        };
        migration.required_module = "runtime".to_owned();
        assert!(
            assert_error(migration_owner.validate())
                .to_string()
                .contains("must require the `migrations` module")
        );
        Ok(())
    }

    #[test]
    fn extension_rejects_conflicting_inherited_runtime_descriptor() -> Result<(), CatalogError> {
        let mut catalog = ModuleCatalog::from_yaml(BASE_CATALOG_SOURCE)?;
        let conflicting = WEB_CATALOG_SOURCE.replacen(
            "modules:",
            "runtime_dependencies:\n- kind: external\n  id: redis-or-valkey\n  bindings:\n  - name: OMNIUS__REDIS__URL\n    message: use a conflicting Redis endpoint\n    credential: true\nmodules:",
            1,
        );
        let error = assert_error(catalog.append_extension("web", &conflicting, None));
        assert!(
            error
                .to_string()
                .contains("conflicting inherited runtime dependency `redis-or-valkey`")
        );
        Ok(())
    }

    #[test]
    fn composition_order_is_prerequisite_first() -> Result<(), CatalogError> {
        let catalog = ModuleCatalog::from_yaml(BASE_CATALOG_SOURCE)?;
        let selected = catalog.resolve_add(&BTreeSet::new(), "health")?;
        let ordered = catalog.composition_order(&selected)?;
        let ids = ordered
            .iter()
            .map(|module| module.id.as_str())
            .collect::<Vec<_>>();
        let health = ids
            .iter()
            .position(|id| *id == "health")
            .ok_or_else(|| CatalogError::new("health missing"))?;
        for required in ["runtime", "http"] {
            let position = ids
                .iter()
                .position(|id| *id == required)
                .ok_or_else(|| CatalogError::new(format!("{required} missing")))?;
            assert!(position < health);
        }
        Ok(())
    }
}

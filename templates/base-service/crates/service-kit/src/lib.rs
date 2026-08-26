//! Self-contained operational metadata shared by the generated service.

use std::{error::Error, fmt};

use serde::Serialize;
use time::{OffsetDateTime, format_description::well_known::Rfc3339};

/// Database schema versions with which the generated binary can operate.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub struct SchemaCompatibility {
    /// Oldest supported schema version, or `none` before persistence is added.
    pub minimum: &'static str,
    /// Newest supported schema version, or `none` before persistence is added.
    pub maximum: &'static str,
}

/// One mutually exclusive provider selected by the generated profile.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub struct ProviderMetadata {
    /// Stable provider capability slot.
    pub slot: &'static str,
    /// Installed module occupying the slot.
    pub module: &'static str,
}

/// Compile-time composition values supplied by the generated application.
#[derive(Clone, Copy, Debug)]
pub struct BuildMetadataInput {
    /// Stable service name.
    pub service: &'static str,
    /// Selected named profile.
    pub profile: &'static str,
    /// Installed modules in resolved profile order.
    pub modules: &'static [&'static str],
    /// Provider selections in resolved module order.
    pub providers: &'static [ProviderMetadata],
    /// Compatible database schema range.
    pub schema: SchemaCompatibility,
}

/// Safe build and composition information for `/version` and `profile-info`.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub struct BuildMetadata {
    service: &'static str,
    version: &'static str,
    git_revision: Option<&'static str>,
    build_time: Option<&'static str>,
    compiler: &'static str,
    kit_version: &'static str,
    profile: &'static str,
    modules: &'static [&'static str],
    providers: &'static [ProviderMetadata],
    schema: SchemaCompatibility,
}

impl BuildMetadata {
    /// Validates and constructs public operational metadata.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidBuildMetadata`] if any public field is malformed or a
    /// module identifier occurs more than once.
    pub fn new(
        input: BuildMetadataInput,
        version: &'static str,
        git_revision: Option<&'static str>,
        build_time: Option<&'static str>,
        compiler: &'static str,
        kit_version: &'static str,
    ) -> Result<Self, InvalidBuildMetadata> {
        validate_name("service", input.service)?;
        validate_name("profile", input.profile)?;
        validate_token("version", version)?;
        validate_token("compiler", compiler)?;
        validate_token("kit_version", kit_version)?;
        validate_token("schema.minimum", input.schema.minimum)?;
        validate_token("schema.maximum", input.schema.maximum)?;
        for (index, module) in input.modules.iter().enumerate() {
            validate_name("module", module)?;
            if input.modules[..index].contains(module) {
                return Err(InvalidBuildMetadata::DuplicateModule);
            }
        }
        for (index, provider) in input.providers.iter().enumerate() {
            validate_name("provider.slot", provider.slot)?;
            validate_name("provider.module", provider.module)?;
            if input.providers[..index]
                .iter()
                .any(|existing| existing.slot == provider.slot)
            {
                return Err(InvalidBuildMetadata::DuplicateProviderSlot);
            }
            if !input.modules.contains(&provider.module) {
                return Err(InvalidBuildMetadata::ProviderModuleMissing);
            }
        }
        if let Some(revision) = git_revision
            && (!(7..=64).contains(&revision.len())
                || !revision.bytes().all(|byte| byte.is_ascii_hexdigit()))
        {
            return Err(InvalidBuildMetadata::InvalidField("git_revision"));
        }
        if let Some(timestamp) = build_time {
            OffsetDateTime::parse(timestamp, &Rfc3339)
                .map_err(|_| InvalidBuildMetadata::InvalidField("build_time"))?;
        }
        Ok(Self {
            service: input.service,
            version,
            git_revision,
            build_time,
            compiler,
            kit_version,
            profile: input.profile,
            modules: input.modules,
            providers: input.providers,
            schema: input.schema,
        })
    }

    /// Returns the stable service name.
    #[must_use]
    pub const fn service(&self) -> &'static str {
        self.service
    }

    /// Returns the selected profile.
    #[must_use]
    pub const fn profile(&self) -> &'static str {
        self.profile
    }

    /// Returns installed modules in resolved order.
    #[must_use]
    pub const fn modules(&self) -> &'static [&'static str] {
        self.modules
    }

    /// Returns provider selections in resolved module order.
    #[must_use]
    pub const fn providers(&self) -> &'static [ProviderMetadata] {
        self.providers
    }
}

/// Build metadata contains an unsafe or malformed value.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InvalidBuildMetadata {
    /// One named field failed validation.
    InvalidField(&'static str),
    /// The module list contains a duplicate identifier.
    DuplicateModule,
    /// More than one module occupies a provider slot.
    DuplicateProviderSlot,
    /// A provider record names a module absent from the resolved module list.
    ProviderModuleMissing,
}

impl fmt::Display for InvalidBuildMetadata {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidField(field) => write!(formatter, "invalid build metadata field: {field}"),
            Self::DuplicateModule => {
                formatter.write_str("build metadata contains a duplicate module")
            }
            Self::DuplicateProviderSlot => {
                formatter.write_str("build metadata contains a duplicate provider slot")
            }
            Self::ProviderModuleMissing => {
                formatter.write_str("build metadata provider module is not installed")
            }
        }
    }
}

impl Error for InvalidBuildMetadata {}

fn validate_name(field: &'static str, value: &str) -> Result<(), InvalidBuildMetadata> {
    if value.is_empty()
        || value.len() > 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
    {
        return Err(InvalidBuildMetadata::InvalidField(field));
    }
    Ok(())
}

fn validate_token(field: &'static str, value: &str) -> Result<(), InvalidBuildMetadata> {
    if value.is_empty()
        || value.len() > 128
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_graphic() || byte == b' ')
    {
        return Err(InvalidBuildMetadata::InvalidField(field));
    }
    Ok(())
}

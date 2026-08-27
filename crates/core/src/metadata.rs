use serde::Serialize;
use thiserror::Error;
use time::{OffsetDateTime, format_description::well_known::Rfc3339};

/// The database schema versions with which a binary can operate.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub struct SchemaCompatibility {
    /// Oldest supported schema version.
    pub minimum: &'static str,
    /// Newest supported schema version.
    pub maximum: &'static str,
}

/// Compile-time values supplied by a service composition.
#[derive(Clone, Copy, Debug)]
pub struct BuildMetadataInput {
    /// Stable service name.
    pub service: &'static str,
    /// Selected named profile.
    pub profile: &'static str,
    /// Installed module IDs.
    pub modules: &'static [&'static str],
    /// Supported database schema range.
    pub schema: SchemaCompatibility,
}

/// Safe build and composition information exposed by operational endpoints.
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
    schema: SchemaCompatibility,
}

impl BuildMetadata {
    /// Builds metadata from the crate and release-pipeline environment.
    ///
    /// `OMNIUS_GIT_REVISION` and `OMNIUS_BUILD_TIME` are optional so local builds
    /// remain reproducible. Release builds set both values.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidBuildMetadata`] when a public field is malformed,
    /// unbounded, duplicated, or unsafe to expose.
    pub fn current(input: BuildMetadataInput) -> Result<Self, InvalidBuildMetadata> {
        Self::from_parts(
            input,
            env!("CARGO_PKG_VERSION"),
            option_env!("OMNIUS_GIT_REVISION"),
            option_env!("OMNIUS_BUILD_TIME"),
            env!("OMNIUS_RUSTC_VERSION"),
            env!("CARGO_PKG_VERSION"),
        )
    }

    fn from_parts(
        input: BuildMetadataInput,
        version: &'static str,
        git_revision: Option<&'static str>,
        build_time: Option<&'static str>,
        compiler: &'static str,
        kit_version: &'static str,
    ) -> Result<Self, InvalidBuildMetadata> {
        validate_name("service", input.service)?;
        validate_name("profile", input.profile)?;
        validate_token("version", version, 128)?;
        validate_token("compiler", compiler, 128)?;
        validate_token("kit_version", kit_version, 128)?;
        validate_token("schema.minimum", input.schema.minimum, 128)?;
        validate_token("schema.maximum", input.schema.maximum, 128)?;
        for (index, module) in input.modules.iter().enumerate() {
            validate_name("module", module)?;
            if input.modules[..index].contains(module) {
                return Err(InvalidBuildMetadata::DuplicateModule);
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
            schema: input.schema,
        })
    }

    /// Returns the stable service name.
    #[must_use]
    pub const fn service(&self) -> &'static str {
        self.service
    }

    /// Returns the application version.
    #[must_use]
    pub const fn version(&self) -> &'static str {
        self.version
    }

    /// Returns the release Git revision when supplied by the build pipeline.
    #[must_use]
    pub const fn git_revision(&self) -> Option<&'static str> {
        self.git_revision
    }

    /// Returns the RFC 3339 build time when supplied by the build pipeline.
    #[must_use]
    pub const fn build_time(&self) -> Option<&'static str> {
        self.build_time
    }

    /// Returns the compiler version captured by the build script.
    #[must_use]
    pub const fn compiler(&self) -> &'static str {
        self.compiler
    }

    /// Returns the service-kit version.
    #[must_use]
    pub const fn kit_version(&self) -> &'static str {
        self.kit_version
    }

    /// Returns the selected named profile.
    #[must_use]
    pub const fn profile(&self) -> &'static str {
        self.profile
    }

    /// Returns the installed module IDs.
    #[must_use]
    pub const fn modules(&self) -> &'static [&'static str] {
        self.modules
    }

    /// Returns the compatible schema range.
    #[must_use]
    pub const fn schema(&self) -> SchemaCompatibility {
        self.schema
    }
}

/// Build metadata contains an unsafe or malformed value.
#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum InvalidBuildMetadata {
    /// A named field failed validation.
    #[error("invalid build metadata field: {0}")]
    InvalidField(&'static str),
    /// The module list contains the same module more than once.
    #[error("build metadata contains a duplicate module")]
    DuplicateModule,
}

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

fn validate_token(
    field: &'static str,
    value: &str,
    maximum_length: usize,
) -> Result<(), InvalidBuildMetadata> {
    if value.is_empty()
        || value.len() > maximum_length
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_graphic() || byte == b' ')
    {
        return Err(InvalidBuildMetadata::InvalidField(field));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const SCHEMA: SchemaCompatibility = SchemaCompatibility {
        minimum: "2026082301",
        maximum: "2026082399",
    };

    #[test]
    fn exposes_safe_build_and_profile_information() -> Result<(), Box<dyn std::error::Error>> {
        let metadata = BuildMetadata::current(BuildMetadataInput {
            service: "example-api",
            profile: "minimal",
            modules: &["core", "config"],
            schema: SCHEMA,
        })?;
        let document = serde_json::to_value(metadata)?;
        assert_eq!(document["service"], "example-api");
        assert_eq!(document["profile"], "minimal");
        assert_eq!(document["modules"], serde_json::json!(["core", "config"]));
        assert!(metadata.compiler().starts_with("rustc 1.98.0"));
        assert_eq!(metadata.git_revision(), option_env!("OMNIUS_GIT_REVISION"));
        assert_eq!(metadata.build_time(), option_env!("OMNIUS_BUILD_TIME"));
        Ok(())
    }
    #[test]
    fn exposes_release_revision_and_build_time() -> Result<(), Box<dyn std::error::Error>> {
        let metadata = BuildMetadata::from_parts(
            BuildMetadataInput {
                service: "example-api",
                profile: "minimal",
                modules: &["core"],
                schema: SCHEMA,
            },
            "1.2.3",
            Some("0123456789abcdef"),
            Some("2026-08-23T20:00:00Z"),
            "rustc 1.98.0",
            "0.1.0",
        )?;
        let document = serde_json::to_value(metadata)?;
        assert_eq!(document["git_revision"], "0123456789abcdef");
        assert_eq!(document["build_time"], "2026-08-23T20:00:00Z");
        assert_eq!(document["schema"]["minimum"], "2026082301");
        Ok(())
    }

    #[test]
    fn rejects_duplicate_or_unbounded_public_values() {
        let duplicate = BuildMetadata::current(BuildMetadataInput {
            service: "example-api",
            profile: "minimal",
            modules: &["core", "core"],
            schema: SCHEMA,
        });
        assert_eq!(duplicate, Err(InvalidBuildMetadata::DuplicateModule));

        let unsafe_name = BuildMetadata::current(BuildMetadataInput {
            service: "example api\nsecret",
            profile: "minimal",
            modules: &["core"],
            schema: SCHEMA,
        });
        assert_eq!(
            unsafe_name,
            Err(InvalidBuildMetadata::InvalidField("service"))
        );
    }
}

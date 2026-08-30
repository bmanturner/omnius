use std::fmt;

use omnius_agent_capability_registry::CapabilityRegistry;
use omnius_mcp_server_core::McpRequestContext;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use thiserror::Error;

use crate::lifecycle::{
    SkillLifecycleRepository, SkillRuntimeAdmission, SkillRuntimeGrant, SkillRuntimeGuard,
};
use crate::manifest::{AdmittedSkill, SkillPrincipalPolicy, SkillServerIdentity};

/// Complete file descriptor exposed by `skills/list` and `skills/get` adapters.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SkillFileDescriptor {
    /// Versioned `skill://` resource URI.
    pub uri: String,
    /// Lowercase SHA-256 file digest.
    pub digest: String,
    /// Exact file bytes.
    pub size: u64,
}

/// Transport-neutral static Skills discovery projection carrying a live non-cloneable lease.
#[derive(PartialEq, Serialize)]
pub struct SkillDescriptor {
    runtime: SkillRuntimeGrant,
    frontmatter: Value,
    files: Vec<SkillFileDescriptor>,
}

impl SkillDescriptor {
    /// Projects an admitted, currently enabled static manifest without granting authority.
    ///
    /// Exact negotiation, canonical binding, current lifecycle revision, provenance, registry
    /// revisions, and current principal/server permission intersections are refreshed first.
    ///
    /// # Errors
    ///
    /// Returns [`ProjectionError::Disabled`] when negotiation, canonical binding, enabled
    /// lifecycle state, immutable provenance, current admission, atomic lease acquisition, or the
    /// registry and principal-policy capability intersection fails.
    #[expect(
        clippy::too_many_arguments,
        reason = "each independent authority remains explicit at the discovery trust boundary"
    )]
    pub fn from_enabled(
        request: &McpRequestContext,
        server: &SkillServerIdentity,
        admitted: &AdmittedSkill,
        runtime_guard: &SkillRuntimeGuard,
        lifecycle_repository: &impl SkillLifecycleRepository,
        runtime_admission: &impl SkillRuntimeAdmission,
        registry: &CapabilityRegistry,
        principal_policy: &impl SkillPrincipalPolicy,
    ) -> Result<Self, ProjectionError> {
        let runtime = runtime_guard
            .authorize(
                request,
                server,
                admitted,
                lifecycle_repository,
                runtime_admission,
                registry,
                principal_policy,
            )
            .map_err(|_| ProjectionError::Disabled)?;
        runtime
            .require_admitted(admitted)
            .map_err(|_| ProjectionError::Disabled)?;
        let base = runtime.skill_uri().trim_end_matches('/');
        let files = admitted
            .manifest()
            .inventory
            .iter()
            .map(|entry| SkillFileDescriptor {
                uri: format!("{base}/{}", entry.path),
                digest: entry.digest.clone(),
                size: entry.size,
            })
            .collect();
        Ok(Self {
            runtime,
            frontmatter: admitted.manifest().frontmatter.clone(),
            files,
        })
    }

    /// Borrows the fresh request-scoped runtime proof behind this projection.
    #[must_use]
    pub const fn runtime(&self) -> &SkillRuntimeGrant {
        &self.runtime
    }

    /// Borrows bounded signed frontmatter. It remains untrusted display/instruction data.
    #[must_use]
    pub const fn frontmatter(&self) -> &Value {
        &self.frontmatter
    }

    /// Borrows the complete bounded static inventory projection.
    #[must_use]
    pub fn files(&self) -> &[SkillFileDescriptor] {
        &self.files
    }
}

impl fmt::Debug for SkillDescriptor {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SkillDescriptor([redacted])")
    }
}

/// Skills discovery projection failure.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum ProjectionError {
    /// Exact extension, canonical binding, lifecycle, provenance, registry, or policy denied use.
    #[error("Skill discovery is disabled")]
    Disabled,
}

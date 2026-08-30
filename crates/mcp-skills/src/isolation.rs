use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Maximum private scratch space granted to one execution.
pub const MAX_SCRATCH_BYTES: u64 = 64 * 1024 * 1024;
/// Maximum memory granted to one execution.
pub const MAX_MEMORY_BYTES: u64 = 1024 * 1024 * 1024;
/// Maximum execution duration.
pub const MAX_WALL_TIME_MILLIS: u64 = 5 * 60 * 1000;

/// Network is denied rather than inherited from the host.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NetworkPolicy {
    /// No sockets, DNS, or host network namespace.
    Denied,
}

/// Credential access policy.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CredentialPolicy {
    /// No host, MCP, cloud, tool, or user credentials are mounted.
    None,
}

/// Filesystem isolation profile.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FilesystemPolicy {
    /// Package content is mounted read-only.
    pub package_read_only: bool,
    /// Host root and working directory are not visible.
    pub host_filesystem_visible: bool,
    /// A private empty scratch mount is available.
    pub private_scratch: bool,
    /// Byte quota for that scratch mount.
    pub scratch_bytes: u64,
}

/// Process policy retained for forward-compatible manifests.
///
/// No executable format is currently supported. A non-empty format set is rejected because this
/// crate does not provide or enforce a sandboxed executor.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProcessPolicy {
    /// Must remain empty until a concrete enforced executor exists.
    #[serde(default)]
    pub executable_formats: BTreeSet<ExecutableFormat>,
    /// Maximum child process count reserved for a future enforced executor.
    pub max_processes: u16,
    /// Shell lookup and command-string execution are forbidden.
    pub shell: bool,
}

/// Executable formats recognized only so untrusted declarations can be rejected explicitly.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExecutableFormat {
    /// Unsupported WebAssembly content.
    Wasm,
    /// Unsupported Python source.
    Python,
    /// Unsupported JavaScript module.
    JavaScriptModule,
}

/// Complete least-privilege data-only profile.
///
/// This profile does not sandbox or execute package content.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExecutionProfile {
    /// Ambient network policy.
    pub network: NetworkPolicy,
    /// Filesystem mounts and quotas.
    pub filesystem: FilesystemPolicy,
    /// Credential mounting policy.
    pub credentials: CredentialPolicy,
    /// Whether any host environment variables are inherited.
    pub inherit_environment: bool,
    /// Process constraints. Executable formats must remain empty.
    pub process: ProcessPolicy,
    /// Maximum memory bytes.
    pub memory_bytes: u64,
    /// Maximum wall time in milliseconds.
    pub wall_time_millis: u64,
}

impl ExecutionProfile {
    /// Returns a data-only profile. It does not provide an executable sandbox.
    #[must_use]
    pub fn least_privilege() -> Self {
        Self {
            network: NetworkPolicy::Denied,
            filesystem: FilesystemPolicy {
                package_read_only: true,
                host_filesystem_visible: false,
                private_scratch: true,
                scratch_bytes: 8 * 1024 * 1024,
            },
            credentials: CredentialPolicy::None,
            inherit_environment: false,
            process: ProcessPolicy {
                executable_formats: BTreeSet::new(),
                max_processes: 1,
                shell: false,
            },
            memory_bytes: 256 * 1024 * 1024,
            wall_time_millis: 30_000,
        }
    }

    /// Validates the bounded data-only profile.
    ///
    /// # Errors
    ///
    /// Returns [`IsolationError::ExecutionUnsupported`] for every executable declaration because
    /// no enforced executor or sandbox exists.
    pub fn validate(&self) -> Result<(), IsolationError> {
        if !self.process.executable_formats.is_empty() {
            return Err(IsolationError::ExecutionUnsupported);
        }
        if !self.filesystem.package_read_only
            || self.filesystem.host_filesystem_visible
            || !self.filesystem.private_scratch
            || self.filesystem.scratch_bytes == 0
            || self.filesystem.scratch_bytes > MAX_SCRATCH_BYTES
            || self.inherit_environment
            || self.process.max_processes == 0
            || self.process.max_processes > 16
            || self.process.shell
            || self.memory_bytes == 0
            || self.memory_bytes > MAX_MEMORY_BYTES
            || self.wall_time_millis == 0
            || self.wall_time_millis > MAX_WALL_TIME_MILLIS
        {
            return Err(IsolationError::NotLeastPrivilege);
        }
        Ok(())
    }
}

/// Data-only profile rejection.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum IsolationError {
    /// Profile exposes ambient host authority or exceeds hard resource limits.
    #[error("Skill execution profile is not least privilege")]
    NotLeastPrivilege,
    /// Executable declarations are rejected because no enforced executor or sandbox exists.
    #[error("Skill execution is unsupported; executable content is not sandboxed")]
    ExecutionUnsupported,
}

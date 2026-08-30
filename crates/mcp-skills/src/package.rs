use std::{collections::BTreeSet, fmt};

use omnius_agent_capability_registry::{CapabilityKey, CapabilityRegistry};
use omnius_mcp_server_core::McpRequestContext;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::isolation::{ExecutableFormat, ExecutionProfile};
use crate::lifecycle::{
    RuntimeLeaseFinish, SkillLifecycleRepository, SkillRuntimeAdmission, SkillRuntimeGrant,
    SkillRuntimeGuard,
};
use crate::manifest::{
    AdmittedSkill, SkillBinding, SkillPrincipalPolicy, SkillProvenance, SkillServerIdentity,
};

/// Maximum files in a static Skill inventory.
pub const MAX_SKILL_FILES: usize = 512;
/// Maximum aggregate bytes in a static Skill inventory.
pub const MAX_SKILL_PACKAGE_BYTES: u64 = 16 * 1024 * 1024;
/// Required instruction file.
pub const SKILL_INSTRUCTIONS_PATH: &str = "SKILL.md";

/// Package entry type. Symbolic links are representable for detection and always rejected.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PackageEntryType {
    /// Regular immutable file.
    RegularFile,
    /// Symbolic link from a package archive or filesystem walker.
    SymbolicLink,
}

/// Declared role for a package file.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "role", rename_all = "snake_case")]
pub enum PackageFileKind {
    /// The unique `SKILL.md` file, always treated as untrusted instruction data.
    Instructions,
    /// Non-executable supporting content.
    Resource,
    /// Executable content recognized solely for explicit fail-closed rejection.
    Executable {
        /// Known but unsupported executable format.
        format: ExecutableFormat,
    },
}

impl PackageFileKind {
    /// Requires a file kind to be safe for generic data-only runtime reads.
    ///
    /// # Errors
    ///
    /// Every executable kind returns [`PackageReadError::ExecutionUnsupported`]. Recognizing a
    /// format does not mean it is sandboxed or executable by this crate.
    pub fn require_runtime_readable(self) -> Result<(), PackageReadError> {
        match self {
            Self::Instructions | Self::Resource => Ok(()),
            Self::Executable { .. } => Err(PackageReadError::ExecutionUnsupported),
        }
    }
}

/// Complete, content-addressed static package entry.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PackageEntry {
    /// Normalized relative package path.
    pub path: String,
    /// Exact file byte length.
    pub size: u64,
    /// Lowercase SHA-256 digest.
    pub digest: String,
    /// Exact bounded media type.
    pub media_type: String,
    /// Filesystem/archive entry type.
    pub entry_type: PackageEntryType,
    /// File role and optional fixed executable format.
    pub kind: PackageFileKind,
}

/// Complete bounded object-storage lookup for an immutable admitted package file.
#[derive(Clone, Copy, Debug)]
pub struct SkillArtifactLocator<'a> {
    /// Canonical tenant, principal, server, and installation binding.
    pub binding: &'a SkillBinding,
    /// Versioned Skill URI.
    pub skill_uri: &'a str,
    /// Immutable semantic package version.
    pub version: &'a str,
    /// Aggregate package digest.
    pub package_digest: &'a str,
    /// Verified signed-manifest provenance.
    pub provenance: &'a SkillProvenance,
    /// Exact registry capability revisions admitted with this package.
    pub capability_keys: &'a BTreeSet<CapabilityKey>,
    /// Fresh non-cloneable runtime lease for enabled reads; absent only during install verification.
    ///
    /// Repository adapters must reject a cancelled lease at the exact read boundary.
    pub runtime: Option<&'a SkillRuntimeGrant>,
    /// Normalized inventory path.
    pub path: &'a str,
    /// Expected file digest.
    pub file_digest: &'a str,
    /// Exact signed file size; the destination buffer has precisely this length.
    pub expected_size: u64,
    /// Absolute allocation ceiling the repository must enforce before reading the source.
    pub hard_max_size: u64,
}
/// Metadata returned only after an adapter filled the caller-owned exact-size buffer.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SkillArtifactMetadata {
    /// Authoritative object media type.
    pub media_type: String,
    /// Authoritative entry type from archive extraction or filesystem metadata.
    pub entry_type: PackageEntryType,
}

/// Typed outcome of a bounded exact artifact read.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SkillArtifactRead {
    /// The exact-size destination was filled and carries authoritative metadata.
    Complete(SkillArtifactMetadata),
    /// The source size differed; no partial or truncated object was accepted.
    SizeMismatch,
    /// The runtime lease lifecycle/revocation generation changed or was cancelled at read.
    StaleLease,
}

/// Object-storage boundary for immutable, fully scoped data-only Skill package files.
pub trait SkillArtifactRepository {
    /// Fills an exact-size caller-owned buffer without allocating from untrusted source length.
    ///
    /// The adapter must reject the source before reading when it exceeds `hard_max_size` or differs
    /// from `expected_size`. When `runtime` is present, it must reject cancellation and atomically
    /// verify that lease's exact lifecycle and revocation generations at the read boundary.
    ///
    /// # Errors
    ///
    /// Returns [`ArtifactRepositoryError`] when the scoped immutable object cannot be read or its
    /// authoritative metadata cannot be obtained.
    fn read_exact(
        &self,
        locator: &SkillArtifactLocator<'_>,
        destination: &mut [u8],
    ) -> Result<SkillArtifactRead, ArtifactRepositoryError>;
}

/// Redacted artifact repository failure.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[error("Skill artifact repository operation failed")]
pub struct ArtifactRepositoryError;

/// Verified data-only MCP resource content bound to one live non-cloneable runtime lease.
pub struct SkillFileContents {
    runtime: SkillRuntimeGrant,
    uri: String,
    media_type: String,
    bytes: Vec<u8>,
}

impl SkillFileContents {
    /// Borrows the live request-scoped runtime lease required to consume these bytes.
    #[must_use]
    pub const fn runtime(&self) -> &SkillRuntimeGrant {
        &self.runtime
    }

    /// Borrows the exact versioned `skill://` file URI.
    #[must_use]
    pub fn uri(&self) -> &str {
        &self.uri
    }

    /// Borrows the verified exact media type.
    #[must_use]
    pub fn media_type(&self) -> &str {
        &self.media_type
    }

    /// Borrows verified data-only bytes while the repository lease remains live.
    ///
    /// Instructions remain untrusted data and confer no authority. Executable kinds never reach
    /// this type because execution is unsupported and no sandboxed executor exists.
    ///
    /// # Errors
    ///
    /// Returns [`PackageReadError::LeaseFenced`] when lifecycle or revocation cancellation has
    /// invalidated the non-cloneable lease.
    pub fn bytes(&self) -> Result<&[u8], PackageReadError> {
        self.runtime
            .require_live()
            .map_err(|_| PackageReadError::LeaseFenced)?;
        Ok(&self.bytes)
    }

    /// Finishes the live lease and returns a final-effect fence or a fail-closed outcome.
    #[must_use]
    pub fn finish(self) -> RuntimeLeaseFinish {
        self.runtime.finish()
    }
}

impl PartialEq for SkillFileContents {
    fn eq(&self, other: &Self) -> bool {
        self.runtime == other.runtime
            && self.uri == other.uri
            && self.media_type == other.media_type
            && self.bytes == other.bytes
    }
}

impl Eq for SkillFileContents {}

impl fmt::Debug for SkillFileContents {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SkillFileContents([redacted])")
    }
}

/// Opaque proof that every static inventory entry and frontmatter was verified.
#[derive(Clone, Eq, PartialEq)]
pub struct VerifiedSkillPackage {
    binding: SkillBinding,
    skill_uri: String,
    version: String,
    package_digest: String,
    provenance: SkillProvenance,
    capability_keys: BTreeSet<CapabilityKey>,
}

impl VerifiedSkillPackage {
    /// Borrows the scoped canonical binding.
    #[must_use]
    pub const fn binding(&self) -> &SkillBinding {
        &self.binding
    }

    /// Returns the versioned Skill URI.
    #[must_use]
    pub fn skill_uri(&self) -> &str {
        &self.skill_uri
    }

    /// Returns the immutable semantic package version.
    #[must_use]
    pub fn version(&self) -> &str {
        &self.version
    }

    /// Returns the verified package digest.
    #[must_use]
    pub fn package_digest(&self) -> &str {
        &self.package_digest
    }

    /// Borrows the retained signature provenance.
    #[must_use]
    pub const fn provenance(&self) -> &SkillProvenance {
        &self.provenance
    }

    /// Borrows exact registry capability revisions admitted with this package.
    #[must_use]
    pub const fn capability_keys(&self) -> &BTreeSet<CapabilityKey> {
        &self.capability_keys
    }

    pub(crate) fn matches_admitted(&self, admitted: &AdmittedSkill) -> bool {
        let manifest = admitted.manifest();
        self.binding == *admitted.binding()
            && self.skill_uri == manifest.uri.as_str()
            && self.version == manifest.version
            && self.package_digest == manifest.package_digest
            && self.provenance == *admitted.provenance()
            && self.capability_keys == admitted_capability_keys(admitted)
    }
}

impl fmt::Debug for VerifiedSkillPackage {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("VerifiedSkillPackage([redacted])")
    }
}

struct VerifiedStoredSkillFile {
    uri: String,
    media_type: String,
    bytes: Vec<u8>,
}

/// Verifies immutable package objects against admitted inventory.
pub struct SkillPackageService<R> {
    repository: R,
}

impl<R> SkillPackageService<R>
where
    R: SkillArtifactRepository,
{
    /// Creates a package service around deployment-owned object storage.
    #[must_use]
    pub const fn new(repository: R) -> Self {
        Self { repository }
    }

    /// Reads one runtime resource after exact negotiation and all fresh authoritative checks.
    #[expect(
        clippy::too_many_arguments,
        reason = "each independent authority remains explicit at the runtime trust boundary"
    )]
    ///
    /// # Errors
    ///
    /// Returns [`PackageReadError`] when current runtime authority is denied or fenced, the path is
    /// unsafe or absent from the signed inventory, executable content is requested, repository
    /// access fails, stored integrity metadata differs, or `SKILL.md` frontmatter is invalid.
    pub fn read_enabled_file(
        &self,
        request: &McpRequestContext,
        server: &SkillServerIdentity,
        admitted: &AdmittedSkill,
        runtime_guard: &SkillRuntimeGuard,
        lifecycle_repository: &impl SkillLifecycleRepository,
        runtime_admission: &impl SkillRuntimeAdmission,
        registry: &CapabilityRegistry,
        principal_policy: &impl SkillPrincipalPolicy,
        path: &str,
    ) -> Result<SkillFileContents, PackageReadError> {
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
            .map_err(|_| PackageReadError::Disabled)?;
        runtime
            .require_admitted(admitted)
            .map_err(|_| PackageReadError::Disabled)?;
        let capability_keys = runtime_capability_keys(&runtime);
        let stored =
            self.read_verified_entry(admitted, Some((&runtime, &capability_keys)), path)?;
        runtime
            .require_live()
            .map_err(|_| PackageReadError::LeaseFenced)?;
        if path == SKILL_INSTRUCTIONS_PATH {
            verify_frontmatter(&stored.bytes, &admitted.manifest().frontmatter)?;
        }
        Ok(SkillFileContents {
            runtime,
            uri: stored.uri,
            media_type: stored.media_type,
            bytes: stored.bytes,
        })
    }

    /// Verifies every static entry and the exact parsed `SKILL.md` frontmatter before installation.
    ///
    /// # Errors
    ///
    /// Returns [`PackageReadError`] when an inventory path is unsafe or missing, repository access
    /// fails, stored type, size, digest, or media type differs, executable content is encountered,
    /// or signed `SKILL.md` frontmatter does not match the immutable object.
    pub fn verify_package(
        &self,
        admitted: &AdmittedSkill,
    ) -> Result<VerifiedSkillPackage, PackageReadError> {
        for entry in &admitted.manifest().inventory {
            let contents = self.read_verified_entry(admitted, None, &entry.path)?;
            if entry.path == SKILL_INSTRUCTIONS_PATH {
                verify_frontmatter(&contents.bytes, &admitted.manifest().frontmatter)?;
            }
        }
        Ok(VerifiedSkillPackage {
            binding: admitted.binding().clone(),
            skill_uri: admitted.manifest().uri.as_str().to_owned(),
            version: admitted.manifest().version.clone(),
            package_digest: admitted.manifest().package_digest.clone(),
            provenance: admitted.provenance().clone(),
            capability_keys: admitted_capability_keys(admitted),
        })
    }

    fn read_verified_entry(
        &self,
        admitted: &AdmittedSkill,
        runtime: Option<(&SkillRuntimeGrant, &BTreeSet<CapabilityKey>)>,
        path: &str,
    ) -> Result<VerifiedStoredSkillFile, PackageReadError> {
        if !is_safe_relative_path(path) {
            return Err(PackageReadError::InvalidPath);
        }
        let manifest = admitted.manifest();
        let entry = manifest
            .inventory
            .iter()
            .find(|entry| entry.path == path)
            .ok_or(PackageReadError::UnlistedFile)?;
        if runtime.is_some() {
            entry.kind.require_runtime_readable()?;
        }
        let admitted_keys;
        let (binding, skill_uri, version, package_digest, provenance, capability_keys) =
            if let Some((runtime, capability_keys)) = runtime {
                runtime
                    .require_live()
                    .map_err(|_| PackageReadError::LeaseFenced)?;
                (
                    runtime.binding(),
                    runtime.skill_uri(),
                    runtime.version(),
                    runtime.package_digest(),
                    runtime.provenance(),
                    capability_keys,
                )
            } else {
                admitted_keys = admitted_capability_keys(admitted);
                (
                    admitted.binding(),
                    manifest.uri.as_str(),
                    manifest.version.as_str(),
                    manifest.package_digest.as_str(),
                    admitted.provenance(),
                    &admitted_keys,
                )
            };
        if entry.size == 0 || entry.size > MAX_SKILL_PACKAGE_BYTES {
            return Err(PackageReadError::IntegrityMismatch);
        }
        let exact_size =
            usize::try_from(entry.size).map_err(|_| PackageReadError::IntegrityMismatch)?;
        let mut bytes = vec![0; exact_size];
        let read = self
            .repository
            .read_exact(
                &SkillArtifactLocator {
                    binding,
                    skill_uri,
                    version,
                    package_digest,
                    provenance,
                    capability_keys,
                    runtime: runtime.map(|(runtime, _)| runtime),
                    path,
                    file_digest: &entry.digest,
                    expected_size: entry.size,
                    hard_max_size: MAX_SKILL_PACKAGE_BYTES,
                },
                &mut bytes,
            )
            .map_err(|_| PackageReadError::Unavailable)?;
        let metadata = match read {
            SkillArtifactRead::Complete(metadata) => metadata,
            SkillArtifactRead::SizeMismatch => return Err(PackageReadError::IntegrityMismatch),
            SkillArtifactRead::StaleLease => return Err(PackageReadError::LeaseFenced),
        };
        if let Some((runtime, _)) = runtime {
            runtime
                .require_live()
                .map_err(|_| PackageReadError::LeaseFenced)?;
        }
        verify_stored_entry(entry, &metadata, &bytes)?;
        Ok(VerifiedStoredSkillFile {
            uri: format!("{}/{}", skill_uri.trim_end_matches('/'), path),
            media_type: metadata.media_type,
            bytes,
        })
    }
}

/// Static inventory validation error.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum InventoryError {
    /// Inventory file or byte bounds were exceeded.
    #[error("Skill inventory exceeds package bounds")]
    Bounds,
    /// A path was absolute, traversing, ambiguous, duplicated, or unsorted.
    #[error("invalid Skill inventory path")]
    InvalidPath,
    /// Symbolic links are forbidden.
    #[error("Skill package symbolic links are forbidden")]
    SymbolicLink,
    /// Digest, size, or media type metadata was malformed.
    #[error("invalid Skill inventory integrity metadata")]
    InvalidIntegrity,
    /// Required `SKILL.md` declaration was absent or ambiguous.
    #[error("invalid Skill instructions entry")]
    InvalidInstructions,
    /// Executable content is rejected because no enforced executor or sandbox exists.
    #[error("Skill execution is unsupported; executable content is not sandboxed")]
    ExecutionUnsupported,
}

/// Package read and verification error.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum PackageReadError {
    /// Requested path is unsafe.
    #[error("invalid Skill file path")]
    InvalidPath,
    /// Requested path is not in the signed static inventory.
    #[error("unlisted Skill file")]
    UnlistedFile,
    /// Exact negotiation, canonical binding, registry policy, provenance, or lifecycle denied use.
    #[error("Skill resource is disabled")]
    Disabled,
    /// The live package-read lease was cancelled by lifecycle or revocation fencing.
    #[error("Skill package read lease is fenced")]
    LeaseFenced,
    /// Artifact repository was unavailable.
    #[error("Skill artifact unavailable")]
    Unavailable,
    /// Stored type, size, digest, or media type differs from signed inventory.
    #[error("Skill artifact integrity mismatch")]
    IntegrityMismatch,
    /// `SKILL.md` is not UTF-8 or its bounded frontmatter differs from signed metadata.
    #[error("Skill frontmatter mismatch")]
    FrontmatterMismatch,
    /// Generic reads never expose executable bytes because execution is unsupported.
    #[error("Skill execution is unsupported; executable content is not sandboxed")]
    ExecutionUnsupported,
}

/// Validates the bounded deterministic static inventory.
///
/// # Errors
///
/// Returns [`InventoryError`] when executable content is declared; file or aggregate bounds are
/// exceeded; inventory or package integrity is invalid; paths are unsafe, duplicated, or unsorted;
/// symbolic links are present; or exactly one valid `SKILL.md` instruction entry is not declared.
pub fn validate_inventory(
    entries: &[PackageEntry],
    package_digest: &str,
    execution: &ExecutionProfile,
) -> Result<(), InventoryError> {
    if !execution.process.executable_formats.is_empty() {
        return Err(InventoryError::ExecutionUnsupported);
    }
    if entries.is_empty() || entries.len() > MAX_SKILL_FILES || !is_sha256_digest(package_digest) {
        return Err(InventoryError::Bounds);
    }
    if inventory_digest(entries).as_deref() != Some(package_digest) {
        return Err(InventoryError::InvalidIntegrity);
    }
    let mut total_bytes = 0_u64;
    let mut previous_path: Option<&str> = None;
    let mut instruction_count = 0_usize;
    for entry in entries {
        if !is_safe_relative_path(&entry.path)
            || previous_path.is_some_and(|previous| previous >= entry.path.as_str())
        {
            return Err(InventoryError::InvalidPath);
        }
        previous_path = Some(&entry.path);
        if entry.entry_type == PackageEntryType::SymbolicLink {
            return Err(InventoryError::SymbolicLink);
        }
        if entry.size == 0 || !is_sha256_digest(&entry.digest) || !is_media_type(&entry.media_type)
        {
            return Err(InventoryError::InvalidIntegrity);
        }
        total_bytes = total_bytes
            .checked_add(entry.size)
            .ok_or(InventoryError::Bounds)?;
        if total_bytes > MAX_SKILL_PACKAGE_BYTES {
            return Err(InventoryError::Bounds);
        }
        match entry.kind {
            PackageFileKind::Instructions if entry.path == SKILL_INSTRUCTIONS_PATH => {
                instruction_count += 1;
            }
            PackageFileKind::Instructions => return Err(InventoryError::InvalidInstructions),
            PackageFileKind::Executable { .. } => {
                return Err(InventoryError::ExecutionUnsupported);
            }
            PackageFileKind::Resource => {}
        }
    }
    if instruction_count != 1 {
        return Err(InventoryError::InvalidInstructions);
    }
    Ok(())
}

fn is_media_type(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value.bytes().all(|byte| byte.is_ascii_graphic())
        && value.contains('/')
}

/// Checks a path before object lookup or URI construction.
#[must_use]
pub fn is_safe_relative_path(path: &str) -> bool {
    !path.is_empty()
        && path.len() <= 256
        && !path.starts_with('/')
        && !path.contains(['\\', '\0', '%', ':'])
        && path.split('/').all(|segment| {
            !segment.is_empty()
                && segment != "."
                && segment != ".."
                && segment
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_'))
        })
}

/// Returns the deterministic digest of the signed ordered inventory.
#[must_use]
pub fn inventory_digest(entries: &[PackageEntry]) -> Option<String> {
    serde_json::to_vec(entries)
        .ok()
        .map(|encoded| sha256_digest(&encoded))
}

/// Returns a lowercase SHA-256 content address.
#[must_use]
pub fn sha256_digest(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let digest = Sha256::digest(bytes);
    let mut encoded = String::with_capacity("sha256:".len() + digest.len() * 2);
    encoded.push_str("sha256:");

    for byte in digest {
        encoded.push(char::from(HEX[usize::from(byte >> 4)]));
        encoded.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    encoded
}

pub(crate) fn is_sha256_digest(value: &str) -> bool {
    value.strip_prefix("sha256:").is_some_and(|hex| {
        hex.len() == 64
            && hex
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    })
}

fn verify_stored_entry(
    entry: &PackageEntry,
    metadata: &SkillArtifactMetadata,
    bytes: &[u8],
) -> Result<(), PackageReadError> {
    if metadata.entry_type != PackageEntryType::RegularFile
        || metadata.media_type != entry.media_type
        || u64::try_from(bytes.len()).ok() != Some(entry.size)
        || sha256_digest(bytes) != entry.digest
    {
        return Err(PackageReadError::IntegrityMismatch);
    }
    Ok(())
}

fn verify_frontmatter(bytes: &[u8], expected: &Value) -> Result<(), PackageReadError> {
    let text = std::str::from_utf8(bytes).map_err(|_| PackageReadError::FrontmatterMismatch)?;
    let frontmatter = extract_frontmatter(text).ok_or(PackageReadError::FrontmatterMismatch)?;
    let parsed = serde_yaml::from_str::<Value>(frontmatter)
        .map_err(|_| PackageReadError::FrontmatterMismatch)?;
    if &parsed != expected {
        return Err(PackageReadError::FrontmatterMismatch);
    }
    Ok(())
}

fn extract_frontmatter(text: &str) -> Option<&str> {
    let rest = text.strip_prefix("---\n")?;
    let end = rest.find("\n---\n")?;
    Some(&rest[..end])
}

fn admitted_capability_keys(admitted: &AdmittedSkill) -> BTreeSet<CapabilityKey> {
    admitted
        .capabilities()
        .iter()
        .map(|capability| capability.key().clone())
        .collect()
}

fn runtime_capability_keys(runtime: &SkillRuntimeGrant) -> BTreeSet<CapabilityKey> {
    runtime
        .capabilities()
        .iter()
        .map(|capability| capability.key().clone())
        .collect()
}

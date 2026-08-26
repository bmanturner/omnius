use std::collections::{BTreeMap, BTreeSet};
#[cfg(any(target_os = "linux", target_os = "macos"))]
use std::fs::File;
#[cfg(any(target_os = "linux", target_os = "macos"))]
use std::io::Read as _;
use std::path::Path;

use fluent_bundle::FluentResource;
use fluent_bundle::concurrent::FluentBundle;
use fluent_langneg::{NegotiationStrategy, negotiate_languages};
#[cfg(any(target_os = "linux", target_os = "macos"))]
use rustix::fs::{FileType, Mode, OFlags, fstat, open, openat};
use thiserror::Error;
use unic_langid::LanguageIdentifier;

use crate::{Locale, NegotiationError};

const HARD_MAX_CATALOG_BYTES: usize = 1_048_576;
const HARD_MAX_CATALOGS: usize = 64;
const HARD_MAX_FALLBACK_DEPTH: usize = 16;
const HARD_MAX_ARGUMENT_COUNT: usize = 64;
const HARD_MAX_ARGUMENT_BYTES: usize = 16_384;
const HARD_MAX_RENDERED_BYTES: usize = 1_048_576;

/// Runtime and catalog bounds enforced before a snapshot is published.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CatalogLimits {
    catalog_bytes: usize,
    catalogs: usize,
    fallback_depth: usize,
    arguments: usize,
    argument_bytes: usize,
    rendered_bytes: usize,
}

impl CatalogLimits {
    /// Creates limits below immutable safety ceilings.
    ///
    /// # Errors
    ///
    /// Returns [`LimitsError`] when any value is zero or exceeds its immutable safety ceiling.
    pub fn new(
        catalog_bytes: usize,
        catalogs: usize,
        fallback_depth: usize,
        arguments: usize,
        argument_bytes: usize,
        rendered_bytes: usize,
    ) -> Result<Self, LimitsError> {
        let limits = Self {
            catalog_bytes,
            catalogs,
            fallback_depth,
            arguments,
            argument_bytes,
            rendered_bytes,
        };
        limits.validate()?;
        Ok(limits)
    }

    fn validate(self) -> Result<(), LimitsError> {
        let valid = (1..=HARD_MAX_CATALOG_BYTES).contains(&self.catalog_bytes)
            && (1..=HARD_MAX_CATALOGS).contains(&self.catalogs)
            && (1..=HARD_MAX_FALLBACK_DEPTH).contains(&self.fallback_depth)
            && (1..=HARD_MAX_ARGUMENT_COUNT).contains(&self.arguments)
            && (1..=HARD_MAX_ARGUMENT_BYTES).contains(&self.argument_bytes)
            && (1..=HARD_MAX_RENDERED_BYTES).contains(&self.rendered_bytes);
        if valid { Ok(()) } else { Err(LimitsError) }
    }
    pub(crate) const fn catalogs(self) -> usize {
        self.catalogs
    }

    pub(crate) const fn arguments(self) -> usize {
        self.arguments
    }

    pub(crate) const fn argument_bytes(self) -> usize {
        self.argument_bytes
    }

    pub(crate) const fn rendered_bytes(self) -> usize {
        self.rendered_bytes
    }
}

impl Default for CatalogLimits {
    fn default() -> Self {
        Self {
            catalog_bytes: 262_144,
            catalogs: 32,
            fallback_depth: 8,
            arguments: 32,
            argument_bytes: 8_192,
            rendered_bytes: 262_144,
        }
    }
}

/// A redacted invalid-limits error.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[error("localization limits exceed safety bounds")]
pub struct LimitsError;

/// Configuration for one locale catalog and its explicit fallback locales.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LocaleCatalog {
    locale: Locale,
    fallbacks: Vec<Locale>,
}

impl LocaleCatalog {
    /// Creates a locale catalog entry.
    ///
    /// The default locale must have no fallbacks. Every other locale must end its fallback list with
    /// the configured default locale. Validation occurs before file access.
    #[must_use]
    pub fn new(locale: Locale, fallbacks: Vec<Locale>) -> Self {
        Self { locale, fallbacks }
    }

    /// Returns this entry's locale.
    #[must_use]
    pub const fn locale(&self) -> &Locale {
        &self.locale
    }

    /// Returns the configured fallback locales, excluding the entry's own locale.
    #[must_use]
    pub fn fallbacks(&self) -> &[Locale] {
        &self.fallbacks
    }
}

/// Trusted deployment configuration for a complete catalog snapshot.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CatalogConfig {
    default_locale: Locale,
    catalogs: Vec<LocaleCatalog>,
}

impl CatalogConfig {
    /// Creates catalog configuration. `CatalogLoader::load` validates the complete graph.
    #[must_use]
    pub fn new(default_locale: Locale, catalogs: Vec<LocaleCatalog>) -> Self {
        Self {
            default_locale,
            catalogs,
        }
    }

    /// Returns the default locale.
    #[must_use]
    pub const fn default_locale(&self) -> &Locale {
        &self.default_locale
    }

    /// Returns all configured catalogs.
    #[must_use]
    pub fn catalogs(&self) -> &[LocaleCatalog] {
        &self.catalogs
    }
}

/// A loader confined to a trusted, non-symlink catalog directory.
///
/// Each catalog is a single flat file named from its canonical locale (for example,
/// `en-US.ftl`). Callers cannot provide catalog paths.
/// Files must be regular, single-linked, and owned by the catalog-directory owner.
///
/// A multi-locale deployment must stage an immutable versioned directory and construct a new loader
/// for reload; changing separate files in place cannot represent one coherent catalog generation.
pub struct CatalogLoader {
    directory: TrustedCatalogDirectory,
    limits: CatalogLimits,
}

impl CatalogLoader {
    /// Opens a trusted catalog root through a non-following directory descriptor.
    ///
    /// # Errors
    ///
    /// Returns [`CatalogError`] when the platform cannot provide descriptor-relative safe access,
    /// or when the root cannot be opened without following symlinks as a regular directory.
    pub fn new(root: impl AsRef<Path>, limits: CatalogLimits) -> Result<Self, CatalogError> {
        let directory = open_trusted_catalog_directory(root.as_ref())?;
        Ok(Self { directory, limits })
    }

    /// Loads and validates every catalog before returning a publishable snapshot.
    ///
    /// # Errors
    ///
    /// Returns [`CatalogError`] for invalid configuration, unsafe or inaccessible files, exceeded
    /// bounds, invalid UTF-8 or Fluent syntax, and duplicate identifiers.
    pub fn load(&self, config: &CatalogConfig) -> Result<CatalogSnapshot, CatalogError> {
        let layout = validate_config(config, self.limits)?;
        let mut catalogs = Vec::with_capacity(config.catalogs.len());

        for spec in &config.catalogs {
            let source = self.read_catalog(&spec.locale)?;
            let resource = FluentResource::try_new(source)
                .map_err(|(_partial, _errors)| CatalogError::InvalidSyntax)?;
            let mut bundle = FluentBundle::new_concurrent(vec![spec.locale.language_id().clone()]);
            bundle
                .add_resource(resource)
                .map_err(|_errors| CatalogError::DuplicateIdentifier)?;
            catalogs.push(Catalog {
                locale: spec.locale.clone(),
                bundle,
            });
        }

        let available_ids = catalogs
            .iter()
            .map(|catalog| catalog.locale.language_id().clone())
            .collect();
        Ok(CatalogSnapshot {
            catalogs,
            chains: layout.chains,
            available_ids,
            default_index: layout.default_index,
            limits: self.limits,
        })
    }

    fn read_catalog(&self, locale: &Locale) -> Result<String, CatalogError> {
        let file_name = format!("{}.ftl", locale.as_str());
        read_trusted_catalog(&self.directory, &file_name, self.limits.catalog_bytes)
    }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
struct TrustedCatalogDirectory {
    file: File,
    owner: u32,
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
struct TrustedCatalogDirectory;

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn open_trusted_catalog_directory(path: &Path) -> Result<TrustedCatalogDirectory, CatalogError> {
    let descriptor = open(
        path,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|_| CatalogError::FileAccess)?;
    let file = File::from(descriptor);
    let stat = fstat(&file).map_err(|_| CatalogError::FileAccess)?;
    if !FileType::from_raw_mode(stat.st_mode).is_dir() {
        return Err(CatalogError::UnsafePath);
    }
    Ok(TrustedCatalogDirectory {
        file,
        owner: stat.st_uid,
    })
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn open_trusted_catalog_directory(_path: &Path) -> Result<TrustedCatalogDirectory, CatalogError> {
    Err(CatalogError::UnsafePath)
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn read_trusted_catalog(
    directory: &TrustedCatalogDirectory,
    relative: &str,
    maximum: usize,
) -> Result<String, CatalogError> {
    let descriptor = openat(
        &directory.file,
        relative,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK,
        Mode::empty(),
    )
    .map_err(|_| CatalogError::FileAccess)?;
    let file = File::from(descriptor);
    let before = fstat(&file).map_err(|_| CatalogError::FileAccess)?;
    if !FileType::from_raw_mode(before.st_mode).is_file()
        || before.st_nlink != 1
        || before.st_uid != directory.owner
    {
        return Err(CatalogError::UnsafePath);
    }
    let file_len = usize::try_from(before.st_size).map_err(|_| CatalogError::CatalogTooLarge)?;
    if file_len > maximum {
        return Err(CatalogError::CatalogTooLarge);
    }
    let read_limit = u64::try_from(maximum)
        .map_err(|_| CatalogError::CatalogTooLarge)?
        .checked_add(1)
        .ok_or(CatalogError::CatalogTooLarge)?;
    let mut bytes = Vec::with_capacity(file_len.saturating_add(1));
    let mut reader = (&file).take(read_limit);
    reader
        .read_to_end(&mut bytes)
        .map_err(|_| CatalogError::FileAccess)?;
    if bytes.len() > maximum {
        return Err(CatalogError::CatalogTooLarge);
    }
    let after = fstat(&file).map_err(|_| CatalogError::FileAccess)?;
    if before.st_dev != after.st_dev
        || before.st_ino != after.st_ino
        || before.st_size != after.st_size
        || before.st_mtime != after.st_mtime
        || before.st_mtime_nsec != after.st_mtime_nsec
        || before.st_ctime != after.st_ctime
        || before.st_ctime_nsec != after.st_ctime_nsec
    {
        return Err(CatalogError::CatalogChanged);
    }
    String::from_utf8(bytes).map_err(|_| CatalogError::InvalidEncoding)
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn read_trusted_catalog(
    _directory: &TrustedCatalogDirectory,
    _relative: &str,
    _maximum: usize,
) -> Result<String, CatalogError> {
    Err(CatalogError::UnsafePath)
}

struct ValidatedLayout {
    chains: Vec<Vec<usize>>,
    default_index: usize,
}

fn validate_config(
    config: &CatalogConfig,
    limits: CatalogLimits,
) -> Result<ValidatedLayout, CatalogError> {
    if config.catalogs.is_empty() || config.catalogs.len() > limits.catalogs {
        return Err(CatalogError::InvalidConfiguration);
    }

    let mut index_by_locale = BTreeMap::new();
    for (index, spec) in config.catalogs.iter().enumerate() {
        if index_by_locale.insert(spec.locale.clone(), index).is_some() {
            return Err(CatalogError::DuplicateLocale);
        }
    }
    let Some(&default_index) = index_by_locale.get(&config.default_locale) else {
        return Err(CatalogError::InvalidConfiguration);
    };

    let mut chains = Vec::with_capacity(config.catalogs.len());
    for (index, spec) in config.catalogs.iter().enumerate() {
        if spec.fallbacks.len().saturating_add(1) > limits.fallback_depth {
            return Err(CatalogError::FallbackTooDeep);
        }
        if index == default_index {
            if !spec.fallbacks.is_empty() {
                return Err(CatalogError::InvalidFallback);
            }
        } else if spec.fallbacks.last() != Some(&config.default_locale) {
            return Err(CatalogError::InvalidFallback);
        }

        let mut seen = BTreeSet::new();
        seen.insert(spec.locale.clone());
        let mut chain = Vec::with_capacity(spec.fallbacks.len().saturating_add(1));
        chain.push(index);
        for fallback in &spec.fallbacks {
            if !seen.insert(fallback.clone()) {
                return Err(CatalogError::InvalidFallback);
            }
            let Some(&fallback_index) = index_by_locale.get(fallback) else {
                return Err(CatalogError::InvalidFallback);
            };
            chain.push(fallback_index);
        }
        chains.push(chain);
    }

    Ok(ValidatedLayout {
        chains,
        default_index,
    })
}

pub(crate) struct Catalog {
    pub(crate) locale: Locale,
    pub(crate) bundle: FluentBundle<FluentResource>,
}

/// An immutable, fully validated collection of locale catalogs.
pub struct CatalogSnapshot {
    pub(crate) catalogs: Vec<Catalog>,
    pub(crate) chains: Vec<Vec<usize>>,
    available_ids: Vec<LanguageIdentifier>,
    default_index: usize,
    pub(crate) limits: CatalogLimits,
}

impl CatalogSnapshot {
    /// Returns the configured default locale.
    #[must_use]
    pub fn default_locale(&self) -> &Locale {
        &self.catalogs[self.default_index].locale
    }

    /// Iterates the bounded set of configured locales.
    #[must_use]
    pub fn available_locales(&self) -> impl ExactSizeIterator<Item = &Locale> {
        self.catalogs.iter().map(|catalog| &catalog.locale)
    }

    pub(crate) fn negotiate(&self, requested: &[Locale]) -> Result<usize, NegotiationError> {
        if requested.len() > self.limits.catalogs() {
            return Err(NegotiationError);
        }
        let requested_ids: Vec<LanguageIdentifier> = requested
            .iter()
            .map(|locale| locale.language_id().clone())
            .collect();
        let matched = negotiate_languages(
            &requested_ids,
            &self.available_ids,
            Some(&self.available_ids[self.default_index]),
            NegotiationStrategy::Lookup,
        );
        Ok(matched
            .first()
            .and_then(|selected| {
                self.available_ids
                    .iter()
                    .position(|available| available == *selected)
            })
            .unwrap_or(self.default_index))
    }
}

/// A redacted catalog loading or validation failure.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum CatalogError {
    /// The catalog configuration is empty, oversized, or lacks its default locale.
    #[error("invalid catalog configuration")]
    InvalidConfiguration,
    /// A locale appears more than once.
    #[error("duplicate catalog locale")]
    DuplicateLocale,
    /// A fallback chain is cyclic, incomplete, or references an unavailable locale.
    #[error("invalid fallback chain")]
    InvalidFallback,
    /// A fallback chain exceeds its configured depth.
    #[error("fallback chain exceeds limit")]
    FallbackTooDeep,
    /// The opened catalog root or descriptor is not the required directory/regular-file type.
    #[error("unsafe catalog path")]
    UnsafePath,
    /// A root or catalog file was missing, refused (including symlinks), or otherwise inaccessible.
    /// Paths and operating-system details are redacted.
    #[error("catalog file access failed")]
    FileAccess,
    /// A catalog exceeds its configured byte limit.
    #[error("catalog exceeds size limit")]
    CatalogTooLarge,
    /// A catalog changed while its bounded snapshot was being read.
    #[error("catalog changed while loading")]
    CatalogChanged,
    /// A catalog is not UTF-8.
    #[error("catalog encoding is invalid")]
    InvalidEncoding,
    /// Fluent rejected catalog syntax. Source text and parser diagnostics are redacted.
    #[error("catalog syntax is invalid")]
    InvalidSyntax,
    /// Fluent found a duplicate message or term identifier.
    #[error("catalog contains a duplicate identifier")]
    DuplicateIdentifier,
}

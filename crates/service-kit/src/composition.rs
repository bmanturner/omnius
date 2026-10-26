//! Composition inputs, application configuration, and composition failures.

use std::{error::Error, fmt, time::Duration};

use omnius_core::ProviderMetadata;
use omnius_runtime::Criticality;
use serde::Deserialize;

#[cfg(any(feature = "core", test))]
use crate::SelectedModuleContract;
use crate::catalog;

/// Immutable inputs generated from the resolved profile selection.
#[derive(Clone, Copy, Debug)]
#[non_exhaustive]
pub struct CompositionInput {
    /// Selected profile ID.
    pub profile: &'static str,
    /// Selected module IDs in prerequisite-first order.
    pub modules: &'static [&'static str],
    /// Selected provider slots and modules.
    pub providers: &'static [ProviderMetadata],
    #[cfg(any(feature = "core", test))]
    /// Root-owned canonical contracts for the compiled feature set.
    pub(crate) contracts: &'static [SelectedModuleContract],
    /// Runtime-toggle modules explicitly disabled by configuration.
    pub runtime_disabled_modules: &'static [&'static str],
}
impl CompositionInput {
    /// Builds input from generator-owned profile metadata and contracts.
    #[must_use]
    pub const fn generated(
        profile: &'static str,
        modules: &'static [&'static str],
        providers: &'static [ProviderMetadata],
        runtime_disabled_modules: &'static [&'static str],
    ) -> Self {
        Self {
            profile,
            modules,
            providers,
            #[cfg(any(feature = "core", test))]
            contracts: catalog::COMPILED_CONTRACTS,
            runtime_disabled_modules,
        }
    }
}
/// Returns whether any selected module requires an application-owned contribution.
#[must_use]
pub fn selected_requires_application_contributions() -> bool {
    catalog::COMPILED_CONTRACTS
        .iter()
        .any(|contract| !contract.application_requirements.is_empty())
}

/// Configuration for the application-owned service-wide local request limit.
#[derive(Clone, Copy, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApplicationRateLimitConfig {
    /// Whether the selected runtime-toggle limiter is active.
    pub enabled: bool,
    /// Time required to replenish one request token.
    #[serde(with = "humantime_serde")]
    pub replenish_every: Duration,
    /// Maximum immediately available request tokens.
    pub burst_size: u32,
    /// Hard bound on in-memory identity buckets.
    pub identity_buckets: u32,
}

/// Stable failure returned while constructing an application extension.
#[derive(Debug)]
pub enum ApplicationExtensionError {
    /// The selected profile did not construct a PostgreSQL pool.
    MissingPostgresPool,
    /// The selected profile did not construct an idempotency store.
    MissingIdempotencyStore,
    /// The selected profile did not construct outbound HTTP clients.
    MissingOutboundHttpClients,
}

impl fmt::Display for ApplicationExtensionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingPostgresPool => {
                formatter.write_str("application extension requires a selected PostgreSQL pool")
            }
            Self::MissingIdempotencyStore => {
                formatter.write_str("application extension requires a selected idempotency store")
            }
            Self::MissingOutboundHttpClients => {
                formatter.write_str("application extension requires selected outbound HTTP clients")
            }
        }
    }
}

impl Error for ApplicationExtensionError {}

/// Failure returned while consuming the application-owned configuration subtree.
#[derive(Debug)]
pub enum ApplicationConfigError {
    /// The subtree was already consumed by an earlier deserialization attempt.
    AlreadyDeserialized,
    /// The subtree did not match the requested strict application type.
    Deserialize(serde_json::Error),
}

impl fmt::Display for ApplicationConfigError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AlreadyDeserialized => {
                formatter.write_str("application configuration was already deserialized")
            }
            Self::Deserialize(error) => {
                write!(formatter, "invalid application configuration: {error}")
            }
        }
    }
}

impl Error for ApplicationConfigError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::AlreadyDeserialized => None,
            Self::Deserialize(error) => Some(error),
        }
    }
}
/// Catalog criticality translated at the generated application boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CompositionCriticality {
    /// Construction or final task failure makes the service unavailable.
    Required,
    /// Failure keeps the core service up while reporting degradation.
    Degraded,
    /// Failure is diagnostic and does not affect readiness.
    BestEffort,
}

impl From<CompositionCriticality> for Criticality {
    fn from(value: CompositionCriticality) -> Self {
        match value {
            CompositionCriticality::Required => Self::Required,
            CompositionCriticality::Degraded => Self::Degraded,
            CompositionCriticality::BestEffort => Self::BestEffort,
        }
    }
}
/// Static application composition failure.
#[derive(Debug, Eq, PartialEq)]
pub enum CompositionError {
    /// Generated module IDs differ from the ordered compiled feature set.
    SelectionMismatch,
    /// A known runtime module was selected without compiling its feature.
    FeatureNotEnabled {
        /// Selected module ID.
        module: &'static str,
    },
    /// A selected module ID is not a runtime module in the catalog.
    UnknownModule {
        /// Selected module ID.
        module: &'static str,
    },
    /// A selected module requires an application-owned domain port.
    MissingContribution {
        /// Selected module ID.
        module: &'static str,
        /// Stable contribution requirement.
        contribution: &'static str,
    },
    /// A command is structurally unavailable in the selected profile.
    CommandUnavailable {
        /// Selected profile ID.
        profile: &'static str,
        /// Requested command.
        command: &'static str,
    },
    /// The same runtime contract was registered twice.
    DuplicateRegistration {
        /// Contract kind.
        kind: &'static str,
        /// Contract ID.
        id: &'static str,
    },
    /// A bounded runtime collection reached its fixed cardinality.
    CapacityExceeded {
        /// Runtime collection kind.
        kind: &'static str,
        /// Fixed maximum cardinality.
        maximum: usize,
    },
    /// A selected catalog contract was not registered by its owning module.
    ContractMismatch {
        /// Contract kind.
        kind: &'static str,
        /// Contract ID.
        id: &'static str,
    },
    /// A selected built-in registrar rejected its typed configuration.
    InvalidConfiguration {
        /// Selected module ID.
        module: &'static str,
    },
}

impl CompositionError {
    /// Creates the canonical error for a command absent from the selected composition.
    #[must_use]
    pub const fn command_unavailable(profile: &'static str, command: &'static str) -> Self {
        Self::CommandUnavailable { profile, command }
    }

    #[cfg(any(feature = "postgres", feature = "outbound-http", feature = "openapi"))]
    pub(crate) fn construction(module: &'static str, _error: impl Error) -> Self {
        Self::InvalidConfiguration { module }
    }
}

impl fmt::Display for CompositionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SelectionMismatch => formatter.write_str(
                "selected modules do not match the ordered compiled service-kit features",
            ),
            Self::FeatureNotEnabled { module } => {
                write!(
                    formatter,
                    "module `{module}` is not enabled in this service-kit build"
                )
            }
            Self::UnknownModule { module } => {
                write!(formatter, "module `{module}` is not a known runtime module")
            }
            Self::MissingContribution {
                module,
                contribution,
            } => write!(
                formatter,
                "module `{module}` requires application contribution `{contribution}`"
            ),
            Self::CommandUnavailable { profile, command } => write!(
                formatter,
                "command `{command}` is unavailable for profile `{profile}`"
            ),
            Self::DuplicateRegistration { kind, id } => {
                write!(formatter, "duplicate {kind} registration `{id}`")
            }
            Self::CapacityExceeded { kind, maximum } => {
                write!(formatter, "{kind} capacity exceeds fixed maximum {maximum}")
            }
            Self::ContractMismatch { kind, id } => {
                write!(
                    formatter,
                    "selected {kind} contract `{id}` was not registered"
                )
            }
            Self::InvalidConfiguration { module } => {
                write!(formatter, "module `{module}` configuration is invalid")
            }
        }
    }
}

impl Error for CompositionError {}

//! Deterministic service generation and safe catalog-driven module management.

mod application_templates;
mod cargo_resolver;
pub mod cargo_service;
mod catalog;
mod journal;
mod lifecycle;
mod manager;
mod modules;
mod provenance;
mod region;
mod release;
mod render;
mod revision;
mod state;
mod upgrade;

pub use cargo_resolver::{
    CargoDependency, CargoDependencyKind, CargoGraph, CargoGraphDifference, CargoGraphEdge,
    CargoGraphError, CargoInvocation, CargoLockfileResolver, CargoMetadataError, CargoNode,
    CargoPackage, CargoResolverError, CargoResolverMode, CargoResolverRequest, CargoResolverResult,
    LockfileResolver, resolve_lockfile,
};
pub use catalog::{
    KIT_VERSION, ProfileCatalog, ProfileDefinition, ProfileError, ProviderSelection,
    ResolvedProfile, bundled_profile_catalog, resolve_profile,
};
pub use lifecycle::LifecycleError;
pub use manager::{
    ApplyOutcome, Diagnostic, DoctorReport, ManagementPlan, ManagerError, PlanAction,
    PlanOperation, ProjectManager, ProjectSnapshot, SealedManagementPlan, doctor, plan_add,
    plan_diff, plan_profile_set, plan_remove, preserves_historical_path,
};
pub use modules::{
    ApplicationRequirement, ApplicationRequirementProviderFamily, CatalogError,
    ComposeEnvironmentBinding, ComposeHealthcheck, ComposeMigration, ConfigurationField,
    ConfigurationValue, ConfigurationValueType, ExternalEnvironmentBinding, GeneratorOwnership,
    ModuleCatalog, ModuleConfiguration, ModuleDefinition, RuntimeDependencyDescriptor,
    RuntimeDependencyId,
};
pub use region::{ManagedRegion, RegionError, parse_managed_regions, reconcile_managed_region};
pub use release::{
    CANONICAL_REPOSITORY, GENERATOR_VERSION, ReleaseBuildStatus, ReleaseIdentity,
    ReleaseIdentityError,
};
pub use render::{
    RenderError, RenderOutcome, RenderRequest, render_project, render_project_with_options,
    render_project_with_resolver,
};
pub use state::{
    MANAGED_MARKER_VERSION, ManagedRegionRecord, OwnershipKind, OwnershipRecord,
    PROJECT_STATE_PATH, PROJECT_STATE_SCHEMA_VERSION, ProfileSelection, ProjectState,
    SelectedModule, SelectedProvider, StateError,
};

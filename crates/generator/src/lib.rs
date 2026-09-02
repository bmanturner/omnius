//! Deterministic service generation and safe catalog-driven module management.

mod catalog;
mod manager;
mod modules;
mod region;
mod render;
mod state;
mod upgrade;

pub use catalog::{
    KIT_VERSION, ProfileCatalog, ProfileDefinition, ProfileError, ProviderSelection,
    ResolvedProfile, bundled_profile_catalog, resolve_profile,
};
pub use manager::{
    ApplyOutcome, Diagnostic, DoctorReport, ManagementPlan, ManagerError, PlanAction,
    PlanOperation, ProjectManager, ProjectSnapshot, doctor, plan_add, plan_diff, plan_remove,
    preserves_historical_path,
};
pub use modules::{
    ApplicationRequirement, ApplicationRequirementProviderFamily, CatalogError,
    ComposeEnvironmentBinding, ComposeHealthcheck, ComposeMigration, ConfigurationField,
    ConfigurationValue, ConfigurationValueType, ExternalEnvironmentBinding, GeneratorOwnership,
    ModuleCatalog, ModuleConfiguration, ModuleDefinition, RuntimeDependencyDescriptor,
    RuntimeDependencyId,
};
pub use region::{ManagedRegion, RegionError, parse_managed_regions, reconcile_managed_region};
pub use render::{RenderError, RenderOutcome, RenderRequest, render_project};
pub use state::{
    MANAGED_MARKER_VERSION, ManagedRegionRecord, OwnershipKind, OwnershipRecord,
    PROJECT_STATE_PATH, PROJECT_STATE_SCHEMA_VERSION, ProfileSelection, ProjectState,
    SelectedModule, SelectedProvider, StateError,
};
pub use upgrade::{UPGRADE_RECIPES, UpgradeRecipe, plan_upgrade};

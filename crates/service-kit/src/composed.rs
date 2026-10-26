//! Fully validated composition output and its runtime hand-off.

use std::collections::{BTreeMap, BTreeSet};

use axum::Router;
use omnius_health::HealthCheckSpec;
use omnius_runtime::TaskSpec;

use crate::ShutdownHook;

/// Fully validated output of the generated static registrar graph.
pub struct ComposedApplication {
    pub(crate) router: Router,
    pub(crate) health_specs: Vec<HealthCheckSpec>,
    pub(crate) health_runtime: bool,
    pub(crate) task_specs: Vec<TaskSpec>,
    pub(crate) shutdown_hooks: Vec<ShutdownHook>,
    pub(crate) public_operations: BTreeSet<&'static str>,
    pub(crate) capabilities: BTreeMap<&'static str, bool>,
}

/// Runtime parts consumed from a [`ComposedApplication`].
pub struct RuntimeParts {
    /// Composed application router.
    pub router: Router,
    /// Registered cached health checks.
    pub health_specs: Vec<HealthCheckSpec>,
    /// Deferred health-runtime marker.
    pub health_runtime: bool,
    /// Registered supervised tasks.
    pub task_specs: Vec<TaskSpec>,
    /// Application shutdown actions.
    pub shutdown_hooks: Vec<ShutdownHook>,
}

impl ComposedApplication {
    /// Consumes the composition into its router, cached health checks, deferred
    /// health-runtime marker, supervised tasks, and application shutdown actions.
    #[must_use = "the composed runtime parts must be installed into the application process"]
    pub fn into_runtime_parts(self) -> RuntimeParts {
        RuntimeParts {
            router: self.router,
            health_specs: self.health_specs,
            health_runtime: self.health_runtime,
            task_specs: self.task_specs,
            shutdown_hooks: self.shutdown_hooks,
        }
    }

    /// Returns registered cached health checks.
    #[must_use]
    pub fn health_specs(&self) -> &[HealthCheckSpec] {
        &self.health_specs
    }

    /// Returns registered supervised tasks.
    #[must_use]
    pub fn task_specs(&self) -> &[TaskSpec] {
        &self.task_specs
    }

    /// Returns mounted public operation IDs.
    #[must_use]
    pub fn public_operations(&self) -> &BTreeSet<&'static str> {
        &self.public_operations
    }

    /// Returns compiled capabilities and runtime availability.
    #[must_use]
    pub fn capabilities(&self) -> &BTreeMap<&'static str, bool> {
        &self.capabilities
    }
}

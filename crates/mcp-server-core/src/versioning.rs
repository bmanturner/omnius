//! Public MCP contract change classification shared by projection catalogs.

use serde::Serialize;

/// Reviewed classification for a documented public compatibility window.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum McpContractChange {
    /// The public JSON Schema or declared result schema changed incompatibly.
    Schema,
    /// Public behavior changed incompatibly without a schema change.
    Semantic,
    /// Both schema and semantic behavior changed incompatibly.
    SchemaAndSemantic,
}

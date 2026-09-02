use std::{collections::BTreeMap, fmt};

use http::Uri;
use serde::{Deserialize, Deserializer, Serialize, Serializer, de};
use thiserror::Error;

use crate::artifact::SafeRelativePath;

/// Frozen MCP protocol requirements revision exercised by this harness.
pub const MCP_REQUIREMENTS_REVISION: &str = "2026-07-28";
/// Exact official server conformance package.
pub const CONFORMANCE_PACKAGE: &str = "@modelcontextprotocol/conformance";
/// Exact official server conformance package version.
pub const CONFORMANCE_VERSION: &str = "0.2.0-alpha.11";
/// Exact official Inspector package.
pub const INSPECTOR_PACKAGE: &str = "@modelcontextprotocol/inspector";
/// Exact official Inspector package version.
pub const INSPECTOR_VERSION: &str = "2.4.0";
/// Minimum Node version required by the pinned Inspector.
pub const MINIMUM_NODE_VERSION: NodeVersion = NodeVersion::new(22, 19, 0);

/// A parsed three-component Node runtime version.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct NodeVersion {
    /// Major version.
    pub major: u64,
    /// Minor version.
    pub minor: u64,
    /// Patch version.
    pub patch: u64,
}

impl NodeVersion {
    /// Creates a Node version.
    #[must_use]
    pub const fn new(major: u64, minor: u64, patch: u64) -> Self {
        Self {
            major,
            minor,
            patch,
        }
    }

    /// Parses the exact output shape produced by `node --version`.
    ///
    /// # Errors
    ///
    /// Returns [`PlanError::InvalidNodeVersion`] when the output is not exactly three
    /// dot-separated unsigned version components, optionally prefixed with `v` or suffixed with a
    /// prerelease label.
    pub fn parse(output: &str) -> Result<Self, PlanError> {
        let version = output.trim().strip_prefix('v').unwrap_or(output.trim());
        let core = version.split_once('-').map_or(version, |(core, _)| core);
        let mut components = core.split('.');
        let major = parse_version_component(components.next())?;
        let minor = parse_version_component(components.next())?;
        let patch = parse_version_component(components.next())?;
        if components.next().is_some() {
            return Err(PlanError::InvalidNodeVersion);
        }
        Ok(Self::new(major, minor, patch))
    }

    /// Rejects runtimes below the minimum supported by the pinned tools.
    ///
    /// # Errors
    ///
    /// Returns [`PlanError::UnsupportedNodeVersion`] when this version is older than
    /// [`MINIMUM_NODE_VERSION`].
    pub fn require_supported(self) -> Result<(), PlanError> {
        if self < MINIMUM_NODE_VERSION {
            Err(PlanError::UnsupportedNodeVersion {
                found: self,
                minimum: MINIMUM_NODE_VERSION,
            })
        } else {
            Ok(())
        }
    }
}

impl fmt::Display for NodeVersion {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let Self {
            major,
            minor,
            patch,
        } = self;
        write!(formatter, "{major}.{minor}.{patch}")
    }
}

/// An authenticated-data-free HTTP endpoint.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HttpEndpoint(String);

impl HttpEndpoint {
    /// Parses an HTTP(S) MCP endpoint and rejects credentials, query tokens, and fragments.
    ///
    /// # Errors
    ///
    /// Returns [`PlanError::InvalidHttpEndpoint`] unless the value is an absolute HTTP(S) URI
    /// with an authority and host and without credentials, query parameters, or a fragment.
    pub fn parse(value: impl Into<String>) -> Result<Self, PlanError> {
        let value = value.into();
        let uri: Uri = value.parse().map_err(|_| PlanError::InvalidHttpEndpoint)?;
        if !matches!(uri.scheme_str(), Some("http" | "https"))
            || uri.authority().is_none()
            || uri.host().is_none()
            || uri.query().is_some()
            || value.contains('#')
            || uri
                .authority()
                .is_some_and(|authority| authority.as_str().contains('@'))
        {
            return Err(PlanError::InvalidHttpEndpoint);
        }
        Ok(Self(value))
    }

    /// Returns the validated endpoint.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Serialize for HttpEndpoint {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for HttpEndpoint {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::parse(value).map_err(de::Error::custom)
    }
}

/// Exact package identity used by a generated command.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PinnedTool {
    /// Official MCP conformance runner.
    Conformance,
    /// Official MCP Inspector.
    Inspector,
}

impl PinnedTool {
    /// Returns `package@exact-version` for `npx`.
    #[must_use]
    pub fn package_spec(self) -> &'static str {
        match self {
            Self::Conformance => "@modelcontextprotocol/conformance@0.2.0-alpha.11",
            Self::Inspector => "@modelcontextprotocol/inspector@2.4.0",
        }
    }

    /// Returns the package name without a version suffix.
    #[must_use]
    pub fn package(self) -> &'static str {
        match self {
            Self::Conformance => CONFORMANCE_PACKAGE,
            Self::Inspector => INSPECTOR_PACKAGE,
        }
    }

    /// Returns the exact package version.
    #[must_use]
    pub fn version(self) -> &'static str {
        match self {
            Self::Conformance => CONFORMANCE_VERSION,
            Self::Inspector => INSPECTOR_VERSION,
        }
    }
}

/// A shell-free external command plan with exact package and runtime requirements.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CommandPlan {
    /// Executable invoked without a shell.
    pub executable: String,
    /// Ordered executable arguments.
    pub arguments: Vec<String>,
    /// Exact tool identity.
    pub tool: PinnedTool,
    /// Minimum supported Node version.
    pub minimum_node: NodeVersion,
}

impl CommandPlan {
    /// Validates that package and Node pins have not drifted.
    ///
    /// # Errors
    ///
    /// Returns [`PlanError::PinDrift`] when the executable, minimum Node version, package
    /// specification, or required `npx` arguments differ from the pinned values.
    pub fn validate_pins(&self) -> Result<(), PlanError> {
        if self.executable != "npx"
            || self.minimum_node != MINIMUM_NODE_VERSION
            || self.arguments.first().map(String::as_str) != Some("-y")
            || self.arguments.get(1).map(String::as_str) != Some(self.tool.package_spec())
            || !self.tool.package_spec().ends_with(self.tool.version())
        {
            return Err(PlanError::PinDrift);
        }
        Ok(())
    }
}

/// Target kind recorded with official conformance evidence.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum OfficialTarget {
    /// A native Streamable HTTP endpoint.
    StreamableHttp {
        /// Validated native Streamable HTTP endpoint.
        endpoint: HttpEndpoint,
    },
}

/// Exact official conformance command and its target classification.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OfficialConformancePlan {
    /// HTTP target classification.
    pub target: OfficialTarget,
    /// Frozen requirements revision.
    pub requirements_revision: String,
    /// Safe output directory.
    pub artifact_directory: SafeRelativePath,
    /// Shell-free pinned command.
    pub command: CommandPlan,
}

impl OfficialConformancePlan {
    /// Plans official execution against a native Streamable HTTP endpoint.
    ///
    /// # Errors
    ///
    /// Returns an error if the generated command or its pinned target, path, revision, and
    /// package invariants cannot be validated.
    pub fn streamable_http(
        endpoint: HttpEndpoint,
        artifact_directory: SafeRelativePath,
    ) -> Result<Self, PlanError> {
        Self::build(
            OfficialTarget::StreamableHttp { endpoint },
            artifact_directory,
        )
    }

    /// Revalidates every revision, target, path, package, and argument invariant.
    ///
    /// # Errors
    ///
    /// Returns [`PlanError::PinDrift`] when a command, revision, or argument pin differs.
    pub fn validate(&self) -> Result<(), PlanError> {
        self.command.validate_pins()?;
        if self.command.tool != PinnedTool::Conformance
            || self.requirements_revision != MCP_REQUIREMENTS_REVISION
            || self.command.arguments != self.expected_arguments()
        {
            return Err(PlanError::PinDrift);
        }
        match &self.target {
            OfficialTarget::StreamableHttp { .. } => Ok(()),
        }
    }

    fn build(
        target: OfficialTarget,
        artifact_directory: SafeRelativePath,
    ) -> Result<Self, PlanError> {
        let endpoint = match &target {
            OfficialTarget::StreamableHttp { endpoint } => endpoint,
        };
        let command = CommandPlan {
            executable: "npx".to_owned(),
            arguments: vec![
                "-y".to_owned(),
                PinnedTool::Conformance.package_spec().to_owned(),
                "server".to_owned(),
                "--url".to_owned(),
                endpoint.as_str().to_owned(),
                "--requirements".to_owned(),
                MCP_REQUIREMENTS_REVISION.to_owned(),
                "--output-dir".to_owned(),
                artifact_directory.as_str().to_owned(),
            ],
            tool: PinnedTool::Conformance,
            minimum_node: MINIMUM_NODE_VERSION,
        };
        let plan = Self {
            target,
            requirements_revision: MCP_REQUIREMENTS_REVISION.to_owned(),
            artifact_directory,
            command,
        };
        plan.validate()?;
        Ok(plan)
    }

    fn expected_arguments(&self) -> Vec<String> {
        let endpoint = match &self.target {
            OfficialTarget::StreamableHttp { endpoint } => endpoint,
        };
        vec![
            "-y".to_owned(),
            PinnedTool::Conformance.package_spec().to_owned(),
            "server".to_owned(),
            "--url".to_owned(),
            endpoint.as_str().to_owned(),
            "--requirements".to_owned(),
            MCP_REQUIREMENTS_REVISION.to_owned(),
            "--output-dir".to_owned(),
            self.artifact_directory.as_str().to_owned(),
        ]
    }
}

/// Inspector one-shot method admitted by the non-interactive smoke plan.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InspectorMethod {
    /// Discover the visible tool catalog.
    ToolsList,
    /// Discover the visible resource catalog.
    ResourcesList,
    /// Discover the visible prompt catalog.
    PromptsList,
}

impl InspectorMethod {
    fn as_str(self) -> &'static str {
        match self {
            Self::ToolsList => "tools/list",
            Self::ResourcesList => "resources/list",
            Self::PromptsList => "prompts/list",
        }
    }
}

/// Minimal Inspector server entry that explicitly selects the modern protocol era.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct InspectorServerConfig {
    /// Inspector transport type.
    #[serde(rename = "type")]
    pub transport_type: String,
    /// Streamable HTTP endpoint.
    pub url: HttpEndpoint,
    /// Required modern protocol selection.
    #[serde(rename = "protocolEra")]
    pub protocol_era: String,
}

/// Minimal source-verified Inspector configuration document.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct InspectorConfig {
    /// Named MCP server entries.
    #[serde(rename = "mcpServers")]
    pub mcp_servers: BTreeMap<String, InspectorServerConfig>,
}

/// Pinned headless Inspector smoke plan.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct InspectorPlan {
    /// Shell-free Inspector command.
    pub command: CommandPlan,
    /// Generated config for the HTTP target.
    pub http_config: InspectorConfig,
    /// Generated config path for the HTTP target.
    pub config_path: SafeRelativePath,
}

impl InspectorPlan {
    /// Plans a modern Streamable HTTP smoke using a generated named config entry.
    ///
    /// # Errors
    ///
    /// Returns an error if the generated Inspector command, config path, package, runtime,
    /// format, or modern HTTP configuration pins cannot be validated.
    pub fn streamable_http(
        endpoint: HttpEndpoint,
        config_path: SafeRelativePath,
        method: InspectorMethod,
    ) -> Result<Self, PlanError> {
        let server_name = "target".to_owned();
        let http_config = InspectorConfig {
            mcp_servers: BTreeMap::from([(
                server_name.clone(),
                InspectorServerConfig {
                    transport_type: "http".to_owned(),
                    url: endpoint,
                    protocol_era: "modern".to_owned(),
                },
            )]),
        };
        let plan = Self {
            command: inspector_command(vec![
                "--config".to_owned(),
                config_path.as_str().to_owned(),
                "--server".to_owned(),
                server_name,
                "--stored-auth-only".to_owned(),
                "--method".to_owned(),
                method.as_str().to_owned(),
                "--format".to_owned(),
                "json".to_owned(),
                "--strict".to_owned(),
            ]),
            http_config,
            config_path,
        };
        plan.validate()?;
        Ok(plan)
    }

    /// Revalidates Inspector package, runtime, format, and modern HTTP config pins.
    ///
    /// # Errors
    ///
    /// Returns [`PlanError::PinDrift`] when command, package, runtime, one-shot method, format,
    /// or HTTP configuration invariants do not match the pinned smoke-plan contract.
    pub fn validate(&self) -> Result<(), PlanError> {
        self.command.validate_pins()?;
        let one_shot_method = self.command.arguments.windows(2).any(|pair| {
            pair[0] == "--method"
                && matches!(
                    pair[1].as_str(),
                    "tools/list" | "resources/list" | "prompts/list"
                )
        });
        if self.command.tool != PinnedTool::Inspector
            || self.command.arguments.get(2).map(String::as_str) != Some("--cli")
            || !self
                .command
                .arguments
                .iter()
                .any(|value| value == "--strict")
            || !self
                .command
                .arguments
                .windows(2)
                .any(|pair| pair[0] == "--format" && pair[1] == "json")
            || !one_shot_method
        {
            return Err(PlanError::PinDrift);
        }
        let Some(server) = self.http_config.mcp_servers.get("target") else {
            return Err(PlanError::PinDrift);
        };
        let config_argument_present = self
            .command
            .arguments
            .windows(2)
            .any(|pair| pair[0] == "--config" && pair[1] == self.config_path.as_str());
        let server_argument_present = self
            .command
            .arguments
            .windows(2)
            .any(|pair| pair[0] == "--server" && pair[1] == "target");
        if server.transport_type != "http"
            || server.protocol_era != "modern"
            || !config_argument_present
            || !server_argument_present
            || !self
                .command
                .arguments
                .iter()
                .any(|argument| argument == "--stored-auth-only")
        {
            return Err(PlanError::PinDrift);
        }
        Ok(())
    }
}

fn inspector_command(mut arguments: Vec<String>) -> CommandPlan {
    let mut pinned = Vec::with_capacity(arguments.len() + 3);
    pinned.extend([
        "-y".to_owned(),
        PinnedTool::Inspector.package_spec().to_owned(),
        "--cli".to_owned(),
    ]);
    pinned.append(&mut arguments);
    CommandPlan {
        executable: "npx".to_owned(),
        arguments: pinned,
        tool: PinnedTool::Inspector,
        minimum_node: MINIMUM_NODE_VERSION,
    }
}

fn parse_version_component(component: Option<&str>) -> Result<u64, PlanError> {
    component
        .filter(|value| !value.is_empty())
        .ok_or(PlanError::InvalidNodeVersion)?
        .parse()
        .map_err(|_| PlanError::InvalidNodeVersion)
}

/// Pinned-tool plan validation failure.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum PlanError {
    /// Node did not report a semantic version.
    #[error("node version must contain major.minor.patch")]
    InvalidNodeVersion,
    /// Node is older than the pinned Inspector permits.
    #[error("node {found} is unsupported; minimum is {minimum}")]
    UnsupportedNodeVersion {
        /// Discovered Node version.
        found: NodeVersion,
        /// Required minimum version.
        minimum: NodeVersion,
    },
    /// A plan did not contain the exact admitted package, version, revision, or argument sequence.
    #[error("official tool pin or command revision drifted")]
    PinDrift,
    /// The endpoint was not an authenticated-data-free HTTP(S) URI.
    #[error("MCP endpoint must be an HTTP(S) URI without user info, query, or fragment")]
    InvalidHttpEndpoint,
}

use std::{path::Path, process::Stdio, time::Duration};

use serde::{Deserialize, Serialize};
use thiserror::Error;
use tokio::{
    io::{AsyncRead, AsyncReadExt},
    process::Command,
    time::{Instant, timeout_at},
};

use crate::{
    artifact::{ArtifactError, ArtifactStore},
    evidence::{
        AcceptanceId, CaseEvidence, CaseEvidenceDraft, CheckOutcome, EvidenceBounds, EvidenceCheck,
        EvidenceError, EvidenceReport, EvidenceSuiteKind, EvidenceToolchain, Transport,
    },
    official::{
        CommandPlan, InspectorPlan, MCP_REQUIREMENTS_REVISION, NodeVersion,
        OfficialConformancePlan, OfficialTarget, PinnedTool, PlanError,
    },
    redaction::RedactedDiagnostic,
};

/// Finite external-process limits for opt-in official execution.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExternalExecutionBounds {
    /// Node prerequisite probe deadline.
    pub node_probe_deadline_ms: u64,
    /// Official tool process deadline.
    pub tool_deadline_ms: u64,
    /// Maximum bytes retained from each output stream.
    pub max_output_bytes_per_stream: usize,
}

impl Default for ExternalExecutionBounds {
    fn default() -> Self {
        Self {
            node_probe_deadline_ms: 5_000,
            tool_deadline_ms: 10 * 60 * 1_000,
            max_output_bytes_per_stream: 4_096,
        }
    }
}

impl ExternalExecutionBounds {
    fn validate(self) -> Result<(), ExecutionError> {
        if self.node_probe_deadline_ms == 0
            || self.tool_deadline_ms == 0
            || self.tool_deadline_ms > 30 * 60 * 1_000
            || !(256..=64 * 1_024).contains(&self.max_output_bytes_per_stream)
        {
            Err(ExecutionError::InvalidBounds)
        } else {
            Ok(())
        }
    }
}

/// Capability token that can only be created by an explicit affirmative caller action.
#[derive(Clone, Copy, Debug)]
pub struct OfficialExecutionOptIn(());

impl OfficialExecutionOptIn {
    /// Creates the capability only when the caller explicitly passes `true`.
    ///
    /// # Errors
    ///
    /// Returns [`ExecutionError::OfficialExecutionNotOptedIn`] unless `allowed` is true.
    pub fn explicit(allowed: bool) -> Result<Self, ExecutionError> {
        allowed
            .then_some(Self(()))
            .ok_or(ExecutionError::OfficialExecutionNotOptedIn)
    }
}

/// Executes the exact pinned official command without a shell.
#[derive(Clone, Debug)]
pub struct OfficialExecutor {
    bounds: ExternalExecutionBounds,
}

impl OfficialExecutor {
    /// Creates an executor with validated finite deadlines and output retention.
    ///
    /// # Errors
    ///
    /// Returns [`ExecutionError::InvalidBounds`] when a deadline or output bound is invalid.
    pub fn new(bounds: ExternalExecutionBounds) -> Result<Self, ExecutionError> {
        bounds.validate()?;
        Ok(Self { bounds })
    }

    /// Executes the pinned HTTP-only official runner after path, Node, package, and revision checks.
    ///
    /// # Errors
    ///
    /// Returns [`ExecutionError`] when plan validation, prerequisites, isolated artifact
    /// preparation, execution, bounded capture, or evidence construction fails.
    pub async fn execute_conformance(
        &self,
        plan: &OfficialConformancePlan,
        _opt_in: OfficialExecutionOptIn,
        workspace_root: impl AsRef<Path>,
    ) -> Result<EvidenceReport, ExecutionError> {
        plan.validate()?;
        let workspace_root = workspace_root.as_ref();
        let scratch = tempfile::Builder::new()
            .prefix("omnius-mcp-conformance-")
            .tempdir()
            .map_err(ExecutionError::ScratchDirectory)?;
        let command = command_with_output_directory(&plan.command, scratch.path())?;

        let node_version = self.probe_node(workspace_root).await?;

        let started = Instant::now();
        let output = run_plan(
            &command,
            Duration::from_millis(self.bounds.tool_deadline_ms),
            self.bounds.max_output_bytes_per_stream,
            workspace_root,
        )
        .await?;
        let duration_ms = u64::try_from(started.elapsed().as_millis())
            .unwrap_or(u64::MAX)
            .min(self.bounds.tool_deadline_ms);
        official_report(plan, node_version, &output, duration_ms, self.bounds)
            .map_err(ExecutionError::Evidence)
    }

    /// Executes a pinned headless Inspector smoke after persisting its immutable modern config.
    ///
    /// # Errors
    ///
    /// Returns [`ExecutionError`] when plan validation, config persistence, prerequisites,
    /// execution, bounded capture, or evidence construction fails.
    pub async fn execute_inspector(
        &self,
        plan: &InspectorPlan,
        _opt_in: OfficialExecutionOptIn,
        workspace_root: impl AsRef<Path>,
    ) -> Result<EvidenceReport, ExecutionError> {
        plan.validate()?;
        let workspace_root = workspace_root.as_ref();
        if let (Some(config), Some(config_path)) = (&plan.http_config, &plan.config_path) {
            let config_json =
                serde_json::to_vec_pretty(config).map_err(EvidenceError::Serialize)?;
            ArtifactStore::write_workspace_json_if_unchanged(
                workspace_root,
                config_path,
                &config_json,
                64 * 1_024,
            )?;
        }
        let node_version = self.probe_node(workspace_root).await?;
        let started = Instant::now();
        let output = run_plan(
            &plan.command,
            Duration::from_millis(self.bounds.tool_deadline_ms),
            self.bounds.max_output_bytes_per_stream,
            workspace_root,
        )
        .await?;
        let duration_ms = u64::try_from(started.elapsed().as_millis())
            .unwrap_or(u64::MAX)
            .min(self.bounds.tool_deadline_ms);
        inspector_report(plan, node_version, &output, duration_ms, self.bounds)
            .map_err(ExecutionError::Evidence)
    }

    async fn probe_node(&self, workspace_root: &Path) -> Result<NodeVersion, ExecutionError> {
        let node = run_bounded(
            "node",
            &["--version".to_owned()],
            Duration::from_millis(self.bounds.node_probe_deadline_ms),
            128,
            workspace_root,
        )
        .await?;
        if node.timed_out || node.exit_code != Some(0) {
            return Err(ExecutionError::NodeProbeFailed);
        }
        let node_version = NodeVersion::parse(&String::from_utf8_lossy(&node.stdout))?;
        node_version.require_supported()?;
        Ok(node_version)
    }
}

/// Creates honest machine-readable evidence for an official run deliberately not executed.
///
/// # Errors
///
/// Returns [`ExecutionError`] when the plan is invalid or bounded evidence cannot be built.
pub fn skipped_official_evidence(
    plan: &OfficialConformancePlan,
    reason: &str,
) -> Result<EvidenceReport, ExecutionError> {
    plan.validate()?;
    let bounds = official_evidence_bounds(1_000, 4_096);
    let reason = RedactedDiagnostic::new("official_execution_skipped", reason, 1_024);
    let checks = [
        "package_pin_valid",
        "node_supported",
        "requirements_revision_pinned",
        "official_process_exit_zero",
    ]
    .into_iter()
    .map(|check_id| EvidenceCheck {
        check_id: check_id.to_owned(),
        outcome: CheckOutcome::NotRun {
            reason: reason.clone(),
        },
    })
    .collect();
    let case = CaseEvidence::from_checks(CaseEvidenceDraft {
        case_id: format!("{}.not_executed", official_case_prefix(&plan.target)),
        acceptance_ids: vec![AcceptanceId::AcAi105],
        transport: Some(official_transport(&plan.target)),
        category: official_category(&plan.target).to_owned(),
        deadline_ms: bounds.case_deadline_ms,
        duration_ms: 0,
        retained_bytes: 0,
        checks,
        diagnostics: vec![reason],
    })?;
    EvidenceReport::new(
        EvidenceSuiteKind::OfficialConformance,
        official_suite_id(&plan.target),
        MCP_REQUIREMENTS_REVISION,
        Some(EvidenceToolchain::pinned(PinnedTool::Conformance, None)),
        bounds,
        vec![case],
    )
    .map_err(ExecutionError::Evidence)
}

fn official_report(
    plan: &OfficialConformancePlan,
    node_version: NodeVersion,
    output: &BoundedOutput,
    duration_ms: u64,
    execution_bounds: ExternalExecutionBounds,
) -> Result<EvidenceReport, EvidenceError> {
    let bounds = official_evidence_bounds(
        execution_bounds.tool_deadline_ms,
        execution_bounds.max_output_bytes_per_stream * 2,
    );
    let process_succeeded = output.exit_code == Some(0) && !output.timed_out;
    let diagnostics = output_diagnostics(
        output,
        &bounds,
        "official",
        "official tool output exceeded the configured retention bound",
    );
    let failure = RedactedDiagnostic::new(
        if output.timed_out {
            "official_deadline_exceeded"
        } else {
            "official_nonzero_exit"
        },
        if output.timed_out {
            "official conformance exceeded its finite process deadline"
        } else {
            "official conformance returned a nonzero exit status"
        },
        bounds.max_diagnostic_bytes,
    );
    let checks = vec![
        EvidenceCheck {
            check_id: "package_pin_valid".to_owned(),
            outcome: CheckOutcome::Satisfied,
        },
        EvidenceCheck {
            check_id: "node_supported".to_owned(),
            outcome: if node_version >= plan.command.minimum_node {
                CheckOutcome::Satisfied
            } else {
                CheckOutcome::Failed {
                    diagnostic: failure.clone(),
                }
            },
        },
        EvidenceCheck {
            check_id: "requirements_revision_pinned".to_owned(),
            outcome: CheckOutcome::Satisfied,
        },
        EvidenceCheck {
            check_id: "official_process_exit_zero".to_owned(),
            outcome: if process_succeeded {
                CheckOutcome::Satisfied
            } else {
                CheckOutcome::Failed {
                    diagnostic: failure.clone(),
                }
            },
        },
    ];
    let retained_bytes =
        (output.stdout.len() + output.stderr.len()).min(bounds.max_retained_bytes_per_case);
    let case = CaseEvidence::from_checks(CaseEvidenceDraft {
        case_id: official_case_prefix(&plan.target).to_owned(),
        acceptance_ids: vec![AcceptanceId::AcAi105],
        transport: Some(official_transport(&plan.target)),
        category: official_category(&plan.target).to_owned(),
        deadline_ms: bounds.case_deadline_ms,
        duration_ms,
        retained_bytes,
        checks,
        diagnostics,
    })?;
    EvidenceReport::new(
        EvidenceSuiteKind::OfficialConformance,
        official_suite_id(&plan.target),
        MCP_REQUIREMENTS_REVISION,
        Some(EvidenceToolchain::pinned(
            PinnedTool::Conformance,
            Some(node_version),
        )),
        bounds,
        vec![case],
    )
}

fn inspector_report(
    plan: &InspectorPlan,
    node_version: NodeVersion,
    output: &BoundedOutput,
    duration_ms: u64,
    execution_bounds: ExternalExecutionBounds,
) -> Result<EvidenceReport, EvidenceError> {
    let bounds = official_evidence_bounds(
        execution_bounds.tool_deadline_ms,
        execution_bounds.max_output_bytes_per_stream * 2,
    );
    let process_succeeded = output.exit_code == Some(0) && !output.timed_out;
    let json_output_valid = !output.stdout_truncated
        && serde_json::from_slice::<serde_json::Value>(&output.stdout).is_ok();
    let failure = RedactedDiagnostic::new(
        if output.timed_out {
            "inspector_deadline_exceeded"
        } else {
            "inspector_smoke_failed"
        },
        if output.timed_out {
            "Inspector exceeded its finite process deadline"
        } else {
            "Inspector returned a nonzero status or invalid bounded JSON output"
        },
        bounds.max_diagnostic_bytes,
    );
    let outcome = |satisfied| {
        if satisfied {
            CheckOutcome::Satisfied
        } else {
            CheckOutcome::Failed {
                diagnostic: failure.clone(),
            }
        }
    };
    let checks = vec![
        EvidenceCheck {
            check_id: "package_pin_valid".to_owned(),
            outcome: CheckOutcome::Satisfied,
        },
        EvidenceCheck {
            check_id: "node_supported".to_owned(),
            outcome: outcome(node_version >= plan.command.minimum_node),
        },
        EvidenceCheck {
            check_id: "target_plan_valid".to_owned(),
            outcome: CheckOutcome::Satisfied,
        },
        EvidenceCheck {
            check_id: "inspector_process_exit_zero".to_owned(),
            outcome: outcome(process_succeeded),
        },
        EvidenceCheck {
            check_id: "inspector_json_output_valid".to_owned(),
            outcome: outcome(json_output_valid),
        },
    ];
    let diagnostics = output_diagnostics(
        output,
        &bounds,
        "inspector",
        "Inspector output exceeded the configured retention bound",
    );
    let is_http = plan.http_config.is_some();
    let retained_bytes =
        (output.stdout.len() + output.stderr.len()).min(bounds.max_retained_bytes_per_case);
    let case = CaseEvidence::from_checks(CaseEvidenceDraft {
        case_id: if is_http {
            "inspector_smoke.streamable_http".to_owned()
        } else {
            "inspector_smoke.stdio".to_owned()
        },
        acceptance_ids: vec![AcceptanceId::AcAi106],
        transport: Some(if is_http {
            Transport::StreamableHttp
        } else {
            Transport::Stdio
        }),
        category: "inspector_smoke".to_owned(),
        deadline_ms: bounds.case_deadline_ms,
        duration_ms,
        retained_bytes,
        checks,
        diagnostics,
    })?;
    EvidenceReport::new(
        EvidenceSuiteKind::InspectorSmoke,
        if is_http {
            "inspector-smoke-streamable-http"
        } else {
            "inspector-smoke-stdio"
        },
        MCP_REQUIREMENTS_REVISION,
        Some(EvidenceToolchain::pinned(
            PinnedTool::Inspector,
            Some(node_version),
        )),
        bounds,
        vec![case],
    )
}

fn official_transport(target: &OfficialTarget) -> Transport {
    match target {
        OfficialTarget::StreamableHttp { .. } => Transport::StreamableHttp,
        OfficialTarget::TestOnlyStdioBridge { .. } => Transport::Stdio,
    }
}

fn official_case_prefix(target: &OfficialTarget) -> &'static str {
    match target {
        OfficialTarget::StreamableHttp { .. } => "official_conformance.streamable_http",
        OfficialTarget::TestOnlyStdioBridge { .. } => "official_conformance.test_only_stdio_bridge",
    }
}

fn official_category(target: &OfficialTarget) -> &'static str {
    match target {
        OfficialTarget::StreamableHttp { .. } => "official_conformance",
        OfficialTarget::TestOnlyStdioBridge { .. } => {
            "official_conformance_via_test_only_stdio_bridge"
        }
    }
}

fn official_suite_id(target: &OfficialTarget) -> &'static str {
    match target {
        OfficialTarget::StreamableHttp { .. } => "official-conformance-server",
        OfficialTarget::TestOnlyStdioBridge { .. } => {
            "official-conformance-via-test-only-stdio-bridge"
        }
    }
}

fn official_evidence_bounds(deadline_ms: u64, retained_bytes: usize) -> EvidenceBounds {
    EvidenceBounds {
        seed: 0,
        case_deadline_ms: deadline_ms,
        total_deadline_ms: deadline_ms,
        max_concurrency: 1,
        max_cases: 1,
        max_retained_bytes_per_case: retained_bytes.max(1),
        max_retained_bytes_total: retained_bytes.max(1),
        max_diagnostics_per_case: 4,
        max_diagnostic_bytes: 1_024,
        max_report_bytes: 64 * 1_024,
    }
}

fn output_diagnostics(
    output: &BoundedOutput,
    bounds: &EvidenceBounds,
    code_prefix: &str,
    truncation_message: &str,
) -> Vec<RedactedDiagnostic> {
    let mut diagnostics = Vec::new();
    if !output.stdout.is_empty() {
        diagnostics.push(RedactedDiagnostic::new(
            format!("{code_prefix}_stdout"),
            &String::from_utf8_lossy(&output.stdout),
            bounds.max_diagnostic_bytes,
        ));
    }
    if !output.stderr.is_empty() && diagnostics.len() < bounds.max_diagnostics_per_case {
        diagnostics.push(RedactedDiagnostic::new(
            format!("{code_prefix}_stderr"),
            &String::from_utf8_lossy(&output.stderr),
            bounds.max_diagnostic_bytes,
        ));
    }
    if (output.stdout_truncated || output.stderr_truncated)
        && diagnostics.len() < bounds.max_diagnostics_per_case
    {
        diagnostics.push(RedactedDiagnostic::new(
            format!("{code_prefix}_output_truncated"),
            truncation_message,
            bounds.max_diagnostic_bytes,
        ));
    }
    diagnostics
}

fn command_with_output_directory(
    plan: &CommandPlan,
    output_directory: &Path,
) -> Result<CommandPlan, ExecutionError> {
    let output_directory = output_directory
        .to_str()
        .ok_or(ExecutionError::ScratchPathNotUtf8)?;
    let output_flag = plan
        .arguments
        .iter()
        .position(|argument| argument == "--output-dir")
        .ok_or(ExecutionError::MissingOutputDirectoryArgument)?;
    let mut command = plan.clone();
    let output_argument = command
        .arguments
        .get_mut(output_flag.saturating_add(1))
        .ok_or(ExecutionError::MissingOutputDirectoryArgument)?;
    output_directory.clone_into(output_argument);
    Ok(command)
}

async fn run_plan(
    plan: &CommandPlan,
    deadline: Duration,
    max_output_bytes: usize,
    current_directory: &Path,
) -> Result<BoundedOutput, ExecutionError> {
    plan.validate_pins()?;
    run_bounded(
        &plan.executable,
        &plan.arguments,
        deadline,
        max_output_bytes,
        current_directory,
    )
    .await
}

struct BoundedOutput {
    exit_code: Option<i32>,
    timed_out: bool,
    stdout: Vec<u8>,
    stdout_truncated: bool,
    stderr: Vec<u8>,
    stderr_truncated: bool,
}

struct DrainedOutput {
    bytes: Vec<u8>,
    truncated: bool,
    timed_out: bool,
}

async fn run_bounded(
    executable: &str,
    arguments: &[String],
    deadline: Duration,
    max_output_bytes: usize,
    current_directory: &Path,
) -> Result<BoundedOutput, ExecutionError> {
    let mut command = Command::new(executable);
    command
        .args(arguments)
        .current_dir(current_directory)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    #[cfg(unix)]
    command.process_group(0);
    let mut child = command.spawn().map_err(ExecutionError::Spawn)?;
    let process_id = child.id().ok_or_else(missing_process_id)?;
    let deadline = Instant::now() + deadline;
    let stdout = child.stdout.take().ok_or(ExecutionError::MissingPipe)?;
    let stderr = child.stderr.take().ok_or(ExecutionError::MissingPipe)?;
    let stdout_task = tokio::spawn(drain_bounded(stdout, max_output_bytes, deadline));
    let stderr_task = tokio::spawn(drain_bounded(stderr, max_output_bytes, deadline));

    let (exit_code, process_timed_out) =
        if let Ok(result) = timeout_at(deadline, child.wait()).await {
            (result.map_err(ExecutionError::Wait)?.code(), false)
        } else {
            terminate_process_tree(&mut child, process_id).await?;
            (None, true)
        };
    let stdout = stdout_task.await.map_err(ExecutionError::OutputTask)??;
    let stderr = stderr_task.await.map_err(ExecutionError::OutputTask)??;
    let output_timed_out = stdout.timed_out || stderr.timed_out;
    if output_timed_out && !process_timed_out {
        kill_process_group(process_id)?;
    }
    Ok(BoundedOutput {
        exit_code,
        timed_out: process_timed_out || output_timed_out,
        stdout: stdout.bytes,
        stdout_truncated: stdout.truncated,
        stderr: stderr.bytes,
        stderr_truncated: stderr.truncated,
    })
}

fn missing_process_id() -> ExecutionError {
    ExecutionError::Kill(std::io::Error::new(
        std::io::ErrorKind::InvalidInput,
        "external process identifier unavailable",
    ))
}

#[cfg(unix)]
fn kill_process_group(process_id: u32) -> Result<(), ExecutionError> {
    use nix::{
        errno::Errno,
        sys::signal::{Signal, killpg},
        unistd::Pid,
    };

    let process_group = i32::try_from(process_id).map_err(|_| {
        ExecutionError::Kill(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "external process identifier exceeds platform range",
        ))
    })?;
    match killpg(Pid::from_raw(process_group), Signal::SIGKILL) {
        Ok(()) | Err(Errno::ESRCH) => Ok(()),
        Err(error) => Err(ExecutionError::Kill(std::io::Error::from_raw_os_error(
            error as i32,
        ))),
    }
}

#[cfg(unix)]
async fn terminate_process_tree(
    child: &mut tokio::process::Child,
    process_id: u32,
) -> Result<(), ExecutionError> {
    kill_process_group(process_id)?;
    let _status = child.wait().await.map_err(ExecutionError::Wait)?;
    Ok(())
}

#[cfg(not(unix))]
fn kill_process_group(_process_id: u32) -> Result<(), ExecutionError> {
    Ok(())
}

#[cfg(not(unix))]
async fn terminate_process_tree(
    child: &mut tokio::process::Child,
    _process_id: u32,
) -> Result<(), ExecutionError> {
    child.kill().await.map_err(ExecutionError::Kill)?;
    let _status = child.wait().await.map_err(ExecutionError::Wait)?;
    Ok(())
}

async fn drain_bounded<R: AsyncRead + Unpin>(
    mut reader: R,
    maximum: usize,
    deadline: Instant,
) -> Result<DrainedOutput, std::io::Error> {
    let mut retained = Vec::with_capacity(maximum.min(4_096));
    let mut truncated = false;
    let mut buffer = [0u8; 4_096];
    loop {
        let read = match timeout_at(deadline, reader.read(&mut buffer)).await {
            Ok(result) => result?,
            Err(_) => {
                return Ok(DrainedOutput {
                    bytes: retained,
                    truncated: true,
                    timed_out: true,
                });
            }
        };
        if read == 0 {
            break;
        }
        let remaining = maximum.saturating_sub(retained.len());
        let retained_from_chunk = read.min(remaining);
        retained.extend_from_slice(&buffer[..retained_from_chunk]);
        truncated |= retained_from_chunk < read;
    }
    Ok(DrainedOutput {
        bytes: retained,
        truncated,
        timed_out: false,
    })
}

/// Opt-in external execution failure.
#[derive(Debug, Error)]
pub enum ExecutionError {
    /// External execution limits were zero or unreasonably large.
    #[error("invalid external execution bounds")]
    InvalidBounds,
    /// The caller did not explicitly opt in to external official execution.
    #[error("official execution requires explicit opt-in")]
    OfficialExecutionNotOptedIn,
    /// Official command plan was invalid or unsupported.
    #[error(transparent)]
    Plan(#[from] PlanError),
    /// Artifact directory preparation failed.
    #[error(transparent)]
    Artifact(#[from] ArtifactError),
    /// An isolated temporary directory could not be created for raw official artifacts.
    #[error("failed to create isolated official artifact directory")]
    ScratchDirectory(#[source] std::io::Error),
    /// The isolated raw artifact directory could not be represented safely.
    #[error("isolated official artifact directory is not UTF-8")]
    ScratchPathNotUtf8,
    /// The validated official command unexpectedly lacked its output directory argument.
    #[error("official command lacks its pinned output directory argument")]
    MissingOutputDirectoryArgument,
    /// Node could not be probed successfully.
    #[error("node prerequisite probe failed")]
    NodeProbeFailed,
    /// An external process could not be started.
    #[error("failed to spawn external tool")]
    Spawn(#[source] std::io::Error),
    /// An external process could not be waited on.
    #[error("failed to wait for external tool")]
    Wait(#[source] std::io::Error),
    /// A timed-out external process could not be terminated.
    #[error("failed to terminate timed-out external tool")]
    Kill(#[source] std::io::Error),
    /// An expected output pipe was unavailable.
    #[error("external tool output pipe unavailable")]
    MissingPipe,
    /// An output drain task failed.
    #[error("external output task failed")]
    OutputTask(#[source] tokio::task::JoinError),
    /// An output stream could not be drained.
    #[error("external output stream failed")]
    Output(#[from] std::io::Error),
    /// Structured evidence construction failed.
    #[error(transparent)]
    Evidence(#[from] EvidenceError),
}

#[cfg(test)]
mod tests {
    use std::{error::Error, io, time::Duration};

    use super::{command_with_output_directory, run_bounded};
    use crate::{HttpEndpoint, OfficialConformancePlan, SafeRelativePath};

    #[test]
    fn official_output_directory_is_replaced_only_for_ephemeral_execution()
    -> Result<(), Box<dyn Error>> {
        let plan = OfficialConformancePlan::streamable_http(
            HttpEndpoint::parse("https://example.test/mcp")?,
            SafeRelativePath::new("artifacts/mcp-conformance")?,
        )?;
        let scratch = tempfile::tempdir()?;
        let command = command_with_output_directory(&plan.command, scratch.path())?;

        assert_eq!(
            command.arguments.last().map(String::as_str),
            scratch.path().to_str()
        );
        assert_eq!(
            plan.command.arguments.last().map(String::as_str),
            Some("artifacts/mcp-conformance")
        );
        Ok(())
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn deadline_terminates_external_process_descendants() -> Result<(), Box<dyn Error>> {
        let directory = tempfile::tempdir()?;
        let marker = directory.path().join("descendant-finished");
        let marker = marker.to_str().ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidData, "temporary path is not UTF-8")
        })?;
        let arguments = vec![
            "-c".to_owned(),
            "(sleep 0.4; printf child > \"$1\") & wait".to_owned(),
            "sh".to_owned(),
            marker.to_owned(),
        ];

        let output = run_bounded(
            "sh",
            &arguments,
            Duration::from_millis(40),
            256,
            directory.path(),
        )
        .await?;
        tokio::time::sleep(Duration::from_millis(500)).await;

        assert!(output.timed_out);
        assert!(!directory.path().join("descendant-finished").exists());
        Ok(())
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn deadline_bounds_output_held_by_exited_process_descendant() -> Result<(), Box<dyn Error>>
    {
        let directory = tempfile::tempdir()?;
        let marker = directory.path().join("pipe-holder-finished");
        let marker = marker.to_str().ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidData, "temporary path is not UTF-8")
        })?;
        let arguments = vec![
            "-c".to_owned(),
            "(sleep 0.4; printf child > \"$1\") &".to_owned(),
            "sh".to_owned(),
            marker.to_owned(),
        ];

        let output = run_bounded(
            "sh",
            &arguments,
            Duration::from_millis(40),
            256,
            directory.path(),
        )
        .await?;
        tokio::time::sleep(Duration::from_millis(500)).await;

        assert!(output.timed_out);
        assert!(!directory.path().join("pipe-holder-finished").exists());
        Ok(())
    }
}

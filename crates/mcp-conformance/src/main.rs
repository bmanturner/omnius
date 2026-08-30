//! Command-line entry point for deterministic synthetic and opt-in official MCP conformance runs.

use std::{env, error::Error};

use omnius_mcp_conformance::{
    ArtifactStore, DEFAULT_ARTIFACT_DIRECTORY, ExternalExecutionBounds, HttpEndpoint,
    InspectorMethod, InspectorPlan, MatrixRunner, OfficialConformancePlan, OfficialExecutionOptIn,
    OfficialExecutor, ReferenceSyntheticAdapter, SafeRelativePath, StdioBridgeDeclaration,
    SyntheticMatrix, skipped_official_evidence,
};
use thiserror::Error;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let mut arguments = env::args().skip(1);
    let command = arguments.next().ok_or(CliError::Usage)?;
    match command.as_str() {
        "synthetic" => run_synthetic(&mut arguments).await,
        "official-plan-http" => plan_official_http(&mut arguments),
        "official-plan-stdio" => reject_direct_official_stdio(&mut arguments),
        "official-plan-stdio-bridge" => plan_official_stdio_bridge(&mut arguments),
        "official-run" => run_official(&mut arguments).await,
        "official-skip" => skip_official(&mut arguments),
        "inspector-http-plan" => plan_inspector_http(&mut arguments),
        "inspector-run-http" => run_inspector_http(&mut arguments).await,
        "inspector-stdio-plan" => plan_inspector_stdio(&mut arguments),
        "inspector-run-stdio" => run_inspector_stdio(&mut arguments).await,
        _ => Err(CliError::Usage.into()),
    }
}

async fn run_synthetic(arguments: &mut impl Iterator<Item = String>) -> Result<(), Box<dyn Error>> {
    let output_file = arguments.next();
    reject_extra(arguments)?;
    let matrix = SyntheticMatrix::default();
    let report = MatrixRunner
        .run(&matrix, &ReferenceSyntheticAdapter)
        .await?;
    let json = report.to_json_pretty()?;
    if let Some(output_file) = output_file {
        let store = ArtifactStore::prepare(
            env::current_dir()?,
            SafeRelativePath::new(DEFAULT_ARTIFACT_DIRECTORY)?,
        )?;
        store.write_json(
            &SafeRelativePath::new(output_file)?,
            &json,
            report.bounds.max_report_bytes,
        )?;
    }
    print_json(&json)?;
    Ok(())
}

fn plan_official_http(arguments: &mut impl Iterator<Item = String>) -> Result<(), Box<dyn Error>> {
    let endpoint = required(arguments)?;
    let artifact_directory = artifact_directory(arguments.next())?;
    reject_extra(arguments)?;
    let plan = OfficialConformancePlan::streamable_http(
        HttpEndpoint::parse(endpoint)?,
        artifact_directory,
    )?;
    print_json(&serde_json::to_vec_pretty(&plan)?)?;
    Ok(())
}

fn reject_direct_official_stdio(
    arguments: &mut impl Iterator<Item = String>,
) -> Result<(), Box<dyn Error>> {
    reject_extra(arguments)?;
    let _plan = OfficialConformancePlan::direct_stdio()?;
    Ok(())
}

fn plan_official_stdio_bridge(
    arguments: &mut impl Iterator<Item = String>,
) -> Result<(), Box<dyn Error>> {
    let endpoint = required(arguments)?;
    let bridge_id = required(arguments)?;
    let artifact_directory = artifact_directory(arguments.next())?;
    reject_extra(arguments)?;
    let plan = OfficialConformancePlan::stdio_via_test_bridge(
        HttpEndpoint::parse(endpoint)?,
        StdioBridgeDeclaration::test_only(bridge_id)?,
        artifact_directory,
    )?;
    print_json(&serde_json::to_vec_pretty(&plan)?)?;
    Ok(())
}

async fn run_official(arguments: &mut impl Iterator<Item = String>) -> Result<(), Box<dyn Error>> {
    let opt_in = required(arguments)?;
    let endpoint = required(arguments)?;
    let artifact_directory = artifact_directory(arguments.next())?;
    reject_extra(arguments)?;
    let plan = OfficialConformancePlan::streamable_http(
        HttpEndpoint::parse(endpoint)?,
        artifact_directory,
    )?;
    let capability = OfficialExecutionOptIn::explicit(opt_in == "--execute")?;
    let executor = OfficialExecutor::new(ExternalExecutionBounds::default())?;
    let report = executor
        .execute_conformance(&plan, capability, env::current_dir()?)
        .await?;
    print_json(&report.to_json_pretty()?)?;
    Ok(())
}

fn skip_official(arguments: &mut impl Iterator<Item = String>) -> Result<(), Box<dyn Error>> {
    let endpoint = required(arguments)?;
    let reason: Vec<_> = arguments.collect();
    if reason.is_empty() {
        return Err(CliError::Usage.into());
    }
    let plan = OfficialConformancePlan::streamable_http(
        HttpEndpoint::parse(endpoint)?,
        SafeRelativePath::new(DEFAULT_ARTIFACT_DIRECTORY)?,
    )?;
    let report = skipped_official_evidence(&plan, &reason.join(" "))?;
    print_json(&report.to_json_pretty()?)?;
    Ok(())
}

fn plan_inspector_http(arguments: &mut impl Iterator<Item = String>) -> Result<(), Box<dyn Error>> {
    let endpoint = required(arguments)?;
    let config_path = required(arguments)?;
    reject_extra(arguments)?;
    let plan = InspectorPlan::streamable_http(
        HttpEndpoint::parse(endpoint)?,
        SafeRelativePath::new(config_path)?,
        InspectorMethod::ToolsList,
    )?;
    print_json(&serde_json::to_vec_pretty(&plan)?)?;
    Ok(())
}

async fn run_inspector_http(
    arguments: &mut impl Iterator<Item = String>,
) -> Result<(), Box<dyn Error>> {
    let opt_in = required(arguments)?;
    let endpoint = required(arguments)?;
    let config_path = required(arguments)?;
    reject_extra(arguments)?;
    let plan = InspectorPlan::streamable_http(
        HttpEndpoint::parse(endpoint)?,
        SafeRelativePath::new(config_path)?,
        InspectorMethod::ToolsList,
    )?;
    let capability = OfficialExecutionOptIn::explicit(opt_in == "--execute")?;
    let executor = OfficialExecutor::new(ExternalExecutionBounds::default())?;
    let report = executor
        .execute_inspector(&plan, capability, env::current_dir()?)
        .await?;
    print_json(&report.to_json_pretty()?)?;
    Ok(())
}

fn plan_inspector_stdio(
    arguments: &mut impl Iterator<Item = String>,
) -> Result<(), Box<dyn Error>> {
    let program = required(arguments)?;
    let program_arguments = arguments.collect();
    let plan = InspectorPlan::stdio(program, program_arguments, InspectorMethod::ToolsList)?;
    print_json(&serde_json::to_vec_pretty(&plan)?)?;
    Ok(())
}

async fn run_inspector_stdio(
    arguments: &mut impl Iterator<Item = String>,
) -> Result<(), Box<dyn Error>> {
    let opt_in = required(arguments)?;
    let program = required(arguments)?;
    let program_arguments = arguments.collect();
    let plan = InspectorPlan::stdio(program, program_arguments, InspectorMethod::ToolsList)?;
    let capability = OfficialExecutionOptIn::explicit(opt_in == "--execute")?;
    let executor = OfficialExecutor::new(ExternalExecutionBounds::default())?;
    let report = executor
        .execute_inspector(&plan, capability, env::current_dir()?)
        .await?;
    print_json(&report.to_json_pretty()?)?;
    Ok(())
}

fn artifact_directory(value: Option<String>) -> Result<SafeRelativePath, CliError> {
    SafeRelativePath::new(value.unwrap_or_else(|| DEFAULT_ARTIFACT_DIRECTORY.to_owned()))
        .map_err(CliError::ArtifactPath)
}

fn required(arguments: &mut impl Iterator<Item = String>) -> Result<String, CliError> {
    arguments.next().ok_or(CliError::Usage)
}

fn reject_extra(mut arguments: impl Iterator<Item = String>) -> Result<(), CliError> {
    if arguments.next().is_some() {
        Err(CliError::Usage)
    } else {
        Ok(())
    }
}

fn print_json(json: &[u8]) -> Result<(), CliError> {
    let json = std::str::from_utf8(json).map_err(CliError::Utf8)?;
    println!("{json}");
    Ok(())
}

#[derive(Debug, Error)]
enum CliError {
    #[error(
        "usage: mcp-conformance <synthetic [relative-json-file] | official-plan-http URL [ARTIFACT_DIR] | official-plan-stdio | official-plan-stdio-bridge LOOPBACK_URL BRIDGE_ID [ARTIFACT_DIR] | official-run --execute URL [ARTIFACT_DIR] | official-skip URL REASON... | inspector-http-plan URL CONFIG_PATH | inspector-run-http --execute URL CONFIG_PATH | inspector-stdio-plan PROGRAM [ARG...] | inspector-run-stdio --execute PROGRAM [ARG...]>"
    )]
    Usage,
    #[error("invalid artifact path")]
    ArtifactPath(#[source] omnius_mcp_conformance::ArtifactError),
    #[error("generated JSON was not UTF-8")]
    Utf8(#[source] std::str::Utf8Error),
}

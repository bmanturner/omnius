//! Acceptance contracts for pinned tools, bounded evidence, security, and load scenarios.

#![expect(
    clippy::unwrap_used,
    reason = "fixed-fixture contract tests require successful setup before exercising assertions"
)]

use std::error::Error;
#[cfg(unix)]
use std::{
    fs,
    time::{SystemTime, UNIX_EPOCH},
};

use omnius_mcp_conformance::{
    AcceptanceId, ArtifactError, ArtifactStore, CONFORMANCE_VERSION, EvidenceReport,
    EvidenceStatus, ExecutionError, HttpEndpoint, INSPECTOR_VERSION, InspectorMethod,
    InspectorPlan, MCP_REQUIREMENTS_REVISION, MINIMUM_NODE_VERSION, MatrixRunner, NodeVersion,
    OfficialConformancePlan, OfficialExecutionOptIn, PlanError, SafeRelativePath, SyntheticMatrix,
    SyntheticScenario, TargetSyntheticAdapter, Transport, execute_fixture_target,
    redact_diagnostic, skipped_official_evidence,
};
use serde_json::json;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    task::JoinHandle,
};

struct FixtureTarget {
    adapter: TargetSyntheticAdapter,
    server: JoinHandle<()>,
}

impl Drop for FixtureTarget {
    fn drop(&mut self) {
        self.server.abort();
    }
}

async fn fixture_target() -> Result<FixtureTarget, Box<dyn Error>> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    let server = tokio::spawn(async move {
        while let Ok((stream, _peer)) = listener.accept().await {
            tokio::spawn(serve_fixture_http(stream));
        }
    });
    let adapter = TargetSyntheticAdapter::new(address);
    Ok(FixtureTarget { adapter, server })
}

async fn serve_fixture_http(mut stream: TcpStream) {
    let mut request = Vec::new();
    if (&mut stream)
        .take(64 * 1_024 + 1)
        .read_to_end(&mut request)
        .await
        .is_err()
        || request.len() > 64 * 1_024
    {
        return;
    }
    let Ok(response) = execute_fixture_target(Transport::StreamableHttp, &request).await else {
        return;
    };
    let headers = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        response.len()
    );
    if stream.write_all(headers.as_bytes()).await.is_ok() {
        let _result = stream.write_all(&response).await;
    }
}

#[test]
fn ac_ai_105_official_command_is_exactly_pinned_and_http_only() {
    let plan = OfficialConformancePlan::streamable_http(
        HttpEndpoint::parse("http://127.0.0.1:9010/mcp").unwrap(),
        SafeRelativePath::new("artifacts/mcp-conformance").unwrap(),
    )
    .unwrap();

    assert_eq!(CONFORMANCE_VERSION, "0.2.0-alpha.11");
    assert_eq!(MCP_REQUIREMENTS_REVISION, "2026-07-28");
    assert_eq!(plan.command.executable, "npx");
    assert_eq!(
        plan.command.arguments,
        [
            "-y",
            "@modelcontextprotocol/conformance@0.2.0-alpha.11",
            "server",
            "--url",
            "http://127.0.0.1:9010/mcp",
            "--requirements",
            "2026-07-28",
            "--output-dir",
            "artifacts/mcp-conformance",
        ]
    );
}

#[test]
fn ac_ai_105_node_package_and_revision_checks_fail_closed() {
    let minimum = NodeVersion::parse("v22.19.0").unwrap();
    let newer = NodeVersion::parse("23.0.1").unwrap();
    let older = NodeVersion::parse("v22.18.9").unwrap();

    assert_eq!(minimum, MINIMUM_NODE_VERSION);
    assert!(newer.require_supported().is_ok());
    assert!(matches!(
        older.require_supported(),
        Err(PlanError::UnsupportedNodeVersion { .. })
    ));
    assert!(NodeVersion::parse("latest").is_err());
    assert!(matches!(
        OfficialExecutionOptIn::explicit(false),
        Err(ExecutionError::OfficialExecutionNotOptedIn)
    ));
    assert!(OfficialExecutionOptIn::explicit(true).is_ok());
}

#[test]
fn ac_ai_106_inspector_plan_pins_modern_http_smoke() {
    let http = InspectorPlan::streamable_http(
        HttpEndpoint::parse("http://127.0.0.1:9020/mcp").unwrap(),
        SafeRelativePath::new("artifacts/mcp-conformance/inspector.json").unwrap(),
        InspectorMethod::ToolsList,
    )
    .unwrap();
    let config = serde_json::to_value(&http.http_config).unwrap();
    let mut legacy = http.clone();
    legacy
        .http_config
        .mcp_servers
        .get_mut("target")
        .unwrap()
        .protocol_era = "legacy".to_owned();

    assert_eq!(INSPECTOR_VERSION, "2.4.0");
    assert_eq!(config["mcpServers"]["target"]["type"], "http");
    assert_eq!(config["mcpServers"]["target"]["protocolEra"], "modern");
    assert!(
        http.command
            .arguments
            .contains(&"@modelcontextprotocol/inspector@2.4.0".to_owned())
    );
    assert!(
        http.command
            .arguments
            .contains(&"--stored-auth-only".to_owned())
    );
    assert_eq!(
        http.config_path.as_str(),
        "artifacts/mcp-conformance/inspector.json"
    );
    assert!(matches!(legacy.validate(), Err(PlanError::PinDrift)));
}

#[tokio::test]
async fn ac_ai_109_http_authorization_matrix_denies_every_bypass() {
    let matrix = SyntheticMatrix::default();
    let target = fixture_target().await.unwrap();
    let report = MatrixRunner.run(&matrix, &target.adapter).await.unwrap();
    let authorization_scenarios = [
        SyntheticScenario::CrossTenantBypass,
        SyntheticScenario::PrincipalBypass,
        SyntheticScenario::CapabilityBypass,
    ];

    for scenario in authorization_scenarios {
        let rows: Vec<_> = matrix
            .cases
            .iter()
            .filter(|case| case.scenario == scenario)
            .collect();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].transport, Transport::StreamableHttp);
        for row in rows {
            let evidence = report
                .cases
                .iter()
                .find(|case| case.case_id == row.case_id)
                .unwrap();
            assert!(
                matches!(&evidence.status, EvidenceStatus::Passed),
                "{evidence:#?}"
            );
            assert_eq!(evidence.acceptance_ids, [AcceptanceId::AcAi109]);
        }
    }
}

#[tokio::test]
async fn ac_ai_110_load_soak_cancellation_backpressure_and_failure_are_bounded() {
    let matrix = SyntheticMatrix::default();
    let target = fixture_target().await.unwrap();
    let report = MatrixRunner.run(&matrix, &target.adapter).await.unwrap();
    let scenarios = [
        SyntheticScenario::BoundedLoad,
        SyntheticScenario::BoundedSoak,
        SyntheticScenario::Cancellation,
        SyntheticScenario::Backpressure,
        SyntheticScenario::ProviderFailure,
    ];

    for scenario in scenarios {
        assert_eq!(
            matrix
                .cases
                .iter()
                .filter(|case| case.scenario == scenario)
                .count(),
            1
        );
    }
    assert!(report.summary.gate_passed, "{report:#?}");
    assert_eq!(report.summary.skipped, 0);
    assert!(report.cases.iter().all(|case| {
        case.duration_ms <= report.bounds.case_deadline_ms
            && case.retained_bytes <= report.bounds.max_retained_bytes_per_case
    }));
    assert!(report.to_json_pretty().unwrap().len() <= report.bounds.max_report_bytes);
}

#[tokio::test]
async fn ac_ai_112_all_five_adversarial_classes_run_over_http() {
    let matrix = SyntheticMatrix::default();
    let target = fixture_target().await.unwrap();
    let report = MatrixRunner.run(&matrix, &target.adapter).await.unwrap();
    let scenarios = [
        SyntheticScenario::PromptInjection,
        SyntheticScenario::Exfiltration,
        SyntheticScenario::ForgedState,
        SyntheticScenario::MaliciousUri,
        SyntheticScenario::TokenConfusion,
    ];

    for scenario in scenarios {
        let identifiers: Vec<_> = matrix
            .cases
            .iter()
            .filter(|case| case.scenario == scenario)
            .map(|case| case.case_id.as_str())
            .collect();
        assert_eq!(identifiers.len(), 1);
        assert!(identifiers[0].starts_with("streamable_http."));
    }
    assert!(report.summary.gate_passed, "{report:#?}");
}

#[test]
fn evidence_rejects_dishonest_skipped_as_passed_and_dishonest_summary() {
    let plan = OfficialConformancePlan::streamable_http(
        HttpEndpoint::parse("http://127.0.0.1:9030/mcp").unwrap(),
        SafeRelativePath::new("artifacts/mcp-conformance").unwrap(),
    )
    .unwrap();
    let skipped = skipped_official_evidence(&plan, "official execution is opt-in").unwrap();
    let trusted_sha256 = skipped.canonical_sha256().unwrap();
    assert!(!skipped.summary.gate_passed);
    assert_eq!(skipped.summary.passed, 0);
    assert_eq!(skipped.summary.skipped, 1);
    assert_eq!(
        skipped.toolchain.as_ref().unwrap().version,
        "0.2.0-alpha.11"
    );

    let mut dishonest_status = serde_json::to_value(&skipped).unwrap();
    dishonest_status["cases"][0]["status"] = json!({"status": "passed"});
    assert!(
        EvidenceReport::from_json(
            &serde_json::to_vec(&dishonest_status).unwrap(),
            &trusted_sha256,
        )
        .is_err()
    );

    let mut dishonest_summary = serde_json::to_value(&skipped).unwrap();
    dishonest_summary["summary"]["passed"] = json!(1);
    dishonest_summary["summary"]["skipped"] = json!(0);
    dishonest_summary["summary"]["gate_passed"] = json!(true);
    assert!(
        EvidenceReport::from_json(
            &serde_json::to_vec(&dishonest_summary).unwrap(),
            &trusted_sha256,
        )
        .is_err()
    );

    let mut dishonest_toolchain = serde_json::to_value(&skipped).unwrap();
    dishonest_toolchain["toolchain"]["version"] = json!("latest");
    assert!(
        EvidenceReport::from_json(
            &serde_json::to_vec(&dishonest_toolchain).unwrap(),
            &trusted_sha256,
        )
        .is_err()
    );
}

#[test]
fn artifact_paths_and_endpoints_reject_escape_or_embedded_credentials() {
    assert!(SafeRelativePath::new("../outside.json").is_err());
    assert!(SafeRelativePath::new("/tmp/outside.json").is_err());
    assert!(SafeRelativePath::new("artifacts/./evidence.json").is_err());
    assert!(SafeRelativePath::new("C:/outside.json").is_err());
    assert!(HttpEndpoint::parse("https://user:password@example.test/mcp").is_err());
    assert!(HttpEndpoint::parse("https://example.test/mcp?access_token=secret").is_err());
}

#[cfg(unix)]
#[test]
fn artifact_store_rejects_symlinked_directory_components() -> Result<(), Box<dyn Error>> {
    use std::os::unix::fs::symlink;

    let nonce = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
    let root = std::env::temp_dir().join(format!(
        "omnius-mcp-conformance-{}-{nonce}",
        std::process::id()
    ));
    let outside = root.join("outside");
    let safe = root.join("safe");
    fs::create_dir_all(&outside)?;
    fs::create_dir(&safe)?;
    symlink(&outside, safe.join("link"))?;

    let result = ArtifactStore::prepare(&root, SafeRelativePath::new("safe/link")?);
    fs::remove_dir_all(&root)?;

    assert!(matches!(result, Err(ArtifactError::SymlinkComponent(_))));
    Ok(())
}

#[test]
fn url_and_token_diagnostics_are_redacted_before_retention() {
    let diagnostic = redact_diagnostic(
        "GET https://user:password@example.test/mcp?access_token=url-secret Authorization: Bearer header-secret",
        256,
    );

    assert!(!diagnostic.contains("password"));
    assert!(!diagnostic.contains("url-secret"));
    assert!(!diagnostic.contains("header-secret"));
    assert!(diagnostic.contains("[REDACTED]"));
    assert!(diagnostic.len() <= 256);
}

#[test]
fn credential_redaction_tolerates_adversarial_whitespace() {
    let diagnostic = redact_diagnostic(
        "Authorization \t:  Bearer    header-secret\n\
         {\"api_key\" \n : \t \"json-secret\"} token \t=\t query-secret \
         Bearer \t standalone-secret AWS_SECRET_ACCESS_KEY=cloud-secret",
        512,
    );

    for secret in [
        "header-secret",
        "json-secret",
        "query-secret",
        "standalone-secret",
        "cloud-secret",
    ] {
        assert!(!diagnostic.contains(secret));
    }
    assert!(diagnostic.matches("[REDACTED]").count() >= 4);
}

#[tokio::test]
async fn every_extension_matrix_row_emits_round_trippable_machine_evidence() {
    let matrix = SyntheticMatrix::default();
    let target = fixture_target().await.unwrap();
    for scenario in [
        SyntheticScenario::Apps,
        SyntheticScenario::ElicitationMrtr,
        SyntheticScenario::Tasks,
        SyntheticScenario::Subscriptions,
    ] {
        assert_eq!(
            matrix
                .cases
                .iter()
                .filter(|case| case.scenario == scenario)
                .count(),
            1
        );
    }

    let report = MatrixRunner.run(&matrix, &target.adapter).await.unwrap();
    let bytes = report.to_json_pretty().unwrap();
    let trusted_sha256 = report.canonical_sha256().unwrap();
    let decoded = EvidenceReport::from_json(&bytes, &trusted_sha256).unwrap();
    assert_eq!(decoded, report);

    let mut incomplete = serde_json::to_value(&report).unwrap();
    incomplete["cases"].as_array_mut().unwrap().remove(0);
    let incomplete: EvidenceReport = serde_json::from_value(incomplete).unwrap();
    assert!(incomplete.validate().is_err());

    let mut incomplete_checks = serde_json::to_value(&report).unwrap();
    incomplete_checks["cases"][0]["checks"]
        .as_array_mut()
        .unwrap()
        .remove(0);
    let incomplete_checks: EvidenceReport = serde_json::from_value(incomplete_checks).unwrap();
    assert!(incomplete_checks.validate().is_err());
}

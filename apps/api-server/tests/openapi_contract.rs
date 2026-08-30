//! Consumer-facing `OpenAPI` determinism and route-coverage contract.

use std::{collections::BTreeSet, error::Error};

use omnius_api_server::{PUBLIC_HTTP_OPERATIONS, openapi_json};
use serde_json::Value;

#[test]
fn canonical_openapi_is_deterministic_and_covers_public_routes() -> Result<(), Box<dyn Error>> {
    let first = openapi_json()?;
    let second = openapi_json()?;
    assert_eq!(first, second);

    let document: Value = serde_json::from_slice(&first)?;
    let paths = document
        .get("paths")
        .and_then(Value::as_object)
        .ok_or("OpenAPI document has no paths")?;
    let operation_ids = paths
        .values()
        .filter_map(Value::as_object)
        .flat_map(|path| path.values())
        .filter_map(|operation| operation.get("operationId"))
        .filter_map(Value::as_str)
        .collect::<BTreeSet<_>>();
    let expected = PUBLIC_HTTP_OPERATIONS
        .iter()
        .map(|operation| operation.operation_id)
        .collect::<BTreeSet<_>>();
    assert_eq!(operation_ids, expected);
    Ok(())
}

#[test]
fn llm_openapi_reuses_canonical_contracts_and_explicit_terminals() -> Result<(), Box<dyn Error>> {
    let bytes = openapi_json()?;
    let document: Value = serde_json::from_slice(&bytes)?;
    let schemas = document
        .pointer("/components/schemas")
        .and_then(Value::as_object)
        .ok_or("OpenAPI document has no schemas")?;
    for component in [
        "LlmRequest",
        "LlmResponse",
        "LlmStreamEvent",
        "LlmStreamTerminalState",
        "LlmJobSubmission",
        "LlmJob",
        "LlmConversation",
        "LlmConversationMessage",
        "LlmProviderState",
    ] {
        assert!(schemas.contains_key(component), "missing {component}");
    }

    assert_eq!(
        document
            .pointer(
                "/paths/~1api~1ai~1responses/post/requestBody/content/application~1json/schema/$ref",
            )
            .and_then(Value::as_str),
        Some("#/components/schemas/LlmRequest")
    );
    assert_eq!(
        document
            .pointer(
                "/paths/~1api~1ai~1jobs~1{job_id}~1result/get/responses/200/content/application~1json/schema/$ref",
            )
            .and_then(Value::as_str),
        Some("#/components/schemas/LlmResponse")
    );
    assert_eq!(
        document
            .pointer(
                "/paths/~1api~1ai~1responses~1stream/post/responses/200/content/text~1event-stream/schema/$ref",
            )
            .and_then(Value::as_str),
        Some("#/components/schemas/LlmStreamEvent")
    );

    let terminal = serde_json::to_string(
        schemas
            .get("LlmStreamTerminalState")
            .ok_or("missing terminal schema")?,
    )?;
    for state in [
        "completed",
        "provider_refused",
        "safety_refused",
        "cancelled",
        "failed",
        "partial_interrupted",
    ] {
        assert!(terminal.contains(state), "missing terminal state {state}");
    }
    Ok(())
}

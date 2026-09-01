//! Consumer-facing `OpenAPI` determinism and route-coverage contract.

use std::{collections::BTreeSet, error::Error};

use omnius_reference_api::{
    PUBLIC_HTTP_OPERATIONS, REFERENCE_HTTP_OPERATIONS, openapi_json, reference_openapi_contribution,
};
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
fn unmounted_llm_operations_are_absent() -> Result<(), Box<dyn Error>> {
    let bytes = openapi_json()?;
    let document: Value = serde_json::from_slice(&bytes)?;
    let paths = document
        .get("paths")
        .and_then(Value::as_object)
        .ok_or("OpenAPI document has no paths")?;
    assert!(
        paths.keys().all(|path| !path.starts_with("/api/ai/")),
        "unmounted AI operations must not be published"
    );
    Ok(())
}

#[test]
fn unauthenticated_reference_contribution_matches_its_mounted_routes() -> Result<(), Box<dyn Error>>
{
    let document = reference_openapi_contribution()?;
    let paths = document
        .get("paths")
        .and_then(Value::as_object)
        .ok_or("reference OpenAPI contribution has no paths")?;
    let operations = paths
        .values()
        .filter_map(Value::as_object)
        .flat_map(|path| path.values())
        .collect::<Vec<_>>();
    assert_eq!(operations.len(), REFERENCE_HTTP_OPERATIONS.len());
    assert!(
        operations.iter().all(|operation| operation
            .get("security")
            .and_then(Value::as_array)
            .is_some_and(Vec::is_empty)),
        "unauthenticated reference operations must declare empty security"
    );
    Ok(())
}

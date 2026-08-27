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

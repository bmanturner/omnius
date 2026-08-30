//! Provider catalog ownership contract tests.

use std::{collections::BTreeMap, error::Error};

use omnius_llm_provider_rig::CatalogProvider;
use serde::Deserialize;

#[derive(Deserialize)]
struct Catalog {
    providers: Vec<Entry>,
}

#[derive(Deserialize)]
struct Entry {
    id: String,
    adapter_module: String,
}

#[test]
fn machine_catalog_covers_all_six_provider_and_module_owners() -> Result<(), Box<dyn Error>> {
    let catalog: Catalog = serde_yaml::from_str(include_str!(
        "../../../specs/machine/extensions/llm-mcp-suite/provider-catalog.yaml"
    ))?;
    let entries = catalog
        .providers
        .into_iter()
        .map(|entry| (entry.id, entry.adapter_module))
        .collect::<BTreeMap<_, _>>();
    assert_eq!(entries.len(), CatalogProvider::ALL.len());
    for provider in CatalogProvider::ALL {
        assert_eq!(
            entries.get(provider.as_str()).map(String::as_str),
            Some(provider.adapter_module())
        );
    }
    assert!(CatalogProvider::Bedrock.direct().is_none());
    assert!(CatalogProvider::Vertex.direct().is_none());
    Ok(())
}

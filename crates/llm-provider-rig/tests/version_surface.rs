//! Rig dependency compatibility surface tests.

use std::error::Error;

use omnius_llm_provider_rig::RIG_COMPATIBILITY_VERSION;

#[test]
fn rig_packages_are_exact_and_rmcp_is_never_enabled() -> Result<(), Box<dyn Error>> {
    let root: toml::Value = toml::from_str(include_str!("../../../Cargo.toml"))?;
    let dependencies = root
        .get("workspace")
        .and_then(|workspace| workspace.get("dependencies"))
        .and_then(toml::Value::as_table)
        .ok_or("missing workspace dependencies")?;
    for package in ["rig-core", "rig-agent"] {
        let dependency = dependencies
            .get(package)
            .and_then(toml::Value::as_table)
            .ok_or("missing Rig package")?;
        assert_eq!(
            dependency.get("version").and_then(toml::Value::as_str),
            Some("=0.42.0")
        );
        assert_eq!(
            dependency
                .get("default-features")
                .and_then(toml::Value::as_bool),
            Some(false)
        );
    }
    let rig_agent = dependencies
        .get("rig-agent")
        .and_then(toml::Value::as_table)
        .ok_or("missing rig-agent")?;
    assert!(
        !rig_agent
            .get("features")
            .and_then(toml::Value::as_array)
            .is_some_and(|features| features
                .iter()
                .any(|feature| feature.as_str() == Some("rmcp")))
    );
    assert_eq!(RIG_COMPATIBILITY_VERSION, "0.42.0");
    Ok(())
}

#[test]
fn adapter_manifest_uses_only_workspace_rig_pins() -> Result<(), Box<dyn Error>> {
    let manifest: toml::Value = toml::from_str(include_str!("../Cargo.toml"))?;
    let dependencies = manifest
        .get("dependencies")
        .and_then(toml::Value::as_table)
        .ok_or("missing dependencies")?;
    for package in ["rig-core", "rig-agent"] {
        assert_eq!(
            dependencies
                .get(package)
                .and_then(toml::Value::as_table)
                .and_then(|dependency| dependency.get("workspace"))
                .and_then(toml::Value::as_bool),
            Some(true)
        );
    }
    Ok(())
}

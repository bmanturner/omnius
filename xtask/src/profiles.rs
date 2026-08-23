use std::{
    collections::{HashMap, HashSet},
    fs,
    path::Path,
};

use anyhow::{Context, Result, bail, ensure};
use serde::de::DeserializeOwned;

use crate::model::{Module, ModuleCatalog, Patterns, Profile, ProfileCatalog};

pub(crate) struct ProfileSummary {
    pub(crate) modules: usize,
    pub(crate) profiles: usize,
}

pub(crate) fn verify(root: &Path) -> Result<ProfileSummary> {
    let patterns = Patterns::new()?;
    let modules: ModuleCatalog = load_yaml(&root.join("machine/module-catalog.yaml"))?;
    let profiles: ProfileCatalog = load_yaml(&root.join("machine/profiles.yaml"))?;
    modules.validate(&patterns)?;
    profiles.validate_shape(&patterns)?;
    validate_catalogs(&modules.modules, &profiles.profiles)?;
    Ok(ProfileSummary {
        modules: modules.modules.len(),
        profiles: profiles.profiles.len(),
    })
}

pub(crate) fn load_yaml<T: DeserializeOwned>(path: &Path) -> Result<T> {
    let contents = fs::read_to_string(path).with_context(|| format!("read {}", path.display()))?;
    serde_yaml::from_str(&contents).with_context(|| format!("parse {}", path.display()))
}

fn validate_catalogs(modules: &[Module], profiles: &[Profile]) -> Result<()> {
    let module_by_id: HashMap<&str, &Module> = modules
        .iter()
        .map(|module| (module.id.as_str(), module))
        .collect();
    let profile_by_id: HashMap<&str, &Profile> = profiles
        .iter()
        .map(|profile| (profile.id.as_str(), profile))
        .collect();

    for module in modules {
        for requirement in &module.requires {
            ensure!(
                module_by_id.contains_key(requirement.as_str()),
                "module {} requires unknown module {requirement}",
                module.id
            );
        }
        for conflict in &module.conflicts_with {
            ensure!(
                module_by_id.contains_key(conflict.as_str()),
                "module {} conflicts with unknown module {conflict}",
                module.id
            );
            ensure!(
                conflict != &module.id,
                "module {} conflicts with itself",
                module.id
            );
        }
    }

    for profile in profiles {
        let selected = resolve_profile(profile.id.as_str(), &profile_by_id, &mut Vec::new())?;
        validate_profile(profile.id.as_str(), &selected, &module_by_id)?;
    }
    Ok(())
}

fn resolve_profile<'a>(
    profile_id: &'a str,
    profiles: &HashMap<&'a str, &'a Profile>,
    stack: &mut Vec<&'a str>,
) -> Result<Vec<&'a str>> {
    if stack.contains(&profile_id) {
        stack.push(profile_id);
        bail!("profile extension cycle: {}", stack.join(" -> "));
    }
    let profile = profiles
        .get(profile_id)
        .with_context(|| format!("unknown profile {profile_id}"))?;
    stack.push(profile_id);
    let mut resolved = if let Some(parent) = profile.extends.as_deref() {
        ensure!(
            profiles.contains_key(parent),
            "profile {profile_id} extends unknown profile {parent}"
        );
        resolve_profile(parent, profiles, stack)?
    } else {
        Vec::new()
    };
    stack.pop();
    for module in &profile.modules {
        if !resolved.contains(&module.as_str()) {
            resolved.push(module);
        }
    }
    Ok(resolved)
}

fn validate_profile(
    profile_id: &str,
    selected_modules: &[&str],
    modules: &HashMap<&str, &Module>,
) -> Result<()> {
    let selected: HashSet<&str> = selected_modules.iter().copied().collect();
    let mut provider_slots: HashMap<&str, &str> = HashMap::new();
    for module_id in selected_modules {
        let module = modules.get(module_id).with_context(|| {
            format!("profile {profile_id} references unknown module {module_id}")
        })?;
        for requirement in &module.requires {
            ensure!(
                selected.contains(requirement.as_str()),
                "profile {profile_id}: {module_id} requires {requirement}"
            );
        }
        for conflict in &module.conflicts_with {
            ensure!(
                !selected.contains(conflict.as_str()),
                "profile {profile_id}: {module_id} conflicts with {conflict}"
            );
        }
        if let Some(slot) = module.provider_slot.as_deref()
            && let Some(existing) = provider_slots.insert(slot, module_id)
        {
            bail!("profile {profile_id}: provider slot {slot} has both {existing} and {module_id}");
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{GeneratorOwnership, ModuleConfiguration};

    fn module(id: &str, requires: &[&str], conflicts: &[&str], slot: Option<&str>) -> Module {
        Module {
            id: id.into(),
            title: id.into(),
            version: "0.1.0".into(),
            owner: "test".into(),
            spec: "RSK-001".into(),
            kind: "capability".into(),
            requires: requires.iter().map(ToString::to_string).collect(),
            conflicts_with: conflicts.iter().map(ToString::to_string).collect(),
            provider_slot: slot.map(ToString::to_string),
            criticality: "required".into(),
            _runtime_toggle: false,
            external_services: vec![],
            primary_crates: vec![],
            acceptance: vec!["AC-GEN-005".into()],
            persistence: vec![],
            configuration: ModuleConfiguration {
                prefix: id.replace('-', "_"),
                schema: None,
                secret_fields: vec![],
            },
            routes: vec![],
            background_tasks: vec![],
            health_checks: vec![],
            metrics_prefix: id.replace('-', "_"),
            test_fixtures: vec![],
            generator_ownership: GeneratorOwnership {
                kit_owned: vec![],
                managed_regions: vec![],
                derived: vec![],
            },
            removal_behavior: "remove".into(),
        }
    }
    fn rejection(result: Result<()>) -> String {
        match result {
            Ok(()) => panic!("invalid profile was accepted"),
            Err(error) => error.to_string(),
        }
    }

    #[test]
    fn rejects_missing_profile_requirement() {
        let modules = vec![
            module("api", &["database"], &[], None),
            module("database", &[], &[], None),
        ];
        let profiles = vec![Profile {
            id: "broken".into(),
            description: "broken".into(),
            extends: None,
            modules: vec!["api".into()],
        }];
        let error = rejection(validate_catalogs(&modules, &profiles));
        assert!(error.contains("requires database"));
    }

    #[test]
    fn rejects_duplicate_provider_slot() {
        let modules = vec![
            module("redis-jobs", &[], &[], Some("jobs")),
            module("pg-jobs", &[], &[], Some("jobs")),
        ];
        let profiles = vec![Profile {
            id: "broken".into(),
            description: "broken".into(),
            extends: None,
            modules: vec!["redis-jobs".into(), "pg-jobs".into()],
        }];
        let error = rejection(validate_catalogs(&modules, &profiles));
        assert!(error.contains("provider slot jobs"));
    }

    #[test]
    fn rejects_profile_extension_cycle() {
        let modules = vec![];
        let profiles = vec![
            Profile {
                id: "one".into(),
                description: "one".into(),
                extends: Some("two".into()),
                modules: vec![],
            },
            Profile {
                id: "two".into(),
                description: "two".into(),
                extends: Some("one".into()),
                modules: vec![],
            },
        ];
        let error = rejection(validate_catalogs(&modules, &profiles));
        assert!(error.contains("profile extension cycle"));
    }
}

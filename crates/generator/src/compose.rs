use std::{
    collections::{BTreeMap, BTreeSet},
    fmt::Write as _,
};

use crate::{
    manager::ManagerError,
    modules::{ComposeMigration, ModuleCatalog, RuntimeDependencyDescriptor},
};

pub(crate) fn render_compose(
    catalog: &ModuleCatalog,
    selected: &BTreeSet<String>,
) -> Result<String, ManagerError> {
    let dependencies = catalog.selected_runtime_dependencies(selected)?;
    let migration_owner = dependencies.iter().find_map(|dependency| {
        let RuntimeDependencyDescriptor::Compose {
            service,
            migration: Some(migration),
            ..
        } = dependency
        else {
            return None;
        };
        selected
            .contains(&migration.required_module)
            .then_some((service.as_str(), migration))
    });
    let application_environment =
        compose_application_environment(&dependencies, migration_owner.is_some())?;

    let mut output = String::from("services:\n  app:\n");
    push_compose_application(
        &mut output,
        &dependencies,
        &application_environment,
        migration_owner.is_some(),
    )?;
    push_compose_migration(&mut output, migration_owner, &application_environment)?;
    push_compose_dependencies(&mut output, &dependencies)?;
    Ok(output)
}

fn compose_application_environment<'a>(
    dependencies: &[&'a RuntimeDependencyDescriptor],
    has_migration_owner: bool,
) -> Result<BTreeMap<&'a str, String>, ManagerError> {
    let mut environment: BTreeMap<&'a str, String> =
        BTreeMap::from([("OMNIUS__SERVER__LISTEN_ADDRESS", "0.0.0.0:3000".to_owned())]);
    for dependency in dependencies {
        match dependency {
            RuntimeDependencyDescriptor::Compose {
                application_environment: bindings,
                ..
            } => {
                for binding in bindings {
                    if binding.name == "OMNIUS__MIGRATIONS__RUN_ON_STARTUP" && !has_migration_owner
                    {
                        continue;
                    }
                    insert_compose_environment(&mut environment, &binding.name, &binding.value)?;
                }
            }
            RuntimeDependencyDescriptor::External { bindings, .. } => {
                for binding in bindings {
                    insert_compose_environment(
                        &mut environment,
                        &binding.name,
                        &format!("${{{}:?{}}}", binding.name, binding.message),
                    )?;
                }
            }
        }
    }
    Ok(environment)
}

fn push_compose_application(
    output: &mut String,
    dependencies: &[&RuntimeDependencyDescriptor],
    application_environment: &BTreeMap<&str, String>,
    has_migration_owner: bool,
) -> Result<(), ManagerError> {
    push_generated_build(output, 4);
    output.push_str("    environment:\n");
    push_compose_environment(output, application_environment, 6)?;
    if dependencies
        .iter()
        .any(|dependency| matches!(dependency, RuntimeDependencyDescriptor::Compose { .. }))
    {
        output.push_str("    depends_on:\n");
        let mut compose_services = dependencies
            .iter()
            .filter_map(|dependency| {
                let RuntimeDependencyDescriptor::Compose { service, .. } = dependency else {
                    return None;
                };
                Some(service.as_str())
            })
            .collect::<Vec<_>>();
        compose_services.sort_unstable();
        for service in compose_services {
            writeln!(
                output,
                "      {service}:\n        condition: service_healthy"
            )
            .map_err(|_| ManagerError::InvalidProject("cannot render Compose".to_owned()))?;
        }
        if has_migration_owner {
            output.push_str("      migrate:\n        condition: service_completed_successfully\n");
        }
    }
    output.push_str(
        "    ports:\n    - \"127.0.0.1:3000:3000\"\n    read_only: true\n    tmpfs:\n    - /tmp:size=16m,mode=1777\n    security_opt:\n    - no-new-privileges:true\n",
    );
    Ok(())
}

fn push_compose_migration(
    output: &mut String,
    migration_owner: Option<(&str, &ComposeMigration)>,
    application_environment: &BTreeMap<&str, String>,
) -> Result<(), ManagerError> {
    let Some((service, migration)) = migration_owner else {
        return Ok(());
    };
    output.push_str("  migrate:\n");
    push_generated_build(output, 4);
    output.push_str("    command: [");
    for (index, argument) in migration.command.iter().enumerate() {
        if index > 0 {
            output.push_str(", ");
        }
        push_yaml_string(output, argument)?;
    }
    output.push_str("]\n    environment:\n");
    let migration_environment = application_environment
        .iter()
        .filter(|(name, _)| **name != "OMNIUS__SERVER__LISTEN_ADDRESS")
        .map(|(name, value)| (*name, value.clone()))
        .collect::<BTreeMap<_, _>>();
    push_compose_environment(output, &migration_environment, 6)?;
    writeln!(
        output,
        "    depends_on:\n      {service}:\n        condition: service_healthy"
    )
    .map_err(|_| ManagerError::InvalidProject("cannot render Compose".to_owned()))?;
    output.push_str(
        "    restart: \"no\"\n    read_only: true\n    tmpfs:\n    - /tmp:size=16m,mode=1777\n    security_opt:\n    - no-new-privileges:true\n",
    );
    Ok(())
}

fn push_compose_dependencies(
    output: &mut String,
    dependencies: &[&RuntimeDependencyDescriptor],
) -> Result<(), ManagerError> {
    let mut compose_dependencies = dependencies
        .iter()
        .filter_map(|dependency| {
            matches!(dependency, RuntimeDependencyDescriptor::Compose { .. }).then_some(*dependency)
        })
        .collect::<Vec<_>>();
    compose_dependencies.sort_by_key(|dependency| match dependency {
        RuntimeDependencyDescriptor::Compose { service, .. } => service.as_str(),
        RuntimeDependencyDescriptor::External { .. } => "",
    });
    let mut volumes = BTreeSet::new();
    for dependency in compose_dependencies {
        let RuntimeDependencyDescriptor::Compose {
            service,
            image,
            volume,
            volume_mount,
            healthcheck,
            service_environment,
            ..
        } = dependency
        else {
            continue;
        };
        volumes.insert(volume);
        writeln!(output, "  {service}:\n    image: {image}")
            .map_err(|_| ManagerError::InvalidProject("cannot render Compose".to_owned()))?;
        output.push_str("    environment:\n");
        let environment = service_environment
            .iter()
            .map(|binding| (binding.name.as_str(), binding.value.clone()))
            .collect::<BTreeMap<_, _>>();
        push_compose_environment(output, &environment, 6)?;
        output.push_str("    volumes:\n    - ");
        push_yaml_string(output, &format!("{volume}:{volume_mount}"))?;
        output.push_str("\n    healthcheck:\n      test: [");
        for (index, argument) in healthcheck.test.iter().enumerate() {
            if index > 0 {
                output.push_str(", ");
            }
            push_yaml_string(output, argument)?;
        }
        writeln!(
            output,
            "]\n      interval: {}\n      timeout: {}\n      retries: {}",
            healthcheck.interval, healthcheck.timeout, healthcheck.retries
        )
        .map_err(|_| ManagerError::InvalidProject("cannot render Compose".to_owned()))?;
    }
    if !volumes.is_empty() {
        output.push_str("volumes:\n");
        for volume in volumes {
            writeln!(output, "  {volume}:")
                .map_err(|_| ManagerError::InvalidProject("cannot render Compose".to_owned()))?;
        }
    }
    Ok(())
}

fn insert_compose_environment<'a>(
    environment: &mut BTreeMap<&'a str, String>,
    name: &'a str,
    value: &str,
) -> Result<(), ManagerError> {
    if let Some(existing) = environment.insert(name, value.to_owned())
        && existing != value
    {
        return Err(ManagerError::InvalidProject(format!(
            "runtime dependencies define conflicting Compose binding `{name}`"
        )));
    }
    Ok(())
}

fn push_generated_build(output: &mut String, indent: usize) {
    let padding = " ".repeat(indent);
    let _ = writeln!(
        output,
        "{padding}build:\n{padding}  context: .\n{padding}  dockerfile: ops/Dockerfile"
    );
}

fn push_compose_environment(
    output: &mut String,
    environment: &BTreeMap<&str, String>,
    indent: usize,
) -> Result<(), ManagerError> {
    let padding = " ".repeat(indent);
    for (name, value) in environment {
        write!(output, "{padding}{name}: ")
            .map_err(|_| ManagerError::InvalidProject("cannot render Compose".to_owned()))?;
        push_yaml_string(output, value)?;
        output.push('\n');
    }
    Ok(())
}

fn push_yaml_string(output: &mut String, value: &str) -> Result<(), ManagerError> {
    let encoded = serde_json::to_string(value).map_err(|error| {
        ManagerError::InvalidProject(format!("cannot encode Compose scalar: {error}"))
    })?;
    output.push_str(&encoded);
    Ok(())
}

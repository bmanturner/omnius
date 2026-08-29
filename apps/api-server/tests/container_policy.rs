//! Structural policy checks for the local production container definition.

use std::collections::BTreeSet;

const NODE_IMAGE: &str = "node:24.19.0-bookworm-slim@sha256:a9f5f7c91a432850b2a8a7797adf5eadb6c733ceed61167806cee7ea7fbc29df";
const RUST_IMAGE: &str =
    "rust:1.98.0-bookworm@sha256:82150a52ec202c1b14d7817e14516c392bb7f5cfebd88f1ed531cb37ebd39922";
const RUNTIME_IMAGE: &str =
    "debian:12.13-slim@sha256:67b30a61dc87758f0caf819646104f29ecbda97d920aaf5edc834128ac8493d3";

#[derive(Debug)]
struct Instruction {
    keyword: String,
    arguments: String,
}

#[derive(Debug)]
struct Stage {
    image: String,
    name: String,
    instructions: Vec<Instruction>,
}

fn parse_dockerfile(source: &str) -> Vec<Stage> {
    let mut logical_lines = Vec::new();
    let mut current = String::new();
    for raw_line in source.lines() {
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let continued = line.ends_with('\\');
        let segment = line.strip_suffix('\\').unwrap_or(line).trim_end();
        if !current.is_empty() {
            current.push(' ');
        }
        current.push_str(segment);
        if !continued {
            logical_lines.push(std::mem::take(&mut current));
        }
    }
    assert!(current.is_empty(), "unterminated Dockerfile continuation");

    let mut stages = Vec::new();
    for line in logical_lines {
        let Some((keyword, arguments)) = line.split_once(char::is_whitespace) else {
            panic!("Dockerfile instruction has no arguments: {line}");
        };
        if keyword.eq_ignore_ascii_case("FROM") {
            let fields: Vec<_> = arguments.split_ascii_whitespace().collect();
            assert_eq!(
                fields.len(),
                3,
                "every stage must use FROM <image> AS <name>"
            );
            assert!(fields[1].eq_ignore_ascii_case("AS"));
            stages.push(Stage {
                image: fields[0].to_owned(),
                name: fields[2].to_owned(),
                instructions: Vec::new(),
            });
        } else {
            let Some(stage) = stages.last_mut() else {
                panic!("instruction appears before the first stage");
            };
            stage.instructions.push(Instruction {
                keyword: keyword.to_ascii_uppercase(),
                arguments: arguments.to_owned(),
            });
        }
    }
    stages
}

fn stage<'stages>(stages: &'stages [Stage], name: &str) -> &'stages Stage {
    let Some(stage) = stages.iter().find(|stage| stage.name == name) else {
        panic!("missing Docker stage {name}");
    };
    stage
}

fn instructions<'stage>(stage: &'stage Stage, keyword: &str) -> impl Iterator<Item = &'stage str> {
    stage
        .instructions
        .iter()
        .filter(move |instruction| instruction.keyword == keyword)
        .map(|instruction| instruction.arguments.as_str())
}

#[test]
fn container_build_is_pinned_frozen_and_metadata_consistent() {
    let stages = parse_dockerfile(include_str!("../../../Dockerfile"));
    assert_eq!(stage(&stages, "web-dependencies").image, NODE_IMAGE);
    assert_eq!(stage(&stages, "rust-build").image, RUST_IMAGE);

    let web_dependencies = stage(&stages, "web-dependencies");
    let dependency_runs: Vec<_> = instructions(web_dependencies, "RUN").collect();
    assert!(dependency_runs.iter().any(|run| {
        run.contains("corepack prepare pnpm@11.23.0 --activate")
            && run.contains("pnpm config set store-dir /pnpm/store")
    }));
    assert!(
        dependency_runs
            .iter()
            .any(|run| run.contains("pnpm install --frozen-lockfile"))
    );

    let web_build = stage(&stages, "web-build");
    let build_arguments: BTreeSet<_> = instructions(web_build, "ARG").collect();
    assert!(build_arguments.contains("OMNIUS_GIT_REVISION"));
    assert!(build_arguments.contains("OMNIUS_BUILD_TIME"));
    assert!(build_arguments.contains("OMNIUS_SOURCE_MAP_POLICY=disabled"));
    let web_runs: Vec<_> = instructions(web_build, "RUN").collect();
    assert!(web_runs.iter().any(|run| {
        run.contains("pnpm sdk:check:generated")
            && run.contains("pnpm sdk:build")
            && run.contains("OMNIUS_GIT_REVISION=\"$OMNIUS_GIT_REVISION\"")
            && run.contains("OMNIUS_BUILD_TIME=\"$OMNIUS_BUILD_TIME\"")
            && run.contains("pnpm web:build")
    }));

    let rust_build = stage(&stages, "rust-build");
    let rust_runs: Vec<_> = instructions(rust_build, "RUN").collect();
    assert!(rust_runs.iter().any(|run| {
        run.contains("OMNIUS_GIT_REVISION=\"$OMNIUS_GIT_REVISION\"")
            && run.contains("OMNIUS_BUILD_TIME=\"$OMNIUS_BUILD_TIME\"")
            && run.contains("cargo build --locked --release --package omnius-api-server")
    }));
}

#[test]
fn runtime_stage_is_non_root_and_copies_only_runtime_artifacts() {
    let stages = parse_dockerfile(include_str!("../../../Dockerfile"));
    let source_maps = stage(&stages, "web-runtime-artifacts");
    assert_eq!(source_maps.image, NODE_IMAGE);
    let map_runs: Vec<_> = instructions(source_maps, "RUN").collect();
    assert!(map_runs.iter().any(|run| {
        run.contains("disabled|private")
            && run.contains("-name '*.map'")
            && run.contains("-delete")
            && run.contains("public)")
    }));

    let runtime = stage(&stages, "runtime");
    assert_eq!(runtime.image, RUNTIME_IMAGE);
    assert_eq!(
        instructions(runtime, "USER").collect::<Vec<_>>(),
        ["65532:65532"]
    );
    let copies: Vec<_> = instructions(runtime, "COPY").collect();
    assert_eq!(copies.len(), 4);
    assert!(copies.iter().any(|copy| {
        copy.contains("--from=rust-build") && copy.ends_with("/usr/local/bin/omnius-api-server")
    }));
    assert!(copies.iter().any(|copy| {
        *copy == "--chown=65532:65532 config/reference.toml /etc/omnius/reference.toml"
    }));
    assert!(copies.iter().any(|copy| {
        *copy == "--chown=65532:65532 apps/api-server/email-templates ./email-templates"
    }));
    assert!(copies.iter().any(|copy| {
        copy.contains("--from=web-runtime-artifacts") && copy.ends_with("./web/dist")
    }));
    for copy in copies {
        for forbidden in [
            "contracts",
            "packages",
            "package.json",
            ".env",
            "/src",
            "Cargo.toml",
        ] {
            assert!(
                !copy.contains(forbidden),
                "runtime copy leaked {forbidden}: {copy}"
            );
        }
    }
    let environment = instructions(runtime, "ENV").collect::<Vec<_>>().join(" ");
    assert!(environment.contains("OMNIUS__STATIC_DELIVERY__SOURCE_MAPS=$OMNIUS_SOURCE_MAP_POLICY"));
    assert!(environment.contains("OMNIUS__STATIC_DELIVERY__BASE_PATH=$OMNIUS_WEB_BASE_PATH"));
    assert!(environment.contains("EMAIL_TEMPLATE_DIR=/opt/omnius/email-templates"));
}

#[test]
fn container_context_excludes_local_secrets_and_build_outputs() {
    let ignored: BTreeSet<_> = include_str!("../../../.dockerignore")
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .collect();
    for required in [
        ".git",
        ".env",
        ".env.*",
        "**/.env",
        "**/.env.*",
        "**/.npmrc",
        "**/*.key",
        "target",
        "**/target",
        "node_modules",
        "**/node_modules",
        "web/dist",
    ] {
        assert!(
            ignored.contains(required),
            "missing ignore policy {required}"
        );
    }
}

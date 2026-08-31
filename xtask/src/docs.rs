use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::{Component, Path, PathBuf},
};

use anyhow::{Context, Result, bail, ensure};
use regex::Regex;
use serde::Deserialize;
use serde_yaml::Value;
use walkdir::WalkDir;

const CENTRAL_DOCUMENTS: &[&str] = &[
    "docs/evidence-inventory.md",
    "docs/coverage-matrix.md",
    "docs/navigation.md",
    "docs/journeys.md",
    "docs/verification-plan.md",
];
const STATUS_VALUES: &[&str] = &["experimental", "stable", "deprecated"];
const IMPLEMENTATION_VALUES: &[&str] = &[
    "implemented",
    "partial",
    "source-only",
    "specified-only",
    "unavailable",
];
const EXPOSURE_VALUES: &[&str] = &[
    "assembled",
    "generated-only",
    "library-only",
    "unassembled",
    "not-applicable",
];

pub(crate) struct DocsSummary {
    pub(crate) pages: usize,
    pub(crate) capabilities: usize,
    pub(crate) navigation_entries: usize,
}

#[derive(Debug, Deserialize)]
struct Frontmatter {
    title: String,
    description: String,
    status: String,
    implementation: String,
    #[serde(alias = "profile-availability")]
    profile_availability: Vec<String>,
    #[serde(alias = "public-exposure")]
    public_exposure: String,
    audience: Vec<String>,
    topics: Vec<String>,
    capabilities: Vec<String>,
    source: Vec<String>,
    evidence: Vec<String>,
    #[serde(alias = "last-verified")]
    last_verified: String,
    #[serde(flatten)]
    _additional: BTreeMap<String, Value>,
}

#[derive(Debug)]
struct Page {
    relative: String,
    frontmatter: Frontmatter,
    body: String,
    body_start_line: usize,
    anchors: BTreeSet<String>,
    links: Vec<Link>,
}

#[derive(Debug)]
struct Link {
    target: String,
    fragment: Option<String>,
    line: usize,
}

#[derive(Debug)]
struct Table {
    headers: Vec<String>,
    rows: Vec<TableRow>,
}

#[derive(Debug)]
struct TableRow {
    cells: Vec<String>,
    line: usize,
}

#[derive(Debug)]
struct CoverageRow {
    capabilities: Vec<String>,
    owner_page: String,
    status: String,
    implementation: String,
    profiles: Vec<String>,
    exposure: String,
    primary_evidence: String,
    evidence_owner: String,
    writing_owner: String,
    reviewer: String,
    verification: String,
    gaps: String,
    modules: Vec<String>,
    profile_evidence: String,
    exposure_evidence: String,
    line: usize,
}

#[derive(Debug, Default)]
struct Catalogs {
    profile_modules: BTreeMap<String, BTreeSet<String>>,
    modules: BTreeSet<String>,
}

pub(crate) fn verify(workspace: &Path) -> Result<DocsSummary> {
    let docs_root = workspace.join("docs");
    ensure!(
        docs_root.is_dir(),
        "docs: documentation directory does not exist"
    );
    for relative in CENTRAL_DOCUMENTS {
        ensure!(
            workspace.join(relative).is_file(),
            "{relative}: required central documentation file does not exist"
        );
    }

    let mut pages = collect_pages(workspace, &docs_root)?;
    pages.sort_by(|left, right| left.relative.cmp(&right.relative));
    ensure!(!pages.is_empty(), "docs: no Markdown pages were found");

    validate_unique_page_metadata(&pages)?;
    let catalogs = load_catalogs(workspace)?;
    validate_frontmatter(workspace, &pages, &catalogs)?;
    validate_links(workspace, &pages)?;
    validate_content(workspace, &pages)?;

    let coverage_page = page_by_relative(&pages, "docs/coverage-matrix.md")?;
    let coverage = parse_coverage(coverage_page)?;
    let evidence_page = page_by_relative(&pages, "docs/evidence-inventory.md")?;
    let evidence = parse_evidence_inventory(evidence_page)?;
    validate_coverage(workspace, &pages, &coverage, &evidence, &catalogs)?;

    let navigation_page = page_by_relative(&pages, "docs/navigation.md")?;
    let navigation_entries = validate_navigation(&pages, navigation_page)?;
    validate_central_references(workspace, &pages, &coverage, &evidence)?;
    for relative in [
        "docs/navigation.md",
        "docs/journeys.md",
        "docs/verification-plan.md",
    ] {
        validate_role_evidence_tables(page_by_relative(&pages, relative)?)?;
    }

    Ok(DocsSummary {
        pages: pages.len(),
        capabilities: coverage.iter().map(|row| row.capabilities.len()).sum(),
        navigation_entries,
    })
}

fn collect_pages(workspace: &Path, docs_root: &Path) -> Result<Vec<Page>> {
    let mut paths = WalkDir::new(docs_root)
        .follow_links(false)
        .into_iter()
        .filter_entry(|entry| {
            entry.depth() == 0 || !entry.file_name().to_string_lossy().starts_with('.')
        })
        .filter_map(|entry| match entry {
            Ok(entry)
                if entry.file_type().is_file()
                    && entry.path().extension().is_some_and(|ext| ext == "md") =>
            {
                Some(Ok(entry.into_path()))
            }
            Ok(_) => None,
            Err(error) => Some(Err(error.into())),
        })
        .collect::<Result<Vec<PathBuf>>>()?;
    paths.sort();
    paths
        .iter()
        .map(|path| parse_page(workspace, path))
        .collect()
}

fn parse_page(workspace: &Path, path: &Path) -> Result<Page> {
    let relative = repo_relative(workspace, path)?;
    let source = fs::read_to_string(path).with_context(|| format!("{relative}: read page"))?;
    let (yaml, body, body_start_line) =
        split_frontmatter(&source).with_context(|| format!("{relative}: malformed frontmatter"))?;
    let frontmatter: Frontmatter = serde_yaml::from_str(yaml)
        .with_context(|| format!("{relative}: parse YAML frontmatter"))?;
    let (anchors, links) = scan_markdown(&relative, body, body_start_line)?;
    Ok(Page {
        relative,
        frontmatter,
        body: body.to_owned(),
        body_start_line,
        anchors,
        links,
    })
}

fn split_frontmatter(source: &str) -> Result<(&str, &str, usize)> {
    ensure!(
        source.starts_with("---\n"),
        "frontmatter must begin with `---` on line 1"
    );
    let remainder = &source[4..];
    let Some(end) = remainder.find("\n---\n") else {
        bail!("frontmatter has no closing `---`");
    };
    let yaml = &remainder[..end];
    ensure!(!yaml.trim().is_empty(), "frontmatter is empty");
    let body = &remainder[end + 5..];
    let body_start_line = yaml.lines().count() + 4;
    Ok((yaml, body, body_start_line))
}

fn scan_markdown(
    relative: &str,
    body: &str,
    body_start_line: usize,
) -> Result<(BTreeSet<String>, Vec<Link>)> {
    let heading = Regex::new(r"^#{1,6}\s+(.+?)\s*#*\s*$")?;
    let link = Regex::new(r#"\[[^\]]*\]\((?:<([^>]+)>|([^\s)]+))(?:\s+[\"'][^\"']*[\"'])?\)"#)?;
    let mut anchors = BTreeSet::new();
    let mut links = Vec::new();
    let mut fence: Option<(char, usize)> = None;
    for (offset, line) in body.lines().enumerate() {
        let line_number = body_start_line + offset;
        if let Some((character, width)) = fence_marker(line) {
            match fence {
                Some((open, minimum)) if open == character && width >= minimum => fence = None,
                None => fence = Some((character, width)),
                _ => {}
            }
            continue;
        }
        if fence.is_some() {
            continue;
        }
        if let Some(captures) = heading.captures(line) {
            let title = captures.get(1).map_or("", |capture| capture.as_str());
            let anchor = normalize_anchor(title);
            ensure!(
                !anchor.is_empty(),
                "{relative}:{line_number}: heading has an empty anchor"
            );
            ensure!(
                anchors.insert(anchor.clone()),
                "{relative}:{line_number}: duplicate normalized anchor `#{anchor}`"
            );
        }
        for captures in link.captures_iter(line) {
            let raw = captures
                .get(1)
                .or_else(|| captures.get(2))
                .map_or("", |capture| capture.as_str());
            if raw.is_empty() || is_external_link(raw) {
                continue;
            }
            let (target, fragment) = raw
                .split_once('#')
                .map_or((raw, None), |(target, fragment)| (target, Some(fragment)));
            links.push(Link {
                target: percent_decode(target)?,
                fragment: fragment.map(percent_decode).transpose()?,
                line: line_number,
            });
        }
    }
    ensure!(
        fence.is_none(),
        "{relative}:{}: unterminated fenced code block",
        body_start_line + body.lines().count().saturating_sub(1)
    );
    Ok((anchors, links))
}

fn validate_unique_page_metadata(pages: &[Page]) -> Result<()> {
    let mut titles = BTreeMap::<&str, &str>::new();
    let mut capabilities = BTreeMap::<&str, &str>::new();
    for page in pages {
        let title = page.frontmatter.title.trim();
        ensure!(
            !title.is_empty(),
            "{}: frontmatter `title` must not be empty",
            page.relative
        );
        if let Some(previous) = titles.insert(title, &page.relative) {
            bail!(
                "{}: duplicate title `{title}` also used by {previous}",
                page.relative
            );
        }
        for capability in &page.frontmatter.capabilities {
            let capability = capability.trim();
            ensure!(
                !capability.is_empty(),
                "{}: frontmatter `capabilities` contains an empty value",
                page.relative
            );
            if let Some(previous) = capabilities.insert(capability, &page.relative) {
                bail!(
                    "{}: capability `{capability}` has duplicate owners; first owned by {previous}",
                    page.relative
                );
            }
        }
    }
    Ok(())
}

fn validate_frontmatter(workspace: &Path, pages: &[Page], catalogs: &Catalogs) -> Result<()> {
    let pages_by_path = pages
        .iter()
        .map(|page| (page.relative.as_str(), page))
        .collect::<BTreeMap<_, _>>();
    for page in pages {
        let frontmatter = &page.frontmatter;
        ensure!(
            !frontmatter.description.trim().is_empty(),
            "{}: frontmatter `description` must not be empty",
            page.relative
        );
        ensure_one_of(&page.relative, "status", &frontmatter.status, STATUS_VALUES)?;
        ensure_one_of(
            &page.relative,
            "implementation",
            &frontmatter.implementation,
            IMPLEMENTATION_VALUES,
        )?;
        ensure_one_of(
            &page.relative,
            "public_exposure",
            &frontmatter.public_exposure,
            EXPOSURE_VALUES,
        )?;
        ensure!(
            !frontmatter.audience.is_empty(),
            "{}: frontmatter `audience` must contain at least one value",
            page.relative
        );
        ensure!(
            !frontmatter.topics.is_empty(),
            "{}: frontmatter `topics` must contain at least one value",
            page.relative
        );
        ensure_unique_array(
            &page.relative,
            "profile_availability",
            &frontmatter.profile_availability,
        )?;
        ensure_unique_array(&page.relative, "audience", &frontmatter.audience)?;
        ensure_unique_array(&page.relative, "topics", &frontmatter.topics)?;
        ensure_unique_array(&page.relative, "capabilities", &frontmatter.capabilities)?;
        ensure_unique_array(&page.relative, "source", &frontmatter.source)?;
        ensure_unique_array(&page.relative, "evidence", &frontmatter.evidence)?;
        let verified_day = parse_date(&frontmatter.last_verified)
            .with_context(|| format!("{}: invalid frontmatter `last_verified`", page.relative))?;
        for profile in &frontmatter.profile_availability {
            ensure!(
                catalogs.profile_modules.contains_key(profile),
                "{}: unknown profile ID `{profile}`",
                page.relative
            );
        }
        for reference in frontmatter.source.iter().chain(&frontmatter.evidence) {
            let resolved = validate_repo_path(workspace, &page.relative, reference)?;
            let referenced_relative = repo_relative(workspace, &resolved)?;
            let Some(referenced_page) = pages_by_path.get(referenced_relative.as_str()) else {
                continue;
            };
            let referenced_verified_day = parse_date(&referenced_page.frontmatter.last_verified)
                .with_context(|| {
                    format!(
                        "{}: invalid frontmatter `last_verified`",
                        referenced_page.relative
                    )
                })?;
            ensure!(
                referenced_verified_day <= verified_day,
                "{}: documentation reference `{reference}` was last verified {} after this page's \
                 last_verified {}; re-verify the page",
                page.relative,
                referenced_page.frontmatter.last_verified,
                frontmatter.last_verified
            );
        }
    }
    Ok(())
}

fn validate_links(workspace: &Path, pages: &[Page]) -> Result<()> {
    let canonical_workspace = workspace
        .canonicalize()
        .with_context(|| format!("canonicalize {}", workspace.display()))?;
    let by_path = pages
        .iter()
        .map(|page| (page.relative.as_str(), page))
        .collect::<BTreeMap<_, _>>();
    for page in pages {
        for link in &page.links {
            let target = if link.target.is_empty() {
                page.relative.clone()
            } else {
                resolve_repository_link_target(&page.relative, &link.target).with_context(|| {
                    format!(
                        "{}:{}: invalid relative link `{}`",
                        page.relative, link.line, link.target
                    )
                })?
            };
            let docs_target = (link.target.ends_with('/') && target.starts_with("docs/"))
                .then(|| format!("{target}/README.md"));
            let collected_target = docs_target.as_deref().unwrap_or(&target);
            if let Some(target_page) = by_path.get(collected_target) {
                validate_link_fragment(page, link, collected_target, &target_page.anchors)?;
                continue;
            }
            ensure!(
                !collected_target.starts_with("docs/") || !collected_target.ends_with(".md"),
                "{}:{}: link target `{collected_target}` does not exist",
                page.relative,
                link.line
            );
            let candidate = validate_workspace_link_target(
                workspace,
                &canonical_workspace,
                page,
                link,
                &target,
            )?;
            if link.fragment.is_some()
                && candidate.is_file()
                && candidate
                    .extension()
                    .is_some_and(|extension| extension == "md")
            {
                let source = fs::read_to_string(&candidate).with_context(|| {
                    format!(
                        "{}:{}: read external Markdown link target {target}",
                        page.relative, link.line
                    )
                })?;
                let (anchors, _) = scan_markdown(&target, &source, 1).with_context(|| {
                    format!(
                        "{}:{}: parse external Markdown link target {target}",
                        page.relative, link.line
                    )
                })?;
                validate_link_fragment(page, link, &target, &anchors)?;
            }
        }
    }
    Ok(())
}

fn validate_workspace_link_target(
    workspace: &Path,
    canonical_workspace: &Path,
    page: &Page,
    link: &Link,
    target: &str,
) -> Result<PathBuf> {
    let candidate = workspace.join(target);
    ensure!(
        candidate.exists(),
        "{}:{}: link target `{target}` does not exist",
        page.relative,
        link.line
    );
    let canonical_candidate = candidate.canonicalize().with_context(|| {
        format!(
            "{}:{}: canonicalize link target `{target}`",
            page.relative, link.line
        )
    })?;
    ensure!(
        canonical_candidate.starts_with(canonical_workspace),
        "{}:{}: link target `{target}` resolves outside the repository",
        page.relative,
        link.line
    );
    Ok(candidate)
}

fn validate_link_fragment(
    page: &Page,
    link: &Link,
    target: &str,
    anchors: &BTreeSet<String>,
) -> Result<()> {
    if let Some(fragment) = &link.fragment {
        let anchor = normalize_anchor(fragment);
        ensure!(
            anchors.contains(&anchor),
            "{}:{}: link fragment `#{fragment}` does not exist in {target}",
            page.relative,
            link.line
        );
    }
    Ok(())
}

fn validate_content(workspace: &Path, pages: &[Page]) -> Result<()> {
    let placeholder =
        Regex::new(r"(?i)(?:\bTODO\b|\bTBD\b|\bFIXME\b|\?\?\?|todo!\s*\(|unimplemented!\s*\()")?;
    let local_path =
        Regex::new(r"(?i)(?:file://|/Users/[^\s`]+|/home/[^\s`]+|[A-Z]:\\Users\\[^\s`]+)")?;
    let secret = Regex::new(
        r#"(?i)\b(?:password|secret|token|api[_-]?key)\s*[:=]\s*[\"'][^\"'$<{][^\"']{7,}[\"']|\b(?:AKIA|ASIA)[A-Z0-9]{16}\b"#,
    )?;
    let cargo_packages = cargo_packages(workspace)?;
    let package_scripts = package_scripts(workspace)?;
    for page in pages {
        for (name, regex) in [
            ("placeholder", &placeholder),
            ("absolute local path", &local_path),
            ("secret-looking value", &secret),
        ] {
            if let Some(found) = regex.find(&page.body) {
                let line = page.body_start_line
                    + page.body[..found.start()].lines().count().saturating_sub(1);
                bail!(
                    "{}:{line}: forbidden {name} `{}`",
                    page.relative,
                    found.as_str()
                );
            }
        }
        validate_fences(page)?;
        validate_documented_commands(page, workspace, &cargo_packages, &package_scripts)?;
    }
    Ok(())
}

fn validate_fences(page: &Page) -> Result<()> {
    let mut open: Option<(char, usize, String, usize, String)> = None;
    for (offset, line) in page.body.lines().enumerate() {
        let line_number = page.body_start_line + offset;
        if let Some((character, width)) = fence_marker(line) {
            if let Some((opener, minimum, language, start, content)) = open.take() {
                if opener == character && width >= minimum {
                    match language.as_str() {
                        "json" => {
                            serde_json::from_str::<serde_json::Value>(&content).with_context(
                                || format!("{}:{start}: invalid JSON fence", page.relative),
                            )?;
                        }
                        "yaml" | "yml" => {
                            serde_yaml::from_str::<Value>(&content).with_context(|| {
                                format!("{}:{start}: invalid YAML fence", page.relative)
                            })?;
                        }
                        "toml" => {
                            toml::from_str::<toml::Value>(&content).with_context(|| {
                                format!("{}:{start}: invalid TOML fence", page.relative)
                            })?;
                        }
                        _ => {}
                    }
                } else {
                    open = Some((opener, minimum, language, start, content));
                }
            } else {
                let language = line
                    .trim_start()
                    .trim_start_matches(character)
                    .split_whitespace()
                    .next()
                    .unwrap_or("")
                    .to_ascii_lowercase();
                open = Some((character, width, language, line_number, String::new()));
            }
        } else if let Some((_, _, _, _, content)) = open.as_mut() {
            content.push_str(line);
            content.push('\n');
        }
    }
    ensure!(
        open.is_none(),
        "{}: unterminated fenced code block",
        page.relative
    );
    Ok(())
}

fn validate_documented_commands(
    page: &Page,
    workspace: &Path,
    cargo_packages: &BTreeMap<String, BTreeSet<String>>,
    package_scripts: &BTreeSet<String>,
) -> Result<()> {
    let xtask = Regex::new(r"cargo\s+(?:run\s+-p\s+xtask\s+--|xtask)\s+([^\n`]+)")?;
    for captures in xtask.captures_iter(&page.body) {
        let arguments = captures.get(1).map_or("", |capture| capture.as_str());
        let arguments = shell_words(arguments);
        ensure!(
            supported_xtask_command(&arguments),
            "{}: documented command `cargo xtask {}` is not supported by xtask",
            page.relative,
            arguments.join(" ")
        );
    }
    let cargo_run = Regex::new(r"\bcargo\s+run\s+([^\n`]+)")?;
    for captures in cargo_run.captures_iter(&page.body) {
        let Some(arguments_match) = captures.get(1) else {
            continue;
        };
        let arguments = shell_words(arguments_match.as_str());
        let line = page.body_start_line
            + page.body[..captures.get(0).map_or(0, |capture| capture.start())]
                .bytes()
                .filter(|byte| *byte == b'\n')
                .count();
        let command = format!("cargo run {}", arguments.join(" "));
        let selection = parse_cargo_run(&arguments).map_err(|error| {
            anyhow::anyhow!(
                "{}:{line}: documented command `{command}`: {error}",
                page.relative
            )
        })?;
        let selected_packages = selection
            .manifest_path
            .map(|manifest_path| {
                selected_cargo_packages(workspace, manifest_path).map_err(|error| {
                    anyhow::anyhow!(
                        "{}:{line}: documented command `{command}`: {error}",
                        page.relative
                    )
                })
            })
            .transpose()?
            .flatten();
        if selection.manifest_path.is_some() && selected_packages.is_none() {
            continue;
        }
        let Some(package) = selection.package else {
            continue;
        };
        let packages = selected_packages.as_ref().unwrap_or(cargo_packages);
        let binaries = packages.get(package).ok_or_else(|| {
            anyhow::anyhow!(
                "{}:{line}: documented command `{command}` selects unknown Cargo package `{package}`",
                page.relative
            )
        })?;
        if let Some(binary) = selection.binary {
            ensure!(
                binaries.contains(binary),
                "{}:{line}: documented command `{command}` selects binary `{binary}`, but Cargo package `{package}` only defines: {}",
                page.relative,
                display_binary_targets(binaries)
            );
        } else {
            ensure!(
                !binaries.is_empty(),
                "{}:{line}: documented command `{command}` selects Cargo package `{package}`, which does not define a binary target",
                page.relative
            );
            ensure!(
                binaries.len() == 1,
                "{}:{line}: documented command `{command}` is ambiguous because Cargo package `{package}` defines multiple binary targets: {}; add `--bin <name>`",
                page.relative,
                display_binary_targets(binaries)
            );
        }
    }
    let pnpm = Regex::new(r"(?m)(?:^[ \t]*(?:\$\s+)?|`(?:\$\s+)?)pnpm(?:[ \t]+([^\n`]+))?")?;
    for captures in pnpm.captures_iter(&page.body) {
        let arguments = shell_words(captures.get(1).map_or("", |capture| capture.as_str()));
        let command = if arguments.is_empty() {
            "pnpm".to_owned()
        } else {
            format!("pnpm {}", arguments.join(" "))
        };
        let selection = parse_pnpm_command(&arguments).map_err(|error| {
            anyhow::anyhow!("{}: documented command `{command}`: {error}", page.relative)
        })?;
        let selected_scripts = selection
            .directory
            .map(|directory| {
                selected_package_scripts(workspace, directory).map_err(|error| {
                    anyhow::anyhow!("{}: documented command `{command}`: {error}", page.relative)
                })
            })
            .transpose()?;
        let Some(script) = selection.script else {
            continue;
        };
        let (scripts, manifest) = match (selected_scripts.as_ref(), selection.directory) {
            (Some(scripts), Some(directory)) => (
                scripts,
                Path::new(directory)
                    .join("package.json")
                    .display()
                    .to_string(),
            ),
            _ => (package_scripts, "package.json".to_owned()),
        };
        ensure!(
            scripts.contains(script),
            "{}: documented pnpm command `{command}` selects script `{script}`, but {manifest} does not define it",
            page.relative
        );
    }
    let package_command = Regex::new(r"\b(?:npm|yarn)\s+(?:run\s+)?([a-zA-Z0-9:_-]+)")?;
    for captures in package_command.captures_iter(&page.body) {
        let script = captures.get(1).map_or("", |capture| capture.as_str());
        if package_command_builtin(script) {
            continue;
        }
        ensure!(
            package_scripts.contains(script),
            "{}: documented package script `{script}` does not exist in package.json",
            page.relative
        );
    }
    Ok(())
}

#[derive(Clone, Copy)]
struct PnpmCommand<'a> {
    directory: Option<&'a str>,
    script: Option<&'a str>,
}

fn parse_pnpm_command(arguments: &[String]) -> Result<PnpmCommand<'_>> {
    let mut directory = None;
    let mut index = 0;
    while let Some(argument) = arguments.get(index) {
        match argument.as_str() {
            "--dir" | "-C" => {
                let value = arguments
                    .get(index + 1)
                    .map(String::as_str)
                    .filter(|value| !value.is_empty())
                    .with_context(|| format!("option `{argument}` requires a directory"))?;
                directory = Some(value);
                index += 2;
            }
            "run" => {
                let script = arguments.get(index + 1).map(String::as_str);
                ensure!(
                    script.is_none_or(|script| !script.starts_with('-')),
                    "option `{}` after `run` is not supported",
                    script.unwrap_or_default()
                );
                return Ok(PnpmCommand { directory, script });
            }
            argument if package_command_builtin(argument) => {
                return Ok(PnpmCommand {
                    directory,
                    script: None,
                });
            }
            argument if argument.starts_with('-') => {
                bail!("option `{argument}` is not supported");
            }
            script => {
                return Ok(PnpmCommand {
                    directory,
                    script: Some(script),
                });
            }
        }
    }
    Ok(PnpmCommand {
        directory,
        script: None,
    })
}

fn package_command_builtin(command: &str) -> bool {
    matches!(command, "install" | "add" | "remove" | "exec" | "dlx")
}

fn selected_package_scripts(workspace: &Path, directory: &str) -> Result<BTreeSet<String>> {
    let workspace = workspace
        .canonicalize()
        .with_context(|| format!("resolve workspace {}", workspace.display()))?;
    let requested = workspace.join(directory);
    let selected = requested
        .canonicalize()
        .with_context(|| format!("package directory `{directory}` does not exist"))?;
    ensure!(
        selected.starts_with(&workspace),
        "package directory `{directory}` is outside the workspace"
    );
    ensure!(
        selected.is_dir(),
        "package directory `{directory}` is not a directory"
    );
    ensure!(
        selected.join("package.json").is_file(),
        "package directory `{directory}` does not contain package.json"
    );
    package_scripts(&selected)
}

#[derive(Clone, Copy)]
struct CargoRun<'a> {
    manifest_path: Option<&'a str>,
    package: Option<&'a str>,
    binary: Option<&'a str>,
}

fn parse_cargo_run(arguments: &[String]) -> Result<CargoRun<'_>> {
    let mut manifest_path = None;
    let mut package = None;
    let mut binary = None;
    let mut index = 0;
    while let Some(argument) = arguments.get(index) {
        if argument == "--" {
            break;
        }
        match argument.as_str() {
            "--manifest-path" | "-p" | "--package" | "--bin" => {
                let value = arguments
                    .get(index + 1)
                    .map(String::as_str)
                    .filter(|value| !value.is_empty() && !value.starts_with('-'))
                    .with_context(|| format!("option `{argument}` requires a value"))?;
                match argument.as_str() {
                    "--manifest-path" => manifest_path = Some(value),
                    "-p" | "--package" => package = Some(value),
                    "--bin" => binary = Some(value),
                    _ => unreachable!(),
                }
                index += 1;
            }
            _ => {
                if let Some(value) = argument.strip_prefix("--manifest-path=") {
                    ensure!(
                        !value.is_empty(),
                        "option `--manifest-path` requires a value"
                    );
                    manifest_path = Some(value);
                } else if let Some(value) = argument.strip_prefix("--package=") {
                    ensure!(!value.is_empty(), "option `--package` requires a value");
                    package = Some(value);
                } else if let Some(value) = argument.strip_prefix("--bin=") {
                    ensure!(!value.is_empty(), "option `--bin` requires a value");
                    binary = Some(value);
                } else if let Some(value) = argument.strip_prefix("-p")
                    && !value.is_empty()
                {
                    package = Some(value);
                }
            }
        }
        index += 1;
    }
    Ok(CargoRun {
        manifest_path,
        package,
        binary,
    })
}

fn selected_cargo_packages(
    workspace: &Path,
    manifest_path: &str,
) -> Result<Option<BTreeMap<String, BTreeSet<String>>>> {
    let workspace = workspace
        .canonicalize()
        .with_context(|| format!("resolve workspace {}", workspace.display()))?;
    let mut relative = PathBuf::new();
    for component in Path::new(manifest_path).components() {
        match component {
            Component::Normal(component) => relative.push(component),
            Component::CurDir => {}
            Component::ParentDir => {
                ensure!(
                    relative.pop(),
                    "manifest path `{manifest_path}` is outside the workspace"
                );
            }
            Component::RootDir | Component::Prefix(_) => {
                bail!("manifest path `{manifest_path}` is outside the workspace");
            }
        }
    }
    ensure!(
        !relative.as_os_str().is_empty(),
        "manifest path `{manifest_path}` is empty"
    );

    let requested = workspace.join(&relative);
    let existing_ancestor = requested
        .ancestors()
        .find(|ancestor| ancestor.exists())
        .context("manifest path has no existing ancestor")?
        .canonicalize()
        .with_context(|| format!("resolve manifest path `{manifest_path}`"))?;
    ensure!(
        existing_ancestor.starts_with(&workspace),
        "manifest path `{manifest_path}` is outside the workspace"
    );
    if !requested.exists() {
        ensure!(
            relative.starts_with("target"),
            "manifest path `{manifest_path}` does not exist"
        );
        return Ok(None);
    }

    let selected = requested
        .canonicalize()
        .with_context(|| format!("resolve manifest path `{manifest_path}`"))?;
    ensure!(
        selected.starts_with(&workspace),
        "manifest path `{manifest_path}` is outside the workspace"
    );
    ensure!(
        selected.is_file(),
        "manifest path `{manifest_path}` is not a file"
    );
    cargo_packages_from_manifest(&selected).map(Some)
}

fn display_binary_targets(binaries: &BTreeSet<String>) -> String {
    binaries
        .iter()
        .map(|binary| format!("`{binary}`"))
        .collect::<Vec<_>>()
        .join(", ")
}

fn supported_xtask_command(arguments: &[String]) -> bool {
    match arguments {
        [scope, command]
            if scope == "specs" && matches!(command.as_str(), "generate" | "verify") =>
        {
            true
        }
        [scope, area, command]
            if scope == "specs" && area == "extensions" && command == "record" =>
        {
            true
        }
        [scope, command, ..] if scope == "profiles" && command == "generate-verify" => true,
        [scope, command] if scope == "profiles" && command == "verify" => true,
        [scope, command] if scope == "ai" && command == "verify" => true,
        [scope, command] if scope == "docs" && command == "verify" => true,
        [scope, command]
            if scope == "openapi" && matches!(command.as_str(), "generate" | "verify") =>
        {
            true
        }
        [scope, command, _] if scope == "openapi" && command == "breaking" => true,
        [scope, command]
            if scope == "asyncapi" && matches!(command.as_str(), "generate" | "verify") =>
        {
            true
        }
        [scope, command]
            if scope == "contracts" && matches!(command.as_str(), "generate" | "check") =>
        {
            true
        }
        [scope, command, flag, _]
            if scope == "contracts" && command == "diff" && flag == "--against" =>
        {
            true
        }
        [scope, command, _, _] if scope == "email" && command == "lint" => true,
        [scope, command, _, _, _] if scope == "email" && command == "preview" => true,
        [scope, command, ..]
            if scope == "service"
                && matches!(
                    command.as_str(),
                    "add" | "remove" | "upgrade" | "doctor" | "diff"
                ) =>
        {
            true
        }
        _ => false,
    }
}

fn parse_coverage(page: &Page) -> Result<Vec<CoverageRow>> {
    let tables = parse_tables(page)?;
    let table = tables
        .iter()
        .find(|table| {
            table.headers.iter().any(|header| {
                matches!(
                    header.as_str(),
                    "capability" | "capability_id" | "capability_id_s" | "stable_id"
                )
            })
        })
        .ok_or_else(|| anyhow::anyhow!("{}: coverage table was not found", page.relative))?;
    let required = [
        &[
            "capability",
            "capability_id",
            "capability_id_s",
            "stable_id",
        ][..],
        &["owner_page", "page", "documentation_owner_page"][..],
        &["maturity", "status"][..],
        &["implementation"][..],
        &["profile_availability", "profiles"][..],
        &["public_exposure", "exposure"][..],
        &["primary_evidence", "evidence"][..],
        &["evidence_owner"][..],
        &["writing_owner"][..],
        &["independent_reviewer", "reviewer"][..],
        &["verification_method_result", "verification"][..],
        &["notes_gaps", "gaps", "notes"][..],
    ];
    for aliases in required {
        ensure!(
            find_header(&table.headers, aliases).is_some(),
            "{}: coverage table is missing required column `{}`",
            page.relative,
            aliases[0]
        );
    }
    ensure!(
        !table.rows.is_empty(),
        "{}: coverage table has no capability rows",
        page.relative
    );
    table
        .rows
        .iter()
        .map(|row| {
            let value =
                |aliases: &[&str]| cell(table, row, aliases).unwrap_or("").trim().to_owned();
            let capabilities = split_values(&value(&[
                "capability",
                "capability_id",
                "capability_id_s",
                "stable_id",
            ]));
            ensure!(
                !capabilities.is_empty(),
                "{}:{}: coverage capability is empty",
                page.relative,
                row.line
            );
            Ok(CoverageRow {
                capabilities,
                owner_page: markdown_value(&value(&[
                    "owner_page",
                    "page",
                    "documentation_owner_page",
                ])),
                status: strip_markup(&value(&["maturity", "status"])),
                implementation: strip_markup(&value(&["implementation"])),
                profiles: split_values(&value(&["profile_availability", "profiles"])),
                exposure: strip_markup(&value(&["public_exposure", "exposure"])),
                primary_evidence: value(&["primary_evidence", "evidence"]),
                evidence_owner: value(&["evidence_owner"]),
                writing_owner: value(&["writing_owner"]),
                reviewer: value(&["independent_reviewer", "reviewer"]),
                verification: value(&["verification_method_result", "verification"]),
                gaps: value(&["notes_gaps", "gaps", "notes"]),
                modules: split_values(&value(&["module_ids", "modules"])),
                profile_evidence: value(&["profile_evidence"]),
                exposure_evidence: value(&["exposure_evidence"]),
                line: row.line,
            })
        })
        .collect()
}

fn parse_evidence_inventory(page: &Page) -> Result<BTreeMap<String, String>> {
    let mut inventory = BTreeMap::new();
    for table in parse_tables(page)? {
        let Some(id_index) = find_header(&table.headers, &["evidence_id", "id", "evidence"]) else {
            continue;
        };
        let Some(path_index) = find_header(
            &table.headers,
            &["path", "source_path", "artifact", "location"],
        ) else {
            continue;
        };
        for row in &table.rows {
            let id = strip_markup(&row.cells[id_index]);
            let path = markdown_value(&row.cells[path_index]);
            ensure!(
                !id.is_empty(),
                "{}:{}: evidence ID is empty",
                page.relative,
                row.line
            );
            ensure!(
                !path.is_empty(),
                "{}:{}: evidence path is empty",
                page.relative,
                row.line
            );
            ensure!(
                inventory.insert(id.clone(), path).is_none(),
                "{}:{}: duplicate evidence ID `{id}`",
                page.relative,
                row.line
            );
        }
    }
    for path in extract_backtick_values(&page.body)
        .into_iter()
        .filter(|value| looks_like_repo_path(value))
    {
        inventory.entry(path.clone()).or_insert(path);
    }
    Ok(inventory)
}

fn validate_coverage(
    workspace: &Path,
    pages: &[Page],
    rows: &[CoverageRow],
    evidence: &BTreeMap<String, String>,
    catalogs: &Catalogs,
) -> Result<()> {
    let pages_by_path = pages
        .iter()
        .map(|page| (page.relative.as_str(), page))
        .collect::<BTreeMap<_, _>>();
    let mut owner_row_counts = BTreeMap::<String, usize>::new();
    for row in rows {
        let owner_path = coverage_owner_path(&row.owner_page)?;
        *owner_row_counts.entry(owner_path).or_default() += 1;
    }
    let mut row_owners = BTreeMap::<&str, (&str, usize)>::new();
    for row in rows {
        ensure_one_of_at(
            "docs/coverage-matrix.md",
            row.line,
            "status",
            &row.status,
            STATUS_VALUES,
        )?;
        ensure_one_of_at(
            "docs/coverage-matrix.md",
            row.line,
            "implementation",
            &row.implementation,
            IMPLEMENTATION_VALUES,
        )?;
        ensure_one_of_at(
            "docs/coverage-matrix.md",
            row.line,
            "public exposure",
            &row.exposure,
            EXPOSURE_VALUES,
        )?;
        ensure!(
            !row.owner_page.is_empty(),
            "docs/coverage-matrix.md:{}: owner page is empty",
            row.line
        );
        let owner_path = coverage_owner_path(&row.owner_page)?;
        let owner = pages_by_path.get(owner_path.as_str()).ok_or_else(|| {
            anyhow::anyhow!(
                "docs/coverage-matrix.md:{}: owner page `{owner_path}` does not exist",
                row.line
            )
        })?;
        for field in [
            (&row.primary_evidence, "primary evidence"),
            (&row.evidence_owner, "evidence owner"),
            (&row.writing_owner, "writing owner"),
            (&row.reviewer, "independent reviewer"),
            (&row.verification, "verification method/result"),
        ] {
            ensure!(
                !field.0.trim().is_empty() && field.0.trim() != "—",
                "docs/coverage-matrix.md:{}: {} is empty",
                row.line,
                field.1
            );
        }
        for capability in &row.capabilities {
            record_capability_owner(&mut row_owners, capability, &owner.relative, row.line)?;
            ensure!(
                owner
                    .frontmatter
                    .capabilities
                    .iter()
                    .any(|owned| owned == capability),
                "docs/coverage-matrix.md:{}: capability `{capability}` is owned by {} but is absent from that page's frontmatter",
                row.line,
                owner.relative
            );
        }
        if owner_row_counts.get(&owner_path) == Some(&1) {
            ensure!(
                owner.frontmatter.status == row.status,
                "docs/coverage-matrix.md:{}: status `{}` disagrees with {} frontmatter `{}`",
                row.line,
                row.status,
                owner.relative,
                owner.frontmatter.status
            );
            ensure!(
                owner.frontmatter.implementation == row.implementation,
                "docs/coverage-matrix.md:{}: implementation `{}` disagrees with {} frontmatter `{}`",
                row.line,
                row.implementation,
                owner.relative,
                owner.frontmatter.implementation
            );
            ensure!(
                owner.frontmatter.public_exposure == row.exposure,
                "docs/coverage-matrix.md:{}: public exposure `{}` disagrees with {} frontmatter `{}`",
                row.line,
                row.exposure,
                owner.relative,
                owner.frontmatter.public_exposure
            );
            ensure!(
                as_set(&owner.frontmatter.profile_availability) == as_set(&row.profiles),
                "docs/coverage-matrix.md:{}: profile availability disagrees with {} frontmatter",
                row.line,
                owner.relative
            );
        } else {
            ensure!(
                owner.frontmatter.status == row.status,
                "docs/coverage-matrix.md:{}: status `{}` disagrees with {} frontmatter `{}`",
                row.line,
                row.status,
                owner.relative,
                owner.frontmatter.status
            );
        }
        for profile in &row.profiles {
            let selected = catalogs.profile_modules.get(profile).ok_or_else(|| {
                anyhow::anyhow!(
                    "docs/coverage-matrix.md:{}: unknown profile ID `{profile}`",
                    row.line
                )
            })?;
            for module in &row.modules {
                ensure!(
                    selected.contains(module),
                    "docs/coverage-matrix.md:{}: profile `{profile}` does not select declared module `{module}`",
                    row.line
                );
            }
        }
        for module in &row.modules {
            ensure!(
                catalogs.modules.contains(module),
                "docs/coverage-matrix.md:{}: unknown module ID `{module}`",
                row.line
            );
        }
        if matches!(row.implementation.as_str(), "partial" | "specified-only") {
            ensure!(
                !row.gaps.trim().is_empty() && row.gaps.trim() != "—",
                "docs/coverage-matrix.md:{}: `{}` capability must document gaps",
                row.line,
                row.implementation
            );
            ensure!(
                owner
                    .body
                    .to_ascii_lowercase()
                    .contains(&row.implementation),
                "{}: page must visibly label its `{}` implementation state",
                owner.relative,
                row.implementation
            );
        }
        validate_primary_evidence(workspace, row, evidence)?;
        if matches!(row.exposure.as_str(), "assembled" | "generated-only") {
            validate_exposure_evidence(workspace, owner, row, evidence)?;
        }
    }
    for page in pages {
        if CENTRAL_DOCUMENTS.contains(&page.relative.as_str()) {
            continue;
        }
        for capability in &page.frontmatter.capabilities {
            ensure!(
                row_owners.contains_key(capability.as_str()),
                "{}: capability `{capability}` is missing from docs/coverage-matrix.md",
                page.relative
            );
        }
    }
    Ok(())
}

fn record_capability_owner<'a>(
    owners: &mut BTreeMap<&'a str, (&'a str, usize)>,
    capability: &'a str,
    owner: &'a str,
    line: usize,
) -> Result<()> {
    if let Some((previous, previous_line)) = owners.insert(capability, (owner, line)) {
        bail!(
            "docs/coverage-matrix.md:{line}: capability `{capability}` has duplicate owners \
             `{previous}` (line {previous_line}) and `{owner}`"
        );
    }
    Ok(())
}

fn validate_primary_evidence(
    workspace: &Path,
    row: &CoverageRow,
    inventory: &BTreeMap<String, String>,
) -> Result<()> {
    let values = split_values(&row.primary_evidence);
    ensure!(
        !values.is_empty(),
        "docs/coverage-matrix.md:{}: primary evidence is empty",
        row.line
    );
    for value in values {
        let plain = strip_markup(&value);
        let reference = inventory.get(&plain).map_or(plain.as_str(), String::as_str);
        validate_repo_path(workspace, "docs/coverage-matrix.md", reference).with_context(|| {
            format!(
                "docs/coverage-matrix.md:{}: invalid primary evidence `{plain}`",
                row.line
            )
        })?;
    }
    Ok(())
}

fn validate_exposure_evidence(
    workspace: &Path,
    owner: &Page,
    row: &CoverageRow,
    inventory: &BTreeMap<String, String>,
) -> Result<()> {
    let mut references = owner
        .frontmatter
        .source
        .iter()
        .chain(&owner.frontmatter.evidence)
        .cloned()
        .collect::<Vec<_>>();
    references.extend(
        split_values(&row.primary_evidence)
            .into_iter()
            .map(|value| {
                inventory
                    .get(&strip_markup(&value))
                    .cloned()
                    .unwrap_or(value)
            }),
    );
    references.extend(extract_backtick_values(&row.exposure_evidence));
    references.extend(extract_backtick_values(&row.profile_evidence));
    let has_generated_artifact = references.iter().any(|reference| {
        is_generated_artifact_reference(reference)
            && validate_repo_path(workspace, &owner.relative, reference).is_ok()
    });
    let has_composition = references.iter().any(|reference| {
        let lower = reference.to_ascii_lowercase();
        (lower.contains("composition")
            || lower.ends_with("/main.rs")
            || lower.starts_with("apps/")
            || lower.contains("/apps/"))
            && validate_repo_path(workspace, &owner.relative, reference).is_ok()
    });
    if row.exposure == "generated-only" {
        ensure!(
            has_generated_artifact,
            "docs/coverage-matrix.md:{}: generated-only capability must cite an existing contract, template, generator, or profile/catalog artifact",
            row.line
        );
    } else {
        ensure!(
            has_composition,
            "docs/coverage-matrix.md:{}: assembled capability must cite an existing composition-root source",
            row.line
        );
    }
    Ok(())
}

fn is_generated_artifact_reference(reference: &str) -> bool {
    let Ok(path) = normalize_repo_reference(reference) else {
        return false;
    };
    path.starts_with("contracts/")
        || path.starts_with("templates/")
        || path.split('/').any(|component| {
            matches!(
                component,
                "generator" | "generators" | "profile" | "profiles"
            )
        })
        || path.ends_with("/profiles.yaml")
        || path.ends_with("/catalog.rs")
}

fn coverage_owner_path(value: &str) -> Result<String> {
    let path = normalize_repo_reference(value)?;
    Ok(if path.starts_with("docs/") {
        path
    } else {
        format!("docs/{path}")
    })
}
fn navigation_page_path(value: &str) -> Result<String> {
    let path = normalize_repo_reference(value)?;
    ensure!(
        path.ends_with(".md"),
        "navigation page `{path}` must target a Markdown page"
    );
    Ok(if path.starts_with("docs/") {
        path
    } else {
        format!("docs/{path}")
    })
}

fn validate_navigation(pages: &[Page], navigation: &Page) -> Result<usize> {
    let mut targets = BTreeSet::new();
    for table in parse_tables(navigation)? {
        let Some(page_index) = find_header(&table.headers, &["page"]) else {
            continue;
        };
        let owner_index = find_header(&table.headers, &["owner"]);
        let reviewer_index = find_header(&table.headers, &["reviewer"]);
        for row in &table.rows {
            let target = navigation_page_path(&row.cells[page_index]).with_context(|| {
                format!(
                    "{}:{}: invalid navigation page",
                    navigation.relative, row.line
                )
            })?;
            ensure!(
                pages.iter().any(|page| page.relative == target),
                "{}:{}: navigation page `{target}` was not collected",
                navigation.relative,
                row.line
            );
            if let Some(index) = owner_index {
                ensure!(
                    is_meaningful_cell(&row.cells[index]),
                    "{}:{}: navigation owner is empty",
                    navigation.relative,
                    row.line
                );
            }
            if let Some(index) = reviewer_index {
                ensure!(
                    is_meaningful_cell(&row.cells[index]),
                    "{}:{}: navigation reviewer is empty",
                    navigation.relative,
                    row.line
                );
            }
            ensure!(
                targets.insert(target.clone()),
                "{}:{}: duplicate navigation page `{target}`",
                navigation.relative,
                row.line
            );
        }
    }

    for page in pages {
        ensure!(
            targets.contains(&page.relative),
            "{}: orphan page is not listed in docs/navigation.md",
            page.relative
        );
    }
    Ok(targets.len())
}

fn validate_role_evidence_tables(page: &Page) -> Result<()> {
    for table in parse_tables(page)? {
        let required = table
            .headers
            .iter()
            .enumerate()
            .filter(|(_, header)| {
                header.contains("owner")
                    || header.contains("reviewer")
                    || header.contains("evidence")
                    || header.contains("result")
            })
            .collect::<Vec<_>>();
        for row in &table.rows {
            for (index, header) in &required {
                ensure!(
                    is_meaningful_cell(&row.cells[*index]),
                    "{}:{}: `{header}` is empty",
                    page.relative,
                    row.line
                );
            }
        }
    }
    Ok(())
}

fn is_meaningful_cell(value: &str) -> bool {
    let plain = strip_markup(value);
    !plain.is_empty() && plain != "—"
}

fn validate_central_references(
    workspace: &Path,
    pages: &[Page],
    coverage: &[CoverageRow],
    inventory: &BTreeMap<String, String>,
) -> Result<()> {
    let verification = page_by_relative(pages, "docs/verification-plan.md")?;
    for row in coverage {
        for id in extract_reference_ids(&row.verification)? {
            ensure!(
                verification.body.contains(&id),
                "docs/coverage-matrix.md:{}: verification reference `{id}` is absent from docs/verification-plan.md",
                row.line
            );
        }
    }
    for (id, path) in inventory {
        validate_repo_path(workspace, "docs/evidence-inventory.md", path)
            .with_context(|| format!("docs/evidence-inventory.md: evidence `{id}`"))?;
    }
    Ok(())
}

fn parse_tables(page: &Page) -> Result<Vec<Table>> {
    let lines = page.body.lines().collect::<Vec<_>>();
    let mut tables = Vec::new();
    let mut index = 0;
    let mut fence: Option<(char, usize)> = None;
    while index < lines.len() {
        if let Some((character, width)) = fence_marker(lines[index]) {
            match fence {
                Some((opener, minimum)) if opener == character && width >= minimum => {
                    fence = None;
                }
                None => {
                    fence = Some((character, width));
                }
                Some(_) => {}
            }
            index += 1;
            continue;
        }
        if fence.is_none() && index + 1 < lines.len() && is_table_separator(lines[index + 1]) {
            let headers = split_table_row(lines[index])?;
            ensure!(
                !headers.is_empty(),
                "{}:{}: table has no headers",
                page.relative,
                page.body_start_line + index
            );
            let normalized = headers
                .iter()
                .map(|header| normalize_header(header))
                .collect::<Vec<_>>();
            let unique = normalized.iter().collect::<BTreeSet<_>>();
            ensure!(
                unique.len() == normalized.len(),
                "{}:{}: table has duplicate normalized headers",
                page.relative,
                page.body_start_line + index
            );
            index += 2;
            let mut rows = Vec::new();
            while index < lines.len() && looks_like_table_row(lines[index]) {
                let cells = split_table_row(lines[index])?;
                ensure!(
                    cells.len() == normalized.len(),
                    "{}:{}: table row has {} cells; expected {}",
                    page.relative,
                    page.body_start_line + index,
                    cells.len(),
                    normalized.len()
                );
                rows.push(TableRow {
                    cells,
                    line: page.body_start_line + index,
                });
                index += 1;
            }
            tables.push(Table {
                headers: normalized,
                rows,
            });
            continue;
        }
        index += 1;
    }
    Ok(tables)
}

fn split_table_row(line: &str) -> Result<Vec<String>> {
    let trimmed = line.trim().trim_start_matches('|').trim_end_matches('|');
    let mut cells = Vec::new();
    let mut current = String::new();
    let mut escaped = false;
    let mut code_ticks = 0usize;
    for character in trimmed.chars() {
        if escaped {
            current.push(character);
            escaped = false;
        } else if character == '\\' {
            escaped = true;
        } else if character == '`' {
            code_ticks ^= 1;
            current.push(character);
        } else if character == '|' && code_ticks == 0 {
            cells.push(current.trim().to_owned());
            current.clear();
        } else {
            current.push(character);
        }
    }
    ensure!(!escaped, "table row ends with an incomplete escape");
    cells.push(current.trim().to_owned());
    Ok(cells)
}

fn load_catalogs(workspace: &Path) -> Result<Catalogs> {
    let specs = workspace.join("specs");
    let overlay = crate::extensions::Overlay::verify(&specs)?;
    let modules_document = overlay.yaml_value(&specs, "machine/module-catalog.yaml")?;
    let profiles_document = overlay.yaml_value(&specs, "machine/profiles.yaml")?;
    let modules = yaml_sequence(&modules_document, "modules")?
        .iter()
        .map(|entry| yaml_string(entry, "id"))
        .collect::<Result<BTreeSet<_>>>()?;
    let profiles = yaml_sequence(&profiles_document, "profiles")?;
    let raw = profiles
        .iter()
        .map(|entry| {
            let id = yaml_string(entry, "id")?;
            let extends = yaml_optional_string(entry, "extends")?;
            let selected = yaml_optional_sequence(entry, "modules")?
                .into_iter()
                .collect::<BTreeSet<_>>();
            Ok((id, (extends, selected)))
        })
        .collect::<Result<BTreeMap<_, _>>>()?;
    let mut profile_modules = BTreeMap::new();
    for id in raw.keys() {
        let selected = resolve_profile_modules(id, &raw, &mut BTreeSet::new())?;
        profile_modules.insert(id.clone(), selected);
    }
    Ok(Catalogs {
        profile_modules,
        modules,
    })
}

fn resolve_profile_modules(
    id: &str,
    profiles: &BTreeMap<String, (Option<String>, BTreeSet<String>)>,
    visiting: &mut BTreeSet<String>,
) -> Result<BTreeSet<String>> {
    ensure!(
        visiting.insert(id.to_owned()),
        "profile inheritance cycle at `{id}`"
    );
    let (parent, own) = profiles
        .get(id)
        .ok_or_else(|| anyhow::anyhow!("unknown inherited profile `{id}`"))?;
    let mut selected = if let Some(parent) = parent {
        resolve_profile_modules(parent, profiles, visiting)?
    } else {
        BTreeSet::new()
    };
    selected.extend(own.iter().cloned());
    visiting.remove(id);
    Ok(selected)
}

fn validate_repo_path(workspace: &Path, document: &str, reference: &str) -> Result<PathBuf> {
    let normalized = normalize_repo_reference(reference)?;
    let path = Path::new(&normalized);
    ensure!(
        !path.is_absolute(),
        "{document}: absolute path `{reference}` is not allowed"
    );
    ensure!(
        !path.components().any(|component| matches!(
            component,
            Component::ParentDir | Component::RootDir | Component::Prefix(_)
        )),
        "{document}: path `{reference}` escapes the repository"
    );
    let candidate = workspace.join(path);
    ensure!(
        candidate.exists(),
        "{document}: referenced path `{normalized}` does not exist"
    );
    let canonical_workspace = workspace
        .canonicalize()
        .with_context(|| format!("canonicalize {}", workspace.display()))?;
    let canonical_candidate = candidate
        .canonicalize()
        .with_context(|| format!("{document}: canonicalize `{normalized}`"))?;
    ensure!(
        canonical_candidate.starts_with(&canonical_workspace),
        "{document}: path `{reference}` resolves outside the repository"
    );
    Ok(candidate)
}

fn normalize_repo_reference(reference: &str) -> Result<String> {
    let value = markdown_value(reference);
    let value = value.split('#').next().unwrap_or("").trim();
    let value = value.strip_prefix("./").unwrap_or(value).replace('\\', "/");
    ensure!(!value.is_empty(), "empty repository path");
    Ok(value)
}

fn resolve_repository_link_target(source: &str, target: &str) -> Result<String> {
    let target_path = Path::new(target);
    ensure!(
        !target_path.is_absolute(),
        "absolute Markdown target is not portable"
    );
    let base = Path::new(source).parent().unwrap_or_else(|| Path::new(""));
    let mut components = Vec::<String>::new();
    for component in base.join(target_path).components() {
        match component {
            Component::Normal(value) => components.push(value.to_string_lossy().into_owned()),
            Component::CurDir => {}
            Component::ParentDir => {
                ensure!(components.pop().is_some(), "link escapes repository");
            }
            Component::RootDir | Component::Prefix(_) => bail!("link escapes repository"),
        }
    }
    Ok(components.join("/"))
}

fn page_by_relative<'a>(pages: &'a [Page], relative: &str) -> Result<&'a Page> {
    pages
        .iter()
        .find(|page| page.relative == relative)
        .ok_or_else(|| anyhow::anyhow!("{relative}: required page was not collected"))
}

fn repo_relative(workspace: &Path, path: &Path) -> Result<String> {
    Ok(path
        .strip_prefix(workspace)
        .with_context(|| format!("{} is outside workspace", path.display()))?
        .to_string_lossy()
        .replace('\\', "/"))
}

fn ensure_one_of(document: &str, field: &str, value: &str, allowed: &[&str]) -> Result<()> {
    ensure_one_of_at(document, 1, field, value, allowed)
}

fn ensure_one_of_at(
    document: &str,
    line: usize,
    field: &str,
    value: &str,
    allowed: &[&str],
) -> Result<()> {
    ensure!(
        allowed.contains(&value),
        "{document}:{line}: invalid {field} `{value}`; expected one of {}",
        allowed.join(", ")
    );
    Ok(())
}

fn ensure_unique_array(document: &str, field: &str, values: &[String]) -> Result<()> {
    let mut unique = BTreeSet::new();
    for value in values {
        ensure!(
            !value.trim().is_empty(),
            "{document}: frontmatter `{field}` contains an empty value"
        );
        ensure!(
            unique.insert(value),
            "{document}: frontmatter `{field}` contains duplicate `{value}`"
        );
    }
    Ok(())
}

fn parse_date(value: &str) -> Result<i64> {
    let parts = value.split('-').collect::<Vec<_>>();
    ensure!(
        parts.len() == 3 && parts[0].len() == 4 && parts[1].len() == 2 && parts[2].len() == 2,
        "expected YYYY-MM-DD"
    );
    let year: i32 = parts[0].parse()?;
    let month: u32 = parts[1].parse()?;
    let day: u32 = parts[2].parse()?;
    ensure!((1..=12).contains(&month), "month is out of range");
    let leap = year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
    let days_in_month = [
        31,
        if leap { 29 } else { 28 },
        31,
        30,
        31,
        30,
        31,
        31,
        30,
        31,
        30,
        31,
    ];
    ensure!(
        day > 0 && day <= days_in_month[(month - 1) as usize],
        "day is out of range"
    );
    let adjusted_year = year - i32::from(month <= 2);
    let era = if adjusted_year >= 0 {
        adjusted_year
    } else {
        adjusted_year - 399
    } / 400;
    let year_of_era = adjusted_year - era * 400;
    let shifted_month = month as i32 + if month > 2 { -3 } else { 9 };
    let day_of_year = (153 * shifted_month + 2) / 5 + day as i32 - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    Ok((era * 146_097 + day_of_era - 719_468) as i64)
}

fn normalize_anchor(value: &str) -> String {
    let mut anchor = String::new();
    let mut in_tag = false;
    for character in strip_markup(value).to_ascii_lowercase().chars() {
        match character {
            '<' => in_tag = true,
            '>' => in_tag = false,
            '-' | '_' | ' ' if !in_tag => {
                if !anchor.is_empty() && !anchor.ends_with('-') {
                    anchor.push('-');
                }
            }
            character if !in_tag && character.is_alphanumeric() => anchor.push(character),
            _ => {}
        }
    }
    anchor.trim_matches('-').to_owned()
}

fn percent_decode(value: &str) -> Result<String> {
    let bytes = value.as_bytes();
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%' {
            ensure!(
                index + 2 < bytes.len(),
                "incomplete percent escape in `{value}`"
            );
            let hex = std::str::from_utf8(&bytes[index + 1..index + 3])?;
            decoded.push(
                u8::from_str_radix(hex, 16)
                    .with_context(|| format!("invalid percent escape `%{hex}`"))?,
            );
            index += 3;
        } else {
            decoded.push(bytes[index]);
            index += 1;
        }
    }
    String::from_utf8(decoded).context("link is not UTF-8")
}

fn fence_marker(line: &str) -> Option<(char, usize)> {
    let trimmed = line.trim_start();
    let character = trimmed.chars().next()?;
    if !matches!(character, '`' | '~') {
        return None;
    }
    let width = trimmed
        .chars()
        .take_while(|candidate| *candidate == character)
        .count();
    (width >= 3).then_some((character, width))
}

fn is_external_link(link: &str) -> bool {
    link.starts_with("http://")
        || link.starts_with("https://")
        || link.starts_with("mailto:")
        || link.starts_with("data:")
        || link.starts_with("tel:")
}

fn normalize_header(value: &str) -> String {
    let mut result = String::new();
    for character in strip_markup(value).to_ascii_lowercase().chars() {
        if character.is_ascii_alphanumeric() {
            result.push(character);
        } else if !result.is_empty() && !result.ends_with('_') {
            result.push('_');
        }
    }
    result.trim_matches('_').to_owned()
}

fn find_header(headers: &[String], aliases: &[&str]) -> Option<usize> {
    headers
        .iter()
        .position(|header| aliases.contains(&header.as_str()))
}

fn cell<'a>(table: &'a Table, row: &'a TableRow, aliases: &[&str]) -> Option<&'a str> {
    find_header(&table.headers, aliases).map(|index| row.cells[index].as_str())
}

fn looks_like_table_row(line: &str) -> bool {
    let trimmed = line.trim();
    !trimmed.is_empty() && trimmed.contains('|')
}

fn is_table_separator(line: &str) -> bool {
    let Ok(cells) = split_table_row(line) else {
        return false;
    };
    !cells.is_empty()
        && cells.iter().all(|cell| {
            let value = cell.trim().trim_matches(':');
            value.len() >= 3 && value.chars().all(|character| character == '-')
        })
}

fn markdown_value(value: &str) -> String {
    let value = value.trim();
    if let Some(open) = value.find("(")
        && value.ends_with(')')
        && value[..open].contains(']')
    {
        return value[open + 1..value.len() - 1]
            .split('#')
            .next()
            .unwrap_or("")
            .trim()
            .to_owned();
    }
    strip_markup(value)
}

fn strip_markup(value: &str) -> String {
    value.trim().trim_matches('`').trim().to_owned()
}

fn split_values(value: &str) -> Vec<String> {
    value
        .replace("<br>", ",")
        .replace("<br/>", ",")
        .replace("<br />", ",")
        .split([',', ';'])
        .map(strip_markup)
        .filter(|value| !value.is_empty() && value != "—" && value != "none" && value != "[]")
        .collect()
}

fn as_set(values: &[String]) -> BTreeSet<&str> {
    values.iter().map(String::as_str).collect()
}

fn extract_backtick_values(value: &str) -> Vec<String> {
    let Ok(regex) = Regex::new(r"`([^`]+)`") else {
        return Vec::new();
    };
    regex
        .captures_iter(value)
        .filter_map(|capture| capture.get(1).map(|value| value.as_str().to_owned()))
        .collect()
}

fn looks_like_repo_path(value: &str) -> bool {
    let value = value.trim_start_matches("./");
    value.starts_with("docs/")
        || value.starts_with("crates/")
        || value.starts_with("apps/")
        || value.starts_with("contracts/")
        || value.starts_with("specs/")
        || value.starts_with("xtask/")
        || value.starts_with(".github/")
        || matches!(
            value,
            "Cargo.toml" | "Cargo.lock" | "package.json" | "pnpm-lock.yaml"
        )
}

fn extract_reference_ids(value: &str) -> Result<Vec<String>> {
    let regex = Regex::new(r"\b(?:VFY|VERIFY|CHECK)-[A-Z0-9][A-Z0-9-]*\b")?;
    Ok(regex
        .find_iter(value)
        .map(|found| found.as_str().to_owned())
        .collect())
}

fn shell_words(value: &str) -> Vec<String> {
    value
        .split_whitespace()
        .take_while(|word| !word.starts_with('#') && !matches!(*word, "&&" | "||" | "|"))
        .map(|word| word.trim_matches(['"', '\'', ';']).to_owned())
        .collect()
}
fn cargo_packages(workspace: &Path) -> Result<BTreeMap<String, BTreeSet<String>>> {
    cargo_packages_from_manifest(&workspace.join("Cargo.toml"))
}

fn cargo_packages_from_manifest(
    root_manifest_path: &Path,
) -> Result<BTreeMap<String, BTreeSet<String>>> {
    let root_manifest = parse_cargo_manifest(root_manifest_path)?;
    let root_directory = root_manifest_path
        .parent()
        .context("Cargo manifest has no parent directory")?;
    let mut manifest_paths = BTreeSet::new();
    if root_manifest.get("package").is_some() {
        manifest_paths.insert(root_manifest_path.to_owned());
    }
    if let Some(members) = root_manifest
        .get("workspace")
        .and_then(|workspace| workspace.get("members"))
    {
        let members = members
            .as_array()
            .context("Cargo.toml: workspace.members must be an array")?;
        for member in members {
            let member = member
                .as_str()
                .context("Cargo.toml: workspace member must be a string")?;
            ensure!(
                !member
                    .chars()
                    .any(|character| matches!(character, '*' | '?' | '[')),
                "Cargo.toml: workspace member glob `{member}` is not supported by docs validation"
            );
            manifest_paths.insert(root_directory.join(member).join("Cargo.toml"));
        }
    }

    let mut packages = BTreeMap::new();
    for manifest_path in manifest_paths {
        let manifest = parse_cargo_manifest(&manifest_path)?;
        let package = manifest
            .get("package")
            .and_then(toml::Value::as_table)
            .with_context(|| format!("{}: missing [package] table", manifest_path.display()))?;
        let name = package
            .get("name")
            .and_then(toml::Value::as_str)
            .with_context(|| {
                format!("{}: package.name must be a string", manifest_path.display())
            })?;
        let manifest_directory = manifest_path
            .parent()
            .context("Cargo package manifest has no parent directory")?;
        let binaries = cargo_binary_targets(manifest_directory, name, &manifest)?;
        ensure!(
            packages.insert(name.to_owned(), binaries).is_none(),
            "Cargo workspace defines duplicate package name `{name}`"
        );
    }
    Ok(packages)
}

fn parse_cargo_manifest(path: &Path) -> Result<toml::Value> {
    toml::from_str(&fs::read_to_string(path).with_context(|| format!("read {}", path.display()))?)
        .with_context(|| format!("parse {}", path.display()))
}

fn cargo_binary_targets(
    manifest_directory: &Path,
    package_name: &str,
    manifest: &toml::Value,
) -> Result<BTreeSet<String>> {
    let mut binaries = BTreeSet::new();
    let mut explicit_paths = BTreeSet::new();
    if let Some(targets) = manifest.get("bin") {
        let targets = targets.as_array().context("[[bin]] must be an array")?;
        for target in targets {
            let target = target.as_table().context("[[bin]] must be a table")?;
            let path = target.get("path").and_then(toml::Value::as_str);
            let name = target
                .get("name")
                .and_then(toml::Value::as_str)
                .or_else(|| {
                    path.and_then(|path| inferred_binary_name(Path::new(path), package_name))
                })
                .context("[[bin]] must define a name or an inferable path")?;
            binaries.insert(name.to_owned());
            if let Some(path) = path {
                explicit_paths.insert(PathBuf::from(path));
            }
        }
    }

    let autobins = manifest
        .get("package")
        .and_then(|package| package.get("autobins"))
        .and_then(toml::Value::as_bool)
        .unwrap_or(true);
    if !autobins {
        return Ok(binaries);
    }
    if manifest_directory.join("src/main.rs").is_file()
        && !explicit_paths.contains(Path::new("src/main.rs"))
    {
        binaries.insert(package_name.to_owned());
    }
    let src_bin = manifest_directory.join("src/bin");
    if src_bin.is_dir() {
        for entry in
            fs::read_dir(&src_bin).with_context(|| format!("read {}", src_bin.display()))?
        {
            let entry = entry.with_context(|| format!("read {}", src_bin.display()))?;
            let path = entry.path();
            let relative = path
                .strip_prefix(manifest_directory)
                .context("binary target path is outside its package")?;
            if explicit_paths.contains(relative) {
                continue;
            }
            if path.is_file()
                && path
                    .extension()
                    .and_then(|extension| extension.to_str())
                    .is_some_and(|extension| extension == "rs")
            {
                if let Some(name) = path.file_stem().and_then(|name| name.to_str()) {
                    binaries.insert(name.to_owned());
                }
            } else if path.join("main.rs").is_file() {
                let relative_main = relative.join("main.rs");
                if !explicit_paths.contains(&relative_main)
                    && let Some(name) = path.file_name().and_then(|name| name.to_str())
                {
                    binaries.insert(name.to_owned());
                }
            }
        }
    }
    Ok(binaries)
}

fn inferred_binary_name<'a>(path: &'a Path, package_name: &'a str) -> Option<&'a str> {
    if path
        .file_name()
        .and_then(|name| name.to_str())
        .is_some_and(|name| name == "main.rs")
    {
        let parent = path.parent()?.file_name()?.to_str()?;
        return Some(if parent == "src" {
            package_name
        } else {
            parent
        });
    }
    path.file_stem()?.to_str()
}

fn package_scripts(workspace: &Path) -> Result<BTreeSet<String>> {
    let path = workspace.join("package.json");
    if !path.is_file() {
        return Ok(BTreeSet::new());
    }
    let value: serde_json::Value = serde_json::from_str(
        &fs::read_to_string(&path).with_context(|| format!("read {}", path.display()))?,
    )
    .with_context(|| format!("parse {}", path.display()))?;
    Ok(value
        .get("scripts")
        .and_then(serde_json::Value::as_object)
        .map(|scripts| scripts.keys().cloned().collect())
        .unwrap_or_default())
}

fn yaml_sequence<'a>(document: &'a Value, key: &str) -> Result<&'a Vec<Value>> {
    document
        .get(key)
        .and_then(Value::as_sequence)
        .ok_or_else(|| anyhow::anyhow!("composed catalog `{key}` is not an array"))
}

fn yaml_string(entry: &Value, key: &str) -> Result<String> {
    entry
        .get(key)
        .and_then(Value::as_str)
        .map(ToOwned::to_owned)
        .ok_or_else(|| anyhow::anyhow!("catalog entry `{key}` is not a string"))
}

fn yaml_optional_string(entry: &Value, key: &str) -> Result<Option<String>> {
    match entry.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(value) => value
            .as_str()
            .map(|value| Some(value.to_owned()))
            .ok_or_else(|| anyhow::anyhow!("catalog entry `{key}` is not a string")),
    }
}

fn yaml_optional_sequence(entry: &Value, key: &str) -> Result<Vec<String>> {
    match entry.get(key) {
        None | Some(Value::Null) => Ok(Vec::new()),
        Some(value) => value
            .as_sequence()
            .ok_or_else(|| anyhow::anyhow!("catalog entry `{key}` is not an array"))?
            .iter()
            .map(|value| {
                value
                    .as_str()
                    .map(ToOwned::to_owned)
                    .ok_or_else(|| anyhow::anyhow!("catalog `{key}` value is not a string"))
            })
            .collect(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use omnius_test_support::CleanDirectory;

    #[test]
    fn split_frontmatter_rejects_missing_closing_delimiter() {
        let error = split_frontmatter("---\ntitle: Broken\n").unwrap_err();
        assert!(error.to_string().contains("closing"));
    }

    #[test]
    fn scan_markdown_rejects_duplicate_normalized_anchors() {
        let error =
            scan_markdown("docs/page.md", "# Same heading\n\n## Same_heading\n", 2).unwrap_err();
        assert!(error.to_string().contains("duplicate normalized anchor"));
    }

    #[test]
    fn split_table_row_preserves_escaped_and_backticked_pipes() {
        let cells = split_table_row("| one \\| two | `three | four` |").unwrap();
        assert_eq!(cells, ["one | two", "`three | four`"]);
    }

    #[test]
    fn parse_tables_tracks_fence_delimiter_and_opener_width() -> Result<()> {
        let page = test_page(
            "docs/page.md",
            "````markdown\n~~~\n| Hidden |\n| --- |\n~~~\n```rust\n```\n````\n\n| Visible |\n| --- |\n| value |\n",
        );

        let tables = parse_tables(&page)?;

        assert_eq!(tables.len(), 1);
        assert_eq!(tables[0].headers, ["visible"]);
        assert_eq!(tables[0].rows[0].cells, ["value"]);
        Ok(())
    }

    #[test]
    fn parse_date_rejects_impossible_calendar_date() {
        let error = parse_date("2025-02-29").unwrap_err();
        assert!(error.to_string().contains("day is out of range"));
    }

    #[test]
    fn navigation_inventory_resolves_root_readme_relative_to_docs() -> Result<()> {
        let navigation = test_page(
            "docs/navigation.md",
            "| Page | Owner | Reviewer |\n| --- | --- | --- |\n| README.md | Writer | Reviewer |\n| docs/navigation.md | Writer | Reviewer |\n",
        );
        let pages = [
            test_page("docs/README.md", ""),
            test_page("docs/navigation.md", &navigation.body),
        ];

        let entries = validate_navigation(&pages, &navigation)?;

        assert_eq!(entries, 2);
        Ok(())
    }

    #[test]
    fn navigation_inventory_resolves_nested_paths_relative_to_docs() -> Result<()> {
        let navigation = test_page(
            "docs/navigation.md",
            "| Page | Owner | Reviewer |\n| --- | --- | --- |\n| getting-started/overview.md | Writer | Reviewer |\n| navigation.md | Writer | Reviewer |\n",
        );
        let pages = [
            test_page("docs/getting-started/overview.md", ""),
            test_page("docs/navigation.md", &navigation.body),
        ];

        let entries = validate_navigation(&pages, &navigation)?;

        assert_eq!(entries, 2);
        Ok(())
    }

    #[test]
    fn navigation_inventory_rejects_nonexistent_docs_relative_target() {
        let navigation = test_page(
            "docs/navigation.md",
            "| Page | Owner | Reviewer |\n| --- | --- | --- |\n| missing.md | Writer | Reviewer |\n| navigation.md | Writer | Reviewer |\n",
        );
        let pages = [test_page("docs/navigation.md", &navigation.body)];

        let error = validate_navigation(&pages, &navigation).unwrap_err();

        assert!(
            error
                .to_string()
                .contains("navigation page `docs/missing.md` was not collected")
        );
    }

    #[test]
    fn navigation_links_do_not_satisfy_inventory_orphan_check() {
        let mut navigation = test_page(
            "docs/navigation.md",
            "| Page | Owner | Reviewer |\n| --- | --- | --- |\n| navigation.md | Writer | Reviewer |\n",
        );
        navigation.links.push(Link {
            target: "unlisted.md".to_owned(),
            fragment: None,
            line: 6,
        });
        let pages = [
            test_page("docs/navigation.md", &navigation.body),
            test_page("docs/unlisted.md", ""),
        ];

        let error = validate_navigation(&pages, &navigation).unwrap_err();

        assert_eq!(
            error.to_string(),
            "docs/unlisted.md: orphan page is not listed in docs/navigation.md"
        );
    }

    #[test]
    fn supported_xtask_command_rejects_unknown_command() {
        let arguments = ["docs".to_owned(), "publish".to_owned()];
        assert!(!supported_xtask_command(&arguments));
    }
    #[test]
    fn documented_cargo_run_rejects_ambiguous_package() -> Result<()> {
        let workspace = cargo_command_workspace("docs-cargo-run-ambiguous")?;
        let packages = cargo_packages(workspace.path())?;
        let page = test_page("docs/run.md", "Run the service:\n\n`cargo run -p runner`\n");

        let error =
            validate_documented_commands(&page, workspace.path(), &packages, &BTreeSet::new())
                .unwrap_err();

        assert_eq!(
            error.to_string(),
            "docs/run.md:4: documented command `cargo run -p runner` is ambiguous because Cargo package `runner` defines multiple binary targets: `runner-admin`, `runner-api`; add `--bin <name>`"
        );
        Ok(())
    }

    #[test]
    fn documented_cargo_run_accepts_explicit_package_binary() -> Result<()> {
        let workspace = cargo_command_workspace("docs-cargo-run-explicit")?;
        let packages = cargo_packages(workspace.path())?;
        let page = test_page("docs/run.md", "`cargo run -p runner --bin runner-api`\n");

        validate_documented_commands(&page, workspace.path(), &packages, &BTreeSet::new())
    }

    #[test]
    fn documented_cargo_run_rejects_binary_outside_package() -> Result<()> {
        let workspace = cargo_command_workspace("docs-cargo-run-invalid-bin")?;
        let packages = cargo_packages(workspace.path())?;
        let page = test_page(
            "docs/run.md",
            "Run the service:\n\n`cargo run -p runner --bin other`\n",
        );

        let error =
            validate_documented_commands(&page, workspace.path(), &packages, &BTreeSet::new())
                .unwrap_err();

        assert_eq!(
            error.to_string(),
            "docs/run.md:4: documented command `cargo run -p runner --bin other` selects binary `other`, but Cargo package `runner` only defines: `runner-admin`, `runner-api`"
        );
        Ok(())
    }

    #[test]
    fn documented_cargo_run_accepts_absent_generated_manifest() -> Result<()> {
        let workspace = cargo_command_workspace("docs-cargo-run-generated-manifest")?;
        let packages = cargo_packages(workspace.path())?;
        let page = test_page(
            "docs/run.md",
            "`cargo run --manifest-path target/profile-matrix/work/minimal/Cargo.toml --package matrix-minimal -- profile-info`\n\
             `cargo run --manifest-path=target/profile-matrix/work/minimal/Cargo.toml --package=matrix-minimal -- profile-info`\n",
        );

        validate_documented_commands(&page, workspace.path(), &packages, &BTreeSet::new())
    }

    #[test]
    fn documented_cargo_run_rejects_package_outside_selected_manifest() -> Result<()> {
        let workspace = cargo_command_workspace("docs-cargo-run-selected-manifest")?;
        let selected = workspace.path().join("selected");
        fs::create_dir_all(&selected)?;
        fs::write(
            selected.join("Cargo.toml"),
            "[package]\nname = \"selected\"\nversion = \"0.1.0\"\nedition = \"2024\"\n\n[workspace]\n",
        )?;
        let packages = cargo_packages(workspace.path())?;
        let page = test_page(
            "docs/run.md",
            "`cargo run --manifest-path selected/Cargo.toml --package runner`\n",
        );

        let error =
            validate_documented_commands(&page, workspace.path(), &packages, &BTreeSet::new())
                .unwrap_err();

        assert!(
            error
                .to_string()
                .contains("selects unknown Cargo package `runner`")
        );
        Ok(())
    }

    #[test]
    fn documented_cargo_run_rejects_manifest_workspace_escape() -> Result<()> {
        let workspace = cargo_command_workspace("docs-cargo-run-manifest-escape")?;
        let packages = cargo_packages(workspace.path())?;
        let page = test_page(
            "docs/run.md",
            "`cargo run --manifest-path ../outside/Cargo.toml --package runner`\n",
        );

        let error =
            validate_documented_commands(&page, workspace.path(), &packages, &BTreeSet::new())
                .unwrap_err();

        assert!(
            error
                .to_string()
                .contains("manifest path `../outside/Cargo.toml` is outside the workspace")
        );
        Ok(())
    }

    #[test]
    fn documented_cargo_run_rejects_unknown_root_package() -> Result<()> {
        let workspace = cargo_command_workspace("docs-cargo-run-unknown-root-package")?;
        let packages = cargo_packages(workspace.path())?;
        let page = test_page("docs/run.md", "`cargo run --package missing`\n");

        let error =
            validate_documented_commands(&page, workspace.path(), &packages, &BTreeSet::new())
                .unwrap_err();

        assert!(
            error
                .to_string()
                .contains("selects unknown Cargo package `missing`")
        );
        Ok(())
    }

    #[test]
    fn documented_pnpm_dir_accepts_script_from_selected_package() -> Result<()> {
        let workspace = package_command_workspace("docs-pnpm-dir-valid")?;
        let page = test_page("docs/run.md", "`pnpm --dir web test:e2e:base-path`\n");

        validate_documented_commands(
            &page,
            workspace.path(),
            &BTreeMap::new(),
            &package_scripts(workspace.path())?,
        )
    }

    #[test]
    fn documented_pnpm_dir_rejects_missing_child_script() -> Result<()> {
        let workspace = package_command_workspace("docs-pnpm-dir-missing-script")?;
        let page = test_page("docs/run.md", "`pnpm -C web missing`\n");

        let error = validate_documented_commands(
            &page,
            workspace.path(),
            &BTreeMap::new(),
            &package_scripts(workspace.path())?,
        )
        .unwrap_err();

        assert_eq!(
            error.to_string(),
            "docs/run.md: documented pnpm command `pnpm -C web missing` selects script `missing`, but web/package.json does not define it"
        );
        Ok(())
    }

    #[test]
    fn documented_pnpm_dir_rejects_workspace_escape() -> Result<()> {
        let root = CleanDirectory::new("docs-pnpm-dir-escape")?;
        let workspace = root.path().join("workspace");
        let outside = root.path().join("outside");
        fs::create_dir_all(&workspace)?;
        fs::create_dir_all(&outside)?;
        fs::write(workspace.join("package.json"), r#"{"scripts": {}}"#)?;
        fs::write(
            outside.join("package.json"),
            r#"{"scripts": {"test": "true"}}"#,
        )?;
        let page = test_page("docs/run.md", "`pnpm --dir ../outside test`\n");

        let error = validate_documented_commands(
            &page,
            &workspace,
            &BTreeMap::new(),
            &package_scripts(&workspace)?,
        )
        .unwrap_err();

        assert!(
            error
                .to_string()
                .contains("package directory `../outside` is outside the workspace")
        );
        Ok(())
    }

    #[test]
    fn structured_fence_reports_invalid_json() {
        let page = Page {
            relative: "docs/page.md".to_owned(),
            frontmatter: test_frontmatter(),
            body: "```json\n{invalid}\n```\n".to_owned(),
            body_start_line: 2,
            anchors: BTreeSet::new(),
            links: Vec::new(),
        };
        let error = validate_fences(&page).unwrap_err();
        assert!(error.to_string().contains("invalid JSON fence"));
    }

    #[test]
    fn vocabulary_validation_reports_invalid_classification() {
        let error = ensure_one_of("docs/page.md", "status", "done", STATUS_VALUES).unwrap_err();
        assert!(error.to_string().contains("invalid status `done`"));
    }
    #[test]
    fn link_validation_reports_missing_target() -> Result<()> {
        let workspace = CleanDirectory::new("docs-missing-link-target")?;
        let mut page = test_page("docs/page.md", "");
        page.links.push(Link {
            target: "missing.md".to_owned(),
            fragment: None,
            line: 7,
        });

        let error = validate_links(workspace.path(), &[page]).unwrap_err();

        assert!(
            error
                .to_string()
                .contains("docs/page.md:7: link target `docs/missing.md` does not exist")
        );
        Ok(())
    }

    #[test]
    fn link_validation_accepts_repository_external_markdown_target() -> Result<()> {
        let workspace = CleanDirectory::new("docs-external-markdown-link")?;
        let target = workspace.path().join("specs/01-system-architecture.md");
        fs::create_dir_all(target.parent().unwrap())?;
        fs::write(&target, "# System architecture\n")?;
        let mut page = test_page("docs/concepts/system.md", "");
        page.links.push(Link {
            target: "../../specs/01-system-architecture.md".to_owned(),
            fragment: None,
            line: 9,
        });

        validate_links(workspace.path(), &[page])
    }

    #[test]
    fn link_validation_reports_missing_repository_target() -> Result<()> {
        let workspace = CleanDirectory::new("docs-missing-external-link")?;
        let mut page = test_page("docs/concepts/system.md", "");
        page.links.push(Link {
            target: "../../specs/missing.md".to_owned(),
            fragment: None,
            line: 11,
        });

        let error = validate_links(workspace.path(), &[page]).unwrap_err();

        assert!(
            error.to_string().contains(
                "docs/concepts/system.md:11: link target `specs/missing.md` does not exist"
            )
        );
        Ok(())
    }

    #[test]
    fn link_validation_reports_missing_external_markdown_fragment() -> Result<()> {
        let workspace = CleanDirectory::new("docs-missing-external-fragment")?;
        let target = workspace.path().join("specs/01-system-architecture.md");
        fs::create_dir_all(target.parent().unwrap())?;
        fs::write(&target, "# System architecture\n")?;
        let mut page = test_page("docs/concepts/system.md", "");
        page.links.push(Link {
            target: "../../specs/01-system-architecture.md".to_owned(),
            fragment: Some("missing-section".to_owned()),
            line: 13,
        });

        let error = validate_links(workspace.path(), &[page]).unwrap_err();

        assert!(error.to_string().contains(
            "docs/concepts/system.md:13: link fragment `#missing-section` does not exist in \
                 specs/01-system-architecture.md"
        ));
        Ok(())
    }

    #[test]
    fn navigation_rejects_table_target_that_was_not_collected() {
        let pages = [test_page(
            "docs/navigation.md",
            "| Page | Owner |\n| --- | --- |\n| docs/missing.md | Docs team |\n",
        )];

        let error = validate_navigation(&pages, &pages[0]).unwrap_err();

        assert!(
            error.to_string().contains(
                "docs/navigation.md:4: navigation page `docs/missing.md` was not collected"
            )
        );
    }

    #[test]
    fn repository_path_validation_reports_missing_evidence() -> Result<()> {
        let workspace = CleanDirectory::new("docs-missing-evidence")?;
        let error =
            validate_repo_path(workspace.path(), "docs/page.md", "specs/missing.yaml").unwrap_err();
        assert!(error.to_string().contains("does not exist"));
        Ok(())
    }

    #[test]
    fn generated_only_accepts_existing_template_artifact() -> Result<()> {
        let workspace = CleanDirectory::new("docs-template-evidence")?;
        let artifact = workspace
            .path()
            .join("templates/base-service/template.toml");
        fs::create_dir_all(artifact.parent().unwrap())?;
        fs::write(&artifact, "")?;
        let owner = test_page("docs/page.md", "");
        let row = test_coverage_row("templates/base-service/template.toml");

        validate_exposure_evidence(workspace.path(), &owner, &row, &BTreeMap::new())?;
        Ok(())
    }

    #[test]
    fn generated_only_accepts_existing_profile_artifact() -> Result<()> {
        let workspace = CleanDirectory::new("docs-profile-evidence")?;
        let artifact = workspace
            .path()
            .join("specs/machine/extensions/example/profiles.yaml");
        fs::create_dir_all(artifact.parent().unwrap())?;
        fs::write(&artifact, "profiles: []\n")?;
        let owner = test_page("docs/page.md", "");
        let row = test_coverage_row("specs/machine/extensions/example/profiles.yaml");

        validate_exposure_evidence(workspace.path(), &owner, &row, &BTreeMap::new())?;
        Ok(())
    }

    #[test]
    fn generated_only_rejects_nonexistent_generated_artifact() -> Result<()> {
        let workspace = CleanDirectory::new("docs-missing-generated-evidence")?;
        let owner = test_page("docs/page.md", "");
        let row = test_coverage_row("templates/missing/template.toml");

        let error = validate_exposure_evidence(workspace.path(), &owner, &row, &BTreeMap::new())
            .unwrap_err();

        assert_eq!(
            error.to_string(),
            "docs/coverage-matrix.md:17: generated-only capability must cite an existing contract, template, generator, or profile/catalog artifact"
        );
        Ok(())
    }

    #[test]
    fn duplicate_capability_owner_is_rejected() {
        let mut owners = BTreeMap::new();
        record_capability_owner(&mut owners, "capability", "docs/one.md", 10).unwrap();
        let error =
            record_capability_owner(&mut owners, "capability", "docs/two.md", 20).unwrap_err();
        assert!(error.to_string().contains("duplicate owners"));
    }

    #[test]
    fn future_skewed_source_mtime_does_not_make_page_stale() -> Result<()> {
        let workspace = CleanDirectory::new("docs-future-source-mtime")?;
        let source = workspace.path().join("src/lib.rs");
        fs::create_dir_all(source.parent().unwrap())?;
        fs::write(&source, "")?;
        let now = std::time::SystemTime::now();
        let future_mtime = now + std::time::Duration::from_secs(366 * 24 * 60 * 60);
        fs::File::options()
            .write(true)
            .open(&source)?
            .set_times(fs::FileTimes::new().set_modified(future_mtime))?;
        ensure!(
            fs::metadata(&source)?.modified()? > now,
            "test source mtime was not future-skewed"
        );
        let mut page = test_page("docs/page.md", "");
        page.frontmatter.source = vec!["src/lib.rs".to_owned()];

        validate_frontmatter(workspace.path(), &[page], &Catalogs::default())?;
        Ok(())
    }

    #[test]
    fn newer_documentation_review_metadata_makes_referring_page_stale() -> Result<()> {
        let workspace = CleanDirectory::new("docs-newer-review-metadata")?;
        let referenced_path = workspace.path().join("docs/newer.md");
        fs::create_dir_all(referenced_path.parent().unwrap())?;
        fs::write(&referenced_path, "")?;
        let mut referring_page = test_page("docs/referring.md", "");
        referring_page.frontmatter.last_verified = "2026-08-29".to_owned();
        referring_page.frontmatter.evidence = vec!["docs/newer.md".to_owned()];
        let referenced_page = test_page("docs/newer.md", "");

        let error = validate_frontmatter(
            workspace.path(),
            &[referring_page, referenced_page],
            &Catalogs::default(),
        )
        .unwrap_err();

        assert!(error.to_string().contains(
            "documentation reference `docs/newer.md` was last verified 2026-08-30 after this page's \
             last_verified 2026-08-29"
        ));
        Ok(())
    }

    fn cargo_command_workspace(name: &str) -> Result<CleanDirectory> {
        let workspace = CleanDirectory::new(name)?;
        fs::write(
            workspace.path().join("Cargo.toml"),
            "[workspace]\nmembers = [\"runner\"]\nresolver = \"3\"\n",
        )?;
        let package = workspace.path().join("runner");
        fs::create_dir_all(&package)?;
        fs::write(
            package.join("Cargo.toml"),
            r#"[package]
name = "runner"
version = "0.1.0"
edition = "2024"
autobins = false

[[bin]]
name = "runner-api"
path = "src/api.rs"

[[bin]]
name = "runner-admin"
path = "src/admin.rs"
"#,
        )?;
        Ok(workspace)
    }

    fn package_command_workspace(name: &str) -> Result<CleanDirectory> {
        let workspace = CleanDirectory::new(name)?;
        fs::write(
            workspace.path().join("package.json"),
            r#"{"scripts": {"root:test": "true"}}"#,
        )?;
        let package = workspace.path().join("web");
        fs::create_dir_all(&package)?;
        fs::write(
            package.join("package.json"),
            r#"{"scripts": {"test:e2e:base-path": "true"}}"#,
        )?;
        Ok(workspace)
    }

    fn test_page(relative: &str, body: &str) -> Page {
        Page {
            relative: relative.to_owned(),
            frontmatter: test_frontmatter(),
            body: body.to_owned(),
            body_start_line: 2,
            anchors: BTreeSet::new(),
            links: Vec::new(),
        }
    }

    fn test_coverage_row(primary_evidence: &str) -> CoverageRow {
        CoverageRow {
            capabilities: vec!["capability".to_owned()],
            owner_page: "docs/page.md".to_owned(),
            status: "stable".to_owned(),
            implementation: "implemented".to_owned(),
            profiles: Vec::new(),
            exposure: "generated-only".to_owned(),
            primary_evidence: primary_evidence.to_owned(),
            evidence_owner: "Maintainer".to_owned(),
            writing_owner: "Writer".to_owned(),
            reviewer: "Reviewer".to_owned(),
            verification: "Verify artifact".to_owned(),
            gaps: String::new(),
            modules: Vec::new(),
            profile_evidence: String::new(),
            exposure_evidence: String::new(),
            line: 17,
        }
    }

    fn test_frontmatter() -> Frontmatter {
        Frontmatter {
            title: "Page".to_owned(),
            description: "Description".to_owned(),
            status: "stable".to_owned(),
            implementation: "implemented".to_owned(),
            profile_availability: Vec::new(),
            public_exposure: "not-applicable".to_owned(),
            audience: vec!["maintainer".to_owned()],
            topics: vec!["test".to_owned()],
            capabilities: Vec::new(),
            source: Vec::new(),
            evidence: Vec::new(),
            last_verified: "2026-08-30".to_owned(),
            _additional: BTreeMap::new(),
        }
    }
}

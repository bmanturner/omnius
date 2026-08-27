#!/usr/bin/env python3
"""Validate the Web Application feature-suite extension in a merged specs tree."""

from __future__ import annotations

import argparse
import collections
import csv
import hashlib
import json
import re
import sys
import tomllib
from pathlib import Path

import yaml
from jsonschema import Draft202012Validator

EXT = Path("machine/extensions/web-application-suite")
MARKERS = ("TO" + "DO", "T" + "BD", "FIX" + "ME", "?" * 3, "unimplemented!" + "()", "todo!" + "()")
SPEC_ID_PATTERN = re.compile(r"^(?:OMNIUS-[A-Z0-9]+(?:-[A-Z0-9]+)*|ADR-[0-9]{4})$")


def load_frontmatter(path: Path) -> dict:
    text = path.read_text(encoding="utf-8")
    if not text.startswith("---\n"):
        raise ValueError("missing YAML frontmatter")
    end = text.find("\n---\n", 4)
    if end < 0:
        raise ValueError("unterminated YAML frontmatter")
    value = yaml.safe_load(text[4:end])
    if not isinstance(value, dict):
        raise ValueError("frontmatter is not an object")
    return value


def load_yaml(path: Path) -> dict:
    value = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"{path} does not contain an object")
    return value


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def validate(root: Path) -> list[str]:
    errors: list[str] = []

    def err(message: str) -> None:
        errors.append(message)

    required = [
        "MANIFEST.json",
        "machine/module-catalog.yaml",
        "machine/profiles.yaml",
        "machine/acceptance-criteria.yaml",
        "machine/tasks.yaml",
        "machine/module-manifest.schema.json",
        "machine/profile.schema.json",
        "WEB_FEATURE_SUITE_README.md",
        "WEB_FEATURE_SUITE_MANIFEST.json",
        str(EXT / "spec-extension-manifest.json"),
        str(EXT / "module-catalog.yaml"),
        str(EXT / "profiles.yaml"),
        str(EXT / "acceptance-criteria.yaml"),
        str(EXT / "tasks.yaml"),
        str(EXT / "frontend-capabilities.yaml"),
        str(EXT / "merge-plan.yaml"),
    ]
    for rel in required:
        if not (root / rel).is_file():
            err(f"missing required file {rel}")

    if errors:
        return errors

    base_manifest = json.loads((root / "MANIFEST.json").read_text(encoding="utf-8"))
    base_version = base_manifest.get("bundle", {}).get("version")
    ext_manifest_doc = json.loads((root / EXT / "spec-extension-manifest.json").read_text(encoding="utf-8"))
    expected_base = ext_manifest_doc.get("extension", {}).get("base_bundle_version")
    if base_version != expected_base:
        err(f"extension requires base bundle {expected_base}, found {base_version}")

    # Parse structured files.
    for path in root.rglob("*"):
        if not path.is_file():
            continue
        try:
            if path.suffix in {".yaml", ".yml"}:
                yaml.safe_load(path.read_text(encoding="utf-8"))
            elif path.suffix == ".json":
                json.loads(path.read_text(encoding="utf-8"))
            elif path.suffix == ".toml":
                tomllib.loads(path.read_text(encoding="utf-8"))
        except Exception as exc:
            err(f"{path.relative_to(root)} parse failure: {exc}")

    # Markdown metadata and unique IDs.
    specs: dict[str, str] = {}
    for path in root.rglob("*.md"):
        try:
            meta = load_frontmatter(path)
        except Exception as exc:
            err(f"{path.relative_to(root)}: {exc}")
            continue
        for key in ("spec_id", "title", "version", "status", "last_verified"):
            if key not in meta:
                err(f"{path.relative_to(root)} missing frontmatter field {key}")
        spec_id = meta.get("spec_id")
        if not isinstance(spec_id, str):
            err(f"{path.relative_to(root)} has non-string spec_id")
        elif not SPEC_ID_PATTERN.fullmatch(spec_id):
            err(f"{path.relative_to(root)} has invalid spec_id {spec_id}")
        elif spec_id in specs:
            err(f"duplicate spec_id {spec_id}: {specs[spec_id]} and {path.relative_to(root)}")
        else:
            specs[spec_id] = path.relative_to(root).as_posix()

    # Collision and manifest hash checks.
    base_paths = {item["path"] for item in base_manifest.get("files", [])}
    extension_manifest = json.loads((root / "WEB_FEATURE_SUITE_MANIFEST.json").read_text(encoding="utf-8"))
    extension_paths = {item["path"] for item in extension_manifest.get("files", [])}
    collisions = sorted(base_paths & extension_paths)
    if collisions:
        err(f"extension collides with base paths: {collisions}")
    for item in extension_manifest.get("files", []):
        path = root / item["path"]
        if not path.is_file():
            err(f"manifest path is missing: {item['path']}")
            continue
        actual = sha256(path)
        if actual != item["sha256"]:
            err(f"manifest hash mismatch for {item['path']}")
        if path.stat().st_size != item["bytes"]:
            err(f"manifest size mismatch for {item['path']}")

    # Merge base and extension catalogs in memory.
    base_modules = load_yaml(root / "machine/module-catalog.yaml")["modules"]
    ext_modules = load_yaml(root / EXT / "module-catalog.yaml")["modules"]
    base_profiles = load_yaml(root / "machine/profiles.yaml")["profiles"]
    ext_profiles = load_yaml(root / EXT / "profiles.yaml")["profiles"]
    base_criteria = load_yaml(root / "machine/acceptance-criteria.yaml")["criteria"]
    ext_criteria = load_yaml(root / EXT / "acceptance-criteria.yaml")["criteria"]
    base_tasks = load_yaml(root / "machine/tasks.yaml")["tasks"]
    ext_tasks = load_yaml(root / EXT / "tasks.yaml")["tasks"]

    modules = [*base_modules, *ext_modules]
    profiles = [*base_profiles, *ext_profiles]
    criteria = [*base_criteria, *ext_criteria]
    tasks = [*base_tasks, *ext_tasks]

    def unique_map(items: list[dict], key: str, label: str) -> dict:
        result: dict = {}
        for item in items:
            value = item.get(key)
            if value in result:
                err(f"duplicate {label} {value}")
            else:
                result[value] = item
        return result

    module_by_id = unique_map(modules, "id", "module ID")
    profile_by_id = unique_map(profiles, "id", "profile ID")
    acceptance_by_id = unique_map(criteria, "id", "acceptance ID")
    task_by_id = unique_map(tasks, "id", "task ID")

    # Base schemas validate extension objects too.
    module_schema = json.loads((root / "machine/module-manifest.schema.json").read_text(encoding="utf-8"))
    profile_schema = json.loads((root / "machine/profile.schema.json").read_text(encoding="utf-8"))
    module_validator = Draft202012Validator(module_schema)
    profile_validator = Draft202012Validator(profile_schema)
    for module in modules:
        for issue in module_validator.iter_errors(module):
            err(f"module {module.get('id')}: {issue.message}")
    for profile in profiles:
        for issue in profile_validator.iter_errors(profile):
            err(f"profile {profile.get('id')}: {issue.message}")

    # Module references.
    for module in modules:
        if module.get("spec") not in specs:
            err(f"module {module.get('id')} references unknown spec {module.get('spec')}")
        for requirement in module.get("requires", []):
            if requirement not in module_by_id:
                err(f"module {module.get('id')} requires unknown module {requirement}")
        for conflict in module.get("conflicts_with", []):
            if conflict not in module_by_id:
                err(f"module {module.get('id')} conflicts with unknown module {conflict}")
        for criterion in module.get("acceptance", []):
            if criterion not in acceptance_by_id:
                err(f"module {module.get('id')} references unknown acceptance {criterion}")

    # Profile resolution.
    profile_cache: dict[str, list[str]] = {}

    def resolve_profile(profile_id: str, stack: tuple[str, ...] = ()) -> list[str]:
        if profile_id in profile_cache:
            return profile_cache[profile_id]
        if profile_id in stack:
            err(f"profile extension cycle: {' -> '.join((*stack, profile_id))}")
            return []
        profile = profile_by_id.get(profile_id)
        if profile is None:
            err(f"unknown profile {profile_id}")
            return []
        resolved: list[str] = []
        parent = profile.get("extends")
        if parent:
            if parent not in profile_by_id:
                err(f"profile {profile_id} extends unknown profile {parent}")
            else:
                resolved.extend(resolve_profile(parent, (*stack, profile_id)))
        resolved.extend(profile.get("modules", []))
        deduped = list(dict.fromkeys(resolved))
        profile_cache[profile_id] = deduped
        return deduped

    for profile_id in profile_by_id:
        resolved = resolve_profile(profile_id)
        selected = set(resolved)
        slots: dict[str, list[str]] = collections.defaultdict(list)
        for module_id in resolved:
            module = module_by_id.get(module_id)
            if module is None:
                err(f"profile {profile_id} references unknown module {module_id}")
                continue
            for requirement in module.get("requires", []):
                if requirement not in selected:
                    err(f"profile {profile_id}: {module_id} requires {requirement}")
            for conflict in module.get("conflicts_with", []):
                if conflict in selected:
                    err(f"profile {profile_id}: {module_id} conflicts with {conflict}")
            slot = module.get("provider_slot")
            if slot:
                slots[slot].append(module_id)
        for slot, providers in slots.items():
            if len(providers) > 1:
                err(f"profile {profile_id}: provider slot {slot} has {providers}")

    # Acceptance and task references.
    for criterion in ext_criteria:
        if criterion.get("spec") not in specs:
            err(f"acceptance {criterion.get('id')} references unknown spec {criterion.get('spec')}")

    graph = {task["id"]: task.get("depends_on", []) for task in tasks}
    for task in tasks:
        for dependency in task.get("depends_on", []):
            if dependency not in task_by_id:
                err(f"task {task.get('id')} references unknown dependency {dependency}")
        for criterion in task.get("acceptance", []):
            if criterion not in acceptance_by_id:
                err(f"task {task.get('id')} references unknown acceptance {criterion}")

    temporary: set[str] = set()
    permanent: set[str] = set()

    def visit(task_id: str) -> None:
        if task_id in permanent:
            return
        if task_id in temporary:
            err(f"task dependency cycle at {task_id}")
            return
        temporary.add(task_id)
        for dependency in graph.get(task_id, []):
            visit(dependency)
        temporary.remove(task_id)
        permanent.add(task_id)

    for task_id in graph:
        visit(task_id)

    # Recommendation traceability across base and extension.
    recommendations: list[dict] = []
    for rel in (
        Path("machine/recommendation-traceability.csv"),
        EXT / "recommendation-traceability.csv",
    ):
        with (root / rel).open(newline="", encoding="utf-8") as stream:
            recommendations.extend(csv.DictReader(stream))
    rec_by_id = unique_map(recommendations, "recommendation_id", "recommendation ID")
    for row in recommendations:
        for spec in filter(None, (item.strip() for item in re.split(r"[;,]", row["specification"]))):
            if spec not in specs:
                err(f"recommendation {row['recommendation_id']} references unknown spec {spec}")
        for criterion in filter(None, (item.strip() for item in re.split(r"[;,]", row["acceptance_id"]))):
            if criterion not in acceptance_by_id:
                err(f"recommendation {row['recommendation_id']} references unknown acceptance {criterion}")

    expected_ext_rec = len(ext_criteria)
    actual_ext_rec = sum(1 for key in rec_by_id if str(key).startswith("REC-WEB-"))
    if actual_ext_rec != expected_ext_rec:
        err(f"expected {expected_ext_rec} web recommendations, found {actual_ext_rec}")

    # Frontend exposure coverage.
    capability_doc = load_yaml(root / EXT / "frontend-capabilities.yaml")
    capability_records = capability_doc.get("capabilities", [])
    capability_schema = json.loads((root / EXT / "schemas/frontend-capability.schema.json").read_text(encoding="utf-8"))
    capability_validator = Draft202012Validator(capability_schema)
    cap_by_module = unique_map(capability_records, "module_id", "frontend capability module")
    for record in capability_records:
        for issue in capability_validator.iter_errors(record):
            err(f"frontend capability {record.get('module_id')}: {issue.message}")
        if record.get("module_id") not in module_by_id:
            err(f"frontend capability references unknown module {record.get('module_id')}")
        if record.get("exposure") == "none":
            contracts = record.get("contracts", {})
            provides = record.get("provides", {})
            if any(contracts.get(key) for key in ("openapi_tags", "asyncapi_events", "runtime_capabilities")):
                err(f"headless module {record.get('module_id')} declares public contracts")
            if any(provides.get(key) for key in ("core_exports", "react_exports", "route_requirements", "query_effects", "testing")):
                err(f"headless module {record.get('module_id')} declares frontend exports")
    missing_exposure = sorted(set(module_by_id) - set(cap_by_module))
    extra_exposure = sorted(set(cap_by_module) - set(module_by_id))
    if missing_exposure:
        err(f"modules missing frontend exposure declarations: {missing_exposure}")
    if extra_exposure:
        err(f"frontend exposure records for unknown modules: {extra_exposure}")

    # Extension schemas/examples.
    schema_examples = (
        ("capabilities.schema.json", "capabilities.example.json"),
        ("permissions.schema.json", "permissions.example.json"),
        ("contract-manifest.schema.json", "contract-manifest.example.json"),
        ("query-effects.schema.json", "query-effects.example.yaml"),
        ("frontend-capability.schema.json", "frontend-capability.example.yaml"),
    )
    for schema_name, example_name in schema_examples:
        schema = json.loads((root / EXT / "schemas" / schema_name).read_text(encoding="utf-8"))
        example_path = root / "examples/web-application-suite" / example_name
        if example_path.suffix == ".json":
            instance = json.loads(example_path.read_text(encoding="utf-8"))
        else:
            instance = yaml.safe_load(example_path.read_text(encoding="utf-8"))
        validator = Draft202012Validator(schema, format_checker=Draft202012Validator.FORMAT_CHECKER)
        for issue in validator.iter_errors(instance):
            err(f"{example_path.relative_to(root)}: {issue.message}")

    # Base event schema also validates the realtime example.
    event_schema = json.loads((root / "machine/event-envelope.schema.json").read_text(encoding="utf-8"))
    event_instance = json.loads((root / "examples/web-application-suite/realtime-event.example.json").read_text(encoding="utf-8"))
    event_validator = Draft202012Validator(event_schema, format_checker=Draft202012Validator.FORMAT_CHECKER)
    for issue in event_validator.iter_errors(event_instance):
        err(f"examples/web-application-suite/realtime-event.example.json: {issue.message}")

    # Research source references.
    sources_path = root / "research/web-application-suite/sources.md"
    source_ids = set(re.findall(r"`(SRC-WEB-[A-Z0-9-]+)`", sources_path.read_text(encoding="utf-8")))
    for path in (root / "research/web-application-suite").glob("*.md"):
        if path == sources_path:
            continue
        for source_id in set(re.findall(r"SRC-WEB-[A-Z0-9-]+", path.read_text(encoding="utf-8"))):
            if source_id not in source_ids:
                err(f"{path.relative_to(root)} references unknown source {source_id}")

    # Prohibited unresolved markers in human and structured artifacts.
    scan_suffixes = {".md", ".yaml", ".yml", ".toml", ".json", ".csv", ".ts"}
    for path in root.rglob("*"):
        if not path.is_file() or path.suffix.lower() not in scan_suffixes:
            continue
        text = path.read_text(encoding="utf-8", errors="ignore")
        for marker in MARKERS:
            if marker in text:
                err(f"{path.relative_to(root)} contains prohibited marker {marker}")

    return errors


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("root", nargs="?", type=Path, default=Path(__file__).resolve().parents[1])
    args = parser.parse_args()
    root = args.root.resolve()
    errors = validate(root)
    if errors:
        print(f"FAILED: {len(errors)} issue(s)", file=sys.stderr)
        for issue in errors:
            print(f"- {issue}", file=sys.stderr)
        return 1

    ext = load_yaml(root / EXT / "spec-extension-manifest.json")
    counts = ext["counts"]
    print(
        "OK: web feature suite "
        f"{ext['extension']['version']} — "
        f"{counts['numbered_specs']} specs, {counts['adrs']} ADRs, "
        f"{counts['modules']} modules, {counts['profiles']} profiles, "
        f"{counts['acceptance_criteria']} acceptance criteria, "
        f"{counts['tasks']} tasks, {counts['recommendations']} recommendations"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

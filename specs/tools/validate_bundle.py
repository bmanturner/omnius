#!/usr/bin/env python3
"""Validate the Omnius specification bundle."""

from __future__ import annotations

import argparse
import collections
import csv
import json
import re
import sys
import tomllib
from pathlib import Path

import yaml
from jsonschema import Draft202012Validator


MARKERS = ("TODO", "TBD", "FIXME", "???", "unimplemented!()", "todo!()")
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


def validate_bundle(root: Path) -> list[str]:
    errors: list[str] = []

    def err(message: str) -> None:
        errors.append(message)

    # Parse all structured files.
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
        except Exception as exc:  # validation tool should report all files
            err(f"{path.relative_to(root)} parse failure: {exc}")

    # Markdown metadata.
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

    # Load catalogs.
    modules_doc = yaml.safe_load((root / "machine/module-catalog.yaml").read_text(encoding="utf-8"))
    profiles_doc = yaml.safe_load((root / "machine/profiles.yaml").read_text(encoding="utf-8"))
    acceptance_doc = yaml.safe_load((root / "machine/acceptance-criteria.yaml").read_text(encoding="utf-8"))
    tasks_doc = yaml.safe_load((root / "machine/tasks.yaml").read_text(encoding="utf-8"))

    modules = modules_doc["modules"]
    profiles = profiles_doc["profiles"]
    criteria = acceptance_doc["criteria"]
    tasks = tasks_doc["tasks"]

    module_by_id = {item["id"]: item for item in modules}
    profile_by_id = {item["id"]: item for item in profiles}
    acceptance_ids = {item["id"] for item in criteria}
    task_ids = {item["id"] for item in tasks}

    if len(module_by_id) != len(modules):
        err("duplicate module IDs")
    if len(profile_by_id) != len(profiles):
        err("duplicate profile IDs")
    if len(acceptance_ids) != len(criteria):
        err("duplicate acceptance IDs")
    if len(task_ids) != len(tasks):
        err("duplicate task IDs")

    # JSON Schema.
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
        if module["spec"] not in specs:
            err(f"module {module['id']} references unknown spec {module['spec']}")
        for criterion in module["acceptance"]:
            if criterion not in acceptance_ids:
                err(f"module {module['id']} references unknown acceptance {criterion}")

    # Profile inheritance, requirements, conflicts, and provider slots.
    def resolve_profile(profile_id: str, stack: tuple[str, ...] = ()) -> list[str]:
        if profile_id in stack:
            err(f"profile extension cycle: {' -> '.join((*stack, profile_id))}")
            return []
        profile = profile_by_id[profile_id]
        resolved: list[str] = []
        parent = profile.get("extends")
        if parent:
            if parent not in profile_by_id:
                err(f"profile {profile_id} extends unknown profile {parent}")
            else:
                resolved.extend(resolve_profile(parent, (*stack, profile_id)))
        resolved.extend(profile["modules"])
        return list(dict.fromkeys(resolved))

    for profile_id in profile_by_id:
        resolved = resolve_profile(profile_id)
        selected = set(resolved)
        provider_slots: dict[str, list[str]] = collections.defaultdict(list)
        for module_id in resolved:
            module = module_by_id.get(module_id)
            if module is None:
                err(f"profile {profile_id} references unknown module {module_id}")
                continue
            for requirement in module["requires"]:
                if requirement not in selected:
                    err(f"profile {profile_id}: {module_id} requires {requirement}")
            for conflict in module["conflicts_with"]:
                if conflict in selected:
                    err(f"profile {profile_id}: {module_id} conflicts with {conflict}")
            slot = module.get("provider_slot")
            if slot:
                provider_slots[slot].append(module_id)
        for slot, providers in provider_slots.items():
            if len(providers) > 1:
                err(f"profile {profile_id}: provider slot {slot} has {providers}")

    # Task graph and references.
    graph = {task["id"]: task["depends_on"] for task in tasks}
    for task in tasks:
        for dependency in task["depends_on"]:
            if dependency not in task_ids:
                err(f"task {task['id']} references unknown dependency {dependency}")
        for criterion in task["acceptance"]:
            if criterion not in acceptance_ids:
                err(f"task {task['id']} references unknown acceptance {criterion}")

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

    # Recommendation traceability.
    with (root / "machine/recommendation-traceability.csv").open(
        newline="", encoding="utf-8"
    ) as stream:
        recommendations = list(csv.DictReader(stream))
    recommendation_ids = [row["recommendation_id"] for row in recommendations]
    if len(recommendation_ids) != len(set(recommendation_ids)):
        err("duplicate recommendation IDs")
    for row in recommendations:
        for spec in filter(None, (item.strip() for item in re.split(r"[;,]", row["specification"]))):
            if spec not in specs:
                err(f"recommendation {row['recommendation_id']} references unknown spec {spec}")
        for criterion in filter(None, (item.strip() for item in re.split(r"[;,]", row["acceptance_id"]))):
            if criterion not in acceptance_ids:
                err(
                    f"recommendation {row['recommendation_id']} references unknown acceptance {criterion}"
                )

    # Source IDs.
    sources_text = (root / "research/sources.md").read_text(encoding="utf-8")
    source_ids = set(re.findall(r"`(SRC-[A-Z0-9-]+)`", sources_text))
    for path in (root / "21-crate-selection-matrix.md", root / "research/compatibility-findings.md"):
        for source_id in set(re.findall(r"SRC-[A-Z0-9-]+", path.read_text(encoding="utf-8"))):
            if source_id not in source_ids:
                err(f"{path.relative_to(root)} references unknown source {source_id}")

    # Contract examples.
    for schema_name, example_name in (
        ("problem-details.schema.json", "problem-details.json"),
        ("event-envelope.schema.json", "event-envelope.json"),
        ("job-envelope.schema.json", "job-envelope.json"),
    ):
        schema = json.loads((root / "machine" / schema_name).read_text(encoding="utf-8"))
        instance = json.loads((root / "examples" / example_name).read_text(encoding="utf-8"))
        validator = Draft202012Validator(schema, format_checker=Draft202012Validator.FORMAT_CHECKER)
        for issue in validator.iter_errors(instance):
            err(f"examples/{example_name}: {issue.message}")

    # Unresolved placeholders.
    for path in root.rglob("*"):
        if not path.is_file() or path.suffix.lower() not in {".md", ".yaml", ".yml", ".toml", ".json", ".csv"}:
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
    errors = validate_bundle(root)
    if errors:
        print(f"FAILED: {len(errors)} issue(s)", file=sys.stderr)
        for issue in errors:
            print(f"- {issue}", file=sys.stderr)
        return 1

    modules = yaml.safe_load((root / "machine/module-catalog.yaml").read_text())["modules"]
    profiles = yaml.safe_load((root / "machine/profiles.yaml").read_text())["profiles"]
    criteria = yaml.safe_load((root / "machine/acceptance-criteria.yaml").read_text())["criteria"]
    tasks = yaml.safe_load((root / "machine/tasks.yaml").read_text())["tasks"]
    with (root / "machine/recommendation-traceability.csv").open(newline="", encoding="utf-8") as stream:
        recommendations = list(csv.DictReader(stream))
    print(
        "OK: "
        f"{len(modules)} modules, {len(profiles)} profiles, "
        f"{len(criteria)} acceptance criteria, {len(tasks)} tasks, "
        f"{len(recommendations)} traced recommendations"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

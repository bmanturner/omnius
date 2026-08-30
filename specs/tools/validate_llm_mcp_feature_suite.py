#!/usr/bin/env python3
"""Validate the append-only LLM/MCP suite in a merged Omnius specs tree."""
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
from urllib.parse import urlsplit

import yaml
from jsonschema import Draft202012Validator
from referencing import Registry, Resource

WEB = Path("machine/extensions/web-application-suite")
AI = Path("machine/extensions/llm-mcp-suite")
MARKERS = ("TO" + "DO", "T" + "BD", "FIX" + "ME", "?" * 3, "unimplemented!" + "()", "todo!" + "()")
SPEC_ID_PATTERN = re.compile(r"^(?:OMNIUS-[A-Z0-9]+(?:-[A-Z0-9]+)*|ADR-[0-9]{4})$")
FULL_GIT_REVISION = re.compile(r"^(?:[0-9a-f]{40}|[0-9a-f]{64})$")
SHA256_CONTENT_REVISION = re.compile(r"^sha256:[0-9a-f]{64}$")
GITHUB_HOSTS = {"github.com", "raw.githubusercontent.com"}


def immutable_source_error(source: object) -> str | None:
    if not isinstance(source, dict) or set(source) != {"authority", "uri", "revision"}:
        return "source must contain exactly authority, uri, and revision"
    authority = source.get("authority")
    uri = source.get("uri")
    revision = source.get("revision")
    if (
        not isinstance(authority, str)
        or not authority
        or len(authority) > 128
        or any(ord(character) < 32 or ord(character) == 127 for character in authority)
    ):
        return "source authority is invalid"
    if not isinstance(uri, str) or not isinstance(revision, str):
        return "source URI and revision must be strings"
    try:
        parsed = urlsplit(uri)
        port = parsed.port
    except ValueError:
        return "source URI is invalid"
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or port is not None
        or parsed.query
        or parsed.fragment
        or any(character.isspace() for character in uri)
        or "%" in parsed.path
    ):
        return "source URI must be credential-free canonical HTTPS without port, query, fragment, or escapes"

    host = parsed.hostname.lower()
    if host not in GITHUB_HOSTS:
        if SHA256_CONTENT_REVISION.fullmatch(revision) is None:
            return "mutable HTTPS sources require an explicit sha256 content digest"
        return None

    if FULL_GIT_REVISION.fullmatch(revision) is None:
        return "GitHub sources require a full lowercase 40- or 64-hex revision"
    segments = [segment for segment in parsed.path.split("/") if segment]
    if host == "github.com":
        if len(segments) < 4 or segments[2] not in {"commit", "blob", "raw"}:
            return "GitHub source must be a commit, blob, or raw permalink"
        if segments[3] != revision:
            return "GitHub permalink revision does not match source revision"
        if segments[2] == "commit" and len(segments) != 4:
            return "GitHub commit permalink must identify exactly one commit"
        if segments[2] in {"blob", "raw"} and len(segments) < 5:
            return "GitHub blob or raw permalink must identify a file"
        return None
    if len(segments) < 4:
        return "raw GitHub permalink must identify a file at an immutable revision"
    if segments[2] != revision:
        return "raw GitHub permalink revision does not match source revision"
    return None


def load_yaml(path: Path) -> dict:
    value = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"{path} is not an object")
    return value


def frontmatter(path: Path) -> dict:
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


def digest(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def validate(root: Path) -> list[str]:
    errors: list[str] = []
    add = errors.append

    required = [
        "MANIFEST.json", "WEB_FEATURE_SUITE_MANIFEST.json", "LLM_MCP_FEATURE_SUITE_MANIFEST.json",
        "machine/module-catalog.yaml", "machine/profiles.yaml", "machine/acceptance-criteria.yaml",
        "machine/tasks.yaml", "machine/module-manifest.schema.json", "machine/profile.schema.json",
        str(WEB / "module-catalog.yaml"), str(WEB / "profiles.yaml"),
        str(WEB / "acceptance-criteria.yaml"), str(WEB / "tasks.yaml"),
        str(WEB / "frontend-capabilities.yaml"),
        str(AI / "spec-extension-manifest.json"), str(AI / "module-catalog.yaml"),
        str(AI / "profiles.yaml"), str(AI / "acceptance-criteria.yaml"), str(AI / "tasks.yaml"),
        str(AI / "frontend-capabilities.yaml"), str(AI / "llm-capabilities.yaml"),
        str(AI / "provider-catalog.yaml"), str(AI / "mcp-exposure-catalog.yaml"),
        str(AI / "mcp-extension-registry.yaml"), str(AI / "protocol-compatibility.yaml"),
        str(AI / "merge-plan.yaml"), str(AI / "dependency-baseline.toml"),
        str(AI / "schemas/llm-request.schema.json"), str(AI / "schemas/model-response.schema.json"),
        "examples/llm-mcp-suite/llm-request.example.json",
        "examples/llm-mcp-suite/embedding-response.example.json",
        "examples/llm-mcp-suite/rerank-response.example.json",
        "examples/llm-mcp-suite/transcription-response.example.json",
        "examples/llm-mcp-suite/speech-response.example.json",
        "examples/llm-mcp-suite/media-generation-response.example.json",
        "examples/llm-mcp-suite/classification-response.example.json",
        "examples/llm-mcp-suite/mcp-task.example.json",
        "examples/llm-mcp-suite/mcp-task-get-completed.example.json",
        "examples/llm-mcp-suite/mcp-subscription.example.json",
        "LLM_MCP_FEATURE_SUITE_README.md", "LLM_MCP_FEATURE_SUITE_AGENT_HANDOFF.md",
        "LLM_MCP_FEATURE_SUITE_INTEGRATION.md", "LLM_MCP_FEATURE_SUITE_COMPLETE_SPEC.md",
    ]
    for rel in required:
        if not (root / rel).is_file():
            add(f"missing required file {rel}")
    if errors:
        return errors

    base_manifest = json.loads((root / "MANIFEST.json").read_text())
    web_manifest = json.loads((root / "WEB_FEATURE_SUITE_MANIFEST.json").read_text())
    suite_manifest = json.loads((root / "LLM_MCP_FEATURE_SUITE_MANIFEST.json").read_text())
    extension_manifest = json.loads((root / AI / "spec-extension-manifest.json").read_text())
    ext = extension_manifest["extension"]
    if ext["base_bundle_version"] != base_manifest["bundle"]["version"]:
        add("base bundle version does not satisfy AI extension")
    if ext["required_extension_versions"]["web-application-suite"] != web_manifest["suite"]["version"]:
        add("web suite version does not satisfy AI extension")

    # Parse all structured artifacts.
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
            add(f"{path.relative_to(root)} parse failure: {exc}")

    # Markdown metadata and globally unique IDs.
    spec_paths: dict[str, str] = {}
    for path in root.rglob("*.md"):
        try:
            meta = frontmatter(path)
        except Exception as exc:
            add(f"{path.relative_to(root)}: {exc}")
            continue
        for key in ("spec_id", "title", "version", "status", "last_verified"):
            if key not in meta:
                add(f"{path.relative_to(root)} missing frontmatter field {key}")
        sid = meta.get("spec_id")
        if not isinstance(sid, str):
            add(f"{path.relative_to(root)} has non-string spec_id")
        elif not SPEC_ID_PATTERN.fullmatch(sid):
            add(f"{path.relative_to(root)} has invalid spec_id {sid}")
        elif sid in spec_paths:
            add(f"duplicate spec_id {sid}: {spec_paths[sid]} and {path.relative_to(root)}")
        else:
            spec_paths[sid] = path.relative_to(root).as_posix()
    expected_docs = {f"OMNIUS-{n:03d}" for n in range(35, 50)} | {
        f"OMNIUS-ADR-{n:04d}" for n in range(15, 25)
    }
    if expected_docs - set(spec_paths):
        add(f"missing AI specification IDs: {sorted(expected_docs - set(spec_paths))}")

    # Archive collision and integrity checks.
    base_paths = {x["path"] for x in base_manifest.get("files", [])}
    web_paths = {x["path"] for x in web_manifest.get("files", [])}
    ai_paths = {x["path"] for x in suite_manifest.get("files", [])}
    if base_paths & ai_paths:
        add(f"AI paths collide with base: {sorted(base_paths & ai_paths)}")
    if web_paths & ai_paths:
        add(f"AI paths collide with web: {sorted(web_paths & ai_paths)}")
    for item in suite_manifest.get("files", []):
        path = root / item["path"]
        if not path.is_file():
            add(f"manifest path missing: {item['path']}")
        elif digest(path) != item["sha256"] or path.stat().st_size != item["bytes"]:
            add(f"manifest integrity mismatch: {item['path']}")

    # Merge catalogs in memory.
    base_modules = load_yaml(root / "machine/module-catalog.yaml")["modules"]
    web_modules = load_yaml(root / WEB / "module-catalog.yaml")["modules"]
    ai_modules = load_yaml(root / AI / "module-catalog.yaml")["modules"]
    base_profiles = load_yaml(root / "machine/profiles.yaml")["profiles"]
    web_profiles = load_yaml(root / WEB / "profiles.yaml")["profiles"]
    ai_profiles = load_yaml(root / AI / "profiles.yaml")["profiles"]
    base_criteria = load_yaml(root / "machine/acceptance-criteria.yaml")["criteria"]
    web_criteria = load_yaml(root / WEB / "acceptance-criteria.yaml")["criteria"]
    ai_criteria = load_yaml(root / AI / "acceptance-criteria.yaml")["criteria"]
    base_tasks = load_yaml(root / "machine/tasks.yaml")["tasks"]
    web_tasks = load_yaml(root / WEB / "tasks.yaml")["tasks"]
    ai_tasks = load_yaml(root / AI / "tasks.yaml")["tasks"]
    modules, profiles = base_modules + web_modules + ai_modules, base_profiles + web_profiles + ai_profiles
    criteria, tasks = base_criteria + web_criteria + ai_criteria, base_tasks + web_tasks + ai_tasks

    def index(items: list[dict], field: str, label: str) -> dict:
        result = {}
        for item in items:
            key = item.get(field)
            if key in result:
                add(f"duplicate {label} {key}")
            result[key] = item
        return result

    module_by_id = index(modules, "id", "module")
    profile_by_id = index(profiles, "id", "profile")
    criterion_by_id = index(criteria, "id", "acceptance")
    task_by_id = index(tasks, "id", "task")

    module_validator = Draft202012Validator(json.loads((root / "machine/module-manifest.schema.json").read_text()))
    profile_validator = Draft202012Validator(json.loads((root / "machine/profile.schema.json").read_text()))
    for module in modules:
        for issue in module_validator.iter_errors(module):
            add(f"module {module.get('id')}: {issue.message}")
        if module.get("spec") not in spec_paths:
            add(f"module {module.get('id')} references unknown spec {module.get('spec')}")
        for dep in module.get("requires", []):
            if dep not in module_by_id:
                add(f"module {module.get('id')} requires unknown module {dep}")
        for conflict in module.get("conflicts_with", []):
            if conflict not in module_by_id:
                add(f"module {module.get('id')} conflicts with unknown module {conflict}")
        for ac in module.get("acceptance", []):
            if ac not in criterion_by_id:
                add(f"module {module.get('id')} references unknown acceptance {ac}")
    for profile in profiles:
        for issue in profile_validator.iter_errors(profile):
            add(f"profile {profile.get('id')}: {issue.message}")

    resolved_cache: dict[str, list[str]] = {}
    def resolve_profile(pid: str, stack: tuple[str, ...] = ()) -> list[str]:
        if pid in resolved_cache:
            return resolved_cache[pid]
        if pid in stack:
            add(f"profile inheritance cycle: {' -> '.join((*stack, pid))}")
            return []
        profile = profile_by_id.get(pid)
        if profile is None:
            add(f"unknown profile {pid}")
            return []
        values: list[str] = []
        if profile.get("extends"):
            values.extend(resolve_profile(profile["extends"], (*stack, pid)))
        values.extend(profile.get("modules", []))
        resolved_cache[pid] = list(dict.fromkeys(values))
        return resolved_cache[pid]

    for pid in profile_by_id:
        selected = set(resolve_profile(pid))
        slots: dict[str, list[str]] = collections.defaultdict(list)
        for mid in resolve_profile(pid):
            module = module_by_id.get(mid)
            if module is None:
                add(f"profile {pid} references unknown module {mid}")
                continue
            for dep in module.get("requires", []):
                if dep not in selected:
                    add(f"profile {pid}: {mid} requires {dep}")
            for conflict in module.get("conflicts_with", []):
                if conflict in selected:
                    add(f"profile {pid}: {mid} conflicts with {conflict}")
            if module.get("provider_slot"):
                slots[module["provider_slot"]].append(mid)
        for slot, providers in slots.items():
            if len(providers) > 1:
                add(f"profile {pid}: provider slot {slot} has {providers}")
    ai_selected = set().union(*(set(resolve_profile(p["id"])) for p in ai_profiles))
    if {m["id"] for m in ai_modules} - ai_selected:
        add(f"AI modules absent from all AI profiles: {sorted({m['id'] for m in ai_modules} - ai_selected)}")

    # Task graph and one-to-one AI acceptance coverage.
    ai_task_ids = {t["id"] for t in ai_tasks}
    task_coverage: collections.Counter[str] = collections.Counter()
    graph = {t["id"]: t.get("depends_on", []) for t in tasks}
    for task in tasks:
        for dep in task.get("depends_on", []):
            if dep not in task_by_id:
                add(f"task {task['id']} references unknown dependency {dep}")
        for ac in task.get("acceptance", []):
            if ac not in criterion_by_id:
                add(f"task {task['id']} references unknown acceptance {ac}")
            if task["id"] in ai_task_ids and ac.startswith("AC-AI-"):
                task_coverage[ac] += 1
    for criterion in ai_criteria:
        if criterion.get("spec") not in spec_paths:
            add(f"acceptance {criterion['id']} references unknown spec {criterion.get('spec')}")
        if task_coverage[criterion["id"]] != 1:
            add(f"{criterion['id']} has {task_coverage[criterion['id']]} AI task mappings; expected 1")
    amended_task_ownership = {
        "T150": {"AC-AI-001"},
        "T151": {f"AC-AI-{value:03d}" for value in range(2, 9)},
        "T172": {"AC-AI-089", "AC-AI-090"},
        "T173": {f"AC-AI-{value:03d}" for value in range(91, 94)},
        "T174": {f"AC-AI-{value:03d}" for value in range(94, 97)},
        "T175": {f"AC-AI-{value:03d}" for value in range(97, 100)},
        "T176": {f"AC-AI-{value:03d}" for value in range(100, 105)},
        "T177": {"AC-AI-107", "AC-AI-108", "AC-AI-111"},
        "T178": {"AC-AI-105", "AC-AI-106", "AC-AI-109", "AC-AI-110", "AC-AI-112"},
        "T179": {f"AC-AI-{value:03d}" for value in range(113, 121)},
    }
    for task_id, expected in amended_task_ownership.items():
        actual = set(task_by_id[task_id].get("acceptance", []))
        if actual != expected:
            add(
                f"{task_id} acceptance ownership differs from ADR-0033: "
                f"expected {sorted(expected)}, found {sorted(actual)}"
            )
    visiting, done = set(), set()
    def visit(task_id: str) -> None:
        if task_id in done:
            return
        if task_id in visiting:
            add(f"task dependency cycle at {task_id}")
            return
        visiting.add(task_id)
        for dep in graph.get(task_id, []):
            visit(dep)
        visiting.remove(task_id)
        done.add(task_id)
    for tid in graph:
        visit(tid)

    # Recommendation coverage.
    rows: list[dict] = []
    for rel in (Path("machine/recommendation-traceability.csv"), WEB / "recommendation-traceability.csv", AI / "recommendation-traceability.csv"):
        with (root / rel).open(newline="", encoding="utf-8") as stream:
            rows.extend(csv.DictReader(stream))
    rec_by_id = index(rows, "recommendation_id", "recommendation")
    rec_coverage: collections.Counter[str] = collections.Counter()
    for row in rows:
        for sid in filter(None, (x.strip() for x in re.split(r"[;,]", row["specification"]))):
            if sid not in spec_paths:
                add(f"recommendation {row['recommendation_id']} references unknown spec {sid}")
        for ac in filter(None, (x.strip() for x in re.split(r"[;,]", row["acceptance_id"]))):
            if ac not in criterion_by_id:
                add(f"recommendation {row['recommendation_id']} references unknown acceptance {ac}")
            if row["recommendation_id"].startswith("REC-AI-") and ac.startswith("AC-AI-"):
                rec_coverage[ac] += 1
    if len([x for x in rec_by_id if str(x).startswith("REC-AI-")]) != len(ai_criteria):
        add("AI recommendation count does not match AI acceptance count")
    for criterion in ai_criteria:
        if rec_coverage[criterion["id"]] != 1:
            add(f"{criterion['id']} has {rec_coverage[criterion['id']]} AI recommendation mappings; expected 1")

    # Browser exposure coverage across base, web, and AI modules.
    frontend_records = load_yaml(root / WEB / "frontend-capabilities.yaml")["capabilities"] + load_yaml(root / AI / "frontend-capabilities.yaml")["capabilities"]
    frontend_by_module = index(frontend_records, "module_id", "frontend exposure")
    fv = Draft202012Validator(json.loads((root / AI / "schemas/frontend-capability.schema.json").read_text()))
    for record in frontend_records:
        for issue in fv.iter_errors(record):
            add(f"frontend capability {record.get('module_id')}: {issue.message}")
        if record.get("module_id") not in module_by_id:
            add(f"frontend exposure references unknown module {record.get('module_id')}")
        if record.get("exposure") == "none":
            if any(record.get("contracts", {}).get(k) for k in ("openapi_tags", "asyncapi_events", "runtime_capabilities")):
                add(f"headless module {record.get('module_id')} declares public contracts")
            if any(record.get("provides", {}).get(k) for k in ("core_exports", "react_exports", "route_requirements", "query_effects", "testing")):
                add(f"headless module {record.get('module_id')} declares frontend exports")
    if set(module_by_id) - set(frontend_by_module):
        add(f"modules missing frontend exposure: {sorted(set(module_by_id) - set(frontend_by_module))}")

    # Extension schemas, examples, and cross-references.
    schema_dir, examples = root / AI / "schemas", root / "examples/llm-mcp-suite"
    registry = Registry()
    for schema_path in schema_dir.glob("*.json"):
        schema_value = json.loads(schema_path.read_text())
        if isinstance(schema_value, dict) and isinstance(schema_value.get("$id"), str):
            registry = registry.with_resource(schema_value["$id"], Resource.from_contents(schema_value))
    def check(schema_name: str, instance, label: str, use_registry: bool = False) -> None:
        kwargs = {"format_checker": Draft202012Validator.FORMAT_CHECKER}
        if use_registry:
            kwargs["registry"] = registry
        validator = Draft202012Validator(json.loads((schema_dir / schema_name).read_text()), **kwargs)
        for issue in validator.iter_errors(instance):
            loc = "/".join(map(str, issue.absolute_path))
            add(f"{label}{' at ' + loc if loc else ''}: {issue.message}")
    check("agent-capability.schema.json", load_yaml(examples / "agent-capability.example.yaml"), "agent capability")
    check("llm-request.schema.json", json.loads((examples / "llm-request.example.json").read_text()), "LLM request", True)
    check("llm-response.schema.json", json.loads((examples / "llm-response.example.json").read_text()), "LLM response", True)
    check("model-response.schema.json", json.loads((examples / "llm-response.example.json").read_text()), "model completion response", True)
    for model_example in (
        "embedding-response.example.json", "rerank-response.example.json",
        "transcription-response.example.json", "speech-response.example.json",
        "media-generation-response.example.json", "classification-response.example.json",
    ):
        check("model-response.schema.json", json.loads((examples / model_example).read_text()), model_example, True)
    for n, line in enumerate((examples / "llm-stream.example.ndjson").read_text().splitlines(), 1):
        if line.strip():
            check("llm-stream-event.schema.json", json.loads(line), f"LLM stream line {n}")
    check("prompt-definition.schema.json", load_yaml(examples / "prompt-definition.example.yaml"), "prompt")
    check("model-route.schema.json", load_yaml(examples / "model-route.example.yaml"), "route")
    check("mcp-exposure.schema.json", load_yaml(examples / "mcp-exposure.example.yaml"), "MCP exposure")
    check("mcp-extension.schema.json", load_yaml(examples / "mcp-extension.example.yaml"), "MCP extension")
    check("frontend-capability.schema.json", load_yaml(examples / "frontend-capability.example.yaml"), "frontend capability")

    capability_ids = {x["id"] for x in load_yaml(root / AI / "llm-capabilities.yaml")["capabilities"]}
    provider_validator = Draft202012Validator(json.loads((schema_dir / "llm-provider.schema.json").read_text()))
    for provider in load_yaml(root / AI / "provider-catalog.yaml")["providers"]:
        for issue in provider_validator.iter_errors(provider):
            add(f"provider {provider.get('id')}: {issue.message}")
        if provider["adapter_module"] not in module_by_id:
            add(f"provider {provider['id']} references unknown module {provider['adapter_module']}")
        if set(provider.get("capabilities", [])) - capability_ids:
            add(f"provider {provider['id']} has unknown capabilities {sorted(set(provider.get('capabilities', [])) - capability_ids)}")
    ev = Draft202012Validator(json.loads((schema_dir / "mcp-exposure.schema.json").read_text()))
    for exposure in load_yaml(root / AI / "mcp-exposure-catalog.yaml")["exposures"]:
        for issue in ev.iter_errors(exposure):
            add(f"MCP exposure {exposure.get('name')}: {issue.message}")
    extension_schema = json.loads((schema_dir / "mcp-extension.schema.json").read_text())
    xv = Draft202012Validator(extension_schema, format_checker=Draft202012Validator.FORMAT_CHECKER)
    lifecycle_values = ["stable", "draft", "experimental", "deprecated", "removed"]
    if extension_schema.get("properties", {}).get("status", {}).get("enum") != lifecycle_values:
        add("MCP extension schema lifecycle values must be stable, draft, experimental, deprecated, removed")

    extension_items = load_yaml(root / AI / "mcp-extension-registry.yaml")["extensions"]
    indexed_extension_items: list[tuple[str, dict]] = []
    for extension_item in extension_items:
        if not isinstance(extension_item, dict):
            continue
        extension_id = extension_item.get("id")
        if isinstance(extension_id, str) and extension_id:
            indexed_extension_items.append((extension_id, extension_item))
    extension_ids = [extension_id for extension_id, _ in indexed_extension_items]
    duplicate_extension_ids = sorted(
        extension_id
        for extension_id, count in collections.Counter(extension_ids).items()
        if count > 1
    )
    if duplicate_extension_ids:
        add(f"duplicate MCP extension IDs: {duplicate_extension_ids}")

    expected_extensions = {
        "io.modelcontextprotocol/tasks": ("stable", "2026-07-28", "mcp-tasks", "per-request-capabilities"),
        "io.modelcontextprotocol/ui": ("stable", "2026-01-26", "mcp-apps", "per-request-capabilities"),
        "io.modelcontextprotocol/skills": ("experimental", "2026-08-22", "mcp-skills", "per-request-capabilities"),
        "io.modelcontextprotocol/oauth-client-credentials": (
            "stable", "2026-07-28", "mcp-auth-client-credentials", "per-request-capabilities",
        ),
        "io.modelcontextprotocol/enterprise-managed-authorization": (
            "stable", "2026-07-28", "mcp-auth-enterprise", "per-request-capabilities",
        ),
        "server-card-preview": ("experimental", "1", "mcp-server-card-preview", "not-wire-visible"),
        "progressive-discovery-preview": (
            "experimental", "1", "mcp-progressive-discovery-preview", "not-wire-visible",
        ),
        "roots": ("deprecated", "2026-07-28", None, "prohibited"),
        "sampling": ("deprecated", "2026-07-28", None, "prohibited"),
        "logging": ("deprecated", "2026-07-28", None, "prohibited"),
        "http-sse": ("deprecated", "2026-07-28", None, "prohibited"),
    }
    expected_sources = {
        "io.modelcontextprotocol/tasks": {
            "authority": "Model Context Protocol",
            "uri": "https://modelcontextprotocol.io/extensions/tasks/overview.md",
            "revision": "sha256:08ca547b93b20be582dc419075510430dbcc152bd623ccc3009f552c1c1d2190",
        },
        "io.modelcontextprotocol/ui": {
            "authority": "Model Context Protocol",
            "uri": "https://modelcontextprotocol.io/extensions/apps/overview.md",
            "revision": "sha256:6d3c751017967dec9f634bb58b1c3b8918e71f9e54dd5f39cbd81836f812f7fc",
        },
        "io.modelcontextprotocol/skills": {
            "authority": "Model Context Protocol",
            "uri": (
                "https://github.com/modelcontextprotocol/experimental-ext-skills/commit/"
                "7bf5c7d397fdaa40c979a7248b16448de2d076ef"
            ),
            "revision": "7bf5c7d397fdaa40c979a7248b16448de2d076ef",
        },
        "io.modelcontextprotocol/oauth-client-credentials": {
            "authority": "Model Context Protocol",
            "uri": "https://modelcontextprotocol.io/extensions/auth/oauth-client-credentials.md",
            "revision": "sha256:1b4e4a1069c800066f2b310bf29311b321772216110620805c00dde813a8a371",
        },
        "io.modelcontextprotocol/enterprise-managed-authorization": {
            "authority": "Model Context Protocol",
            "uri": "https://modelcontextprotocol.io/extensions/auth/enterprise-managed-authorization.md",
            "revision": "sha256:f3a91c6d40f884daba09f55d7443f8b1cdd3fd169f9de739365d0621596c2af6",
        },
        "server-card-preview": {
            "authority": "Model Context Protocol",
            "uri": "https://modelcontextprotocol.io/development/roadmap.md",
            "revision": "sha256:d4bc14ba66ff98e893653fe76f10b948012bd1c8975d62c9755c392d10c6ced1",
        },
        "progressive-discovery-preview": {
            "authority": "Model Context Protocol",
            "uri": "https://modelcontextprotocol.io/development/roadmap.md",
            "revision": "sha256:d4bc14ba66ff98e893653fe76f10b948012bd1c8975d62c9755c392d10c6ced1",
        },
        "roots": {
            "authority": "Model Context Protocol",
            "uri": "https://modelcontextprotocol.io/extensions/overview.md",
            "revision": "sha256:6826c39f36fe04d477ab5a0e25a3d694ab44c1e4907333ba0aa6b38c192962e6",
        },
        "sampling": {
            "authority": "Model Context Protocol",
            "uri": "https://modelcontextprotocol.io/extensions/overview.md",
            "revision": "sha256:6826c39f36fe04d477ab5a0e25a3d694ab44c1e4907333ba0aa6b38c192962e6",
        },
        "logging": {
            "authority": "Model Context Protocol",
            "uri": "https://modelcontextprotocol.io/extensions/overview.md",
            "revision": "sha256:6826c39f36fe04d477ab5a0e25a3d694ab44c1e4907333ba0aa6b38c192962e6",
        },
        "http-sse": {
            "authority": "Model Context Protocol",
            "uri": "https://modelcontextprotocol.io/extensions/overview.md",
            "revision": "sha256:6826c39f36fe04d477ab5a0e25a3d694ab44c1e4907333ba0aa6b38c192962e6",
        },
    }
    actual_extension_ids = set(extension_ids)
    expected_extension_ids = set(expected_extensions)
    if actual_extension_ids != expected_extension_ids:
        add(
            "MCP extension identities mismatch: "
            f"missing={sorted(expected_extension_ids - actual_extension_ids)}, "
            f"unexpected={sorted(actual_extension_ids - expected_extension_ids)}"
        )

    extension_registry = dict(indexed_extension_items)
    for extension_item in extension_items:
        extension_id = extension_item.get("id") if isinstance(extension_item, dict) else None
        for issue in xv.iter_errors(extension_item):
            add(f"MCP extension {extension_id}: {issue.message}")
        if not isinstance(extension_item, dict) or not isinstance(extension_id, str) or not extension_id:
            continue
        module = extension_item.get("module")
        negotiation = extension_item.get("negotiation")
        status = extension_item.get("status")
        default_enabled = extension_item.get("default_enabled")
        if module and module not in module_by_id:
            add(f"MCP extension {extension_id} references unknown module {module}")
        if status in {"stable", "draft", "experimental"} and (
            not isinstance(module, str) or not module or negotiation == "prohibited"
        ):
            add(f"MCP extension {extension_id} lifecycle requires a module and negotiation")
        if default_enabled is not False:
            add(f"MCP extension {extension_id} must be disabled by default")
        if status == "removed":
            if module is not None or negotiation != "prohibited":
                add(f"removed MCP extension {extension_id} must be unbacked and prohibited")
        elif negotiation == "prohibited" and module is not None:
            add(f"prohibited MCP extension {extension_id} must be unbacked")

        source = extension_item.get("source")
        source_error = immutable_source_error(source)
        if source_error is not None:
            add(f"MCP extension {extension_id} source is not immutable: {source_error}")
        expected_source = expected_sources.get(extension_id)
        if expected_source is not None and source != expected_source:
            add(f"MCP extension {extension_id} source provenance tuple mismatch")

    for extension_id, expected in expected_extensions.items():
        extension_item = extension_registry.get(extension_id)
        if extension_item is None:
            continue
        actual = (
            extension_item.get("status"),
            extension_item.get("revision"),
            extension_item.get("module"),
            extension_item.get("negotiation"),
        )
        if actual != expected:
            add(
                f"MCP extension {extension_id} contract mismatch: "
                f"expected {expected[0]} revision {expected[1]} module {expected[2]} negotiation {expected[3]}"
            )

    # Current MCP protocol shapes and anti-legacy guardrails.
    discover = json.loads((examples / "mcp-server-discover.example.json").read_text())["result"]
    if discover.get("resultType") != "complete" or discover.get("supportedVersions") != ["2026-07-28"]:
        add("server/discover example is not current MCP 2026-07-28")
    if "protocolVersions" in discover or not isinstance(discover.get("ttlMs"), int) or discover.get("cacheScope") not in {"public", "private"}:
        add("server/discover example lacks current cache/version fields")
    mrtr = json.loads((examples / "mcp-input-required.example.json").read_text())["result"]
    if mrtr.get("resultType") != "input_required" or not isinstance(mrtr.get("inputRequests"), dict):
        add("MRTR example must use input_required and an inputRequests map")
    for key, request in mrtr.get("inputRequests", {}).items():
        if not isinstance(request, dict) or "method" not in request or "params" not in request:
            add(f"MRTR input request {key} lacks method/params")
    task = json.loads((examples / "mcp-task.example.json").read_text())["result"]
    if task.get("resultType") != "task" or not task.get("taskId") or "task" in task:
        add("Tasks example must be a direct current CreateTaskResult")
    task_statuses = {"working", "input_required", "completed", "cancelled", "failed"}
    if task.get("status") not in task_statuses:
        add("CreateTaskResult has an invalid task status")
    for field in ("createdAt", "lastUpdatedAt"):
        if not isinstance(task.get(field), str) or not re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z", task[field]):
            add(f"CreateTaskResult lacks a current ISO-8601 {field}")
    if task.get("ttlMs") is not None and (not isinstance(task.get("ttlMs"), int) or task["ttlMs"] < 0):
        add("CreateTaskResult ttlMs must be a non-negative integer or null")
    if "pollIntervalMs" in task and (not isinstance(task["pollIntervalMs"], int) or task["pollIntervalMs"] <= 0):
        add("CreateTaskResult pollIntervalMs must be a positive integer")

    completed_task = json.loads((examples / "mcp-task-get-completed.example.json").read_text())["result"]
    if completed_task.get("resultType") != "complete" or completed_task.get("status") != "completed":
        add("tasks/get completed example must be a complete DetailedTask")
    if completed_task.get("taskId") != task.get("taskId") or not isinstance(completed_task.get("result"), dict):
        add("tasks/get completed example must retain task identity and inline the original result")
    if completed_task.get("result", {}).get("resultType") != "complete":
        add("tasks/get completed example must preserve the original completed method result")
    for field in ("createdAt", "lastUpdatedAt", "ttlMs"):
        if field not in completed_task:
            add(f"tasks/get completed example lacks required {field}")

    subscription = json.loads((examples / "mcp-subscription.example.json").read_text())
    listen = subscription.get("listenRequest", {})
    messages = subscription.get("streamMessages", [])
    subscription_id = listen.get("id")
    if listen.get("method") != "subscriptions/listen" or subscription_id is None or not messages:
        add("subscription example lacks a valid subscriptions/listen request and stream")
    elif messages[0].get("method") != "notifications/subscriptions/acknowledged":
        add("subscription acknowledgment must be the first stream message")
    for n, message in enumerate(messages, 1):
        if "params" in message:
            meta = message.get("params", {}).get("_meta", {})
        else:
            meta = message.get("result", {}).get("_meta", {})
        if meta.get("io.modelcontextprotocol/subscriptionId") != subscription_id:
            add(f"subscription stream message {n} is not correlated to the listen request ID")
    if messages and (messages[-1].get("id") != subscription_id or messages[-1].get("result", {}).get("resultType") != "complete"):
        add("subscription graceful closure must be a complete response to the listen request")

    enterprise_modules = set(profile_by_id.get("mcp-enterprise", {}).get("modules", []))
    if "mcp-skills" in enterprise_modules:
        add("mcp-enterprise must not enable experimental Skills by default")

    protocol = load_yaml(root / AI / "protocol-compatibility.yaml")
    if protocol.get("baseline") != "2026-07-28":
        add("MCP protocol baseline is not 2026-07-28")
    current = protocol.get("current", {})
    for key, expected in {"stateless": True, "server_discover_required": True, "per_request_capabilities": True, "result_type_required": True, "mcp_session_id": False, "initialize_required": False, "sse_resume": False}.items():
        if current.get(key) is not expected:
            add(f"MCP protocol guard {key} must be {expected}")
    for mid in module_by_id:
        if any(token in mid for token in ("mcp-roots", "mcp-sampling", "mcp-logging", "mcp-http-sse")):
            add(f"deprecated MCP module present: {mid}")

    deps = tomllib.loads((root / AI / "dependency-baseline.toml").read_text())
    expected_versions = {("llm", "rig_core"): "0.42.0", ("llm", "rig_agent"): "0.42.0", ("llm", "rig_bedrock"): "0.42.0", ("llm", "rig_vertexai"): "0.42.0", ("llm", "schemars"): "1.2.2", ("llm", "jsonschema"): "0.51.0", ("mcp", "rmcp"): "3.1.4"}
    if deps.get("protocol", {}).get("mcp") != "2026-07-28":
        add("dependency baseline MCP revision mismatch")
    for (section, key), expected in expected_versions.items():
        if deps.get(section, {}).get(key) != expected:
            add(f"dependency {section}.{key} expected {expected}, found {deps.get(section, {}).get(key)}")

    # Research references and unresolved placeholders.
    sources = root / "research/llm-mcp-suite/sources.md"
    source_ids = set(re.findall(r"`(SRC-AI-[A-Z0-9-]+)`", sources.read_text()))
    for path in (root / "research/llm-mcp-suite").glob("*.md"):
        if path != sources:
            for sid in set(re.findall(r"SRC-AI-[A-Z0-9-]+", path.read_text())):
                if sid not in source_ids:
                    add(f"{path.relative_to(root)} references unknown source {sid}")
    for path in root.rglob("*"):
        if path.is_file() and path.suffix.lower() in {".md", ".yaml", ".yml", ".toml", ".json", ".csv"}:
            text = path.read_text(encoding="utf-8", errors="ignore")
            for marker in MARKERS:
                if marker in text:
                    add(f"{path.relative_to(root)} contains prohibited marker {marker}")
    return errors


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("root", nargs="?", type=Path, default=Path(__file__).resolve().parents[1])
    root = parser.parse_args().root.resolve()
    errors = validate(root)
    if errors:
        print(f"FAILED: {len(errors)} issue(s)", file=sys.stderr)
        for issue in errors:
            print(f"- {issue}", file=sys.stderr)
        return 1
    ext = json.loads((root / AI / "spec-extension-manifest.json").read_text())
    counts = ext["counts"]
    print(f"OK: LLM/MCP feature suite {ext['extension']['version']} — {counts['numbered_specs']} specs, {counts['adrs']} ADRs, {counts['modules']} modules, {counts['profiles']} profiles, {counts['acceptance_criteria']} acceptance criteria, {counts['tasks']} tasks, {counts['recommendations']} recommendations")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

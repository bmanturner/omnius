#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import shutil
import sys
import tempfile
import unicodedata
from pathlib import Path, PurePosixPath, PureWindowsPath
from typing import Any, NoReturn, Sequence
from jsonschema import Draft202012Validator
import yaml

sys.path.insert(0, str(Path(__file__).resolve().parent))
import web_evidence

AI_PROFILE_IDS = (
    "llm-runtime",
    "llm-api",
    "llm-agent",
    "ai-worker",
    "mcp-local",
    "mcp-http",
    "mcp-enterprise",
    "ai-platform",
    "full-reference-ai",
)
BASE_MATRIX_CHECKS = {
    "render-fresh",
    "render-repeat",
    "byte-identical",
    "metadata-artifacts",
    "doctor-clean",
    "diff-clean",
    "cargo-test",
    "profile-info",
    "process-lifecycle",
}
REQUIRED_RESULTS = {
    "ai-architecture-validation": "AC-AI-116",
    "generated-ai-mcp-profile-matrix": "AC-AI-113",
    "ai-suite-static-validation": "AC-AI-117",
    "prior-version-module-lifecycle": "AC-AI-114",
}
EXPECTED_CARGO_ARGUMENTS = {
    "ai-architecture-validation": ["xtask", "ai", "verify"],
    "generated-ai-mcp-profile-matrix": [
        "xtask",
        "profiles",
        "generate-verify",
        "--jobs",
        "2",
        "--automated-evidence-only",
    ],
    "prior-version-module-lifecycle": [
        "test",
        "-p",
        "omnius-generator",
        "--test",
        "module_management",
    ],
}
WINDOWS_RESERVED_NAMES = {
    "CON",
    "PRN",
    "AUX",
    "NUL",
    *(f"COM{number}" for number in range(1, 10)),
    *(f"LPT{number}" for number in range(1, 10)),
}


class EvidenceError(RuntimeError):
    pass


def fail(message: str) -> NoReturn:
    raise EvidenceError(message)

def validate_result_command(result_id: str, value: dict[str, Any]) -> None:
    argv = value.get("argv")
    if (
        not isinstance(argv, list)
        or not argv
        or not all(isinstance(argument, str) for argument in argv)
    ):
        fail(f"AI/MCP command result {result_id} has invalid argv")
    if result_id == "ai-suite-static-validation":
        valid = argv == [
            "python3",
            "specs/tools/validate_llm_mcp_feature_suite.py",
            "specs",
        ]
    else:
        valid = argv == ["cargo", *EXPECTED_CARGO_ARGUMENTS[result_id]]
    if not valid:
        fail(f"AI/MCP command result {result_id} records an unexpected command")


def artifact(root: Path, value: Path | str) -> dict[str, str]:
    path, relative = web_evidence.relative_path(root, value)
    if not path.is_file():
        fail(f"evidence artifact is missing: {relative}")
    return {"path": relative, "sha256": web_evidence.sha256_file(path)}


def load_object(path: Path, label: str) -> dict[str, Any]:
    value = web_evidence.load_json(path, label)
    if not isinstance(value, dict):
        fail(f"{label} is not an object")
    return value


def validate_profile_matrix(value: dict[str, Any]) -> list[dict[str, Any]]:
    if value.get("matrix_success") is not True:
        fail("profile matrix did not pass")
    raw_profiles = value.get("profiles")
    if not isinstance(raw_profiles, list):
        fail("profile matrix omits profiles")
    indexed = {
        profile.get("profile"): profile
        for profile in raw_profiles
        if isinstance(profile, dict) and isinstance(profile.get("profile"), str)
    }
    missing = set(AI_PROFILE_IDS) - set(indexed)
    if missing:
        fail(f"profile matrix omits AI/MCP profiles: {sorted(missing)}")

    profiles: list[dict[str, Any]] = []
    for profile_id in AI_PROFILE_IDS:
        profile = indexed[profile_id]
        if profile.get("success") is not True:
            fail(f"profile {profile_id} did not pass")
        raw_checks = profile.get("checks")
        if not isinstance(raw_checks, list):
            fail(f"profile {profile_id} omits checks")
        checks = {
            check.get("name"): check
            for check in raw_checks
            if isinstance(check, dict) and isinstance(check.get("name"), str)
        }
        missing_checks = BASE_MATRIX_CHECKS - set(checks)
        if missing_checks:
            fail(f"profile {profile_id} omits matrix checks: {sorted(missing_checks)}")
        for name in BASE_MATRIX_CHECKS:
            check = checks[name]
            if (
                check.get("required") is not True
                or check.get("executed") is not True
                or check.get("status") != "passed"
                or check.get("success") is not True
            ):
                fail(f"profile {profile_id} base matrix check {name} did not pass")
        passed: list[str] = []
        for name, check in checks.items():
            if check.get("required") is True:
                if (
                    check.get("executed") is not True
                    or check.get("status") != "passed"
                    or check.get("success") is not True
                ):
                    fail(f"profile {profile_id} required check {name} did not pass")
                passed.append(name)
        profiles.append({"id": profile_id, "status": "passed", "checks": sorted(passed)})
    return profiles


def rehearse_clean_extraction(root: Path) -> int:
    bundle_metadata = (
        ("MANIFEST.json", "SHA256SUMS"),
        ("WEB_FEATURE_SUITE_MANIFEST.json", "WEB_FEATURE_SUITE_SHA256SUMS"),
        ("LLM_MCP_FEATURE_SUITE_MANIFEST.json", "LLM_MCP_FEATURE_SUITE_SHA256SUMS"),
    )
    specs_path = root / "specs"
    if specs_path.is_symlink() or not specs_path.is_dir():
        fail("specs root is missing or unsafe")
    specs_root = specs_path.resolve(strict=True)
    collision_keys: set[str] = set()
    extracted = 0
    with tempfile.TemporaryDirectory(prefix="omnius-ai-mcp-extraction-") as temporary:
        destination_root = Path(temporary)
        for manifest_name, checksum_name in bundle_metadata:
            manifest_path = specs_path / manifest_name
            manifest = load_object(manifest_path, manifest_path.name)
            entries = manifest.get("files")
            if not isinstance(entries, list):
                fail(f"{manifest_path.name} omits files")
            raw_paths: list[str] = []
            for entry in entries:
                if not isinstance(entry, dict) or not isinstance(entry.get("path"), str):
                    fail(f"{manifest_path.name} contains an invalid file entry")
                raw_paths.append(entry["path"])
            raw_paths.extend((manifest_name, checksum_name))
            for raw_path in raw_paths:
                posix_path = PurePosixPath(raw_path)
                windows_path = PureWindowsPath(raw_path)
                unsafe_component = any(
                    not component
                    or component in {".", ".."}
                    or component != component.rstrip(" .")
                    or ":" in component
                    or any(ord(character) < 32 for character in component)
                    or component.split(".", 1)[0].upper() in WINDOWS_RESERVED_NAMES
                    for component in posix_path.parts
                )
                if (
                    not raw_path
                    or "\\" in raw_path
                    or raw_path != posix_path.as_posix()
                    or posix_path.is_absolute()
                    or windows_path.is_absolute()
                    or windows_path.drive
                    or unsafe_component
                ):
                    fail(f"{manifest_path.name} contains unsafe path {raw_path}")
                collision_key = unicodedata.normalize(
                    "NFC", posix_path.as_posix()
                ).casefold()
                if collision_key in collision_keys:
                    fail(f"archive extraction collision at {raw_path}")
                collision_keys.add(collision_key)

                source = specs_root.joinpath(*posix_path.parts)
                current = specs_root
                for component in posix_path.parts:
                    current /= component
                    if current.is_symlink():
                        fail(f"archive source is missing or unsafe: specs/{raw_path}")
                if not source.is_file():
                    fail(f"archive source is missing or unsafe: specs/{raw_path}")
                try:
                    source.resolve(strict=True).relative_to(specs_root)
                except ValueError:
                    fail(f"archive source escapes specs: {raw_path}")

                destination = destination_root.joinpath(*posix_path.parts)
                if destination.exists():
                    fail(f"archive extraction collision at {raw_path}")
                destination.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(source, destination)
                extracted += 1
    return extracted


def validate_runbook(path: Path) -> None:
    text = path.read_text(encoding="utf-8").lower()
    required = (
        "provider operations",
        "protocol upgrades",
        "security response",
        "cost controls",
        "operational response",
        "rollback",
        "release evidence",
    )
    missing = [heading for heading in required if heading not in text]
    if missing:
        fail(f"AI/MCP runbook omits required sections: {missing}")

def validate_append_only_tasks(root: Path) -> tuple[int, int]:
    task_paths = (
        root / "specs/machine/tasks.yaml",
        root / "specs/machine/extensions/web-application-suite/tasks.yaml",
        root / "specs/machine/extensions/llm-mcp-suite/tasks.yaml",
    )
    catalogs: list[list[dict[str, Any]]] = []
    for path in task_paths:
        value = yaml.safe_load(path.read_text(encoding="utf-8"))
        tasks = value.get("tasks") if isinstance(value, dict) else None
        if not isinstance(tasks, list) or not all(isinstance(task, dict) for task in tasks):
            fail(f"task catalog is invalid: {path.relative_to(root)}")
        catalogs.append(tasks)

    all_tasks = [task for catalog in catalogs for task in catalog]
    indexed = {
        task.get("id"): task
        for task in all_tasks
        if isinstance(task.get("id"), str)
    }
    if len(indexed) != len(all_tasks):
        fail("merged task catalogs contain missing or duplicate identifiers")

    ai_tasks = catalogs[-1]
    expected_ai_ids = [f"T{number:03d}" for number in range(150, 180)]
    if [task.get("id") for task in ai_tasks] != expected_ai_ids:
        fail("AI/MCP tasks are not the append-only T150 through T179 sequence")

    def task_number(task_id: str) -> int:
        if len(task_id) != 4 or not task_id.startswith("T") or not task_id[1:].isdigit():
            fail(f"task identifier is not canonical: {task_id}")
        return int(task_id[1:])

    for task in ai_tasks:
        task_id = task["id"]
        dependencies = task.get("depends_on")
        if not isinstance(dependencies, list) or not all(
            isinstance(dependency, str) for dependency in dependencies
        ):
            fail(f"AI/MCP task {task_id} has invalid dependencies")
        for dependency in dependencies:
            if dependency not in indexed:
                fail(f"AI/MCP task {task_id} references unknown dependency {dependency}")
            if task_number(dependency) >= task_number(task_id):
                fail(f"AI/MCP task {task_id} restarts or forward-references {dependency}")

    final_task = ai_tasks[-1]
    expected_dependencies = ["T111", "T112", "T113", "T114", "T149", "T178"]
    expected_acceptance = [f"AC-AI-{number:03d}" for number in range(113, 121)]
    if final_task.get("depends_on") != expected_dependencies:
        fail("T179 prerequisite set is not the approved append-only dependency boundary")
    if final_task.get("acceptance") != expected_acceptance:
        fail("T179 acceptance ownership is not exactly AC-AI-113 through AC-AI-120")

    prerequisite_ids: set[str] = set()
    pending = list(expected_dependencies)
    while pending:
        dependency = pending.pop()
        if dependency in prerequisite_ids:
            continue
        prerequisite_ids.add(dependency)
        pending.extend(indexed[dependency].get("depends_on", []))
    prerequisite_acceptance = {
        criterion_id
        for task_id in prerequisite_ids
        for criterion_id in indexed[task_id].get("acceptance", [])
    }
    if prerequisite_acceptance & set(expected_acceptance):
        fail("T179 restarts acceptance work owned by a completed prerequisite")
    return len(ai_tasks), len(prerequisite_ids)


def criterion(
    criterion_id: str,
    detail: str,
    artifacts: list[dict[str, str]],
) -> dict[str, Any]:
    return {
        "id": criterion_id,
        "status": "passed",
        "detail": detail,
        "artifacts": artifacts,
    }

def validate_document(value: dict[str, Any]) -> None:
    if set(value) != {
        "schemaVersion",
        "evidenceId",
        "status",
        "generatedAt",
        "binding",
        "profiles",
        "criteria",
    }:
        fail("AI/MCP evidence has missing or unexpected fields")
    if (
        value["schemaVersion"] != 1
        or value["evidenceId"] != "ai-mcp-release-readiness"
        or value["status"] != "passed"
    ):
        fail("AI/MCP evidence identity or status is invalid")
    if not isinstance(value["generatedAt"], str) or not value["generatedAt"]:
        fail("AI/MCP evidence generation time is invalid")
    binding = value["binding"]
    if (
        not isinstance(binding, dict)
        or set(binding)
        != {
            "runId",
            "revision",
            "specManifestSha256",
            "contractAggregateSha256",
        }
        or not isinstance(binding["runId"], str)
        or not binding["runId"]
        or not isinstance(binding["revision"], str)
        or len(binding["revision"]) < 7
        or not web_evidence.is_sha256(binding["specManifestSha256"])
        or not web_evidence.is_sha256(binding["contractAggregateSha256"])
    ):
        fail("AI/MCP evidence binding is invalid")
    profiles = value["profiles"]
    if (
        not isinstance(profiles, list)
        or [profile.get("id") for profile in profiles if isinstance(profile, dict)]
        != list(AI_PROFILE_IDS)
    ):
        fail("AI/MCP evidence does not contain the exact ordered profile set")
    for profile in profiles:
        checks = profile.get("checks")
        if (
            set(profile) != {"id", "status", "checks"}
            or profile.get("status") != "passed"
            or not isinstance(checks, list)
            or not checks
            or len(checks) != len(set(checks))
            or not all(isinstance(check, str) and check for check in checks)
        ):
            fail(f"AI/MCP profile evidence is incomplete: {profile.get('id')}")
    expected_criteria = {f"AC-AI-{number:03d}" for number in range(113, 121)}
    criteria = value["criteria"]
    if (
        not isinstance(criteria, list)
        or len(criteria) != len(expected_criteria)
        or {
            item.get("id")
            for item in criteria
            if isinstance(item, dict)
        }
        != expected_criteria
    ):
        fail("AI/MCP evidence does not contain exactly AC-AI-113 through AC-AI-120")
    for item in criteria:
        if not isinstance(item, dict) or set(item) != {
            "id",
            "status",
            "detail",
            "artifacts",
        }:
            fail("AI/MCP criterion has missing or unexpected fields")
        artifacts = item.get("artifacts")
        if (
            item.get("status") != "passed"
            or not isinstance(item.get("detail"), str)
            or not item["detail"]
            or not isinstance(artifacts, list)
            or not artifacts
        ):
            fail(f"AI/MCP criterion {item.get('id')} is incomplete")
        for record in artifacts:
            if (
                not isinstance(record, dict)
                or set(record) != {"path", "sha256"}
                or not isinstance(record["path"], str)
                or not record["path"]
                or not web_evidence.is_sha256(record["sha256"])
            ):
                fail(f"AI/MCP criterion {item.get('id')} has an invalid artifact")


def produce(root: Path, arguments: argparse.Namespace) -> int:
    binding = web_evidence.current_binding(root)

    validated_results: dict[str, tuple[dict[str, Any], str]] = {}
    for raw_path in arguments.result:
        result = web_evidence.validate_result(root, Path(raw_path), binding)
        _, relative = web_evidence.relative_path(root, raw_path)
        result_id = result.get("resultId")
        if result_id not in REQUIRED_RESULTS:
            fail(f"unexpected AI/MCP command result {result_id!r}")
        if result_id in validated_results:
            fail(f"duplicate AI/MCP command result {result_id}")
        if result.get("status") != "passed":
            fail(f"AI/MCP command result {result_id} did not pass")
        validate_result_command(result_id, result)
        validated_results[result_id] = (result, relative)
    missing_results = set(REQUIRED_RESULTS) - set(validated_results)
    if missing_results:
        fail(f"missing AI/MCP command results: {sorted(missing_results)}")
    matrix_result = validated_results["generated-ai-mcp-profile-matrix"][0]
    matrix_records = matrix_result.get("artifacts")
    matrix_record = next(
        (
            record
            for record in matrix_records
            if isinstance(record, dict)
            and record.get("path") == "target/profile-matrix/report.json"
        ),
        None,
    ) if isinstance(matrix_records, list) else None
    if matrix_record is None:
        fail("bound profile matrix result omits target/profile-matrix/report.json")
    matrix_path, _ = web_evidence.relative_path(root, matrix_record["path"])
    profiles = validate_profile_matrix(load_object(matrix_path, "profile matrix report"))

    extracted = rehearse_clean_extraction(root)
    runbook_path = root / "release/ai-mcp-suite-runbook.md"
    validate_runbook(runbook_path)
    ai_task_count, prerequisite_count = validate_append_only_tasks(root)

    matrix_artifact = artifact(root, matrix_record["path"])
    lifecycle_artifact = artifact(
        root, validated_results["prior-version-module-lifecycle"][1]
    )
    architecture_artifact = artifact(
        root, validated_results["ai-architecture-validation"][1]
    )
    static_artifact = artifact(
        root, validated_results["ai-suite-static-validation"][1]
    )
    manifests = [
        artifact(root, "specs/MANIFEST.json"),
        artifact(root, "specs/WEB_FEATURE_SUITE_MANIFEST.json"),
        artifact(root, "specs/LLM_MCP_FEATURE_SUITE_MANIFEST.json"),
    ]
    criteria = [
        criterion(
            "AC-AI-113",
            "all nine AI/MCP profiles passed every required declared matrix check",
            [matrix_artifact],
        ),
        criterion(
            "AC-AI-114",
            "AI generator add, remove, doctor, diff, and prior-version upgrade rehearsal passed idempotently",
            [
                lifecycle_artifact,
                artifact(root, "crates/generator/tests/module_management.rs"),
            ],
        ),
        criterion(
            "AC-AI-115",
            f"clean extraction rehearsal copied {extracted} manifest entries with zero collisions",
            manifests,
        ),
        criterion(
            "AC-AI-116",
            "pinned dependency ownership and protocol compatibility architecture gate passed",
            [
                architecture_artifact,
                artifact(root, "specs/machine/extensions/llm-mcp-suite/dependency-baseline.toml"),
                artifact(root, "specs/machine/extensions/llm-mcp-suite/protocol-compatibility.yaml"),
            ],
        ),
        criterion(
            "AC-AI-117",
            "merged machine catalogs passed deterministic composition and unique identifier validation",
            [
                static_artifact,
                artifact(root, "specs/machine/extensions/llm-mcp-suite/module-catalog.yaml"),
                artifact(root, "specs/machine/extensions/llm-mcp-suite/profiles.yaml"),
            ],
        ),
        criterion(
            "AC-AI-118",
            "AI/MCP recommendation traceability passed one-to-one acceptance coverage validation",
            [
                static_artifact,
                artifact(root, "specs/machine/extensions/llm-mcp-suite/recommendation-traceability.csv"),
            ],
        ),
        criterion(
            "AC-AI-119",
            "provider, protocol, security, cost, and operations procedures are release-bound",
            [artifact(root, "release/ai-mcp-suite-runbook.md")],
        ),
        criterion(
            "AC-AI-120",
            (
                f"validated {ai_task_count} ordered AI tasks ending at T179 and "
                f"{prerequisite_count} earlier, non-overlapping prerequisites"
            ),
            [
                static_artifact,
                artifact(root, "specs/machine/tasks.yaml"),
                artifact(root, "specs/machine/extensions/web-application-suite/tasks.yaml"),
                artifact(root, "specs/machine/extensions/llm-mcp-suite/tasks.yaml"),
            ],
        ),
    ]
    document = {
        "schemaVersion": 1,
        "evidenceId": "ai-mcp-release-readiness",
        "status": "passed",
        "generatedAt": web_evidence.utc_now(),
        "binding": binding,
        "profiles": profiles,
        "criteria": criteria,
    }
    schema = load_object(
        root / "release/ai-mcp-release-evidence.schema.json",
        "AI/MCP evidence schema",
    )
    Draft202012Validator.check_schema(schema)
    issues = sorted(
        Draft202012Validator(schema).iter_errors(document),
        key=lambda issue: list(issue.path),
    )
    if issues:
        fail(f"AI/MCP evidence violates schema: {issues[0].message}")
    validate_document(document)
    output, _ = web_evidence.relative_path(root, arguments.output)
    web_evidence.write_json(output, document)
    return 0


def parse_args(arguments: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(prog="ai_mcp_evidence.py")
    parser.add_argument("--result", action="append", required=True)
    parser.add_argument("--output", required=True)
    return parser.parse_args(arguments)


def main(arguments: Sequence[str] | None = None, *, root: Path | None = None) -> int:
    try:
        return produce(root or web_evidence.repository_root(), parse_args(arguments))
    except (EvidenceError, web_evidence.EvidenceError, OSError, ValueError) as error:
        print(f"ai-mcp evidence error: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())

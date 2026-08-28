#!/usr/bin/env python3
from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
import shlex
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any, NoReturn, Sequence

SHA256_LENGTH = 64
RESULT_KEYS = {
    "schemaVersion",
    "resultId",
    "status",
    "detail",
    "command",
    "argv",
    "exitCode",
    "startedAt",
    "completedAt",
    "binding",
    "artifacts",
}
BINDING_KEYS = {
    "runId",
    "revision",
    "specManifestSha256",
    "contractAggregateSha256",
}
ARTIFACT_KEYS = {"path", "sha256"}


class EvidenceError(RuntimeError):
    pass


def fail(message: str) -> NoReturn:
    raise EvidenceError(message)


def repository_root() -> Path:
    root = Path(__file__).resolve().parents[2]
    if not (root / "Cargo.toml").is_file() or not (root / "package.json").is_file():
        fail("web evidence producer is not under the repository root")
    return root


def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def sha256_bytes(contents: bytes) -> str:
    return hashlib.sha256(contents).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    try:
        with path.open("rb") as handle:
            while chunk := handle.read(1024 * 1024):
                digest.update(chunk)
    except OSError as error:
        fail(f"cannot hash {path}: {error}")
    return digest.hexdigest()


def is_sha256(value: object) -> bool:
    return (
        isinstance(value, str)
        and len(value) == SHA256_LENGTH
        and all(character in "0123456789abcdef" for character in value)
    )


def relative_path(root: Path, value: Path | str) -> tuple[Path, str]:
    candidate = Path(value)
    if candidate.is_absolute():
        fail(f"artifact path must be repository-relative: {candidate}")
    if any(part == ".." for part in candidate.parts):
        fail(f"artifact path must not escape the repository: {candidate}")
    resolved = (root / candidate).resolve(strict=False)
    try:
        relative = resolved.relative_to(root.resolve())
    except ValueError:
        fail(f"artifact path escapes the repository: {candidate}")
    if not relative.parts:
        fail("artifact path must name a file")
    return resolved, relative.as_posix()


def artifact(root: Path, value: Path | str, *, allow_empty: bool = True) -> dict[str, str]:
    path, relative = relative_path(root, value)
    if path.is_symlink() or not path.is_file():
        fail(f"required artifact is not a regular file: {relative}")
    if not allow_empty and path.stat().st_size == 0:
        fail(f"required artifact is empty: {relative}")
    return {"path": relative, "sha256": sha256_file(path)}


def load_json(path: Path, label: str) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        fail(f"cannot read {label} as JSON: {error}")


def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(
        json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    temporary.replace(path)


def environment_value(*names: str) -> str | None:
    for name in names:
        value = os.environ.get(name, "").strip()
        if value:
            return value
    return None


def revision(root: Path) -> str:
    configured = environment_value("OMNIUS_RELEASE_REVISION", "GITHUB_SHA")
    if configured is not None:
        return configured
    try:
        completed = subprocess.run(
            ["git", "-C", str(root), "rev-parse", "HEAD"],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
    except (OSError, subprocess.CalledProcessError) as error:
        fail(f"cannot resolve current revision: {error}")
    value = completed.stdout.strip()
    if len(value) < 7:
        fail("current revision is missing or too short")
    return value


def run_id() -> str:
    configured = environment_value("OMNIUS_RELEASE_RUN_ID")
    if configured is not None:
        return configured
    github_run = environment_value("GITHUB_RUN_ID")
    github_attempt = environment_value("GITHUB_RUN_ATTEMPT")
    if github_run is None or github_attempt is None:
        fail("OMNIUS_RELEASE_RUN_ID or both GitHub run identifiers are required")
    return f"github-{github_run}-{github_attempt}"


def validated_spec_manifest_sha256(root: Path) -> str:
    manifest_path = root / "specs/machine/spec-manifest.json"
    try:
        manifest_bytes = manifest_path.read_bytes()
    except OSError as error:
        fail(f"cannot read specification manifest: {error}")
    try:
        manifest = json.loads(manifest_bytes)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        fail(f"specification manifest is invalid JSON: {error}")
    if not isinstance(manifest, dict) or manifest.get("schema_version") != 1:
        fail("specification manifest has an unsupported schema")
    documents = manifest.get("documents")
    if not isinstance(documents, list) or not documents:
        fail("specification manifest has no documents")
    seen: set[str] = set()
    for entry in documents:
        if not isinstance(entry, dict) or not {"path", "bytes", "sha256"} <= set(entry):
            fail("specification manifest contains a malformed document entry")
        if (
            not isinstance(entry["bytes"], int)
            or isinstance(entry["bytes"], bool)
            or not is_sha256(entry["sha256"])
        ):
            fail("specification manifest contains invalid document metadata")
        relative = entry["path"]
        if not isinstance(relative, str) or not relative or relative in seen:
            fail("specification manifest contains a missing or duplicate path")
        seen.add(relative)
        document, _ = relative_path(root / "specs", relative)
        try:
            contents = document.read_bytes()
        except OSError as error:
            fail(f"cannot read specification document {relative}: {error}")
        if entry["bytes"] != len(contents) or entry["sha256"] != sha256_bytes(contents):
            fail(f"specification manifest entry is stale: {relative}")
    return sha256_bytes(manifest_bytes)


def contract_aggregate_sha256(root: Path) -> str:
    manifest = load_json(root / "contracts/contract-manifest.json", "contract manifest")
    if not isinstance(manifest, dict) or not is_sha256(manifest.get("aggregate_sha256")):
        fail("contract manifest has no valid aggregate SHA-256")
    return manifest["aggregate_sha256"]


def current_binding(root: Path) -> dict[str, str]:
    current_revision = revision(root)
    if len(current_revision) < 7:
        fail("current revision is missing or too short")
    return {
        "runId": run_id(),
        "revision": current_revision,
        "specManifestSha256": validated_spec_manifest_sha256(root),
        "contractAggregateSha256": contract_aggregate_sha256(root),
    }


def execute_command(root: Path, arguments: argparse.Namespace) -> int:
    command = list(arguments.command)
    if command and command[0] == "--":
        command.pop(0)
    if not command:
        fail("run requires a command after --")
    if not arguments.result_id.strip():
        fail("run requires a nonempty result ID")
    output_path, _ = relative_path(root, arguments.output)
    log_value = arguments.log or arguments.output.with_suffix(".log")
    log_path, log_relative = relative_path(root, log_value)
    if output_path == log_path:
        fail("command result and command log paths must differ")
    log_path.parent.mkdir(parents=True, exist_ok=True)
    binding = current_binding(root)
    started_at = utc_now()
    launch_error: str | None = None
    try:
        completed = subprocess.run(
            command,
            cwd=root,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            check=False,
        )
        exit_code = completed.returncode
        command_output = completed.stdout
    except OSError as error:
        exit_code = 127
        launch_error = f"cannot execute {command[0]}: {error}"
        command_output = (launch_error + "\n").encode()
    log_path.write_bytes(command_output)
    sys.stdout.buffer.write(command_output)
    sys.stdout.buffer.flush()
    artifacts = [{"path": log_relative, "sha256": sha256_bytes(command_output)}]
    missing: list[str] = []
    for retained in arguments.retain_artifact:
        source_value, separator, destination_value = retained.partition("=")
        if not separator or not source_value or not destination_value:
            missing.append(f"retained artifact must use SOURCE=DEST: {retained}")
            continue
        try:
            source, source_relative = relative_path(root, source_value)
            destination, destination_relative = relative_path(root, destination_value)
            if source.is_symlink() or not source.is_file() or source.stat().st_size == 0:
                fail(f"required artifact is absent or empty: {source_relative}")
            if destination in {output_path, log_path}:
                fail(f"retained artifact collides with producer output: {destination_relative}")
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(source, destination)
            artifacts.append(artifact(root, destination_relative, allow_empty=False))
        except (EvidenceError, OSError) as error:
            missing.append(str(error))

    for requested in arguments.artifact:
        try:
            descriptor = artifact(root, requested, allow_empty=False)
        except EvidenceError as error:
            missing.append(str(error))
        else:
            if descriptor["path"] != log_relative:
                artifacts.append(descriptor)
    artifacts.sort(key=lambda item: item["path"])
    status = "passed" if exit_code == 0 and launch_error is None and not missing else "failed"
    if launch_error is not None:
        detail = launch_error
    elif exit_code != 0:
        detail = f"command exited with status {exit_code}"
    elif missing:
        detail = "; ".join(missing)
    else:
        detail = "command completed and every declared artifact was retained"
    result = {
        "schemaVersion": 1,
        "resultId": arguments.result_id,
        "status": status,
        "detail": detail,
        "command": shlex.join(command),
        "argv": command,
        "exitCode": exit_code,
        "startedAt": started_at,
        "completedAt": utc_now(),
        "binding": binding,
        "artifacts": artifacts,
    }
    write_json(output_path, result)
    return 0 if status == "passed" else (exit_code if exit_code != 0 else 1)


def require_exact_keys(value: object, expected: set[str], label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != expected:
        fail(f"{label} has missing or unexpected fields")
    return value


def validate_binding(value: object, expected: dict[str, str], label: str) -> None:
    binding = require_exact_keys(value, BINDING_KEYS, f"{label} binding")
    if binding != expected:
        fail(f"{label} binding does not match the current run")


def validate_result(root: Path, path_value: Path, expected: dict[str, str]) -> dict[str, Any]:
    path, relative = relative_path(root, path_value)
    value = require_exact_keys(load_json(path, relative), RESULT_KEYS, f"command result {relative}")
    if value["schemaVersion"] != 1:
        fail(f"command result {relative} has an unsupported schema")
    if not isinstance(value["resultId"], str) or not value["resultId"].strip():
        fail(f"command result {relative} has no result ID")
    if value["status"] not in {"passed", "failed"}:
        fail(f"command result {relative} has an invalid status")
    if not isinstance(value["detail"], str) or not value["detail"].strip():
        fail(f"command result {relative} has no detail")
    if not isinstance(value["command"], str) or not value["command"].strip():
        fail(f"command result {relative} has no command")
    if not isinstance(value["argv"], list) or not value["argv"] or not all(
        isinstance(item, str) for item in value["argv"]
    ):
        fail(f"command result {relative} has invalid command arguments")
    if value["command"] != shlex.join(value["argv"]):
        fail(f"command result {relative} command text does not match its arguments")
    if not isinstance(value["exitCode"], int):
        fail(f"command result {relative} has no integer exit code")
    if value["status"] == "passed" and value["exitCode"] != 0:
        fail(f"command result {relative} claims success for a failing command")
    for field in ("startedAt", "completedAt"):
        if not isinstance(value[field], str) or not value[field].strip():
            fail(f"command result {relative} has no {field}")
    validate_binding(value["binding"], expected, f"command result {relative}")
    raw_artifacts = value["artifacts"]
    if not isinstance(raw_artifacts, list) or not raw_artifacts:
        fail(f"command result {relative} has no artifacts")
    seen: set[str] = set()
    for index, raw_artifact in enumerate(raw_artifacts):
        descriptor = require_exact_keys(
            raw_artifact, ARTIFACT_KEYS, f"artifact {index} in command result {relative}"
        )
        artifact_path = descriptor["path"]
        if not isinstance(artifact_path, str) or artifact_path in seen:
            fail(f"command result {relative} has a missing or duplicate artifact path")
        seen.add(artifact_path)
        actual = artifact(root, artifact_path)
        if not is_sha256(descriptor["sha256"]) or actual["sha256"] != descriptor["sha256"]:
            fail(f"command result {relative} has a stale artifact hash for {artifact_path}")
    value["_recordArtifact"] = artifact(root, relative)
    return value


def combined_status(statuses: Sequence[str]) -> str:
    return "failed" if "failed" in statuses else "passed"


def produce_evidence(root: Path, arguments: argparse.Namespace) -> int:
    if not arguments.result:
        fail("produce requires at least one --result")
    if not arguments.evidence_id.strip():
        fail("produce requires a nonempty evidence ID")
    binding = current_binding(root)
    results = [validate_result(root, path, binding) for path in arguments.result]
    ids = [result["resultId"] for result in results]
    if len(ids) != len(set(ids)):
        fail("release evidence contains duplicate command result IDs")
    checks = []
    for result in results:
        artifacts = [result["_recordArtifact"], *result["artifacts"]]
        artifacts.sort(key=lambda item: item["path"])
        checks.append(
            {
                "id": result["resultId"],
                "status": result["status"],
                "command": result["command"],
                "artifacts": artifacts,
            }
        )
    checks.sort(key=lambda check: check["id"])
    status = combined_status([check["status"] for check in checks])
    passed = sum(check["status"] == "passed" for check in checks)
    document = {
        "schemaVersion": 2,
        "evidenceId": arguments.evidence_id,
        "status": status,
        "detail": f"{passed} of {len(checks)} recorded commands passed with current bound artifacts",
        "generatedAt": utc_now(),
        "binding": binding,
        "checks": checks,
    }
    output_path, _ = relative_path(root, arguments.output)
    write_json(output_path, document)
    return 0


def parse_args(arguments: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(prog="web_evidence.py")
    subparsers = parser.add_subparsers(dest="operation", required=True)

    run_parser = subparsers.add_parser("run")
    run_parser.add_argument("--result-id", required=True)
    run_parser.add_argument("--output", required=True, type=Path)
    run_parser.add_argument("--log", type=Path)
    run_parser.add_argument("--artifact", action="append", default=[], type=Path)
    run_parser.add_argument("--retain-artifact", action="append", default=[])
    run_parser.add_argument("command", nargs=argparse.REMAINDER)

    produce_parser = subparsers.add_parser("produce")
    produce_parser.add_argument("--evidence-id", required=True)
    produce_parser.add_argument("--output", required=True, type=Path)
    produce_parser.add_argument("--result", action="append", default=[], type=Path)
    return parser.parse_args(arguments)


def main(arguments: Sequence[str] | None = None, *, root: Path | None = None) -> int:
    parsed = parse_args(arguments)
    workspace = (root or repository_root()).resolve()
    try:
        if parsed.operation == "run":
            return execute_command(workspace, parsed)
        return produce_evidence(workspace, parsed)
    except EvidenceError as error:
        print(f"web release evidence error: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())

from __future__ import annotations

import base64
import binascii
import datetime as dt
import gzip
import hashlib
import io
import json
import os
import re
import shutil
import stat
import subprocess
import tarfile
import tempfile
import tomllib
import urllib.parse
import uuid
from pathlib import Path
from typing import Any, NoReturn

BUNDLE_DIR = "bundle"
ARCHIVE_NAME = "omnius-release-bundle.tar.gz"
ARCHIVE_CHECKSUM_NAME = f"{ARCHIVE_NAME}.sha256"
ARCHIVE_SIGNATURE_NAME = f"{ARCHIVE_NAME}.signature.json"
CORE_FILES = (
    "manifest.json",
    "provenance.intoto.json",
    "sbom.cdx.json",
)
INNER_FILES = (*CORE_FILES, "SHA256SUMS", "signature.json")
OUTPUT_FILES = (BUNDLE_DIR, ARCHIVE_NAME, ARCHIVE_CHECKSUM_NAME, ARCHIVE_SIGNATURE_NAME)
KEY_PATH = Path("release/test-keys/t123-ed25519-public.json")
MEDIA_TYPE = "application/vnd.omnius.release-bundle.v1+json"
SIGNATURE_MEDIA_TYPE = "application/vnd.omnius.detached-signature.v1+json"
IN_TOTO_STATEMENT = "https://in-toto.io/Statement/v1"
SLSA_PROVENANCE = "https://slsa.dev/provenance/v1"
BUILD_TYPE = "https://omnius.dev/build-types/local-release-bundle/v1"
BUILDER_ID = "https://omnius.dev/builders/local-release-bundle/v1"
EXPECTED_KEY_ID = (
    "rfc8032-test-vector-1-ed25519-sha256:"
    "21fe31dfa154a261626bf854046fd2271b7bed4b6abe45aa58877ef47f9721b9"
)
EXPECTED_PUBLIC_KEY = bytes.fromhex(
    "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
)
RFC8032_TEST_SEED = bytes.fromhex(
    "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"
)
PRIVATE_SEED_HEX = RFC8032_TEST_SEED.hex().encode()
PRIVATE_SEED_B64 = base64.b64encode(RFC8032_TEST_SEED)
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
COMMIT_RE = re.compile(r"^[0-9a-f]{40,64}$")
CHECKSUM_RE = re.compile(r"^([0-9a-f]{64})  ([A-Za-z0-9][A-Za-z0-9._-]*)$")


class ReleaseBundleError(RuntimeError):
    pass


class VerificationError(ReleaseBundleError):
    pass


def fail(message: str) -> NoReturn:
    raise ReleaseBundleError(message)


def repository_root() -> Path:
    root = Path(__file__).resolve().parents[2]
    if not (root / "Cargo.lock").is_file() or not (root / "Cargo.toml").is_file():
        fail("release command must reside under a Cargo workspace root")
    return root


def canonical_json(value: Any) -> bytes:
    return (json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n").encode()


def reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise VerificationError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def load_json_bytes(data: bytes, label: str) -> Any:
    try:
        return json.loads(data, object_pairs_hook=reject_duplicate_keys)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise VerificationError(f"{label} is not valid UTF-8 JSON: {error}") from error


def load_json_file(path: Path) -> Any:
    try:
        data = path.read_bytes()
    except OSError as error:
        raise VerificationError(f"cannot read {path.name}: {error}") from error
    return load_json_bytes(data, path.name)


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    try:
        with path.open("rb") as handle:
            while chunk := handle.read(1024 * 1024):
                digest.update(chunk)
    except OSError as error:
        raise ReleaseBundleError(f"cannot hash {path}: {error}") from error
    return digest.hexdigest()


def write_bytes(path: Path, data: bytes, mode: int = 0o644) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("wb") as handle:
        handle.write(data)
    path.chmod(mode)


def run_checked(args: list[str], root: Path) -> bytes:
    try:
        completed = subprocess.run(
            args,
            cwd=root,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
    except OSError as error:
        fail(f"cannot execute {args[0]}: {error}")
    if completed.returncode != 0:
        detail = completed.stderr.decode("utf-8", "replace").strip()
        fail(f"{' '.join(args[:2])} failed: {detail or f'exit {completed.returncode}'}")
    return completed.stdout


def git_value(root: Path, *arguments: str) -> str:
    value = run_checked(["git", *arguments], root).decode("utf-8", "strict").strip()
    if not value:
        fail(f"git {' '.join(arguments)} returned an empty value")
    return value


def source_epoch(root: Path, explicit: int | None) -> int:
    if explicit is not None:
        value = explicit
    elif "SOURCE_DATE_EPOCH" in os.environ:
        raw = os.environ["SOURCE_DATE_EPOCH"]
        if not raw.isascii() or not raw.isdigit():
            fail("SOURCE_DATE_EPOCH must be a non-negative integer")
        value = int(raw)
    else:
        raw = git_value(root, "show", "-s", "--format=%ct", "HEAD")
        if not raw.isascii() or not raw.isdigit():
            fail("HEAD commit timestamp is not a non-negative integer")
        value = int(raw)
    if value < 0 or value > 4_294_967_295:
        fail("source date epoch is outside the deterministic gzip timestamp range")
    return value


def rfc3339(epoch: int) -> str:
    return dt.datetime.fromtimestamp(epoch, tz=dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def ensure_output_path(root: Path, output: Path) -> Path:
    candidate = output if output.is_absolute() else root / output
    if candidate.is_symlink():
        fail("release output must not be a symbolic link")
    resolved = candidate.resolve(strict=False)
    artifact_root = (root / "target").resolve(strict=False)
    if resolved == artifact_root or not resolved.is_relative_to(artifact_root):
        fail("release output must be a child directory of target/")
    if resolved.exists() and not resolved.is_dir():
        fail("release output must be a directory")
    return resolved


def read_workspace(root: Path) -> tuple[str, bytes, bytes]:
    cargo_toml_bytes = (root / "Cargo.toml").read_bytes()
    cargo_lock_bytes = (root / "Cargo.lock").read_bytes()
    try:
        cargo_toml = tomllib.loads(cargo_toml_bytes.decode("utf-8"))
        tomllib.loads(cargo_lock_bytes.decode("utf-8"))
        version = cargo_toml["workspace"]["package"]["version"]
    except (UnicodeDecodeError, tomllib.TOMLDecodeError, KeyError, TypeError) as error:
        fail(f"cannot determine workspace version: {error}")
    if not isinstance(version, str) or not version:
        fail("workspace.package.version must be a non-empty string")
    return version, cargo_toml_bytes, cargo_lock_bytes


def cargo_metadata(root: Path) -> dict[str, Any]:
    raw = run_checked(
        [
            "cargo",
            "metadata",
            "--locked",
            "--offline",
            "--all-features",
            "--format-version",
            "1",
        ],
        root,
    )
    value = load_json_bytes(raw, "cargo metadata")
    if not isinstance(value, dict):
        fail("cargo metadata did not return an object")
    return value


def package_key(package: dict[str, Any]) -> tuple[str, str, str]:
    name = package.get("name")
    version = package.get("version")
    source = package.get("source") or ""
    if not isinstance(name, str) or not isinstance(version, str) or not isinstance(source, str):
        fail("Cargo package contains invalid identity fields")
    return name, version, source


def component_ref(key: tuple[str, str, str]) -> str:
    coordinate = "\0".join(key).encode()
    return f"urn:omnius:cargo:{sha256_bytes(coordinate)}"


def package_purl(name: str, version: str) -> str:
    quoted_name = urllib.parse.quote(name, safe="")
    quoted_version = urllib.parse.quote(version, safe="")
    return f"pkg:cargo/{quoted_name}@{quoted_version}"


def safe_public_url(value: Any) -> str | None:
    if not isinstance(value, str) or not value:
        return None
    try:
        parsed = urllib.parse.urlsplit(value)
    except ValueError:
        return None
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        return None
    if parsed.username is not None or parsed.password is not None:
        return None
    host = parsed.hostname.lower()
    if parsed.port is not None:
        host = f"{host}:{parsed.port}"
    return urllib.parse.urlunsplit((parsed.scheme.lower(), host, parsed.path, "", ""))


def source_kind(source: str) -> str:
    if not source:
        return "workspace"
    if source.startswith("registry+"):
        return "registry"
    if source.startswith("git+"):
        return "git"
    return "other"


def source_reference(source: str) -> str | None:
    if not source.startswith("git+"):
        return None
    raw = source.removeprefix("git+")
    revision = ""
    if "#" in raw:
        raw, revision = raw.rsplit("#", 1)
    safe = safe_public_url(raw)
    if safe is None:
        return None
    if revision and re.fullmatch(r"[0-9a-f]{7,64}", revision):
        return f"{safe}#{revision}"
    return safe


def lock_packages(cargo_lock_bytes: bytes) -> dict[tuple[str, str, str], dict[str, Any]]:
    try:
        lock = tomllib.loads(cargo_lock_bytes.decode("utf-8"))
    except (UnicodeDecodeError, tomllib.TOMLDecodeError) as error:
        fail(f"Cargo.lock is invalid: {error}")
    packages = lock.get("package")
    if not isinstance(packages, list) or not packages:
        fail("Cargo.lock contains no packages")
    result: dict[tuple[str, str, str], dict[str, Any]] = {}
    for package in packages:
        if not isinstance(package, dict):
            fail("Cargo.lock package entry is not a table")
        key = package_key(package)
        if key in result:
            fail(f"duplicate Cargo.lock package: {key[0]} {key[1]}")
        result[key] = package
    return result


def resolve_lock_dependency(
    value: str,
    by_name: dict[str, list[tuple[str, str, str]]],
) -> tuple[str, str, str]:
    source = None
    coordinate = value
    if value.endswith(")") and " (" in value:
        coordinate, source = value.rsplit(" (", 1)
        source = source[:-1]
    parts = coordinate.split(" ")
    if len(parts) not in {1, 2} or not parts[0]:
        fail(f"unsupported Cargo.lock dependency coordinate: {value}")
    candidates = list(by_name.get(parts[0], []))
    if len(parts) == 2:
        candidates = [key for key in candidates if key[1] == parts[1]]
    if source is not None:
        candidates = [key for key in candidates if key[2] == source]
    if len(candidates) != 1:
        fail(f"Cargo.lock dependency is ambiguous or missing: {value}")
    return candidates[0]


def build_sbom(
    metadata: dict[str, Any],
    lock: dict[tuple[str, str, str], dict[str, Any]],
    version: str,
    timestamp: str,
    lock_digest: str,
) -> dict[str, Any]:
    metadata_packages = metadata.get("packages")
    workspace_member_ids = metadata.get("workspace_members")
    if not isinstance(metadata_packages, list) or not isinstance(workspace_member_ids, list):
        fail("cargo metadata is missing packages or workspace_members")
    metadata_by_key: dict[tuple[str, str, str], dict[str, Any]] = {}
    key_by_id: dict[str, tuple[str, str, str]] = {}
    for package in metadata_packages:
        if not isinstance(package, dict) or not isinstance(package.get("id"), str):
            fail("cargo metadata contains an invalid package")
        key = package_key(package)
        metadata_by_key[key] = package
        key_by_id[package["id"]] = key
    missing_metadata = sorted(set(lock) - set(metadata_by_key))
    extra_metadata = sorted(set(metadata_by_key) - set(lock))
    if missing_metadata or extra_metadata:
        fail(
            "cargo metadata and Cargo.lock package inventories differ "
            f"(missing={len(missing_metadata)}, extra={len(extra_metadata)})"
        )

    components: list[dict[str, Any]] = []
    for key in sorted(lock):
        name, package_version, source = key
        package = metadata_by_key[key]
        component: dict[str, Any] = {
            "bom-ref": component_ref(key),
            "name": name,
            "properties": [
                {"name": "omnius:cargo:source-kind", "value": source_kind(source)},
                {
                    "name": "omnius:cargo:workspace-member",
                    "value": "true" if package["id"] in workspace_member_ids else "false",
                },
            ],
            "purl": package_purl(name, package_version),
            "type": "library",
            "version": package_version,
        }
        checksum = lock[key].get("checksum")
        if checksum is not None:
            if not isinstance(checksum, str) or SHA256_RE.fullmatch(checksum) is None:
                fail(f"Cargo.lock checksum is invalid for {name} {package_version}")
            component["hashes"] = [{"alg": "SHA-256", "content": checksum}]
        license_expression = package.get("license")
        if isinstance(license_expression, str) and license_expression:
            component["licenses"] = [{"expression": license_expression}]
        references: list[dict[str, str]] = []
        repository = safe_public_url(package.get("repository"))
        homepage = safe_public_url(package.get("homepage"))
        vcs = source_reference(source)
        if repository is not None:
            references.append({"type": "vcs", "url": repository})
        elif vcs is not None:
            references.append({"type": "vcs", "url": vcs})
        if homepage is not None and homepage != repository:
            references.append({"type": "website", "url": homepage})
        if references:
            component["externalReferences"] = references
        components.append(component)

    by_name: dict[str, list[tuple[str, str, str]]] = {}
    for key in lock:
        by_name.setdefault(key[0], []).append(key)
    dependencies: list[dict[str, Any]] = []
    for key in sorted(lock):
        raw_dependencies = lock[key].get("dependencies", [])
        if not isinstance(raw_dependencies, list) or not all(isinstance(item, str) for item in raw_dependencies):
            fail(f"Cargo.lock dependencies are invalid for {key[0]} {key[1]}")
        dependency_refs = sorted(
            component_ref(resolve_lock_dependency(item, by_name)) for item in raw_dependencies
        )
        dependencies.append({"dependsOn": dependency_refs, "ref": component_ref(key)})
    try:
        root_dependencies = sorted(component_ref(key_by_id[item]) for item in workspace_member_ids)
    except KeyError as error:
        fail(f"workspace member is absent from package inventory: {error}")
    root_ref = package_purl("omnius", version)
    dependencies.append({"dependsOn": root_dependencies, "ref": root_ref})
    dependencies.sort(key=lambda item: item["ref"])

    serial = uuid.uuid5(uuid.NAMESPACE_URL, f"omnius:{version}:{lock_digest}")
    return {
        "bomFormat": "CycloneDX",
        "components": components,
        "dependencies": dependencies,
        "metadata": {
            "component": {
                "bom-ref": root_ref,
                "group": "dev.omnius",
                "name": "omnius",
                "type": "application",
                "version": version,
            },
            "timestamp": timestamp,
            "tools": {
                "components": [
                    {
                        "name": "local-release-bundle",
                        "supplier": {"name": "Omnius"},
                        "type": "application",
                        "version": "1",
                    }
                ]
            },
        },
        "serialNumber": f"urn:uuid:{serial}",
        "specVersion": "1.5",
        "version": 1,
    }


def material(path: str, data: bytes) -> dict[str, Any]:
    return {"digest": {"sha256": sha256_bytes(data)}, "uri": f"file:{path}"}


def build_provenance(
    sbom_bytes: bytes,
    version: str,
    commit: str,
    epoch: int,
    input_materials: list[dict[str, Any]],
) -> dict[str, Any]:
    timestamp = rfc3339(epoch)
    invocation_input = canonical_json(
        {
            "commit": commit,
            "epoch": epoch,
            "materials": input_materials,
            "version": version,
        }
    )
    return {
        "_type": IN_TOTO_STATEMENT,
        "predicate": {
            "buildDefinition": {
                "buildType": BUILD_TYPE,
                "externalParameters": {
                    "acceptance": ["AC-SEC-003"],
                    "sourceDateEpoch": epoch,
                    "workspaceVersion": version,
                },
                "internalParameters": {},
                "resolvedDependencies": [
                    {
                        "digest": {"gitCommit": commit},
                        "uri": f"git+local://omnius@{commit}",
                    },
                    *input_materials,
                ],
            },
            "runDetails": {
                "builder": {"id": BUILDER_ID},
                "byproducts": [
                    {
                        "digest": {"sha256": sha256_bytes(sbom_bytes)},
                        "name": "sbom.cdx.json",
                    }
                ],
                "metadata": {
                    "finishedOn": timestamp,
                    "invocationId": f"sha256:{sha256_bytes(invocation_input)}",
                    "startedOn": timestamp,
                },
            },
        },
        "predicateType": SLSA_PROVENANCE,
        "subject": [
            {"digest": {"sha256": sha256_bytes(sbom_bytes)}, "name": "sbom.cdx.json"}
        ],
    }


def artifact_entry(path: str, role: str, media_type: str, data: bytes) -> dict[str, Any]:
    return {
        "mediaType": media_type,
        "path": path,
        "role": role,
        "sha256": sha256_bytes(data),
        "size": len(data),
    }


def load_test_key(root: Path) -> dict[str, Any]:
    key = load_json_file(root / KEY_PATH)
    if not isinstance(key, dict):
        fail("test public key descriptor must be an object")
    try:
        public_key = base64.b64decode(key["publicKey"]["value"], validate=True)
    except (KeyError, TypeError, ValueError, binascii.Error) as error:
        fail(f"test public key descriptor is invalid: {error}")
    if (
        key.get("schemaVersion") != 1
        or key.get("algorithm") != "Ed25519"
        or key.get("keyUsage") != "test-only"
        or key.get("keyId") != EXPECTED_KEY_ID
        or key.get("publicKey", {}).get("encoding") != "base64"
        or public_key != EXPECTED_PUBLIC_KEY
        or hashlib.sha256(public_key).hexdigest() not in EXPECTED_KEY_ID
    ):
        fail("test public key descriptor does not match the pinned RFC 8032 key")
    return key


def pem(label: str, der: bytes) -> bytes:
    encoded = base64.b64encode(der).decode("ascii")
    lines = [encoded[index : index + 64] for index in range(0, len(encoded), 64)]
    return (f"-----BEGIN {label}-----\n" + "\n".join(lines) + f"\n-----END {label}-----\n").encode()


def private_test_key_pem() -> bytes:
    prefix = bytes.fromhex("302e020100300506032b657004220420")
    return pem("PRIVATE KEY", prefix + RFC8032_TEST_SEED)


def public_test_key_pem() -> bytes:
    prefix = bytes.fromhex("302a300506032b6570032100")
    return pem("PUBLIC KEY", prefix + EXPECTED_PUBLIC_KEY)


def openssl(args: list[str], root: Path) -> None:
    try:
        completed = subprocess.run(
            ["openssl", *args],
            cwd=root,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
    except OSError as error:
        fail(f"cannot execute openssl: {error}")
    if completed.returncode != 0:
        detail = completed.stderr.decode("utf-8", "replace").strip()
        fail(f"OpenSSL Ed25519 operation failed: {detail or f'exit {completed.returncode}'}")


def sign_bytes(data: bytes, root: Path) -> bytes:
    with tempfile.TemporaryDirectory(prefix="omnius-test-signing-") as temporary:
        directory = Path(temporary)
        key_path = directory / "test-key.pem"
        input_path = directory / "input"
        signature_path = directory / "signature"
        write_bytes(key_path, private_test_key_pem(), 0o600)
        write_bytes(input_path, data, 0o600)
        openssl(
            [
                "pkeyutl",
                "-sign",
                "-rawin",
                "-inkey",
                str(key_path),
                "-in",
                str(input_path),
                "-out",
                str(signature_path),
            ],
            root,
        )
        signature = signature_path.read_bytes()
    if len(signature) != 64:
        fail("OpenSSL returned an invalid Ed25519 signature length")
    return signature


def verify_signature_bytes(data: bytes, signature: bytes, root: Path) -> None:
    if len(signature) != 64:
        raise VerificationError("Ed25519 signature must be exactly 64 bytes")
    with tempfile.TemporaryDirectory(prefix="omnius-test-verification-") as temporary:
        directory = Path(temporary)
        key_path = directory / "test-public-key.pem"
        input_path = directory / "input"
        signature_path = directory / "signature"
        write_bytes(key_path, public_test_key_pem(), 0o600)
        write_bytes(input_path, data, 0o600)
        write_bytes(signature_path, signature, 0o600)
        try:
            openssl(
                [
                    "pkeyutl",
                    "-verify",
                    "-rawin",
                    "-pubin",
                    "-inkey",
                    str(key_path),
                    "-in",
                    str(input_path),
                    "-sigfile",
                    str(signature_path),
                ],
                root,
            )
        except ReleaseBundleError as error:
            raise VerificationError("Ed25519 signature verification failed") from error


def signature_descriptor(path: str, data: bytes, signature: bytes) -> dict[str, Any]:
    return {
        "algorithm": "Ed25519",
        "keyId": EXPECTED_KEY_ID,
        "keyUsage": "test-only",
        "mediaType": SIGNATURE_MEDIA_TYPE,
        "schemaVersion": 1,
        "signature": {
            "encoding": "base64",
            "value": base64.b64encode(signature).decode("ascii"),
        },
        "signed": {"path": path, "sha256": sha256_bytes(data), "size": len(data)},
    }


def create_archive(bundle: Path, archive: Path, epoch: int) -> None:
    with archive.open("wb") as raw:
        with gzip.GzipFile(filename="", mode="wb", fileobj=raw, compresslevel=9, mtime=epoch) as compressed:
            with tarfile.open(fileobj=compressed, mode="w", format=tarfile.GNU_FORMAT) as tar:
                for name in INNER_FILES:
                    data = (bundle / name).read_bytes()
                    info = tarfile.TarInfo(name=f"release-bundle/{name}")
                    info.size = len(data)
                    info.mode = 0o644
                    info.mtime = epoch
                    info.uid = 0
                    info.gid = 0
                    info.uname = ""
                    info.gname = ""
                    tar.addfile(info, io.BytesIO(data))
    archive.chmod(0o644)


def reject_secret_material(root: Path, paths: list[Path]) -> None:
    forbidden = [
        b"-----BEGIN PRIVATE KEY-----",
        PRIVATE_SEED_HEX,
        PRIVATE_SEED_B64,
        str(root.resolve()).encode(),
        str(Path.home().resolve()).encode(),
    ]
    for path in paths:
        data = path.read_bytes()
        for marker in forbidden:
            if marker and marker in data:
                fail(f"generated artifact {path.name} contains forbidden private or host material")


def create_release_bundle(root: Path, output: Path, explicit_epoch: int | None = None) -> dict[str, Any]:
    load_test_key(root)
    version, cargo_toml_bytes, cargo_lock_bytes = read_workspace(root)
    metadata = cargo_metadata(root)
    epoch = source_epoch(root, explicit_epoch)
    timestamp = rfc3339(epoch)
    commit = git_value(root, "rev-parse", "HEAD").lower()
    if COMMIT_RE.fullmatch(commit) is None:
        fail("git HEAD is not a supported hexadecimal commit identifier")
    inputs = [
        material("Cargo.lock", cargo_lock_bytes),
        material("Cargo.toml", cargo_toml_bytes),
        material(KEY_PATH.as_posix(), (root / KEY_PATH).read_bytes()),
        material("scripts/release/build_bundle.py", (root / "scripts/release/build_bundle.py").read_bytes()),
        material("scripts/release/release_bundle.py", Path(__file__).read_bytes()),
    ]
    inputs.sort(key=lambda item: item["uri"])
    lock_digest = sha256_bytes(cargo_lock_bytes)
    sbom = build_sbom(metadata, lock_packages(cargo_lock_bytes), version, timestamp, lock_digest)
    sbom_bytes = canonical_json(sbom)
    provenance = build_provenance(sbom_bytes, version, commit, epoch, inputs)
    provenance_bytes = canonical_json(provenance)
    artifacts = [
        artifact_entry(
            "provenance.intoto.json",
            "build-provenance",
            "application/vnd.in-toto+json",
            provenance_bytes,
        ),
        artifact_entry(
            "sbom.cdx.json",
            "software-bill-of-materials",
            "application/vnd.cyclonedx+json; version=1.5",
            sbom_bytes,
        ),
    ]
    artifacts.sort(key=lambda item: item["path"])
    manifest = {
        "acceptance": ["AC-SEC-003"],
        "artifacts": artifacts,
        "bundleLayout": {
            "checksum": "SHA256SUMS",
            "requiredFiles": list(INNER_FILES),
            "signature": "signature.json",
        },
        "createdAt": timestamp,
        "mediaType": MEDIA_TYPE,
        "release": {"name": "omnius", "version": version},
        "schemaVersion": 1,
        "signaturePolicy": {
            "algorithm": "Ed25519",
            "keyId": EXPECTED_KEY_ID,
            "keyUsage": "test-only",
            "signedPath": "SHA256SUMS",
        },
        "source": {"commit": commit, "lockSha256": lock_digest},
    }
    manifest_bytes = canonical_json(manifest)

    output.parent.mkdir(parents=True, exist_ok=True)
    staging = Path(tempfile.mkdtemp(prefix=".release-artifacts-", dir=output.parent))
    try:
        bundle = staging / BUNDLE_DIR
        bundle.mkdir(mode=0o755)
        payloads = {
            "manifest.json": manifest_bytes,
            "provenance.intoto.json": provenance_bytes,
            "sbom.cdx.json": sbom_bytes,
        }
        for name, data in payloads.items():
            write_bytes(bundle / name, data)
        checksum_bytes = "".join(
            f"{sha256_bytes(payloads[name])}  {name}\n" for name in sorted(payloads)
        ).encode("ascii")
        write_bytes(bundle / "SHA256SUMS", checksum_bytes)
        inner_signature = sign_bytes(checksum_bytes, root)
        write_bytes(
            bundle / "signature.json",
            canonical_json(signature_descriptor("SHA256SUMS", checksum_bytes, inner_signature)),
        )
        create_archive(bundle, staging / ARCHIVE_NAME, epoch)
        archive_bytes = (staging / ARCHIVE_NAME).read_bytes()
        archive_checksum = f"{sha256_bytes(archive_bytes)}  {ARCHIVE_NAME}\n".encode("ascii")
        write_bytes(staging / ARCHIVE_CHECKSUM_NAME, archive_checksum)
        write_bytes(
            staging / ARCHIVE_SIGNATURE_NAME,
            canonical_json(
                signature_descriptor(ARCHIVE_NAME, archive_bytes, sign_bytes(archive_bytes, root))
            ),
        )
        reject_secret_material(
            root,
            [
                *(bundle / name for name in INNER_FILES),
                staging / ARCHIVE_CHECKSUM_NAME,
                staging / ARCHIVE_SIGNATURE_NAME,
            ],
        )
        if output.exists():
            if output.is_symlink() or not output.is_dir():
                fail("existing release output is not a replaceable directory")
            shutil.rmtree(output)
        os.replace(staging, output)
    except BaseException:
        if staging.exists():
            shutil.rmtree(staging)
        raise
    return manifest


def require_object(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise VerificationError(f"{label} must be a JSON object")
    return value


def require_exact_keys(value: dict[str, Any], keys: set[str], label: str) -> None:
    missing = keys - set(value)
    if missing:
        raise VerificationError(f"{label} is missing required fields: {', '.join(sorted(missing))}")


def require_sha256(value: Any, label: str) -> str:
    if not isinstance(value, str) or SHA256_RE.fullmatch(value) is None:
        raise VerificationError(f"{label} must be a lowercase SHA-256 digest")
    return value


def verify_regular_file(path: Path) -> bytes:
    try:
        metadata = path.lstat()
    except OSError as error:
        raise VerificationError(f"required file is missing: {path.name}") from error
    if not stat.S_ISREG(metadata.st_mode):
        raise VerificationError(f"required path is not a regular file: {path.name}")
    return path.read_bytes()


def parse_checksums(data: bytes, expected_paths: set[str], label: str) -> dict[str, str]:
    try:
        text = data.decode("ascii")
    except UnicodeDecodeError as error:
        raise VerificationError(f"{label} must be ASCII") from error
    if not text.endswith("\n") or "\r" in text:
        raise VerificationError(f"{label} must use canonical newline termination")
    result: dict[str, str] = {}
    for line in text.splitlines():
        match = CHECKSUM_RE.fullmatch(line)
        if match is None:
            raise VerificationError(f"{label} contains an invalid checksum line")
        digest, path = match.groups()
        if path in result:
            raise VerificationError(f"{label} contains duplicate path {path}")
        result[path] = digest
    if set(result) != expected_paths:
        raise VerificationError(f"{label} does not cover exactly the required files")
    return result


def verify_signature_descriptor(
    descriptor: Any,
    expected_path: str,
    data: bytes,
    root: Path,
) -> None:
    value = require_object(descriptor, "signature descriptor")
    require_exact_keys(
        value,
        {"algorithm", "keyId", "keyUsage", "mediaType", "schemaVersion", "signature", "signed"},
        "signature descriptor",
    )
    if (
        value.get("schemaVersion") != 1
        or value.get("mediaType") != SIGNATURE_MEDIA_TYPE
        or value.get("algorithm") != "Ed25519"
        or value.get("keyId") != EXPECTED_KEY_ID
        or value.get("keyUsage") != "test-only"
    ):
        raise VerificationError("signature descriptor policy fields are invalid")
    signed = require_object(value.get("signed"), "signature signed field")
    require_exact_keys(signed, {"path", "sha256", "size"}, "signature signed field")
    if signed.get("path") != expected_path:
        raise VerificationError("signature covers an unexpected path")
    if require_sha256(signed.get("sha256"), "signature signed sha256") != sha256_bytes(data):
        raise VerificationError("signature signed digest does not match its payload")
    if signed.get("size") != len(data):
        raise VerificationError("signature signed size does not match its payload")
    signature_field = require_object(value.get("signature"), "signature value")
    require_exact_keys(signature_field, {"encoding", "value"}, "signature value")
    if signature_field.get("encoding") != "base64" or not isinstance(signature_field.get("value"), str):
        raise VerificationError("signature value encoding is invalid")
    try:
        signature = base64.b64decode(signature_field["value"], validate=True)
    except (ValueError, binascii.Error) as error:
        raise VerificationError("signature value is not canonical base64") from error
    if base64.b64encode(signature).decode("ascii") != signature_field["value"]:
        raise VerificationError("signature value is not canonical base64")
    verify_signature_bytes(data, signature, root)


def verify_sbom(
    value: Any,
    manifest: dict[str, Any],
    lock: dict[tuple[str, str, str], dict[str, Any]],
) -> None:
    sbom = require_object(value, "SBOM")
    require_exact_keys(
        sbom,
        {"bomFormat", "components", "dependencies", "metadata", "serialNumber", "specVersion", "version"},
        "SBOM",
    )
    if sbom.get("bomFormat") != "CycloneDX" or sbom.get("specVersion") != "1.5" or sbom.get("version") != 1:
        raise VerificationError("SBOM is not CycloneDX 1.5")
    if not isinstance(sbom.get("serialNumber"), str) or not sbom["serialNumber"].startswith("urn:uuid:"):
        raise VerificationError("SBOM serialNumber is invalid")
    try:
        uuid.UUID(sbom["serialNumber"].removeprefix("urn:uuid:"))
    except ValueError as error:
        raise VerificationError("SBOM serialNumber is not a UUID") from error
    metadata = require_object(sbom.get("metadata"), "SBOM metadata")
    require_exact_keys(metadata, {"component", "timestamp", "tools"}, "SBOM metadata")
    if metadata.get("timestamp") != manifest.get("createdAt"):
        raise VerificationError("SBOM timestamp does not match the manifest")
    release = require_object(manifest.get("release"), "manifest release")
    root_ref = package_purl("omnius", release["version"])
    root_component = require_object(metadata.get("component"), "SBOM root component")
    if root_component != {
        "bom-ref": root_ref,
        "group": "dev.omnius",
        "name": release.get("name"),
        "type": "application",
        "version": release.get("version"),
    }:
        raise VerificationError("SBOM root component does not match the release")
    if metadata.get("tools") != {
        "components": [
            {
                "name": "local-release-bundle",
                "supplier": {"name": "Omnius"},
                "type": "application",
                "version": "1",
            }
        ]
    }:
        raise VerificationError("SBOM generator identity is invalid")

    components = sbom.get("components")
    dependencies = sbom.get("dependencies")
    if not isinstance(components, list) or len(components) != len(lock):
        raise VerificationError("SBOM component count does not match Cargo.lock")
    if not isinstance(dependencies, list) or len(dependencies) != len(lock) + 1:
        raise VerificationError("SBOM dependency graph is incomplete")
    expected_by_ref = {component_ref(key): key for key in lock}
    expected_order = [component_ref(key) for key in sorted(lock)]
    actual_order: list[str] = []
    for component in components:
        item = require_object(component, "SBOM component")
        require_exact_keys(
            item,
            {"bom-ref", "name", "properties", "purl", "type", "version"},
            "SBOM component",
        )
        ref = item.get("bom-ref")
        if not isinstance(ref, str) or ref not in expected_by_ref or ref in actual_order:
            raise VerificationError("SBOM component reference is unknown or duplicated")
        name, version, source = expected_by_ref[ref]
        if (
            item.get("name") != name
            or item.get("version") != version
            or item.get("purl") != package_purl(name, version)
            or item.get("type") != "library"
        ):
            raise VerificationError(f"SBOM component identity does not match Cargo.lock: {name} {version}")
        checksum = lock[(name, version, source)].get("checksum")
        if checksum is not None and item.get("hashes") != [{"alg": "SHA-256", "content": checksum}]:
            raise VerificationError(f"SBOM component checksum does not match Cargo.lock: {name} {version}")
        properties = item.get("properties")
        if not isinstance(properties, list):
            raise VerificationError("SBOM component properties are invalid")
        source_properties = [
            entry
            for entry in properties
            if isinstance(entry, dict) and entry.get("name") == "omnius:cargo:source-kind"
        ]
        workspace_properties = [
            entry
            for entry in properties
            if isinstance(entry, dict) and entry.get("name") == "omnius:cargo:workspace-member"
        ]
        if source_properties != [
            {"name": "omnius:cargo:source-kind", "value": source_kind(source)}
        ] or workspace_properties not in (
            [{"name": "omnius:cargo:workspace-member", "value": "true"}],
            [{"name": "omnius:cargo:workspace-member", "value": "false"}],
        ):
            raise VerificationError("SBOM component source properties are invalid")
        actual_order.append(ref)
    if actual_order != expected_order:
        raise VerificationError("SBOM components are not in deterministic Cargo.lock order")

    by_name: dict[str, list[tuple[str, str, str]]] = {}
    for key in lock:
        by_name.setdefault(key[0], []).append(key)
    expected_edges: dict[str, list[str]] = {}
    for key, package in lock.items():
        raw_dependencies = package.get("dependencies", [])
        expected_edges[component_ref(key)] = sorted(
            component_ref(resolve_lock_dependency(item, by_name)) for item in raw_dependencies
        )
    expected_edges[root_ref] = sorted(component_ref(key) for key in lock if key[2] == "")
    actual_edges: dict[str, list[str]] = {}
    for dependency in dependencies:
        item = require_object(dependency, "SBOM dependency")
        require_exact_keys(item, {"dependsOn", "ref"}, "SBOM dependency")
        ref = item.get("ref")
        depends_on = item.get("dependsOn")
        if not isinstance(ref, str) or ref in actual_edges:
            raise VerificationError("SBOM dependency references must be unique strings")
        if (
            not isinstance(depends_on, list)
            or not all(isinstance(child, str) for child in depends_on)
            or depends_on != sorted(set(depends_on))
        ):
            raise VerificationError("SBOM dependency edges are not deterministic unique strings")
        actual_edges[ref] = depends_on
    if actual_edges != expected_edges:
        raise VerificationError("SBOM dependency graph does not match Cargo.lock")


def verify_provenance(
    root: Path,
    value: Any,
    manifest: dict[str, Any],
    sbom_bytes: bytes,
) -> None:
    provenance = require_object(value, "provenance")
    require_exact_keys(provenance, {"_type", "predicate", "predicateType", "subject"}, "provenance")
    if provenance.get("_type") != IN_TOTO_STATEMENT or provenance.get("predicateType") != SLSA_PROVENANCE:
        raise VerificationError("provenance statement type is invalid")
    expected_subject = [{"digest": {"sha256": sha256_bytes(sbom_bytes)}, "name": "sbom.cdx.json"}]
    if provenance.get("subject") != expected_subject:
        raise VerificationError("provenance subject does not bind the SBOM")
    predicate = require_object(provenance.get("predicate"), "provenance predicate")
    require_exact_keys(predicate, {"buildDefinition", "runDetails"}, "provenance predicate")
    definition = require_object(predicate.get("buildDefinition"), "provenance buildDefinition")
    require_exact_keys(
        definition,
        {"buildType", "externalParameters", "internalParameters", "resolvedDependencies"},
        "provenance buildDefinition",
    )
    if definition.get("buildType") != BUILD_TYPE or definition.get("internalParameters") != {}:
        raise VerificationError("provenance build definition is invalid")
    parameters = require_object(definition.get("externalParameters"), "provenance externalParameters")
    require_exact_keys(
        parameters,
        {"acceptance", "sourceDateEpoch", "workspaceVersion"},
        "provenance externalParameters",
    )
    release = require_object(manifest.get("release"), "manifest release")
    epoch = parameters.get("sourceDateEpoch")
    if (
        parameters.get("acceptance") != ["AC-SEC-003"]
        or parameters.get("workspaceVersion") != release.get("version")
        or not isinstance(epoch, int)
        or epoch < 0
        or epoch > 4_294_967_295
    ):
        raise VerificationError("provenance external parameters are invalid")
    if rfc3339(epoch) != manifest.get("createdAt"):
        raise VerificationError("provenance source date epoch does not match manifest")

    source = require_object(manifest.get("source"), "manifest source")
    try:
        current_commit = git_value(root, "rev-parse", "HEAD").lower()
    except ReleaseBundleError as error:
        raise VerificationError(str(error)) from error
    if source.get("commit") != current_commit:
        raise VerificationError("provenance source commit does not match the current checkout")
    input_materials = [
        material("Cargo.lock", (root / "Cargo.lock").read_bytes()),
        material("Cargo.toml", (root / "Cargo.toml").read_bytes()),
        material(KEY_PATH.as_posix(), (root / KEY_PATH).read_bytes()),
        material(
            "scripts/release/build_bundle.py",
            (root / "scripts/release/build_bundle.py").read_bytes(),
        ),
        material("scripts/release/release_bundle.py", Path(__file__).read_bytes()),
    ]
    input_materials.sort(key=lambda item: item["uri"])
    expected_dependencies = [
        {
            "digest": {"gitCommit": source.get("commit")},
            "uri": f"git+local://omnius@{source.get('commit')}",
        },
        *input_materials,
    ]
    if definition.get("resolvedDependencies") != expected_dependencies:
        raise VerificationError("provenance materials do not match the current release inputs")

    run_details = require_object(predicate.get("runDetails"), "provenance runDetails")
    require_exact_keys(run_details, {"builder", "byproducts", "metadata"}, "provenance runDetails")
    if run_details.get("builder") != {"id": BUILDER_ID}:
        raise VerificationError("provenance builder identity is invalid")
    expected_byproducts = [
        {
            "digest": {"sha256": sha256_bytes(sbom_bytes)},
            "name": "sbom.cdx.json",
        }
    ]
    if run_details.get("byproducts") != expected_byproducts:
        raise VerificationError("provenance byproducts do not bind the SBOM")
    run_metadata = require_object(run_details.get("metadata"), "provenance run metadata")
    require_exact_keys(
        run_metadata,
        {"finishedOn", "invocationId", "startedOn"},
        "provenance run metadata",
    )
    if (
        run_metadata.get("startedOn") != manifest.get("createdAt")
        or run_metadata.get("finishedOn") != manifest.get("createdAt")
    ):
        raise VerificationError("provenance timestamps do not match manifest")
    expected_invocation = sha256_bytes(
        canonical_json(
            {
                "commit": source.get("commit"),
                "epoch": epoch,
                "materials": input_materials,
                "version": release.get("version"),
            }
        )
    )
    if run_metadata.get("invocationId") != f"sha256:{expected_invocation}":
        raise VerificationError("provenance invocationId does not match its inputs")


def verify_manifest(value: Any, payloads: dict[str, bytes]) -> dict[str, Any]:
    manifest = require_object(value, "manifest")
    require_exact_keys(
        manifest,
        {
            "acceptance",
            "artifacts",
            "bundleLayout",
            "createdAt",
            "mediaType",
            "release",
            "schemaVersion",
            "signaturePolicy",
            "source",
        },
        "manifest",
    )
    if manifest.get("schemaVersion") != 1 or manifest.get("mediaType") != MEDIA_TYPE:
        raise VerificationError("manifest schema fields are invalid")
    if manifest.get("acceptance") != ["AC-SEC-003"]:
        raise VerificationError("manifest acceptance linkage is invalid")
    if not isinstance(manifest.get("createdAt"), str):
        raise VerificationError("manifest createdAt is missing")
    try:
        dt.datetime.strptime(manifest["createdAt"], "%Y-%m-%dT%H:%M:%SZ")
    except ValueError as error:
        raise VerificationError("manifest createdAt is not canonical UTC") from error
    release = require_object(manifest.get("release"), "manifest release")
    if release.get("name") != "omnius" or not isinstance(release.get("version"), str) or not release["version"]:
        raise VerificationError("manifest release identity is invalid")
    source = require_object(manifest.get("source"), "manifest source")
    if not isinstance(source.get("commit"), str) or COMMIT_RE.fullmatch(source["commit"]) is None:
        raise VerificationError("manifest source commit is invalid")
    require_sha256(source.get("lockSha256"), "manifest lockSha256")
    layout = require_object(manifest.get("bundleLayout"), "manifest bundleLayout")
    if (
        layout.get("requiredFiles") != list(INNER_FILES)
        or layout.get("checksum") != "SHA256SUMS"
        or layout.get("signature") != "signature.json"
    ):
        raise VerificationError("manifest bundle layout is invalid")
    policy = require_object(manifest.get("signaturePolicy"), "manifest signaturePolicy")
    if policy != {
        "algorithm": "Ed25519",
        "keyId": EXPECTED_KEY_ID,
        "keyUsage": "test-only",
        "signedPath": "SHA256SUMS",
    }:
        raise VerificationError("manifest signature policy is invalid")
    artifacts = manifest.get("artifacts")
    if not isinstance(artifacts, list) or len(artifacts) != 2:
        raise VerificationError("manifest must index exactly SBOM and provenance artifacts")
    expected = {
        "provenance.intoto.json": ("build-provenance", "application/vnd.in-toto+json"),
        "sbom.cdx.json": (
            "software-bill-of-materials",
            "application/vnd.cyclonedx+json; version=1.5",
        ),
    }
    seen: set[str] = set()
    for artifact in artifacts:
        item = require_object(artifact, "manifest artifact")
        require_exact_keys(item, {"mediaType", "path", "role", "sha256", "size"}, "manifest artifact")
        path = item.get("path")
        if path not in expected or path in seen:
            raise VerificationError("manifest artifact path is unexpected or duplicated")
        role, media_type = expected[path]
        data = payloads[path]
        if (
            item.get("role") != role
            or item.get("mediaType") != media_type
            or item.get("size") != len(data)
            or require_sha256(item.get("sha256"), "manifest artifact sha256") != sha256_bytes(data)
        ):
            raise VerificationError(f"manifest artifact metadata does not match {path}")
        seen.add(path)
    if seen != set(expected):
        raise VerificationError("manifest does not index all required artifacts")
    return manifest


def verify_no_forbidden_material(root: Path, payloads: list[bytes]) -> None:
    markers = [
        b"-----BEGIN PRIVATE KEY-----",
        PRIVATE_SEED_HEX,
        PRIVATE_SEED_B64,
        str(root.resolve()).encode(),
        str(Path.home().resolve()).encode(),
    ]
    for data in payloads:
        if any(marker and marker in data for marker in markers):
            raise VerificationError("bundle contains private signing or host-specific material")


def verify_inner_bundle(root: Path, bundle: Path) -> dict[str, Any]:
    if bundle.is_symlink() or not bundle.is_dir():
        raise VerificationError("bundle directory is missing or is not a real directory")
    names = {entry.name for entry in bundle.iterdir()}
    if names != set(INNER_FILES):
        raise VerificationError("bundle directory does not contain exactly the required files")
    payloads = {name: verify_regular_file(bundle / name) for name in INNER_FILES}
    verify_no_forbidden_material(root, list(payloads.values()))
    checksums = parse_checksums(payloads["SHA256SUMS"], set(CORE_FILES), "SHA256SUMS")
    for name in CORE_FILES:
        if checksums[name] != sha256_bytes(payloads[name]):
            raise VerificationError(f"checksum mismatch for {name}")
    signature = load_json_bytes(payloads["signature.json"], "signature.json")
    verify_signature_descriptor(signature, "SHA256SUMS", payloads["SHA256SUMS"], root)
    manifest_value = load_json_bytes(payloads["manifest.json"], "manifest.json")
    manifest = verify_manifest(manifest_value, payloads)
    try:
        lock = lock_packages((root / "Cargo.lock").read_bytes())
    except ReleaseBundleError as error:
        raise VerificationError(str(error)) from error
    sbom_value = load_json_bytes(payloads["sbom.cdx.json"], "sbom.cdx.json")
    verify_sbom(sbom_value, manifest, lock)
    provenance_value = load_json_bytes(payloads["provenance.intoto.json"], "provenance.intoto.json")
    verify_provenance(root, provenance_value, manifest, payloads["sbom.cdx.json"])
    if manifest["source"]["lockSha256"] != sha256_file(root / "Cargo.lock"):
        raise VerificationError("bundle was not built from the current Cargo.lock")
    return manifest


def verify_archive(root: Path, output: Path, bundle: Path, epoch: int) -> None:
    archive = output / ARCHIVE_NAME
    archive_bytes = verify_regular_file(archive)
    if (
        len(archive_bytes) < 10
        or archive_bytes[:3] != b"\x1f\x8b\x08"
        or archive_bytes[3] != 0
        or int.from_bytes(archive_bytes[4:8], "little") != epoch
    ):
        raise VerificationError("release archive gzip header is not deterministic")
    checksum_bytes = verify_regular_file(output / ARCHIVE_CHECKSUM_NAME)
    checksums = parse_checksums(checksum_bytes, {ARCHIVE_NAME}, ARCHIVE_CHECKSUM_NAME)
    if checksums[ARCHIVE_NAME] != sha256_bytes(archive_bytes):
        raise VerificationError("release archive checksum mismatch")
    signature = load_json_file(output / ARCHIVE_SIGNATURE_NAME)
    verify_signature_descriptor(signature, ARCHIVE_NAME, archive_bytes, root)
    expected_members = {f"release-bundle/{name}" for name in INNER_FILES}
    try:
        with tarfile.open(archive, mode="r:gz") as tar:
            members = tar.getmembers()
            if {member.name for member in members} != expected_members or len(members) != len(expected_members):
                raise VerificationError("release archive member set is invalid")
            for member in members:
                if (
                    not member.isfile()
                    or member.uid != 0
                    or member.gid != 0
                    or member.uname != ""
                    or member.gname != ""
                    or member.mode != 0o644
                    or member.mtime != epoch
                ):
                    raise VerificationError(f"release archive metadata is not deterministic for {member.name}")
                extracted = tar.extractfile(member)
                if extracted is None:
                    raise VerificationError(f"cannot read release archive member {member.name}")
                expected = (bundle / member.name.removeprefix("release-bundle/")).read_bytes()
                if extracted.read() != expected:
                    raise VerificationError(f"release archive member differs from bundle: {member.name}")
    except (tarfile.TarError, OSError) as error:
        raise VerificationError(f"release archive is invalid: {error}") from error


def verify_release_bundle(root: Path, output: Path) -> dict[str, Any]:
    load_test_key(root)
    try:
        metadata = output.lstat()
    except OSError as error:
        raise VerificationError(f"release output does not exist: {output}") from error
    if not stat.S_ISDIR(metadata.st_mode) or output.is_symlink():
        raise VerificationError("release output is not a real directory")
    names = {entry.name for entry in output.iterdir()}
    if names != set(OUTPUT_FILES):
        raise VerificationError("release output does not contain exactly the required paths")
    manifest = verify_inner_bundle(root, output / BUNDLE_DIR)
    parameters = load_json_file(output / BUNDLE_DIR / "provenance.intoto.json")["predicate"]["buildDefinition"]["externalParameters"]
    verify_archive(root, output, output / BUNDLE_DIR, parameters["sourceDateEpoch"])
    return manifest


def run_tamper_probes(root: Path, output: Path) -> None:
    with tempfile.TemporaryDirectory(prefix="omnius-release-tamper-") as temporary:
        tampered = Path(temporary) / "content"
        shutil.copytree(output, tampered)
        sbom = tampered / BUNDLE_DIR / "sbom.cdx.json"
        data = sbom.read_bytes()
        if not data:
            raise VerificationError("cannot tamper-test an empty SBOM")
        write_bytes(sbom, bytes([data[0] ^ 1]) + data[1:])
        try:
            verify_release_bundle(root, tampered)
        except VerificationError:
            pass
        else:
            raise VerificationError("content tamper probe was not detected")

        tampered_signature = Path(temporary) / "signature"
        shutil.copytree(output, tampered_signature)
        signature_path = tampered_signature / BUNDLE_DIR / "signature.json"
        descriptor = load_json_file(signature_path)
        signature = bytearray(base64.b64decode(descriptor["signature"]["value"], validate=True))
        signature[0] ^= 1
        descriptor["signature"]["value"] = base64.b64encode(signature).decode("ascii")
        write_bytes(signature_path, canonical_json(descriptor))
        try:
            verify_release_bundle(root, tampered_signature)
        except VerificationError:
            pass
        else:
            raise VerificationError("signature tamper probe was not detected")

#!/usr/bin/env python3
"""Reject unapproved secret files and cryptographic key material."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tomllib

REPOSITORY = Path(__file__).resolve().parent.parent
EXEMPTIONS = Path(__file__).with_name("material-exemptions.toml")
GITLEAKS_CONFIG = Path(__file__).with_name("gitleaks.toml")
OPENSSL = shutil.which("openssl")
SENSITIVE_NAMES = frozenset(
    {
        ".env",
        ".gitleaksignore",
        ".npmrc",
        ".pypirc",
        "credentials.json",
        "credentials.toml",
        "credentials.yaml",
        "credentials.yml",
        "id_dsa",
        "id_ecdsa",
        "id_ed25519",
        "id_rsa",
        "secrets.json",
        "secrets.toml",
        "secrets.yaml",
        "secrets.yml",
        "service-account.json",
    }
)
ENV_TEMPLATES = frozenset({".env.example", ".env.sample", ".env.template"})
SENSITIVE_SUFFIXES = frozenset(
    {
        ".cer",
        ".crt",
        ".der",
        ".jks",
        ".kdb",
        ".kdbx",
        ".key",
        ".gpg",
        ".keystore",
        ".p12",
        ".pem",
        ".pgp",
        ".pfx",
    }
)
PRIVATE_MARKERS = tuple(
    marker.encode("ascii")
    for marker in (
        "-----BEGIN " + "PRIVATE KEY-----",
        "-----BEGIN RSA " + "PRIVATE KEY-----",
        "-----BEGIN DSA " + "PRIVATE KEY-----",
        "-----BEGIN EC " + "PRIVATE KEY-----",
        "-----BEGIN ENCRYPTED " + "PRIVATE KEY-----",
        "-----BEGIN OPENSSH " + "PRIVATE KEY-----",
        "-----BEGIN PGP " + "PRIVATE KEY BLOCK-----",
        "-----BEGIN AGE " + "ENCRYPTED FILE-----",
    )
)
CHUNK_SIZE = 128 * 1024
MARKER_OVERLAP = max(map(len, PRIVATE_MARKERS)) - 1
GITLEAKS_REGEX_ALLOWLISTS = frozenset(
    {
        (
            "Cargo workspace member false positive",
            "secret",
            (r"^crates/billing$",),
        ),
        (
            "Public SHA-256 pin for the RFC8032 test fixture",
            "secret",
            (r"^c4932a9b6b97423b249a53e58d706f820185467464699038ed7ca5b29815ba03$",),
        ),
    }
)


@dataclass(frozen=True)
class Exemption:
    sha256: frozenset[str]
    reason: str
    scope: str


def tracked_files() -> list[Path]:
    if (REPOSITORY / ".gitleaksignore").exists():
        raise ValueError(".gitleaksignore is prohibited; exemptions are centralized")
    if OPENSSL is None:
        raise ValueError("material policy requires openssl")
    shallow = subprocess.run(
        ["git", "rev-parse", "--is-shallow-repository"],
        cwd=REPOSITORY,
        check=True,
        stdout=subprocess.PIPE,
        text=True,
    )
    if shallow.stdout.strip() != "false":
        raise ValueError("material policy requires a complete Git history")
    result = subprocess.run(
        ["git", "ls-files", "--cached", "-z"],
        cwd=REPOSITORY,
        check=True,
        stdout=subprocess.PIPE,
    )
    paths = result.stdout.decode("utf-8", errors="surrogateescape").split("\0")
    return [REPOSITORY / path for path in paths if path]


def configured_exemptions() -> dict[str, Exemption]:
    document = tomllib.loads(EXEMPTIONS.read_text(encoding="utf-8"))
    configured: dict[str, Exemption] = {}
    for entry in document.get("exemptions", []):
        path = entry.get("path")
        digests = entry.get("sha256")
        reason = entry.get("reason")
        scope = entry.get("scope")
        if not isinstance(path, str) or path.startswith("/") or ".." in Path(path).parts:
            raise ValueError("every material exemption needs a repository-relative path")
        if "tests" not in Path(path).parts and "test" not in Path(path).parts:
            raise ValueError(f"material exemption is outside a test fixture path: {path}")
        if (
            not isinstance(digests, list)
            or not digests
            or len(digests) != len(set(digests))
            or any(
                not isinstance(digest, str)
                or len(digest) != 64
                or any(character not in "0123456789abcdef" for character in digest)
                for digest in digests
            )
        ):
            raise ValueError(f"invalid SHA-256 list for material exemption: {path}")
        if not isinstance(reason, str) or not reason.strip():
            raise ValueError(f"missing material exemption reason: {path}")
        if scope != "test-only":
            raise ValueError(f"material exemption is not test-only: {path}")
        if path in configured:
            raise ValueError(f"duplicate material exemption: {path}")
        configured[path] = Exemption(frozenset(digests), reason, scope)
    validate_gitleaks_allowlists(configured.keys())
    return configured


def validate_gitleaks_allowlists(exempt_paths: object) -> None:
    document = tomllib.loads(GITLEAKS_CONFIG.read_text(encoding="utf-8"))
    if set(document) != {"title", "extend", "allowlists"}:
        raise ValueError("gitleaks config may contain only title, extend, and allowlists")
    if not isinstance(document["title"], str) or not document["title"].strip():
        raise ValueError("gitleaks config needs a title")
    if document["extend"] != {"useDefault": True}:
        raise ValueError("gitleaks config must enable the unmodified default rules")
    allowlists = document.get("allowlists", [])
    if not isinstance(allowlists, list):
        raise ValueError("gitleaks allowlists must be an array")

    actual_patterns: set[str] = set()
    actual_regex_allowlists: set[tuple[str, str, tuple[str, ...]]] = set()
    for allowlist in allowlists:
        if not isinstance(allowlist, dict):
            raise ValueError("gitleaks allowlists must be tables")
        description = allowlist.get("description")
        if not isinstance(description, str) or not description.strip():
            raise ValueError("gitleaks allowlist needs a description")
        if set(allowlist) == {"description", "paths"}:
            paths = allowlist["paths"]
            if (
                not isinstance(paths, list)
                or not paths
                or not all(isinstance(path, str) for path in paths)
            ):
                raise ValueError("gitleaks allowlist paths must be a non-empty string array")
            actual_patterns.update(paths)
            continue
        if set(allowlist) == {"description", "regexTarget", "regexes"}:
            regex_target = allowlist["regexTarget"]
            regexes = allowlist["regexes"]
            if (
                not isinstance(regex_target, str)
                or not isinstance(regexes, list)
                or not regexes
                or not all(isinstance(regex, str) for regex in regexes)
            ):
                raise ValueError("gitleaks regex allowlists need a target and non-empty regex array")
            identity = (description, regex_target, tuple(regexes))
            if identity in actual_regex_allowlists:
                raise ValueError("duplicate gitleaks regex allowlist")
            actual_regex_allowlists.add(identity)
            continue
        raise ValueError("unsupported gitleaks allowlist fields")

    expected_patterns = {f"^{re.escape(path)}$" for path in exempt_paths}
    if actual_patterns != expected_patterns:
        raise ValueError(
            "gitleaks path allowlists must exactly match hash-locked material exemptions"
        )
    if actual_regex_allowlists != GITLEAKS_REGEX_ALLOWLISTS:
        raise ValueError("gitleaks regex allowlists must exactly match approved false positives")


def contains_private_marker(path: Path) -> bool:
    overlap = b""
    with path.open("rb") as source:
        while chunk := source.read(CHUNK_SIZE):
            window = overlap + chunk
            if any(marker in window for marker in PRIVATE_MARKERS):
                return True
            overlap = window[-MARKER_OVERLAP:]
    return False


def read_der_tlv(source: object, offset: int, limit: int) -> tuple[int, int, int] | None:
    if offset < 0 or offset + 2 > limit:
        return None
    source.seek(offset)
    header = source.read(2)
    if len(header) != 2:
        return None
    tag, first_length = header
    if first_length < 0x80:
        content_offset = offset + 2
        content_length = first_length
    else:
        length_bytes = first_length & 0x7F
        if length_bytes == 0 or length_bytes > 8 or offset + 2 + length_bytes > limit:
            return None
        encoded_length = source.read(length_bytes)
        if len(encoded_length) != length_bytes or encoded_length[0] == 0:
            return None
        content_offset = offset + 2 + length_bytes
        content_length = int.from_bytes(encoded_length)
    end_offset = content_offset + content_length
    if end_offset > limit:
        return None
    return tag, content_offset, end_offset


def contains_der_private_key(path: Path) -> bool:
    size = path.stat().st_size
    with path.open("rb") as source:
        outer = read_der_tlv(source, 0, size)
        if outer is None or outer[0] != 0x30 or outer[2] != size:
            return False

        algorithm = read_der_tlv(source, outer[1], outer[2])
        if algorithm is not None and algorithm[0] == 0x30:
            algorithm_oid = read_der_tlv(source, algorithm[1], algorithm[2])
            encrypted_data = read_der_tlv(source, algorithm[2], outer[2])
            if (
                algorithm_oid is not None
                and algorithm_oid[0] == 0x06
                and encrypted_data is not None
                and encrypted_data[0] == 0x04
                and encrypted_data[2] == outer[2]
            ):
                return True

    result = subprocess.run(
        [OPENSSL, "pkey", "-inform", "DER", "-in", path, "-noout", "-passin", "pass:"],
        check=False,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        timeout=5,
    )
    return result.returncode == 0

def binary_key_container(path: Path) -> str | None:
    size = path.stat().st_size
    with path.open("rb") as source:
        magic = source.read(8)
        if magic[:4] == bytes.fromhex("feedfeed"):
            return "JKS key store"
        if magic[:4] == bytes.fromhex("cececece"):
            return "JCEKS key store"
        if magic in {
            bytes.fromhex("03d9a29a65fb4bb5"),
            bytes.fromhex("03d9a29a67fb4bb5"),
        }:
            return "KeePass key database"

        outer = read_der_tlv(source, 0, size)
        if outer is None or outer[0] != 0x30 or outer[2] != size:
            return None
        version = read_der_tlv(source, outer[1], outer[2])
        if version is None or version[0] != 0x02 or version[2] - version[1] != 1:
            return None
        source.seek(version[1])
        if source.read(1) != b"\x03":
            return None
        auth_safe = read_der_tlv(source, version[2], outer[2])
        if auth_safe is None or auth_safe[0] != 0x30:
            return None
        content_type = read_der_tlv(source, auth_safe[1], auth_safe[2])
        if (
            content_type is None
            or content_type[0] != 0x06
            or content_type[2] - content_type[1] > 32
        ):
            return None
        source.seek(content_type[1])
        oid = source.read(content_type[2] - content_type[1])
        if oid.startswith(bytes.fromhex("2a864886f70d0107")):
            return "PKCS#12 key container"
    return None


def read_openpgp_length(source: object) -> tuple[int, bool] | None:
    encoded = source.read(1)
    if len(encoded) != 1:
        return None
    first = encoded[0]
    if first < 192:
        return first, False
    if first < 224:
        second = source.read(1)
        if len(second) != 1:
            return None
        return ((first - 192) << 8) + second[0] + 192, False
    if first == 255:
        length = source.read(4)
        if len(length) != 4:
            return None
        return int.from_bytes(length), False
    return 1 << (first & 0x1F), True


def contains_openpgp_secret_key(path: Path) -> bool:
    size = path.stat().st_size
    with path.open("rb") as source:
        while source.tell() < size:
            encoded_tag = source.read(1)
            if len(encoded_tag) != 1 or encoded_tag[0] & 0x80 == 0:
                return False

            if encoded_tag[0] & 0x40:
                packet_tag = encoded_tag[0] & 0x3F
                encoded_length = read_openpgp_length(source)
                if encoded_length is None:
                    return False
                body_length, partial = encoded_length
                body_offset = source.tell()
                if body_offset + body_length > size:
                    return False
                if packet_tag in {5, 7} and body_length > 0:
                    version = source.read(1)
                    if len(version) == 1 and version[0] in {3, 4, 5, 6}:
                        return True
                    source.seek(body_offset)
                source.seek(body_offset + body_length)
                while partial:
                    encoded_length = read_openpgp_length(source)
                    if encoded_length is None:
                        return False
                    body_length, partial = encoded_length
                    if source.tell() + body_length > size:
                        return False
                    source.seek(body_length, 1)
                continue

            packet_tag = (encoded_tag[0] >> 2) & 0x0F
            length_type = encoded_tag[0] & 0x03
            length_size = (1, 2, 4, 0)[length_type]
            if length_size == 0:
                body_length = size - source.tell()
            else:
                encoded_length = source.read(length_size)
                if len(encoded_length) != length_size:
                    return False
                body_length = int.from_bytes(encoded_length)
            body_offset = source.tell()
            if body_offset + body_length > size:
                return False
            if packet_tag in {5, 7} and body_length > 0:
                version = source.read(1)
                if len(version) == 1 and version[0] in {3, 4, 5, 6}:
                    return True
                source.seek(body_offset)
            source.seek(body_offset + body_length)
            if length_size == 0:
                return False
    return False


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        while chunk := source.read(CHUNK_SIZE):
            digest.update(chunk)
    return digest.hexdigest()

def historical_blob_digests(path: str) -> set[str]:
    objects = subprocess.run(
        ["git", "rev-list", "--objects", "--all", "--", path],
        cwd=REPOSITORY,
        check=True,
        stdout=subprocess.PIPE,
        text=True,
    )
    object_ids = {
        fields[0]
        for line in objects.stdout.splitlines()
        if len(fields := line.split(" ", maxsplit=1)) == 2 and fields[1] == path
    }
    digests: set[str] = set()
    for object_id in object_ids:
        blob = subprocess.run(
            ["git", "cat-file", "blob", object_id],
            cwd=REPOSITORY,
            check=True,
            stdout=subprocess.PIPE,
        )
        digests.add(hashlib.sha256(blob.stdout).hexdigest())
    return digests


def findings(path: Path) -> list[str]:
    categories: list[str] = []
    name = path.name.lower()
    if name in SENSITIVE_NAMES or (name.startswith(".env.") and name not in ENV_TEMPLATES):
        categories.append("sensitive filename")
    if path.suffix.lower() in SENSITIVE_SUFFIXES:
        categories.append("cryptographic material file extension")
    if path.is_file() and not path.is_symlink():
        if contains_private_marker(path):
            categories.append("private cryptographic material")
        if contains_der_private_key(path):
            categories.append("DER private key material")
        if contains_openpgp_secret_key(path):
            categories.append("binary OpenPGP secret-key material")
        if container := binary_key_container(path):
            categories.append(container)
    return categories


def main() -> int:
    try:
        exemptions = configured_exemptions()
        files = tracked_files()
    except (
        OSError,
        subprocess.CalledProcessError,
        tomllib.TOMLDecodeError,
        TypeError,
        ValueError,
    ) as error:
        print(f"material policy error: {error}", file=sys.stderr)
        return 1

    used: set[str] = set()
    failures: list[str] = []
    finding_count = 0
    for path in files:
        relative = path.relative_to(REPOSITORY).as_posix()
        try:
            categories = findings(path)
        except (OSError, subprocess.TimeoutExpired) as error:
            failures.append(f"cannot inspect {relative}: {error}")
            continue
        exemption = exemptions.get(relative)
        if exemption is not None and not categories:
            categories.append("explicitly allowlisted test fixture")
        if not categories:
            continue
        finding_count += 1
        if exemption is None:
            failures.append(f"{relative}: {', '.join(categories)}")
            continue
        try:
            actual_digest = sha256(path)
            history_digests = historical_blob_digests(relative)
        except (OSError, subprocess.CalledProcessError) as error:
            failures.append(f"cannot verify exempt material {relative}: {error}")
            continue
        if actual_digest not in exemption.sha256:
            failures.append(
                f"exempt material changed: {relative} (found {actual_digest})"
            )
            continue
        unexpected_history = history_digests - exemption.sha256
        if unexpected_history:
            failures.append(
                f"unapproved historical material at {relative}: "
                f"{', '.join(sorted(unexpected_history))}"
            )
            continue
        used.add(relative)

    for path in sorted(exemptions.keys() - used):
        failures.append(f"stale material exemption: {path}")

    if failures:
        print("material policy failed:", file=sys.stderr)
        print("\n".join(f"- {failure}" for failure in failures), file=sys.stderr)
        return 1

    print(
        f"material policy passed: {len(files)} tracked files checked, "
        f"{finding_count} hash-locked test fixture exemption(s)"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

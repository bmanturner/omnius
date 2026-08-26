#!/usr/bin/env python3
from __future__ import annotations

import argparse
import sys
from pathlib import Path
sys.dont_write_bytecode = True


from release_bundle import (
    ReleaseBundleError,
    VerificationError,
    ensure_output_path,
    repository_root,
    run_tamper_probes,
    verify_release_bundle,
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(prog="verify_bundle.py")
    parser.add_argument(
        "--bundle",
        type=Path,
        default=Path("target/release-artifacts"),
        help="artifact directory under target/",
    )
    parser.add_argument(
        "--skip-tamper-probes",
        action="store_true",
        help="verify the bundle without exercising isolated content and signature tamper probes",
    )
    return parser.parse_args()


def main() -> int:
    arguments = parse_args()
    root = repository_root()
    try:
        bundle = ensure_output_path(root, arguments.bundle)
        manifest = verify_release_bundle(root, bundle)
        if not arguments.skip_tamper_probes:
            run_tamper_probes(root, bundle)
    except (ReleaseBundleError, VerificationError) as error:
        print(f"release bundle verification failed: {error}", file=sys.stderr)
        return 1
    suffix = " with tamper probes" if not arguments.skip_tamper_probes else ""
    print(
        f"verified {bundle.relative_to(root)} for "
        f"{manifest['release']['name']} {manifest['release']['version']}{suffix}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

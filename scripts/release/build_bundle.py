#!/usr/bin/env python3
from __future__ import annotations

import argparse
import sys
from pathlib import Path
sys.dont_write_bytecode = True


from release_bundle import ReleaseBundleError, create_release_bundle, ensure_output_path, repository_root


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(prog="build_bundle.py")
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("target/release-artifacts"),
        help="artifact directory under target/",
    )
    parser.add_argument(
        "--source-date-epoch",
        type=int,
        help="deterministic timestamp; defaults to SOURCE_DATE_EPOCH or the HEAD commit timestamp",
    )
    return parser.parse_args()


def main() -> int:
    arguments = parse_args()
    root = repository_root()
    output = ensure_output_path(root, arguments.output)
    try:
        manifest = create_release_bundle(root, output, arguments.source_date_epoch)
    except ReleaseBundleError as error:
        print(f"release bundle build failed: {error}", file=sys.stderr)
        return 1
    print(f"created {output.relative_to(root)} for {manifest['release']['name']} {manifest['release']['version']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

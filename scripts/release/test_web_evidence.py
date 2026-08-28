from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent))

import jsonschema

import web_evidence


class WebEvidenceProducerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="omnius-web-evidence-")
        self.root = Path(self.temporary.name)
        (self.root / "specs/machine").mkdir(parents=True)
        (self.root / "specs/example.md").write_text("example\n", encoding="utf-8")
        contents = (self.root / "specs/example.md").read_bytes()
        (self.root / "specs/machine/spec-manifest.json").write_text(
            json.dumps(
                {
                    "schema_version": 1,
                    "bundle_version": "test",
                    "documents": [
                        {
                            "spec_id": "TEST-001",
                            "path": "example.md",
                            "bytes": len(contents),
                            "sha256": web_evidence.sha256_bytes(contents),
                        }
                    ],
                }
            ),
            encoding="utf-8",
        )
        (self.root / "contracts").mkdir()
        (self.root / "contracts/contract-manifest.json").write_text(
            json.dumps({"aggregate_sha256": "c" * 64}), encoding="utf-8"
        )
        (self.root / "Cargo.toml").write_text("[workspace]\n", encoding="utf-8")
        (self.root / "package.json").write_text("{}\n", encoding="utf-8")
        self.environment = patch.dict(
            "os.environ",
            {
                "OMNIUS_RELEASE_RUN_ID": "test-run-1",
                "OMNIUS_RELEASE_REVISION": "a" * 40,
            },
            clear=False,
        )
        self.environment.start()

    def tearDown(self) -> None:
        self.environment.stop()
        self.temporary.cleanup()

    def load(self, relative: str) -> dict[str, object]:
        return json.loads((self.root / relative).read_text(encoding="utf-8"))

    def validate_schema(self, relative: str, schema_name: str) -> None:
        repository = Path(__file__).resolve().parents[2]
        schema = json.loads((repository / "release" / schema_name).read_text(encoding="utf-8"))
        jsonschema.Draft202012Validator(schema).validate(self.load(relative))

    def test_current_command_result_produces_valid_schema_v2_evidence(self) -> None:
        command = [
            sys.executable,
            "-c",
            "from pathlib import Path; Path('target/proof.json').parent.mkdir(parents=True, exist_ok=True); Path('target/proof.json').write_text('proof')",
        ]
        exit_code = web_evidence.main(
            [
                "run",
                "--result-id",
                "focused-check",
                "--output",
                "target/inputs/focused.json",
                "--retain-artifact",
                "target/proof.json=target/retained/proof.json",
                "--",
                *command,
            ],
            root=self.root,
        )
        self.assertEqual(exit_code, 0)
        self.validate_schema(
            "target/inputs/focused.json", "web-release-command-result.schema.json"
        )
        self.assertTrue((self.root / "target/retained/proof.json").is_file())

        exit_code = web_evidence.main(
            [
                "produce",
                "--evidence-id",
                "focused-evidence",
                "--output",
                "target/evidence/focused.json",
                "--result",
                "target/inputs/focused.json",
            ],
            root=self.root,
        )
        self.assertEqual(exit_code, 0)
        self.validate_schema("target/evidence/focused.json", "web-release-evidence.schema.json")
        self.assertEqual(self.load("target/evidence/focused.json")["status"], "passed")

    def test_missing_command_result_is_rejected_without_evidence(self) -> None:
        exit_code = web_evidence.main(
            [
                "produce",
                "--evidence-id",
                "focused-evidence",
                "--output",
                "target/evidence/focused.json",
                "--result",
                "target/inputs/missing.json",
            ],
            root=self.root,
        )
        self.assertEqual(exit_code, 2)
        self.assertFalse((self.root / "target/evidence/focused.json").exists())

    def test_failed_command_produces_failed_schema_v2_evidence(self) -> None:
        exit_code = web_evidence.main(
            [
                "run",
                "--result-id",
                "failing-check",
                "--output",
                "target/inputs/failed.json",
                "--",
                sys.executable,
                "-c",
                "raise SystemExit(7)",
            ],
            root=self.root,
        )
        self.assertEqual(exit_code, 7)
        self.validate_schema(
            "target/inputs/failed.json", "web-release-command-result.schema.json"
        )
        self.assertEqual(self.load("target/inputs/failed.json")["status"], "failed")

        exit_code = web_evidence.main(
            [
                "produce",
                "--evidence-id",
                "failed-evidence",
                "--output",
                "target/evidence/failed.json",
                "--result",
                "target/inputs/failed.json",
            ],
            root=self.root,
        )
        self.assertEqual(exit_code, 0)
        self.validate_schema("target/evidence/failed.json", "web-release-evidence.schema.json")
        self.assertEqual(self.load("target/evidence/failed.json")["status"], "failed")

    def test_successful_command_missing_declared_artifact_is_failed(self) -> None:
        exit_code = web_evidence.main(
            [
                "run",
                "--result-id",
                "missing-output",
                "--output",
                "target/inputs/missing-output.json",
                "--artifact",
                "target/never-created.json",
                "--",
                sys.executable,
                "-c",
                "print('completed without its required output')",
            ],
            root=self.root,
        )
        self.assertEqual(exit_code, 1)
        self.validate_schema(
            "target/inputs/missing-output.json", "web-release-command-result.schema.json"
        )
        self.assertEqual(self.load("target/inputs/missing-output.json")["status"], "failed")


if __name__ == "__main__":
    unittest.main()

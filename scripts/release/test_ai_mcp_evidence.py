from __future__ import annotations

import json
import runpy
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))


import ai_mcp_evidence

LLM_MCP_VALIDATOR = runpy.run_path(
    str(Path(__file__).resolve().parents[2] / "specs" / "tools" / "validate_llm_mcp_feature_suite.py")
)


class AiMcpEvidenceTests(unittest.TestCase):
    @staticmethod
    def matrix() -> dict[str, object]:
        checks = [
            {
                "name": name,
                "required": True,
                "executed": True,
                "status": "passed",
                "success": True,
            }
            for name in sorted(ai_mcp_evidence.BASE_MATRIX_CHECKS)
        ]
        return {
            "matrix_success": True,
            "profiles": [
                {"profile": profile, "success": True, "checks": checks}
                for profile in ai_mcp_evidence.AI_PROFILE_IDS
            ],
        }

    def test_exact_nine_profiles_pass_required_matrix(self) -> None:
        profiles = ai_mcp_evidence.validate_profile_matrix(self.matrix())
        self.assertEqual(
            [profile["id"] for profile in profiles],
            list(ai_mcp_evidence.AI_PROFILE_IDS),
        )
        self.assertTrue(all(profile["status"] == "passed" for profile in profiles))

    def test_runtime_profile_coverage_excludes_tooling_modules(self) -> None:
        modules = [
            {"id": "llm-core", "kind": "kernel"},
            {"id": "llm-http-api", "kind": "feature"},
            {"id": "llm-evals", "kind": "tooling"},
            {"id": "mcp-conformance", "kind": "tooling"},
        ]

        self.assertEqual(
            LLM_MCP_VALIDATOR["application_profile_module_ids"](modules),
            {"llm-core", "llm-http-api"},
        )

    def test_missing_profile_is_rejected(self) -> None:
        matrix = self.matrix()
        matrix["profiles"] = matrix["profiles"][:-1]
        with self.assertRaisesRegex(ai_mcp_evidence.EvidenceError, "omits AI/MCP profiles"):
            ai_mcp_evidence.validate_profile_matrix(matrix)

    def test_skipped_base_matrix_check_is_rejected(self) -> None:
        matrix = self.matrix()
        matrix["profiles"][0]["checks"][0]["required"] = False
        matrix["profiles"][0]["checks"][0]["executed"] = False
        matrix["profiles"][0]["checks"][0]["status"] = "skipped"
        matrix["profiles"][0]["checks"][0]["success"] = False
        with self.assertRaisesRegex(ai_mcp_evidence.EvidenceError, "base matrix check"):
            ai_mcp_evidence.validate_profile_matrix(matrix)


    def test_command_argv_must_be_exact(self) -> None:
        ai_mcp_evidence.validate_result_command(
            "ai-architecture-validation",
            {"argv": ["cargo", "xtask", "ai", "verify"]},
        )
        with self.assertRaisesRegex(ai_mcp_evidence.EvidenceError, "unexpected command"):
            ai_mcp_evidence.validate_result_command(
                "ai-architecture-validation",
                {"argv": ["./cargo", "xtask", "ai", "verify"]},
            )
        with self.assertRaisesRegex(ai_mcp_evidence.EvidenceError, "unexpected command"):
            ai_mcp_evidence.validate_result_command(
                "ai-architecture-validation",
                {"argv": ["/usr/bin/true", "cargo", "xtask", "ai", "verify"]},
            )

    def test_repository_task_catalog_is_append_only_through_t179(self) -> None:
        repository = Path(__file__).resolve().parents[2]
        task_count, prerequisite_count = ai_mcp_evidence.validate_append_only_tasks(repository)
        self.assertEqual(task_count, 30)
        self.assertGreater(prerequisite_count, 6)

    def test_repository_bundles_extract_without_portable_collisions(self) -> None:
        repository = Path(__file__).resolve().parents[2]
        self.assertGreater(ai_mcp_evidence.rehearse_clean_extraction(repository), 200)

    def test_clean_extraction_detects_collisions(self) -> None:
        with tempfile.TemporaryDirectory(prefix="omnius-ai-evidence-test-") as temporary:
            root = Path(temporary)
            specs = root / "specs"
            specs.mkdir()
            manifests = (
                "MANIFEST.json",
                "WEB_FEATURE_SUITE_MANIFEST.json",
                "LLM_MCP_FEATURE_SUITE_MANIFEST.json",
            )
            checksums = (
                "SHA256SUMS",
                "WEB_FEATURE_SUITE_SHA256SUMS",
                "LLM_MCP_FEATURE_SUITE_SHA256SUMS",
            )
            for checksum in checksums:
                (specs / checksum).write_text("checksum\n", encoding="utf-8")
            for index, manifest in enumerate(manifests):
                relative = f"bundle-{index}.txt"
                (specs / relative).write_text(relative, encoding="utf-8")
                (specs / manifest).write_text(
                    json.dumps({"files": [{"path": relative}]}), encoding="utf-8"
                )
            self.assertEqual(ai_mcp_evidence.rehearse_clean_extraction(root), 9)
            (specs / manifests[0]).write_text(
                json.dumps({"files": [{"path": "WEB_FEATURE_SUITE_MANIFEST.json"}]}),
                encoding="utf-8",
            )
            with self.assertRaisesRegex(ai_mcp_evidence.EvidenceError, "collision"):
                ai_mcp_evidence.rehearse_clean_extraction(root)
            (specs / manifests[0]).write_text(
                json.dumps({"files": [{"path": "bundle-0.txt"}]}), encoding="utf-8"
            )
            symlink = specs / "linked.txt"
            symlink.symlink_to("bundle-0.txt")
            (specs / manifests[-1]).write_text(
                json.dumps({"files": [{"path": "linked.txt"}]}), encoding="utf-8"
            )
            with self.assertRaisesRegex(ai_mcp_evidence.EvidenceError, "unsafe"):
                ai_mcp_evidence.rehearse_clean_extraction(root)
            outside = root / "outside"
            outside.mkdir()
            (outside / "secret.txt").write_text("secret", encoding="utf-8")
            (specs / "linked-directory").symlink_to(outside, target_is_directory=True)
            (specs / manifests[-1]).write_text(
                json.dumps({"files": [{"path": "linked-directory/secret.txt"}]}),
                encoding="utf-8",
            )
            with self.assertRaisesRegex(ai_mcp_evidence.EvidenceError, "unsafe"):
                ai_mcp_evidence.rehearse_clean_extraction(root)

            (specs / manifests[-1]).write_text(
                json.dumps({"files": [{"path": "..\\\\outside"}]}), encoding="utf-8"
            )
            with self.assertRaisesRegex(ai_mcp_evidence.EvidenceError, "unsafe path"):
                ai_mcp_evidence.rehearse_clean_extraction(root)
            nested = specs / "nested"
            nested.mkdir()
            (nested / "file.txt").write_text("nested", encoding="utf-8")
            (specs / manifests[0]).write_text(
                json.dumps({"files": [{"path": "nested/file.txt"}]}), encoding="utf-8"
            )
            (specs / manifests[1]).write_text(
                json.dumps({"files": [{"path": "nested//file.txt"}]}), encoding="utf-8"
            )
            with self.assertRaisesRegex(ai_mcp_evidence.EvidenceError, "unsafe path"):
                ai_mcp_evidence.rehearse_clean_extraction(root)

            (specs / manifests[0]).write_text(
                json.dumps({"files": [{"path": "bundle-0.txt"}]}), encoding="utf-8"
            )

            (specs / manifests[1]).write_text(
                json.dumps({"files": [{"path": "BUNDLE-0.TXT"}]}), encoding="utf-8"
            )
            (specs / manifests[-1]).write_text(
                json.dumps({"files": [{"path": "bundle-2.txt"}]}), encoding="utf-8"
            )
            with self.assertRaisesRegex(ai_mcp_evidence.EvidenceError, "collision"):
                ai_mcp_evidence.rehearse_clean_extraction(root)

            (specs / manifests[1]).write_text(
                json.dumps({"files": [{"path": "bundle-1.txt"}]}), encoding="utf-8"
            )

            (specs / manifests[-1]).write_text(
                json.dumps({"files": [{"path": "bundle-0.txt"}]}), encoding="utf-8"
            )
            with self.assertRaisesRegex(ai_mcp_evidence.EvidenceError, "collision"):
                ai_mcp_evidence.rehearse_clean_extraction(root)

    def test_schema_requires_eight_release_criteria(self) -> None:
        repository = Path(__file__).resolve().parents[2]
        schema = json.loads(
            (repository / "release/ai-mcp-release-evidence.schema.json").read_text(
                encoding="utf-8"
            )
        )
        artifact = {"path": "proof.json", "sha256": "a" * 64}
        document = {
            "schemaVersion": 1,
            "evidenceId": "ai-mcp-release-readiness",
            "status": "passed",
            "generatedAt": "2026-01-01T00:00:00Z",
            "binding": {
                "runId": "run-1",
                "revision": "b" * 40,
                "specManifestSha256": "c" * 64,
                "contractAggregateSha256": "d" * 64,
            },
            "profiles": [
                {"id": profile, "status": "passed", "checks": ["cargo-test"]}
                for profile in ai_mcp_evidence.AI_PROFILE_IDS
            ],
            "criteria": [
                {
                    "id": f"AC-AI-{number:03d}",
                    "status": "passed",
                    "detail": "verified",
                    "artifacts": [artifact],
                }
                for number in range(113, 121)
            ],
        }
        self.assertEqual(schema["properties"]["profiles"]["minItems"], 9)
        self.assertEqual(schema["properties"]["criteria"]["minItems"], 8)
        ai_mcp_evidence.validate_document(document)
        document["criteria"].pop()
        with self.assertRaisesRegex(ai_mcp_evidence.EvidenceError, "exactly AC-AI"):
            ai_mcp_evidence.validate_document(document)

        ai_mcp_evidence.validate_runbook(repository / "release/ai-mcp-suite-runbook.md")


if __name__ == "__main__":
    unittest.main()

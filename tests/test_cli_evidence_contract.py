from __future__ import annotations

import ast
import hashlib
import json
import tomllib
import unittest
from pathlib import Path
from typing import cast

PROJECT_ROOT = Path(__file__).resolve().parents[1]
CLI_ROOT = PROJECT_ROOT / "docs" / "cli-evidence"
FIXTURE_PATH = CLI_ROOT / "fixtures" / "cli-demo.v1.jsonl"
GENERATOR_PATH = PROJECT_ROOT / "scripts" / "render_cli_evidence.py"
CONTRACT_PATH = PROJECT_ROOT / "docs" / "portable-receipt-contract.md"
WORKFLOW_PATH = PROJECT_ROOT / ".github" / "workflows" / "ci.yml"
REQUIREMENTS_PATH = PROJECT_ROOT / "requirements" / "cli-visuals.txt"
NOTICES_PATH = PROJECT_ROOT / "THIRD_PARTY_NOTICES.md"
MANIFEST_PATH = PROJECT_ROOT / "MANIFEST.in"

FIXTURE_SHA256 = "a77c90ed5e767a4e0a8029cad14ed347354a3b939b62ad75c0da091b522a259f"
PILLOW_SHA256 = "78cb2c6865a35ab8ff8b75fd122f6033b92a62c82801110e48ddd6c936a45d91"
UPLOAD_ARTIFACT_SHA = "043fb46d1a93c77aae656e7c1c64a875d1fc6a0a"
CANDIDATE_OUTPUTS = (
    "docs/cli-evidence/evidence/cli-evidence.v1.json",
    "docs/cli-evidence/evidence/cli-demo.receipt.v1.json",
    "docs/cli-evidence/cli-transcript.png",
    "docs/cli-evidence/cli-demo.gif",
    "docs/cli-evidence/cli-result.svg",
    "docs/cli-evidence/cli-workflow.svg",
)
FIXTURE_RECORDS = (
    ("ascii-a", "A"),
    ("ascii-k", "K"),
    ("eszett", "\u00df"),
    ("fullwidth-a", "\uff21"),
    ("kelvin-sign", "\u212a"),
    ("lower-ss", "ss"),
    ("upper-ss", "SS"),
)


def _object(value: object) -> dict[str, object]:
    if type(value) is not dict:
        raise TypeError("expected a JSON object")
    return cast(dict[str, object], value)


class CliEvidenceCandidateContractTests(unittest.TestCase):
    def test_reviewed_fixture_is_exact_synthetic_corpus(self) -> None:
        fixture = FIXTURE_PATH.read_bytes()
        self.assertEqual(hashlib.sha256(fixture).hexdigest(), FIXTURE_SHA256)
        self.assertEqual(len(fixture), 384)
        self.assertTrue(fixture.isascii())
        self.assertTrue(fixture.endswith(b"\n"))

        lines = fixture.decode("ascii").splitlines()
        self.assertEqual(len(lines), 8)
        header = _object(json.loads(lines[0]))
        self.assertEqual(
            header,
            {
                "schema": "casefold-observatory.identifier-corpus",
                "schema_version": 1,
            },
        )
        records = tuple(
            (
                cast(str, _object(json.loads(line))["record_id"]),
                cast(str, _object(json.loads(line))["identifier"]),
            )
            for line in lines[1:]
        )
        self.assertEqual(records, FIXTURE_RECORDS)

    def test_renderer_contract_is_static_without_importing_pillow(self) -> None:
        source = GENERATOR_PATH.read_text(encoding="utf-8")
        compile(source, GENERATOR_PATH.as_posix(), "exec")
        module = ast.parse(source)
        imports = {
            alias.name.split(".", 1)[0]
            for node in ast.walk(module)
            if isinstance(node, ast.Import)
            for alias in node.names
        }
        imports.update(
            node.module.split(".", 1)[0]
            for node in ast.walk(module)
            if isinstance(node, ast.ImportFrom) and node.module is not None
        )

        self.assertTrue({"PIL", "subprocess"}.issubset(imports))
        self.assertTrue(
            imports.isdisjoint({"http", "requests", "socket", "urllib", "webbrowser"})
        )
        self.assertNotIn("shell=True", source)
        self.assertNotIn("datetime", imports)
        self.assertIn('EXPECTED_PYTHON: Final = "3.12.3"', source)
        self.assertIn('EXPECTED_UNICODE: Final = "15.0.0"', source)
        self.assertIn('EXPECTED_PILLOW: Final = "12.3.0"', source)
        self.assertIn("runtime_files", source)
        self.assertIn("runtime_tree_sha256", source)
        self.assertNotIn("wheel_sha256", source)
        self.assertNotIn("CONTRACT_PATH", source)
        for output in CANDIDATE_OUTPUTS:
            self.assertIn(f'"{output}"', source)

    def test_stage_one_keeps_candidate_bytes_out_of_repository(self) -> None:
        actual_files = {
            path.relative_to(PROJECT_ROOT).as_posix()
            for path in CLI_ROOT.rglob("*")
            if path.is_file()
        }
        self.assertEqual(
            actual_files,
            {"docs/cli-evidence/fixtures/cli-demo.v1.jsonl"},
        )
        for output in CANDIDATE_OUTPUTS:
            self.assertFalse((PROJECT_ROOT / output).exists())

    def test_capture_environment_and_two_stage_gate_are_documented(self) -> None:
        contract = CONTRACT_PATH.read_text(encoding="utf-8")
        self.assertIn("## CLI visual-evidence candidate and adoption gates", contract)
        self.assertIn(FIXTURE_SHA256, contract)
        self.assertIn("exact CPython 3.12.3", contract)
        self.assertIn("Unicode database 15.0.0", contract)
        self.assertIn("Pillow 12.3.0", contract)
        self.assertIn(PILLOW_SHA256, contract)
        self.assertIn("exactly six files", contract)
        self.assertIn("deliberately does not hash itself", contract)
        self.assertIn("single-link mode-0600", contract)
        self.assertIn("regular `100644` repository file", contract)
        self.assertIn("Stage two must download that hosted artifact", contract)
        self.assertIn("verified rasterized CLI transcript", contract)
        for output in CANDIDATE_OUTPUTS:
            self.assertIn(f"`{output}`", contract)

    def test_visual_dependency_is_hash_locked_and_not_runtime(self) -> None:
        requirements = REQUIREMENTS_PATH.read_text(encoding="utf-8")
        self.assertEqual(
            requirements,
            (
                "# Canonical CLI visual renderer only: CPython 3.12, Linux x86_64.\n"
                "# Not installed by, or declared as a runtime dependency of, the "
                "package.\n"
                "Pillow==12.3.0 \\\n"
                f"    --hash=sha256:{PILLOW_SHA256}\n"
            ),
        )

        pyproject = tomllib.loads(
            (PROJECT_ROOT / "pyproject.toml").read_text(encoding="utf-8")
        )
        project = _object(pyproject["project"])
        self.assertEqual(project["dependencies"], [])

        notices = NOTICES_PATH.read_text(encoding="utf-8")
        self.assertIn("no runtime dependencies", notices)
        self.assertIn("included in its wheel", notices)
        self.assertIn("Pillow 12.3.0", notices)
        self.assertIn(PILLOW_SHA256, notices)
        self.assertIn("Aileron Regular", notices)
        self.assertIn("No Rights Reserved", notices)

    def test_hosted_candidate_uses_explicit_head_and_exact_uploader(self) -> None:
        workflow = WORKFLOW_PATH.read_text(encoding="utf-8")
        self.assertIn("cli-evidence-candidate:", workflow)
        self.assertIn(
            "SOURCE_REVISION: ${{ github.event.pull_request.head.sha || github.sha }}",
            workflow,
        )
        self.assertIn("ref: ${{ env.SOURCE_REVISION }}", workflow)
        self.assertIn('test "$(git rev-parse HEAD)" = "$SOURCE_REVISION"', workflow)
        self.assertIn("git rev-parse HEAD^{tree}", workflow)
        self.assertIn('python-version: "3.12.3"', workflow)
        self.assertEqual(
            workflow.count("scripts/render_cli_evidence.py render"),
            2,
        )
        self.assertEqual(
            workflow.count("scripts/render_cli_evidence.py compare"),
            1,
        )
        self.assertIn(f"actions/upload-artifact@{UPLOAD_ARTIFACT_SHA}", workflow)
        self.assertIn("name: case-cli-evidence-candidate", workflow)
        self.assertIn("compression-level: 0", workflow)
        self.assertIn("git status --porcelain --untracked-files=all", workflow)

    def test_source_distribution_contract_carries_candidate_sources_only(self) -> None:
        manifest = MANIFEST_PATH.read_text(encoding="utf-8")
        for required in (
            "include THIRD_PARTY_NOTICES.md",
            "include requirements/cli-visuals.txt",
            "include scripts/render_cli_evidence.py",
            "recursive-include docs/cli-evidence *.gif *.json *.jsonl *.md *.png *.svg",
        ):
            self.assertIn(required, manifest)
        self.assertNotIn("docs/cli-evidence/evidence/cli-evidence.v1.json", manifest)


if __name__ == "__main__":
    unittest.main()

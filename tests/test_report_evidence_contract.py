from __future__ import annotations

import ast
import hashlib
import json
import unittest
from pathlib import Path
from typing import cast

PROJECT_ROOT = Path(__file__).resolve().parents[1]
FIXTURE_PATH = (
    PROJECT_ROOT / "docs" / "report-evidence" / "fixtures" / "report-demo.v1.jsonl"
)
GENERATOR_PATH = PROJECT_ROOT / "scripts" / "render_report_evidence.py"
VERIFIER_PATH = PROJECT_ROOT / "scripts" / "verify_report_evidence.py"
WORKFLOW_PATH = PROJECT_ROOT / ".github" / "workflows" / "report-evidence.yml"
REQUIREMENTS_PATH = PROJECT_ROOT / "requirements" / "report-browser.txt"
IMAGE_LOCK_PATH = PROJECT_ROOT / "requirements" / "report-browser-image.lock.json"
MANIFEST_TEMPLATE_PATH = PROJECT_ROOT / "MANIFEST.in"
README_PATH = PROJECT_ROOT / "README.md"
SECURITY_PATH = PROJECT_ROOT / "SECURITY.md"
CONTRACT_PATH = PROJECT_ROOT / "docs" / "portable-receipt-contract.md"
REPORT_IMPLEMENTATION_PATH = PROJECT_ROOT / "src" / "casefold_observatory" / "report.py"
EVIDENCE_MANIFEST_PATH = (
    PROJECT_ROOT / "docs" / "report-evidence" / "evidence" / "report-evidence.v1.json"
)

FIXTURE_SHA256 = "58c4b868820471fcb67a42351d7bddbfbcc66bfd4b2165d4e9868390787991cf"
PLATFORM_DIGEST = (
    "sha256:51d31fdfacb0cff99a1a724152e34ae408d2bd4e7da310ff157450f49261cc59"
)
INDEX_DIGEST = "sha256:aa81288e738725378becba5b3e06cb0f3a7f012a610e87e8d767a090ea3f740d"
OUTPUT_PATHS = (
    "docs/report-evidence/evidence/report-evidence.v1.json",
    "docs/report-evidence/evidence/report-demo.receipt.v1.json",
    "docs/report-evidence/evidence/report-demo.v1.html",
    "docs/report-evidence/report-desktop.png",
    "docs/report-evidence/report-mobile.png",
    "docs/report-evidence/report-full-page.png",
    "docs/report-evidence/report-scroll.gif",
    "docs/report-evidence/report-architecture.svg",
)


def _object(value: object) -> dict[str, object]:
    if type(value) is not dict:
        raise TypeError("expected object")
    return cast(dict[str, object], value)


class ReportEvidenceContractTests(unittest.TestCase):
    def test_fixture_is_exact_ascii_synthetic_unicode_spectrum(self) -> None:
        payload = FIXTURE_PATH.read_bytes()
        self.assertTrue(payload.isascii())
        self.assertTrue(payload.endswith(b"\n"))
        self.assertEqual(hashlib.sha256(payload).hexdigest(), FIXTURE_SHA256)
        lines = payload.decode("ascii").splitlines()
        self.assertEqual(len(lines), 13)
        header = _object(json.loads(lines[0]))
        self.assertEqual(
            header,
            {
                "schema": "casefold-observatory.identifier-corpus",
                "schema_version": 1,
            },
        )
        records = tuple(_object(json.loads(line)) for line in lines[1:])
        self.assertEqual(len(records), 12)
        identifiers = {cast(str, item["identifier"]) for item in records}
        self.assertIn("</style><script>alert(1)</script>", identifiers)
        self.assertIn("admin\u202e", identifiers)
        self.assertIn("pay\u200dpal", identifiers)
        self.assertIn("e\u0301", identifiers)
        self.assertIn("\u00e9", identifiers)

    def test_scripts_compile_and_keep_generator_and_verifier_independent(
        self,
    ) -> None:
        generator = GENERATOR_PATH.read_text(encoding="utf-8")
        verifier = VERIFIER_PATH.read_text(encoding="utf-8")
        compile(generator, GENERATOR_PATH.as_posix(), "exec")
        compile(verifier, VERIFIER_PATH.as_posix(), "exec")
        generator_tree = ast.parse(generator)
        verifier_tree = ast.parse(verifier)

        def imports(tree: ast.AST) -> set[str]:
            names: set[str] = set()
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    names.update(alias.name for alias in node.names)
                elif isinstance(node, ast.ImportFrom) and node.module is not None:
                    names.add(node.module)
            return names

        generator_imports = imports(generator_tree)
        verifier_imports = imports(verifier_tree)
        self.assertFalse(
            any(name.startswith("casefold_observatory") for name in generator_imports)
        )
        self.assertFalse(
            any(name.startswith("casefold_observatory") for name in verifier_imports)
        )
        self.assertNotIn("scripts.render_report_evidence", imports(verifier_tree))
        self.assertNotIn("playwright.sync_api import", generator)
        for path in OUTPUT_PATHS:
            self.assertIn(path, generator)
            self.assertIn(path, verifier)

    def test_workflow_is_detached_offline_and_digest_pinned(self) -> None:
        workflow = WORKFLOW_PATH.read_text(encoding="utf-8")
        self.assertIn("ubuntu-24.04", workflow)
        self.assertIn(PLATFORM_DIGEST, workflow)
        self.assertIn("ref: \x24{{ env.CHECKOUT_REVISION }}", workflow)
        self.assertIn("persist-credentials: false", workflow)
        self.assertIn("--network=none", workflow)
        self.assertIn("--read-only", workflow)
        self.assertIn("--cap-drop=ALL", workflow)
        self.assertIn("--security-opt=no-new-privileges", workflow)
        self.assertIn('--user "$(id -u):$(id -g)"', workflow)
        generator = GENERATOR_PATH.read_text(encoding="utf-8")
        self.assertIn("chromium_sandbox=True", generator)
        self.assertIn("java_script_enabled=True", generator)
        self.assertNotIn("pull_request_target", workflow)
        self.assertNotIn("--no-sandbox", workflow)
        self.assertNotIn(
            "actions/checkout@",
            workflow.replace(
                "actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1",
                "",
            ),
        )

    def test_package_and_image_inputs_are_exactly_locked(self) -> None:
        requirements = REQUIREMENTS_PATH.read_text(encoding="ascii")
        for version in (
            "greenlet==3.2.4",
            "Pillow==12.3.0",
            "playwright==1.62.0",
            "pyee==13.0.0",
            "typing-extensions==4.15.0",
        ):
            self.assertIn(version, requirements)
        self.assertEqual(requirements.count("--hash=sha256:"), 6)
        image_payload = IMAGE_LOCK_PATH.read_bytes()
        image = _object(json.loads(image_payload))
        expected = (
            json.dumps(
                image,
                ensure_ascii=True,
                allow_nan=False,
                indent=2,
                sort_keys=True,
            ).encode("ascii")
            + b"\n"
        )
        self.assertEqual(image_payload, expected)
        self.assertEqual(image["platform_manifest_digest"], PLATFORM_DIGEST)
        self.assertEqual(image["index_digest"], INDEX_DIGEST)
        self.assertEqual(image["architecture"], "amd64")
        self.assertEqual(image["os"], "linux")

    def test_distribution_and_docs_name_the_implemented_evidence(self) -> None:
        manifest = MANIFEST_TEMPLATE_PATH.read_text(encoding="utf-8")
        for required in (
            "requirements/report-browser.txt",
            "requirements/report-browser-image.lock.json",
            "scripts/render_report_evidence.py",
            "scripts/verify_report_evidence.py",
            "recursive-include docs/report-evidence",
        ):
            self.assertIn(required, manifest)
        documentation = "\n".join(
            path.read_text(encoding="utf-8")
            for path in (README_PATH, SECURITY_PATH, CONTRACT_PATH)
        )
        for phrase in (
            "casefold-observatory report",
            "mode 0600",
            "Content Security Policy",
            "Chromium",
        ):
            self.assertIn(phrase, documentation)

    def test_decoded_witness_separator_stays_ascii(self) -> None:
        source = REPORT_IMPLEMENTATION_PATH.read_text(encoding="utf-8")
        self.assertIn('" -&gt; "', source)
        self.assertNotIn("&rarr;", source)

    def test_adopted_manifest_is_self_consistent_when_present(self) -> None:
        if not EVIDENCE_MANIFEST_PATH.exists():
            self.skipTest("browser candidate has not been reviewed and adopted")
        payload = EVIDENCE_MANIFEST_PATH.read_bytes()
        manifest = _object(json.loads(payload))
        expected = (
            json.dumps(
                manifest,
                ensure_ascii=True,
                allow_nan=False,
                indent=2,
                sort_keys=True,
            ).encode("ascii")
            + b"\n"
        )
        self.assertEqual(payload, expected)
        self.assertEqual(manifest["generated_files"], list(OUTPUT_PATHS))
        artifacts = _object(manifest["artifacts"])
        for relative in OUTPUT_PATHS[1:]:
            artifact = _object(artifacts[relative])
            content = (PROJECT_ROOT / relative).read_bytes()
            self.assertEqual(artifact["bytes"], len(content))
            self.assertEqual(artifact["sha256"], hashlib.sha256(content).hexdigest())


if __name__ == "__main__":
    unittest.main()

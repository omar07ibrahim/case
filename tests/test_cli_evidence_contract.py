from __future__ import annotations

import ast
import hashlib
import importlib.util
import json
import runpy
import tomllib
import unittest
from pathlib import Path
from typing import Protocol, cast

PROJECT_ROOT = Path(__file__).resolve().parents[1]
CLI_ROOT = PROJECT_ROOT / "docs" / "cli-evidence"
FIXTURE_PATH = CLI_ROOT / "fixtures" / "cli-demo.v1.jsonl"
GENERATOR_PATH = PROJECT_ROOT / "scripts" / "render_cli_evidence.py"
PILLOW_AVAILABLE = importlib.util.find_spec("PIL") is not None
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


class _TextPlacementResult(Protocol):
    draw_position: tuple[int, int]
    ink_bounds: tuple[int, int, int, int]


class _TextPlacementFactory(Protocol):
    def __call__(
        self,
        font: object,
        value: str,
        position: tuple[int, int],
        /,
    ) -> _TextPlacementResult: ...


class _GifLayoutResult(Protocol):
    canvas_height: int
    panel_bottom: int
    footer_top: int
    footer_bottom: int
    phase_bottoms: tuple[int, ...]
    tallest_phase: int


class _GifLayoutFactory(Protocol):
    def __call__(
        self,
        line_heights_by_phase: tuple[tuple[int, ...], ...],
        *,
        footer_height: int,
    ) -> _GifLayoutResult: ...


def _renderer_namespace() -> dict[str, object]:
    return cast(dict[str, object], runpy.run_path(GENERATOR_PATH.as_posix()))


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
        self.assertNotIn(".read_bytes()", source)
        self.assertNotIn("datetime", imports)
        for boundary in (
            "os.O_NOFOLLOW",
            "os.O_CLOEXEC",
            "os.fstat",
            "maximum + 1",
            "st_mtime_ns",
            "st_ctime_ns",
            "follow_symlinks=False",
        ):
            self.assertIn(boundary, source)
        self.assertIn('EXPECTED_PYTHON: Final = "3.12.3"', source)
        self.assertIn('EXPECTED_SYSTEM: Final = "Linux"', source)
        self.assertIn('EXPECTED_MACHINE: Final = "x86_64"', source)
        self.assertIn('EXPECTED_UNICODE: Final = "15.0.0"', source)
        self.assertIn('EXPECTED_PILLOW: Final = "12.3.0"', source)
        self.assertIn("EXPECTED_PILLOW_WHEEL_SHA256", source)
        self.assertIn("EXPECTED_FONT_NAME", source)
        self.assertIn("EXPECTED_BUILD_DISTRIBUTIONS", source)
        self.assertIn("ImageFont.load_default", source)
        self.assertIn(".getname()", source)
        self.assertIn("runtime_files", source)
        self.assertIn("runtime_tree_sha256", source)
        self.assertNotIn('"wheel_bytes"', source)
        self.assertNotIn("CONTRACT_PATH", source)
        for layout_boundary in (
            "def _wrap_pixels(",
            "font.getbbox(value)",
            "draw.textbbox(placement.draw_position, value, font=font)",
            "visual transcript wrapping changed captured text",
            "visual transcript text escaped its measured bounds",
            '"png_size": [1400, 1120]',
            "def _text_placement(",
            "def _gif_layout(",
            "layout.canvas_height",
            "_text_dimensions(body_font, line)[1]",
        ):
            self.assertIn(layout_boundary, source)
        self.assertNotIn("height = 650", source)
        self.assertNotIn('"gif_size": [1200, 650]', source)
        self.assertEqual(source.count("draw.text("), 1)
        self.assertGreaterEqual(source.count("_draw_bounded_text("), 10)
        for media_boundary in (
            "png.getexif()",
            '"n_frames"',
            '"loop"',
            '"disposal_method"',
            '"dispose_extent"',
            '"transparency"',
            "decoded_frame.load()",
        ):
            self.assertIn(media_boundary, source)
        for output in CANDIDATE_OUTPUTS:
            self.assertIn(f'"{output}"', source)

    @unittest.skipUnless(PILLOW_AVAILABLE, "canonical Pillow is not installed")
    def test_text_placement_normalizes_negative_glyph_bearings(self) -> None:
        from PIL import ImageFont

        class NegativeBearingFont:
            def getbbox(self, value: str) -> tuple[int, int, int, int]:
                self_value = value
                if self_value != "j":
                    raise AssertionError("unexpected test glyph")
                return (-4, 7, 9, 22)

        namespace = _renderer_namespace()
        place_text = cast(_TextPlacementFactory, namespace["_text_placement"])
        font = cast(ImageFont.ImageFont, NegativeBearingFont())
        placement = place_text(font, "j", (100, 200))

        self.assertEqual(placement.draw_position, (104, 193))
        self.assertEqual(placement.ink_bounds, (100, 200, 113, 215))

    @unittest.skipUnless(PILLOW_AVAILABLE, "canonical Pillow is not installed")
    def test_gif_layout_selects_the_tallest_measured_phase(self) -> None:
        namespace = _renderer_namespace()
        layout_gif = cast(_GifLayoutFactory, namespace["_gif_layout"])
        footer_gap = cast(int, namespace["_GIF_TRANSCRIPT_FOOTER_GAP"])
        layout = layout_gif(
            ((11,), (8, 30, 9), (20, 20)),
            footer_height=13,
        )

        self.assertEqual(layout.phase_bottoms, (196, 248, 233))
        self.assertEqual(layout.tallest_phase, 1)
        self.assertEqual(
            layout.footer_top,
            layout.phase_bottoms[1] + footer_gap,
        )

    @unittest.skipUnless(PILLOW_AVAILABLE, "canonical Pillow is not installed")
    def test_gif_layout_preserves_exact_footer_and_canvas_gaps(self) -> None:
        namespace = _renderer_namespace()
        layout_gif = cast(_GifLayoutFactory, namespace["_gif_layout"])
        footer_gap = cast(int, namespace["_GIF_TRANSCRIPT_FOOTER_GAP"])
        panel_gap = cast(int, namespace["_GIF_FOOTER_PANEL_GAP"])
        canvas_gap = cast(int, namespace["_GIF_CANVAS_BOTTOM_GAP"])
        layout = layout_gif(((14, 13),), footer_height=12)

        self.assertEqual(
            layout.footer_top - max(layout.phase_bottoms),
            footer_gap,
        )
        self.assertEqual(
            layout.panel_bottom - layout.footer_bottom,
            panel_gap,
        )
        self.assertEqual(
            layout.canvas_height - layout.panel_bottom,
            canvas_gap,
        )

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
        self.assertIn("source commit and tree identities", contract)
        self.assertIn('("Aileron", "Regular")', contract)
        self.assertIn("actual ink\nbounding-box top-left", contract)
        self.assertIn("tallest measured phase", contract)
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
                "--only-binary=:all:\n"
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
        self.assertIn('getname()` resolves exactly to `("Aileron",', notices)
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
        self.assertIn("id: source_identity", workflow)
        self.assertIn('echo "tree=$source_tree" >> "$GITHUB_OUTPUT"', workflow)
        self.assertIn("runs-on: ubuntu-24.04", workflow)
        self.assertIn('python-version: "3.12.3"', workflow)
        self.assertEqual(workflow.count("--source-tree"), 2)
        self.assertEqual(
            workflow.count("scripts/render_cli_evidence.py render"),
            2,
        )
        self.assertEqual(
            workflow.count("scripts/render_cli_evidence.py compare"),
            1,
        )
        self.assertIn(f"actions/upload-artifact@{UPLOAD_ARTIFACT_SHA}", workflow)
        self.assertIn(
            "name: case-cli-evidence-candidate-${{ github.run_id }}-"
            "${{ github.run_attempt }}",
            workflow,
        )
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

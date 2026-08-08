from __future__ import annotations

import ast
import hashlib
import importlib.util
import json
import runpy
import stat
import tomllib
import unittest
from pathlib import Path
from typing import Protocol, cast

PROJECT_ROOT = Path(__file__).resolve().parents[1]
CLI_ROOT = PROJECT_ROOT / "docs" / "cli-evidence"
FIXTURE_PATH = CLI_ROOT / "fixtures" / "cli-demo.v1.jsonl"
GENERATOR_PATH = PROJECT_ROOT / "scripts" / "render_cli_evidence.py"
ADOPTION_PATH = "docs/cli-evidence/evidence/cli-evidence-adoption.v1.json"
PILLOW_AVAILABLE = importlib.util.find_spec("PIL") is not None
CONTRACT_PATH = PROJECT_ROOT / "docs" / "portable-receipt-contract.md"
README_PATH = PROJECT_ROOT / "README.md"
CLI_INDEX_PATH = CLI_ROOT / "README.md"
WORKFLOW_PATH = PROJECT_ROOT / ".github" / "workflows" / "ci.yml"
REQUIREMENTS_PATH = PROJECT_ROOT / "requirements" / "cli-visuals.txt"
NOTICES_PATH = PROJECT_ROOT / "THIRD_PARTY_NOTICES.md"
MANIFEST_PATH = PROJECT_ROOT / "MANIFEST.in"

FIXTURE_SHA256 = "a77c90ed5e767a4e0a8029cad14ed347354a3b939b62ad75c0da091b522a259f"
PILLOW_SHA256 = "78cb2c6865a35ab8ff8b75fd122f6033b92a62c82801110e48ddd6c936a45d91"
ARTIFACT_ARCHIVE_BYTES = 188_273
ARTIFACT_ARCHIVE_SHA256 = (
    "11c9a0d0bfd33c2b828629dd9b207a9a587a1fa907e23ec0a5d4c18d0ead90f7"
)
ARTIFACT_ID = 9_026_465_100
ARTIFACT_NAME = "case-cli-evidence-candidate-31273971052-1"
ARTIFACT_RUN_ID = 31_273_971_052
ARTIFACT_JOB_ID = 93_144_542_401
ADOPTED_SOURCE_REVISION = "b83e7a936f0b3e77ac4c2e1285b2e88dcc029741"
ADOPTED_SOURCE_TREE = "71e4f3ec9cd69ba74036601232c59e015b03a437"
ADOPTION_COMMIT = "2a83f25ca18b12469a3336341f42c58d6643a834"
ADOPTED_OUTPUTS = (
    "docs/cli-evidence/evidence/cli-evidence.v1.json",
    "docs/cli-evidence/evidence/cli-demo.receipt.v1.json",
    "docs/cli-evidence/cli-transcript.png",
    "docs/cli-evidence/cli-demo.gif",
    "docs/cli-evidence/cli-result.svg",
    "docs/cli-evidence/cli-workflow.svg",
)
ADOPTED_IDENTITIES: dict[str, dict[str, object]] = {
    "docs/cli-evidence/cli-demo.gif": {
        "bytes": 45_778,
        "sha256": "0034dccbefc08dfde3a3884162d44566664fbe80e0fc56bfef7dca9677543aea",
    },
    "docs/cli-evidence/cli-result.svg": {
        "bytes": 6_582,
        "sha256": "dba4fcad5da2303e3ccbfa6ea53709ad4d4e28201cdf5dde110bb64712c71ed2",
    },
    "docs/cli-evidence/cli-transcript.png": {
        "bytes": 109_515,
        "sha256": "e76316607fe1813661e799178645818bddfe73419ceaa179b0684be49ea9ed89",
    },
    "docs/cli-evidence/cli-workflow.svg": {
        "bytes": 9_610,
        "sha256": "96752ec5aec6465b8d25179f78573b803e026ffed81ef8623b2d1cedd68be684",
    },
    "docs/cli-evidence/evidence/cli-demo.receipt.v1.json": {
        "bytes": 6_905,
        "sha256": "f27a1e8abecfea76d9ef054ceea0bf3d38d07d246d21653ade01e65846a58ccb",
    },
    "docs/cli-evidence/evidence/cli-evidence.v1.json": {
        "bytes": 8_849,
        "sha256": "e61e48ed714c85403b032781e7d21b7ba0dc2a40a8063fa61180ee0d83829e21",
    },
}
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
        *,
        font_mode: str,
    ) -> _TextPlacementResult: ...


class _TextWidthFactory(Protocol):
    def __call__(
        self,
        font: object,
        value: str,
        /,
        *,
        font_mode: str,
    ) -> int: ...


class _FontModeFactory(Protocol):
    def __call__(self, draw: object, /) -> str: ...


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


class CliEvidenceContractTests(unittest.TestCase):
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
            "font.getbbox(value, font_mode)",
            "draw.textbbox(placement.draw_position, value, font=font)",
            "visual transcript wrapping changed captured text",
            "visual transcript text escaped its measured bounds",
            '"png_size": [1400, 1120]',
            "def _text_placement(",
            "def _font_mode_for_draw(",
            "def _gif_layout(",
            "layout.canvas_height",
            '_text_dimensions(body_font, line, font_mode="1")[1]',
            "height == 0 and not value.isspace()",
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
        for output in ADOPTED_OUTPUTS:
            self.assertIn(f'"{output}"', source)

    @unittest.skipUnless(PILLOW_AVAILABLE, "canonical Pillow is not installed")
    def test_text_placement_normalizes_negative_glyph_bearings(self) -> None:
        from PIL import ImageFont

        class NegativeBearingFont:
            def getbbox(
                self,
                value: str,
                font_mode: str,
            ) -> tuple[int, int, int, int]:
                if value != "j" or font_mode != "L":
                    raise AssertionError("unexpected test measurement")
                return (-4, 7, 9, 22)

        namespace = _renderer_namespace()
        place_text = cast(_TextPlacementFactory, namespace["_text_placement"])
        font = cast(ImageFont.ImageFont, NegativeBearingFont())
        placement = place_text(font, "j", (100, 200), font_mode="L")

        self.assertEqual(placement.draw_position, (104, 193))
        self.assertEqual(placement.ink_bounds, (100, 200, 113, 215))

    @unittest.skipUnless(PILLOW_AVAILABLE, "canonical Pillow is not installed")
    def test_text_width_accepts_a_non_inking_continuation_indent(self) -> None:
        from PIL import ImageFont

        namespace = _renderer_namespace()
        measure_width = cast(_TextWidthFactory, namespace["_text_width"])
        font = ImageFont.load_default(size=18)
        left, top, right, bottom = font.getbbox("         ", "1")

        self.assertGreater(right - left, 0)
        self.assertEqual(bottom - top, 0)
        self.assertGreater(measure_width(font, "         ", font_mode="1"), 0)

    @unittest.skipUnless(PILLOW_AVAILABLE, "canonical Pillow is not installed")
    def test_palette_draw_and_font_use_the_same_raster_mode(self) -> None:
        from PIL import Image, ImageDraw, ImageFont

        namespace = _renderer_namespace()
        choose_font_mode = cast(_FontModeFactory, namespace["_font_mode_for_draw"])
        place_text = cast(_TextPlacementFactory, namespace["_text_placement"])
        font = ImageFont.load_default(size=28)
        frame = Image.new("P", (600, 100), 0)
        draw = ImageDraw.Draw(frame)
        value = "Installed-wheel CLI evidence"
        font_mode = choose_font_mode(draw)

        self.assertEqual(font_mode, "1")
        self.assertNotEqual(font.getbbox(value), font.getbbox(value, font_mode))
        self.assertEqual(
            draw.textbbox((0, 0), value, font=font),
            font.getbbox(value, font_mode),
        )

        placement = place_text(font, value, (62, 53), font_mode=font_mode)
        self.assertEqual(
            draw.textbbox(placement.draw_position, value, font=font),
            placement.ink_bounds,
        )

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

    def test_adopted_bundle_matches_reviewed_hosted_artifact(self) -> None:
        expected_files = {
            "docs/cli-evidence/README.md",
            "docs/cli-evidence/fixtures/cli-demo.v1.jsonl",
            ADOPTION_PATH,
            *ADOPTED_OUTPUTS,
        }
        actual_files = {
            path.relative_to(PROJECT_ROOT).as_posix()
            for path in CLI_ROOT.rglob("*")
            if path.is_file()
        }
        self.assertEqual(actual_files, expected_files)

        for relative_path, expected_identity in ADOPTED_IDENTITIES.items():
            path = PROJECT_ROOT / relative_path
            self.assertFalse(path.is_symlink())
            status = path.stat()
            self.assertTrue(stat.S_ISREG(status.st_mode))
            self.assertEqual(stat.S_IMODE(status.st_mode), 0o644)
            data = path.read_bytes()
            self.assertEqual(
                {
                    "bytes": len(data),
                    "sha256": hashlib.sha256(data).hexdigest(),
                },
                expected_identity,
            )

        adoption_bytes = (PROJECT_ROOT / ADOPTION_PATH).read_bytes()
        self.assertTrue(adoption_bytes.isascii())
        adoption = _object(json.loads(adoption_bytes))
        self.assertEqual(
            adoption_bytes,
            (
                json.dumps(
                    adoption,
                    ensure_ascii=True,
                    allow_nan=False,
                    indent=2,
                    sort_keys=True,
                )
                + "\n"
            ).encode("ascii"),
        )
        self.assertEqual(
            adoption,
            {
                "artifact": {
                    "archive_bytes": ARTIFACT_ARCHIVE_BYTES,
                    "archive_sha256": ARTIFACT_ARCHIVE_SHA256,
                    "id": ARTIFACT_ID,
                    "name": ARTIFACT_NAME,
                    "run_attempt": 1,
                    "workflow_job_id": ARTIFACT_JOB_ID,
                    "workflow_run_id": ARTIFACT_RUN_ID,
                },
                "files": ADOPTED_IDENTITIES,
                "schema": "casefold-observatory.cli-evidence-adoption",
                "schema_version": 1,
                "source_revision": ADOPTED_SOURCE_REVISION,
                "source_tree": ADOPTED_SOURCE_TREE,
                "validation": {
                    "archive_entry_mode": "100644",
                    "archive_inventory_exact": True,
                    "byte_identities_match_manifest": True,
                    "media_structure_validated": True,
                    "privacy_scan_passed": True,
                    "visual_review_passed": True,
                },
            },
        )

        manifest = _object(json.loads((PROJECT_ROOT / ADOPTED_OUTPUTS[0]).read_bytes()))
        self.assertEqual(manifest["source_revision"], ADOPTED_SOURCE_REVISION)
        self.assertEqual(manifest["source_tree"], ADOPTED_SOURCE_TREE)
        self.assertEqual(manifest["artifact_inventory"], list(ADOPTED_OUTPUTS))

    def test_adopted_capture_and_review_are_documented(self) -> None:
        contract = CONTRACT_PATH.read_text(encoding="utf-8")
        self.assertIn("## Adopted CLI visual evidence", contract)
        self.assertIn(FIXTURE_SHA256, contract)
        self.assertIn("exact CPython 3.12.3", contract)
        self.assertIn("Unicode database 15.0.0", contract)
        self.assertIn("Pillow 12.3.0", contract)
        self.assertIn(PILLOW_SHA256, contract)
        self.assertIn("exactly six files", contract)
        self.assertIn("deliberately does not hash itself", contract)
        self.assertIn("single-link mode-0600", contract)
        self.assertIn("regular `100644` repository file", contract)
        self.assertIn(ARTIFACT_ARCHIVE_SHA256, contract)
        self.assertIn(str(ARTIFACT_ARCHIVE_BYTES), contract)
        self.assertIn(str(ARTIFACT_ID), contract)
        self.assertIn(ARTIFACT_NAME, contract)
        self.assertIn(str(ARTIFACT_RUN_ID), contract)
        self.assertIn(str(ARTIFACT_JOB_ID), contract)
        self.assertIn(ADOPTED_SOURCE_REVISION, contract)
        self.assertIn(ADOPTED_SOURCE_TREE, contract)
        self.assertIn(ADOPTION_COMMIT, contract)
        self.assertIn("independently downloaded and checked", contract)
        self.assertIn("without rerendering", contract)
        self.assertIn("verified\nrasterized CLI transcript", contract)
        self.assertIn("source commit and tree identities", contract)
        self.assertIn('("Aileron", "Regular")', contract)
        self.assertIn("actual ink bounding-box top-left", contract)
        self.assertIn("tallest measured phase", contract)
        self.assertIn("raster mode derived from\nthe target drawing surface", contract)
        self.assertIn("does not upload or substitute generated media", contract)
        for output in ADOPTED_OUTPUTS:
            self.assertIn(f"`{output}`", contract)

    def test_readmes_embed_real_evidence_and_exact_reproduction(self) -> None:
        readme = README_PATH.read_text(encoding="utf-8")
        index = CLI_INDEX_PATH.read_text(encoding="utf-8")

        self.assertIn("## Verified CLI workflow and results", readme)
        self.assertIn("not speculative UI mockups", readme)
        self.assertIn("not an operating-system screenshot", readme)
        self.assertIn("two fresh captures", readme)
        for output in (
            "docs/cli-evidence/cli-workflow.svg",
            "docs/cli-evidence/cli-transcript.png",
            "docs/cli-evidence/cli-demo.gif",
            "docs/cli-evidence/cli-result.svg",
        ):
            self.assertIn(f"]({output})", readme)
            self.assertIn(f"]({Path(output).name})", index)

        self.assertIn("This README is an index", index)
        self.assertIn("not a seventh artifact member", index)
        self.assertIn(ARTIFACT_ARCHIVE_SHA256, index)
        self.assertIn(ARTIFACT_NAME, index)
        self.assertIn(ADOPTED_SOURCE_REVISION, index)
        self.assertIn(ADOPTED_SOURCE_TREE, index)
        self.assertIn(ADOPTION_COMMIT, index)
        self.assertIn('test "${#wheels[@]}" -eq 1', index)
        self.assertIn("scripts/render_cli_evidence.py check", index)
        self.assertIn("git diff --exit-code", index)
        for output, identity in ADOPTED_IDENTITIES.items():
            self.assertIn(Path(output).name, index)
            self.assertIn(cast(str, identity["sha256"]), index)

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

    def test_adopted_evidence_is_reproduced_from_explicit_head(self) -> None:
        workflow = WORKFLOW_PATH.read_text(encoding="utf-8")
        self.assertIn("cli-evidence:", workflow)
        self.assertNotIn("cli-evidence-candidate:", workflow)
        self.assertIn(
            "SOURCE_REVISION: ${{ github.event.pull_request.head.sha || github.sha }}",
            workflow,
        )
        self.assertIn("ref: ${{ env.SOURCE_REVISION }}", workflow)
        self.assertIn('test "$(git rev-parse HEAD)" = "$SOURCE_REVISION"', workflow)
        self.assertIn("git rev-parse HEAD^{tree}", workflow)
        self.assertIn("runs-on: ubuntu-24.04", workflow)
        self.assertIn('python-version: "3.12.3"', workflow)
        self.assertEqual(
            workflow.count("scripts/render_cli_evidence.py check"),
            1,
        )
        self.assertEqual(
            workflow.count("scripts/render_cli_evidence.py render"),
            0,
        )
        self.assertEqual(
            workflow.count("scripts/render_cli_evidence.py compare"),
            0,
        )
        self.assertNotIn("--source-tree", workflow)
        self.assertNotIn("actions/upload-artifact@", workflow)
        self.assertIn("Reproduce and verify adopted CLI evidence", workflow)
        self.assertIn("git diff --exit-code", workflow)
        self.assertIn("git status --porcelain --untracked-files=all", workflow)

    def test_source_distribution_carries_the_evidence_contract(self) -> None:
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

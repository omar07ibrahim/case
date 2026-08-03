from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import stat
import subprocess
import sys
import tempfile
import unicodedata
import unittest
from pathlib import Path
from types import ModuleType
from typing import Protocol, cast
from unittest.mock import patch
from xml.etree import ElementTree

from casefold_observatory import (
    COLLISION_ALGORITHM,
    MAX_ANALYSIS_COMPONENTS,
    MAX_ANALYSIS_POLICIES,
    MAX_ANALYSIS_POLICY_GROUPS,
    MAX_ANALYSIS_RECORDS,
    MAX_ANALYSIS_TOTAL_INPUT_UTF8_BYTES,
    MAX_ANALYSIS_TRANSFORM_APPLICATIONS,
    MAX_ANALYSIS_TRANSFORMED_UTF8_BYTES,
    MAX_ANALYSIS_WITNESSES,
    CollisionGraph,
    HazardHandling,
    TransformStep,
    analyze_collisions,
    create_identifier_record,
    create_policy,
)

PROJECT_ROOT = Path(__file__).resolve().parents[1]
VISUAL_ROOT = PROJECT_ROOT / "docs" / "visuals"
EVIDENCE_PATH = VISUAL_ROOT / "evidence" / "collision-visuals.v1.json"
GENERATOR_PATH = PROJECT_ROOT / "scripts" / "render_collision_visuals.py"
EXPECTED_FILES = {
    "README.md",
    "architecture.svg",
    "collision-witness-graph.svg",
    "evidence/collision-visuals.v1.json",
    "policy-collision-landscape.svg",
}
EXPECTED_GENERATED_OUTPUTS = [
    "docs/visuals/README.md",
    "docs/visuals/evidence/collision-visuals.v1.json",
    "docs/visuals/architecture.svg",
    "docs/visuals/collision-witness-graph.svg",
    "docs/visuals/policy-collision-landscape.svg",
]
SVG_DIMENSIONS = {
    "architecture.svg": ("1600", "970", "0 0 1600 970"),
    "collision-witness-graph.svg": ("1500", "900", "0 0 1500 900"),
    "policy-collision-landscape.svg": (
        "1600",
        "1120",
        "0 0 1600 1120",
    ),
}
IMPLEMENTATION_PATHS = (
    "src/casefold_observatory/__init__.py",
    "src/casefold_observatory/collision.py",
    "src/casefold_observatory/engine.py",
    "src/casefold_observatory/model.py",
)
SVG_NAMESPACE = "http://www.w3.org/2000/svg"


class _Renderer(Protocol):
    PROJECT_ROOT: Path
    VISUAL_ROOT: Path
    _GROUP_FILLS: tuple[str, ...]
    _INK: str

    def _write_one(self, path: Path, content: bytes) -> None: ...

    def _validated_output_path(
        self,
        relative_path: str,
        *,
        create_parents: bool,
    ) -> Path: ...


def _load_renderer() -> _Renderer:
    spec = importlib.util.spec_from_file_location(
        "casefold_visual_renderer_for_tests",
        GENERATOR_PATH,
    )
    if spec is None or spec.loader is None:
        raise RuntimeError("could not load the visual renderer")
    module: ModuleType = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return cast(_Renderer, module)


renderer = _load_renderer()


def _object(value: object) -> dict[str, object]:
    if type(value) is not dict:
        raise TypeError("expected a JSON object")
    return cast(dict[str, object], value)


def _array(value: object) -> list[object]:
    if type(value) is not list:
        raise TypeError("expected a JSON array")
    return cast(list[object], value)


def _string(value: object) -> str:
    if type(value) is not str:
        raise TypeError("expected a JSON string")
    return value


def _integer(value: object) -> int:
    if type(value) is not int:
        raise TypeError("expected a JSON integer")
    return value


def _relative_luminance(color: str) -> float:
    if len(color) != 7 or not color.startswith("#"):
        raise ValueError("expected a six-digit hexadecimal color")
    channels = tuple(int(color[offset : offset + 2], 16) / 255 for offset in (1, 3, 5))
    linear = tuple(
        channel / 12.92 if channel <= 0.04045 else ((channel + 0.055) / 1.055) ** 2.4
        for channel in channels
    )
    return 0.2126 * linear[0] + 0.7152 * linear[1] + 0.0722 * linear[2]


def _contrast_ratio(foreground: str, background: str) -> float:
    foreground_luminance = _relative_luminance(foreground)
    background_luminance = _relative_luminance(background)
    lighter = max(foreground_luminance, background_luminance)
    darker = min(foreground_luminance, background_luminance)
    return (lighter + 0.05) / (darker + 0.05)


def _evidence() -> dict[str, object]:
    value: object = json.loads(EVIDENCE_PATH.read_text(encoding="utf-8"))
    return _object(value)


def _evidence_unicode_version() -> str:
    payload = _evidence()
    versions = {
        _string(_object(_object(payload[name])["graph"])["unicode_version"])
        for name in ("first_merge", "landscape")
    }
    if len(versions) != 1:
        raise RuntimeError("visual scenarios must bind one Unicode database version")
    return next(iter(versions))


EVIDENCE_UNICODE_VERSION = _evidence_unicode_version()
EVIDENCE_RUNTIME_REASON = (
    "exact visual replay requires Unicode database "
    f"{EVIDENCE_UNICODE_VERSION}; this runtime provides "
    f"{unicodedata.unidata_version}"
)


def _codepoints(value: str) -> str:
    return " ".join(f"U+{ord(character):04X}" for character in value)


def _graph_projection(graph: CollisionGraph) -> dict[str, object]:
    return {
        "algorithm": graph.algorithm,
        "colliding_record_count": graph.colliding_record_count,
        "components": [
            {
                "component_id": component.component_id,
                "duplicate_group_ids": list(component.duplicate_group_ids),
                "member_record_ordinals": list(component.member_record_ordinals),
                "policy_group_ids": list(component.policy_group_ids),
                "policy_ordinals": list(component.policy_ordinals),
                "witness_tree_ids": list(component.witness_tree_ids),
            }
            for component in graph.components
        ],
        "duplicate_groups": [
            {
                "group_id": group.group_id,
                "member_record_ordinals": list(group.member_record_ordinals),
                "witness_ids": list(group.witness_ids),
            }
            for group in graph.duplicate_groups
        ],
        "isolated_record_ordinals": list(graph.isolated_record_ordinals),
        "policy_groups": [
            {
                "group_id": group.group_id,
                "member_record_ordinals": list(group.member_record_ordinals),
                "output_codepoints": group.output_codepoints,
                "output_utf8_bytes": group.output_utf8_bytes,
                "policy_id": group.policy_id,
                "policy_ordinal": group.policy_ordinal,
                "transformed": group.transformed,
                "transformed_codepoints": _codepoints(group.transformed),
                "witness_ids": list(group.witness_ids),
            }
            for group in graph.policy_groups
        ],
        "policy_ids": list(graph.policy_ids),
        "record_count": graph.record_count,
        "record_ids": list(graph.record_ids),
        "semantic_corpus_sha256": graph.semantic_corpus_sha256,
        "unicode_version": graph.unicode_version,
        "witnesses": [
            {
                "kind": witness.kind.value,
                "left_record_ordinal": witness.left_record_ordinal,
                "policy_id": witness.policy_id,
                "policy_ordinal": witness.policy_ordinal,
                "right_record_ordinal": witness.right_record_ordinal,
                "stage_index": witness.stage_index,
                "step": None if witness.step is None else witness.step.value,
                "witness_id": witness.witness_id,
            }
            for witness in graph.witnesses
        ],
    }


def _rebuild_graph(scenario: dict[str, object]) -> CollisionGraph:
    record_values = _array(scenario["records"])
    policy_values = _array(scenario["policies"])
    records = tuple(
        create_identifier_record(
            _string(_object(value)["record_id"]),
            _string(_object(value)["input"]),
        )
        for value in reversed(record_values)
    )
    policies = tuple(
        create_policy(
            tuple(
                TransformStep(_string(step)) for step in _array(_object(value)["steps"])
            ),
            hazard_handling=HazardHandling(_string(_object(value)["hazard_handling"])),
        )
        for value in policy_values
    )
    return analyze_collisions(records, policies)


def _compact_sha256(value: object) -> str:
    canonical = json.dumps(
        value,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    )
    return hashlib.sha256(f"{canonical}\n".encode()).hexdigest()


def _implementation_tree_sha256() -> str:
    digest = hashlib.sha256()
    digest.update(b"casefold-observatory.visual-source-tree.v1\x00")
    for relative_path in IMPLEMENTATION_PATHS:
        path_bytes = relative_path.encode()
        content = (PROJECT_ROOT / relative_path).read_bytes()
        digest.update(len(path_bytes).to_bytes(8, "big"))
        digest.update(path_bytes)
        digest.update(len(content).to_bytes(8, "big"))
        digest.update(content)
    return digest.hexdigest()


class CollisionVisualContractTests(unittest.TestCase):
    def test_exact_generated_set_and_modes(self) -> None:
        observed = {
            path.relative_to(VISUAL_ROOT).as_posix()
            for path in VISUAL_ROOT.rglob("*")
            if path.is_file()
        }
        self.assertEqual(observed, EXPECTED_FILES)
        for relative_path in EXPECTED_FILES:
            path = VISUAL_ROOT / relative_path
            status = os.lstat(path)
            self.assertTrue(stat.S_ISREG(status.st_mode), relative_path)
            self.assertFalse(stat.S_ISLNK(status.st_mode), relative_path)
            self.assertEqual(stat.S_IMODE(status.st_mode), 0o644, relative_path)

    @unittest.skipUnless(
        unicodedata.unidata_version == EVIDENCE_UNICODE_VERSION,
        EVIDENCE_RUNTIME_REASON,
    )
    def test_exact_generated_bytes_on_the_evidence_unicode_version(self) -> None:
        completed = subprocess.run(
            (
                sys.executable,
                GENERATOR_PATH.as_posix(),
                "--check",
            ),
            cwd=PROJECT_ROOT,
            check=True,
            capture_output=True,
            text=True,
        )
        self.assertEqual(
            completed.stdout,
            "collision visuals verified (5 files, byte-for-byte)\n",
        )
        self.assertEqual(completed.stderr, "")

    def test_evidence_is_canonical_bounded_and_has_reproducible_provenance(
        self,
    ) -> None:
        raw = EVIDENCE_PATH.read_bytes()
        payload = _evidence()
        expected = (
            json.dumps(
                payload,
                ensure_ascii=False,
                indent=2,
                sort_keys=True,
            ).encode()
            + b"\n"
        )
        self.assertEqual(raw, expected)
        self.assertLess(len(raw), 64 * 1024)
        self.assertEqual(
            payload["schema"],
            "casefold-observatory.collision-visual-evidence",
        )
        self.assertEqual(payload["schema_version"], 1)

        metadata = _object(payload["generator"])
        self.assertEqual(metadata["generator"], "scripts/render_collision_visuals.py")
        self.assertEqual(metadata["generator_version"], 2)
        self.assertEqual(
            metadata["source_api"],
            "casefold_observatory.analyze_collisions",
        )
        self.assertEqual(metadata["source_paths"], list(IMPLEMENTATION_PATHS))
        self.assertEqual(metadata["outputs"], EXPECTED_GENERATED_OUTPUTS)
        self.assertEqual(
            metadata["generator_sha256"],
            hashlib.sha256(GENERATOR_PATH.read_bytes()).hexdigest(),
        )
        self.assertEqual(
            metadata["source_tree_sha256"],
            _implementation_tree_sha256(),
        )
        completed = subprocess.run(
            (
                "git",
                "log",
                "-1",
                "--format=%H",
                "--",
                *IMPLEMENTATION_PATHS,
            ),
            cwd=PROJECT_ROOT,
            check=True,
            capture_output=True,
            text=True,
        )
        self.assertEqual(
            metadata["source_revision"],
            completed.stdout.strip(),
        )
        text = raw.decode()
        for forbidden in (
            "/home/",
            "access_token",
            "api_key",
            "password",
            "private_key",
        ):
            self.assertNotIn(forbidden, text.casefold())
        self.assertNotIn('"generated_at"', text)
        self.assertNotIn('"timestamp"', text)

    @unittest.skipUnless(
        unicodedata.unidata_version == EVIDENCE_UNICODE_VERSION,
        EVIDENCE_RUNTIME_REASON,
    )
    def test_scenarios_replay_to_the_exact_public_graph(self) -> None:
        payload = _evidence()
        for scenario_name in ("first_merge", "landscape"):
            with self.subTest(scenario=scenario_name):
                scenario = _object(payload[scenario_name])
                rebuilt = _rebuild_graph(scenario)
                self.assertEqual(
                    _graph_projection(rebuilt),
                    _object(scenario["graph"]),
                )

    def test_first_merge_fixture_reports_the_reviewed_minimum_tree(self) -> None:
        scenario = _object(_evidence()["first_merge"])
        graph = _object(scenario["graph"])
        self.assertEqual(graph["record_ids"], ["eszett", "lower", "upper"])
        witness_values = _array(graph["witnesses"])
        witnesses = [_object(value) for value in witness_values]
        self.assertEqual(
            [
                (
                    _integer(witness["stage_index"]),
                    _string(witness["step"]),
                    _integer(witness["left_record_ordinal"]),
                    _integer(witness["right_record_ordinal"]),
                )
                for witness in witnesses
            ],
            [
                (0, TransformStep.LOWER.value, 1, 2),
                (1, TransformStep.CASEFOLD.value, 0, 1),
            ],
        )
        group = _object(_array(graph["policy_groups"])[0])
        self.assertEqual(group["member_record_ordinals"], [0, 1, 2])
        self.assertEqual(len(_array(group["witness_ids"])), 2)
        self.assertEqual(group["transformed"], "ss")

    def test_landscape_cells_match_groups_and_keep_union_nonclaim_visible(
        self,
    ) -> None:
        scenario = _object(_evidence()["landscape"])
        graph = _object(scenario["graph"])
        self.assertEqual(graph["record_count"], 12)
        self.assertEqual(len(_array(graph["policy_ids"])), 4)
        self.assertEqual(len(_array(graph["policy_groups"])), 11)
        self.assertEqual(len(_array(graph["components"])), 4)
        self.assertEqual(graph["isolated_record_ordinals"], [6])
        members_by_policy = [
            (
                _integer(group["policy_ordinal"]),
                tuple(
                    _integer(member)
                    for member in _array(group["member_record_ordinals"])
                ),
            )
            for group in (_object(value) for value in _array(graph["policy_groups"]))
        ]
        self.assertIn((1, (0, 2, 5)), members_by_policy)
        self.assertIn((2, (3, 9, 10)), members_by_policy)
        self.assertIn((3, (4, 8, 11)), members_by_policy)

        landscape_text = (VISUAL_ROOT / "policy-collision-landscape.svg").read_text(
            encoding="utf-8"
        )
        for visible_label in ("①", "１", "K", "ß", "e◌́", "E◌́"):
            self.assertIn(visible_label, landscape_text)
        self.assertIn(
            "not one equivalence class",
            landscape_text,
        )
        for component in (_object(value) for value in _array(graph["components"])):
            self.assertIn(_string(component["component_id"]), landscape_text)
        self.assertIn("isolated", landscape_text)
        self.assertIn("record tag + border", landscape_text)

    def test_filled_landscape_cells_meet_text_contrast(self) -> None:
        for fill in renderer._GROUP_FILLS:
            with self.subTest(fill=fill):
                self.assertGreaterEqual(
                    _contrast_ratio(renderer._INK, fill),
                    4.5,
                )

        graph = _object(_object(_evidence()["landscape"])["graph"])
        expected_filled_cells = sum(
            len(_array(_object(group)["member_record_ordinals"]))
            for group in _array(graph["policy_groups"])
        )
        landscape_text = (VISUAL_ROOT / "policy-collision-landscape.svg").read_text(
            encoding="utf-8"
        )
        self.assertEqual(
            landscape_text.count('class="filled-cell mono"'),
            expected_filled_cells,
        )

    def test_svg_metadata_dimensions_and_data_hashes_are_exact(self) -> None:
        payload = _evidence()
        section_by_svg = {
            "architecture.svg": "architecture",
            "collision-witness-graph.svg": "first_merge",
            "policy-collision-landscape.svg": "landscape",
        }
        for filename, section_name in section_by_svg.items():
            with self.subTest(svg=filename):
                root = ElementTree.fromstring((VISUAL_ROOT / filename).read_bytes())
                width, height, view_box = SVG_DIMENSIONS[filename]
                self.assertEqual(root.attrib["width"], width)
                self.assertEqual(root.attrib["height"], height)
                self.assertEqual(root.attrib["viewBox"], view_box)
                self.assertEqual(root.attrib["role"], "img")
                metadata_node = root.find(f"{{{SVG_NAMESPACE}}}metadata")
                self.assertIsNotNone(metadata_node)
                assert metadata_node is not None
                metadata_value: object = json.loads(metadata_node.text or "")
                metadata = _object(metadata_value)
                self.assertEqual(
                    metadata["data_sha256"],
                    _compact_sha256(payload[section_name]),
                )
                self.assertEqual(
                    metadata["source_revision"],
                    _object(payload["generator"])["source_revision"],
                )

    def test_svg_header_dividers_stay_inside_their_viewboxes(self) -> None:
        for filename, (width, _, _) in SVG_DIMENSIONS.items():
            with self.subTest(svg=filename):
                root = ElementTree.fromstring((VISUAL_ROOT / filename).read_bytes())
                dividers = [
                    element
                    for element in root.findall(f"{{{SVG_NAMESPACE}}}line")
                    if element.attrib.get("y1") == "106"
                    and element.attrib.get("y2") == "106"
                ]
                self.assertEqual(len(dividers), 1)
                self.assertEqual(dividers[0].attrib.get("x1"), "54")
                self.assertEqual(
                    dividers[0].attrib.get("x2"),
                    str(int(width) - 54),
                )

    def test_svgs_have_no_active_or_remote_assets(self) -> None:
        forbidden_tags = {"script", "image", "foreignobject", "iframe", "object"}
        forbidden_attribute_fragments = (
            "data:",
            "javascript:",
            "url(",
            "https://",
        )
        for filename in SVG_DIMENSIONS:
            with self.subTest(svg=filename):
                raw = (VISUAL_ROOT / filename).read_text(encoding="utf-8")
                self.assertEqual(
                    raw.count("http://"),
                    1,
                    "only the standard SVG namespace is allowed",
                )
                self.assertIn(
                    'xmlns="http://www.w3.org/2000/svg"',
                    raw,
                )
                root = ElementTree.fromstring(raw)
                for element in root.iter():
                    local_name = element.tag.rsplit("}", 1)[-1].casefold()
                    self.assertNotIn(local_name, forbidden_tags)
                    for attribute_name, attribute_value in element.attrib.items():
                        lowered_name = attribute_name.casefold()
                        lowered_value = attribute_value.casefold()
                        self.assertNotIn("href", lowered_name)
                        for fragment in forbidden_attribute_fragments:
                            self.assertNotIn(fragment, lowered_value)
                lowered_raw = raw.casefold()
                self.assertNotIn("@import", lowered_raw)
                self.assertNotIn("<!entity", lowered_raw)
                self.assertNotIn("<!doctype", lowered_raw)

    def test_architecture_describes_only_current_implemented_surfaces(self) -> None:
        payload = _evidence()
        architecture = _object(payload["architecture"])
        bounds = _object(architecture["bounds"])
        self.assertEqual(architecture["algorithm"], COLLISION_ALGORITHM)
        self.assertEqual(
            bounds,
            {
                "max_components": MAX_ANALYSIS_COMPONENTS,
                "max_policies": MAX_ANALYSIS_POLICIES,
                "max_policy_groups": MAX_ANALYSIS_POLICY_GROUPS,
                "max_records": MAX_ANALYSIS_RECORDS,
                "max_total_input_utf8_bytes": (MAX_ANALYSIS_TOTAL_INPUT_UTF8_BYTES),
                "max_transform_applications": (MAX_ANALYSIS_TRANSFORM_APPLICATIONS),
                "max_transformed_utf8_bytes": (MAX_ANALYSIS_TRANSFORMED_UTF8_BYTES),
                "max_witnesses": MAX_ANALYSIS_WITNESSES,
            },
        )
        svg_text = (VISUAL_ROOT / "architecture.svg").read_text(encoding="utf-8")
        for implemented in (
            "public Python API probes",
            "oracle + boundary tests",
            "checked SVG evidence",
            "documented security review",
        ):
            self.assertIn(implemented, svg_text)
        for unimplemented in ("receipts", "CLI / SVG renderers"):
            self.assertNotIn(unimplemented, svg_text)

    def test_secure_writer_replaces_a_symlink_without_following_it(self) -> None:
        with tempfile.TemporaryDirectory(
            prefix=".visual-writer-test-",
            dir=PROJECT_ROOT,
        ) as directory:
            root = Path(directory)
            target = root / "target"
            target.write_bytes(b"sentinel")
            output = root / "output"
            output.symlink_to(target.name)

            renderer._write_one(output, b"replacement")

            self.assertEqual(target.read_bytes(), b"sentinel")
            self.assertFalse(output.is_symlink())
            self.assertEqual(output.read_bytes(), b"replacement")
            self.assertEqual(stat.S_IMODE(os.lstat(output).st_mode), 0o644)
            self.assertEqual(
                sorted(path.name for path in root.iterdir()),
                ["output", "target"],
            )

    def test_output_validator_rejects_symlinks_and_special_files(self) -> None:
        with tempfile.TemporaryDirectory(
            prefix=".visual-path-test-",
            dir=PROJECT_ROOT,
        ) as directory:
            root = Path(directory)
            visual_root = root / "docs" / "visuals"
            evidence_root = visual_root / "evidence"
            evidence_root.mkdir(parents=True)
            target = root / "target"
            target.write_text("sentinel", encoding="utf-8")
            (visual_root / "architecture.svg").symlink_to(target)
            fifo = visual_root / "collision-witness-graph.svg"
            os.mkfifo(fifo)

            with (
                patch.object(renderer, "PROJECT_ROOT", root),
                patch.object(renderer, "VISUAL_ROOT", visual_root),
            ):
                with self.assertRaisesRegex(RuntimeError, "symlink or special"):
                    renderer._validated_output_path(
                        "docs/visuals/architecture.svg",
                        create_parents=False,
                    )
                with self.assertRaisesRegex(RuntimeError, "symlink or special"):
                    renderer._validated_output_path(
                        "docs/visuals/collision-witness-graph.svg",
                        create_parents=False,
                    )


if __name__ == "__main__":
    unittest.main()

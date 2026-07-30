"""Render deterministic collision-analysis evidence and portfolio SVGs.

The three visuals are generated from the public ``analyze_collisions`` API.
There are no network, browser, font, image, Graphviz, or third-party runtime
dependencies. Run with ``--check`` to verify every committed byte.
"""

from __future__ import annotations

import argparse
import hashlib
import html
import json
import os
import re
import secrets
import stat
import subprocess
import sys
import unicodedata
from itertools import pairwise
from pathlib import Path
from typing import Final

PROJECT_ROOT: Final = Path(__file__).resolve().parents[1]
SOURCE_ROOT: Final = PROJECT_ROOT / "src"
if SOURCE_ROOT.as_posix() not in sys.path:
    sys.path.insert(0, SOURCE_ROOT.as_posix())

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
    TransformPolicy,
    TransformStep,
    WitnessKind,
    analyze_collisions,
    apply_policy,
    create_identifier_record,
    create_policy,
)

GENERATOR_VERSION: Final = 1
GENERATOR_PATH: Final = "scripts/render_collision_visuals.py"
IMPLEMENTATION_PATHS: Final = (
    "src/casefold_observatory/collision.py",
    "src/casefold_observatory/engine.py",
    "src/casefold_observatory/model.py",
)
VISUAL_ROOT: Final = PROJECT_ROOT / "docs" / "visuals"
EVIDENCE_RELATIVE_PATH: Final = "docs/visuals/evidence/collision-visuals.v1.json"
SVG_RELATIVE_PATHS: Final = (
    "docs/visuals/architecture.svg",
    "docs/visuals/collision-witness-graph.svg",
    "docs/visuals/policy-collision-landscape.svg",
)
INDEX_RELATIVE_PATH: Final = "docs/visuals/README.md"
OUTPUT_RELATIVE_PATHS: Final = (
    INDEX_RELATIVE_PATH,
    EVIDENCE_RELATIVE_PATH,
    *SVG_RELATIVE_PATHS,
)
_REVISION_PATTERN: Final = re.compile(r"[0-9a-f]{40}\Z")

JsonValue = None | bool | int | float | str | list["JsonValue"] | dict[str, "JsonValue"]
JsonObject = dict[str, JsonValue]
JsonArray = list[JsonValue]

FIRST_MERGE_INPUTS: Final = (
    ("upper", "SS"),
    ("eszett", "ß"),
    ("lower", "ss"),
)
LANDSCAPE_INPUTS: Final = (
    ("ascii-digit", "1"),
    ("ascii-k", "K"),
    ("circled-digit", "①"),
    ("decomposed", "e\u0301"),
    ("eszett", "ß"),
    ("fullwidth-digit", "１"),
    ("isolated", "atlas"),
    ("kelvin", "K"),
    ("lower-ss", "ss"),
    ("precomposed", "é"),
    ("upper-decomposed", "E\u0301"),
    ("upper-ss", "SS"),
)

_BACKGROUND = "#07111f"
_PANEL = "#0e1b2d"
_PANEL_LIGHT = "#142640"
_INK = "#eff6ff"
_MUTED = "#9fb2c9"
_GRID = "#29425f"
_TEAL = "#42d6c5"
_CYAN = "#4db5ff"
_AMBER = "#ffbd59"
_PINK = "#ff78a9"
_GREEN = "#7ee787"
_POLICY_COLORS: Final = (_TEAL, _CYAN, _AMBER, _PINK)
_GROUP_FILLS: Final = (
    "#164d4a",
    "#243f6d",
    "#5a4020",
    "#583147",
    "#31513c",
)


def _canonical_json(value: JsonValue, *, pretty: bool) -> bytes:
    if pretty:
        text = json.dumps(
            value,
            ensure_ascii=False,
            indent=2,
            sort_keys=True,
        )
    else:
        text = json.dumps(
            value,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        )
    return f"{text}\n".encode()


def _json_object(value: JsonValue, *, context: str) -> JsonObject:
    if not isinstance(value, dict):
        raise TypeError(f"{context} must be a JSON object")
    return value


def _json_array(value: JsonValue, *, context: str) -> JsonArray:
    if not isinstance(value, list):
        raise TypeError(f"{context} must be a JSON array")
    return value


def _json_integer(value: JsonValue, *, context: str) -> int:
    if type(value) is not int:
        raise TypeError(f"{context} must be a JSON integer")
    return value


def _sha256(value: JsonValue) -> str:
    return hashlib.sha256(_canonical_json(value, pretty=False)).hexdigest()


def _xml(value: object) -> str:
    return html.escape(str(value), quote=True)


def _visible_identifier(value: str) -> str:
    """Return display notation that makes combining/invisible input explicit."""

    visible: list[str] = []
    for character in value:
        category = unicodedata.category(character)
        if unicodedata.combining(character):
            visible.extend(("◌", character))
        elif category in {"Cc", "Cf", "Cs"}:
            visible.append(f"⟦U+{ord(character):04X}⟧")
        else:
            visible.append(character)
    return "".join(visible)


def _codepoints(value: str) -> str:
    return " ".join(f"U+{ord(character):04X}" for character in value)


def _compact_step_label(value: str) -> str:
    namespace, separator, operation = value.partition(":")
    if not separator:
        return value
    if namespace == "normalize":
        return operation.upper()
    return operation


def _implementation_revision() -> str:
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
    revision = completed.stdout.strip()
    if _REVISION_PATTERN.fullmatch(revision) is None:
        raise RuntimeError("could not resolve a canonical implementation revision")
    return revision


def _implementation_tree_sha256() -> str:
    digest = hashlib.sha256()
    digest.update(b"casefold-observatory.visual-source-tree.v1\x00")
    for relative_path in IMPLEMENTATION_PATHS:
        path_bytes = relative_path.encode("utf-8")
        content = (PROJECT_ROOT / relative_path).read_bytes()
        digest.update(len(path_bytes).to_bytes(8, "big"))
        digest.update(path_bytes)
        digest.update(len(content).to_bytes(8, "big"))
        digest.update(content)
    return digest.hexdigest()


def _generator_sha256() -> str:
    return hashlib.sha256((PROJECT_ROOT / GENERATOR_PATH).read_bytes()).hexdigest()


def _prefix_stage_outputs(
    identifier: str,
    policy: TransformPolicy,
) -> JsonArray:
    stages: JsonArray = []
    for stage_index, step in enumerate(policy.steps):
        prefix = create_policy(
            policy.steps[: stage_index + 1],
            hazard_handling=policy.hazard_handling,
        )
        result = apply_policy(identifier, prefix)
        stages.append(
            {
                "output": result.transformed,
                "output_codepoints": _codepoints(result.transformed),
                "stage_index": stage_index,
                "step": step.value,
            }
        )
    return stages


def _graph_projection(graph: CollisionGraph) -> dict[str, JsonValue]:
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


def _scenario(
    *,
    name: str,
    description: str,
    inputs: tuple[tuple[str, str], ...],
    policy_specs: tuple[
        tuple[str, str, tuple[TransformStep, ...]],
        ...,
    ],
) -> dict[str, JsonValue]:
    records = tuple(
        create_identifier_record(record_id, identifier)
        for record_id, identifier in inputs
    )
    policies = tuple(create_policy(steps) for _label, _intent, steps in policy_specs)
    graph = analyze_collisions(records, policies)
    raw_by_id = dict(inputs)

    record_evidence: JsonArray = []
    for record_ordinal, record_id in enumerate(graph.record_ids):
        identifier = raw_by_id[record_id]
        record_evidence.append(
            {
                "input": identifier,
                "input_codepoints": _codepoints(identifier),
                "record_id": record_id,
                "record_ordinal": record_ordinal,
                "stages_by_policy": [
                    {
                        "policy_ordinal": policy_ordinal,
                        "stages": _prefix_stage_outputs(identifier, policy),
                    }
                    for policy_ordinal, policy in enumerate(policies)
                ],
                "visible_input": _visible_identifier(identifier),
            }
        )

    return {
        "description": description,
        "graph": _graph_projection(graph),
        "name": name,
        "policies": [
            {
                "hazard_handling": policy.hazard_handling.value,
                "intent": intent,
                "label": label,
                "policy_id": policy.policy_id,
                "policy_ordinal": policy_ordinal,
                "steps": [step.value for step in policy.steps],
            }
            for policy_ordinal, ((label, intent, _steps), policy) in enumerate(
                zip(policy_specs, policies, strict=True)
            )
        ],
        "records": record_evidence,
    }


def _first_merge_scenario() -> dict[str, JsonValue]:
    return _scenario(
        name="first_merge_witness",
        description=(
            "SS and ss first merge at lower; ß joins only at casefold. "
            "The two API witnesses form the minimum two-edge explanation tree."
        ),
        inputs=FIRST_MERGE_INPUTS,
        policy_specs=(
            (
                "lower → casefold",
                "Separate the first equality-producing stage from the final group.",
                (TransformStep.LOWER, TransformStep.CASEFOLD),
            ),
        ),
    )


def _landscape_scenario() -> dict[str, JsonValue]:
    return _scenario(
        name="multi_policy_landscape",
        description=(
            "Reviewed synthetic Unicode identifiers evaluated under four ordered "
            "policies. Filled cells are exact final-equality collision groups."
        ),
        inputs=LANDSCAPE_INPUTS,
        policy_specs=(
            (
                "lower → casefold",
                "Locale-independent case convergence in two observable stages.",
                (TransformStep.LOWER, TransformStep.CASEFOLD),
            ),
            (
                "NFKC",
                "Compatibility normalization for width and presentation forms.",
                (TransformStep.NFKC,),
            ),
            (
                "NFD → casefold → NFC",
                "Decompose, fold case, then recompose canonically.",
                (
                    TransformStep.NFD,
                    TransformStep.CASEFOLD,
                    TransformStep.NFC,
                ),
            ),
            (
                "upper",
                "Locale-independent uppercase mapping without normalization.",
                (TransformStep.UPPER,),
            ),
        ),
    )


def _architecture_evidence() -> dict[str, JsonValue]:
    return {
        "algorithm": COLLISION_ALGORITHM,
        "bounds": {
            "max_components": MAX_ANALYSIS_COMPONENTS,
            "max_policy_groups": MAX_ANALYSIS_POLICY_GROUPS,
            "max_policies": MAX_ANALYSIS_POLICIES,
            "max_records": MAX_ANALYSIS_RECORDS,
            "max_total_input_utf8_bytes": (MAX_ANALYSIS_TOTAL_INPUT_UTF8_BYTES),
            "max_transform_applications": (MAX_ANALYSIS_TRANSFORM_APPLICATIONS),
            "max_transformed_utf8_bytes": (MAX_ANALYSIS_TRANSFORMED_UTF8_BYTES),
            "max_witnesses": MAX_ANALYSIS_WITNESSES,
        },
        "invariants": [
            "Record IDs define canonical ordinals; caller tuple order is non-semantic.",
            "Policy tuple order is explicit and significant.",
            "Exact strings define equality; hashes only label the semantic corpus.",
            "A policy rejection aborts analysis atomically.",
            "Each policy collision group receives a minimum witness tree.",
            "Global components are cross-policy risk neighborhoods, not equivalence.",
        ],
        "workflow": [
            "records + ordered policies",
            "revalidate types, Unicode scalars, IDs, and aggregate budgets",
            "canonicalize records by stable ID and label the semantic corpus",
            "evaluate every stage under every ordered policy",
            "connect first-merging partitions with minimum witness forests",
            "union policy relations and select a separate component tree",
            "return an immutable bounded CollisionGraph",
        ],
    }


def _metadata(
    *,
    generator_sha256: str,
    source_revision: str,
    source_tree_sha256: str,
) -> dict[str, JsonValue]:
    return {
        "canonical_json": (
            "UTF-8; sorted object keys; two-space indentation; trailing LF"
        ),
        "check_command": "python scripts/render_collision_visuals.py --check",
        "command": "python scripts/render_collision_visuals.py",
        "generator": GENERATOR_PATH,
        "generator_sha256": generator_sha256,
        "generator_version": GENERATOR_VERSION,
        "outputs": list(OUTPUT_RELATIVE_PATHS),
        "source_api": "casefold_observatory.analyze_collisions",
        "source_paths": list(IMPLEMENTATION_PATHS),
        "source_revision": source_revision,
        "source_tree_sha256": source_tree_sha256,
    }


def _svg_open(
    *,
    width: int,
    height: int,
    title: str,
    description: str,
    metadata: dict[str, JsonValue],
) -> list[str]:
    metadata_text = _canonical_json(metadata, pretty=False).decode().strip()
    return [
        (
            f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" '
            f'height="{height}" viewBox="0 0 {width} {height}" '
            'role="img" aria-labelledby="svg-title svg-description">'
        ),
        f'  <title id="svg-title">{_xml(title)}</title>',
        (f'  <desc id="svg-description">{_xml(description)}</desc>'),
        f"  <metadata>{_xml(metadata_text)}</metadata>",
        "  <style>",
        ("    text { font-family: Inter, 'Segoe UI', 'DejaVu Sans', sans-serif; }"),
        "    .title { fill: #eff6ff; font-size: 34px; font-weight: 750; }",
        "    .subtitle { fill: #9fb2c9; font-size: 16px; }",
        "    .section { fill: #eff6ff; font-size: 18px; font-weight: 700; }",
        "    .body { fill: #dce8f6; font-size: 15px; }",
        "    .small { fill: #9fb2c9; font-size: 12px; }",
        "    .mono { font-family: 'DejaVu Sans Mono', monospace; }",
        "  </style>",
        f'  <rect width="{width}" height="{height}" fill="{_BACKGROUND}"/>',
    ]


def _header(
    lines: list[str],
    *,
    title: str,
    subtitle: str,
) -> None:
    lines.extend(
        [
            (f'  <text x="54" y="58" class="title">{_xml(title)}</text>'),
            (f'  <text x="54" y="88" class="subtitle">{_xml(subtitle)}</text>'),
            (f'  <line x1="54" y1="106" x2="1546" y2="106" stroke="{_GRID}"/>'),
        ]
    )


def _metric_card(
    lines: list[str],
    *,
    x: int,
    y: int,
    width: int,
    label: str,
    value: str,
    accent: str,
) -> None:
    lines.extend(
        [
            (
                f'  <rect x="{x}" y="{y}" width="{width}" height="74" rx="12" '
                f'fill="{_PANEL}" stroke="{_GRID}"/>'
            ),
            (f'  <rect x="{x}" y="{y}" width="5" height="74" rx="2" fill="{accent}"/>'),
            (
                f'  <text x="{x + 20}" y="{y + 27}" class="small">'
                f"{_xml(label.upper())}</text>"
            ),
            (f'  <text x="{x + 20}" y="{y + 55}" class="section">{_xml(value)}</text>'),
        ]
    )


def _policy_rows(
    scenario: dict[str, JsonValue],
) -> tuple[list[dict[str, JsonValue]], list[dict[str, JsonValue]]]:
    policies = scenario["policies"]
    records = scenario["records"]
    if not isinstance(policies, list) or not isinstance(records, list):
        raise TypeError("scenario evidence lost policies or records")
    return (
        [item for item in policies if isinstance(item, dict)],
        [item for item in records if isinstance(item, dict)],
    )


def _graph_dict(scenario: dict[str, JsonValue]) -> dict[str, JsonValue]:
    graph = scenario["graph"]
    if not isinstance(graph, dict):
        raise TypeError("scenario evidence lost its graph")
    return graph


def _render_witness_svg(
    scenario: dict[str, JsonValue],
    *,
    source_revision: str,
) -> bytes:
    graph = _graph_dict(scenario)
    policies, records = _policy_rows(scenario)
    witnesses = graph["witnesses"]
    groups = graph["policy_groups"]
    if (
        len(policies) != 1
        or not isinstance(witnesses, list)
        or not isinstance(groups, list)
        or len(groups) != 1
    ):
        raise RuntimeError("first-merge evidence shape changed")

    data_sha256 = _sha256(scenario)
    lines = _svg_open(
        width=1500,
        height=900,
        title="First-merge witness graph",
        description=(
            "A real collision graph for SS, ss, and eszett under lower then "
            "casefold, showing the first stage at which each edge merges."
        ),
        metadata={
            "data_sha256": data_sha256,
            "generated_by": GENERATOR_PATH,
            "scenario": "first_merge_witness",
            "source_revision": source_revision,
        },
    )
    _header(
        lines,
        title="First-merge witness graph",
        subtitle=("Real API output · exact equality · minimum explanation tree"),
    )
    _metric_card(
        lines,
        x=54,
        y=128,
        width=282,
        label="records",
        value=str(graph["record_count"]),
        accent=_TEAL,
    )
    _metric_card(
        lines,
        x=354,
        y=128,
        width=282,
        label="witness edges",
        value=str(len(witnesses)),
        accent=_CYAN,
    )
    _metric_card(
        lines,
        x=654,
        y=128,
        width=350,
        label="algorithm",
        value=str(graph["algorithm"]),
        accent=_AMBER,
    )
    _metric_card(
        lines,
        x=1022,
        y=128,
        width=424,
        label="Unicode database",
        value=str(graph["unicode_version"]),
        accent=_PINK,
    )

    policy = policies[0]
    steps = policy["steps"]
    if not isinstance(steps, list):
        raise TypeError("first-merge policy steps changed shape")
    lines.extend(
        [
            (
                f'  <rect x="54" y="224" width="1392" height="64" rx="12" '
                f'fill="{_PANEL_LIGHT}" stroke="{_GRID}"/>'
            ),
            (
                f'  <text x="76" y="250" class="small">'
                f"POLICY 0 · {_xml(str(policy['label']))}</text>"
            ),
            (
                f'  <text x="76" y="275" class="body mono">'
                f"{_xml('  →  '.join(str(step) for step in steps))}</text>"
            ),
            (
                f'  <text x="1420" y="262" text-anchor="end" class="small mono">'
                f"id {_xml(str(policy['policy_id'])[:12])}…</text>"
            ),
        ]
    )

    column_x = (405, 780, 1155)
    column_labels = ("input", "stage 0 · lower", "stage 1 · casefold")
    for x, label in zip(column_x, column_labels, strict=True):
        lines.extend(
            [
                (
                    f'  <text x="{x}" y="326" text-anchor="middle" '
                    f'class="section">{_xml(label)}</text>'
                ),
                (
                    f'  <line x1="{x}" y1="342" x2="{x}" y2="755" '
                    f'stroke="{_GRID}" stroke-dasharray="3 8"/>'
                ),
            ]
        )

    row_y = (405, 555, 705)
    record_by_id = {str(record["record_id"]): record for record in records}
    ordered_records = [
        record_by_id[record_id] for record_id in ("eszett", "lower", "upper")
    ]
    for y, record in zip(row_y, ordered_records, strict=True):
        input_value = str(record["input"])
        policy_stages = record["stages_by_policy"]
        if not isinstance(policy_stages, list) or len(policy_stages) != 1:
            raise TypeError("first-merge record stages changed shape")
        stage_items = policy_stages[0]
        if not isinstance(stage_items, dict):
            raise TypeError("first-merge stage item changed shape")
        stages = _json_array(
            stage_items["stages"],
            context="first-merge stages",
        )
        if len(stages) != 2:
            raise TypeError("first-merge stage list changed shape")
        stage_zero = _json_object(
            stages[0],
            context="first-merge stage zero",
        )
        stage_one = _json_object(
            stages[1],
            context="first-merge stage one",
        )
        values = [
            input_value,
            str(stage_zero["output"]),
            str(stage_one["output"]),
        ]

        lines.extend(
            [
                (
                    f'  <text x="54" y="{y - 7}" class="section">'
                    f"{_xml(str(record['record_id']))}</text>"
                ),
                (
                    f'  <text x="54" y="{y + 17}" class="small mono">'
                    f"{_xml(str(record['input_codepoints']))}</text>"
                ),
            ]
        )
        for index, (x, value) in enumerate(zip(column_x, values, strict=True)):
            stroke = _TEAL if index == 2 else _GRID
            lines.extend(
                [
                    (
                        f'  <rect x="{x - 86}" y="{y - 40}" width="172" '
                        f'height="74" rx="14" fill="{_PANEL}" '
                        f'stroke="{stroke}" stroke-width="2"/>'
                    ),
                    (
                        f'  <text x="{x}" y="{y + 7}" text-anchor="middle" '
                        f'class="section mono">{_xml(_visible_identifier(value))}'
                        "</text>"
                    ),
                ]
            )
            if index < 2:
                lines.extend(
                    [
                        (
                            f'  <line x1="{x + 90}" y1="{y - 3}" '
                            f'x2="{column_x[index + 1] - 100}" y2="{y - 3}" '
                            f'stroke="{_MUTED}" stroke-width="2"/>'
                        ),
                        (
                            f'  <path d="M {column_x[index + 1] - 100} '
                            f'{y - 3} l -9 -5 v 10 z" fill="{_MUTED}"/>'
                        ),
                    ]
                )

    # The actual API returns these deterministic first-merge edges:
    # lower↔upper at stage 0, then eszett↔lower at stage 1.
    witness_by_stage = {
        int(witness["stage_index"]): witness
        for witness in witnesses
        if isinstance(witness, dict)
        and witness["kind"] == WitnessKind.TRANSFORM_STAGE.value
        and isinstance(witness["stage_index"], int)
    }
    for stage_index, x, y1, y2, color in (
        (0, column_x[1], row_y[1] + 40, row_y[2] - 40, _CYAN),
        (1, column_x[2], row_y[0] + 40, row_y[1] - 40, _AMBER),
    ):
        witness = witness_by_stage[stage_index]
        lines.extend(
            [
                (
                    f'  <line x1="{x}" y1="{y1}" x2="{x}" y2="{y2}" '
                    f'stroke="{color}" stroke-width="4" '
                    'stroke-dasharray="7 6"/>'
                ),
                (f'  <circle cx="{x}" cy="{(y1 + y2) // 2}" r="7" fill="{color}"/>'),
                (
                    f'  <rect x="{x + 22}" y="{(y1 + y2) // 2 - 26}" '
                    f'width="250" height="52" rx="10" fill="{_PANEL_LIGHT}" '
                    f'stroke="{color}"/>'
                ),
                (
                    f'  <text x="{x + 36}" y="{(y1 + y2) // 2 - 3}" '
                    f'class="small mono">{_xml(str(witness["witness_id"]))}'
                    "</text>"
                ),
                (
                    f'  <text x="{x + 36}" y="{(y1 + y2) // 2 + 16}" '
                    f'class="body">{_xml(str(witness["step"]))}</text>'
                ),
            ]
        )

    group = _json_object(groups[0], context="first-merge group")
    group_members = _json_array(
        group["member_record_ordinals"],
        context="first-merge group members",
    )
    lines.extend(
        [
            (
                f'  <rect x="54" y="792" width="1392" height="62" rx="12" '
                f'fill="#102c2f" stroke="{_TEAL}"/>'
            ),
            (
                f'  <text x="76" y="819" class="section">'
                f"{_xml(str(group['group_id']))} · "
                f"{len(group_members)} records → "
                f"{_xml(_visible_identifier(str(group['transformed'])))}"
                "</text>"
            ),
            (
                '  <text x="76" y="842" class="small">'
                "Two witnesses connect three records: n − 1, never a clique."
                "</text>"
            ),
            (
                f'  <text x="1422" y="832" text-anchor="end" class="small mono">'
                f"data {_xml(data_sha256[:16])}…</text>"
            ),
        ]
    )
    lines.append("</svg>")
    return "\n".join(lines).encode() + b"\n"


def _member_group_map(
    graph: dict[str, JsonValue],
) -> tuple[
    dict[tuple[int, int], tuple[str, int]],
    dict[int, str],
]:
    policy_groups = graph["policy_groups"]
    components = graph["components"]
    if not isinstance(policy_groups, list) or not isinstance(components, list):
        raise TypeError("landscape graph groups changed shape")

    group_indexes: dict[int, int] = {}
    membership: dict[tuple[int, int], tuple[str, int]] = {}
    for group_value in policy_groups:
        group = _json_object(group_value, context="policy group")
        policy_ordinal = _json_integer(
            group["policy_ordinal"],
            context="policy ordinal",
        )
        group_index = group_indexes.get(policy_ordinal, 0)
        group_indexes[policy_ordinal] = group_index + 1
        members = _json_array(
            group["member_record_ordinals"],
            context="policy group members",
        )
        for member in members:
            membership[
                (
                    _json_integer(member, context="policy group member"),
                    policy_ordinal,
                )
            ] = (
                str(group["group_id"]),
                group_index,
            )

    component_by_member: dict[int, str] = {}
    for component_value in components:
        component = _json_object(component_value, context="component")
        members = _json_array(
            component["member_record_ordinals"],
            context="component members",
        )
        for member in members:
            component_by_member[_json_integer(member, context="component member")] = (
                str(component["component_id"])
            )
    return membership, component_by_member


def _render_landscape_svg(
    scenario: dict[str, JsonValue],
    *,
    source_revision: str,
) -> bytes:
    graph = _graph_dict(scenario)
    policies, records = _policy_rows(scenario)
    if len(policies) != 4 or len(records) != 12:
        raise RuntimeError("landscape fixture dimensions changed")
    membership, component_by_member = _member_group_map(graph)
    components = graph["components"]
    isolated = graph["isolated_record_ordinals"]
    if not isinstance(components, list) or not isinstance(isolated, list):
        raise TypeError("landscape component evidence changed shape")

    data_sha256 = _sha256(scenario)
    lines = _svg_open(
        width=1600,
        height=1120,
        title="Multi-policy collision landscape",
        description=(
            "Twelve reviewed synthetic identifiers by four Unicode policies. "
            "Filled matrix cells are collision groups returned by the API."
        ),
        metadata={
            "data_sha256": data_sha256,
            "generated_by": GENERATOR_PATH,
            "scenario": "multi_policy_landscape",
            "source_revision": source_revision,
        },
    )
    _header(
        lines,
        title="Multi-policy collision landscape",
        subtitle=(
            "12 reviewed synthetic inputs · 4 ordered policies · real exact groups"
        ),
    )
    _metric_card(
        lines,
        x=54,
        y=126,
        width=260,
        label="records",
        value=str(graph["record_count"]),
        accent=_TEAL,
    )
    _metric_card(
        lines,
        x=330,
        y=126,
        width=260,
        label="policy groups",
        value=str(
            len(
                _json_array(
                    graph["policy_groups"],
                    context="landscape policy groups",
                )
            )
        ),
        accent=_CYAN,
    )
    _metric_card(
        lines,
        x=606,
        y=126,
        width=300,
        label="risk neighborhoods",
        value=str(len(components)),
        accent=_AMBER,
    )
    _metric_card(
        lines,
        x=922,
        y=126,
        width=260,
        label="isolated",
        value=str(len(isolated)),
        accent=_PINK,
    )
    _metric_card(
        lines,
        x=1198,
        y=126,
        width=348,
        label="Unicode database",
        value=str(graph["unicode_version"]),
        accent=_GREEN,
    )

    record_x = 54
    record_width = 322
    policy_x = (392, 680, 968, 1256)
    policy_width = 274
    header_y = 222
    header_height = 92
    for policy_ordinal, (x, policy) in enumerate(zip(policy_x, policies, strict=True)):
        color = _POLICY_COLORS[policy_ordinal]
        steps = policy["steps"]
        if not isinstance(steps, list):
            raise TypeError("landscape policy steps changed shape")
        lines.extend(
            [
                (
                    f'  <rect x="{x}" y="{header_y}" width="{policy_width}" '
                    f'height="{header_height}" rx="12" fill="{_PANEL_LIGHT}" '
                    f'stroke="{color}" stroke-width="2"/>'
                ),
                (
                    f'  <text x="{x + 16}" y="{header_y + 28}" '
                    f'class="section">{_xml(str(policy["label"]))}</text>'
                ),
                (
                    f'  <text x="{x + 16}" y="{header_y + 52}" '
                    f'class="small mono">'
                    f"{_xml(' · '.join(_compact_step_label(str(step)) for step in steps))}"
                    "</text>"
                ),
                (
                    f'  <text x="{x + 16}" y="{header_y + 75}" '
                    f'class="small mono">p{policy_ordinal} · '
                    f"{_xml(str(policy['policy_id'])[:10])}…</text>"
                ),
            ]
        )
    lines.extend(
        [
            (
                f'  <rect x="{record_x}" y="{header_y}" width="{record_width}" '
                f'height="{header_height}" rx="12" fill="{_PANEL_LIGHT}" '
                f'stroke="{_GRID}"/>'
            ),
            (
                f'  <text x="{record_x + 18}" y="{header_y + 35}" '
                'class="section">canonical record</text>'
            ),
            (
                f'  <text x="{record_x + 18}" y="{header_y + 62}" '
                'class="small">stable ID · visible input · code points</text>'
            ),
        ]
    )

    row_start_y = 330
    row_height = 54
    component_colors = {
        component_id: _POLICY_COLORS[index % len(_POLICY_COLORS)]
        for index, component_id in enumerate(sorted(set(component_by_member.values())))
    }
    for record_ordinal, record in enumerate(records):
        y = row_start_y + record_ordinal * row_height
        component_id = component_by_member.get(record_ordinal)
        component_color = (
            component_colors[component_id] if component_id is not None else _GRID
        )
        lines.extend(
            [
                (
                    f'  <rect x="{record_x}" y="{y}" width="{record_width}" '
                    f'height="{row_height - 4}" rx="8" fill="{_PANEL}" '
                    f'stroke="{component_color}"/>'
                ),
                (
                    f'  <text x="{record_x + 14}" y="{y + 21}" '
                    f'class="body">{_xml(str(record["record_id"]))}</text>'
                ),
                (
                    f'  <text x="{record_x + 14}" y="{y + 40}" '
                    f'class="small mono">'
                    f"{_xml(_visible_identifier(str(record['input'])))} · "
                    f"{_xml(str(record['input_codepoints']))}</text>"
                ),
            ]
        )
        for policy_ordinal, x in enumerate(policy_x):
            group = membership.get((record_ordinal, policy_ordinal))
            if group is None:
                fill = "#0b1727"
                stroke = _GRID
                label = "—"
                label_class = "small"
            else:
                group_id, group_index = group
                fill = _GROUP_FILLS[(policy_ordinal + group_index) % len(_GROUP_FILLS)]
                stroke = _POLICY_COLORS[policy_ordinal]
                label = group_id
                label_class = "small mono"
            lines.extend(
                [
                    (
                        f'  <rect x="{x}" y="{y}" width="{policy_width}" '
                        f'height="{row_height - 4}" rx="8" fill="{fill}" '
                        f'stroke="{stroke}"/>'
                    ),
                    (
                        f'  <text x="{x + policy_width // 2}" y="{y + 31}" '
                        f'text-anchor="middle" class="{label_class}">'
                        f"{_xml(label)}</text>"
                    ),
                ]
            )

    legend_y = 1000
    lines.extend(
        [
            (
                f'  <rect x="54" y="{legend_y}" width="1492" height="76" '
                f'rx="12" fill="{_PANEL_LIGHT}" stroke="{_GRID}"/>'
            ),
            (
                f'  <rect x="74" y="{legend_y + 20}" width="26" height="26" '
                f'rx="5" fill="{_GROUP_FILLS[0]}" stroke="{_TEAL}"/>'
            ),
            (
                f'  <text x="114" y="{legend_y + 39}" class="body">'
                "filled = distinct raw inputs share one exact final value"
                "</text>"
            ),
            (
                f'  <text x="654" y="{legend_y + 39}" class="body">'
                "record border = global union component"
                "</text>"
            ),
            (
                f'  <text x="1024" y="{legend_y + 39}" class="body">'
                "— = no policy collision"
                "</text>"
            ),
            (
                f'  <text x="74" y="{legend_y + 63}" class="small">'
                "A union component is a risk neighborhood across policies; "
                "it is not one equivalence class."
                "</text>"
            ),
            (
                f'  <text x="1520" y="{legend_y + 63}" text-anchor="end" '
                f'class="small mono">data {_xml(data_sha256[:16])}…</text>'
            ),
        ]
    )
    lines.append("</svg>")
    return "\n".join(lines).encode() + b"\n"


def _architecture_box(
    lines: list[str],
    *,
    x: int,
    y: int,
    number: int,
    title: str,
    body: tuple[str, ...],
    accent: str,
) -> None:
    lines.extend(
        [
            (
                f'  <rect x="{x}" y="{y}" width="322" height="198" rx="16" '
                f'fill="{_PANEL}" stroke="{accent}" stroke-width="2"/>'
            ),
            (f'  <circle cx="{x + 30}" cy="{y + 30}" r="17" fill="{accent}"/>'),
            (
                f'  <text x="{x + 30}" y="{y + 36}" text-anchor="middle" '
                f'font-size="15" font-weight="800" fill="{_BACKGROUND}">'
                f"{number}</text>"
            ),
            (f'  <text x="{x + 58}" y="{y + 36}" class="section">{_xml(title)}</text>'),
        ]
    )
    for index, text in enumerate(body):
        lines.append(
            f'  <text x="{x + 22}" y="{y + 78 + index * 25}" '
            f'class="body">{_xml(text)}</text>'
        )


def _arrow(
    lines: list[str],
    *,
    x1: int,
    y1: int,
    x2: int,
    y2: int,
    color: str = _MUTED,
) -> None:
    lines.extend(
        [
            (
                f'  <line x1="{x1}" y1="{y1}" x2="{x2}" y2="{y2}" '
                f'stroke="{color}" stroke-width="3"/>'
            ),
            (f'  <circle cx="{x1}" cy="{y1}" r="4" fill="{color}"/>'),
        ]
    )
    if x2 > x1:
        path = f"M {x2} {y2} l -11 -7 v 14 z"
    elif x2 < x1:
        path = f"M {x2} {y2} l 11 -7 v 14 z"
    else:
        path = f"M {x2} {y2} l -7 -11 h 14 z"
    lines.append(f'  <path d="{path}" fill="{color}"/>')


def _render_architecture_svg(
    architecture: dict[str, JsonValue],
    *,
    source_revision: str,
) -> bytes:
    bounds = architecture["bounds"]
    if not isinstance(bounds, dict):
        raise TypeError("architecture bounds changed shape")
    data_sha256 = _sha256(architecture)
    lines = _svg_open(
        width=1600,
        height=970,
        title="Collision analysis architecture",
        description=(
            "The bounded deterministic workflow from validated records and "
            "ordered policies to minimal witnesses and a collision graph."
        ),
        metadata={
            "data_sha256": data_sha256,
            "generated_by": GENERATOR_PATH,
            "scenario": "architecture",
            "source_revision": source_revision,
        },
    )
    _header(
        lines,
        title="Collision analysis architecture",
        subtitle=("Bounded trust boundary → exact partitions → minimum witnesses"),
    )
    _metric_card(
        lines,
        x=54,
        y=126,
        width=468,
        label="algorithm",
        value=str(architecture["algorithm"]),
        accent=_TEAL,
    )
    _metric_card(
        lines,
        x=538,
        y=126,
        width=310,
        label="records / policies",
        value=f"{bounds['max_records']:,} / {bounds['max_policies']}",
        accent=_CYAN,
    )
    _metric_card(
        lines,
        x=864,
        y=126,
        width=330,
        label="transform applications",
        value=f"{bounds['max_transform_applications']:,}",
        accent=_AMBER,
    )
    _metric_card(
        lines,
        x=1210,
        y=126,
        width=336,
        label="witness budget",
        value=f"{bounds['max_witnesses']:,}",
        accent=_PINK,
    )

    top_y = 256
    bottom_y = 582
    x_positions = (54, 430, 806, 1182)
    _architecture_box(
        lines,
        x=x_positions[0],
        y=top_y,
        number=1,
        title="Explicit inputs",
        body=(
            "IdentifierRecord tuple",
            "ordered TransformPolicy tuple",
            "stable opaque record IDs",
            "caller order is non-semantic",
        ),
        accent=_TEAL,
    )
    _architecture_box(
        lines,
        x=x_positions[1],
        y=top_y,
        number=2,
        title="Trust boundary",
        body=(
            "revalidate forged state",
            "Unicode scalar checks",
            "per-value + aggregate bounds",
            "any rejection is atomic",
        ),
        accent=_CYAN,
    )
    _architecture_box(
        lines,
        x=x_positions[2],
        y=top_y,
        number=3,
        title="Canonical corpus",
        body=(
            "sort by record ID",
            "preserve every occurrence",
            "classify exact duplicates",
            "hashes label, never decide equality",
        ),
        accent=_AMBER,
    )
    _architecture_box(
        lines,
        x=x_positions[3],
        y=top_y,
        number=4,
        title="Ordered evaluation",
        body=(
            "run each policy stage",
            "track exact stage values",
            "partitions only coarsen",
            "enforce transformed-byte cap",
        ),
        accent=_PINK,
    )
    _architecture_box(
        lines,
        x=x_positions[3],
        y=bottom_y,
        number=5,
        title="Policy witnesses",
        body=(
            "detect first-merging buckets",
            "connect prior components",
            "store n − 1 edges per group",
            "no quadratic clique output",
        ),
        accent=_PINK,
    )
    _architecture_box(
        lines,
        x=x_positions[2],
        y=bottom_y,
        number=6,
        title="Global union",
        body=(
            "union every policy relation",
            "build risk neighborhoods",
            "select a separate minimum tree",
            "not one-policy equivalence",
        ),
        accent=_AMBER,
    )
    _architecture_box(
        lines,
        x=x_positions[1],
        y=bottom_y,
        number=7,
        title="CollisionGraph",
        body=(
            "immutable bounded result",
            "groups + witness edges",
            "components + isolated records",
            "canonical deterministic IDs",
        ),
        accent=_CYAN,
    )
    _architecture_box(
        lines,
        x=x_positions[0],
        y=bottom_y,
        number=8,
        title="Current verification",
        body=(
            "public Python API probes",
            "oracle + boundary tests",
            "checked SVG evidence",
            "documented security review",
        ),
        accent=_TEAL,
    )

    for left, right in pairwise(x_positions):
        _arrow(
            lines,
            x1=left + 322,
            y1=top_y + 99,
            x2=right - 14,
            y2=top_y + 99,
        )
    _arrow(
        lines,
        x1=x_positions[3] + 161,
        y1=top_y + 198,
        x2=x_positions[3] + 161,
        y2=bottom_y - 14,
    )
    for right, left in pairwise(reversed(x_positions)):
        _arrow(
            lines,
            x1=right,
            y1=bottom_y + 99,
            x2=left + 336,
            y2=bottom_y + 99,
        )

    lines.extend(
        [
            (
                f'  <rect x="54" y="838" width="1492" height="86" rx="14" '
                f'fill="{_PANEL_LIGHT}" stroke="{_GRID}"/>'
            ),
            (
                f'  <text x="76" y="870" class="section" fill="{_GREEN}">'
                "Correctness boundary</text>"
            ),
            (
                '  <text x="76" y="898" class="body">'
                "Exact strings determine equality. The corpus digest is an "
                "integrity label, not anonymity, authentication, or identity."
                "</text>"
            ),
            (
                f'  <text x="1520" y="898" text-anchor="end" '
                f'class="small mono">data {_xml(data_sha256[:16])}…</text>'
            ),
        ]
    )
    lines.append("</svg>")
    return "\n".join(lines).encode() + b"\n"


def _render_visual_index(
    *,
    first_merge: dict[str, JsonValue],
    landscape: dict[str, JsonValue],
    source_revision: str,
    source_tree_sha256: str,
    generator_sha256: str,
) -> bytes:
    first_graph = _graph_dict(first_merge)
    landscape_graph = _graph_dict(landscape)
    content = f"""# Collision visual evidence

These deterministic artifacts visualize the current public
`casefold_observatory.analyze_collisions` API. They are generated from reviewed,
bounded synthetic Unicode inputs—not screenshots, UI mockups, or hand-entered
results.

| Artifact | Executed fixture | What the visual proves |
| --- | --- | --- |
| [`collision-witness-graph.svg`](collision-witness-graph.svg) | `SS`, `ss`, `ß` under `lower → casefold` | The API reports the `ss`/`SS` first merge at stage 0 and the `ß` join at stage 1; two witnesses are the minimum tree for three records. |
| [`policy-collision-landscape.svg`](policy-collision-landscape.svg) | 12 synthetic inputs including `1`/`①`/`１`, `K`/`K`, `SS`/`ss`/`ß`, and composed/decomposed `é` | The matrix is rendered from the API's exact final-equality policy groups across four ordered policies. |
| [`architecture.svg`](architecture.svg) | Public bounds and the implemented graph workflow | The trust boundary, canonical ordering, stage partitions, minimum policy forests, and separate global union tree are shown without claiming unimplemented surfaces. |
| [`evidence/collision-visuals.v1.json`](evidence/collision-visuals.v1.json) | Canonical evidence for both fixtures plus architecture constants | Every record, stage output, policy ID, group, witness, component, digest, and bound used by the SVGs is reviewable as UTF-8 JSON. |

## Reproduce

Run from the repository root with the project environment active:

```console
python scripts/render_collision_visuals.py
python scripts/render_collision_visuals.py --check
```

`--check` rebuilds all five artifacts in memory, checks the exact file set,
compares every byte and mode, and rejects symlink or special-file outputs. The
renderer uses only Python's standard library and the local package; it performs
no network requests and loads no remote fonts, scripts, images, or styles.

## Evidence relationship

Each SVG embeds a canonical `data_sha256` in its `<metadata>` element. It is the
SHA-256 of the matching compact, sorted JSON subsection:

- `first_merge` → `collision-witness-graph.svg`
- `landscape` → `policy-collision-landscape.svg`
- `architecture` → `architecture.svg`

The committed evidence records:

- implementation revision: `{source_revision}`
- implementation tree SHA-256: `{source_tree_sha256}`
- generator SHA-256: `{generator_sha256}`
- algorithm: `{first_graph["algorithm"]}`
- Unicode database: `{first_graph["unicode_version"]}`
- first-merge corpus label: `{first_graph["semantic_corpus_sha256"]}`
- landscape corpus label: `{landscape_graph["semantic_corpus_sha256"]}`

The revision is the newest commit touching the analyzed implementation paths,
not repository `HEAD`; therefore a later visuals-only commit does not make the
evidence stale. The tree and generator hashes still detect uncommitted or
post-revision byte changes.

## Review notes and nonclaims

- Inputs are public synthetic Unicode examples. No credentials, secrets,
  personal data, local absolute paths, timestamps, or machine identifiers are
  captured.
- Equality is determined by exact strings. Digests are integrity labels; they
  do not provide anonymity, authentication, freshness, or proof of original
  source bytes.
- A global component is a cross-policy risk neighborhood, not a claim that all
  members are equal under one policy.
- Combining marks use dotted-circle display notation in labels so decomposed
  forms remain visibly distinct. The canonical JSON retains the exact strings.
- The SVGs are explanatory renderings of current API results, not an interactive
  CLI, application screenshot, or security boundary.
"""
    return content.encode()


def build_outputs() -> dict[str, bytes]:
    source_revision = _implementation_revision()
    source_tree_sha256 = _implementation_tree_sha256()
    generator_sha256 = _generator_sha256()
    first_merge = _first_merge_scenario()
    landscape = _landscape_scenario()
    architecture = _architecture_evidence()
    evidence: dict[str, JsonValue] = {
        "architecture": architecture,
        "first_merge": first_merge,
        "generator": _metadata(
            generator_sha256=generator_sha256,
            source_revision=source_revision,
            source_tree_sha256=source_tree_sha256,
        ),
        "landscape": landscape,
        "schema": "casefold-observatory.collision-visual-evidence",
        "schema_version": 1,
    }
    return {
        INDEX_RELATIVE_PATH: _render_visual_index(
            first_merge=first_merge,
            landscape=landscape,
            source_revision=source_revision,
            source_tree_sha256=source_tree_sha256,
            generator_sha256=generator_sha256,
        ),
        EVIDENCE_RELATIVE_PATH: _canonical_json(evidence, pretty=True),
        "docs/visuals/architecture.svg": _render_architecture_svg(
            architecture,
            source_revision=source_revision,
        ),
        "docs/visuals/collision-witness-graph.svg": _render_witness_svg(
            first_merge,
            source_revision=source_revision,
        ),
        "docs/visuals/policy-collision-landscape.svg": (
            _render_landscape_svg(
                landscape,
                source_revision=source_revision,
            )
        ),
    }


def _observed_visual_files() -> set[str]:
    if not VISUAL_ROOT.exists():
        return set()
    visual_root_status = os.lstat(VISUAL_ROOT)
    if stat.S_ISLNK(visual_root_status.st_mode) or not stat.S_ISDIR(
        visual_root_status.st_mode
    ):
        raise RuntimeError("docs/visuals must be a real directory")
    return {
        path.relative_to(PROJECT_ROOT).as_posix()
        for path in VISUAL_ROOT.rglob("*")
        if stat.S_ISLNK(os.lstat(path).st_mode)
        or not stat.S_ISDIR(os.lstat(path).st_mode)
    }


def _validated_output_path(
    relative_path: str,
    *,
    create_parents: bool,
) -> Path:
    relative = Path(relative_path)
    if (
        relative.is_absolute()
        or ".." in relative.parts
        or relative.parts[:2] != ("docs", "visuals")
    ):
        raise RuntimeError("generated output escaped docs/visuals")
    path = PROJECT_ROOT / relative
    project_root = PROJECT_ROOT.resolve(strict=True)
    current = PROJECT_ROOT
    for component in relative.parts[:-1]:
        current /= component
        try:
            status = os.lstat(current)
        except FileNotFoundError:
            if not create_parents:
                return path
            current.mkdir(mode=0o755)
            status = os.lstat(current)
        if stat.S_ISLNK(status.st_mode) or not stat.S_ISDIR(status.st_mode):
            raise RuntimeError(f"output parent is not a real directory: {current}")
        if not current.resolve(strict=True).is_relative_to(project_root):
            raise RuntimeError("generated output parent escaped the project")
    try:
        output_status = os.lstat(path)
    except FileNotFoundError:
        return path
    if stat.S_ISLNK(output_status.st_mode) or not stat.S_ISREG(output_status.st_mode):
        raise RuntimeError(f"output is a symlink or special file: {relative_path}")
    return path


def _check(outputs: dict[str, bytes]) -> int:
    problems: list[str] = []
    expected = set(outputs)
    try:
        observed = _observed_visual_files()
    except RuntimeError as error:
        print(f"unsafe: {error}", file=sys.stderr)
        return 1
    for unexpected in sorted(observed - expected):
        problems.append(f"unexpected: {unexpected}")
    for relative_path, expected_bytes in outputs.items():
        try:
            path = _validated_output_path(
                relative_path,
                create_parents=False,
            )
        except RuntimeError as error:
            problems.append(f"unsafe: {relative_path} ({error})")
            continue
        try:
            output_status = os.lstat(path)
        except FileNotFoundError:
            problems.append(f"missing: {relative_path}")
            continue
        if not stat.S_ISREG(output_status.st_mode):
            problems.append(f"unsafe: {relative_path} (not a regular file)")
        elif path.read_bytes() != expected_bytes:
            problems.append(f"stale: {relative_path}")
        elif stat.S_IMODE(output_status.st_mode) != 0o644:
            problems.append(f"mode: {relative_path} (expected 0644)")
    if problems:
        for problem in problems:
            print(problem, file=sys.stderr)
        return 1
    print(f"collision visuals verified ({len(outputs)} files, byte-for-byte)")
    return 0


def _open_exclusive_temporary(
    *,
    directory_descriptor: int,
    output_name: str,
) -> tuple[int, str]:
    flags = (
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    for _attempt in range(128):
        temporary_name = f".{output_name}.{secrets.token_hex(16)}.tmp"
        try:
            descriptor = os.open(
                temporary_name,
                flags,
                0o600,
                dir_fd=directory_descriptor,
            )
        except FileExistsError:
            continue
        return descriptor, temporary_name
    raise RuntimeError("could not reserve an exclusive temporary output")


def _write_one(path: Path, content: bytes) -> None:
    directory_flags = (
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    directory_descriptor = os.open(path.parent, directory_flags)
    descriptor = -1
    temporary_name: str | None = None
    try:
        descriptor, temporary_name = _open_exclusive_temporary(
            directory_descriptor=directory_descriptor,
            output_name=path.name,
        )
        with os.fdopen(descriptor, "wb") as stream:
            descriptor = -1
            stream.write(content)
            stream.flush()
            os.fchmod(stream.fileno(), 0o644)
            os.fsync(stream.fileno())
        os.replace(
            temporary_name,
            path.name,
            src_dir_fd=directory_descriptor,
            dst_dir_fd=directory_descriptor,
        )
        temporary_name = None
        os.fsync(directory_descriptor)
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        if temporary_name is not None:
            try:
                os.unlink(temporary_name, dir_fd=directory_descriptor)
            except FileNotFoundError:
                pass
        os.close(directory_descriptor)


def _write(outputs: dict[str, bytes]) -> None:
    unexpected = _observed_visual_files() - set(outputs)
    if unexpected:
        names = ", ".join(sorted(unexpected))
        raise RuntimeError(f"refusing to replace an unexpected visual set: {names}")
    for relative_path, content in outputs.items():
        path = _validated_output_path(
            relative_path,
            create_parents=True,
        )
        _write_one(path, content)
    print(f"rendered {len(outputs)} deterministic collision visual files")


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Render deterministic Unicode collision visuals.",
    )
    parser.add_argument(
        "--check",
        action="store_true",
        help="verify committed outputs instead of rewriting them",
    )
    arguments = parser.parse_args()
    outputs = build_outputs()
    if arguments.check:
        return _check(outputs)
    _write(outputs)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

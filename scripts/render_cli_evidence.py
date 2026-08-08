"""Capture and render deterministic evidence from the installed wheel CLI.

This visual-only tool requires the canonical CPython and Pillow versions declared
below. It never imports the project package from the source checkout: every
captured command resolves through a dedicated environment containing the built
wheel.
"""

from __future__ import annotations

import argparse
import hashlib
import html
import io
import json
import os
import platform
import re
import stat
import subprocess
import tempfile
import textwrap
import unicodedata
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from pathlib import Path
from typing import Final, NoReturn, cast

from PIL import Image, ImageDraw, ImageFont
from PIL import __version__ as PILLOW_VERSION

PROJECT_ROOT: Final = Path(__file__).resolve().parents[1]
GENERATOR_PATH: Final = "scripts/render_cli_evidence.py"
FIXTURE_PATH: Final = "docs/cli-evidence/fixtures/cli-demo.v1.jsonl"
PYPROJECT_PATH: Final = "pyproject.toml"

MANIFEST_PATH: Final = "docs/cli-evidence/evidence/cli-evidence.v1.json"
RECEIPT_PATH: Final = "docs/cli-evidence/evidence/cli-demo.receipt.v1.json"
PNG_PATH: Final = "docs/cli-evidence/cli-transcript.png"
GIF_PATH: Final = "docs/cli-evidence/cli-demo.gif"
RESULT_SVG_PATH: Final = "docs/cli-evidence/cli-result.svg"
WORKFLOW_SVG_PATH: Final = "docs/cli-evidence/cli-workflow.svg"
OUTPUT_PATHS: Final = (
    MANIFEST_PATH,
    RECEIPT_PATH,
    PNG_PATH,
    GIF_PATH,
    RESULT_SVG_PATH,
    WORKFLOW_SVG_PATH,
)
HASHED_OUTPUT_PATHS: Final = tuple(
    path for path in OUTPUT_PATHS if path != MANIFEST_PATH
)

SOURCE_BINDINGS: Final = (
    GENERATOR_PATH,
    FIXTURE_PATH,
    PYPROJECT_PATH,
    "src/casefold_observatory/__init__.py",
    "src/casefold_observatory/__main__.py",
    "src/casefold_observatory/cli.py",
    "src/casefold_observatory/collision.py",
    "src/casefold_observatory/corpus.py",
    "src/casefold_observatory/engine.py",
    "src/casefold_observatory/filesystem.py",
    "src/casefold_observatory/model.py",
    "src/casefold_observatory/receipt.py",
    "src/casefold_observatory/py.typed",
)

EXPECTED_IMPLEMENTATION: Final = "CPython"
EXPECTED_PYTHON: Final = "3.12.3"
EXPECTED_UNICODE: Final = "15.0.0"
EXPECTED_PACKAGE: Final = "casefold-observatory"
EXPECTED_PACKAGE_VERSION: Final = "0.4.0"
EXPECTED_PILLOW: Final = "12.3.0"
EXPECTED_COMMAND_IDS: Final = (
    "analyze",
    "verify",
    "no_clobber",
    "source_mismatch",
)
EXPECTED_STATUSES: Final = (0, 0, 5, 4)
EXPECTED_FAILURES: Final = (
    ("no_clobber", "filesystem.destination_exists"),
    ("source_mismatch", "receipt.source_mismatch"),
)
_REVISION = re.compile(r"[0-9a-f]{40}\Z")
_HEX_DIGEST = re.compile(r"[0-9a-f]{64}\Z")

_MAX_CHANNEL_BYTES: Final = 8_192
_MAX_OUTPUT_BYTES: Final = {
    MANIFEST_PATH: 196_608,
    RECEIPT_PATH: 1_048_576,
    PNG_PATH: 524_288,
    GIF_PATH: 1_048_576,
    RESULT_SVG_PATH: 196_608,
    WORKFLOW_SVG_PATH: 196_608,
}

_BACKGROUND: Final = (7, 17, 31)
_PANEL: Final = (14, 27, 45)
_PANEL_LIGHT: Final = (20, 38, 64)
_INK: Final = (239, 246, 255)
_MUTED: Final = (159, 178, 201)
_TEAL: Final = (66, 214, 197)
_CYAN: Final = (77, 181, 255)
_AMBER: Final = (255, 189, 89)
_PINK: Final = (255, 120, 169)
_GREEN: Final = (126, 231, 135)
_RED: Final = (255, 123, 114)

_SVG_BACKGROUND: Final = "#07111f"
_SVG_PANEL: Final = "#0e1b2d"
_SVG_PANEL_LIGHT: Final = "#142640"
_SVG_INK: Final = "#eff6ff"
_SVG_MUTED: Final = "#9fb2c9"
_SVG_TEAL: Final = "#42d6c5"
_SVG_CYAN: Final = "#4db5ff"
_SVG_AMBER: Final = "#ffbd59"
_SVG_PINK: Final = "#ff78a9"
_SVG_GREEN: Final = "#7ee787"
_SVG_GRID: Final = "#29425f"

JsonObject = dict[str, object]


@dataclass(frozen=True, slots=True)
class CapturedCommand:
    command_id: str
    argv: tuple[str, ...]
    exit_status: int
    stdout: bytes
    stderr: bytes

    def document(self) -> JsonObject:
        return {
            "argv": list(self.argv),
            "exit_status": self.exit_status,
            "id": self.command_id,
            "stderr": self.stderr.decode("ascii"),
            "stderr_bytes": len(self.stderr),
            "stderr_sha256": _sha256(self.stderr),
            "stdout": self.stdout.decode("ascii"),
            "stdout_bytes": len(self.stdout),
            "stdout_sha256": _sha256(self.stdout),
        }


def _fail(message: str) -> NoReturn:
    raise RuntimeError(message)


def _sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _canonical_json(value: object, *, pretty: bool) -> bytes:
    if pretty:
        rendered = json.dumps(
            value,
            ensure_ascii=True,
            allow_nan=False,
            indent=2,
            sort_keys=True,
        )
    else:
        rendered = json.dumps(
            value,
            ensure_ascii=True,
            allow_nan=False,
            separators=(",", ":"),
            sort_keys=True,
        )
    return (rendered + "\n").encode("ascii")


def _xml(value: object) -> str:
    return html.escape(str(value), quote=True)


def _read_regular(path: Path, *, maximum: int) -> bytes:
    try:
        status = os.lstat(path)
    except FileNotFoundError:
        _fail("required evidence input is missing")
    if (
        stat.S_ISLNK(status.st_mode)
        or not stat.S_ISREG(status.st_mode)
        or status.st_nlink != 1
        or status.st_size > maximum
    ):
        _fail("evidence input must be one bounded single-link regular file")
    data = path.read_bytes()
    if len(data) != status.st_size:
        _fail("evidence input changed during capture")
    return data


def _source_bindings() -> dict[str, str]:
    bindings: dict[str, str] = {}
    for relative_path in SOURCE_BINDINGS:
        data = _read_regular(PROJECT_ROOT / relative_path, maximum=2_000_000)
        bindings[relative_path] = _sha256(data)
    return bindings


def _expected_runtime_files(bindings: dict[str, str]) -> dict[str, str]:
    runtime_files = {
        path.removeprefix("src/"): digest
        for path, digest in bindings.items()
        if path.startswith("src/casefold_observatory/")
    }
    if not runtime_files:
        _fail("runtime source binding inventory is empty")
    return runtime_files


def _runtime_tree_sha256(runtime_files: dict[str, str]) -> str:
    return _sha256(_canonical_json(runtime_files, pretty=False))


def _assert_canonical_line(value: bytes) -> JsonObject:
    if not value or len(value) > _MAX_CHANNEL_BYTES or not value.isascii():
        _fail("CLI channel is not bounded non-empty ASCII")
    if not value.endswith(b"\n") or value.count(b"\n") != 1:
        _fail("CLI channel is not exactly one line")
    try:
        document = json.loads(value)
    except json.JSONDecodeError:
        _fail("CLI channel is not JSON")
    if type(document) is not dict:
        _fail("CLI channel JSON is not an object")
    typed = cast(JsonObject, document)
    if value != _canonical_json(typed, pretty=False):
        _fail("CLI channel is not canonical")
    return typed


def _capture(
    command_id: str,
    argv: tuple[str, ...],
    *,
    cwd: Path,
    venv_bin: Path,
) -> CapturedCommand:
    environment = {
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "PATH": venv_bin.as_posix(),
        "PYTHONDONTWRITEBYTECODE": "1",
        "PYTHONHASHSEED": "0",
        "PYTHONNOUSERSITE": "1",
    }
    completed = subprocess.run(
        argv,
        cwd=cwd,
        env=environment,
        stdin=subprocess.DEVNULL,
        capture_output=True,
        check=False,
        timeout=30,
    )
    if (
        len(completed.stdout) > _MAX_CHANNEL_BYTES
        or len(completed.stderr) > _MAX_CHANNEL_BYTES
    ):
        _fail("CLI channel exceeded the evidence bound")
    return CapturedCommand(
        command_id=command_id,
        argv=argv,
        exit_status=completed.returncode,
        stdout=completed.stdout,
        stderr=completed.stderr,
    )


def _runtime_probe(
    venv_bin: Path,
    *,
    expected_files: dict[str, str],
) -> JsonObject:
    program = """\
import hashlib
import importlib.metadata
import json
import platform
import unicodedata

distribution = importlib.metadata.distribution("casefold-observatory")
runtime_files = {}
for entry in sorted(distribution.files or (), key=str):
    relative = str(entry)
    if relative.startswith("casefold_observatory/") and (
        relative.endswith(".py") or relative == "casefold_observatory/py.typed"
    ):
        data = distribution.locate_file(entry).read_bytes()
        runtime_files[relative] = hashlib.sha256(data).hexdigest()
runtime_tree = hashlib.sha256(
    (json.dumps(runtime_files, sort_keys=True, separators=(",", ":")) + "\\n").encode(
        "ascii"
    )
).hexdigest()
print(
    json.dumps(
        {
            "distribution": distribution.metadata["Name"],
            "implementation": platform.python_implementation(),
            "package_version": distribution.version,
            "python_version": platform.python_version(),
            "runtime_files": runtime_files,
            "runtime_tree_sha256": runtime_tree,
            "unicode_version": unicodedata.unidata_version,
        },
        sort_keys=True,
        separators=(",", ":"),
    )
)
"""
    completed = subprocess.run(
        ("python", "-c", program),
        cwd=PROJECT_ROOT,
        env={
            "LANG": "C.UTF-8",
            "LC_ALL": "C.UTF-8",
            "PATH": venv_bin.as_posix(),
            "PYTHONDONTWRITEBYTECODE": "1",
            "PYTHONHASHSEED": "0",
            "PYTHONNOUSERSITE": "1",
        },
        stdin=subprocess.DEVNULL,
        capture_output=True,
        check=False,
        timeout=30,
    )
    if completed.returncode != 0 or completed.stderr:
        _fail("installed-wheel runtime probe failed")
    document = _assert_canonical_line(completed.stdout)
    expected = {
        "distribution": EXPECTED_PACKAGE,
        "implementation": EXPECTED_IMPLEMENTATION,
        "package_version": EXPECTED_PACKAGE_VERSION,
        "python_version": EXPECTED_PYTHON,
        "runtime_files": expected_files,
        "runtime_tree_sha256": _runtime_tree_sha256(expected_files),
        "unicode_version": EXPECTED_UNICODE,
    }
    if document != expected:
        _fail("installed-wheel runtime identity is not canonical")
    return document


def _validate_renderer_runtime() -> None:
    if platform.python_implementation() != EXPECTED_IMPLEMENTATION:
        _fail("visual renderer requires canonical CPython")
    if platform.python_version() != EXPECTED_PYTHON:
        _fail("visual renderer requires exact CPython 3.12.3")
    if unicodedata.unidata_version != EXPECTED_UNICODE:
        _fail("visual renderer requires Unicode database 15.0.0")
    if PILLOW_VERSION != EXPECTED_PILLOW:
        _fail("visual renderer requires exact Pillow 12.3.0")


def _analyze_argv() -> tuple[str, ...]:
    return (
        "casefold-observatory",
        "analyze",
        "--source",
        "corpus.jsonl",
        "--policy",
        "reject@case:lower",
        "--policy",
        "reject@case:casefold",
        "--policy",
        "reject@normalize:nfkc,case:casefold",
        "--receipt",
        "result.receipt.json",
    )


def _verify_argv() -> tuple[str, ...]:
    return (
        "python",
        "-m",
        "casefold_observatory",
        "verify",
        "--source",
        "corpus.jsonl",
        "--receipt",
        "result.receipt.json",
    )


def _capture_workflow(
    *,
    fixture: bytes,
    venv_bin: Path,
) -> tuple[tuple[CapturedCommand, ...], bytes, JsonObject]:
    with tempfile.TemporaryDirectory(prefix="casefold-cli-capture-") as directory:
        root = Path(directory)
        source_path = root / "corpus.jsonl"
        receipt_path = root / "result.receipt.json"
        source_path.write_bytes(fixture)
        os.chmod(source_path, 0o600)

        analyze = _capture(
            "analyze",
            _analyze_argv(),
            cwd=root,
            venv_bin=venv_bin,
        )
        if analyze.exit_status != 0 or analyze.stderr:
            _fail("installed analyze command failed")
        analyze_summary = _assert_canonical_line(analyze.stdout)

        receipt_status = os.lstat(receipt_path)
        if (
            not stat.S_ISREG(receipt_status.st_mode)
            or stat.S_ISLNK(receipt_status.st_mode)
            or receipt_status.st_nlink != 1
            or stat.S_IMODE(receipt_status.st_mode) != 0o600
        ):
            _fail("installed analyze command published an unsafe receipt")
        receipt = _read_regular(receipt_path, maximum=1_048_576)
        receipt_sha256 = _sha256(receipt)
        if analyze_summary.get("receipt_sha256") != receipt_sha256:
            _fail("analyze summary does not bind the produced receipt")

        verify = _capture(
            "verify",
            _verify_argv(),
            cwd=root,
            venv_bin=venv_bin,
        )
        if verify.exit_status != 0 or verify.stderr:
            _fail("installed module verification failed")
        verify_summary = _assert_canonical_line(verify.stdout)
        if verify_summary != {
            "receipt_sha256": receipt_sha256,
            "status": "verified",
        }:
            _fail("verify summary does not bind the produced receipt")

        no_clobber = _capture(
            "no_clobber",
            _analyze_argv(),
            cwd=root,
            venv_bin=venv_bin,
        )
        if no_clobber.exit_status != 5 or no_clobber.stdout:
            _fail("no-clobber capture did not fail closed")
        no_clobber_error = _assert_canonical_line(no_clobber.stderr)
        if no_clobber_error != {
            "code": "filesystem.destination_exists",
            "status": "error",
        }:
            _fail("no-clobber error taxonomy changed")
        if _read_regular(receipt_path, maximum=1_048_576) != receipt:
            _fail("no-clobber failure changed the receipt")

        mismatch_fixture = fixture.replace(
            b'"identifier":"A","record_id":"ascii-a"',
            b'"identifier":"B","record_id":"ascii-a"',
            1,
        )
        if mismatch_fixture == fixture or len(mismatch_fixture) != len(fixture):
            _fail("reviewed mismatch fixture could not be derived")
        source_path.write_bytes(mismatch_fixture)
        os.chmod(source_path, 0o600)

        source_mismatch = _capture(
            "source_mismatch",
            _verify_argv(),
            cwd=root,
            venv_bin=venv_bin,
        )
        if source_mismatch.exit_status != 4 or source_mismatch.stdout:
            _fail("source-mismatch capture did not fail closed")
        mismatch_error = _assert_canonical_line(source_mismatch.stderr)
        if mismatch_error != {
            "code": "receipt.source_mismatch",
            "status": "error",
        }:
            _fail("source-mismatch error taxonomy changed")

        commands = (analyze, verify, no_clobber, source_mismatch)
        if tuple(command.command_id for command in commands) != EXPECTED_COMMAND_IDS:
            _fail("command inventory changed")
        if tuple(command.exit_status for command in commands) != EXPECTED_STATUSES:
            _fail("command status inventory changed")
        return commands, receipt, analyze_summary


def _font(size: int) -> ImageFont.FreeTypeFont | ImageFont.ImageFont:
    return ImageFont.load_default(size=size)


def _command_lines(command: CapturedCommand, *, width: int) -> list[str]:
    command_text = "$ " + " ".join(command.argv)
    lines = textwrap.wrap(
        command_text,
        width=width,
        subsequent_indent="  ",
        break_long_words=False,
        break_on_hyphens=False,
    )
    lines.append(f"exit | {command.exit_status}")
    for channel_name, payload in (
        ("stdout", command.stdout),
        ("stderr", command.stderr),
    ):
        if not payload:
            lines.append(f"{channel_name} | <empty>")
            continue
        channel = payload.decode("ascii").rstrip("\n")
        lines.extend(
            textwrap.wrap(
                f"{channel_name} | {channel}",
                width=width,
                subsequent_indent="         ",
                break_long_words=False,
                break_on_hyphens=False,
            )
        )
    return lines


def _render_png(evidence: JsonObject, commands: tuple[CapturedCommand, ...]) -> bytes:
    width = 1400
    height = 1060
    image = Image.new("RGB", (width, height), _BACKGROUND)
    draw = ImageDraw.Draw(image)
    title_font = _font(32)
    heading_font = _font(21)
    body_font = _font(18)

    draw.rounded_rectangle((40, 34, width - 40, 150), radius=18, fill=_PANEL)
    draw.text(
        (70, 56),
        "Verified rasterized CLI transcript",
        font=title_font,
        fill=_INK,
    )
    draw.text(
        (72, 108),
        "Captured from the installed wheel; this is not an OS terminal screenshot.",
        font=body_font,
        fill=_MUTED,
    )

    receipt_document = cast(JsonObject, evidence["receipt"])
    fixture_document = cast(JsonObject, evidence["fixture"])
    package_document = cast(JsonObject, evidence["package"])
    provenance = (
        f"package {package_document['version']}  |  UCD {evidence['unicode_version']}  "
        f"| receipt {str(receipt_document['sha256'])[:16]}  "
        f"| source {str(fixture_document['sha256'])[:16]}"
    )
    draw.text((70, 170), provenance, font=body_font, fill=_TEAL)

    block_top = 215
    block_height = 190
    accent_colors = (_TEAL, _CYAN, _AMBER, _PINK)
    for index, command in enumerate(commands):
        top = block_top + index * (block_height + 12)
        draw.rounded_rectangle(
            (50, top, width - 50, top + block_height),
            radius=14,
            fill=_PANEL,
            outline=accent_colors[index],
            width=2,
        )
        draw.text(
            (76, top + 18),
            f"{index + 1:02d}  {command.command_id}",
            font=heading_font,
            fill=accent_colors[index],
        )
        line_y = top + 56
        for line in _command_lines(command, width=124):
            fill = _GREEN if line == "exit | 0" else _INK
            if line.startswith("exit |") and command.exit_status != 0:
                fill = _AMBER
            draw.text((76, line_y), line, font=body_font, fill=fill)
            line_y += 24

    draw.text(
        (52, height - 34),
        "Canonical ASCII channels; relative fixture paths; no secrets, host paths, or raw source lines.",
        font=body_font,
        fill=_MUTED,
    )
    buffer = io.BytesIO()
    image.save(buffer, format="PNG", optimize=False, compress_level=9)
    return buffer.getvalue()


def _gif_palette() -> list[int]:
    colors = (
        _BACKGROUND,
        _PANEL,
        _PANEL_LIGHT,
        _INK,
        _MUTED,
        _TEAL,
        _CYAN,
        _AMBER,
        _PINK,
        _GREEN,
        _RED,
    )
    flattened = [channel for color in colors for channel in color]
    return flattened + [0] * (768 - len(flattened))


def _render_gif(evidence: JsonObject, commands: tuple[CapturedCommand, ...]) -> bytes:
    width = 1200
    height = 650
    palette = _gif_palette()
    body_font = _font(18)
    title_font = _font(28)
    accent_indices = (5, 6, 7, 8)
    frames: list[Image.Image] = []

    receipt_document = cast(JsonObject, evidence["receipt"])
    for index, command in enumerate(commands):
        frame = Image.new("P", (width, height), 0)
        frame.putpalette(palette)
        draw = ImageDraw.Draw(frame)
        draw.rounded_rectangle((34, 32, width - 34, height - 32), radius=18, fill=1)
        draw.rectangle((34, 32, width - 34, 110), fill=2)
        draw.text(
            (62, 53),
            "Installed-wheel CLI evidence",
            font=title_font,
            fill=3,
        )
        draw.text(
            (62, 128),
            f"step {index + 1}/4  |  {command.command_id}",
            font=title_font,
            fill=accent_indices[index],
        )
        line_y = 185
        for line in _command_lines(command, width=103):
            fill = 9 if line == "exit | 0" else 3
            if line.startswith("exit |") and command.exit_status != 0:
                fill = 7
            draw.text((62, line_y), line, font=body_font, fill=fill)
            line_y += 28
        draw.text(
            (62, height - 74),
            f"receipt sha256 {receipt_document['sha256']}",
            font=body_font,
            fill=4,
        )
        frames.append(frame)

    buffer = io.BytesIO()
    frames[0].save(
        buffer,
        format="GIF",
        save_all=True,
        append_images=frames[1:],
        duration=[1400, 1200, 1400, 1400],
        loop=0,
        disposal=2,
        optimize=False,
    )
    return buffer.getvalue()


def _svg_document(
    *,
    width: int,
    height: int,
    title: str,
    description: str,
    metadata: JsonObject,
    content: str,
) -> bytes:
    metadata_text = _canonical_json(metadata, pretty=False).decode("ascii").strip()
    rendered = f"""<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" viewBox="0 0 {width} {height}" role="img" aria-labelledby="title desc">
<title id="title">{_xml(title)}</title>
<desc id="desc">{_xml(description)}</desc>
<metadata>{_xml(metadata_text)}</metadata>
<rect width="{width}" height="{height}" fill="{_SVG_BACKGROUND}"/>
{content}
</svg>
"""
    return rendered.encode("ascii")


def _svg_text(
    x: int,
    y: int,
    value: object,
    *,
    size: int,
    fill: str = _SVG_INK,
    weight: int = 400,
    anchor: str = "start",
) -> str:
    return (
        f'<text x="{x}" y="{y}" fill="{fill}" font-family="ui-monospace,'
        f'SFMono-Regular,Consolas,monospace" font-size="{size}" '
        f'font-weight="{weight}" text-anchor="{anchor}">{_xml(value)}</text>'
    )


def _render_result_svg(evidence: JsonObject, receipt: JsonObject) -> bytes:
    graph = cast(JsonObject, receipt["graph"])
    record_ids = cast(list[object], graph["record_ids"])
    components = cast(list[object], graph["components"])
    policy_groups = cast(list[object], graph["policy_groups"])
    witnesses = cast(list[object], graph["witnesses"])
    receipt_document = cast(JsonObject, evidence["receipt"])
    fixture_document = cast(JsonObject, evidence["fixture"])

    rows: list[str] = []
    row_top = 365
    for index, raw_component in enumerate(components):
        component = cast(JsonObject, raw_component)
        members = cast(list[object], component["member_record_ordinals"])
        member_labels = ", ".join(str(record_ids[cast(int, item)]) for item in members)
        policy_ordinals = cast(list[object], component["policy_ordinals"])
        policy_labels = ", ".join(str(item) for item in policy_ordinals) or "exact only"
        tree_ids = cast(list[object], component["witness_tree_ids"])
        y = row_top + index * 92
        fill = _SVG_PANEL if index % 2 == 0 else _SVG_PANEL_LIGHT
        rows.append(
            f'<rect x="70" y="{y - 38}" width="1360" height="72" rx="12" fill="{fill}"/>'
        )
        rows.append(
            _svg_text(96, y - 4, f"C{index}", size=20, fill=_SVG_TEAL, weight=700)
        )
        rows.append(_svg_text(190, y - 4, member_labels, size=18))
        rows.append(_svg_text(830, y - 4, policy_labels, size=18, fill=_SVG_CYAN))
        rows.append(_svg_text(1120, y - 4, len(tree_ids), size=18, fill=_SVG_AMBER))

    height = max(720, row_top + len(components) * 92 + 150)
    header = [
        _svg_text(70, 78, "Receipt-derived collision result", size=34, weight=700),
        _svg_text(
            70,
            120,
            "Actual installed-command receipt; labels are reviewed synthetic record IDs.",
            size=18,
            fill=_SVG_MUTED,
        ),
        f'<line x1="70" y1="150" x2="1430" y2="150" stroke="{_SVG_GRID}"/>',
    ]
    metrics = (
        ("records", len(record_ids), _SVG_TEAL),
        ("policies", len(cast(list[object], graph["policy_ids"])), _SVG_CYAN),
        ("groups", len(policy_groups), _SVG_AMBER),
        ("witnesses", len(witnesses), _SVG_PINK),
        ("components", len(components), _SVG_GREEN),
    )
    for index, (label, value, color) in enumerate(metrics):
        x = 70 + index * 270
        header.append(
            f'<rect x="{x}" y="180" width="240" height="100" rx="14" fill="{_SVG_PANEL}"/>'
        )
        header.append(_svg_text(x + 22, 222, value, size=30, fill=color, weight=700))
        header.append(_svg_text(x + 22, 258, label, size=16, fill=_SVG_MUTED))

    table = [
        _svg_text(96, 326, "component", size=15, fill=_SVG_MUTED),
        _svg_text(190, 326, "record IDs", size=15, fill=_SVG_MUTED),
        _svg_text(830, 326, "policy ordinals", size=15, fill=_SVG_MUTED),
        _svg_text(1120, 326, "tree edges", size=15, fill=_SVG_MUTED),
        *rows,
        _svg_text(
            70,
            height - 78,
            f"receipt sha256 {receipt_document['sha256']}",
            size=16,
            fill=_SVG_MUTED,
        ),
        _svg_text(
            70,
            height - 46,
            f"source sha256  {fixture_document['sha256']}",
            size=16,
            fill=_SVG_MUTED,
        ),
    ]
    metadata = {
        "kind": "receipt-derived-result",
        "receipt_sha256": receipt_document["sha256"],
        "schema": "casefold-observatory.cli-evidence-svg",
        "schema_version": 1,
        "source_sha256": fixture_document["sha256"],
    }
    return _svg_document(
        width=1500,
        height=height,
        title="Receipt-derived collision result",
        description=(
            "Component membership and witness-tree counts read from the real "
            "installed-command receipt."
        ),
        metadata=metadata,
        content="\n".join((*header, *table)),
    )


def _workflow_box(
    x: int,
    y: int,
    width: int,
    title: str,
    lines: tuple[str, ...],
    *,
    accent: str,
) -> str:
    content = [
        (
            f'<rect x="{x}" y="{y}" width="{width}" height="126" rx="16" '
            f'fill="{_SVG_PANEL}" stroke="{accent}" stroke-width="2"/>'
        ),
        _svg_text(x + 22, y + 38, title, size=20, fill=accent, weight=700),
    ]
    for index, line in enumerate(lines):
        content.append(
            _svg_text(x + 22, y + 72 + index * 25, line, size=15, fill=_SVG_MUTED)
        )
    return "\n".join(content)


def _workflow_arrow(x1: int, y1: int, x2: int, y2: int, label: str) -> str:
    middle_x = (x1 + x2) // 2
    return "\n".join(
        (
            (
                f'<line x1="{x1}" y1="{y1}" x2="{x2}" y2="{y2}" '
                f'stroke="{_SVG_GRID}" stroke-width="3"/>'
            ),
            (
                f'<path d="M {x2 - 12} {y2 - 7} L {x2} {y2} L {x2 - 12} {y2 + 7}" '
                f'fill="none" stroke="{_SVG_GRID}" stroke-width="3"/>'
            ),
            _svg_text(
                middle_x, y1 - 12, label, size=13, fill=_SVG_MUTED, anchor="middle"
            ),
        )
    )


def _render_workflow_svg(evidence: JsonObject) -> bytes:
    fixture_document = cast(JsonObject, evidence["fixture"])
    receipt_document = cast(JsonObject, evidence["receipt"])
    package_document = cast(JsonObject, evidence["package"])
    boxes = (
        _workflow_box(
            70,
            210,
            250,
            "1  exact CLI grammar",
            ("explicit files + policies", "no stdin/config/network"),
            accent=_SVG_TEAL,
        ),
        _workflow_box(
            370,
            210,
            250,
            "2  POSIX capture",
            ("dir-fd + no-follow", "stable regular single-link"),
            accent=_SVG_CYAN,
        ),
        _workflow_box(
            670,
            210,
            250,
            "3  bounded replay",
            ("JSONL -> collision graph", "canonical receipt bytes"),
            accent=_SVG_AMBER,
        ),
        _workflow_box(
            970,
            210,
            250,
            "4  durable publish",
            ("0600 temp + full writes", "fsync + no-clobber link"),
            accent=_SVG_PINK,
        ),
        _workflow_box(
            1270,
            210,
            250,
            "5  redacted channels",
            ("canonical ASCII summary", "stable status taxonomy"),
            accent=_SVG_GREEN,
        ),
    )
    arrows = (
        _workflow_arrow(320, 273, 370, 273, "argv"),
        _workflow_arrow(620, 273, 670, 273, "bytes"),
        _workflow_arrow(920, 273, 970, 273, "receipt"),
        _workflow_arrow(1220, 273, 1270, 273, "status"),
    )
    verify_boxes = (
        _workflow_box(
            330,
            485,
            340,
            "verify source + receipt",
            ("capture each identity once", "reject alias or mutation"),
            accent=_SVG_CYAN,
        ),
        _workflow_box(
            805,
            485,
            340,
            "trust-reconstruct receipt",
            ("schema + canonical bytes", "replay source and compare"),
            accent=_SVG_AMBER,
        ),
        _workflow_box(
            1280,
            485,
            240,
            "verified / mismatch",
            ("0 success", "4 replay mismatch"),
            accent=_SVG_GREEN,
        ),
    )
    verify_arrows = (
        _workflow_arrow(670, 548, 805, 548, "captured bytes"),
        _workflow_arrow(1145, 548, 1280, 548, "canonical result"),
    )
    content = [
        _svg_text(
            70,
            76,
            "Current installed CLI architecture and workflow",
            size=34,
            weight=700,
        ),
        _svg_text(
            70,
            118,
            "Explanatory diagram bound to the captured package, source, and receipt.",
            size=18,
            fill=_SVG_MUTED,
        ),
        _svg_text(
            70,
            160,
            f"runtime {package_document['runtime_tree_sha256']}  |  UCD {evidence['unicode_version']}",
            size=15,
            fill=_SVG_MUTED,
        ),
        *boxes,
        *arrows,
        _svg_text(70, 440, "verification path", size=20, fill=_SVG_TEAL, weight=700),
        *verify_boxes,
        *verify_arrows,
        _svg_text(
            70,
            700,
            f"source {fixture_document['sha256']}  |  receipt {receipt_document['sha256']}",
            size=15,
            fill=_SVG_MUTED,
        ),
        _svg_text(
            70,
            744,
            "Receipt integrity is not authentication, authorization, freshness, or anonymity.",
            size=16,
            fill=_SVG_AMBER,
        ),
    ]
    metadata = {
        "kind": "explanatory-current-cli-workflow",
        "package_version": package_document["version"],
        "receipt_sha256": receipt_document["sha256"],
        "schema": "casefold-observatory.cli-evidence-svg",
        "schema_version": 1,
        "source_sha256": fixture_document["sha256"],
        "source_revision": evidence["source_revision"],
    }
    return _svg_document(
        width=1600,
        height=810,
        title="Current installed CLI architecture and workflow",
        description=(
            "Explanatory flow from explicit CLI grammar through hardened POSIX "
            "capture, collision replay, durable publication, and verification."
        ),
        metadata=metadata,
        content="\n".join(content),
    )


def _build_outputs(
    *,
    venv_bin: Path,
    wheel: Path,
    source_revision: str,
) -> dict[str, bytes]:
    _validate_renderer_runtime()
    if _REVISION.fullmatch(source_revision) is None:
        _fail("source revision must be one lowercase 40-character commit")
    fixture = _read_regular(PROJECT_ROOT / FIXTURE_PATH, maximum=65_536)
    _read_regular(wheel, maximum=32_000_000)
    bindings = _source_bindings()
    expected_runtime_files = _expected_runtime_files(bindings)
    runtime = _runtime_probe(venv_bin, expected_files=expected_runtime_files)
    commands, receipt_bytes, analyze_summary = _capture_workflow(
        fixture=fixture,
        venv_bin=venv_bin,
    )
    try:
        receipt_value = json.loads(receipt_bytes)
    except json.JSONDecodeError:
        _fail("installed command produced a non-JSON receipt")
    if type(receipt_value) is not dict:
        _fail("installed command produced a non-object receipt")
    receipt = cast(JsonObject, receipt_value)
    if receipt_bytes != _canonical_json(receipt, pretty=False):
        _fail("installed command produced a noncanonical receipt")

    evidence: JsonObject = {
        "analyze_summary": analyze_summary,
        "artifact_inventory": list(OUTPUT_PATHS),
        "commands": [command.document() for command in commands],
        "fixture": {
            "bytes": len(fixture),
            "path": FIXTURE_PATH,
            "sha256": _sha256(fixture),
        },
        "font": {
            "implementation": "Pillow ImageFont.load_default(size), embedded limited Aileron Regular",
            "provenance": "https://pillow.readthedocs.io/en/stable/reference/ImageFont.html",
            "upstream": "https://dotcolon.net/fonts/aileron/",
        },
        "package": {
            "distribution": runtime["distribution"],
            "runtime_files": runtime["runtime_files"],
            "runtime_tree_sha256": runtime["runtime_tree_sha256"],
            "version": runtime["package_version"],
            "wheel_filename": wheel.name,
        },
        "python_implementation": runtime["implementation"],
        "python_version": runtime["python_version"],
        "receipt": {
            "adopted_git_mode": "100644",
            "bytes": len(receipt_bytes),
            "capture_mode": "0600",
            "path": RECEIPT_PATH,
            "sha256": _sha256(receipt_bytes),
            "single_link": True,
        },
        "renderer": {
            "pillow_version": PILLOW_VERSION,
            "png_size": [1400, 1060],
            "gif_size": [1200, 650],
            "gif_frame_durations_ms": [1400, 1200, 1400, 1400],
            "gif_frames": 4,
        },
        "schema": "casefold-observatory.cli-evidence",
        "schema_version": 1,
        "source_bindings": bindings,
        "source_revision": source_revision,
        "unicode_version": runtime["unicode_version"],
    }

    outputs = {
        RECEIPT_PATH: receipt_bytes,
        PNG_PATH: _render_png(evidence, commands),
        GIF_PATH: _render_gif(evidence, commands),
        RESULT_SVG_PATH: _render_result_svg(evidence, receipt),
        WORKFLOW_SVG_PATH: _render_workflow_svg(evidence),
    }
    generated_files = {
        path: {
            "bytes": len(outputs[path]),
            "sha256": _sha256(outputs[path]),
        }
        for path in HASHED_OUTPUT_PATHS
    }
    evidence["generated_files"] = generated_files
    outputs[MANIFEST_PATH] = _canonical_json(evidence, pretty=True)
    if set(outputs) != set(OUTPUT_PATHS):
        _fail("generator output inventory changed")
    _audit_outputs(outputs)
    return outputs


def _image_from_bytes(data: bytes) -> Image.Image:
    image = Image.open(io.BytesIO(data))
    image.load()
    return image


def _audit_outputs(outputs: dict[str, bytes]) -> None:
    if set(outputs) != set(OUTPUT_PATHS):
        _fail("candidate output inventory is not exact")
    for relative_path, data in outputs.items():
        if not data or len(data) > _MAX_OUTPUT_BYTES[relative_path]:
            _fail("candidate output violates its size bound")
        for forbidden in (
            b"/home/",
            b"/Users/",
            b"runner/work",
            b"AKIA",
            b"ghp_",
            b"BEGIN PRIVATE",
            b"file://",
        ):
            if forbidden in data:
                _fail("candidate output contains a forbidden host or secret marker")

    try:
        manifest_value = json.loads(outputs[MANIFEST_PATH])
    except json.JSONDecodeError:
        _fail("candidate manifest is not JSON")
    if type(manifest_value) is not dict:
        _fail("candidate manifest is not an object")
    manifest = cast(JsonObject, manifest_value)
    if outputs[MANIFEST_PATH] != _canonical_json(manifest, pretty=True):
        _fail("candidate manifest is not canonical ASCII JSON")
    if manifest.get("schema") != "casefold-observatory.cli-evidence":
        _fail("candidate manifest schema changed")
    if manifest.get("schema_version") != 1:
        _fail("candidate manifest version changed")
    if manifest.get("artifact_inventory") != list(OUTPUT_PATHS):
        _fail("candidate manifest inventory changed")
    generated_files = cast(JsonObject, manifest.get("generated_files"))
    if set(generated_files) != set(HASHED_OUTPUT_PATHS):
        _fail("candidate manifest hash inventory is not acyclic and exact")
    if MANIFEST_PATH in generated_files:
        _fail("candidate manifest must not hash itself")
    for relative_path in HASHED_OUTPUT_PATHS:
        identity = cast(JsonObject, generated_files[relative_path])
        if identity != {
            "bytes": len(outputs[relative_path]),
            "sha256": _sha256(outputs[relative_path]),
        }:
            _fail("candidate output identity mismatch")

    receipt_document = cast(JsonObject, manifest["receipt"])
    if receipt_document.get("sha256") != _sha256(outputs[RECEIPT_PATH]):
        _fail("candidate receipt identity mismatch")
    if outputs[RECEIPT_PATH] != _canonical_json(
        json.loads(outputs[RECEIPT_PATH]),
        pretty=False,
    ):
        _fail("candidate receipt is not canonical ASCII JSON")

    commands = cast(list[object], manifest["commands"])
    if tuple(cast(JsonObject, command)["id"] for command in commands) != (
        EXPECTED_COMMAND_IDS
    ):
        _fail("candidate command IDs changed")
    if tuple(cast(JsonObject, command)["exit_status"] for command in commands) != (
        EXPECTED_STATUSES
    ):
        _fail("candidate command statuses changed")
    for command in commands:
        document = cast(JsonObject, command)
        argv = cast(list[object], document["argv"])
        if not argv or not all(type(value) is str for value in argv):
            _fail("candidate argv is not exact text")
        for channel in ("stdout", "stderr"):
            value = document[channel]
            if type(value) is not str or not value.isascii():
                _fail("candidate channel is not ASCII")
            encoded = value.encode("ascii")
            if document[f"{channel}_bytes"] != len(encoded):
                _fail("candidate channel byte count changed")
            if document[f"{channel}_sha256"] != _sha256(encoded):
                _fail("candidate channel digest changed")
    for command_id, code in EXPECTED_FAILURES:
        document = next(
            cast(JsonObject, command)
            for command in commands
            if cast(JsonObject, command)["id"] == command_id
        )
        if document["stdout"] != "":
            _fail("candidate handled failure wrote stdout")
        error = json.loads(cast(str, document["stderr"]))
        if error != {"code": code, "status": "error"}:
            _fail("candidate handled failure is not redacted")

    png = _image_from_bytes(outputs[PNG_PATH])
    if png.format != "PNG" or png.mode != "RGB" or png.size != (1400, 1060):
        _fail("candidate PNG contract changed")
    if png.info:
        _fail("candidate PNG contains metadata")

    gif = Image.open(io.BytesIO(outputs[GIF_PATH]))
    if gif.format != "GIF" or gif.size != (1200, 650):
        _fail("candidate GIF contract changed")
    frame_count = 0
    durations: list[int] = []
    while True:
        durations.append(cast(int, gif.info.get("duration", 0)))
        frame_count += 1
        try:
            gif.seek(frame_count)
        except EOFError:
            break
    if frame_count != 4 or durations != [1400, 1200, 1400, 1400]:
        _fail("candidate GIF timing contract changed")
    if "comment" in gif.info:
        _fail("candidate GIF contains a comment extension")

    for relative_path in (RESULT_SVG_PATH, WORKFLOW_SVG_PATH):
        svg = outputs[relative_path]
        if not svg.isascii():
            _fail("candidate SVG is not ASCII")
        lowered = svg.lower().replace(
            b'xmlns="http://www.w3.org/2000/svg"',
            b"",
        )
        for forbidden in (
            b"<script",
            b"<foreignobject",
            b"javascript:",
            b"http://",
            b"https://",
            b"data:",
            b"@import",
        ):
            if forbidden in lowered:
                _fail("candidate SVG contains active or remote content")
        try:
            root = ET.fromstring(svg)
        except ET.ParseError:
            _fail("candidate SVG is not XML")
        if root.tag != "{http://www.w3.org/2000/svg}svg":
            _fail("candidate SVG root changed")


def _validated_output_path(root: Path, relative_path: str) -> Path:
    relative = Path(relative_path)
    if relative.is_absolute() or ".." in relative.parts:
        _fail("candidate output escaped its root")
    path = root / relative
    current = root
    for component in relative.parts[:-1]:
        current /= component
        try:
            status = os.lstat(current)
        except FileNotFoundError:
            current.mkdir(mode=0o755)
            status = os.lstat(current)
        if stat.S_ISLNK(status.st_mode) or not stat.S_ISDIR(status.st_mode):
            _fail("candidate output parent is not a real directory")
    try:
        status = os.lstat(path)
    except FileNotFoundError:
        return path
    if stat.S_ISLNK(status.st_mode) or not stat.S_ISREG(status.st_mode):
        _fail("candidate output target is unsafe")
    return path


def _write_outputs(root: Path, outputs: dict[str, bytes]) -> None:
    root.mkdir(mode=0o755, parents=True, exist_ok=True)
    root_status = os.lstat(root)
    if stat.S_ISLNK(root_status.st_mode) or not stat.S_ISDIR(root_status.st_mode):
        _fail("candidate root is not a real directory")
    for relative_path in OUTPUT_PATHS:
        path = _validated_output_path(root, relative_path)
        with path.open("xb") as stream:
            stream.write(outputs[relative_path])
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(path, 0o644)
    _audit_tree(root, exact_inventory=True)


def _read_output_set(root: Path, *, exact_inventory: bool) -> dict[str, bytes]:
    outputs: dict[str, bytes] = {}
    for relative_path in OUTPUT_PATHS:
        path = root / relative_path
        status = os.lstat(path)
        if (
            stat.S_ISLNK(status.st_mode)
            or not stat.S_ISREG(status.st_mode)
            or status.st_nlink != 1
            or stat.S_IMODE(status.st_mode) != 0o644
        ):
            _fail("candidate output is not a safe committed-style file")
        outputs[relative_path] = _read_regular(
            path,
            maximum=_MAX_OUTPUT_BYTES[relative_path],
        )
    if exact_inventory:
        observed = {
            path.relative_to(root).as_posix()
            for path in root.rglob("*")
            if not path.is_dir()
        }
        if observed != set(OUTPUT_PATHS):
            _fail("candidate tree inventory is not exact")
    _audit_outputs(outputs)
    return outputs


def _audit_tree(root: Path, *, exact_inventory: bool) -> None:
    _read_output_set(root, exact_inventory=exact_inventory)
    for path in root.rglob("*"):
        status = os.lstat(path)
        if stat.S_ISLNK(status.st_mode):
            _fail("candidate tree contains a symlink")
        if path.is_dir() and not stat.S_ISDIR(status.st_mode):
            _fail("candidate tree contains a special directory entry")


def _compare_roots(left: Path, right: Path) -> None:
    left_outputs = _read_output_set(left, exact_inventory=True)
    right_outputs = _read_output_set(right, exact_inventory=True)
    for relative_path in OUTPUT_PATHS:
        if left_outputs[relative_path] != right_outputs[relative_path]:
            _fail("independent candidate renders are not byte-identical")


def _adopted_source_revision() -> str:
    manifest_bytes = _read_regular(
        PROJECT_ROOT / MANIFEST_PATH,
        maximum=_MAX_OUTPUT_BYTES[MANIFEST_PATH],
    )
    try:
        value = json.loads(manifest_bytes)
    except json.JSONDecodeError:
        _fail("adopted manifest is not JSON")
    if type(value) is not dict:
        _fail("adopted manifest is not an object")
    revision = cast(JsonObject, value).get("source_revision")
    if type(revision) is not str or _REVISION.fullmatch(revision) is None:
        _fail("adopted manifest source revision is invalid")
    return revision


def _check_adopted(*, venv_bin: Path, wheel: Path) -> None:
    source_revision = _adopted_source_revision()
    with (
        tempfile.TemporaryDirectory(prefix="casefold-cli-check-a-") as left_directory,
        tempfile.TemporaryDirectory(prefix="casefold-cli-check-b-") as right_directory,
    ):
        left = Path(left_directory)
        right = Path(right_directory)
        _write_outputs(
            left,
            _build_outputs(
                venv_bin=venv_bin,
                wheel=wheel,
                source_revision=source_revision,
            ),
        )
        _write_outputs(
            right,
            _build_outputs(
                venv_bin=venv_bin,
                wheel=wheel,
                source_revision=source_revision,
            ),
        )
        _compare_roots(left, right)
        adopted = _read_output_set(PROJECT_ROOT, exact_inventory=False)
        candidate = _read_output_set(left, exact_inventory=True)
        for relative_path in OUTPUT_PATHS:
            if adopted[relative_path] != candidate[relative_path]:
                _fail("adopted CLI evidence is stale")
    print("CLI evidence verified (6 adopted files, two byte-exact captures)")


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Capture deterministic installed-wheel CLI evidence.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    render = subparsers.add_parser("render")
    render.add_argument("--venv-bin", required=True, type=Path)
    render.add_argument("--wheel", required=True, type=Path)
    render.add_argument("--source-revision", required=True)
    render.add_argument("--output-root", required=True, type=Path)

    compare = subparsers.add_parser("compare")
    compare.add_argument("left", type=Path)
    compare.add_argument("right", type=Path)

    check = subparsers.add_parser("check")
    check.add_argument("--venv-bin", required=True, type=Path)
    check.add_argument("--wheel", required=True, type=Path)
    return parser


def main() -> int:
    arguments = _parser().parse_args()
    if arguments.command == "render":
        outputs = _build_outputs(
            venv_bin=arguments.venv_bin,
            wheel=arguments.wheel,
            source_revision=arguments.source_revision,
        )
        _write_outputs(arguments.output_root, outputs)
        print("CLI evidence candidate rendered (6 files)")
        return 0
    if arguments.command == "compare":
        _compare_roots(arguments.left, arguments.right)
        print("CLI evidence candidates match (6 files, byte-for-byte)")
        return 0
    _check_adopted(
        venv_bin=arguments.venv_bin,
        wheel=arguments.wheel,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

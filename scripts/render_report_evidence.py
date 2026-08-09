"""Capture reproducible browser evidence for the verified offline HTML report.

This tool runs only in the pinned evidence container. It invokes an installed
wheel, keeps Chromium offline, records real viewport/full-page/scroll captures,
and never imports the project package from the source checkout.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import importlib
import io
import json
import os
import platform
import re
import stat
import subprocess
import tempfile
import zipfile
from pathlib import Path
from typing import Any, Final, NoReturn, cast

from PIL import Image
from PIL import __version__ as PILLOW_VERSION

PROJECT_ROOT: Final = Path(__file__).resolve().parents[1]
GENERATOR_PATH: Final = "scripts/render_report_evidence.py"
VERIFIER_PATH: Final = "scripts/verify_report_evidence.py"
FIXTURE_PATH: Final = "docs/report-evidence/fixtures/report-demo.v1.jsonl"
WORKFLOW_PATH: Final = ".github/workflows/report-evidence.yml"
REQUIREMENTS_PATH: Final = "requirements/report-browser.txt"
IMAGE_LOCK_PATH: Final = "requirements/report-browser-image.lock.json"
PYPROJECT_PATH: Final = "pyproject.toml"

MANIFEST_PATH: Final = "docs/report-evidence/evidence/report-evidence.v1.json"
RECEIPT_PATH: Final = "docs/report-evidence/evidence/report-demo.receipt.v1.json"
REPORT_PATH: Final = "docs/report-evidence/evidence/report-demo.v1.html"
DESKTOP_PATH: Final = "docs/report-evidence/report-desktop.png"
MOBILE_PATH: Final = "docs/report-evidence/report-mobile.png"
FULL_PAGE_PATH: Final = "docs/report-evidence/report-full-page.png"
SCROLL_PATH: Final = "docs/report-evidence/report-scroll.gif"
ARCHITECTURE_PATH: Final = "docs/report-evidence/report-architecture.svg"
OUTPUT_PATHS: Final = (
    MANIFEST_PATH,
    RECEIPT_PATH,
    REPORT_PATH,
    DESKTOP_PATH,
    MOBILE_PATH,
    FULL_PAGE_PATH,
    SCROLL_PATH,
    ARCHITECTURE_PATH,
)
SOURCE_BINDINGS: Final = (
    GENERATOR_PATH,
    VERIFIER_PATH,
    FIXTURE_PATH,
    WORKFLOW_PATH,
    REQUIREMENTS_PATH,
    IMAGE_LOCK_PATH,
    PYPROJECT_PATH,
    "README.md",
    "src/casefold_observatory/__init__.py",
    "src/casefold_observatory/__main__.py",
    "src/casefold_observatory/cli.py",
    "src/casefold_observatory/collision.py",
    "src/casefold_observatory/corpus.py",
    "src/casefold_observatory/engine.py",
    "src/casefold_observatory/filesystem.py",
    "src/casefold_observatory/model.py",
    "src/casefold_observatory/receipt.py",
    "src/casefold_observatory/report.py",
    "src/casefold_observatory/py.typed",
)
EXPECTED_PACKAGE: Final = "casefold-observatory"
EXPECTED_PACKAGE_VERSION: Final = "0.5.0"
EXPECTED_PLAYWRIGHT: Final = "1.62.0"
EXPECTED_CHROMIUM: Final = "151.0.7922.34"
EXPECTED_PILLOW: Final = "12.3.0"
EXPECTED_CONTAINER: Final = (
    "mcr.microsoft.com/playwright/python@"
    "sha256:51d31fdfacb0cff99a1a724152e34ae408d2bd4e7da310ff157450f49261cc59"
)
EXPECTED_MACHINE: Final = "x86_64"
_REVISION = re.compile(r"[0-9a-f]{40}\Z")
MAX_FILE_BYTES: Final = {
    MANIFEST_PATH: 524_288,
    RECEIPT_PATH: 1_048_576,
    REPORT_PATH: 8_388_608,
    DESKTOP_PATH: 4_194_304,
    MOBILE_PATH: 2_097_152,
    FULL_PAGE_PATH: 12_582_912,
    SCROLL_PATH: 12_582_912,
    ARCHITECTURE_PATH: 262_144,
}
JsonObject = dict[str, object]


def _fail(message: str) -> NoReturn:
    raise RuntimeError(message) from None


def _sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _canonical_json(value: object) -> bytes:
    return (
        json.dumps(
            value,
            ensure_ascii=True,
            allow_nan=False,
            indent=2,
            sort_keys=True,
        ).encode("ascii")
        + b"\n"
    )


def _read(path: Path, limit: int) -> bytes:
    if path.is_symlink():
        _fail("evidence input must not be a symlink")
    before = path.stat()
    if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
        _fail("evidence input must be a single-link regular file")
    if before.st_size > limit:
        _fail("evidence input exceeds its byte limit")
    with path.open("rb") as stream:
        payload = stream.read(limit + 1)
    after = path.stat()
    before_identity = (
        before.st_dev,
        before.st_ino,
        before.st_size,
        before.st_mtime_ns,
        before.st_ctime_ns,
    )
    after_identity = (
        after.st_dev,
        after.st_ino,
        after.st_size,
        after.st_mtime_ns,
        after.st_ctime_ns,
    )
    if before_identity != after_identity:
        _fail("evidence input changed during capture")
    if len(payload) > limit:
        _fail("evidence input exceeds its byte limit")
    return payload


def _write(root: Path, relative: str, payload: bytes) -> None:
    if len(payload) > MAX_FILE_BYTES[relative]:
        _fail(f"generated file exceeded limit: {relative}")
    target = root / relative
    target.parent.mkdir(parents=True, exist_ok=True)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    flags |= getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(target, flags, 0o644)
    try:
        view = memoryview(payload)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                _fail("short evidence write")
            view = view[written:]
        os.fchmod(descriptor, 0o644)
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _command(
    argv: tuple[str, ...],
    display_argv: tuple[str, ...],
    *,
    cwd: Path,
) -> tuple[subprocess.CompletedProcess[bytes], JsonObject]:
    environment = os.environ.copy()
    environment.pop("PYTHONPATH", None)
    evidence_site_root = os.environ.get("EVIDENCE_SITE_ROOT")
    if evidence_site_root is None:
        _fail("isolated evidence site root is missing")
    site_root = Path(evidence_site_root)
    if not site_root.is_absolute() or site_root.is_symlink() or not site_root.is_dir():
        _fail("isolated evidence site root is invalid")
    environment["PYTHONPATH"] = site_root.as_posix()
    environment["PYTHONNOUSERSITE"] = "1"
    completed = subprocess.run(
        argv,
        cwd=cwd,
        env=environment,
        check=False,
        capture_output=True,
    )
    if len(completed.stdout) > 16_384 or len(completed.stderr) > 16_384:
        _fail("captured CLI channel exceeded limit")
    for channel in (completed.stdout, completed.stderr):
        if not channel.isascii():
            _fail("captured CLI channel was not ASCII")
    return completed, {
        "argv": list(display_argv),
        "exit_status": completed.returncode,
        "stderr": completed.stderr.decode("ascii"),
        "stderr_bytes": len(completed.stderr),
        "stderr_sha256": _sha256(completed.stderr),
        "stdout": completed.stdout.decode("ascii"),
        "stdout_bytes": len(completed.stdout),
        "stdout_sha256": _sha256(completed.stdout),
    }


def _json_line(channel: bytes) -> JsonObject:
    if not channel.endswith(b"\n") or channel.count(b"\n") != 1:
        _fail("successful CLI output must be exactly one line")
    value: object = json.loads(channel)
    if type(value) is not dict:
        _fail("successful CLI output must be an object")
    return cast(JsonObject, value)


def _installed_runtime(venv_python: Path) -> JsonObject:
    probe = r"""
import hashlib
import importlib.metadata
import json
import platform
import sys
import unicodedata
from pathlib import Path

import os
import casefold_observatory

package_root = Path(casefold_observatory.__file__).resolve().parent
site_root = Path(os.environ["EVIDENCE_SITE_ROOT"]).resolve()
if not package_root.is_relative_to(site_root):
    raise RuntimeError("project package was not imported from the isolated target")
files = {}
for path in sorted(package_root.iterdir()):
    if path.is_file() and (path.suffix == ".py" or path.name == "py.typed"):
        payload = path.read_bytes()
        files[path.name] = {
            "bytes": len(payload),
            "sha256": hashlib.sha256(payload).hexdigest(),
        }
print(json.dumps({
    "implementation": platform.python_implementation(),
    "package_files": files,
    "package_version": importlib.metadata.version("casefold-observatory"),
    "python_version": platform.python_version(),
    "unicode_version": unicodedata.unidata_version,
}, sort_keys=True, separators=(",", ":")))
"""
    completed = subprocess.run(
        (venv_python.as_posix(), "-c", probe),
        cwd=Path("/tmp"),
        check=True,
        capture_output=True,
        text=True,
    )
    value: object = json.loads(completed.stdout)
    if type(value) is not dict:
        _fail("installed runtime probe returned a non-object")
    result = cast(JsonObject, value)
    if result.get("implementation") != "CPython":
        _fail("evidence runtime must be CPython")
    if result.get("package_version") != EXPECTED_PACKAGE_VERSION:
        _fail("installed package version changed")
    return result


def _font_identity(pattern: str) -> JsonObject:
    completed = subprocess.run(
        ("fc-match", "-f", "%{file}\n%{family}\n%{style}\n", pattern),
        check=True,
        capture_output=True,
        text=True,
    )
    lines = completed.stdout.splitlines()
    if len(lines) < 3:
        _fail("fontconfig returned an incomplete identity")
    path = Path(lines[0])
    payload = _read(path, 32 * 1024 * 1024)
    return {
        "bytes": len(payload),
        "family": lines[1],
        "file": path.name,
        "sha256": _sha256(payload),
        "style": lines[2],
    }


def _normalize_png(payload: bytes) -> tuple[bytes, JsonObject]:
    with Image.open(io.BytesIO(payload)) as source:
        source.load()
        image = source.convert("RGB")
    output = io.BytesIO()
    image.save(output, format="PNG", optimize=False, compress_level=9)
    normalized = output.getvalue()
    with Image.open(io.BytesIO(normalized)) as checked:
        checked.load()
        if checked.mode != "RGB" or checked.info:
            _fail("normalized PNG retained metadata or changed mode")
        width, height = checked.size
    return normalized, {"height": height, "mode": "RGB", "width": width}


def _page_assertions(page: Any) -> JsonObject:
    value: object = page.evaluate(
        """() => {
          const allowed = new Set([
            "ARTICLE","BODY","BR","CODE","DIV","FOOTER","H1","H2","H3",
            "HEAD","HTML","LI","MAIN","META","OL","P","SECTION","SMALL",
            "SPAN","STRONG","STYLE","TABLE","TBODY","TD","TH","THEAD",
            "TITLE","TR"
          ]);
          const urlAttrs = new Set([
            "action","cite","data","formaction","href","poster","src","srcset"
          ]);
          const elements = [...document.querySelectorAll("*")];
          const badTags = elements.filter(el => !allowed.has(el.tagName))
            .map(el => el.tagName);
          const badAttrs = [];
          for (const el of elements) {
            for (const attr of [...el.attributes]) {
              if (attr.name.startsWith("on") || attr.name === "style" ||
                  urlAttrs.has(attr.name)) {
                badAttrs.push(el.tagName + ":" + attr.name);
              }
            }
          }
          const text = document.documentElement.textContent || "";
          const csp = [...document.querySelectorAll(
            'meta[http-equiv="Content-Security-Policy"]'
          )].map(el => el.getAttribute("content"));
          const style = [...document.querySelectorAll("style")]
            .map(el => el.textContent || "");
          return {
            bad_attributes: badAttrs,
            bad_tags: badTags,
            body_background: getComputedStyle(document.body).backgroundColor,
            csp,
            document_client_width: document.documentElement.clientWidth,
            document_scroll_height: document.documentElement.scrollHeight,
            document_scroll_width: document.documentElement.scrollWidth,
            style,
            text_ascii: [...text].every(ch => ch.codePointAt(0) <= 127)
          };
        }"""
    )
    if type(value) is not dict:
        _fail("browser DOM probe returned a non-object")
    result = cast(JsonObject, value)
    if result.get("bad_attributes") != [] or result.get("bad_tags") != []:
        _fail("report DOM escaped its active-content allowlist")
    if result.get("text_ascii") is not True:
        _fail("decoded report DOM text was not ASCII")
    if result.get("body_background") != "rgb(9, 16, 21)":
        _fail("hash-bound report stylesheet did not apply")
    scroll_width = result.get("document_scroll_width")
    client_width = result.get("document_client_width")
    scroll_height = result.get("document_scroll_height")
    if (
        type(scroll_width) is not int
        or type(client_width) is not int
        or type(scroll_height) is not int
        or scroll_width > client_width
        or scroll_height < 1_200
        or scroll_height > 30_000
    ):
        _fail("report layout escaped reviewed bounds")
    csp = result.get("csp")
    styles = result.get("style")
    if type(csp) is not list or len(csp) != 1:
        _fail("browser found the wrong CSP count")
    if type(styles) is not list or len(styles) != 1 or type(styles[0]) is not str:
        _fail("browser found the wrong stylesheet count")
    style_hash = hashlib.sha256(styles[0].encode("ascii")).digest()
    directive = "'sha256-" + base64.b64encode(style_hash).decode("ascii") + "'"
    if type(csp[0]) is not str or directive not in csp[0]:
        _fail("browser CSP did not bind the exact stylesheet")
    result.pop("style")
    return result


def _capture_page(
    browser: Any,
    report_path: Path,
    *,
    viewport: tuple[int, int],
    mobile: bool,
    full_page: bool,
) -> tuple[bytes, JsonObject, Any]:
    context = browser.new_context(
        color_scheme="dark",
        device_scale_factor=1,
        has_touch=mobile,
        is_mobile=mobile,
        java_script_enabled=True,
        locale="en-US",
        offline=True,
        reduced_motion="reduce",
        service_workers="block",
        timezone_id="UTC",
        viewport={"height": viewport[1], "width": viewport[0]},
    )
    requests: list[tuple[str, str]] = []
    console_messages: list[tuple[str, str]] = []
    page_errors: list[str] = []
    popups: list[str] = []
    context.on(
        "request", lambda request: requests.append((request.resource_type, request.url))
    )
    context.on("page", lambda _page: popups.append("popup"))
    page = context.new_page()
    page.on(
        "console", lambda message: console_messages.append((message.type, message.text))
    )
    page.on("pageerror", lambda error: page_errors.append(str(error)))
    uri = report_path.resolve().as_uri()
    page.goto(uri, wait_until="load")
    page.emulate_media(color_scheme="dark", reduced_motion="reduce")
    assertions = _page_assertions(page)
    if requests != [("document", uri)]:
        _fail("browser loaded a subresource or unexpected document")
    if console_messages or page_errors or popups:
        _fail("clean report load produced a browser error or popup")
    raw = page.screenshot(full_page=full_page, animations="disabled")
    png, image = _normalize_png(raw)
    assertions.update(
        {
            "console_errors": 0,
            "image": image,
            "page_errors": 0,
            "popup_count": 0,
            "request_count": 1,
            "resource_types": ["document"],
            "subresource_request_count": 0,
            "viewport": {"height": viewport[1], "width": viewport[0]},
        }
    )
    return png, assertions, (context, page)


def _csp_negative_probe(page: Any) -> JsonObject:
    result: object = page.evaluate(
        """() => {
          window.__casefold_probe = "blocked";
          const script = document.createElement("script");
          script.textContent = 'window.__casefold_probe = "executed"';
          document.body.appendChild(script);
          const before = getComputedStyle(document.body).backgroundColor;
          const style = document.createElement("style");
          style.textContent = "body{background:rgb(1,2,3)!important}";
          document.head.appendChild(style);
          const after = getComputedStyle(document.body).backgroundColor;
          return {
            inline_script_blocked: window.__casefold_probe === "blocked",
            tampered_style_blocked: before === after,
            observed_background: after
          };
        }"""
    )
    if type(result) is not dict:
        _fail("CSP negative probe returned a non-object")
    probe = cast(JsonObject, result)
    if (
        probe.get("inline_script_blocked") is not True
        or probe.get("tampered_style_blocked") is not True
    ):
        _fail("CSP negative probe executed injected content")
    return probe


def _scroll_gif(page: Any, scroll_height: int) -> tuple[bytes, JsonObject]:
    viewport_height = 1_000
    maximum = max(0, scroll_height - viewport_height)
    requested = tuple(round(maximum * fraction / 3) for fraction in range(4))
    frames: list[Image.Image] = []
    frame_hashes: list[str] = []
    observed: list[int] = []
    for position in requested:
        page.evaluate("(y) => window.scrollTo({top:y,behavior:'instant'})", position)
        actual = page.evaluate("() => Math.round(window.scrollY)")
        if type(actual) is not int:
            _fail("browser returned a non-integer scroll position")
        observed.append(actual)
        raw = page.screenshot(full_page=False, animations="disabled")
        png, info = _normalize_png(raw)
        if info != {"height": 1_000, "mode": "RGB", "width": 1_440}:
            _fail("scroll frame dimensions changed")
        frame_hashes.append(_sha256(png))
        with Image.open(io.BytesIO(png)) as source:
            source.load()
            frames.append(
                source.convert("RGB").quantize(
                    colors=128,
                    method=Image.Quantize.MAXCOVERAGE,
                    dither=Image.Dither.NONE,
                )
            )
    if observed[0] != 0 or observed[-1] != maximum or maximum <= 0:
        _fail("real browser scroll did not cover the document")
    output = io.BytesIO()
    frames[0].save(
        output,
        format="GIF",
        save_all=True,
        append_images=frames[1:],
        duration=[1_100, 1_100, 1_100, 1_500],
        loop=0,
        disposal=2,
        optimize=False,
    )
    payload = output.getvalue()
    with Image.open(io.BytesIO(payload)) as gif:
        gif.load()
        if gif.size != (1_440, 1_000) or getattr(gif, "n_frames", 1) != 4:
            _fail("scroll GIF structure changed")
        if "comment" in gif.info or "transparency" in gif.info:
            _fail("scroll GIF retained metadata or transparency")
    return payload, {
        "durations_ms": [1_100, 1_100, 1_100, 1_500],
        "frame_png_sha256": frame_hashes,
        "frames": 4,
        "observed_scroll_y": observed,
        "requested_scroll_y": list(requested),
        "source": "four real Chromium viewport screenshots after scrollTo",
    }


def _architecture_svg() -> bytes:
    boxes = (
        ("01", "Exact inputs", "stable source + canonical receipt"),
        ("02", "Installed wheel", "analyze -> report -> verify"),
        ("03", "Safe publish", "mode 0600 + no clobber"),
        ("04", "Offline Chromium", "JS on + CSP + zero subresources"),
        ("05", "Real captures", "desktop + mobile + full page + scroll"),
        ("06", "Independent gate", "structure + hashes + human adoption"),
    )
    parts = [
        (
            '<svg xmlns="http://www.w3.org/2000/svg" width="1440" height="560" '
            'viewBox="0 0 1440 560" role="img" '
            'aria-labelledby="title description">'
        ),
        '<title id="title">Casefold Observatory report evidence architecture</title>',
        (
            '<desc id="description">Six-stage offline evidence flow from exact '
            "inputs to independently reviewed browser artifacts.</desc>"
        ),
        '<rect width="1440" height="560" fill="#091015"/>',
        '<text x="72" y="76" fill="#63e6d2" ',
        'font-family="monospace" font-size="18" font-weight="700">',
        "VERIFIED OFFLINE REPORT / EVIDENCE FLOW</text>",
        '<text x="72" y="122" fill="#edf5f1" ',
        'font-family="sans-serif" font-size="34" font-weight="700">',
        "Real browser output, bound to exact bytes.</text>",
    ]
    for index, (number, title, detail) in enumerate(boxes):
        column = index % 3
        row = index // 3
        x = 72 + column * 440
        y = 175 + row * 170
        parts.extend(
            (
                (
                    f'<rect x="{x}" y="{y}" width="392" height="126" rx="18" '
                    'fill="#111c21" stroke="#36505a"/>'
                ),
                (
                    f'<text x="{x + 24}" y="{y + 35}" fill="#f4c95d" '
                    f'font-family="monospace" font-size="14" font-weight="700">'
                    f"{number}</text>"
                ),
                (
                    f'<text x="{x + 24}" y="{y + 70}" fill="#edf5f1" '
                    f'font-family="sans-serif" font-size="22" font-weight="700">'
                    f"{title}</text>"
                ),
                (
                    f'<text x="{x + 24}" y="{y + 98}" fill="#9fb4ad" '
                    f'font-family="monospace" font-size="13">{detail}</text>'
                ),
            )
        )
    parts.extend(
        (
            (
                '<path d="M464 238H502M904 238H942M1268 301V345'
                'M942 408H904M502 408H464" stroke="#63e6d2" '
                'stroke-width="4" fill="none"/>'
            ),
            (
                '<text x="72" y="520" fill="#9fb4ad" font-family="monospace" '
                'font-size="14">No network during capture / synthetic data only / '
                "artifact adoption is a separate reviewed commit</text>"
            ),
            "</svg>",
        )
    )
    return ("".join(parts) + "\n").encode("ascii")


def _source_bindings() -> JsonObject:
    result: JsonObject = {}
    for relative in SOURCE_BINDINGS:
        payload = _read(PROJECT_ROOT / relative, 2 * 1024 * 1024)
        result[relative] = {"bytes": len(payload), "sha256": _sha256(payload)}
    return result


def _wheel_identity(wheel: Path) -> JsonObject:
    payload = _read(wheel, 8 * 1024 * 1024)
    with zipfile.ZipFile(io.BytesIO(payload)) as archive:
        names = sorted(archive.namelist())
        if any(name.startswith("/") or ".." in Path(name).parts for name in names):
            _fail("wheel contains an unsafe path")
    return {
        "bytes": len(payload),
        "filename": wheel.name,
        "sha256": _sha256(payload),
    }


def _render(
    *,
    venv_bin: Path,
    wheel: Path,
    source_revision: str,
    source_tree: str,
    container_image: str,
    output_root: Path,
) -> None:
    if _REVISION.fullmatch(source_revision) is None:
        _fail("source revision must be 40 lowercase hexadecimal characters")
    if _REVISION.fullmatch(source_tree) is None:
        _fail("source tree must be 40 lowercase hexadecimal characters")
    if container_image != EXPECTED_CONTAINER:
        _fail("capture container identity changed")
    if output_root.exists():
        if output_root.is_symlink() or any(output_root.iterdir()):
            _fail("output root must be a new or empty directory")
    else:
        output_root.mkdir(parents=True)
    if platform.system() != "Linux" or platform.machine() != EXPECTED_MACHINE:
        _fail("capture must run on Linux x86-64")
    if os.geteuid() == 0:
        _fail("capture container must run as a non-root user")
    if PILLOW_VERSION != EXPECTED_PILLOW:
        _fail("Pillow version changed")
    playwright_metadata = importlib.import_module("importlib.metadata")
    if playwright_metadata.version("playwright") != EXPECTED_PLAYWRIGHT:
        _fail("Playwright version changed")

    fixture = _read(PROJECT_ROOT / FIXTURE_PATH, 64 * 1024)
    if not fixture.isascii() or not fixture.endswith(b"\n"):
        _fail("report fixture must be canonical ASCII JSON Lines")
    venv_python = venv_bin / "python"
    if not venv_python.is_file():
        _fail("evidence Python executable is missing")
    runtime = _installed_runtime(venv_python)
    command_prefix = (
        venv_python.as_posix(),
        "-m",
        "casefold_observatory",
    )

    with tempfile.TemporaryDirectory(prefix="report-evidence-", dir="/tmp") as name:
        temporary = Path(name)
        source = temporary / "source.jsonl"
        receipt = temporary / "result.receipt.json"
        report = temporary / "result.html"
        source.write_bytes(fixture)
        os.chmod(source, 0o600)
        policies = (
            "preserve@case:lower,case:casefold",
            "preserve@normalize:nfc,case:casefold",
            "preserve@normalize:nfkc,case:casefold",
        )
        analyze_argv = (
            *command_prefix,
            "analyze",
            "--source",
            source.as_posix(),
            "--policy",
            policies[0],
            "--policy",
            policies[1],
            "--policy",
            policies[2],
            "--receipt",
            receipt.as_posix(),
        )
        analyze_display = (
            "python",
            "-m",
            "casefold_observatory",
            "analyze",
            "--source",
            "$FIXTURE",
            "--policy",
            policies[0],
            "--policy",
            policies[1],
            "--policy",
            policies[2],
            "--receipt",
            "$RECEIPT",
        )
        analyzed, analyzed_doc = _command(
            analyze_argv,
            analyze_display,
            cwd=temporary,
        )
        if analyzed.returncode != 0 or analyzed.stderr:
            _fail("installed analyze command failed")
        analyze_summary = _json_line(analyzed.stdout)
        if analyze_summary.get("status") != "analyzed":
            _fail("installed analyze status changed")

        reported, reported_doc = _command(
            (
                *command_prefix,
                "report",
                "--source",
                source.as_posix(),
                "--receipt",
                receipt.as_posix(),
                "--output",
                report.as_posix(),
            ),
            (
                "python",
                "-m",
                "casefold_observatory",
                "report",
                "--source",
                "$FIXTURE",
                "--receipt",
                "$RECEIPT",
                "--output",
                "$REPORT",
            ),
            cwd=temporary,
        )
        if reported.returncode != 0 or reported.stderr:
            _fail("installed report command failed")
        report_summary = _json_line(reported.stdout)
        if report_summary.get("status") != "reported":
            _fail("installed report status changed")

        verified, verified_doc = _command(
            (
                *command_prefix,
                "verify",
                "--source",
                source.as_posix(),
                "--receipt",
                receipt.as_posix(),
            ),
            (
                "python",
                "-m",
                "casefold_observatory",
                "verify",
                "--source",
                "$FIXTURE",
                "--receipt",
                "$RECEIPT",
            ),
            cwd=temporary,
        )
        if verified.returncode != 0 or verified.stderr:
            _fail("installed verify command failed")
        verify_summary = _json_line(verified.stdout)
        if verify_summary.get("status") != "verified":
            _fail("installed verify status changed")

        receipt_bytes = _read(receipt, 1_048_576)
        report_bytes = _read(report, 8_388_608)
        for runtime_path in (receipt, report):
            mode = stat.S_IMODE(runtime_path.stat().st_mode)
            if mode != 0o600 or runtime_path.stat().st_nlink != 1:
                _fail("runtime output lost mode-0600 single-link semantics")
        if not report_bytes.isascii():
            _fail("offline report source must be ASCII")
        if analyze_summary.get("receipt_sha256") != _sha256(receipt_bytes):
            _fail("analyze receipt digest changed")
        if verify_summary.get("receipt_sha256") != _sha256(receipt_bytes):
            _fail("verify receipt digest changed")
        if report_summary.get("receipt_sha256") != _sha256(receipt_bytes):
            _fail("report receipt digest changed")
        if report_summary.get("report_sha256") != _sha256(report_bytes):
            _fail("report output digest changed")
        if report_summary.get("report_byte_count") != len(report_bytes):
            _fail("report byte count changed")

        sync_api = importlib.import_module("playwright.sync_api")
        with sync_api.sync_playwright() as playwright:
            executable = Path(playwright.chromium.executable_path)
            executable_bytes = _read(executable, 512 * 1024 * 1024)
            # GitHub-hosted Docker does not expose a usable Chromium user
            # namespace. The trusted local report is instead contained by the
            # non-root, no-network, read-only, cap-drop=ALL outer container.
            browser = playwright.chromium.launch(
                args=("--disable-dev-shm-usage", "--force-color-profile=srgb"),
                chromium_sandbox=False,
                headless=True,
            )
            version = browser.version
            if version != EXPECTED_CHROMIUM:
                browser.close()
                _fail("Chromium version changed")
            desktop, desktop_checks, desktop_state = _capture_page(
                browser,
                report,
                viewport=(1_440, 1_000),
                mobile=False,
                full_page=False,
            )
            desktop_context, desktop_page = desktop_state
            full_page, full_checks, full_state = _capture_page(
                browser,
                report,
                viewport=(1_440, 1_000),
                mobile=False,
                full_page=True,
            )
            full_context, _full_page = full_state
            mobile_png, mobile_checks, mobile_state = _capture_page(
                browser,
                report,
                viewport=(390, 844),
                mobile=True,
                full_page=False,
            )
            mobile_context, _mobile_page = mobile_state
            scroll_height = cast(int, desktop_checks["document_scroll_height"])
            scroll_gif, scroll_checks = _scroll_gif(desktop_page, scroll_height)
            csp_probe = _csp_negative_probe(desktop_page)
            desktop_context.close()
            full_context.close()
            mobile_context.close()
            browser.close()

        architecture = _architecture_svg()
        payloads = {
            RECEIPT_PATH: receipt_bytes,
            REPORT_PATH: report_bytes,
            DESKTOP_PATH: desktop,
            MOBILE_PATH: mobile_png,
            FULL_PAGE_PATH: full_page,
            SCROLL_PATH: scroll_gif,
            ARCHITECTURE_PATH: architecture,
        }
        artifacts = {
            path: {"bytes": len(payload), "sha256": _sha256(payload)}
            for path, payload in sorted(payloads.items())
        }
        os_release: dict[str, str] = {}
        for line in Path("/etc/os-release").read_text(encoding="utf-8").splitlines():
            key, separator, value = line.partition("=")
            if separator and key in {"ID", "VERSION_ID"}:
                os_release[key.lower()] = value.strip('"')
        manifest: JsonObject = {
            "artifacts": artifacts,
            "browser": {
                "assertions": {
                    "csp_negative_probe": csp_probe,
                    "desktop": desktop_checks,
                    "full_page": full_checks,
                    "mobile_emulation": mobile_checks,
                    "scroll": scroll_checks,
                },
                "chromium_executable_bytes": len(executable_bytes),
                "chromium_executable_sha256": _sha256(executable_bytes),
                "chromium_version": version,
                "container_image": container_image,
                "java_script_enabled": True,
                "launch_args": [
                    "--disable-dev-shm-usage",
                    "--force-color-profile=srgb",
                ],
                "network": "none",
                "outer_isolation": {
                    "capabilities": "dropped",
                    "network": "none",
                    "new_privileges": False,
                    "root_filesystem": "read_only",
                    "runtime_user": "non_root",
                },
                "playwright_version": EXPECTED_PLAYWRIGHT,
                "process_sandbox": False,
                "service_workers": "block",
            },
            "commands": [
                analyzed_doc,
                reported_doc,
                verified_doc,
            ],
            "environment": {
                "architecture": platform.machine(),
                "fonts": {
                    "monospace": _font_identity("monospace"),
                    "sans_serif": _font_identity("sans-serif"),
                },
                "operating_system": os_release,
                "pillow_version": PILLOW_VERSION,
                "python": runtime,
            },
            "fixture": {
                "bytes": len(fixture),
                "path": FIXTURE_PATH,
                "record_count": len(fixture.splitlines()) - 1,
                "sha256": _sha256(fixture),
                "synthetic": True,
            },
            "generated_files": list(OUTPUT_PATHS),
            "package": {
                "distribution": EXPECTED_PACKAGE,
                "runtime": runtime,
                "wheel": _wheel_identity(wheel),
            },
            "runtime_outputs": {
                "receipt": {
                    "bytes": len(receipt_bytes),
                    "mode": "0600",
                    "nlink": 1,
                    "sha256": _sha256(receipt_bytes),
                },
                "report": {
                    "bytes": len(report_bytes),
                    "mode": "0600",
                    "nlink": 1,
                    "sha256": _sha256(report_bytes),
                },
            },
            "schema": "casefold-observatory.report-evidence",
            "schema_version": 1,
            "source": {
                "bindings": _source_bindings(),
                "revision": source_revision,
                "tree": source_tree,
            },
        }
        manifest_bytes = _canonical_json(manifest)
        for relative, payload in payloads.items():
            _write(output_root, relative, payload)
        _write(output_root, MANIFEST_PATH, manifest_bytes)
    print(f"report evidence candidate rendered ({len(OUTPUT_PATHS)} files)")


def _compare(left: Path, right: Path) -> None:
    for relative in OUTPUT_PATHS:
        left_payload = _read(left / relative, MAX_FILE_BYTES[relative])
        right_payload = _read(right / relative, MAX_FILE_BYTES[relative])
        if left_payload != right_payload:
            _fail(f"report evidence differs: {relative}")
    print(f"report evidence candidates match ({len(OUTPUT_PATHS)} files)")


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)
    render = subparsers.add_parser("render")
    render.add_argument("--venv-bin", type=Path, required=True)
    render.add_argument("--wheel", type=Path, required=True)
    render.add_argument("--source-revision", required=True)
    render.add_argument("--source-tree", required=True)
    render.add_argument("--container-image", required=True)
    render.add_argument("--output-root", type=Path, required=True)
    compare = subparsers.add_parser("compare")
    compare.add_argument("left", type=Path)
    compare.add_argument("right", type=Path)
    return parser


def main() -> int:
    arguments = _parser().parse_args()
    if arguments.command == "render":
        _render(
            venv_bin=arguments.venv_bin,
            wheel=arguments.wheel,
            source_revision=arguments.source_revision,
            source_tree=arguments.source_tree,
            container_image=arguments.container_image,
            output_root=arguments.output_root,
        )
    else:
        _compare(arguments.left, arguments.right)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

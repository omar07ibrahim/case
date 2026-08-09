"""Independently verify the exact report-evidence bundle.

The verifier does not import the generator or the project package. Browser and
package behavior are treated as untrusted evidence and checked from bytes.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import importlib
import io
import json
import re
import stat
import xml.etree.ElementTree as ET
import zipfile
from html.parser import HTMLParser
from pathlib import Path
from typing import Final, NoReturn, cast

PROJECT_ROOT: Final = Path(__file__).resolve().parents[1]
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
HASHED_OUTPUT_PATHS: Final = tuple(
    path for path in OUTPUT_PATHS if path != MANIFEST_PATH
)
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
EXPECTED_SOURCE_BINDINGS: Final = (
    "scripts/render_report_evidence.py",
    "scripts/verify_report_evidence.py",
    "docs/report-evidence/fixtures/report-demo.v1.jsonl",
    ".github/workflows/report-evidence.yml",
    "requirements/report-browser.txt",
    "requirements/report-browser-image.lock.json",
    "pyproject.toml",
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
EXPECTED_CONTAINER: Final = (
    "mcr.microsoft.com/playwright/python@"
    "sha256:51d31fdfacb0cff99a1a724152e34ae408d2bd4e7da310ff157450f49261cc59"
)
EXPECTED_CHROMIUM: Final = "151.0.7922.34"
EXPECTED_PLAYWRIGHT: Final = "1.62.0"
EXPECTED_PILLOW: Final = "12.3.0"
_REVISION = re.compile(r"[0-9a-f]{40}\Z")
_DIGEST = re.compile(r"[0-9a-f]{64}\Z")
JsonObject = dict[str, object]


def _fail(message: str) -> NoReturn:
    raise RuntimeError(message) from None


def _sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _read(path: Path, limit: int) -> bytes:
    if path.is_symlink():
        _fail("evidence file must not be a symlink")
    before = path.stat()
    if (
        not stat.S_ISREG(before.st_mode)
        or before.st_nlink != 1
        or stat.S_IMODE(before.st_mode) != 0o644
    ):
        _fail("evidence file must be a single-link mode-0644 regular file")
    if before.st_size > limit:
        _fail("evidence file exceeds its byte limit")
    payload = path.read_bytes()
    after = path.stat()
    if (
        before.st_dev,
        before.st_ino,
        before.st_size,
        before.st_mtime_ns,
        before.st_ctime_ns,
    ) != (
        after.st_dev,
        after.st_ino,
        after.st_size,
        after.st_mtime_ns,
        after.st_ctime_ns,
    ):
        _fail("evidence file changed during verification")
    if len(payload) > limit:
        _fail("evidence file exceeds its byte limit")
    return payload


def _object(value: object) -> JsonObject:
    if type(value) is not dict:
        _fail("expected a JSON object")
    return cast(JsonObject, value)


def _canonical_json(payload: bytes, *, pretty: bool) -> JsonObject:
    if not payload.isascii() or not payload.endswith(b"\n"):
        _fail("JSON evidence must be canonical ASCII plus LF")
    value: object = json.loads(payload)
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
    expected = rendered.encode("ascii") + b"\n"
    if expected != payload:
        _fail("JSON evidence is not canonical")
    return _object(value)


class _ReportParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.tags: list[str] = []
        self.attributes: list[tuple[str, str, str | None]] = []
        self.data: list[str] = []
        self.comments = 0
        self.csp: list[str] = []
        self.styles: list[str] = []
        self.receipt_digests: list[str] = []
        self._inside_style = False

    def handle_starttag(
        self,
        tag: str,
        attrs: list[tuple[str, str | None]],
    ) -> None:
        self.tags.append(tag)
        values = dict(attrs)
        for name, value in attrs:
            self.attributes.append((tag, name, value))
        if tag == "meta" and values.get("http-equiv") == "Content-Security-Policy":
            content = values.get("content")
            if content is None:
                _fail("CSP meta omitted content")
            self.csp.append(content)
        if tag == "main":
            digest = values.get("data-receipt-sha256")
            if digest is not None:
                self.receipt_digests.append(digest)
        if tag == "style":
            self._inside_style = True

    def handle_endtag(self, tag: str) -> None:
        if tag == "style":
            self._inside_style = False

    def handle_data(self, data: str) -> None:
        self.data.append(data)
        if self._inside_style:
            self.styles.append(data)

    def handle_comment(self, _data: str) -> None:
        self.comments += 1


def _verify_html(payload: bytes, receipt_sha256: str) -> None:
    if not payload.isascii() or not payload.startswith(b"<!doctype html>\n"):
        _fail("report must be ASCII HTML with the exact doctype")
    parser = _ReportParser()
    parser.feed(payload.decode("ascii"))
    parser.close()
    if not "".join(parser.data).isascii():
        _fail("decoded DOM text was not ASCII")
    allowed_tags = {
        "article",
        "body",
        "br",
        "code",
        "div",
        "footer",
        "h1",
        "h2",
        "h3",
        "head",
        "html",
        "li",
        "main",
        "meta",
        "ol",
        "p",
        "section",
        "small",
        "span",
        "strong",
        "style",
        "table",
        "tbody",
        "td",
        "th",
        "thead",
        "title",
        "tr",
    }
    if not set(parser.tags).issubset(allowed_tags):
        _fail("report contains a forbidden element")
    url_attributes = {
        "action",
        "cite",
        "data",
        "formaction",
        "href",
        "poster",
        "src",
        "srcset",
    }
    for _tag, name, _value in parser.attributes:
        if name.startswith("on") or name == "style" or name in url_attributes:
            _fail("report contains an active or URL-bearing attribute")
    if parser.comments:
        _fail("report contains an HTML comment")
    if len(parser.csp) != 1 or len(parser.styles) != 1:
        _fail("report must contain exactly one CSP and stylesheet")
    style = parser.styles[0].encode("ascii")
    style_hash = base64.b64encode(hashlib.sha256(style).digest()).decode("ascii")
    directive = f"'sha256-{style_hash}'"
    if directive not in parser.csp[0]:
        _fail("CSP does not bind the exact stylesheet")
    required_csp = (
        "default-src 'none'",
        "script-src 'none'",
        "style-src-attr 'none'",
        "img-src 'none'",
        "connect-src 'none'",
        "worker-src 'none'",
        "frame-src 'none'",
    )
    if any(item not in parser.csp[0] for item in required_csp):
        _fail("CSP lost a required restrictive directive")
    if parser.receipt_digests != [receipt_sha256]:
        _fail("report does not bind the exact receipt")


def _verify_png(payload: bytes, expected: tuple[int, int] | None) -> tuple[int, int]:
    image_module = importlib.import_module("PIL.Image")
    with image_module.open(io.BytesIO(payload)) as image:
        image.load()
        if image.format != "PNG" or image.mode != "RGB" or image.info:
            _fail("PNG structure or metadata changed")
        size = cast(tuple[int, int], image.size)
    if expected is not None and size != expected:
        _fail("PNG dimensions changed")
    if size[0] < 320 or size[1] < 700 or size[1] > 30_000:
        _fail("PNG dimensions escaped reviewed bounds")
    return size


def _verify_gif(payload: bytes, manifest: JsonObject) -> None:
    image_module = importlib.import_module("PIL.Image")
    with image_module.open(io.BytesIO(payload)) as image:
        if image.format != "GIF" or image.size != (1_440, 1_000):
            _fail("scroll GIF dimensions or format changed")
        if getattr(image, "n_frames", 1) != 4:
            _fail("scroll GIF frame count changed")
        if "comment" in image.info or "transparency" in image.info:
            _fail("scroll GIF retained forbidden metadata")
        durations: list[int] = []
        for index in range(4):
            image.seek(index)
            image.load()
            duration = image.info.get("duration")
            if type(duration) is not int:
                _fail("scroll GIF frame omitted duration")
            durations.append(duration)
    if durations != manifest.get("durations_ms"):
        _fail("scroll GIF durations disagree with the manifest")


def _verify_svg(payload: bytes) -> None:
    namespace = b'xmlns="http://www.w3.org/2000/svg"'
    if not payload.isascii() or payload.count(namespace) != 1:
        _fail("architecture SVG contains non-ASCII or an invalid namespace")
    remote_scan = payload.replace(namespace, b"", 1)
    if b"http://" in remote_scan or b"https://" in remote_scan:
        _fail("architecture SVG contains remote content")
    root = ET.fromstring(payload)
    if root.tag != "{http://www.w3.org/2000/svg}svg":
        _fail("architecture evidence is not SVG")
    allowed = {"svg", "title", "desc", "rect", "text", "path"}
    for element in root.iter():
        local = element.tag.rsplit("}", 1)[-1]
        if local not in allowed:
            _fail("architecture SVG contains an active element")
        for name in element.attrib:
            if name.rsplit("}", 1)[-1] in {"href", "style"} or name.startswith("on"):
                _fail("architecture SVG contains an active attribute")


def _wheel_identity(wheel: Path) -> tuple[JsonObject, JsonObject]:
    payload = wheel.read_bytes()
    if len(payload) > 8 * 1024 * 1024:
        _fail("wheel exceeded evidence bound")
    package_files: JsonObject = {}
    with zipfile.ZipFile(io.BytesIO(payload)) as archive:
        names = archive.namelist()
        if not any(name.endswith("casefold_observatory/report.py") for name in names):
            _fail("wheel omitted the offline report implementation")
        for name in sorted(names):
            path = Path(name)
            if (
                len(path.parts) == 2
                and path.parts[0] == "casefold_observatory"
                and (path.suffix == ".py" or path.name == "py.typed")
            ):
                content = archive.read(name)
                package_files[path.name] = {
                    "bytes": len(content),
                    "sha256": _sha256(content),
                }
    identity = {
        "bytes": len(payload),
        "filename": wheel.name,
        "sha256": _sha256(payload),
    }
    return identity, package_files


def _inventory(root: Path) -> tuple[str, ...]:
    paths: list[str] = []
    for path in root.rglob("*"):
        if path.is_symlink():
            _fail("bundle contains a symlink")
        if path.is_file():
            paths.append(path.relative_to(root).as_posix())
        elif not path.is_dir():
            _fail("bundle contains a special file")
    return tuple(sorted(paths))


def _verify(
    root: Path,
    *,
    source_revision: str,
    source_tree: str,
    wheel: Path,
) -> None:
    if _REVISION.fullmatch(source_revision) is None:
        _fail("source revision is not canonical")
    if _REVISION.fullmatch(source_tree) is None:
        _fail("source tree is not canonical")
    if _inventory(root) != tuple(sorted(OUTPUT_PATHS)):
        _fail("report evidence inventory changed")
    payloads = {
        relative: _read(root / relative, MAX_FILE_BYTES[relative])
        for relative in OUTPUT_PATHS
    }
    manifest = _canonical_json(payloads[MANIFEST_PATH], pretty=True)
    if manifest.get("schema") != "casefold-observatory.report-evidence":
        _fail("report evidence schema changed")
    if manifest.get("schema_version") != 1:
        _fail("report evidence schema version changed")
    if manifest.get("generated_files") != list(OUTPUT_PATHS):
        _fail("report evidence generated file list changed")

    artifacts = _object(manifest.get("artifacts"))
    if set(artifacts) != set(HASHED_OUTPUT_PATHS):
        _fail("report evidence artifact inventory changed")
    for relative in HASHED_OUTPUT_PATHS:
        identity = _object(artifacts.get(relative))
        payload = payloads[relative]
        if identity != {"bytes": len(payload), "sha256": _sha256(payload)}:
            _fail(f"artifact identity changed: {relative}")

    source = _object(manifest.get("source"))
    if source.get("revision") != source_revision or source.get("tree") != source_tree:
        _fail("manifest source identity changed")
    bindings = _object(source.get("bindings"))
    if set(bindings) != set(EXPECTED_SOURCE_BINDINGS):
        _fail("source binding inventory changed")
    for relative, identity_value in bindings.items():
        if type(relative) is not str:
            _fail("source binding path is not a string")
        path = PROJECT_ROOT / relative
        payload = path.read_bytes()
        identity = _object(identity_value)
        if identity != {"bytes": len(payload), "sha256": _sha256(payload)}:
            _fail(f"source binding changed: {relative}")

    package = _object(manifest.get("package"))
    if package.get("distribution") != "casefold-observatory":
        _fail("package distribution changed")
    wheel_identity, wheel_files = _wheel_identity(wheel)
    if _object(package.get("wheel")) != wheel_identity:
        _fail("wheel identity changed")
    runtime = _object(package.get("runtime"))
    if runtime.get("package_version") != "0.5.0":
        _fail("installed package version changed")
    if _object(runtime.get("package_files")) != wheel_files:
        _fail("installed runtime files disagree with the wheel")

    environment = _object(manifest.get("environment"))
    if environment.get("architecture") != "x86_64":
        _fail("evidence architecture changed")
    if environment.get("pillow_version") != EXPECTED_PILLOW:
        _fail("Pillow version changed")
    if _object(environment.get("python")) != runtime:
        _fail("environment and package runtime identities disagree")
    if runtime.get("implementation") != "CPython":
        _fail("Python implementation changed")
    python_version = runtime.get("python_version")
    if type(python_version) is not str or not python_version.startswith("3.12."):
        _fail("Python evidence version changed")
    if runtime.get("unicode_version") != "15.0.0":
        _fail("Unicode evidence version changed")
    fonts = _object(environment.get("fonts"))
    if set(fonts) != {"monospace", "sans_serif"}:
        _fail("font role inventory changed")
    for font_value in fonts.values():
        font = _object(font_value)
        if set(font) != {"bytes", "family", "file", "sha256", "style"}:
            _fail("font identity shape changed")
        byte_count = font.get("bytes")
        digest = font.get("sha256")
        filename = font.get("file")
        if type(byte_count) is not int or byte_count < 1_000:
            _fail("font byte count is invalid")
        if type(digest) is not str or _DIGEST.fullmatch(digest) is None:
            _fail("font digest is invalid")
        if type(filename) is not str or "/" in filename or "\\" in filename:
            _fail("font filename leaked a path")

    fixture = _object(manifest.get("fixture"))
    fixture_path = fixture.get("path")
    if type(fixture_path) is not str:
        _fail("fixture path changed")
    fixture_bytes = (PROJECT_ROOT / fixture_path).read_bytes()
    if fixture.get("synthetic") is not True:
        _fail("fixture lost its synthetic-data label")
    if fixture.get("bytes") != len(fixture_bytes):
        _fail("fixture byte count changed")
    if fixture.get("sha256") != _sha256(fixture_bytes):
        _fail("fixture digest changed")

    receipt = _canonical_json(payloads[RECEIPT_PATH], pretty=False)
    if receipt.get("schema") != "casefold-observatory.analysis-receipt":
        _fail("receipt schema changed")
    receipt_sha = _sha256(payloads[RECEIPT_PATH])
    runtime_outputs = _object(manifest.get("runtime_outputs"))
    receipt_runtime = _object(runtime_outputs.get("receipt"))
    report_runtime = _object(runtime_outputs.get("report"))
    if receipt_runtime != {
        "bytes": len(payloads[RECEIPT_PATH]),
        "mode": "0600",
        "nlink": 1,
        "sha256": receipt_sha,
    }:
        _fail("runtime receipt identity changed")
    if report_runtime != {
        "bytes": len(payloads[REPORT_PATH]),
        "mode": "0600",
        "nlink": 1,
        "sha256": _sha256(payloads[REPORT_PATH]),
    }:
        _fail("runtime report identity changed")
    _verify_html(payloads[REPORT_PATH], receipt_sha)

    commands = manifest.get("commands")
    if type(commands) is not list or len(commands) != 3:
        _fail("captured command inventory changed")
    expected_statuses = ("analyzed", "reported", "verified")
    command_payloads: list[JsonObject] = []
    for command, expected_status in zip(commands, expected_statuses, strict=True):
        document = _object(command)
        if document.get("exit_status") != 0 or document.get("stderr") != "":
            _fail("captured success command failed or wrote stderr")
        stdout = document.get("stdout")
        if type(stdout) is not str or not stdout.isascii():
            _fail("captured command stdout changed")
        stdout_bytes = stdout.encode("ascii")
        if document.get("stdout_bytes") != len(stdout_bytes):
            _fail("captured stdout byte count changed")
        if document.get("stdout_sha256") != _sha256(stdout_bytes):
            _fail("captured stdout digest changed")
        command_payload = _object(json.loads(stdout))
        if command_payload.get("status") != expected_status:
            _fail("captured command status changed")
        command_payloads.append(command_payload)
    if command_payloads[0].get("receipt_sha256") != receipt_sha:
        _fail("analyze summary lost receipt parity")
    if command_payloads[1].get("receipt_sha256") != receipt_sha:
        _fail("report summary lost receipt parity")
    if command_payloads[1].get("report_sha256") != _sha256(payloads[REPORT_PATH]):
        _fail("report summary lost output parity")
    if command_payloads[2].get("receipt_sha256") != receipt_sha:
        _fail("verify summary lost receipt parity")

    browser = _object(manifest.get("browser"))
    if browser.get("container_image") != EXPECTED_CONTAINER:
        _fail("browser container identity changed")
    if browser.get("chromium_version") != EXPECTED_CHROMIUM:
        _fail("Chromium version changed")
    if browser.get("playwright_version") != EXPECTED_PLAYWRIGHT:
        _fail("Playwright version changed")
    if (
        browser.get("network") != "none"
        or browser.get("process_sandbox") is not False
        or browser.get("java_script_enabled") is not True
        or browser.get("service_workers") != "block"
    ):
        _fail("browser isolation claim changed")
    if browser.get("outer_isolation") != {
        "capabilities": "dropped",
        "network": "none",
        "new_privileges": False,
        "root_filesystem": "read_only",
        "runtime_user": "non_root",
    }:
        _fail("outer browser isolation claim changed")
    if browser.get("launch_args") != [
        "--disable-dev-shm-usage",
        "--force-color-profile=srgb",
    ]:
        _fail("browser launch arguments changed")
    executable_bytes = browser.get("chromium_executable_bytes")
    if type(executable_bytes) is not int or executable_bytes < 1_000_000:
        _fail("Chromium executable size is invalid")
    executable_sha = browser.get("chromium_executable_sha256")
    if type(executable_sha) is not str or _DIGEST.fullmatch(executable_sha) is None:
        _fail("Chromium executable digest is invalid")

    assertions = _object(browser.get("assertions"))
    desktop_assertions = _object(assertions.get("desktop"))
    mobile_assertions = _object(assertions.get("mobile_emulation"))
    full_assertions = _object(assertions.get("full_page"))
    scroll_assertions = _object(assertions.get("scroll"))
    for page_assertions in (
        desktop_assertions,
        mobile_assertions,
        full_assertions,
    ):
        if (
            page_assertions.get("request_count") != 1
            or page_assertions.get("subresource_request_count") != 0
            or page_assertions.get("text_ascii") is not True
            or page_assertions.get("bad_attributes") != []
            or page_assertions.get("bad_tags") != []
        ):
            _fail("browser page assertions changed")
    csp_probe = _object(assertions.get("csp_negative_probe"))
    if (
        csp_probe.get("inline_script_blocked") is not True
        or csp_probe.get("tampered_style_blocked") is not True
    ):
        _fail("CSP negative probe changed")

    desktop_size = _verify_png(payloads[DESKTOP_PATH], (1_440, 1_000))
    mobile_size = _verify_png(payloads[MOBILE_PATH], (390, 844))
    full_size = _verify_png(payloads[FULL_PAGE_PATH], None)
    if desktop_size != (1_440, 1_000) or mobile_size != (390, 844):
        _fail("viewport evidence dimensions changed")
    if desktop_assertions.get("image") != {
        "height": desktop_size[1],
        "mode": "RGB",
        "width": desktop_size[0],
    }:
        _fail("desktop image assertion changed")
    if mobile_assertions.get("image") != {
        "height": mobile_size[1],
        "mode": "RGB",
        "width": mobile_size[0],
    }:
        _fail("mobile image assertion changed")
    if full_assertions.get("image") != {
        "height": full_size[1],
        "mode": "RGB",
        "width": full_size[0],
    }:
        _fail("full-page image assertion changed")
    if full_size[0] != 1_440:
        _fail("full-page evidence width changed")
    if full_size[1] != full_assertions.get("document_scroll_height"):
        _fail("full-page height does not match measured scroll height")
    _verify_gif(payloads[SCROLL_PATH], scroll_assertions)
    observed = scroll_assertions.get("observed_scroll_y")
    requested = scroll_assertions.get("requested_scroll_y")
    if observed != requested or type(observed) is not list or len(observed) != 4:
        _fail("real-scroll positions changed")
    _verify_svg(payloads[ARCHITECTURE_PATH])

    serialized = payloads[MANIFEST_PATH] + payloads[REPORT_PATH]
    forbidden = (b"/home/", b"/tmp/", b"file://", b"github_pat_", b"gho_")
    if any(fragment in serialized for fragment in forbidden):
        _fail("evidence leaked a host path or credential marker")
    print(f"report evidence independently verified ({len(OUTPUT_PATHS)} files)")


def _compare(left: Path, right: Path) -> None:
    try:
        if _inventory(left) != tuple(sorted(OUTPUT_PATHS)):
            raise RuntimeError
        if _inventory(right) != tuple(sorted(OUTPUT_PATHS)):
            raise RuntimeError
        for relative in OUTPUT_PATHS:
            if (left / relative).read_bytes() != (right / relative).read_bytes():
                raise RuntimeError
    except (OSError, RuntimeError):
        raise SystemExit(1) from None
    print(f"report evidence bundles match ({len(OUTPUT_PATHS)} files)")


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)
    verify = subparsers.add_parser("verify")
    verify.add_argument("root", type=Path)
    verify.add_argument("--source-revision", required=True)
    verify.add_argument("--source-tree", required=True)
    verify.add_argument("--wheel", type=Path, required=True)
    compare = subparsers.add_parser("compare")
    compare.add_argument("left", type=Path)
    compare.add_argument("right", type=Path)
    return parser


def main() -> int:
    arguments = _parser().parse_args()
    if arguments.command == "verify":
        _verify(
            arguments.root,
            source_revision=arguments.source_revision,
            source_tree=arguments.source_tree,
            wheel=arguments.wheel,
        )
    else:
        _compare(arguments.left, arguments.right)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

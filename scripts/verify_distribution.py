"""Build from the sdist and probe the installed wheel without network access."""

from __future__ import annotations

import hashlib
import json
import os
import stat
import subprocess
import sys
import tarfile
import tempfile
import tomllib
import venv
import zipfile
from pathlib import Path, PurePosixPath

PROJECT_ROOT = Path(__file__).resolve().parents[1]


def _project_version() -> str:
    document = tomllib.loads(
        (PROJECT_ROOT / "pyproject.toml").read_text(encoding="utf-8")
    )
    project = document.get("project")
    if not isinstance(project, dict):
        raise TypeError("pyproject project metadata must be a table")
    version = project.get("version")
    if not isinstance(version, str):
        raise TypeError("pyproject project.version must be a string")
    if not version:
        raise ValueError("pyproject project.version must not be empty")
    return version


def _run(*args: str, cwd: Path) -> subprocess.CompletedProcess[str]:
    environment = os.environ.copy()
    environment.pop("PYTHONPATH", None)
    environment["PYTHONNOUSERSITE"] = "1"
    return subprocess.run(
        args,
        cwd=cwd,
        env=environment,
        check=True,
        capture_output=True,
        text=True,
    )


def _single_artifact(directory: Path, suffix: str) -> Path:
    artifacts = sorted(directory.glob(f"*{suffix}"))
    if len(artifacts) != 1:
        raise RuntimeError(f"expected one {suffix} artifact, found {len(artifacts)}")
    return artifacts[0]


def _extract_generated_sdist(sdist: Path, destination: Path) -> Path:
    with tarfile.open(sdist, "r:gz") as archive:
        members = archive.getmembers()
        for member in members:
            path = PurePosixPath(member.name)
            if path.is_absolute() or ".." in path.parts:
                raise RuntimeError("generated sdist contains an unsafe path")
            if member.issym() or member.islnk():
                raise RuntimeError("generated sdist contains a link")
            if not member.isfile() and not member.isdir():
                raise RuntimeError("generated sdist contains a special file")
        archive.extractall(destination, filter="data")

    roots = [path for path in destination.iterdir() if path.is_dir()]
    if len(roots) != 1:
        raise RuntimeError("generated sdist must contain one root directory")
    return roots[0]


def _assert_archive_contract(sdist: Path, wheel: Path) -> None:
    with tarfile.open(sdist, "r:gz") as archive:
        sdist_names = tuple(member.name for member in archive.getmembers())
    with zipfile.ZipFile(wheel) as archive:
        wheel_names = tuple(archive.namelist())

    required_package_files = (
        "casefold_observatory/__init__.py",
        "casefold_observatory/__main__.py",
        "casefold_observatory/cli.py",
        "casefold_observatory/collision.py",
        "casefold_observatory/corpus.py",
        "casefold_observatory/engine.py",
        "casefold_observatory/filesystem.py",
        "casefold_observatory/model.py",
        "casefold_observatory/report.py",
        "casefold_observatory/py.typed",
        "casefold_observatory/receipt.py",
    )
    for required in required_package_files:
        if not any(name.endswith(required) for name in sdist_names):
            raise RuntimeError(f"sdist omitted {required}")
        if required not in wheel_names:
            raise RuntimeError(f"wheel omitted {required}")

    required_source_files = (
        ".github/workflows/report-evidence.yml",
        "README.md",
        "SECURITY.md",
        "THIRD_PARTY_NOTICES.md",
        "docs/cli-evidence/fixtures/cli-demo.v1.jsonl",
        "docs/collision-graph-contract.md",
        "docs/portable-receipt-contract.md",
        "docs/report-evidence/README.md",
        "docs/report-evidence/evidence/report-demo.receipt.v1.json",
        "docs/report-evidence/evidence/report-demo.v1.html",
        "docs/report-evidence/evidence/report-evidence-adoption.v1.json",
        "docs/report-evidence/evidence/report-evidence.v1.json",
        "docs/report-evidence/fixtures/report-demo.v1.jsonl",
        "docs/report-evidence/report-architecture.svg",
        "docs/report-evidence/report-desktop.png",
        "docs/report-evidence/report-full-page.png",
        "docs/report-evidence/report-mobile.png",
        "docs/report-evidence/report-scroll.gif",
        "docs/visuals/README.md",
        "docs/visuals/architecture.svg",
        "docs/visuals/collision-witness-graph.svg",
        "docs/visuals/evidence/collision-visuals.v1.json",
        "docs/visuals/policy-collision-landscape.svg",
        "requirements/cli-visuals.txt",
        "requirements/report-browser-image.lock.json",
        "requirements/report-browser.txt",
        "scripts/render_cli_evidence.py",
        "scripts/render_collision_visuals.py",
        "scripts/render_report_evidence.py",
        "scripts/verify_distribution.py",
        "scripts/verify_report_evidence.py",
        "tests/test_collision.py",
        "tests/test_collision_properties.py",
        "tests/test_corpus.py",
        "tests/test_cli.py",
        "tests/test_cli_evidence_contract.py",
        "tests/test_distribution_script.py",
        "tests/test_filesystem.py",
        "tests/test_receipt.py",
        "tests/test_report.py",
        "tests/test_report_evidence_contract.py",
        "tests/test_visuals.py",
    )
    for required in required_source_files:
        if not any(name.endswith(required) for name in sdist_names):
            raise RuntimeError(f"sdist omitted {required}")

    forbidden_fragments = (
        "/.coverage",
        "/.git/",
        "/.mypy_cache/",
        "/.pytest_cache/",
        "/.ruff_cache/",
        "/__pycache__/",
    )
    for name in (*sdist_names, *wheel_names):
        if any(fragment in f"/{name}" for fragment in forbidden_fragments):
            raise RuntimeError(f"distribution leaked generated state: {name}")


def _installed_wheel_probe(venv_python: Path, workdir: Path) -> dict[str, object]:
    probe = """
import json
import sys
from importlib import metadata
from pathlib import Path

import casefold_observatory
from casefold_observatory import (
    TransformStep,
    analyze_collisions,
    canonical_receipt_bytes,
    create_collision_receipt,
    create_identifier_record,
    create_policy,
    verify_collision_receipt,
)

module_path = Path(casefold_observatory.__file__).resolve()
if not module_path.is_relative_to(Path(sys.prefix).resolve()):
    raise RuntimeError("probe imported outside the isolated environment")

records = tuple(
    create_identifier_record(record_id, value)
    for record_id, value in (
        ("upper", "SS"),
        ("eszett", "ß"),
        ("lower", "ss"),
    )
)
policy = create_policy((TransformStep.LOWER, TransformStep.CASEFOLD))
graph = analyze_collisions(records, (policy,))
source = (
    b'{"schema":"casefold-observatory.identifier-corpus","schema_version":1}\\n'
    b'{"identifier":"SS","record_id":"upper"}\\n'
    b'{"identifier":"\\u00df","record_id":"eszett"}\\n'
    b'{"identifier":"ss","record_id":"lower"}\\n'
)
receipt_bytes = canonical_receipt_bytes(
    create_collision_receipt(source, (policy,))
)
verified_receipt = verify_collision_receipt(receipt_bytes, source)
print(
    json.dumps(
        {
            "algorithm": graph.algorithm,
            "component_members": graph.components[0].member_record_ordinals,
            "policy_group_members": graph.policy_groups[0].member_record_ordinals,
            "receipt_schema": verified_receipt.schema,
            "receipt_source_bytes": verified_receipt.source.byte_count,
            "receipt_verified": (
                canonical_receipt_bytes(verified_receipt) == receipt_bytes
            ),
            "record_ids": graph.record_ids,
            "version": metadata.version("casefold-observatory"),
            "witness_stages": [
                witness.stage_index for witness in graph.witnesses
            ],
        },
        sort_keys=True,
        separators=(",", ":"),
    )
)
"""
    completed = _run(venv_python.as_posix(), "-c", probe, cwd=workdir)
    payload: object = json.loads(completed.stdout)
    if not isinstance(payload, dict):
        raise TypeError("installed-wheel probe returned a non-object")

    source_path = workdir / "cli-source.jsonl"
    receipt_path = workdir / "cli-result.receipt.json"
    report_path = workdir / "cli-result.html"
    source_path.write_bytes(
        b'{"schema":"casefold-observatory.identifier-corpus",'
        b'"schema_version":1}\n'
        b'{"identifier":"SS","record_id":"upper"}\n'
        b'{"identifier":"\\u00df","record_id":"eszett"}\n'
        b'{"identifier":"ss","record_id":"lower"}\n'
    )
    console = venv_python.with_name("casefold-observatory")
    if not console.is_file():
        raise RuntimeError("wheel omitted the installed console script")
    analyzed = _run(
        console.as_posix(),
        "analyze",
        "--source",
        source_path.as_posix(),
        "--policy",
        "reject@case:lower,case:casefold",
        "--receipt",
        receipt_path.as_posix(),
        cwd=workdir,
    )
    reported = _run(
        console.as_posix(),
        "report",
        "--source",
        source_path.as_posix(),
        "--receipt",
        receipt_path.as_posix(),
        "--output",
        report_path.as_posix(),
        cwd=workdir,
    )
    verified = _run(
        venv_python.as_posix(),
        "-m",
        "casefold_observatory",
        "verify",
        "--source",
        source_path.as_posix(),
        "--receipt",
        receipt_path.as_posix(),
        cwd=workdir,
    )
    if analyzed.stderr or reported.stderr or verified.stderr:
        raise RuntimeError("installed CLI wrote to stderr on success")
    analyzed_payload: object = json.loads(analyzed.stdout)
    reported_payload: object = json.loads(reported.stdout)
    verified_payload: object = json.loads(verified.stdout)
    if (
        not isinstance(analyzed_payload, dict)
        or not isinstance(reported_payload, dict)
        or not isinstance(verified_payload, dict)
    ):
        raise TypeError("installed CLI returned a non-object")
    report_bytes = report_path.read_bytes()
    payload["cli_analyze_status"] = analyzed_payload.get("status")
    payload["cli_report_ascii"] = report_bytes.isascii()
    payload["cli_report_contains_csp"] = (
        b'http-equiv="Content-Security-Policy"' in report_bytes
    )
    payload["cli_report_digest_parity"] = (
        reported_payload.get("report_sha256")
        == hashlib.sha256(report_bytes).hexdigest()
    )
    payload["cli_report_mode"] = stat.S_IMODE(report_path.stat().st_mode)
    payload["cli_report_nlink"] = report_path.stat().st_nlink
    payload["cli_report_status"] = reported_payload.get("status")
    payload["cli_verify_status"] = verified_payload.get("status")
    payload["cli_digest_parity"] = analyzed_payload.get(
        "receipt_sha256"
    ) == verified_payload.get("receipt_sha256")
    payload["cli_receipt_mode"] = stat.S_IMODE(receipt_path.stat().st_mode)
    return payload


def main() -> None:
    expected_version = _project_version()
    with tempfile.TemporaryDirectory(prefix="casefold-dist-") as temporary:
        root = Path(temporary)
        source_dist = root / "source-dist"
        source_dist.mkdir()
        _run(
            sys.executable,
            "-m",
            "build",
            "--sdist",
            "--no-isolation",
            "--outdir",
            source_dist.as_posix(),
            cwd=PROJECT_ROOT,
        )
        sdist = _single_artifact(source_dist, ".tar.gz")

        extracted_root = _extract_generated_sdist(sdist, root / "extracted")
        wheel_dist = root / "wheel-dist"
        wheel_dist.mkdir()
        _run(
            sys.executable,
            "-m",
            "build",
            "--wheel",
            "--no-isolation",
            "--outdir",
            wheel_dist.as_posix(),
            cwd=extracted_root,
        )
        wheel = _single_artifact(wheel_dist, ".whl")
        _assert_archive_contract(sdist, wheel)

        isolated = root / "installed"
        venv.EnvBuilder(with_pip=True).create(isolated)
        venv_python = isolated / "bin" / "python"
        _run(
            venv_python.as_posix(),
            "-m",
            "pip",
            "install",
            "--no-deps",
            "--no-index",
            wheel.as_posix(),
            cwd=root,
        )
        payload = _installed_wheel_probe(venv_python, root)

    expected = {
        "algorithm": "stage-partition-witness-v1",
        "cli_analyze_status": "analyzed",
        "cli_digest_parity": True,
        "cli_receipt_mode": 0o600,
        "cli_report_ascii": True,
        "cli_report_contains_csp": True,
        "cli_report_digest_parity": True,
        "cli_report_mode": 0o600,
        "cli_report_nlink": 1,
        "cli_report_status": "reported",
        "cli_verify_status": "verified",
        "component_members": [0, 1, 2],
        "policy_group_members": [0, 1, 2],
        "receipt_schema": "casefold-observatory.analysis-receipt",
        "receipt_source_bytes": 196,
        "receipt_verified": True,
        "record_ids": ["eszett", "lower", "upper"],
        "version": expected_version,
        "witness_stages": [0, 1],
    }
    if payload != expected:
        raise RuntimeError(
            "installed-wheel probe changed: " + json.dumps(payload, sort_keys=True)
        )
    print(
        "distribution verification passed "
        f"(version={payload['version']}, source=sdist, install=wheel)"
    )


if __name__ == "__main__":
    main()

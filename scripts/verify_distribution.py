"""Build from the sdist and probe the installed wheel without network access."""

from __future__ import annotations

import json
import os
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
        archive.extractall(destination)

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
        "casefold_observatory/collision.py",
        "casefold_observatory/engine.py",
        "casefold_observatory/model.py",
        "casefold_observatory/py.typed",
    )
    for required in required_package_files:
        if not any(name.endswith(required) for name in sdist_names):
            raise RuntimeError(f"sdist omitted {required}")
        if required not in wheel_names:
            raise RuntimeError(f"wheel omitted {required}")

    required_source_files = (
        "README.md",
        "SECURITY.md",
        "docs/collision-graph-contract.md",
        "docs/visuals/README.md",
        "docs/visuals/architecture.svg",
        "docs/visuals/collision-witness-graph.svg",
        "docs/visuals/evidence/collision-visuals.v1.json",
        "docs/visuals/policy-collision-landscape.svg",
        "scripts/render_collision_visuals.py",
        "scripts/verify_distribution.py",
        "tests/test_collision.py",
        "tests/test_collision_properties.py",
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
    create_identifier_record,
    create_policy,
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
print(
    json.dumps(
        {
            "algorithm": graph.algorithm,
            "component_members": graph.components[0].member_record_ordinals,
            "policy_group_members": graph.policy_groups[0].member_record_ordinals,
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
        "component_members": [0, 1, 2],
        "policy_group_members": [0, 1, 2],
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

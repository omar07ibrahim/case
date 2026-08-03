from __future__ import annotations

import importlib.util
import io
import tarfile
import tempfile
import unittest
from pathlib import Path
from types import ModuleType
from typing import Protocol, cast

VERIFIER_PATH = (
    Path(__file__).resolve().parents[1] / "scripts" / "verify_distribution.py"
)


class _Verifier(Protocol):
    PROJECT_ROOT: Path

    def _extract_generated_sdist(
        self,
        sdist: Path,
        destination: Path,
    ) -> Path: ...


def _load_verifier() -> _Verifier:
    spec = importlib.util.spec_from_file_location(
        "casefold_distribution_verifier_for_tests",
        VERIFIER_PATH,
    )
    if spec is None or spec.loader is None:
        raise RuntimeError("could not load the distribution verifier")
    module: ModuleType = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return cast(_Verifier, module)


verify_distribution = _load_verifier()


def _write_archive(
    path: Path,
    members: list[tuple[tarfile.TarInfo, bytes | None]],
) -> None:
    with tarfile.open(path, "w:gz") as archive:
        for member, content in members:
            if content is not None:
                member.size = len(content)
            archive.addfile(
                member,
                io.BytesIO(content) if content is not None else None,
            )


def _directory(name: str) -> tarfile.TarInfo:
    member = tarfile.TarInfo(name)
    member.type = tarfile.DIRTYPE
    member.mode = 0o755
    return member


def _regular(name: str) -> tarfile.TarInfo:
    member = tarfile.TarInfo(name)
    member.mode = 0o644
    return member


class DistributionExtractionTests(unittest.TestCase):
    def test_extracts_one_closed_regular_tree_with_the_data_filter(self) -> None:
        with tempfile.TemporaryDirectory(
            prefix=".distribution-script-test-",
            dir=verify_distribution.PROJECT_ROOT,
        ) as directory:
            root = Path(directory)
            archive = root / "safe.tar.gz"
            _write_archive(
                archive,
                [
                    (_directory("casefold-observatory-0.2.0"), None),
                    (
                        _regular("casefold-observatory-0.2.0/README.md"),
                        b"reviewed\n",
                    ),
                ],
            )

            extracted = verify_distribution._extract_generated_sdist(
                archive,
                root / "output",
            )

            self.assertEqual(extracted.name, "casefold-observatory-0.2.0")
            self.assertEqual((extracted / "README.md").read_bytes(), b"reviewed\n")

    def test_rejects_traversal_links_and_special_files_before_extraction(
        self,
    ) -> None:
        link = tarfile.TarInfo("casefold-observatory-0.2.0/link")
        link.type = tarfile.SYMTYPE
        link.linkname = "README.md"
        fifo = tarfile.TarInfo("casefold-observatory-0.2.0/fifo")
        fifo.type = tarfile.FIFOTYPE
        cases = (
            ("traversal", _regular("../escape.txt"), b"escape", "unsafe path"),
            ("link", link, None, "contains a link"),
            ("fifo", fifo, None, "contains a special file"),
        )
        for label, hostile, content, message in cases:
            with (
                self.subTest(case=label),
                tempfile.TemporaryDirectory(
                    prefix=".distribution-script-test-",
                    dir=verify_distribution.PROJECT_ROOT,
                ) as directory,
            ):
                root = Path(directory)
                archive = root / "hostile.tar.gz"
                _write_archive(
                    archive,
                    [
                        (_directory("casefold-observatory-0.2.0"), None),
                        (hostile, content),
                    ],
                )

                with self.assertRaisesRegex(RuntimeError, message):
                    verify_distribution._extract_generated_sdist(
                        archive,
                        root / "output",
                    )
                self.assertFalse((root.parent / "escape.txt").exists())


if __name__ == "__main__":
    unittest.main()

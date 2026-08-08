from __future__ import annotations

import errno
import os
import stat
import tempfile
import unittest
from collections.abc import Callable
from functools import partial
from pathlib import Path
from types import SimpleNamespace
from typing import cast
from unittest import mock

from casefold_observatory import filesystem
from casefold_observatory.filesystem import (
    FileBoundaryError,
    FileBoundaryErrorCode,
    capture_regular_file,
    publish_new_file,
)


def _expect_code(
    testcase: unittest.TestCase,
    code: FileBoundaryErrorCode,
    call: Callable[[], object],
) -> FileBoundaryError:
    with testcase.assertRaises(FileBoundaryError) as caught:
        call()
    testcase.assertIs(caught.exception.code, code)
    testcase.assertNotIn("/", str(caught.exception))
    return caught.exception


def _fake_stat(
    value: os.stat_result,
    **changes: int,
) -> os.stat_result:
    fields = {
        "st_mode": value.st_mode,
        "st_ino": value.st_ino,
        "st_dev": value.st_dev,
        "st_nlink": value.st_nlink,
        "st_size": value.st_size,
        "st_mtime_ns": value.st_mtime_ns,
        "st_ctime_ns": value.st_ctime_ns,
    }
    fields.update(changes)
    return cast(os.stat_result, SimpleNamespace(**fields))


class FileCaptureTests(unittest.TestCase):
    def test_captures_exact_stable_bytes_and_identity(self) -> None:
        with tempfile.TemporaryDirectory(prefix="casefold-file-capture-") as directory:
            root = Path(directory)
            nested = root / "nested"
            nested.mkdir()
            source = nested / "source.jsonl"
            source.write_bytes(b"abc\x00def")

            captured = capture_regular_file(source.as_posix(), limit=7)

            info = source.stat()
            self.assertEqual(captured.data, b"abc\x00def")
            self.assertEqual(
                (captured.device, captured.inode),
                (info.st_dev, info.st_ino),
            )

    def test_relative_dot_component_and_empty_file_are_supported(self) -> None:
        with tempfile.TemporaryDirectory(
            prefix="casefold-relative-capture-",
            dir=Path.cwd(),
        ) as directory:
            source = Path(directory) / "empty"
            source.write_bytes(b"")
            relative = source.relative_to(Path.cwd()).as_posix()
            parent, name = relative.rsplit("/", 1)

            captured = capture_regular_file(f"./{parent}//{name}", limit=0)

            self.assertEqual(captured.data, b"")

    def test_invalid_paths_and_traversal_fail_before_opening_content(self) -> None:
        cases: tuple[tuple[str, FileBoundaryErrorCode], ...] = (
            ("", FileBoundaryErrorCode.INVALID_PATH),
            ("-", FileBoundaryErrorCode.INVALID_PATH),
            (".", FileBoundaryErrorCode.INVALID_PATH),
            ("/", FileBoundaryErrorCode.INVALID_PATH),
            ("name/", FileBoundaryErrorCode.INVALID_PATH),
            ("nul\x00name", FileBoundaryErrorCode.INVALID_PATH),
            ("../name", FileBoundaryErrorCode.TRAVERSAL),
            ("safe/../name", FileBoundaryErrorCode.TRAVERSAL),
        )
        for path, code in cases:
            with self.subTest(code=code):
                _expect_code(
                    self,
                    code,
                    partial(capture_regular_file, path, limit=1),
                )

        with self.assertRaisesRegex(TypeError, "exact str"):
            capture_regular_file(cast(str, b"path"), limit=1)
        with self.assertRaisesRegex(ValueError, "non-negative"):
            capture_regular_file("path", limit=-1)
        with self.assertRaisesRegex(ValueError, "non-negative"):
            capture_regular_file("path", limit=cast(int, True))

    def test_missing_symlink_directory_fifo_and_hardlink_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory(prefix="casefold-file-types-") as directory:
            root = Path(directory)
            regular = root / "regular"
            regular.write_bytes(b"x")
            symlink = root / "symlink"
            symlink.symlink_to(regular.name)
            directory_path = root / "directory"
            directory_path.mkdir()
            fifo = root / "fifo"
            os.mkfifo(fifo)
            hardlink = root / "hardlink"
            os.link(regular, hardlink)

            cases = (
                (
                    root / "missing",
                    FileBoundaryErrorCode.NOT_FOUND,
                ),
                (
                    symlink,
                    FileBoundaryErrorCode.SYMLINK,
                ),
                (
                    directory_path,
                    FileBoundaryErrorCode.SPECIAL_FILE,
                ),
                (
                    fifo,
                    FileBoundaryErrorCode.SPECIAL_FILE,
                ),
                (
                    regular,
                    FileBoundaryErrorCode.MULTIPLE_LINKS,
                ),
                (
                    hardlink,
                    FileBoundaryErrorCode.MULTIPLE_LINKS,
                ),
            )
            for path, code in cases:
                with self.subTest(code=code):
                    _expect_code(
                        self,
                        code,
                        partial(capture_regular_file, path.as_posix(), limit=8),
                    )

    def test_directory_components_reject_symlinks_and_regular_files(self) -> None:
        with tempfile.TemporaryDirectory(prefix="casefold-parent-types-") as directory:
            root = Path(directory)
            target = root / "target"
            target.mkdir()
            (target / "value").write_bytes(b"x")
            symlink = root / "link"
            symlink.symlink_to(target.name, target_is_directory=True)
            regular = root / "regular"
            regular.write_bytes(b"x")

            _expect_code(
                self,
                FileBoundaryErrorCode.SYMLINK,
                partial(
                    capture_regular_file,
                    (symlink / "value").as_posix(),
                    limit=1,
                ),
            )
            _expect_code(
                self,
                FileBoundaryErrorCode.DIRECTORY_COMPONENT,
                partial(
                    capture_regular_file,
                    (regular / "value").as_posix(),
                    limit=1,
                ),
            )

    def test_size_is_early_rejected_and_limit_plus_one_is_authoritative(self) -> None:
        with tempfile.TemporaryDirectory(prefix="casefold-size-limit-") as directory:
            source = Path(directory) / "source"
            source.write_bytes(b"ab")
            _expect_code(
                self,
                FileBoundaryErrorCode.READ_LIMIT,
                partial(capture_regular_file, source.as_posix(), limit=1),
            )

        with mock.patch.object(filesystem.os, "read", return_value=b"ab"):
            _expect_code(
                self,
                FileBoundaryErrorCode.READ_LIMIT,
                partial(filesystem._read_bounded, 0, 1),
            )

    def test_short_reads_and_interrupted_reads_continue(self) -> None:
        with tempfile.TemporaryDirectory(prefix="casefold-short-read-") as directory:
            source = Path(directory) / "source"
            source.write_bytes(b"abcdef")
            original_read = os.read
            interrupted = True

            def read_one(descriptor: int, count: int) -> bytes:
                nonlocal interrupted
                if interrupted:
                    interrupted = False
                    raise InterruptedError
                return original_read(descriptor, min(count, 1))

            with mock.patch.object(filesystem.os, "read", side_effect=read_one):
                captured = capture_regular_file(source.as_posix(), limit=6)

            self.assertEqual(captured.data, b"abcdef")

    def test_invalid_or_failed_read_is_redacted(self) -> None:
        cases: tuple[tuple[object, FileBoundaryErrorCode], ...] = (
            (bytearray(b"x"), FileBoundaryErrorCode.IO_ERROR),
            (b"xxx", FileBoundaryErrorCode.IO_ERROR),
            (OSError(errno.EIO, "private-path"), FileBoundaryErrorCode.IO_ERROR),
        )
        for result, code in cases:
            with self.subTest(result_type=type(result).__name__):
                patcher = (
                    mock.patch.object(filesystem.os, "read", side_effect=result)
                    if isinstance(result, OSError)
                    else mock.patch.object(filesystem.os, "read", return_value=result)
                )
                with patcher:
                    _expect_code(
                        self,
                        code,
                        partial(filesystem._read_bounded, 0, 1),
                    )

    def test_open_and_post_read_identity_races_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory(prefix="casefold-file-races-") as directory:
            source = Path(directory) / "source"
            source.write_bytes(b"stable")
            original_fstat = os.fstat
            regular_calls = 0

            def changed_open_stat(descriptor: int) -> os.stat_result:
                nonlocal regular_calls
                info = original_fstat(descriptor)
                if stat.S_ISREG(info.st_mode):
                    regular_calls += 1
                    if regular_calls == 1:
                        return _fake_stat(info, st_ctime_ns=info.st_ctime_ns + 1)
                return info

            with mock.patch.object(
                filesystem.os,
                "fstat",
                side_effect=changed_open_stat,
            ):
                _expect_code(
                    self,
                    FileBoundaryErrorCode.CONCURRENT_MUTATION,
                    partial(capture_regular_file, source.as_posix(), limit=6),
                )

            regular_calls = 0

            def changed_after_read(descriptor: int) -> os.stat_result:
                nonlocal regular_calls
                info = original_fstat(descriptor)
                if stat.S_ISREG(info.st_mode):
                    regular_calls += 1
                    if regular_calls == 2:
                        return _fake_stat(info, st_mtime_ns=info.st_mtime_ns + 1)
                return info

            with mock.patch.object(
                filesystem.os,
                "fstat",
                side_effect=changed_after_read,
            ):
                _expect_code(
                    self,
                    FileBoundaryErrorCode.CONCURRENT_MUTATION,
                    partial(capture_regular_file, source.as_posix(), limit=6),
                )

    def test_path_disappearance_after_read_is_a_mutation(self) -> None:
        with tempfile.TemporaryDirectory(prefix="casefold-path-race-") as directory:
            source = Path(directory) / "source"
            source.write_bytes(b"stable")
            original_stat = os.stat
            final_stats = 0

            def disappearing_stat(
                path: str | bytes | int,
                *,
                dir_fd: int | None = None,
                follow_symlinks: bool = True,
            ) -> os.stat_result:
                nonlocal final_stats
                if path == source.name and dir_fd is not None:
                    final_stats += 1
                    if final_stats == 2:
                        raise FileNotFoundError
                return original_stat(
                    path,
                    dir_fd=dir_fd,
                    follow_symlinks=follow_symlinks,
                )

            with mock.patch.object(
                filesystem.os,
                "stat",
                side_effect=disappearing_stat,
            ):
                _expect_code(
                    self,
                    FileBoundaryErrorCode.CONCURRENT_MUTATION,
                    partial(capture_regular_file, source.as_posix(), limit=6),
                )

    def test_directory_identity_swap_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory(prefix="casefold-dir-race-") as directory:
            root = Path(directory)
            nested = root / "nested"
            nested.mkdir()
            (nested / "source").write_bytes(b"x")
            nested_info = nested.stat()
            original_fstat = os.fstat

            def swapped_directory(descriptor: int) -> os.stat_result:
                info = original_fstat(descriptor)
                if (
                    stat.S_ISDIR(info.st_mode)
                    and info.st_ino == nested_info.st_ino
                    and info.st_dev == nested_info.st_dev
                ):
                    return _fake_stat(info, st_ino=info.st_ino + 1)
                return info

            with mock.patch.object(
                filesystem.os,
                "fstat",
                side_effect=swapped_directory,
            ):
                _expect_code(
                    self,
                    FileBoundaryErrorCode.CONCURRENT_MUTATION,
                    partial(
                        capture_regular_file,
                        (nested / "source").as_posix(),
                        limit=1,
                    ),
                )


class PosixPrimitiveTests(unittest.TestCase):
    def test_platform_and_descriptor_features_fail_closed(self) -> None:
        with mock.patch.object(filesystem.os, "name", "nt"):
            _expect_code(
                self,
                FileBoundaryErrorCode.UNSUPPORTED_PLATFORM,
                partial(capture_regular_file, "source", limit=1),
            )
        with mock.patch.object(filesystem.os, "supports_dir_fd", set()):
            _expect_code(
                self,
                FileBoundaryErrorCode.UNSUPPORTED_PLATFORM,
                partial(capture_regular_file, "source", limit=1),
            )
        with mock.patch.object(filesystem.os, "O_NOFOLLOW", None):
            _expect_code(
                self,
                FileBoundaryErrorCode.UNSUPPORTED_PLATFORM,
                partial(capture_regular_file, "source", limit=1),
            )

    def test_os_error_mapping_is_total_and_redacted(self) -> None:
        cases = (
            (errno.ENOENT, FileBoundaryErrorCode.NOT_FOUND),
            (errno.ELOOP, FileBoundaryErrorCode.SYMLINK),
            (errno.ENOTDIR, FileBoundaryErrorCode.DIRECTORY_COMPONENT),
            (errno.EACCES, FileBoundaryErrorCode.IO_ERROR),
        )
        for number, code in cases:
            with self.subTest(code=code):
                _expect_code(
                    self,
                    code,
                    partial(
                        filesystem._mapped_os_error,
                        OSError(number, "private-path"),
                    ),
                )

    def test_safe_close_and_cleanup_suppress_only_cleanup_errors(self) -> None:
        with mock.patch.object(filesystem.os, "close", side_effect=OSError):
            filesystem._safe_close(99)
        filesystem._cleanup_temporary(99, None)
        with mock.patch.object(filesystem.os, "unlink", side_effect=OSError):
            filesystem._cleanup_temporary(99, "private-temp")


class FilePublicationTests(unittest.TestCase):
    def test_short_writes_interrupts_mode_and_durability_path(self) -> None:
        with tempfile.TemporaryDirectory(prefix="casefold-publish-") as directory:
            destination = Path(directory) / "receipt.json"
            original_write = os.write
            interrupted = True

            def write_one(descriptor: int, data: bytes) -> int:
                nonlocal interrupted
                if interrupted:
                    interrupted = False
                    raise InterruptedError
                return original_write(descriptor, data[:1])

            with mock.patch.object(filesystem.os, "write", side_effect=write_one):
                publish_new_file(destination.as_posix(), b"receipt\n")

            info = destination.stat()
            self.assertEqual(destination.read_bytes(), b"receipt\n")
            self.assertEqual(stat.S_IMODE(info.st_mode), 0o600)
            self.assertEqual(info.st_nlink, 1)
            self.assertEqual(
                list(destination.parent.glob(".casefold-observatory-*.tmp")),
                [],
            )

    def test_empty_file_publication_exercises_zero_write_path(self) -> None:
        with tempfile.TemporaryDirectory(prefix="casefold-empty-publish-") as directory:
            destination = Path(directory) / "empty"
            publish_new_file(destination.as_posix(), b"")
            self.assertEqual(destination.read_bytes(), b"")

    def test_existing_destination_symlink_and_alias_never_clobber(self) -> None:
        with tempfile.TemporaryDirectory(prefix="casefold-no-clobber-") as directory:
            root = Path(directory)
            source = root / "source"
            source.write_bytes(b"source")
            source_info = source.stat()
            existing = root / "existing"
            existing.write_bytes(b"existing")
            symlink = root / "symlink"
            symlink.symlink_to(existing.name)

            _expect_code(
                self,
                FileBoundaryErrorCode.DESTINATION_EXISTS,
                partial(publish_new_file, existing.as_posix(), b"new"),
            )
            _expect_code(
                self,
                FileBoundaryErrorCode.SYMLINK,
                partial(publish_new_file, symlink.as_posix(), b"new"),
            )
            _expect_code(
                self,
                FileBoundaryErrorCode.ALIAS,
                partial(
                    publish_new_file,
                    source.as_posix(),
                    b"new",
                    forbidden_identities=((source_info.st_dev, source_info.st_ino),),
                ),
            )
            self.assertEqual(source.read_bytes(), b"source")
            self.assertEqual(existing.read_bytes(), b"existing")

    def test_temporary_name_collisions_are_bounded(self) -> None:
        with tempfile.TemporaryDirectory(
            prefix="casefold-temp-collision-"
        ) as directory:
            root = Path(directory)
            token = "a" * 32
            temporary = root / f".casefold-observatory-{token}.tmp"
            temporary.write_bytes(b"occupied")
            with mock.patch.object(
                filesystem.secrets,
                "token_hex",
                return_value=token,
            ):
                _expect_code(
                    self,
                    FileBoundaryErrorCode.TEMPORARY_COLLISION,
                    partial(
                        publish_new_file,
                        (root / "receipt").as_posix(),
                        b"new",
                    ),
                )
            self.assertEqual(temporary.read_bytes(), b"occupied")

    def test_invalid_write_results_and_write_error_cleanup(self) -> None:
        results: tuple[object, ...] = (0, -1, "1", 99)
        for result in results:
            with (
                self.subTest(result=result),
                tempfile.TemporaryDirectory(
                    prefix="casefold-write-result-"
                ) as directory,
            ):
                destination = Path(directory) / "receipt"
                with mock.patch.object(
                    filesystem.os,
                    "write",
                    return_value=result,
                ):
                    _expect_code(
                        self,
                        FileBoundaryErrorCode.SHORT_WRITE,
                        partial(
                            publish_new_file,
                            destination.as_posix(),
                            b"x",
                        ),
                    )
                self.assertFalse(destination.exists())
                self.assertEqual(
                    list(destination.parent.glob(".casefold-observatory-*.tmp")),
                    [],
                )

        with tempfile.TemporaryDirectory(prefix="casefold-write-error-") as directory:
            destination = Path(directory) / "receipt"
            with mock.patch.object(
                filesystem.os,
                "write",
                side_effect=OSError(errno.EIO, "private-path"),
            ):
                _expect_code(
                    self,
                    FileBoundaryErrorCode.IO_ERROR,
                    partial(publish_new_file, destination.as_posix(), b"x"),
                )
            self.assertEqual(
                list(destination.parent.glob(".casefold-observatory-*.tmp")),
                [],
            )

    def test_keyboard_interrupt_removes_only_owned_temporary(self) -> None:
        with tempfile.TemporaryDirectory(prefix="casefold-interrupt-") as directory:
            root = Path(directory)
            unrelated = root / ".casefold-observatory-unrelated.tmp"
            unrelated.write_bytes(b"keep")
            destination = root / "receipt"
            with (
                mock.patch.object(
                    filesystem.secrets,
                    "token_hex",
                    return_value="b" * 32,
                ),
                mock.patch.object(
                    filesystem.os,
                    "write",
                    side_effect=KeyboardInterrupt,
                ),
                self.assertRaises(KeyboardInterrupt),
            ):
                publish_new_file(destination.as_posix(), b"x")
            self.assertFalse(destination.exists())
            self.assertEqual(unrelated.read_bytes(), b"keep")
            self.assertFalse((root / f".casefold-observatory-{'b' * 32}.tmp").exists())

    def test_link_races_and_link_errors_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory(prefix="casefold-link-race-") as directory:
            destination = Path(directory) / "receipt"
            with mock.patch.object(
                filesystem.os,
                "link",
                side_effect=FileExistsError(errno.EEXIST, "private-path"),
            ):
                _expect_code(
                    self,
                    FileBoundaryErrorCode.DESTINATION_EXISTS,
                    partial(publish_new_file, destination.as_posix(), b"x"),
                )

        with tempfile.TemporaryDirectory(prefix="casefold-link-error-") as directory:
            destination = Path(directory) / "receipt"
            with mock.patch.object(
                filesystem.os,
                "link",
                side_effect=OSError(errno.EPERM, "private-path"),
            ):
                _expect_code(
                    self,
                    FileBoundaryErrorCode.IO_ERROR,
                    partial(publish_new_file, destination.as_posix(), b"x"),
                )

    def test_alias_created_during_link_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory(prefix="casefold-link-alias-") as directory:
            root = Path(directory)
            source = root / "source"
            source.write_bytes(b"source")
            identity = (source.stat().st_dev, source.stat().st_ino)
            destination = root / "receipt"
            original_link = os.link

            def create_alias_then_fail(
                _source_name: str,
                destination_name: str,
                *,
                src_dir_fd: int | None = None,
                dst_dir_fd: int | None = None,
                follow_symlinks: bool = True,
            ) -> None:
                self.assertIsNotNone(dst_dir_fd)
                original_link(
                    source.as_posix(),
                    destination_name,
                    dst_dir_fd=dst_dir_fd,
                    follow_symlinks=follow_symlinks,
                )
                raise FileExistsError(errno.EEXIST, "private-path")

            with mock.patch.object(
                filesystem.os,
                "link",
                side_effect=create_alias_then_fail,
            ):
                _expect_code(
                    self,
                    FileBoundaryErrorCode.ALIAS,
                    partial(
                        publish_new_file,
                        destination.as_posix(),
                        b"x",
                        forbidden_identities=(identity,),
                    ),
                )
            self.assertEqual(destination.read_bytes(), b"source")

    def test_directory_fsync_failure_keeps_complete_destination_and_cleans_temp(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory(prefix="casefold-fsync-failure-") as directory:
            destination = Path(directory) / "receipt"
            original_fsync = os.fsync
            calls = 0

            def fail_directory_fsync(descriptor: int) -> None:
                nonlocal calls
                calls += 1
                if calls == 2:
                    raise OSError(errno.EIO, "private-path")
                original_fsync(descriptor)

            with mock.patch.object(
                filesystem.os,
                "fsync",
                side_effect=fail_directory_fsync,
            ):
                _expect_code(
                    self,
                    FileBoundaryErrorCode.IO_ERROR,
                    partial(
                        publish_new_file,
                        destination.as_posix(),
                        b"complete",
                    ),
                )
            self.assertEqual(destination.read_bytes(), b"complete")
            self.assertEqual(
                list(destination.parent.glob(".casefold-observatory-*.tmp")),
                [],
            )

    def test_unlink_failure_is_redacted_and_finally_retries_cleanup(self) -> None:
        with tempfile.TemporaryDirectory(
            prefix="casefold-unlink-failure-"
        ) as directory:
            destination = Path(directory) / "receipt"
            original_unlink = os.unlink
            calls = 0

            def fail_first_unlink(
                path: str,
                *,
                dir_fd: int | None = None,
            ) -> None:
                nonlocal calls
                calls += 1
                if calls == 1:
                    raise OSError(errno.EIO, "private-path")
                original_unlink(path, dir_fd=dir_fd)

            with mock.patch.object(
                filesystem.os,
                "unlink",
                side_effect=fail_first_unlink,
            ):
                _expect_code(
                    self,
                    FileBoundaryErrorCode.IO_ERROR,
                    partial(publish_new_file, destination.as_posix(), b"x"),
                )
            self.assertEqual(destination.read_bytes(), b"x")
            self.assertEqual(
                list(destination.parent.glob(".casefold-observatory-*.tmp")),
                [],
            )

    def test_post_publication_identity_or_mode_swap_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory(prefix="casefold-post-publish-") as directory:
            destination = Path(directory) / "receipt"
            original_state = filesystem._destination_state
            calls = 0

            def changed_state(
                parent_descriptor: int,
                final_name: str,
            ) -> os.stat_result | None:
                nonlocal calls
                calls += 1
                result = original_state(parent_descriptor, final_name)
                if calls == 2:
                    assert result is not None
                    return _fake_stat(result, st_ino=result.st_ino + 1)
                return result

            with mock.patch.object(
                filesystem,
                "_destination_state",
                side_effect=changed_state,
            ):
                _expect_code(
                    self,
                    FileBoundaryErrorCode.CONCURRENT_MUTATION,
                    partial(publish_new_file, destination.as_posix(), b"x"),
                )
            self.assertEqual(destination.read_bytes(), b"x")

    def test_temporary_inode_must_be_single_link_regular_file(self) -> None:
        with tempfile.TemporaryDirectory(prefix="casefold-temp-inode-") as directory:
            destination = Path(directory) / "receipt"
            original_fstat = os.fstat

            def forged_link_count(descriptor: int) -> os.stat_result:
                result = original_fstat(descriptor)
                if stat.S_ISREG(result.st_mode):
                    return _fake_stat(result, st_nlink=2)
                return result

            with mock.patch.object(
                filesystem.os,
                "fstat",
                side_effect=forged_link_count,
            ):
                _expect_code(
                    self,
                    FileBoundaryErrorCode.MULTIPLE_LINKS,
                    partial(publish_new_file, destination.as_posix(), b"x"),
                )
            self.assertFalse(destination.exists())

    def test_internal_argument_types_fail_closed(self) -> None:
        with self.assertRaisesRegex(TypeError, "exact bytes"):
            publish_new_file("receipt", cast(bytes, bytearray(b"x")))
        with self.assertRaisesRegex(TypeError, "integer pairs"):
            publish_new_file(
                "receipt",
                b"x",
                forbidden_identities=cast(
                    tuple[tuple[int, int], ...],
                    ((1, "2"),),
                ),
            )


if __name__ == "__main__":
    unittest.main()

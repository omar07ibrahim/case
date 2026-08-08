"""Hardened POSIX file capture and no-clobber receipt publication."""

from __future__ import annotations

import errno
import os
import secrets
import stat
from dataclasses import dataclass, field
from enum import Enum
from typing import NoReturn

READ_CHUNK_BYTES = 65_536
TEMPORARY_NAME_ATTEMPTS = 16

_DIRECTORY_FLAGS = ("O_CLOEXEC", "O_DIRECTORY", "O_NOFOLLOW", "O_RDONLY")
_FILE_FLAGS = ("O_CLOEXEC", "O_NOFOLLOW", "O_NONBLOCK", "O_RDONLY")
_OUTPUT_FLAGS = (
    "O_CLOEXEC",
    "O_CREAT",
    "O_EXCL",
    "O_NOFOLLOW",
    "O_WRONLY",
)


class FileBoundaryErrorCode(Enum):
    """Stable, non-echoing failures for the POSIX file boundary."""

    ALIAS = "alias"
    CONCURRENT_MUTATION = "concurrent_mutation"
    DESTINATION_EXISTS = "destination_exists"
    DIRECTORY_COMPONENT = "directory_component"
    INVALID_PATH = "invalid_path"
    IO_ERROR = "io_error"
    MULTIPLE_LINKS = "multiple_links"
    NOT_FOUND = "not_found"
    READ_LIMIT = "read_limit"
    SHORT_WRITE = "short_write"
    SPECIAL_FILE = "special_file"
    SYMLINK = "symlink"
    TEMPORARY_COLLISION = "temporary_collision"
    TRAVERSAL = "traversal"
    UNSUPPORTED_PLATFORM = "unsupported_platform"


class FileBoundaryError(ValueError):
    """A filesystem rejection that never includes a pathname."""

    def __init__(self, code: FileBoundaryErrorCode) -> None:
        self.code = code
        super().__init__(f"file boundary rejected: {code.value}")


@dataclass(frozen=True, slots=True)
class CapturedFile:
    """Exact bytes plus the identity of the descriptor that supplied them."""

    data: bytes = field(repr=False)
    device: int
    inode: int


@dataclass(frozen=True, slots=True)
class _Snapshot:
    device: int
    inode: int
    size: int
    mtime_ns: int
    ctime_ns: int


def _raise_file(code: FileBoundaryErrorCode) -> NoReturn:
    raise FileBoundaryError(code) from None


def _required_flag(name: str) -> int:
    value = getattr(os, name, None)
    if type(value) is not int:
        _raise_file(FileBoundaryErrorCode.UNSUPPORTED_PLATFORM)
    return value


def _require_posix_primitives() -> None:
    if os.name != "posix":
        _raise_file(FileBoundaryErrorCode.UNSUPPORTED_PLATFORM)
    for name in {*_DIRECTORY_FLAGS, *_FILE_FLAGS, *_OUTPUT_FLAGS}:
        _required_flag(name)
    if (
        os.open not in os.supports_dir_fd
        or os.stat not in os.supports_dir_fd
        or os.link not in os.supports_dir_fd
        or os.unlink not in os.supports_dir_fd
        or os.stat not in os.supports_follow_symlinks
        or os.link not in os.supports_follow_symlinks
    ):
        _raise_file(FileBoundaryErrorCode.UNSUPPORTED_PLATFORM)


def _directory_flags() -> int:
    return (
        _required_flag("O_RDONLY")
        | _required_flag("O_DIRECTORY")
        | _required_flag("O_NOFOLLOW")
        | _required_flag("O_CLOEXEC")
    )


def _file_flags() -> int:
    return (
        _required_flag("O_RDONLY")
        | _required_flag("O_NONBLOCK")
        | _required_flag("O_NOFOLLOW")
        | _required_flag("O_CLOEXEC")
    )


def _output_flags() -> int:
    return (
        _required_flag("O_WRONLY")
        | _required_flag("O_CREAT")
        | _required_flag("O_EXCL")
        | _required_flag("O_NOFOLLOW")
        | _required_flag("O_CLOEXEC")
    )


def _snapshot(value: os.stat_result) -> _Snapshot:
    return _Snapshot(
        device=value.st_dev,
        inode=value.st_ino,
        size=value.st_size,
        mtime_ns=value.st_mtime_ns,
        ctime_ns=value.st_ctime_ns,
    )


def _identity(value: os.stat_result) -> tuple[int, int]:
    return value.st_dev, value.st_ino


def _safe_close(descriptor: int) -> None:
    try:
        os.close(descriptor)
    except OSError:
        pass


def _mapped_os_error(
    error: OSError,
    *,
    missing: FileBoundaryErrorCode = FileBoundaryErrorCode.NOT_FOUND,
) -> NoReturn:
    if error.errno == errno.ENOENT:
        _raise_file(missing)
    if error.errno == errno.ELOOP:
        _raise_file(FileBoundaryErrorCode.SYMLINK)
    if error.errno == errno.ENOTDIR:
        _raise_file(FileBoundaryErrorCode.DIRECTORY_COMPONENT)
    _raise_file(FileBoundaryErrorCode.IO_ERROR)


def _path_parts(path: str) -> tuple[bool, tuple[str, ...]]:
    if type(path) is not str:
        raise TypeError("path must be an exact str")
    if not path or path == "-" or "\x00" in path or path.endswith("/"):
        _raise_file(FileBoundaryErrorCode.INVALID_PATH)
    raw_parts = path.split("/")
    if ".." in raw_parts:
        _raise_file(FileBoundaryErrorCode.TRAVERSAL)
    absolute = path.startswith("/")
    parts = tuple(part for part in raw_parts if part)
    if not parts or parts[-1] == ".":
        _raise_file(FileBoundaryErrorCode.INVALID_PATH)
    return absolute, parts


def _stat_at(parent_descriptor: int, name: str) -> os.stat_result:
    try:
        return os.stat(
            name,
            dir_fd=parent_descriptor,
            follow_symlinks=False,
        )
    except OSError as error:
        _mapped_os_error(error)


def _open_parent(path: str) -> tuple[int, str]:
    _require_posix_primitives()
    absolute, parts = _path_parts(path)
    try:
        current = os.open("/" if absolute else ".", _directory_flags())
    except OSError as error:
        _mapped_os_error(error, missing=FileBoundaryErrorCode.IO_ERROR)

    try:
        base_info = os.fstat(current)
        if not stat.S_ISDIR(base_info.st_mode):
            _raise_file(FileBoundaryErrorCode.DIRECTORY_COMPONENT)
        for component in parts[:-1]:
            if component == ".":
                continue
            before = _stat_at(current, component)
            if stat.S_ISLNK(before.st_mode):
                _raise_file(FileBoundaryErrorCode.SYMLINK)
            if not stat.S_ISDIR(before.st_mode):
                _raise_file(FileBoundaryErrorCode.DIRECTORY_COMPONENT)
            try:
                next_descriptor = os.open(
                    component,
                    _directory_flags(),
                    dir_fd=current,
                )
            except OSError as error:
                _mapped_os_error(error)
            try:
                after = os.fstat(next_descriptor)
                if (
                    not stat.S_ISDIR(after.st_mode)
                    or _identity(before) != _identity(after)
                ):
                    _raise_file(FileBoundaryErrorCode.CONCURRENT_MUTATION)
            except BaseException:
                _safe_close(next_descriptor)
                raise
            _safe_close(current)
            current = next_descriptor
        return current, parts[-1]
    except BaseException:
        _safe_close(current)
        raise


def _require_regular_single_link(value: os.stat_result) -> None:
    if stat.S_ISLNK(value.st_mode):
        _raise_file(FileBoundaryErrorCode.SYMLINK)
    if not stat.S_ISREG(value.st_mode):
        _raise_file(FileBoundaryErrorCode.SPECIAL_FILE)
    if value.st_nlink != 1:
        _raise_file(FileBoundaryErrorCode.MULTIPLE_LINKS)


def _read_bounded(descriptor: int, limit: int) -> bytes:
    chunks: list[bytes] = []
    remaining = limit + 1
    while remaining:
        requested = min(READ_CHUNK_BYTES, remaining)
        try:
            chunk = os.read(descriptor, requested)
        except InterruptedError:
            continue
        except OSError as error:
            _mapped_os_error(error, missing=FileBoundaryErrorCode.IO_ERROR)
        if type(chunk) is not bytes or len(chunk) > requested:
            _raise_file(FileBoundaryErrorCode.IO_ERROR)
        if not chunk:
            break
        chunks.append(chunk)
        remaining -= len(chunk)
    result = b"".join(chunks)
    if len(result) > limit:
        _raise_file(FileBoundaryErrorCode.READ_LIMIT)
    return result


def capture_regular_file(path: str, *, limit: int) -> CapturedFile:
    """Capture one stable, single-link regular file through a pinned descriptor."""

    if type(limit) is not int or limit < 0:
        raise ValueError("limit must be a non-negative exact integer")
    parent_descriptor, final_name = _open_parent(path)
    file_descriptor: int | None = None
    try:
        before_name = _stat_at(parent_descriptor, final_name)
        _require_regular_single_link(before_name)
        try:
            file_descriptor = os.open(
                final_name,
                _file_flags(),
                dir_fd=parent_descriptor,
            )
        except OSError as error:
            _mapped_os_error(error)
        before_file = os.fstat(file_descriptor)
        _require_regular_single_link(before_file)
        if _snapshot(before_name) != _snapshot(before_file):
            _raise_file(FileBoundaryErrorCode.CONCURRENT_MUTATION)
        if before_file.st_size > limit:
            _raise_file(FileBoundaryErrorCode.READ_LIMIT)

        captured = _read_bounded(file_descriptor, limit)
        after_file = os.fstat(file_descriptor)
        _require_regular_single_link(after_file)
        if _snapshot(before_file) != _snapshot(after_file):
            _raise_file(FileBoundaryErrorCode.CONCURRENT_MUTATION)
        try:
            after_name = os.stat(
                final_name,
                dir_fd=parent_descriptor,
                follow_symlinks=False,
            )
        except OSError:
            _raise_file(FileBoundaryErrorCode.CONCURRENT_MUTATION)
        _require_regular_single_link(after_name)
        if _snapshot(before_file) != _snapshot(after_name):
            _raise_file(FileBoundaryErrorCode.CONCURRENT_MUTATION)
        return CapturedFile(
            data=captured,
            device=after_file.st_dev,
            inode=after_file.st_ino,
        )
    except FileBoundaryError:
        raise
    except OSError:
        _raise_file(FileBoundaryErrorCode.IO_ERROR)
    finally:
        if file_descriptor is not None:
            _safe_close(file_descriptor)
        _safe_close(parent_descriptor)


def _destination_state(
    parent_descriptor: int,
    final_name: str,
) -> os.stat_result | None:
    try:
        return os.stat(
            final_name,
            dir_fd=parent_descriptor,
            follow_symlinks=False,
        )
    except FileNotFoundError:
        return None
    except OSError as error:
        _mapped_os_error(error, missing=FileBoundaryErrorCode.IO_ERROR)


def _reject_existing_destination(
    existing: os.stat_result,
    forbidden_identities: tuple[tuple[int, int], ...],
) -> NoReturn:
    if _identity(existing) in forbidden_identities:
        _raise_file(FileBoundaryErrorCode.ALIAS)
    if stat.S_ISLNK(existing.st_mode):
        _raise_file(FileBoundaryErrorCode.SYMLINK)
    _raise_file(FileBoundaryErrorCode.DESTINATION_EXISTS)


def _reserve_temporary(parent_descriptor: int) -> tuple[int, str]:
    for _attempt in range(TEMPORARY_NAME_ATTEMPTS):
        name = f".casefold-observatory-{secrets.token_hex(16)}.tmp"
        try:
            descriptor = os.open(
                name,
                _output_flags(),
                0o600,
                dir_fd=parent_descriptor,
            )
        except FileExistsError:
            continue
        except OSError as error:
            _mapped_os_error(error, missing=FileBoundaryErrorCode.IO_ERROR)
        return descriptor, name
    _raise_file(FileBoundaryErrorCode.TEMPORARY_COLLISION)


def _write_complete(descriptor: int, data: bytes) -> None:
    offset = 0
    while offset < len(data):
        try:
            written = os.write(descriptor, data[offset:])
        except InterruptedError:
            continue
        except OSError as error:
            _mapped_os_error(error, missing=FileBoundaryErrorCode.IO_ERROR)
        if type(written) is not int or not 0 < written <= len(data) - offset:
            _raise_file(FileBoundaryErrorCode.SHORT_WRITE)
        offset += written


def _cleanup_temporary(parent_descriptor: int, temporary_name: str | None) -> None:
    if temporary_name is None:
        return
    try:
        os.unlink(temporary_name, dir_fd=parent_descriptor)
    except OSError:
        pass


def publish_new_file(
    path: str,
    data: bytes,
    *,
    forbidden_identities: tuple[tuple[int, int], ...] = (),
) -> None:
    """Durably publish exact bytes once, without replacing any destination."""

    if type(data) is not bytes:
        raise TypeError("data must be exact bytes")
    if type(forbidden_identities) is not tuple or any(
        type(identity) is not tuple
        or len(identity) != 2
        or any(type(part) is not int for part in identity)
        for identity in forbidden_identities
    ):
        raise TypeError("forbidden identities must be exact integer pairs")

    parent_descriptor, final_name = _open_parent(path)
    temporary_descriptor: int | None = None
    temporary_name: str | None = None
    linked_identity: tuple[int, int] | None = None
    try:
        existing = _destination_state(parent_descriptor, final_name)
        if existing is not None:
            _reject_existing_destination(existing, forbidden_identities)

        temporary_descriptor, temporary_name = _reserve_temporary(parent_descriptor)
        temporary_info = os.fstat(temporary_descriptor)
        _require_regular_single_link(temporary_info)
        if _identity(temporary_info) in forbidden_identities:
            _raise_file(FileBoundaryErrorCode.ALIAS)

        _write_complete(temporary_descriptor, data)
        os.fchmod(temporary_descriptor, 0o600)
        os.fsync(temporary_descriptor)
        temporary_info = os.fstat(temporary_descriptor)
        _require_regular_single_link(temporary_info)
        linked_identity = _identity(temporary_info)

        try:
            os.link(
                temporary_name,
                final_name,
                src_dir_fd=parent_descriptor,
                dst_dir_fd=parent_descriptor,
                follow_symlinks=False,
            )
        except FileExistsError:
            existing = _destination_state(parent_descriptor, final_name)
            if existing is not None:
                _reject_existing_destination(existing, forbidden_identities)
            _raise_file(FileBoundaryErrorCode.DESTINATION_EXISTS)
        except OSError as error:
            _mapped_os_error(error, missing=FileBoundaryErrorCode.IO_ERROR)

        os.fsync(parent_descriptor)
        os.unlink(temporary_name, dir_fd=parent_descriptor)
        temporary_name = None
        os.fsync(parent_descriptor)

        published = _destination_state(parent_descriptor, final_name)
        if (
            published is None
            or not stat.S_ISREG(published.st_mode)
            or published.st_nlink != 1
            or _identity(published) != linked_identity
            or stat.S_IMODE(published.st_mode) != 0o600
        ):
            _raise_file(FileBoundaryErrorCode.CONCURRENT_MUTATION)
    except FileBoundaryError:
        raise
    except OSError:
        _raise_file(FileBoundaryErrorCode.IO_ERROR)
    finally:
        if temporary_descriptor is not None:
            _safe_close(temporary_descriptor)
        _cleanup_temporary(parent_descriptor, temporary_name)
        _safe_close(parent_descriptor)

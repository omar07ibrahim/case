"""Installed, non-echoing command line for portable collision receipts."""

from __future__ import annotations

import hashlib
import json
import sys
from dataclasses import dataclass
from enum import Enum
from typing import BinaryIO, NoReturn, cast

from casefold_observatory.collision import CollisionAnalysisError
from casefold_observatory.corpus import (
    MAX_CORPUS_SOURCE_BYTES,
    CorpusErrorCode,
    CorpusIngestionError,
)
from casefold_observatory.filesystem import (
    CapturedFile,
    FileBoundaryError,
    FileBoundaryErrorCode,
    capture_regular_file,
    publish_new_file,
)
from casefold_observatory.model import (
    HazardHandling,
    TransformPolicy,
    TransformStep,
    create_policy,
)
from casefold_observatory.receipt import (
    DISTRIBUTION_VERSION,
    MAX_RECEIPT_BYTES,
    ReceiptErrorCode,
    ReceiptVerificationError,
    canonical_receipt_bytes,
    create_collision_receipt,
    verify_collision_receipt,
)
from casefold_observatory.report import OfflineReportError, render_offline_report

EXIT_SUCCESS = 0
EXIT_INTERNAL = 1
EXIT_USAGE = 2
EXIT_POLICY = 3
EXIT_MISMATCH = 4
EXIT_FILESYSTEM = 5

MAX_POLICY_ARGUMENT_BYTES = 256

_TOP_HELP = b"""Usage: casefold-observatory <command> [options]

Commands:
  analyze  create a no-clobber collision receipt
  report   render a verified, no-clobber offline HTML report
  verify   replay a receipt against exact source bytes

Run 'casefold-observatory <command> --help' for command options.
"""
_ANALYZE_HELP = (
    b"Usage: casefold-observatory analyze --source PATH --policy SPEC "
    b"[--policy SPEC ...] --receipt PATH\n\n"
    b"SPEC is exactly (reject|preserve)@STEP[,STEP...].\n"
    b"One through eight policies are required and their order is significant.\n"
)
_REPORT_HELP = (
    b"Usage: casefold-observatory report --source PATH --receipt PATH "
    b"--output PATH\n"
)
_VERIFY_HELP = b"""Usage: casefold-observatory verify --source PATH --receipt PATH
"""


class _UsageError(ValueError):
    pass


class _PolicyArgumentError(ValueError):
    pass


class _StaticRequest(Enum):
    TOP_HELP = "top_help"
    ANALYZE_HELP = "analyze_help"
    REPORT_HELP = "report_help"
    VERIFY_HELP = "verify_help"
    VERSION = "version"


@dataclass(frozen=True, slots=True)
class _AnalyzeCommand:
    source_path: str
    receipt_path: str
    policies: tuple[TransformPolicy, ...]


@dataclass(frozen=True, slots=True)
class _ReportCommand:
    source_path: str
    receipt_path: str
    output_path: str


@dataclass(frozen=True, slots=True)
class _VerifyCommand:
    source_path: str
    receipt_path: str


_Command = _StaticRequest | _AnalyzeCommand | _ReportCommand | _VerifyCommand


def _raise_usage() -> NoReturn:
    raise _UsageError from None


def _raise_policy() -> NoReturn:
    raise _PolicyArgumentError from None


def _parse_policy_argument(value: str) -> TransformPolicy:
    if (
        type(value) is not str
        or not value.isascii()
        or len(value.encode("ascii")) > MAX_POLICY_ARGUMENT_BYTES
        or value.count("@") != 1
    ):
        _raise_policy()
    handling_value, steps_value = value.split("@")
    step_values = steps_value.split(",")
    if not 1 <= len(step_values) <= 8 or any(not step for step in step_values):
        _raise_policy()
    try:
        handling = HazardHandling(handling_value)
        steps = tuple(TransformStep(step) for step in step_values)
        return create_policy(steps, hazard_handling=handling)
    except (TypeError, ValueError):
        _raise_policy()


def _parse_analyze(argv: tuple[str, ...]) -> _AnalyzeCommand | _StaticRequest:
    if argv == ("analyze", "--help"):
        return _StaticRequest.ANALYZE_HELP
    if len(argv) < 7 or len(argv) % 2 == 0:
        _raise_usage()

    source_path: str | None = None
    receipt_path: str | None = None
    policy_values: list[str] = []
    index = 1
    while index < len(argv):
        option = argv[index]
        value = argv[index + 1]
        if option == "--source":
            if source_path is not None or value == "-":
                _raise_usage()
            source_path = value
        elif option == "--receipt":
            if receipt_path is not None or value == "-":
                _raise_usage()
            receipt_path = value
        elif option == "--policy":
            policy_values.append(value)
            if len(policy_values) > 8:
                _raise_policy()
        else:
            _raise_usage()
        index += 2

    if source_path is None or receipt_path is None or not policy_values:
        _raise_usage()
    policies = tuple(_parse_policy_argument(value) for value in policy_values)
    return _AnalyzeCommand(
        source_path=source_path,
        receipt_path=receipt_path,
        policies=policies,
    )


def _parse_verify(argv: tuple[str, ...]) -> _VerifyCommand | _StaticRequest:
    if argv == ("verify", "--help"):
        return _StaticRequest.VERIFY_HELP
    if len(argv) != 5:
        _raise_usage()

    source_path: str | None = None
    receipt_path: str | None = None
    index = 1
    while index < len(argv):
        option = argv[index]
        value = argv[index + 1]
        if option == "--source":
            if source_path is not None or value == "-":
                _raise_usage()
            source_path = value
        elif option == "--receipt":
            if receipt_path is not None or value == "-":
                _raise_usage()
            receipt_path = value
        else:
            _raise_usage()
        index += 2
    # Exact arity plus duplicate and unknown-option rejection establish both fields.
    return _VerifyCommand(
        source_path=cast(str, source_path),
        receipt_path=cast(str, receipt_path),
    )


def _parse_report(argv: tuple[str, ...]) -> _ReportCommand | _StaticRequest:
    if argv == ("report", "--help"):
        return _StaticRequest.REPORT_HELP
    if len(argv) != 7:
        _raise_usage()

    source_path: str | None = None
    receipt_path: str | None = None
    output_path: str | None = None
    index = 1
    while index < len(argv):
        option = argv[index]
        value = argv[index + 1]
        if option == "--source":
            if source_path is not None or value == "-":
                _raise_usage()
            source_path = value
        elif option == "--receipt":
            if receipt_path is not None or value == "-":
                _raise_usage()
            receipt_path = value
        elif option == "--output":
            if output_path is not None or value == "-":
                _raise_usage()
            output_path = value
        else:
            _raise_usage()
        index += 2
    return _ReportCommand(
        source_path=cast(str, source_path),
        receipt_path=cast(str, receipt_path),
        output_path=cast(str, output_path),
    )


def _parse_command(argv: tuple[str, ...]) -> _Command:
    if type(argv) is not tuple or any(type(argument) is not str for argument in argv):
        raise TypeError("argv must be an exact tuple of exact strings")
    if argv == ("--help",):
        return _StaticRequest.TOP_HELP
    if argv == ("--version",):
        return _StaticRequest.VERSION
    if not argv:
        _raise_usage()
    if argv[0] == "analyze":
        return _parse_analyze(argv)
    if argv[0] == "report":
        return _parse_report(argv)
    if argv[0] == "verify":
        return _parse_verify(argv)
    _raise_usage()


def _canonical_line(document: dict[str, object]) -> bytes:
    return (
        json.dumps(
            document,
            ensure_ascii=True,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        )
        + "\n"
    ).encode("ascii")


def _error_line(
    code: str,
    *,
    physical_line_ordinal: int | None = None,
    input_record_ordinal: int | None = None,
    canonical_record_ordinal: int | None = None,
    policy_ordinal: int | None = None,
) -> bytes:
    document: dict[str, object] = {"code": code, "status": "error"}
    if physical_line_ordinal is not None:
        document["physical_line_ordinal"] = physical_line_ordinal
    if input_record_ordinal is not None:
        document["input_record_ordinal"] = input_record_ordinal
    if canonical_record_ordinal is not None:
        document["canonical_record_ordinal"] = canonical_record_ordinal
    if policy_ordinal is not None:
        document["policy_ordinal"] = policy_ordinal
    return _canonical_line(document)


def _static_output(request: _StaticRequest) -> bytes:
    if request is _StaticRequest.TOP_HELP:
        return _TOP_HELP
    if request is _StaticRequest.ANALYZE_HELP:
        return _ANALYZE_HELP
    if request is _StaticRequest.REPORT_HELP:
        return _REPORT_HELP
    if request is _StaticRequest.VERIFY_HELP:
        return _VERIFY_HELP
    return f"casefold-observatory {DISTRIBUTION_VERSION}\n".encode("ascii")


def _analyze(command: _AnalyzeCommand) -> bytes:
    source = capture_regular_file(
        command.source_path,
        limit=MAX_CORPUS_SOURCE_BYTES,
    )
    receipt = create_collision_receipt(source.data, command.policies)
    receipt_bytes = canonical_receipt_bytes(receipt)
    publish_new_file(
        command.receipt_path,
        receipt_bytes,
        forbidden_identities=((source.device, source.inode),),
    )
    graph = receipt.graph
    return _canonical_line(
        {
            "colliding_record_count": graph.colliding_record_count,
            "component_count": len(graph.components),
            "policy_group_count": len(graph.policy_groups),
            "receipt_sha256": hashlib.sha256(receipt_bytes).hexdigest(),
            "record_count": graph.record_count,
            "status": "analyzed",
            "witness_count": len(graph.witnesses),
        }
    )


def _same_file(left: CapturedFile, right: CapturedFile) -> bool:
    return (left.device, left.inode) == (right.device, right.inode)


def _verify(command: _VerifyCommand) -> bytes:
    receipt_file = capture_regular_file(
        command.receipt_path,
        limit=MAX_RECEIPT_BYTES,
    )
    source_file = capture_regular_file(
        command.source_path,
        limit=MAX_CORPUS_SOURCE_BYTES,
    )
    if _same_file(receipt_file, source_file):
        raise FileBoundaryError(FileBoundaryErrorCode.ALIAS)
    verify_collision_receipt(receipt_file.data, source_file.data)
    return _canonical_line(
        {
            "receipt_sha256": hashlib.sha256(receipt_file.data).hexdigest(),
            "status": "verified",
        }
    )


def _report(command: _ReportCommand) -> bytes:
    receipt_file = capture_regular_file(
        command.receipt_path,
        limit=MAX_RECEIPT_BYTES,
    )
    source_file = capture_regular_file(
        command.source_path,
        limit=MAX_CORPUS_SOURCE_BYTES,
    )
    if _same_file(receipt_file, source_file):
        raise FileBoundaryError(FileBoundaryErrorCode.ALIAS)
    report_bytes = render_offline_report(receipt_file.data, source_file.data)
    publish_new_file(
        command.output_path,
        report_bytes,
        forbidden_identities=(
            (receipt_file.device, receipt_file.inode),
            (source_file.device, source_file.inode),
        ),
    )
    return _canonical_line(
        {
            "receipt_sha256": hashlib.sha256(receipt_file.data).hexdigest(),
            "report_byte_count": len(report_bytes),
            "report_sha256": hashlib.sha256(report_bytes).hexdigest(),
            "status": "reported",
        }
    )


_CORPUS_RESOURCE_CODES = {
    CorpusErrorCode.JSON_DEPTH,
    CorpusErrorCode.LINE_COUNT,
    CorpusErrorCode.LINE_TOO_LARGE,
    CorpusErrorCode.SOURCE_TOO_LARGE,
}
_RECEIPT_SCHEMA_CODES = {
    ReceiptErrorCode.DUPLICATE_KEY,
    ReceiptErrorCode.INVALID_JSON,
    ReceiptErrorCode.INVALID_RECEIPT,
    ReceiptErrorCode.NONCANONICAL_RECEIPT,
    ReceiptErrorCode.SCHEMA_MISMATCH,
}
_RECEIPT_RESOURCE_CODES = {
    ReceiptErrorCode.JSON_DEPTH,
    ReceiptErrorCode.RECEIPT_TOO_LARGE,
}


def _dispatch(argv: tuple[str, ...]) -> tuple[int, bytes, bytes]:
    try:
        command = _parse_command(argv)
        if type(command) is _StaticRequest:
            return EXIT_SUCCESS, _static_output(command), b""
        if type(command) is _AnalyzeCommand:
            return EXIT_SUCCESS, _analyze(command), b""
        if type(command) is _ReportCommand:
            return EXIT_SUCCESS, _report(command), b""
        if type(command) is _VerifyCommand:
            return EXIT_SUCCESS, _verify(command), b""
        raise RuntimeError("parsed command has an unsupported type")
    except _UsageError:
        return (
            EXIT_USAGE,
            b"",
            _error_line("usage.invalid_arguments"),
        )
    except _PolicyArgumentError:
        return (
            EXIT_POLICY,
            b"",
            _error_line("policy.invalid_argument"),
        )
    except CorpusIngestionError as error:
        status = EXIT_POLICY if error.code in _CORPUS_RESOURCE_CODES else EXIT_USAGE
        return (
            status,
            b"",
            _error_line(
                f"corpus.{error.code.value}",
                physical_line_ordinal=error.physical_line_ordinal,
                input_record_ordinal=error.input_record_ordinal,
            ),
        )
    except CollisionAnalysisError as error:
        return (
            EXIT_POLICY,
            b"",
            _error_line(
                f"collision.{error.code.value}",
                input_record_ordinal=error.input_record_ordinal,
                canonical_record_ordinal=error.canonical_record_ordinal,
                policy_ordinal=error.policy_ordinal,
            ),
        )
    except OfflineReportError as error:
        return (
            EXIT_POLICY,
            b"",
            _error_line(f"report.{error.code.value}"),
        )
    except ReceiptVerificationError as error:
        if error.code in _RECEIPT_SCHEMA_CODES:
            status = EXIT_USAGE
        elif error.code in _RECEIPT_RESOURCE_CODES:
            status = EXIT_POLICY
        else:
            status = EXIT_MISMATCH
        return (
            status,
            b"",
            _error_line(
                f"receipt.{error.code.value}",
                policy_ordinal=error.policy_ordinal,
            ),
        )
    except FileBoundaryError as error:
        status = (
            EXIT_POLICY
            if error.code is FileBoundaryErrorCode.READ_LIMIT
            else EXIT_FILESYSTEM
        )
        return (
            status,
            b"",
            _error_line(f"filesystem.{error.code.value}"),
        )
    except KeyboardInterrupt:
        return (
            EXIT_INTERNAL,
            b"",
            _error_line("internal.interrupted"),
        )
    except Exception:  # noqa: BLE001 - public boundary must redact unknown errors.
        return (
            EXIT_INTERNAL,
            b"",
            _error_line("internal.unexpected"),
        )


def _write_all(stream: BinaryIO, payload: bytes) -> None:
    offset = 0
    while offset < len(payload):
        try:
            written = stream.write(payload[offset:])
        except InterruptedError:
            continue
        if type(written) is not int or not 0 < written <= len(payload) - offset:
            raise OSError("bounded terminal write failed")
        offset += written
    stream.flush()


def _default_stream(name: str) -> BinaryIO:
    stream = getattr(sys, name)
    buffer = getattr(stream, "buffer", None)
    if buffer is None:
        raise RuntimeError("binary standard stream is unavailable")
    return cast(BinaryIO, buffer)


def main(
    argv: tuple[str, ...] | None = None,
    *,
    stdout: BinaryIO | None = None,
    stderr: BinaryIO | None = None,
) -> int:
    """Run the installed command without exposing exception or argument text."""

    arguments = tuple(sys.argv[1:]) if argv is None else argv
    try:
        status, output, error = _dispatch(arguments)
        output_stream = _default_stream("stdout") if stdout is None else stdout
        error_stream = _default_stream("stderr") if stderr is None else stderr
        if output:
            _write_all(output_stream, output)
        if error:
            _write_all(error_stream, error)
        return status
    except (Exception, KeyboardInterrupt):  # noqa: BLE001 - fail closed.
        return EXIT_INTERNAL

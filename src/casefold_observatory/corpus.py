"""Strict, bounded JSON Lines ingestion for portable collision receipts."""

from __future__ import annotations

import json
from enum import Enum
from typing import NoReturn, cast

from casefold_observatory.collision import IdentifierRecord, create_identifier_record

CORPUS_FORMAT = "casefold-observatory.identifier-corpus-jsonl"
CORPUS_FORMAT_VERSION = 1
CORPUS_SCHEMA = "casefold-observatory.identifier-corpus"
CORPUS_SCHEMA_VERSION = 1
MAX_CORPUS_SOURCE_BYTES = 4_194_304
MAX_CORPUS_LINE_BYTES = 8_192
MAX_CORPUS_LINES = 2_049
MAX_JSON_DEPTH = 16


class CorpusErrorCode(Enum):
    """Stable failures for the bounded corpus byte boundary."""

    BYTE_ORDER_MARK = "byte_order_mark"
    DUPLICATE_KEY = "duplicate_key"
    DUPLICATE_RECORD_ID = "duplicate_record_id"
    INVALID_HEADER = "invalid_header"
    INVALID_JSON = "invalid_json"
    INVALID_LINE_TERMINATOR = "invalid_line_terminator"
    INVALID_RECORD = "invalid_record"
    INVALID_UTF8 = "invalid_utf8"
    JSON_DEPTH = "json_depth"
    LINE_COUNT = "line_count"
    LINE_TOO_LARGE = "line_too_large"
    SOURCE_TOO_LARGE = "source_too_large"


class CorpusIngestionError(ValueError):
    """A redacted corpus failure with numeric context only."""

    def __init__(
        self,
        code: CorpusErrorCode,
        *,
        physical_line_ordinal: int | None = None,
        input_record_ordinal: int | None = None,
    ) -> None:
        self.code = code
        self.physical_line_ordinal = physical_line_ordinal
        self.input_record_ordinal = input_record_ordinal
        details: list[str] = []
        if physical_line_ordinal is not None:
            details.append(f"physical_line_ordinal={physical_line_ordinal}")
        if input_record_ordinal is not None:
            details.append(f"input_record_ordinal={input_record_ordinal}")
        suffix = "" if not details else f" ({', '.join(details)})"
        super().__init__(f"corpus ingestion rejected: {code.value}{suffix}")


class _JsonIssue(Enum):
    DUPLICATE_KEY = "duplicate_key"
    INVALID_ENCODING = "invalid_encoding"
    INVALID_JSON = "invalid_json"
    JSON_DEPTH = "json_depth"


class _BoundedJsonError(ValueError):
    def __init__(self, issue: _JsonIssue) -> None:
        self.issue = issue
        super().__init__(f"bounded JSON rejected: {issue.value}")


class _DuplicateKeyError(ValueError):
    pass


class _NonFiniteError(ValueError):
    pass


def _raise_corpus(
    code: CorpusErrorCode,
    *,
    physical_line_ordinal: int | None = None,
    input_record_ordinal: int | None = None,
) -> NoReturn:
    raise CorpusIngestionError(
        code,
        physical_line_ordinal=physical_line_ordinal,
        input_record_ordinal=input_record_ordinal,
    ) from None


def _json_object_pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
    document: dict[str, object] = {}
    for key, value in pairs:
        if key in document:
            raise _DuplicateKeyError
        document[key] = value
    return document


def _reject_nonfinite(_value: str) -> NoReturn:
    raise _NonFiniteError


def _enforce_json_depth(text: str) -> None:
    depth = 0
    in_string = False
    escaped = False
    for character in text:
        if in_string:
            if escaped:
                escaped = False
            elif character == "\\":
                escaped = True
            elif character == '"':
                in_string = False
            continue
        if character == '"':
            in_string = True
        elif character in "[{":
            depth += 1
            if depth > MAX_JSON_DEPTH:
                raise _BoundedJsonError(_JsonIssue.JSON_DEPTH)
        elif character in "]}":
            depth -= 1


def _load_bounded_json(raw: bytes, *, ascii_only: bool) -> object:
    encoding = "ascii" if ascii_only else "utf-8"
    try:
        text = raw.decode(encoding, errors="strict")
    except UnicodeDecodeError:
        raise _BoundedJsonError(_JsonIssue.INVALID_ENCODING) from None
    _enforce_json_depth(text)
    try:
        value: object = json.loads(
            text,
            object_pairs_hook=_json_object_pairs,
            parse_constant=_reject_nonfinite,
        )
    except _DuplicateKeyError:
        raise _BoundedJsonError(_JsonIssue.DUPLICATE_KEY) from None
    except (json.JSONDecodeError, _NonFiniteError, RecursionError, ValueError):
        raise _BoundedJsonError(_JsonIssue.INVALID_JSON) from None
    return value


def _corpus_json_code(issue: _JsonIssue) -> CorpusErrorCode:
    if issue is _JsonIssue.INVALID_ENCODING:
        return CorpusErrorCode.INVALID_UTF8
    if issue is _JsonIssue.JSON_DEPTH:
        return CorpusErrorCode.JSON_DEPTH
    if issue is _JsonIssue.DUPLICATE_KEY:
        return CorpusErrorCode.DUPLICATE_KEY
    return CorpusErrorCode.INVALID_JSON


def _physical_lines(source: bytes) -> tuple[bytes, ...]:
    lines: list[bytes] = []
    start = 0
    while start < len(source):
        newline = source.find(b"\n", start)
        terminated = newline >= 0
        end = newline + 1 if terminated else len(source)
        physical = source[start:end]
        line_ordinal = len(lines)
        if len(physical) > MAX_CORPUS_LINE_BYTES:
            _raise_corpus(
                CorpusErrorCode.LINE_TOO_LARGE,
                physical_line_ordinal=line_ordinal,
            )
        content = physical[:-1] if terminated else physical
        if terminated and content.endswith(b"\r"):
            content = content[:-1]
        if b"\r" in content:
            _raise_corpus(
                CorpusErrorCode.INVALID_LINE_TERMINATOR,
                physical_line_ordinal=line_ordinal,
            )
        lines.append(content)
        if len(lines) > MAX_CORPUS_LINES:
            _raise_corpus(
                CorpusErrorCode.LINE_COUNT,
                physical_line_ordinal=line_ordinal,
            )
        start = end
    return tuple(lines)


def _load_corpus_line(
    raw: bytes,
    *,
    physical_line_ordinal: int,
    input_record_ordinal: int | None,
) -> object:
    try:
        return _load_bounded_json(raw, ascii_only=False)
    except _BoundedJsonError as error:
        _raise_corpus(
            _corpus_json_code(error.issue),
            physical_line_ordinal=physical_line_ordinal,
            input_record_ordinal=input_record_ordinal,
        )


def _exact_object(value: object) -> dict[str, object] | None:
    if type(value) is not dict:
        return None
    return cast(dict[str, object], value)


def _parse_corpus_bytes(source_bytes: bytes) -> tuple[IdentifierRecord, ...]:
    if type(source_bytes) is not bytes:
        raise TypeError("source_bytes must be an exact bytes object")
    if len(source_bytes) > MAX_CORPUS_SOURCE_BYTES:
        _raise_corpus(CorpusErrorCode.SOURCE_TOO_LARGE)
    if source_bytes.startswith(b"\xef\xbb\xbf"):
        _raise_corpus(
            CorpusErrorCode.BYTE_ORDER_MARK,
            physical_line_ordinal=0,
        )

    lines = _physical_lines(source_bytes)
    if not lines:
        _raise_corpus(
            CorpusErrorCode.INVALID_HEADER,
            physical_line_ordinal=0,
        )
    header_value = _load_corpus_line(
        lines[0],
        physical_line_ordinal=0,
        input_record_ordinal=None,
    )
    header = _exact_object(header_value)
    if (
        header is None
        or set(header) != {"schema", "schema_version"}
        or type(header.get("schema")) is not str
        or header["schema"] != CORPUS_SCHEMA
        or type(header.get("schema_version")) is not int
        or header["schema_version"] != CORPUS_SCHEMA_VERSION
    ):
        _raise_corpus(
            CorpusErrorCode.INVALID_HEADER,
            physical_line_ordinal=0,
        )

    records: list[IdentifierRecord] = []
    seen_record_ids: set[str] = set()
    for input_record_ordinal, raw in enumerate(lines[1:]):
        physical_line_ordinal = input_record_ordinal + 1
        value = _load_corpus_line(
            raw,
            physical_line_ordinal=physical_line_ordinal,
            input_record_ordinal=input_record_ordinal,
        )
        document = _exact_object(value)
        if (
            document is None
            or set(document) != {"identifier", "record_id"}
            or type(document.get("record_id")) is not str
            or type(document.get("identifier")) is not str
        ):
            _raise_corpus(
                CorpusErrorCode.INVALID_RECORD,
                physical_line_ordinal=physical_line_ordinal,
                input_record_ordinal=input_record_ordinal,
            )
        record_id = cast(str, document["record_id"])
        identifier = cast(str, document["identifier"])
        try:
            record = create_identifier_record(record_id, identifier)
        except (TypeError, ValueError):
            _raise_corpus(
                CorpusErrorCode.INVALID_RECORD,
                physical_line_ordinal=physical_line_ordinal,
                input_record_ordinal=input_record_ordinal,
            )
        if record_id in seen_record_ids:
            _raise_corpus(
                CorpusErrorCode.DUPLICATE_RECORD_ID,
                physical_line_ordinal=physical_line_ordinal,
                input_record_ordinal=input_record_ordinal,
            )
        seen_record_ids.add(record_id)
        records.append(record)
    return tuple(records)

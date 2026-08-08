from __future__ import annotations

import json
import unittest
from typing import cast

from casefold_observatory import (
    CORPUS_SCHEMA,
    CORPUS_SCHEMA_VERSION,
    MAX_CORPUS_LINE_BYTES,
    MAX_CORPUS_LINES,
    MAX_CORPUS_SOURCE_BYTES,
    MAX_JSON_DEPTH,
    CorpusErrorCode,
    CorpusIngestionError,
)
from casefold_observatory import corpus as corpus_module

_HEADER = b'{"schema":"casefold-observatory.identifier-corpus","schema_version":1}'


def _record(record_id: str, identifier: str) -> bytes:
    return json.dumps(
        {"identifier": identifier, "record_id": record_id},
        ensure_ascii=True,
        separators=(",", ":"),
    ).encode("ascii")


def _source(*records: bytes, newline: bytes = b"\n", final: bool = True) -> bytes:
    parts = (_HEADER, *records)
    result = newline.join(parts)
    return result + newline if final else result


def _assert_code(
    testcase: unittest.TestCase,
    source: object,
    code: CorpusErrorCode,
) -> CorpusIngestionError:
    with testcase.assertRaises(CorpusIngestionError) as caught:
        corpus_module._parse_corpus_bytes(source)  # type: ignore[arg-type]
    testcase.assertIs(caught.exception.code, code)
    testcase.assertNotIn("private-value", str(caught.exception))
    return caught.exception


class CorpusBoundaryTests(unittest.TestCase):
    def test_contract_constants_and_numeric_error_context(self) -> None:
        self.assertEqual(CORPUS_SCHEMA, "casefold-observatory.identifier-corpus")
        self.assertEqual(CORPUS_SCHEMA_VERSION, 1)
        self.assertEqual(MAX_CORPUS_SOURCE_BYTES, 4_194_304)
        self.assertEqual(MAX_CORPUS_LINE_BYTES, 8_192)
        self.assertEqual(MAX_CORPUS_LINES, 2_049)
        self.assertEqual(MAX_JSON_DEPTH, 16)
        error = CorpusIngestionError(
            CorpusErrorCode.INVALID_RECORD,
            physical_line_ordinal=2,
            input_record_ordinal=1,
        )
        self.assertEqual(
            str(error),
            "corpus ingestion rejected: invalid_record "
            "(physical_line_ordinal=2, input_record_ordinal=1)",
        )
        self.assertEqual(
            str(CorpusIngestionError(CorpusErrorCode.SOURCE_TOO_LARGE)),
            "corpus ingestion rejected: source_too_large",
        )

    def test_lf_crlf_final_line_and_header_only_are_accepted(self) -> None:
        record = _record("alpha", "Straße")
        variants = (
            _source(record),
            _source(record, final=False),
            _source(record, newline=b"\r\n"),
            _source(record, newline=b"\r\n", final=False),
        )
        for variant in variants:
            with self.subTest(variant=variant[-4:]):
                parsed = corpus_module._parse_corpus_bytes(variant)
                self.assertEqual(len(parsed), 1)
                self.assertEqual(parsed[0].record_id, "alpha")
                self.assertEqual(parsed[0].identifier, "Straße")
        self.assertEqual(corpus_module._parse_corpus_bytes(_source()), ())

    def test_exact_physical_line_and_line_count_bounds(self) -> None:
        padded_header = (
            _HEADER + b" " * (MAX_CORPUS_LINE_BYTES - len(_HEADER) - 1) + b"\n"
        )
        self.assertEqual(len(padded_header), MAX_CORPUS_LINE_BYTES)
        self.assertEqual(corpus_module._parse_corpus_bytes(padded_header), ())
        _assert_code(
            self,
            padded_header[:-1] + b" \n",
            CorpusErrorCode.LINE_TOO_LARGE,
        )

        lines = [_HEADER]
        lines.extend(_record(f"r{index:04d}", "x") for index in range(2_048))
        maximum = b"\n".join(lines) + b"\n"
        self.assertEqual(len(maximum.splitlines()), MAX_CORPUS_LINES)
        self.assertEqual(len(corpus_module._parse_corpus_bytes(maximum)), 2_048)
        too_many = maximum + b"{}\n"
        error = _assert_code(self, too_many, CorpusErrorCode.LINE_COUNT)
        self.assertEqual(error.physical_line_ordinal, MAX_CORPUS_LINES)

    def test_exact_complete_source_byte_bound(self) -> None:
        lines = [_HEADER + b"\n"]
        lines.extend(_record(f"r{index:04d}", "x") + b"\n" for index in range(2_048))
        remaining = MAX_CORPUS_SOURCE_BYTES - sum(map(len, lines))
        padded: list[bytes] = []
        for line in lines:
            addition = min(remaining, MAX_CORPUS_LINE_BYTES - len(line))
            padded.append(line[:-1] + b" " * addition + b"\n")
            remaining -= addition
        self.assertEqual(remaining, 0)
        exact = b"".join(padded)
        self.assertEqual(len(exact), MAX_CORPUS_SOURCE_BYTES)
        self.assertEqual(len(corpus_module._parse_corpus_bytes(exact)), 2_048)
        _assert_code(
            self,
            exact + b"x",
            CorpusErrorCode.SOURCE_TOO_LARGE,
        )

    def test_encoding_terminator_and_json_failures_are_redacted(self) -> None:
        cases = (
            (b"\xef\xbb\xbf" + _source(), CorpusErrorCode.BYTE_ORDER_MARK),
            (_HEADER + b"\r", CorpusErrorCode.INVALID_LINE_TERMINATOR),
            (_HEADER + b"\r " + b"\n", CorpusErrorCode.INVALID_LINE_TERMINATOR),
            (
                _source(b'{"identifier":"\xff","record_id":"private-value"}'),
                CorpusErrorCode.INVALID_UTF8,
            ),
            (b"", CorpusErrorCode.INVALID_HEADER),
            (b"\n", CorpusErrorCode.INVALID_JSON),
            (_source(b""), CorpusErrorCode.INVALID_JSON),
            (_source(b"# private-value"), CorpusErrorCode.INVALID_JSON),
            (_source(b"{"), CorpusErrorCode.INVALID_JSON),
            (
                _source(b'{"identifier":NaN,"record_id":"private-value"}'),
                CorpusErrorCode.INVALID_JSON,
            ),
            (
                _source(b'{"identifier":Infinity,"record_id":"private-value"}'),
                CorpusErrorCode.INVALID_JSON,
            ),
            (
                _source(b'{"identifier":-Infinity,"record_id":"private-value"}'),
                CorpusErrorCode.INVALID_JSON,
            ),
            (
                (
                    b'{"schema":"casefold-observatory.identifier-corpus",'
                    b'"schema":"private-value","schema_version":1}\n'
                ),
                CorpusErrorCode.DUPLICATE_KEY,
            ),
            (
                _source(
                    b'{"identifier":"a","identifier":"private-value",'
                    b'"record_id":"alpha"}'
                ),
                CorpusErrorCode.DUPLICATE_KEY,
            ),
        )
        for source, expected in cases:
            with self.subTest(expected=expected, source=source[:20]):
                error = _assert_code(self, source, expected)
                self.assertTrue(error.__suppress_context__)

    def test_header_and_record_exact_schema_validation(self) -> None:
        bad_headers = (
            b"null\n",
            b"[]\n",
            b"{}\n",
            b'{"schema":"wrong","schema_version":1}\n',
            b'{"schema":"casefold-observatory.identifier-corpus"}\n',
            (
                b'{"schema":"casefold-observatory.identifier-corpus",'
                b'"schema_version":true}\n'
            ),
            (
                b'{"schema":"casefold-observatory.identifier-corpus",'
                b'"schema_version":1,"x":0}\n'
            ),
        )
        for source in bad_headers:
            with self.subTest(header=source):
                _assert_code(self, source, CorpusErrorCode.INVALID_HEADER)

        bad_records = (
            b"null",
            b"[]",
            b"{}",
            b'{"identifier":"private-value"}',
            b'{"identifier":"private-value","record_id":"alpha","x":0}',
            b'{"identifier":1,"record_id":"alpha"}',
            b'{"identifier":"private-value","record_id":true}',
            b'{"identifier":"private-value","record_id":"Upper"}',
            b'{"identifier":"","record_id":"alpha"}',
            b'{"identifier":"private-value","record_id":"' + b"a" * 65 + b'"}',
            b'{"identifier":"\\ud800","record_id":"alpha"}',
        )
        for record in bad_records:
            with self.subTest(record=record):
                error = _assert_code(
                    self,
                    _source(record),
                    CorpusErrorCode.INVALID_RECORD,
                )
                self.assertEqual(error.physical_line_ordinal, 1)
                self.assertEqual(error.input_record_ordinal, 0)

        duplicate = _source(_record("alpha", "a"), _record("alpha", "b"))
        error = _assert_code(
            self,
            duplicate,
            CorpusErrorCode.DUPLICATE_RECORD_ID,
        )
        self.assertEqual(error.physical_line_ordinal, 2)
        self.assertEqual(error.input_record_ordinal, 1)

    def test_json_depth_boundary_and_braces_inside_strings(self) -> None:
        safe_string = _record("alpha", r"quoted \" {[ ]}")
        self.assertEqual(
            corpus_module._parse_corpus_bytes(_source(safe_string))[0].record_id,
            "alpha",
        )
        depth_16 = b"[" * 15 + b"{}" + b"]" * 15 + b"\n"
        _assert_code(self, depth_16, CorpusErrorCode.INVALID_HEADER)
        depth_17 = b"[" * 16 + b"{}" + b"]" * 16 + b"\n"
        _assert_code(self, depth_17, CorpusErrorCode.JSON_DEPTH)

    def test_exact_bytes_type_is_required(self) -> None:
        with self.assertRaisesRegex(TypeError, "exact bytes"):
            corpus_module._parse_corpus_bytes(cast(bytes, bytearray(_source())))

    def test_internal_json_code_mapping_is_total(self) -> None:
        mapping = {
            corpus_module._JsonIssue.INVALID_ENCODING: CorpusErrorCode.INVALID_UTF8,
            corpus_module._JsonIssue.JSON_DEPTH: CorpusErrorCode.JSON_DEPTH,
            corpus_module._JsonIssue.DUPLICATE_KEY: CorpusErrorCode.DUPLICATE_KEY,
            corpus_module._JsonIssue.INVALID_JSON: CorpusErrorCode.INVALID_JSON,
        }
        for issue, expected in mapping.items():
            with self.subTest(issue=issue):
                self.assertIs(corpus_module._corpus_json_code(issue), expected)


if __name__ == "__main__":
    unittest.main()

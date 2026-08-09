from __future__ import annotations

import base64
import hashlib
import json
import re
import unittest
from unittest import mock

from casefold_observatory import (
    MAX_OFFLINE_REPORT_BYTES,
    MAX_OFFLINE_REPORT_CODEPOINT_TOKENS,
    MAX_OFFLINE_REPORT_RECORDS,
    OFFLINE_REPORT_SCHEMA,
    OFFLINE_REPORT_SCHEMA_VERSION,
    HazardHandling,
    OfflineReportError,
    OfflineReportErrorCode,
    TransformStep,
    canonical_receipt_bytes,
    create_collision_receipt,
    create_identifier_record,
    create_policy,
    render_offline_report,
)
from casefold_observatory import report as report_module

_HEADER = b'{"schema":"casefold-observatory.identifier-corpus","schema_version":1}'


def _source(*records: tuple[str, str]) -> bytes:
    lines = [_HEADER]
    lines.extend(
        json.dumps(
            {"identifier": identifier, "record_id": record_id},
            ensure_ascii=True,
            separators=(",", ":"),
        ).encode("ascii")
        for record_id, identifier in records
    )
    return b"\n".join(lines) + b"\n"


def _receipt(source: bytes, *, preserve: bool = False) -> bytes:
    handling = HazardHandling.PRESERVE if preserve else HazardHandling.REJECT
    policies = (
        create_policy(
            (TransformStep.NFKC, TransformStep.CASEFOLD),
            hazard_handling=handling,
        ),
        create_policy((TransformStep.LOWER,), hazard_handling=handling),
    )
    return canonical_receipt_bytes(create_collision_receipt(source, policies))


class OfflineReportTests(unittest.TestCase):
    def test_contract_constants_and_redacted_error(self) -> None:
        self.assertEqual(
            OFFLINE_REPORT_SCHEMA,
            "casefold-observatory.offline-report",
        )
        self.assertEqual(OFFLINE_REPORT_SCHEMA_VERSION, 1)
        self.assertEqual(MAX_OFFLINE_REPORT_RECORDS, 256)
        self.assertEqual(MAX_OFFLINE_REPORT_CODEPOINT_TOKENS, 8_192)
        self.assertEqual(MAX_OFFLINE_REPORT_BYTES, 8_388_608)
        error = OfflineReportError(OfflineReportErrorCode.TOKEN_LIMIT)
        self.assertEqual(str(error), "offline report rejected: token_limit")
        self.assertNotIn("private-value", str(error))

    def test_report_is_deterministic_ascii_source_bound_and_network_free(self) -> None:
        source = _source(
            ("ascii-a", "A"),
            ("duplicate-a", "A"),
            ("fullwidth-a", "Ａ"),
            ("markup", '<script>&"'),
            ("markup-duplicate", '<script>&"'),
        )
        receipt = _receipt(source)
        first = render_offline_report(receipt, source)
        second = render_offline_report(receipt, source)
        self.assertEqual(first, second)
        self.assertTrue(first.isascii())
        self.assertTrue(first.startswith(b"<!doctype html>\n"))
        self.assertIn(OFFLINE_REPORT_SCHEMA.encode("ascii"), first)
        self.assertIn(hashlib.sha256(receipt).hexdigest().encode("ascii"), first)
        self.assertIn(b"U+FF21", first)
        self.assertIn(b"U+003C", first)
        self.assertIn(b"exact duplicate", first)
        self.assertIn(b"transform_stage", first)
        self.assertIn(b"No isolated records.", first)
        self.assertNotIn(b"<script>", first)
        self.assertNotIn(b"http://", first)
        self.assertNotIn(b"https://", first)
        self.assertNotIn(b"onload=", first)
        self.assertNotIn(b"javascript:", first)

        style_match = re.search(rb"<style>(.*?)</style>", first, re.DOTALL)
        self.assertIsNotNone(style_match)
        style = style_match.group(1)  # type: ignore[union-attr]
        digest = base64.b64encode(hashlib.sha256(style).digest())
        self.assertIn(b"style-src 'sha256-" + digest + b"'", first)
        self.assertIn(b"script-src 'none'", first)
        self.assertIn(b"connect-src 'none'", first)
        self.assertIn(b"form-action 'none'", first)

    def test_controls_whitespace_combining_and_bidi_are_explicit(self) -> None:
        identifier = "A\u0301 \t\n\u202e\u0378"
        source = _source(("hazards", identifier))
        report = render_offline_report(_receipt(source, preserve=True), source)
        for marker in (
            b"U+0041",
            b"U+0301",
            b"U+0020",
            b"U+0009",
            b"U+000A",
            b"U+202E",
            b"U+0378",
            b"COMBINING ACUTE ACCENT",
            b"RIGHT-TO-LEFT OVERRIDE",
            b"UNNAMED",
            b"SPACE",
            b"TAB",
            b"LF",
            b"bidi=RLO",
            b"bidi=NONE",
            b"glyph mark",
            b"glyph invisible",
        ):
            self.assertIn(marker, report)
        self.assertNotIn(identifier.encode("utf-8"), report)

    def test_empty_collision_sections_and_isolated_record_are_labeled(self) -> None:
        source = _source(("isolated", "plain"))
        report = render_offline_report(_receipt(source), source)
        self.assertIn(b"No collision components.", report)
        self.assertIn(b"No exact duplicate groups.", report)
        self.assertIn(b"No policy collision groups.", report)
        self.assertIn(b"No witnesses.", report)
        self.assertIn(b"isolated", report)

    def test_record_token_and_output_limits_fail_closed(self) -> None:
        source = _source(("alpha", "A"))
        receipt = _receipt(source)
        cases = (
            ("MAX_OFFLINE_REPORT_RECORDS", 0, OfflineReportErrorCode.RECORD_LIMIT),
            (
                "MAX_OFFLINE_REPORT_CODEPOINT_TOKENS",
                0,
                OfflineReportErrorCode.TOKEN_LIMIT,
            ),
            ("MAX_OFFLINE_REPORT_BYTES", 1, OfflineReportErrorCode.OUTPUT_TOO_LARGE),
        )
        for name, value, code in cases:
            with self.subTest(name=name):
                with mock.patch.object(report_module, name, value):
                    with self.assertRaises(OfflineReportError) as caught:
                        render_offline_report(receipt, source)
                self.assertIs(caught.exception.code, code)

    def test_verified_graph_and_parsed_records_must_match(self) -> None:
        source = _source(("alpha", "A"))
        receipt = _receipt(source)
        replacement = create_identifier_record("other", "A")
        with mock.patch.object(
            report_module,
            "_parse_corpus_bytes",
            return_value=(replacement,),
        ):
            with self.assertRaises(OfflineReportError) as caught:
                render_offline_report(receipt, source)
        self.assertIs(caught.exception.code, OfflineReportErrorCode.INVALID_MODEL)

    def test_non_ascii_internal_metadata_and_document_fail_closed(self) -> None:
        with self.assertRaises(OfflineReportError) as caught:
            report_module._escaped("private-é")
        self.assertIs(caught.exception.code, OfflineReportErrorCode.INVALID_MODEL)

        source = _source(("alpha", "A"))
        receipt = _receipt(source)
        with mock.patch.object(report_module, "_policy_cards", return_value="é"):
            with self.assertRaises(OfflineReportError) as document_error:
                render_offline_report(receipt, source)
        self.assertIs(
            document_error.exception.code,
            OfflineReportErrorCode.INVALID_MODEL,
        )

    def test_receipt_and_source_verification_errors_propagate(self) -> None:
        source = _source(("alpha", "A"))
        receipt = _receipt(source)
        with self.assertRaises(ValueError):
            render_offline_report(receipt, _source(("alpha", "B")))
        with self.assertRaises(TypeError):
            render_offline_report(receipt, bytearray(source))  # type: ignore[arg-type]


if __name__ == "__main__":
    unittest.main()

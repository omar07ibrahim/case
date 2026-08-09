from __future__ import annotations

import base64
import hashlib
import json
import re
import unittest
from html.parser import HTMLParser
from unittest import mock

from casefold_observatory import (
    MAX_OFFLINE_REPORT_BYTES,
    MAX_OFFLINE_REPORT_CODEPOINT_TOKENS,
    MAX_OFFLINE_REPORT_COMPONENTS,
    MAX_OFFLINE_REPORT_GROUPS,
    MAX_OFFLINE_REPORT_RECORDS,
    MAX_OFFLINE_REPORT_WITNESSES,
    OFFLINE_REPORT_SCHEMA,
    OFFLINE_REPORT_SCHEMA_VERSION,
    HazardHandling,
    OfflineReportError,
    OfflineReportErrorCode,
    ReceiptVerificationError,
    TransformPolicy,
    TransformStep,
    canonical_receipt_bytes,
    create_collision_receipt,
    create_identifier_record,
    create_policy,
    render_offline_report,
)
from casefold_observatory import receipt as receipt_module
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


def _policies(*, preserve: bool = False) -> tuple[TransformPolicy, ...]:
    handling = HazardHandling.PRESERVE if preserve else HazardHandling.REJECT
    return (
        create_policy(
            (TransformStep.NFKC, TransformStep.CASEFOLD),
            hazard_handling=handling,
        ),
        create_policy((TransformStep.LOWER,), hazard_handling=handling),
    )


def _receipt(source: bytes, *, preserve: bool = False) -> bytes:
    return canonical_receipt_bytes(
        create_collision_receipt(source, _policies(preserve=preserve))
    )


class _ReportParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.data_chunks: list[str] = []
        self.start_tags: list[tuple[str, list[tuple[str, str | None]]]] = []

    def handle_starttag(
        self,
        tag: str,
        attrs: list[tuple[str, str | None]],
    ) -> None:
        self.start_tags.append((tag, attrs))

    def handle_data(self, data: str) -> None:
        self.data_chunks.append(data)


def _parsed(report: bytes) -> _ReportParser:
    parser = _ReportParser()
    parser.feed(report.decode("ascii"))
    parser.close()
    return parser


class OfflineReportTests(unittest.TestCase):
    def test_contract_constants_and_redacted_error(self) -> None:
        self.assertEqual(
            OFFLINE_REPORT_SCHEMA,
            "casefold-observatory.offline-report",
        )
        self.assertEqual(OFFLINE_REPORT_SCHEMA_VERSION, 1)
        self.assertEqual(MAX_OFFLINE_REPORT_COMPONENTS, 1_024)
        self.assertEqual(MAX_OFFLINE_REPORT_GROUPS, 4_096)
        self.assertEqual(MAX_OFFLINE_REPORT_RECORDS, 256)
        self.assertEqual(MAX_OFFLINE_REPORT_CODEPOINT_TOKENS, 8_192)
        self.assertEqual(MAX_OFFLINE_REPORT_WITNESSES, 4_096)
        self.assertEqual(MAX_OFFLINE_REPORT_BYTES, 8_388_608)
        error = OfflineReportError(OfflineReportErrorCode.TOKEN_LIMIT)
        self.assertEqual(str(error), "offline report rejected: token_limit")
        self.assertNotIn("private-value", str(error))

    def test_report_is_deterministic_source_bound_and_exact_csp(self) -> None:
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
        self.assertNotIn(b"javascript:", first)
        self.assertNotIn(b" unsafe-inline", first)
        self.assertNotIn(b" style=", first)
        self.assertNotIn(b"url(", first)
        self.assertNotIn(b"@import", first)
        self.assertNotIn(b"@font-face", first)

        style_match = re.search(rb"<style>(.*?)</style>", first, re.DOTALL)
        self.assertIsNotNone(style_match)
        style = style_match.group(1)  # type: ignore[union-attr]
        digest = base64.b64encode(hashlib.sha256(style).digest())
        expected_csp = (
            b"default-src 'none'; base-uri 'none'; form-action 'none'; "
            b"object-src 'none'; script-src 'none'; script-src-elem 'none'; "
            b"script-src-attr 'none'; style-src 'sha256-"
            + digest
            + b"'; style-src-elem 'sha256-"
            + digest
            + b"'; style-src-attr 'none'; img-src 'none'; font-src 'none'; "
            b"media-src 'none'; connect-src 'none'; worker-src 'none'; "
            b"child-src 'none'; frame-src 'none'; manifest-src 'none'"
        )
        csp_meta = (
            b'<meta http-equiv="Content-Security-Policy" content="'
            + expected_csp
            + b'">'
        )
        self.assertIn(csp_meta, first)
        self.assertLess(first.index(b'<meta charset="utf-8">'), first.index(csp_meta))
        self.assertLess(first.index(csp_meta), first.index(b"<style>"))

    def test_dom_allowlist_and_decoded_text_are_ascii(self) -> None:
        source = _source(
            ("close-style", "</style><script>alert(1)</script>"),
            ("comment", "<!--"),
            ("entity", "&#x202E;"),
            ("event", '"><img src=x onerror=alert(1)>'),
            ("url", "url(file:///etc/passwd)"),
        )
        report = render_offline_report(_receipt(source), source)
        parser = _parsed(report)
        self.assertTrue("".join(parser.data_chunks).isascii())
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
        for tag, attrs in parser.start_tags:
            with self.subTest(tag=tag):
                self.assertIn(tag, allowed_tags)
                for name, _value in attrs:
                    self.assertFalse(name.startswith("on"))
                    self.assertNotIn(name, url_attributes)
                    self.assertNotEqual(name, "style")
        tags = tuple(tag for tag, _attrs in parser.start_tags)
        self.assertNotIn("script", tags)
        self.assertNotIn("img", tags)
        self.assertNotIn("a", tags)
        self.assertNotIn("form", tags)

    def test_unicode_metadata_never_emits_non_ascii_dom_text(self) -> None:
        bidi_controls = (
            0x061C,
            0x200E,
            0x200F,
            0x202A,
            0x202B,
            0x202C,
            0x202D,
            0x202E,
            0x2066,
            0x2067,
            0x2068,
            0x2069,
        )
        identifier = (
            "".join(chr(codepoint) for codepoint in bidi_controls)
            + "\x00\t\n\r\x7f"
            + "\ufeff\u200d\u200c\u00ad"
            + "\u0301\u0903\u20dd"
            + "\u00a0\u2028\u2029"
            + "\u0627"
            + "\U0001f469\u200d\U0001f4bb\ufe0f"
            + "\ue000\u0378\ufdd0\U0010ffff"
        )
        source = _source(("unicode-spectrum", identifier))
        report = render_offline_report(_receipt(source, preserve=True), source)
        parsed_text = "".join(_parsed(report).data_chunks)
        self.assertTrue(parsed_text.isascii())
        for codepoint in bidi_controls:
            self.assertIn(f"U+{codepoint:04X}".encode("ascii"), report)
            self.assertNotIn(
                f"&#x{codepoint:X};".encode("ascii").lower(),
                report.lower(),
            )
        for marker in (
            b"U+0000",
            b"U+0009",
            b"U+000A",
            b"U+000D",
            b"U+007F",
            b"U+0301",
            b"U+0903",
            b"U+20DD",
            b"U+00A0",
            b"U+2028",
            b"U+2029",
            b"U+E000",
            b"U+0378",
            b"U+FDD0",
            b"U+10FFFF",
            b"engine_hazard=bidi_control",
            b"engine_hazard=control",
            b"engine_hazard=format",
            b"display_flags=WHITESPACE",
            b"COMBINING_MARK",
            b"SEPARATOR",
            b"PRIVATE_USE",
            b"UNASSIGNED",
            b"NONCHARACTER",
            b"NON_ASCII",
            b"ccc=0",
            b"glyph mark",
            b"glyph invisible",
            b"glyph non-ascii",
        ):
            self.assertIn(marker, report)
        self.assertNotIn(identifier.encode("utf-8"), report)

    def test_reverse_input_order_maps_values_to_canonical_record_ordinals(self) -> None:
        source = _source(("zeta", "Z"), ("alpha", "A"))
        receipt = _receipt(source)
        with mock.patch.object(
            receipt_module,
            "_parse_corpus_bytes",
            wraps=receipt_module._parse_corpus_bytes,
        ) as parse:
            report = render_offline_report(receipt, source)
        self.assertEqual(parse.call_count, 1)
        alpha = report.index(b"<h3>alpha</h3>")
        zeta = report.index(b"<h3>zeta</h3>")
        self.assertLess(alpha, zeta)
        self.assertIn(b"U+0041", report[alpha:zeta])
        self.assertNotIn(b"U+005A", report[alpha:zeta])
        self.assertIn(b"U+005A", report[zeta:])

    def test_empty_collision_sections_and_isolated_record_are_labeled(self) -> None:
        source = _source(("isolated", "plain"))
        report = render_offline_report(_receipt(source), source)
        self.assertIn(b"No collision components.", report)
        self.assertIn(b"No exact duplicate groups.", report)
        self.assertIn(b"No policy collision groups.", report)
        self.assertIn(b"No witnesses.", report)
        self.assertIn(b"isolated", report)

    def test_every_budget_accepts_boundary_and_rejects_one_past(self) -> None:
        source = _source(("alpha", "A"))
        receipt = _receipt(source)
        baseline = render_offline_report(receipt, source)
        exact_limits = (
            ("MAX_OFFLINE_REPORT_RECORDS", 1, OfflineReportErrorCode.RECORD_LIMIT),
            (
                "MAX_OFFLINE_REPORT_CODEPOINT_TOKENS",
                1,
                OfflineReportErrorCode.TOKEN_LIMIT,
            ),
            (
                "MAX_OFFLINE_REPORT_COMPONENTS",
                0,
                OfflineReportErrorCode.STRUCTURE_LIMIT,
            ),
            (
                "MAX_OFFLINE_REPORT_GROUPS",
                0,
                OfflineReportErrorCode.STRUCTURE_LIMIT,
            ),
            (
                "MAX_OFFLINE_REPORT_WITNESSES",
                0,
                OfflineReportErrorCode.STRUCTURE_LIMIT,
            ),
            (
                "MAX_OFFLINE_REPORT_BYTES",
                len(baseline),
                OfflineReportErrorCode.OUTPUT_TOO_LARGE,
            ),
        )
        for name, exact, code in exact_limits:
            with (
                self.subTest(name=name, case="boundary"),
                mock.patch.object(report_module, name, exact),
            ):
                self.assertEqual(render_offline_report(receipt, source), baseline)
            with (
                self.subTest(name=name, case="one-past"),
                mock.patch.object(report_module, name, exact - 1),
                self.assertRaises(OfflineReportError) as caught,
            ):
                render_offline_report(receipt, source)
            self.assertIs(caught.exception.code, code)

    def test_verified_graph_and_canonical_records_must_match(self) -> None:
        source = _source(("alpha", "A"))
        receipt_bytes = _receipt(source)
        verified, records = report_module._verify_collision_receipt_and_records(
            receipt_bytes,
            source,
        )
        replacement = create_identifier_record("other", "A")
        with (
            mock.patch.object(
                report_module,
                "_verify_collision_receipt_and_records",
                return_value=(verified, (replacement,)),
            ),
            self.assertRaises(OfflineReportError) as caught,
        ):
            render_offline_report(receipt_bytes, source)
        self.assertIs(caught.exception.code, OfflineReportErrorCode.INVALID_MODEL)
        self.assertEqual(records[0].record_id, "alpha")

        duplicate = create_identifier_record("alpha", "B")
        with self.assertRaises(ReceiptVerificationError):
            receipt_module._canonical_verified_records(
                (records[0], duplicate),
                ("alpha",),
            )
        with self.assertRaises(ReceiptVerificationError):
            receipt_module._canonical_verified_records(
                records,
                ("other",),
            )

    def test_non_ascii_internal_metadata_and_document_fail_closed(self) -> None:
        with self.assertRaises(OfflineReportError) as caught:
            report_module._escaped("private-é")
        self.assertIs(caught.exception.code, OfflineReportErrorCode.INVALID_MODEL)

        source = _source(("alpha", "A"))
        receipt = _receipt(source)
        verified, records = report_module._verify_collision_receipt_and_records(
            receipt,
            source,
        )
        with (
            mock.patch.object(report_module, "_policy_cards", return_value="é"),
            self.assertRaises(OfflineReportError) as document_error,
        ):
            report_module._render_verified_report(receipt, verified, records)
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

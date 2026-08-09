"""Verified, bounded, network-free HTML views of collision receipts."""

from __future__ import annotations

import base64
import hashlib
import html
import unicodedata
from enum import Enum
from typing import NoReturn

from casefold_observatory.collision import (
    CollisionWitness,
    IdentifierRecord,
    PolicyCollisionGroup,
)
from casefold_observatory.engine import _hazard_kind
from casefold_observatory.model import HazardKind
from casefold_observatory.receipt import (
    CollisionReceipt,
    _verify_collision_receipt_and_records,
)

OFFLINE_REPORT_SCHEMA = "casefold-observatory.offline-report"
OFFLINE_REPORT_SCHEMA_VERSION = 1
MAX_OFFLINE_REPORT_COMPONENTS = 1_024
MAX_OFFLINE_REPORT_GROUPS = 4_096
MAX_OFFLINE_REPORT_RECORDS = 256
MAX_OFFLINE_REPORT_CODEPOINT_TOKENS = 8_192
MAX_OFFLINE_REPORT_WITNESSES = 4_096
MAX_OFFLINE_REPORT_BYTES = 8_388_608

_STYLE = """:root{color-scheme:dark;font-family:ui-sans-serif,system-ui,sans-serif;background:#091015;color:#edf5f1}
*{box-sizing:border-box}
body{margin:0;background:#091015;color:#edf5f1}
main{width:min(1500px,calc(100% - 32px));margin:0 auto;padding:32px 0 64px}
h1,h2,h3,p{margin-top:0}
h1{font-size:clamp(2rem,5vw,4rem);letter-spacing:-.04em;margin-bottom:12px}
h2{font-size:1.55rem;margin:48px 0 18px}
h3{font-size:1rem;margin-bottom:12px}
.eyebrow,.label{font:700 .75rem ui-monospace,monospace;letter-spacing:.14em;text-transform:uppercase;color:#63e6d2}
.lede{max-width:920px;color:#b7c8c2;font-size:1.05rem;line-height:1.6}
.boundary{margin:28px 0;padding:18px 20px;border:1px solid #f4c95d;border-radius:16px;background:#171b17;color:#f9e7ae}
.metrics,.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:14px}
.card,.metric,.component{border:1px solid #36505a;border-radius:16px;background:#111c21;padding:18px;overflow:hidden}
.metric strong{display:block;margin-top:8px;font:700 1.45rem ui-monospace,monospace;color:#fff;overflow-wrap:anywhere}
.meta{color:#9fb4ad;font:500 .82rem ui-monospace,monospace;line-height:1.5;overflow-wrap:anywhere}
.codepoints{display:grid;grid-template-columns:repeat(auto-fit,minmax(170px,1fr));gap:8px;padding:0;margin:14px 0 0;list-style:none}
.cp{min-width:0;border:1px solid #2c424b;border-radius:12px;background:#0b1419;padding:10px}
.glyph{display:flex;align-items:center;justify-content:center;min-height:48px;margin-bottom:8px;border-radius:8px;background:#17262d;font-size:1.65rem;unicode-bidi:isolate}
.glyph.invisible,.glyph.non-ascii{font:700 .72rem ui-monospace,monospace;color:#f4c95d;letter-spacing:.08em}
.glyph.mark{border:1px dashed #63e6d2;font:700 .72rem ui-monospace,monospace;color:#63e6d2}
.cp code,.members code{font:600 .78rem ui-monospace,monospace;color:#63e6d2}
.cp small{display:block;margin-top:5px;color:#9fb4ad;font:500 .68rem ui-monospace,monospace;overflow-wrap:anywhere}
.members{display:flex;flex-wrap:wrap;gap:7px;margin-top:12px}
.members code{padding:5px 8px;border-radius:999px;background:#17262d}
.stack{display:grid;gap:14px}
table{width:100%;border-collapse:collapse;font-size:.82rem}
th,td{text-align:left;padding:10px;border-bottom:1px solid #2c424b;vertical-align:top;overflow-wrap:anywhere}
th{color:#9fb4ad;font:700 .7rem ui-monospace,monospace;text-transform:uppercase;letter-spacing:.08em}
td code{font:500 .75rem ui-monospace,monospace;color:#d7e4df}
.table-wrap{overflow-x:auto;border:1px solid #36505a;border-radius:16px;background:#111c21;padding:6px 12px}
.empty{color:#9fb4ad;font-style:italic}
footer{margin-top:48px;padding-top:20px;border-top:1px solid #36505a;color:#9fb4ad;font-size:.85rem;line-height:1.6}
@media(max-width:620px){main{width:min(100% - 20px,1500px);padding-top:20px}.card,.metric,.component{padding:14px}.codepoints{grid-template-columns:repeat(auto-fit,minmax(135px,1fr))}th,td{padding:8px}}
"""


class OfflineReportErrorCode(Enum):
    """Stable, non-echoing offline report failures."""

    INVALID_MODEL = "invalid_model"
    OUTPUT_TOO_LARGE = "output_too_large"
    RECORD_LIMIT = "record_limit"
    STRUCTURE_LIMIT = "structure_limit"
    TOKEN_LIMIT = "token_limit"


class OfflineReportError(ValueError):
    """A bounded report failure that never echoes source values."""

    def __init__(self, code: OfflineReportErrorCode) -> None:
        self.code = code
        super().__init__(f"offline report rejected: {code.value}")


def _raise_report(code: OfflineReportErrorCode) -> NoReturn:
    raise OfflineReportError(code) from None


def _escaped(value: str) -> str:
    if not value.isascii():
        _raise_report(OfflineReportErrorCode.INVALID_MODEL)
    return html.escape(value, quote=True)


def _is_noncharacter(codepoint: int) -> bool:
    return 0xFDD0 <= codepoint <= 0xFDEF or codepoint & 0xFFFF in {
        0xFFFE,
        0xFFFF,
    }


def _display_flags(character: str, category: str) -> tuple[str, ...]:
    codepoint = ord(character)
    flags: list[str] = []
    if character.isspace():
        flags.append("WHITESPACE")
    if not character.isprintable():
        flags.append("NONPRINTABLE")
    if category.startswith("M"):
        flags.append("COMBINING_MARK")
    if category.startswith("Z"):
        flags.append("SEPARATOR")
    if category == "Co":
        flags.append("PRIVATE_USE")
    if category == "Cn":
        flags.append("UNASSIGNED")
    if _is_noncharacter(codepoint):
        flags.append("NONCHARACTER")
    if codepoint > 0x7F:
        flags.append("NON_ASCII")
    return tuple(flags)


def _glyph_label(character: str, category: str) -> tuple[str, str]:
    codepoint = ord(character)
    if 0x21 <= codepoint <= 0x7E:
        return html.escape(character, quote=True), "glyph"
    if category.startswith("M"):
        return "COMBINING MARK", "glyph mark"
    hazard = _hazard_kind(character)
    if hazard is HazardKind.BIDI_CONTROL:
        return "BIDI CONTROL", "glyph invisible"
    invisible = {" ": "SPACE", "\t": "TAB", "\n": "LF", "\r": "CR"}
    if character in invisible:
        return invisible[character], "glyph invisible"
    if category == "Co":
        return "PRIVATE USE", "glyph non-ascii"
    if category == "Cn":
        return "UNASSIGNED", "glyph non-ascii"
    if category.startswith("Z"):
        return "SEPARATOR", "glyph invisible"
    if category.startswith("C"):
        return "NONPRINTABLE", "glyph invisible"
    return "NON-ASCII", "glyph non-ascii"


def _codepoint_tokens(value: str) -> str:
    items: list[str] = []
    for ordinal, character in enumerate(value):
        codepoint = ord(character)
        category = unicodedata.category(character)
        bidi = unicodedata.bidirectional(character) or "NONE"
        name = unicodedata.name(character, "UNNAMED")
        combining_class = unicodedata.combining(character)
        utf8_hex = character.encode("utf-8").hex().upper()
        hazard = _hazard_kind(character)
        hazard_label = "none" if hazard is None else hazard.value
        flags = _display_flags(character, category)
        flag_label = "none" if not flags else ",".join(flags)
        glyph, glyph_class = _glyph_label(character, category)
        items.append(
            '<li class="cp">'
            f'<span class="{glyph_class}" aria-hidden="true">{glyph}</span>'
            f"<code>#{ordinal} U+{codepoint:04X}</code>"
            f"<small>{_escaped(name)}</small>"
            f"<small>gc={_escaped(category)} bidi={_escaped(bidi)} "
            f"ccc={combining_class}</small>"
            f"<small>utf8={utf8_hex}</small>"
            f"<small>engine_hazard={_escaped(hazard_label)}</small>"
            f"<small>display_flags={_escaped(flag_label)}</small>"
            "</li>"
        )
    return '<ol class="codepoints">' + "".join(items) + "</ol>"


def _members(record_ids: tuple[str, ...]) -> str:
    return '<div class="members">' + "".join(
        f"<code>{_escaped(record_id)}</code>" for record_id in record_ids
    ) + "</div>"


def _record_card(record: IdentifierRecord, ordinal: int) -> str:
    return (
        '<article class="card">'
        f'<p class="label">record {ordinal}</p>'
        f"<h3>{_escaped(record.record_id)}</h3>"
        f'<p class="meta">{record.input_codepoints} code points / '
        f"{record.input_utf8_bytes} UTF-8 bytes</p>"
        f"{_codepoint_tokens(record.identifier)}"
        "</article>"
    )


def _policy_group_card(
    group: PolicyCollisionGroup,
    record_ids: tuple[str, ...],
) -> str:
    members = tuple(record_ids[index] for index in group.member_record_ordinals)
    return (
        '<article class="card">'
        f'<p class="label">policy {group.policy_ordinal} collision</p>'
        f"<h3>{_escaped(group.group_id)}</h3>"
        f'<p class="meta">{group.output_codepoints} output code points / '
        f"{group.output_utf8_bytes} UTF-8 bytes / "
        f"{len(group.witness_ids)} witnesses</p>"
        f"{_codepoint_tokens(group.transformed)}"
        f"{_members(members)}"
        "</article>"
    )


def _witness_row(
    witness: CollisionWitness,
    record_ids: tuple[str, ...],
) -> str:
    policy = "none" if witness.policy_ordinal is None else str(witness.policy_ordinal)
    stage = "none" if witness.stage_index is None else str(witness.stage_index)
    step = "none" if witness.step is None else witness.step.value
    return (
        "<tr>"
        f"<td><code>{_escaped(witness.witness_id)}</code></td>"
        f"<td>{_escaped(witness.kind.value)}</td>"
        f"<td><code>{_escaped(record_ids[witness.left_record_ordinal])}</code>"
        " &rarr; "
        f"<code>{_escaped(record_ids[witness.right_record_ordinal])}</code></td>"
        f"<td>{policy}</td><td>{stage}</td><td>{_escaped(step)}</td>"
        "</tr>"
    )


def _policy_cards(receipt: CollisionReceipt) -> str:
    cards: list[str] = []
    for ordinal, policy in enumerate(receipt.policies):
        steps = tuple(step.value for step in policy.steps)
        cards.append(
            '<article class="card">'
            f'<p class="label">policy {ordinal}</p>'
            f"<h3>{_escaped(policy.hazard_handling.value)}</h3>"
            f'<p class="meta">unicode={_escaped(policy.unicode_version)}<br>'
            f"id={_escaped(policy.policy_id)}</p>"
            f"{_members(steps)}"
            "</article>"
        )
    return "".join(cards)


def _empty_or(value: str, message: str) -> str:
    return value if value else f'<p class="empty">{message}</p>'


def _render_verified_report(
    receipt_bytes: bytes,
    receipt: CollisionReceipt,
    records: tuple[IdentifierRecord, ...],
) -> bytes:
    graph = receipt.graph
    if len(records) > MAX_OFFLINE_REPORT_RECORDS:
        _raise_report(OfflineReportErrorCode.RECORD_LIMIT)
    if tuple(record.record_id for record in records) != graph.record_ids:
        _raise_report(OfflineReportErrorCode.INVALID_MODEL)
    group_count = len(graph.duplicate_groups) + len(graph.policy_groups)
    if (
        len(graph.components) > MAX_OFFLINE_REPORT_COMPONENTS
        or group_count > MAX_OFFLINE_REPORT_GROUPS
        or len(graph.witnesses) > MAX_OFFLINE_REPORT_WITNESSES
    ):
        _raise_report(OfflineReportErrorCode.STRUCTURE_LIMIT)

    token_count = sum(len(record.identifier) for record in records)
    token_count += sum(len(group.transformed) for group in graph.policy_groups)
    if token_count > MAX_OFFLINE_REPORT_CODEPOINT_TOKENS:
        _raise_report(OfflineReportErrorCode.TOKEN_LIMIT)

    record_cards = "".join(
        _record_card(record, ordinal) for ordinal, record in enumerate(records)
    )
    component_cards = "".join(
        '<article class="component">'
        f'<p class="label">component {ordinal}</p>'
        f"<h3>{_escaped(component.component_id)}</h3>"
        f'<p class="meta">{len(component.member_record_ordinals)} records / '
        f"{len(component.policy_group_ids)} policy groups / "
        f"{len(component.witness_tree_ids)} tree witnesses</p>"
        + _members(
            tuple(graph.record_ids[index] for index in component.member_record_ordinals)
        )
        + _members(component.policy_group_ids)
        + _members(component.witness_tree_ids)
        + "</article>"
        for ordinal, component in enumerate(graph.components)
    )
    duplicate_cards = "".join(
        '<article class="card">'
        f'<p class="label">exact duplicate</p><h3>{_escaped(group.group_id)}</h3>'
        + _members(
            tuple(graph.record_ids[index] for index in group.member_record_ordinals)
        )
        + _members(group.witness_ids)
        + "</article>"
        for group in graph.duplicate_groups
    )
    group_cards = "".join(
        _policy_group_card(group, graph.record_ids) for group in graph.policy_groups
    )
    witness_rows = "".join(
        _witness_row(witness, graph.record_ids) for witness in graph.witnesses
    )
    witness_empty = "" if witness_rows else '<p class="empty">No witnesses.</p>'
    isolated = tuple(
        graph.record_ids[index] for index in graph.isolated_record_ordinals
    )
    isolated_members = _members(isolated) if isolated else ""
    receipt_sha256 = hashlib.sha256(receipt_bytes).hexdigest()
    style_sha256 = base64.b64encode(hashlib.sha256(_STYLE.encode("ascii")).digest())
    style_hash = style_sha256.decode("ascii")
    csp = (
        "default-src 'none'; base-uri 'none'; form-action 'none'; "
        "object-src 'none'; script-src 'none'; script-src-elem 'none'; "
        "script-src-attr 'none'; "
        f"style-src 'sha256-{style_hash}'; "
        f"style-src-elem 'sha256-{style_hash}'; style-src-attr 'none'; "
        "img-src 'none'; font-src 'none'; media-src 'none'; "
        "connect-src 'none'; worker-src 'none'; child-src 'none'; "
        "frame-src 'none'; manifest-src 'none'"
    )
    document = f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta http-equiv="Content-Security-Policy" content="{csp}">
<meta name="referrer" content="no-referrer">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="casefold-observatory-report-schema" content="{OFFLINE_REPORT_SCHEMA}">
<meta name="casefold-observatory-report-schema-version" content="{OFFLINE_REPORT_SCHEMA_VERSION}">
<title>Casefold Observatory offline collision report</title>
<style>{_STYLE}</style>
</head>
<body>
<main data-receipt-sha256="{receipt_sha256}">
<p class="eyebrow">Casefold Observatory / verified offline report</p>
<h1>Unicode collision evidence, code point by code point.</h1>
<p class="lede">This static document was rendered only after replaying the canonical receipt against the exact source bytes. Identifiers and transformed values are represented as ASCII-only, logical-indexed code-point metadata; raw glyphs are limited to printable ASCII.</p>
<div class="boundary"><strong>Boundary:</strong> this file contains source-derived identifier data. Verified replay is not a signature, authenticity proof, freshness proof, or safety verdict. The report performs no network access, embeds no JavaScript, and must be handled as sensitive output.</div>
<section aria-labelledby="overview"><h2 id="overview">Verified overview</h2><div class="metrics">
<div class="metric"><span class="label">records</span><strong>{graph.record_count}</strong></div>
<div class="metric"><span class="label">colliding records</span><strong>{graph.colliding_record_count}</strong></div>
<div class="metric"><span class="label">components</span><strong>{len(graph.components)}</strong></div>
<div class="metric"><span class="label">witnesses</span><strong>{len(graph.witnesses)}</strong></div>
</div><p class="meta">receipt_sha256={receipt_sha256}<br>source_sha256={receipt.source.sha256}<br>semantic_sha256={graph.semantic_corpus_sha256}<br>algorithm={_escaped(graph.algorithm)}<br>unicode={_escaped(graph.unicode_version)} / producer={_escaped(receipt.producer_version)}</p></section>
<section aria-labelledby="policies"><h2 id="policies">Explicit policies</h2><div class="grid">{_policy_cards(receipt)}</div></section>
<section aria-labelledby="records"><h2 id="records">Canonical records</h2><div class="grid">{record_cards}</div></section>
<section aria-labelledby="components"><h2 id="components">Cross-policy risk components</h2><div class="stack">{_empty_or(component_cards, "No collision components.")}</div></section>
<section aria-labelledby="duplicates"><h2 id="duplicates">Exact duplicate groups</h2><div class="grid">{_empty_or(duplicate_cards, "No exact duplicate groups.")}</div></section>
<section aria-labelledby="groups"><h2 id="groups">Per-policy collision groups</h2><div class="grid">{_empty_or(group_cards, "No policy collision groups.")}</div></section>
<section aria-labelledby="isolated"><h2 id="isolated">Isolated records</h2>{_empty_or(isolated_members, "No isolated records.")}</section>
<section aria-labelledby="witnesses"><h2 id="witnesses">Minimal witnesses</h2><div class="table-wrap"><table><thead><tr><th>Witness</th><th>Kind</th><th>Records</th><th>Policy</th><th>Stage</th><th>Step</th></tr></thead><tbody>{witness_rows}</tbody></table>{witness_empty}</div></section>
<footer>Schema {OFFLINE_REPORT_SCHEMA}/v{OFFLINE_REPORT_SCHEMA_VERSION}. Rendering is deterministic for the exact receipt, source bytes, Python Unicode database, and package version. The meta CSP permits only the hash-bound inline stylesheet; anti-framing requires HTTP response headers when served.</footer>
</main>
</body>
</html>
"""
    try:
        payload = document.encode("ascii")
    except UnicodeEncodeError:
        _raise_report(OfflineReportErrorCode.INVALID_MODEL)
    if len(payload) > MAX_OFFLINE_REPORT_BYTES:
        _raise_report(OfflineReportErrorCode.OUTPUT_TOO_LARGE)
    return payload


def render_offline_report(receipt_bytes: bytes, source_bytes: bytes) -> bytes:
    """Verify exact inputs and render a bounded, deterministic static report."""

    receipt, records = _verify_collision_receipt_and_records(
        receipt_bytes,
        source_bytes,
    )
    return _render_verified_report(receipt_bytes, receipt, records)

"""Canonical, replay-verifiable receipts for bounded collision analyses."""

from __future__ import annotations

import hashlib
import hmac
import json
import re
import unicodedata
from dataclasses import dataclass, field
from enum import Enum
from typing import NoReturn, Self, cast, final

from casefold_observatory.collision import (
    COLLISION_ALGORITHM,
    MAX_ANALYSIS_POLICIES,
    MAX_ANALYSIS_RECORDS,
    CollisionAnalysisError,
    CollisionGraph,
    CollisionWitness,
    ExactDuplicateGroup,
    GlobalCollisionComponent,
    IdentifierRecord,
    PolicyCollisionGroup,
    WitnessKind,
    analyze_collisions,
)
from casefold_observatory.corpus import (
    CORPUS_FORMAT,
    CORPUS_FORMAT_VERSION,
    MAX_CORPUS_SOURCE_BYTES,
    CorpusIngestionError,
    _BoundedJsonError,
    _JsonIssue,
    _load_bounded_json,
    _parse_corpus_bytes,
)
from casefold_observatory.engine import canonical_policy_bytes
from casefold_observatory.model import (
    HazardHandling,
    TransformPolicy,
    TransformStep,
    create_policy,
)

DISTRIBUTION_NAME = "casefold-observatory"
DISTRIBUTION_VERSION = "0.4.0"
RECEIPT_SCHEMA = "casefold-observatory.analysis-receipt"
RECEIPT_SCHEMA_VERSION = 1
MAX_RECEIPT_BYTES = 16_777_216

_HEX_DIGEST = re.compile(r"[0-9a-f]{64}\Z")
_RECORD_ID = re.compile(r"[a-z][a-z0-9._-]{0,63}\Z")
_GRAPH_KEYS = {
    "algorithm",
    "components",
    "duplicate_groups",
    "isolated_record_ordinals",
    "policy_groups",
    "policy_ids",
    "record_ids",
    "semantic_corpus_sha256",
    "unicode_version",
    "witnesses",
}
_POLICY_DOCUMENT_KEYS = {
    "bounds",
    "hazard_handling",
    "schema",
    "schema_version",
    "steps",
    "unicode_version",
}

JsonValue = object
JsonObject = dict[str, object]


class ReceiptErrorCode(Enum):
    """Stable failures for canonical receipt creation and replay."""

    ALGORITHM_MISMATCH = "algorithm_mismatch"
    DUPLICATE_KEY = "duplicate_key"
    GRAPH_MISMATCH = "graph_mismatch"
    INVALID_JSON = "invalid_json"
    INVALID_RECEIPT = "invalid_receipt"
    JSON_DEPTH = "json_depth"
    NONCANONICAL_RECEIPT = "noncanonical_receipt"
    POLICY_MISMATCH = "policy_mismatch"
    PRODUCER_MISMATCH = "producer_mismatch"
    RECEIPT_TOO_LARGE = "receipt_too_large"
    SCHEMA_MISMATCH = "schema_mismatch"
    SOURCE_MISMATCH = "source_mismatch"
    UNICODE_MISMATCH = "unicode_mismatch"


class ReceiptVerificationError(ValueError):
    """A redacted receipt failure with bounded numeric context only."""

    def __init__(
        self,
        code: ReceiptErrorCode,
        *,
        policy_ordinal: int | None = None,
    ) -> None:
        self.code = code
        self.policy_ordinal = policy_ordinal
        suffix = "" if policy_ordinal is None else f" (policy_ordinal={policy_ordinal})"
        super().__init__(f"receipt rejected: {code.value}{suffix}")


@final
@dataclass(frozen=True, slots=True, init=False)
class ReceiptSource:
    """Exact source-byte identity retained by a receipt."""

    format: str
    format_version: int
    byte_count: int
    sha256: str = field(repr=False)

    def __new__(cls) -> Self:
        raise TypeError("ReceiptSource objects are created by create_collision_receipt")


@final
@dataclass(frozen=True, slots=True, init=False)
class CollisionReceipt:
    """A complete graph receipt created from bounded source bytes."""

    schema: str
    schema_version: int
    producer_distribution: str
    producer_version: str
    source: ReceiptSource = field(repr=False)
    policies: tuple[TransformPolicy, ...] = field(repr=False)
    graph: CollisionGraph = field(repr=False)
    _document_sha256: str = field(repr=False)

    def __new__(cls) -> Self:
        raise TypeError(
            "CollisionReceipt objects are created by create_collision_receipt"
        )


def _raise_receipt(
    code: ReceiptErrorCode,
    *,
    policy_ordinal: int | None = None,
) -> NoReturn:
    raise ReceiptVerificationError(
        code,
        policy_ordinal=policy_ordinal,
    ) from None


def _require(
    condition: bool,
    *,
    code: ReceiptErrorCode = ReceiptErrorCode.INVALID_RECEIPT,
    policy_ordinal: int | None = None,
) -> None:
    if not condition:
        _raise_receipt(code, policy_ordinal=policy_ordinal)


def _string(value: object) -> str:
    _require(type(value) is str)
    return cast(str, value)


def _integer(value: object) -> int:
    _require(type(value) is int)
    return cast(int, value)


def _optional_integer(value: object) -> int | None:
    _require(value is None or type(value) is int)
    return cast(int | None, value)


def _optional_string(value: object) -> str | None:
    _require(value is None or type(value) is str)
    return cast(str | None, value)


def _exact_tuple(value: object) -> tuple[object, ...]:
    _require(type(value) is tuple)
    return cast(tuple[object, ...], value)


def _string_tuple(value: object) -> tuple[str, ...]:
    items = _exact_tuple(value)
    _require(all(type(item) is str for item in items))
    return cast(tuple[str, ...], items)


def _ordinal_tuple(
    value: object,
    *,
    record_count: int,
    minimum_length: int = 0,
) -> tuple[int, ...]:
    items = _exact_tuple(value)
    _require(all(type(item) is int for item in items))
    ordinals = cast(tuple[int, ...], items)
    _require(len(ordinals) >= minimum_length)
    _require(ordinals == tuple(sorted(set(ordinals))))
    _require(all(0 <= ordinal < record_count for ordinal in ordinals))
    return ordinals


def _is_digest(value: object) -> bool:
    return type(value) is str and _HEX_DIGEST.fullmatch(value) is not None


def _policy_document(policy: TransformPolicy) -> JsonObject:
    try:
        value: object = json.loads(canonical_policy_bytes(policy))
    except (TypeError, ValueError, json.JSONDecodeError):
        _raise_receipt(ReceiptErrorCode.INVALID_RECEIPT)
    _require(type(value) is dict)
    return cast(JsonObject, value)


def _duplicate_group_document(
    group: ExactDuplicateGroup,
    *,
    record_count: int,
) -> JsonObject:
    _require(type(group) is ExactDuplicateGroup)
    group_id = _string(group.group_id)
    members = _ordinal_tuple(
        group.member_record_ordinals,
        record_count=record_count,
        minimum_length=2,
    )
    witness_ids = _string_tuple(group.witness_ids)
    _require(len(witness_ids) == len(members) - 1)
    return {
        "group_id": group_id,
        "member_record_ordinals": list(members),
        "witness_ids": list(witness_ids),
    }


def _policy_group_document(
    group: PolicyCollisionGroup,
    *,
    record_count: int,
    policy_ids: tuple[str, ...],
) -> JsonObject:
    _require(type(group) is PolicyCollisionGroup)
    policy_ordinal = _integer(group.policy_ordinal)
    _require(0 <= policy_ordinal < len(policy_ids))
    policy_id = _string(group.policy_id)
    _require(policy_id == policy_ids[policy_ordinal])
    transformed = _string(group.transformed)
    output_codepoints = _integer(group.output_codepoints)
    output_utf8_bytes = _integer(group.output_utf8_bytes)
    _require(output_codepoints == len(transformed))
    _require(output_utf8_bytes == len(transformed.encode("utf-8")))
    members = _ordinal_tuple(
        group.member_record_ordinals,
        record_count=record_count,
        minimum_length=2,
    )
    witness_ids = _string_tuple(group.witness_ids)
    _require(len(witness_ids) == len(members) - 1)
    return {
        "group_id": _string(group.group_id),
        "member_record_ordinals": list(members),
        "output_codepoints": output_codepoints,
        "output_utf8_bytes": output_utf8_bytes,
        "policy_id": policy_id,
        "policy_ordinal": policy_ordinal,
        "transformed": transformed,
        "witness_ids": list(witness_ids),
    }


def _witness_document(
    witness: CollisionWitness,
    *,
    record_count: int,
    policy_ids: tuple[str, ...],
) -> JsonObject:
    _require(type(witness) is CollisionWitness)
    left = _integer(witness.left_record_ordinal)
    right = _integer(witness.right_record_ordinal)
    _require(0 <= left < right < record_count)
    _require(type(witness.kind) is WitnessKind)
    policy_ordinal = _optional_integer(witness.policy_ordinal)
    policy_id = _optional_string(witness.policy_id)
    stage_index = _optional_integer(witness.stage_index)
    step_value: str | None
    if witness.step is None:
        step_value = None
    else:
        _require(type(witness.step) is TransformStep)
        step_value = witness.step.value
    if witness.kind is WitnessKind.EXACT_INPUT:
        _require(
            policy_ordinal is None
            and policy_id is None
            and stage_index is None
            and step_value is None
        )
    else:
        _require(policy_ordinal is not None)
        assert policy_ordinal is not None
        _require(0 <= policy_ordinal < len(policy_ids))
        _require(policy_id == policy_ids[policy_ordinal])
        _require(stage_index is not None and stage_index >= 0)
        _require(step_value is not None)
    return {
        "kind": witness.kind.value,
        "left_record_ordinal": left,
        "policy_id": policy_id,
        "policy_ordinal": policy_ordinal,
        "right_record_ordinal": right,
        "stage_index": stage_index,
        "step": step_value,
        "witness_id": _string(witness.witness_id),
    }


def _component_document(
    component: GlobalCollisionComponent,
    *,
    record_count: int,
    policy_count: int,
) -> JsonObject:
    _require(type(component) is GlobalCollisionComponent)
    members = _ordinal_tuple(
        component.member_record_ordinals,
        record_count=record_count,
        minimum_length=2,
    )
    witness_tree_ids = _string_tuple(component.witness_tree_ids)
    _require(len(witness_tree_ids) == len(members) - 1)
    policy_ordinals = _ordinal_tuple(
        component.policy_ordinals,
        record_count=policy_count,
    )
    return {
        "component_id": _string(component.component_id),
        "duplicate_group_ids": list(_string_tuple(component.duplicate_group_ids)),
        "member_record_ordinals": list(members),
        "policy_group_ids": list(_string_tuple(component.policy_group_ids)),
        "policy_ordinals": list(policy_ordinals),
        "witness_tree_ids": list(witness_tree_ids),
    }


def _graph_document(graph: CollisionGraph) -> JsonObject:
    _require(type(graph) is CollisionGraph)
    _require(type(graph.algorithm) is str and graph.algorithm == COLLISION_ALGORITHM)
    _require(
        type(graph.unicode_version) is str
        and graph.unicode_version == unicodedata.unidata_version
    )
    _require(_is_digest(graph.semantic_corpus_sha256))
    record_ids = _string_tuple(graph.record_ids)
    _require(len(record_ids) <= MAX_ANALYSIS_RECORDS)
    _require(record_ids == tuple(sorted(set(record_ids))))
    _require(
        all(_RECORD_ID.fullmatch(record_id) is not None for record_id in record_ids)
    )
    policy_ids = _string_tuple(graph.policy_ids)
    _require(1 <= len(policy_ids) <= MAX_ANALYSIS_POLICIES)
    _require(len(set(policy_ids)) == len(policy_ids))
    _require(all(_is_digest(policy_id) for policy_id in policy_ids))
    record_count = len(record_ids)

    duplicate_groups = [
        _duplicate_group_document(
            cast(ExactDuplicateGroup, group),
            record_count=record_count,
        )
        for group in _exact_tuple(graph.duplicate_groups)
    ]
    policy_groups = [
        _policy_group_document(
            cast(PolicyCollisionGroup, group),
            record_count=record_count,
            policy_ids=policy_ids,
        )
        for group in _exact_tuple(graph.policy_groups)
    ]
    witnesses = [
        _witness_document(
            cast(CollisionWitness, witness),
            record_count=record_count,
            policy_ids=policy_ids,
        )
        for witness in _exact_tuple(graph.witnesses)
    ]
    components = [
        _component_document(
            cast(GlobalCollisionComponent, component),
            record_count=record_count,
            policy_count=len(policy_ids),
        )
        for component in _exact_tuple(graph.components)
    ]
    isolated = _ordinal_tuple(
        graph.isolated_record_ordinals,
        record_count=record_count,
    )

    witness_ids = tuple(_string(item["witness_id"]) for item in witnesses)
    _require(len(set(witness_ids)) == len(witness_ids))
    known_witness_ids = set(witness_ids)
    for group in (*duplicate_groups, *policy_groups):
        ids = cast(list[JsonValue], group["witness_ids"])
        _require(all(type(item) is str and item in known_witness_ids for item in ids))
    for component in components:
        ids = cast(list[JsonValue], component["witness_tree_ids"])
        _require(all(type(item) is str and item in known_witness_ids for item in ids))

    covered = set(isolated)
    for component in components:
        members = cast(list[JsonValue], component["member_record_ordinals"])
        member_set = {cast(int, member) for member in members}
        _require(covered.isdisjoint(member_set))
        covered.update(member_set)
    _require(covered == set(range(record_count)))

    return {
        "algorithm": graph.algorithm,
        "components": components,
        "duplicate_groups": duplicate_groups,
        "isolated_record_ordinals": list(isolated),
        "policy_groups": policy_groups,
        "policy_ids": list(policy_ids),
        "record_ids": list(record_ids),
        "semantic_corpus_sha256": graph.semantic_corpus_sha256,
        "unicode_version": graph.unicode_version,
        "witnesses": witnesses,
    }


def _source_document(source: ReceiptSource) -> JsonObject:
    _require(type(source) is ReceiptSource)
    _require(type(source.format) is str and source.format == CORPUS_FORMAT)
    _require(
        type(source.format_version) is int
        and source.format_version == CORPUS_FORMAT_VERSION
    )
    byte_count = _integer(source.byte_count)
    _require(0 <= byte_count <= MAX_CORPUS_SOURCE_BYTES)
    _require(_is_digest(source.sha256))
    return {
        "byte_count": byte_count,
        "format": source.format,
        "format_version": source.format_version,
        "sha256": source.sha256,
    }


def _receipt_document(receipt: CollisionReceipt) -> JsonObject:
    _require(type(receipt) is CollisionReceipt)
    _require(type(receipt.schema) is str and receipt.schema == RECEIPT_SCHEMA)
    _require(
        type(receipt.schema_version) is int
        and receipt.schema_version == RECEIPT_SCHEMA_VERSION
    )
    _require(
        type(receipt.producer_distribution) is str
        and receipt.producer_distribution == DISTRIBUTION_NAME
    )
    _require(
        type(receipt.producer_version) is str
        and receipt.producer_version == DISTRIBUTION_VERSION
    )
    policies = _exact_tuple(receipt.policies)
    _require(1 <= len(policies) <= MAX_ANALYSIS_POLICIES)
    _require(all(type(policy) is TransformPolicy for policy in policies))
    typed_policies = cast(tuple[TransformPolicy, ...], policies)
    policy_documents = [
        {
            "document": _policy_document(policy),
            "policy_id": policy.policy_id,
        }
        for policy in typed_policies
    ]
    graph = _graph_document(receipt.graph)
    graph_policy_ids = cast(list[JsonValue], graph["policy_ids"])
    _require(
        graph_policy_ids
        == [cast(str, document["policy_id"]) for document in policy_documents]
    )
    return {
        "graph": graph,
        "policies": policy_documents,
        "producer": {
            "distribution": receipt.producer_distribution,
            "version": receipt.producer_version,
        },
        "schema": receipt.schema,
        "schema_version": receipt.schema_version,
        "source": _source_document(receipt.source),
    }


def _canonical_json(document: JsonValue) -> bytes:
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


def _checked_receipt_bytes(
    receipt: CollisionReceipt,
    *,
    require_seal: bool,
) -> bytes:
    document = _receipt_document(receipt)
    encoded = _canonical_json(document)
    if len(encoded) > MAX_RECEIPT_BYTES:
        _raise_receipt(ReceiptErrorCode.RECEIPT_TOO_LARGE)
    if require_seal:
        _require(
            type(receipt._document_sha256) is str
            and hmac.compare_digest(
                receipt._document_sha256,
                hashlib.sha256(encoded).hexdigest(),
            )
        )
    return encoded


def _new_source(source_bytes: bytes) -> ReceiptSource:
    source: ReceiptSource = object.__new__(ReceiptSource)
    object.__setattr__(source, "format", CORPUS_FORMAT)
    object.__setattr__(source, "format_version", CORPUS_FORMAT_VERSION)
    object.__setattr__(source, "byte_count", len(source_bytes))
    object.__setattr__(source, "sha256", hashlib.sha256(source_bytes).hexdigest())
    return source


def _seal_collision_receipt(
    source_bytes: bytes,
    policies: tuple[TransformPolicy, ...],
    graph: CollisionGraph,
) -> CollisionReceipt:
    receipt: CollisionReceipt = object.__new__(CollisionReceipt)
    object.__setattr__(receipt, "schema", RECEIPT_SCHEMA)
    object.__setattr__(receipt, "schema_version", RECEIPT_SCHEMA_VERSION)
    object.__setattr__(receipt, "producer_distribution", DISTRIBUTION_NAME)
    object.__setattr__(receipt, "producer_version", DISTRIBUTION_VERSION)
    object.__setattr__(receipt, "source", _new_source(source_bytes))
    object.__setattr__(receipt, "policies", policies)
    object.__setattr__(receipt, "graph", graph)
    object.__setattr__(receipt, "_document_sha256", "")
    encoded = _checked_receipt_bytes(receipt, require_seal=False)
    object.__setattr__(
        receipt,
        "_document_sha256",
        hashlib.sha256(encoded).hexdigest(),
    )
    return receipt


def _create_collision_receipt_from_records(
    source_bytes: bytes,
    policies: tuple[TransformPolicy, ...],
    records: tuple[IdentifierRecord, ...],
) -> CollisionReceipt:
    graph = analyze_collisions(records, policies)
    return _seal_collision_receipt(source_bytes, policies, graph)


def create_collision_receipt(
    source_bytes: bytes,
    policies: tuple[TransformPolicy, ...],
) -> CollisionReceipt:
    """Analyze exact corpus bytes and return a bounded factory-owned receipt."""

    records = _parse_corpus_bytes(source_bytes)
    return _create_collision_receipt_from_records(source_bytes, policies, records)


def canonical_receipt_bytes(receipt: CollisionReceipt) -> bytes:
    """Return the exact canonical ASCII JSON representation of a receipt."""

    try:
        return _checked_receipt_bytes(receipt, require_seal=True)
    except ReceiptVerificationError:
        raise
    except (AttributeError, TypeError, ValueError):
        _raise_receipt(ReceiptErrorCode.INVALID_RECEIPT)


def _schema_object(
    value: object,
    *,
    code: ReceiptErrorCode = ReceiptErrorCode.SCHEMA_MISMATCH,
    policy_ordinal: int | None = None,
) -> dict[str, object]:
    if type(value) is not dict:
        _raise_receipt(code, policy_ordinal=policy_ordinal)
    return cast(dict[str, object], value)


def _schema_list(
    value: object,
    *,
    code: ReceiptErrorCode = ReceiptErrorCode.SCHEMA_MISMATCH,
    policy_ordinal: int | None = None,
) -> list[object]:
    if type(value) is not list:
        _raise_receipt(code, policy_ordinal=policy_ordinal)
    return cast(list[object], value)


def _schema_keys(
    document: dict[str, object],
    expected: set[str],
    *,
    code: ReceiptErrorCode = ReceiptErrorCode.SCHEMA_MISMATCH,
    policy_ordinal: int | None = None,
) -> None:
    if set(document) != expected:
        _raise_receipt(code, policy_ordinal=policy_ordinal)


def _valid_receipt_json_types(value: object) -> bool:
    if value is None or type(value) in {str, int}:
        return True
    if type(value) is list:
        return all(
            _valid_receipt_json_types(item) for item in cast(list[object], value)
        )
    if type(value) is dict:
        document = cast(dict[str, object], value)
        return all(
            type(key) is str and _valid_receipt_json_types(item)
            for key, item in document.items()
        )
    return False


def _receipt_json_code(issue: _JsonIssue) -> ReceiptErrorCode:
    if issue is _JsonIssue.JSON_DEPTH:
        return ReceiptErrorCode.JSON_DEPTH
    if issue is _JsonIssue.DUPLICATE_KEY:
        return ReceiptErrorCode.DUPLICATE_KEY
    return ReceiptErrorCode.INVALID_JSON


def _parse_policy_documents(value: object) -> tuple[TransformPolicy, ...]:
    entries = _schema_list(value)
    if not 1 <= len(entries) <= MAX_ANALYSIS_POLICIES:
        _raise_receipt(ReceiptErrorCode.POLICY_MISMATCH)
    policies: list[TransformPolicy] = []
    seen_ids: set[str] = set()
    for policy_ordinal, entry_value in enumerate(entries):
        entry = _schema_object(
            entry_value,
            code=ReceiptErrorCode.POLICY_MISMATCH,
            policy_ordinal=policy_ordinal,
        )
        _schema_keys(
            entry,
            {"document", "policy_id"},
            code=ReceiptErrorCode.POLICY_MISMATCH,
            policy_ordinal=policy_ordinal,
        )
        document = _schema_object(
            entry["document"],
            code=ReceiptErrorCode.POLICY_MISMATCH,
            policy_ordinal=policy_ordinal,
        )
        _schema_keys(
            document,
            _POLICY_DOCUMENT_KEYS,
            code=ReceiptErrorCode.POLICY_MISMATCH,
            policy_ordinal=policy_ordinal,
        )
        unicode_version = document["unicode_version"]
        if (
            type(unicode_version) is not str
            or unicode_version != unicodedata.unidata_version
        ):
            _raise_receipt(
                ReceiptErrorCode.UNICODE_MISMATCH,
                policy_ordinal=policy_ordinal,
            )
        steps_value = _schema_list(
            document["steps"],
            code=ReceiptErrorCode.POLICY_MISMATCH,
            policy_ordinal=policy_ordinal,
        )
        if not 1 <= len(steps_value) <= 8 or any(
            type(step) is not str for step in steps_value
        ):
            _raise_receipt(
                ReceiptErrorCode.POLICY_MISMATCH,
                policy_ordinal=policy_ordinal,
            )
        if type(document["hazard_handling"]) is not str:
            _raise_receipt(
                ReceiptErrorCode.POLICY_MISMATCH,
                policy_ordinal=policy_ordinal,
            )
        try:
            steps = tuple(TransformStep(cast(str, step)) for step in steps_value)
            handling = HazardHandling(document["hazard_handling"])
            policy = create_policy(steps, hazard_handling=handling)
        except (TypeError, ValueError):
            _raise_receipt(
                ReceiptErrorCode.POLICY_MISMATCH,
                policy_ordinal=policy_ordinal,
            )
        expected_document = _policy_document(policy)
        if document != expected_document:
            _raise_receipt(
                ReceiptErrorCode.POLICY_MISMATCH,
                policy_ordinal=policy_ordinal,
            )
        policy_id = entry["policy_id"]
        if (
            not _is_digest(policy_id)
            or not hmac.compare_digest(cast(str, policy_id), policy.policy_id)
            or cast(str, policy_id) in seen_ids
        ):
            _raise_receipt(
                ReceiptErrorCode.POLICY_MISMATCH,
                policy_ordinal=policy_ordinal,
            )
        seen_ids.add(cast(str, policy_id))
        policies.append(policy)
    return tuple(policies)


def _canonical_verified_records(
    records: tuple[IdentifierRecord, ...],
    record_ids: tuple[str, ...],
) -> tuple[IdentifierRecord, ...]:
    by_id = {record.record_id: record for record in records}
    if len(by_id) != len(records) or set(by_id) != set(record_ids):
        _raise_receipt(ReceiptErrorCode.GRAPH_MISMATCH)
    return tuple(by_id[record_id] for record_id in record_ids)


def _verify_collision_receipt_and_records(
    receipt_bytes: bytes,
    source_bytes: bytes,
) -> tuple[CollisionReceipt, tuple[IdentifierRecord, ...]]:
    """Verify a receipt and return its factory-owned canonical source records."""

    if type(receipt_bytes) is not bytes:
        raise TypeError("receipt_bytes must be an exact bytes object")
    if type(source_bytes) is not bytes:
        raise TypeError("source_bytes must be an exact bytes object")
    if len(receipt_bytes) > MAX_RECEIPT_BYTES:
        _raise_receipt(ReceiptErrorCode.RECEIPT_TOO_LARGE)
    try:
        value = _load_bounded_json(receipt_bytes, ascii_only=True)
    except _BoundedJsonError as error:
        _raise_receipt(_receipt_json_code(error.issue))

    if not _valid_receipt_json_types(value):
        _raise_receipt(ReceiptErrorCode.SCHEMA_MISMATCH)
    canonical = _canonical_json(value)
    if not hmac.compare_digest(canonical, receipt_bytes):
        _raise_receipt(ReceiptErrorCode.NONCANONICAL_RECEIPT)

    document = _schema_object(value)
    _schema_keys(
        document,
        {"graph", "policies", "producer", "schema", "schema_version", "source"},
    )
    if (
        type(document["schema"]) is not str
        or document["schema"] != RECEIPT_SCHEMA
        or type(document["schema_version"]) is not int
        or document["schema_version"] != RECEIPT_SCHEMA_VERSION
    ):
        _raise_receipt(ReceiptErrorCode.SCHEMA_MISMATCH)

    producer = _schema_object(document["producer"])
    _schema_keys(producer, {"distribution", "version"})
    if (
        type(producer["distribution"]) is not str
        or producer["distribution"] != DISTRIBUTION_NAME
        or type(producer["version"]) is not str
        or producer["version"] != DISTRIBUTION_VERSION
    ):
        _raise_receipt(ReceiptErrorCode.PRODUCER_MISMATCH)

    source = _schema_object(document["source"])
    _schema_keys(source, {"byte_count", "format", "format_version", "sha256"})
    if (
        type(source["format"]) is not str
        or source["format"] != CORPUS_FORMAT
        or type(source["format_version"]) is not int
        or source["format_version"] != CORPUS_FORMAT_VERSION
        or type(source["byte_count"]) is not int
        or source["byte_count"] < 0
        or not _is_digest(source["sha256"])
    ):
        _raise_receipt(ReceiptErrorCode.SCHEMA_MISMATCH)

    policies = _parse_policy_documents(document["policies"])
    policy_ids = [policy.policy_id for policy in policies]

    graph = _schema_object(document["graph"])
    _schema_keys(graph, _GRAPH_KEYS)
    if type(graph["algorithm"]) is not str or graph["algorithm"] != COLLISION_ALGORITHM:
        _raise_receipt(ReceiptErrorCode.ALGORITHM_MISMATCH)
    if (
        type(graph["unicode_version"]) is not str
        or graph["unicode_version"] != unicodedata.unidata_version
    ):
        _raise_receipt(ReceiptErrorCode.UNICODE_MISMATCH)
    graph_policy_ids = _schema_list(graph["policy_ids"])
    if graph_policy_ids != policy_ids:
        _raise_receipt(ReceiptErrorCode.POLICY_MISMATCH)

    expected_source_digest = cast(str, source["sha256"])
    if (
        len(source_bytes) > MAX_CORPUS_SOURCE_BYTES
        or source["byte_count"] != len(source_bytes)
        or not hmac.compare_digest(
            expected_source_digest,
            hashlib.sha256(source_bytes).hexdigest(),
        )
    ):
        _raise_receipt(ReceiptErrorCode.SOURCE_MISMATCH)

    try:
        records = _parse_corpus_bytes(source_bytes)
        expected = _create_collision_receipt_from_records(
            source_bytes,
            policies,
            records,
        )
        expected_bytes = canonical_receipt_bytes(expected)
    except (CorpusIngestionError, CollisionAnalysisError):
        _raise_receipt(ReceiptErrorCode.GRAPH_MISMATCH)
    if not hmac.compare_digest(expected_bytes, receipt_bytes):
        _raise_receipt(ReceiptErrorCode.GRAPH_MISMATCH)
    canonical_records = _canonical_verified_records(
        records,
        expected.graph.record_ids,
    )
    return expected, canonical_records


def verify_collision_receipt(
    receipt_bytes: bytes,
    source_bytes: bytes,
) -> CollisionReceipt:
    """Recompute a canonical receipt from exact source bytes and compare it."""

    receipt, _records = _verify_collision_receipt_and_records(
        receipt_bytes,
        source_bytes,
    )
    return receipt

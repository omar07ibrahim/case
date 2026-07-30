"""Bounded, deterministic collision graphs for explicit Unicode policies."""

from __future__ import annotations

import hashlib
import re
import unicodedata
from dataclasses import dataclass, field
from enum import Enum
from typing import NoReturn, Self, final

from casefold_observatory.engine import (
    _evaluate_policy,
    _validated_identifier_bytes,
)
from casefold_observatory.model import (
    IdentifierTransformError,
    TransformErrorCode,
    TransformPolicy,
    TransformResult,
    TransformStep,
    _validate_policy,
)

MAX_RECORD_ID_CHARS = 64
MAX_ANALYSIS_RECORDS = 2_048
MAX_ANALYSIS_POLICIES = 8
MAX_ANALYSIS_TOTAL_INPUT_UTF8_BYTES = 524_288
MAX_ANALYSIS_TRANSFORM_APPLICATIONS = 65_536
MAX_ANALYSIS_TRANSFORMED_UTF8_BYTES = 33_554_432
MAX_ANALYSIS_POLICY_GROUPS = 8_192
MAX_ANALYSIS_WITNESSES = 20_480
MAX_ANALYSIS_COMPONENTS = 1_024

COLLISION_ALGORITHM = "stage-partition-witness-v1"
_SEMANTIC_CORPUS_DOMAIN = b"casefold-observatory.semantic-corpus.v1\x00"
_RECORD_ID_PATTERN = re.compile(r"[a-z][a-z0-9._-]{0,63}\Z")


class CollisionErrorCode(Enum):
    """Stable, non-echoing collision-analysis failures."""

    DUPLICATE_POLICY = "duplicate_policy"
    DUPLICATE_RECORD_ID = "duplicate_record_id"
    INVALID_POLICY = "invalid_policy"
    INVALID_RECORD = "invalid_record"
    OUTPUT_BUDGET_EXCEEDED = "output_budget_exceeded"
    POLICY_COUNT = "policy_count"
    POLICY_REJECTED_RECORD = "policy_rejected_record"
    RECORD_COUNT = "record_count"
    TOTAL_INPUT_TOO_LARGE = "total_input_too_large"
    TRANSFORM_BUDGET_EXCEEDED = "transform_budget_exceeded"
    TRANSFORMED_DATA_TOO_LARGE = "transformed_data_too_large"


class CollisionAnalysisError(ValueError):
    """A bounded analysis failure that never echoes identifiers or record IDs."""

    def __init__(
        self,
        code: CollisionErrorCode,
        *,
        input_record_ordinal: int | None = None,
        canonical_record_ordinal: int | None = None,
        policy_ordinal: int | None = None,
        transform_error_code: TransformErrorCode | None = None,
    ) -> None:
        self.code = code
        self.input_record_ordinal = input_record_ordinal
        self.canonical_record_ordinal = canonical_record_ordinal
        self.policy_ordinal = policy_ordinal
        self.transform_error_code = transform_error_code
        details: list[str] = []
        if input_record_ordinal is not None:
            details.append(f"input_record_ordinal={input_record_ordinal}")
        if canonical_record_ordinal is not None:
            details.append(f"canonical_record_ordinal={canonical_record_ordinal}")
        if policy_ordinal is not None:
            details.append(f"policy_ordinal={policy_ordinal}")
        if transform_error_code is not None:
            details.append(f"transform_error={transform_error_code.value}")
        suffix = "" if not details else f" ({', '.join(details)})"
        super().__init__(f"collision analysis rejected: {code.value}{suffix}")


class WitnessKind(Enum):
    """Why two previously separate record components became connected."""

    EXACT_INPUT = "exact_input"
    TRANSFORM_STAGE = "transform_stage"


@final
@dataclass(frozen=True, slots=True, init=False)
class IdentifierRecord:
    """One exact namespace occurrence keyed by a stable opaque record ID."""

    record_id: str = field(repr=False)
    identifier: str = field(repr=False)
    input_codepoints: int
    input_utf8_bytes: int

    def __new__(cls) -> Self:
        raise TypeError(
            "IdentifierRecord objects are created by create_identifier_record"
        )


@final
@dataclass(frozen=True, slots=True, init=False)
class ExactDuplicateGroup:
    """Occurrences whose raw identifiers are exactly equal before any policy."""

    group_id: str
    member_record_ordinals: tuple[int, ...]
    witness_ids: tuple[str, ...]

    def __new__(cls) -> Self:
        raise TypeError("ExactDuplicateGroup objects are created by analyze_collisions")


@final
@dataclass(frozen=True, slots=True, init=False)
class CollisionWitness:
    """One edge in a deterministic minimal explanation forest."""

    witness_id: str
    kind: WitnessKind
    left_record_ordinal: int
    right_record_ordinal: int
    policy_ordinal: int | None
    policy_id: str | None
    stage_index: int | None
    step: TransformStep | None

    def __new__(cls) -> Self:
        raise TypeError("CollisionWitness objects are created by analyze_collisions")


@final
@dataclass(frozen=True, slots=True, init=False)
class PolicyCollisionGroup:
    """A final exact-equality bucket containing distinct raw identifiers."""

    group_id: str
    policy_ordinal: int
    policy_id: str
    transformed: str = field(repr=False)
    output_codepoints: int
    output_utf8_bytes: int
    member_record_ordinals: tuple[int, ...]
    witness_ids: tuple[str, ...]

    def __new__(cls) -> Self:
        raise TypeError(
            "PolicyCollisionGroup objects are created by analyze_collisions"
        )


@final
@dataclass(frozen=True, slots=True, init=False)
class GlobalCollisionComponent:
    """A union-graph risk neighborhood, not one-policy equivalence."""

    component_id: str
    member_record_ordinals: tuple[int, ...]
    duplicate_group_ids: tuple[str, ...]
    policy_group_ids: tuple[str, ...]
    policy_ordinals: tuple[int, ...]
    witness_tree_ids: tuple[str, ...]

    def __new__(cls) -> Self:
        raise TypeError(
            "GlobalCollisionComponent objects are created by analyze_collisions"
        )


@final
@dataclass(frozen=True, slots=True, init=False)
class CollisionGraph:
    """Complete bounded collision relation plus minimal witness trees."""

    algorithm: str
    unicode_version: str
    semantic_corpus_sha256: str
    record_ids: tuple[str, ...] = field(repr=False)
    policy_ids: tuple[str, ...]
    duplicate_groups: tuple[ExactDuplicateGroup, ...]
    policy_groups: tuple[PolicyCollisionGroup, ...]
    witnesses: tuple[CollisionWitness, ...]
    components: tuple[GlobalCollisionComponent, ...]
    isolated_record_ordinals: tuple[int, ...]

    def __new__(cls) -> Self:
        raise TypeError("CollisionGraph objects are created by analyze_collisions")

    @property
    def record_count(self) -> int:
        return len(self.record_ids)

    @property
    def colliding_record_count(self) -> int:
        return self.record_count - len(self.isolated_record_ordinals)


class _DisjointSet:
    __slots__ = ("_parent",)

    def __init__(self, members: tuple[int, ...]) -> None:
        self._parent = {member: member for member in members}

    def find(self, member: int) -> int:
        parent = self._parent[member]
        if parent != member:
            parent = self.find(parent)
            self._parent[member] = parent
        return parent

    def union(self, left: int, right: int) -> bool:
        left_root = self.find(left)
        right_root = self.find(right)
        if left_root == right_root:
            return False
        smaller, larger = sorted((left_root, right_root))
        self._parent[larger] = smaller
        return True


def _raise_collision_error(
    code: CollisionErrorCode,
    *,
    input_record_ordinal: int | None = None,
    canonical_record_ordinal: int | None = None,
    policy_ordinal: int | None = None,
    transform_error_code: TransformErrorCode | None = None,
) -> NoReturn:
    raise CollisionAnalysisError(
        code,
        input_record_ordinal=input_record_ordinal,
        canonical_record_ordinal=canonical_record_ordinal,
        policy_ordinal=policy_ordinal,
        transform_error_code=transform_error_code,
    )


def _require_internal(condition: bool, message: str) -> None:
    if not condition:
        raise RuntimeError(message)


def _is_record_id(value: str) -> bool:
    return (
        len(value) <= MAX_RECORD_ID_CHARS
        and _RECORD_ID_PATTERN.fullmatch(value) is not None
    )


def create_identifier_record(record_id: str, identifier: str) -> IdentifierRecord:
    """Create one validated record without exposing its identifier in ``repr``."""

    if type(record_id) is not str or not _is_record_id(record_id):
        raise ValueError("record_id must be bounded canonical lowercase ASCII")
    encoded = _validated_identifier_bytes(identifier)
    record: IdentifierRecord = object.__new__(IdentifierRecord)
    object.__setattr__(record, "record_id", record_id)
    object.__setattr__(record, "identifier", identifier)
    object.__setattr__(record, "input_codepoints", len(identifier))
    object.__setattr__(record, "input_utf8_bytes", len(encoded))
    return record


def _try_identifier_bytes(identifier: str) -> bytes | None:
    try:
        return _validated_identifier_bytes(identifier)
    except (IdentifierTransformError, TypeError):
        return None


def _try_record_fields(
    record: IdentifierRecord,
) -> tuple[str, str, int, int] | None:
    try:
        return (
            record.record_id,
            record.identifier,
            record.input_codepoints,
            record.input_utf8_bytes,
        )
    except AttributeError:
        return None


def _validate_record(record: IdentifierRecord, *, input_ordinal: int) -> bytes:
    if type(record) is not IdentifierRecord:
        _raise_collision_error(
            CollisionErrorCode.INVALID_RECORD,
            input_record_ordinal=input_ordinal,
        )
    fields = _try_record_fields(record)
    if fields is None:
        _raise_collision_error(
            CollisionErrorCode.INVALID_RECORD,
            input_record_ordinal=input_ordinal,
        )
    record_id, identifier, input_codepoints, input_utf8_bytes = fields
    if (
        type(record_id) is not str
        or not _is_record_id(record_id)
        or type(input_codepoints) is not int
        or type(input_utf8_bytes) is not int
    ):
        _raise_collision_error(
            CollisionErrorCode.INVALID_RECORD,
            input_record_ordinal=input_ordinal,
        )
    encoded = _try_identifier_bytes(identifier)
    if encoded is None:
        _raise_collision_error(
            CollisionErrorCode.INVALID_RECORD,
            input_record_ordinal=input_ordinal,
        )
    if input_codepoints != len(identifier) or input_utf8_bytes != len(encoded):
        _raise_collision_error(
            CollisionErrorCode.INVALID_RECORD,
            input_record_ordinal=input_ordinal,
        )
    return encoded


def _validated_records(
    records: tuple[IdentifierRecord, ...],
) -> tuple[tuple[IdentifierRecord, bytes], ...]:
    if type(records) is not tuple:
        raise TypeError("records must be an exact tuple")
    if len(records) > MAX_ANALYSIS_RECORDS:
        _raise_collision_error(CollisionErrorCode.RECORD_COUNT)

    validated: list[tuple[IdentifierRecord, bytes]] = []
    seen_record_ids: set[str] = set()
    total_input_bytes = 0
    for input_ordinal, record in enumerate(records):
        encoded = _validate_record(record, input_ordinal=input_ordinal)
        total_input_bytes += len(encoded)
        if total_input_bytes > MAX_ANALYSIS_TOTAL_INPUT_UTF8_BYTES:
            _raise_collision_error(
                CollisionErrorCode.TOTAL_INPUT_TOO_LARGE,
                input_record_ordinal=input_ordinal,
            )
        if record.record_id in seen_record_ids:
            _raise_collision_error(
                CollisionErrorCode.DUPLICATE_RECORD_ID,
                input_record_ordinal=input_ordinal,
            )
        seen_record_ids.add(record.record_id)
        validated.append((record, encoded))
    validated.sort(key=lambda item: item[0].record_id)
    return tuple(validated)


def _try_policy_id(policy: TransformPolicy) -> str | None:
    try:
        _validate_policy(policy)
        return policy.policy_id
    except (TypeError, ValueError):
        return None


def _validated_policies(
    policies: tuple[TransformPolicy, ...],
) -> tuple[TransformPolicy, ...]:
    if type(policies) is not tuple:
        raise TypeError("policies must be an exact tuple")
    if not 1 <= len(policies) <= MAX_ANALYSIS_POLICIES:
        _raise_collision_error(CollisionErrorCode.POLICY_COUNT)

    seen_policy_ids: set[str] = set()
    for policy_ordinal, policy in enumerate(policies):
        if type(policy) is not TransformPolicy:
            _raise_collision_error(
                CollisionErrorCode.INVALID_POLICY,
                policy_ordinal=policy_ordinal,
            )
        policy_id = _try_policy_id(policy)
        if policy_id is None:
            _raise_collision_error(
                CollisionErrorCode.INVALID_POLICY,
                policy_ordinal=policy_ordinal,
            )
        if policy_id in seen_policy_ids:
            _raise_collision_error(
                CollisionErrorCode.DUPLICATE_POLICY,
                policy_ordinal=policy_ordinal,
            )
        seen_policy_ids.add(policy_id)
    return policies


def _update_length_prefixed(digest: object, payload: bytes) -> None:
    if (
        not isinstance(digest, type(hashlib.sha256()))
        or digest.name != "sha256"
        or digest.digest_size != 32
    ):
        raise TypeError("digest must be a SHA-256 object")
    digest.update(len(payload).to_bytes(8, "big"))
    digest.update(payload)


def _semantic_corpus_sha256(
    records: tuple[tuple[IdentifierRecord, bytes], ...],
) -> str:
    digest = hashlib.sha256()
    digest.update(_SEMANTIC_CORPUS_DOMAIN)
    for record, encoded in records:
        _update_length_prefixed(digest, record.record_id.encode("ascii"))
        _update_length_prefixed(digest, encoded)
    return digest.hexdigest()


def _new_duplicate_group(
    *,
    group_id: str,
    members: tuple[int, ...],
    witness_ids: tuple[str, ...],
) -> ExactDuplicateGroup:
    group: ExactDuplicateGroup = object.__new__(ExactDuplicateGroup)
    object.__setattr__(group, "group_id", group_id)
    object.__setattr__(group, "member_record_ordinals", members)
    object.__setattr__(group, "witness_ids", witness_ids)
    return group


def _new_witness(
    *,
    witness_id: str,
    kind: WitnessKind,
    left: int,
    right: int,
    policy_ordinal: int | None,
    policy_id: str | None,
    stage_index: int | None,
    step: TransformStep | None,
) -> CollisionWitness:
    witness: CollisionWitness = object.__new__(CollisionWitness)
    object.__setattr__(witness, "witness_id", witness_id)
    object.__setattr__(witness, "kind", kind)
    object.__setattr__(witness, "left_record_ordinal", left)
    object.__setattr__(witness, "right_record_ordinal", right)
    object.__setattr__(witness, "policy_ordinal", policy_ordinal)
    object.__setattr__(witness, "policy_id", policy_id)
    object.__setattr__(witness, "stage_index", stage_index)
    object.__setattr__(witness, "step", step)
    return witness


def _new_policy_group(
    *,
    group_id: str,
    policy_ordinal: int,
    policy_id: str,
    transformed: str,
    members: tuple[int, ...],
    witness_ids: tuple[str, ...],
) -> PolicyCollisionGroup:
    group: PolicyCollisionGroup = object.__new__(PolicyCollisionGroup)
    object.__setattr__(group, "group_id", group_id)
    object.__setattr__(group, "policy_ordinal", policy_ordinal)
    object.__setattr__(group, "policy_id", policy_id)
    object.__setattr__(group, "transformed", transformed)
    object.__setattr__(group, "output_codepoints", len(transformed))
    object.__setattr__(
        group,
        "output_utf8_bytes",
        len(transformed.encode("utf-8")),
    )
    object.__setattr__(group, "member_record_ordinals", members)
    object.__setattr__(group, "witness_ids", witness_ids)
    return group


def _new_component(
    *,
    component_id: str,
    members: tuple[int, ...],
    duplicate_group_ids: tuple[str, ...],
    policy_group_ids: tuple[str, ...],
    policy_ordinals: tuple[int, ...],
    witness_tree_ids: tuple[str, ...],
) -> GlobalCollisionComponent:
    component: GlobalCollisionComponent = object.__new__(GlobalCollisionComponent)
    object.__setattr__(component, "component_id", component_id)
    object.__setattr__(component, "member_record_ordinals", members)
    object.__setattr__(component, "duplicate_group_ids", duplicate_group_ids)
    object.__setattr__(component, "policy_group_ids", policy_group_ids)
    object.__setattr__(component, "policy_ordinals", policy_ordinals)
    object.__setattr__(component, "witness_tree_ids", witness_tree_ids)
    return component


def _exact_duplicate_groups(
    records: tuple[tuple[IdentifierRecord, bytes], ...],
) -> tuple[list[ExactDuplicateGroup], list[CollisionWitness]]:
    buckets: dict[str, list[int]] = {}
    for record_ordinal, (record, _encoded) in enumerate(records):
        buckets.setdefault(record.identifier, []).append(record_ordinal)
    member_groups = sorted(
        tuple(members) for members in buckets.values() if len(members) > 1
    )

    duplicate_groups: list[ExactDuplicateGroup] = []
    witnesses: list[CollisionWitness] = []
    for group_ordinal, members in enumerate(member_groups):
        group_id = f"dg_{group_ordinal:04d}"
        anchor = members[0]
        witness_ids: list[str] = []
        for edge_ordinal, member in enumerate(members[1:]):
            witness_id = f"wi_x{group_ordinal:04d}_{edge_ordinal:04d}"
            witness_ids.append(witness_id)
            if len(witnesses) >= MAX_ANALYSIS_WITNESSES:
                _raise_collision_error(CollisionErrorCode.OUTPUT_BUDGET_EXCEEDED)
            witnesses.append(
                _new_witness(
                    witness_id=witness_id,
                    kind=WitnessKind.EXACT_INPUT,
                    left=anchor,
                    right=member,
                    policy_ordinal=None,
                    policy_id=None,
                    stage_index=None,
                    step=None,
                )
            )
        duplicate_groups.append(
            _new_duplicate_group(
                group_id=group_id,
                members=members,
                witness_ids=tuple(witness_ids),
            )
        )
    return duplicate_groups, witnesses


def _witness_sort_key(
    witness: CollisionWitness,
) -> tuple[int, int, int, int, int]:
    if witness.kind is WitnessKind.EXACT_INPUT:
        return (
            0,
            -1,
            -1,
            witness.left_record_ordinal,
            witness.right_record_ordinal,
        )
    if witness.policy_ordinal is None or witness.stage_index is None:
        raise RuntimeError("transform witness lost its policy or stage")
    return (
        1,
        witness.policy_ordinal,
        witness.stage_index,
        witness.left_record_ordinal,
        witness.right_record_ordinal,
    )


def _try_evaluate_policy(
    identifier: str,
    policy: TransformPolicy,
) -> tuple[TransformResult, tuple[str, ...]] | TransformErrorCode:
    try:
        return _evaluate_policy(identifier, policy)
    except IdentifierTransformError as error:
        return error.code


def _policy_groups_and_witnesses(
    *,
    records: tuple[tuple[IdentifierRecord, bytes], ...],
    policy: TransformPolicy,
    policy_ordinal: int,
    policy_id: str,
    duplicate_groups: list[ExactDuplicateGroup],
    exact_witnesses_by_id: dict[str, CollisionWitness],
    transformed_byte_count: int,
    existing_policy_group_count: int,
    existing_witness_count: int,
) -> tuple[list[PolicyCollisionGroup], list[CollisionWitness], int]:
    stage_values: list[tuple[str, ...]] = []
    for record_ordinal, (record, _encoded) in enumerate(records):
        evaluation = _try_evaluate_policy(record.identifier, policy)
        if isinstance(evaluation, TransformErrorCode):
            _raise_collision_error(
                CollisionErrorCode.POLICY_REJECTED_RECORD,
                canonical_record_ordinal=record_ordinal,
                policy_ordinal=policy_ordinal,
                transform_error_code=evaluation,
            )
        result, values = evaluation
        transformed_byte_count += sum(stage.after_utf8_bytes for stage in result.stages)
        if transformed_byte_count > MAX_ANALYSIS_TRANSFORMED_UTF8_BYTES:
            _raise_collision_error(
                CollisionErrorCode.TRANSFORMED_DATA_TOO_LARGE,
                canonical_record_ordinal=record_ordinal,
                policy_ordinal=policy_ordinal,
            )
        stage_values.append(values)

    final_buckets: dict[str, list[int]] = {}
    for record_ordinal, values in enumerate(stage_values):
        final_buckets.setdefault(values[-1], []).append(record_ordinal)
    collision_buckets = sorted(
        (
            (tuple(members), transformed)
            for transformed, members in final_buckets.items()
            if len(members) > 1
            and len({records[member][0].identifier for member in members}) > 1
        ),
        key=lambda item: item[0],
    )

    groups: list[PolicyCollisionGroup] = []
    witnesses: list[CollisionWitness] = []
    for group_ordinal, (members, transformed) in enumerate(collision_buckets):
        if existing_policy_group_count + len(groups) >= MAX_ANALYSIS_POLICY_GROUPS:
            _raise_collision_error(CollisionErrorCode.OUTPUT_BUDGET_EXCEEDED)
        group_id = f"pc_p{policy_ordinal:02d}_{group_ordinal:04d}"
        member_set = frozenset(members)
        disjoint = _DisjointSet(members)
        witness_ids: list[str] = []

        for duplicate_group in duplicate_groups:
            duplicate_members = duplicate_group.member_record_ordinals
            if not frozenset(duplicate_members).issubset(member_set):
                continue
            anchor = duplicate_members[0]
            for member in duplicate_members[1:]:
                _require_internal(
                    disjoint.union(anchor, member),
                    "exact duplicate witness formed a cycle",
                )
            witness_ids.extend(duplicate_group.witness_ids)

        for stage_index, step in enumerate(policy.steps):
            stage_buckets: dict[str, list[int]] = {}
            for member in members:
                stage_buckets.setdefault(
                    stage_values[member][stage_index],
                    [],
                ).append(member)
            for stage_members in sorted(
                (tuple(value) for value in stage_buckets.values()),
            ):
                roots = sorted({disjoint.find(member) for member in stage_members})
                if len(roots) < 2:
                    continue
                anchor = roots[0]
                for other in roots[1:]:
                    left = disjoint.find(anchor)
                    right = disjoint.find(other)
                    _require_internal(
                        left < right,
                        "disjoint-set roots lost canonical order",
                    )
                    before_left = (
                        records[left][0].identifier
                        if stage_index == 0
                        else stage_values[left][stage_index - 1]
                    )
                    before_right = (
                        records[right][0].identifier
                        if stage_index == 0
                        else stage_values[right][stage_index - 1]
                    )
                    after_left = stage_values[left][stage_index]
                    after_right = stage_values[right][stage_index]
                    _require_internal(
                        before_left != before_right and after_left == after_right,
                        "stage witness violated first-merge invariants",
                    )
                    witness_id = (
                        f"wi_p{policy_ordinal:02d}_s{stage_index:02d}_"
                        f"{left:04d}_{right:04d}"
                    )
                    witness = _new_witness(
                        witness_id=witness_id,
                        kind=WitnessKind.TRANSFORM_STAGE,
                        left=left,
                        right=right,
                        policy_ordinal=policy_ordinal,
                        policy_id=policy_id,
                        stage_index=stage_index,
                        step=step,
                    )
                    if (
                        existing_witness_count + len(witnesses)
                        >= MAX_ANALYSIS_WITNESSES
                    ):
                        _raise_collision_error(
                            CollisionErrorCode.OUTPUT_BUDGET_EXCEEDED
                        )
                    witnesses.append(witness)
                    witness_ids.append(witness_id)
                    _require_internal(
                        disjoint.union(left, right),
                        "transform witness formed a cycle",
                    )
                _require_internal(
                    len({disjoint.find(member) for member in stage_members}) == 1,
                    "stage bucket did not become connected",
                )

        _require_internal(
            len({disjoint.find(member) for member in members}) == 1,
            "final collision bucket is not connected",
        )
        _require_internal(
            len(witness_ids) == len(members) - 1,
            "policy witness forest is not minimal",
        )
        for witness_id in witness_ids:
            _require_internal(
                not witness_id.startswith("wi_x")
                or witness_id in exact_witnesses_by_id,
                "policy group references unknown duplicate witness",
            )
        groups.append(
            _new_policy_group(
                group_id=group_id,
                policy_ordinal=policy_ordinal,
                policy_id=policy_id,
                transformed=transformed,
                members=members,
                witness_ids=tuple(witness_ids),
            )
        )
    return groups, witnesses, transformed_byte_count


def _global_components(
    *,
    record_count: int,
    duplicate_groups: list[ExactDuplicateGroup],
    policy_groups: list[PolicyCollisionGroup],
    witnesses: list[CollisionWitness],
) -> tuple[list[GlobalCollisionComponent], tuple[int, ...]]:
    all_members = tuple(range(record_count))
    disjoint = _DisjointSet(all_members)
    for witness in witnesses:
        disjoint.union(
            witness.left_record_ordinal,
            witness.right_record_ordinal,
        )

    buckets: dict[int, list[int]] = {}
    for member in all_members:
        buckets.setdefault(disjoint.find(member), []).append(member)
    member_groups = sorted(tuple(members) for members in buckets.values())
    component_members = [members for members in member_groups if len(members) > 1]
    isolated = tuple(members[0] for members in member_groups if len(members) == 1)
    if len(component_members) > MAX_ANALYSIS_COMPONENTS:
        _raise_collision_error(CollisionErrorCode.OUTPUT_BUDGET_EXCEEDED)

    sorted_witnesses = sorted(witnesses, key=_witness_sort_key)
    components: list[GlobalCollisionComponent] = []
    for component_ordinal, members in enumerate(component_members):
        member_set = frozenset(members)
        duplicate_group_ids = tuple(
            group.group_id
            for group in duplicate_groups
            if frozenset(group.member_record_ordinals).issubset(member_set)
        )
        matching_policy_groups = tuple(
            group
            for group in policy_groups
            if frozenset(group.member_record_ordinals).issubset(member_set)
        )
        policy_group_ids = tuple(group.group_id for group in matching_policy_groups)
        policy_ordinals = tuple(
            sorted({group.policy_ordinal for group in matching_policy_groups})
        )

        tree = _DisjointSet(members)
        tree_witness_ids: list[str] = []
        for witness in sorted_witnesses:
            if (
                witness.left_record_ordinal not in member_set
                or witness.right_record_ordinal not in member_set
            ):
                continue
            if tree.union(
                witness.left_record_ordinal,
                witness.right_record_ordinal,
            ):
                tree_witness_ids.append(witness.witness_id)
        _require_internal(
            len(tree_witness_ids) == len(members) - 1,
            "global component witness selection is not minimal",
        )
        components.append(
            _new_component(
                component_id=f"gc_{component_ordinal:04d}",
                members=members,
                duplicate_group_ids=duplicate_group_ids,
                policy_group_ids=policy_group_ids,
                policy_ordinals=policy_ordinals,
                witness_tree_ids=tuple(tree_witness_ids),
            )
        )
    return components, isolated


def analyze_collisions(
    records: tuple[IdentifierRecord, ...],
    policies: tuple[TransformPolicy, ...],
) -> CollisionGraph:
    """Analyze a canonical record set atomically under ordered policies.

    Record tuple order is intentionally non-semantic. Unique record IDs define
    canonical record ordinals; policy tuple order remains explicit and
    significant. Any rejected record aborts the whole analysis.
    """

    validated_records = _validated_records(records)
    validated_policies = _validated_policies(policies)
    transform_applications = len(validated_records) * sum(
        len(policy.steps) for policy in validated_policies
    )
    if transform_applications > MAX_ANALYSIS_TRANSFORM_APPLICATIONS:
        _raise_collision_error(CollisionErrorCode.TRANSFORM_BUDGET_EXCEEDED)

    semantic_corpus_sha256 = _semantic_corpus_sha256(validated_records)
    duplicate_groups, witnesses = _exact_duplicate_groups(validated_records)
    exact_witnesses_by_id = {witness.witness_id: witness for witness in witnesses}
    policy_groups: list[PolicyCollisionGroup] = []
    transformed_byte_count = 0
    for policy_ordinal, policy in enumerate(validated_policies):
        groups, policy_witnesses, transformed_byte_count = _policy_groups_and_witnesses(
            records=validated_records,
            policy=policy,
            policy_ordinal=policy_ordinal,
            policy_id=policy.policy_id,
            duplicate_groups=duplicate_groups,
            exact_witnesses_by_id=exact_witnesses_by_id,
            transformed_byte_count=transformed_byte_count,
            existing_policy_group_count=len(policy_groups),
            existing_witness_count=len(witnesses),
        )
        policy_groups.extend(groups)
        witnesses.extend(policy_witnesses)

    witnesses.sort(key=_witness_sort_key)
    _require_internal(
        len({witness.witness_id for witness in witnesses}) == len(witnesses),
        "collision witness IDs are not unique",
    )
    components, isolated = _global_components(
        record_count=len(validated_records),
        duplicate_groups=duplicate_groups,
        policy_groups=policy_groups,
        witnesses=witnesses,
    )

    graph: CollisionGraph = object.__new__(CollisionGraph)
    object.__setattr__(graph, "algorithm", COLLISION_ALGORITHM)
    object.__setattr__(graph, "unicode_version", unicodedata.unidata_version)
    object.__setattr__(
        graph,
        "semantic_corpus_sha256",
        semantic_corpus_sha256,
    )
    object.__setattr__(
        graph,
        "record_ids",
        tuple(record.record_id for record, _encoded in validated_records),
    )
    object.__setattr__(
        graph,
        "policy_ids",
        tuple(policy.policy_id for policy in validated_policies),
    )
    object.__setattr__(graph, "duplicate_groups", tuple(duplicate_groups))
    object.__setattr__(graph, "policy_groups", tuple(policy_groups))
    object.__setattr__(graph, "witnesses", tuple(witnesses))
    object.__setattr__(graph, "components", tuple(components))
    object.__setattr__(graph, "isolated_record_ordinals", isolated)
    return graph

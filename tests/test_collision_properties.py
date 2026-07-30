from __future__ import annotations

import hashlib
import itertools
import json
import os
import subprocess
import sys
import textwrap
import unicodedata
import unittest
from collections import deque
from pathlib import Path

from casefold_observatory import (
    CollisionGraph,
    CollisionWitness,
    IdentifierRecord,
    TransformPolicy,
    TransformStep,
    WitnessKind,
    analyze_collisions,
    create_identifier_record,
    create_policy,
)


def _records(*values: tuple[str, str]) -> tuple[IdentifierRecord, ...]:
    return tuple(
        create_identifier_record(record_id, identifier)
        for record_id, identifier in values
    )


def _oracle_apply_step(value: str, step: TransformStep) -> str:
    if step is TransformStep.NFC:
        return unicodedata.normalize("NFC", value)
    if step is TransformStep.NFD:
        return unicodedata.normalize("NFD", value)
    if step is TransformStep.NFKC:
        return unicodedata.normalize("NFKC", value)
    if step is TransformStep.NFKD:
        return unicodedata.normalize("NFKD", value)
    if step is TransformStep.LOWER:
        return value.lower()
    if step is TransformStep.UPPER:
        return value.upper()
    if step is TransformStep.CASEFOLD:
        return value.casefold()
    raise AssertionError("the test oracle is missing a transformation step")


def _oracle_stages(value: str, policy: TransformPolicy) -> tuple[str, ...]:
    values: list[str] = []
    for step in policy.steps:
        value = _oracle_apply_step(value, step)
        values.append(value)
    return tuple(values)


def _path_witnesses(
    *,
    left: int,
    right: int,
    witness_ids: tuple[str, ...],
    witnesses_by_id: dict[str, CollisionWitness],
) -> tuple[CollisionWitness, ...]:
    adjacency: dict[int, list[tuple[int, CollisionWitness]]] = {}
    for witness_id in witness_ids:
        witness = witnesses_by_id[witness_id]
        adjacency.setdefault(witness.left_record_ordinal, []).append(
            (witness.right_record_ordinal, witness)
        )
        adjacency.setdefault(witness.right_record_ordinal, []).append(
            (witness.left_record_ordinal, witness)
        )

    queue: deque[tuple[int, tuple[CollisionWitness, ...]]] = deque([(left, ())])
    seen = {left}
    while queue:
        current, path = queue.popleft()
        if current == right:
            return path
        for neighbor, witness in adjacency.get(current, ()):
            if neighbor in seen:
                continue
            seen.add(neighbor)
            queue.append((neighbor, (*path, witness)))
    raise AssertionError("witness tree did not connect two group members")


def _witness_stage_rank(witness: CollisionWitness) -> int:
    if witness.kind is WitnessKind.EXACT_INPUT:
        return -1
    if witness.stage_index is None:
        raise AssertionError("transform witness is missing its stage")
    return witness.stage_index


def _component_partition(
    graph: CollisionGraph,
) -> tuple[tuple[int, ...], ...]:
    parent = list(range(graph.record_count))

    def find(member: int) -> int:
        while parent[member] != member:
            parent[member] = parent[parent[member]]
            member = parent[member]
        return member

    def union(left: int, right: int) -> None:
        left_root = find(left)
        right_root = find(right)
        if left_root != right_root:
            parent[max(left_root, right_root)] = min(left_root, right_root)

    relations = (
        *(group.member_record_ordinals for group in graph.duplicate_groups),
        *(group.member_record_ordinals for group in graph.policy_groups),
    )
    for members in relations:
        for member in members[1:]:
            union(members[0], member)

    buckets: dict[int, list[int]] = {}
    for member in range(graph.record_count):
        buckets.setdefault(find(member), []).append(member)
    return tuple(sorted(tuple(members) for members in buckets.values()))


class CollisionOracleTests(unittest.TestCase):
    def test_groups_witnesses_and_components_match_independent_oracles(self) -> None:
        source = _records(
            ("ascii-digit", "1"),
            ("ascii-k", "K"),
            ("circled-digit", "①"),
            ("decomposed", "e\u0301"),
            ("duplicate-a", "same"),
            ("duplicate-b", "same"),
            ("eszett", "ß"),
            ("fullwidth-digit", "１"),
            ("kelvin", "K"),
            ("lower-ss", "ss"),
            ("precomposed", "é"),
            ("upper-ss", "SS"),
        )
        policies = (
            create_policy((TransformStep.LOWER, TransformStep.CASEFOLD)),
            create_policy((TransformStep.NFKC,)),
            create_policy(
                (
                    TransformStep.NFD,
                    TransformStep.CASEFOLD,
                    TransformStep.NFC,
                )
            ),
            create_policy((TransformStep.UPPER,)),
        )
        graph = analyze_collisions(tuple(reversed(source)), policies)
        source_by_id = {record.record_id: record.identifier for record in source}
        raw_values = tuple(source_by_id[record_id] for record_id in graph.record_ids)
        stages = tuple(
            tuple(_oracle_stages(raw, policy) for raw in raw_values)
            for policy in policies
        )

        expected_groups: list[tuple[int, tuple[int, ...], str]] = []
        for policy_ordinal, policy_stages in enumerate(stages):
            buckets: dict[str, list[int]] = {}
            for record_ordinal, values in enumerate(policy_stages):
                buckets.setdefault(values[-1], []).append(record_ordinal)
            expected_groups.extend(
                (
                    policy_ordinal,
                    tuple(members),
                    transformed,
                )
                for transformed, members in buckets.items()
                if len(members) > 1
                and len({raw_values[member] for member in members}) > 1
            )
        expected_groups.sort(key=lambda item: (item[0], item[1]))
        self.assertEqual(
            [
                (
                    group.policy_ordinal,
                    group.member_record_ordinals,
                    group.transformed,
                )
                for group in graph.policy_groups
            ],
            expected_groups,
        )

        witnesses_by_id = {witness.witness_id: witness for witness in graph.witnesses}
        self.assertEqual(len(witnesses_by_id), len(graph.witnesses))
        for witness in graph.witnesses:
            left = witness.left_record_ordinal
            right = witness.right_record_ordinal
            if witness.kind is WitnessKind.EXACT_INPUT:
                self.assertEqual(raw_values[left], raw_values[right])
                self.assertIsNone(witness.policy_ordinal)
                self.assertIsNone(witness.stage_index)
                continue
            self.assertIsNotNone(witness.policy_ordinal)
            self.assertIsNotNone(witness.stage_index)
            witness_policy_ordinal = witness.policy_ordinal
            witness_stage_index = witness.stage_index
            assert witness_policy_ordinal is not None
            assert witness_stage_index is not None
            before_left = (
                raw_values[left]
                if witness_stage_index == 0
                else stages[witness_policy_ordinal][left][witness_stage_index - 1]
            )
            before_right = (
                raw_values[right]
                if witness_stage_index == 0
                else stages[witness_policy_ordinal][right][witness_stage_index - 1]
            )
            self.assertNotEqual(before_left, before_right)
            self.assertEqual(
                stages[witness_policy_ordinal][left][witness_stage_index],
                stages[witness_policy_ordinal][right][witness_stage_index],
            )

        for group in graph.policy_groups:
            self.assertEqual(
                len(group.witness_ids),
                len(group.member_record_ordinals) - 1,
            )
            policy_stages = stages[group.policy_ordinal]
            for left, right in itertools.combinations(
                group.member_record_ordinals,
                2,
            ):
                path = _path_witnesses(
                    left=left,
                    right=right,
                    witness_ids=group.witness_ids,
                    witnesses_by_id=witnesses_by_id,
                )
                path_merge_stage = max(_witness_stage_rank(witness) for witness in path)
                first_equal_stage = (
                    -1
                    if raw_values[left] == raw_values[right]
                    else next(
                        stage_index
                        for stage_index in range(
                            len(policies[group.policy_ordinal].steps)
                        )
                        if policy_stages[left][stage_index]
                        == policy_stages[right][stage_index]
                    )
                )
                self.assertEqual(path_merge_stage, first_equal_stage)

        expected_partition = _component_partition(graph)
        self.assertEqual(
            tuple(
                sorted(
                    (
                        *(
                            component.member_record_ordinals
                            for component in graph.components
                        ),
                        *((member,) for member in graph.isolated_record_ordinals),
                    )
                )
            ),
            expected_partition,
        )
        for component in graph.components:
            self.assertEqual(
                len(component.witness_tree_ids),
                len(component.member_record_ordinals) - 1,
            )
            for witness_id in component.witness_tree_ids:
                witness = witnesses_by_id[witness_id]
                self.assertIn(
                    witness.left_record_ordinal,
                    component.member_record_ordinals,
                )
                self.assertIn(
                    witness.right_record_ordinal,
                    component.member_record_ordinals,
                )

    def test_semantic_digest_has_a_stable_length_framed_known_answer(self) -> None:
        policy = (create_policy((TransformStep.NFC,)),)
        graph = analyze_collisions(
            _records(("eszett", "ß"), ("ascii", "SS")),
            policy,
        )

        self.assertEqual(
            graph.semantic_corpus_sha256,
            "c9d6a4384f3ad8e7e99dad43b020e10c433a279f3a0bfd8c9f9ed7021c117c80",
        )
        self.assertEqual(
            graph.semantic_corpus_sha256,
            analyze_collisions(
                _records(("ascii", "SS"), ("eszett", "ß")),
                policy,
            ).semantic_corpus_sha256,
        )

        first = analyze_collisions(_records(("a", "bc")), policy)
        second = analyze_collisions(_records(("ab", "c")), policy)
        self.assertEqual(
            b"a" + b"bc",
            b"ab" + b"c",
        )
        self.assertNotEqual(
            first.semantic_corpus_sha256,
            second.semantic_corpus_sha256,
        )

        manual = hashlib.sha256()
        manual.update(b"casefold-observatory.semantic-corpus.v1\x00")
        for record_id, identifier in (("ascii", "SS"), ("eszett", "ß")):
            for payload in (record_id.encode("ascii"), identifier.encode("utf-8")):
                manual.update(len(payload).to_bytes(8, "big"))
                manual.update(payload)
        self.assertEqual(graph.semantic_corpus_sha256, manual.hexdigest())

    def test_graph_projection_is_stable_across_python_hash_seeds(self) -> None:
        script = textwrap.dedent(
            """
            import json
            from casefold_observatory import (
                TransformStep,
                analyze_collisions,
                create_identifier_record,
                create_policy,
            )

            records = tuple(
                create_identifier_record(record_id, value)
                for record_id, value in (
                    ("upper", "SS"),
                    ("kelvin", "K"),
                    ("lower", "ss"),
                    ("ascii-k", "K"),
                    ("eszett", "ß"),
                )
            )
            policies = (
                create_policy((TransformStep.LOWER, TransformStep.CASEFOLD)),
                create_policy((TransformStep.NFKC, TransformStep.CASEFOLD)),
            )
            graph = analyze_collisions(records, policies)
            payload = {
                "algorithm": graph.algorithm,
                "components": [
                    [
                        component.component_id,
                        component.member_record_ordinals,
                        component.policy_group_ids,
                        component.witness_tree_ids,
                    ]
                    for component in graph.components
                ],
                "digest": graph.semantic_corpus_sha256,
                "duplicate_groups": [
                    [
                        group.group_id,
                        group.member_record_ordinals,
                        group.witness_ids,
                    ]
                    for group in graph.duplicate_groups
                ],
                "policy_groups": [
                    [
                        group.group_id,
                        group.policy_ordinal,
                        group.member_record_ordinals,
                        group.witness_ids,
                    ]
                    for group in graph.policy_groups
                ],
                "record_ids": graph.record_ids,
                "witnesses": [
                    [
                        witness.witness_id,
                        witness.kind.value,
                        witness.left_record_ordinal,
                        witness.right_record_ordinal,
                        witness.policy_ordinal,
                        witness.stage_index,
                    ]
                    for witness in graph.witnesses
                ],
            }
            print(json.dumps(payload, sort_keys=True, separators=(",", ":")))
            """
        )
        project_root = Path(__file__).resolve().parents[1]
        outputs: list[str] = []
        for seed in ("1", "7", "42", "314159"):
            environment = os.environ.copy()
            environment["PYTHONHASHSEED"] = seed
            environment["PYTHONPATH"] = str(project_root / "src")
            completed = subprocess.run(
                [sys.executable, "-c", script],
                check=True,
                capture_output=True,
                text=True,
                env=environment,
            )
            outputs.append(completed.stdout)

        self.assertTrue(all(output == outputs[0] for output in outputs[1:]))
        self.assertEqual(
            json.loads(outputs[0])["record_ids"],
            ["ascii-k", "eszett", "kelvin", "lower", "upper"],
        )


if __name__ == "__main__":
    unittest.main()

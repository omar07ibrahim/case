from __future__ import annotations

import hashlib
import traceback
import unicodedata
import unittest
from unittest.mock import patch

import casefold_observatory.collision as collision_module
from casefold_observatory import (
    MAX_INPUT_CODEPOINTS,
    MAX_RECORD_ID_CHARS,
    CollisionAnalysisError,
    CollisionErrorCode,
    HazardHandling,
    IdentifierRecord,
    IdentifierTransformError,
    TransformErrorCode,
    TransformPolicy,
    TransformStep,
    WitnessKind,
    analyze_collisions,
    apply_policy,
    create_identifier_record,
    create_policy,
)


def records(*values: tuple[str, str]) -> tuple[IdentifierRecord, ...]:
    return tuple(
        create_identifier_record(record_id, identifier)
        for record_id, identifier in values
    )


def assert_tree(
    test: unittest.TestCase,
    members: tuple[int, ...],
    witness_ids: tuple[str, ...],
    graph_witnesses: tuple[collision_module.CollisionWitness, ...],
) -> None:
    by_id = {witness.witness_id: witness for witness in graph_witnesses}
    parent = {member: member for member in members}

    def find(member: int) -> int:
        while parent[member] != member:
            member = parent[member]
        return member

    test.assertEqual(len(witness_ids), len(members) - 1)
    for witness_id in witness_ids:
        witness = by_id[witness_id]
        left = find(witness.left_record_ordinal)
        right = find(witness.right_record_ordinal)
        test.assertNotEqual(left, right)
        parent[max(left, right)] = min(left, right)
    test.assertEqual({find(member) for member in members}, {min(members)})


class CollisionGraphTests(unittest.TestCase):
    def test_staged_merges_emit_a_minimal_first_stage_witness_tree(self) -> None:
        graph = analyze_collisions(
            records(
                ("upper", "SS"),
                ("eszett", "ß"),
                ("lower", "ss"),
            ),
            (create_policy((TransformStep.LOWER, TransformStep.CASEFOLD)),),
        )

        self.assertEqual(graph.record_ids, ("eszett", "lower", "upper"))
        self.assertEqual(graph.record_count, 3)
        self.assertEqual(graph.colliding_record_count, 3)
        self.assertEqual(graph.isolated_record_ordinals, ())
        self.assertEqual(len(graph.policy_groups), 1)
        group = graph.policy_groups[0]
        self.assertEqual(group.member_record_ordinals, (0, 1, 2))
        self.assertEqual(group.transformed, "ss")
        self.assertEqual(group.output_codepoints, 2)
        self.assertEqual(group.output_utf8_bytes, 2)
        self.assertEqual(
            [
                (
                    witness.left_record_ordinal,
                    witness.right_record_ordinal,
                    witness.stage_index,
                    witness.step,
                )
                for witness in graph.witnesses
            ],
            [
                (1, 2, 0, TransformStep.LOWER),
                (0, 1, 1, TransformStep.CASEFOLD),
            ],
        )
        self.assertTrue(
            all(
                witness.kind is WitnessKind.TRANSFORM_STAGE
                for witness in graph.witnesses
            )
        )
        assert_tree(
            self,
            group.member_record_ordinals,
            group.witness_ids,
            graph.witnesses,
        )
        self.assertEqual(len(graph.components), 1)
        assert_tree(
            self,
            graph.components[0].member_record_ordinals,
            graph.components[0].witness_tree_ids,
            graph.witnesses,
        )

    def test_exact_duplicate_occurrences_are_preserved_and_classified(self) -> None:
        graph = analyze_collisions(
            records(
                ("duplicate-b", "K"),
                ("kelvin", "K"),
                ("duplicate-a", "K"),
            ),
            (create_policy((TransformStep.NFC,)),),
        )

        self.assertEqual(
            graph.record_ids,
            ("duplicate-a", "duplicate-b", "kelvin"),
        )
        self.assertEqual(len(graph.duplicate_groups), 1)
        duplicate = graph.duplicate_groups[0]
        self.assertEqual(duplicate.member_record_ordinals, (0, 1))
        exact = graph.witnesses[0]
        self.assertEqual(exact.kind, WitnessKind.EXACT_INPUT)
        self.assertIsNone(exact.policy_ordinal)
        self.assertIsNone(exact.policy_id)
        self.assertIsNone(exact.stage_index)
        self.assertIsNone(exact.step)

        group = graph.policy_groups[0]
        self.assertEqual(group.member_record_ordinals, (0, 1, 2))
        self.assertEqual(len(group.witness_ids), 2)
        transform = graph.witnesses[1]
        self.assertEqual(transform.kind, WitnessKind.TRANSFORM_STAGE)
        self.assertEqual(transform.stage_index, 0)
        self.assertEqual(transform.step, TransformStep.NFC)
        self.assertEqual(graph.components[0].duplicate_group_ids, (duplicate.group_id,))
        assert_tree(
            self,
            group.member_record_ordinals,
            group.witness_ids,
            graph.witnesses,
        )

    def test_two_duplicate_classes_merge_with_one_transform_witness(self) -> None:
        graph = analyze_collisions(
            records(
                ("lower-a", "a"),
                ("upper-a", "A"),
                ("lower-b", "a"),
                ("upper-b", "A"),
            ),
            (create_policy((TransformStep.LOWER,)),),
        )

        self.assertEqual(
            [group.member_record_ordinals for group in graph.duplicate_groups],
            [(0, 1), (2, 3)],
        )
        group = graph.policy_groups[0]
        self.assertEqual(group.member_record_ordinals, (0, 1, 2, 3))
        self.assertEqual(len(group.witness_ids), 3)
        self.assertEqual(
            [witness.kind for witness in graph.witnesses],
            [
                WitnessKind.EXACT_INPUT,
                WitnessKind.EXACT_INPUT,
                WitnessKind.TRANSFORM_STAGE,
            ],
        )
        assert_tree(
            self,
            group.member_record_ordinals,
            group.witness_ids,
            graph.witnesses,
        )

    def test_exact_duplicates_without_a_policy_merge_are_not_repeated(self) -> None:
        graph = analyze_collisions(
            records(("same-a", "same"), ("same-b", "same"), ("other", "other")),
            (create_policy((TransformStep.NFC,)),),
        )

        self.assertEqual(len(graph.duplicate_groups), 1)
        self.assertEqual(graph.policy_groups, ())
        self.assertEqual(len(graph.witnesses), 1)
        self.assertEqual(graph.components[0].policy_group_ids, ())
        self.assertEqual(graph.components[0].policy_ordinals, ())
        self.assertEqual(graph.isolated_record_ordinals, (0,))

    def test_disjoint_duplicate_and_policy_components_remain_separate(self) -> None:
        graph = analyze_collisions(
            records(
                ("duplicate-a", "same"),
                ("duplicate-b", "same"),
                ("lower", "a"),
                ("upper", "A"),
            ),
            (create_policy((TransformStep.LOWER,)),),
        )

        self.assertEqual(
            [component.member_record_ordinals for component in graph.components],
            [(0, 1), (2, 3)],
        )
        self.assertEqual(graph.components[0].duplicate_group_ids, ("dg_0000",))
        self.assertEqual(graph.components[0].policy_group_ids, ())
        self.assertEqual(graph.components[1].duplicate_group_ids, ())
        self.assertEqual(
            graph.components[1].policy_group_ids,
            ("pc_p00_0000",),
        )
        for component in graph.components:
            assert_tree(
                self,
                component.member_record_ordinals,
                component.witness_tree_ids,
                graph.witnesses,
            )

    def test_simultaneous_multiway_merge_uses_a_star_not_a_clique(self) -> None:
        graph = analyze_collisions(
            records(
                ("ascii", "1"),
                ("circled", "①"),
                ("fullwidth", "１"),
            ),
            (create_policy((TransformStep.NFKC,)),),
        )

        group = graph.policy_groups[0]
        self.assertEqual(group.transformed, "1")
        self.assertEqual(len(group.witness_ids), 2)
        self.assertEqual(
            {
                (
                    witness.left_record_ordinal,
                    witness.right_record_ordinal,
                )
                for witness in graph.witnesses
            },
            {(0, 1), (0, 2)},
        )
        assert_tree(
            self,
            group.member_record_ordinals,
            group.witness_ids,
            graph.witnesses,
        )

    def test_cross_policy_component_is_a_union_not_one_equivalence_class(self) -> None:
        corpus = records(
            ("precomposed", "é"),
            ("decomposed", "e\u0301"),
            ("upper-decomposed", "E\u0301"),
        )
        policies = (
            create_policy((TransformStep.NFC,)),
            create_policy((TransformStep.LOWER,)),
            create_policy((TransformStep.NFD,)),
        )
        graph = analyze_collisions(corpus, policies)

        self.assertEqual(
            graph.record_ids, ("decomposed", "precomposed", "upper-decomposed")
        )
        self.assertEqual(
            [group.member_record_ordinals for group in graph.policy_groups],
            [(0, 1), (0, 2), (0, 1)],
        )
        self.assertEqual(len(graph.witnesses), 3)
        component = graph.components[0]
        self.assertEqual(component.member_record_ordinals, (0, 1, 2))
        self.assertEqual(component.policy_ordinals, (0, 1, 2))
        self.assertEqual(len(component.witness_tree_ids), 2)
        self.assertNotEqual(
            apply_policy(corpus[0].identifier, policies[0]).transformed,
            apply_policy(corpus[2].identifier, policies[0]).transformed,
        )
        self.assertNotEqual(
            apply_policy(corpus[0].identifier, policies[1]).transformed,
            apply_policy(corpus[2].identifier, policies[1]).transformed,
        )
        assert_tree(
            self,
            component.member_record_ordinals,
            component.witness_tree_ids,
            graph.witnesses,
        )

    def test_record_tuple_order_is_non_semantic_but_policy_order_is_explicit(
        self,
    ) -> None:
        first = create_identifier_record("first", "Straße")
        second = create_identifier_record("second", "STRASSE")
        lower = create_policy((TransformStep.LOWER,))
        folded = create_policy((TransformStep.CASEFOLD,))

        ordered = analyze_collisions((first, second), (lower, folded))
        shuffled = analyze_collisions((second, first), (lower, folded))
        reordered_policies = analyze_collisions((first, second), (folded, lower))

        self.assertEqual(ordered, shuffled)
        self.assertEqual(
            ordered.semantic_corpus_sha256,
            shuffled.semantic_corpus_sha256,
        )
        self.assertNotEqual(ordered.policy_ids, reordered_policies.policy_ids)
        self.assertEqual(
            [component.member_record_ordinals for component in ordered.components],
            [
                component.member_record_ordinals
                for component in reordered_policies.components
            ],
        )

    def test_empty_singleton_and_no_collision_corpora_remain_visible(self) -> None:
        policy = (create_policy((TransformStep.NFC,)),)
        empty = analyze_collisions((), policy)
        singleton = analyze_collisions(records(("only", "only")), policy)
        distinct = analyze_collisions(
            records(("alpha", "alpha"), ("beta", "beta")),
            policy,
        )

        self.assertEqual(empty.record_count, 0)
        self.assertEqual(empty.components, ())
        self.assertEqual(empty.isolated_record_ordinals, ())
        self.assertEqual(singleton.isolated_record_ordinals, (0,))
        self.assertEqual(distinct.isolated_record_ordinals, (0, 1))
        self.assertEqual(distinct.colliding_record_count, 0)
        self.assertRegex(empty.semantic_corpus_sha256, r"^[0-9a-f]{64}$")

    def test_global_corpus_digest_never_defines_identifier_equality(self) -> None:
        with patch.object(
            collision_module,
            "_semantic_corpus_sha256",
            return_value="0" * 64,
        ):
            graph = analyze_collisions(
                records(("alpha", "alpha"), ("beta", "beta")),
                (create_policy((TransformStep.NFC,)),),
            )

        self.assertEqual(graph.semantic_corpus_sha256, "0" * 64)
        self.assertEqual(graph.policy_groups, ())
        self.assertEqual(graph.components, ())

    def test_preserved_hazards_analyze_but_rejection_is_atomic_and_redacted(
        self,
    ) -> None:
        secret = "private\u202evalue"
        corpus = records(("private-record", secret), ("safe-record", "safe"))
        preserve = create_policy(
            (TransformStep.NFC,),
            hazard_handling=HazardHandling.PRESERVE,
        )
        graph = analyze_collisions(corpus, (preserve,))
        self.assertEqual(graph.isolated_record_ordinals, (0, 1))

        reject = create_policy((TransformStep.NFC,))
        with self.assertRaises(CollisionAnalysisError) as raised:
            analyze_collisions(corpus, (reject,))
        error = raised.exception
        self.assertEqual(error.code, CollisionErrorCode.POLICY_REJECTED_RECORD)
        self.assertEqual(error.canonical_record_ordinal, 0)
        self.assertIsNone(error.input_record_ordinal)
        self.assertEqual(error.policy_ordinal, 0)
        self.assertEqual(
            error.transform_error_code,
            TransformErrorCode.FORBIDDEN_CODE_POINT,
        )
        rendered = "".join(
            traceback.format_exception(type(error), error, error.__traceback__)
        )
        self.assertNotIn(secret, str(error))
        self.assertNotIn(secret, rendered)
        self.assertNotIn("private-record", str(error))
        self.assertIsNone(error.__context__)

    def test_stage_expansion_failure_aborts_without_partial_graph(self) -> None:
        expansion = unicodedata.normalize("NFKD", "\ufdfa")
        value = "\ufdfa" * (4_096 // len(expansion) + 1)
        self.assertLessEqual(len(value), MAX_INPUT_CODEPOINTS)

        with self.assertRaises(CollisionAnalysisError) as raised:
            analyze_collisions(
                records(("expanding", value)),
                (create_policy((TransformStep.NFKD,)),),
            )

        self.assertEqual(
            raised.exception.transform_error_code,
            TransformErrorCode.STAGE_TOO_LARGE,
        )
        self.assertEqual(raised.exception.canonical_record_ordinal, 0)
        self.assertIsNone(raised.exception.input_record_ordinal)

    def test_rejected_record_selection_uses_canonical_record_order(self) -> None:
        first = create_identifier_record("a-secret", "a\u202e")
        second = create_identifier_record("z-secret", "z\u202e")
        policy = (create_policy((TransformStep.NFC,)),)

        errors: list[CollisionAnalysisError] = []
        for corpus in ((first, second), (second, first)):
            with self.assertRaises(CollisionAnalysisError) as raised:
                analyze_collisions(corpus, policy)
            errors.append(raised.exception)

        for error in errors:
            self.assertEqual(
                error.code,
                CollisionErrorCode.POLICY_REJECTED_RECORD,
            )
            self.assertEqual(error.canonical_record_ordinal, 0)
            self.assertIsNone(error.input_record_ordinal)
        self.assertEqual(str(errors[0]), str(errors[1]))

    def test_repr_omits_record_ids_raw_values_and_transformed_values(self) -> None:
        secret_id = "private-id"
        secret_value = "Straße-private"
        record = create_identifier_record(secret_id, secret_value)
        graph = analyze_collisions(
            (
                record,
                create_identifier_record("other", "STRASSE-PRIVATE"),
            ),
            (create_policy((TransformStep.CASEFOLD,)),),
        )

        self.assertNotIn(secret_id, repr(record))
        self.assertNotIn(secret_value, repr(record))
        self.assertNotIn("strasse-private", repr(graph.policy_groups[0]))
        self.assertNotIn(secret_id, repr(graph))
        self.assertNotIn(secret_value, repr(graph))


class CollisionBoundaryTests(unittest.TestCase):
    def test_record_factory_requires_canonical_id_and_exact_bounded_text(self) -> None:
        accepted_id = "a" * MAX_RECORD_ID_CHARS
        accepted = create_identifier_record(accepted_id, "rocket-🚀")
        self.assertEqual(accepted.record_id, accepted_id)
        self.assertEqual(accepted.input_codepoints, 8)
        self.assertEqual(accepted.input_utf8_bytes, 11)
        self.assertEqual(
            create_identifier_record("a.0_-", "safe").record_id,
            "a.0_-",
        )

        invalid_ids: tuple[object, ...] = (
            7,
            "",
            "Upper",
            "7starts-with-digit",
            "space id",
            "non-ascii-é",
            "path/name",
            "colon:name",
            "nul\u0000id",
            "newline\n",
            "a" * (MAX_RECORD_ID_CHARS + 1),
        )
        for record_id in invalid_ids:
            with (
                self.subTest(record_id=record_id),
                self.assertRaisesRegex(ValueError, "^record_id must be bounded"),
            ):
                create_identifier_record(record_id, "safe")  # type: ignore[arg-type]

        with self.assertRaisesRegex(TypeError, "^identifier must be an exact str$"):
            create_identifier_record("valid", object())  # type: ignore[arg-type]
        with self.assertRaises(IdentifierTransformError) as raised:
            create_identifier_record("valid", "\ud800")
        self.assertEqual(
            raised.exception.code,
            TransformErrorCode.INVALID_UNICODE_SCALAR,
        )

    def test_duplicate_ids_and_policies_fail_before_analysis(self) -> None:
        duplicate_ids = records(("same", "first"), ("same", "second"))
        policy = create_policy((TransformStep.NFC,))
        with self.assertRaises(CollisionAnalysisError) as record_error:
            analyze_collisions(duplicate_ids, (policy,))
        self.assertEqual(
            record_error.exception.code,
            CollisionErrorCode.DUPLICATE_RECORD_ID,
        )
        self.assertEqual(record_error.exception.input_record_ordinal, 1)
        self.assertIsNone(record_error.exception.canonical_record_ordinal)

        with self.assertRaises(CollisionAnalysisError) as policy_error:
            analyze_collisions(records(("only", "value")), (policy, policy))
        self.assertEqual(
            policy_error.exception.code,
            CollisionErrorCode.DUPLICATE_POLICY,
        )
        self.assertEqual(policy_error.exception.policy_ordinal, 1)

    def test_analyzer_requires_exact_tuples_and_exact_nested_types(self) -> None:
        record = create_identifier_record("record", "value")
        policy = create_policy((TransformStep.NFC,))
        with self.assertRaisesRegex(TypeError, "^records must be an exact tuple$"):
            analyze_collisions([record], (policy,))  # type: ignore[arg-type]
        with self.assertRaisesRegex(TypeError, "^policies must be an exact tuple$"):
            analyze_collisions((record,), [policy])  # type: ignore[arg-type]

        class RecordSubclass(IdentifierRecord):  # type: ignore[misc]
            pass

        forged_subclass = object.__new__(RecordSubclass)
        for field_name in (
            "record_id",
            "identifier",
            "input_codepoints",
            "input_utf8_bytes",
        ):
            object.__setattr__(forged_subclass, field_name, getattr(record, field_name))
        with self.assertRaises(CollisionAnalysisError) as raised:
            analyze_collisions((forged_subclass,), (policy,))
        self.assertEqual(raised.exception.code, CollisionErrorCode.INVALID_RECORD)

        with self.assertRaises(CollisionAnalysisError) as raised:
            analyze_collisions((record,), (object(),))  # type: ignore[arg-type]
        self.assertEqual(raised.exception.code, CollisionErrorCode.INVALID_POLICY)

    def test_forged_record_state_is_revalidated_without_echoing_values(self) -> None:
        policy = create_policy((TransformStep.NFC,))

        def forged(**fields: object) -> IdentifierRecord:
            value = object.__new__(IdentifierRecord)
            for name, field_value in fields.items():
                object.__setattr__(value, name, field_value)
            return value

        valid = create_identifier_record("valid", "private")

        def changed(**fields: object) -> IdentifierRecord:
            values: dict[str, object] = {
                "record_id": valid.record_id,
                "identifier": valid.identifier,
                "input_codepoints": valid.input_codepoints,
                "input_utf8_bytes": valid.input_utf8_bytes,
            }
            values.update(fields)
            return forged(**values)

        cases = (
            forged(),
            forged(
                record_id="valid",
                identifier="private",
                input_codepoints=7,
            ),
            forged(
                record_id="INVALID",
                identifier="private",
                input_codepoints=7,
                input_utf8_bytes=7,
            ),
            forged(
                record_id="valid",
                identifier=object(),
                input_codepoints=7,
                input_utf8_bytes=7,
            ),
            forged(
                record_id="valid",
                identifier="\ud800",
                input_codepoints=1,
                input_utf8_bytes=3,
            ),
            forged(
                record_id="valid",
                identifier="private",
                input_codepoints=True,
                input_utf8_bytes=7,
            ),
            changed(input_codepoints=8),
            changed(input_utf8_bytes=8),
        )
        for index, record in enumerate(cases):
            with self.subTest(case=index):
                with self.assertRaises(CollisionAnalysisError) as raised:
                    analyze_collisions((record,), (policy,))
                self.assertEqual(
                    raised.exception.code,
                    CollisionErrorCode.INVALID_RECORD,
                )
                self.assertNotIn("private", str(raised.exception))
                self.assertIsNone(raised.exception.__context__)

    def test_forged_policy_state_is_revalidated(self) -> None:
        forged = object.__new__(TransformPolicy)
        object.__setattr__(forged, "steps", ("not-a-step",))
        object.__setattr__(forged, "hazard_handling", HazardHandling.REJECT)
        object.__setattr__(forged, "unicode_version", unicodedata.unidata_version)

        with self.assertRaises(CollisionAnalysisError) as raised:
            analyze_collisions(records(("record", "value")), (forged,))

        self.assertEqual(raised.exception.code, CollisionErrorCode.INVALID_POLICY)
        self.assertEqual(raised.exception.policy_ordinal, 0)
        self.assertIsNone(raised.exception.__context__)

        mismatched = object.__new__(TransformPolicy)
        object.__setattr__(mismatched, "steps", (TransformStep.NFC,))
        object.__setattr__(
            mismatched,
            "hazard_handling",
            HazardHandling.REJECT,
        )
        object.__setattr__(mismatched, "unicode_version", "0.0.0")
        with self.assertRaises(CollisionAnalysisError) as raised:
            analyze_collisions(records(("record", "value")), (mismatched,))
        self.assertEqual(raised.exception.code, CollisionErrorCode.INVALID_POLICY)
        self.assertEqual(raised.exception.policy_ordinal, 0)
        self.assertIsNone(raised.exception.__context__)

    def test_record_policy_and_aggregate_bounds_fail_closed(self) -> None:
        corpus = records(("first", "a"), ("second", "A"))
        policy = (create_policy((TransformStep.LOWER,)),)
        cases = (
            (
                "MAX_ANALYSIS_RECORDS",
                1,
                CollisionErrorCode.RECORD_COUNT,
            ),
            (
                "MAX_ANALYSIS_TOTAL_INPUT_UTF8_BYTES",
                1,
                CollisionErrorCode.TOTAL_INPUT_TOO_LARGE,
            ),
            (
                "MAX_ANALYSIS_TRANSFORM_APPLICATIONS",
                1,
                CollisionErrorCode.TRANSFORM_BUDGET_EXCEEDED,
            ),
            (
                "MAX_ANALYSIS_TRANSFORMED_UTF8_BYTES",
                1,
                CollisionErrorCode.TRANSFORMED_DATA_TOO_LARGE,
            ),
            (
                "MAX_ANALYSIS_POLICY_GROUPS",
                0,
                CollisionErrorCode.OUTPUT_BUDGET_EXCEEDED,
            ),
            (
                "MAX_ANALYSIS_WITNESSES",
                0,
                CollisionErrorCode.OUTPUT_BUDGET_EXCEEDED,
            ),
            (
                "MAX_ANALYSIS_COMPONENTS",
                0,
                CollisionErrorCode.OUTPUT_BUDGET_EXCEEDED,
            ),
        )
        for constant, limit, expected in cases:
            with self.subTest(constant=constant):
                with (
                    patch.object(collision_module, constant, limit),
                    self.assertRaises(CollisionAnalysisError) as raised,
                ):
                    analyze_collisions(corpus, policy)
                self.assertEqual(raised.exception.code, expected)
                if constant == "MAX_ANALYSIS_TOTAL_INPUT_UTF8_BYTES":
                    self.assertEqual(
                        raised.exception.input_record_ordinal,
                        1,
                    )
                    self.assertIsNone(raised.exception.canonical_record_ordinal)
                if constant == "MAX_ANALYSIS_TRANSFORMED_UTF8_BYTES":
                    self.assertEqual(
                        raised.exception.canonical_record_ordinal,
                        1,
                    )
                    self.assertIsNone(raised.exception.input_record_ordinal)

        with (
            patch.object(collision_module, "MAX_ANALYSIS_POLICIES", 0),
            self.assertRaises(CollisionAnalysisError) as raised,
        ):
            analyze_collisions((), policy)
        self.assertEqual(raised.exception.code, CollisionErrorCode.POLICY_COUNT)

        with self.assertRaises(CollisionAnalysisError) as raised:
            analyze_collisions((), ())
        self.assertEqual(raised.exception.code, CollisionErrorCode.POLICY_COUNT)

    def test_all_aggregate_limits_accept_the_exact_accounted_boundary(self) -> None:
        corpus = records(("first", "A"), ("second", "a"))
        policies = (create_policy((TransformStep.LOWER,)),)
        with patch.multiple(
            collision_module,
            MAX_ANALYSIS_RECORDS=2,
            MAX_ANALYSIS_POLICIES=1,
            MAX_ANALYSIS_TOTAL_INPUT_UTF8_BYTES=2,
            MAX_ANALYSIS_TRANSFORM_APPLICATIONS=2,
            MAX_ANALYSIS_TRANSFORMED_UTF8_BYTES=2,
            MAX_ANALYSIS_POLICY_GROUPS=1,
            MAX_ANALYSIS_WITNESSES=1,
            MAX_ANALYSIS_COMPONENTS=1,
        ):
            graph = analyze_collisions(corpus, policies)

        self.assertEqual(graph.record_count, 2)
        self.assertEqual(len(graph.policy_groups), 1)
        self.assertEqual(len(graph.witnesses), 1)
        self.assertEqual(len(graph.components), 1)

    def test_policy_group_and_witness_budgets_are_cumulative(self) -> None:
        corpus = records(("first", "A"), ("second", "a"))
        policies = (
            create_policy((TransformStep.LOWER,)),
            create_policy((TransformStep.CASEFOLD,)),
        )
        for constant in (
            "MAX_ANALYSIS_POLICY_GROUPS",
            "MAX_ANALYSIS_WITNESSES",
        ):
            with self.subTest(constant=constant):
                with (
                    patch.object(collision_module, constant, 1),
                    self.assertRaises(CollisionAnalysisError) as raised,
                ):
                    analyze_collisions(corpus, policies)
                self.assertEqual(
                    raised.exception.code,
                    CollisionErrorCode.OUTPUT_BUDGET_EXCEEDED,
                )

    def test_internal_helpers_fail_closed_on_impossible_state(self) -> None:
        with self.assertRaisesRegex(RuntimeError, "^forced invariant failure$"):
            collision_module._require_internal(
                False,
                "forced invariant failure",
            )

        with self.assertRaisesRegex(TypeError, "^digest must be a SHA-256 object$"):
            collision_module._update_length_prefixed(object(), b"value")
        with self.assertRaisesRegex(TypeError, "^digest must be a SHA-256 object$"):
            collision_module._update_length_prefixed(
                hashlib.sha1(),
                b"value",
            )

        witness = object.__new__(collision_module.CollisionWitness)
        object.__setattr__(witness, "kind", WitnessKind.TRANSFORM_STAGE)
        object.__setattr__(witness, "policy_ordinal", None)
        object.__setattr__(witness, "stage_index", None)
        object.__setattr__(witness, "left_record_ordinal", 0)
        object.__setattr__(witness, "right_record_ordinal", 1)
        with self.assertRaisesRegex(RuntimeError, "lost its policy or stage"):
            collision_module._witness_sort_key(witness)

    def test_exact_duplicate_witness_budget_is_checked_before_policy_work(
        self,
    ) -> None:
        with (
            patch.object(collision_module, "MAX_ANALYSIS_WITNESSES", 0),
            self.assertRaises(CollisionAnalysisError) as raised,
        ):
            analyze_collisions(
                records(("same-a", "same"), ("same-b", "same")),
                (create_policy((TransformStep.NFC,)),),
            )

        self.assertEqual(
            raised.exception.code,
            CollisionErrorCode.OUTPUT_BUDGET_EXCEEDED,
        )


if __name__ == "__main__":
    unittest.main()

from __future__ import annotations

import json
import traceback
import unicodedata
import unittest
from unittest.mock import patch

import casefold_observatory.engine as engine_module
import casefold_observatory.model as model_module
from casefold_observatory import (
    MAX_INPUT_CODEPOINTS,
    MAX_INPUT_UTF8_BYTES,
    MAX_STAGE_CODEPOINTS,
    MAX_STAGE_UTF8_BYTES,
    MAX_UNICODE_VERSION_CHARS,
    HazardHandling,
    HazardKind,
    IdentifierTransformError,
    TransformErrorCode,
    TransformPolicy,
    TransformStep,
    apply_policy,
    canonical_policy_bytes,
    create_policy,
)


class IdentifierSubclass(str):
    pass


class PolicyEvaluationTests(unittest.TestCase):
    def test_lower_and_casefold_have_different_semantics(self) -> None:
        lower = create_policy((TransformStep.LOWER,))
        folded = create_policy((TransformStep.CASEFOLD,))

        lower_result = apply_policy("Straße", lower)
        folded_result = apply_policy("Straße", folded)

        self.assertEqual(lower_result.transformed, "straße")
        self.assertEqual(folded_result.transformed, "strasse")
        self.assertEqual(lower_result.unicode_version, unicodedata.unidata_version)
        self.assertNotEqual(lower.policy_id, folded.policy_id)

    def test_operation_order_is_explicit_and_observable(self) -> None:
        # U+03D2 has a compatibility mapping whose case behavior depends on order.
        normalize_then_fold = create_policy(
            (TransformStep.NFKC, TransformStep.CASEFOLD)
        )
        fold_then_normalize = create_policy(
            (TransformStep.CASEFOLD, TransformStep.NFKC)
        )

        first = apply_policy("\u03d2", normalize_then_fold)
        second = apply_policy("\u03d2", fold_then_normalize)

        self.assertEqual(first.transformed, "\u03c5")
        self.assertEqual(second.transformed, "\u03a5")
        self.assertNotEqual(first.transformed, second.transformed)
        self.assertEqual([stage.stage_index for stage in first.stages], [0, 1])
        self.assertTrue(all(stage.changed for stage in first.stages))

    def test_all_normalization_and_case_steps_are_evaluated(self) -> None:
        cases = (
            (TransformStep.NFC, "e\u0301", "\u00e9"),
            (TransformStep.NFD, "\u00e9", "e\u0301"),
            (TransformStep.NFKC, "\uff2b", "K"),
            (TransformStep.NFKD, "\uff2b", "K"),
            (TransformStep.LOWER, "ABC", "abc"),
            (TransformStep.UPPER, "abc", "ABC"),
            (TransformStep.CASEFOLD, "\u00df", "ss"),
        )
        for step, identifier, expected in cases:
            with self.subTest(step=step):
                result = apply_policy(identifier, create_policy((step,)))
                self.assertEqual(result.transformed, expected)
                self.assertEqual(result.stages[0].after_codepoints, len(expected))

    def test_unchanged_stage_and_result_counts_are_reported(self) -> None:
        result = apply_policy("plain", create_policy((TransformStep.NFC,)))
        self.assertFalse(result.changed)
        self.assertFalse(result.stages[0].changed)
        self.assertEqual(result.input_codepoints, 5)
        self.assertEqual(result.output_codepoints, 5)
        self.assertEqual(result.input_utf8_bytes, 5)
        self.assertEqual(result.output_utf8_bytes, 5)
        self.assertEqual(result.input_hazards, ())
        self.assertEqual(result.output_hazards, ())

    def test_default_policy_rejects_bidi_controls_without_echoing_input(self) -> None:
        identifier = "safe\u202eevil"
        with self.assertRaises(IdentifierTransformError) as raised:
            apply_policy(identifier, create_policy((TransformStep.NFC,)))

        error = raised.exception
        self.assertEqual(error.code, TransformErrorCode.FORBIDDEN_CODE_POINT)
        self.assertEqual(error.codepoint_index, 4)
        self.assertEqual(error.hazard_kind, HazardKind.BIDI_CONTROL)
        self.assertNotIn(identifier, str(error))
        self.assertNotIn("\u202e", str(error))

    def test_every_bidi_control_has_explicit_hazard_classification(self) -> None:
        bidi_controls = (
            "\u061c",
            "\u200e",
            "\u200f",
            "\u202a",
            "\u202b",
            "\u202c",
            "\u202d",
            "\u202e",
            "\u2066",
            "\u2067",
            "\u2068",
            "\u2069",
        )
        identifier = "x" + "".join(bidi_controls) + "\u00ady"
        policy = create_policy(
            (TransformStep.NFC,),
            hazard_handling=HazardHandling.PRESERVE,
        )

        result = apply_policy(identifier, policy)

        self.assertEqual(
            [hazard.kind for hazard in result.input_hazards[:-1]],
            [HazardKind.BIDI_CONTROL] * len(bidi_controls),
        )
        self.assertEqual(
            [hazard.codepoint_index for hazard in result.input_hazards[:-1]],
            list(range(1, len(bidi_controls) + 1)),
        )
        self.assertEqual(result.input_hazards[-1].kind, HazardKind.FORMAT)
        self.assertEqual(
            {hazard.bidi_class for hazard in result.input_hazards[:-1]},
            {
                "AL",
                "L",
                "R",
                "LRE",
                "RLE",
                "PDF",
                "LRO",
                "RLO",
                "LRI",
                "RLI",
                "FSI",
                "PDI",
            },
        )

    def test_explicit_preserve_mode_returns_redacted_hazard_evidence(self) -> None:
        identifier = "a\u0007\u00adb"
        policy = create_policy(
            (TransformStep.NFC,),
            hazard_handling=HazardHandling.PRESERVE,
        )
        result = apply_policy(identifier, policy)

        self.assertEqual(result.transformed, identifier)
        self.assertEqual(
            [hazard.kind for hazard in result.input_hazards],
            [HazardKind.CONTROL, HazardKind.FORMAT],
        )
        self.assertEqual(
            [hazard.codepoint_index for hazard in result.input_hazards],
            [1, 2],
        )
        self.assertNotIn(identifier, repr(result))

    def test_empty_oversized_and_surrogate_inputs_fail_closed(self) -> None:
        policy = create_policy((TransformStep.NFC,))
        cases = (
            ("", TransformErrorCode.EMPTY_IDENTIFIER),
            ("x" * (MAX_INPUT_CODEPOINTS + 1), TransformErrorCode.INPUT_TOO_LARGE),
            ("\ud800", TransformErrorCode.INVALID_UNICODE_SCALAR),
        )
        for identifier, expected_code in cases:
            with self.subTest(code=expected_code):
                with self.assertRaises(IdentifierTransformError) as raised:
                    apply_policy(identifier, policy)
                self.assertEqual(raised.exception.code, expected_code)
                if identifier:
                    self.assertNotIn(identifier, str(raised.exception))

    def test_invalid_scalar_creates_no_library_exception_context(
        self,
    ) -> None:
        identifier = "PRIVATE-NAMESPACE-\ud800-DO-NOT-ECHO"
        with self.assertRaises(IdentifierTransformError) as raised:
            apply_policy(identifier, create_policy((TransformStep.NFC,)))

        error = raised.exception
        rendered = "".join(
            traceback.format_exception(type(error), error, error.__traceback__)
        )
        self.assertEqual(error.code, TransformErrorCode.INVALID_UNICODE_SCALAR)
        self.assertIsNone(error.__context__)
        self.assertIsNone(error.__cause__)
        self.assertNotIn(identifier, str(error))
        self.assertNotIn(repr(identifier), repr(error))
        self.assertNotIn("PRIVATE-NAMESPACE", rendered)
        self.assertNotIn("UnicodeEncodeError", rendered)

    def test_caller_ambient_exception_context_is_not_a_library_boundary(self) -> None:
        ambient_error = RuntimeError("CALLER-CONTROLLED-PAYLOAD")
        try:
            raise ambient_error
        except RuntimeError:
            with self.assertRaises(IdentifierTransformError) as raised:
                apply_policy("\ud800", create_policy((TransformStep.NFC,)))

        error = raised.exception
        rendered = "".join(
            traceback.format_exception(type(error), error, error.__traceback__)
        )
        self.assertIs(error.__context__, ambient_error)
        self.assertIn("CALLER-CONTROLLED-PAYLOAD", rendered)
        self.assertNotIn("UnicodeEncodeError", rendered)

    def test_codepoint_bound_precedes_utf8_validation(self) -> None:
        identifier = "x" * MAX_INPUT_CODEPOINTS + "\ud800"
        with self.assertRaises(IdentifierTransformError) as raised:
            apply_policy(identifier, create_policy((TransformStep.NFC,)))

        self.assertEqual(raised.exception.code, TransformErrorCode.INPUT_TOO_LARGE)
        self.assertIsNone(raised.exception.__context__)

    def test_utf8_byte_bound_is_independent_of_codepoint_bound(self) -> None:
        policy = create_policy((TransformStep.NFC,))
        identifier = "\U0001f680" * (MAX_INPUT_UTF8_BYTES // 4 + 1)
        with self.assertRaises(IdentifierTransformError) as raised:
            apply_policy(identifier, policy)
        self.assertEqual(raised.exception.code, TransformErrorCode.INPUT_TOO_LARGE)

    def test_real_normalization_expansion_hits_codepoint_stage_bound(self) -> None:
        character = "\ufdfa"
        expansion = unicodedata.normalize("NFKD", character)
        repetitions = MAX_STAGE_CODEPOINTS // len(expansion) + 1
        identifier = character * repetitions
        self.assertLessEqual(len(identifier), MAX_INPUT_CODEPOINTS)
        self.assertLessEqual(len(identifier.encode("utf-8")), MAX_INPUT_UTF8_BYTES)
        self.assertGreater(len(expansion * repetitions), MAX_STAGE_CODEPOINTS)
        self.assertLessEqual(
            len((expansion * repetitions).encode("utf-8")),
            MAX_STAGE_UTF8_BYTES,
        )

        with self.assertRaises(IdentifierTransformError) as raised:
            apply_policy(identifier, create_policy((TransformStep.NFKD,)))

        self.assertEqual(raised.exception.code, TransformErrorCode.STAGE_TOO_LARGE)
        self.assertEqual(raised.exception.stage_index, 0)

    def test_real_normalization_expansion_hits_utf8_stage_bound(self) -> None:
        character = "\u3356"
        expansion = unicodedata.normalize("NFKD", character)
        repetitions = MAX_STAGE_UTF8_BYTES // len(expansion.encode("utf-8")) + 1
        identifier = character * repetitions
        expanded = expansion * repetitions
        self.assertLessEqual(len(identifier), MAX_INPUT_CODEPOINTS)
        self.assertLessEqual(len(identifier.encode("utf-8")), MAX_INPUT_UTF8_BYTES)
        self.assertLessEqual(len(expanded), MAX_STAGE_CODEPOINTS)
        self.assertGreater(len(expanded.encode("utf-8")), MAX_STAGE_UTF8_BYTES)

        with self.assertRaises(IdentifierTransformError) as raised:
            apply_policy(identifier, create_policy((TransformStep.NFKD,)))

        self.assertEqual(raised.exception.code, TransformErrorCode.STAGE_TOO_LARGE)
        self.assertEqual(raised.exception.stage_index, 0)

    def test_stage_codepoint_bound_precedes_utf8_validation(self) -> None:
        identifier = "x" * MAX_STAGE_CODEPOINTS + "\ud800"
        with self.assertRaises(IdentifierTransformError) as raised:
            engine_module._enforce_stage_bounds(identifier, stage_index=7)

        self.assertEqual(raised.exception.code, TransformErrorCode.STAGE_TOO_LARGE)
        self.assertEqual(raised.exception.stage_index, 7)
        self.assertIsNone(raised.exception.__context__)

    def test_unknown_internal_step_fails_closed(self) -> None:
        with self.assertRaisesRegex(RuntimeError, "^unsupported transformation step$"):
            engine_module._apply_step("private-value", object())  # type: ignore[arg-type]

    def test_policy_unicode_version_mismatch_is_rejected(self) -> None:
        policy = create_policy((TransformStep.NFC,))
        with (
            patch.object(unicodedata, "unidata_version", "0.0-test"),
            self.assertRaises(IdentifierTransformError) as raised,
        ):
            apply_policy("safe", policy)
        self.assertEqual(
            raised.exception.code,
            TransformErrorCode.POLICY_UNICODE_MISMATCH,
        )

    def test_exact_public_types_are_required(self) -> None:
        policy = create_policy((TransformStep.NFC,))
        with self.assertRaisesRegex(TypeError, "^identifier must be an exact str$"):
            apply_policy(IdentifierSubclass("safe"), policy)
        with self.assertRaisesRegex(TypeError, "^policy must be created"):
            apply_policy("safe", object())  # type: ignore[arg-type]


class CanonicalPolicyTests(unittest.TestCase):
    def test_canonical_policy_is_stable_and_self_describing(self) -> None:
        policy = create_policy(
            (TransformStep.NFKC, TransformStep.CASEFOLD),
            hazard_handling=HazardHandling.PRESERVE,
        )
        payload = canonical_policy_bytes(policy)
        document = json.loads(payload)

        self.assertEqual(payload, canonical_policy_bytes(policy))
        self.assertTrue(payload.endswith(b"\n"))
        self.assertEqual(
            document["schema"],
            "casefold-observatory.transform-policy",
        )
        self.assertEqual(document["schema_version"], 1)
        self.assertEqual(
            document["steps"],
            ["normalize:nfkc", "case:casefold"],
        )
        self.assertEqual(document["unicode_version"], unicodedata.unidata_version)
        self.assertEqual(
            document["bounds"]["max_unicode_version_chars"],
            MAX_UNICODE_VERSION_CHARS,
        )
        self.assertEqual(len(policy.policy_id), 64)

    def test_policy_factory_rejects_impossible_inputs(self) -> None:
        with self.assertRaisesRegex(TypeError, "^steps must be an exact tuple$"):
            create_policy([TransformStep.NFC])  # type: ignore[arg-type]
        for steps in ((), (TransformStep.NFC,) * 9):
            with (
                self.subTest(length=len(steps)),
                self.assertRaisesRegex(ValueError, "^steps must contain"),
            ):
                create_policy(steps)
        with self.assertRaisesRegex(TypeError, "^every step"):
            create_policy(("NFC",))  # type: ignore[arg-type]
        with self.assertRaisesRegex(TypeError, "^hazard_handling"):
            create_policy(
                (TransformStep.NFC,),
                hazard_handling="reject",  # type: ignore[arg-type]
            )

    def test_forged_policy_state_is_revalidated_at_public_boundaries(self) -> None:
        policy = object.__new__(TransformPolicy)
        object.__setattr__(policy, "steps", ("not-a-step",))
        object.__setattr__(policy, "hazard_handling", HazardHandling.REJECT)
        object.__setattr__(policy, "unicode_version", unicodedata.unidata_version)

        with self.assertRaisesRegex(ValueError, "^policy contains invalid steps$"):
            canonical_policy_bytes(policy)
        with self.assertRaisesRegex(ValueError, "^policy contains invalid steps$"):
            apply_policy("safe", policy)

        invalid_states = (
            (None, HazardHandling.REJECT, unicodedata.unidata_version, "steps"),
            ((), HazardHandling.REJECT, unicodedata.unidata_version, "steps"),
            ((TransformStep.NFC,), "reject", unicodedata.unidata_version, "hazard"),
            ((TransformStep.NFC,), HazardHandling.REJECT, None, "Unicode"),
            ((TransformStep.NFC,), HazardHandling.REJECT, "", "Unicode"),
            ((TransformStep.NFC,), HazardHandling.REJECT, "15.01.0", "Unicode"),
            ((TransformStep.NFC,), HazardHandling.REJECT, "not-a-version", "Unicode"),
        )
        for steps, hazard_handling, unicode_version, message in invalid_states:
            with self.subTest(message=message, unicode_version=unicode_version):
                forged = object.__new__(TransformPolicy)
                object.__setattr__(forged, "steps", steps)
                object.__setattr__(forged, "hazard_handling", hazard_handling)
                object.__setattr__(forged, "unicode_version", unicode_version)
                with self.assertRaisesRegex(ValueError, message):
                    canonical_policy_bytes(forged)

        mismatched = object.__new__(TransformPolicy)
        object.__setattr__(mismatched, "steps", (TransformStep.NFC,))
        object.__setattr__(mismatched, "hazard_handling", HazardHandling.REJECT)
        object.__setattr__(mismatched, "unicode_version", "999.0.0")
        with self.assertRaisesRegex(ValueError, "does not match the active runtime"):
            canonical_policy_bytes(mismatched)
        with self.assertRaises(IdentifierTransformError) as raised:
            apply_policy("safe", mismatched)
        self.assertEqual(
            raised.exception.code,
            TransformErrorCode.POLICY_UNICODE_MISMATCH,
        )

    def test_oversized_unicode_version_stops_before_component_scans(self) -> None:
        oversized_version = ("1." * MAX_UNICODE_VERSION_CHARS)[
            : MAX_UNICODE_VERSION_CHARS + 1
        ]
        self.assertEqual(
            len(oversized_version),
            MAX_UNICODE_VERSION_CHARS + 1,
        )
        forged = object.__new__(TransformPolicy)
        object.__setattr__(forged, "steps", (TransformStep.NFC,))
        object.__setattr__(forged, "hazard_handling", HazardHandling.REJECT)
        object.__setattr__(forged, "unicode_version", oversized_version)

        with patch.object(
            model_module,
            "_has_canonical_unicode_version_components",
            side_effect=AssertionError("oversized value reached component scans"),
        ) as component_scan:
            with self.assertRaisesRegex(ValueError, "invalid Unicode version"):
                canonical_policy_bytes(forged)
            with self.assertRaisesRegex(ValueError, "invalid Unicode version"):
                apply_policy("safe", forged)

        component_scan.assert_not_called()


if __name__ == "__main__":
    unittest.main()

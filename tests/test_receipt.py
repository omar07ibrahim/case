from __future__ import annotations

import ast
import copy
import hashlib
import inspect
import json
import os
import subprocess
import sys
import unittest
from collections.abc import Callable
from importlib import metadata
from unittest import mock

import casefold_observatory.corpus as corpus_module
import casefold_observatory.receipt as receipt_module
from casefold_observatory import (
    COLLISION_ALGORITHM,
    CORPUS_FORMAT,
    CORPUS_FORMAT_VERSION,
    DISTRIBUTION_NAME,
    DISTRIBUTION_VERSION,
    MAX_CORPUS_SOURCE_BYTES,
    MAX_RECEIPT_BYTES,
    RECEIPT_SCHEMA,
    RECEIPT_SCHEMA_VERSION,
    CollisionReceipt,
    HazardHandling,
    ReceiptErrorCode,
    ReceiptSource,
    ReceiptVerificationError,
    TransformPolicy,
    TransformStep,
    canonical_policy_bytes,
    canonical_receipt_bytes,
    create_collision_receipt,
    create_policy,
    verify_collision_receipt,
)

_HEADER = b'{"schema":"casefold-observatory.identifier-corpus","schema_version":1}\n'
_SAMPLE_SOURCE = _HEADER + b"".join(
    (
        b'{"identifier":"A\\u0001","record_id":"ctrl-a"}\n',
        b'{"identifier":"a\\u0001","record_id":"ctrl-b"}\n',
        b'{"identifier":"AA","record_id":"exact-a"}\n',
        b'{"identifier":"AA","record_id":"exact-b"}\n',
        b'{"identifier":"aa","record_id":"lower"}\n',
        b'{"identifier":"\\u00df","record_id":"eszett"}\n',
        b'{"identifier":"ss","record_id":"ss"}\n',
    )
)


def _policies() -> tuple[TransformPolicy, ...]:
    return (
        create_policy(
            (TransformStep.LOWER,),
            hazard_handling=HazardHandling.PRESERVE,
        ),
        create_policy(
            (TransformStep.CASEFOLD,),
            hazard_handling=HazardHandling.PRESERVE,
        ),
    )


def _receipt() -> CollisionReceipt:
    return create_collision_receipt(_SAMPLE_SOURCE, _policies())


def _document(receipt: CollisionReceipt | None = None) -> dict[str, object]:
    value: object = json.loads(canonical_receipt_bytes(receipt or _receipt()))
    if type(value) is not dict:
        raise AssertionError("receipt document must be an object")
    return value


def _encoded(document: object) -> bytes:
    return receipt_module._canonical_json(document)


def _expect_failure(
    testcase: unittest.TestCase,
    call: Callable[[], object],
    code: ReceiptErrorCode = ReceiptErrorCode.INVALID_RECEIPT,
) -> ReceiptVerificationError:
    with testcase.assertRaises(ReceiptVerificationError) as caught:
        call()
    testcase.assertIs(caught.exception.code, code)
    testcase.assertNotIn("private-value", str(caught.exception))
    return caught.exception


def _verify_document(
    testcase: unittest.TestCase,
    document: object,
    code: ReceiptErrorCode,
    *,
    source: bytes = _SAMPLE_SOURCE,
) -> ReceiptVerificationError:
    return _expect_failure(
        testcase,
        lambda: verify_collision_receipt(_encoded(document), source),
        code,
    )


class ReceiptPublicApiTests(unittest.TestCase):
    def test_contract_identity_and_round_trip(self) -> None:
        receipt = _receipt()
        encoded = canonical_receipt_bytes(receipt)
        verified = verify_collision_receipt(encoded, _SAMPLE_SOURCE)
        self.assertEqual(canonical_receipt_bytes(verified), encoded)
        self.assertEqual(RECEIPT_SCHEMA, "casefold-observatory.analysis-receipt")
        self.assertEqual(RECEIPT_SCHEMA_VERSION, 1)
        self.assertEqual(DISTRIBUTION_NAME, "casefold-observatory")
        self.assertEqual(DISTRIBUTION_VERSION, "0.3.0")
        self.assertEqual(CORPUS_FORMAT_VERSION, 1)
        self.assertEqual(MAX_RECEIPT_BYTES, 16_777_216)
        self.assertEqual(receipt.schema, RECEIPT_SCHEMA)
        self.assertEqual(receipt.producer_distribution, DISTRIBUTION_NAME)
        self.assertEqual(receipt.graph.algorithm, COLLISION_ALGORITHM)
        self.assertEqual(metadata.version(DISTRIBUTION_NAME), DISTRIBUTION_VERSION)

    def test_complete_projection_source_and_semantic_digests(self) -> None:
        receipt = _receipt()
        document = _document(receipt)
        self.assertEqual(
            set(document),
            {"graph", "policies", "producer", "schema", "schema_version", "source"},
        )
        source = document["source"]
        graph = document["graph"]
        policies = document["policies"]
        self.assertIs(type(source), dict)
        self.assertIs(type(graph), dict)
        self.assertIs(type(policies), list)
        typed_source = source
        typed_graph = graph
        typed_policies = policies
        assert isinstance(typed_source, dict)
        assert isinstance(typed_graph, dict)
        assert isinstance(typed_policies, list)
        self.assertEqual(typed_source["byte_count"], len(_SAMPLE_SOURCE))
        self.assertEqual(typed_source["format"], CORPUS_FORMAT)
        self.assertEqual(
            typed_source["sha256"],
            hashlib.sha256(_SAMPLE_SOURCE).hexdigest(),
        )
        self.assertNotEqual(
            typed_source["sha256"],
            typed_graph["semantic_corpus_sha256"],
        )
        self.assertEqual(
            set(typed_graph),
            receipt_module._GRAPH_KEYS,
        )
        self.assertTrue(typed_graph["duplicate_groups"])
        self.assertTrue(typed_graph["policy_groups"])
        self.assertTrue(typed_graph["witnesses"])
        self.assertTrue(typed_graph["components"])
        self.assertEqual(
            [entry["document"] for entry in typed_policies],
            [json.loads(canonical_policy_bytes(policy)) for policy in receipt.policies],
        )
        self.assertEqual(
            [entry["policy_id"] for entry in typed_policies],
            list(receipt.graph.policy_ids),
        )

    def test_canonical_ascii_lf_and_control_escaping(self) -> None:
        encoded = canonical_receipt_bytes(_receipt())
        self.assertTrue(encoded.endswith(b"\n"))
        self.assertFalse(encoded.endswith(b"\n\n"))
        encoded.decode("ascii", errors="strict")
        self.assertNotIn(b"\x01", encoded)
        self.assertIn(b"\\u0001", encoded)
        self.assertEqual(encoded, _encoded(json.loads(encoded)))
        self.assertNotIn(b": ", encoded)
        self.assertNotIn(b", ", encoded)

    def test_source_representation_digest_is_separate_from_semantics(self) -> None:
        policies = _policies()
        lf = create_collision_receipt(_SAMPLE_SOURCE, policies)
        crlf_source = _SAMPLE_SOURCE.replace(b"\n", b"\r\n")
        crlf = create_collision_receipt(crlf_source, policies)
        lines = _SAMPLE_SOURCE.splitlines()
        reordered_source = b"\n".join((lines[0], *reversed(lines[1:]))) + b"\n"
        reordered = create_collision_receipt(reordered_source, policies)
        self.assertNotEqual(lf.source.sha256, crlf.source.sha256)
        self.assertNotEqual(lf.source.sha256, reordered.source.sha256)
        self.assertEqual(
            lf.graph.semantic_corpus_sha256,
            crlf.graph.semantic_corpus_sha256,
        )
        self.assertEqual(
            lf.graph.semantic_corpus_sha256,
            reordered.graph.semantic_corpus_sha256,
        )
        self.assertEqual(
            receipt_module._graph_document(lf.graph),
            receipt_module._graph_document(reordered.graph),
        )

    def test_factory_only_frozen_models_and_safe_repr(self) -> None:
        for model in (ReceiptSource, CollisionReceipt):
            with (
                self.subTest(model=model.__name__),
                self.assertRaisesRegex(TypeError, "created by"),
            ):
                model()
        receipt = _receipt()
        with self.assertRaises((AttributeError, TypeError)):
            receipt.schema = "private-value"  # type: ignore[misc]
        self.assertNotIn("ctrl-a", repr(receipt))
        self.assertNotIn(receipt.source.sha256, repr(receipt.source))

    def test_runtime_modules_have_no_filesystem_or_process_imports(self) -> None:
        forbidden = {"open", "os", "pathlib", "socket", "subprocess"}
        for module in (corpus_module, receipt_module):
            tree = ast.parse(inspect.getsource(module))
            imported: set[str] = set()
            called: set[str] = set()
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    imported.update(alias.name.split(".")[0] for alias in node.names)
                elif isinstance(node, ast.ImportFrom) and node.module:
                    imported.add(node.module.split(".")[0])
                elif isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
                    called.add(node.func.id)
            with self.subTest(module=module.__name__):
                self.assertTrue(forbidden.isdisjoint(imported | called))


class ReceiptVerificationBoundaryTests(unittest.TestCase):
    def test_exact_byte_types_and_receipt_size_boundary(self) -> None:
        encoded = canonical_receipt_bytes(_receipt())
        for receipt_value, source_value in (
            (bytearray(encoded), _SAMPLE_SOURCE),
            (encoded, bytearray(_SAMPLE_SOURCE)),
        ):
            with (
                self.subTest(receipt_type=type(receipt_value).__name__),
                self.assertRaisesRegex(TypeError, "exact bytes"),
            ):
                verify_collision_receipt(  # type: ignore[arg-type]
                    receipt_value,
                    source_value,
                )

        exact = b"0" + b" " * (MAX_RECEIPT_BYTES - 1)
        _expect_failure(
            self,
            lambda: verify_collision_receipt(exact, _SAMPLE_SOURCE),
            ReceiptErrorCode.NONCANONICAL_RECEIPT,
        )
        _expect_failure(
            self,
            lambda: verify_collision_receipt(exact + b" ", _SAMPLE_SOURCE),
            ReceiptErrorCode.RECEIPT_TOO_LARGE,
        )

    def test_json_and_canonical_rejections(self) -> None:
        encoded = canonical_receipt_bytes(_receipt())
        cases = (
            (b"{", ReceiptErrorCode.INVALID_JSON),
            (b'{"x":NaN}\n', ReceiptErrorCode.INVALID_JSON),
            (b'{"x":1,"x":2}\n', ReceiptErrorCode.DUPLICATE_KEY),
            (b"[" * 17 + b"]" * 17 + b"\n", ReceiptErrorCode.JSON_DEPTH),
            (b'{"x":"\xff"}\n', ReceiptErrorCode.INVALID_JSON),
            (b"true\n", ReceiptErrorCode.SCHEMA_MISMATCH),
            (b"1.0\n", ReceiptErrorCode.SCHEMA_MISMATCH),
            (encoded[:-1], ReceiptErrorCode.NONCANONICAL_RECEIPT),
            (b" " + encoded, ReceiptErrorCode.NONCANONICAL_RECEIPT),
        )
        for value, code in cases:
            with self.subTest(code=code, prefix=value[:12]):
                error = _expect_failure(
                    self,
                    lambda value=value: verify_collision_receipt(
                        value,
                        _SAMPLE_SOURCE,
                    ),
                    code,
                )
                self.assertTrue(error.__suppress_context__)

    def test_top_level_schema_and_producer_rejections(self) -> None:
        mutations: tuple[
            tuple[Callable[[dict[str, object]], None], ReceiptErrorCode],
            ...,
        ] = (
            (lambda doc: doc.pop("source"), ReceiptErrorCode.SCHEMA_MISMATCH),
            (
                lambda doc: doc.update(schema="private-value"),
                ReceiptErrorCode.SCHEMA_MISMATCH,
            ),
            (
                lambda doc: doc.update(schema_version=True),
                ReceiptErrorCode.SCHEMA_MISMATCH,
            ),
            (lambda doc: doc.update(producer=[]), ReceiptErrorCode.SCHEMA_MISMATCH),
            (
                lambda doc: doc.__setitem__(
                    "producer",
                    {"distribution": DISTRIBUTION_NAME},
                ),
                ReceiptErrorCode.SCHEMA_MISMATCH,
            ),
            (
                lambda doc: doc.__setitem__(
                    "producer",
                    {"distribution": "private-value", "version": DISTRIBUTION_VERSION},
                ),
                ReceiptErrorCode.PRODUCER_MISMATCH,
            ),
            (
                lambda doc: doc.__setitem__(
                    "producer",
                    {"distribution": DISTRIBUTION_NAME, "version": 3},
                ),
                ReceiptErrorCode.PRODUCER_MISMATCH,
            ),
        )
        for mutate, code in mutations:
            document = _document()
            mutate(document)
            with self.subTest(code=code):
                _verify_document(self, document, code)

    def test_source_identity_rejections_use_constant_time_digest(self) -> None:
        base = _document()
        source_value = base["source"]
        assert isinstance(source_value, dict)
        mutations: tuple[tuple[str, object, ReceiptErrorCode], ...] = (
            ("format", "private-value", ReceiptErrorCode.SCHEMA_MISMATCH),
            ("format_version", True, ReceiptErrorCode.SCHEMA_MISMATCH),
            ("byte_count", -1, ReceiptErrorCode.SCHEMA_MISMATCH),
            ("sha256", "x" * 64, ReceiptErrorCode.SCHEMA_MISMATCH),
            ("byte_count", len(_SAMPLE_SOURCE) + 1, ReceiptErrorCode.SOURCE_MISMATCH),
            ("sha256", "0" * 64, ReceiptErrorCode.SOURCE_MISMATCH),
        )
        for key, value, code in mutations:
            document = copy.deepcopy(base)
            source = document["source"]
            assert isinstance(source, dict)
            source[key] = value
            with self.subTest(key=key, value=value):
                _verify_document(self, document, code)

        document = copy.deepcopy(base)
        document["source"] = []
        _verify_document(self, document, ReceiptErrorCode.SCHEMA_MISMATCH)
        document = copy.deepcopy(base)
        document["source"] = {
            "byte_count": len(_SAMPLE_SOURCE),
            "format": CORPUS_FORMAT,
            "format_version": CORPUS_FORMAT_VERSION,
        }
        _verify_document(self, document, ReceiptErrorCode.SCHEMA_MISMATCH)

        oversized = b"x" * (MAX_CORPUS_SOURCE_BYTES + 1)
        document = copy.deepcopy(base)
        document["source"] = {
            "byte_count": len(oversized),
            "format": CORPUS_FORMAT,
            "format_version": CORPUS_FORMAT_VERSION,
            "sha256": hashlib.sha256(oversized).hexdigest(),
        }
        _verify_document(
            self,
            document,
            ReceiptErrorCode.SOURCE_MISMATCH,
            source=oversized,
        )

    def test_policy_reconstruction_rejects_every_untrusted_surface(self) -> None:
        def mutate_policy(
            document: dict[str, object],
            ordinal: int,
        ) -> tuple[dict[str, object], dict[str, object]]:
            entries = document["policies"]
            assert isinstance(entries, list)
            entry = entries[ordinal]
            assert isinstance(entry, dict)
            policy_document = entry["document"]
            assert isinstance(policy_document, dict)
            return entry, policy_document

        mutations: tuple[
            tuple[Callable[[dict[str, object]], None], ReceiptErrorCode],
            ...,
        ] = (
            (lambda doc: doc.update(policies={}), ReceiptErrorCode.SCHEMA_MISMATCH),
            (lambda doc: doc.update(policies=[]), ReceiptErrorCode.POLICY_MISMATCH),
            (
                lambda doc: doc.update(policies=[None]),
                ReceiptErrorCode.POLICY_MISMATCH,
            ),
            (
                lambda doc: doc.update(policies=[{"document": {}}]),
                ReceiptErrorCode.POLICY_MISMATCH,
            ),
            (
                lambda doc: mutate_policy(doc, 0)[0].update(document=[]),
                ReceiptErrorCode.POLICY_MISMATCH,
            ),
            (
                lambda doc: mutate_policy(doc, 0)[1].pop("bounds"),
                ReceiptErrorCode.POLICY_MISMATCH,
            ),
            (
                lambda doc: mutate_policy(doc, 0)[1].update(
                    unicode_version="private-value"
                ),
                ReceiptErrorCode.UNICODE_MISMATCH,
            ),
            (
                lambda doc: mutate_policy(doc, 0)[1].update(steps={}),
                ReceiptErrorCode.POLICY_MISMATCH,
            ),
            (
                lambda doc: mutate_policy(doc, 0)[1].update(steps=[]),
                ReceiptErrorCode.POLICY_MISMATCH,
            ),
            (
                lambda doc: mutate_policy(doc, 0)[1].update(steps=[1]),
                ReceiptErrorCode.POLICY_MISMATCH,
            ),
            (
                lambda doc: mutate_policy(doc, 0)[1].update(hazard_handling=1),
                ReceiptErrorCode.POLICY_MISMATCH,
            ),
            (
                lambda doc: mutate_policy(doc, 0)[1].update(
                    hazard_handling="private-value"
                ),
                ReceiptErrorCode.POLICY_MISMATCH,
            ),
            (
                lambda doc: mutate_policy(doc, 0)[1].update(
                    bounds={"private-value": 1}
                ),
                ReceiptErrorCode.POLICY_MISMATCH,
            ),
            (
                lambda doc: mutate_policy(doc, 0)[0].update(policy_id="x"),
                ReceiptErrorCode.POLICY_MISMATCH,
            ),
            (
                lambda doc: mutate_policy(doc, 0)[0].update(policy_id="0" * 64),
                ReceiptErrorCode.POLICY_MISMATCH,
            ),
            (
                lambda doc: doc.__setitem__(
                    "policies",
                    [copy.deepcopy(doc["policies"][0])] * 2,  # type: ignore[index]
                ),
                ReceiptErrorCode.POLICY_MISMATCH,
            ),
        )
        for mutate, code in mutations:
            document = _document()
            mutate(document)
            with self.subTest(code=code, mutation=mutate):
                error = _verify_document(self, document, code)
                if error.policy_ordinal is not None:
                    self.assertGreaterEqual(error.policy_ordinal, 0)

        too_many = _document()
        entries = too_many["policies"]
        assert isinstance(entries, list)
        too_many["policies"] = [copy.deepcopy(entries[0]) for _ in range(9)]
        _verify_document(self, too_many, ReceiptErrorCode.POLICY_MISMATCH)

    def test_algorithm_unicode_policy_and_graph_tampering(self) -> None:
        mutations: tuple[tuple[str, object, ReceiptErrorCode], ...] = (
            ("algorithm", "private-value", ReceiptErrorCode.ALGORITHM_MISMATCH),
            ("unicode_version", "private-value", ReceiptErrorCode.UNICODE_MISMATCH),
            ("policy_ids", {}, ReceiptErrorCode.SCHEMA_MISMATCH),
            ("policy_ids", [], ReceiptErrorCode.POLICY_MISMATCH),
            ("semantic_corpus_sha256", "0" * 64, ReceiptErrorCode.GRAPH_MISMATCH),
            ("record_ids", [], ReceiptErrorCode.GRAPH_MISMATCH),
            ("components", [], ReceiptErrorCode.GRAPH_MISMATCH),
        )
        for key, value, code in mutations:
            document = _document()
            graph = document["graph"]
            assert isinstance(graph, dict)
            graph[key] = value
            with self.subTest(key=key):
                _verify_document(self, document, code)

        document = _document()
        document["graph"] = []
        _verify_document(self, document, ReceiptErrorCode.SCHEMA_MISMATCH)
        document = _document()
        graph = document["graph"]
        assert isinstance(graph, dict)
        graph.pop("witnesses")
        _verify_document(self, document, ReceiptErrorCode.SCHEMA_MISMATCH)

    def test_replay_maps_invalid_source_and_analysis_to_graph_mismatch(self) -> None:
        malformed = _HEADER + b"{\n"
        document = _document()
        source = document["source"]
        assert isinstance(source, dict)
        source["byte_count"] = len(malformed)
        source["sha256"] = hashlib.sha256(malformed).hexdigest()
        _verify_document(
            self,
            document,
            ReceiptErrorCode.GRAPH_MISMATCH,
            source=malformed,
        )

        large_identifier = "x" * 2_048
        records = [
            json.dumps(
                {"identifier": large_identifier, "record_id": f"r{index:03d}"},
                separators=(",", ":"),
            ).encode("ascii")
            for index in range(257)
        ]
        over_budget = _HEADER + b"\n".join(records) + b"\n"
        document = _document()
        source = document["source"]
        assert isinstance(source, dict)
        source["byte_count"] = len(over_budget)
        source["sha256"] = hashlib.sha256(over_budget).hexdigest()
        _verify_document(
            self,
            document,
            ReceiptErrorCode.GRAPH_MISMATCH,
            source=over_budget,
        )


class ReceiptForgedStateTests(unittest.TestCase):
    def test_receipt_and_source_state_are_revalidated(self) -> None:
        cases: tuple[tuple[str, str, object], ...] = (
            ("receipt", "schema", "private-value"),
            ("receipt", "schema_version", True),
            ("receipt", "producer_distribution", "private-value"),
            ("receipt", "producer_version", "private-value"),
            ("receipt", "policies", ()),
            ("source", "format", "private-value"),
            ("source", "format_version", True),
            ("source", "byte_count", -1),
            ("source", "sha256", "private-value"),
            ("receipt", "_document_sha256", "0" * 64),
        )
        for owner, attribute, value in cases:
            receipt = _receipt()
            target = receipt if owner == "receipt" else receipt.source
            object.__setattr__(target, attribute, value)
            with self.subTest(owner=owner, attribute=attribute):
                _expect_failure(
                    self,
                    lambda receipt=receipt: canonical_receipt_bytes(receipt),
                )

        forged = object.__new__(CollisionReceipt)
        _expect_failure(self, lambda: canonical_receipt_bytes(forged))
        _expect_failure(
            self,
            lambda: canonical_receipt_bytes("private-value"),  # type: ignore[arg-type]
        )

    def test_graph_projection_revalidates_nested_model_state(self) -> None:
        def invalid_graph(attribute: str, value: object) -> None:
            graph = _receipt().graph
            object.__setattr__(graph, attribute, value)
            _expect_failure(self, lambda: receipt_module._graph_document(graph))

        graph_cases = (
            ("algorithm", "private-value"),
            ("unicode_version", "private-value"),
            ("semantic_corpus_sha256", "private-value"),
            ("record_ids", ["wrong-container"]),
            ("record_ids", ("Upper",)),
            ("record_ids", ("z", "a")),
            ("policy_ids", ()),
            ("policy_ids", ("0" * 64, "0" * 64)),
            ("policy_ids", ("private-value",)),
            ("duplicate_groups", []),
            ("policy_groups", []),
            ("witnesses", []),
            ("components", []),
            ("isolated_record_ordinals", []),
        )
        for attribute, value in graph_cases:
            with self.subTest(attribute=attribute, value=value):
                invalid_graph(attribute, value)

    def test_group_witness_and_component_validators_fail_closed(self) -> None:
        receipt = _receipt()
        graph = receipt.graph
        duplicate = graph.duplicate_groups[0]
        policy_group = graph.policy_groups[0]
        exact_witness = next(
            witness for witness in graph.witnesses if witness.policy_ordinal is None
        )
        transform_witness = next(
            witness for witness in graph.witnesses if witness.policy_ordinal is not None
        )
        component = graph.components[0]
        record_count = graph.record_count
        policy_ids = graph.policy_ids

        _expect_failure(
            self,
            lambda: receipt_module._duplicate_group_document(
                "private-value",  # type: ignore[arg-type]
                record_count=record_count,
            ),
        )
        for attribute, value in (
            ("group_id", 1),
            ("member_record_ordinals", (0,)),
            ("witness_ids", ()),
        ):
            fresh = _receipt().graph.duplicate_groups[0]
            object.__setattr__(fresh, attribute, value)
            _expect_failure(
                self,
                lambda fresh=fresh: receipt_module._duplicate_group_document(
                    fresh,
                    record_count=record_count,
                ),
            )

        _expect_failure(
            self,
            lambda: receipt_module._policy_group_document(
                "private-value",  # type: ignore[arg-type]
                record_count=record_count,
                policy_ids=policy_ids,
            ),
        )
        for attribute, value in (
            ("policy_ordinal", -1),
            ("policy_id", "0" * 64),
            ("transformed", 1),
            ("output_codepoints", -1),
            ("output_utf8_bytes", -1),
            ("member_record_ordinals", (0,)),
            ("witness_ids", ()),
        ):
            fresh = _receipt().graph.policy_groups[0]
            object.__setattr__(fresh, attribute, value)
            _expect_failure(
                self,
                lambda fresh=fresh: receipt_module._policy_group_document(
                    fresh,
                    record_count=record_count,
                    policy_ids=policy_ids,
                ),
            )

        _expect_failure(
            self,
            lambda: receipt_module._witness_document(
                "private-value",  # type: ignore[arg-type]
                record_count=record_count,
                policy_ids=policy_ids,
            ),
        )
        witness_cases = (
            (exact_witness, "left_record_ordinal", -1),
            (exact_witness, "kind", "private-value"),
            (exact_witness, "policy_ordinal", 0),
            (transform_witness, "policy_ordinal", None),
            (transform_witness, "policy_ordinal", 99),
            (transform_witness, "policy_id", "0" * 64),
            (transform_witness, "stage_index", -1),
            (transform_witness, "step", None),
        )
        for original, attribute, value in witness_cases:
            fresh_receipt = _receipt()
            candidates = (
                witness
                for witness in fresh_receipt.graph.witnesses
                if (witness.policy_ordinal is None) == (original.policy_ordinal is None)
            )
            fresh = next(candidates)
            object.__setattr__(fresh, attribute, value)
            _expect_failure(
                self,
                lambda fresh=fresh: receipt_module._witness_document(
                    fresh,
                    record_count=record_count,
                    policy_ids=policy_ids,
                ),
            )

        _expect_failure(
            self,
            lambda: receipt_module._component_document(
                "private-value",  # type: ignore[arg-type]
                record_count=record_count,
                policy_count=len(policy_ids),
            ),
        )
        for attribute, value in (
            ("member_record_ordinals", (0,)),
            ("witness_tree_ids", ()),
            ("policy_ordinals", (99,)),
        ):
            fresh = _receipt().graph.components[0]
            object.__setattr__(fresh, attribute, value)
            _expect_failure(
                self,
                lambda fresh=fresh: receipt_module._component_document(
                    fresh,
                    record_count=record_count,
                    policy_count=len(policy_ids),
                ),
            )

        self.assertEqual(duplicate.group_id, "dg_0000")
        self.assertGreaterEqual(policy_group.output_utf8_bytes, 1)
        self.assertTrue(component.component_id.startswith("gc_"))

    def test_internal_exact_type_and_schema_helpers(self) -> None:
        invalid_calls: tuple[Callable[[], object], ...] = (
            lambda: receipt_module._string(1),
            lambda: receipt_module._integer(True),
            lambda: receipt_module._optional_integer("x"),
            lambda: receipt_module._optional_string(1),
            lambda: receipt_module._exact_tuple([]),
            lambda: receipt_module._string_tuple(("ok", 1)),
            lambda: receipt_module._ordinal_tuple(
                (0, 0),
                record_count=2,
            ),
            lambda: receipt_module._ordinal_tuple(
                (2,),
                record_count=2,
            ),
            lambda: receipt_module._ordinal_tuple(
                (),
                record_count=2,
                minimum_length=1,
            ),
        )
        for call in invalid_calls:
            with self.subTest(call=call):
                _expect_failure(self, call)

        schema_calls: tuple[Callable[[], object], ...] = (
            lambda: receipt_module._schema_object([]),
            lambda: receipt_module._schema_list({}),
            lambda: receipt_module._schema_keys({}, {"required"}),
        )
        for call in schema_calls:
            with self.subTest(schema_call=call):
                _expect_failure(
                    self,
                    call,
                    ReceiptErrorCode.SCHEMA_MISMATCH,
                )

        self.assertEqual(receipt_module._string("x"), "x")
        self.assertEqual(receipt_module._integer(1), 1)
        self.assertIsNone(receipt_module._optional_integer(None))
        self.assertEqual(receipt_module._optional_integer(1), 1)
        self.assertIsNone(receipt_module._optional_string(None))
        self.assertEqual(receipt_module._optional_string("x"), "x")
        self.assertEqual(receipt_module._exact_tuple(()), ())
        self.assertEqual(receipt_module._string_tuple(("x",)), ("x",))
        self.assertEqual(
            receipt_module._ordinal_tuple((0, 1), record_count=2),
            (0, 1),
        )
        self.assertTrue(receipt_module._is_digest("0" * 64))
        self.assertFalse(receipt_module._is_digest(0))

    def test_recursive_json_type_validator_and_error_mapping(self) -> None:
        valid = (None, "x", 1, [None, {"x": [1]}], {"x": "y"})
        invalid = (True, 1.0, [object()], {1: "x"}, {"x": object()})
        for value in valid:
            with self.subTest(value=value):
                self.assertTrue(receipt_module._valid_receipt_json_types(value))
        for value in invalid:
            with self.subTest(value=type(value).__name__):
                self.assertFalse(receipt_module._valid_receipt_json_types(value))

        mapping = {
            corpus_module._JsonIssue.JSON_DEPTH: ReceiptErrorCode.JSON_DEPTH,
            corpus_module._JsonIssue.DUPLICATE_KEY: ReceiptErrorCode.DUPLICATE_KEY,
            corpus_module._JsonIssue.INVALID_JSON: ReceiptErrorCode.INVALID_JSON,
            corpus_module._JsonIssue.INVALID_ENCODING: ReceiptErrorCode.INVALID_JSON,
        }
        for issue, code in mapping.items():
            self.assertIs(receipt_module._receipt_json_code(issue), code)

    def test_checked_size_policy_document_and_seal_failures(self) -> None:
        receipt = _receipt()
        with mock.patch.object(receipt_module, "MAX_RECEIPT_BYTES", 1):
            _expect_failure(
                self,
                lambda: receipt_module._checked_receipt_bytes(
                    receipt,
                    require_seal=False,
                ),
                ReceiptErrorCode.RECEIPT_TOO_LARGE,
            )

        policy = receipt.policies[0]
        with mock.patch.object(
            receipt_module,
            "canonical_policy_bytes",
            side_effect=ValueError("private-value"),
        ):
            _expect_failure(
                self,
                lambda: receipt_module._policy_document(policy),
            )

        source = receipt.source
        self.assertEqual(
            receipt_module._source_document(source)["sha256"],
            source.sha256,
        )


class ReceiptHashSeedTests(unittest.TestCase):
    def test_hashseed_does_not_change_canonical_receipt(self) -> None:
        script = (
            "import hashlib;"
            "from casefold_observatory import *;"
            f"s={_SAMPLE_SOURCE!r};"
            "p=(create_policy((TransformStep.LOWER,),"
            "hazard_handling=HazardHandling.PRESERVE),"
            "create_policy((TransformStep.CASEFOLD,),"
            "hazard_handling=HazardHandling.PRESERVE));"
            "print(hashlib.sha256(canonical_receipt_bytes("
            "create_collision_receipt(s,p))).hexdigest())"
        )
        digests: list[str] = []
        for seed in ("1", "7", "123"):
            environment = os.environ.copy()
            environment["PYTHONHASHSEED"] = seed
            completed = subprocess.run(
                [sys.executable, "-c", script],
                check=True,
                capture_output=True,
                text=True,
                env=environment,
            )
            digests.append(completed.stdout.strip())
        self.assertEqual(len(set(digests)), 1)


if __name__ == "__main__":
    unittest.main()

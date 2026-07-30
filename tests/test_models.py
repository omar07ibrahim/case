from __future__ import annotations

import unittest

from casefold_observatory import (
    CollisionGraph,
    CollisionWitness,
    ExactDuplicateGroup,
    GlobalCollisionComponent,
    HazardEvidence,
    IdentifierRecord,
    PolicyCollisionGroup,
    TransformPolicy,
    TransformResult,
    TransformStageEvidence,
)


class ConstructionBoundaryTests(unittest.TestCase):
    def test_derived_model_constructors_are_blocked(self) -> None:
        cases = (
            (TransformPolicy, "TransformPolicy objects"),
            (HazardEvidence, "HazardEvidence objects"),
            (TransformStageEvidence, "TransformStageEvidence objects"),
            (TransformResult, "TransformResult objects"),
            (IdentifierRecord, "IdentifierRecord objects"),
            (ExactDuplicateGroup, "ExactDuplicateGroup objects"),
            (CollisionWitness, "CollisionWitness objects"),
            (PolicyCollisionGroup, "PolicyCollisionGroup objects"),
            (GlobalCollisionComponent, "GlobalCollisionComponent objects"),
            (CollisionGraph, "CollisionGraph objects"),
        )
        for model, message in cases:
            with (
                self.subTest(model=model.__name__),
                self.assertRaisesRegex(TypeError, f"^{message}"),
            ):
                model()


if __name__ == "__main__":
    unittest.main()

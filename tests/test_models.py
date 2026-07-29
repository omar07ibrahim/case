from __future__ import annotations

import unittest

from casefold_observatory import (
    HazardEvidence,
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
        )
        for model, message in cases:
            with (
                self.subTest(model=model.__name__),
                self.assertRaisesRegex(TypeError, f"^{message}"),
            ):
                model()


if __name__ == "__main__":
    unittest.main()

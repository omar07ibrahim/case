from __future__ import annotations

import unittest
from importlib import metadata, resources

from casefold_observatory import DISTRIBUTION_NAME, DISTRIBUTION_VERSION


class PackagingContractTests(unittest.TestCase):
    def test_pep561_marker_is_packaged(self) -> None:
        marker = resources.files("casefold_observatory").joinpath("py.typed")
        self.assertTrue(marker.is_file())
        self.assertIn(marker.read_bytes(), (b"", b"\n"))

    def test_runtime_identity_matches_distribution_metadata(self) -> None:
        self.assertEqual(metadata.version(DISTRIBUTION_NAME), DISTRIBUTION_VERSION)


if __name__ == "__main__":
    unittest.main()

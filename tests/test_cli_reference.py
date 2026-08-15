# SPDX-License-Identifier: 0BSD
"""Ensure the committed CLI reference doc matches the live argparse definition."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
_SCRIPTS = ROOT / "scripts"
if str(_SCRIPTS) not in sys.path:
    sys.path.insert(0, str(_SCRIPTS))

from generate_cli_reference import _OUTPUT_PATH, render  # noqa: E402


class CliReferenceTests(unittest.TestCase):
    @unittest.skipUnless(
        sys.version_info[:2] == (3, 14),
        "argparse help formatting differs across Python versions; "
        "the committed reference is generated from Python 3.14",
    )
    def test_generated_reference_matches_committed_doc(self) -> None:
        self.assertTrue(_OUTPUT_PATH.exists(), f"{_OUTPUT_PATH} is missing; run the generator")
        committed = _OUTPUT_PATH.read_text(encoding="utf-8")
        self.assertEqual(
            committed,
            render(),
            "docs/cli-reference.md is stale; run "
            "'python scripts/generate_cli_reference.py' and commit the result",
        )


if __name__ == "__main__":
    unittest.main()

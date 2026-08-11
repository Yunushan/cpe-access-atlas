# SPDX-License-Identifier: 0BSD
from __future__ import annotations

import unittest

from cpe_access_atlas.catalog import find_recipe
from cpe_access_atlas.report import build_research_template


class ReportTests(unittest.TestCase):
    def test_template_names_exact_target_and_warns_about_secrets(self) -> None:
        recipe = find_recipe(
            "turk-telekom",
            "H3600P",
            "V9.0",
            "H3600P V9.0 TTN.10_260210",
        )
        content = build_research_template(recipe)
        self.assertIn(recipe.id, content)
        self.assertIn(recipe.firmware, content)
        self.assertIn("Hardware revision verification: unresolved", content)
        self.assertIn("Do not paste passwords", content)
        self.assertIn("No configuration backup is attached", content)


if __name__ == "__main__":
    unittest.main()

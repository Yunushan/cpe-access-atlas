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
        self.assertIn("Local IPv4 Remote Access baseline", content)
        self.assertIn("Local IPv4 Remote Access post-change", content)
        self.assertIn("Local INTERNET WAN firewall baseline", content)
        self.assertIn("Local INTERNET WAN firewall post-change", content)
        self.assertIn("External baseline management reachability", content)
        self.assertIn("External post-change management reachability", content)
        self.assertIn("Separate external test evidence URL", content)
        self.assertIn("local settings alone never prove isolation", content)
        self.assertIn("No public or private IP address is present", content)
        self.assertNotIn("Local UI address:", content)


if __name__ == "__main__":
    unittest.main()

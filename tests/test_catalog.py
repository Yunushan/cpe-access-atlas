# SPDX-License-Identifier: 0BSD
from __future__ import annotations

import unittest

from cpe_access_atlas.catalog import (
    CatalogError,
    find_recipe,
    load_providers,
    normalize,
    resolve_provider,
    validate_catalog,
)


class CatalogTests(unittest.TestCase):
    def test_seven_requested_providers_are_present(self) -> None:
        providers = load_providers()
        self.assertEqual(len(providers), 7)
        self.assertEqual(
            {provider.id for provider in providers},
            {
                "turknet",
                "turkcell-superonline",
                "turksat-kablonet",
                "turk-telekom",
                "netspeed",
                "vodafone-net",
                "millenicom",
            },
        )

    def test_provider_alias_resolves(self) -> None:
        self.assertEqual(resolve_provider("TTNET").id, "turk-telekom")
        self.assertEqual(resolve_provider("Turksat Kablonet").id, "turksat-kablonet")

    def test_exact_h3600_recipe_matches_aliases(self) -> None:
        recipe = find_recipe(
            "Türk Telekom",
            "ZTE ZXHN H3600P",
            "H3600P V9.0 TTN.10_260210",
        )
        self.assertEqual(recipe.status, "blocked")
        self.assertEqual(recipe.access["local_root_shell"], "not-supported")

    def test_nonbreaking_space_is_normalized(self) -> None:
        recipe = find_recipe(
            "Turk Telekom",
            "H3600P",
            "H3600P\u00a0V9.0\u00a0TTN.10_260210",
        )
        self.assertEqual(recipe.id, "tr.turk-telekom.zte.h3600p.h3600p-v9-ttn10-260210")
        self.assertEqual(normalize("A\u00a0B"), "a b")

    def test_firmware_fallback_is_forbidden(self) -> None:
        with self.assertRaises(CatalogError):
            find_recipe("Türk Telekom", "H3600P", "H3600P V9.0 TTN.5_240228")

    def test_catalog_is_valid(self) -> None:
        self.assertEqual(validate_catalog(), [])


if __name__ == "__main__":
    unittest.main()

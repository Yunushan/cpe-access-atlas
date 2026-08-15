# SPDX-License-Identifier: 0BSD
from __future__ import annotations

import json
import unittest
from importlib import resources
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import cpe_access_atlas.catalog as catalog
from cpe_access_atlas.catalog import (
    CatalogError,
    find_recipe,
    load_official_devices,
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

    def test_official_device_inventory_is_separate_from_recipe_support(self) -> None:
        devices = load_official_devices()
        self.assertEqual(len(devices), 59)
        self.assertIn(
            ("turkcell-superonline", "ZTE", "H3600P"),
            {(device.provider_id, device.vendor, device.model) for device in devices},
        )
        kablonet = [
            device
            for device in devices
            if device.provider_id == "turksat-kablonet" and device.model == "ZXHN F6600"
        ]
        self.assertEqual(len(kablonet), 1)
        self.assertEqual(kablonet[0].network_technology, "GPON")
        self.assertEqual(
            kablonet[0].source_ids,
            ("turksat-kablonet-devices", "turksat-kablo-devices"),
        )

    def test_exact_h3600_recipe_matches_aliases(self) -> None:
        recipe = find_recipe(
            "Türk Telekom",
            "ZTE ZXHN H3600P",
            "V9.0",
            "H3600P V9.0 TTN.10_260210",
        )
        self.assertEqual(recipe.status, "blocked")
        self.assertEqual(recipe.access["local_root_shell"], "not-supported")

    def test_nonbreaking_space_is_normalized(self) -> None:
        recipe = find_recipe(
            "Turk Telekom",
            "H3600P",
            "V9.0",
            "H3600P\u00a0V9.0\u00a0TTN.10_260210",
        )
        self.assertEqual(recipe.id, "tr.turk-telekom.zte.h3600p.h3600p-v9-ttn10-260210")
        self.assertEqual(normalize("A\u00a0B"), "a b")

    def test_non_string_lookup_values_are_controlled_errors(self) -> None:
        with self.assertRaises(CatalogError):
            normalize(None)  # type: ignore[arg-type]
        with self.assertRaises(CatalogError):
            resolve_provider(None)  # type: ignore[arg-type]

    def test_firmware_fallback_is_forbidden(self) -> None:
        with self.assertRaises(CatalogError):
            find_recipe(
                "Türk Telekom",
                "H3600P",
                "V9.0",
                "H3600P V9.0 TTN.5_240228",
            )

    def test_hardware_revision_is_required_for_an_exact_match(self) -> None:
        with self.assertRaises(CatalogError):
            find_recipe(
                "Türk Telekom",
                "H3600P",
                "V9.1",
                "H3600P V9.0 TTN.10_260210",
            )

    def test_catalog_is_valid(self) -> None:
        self.assertEqual(validate_catalog(), [])

    def test_source_and_packaged_schemas_match(self) -> None:
        source_root = Path(__file__).parents[1] / "schemas"
        package_root = resources.files("cpe_access_atlas").joinpath("data", "schemas")
        for filename in (
            "recipe.schema.json",
            "providers.schema.json",
            "device_inventory.schema.json",
        ):
            with self.subTest(filename=filename):
                source = json.loads((source_root / filename).read_text(encoding="utf-8"))
                packaged = json.loads(package_root.joinpath(filename).read_text(encoding="utf-8"))
                self.assertEqual(source, packaged)

    def test_unknown_and_ambiguous_provider_are_rejected(self) -> None:
        provider_a = catalog.Provider("a", "A", ("same",), "TR", "cataloged")
        provider_b = catalog.Provider("b", "B", ("same",), "TR", "cataloged")
        with self.assertRaises(CatalogError):
            resolve_provider("missing", [provider_a])
        with self.assertRaises(CatalogError):
            resolve_provider("same", [provider_a, provider_b])

    def test_schema_validation_rejects_invalid_payloads(self) -> None:
        with self.assertRaises(CatalogError):
            catalog._validate_payload({}, "recipe.schema.json", "fixture")
        with self.assertRaises(CatalogError):
            catalog._validate_payload(
                {"schema_version": 1, "country": "TR", "providers": []},
                "providers.schema.json",
                "fixture",
            )
        with patch.object(catalog, "_load_schema", return_value={"type": {"bad": 1}}):
            with self.assertRaises(CatalogError):
                catalog._validate_payload({}, "broken.schema.json", "fixture")

        payload = catalog._load_json("recipes/tr_turk_telekom_zte_h3600p_ttn10_260210.json")
        payload["evidence"][0]["url"] = "http://example.test/insecure"
        with self.assertRaises(CatalogError):
            catalog._validate_payload(payload, "recipe.schema.json", "fixture")

    def test_official_device_loader_rejects_unknown_source(self) -> None:
        payload = catalog._load_json("device_inventory.json")
        payload["providers"][0]["devices"][0]["source_ids"] = ["missing-source"]
        with patch.object(catalog, "_load_json", return_value=payload):
            with self.assertRaises(CatalogError):
                load_official_devices()

        duplicate_source_payload = catalog._load_json("device_inventory.json")
        duplicate_source_payload["sources"].append(dict(duplicate_source_payload["sources"][0]))
        with patch.object(catalog, "_load_json", return_value=duplicate_source_payload):
            with self.assertRaises(CatalogError):
                load_official_devices()

        mismatched_count_payload = catalog._load_json("device_inventory.json")
        mismatched_count_payload["sources"][0]["expected_device_count"] += 1
        with patch.object(catalog, "_load_json", return_value=mismatched_count_payload):
            with self.assertRaises(CatalogError):
                load_official_devices()

        duplicate_provider_payload = catalog._load_json("device_inventory.json")
        duplicate_provider_payload["providers"].append(
            dict(duplicate_provider_payload["providers"][0])
        )
        with patch.object(catalog, "_load_json", return_value=duplicate_provider_payload):
            with self.assertRaises(CatalogError):
                load_official_devices()

    def test_catalog_loader_reports_json_and_schema_errors(self) -> None:
        class BrokenResource:
            def open(self, *_args: object, **_kwargs: object) -> None:
                raise OSError("unreadable")

        with self.assertRaises(CatalogError):
            catalog._read_json(BrokenResource(), "broken.json")
        with patch.object(catalog, "_read_json", return_value=[]):
            with self.assertRaises(CatalogError):
                catalog._load_schema("broken.schema.json")

    def test_recipe_loader_handles_missing_and_non_json_entries(self) -> None:
        class FakeRoot:
            def joinpath(self, *_parts: str) -> FakeRoot:
                return self

            def iterdir(self) -> list[SimpleNamespace]:
                return [SimpleNamespace(name="README.txt")]

        with patch.object(catalog.resources, "files", return_value=FakeRoot()):
            self.assertEqual(catalog.load_recipes(), ())

        class BrokenRoot(FakeRoot):
            def iterdir(self) -> list[SimpleNamespace]:
                raise OSError("missing")

        with patch.object(catalog.resources, "files", return_value=BrokenRoot()):
            with self.assertRaises(CatalogError):
                catalog.load_recipes()

    def test_validate_catalog_reports_loader_errors(self) -> None:
        with patch.object(
            catalog,
            "load_providers",
            side_effect=CatalogError("broken provider catalog"),
        ):
            self.assertEqual(catalog.validate_catalog(), ["broken provider catalog"])

    def test_find_recipe_rejects_duplicate_matches(self) -> None:
        provider = catalog.Provider("isp", "ISP", (), "TR", "cataloged")
        matching = SimpleNamespace(
            matches=lambda *_args: True,
        )
        with (
            patch.object(catalog, "resolve_provider", return_value=provider),
            patch.object(catalog, "load_recipes", return_value=(matching, matching)),
        ):
            with self.assertRaises(CatalogError):
                catalog.find_recipe("isp", "model", "hardware", "firmware")

    def test_validate_catalog_reports_cross_record_invariants(self) -> None:
        provider = catalog.Provider("isp", "ISP", ("shared",), "TR", "cataloged")
        duplicate_provider = catalog.Provider("isp", "Other", ("shared",), "TR", "cataloged")
        colliding_provider = catalog.Provider(
            "other", "Other Provider", ("shared",), "TR", "cataloged"
        )
        recipe = SimpleNamespace(
            schema_version=2,
            id="recipe",
            isp_id="missing",
            isp_name="wrong",
            status="invalid",
            firmware_match="loose",
            evidence=(),
            hardware_revision="hardware",
            hardware_revision_status="unresolved",
            model="model",
            firmware="firmware",
        )
        known_mismatch = SimpleNamespace(
            schema_version=1,
            id="known",
            isp_id="isp",
            isp_name="wrong",
            status="blocked",
            firmware_match="exact",
            evidence=("evidence",),
            hardware_revision="hardware-2",
            hardware_revision_status="unresolved",
            model="model-2",
            firmware="firmware-2",
        )
        inventory_device = SimpleNamespace(
            provider_id="missing-inventory-provider",
            vendor="Vendor",
            model="Model",
            source_provider_ids=("other-provider",),
        )
        with (
            patch.object(
                catalog,
                "load_providers",
                return_value=(provider, duplicate_provider, colliding_provider),
            ),
            patch.object(
                catalog,
                "load_recipes",
                return_value=(recipe, recipe, known_mismatch),
            ),
            patch.object(
                catalog,
                "load_official_devices",
                return_value=(inventory_device, inventory_device),
            ),
        ):
            errors = catalog.validate_catalog()
        self.assertTrue(any("provider IDs are not unique" in error for error in errors))
        self.assertTrue(any("provider alias is ambiguous" in error for error in errors))
        self.assertTrue(any("unknown provider" in error for error in errors))
        self.assertTrue(any("invalid status" in error for error in errors))
        self.assertTrue(any("duplicate exact target" in error for error in errors))
        self.assertTrue(any("provider name does not match" in error for error in errors))
        self.assertTrue(
            any("official device inventory: unknown provider" in error for error in errors)
        )
        self.assertTrue(any("source provider does not match" in error for error in errors))
        self.assertTrue(
            any("official device inventory: duplicate device" in error for error in errors)
        )

    def test_verified_recipe_requires_exact_hardware_status(self) -> None:
        provider = catalog.Provider("isp", "ISP", (), "TR", "cataloged")
        recipe = SimpleNamespace(
            schema_version=1,
            id="recipe",
            isp_id="isp",
            isp_name="ISP",
            status="verified",
            firmware_match="exact",
            evidence=("evidence",),
            hardware_revision="V9.0",
            hardware_revision_status="unresolved",
            model="model",
            firmware="firmware",
        )
        with (
            patch.object(catalog, "load_providers", return_value=(provider,)),
            patch.object(catalog, "load_recipes", return_value=(recipe,)),
        ):
            errors = catalog.validate_catalog()
        self.assertTrue(any("resolved hardware revision" in error for error in errors))


if __name__ == "__main__":
    unittest.main()

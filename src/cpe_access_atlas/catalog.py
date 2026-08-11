# SPDX-License-Identifier: 0BSD
"""Read and validate the bundled provider and device catalog."""

from __future__ import annotations

import json
import re
import unicodedata
from collections.abc import Iterable
from dataclasses import dataclass
from importlib import resources
from typing import Any

from jsonschema import Draft202012Validator, FormatChecker
from jsonschema.exceptions import SchemaError


class CatalogError(ValueError):
    """Raised when catalog data is invalid or ambiguous."""


def normalize(value: str) -> str:
    value = unicodedata.normalize("NFKC", value)
    return re.sub(r"\s+", " ", value).strip().casefold()


@dataclass(frozen=True)
class Provider:
    id: str
    name: str
    aliases: tuple[str, ...]
    country: str
    status: str

    @classmethod
    def from_dict(cls, item: dict[str, Any]) -> Provider:
        return cls(
            id=str(item["id"]),
            name=str(item["name"]),
            aliases=tuple(str(value) for value in item.get("aliases", [])),
            country=str(item["country"]),
            status=str(item["status"]),
        )


@dataclass(frozen=True)
class Recipe:
    schema_version: int
    id: str
    country: str
    status: str
    confidence: str
    isp_id: str
    isp_name: str
    vendor: str
    model: str
    model_aliases: tuple[str, ...]
    hardware_revision: str
    hardware_revision_status: str
    firmware: str
    firmware_match: str
    access: dict[str, str]
    capabilities: tuple[str, ...]
    blockers: tuple[str, ...]
    evidence: tuple[dict[str, str], ...]
    next_evidence: tuple[str, ...]
    last_reviewed: str

    @classmethod
    def from_dict(cls, item: dict[str, Any]) -> Recipe:
        isp = item["isp"]
        device = item["device"]
        firmware = item["firmware"]
        return cls(
            schema_version=int(item["schema_version"]),
            id=str(item["id"]),
            country=str(item["country"]),
            status=str(item["status"]),
            confidence=str(item["confidence"]),
            isp_id=str(isp["id"]),
            isp_name=str(isp["name"]),
            vendor=str(device["vendor"]),
            model=str(device["model"]),
            model_aliases=tuple(str(value) for value in device.get("aliases", [])),
            hardware_revision=str(device["hardware_revision"]),
            hardware_revision_status=str(device["hardware_revision_status"]),
            firmware=str(firmware["display"]),
            firmware_match=str(firmware["match_policy"]),
            access={str(key): str(value) for key, value in item["access"].items()},
            capabilities=tuple(str(value) for value in item.get("capabilities", [])),
            blockers=tuple(str(value) for value in item.get("blockers", [])),
            evidence=tuple(
                {"title": str(value["title"]), "url": str(value["url"])}
                for value in item.get("evidence", [])
            ),
            next_evidence=tuple(str(value) for value in item.get("next_evidence", [])),
            last_reviewed=str(item["last_reviewed"]),
        )

    def matches(
        self,
        isp: str,
        model: str,
        hardware_revision: str,
        firmware: str,
    ) -> bool:
        isp_values = {normalize(self.isp_id), normalize(self.isp_name)}
        model_values = {
            normalize(self.model),
            normalize(f"{self.vendor} {self.model}"),
            *(normalize(alias) for alias in self.model_aliases),
        }
        return (
            normalize(isp) in isp_values
            and normalize(model) in model_values
            and normalize(hardware_revision) == normalize(self.hardware_revision)
            and normalize(firmware) == normalize(self.firmware)
        )


def _load_json(relative_path: str) -> Any:
    data_root = resources.files("cpe_access_atlas").joinpath("data")
    return _read_json(data_root.joinpath(relative_path), relative_path)


def _read_json(resource: Any, label: str) -> Any:
    try:
        with resource.open("r", encoding="utf-8") as handle:
            return json.load(handle)
    except (OSError, json.JSONDecodeError) as exc:
        raise CatalogError(f"invalid catalog JSON in {label}: {exc}") from exc


def _load_schema(filename: str) -> dict[str, Any]:
    schema_root = resources.files("cpe_access_atlas").joinpath("data", "schemas")
    payload = _read_json(schema_root.joinpath(filename), filename)
    if not isinstance(payload, dict):
        raise CatalogError(f"schema {filename} must contain a JSON object")
    return payload


def _validate_payload(payload: Any, schema_filename: str, label: str) -> Any:
    schema = _load_schema(schema_filename)
    try:
        Draft202012Validator.check_schema(schema)
        validator = Draft202012Validator(schema, format_checker=FormatChecker())
        errors = sorted(validator.iter_errors(payload), key=lambda error: list(error.path))
    except SchemaError as exc:
        raise CatalogError(f"invalid bundled schema {schema_filename}: {exc.message}") from exc
    if errors:
        details = "; ".join(
            f"{label} at {'.'.join(str(part) for part in error.path) or '<root>'}: {error.message}"
            for error in errors[:5]
        )
        if len(errors) > 5:
            details += f"; and {len(errors) - 5} more error(s)"
        raise CatalogError(details)
    return payload


def load_providers() -> tuple[Provider, ...]:
    payload = _validate_payload(
        _load_json("providers.json"),
        "providers.schema.json",
        "providers.json",
    )
    return tuple(Provider.from_dict(item) for item in payload["providers"])


def load_recipes() -> tuple[Recipe, ...]:
    recipe_root = resources.files("cpe_access_atlas").joinpath("data", "recipes")
    recipes: list[Recipe] = []
    try:
        entries = sorted(recipe_root.iterdir(), key=lambda item: item.name)
    except OSError as exc:
        raise CatalogError(f"unable to read recipe catalog: {exc}") from exc
    for entry in entries:
        if entry.name.endswith(".json"):
            payload = _validate_payload(
                _read_json(entry, entry.name),
                "recipe.schema.json",
                entry.name,
            )
            recipes.append(Recipe.from_dict(payload))
    return tuple(recipes)


def resolve_provider(value: str, providers: Iterable[Provider] | None = None) -> Provider:
    candidates = providers if providers is not None else load_providers()
    wanted = normalize(value)
    matches = [
        provider
        for provider in candidates
        if wanted
        in {
            normalize(provider.id),
            normalize(provider.name),
            *(normalize(alias) for alias in provider.aliases),
        }
    ]
    if len(matches) != 1:
        raise CatalogError(f"unknown or ambiguous provider: {value!r}")
    return matches[0]


def find_recipe(
    isp: str,
    model: str,
    hardware_revision: str,
    firmware: str,
) -> Recipe:
    provider = resolve_provider(isp)
    matches = [
        recipe
        for recipe in load_recipes()
        if recipe.matches(provider.id, model, hardware_revision, firmware)
    ]
    if not matches:
        raise CatalogError(
            "no exact recipe for the supplied ISP, model, hardware revision, and firmware"
        )
    if len(matches) > 1:
        raise CatalogError("multiple exact recipes matched; catalog is invalid")
    return matches[0]


def validate_catalog() -> list[str]:
    errors: list[str] = []
    try:
        providers = load_providers()
        recipes = load_recipes()
    except CatalogError as exc:
        return [str(exc)]
    provider_ids = [item.id for item in providers]
    recipe_ids = [item.id for item in recipes]

    if len(provider_ids) != len(set(provider_ids)):
        errors.append("provider IDs are not unique")
    if len(recipe_ids) != len(set(recipe_ids)):
        errors.append("recipe IDs are not unique")

    known_providers = set(provider_ids)
    provider_by_id = {item.id: item for item in providers}
    provider_names: dict[str, str] = {}
    for provider in providers:
        for value in (provider.id, provider.name, *provider.aliases):
            key = normalize(value)
            previous = provider_names.get(key)
            if previous is not None and previous != provider.id:
                errors.append(f"provider alias is ambiguous: {value!r}")
            provider_names[key] = provider.id

    valid_statuses = {"researching", "experimental", "verified", "stable", "blocked"}
    target_keys: set[tuple[str, str, str, str]] = set()
    for recipe in recipes:
        if recipe.schema_version != 1:
            errors.append(f"{recipe.id}: unsupported schema version")
        if recipe.isp_id not in known_providers:
            errors.append(f"{recipe.id}: unknown provider {recipe.isp_id}")
        elif recipe.isp_name != provider_by_id[recipe.isp_id].name:
            errors.append(f"{recipe.id}: provider name does not match provider catalog")
        if recipe.status not in valid_statuses:
            errors.append(f"{recipe.id}: invalid status {recipe.status}")
        if recipe.firmware_match != "exact":
            errors.append(f"{recipe.id}: firmware matching must be exact")
        if not recipe.evidence:
            errors.append(f"{recipe.id}: at least one evidence link is required")
        if recipe.hardware_revision_status != "exact" and recipe.status in {
            "verified",
            "stable",
        }:
            errors.append(f"{recipe.id}: verified recipes require a resolved hardware revision")
        target_key = (
            normalize(recipe.isp_id),
            normalize(recipe.model),
            normalize(recipe.hardware_revision),
            normalize(recipe.firmware),
        )
        if target_key in target_keys:
            errors.append(f"{recipe.id}: duplicate exact target")
        target_keys.add(target_key)

    return errors

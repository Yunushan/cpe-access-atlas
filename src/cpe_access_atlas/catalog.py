# SPDX-License-Identifier: 0BSD
"""Read and validate the bundled provider and device catalog."""

from __future__ import annotations

from dataclasses import dataclass
from importlib import resources
import json
import re
import unicodedata
from typing import Any, Iterable


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
    def from_dict(cls, item: dict[str, Any]) -> "Provider":
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
    firmware: str
    firmware_match: str
    access: dict[str, str]
    capabilities: tuple[str, ...]
    blockers: tuple[str, ...]
    evidence: tuple[dict[str, str], ...]
    next_evidence: tuple[str, ...]
    last_reviewed: str

    @classmethod
    def from_dict(cls, item: dict[str, Any]) -> "Recipe":
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

    def matches(self, isp: str, model: str, firmware: str) -> bool:
        isp_values = {normalize(self.isp_id), normalize(self.isp_name)}
        model_values = {
            normalize(self.model),
            normalize(f"{self.vendor} {self.model}"),
            *(normalize(alias) for alias in self.model_aliases),
        }
        return (
            normalize(isp) in isp_values
            and normalize(model) in model_values
            and normalize(firmware) == normalize(self.firmware)
        )


def _load_json(relative_path: str) -> Any:
    data_root = resources.files("cpe_access_atlas").joinpath("data")
    with data_root.joinpath(relative_path).open("r", encoding="utf-8") as handle:
        return json.load(handle)


def load_providers() -> tuple[Provider, ...]:
    payload = _load_json("providers.json")
    return tuple(Provider.from_dict(item) for item in payload["providers"])


def load_recipes() -> tuple[Recipe, ...]:
    recipe_root = resources.files("cpe_access_atlas").joinpath("data", "recipes")
    recipes: list[Recipe] = []
    for entry in sorted(recipe_root.iterdir(), key=lambda item: item.name):
        if entry.name.endswith(".json"):
            with entry.open("r", encoding="utf-8") as handle:
                recipes.append(Recipe.from_dict(json.load(handle)))
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


def find_recipe(isp: str, model: str, firmware: str) -> Recipe:
    provider = resolve_provider(isp)
    matches = [
        recipe
        for recipe in load_recipes()
        if recipe.matches(provider.id, model, firmware)
    ]
    if not matches:
        raise CatalogError(
            "no exact recipe for the supplied ISP, model, and firmware"
        )
    if len(matches) > 1:
        raise CatalogError("multiple exact recipes matched; catalog is invalid")
    return matches[0]


def validate_catalog() -> list[str]:
    errors: list[str] = []
    providers = load_providers()
    recipes = load_recipes()
    provider_ids = [item.id for item in providers]
    recipe_ids = [item.id for item in recipes]

    if len(provider_ids) != len(set(provider_ids)):
        errors.append("provider IDs are not unique")
    if len(recipe_ids) != len(set(recipe_ids)):
        errors.append("recipe IDs are not unique")

    known_providers = set(provider_ids)
    valid_statuses = {"researching", "experimental", "verified", "stable", "blocked"}
    for recipe in recipes:
        if recipe.schema_version != 1:
            errors.append(f"{recipe.id}: unsupported schema version")
        if recipe.isp_id not in known_providers:
            errors.append(f"{recipe.id}: unknown provider {recipe.isp_id}")
        if recipe.status not in valid_statuses:
            errors.append(f"{recipe.id}: invalid status {recipe.status}")
        if recipe.firmware_match != "exact":
            errors.append(f"{recipe.id}: firmware matching must be exact")
        if not recipe.evidence:
            errors.append(f"{recipe.id}: at least one evidence link is required")
    return errors

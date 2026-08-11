# SPDX-License-Identifier: 0BSD
"""Command-line interface for the compatibility catalog."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

from . import __version__
from .catalog import (
    CatalogError,
    Recipe,
    find_recipe,
    load_providers,
    load_recipes,
    validate_catalog,
)
from .policy import PolicyError, parse_ports, parse_single_private_address, probe_tcp_ports
from .report import build_research_template


def _recipe_from_args(args: argparse.Namespace) -> Recipe:
    return find_recipe(args.isp, args.model, args.firmware)


def _add_target_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--isp", required=True, help="provider ID or name")
    parser.add_argument("--model", required=True, help="exact device model")
    parser.add_argument("--firmware", required=True, help="exact firmware string")


def _recipe_payload(recipe: Recipe) -> dict[str, object]:
    return {
        "id": recipe.id,
        "status": recipe.status,
        "confidence": recipe.confidence,
        "isp": recipe.isp_name,
        "device": f"{recipe.vendor} {recipe.model}",
        "hardware_revision": recipe.hardware_revision,
        "firmware": recipe.firmware,
        "access": recipe.access,
        "capabilities": list(recipe.capabilities),
        "blockers": list(recipe.blockers),
        "last_reviewed": recipe.last_reviewed,
    }


def command_providers(args: argparse.Namespace) -> int:
    providers = load_providers()
    if args.json:
        print(json.dumps([item.__dict__ for item in providers], ensure_ascii=False, indent=2))
        return 0
    print("Provider ID               Name                    Status")
    print("------------------------  ----------------------  ---------")
    for provider in providers:
        print(f"{provider.id:<24}  {provider.name:<22}  {provider.status}")
    return 0


def command_recipes(args: argparse.Namespace) -> int:
    recipes = load_recipes()
    if args.json:
        print(
            json.dumps(
                [_recipe_payload(recipe) for recipe in recipes],
                ensure_ascii=False,
                indent=2,
            )
        )
        return 0
    for recipe in recipes:
        print(
            f"{recipe.id}\n"
            f"  {recipe.isp_name} | {recipe.vendor} {recipe.model} | {recipe.firmware}\n"
            f"  status={recipe.status}, confidence={recipe.confidence}"
        )
    return 0


def command_status(args: argparse.Namespace) -> int:
    recipe = _recipe_from_args(args)
    payload = _recipe_payload(recipe)
    if args.json:
        print(json.dumps(payload, ensure_ascii=False, indent=2))
        return 0
    print(f"Recipe:     {recipe.id}")
    print(f"Status:     {recipe.status}")
    print(f"Confidence: {recipe.confidence}")
    print(f"Target:     {recipe.isp_name} / {recipe.vendor} {recipe.model}")
    print(f"Hardware:   {recipe.hardware_revision}")
    print(f"Firmware:   {recipe.firmware} (exact match)")
    print("Access:")
    for level, status in recipe.access.items():
        print(f"  - {level}: {status}")
    if recipe.blockers:
        print("Blockers:")
        for blocker in recipe.blockers:
            print(f"  - {blocker}")
    print("No device change was attempted.")
    return 0


def command_evidence(args: argparse.Namespace) -> int:
    recipe = _recipe_from_args(args)
    for item in recipe.evidence:
        print(f"- {item['title']}: {item['url']}")
    return 0


def command_plan(args: argparse.Namespace) -> int:
    recipe = _recipe_from_args(args)
    print(f"Target record: {recipe.id}")
    print(f"Current status: {recipe.status}")
    if recipe.status in {"blocked", "researching"}:
        print("Decision: STOP")
        print("Reason: no verified mutation workflow exists for this exact firmware.")
        print("The project will not substitute a recipe from another firmware.")
        print("Next evidence needed:")
        for item in recipe.next_evidence:
            print(f"  - {item}")
        return 0
    print("Decision: REVIEW REQUIRED")
    print("No mutating adapter is included in this release.")
    return 0


def command_apply(args: argparse.Namespace) -> int:
    recipe = _recipe_from_args(args)
    if not args.i_own_or_administer_this_device:
        print(
            "Refused: explicit ownership/authorization acknowledgement is required.",
            file=sys.stderr,
        )
        return 3
    print(
        f"Refused: {recipe.id} is {recipe.status}; no verified apply adapter exists. "
        "No device change was attempted.",
        file=sys.stderr,
    )
    return 3


def command_doctor(args: argparse.Namespace) -> int:
    address = parse_single_private_address(args.host)
    ports = parse_ports(args.ports)
    print(f"Accepted single private target: {address}")
    print(f"Explicit ports: {', '.join(str(port) for port in ports)}")
    if not args.probe:
        print("Probe disabled; no network connection was attempted.")
        return 0
    results = probe_tcp_ports(str(address), ports, timeout=args.timeout)
    for port, is_open in results.items():
        print(f"tcp/{port}: {'open' if is_open else 'closed/unreachable'}")
    return 0


def command_report_template(args: argparse.Namespace) -> int:
    recipe = _recipe_from_args(args)
    content = build_research_template(recipe)
    if not args.output:
        print(content, end="")
        return 0
    output = Path(args.output)
    if output.exists() and not args.force:
        print(f"Refused: {output} already exists; use --force to replace it.", file=sys.stderr)
        return 4
    output.write_text(content, encoding="utf-8")
    print(f"Wrote sanitized research template: {output}")
    return 0


def command_validate(args: argparse.Namespace) -> int:
    del args
    errors = validate_catalog()
    if errors:
        for error in errors:
            print(f"ERROR: {error}", file=sys.stderr)
        return 1
    print("Catalog validation passed.")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="cpe-atlas",
        description=(
            "Firmware-aware catalog and safe research tooling for owner-authorized CPE access"
        ),
    )
    parser.add_argument("--version", action="version", version=__version__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    providers = subparsers.add_parser("providers", help="list cataloged providers")
    providers.add_argument("--json", action="store_true")
    providers.set_defaults(func=command_providers)

    recipes = subparsers.add_parser("recipes", help="list exact device recipes")
    recipes.add_argument("--json", action="store_true")
    recipes.set_defaults(func=command_recipes)

    status = subparsers.add_parser("status", help="show exact target status")
    _add_target_arguments(status)
    status.add_argument("--json", action="store_true")
    status.set_defaults(func=command_status)

    evidence = subparsers.add_parser("evidence", help="show public evidence links")
    _add_target_arguments(evidence)
    evidence.set_defaults(func=command_evidence)

    plan = subparsers.add_parser("plan", help="render a non-mutating decision plan")
    _add_target_arguments(plan)
    plan.set_defaults(func=command_plan)

    apply_parser = subparsers.add_parser(
        "apply",
        help="fail-closed mutation entry point; unavailable until a recipe is verified",
    )
    _add_target_arguments(apply_parser)
    apply_parser.add_argument(
        "--i-own-or-administer-this-device",
        action="store_true",
        help="acknowledge ownership or explicit authorization",
    )
    apply_parser.set_defaults(func=command_apply)

    doctor = subparsers.add_parser("doctor", help="validate one private target")
    doctor.add_argument("--host", required=True, help="one RFC1918 or IPv6 ULA literal")
    doctor.add_argument("--ports", default="80,443", help="up to eight explicit TCP ports")
    doctor.add_argument("--probe", action="store_true", help="connect to the listed ports")
    doctor.add_argument("--timeout", type=float, default=1.0)
    doctor.set_defaults(func=command_doctor)

    report = subparsers.add_parser(
        "report-template",
        help="generate a sanitized hardware research template",
    )
    _add_target_arguments(report)
    report.add_argument("--output")
    report.add_argument("--force", action="store_true")
    report.set_defaults(func=command_report_template)

    validate = subparsers.add_parser("validate", help="validate bundled catalog data")
    validate.set_defaults(func=command_validate)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return int(args.func(args))
    except (CatalogError, PolicyError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print("Interrupted; no retry was attempted.", file=sys.stderr)
        return 130


if __name__ == "__main__":
    raise SystemExit(main())

# SPDX-License-Identifier: 0BSD
"""Command-line interface for the compatibility catalog."""

from __future__ import annotations

import argparse
import getpass
import json
import os
import sys
import warnings
from pathlib import Path

from . import __version__
from .catalog import (
    CatalogError,
    OfficialDevice,
    Recipe,
    find_recipe,
    load_official_devices,
    load_providers,
    load_recipes,
    resolve_provider,
    validate_catalog,
)
from .config import (
    H3600P_SIGNATURE,
    ConfigError,
    decode_config,
    default_root_xml,
    encode_config,
    inspect_config,
    patch_root_ssh,
    read_private_config,
)
from .firmware import FirmwareInspectionError, inspect_firmware
from .policy import (
    PolicyError,
    parse_ports,
    parse_single_private_address,
    parse_timeout,
    probe_tcp_ports,
)
from .private_container import (
    MAX_CONTAINER_BYTES,
    MAX_PRIVATE_BYTES,
    PrivateContainerError,
    protect_private_bytes,
    unprotect_private_bytes,
)
from .private_files import write_private_bytes, write_private_text
from .redaction import MAX_REPORT_CHARS, RedactionError, redact_text
from .report import build_research_template
from .uart_evidence import UartEvidenceError, inspect_uart_log
from .web_evidence import WebEvidenceError, collect_zte_web_evidence

MAX_CONFIG_IDENTITY_BYTES = 1_024


def _recipe_from_args(args: argparse.Namespace) -> Recipe:
    return find_recipe(
        args.isp,
        args.model,
        args.hardware_revision,
        args.firmware,
    )


def _add_target_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--isp", required=True, help="provider ID or name")
    parser.add_argument("--model", required=True, help="exact device model")
    parser.add_argument(
        "--hardware-revision",
        required=True,
        help="exact hardware revision recorded in the catalog",
    )
    parser.add_argument("--firmware", required=True, help="exact firmware string")


def _paths_alias(left: Path, right: Path) -> bool:
    """Return whether two user-selected paths identify the same file path."""

    try:
        if left.exists() and right.exists() and left.samefile(right):
            return True
    except OSError:
        # The normalized resolved paths below still catch ordinary aliases when
        # samefile is unavailable (for example, before a destination exists).
        pass
    try:
        return os.path.normcase(str(left.resolve(strict=False))) == os.path.normcase(
            str(right.resolve(strict=False))
        )
    except OSError as exc:
        raise ConfigError("unable to compare private input and output paths") from exc


def _parse_timeout_argument(value: str) -> float:
    try:
        return parse_timeout(value)
    except PolicyError as exc:
        raise argparse.ArgumentTypeError(str(exc)) from exc


def _recipe_payload(recipe: Recipe) -> dict[str, object]:
    return {
        "id": recipe.id,
        "status": recipe.status,
        "confidence": recipe.confidence,
        "isp": recipe.isp_name,
        "device": f"{recipe.vendor} {recipe.model}",
        "hardware_revision": recipe.hardware_revision,
        "hardware_revision_status": recipe.hardware_revision_status,
        "firmware": recipe.firmware,
        "access": recipe.access,
        "capabilities": list(recipe.capabilities),
        "blockers": list(recipe.blockers),
        "last_reviewed": recipe.last_reviewed,
        "qualification": dict(recipe.qualification),
        "qualification_records": [dict(record) for record in recipe.qualification_records],
    }


def _device_payload(device: OfficialDevice) -> dict[str, object]:
    return {
        "provider_id": device.provider_id,
        "vendor": device.vendor,
        "model": device.model,
        "official_name": device.official_name,
        "category": device.category,
        "network_technology": device.network_technology,
        "source_ids": list(device.source_ids),
        "source_urls": list(device.source_urls),
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


def command_devices(args: argparse.Namespace) -> int:
    devices = load_official_devices()
    if args.isp:
        provider = resolve_provider(args.isp)
        devices = tuple(device for device in devices if device.provider_id == provider.id)
    if args.json:
        print(
            json.dumps(
                [_device_payload(device) for device in devices],
                ensure_ascii=False,
                indent=2,
            )
        )
        return 0
    print("Provider ID               Vendor       Model                 Category")
    print("------------------------  -----------  --------------------  ----------------")
    if not devices:
        print("No official device listings found for the selected provider.")
    for device in devices:
        print(
            f"{device.provider_id:<24}  {device.vendor:<11}  {device.model:<20}  {device.category}"
        )
    print("Official listings only; this command makes no firmware or access-support claim.")
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
    print(f"Hardware verification: {recipe.hardware_revision_status}")
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
    if recipe.status in {"blocked", "researching"} or recipe.hardware_revision_status != "exact":
        print("Decision: STOP")
        print("Reason: no verified mutation workflow exists for this exact target.")
        print("The project will not substitute another hardware revision or firmware.")
        print("Next evidence needed:")
        for item in recipe.next_evidence:
            print(f"  - {item}")
        return 0
    print("Decision: REVIEW REQUIRED")
    print("No mutating adapter is included in this release.")
    return 0


def command_root_readiness(args: argparse.Namespace) -> int:
    """Report whether the catalog has enough evidence for root research.

    This command is deliberately a read-only gate.  It may hash and scan one
    private firmware artifact, but it never reads configuration XML, connects
    to a device, executes firmware, generates a config, or flashes anything.
    """

    recipe = _recipe_from_args(args)
    if args.expected_sha256 and not args.firmware_input:
        raise FirmwareInspectionError("--expected-sha256 requires --firmware-input")
    inspection = (
        inspect_firmware(args.firmware_input, recipe.firmware, args.expected_sha256)
        if args.firmware_input
        else None
    )
    exact_hardware = recipe.hardware_revision_status == "exact"
    root_method_verified = recipe.status in {"verified", "stable"} and recipe.access.get(
        "local_root_shell"
    ) in {"verified", "stable"}
    artifact_exact = None if inspection is None else inspection.exact_build_match
    artifact_hash = None if inspection is None else inspection.sha256_match
    artifact_evidence_matches = (
        inspection is not None
        and inspection.exact_build_match is True
        and (inspection.expected_sha256 is None or inspection.sha256_match is True)
    )

    blockers = list(recipe.blockers)
    if not exact_hardware:
        blockers.append("The hardware revision is not resolved to an exact catalog value.")
    if not root_method_verified:
        blockers.append("No verified exact-build Linux root-shell method is recorded.")
    if inspection is None:
        blockers.append("No private firmware artifact was supplied for exact-build inspection.")
    elif inspection.exact_build_match is not True:
        blockers.append("The supplied firmware artifact does not prove the exact catalog build.")
    elif inspection.expected_sha256 is not None and inspection.sha256_match is not True:
        blockers.append("The supplied firmware artifact does not match the expected SHA-256.")

    decision = "STOP" if blockers else "REVIEW REQUIRED"
    payload: dict[str, object] = {
        "target": _recipe_payload(recipe),
        "decision": decision,
        "checks": {
            "exact_hardware_revision": exact_hardware,
            "catalog_root_method_verified": root_method_verified,
            "firmware_artifact_supplied": inspection is not None,
            "firmware_exact_build_match": artifact_exact,
            "firmware_sha256_match": artifact_hash,
            "firmware_evidence_matches": artifact_evidence_matches,
            # Retained for JSON consumers, but never claim authenticity from
            # embedded strings or a hash whose provenance we cannot verify.
            "firmware_identity_verified": False,
        },
        "blockers": blockers,
        "required_before_any_mutation": [
            "A reproducible method for this exact firmware and hardware revision.",
            "A recovery path tested before and after the experiment.",
            "Separate local login verification and service-preservation checks.",
            "Private handling of configuration, firmware, credentials, and device identifiers.",
        ],
        "device_io_attempted": False,
        "config_or_firmware_written": False,
    }
    if inspection is not None:
        payload["firmware_artifact"] = {
            "size": inspection.size,
            "sha256": inspection.sha256,
            "version_strings": list(inspection.version_strings),
            "markers": list(inspection.markers),
        }

    if args.json:
        print(json.dumps(payload, ensure_ascii=False, indent=2))
    else:
        print(f"Target record: {recipe.id}")
        print(f"Decision: {decision}")
        print(f"Root shell status: {recipe.access.get('local_root_shell', 'not-recorded')}")
        print(f"Exact hardware revision: {'yes' if exact_hardware else 'no'}")
        if inspection is None:
            print("Firmware artifact: not supplied; no artifact was read")
        else:
            print("Firmware artifact: supplied private file")
            print(f"Exact build match: {artifact_exact}")
            print(f"SHA-256 match: {artifact_hash}")
            print(
                "Evidence match only; firmware authenticity and flash compatibility are unverified."
            )
        print("Blockers:")
        for blocker in blockers:
            print(f"  - {blocker}")
        print("No device connection, config write, firmware execution, or flashing was attempted.")
    return int(decision == "STOP")


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


def _read_secret(
    args: argparse.Namespace,
    stdin_name: str,
    prompt: str,
    label: str,
    *,
    max_chars: int,
) -> str:
    try:
        if getattr(args, stdin_name, False):
            # Allow one CRLF terminator without reading an unbounded line or
            # stripping arbitrary trailing characters into an accepted secret.
            value = sys.stdin.readline(max_chars + 2).removesuffix("\n").removesuffix("\r")
        else:
            # getpass warns BEFORE its echoing fallback reads from stdin.
            # Make that warning fatal even if the process normally ignores it.
            with warnings.catch_warnings():
                warnings.simplefilter("error", getpass.GetPassWarning)
                value = getpass.getpass(prompt)
    except getpass.GetPassWarning as exc:
        raise ConfigError(
            "hidden secret input is unavailable; use a terminal with hidden input "
            "or an explicit secret-stdin option with a private pipe or file"
        ) from exc
    except EOFError as exc:
        raise ConfigError(f"{label} input ended before a value was read") from exc
    except (OSError, UnicodeError, ValueError) as exc:
        # Input-layer diagnostics can themselves contain private paths/data.
        raise ConfigError(f"unable to read {label} securely") from exc
    if not value:
        raise ConfigError(f"{label} must not be empty")
    if len(value) > max_chars:
        raise ConfigError(f"{label} exceeds the {max_chars}-character input limit")
    return value


def _read_private_file(path: str | Path, maximum: int, label: str) -> bytes:
    try:
        with Path(path).open("rb") as stream:
            data = stream.read(maximum + 1)
    except OSError as exc:
        raise ConfigError(f"unable to read {label}") from exc
    if not data:
        raise ConfigError(f"{label} is empty")
    if len(data) > maximum:
        raise ConfigError(f"{label} exceeds the safety size limit")
    return data


def _config_identity(args: argparse.Namespace) -> tuple[str | None, str | None]:
    """Read device identifiers without requiring command-line disclosure."""

    if args.identity_file is None:
        return args.serial, args.mac
    if args.serial is not None or args.mac is not None:
        raise ConfigError("--identity-file cannot be combined with --serial or --mac")
    data = _read_private_file(args.identity_file, MAX_CONFIG_IDENTITY_BYTES, "device identity file")
    try:
        value = json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, ValueError, RecursionError) as exc:
        raise ConfigError("device identity file must contain bounded UTF-8 JSON") from exc
    if not isinstance(value, dict) or set(value) != {"serial", "mac"}:
        raise ConfigError("device identity file must contain exactly serial and mac fields")
    serial = value["serial"]
    mac = value["mac"]
    if not isinstance(serial, str) or not isinstance(mac, str):
        raise ConfigError("device identity serial and mac fields must be strings")
    return serial, mac


def command_config_generate(args: argparse.Namespace) -> int:
    recipe = _recipe_from_args(args)
    if not args.i_own_or_administer_this_device:
        print(
            "Refused: explicit ownership/authorization acknowledgement is required.",
            file=sys.stderr,
        )
        return 3

    if (
        recipe.vendor != "ZTE"
        or recipe.model != "H3600P V9"
        or recipe.hardware_revision != "V9.0"
        or "offline-private-config-codec" not in recipe.capabilities
    ):
        raise ConfigError("no compatible offline configuration codec is registered for this target")
    if args.signature != H3600P_SIGNATURE:
        raise ConfigError("configuration signature must match the selected H3600P V9.0 codec")

    if (
        recipe.status not in {"verified", "stable"} or recipe.hardware_revision_status != "exact"
    ) and not args.acknowledge_unverified_compatibility:
        raise ConfigError(
            "exact firmware acceptance and recovery are unverified; pass "
            "--acknowledge-unverified-compatibility to generate an offline artifact "
            "while accepting that the target may reject it and recovery may be unavailable"
        )

    output = Path(args.output)
    baseline = args.input_config or args.input_xml
    if baseline is not None and _paths_alias(Path(baseline), output):
        raise ConfigError(
            "output path must differ from the private baseline; keep the original backup"
        )
    if args.identity_file is not None and _paths_alias(Path(args.identity_file), output):
        raise ConfigError(
            "output path must differ from the private identity file; keep the original identifiers"
        )
    serial, mac = _config_identity(args)
    if output.exists() and not args.force:
        print(
            "Refused: output artifact already exists; use --force to replace it.",
            file=sys.stderr,
        )
        return 4

    source_label = "minimal offline template"
    device_key: str | None = None
    private_config: bytes | None = None
    private_config_encrypted = False
    source_xml: bytes | None
    if args.input_config:
        source_label = "private configuration baseline"
        private_config = read_private_config(args.input_config)
        metadata = inspect_config(private_config)
        if metadata.signature not in (None, H3600P_SIGNATURE):
            raise ConfigError("configuration baseline signature does not match the selected codec")
        private_config_encrypted = metadata.encrypted
        if private_config_encrypted and (not serial or not mac):
            raise ConfigError(
                "encrypted input requires --serial/--mac or --identity-file for local decryption"
            )
        source_xml = None
    elif args.input_xml:
        source_label = "private XML baseline"
        source_xml = read_private_config(args.input_xml, xml=True)
    else:
        source_xml = None

    encrypted_output = args.encrypted or (private_config_encrypted and not args.allow_unencrypted)
    if not encrypted_output and not args.allow_unencrypted:
        raise ConfigError(
            "unencrypted output requires explicit --allow-unencrypted acknowledgement"
        )
    if encrypted_output and (not serial or not mac):
        raise ConfigError("encrypted output requires --serial/--mac or --identity-file")
    if encrypted_output and not args.acknowledge_legacy_crypto:
        raise ConfigError(
            "vendor-compatible encryption uses legacy SHA-256 derivation and unauthenticated "
            "CBC; pass --acknowledge-legacy-crypto to accept this compatibility risk"
        )

    ssh_password = _read_secret(
        args,
        "ssh_password_stdin",
        "SSH password to write into the private artifact: ",
        "SSH password",
        max_chars=128,
    )
    if private_config is not None:
        if private_config_encrypted:
            device_key = _read_secret(
                args,
                "device_key_stdin",
                "H3600P device encryption passphrase: ",
                "H3600P device encryption passphrase",
                max_chars=32,
            )
        decoded = decode_config(
            private_config,
            device_key=device_key,
            serial=serial,
            mac=mac,
        )
        source_xml = decoded.xml
    if encrypted_output and device_key is None:
        device_key = _read_secret(
            args,
            "device_key_stdin",
            "H3600P device encryption passphrase: ",
            "H3600P device encryption passphrase",
            max_chars=32,
        )
    if source_xml is None:
        source_xml = default_root_xml(ssh_password, args.username)
    else:
        source_xml = patch_root_ssh(source_xml, ssh_password, args.username)

    artifact = encode_config(
        source_xml,
        signature=args.signature,
        base64_wrap=not args.raw,
        encrypted=encrypted_output,
        acknowledge_legacy_crypto=args.acknowledge_legacy_crypto,
        device_key=device_key,
        serial=serial,
        mac=mac,
    )
    verification = decode_config(
        artifact,
        device_key=device_key if encrypted_output else None,
        serial=serial if encrypted_output else None,
        mac=mac if encrypted_output else None,
    )
    if verification.xml != source_xml:
        raise ConfigError("generated configuration failed its in-memory round-trip check")
    try:
        write_private_bytes(output, artifact, replace=args.force)
    except OSError as exc:
        raise ConfigError("unable to write configuration artifact") from exc

    encryption_label = "encrypted type-4" if encrypted_output else "compressed, unencrypted"
    wrapper_label = "base64 wrapped" if not args.raw else "raw binary"
    print("Wrote offline configuration artifact.")
    print(f"Target: {recipe.id}")
    print(f"Source: {source_label}")
    print(f"Container: {encryption_label}; {wrapper_label}")
    print("SSH privilege fields were patched locally; no device connection was attempted.")
    print(
        "WARNING: acceptance on this exact firmware, preservation of ISP settings, "
        "and recovery are not verified. Keep the original backup private."
    )
    return 0


def _private_container_paths(args: argparse.Namespace) -> tuple[Path, Path] | None:
    source = Path(args.input)
    output = Path(args.output)
    if _paths_alias(source, output):
        raise ConfigError(
            "output path must differ from the private input; keep the original artifact"
        )
    if output.exists() and not args.force:
        print(
            "Refused: output artifact already exists; use --force to replace it.",
            file=sys.stderr,
        )
        return None
    return source, output


def command_private_protect(args: argparse.Namespace) -> int:
    """Protect one local private artifact with an authenticated container."""

    if not args.i_am_authorized_to_handle_this_private_file:
        print(
            "Refused: explicit authorization to handle the private file is required.",
            file=sys.stderr,
        )
        return 3
    paths = _private_container_paths(args)
    if paths is None:
        return 4
    source, output = paths
    data = _read_private_file(source, MAX_PRIVATE_BYTES, "private artifact")
    passphrase = _read_secret(
        args,
        "passphrase_stdin",
        "Private-container passphrase: ",
        "private-container passphrase",
        max_chars=256,
    )
    protected = protect_private_bytes(data, passphrase)
    try:
        write_private_bytes(output, protected, replace=args.force)
    except FileExistsError:
        print(
            "Refused: output artifact already exists; use --force to replace it.",
            file=sys.stderr,
        )
        return 4
    except OSError as exc:
        raise OSError("unable to write protected private artifact") from exc
    print("Wrote authenticated private container.")
    print("This container is for local protection only; it is not a modem-import configuration.")
    return 0


def command_private_unprotect(args: argparse.Namespace) -> int:
    """Decrypt one authenticated local container into a private artifact."""

    if not args.i_am_authorized_to_handle_this_private_file:
        print(
            "Refused: explicit authorization to handle the private file is required.",
            file=sys.stderr,
        )
        return 3
    paths = _private_container_paths(args)
    if paths is None:
        return 4
    source, output = paths
    data = _read_private_file(source, MAX_CONTAINER_BYTES, "private container")
    passphrase = _read_secret(
        args,
        "passphrase_stdin",
        "Private-container passphrase: ",
        "private-container passphrase",
        max_chars=256,
    )
    plaintext = unprotect_private_bytes(data, passphrase)
    try:
        write_private_bytes(output, plaintext, replace=args.force)
    except FileExistsError:
        print(
            "Refused: output artifact already exists; use --force to replace it.",
            file=sys.stderr,
        )
        return 4
    except OSError as exc:
        raise OSError("unable to write unprotected private artifact") from exc
    print("Wrote private artifact from authenticated container.")
    print("The output contains the original private contents; keep it protected and local.")
    return 0


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


def command_web_evidence(args: argparse.Namespace) -> int:
    """Collect sanitized authenticated evidence from the exact local target."""

    recipe = _recipe_from_args(args)
    if not args.i_own_or_administer_this_device:
        print(
            "Refused: explicit ownership/authorization acknowledgement is required.",
            file=sys.stderr,
        )
        return 3
    if not args.acknowledge_local_http_authentication:
        print(
            "Refused: acknowledge that this firmware's local login uses HTTP before continuing.",
            file=sys.stderr,
        )
        return 3
    if recipe.vendor != "ZTE" or recipe.model != "H3600P V9":
        raise WebEvidenceError("the read-only web evidence adapter is limited to ZTE H3600P V9")

    password = _read_secret(
        args,
        "password_stdin",
        "Local router web password (not stored): ",
        "local router web password",
        max_chars=256,
    )
    evidence = collect_zte_web_evidence(
        args.host,
        args.username,
        password,
        timeout=args.timeout,
        expected_firmware=recipe.firmware,
        expected_model=recipe.model,
        expected_hardware=recipe.hardware_revision,
    )
    print(
        json.dumps(
            {"target": _recipe_payload(recipe), "web_evidence": evidence},
            ensure_ascii=False,
            indent=2,
        )
    )
    return 0


def command_uart_evidence(args: argparse.Namespace) -> int:
    """Inspect a private UART boot capture without emitting raw log data."""

    recipe = _recipe_from_args(args)
    if recipe.vendor != "ZTE" or recipe.model != "H3600P V9":
        raise UartEvidenceError("the UART evidence adapter is limited to ZTE H3600P V9")
    evidence = inspect_uart_log(args.input, recipe.firmware)
    payload = {
        "size": evidence.size,
        "line_count": evidence.line_count,
        "expected_firmware": evidence.expected_firmware,
        "firmware_versions": list(evidence.firmware_versions),
        "firmware_identity_status": evidence.firmware_identity_status,
        "bootloader_versions": list(evidence.bootloader_versions),
        "bootloader_builds": list(evidence.bootloader_builds),
        "linux_versions": list(evidence.linux_versions),
        "hardware_versions": list(evidence.hardware_versions),
        "soc_models": list(evidence.soc_models),
        "board_models": list(evidence.board_models),
        "product_ids": list(evidence.product_ids),
        "dram_mib": list(evidence.dram_mib),
        "boot_security": evidence.boot_security,
        "uboot_security": evidence.uboot_security,
        "boot_interrupt_prompt_observed": evidence.boot_interrupt_prompt_observed,
        "bootloader_password_prompt_observed": evidence.bootloader_access_gate_observed,
        "bootloader_shell_prompt_observed": evidence.bootloader_shell_prompt_observed,
        "kernel_start_observed": evidence.kernel_start_observed,
        "linux_console_output_observed": evidence.linux_console_output_observed,
        "linux_login_prompt_observed": evidence.linux_login_prompt_observed,
        "uid_zero_marker_observed": evidence.uid_zero_marker_observed,
        "recognized_h3600p_boot_output": evidence.recognized_h3600p_boot_output,
        "device_io_attempted": evidence.device_io_attempted,
        "raw_log_output": evidence.raw_log_output,
        "secret_or_identity_values_output": evidence.non_allowlisted_values_emitted,
        "root_access_verified": evidence.root_access_verified,
    }
    print(
        json.dumps(
            {"target": _recipe_payload(recipe), "uart_evidence": payload},
            ensure_ascii=False,
            indent=2,
        )
    )
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
    try:
        write_private_text(output, content, replace=args.force)
    except FileExistsError:
        print(f"Refused: {output} already exists; use --force to replace it.", file=sys.stderr)
        return 4
    print(f"Wrote sanitized research template: {output}")
    return 0


def command_redact(args: argparse.Namespace) -> int:
    if not args.output:
        print(
            "Refused: --output is required; redacted text is never printed to the terminal.",
            file=sys.stderr,
        )
        return 4
    output = Path(args.output)
    if args.input and _paths_alias(Path(args.input), output):
        raise RedactionError("output path must differ from the private input report")
    try:
        output_exists = output.exists()
    except OSError:
        raise RedactionError("unable to inspect private output path") from None
    if output_exists and not args.force:
        print(
            "Refused: output already exists; use --force to replace it.",
            file=sys.stderr,
        )
        return 4
    if args.input:
        try:
            with Path(args.input).open(encoding="utf-8") as stream:
                value = stream.read(MAX_REPORT_CHARS + 1)
        except OSError:
            raise RedactionError("unable to read private input report") from None
    else:
        value = sys.stdin.read(MAX_REPORT_CHARS + 1)
    if len(value) > MAX_REPORT_CHARS:
        raise RedactionError("report exceeds the safety size limit")
    content = redact_text(value)
    try:
        write_private_text(output, content, replace=args.force)
    except OSError as exc:
        raise OSError("unable to write redacted text") from exc
    print("Wrote redacted text.")
    print(
        "Manual review required before sharing: unrecognized sensitive fields may remain. "
        "Never upload configuration backups."
    )
    return 0


def command_firmware_inspect(args: argparse.Namespace) -> int:
    inspection = inspect_firmware(
        args.input,
        args.expected_version,
        args.expected_sha256,
    )
    payload = {
        "size": inspection.size,
        "sha256": inspection.sha256,
        "version_strings": list(inspection.version_strings),
        "markers": list(inspection.markers),
        "expected_version": inspection.expected_version,
        "exact_build_match": inspection.exact_build_match,
        "expected_sha256": inspection.expected_sha256,
        "sha256_match": inspection.sha256_match,
    }
    if args.json:
        print(json.dumps(payload, ensure_ascii=False, indent=2))
    else:
        print("Artifact:       supplied private file")
        print(f"Size:           {inspection.size} bytes")
        print(f"SHA-256:        {inspection.sha256}")
        print("Version strings: " + (", ".join(inspection.version_strings) or "none detected"))
        print("Markers:        " + (", ".join(inspection.markers) or "none detected"))
        version_match_label = {
            None: "not checked",
            True: "yes",
            False: "no",
        }[inspection.exact_build_match]
        sha256_match_label = {
            None: "not checked",
            True: "yes",
            False: "no",
        }[inspection.sha256_match]
        print(f"Exact build match: {version_match_label}")
        print(f"SHA-256 match:     {sha256_match_label}")
        print("No firmware code was executed or modified.")
    return int(False in {inspection.exact_build_match, inspection.sha256_match})


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

    devices = subparsers.add_parser(
        "devices",
        help="list devices published on official ISP pages (not support recipes)",
    )
    devices.add_argument("--isp", help="filter by provider ID, name, or alias")
    devices.add_argument("--json", action="store_true")
    devices.set_defaults(func=command_devices)

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

    root_readiness = subparsers.add_parser(
        "root-readiness",
        help="check exact-build root evidence without changing a device",
    )
    _add_target_arguments(root_readiness)
    root_readiness.add_argument(
        "--firmware-input",
        help="optional private firmware artifact to hash and scan only",
    )
    root_readiness.add_argument(
        "--expected-sha256",
        help="expected SHA-256 for the private firmware artifact",
    )
    root_readiness.add_argument("--json", action="store_true")
    root_readiness.set_defaults(func=command_root_readiness)

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

    config_generate = subparsers.add_parser(
        "config-generate",
        help="generate a private offline H3600P config artifact; never flashes a device",
    )
    _add_target_arguments(config_generate)
    source = config_generate.add_mutually_exclusive_group()
    source.add_argument(
        "--input-config",
        help="private existing config.bin baseline; never upload this file",
    )
    source.add_argument(
        "--input-xml",
        help="private decoded XML baseline",
    )
    config_generate.add_argument(
        "--output",
        required=True,
        help="output path for the generated private artifact",
    )
    config_generate.add_argument("--username", default="admin")
    config_generate.add_argument(
        "--ssh-password-stdin",
        action="store_true",
        help="read the SSH password from the first stdin line instead of prompting",
    )
    config_generate.add_argument(
        "--device-key-stdin",
        action="store_true",
        help="read the H3600P device encryption passphrase from stdin when needed",
    )
    config_generate.add_argument(
        "--serial",
        help="device serial required to decode or encrypt a type-4 artifact",
    )
    config_generate.add_argument(
        "--mac",
        help="lower-case colon-separated device MAC required for type-4 crypto",
    )
    config_generate.add_argument(
        "--identity-file",
        help="private bounded JSON file containing serial and mac instead of CLI values",
    )
    config_generate.add_argument("--signature", default=H3600P_SIGNATURE)
    output_format = config_generate.add_mutually_exclusive_group()
    output_format.add_argument(
        "--encrypted",
        action="store_true",
        help="emit the device-specific encrypted type-4 container",
    )
    output_format.add_argument(
        "--allow-unencrypted",
        action="store_true",
        help="explicitly allow a credential-bearing unencrypted artifact",
    )
    config_generate.add_argument(
        "--raw",
        action="store_true",
        help="write raw binary instead of the usual base64 wrapper",
    )
    config_generate.add_argument("--force", action="store_true")
    config_generate.add_argument(
        "--i-own-or-administer-this-device",
        action="store_true",
        help="acknowledge ownership or explicit authorization",
    )
    config_generate.add_argument(
        "--acknowledge-unverified-compatibility",
        action="store_true",
        help=(
            "acknowledge exact firmware acceptance and recovery are unverified "
            "(offline artifact only)"
        ),
    )
    config_generate.add_argument(
        "--acknowledge-legacy-crypto",
        action="store_true",
        help=("acknowledge the vendor codec's legacy SHA-256 derivation and unauthenticated CBC"),
    )
    config_generate.set_defaults(func=command_config_generate)

    doctor = subparsers.add_parser("doctor", help="validate one private target")
    doctor.add_argument("--host", required=True, help="one RFC1918 or IPv6 ULA literal")
    doctor.add_argument("--ports", default="80,443", help="up to eight explicit TCP ports")
    doctor.add_argument("--probe", action="store_true", help="connect to the listed ports")
    doctor.add_argument("--timeout", type=_parse_timeout_argument, default=1.0)
    doctor.set_defaults(func=command_doctor)

    web_evidence = subparsers.add_parser(
        "web-evidence",
        help="collect sanitized authenticated read-only evidence from one local ZTE target",
    )
    _add_target_arguments(web_evidence)
    web_evidence.add_argument("--host", required=True, help="one RFC1918 or IPv6 ULA literal")
    web_evidence.add_argument("--username", default="admin", help="local web-console username")
    web_evidence.add_argument(
        "--password-stdin",
        action="store_true",
        help="read the local web password from the first stdin line instead of prompting",
    )
    web_evidence.add_argument("--timeout", type=_parse_timeout_argument, default=5.0)
    web_evidence.add_argument(
        "--i-own-or-administer-this-device",
        action="store_true",
        help="acknowledge ownership or explicit authorization",
    )
    web_evidence.add_argument(
        "--acknowledge-local-http-authentication",
        action="store_true",
        help="accept the risk of the firmware's challenge-hash login over local HTTP",
    )
    web_evidence.set_defaults(func=command_web_evidence)

    uart_evidence = subparsers.add_parser(
        "uart-evidence",
        help="inspect a private UART boot log without printing raw or secret values",
    )
    _add_target_arguments(uart_evidence)
    uart_evidence.add_argument("--input", required=True, help="private UART boot-log file")
    uart_evidence.set_defaults(func=command_uart_evidence)

    report = subparsers.add_parser(
        "report-template",
        help="generate a sanitized hardware research template",
    )
    _add_target_arguments(report)
    report.add_argument("--output")
    report.add_argument("--force", action="store_true")
    report.set_defaults(func=command_report_template)

    redact = subparsers.add_parser(
        "redact",
        help="redact common secrets and identifying network data from text",
    )
    redact.add_argument("--input", help="input text file; stdin is used when omitted")
    redact.add_argument("--output")
    redact.add_argument("--force", action="store_true")
    redact.set_defaults(func=command_redact)

    private_protect = subparsers.add_parser(
        "private-protect",
        help="protect a private local artifact with scrypt and AES-GCM",
    )
    private_protect.add_argument("--input", required=True, help="private artifact to protect")
    private_protect.add_argument("--output", required=True, help="protected output path")
    private_protect.add_argument(
        "--passphrase-stdin",
        action="store_true",
        help="read the protection passphrase from stdin instead of prompting",
    )
    private_protect.add_argument("--force", action="store_true")
    private_protect.add_argument(
        "--i-am-authorized-to-handle-this-private-file",
        action="store_true",
        help="acknowledge ownership or explicit authorization for the private file",
    )
    private_protect.set_defaults(func=command_private_protect)

    private_unprotect = subparsers.add_parser(
        "private-unprotect",
        help="decrypt an authenticated private local container",
    )
    private_unprotect.add_argument("--input", required=True, help="protected private container")
    private_unprotect.add_argument("--output", required=True, help="private output path")
    private_unprotect.add_argument(
        "--passphrase-stdin",
        action="store_true",
        help="read the protection passphrase from stdin instead of prompting",
    )
    private_unprotect.add_argument("--force", action="store_true")
    private_unprotect.add_argument(
        "--i-am-authorized-to-handle-this-private-file",
        action="store_true",
        help="acknowledge ownership or explicit authorization for the private file",
    )
    private_unprotect.set_defaults(func=command_private_unprotect)

    firmware = subparsers.add_parser(
        "firmware-inspect",
        help="hash and scan one private firmware artifact without modifying it",
    )
    firmware.add_argument("--input", required=True, help="path to a private firmware artifact")
    firmware.add_argument("--expected-version", help="exact firmware string to check")
    firmware.add_argument(
        "--expected-sha256",
        help="expected SHA-256 hash of the private artifact (64 hexadecimal characters)",
    )
    firmware.add_argument("--json", action="store_true")
    firmware.set_defaults(func=command_firmware_inspect)

    validate = subparsers.add_parser("validate", help="validate bundled catalog data")
    validate.set_defaults(func=command_validate)
    return parser


def _configure_stdio() -> None:
    """Prefer UTF-8 output while leaving test and embedded streams untouched."""

    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is None:
            continue
        try:
            reconfigure(encoding="utf-8", errors="backslashreplace")
        except (AttributeError, OSError, ValueError):
            continue


def main(argv: list[str] | None = None) -> int:
    _configure_stdio()
    parser = build_parser()
    try:
        args = parser.parse_args(argv)
    except SystemExit as exc:
        code = exc.code
        if code is None:
            return 0
        if isinstance(code, int):
            return code
        return 1
    try:
        return int(args.func(args))
    except (
        CatalogError,
        ConfigError,
        FirmwareInspectionError,
        PolicyError,
        PrivateContainerError,
        RedactionError,
        UartEvidenceError,
        WebEvidenceError,
    ) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2
    except OSError as exc:
        print(f"ERROR: filesystem operation failed: {exc}", file=sys.stderr)
        return 1
    except UnicodeError as exc:
        print(f"ERROR: text encoding failed: {exc}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("Interrupted; no retry was attempted.", file=sys.stderr)
        return 130


if __name__ == "__main__":
    raise SystemExit(main())

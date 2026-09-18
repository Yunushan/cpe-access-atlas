# SPDX-License-Identifier: 0BSD
"""Sanitized, offline inspection of owner-captured UART boot logs."""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path


class UartEvidenceError(ValueError):
    """Raised when a UART log cannot be inspected safely."""


@dataclass(frozen=True)
class UartEvidence:
    """Non-secret metadata extracted without opening or controlling a serial port."""

    size: int
    line_count: int
    expected_firmware: str
    firmware_versions: tuple[str, ...]
    firmware_identity_status: str
    bootloader_versions: tuple[str, ...]
    bootloader_builds: tuple[str, ...]
    linux_versions: tuple[str, ...]
    hardware_versions: tuple[str, ...]
    soc_models: tuple[str, ...]
    board_models: tuple[str, ...]
    product_ids: tuple[str, ...]
    dram_mib: tuple[int, ...]
    boot_security: str
    uboot_security: str
    boot_interrupt_prompt_observed: bool
    bootloader_access_gate_observed: bool
    bootloader_shell_prompt_observed: bool
    kernel_start_observed: bool
    linux_console_output_observed: bool
    linux_login_prompt_observed: bool
    uid_zero_marker_observed: bool
    recognized_h3600p_boot_output: bool
    device_io_attempted: bool = False
    raw_log_output: bool = False
    non_allowlisted_values_emitted: bool = False
    root_access_verified: bool = False


MAX_UART_LOG_BYTES = 8 * 1024 * 1024

_FIRMWARE_PATTERN = re.compile(
    rb"(?i)(?<![a-z0-9_.+-])(H3600P[ \t]+V9\.0[ \t]+TTN\.\d+_\d{6})"
    rb"(?![a-z0-9_.+-])"
)
_UBOOT_RELEASE_PATTERN = re.compile(
    rb"(?im)^[ \t]*U-Boot[ \t]+(v?\d{1,4}(?:\.\d{1,4}){1,4}(?:-[a-z0-9._-]{1,12})?)"
    rb"(?:[ \t]+\(((?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)"
    rb"[ \t]+\d{1,2}[ \t]+\d{4}[ \t]+-[ \t]+\d{2}:\d{2}:\d{2})\))?[ \t]*\r?$"
)
_UBOOT_CMDLINE_PATTERN = re.compile(
    rb"(?im)^[ \t]*cmdline=U-Boot[ \t]+(v?\d{1,4}(?:\.\d{1,4}){1,4})"
    rb"(?:[ \t]+([0-9]{8,14}))?[ \t]*\r?$"
)
_LINUX_PATTERN = re.compile(
    rb"(?i)\bLinux version[ \t]+(\d{1,4}(?:\.\d{1,4}){1,4}(?:[-+][a-z0-9._-]{1,12})?)"
)
_HARDWARE_PATTERN = re.compile(
    rb"(?im)^[ \t]*sHardVersion[ \t]*=[ \t]*(V\d{1,4}(?:\.\d{1,4}){1,4})[ \t]*\r?$"
)
_BOARD_PATTERN = re.compile(rb"(?im)^[ \t]*Board:[ \t]*(ZTE[ \t]+zx279128sevb)[ \t]*\r?$")
_PRODUCT_PATTERN = re.compile(
    rb"(?im)^[ \t]*vid[ \t]*=[ \t]*([0-9]{1,4}-H3600PV[0-9]{1,4})[ \t]*\r?$"
)
_DRAM_PATTERN = re.compile(rb"(?im)^[ \t]*[0-9]?DRAM:[ \t]*(\d{1,4})[ \t]+MiB\b")
_UBOOT_PROMPT_PATTERN = re.compile(
    rb"(?im)^[ \t]*=>[ \t]*(?:$|help\b|version\b|printenv\b|echo\b|md(?:\.b)?\b|nand\b)"
)
_LOGIN_PROMPT_PATTERN = re.compile(rb"(?im)^[^\r\n]{0,32}\blogin:[ \t]*\r?$")
_UID_ZERO_PATTERN = re.compile(rb"(?i)(?<![a-z0-9_])uid=0\(root\)(?![a-z0-9_])")


def _extract_ascii(pattern: re.Pattern[bytes], data: bytes, group: int = 1) -> tuple[str, ...]:
    values: set[str] = set()
    for match in pattern.finditer(data):
        value = match.group(group)
        if value is not None:
            values.add(value.decode("ascii"))
    return tuple(sorted(values))


def _security_state(data: bytes, subject: bytes) -> str:
    escaped = re.escape(subject)
    non_secure = re.search(rb"(?im)^[ \t]*non secure " + escaped + rb"[ \t]*\r?$", data)
    secure = re.search(rb"(?im)^[ \t]*secure " + escaped + rb"[ \t]*\r?$", data)
    if non_secure is not None and secure is not None:
        return "conflicting"
    if non_secure is not None:
        return "non-secure"
    if secure is not None:
        return "secure"
    return "not-observed"


def _firmware_status(versions: tuple[str, ...], expected: str) -> str:
    if any(version.casefold() == expected.casefold() for version in versions):
        return "matched"
    if versions:
        return "different-build-observed"
    return "not-observed"


def _validate_arguments(path: str | Path, expected_firmware: str) -> None:
    if not isinstance(path, (str, Path)):
        raise UartEvidenceError("input path must be a string or pathlib.Path")
    if not isinstance(expected_firmware, str) or not expected_firmware.strip():
        raise UartEvidenceError("expected firmware must be a non-empty string")


def inspect_uart_log(path: str | Path, expected_firmware: str) -> UartEvidence:
    """Inspect one private UART capture without emitting its raw contents.

    This function only reads a bounded local file. It does not open a serial
    port, send bytes to a device, infer that an old password still applies, or
    treat an observed prompt as proof of root access.
    """

    _validate_arguments(path, expected_firmware)
    source = Path(path)
    try:
        if not source.is_file():
            raise UartEvidenceError("UART log does not exist or is not a regular file")
        with source.open("rb") as stream:
            data = stream.read(MAX_UART_LOG_BYTES + 1)
    except OSError:
        # OS exceptions can embed the private path. Suppress their text and
        # exception chain in both CLI diagnostics and library tracebacks.
        raise UartEvidenceError("unable to read UART log") from None
    if len(data) > MAX_UART_LOG_BYTES:
        raise UartEvidenceError("UART log exceeds the 8 MiB safety limit")

    firmware_versions = tuple(
        sorted({" ".join(version.split()) for version in _extract_ascii(_FIRMWARE_PATTERN, data)})
    )
    bootloader_versions = set(_extract_ascii(_UBOOT_RELEASE_PATTERN, data))
    bootloader_versions.update(_extract_ascii(_UBOOT_CMDLINE_PATTERN, data))
    bootloader_builds = set(_extract_ascii(_UBOOT_RELEASE_PATTERN, data, 2))
    bootloader_builds.update(_extract_ascii(_UBOOT_CMDLINE_PATTERN, data, 2))
    linux_versions = _extract_ascii(_LINUX_PATTERN, data)
    hardware_versions = _extract_ascii(_HARDWARE_PATTERN, data)
    board_models = _extract_ascii(_BOARD_PATTERN, data)
    product_ids = _extract_ascii(_PRODUCT_PATTERN, data)
    dram_mib = tuple(sorted({int(value) for value in _extract_ascii(_DRAM_PATTERN, data)}))
    soc_models = ("ZX279128S",) if re.search(rb"(?i)\bZX279128S\b", data) else ()

    return UartEvidence(
        size=len(data),
        line_count=len(data.splitlines()),
        expected_firmware=expected_firmware,
        firmware_versions=firmware_versions,
        firmware_identity_status=_firmware_status(firmware_versions, expected_firmware),
        bootloader_versions=tuple(sorted(bootloader_versions)),
        bootloader_builds=tuple(sorted(bootloader_builds)),
        linux_versions=linux_versions,
        hardware_versions=hardware_versions,
        soc_models=soc_models,
        board_models=board_models,
        product_ids=product_ids,
        dram_mib=dram_mib,
        boot_security=_security_state(data, b"boot"),
        uboot_security=_security_state(data, b"uboot"),
        boot_interrupt_prompt_observed=b"Press 1 means entering boot mode" in data,
        bootloader_access_gate_observed=b"Please input bootmode password" in data,
        bootloader_shell_prompt_observed=_UBOOT_PROMPT_PATTERN.search(data) is not None,
        kernel_start_observed=b"Starting kernel" in data,
        linux_console_output_observed=b"Linux version" in data,
        linux_login_prompt_observed=_LOGIN_PROMPT_PATTERN.search(data) is not None,
        uid_zero_marker_observed=_UID_ZERO_PATTERN.search(data) is not None,
        recognized_h3600p_boot_output=bool(
            firmware_versions
            or product_ids
            or (soc_models and (bootloader_versions or linux_versions))
        ),
    )

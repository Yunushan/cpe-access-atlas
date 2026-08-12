# SPDX-License-Identifier: 0BSD
"""Read-only evidence inspection for private firmware artifacts."""

from __future__ import annotations

import re
from dataclasses import dataclass
from hashlib import sha256
from pathlib import Path


class FirmwareInspectionError(ValueError):
    """Raised when a firmware artifact cannot be inspected safely."""


@dataclass(frozen=True)
class FirmwareInspection:
    """Evidence collected without executing, extracting, or modifying an image."""

    path: str
    size: int
    sha256: str
    version_strings: tuple[str, ...]
    markers: tuple[str, ...]
    expected_version: str | None
    exact_build_match: bool | None
    expected_sha256: str | None
    sha256_match: bool | None


_CHUNK_SIZE = 1024 * 1024
_SCAN_OVERLAP = 256
_VERSION_PATTERN = re.compile(
    rb"(?i)H3600P\s+V9\.0\s+TTN\.\d+_\d{6}"
)
_SHA256_PATTERN = re.compile(r"[0-9a-fA-F]{64}")
_MARKERS = (
    ("uImage", b"\x27\x05\x19\x56"),
    ("SquashFS", b"hsqs"),
    ("CramFS", b"\x45\x3d\xcd\x28"),
    ("UBI", b"UBI#"),
    ("gzip", b"\x1f\x8b\x08"),
    ("XZ", b"\xfd7zXZ\x00"),
    ("U-Boot", b"U-Boot"),
    ("Linux", b"Linux version"),
    ("Buildroot", b"Buildroot"),
)


def _validate_arguments(
    path: str | Path,
    expected_version: str | None,
    expected_sha256: str | None,
) -> None:
    if not isinstance(path, (str, Path)):
        raise FirmwareInspectionError("input path must be a string or pathlib.Path")
    if expected_version is not None and (
        not isinstance(expected_version, str) or not expected_version.strip()
    ):
        raise FirmwareInspectionError("expected firmware version must be a non-empty string")
    if expected_sha256 is not None and (
        not isinstance(expected_sha256, str)
        or _SHA256_PATTERN.fullmatch(expected_sha256) is None
    ):
        raise FirmwareInspectionError("expected SHA-256 must be exactly 64 hexadecimal characters")


def inspect_firmware(
    path: str | Path,
    expected_version: str | None = None,
    expected_sha256: str | None = None,
) -> FirmwareInspection:
    """Hash and scan one private artifact without executing or changing it.

    The scanner reads the file as opaque bytes. It does not unpack archives,
    run embedded code, validate signatures, or write any output artifact.
    """

    _validate_arguments(path, expected_version, expected_sha256)
    source = Path(path)
    if not source.is_file():
        raise FirmwareInspectionError(
            f"firmware artifact does not exist or is not a regular file: {source}"
        )

    digest = sha256()
    size = 0
    versions: set[str] = set()
    markers: set[str] = set()
    overlap = b""
    try:
        with source.open("rb") as stream:
            while chunk := stream.read(_CHUNK_SIZE):
                scan_data = overlap + chunk
                digest.update(chunk)
                size += len(chunk)
                for match in _VERSION_PATTERN.finditer(scan_data):
                    versions.add(match.group().decode("ascii"))
                for name, signature in _MARKERS:
                    if signature in scan_data:
                        markers.add(name)
                overlap = scan_data[-_SCAN_OVERLAP:]
    except OSError as exc:
        raise FirmwareInspectionError(f"unable to read firmware artifact: {exc}") from exc

    detected_versions = tuple(sorted(versions))
    exact_build_match = (
        None if expected_version is None else expected_version in detected_versions
    )
    digest_hex = digest.hexdigest()
    sha256_match = (
        None
        if expected_sha256 is None
        else digest_hex.casefold() == expected_sha256.casefold()
    )
    return FirmwareInspection(
        path=str(source),
        size=size,
        sha256=digest_hex,
        version_strings=detected_versions,
        markers=tuple(sorted(markers)),
        expected_version=expected_version,
        exact_build_match=exact_build_match,
        expected_sha256=expected_sha256,
        sha256_match=sha256_match,
    )

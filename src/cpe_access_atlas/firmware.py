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
# A version may straddle a read boundary. Bound its variable-width fields so
# the overlap can always retain the entire candidate and its leading boundary.
# Real build identifiers are far shorter than these defensive limits.
_MAX_VERSION_WHITESPACE = 32
_MAX_VERSION_BUILD_DIGITS = 4096
_MAX_VERSION_BYTES = 6 + 2 * _MAX_VERSION_WHITESPACE + 4 + 4 + _MAX_VERSION_BUILD_DIGITS + 1 + 6
_SCAN_OVERLAP = _MAX_VERSION_BYTES + 1
_MAX_DISTINCT_VERSIONS = 256
_VERSION_PATTERN = re.compile(
    rb"(?i)(?<![a-z0-9_.+-])H3600P\s{1,32}V9\.0\s{1,32}TTN\.\d{1,4096}_\d{6}"
    rb"(?![a-z0-9_.+-])"
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


def _scan_versions(data: bytes, versions: set[str], *, begins_file: bool, ends_file: bool) -> None:
    """Collect bounded, distinct versions with real file token boundaries."""

    for match in _VERSION_PATTERN.finditer(data):
        if (match.start() == 0 and not begins_file) or (match.end() == len(data) and not ends_file):
            continue
        version = match.group().decode("ascii")
        if version not in versions and len(versions) >= _MAX_DISTINCT_VERSIONS:
            raise FirmwareInspectionError("firmware artifact contains too many distinct versions")
        versions.add(version)


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
        not isinstance(expected_sha256, str) or _SHA256_PATTERN.fullmatch(expected_sha256) is None
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
        raise FirmwareInspectionError("firmware artifact does not exist or is not a regular file")

    digest = sha256()
    size = 0
    versions: set[str] = set()
    markers: set[str] = set()
    overlap = b""
    try:
        with source.open("rb") as stream:
            next_byte = stream.read(1)
            while next_byte:
                chunk = next_byte + stream.read(_CHUNK_SIZE - 1)
                next_byte = stream.read(1)
                scan_data = overlap + chunk
                digest.update(chunk)
                size += len(chunk)
                # Check the following byte (or EOF) while a complete bounded
                # candidate and its leading delimiter remain in this window.
                _scan_versions(
                    scan_data + next_byte,
                    versions,
                    begins_file=size == len(scan_data),
                    ends_file=not next_byte,
                )
                for name, signature in _MARKERS:
                    if signature in scan_data:
                        markers.add(name)
                overlap = scan_data[-_SCAN_OVERLAP:]
    except OSError:
        # OS diagnostics can include the private artifact path. Keep both the
        # message and exception chain out of callers' logs.
        raise FirmwareInspectionError("unable to read firmware artifact") from None

    detected_versions = tuple(sorted(versions))
    exact_build_match = None if expected_version is None else expected_version in detected_versions
    digest_hex = digest.hexdigest()
    sha256_match = (
        None if expected_sha256 is None else digest_hex.casefold() == expected_sha256.casefold()
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

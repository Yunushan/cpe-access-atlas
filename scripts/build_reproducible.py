# SPDX-License-Identifier: 0BSD
"""Build and independently verify byte-reproducible wheel and source archives."""

from __future__ import annotations

import argparse
import ast
import base64
import configparser
import csv
import hashlib
import io
import os
import re
import shutil
import stat
import struct
import subprocess
import sys
import tarfile
import time
import tomllib
import unicodedata
import zipfile
import zlib
from collections.abc import Iterable
from dataclasses import dataclass
from email.message import Message
from email.parser import Parser
from email.policy import default
from pathlib import Path, PurePosixPath, PureWindowsPath
from tempfile import NamedTemporaryFile, TemporaryDirectory

from packaging.requirements import InvalidRequirement, Requirement
from packaging.specifiers import InvalidSpecifier, SpecifierSet
from packaging.utils import canonicalize_name
from packaging.version import InvalidVersion, Version

ROOT = Path(__file__).resolve().parents[1]
_MIN_ZIP_EPOCH = 315532800  # 1980-01-01; wheels use the ZIP timestamp range.
_MAX_GZIP_EPOCH = 0xFFFFFFFF
_MAX_SDIST_BYTES = 64 * 1024 * 1024
_MAX_WHEEL_BYTES = 64 * 1024 * 1024
_MAX_SDIST_MEMBERS = 4096
_MAX_EXPANDED_BYTES = 128 * 1024 * 1024
_MAX_ARCHIVE_PATH_BYTES = 255
_GIT_OBJECT_ID = re.compile(r"[0-9a-fA-F]{40}|[0-9a-fA-F]{64}")
_WINDOWS_INVALID_CHARACTERS = frozenset('<>:"\\|?*')
_WINDOWS_RESERVED_BASENAMES = frozenset(
    {
        "aux",
        "con",
        "conin$",
        "conout$",
        "nul",
        "prn",
        *(f"com{suffix}" for suffix in (*range(1, 10), "¹", "²", "³")),
        *(f"lpt{suffix}" for suffix in (*range(1, 10), "¹", "²", "³")),
    }
)
_WHEEL_GENERATED_TEXT = frozenset({"METADATA", "WHEEL", "entry_points.txt", "top_level.txt"})
_SDIST_EGG_INFO_TEXT = frozenset(
    {
        "PKG-INFO",
        "SOURCES.txt",
        "dependency_links.txt",
        "entry_points.txt",
        "requires.txt",
        "top_level.txt",
    }
)


class ReproducibleBuildError(ValueError):
    """The local build cannot be proved byte-reproducible."""


@dataclass(frozen=True)
class WheelSourceBinding:
    """Immutable source and metadata expectations captured before backend execution."""

    project_name: str
    package_name: str
    version: str
    requires_python: str
    requirements: frozenset[Requirement]
    extras: frozenset[str]
    scripts: tuple[tuple[str, str], ...]
    package_entries: tuple[tuple[str, bytes], ...]
    license_expression: str
    license_entries: tuple[tuple[str, bytes], ...]


@dataclass(frozen=True)
class BuiltArtifact:
    """One bounded, verified artifact captured independently of its mutable path."""

    name: str
    payload: bytes


class _CaseSensitiveConfigParser(configparser.ConfigParser):
    def optionxform(self, optionstr: str) -> str:
        return optionstr


def validate_portable_archive_path(name: str) -> PurePosixPath:
    """Return one canonical relative path that is safe on every supported OS."""

    path = PurePosixPath(name)
    canonical_name = path.as_posix()
    if (
        not path.parts
        or path.is_absolute()
        or ".." in path.parts
        or canonical_name != name
        or unicodedata.normalize("NFC", canonical_name) != canonical_name
    ):
        raise ReproducibleBuildError("archive path is unsafe or not portable")
    try:
        encoded_name = canonical_name.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise ReproducibleBuildError("archive path is unsafe or not portable") from exc
    if len(encoded_name) > _MAX_ARCHIVE_PATH_BYTES:
        raise ReproducibleBuildError("archive path is unsafe or not portable")
    for component in path.parts:
        reserved_basename = component.split(".", 1)[0].rstrip(" ").casefold()
        has_unsupported_character = any(
            unicodedata.category(character) in {"Cc", "Cs", "Cn"}
            or unicodedata.ucd_3_2_0.category(character) == "Cn"
            for character in component
        )
        if (
            component.endswith((" ", "."))
            or reserved_basename in _WINDOWS_RESERVED_BASENAMES
            or PureWindowsPath(component).drive
            or any(character in _WINDOWS_INVALID_CHARACTERS for character in component)
            or has_unsupported_character
            or len(component.encode("utf-8")) > 255
        ):
            raise ReproducibleBuildError("archive path is unsafe or not portable")
    return path


def _validate_portable_path_inventory(
    entries: Iterable[tuple[PurePosixPath, bool]],
) -> None:
    """Reject portable-path hierarchies that change meaning across filesystems."""

    prefix_spellings: dict[str, str] = {}
    ancestor_names: set[str] = set()
    regular_file_names: set[str] = set()
    for path, is_directory in entries:
        for length in range(1, len(path.parts) + 1):
            prefix = PurePosixPath(*path.parts[:length]).as_posix()
            folded = prefix.casefold()
            previous = prefix_spellings.setdefault(folded, prefix)
            if previous != prefix:
                raise ReproducibleBuildError(
                    "archive path inventory has a case-insensitive hierarchy collision"
                )
            if length < len(path.parts):
                ancestor_names.add(folded)
        if not is_directory:
            regular_file_names.add(path.as_posix().casefold())
    if regular_file_names & ancestor_names:
        raise ReproducibleBuildError(
            "archive path inventory has a file/directory hierarchy collision"
        )


def _requirement_without_marker(requirement: Requirement) -> str:
    extras = f"[{','.join(sorted(requirement.extras))}]" if requirement.extras else ""
    result = f"{requirement.name}{extras}"
    if requirement.url is not None:
        return f"{result} @ {requirement.url}"
    return f"{result}{requirement.specifier}"


def _optional_requirement(value: str, extra: str) -> Requirement:
    requirement = Requirement(value)
    extra_marker = f'extra == "{extra}"'
    marker = (
        f"({requirement.marker}) and {extra_marker}"
        if requirement.marker is not None
        else extra_marker
    )
    separator = " ; " if requirement.url is not None else "; "
    return Requirement(f"{_requirement_without_marker(requirement)}{separator}{marker}")


def _source_version(package_directory: Path) -> str:
    try:
        tree = ast.parse((package_directory / "__init__.py").read_text(encoding="utf-8"))
    except (OSError, SyntaxError, UnicodeError) as exc:
        raise ReproducibleBuildError("package version source is unavailable or invalid") from exc
    versions = [
        node.value.value
        for node in tree.body
        if isinstance(node, ast.Assign)
        and any(
            isinstance(target, ast.Name) and target.id == "__version__" for target in node.targets
        )
        and isinstance(node.value, ast.Constant)
        and isinstance(node.value.value, str)
    ]
    if len(versions) != 1:
        raise ReproducibleBuildError("package version must be one literal __version__ assignment")
    try:
        return str(Version(versions[0]))
    except InvalidVersion as exc:
        raise ReproducibleBuildError("package version is invalid") from exc


def capture_wheel_source_binding(root: Path) -> WheelSourceBinding:
    """Capture exact wheel expectations before the build backend can mutate source."""

    try:
        document = tomllib.loads((root / "pyproject.toml").read_text(encoding="utf-8"))
    except (OSError, tomllib.TOMLDecodeError, UnicodeError) as exc:
        raise ReproducibleBuildError("project metadata is unavailable or invalid") from exc
    project = document.get("project")
    if not isinstance(project, dict):
        raise ReproducibleBuildError("project metadata table is missing")

    project_name = project.get("name")
    if not isinstance(project_name, str) or not project_name:
        raise ReproducibleBuildError("project name is missing or invalid")
    package_name = canonicalize_name(project_name).replace("-", "_")
    package_directory = root / "src" / package_name
    if not package_directory.is_dir():
        raise ReproducibleBuildError("project package directory is missing")

    dynamic = project.get("dynamic")
    tool = document.get("tool")
    setuptools = tool.get("setuptools") if isinstance(tool, dict) else None
    dynamic_config = setuptools.get("dynamic") if isinstance(setuptools, dict) else None
    version_config = dynamic_config.get("version") if isinstance(dynamic_config, dict) else None
    version_attribute = version_config.get("attr") if isinstance(version_config, dict) else None
    if (
        not isinstance(dynamic, list)
        or dynamic.count("version") != 1
        or version_attribute != f"{package_name}.__version__"
    ):
        raise ReproducibleBuildError("project version binding is missing or invalid")
    version = _source_version(package_directory)

    requires_python = project.get("requires-python")
    if not isinstance(requires_python, str):
        raise ReproducibleBuildError("project Python requirement is missing or invalid")
    try:
        requires_python = str(SpecifierSet(requires_python))
    except InvalidSpecifier as exc:
        raise ReproducibleBuildError("project Python requirement is invalid") from exc

    dependency_values = project.get("dependencies")
    optional_values = project.get("optional-dependencies")
    script_values = project.get("scripts")
    license_expression = project.get("license")
    license_file_values = project.get("license-files")
    if not isinstance(dependency_values, list) or not all(
        isinstance(value, str) for value in dependency_values
    ):
        raise ReproducibleBuildError("project dependencies are missing or invalid")
    if not isinstance(optional_values, dict) or not all(
        isinstance(extra, str)
        and isinstance(values, list)
        and all(isinstance(value, str) for value in values)
        for extra, values in optional_values.items()
    ):
        raise ReproducibleBuildError("project optional dependencies are missing or invalid")
    if not isinstance(script_values, dict) or not all(
        isinstance(name, str) and isinstance(value, str) for name, value in script_values.items()
    ):
        raise ReproducibleBuildError("project scripts are missing or invalid")
    if (
        not isinstance(license_expression, str)
        or not license_expression
        or license_expression.strip() != license_expression
        or "\r" in license_expression
        or "\n" in license_expression
    ):
        raise ReproducibleBuildError("project license expression is missing or invalid")
    if (
        not isinstance(license_file_values, list)
        or not license_file_values
        or not all(isinstance(value, str) for value in license_file_values)
    ):
        raise ReproducibleBuildError("project license files are missing or invalid")
    try:
        license_paths = tuple(
            validate_portable_archive_path(value) for value in license_file_values
        )
        _validate_portable_path_inventory((path, False) for path in license_paths)
    except ReproducibleBuildError as exc:
        raise ReproducibleBuildError("project license files are missing or invalid") from exc
    if len(license_paths) != len({path.as_posix() for path in license_paths}):
        raise ReproducibleBuildError("project license files contain duplicates")
    try:
        license_entries = tuple(
            (path.as_posix(), (root.joinpath(*path.parts)).read_bytes()) for path in license_paths
        )
    except OSError as exc:
        raise ReproducibleBuildError("project license file payload is unavailable") from exc

    try:
        requirements = [Requirement(value) for value in dependency_values]
        extras = [canonicalize_name(extra) for extra in optional_values]
        requirements.extend(
            _optional_requirement(value, canonicalize_name(extra))
            for extra, values in optional_values.items()
            for value in values
        )
    except InvalidRequirement as exc:
        raise ReproducibleBuildError("project dependency requirement is invalid") from exc
    if len(requirements) != len(set(requirements)) or len(extras) != len(set(extras)):
        raise ReproducibleBuildError("project dependency metadata contains duplicates")

    package_entries: list[tuple[str, bytes]] = []
    for source in sorted(path for path in package_directory.rglob("*") if path.is_file()):
        relative = source.relative_to(package_directory).as_posix()
        archive_path = validate_portable_archive_path(f"{package_name}/{relative}").as_posix()
        package_entries.append((archive_path, source.read_bytes()))
    if not package_entries:
        raise ReproducibleBuildError("project package has no wheel payload")

    scripts = tuple(sorted((str(name), str(value)) for name, value in script_values.items()))
    return WheelSourceBinding(
        project_name=project_name,
        package_name=package_name,
        version=version,
        requires_python=requires_python,
        requirements=frozenset(requirements),
        extras=frozenset(extras),
        scripts=scripts,
        package_entries=tuple(package_entries),
        license_expression=license_expression,
        license_entries=license_entries,
    )


def parse_epoch(value: str) -> int:
    """Parse a SOURCE_DATE_EPOCH that is valid for both ZIP and gzip."""

    if len(value) > 10 or not value.isascii() or not value.isdecimal():
        raise ReproducibleBuildError("build epoch must be an unsigned decimal integer")
    epoch = int(value)
    if not _MIN_ZIP_EPOCH <= epoch <= _MAX_GZIP_EPOCH:
        raise ReproducibleBuildError("build epoch is outside the supported archive range")
    return epoch


def source_date_epoch(root: Path = ROOT, source_ref: str = "HEAD") -> int:
    """Use an explicit epoch or the reviewed Git commit's committer timestamp."""

    configured = os.environ.get("SOURCE_DATE_EPOCH")
    if configured is not None:
        return parse_epoch(configured)
    result = subprocess.run(  # noqa: S603 -- fixed Git executable and reviewed source ref
        [  # noqa: S607 -- fixed Git query and prevalidated object id
            "git",
            "show",
            "-s",
            "--format=%ct",
            source_ref,
        ],
        cwd=root,
        capture_output=True,
        text=True,
        check=True,
        timeout=30,
    )
    return parse_epoch(result.stdout.strip())


def resolve_source_commit(root: Path, source_ref: str) -> str:
    """Resolve a constrained ref to the immutable commit used for the build."""

    if source_ref != "HEAD" and _GIT_OBJECT_ID.fullmatch(source_ref) is None:
        raise ReproducibleBuildError("source ref must be HEAD or a full Git object id")
    result = subprocess.run(  # noqa: S603 -- fixed Git executable and constrained ref
        [  # noqa: S607 -- source ref is constrained above; no shell is involved
            "git",
            "rev-parse",
            "--verify",
            f"{source_ref}^{{commit}}",
        ],
        cwd=root,
        capture_output=True,
        text=True,
        check=True,
        timeout=30,
    )
    commit = result.stdout.strip()
    if _GIT_OBJECT_ID.fullmatch(commit) is None:
        raise ReproducibleBuildError("Git returned an invalid source commit id")
    return commit.lower()


def _validated_members(archive: tarfile.TarFile) -> tuple[tarfile.TarInfo, ...]:
    members: list[tarfile.TarInfo] = []
    names: set[str] = set()
    casefolded_names: set[str] = set()
    expanded = 0
    while (member := archive.next()) is not None:
        if len(members) >= _MAX_SDIST_MEMBERS:
            raise ReproducibleBuildError("source archive has an invalid member count")
        try:
            path = validate_portable_archive_path(member.name)
        except ReproducibleBuildError as exc:
            raise ReproducibleBuildError("source archive has an unsafe or duplicate path") from exc
        canonical_name = path.as_posix()
        folded = canonical_name.casefold()
        if canonical_name in names or folded in casefolded_names:
            raise ReproducibleBuildError("source archive has an unsafe or duplicate path")
        names.add(canonical_name)
        casefolded_names.add(folded)
        if member.type not in {tarfile.REGTYPE, tarfile.AREGTYPE, tarfile.DIRTYPE}:
            raise ReproducibleBuildError("source archive contains a link or special file")
        if member.size < 0 or (member.isdir() and member.size != 0):
            raise ReproducibleBuildError("source archive member has an invalid size")
        expanded += member.size
        if expanded > _MAX_EXPANDED_BYTES:
            raise ReproducibleBuildError("source archive exceeds the expanded-size limit")
        members.append(member)
    if not members:
        raise ReproducibleBuildError("source archive has an invalid member count")
    try:
        _validate_portable_path_inventory(
            (validate_portable_archive_path(member.name), member.isdir()) for member in members
        )
    except ReproducibleBuildError as exc:
        raise ReproducibleBuildError("source archive has an unsafe or duplicate path") from exc
    return tuple(members)


def canonicalize_sdist(path: Path, epoch: int) -> bytes:
    """Replace build-time tar/gzip metadata without extracting archive contents."""

    parse_epoch(str(epoch))
    if not path.name.endswith(".tar.gz"):
        raise ReproducibleBuildError("source archive must use the .tar.gz format")
    size = path.stat().st_size
    if not 0 < size <= _MAX_SDIST_BYTES:
        raise ReproducibleBuildError("source archive has an invalid compressed size")

    with NamedTemporaryFile(
        dir=path.parent,
        prefix=f".{path.name}.",
        suffix=".tmp",
        delete=False,
    ) as temporary:
        temporary_path = Path(temporary.name)
    try:
        with tarfile.open(path, "r:gz") as source:
            members = tuple(sorted(_validated_members(source), key=lambda member: member.name))
            roots = {PurePosixPath(member.name).parts[0] for member in members}
            if len(roots) != 1:
                raise ReproducibleBuildError("source archive must contain one top-level root")
            root = next(iter(roots))
            raw_tar = io.BytesIO()
            with tarfile.open(
                fileobj=raw_tar,
                mode="w:",
                format=tarfile.USTAR_FORMAT,
            ) as target:
                for member in members:
                    canonical = tarfile.TarInfo(member.name)
                    canonical.type = tarfile.DIRTYPE if member.isdir() else tarfile.REGTYPE
                    canonical.mtime = epoch
                    canonical.uid = 0
                    canonical.gid = 0
                    canonical.uname = ""
                    canonical.gname = ""
                    canonical.mode = 0o755 if member.isdir() else 0o644
                    canonical.pax_headers = {}
                    canonical.linkname = ""
                    canonical.devmajor = 0
                    canonical.devminor = 0
                    canonical_payload: io.BytesIO | None = None
                    if not member.isdir():
                        payload = source.extractfile(member)
                        if payload is None:
                            raise ReproducibleBuildError(
                                "source archive regular file has no payload"
                            )
                        with payload:
                            data = payload.read()
                        archive_path = PurePosixPath(member.name)
                        is_root_metadata = member.name in {
                            f"{root}/PKG-INFO",
                            f"{root}/setup.cfg",
                        }
                        is_egg_info_metadata = (
                            archive_path.parent.name.endswith(".egg-info")
                            and archive_path.name in _SDIST_EGG_INFO_TEXT
                        )
                        if is_root_metadata or is_egg_info_metadata:
                            data = _normalize_newlines(data)
                        canonical.size = len(data)
                        canonical_payload = io.BytesIO(data)
                    try:
                        target.addfile(canonical, canonical_payload)
                    except ValueError as exc:
                        raise ReproducibleBuildError(
                            "source archive path cannot be represented canonically"
                        ) from exc
            canonical_archive = _gzip_stored(raw_tar.getvalue(), epoch)
            temporary_path.write_bytes(canonical_archive)
        if len(canonical_archive) > _MAX_SDIST_BYTES:
            raise ReproducibleBuildError(
                "canonical source archive exceeds the compressed-size limit"
            )
        temporary_path.replace(path)
        os.utime(path, (epoch, epoch))
        return canonical_archive
    except BaseException:
        temporary_path.unlink(missing_ok=True)
        raise


def _normalize_newlines(payload: bytes) -> bytes:
    return payload.replace(b"\r\n", b"\n").replace(b"\r", b"\n")


def _gzip_stored(payload: bytes, epoch: int) -> bytes:
    """Encode gzip with raw stored DEFLATE blocks, independent of zlib versions."""

    header = b"\x1f\x8b\x08\x00" + struct.pack("<I", epoch) + b"\x00\xff"
    encoded = bytearray(header)
    if payload:
        offsets = range(0, len(payload), 0xFFFF)
        for offset in offsets:
            block = payload[offset : offset + 0xFFFF]
            final = offset + len(block) == len(payload)
            encoded.append(1 if final else 0)
            encoded.extend(struct.pack("<HH", len(block), len(block) ^ 0xFFFF))
            encoded.extend(block)
    else:
        encoded.extend(b"\x01\x00\x00\xff\xff")
    encoded.extend(struct.pack("<II", zlib.crc32(payload) & 0xFFFFFFFF, len(payload) & 0xFFFFFFFF))
    return bytes(encoded)


def _validated_wheel_entries(archive: zipfile.ZipFile) -> dict[str, bytes]:
    entries: dict[str, bytes] = {}
    folded_names: set[str] = set()
    expanded = 0
    for member in archive.infolist():
        if len(entries) >= _MAX_SDIST_MEMBERS:
            raise ReproducibleBuildError("wheel has an invalid member count")
        try:
            path = validate_portable_archive_path(member.filename)
        except ReproducibleBuildError as exc:
            raise ReproducibleBuildError("wheel has an unsafe, duplicate, or special path") from exc
        canonical_name = path.as_posix()
        folded_name = canonical_name.casefold()
        unix_mode = member.external_attr >> 16
        if (
            member.orig_filename != member.filename
            or canonical_name in entries
            or folded_name in folded_names
            or member.is_dir()
            or (stat.S_IFMT(unix_mode) not in {0, stat.S_IFREG})
        ):
            raise ReproducibleBuildError("wheel has an unsafe, duplicate, or special path")
        if member.flag_bits & 0x1 or member.file_size < 0:
            raise ReproducibleBuildError("wheel contains an encrypted or invalid member")
        expanded += member.file_size
        if expanded > _MAX_EXPANDED_BYTES:
            raise ReproducibleBuildError("wheel exceeds the expanded-size limit")
        try:
            payload = archive.read(member)
        except (RuntimeError, zipfile.BadZipFile, zlib.error) as exc:
            raise ReproducibleBuildError("wheel member failed its integrity check") from exc
        if len(payload) != member.file_size:
            raise ReproducibleBuildError("wheel member has an invalid size")
        entries[canonical_name] = payload
        folded_names.add(folded_name)
    if not entries:
        raise ReproducibleBuildError("wheel has an invalid member count")
    try:
        _validate_portable_path_inventory(
            (validate_portable_archive_path(name), False) for name in entries
        )
    except ReproducibleBuildError as exc:
        raise ReproducibleBuildError("wheel has an unsafe, duplicate, or special path") from exc
    return entries


def _wheel_record(entries: dict[str, bytes], record_name: str) -> bytes:
    output = io.StringIO(newline="")
    writer = csv.writer(output, lineterminator="\n")
    for name in sorted(entries):
        if name == record_name:
            continue
        digest = base64.urlsafe_b64encode(hashlib.sha256(entries[name]).digest()).rstrip(b"=")
        writer.writerow((name, f"sha256={digest.decode('ascii')}", len(entries[name])))
    writer.writerow((record_name, "", ""))
    return output.getvalue().encode("utf-8")


def _verify_wheel_record(entries: dict[str, bytes], record_name: str) -> None:
    signature_names = {f"{record_name}.jws", f"{record_name}.p7s"}
    if entries.keys() & signature_names:
        raise ReproducibleBuildError("signed wheel RECORD files are not supported")
    try:
        rows = tuple(
            csv.reader(
                io.StringIO(entries[record_name].decode("utf-8"), newline=""),
                strict=True,
            )
        )
    except (UnicodeDecodeError, csv.Error) as exc:
        raise ReproducibleBuildError("wheel RECORD is malformed") from exc
    by_name: dict[str, tuple[str, str]] = {}
    for row in rows:
        if len(row) != 3 or row[0] in by_name:
            raise ReproducibleBuildError("wheel RECORD is malformed")
        by_name[row[0]] = (row[1], row[2])
    if by_name.keys() != entries.keys():
        raise ReproducibleBuildError("wheel RECORD inventory does not match its members")
    for name, payload in entries.items():
        digest, size = by_name[name]
        if name == record_name:
            if digest or size:
                raise ReproducibleBuildError("wheel RECORD self-entry must be unhashed")
            continue
        expected = base64.urlsafe_b64encode(hashlib.sha256(payload).digest()).rstrip(b"=")
        if digest != f"sha256={expected.decode('ascii')}" or size != str(len(payload)):
            raise ReproducibleBuildError("wheel RECORD integrity check failed")


def _verified_wheel_entries(source_path: Path | io.BytesIO) -> tuple[dict[str, bytes], str, str]:
    with zipfile.ZipFile(source_path, "r") as source:
        entries = _validated_wheel_entries(source)
    dist_info_roots = {
        PurePosixPath(name).parts[0]
        for name in entries
        if PurePosixPath(name).parts[0].endswith(".dist-info")
    }
    if len(dist_info_roots) != 1:
        raise ReproducibleBuildError("wheel must contain exactly one dist-info directory")
    dist_info = next(iter(dist_info_roots))
    record_name = f"{dist_info}/RECORD"
    if record_name not in entries:
        raise ReproducibleBuildError("wheel is missing its RECORD")
    _verify_wheel_record(entries, record_name)
    return entries, dist_info, record_name


def _metadata_message(payload: bytes, label: str) -> Message:
    try:
        message = Parser(policy=default).parsestr(payload.decode("utf-8"))
    except (UnicodeDecodeError, ValueError) as exc:
        raise ReproducibleBuildError(f"wheel {label} metadata is malformed") from exc
    if message.defects:
        raise ReproducibleBuildError(f"wheel {label} metadata is malformed")
    return message


def _single_metadata_header(message: Message, name: str, label: str) -> str:
    values = tuple(str(value) for value in message.get_all(name, []))
    if len(values) != 1:
        raise ReproducibleBuildError(f"wheel {label} must contain exactly one {name} header")
    return values[0]


def verify_wheel_source(path: Path, binding: WheelSourceBinding) -> None:
    """Bind every installable wheel member and critical metadata to reviewed source."""

    entries, dist_info, _record_name = _verified_wheel_entries(path)
    _verify_wheel_source_entries(path.name, entries, dist_info, binding)


def _verify_wheel_payload(filename: str, payload: bytes, binding: WheelSourceBinding) -> None:
    if not 0 < len(payload) <= _MAX_WHEEL_BYTES:
        raise ReproducibleBuildError("verified wheel payload has an invalid size")
    entries, dist_info, _record_name = _verified_wheel_entries(io.BytesIO(payload))
    _verify_wheel_source_entries(filename, entries, dist_info, binding)


def _verify_wheel_source_entries(
    filename: str,
    entries: dict[str, bytes],
    dist_info: str,
    binding: WheelSourceBinding,
) -> None:
    distribution = canonicalize_name(binding.project_name).replace("-", "_")
    expected_dist_info = f"{distribution}-{binding.version}.dist-info"
    expected_filename = f"{distribution}-{binding.version}-py3-none-any.whl"
    if filename != expected_filename or dist_info != expected_dist_info:
        raise ReproducibleBuildError("wheel filename or dist-info identity differs from source")

    generated_names = {
        f"{dist_info}/METADATA",
        f"{dist_info}/RECORD",
        f"{dist_info}/WHEEL",
        f"{dist_info}/top_level.txt",
        *(f"{dist_info}/licenses/{name}" for name, _payload in binding.license_entries),
    }
    if binding.scripts:
        generated_names.add(f"{dist_info}/entry_points.txt")
    package_entries = dict(binding.package_entries)
    expected_names = set(package_entries) | generated_names
    if entries.keys() != expected_names:
        raise ReproducibleBuildError(
            "wheel member inventory contains missing or unexpected installable files"
        )
    for name, payload in package_entries.items():
        if entries[name] != payload:
            raise ReproducibleBuildError(f"wheel package payload differs from source: {name}")
    for name, payload in binding.license_entries:
        if entries[f"{dist_info}/licenses/{name}"] != payload:
            raise ReproducibleBuildError(f"wheel license payload differs from source: {name}")
    if entries[f"{dist_info}/top_level.txt"] != f"{binding.package_name}\n".encode():
        raise ReproducibleBuildError("wheel top-level package metadata differs from source")

    wheel = _metadata_message(entries[f"{dist_info}/WHEEL"], "WHEEL")
    wheel_headers = {
        "Wheel-Version": "1.0",
        "Root-Is-Purelib": "true",
        "Tag": "py3-none-any",
    }
    for name, expected in wheel_headers.items():
        if _single_metadata_header(wheel, name, "WHEEL") != expected:
            raise ReproducibleBuildError(f"wheel WHEEL {name} header differs from source policy")

    metadata = _metadata_message(entries[f"{dist_info}/METADATA"], "METADATA")
    metadata_headers = {
        "Metadata-Version": "2.4",
        "Name": binding.project_name,
        "Version": binding.version,
        "License-Expression": binding.license_expression,
    }
    for name, expected in metadata_headers.items():
        if _single_metadata_header(metadata, name, "METADATA") != expected:
            raise ReproducibleBuildError(f"wheel METADATA {name} header differs from source")
    actual_python = _single_metadata_header(metadata, "Requires-Python", "METADATA")
    try:
        python_requirement = str(SpecifierSet(actual_python))
    except InvalidSpecifier as exc:
        raise ReproducibleBuildError("wheel METADATA Requires-Python header is invalid") from exc
    if python_requirement != binding.requires_python:
        raise ReproducibleBuildError("wheel Python requirement differs from source")

    license_files = tuple(str(value) for value in metadata.get_all("License-File", []))
    expected_license_files = tuple(name for name, _payload in binding.license_entries)
    if len(license_files) != len(set(license_files)) or frozenset(license_files) != frozenset(
        expected_license_files
    ):
        raise ReproducibleBuildError("wheel license-file metadata differs from source")

    requirement_values = tuple(str(value) for value in metadata.get_all("Requires-Dist", []))
    try:
        requirements = tuple(Requirement(value) for value in requirement_values)
    except InvalidRequirement as exc:
        raise ReproducibleBuildError("wheel dependency metadata is invalid") from exc
    if (
        len(requirements) != len(set(requirements))
        or frozenset(requirements) != binding.requirements
    ):
        raise ReproducibleBuildError("wheel dependency metadata differs from source")
    extra_values = tuple(str(value) for value in metadata.get_all("Provides-Extra", []))
    extras = tuple(canonicalize_name(value) for value in extra_values)
    if len(extras) != len(set(extras)) or frozenset(extras) != binding.extras:
        raise ReproducibleBuildError("wheel optional-dependency metadata differs from source")

    if binding.scripts:
        parser = _CaseSensitiveConfigParser(interpolation=None, delimiters=("=",), strict=True)
        try:
            parser.read_string(entries[f"{dist_info}/entry_points.txt"].decode("utf-8"))
        except (UnicodeDecodeError, configparser.Error) as exc:
            raise ReproducibleBuildError("wheel entry-point metadata is malformed") from exc
        if (
            parser.defaults()
            or parser.sections() != ["console_scripts"]
            or tuple(sorted(parser.items("console_scripts", raw=True))) != binding.scripts
        ):
            raise ReproducibleBuildError("wheel entry-point metadata differs from source")


def canonicalize_wheel(path: Path, epoch: int) -> bytes:
    """Rewrite a pure-Python wheel with platform-neutral metadata and RECORD."""

    parse_epoch(str(epoch))
    if path.suffix != ".whl":
        raise ReproducibleBuildError("wheel archive must use the .whl format")
    size = path.stat().st_size
    if not 0 < size <= _MAX_WHEEL_BYTES:
        raise ReproducibleBuildError("wheel has an invalid compressed size")

    entries, dist_info, record_name = _verified_wheel_entries(path)
    for name, payload in tuple(entries.items()):
        archive_path = PurePosixPath(name)
        if archive_path.parts[0] == dist_info and archive_path.name in _WHEEL_GENERATED_TEXT:
            entries[name] = _normalize_newlines(payload)
    entries[record_name] = _wheel_record(entries, record_name)

    with NamedTemporaryFile(
        dir=path.parent,
        prefix=f".{path.name}.",
        suffix=".tmp",
        delete=False,
    ) as temporary:
        temporary_path = Path(temporary.name)
    try:
        zip_timestamp = time.gmtime(epoch)[:6]
        canonical_buffer = io.BytesIO()
        with zipfile.ZipFile(canonical_buffer, "w", allowZip64=False) as target:
            ordered_names = [name for name in sorted(entries) if name != record_name]
            ordered_names.append(record_name)
            for name in ordered_names:
                member = zipfile.ZipInfo(name, date_time=zip_timestamp)
                member.compress_type = zipfile.ZIP_STORED
                member.create_system = 3
                member.external_attr = (stat.S_IFREG | 0o644) << 16
                target.writestr(member, entries[name])
        canonical_archive = canonical_buffer.getvalue()
        if len(canonical_archive) > _MAX_WHEEL_BYTES:
            raise ReproducibleBuildError("canonical wheel exceeds the compressed-size limit")
        temporary_path.write_bytes(canonical_archive)
        temporary_path.replace(path)
        os.utime(path, (epoch, epoch))
        return canonical_archive
    except BaseException:
        temporary_path.unlink(missing_ok=True)
        raise


def _artifacts(dist_dir: Path) -> tuple[Path, Path]:
    entries = tuple(sorted(path for path in dist_dir.iterdir() if path.is_file()))
    wheels = tuple(path for path in entries if path.name.endswith(".whl"))
    sdists = tuple(path for path in entries if path.name.endswith(".tar.gz"))
    if len(entries) != 2 or len(wheels) != 1 or len(sdists) != 1:
        raise ReproducibleBuildError(
            "distribution directory must contain exactly one wheel and one source archive"
        )
    return wheels[0], sdists[0]


def _digest(path: Path) -> str:
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def _artifact_directory_matches(
    directory: Path,
    identity: tuple[int, int],
    expected: dict[str, bytes],
) -> bool:
    try:
        directory_stat = directory.stat(follow_symlinks=False)
        entries = tuple(directory.iterdir())
        if (
            not stat.S_ISDIR(directory_stat.st_mode)
            or (directory_stat.st_dev, directory_stat.st_ino) != identity
            or {entry.name for entry in entries} != expected.keys()
        ):
            return False
        return all(
            stat.S_ISREG(entry.stat(follow_symlinks=False).st_mode)
            and entry.stat(follow_symlinks=False).st_size == len(expected[entry.name])
            and entry.read_bytes() == expected[entry.name]
            for entry in entries
        )
    except OSError:
        return False


def _copy_source_snapshot(
    root: Path,
    destination: Path,
    epoch: int,
    source_ref: str = "HEAD",
) -> None:
    """Materialize immutable Git blob bytes into a normalized source snapshot."""

    commit = resolve_source_commit(root, source_ref)
    inventory = subprocess.run(  # noqa: S603 -- fixed Git executable and exact commit
        [  # noqa: S607 -- exact validated commit; read-only object inventory
            "git",
            "ls-tree",
            "-r",
            "-z",
            "--full-tree",
            commit,
        ],
        cwd=root,
        capture_output=True,
        check=True,
        timeout=30,
    ).stdout
    records = tuple(record for record in inventory.split(b"\0") if record)
    if not records or len(records) > _MAX_SDIST_MEMBERS:
        raise ReproducibleBuildError("Git source tree has an invalid member count")
    names: set[str] = set()
    casefolded_names: set[str] = set()
    source_entries: list[tuple[PurePosixPath, str]] = []
    expanded = 0
    for record in records:
        try:
            metadata, encoded_name = record.split(b"\t", 1)
            mode, object_type, encoded_object = metadata.split(b" ", 2)
            name = encoded_name.decode("ascii")
            object_id = encoded_object.decode("ascii")
        except (UnicodeDecodeError, ValueError) as exc:
            raise ReproducibleBuildError("Git source tree has an invalid entry") from exc
        try:
            path = validate_portable_archive_path(name)
        except ReproducibleBuildError as exc:
            raise ReproducibleBuildError("Git source tree has an unsafe or special entry") from exc
        canonical_name = path.as_posix()
        folded = canonical_name.casefold()
        if (
            mode not in {b"100644", b"100755"}
            or object_type != b"blob"
            or _GIT_OBJECT_ID.fullmatch(object_id) is None
            or canonical_name in names
            or folded in casefolded_names
        ):
            raise ReproducibleBuildError("Git source tree has an unsafe or special entry")
        names.add(canonical_name)
        casefolded_names.add(folded)
        source_entries.append((path, object_id))
    try:
        _validate_portable_path_inventory((path, False) for path, _object_id in source_entries)
    except ReproducibleBuildError as exc:
        raise ReproducibleBuildError("Git source tree has an unsafe or special entry") from exc

    if destination.exists():
        raise FileExistsError(destination)
    destination.parent.mkdir(parents=True, exist_ok=True)
    with TemporaryDirectory(dir=destination.parent, prefix=f".{destination.name}.") as directory:
        staging = Path(directory) / "snapshot"
        staging.mkdir()
        for path, object_id in source_entries:
            payload = subprocess.run(  # noqa: S603 -- fixed Git executable and exact object id
                [  # noqa: S607 -- exact object id parsed from the immutable tree above
                    "git",
                    "cat-file",
                    "blob",
                    object_id,
                ],
                cwd=root,
                capture_output=True,
                check=True,
                timeout=30,
            ).stdout
            expanded += len(payload)
            if expanded > _MAX_EXPANDED_BYTES:
                raise ReproducibleBuildError("Git source tree exceeds the expanded-size limit")
            target = staging.joinpath(*path.parts)
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(payload)
            target.chmod(0o644)
            os.utime(target, (epoch, epoch))
        for child in sorted((path for path in staging.rglob("*") if path.is_dir()), reverse=True):
            child.chmod(0o755)
            os.utime(child, (epoch, epoch))
        os.utime(staging, (epoch, epoch))
        staging.replace(destination)


def build_once(root: Path, dist_dir: Path, epoch: int) -> tuple[BuiltArtifact, BuiltArtifact]:
    """Build one clean artifact pair and canonicalize its source archive."""

    if dist_dir.exists() and any(dist_dir.iterdir()):
        raise ReproducibleBuildError("distribution output directory must be empty")
    wheel_binding = capture_wheel_source_binding(root)
    dist_dir.mkdir(parents=True, exist_ok=True)
    environment = {**os.environ, "SOURCE_DATE_EPOCH": str(epoch)}
    subprocess.run(  # noqa: S603 -- fixed interpreter/module and reviewed local source
        [
            sys.executable,
            "-m",
            "build",
            "--wheel",
            "--sdist",
            "--no-isolation",
            "--outdir",
            str(dist_dir),
        ],
        cwd=root,
        env=environment,
        check=True,
        timeout=300,
    )
    wheel, sdist = _artifacts(dist_dir)
    wheel_payload = canonicalize_wheel(wheel, epoch)
    _verify_wheel_payload(wheel.name, wheel_payload, wheel_binding)
    sdist_payload = canonicalize_sdist(sdist, epoch)
    return (
        BuiltArtifact(wheel.name, wheel_payload),
        BuiltArtifact(sdist.name, sdist_payload),
    )


def build_reproducible(
    root: Path,
    dist_dir: Path,
    epoch: int,
    source_ref: str = "HEAD",
) -> tuple[Path, Path]:
    """Build in separate source trees and publish only byte-identical artifacts."""

    if os.path.lexists(dist_dir):
        raise ReproducibleBuildError("distribution output directory must not already exist")
    dist_dir.parent.mkdir(parents=True, exist_ok=True)
    with (
        TemporaryDirectory(
            dir=dist_dir.parent,
            prefix=f".{dist_dir.name}.publish.",
        ) as publish_directory,
        TemporaryDirectory(prefix="cpe-atlas-rebuild-") as directory,
    ):
        publish_root = Path(publish_directory)
        staging = publish_root / "artifacts"
        staging.mkdir()
        parent_stat = dist_dir.parent.stat(follow_symlinks=False)
        parent_identity = (parent_stat.st_dev, parent_stat.st_ino)
        parent_mtime = parent_stat.st_mtime_ns
        staging_stat = staging.stat(follow_symlinks=False)
        staging_identity = (staging_stat.st_dev, staging_stat.st_ino)

        temporary = Path(directory)
        snapshot = temporary / "snapshot"
        _copy_source_snapshot(root, snapshot, epoch, source_ref)
        first_source = shutil.copytree(snapshot, temporary / "first-source")
        second_source = shutil.copytree(snapshot, temporary / "second-source")
        primary = build_once(first_source, temporary / "first-dist", epoch)
        rebuilt = build_once(second_source, temporary / "second-dist", epoch)
        primary_by_name = {artifact.name: artifact.payload for artifact in primary}
        rebuilt_by_name = {artifact.name: artifact.payload for artifact in rebuilt}
        if (
            len(primary_by_name) != 2
            or len(rebuilt_by_name) != 2
            or primary_by_name != rebuilt_by_name
        ):
            raise ReproducibleBuildError("independent artifact rebuild differs byte-for-byte")

        current_parent = dist_dir.parent.stat(follow_symlinks=False)
        current_staging = staging.stat(follow_symlinks=False)
        if (
            (current_parent.st_dev, current_parent.st_ino) != parent_identity
            or current_parent.st_mtime_ns != parent_mtime
            or (current_staging.st_dev, current_staging.st_ino) != staging_identity
            or any(staging.iterdir())
            or os.path.lexists(dist_dir)
        ):
            raise ReproducibleBuildError("distribution output path changed during the build")

        for name, payload in primary_by_name.items():
            with (staging / name).open("xb") as target:
                target.write(payload)
                target.flush()
                os.fsync(target.fileno())
        if not _artifact_directory_matches(staging, staging_identity, primary_by_name):
            raise ReproducibleBuildError("staged distribution artifacts changed before publication")
        if os.path.lexists(dist_dir):
            raise ReproducibleBuildError("distribution output path changed during publication")

        try:
            staging.rename(dist_dir)
        except OSError as exc:
            raise ReproducibleBuildError(
                "distribution output path changed during publication"
            ) from exc
        if not _artifact_directory_matches(dist_dir, staging_identity, primary_by_name):
            try:
                published_stat = dist_dir.stat(follow_symlinks=False)
                if (published_stat.st_dev, published_stat.st_ino) == staging_identity:
                    dist_dir.rename(publish_root / "rejected")
            except OSError:
                pass
            raise ReproducibleBuildError("published distribution artifacts changed unexpectedly")
        published = tuple(dist_dir / artifact.name for artifact in primary)
    return published[0], published[1]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dist-dir", type=Path, default=Path("dist"))
    parser.add_argument("--epoch", help="override SOURCE_DATE_EPOCH for a reviewed build")
    parser.add_argument(
        "--source-ref",
        default=os.environ.get("GITHUB_SHA", "HEAD"),
        help="full reviewed Git commit id (defaults to GITHUB_SHA or HEAD)",
    )
    args = parser.parse_args(argv)
    try:
        source_commit = resolve_source_commit(ROOT, args.source_ref)
        epoch = (
            parse_epoch(args.epoch)
            if args.epoch is not None
            else source_date_epoch(ROOT, source_commit)
        )
        artifacts = build_reproducible(ROOT, args.dist_dir, epoch, source_commit)
    except (
        OSError,
        ReproducibleBuildError,
        subprocess.SubprocessError,
        tarfile.TarError,
        zipfile.BadZipFile,
    ) as exc:
        print(f"Reproducible build failed: {exc}", file=sys.stderr)
        return 1
    print(
        "Reproducible build verified: "
        + ", ".join(f"{path.name} sha256={_digest(path)}" for path in artifacts)
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

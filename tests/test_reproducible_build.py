# SPDX-License-Identifier: 0BSD
"""Verify deterministic release builds and hostile-archive rejection."""

from __future__ import annotations

import base64
import csv
import gzip
import hashlib
import io
import os
import stat
import subprocess
import tarfile
import time
import unittest
import zipfile
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path, PurePosixPath, PureWindowsPath
from tempfile import TemporaryDirectory
from unittest.mock import Mock, patch

from scripts import build_reproducible as reproducible

EPOCH = 1_700_000_000


class ReproducibleBuildTests(unittest.TestCase):
    def setUp(self) -> None:
        temporary = TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.base = Path(temporary.name)

    @staticmethod
    def source_project(root: Path) -> reproducible.WheelSourceBinding:
        files = {
            "LICENSE": b"synthetic license\n",
            "src/package/__init__.py": b'__version__ = "1.0"\n',
            "src/package/cli.py": b"def main():\n    return 0\n",
            "src/package/value.txt": b"reviewed bytes\n",
        }
        for name, payload in files.items():
            path = root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(payload)
        (root / "pyproject.toml").write_text(
            """\
[project]
name = "package"
dynamic = ["version"]
requires-python = ">=3.11,<3.16"
license = "0BSD"
license-files = ["LICENSE"]
dependencies = ["dependency>=1,<2"]

[project.optional-dependencies]
dev = ["tool>=2,<3"]

[project.scripts]
package-cli = "package.cli:main"

[tool.setuptools.dynamic]
version = { attr = "package.__version__" }
""",
            encoding="utf-8",
        )
        return reproducible.capture_wheel_source_binding(root)

    @staticmethod
    def archive(
        path: Path,
        *,
        mtime: int,
        members: tuple[tuple[str, bytes | None, bytes | None], ...] = (
            ("package", None, None),
            ("package/value.txt", b"reviewed bytes\n", None),
        ),
    ) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        with tarfile.open(path, "w:gz") as archive:
            for name, value, kind in members:
                member = tarfile.TarInfo(name)
                member.mtime = mtime
                member.uid = 123
                member.gid = 456
                member.uname = "builder"
                member.gname = "builder"
                member.pax_headers = {
                    "atime": str(mtime + 11),
                    "comment": f"builder-{mtime}",
                    "gid": str((mtime % 1000) + 2000),
                    "gname": f"pax-group-{mtime}",
                    "uid": str((mtime % 1000) + 1000),
                    "uname": f"pax-user-{mtime}",
                }
                if kind is not None:
                    member.type = kind
                    member.linkname = "target"
                    archive.addfile(member)
                elif value is None:
                    member.type = tarfile.DIRTYPE
                    member.mode = 0o700
                    archive.addfile(member)
                else:
                    member.size = len(value)
                    member.mode = 0o600
                    archive.addfile(member, io.BytesIO(value))

    @staticmethod
    def wheel_archive(
        path: Path,
        *,
        newline: bytes = b"\n",
        create_system: int = 3,
        external_attr: int = (stat.S_IFREG | 0o644) << 16,
    ) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        entries = {
            "package/value.txt": b"reviewed bytes\n",
            "package-1.0.dist-info/METADATA": (
                newline.join((b"Metadata-Version: 2.4", b"Name: package", b"Version: 1.0", b""))
            ),
            "package-1.0.dist-info/WHEEL": newline.join(
                (b"Wheel-Version: 1.0", b"Root-Is-Purelib: true", b"Tag: py3-none-any", b"")
            ),
            "package-1.0.dist-info/RECORD": b"",
        }
        entries["package-1.0.dist-info/RECORD"] = reproducible._wheel_record(
            entries,
            "package-1.0.dist-info/RECORD",
        )
        with zipfile.ZipFile(path, "w") as archive:
            for name, payload in entries.items():
                member = zipfile.ZipInfo(name, date_time=(2024, 1, 2, 3, 4, 6))
                member.compress_type = zipfile.ZIP_DEFLATED
                member.create_system = create_system
                member.external_attr = external_attr
                archive.writestr(member, payload)

    @staticmethod
    def bound_wheel_entries(binding: reproducible.WheelSourceBinding) -> dict[str, bytes]:
        distribution = reproducible.canonicalize_name(binding.project_name).replace("-", "_")
        dist_info = f"{distribution}-{binding.version}.dist-info"
        metadata = [
            "Metadata-Version: 2.4",
            f"Name: {binding.project_name}",
            f"Version: {binding.version}",
            f"License-Expression: {binding.license_expression}",
            *(f"License-File: {name}" for name, _payload in binding.license_entries),
            f"Requires-Python: {binding.requires_python}",
            *(
                f"Requires-Dist: {requirement}"
                for requirement in sorted(binding.requirements, key=str)
            ),
            *(f"Provides-Extra: {extra}" for extra in sorted(binding.extras)),
            "",
            "",
        ]
        entries = {
            **dict(binding.package_entries),
            f"{dist_info}/METADATA": "\n".join(metadata).encode(),
            f"{dist_info}/WHEEL": (
                b"Wheel-Version: 1.0\n"
                b"Generator: synthetic\n"
                b"Root-Is-Purelib: true\n"
                b"Tag: py3-none-any\n\n"
            ),
            **{
                f"{dist_info}/licenses/{name}": payload for name, payload in binding.license_entries
            },
            f"{dist_info}/top_level.txt": f"{binding.package_name}\n".encode(),
            f"{dist_info}/RECORD": b"",
        }
        if binding.scripts:
            entries[f"{dist_info}/entry_points.txt"] = (
                "[console_scripts]\n"
                + "".join(f"{name} = {value}\n" for name, value in binding.scripts)
                + "\n"
            ).encode()
        record_name = f"{dist_info}/RECORD"
        entries[record_name] = reproducible._wheel_record(entries, record_name)
        return entries

    @staticmethod
    def write_wheel_entries(path: Path, entries: dict[str, bytes]) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        with zipfile.ZipFile(path, "w") as archive:
            for name, payload in entries.items():
                archive.writestr(name, payload, compress_type=zipfile.ZIP_DEFLATED)

    def test_epoch_parser_and_sources_are_bounded(self) -> None:
        self.assertEqual(reproducible.parse_epoch(str(EPOCH)), EPOCH)
        for invalid in (
            "",
            "-1",
            "1.5",
            "9" * 10_000,
            "\u0661\u0662\u0663",
            str(reproducible._MIN_ZIP_EPOCH - 1),
            str(reproducible._MAX_GZIP_EPOCH + 1),
        ):
            with self.subTest(invalid=invalid):
                with self.assertRaises(reproducible.ReproducibleBuildError):
                    reproducible.parse_epoch(invalid)

        with patch.dict(os.environ, {"SOURCE_DATE_EPOCH": str(EPOCH)}):
            self.assertEqual(reproducible.source_date_epoch(self.base), EPOCH)
        completed = subprocess.CompletedProcess(["git"], 0, f"{EPOCH}\n", "")
        with (
            patch.dict(os.environ, {}, clear=True),
            patch.object(reproducible.subprocess, "run", return_value=completed) as run,
        ):
            self.assertEqual(reproducible.source_date_epoch(self.base), EPOCH)
        self.assertEqual(run.call_args.args[0], ["git", "show", "-s", "--format=%ct", "HEAD"])
        self.assertEqual(run.call_args.kwargs["cwd"], self.base)
        self.assertEqual(run.call_args.kwargs["timeout"], 30)

        commit = "A" * 40
        resolved = subprocess.CompletedProcess(["git"], 0, f"{commit}\n", "")
        with patch.object(reproducible.subprocess, "run", return_value=resolved) as run:
            self.assertEqual(reproducible.resolve_source_commit(self.base, "HEAD"), commit.lower())
        self.assertEqual(
            run.call_args.args[0],
            ["git", "rev-parse", "--verify", "HEAD^{commit}"],
        )
        for invalid in ("main", "--help", "a" * 39, "g" * 40):
            with self.subTest(source_ref=invalid):
                with self.assertRaisesRegex(reproducible.ReproducibleBuildError, "source ref"):
                    reproducible.resolve_source_commit(self.base, invalid)
        invalid_result = subprocess.CompletedProcess(["git"], 0, "not-an-object\n", "")
        with patch.object(reproducible.subprocess, "run", return_value=invalid_result):
            with self.assertRaisesRegex(reproducible.ReproducibleBuildError, "invalid"):
                reproducible.resolve_source_commit(self.base, "HEAD")

    def test_portable_archive_paths_reject_every_windows_hazard(self) -> None:
        for safe in (
            "package/value.txt",
            "package/nested/value-with spaces.txt",
            "package/caf\N{LATIN SMALL LETTER E WITH ACUTE}.txt",
        ):
            with self.subTest(safe=safe):
                self.assertEqual(
                    reproducible.validate_portable_archive_path(safe),
                    PurePosixPath(safe),
                )

        unsafe = (
            "",
            ".",
            "/absolute",
            "../escape",
            "package/../escape",
            "package//value",
            "package\\value",
            "C:escape",
            "package/D:escape",
            "package/file:stream",
            "package/name<value",
            'package/name"value',
            "package/name|value",
            "package/name?value",
            "package/name*value",
            "package/trailing.",
            "package/trailing ",
            "package/control\x01",
            "package/delete\x7f",
            "package/control\x80",
            "package/surrogate\udcff",
            "package/unassigned\u0378",
            "package/noncharacter\ufdd0",
            "package/post-unicode-3.2\N{GRINNING FACE}",
            f"package/{'x' * 256}",
            "package/" + "\N{LATIN SMALL LETTER E WITH ACUTE}" * 128,
            "/".join(("package", *("ab" for _ in range(90)))),
            "package/e\N{COMBINING ACUTE ACCENT}.txt",
            "package/CON",
            "package/con.txt",
            "package/NUL .log",
            "package/AUX..txt",
            "package/PRN",
            "package/COM1.log",
            "package/com\N{SUPERSCRIPT ONE}.log",
            "package/LPT9",
            "package/lpt\N{SUPERSCRIPT THREE}.txt",
            "package/CONIN$",
            "package/conout$.txt",
        )
        for name in unsafe:
            with self.subTest(name=name):
                with self.assertRaisesRegex(
                    reproducible.ReproducibleBuildError,
                    "unsafe or not portable",
                ):
                    reproducible.validate_portable_archive_path(name)

        # Parsing the complete POSIX name misses a nested drive-relative
        # component. Joining its individual components can then discard the
        # supposedly safe destination on Windows.
        nested_drive = PurePosixPath("package/D:escape")
        self.assertEqual(PureWindowsPath(nested_drive.as_posix()).drive, "")
        self.assertEqual(
            PureWindowsPath("C:/safe/destination").joinpath(*nested_drive.parts),
            PureWindowsPath("D:escape"),
        )

    def test_canonical_source_archives_are_byte_identical(self) -> None:
        first = self.base / "a" / "package.tar.gz"
        second = self.base / "b" / "package.tar.gz"
        first_members = (
            ("package", None, None),
            ("package/value.txt", b"reviewed bytes\r\n", None),
            ("package/PKG-INFO", b"Name: package\r\nVersion: 1.0\r\n", None),
            ("package/setup.cfg", b"[egg_info]\r\ntag_date = 0\r\n", None),
            ("package/src/package.egg-info/SOURCES.txt", b"one.py\r\ntwo.py\r\n", None),
            ("package/docs/PKG-INFO", b"source payload\r\n", None),
        )
        second_members = (
            ("package/setup.cfg", b"[egg_info]\ntag_date = 0\n", None),
            ("package/PKG-INFO", b"Name: package\nVersion: 1.0\n", None),
            ("package/src/package.egg-info/SOURCES.txt", b"one.py\ntwo.py\n", None),
            ("package/docs/PKG-INFO", b"source payload\r\n", None),
            ("package/value.txt", b"reviewed bytes\r\n", None),
            ("package", None, None),
        )
        self.archive(first, mtime=EPOCH + 1, members=first_members)
        self.archive(second, mtime=EPOCH + 2, members=second_members)

        reproducible.canonicalize_sdist(first, EPOCH)
        reproducible.canonicalize_sdist(second, EPOCH)

        self.assertEqual(first.read_bytes(), second.read_bytes())
        self.assertEqual(first.stat().st_mtime, EPOCH)
        with tarfile.open(first, "r:gz") as archive:
            members = archive.getmembers()
            self.assertEqual(
                [member.name for member in members],
                [
                    "package",
                    "package/PKG-INFO",
                    "package/docs/PKG-INFO",
                    "package/setup.cfg",
                    "package/src/package.egg-info/SOURCES.txt",
                    "package/value.txt",
                ],
            )
            self.assertTrue(all(member.mtime == EPOCH for member in members))
            self.assertTrue(all(member.uid == member.gid == 0 for member in members))
            self.assertTrue(all(member.uname == member.gname == "" for member in members))
            self.assertTrue(all(member.pax_headers == {} for member in members))
            self.assertEqual(
                [member.mode for member in members],
                [0o755, 0o644, 0o644, 0o644, 0o644, 0o644],
            )
            payload = archive.extractfile(members[5])
            self.assertIsNotNone(payload)
            self.assertEqual(payload.read(), b"reviewed bytes\r\n")
            metadata = archive.extractfile(members[1])
            source_metadata = archive.extractfile(members[2])
            setup = archive.extractfile(members[3])
            egg_info = archive.extractfile(members[4])
            self.assertIsNotNone(metadata)
            self.assertIsNotNone(source_metadata)
            self.assertIsNotNone(setup)
            self.assertIsNotNone(egg_info)
            self.assertNotIn(b"\r", metadata.read())
            self.assertIn(b"\r\n", source_metadata.read())
            self.assertNotIn(b"\r", setup.read())
            self.assertNotIn(b"\r", egg_info.read())

        once = first.read_bytes()
        reproducible.canonicalize_sdist(first, EPOCH)
        self.assertEqual(first.read_bytes(), once)
        self.assertEqual(gzip.decompress(reproducible._gzip_stored(b"", EPOCH)), b"")

    def test_canonical_wheels_are_platform_neutral_and_have_valid_records(self) -> None:
        first = self.base / "a" / "package.whl"
        second = self.base / "b" / "package.whl"
        self.wheel_archive(
            first,
            newline=b"\r\n",
            create_system=0,
            external_attr=(stat.S_IFREG | 0o666) << 16,
        )
        self.wheel_archive(second)

        reproducible.canonicalize_wheel(first, EPOCH)
        reproducible.canonicalize_wheel(second, EPOCH)

        self.assertEqual(first.read_bytes(), second.read_bytes())
        self.assertEqual(first.stat().st_mtime, EPOCH)
        with zipfile.ZipFile(first) as archive:
            members = archive.infolist()
            record_name = "package-1.0.dist-info/RECORD"
            expected_order = [
                *sorted(member.filename for member in members if member.filename != record_name),
                record_name,
            ]
            self.assertEqual([member.filename for member in members], expected_order)
            self.assertTrue(all(member.date_time == time.gmtime(EPOCH)[:6] for member in members))
            self.assertTrue(all(member.create_system == 3 for member in members))
            self.assertTrue(all(member.compress_type == zipfile.ZIP_STORED for member in members))
            self.assertTrue(
                all(member.external_attr == (stat.S_IFREG | 0o644) << 16 for member in members)
            )
            metadata = archive.read("package-1.0.dist-info/METADATA")
            self.assertNotIn(b"\r", metadata)
            rows = list(
                csv.reader(
                    io.StringIO(archive.read("package-1.0.dist-info/RECORD").decode("utf-8"))
                )
            )
            for name, digest, size in rows[:-1]:
                payload = archive.read(name)
                expected = base64.urlsafe_b64encode(hashlib.sha256(payload).digest()).rstrip(b"=")
                self.assertEqual(digest, f"sha256={expected.decode('ascii')}")
                self.assertEqual(int(size), len(payload))
            self.assertEqual(rows[-1], ["package-1.0.dist-info/RECORD", "", ""])

        once = first.read_bytes()
        reproducible.canonicalize_wheel(first, EPOCH)
        self.assertEqual(first.read_bytes(), once)

    def test_wheel_entry_validation_rejects_hostile_members(self) -> None:
        def member(
            name: str,
            payload: bytes = b"value",
            *,
            original: str | None = None,
            mode: int = stat.S_IFREG | 0o644,
            flags: int = 0,
            size: int | None = None,
            directory: bool = False,
        ) -> Mock:
            result = Mock()
            result.filename = name
            result.orig_filename = name if original is None else original
            result.external_attr = mode << 16
            result.flag_bits = flags
            result.file_size = len(payload) if size is None else size
            result.is_dir.return_value = directory
            result.payload = payload
            return result

        def archive(*members: Mock) -> Mock:
            result = Mock()
            result.infolist.return_value = list(members)
            result.read.side_effect = lambda item: item.payload
            return result

        unsafe_members = (
            member(""),
            member("/absolute"),
            member("../escape"),
            member("folder\\escape"),
            member("C:escape"),
            member("folder/D:escape"),
            member("folder/file:stream"),
            member("folder/CON.txt"),
            member("folder/trailing."),
            member("folder/control\x01"),
            member("folder//escape"),
            member("safe", original="different"),
            member("e\N{COMBINING ACUTE ACCENT}.txt"),
            member("folder/", directory=True),
            member("link", mode=stat.S_IFLNK | 0o777),
        )
        for hostile in unsafe_members:
            with self.subTest(name=hostile.filename):
                with self.assertRaisesRegex(reproducible.ReproducibleBuildError, "unsafe"):
                    reproducible._validated_wheel_entries(archive(hostile))

        for colliding in (
            (member("same"), member("same")),
            (member("Name"), member("name")),
            (member("package/A"), member("package/a/child")),
            (member("package/A/one"), member("package/a/two")),
            (member("package/straße/one"), member("package/STRASSE/two")),
            (member("package/file"), member("package/file/child")),
        ):
            with self.subTest(collision=[item.filename for item in colliding]):
                with self.assertRaisesRegex(reproducible.ReproducibleBuildError, "unsafe"):
                    reproducible._validated_wheel_entries(archive(*colliding))

        with patch.object(reproducible, "_MAX_SDIST_MEMBERS", 1):
            with self.assertRaisesRegex(reproducible.ReproducibleBuildError, "member count"):
                reproducible._validated_wheel_entries(archive(member("one"), member("two")))
        for invalid in (member("encrypted", flags=1), member("negative", size=-1)):
            with self.subTest(name=invalid.filename):
                with self.assertRaisesRegex(reproducible.ReproducibleBuildError, "encrypted"):
                    reproducible._validated_wheel_entries(archive(invalid))
        with patch.object(reproducible, "_MAX_EXPANDED_BYTES", 4):
            with self.assertRaisesRegex(reproducible.ReproducibleBuildError, "expanded"):
                reproducible._validated_wheel_entries(archive(member("large")))
        with self.assertRaisesRegex(reproducible.ReproducibleBuildError, "invalid size"):
            reproducible._validated_wheel_entries(archive(member("short", size=6)))
        with self.assertRaisesRegex(reproducible.ReproducibleBuildError, "member count"):
            reproducible._validated_wheel_entries(archive())

    def test_wheel_record_and_inventory_validation_fail_closed(self) -> None:
        record_name = "package-1.0.dist-info/RECORD"

        def valid_entries() -> dict[str, bytes]:
            entries = {"package/value.txt": b"value", record_name: b""}
            entries[record_name] = reproducible._wheel_record(entries, record_name)
            return entries

        signed = valid_entries()
        signed[f"{record_name}.jws"] = b"signature"
        with self.assertRaisesRegex(reproducible.ReproducibleBuildError, "signed"):
            reproducible._verify_wheel_record(signed, record_name)

        malformed_payloads = (b"\xff", b"only,two\n", b"a,b,c\na,d,e\n")
        for payload in malformed_payloads:
            with self.subTest(payload=payload):
                entries = valid_entries()
                entries[record_name] = payload
                with self.assertRaisesRegex(reproducible.ReproducibleBuildError, "malformed"):
                    reproducible._verify_wheel_record(entries, record_name)

        missing = valid_entries()
        missing[record_name] = f"{record_name},,\n".encode()
        with self.assertRaisesRegex(reproducible.ReproducibleBuildError, "inventory"):
            reproducible._verify_wheel_record(missing, record_name)

        self_hashed = valid_entries()
        rows = (
            self_hashed[record_name]
            .decode()
            .replace(f"{record_name},,", f"{record_name},sha256=invalid,1")
        )
        self_hashed[record_name] = rows.encode()
        with self.assertRaisesRegex(reproducible.ReproducibleBuildError, "self-entry"):
            reproducible._verify_wheel_record(self_hashed, record_name)

        for replacement in ("sha256=invalid", "999"):
            entries = valid_entries()
            rows = list(csv.reader(io.StringIO(entries[record_name].decode())))
            rows[0][1 if replacement.startswith("sha256") else 2] = replacement
            output = io.StringIO(newline="")
            csv.writer(output, lineterminator="\n").writerows(rows)
            entries[record_name] = output.getvalue().encode()
            with self.subTest(replacement=replacement):
                with self.assertRaisesRegex(reproducible.ReproducibleBuildError, "integrity"):
                    reproducible._verify_wheel_record(entries, record_name)

    def test_wheel_payload_and_metadata_are_bound_to_reviewed_source(self) -> None:
        binding = self.source_project(self.base / "source")
        filename = "package-1.0-py3-none-any.whl"

        def write_case(label: str, entries: dict[str, bytes], *, name: str = filename) -> Path:
            record_name = next(entry for entry in entries if entry.endswith(".dist-info/RECORD"))
            entries[record_name] = reproducible._wheel_record(entries, record_name)
            path = self.base / label / name
            self.write_wheel_entries(path, entries)
            reproducible.canonicalize_wheel(path, EPOCH)
            return path

        valid = write_case("valid", self.bound_wheel_entries(binding))
        reproducible.verify_wheel_source(valid, binding)
        for payload in (b"", b"too-large"):
            limit = 1 if payload else reproducible._MAX_WHEEL_BYTES
            with (
                self.subTest(verified_payload_size=len(payload)),
                patch.object(reproducible, "_MAX_WHEEL_BYTES", limit),
                self.assertRaisesRegex(reproducible.ReproducibleBuildError, "invalid size"),
            ):
                reproducible._verify_wheel_payload(filename, payload, binding)

        inventory_cases = {
            "top-level-module": ("sitecustomize.py", b"raise SystemExit\n"),
            "pth-injection": ("injected.pth", b"import sitecustomize\n"),
            "data-script": ("package-1.0.data/scripts/injected", b"#!/bin/sh\n"),
            "extra-dist-info": ("package-1.0.dist-info/injected.py", b"raise SystemExit\n"),
        }
        for label, (name, payload) in inventory_cases.items():
            entries = self.bound_wheel_entries(binding)
            entries[name] = payload
            with (
                self.subTest(label=label),
                self.assertRaisesRegex(
                    reproducible.ReproducibleBuildError,
                    "inventory",
                ),
            ):
                reproducible.verify_wheel_source(write_case(label, entries), binding)

        for label, name in (
            ("changed-package", "package/value.txt"),
            ("changed-license", "package-1.0.dist-info/licenses/LICENSE"),
            ("changed-top-level", "package-1.0.dist-info/top_level.txt"),
        ):
            entries = self.bound_wheel_entries(binding)
            entries[name] = b"changed\n"
            with self.subTest(label=label), self.assertRaises(reproducible.ReproducibleBuildError):
                reproducible.verify_wheel_source(write_case(label, entries), binding)

        missing = self.bound_wheel_entries(binding)
        del missing["package/value.txt"]
        with self.assertRaisesRegex(reproducible.ReproducibleBuildError, "inventory"):
            reproducible.verify_wheel_source(write_case("missing-package", missing), binding)

        wrong_name = write_case(
            "wrong-name",
            self.bound_wheel_entries(binding),
            name="different-1.0-py3-none-any.whl",
        )
        with self.assertRaisesRegex(reproducible.ReproducibleBuildError, "identity"):
            reproducible.verify_wheel_source(wrong_name, binding)

    def test_wheel_critical_metadata_is_bound_to_project_configuration(self) -> None:
        binding = self.source_project(self.base / "source")
        filename = "package-1.0-py3-none-any.whl"

        def changed(label: str, member: str, old: bytes, new: bytes) -> Path:
            entries = self.bound_wheel_entries(binding)
            name = f"package-1.0.dist-info/{member}"
            self.assertIn(old, entries[name])
            entries[name] = entries[name].replace(old, new, 1)
            record_name = "package-1.0.dist-info/RECORD"
            entries[record_name] = reproducible._wheel_record(entries, record_name)
            path = self.base / label / filename
            self.write_wheel_entries(path, entries)
            reproducible.canonicalize_wheel(path, EPOCH)
            return path

        cases = (
            ("wheel-version", "WHEEL", b"Wheel-Version: 1.0", b"Wheel-Version: 2.0"),
            ("purelib", "WHEEL", b"Root-Is-Purelib: true", b"Root-Is-Purelib: false"),
            ("tag", "WHEEL", b"Tag: py3-none-any", b"Tag: cp314-none-any"),
            (
                "metadata-version",
                "METADATA",
                b"Metadata-Version: 2.4",
                b"Metadata-Version: 2.3",
            ),
            ("name", "METADATA", b"Name: package", b"Name: injected"),
            ("version", "METADATA", b"Version: 1.0", b"Version: 2.0"),
            (
                "license-expression",
                "METADATA",
                b"License-Expression: 0BSD",
                b"License-Expression: GPL-3.0-only",
            ),
            (
                "license-expression-duplicate",
                "METADATA",
                b"License-Expression: 0BSD",
                b"License-Expression: 0BSD\nLicense-Expression: 0BSD",
            ),
            (
                "license-file",
                "METADATA",
                b"License-File: LICENSE",
                b"License-File: COPYING",
            ),
            (
                "license-file-duplicate",
                "METADATA",
                b"License-File: LICENSE",
                b"License-File: LICENSE\nLicense-File: LICENSE",
            ),
            (
                "python",
                "METADATA",
                b"Requires-Python: <3.16,>=3.11",
                b"Requires-Python: >=3.12",
            ),
            (
                "python-invalid",
                "METADATA",
                b"Requires-Python: <3.16,>=3.11",
                b"Requires-Python: not-a-specifier",
            ),
            (
                "dependency",
                "METADATA",
                b"Requires-Dist: dependency<2,>=1",
                b"Requires-Dist: injected>=1",
            ),
            (
                "dependency-invalid",
                "METADATA",
                b"Requires-Dist: dependency<2,>=1",
                b"Requires-Dist: ???",
            ),
            (
                "dependency-duplicate",
                "METADATA",
                b"Requires-Dist: dependency<2,>=1",
                b"Requires-Dist: dependency<2,>=1\nRequires-Dist: dependency<2,>=1",
            ),
            ("extra", "METADATA", b"Provides-Extra: dev", b"Provides-Extra: release"),
            (
                "extra-duplicate",
                "METADATA",
                b"Provides-Extra: dev",
                b"Provides-Extra: dev\nProvides-Extra: dev",
            ),
            (
                "entry-point",
                "entry_points.txt",
                b"package-cli = package.cli:main",
                b"package-cli = os:system",
            ),
        )
        for label, member, old, new in cases:
            with self.subTest(label=label), self.assertRaises(reproducible.ReproducibleBuildError):
                reproducible.verify_wheel_source(changed(label, member, old, new), binding)

        malformed_cases = (
            ("metadata-encoding", "METADATA", b"\xff"),
            ("wheel-encoding", "WHEEL", b"\xff"),
            ("wheel-defect", "WHEEL", b"not-a-header\n"),
            (
                "wheel-duplicate-header",
                "WHEEL",
                b"Wheel-Version: 1.0\n"
                b"Root-Is-Purelib: true\n"
                b"Tag: py3-none-any\n"
                b"Tag: py3-none-any\n\n",
            ),
            ("entrypoint-encoding", "entry_points.txt", b"\xff"),
            ("entrypoint-section", "entry_points.txt", b"[other]\nvalue = target\n"),
        )
        for label, member, payload in malformed_cases:
            entries = self.bound_wheel_entries(binding)
            name = f"package-1.0.dist-info/{member}"
            entries[name] = payload
            record_name = "package-1.0.dist-info/RECORD"
            entries[record_name] = reproducible._wheel_record(entries, record_name)
            path = self.base / label / filename
            self.write_wheel_entries(path, entries)
            reproducible.canonicalize_wheel(path, EPOCH)
            with self.subTest(label=label), self.assertRaises(reproducible.ReproducibleBuildError):
                reproducible.verify_wheel_source(path, binding)

    def test_source_binding_rejects_malformed_project_configuration(self) -> None:
        def configured_root(label: str) -> tuple[Path, str]:
            root = self.base / label
            self.source_project(root)
            pyproject = (root / "pyproject.toml").read_text(encoding="utf-8")
            return root, pyproject

        invalid_pyprojects = {
            "invalid-toml": "[project\n",
            "missing-project": "[build-system]\nrequires = []\n",
            "invalid-name": None,
            "missing-package": None,
            "invalid-version-binding": None,
            "invalid-python-type": None,
            "invalid-python-specifier": None,
            "invalid-dependencies": None,
            "invalid-optional-dependencies": None,
            "invalid-scripts": None,
            "invalid-license-expression": None,
            "invalid-license-files": None,
            "empty-license-files": None,
            "duplicate-license-file": None,
            "unsafe-license-file": None,
            "missing-license-file": None,
            "invalid-requirement": None,
            "duplicate-requirement": None,
            "duplicate-extra": None,
        }
        replacements = {
            "invalid-name": ('name = "package"', 'name = ""'),
            "missing-package": ('name = "package"', 'name = "missing"'),
            "invalid-version-binding": ('dynamic = ["version"]', "dynamic = []"),
            "invalid-python-type": ('requires-python = ">=3.11,<3.16"', "requires-python = 42"),
            "invalid-python-specifier": (
                'requires-python = ">=3.11,<3.16"',
                'requires-python = "not-a-specifier"',
            ),
            "invalid-dependencies": (
                'dependencies = ["dependency>=1,<2"]',
                "dependencies = [42]",
            ),
            "invalid-optional-dependencies": ('dev = ["tool>=2,<3"]', "dev = [42]"),
            "invalid-scripts": ('package-cli = "package.cli:main"', "package-cli = 42"),
            "invalid-license-expression": ('license = "0BSD"', 'license = " 0BSD"'),
            "invalid-license-files": ('license-files = ["LICENSE"]', "license-files = [42]"),
            "empty-license-files": ('license-files = ["LICENSE"]', "license-files = []"),
            "duplicate-license-file": (
                'license-files = ["LICENSE"]',
                'license-files = ["LICENSE", "LICENSE"]',
            ),
            "unsafe-license-file": (
                'license-files = ["LICENSE"]',
                'license-files = ["CON"]',
            ),
            "missing-license-file": (
                'license-files = ["LICENSE"]',
                'license-files = ["MISSING"]',
            ),
            "invalid-requirement": (
                'dependencies = ["dependency>=1,<2"]',
                'dependencies = ["???"]',
            ),
            "duplicate-requirement": (
                'dependencies = ["dependency>=1,<2"]',
                'dependencies = ["dependency>=1,<2", "dependency>=1,<2"]',
            ),
            "duplicate-extra": (
                'dev = ["tool>=2,<3"]',
                "dev-test = []\ndev_test = []",
            ),
        }
        for label, literal in invalid_pyprojects.items():
            root, pyproject = configured_root(label)
            if literal is None:
                old, new = replacements[label]
                self.assertIn(old, pyproject)
                literal = pyproject.replace(old, new, 1)
            (root / "pyproject.toml").write_text(literal, encoding="utf-8")
            with self.subTest(label=label), self.assertRaises(reproducible.ReproducibleBuildError):
                reproducible.capture_wheel_source_binding(root)

        for label, version_source in (
            ("invalid-version-source", "def broken(:\n"),
            ("missing-version", "VALUE = '1.0'\n"),
            ("invalid-version", "__version__ = 'not a version'\n"),
        ):
            root, _pyproject = configured_root(label)
            (root / "src/package/__init__.py").write_text(version_source, encoding="utf-8")
            with self.subTest(label=label), self.assertRaises(reproducible.ReproducibleBuildError):
                reproducible.capture_wheel_source_binding(root)

        missing_pyproject = self.base / "missing-pyproject"
        missing_pyproject.mkdir()
        with self.assertRaisesRegex(reproducible.ReproducibleBuildError, "unavailable"):
            reproducible.capture_wheel_source_binding(missing_pyproject)

        empty_package, _pyproject = configured_root("empty-package")
        for source in (empty_package / "src/package").iterdir():
            source.unlink()
        with (
            patch.object(reproducible, "_source_version", return_value="1.0"),
            self.assertRaisesRegex(reproducible.ReproducibleBuildError, "no wheel payload"),
        ):
            reproducible.capture_wheel_source_binding(empty_package)

        direct_url, pyproject = configured_root("direct-url")
        pyproject = pyproject.replace(
            'dependencies = ["dependency>=1,<2"]',
            'dependencies = ["dependency @ https://example.invalid/dependency.whl"]',
        ).replace(
            'dev = ["tool>=2,<3"]',
            "dev = [\"tool @ https://example.invalid/tool.whl ; python_version >= '3.11'\"]",
        )
        (direct_url / "pyproject.toml").write_text(pyproject, encoding="utf-8")
        direct_binding = reproducible.capture_wheel_source_binding(direct_url)
        self.assertTrue(any(requirement.url for requirement in direct_binding.requirements))

    def test_wheel_binding_without_console_scripts_is_exact(self) -> None:
        root = self.base / "no-scripts"
        self.source_project(root)
        pyproject_path = root / "pyproject.toml"
        pyproject = pyproject_path.read_text(encoding="utf-8")
        pyproject_path.write_text(
            pyproject.replace('package-cli = "package.cli:main"\n', ""),
            encoding="utf-8",
        )
        binding = reproducible.capture_wheel_source_binding(root)
        self.assertEqual(binding.scripts, ())
        wheel = self.base / "no-scripts-dist/package-1.0-py3-none-any.whl"
        self.write_wheel_entries(wheel, self.bound_wheel_entries(binding))
        reproducible.canonicalize_wheel(wheel, EPOCH)
        reproducible.verify_wheel_source(wheel, binding)

    def test_wheel_canonicalizer_rejects_invalid_layouts_and_cleans_up(self) -> None:
        wrong_suffix = self.base / "wrong.zip"
        wrong_suffix.write_bytes(b"value")
        with self.assertRaisesRegex(reproducible.ReproducibleBuildError, "whl format"):
            reproducible.canonicalize_wheel(wrong_suffix, EPOCH)
        empty = self.base / "empty.whl"
        empty.write_bytes(b"")
        with self.assertRaisesRegex(reproducible.ReproducibleBuildError, "compressed size"):
            reproducible.canonicalize_wheel(empty, EPOCH)
        oversized = self.base / "oversized.whl"
        oversized.write_bytes(b"value")
        with patch.object(reproducible, "_MAX_WHEEL_BYTES", 4):
            with self.assertRaisesRegex(reproducible.ReproducibleBuildError, "compressed size"):
                reproducible.canonicalize_wheel(oversized, EPOCH)

        def write(path: Path, entries: dict[str, bytes]) -> None:
            with zipfile.ZipFile(path, "w") as archive:
                for name, payload in entries.items():
                    archive.writestr(name, payload)

        layouts = {
            "empty-layout": {},
            "no-dist-info": {"package/value": b"value"},
            "two-dist-info": {
                "one.dist-info/RECORD": b"",
                "two.dist-info/RECORD": b"",
            },
            "missing-record": {"package-1.0.dist-info/METADATA": b"metadata"},
        }
        for label, entries in layouts.items():
            path = self.base / f"{label}.whl"
            write(path, entries)
            with self.subTest(label=label):
                with self.assertRaises(reproducible.ReproducibleBuildError):
                    reproducible.canonicalize_wheel(path, EPOCH)

        valid = self.base / "write-failure.whl"
        self.wheel_archive(valid)
        with patch.object(zipfile.ZipFile, "writestr", side_effect=OSError("disk")):
            with self.assertRaisesRegex(OSError, "disk"):
                reproducible.canonicalize_wheel(valid, EPOCH)
        self.assertEqual(list(self.base.glob(".*.tmp")), [])

        corrupt = self.base / "corrupt.whl"
        self.wheel_archive(corrupt)
        with zipfile.ZipFile(corrupt) as archive:
            item = archive.getinfo("package/value.txt")
            payload_offset = (
                item.header_offset + 30 + len(item.filename.encode("utf-8")) + len(item.extra)
            )
        damaged = bytearray(corrupt.read_bytes())
        damaged[payload_offset] ^= 0xFF
        corrupt.write_bytes(damaged)
        with self.assertRaisesRegex(reproducible.ReproducibleBuildError, "integrity"):
            reproducible.canonicalize_wheel(corrupt, EPOCH)

    def test_canonicalizer_rejects_invalid_archives_and_cleans_temporary_files(self) -> None:
        invalid_cases = (
            ("empty", (), None),
            ("multiple-roots", (("one", None, None), ("two", None, None)), None),
            ("duplicate", (("package", None, None), ("package", None, None)), None),
            ("traversal", (("../escape", b"value", None),), None),
            ("absolute", (("/escape", b"value", None),), None),
            ("backslash", (("package\\escape", b"value", None),), None),
            ("windows-drive", (("C:escape", b"value", None),), None),
            ("nested-windows-drive", (("package/D:escape", b"value", None),), None),
            ("windows-stream", (("package/file:stream", b"value", None),), None),
            ("windows-device", (("package/CON.txt", b"value", None),), None),
            ("windows-trailing-dot", (("package/value.", b"value", None),), None),
            ("control-character", (("package/value\x01", b"value", None),), None),
            ("noncanonical", (("package//escape", b"value", None),), None),
            (
                "casefold-collision",
                (("package/Name", b"one", None), ("package/name", b"two", None)),
                None,
            ),
            (
                "casefold-ancestor-file-collision",
                (("package/A", b"one", None), ("package/a/child", b"two", None)),
                None,
            ),
            (
                "casefold-ancestor-directory-collision",
                (("package/A", None, None), ("package/a/child", b"two", None)),
                None,
            ),
            (
                "casefold-implied-directory-collision",
                (("package/A/one", b"one", None), ("package/a/two", b"two", None)),
                None,
            ),
            (
                "unicode-casefold-implied-directory-collision",
                (
                    ("package/straße/one", b"one", None),
                    ("package/STRASSE/two", b"two", None),
                ),
                None,
            ),
            (
                "file-directory-collision",
                (("package/file", b"one", None), ("package/file/child", b"two", None)),
                None,
            ),
            ("non-nfc", (("package/e\N{COMBINING ACUTE ACCENT}.txt", b"value", None),), None),
            ("link", (("package/link", None, tarfile.SYMTYPE),), None),
            ("sparse", (("package/sparse", None, tarfile.GNUTYPE_SPARSE),), None),
            (
                "too-many",
                (("package", None, None), ("package/value", b"value", None)),
                "_MAX_SDIST_MEMBERS",
            ),
            (
                "expanded",
                (("package", None, None), ("package/value", b"value", None)),
                "_MAX_EXPANDED_BYTES",
            ),
        )
        for label, members, limit in invalid_cases:
            with self.subTest(label=label):
                path = self.base / label / "package.tar.gz"
                self.archive(path, mtime=EPOCH + 1, members=members)
                replacement = 1 if limit == "_MAX_SDIST_MEMBERS" else 4
                context = (
                    patch.object(reproducible, limit, replacement)
                    if limit
                    else patch.object(
                        reproducible, "_MAX_SDIST_MEMBERS", reproducible._MAX_SDIST_MEMBERS
                    )
                )
                with context:
                    with self.assertRaises(reproducible.ReproducibleBuildError):
                        reproducible.canonicalize_sdist(path, EPOCH)
                self.assertEqual(list(path.parent.glob(".*.tmp")), [])

        directory_size = self.base / "directory-size" / "package.tar.gz"
        directory_size.parent.mkdir(parents=True)
        with tarfile.open(directory_size, "w:gz") as archive:
            member = tarfile.TarInfo("package")
            member.type = tarfile.DIRTYPE
            member.size = 1
            archive.addfile(member, io.BytesIO(b"x"))
        with self.assertRaisesRegex(reproducible.ReproducibleBuildError, "invalid size"):
            reproducible.canonicalize_sdist(directory_size, EPOCH)

        negative = tarfile.TarInfo("package/value")
        negative.size = -1
        source = Mock()
        source.next.side_effect = [negative, None]
        with self.assertRaisesRegex(reproducible.ReproducibleBuildError, "invalid size"):
            reproducible._validated_members(source)

        wrong_suffix = self.base / "wrong.zip"
        wrong_suffix.write_bytes(b"value")
        with self.assertRaisesRegex(reproducible.ReproducibleBuildError, "tar.gz"):
            reproducible.canonicalize_sdist(wrong_suffix, EPOCH)
        empty = self.base / "empty.tar.gz"
        empty.write_bytes(b"")
        with self.assertRaisesRegex(reproducible.ReproducibleBuildError, "compressed size"):
            reproducible.canonicalize_sdist(empty, EPOCH)
        oversized = self.base / "oversized.tar.gz"
        oversized.write_bytes(b"value")
        with patch.object(reproducible, "_MAX_SDIST_BYTES", 4):
            with self.assertRaisesRegex(reproducible.ReproducibleBuildError, "compressed size"):
                reproducible.canonicalize_sdist(oversized, EPOCH)

        long_path = self.base / "long-path" / "package.tar.gz"
        self.archive(
            long_path,
            mtime=EPOCH,
            members=(
                ("package", None, None),
                (f"package/{'x' * 101}", b"value", None),
            ),
        )
        with self.assertRaisesRegex(reproducible.ReproducibleBuildError, "canonically"):
            reproducible.canonicalize_sdist(long_path, EPOCH)
        self.assertEqual(list(long_path.parent.glob(".*.tmp")), [])

    def test_canonical_output_size_limits_preserve_original_archives(self) -> None:
        sdist = self.base / "sdist-size" / "package.tar.gz"
        self.archive(
            sdist,
            mtime=EPOCH,
            members=(
                ("package", None, None),
                ("package/value", b"a" * 20_000, None),
            ),
        )
        original_sdist = sdist.read_bytes()
        reproducible.canonicalize_sdist(sdist, EPOCH)
        canonical_sdist_size = sdist.stat().st_size
        self.assertLess(len(original_sdist), canonical_sdist_size)
        sdist.write_bytes(original_sdist)
        with patch.object(reproducible, "_MAX_SDIST_BYTES", canonical_sdist_size - 1):
            with self.assertRaisesRegex(reproducible.ReproducibleBuildError, "canonical source"):
                reproducible.canonicalize_sdist(sdist, EPOCH)
        self.assertEqual(sdist.read_bytes(), original_sdist)
        self.assertEqual(list(sdist.parent.glob(".*.tmp")), [])

        wheel = self.base / "wheel-size" / "package.whl"
        record_name = "package-1.0.dist-info/RECORD"
        entries = {
            "package/value": b"a" * 20_000,
            "package-1.0.dist-info/METADATA": b"Name: package\nVersion: 1.0\n",
            "package-1.0.dist-info/WHEEL": b"Wheel-Version: 1.0\n",
            record_name: b"",
        }
        entries[record_name] = reproducible._wheel_record(entries, record_name)
        self.write_wheel_entries(wheel, entries)
        original_wheel = wheel.read_bytes()
        reproducible.canonicalize_wheel(wheel, EPOCH)
        canonical_wheel_size = wheel.stat().st_size
        self.assertLess(len(original_wheel), canonical_wheel_size)
        wheel.write_bytes(original_wheel)
        with patch.object(reproducible, "_MAX_WHEEL_BYTES", canonical_wheel_size - 1):
            with self.assertRaisesRegex(reproducible.ReproducibleBuildError, "canonical wheel"):
                reproducible.canonicalize_wheel(wheel, EPOCH)
        self.assertEqual(wheel.read_bytes(), original_wheel)
        self.assertEqual(list(wheel.parent.glob(".*.tmp")), [])

    def test_regular_file_without_payload_is_rejected(self) -> None:
        path = self.base / "payload" / "package.tar.gz"
        self.archive(path, mtime=EPOCH)
        real_open = reproducible.tarfile.open

        class MissingPayload:
            def __enter__(self) -> MissingPayload:
                self.archive = real_open(path, "r:gz")
                return self

            def __exit__(self, *args: object) -> None:
                self.archive.close()

            def next(self) -> tarfile.TarInfo | None:
                return self.archive.next()

            def extractfile(self, member: tarfile.TarInfo) -> None:
                del member
                return None

        def open_archive(*args: object, **kwargs: object) -> object:
            if args and args[0] == path:
                return MissingPayload()
            return real_open(*args, **kwargs)

        with patch.object(reproducible.tarfile, "open", side_effect=open_archive):
            with self.assertRaisesRegex(reproducible.ReproducibleBuildError, "no payload"):
                reproducible.canonicalize_sdist(path, EPOCH)
        self.assertEqual(list(path.parent.glob(".*.tmp")), [])

    def test_artifact_inventory_and_build_invocation(self) -> None:
        dist = self.base / "dist"
        dist.mkdir()
        for files in ((), ("one.whl",), ("one.whl", "one.tar.gz", "extra.txt")):
            with self.subTest(files=files):
                for path in dist.iterdir():
                    path.unlink()
                for name in files:
                    (dist / name).write_bytes(b"value")
                with self.assertRaises(reproducible.ReproducibleBuildError):
                    reproducible._artifacts(dist)

        for path in dist.iterdir():
            path.unlink()
        self.archive(dist / "package.tar.gz", mtime=EPOCH + 1)
        (dist / "package.whl").write_bytes(b"wheel")
        self.assertEqual(
            [path.name for path in reproducible._artifacts(dist)],
            ["package.whl", "package.tar.gz"],
        )

        occupied = self.base / "occupied"
        occupied.mkdir()
        (occupied / "existing").write_bytes(b"value")
        with self.assertRaisesRegex(reproducible.ReproducibleBuildError, "must be empty"):
            reproducible.build_once(self.base, occupied, EPOCH)

        output = self.base / "output"
        binding = self.source_project(self.base)

        def run(command: list[str], **kwargs: object) -> None:
            self.assertEqual(command[:3], [reproducible.sys.executable, "-m", "build"])
            self.assertEqual(kwargs["cwd"], self.base)
            self.assertEqual(kwargs["env"]["SOURCE_DATE_EPOCH"], str(EPOCH))
            self.assertIs(kwargs["check"], True)
            self.assertEqual(kwargs["timeout"], 300)
            outdir = Path(command[-1])
            self.archive(outdir / "package.tar.gz", mtime=EPOCH + 1)
            self.write_wheel_entries(
                outdir / "package-1.0-py3-none-any.whl",
                self.bound_wheel_entries(binding),
            )

        with patch.object(reproducible.subprocess, "run", side_effect=run) as invoked:
            artifacts = reproducible.build_once(self.base, output, EPOCH)
        self.assertEqual(invoked.call_count, 1)
        self.assertEqual(
            [path.name for path in artifacts],
            ["package-1.0-py3-none-any.whl", "package.tar.gz"],
        )

    def test_backend_cannot_redefine_the_prebuild_source_binding(self) -> None:
        root = self.base / "source"
        self.source_project(root)

        def run(command: list[str], **kwargs: object) -> None:
            (root / "src/package/value.txt").write_bytes(b"backend mutation\n")
            mutated_binding = reproducible.capture_wheel_source_binding(root)
            outdir = Path(command[-1])
            self.archive(outdir / "package.tar.gz", mtime=EPOCH)
            self.write_wheel_entries(
                outdir / "package-1.0-py3-none-any.whl",
                self.bound_wheel_entries(mutated_binding),
            )

        with patch.object(reproducible.subprocess, "run", side_effect=run):
            with self.assertRaisesRegex(reproducible.ReproducibleBuildError, "payload differs"):
                reproducible.build_once(root, self.base / "mutated-dist", EPOCH)

    def test_source_snapshot_uses_immutable_commit_not_working_tree(self) -> None:
        root = self.base / "root"
        root.mkdir()
        subprocess.run(
            ["git", "init", "--quiet"],  # noqa: S607 -- isolated test repository
            cwd=root,
            check=True,
            timeout=30,
        )
        (root / "tracked.txt").write_bytes(b"reviewed\n")
        (root / "folder").mkdir()
        (root / "folder" / "nested.txt").write_bytes(b"nested\n")
        subprocess.run(
            [  # noqa: S607 -- isolated test repository
                "git",
                "add",
                "tracked.txt",
                "folder/nested.txt",
            ],
            cwd=root,
            check=True,
            timeout=30,
        )
        subprocess.run(
            [  # noqa: S607 -- isolated test repository
                "git",
                "-c",
                "user.name=Build Test",
                "-c",
                "user.email=build-test@example.invalid",
                "commit",
                "--quiet",
                "-m",
                "reviewed source",
            ],
            cwd=root,
            check=True,
            timeout=30,
        )
        commit = reproducible.resolve_source_commit(root, "HEAD")
        reviewed_blob = subprocess.run(  # noqa: S603 -- exact reviewed test object
            ["git", "show", f"{commit}:tracked.txt"],  # noqa: S607 -- fixed Git query
            cwd=root,
            capture_output=True,
            check=True,
            timeout=30,
        ).stdout
        (root / "tracked.txt").write_bytes(b"mutated\n")
        (root / "injected.txt").write_bytes(b"untracked\n")
        snapshot = self.base / "snapshot"
        reproducible._copy_source_snapshot(root, snapshot, EPOCH, commit)
        self.assertEqual((snapshot / "tracked.txt").read_bytes(), reviewed_blob)
        self.assertNotEqual((snapshot / "tracked.txt").read_bytes(), b"mutated\n")
        self.assertFalse((snapshot / "injected.txt").exists())
        self.assertEqual((snapshot / "tracked.txt").stat().st_mtime, EPOCH)
        self.assertEqual((snapshot / "folder").stat().st_mtime, EPOCH)
        self.assertEqual(snapshot.stat().st_mtime, EPOCH)
        with self.assertRaises(FileExistsError):
            reproducible._copy_source_snapshot(root, snapshot, EPOCH, commit)

    def test_source_snapshot_rejects_malformed_or_unsafe_git_trees(self) -> None:
        object_id = b"a" * 40

        def record(name: bytes, *, mode: bytes = b"100644", kind: bytes = b"blob") -> bytes:
            return mode + b" " + kind + b" " + object_id + b"\t" + name + b"\0"

        invalid_inventories = (
            b"malformed\0",
            record(b"non-ascii-\xff"),
            record(b"link", mode=b"120000"),
            record(b"tree", kind=b"tree"),
            b"100644 blob invalid\tfile\0",
            record(b""),
            record(b"/absolute"),
            record(b"../escape"),
            record(b"folder\\escape"),
            record(b"C:escape"),
            record(b"folder/D:escape"),
            record(b"folder/file:stream"),
            record(b"folder/CON.txt"),
            record(b"folder/trailing."),
            record(b"folder/control\x01"),
            record(b"folder//escape"),
            record(b"same") + record(b"same"),
            record(b"Name") + record(b"name"),
            record(b"package/A") + record(b"package/a/child"),
            record(b"package/A/one") + record(b"package/a/two"),
            record(b"package/file") + record(b"package/file/child"),
        )
        for index, inventory in enumerate(invalid_inventories):
            completed = subprocess.CompletedProcess(["git"], 0, inventory, b"")
            destination = self.base / f"invalid-tree-{index}"
            with (
                self.subTest(index=index),
                patch.object(reproducible, "resolve_source_commit", return_value="a" * 40),
                patch.object(reproducible.subprocess, "run", return_value=completed),
            ):
                with self.assertRaises(reproducible.ReproducibleBuildError):
                    reproducible._copy_source_snapshot(
                        self.base,
                        destination,
                        EPOCH,
                    )
            self.assertFalse(destination.exists())

        valid_inventory = subprocess.CompletedProcess(["git"], 0, record(b"file.txt"), b"")
        with (
            patch.object(reproducible, "resolve_source_commit", return_value="a" * 40),
            patch.object(reproducible.subprocess, "run", return_value=valid_inventory),
            patch.object(reproducible, "_MAX_SDIST_MEMBERS", 0),
        ):
            with self.assertRaisesRegex(reproducible.ReproducibleBuildError, "member count"):
                reproducible._copy_source_snapshot(
                    self.base,
                    self.base / "too-many-tree-members",
                    EPOCH,
                )

        two_file_inventory = subprocess.CompletedProcess(
            ["git"],
            0,
            record(b"one.txt") + record(b"two.txt"),
            b"",
        )
        first_blob = subprocess.CompletedProcess(["git"], 0, b"one", b"")
        second_blob = subprocess.CompletedProcess(["git"], 0, b"two", b"")
        expanded_destination = self.base / "expanded-tree"
        with (
            patch.object(reproducible, "resolve_source_commit", return_value="a" * 40),
            patch.object(
                reproducible.subprocess,
                "run",
                side_effect=(two_file_inventory, first_blob, second_blob),
            ),
            patch.object(reproducible, "_MAX_EXPANDED_BYTES", 5),
        ):
            with self.assertRaisesRegex(reproducible.ReproducibleBuildError, "expanded"):
                reproducible._copy_source_snapshot(
                    self.base,
                    expanded_destination,
                    EPOCH,
                )
        self.assertFalse(expanded_destination.exists())
        self.assertEqual(list(self.base.glob(".expanded-tree.*")), [])

    def test_independent_rebuild_must_match_exactly(self) -> None:
        calls = 0
        source_roots: list[Path] = []
        primary_wheel: Path | None = None

        def snapshot(root: Path, destination: Path, epoch: int, source_ref: str) -> None:
            self.assertEqual((root, epoch, source_ref), (self.base, EPOCH, "reviewed-commit"))
            destination.mkdir(parents=True)
            (destination / "source.txt").write_bytes(b"reviewed source")

        def build(
            root: Path,
            dist: Path,
            epoch: int,
        ) -> tuple[reproducible.BuiltArtifact, reproducible.BuiltArtifact]:
            nonlocal calls, primary_wheel
            self.assertEqual(epoch, EPOCH)
            self.assertEqual((root / "source.txt").read_bytes(), b"reviewed source")
            source_roots.append(root)
            calls += 1
            dist.mkdir(parents=True)
            wheel = dist / "package.whl"
            wheel.write_bytes(b"verified-path-bytes")
            if calls == 1:
                primary_wheel = wheel
            elif calls == 2:
                self.assertIsNotNone(primary_wheel)
                primary_wheel.write_bytes(b"evil-after-verification")
            wheel_payload = b"different-wheel" if calls == 4 else b"same-wheel"
            return (
                reproducible.BuiltArtifact("package.whl", wheel_payload),
                reproducible.BuiltArtifact("package.tar.gz", b"same-sdist"),
            )

        with (
            patch.object(reproducible, "_copy_source_snapshot", side_effect=snapshot),
            patch.object(reproducible, "build_once", side_effect=build),
        ):
            artifacts = reproducible.build_reproducible(
                self.base,
                self.base / "good",
                EPOCH,
                "reviewed-commit",
            )
            self.assertEqual([path.name for path in artifacts], ["package.whl", "package.tar.gz"])
            self.assertEqual(artifacts[0].read_bytes(), b"same-wheel")
            with self.assertRaisesRegex(reproducible.ReproducibleBuildError, "differs"):
                reproducible.build_reproducible(
                    self.base,
                    self.base / "bad",
                    EPOCH,
                    "reviewed-commit",
                )
        self.assertEqual(calls, 4)
        self.assertEqual(len(set(source_roots)), 4)
        self.assertFalse((self.base / "bad").exists())

    def test_output_validation_and_publication_failure_leave_no_artifacts(self) -> None:
        output_file = self.base / "output-file"
        output_file.write_bytes(b"occupied")
        with self.assertRaisesRegex(reproducible.ReproducibleBuildError, "must not already exist"):
            reproducible.build_reproducible(self.base, output_file, EPOCH)

        occupied = self.base / "occupied"
        occupied.mkdir()
        (occupied / "existing").write_bytes(b"occupied")
        with self.assertRaisesRegex(reproducible.ReproducibleBuildError, "must not already exist"):
            reproducible.build_reproducible(self.base, occupied, EPOCH)

        empty = self.base / "empty"
        empty.mkdir()
        with self.assertRaisesRegex(reproducible.ReproducibleBuildError, "must not already exist"):
            reproducible.build_reproducible(self.base, empty, EPOCH)

        def snapshot(root: Path, destination: Path, epoch: int, source_ref: str) -> None:
            self.assertEqual((root, epoch, source_ref), (self.base, EPOCH, "HEAD"))
            destination.mkdir(parents=True)

        def build(
            root: Path,
            dist: Path,
            epoch: int,
        ) -> tuple[reproducible.BuiltArtifact, reproducible.BuiltArtifact]:
            del root
            self.assertEqual(epoch, EPOCH)
            return (
                reproducible.BuiltArtifact("package.whl", b"wheel"),
                reproducible.BuiltArtifact("package.tar.gz", b"sdist"),
            )

        output = self.base / "failed-publication"
        with (
            patch.object(reproducible, "_copy_source_snapshot", side_effect=snapshot),
            patch.object(reproducible, "build_once", side_effect=build),
            patch.object(reproducible.os, "fsync", side_effect=OSError("disk")),
        ):
            with self.assertRaisesRegex(OSError, "disk"):
                reproducible.build_reproducible(self.base, output, EPOCH)
        self.assertFalse(output.exists())
        self.assertEqual(list(self.base.glob(".failed-publication.publish.*")), [])

    def test_concurrent_output_changes_cannot_coexist_with_success(self) -> None:
        def snapshot(root: Path, destination: Path, epoch: int, source_ref: str) -> None:
            del root, epoch, source_ref
            destination.mkdir(parents=True)

        artifacts = (
            reproducible.BuiltArtifact("package.whl", b"wheel"),
            reproducible.BuiltArtifact("package.tar.gz", b"sdist"),
        )
        output = self.base / "occupied-during-build"
        calls = 0

        def occupying_build(
            root: Path,
            dist: Path,
            epoch: int,
        ) -> tuple[reproducible.BuiltArtifact, reproducible.BuiltArtifact]:
            nonlocal calls
            del root, dist, epoch
            calls += 1
            if calls == 2:
                output.mkdir()
                (output / "injected").write_bytes(b"unverified")
            return artifacts

        with (
            patch.object(reproducible, "_copy_source_snapshot", side_effect=snapshot),
            patch.object(reproducible, "build_once", side_effect=occupying_build),
            self.assertRaisesRegex(reproducible.ReproducibleBuildError, "changed during the build"),
        ):
            reproducible.build_reproducible(self.base, output, EPOCH)
        self.assertEqual([path.name for path in output.iterdir()], ["injected"])

        output = self.base / "occupied-during-rename"
        original_rename = Path.rename

        def occupy_before_rename(source: Path, target: Path) -> Path:
            if target == output:
                output.mkdir()
                (output / "injected").write_bytes(b"unverified")
            return original_rename(source, target)

        with (
            patch.object(reproducible, "_copy_source_snapshot", side_effect=snapshot),
            patch.object(reproducible, "build_once", return_value=artifacts),
            patch.object(Path, "rename", occupy_before_rename),
            self.assertRaisesRegex(reproducible.ReproducibleBuildError, "during publication"),
        ):
            reproducible.build_reproducible(self.base, output, EPOCH)
        self.assertEqual([path.name for path in output.iterdir()], ["injected"])

        output = self.base / "occupied-after-staging"
        match_artifacts = reproducible._artifact_directory_matches

        def occupy_after_staging(
            directory: Path,
            identity: tuple[int, int],
            expected: dict[str, bytes],
        ) -> bool:
            result = match_artifacts(directory, identity, expected)
            if directory.name == "artifacts" and result:
                output.mkdir()
                (output / "injected").write_bytes(b"unverified")
            return result

        with (
            patch.object(reproducible, "_copy_source_snapshot", side_effect=snapshot),
            patch.object(reproducible, "build_once", return_value=artifacts),
            patch.object(
                reproducible,
                "_artifact_directory_matches",
                side_effect=occupy_after_staging,
            ),
            self.assertRaisesRegex(reproducible.ReproducibleBuildError, "during publication"),
        ):
            reproducible.build_reproducible(self.base, output, EPOCH)
        self.assertEqual([path.name for path in output.iterdir()], ["injected"])

        output = self.base / "tampered-staging"
        fsync_calls = 0

        def inject_into_staging(file_descriptor: int) -> None:
            nonlocal fsync_calls
            del file_descriptor
            fsync_calls += 1
            if fsync_calls == 2:
                roots = tuple(self.base.glob(".tampered-staging.publish.*"))
                self.assertEqual(len(roots), 1)
                (roots[0] / "artifacts/injected").write_bytes(b"unverified")

        with (
            patch.object(reproducible, "_copy_source_snapshot", side_effect=snapshot),
            patch.object(reproducible, "build_once", return_value=artifacts),
            patch.object(reproducible.os, "fsync", side_effect=inject_into_staging),
            self.assertRaisesRegex(reproducible.ReproducibleBuildError, "before publication"),
        ):
            reproducible.build_reproducible(self.base, output, EPOCH)
        self.assertFalse(output.exists())

        output = self.base / "injected-after-rename"

        def inject_after_rename(source: Path, target: Path) -> Path:
            result = original_rename(source, target)
            if target == output:
                (output / "injected").write_bytes(b"unverified")
            return result

        with (
            patch.object(reproducible, "_copy_source_snapshot", side_effect=snapshot),
            patch.object(reproducible, "build_once", return_value=artifacts),
            patch.object(Path, "rename", inject_after_rename),
            self.assertRaisesRegex(reproducible.ReproducibleBuildError, "changed unexpectedly"),
        ):
            reproducible.build_reproducible(self.base, output, EPOCH)
        self.assertFalse(output.exists())

        output = self.base / "swapped-after-rename"
        verified_original = self.base / "verified-original"

        def swap_after_rename(source: Path, target: Path) -> Path:
            result = original_rename(source, target)
            if target == output:
                original_rename(output, verified_original)
                output.mkdir()
                (output / "injected").write_bytes(b"unverified")
            return result

        with (
            patch.object(reproducible, "_copy_source_snapshot", side_effect=snapshot),
            patch.object(reproducible, "build_once", return_value=artifacts),
            patch.object(Path, "rename", swap_after_rename),
            self.assertRaisesRegex(reproducible.ReproducibleBuildError, "changed unexpectedly"),
        ):
            reproducible.build_reproducible(self.base, output, EPOCH)
        self.assertEqual([path.name for path in output.iterdir()], ["injected"])
        self.assertEqual(
            sorted(path.name for path in verified_original.iterdir()),
            ["package.tar.gz", "package.whl"],
        )

        output = self.base / "unreadable-after-rename"
        original_stat = Path.stat

        def fail_published_stat(path: Path, *args: object, **kwargs: object) -> os.stat_result:
            if path == output and os.path.lexists(output):
                raise OSError("publication became unreadable")
            return original_stat(path, *args, **kwargs)

        with (
            patch.object(reproducible, "_copy_source_snapshot", side_effect=snapshot),
            patch.object(reproducible, "build_once", return_value=artifacts),
            patch.object(Path, "stat", fail_published_stat),
            self.assertRaisesRegex(reproducible.ReproducibleBuildError, "changed unexpectedly"),
        ):
            reproducible.build_reproducible(self.base, output, EPOCH)
        self.assertTrue(output.is_dir())

    def test_cli_reports_success_and_controlled_failures(self) -> None:
        wheel = self.base / "package.whl"
        sdist = self.base / "package.tar.gz"
        wheel.write_bytes(b"wheel")
        sdist.write_bytes(b"sdist")
        with (
            patch.object(reproducible, "resolve_source_commit", return_value="a" * 40),
            patch.object(reproducible, "build_reproducible", return_value=(wheel, sdist)) as build,
            redirect_stdout(io.StringIO()) as output,
        ):
            self.assertEqual(
                reproducible.main(["--dist-dir", "artifacts", "--epoch", str(EPOCH)]),
                0,
            )
        build.assert_called_once_with(reproducible.ROOT, Path("artifacts"), EPOCH, "a" * 40)
        self.assertIn("sha256=", output.getvalue())

        failures: tuple[BaseException, ...] = (
            OSError("filesystem"),
            reproducible.ReproducibleBuildError("mismatch"),
            subprocess.TimeoutExpired(["build"], 300),
            tarfile.TarError("archive"),
        )
        for failure in failures:
            with self.subTest(failure=failure):
                with (
                    patch.object(reproducible, "resolve_source_commit", return_value="a" * 40),
                    patch.object(reproducible, "source_date_epoch", return_value=EPOCH),
                    patch.object(reproducible, "build_reproducible", side_effect=failure),
                    redirect_stderr(io.StringIO()) as error,
                ):
                    self.assertEqual(reproducible.main([]), 1)
                self.assertIn("Reproducible build failed", error.getvalue())

        with patch.object(reproducible, "build_reproducible") as build:
            with self.assertRaises(SystemExit):
                reproducible.main(["--dist-dri", "typo"])
        build.assert_not_called()


if __name__ == "__main__":
    unittest.main()

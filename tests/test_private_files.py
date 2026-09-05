# SPDX-License-Identifier: 0BSD
from __future__ import annotations

import os
import stat
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

from cpe_access_atlas import private_files
from cpe_access_atlas.private_files import write_private_bytes, write_private_text


class PrivateFileTests(unittest.TestCase):
    def test_posix_creation_path_is_restricted_and_atomic(self) -> None:
        with TemporaryDirectory() as directory:
            target = Path(directory) / "synthetic.txt"
            with patch.object(private_files, "_IS_WINDOWS", False):
                with patch.object(
                    private_files,
                    "_restrict_permissions",
                    wraps=private_files._restrict_permissions,
                ) as restrict:
                    write_private_bytes(target, b"synthetic")
                restrict.assert_called_once()
            self.assertEqual(target.read_bytes(), b"synthetic")

    def test_windows_dispatch_does_not_substitute_chmod_for_a_native_acl(self) -> None:
        with TemporaryDirectory() as directory:
            target = Path(directory) / "synthetic.txt"
            descriptor, temporary = private_files.tempfile.mkstemp(dir=directory)
            with patch.object(private_files, "_IS_WINDOWS", True):
                with patch.object(
                    private_files, "create_private_temp", return_value=(descriptor, temporary)
                ) as native:
                    with patch.object(private_files, "_restrict_permissions") as chmod:
                        write_private_bytes(target, b"synthetic")
                native.assert_called_once_with(target)
                chmod.assert_not_called()
            self.assertEqual(target.read_bytes(), b"synthetic")

    def test_write_private_bytes_is_atomic_and_restrictive(self) -> None:
        with TemporaryDirectory() as directory:
            target = Path(directory) / "private.bin"
            write_private_bytes(target, b"first")
            self.assertEqual(target.read_bytes(), b"first")
            if os.name != "nt":
                self.assertEqual(stat.S_IMODE(target.stat().st_mode), 0o600)
            self.assertEqual(list(Path(directory).glob(".private.bin.*")), [])

            with self.assertRaises(FileExistsError):
                write_private_bytes(target, b"second")
            self.assertEqual(target.read_bytes(), b"first")

            write_private_bytes(target, b"second", replace=True)
            self.assertEqual(target.read_bytes(), b"second")

    def test_write_private_bytes_cleans_up_after_write_failure(self) -> None:
        with TemporaryDirectory() as directory:
            target = Path(directory) / "private.bin"
            with patch(
                "cpe_access_atlas.private_files.os.fdopen",
                side_effect=OSError("simulated write failure"),
            ):
                with self.assertRaisesRegex(OSError, "simulated write failure"):
                    write_private_bytes(target, b"secret")
            self.assertFalse(target.exists())
            self.assertEqual(list(Path(directory).glob(".private.bin.*")), [])

    def test_write_private_bytes_handles_racing_destination(self) -> None:
        with TemporaryDirectory() as directory:
            target = Path(directory) / "private.bin"
            real_link = os.link

            def competing_link(source: Path, destination: Path) -> None:
                destination.write_bytes(b"competing backup")
                real_link(source, destination)

            with patch("cpe_access_atlas.private_files.os.link", side_effect=competing_link):
                with self.assertRaises(FileExistsError):
                    write_private_bytes(target, b"secret")
            self.assertEqual(target.read_bytes(), b"competing backup")
            self.assertEqual(list(Path(directory).glob(".private.bin.*")), [])

    def test_unsupported_link_fails_without_publishing_or_leaving_a_temp_file(self) -> None:
        with TemporaryDirectory() as directory:
            target = Path(directory) / "private.bin"
            with patch(
                "cpe_access_atlas.private_files.os.link", side_effect=OSError("unsupported")
            ):
                with self.assertRaisesRegex(OSError, "unsupported"):
                    write_private_bytes(target, b"synthetic")
            self.assertEqual(list(Path(directory).iterdir()), [])

    def test_write_private_bytes_reports_missing_parent(self) -> None:
        with TemporaryDirectory() as directory:
            target = Path(directory) / "missing" / "private.bin"
            with self.assertRaises(FileNotFoundError):
                write_private_bytes(target, b"secret")

    def test_write_private_text_encodes_utf8(self) -> None:
        with TemporaryDirectory() as directory:
            target = Path(directory) / "private.txt"
            write_private_text(target, "şifre")
            self.assertEqual(target.read_text(encoding="utf-8"), "şifre")


if __name__ == "__main__":
    unittest.main()

# SPDX-License-Identifier: 0BSD
from __future__ import annotations

import os
import stat
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

from cpe_access_atlas.private_files import write_private_bytes, write_private_text


class PrivateFileTests(unittest.TestCase):
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
            with patch.object(Path, "exists", side_effect=[False, True]):
                with self.assertRaises(FileExistsError):
                    write_private_bytes(target, b"secret")
            self.assertEqual(list(Path(directory).glob(".private.bin.*")), [])

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

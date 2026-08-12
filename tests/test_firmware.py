# SPDX-License-Identifier: 0BSD
from __future__ import annotations

import hashlib
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

from cpe_access_atlas.firmware import FirmwareInspectionError, inspect_firmware

TARGET_VERSION = b"H3600P V9.0 TTN.10_260210"


class FirmwareInspectionTests(unittest.TestCase):
    def test_inspects_hash_version_and_common_markers(self) -> None:
        content = b"prefix" + TARGET_VERSION + b"\x27\x05\x19\x56hsqsUBI#U-Boot"
        with TemporaryDirectory() as directory:
            path = Path(directory) / "firmware.bin"
            path.write_bytes(content)
            expected_hash = hashlib.sha256(content).hexdigest().upper()
            result = inspect_firmware(
                path,
                TARGET_VERSION.decode("ascii"),
                expected_hash,
            )

        self.assertEqual(result.size, len(content))
        self.assertEqual(result.sha256, hashlib.sha256(content).hexdigest())
        self.assertEqual(result.version_strings, (TARGET_VERSION.decode("ascii"),))
        self.assertEqual(result.markers, ("SquashFS", "U-Boot", "UBI", "uImage"))
        self.assertTrue(result.exact_build_match)
        self.assertEqual(result.expected_sha256, expected_hash)
        self.assertTrue(result.sha256_match)

    def test_scans_signatures_split_across_read_chunks(self) -> None:
        content = b"x" * 7 + TARGET_VERSION + b"y" * 3 + b"Linux version"
        with TemporaryDirectory() as directory:
            path = Path(directory) / "split.bin"
            path.write_bytes(content)
            with patch("cpe_access_atlas.firmware._CHUNK_SIZE", 8):
                result = inspect_firmware(path)

        self.assertEqual(result.version_strings, (TARGET_VERSION.decode("ascii"),))
        self.assertEqual(result.markers, ("Linux",))
        self.assertIsNone(result.exact_build_match)

    def test_reports_no_matches_and_exact_mismatch(self) -> None:
        content = b"opaque bytes only"
        with TemporaryDirectory() as directory:
            path = Path(directory) / "unknown.bin"
            path.write_bytes(content)
            result = inspect_firmware(
                path,
                TARGET_VERSION.decode("ascii"),
                "0" * 64,
            )

        self.assertEqual(result.version_strings, ())
        self.assertEqual(result.markers, ())
        self.assertFalse(result.exact_build_match)
        self.assertFalse(result.sha256_match)

    def test_rejects_invalid_arguments(self) -> None:
        with self.assertRaises(FirmwareInspectionError):
            inspect_firmware(123)  # type: ignore[arg-type]
        with self.assertRaises(FirmwareInspectionError):
            inspect_firmware("artifact.bin", 123)  # type: ignore[arg-type]
        with self.assertRaises(FirmwareInspectionError):
            inspect_firmware("artifact.bin", "  ")
        with self.assertRaises(FirmwareInspectionError):
            inspect_firmware("artifact.bin", expected_sha256=123)  # type: ignore[arg-type]
        with self.assertRaises(FirmwareInspectionError):
            inspect_firmware("artifact.bin", expected_sha256="not-a-hash")

    def test_rejects_missing_or_non_file_path(self) -> None:
        with TemporaryDirectory() as directory:
            missing = Path(directory) / "missing.bin"
            with self.assertRaises(FirmwareInspectionError):
                inspect_firmware(missing)
            with self.assertRaises(FirmwareInspectionError):
                inspect_firmware(Path(directory))

    def test_converts_read_errors_to_controlled_errors(self) -> None:
        with TemporaryDirectory() as directory:
            path = Path(directory) / "unreadable.bin"
            path.write_bytes(b"data")
            with patch.object(Path, "open", side_effect=OSError("denied")):
                with self.assertRaisesRegex(FirmwareInspectionError, "unable to read"):
                    inspect_firmware(path)


if __name__ == "__main__":
    unittest.main()

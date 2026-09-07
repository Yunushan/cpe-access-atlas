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
    def test_version_identifier_boundaries_are_required(self) -> None:
        with TemporaryDirectory() as directory:
            path = Path(directory) / "synthetic.bin"
            for adjacent in (b"9", b"a", b"_modified", b"-rc1", b".1", b"+local"):
                for content in (adjacent + TARGET_VERSION, TARGET_VERSION + adjacent):
                    for chunk_size in (1, len(TARGET_VERSION), len(content), 1024):
                        with self.subTest(content=content, chunk_size=chunk_size):
                            path.write_bytes(content)
                            with patch("cpe_access_atlas.firmware._CHUNK_SIZE", chunk_size):
                                result = inspect_firmware(path, TARGET_VERSION.decode("ascii"))
                            self.assertFalse(result.exact_build_match)
                            self.assertEqual(result.version_strings, ())
                            self.assertEqual(result.size, len(content))
                            self.assertEqual(result.sha256, hashlib.sha256(content).hexdigest())

    def test_delimited_versions_are_detected_at_each_chunk_boundary(self) -> None:
        with TemporaryDirectory() as directory:
            path = Path(directory) / "synthetic.bin"
            for prefix, suffix in ((b"", b""), (b"header\x00", b"\x00tail"), (b'"', b'"')):
                content = prefix + TARGET_VERSION + suffix
                path.write_bytes(content)
                for chunk_size in range(1, len(content) + 2):
                    with self.subTest(prefix=prefix, suffix=suffix, chunk_size=chunk_size):
                        with patch("cpe_access_atlas.firmware._CHUNK_SIZE", chunk_size):
                            result = inspect_firmware(path, TARGET_VERSION.decode("ascii"))
                        self.assertTrue(result.exact_build_match)
                        self.assertEqual(result.version_strings, (TARGET_VERSION.decode("ascii"),))
                        self.assertEqual(result.size, len(content))
                        self.assertEqual(result.sha256, hashlib.sha256(content).hexdigest())

    def test_overlap_is_not_treated_as_file_start(self) -> None:
        # A long candidate exactly fills the retained overlap. Its preceding
        # identifier character must not be forgotten at the next scan or EOF.
        version = b"H3600P V9.0 TTN." + b"1" * (256 - len(b"H3600P V9.0 TTN._260210")) + b"_260210"
        self.assertEqual(len(version), 256)
        with TemporaryDirectory() as directory:
            path = Path(directory) / "synthetic.bin"
            for suffix in (b"", b"\x00"):
                path.write_bytes(b"X" + version + suffix)
                with patch("cpe_access_atlas.firmware._CHUNK_SIZE", 257):
                    result = inspect_firmware(path, version.decode("ascii"))
                self.assertFalse(result.exact_build_match)
                self.assertEqual(result.version_strings, ())

    def test_real_read_boundary_requires_the_following_byte_or_eof(self) -> None:
        prefix = b"\x00" * (1024 * 1024 - len(TARGET_VERSION))
        with TemporaryDirectory() as directory:
            path = Path(directory) / "synthetic.bin"
            for suffix, expected_match in (
                (b"9", False),
                (b"\x00Linux version", True),
                (b"", True),
            ):
                with self.subTest(suffix=suffix):
                    content = prefix + TARGET_VERSION + suffix
                    path.write_bytes(content)
                    result = inspect_firmware(path, TARGET_VERSION.decode("ascii"))
                    self.assertEqual(result.exact_build_match, expected_match)
                    self.assertEqual(result.size, len(content))
                    self.assertEqual(result.sha256, hashlib.sha256(content).hexdigest())
                    self.assertEqual(result.markers, ("Linux",) if b"Linux" in suffix else ())

    def test_multiple_versions_remain_complete_sorted_and_unique(self) -> None:
        other_version = b"H3600P V9.0 TTN.9_250626"
        content = b"\x00".join((other_version, TARGET_VERSION, TARGET_VERSION))
        with TemporaryDirectory() as directory:
            path = Path(directory) / "synthetic.bin"
            path.write_bytes(content)
            with patch("cpe_access_atlas.firmware._CHUNK_SIZE", 1):
                result = inspect_firmware(path)
        self.assertEqual(
            result.version_strings, tuple(sorted({TARGET_VERSION.decode(), other_version.decode()}))
        )
        self.assertEqual(result.size, len(content))
        self.assertEqual(result.sha256, hashlib.sha256(content).hexdigest())

    def test_empty_artifact_has_no_version_or_marker(self) -> None:
        with TemporaryDirectory() as directory:
            path = Path(directory) / "synthetic.bin"
            path.write_bytes(b"")
            result = inspect_firmware(path, TARGET_VERSION.decode("ascii"))
        self.assertEqual(result.version_strings, ())
        self.assertEqual(result.markers, ())
        self.assertEqual(result.size, 0)
        self.assertEqual(result.sha256, hashlib.sha256(b"").hexdigest())
        self.assertFalse(result.exact_build_match)

    def test_inspects_hash_version_and_common_markers(self) -> None:
        content = b"prefix\x00" + TARGET_VERSION + b"\x27\x05\x19\x56hsqsUBI#U-Boot"
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
        content = b"x" * 6 + b"\x00" + TARGET_VERSION + b"\x00yyLinux version"
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

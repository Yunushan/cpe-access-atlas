# SPDX-License-Identifier: 0BSD
from __future__ import annotations

import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

from cpe_access_atlas.uart_evidence import (
    MAX_UART_LOG_BYTES,
    MAX_UART_METADATA_VALUES,
    UartEvidenceError,
    inspect_uart_log,
)

EXPECTED = "H3600P V9.0 TTN.10_260210"


class UartEvidenceTests(unittest.TestCase):
    def test_extracts_only_bounded_non_secret_boot_metadata(self) -> None:
        content = b"\n".join(
            (
                b"H3600P V9.0 TTN.10_260210",
                b"non secure boot",
                b"non secure uboot",
                b"U-Boot 2013.04 (Dec 13 2022 - 20:57:32)",
                b"CPU  : ZX279128S@A9,1000MHZ",
                b"Board: ZTE zx279128sevb",
                b"5DRAM:  512 MiB",
                b"vid=46-H3600PV90",
                b"*** Press 1 means entering boot mode***",
                b"*** Please input bootmode password: ***",
                b"=> help",
                b"cmdline=U-Boot V1.0.0 20240228161322",
                b"Starting kernel ...",
                b"Linux version 4.1.25 (root@private-build-host)",
                b"sHardVersion=V9.0.3",
                b"h3600p login:",
                b"uid=0(root) gid=0(root)",
                b"SerialNumber=SYNTHETIC-PRIVATE-SERIAL",
                b"MAC=00:11:22:33:44:55",
                b"password=SYNTHETIC-PRIVATE-PASSWORD",
            )
        )
        with TemporaryDirectory() as directory:
            path = Path(directory) / "private-uart.log"
            path.write_bytes(content)
            result = inspect_uart_log(path, EXPECTED)

        self.assertEqual(result.size, len(content))
        self.assertEqual(result.line_count, 20)
        self.assertEqual(result.firmware_versions, (EXPECTED,))
        self.assertEqual(result.firmware_identity_status, "matched")
        self.assertEqual(result.bootloader_versions, ("2013.04", "V1.0.0"))
        self.assertEqual(
            result.bootloader_builds,
            ("20240228161322", "Dec 13 2022 - 20:57:32"),
        )
        self.assertEqual(result.linux_versions, ("4.1.25",))
        self.assertEqual(result.hardware_versions, ("V9.0.3",))
        self.assertEqual(result.soc_models, ("ZX279128S",))
        self.assertEqual(result.board_models, ("ZTE zx279128sevb",))
        self.assertEqual(result.product_ids, ("46-H3600PV90",))
        self.assertEqual(result.dram_mib, (512,))
        self.assertEqual((result.boot_security, result.uboot_security), ("non-secure",) * 2)
        self.assertTrue(result.boot_interrupt_prompt_observed)
        self.assertTrue(result.bootloader_access_gate_observed)
        self.assertTrue(result.bootloader_shell_prompt_observed)
        self.assertTrue(result.kernel_start_observed)
        self.assertTrue(result.linux_console_output_observed)
        self.assertTrue(result.linux_login_prompt_observed)
        self.assertTrue(result.uid_zero_marker_observed)
        self.assertTrue(result.recognized_h3600p_boot_output)
        self.assertFalse(result.device_io_attempted)
        self.assertFalse(result.raw_log_output)
        self.assertFalse(result.non_allowlisted_values_emitted)
        self.assertFalse(result.root_access_verified)
        self.assertNotIn("SYNTHETIC-PRIVATE", repr(result))
        self.assertNotIn("00:11:22", repr(result))

    def test_reports_secure_conflicting_and_absent_boot_states(self) -> None:
        cases = (
            (b"secure boot\nsecure uboot", "secure"),
            (b"non secure boot\nsecure boot\nnon secure uboot\nsecure uboot", "conflicting"),
            (b"unrelated", "not-observed"),
        )
        with TemporaryDirectory() as directory:
            path = Path(directory) / "capture.log"
            for content, expected in cases:
                with self.subTest(expected=expected):
                    path.write_bytes(content)
                    result = inspect_uart_log(path, EXPECTED)
                    self.assertEqual((result.boot_security, result.uboot_security), (expected,) * 2)

    def test_distinguishes_other_build_and_unobserved_identity(self) -> None:
        with TemporaryDirectory() as directory:
            path = Path(directory) / "capture.log"
            path.write_bytes(b"H3600P V9.0 TTN.8_250626")
            different = inspect_uart_log(path, EXPECTED)
            self.assertEqual(different.firmware_identity_status, "different-build-observed")
            self.assertEqual(different.firmware_versions, ("H3600P V9.0 TTN.8_250626",))
            self.assertTrue(different.recognized_h3600p_boot_output)

            path.write_bytes(b"U-Boot V1.0.0\nZX279128S\n")
            inferred = inspect_uart_log(path, EXPECTED)
            self.assertEqual(inferred.firmware_identity_status, "not-observed")
            self.assertTrue(inferred.recognized_h3600p_boot_output)
            self.assertEqual(inferred.bootloader_builds, ())

            path.write_bytes(b"unrecognized\xffbinary")
            absent = inspect_uart_log(path, EXPECTED)
            self.assertEqual(absent.firmware_identity_status, "not-observed")
            self.assertFalse(absent.recognized_h3600p_boot_output)
            self.assertEqual(absent.line_count, 1)

            path.write_bytes(
                b"U-Boot 123SECRET (password SYNTHETIC-PRIVATE)\n"
                b"Linux version 123SECRET\nBoard: ZTE zxSYNTHETICPRIVATE\n"
            )
            allow_listed = inspect_uart_log(path, EXPECTED)
            self.assertEqual(allow_listed.bootloader_versions, ())
            self.assertEqual(allow_listed.bootloader_builds, ())
            self.assertEqual(allow_listed.linux_versions, ())
            self.assertEqual(allow_listed.board_models, ())
            self.assertNotIn("SYNTHETIC-PRIVATE", repr(allow_listed))

    def test_empty_log_is_valid_but_has_no_observations(self) -> None:
        with TemporaryDirectory() as directory:
            path = Path(directory) / "empty.log"
            path.write_bytes(b"")
            result = inspect_uart_log(path, EXPECTED)
        self.assertEqual(result.size, 0)
        self.assertEqual(result.line_count, 0)
        self.assertEqual(result.firmware_versions, ())
        self.assertEqual(result.bootloader_versions, ())
        self.assertFalse(result.bootloader_shell_prompt_observed)

    def test_rejects_invalid_arguments_missing_paths_and_oversized_logs(self) -> None:
        with self.assertRaises(UartEvidenceError):
            inspect_uart_log(123, EXPECTED)  # type: ignore[arg-type]
        with self.assertRaises(UartEvidenceError):
            inspect_uart_log("capture.log", 123)  # type: ignore[arg-type]
        with self.assertRaises(UartEvidenceError):
            inspect_uart_log("capture.log", "  ")
        with self.assertRaisesRegex(UartEvidenceError, "bounded printable ASCII"):
            inspect_uart_log("capture.log", "x" * 257)
        with self.assertRaisesRegex(UartEvidenceError, "bounded printable ASCII"):
            inspect_uart_log("capture.log", EXPECTED + "\n")
        with self.assertRaisesRegex(UartEvidenceError, "bounded printable ASCII"):
            inspect_uart_log("capture.log", EXPECTED + "é")

        with TemporaryDirectory() as directory:
            missing = Path(directory) / "missing.log"
            with self.assertRaisesRegex(UartEvidenceError, "does not exist"):
                inspect_uart_log(missing, EXPECTED)
            with self.assertRaisesRegex(UartEvidenceError, "not a regular file"):
                inspect_uart_log(Path(directory), EXPECTED)

            oversized = Path(directory) / "oversized.log"
            oversized.write_bytes(b"x" * (MAX_UART_LOG_BYTES + 1))
            with self.assertRaisesRegex(UartEvidenceError, "8 MiB"):
                inspect_uart_log(oversized, EXPECTED)

    def test_converts_read_errors_to_controlled_errors(self) -> None:
        with TemporaryDirectory() as directory:
            path = Path(directory) / "capture.log"
            path.write_bytes(b"data")
            with patch.object(Path, "open", side_effect=OSError("denied")):
                with self.assertRaisesRegex(UartEvidenceError, "unable to read"):
                    inspect_uart_log(path, EXPECTED)

    def test_overlong_firmware_build_fails_closed_without_emitting_the_marker(self) -> None:
        with TemporaryDirectory() as directory:
            path = Path(directory) / "synthetic-uart.log"
            path.write_bytes(b"H3600P V9.0 TTN." + b"1" * 16 + b"_260210\n")
            self.assertEqual(len(inspect_uart_log(path, EXPECTED).firmware_versions), 1)
            for digits in (b"1" * 17, b"1" * 65536):
                with self.subTest(digit_count=len(digits)):
                    path.write_bytes(b"H3600P V9.0 TTN." + digits + b"_260210\n")
                    with self.assertRaisesRegex(
                        UartEvidenceError, "overlong firmware version marker"
                    ) as error:
                        inspect_uart_log(path, EXPECTED)
                    self.assertNotIn(str(path), str(error.exception))
                    self.assertNotIn("11111111111111111", str(error.exception))
                    self.assertIsNone(error.exception.__cause__)

    def test_each_extracted_metadata_field_has_a_distinct_value_limit(self) -> None:
        cases = (
            ("firmware versions", lambda i: f"H3600P V9.0 TTN.{i}_260210"),
            ("bootloader versions", lambda i: f"U-Boot 1.{i}"),
            ("Linux versions", lambda i: f"Linux version 1.{i}"),
            ("hardware versions", lambda i: f"sHardVersion=V9.{i}"),
            ("product IDs", lambda i: f"vid={i}-H3600PV90"),
            ("DRAM sizes", lambda i: f"DRAM: {i} MiB"),
        )
        with TemporaryDirectory() as directory:
            path = Path(directory) / "private-synthetic-uart.log"
            for label, make_line in cases:
                with self.subTest(field=label):
                    lines = [make_line(index) for index in range(MAX_UART_METADATA_VALUES + 1)]
                    duplicate = "DRAM: 0000 MiB" if label == "DRAM sizes" else lines[0]
                    path.write_text("\n".join([*lines[:-1], duplicate]), encoding="ascii")
                    result = inspect_uart_log(path, EXPECTED)
                    field = {
                        "firmware versions": result.firmware_versions,
                        "bootloader versions": result.bootloader_versions,
                        "Linux versions": result.linux_versions,
                        "hardware versions": result.hardware_versions,
                        "product IDs": result.product_ids,
                        "DRAM sizes": result.dram_mib,
                    }[label]
                    self.assertEqual(len(field), MAX_UART_METADATA_VALUES)

                    path.write_text("\n".join(lines), encoding="ascii")
                    with self.assertRaisesRegex(
                        UartEvidenceError, f"too many distinct {label}"
                    ) as error:
                        inspect_uart_log(path, EXPECTED)
                    self.assertNotIn(str(path), str(error.exception))
                    self.assertIsNone(error.exception.__cause__)

    def test_combined_bootloader_values_cannot_exceed_the_limit(self) -> None:
        with TemporaryDirectory() as directory:
            path = Path(directory) / "synthetic-uart.log"
            release_versions = [f"U-Boot 1.{index}" for index in range(128)]
            cmdline_versions = [f"cmdline=U-Boot 2.{index}" for index in range(129)]
            path.write_text("\n".join(release_versions + cmdline_versions[:-1]), encoding="ascii")
            self.assertEqual(
                len(inspect_uart_log(path, EXPECTED).bootloader_versions),
                MAX_UART_METADATA_VALUES,
            )
            path.write_text("\n".join(release_versions + cmdline_versions), encoding="ascii")
            with self.assertRaisesRegex(UartEvidenceError, "too many distinct bootloader versions"):
                inspect_uart_log(path, EXPECTED)

            release_builds = [
                f"U-Boot 1.0 (Jan 1 2020 - 00:{index // 60:02d}:{index % 60:02d})"
                for index in range(128)
            ]
            cmdline_builds = [f"cmdline=U-Boot 1.0 20240228{index:06d}" for index in range(129)]
            path.write_text("\n".join(release_builds + cmdline_builds[:-1]), encoding="ascii")
            self.assertEqual(
                len(inspect_uart_log(path, EXPECTED).bootloader_builds),
                MAX_UART_METADATA_VALUES,
            )
            path.write_text("\n".join(release_builds + cmdline_builds), encoding="ascii")
            with self.assertRaisesRegex(UartEvidenceError, "too many distinct bootloader builds"):
                inspect_uart_log(path, EXPECTED)


if __name__ == "__main__":
    unittest.main()

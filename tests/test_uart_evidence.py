# SPDX-License-Identifier: 0BSD
from __future__ import annotations

import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

from cpe_access_atlas.uart_evidence import (
    MAX_UART_LOG_BYTES,
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


if __name__ == "__main__":
    unittest.main()

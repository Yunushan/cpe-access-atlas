# SPDX-License-Identifier: 0BSD
"""CLI safety and integration tests for local private-container protection."""

from __future__ import annotations

import io
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

from cpe_access_atlas.cli import main

AUTH = "--i-am-authorized-to-handle-this-private-file"
PASSPHRASE = "correct horse battery staple"


class PrivateContainerCliTests(unittest.TestCase):
    @staticmethod
    def run_cli(args: list[str], stdin: str = "") -> tuple[int, str, str]:
        stdout, stderr = io.StringIO(), io.StringIO()
        with (
            redirect_stdout(stdout),
            redirect_stderr(stderr),
            patch("cpe_access_atlas.cli.sys.stdin", io.StringIO(stdin)),
        ):
            code = main(args)
        return code, stdout.getvalue(), stderr.getvalue()

    def test_private_protect_and_unprotect_round_trip_without_printing_secrets(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            source, protected, restored = (
                root / "config.bin",
                root / "config.cpap",
                root / "restored.bin",
            )
            secret_data = b"password=SYNTHETIC_PRIVATE_VALUE\x00"
            source.write_bytes(secret_data)

            code, stdout, stderr = self.run_cli(
                [
                    "private-protect",
                    "--input",
                    str(source),
                    "--output",
                    str(protected),
                    "--passphrase-stdin",
                    AUTH,
                ],
                PASSPHRASE + "\n",
            )
            self.assertEqual((code, stderr), (0, ""))
            self.assertIn("authenticated private container", stdout)
            self.assertNotIn("SYNTHETIC_PRIVATE_VALUE", stdout)
            self.assertNotIn(PASSPHRASE, stdout)
            self.assertNotEqual(protected.read_bytes(), secret_data)

            code, stdout, stderr = self.run_cli(
                [
                    "private-unprotect",
                    "--input",
                    str(protected),
                    "--output",
                    str(restored),
                    "--passphrase-stdin",
                    AUTH,
                ],
                PASSPHRASE + "\r\n",
            )
            self.assertEqual((code, stderr), (0, ""))
            self.assertIn("Wrote private artifact", stdout)
            self.assertIn("keep it protected and local", stdout)
            self.assertEqual(restored.read_bytes(), secret_data)

    def test_commands_require_authorization_before_reading_or_prompting(self) -> None:
        for command in ("private-protect", "private-unprotect"):
            with self.subTest(command=command), patch("cpe_access_atlas.cli._read_secret") as read:
                code, stdout, stderr = self.run_cli(
                    [
                        command,
                        "--input",
                        "missing.private",
                        "--output",
                        "output.private",
                    ]
                )
            self.assertEqual((code, stdout), (3, ""))
            self.assertIn("explicit authorization", stderr)
            read.assert_not_called()

    def test_existing_output_is_not_replaced_or_prompted(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            source, output = root / "source.bin", root / "output.bin"
            source.write_bytes(b"private")
            output.write_bytes(b"original")
            for command in ("private-protect", "private-unprotect"):
                with (
                    self.subTest(command=command),
                    patch("cpe_access_atlas.cli._read_secret") as read,
                ):
                    code, stdout, stderr = self.run_cli(
                        [
                            command,
                            "--input",
                            str(source),
                            "--output",
                            str(output),
                            AUTH,
                        ]
                    )
                self.assertEqual((code, stdout), (4, ""))
                self.assertIn("already exists", stderr)
                read.assert_not_called()
                self.assertEqual(output.read_bytes(), b"original")

    def test_same_input_and_output_is_always_rejected(self) -> None:
        with TemporaryDirectory() as directory:
            source = Path(directory) / "private.bin"
            source.write_bytes(b"private")
            for command in ("private-protect", "private-unprotect"):
                with (
                    self.subTest(command=command),
                    patch("cpe_access_atlas.cli._read_secret") as read,
                ):
                    code, stdout, stderr = self.run_cli(
                        [command, "--input", str(source), "--output", str(source), AUTH]
                    )
                self.assertEqual((code, stdout), (2, ""))
                self.assertIn("must differ", stderr)
                read.assert_not_called()
                self.assertEqual(source.read_bytes(), b"private")

    def test_invalid_passphrase_and_authentication_errors_are_sanitized(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            source, protected, restored = (
                root / "source.bin",
                root / "protected.bin",
                root / "restored.bin",
            )
            source.write_bytes(b"private")
            code, stdout, stderr = self.run_cli(
                [
                    "private-protect",
                    "--input",
                    str(source),
                    "--output",
                    str(protected),
                    "--passphrase-stdin",
                    AUTH,
                ],
                "short\n",
            )
            self.assertEqual((code, stdout), (2, ""))
            self.assertIn("12-256 printable", stderr)
            self.assertFalse(protected.exists())

            self.run_cli(
                [
                    "private-protect",
                    "--input",
                    str(source),
                    "--output",
                    str(protected),
                    "--passphrase-stdin",
                    AUTH,
                ],
                PASSPHRASE + "\n",
            )
            code, stdout, stderr = self.run_cli(
                [
                    "private-unprotect",
                    "--input",
                    str(protected),
                    "--output",
                    str(restored),
                    "--passphrase-stdin",
                    AUTH,
                ],
                "wrong correct passphrase\n",
            )
            self.assertEqual((code, stdout), (2, ""))
            self.assertIn("authentication failed", stderr)
            self.assertFalse(restored.exists())

    def test_input_errors_are_controlled_and_do_not_prompt(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            output = root / "output.bin"
            for command, label in (
                ("private-protect", "private artifact"),
                ("private-unprotect", "private container"),
            ):
                with (
                    self.subTest(command=command),
                    patch("cpe_access_atlas.cli._read_secret") as read,
                ):
                    code, stdout, stderr = self.run_cli(
                        [
                            command,
                            "--input",
                            str(root / "missing.bin"),
                            "--output",
                            str(output),
                            AUTH,
                        ]
                    )
                self.assertEqual((code, stdout), (2, ""))
                self.assertIn("unable to read " + label, stderr)
                read.assert_not_called()

            empty = root / "empty.bin"
            empty.write_bytes(b"")
            code, stdout, stderr = self.run_cli(
                ["private-protect", "--input", str(empty), "--output", str(output), AUTH]
            )
            self.assertEqual((code, stdout), (2, ""))
            self.assertIn("private artifact is empty", stderr)

            oversized = root / "oversized.bin"
            oversized.write_bytes(b"12345")
            with patch("cpe_access_atlas.cli.MAX_PRIVATE_BYTES", 4):
                code, stdout, stderr = self.run_cli(
                    ["private-protect", "--input", str(oversized), "--output", str(output), AUTH]
                )
            self.assertEqual((code, stdout), (2, ""))
            self.assertIn("private artifact exceeds", stderr)

    def test_write_races_and_write_failures_are_handled(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            source, output = root / "source.bin", root / "output.bin"
            source.write_bytes(b"private")
            protect_args = [
                "private-protect",
                "--input",
                str(source),
                "--output",
                str(output),
                "--passphrase-stdin",
                AUTH,
            ]
            with patch(
                "cpe_access_atlas.cli.write_private_bytes", side_effect=FileExistsError("race")
            ):
                code, stdout, stderr = self.run_cli(protect_args, PASSPHRASE + "\n")
            self.assertEqual((code, stdout), (4, ""))
            self.assertIn("already exists", stderr)

            with patch("cpe_access_atlas.cli.write_private_bytes", side_effect=OSError("disk")):
                code, stdout, stderr = self.run_cli(protect_args, PASSPHRASE + "\n")
            self.assertEqual((code, stdout), (1, ""))
            self.assertIn("filesystem operation failed", stderr)

    def test_unprotect_write_failure_is_controlled(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            source, protected, output = (
                root / "source.bin",
                root / "protected.bin",
                root / "output.bin",
            )
            source.write_bytes(b"private")
            self.run_cli(
                [
                    "private-protect",
                    "--input",
                    str(source),
                    "--output",
                    str(protected),
                    "--passphrase-stdin",
                    AUTH,
                ],
                PASSPHRASE + "\n",
            )
            with patch("cpe_access_atlas.cli.write_private_bytes", side_effect=OSError("disk")):
                code, stdout, stderr = self.run_cli(
                    [
                        "private-unprotect",
                        "--input",
                        str(protected),
                        "--output",
                        str(output),
                        "--passphrase-stdin",
                        AUTH,
                    ],
                    PASSPHRASE + "\n",
                )
            self.assertEqual((code, stdout), (1, ""))
            self.assertIn("filesystem operation failed", stderr)

            with patch(
                "cpe_access_atlas.cli.write_private_bytes", side_effect=FileExistsError("race")
            ):
                code, stdout, stderr = self.run_cli(
                    [
                        "private-unprotect",
                        "--input",
                        str(protected),
                        "--output",
                        str(output),
                        "--passphrase-stdin",
                        AUTH,
                    ],
                    PASSPHRASE + "\n",
                )
            self.assertEqual((code, stdout), (4, ""))
            self.assertIn("already exists", stderr)


if __name__ == "__main__":
    unittest.main()

# SPDX-License-Identifier: 0BSD
from __future__ import annotations

import argparse
import getpass
import unittest
import warnings
from contextlib import redirect_stderr, redirect_stdout
from io import StringIO
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import Mock, patch

from cpe_access_atlas.cli import _read_secret, main
from cpe_access_atlas.config import ConfigError, decode_config

_TARGET = (
    "--isp",
    "turk-telekom",
    "--model",
    "H3600P",
    "--hardware-revision",
    "V9.0",
    "--firmware",
    "H3600P V9.0 TTN.10_260210",
)
_SECRET_FIELDS = (
    ("ssh_password_stdin", "SSH password", 128),
    ("device_key_stdin", "H3600P device encryption passphrase", 32),
)


class SecretInputTests(unittest.TestCase):
    def test_real_getpass_fallback_is_stopped_before_visible_read(self) -> None:
        for policy in ("ignore", "always", "error"):
            for option, label, limit in _SECRET_FIELDS:
                with self.subTest(policy=policy, option=option), warnings.catch_warnings():
                    warnings.simplefilter(policy, getpass.GetPassWarning)
                    original_filters = list(warnings.filters)
                    with (
                        patch("cpe_access_atlas.cli.getpass.getpass", getpass.fallback_getpass),
                        patch("getpass._raw_input", return_value="SYNTHETIC_ONLY") as raw_input,
                        self.assertRaisesRegex(ConfigError, "hidden secret input is unavailable"),
                    ):
                        _read_secret(
                            argparse.Namespace(), option, "Synthetic: ", label, max_chars=limit
                        )
                    raw_input.assert_not_called()
                    self.assertEqual(warnings.filters, original_filters)

    def test_hidden_prompt_success_preserves_warning_policy(self) -> None:
        for option, label, limit in _SECRET_FIELDS:
            with self.subTest(option=option), warnings.catch_warnings():
                warnings.simplefilter("ignore", getpass.GetPassWarning)
                original_filters = list(warnings.filters)
                secret = "s" * limit
                with patch("cpe_access_atlas.cli.getpass.getpass", return_value=secret) as prompt:
                    self.assertEqual(
                        _read_secret(
                            argparse.Namespace(), option, "Synthetic: ", label, max_chars=limit
                        ),
                        secret,
                    )
                prompt.assert_called_once_with("Synthetic: ")
                self.assertEqual(warnings.filters, original_filters)

    def test_stdin_reads_are_bounded_and_preserve_the_next_line(self) -> None:
        for option, label, limit in _SECRET_FIELDS:
            for ending in ("\n", "\r\n", "", "\r"):
                with self.subTest(option=option, ending=ending):
                    secret = "s" * limit
                    suffix = "NEXT_SYNTHETIC_SECRET\n" if ending.endswith("\n") else ""
                    source = StringIO(secret + ending + suffix)
                    reader = Mock(wraps=source)
                    with (
                        patch("cpe_access_atlas.cli.sys.stdin", reader),
                        patch("cpe_access_atlas.cli.getpass.getpass") as prompt,
                    ):
                        self.assertEqual(
                            _read_secret(
                                argparse.Namespace(**{option: True}),
                                option,
                                "Unused: ",
                                label,
                                max_chars=limit,
                            ),
                            secret,
                        )
                    reader.readline.assert_called_once_with(limit + 2)
                    prompt.assert_not_called()
                    self.assertEqual(source.read(), suffix)

    def test_oversized_stdin_does_not_drain_or_truncate_into_an_accepted_secret(self) -> None:
        for option, label, limit in _SECRET_FIELDS:
            for value in ("s" * (limit + 1), "s" * 1_000_000, "s" * limit + "\r\r"):
                with self.subTest(option=option, size=len(value)):
                    source = StringIO(value + "\nNEXT_SYNTHETIC_SECRET\n")
                    reader = Mock(wraps=source)
                    with patch("cpe_access_atlas.cli.sys.stdin", reader):
                        with self.assertRaisesRegex(ConfigError, f"{limit}-character input limit"):
                            _read_secret(
                                argparse.Namespace(**{option: True}),
                                option,
                                "Unused: ",
                                label,
                                max_chars=limit,
                            )
                    reader.readline.assert_called_once_with(limit + 2)
                    self.assertLessEqual(source.tell(), limit + 2)

    def test_prompt_and_stdin_failures_are_sanitized(self) -> None:
        errors = (
            EOFError("SYNTHETIC_PRIVATE_DIAGNOSTIC"),
            OSError("SYNTHETIC_PRIVATE_DIAGNOSTIC"),
            ValueError("SYNTHETIC_PRIVATE_DIAGNOSTIC"),
            UnicodeDecodeError("utf-8", b"\xff", 0, 1, "SYNTHETIC_PRIVATE_DIAGNOSTIC"),
        )
        for option, label, limit in _SECRET_FIELDS:
            for stdin_mode in (False, True):
                for error in errors:
                    with self.subTest(option=option, stdin=stdin_mode, error=type(error).__name__):
                        reader = Mock()
                        reader.readline.side_effect = error
                        with (
                            patch("cpe_access_atlas.cli.sys.stdin", reader),
                            patch("cpe_access_atlas.cli.getpass.getpass", side_effect=error),
                            self.assertRaises(ConfigError) as caught,
                        ):
                            _read_secret(
                                argparse.Namespace(**{option: stdin_mode}),
                                option,
                                "Synthetic: ",
                                label,
                                max_chars=limit,
                            )
                        self.assertNotIn("SYNTHETIC_PRIVATE_DIAGNOSTIC", str(caught.exception))
                        self.assertIn(label, str(caught.exception))

    def test_empty_and_oversized_hidden_secrets_are_rejected(self) -> None:
        for option, label, limit in _SECRET_FIELDS:
            for value, expected in (("", "must not be empty"), ("s" * (limit + 1), "input limit")):
                with self.subTest(option=option, size=len(value)):
                    with patch("cpe_access_atlas.cli.getpass.getpass", return_value=value):
                        with self.assertRaisesRegex(ConfigError, expected):
                            _read_secret(
                                argparse.Namespace(),
                                option,
                                "Synthetic: ",
                                label,
                                max_chars=limit,
                            )

    def test_cli_secret_failures_preserve_existing_artifact_and_print_no_diagnostics(self) -> None:
        for failed_prompt in (0, 1):
            for error, expected_code in (
                (getpass.GetPassWarning("SYNTHETIC_PRIVATE_DIAGNOSTIC"), 2),
                (EOFError("SYNTHETIC_PRIVATE_DIAGNOSTIC"), 2),
                (OSError("SYNTHETIC_PRIVATE_DIAGNOSTIC"), 2),
                (KeyboardInterrupt(), 130),
            ):
                with self.subTest(prompt=failed_prompt, error=type(error).__name__):
                    with TemporaryDirectory() as directory:
                        output = Path(directory) / "synthetic.bin"
                        output.write_bytes(b"preserve-existing-artifact")
                        stdout, stderr = StringIO(), StringIO()
                        values = ["SYNTHETIC_SSH_PASSWORD"] * failed_prompt + [error]
                        with (
                            redirect_stdout(stdout),
                            redirect_stderr(stderr),
                            patch("cpe_access_atlas.cli.getpass.getpass", side_effect=values),
                        ):
                            code = main(
                                [
                                    "config-generate",
                                    *_TARGET,
                                    "--output",
                                    str(output),
                                    "--force",
                                    "--encrypted",
                                    "--serial",
                                    "ZTE12345678",
                                    "--mac",
                                    "00:11:22:33:44:55",
                                    "--i-own-or-administer-this-device",
                                ]
                            )
                        self.assertEqual((code, stdout.getvalue()), (expected_code, ""))
                        self.assertNotIn("SYNTHETIC", stderr.getvalue())
                        self.assertNotIn("Traceback", stderr.getvalue())
                        self.assertEqual(output.read_bytes(), b"preserve-existing-artifact")
                        self.assertEqual(list(Path(directory).iterdir()), [output])

    def test_cli_maximum_length_secrets_with_crlf_keep_both_values_intact(self) -> None:
        with TemporaryDirectory() as directory:
            output = Path(directory) / "synthetic.bin"
            password, key = "s" * 128, "k" * 32
            stdout, stderr = StringIO(), StringIO()
            with (
                redirect_stdout(stdout),
                redirect_stderr(stderr),
                patch("cpe_access_atlas.cli.sys.stdin", StringIO(password + "\r\n" + key + "\r\n")),
                patch("cpe_access_atlas.cli.getpass.getpass") as prompt,
            ):
                code = main(
                    [
                        "config-generate",
                        *_TARGET,
                        "--output",
                        str(output),
                        "--encrypted",
                        "--serial",
                        "ZTE12345678",
                        "--mac",
                        "00:11:22:33:44:55",
                        "--ssh-password-stdin",
                        "--device-key-stdin",
                        "--i-own-or-administer-this-device",
                    ]
                )
            self.assertEqual((code, stderr.getvalue()), (0, ""))
            prompt.assert_not_called()
            self.assertNotIn(password, stdout.getvalue())
            self.assertNotIn(key, stdout.getvalue())
            decoded = decode_config(
                output.read_bytes(),
                device_key=key,
                serial="ZTE12345678",
                mac="00:11:22:33:44:55",
            )
            self.assertIn(password.encode(), decoded.xml)


if __name__ == "__main__":
    unittest.main()

# SPDX-License-Identifier: 0BSD
from __future__ import annotations

import hashlib
import json
import runpy
import unittest
from contextlib import redirect_stderr, redirect_stdout
from dataclasses import replace
from io import StringIO
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace
from unittest.mock import Mock, patch
from xml.etree import ElementTree as ET

from cpe_access_atlas.catalog import find_recipe
from cpe_access_atlas.cli import _configure_stdio, main
from cpe_access_atlas.config import decode_config, default_root_xml, encode_config

TARGET = [
    "--isp",
    "Türk Telekom",
    "--model",
    "ZTE H3600P",
    "--hardware-revision",
    "V9.0",
    "--firmware",
    "H3600P V9.0 TTN.10_260210",
]


class CliTests(unittest.TestCase):
    def run_cli(self, args: list[str]) -> tuple[int, str, str]:
        stdout = StringIO()
        stderr = StringIO()
        with redirect_stdout(stdout), redirect_stderr(stderr):
            code = main(args)
        return code, stdout.getvalue(), stderr.getvalue()

    def test_stdio_encoding_configuration_is_best_effort(self) -> None:
        stdout = SimpleNamespace(reconfigure=Mock())
        stderr = SimpleNamespace(reconfigure=Mock())
        with patch("cpe_access_atlas.cli.sys.stdout", stdout), patch(
            "cpe_access_atlas.cli.sys.stderr", stderr
        ):
            _configure_stdio()
        stdout.reconfigure.assert_called_once_with(
            encoding="utf-8", errors="backslashreplace"
        )
        stderr.reconfigure.assert_called_once_with(
            encoding="utf-8", errors="backslashreplace"
        )

    def test_status_reports_blocked_and_no_change(self) -> None:
        code, stdout, stderr = self.run_cli(["status", *TARGET])
        self.assertEqual(code, 0)
        self.assertEqual(stderr, "")
        self.assertIn("Status:     blocked", stdout)
        self.assertIn("No device change was attempted", stdout)

    def test_provider_and_recipe_listing_support_text_and_json(self) -> None:
        code, stdout, stderr = self.run_cli(["providers"])
        self.assertEqual((code, stderr), (0, ""))
        self.assertIn("Provider ID", stdout)

        code, stdout, stderr = self.run_cli(["providers", "--json"])
        self.assertEqual((code, stderr), (0, ""))
        self.assertIn('"turk-telekom"', stdout)

        code, stdout, stderr = self.run_cli(["recipes"])
        self.assertEqual((code, stderr), (0, ""))
        self.assertIn("tr.turk-telekom", stdout)

        code, stdout, stderr = self.run_cli(["recipes", "--json"])
        self.assertEqual((code, stderr), (0, ""))
        self.assertIn('"hardware_revision"', stdout)

    def test_official_device_listing_supports_text_json_and_filtering(self) -> None:
        code, stdout, stderr = self.run_cli(["devices"])
        self.assertEqual((code, stderr), (0, ""))
        self.assertIn("Official listings only", stdout)
        self.assertIn("H3600P", stdout)

        code, stdout, stderr = self.run_cli(
            ["devices", "--isp", "Turkcell Superonline", "--json"]
        )
        self.assertEqual((code, stderr), (0, ""))
        payload = json.loads(stdout)
        self.assertEqual({item["provider_id"] for item in payload}, {"turkcell-superonline"})
        self.assertTrue(any(item["model"] == "H3600P" for item in payload))

        code, stdout, stderr = self.run_cli(["devices", "--isp", "TurkNet"])
        self.assertEqual((code, stderr), (0, ""))
        self.assertIn("No official device listings", stdout)

    def test_status_json_and_evidence(self) -> None:
        code, stdout, stderr = self.run_cli(["status", *TARGET, "--json"])
        self.assertEqual((code, stderr), (0, ""))
        self.assertIn('"status": "blocked"', stdout)

        code, stdout, stderr = self.run_cli(["evidence", *TARGET])
        self.assertEqual((code, stderr), (0, ""))
        self.assertIn("Official ZTE H3600P product page", stdout)

    def test_plan_stops_on_exact_build(self) -> None:
        code, stdout, _ = self.run_cli(["plan", *TARGET])
        self.assertEqual(code, 0)
        self.assertIn("Decision: STOP", stdout)
        self.assertIn("will not substitute", stdout)

    def test_plan_requires_review_for_non_blocked_recipe(self) -> None:
        recipe = find_recipe(
            "turk-telekom",
            "H3600P",
            "V9.0",
            "H3600P V9.0 TTN.10_260210",
        )
        with patch(
            "cpe_access_atlas.cli._recipe_from_args",
            return_value=replace(
                recipe,
                status="experimental",
                blockers=(),
                hardware_revision_status="exact",
            ),
        ):
            code, stdout, stderr = self.run_cli(["plan", *TARGET])
        self.assertEqual((code, stderr), (0, ""))
        self.assertIn("REVIEW REQUIRED", stdout)

    def test_root_readiness_stops_without_artifact_or_verified_method(self) -> None:
        code, stdout, stderr = self.run_cli(["root-readiness", *TARGET])
        self.assertEqual((code, stderr), (1, ""))
        self.assertIn("Decision: STOP", stdout)
        self.assertIn("artifact was supplied", stdout)
        self.assertIn("No device connection", stdout)

    def test_root_readiness_json_reports_private_artifact_checks(self) -> None:
        version = "H3600P V9.0 TTN.10_260210"
        with TemporaryDirectory() as directory:
            artifact = Path(directory) / "firmware.bin"
            artifact.write_bytes(b"header" + version.encode("ascii"))
            expected_hash = hashlib.sha256(artifact.read_bytes()).hexdigest()
            code, stdout, stderr = self.run_cli(
                [
                    "root-readiness",
                    *TARGET,
                    "--firmware-input",
                    str(artifact),
                    "--expected-sha256",
                    expected_hash,
                    "--json",
                ]
            )
        self.assertEqual((code, stderr), (1, ""))
        payload = json.loads(stdout)
        self.assertEqual(payload["decision"], "STOP")
        self.assertTrue(payload["checks"]["firmware_exact_build_match"])
        self.assertTrue(payload["checks"]["firmware_sha256_match"])
        self.assertTrue(payload["checks"]["firmware_identity_verified"])
        self.assertFalse(payload["device_io_attempted"])
        self.assertIn("firmware_artifact", payload)

    def test_root_readiness_reports_hash_mismatch(self) -> None:
        version = "H3600P V9.0 TTN.10_260210"
        with TemporaryDirectory() as directory:
            artifact = Path(directory) / "firmware.bin"
            artifact.write_bytes(b"header" + version.encode("ascii"))
            code, stdout, stderr = self.run_cli(
                [
                    "root-readiness",
                    *TARGET,
                    "--firmware-input",
                    str(artifact),
                    "--expected-sha256",
                    "0" * 64,
                ]
            )
        self.assertEqual((code, stderr), (1, ""))
        self.assertIn("SHA-256 match: False", stdout)
        self.assertIn("does not match the expected SHA-256", stdout)

    def test_root_readiness_reports_exact_build_mismatch(self) -> None:
        with TemporaryDirectory() as directory:
            artifact = Path(directory) / "firmware.bin"
            artifact.write_bytes(b"header H3600P V9.0 TTN.9_250626")
            code, stdout, stderr = self.run_cli(
                [
                    "root-readiness",
                    *TARGET,
                    "--firmware-input",
                    str(artifact),
                ]
            )
        self.assertEqual((code, stderr), (1, ""))
        self.assertIn("Exact build match: False", stdout)
        self.assertIn("does not prove the exact catalog build", stdout)

    def test_root_readiness_allows_review_only_when_all_catalog_gates_pass(self) -> None:
        recipe = find_recipe(
            "turk-telekom",
            "H3600P",
            "V9.0",
            "H3600P V9.0 TTN.10_260210",
        )
        version = "H3600P V9.0 TTN.10_260210"
        with TemporaryDirectory() as directory:
            artifact = Path(directory) / "firmware.bin"
            artifact.write_bytes(b"header" + version.encode("ascii"))
            with patch(
                "cpe_access_atlas.cli._recipe_from_args",
                return_value=replace(
                    recipe,
                    status="verified",
                    blockers=(),
                    hardware_revision_status="exact",
                    access={**recipe.access, "local_root_shell": "verified"},
                ),
            ):
                code, stdout, stderr = self.run_cli(
                    [
                        "root-readiness",
                        *TARGET,
                        "--firmware-input",
                        str(artifact),
                    ]
                )
        self.assertEqual((code, stderr), (0, ""))
        self.assertIn("Decision: REVIEW REQUIRED", stdout)
        self.assertIn("SHA-256 match: None", stdout)
        self.assertIn("No device connection", stdout)

    def test_apply_requires_authorization_and_still_refuses(self) -> None:
        code, _, stderr = self.run_cli(["apply", *TARGET])
        self.assertEqual(code, 3)
        self.assertIn("acknowledgement", stderr)

        code, _, stderr = self.run_cli(
            ["apply", *TARGET, "--i-own-or-administer-this-device"]
        )
        self.assertEqual(code, 3)
        self.assertIn("no verified apply adapter", stderr)
        self.assertIn("No device change was attempted", stderr)

    def test_config_generate_requires_authorization_before_prompting(self) -> None:
        with TemporaryDirectory() as directory:
            output = Path(directory) / "config.bin"
            with patch("cpe_access_atlas.cli.getpass.getpass") as prompt:
                code, stdout, stderr = self.run_cli(
                    ["config-generate", *TARGET, "--output", str(output)]
                )
        self.assertEqual((code, stdout), (3, ""))
        self.assertIn("acknowledgement", stderr)
        prompt.assert_not_called()

    def test_config_generate_from_scratch_is_local_and_round_trips(self) -> None:
        with TemporaryDirectory() as directory:
            output = Path(directory) / "generated.bin"
            with patch(
                "cpe_access_atlas.cli.getpass.getpass",
                return_value="DummyPass123",
            ):
                code, stdout, stderr = self.run_cli(
                    [
                        "config-generate",
                        *TARGET,
                        "--output",
                        str(output),
                        "--allow-unencrypted",
                        "--i-own-or-administer-this-device",
                    ]
                )
            decoded = decode_config(output.read_bytes())
        self.assertEqual((code, stderr), (0, ""))
        self.assertIn("Wrote offline configuration artifact", stdout)
        self.assertIn("no device connection was attempted", stdout)
        self.assertNotIn("DummyPass123", stdout + stderr)
        fields = {
            item.attrib["name"]: item.attrib["val"]
            for item in ET.fromstring(decoded.xml).find("Tbl/Row").findall("DM")
        }
        self.assertEqual(fields["SSH_UserName"], "admin")
        self.assertEqual(fields["SSH_PassWord"], "DummyPass123")
        self.assertEqual(fields["SSH_Level"], "1")

    def test_config_generate_patches_private_config_baseline(self) -> None:
        with TemporaryDirectory() as directory:
            source = Path(directory) / "private-config.bin"
            output = Path(directory) / "generated.bin"
            source.write_bytes(encode_config(default_root_xml("OldPass123")))
            with patch(
                "cpe_access_atlas.cli.getpass.getpass",
                return_value="NewPass123",
            ):
                code, stdout, stderr = self.run_cli(
                    [
                        "config-generate",
                        *TARGET,
                        "--input-config",
                        str(source),
                        "--output",
                        str(output),
                        "--allow-unencrypted",
                        "--i-own-or-administer-this-device",
                    ]
                )
            decoded = decode_config(output.read_bytes())
        self.assertEqual((code, stderr), (0, ""))
        self.assertIn("private configuration baseline", stdout)
        self.assertNotIn("NewPass123", stdout + stderr)
        self.assertIn(b'val="NewPass123"', decoded.xml)

    def test_config_generate_supports_encrypted_output_from_stdin(self) -> None:
        with TemporaryDirectory() as directory:
            output = Path(directory) / "encrypted-config.bin"
            stdin = StringIO("NewPass123\n" + "a" * 32 + "\n")
            with patch("cpe_access_atlas.cli.sys.stdin", stdin):
                code, stdout, stderr = self.run_cli(
                    [
                        "config-generate",
                        *TARGET,
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
            decoded = decode_config(
                output.read_bytes(),
                device_key="a" * 32,
                serial="ZTE12345678",
                mac="00:11:22:33:44:55",
            )
        self.assertEqual((code, stderr), (0, ""))
        self.assertIn("encrypted type-4", stdout)
        self.assertNotIn("NewPass123", stdout + stderr)
        self.assertIn(b'val="NewPass123"', decoded.xml)

    def test_config_generate_reads_encrypted_private_baseline(self) -> None:
        with TemporaryDirectory() as directory:
            source = Path(directory) / "encrypted-config.bin"
            output = Path(directory) / "generated.bin"
            source.write_bytes(
                encode_config(
                    default_root_xml("OldPass123"),
                    encrypted=True,
                    device_key="a" * 32,
                    serial="ZTE12345678",
                    mac="00:11:22:33:44:55",
                )
            )
            with patch(
                "cpe_access_atlas.cli.getpass.getpass",
                side_effect=["NewPass123", "a" * 32],
            ):
                code, stdout, stderr = self.run_cli(
                    [
                        "config-generate",
                        *TARGET,
                        "--input-config",
                        str(source),
                        "--output",
                        str(output),
                        "--serial",
                        "ZTE12345678",
                        "--mac",
                        "00:11:22:33:44:55",
                        "--i-own-or-administer-this-device",
                    ]
                )
            decoded = decode_config(
                output.read_bytes(),
                device_key="a" * 32,
                serial="ZTE12345678",
                mac="00:11:22:33:44:55",
            )
        self.assertEqual((code, stderr), (0, ""))
        self.assertIn("private configuration baseline", stdout)
        self.assertIn(b'val="NewPass123"', decoded.xml)

    def test_config_generate_force_guard_and_empty_secret(self) -> None:
        with TemporaryDirectory() as directory:
            output = Path(directory) / "existing.bin"
            output.write_bytes(b"keep")
            with patch("cpe_access_atlas.cli.getpass.getpass") as prompt:
                code, stdout, stderr = self.run_cli(
                    [
                        "config-generate",
                        *TARGET,
                        "--output",
                        str(output),
                        "--allow-unencrypted",
                        "--i-own-or-administer-this-device",
                    ]
                )
            self.assertEqual((code, stdout), (4, ""))
            self.assertIn("already exists", stderr)
            prompt.assert_not_called()

            output.unlink()
            with patch("cpe_access_atlas.cli.getpass.getpass", return_value=""):
                code, stdout, stderr = self.run_cli(
                    [
                        "config-generate",
                        *TARGET,
                        "--output",
                        str(output),
                        "--allow-unencrypted",
                        "--i-own-or-administer-this-device",
                    ]
                )
            self.assertEqual((code, stdout), (2, ""))
            self.assertIn("SSH password must not be empty", stderr)

    def test_config_generate_reports_input_and_output_errors(self) -> None:
        with TemporaryDirectory() as directory:
            directory_path = Path(directory)
            with patch("cpe_access_atlas.cli.getpass.getpass") as prompt:
                code, stdout, stderr = self.run_cli(
                    [
                        "config-generate",
                        *TARGET,
                        "--input-xml",
                        str(directory_path),
                        "--output",
                        str(directory_path / "generated.bin"),
                        "--i-own-or-administer-this-device",
                    ]
                )
            self.assertEqual((code, stdout), (2, ""))
            self.assertIn("unable to read XML baseline", stderr)
            prompt.assert_not_called()

            with patch("cpe_access_atlas.cli.getpass.getpass", return_value="DummyPass123"):
                code, stdout, stderr = self.run_cli(
                    [
                        "config-generate",
                        *TARGET,
                        "--output",
                        str(directory_path / "missing" / "generated.bin"),
                        "--allow-unencrypted",
                        "--i-own-or-administer-this-device",
                    ]
                )
            self.assertEqual((code, stdout), (2, ""))
            self.assertIn("unable to write configuration artifact", stderr)

    def test_config_generate_requires_crypto_coordinates_and_checks_round_trip(self) -> None:
        with TemporaryDirectory() as directory:
            output = Path(directory) / "generated.bin"
            with patch("cpe_access_atlas.cli.getpass.getpass") as prompt:
                code, stdout, stderr = self.run_cli(
                    [
                        "config-generate",
                        *TARGET,
                        "--output",
                        str(output),
                        "--encrypted",
                        "--i-own-or-administer-this-device",
                    ]
                )
            self.assertEqual((code, stdout), (2, ""))
            self.assertIn("encrypted output requires", stderr)
            prompt.assert_not_called()

            with patch("cpe_access_atlas.cli.getpass.getpass") as prompt:
                code, stdout, stderr = self.run_cli(
                    [
                        "config-generate",
                        *TARGET,
                        "--input-config",
                        str(output),
                        "--output",
                        str(Path(directory) / "other.bin"),
                        "--i-own-or-administer-this-device",
                    ]
                )
            self.assertEqual((code, stdout), (2, ""))
            self.assertIn("unable to read configuration artifact", stderr)
            prompt.assert_not_called()

            encrypted_source = Path(directory) / "encrypted.bin"
            encrypted_source.write_bytes(
                encode_config(
                    default_root_xml("OldPass123"),
                    encrypted=True,
                    device_key="a" * 32,
                    serial="ZTE12345678",
                    mac="00:11:22:33:44:55",
                )
            )
            with patch("cpe_access_atlas.cli.getpass.getpass") as prompt:
                code, stdout, stderr = self.run_cli(
                    [
                        "config-generate",
                        *TARGET,
                        "--input-config",
                        str(encrypted_source),
                        "--output",
                        str(Path(directory) / "from-encrypted.bin"),
                        "--i-own-or-administer-this-device",
                    ]
                )
            self.assertEqual((code, stdout), (2, ""))
            self.assertIn("encrypted input requires", stderr)
            prompt.assert_not_called()

            with patch("cpe_access_atlas.cli.getpass.getpass", return_value="DummyPass123"):
                with patch(
                    "cpe_access_atlas.cli.decode_config",
                    return_value=SimpleNamespace(xml=b"different"),
                ):
                    code, stdout, stderr = self.run_cli(
                        [
                            "config-generate",
                            *TARGET,
                            "--output",
                            str(output),
                            "--allow-unencrypted",
                            "--i-own-or-administer-this-device",
                        ]
                    )
            self.assertEqual((code, stdout), (2, ""))
            self.assertIn("round-trip check", stderr)

    def test_config_generate_rejects_unencrypted_output_without_acknowledgement(self) -> None:
        with TemporaryDirectory() as directory:
            output = Path(directory) / "generated.bin"
            with patch("cpe_access_atlas.cli.getpass.getpass") as prompt:
                code, stdout, stderr = self.run_cli(
                    [
                        "config-generate",
                        *TARGET,
                        "--output",
                        str(output),
                        "--i-own-or-administer-this-device",
                    ]
                )
        self.assertEqual((code, stdout), (2, ""))
        self.assertIn("allow-unencrypted", stderr)
        self.assertFalse(output.exists())
        prompt.assert_not_called()

    def test_doctor_does_not_probe_by_default(self) -> None:
        code, stdout, stderr = self.run_cli(["doctor", "--host", "192.168.1.1"])
        self.assertEqual(code, 0)
        self.assertEqual(stderr, "")
        self.assertIn("Probe disabled", stdout)

    def test_doctor_probe_reports_open_and_closed_ports(self) -> None:
        with patch(
            "cpe_access_atlas.cli.probe_tcp_ports",
            return_value={80: True, 443: False},
        ) as probe:
            code, stdout, stderr = self.run_cli(
                ["doctor", "--host", "192.168.1.1", "--probe"]
            )
        self.assertEqual((code, stderr), (0, ""))
        probe.assert_called_once()
        self.assertIn("tcp/80: open", stdout)
        self.assertIn("tcp/443: closed/unreachable", stdout)

    def test_public_target_is_rejected(self) -> None:
        code, _, stderr = self.run_cli(["doctor", "--host", "1.1.1.1"])
        self.assertEqual(code, 2)
        self.assertIn("only RFC1918", stderr)

    def test_invalid_probe_timeout_is_a_cli_error(self) -> None:
        code, stdout, stderr = self.run_cli(
            ["doctor", "--host", "192.168.1.1", "--probe", "--timeout", "-1"]
        )
        self.assertEqual(code, 2)
        self.assertEqual(stdout, "")
        self.assertIn("timeout must be greater than 0", stderr)

    def test_report_template_output_and_force_guard(self) -> None:
        with TemporaryDirectory() as directory:
            output = Path(directory) / "report.md"
            code, stdout, stderr = self.run_cli(["report-template", *TARGET])
            self.assertEqual((code, stderr), (0, ""))
            self.assertIn("Sanitized device research report", stdout)

            args = ["report-template", *TARGET, "--output", str(output)]
            code, stdout, stderr = self.run_cli(args)
            self.assertEqual((code, stderr), (0, ""))
            self.assertTrue(output.exists())

            code, _, stderr = self.run_cli(args)
            self.assertEqual(code, 4)
            self.assertIn("already exists", stderr)

            code, stdout, stderr = self.run_cli([*args, "--force"])
            self.assertEqual((code, stderr), (0, ""))
            self.assertIn("Wrote sanitized", stdout)

    def test_report_template_filesystem_error_is_controlled(self) -> None:
        with TemporaryDirectory() as directory:
            output = Path(directory) / "missing" / "report.md"
            code, stdout, stderr = self.run_cli(
                ["report-template", *TARGET, "--output", str(output)]
            )
        self.assertEqual((code, stdout), (1, ""))
        self.assertIn("filesystem operation failed", stderr)

    def test_redact_command_supports_stdin_and_files(self) -> None:
        with TemporaryDirectory() as directory:
            source = Path(directory) / "source.txt"
            output = Path(directory) / "redacted.txt"
            source.write_text("password=secret public=8.8.8.8", encoding="utf-8")

            code, stdout, stderr = self.run_cli(["redact", "--input", str(source)])
            self.assertEqual((code, stdout), (4, ""))
            self.assertIn("--output is required", stderr)

            args = ["redact", "--input", str(source), "--output", str(output)]
            code, stdout, stderr = self.run_cli(args)
            self.assertEqual((code, stderr), (0, ""))
            self.assertTrue(output.exists())
            self.assertNotIn("secret", output.read_text(encoding="utf-8"))

            code, _, stderr = self.run_cli(args)
            self.assertEqual(code, 4)
            self.assertIn("already exists", stderr)

            code, stdout, stderr = self.run_cli([*args, "--force"])
            self.assertEqual((code, stderr), (0, ""))
            self.assertIn("Wrote redacted text", stdout)

    def test_redact_reads_stdin_only_when_writing_a_private_file(self) -> None:
        with TemporaryDirectory() as directory:
            output = Path(directory) / "redacted.txt"
            with patch("cpe_access_atlas.cli.sys.stdin", StringIO("token=secret")):
                code, stdout, stderr = self.run_cli(
                    ["redact", "--output", str(output)]
                )
            self.assertEqual((code, stderr), (0, ""))
            self.assertNotIn("secret", stdout)
            self.assertNotIn("secret", output.read_text(encoding="utf-8"))

    def test_redact_rejects_invalid_text_encoding_cleanly(self) -> None:
        with TemporaryDirectory() as directory:
            source = Path(directory) / "invalid.txt"
            output = Path(directory) / "redacted.txt"
            source.write_bytes(b"password=\xff")
            code, stdout, stderr = self.run_cli(
                ["redact", "--input", str(source), "--output", str(output)]
            )
        self.assertEqual((code, stdout), (1, ""))
        self.assertIn("text encoding failed", stderr)

    def test_redact_write_error_is_controlled(self) -> None:
        with TemporaryDirectory() as directory:
            source = Path(directory) / "source.txt"
            output = Path(directory) / "redacted.txt"
            source.write_text("token=secret", encoding="utf-8")
            with patch(
                "cpe_access_atlas.cli.write_private_text",
                side_effect=OSError("simulated write failure"),
            ):
                code, stdout, stderr = self.run_cli(
                    ["redact", "--input", str(source), "--output", str(output)]
                )
        self.assertEqual((code, stdout), (1, ""))
        self.assertIn("filesystem operation failed", stderr)

    def test_firmware_inspection_supports_text_json_and_exact_mismatch(self) -> None:
        version = "H3600P V9.0 TTN.10_260210"
        with TemporaryDirectory() as directory:
            artifact = Path(directory) / "firmware.bin"
            artifact.write_bytes(b"header\x27\x05\x19\x56" + version.encode("ascii"))

            code, stdout, stderr = self.run_cli(
                ["firmware-inspect", "--input", str(artifact)]
            )
            self.assertEqual((code, stderr), (0, ""))
            self.assertIn("Exact build match: not checked", stdout)
            self.assertIn("No firmware code was executed or modified", stdout)

            code, stdout, stderr = self.run_cli(
                [
                    "firmware-inspect",
                    "--input",
                    str(artifact),
                    "--expected-version",
                    version,
                    "--expected-sha256",
                    hashlib.sha256(artifact.read_bytes()).hexdigest(),
                    "--json",
                ]
            )
            self.assertEqual((code, stderr), (0, ""))
            result = json.loads(stdout)
            self.assertTrue(result["exact_build_match"])
            self.assertTrue(result["sha256_match"])

            code, stdout, stderr = self.run_cli(
                [
                    "firmware-inspect",
                    "--input",
                    str(artifact),
                    "--expected-version",
                    "H3600P V9.0 TTN.9_250626",
                    "--expected-sha256",
                    hashlib.sha256(artifact.read_bytes()).hexdigest(),
                ]
            )
            self.assertEqual(code, 1)
            self.assertEqual(stderr, "")
            self.assertIn("Exact build match: no", stdout)
            self.assertIn("SHA-256 match:     yes", stdout)

            code, stdout, stderr = self.run_cli(
                [
                    "firmware-inspect",
                    "--input",
                    str(artifact),
                    "--expected-version",
                    version,
                    "--expected-sha256",
                    "0" * 64,
                ]
            )
            self.assertEqual(code, 1)
            self.assertEqual(stderr, "")
            self.assertIn("SHA-256 match:     no", stdout)

    def test_firmware_inspection_errors_are_controlled(self) -> None:
        code, stdout, stderr = self.run_cli(
            ["firmware-inspect", "--input", "does-not-exist.bin"]
        )
        self.assertEqual((code, stdout), (2, ""))
        self.assertIn("firmware artifact does not exist", stderr)

    def test_status_without_blockers_omits_blocker_section(self) -> None:
        recipe = find_recipe(
            "turk-telekom",
            "H3600P",
            "V9.0",
            "H3600P V9.0 TTN.10_260210",
        )
        with patch(
            "cpe_access_atlas.cli._recipe_from_args",
            return_value=replace(recipe, blockers=()),
        ):
            code, stdout, stderr = self.run_cli(["status", *TARGET])
        self.assertEqual((code, stderr), (0, ""))
        self.assertNotIn("Blockers:", stdout)

    def test_validate_reports_catalog_errors(self) -> None:
        with patch("cpe_access_atlas.cli.validate_catalog", return_value=["bad record"]):
            code, stdout, stderr = self.run_cli(["validate"])
        self.assertEqual((code, stdout), (1, ""))
        self.assertIn("ERROR: bad record", stderr)

    def test_validate_success_is_reported(self) -> None:
        code, stdout, stderr = self.run_cli(["validate"])
        self.assertEqual((code, stderr), (0, ""))
        self.assertIn("Catalog validation passed", stdout)

    def test_keyboard_interrupt_is_reported_without_retry(self) -> None:
        with patch(
            "cpe_access_atlas.cli.command_validate",
            side_effect=KeyboardInterrupt,
        ):
            code, stdout, stderr = self.run_cli(["validate"])
        self.assertEqual((code, stdout), (130, ""))
        self.assertIn("Interrupted; no retry was attempted", stderr)

    def test_version_is_a_successful_parser_exit(self) -> None:
        code, stdout, stderr = self.run_cli(["--version"])
        self.assertEqual((code, stderr), (0, ""))
        self.assertEqual(stdout.strip(), "0.2.0")

    def test_module_entrypoint_propagates_exit_code(self) -> None:
        with patch("cpe_access_atlas.cli.main", return_value=7):
            with self.assertRaises(SystemExit) as raised:
                runpy.run_module("cpe_access_atlas.__main__", run_name="__main__")
        self.assertEqual(raised.exception.code, 7)


if __name__ == "__main__":
    unittest.main()

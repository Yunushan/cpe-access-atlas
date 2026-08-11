# SPDX-License-Identifier: 0BSD
from __future__ import annotations

from contextlib import redirect_stderr, redirect_stdout
from io import StringIO
import unittest

from cpe_access_atlas.cli import main


TARGET = [
    "--isp",
    "Türk Telekom",
    "--model",
    "ZTE H3600P",
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

    def test_status_reports_blocked_and_no_change(self) -> None:
        code, stdout, stderr = self.run_cli(["status", *TARGET])
        self.assertEqual(code, 0)
        self.assertEqual(stderr, "")
        self.assertIn("Status:     blocked", stdout)
        self.assertIn("No device change was attempted", stdout)

    def test_plan_stops_on_exact_build(self) -> None:
        code, stdout, _ = self.run_cli(["plan", *TARGET])
        self.assertEqual(code, 0)
        self.assertIn("Decision: STOP", stdout)
        self.assertIn("will not substitute", stdout)

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

    def test_doctor_does_not_probe_by_default(self) -> None:
        code, stdout, stderr = self.run_cli(["doctor", "--host", "192.168.1.1"])
        self.assertEqual(code, 0)
        self.assertEqual(stderr, "")
        self.assertIn("Probe disabled", stdout)

    def test_public_target_is_rejected(self) -> None:
        code, _, stderr = self.run_cli(["doctor", "--host", "1.1.1.1"])
        self.assertEqual(code, 2)
        self.assertIn("only RFC1918", stderr)


if __name__ == "__main__":
    unittest.main()

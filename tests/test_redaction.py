# SPDX-License-Identifier: 0BSD
from __future__ import annotations

import unittest

from cpe_access_atlas.redaction import redact_text


class RedactionTests(unittest.TestCase):
    def test_redacts_common_secret_assignments(self) -> None:
        output = redact_text("password=abc123 token: xyz cookie=session-value")
        self.assertNotIn("abc123", output)
        self.assertNotIn("xyz", output)
        self.assertNotIn("session-value", output)
        self.assertEqual(output.count("[REDACTED]"), 3)

    def test_redacts_mac_subscriber_and_public_ip(self) -> None:
        output = redact_text(
            "mac=AA:BB:CC:DD:EE:FF user=subscriber@example.net "
            "public=8.8.8.8 local=192.168.1.1"
        )
        self.assertIn("[REDACTED-MAC]", output)
        self.assertIn("[REDACTED-SUBSCRIBER-ID]", output)
        self.assertIn("[REDACTED-PUBLIC-IP]", output)
        self.assertIn("192.168.1.1", output)


if __name__ == "__main__":
    unittest.main()

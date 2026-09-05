# SPDX-License-Identifier: 0BSD
from __future__ import annotations

import unittest
from unittest.mock import patch

from cpe_access_atlas.redaction import RedactionError, redact_text


class RedactionTests(unittest.TestCase):
    def test_redacts_common_secret_assignments(self) -> None:
        output = redact_text("password=abc123 token: xyz cookie=session-value")
        self.assertNotIn("abc123", output)
        self.assertNotIn("xyz", output)
        self.assertNotIn("session-value", output)
        self.assertEqual(output.count("[REDACTED]"), 3)

    def test_redacts_mac_subscriber_and_public_ip(self) -> None:
        output = redact_text(
            "mac=AA:BB:CC:DD:EE:FF user=subscriber@example.net public=8.8.8.8 local=192.168.1.1"
        )
        self.assertIn("[REDACTED-MAC]", output)
        self.assertIn("[REDACTED-SUBSCRIBER-ID]", output)
        self.assertIn("[REDACTED-PUBLIC-IP]", output)
        self.assertIn("192.168.1.1", output)

    def test_redacts_json_secrets_bearer_tokens_and_public_ipv6(self) -> None:
        output = redact_text(
            '{"password":"abc123"} Authorization: Bearer abc.def.ghi '
            "public=2001:4860:4860::8888 local=fd00::1"
        )
        self.assertNotIn("abc123", output)
        self.assertNotIn("abc.def.ghi", output)
        self.assertIn("[REDACTED-PUBLIC-IP]", output)
        self.assertIn("fd00::1", output)

    def test_redacts_quoted_secrets_and_auth_headers(self) -> None:
        output = redact_text(
            'password="my secret phrase" '
            "api-key='key with spaces' "
            "X-API-Key: abc123 "
            "Authorization: Basic dXNlcjpwYXNz\n"
            'Authorization: "Basic quoted-secret"'
        )
        self.assertNotIn("my secret phrase", output)
        self.assertNotIn("key with spaces", output)
        self.assertNotIn("abc123", output)
        self.assertNotIn("dXNlcjpwYXNz", output)
        self.assertNotIn("quoted-secret", output)
        self.assertEqual(output.count("[REDACTED]"), 5)

    def test_redacts_nonstandard_authorization_headers(self) -> None:
        output = redact_text('Authorization: Digest username="alice", nonce="sensitive-value"\n')
        self.assertNotIn("sensitive-value", output)
        self.assertIn("Authorization: [REDACTED]", output)

    def test_preserves_non_ip_colon_tokens(self) -> None:
        output = redact_text("label=ab:cd:ef")
        self.assertEqual(output, "label=ab:cd:ef")

    def test_redacts_every_cookie_and_folded_header_value(self) -> None:
        for header in (
            "Cookie: session=SYNTHETIC_ONE; refresh=SYNTHETIC_TWO\r\nHost: router.local",
            "Set-Cookie: session=SYNTHETIC_ONE; Expires=Wed, 21 Oct 2026 07:28:00 GMT\n",
            "> Cookie: session=SYNTHETIC_ONE;\r\n\trefresh=SYNTHETIC_TWO\r\nHost: router.local",
            'Cookie: session="SYNTHETIC_ONE; SYNTHETIC_TWO"\nHost: router.local',
            '{"Cookie":"session=SYNTHETIC_ONE; refresh=SYNTHETIC_TWO"}',
        ):
            with self.subTest(header=header):
                output = redact_text(header)
                self.assertNotIn("SYNTHETIC_ONE", output)
                self.assertNotIn("SYNTHETIC_TWO", output)
                self.assertEqual(output, redact_text(output))
                if "Host:" in header:
                    self.assertIn("Host: router.local", output)

    def test_redacts_zte_xml_fields_in_either_attribute_order(self) -> None:
        for xml in (
            '<DM name="SSH_PassWord" val="SYNTHETIC_SECRET"/>',
            "<DM val='SYNTHETIC_SECRET' name='SSH_PassWord'/>",
            '<DM\n name="SSH_PassWord"\n val="SYNTHETIC_SECRET" />',
            '<DM name="SSH_Pass&#87;ord" val="SYNTHETIC_SECRET"/>',
            '<DM name="SerialNumber" val="SYNTHETIC_SECRET"/>',
            '<item key="password" value="SYNTHETIC_SECRET"/>',
            '<item password="SYNTHETIC_SECRET"/>',
            "<Password>SYNTHETIC_SECRET</Password>",
            "<SSH_PassWord><![CDATA[SYNTHETIC_SECRET]]></SSH_PassWord>",
            '<cfg:Password xmlns:cfg="urn:test">SYNTHETIC_SECRET</cfg:Password>',
        ):
            with self.subTest(xml=xml):
                output = redact_text(xml)
                self.assertNotIn("SYNTHETIC_SECRET", output)
                self.assertIn("[REDACTED]", output)
                self.assertEqual(output, redact_text(output))
        safe = '<DM name="VLAN" val="35"/><DM name="SSH_Port" val="22"/>'
        self.assertEqual(redact_text(safe), safe)

    def test_redacts_serial_and_subscriber_identifiers(self) -> None:
        for name in ("SerialNumber", "serial_number", "serial-number", "subscriber_id"):
            output = redact_text(f"{name}=SYNTHETIC_IDENTIFIER")
            self.assertNotIn("SYNTHETIC_IDENTIFIER", output)

    def test_dotted_non_email_tokens_are_not_rescanned_at_each_word_boundary(self) -> None:
        value = "a." * 100_000
        self.assertEqual(redact_text(value), value)
        self.assertEqual(redact_text(f"user={value}@example.net"), "user=[REDACTED-SUBSCRIBER-ID]")

    def test_xml_secret_elements_handle_nesting_and_opaque_markup(self) -> None:
        for interior in (
            "SYNTHETIC_SECRET<Password>nested</Password>tail",
            "<![CDATA[SYNTHETIC_SECRET</Password>hidden]]>",
            "<!-- SYNTHETIC_SECRET </Password> -->tail",
            "<?sample SYNTHETIC_SECRET </Password> ?>tail",
            "<item value='SYNTHETIC_SECRET'/>tail",
            "<Password/>SYNTHETIC_SECRET",
        ):
            with self.subTest(interior=interior):
                value = f"<Password>{interior}</Password><safe>visible</safe>"
                self.assertEqual(
                    redact_text(value),
                    "<Password>[REDACTED]</Password><safe>visible</safe>",
                )

    def test_unterminated_secret_elements_discard_the_remainder_once(self) -> None:
        for suffix in ("SYNTHETIC_SECRET", "<!-- SYNTHETIC_SECRET", "<![CDATA[secret", "<?secret"):
            self.assertEqual(redact_text(f"<Password>{suffix}"), "<Password>[REDACTED]")
        # Large structured adversarial input, not a short random string. This
        # previously retried an end-tag search at each of the 20,000 openings.
        self.assertEqual(redact_text("<Password>" * 20_000), "<Password>[REDACTED]")

    def test_xml_scanning_preserves_nonsecret_text_and_quoted_delimiters(self) -> None:
        for value in (
            "plain text",
            "<",
            "<>value",
            "<1invalid>",
            "<name$invalid>",
            "<!-- <Note>example</Note> -->",
            "<![CDATA[example]]>",
            "<?example data?>",
            "<!-- incomplete",
            "<item",
            "<item<other/>",
            "<item note='a > b'/>",
            '<item note="a > b"/>',
            "<item note='incomplete",
            "<item" + " " * 20_000 + "/>",
        ):
            with self.subTest(value=value[:60]):
                self.assertEqual(redact_text(value), value)
        self.assertEqual(
            redact_text("<Password value='SYNTHETIC_SECRET'/>"),
            "<Password value='[REDACTED]'/>",
        )
        self.assertEqual(
            redact_text("<Password note='a > b'>SYNTHETIC_SECRET</Password>"),
            "<Password note='a > b'>[REDACTED]</Password>",
        )

    def test_credentials_inside_opaque_xml_are_not_left_in_reports(self) -> None:
        for opening, closing, expected in (
            ("<!--", "-->", "<!--[REDACTED]-->"),
            ("<![CDATA[", "]]>", "<![CDATA[[REDACTED]]]>"),
            ("<?example ", "?>", "<?redacted?>"),
        ):
            for field in (
                "<Password>SYNTHETIC_VALUE</Password>",
                '<DM name="SSH_PassWord" val="SYNTHETIC_VALUE"/>',
            ):
                with self.subTest(opening=opening, field=field):
                    value = opening + field + closing
                    self.assertEqual(redact_text(value), expected)
                    self.assertNotIn("SYNTHETIC_VALUE", redact_text(value))
                    self.assertEqual(redact_text(expected), expected)

    def test_redacts_complete_and_incomplete_private_key_blocks(self) -> None:
        for kind in (
            "PRIVATE KEY",
            "RSA PRIVATE KEY",
            "OPENSSH PRIVATE KEY",
            "ENCRYPTED PRIVATE KEY",
        ):
            for suffix in (f"-----END {kind}-----", ""):
                source = f"-----BEGIN {kind}-----\nSYNTHETIC_KEY_MATERIAL\n{suffix}"
                output = redact_text(source)
                self.assertNotIn("SYNTHETIC_KEY_MATERIAL", output)
                self.assertEqual(output, redact_text(output))

    def test_report_size_limit_is_enforced(self) -> None:
        with patch("cpe_access_atlas.redaction.MAX_REPORT_CHARS", 16):
            with self.assertRaisesRegex(RedactionError, "safety size limit"):
                redact_text("x" * 17)


if __name__ == "__main__":
    unittest.main()

# SPDX-License-Identifier: 0BSD
from __future__ import annotations

import json
import unittest
from itertools import product
from unittest.mock import patch

from hypothesis import given, settings
from hypothesis import strategies as st

from cpe_access_atlas.redaction import RedactionError, redact_text


class RedactionTests(unittest.TestCase):
    def test_redacts_common_secret_assignments(self) -> None:
        output = redact_text("password=abc123 token: xyz cookie=session-value")
        self.assertNotIn("abc123", output)
        self.assertNotIn("xyz", output)
        self.assertNotIn("session-value", output)
        self.assertEqual(output.count("[REDACTED]"), 3)

    def test_redacts_wifi_credential_aliases_in_text_and_xml(self) -> None:
        for alias in (
            "KeyPassphrase",
            "key_passphrase",
            "key-passphrase",
            "PreSharedKey",
            "pre_shared_key",
            "pre-shared-key",
            "PSK",
            "WiFiPSK",
            "wifi_psk",
            "wi-fi-psk",
            "wi_fi_psk",
            "WLANPSK",
            "wlan_psk",
            "WPA_PSK",
            "WPAPSK",
            "WPA2PSK",
            "wpa2_psk",
            "WPA3PSK",
            "wpa3-psk",
            "X_VENDOR_WPA_PSK",
            "X-VENDOR-WPA-PSK",
            "X--password",
            "X__WPA_PSK",
            "Café-Password",
            "TürkTelekom-PreSharedKey",
            "_vendor-password",
            "__WPA_PSK",
        ):
            for name in (alias, alias.lower(), alias.upper()):
                for template in (
                    "{name}={value}",
                    '{name}: "{value}"',
                    "'{name}': '{value}'",
                    '{{"{name}":"{value}"}}',
                    '<DM name="{name}" val="{value}"/>',
                    "<DM val='{value}' name='{name}'/>",
                    '<item\n value="{value}"\n key="{name}"/>',
                    '<item {name}="{value}"/>',
                    "<{name}>{value}</{name}>",
                    '<cfg:{name} xmlns:cfg="urn:test">{value}</cfg:{name}>',
                ):
                    with self.subTest(name=name, template=template):
                        source = template.format(name=name, value="SYNTHETIC_WIFI_CREDENTIAL")
                        expected = template.format(name=name, value="[REDACTED]")
                        self.assertEqual(redact_text(source), expected)
                        self.assertEqual(redact_text(expected), expected)

    def test_wifi_xml_names_decode_entities_before_matching(self) -> None:
        for name in ("KeyPassphr&#97;se", "PreShared&#75;ey", "WPA&#95;PSK"):
            source = f'<DM name="{name}" val="SYNTHETIC_WIFI_CREDENTIAL"/>'
            self.assertEqual(redact_text(source), f'<DM name="{name}" val="[REDACTED]"/>')

    def test_preserves_wifi_setting_names_that_are_not_credentials(self) -> None:
        for name in (
            "PSKMode",
            "PreSharedKeyCount",
            "KeyPassphraseLength",
            "WPA_PSKEnabled",
            "WiFi_PSKMode",
            "WPA2Cipher",
            "TürkTelekom-PSKMode",
            "Café--KeyPassphraseLength",
            "SSID",
            "SomeUnrecognizedField",
        ):
            for template in (
                "{name}=visible",
                '{{"{name}":"visible"}}',
                '<DM name="{name}" val="visible"/>',
                '<item {name}="visible"/>',
                "<{name}>visible</{name}>",
            ):
                with self.subTest(name=name, template=template):
                    source = template.format(name=name)
                    self.assertEqual(redact_text(source), source)

    def test_long_vendor_prefix_is_not_rescanned_at_every_separator(self) -> None:
        for separator in ("-", "_", "--", "__", "_-", "-_"):
            prefix = f"véndor{separator}" * 20_000
            safe = f"{prefix}Setting=visible"
            self.assertEqual(redact_text(safe), safe)
            self.assertEqual(
                redact_text(f"{prefix}PreSharedKey=SYNTHETIC_WIFI_CREDENTIAL"),
                f"{prefix}PreSharedKey=[REDACTED]",
            )

    def test_redacts_command_line_option_assignments(self) -> None:
        for name in ("password", "token", "api-key", "KeyPassphrase", "WPA_PSK"):
            for prefix in ("-", "--", "_", "_-", "-_"):
                for quote in ("", "'", '"'):
                    source = f"tool {prefix}{name}={quote}SYNTHETIC_CREDENTIAL{quote} --port=22"
                    expected = f"tool {prefix}{name}={quote}[REDACTED]{quote} --port=22"
                    with self.subTest(name=name, prefix=prefix, quote=quote):
                        self.assertEqual(redact_text(source), expected)
        dashes = "-" * 20_000
        safe = f"{dashes}mode=visible"
        self.assertEqual(redact_text(safe), safe)
        self.assertEqual(
            redact_text(f"{dashes}password=SYNTHETIC_CREDENTIAL"),
            f"{dashes}password=[REDACTED]",
        )

    def test_prefixed_secret_assignments_preserve_masking(self) -> None:
        # Derived from a differential check against the pre-fix redactor.
        # Keep fixed expectations so this regression runs without Git or a
        # copy of the old implementation, including from a source archive.
        for lead, word, separator, field in product(
            ("", "-", "--", "_", "__", "prefix."),
            ("", "X", "Vendor", "café", "é", "z\u0301"),
            ("-", "--", "_", "__", ".", ":", "-_", "_-"),
            ("password", "api-key", "secret_key", "token"),
        ):
            name = lead + word + separator + field
            for template in (
                "{name}={value}",
                '{{"{name}":"{value}"}}',
                "'{name}': '{value}'",
            ):
                with self.subTest(name=name, template=template):
                    source = template.format(name=name, value="SYNTHETIC_CREDENTIAL")
                    expected = template.format(name=name, value="[REDACTED]")
                    self.assertEqual(redact_text(source), expected)

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
        self.assertEqual(
            redact_text(
                'Captured Authorization: Digest username="SYNTHETIC_USER",\n'
                ' response="SYNTHETIC_CREDENTIAL"\nHost: router.local'
            ),
            "Captured Authorization: [REDACTED]\nHost: router.local",
        )

    def test_redacts_complete_authorization_headers_and_folded_continuations(self) -> None:
        for key in ("Authorization", "Proxy-Authorization", "> Authorization"):
            for scheme in ("Digest", "Bearer", "Basic", "CustomScheme"):
                for newline in ("\n", "\r\n"):
                    source = (
                        f'{key}: {scheme} username="SYNTHETIC_USER",{newline}'
                        f' nonce="SYNTHETIC_NONCE",{newline}'
                        f'\tresponse="SYNTHETIC_CREDENTIAL"{newline}'
                        "Host: router.local"
                    )
                    expected = f"{key}: [REDACTED]{newline}Host: router.local"
                    with self.subTest(key=key, scheme=scheme, newline=newline):
                        self.assertEqual(redact_text(source), expected)
                        self.assertEqual(redact_text(expected), expected)

    def test_unterminated_authorization_quotes_are_masked_without_backtracking(self) -> None:
        for size in (1, 12, 30, 1000, 20_000):
            for quote in ('"', "'"):
                credential = quote + "\\" * size + "SYNTHETIC_UNTERMINATED"
                source = f"Captured Authorization: {credential}\nHost: router.local"
                with self.subTest(size=size, quote=quote):
                    expected = "Captured Authorization: [REDACTED]\nHost: router.local"
                    self.assertEqual(redact_text(source), expected)
                    self.assertEqual(redact_text(expected), expected)

    def test_unquoted_credentials_include_punctuation_spaces_and_unclosed_quotes(self) -> None:
        for credential in (
            "SYNTHETIC_HEAD;SYNTHETIC_TAIL",
            "SYNTHETIC_HEAD&SYNTHETIC_TAIL",
            "SYNTHETIC_HEAD,SYNTHETIC_TAIL",
            "SYNTHETIC_HEAD'SYNTHETIC_TAIL",
            'SYNTHETIC_HEAD"SYNTHETIC_TAIL',
            "SYNTHETIC_HEAD SYNTHETIC_TAIL",
            "SYNTHETIC_HEAD}SYNTHETIC_TAIL",
            '"SYNTHETIC_HEAD SYNTHETIC_TAIL',
            "'SYNTHETIC_HEAD SYNTHETIC_TAIL",
            '"SYNTHETIC_HEAD"SYNTHETIC_TAIL',
        ):
            for separator in ("=", ":", ": "):
                source = f"password{separator}{credential}\nmode=bridge"
                expected = f"password{separator}[REDACTED]\nmode=bridge"
                with self.subTest(credential=credential, separator=separator):
                    self.assertEqual(redact_text(source), expected)
                    self.assertEqual(redact_text(expected), expected)

    def test_compact_colon_values_cannot_hide_a_sensitive_key(self) -> None:
        for key in ("password", "token", "cfg:password", "vendor:cfg:password"):
            for credential in ("SYNTHETIC_HEAD:SYNTHETIC_TAIL", "SYNTHETIC_HEAD=value"):
                source = f"{key}:{credential} mode=bridge"
                self.assertEqual(redact_text(source), f"{key}:[REDACTED] mode=bridge")
        self.assertEqual(redact_text("cfg:password=SYNTHETIC_SECRET"), "cfg:password=[REDACTED]")

    def test_assignment_boundaries_preserve_public_fields_and_subsequent_masking(self) -> None:
        self.assertEqual(
            redact_text("setting=password=SYNTHETIC_SECRET"), "setting=password=[REDACTED]"
        )
        for prefix in ("$", "(", "[", "prefix+", "prefix\\", "prefix#"):
            source = f"{prefix}token=SYNTHETIC_SECRET"
            self.assertEqual(redact_text(source), f"{prefix}token=[REDACTED]")
        for boundary in (" ", "\t", ";", "; ", ", ", "&"):
            for public in ("mode=bridge", '"mode":"bridge"', "--port=22"):
                source = (
                    f"password=SYNTHETIC_ONE; ambiguous words{boundary}{public}"
                    f"{boundary}token=SYNTHETIC_TWO&unseparated"
                )
                expected = f"password=[REDACTED]{boundary}{public}{boundary}token=[REDACTED]"
                with self.subTest(boundary=boundary, public=public):
                    self.assertEqual(redact_text(source), expected)
                    self.assertEqual(redact_text(expected), expected)

    def test_yaml_block_scalars_remove_all_indented_secret_content(self) -> None:
        for indicator in ("|", ">", "|-", ">+", "|2", ">2-", "|-2", ">+2 # private"):
            for prefix in ("", "  ", "- ", "  -   "):
                for newline in ("\n", "\r\n"):
                    indent = " " * (len(prefix) + 2)
                    public_indent = " " * len(prefix)
                    source = (
                        f"{prefix}password: {indicator}{newline}"
                        f"{indent}SYNTHETIC_ONE{newline}{newline}"
                        f"{indent}  SYNTHETIC_TWO{newline}"
                        f"{public_indent}mode: bridge{newline}"
                    )
                    expected = (
                        f"{prefix}password: [REDACTED]{newline}{public_indent}mode: bridge{newline}"
                    )
                    with self.subTest(indicator=indicator, prefix=prefix, newline=newline):
                        self.assertEqual(redact_text(source), expected)
                        self.assertEqual(redact_text(expected), expected)
        self.assertEqual(redact_text("password: |\n  SYNTHETIC_SECRET"), "password: [REDACTED]\n")
        self.assertEqual(
            redact_text("password: |\nmode: bridge"), "password: [REDACTED]\nmode: bridge"
        )
        self.assertEqual(redact_text("notes: |\n  public text"), "notes: |\n  public text")

    def test_namespaced_and_dotted_credentials_share_field_recognition(self) -> None:
        for name in (
            "SIP_AuthPassword",
            "SIP_AuthenticationPassword",
            "PPPPassword",
            "InternetGatewayDevice.WANDevice.1.WANPPPConnection.1.Password",
            "Device.WiFi.AccessPoint.1.Security.KeyPassphrase",
            "Device.Users.User.2.X_VENDOR_AuthPassword",
        ):
            for template in (
                "{name}=SYNTHETIC_SECRET",
                '{{"{name}":"SYNTHETIC_SECRET"}}',
                '<DM name="{name}" val="SYNTHETIC_SECRET"/>',
                '<DM val="SYNTHETIC_SECRET" name="{name}"/>',
                '<cfg:DM cfg:key="{name}" cfg:value="SYNTHETIC_SECRET"/>',
                '<cfg:DM cfg:{name}="SYNTHETIC_SECRET"/>',
                "<cfg:{name}>SYNTHETIC_SECRET</cfg:{name}>",
            ):
                source = template.format(name=name)
                expected = source.replace("SYNTHETIC_SECRET", "[REDACTED]")
                with self.subTest(name=name, template=template):
                    self.assertEqual(redact_text(source), expected)
                    self.assertEqual(redact_text(expected), expected)
        for name in (
            "SIP_AuthPasswordLength",
            "Device.WiFi.PreSharedKeyCount",
            "PPPPasswordEnabled",
        ):
            source = f'<DM name="{name}" val="visible"/>'
            self.assertEqual(redact_text(source), source)

    @given(st.text(alphabet="abcXYZ019 _-;,'\"&/\\{}[]!$%çğşΩ🔑", max_size=1000))
    @settings(max_examples=150, deadline=None)
    def test_generated_unquoted_values_are_fully_masked(self, value: str) -> None:
        source = f"password=SYNTHETIC_HEAD{value}SYNTHETIC_TAIL mode=bridge"
        expected = "password=[REDACTED] mode=bridge"
        self.assertEqual(redact_text(source), expected)
        self.assertEqual(redact_text(expected), expected)

    @given(
        st.lists(
            st.text(alphabet="abcdef019 ;,:={}[]!", min_size=1, max_size=100),
            min_size=1,
            max_size=20,
        )
    )
    @settings(max_examples=100, deadline=None)
    def test_generated_yaml_blocks_mask_field_looking_lines(self, lines: list[str]) -> None:
        source = "password: |\n" + "".join(f"  {line}\n" for line in lines) + "mode: bridge\n"
        self.assertEqual(redact_text(source), "password: [REDACTED]\nmode: bridge\n")

    def test_long_report_lines_preserve_bounded_scanning_and_following_fields(self) -> None:
        for count in (1, 1000, 20_000):
            source = "password=SYNTHETIC; tail mode=bridge " * count
            expected = "password=[REDACTED] mode=bridge " * count
            self.assertEqual(redact_text(source), expected)
        path = "Device.Instance.1." * 20_000
        source = f'<DM name="{path}SIP_AuthPassword" val="SYNTHETIC_SECRET"/>'
        self.assertEqual(redact_text(source), source.replace("SYNTHETIC_SECRET", "[REDACTED]"))
        self.assertEqual(redact_text(f"{path}Setting=visible"), f"{path}Setting=visible")

    def test_quoted_assignments_preserve_cross_line_keys_separators_and_values(self) -> None:
        for before_colon, after_colon in product(("", "\n", "\r\n \t"), repeat=2):
            for separator in ("\n", "\r", "\r\n", "\u2028", "\u0085", "\v", "\f"):
                for quote in ('"', "'"):
                    source = (
                        f"{{{quote}password{quote}{before_colon}:{after_colon}"
                        f"{quote}SYNTHETIC_HEAD{separator}SYNTHETIC_TAIL{quote},"
                        f"{quote}mode{quote}: {quote}bridge{quote}}}"
                    )
                    expected = source.replace(
                        f"SYNTHETIC_HEAD{separator}SYNTHETIC_TAIL", "[REDACTED]"
                    )
                    with self.subTest(before=before_colon, after=after_colon, sep=separator):
                        self.assertEqual(redact_text(source), expected)
                        self.assertEqual(redact_text(expected), expected)
        self.assertEqual(redact_text('password:\n "SYNTHETIC_SECRET"'), 'password:\n "[REDACTED]"')
        self.assertEqual(redact_text("password:\nSYNTHETIC_SECRET"), "password:\n[REDACTED]")
        self.assertEqual(
            redact_text("password\n= SYNTHETIC_SECRET mode=bridge"),
            "password\n= [REDACTED] mode=bridge",
        )
        self.assertEqual(redact_text("password:"), "password:")
        self.assertEqual(redact_text("password:\n"), "password:\n[REDACTED]")

    @given(
        st.text(alphabet="aAZ09\"'\\ \t\r\n\v\f\u0085\u2028\u2029çğşΩ🔑", max_size=500),
        st.sampled_from(("", "\n", "\r\n \t")),
        st.sampled_from(("", "\n", "\r\n \t")),
    )
    @settings(max_examples=150, deadline=None)
    def test_json_secrets_with_multiline_formatting_and_unicode_are_fully_masked(
        self, value: str, before_colon: str, after_colon: str
    ) -> None:
        scalar = json.dumps("SYNTHETIC_HEAD" + value + "SYNTHETIC_TAIL", ensure_ascii=False)
        source = f'{{"password"{before_colon}:{after_colon}{scalar},"mode":"bridge"}}'
        expected = f'{{"password"{before_colon}:{after_colon}"[REDACTED]","mode":"bridge"}}'
        self.assertEqual(redact_text(source), expected)
        self.assertEqual(
            json.loads(redact_text(source)), {"password": "[REDACTED]", "mode": "bridge"}
        )
        self.assertEqual(redact_text(expected), expected)

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
                "<PreSharedKey>SYNTHETIC_VALUE</PreSharedKey>",
                '<DM name="KeyPassphrase" val="SYNTHETIC_VALUE"/>',
                '<DM name="WPA_PSK" val="SYNTHETIC_VALUE"/>',
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

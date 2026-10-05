# SPDX-License-Identifier: 0BSD
from __future__ import annotations

import json
import tracemalloc
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

    def test_escaped_json_sensitive_keys_preserve_source_formatting(self) -> None:
        for key in (
            r"\u0070assword",
            r"pass\u0077ord",
            r"\u0063ook\u0069e",
            r"\u0054oken",
            r"api\u005fkey",
            r"WPA\u005fPSK",
            r"PreShared\u004bey",
            r"cfg:pass\u0077ord",
            r"vendor name-pass\u0077ord",
            r"vendor\"-pass\u0077ord",
            r"vendor\\-pass\u0077ord",
            r"\ud83d\udd11-pass\u0077ord",
        ):
            for before_colon, after_colon in product(("", "\n", "\r\n \t"), repeat=2):
                source = (
                    f'{{ "{key}"{before_colon}:{after_colon}"SYNTHETIC_SECRET", '
                    '"mode" : "bridge" }'
                )
                expected = source.replace("SYNTHETIC_SECRET", "[REDACTED]")
                with self.subTest(key=key, before=before_colon, after=after_colon):
                    self.assertEqual(redact_text(source), expected)
                    self.assertEqual(redact_text(expected), expected)
                    self.assertEqual(json.loads(expected)[json.loads(f'"{key}"')], "[REDACTED]")
        self.assertEqual(
            redact_text(r'"pass\u0077ord"=SYNTHETIC_SECRET mode=bridge'),
            r'"pass\u0077ord"=[REDACTED] mode=bridge',
        )

    def test_escaped_json_nonsecret_keys_and_literal_text_escapes_are_preserved(self) -> None:
        for key in (
            r"\u006dode",
            r"Password\u004cength",
            r"WPA\u005fPSKEnabled",
            r"pass\\u0077ord",
            r"vendor\"-mode",
            r"\ud83d\udd11-mode",
        ):
            source = f'{{"{key}":"visible","mode":"bridge"}}'
            with self.subTest(key=key):
                self.assertEqual(redact_text(source), source)
                self.assertEqual(redact_text(redact_text(source)), source)
        for source in (
            r"pass\u0077ord=visible",
            r"'pass\u0077ord': 'visible'",
            r'<DM name="pass\u0077ord" val="visible"/>',
        ):
            with self.subTest(source=source):
                self.assertEqual(redact_text(source), source)

    def test_malformed_json_key_escapes_use_conservative_literal_recognition(self) -> None:
        for key in (r"\qpassword", r"\uZZZZ-password", r"\u123-password"):
            source = f'{{"{key}":"SYNTHETIC_SECRET","mode":"bridge"}}'
            expected = source.replace("SYNTHETIC_SECRET", "[REDACTED]")
            with self.subTest(key=key):
                self.assertEqual(redact_text(source), expected)
                self.assertEqual(redact_text(expected), expected)
        for key in (r"pass\uZZZZword", r"\qmode", "mode\\"):
            source = f'{{"{key}":"visible"}}'
            with self.subTest(key=key):
                self.assertEqual(redact_text(source), source)
                self.assertEqual(redact_text(redact_text(source)), source)

    def test_surrogate_json_key_escapes_never_require_reencoding(self) -> None:
        for key in (r"\ud800-pass\u0077ord", r"\udfff-pass\u0077ord"):
            source = f'{{"{key}":"SYNTHETIC_SECRET"}}'
            expected = source.replace("SYNTHETIC_SECRET", "[REDACTED]")
            with self.subTest(key=key):
                self.assertEqual(redact_text(source), expected)
                self.assertEqual(redact_text(expected), expected)
                self.assertEqual(expected.encode("utf-8").decode("utf-8"), expected)
        for key in (r"\ud800-mode", r"\udfff-mode"):
            source = f'{{"{key}":"visible"}}'
            with self.subTest(key=key):
                self.assertEqual(redact_text(source), source)

    def test_long_escaped_json_keys_keep_bounded_forward_scanning(self) -> None:
        prefix = r"vendor\u005f" * 20_000
        secret = f'{{"{prefix}pass\\u0077ord":"SYNTHETIC_SECRET","mode":"bridge"}}'
        expected = secret.replace("SYNTHETIC_SECRET", "[REDACTED]")
        self.assertEqual(redact_text(secret), expected)
        self.assertEqual(redact_text(expected), expected)
        public = f'{{"{prefix}Setting":"visible"}}'
        self.assertEqual(redact_text(public), public)
        incomplete = '"' + (r"vendor\"name " * 20_000)
        self.assertEqual(redact_text(incomplete), incomplete)

    def test_large_quoted_and_folded_inputs_do_not_amplify_working_memory(self) -> None:
        # Allocate fixtures first: measure redaction's additional working memory,
        # including output, rather than the test's input/expected strings. The
        # old quote/fold loops used 100-300 MiB for these 1 Mi-character inputs.
        size = 1024 * 1024
        plain = "a" * size
        escaped = r"a\"b\\c" * (size // 7)
        folded = " \n" * (size // 2)
        pem_prefix = "A " * (size // 2)
        quoted_key = f'{{"{plain}":"visible"}}'
        escaped_key = f'{{"{escaped}":"visible"}}'
        incomplete_key = '"' + plain
        incomplete_escaped_key = '"' + escaped
        pem_begin = f"-----BEGIN {pem_prefix}PRIVATE KEY-----"
        malformed_pem = f"-----BEGIN {pem_prefix}PUBLIC KEY-----\nvisible"
        cases = (
            ("quoted key", quoted_key, quoted_key),
            ("escaped key", escaped_key, escaped_key),
            ("unterminated key", incomplete_key, incomplete_key),
            ("unterminated escaped key", incomplete_escaped_key, incomplete_escaped_key),
            ("quoted secret", f'password="{plain}"', 'password="[REDACTED]"'),
            ("single-quoted secret", f"password='{plain}'", "password='[REDACTED]'"),
            ("escaped secret", f'password="{escaped}"', 'password="[REDACTED]"'),
            ("unterminated secret", f'password="{plain}', "password=[REDACTED]"),
            (
                "quoted authorization",
                f'Captured Authorization: "{plain}"',
                'Captured Authorization: "[REDACTED]"',
            ),
            (
                "escaped authorization",
                f'Captured Authorization: "{escaped}"',
                'Captured Authorization: "[REDACTED]"',
            ),
            (
                "single-quoted authorization",
                f"Captured Authorization: '{plain}'",
                "Captured Authorization: '[REDACTED]'",
            ),
            (
                "unterminated authorization",
                f'Captured Authorization: "{plain}',
                "Captured Authorization: [REDACTED]",
            ),
            ("folded cookie", "Cookie: SID=secret\n" + folded, "Cookie: [REDACTED]\n"),
            (
                "folded authorization",
                "Authorization: Custom secret\n" + folded,
                "Authorization: [REDACTED]\n",
            ),
            (
                "captured folded authorization",
                "Captured Authorization: Custom secret\n" + folded,
                "Captured Authorization: [REDACTED]\n",
            ),
            ("PEM words", pem_begin + "\nsecret", pem_begin + "\n[REDACTED]\n"),
            ("malformed PEM words", malformed_pem, malformed_pem),
        )
        for label, source, expected in cases:
            with self.subTest(input=label):
                tracemalloc.start()
                try:
                    output = redact_text(source)
                    _, peak = tracemalloc.get_traced_memory()
                finally:
                    tracemalloc.stop()
                self.assertEqual(output, expected)
                self.assertLess(peak, 20 * 1024 * 1024)

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

    def test_yaml_plain_multiline_scalars_remove_the_complete_credential(self) -> None:
        # YAML folds these indented plain lines into one scalar password value.
        # Continuations can contain punctuation or look like independent fields.
        for prefix, newline, key in product(
            ("", "  ", "- ", "  -   "),
            ("\n", "\r\n", "\r"),
            ("password", "WPA_PSK", '"api_key"'),
        ):
            indent = " " * (len(prefix) + 2)
            sibling = " " * len(prefix)
            source = (
                f"{prefix}{key}: SYNTHETIC_FIRST{newline}{newline}"
                f"{indent}SYNTHETIC_SECOND{newline}"
                f"{indent}unknown=SYNTHETIC_THIRD{newline}"
                f"{sibling}mode: bridge{newline}"
            )
            expected = f"{prefix}{key}: [REDACTED]{newline}{sibling}mode: bridge{newline}"
            with self.subTest(prefix=prefix, newline=newline, key=key):
                self.assertEqual(redact_text(source), expected)
                self.assertEqual(redact_text(expected), expected)
        self.assertEqual(
            redact_text("notes: visible\n  still public\nmode: bridge"),
            "notes: visible\n  still public\nmode: bridge",
        )

    def test_yaml_keys_on_separate_lines_remove_complete_nested_values(self) -> None:
        for value in (
            "  SYNTHETIC_FIRST\n  SYNTHETIC_SECOND",
            "  - SYNTHETIC_FIRST\n  - SYNTHETIC_SECOND",
            "  value: SYNTHETIC_FIRST\n  hint: SYNTHETIC_SECOND",
            "  value:\n    nested: SYNTHETIC_FIRST\n  hint: SYNTHETIC_SECOND",
            '  "value": "SYNTHETIC_FIRST"\n  "hint": "SYNTHETIC_SECOND"',
            "  'value': 'SYNTHETIC_FIRST'\n  'hint': 'SYNTHETIC_SECOND'",
        ):
            source = f"password:\n\n{value}\nmode: bridge\n"
            expected = "password:\n\n  [REDACTED]\nmode: bridge\n"
            with self.subTest(value=value):
                self.assertEqual(redact_text(source), expected)
                self.assertEqual(redact_text(expected), expected)
        # Quoted multiline values have already been consumed as one scalar;
        # preserve their surrounding blank lines and source indentation.
        self.assertEqual(
            redact_text('password:\n\n  "SYNTHETIC_SECRET"\nmode: bridge'),
            'password:\n\n  "[REDACTED]"\nmode: bridge',
        )
        self.assertEqual(redact_text("password=\n"), "password=\n[REDACTED]")

    def test_yaml_indentationless_sequences_do_not_leave_later_items(self) -> None:
        for indent, marker in product(("", "  "), ("- ", "-\t", "-\n  ")):
            marker = marker.replace("\n", "\n" + indent)
            source = (
                f"{indent}password:\n"
                f"{indent}{marker}SYNTHETIC_FIRST\n"
                f"{indent}{marker}SYNTHETIC_SECOND\n"
                f"{indent}mode: bridge\n"
            )
            expected = f"{indent}password:\n{indent}- [REDACTED]\n{indent}mode: bridge\n"
            with self.subTest(indent=indent, marker=marker):
                self.assertEqual(redact_text(source), expected)
                self.assertEqual(redact_text(expected), expected)

    def test_json_sensitive_containers_are_replaced_as_complete_values(self) -> None:
        for name, whitespace, private_value in product(
            ("password", "cookie", "authorization", "WPA_PSK", r"pass\u0077ord"),
            ("", " ", "\n  ", "\r\n\t"),
            (
                [],
                {},
                ["SYNTHETIC_FIRST", "SYNTHETIC_SECOND"],
                {"value": "SYNTHETIC_FIRST", "hint": "SYNTHETIC_SECOND"},
                [{"nested": [{"value": 'SYNTHETIC_}]{\\"_SECRET'}]}],
            ),
        ):
            scalar = json.dumps(private_value, indent=2, ensure_ascii=False)
            source = f'{{ "{name}"{whitespace}:{whitespace}{scalar}, "mode": "bridge" }}'
            expected = f'{{ "{name}"{whitespace}:{whitespace}"[REDACTED]", "mode": "bridge" }}'
            with self.subTest(name=name, whitespace=whitespace, value=private_value):
                self.assertEqual(redact_text(source), expected)
                self.assertEqual(
                    json.loads(expected),
                    {json.loads(f'"{name}"'): "[REDACTED]", "mode": "bridge"},
                )
                self.assertEqual(redact_text(expected), expected)

    def test_json_nonstring_scalars_remain_valid_json_after_redaction(self) -> None:
        for scalar in ("0", "-1", "1.25", "1e12", "-2.5E-4", "true", "false", "null"):
            source = f'{{"password":\n  {scalar}, "mode":"bridge"}}'
            expected = '{"password":\n  "[REDACTED]", "mode":"bridge"}'
            with self.subTest(scalar=scalar):
                self.assertEqual(redact_text(source), expected)
                self.assertEqual(json.loads(expected)["password"], "[REDACTED]")
                self.assertEqual(redact_text(expected), expected)
        self.assertEqual(redact_text('"password":123'), '"password":[REDACTED]')
        self.assertEqual(
            redact_text('"password"=123 mode=bridge'), '"password"=[REDACTED] mode=bridge'
        )

    def test_flow_values_handle_quotes_and_discard_ambiguous_boundaries(self) -> None:
        source = "password: ['SYNTHETIC_]}_FIRST', {'value': 'SYNTHETIC_SECOND'}]\nmode: bridge"
        expected = 'password: "[REDACTED]"\nmode: bridge'
        self.assertEqual(redact_text(source), expected)
        self.assertEqual(redact_text(expected), expected)
        for value in (
            "[SYNTHETIC_SECRET",
            "{SYNTHETIC_SECRET",
            "[{SYNTHETIC_SECRET]",
            '{"value":"SYNTHETIC_SECRET}',
            '{"value":"SYNTHETIC_SECRET\\',
        ):
            with self.subTest(value=value):
                self.assertEqual(redact_text("password=" + value), 'password="[REDACTED]"')
        self.assertEqual(redact_text("password=[REDACTED]"), "password=[REDACTED]")
        self.assertEqual(redact_text("password="), "password=")

    def test_flow_comments_cannot_close_sensitive_containers(self) -> None:
        cases = (
            "[FIRST, # comment ] } \" ' \n  SYNTHETIC_DESCENDANT]",
            "{first: FIRST, # comment } ] \" ' \n  second: SYNTHETIC_DESCENDANT}",
            "[# comment ]\n  SYNTHETIC_DESCENDANT]",
            "[FIRST,# comment ]\n  SYNTHETIC_DESCENDANT]",
            '["FIRST"# comment ]\n, SYNTHETIC_DESCENDANT]',
            '["# ] }", "SYNTHETIC_DESCENDANT"]',
            "['# ] }', 'SYNTHETIC_DESCENDANT']",
            "[FIRST#literal, SYNTHETIC_DESCENDANT]",
            "[FIRST:#literal, SYNTHETIC_DESCENDANT]",
        )
        for value in cases:
            source = f"password: {value}\nmode: bridge\n"
            expected = 'password: "[REDACTED]"\nmode: bridge\n'
            with self.subTest(value=value):
                self.assertEqual(redact_text(source), expected)
                self.assertEqual(redact_text(expected), expected)
        self.assertEqual(redact_text("password: [# incomplete ]"), 'password: "[REDACTED]"')

    def test_yaml_comments_do_not_release_sensitive_descendant_state(self) -> None:
        cases = (
            (
                "password:\n- FIRST\n# comment\n- SYNTHETIC_DESCENDANT\nmode: bridge\n",
                "password:\n- [REDACTED]\nmode: bridge\n",
            ),
            (
                "password:\n# comment\n- SYNTHETIC_DESCENDANT\nmode: bridge\n",
                "password:\n# [REDACTED]\n- [REDACTED]\nmode: bridge\n",
            ),
            (
                "password:\n  first: FIRST\n# comment\n"
                "  second: SYNTHETIC_DESCENDANT\nmode: bridge\n",
                "password:\n  [REDACTED]\nmode: bridge\n",
            ),
            ("password:\n# comment", "password:\n# [REDACTED]"),
        )
        for source, expected in cases:
            with self.subTest(source=source):
                self.assertEqual(redact_text(source), expected)
                self.assertEqual(redact_text(expected), expected)

    def test_yaml_properties_and_leading_comments_cannot_hide_flow_values(self) -> None:
        for prefix in (
            "&synthetic ",
            "!!seq ",
            "!local ",
            "! ",
            "!<tag:yaml.org,2002:seq> ",
            "!!seq &synthetic ",
            "&synthetic !!seq ",
            "&synthetic # comment\n  ",
            "# comment\n  ",
            "# first\n # second\n  ",
        ):
            source = f"password: {prefix}[FIRST,\nSYNTHETIC_DESCENDANT]\nmode: bridge\n"
            expected = 'password: "[REDACTED]"\nmode: bridge\n'
            with self.subTest(prefix=prefix):
                self.assertEqual(redact_text(source), expected)
                self.assertEqual(redact_text(expected), expected)
        for prefix in ("&synthetic", "!!seq", "!!seq &synthetic"):
            source = f"password: {prefix}\n- FIRST\n# comment\n- SYNTHETIC_DESCENDANT\nmode: bridge"
            expected = "password: [REDACTED]\nmode: bridge"
            with self.subTest(prefix=prefix):
                self.assertEqual(redact_text(source), expected)
                self.assertEqual(redact_text(expected), expected)
        self.assertEqual(redact_text("password: &synthetic \n"), "password: [REDACTED]\n")
        self.assertEqual(redact_text("password: # comment"), "password: [REDACTED]")

    def test_json_atom_prefixes_do_not_expose_yaml_plain_scalar_continuations(self) -> None:
        for atom in ("123", "true", "false", "null", "-1.2e+3"):
            source = f'"password": {atom}\n  SYNTHETIC_DESCENDANT\nmode: bridge\n'
            expected = '"password": [REDACTED]\nmode: bridge\n'
            self.assertEqual(redact_text(source), expected)
            self.assertEqual(redact_text(expected), expected)
            for comment in ("", " # ignored } ]\n "):
                source = f'{{"password": {atom}{comment}\n  SYNTHETIC_DESCENDANT, mode: bridge}}\n'
                expected = '{"password": "[REDACTED]", mode: bridge}\n'
                self.assertEqual(redact_text(source), expected)
                self.assertEqual(redact_text(expected), expected)
        self.assertEqual(redact_text('{"password":123 unknown'), '{"password":"[REDACTED]"')

    def test_container_prefixes_do_not_expose_plaintext_credential_suffixes(self) -> None:
        for container, suffix, assignment in product(
            ("[SYNTHETIC_FIRST]", "{SYNTHETIC_FIRST}"),
            (" SYNTHETIC_SECOND", ";SYNTHETIC_SECOND", ",SYNTHETIC_SECOND", "}SYNTHETIC_SECOND"),
            ("=", ": "),
        ):
            source = f"password{assignment}{container}{suffix} mode=bridge"
            expected = f'password{assignment}"[REDACTED]" mode=bridge'
            with self.subTest(container=container, suffix=suffix, assignment=assignment):
                self.assertEqual(redact_text(source), expected)
                self.assertEqual(redact_text(expected), expected)
        source = 'password=["SYNTHETIC_FIRST"] SYNTHETIC_SECOND\nmode=bridge'
        self.assertEqual(redact_text(source), 'password="[REDACTED]"\nmode=bridge')
        self.assertEqual(redact_text("password=[SYNTHETIC_FIRST] tail"), 'password="[REDACTED]"')

    def test_adjacent_and_nested_json_containers_keep_public_structure(self) -> None:
        cases = (
            ('[{"password":[]}]', '[{"password":"[REDACTED]"}]'),
            (
                '{\n"password": [],\n"mode":"bridge"\n}',
                '{\n"password": "[REDACTED]",\n"mode":"bridge"\n}',
            ),
            (
                '{"password": [], "token":{}, "mode":"bridge"}',
                '{"password": "[REDACTED]", "token":"[REDACTED]", "mode":"bridge"}',
            ),
            (
                '{"nested":{"password":{} }, "mode":"bridge"}',
                '{"nested":{"password":"[REDACTED]" }, "mode":"bridge"}',
            ),
            (
                '{"list":[{ "password": []}, {"mode":"bridge"}]}',
                '{"list":[{ "password": "[REDACTED]"}, {"mode":"bridge"}]}',
            ),
            (
                '[{"password":[]},\n "visible", 123, true, null]',
                '[{"password":"[REDACTED]"},\n "visible", 123, true, null]',
            ),
        )
        for source, expected in cases:
            with self.subTest(source=source):
                self.assertEqual(redact_text(source), expected)
                self.assertEqual(json.loads(redact_text(source)), json.loads(expected))
        self.assertEqual(
            redact_text("parent:\n  list: [{password: []}, {mode: bridge}]"),
            'parent:\n  list: [{password: "[REDACTED]"}, {mode: bridge}]',
        )
        source = "password=[SYNTHETIC_SECRET] mode=bridge " * 20_000
        expected = 'password="[REDACTED]" mode=bridge ' * 20_000
        self.assertEqual(redact_text(source), expected)

    def test_mixed_json_xml_remains_conservative_without_a_format_guarantee(self) -> None:
        # Embedded markup can make the XML pass discard the rest of a JSON
        # string/document. Retain this conservative masking: skipping XML just
        # because the report begins with '{' could expose an embedded secret.
        source = '{"public":"<password>SYNTHETIC_SECRET","mode":"bridge"}'
        output = redact_text(source)
        self.assertNotIn("SYNTHETIC_SECRET", output)
        self.assertEqual(output, '{"public":"<password>[REDACTED]')
        with self.assertRaises(json.JSONDecodeError):
            json.loads(output)

    def test_secret_containers_have_bounded_nonrecursive_scanning(self) -> None:
        depth = 20_000
        nested = '{"value":[' * depth + '"SYNTHETIC_SECRET"' + "]}" * depth
        source = f'{{"password":{nested},"mode":"bridge"}}'
        expected = '{"password":"[REDACTED]","mode":"bridge"}'
        tracemalloc.start()
        try:
            output = redact_text(source)
            _, peak = tracemalloc.get_traced_memory()
        finally:
            tracemalloc.stop()
        self.assertEqual(output, expected)
        self.assertLess(peak, 20 * 1024 * 1024)
        self.assertEqual(
            redact_text("password=[SYNTHETIC_SECRET " * 20_000),
            'password="[REDACTED]"',
        )

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

    def test_private_key_kind_words_cannot_consume_the_required_delimiter(self) -> None:
        for prefix in (
            "PRIVATE KEY RSA ",
            "RSA PRIVATE KEY ENCRYPTED ",
            "PRIVATE PRIVATE KEY ",
            "ENCRYPTED OPENSSH ",
        ):
            kind = prefix + "PRIVATE KEY"
            begin, end = f"-----BEGIN {kind}-----", f"-----END {kind}-----"
            for suffix in (end + "\nvisible", "-----END OTHER PRIVATE KEY-----", ""):
                source = begin + "\nSYNTHETIC_KEY_MATERIAL\n" + suffix
                expected = begin + "\n[REDACTED]\n" + (suffix if suffix.startswith(end) else "")
                with self.subTest(kind=kind, suffix=suffix):
                    self.assertEqual(redact_text(source), expected)
                    self.assertEqual(redact_text(expected), expected)
        malformed = "-----BEGIN RSA PRIVATE KEY WITHOUT DELIMITER-----\nvisible"
        self.assertEqual(redact_text(malformed), malformed)

    def test_report_size_limit_is_enforced(self) -> None:
        with patch("cpe_access_atlas.redaction.MAX_REPORT_CHARS", 16):
            with self.assertRaisesRegex(RedactionError, "safety size limit"):
                redact_text("x" * 17)


if __name__ == "__main__":
    unittest.main()

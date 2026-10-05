# SPDX-License-Identifier: 0BSD
"""Property-based robustness tests for code that parses untrusted input.

These tests do not assert 100% coverage of new branches; they exist to
catch crashes (IndexError, struct.error, UnicodeDecodeError, RecursionError,
etc.) on malformed or adversarial input that example-based unit tests would
not think to construct. `config.py` decodes attacker-influenced binary
containers and `redaction.py` runs several regexes over untrusted text, so
both are exercised here with wide, randomized inputs.
"""

from __future__ import annotations

import contextlib
import json
import struct
import unittest
import zlib
from html import escape

from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from cpe_access_atlas.config import (
    PAYLOAD_MAGIC,
    ConfigError,
    buggy_sha256,
    decode_config,
    encode_config,
    inspect_config,
)
from cpe_access_atlas.redaction import redact_text

# Deadline disabled: these functions include intentional bounded work (zlib
# decompression, regex passes) whose wall-clock time depends on the machine
# running the suite, not on a logic defect.
_SUITE_SETTINGS = settings(
    max_examples=200,
    deadline=None,
    suppress_health_check=[HealthCheck.too_slow],
)


class ConfigDecodingFuzzTests(unittest.TestCase):
    @given(st.lists(st.binary(max_size=256), min_size=1, max_size=8))
    @_SUITE_SETTINGS
    def test_structured_multichunk_inputs_round_trip_and_require_a_final_chunk(
        self, chunks: list[bytes]
    ) -> None:
        packed = [zlib.compress(chunk) for chunk in chunks]
        plain_size, packed_data = sum(map(len, chunks)), b"".join(packed)
        header = struct.pack(
            ">6I",
            PAYLOAD_MAGIC,
            0,
            plain_size,
            len(packed_data),
            plain_size,
            zlib.crc32(packed_data),
        )
        prefix = header + struct.pack(">I", zlib.crc32(header)) + bytes(32)
        body = b"".join(
            struct.pack(">3I", len(plain), len(compressed), int(index < len(chunks) - 1))
            + compressed
            for index, (plain, compressed) in enumerate(zip(chunks, packed, strict=True))
        )
        self.assertEqual(decode_config(prefix + body).xml, b"".join(chunks))
        with self.assertRaises(ConfigError):
            decode_config(prefix + body + b"unexpected trailer")

    @given(st.binary(min_size=1, max_size=2048))
    @_SUITE_SETTINGS
    def test_encrypted_structured_artifacts_round_trip_and_reject_truncation(
        self, xml: bytes
    ) -> None:
        coordinates = {"device_key": "a" * 32, "serial": "ZTE12345678", "mac": "00:11:22:33:44:55"}
        artifact = encode_config(
            xml,
            encrypted=True,
            acknowledge_legacy_crypto=True,
            base64_wrap=False,
            **coordinates,
        )
        self.assertEqual(decode_config(artifact, **coordinates).xml, xml)
        with self.assertRaises(ConfigError):
            decode_config(artifact[:-1], **coordinates)

    @given(st.binary(min_size=0, max_size=4096))
    @_SUITE_SETTINGS
    def test_decode_config_never_raises_an_uncontrolled_exception(self, data: bytes) -> None:
        # ConfigError is the only exception this API is allowed to raise on bad input.
        with contextlib.suppress(ConfigError):
            decode_config(data)

    @given(
        st.binary(min_size=0, max_size=4096),
        st.text(min_size=0, max_size=32),
        st.text(min_size=0, max_size=32),
        st.text(min_size=0, max_size=32),
    )
    @_SUITE_SETTINGS
    def test_decode_config_with_arbitrary_credentials_never_crashes(
        self, data: bytes, device_key: str, serial: str, mac: str
    ) -> None:
        with contextlib.suppress(ConfigError):
            decode_config(data, device_key=device_key, serial=serial, mac=mac)

    @given(st.binary(min_size=0, max_size=4096))
    @_SUITE_SETTINGS
    def test_inspect_config_never_raises_an_uncontrolled_exception(self, data: bytes) -> None:
        with contextlib.suppress(ConfigError):
            inspect_config(data)

    @given(st.binary(max_size=1024))
    @_SUITE_SETTINGS
    def test_buggy_sha256_always_returns_a_32_byte_digest(self, message: bytes) -> None:
        digest = buggy_sha256(message)
        self.assertEqual(len(digest), 32)
        self.assertEqual(digest, buggy_sha256(message))  # deterministic

    @given(st.binary(max_size=512), st.binary(max_size=512))
    @_SUITE_SETTINGS
    def test_buggy_sha256_distinguishes_most_distinct_inputs(
        self, left: bytes, right: bytes
    ) -> None:
        if left != right:
            # Not a cryptographic guarantee, just a smoke check that the
            # digest is not a constant function of its input.
            digest_left = buggy_sha256(left)
            digest_right = buggy_sha256(right)
            if len(left) != len(right):
                self.assertNotEqual(digest_left, digest_right)


class RedactionFuzzTests(unittest.TestCase):
    @given(
        st.sampled_from(("[SYNTHETIC_FIRST]", "{SYNTHETIC_FIRST}")),
        st.sampled_from((" ", ";", ",", "}", "]", "\t")),
        st.text(alphabet="abcXYZ019 _-;,'\"&/\\{}[]!$%çğşΩ", max_size=200),
    )
    @_SUITE_SETTINGS
    def test_container_prefixes_mask_complete_plaintext_suffixes(
        self, prefix: str, separator: str, suffix: str
    ) -> None:
        source = f"password={prefix}{separator}SYNTHETIC_{suffix}_TAIL mode=bridge"
        expected = 'password="[REDACTED]" mode=bridge'
        self.assertEqual(redact_text(source), expected)
        self.assertEqual(redact_text(expected), expected)

    @given(
        st.recursive(
            st.one_of(
                st.none(),
                st.booleans(),
                st.integers(),
                st.text(alphabet="aAzZ019 _-:;,\"'\\{}[]<>&\t\r\nçğşΩ🔑", max_size=64),
            ),
            lambda children: st.one_of(
                st.lists(children, max_size=5),
                st.dictionaries(st.sampled_from(("value", "hint", "unknown")), children),
            ),
            max_leaves=30,
        ),
        st.sampled_from(("password", "cookie", "authorization", "WPA_PSK")),
        st.sampled_from((None, 0, 2, "\t")),
    )
    @_SUITE_SETTINGS
    def test_sensitive_json_subtrees_are_removed_without_exposing_descendants(
        self, subtree: object, name: str, indent: int | str | None
    ) -> None:
        secret = {"value": subtree, "marker": "SYNTHETIC_SECRET"}
        source = json.dumps({name: secret, "mode": "bridge"}, indent=indent, ensure_ascii=False)
        expected = json.dumps(
            {name: "[REDACTED]", "mode": "bridge"}, indent=indent, ensure_ascii=False
        )
        self.assertEqual(redact_text(source), expected)
        self.assertEqual(json.loads(expected), {name: "[REDACTED]", "mode": "bridge"})
        self.assertEqual(redact_text(expected), expected)

    @given(
        st.lists(
            st.text(alphabet="abc019 ;,={}[]!$&'\"çğşΩ", max_size=80),
            min_size=1,
            max_size=20,
        ),
        st.sampled_from(("", "  ", "- ", "  -   ")),
        st.sampled_from(("\n", "\r\n", "\r")),
    )
    @_SUITE_SETTINGS
    def test_yaml_plain_scalar_continuations_are_fully_removed(
        self, lines: list[str], prefix: str, newline: str
    ) -> None:
        indentation = " " * (len(prefix) + 2)
        sibling = " " * len(prefix)
        source = (
            f"{prefix}password: SYNTHETIC_FIRST{newline}"
            + "".join(f"{indentation}SYNTHETIC_{line}{newline}" for line in lines)
            + f"{sibling}mode: bridge{newline}"
        )
        expected = f"{prefix}password: [REDACTED]{newline}{sibling}mode: bridge{newline}"
        self.assertEqual(redact_text(source), expected)
        self.assertEqual(redact_text(expected), expected)

    @given(
        st.lists(
            st.text(alphabet="abc019 ;,={}[]!$&çğşΩ", max_size=80),
            min_size=1,
            max_size=20,
        ),
        st.sampled_from(('"', "'")),
        st.sampled_from(("", "  ", "- ", "  -   ")),
        st.sampled_from(("\n", "\r\n", "\r")),
    )
    @_SUITE_SETTINGS
    def test_yaml_sensitive_mappings_remove_quoted_keys_and_all_values(
        self, values: list[str], quote: str, prefix: str, newline: str
    ) -> None:
        indentation = " " * (len(prefix) + 2)
        sibling = " " * len(prefix)
        source = (
            f"{prefix}password:{newline}"
            + "".join(
                f"{indentation}{quote}key{index}{quote}: {quote}SYNTHETIC_{value}{quote}{newline}"
                for index, value in enumerate(values)
            )
            + f"{sibling}mode: bridge{newline}"
        )
        expected = (
            f"{prefix}password:{newline}{indentation}[REDACTED]{newline}"
            f"{sibling}mode: bridge{newline}"
        )
        self.assertEqual(redact_text(source), expected)
        self.assertEqual(redact_text(expected), expected)

    @given(st.text(alphabet="aAzZ019 _-:;,'\"\\<>&\t\r\nçğşΩ🔑", max_size=512))
    @_SUITE_SETTINGS
    def test_quoted_text_credentials_preserve_escaped_delimiters(self, value: str) -> None:
        for quote in ('"', "'"):
            escaped = ("SYNTHETIC_HEAD" + value + "SYNTHETIC_TAIL").replace("\\", "\\\\")
            escaped = escaped.replace(quote, "\\" + quote)
            source = f"password={quote}{escaped}{quote} mode=bridge"
            expected = f"password={quote}[REDACTED]{quote} mode=bridge"
            self.assertEqual(redact_text(source), expected)
            self.assertEqual(redact_text(expected), expected)

    @given(
        st.sampled_from(("password", "Token", "cookie", "api_key", "WPA_PSK", "KeyPassphrase")),
        st.sampled_from(("", "Café-", "vendor:", "vendor name-", 'vendor"-', "vendor\\-", "🔑-")),
        st.integers(min_value=1, max_value=2**64 - 1),
        st.text(alphabet="aAzZ019 _-:;,'\"\\<>&\t\r\nçğşΩ🔑", max_size=256),
        st.sampled_from(("", "\n", "\r\n \t")),
    )
    @_SUITE_SETTINGS
    def test_json_sensitive_keys_with_generated_escape_spellings_are_fully_removed(
        self, name: str, prefix: str, mask: int, value: str, whitespace: str
    ) -> None:
        # The first credential-name character is always escaped; the mask
        # varies every other character between literal and Unicode spelling.
        key = (
            json.dumps(prefix, ensure_ascii=True)[:-1]
            + "".join(
                f"\\u{ord(character):04x}" if index == 0 or (mask >> index) & 1 else character
                for index, character in enumerate(name)
            )
            + '"'
        )
        scalar = json.dumps("SYNTHETIC_HEAD" + value + "SYNTHETIC_TAIL", ensure_ascii=False)
        source = f'{{{key}{whitespace}:{whitespace}{scalar},"mode":"bridge"}}'
        expected = f'{{{key}{whitespace}:{whitespace}"[REDACTED]","mode":"bridge"}}'
        self.assertEqual(redact_text(source), expected)
        self.assertEqual(json.loads(expected), {prefix + name: "[REDACTED]", "mode": "bridge"})
        self.assertEqual(redact_text(expected), expected)

    @given(
        st.sampled_from(
            (
                "KeyPassphrase",
                "PreSharedKey",
                "wifi_psk",
                "WPA_PSK",
                "WPA2PSK",
                "X--password",
                "Café-Password",
            )
        ),
        st.text(alphabet="aAzZ019 _-:;,'\"\\<>&\t\r\nçğşΩ🔑", max_size=256),
        st.booleans(),
    )
    @_SUITE_SETTINGS
    def test_wifi_credentials_with_escaped_values_are_fully_removed(
        self, name: str, value: str, uppercase: bool
    ) -> None:
        name = name.upper() if uppercase else name.lower()
        examples = [
            (
                json.dumps({name: value}, ensure_ascii=False),
                json.dumps({name: "[REDACTED]"}, ensure_ascii=False),
            ),
            (
                f'<DM name="{name}" val="{escape(value, quote=True)}"/>',
                f'<DM name="{name}" val="[REDACTED]"/>',
            ),
            (
                f"<DM val='{escape(value, quote=True)}' name='{name}'/>",
                f"<DM val='[REDACTED]' name='{name}'/>",
            ),
        ]
        if name.isascii():
            examples.append((json.dumps({name: value}), json.dumps({name: "[REDACTED]"})))
        for source, expected in examples:
            self.assertEqual(redact_text(source), expected)
            self.assertEqual(redact_text(expected), expected)

    @given(
        st.lists(
            st.text(alphabet="abcdefghijklmnopqrstuvwxyz0123456789", min_size=8, max_size=32),
            min_size=2,
            max_size=8,
        )
    )
    @_SUITE_SETTINGS
    def test_every_cookie_value_is_removed_from_a_structured_header(
        self, values: list[str]
    ) -> None:
        header = "Cookie: " + "; ".join(
            f"cookie{index}={value}" for index, value in enumerate(values)
        )
        self.assertEqual(redact_text(header), "Cookie: [REDACTED]")

    @given(st.text(max_size=2000))
    @_SUITE_SETTINGS
    def test_redact_text_never_raises_on_arbitrary_unicode(self, value: str) -> None:
        result = redact_text(value)
        self.assertIsInstance(result, str)

    @given(st.text(alphabet=st.characters(min_codepoint=0, max_codepoint=0x10FFFF), max_size=500))
    @_SUITE_SETTINGS
    def test_redact_text_never_raises_on_full_unicode_range(self, value: str) -> None:
        result = redact_text(value)
        self.assertIsInstance(result, str)

    @given(st.text(max_size=500))
    @_SUITE_SETTINGS
    def test_redact_text_is_idempotent_on_its_own_output(self, value: str) -> None:
        once = redact_text(value)
        twice = redact_text(once)
        self.assertEqual(once, twice)


if __name__ == "__main__":
    unittest.main()

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
import unittest

from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from cpe_access_atlas.config import ConfigError, buggy_sha256, decode_config, inspect_config
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

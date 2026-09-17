# SPDX-License-Identifier: 0BSD
"""Tests for the authenticated local private-artifact container."""

from __future__ import annotations

import struct
import unittest
from unittest.mock import patch

import cpe_access_atlas.private_container as private_container
from cpe_access_atlas.private_container import (
    PrivateContainerError,
    protect_private_bytes,
    unprotect_private_bytes,
)

PASSPHRASE = "correct horse battery staple"

# Synthetic CPAP v1 vector generated independently with CPython 3.12's
# hashlib.scrypt and cryptography 50.0.1 AESGCM, not this package's encoder/KDF.
# Salt is bytes(range(16)); nonce is bytes(range(16, 28)); scrypt parameters
# are N=32768, r=8, p=1, dklen=32. U+1FAE9 is assigned only in Unicode 16;
# the final e + combining acute accent must not be normalized to U+00E9.
INDEPENDENT_PASSPHRASE = "synthetic-cpap-\U0001fae9-e\u0301"
INDEPENDENT_PLAINTEXT = b"CPAP-v1 independent vector\x00\xff"
INDEPENDENT_CONTAINER = bytes.fromhex(
    "43504150010101100c000000000000001c000102030405060708090a0b0c0d0e0f"
    "101112131415161718191a1bae31c0cc1c271a82687cadc1ba1d86f5d62ebc192ffaa6"
    "2cf26340d2f21a7c6e3a0999b7439f58e68b026050"
)

# Saved before the Unicode validation fix using Python 3.14.7 / Unicode 16.
# Python 3.11/3.12 consider U+1FAE9 unassigned; the old validator consequently
# rejected this intact container before authentication. Keep these bytes fixed.
LEGACY_UNICODE_CONTAINER = bytes.fromhex(
    "43504150010101100c0000000000000026ba2e383ff5ce9e0b9adaf8d7ebb6d578"
    "cea5d3e12052ed02d8138b9f9f527433c2a4c2072d242cac0bfeb8a634a86b966d86"
    "6d3a493d2c40241091e1631d644192affbe2c4be0389e6b15e8efab6f93a8f75"
)


class PrivateContainerTests(unittest.TestCase):
    def test_independent_unicode_vector_decrypts_and_encryption_matches_exactly(self) -> None:
        self.assertEqual(
            unprotect_private_bytes(INDEPENDENT_CONTAINER, INDEPENDENT_PASSPHRASE),
            INDEPENDENT_PLAINTEXT,
        )
        with patch.object(
            private_container,
            "_random_bytes",
            side_effect=[bytes(range(16)), bytes(range(16, 28))],
        ):
            self.assertEqual(
                protect_private_bytes(INDEPENDENT_PLAINTEXT, INDEPENDENT_PASSPHRASE),
                INDEPENDENT_CONTAINER,
            )

    def test_python_314_container_opens_on_every_supported_unicode_database(self) -> None:
        self.assertEqual(
            unprotect_private_bytes(LEGACY_UNICODE_CONTAINER, "audit-passphrase-\U0001fae9"),
            b"synthetic unicode compatibility vector",
        )

    def test_passphrase_scalar_policy_is_independent_of_unicode_assignments(self) -> None:
        # Exercise range edges, multiple scripts, combining marks, old/new emoji,
        # private-use and currently unassigned scalars without Unicode lookup.
        for suffix in (
            " ",
            "~",
            "\u00a0",
            "\u2027",
            "\u202a",
            "\ud7ff",
            "\ue000",
            "\U0010ffff",
            "\u0378",
            "\U0001fae9",
            "\U0001f511",
            "şifre日本語",
            "e\u0301",
        ):
            value = "synthetic-passphrase-" + suffix
            with self.subTest(suffix=ascii(suffix)):
                self.assertEqual(private_container._validate_passphrase(value), value.encode())
        for length in (12, 256):
            value = "\U0001fae9" * length
            self.assertEqual(private_container._validate_passphrase(value), value.encode())

    def test_controls_line_separators_and_surrogates_fail_before_crypto(self) -> None:
        invalid_codepoints = [*range(0x20), *range(0x7F, 0xA0), 0x2028, 0x2029, 0xD800, 0xDFFF]
        for codepoint in invalid_codepoints:
            value = "synthetic-passphrase-" + chr(codepoint)
            with (
                self.subTest(codepoint=hex(codepoint)),
                patch.object(private_container, "_require_crypto") as crypto,
            ):
                with self.assertRaisesRegex(PrivateContainerError, "without C0/C1 controls"):
                    protect_private_bytes(b"synthetic", value)
                with self.assertRaisesRegex(PrivateContainerError, "without C0/C1 controls"):
                    unprotect_private_bytes(INDEPENDENT_CONTAINER, value)
                crypto.assert_not_called()

    def test_independent_vector_rejects_parameter_and_authenticated_data_tampering(self) -> None:
        for offset in (0, 4, 7, 9, 17, 33, 45, len(INDEPENDENT_CONTAINER) - 1):
            tampered = bytearray(INDEPENDENT_CONTAINER)
            tampered[offset] ^= 1
            with self.subTest(offset=offset), self.assertRaises(PrivateContainerError):
                unprotect_private_bytes(bytes(tampered), INDEPENDENT_PASSPHRASE)

    def test_passphrase_bytes_are_not_normalized_trimmed_or_case_folded(self) -> None:
        variants = (
            INDEPENDENT_PASSPHRASE.replace("e\u0301", "\u00e9"),
            INDEPENDENT_PASSPHRASE.upper(),
            INDEPENDENT_PASSPHRASE + " ",
            " " + INDEPENDENT_PASSPHRASE,
        )
        for value in variants:
            with self.subTest(value=ascii(value)):
                with self.assertRaisesRegex(PrivateContainerError, "authentication failed"):
                    unprotect_private_bytes(INDEPENDENT_CONTAINER, value)

    def test_round_trip_is_authenticated_and_uses_fresh_randomness(self) -> None:
        plaintext = b"synthetic private configuration=not-a-real-secret"
        first = protect_private_bytes(plaintext, PASSPHRASE)
        second = protect_private_bytes(plaintext, PASSPHRASE)

        self.assertNotEqual(first, second)
        self.assertEqual(unprotect_private_bytes(first, PASSPHRASE), plaintext)
        self.assertEqual(unprotect_private_bytes(second, PASSPHRASE), plaintext)
        self.assertTrue(first.startswith(b"CPAP"))
        self.assertEqual(len(first), private_container._HEADER.size + 16 + 12 + len(plaintext) + 16)

    def test_deterministic_random_inputs_make_the_format_reproducible(self) -> None:
        plaintext = b"synthetic"
        with patch.object(
            private_container,
            "_random_bytes",
            side_effect=[b"s" * 16, b"n" * 12, b"s" * 16, b"n" * 12],
        ):
            first = protect_private_bytes(plaintext, PASSPHRASE)
            second = protect_private_bytes(plaintext, PASSPHRASE)
        self.assertEqual(first, second)

    def test_invalid_plaintext_and_passphrases_are_rejected(self) -> None:
        for value in (b"", bytearray(b"data"), None):
            with (
                self.subTest(value=value),
                self.assertRaisesRegex(PrivateContainerError, "empty or exceeds"),
            ):
                protect_private_bytes(value, PASSPHRASE)  # type: ignore[arg-type]
        for value in (None, "short", "x" * 257, "line\nbreak"):
            with (
                self.subTest(value=value),
                self.assertRaisesRegex(PrivateContainerError, "12-256 Unicode"),
            ):
                protect_private_bytes(b"data", value)  # type: ignore[arg-type]

    def test_missing_crypto_backend_is_a_controlled_error(self) -> None:
        with patch.object(private_container, "AES", None):
            with self.assertRaisesRegex(PrivateContainerError, "support is unavailable"):
                protect_private_bytes(b"data", PASSPHRASE)

    def test_wrong_passphrase_and_tampering_fail_authentication(self) -> None:
        artifact = protect_private_bytes(b"synthetic", PASSPHRASE)
        with self.assertRaisesRegex(PrivateContainerError, "authentication failed"):
            unprotect_private_bytes(artifact, "another correct passphrase")
        tampered = bytearray(artifact)
        tampered[-1] ^= 1
        with self.assertRaisesRegex(PrivateContainerError, "authentication failed"):
            unprotect_private_bytes(bytes(tampered), PASSPHRASE)

    def test_parser_rejects_nonbytes_truncation_and_oversized_input(self) -> None:
        for value in (bytearray(b"x"), b"x" * 10):
            with self.subTest(value_type=type(value).__name__):
                with self.assertRaisesRegex(PrivateContainerError, "safety size|header"):
                    unprotect_private_bytes(value, PASSPHRASE)  # type: ignore[arg-type]
        with patch.object(private_container, "MAX_CONTAINER_BYTES", 1):
            with self.assertRaisesRegex(PrivateContainerError, "safety size"):
                unprotect_private_bytes(b"x" * 2, PASSPHRASE)

    def test_parser_rejects_unknown_format_parameters_and_lengths(self) -> None:
        artifact = protect_private_bytes(b"synthetic", PASSPHRASE)

        unknown = bytearray(artifact)
        unknown[0] ^= 1
        with self.assertRaisesRegex(PrivateContainerError, "format is not recognized"):
            unprotect_private_bytes(bytes(unknown), PASSPHRASE)

        for offset in (4, 5, 6):
            malformed = bytearray(artifact)
            malformed[offset] = 2
            with (
                self.subTest(offset=offset),
                self.assertRaisesRegex(PrivateContainerError, "format is not recognized"),
            ):
                unprotect_private_bytes(bytes(malformed), PASSPHRASE)

        for offset in (7, 8):
            malformed = bytearray(artifact)
            malformed[offset] = 8
            with (
                self.subTest(offset=offset),
                self.assertRaisesRegex(PrivateContainerError, "parameters are not supported"),
            ):
                unprotect_private_bytes(bytes(malformed), PASSPHRASE)

        for payload_length in (0, private_container.MAX_PRIVATE_BYTES + 1):
            malformed = bytearray(artifact)
            struct.pack_into(">Q", malformed, 9, payload_length)
            with (
                self.subTest(payload_length=payload_length),
                self.assertRaisesRegex(PrivateContainerError, "payload size is invalid"),
            ):
                unprotect_private_bytes(bytes(malformed), PASSPHRASE)

        with self.assertRaisesRegex(PrivateContainerError, "length is invalid"):
            unprotect_private_bytes(artifact + b"trailing", PASSPHRASE)

    def test_parser_accepts_only_a_complete_container_and_crypto_failure_is_controlled(
        self,
    ) -> None:
        artifact = protect_private_bytes(b"synthetic", PASSPHRASE)
        for malformed in (artifact[: private_container._HEADER.size - 1], artifact[:-1]):
            with (
                self.subTest(length=len(malformed)),
                self.assertRaisesRegex(
                    PrivateContainerError, "header is truncated|length is invalid"
                ),
            ):
                unprotect_private_bytes(malformed, PASSPHRASE)
        with patch.object(private_container, "AES", None):
            with self.assertRaisesRegex(PrivateContainerError, "support is unavailable"):
                unprotect_private_bytes(artifact, PASSPHRASE)


if __name__ == "__main__":
    unittest.main()

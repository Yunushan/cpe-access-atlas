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


class PrivateContainerTests(unittest.TestCase):
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
                self.assertRaisesRegex(PrivateContainerError, "12-256 printable"),
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

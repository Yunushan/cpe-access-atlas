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
    def test_independent_v1_unicode_vector_remains_decryptable(self) -> None:
        with patch.object(private_container, "_scrypt", wraps=private_container._scrypt) as derive:
            self.assertEqual(
                unprotect_private_bytes(INDEPENDENT_CONTAINER, INDEPENDENT_PASSPHRASE),
                INDEPENDENT_PLAINTEXT,
            )
        self.assertEqual(
            derive.call_args.args[3:],
            (
                private_container._V1_SCRYPT_N,
                private_container._SCRYPT_R,
                private_container._SCRYPT_P,
            ),
        )

    def test_v1_plaintext_can_be_migrated_to_a_v2_container(self) -> None:
        plaintext = unprotect_private_bytes(INDEPENDENT_CONTAINER, INDEPENDENT_PASSPHRASE)
        migrated = protect_private_bytes(plaintext, INDEPENDENT_PASSPHRASE)

        self.assertEqual(migrated[:4], b"CPAP")
        self.assertEqual(migrated[4], private_container._VERSION_2)
        self.assertNotEqual(migrated, INDEPENDENT_CONTAINER)
        self.assertEqual(unprotect_private_bytes(migrated, INDEPENDENT_PASSPHRASE), plaintext)

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
        with patch.object(private_container, "_scrypt", wraps=private_container._scrypt) as derive:
            first = protect_private_bytes(plaintext, PASSPHRASE)
            second = protect_private_bytes(plaintext, PASSPHRASE)
            self.assertEqual(unprotect_private_bytes(first, PASSPHRASE), plaintext)
            self.assertEqual(unprotect_private_bytes(second, PASSPHRASE), plaintext)

        self.assertNotEqual(first, second)
        self.assertEqual(
            [call.args[3:] for call in derive.call_args_list],
            [(2**17, 8, 1)] * 4,
        )
        self.assertTrue(first.startswith(b"CPAP"))
        self.assertEqual(len(first), private_container._HEADER.size + 16 + 12 + len(plaintext) + 16)

        (
            magic,
            version,
            kdf,
            cipher,
            salt_length,
            nonce_length,
            scrypt_n,
            scrypt_r,
            scrypt_p,
            payload_length,
        ) = private_container._V2_HEADER.unpack(first[: private_container._V2_HEADER.size])
        self.assertEqual(
            (
                magic,
                version,
                kdf,
                cipher,
                salt_length,
                nonce_length,
                scrypt_n,
                scrypt_r,
                scrypt_p,
                payload_length,
            ),
            (
                b"CPAP",
                private_container._VERSION_2,
                private_container._KDF_SCRYPT,
                private_container._CIPHER_AES_GCM,
                16,
                12,
                2**17,
                8,
                1,
                len(plaintext),
            ),
        )

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

    def test_v2_header_salt_nonce_ciphertext_and_tag_are_authenticated(self) -> None:
        plaintext = b"synthetic authenticated fields"
        artifact = protect_private_bytes(plaintext, PASSPHRASE)
        header_size = private_container._V2_HEADER.size
        for offset in (
            header_size,
            header_size + private_container._SALT_LENGTH,
            header_size + private_container._SALT_LENGTH + private_container._NONCE_LENGTH,
            len(artifact) - 1,
        ):
            tampered = bytearray(artifact)
            tampered[offset] ^= 1
            with (
                self.subTest(offset=offset),
                self.assertRaisesRegex(PrivateContainerError, "authentication failed"),
            ):
                unprotect_private_bytes(bytes(tampered), PASSPHRASE)

        # Keep the structural length internally consistent while changing the
        # authenticated payload-length field and ciphertext together.
        shortened = bytearray(artifact)
        struct.pack_into(">Q", shortened, 21, len(plaintext) - 1)
        del shortened[header_size + 16 + 12 + len(plaintext) - 1]
        with self.assertRaisesRegex(PrivateContainerError, "authentication failed"):
            unprotect_private_bytes(bytes(shortened), PASSPHRASE)

    def test_parser_rejects_nonbytes_truncation_and_oversized_input(self) -> None:
        for value in (bytearray(b"x"), b"CPAP", b"x" * 10):
            with self.subTest(value_type=type(value).__name__):
                with self.assertRaisesRegex(
                    PrivateContainerError, "must be bytes|header is truncated|format"
                ):
                    unprotect_private_bytes(value, PASSPHRASE)  # type: ignore[arg-type]
        truncated_v1 = INDEPENDENT_CONTAINER[
            : private_container._V1_HEADER.size
            + private_container._SALT_LENGTH
            + private_container._NONCE_LENGTH
            + private_container._TAG_LENGTH
            - 1
        ]
        with self.assertRaisesRegex(PrivateContainerError, "header is truncated"):
            unprotect_private_bytes(truncated_v1, PASSPHRASE)
        with patch.object(private_container, "MAX_CONTAINER_BYTES", 1):
            with self.assertRaisesRegex(PrivateContainerError, "safety size"):
                unprotect_private_bytes(b"x" * 2, PASSPHRASE)

    def test_parser_rejects_unknown_format_parameters_and_lengths(self) -> None:
        artifact = protect_private_bytes(b"synthetic", PASSPHRASE)

        unknown = bytearray(artifact)
        unknown[0] ^= 1
        with patch.object(private_container, "_require_crypto") as crypto:
            with self.assertRaisesRegex(PrivateContainerError, "format is not recognized"):
                unprotect_private_bytes(bytes(unknown), PASSPHRASE)
            crypto.assert_not_called()

        malformed = bytearray(artifact)
        malformed[4] = 3
        with patch.object(private_container, "_require_crypto") as crypto:
            with self.assertRaisesRegex(PrivateContainerError, "version is not supported"):
                unprotect_private_bytes(bytes(malformed), PASSPHRASE)
            crypto.assert_not_called()

        for offset in (5, 6):
            malformed = bytearray(artifact)
            malformed[offset] = 2
            with (
                self.subTest(offset=offset),
                patch.object(private_container, "_require_crypto") as crypto,
            ):
                with self.assertRaisesRegex(PrivateContainerError, "algorithm identifiers"):
                    unprotect_private_bytes(bytes(malformed), PASSPHRASE)
                crypto.assert_not_called()

        for offset in (7, 8):
            malformed = bytearray(artifact)
            malformed[offset] = 8
            with (
                self.subTest(offset=offset),
                patch.object(private_container, "_require_crypto") as crypto,
            ):
                with self.assertRaisesRegex(PrivateContainerError, "parameters are not supported"):
                    unprotect_private_bytes(bytes(malformed), PASSPHRASE)
                crypto.assert_not_called()

        for offset, value in (
            (9, 2**15),
            (9, 2**18),
            (13, 7),
            (13, 9),
            (17, 0),
            (17, 2),
        ):
            malformed = bytearray(artifact)
            struct.pack_into(">I", malformed, offset, value)
            with (
                self.subTest(offset=offset, value=value),
                patch.object(private_container, "_require_crypto") as crypto,
            ):
                with self.assertRaisesRegex(PrivateContainerError, "scrypt parameters"):
                    unprotect_private_bytes(bytes(malformed), PASSPHRASE)
                crypto.assert_not_called()

        for payload_length in (0, private_container.MAX_PRIVATE_BYTES + 1):
            malformed = bytearray(artifact)
            struct.pack_into(">Q", malformed, 21, payload_length)
            with (
                self.subTest(payload_length=payload_length),
                patch.object(private_container, "_require_crypto") as crypto,
            ):
                with self.assertRaisesRegex(PrivateContainerError, "payload size is invalid"):
                    unprotect_private_bytes(bytes(malformed), PASSPHRASE)
                crypto.assert_not_called()

        with self.assertRaisesRegex(PrivateContainerError, "length is invalid"):
            unprotect_private_bytes(artifact + b"trailing", PASSPHRASE)

    def test_parser_accepts_only_a_complete_container_and_crypto_failure_is_controlled(
        self,
    ) -> None:
        artifact = protect_private_bytes(b"synthetic", PASSPHRASE)
        for malformed in (artifact[: private_container._V2_HEADER.size - 1], artifact[:-1]):
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

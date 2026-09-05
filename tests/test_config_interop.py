# SPDX-License-Identifier: 0BSD
"""Synthetic external-reference regressions; never actual router exports."""

from __future__ import annotations

import base64
import hashlib
import struct
import unittest
import zlib
from contextlib import redirect_stderr, redirect_stdout
from io import StringIO
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

import cpe_access_atlas.config as config
from cpe_access_atlas.cli import main
from cpe_access_atlas.config import (
    ConfigError,
    _derive_h3600p_keys,
    _sha256_raw_digest,
    buggy_sha256,
    decode_config,
    inspect_config,
)

# See docs/config-cryptography.md for source/provenance and exact limitations.
# The reference script independently decoded both fixtures to b"<DB/>".
_SINGLE = (
    "AQIDBAAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    "AAAAAAAAAVQAAAGAAAAAAK19VqZbKCmgCqCIN744Mjko74dK9oE8jWLnTdzw569ITCbzAJ+"
    "XegcKkcbwKyOYwRTZtgvo1lYbowMs6VgAANXtzRij35RF4UU+zUWcC+hhA4F66jfD0O25"
    "SbXjEZFhu"
)
_MULTIPLE = (
    "AQIDBAAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    "AAAAAAAAAQAAAAEAAAAABK19VqZbKCmgCqCIN744Mjko74dK9oE8jWLnTdzw569ITCbzAJ+"
    "XegcKkcbwKyOYwRTZtgvo1lYbowMs6VgAANQAAABUAAAAgAAAAAJXcsHNc7rRnBdaucRw5"
    "MuNOhNa+egSlihz1e1OLDwop"
)
_COORDINATES = {"device_key": "a" * 32, "serial": "ZTE12345678", "mac": "00:11:22:33:44:55"}
# zcu's pinned compression implementation produced this four-chunk fixture;
# both zcu and the unchanged H3600P reference independently decoded it.
_COMPRESSED = (
    "AQIDBAAAAAAAAADKAAAAngAAAECe+axztdvLwQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    "AAAAAAAAAAQAAAABoAAABieNqzcXGys3FJLEm0S0xKTklNI5UEAO+AF/IAAABAAAAAEQAA"
    "AH942ktMSk5JTUskmwQAKB8Y3QAAAEAAAAATAAAAnnjaS01LTEpOSSWTtNEHACioGIkAAA"
    "AKAAAAEgAAAAB42nNJLEm0s9F3cbIDABFMAug="
)


class ConfigInteropTests(unittest.TestCase):
    def test_reference_compressed_chunks_and_header_conventions(self) -> None:
        fixture = base64.b64decode(_COMPRESSED, validate=True)
        expected = b"<DB><Data>" + b"abcdef" * 30 + b"</Data></DB>"
        self.assertEqual((len(fixture), len(expected)), (188, 202))
        self.assertEqual(struct.unpack_from(">3I", fixture, 8), (202, 158, 64))
        for summed_length in (False, True):
            for boolean_continuation in (False, True):
                with self.subTest(summed=summed_length, boolean=boolean_continuation):
                    raw = bytearray(fixture)
                    if summed_length:
                        struct.pack_into(">I", raw, 12, 80)
                        struct.pack_into(">I", raw, 24, zlib.crc32(raw[:24]))
                    if boolean_continuation:
                        for offset in (68, 106, 135):
                            struct.pack_into(">I", raw, offset, 1)
                    for data in (bytes(raw), base64.b64encode(raw)):
                        self.assertEqual(decode_config(data).xml, expected)

    def test_reference_compressed_fixture_still_rejects_corruption(self) -> None:
        fixture = base64.b64decode(_COMPRESSED, validate=True)
        cases = (
            (16, 63, "exceeds its capacity"),
            (16, 0, "exceeds its capacity"),
            (16, 8 * 1024 * 1024 + 1, "capacity exceeds the safety size limit"),
            (12, 157, "compressed length does not match"),
            (12, 79, "compressed length does not match"),
            (68, 0xFFFFFFFF, "continuation flag"),
            (68, 0, "trailing data"),
            (166, 188, "continuation chunk header is missing"),
            (20, 0, "checksum is invalid"),
        )
        for offset, value, message in cases:
            with self.subTest(offset=offset, value=value):
                raw = bytearray(fixture)
                struct.pack_into(">I", raw, offset, value)
                struct.pack_into(">I", raw, 24, zlib.crc32(raw[:24]))
                with self.assertRaisesRegex(ConfigError, message):
                    decode_config(bytes(raw))
        with self.assertRaisesRegex(ConfigError, "chunk is truncated"):
            decode_config(fixture[:-1])

    def test_compressed_budget_is_independent_of_header_convention(self) -> None:
        raw = bytearray(base64.b64decode(_COMPRESSED, validate=True))
        # A misleading, small metadata field must not disable the cumulative
        # compressed-byte limit while its two supported meanings are checked.
        struct.pack_into(">I", raw, 12, 60)
        struct.pack_into(">I", raw, 24, zlib.crc32(raw[:24]))
        real_decompressobj = zlib.decompressobj
        with (
            patch.object(config, "_MAX_COMPRESSED_BYTES", 79),
            patch.object(config.zlib, "decompressobj", wraps=real_decompressobj) as decompress,
        ):
            with self.assertRaisesRegex(ConfigError, "chunk total exceeds the safety size limit"):
                decode_config(bytes(raw))
        self.assertEqual(decompress.call_count, 3)

    def test_chunk_capacity_bounds_actual_expansion_not_only_declared_length(self) -> None:
        raw = bytearray(base64.b64decode(_COMPRESSED, validate=True))
        struct.pack_into(">I", raw, 16, 63)
        struct.pack_into(">I", raw, 24, zlib.crc32(raw[:24]))
        struct.pack_into(">I", raw, 60, 63)
        with self.assertRaisesRegex(ConfigError, "data exceeds the safety size limit"):
            decode_config(bytes(raw))

    def test_raw_compression_function_matches_standard_sha256(self) -> None:
        # Standard padding makes hashlib an independent oracle for the raw
        # compression routine, including constants used on vendor-bug paths.
        for length in (0, 1, 55, 56, 57, 63, 64, 65, 119, 120, 121, 127, 128, 191, 1024):
            with self.subTest(length=length):
                message = bytes(index % 256 for index in range(length))
                padding = b"\x80" + bytes((55 - length) % 64) + struct.pack(">Q", length * 8)
                self.assertEqual(
                    _sha256_raw_digest(message + padding), hashlib.sha256(message).digest()
                )

    def test_reference_digest_vectors_across_block_boundaries(self) -> None:
        vectors = {
            63: "0658f910d654bf9f946584e86b4b20115df120dee433be04dcbc9064dee19c58",
            120: "ebf1017d998aa27f4f7b3a7685215c05c7f6a39f75812cb108ae96d3fe7f654a",
            121: "f9fb2a9d28c419550c2f0f65814e24af0bfe5984f1c6ddd542b2edccbe95970f",
        }
        for length, expected in vectors.items():
            with self.subTest(length=length):
                self.assertEqual(buggy_sha256(b"a" * length).hex(), expected)

    def test_reference_device_derivation(self) -> None:
        key, iv = _derive_h3600p_keys(**_COORDINATES)
        self.assertEqual(
            key.hex(), "b532767c671771ddc30e8a147297e66afdab530dc12a13d34054e5f9a9eaa61a"
        )
        self.assertEqual(iv.hex(), "daecfbdc061146786cae668f57b13ffa")

    def test_reference_encrypted_fixtures_with_each_transport_wrapper(self) -> None:
        signature = b"H3600P V9.0"
        prefix = struct.pack(">3I", 0x04030201, 0, len(signature)) + signature
        for fixture in (_SINGLE, _MULTIPLE):
            for wrapped in (False, True):
                for encoded in (False, True):
                    with self.subTest(
                        multichunk=fixture == _MULTIPLE, wrapped=wrapped, encoded=encoded
                    ):
                        data = (prefix if wrapped else b"") + base64.b64decode(
                            fixture, validate=True
                        )
                        if encoded:
                            data = base64.b64encode(data)
                        metadata = inspect_config(data)
                        decoded = decode_config(data, **_COORDINATES)
                        self.assertEqual(decoded.xml, b"<DB/>")
                        self.assertEqual(decoded.metadata, metadata)
                        self.assertEqual(metadata.signature, "H3600P V9.0" if wrapped else None)
                        self.assertEqual(metadata.payload_type, 4)
                        self.assertTrue(metadata.encrypted)
                        self.assertEqual(metadata.base64_wrapped, encoded)

    def test_raw_encrypted_header_and_required_credentials(self) -> None:
        data = base64.b64decode(_SINGLE, validate=True)
        for length in (8, 59):
            with self.subTest(length=length), self.assertRaisesRegex(ConfigError, "payload header"):
                decode_config(data[:length], **_COORDINATES)
        with self.assertRaisesRegex(ConfigError, "requires the device passphrase"):
            decode_config(data)

    def test_defective_prerelease_ciphertext_is_not_silently_accepted(self) -> None:
        # Generated by the provenance-verified, separately installed v0.4.0a1
        # wheel using <DB/> and the same synthetic coordinates as the fixtures.
        legacy = (
            "BAMCAQAAAAAAAAALSDM2MDBQIFY5LjABAgMEAAAABAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABVAAAAYAAAAADbJ999JGyRyQrgeaMY"
            "OEuCuwq8Pvi0nfgoUXX7O3+HEn4GbTQlPTXV4Ask7oSOEiyDeMjxHupTs9VWGRAnL13"
            "wZZG0x6YiGtM4i0vo1OlikauhMY9XcqJ2+t8/eWpYx28="
        )
        data = base64.b64decode(legacy, validate=True)
        self.assertEqual(len(data), 191)
        self.assertEqual(
            hashlib.sha256(data).hexdigest(),
            "0fa25650371b9c43fd1487640ee10aa857a1dc5756b50cf6da30cc5a689b8a4b",
        )
        self.assertTrue(inspect_config(data).encrypted)
        with self.assertRaises(ConfigError):
            decode_config(data, **_COORDINATES)

    def test_cli_preserves_encryption_for_raw_reference_baseline(self) -> None:
        raw = base64.b64decode(_MULTIPLE, validate=True)
        with TemporaryDirectory() as directory:
            source = Path(directory) / "synthetic-input.bin"
            output = Path(directory) / "synthetic-output.bin"
            source.write_bytes(raw)
            stdout, stderr = StringIO(), StringIO()
            with (
                patch(
                    "cpe_access_atlas.cli.getpass.getpass", side_effect=["DummyPass123", "a" * 32]
                ),
                redirect_stdout(stdout),
                redirect_stderr(stderr),
            ):
                code = main(
                    [
                        "config-generate",
                        "--isp",
                        "turk-telekom",
                        "--model",
                        "H3600P",
                        "--hardware-revision",
                        "V9.0",
                        "--firmware",
                        "H3600P V9.0 TTN.10_260210",
                        "--input-config",
                        str(source),
                        "--output",
                        str(output),
                        "--serial",
                        _COORDINATES["serial"],
                        "--mac",
                        _COORDINATES["mac"],
                        "--i-own-or-administer-this-device",
                    ]
                )
            self.assertEqual((code, stderr.getvalue()), (0, ""))
            self.assertEqual(source.read_bytes(), raw)
            decoded = decode_config(output.read_bytes(), **_COORDINATES)
            self.assertTrue(decoded.metadata.encrypted)
            self.assertIn(b'val="DummyPass123"', decoded.xml)
            self.assertIn("not verified", stdout.getvalue())
            for value in ("DummyPass123", *_COORDINATES.values()):
                self.assertNotIn(value, stdout.getvalue() + stderr.getvalue())


if __name__ == "__main__":
    unittest.main()

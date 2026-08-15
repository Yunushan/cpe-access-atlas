# SPDX-License-Identifier: 0BSD
from __future__ import annotations

import hashlib
import struct
import unittest
import zlib
from io import BytesIO
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch
from xml.etree import ElementTree as ET

from cpe_access_atlas.config import (
    ConfigError,
    _derive_h3600p_keys,
    _read_chunks,
    _sha256_raw_digest,
    buggy_sha256,
    decode_config,
    default_root_xml,
    encode_config,
    inspect_config,
    patch_root_ssh,
    read_private_config,
)

KEY = "a" * 32
SERIAL = "ZTE12345678"
MAC = "00:11:22:33:44:55"


class ConfigTests(unittest.TestCase):
    def test_buggy_sha256_compatibility_vectors(self) -> None:
        self.assertEqual(
            buggy_sha256(b"a" * 55),
            hashlib.sha256(b"a" * 55).digest(),
        )
        self.assertEqual(
            buggy_sha256(b"a" * 56).hex(),
            "aa114fea373c70a351c18d9d5f0e3336ed78e99a92e682cacd31ca7d896fb185",
        )
        self.assertEqual(
            buggy_sha256(b"a" * 57).hex(),
            "038be71d33942b35fd2ca81759444e05800fe7a03bd315f8f156d88a4ad18c2f",
        )
        with self.assertRaises(ConfigError):
            buggy_sha256("not-bytes")  # type: ignore[arg-type]

    def test_unencrypted_base64_round_trip_and_metadata(self) -> None:
        xml = default_root_xml("DummyPass123")
        artifact = encode_config(xml)
        metadata = inspect_config(artifact)
        self.assertEqual(metadata.payload_type, 0)
        self.assertTrue(metadata.base64_wrapped)
        self.assertFalse(metadata.encrypted)
        self.assertEqual(decode_config(artifact).xml, xml)
        self.assertEqual(decode_config(b"\n" + artifact + b"\n").xml, xml)

    def test_unencrypted_raw_round_trip(self) -> None:
        xml = default_root_xml("DummyPass123")
        artifact = encode_config(xml, base64_wrap=False)
        metadata = inspect_config(artifact)
        self.assertFalse(metadata.base64_wrapped)
        self.assertEqual(decode_config(artifact).xml, xml)

    def test_encrypted_round_trip_and_metadata(self) -> None:
        xml = default_root_xml("DummyPass123")
        artifact = encode_config(
            xml,
            encrypted=True,
            base64_wrap=False,
            device_key=KEY,
            serial=SERIAL,
            mac=MAC,
        )
        metadata = inspect_config(artifact)
        self.assertEqual(metadata.signature, "H3600P V9.0")
        self.assertEqual(metadata.payload_type, 4)
        self.assertTrue(metadata.encrypted)
        self.assertFalse(metadata.base64_wrapped)
        decoded = decode_config(
            artifact,
            device_key=KEY,
            serial=SERIAL,
            mac=MAC,
        )
        self.assertEqual(decoded.xml, xml)
        with self.assertRaisesRegex(ConfigError, "requires"):
            decode_config(artifact)
        with self.assertRaises(ConfigError):
            decode_config(artifact, device_key="b" * 32, serial=SERIAL, mac=MAC)

    def test_internal_digest_and_base64_rejection_paths(self) -> None:
        with self.assertRaises(ConfigError):
            _sha256_raw_digest(b"not-a-block")
        with self.assertRaises(ConfigError):
            decode_config(b"====")
        with self.assertRaises(ConfigError):
            decode_config(b"YWJj")
        self.assertEqual(
            _read_chunks(BytesIO(struct.pack(">3I", 16, 16, 0) + b"x" * 16)),
            b"x" * 16,
        )

    def test_compressed_container_validation_paths(self) -> None:
        xml = default_root_xml("DummyPass123")
        raw = bytes(encode_config(xml, base64_wrap=False))

        with self.assertRaisesRegex(ConfigError, "recognized compressed"):
            decode_config(struct.pack(">2I", 0x01020304, 1) + b"\x00" * 52)
        with self.assertRaisesRegex(ConfigError, "header is truncated"):
            decode_config(struct.pack(">I", 0x01020304))
        with self.assertRaisesRegex(ConfigError, "no data chunks"):
            decode_config(raw[:60])
        with self.assertRaisesRegex(ConfigError, "chunk header is truncated"):
            decode_config(raw[:61])
        with self.assertRaisesRegex(ConfigError, "chunk is truncated"):
            decode_config(raw[:72])

        invalid_more = bytearray(raw)
        struct.pack_into(">I", invalid_more, 68, 2)
        with self.assertRaisesRegex(ConfigError, "continuation flag"):
            decode_config(bytes(invalid_more))

        invalid_zlib = bytearray(raw)
        invalid_zlib[72] ^= 0xFF
        with self.assertRaisesRegex(ConfigError, "compressed configuration data"):
            decode_config(bytes(invalid_zlib))

        invalid_plain_length = bytearray(raw)
        struct.pack_into(">I", invalid_plain_length, 60, len(xml) + 1)
        with self.assertRaisesRegex(ConfigError, "chunk length"):
            decode_config(bytes(invalid_plain_length))

        invalid_header_lengths = bytearray(raw)
        struct.pack_into(">I", invalid_header_lengths, 16, len(xml) + 1)
        with self.assertRaisesRegex(ConfigError, "fields disagree"):
            decode_config(bytes(invalid_header_lengths))

        invalid_output_length = bytearray(raw)
        struct.pack_into(">I", invalid_output_length, 8, len(xml) + 1)
        struct.pack_into(">I", invalid_output_length, 16, len(xml) + 1)
        struct.pack_into(">I", invalid_output_length, 24, zlib.crc32(invalid_output_length[:24]))
        with self.assertRaisesRegex(ConfigError, "does not match its header"):
            decode_config(bytes(invalid_output_length))

        invalid_compressed_length = bytearray(raw)
        struct.pack_into(">I", invalid_compressed_length, 12, len(raw) + 1)
        struct.pack_into(
            ">I", invalid_compressed_length, 24, zlib.crc32(invalid_compressed_length[:24])
        )
        with self.assertRaisesRegex(ConfigError, "compressed length"):
            decode_config(bytes(invalid_compressed_length))

        invalid_crc = bytearray(raw)
        struct.pack_into(">I", invalid_crc, 20, 0)
        struct.pack_into(">I", invalid_crc, 24, zlib.crc32(invalid_crc[:24]))
        with self.assertRaisesRegex(ConfigError, "checksum"):
            decode_config(bytes(invalid_crc))

        first = xml[: len(xml) // 2]
        second = xml[len(xml) // 2 :]
        first_compressed = zlib.compress(first, level=9)
        second_compressed = zlib.compress(second, level=9)
        compressed = first_compressed + second_compressed
        header_without_crc = struct.pack(
            ">6I",
            0x01020304,
            0,
            len(xml),
            len(compressed),
            len(xml),
            zlib.crc32(compressed),
        )
        two_chunk = (
            header_without_crc
            + struct.pack(">I", zlib.crc32(header_without_crc))
            + b"\x00" * 32
            + struct.pack(">3I", len(first), len(first_compressed), 1)
            + first_compressed
            + struct.pack(">3I", len(second), len(second_compressed), 0)
            + second_compressed
        )
        self.assertEqual(decode_config(two_chunk).xml, xml)

    def test_outer_container_validation_paths(self) -> None:
        xml = default_root_xml("DummyPass123")
        encrypted = bytes(
            encode_config(
                xml,
                encrypted=True,
                base64_wrap=False,
                device_key=KEY,
                serial=SERIAL,
                mac=MAC,
            )
        )
        chunk_offset = 12 + len("H3600P V9.0") + 60

        with self.assertRaisesRegex(ConfigError, "signature header"):
            decode_config(struct.pack(">I", 0x04030201))
        with self.assertRaisesRegex(ConfigError, "signature is truncated"):
            decode_config(struct.pack(">3I", 0x04030201, 0, 4) + b"ab")
        with self.assertRaisesRegex(ConfigError, "signature is not ASCII"):
            decode_config(struct.pack(">3I", 0x04030201, 0, 1) + b"\xff")
        signature = b"H3600P V9.0"
        with self.assertRaisesRegex(ConfigError, "payload header"):
            decode_config(struct.pack(">3I", 0x04030201, 0, len(signature)) + signature)
        with self.assertRaisesRegex(ConfigError, "payload magic"):
            decode_config(
                struct.pack(">3I", 0x04030201, 0, len(signature)) + signature + b"\x00" * 60
            )
        with self.assertRaisesRegex(ConfigError, "unsupported encrypted"):
            decode_config(
                struct.pack(">3I", 0x04030201, 0, len(signature))
                + signature
                + struct.pack(">15I", 0x01020304, 3, *([0] * 13))
            )

        short_chunks = encrypted[:chunk_offset]
        with self.assertRaisesRegex(ConfigError, "chunk header"):
            decode_config(short_chunks, device_key=KEY, serial=SERIAL, mac=MAC)
        invalid_encrypted_length = bytearray(encrypted)
        struct.pack_into(">I", invalid_encrypted_length, chunk_offset + 4, 0)
        with self.assertRaisesRegex(ConfigError, "encrypted length"):
            decode_config(
                bytes(invalid_encrypted_length),
                device_key=KEY,
                serial=SERIAL,
                mac=MAC,
            )
        invalid_contents = encrypted[:-1]
        with self.assertRaisesRegex(ConfigError, "chunk contents"):
            decode_config(invalid_contents, device_key=KEY, serial=SERIAL, mac=MAC)
        invalid_plain_length = bytearray(encrypted)
        encrypted_chunk_length = len(encrypted) - chunk_offset - 12
        struct.pack_into(">I", invalid_plain_length, chunk_offset, encrypted_chunk_length + 1)
        with self.assertRaisesRegex(ConfigError, "plaintext length"):
            decode_config(
                bytes(invalid_plain_length),
                device_key=KEY,
                serial=SERIAL,
                mac=MAC,
            )
        invalid_more = bytearray(encrypted)
        struct.pack_into(">I", invalid_more, chunk_offset + 8, 1)
        with self.assertRaisesRegex(ConfigError, "chunk header"):
            decode_config(bytes(invalid_more), device_key=KEY, serial=SERIAL, mac=MAC)
        invalid_encrypted_more = bytearray(encrypted)
        struct.pack_into(">I", invalid_encrypted_more, chunk_offset + 8, 2)
        with self.assertRaisesRegex(ConfigError, "continuation flag"):
            decode_config(
                bytes(invalid_encrypted_more),
                device_key=KEY,
                serial=SERIAL,
                mac=MAC,
            )

    def test_inspect_signature_validation_paths(self) -> None:
        magic = 0x04030201
        with self.assertRaisesRegex(ConfigError, "signature header"):
            inspect_config(struct.pack(">I", magic))
        with self.assertRaisesRegex(ConfigError, "signature is not ASCII"):
            inspect_config(struct.pack(">3I", magic, 0, 1) + b"\xff")
        signature = b"H3600P V9.0"
        with self.assertRaisesRegex(ConfigError, "payload header"):
            inspect_config(struct.pack(">3I", magic, 0, len(signature)) + signature)
        with self.assertRaisesRegex(ConfigError, "payload magic"):
            inspect_config(
                struct.pack(">3I", magic, 0, len(signature)) + signature + struct.pack(">2I", 0, 4)
            )

    def test_device_input_types_are_rejected(self) -> None:
        with self.assertRaises(ConfigError):
            _derive_h3600p_keys(KEY, 123, MAC)  # type: ignore[arg-type]
        with self.assertRaises(ConfigError):
            _derive_h3600p_keys(KEY, SERIAL, 123)  # type: ignore[arg-type]
        with self.assertRaises(ConfigError):
            _derive_h3600p_keys("ä" * 32, SERIAL, MAC)
        with self.assertRaises(ConfigError):
            _read_chunks(BytesIO(struct.pack(">3I", 1, 16 * 1024 * 1024 + 16, 0)))
        with self.assertRaisesRegex(ConfigError, "plaintext length"):
            _read_chunks(BytesIO(struct.pack(">3I", 16 * 1024 * 1024 + 1, 16, 0) + b"x" * 16))

    def test_input_and_size_limits_are_rejected(self) -> None:
        with self.assertRaisesRegex(ConfigError, "must be bytes"):
            decode_config("not-bytes")  # type: ignore[arg-type]
        with self.assertRaisesRegex(ConfigError, "empty"):
            decode_config(b"")
        with self.assertRaisesRegex(ConfigError, "safety size limit"):
            decode_config(b"x" * (16 * 1024 * 1024 + 1))

        oversized_xml = b"x" * (8 * 1024 * 1024 + 1)
        with self.assertRaisesRegex(ConfigError, "safety size limit"):
            encode_config(oversized_xml)
        with self.assertRaisesRegex(ConfigError, "safety size limit"):
            patch_root_ssh(oversized_xml, "DummyPass123")

        oversized_header = (
            struct.pack(
                ">7I",
                0x01020304,
                0,
                8 * 1024 * 1024 + 1,
                1,
                8 * 1024 * 1024 + 1,
                0,
                0,
            )
            + b"\x00" * 32
        )
        with self.assertRaisesRegex(ConfigError, "safety size limit"):
            decode_config(oversized_header)

        def compressed_container(
            expected_length: int,
            expected_compressed_length: int,
            plain_length: int,
            compressed: bytes,
            chunk_compressed_length: int | None = None,
        ) -> bytes:
            header_without_crc = struct.pack(
                ">6I",
                0x01020304,
                0,
                expected_length,
                expected_compressed_length,
                expected_length,
                zlib.crc32(compressed),
            )
            header = (
                header_without_crc
                + struct.pack(">I", zlib.crc32(header_without_crc))
                + b"\x00" * 32
            )
            return (
                header
                + struct.pack(
                    ">3I",
                    plain_length,
                    len(compressed) if chunk_compressed_length is None else chunk_compressed_length,
                    0,
                )
                + compressed
            )

        with self.assertRaisesRegex(ConfigError, "safety size limit"):
            decode_config(compressed_container(1, 16 * 1024 * 1024 + 1, 1, b"x"))
        with self.assertRaisesRegex(ConfigError, "safety size limit"):
            decode_config(
                compressed_container(
                    1,
                    1,
                    1,
                    b"x",
                    chunk_compressed_length=16 * 1024 * 1024 + 1,
                )
            )
        with self.assertRaisesRegex(ConfigError, "safety size limit"):
            decode_config(compressed_container(1, 1, 16 * 1024 * 1024 + 1, b"x"))

        expanded = zlib.compress(b"x" * (8 * 1024 * 1024 + 1))
        with self.assertRaisesRegex(ConfigError, "safety size limit"):
            decode_config(compressed_container(1, len(expanded), 1, expanded))
        truncated = zlib.compress(b"tiny")[:-1]
        with self.assertRaisesRegex(ConfigError, "data is invalid"):
            decode_config(compressed_container(4, len(truncated), 4, truncated))

    def test_patch_updates_existing_ssh_fields(self) -> None:
        xml = b"""<DB><Tbl name="SSHCfg" RowCount="1"><Row No="0">
        <DM name="SSH_Enable" val="0"/><DM name="SSH_UserName" val="old"/>
        <DM name="SSH_PassWord" val="oldpass"/><DM name="SSH_ProcType" val="7"/>
        <DM name="SSH_Level" val="0"/></Row></Tbl></DB>"""
        result = patch_root_ssh(xml, "NewPass123", "root")
        fields = {
            item.attrib["name"]: item.attrib["val"]
            for item in ET.fromstring(result).find("Tbl").find("Row").findall("DM")
        }
        self.assertEqual(
            {name: fields[name] for name in fields if name.startswith("SSH_")},
            {
                "SSH_Enable": "1",
                "SSH_UserName": "root",
                "SSH_PassWord": "NewPass123",
                "SSH_ProcType": "0",
                "SSH_Level": "1",
            },
        )

    def test_patch_creates_missing_table_and_row(self) -> None:
        result = patch_root_ssh(b"<DB/>", "NewPass123")
        root = ET.fromstring(result)
        table = root.find("Tbl")
        self.assertIsNotNone(table)
        self.assertEqual(table.attrib["name"], "SSHCfg")
        self.assertIsNotNone(table.find("Row"))

    def test_patch_creates_row_in_existing_table(self) -> None:
        result = patch_root_ssh(b'<DB><Tbl name="SSHCfg"/></DB>', "NewPass123")
        row = ET.fromstring(result).find("Tbl/Row")
        self.assertIsNotNone(row)
        self.assertEqual(row.attrib["No"], "0")

    def test_patch_rejects_unsafe_or_invalid_xml(self) -> None:
        invalid_inputs = [
            (b"<DB/>", "short"),
            (b"<DB/>", "NewPass123"),
        ]
        with self.assertRaises(ConfigError):
            patch_root_ssh(invalid_inputs[0][0], invalid_inputs[0][1])
        with self.assertRaises(ConfigError):
            patch_root_ssh(b"<DB/>", "NewPass123", "")
        with self.assertRaises(ConfigError):
            patch_root_ssh(b"<DB/>", "NewPass123", "x" * 65)
        with self.assertRaises(ConfigError):
            patch_root_ssh(
                b"<!DOCTYPE DB [<!ENTITY x SYSTEM 'file:///secret'>]><DB/>",
                "NewPass123",
            )
        with self.assertRaises(ConfigError):
            patch_root_ssh(b"<DB>", "NewPass123")
        with self.assertRaises(ConfigError):
            patch_root_ssh(b"<NotDB/>", "NewPass123")
        with self.assertRaises(ConfigError):
            patch_root_ssh(b"<DB/>", "NewPass\n123")
        with self.assertRaises(ConfigError):
            patch_root_ssh(b"<DB/>", "NewPass123", "root\n")

    def test_encryption_and_signature_arguments_are_validated(self) -> None:
        xml = default_root_xml("DummyPass123")
        with self.assertRaises(ConfigError):
            encode_config(b"")
        with self.assertRaises(ConfigError):
            encode_config("not-bytes")  # type: ignore[arg-type]
        with self.assertRaisesRegex(ConfigError, "encrypted output requires"):
            encode_config(xml, encrypted=True)
        with self.assertRaisesRegex(ConfigError, "exactly 32"):
            encode_config(xml, encrypted=True, device_key="short", serial=SERIAL, mac=MAC)
        with self.assertRaises(ConfigError):
            encode_config(xml, encrypted=True, device_key=KEY, serial="bad", mac=MAC)
        with self.assertRaises(ConfigError):
            encode_config(xml, encrypted=True, device_key=KEY, serial=SERIAL, mac="bad")
        with self.assertRaises(ConfigError):
            encode_config(xml, signature="")
        with self.assertRaises(ConfigError):
            encode_config(xml, signature="H3600P é")
        with patch("cpe_access_atlas.config.AES", None):
            with self.assertRaisesRegex(ConfigError, "AES support"):
                encode_config(
                    xml,
                    encrypted=True,
                    device_key=KEY,
                    serial=SERIAL,
                    mac=MAC,
                )

    def test_malformed_containers_are_rejected(self) -> None:
        xml = default_root_xml("DummyPass123")
        artifact = bytearray(encode_config(xml, base64_wrap=False))
        artifact[24] ^= 1
        with self.assertRaisesRegex(ConfigError, "checksum"):
            decode_config(bytes(artifact))
        with self.assertRaises(ConfigError):
            decode_config(b"not-a-config")
        with self.assertRaises(ConfigError):
            inspect_config(b"not-a-config")

    def test_private_artifact_reader(self) -> None:
        with TemporaryDirectory() as directory:
            path = Path(directory) / "config.bin"
            path.write_bytes(encode_config(default_root_xml("DummyPass123")))
            self.assertTrue(read_private_config(path))
            empty = Path(directory) / "empty.bin"
            empty.write_bytes(b"")
            with self.assertRaises(ConfigError):
                read_private_config(empty)
            with self.assertRaises(ConfigError):
                read_private_config(Path(directory) / "missing.bin")
            oversized = Path(directory) / "oversized.bin"
            oversized.write_bytes(b"x" * (16 * 1024 * 1024 + 1))
            with self.assertRaisesRegex(ConfigError, "safety size limit"):
                read_private_config(oversized)


if __name__ == "__main__":
    unittest.main()

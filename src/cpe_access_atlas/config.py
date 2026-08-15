# SPDX-License-Identifier: 0BSD
"""Offline H3600P configuration inspection and artifact generation.

This module never connects to a router.  It can decode a private H3600P
configuration, patch only the SSH privilege fields, and emit the compressed
configuration container used by the public H3600P research.  The exact
Turk Telekom build in the catalog remains experimental: producing an artifact
does not prove that the device will accept it or that recovery is available.
"""

from __future__ import annotations

import base64
import binascii
import re
import struct
import zlib
from dataclasses import dataclass
from io import BytesIO
from pathlib import Path
from typing import BinaryIO, Protocol
from xml.etree import ElementTree as ET


class _CipherContext(Protocol):
    """Shape of an AES-CBC cipher context used for both directions."""

    def decrypt(self, data: bytes) -> bytes: ...

    def encrypt(self, data: bytes) -> bytes: ...


class _CipherModule(Protocol):
    """Shape of the subset of `Crypto.Cipher.AES` this module relies on."""

    MODE_CBC: int

    def new(self, key: bytes, mode: int, iv: bytes) -> _CipherContext: ...


AES: _CipherModule | None
try:
    from Crypto.Cipher import AES  # type: ignore[assignment]
except ImportError:  # pragma: no cover - exercised by installation diagnostics
    AES = None


class ConfigError(ValueError):
    """Raised when a configuration artifact cannot be safely processed."""


PAYLOAD_MAGIC = 0x01020304
SIGNATURE_MAGIC = 0x04030201
H3600P_SIGNATURE = "H3600P V9.0"
_HEADER_SIZE = 0x3C
_CHUNK_HEADER_SIZE = 12
_SERIAL_PATTERN = re.compile(r"^ZTE[A-Z0-9]{8,32}$")
_MAC_PATTERN = re.compile(r"^[0-9a-f]{2}(?::[0-9a-f]{2}){5}$")
_BASE64_PATTERN = re.compile(rb"^[A-Za-z0-9+/=]+$")
_MAX_ARTIFACT_BYTES = 16 * 1024 * 1024
_MAX_XML_BYTES = 8 * 1024 * 1024
_MAX_COMPRESSED_BYTES = 16 * 1024 * 1024

_ROUND_CONSTANTS = (
    0x428A2F98,
    0x71374491,
    0xB5C0FBCF,
    0xE9B5DBA5,
    0x3956C25B,
    0x59F111F1,
    0x923F82A4,
    0xAB1C5ED5,
    0xD807AA98,
    0x12835B01,
    0x243185BE,
    0x550C7DC3,
    0x72BE5D74,
    0x80DEB1FE,
    0x9BDC06A7,
    0xC19BF174,
    0xE49B69C1,
    0xEFBE4786,
    0x0FC19DC6,
    0x240CA1CC,
    0x2DE92C6F,
    0x4A7484AA,
    0x5CB0A9DC,
    0x76F988DA,
    0x983E5152,
    0xA831C66D,
    0xB00327C8,
    0xBF597FC7,
    0xC6E00BF3,
    0xD5A79147,
    0x06CA6351,
    0x14292967,
    0x27B70A85,
    0x2E1B2138,
    0x4D2C6DFB,
    0x53380D13,
    0x650A7354,
    0x766A0ABB,
    0x81C2C92E,
    0x92722C85,
    0xA2BFE8A1,
    0xA81A664B,
    0xC24B8B70,
    0xC76C51A3,
    0xD192E819,
    0xD6990624,
    0xF40E3585,
    0x106AA070,
    0x19A4C116,
    0x1E376C08,
    0x2748774C,
    0x34B0BCB5,
    0x391C0CB3,
    0x4ED8AA4A,
    0x5B9CCA4F,
    0x682E6FF3,
    0x748F82EE,
    0x78A5636F,
    0x84C87814,
    0x8CC70208,
    0x90BEFFFA,
    0xA4506CEB,
    0xBEF9A3F7,
    0xC67178F2,
)

_DEFAULT_XML = b"""<DB>
<Tbl name=\"SSHCfg\" RowCount=\"1\">
<Row No=\"0\">
<DM name=\"SSH_Enable\" val=\"1\"/>
<DM name=\"SSH_UserName\" val=\"admin\"/>
<DM name=\"SSH_PassWord\" val=\"\"/>
<DM name=\"SSH_Port\" val=\"22\"/>
<DM name=\"SSH_Max_Con_Num\" val=\"5\"/>
<DM name=\"Max_Auth_Tries\" val=\"3\"/>
<DM name=\"Auth_Lock_Time\" val=\"60\"/>
<DM name=\"Idle_Time\" val=\"0\"/>
<DM name=\"SSH_ProcType\" val=\"0\"/>
<DM name=\"DSCPRemark\" val=\"-1\"/>
<DM name=\"VLanPrioRemark\" val=\"-1\"/>
<DM name=\"QueueNum\" val=\"-1\"/>
<DM name=\"SSH_Level\" val=\"1\"/>
<DM name=\"TimeoutEnable\" val=\"0\"/>
<DM name=\"TimeoutInterval\" val=\"300\"/>
</Row>
</Tbl>
</DB>
"""


@dataclass(frozen=True)
class ConfigMetadata:
    """Non-secret metadata collected from a configuration container."""

    signature: str | None
    payload_type: int
    base64_wrapped: bool
    encrypted: bool


@dataclass(frozen=True)
class DecodedConfig:
    """Decoded XML plus metadata; the XML is deliberately not logged by the CLI."""

    xml: bytes
    metadata: ConfigMetadata


def _rotr32(value: int, count: int) -> int:
    return ((value >> count) | (value << (32 - count))) & 0xFFFFFFFF


def _sha256_raw_digest(message: bytes) -> bytes:
    if len(message) % 64:
        raise ConfigError("internal SHA-256 input was not block-aligned")
    digest = [
        0x6A09E667,
        0xBB67AE85,
        0x3C6EF372,
        0xA54FF53A,
        0x510E527F,
        0x9B05688C,
        0x1F83D9AB,
        0x5BE0CD19,
    ]
    for offset in range(0, len(message), 64):
        chunk = message[offset : offset + 64]
        words = list(struct.unpack(">16I", chunk))
        for _ in range(16, 64):
            s0 = _rotr32(words[-15], 7) ^ _rotr32(words[-15], 18) ^ (words[-15] >> 3)
            s1 = _rotr32(words[-2], 17) ^ _rotr32(words[-2], 19) ^ (words[-2] >> 10)
            words.append((words[-16] + s0 + words[-7] + s1) & 0xFFFFFFFF)
        a, b, c, d, e, f, g, h = digest
        for word, constant in zip(words, _ROUND_CONSTANTS, strict=True):
            s1 = _rotr32(e, 6) ^ _rotr32(e, 11) ^ _rotr32(e, 25)
            choose = (e & f) ^ ((e ^ 0xFFFFFFFF) & g)
            temp1 = h + s1 + choose + constant + word
            s0 = _rotr32(a, 2) ^ _rotr32(a, 13) ^ _rotr32(a, 22)
            majority = (a & b) ^ (a & c) ^ (b & c)
            temp2 = s0 + majority
            h, g, f = g, f, e
            e = (d + temp1) & 0xFFFFFFFF
            d, c, b = c, b, a
            a = (temp1 + temp2) & 0xFFFFFFFF
        digest = [
            (old + new) & 0xFFFFFFFF
            for old, new in zip(digest, (a, b, c, d, e, f, g, h), strict=True)
        ]
    return struct.pack(">8I", *digest)


def buggy_sha256(message: bytes) -> bytes:
    """Reproduce the H3600P firmware's documented SHA-256 bug."""

    if not isinstance(message, bytes):
        raise ConfigError("key-derivation input must be bytes")
    last_chunk_length = len(message) % 64
    if last_chunk_length <= 55:
        import hashlib

        return hashlib.sha256(message).digest()
    packed_length = struct.pack(">Q", 8 * len(message))
    if last_chunk_length == 56:
        return _sha256_raw_digest(message + packed_length)
    message += b"\x80" + b"\x00" * (64 - last_chunk_length - 1)
    message += message[-64:-8] + packed_length
    return _sha256_raw_digest(message)


def _require_aes() -> _CipherModule:
    if AES is None:
        raise ConfigError(
            "AES support is unavailable; install the package with its runtime dependencies"
        )
    return AES


def _validate_device_inputs(device_key: str, serial: str, mac: str) -> None:
    if not isinstance(device_key, str) or len(device_key) != 32 or not device_key.isascii():
        raise ConfigError("H3600P device encryption passphrase must be exactly 32 characters")
    if not isinstance(serial, str) or not _SERIAL_PATTERN.fullmatch(serial.upper()):
        raise ConfigError(
            "H3600P serial must start with ZTE and contain 8-32 alphanumeric characters"
        )
    if not isinstance(mac, str) or not _MAC_PATTERN.fullmatch(mac.lower()):
        raise ConfigError("MAC address must contain six hexadecimal pairs")


def _derive_h3600p_keys(device_key: str, serial: str, mac: str) -> tuple[bytes, bytes]:
    _validate_device_inputs(device_key, serial, mac)
    serial = serial.upper()
    mac = mac.lower()
    key_seed = f"{device_key}{serial}Mcd5c46".encode("ascii")
    iv_seed = f"G21b667b{mac}{device_key}".encode("ascii")
    return buggy_sha256(key_seed), buggy_sha256(iv_seed)[:16]


def _decode_base64_wrapper(data: bytes) -> tuple[bytes, bool]:
    if not isinstance(data, bytes):
        raise ConfigError("configuration artifact must be bytes")
    if not data:
        raise ConfigError("configuration artifact is empty")
    if len(data) > _MAX_ARTIFACT_BYTES:
        raise ConfigError("configuration artifact exceeds the safety size limit")
    candidate = b"".join(data.split())
    if not candidate or len(candidate) % 4 or _BASE64_PATTERN.fullmatch(candidate) is None:
        return data, False
    try:
        decoded = base64.b64decode(candidate, validate=True)
    except (binascii.Error, ValueError):
        return data, False
    if decoded[:4] in {
        struct.pack(">I", PAYLOAD_MAGIC),
        struct.pack(">I", SIGNATURE_MAGIC),
    }:
        return decoded, True
    return data, False


def _read_chunks(stream: BinaryIO, decryptor: _CipherContext | None = None) -> bytes:
    chunks: list[bytes] = []
    while True:
        header = stream.read(_CHUNK_HEADER_SIZE)
        if len(header) != _CHUNK_HEADER_SIZE:
            raise ConfigError("configuration chunk header is truncated")
        plain_length, encrypted_length, more = struct.unpack(">3I", header)
        if encrypted_length == 0 or encrypted_length % 16:
            raise ConfigError("configuration chunk has an invalid encrypted length")
        if encrypted_length > _MAX_COMPRESSED_BYTES:
            raise ConfigError("configuration chunk exceeds the safety size limit")
        if plain_length > _MAX_COMPRESSED_BYTES:
            raise ConfigError("configuration chunk plaintext length exceeds the safety size limit")
        if more not in (0, 1):
            raise ConfigError("configuration chunk continuation flag is invalid")
        chunk = stream.read(encrypted_length)
        if len(chunk) != encrypted_length:
            raise ConfigError("configuration chunk contents are truncated")
        if decryptor is not None:
            chunk = decryptor.decrypt(chunk)
        if plain_length > len(chunk):
            raise ConfigError("configuration chunk plaintext length is invalid")
        chunks.append(chunk[:plain_length])
        if more == 0:
            break
    return b"".join(chunks)


def _decode_compressed(data: bytes) -> bytes:
    if len(data) < _HEADER_SIZE:
        raise ConfigError("compressed configuration header is truncated")
    header = data[:_HEADER_SIZE]
    (
        magic,
        version,
        expected_length,
        expected_compressed_length,
        duplicate_length,
        expected_crc,
        header_crc,
    ) = struct.unpack(">7I", header[:28])
    if magic != PAYLOAD_MAGIC or version != 0:
        raise ConfigError("configuration does not contain a recognized compressed payload")
    if expected_length != duplicate_length:
        raise ConfigError("compressed configuration length fields disagree")
    if expected_length > _MAX_XML_BYTES:
        raise ConfigError("compressed configuration XML exceeds the safety size limit")
    if expected_compressed_length > _MAX_COMPRESSED_BYTES:
        raise ConfigError("compressed configuration exceeds the safety size limit")
    if zlib.crc32(header[:24]) & 0xFFFFFFFF != header_crc:
        raise ConfigError("compressed configuration header checksum is invalid")
    stream = BytesIO(data[_HEADER_SIZE:])
    output = bytearray()
    compressed_crc = 0
    compressed_total = 0
    chunk_count = 0
    while stream.tell() < len(data) - _HEADER_SIZE:
        chunk_header = stream.read(_CHUNK_HEADER_SIZE)
        if len(chunk_header) != _CHUNK_HEADER_SIZE:
            raise ConfigError("compressed configuration chunk header is truncated")
        plain_length, compressed_length, more = struct.unpack(">3I", chunk_header)
        if compressed_length == 0 or compressed_length > _MAX_COMPRESSED_BYTES:
            raise ConfigError("compressed configuration chunk exceeds the safety size limit")
        if plain_length > _MAX_XML_BYTES:
            raise ConfigError("compressed configuration chunk XML exceeds the safety size limit")
        compressed = stream.read(compressed_length)
        if len(compressed) != compressed_length:
            raise ConfigError("compressed configuration chunk is truncated")
        if more not in (0, 1):
            raise ConfigError("compressed configuration continuation flag is invalid")
        compressed_crc = zlib.crc32(compressed, compressed_crc) & 0xFFFFFFFF
        compressed_total += compressed_length
        chunk_count += 1
        try:
            decompressor = zlib.decompressobj()
            plain = decompressor.decompress(compressed, _MAX_XML_BYTES + 1)
        except zlib.error as exc:
            raise ConfigError("compressed configuration data is invalid") from exc
        if len(plain) > _MAX_XML_BYTES or decompressor.unconsumed_tail:
            raise ConfigError("compressed configuration data exceeds the safety size limit")
        if not decompressor.eof:
            raise ConfigError("compressed configuration data is invalid")
        if len(plain) != plain_length:
            raise ConfigError("compressed configuration chunk length is invalid")
        output.extend(plain)
        if more == 0:
            break
    if chunk_count == 0:
        raise ConfigError("compressed configuration has no data chunks")
    if len(output) != expected_length:
        raise ConfigError("compressed configuration length does not match its header")
    if compressed_total != expected_compressed_length:
        raise ConfigError("compressed configuration compressed length does not match its header")
    if compressed_crc != expected_crc:
        raise ConfigError("compressed configuration checksum is invalid")
    return bytes(output)


def decode_config(
    data: bytes, *, device_key: str | None = None, serial: str | None = None, mac: str | None = None
) -> DecodedConfig:
    """Decode a private H3600P config without logging or writing its XML."""

    binary, base64_wrapped = _decode_base64_wrapper(data)
    signature: str | None = None
    payload_type = 0
    encrypted = False
    if binary[:4] == struct.pack(">I", SIGNATURE_MAGIC):
        if len(binary) < 12:
            raise ConfigError("configuration signature header is truncated")
        _, _, signature_length = struct.unpack(">3I", binary[:12])
        signature_bytes = binary[12 : 12 + signature_length]
        if len(signature_bytes) != signature_length:
            raise ConfigError("configuration signature is truncated")
        try:
            signature = signature_bytes.decode("ascii")
        except UnicodeDecodeError as exc:
            raise ConfigError("configuration signature is not ASCII") from exc
        payload_offset = 12 + signature_length
        if len(binary) < payload_offset + _HEADER_SIZE:
            raise ConfigError("configuration payload header is truncated")
        payload_header = struct.unpack(
            ">15I", binary[payload_offset : payload_offset + _HEADER_SIZE]
        )
        if payload_header[0] != PAYLOAD_MAGIC:
            raise ConfigError("configuration payload magic is invalid")
        payload_type = payload_header[1]
        if payload_type != 4:
            raise ConfigError(f"unsupported encrypted H3600P payload type: {payload_type}")
        encrypted = True
        stream = BytesIO(binary[payload_offset + _HEADER_SIZE :])
        if not device_key or not serial or not mac:
            raise ConfigError(
                "encrypted H3600P config requires the device passphrase, serial, and MAC"
            )
        key, iv = _derive_h3600p_keys(device_key, serial, mac)
        aes = _require_aes()
        decrypted = _read_chunks(stream, aes.new(key, aes.MODE_CBC, iv=iv))
        xml = _decode_compressed(decrypted)
    elif binary[:4] == struct.pack(">I", PAYLOAD_MAGIC):
        xml = _decode_compressed(binary)
    else:
        raise ConfigError("file is not a supported H3600P config container")
    return DecodedConfig(
        xml=xml,
        metadata=ConfigMetadata(signature, payload_type, base64_wrapped, encrypted),
    )


def _encode_compressed(xml: bytes) -> bytes:
    compressed = zlib.compress(xml, level=9)
    header_without_crc = struct.pack(
        ">6I",
        PAYLOAD_MAGIC,
        0,
        len(xml),
        len(compressed),
        len(xml),
        zlib.crc32(compressed) & 0xFFFFFFFF,
    )
    header = header_without_crc + struct.pack(">I", zlib.crc32(header_without_crc) & 0xFFFFFFFF)
    header += b"\x00" * (_HEADER_SIZE - len(header))
    chunk = struct.pack(">3I", len(xml), len(compressed), 0) + compressed
    return header + chunk


def encode_config(
    xml: bytes,
    *,
    signature: str = H3600P_SIGNATURE,
    base64_wrap: bool = True,
    encrypted: bool = False,
    device_key: str | None = None,
    serial: str | None = None,
    mac: str | None = None,
) -> bytes:
    """Encode XML as an offline H3600P artifact.

    The default is the unencrypted compressed form documented by the public
    H3600P research.  Encryption is optional and requires device-specific
    inputs; neither mode proves acceptance by the target firmware.
    """

    if not isinstance(xml, bytes) or not xml:
        raise ConfigError("configuration XML must be non-empty UTF-8 bytes")
    if len(xml) > _MAX_XML_BYTES:
        raise ConfigError("configuration XML exceeds the safety size limit")
    if not isinstance(signature, str) or not signature:
        raise ConfigError("configuration signature must be a non-empty ASCII string")
    try:
        signature_bytes = signature.encode("ascii")
    except UnicodeEncodeError as exc:
        raise ConfigError("configuration signature must be a non-empty ASCII string") from exc
    compressed = _encode_compressed(xml)
    if encrypted:
        if not device_key or not serial or not mac:
            raise ConfigError("encrypted output requires the device passphrase, serial, and MAC")
        key, iv = _derive_h3600p_keys(device_key, serial, mac)
        aes = _require_aes()
        padding = (-len(compressed)) % 16
        ciphertext = aes.new(key, aes.MODE_CBC, iv=iv).encrypt(compressed + b"\x00" * padding)
        outer_header = struct.pack(">3I", SIGNATURE_MAGIC, 0, len(signature_bytes))
        outer_header += signature_bytes
        payload_header = struct.pack(">15I", PAYLOAD_MAGIC, 4, *([0] * 13))
        outer_chunk = struct.pack(">3I", len(compressed), len(ciphertext), 0) + ciphertext
        binary = outer_header + payload_header + outer_chunk
    else:
        binary = compressed
    return base64.b64encode(binary) if base64_wrap else binary


def _reject_unsafe_xml(xml: bytes) -> None:
    upper = xml.upper()
    if b"<!DOCTYPE" in upper or b"<!ENTITY" in upper:
        raise ConfigError("configuration XML may not contain external entities")


def _find_or_create_ssh_table(root: ET.Element) -> tuple[ET.Element, ET.Element]:
    table = next(
        (item for item in root.findall("Tbl") if item.attrib.get("name") == "SSHCfg"),
        None,
    )
    if table is None:
        table = ET.SubElement(root, "Tbl", {"name": "SSHCfg", "RowCount": "1"})
    rows = table.findall("Row")
    row = rows[0] if rows else ET.SubElement(table, "Row", {"No": "0"})
    table.set("RowCount", "1")
    return table, row


def patch_root_ssh(xml: bytes, password: str, username: str = "admin") -> bytes:
    """Enable an SSH root-shell profile in a local XML configuration."""

    if not isinstance(password, str) or not 8 <= len(password) <= 128 or not password.isprintable():
        raise ConfigError("SSH password must contain 8-128 characters")
    if (
        not isinstance(username, str)
        or not username
        or len(username) > 64
        or not username.isprintable()
    ):
        raise ConfigError("SSH username must contain 1-64 characters")
    if not isinstance(xml, bytes) or len(xml) > _MAX_XML_BYTES:
        raise ConfigError("configuration XML exceeds the safety size limit")
    _reject_unsafe_xml(xml)
    try:
        # _reject_unsafe_xml already rejects DOCTYPE/ENTITY declarations above,
        # which removes the XXE/entity-expansion risk stdlib ElementTree carries;
        # a defusedxml dependency is not needed for this pre-filtered input.
        root = ET.fromstring(xml)  # noqa: S314
    except ET.ParseError as exc:
        raise ConfigError("configuration XML is invalid") from exc
    if root.tag != "DB":
        raise ConfigError("configuration XML root must be DB")
    _, row = _find_or_create_ssh_table(root)
    values = {
        "SSH_Enable": "1",
        "SSH_UserName": username,
        "SSH_PassWord": password,
        "SSH_ProcType": "0",
        "SSH_Level": "1",
    }
    fields = {item.attrib.get("name"): item for item in row.findall("DM")}
    for name, value in values.items():
        field = fields.get(name)
        if field is None:
            field = ET.SubElement(row, "DM", {"name": name, "val": value})
        else:
            field.set("val", value)
    # ET.tostring's overloads type this as Any for a non-literal `encoding`
    # argument; passing anything other than "unicode" always yields bytes.
    result: bytes = ET.tostring(root, encoding="utf-8")
    return result


def default_root_xml(password: str, username: str = "admin") -> bytes:
    """Build the minimal offline SSH-root template used without a baseline."""

    return patch_root_ssh(_DEFAULT_XML, password, username)


def inspect_config(data: bytes) -> ConfigMetadata:
    """Read only non-secret container metadata without decrypting settings."""

    binary, base64_wrapped = _decode_base64_wrapper(data)
    if binary[:4] == struct.pack(">I", SIGNATURE_MAGIC):
        if len(binary) < 12:
            raise ConfigError("configuration signature header is truncated")
        _, _, signature_length = struct.unpack(">3I", binary[:12])
        signature_bytes = binary[12 : 12 + signature_length]
        try:
            signature = signature_bytes.decode("ascii")
        except UnicodeDecodeError as exc:
            raise ConfigError("configuration signature is not ASCII") from exc
        payload_offset = 12 + signature_length
        if len(binary) < payload_offset + 8:
            raise ConfigError("configuration payload header is truncated")
        magic, payload_type = struct.unpack(">2I", binary[payload_offset : payload_offset + 8])
        if magic != PAYLOAD_MAGIC:
            raise ConfigError("configuration payload magic is invalid")
        return ConfigMetadata(signature, payload_type, base64_wrapped, payload_type != 0)
    if binary[:8] == struct.pack(">2I", PAYLOAD_MAGIC, 0):
        return ConfigMetadata(None, 0, base64_wrapped, False)
    raise ConfigError("file is not a supported H3600P config container")


def read_private_config(path: str | Path) -> bytes:
    """Read one private config artifact; no contents are logged by this module."""

    source = Path(path)
    try:
        with source.open("rb") as stream:
            data = stream.read(_MAX_ARTIFACT_BYTES + 1)
    except OSError as exc:
        raise ConfigError("unable to read configuration artifact") from exc
    if not data:
        raise ConfigError("configuration artifact is empty")
    if len(data) > _MAX_ARTIFACT_BYTES:
        raise ConfigError("configuration artifact exceeds the safety size limit")
    return data

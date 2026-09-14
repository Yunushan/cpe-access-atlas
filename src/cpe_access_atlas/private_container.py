# SPDX-License-Identifier: 0BSD
"""Authenticated encryption for private local artifacts.

This format is deliberately separate from the vendor-compatible H3600P
configuration container.  It is suitable for protecting a local copy at rest,
not for importing into a modem and not for establishing firmware support.
"""

from __future__ import annotations

import struct
from collections.abc import Callable
from typing import Protocol, cast


class PrivateContainerError(ValueError):
    """Raised when a private local container cannot be safely processed."""


class _GcmContext(Protocol):
    def update(self, assoc_data: bytes) -> None: ...

    def encrypt_and_digest(self, data: bytes) -> tuple[bytes, bytes]: ...

    def decrypt_and_verify(self, data: bytes, received_mac_tag: bytes) -> bytes: ...


class _CipherModule(Protocol):
    MODE_GCM: int

    def new(
        self,
        key: bytes | bytearray,
        mode: int,
        *,
        nonce: bytes,
        mac_len: int,
    ) -> _GcmContext: ...


AES: _CipherModule | None
_scrypt: Callable[[bytes, bytes, int, int, int, int], bytes] | None
_random_bytes: Callable[[int], bytes] | None
try:
    from Crypto.Cipher import AES as _imported_aes
    from Crypto.Protocol.KDF import scrypt as _imported_scrypt
    from Crypto.Random import get_random_bytes as _imported_random_bytes

    AES = cast(_CipherModule, _imported_aes)
    _scrypt = cast(Callable[[bytes, bytes, int, int, int, int], bytes], _imported_scrypt)
    _random_bytes = _imported_random_bytes
except ImportError:  # pragma: no cover - exercised by installation diagnostics
    AES = None
    _scrypt = None
    _random_bytes = None


_MAGIC = b"CPAP"
_VERSION = 1
_KDF_SCRYPT = 1
_CIPHER_AES_GCM = 1
_SALT_LENGTH = 16
_NONCE_LENGTH = 12
_TAG_LENGTH = 16
_KEY_LENGTH = 32
_SCRYPT_N = 2**15
_SCRYPT_R = 8
_SCRYPT_P = 1
_MIN_PASSPHRASE_CHARS = 12
_MAX_PASSPHRASE_CHARS = 256
MAX_PRIVATE_BYTES = 16 * 1024 * 1024
_HEADER = struct.Struct(">4sBBBBBQ")
MAX_CONTAINER_BYTES = MAX_PRIVATE_BYTES + _HEADER.size + _SALT_LENGTH + _NONCE_LENGTH + _TAG_LENGTH


def _validate_passphrase(passphrase: str) -> bytes:
    if (
        not isinstance(passphrase, str)
        or not _MIN_PASSPHRASE_CHARS <= len(passphrase) <= _MAX_PASSPHRASE_CHARS
        or not passphrase.isprintable()
    ):
        raise PrivateContainerError(
            "private-container passphrase must contain 12-256 printable characters"
        )
    return passphrase.encode("utf-8")


def _require_crypto() -> tuple[
    _CipherModule,
    Callable[[bytes, bytes, int, int, int, int], bytes],
    Callable[[int], bytes],
]:
    if AES is None or _scrypt is None or _random_bytes is None:
        raise PrivateContainerError(
            "authenticated private-container support is unavailable; install runtime dependencies"
        )
    return AES, _scrypt, _random_bytes


def _make_header(payload_length: int) -> bytes:
    return _HEADER.pack(
        _MAGIC,
        _VERSION,
        _KDF_SCRYPT,
        _CIPHER_AES_GCM,
        _SALT_LENGTH,
        _NONCE_LENGTH,
        payload_length,
    )


def _parse_container(data: bytes) -> tuple[bytes, bytes, bytes, bytes, bytes]:
    if not isinstance(data, bytes) or len(data) > MAX_CONTAINER_BYTES:
        raise PrivateContainerError("private container exceeds the safety size limit")
    if len(data) < _HEADER.size + _SALT_LENGTH + _NONCE_LENGTH + _TAG_LENGTH:
        raise PrivateContainerError("private container header is truncated")
    header = data[: _HEADER.size]
    magic, version, kdf, cipher, salt_length, nonce_length, payload_length = _HEADER.unpack(header)
    if (magic, version, kdf, cipher) != (_MAGIC, _VERSION, _KDF_SCRYPT, _CIPHER_AES_GCM):
        raise PrivateContainerError("private container format is not recognized")
    if salt_length != _SALT_LENGTH or nonce_length != _NONCE_LENGTH:
        raise PrivateContainerError("private container parameters are not supported")
    if not 1 <= payload_length <= MAX_PRIVATE_BYTES:
        raise PrivateContainerError("private container payload size is invalid")
    expected_length = _HEADER.size + salt_length + nonce_length + payload_length + _TAG_LENGTH
    if len(data) != expected_length:
        raise PrivateContainerError("private container length is invalid")
    salt_start = _HEADER.size
    nonce_start = salt_start + salt_length
    ciphertext_start = nonce_start + nonce_length
    salt = data[salt_start:nonce_start]
    nonce = data[nonce_start:ciphertext_start]
    ciphertext = data[ciphertext_start:-_TAG_LENGTH]
    tag = data[-_TAG_LENGTH:]
    return header + salt + nonce, salt, nonce, ciphertext, tag


def protect_private_bytes(data: bytes, passphrase: str) -> bytes:
    """Protect private bytes with scrypt and AES-GCM for local storage."""

    if not isinstance(data, bytes) or not 1 <= len(data) <= MAX_PRIVATE_BYTES:
        raise PrivateContainerError("private artifact is empty or exceeds the safety size limit")
    passphrase_bytes = _validate_passphrase(passphrase)
    aes, scrypt, random_bytes = _require_crypto()
    salt = random_bytes(_SALT_LENGTH)
    nonce = random_bytes(_NONCE_LENGTH)
    header = _make_header(len(data))
    associated_data = header + salt + nonce
    key = bytearray(scrypt(passphrase_bytes, salt, _KEY_LENGTH, _SCRYPT_N, _SCRYPT_R, _SCRYPT_P))
    try:
        cipher = aes.new(key, aes.MODE_GCM, nonce=nonce, mac_len=_TAG_LENGTH)
        cipher.update(associated_data)
        ciphertext, tag = cipher.encrypt_and_digest(data)
    finally:
        key[:] = b"\x00" * len(key)
    return associated_data + ciphertext + tag


def unprotect_private_bytes(data: bytes, passphrase: str) -> bytes:
    """Authenticate and decrypt a private local container."""

    associated_data, salt, nonce, ciphertext, tag = _parse_container(data)
    passphrase_bytes = _validate_passphrase(passphrase)
    aes, scrypt, _ = _require_crypto()
    key = bytearray(scrypt(passphrase_bytes, salt, _KEY_LENGTH, _SCRYPT_N, _SCRYPT_R, _SCRYPT_P))
    try:
        cipher = aes.new(key, aes.MODE_GCM, nonce=nonce, mac_len=_TAG_LENGTH)
        cipher.update(associated_data)
        try:
            return cipher.decrypt_and_verify(ciphertext, tag)
        except ValueError as exc:
            raise PrivateContainerError(
                "private container authentication failed; passphrase may be incorrect "
                "or data corrupted"
            ) from exc
    finally:
        key[:] = b"\x00" * len(key)

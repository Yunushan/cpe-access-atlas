# SPDX-License-Identifier: 0BSD
"""Authenticated encryption for private local artifacts.

This format is deliberately separate from the vendor-compatible H3600P
configuration container.  It is suitable for protecting a local copy at rest,
not for importing into a modem and not for establishing firmware support.
"""

from __future__ import annotations

import struct
from collections.abc import Callable
from dataclasses import dataclass
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
_VERSION_1 = 1
_VERSION_2 = 2
_VERSION = _VERSION_2
_KDF_SCRYPT = 1
_CIPHER_AES_GCM = 1
_SALT_LENGTH = 16
_NONCE_LENGTH = 12
_TAG_LENGTH = 16
_KEY_LENGTH = 32
_V1_SCRYPT_N = 2**15
_V2_SCRYPT_N = 2**17
_SCRYPT_R = 8
_SCRYPT_P = 1
_MIN_PASSPHRASE_CHARS = 12
_MAX_PASSPHRASE_CHARS = 256
MAX_PRIVATE_BYTES = 16 * 1024 * 1024
_V1_HEADER = struct.Struct(">4sBBBBBQ")
_V2_HEADER = struct.Struct(">4sBBBBBIIIQ")
# The private name existed for the original format. Keep it as an alias for the
# current write format so focused diagnostics can calculate current overhead.
_HEADER = _V2_HEADER
MAX_CONTAINER_BYTES = (
    MAX_PRIVATE_BYTES
    + max(_V1_HEADER.size, _V2_HEADER.size)
    + _SALT_LENGTH
    + _NONCE_LENGTH
    + _TAG_LENGTH
)


@dataclass(frozen=True)
class _ParsedContainer:
    associated_data: bytes
    salt: bytes
    nonce: bytes
    ciphertext: bytes
    tag: bytes
    scrypt_n: int
    scrypt_r: int
    scrypt_p: int


def _validate_passphrase(passphrase: str) -> bytes:
    # Unicode categories change with Python's Unicode database. In particular,
    # isprintable() can reject a passphrase containing a newer assigned character
    # when an existing container is opened on an older supported interpreter.
    # Use fixed ranges instead: Unicode scalars except C0/C1 controls and the
    # line/paragraph separators. Future assignments therefore remain compatible.
    # Do not normalize or trim: the exact UTF-8 bytes are part of every format
    # version's KDF input and must remain stable when an old container is read.
    if (
        not isinstance(passphrase, str)
        or not _MIN_PASSPHRASE_CHARS <= len(passphrase) <= _MAX_PASSPHRASE_CHARS
        or any(
            codepoint < 0x20
            or 0x7F <= codepoint <= 0x9F
            or 0x2028 <= codepoint <= 0x2029
            or 0xD800 <= codepoint <= 0xDFFF
            for codepoint in map(ord, passphrase)
        )
    ):
        raise PrivateContainerError(
            "private-container passphrase must contain 12-256 Unicode characters "
            "without C0/C1 controls, line separators, or surrogates"
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
    return _V2_HEADER.pack(
        _MAGIC,
        _VERSION,
        _KDF_SCRYPT,
        _CIPHER_AES_GCM,
        _SALT_LENGTH,
        _NONCE_LENGTH,
        _V2_SCRYPT_N,
        _SCRYPT_R,
        _SCRYPT_P,
        payload_length,
    )


def _parse_container(data: bytes) -> _ParsedContainer:
    """Validate all attacker-controlled work factors before invoking scrypt."""

    if not isinstance(data, bytes):
        raise PrivateContainerError("private container must be bytes")
    if len(data) > MAX_CONTAINER_BYTES:
        raise PrivateContainerError("private container exceeds the safety size limit")
    if len(data) < len(_MAGIC) + 1:
        raise PrivateContainerError("private container header is truncated")
    if data[: len(_MAGIC)] != _MAGIC:
        raise PrivateContainerError("private container format is not recognized")
    version = data[len(_MAGIC)]
    if version == _VERSION_1:
        if len(data) < _V1_HEADER.size + _SALT_LENGTH + _NONCE_LENGTH + _TAG_LENGTH:
            raise PrivateContainerError("private container header is truncated")
        header = data[: _V1_HEADER.size]
        (
            _,
            _,
            kdf,
            cipher,
            salt_length,
            nonce_length,
            payload_length,
        ) = _V1_HEADER.unpack(header)
        scrypt_n = _V1_SCRYPT_N
        scrypt_r = _SCRYPT_R
        scrypt_p = _SCRYPT_P
    elif version == _VERSION_2:
        if len(data) < _V2_HEADER.size + _SALT_LENGTH + _NONCE_LENGTH + _TAG_LENGTH:
            raise PrivateContainerError("private container header is truncated")
        header = data[: _V2_HEADER.size]
        (
            _,
            _,
            kdf,
            cipher,
            salt_length,
            nonce_length,
            scrypt_n,
            scrypt_r,
            scrypt_p,
            payload_length,
        ) = _V2_HEADER.unpack(header)
        if (scrypt_n, scrypt_r, scrypt_p) != (_V2_SCRYPT_N, _SCRYPT_R, _SCRYPT_P):
            raise PrivateContainerError("private container scrypt parameters are not supported")
    else:
        raise PrivateContainerError("private container version is not supported")
    if (kdf, cipher) != (_KDF_SCRYPT, _CIPHER_AES_GCM):
        raise PrivateContainerError("private container algorithm identifiers are not supported")
    if salt_length != _SALT_LENGTH or nonce_length != _NONCE_LENGTH:
        raise PrivateContainerError("private container parameters are not supported")
    if not 1 <= payload_length <= MAX_PRIVATE_BYTES:
        raise PrivateContainerError("private container payload size is invalid")
    expected_length = len(header) + salt_length + nonce_length + payload_length + _TAG_LENGTH
    if len(data) != expected_length:
        raise PrivateContainerError("private container length is invalid")
    salt_start = len(header)
    nonce_start = salt_start + salt_length
    ciphertext_start = nonce_start + nonce_length
    salt = data[salt_start:nonce_start]
    nonce = data[nonce_start:ciphertext_start]
    ciphertext = data[ciphertext_start:-_TAG_LENGTH]
    tag = data[-_TAG_LENGTH:]
    return _ParsedContainer(
        associated_data=header + salt + nonce,
        salt=salt,
        nonce=nonce,
        ciphertext=ciphertext,
        tag=tag,
        scrypt_n=scrypt_n,
        scrypt_r=scrypt_r,
        scrypt_p=scrypt_p,
    )


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
    key = bytearray(
        scrypt(
            passphrase_bytes,
            salt,
            _KEY_LENGTH,
            _V2_SCRYPT_N,
            _SCRYPT_R,
            _SCRYPT_P,
        )
    )
    try:
        cipher = aes.new(key, aes.MODE_GCM, nonce=nonce, mac_len=_TAG_LENGTH)
        cipher.update(associated_data)
        ciphertext, tag = cipher.encrypt_and_digest(data)
    finally:
        key[:] = b"\x00" * len(key)
    return associated_data + ciphertext + tag


def unprotect_private_bytes(data: bytes, passphrase: str) -> bytes:
    """Authenticate and decrypt a private local container."""

    parsed = _parse_container(data)
    passphrase_bytes = _validate_passphrase(passphrase)
    aes, scrypt, _ = _require_crypto()
    key = bytearray(
        scrypt(
            passphrase_bytes,
            parsed.salt,
            _KEY_LENGTH,
            parsed.scrypt_n,
            parsed.scrypt_r,
            parsed.scrypt_p,
        )
    )
    try:
        cipher = aes.new(key, aes.MODE_GCM, nonce=parsed.nonce, mac_len=_TAG_LENGTH)
        cipher.update(parsed.associated_data)
        try:
            return cipher.decrypt_and_verify(parsed.ciphertext, parsed.tag)
        except ValueError as exc:
            raise PrivateContainerError(
                "private container authentication failed; passphrase may be incorrect "
                "or data corrupted"
            ) from exc
    finally:
        key[:] = b"\x00" * len(key)

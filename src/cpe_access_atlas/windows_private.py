# SPDX-License-Identifier: 0BSD
"""Secure-at-creation Windows temporary files for credential-bearing artifacts.

Only the creating process's user is granted access. This does not defend against
that user, administrators exercising elevated privileges, or an untrusted
storage provider. Keep the destination directory under the user's control.
"""

from __future__ import annotations

import ctypes
import importlib
import os
import secrets
from pathlib import Path
from typing import Any, cast

_DWORD = ctypes.c_uint32
_BOOL = ctypes.c_int32
_HANDLE = ctypes.c_void_p
_FILE_ALL_ACCESS = 0x001F01FF
_SECURITY_INFORMATION = 0x00000001 | 0x00000004  # owner and DACL
_SE_DACL_PRESENT_AND_PROTECTED = 0x0004 | 0x1000
_FILE_PERSISTENT_ACLS = 0x00000008
_INVALID_HANDLE = ctypes.c_void_p(-1).value


class _SecurityAttributes(ctypes.Structure):
    _fields_ = [("length", _DWORD), ("descriptor", ctypes.c_void_p), ("inherit", _BOOL)]


class _TokenUser(ctypes.Structure):
    _fields_ = [("sid", ctypes.c_void_p), ("attributes", _DWORD)]


class _AclSize(ctypes.Structure):
    _fields_ = [("count", _DWORD), ("used", _DWORD), ("free", _DWORD)]


class _AllowedAce(ctypes.Structure):
    _fields_ = [
        ("type", ctypes.c_ubyte),
        ("flags", ctypes.c_ubyte),
        ("size", ctypes.c_uint16),
        ("mask", _DWORD),
        ("sid_start", _DWORD),
    ]


def _bind(library: Any, name: str, result: Any, arguments: list[Any]) -> Any:
    function = getattr(library, name)
    function.restype = result
    function.argtypes = arguments
    return function


class _WindowsApi:
    """Typed layouts and explicit System32 loading for the small native API surface."""

    def __init__(self) -> None:
        loader = getattr(ctypes, "WinDLL", None)
        if loader is None:
            raise OSError("Windows secure file APIs are unavailable")
        kernel = loader("kernel32.dll", use_last_error=True, winmode=0x800)
        security = loader("advapi32.dll", use_last_error=True, winmode=0x800)
        pointer = ctypes.c_void_p
        self.process = _bind(kernel, "GetCurrentProcess", _HANDLE, [])
        self.close = _bind(kernel, "CloseHandle", _BOOL, [_HANDLE])
        self.free = _bind(kernel, "LocalFree", pointer, [pointer])
        self.open_token = _bind(security, "OpenProcessToken", _BOOL, [_HANDLE, _DWORD, pointer])
        self.token_info = _bind(
            security, "GetTokenInformation", _BOOL, [_HANDLE, _DWORD, pointer, _DWORD, pointer]
        )
        self.sid_string = _bind(security, "ConvertSidToStringSidW", _BOOL, [pointer, pointer])
        self.make_sd = _bind(
            security,
            "ConvertStringSecurityDescriptorToSecurityDescriptorW",
            _BOOL,
            [ctypes.c_wchar_p, _DWORD, pointer, pointer],
        )
        self.create = _bind(
            kernel,
            "CreateFileW",
            _HANDLE,
            [ctypes.c_wchar_p, _DWORD, _DWORD, pointer, _DWORD, _DWORD, _HANDLE],
        )
        self.volume_info = _bind(
            kernel,
            "GetVolumeInformationByHandleW",
            _BOOL,
            [_HANDLE, pointer, _DWORD, pointer, pointer, pointer, pointer, _DWORD],
        )
        self.get_sd = _bind(
            security,
            "GetSecurityInfo",
            _DWORD,
            [_HANDLE, _DWORD, _DWORD, pointer, pointer, pointer, pointer, pointer],
        )
        self.sd_control = _bind(
            security, "GetSecurityDescriptorControl", _BOOL, [pointer, pointer, pointer]
        )
        self.acl_info = _bind(
            security, "GetAclInformation", _BOOL, [pointer, pointer, _DWORD, _DWORD]
        )
        self.get_ace = _bind(security, "GetAce", _BOOL, [pointer, _DWORD, pointer])

    @staticmethod
    def error(operation: str, code: int | None = None) -> OSError:
        if code is None:
            code = int(getattr(ctypes, "get_last_error", lambda: 0)())
        message = f"Windows private-file operation failed: {operation}"
        factory = getattr(ctypes, "WinError", None)
        if factory is None:
            return OSError(code, message)
        return cast(OSError, factory(code, message))

    def sid_text(self, sid: int | None) -> str:
        value = ctypes.c_wchar_p()
        if not self.sid_string(sid, ctypes.byref(value)):
            raise self.error("read owner identity")
        try:
            if not value.value:
                raise OSError("Windows returned an empty user identity")
            return value.value
        finally:
            self.free(value)

    def user_sid(self) -> str:
        token = _HANDLE()
        if not self.open_token(self.process(), 0x0008, ctypes.byref(token)):
            raise self.error("open process token")
        try:
            needed = _DWORD()
            self.token_info(token, 1, None, 0, ctypes.byref(needed))
            if not ctypes.sizeof(_TokenUser) <= needed.value <= 65536:
                raise OSError("Windows returned an invalid user-token size")
            buffer = ctypes.create_string_buffer(needed.value)
            if not self.token_info(token, 1, buffer, needed.value, ctypes.byref(needed)):
                raise self.error("read process token")
            user = ctypes.cast(buffer, ctypes.POINTER(_TokenUser)).contents
            return self.sid_text(user.sid)
        finally:
            self.close(token)

    def descriptor(self, sid: str) -> ctypes.c_void_p:
        # Explicit owner and protected DACL: no inherited group/Everyone ACEs,
        # including during the interval before the first byte is written.
        value = ctypes.c_void_p()
        if not self.make_sd(f"O:{sid}D:P(A;;FA;;;{sid})", 1, ctypes.byref(value), None):
            raise self.error("construct owner-only ACL")
        return value

    def verify_private(self, handle: int, expected_sid: str) -> None:
        flags = _DWORD()
        if not self.volume_info(handle, None, 0, None, None, ctypes.byref(flags), None, 0):
            raise self.error("verify filesystem ACL support")
        if not flags.value & _FILE_PERSISTENT_ACLS:
            raise OSError("Private artifacts require a filesystem with persistent Windows ACLs")
        owner, dacl, descriptor = ctypes.c_void_p(), ctypes.c_void_p(), ctypes.c_void_p()
        result = self.get_sd(
            handle,
            1,
            _SECURITY_INFORMATION,
            ctypes.byref(owner),
            None,
            ctypes.byref(dacl),
            None,
            ctypes.byref(descriptor),
        )
        if result:
            raise self.error("verify private security descriptor", int(result))
        try:
            control, revision = ctypes.c_uint16(), _DWORD()
            if not self.sd_control(descriptor, ctypes.byref(control), ctypes.byref(revision)):
                raise self.error("verify DACL protection")
            if (
                not owner.value
                or not dacl.value
                or control.value & _SE_DACL_PRESENT_AND_PROTECTED != _SE_DACL_PRESENT_AND_PROTECTED
                or self.sid_text(owner.value) != expected_sid
            ):
                raise OSError("Private file owner or protected DACL was not preserved")
            information = _AclSize()
            if not self.acl_info(dacl, ctypes.byref(information), ctypes.sizeof(information), 2):
                raise self.error("verify ACL entries")
            if information.count != 1:
                raise OSError("Private file ACL must contain exactly one owner grant")
            pointer = ctypes.c_void_p()
            if not self.get_ace(dacl, 0, ctypes.byref(pointer)) or not pointer.value:
                raise self.error("read owner ACL entry")
            ace = ctypes.cast(pointer, ctypes.POINTER(_AllowedAce)).contents
            if (
                ace.type != 0
                or ace.flags != 0
                or ace.mask != _FILE_ALL_ACCESS
                or ace.size < ctypes.sizeof(_AllowedAce)
                or self.sid_text(pointer.value + _AllowedAce.sid_start.offset) != expected_sid
            ):
                raise OSError("Private file ACL grants access beyond the creating user")
        finally:
            self.free(descriptor)

    @staticmethod
    def adopt(handle: int) -> int:
        runtime = importlib.import_module("msvcrt")
        flags = os.O_WRONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOINHERIT", 0)
        return int(runtime.open_osfhandle(handle, flags))


def create_private_temp(target: Path) -> tuple[int, str]:
    """Return a non-inheritable writable fd and its private, exclusive temp path.

    CreateFile's CREATE_NEW prevents opening an attacker's preexisting file.
    The descriptor is supplied at creation and verified through that same open
    handle before returning it to a caller that can write credential bytes.
    """

    if ":" in target.name:
        raise OSError("Alternate data streams are not supported for private artifacts")
    api = _WindowsApi()
    sid = api.user_sid()
    descriptor = api.descriptor(sid)
    handle: int | None = None
    temporary: Path | None = None
    try:
        attributes = _SecurityAttributes(ctypes.sizeof(_SecurityAttributes), descriptor, 0)
        for _ in range(32):
            candidate = target.absolute().with_name(f".{target.name}.{secrets.token_hex(16)}")
            # GENERIC_WRITE | READ_CONTROL; no sharing; CREATE_NEW; normal file.
            created = api.create(
                str(candidate), 0x40020000, 0, ctypes.byref(attributes), 1, 0x80, None
            )
            if created not in (None, _INVALID_HANDLE):
                handle, temporary = int(created), candidate
                break
            error = api.error("create private temporary file")
            error_code = getattr(error, "winerror", None)
            if error_code is None:
                error_code = error.errno
            if error_code not in (80, 183):
                raise error
        else:
            raise FileExistsError("Unable to allocate a unique private temporary file")
        api.verify_private(handle, sid)
        descriptor_number = api.adopt(handle)
        handle = None  # The CRT fd now owns the handle; os.close/fdopen closes it.
        return descriptor_number, str(temporary)
    except BaseException:
        if handle is not None:
            api.close(handle)
        if temporary is not None:
            temporary.unlink(missing_ok=True)
        raise
    finally:
        api.free(descriptor)

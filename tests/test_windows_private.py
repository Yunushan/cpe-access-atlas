# SPDX-License-Identifier: 0BSD
"""Native ACL checks plus platform-independent Windows API failure tests."""

from __future__ import annotations

import ctypes
import os
import subprocess
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace
from unittest.mock import Mock, patch

from cpe_access_atlas import private_files
from cpe_access_atlas import windows_private as win

POWERSHELL_PROBE_TIMEOUT_SECONDS = 45


def assign(pointer: object, ctype: object, value: object) -> None:
    ctypes.cast(pointer, ctypes.POINTER(ctype)).contents.value = value


class NativeFixture:
    """Only cast pointers to owned ctypes buffers; fake numeric handles stay opaque."""

    identity = "S-1-5-21-1-2-3-1001"

    def __init__(self) -> None:
        self.buffers: list[object] = []
        self.sid_overrides: dict[int, str] = {}
        self.ace = win._AllowedAce(0, 0, 20, win._FILE_ALL_ACCESS, 0)
        self.control = win._SE_DACL_PRESENT_AND_PROTECTED
        self.owner = 123
        self.dacl = 456
        self.count = 1
        self.volume_flags = win._FILE_PERSISTENT_ACLS
        self.kernel = SimpleNamespace(
            GetCurrentProcess=Mock(return_value=42),
            CloseHandle=Mock(return_value=1),
            LocalFree=Mock(return_value=None),
            CreateFileW=Mock(return_value=88),
            GetVolumeInformationByHandleW=Mock(side_effect=self.volume),
        )
        self.security = SimpleNamespace(
            OpenProcessToken=Mock(side_effect=self.open_token),
            GetTokenInformation=Mock(side_effect=self.token_info),
            ConvertSidToStringSidW=Mock(side_effect=self.sid_string),
            ConvertStringSecurityDescriptorToSecurityDescriptorW=Mock(side_effect=self.make_sd),
            GetSecurityInfo=Mock(side_effect=self.get_sd),
            GetSecurityDescriptorControl=Mock(side_effect=self.sd_control),
            GetAclInformation=Mock(side_effect=self.acl_info),
            GetAce=Mock(side_effect=self.get_ace),
        )

    def loader(self, name: str, **kwargs: object) -> object:
        if kwargs != {"use_last_error": True, "winmode": 0x800}:
            raise AssertionError("Native libraries must load only from System32")
        return {"kernel32.dll": self.kernel, "advapi32.dll": self.security}[name]

    def open_token(self, process: int, access: int, pointer: object) -> int:
        assign(pointer, ctypes.c_void_p, 77)
        return 1

    def token_info(
        self, token: object, kind: int, buffer: object, size: int, needed: object
    ) -> int:
        assign(needed, win._DWORD, ctypes.sizeof(win._TokenUser))
        if buffer is None:
            return 0
        ctypes.cast(buffer, ctypes.POINTER(win._TokenUser)).contents.sid = self.owner
        return 1

    def sid_string(self, sid: int, pointer: object) -> int:
        buffer = ctypes.create_unicode_buffer(self.sid_overrides.get(sid, self.identity))
        self.buffers.append(buffer)
        assign(pointer, ctypes.c_void_p, ctypes.addressof(buffer))
        return 1

    def make_sd(self, text: str, version: int, pointer: object, size: object) -> int:
        assign(pointer, ctypes.c_void_p, 999)
        return 1

    def volume(
        self,
        handle: int,
        name: object,
        size: int,
        serial: object,
        component: object,
        flags: object,
        fsname: object,
        fssize: int,
    ) -> int:
        assign(flags, win._DWORD, self.volume_flags)
        return 1

    def get_sd(
        self,
        handle: int,
        kind: int,
        info: int,
        owner: object,
        group: object,
        dacl: object,
        sacl: object,
        descriptor: object,
    ) -> int:
        assign(owner, ctypes.c_void_p, self.owner)
        assign(dacl, ctypes.c_void_p, self.dacl)
        assign(descriptor, ctypes.c_void_p, 789)
        return 0

    def sd_control(self, descriptor: object, control: object, revision: object) -> int:
        assign(control, ctypes.c_uint16, self.control)
        assign(revision, win._DWORD, 1)
        return 1

    def acl_info(self, acl: object, info: object, length: int, kind: int) -> int:
        ctypes.cast(info, ctypes.POINTER(win._AclSize)).contents.count = self.count
        return 1

    def get_ace(self, acl: object, index: int, pointer: object) -> int:
        assign(pointer, ctypes.c_void_p, ctypes.addressof(self.ace))
        return 1


class WindowsApiTests(unittest.TestCase):
    def setUp(self) -> None:
        self.native = NativeFixture()
        loader = patch.object(ctypes, "WinDLL", side_effect=self.native.loader, create=True)
        loader.start()
        self.addCleanup(loader.stop)
        last_error = patch.object(ctypes, "get_last_error", return_value=5, create=True)
        last_error.start()
        self.addCleanup(last_error.stop)
        self.api = win._WindowsApi()

    def test_descriptor_is_explicit_owner_only_and_protected(self) -> None:
        sid = self.api.user_sid()
        self.assertEqual(sid, self.native.identity)
        self.api.descriptor(sid)
        args = (
            self.native.security.ConvertStringSecurityDescriptorToSecurityDescriptorW.call_args.args
        )
        self.assertEqual(args[:2], (f"O:{sid}D:P(A;;FA;;;{sid})", 1))
        self.native.kernel.CloseHandle.assert_called_once()
        self.api.verify_private(88, sid)

    def test_missing_native_loader_fails_closed(self) -> None:
        with patch.object(ctypes, "WinDLL", None):
            with self.assertRaisesRegex(OSError, "unavailable"):
                win._WindowsApi()

    def test_winerror_factory_and_portable_mock_fallback(self) -> None:
        with patch.object(ctypes, "WinError", None, create=True):
            self.assertEqual(self.api.error("test").errno, 5)
        error = OSError("synthetic failure")
        with patch.object(ctypes, "WinError", return_value=error, create=True) as factory:
            self.assertIs(self.api.error("test", 3), error)
            factory.assert_called_once_with(3, "Windows private-file operation failed: test")

    def test_token_and_sid_failures_close_owned_resources(self) -> None:
        for function, result in (
            ("OpenProcessToken", 0),
            ("GetTokenInformation", 0),
            ("ConvertSidToStringSidW", 0),
        ):
            with self.subTest(function=function):
                with patch.object(self.native.security, function, Mock(return_value=result)):
                    api = win._WindowsApi()
                    with self.assertRaises(OSError):
                        api.user_sid()

        def fail_second(token: object, kind: int, buffer: object, size: int, needed: object) -> int:
            self.native.token_info(token, kind, buffer, size, needed)
            return 0

        with patch.object(self.api, "token_info", side_effect=fail_second):
            with self.assertRaisesRegex(OSError, "read process token"):
                self.api.user_sid()
        self.native.sid_overrides[self.native.owner] = ""
        with self.assertRaisesRegex(OSError, "empty user identity"):
            self.api.user_sid()
        with patch.object(self.api, "make_sd", return_value=0):
            with self.assertRaises(OSError):
                self.api.descriptor(self.native.identity)

    def test_acl_query_failures_never_certify_privacy(self) -> None:
        for function, result in (
            ("volume_info", 0),
            ("get_sd", 5),
            ("sd_control", 0),
            ("acl_info", 0),
            ("get_ace", 0),
        ):
            with self.subTest(function=function):
                with patch.object(self.api, function, return_value=result):
                    with self.assertRaises(OSError):
                        self.api.verify_private(88, self.native.identity)

    def test_inherited_or_permissive_acls_are_rejected(self) -> None:
        for field, value in (
            ("volume_flags", 0),
            ("owner", None),
            ("dacl", None),
            ("control", 4),
            ("count", 0),
            ("count", 2),
        ):
            with self.subTest(field=field, value=value):
                with patch.object(self.native, field, value):
                    with self.assertRaises(OSError):
                        self.api.verify_private(88, self.native.identity)
        for field, value in (("type", 1), ("flags", 16), ("mask", 1), ("size", 4)):
            previous = getattr(self.native.ace, field)
            setattr(self.native.ace, field, value)
            with self.assertRaisesRegex(OSError, "beyond the creating user"):
                self.api.verify_private(88, self.native.identity)
            setattr(self.native.ace, field, previous)
        for pointer in (
            self.native.owner,
            ctypes.addressof(self.native.ace) + win._AllowedAce.sid_start.offset,
        ):
            self.native.sid_overrides[pointer] = "S-1-1-0"
            with self.assertRaises(OSError):
                self.api.verify_private(88, self.native.identity)
            self.native.sid_overrides.clear()

        def empty_ace(acl: object, index: int, pointer: object) -> int:
            assign(pointer, ctypes.c_void_p, None)
            return 1

        with patch.object(self.api, "get_ace", side_effect=empty_ace):
            with self.assertRaises(OSError):
                self.api.verify_private(88, self.native.identity)

    def test_fd_conversion_requests_non_inheritance(self) -> None:
        runtime = SimpleNamespace(open_osfhandle=Mock(return_value=17))
        with patch.object(win.importlib, "import_module", return_value=runtime):
            self.assertEqual(self.api.adopt(88), 17)
        self.assertEqual(runtime.open_osfhandle.call_args.args[0], 88)
        if hasattr(os, "O_NOINHERIT"):
            self.assertTrue(runtime.open_osfhandle.call_args.args[1] & os.O_NOINHERIT)


class WindowsCreationTests(unittest.TestCase):
    def fixture(self) -> SimpleNamespace:
        api = SimpleNamespace(
            user_sid=Mock(return_value=NativeFixture.identity),
            descriptor=Mock(return_value=ctypes.c_void_p(999)),
            free=Mock(),
            close=Mock(side_effect=os.close),
            adopt=Mock(side_effect=lambda handle: handle),
            error=Mock(return_value=OSError(183, "synthetic collision")),
        )

        def create(
            path: str,
            access: int,
            share: int,
            attributes: object,
            disposition: int,
            flags: int,
            template: object,
        ) -> int:
            security = ctypes.cast(attributes, ctypes.POINTER(win._SecurityAttributes)).contents
            self.assertEqual((security.descriptor, security.inherit), (999, 0))
            self.assertEqual((access, share, disposition, flags), (0x40020000, 0, 1, 0x80))
            try:
                return os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
            except FileExistsError:
                return win._INVALID_HANDLE

        def verify(handle: int, sid: str) -> None:
            self.assertEqual(os.fstat(handle).st_size, 0)
            self.assertEqual(sid, NativeFixture.identity)

        api.create = Mock(side_effect=create)
        api.verify_private = Mock(side_effect=verify)
        return api

    def test_exclusive_creation_retries_without_touching_existing_files(self) -> None:
        api = self.fixture()
        with TemporaryDirectory() as directory:
            target = Path(directory) / "artifact.bin"
            collision = target.with_name(".artifact.bin.collision")
            collision.write_bytes(b"original")
            with patch.object(win, "_WindowsApi", return_value=api):
                with patch.object(win.secrets, "token_hex", side_effect=["collision", "new"]):
                    descriptor, path = win.create_private_temp(target)
            with os.fdopen(descriptor, "wb") as stream:
                stream.write(b"synthetic")
            self.assertEqual(Path(path).read_bytes(), b"synthetic")
            self.assertEqual(collision.read_bytes(), b"original")
            api.close.assert_not_called()
            api.verify_private.assert_called_once()
            api.free.assert_called_once()

    def test_verification_or_conversion_failure_cleans_up_before_writing(self) -> None:
        for operation in ("verify_private", "adopt"):
            with TemporaryDirectory() as directory:
                api = self.fixture()
                setattr(api, operation, Mock(side_effect=OSError("synthetic failure")))
                with patch.object(win, "_WindowsApi", return_value=api):
                    with self.assertRaises(OSError):
                        win.create_private_temp(Path(directory) / "artifact.bin")
                self.assertEqual(list(Path(directory).iterdir()), [])
                api.close.assert_called_once()
                api.free.assert_called_once()

    def test_creation_error_and_exhausted_collisions_leave_no_new_files(self) -> None:
        for code, calls in ((5, 1), (183, 32)):
            api = self.fixture()
            api.create = Mock(return_value=win._INVALID_HANDLE)
            api.error = Mock(return_value=OSError(code, "synthetic failure"))
            with TemporaryDirectory() as directory:
                with patch.object(win, "_WindowsApi", return_value=api):
                    with self.assertRaises(OSError):
                        win.create_private_temp(Path(directory) / "artifact.bin")
                self.assertEqual(list(Path(directory).iterdir()), [])
            self.assertEqual(api.create.call_count, calls)
            api.close.assert_not_called()
            api.free.assert_called_once()

    def test_windows_error_code_takes_precedence_over_errno_on_every_platform(self) -> None:
        # Windows maps winerror to a different errno; exercise that distinction
        # explicitly even when the suite runs on Linux or macOS.
        for code, calls in ((5, 1), (80, 32), (183, 32)):
            with self.subTest(winerror=code):
                api = self.fixture()
                error = OSError(5, "synthetic Windows failure")
                error.winerror = code
                api.create = Mock(return_value=win._INVALID_HANDLE)
                api.error = Mock(return_value=error)
                with TemporaryDirectory() as directory:
                    with patch.object(win, "_WindowsApi", return_value=api):
                        with self.assertRaises(OSError) as raised:
                            win.create_private_temp(Path(directory) / "artifact.bin")
                    self.assertEqual(list(Path(directory).iterdir()), [])
                if calls == 1:
                    self.assertIs(raised.exception, error)
                else:
                    self.assertIsInstance(raised.exception, FileExistsError)
                self.assertEqual(api.create.call_count, calls)
                api.close.assert_not_called()
                api.verify_private.assert_not_called()
                api.adopt.assert_not_called()
                api.free.assert_called_once()

    def test_alternate_streams_are_rejected_before_native_calls(self) -> None:
        with patch.object(win, "_WindowsApi") as api:
            with self.assertRaisesRegex(OSError, "Alternate data streams"):
                win.create_private_temp(Path("artifact.bin:secret"))
            api.assert_not_called()


@unittest.skipUnless(os.name == "nt", "native Windows ACL integration")
class NativeWindowsPrivacyTests(unittest.TestCase):
    def powershell(self, command: str, **variables: str) -> list[str]:
        executable = (
            Path(os.environ["SYSTEMROOT"]) / "System32/WindowsPowerShell/v1.0/powershell.exe"
        )
        # Only test-authored scripts are called; synthetic paths are environment
        # data, never executable interpolation. No user directory ACL is changed.
        # A shared Windows runner exceeded the previous 15-second budget.
        # Allow bounded startup/inspection headroom without retrying or accepting
        # an unverified ACL. This is not a production-operation timeout.
        try:
            result = subprocess.run(  # noqa: S603
                [str(executable), "-NoProfile", "-NonInteractive", "-Command", command],
                env={**os.environ, **variables},
                capture_output=True,
                text=True,
                timeout=POWERSHELL_PROBE_TIMEOUT_SECONDS,
                check=False,
            )
        except subprocess.TimeoutExpired:
            self.fail(
                "Native Windows ACL probe exceeded "
                f"{POWERSHELL_PROBE_TIMEOUT_SECONDS}s; the ACL was not verified"
            )
        self.assertEqual(result.returncode, 0, result.stderr)
        return result.stdout.strip().splitlines()

    def assert_private_acl(self, path: str | Path) -> None:
        # Independent .NET inspection of owner, protection, allow/deny mode,
        # inheritance, grant identity, and exact rights, including final paths.
        values = self.powershell(
            "$ErrorActionPreference='Stop'; "
            "$a=[System.IO.File]::GetAccessControl($env:CPE_ATLAS_TEST_FILE); "
            "$sidType=[System.Security.Principal.SecurityIdentifier]; "
            "$rules=$a.GetAccessRules($true,$true,$sidType); "
            "$a.AreAccessRulesProtected; $rules.Count; $rules[0].IsInherited; "
            "$rules[0].IdentityReference.Value; "
            "[System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value; "
            "$a.GetOwner($sidType).Value; $rules[0].AccessControlType; "
            "[int]$rules[0].FileSystemRights",
            CPE_ATLAS_TEST_FILE=str(path),
        )
        self.assertEqual(len(values), 8, "Expected eight independent ACL verification fields")
        self.assertEqual(values[:3], ["True", "1", "False"])
        self.assertRegex(values[4], r"^S-1-\d+(?:-\d+)+$")
        self.assertEqual(values[3], values[4])
        self.assertEqual(values[5], values[4])
        self.assertEqual(values[6:], ["Allow", "2032127"])

    def test_actual_file_acl_is_protected_and_owner_only(self) -> None:
        with TemporaryDirectory() as directory:
            path = Path(directory) / "synthetic.txt"
            descriptor, temporary = win.create_private_temp(path)
            with os.fdopen(descriptor, "wb") as stream:
                self.assertFalse(os.get_inheritable(stream.fileno()))
                self.assert_private_acl(temporary)
                stream.write(b"synthetic\nbytes")
            self.assertEqual(Path(temporary).read_bytes(), b"synthetic\nbytes")
            self.assert_private_acl(temporary)

    def test_output_remains_private_after_publication_and_replacement(self) -> None:
        with TemporaryDirectory() as directory:
            path = Path(directory) / "synthetic.txt"
            private_files.write_private_bytes(path, b"one")
            self.assert_private_acl(path)
            private_files.write_private_bytes(path, b"two", replace=True)
            self.assertEqual(path.read_bytes(), b"two")
            self.assert_private_acl(path)

    def test_everyone_read_on_a_synthetic_parent_is_not_inherited_by_private_files(self) -> None:
        with TemporaryDirectory() as directory:
            # Only this newly created, synthetic-data directory gets a read
            # grant. Existing user/workspace directories are never modified.
            values = self.powershell(
                "$ErrorActionPreference='Stop'; "
                "$p=$env:CPE_ATLAS_TEST_DIRECTORY; "
                "$a=[System.IO.Directory]::GetAccessControl($p); "
                "$sid=[System.Security.Principal.SecurityIdentifier]::new('S-1-1-0'); "
                "$r=[System.Security.AccessControl.FileSystemAccessRule]::new("
                "$sid,'ReadAndExecute','ContainerInherit,ObjectInherit','None','Allow'); "
                "$a.AddAccessRule($r); [System.IO.Directory]::SetAccessControl($p,$a); "
                "$a=[System.IO.Directory]::GetAccessControl($p); "
                "$sidType=[System.Security.Principal.SecurityIdentifier]; "
                "$rules=$a.GetAccessRules($true,$true,$sidType); "
                "@($rules | Where-Object {$_.IdentityReference.Value -eq 'S-1-1-0'}).Count",
                CPE_ATLAS_TEST_DIRECTORY=directory,
            )
            self.assertEqual(values, ["1"])
            path = Path(directory) / "synthetic.txt"
            private_files.write_private_bytes(path, b"synthetic")
            self.assert_private_acl(path)
            private_files.write_private_bytes(path, b"replacement", replace=True)
            self.assert_private_acl(path)


class WindowsProbeHarnessTests(unittest.TestCase):
    """Exercise the independent probe's failure policy on every CI platform."""

    def setUp(self) -> None:
        self.probe = NativeWindowsPrivacyTests()

    def test_probe_uses_bounded_headroom_and_keeps_paths_out_of_commands(self) -> None:
        command = "Write-Output $env:CPE_ATLAS_TEST_FILE"
        synthetic_path = "synthetic path; 'quotes' & characters.txt"
        result = subprocess.CompletedProcess([], 0, stdout="one\ntwo\n", stderr="")
        with patch.dict(os.environ, {"SYSTEMROOT": "synthetic-system-root"}):
            with patch.object(subprocess, "run", return_value=result) as run:
                self.assertEqual(
                    self.probe.powershell(command, CPE_ATLAS_TEST_FILE=synthetic_path),
                    ["one", "two"],
                )
        run.assert_called_once()
        expected = Path("synthetic-system-root") / "System32/WindowsPowerShell/v1.0/powershell.exe"
        self.assertEqual(
            run.call_args.args[0],
            [str(expected), "-NoProfile", "-NonInteractive", "-Command", command],
        )
        options = run.call_args.kwargs
        self.assertEqual(options["env"]["CPE_ATLAS_TEST_FILE"], synthetic_path)
        self.assertEqual(options["timeout"], 45)
        self.assertTrue(options["capture_output"])
        self.assertTrue(options["text"])
        self.assertFalse(options["check"])
        self.assertNotIn("shell", options)

    def test_timeout_fails_without_retrying_or_certifying_permissions(self) -> None:
        error = subprocess.TimeoutExpired("synthetic probe", POWERSHELL_PROBE_TIMEOUT_SECONDS)
        with patch.dict(os.environ, {"SYSTEMROOT": "synthetic-system-root"}):
            with patch.object(subprocess, "run", side_effect=error) as run:
                with self.assertRaisesRegex(AssertionError, "45s; the ACL was not verified"):
                    self.probe.powershell("synthetic probe")
        run.assert_called_once()

    def test_nonzero_exit_fails_even_if_stdout_looks_successful(self) -> None:
        result = subprocess.CompletedProcess(
            [], 1, stdout="True\n1\nFalse\n", stderr="synthetic access denied"
        )
        with patch.dict(os.environ, {"SYSTEMROOT": "synthetic-system-root"}):
            with patch.object(subprocess, "run", return_value=result) as run:
                with self.assertRaisesRegex(AssertionError, "synthetic access denied"):
                    self.probe.powershell("synthetic probe")
        run.assert_called_once()

    def test_launch_failure_is_not_retried_or_ignored(self) -> None:
        error = OSError("synthetic probe launch failure")
        with patch.dict(os.environ, {"SYSTEMROOT": "synthetic-system-root"}):
            with patch.object(subprocess, "run", side_effect=error) as run:
                with self.assertRaises(OSError) as raised:
                    self.probe.powershell("synthetic probe")
        self.assertIs(raised.exception, error)
        run.assert_called_once()

    def test_acl_oracle_requires_every_independent_owner_only_field(self) -> None:
        sid = NativeFixture.identity
        correct = ["True", "1", "False", sid, sid, sid, "Allow", "2032127"]
        with patch.object(self.probe, "powershell", return_value=correct):
            self.probe.assert_private_acl("synthetic.txt")

        invalid_results = [correct[:length] for length in range(len(correct))]
        invalid_results.append([*correct, "unexpected field"])
        for invalid_identity in ("", "not-a-sid", "S-1-5-18 trailing-data"):
            invalid = correct.copy()
            invalid[3:6] = [invalid_identity] * 3
            invalid_results.append(invalid)
        for index, replacement in enumerate(
            ["False", "2", "True", "S-1-1-0", "S-1-1-0", "S-1-1-0", "Deny", "131209"]
        ):
            invalid = correct.copy()
            invalid[index] = replacement
            invalid_results.append(invalid)
        for invalid in invalid_results:
            with self.subTest(result=invalid):
                with patch.object(self.probe, "powershell", return_value=invalid):
                    with self.assertRaises(AssertionError):
                        self.probe.assert_private_acl("synthetic.txt")

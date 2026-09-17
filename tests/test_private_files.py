# SPDX-License-Identifier: 0BSD
from __future__ import annotations

import os
import stat
import unittest
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace
from unittest.mock import Mock, patch

from cpe_access_atlas import private_files
from cpe_access_atlas.private_files import write_private_bytes, write_private_text


@contextmanager
def mock_posix_directory() -> Iterator[tuple[Mock, Mock, Mock]]:
    """Simulate only the directory fd on Windows; temp-file IO remains real."""

    real_close = os.close

    def close_descriptor(descriptor: int) -> None:
        if descriptor != 987654:
            real_close(descriptor)

    with (
        patch.object(private_files, "_IS_WINDOWS", False),
        patch.object(private_files, "_open_sync_directory", return_value=987654) as opened,
        patch.object(private_files, "_sync_directory") as synced,
        patch.object(private_files.os, "close", side_effect=close_descriptor) as closed,
    ):
        yield opened, synced, closed


class PrivateFileTests(unittest.TestCase):
    def test_posix_creation_path_is_restricted_and_atomic(self) -> None:
        with TemporaryDirectory() as directory:
            target = Path(directory) / "synthetic.txt"
            with mock_posix_directory():
                with patch.object(
                    private_files,
                    "_restrict_permissions",
                    wraps=private_files._restrict_permissions,
                ) as restrict:
                    write_private_bytes(target, b"synthetic")
                restrict.assert_called_once()
            self.assertEqual(target.read_bytes(), b"synthetic")

    def test_windows_dispatch_does_not_substitute_chmod_for_a_native_acl(self) -> None:
        with TemporaryDirectory() as directory:
            target = Path(directory) / "synthetic.txt"
            descriptor, temporary = private_files.tempfile.mkstemp(dir=directory)
            with patch.object(private_files, "_IS_WINDOWS", True):
                with patch.object(
                    private_files, "create_private_temp", return_value=(descriptor, temporary)
                ) as native:
                    with patch.object(private_files, "_restrict_permissions") as chmod:
                        write_private_bytes(target, b"synthetic")
                native.assert_called_once_with(target)
                chmod.assert_not_called()
            self.assertEqual(target.read_bytes(), b"synthetic")

    def test_write_private_bytes_is_atomic_and_restrictive(self) -> None:
        with TemporaryDirectory() as directory:
            target = Path(directory) / "private.bin"
            write_private_bytes(target, b"first")
            self.assertEqual(target.read_bytes(), b"first")
            if os.name != "nt":
                self.assertEqual(stat.S_IMODE(target.stat().st_mode), 0o600)
            self.assertEqual(list(Path(directory).glob(".private.bin.*")), [])

            with self.assertRaises(FileExistsError):
                write_private_bytes(target, b"second")
            self.assertEqual(target.read_bytes(), b"first")

            write_private_bytes(target, b"second", replace=True)
            self.assertEqual(target.read_bytes(), b"second")

    def test_write_private_bytes_cleans_up_after_write_failure(self) -> None:
        with TemporaryDirectory() as directory:
            target = Path(directory) / "private.bin"
            with patch(
                "cpe_access_atlas.private_files.os.fdopen",
                side_effect=OSError("simulated write failure"),
            ):
                with self.assertRaisesRegex(OSError, "simulated write failure"):
                    write_private_bytes(target, b"secret")
            self.assertFalse(target.exists())
            self.assertEqual(list(Path(directory).glob(".private.bin.*")), [])

    def test_write_private_bytes_handles_racing_destination(self) -> None:
        with TemporaryDirectory() as directory:
            target = Path(directory) / "private.bin"
            real_link = os.link

            def competing_link(source: Path, destination: Path) -> None:
                destination.write_bytes(b"competing backup")
                real_link(source, destination)

            with patch("cpe_access_atlas.private_files.os.link", side_effect=competing_link):
                with self.assertRaises(FileExistsError):
                    write_private_bytes(target, b"secret")
            self.assertEqual(target.read_bytes(), b"competing backup")
            self.assertEqual(list(Path(directory).glob(".private.bin.*")), [])

    def test_unsupported_link_fails_without_publishing_or_leaving_a_temp_file(self) -> None:
        with TemporaryDirectory() as directory:
            target = Path(directory) / "private.bin"
            with patch(
                "cpe_access_atlas.private_files.os.link", side_effect=OSError("unsupported")
            ):
                with self.assertRaisesRegex(OSError, "unsupported"):
                    write_private_bytes(target, b"synthetic")
            self.assertEqual(list(Path(directory).iterdir()), [])

    def test_write_private_bytes_reports_missing_parent(self) -> None:
        with TemporaryDirectory() as directory:
            target = Path(directory) / "missing" / "private.bin"
            with self.assertRaises(FileNotFoundError):
                write_private_bytes(target, b"secret")

    def test_write_private_text_encodes_utf8(self) -> None:
        with TemporaryDirectory() as directory:
            target = Path(directory) / "private.txt"
            write_private_text(target, "şifre")
            self.assertEqual(target.read_text(encoding="utf-8"), "şifre")


class DirectorySyncTests(unittest.TestCase):
    def test_parent_descriptor_is_checked_and_synchronized_before_return(self) -> None:
        parent = Path("synthetic-parent")
        with (
            patch.object(private_files.os, "open", return_value=77) as opened,
            patch.object(
                private_files.os, "fstat", return_value=SimpleNamespace(st_mode=stat.S_IFDIR)
            ),
            patch.object(private_files.os, "fsync") as synced,
            patch.object(private_files.os, "close") as closed,
        ):
            self.assertEqual(private_files._open_sync_directory(parent), 77)
        opened.assert_called_once_with(
            parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_CLOEXEC", 0)
        )
        synced.assert_called_once_with(77)
        closed.assert_not_called()

    def test_directory_open_failure_does_not_close_an_unowned_descriptor(self) -> None:
        with (
            patch.object(private_files.os, "open", side_effect=OSError("open failed")),
            patch.object(private_files.os, "close") as closed,
        ):
            with self.assertRaisesRegex(OSError, "open failed"):
                private_files._open_sync_directory(Path("synthetic-parent"))
        closed.assert_not_called()

    def test_directory_type_and_preflight_sync_failures_close_the_descriptor(self) -> None:
        for mode, sync_error, message in (
            (stat.S_IFREG, None, "not a directory"),
            (stat.S_IFDIR, OSError("unsupported fsync"), "synchronize private output directory"),
        ):
            with (
                self.subTest(mode=mode),
                patch.object(private_files.os, "open", return_value=77),
                patch.object(private_files.os, "fstat", return_value=SimpleNamespace(st_mode=mode)),
                patch.object(private_files.os, "fsync", side_effect=sync_error) as synced,
                patch.object(private_files.os, "close") as closed,
            ):
                with self.assertRaisesRegex(OSError, message):
                    private_files._open_sync_directory(Path("synthetic-parent"))
                if mode == stat.S_IFREG:
                    synced.assert_not_called()
                else:
                    synced.assert_called_once_with(77)
                closed.assert_called_once_with(77)

    def test_preflight_failure_occurs_before_any_file_creation_or_replacement(self) -> None:
        with TemporaryDirectory() as directory:
            target = Path(directory) / "private.bin"
            target.write_bytes(b"original")
            with (
                mock_posix_directory() as (opened, _, closed),
                patch.object(private_files.tempfile, "mkstemp") as temporary,
            ):
                opened.side_effect = OSError("directory synchronization unsupported")
                with self.assertRaisesRegex(OSError, "synchronization unsupported"):
                    write_private_bytes(target, b"replacement", replace=True)
                temporary.assert_not_called()
                closed.assert_not_called()
            self.assertEqual(target.read_bytes(), b"original")
            self.assertEqual(list(Path(directory).iterdir()), [target])

    def test_publication_and_cleanup_are_synchronized_in_order(self) -> None:
        for replace in (False, True):
            with self.subTest(replace=replace):
                self.assert_publication_order(replace)

    def assert_publication_order(self, replace: bool) -> None:
        with TemporaryDirectory() as directory:
            target = Path(directory) / "private.bin"
            events: list[str] = []
            real_sync, real_link, real_replace, real_unlink = (
                os.fsync,
                os.link,
                Path.replace,
                Path.unlink,
            )

            def open_directory(parent: Path) -> int:
                self.assertEqual(parent, target.parent)
                self.assertEqual(list(parent.iterdir()), [])
                events.append("directory-preflight")
                return 987654

            def sync_file(descriptor: int) -> None:
                self.assertEqual(os.fstat(descriptor).st_size, len(b"synthetic"))
                self.assertFalse(target.exists())
                real_sync(descriptor)
                events.append("file-sync")

            def publish_link(source: Path, destination: Path) -> None:
                self.assertEqual(events[-1], "file-sync")
                real_link(source, destination)
                events.append("publish")

            def publish_replace(source: Path, destination: Path) -> Path:
                self.assertEqual(events[-1], "file-sync")
                result = real_replace(source, destination)
                events.append("publish")
                return result

            def sync_directory(descriptor: int) -> None:
                self.assertEqual(descriptor, 987654)
                self.assertEqual(target.read_bytes(), b"synthetic")
                events.append("directory-sync")

            def remove_temporary(path: Path, *, missing_ok: bool = False) -> None:
                self.assertEqual(events[-1], "directory-sync")
                self.assertNotEqual(path, target)
                real_unlink(path, missing_ok=missing_ok)
                events.append("unlink-temporary")

            with (
                mock_posix_directory() as (opened, synced, closed),
                patch.object(private_files.os, "fsync", side_effect=sync_file),
                patch.object(private_files.os, "link", side_effect=publish_link),
                patch.object(Path, "replace", new=publish_replace),
                patch.object(Path, "unlink", new=remove_temporary),
            ):
                opened.side_effect = open_directory
                synced.side_effect = sync_directory
                write_private_bytes(target, b"synthetic", replace=replace)
                closed.assert_called_once_with(987654)
            expected = ["directory-preflight", "file-sync", "publish", "directory-sync"]
            if not replace:
                expected += ["unlink-temporary", "directory-sync"]
            self.assertEqual(events, expected)
            self.assertEqual(list(target.parent.iterdir()), [target])

    def test_postpublication_sync_failures_preserve_target_and_close_directory(self) -> None:
        for replace, side_effect in (
            (False, [OSError("publication sync failed"), None]),
            (False, [None, OSError("cleanup sync failed")]),
            (True, [OSError("publication sync failed")]),
        ):
            with (
                self.subTest(replace=replace, errors=side_effect),
                TemporaryDirectory() as directory,
            ):
                target = Path(directory) / "private.bin"
                if replace:
                    target.write_bytes(b"original")
                with mock_posix_directory() as (_, synced, closed):
                    synced.side_effect = side_effect
                    with self.assertRaisesRegex(OSError, "sync failed"):
                        write_private_bytes(target, b"complete replacement", replace=replace)
                    closed.assert_called_once_with(987654)
                self.assertEqual(target.read_bytes(), b"complete replacement")
                self.assertEqual(list(target.parent.iterdir()), [target])

    def test_creation_failure_closes_directory_without_attempting_publication(self) -> None:
        with TemporaryDirectory() as directory:
            target = Path(directory) / "private.bin"
            with (
                mock_posix_directory() as (_, synced, closed),
                patch.object(
                    private_files.tempfile, "mkstemp", side_effect=OSError("creation failed")
                ),
            ):
                with self.assertRaisesRegex(OSError, "creation failed"):
                    write_private_bytes(target, b"synthetic")
                synced.assert_not_called()
                closed.assert_called_once_with(987654)
            self.assertEqual(list(target.parent.iterdir()), [])

    def test_failed_write_cleanup_synchronizes_directory_and_closes_both_descriptors(self) -> None:
        with TemporaryDirectory() as directory:
            target = Path(directory) / "private.bin"
            with (
                mock_posix_directory() as (_, synced, closed),
                patch.object(private_files.os, "fdopen", side_effect=OSError("write failed")),
            ):
                with self.assertRaisesRegex(OSError, "write failed"):
                    write_private_bytes(target, b"synthetic")
                synced.assert_called_once_with(987654)
                self.assertEqual(closed.call_count, 2)
                self.assertEqual(closed.call_args.args, (987654,))
            self.assertEqual(list(target.parent.iterdir()), [])

    def test_temporary_unlink_failure_retains_published_target_and_closes_directory(self) -> None:
        with TemporaryDirectory() as directory:
            target = Path(directory) / "private.bin"
            with (
                mock_posix_directory() as (_, synced, closed),
                patch.object(Path, "unlink", side_effect=OSError("cleanup failed")),
            ):
                with self.assertRaisesRegex(OSError, "cleanup failed"):
                    write_private_bytes(target, b"synthetic")
                synced.assert_called_once_with(987654)
                closed.assert_called_once_with(987654)
            self.assertEqual(target.read_bytes(), b"synthetic")
            self.assertEqual(len(list(target.parent.glob(".private.bin.*"))), 1)


if __name__ == "__main__":
    unittest.main()

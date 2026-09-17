# SPDX-License-Identifier: 0BSD
"""Small helpers for writing local artifacts that may contain secrets."""

from __future__ import annotations

import os
import stat
import tempfile
from pathlib import Path

from .windows_private import create_private_temp

_PRIVATE_MODE = stat.S_IRUSR | stat.S_IWUSR
_IS_WINDOWS = os.name == "nt"


def _restrict_permissions(path: Path) -> None:
    """POSIX mode restriction; Windows ACLs are installed at file creation."""

    path.chmod(_PRIVATE_MODE)


def _sync_directory(descriptor: int) -> None:
    """Request directory-entry durability; unsupported filesystems fail closed."""

    try:
        os.fsync(descriptor)
    except OSError as exc:
        raise OSError("unable to synchronize private output directory") from exc


def _open_sync_directory(path: Path) -> int:
    """Check POSIX directory synchronization before creating a private artifact."""

    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_CLOEXEC", 0)
    descriptor = os.open(path, flags)
    try:
        if not stat.S_ISDIR(os.fstat(descriptor).st_mode):
            raise OSError("private output parent is not a directory")
        _sync_directory(descriptor)
    except BaseException:
        os.close(descriptor)
        raise
    return descriptor


def write_private_bytes(
    path: str | Path,
    data: bytes,
    *,
    replace: bool = False,
) -> None:
    """Atomically write bytes with restrictive permissions.

    The destination directory must already exist.  A temporary file in that
    directory is used so an interrupted write cannot leave a truncated
    credential-bearing artifact at the destination.

    Publishing without replacement uses an atomic hard link, not a separate
    existence check followed by replacement. Filesystems without hard-link
    support fail closed; a private local NTFS/APFS/ext4 directory is suitable.
    POSIX publication and temporary-name cleanup synchronize the parent
    directory. A synchronization error is reported even if publication has
    already succeeded; the published target is retained in that case.
    """

    target = Path(path)
    if target.exists() and not replace:
        raise FileExistsError(target)

    temporary: Path | None = None
    descriptor: int | None = None
    directory_descriptor: int | None = None
    try:
        if _IS_WINDOWS:
            descriptor, temporary_name = create_private_temp(target)
        else:
            directory_descriptor = _open_sync_directory(target.parent)
            descriptor, temporary_name = tempfile.mkstemp(
                prefix=f".{target.name}.",
                dir=str(target.parent),
            )
        temporary = Path(temporary_name)
        if not _IS_WINDOWS:
            _restrict_permissions(temporary)
        with os.fdopen(descriptor, "wb") as stream:
            descriptor = None
            # This deliberate sink is restricted to explicit local artifacts;
            # callers never print the content and the file is permission-restricted.
            # codeql[py/clear-text-storage-sensitive-data]
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        if replace:
            temporary.replace(target)
            temporary = None
        else:
            # The filesystem rejects an occupied name atomically, including a
            # file or symlink created since the initial user-friendly check.
            # Both names refer to the already flushed, permission-restricted
            # inode; finally removes only our temporary name.
            os.link(temporary, target)
        if directory_descriptor is not None:
            _sync_directory(directory_descriptor)
    finally:
        try:
            if descriptor is not None:
                os.close(descriptor)
        finally:
            try:
                if temporary is not None:
                    temporary.unlink(missing_ok=True)
                    if directory_descriptor is not None:
                        _sync_directory(directory_descriptor)
            finally:
                if directory_descriptor is not None:
                    os.close(directory_descriptor)


def write_private_text(
    path: str | Path,
    value: str,
    *,
    replace: bool = False,
) -> None:
    """Atomically write UTF-8 text with restrictive permissions."""

    write_private_bytes(path, value.encode("utf-8"), replace=replace)

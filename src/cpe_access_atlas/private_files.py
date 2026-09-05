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
    """

    target = Path(path)
    if target.exists() and not replace:
        raise FileExistsError(target)

    temporary: Path | None = None
    descriptor: int | None = None
    try:
        if _IS_WINDOWS:
            descriptor, temporary_name = create_private_temp(target)
        else:
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
    finally:
        if descriptor is not None:
            os.close(descriptor)
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def write_private_text(
    path: str | Path,
    value: str,
    *,
    replace: bool = False,
) -> None:
    """Atomically write UTF-8 text with restrictive permissions."""

    write_private_bytes(path, value.encode("utf-8"), replace=replace)

# SPDX-License-Identifier: 0BSD
"""Small helpers for writing local artifacts that may contain secrets."""

from __future__ import annotations

import os
import stat
import tempfile
from pathlib import Path

_PRIVATE_MODE = stat.S_IRUSR | stat.S_IWUSR


def _restrict_permissions(path: Path) -> None:
    """Best-effort owner-only mode for a private local artifact.

    POSIX systems enforce the mode bits. Windows keeps its directory ACL as
    the authority because Python's mode emulation does not express an
    owner-only discretionary ACL.
    """

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
    """

    target = Path(path)
    if target.exists() and not replace:
        raise FileExistsError(target)

    temporary: Path | None = None
    descriptor: int | None = None
    try:
        descriptor, temporary_name = tempfile.mkstemp(
            prefix=f".{target.name}.",
            dir=str(target.parent),
        )
        temporary = Path(temporary_name)
        _restrict_permissions(temporary)
        with os.fdopen(descriptor, "wb") as stream:
            descriptor = None
            # This deliberate sink is restricted to explicit local artifacts;
            # callers never print the content and the file is mode-restricted.
            # codeql[py/clear-text-storage-sensitive-data]
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        if target.exists() and not replace:
            raise FileExistsError(target)
        temporary.replace(target)
        temporary = None
        _restrict_permissions(target)
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

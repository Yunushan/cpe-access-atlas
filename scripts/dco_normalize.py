# SPDX-License-Identifier: 0BSD
"""Recover a sign-off collapsed onto the summary by a single-line squash merge.

A squash merge can serialize the whole commit body as a single physical line,
gluing the retained "Signed-off-by:" trailer onto the end of the prose and
removing the blank line that marked the trailer block. ``git interpret-trailers``
then no longer sees a trailer, so the DCO gate fails on a correctly signed commit.

This normalizer recovers the trailer only for the narrow, recognizable squash
shape:

* the message has a real subject line and a blank line;
* the body is exactly one nonempty physical line (the collapsed shape), which
  shares the subject's leading words (GitHub repeats the summary); and
* that line ends with a whitespace-separated, well-formed
  "Signed-off-by: Name <email>".

Anything else -- an ordinary trailer block, a multi-line body, prose that merely
mentions the key, or a glued "NotSigned-off-by:" key -- is left untouched. The
recovered trailer must still match the commit author email in the
``dco-signoff.awk`` matcher, so this never turns an unsigned commit into a pass.

Reads one commit message on stdin and writes the normalized message on stdout.
"""

from __future__ import annotations

import re
import sys

_SUBJECT_PR_NUMBER = re.compile(r"\s*\(#\d+\)\s*$")
# A flattened trailer: some non-space content, whitespace, the exact key, a name,
# and a bracketed address. The lookbehind guarantees prose precedes the key, so a
# sign-off at the very start of the body is never promoted.
_TRAILER = re.compile(r"(?<=\S)[ \t]+Signed-off-by:[^<>\n]*<[^<>\n]+>[ \t]*$")
_LEADING_V = re.compile(r"^v(?=\d)")


def _words(value: str) -> list[str]:
    words = " ".join(_SUBJECT_PR_NUMBER.sub("", value).split()).casefold().split()
    # GitHub may keep a "v" version prefix in the subject but not the repeated
    # body line (or vice versa); ignore that cosmetic difference.
    return [_LEADING_V.sub("", word) for word in words]


def _shares_subject_prefix(subject: str, body: str) -> bool:
    subject_words = _words(subject)
    body_words = _words(body)
    if len(subject_words) < 2:
        return False
    window = min(len(subject_words), 6)
    return body_words[:window] == subject_words[:window]


def normalize(message: str) -> str:
    lines = message.split("\n")
    if len(lines) < 3 or lines[1].strip() != "" or not lines[0].strip():
        return message
    body = [line for line in lines[2:] if line.strip()]
    # The collapsed shape is a single nonempty body line; a normal trailer block
    # already parses and a multi-line body must never be rewritten.
    if len(body) != 1:
        return message
    joined = body[0]
    if not _shares_subject_prefix(lines[0], joined):
        return message
    recovered = _TRAILER.search(joined)
    if recovered is None:
        return message
    prose = joined[: recovered.start()].rstrip()
    trailer = joined[recovered.start() :].strip()
    return "\n".join([lines[0], "", prose, trailer])


def main() -> int:
    sys.stdout.write(normalize(sys.stdin.read()))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

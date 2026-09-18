# SPDX-License-Identifier: 0BSD
"""Validate release metadata without creating a tag or publishing assets."""

from __future__ import annotations

import argparse
import html
import re
import sys
from datetime import date
from pathlib import Path

from cpe_access_atlas import __version__

_RELEASE_NUMBER = r"(?:0|[1-9][0-9]*)"
_RELEASE_VERSION = (
    rf"{_RELEASE_NUMBER}\.{_RELEASE_NUMBER}\.{_RELEASE_NUMBER}"
    rf"(?:(?:a|b|rc){_RELEASE_NUMBER})?"
    rf"(?:\.post{_RELEASE_NUMBER})?"
    rf"(?:\.dev{_RELEASE_NUMBER})?"
)
_RELEASE_TAG = re.compile(rf"v(?P<version>{_RELEASE_VERSION})")
_CHANGELOG_HEADING = re.compile(r"## (?P<version>\S+) - (?P<state>[^\r\n]+)")
_CHANGELOG_PREAMBLE = (
    "# Changelog",
    "",
    "All notable changes are documented here.",
    "",
)
_PHYSICAL_LINE_BREAK = re.compile(r"\r\n|\r|\n")
_MARKDOWN_ESCAPE = re.compile(r"""\\([!"#$%&'()*+,\-./:;<=>?@\[\]\\^_`{|}~])""")
_ATX_H2 = re.compile(r" {0,3}##(?:[ \t]+(?P<text>.*)|[ \t]*)")
_SETEXT_H2 = re.compile(r" {0,3}-+[ \t]*")


def _normalized_markdown_text(value: str) -> str:
    return _MARKDOWN_ESCAPE.sub(r"\1", html.unescape(value))


def _starts_with_version(value: str, release_version: str) -> bool:
    return re.match(rf"{re.escape(release_version)}(?![0-9A-Za-z.])", value.strip()) is not None


def _heading_like_version(line: str, following: str | None, release_version: str) -> bool:
    normalized = _normalized_markdown_text(line)
    atx = _ATX_H2.fullmatch(normalized)
    if atx is not None:
        text = re.sub(r"[ \t]+#+[ \t]*$", "", atx.group("text") or "")
        return _starts_with_version(text, release_version)
    stripped = normalized.lstrip(" ")
    if len(normalized) - len(stripped) <= 3 and stripped.casefold().startswith("<h2"):
        opening_end = stripped.find(">")
        closing_start = stripped.casefold().rfind("</h2>")
        if opening_end >= 3 and (len(stripped) == 3 or stripped[3] in " \t>"):
            content_end = closing_start if closing_start > opening_end else len(stripped)
            return _starts_with_version(stripped[opening_end + 1 : content_end], release_version)
    return (
        following is not None
        and _SETEXT_H2.fullmatch(following) is not None
        and (_starts_with_version(normalized, release_version))
    )


def _release_states(changelog_text: str, release_version: str) -> list[str]:
    """Return raw exact headings only when the candidate occupies the fixed top slot."""

    lines = _PHYSICAL_LINE_BREAK.split(changelog_text)
    heading_index = len(_CHANGELOG_PREAMBLE)
    if tuple(lines[:heading_index]) != _CHANGELOG_PREAMBLE or len(lines) <= heading_index:
        return []
    top_heading = _CHANGELOG_HEADING.fullmatch(lines[heading_index])
    if top_heading is None or top_heading.group("version") != release_version:
        return []
    headings = 0
    for index, line in enumerate(lines):
        following = lines[index + 1] if index + 1 < len(lines) else None
        if _heading_like_version(line, following, release_version):
            headings += 1
        if headings == 2:
            break
    return [top_heading.group("state")] * headings


def validate_release_candidate(
    release_tag: str, package_version: str, changelog_text: str
) -> tuple[str, ...]:
    """Return every release-metadata error found in the candidate."""

    errors: list[str] = []
    match = _RELEASE_TAG.fullmatch(release_tag)
    if match is None:
        return (f"release tag {release_tag!r} is not a supported vX.Y.Z version",)

    release_version = match.group("version")
    if release_version != package_version:
        errors.append(
            f"release tag {release_tag} does not match package version v{package_version}"
        )

    states = _release_states(changelog_text, release_version)
    if not states:
        errors.append(f"CHANGELOG.md has no exact heading for release {release_version}")
    elif len(states) > 1:
        errors.append(f"CHANGELOG.md has duplicate headings for release {release_version}")
    elif states[0] == "Unreleased":
        errors.append(f"CHANGELOG.md still marks release {release_version} as Unreleased")
    else:
        try:
            parsed_date = date.fromisoformat(states[0])
        except ValueError:
            errors.append(
                f"CHANGELOG.md release {release_version} must use an ISO date, not {states[0]!r}"
            )
        else:
            if parsed_date.isoformat() != states[0]:
                errors.append(f"CHANGELOG.md release {release_version} must use a dashed ISO date")
            elif parsed_date > date.today():
                errors.append(f"CHANGELOG.md release {release_version} cannot use a future date")
    return tuple(errors)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Check package version and release-ready changelog metadata."
    )
    parser.add_argument("--tag", required=True, help="Expected annotated release tag, including v")
    parser.add_argument("--changelog", type=Path, default=Path("CHANGELOG.md"))
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        changelog_text = args.changelog.read_text(encoding="utf-8")
    except OSError:
        print("Release candidate check failed: CHANGELOG.md is unreadable.", file=sys.stderr)
        return 2

    errors = validate_release_candidate(args.tag, __version__, changelog_text)
    if errors:
        for error in errors:
            print(f"Release candidate check failed: {error}.", file=sys.stderr)
        return 1
    print(f"Release candidate {args.tag} has exact, dated package and changelog metadata.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

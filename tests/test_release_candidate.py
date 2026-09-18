# SPDX-License-Identifier: 0BSD
"""Release-candidate metadata validation tests."""

from __future__ import annotations

import io
import subprocess
import sys
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from tempfile import TemporaryDirectory

from scripts import check_release_candidate as candidate

ROOT = Path(__file__).parents[1]
PREAMBLE = "# Changelog\n\nAll notable changes are documented here.\n\n"


def changelog(heading: str, suffix: str = "", newline: str = "\n") -> str:
    text = f"{PREAMBLE}{heading}\n{suffix}"
    return text.replace("\n", newline)


class ReleaseCandidateValidationTests(unittest.TestCase):
    def test_exact_dated_first_heading_passes_with_physical_newline_styles(self) -> None:
        for newline in ("\n", "\r\n", "\r"):
            with self.subTest(newline=repr(newline)):
                self.assertEqual(
                    candidate.validate_release_candidate(
                        "v1.2.3rc4",
                        "1.2.3rc4",
                        changelog("## 1.2.3rc4 - 2026-09-18", newline=newline),
                    ),
                    (),
                )

    def test_malformed_tag_is_rejected_before_heading_checks(self) -> None:
        for release_tag in ("1.2.3", "v01.02.003rc04"):
            with self.subTest(release_tag=release_tag):
                self.assertEqual(
                    candidate.validate_release_candidate(release_tag, "1.2.3", ""),
                    (f"release tag {release_tag!r} is not a supported vX.Y.Z version",),
                )

    def test_version_mismatch_and_required_first_heading_are_reported_together(self) -> None:
        errors = candidate.validate_release_candidate(
            "v1.2.3", "1.2.4", changelog("## 1.2.30 - 2026-09-18")
        )
        self.assertEqual(len(errors), 2)
        self.assertIn("does not match package version", errors[0])
        self.assertIn("no exact heading", errors[1])

    def test_unreleased_duplicate_and_invalid_dates_are_rejected(self) -> None:
        cases = (
            (changelog("## 1.2.3 - Unreleased"), "still marks"),
            (
                changelog("## 1.2.3 - 2026-09-18", "## 1.2.3 - 2026-09-19\n"),
                "duplicate headings",
            ),
            (changelog("## 1.2.3 - September 18, 2026"), "must use an ISO date"),
        )
        for text, message in cases:
            with self.subTest(message=message):
                errors = candidate.validate_release_candidate("v1.2.3", "1.2.3", text)
                self.assertEqual(len(errors), 1)
                self.assertIn(message, errors[0])

    def test_compact_and_future_dates_are_rejected(self) -> None:
        for state, expected in (("20260918", "dashed ISO date"), ("9999-12-31", "future date")):
            with self.subTest(state=state):
                errors = candidate.validate_release_candidate(
                    "v1.2.3", "1.2.3", changelog(f"## 1.2.3 - {state}")
                )
                self.assertEqual(len(errors), 1)
                self.assertIn(expected, errors[0])

    def test_hidden_or_displaced_heading_cannot_satisfy_required_top_slot(self) -> None:
        cases = (
            "```markdown\n## 1.2.3 - 2026-09-18\n```\n",
            "<!--\n## 1.2.3 - 2026-09-18\n-->\n",
            "paragraph\n<x>\n## 1.2.3 - 2026-09-18\n",
            f"{PREAMBLE}intro\n\n## 1.2.3 - 2026-09-18\n",
            "# Wrong preamble\n\nAll notable changes are documented here.\n\n"
            "## 1.2.3 - 2026-09-18\n",
        )
        for text in cases:
            with self.subTest(text=text):
                errors = candidate.validate_release_candidate("v1.2.3", "1.2.3", text)
                self.assertEqual(len(errors), 1)
                self.assertIn("no exact heading", errors[0])

    def test_any_heading_like_duplicate_is_rejected_even_when_hidden_or_noncanonical(self) -> None:
        duplicates = (
            "```markdown\n## 1.2.3 - Unreleased\n```\n",
            "<!--\n## 1.2.3 - Unreleased\n-->\n",
            "<pre>\n## 1.2.3 - Unreleased\n</pre>\n",
            "paragraph\n<x>\n## 1.2.3 - Unreleased\n\n",
            "<x <invalid>\n## 1.2.3 - Unreleased\n\n",
            " ## 1.2.3 - Unreleased\n",
            "   ## 1.2.3 - Unreleased\n",
            "## 1.2.3 - Unreleased ##\n",
            "1.2.3 - Unreleased\n------------------\n",
            "<h2>1.2.3 - Unreleased</h2>\n",
            "<h2>1.2.3 - Unreleased\n",
            "## 1&#46;2&#46;3 - Unreleased\n",
            "## 1\\.2\\.3 - Unreleased\n",
        )
        for suffix in duplicates:
            with self.subTest(suffix=suffix):
                errors = candidate.validate_release_candidate(
                    "v1.2.3",
                    "1.2.3",
                    changelog("## 1.2.3 - 2026-09-18", suffix),
                )
                self.assertEqual(len(errors), 1)
                self.assertIn("duplicate headings", errors[0])

        prose = changelog("## 1.2.3 - 2026-09-18", "- The 1.2.3 wheel is reproducible.\n")
        self.assertEqual(candidate.validate_release_candidate("v1.2.3", "1.2.3", prose), ())

        malformed_nonheading = changelog(
            "## 1.2.3 - 2026-09-18", "<h2\n<h20>1.2.3 - not a heading</h20>\n"
        )
        self.assertEqual(
            candidate.validate_release_candidate("v1.2.3", "1.2.3", malformed_nonheading), ()
        )

    def test_unicode_separators_are_not_treated_as_markdown_line_breaks(self) -> None:
        for separator in ("\u0085", "\u2028", "\u2029", "\v", "\f"):
            with self.subTest(separator=repr(separator)):
                text = PREAMBLE.rstrip("\n") + separator + "## 1.2.3 - 2026-09-18\n"
                errors = candidate.validate_release_candidate("v1.2.3", "1.2.3", text)
                self.assertEqual(len(errors), 1)
                self.assertIn("no exact heading", errors[0])

    def test_hostile_nonheading_line_has_a_bounded_linear_scan(self) -> None:
        code = (
            "from scripts.check_release_candidate import validate_release_candidate as v; "
            f"prefix={PREAMBLE!r}+'## 1.2.3 - 2026-09-18\\n'; "
            "text=prefix+'<x '+('\\\"'*100000)+'<\\n'; "
            "assert v('v1.2.3', '1.2.3', text) == ()"
        )
        subprocess.run(  # noqa: S603 - current test interpreter is trusted.
            [sys.executable, "-c", code],
            cwd=ROOT,
            check=True,
            capture_output=True,
            text=True,
            timeout=3,
        )

    def test_cli_success_failure_and_unreadable_changelog(self) -> None:
        with TemporaryDirectory() as directory:
            path = Path(directory) / "CHANGELOG.md"
            path.write_text(changelog(f"## {candidate.__version__} - 2026-09-18"), encoding="utf-8")
            out, err = io.StringIO(), io.StringIO()
            with redirect_stdout(out), redirect_stderr(err):
                code = candidate.main(
                    ["--tag", f"v{candidate.__version__}", "--changelog", str(path)]
                )
            self.assertEqual(code, 0)
            self.assertIn("exact, dated", out.getvalue())
            self.assertEqual(err.getvalue(), "")

            path.write_text(changelog(f"## {candidate.__version__} - Unreleased"), encoding="utf-8")
            out, err = io.StringIO(), io.StringIO()
            with redirect_stdout(out), redirect_stderr(err):
                code = candidate.main(
                    ["--tag", f"v{candidate.__version__}", "--changelog", str(path)]
                )
            self.assertEqual(code, 1)
            self.assertEqual(out.getvalue(), "")
            self.assertIn("still marks", err.getvalue())

            err = io.StringIO()
            with redirect_stderr(err):
                code = candidate.main(
                    [
                        "--tag",
                        f"v{candidate.__version__}",
                        "--changelog",
                        str(path) + ".missing",
                    ]
                )
            self.assertEqual(code, 2)
            self.assertIn("unreadable", err.getvalue())

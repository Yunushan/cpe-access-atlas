# SPDX-License-Identifier: 0BSD
"""Ensure the committed CLI reference doc matches the live argparse definition."""

from __future__ import annotations

import argparse
import io
import sys
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

from scripts import generate_cli_reference as reference


class CliReferenceTests(unittest.TestCase):
    @unittest.skipUnless(
        sys.version_info[:2] == (3, 14),
        "argparse help formatting differs across Python versions; "
        "the committed reference is generated from Python 3.14",
    )
    def test_generated_reference_matches_committed_doc(self) -> None:
        self.assertTrue(reference._OUTPUT_PATH.exists(), "CLI reference missing; run the generator")
        committed = reference._OUTPUT_PATH.read_text(encoding="utf-8")
        self.assertEqual(
            committed,
            reference.render(),
            "docs/cli-reference.md is stale; run "
            "'python scripts/generate_cli_reference.py' and commit the result",
        )

    def test_parser_without_subcommands_and_empty_action_list(self) -> None:
        for help_enabled in (False, True):
            self.assertEqual(
                reference._subparser_choices(argparse.ArgumentParser(add_help=help_enabled)), {}
            )

    def test_writer_and_check_only_paths_use_the_current_renderer(self) -> None:
        # Exercise real rendering on every supported interpreter, but compare
        # the committed file only on its canonical Python 3.14 interpreter.
        with TemporaryDirectory() as directory:
            path = Path(directory) / "reference.md"
            out, err = io.StringIO(), io.StringIO()
            with patch.object(reference, "_OUTPUT_PATH", path):
                with redirect_stdout(out), redirect_stderr(err):
                    self.assertEqual(reference.main(["--check"]), 1)
                self.assertFalse(path.exists())
                self.assertIn("stale", err.getvalue())
                with redirect_stdout(out):
                    self.assertEqual(reference.main([]), 0)
                self.assertEqual(path.read_text(encoding="utf-8"), reference.render())
                before = path.stat().st_mtime_ns
                with patch.object(sys, "argv", ["generate_cli_reference.py", "--check"]):
                    with redirect_stdout(out):
                        self.assertEqual(reference.main(), 0)
                self.assertEqual(path.stat().st_mtime_ns, before)
                self.assertIn("up to date", out.getvalue())
                path.write_text("stale content", encoding="utf-8")
                with redirect_stderr(err):
                    self.assertEqual(reference.main(["--check"]), 1)
                self.assertEqual(path.read_text(encoding="utf-8"), "stale content")

    def test_misspelled_check_option_cannot_overwrite_the_document(self) -> None:
        with patch.object(reference, "render") as render, redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit) as error:
                reference.main(["--chekc"])
        self.assertEqual(error.exception.code, 2)
        render.assert_not_called()


if __name__ == "__main__":
    unittest.main()

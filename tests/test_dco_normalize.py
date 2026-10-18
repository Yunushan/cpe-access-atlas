# SPDX-License-Identifier: 0BSD
from __future__ import annotations

import io
import unittest
from unittest.mock import patch

from scripts import dco_normalize

_FLATTENED = (
    "Release the hardening (#66)\n\n"
    "Release the hardening  Advance the candidate and docs.  "
    "Signed-off-by: Example Person <person@example.test> \n"
)
_RECOVERED = (
    "Release the hardening (#66)\n\n"
    "Release the hardening  Advance the candidate and docs.\n"
    "Signed-off-by: Example Person <person@example.test>"
)


class DcoNormalizeTests(unittest.TestCase):
    def test_recovers_only_the_collapsed_squash_shape(self) -> None:
        self.assertEqual(dco_normalize.normalize(_FLATTENED), _RECOVERED)

    def test_leaves_every_other_message_untouched(self) -> None:
        untouched = (
            # Fewer than three lines, a non-blank separator, or no subject.
            "Single line\n",
            "Subject\nNonblank second line\nThird line\n",
            "\n\nBody without a subject\n",
            # A normal trailer block already parses and must not be rewritten.
            "Subject\n\nSigned-off-by: Person <person@example.test>\n",
            "Subject\n\nBody text.\n\nSigned-off-by: Person <person@example.test>\n",
            # A multi-line body is never the collapsed shape.
            "Subject (#1)\n\nSubject  Signed-off-by: Person <person@example.test>\nSecond\n",
            # A one-word subject cannot repeat as the body prefix.
            "Release\n\nRelease  Signed-off-by: Person <person@example.test>\n",
            # A single body line that does not repeat the subject.
            "Subject (#1)\n\nTotally different prose Signed-off-by: Person <person@example.test>\n",
            # A single body line that repeats the subject but has no trailer.
            "Release the hardening (#66)\n\nRelease the hardening  Advance the docs.\n",
            # A glued key or a mention is not a flattened trailer.
            "Release the hardening (#66)\n\nRelease the hardening  NotSigned-off-by: "
            "Person <person@example.test>\n",
            "Release the hardening (#66)\n\nRelease the hardening  mention "
            "Signed-off-by: Person <person@example.test> mid prose\n",
        )
        for message in untouched:
            with self.subTest(message=message):
                self.assertEqual(dco_normalize.normalize(message), message)

    def test_cli_reads_stdin_and_writes_stdout(self) -> None:
        stdout = io.StringIO()
        with (
            patch("sys.stdin", io.StringIO(_FLATTENED)),
            patch("sys.stdout", stdout),
        ):
            self.assertEqual(dco_normalize.main(), 0)
        self.assertEqual(stdout.getvalue(), _RECOVERED)


if __name__ == "__main__":
    unittest.main()

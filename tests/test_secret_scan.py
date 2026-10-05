# SPDX-License-Identifier: 0BSD
"""Exercise the exact workflow commands with the installed, pinned scanner.

The secret-scan job supplies GITLEAKS_BINARY and must run these tests. Ordinary
Python-only test environments skip them when no scanner has been requested.
Every marker is synthetic and generated inside disposable Git repositories.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import unittest
import zlib
from pathlib import Path
from tempfile import TemporaryDirectory
from textwrap import dedent

ROOT = Path(__file__).resolve().parents[1]


class SecretScanTests(unittest.TestCase):
    def setUp(self) -> None:
        scanner = os.environ.get("GITLEAKS_BINARY")
        if scanner is None:
            self.skipTest("GITLEAKS_BINARY is required by the separate secret-scan job")
        self.scanner = Path(scanner).resolve()
        self.assertTrue(self.scanner.is_file(), "Requested Gitleaks binary is unavailable")
        self.git = shutil.which("git")
        self.assertIsNotNone(self.git, "Git is required for the secret-scan regression gate")
        if os.name == "nt":
            self.bash = str(Path(self.git).parent.parent / "bin" / "bash.exe")
        else:
            self.bash = shutil.which("bash")
        self.assertTrue(self.bash and Path(self.bash).is_file(), "Bash is required")
        temporary = TemporaryDirectory(prefix="cpe-atlas-secret-scan-")
        self.addCleanup(temporary.cleanup)
        self.base = Path(temporary.name)
        self.repo = self.base / "synthetic repository"
        self.repo.mkdir()
        self.environment = os.environ.copy()
        self.environment["GIT_NO_REPLACE_OBJECTS"] = "1"
        self.environment["GIT_CONFIG_NOSYSTEM"] = "1"
        self.environment["GIT_CONFIG_GLOBAL"] = os.devnull
        self.environment["GITLEAKS_BINARY"] = self.scanner.as_posix()
        self.marker = "ATLAS_" + "TEST_ONLY_" + "X" * 24
        workflow = (ROOT / ".github/workflows/secret-scan.yml").read_text(encoding="utf-8")
        step = workflow.split("      - name: Scan complete history and current tree\n", 1)[1]
        match = re.search(r"        run: \|\n((?:          .*\n)+)", step)
        self.assertIsNotNone(match, "The workflow scan commands must be tested directly")
        self.commands = dedent(match.group(1))
        self.run_git("init", "-b", "main")
        self.run_git("config", "user.name", "Synthetic Scanner Test")
        self.run_git("config", "user.email", "scanner-test@example.invalid")
        self.run_git("config", "commit.gpgsign", "false")
        (self.repo / ".gitleaks.toml").write_text(
            "[[rules]]\n"
            'id = "synthetic-scanner-regression"\n'
            'description = "Noncredential regression marker"\n'
            "regex = '''ATLAS_TEST_ONLY_[A-Z]{24}'''\n",
            encoding="utf-8",
        )
        self.commit("Initial clean fixture")

    def run_git(self, *arguments: str, cwd: Path | None = None) -> str:
        result = subprocess.run(  # noqa: S603 -- installed Git, fixed synthetic fixture arguments
            [self.git, *arguments],
            cwd=cwd or self.repo,
            env=self.environment,
            capture_output=True,
            text=True,
            check=True,
            timeout=30,
        )
        return result.stdout.strip()

    def commit(self, message: str) -> None:
        self.run_git("add", "--all")
        self.run_git("commit", "--allow-empty", "-m", message)

    def scan(self, *, cwd: Path | None = None) -> subprocess.CompletedProcess[str]:
        return subprocess.run(  # noqa: S603 -- exact reviewed workflow with generated fixtures
            [self.bash, "-c", self.commands],
            cwd=cwd or self.repo,
            env=self.environment,
            capture_output=True,
            text=True,
            check=False,
            timeout=60,
        )

    def assert_rejected(self, result: subprocess.CompletedProcess[str]) -> None:
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertNotIn(self.marker, result.stdout + result.stderr)

    def assert_detected(self, result: subprocess.CompletedProcess[str]) -> None:
        self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
        self.assert_rejected(result)

    def test_clean_repository_passes(self) -> None:
        result = self.scan()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_deleted_marker_after_thirty_commits_is_detected(self) -> None:
        for index in range(31):
            self.commit(f"Clean fixture commit {index}")
        marker_file = self.repo / "late-marker.txt"
        marker_file.write_text(self.marker, encoding="utf-8")
        self.commit("Introduce synthetic marker beyond the API first page")
        marker_file.unlink()
        self.commit("Delete marker from final tree")
        self.assertGreater(int(self.run_git("rev-list", "--count", "HEAD")), 30)
        self.assert_detected(self.scan())

    def test_deleted_merge_only_marker_is_detected(self) -> None:
        self.run_git("switch", "-c", "side")
        (self.repo / "side.txt").write_text("clean side branch", encoding="utf-8")
        self.commit("Side branch")
        self.run_git("switch", "main")
        (self.repo / "main.txt").write_text("clean main branch", encoding="utf-8")
        self.commit("Main branch")
        self.run_git("merge", "--no-ff", "--no-commit", "side")
        marker_file = self.repo / "merge-marker.txt"
        marker_file.write_text(self.marker, encoding="utf-8")
        self.commit("Merge introduces synthetic marker absent from both parents")
        marker_file.unlink()
        self.commit("Remove merge marker from final tree")
        self.assert_detected(self.scan())

    def test_uncommitted_current_tree_marker_is_detected(self) -> None:
        (self.repo / "current-tree.txt").write_text(self.marker, encoding="utf-8")
        self.assert_detected(self.scan())

    def test_deleted_binary_attributed_marker_is_detected(self) -> None:
        (self.repo / ".gitattributes").write_text("*.txt binary\n", encoding="utf-8")
        marker_file = self.repo / "binary-attributed.txt"
        marker_file.write_text(self.marker, encoding="utf-8")
        self.commit("Introduce marker in a file Git treats as binary")
        marker_file.unlink()
        self.commit("Remove binary-attributed marker from current tree")
        self.assert_detected(self.scan())

    def test_deleted_nul_containing_marker_is_detected(self) -> None:
        marker_file = self.repo / "nul-containing.data"
        marker_file.write_bytes(b"\x00" + self.marker.encode("ascii") + b"\x00")
        self.commit("Introduce marker in a NUL-containing file")
        marker_file.unlink()
        self.commit("Remove NUL-containing marker from current tree")
        self.assert_detected(self.scan())

    def test_repository_fingerprint_ignore_fails_closed(self) -> None:
        marker_file = self.repo / "ignored-marker.txt"
        marker_file.write_text(self.marker + "\n", encoding="utf-8")
        self.commit("Introduce synthetic marker")
        introducing_commit = self.run_git("rev-parse", "HEAD")
        marker_file.unlink()
        (self.repo / ".gitleaksignore").write_text(
            f"{introducing_commit}:ignored-marker.txt:synthetic-scanner-regression:1\n",
            encoding="utf-8",
        )
        self.commit("Try to suppress a deleted marker with a repository fingerprint")
        result = self.scan()
        self.assert_rejected(result)
        self.assertIn("Repository .gitleaksignore is not allowed", result.stdout)

    def test_inline_allow_comment_does_not_hide_marker(self) -> None:
        (self.repo / "inline-allow.txt").write_text(
            self.marker + " #gitleaks:allow\n", encoding="utf-8"
        )
        self.commit("Try to suppress a synthetic marker with an inline comment")
        self.assert_detected(self.scan())

    def remove_loose_object(self, object_id: str) -> None:
        self.assertRegex(object_id, r"^[0-9a-f]{40}$")
        path = self.repo / ".git" / "objects" / object_id[:2] / object_id[2:]
        path.chmod(0o600)
        path.unlink()

    def test_missing_ancestor_fails_closed(self) -> None:
        ancestor = self.run_git("rev-parse", "HEAD")
        self.commit("Child of the object to remove")
        self.remove_loose_object(ancestor)
        self.assert_rejected(self.scan())

    def test_missing_historical_blob_fails_closed(self) -> None:
        historical = self.repo / "historical.txt"
        historical.write_text("ordinary historical fixture bytes", encoding="utf-8")
        self.commit("Historical file")
        blob = self.run_git("rev-parse", "HEAD:historical.txt")
        historical.unlink()
        self.commit("Remove historical file from final tree")
        self.remove_loose_object(blob)
        self.assert_rejected(self.scan())

    def test_corrupt_historical_blob_fails_closed(self) -> None:
        historical = self.repo / "historical.txt"
        historical.write_text("original historical fixture bytes", encoding="utf-8")
        self.commit("Historical file")
        blob = self.run_git("rev-parse", "HEAD:historical.txt")
        historical.unlink()
        self.commit("Remove historical file from final tree")
        path = self.repo / ".git" / "objects" / blob[:2] / blob[2:]
        replacement = b"different fixture bytes with an incorrect object hash"
        path.chmod(0o600)
        path.write_bytes(zlib.compress(b"blob %d\x00" % len(replacement) + replacement))
        self.assert_rejected(self.scan())

    def test_shallow_repository_fails_closed(self) -> None:
        shallow = self.base / "shallow"
        self.run_git("clone", "--depth", "1", self.repo.as_uri(), str(shallow), cwd=self.base)
        self.assertEqual(self.run_git("rev-parse", "--is-shallow-repository", cwd=shallow), "true")
        self.assert_rejected(self.scan(cwd=shallow))

    def test_nonroot_directory_fails_closed(self) -> None:
        child = self.repo / "child"
        child.mkdir()
        self.assert_rejected(self.scan(cwd=child))

    def test_missing_scanner_fails_closed(self) -> None:
        self.environment["GITLEAKS_BINARY"] = (self.base / "missing-scanner").as_posix()
        self.assert_rejected(self.scan())


if __name__ == "__main__":
    unittest.main()

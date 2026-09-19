# SPDX-License-Identifier: 0BSD
"""Exercise the actual archive gate with synthetic tar members, never user files."""

from __future__ import annotations

import io
import os
import runpy
import subprocess
import sys
import tarfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import Mock, patch

from scripts import check_sdist as sdist


class SdistTests(unittest.TestCase):
    def setUp(self) -> None:
        temporary = TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.base = Path(temporary.name)
        self.source = self.base / "reviewed-source"
        self.dist = self.base / "dist"
        self.dist.mkdir()
        self.files = {
            "pyproject.toml": b"[tool.coverage.run]\nsource = ['src/cpe_access_atlas']\n",
            "MANIFEST.in": b"synthetic manifest\n",
            "LICENSE": b"0BSD\n",
            ".gitignore": b".tmp/\n",
            ".gitleaks.toml": b"[extend]\nuseDefault = true\n",
            ".gitattributes": b"* text=auto eol=lf\n",
            ".pre-commit-config.yaml": b"repos: []\n",
            "README.md": b"synthetic\n",
            "requirements-ci.lock": b"# synthetic\n",
            "src/cpe_access_atlas/__init__.py": b"value = 'synthetic'\n",
            "src/cpe_access_atlas/data/catalog.json": b"{}\n",
            "src/cpe_access_atlas/py.typed": b"",
            "scripts/example.py": b"print('synthetic')\n",
            "tests/test_example.py": b"# synthetic test; subprocess mocked\n",
            ".github/workflows/release.yml": b"name: synthetic\n",
            "docs/release.md": b"synthetic release documentation\n",
            "schemas/example.json": b"{}\n",
        }
        for name, value in self.files.items():
            path = self.source / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(value)

    def archive(self, files: dict[str, bytes] | None = None) -> Path:
        path = self.dist / "package.tar.gz"
        with tarfile.open(path, "w:gz") as archive:
            for name, value in (files if files is not None else self.files).items():
                member = tarfile.TarInfo(f"package/{name}")
                member.size = len(value)
                archive.addfile(member, io.BytesIO(value))
        return path

    def assert_refused_before_execution(self) -> None:
        with patch.object(sdist.subprocess, "run") as run:
            with self.assertRaises((sdist.SdistError, tarfile.TarError)):
                sdist.check_sdist(self.dist, self.source)
            run.assert_not_called()

    def test_complete_archive_runs_its_own_source_tests_and_coverage(self) -> None:
        self.archive()
        commands: list[list[str]] = []
        roots: list[Path] = []

        def run(command: list[str], **kwargs: object) -> None:
            root = kwargs["cwd"]
            self.assertIsInstance(root, Path)
            self.assertTrue(root.is_dir())
            self.assertNotEqual(root, self.source)
            self.assertEqual(
                (root / "tests/test_example.py").read_bytes(), self.files["tests/test_example.py"]
            )
            self.assertEqual(kwargs["env"]["PYTHONPATH"], str(root / "src"))
            self.assertEqual(kwargs["env"]["COVERAGE_FILE"], str(root / ".coverage"))
            self.assertEqual(kwargs["env"]["CPE_ATLAS_TEST_ENV"], "preserved")
            self.assertIs(kwargs["check"], True)
            self.assertEqual(kwargs["timeout"], 300)
            self.assertNotIn("shell", kwargs)
            self.assertEqual(command[:3], [sys.executable, "-m", "coverage"])
            self.assertIn(str(root / "pyproject.toml"), command)
            roots.append(root)
            commands.append(command[3:])

        with patch.dict(
            os.environ,
            {
                "PYTHONPATH": "not-the-archive",
                "COVERAGE_FILE": "parent-coverage",
                "CPE_ATLAS_TEST_ENV": "preserved",
            },
        ):
            with (
                patch.object(sdist.subprocess, "run", side_effect=run),
                redirect_stdout(io.StringIO()) as output,
            ):
                sdist.check_sdist(self.dist, self.source)
        self.assertEqual([command[0] for command in commands], ["run", "report"])
        self.assertEqual(commands[0][3:], ["-m", "unittest", "discover", "-s", "tests", "-v"])
        self.assertTrue(all(not root.exists() for root in roots))
        self.assertIn("bundled tests and coverage passed", output.getvalue())

    def test_git_snapshot_is_used_instead_of_mutable_checkout_bytes(self) -> None:
        self.archive()
        subprocess.run(
            ["git", "init", "--quiet"],  # noqa: S607 -- isolated test repository
            cwd=self.source,
            check=True,
            timeout=30,
        )
        subprocess.run(
            ["git", "add", "."],  # noqa: S607 -- isolated test repository
            cwd=self.source,
            check=True,
            timeout=30,
        )
        subprocess.run(
            [  # noqa: S607 -- isolated synthetic test repository
                "git",
                "-c",
                "user.name=Sdist Test",
                "-c",
                "user.email=sdist-test@example.invalid",
                "commit",
                "--quiet",
                "-m",
                "reviewed source",
            ],
            cwd=self.source,
            check=True,
            timeout=30,
        )
        (self.source / "docs/release.md").write_bytes(
            self.files["docs/release.md"].replace(b"\n", b"\r\n")
        )
        (self.source / "tests/test_untracked.py").write_bytes(b"unreviewed\n")
        real_run = subprocess.run
        archive_commands: list[list[str]] = []

        def run(command: list[str], **kwargs: object) -> subprocess.CompletedProcess[bytes] | None:
            if command[0] == "git":
                return real_run(command, **kwargs)
            archive_commands.append(command)
            return None

        with (
            patch.object(sdist.subprocess, "run", side_effect=run),
            redirect_stdout(io.StringIO()) as output,
        ):
            sdist.check_sdist(self.dist, self.source, source_ref="HEAD")
        self.assertIn("matches the reviewed source", output.getvalue())
        self.assertEqual(len(archive_commands), 2)

        archive_commands.clear()
        tampered = b"changed after review\n"
        self.archive({**self.files, "docs/release.md": tampered})
        (self.source / "docs/release.md").write_bytes(tampered)
        with (
            patch.object(sdist.subprocess, "run", side_effect=run),
            self.assertRaisesRegex(sdist.SdistError, "missing or changed"),
        ):
            sdist.check_sdist(self.dist, self.source, source_ref="HEAD")
        self.assertEqual(archive_commands, [])

    def test_direct_cli_import_mode_supports_help(self) -> None:
        script = Path(sdist.__file__).resolve()
        with patch.object(sys, "path", [str(script.parent), *sys.path]):
            namespace = runpy.run_path(str(script), run_name="check_sdist_direct")
        self.assertIn("main", namespace)
        result = subprocess.run(  # noqa: S603 -- fixed current interpreter and local script
            [sys.executable, str(script), "--help"],
            cwd=script.parents[1],
            capture_output=True,
            text=True,
            check=False,
            timeout=30,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("--source-ref", result.stdout)

    def test_generated_bytecode_is_not_an_archive_requirement(self) -> None:
        for relative in (
            "tests/__pycache__/test_example.cpython.pyc",
            "scripts/loose.pyc",
            "scripts/loose.pyo",
        ):
            path = self.source / relative
            path.parent.mkdir(exist_ok=True)
            path.write_bytes(b"generated")
        self.assertEqual(
            {path.relative_to(self.source).as_posix() for path in sdist.source_inputs(self.source)},
            set(self.files),
        )

    def test_empty_test_reference_cannot_pass(self) -> None:
        (self.source / "tests/test_example.py").unlink()
        with self.assertRaisesRegex(sdist.SdistError, "no tests"):
            sdist.source_inputs(self.source)

    def test_zero_multiple_or_invalid_archives_fail_before_execution(self) -> None:
        self.assert_refused_before_execution()
        archive = self.archive()
        with patch.object(sdist.reproducible, "_MAX_SDIST_BYTES", archive.stat().st_size - 1):
            self.assert_refused_before_execution()
        (self.dist / "second.tar.gz").write_bytes(archive.read_bytes())
        self.assert_refused_before_execution()
        (self.dist / "second.tar.gz").unlink()
        archive.write_bytes(b"not a tar archive")
        self.assert_refused_before_execution()

    def test_portable_extractor_rejects_collisions_and_invalid_payloads(self) -> None:
        cases = (
            ("directory-collision", "package", True, b"existing", None, 0, "collision"),
            ("file-collision", "package/value", False, b"existing", None, 0, "collision"),
            ("missing-payload", "package/value", False, None, None, 0, "no payload"),
            ("short-payload", "package/value", False, None, b"x", 2, "invalid size"),
        )
        for label, name, directory, existing, payload, size, error in cases:
            with self.subTest(label=label):
                destination = self.base / f"extract-{label}"
                destination.mkdir()
                target = destination.joinpath(*Path(name).parts)
                if existing is not None:
                    target.parent.mkdir(parents=True, exist_ok=True)
                    target.write_bytes(existing)
                member = tarfile.TarInfo(name)
                member.type = tarfile.DIRTYPE if directory else tarfile.REGTYPE
                member.size = size
                archive = Mock()
                archive.extractfile.return_value = None if payload is None else io.BytesIO(payload)
                with (
                    patch.object(
                        sdist.reproducible,
                        "_validated_members",
                        return_value=(member,),
                    ),
                    self.assertRaisesRegex(sdist.SdistError, error),
                ):
                    sdist._extract_reviewed_archive(archive, destination)

        destination = self.base / "extract-existing-directory"
        (destination / "package").mkdir(parents=True)
        member = tarfile.TarInfo("package")
        member.type = tarfile.DIRTYPE
        with patch.object(
            sdist.reproducible,
            "_validated_members",
            return_value=(member,),
        ):
            sdist._extract_reviewed_archive(Mock(), destination)

    def test_missing_extra_or_modified_source_and_test_inputs_are_rejected(self) -> None:
        for name in self.files:
            with self.subTest(name=name, change="missing"):
                self.archive({key: value for key, value in self.files.items() if key != name})
                self.assert_refused_before_execution()
            with self.subTest(name=name, change="modified"):
                self.archive({**self.files, name: b"unexpected modification"})
                self.assert_refused_before_execution()
        for extra in (
            "tests/test_unreviewed.py",
            "scripts/unreviewed.py",
            "src/cpe_access_atlas/unreviewed.py",
            ".github/workflows/unreviewed.yml",
            "coverage.py",
            "src/sitecustomize.py",
            "tests/__pycache__/test_example.cpython-314.pyc",
            "src/cpe_access_atlas/__init__.pyc",
        ):
            with self.subTest(extra=extra):
                self.archive({**self.files, extra: b"unreviewed"})
                self.assert_refused_before_execution()

    def test_generated_package_metadata_does_not_mask_source_verification(self) -> None:
        self.archive(
            {
                **self.files,
                **{path.as_posix(): b"generated metadata" for path in sdist._GENERATED_METADATA},
            }
        )
        with patch.object(sdist.subprocess, "run") as run, redirect_stdout(io.StringIO()):
            sdist.check_sdist(self.dist, self.source)
        self.assertEqual(run.call_count, 2)

    def test_archives_with_empty_multiple_or_file_roots_fail(self) -> None:
        for roots in ([], ["one", "two"], ["only-file"]):
            with self.subTest(roots=roots):
                with tarfile.open(self.dist / "package.tar.gz", "w:gz") as archive:
                    for name in roots:
                        member = tarfile.TarInfo(name)
                        member.type = tarfile.REGTYPE if name == "only-file" else tarfile.DIRTYPE
                        archive.addfile(member)
                self.assert_refused_before_execution()

    def test_links_and_special_files_are_rejected(self) -> None:
        for kind in (tarfile.SYMTYPE, tarfile.LNKTYPE, tarfile.FIFOTYPE):
            with self.subTest(kind=kind):
                with tarfile.open(self.dist / "package.tar.gz", "w:gz") as archive:
                    member = tarfile.TarInfo("package/link")
                    member.type, member.linkname = kind, "elsewhere"
                    archive.addfile(member)
                self.assert_refused_before_execution()

    def test_data_filter_rejects_path_traversal_before_execution(self) -> None:
        self.archive({"../../outside": b"must not be written"})
        # Even a broken filter must only reach this synthetic test directory,
        # never an unrelated user's TEMP file or the repository checkout.
        with patch.object(
            sdist,
            "TemporaryDirectory",
            side_effect=lambda **kwargs: TemporaryDirectory(dir=self.base, **kwargs),
        ):
            self.assert_refused_before_execution()
        self.assertFalse((self.base / "outside").exists())

    def test_test_failure_or_timeout_prevents_reporting_and_cleans_extraction(self) -> None:
        self.archive()
        for failure in (
            subprocess.CalledProcessError(1, ["coverage"]),
            subprocess.TimeoutExpired(["coverage"], 300),
        ):
            with self.subTest(failure=failure):
                with patch.object(sdist.subprocess, "run", side_effect=failure) as run:
                    with self.assertRaises(subprocess.SubprocessError):
                        sdist.check_sdist(self.dist, self.source)
                    self.assertEqual(run.call_count, 1)
                    self.assertFalse(run.call_args.kwargs["cwd"].exists())

    def test_coverage_failure_is_not_ignored(self) -> None:
        self.archive()
        with patch.object(
            sdist.subprocess,
            "run",
            side_effect=[None, subprocess.CalledProcessError(1, ["coverage", "report"])],
        ) as run:
            with self.assertRaises(subprocess.CalledProcessError):
                sdist.check_sdist(self.dist, self.source)
            self.assertEqual(run.call_count, 2)

    def test_cli_passes_default_and_explicit_directory_and_reports_failures(self) -> None:
        with patch.dict(os.environ, {}, clear=False):
            os.environ.pop("GITHUB_SHA", None)
            with patch.object(sdist, "check_sdist") as check:
                self.assertEqual(sdist.main([]), 0)
                check.assert_called_once_with(Path("dist"), source_ref="HEAD")
        with (
            patch.dict(os.environ, {"GITHUB_SHA": "b" * 40}),
            patch.object(sdist, "check_sdist") as check,
        ):
            self.assertEqual(sdist.main([]), 0)
            check.assert_called_once_with(Path("dist"), source_ref="b" * 40)
        with patch.object(sdist, "check_sdist") as check:
            self.assertEqual(
                sdist.main(["--dist-dir", "artifacts", "--source-ref", "a" * 40]),
                0,
            )
            check.assert_called_once_with(Path("artifacts"), source_ref="a" * 40)
        for failure in (
            OSError("filesystem"),
            sdist.reproducible.ReproducibleBuildError("invalid source ref"),
            tarfile.TarError("invalid archive"),
            sdist.SdistError("mismatch"),
            subprocess.TimeoutExpired(["coverage"], 300),
        ):
            with self.subTest(failure=failure):
                with patch.object(sdist, "check_sdist", side_effect=failure):
                    with redirect_stderr(io.StringIO()) as error:
                        self.assertEqual(sdist.main([]), 1)
                self.assertIn("Source archive verification failed", error.getvalue())
        with patch.object(sdist, "check_sdist") as check, redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit):
                sdist.main(["--dist-dri", "typo"])
            check.assert_not_called()


if __name__ == "__main__":
    unittest.main()

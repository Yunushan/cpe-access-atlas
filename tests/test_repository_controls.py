from __future__ import annotations

import copy
import json
import re
import subprocess
import sys
import tomllib
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from textwrap import dedent
from types import SimpleNamespace
from unittest.mock import patch

from packaging.requirements import Requirement

from scripts import check_github_production_settings as github_audit

ROOT = Path(__file__).parents[1]
WORKFLOW_FILES = (
    ROOT / ".github" / "workflows" / "ci.yml",
    ROOT / ".github" / "workflows" / "security.yml",
    ROOT / ".github" / "workflows" / "release.yml",
    ROOT / ".github" / "workflows" / "codeql.yml",
    ROOT / ".github" / "workflows" / "dco.yml",
    ROOT / ".github" / "workflows" / "secret-scan.yml",
)


class _FakeGitHubApi:
    def __init__(self, payload: object, error: str | None = None) -> None:
        self.payload = payload
        self.error = error

    def get(self, path: str) -> tuple[object, str | None]:
        del path
        return self.payload, self.error


class _MappedGitHubApi:
    def __init__(self, responses: dict[str, object]) -> None:
        self.responses = responses

    def get(self, path: str) -> tuple[object, str | None]:
        response = self.responses[path]
        if isinstance(response, tuple):
            return response
        return response, None


def _successful_workflow_responses() -> dict[str, object]:
    sha = "a" * 40
    runs: list[dict[str, object]] = []
    responses: dict[str, object] = {}
    for run_id, (name, path) in enumerate(github_audit._WORKFLOW_PATHS.items(), start=1):
        runs.append(
            {
                "id": run_id,
                "name": name,
                "path": path,
                "head_sha": sha,
                "head_branch": "main",
                "event": "push",
                "run_attempt": 1,
                "created_at": "2026-09-05T10:00:00Z",
                "status": "completed",
                "conclusion": "success",
            }
        )
        jobs = [
            {
                "name": job,
                "run_id": run_id,
                "run_attempt": 1,
                "head_sha": sha,
                "status": "completed",
                "conclusion": "skipped" if job == "dependency-review" else "success",
            }
            for job in github_audit._WORKFLOW_CHECKS[name]
        ]
        responses[f"actions/runs/{run_id}/attempts/1/jobs?per_page=100"] = {
            "jobs": jobs,
            "total_count": len(jobs),
        }
    responses[f"actions/runs?head_sha={sha}&per_page=100"] = {
        "workflow_runs": runs,
        "total_count": len(runs),
    }
    return responses


class RepositoryControlTests(unittest.TestCase):
    def test_workflow_actions_are_commit_pinned(self) -> None:
        pattern = re.compile(r"^uses:\s+\S+@[0-9a-f]{40}(?:\s+#.*)?$")
        local_calls = {
            f"uses: ./.github/workflows/{name}.yml"
            for name in ("ci", "security", "secret-scan", "codeql")
        }
        for workflow in WORKFLOW_FILES:
            with self.subTest(workflow=workflow.name):
                uses_lines = [
                    line.strip().removeprefix("- ")
                    for line in workflow.read_text(encoding="utf-8").splitlines()
                    if line.strip().startswith(("uses:", "- uses:"))
                ]
                self.assertTrue(uses_lines)
                for line in uses_lines:
                    if line in local_calls:
                        # GitHub resolves these exact local workflow paths at
                        # the caller commit; no mutable @main/@tag exception.
                        self.assertEqual(workflow.name, "release.yml")
                    else:
                        self.assertRegex(line, pattern)

    def test_dependabot_covers_runtime_and_workflow_dependencies(self) -> None:
        config = (ROOT / ".github" / "dependabot.yml").read_text(encoding="utf-8")
        self.assertIn("package-ecosystem: pip", config)
        self.assertIn("package-ecosystem: github-actions", config)
        self.assertIn("interval: weekly", config)

    def test_ci_checks_dependency_consistency(self) -> None:
        ci = (ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
        self.assertIn("python -m pip check", ci)

        build_system = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
        match = re.search(r'requires = \["setuptools==([^\"]+)"\]', build_system)
        self.assertIsNotNone(match)
        setuptools_version = match.group(1)
        for lock_name in (
            "requirements-build.lock",
            "requirements-ci.lock",
            "requirements-release.lock",
            "requirements-security.lock",
        ):
            with self.subTest(lock_name=lock_name):
                lock = (ROOT / lock_name).read_text(encoding="utf-8")
                self.assertIn(f"setuptools=={setuptools_version}", lock)

    def test_dependency_locks_include_hashes_and_conditional_transitives(self) -> None:
        for name in ("runtime", "ci", "security", "release", "build"):
            lock = (ROOT / f"requirements-{name}.lock").read_text(encoding="utf-8")
            self.assertIn("--hash=sha256:", lock)
        runtime = (ROOT / "requirements-runtime.lock").read_text(encoding="utf-8")
        self.assertRegex(runtime, r"typing-extensions==\S+ ; python_full_version < '3.13'")
        ci = (ROOT / "requirements-ci.lock").read_text(encoding="utf-8")
        self.assertIn("pathspec==", ci)
        self.assertIn("librt==", ci)

    def test_mypy_requirement_locks_and_hook_select_the_same_supported_version(self) -> None:
        project = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
        requirement = next(
            Requirement(value)
            for value in project["project"]["optional-dependencies"]["dev"]
            if Requirement(value).name == "mypy"
        )
        versions = []
        for name in ("ci", "release"):
            lock = (ROOT / f"requirements-{name}.lock").read_text(encoding="utf-8")
            match = re.search(r"(?m)^mypy==([^\s;]+)", lock)
            self.assertIsNotNone(match, f"{name} must pin the type checker")
            versions.append(match.group(1))
            self.assertIn(match.group(1), requirement.specifier)
        self.assertEqual(versions[0], versions[1])
        hooks = (ROOT / ".pre-commit-config.yaml").read_text(encoding="utf-8")
        hook = re.search(
            r"repo: https://github\.com/pre-commit/mirrors-mypy\n"
            r"\s+rev: [0-9a-f]{40} # v([^\s]+)",
            hooks,
        )
        self.assertIsNotNone(hook, "mypy hook must have a pinned revision and version")
        self.assertEqual(hook.group(1), versions[0])

    def test_release_sbom_matrix_and_non_overwriting_publication(self) -> None:
        release = (ROOT / ".github/workflows/release.yml").read_text(encoding="utf-8")
        self.assertRegex(release, r"needs: \[[^\]\n]*\bruntime-sbom\]")
        self.assertIn('python: ["3.11", "3.12", "3.13", "3.14", "3.15"]', release)
        self.assertIn("os: [ubuntu-latest, windows-latest, macos-latest]", release)
        self.assertIn("--require-hashes", release)
        self.assertIn("--prerelease", release)
        self.assertIn("Version(__version__).is_prerelease", release)
        self.assertIn("--verify-tag", release)
        self.assertNotIn("--clobber", release)

    def test_sbom_audits_target_installed_metadata_not_the_tool_interpreter(self) -> None:
        workflow = (ROOT / ".github/workflows/release.yml").read_text(encoding="utf-8")
        job = workflow.split("  runtime-sbom:\n")[1].split("  validate-release:\n")[0]
        target = job.index("python-version: ${{ matrix.python }}")
        install = job.index(
            'pip install --require-hashes --target "${{ env.RUNTIME_DEPENDENCIES }}"'
        )
        host = job.index('python-version: "3.14"')
        audit = job.index('pip_audit --path "$RUNTIME_DEPENDENCIES" --strict')
        gate = job.index("- name: Verify SBOM matches the target inventory")
        self.assertLess(target, install)
        self.assertLess(install, host)
        self.assertLess(host, audit)
        self.assertLess(audit, gate)
        self.assertLess(gate, job.index("uses: actions/upload-artifact@"))
        self.assertNotIn("pip_audit -r", job)
        self.assertNotIn("--ignore-vuln", job)
        step = job.split("      - name: Verify SBOM matches the target inventory\n")[1]
        step = step.split("      - uses:")[0]
        code = compile(dedent(step.split("        run: |\n")[1]), "ci-sbom-inventory", "exec")
        expected = [SimpleNamespace(metadata={"Name": "rpds_py"}, version="1.2.3")]
        valid = [{"name": "rpds-py", "version": "1.2.3"}]
        for components, passes in (
            (valid, True),
            ([], False),
            (valid * 2, False),
            ([{"name": "rpds-py", "version": "9.9.9"}], False),
            ([*valid, {"name": "pip-audit", "version": "2.10.1"}], False),
        ):
            with (
                patch.dict("os.environ", {"RUNTIME_DEPENDENCIES": "target-fixture"}),
                patch("importlib.metadata.distributions", return_value=expected) as inventory,
                patch("pathlib.Path.glob", return_value=[Path("fixture.cdx.json")]),
                patch(
                    "pathlib.Path.read_text", return_value=json.dumps({"components": components})
                ),
            ):
                if passes:
                    exec(code, {})  # noqa: S102 -- reviewed verifier, mocked synthetic inventory
                else:
                    with self.assertRaisesRegex(RuntimeError, "exactly match"):
                        exec(code, {})  # noqa: S102 -- reviewed verifier, mocked synthetic inventory
                inventory.assert_called_once_with(path=["target-fixture"])
        for inventory, files in (
            ([], [Path("fixture")]),
            (expected, []),
            (expected, [Path("f")] * 2),
        ):
            with (
                patch.dict("os.environ", {"RUNTIME_DEPENDENCIES": "target-fixture"}),
                patch("importlib.metadata.distributions", return_value=inventory),
                patch("pathlib.Path.glob", return_value=files),
            ):
                with self.assertRaisesRegex(RuntimeError, "nonempty target inventory"):
                    exec(code, {})  # noqa: S102 -- reviewed verifier, mocked synthetic inventory

    def test_publication_requires_same_commit_ci_and_security_workflows(self) -> None:
        release = (ROOT / ".github/workflows/release.yml").read_text(encoding="utf-8")
        jobs = dict(
            re.findall(r"(?ms)^  ([\w-]+):\n(.*?)(?=^  [\w-]+:|\Z)", release.split("jobs:\n", 1)[1])
        )
        calls = {
            "source-validation": "ci",
            "dependency-validation": "security",
            "secret-validation": "secret-scan",
            "codeql-validation": "codeql",
        }
        for job, workflow in calls.items():
            block = jobs[job]
            self.assertIn(f"    uses: ./.github/workflows/{workflow}.yml\n", block)
            self.assertNotRegex(block, r"(?m)^    (?:if|continue-on-error|secrets):")
            self.assertIn("      contents: read", block)
            self.assertNotIn("contents: write", block)
            self.assertNotIn("id-token:", block)
            self.assertNotIn("attestations:", block)
            called = (ROOT / f".github/workflows/{workflow}.yml").read_text(encoding="utf-8")
            self.assertRegex(called, r"(?m)^  workflow_call:\s*$")
            self.assertNotIn("continue-on-error:", called)
        publication = jobs["validate-release"]
        needs = re.search(r"(?m)^    needs: \[([^\]]+)\]$", publication)
        self.assertIsNotNone(needs)
        self.assertEqual(
            {item.strip() for item in needs.group(1).split(",")}, {*calls, "runtime-sbom"}
        )
        self.assertNotRegex(publication, r"(?m)^    (?:if|continue-on-error):")
        self.assertIn("      security-events: write", jobs["codeql-validation"])
        self.assertIn("      pull-requests: read", jobs["dependency-validation"])
        ci = (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
        self.assertIn('python: ["3.11", "3.12", "3.13", "3.14", "3.15"]', ci)
        self.assertIn("os: [ubuntu-latest, windows-latest, macos-latest]", ci)

    def test_actual_built_archive_is_checked_before_package_install_or_publication(self) -> None:
        for name in ("ci", "release"):
            workflow = (ROOT / f".github/workflows/{name}.yml").read_text(encoding="utf-8")
            gate = workflow.index("python scripts/check_sdist.py --dist-dir dist")
            self.assertLess(workflow.index("python -m build --wheel --sdist --no-isolation"), gate)
            self.assertLess(gate, workflow.index("- name: Install wheel in a clean"))
        release = (ROOT / ".github/workflows/release.yml").read_text(encoding="utf-8")
        self.assertLess(
            release.index("python scripts/check_sdist.py"), release.index("gh release create")
        )

    def test_actual_release_classification_command_handles_preview_versions(self) -> None:
        # Execute the test-reviewed workflow's Python classification command,
        # not a reimplementation of it. Only synthetic local package metadata
        # is supplied; this command neither invokes gh nor publishes a release.
        release = (ROOT / ".github/workflows/release.yml").read_text(encoding="utf-8")
        line = next(
            line.strip()
            for line in release.splitlines()
            if line.strip().startswith('prerelease="$(python -c ')
        )
        self.assertTrue(line.endswith("')\""))
        code = line.removeprefix("prerelease=\"$(python -c '").removesuffix("')\"")
        for status, version, expected in (
            ("3 - Alpha", "0.4.0", "true"),
            ("4 - Beta", "0.4.0", "true"),
            ("5 - Production/Stable", "0.4.0", "false"),
            ("6 - Mature", "0.4.0", "false"),
            ("5 - Production/Stable", "0.4.0rc1", "true"),
            ("5 - Production/Stable", "0.4.0.dev1", "true"),
        ):
            with self.subTest(status=status, version=version), TemporaryDirectory() as directory:
                root = Path(directory)
                (root / "pyproject.toml").write_text(
                    f'[project]\nclassifiers=["Development Status :: {status}"]\n', encoding="utf-8"
                )
                (root / "cpe_access_atlas.py").write_text(
                    f"__version__ = {version!r}\n", encoding="utf-8"
                )
                result = subprocess.run(  # noqa: S603 -- reviewed classification only; no publishing command
                    [sys.executable, "-c", code],
                    cwd=root,
                    capture_output=True,
                    text=True,
                    timeout=15,
                    check=False,
                )
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(result.stdout.strip(), expected)

    def test_ci_and_release_enforce_formatting_and_type_checks(self) -> None:
        ci = (ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
        release = (ROOT / ".github" / "workflows" / "release.yml").read_text(encoding="utf-8")
        for workflow_text in (ci, release):
            self.assertIn("ruff format --check", workflow_text)
            self.assertIn("mypy src scripts", workflow_text)

    def test_quality_gates_cover_runtime_and_maintenance_scripts(self) -> None:
        project = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
        self.assertTrue(project["tool"]["mypy"]["strict"])
        self.assertEqual(project["tool"]["mypy"]["files"], ["src", "scripts"])
        coverage = project["tool"]["coverage"]
        self.assertEqual(coverage["run"]["source"], ["src/cpe_access_atlas", "scripts"])
        self.assertTrue(coverage["run"]["branch"])
        self.assertEqual(coverage["report"]["fail_under"], 100)

    def test_security_audits_locked_dependencies_without_local_project(self) -> None:
        security = (ROOT / ".github" / "workflows" / "security.yml").read_text(encoding="utf-8")
        self.assertIn("-r requirements-security.lock", security)
        self.assertIn("--strict", security)
        self.assertNotIn("--local", security)

    def test_vendor_crypto_is_not_misclassified_or_silently_suppressed(self) -> None:
        config = (ROOT / "src" / "cpe_access_atlas" / "config.py").read_text(encoding="utf-8")
        self.assertNotIn("codeql[py/weak-sensitive-data-hashing]", config)
        self.assertNotIn("usedforsecurity=False", config)
        self.assertIn("docs/config-cryptography.md", config)
        self.assertTrue((ROOT / "docs/config-cryptography.md").is_file())

    def test_distribution_builds_reuse_hash_verified_backend_without_index_access(self) -> None:
        for name, lock in (("ci", "ci"), ("release", "release")):
            workflow = (ROOT / f".github/workflows/{name}.yml").read_text(encoding="utf-8")
            with self.subTest(workflow=name):
                builds = re.findall(r"^\s+run: (python -m build .+)$", workflow, re.MULTILINE)
                expected_count = 2 if name == "ci" else 1
                self.assertEqual(
                    builds, ["python -m build --wheel --sdist --no-isolation"] * expected_count
                )
                hash_verified_builds = re.findall(
                    r'PIP_NO_INDEX: "1"\s+run: python -m build --wheel --sdist --no-isolation',
                    workflow,
                )
                self.assertEqual(len(hash_verified_builds), expected_count)
                self.assertLess(
                    workflow.index(f"pip install --require-hashes -r requirements-{lock}.lock"),
                    workflow.index(builds[0]),
                )

    def test_python_support_metadata_workflows_and_audit_policy_agree(self) -> None:
        project = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
        prefix = "Programming Language :: Python :: 3."
        versions = tuple(
            entry.rsplit(" :: ", 1)[-1]
            for entry in project["project"]["classifiers"]
            if entry.startswith(prefix)
        )
        self.assertEqual(versions, ("3.11", "3.12", "3.13", "3.14", "3.15"))
        self.assertEqual(github_audit._RELEASE_PYTHONS, versions)
        self.assertEqual(project["project"]["requires-python"], ">=3.11")
        for name in ("ci", "release"):
            workflow = (ROOT / f".github/workflows/{name}.yml").read_text(encoding="utf-8")
            matrix = re.search(r"(?m)^        python: (\[.*\])$", workflow)
            self.assertIsNotNone(matrix)
            self.assertEqual(tuple(json.loads(matrix.group(1))), versions)
            self.assertIn("allow-prereleases: ${{ matrix.python == '3.15' }}", workflow)
            self.assertNotIn("continue-on-error:", workflow)
        for system in ("ubuntu-latest", "windows-latest", "macos-latest"):
            check = f"test ({system}, 3.15)"
            self.assertIn(check, github_audit._REQUIRED_BRANCH_CHECKS)
            responses = _successful_workflow_responses()
            jobs = responses["actions/runs/1/attempts/1/jobs?per_page=100"]
            jobs["jobs"] = [job for job in jobs["jobs"] if job["name"] != check]
            jobs["total_count"] = len(jobs["jobs"])
            result = github_audit._audit_current_checks(_MappedGitHubApi(responses), "a" * 40)
            self.assertEqual(result.status, github_audit.STATUS_FAIL)
            self.assertIn(check, result.detail)

    def test_actual_python315_clean_install_step_is_portable_and_fail_closed(self) -> None:
        # Execute only this reviewed, local workflow block with subprocesses mocked.
        workflow = (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
        step = workflow.split(
            "      - name: Install Python 3.15 artifacts in clean environments\n"
        )[1]
        step = step.split("\n  package-smoke:")[0]
        self.assertIn("        if: matrix.python == '3.15'\n", step)
        self.assertIn("        shell: python\n", step)
        code = compile(dedent(step.split("        run: |\n")[1]), "ci-artifact-smoke", "exec")
        for platform in ("win32", "linux", "darwin"):
            with self.subTest(platform=platform), TemporaryDirectory() as directory:
                root = Path(directory)
                dist = root / "dist"
                dist.mkdir()
                wheel, sdist = dist / "sample.whl", dist / "sample.tar.gz"
                wheel.touch()
                sdist.touch()
                with (
                    patch("pathlib.Path.cwd", return_value=root),
                    patch("sys.platform", platform),
                    patch("subprocess.run") as run,
                ):
                    exec(code, {})  # noqa: S102 -- reviewed workflow, all subprocesses mocked
                self.assertEqual(run.call_count, 11)
                calls = run.call_args_list
                for call in calls:
                    self.assertTrue(call.kwargs["check"])
                    self.assertGreater(call.kwargs["timeout"], 0)
                    self.assertLessEqual(call.kwargs["timeout"], 180)
                venvs = [call.args[0][-1] for call in calls if call.args[0][1:3] == ["-m", "venv"]]
                self.assertEqual(len(set(venvs)), 2)
                suffix = "Scripts/python.exe" if platform == "win32" else "bin/python"
                installs = [call.args[0] for call in calls if "install" in call.args[0]]
                self.assertEqual(len(installs), 5)
                self.assertEqual(sum("--require-hashes" in command for command in installs), 3)
                for command in installs:
                    self.assertIn(Path(command[0]), [Path(env) / suffix for env in venvs])
                    if "--require-hashes" not in command:
                        for flag in ("--no-deps", "--no-build-isolation", "--no-index"):
                            self.assertIn(flag, command)
                        self.assertIn(Path(command[-1]), (wheel, sdist))
                validations = [call for call in calls if call.args[0][-1] == "validate"]
                self.assertEqual(len(validations), 2)
                for call in validations:
                    self.assertEqual(call.args[0][1:], ["-I", "-m", "cpe_access_atlas", "validate"])
                    self.assertNotEqual(Path(call.kwargs["cwd"]), root)
                with patch("pathlib.Path.cwd", return_value=root), patch("subprocess.run") as run:
                    run.side_effect = subprocess.CalledProcessError(1, "fixture")
                    with self.assertRaises(subprocess.CalledProcessError):
                        exec(code, {})  # noqa: S102 -- reviewed workflow, subprocesses mocked
                    run.assert_called_once()
                for count in (0, 2):
                    with patch("pathlib.Path.glob", return_value=[wheel] * count):
                        with self.assertRaisesRegex(RuntimeError, "Expected exactly one"):
                            exec(code, {})  # noqa: S102 -- no subprocess runs without an artifact

    def test_github_production_audit_is_read_only(self) -> None:
        audit = (ROOT / "scripts" / "check_github_production_settings.py").read_text(
            encoding="utf-8"
        )
        self.assertIn("gh", audit)
        self.assertNotIn('"-X", "PUT"', audit)
        self.assertNotIn('"-X", "PATCH"', audit)
        self.assertNotIn('"-X", "DELETE"', audit)
        self.assertIn("timeout=30", audit)
        self.assertIn('encoding="utf-8"', audit)
        self.assertIn('errors="replace"', audit)

    def test_github_production_audit_requires_all_current_checks(self) -> None:
        responses = _successful_workflow_responses()
        result = github_audit._audit_current_checks(_MappedGitHubApi(responses), "a" * 40)
        self.assertEqual(result.status, github_audit.STATUS_PASS)

        responses["actions/runs/2/attempts/1/jobs?per_page=100"]["jobs"].pop()
        responses["actions/runs/2/attempts/1/jobs?per_page=100"]["total_count"] = 1
        result = github_audit._audit_current_checks(_MappedGitHubApi(responses), "a" * 40)
        self.assertEqual(result.status, github_audit.STATUS_FAIL)
        self.assertIn("dependency-review", result.detail)

    def test_newer_workflow_failure_cannot_be_hidden_by_historical_success(self) -> None:
        responses = _successful_workflow_responses()
        collection = responses[f"actions/runs?head_sha={'a' * 40}&per_page=100"]
        failed = copy.deepcopy(collection["workflow_runs"][0])
        failed.update(id=10, created_at="2026-09-05T11:00:00Z", conclusion="failure")
        collection["workflow_runs"].append(failed)
        collection["total_count"] += 1
        result = github_audit._audit_workflows(_MappedGitHubApi(responses), "a" * 40)
        self.assertEqual(result.status, github_audit.STATUS_FAIL)
        self.assertIn("CI", result.detail)

    def test_workflow_identity_cannot_be_replaced_by_a_matching_display_name(self) -> None:
        for field, value in (
            ("path", ".github/workflows/untrusted.yml"),
            ("head_branch", "other-branch"),
            ("head_sha", "b" * 40),
            ("event", "pull_request"),
        ):
            responses = _successful_workflow_responses()
            responses[f"actions/runs?head_sha={'a' * 40}&per_page=100"]["workflow_runs"][0][
                field
            ] = value
            with self.subTest(field=field):
                result = github_audit._audit_workflows(_MappedGitHubApi(responses), "a" * 40)
                self.assertEqual(result.status, github_audit.STATUS_FAIL)

    def test_current_jobs_must_come_from_the_latest_attempt_and_exact_commit(self) -> None:
        for field, value in (
            ("run_attempt", 0),
            ("run_id", 99),
            ("head_sha", "b" * 40),
            ("status", "in_progress"),
            ("conclusion", "failure"),
            ("conclusion", "skipped"),
        ):
            responses = _successful_workflow_responses()
            responses["actions/runs/1/attempts/1/jobs?per_page=100"]["jobs"][0][field] = value
            with self.subTest(field=field, value=value):
                result = github_audit._audit_current_checks(_MappedGitHubApi(responses), "a" * 40)
                self.assertEqual(result.status, github_audit.STATUS_FAIL)

    def test_latest_rerun_attempt_is_queried_instead_of_earlier_jobs(self) -> None:
        responses = _successful_workflow_responses()
        responses[f"actions/runs?head_sha={'a' * 40}&per_page=100"]["workflow_runs"][0][
            "run_attempt"
        ] = 2
        responses["actions/runs/1/attempts/2/jobs?per_page=100"] = (None, "HTTP 403")
        result = github_audit._audit_current_checks(_MappedGitHubApi(responses), "a" * 40)
        self.assertEqual(result.status, github_audit.STATUS_UNVERIFIED)
        self.assertIn("403", result.detail)

    def test_rulesets_are_paginated_and_full_details_are_loaded(self) -> None:
        summaries = [{"id": index, "name": f"policy-{index}"} for index in range(1, 101)]
        responses = {
            "rulesets?per_page=100": summaries,
            "rulesets?per_page=100&page=2": [{"id": 101}],
            **{
                f"rulesets/{index}": {"id": index, "rules": [{"type": "deletion"}]}
                for index in range(1, 102)
            },
        }
        details, errors = github_audit._load_rulesets(_MappedGitHubApi(responses))
        self.assertEqual(errors, [])
        self.assertEqual(len(details), 101)
        self.assertEqual(details[-1]["rules"], [{"type": "deletion"}])

    def test_missing_ruleset_details_and_truncated_collections_are_unverified(self) -> None:
        details, errors = github_audit._load_rulesets(
            _MappedGitHubApi(
                {
                    "rulesets?per_page=100": [{"id": 1}],
                    "rulesets/1": (None, "HTTP 403"),
                }
            )
        )
        self.assertEqual(details, [])
        self.assertEqual(errors, ["HTTP 403"])
        records, error = github_audit._get_collection(
            _FakeGitHubApi({"jobs": [], "total_count": 1}), "jobs", "jobs"
        )
        self.assertIsNone(records)
        self.assertIn("incomplete", error)

    def test_ref_aliases_and_exclusions_are_respected(self) -> None:
        for include in ("~ALL", "~DEFAULT_BRANCH", "refs/heads/*", "refs/heads/main"):
            ruleset = {"conditions": {"ref_name": {"include": [include], "exclude": []}}}
            self.assertTrue(github_audit._branch_rule_matches(ruleset, "refs/heads/main"))
            ruleset["conditions"]["ref_name"]["exclude"] = ["refs/heads/main"]
            self.assertFalse(github_audit._branch_rule_matches(ruleset, "refs/heads/main"))
        self.assertFalse(
            github_audit._branch_rule_matches(
                {"conditions": {"ref_name": {"include": ["refs/heads/*"]}}},
                "refs/heads/nested/main",
            )
        )

    def test_tag_exclusion_cannot_be_hidden_by_a_matching_sample_tag(self) -> None:
        ruleset = {
            "target": "tag",
            "enforcement": "active",
            "bypass_actors": [],
            "conditions": {"ref_name": {"include": ["refs/tags/v*"], "exclude": []}},
            "rules": [{"type": name} for name in ("creation", "update", "deletion")],
        }
        self.assertEqual(github_audit._audit_tag_policy([ruleset]).status, github_audit.STATUS_FAIL)
        ruleset["conditions"]["ref_name"]["exclude"] = ["refs/tags/v2*"]
        self.assertEqual(
            github_audit._audit_tag_policy([ruleset]).status, github_audit.STATUS_UNKNOWN
        )

    def test_dependency_graph_uses_capability_evidence_not_an_absent_metadata_key(self) -> None:
        metadata = {
            "security_and_analysis": {
                "secret_scanning": {"status": "enabled"},
                "secret_scanning_push_protection": {"status": "enabled"},
            }
        }
        self.assertEqual(
            github_audit._audit_security_features(metadata).status, github_audit.STATUS_PASS
        )
        self.assertEqual(
            github_audit._audit_dependency_graph(_FakeGitHubApi({"sbom": {"packages": []}})).status,
            github_audit.STATUS_PASS,
        )
        self.assertEqual(
            github_audit._audit_security_features({"security_and_analysis": {}}).status,
            github_audit.STATUS_UNVERIFIED,
        )
        metadata["security_and_analysis"]["secret_scanning"]["status"] = "disabled"
        self.assertEqual(
            github_audit._audit_security_features(metadata).status, github_audit.STATUS_FAIL
        )

    def test_dependabot_settings_distinguish_disabled_paused_and_inaccessible(self) -> None:
        for payload, error, expected in (
            ({"enabled": True, "paused": False}, None, github_audit.STATUS_PASS),
            ({"enabled": True, "paused": True}, None, github_audit.STATUS_FAIL),
            ({"enabled": False}, None, github_audit.STATUS_FAIL),
            (None, "HTTP 401", github_audit.STATUS_UNVERIFIED),
            ({}, None, github_audit.STATUS_UNVERIFIED),
        ):
            with self.subTest(payload=payload):
                result = github_audit._audit_dependabot_updates(_FakeGitHubApi(payload, error))
                self.assertEqual(result.status, expected)

    def test_github_production_audit_normalizes_check_status_shapes(self) -> None:
        names = github_audit._status_check_names(
            {
                "contexts": ["legacy-check"],
                "checks": [{"context": "modern-check"}, {"name": "named-check"}],
            }
        )
        self.assertEqual(names, {"legacy-check", "modern-check", "named-check"})

    def test_github_api_decodes_utf8_repository_metadata(self) -> None:
        completed = SimpleNamespace(
            returncode=0,
            stdout='{"full_name": "Türk Telekom test"}',
            stderr="",
        )
        with (
            patch.object(github_audit.shutil, "which", return_value="gh"),
            patch.object(github_audit.subprocess, "run", return_value=completed) as run,
        ):
            payload, error = github_audit.GitHubApi("Yunushan/cpe-access-atlas").get("")
        self.assertIsNone(error)
        self.assertEqual(payload, {"full_name": "Türk Telekom test"})
        self.assertEqual(run.call_args.kwargs["encoding"], "utf-8")
        self.assertEqual(run.call_args.kwargs["errors"], "replace")

    def test_github_production_audit_accepts_complete_rulesets(self) -> None:
        branch_ruleset = {
            "bypass_actors": [],
            "rules": [
                {"type": "deletion"},
                {"type": "non_fast_forward"},
                {
                    "type": "pull_request",
                    "parameters": {
                        "required_approving_review_count": 1,
                        "require_code_owner_review": True,
                        "dismiss_stale_reviews_on_push": True,
                        "required_review_thread_resolution": True,
                    },
                },
                {
                    "type": "required_status_checks",
                    "parameters": {
                        "strict_required_status_checks_policy": True,
                        "required_status_checks": [
                            {"context": name} for name in github_audit._REQUIRED_BRANCH_CHECKS
                        ],
                    },
                },
            ],
        }
        self.assertTrue(github_audit._ruleset_has_required_branch_controls(branch_ruleset))
        branch_ruleset["bypass_actors"] = [
            {"actor_type": "RepositoryRole", "bypass_mode": "always"}
        ]
        self.assertFalse(github_audit._ruleset_has_required_branch_controls(branch_ruleset))
        del branch_ruleset["bypass_actors"]
        self.assertFalse(github_audit._ruleset_has_required_branch_controls(branch_ruleset))
        tag_ruleset = {
            "target": "tag",
            "enforcement": "active",
            "bypass_actors": [],
            "conditions": {"ref_name": {"include": ["refs/tags/v*"], "exclude": []}},
            "rules": [{"type": "creation"}, {"type": "update"}, {"type": "deletion"}],
        }
        self.assertEqual(
            github_audit._audit_tag_policy([tag_ruleset]).status, github_audit.STATUS_FAIL
        )

    def test_github_production_audit_requires_annotated_main_reachable_release_tag(self) -> None:
        api = _MappedGitHubApi(
            {
                "releases?per_page=100": [
                    {
                        "id": 1,
                        "tag_name": "v0.3.0",
                        "draft": False,
                        "prerelease": True,
                        "published_at": "2026-08-15T00:00:00Z",
                    }
                ],
                "git/ref/tags/v0.3.0": {"object": {"type": "tag", "sha": "b" * 40}},
                f"git/tags/{'b' * 40}": {"object": {"type": "commit", "sha": "c" * 40}},
                "commits/main": {"sha": "a" * 40},
                f"compare/{'a' * 40}...{'c' * 40}": {
                    "status": "behind",
                    "base_commit": {"sha": "a" * 40},
                    "merge_base_commit": {"sha": "c" * 40},
                },
            }
        )
        result = github_audit._audit_release_tag(api)
        self.assertEqual(result.status, github_audit.STATUS_PASS)

    def test_release_contains_required_safety_gates(self) -> None:
        release = (ROOT / ".github" / "workflows" / "release.yml").read_text(encoding="utf-8")
        for marker in (
            "Verify tag matches package version",
            "Verify changelog entry",
            "Verify annotated release tag",
            "Verify tag is on main",
            "-m pip_audit",
            "actions/attest-build-provenance@",
            "name: release",
        ):
            with self.subTest(marker=marker):
                self.assertIn(marker, release)

    def test_production_settings_document_external_security_prerequisites(self) -> None:
        settings = (ROOT / "docs" / "github-production-settings.md").read_text(encoding="utf-8")
        self.assertIn("Dependency graph", settings)
        self.assertIn("release` environment", settings)
        self.assertIn("SHA-pinning enforcement", settings)
        self.assertIn("zero open CodeQL alerts", settings)
        self.assertIn("secret-scan `gitleaks`", settings)

    def test_source_distribution_manifest_includes_governance_config(self) -> None:
        manifest = (ROOT / "MANIFEST.in").read_text(encoding="utf-8")
        self.assertIn(".github/dependabot.yml", manifest)
        self.assertIn("recursive-include .github *.yml", manifest)
        for filename in (".gitignore", ".gitleaks.toml", ".pre-commit-config.yaml"):
            self.assertIn(filename, manifest)

    def test_generated_temporary_artifacts_are_ignored(self) -> None:
        gitignore = (ROOT / ".gitignore").read_text(encoding="utf-8")
        self.assertIn(".tmp/", gitignore)

    def test_dco_workflow_checks_every_pull_request_commit(self) -> None:
        dco = (ROOT / ".github" / "workflows" / "dco.yml").read_text(encoding="utf-8")
        self.assertIn("pull_request", dco)
        self.assertIn("Signed-off-by", dco)
        self.assertIn("git rev-list", dco)

    def test_contributing_documents_signoff_command(self) -> None:
        contributing = (ROOT / "CONTRIBUTING.md").read_text(encoding="utf-8")
        self.assertIn("Signed-off-by:", contributing)

    def test_pre_commit_config_mirrors_ci_checks(self) -> None:
        pre_commit = (ROOT / ".pre-commit-config.yaml").read_text(encoding="utf-8")
        self.assertIn("ruff-format", pre_commit)
        self.assertIn("mypy", pre_commit)
        self.assertIn("cpe-atlas validate", pre_commit)
        self.assertIn("pycryptodome==3.23.0", pre_commit)

    def test_pre_commit_revisions_are_commit_pinned(self) -> None:
        pre_commit = (ROOT / ".pre-commit-config.yaml").read_text(encoding="utf-8")
        revisions = re.findall(r"^\s+rev:\s+([0-9a-f]+)(?:\s+#.*)?$", pre_commit, re.MULTILINE)
        self.assertGreaterEqual(len(revisions), 2)
        for revision in revisions:
            with self.subTest(revision=revision):
                self.assertRegex(revision, r"^[0-9a-f]{40}$")

    def test_secret_scanning_workflow_runs_gitleaks(self) -> None:
        workflow = (ROOT / ".github" / "workflows" / "secret-scan.yml").read_text(encoding="utf-8")
        self.assertIn("gitleaks/gitleaks-action@", workflow)
        self.assertIn("push", workflow)
        self.assertIn("pull_request", workflow)
        gitleaks_config = (ROOT / ".gitleaks.toml").read_text(encoding="utf-8")
        self.assertIn("useDefault = true", gitleaks_config)

    def test_fuzz_suite_covers_untrusted_input_parsers(self) -> None:
        fuzz_tests = (ROOT / "tests" / "test_fuzz_properties.py").read_text(encoding="utf-8")
        self.assertIn("from hypothesis import", fuzz_tests)
        self.assertIn("decode_config", fuzz_tests)
        self.assertIn("redact_text", fuzz_tests)

    def test_code_of_conduct_exists(self) -> None:
        code_of_conduct = ROOT / "CODE_OF_CONDUCT.md"
        self.assertTrue(code_of_conduct.exists())
        text = code_of_conduct.read_text(encoding="utf-8")
        self.assertIn("Enforcement", text)


if __name__ == "__main__":
    unittest.main()

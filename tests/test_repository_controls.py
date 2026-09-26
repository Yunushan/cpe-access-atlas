# SPDX-License-Identifier: 0BSD
from __future__ import annotations

import ast
import copy
import io
import json
import os
import re
import shutil
import subprocess
import sys
import tokenize
import tomllib
import unittest
from datetime import UTC, datetime, timedelta
from pathlib import Path
from tempfile import TemporaryDirectory
from textwrap import dedent
from types import SimpleNamespace
from unittest.mock import patch

from packaging.markers import default_environment
from packaging.requirements import Requirement

from scripts import check_github_production_settings as github_audit

ROOT = Path(__file__).parents[1]
WORKFLOW_FILES = (
    ROOT / ".github" / "workflows" / "ci.yml",
    ROOT / ".github" / "workflows" / "security.yml",
    ROOT / ".github" / "workflows" / "release.yml",
    ROOT / ".github" / "workflows" / "release-preflight.yml",
    ROOT / ".github" / "workflows" / "codeql.yml",
    ROOT / ".github" / "workflows" / "dco.yml",
    ROOT / ".github" / "workflows" / "secret-scan.yml",
)

_SCOPED_CODEQL_SUPPRESSION = re.compile(r"(?i)\b(?:codeql|lgtm)\s*\[[^\]]*\]")
_BARE_LGTM_SUPPRESSION = re.compile(r"(?i)(?:^|;)\s*lgtm(?!\B|\s*\[)")
_BLANKET_NOQA_SUPPRESSION = re.compile(r"(?i)\s*noqa\s*(?:[^:].*)?")


def _suppression_context(relative_path: str, source: bytes) -> list[tuple[str, str, str, str, str]]:
    """Return semantic anchors for effective Python CodeQL suppression comments."""

    text = source.decode("utf-8")
    tree = ast.parse(text, filename=relative_path)
    parents = {child: parent for parent in ast.walk(tree) for child in ast.iter_child_nodes(parent)}
    statements_by_line: dict[int, list[ast.stmt]] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.stmt):
            statements_by_line.setdefault(node.lineno, []).append(node)

    suppressions: list[tuple[str, str, str, str, str]] = []
    for token in tokenize.tokenize(io.BytesIO(source).readline):
        if token.type != tokenize.COMMENT:
            continue
        contents = token.string.removeprefix("#")
        if not (
            _SCOPED_CODEQL_SUPPRESSION.search(contents) is not None
            or _BARE_LGTM_SUPPRESSION.search(contents) is not None
            or _BLANKET_NOQA_SUPPRESSION.fullmatch(contents) is not None
        ):
            continue

        adjacent = statements_by_line.get(token.end[0] + 1, [])
        if len(adjacent) != 1:
            suppressions.append(
                (
                    relative_path,
                    token.string,
                    "<no-unique-adjacent-statement>",
                    "<unknown-parent>",
                    "<unknown-statement>",
                )
            )
            continue
        statement = adjacent[0]
        function = "<module>"
        ancestor: ast.AST | None = statement
        while ancestor in parents:
            ancestor = parents[ancestor]
            if isinstance(ancestor, (ast.FunctionDef, ast.AsyncFunctionDef)):
                function = ancestor.name
                break

        parent = parents.get(statement)
        relation = "<unknown-parent>"
        if parent is not None:
            for field, value in ast.iter_fields(parent):
                if value is statement:
                    relation = f"{type(parent).__name__}.{field}"
                    break
                if isinstance(value, list) and statement in value:
                    relation = f"{type(parent).__name__}.{field}[{value.index(statement)}]"
                    break
        suppressions.append(
            (
                relative_path,
                token.string,
                function,
                relation,
                f"{type(statement).__name__}:{ast.unparse(statement)}",
            )
        )
    return suppressions


def _repository_codeql_suppressions() -> list[tuple[str, str, str, str, str]]:
    python_files = [
        *ROOT.glob("*.py"),
        *(
            path
            for directory in ("src", "scripts", "tests")
            for path in (ROOT / directory).rglob("*.py")
        ),
    ]
    return [
        suppression
        for path in sorted(python_files)
        for suppression in _suppression_context(
            path.relative_to(ROOT).as_posix(),
            path.read_bytes(),
        )
    ]


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
                "created_at": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
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
            for name in ("ci", "security", "secret-scan", "dco", "codeql")
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
                        self.assertIn(workflow.name, {"release.yml", "release-preflight.yml"})
                    else:
                        self.assertRegex(line, pattern)

    def test_dependabot_scope_and_lock_regeneration_are_documented(self) -> None:
        config = (ROOT / ".github" / "dependabot.yml").read_text(encoding="utf-8")
        self.assertIn("package-ecosystem: pip", config)
        self.assertIn("package-ecosystem: github-actions", config)
        self.assertIn("interval: weekly", config)
        contributing = (ROOT / "CONTRIBUTING.md").read_text(encoding="utf-8")
        release = (ROOT / "docs" / "release.md").read_text(encoding="utf-8")
        for document in (contributing, release):
            self.assertIn("does not regenerate", document)
            self.assertIn("requirements-*.lock", document)

    def test_dependency_audit_is_periodic_manual_and_covers_every_lock(self) -> None:
        workflow = (ROOT / ".github" / "workflows" / "security.yml").read_text(encoding="utf-8")
        self.assertIn("  workflow_dispatch:\n", workflow)
        self.assertRegex(workflow, r'(?m)^  schedule:\n    - cron: "[^"]+"$')
        for name in ("runtime", "security", "ci", "release", "build"):
            self.assertIn(f"-r requirements-{name}.lock", workflow)
        audit_job = workflow.split("  dependency-audit:\n", 1)[1].split(
            "\n  dependency-review:", 1
        )[0]
        matrix = re.search(r"(?m)^        python: (\[.*\])$", audit_job)
        self.assertIsNotNone(matrix)
        versions = tuple(json.loads(matrix.group(1)))
        self.assertEqual(versions, github_audit._SECURITY_AUDIT_PYTHONS)
        self.assertIn("runs-on: ubuntu-latest", audit_job)

        requirements: list[tuple[str, Requirement]] = []
        for name in ("runtime", "security", "ci", "release", "build"):
            path = ROOT / f"requirements-{name}.lock"
            for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
                if not line or line[0].isspace() or line.startswith("#"):
                    continue
                requirements.append(
                    (f"{path.name}:{line_number}", Requirement(line.removesuffix("\\").strip()))
                )

        def environments(
            operating_systems: tuple[str, ...], python_versions: tuple[str, ...]
        ) -> list[dict[str, str]]:
            platform_values = {
                "ubuntu-latest": ("posix", "linux", "Linux", "x86_64"),
                "windows-latest": ("nt", "win32", "Windows", "AMD64"),
                "macos-latest": ("posix", "darwin", "Darwin", "x86_64"),
            }
            result: list[dict[str, str]] = []
            for operating_system in operating_systems:
                os_name, sys_platform, platform_system, platform_machine = platform_values[
                    operating_system
                ]
                for python_version in python_versions:
                    environment = default_environment()
                    environment.update(
                        {
                            "os_name": os_name,
                            "sys_platform": sys_platform,
                            "platform_system": platform_system,
                            "platform_machine": platform_machine,
                            "python_version": python_version,
                            "python_full_version": f"{python_version}.0",
                        }
                    )
                    result.append(environment)
            return result

        def active_in(targets: list[dict[str, str]]) -> set[str]:
            return {
                location
                for location, requirement in requirements
                if requirement.marker is None
                or any(requirement.marker.evaluate(environment) for environment in targets)
            }

        supported = environments(github_audit._RELEASE_OSES, github_audit._RELEASE_PYTHONS)
        audited = environments(("ubuntu-latest",), versions)
        self.assertEqual(active_in(supported) - active_in(audited), set())

    def test_ci_is_periodic_manual_and_freshness_audited(self) -> None:
        workflow = (ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
        self.assertIn("  workflow_dispatch:\n", workflow)
        self.assertRegex(workflow, r'(?m)^  schedule:\n    - cron: "[^"]+"$')
        self.assertIn("CI", github_audit._WEEKLY_WORKFLOWS)

    def test_security_response_workflows_are_manually_dispatchable(self) -> None:
        for filename in ("codeql.yml", "secret-scan.yml"):
            with self.subTest(filename=filename):
                workflow = (ROOT / ".github" / "workflows" / filename).read_text(encoding="utf-8")
                self.assertIn("  workflow_dispatch:\n", workflow)

    def test_release_preflight_is_manual_read_only_and_nonpublishing(self) -> None:
        workflow = (ROOT / ".github" / "workflows" / "release-preflight.yml").read_text(
            encoding="utf-8"
        )
        self.assertIn("  workflow_dispatch:\n", workflow)
        self.assertIn("      release_tag:\n", workflow)
        self.assertNotIn("contents: write", workflow)
        self.assertNotIn("attestations: write", workflow)
        self.assertNotIn("id-token: write", workflow)
        self.assertNotIn("gh release create", workflow)
        self.assertIn("scripts/check_release_candidate.py", workflow)
        self.assertIn('if [ "$GITHUB_REF" != "refs/heads/main" ]', workflow)
        self.assertIn("git rev-parse --verify refs/remotes/origin/main", workflow)
        self.assertIn('if [ "$GITHUB_SHA" != "$main_sha" ]', workflow)
        self.assertIn("gh api --paginate --method GET", workflow)
        self.assertIn('-f state=open -f "ref=$GITHUB_REF" -f per_page=100', workflow)
        self.assertIn('"repos/${GITHUB_REPOSITORY}/code-scanning/alerts"', workflow)
        self.assertIn('--codeql-risk-ref "$GITHUB_REF"', workflow)
        self.assertIn('--codeql-risk-commit "$GITHUB_SHA"', workflow)
        self.assertIn('python-version: "3.14"', workflow)
        for name in ("ci", "security", "secret-scan", "dco", "codeql"):
            self.assertIn(f"uses: ./.github/workflows/{name}.yml", workflow)
        reusable_jobs = workflow.split("  source-validation:\n", 1)[1].split(
            "\n  candidate-validation:", 1
        )[0]
        self.assertEqual(reusable_jobs.count("    needs: scope-and-input-validation\n"), 5)
        scope = workflow.split("  scope-and-input-validation:\n", 1)[1].split(
            "\n  source-validation:", 1
        )[0]
        self.assertLess(
            scope.index("Verify preflight runs from main"), scope.index("actions/checkout@")
        )
        self.assertIn("PYTHONPATH: src", scope)

    def test_release_uses_exact_dated_candidate_metadata_validator(self) -> None:
        workflow = (ROOT / ".github" / "workflows" / "release.yml").read_text(encoding="utf-8")
        self.assertIn('python scripts/check_release_candidate.py --tag "$RELEASE_TAG"', workflow)
        self.assertNotIn('grep -Fq "## $version"', workflow)
        self.assertIn("Verify tag is current main head", workflow)
        self.assertIn("git rev-parse --verify refs/remotes/origin/main", workflow)
        self.assertNotIn("git merge-base --is-ancestor", workflow)
        self.assertIn("gh api --paginate --method GET", workflow)
        self.assertIn('-f state=open -f "ref=$GITHUB_REF" -f per_page=100', workflow)
        self.assertIn('--codeql-risk-ref "$GITHUB_REF"', workflow)
        self.assertIn('--codeql-risk-commit "$GITHUB_SHA"', workflow)

    def test_codeql_accepted_risk_policy_is_exact_numbered_and_expiring(self) -> None:
        policy = json.loads(
            (ROOT / ".github" / "codeql-accepted-risks.json").read_text(encoding="utf-8")
        )
        self.assertEqual(policy["schema_version"], 1)
        self.assertEqual(policy["repository"], "Yunushan/cpe-access-atlas")
        risks = {item["alert_number"]: item for item in policy["accepted_risks"]}
        self.assertEqual(set(risks), {5, 9})
        self.assertEqual(
            {item["rule_id"] for item in risks.values()},
            {"py/weak-sensitive-data-hashing"},
        )
        self.assertEqual({item["security_severity_level"] for item in risks.values()}, {"high"})
        self.assertEqual(
            {item["path"] for item in risks.values()},
            {
                "src/cpe_access_atlas/config.py",
                "src/cpe_access_atlas/web_evidence.py",
            },
        )
        for item in risks.values():
            self.assertEqual(item["dismissed_reason"], "won't fix")
            self.assertTrue(item["dismissed_comment"])
            self.assertTrue(item["review_by"])
            self.assertTrue(item["compensating_controls"])
            self.assertTrue(item["re_review_triggers"])

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

    def test_publication_verifies_immutability_without_administrator_credentials(self) -> None:
        workflow = (ROOT / ".github/workflows/release.yml").read_text(encoding="utf-8")
        gate = "      - name: Verify published release is immutable\n"
        self.assertLess(workflow.index("gh release create"), workflow.index(gate))
        step = workflow.split(gate, 1)[1].split(
            "      - name: Verify published asset bytes and attestations\n", 1
        )[0]
        self.assertIn("GH_TOKEN: ${{ github.token }}", step)
        code = compile(dedent(step.split("        run: |\n")[1]), "release-immutability", "exec")
        for payload in ({"immutable": True}, {"immutable": False}, {}, {"immutable": 1}, [], None):
            with (
                self.subTest(payload=payload),
                patch.dict(
                    "os.environ",
                    {"GITHUB_REPOSITORY": "example/project", "GITHUB_REF_NAME": "v0.4.0a1"},
                ),
                patch(
                    "subprocess.run", return_value=SimpleNamespace(stdout=json.dumps(payload))
                ) as run,
            ):
                if payload == {"immutable": True} and type(payload.get("immutable")) is bool:
                    exec(code, {})  # noqa: S102 -- fixed workflow code with mocked GitHub I/O
                else:
                    with self.assertRaises(RuntimeError):
                        exec(code, {})  # noqa: S102 -- fixed workflow code with mocked GitHub I/O
                self.assertEqual(
                    run.call_args.args[0],
                    [
                        "gh",
                        "api",
                        "--method",
                        "GET",
                        "repos/example/project/releases/tags/v0.4.0a1",
                    ],
                )
                self.assertTrue(run.call_args.kwargs["check"])
                self.assertEqual(run.call_args.kwargs["timeout"], 30)
        for failure in (
            subprocess.CalledProcessError(1, "gh"),
            subprocess.TimeoutExpired("gh", 30),
        ):
            with (
                patch.dict(
                    "os.environ",
                    {"GITHUB_REPOSITORY": "example/project", "GITHUB_REF_NAME": "v0.4.0a1"},
                ),
                patch("subprocess.run", side_effect=failure),
                self.assertRaises(type(failure)),
            ):
                exec(code, {})  # noqa: S102 -- fixed workflow code with mocked GitHub I/O

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
            "dco-validation": "dco",
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

    def test_privileged_release_job_only_publishes_the_validated_exact_bundle(self) -> None:
        release = (ROOT / ".github/workflows/release.yml").read_text(encoding="utf-8")
        jobs = dict(
            re.findall(
                r"(?ms)^  ([\w-]+):\n(.*?)(?=^  [\w-]+:|\Z)",
                release.split("jobs:\n", 1)[1],
            )
        )
        validation = jobs["validate-release"]
        publication = jobs["publish-release"]

        self.assertIn("      contents: read", validation)
        self.assertIn("      security-events: read", validation)
        self.assertNotIn(": write", validation)
        self.assertNotIn("id-token:", validation)
        self.assertNotRegex(validation, r"(?m)^    environment:")
        self.assertLess(
            validation.index("Verify annotated release tag"),
            validation.index("actions/setup-python@"),
        )
        self.assertLess(
            validation.index("Verify tag is current main head"),
            validation.index("Install release tooling"),
        )

        self.assertRegex(publication, r"(?m)^    needs: validate-release$")
        self.assertIn("      attestations: write", publication)
        self.assertIn("      contents: write", publication)
        self.assertIn("      id-token: write", publication)
        self.assertRegex(publication, r"(?m)^    environment:\n      name: release$")
        for forbidden in (
            "actions/checkout@",
            "actions/setup-python@",
            "pip install",
            "python -c",
            "scripts/",
            "from cpe_access_atlas",
        ):
            with self.subTest(forbidden=forbidden):
                self.assertNotIn(forbidden, publication)

        markers = (
            "Download validated release bundle",
            "Verify exact release bundle and checksums",
            "Refuse to overwrite an existing release",
            "Reverify annotated tag and main targets before attestation",
            "Attest release artifacts",
            "Reverify annotated tag and main targets after attestation",
            "Publish GitHub release",
            "Verify published release is immutable",
            "Verify published asset bytes and attestations",
        )
        positions = [publication.index(marker) for marker in markers]
        self.assertEqual(positions, sorted(positions))
        for marker in (
            "expected_paths",
            "actual_paths",
            "listed_paths",
            'entry_count="$(find dist -mindepth 1 -maxdepth 1 -print | wc -l)"',
            "sha256sum --check --strict dist/SHA256SUMS",
            'target.get("sha") != os.environ["GITHUB_SHA"]',
        ):
            self.assertIn(marker, publication)
        postpublication = publication.split(
            "      - name: Verify published asset bytes and attestations\n", 1
        )[1]
        for marker in (
            'gh release download "$GITHUB_REF_NAME"',
            '--dir "$workspace/dist"',
            "awk '{print $2}' \"$workspace/dist/SHA256SUMS\"",
            'entry_count="$(find "$workspace/dist" -mindepth 1 -maxdepth 1 -print | wc -l)"',
            "Published release has an unexpected entry count.",
            "Published release has missing or unexpected assets.",
            "Published checksum manifest does not list the exact release assets.",
            '(cd "$workspace" && sha256sum --check --strict dist/SHA256SUMS)',
            'attested_paths=("${expected_paths[@]}" "dist/SHA256SUMS")',
            'gh attestation verify "$workspace/$relative"',
            '--signer-workflow "Yunushan/cpe-access-atlas/.github/workflows/release.yml"',
            '--source-ref "refs/tags/$GITHUB_REF_NAME"',
            '--source-digest "$GITHUB_SHA"',
            "--deny-self-hosted-runners",
        ):
            self.assertIn(marker, postpublication)
        self.assertLess(
            validation.index("Upload distributions"),
            len(validation),
        )

    def test_privileged_publication_reverifies_live_tag_and_main_targets(self) -> None:
        release = (ROOT / ".github/workflows/release.yml").read_text(encoding="utf-8")
        before_attestation = release.split(
            "      - name: Reverify annotated tag and main targets before attestation\n", 1
        )[1].split("      - name: Attest release artifacts\n", 1)[0]
        after_attestation = release.split(
            "      - name: Reverify annotated tag and main targets after attestation\n", 1
        )[1].split("      - name: Publish GitHub release\n", 1)[0]
        self.assertIn("        shell: python\n", before_attestation)
        self.assertIn("        shell: python\n", after_attestation)
        before_code = dedent(before_attestation.split("        run: |\n", 1)[1])
        after_code = dedent(after_attestation.split("        run: |\n", 1)[1])
        self.assertEqual(before_code, after_code)
        code = compile(
            before_code,
            "release-live-tag-verifier",
            "exec",
        )
        commit = "a" * 40
        tag_object = "b" * 40
        valid_ref = {"object": {"type": "tag", "sha": tag_object}}
        valid_tag = {"object": {"type": "commit", "sha": commit}}
        valid_main = {"object": {"type": "commit", "sha": commit}}

        def response(value: object) -> SimpleNamespace:
            return SimpleNamespace(stdout=json.dumps(value))

        environment = {
            "GITHUB_REPOSITORY": "example/project",
            "GITHUB_REF_NAME": "v1.2.3",
            "GITHUB_SHA": commit,
        }
        with (
            patch.dict(os.environ, environment, clear=True),
            patch(
                "subprocess.run",
                side_effect=[response(valid_ref), response(valid_tag), response(valid_main)],
            ) as run,
        ):
            exec(code, {})  # noqa: S102 -- reviewed workflow with mocked subprocesses.
        self.assertEqual(
            [call.args[0] for call in run.call_args_list],
            [
                [
                    "gh",
                    "api",
                    "--method",
                    "GET",
                    "repos/example/project/git/ref/tags/v1.2.3",
                ],
                [
                    "gh",
                    "api",
                    "--method",
                    "GET",
                    f"repos/example/project/git/tags/{tag_object}",
                ],
                [
                    "gh",
                    "api",
                    "--method",
                    "GET",
                    "repos/example/project/git/ref/heads/main",
                ],
            ],
        )
        for call in run.call_args_list:
            self.assertTrue(call.kwargs["capture_output"])
            self.assertTrue(call.kwargs["text"])
            self.assertTrue(call.kwargs["check"])
            self.assertEqual(call.kwargs["timeout"], 30)

        cases = (
            [response([])],
            [response({"object": {"type": "commit", "sha": tag_object}})],
            [response({"object": {"type": "tag", "sha": "invalid"}})],
            [response(valid_ref), response({"object": {"type": "tag", "sha": commit}})],
            [response(valid_ref), response({"object": {"type": "commit", "sha": "c" * 40}})],
            [response(valid_ref), response(valid_tag), response([])],
            [
                response(valid_ref),
                response(valid_tag),
                response({"object": {"type": "tag", "sha": commit}}),
            ],
            [
                response(valid_ref),
                response(valid_tag),
                response({"object": {"type": "commit", "sha": "c" * 40}}),
            ],
        )
        for responses in cases:
            with (
                self.subTest(responses=responses),
                patch.dict(os.environ, environment, clear=True),
                patch("subprocess.run", side_effect=responses),
                self.assertRaises(RuntimeError),
            ):
                exec(code, {})  # noqa: S102 -- reviewed workflow with mocked subprocesses.

        for failure in (
            subprocess.CalledProcessError(1, ["gh"]),
            subprocess.TimeoutExpired(["gh"], 30),
        ):
            with (
                self.subTest(failure=type(failure)),
                patch.dict(os.environ, environment, clear=True),
                patch("subprocess.run", side_effect=failure),
                self.assertRaises(type(failure)),
            ):
                exec(code, {})  # noqa: S102 -- reviewed workflow with mocked subprocesses.

    def test_validation_workflows_avoid_duplicate_branch_push_runs(self) -> None:
        for name in ("ci", "security", "secret-scan", "codeql"):
            workflow = (ROOT / ".github/workflows" / f"{name}.yml").read_text(encoding="utf-8")
            with self.subTest(workflow=name):
                self.assertIn("  push:\n    branches: [main]\n", workflow)
                self.assertIn("  pull_request:\n", workflow)
                self.assertIn("  workflow_call:\n", workflow)
                self.assertNotIn("  push:\n\n", workflow)

    def test_release_blocks_open_codeql_alerts_before_publication(self) -> None:
        release = (ROOT / ".github/workflows/release.yml").read_text(encoding="utf-8")
        self.assertIn("      security-events: read", release)
        gate = release.index("- name: Verify no open CodeQL alerts")
        self.assertLess(gate, release.index("- name: Install release tooling"))
        self.assertIn('"repos/${GITHUB_REPOSITORY}/code-scanning/alerts"', release)
        self.assertIn("--paginate --method GET", release)
        self.assertIn('-f state=open -f "ref=$GITHUB_REF" -f per_page=100', release)
        self.assertIn('page_counts="$(gh api --paginate --method GET', release)
        self.assertIn("--jq 'length')\"", release)
        self.assertIn("open_alerts=$((open_alerts + page_count))", release)

    def test_actual_built_archive_is_checked_before_package_install_or_publication(self) -> None:
        for name in ("ci", "release"):
            workflow = (ROOT / f".github/workflows/{name}.yml").read_text(encoding="utf-8")
            gate = workflow.index("python scripts/check_sdist.py --dist-dir dist")
            self.assertLess(
                workflow.index("python scripts/build_reproducible.py --dist-dir dist"), gate
            )
            self.assertLess(gate, workflow.index("- name: Install wheel in a clean"))
        release = (ROOT / ".github/workflows/release.yml").read_text(encoding="utf-8")
        self.assertLess(
            release.index("python scripts/check_sdist.py"), release.index("gh release create")
        )

    def test_cross_platform_artifact_sha_equality_gates_ci_and_release(self) -> None:
        ci = (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
        release = (ROOT / ".github/workflows/release.yml").read_text(encoding="utf-8")
        artifact_pattern = "python315-distributions-*"
        platforms = ("ubuntu-latest", "windows-latest", "macos-latest")

        upload = ci.split(
            "      - name: Upload Python 3.15 distributions for cross-platform verification\n",
            1,
        )[1].split("\n\n  cross-platform-artifact-reproducibility:", 1)[0]
        self.assertIn("        if: matrix.python == '3.15'\n", upload)
        self.assertIn("actions/upload-artifact@", upload)
        self.assertIn("name: python315-distributions-${{ matrix.os }}", upload)
        self.assertIn("dist/*.whl", upload)
        self.assertIn("dist/*.tar.gz", upload)
        self.assertIn("if-no-files-found: error", upload)

        comparison_job = ci.split("  cross-platform-artifact-reproducibility:\n", 1)[1].split(
            "\n  package-smoke:", 1
        )[0]
        self.assertIn(
            "cross-platform-artifact-reproducibility",
            github_audit._REQUIRED_BRANCH_CHECKS,
        )
        self.assertRegex(comparison_job, r"(?m)^    needs: test$")
        self.assertIn("actions/download-artifact@", comparison_job)
        self.assertIn(f"pattern: {artifact_pattern}", comparison_job)
        self.assertIn("Verify cross-platform artifact SHA-256 equality", comparison_job)

        release_build = release.index("      - name: Build distributions\n")
        release_comparison = release.index(
            "      - name: Verify release artifact SHA-256 equality across platforms\n"
        )
        self.assertLess(release_build, release_comparison)
        self.assertLess(release_comparison, release.index("      - name: Upload distributions\n"))
        self.assertIn(f"pattern: {artifact_pattern}", release[release_build:release_comparison])
        for workflow_block in (comparison_job, release[release_comparison:]):
            for platform in platforms:
                self.assertIn(f'"python315-distributions-{platform}"', workflow_block)
            self.assertIn('hashlib.file_digest(stream, "sha256").hexdigest()', workflow_block)
            self.assertIn("if inventory != baseline", workflow_block)

    def test_cross_platform_artifact_sha_verifiers_fail_closed(self) -> None:
        ci = (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
        release = (ROOT / ".github/workflows/release.yml").read_text(encoding="utf-8")
        ci_step = ci.split("      - name: Verify cross-platform artifact SHA-256 equality\n", 1)[
            1
        ].split("\n\n  package-smoke:", 1)[0]
        release_step = release.split(
            "      - name: Verify release artifact SHA-256 equality across platforms\n", 1
        )[1].split("      - name: Check distribution metadata\n", 1)[0]
        ci_code = compile(dedent(ci_step.split("        run: |\n", 1)[1]), "ci-sha-gate", "exec")
        release_code = compile(
            dedent(release_step.split("        run: |\n", 1)[1]), "release-sha-gate", "exec"
        )
        directory_names = (
            "python315-distributions-ubuntu-latest",
            "python315-distributions-windows-latest",
            "python315-distributions-macos-latest",
        )

        def populate(root: Path, *, include_release: bool = False) -> None:
            for name in directory_names:
                build = root / "cross-platform-dist" / name
                build.mkdir(parents=True)
                (build / "sample-py3-none-any.whl").write_bytes(b"wheel")
                (build / "sample.tar.gz").write_bytes(b"sdist")
            if include_release:
                dist = root / "dist"
                dist.mkdir()
                (dist / "sample-py3-none-any.whl").write_bytes(b"wheel")
                (dist / "sample.tar.gz").write_bytes(b"sdist")

        for code, include_release in ((ci_code, False), (release_code, True)):
            with self.subTest(release=include_release), TemporaryDirectory() as directory:
                root = Path(directory)
                populate(root, include_release=include_release)
                with patch("pathlib.Path.cwd", return_value=root):
                    exec(code, {})  # noqa: S102 -- reviewed local workflow verifier.

                differing = root / "cross-platform-dist" / directory_names[-1] / "sample.tar.gz"
                differing.write_bytes(b"different")
                with (
                    patch("pathlib.Path.cwd", return_value=root),
                    self.assertRaisesRegex(RuntimeError, "SHA-256"),
                ):
                    exec(code, {})  # noqa: S102 -- reviewed local workflow verifier.

            with (
                self.subTest(release=include_release, missing=True),
                TemporaryDirectory() as directory,
            ):
                root = Path(directory)
                populate(root, include_release=include_release)
                shutil.rmtree(root / "cross-platform-dist" / directory_names[-1])
                with (
                    patch("pathlib.Path.cwd", return_value=root),
                    self.assertRaisesRegex(RuntimeError, "Expected cross-platform builds"),
                ):
                    exec(code, {})  # noqa: S102 -- reviewed local workflow verifier.

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

    def test_vendor_crypto_is_not_misclassified_as_nonsecurity(self) -> None:
        config = (ROOT / "src" / "cpe_access_atlas" / "config.py").read_text(encoding="utf-8")
        self.assertNotIn("usedforsecurity=False", config)
        self.assertIn("docs/config-cryptography.md", config)
        self.assertTrue((ROOT / "docs/config-cryptography.md").is_file())

    def test_source_codeql_suppressions_are_exact_and_reviewed(self) -> None:
        expected = (
            "src/cpe_access_atlas/private_files.py",
            "# codeql[py/clear-text-storage-sensitive-data]",
            "write_private_bytes",
            "With.body[1]",
            "Expr:stream.write(data)",
        )
        self.assertEqual(_repository_codeql_suppressions(), [expected])

        source = (ROOT / "src" / "cpe_access_atlas" / "private_files.py").read_bytes()
        anchored = (
            b"            # codeql[py/clear-text-storage-sensitive-data]\n"
            b"            stream.write(data)\n"
        )
        moved = (
            b"            stream.write(data)\n"
            b"            # codeql[py/clear-text-storage-sensitive-data]\n"
        )
        self.assertEqual(source.count(anchored), 1)
        mutated = source.replace(anchored, moved)
        relocated = _suppression_context(expected[0], mutated)
        self.assertEqual(relocated[0][:2], expected[:2])
        self.assertNotEqual(relocated, [expected])

    def test_distribution_builds_reuse_hash_verified_backend_without_index_access(self) -> None:
        for name, lock in (("ci", "ci"), ("release", "release")):
            workflow = (ROOT / f".github/workflows/{name}.yml").read_text(encoding="utf-8")
            with self.subTest(workflow=name):
                builds = re.findall(
                    r"^\s+run: (python scripts/build_reproducible.py .+)$",
                    workflow,
                    re.MULTILINE,
                )
                expected_count = 2 if name == "ci" else 1
                self.assertEqual(
                    builds,
                    ["python scripts/build_reproducible.py --dist-dir dist"] * expected_count,
                )
                hash_verified_builds = re.findall(
                    r'PIP_NO_INDEX: "1"\s+run: python scripts/build_reproducible.py '
                    r"--dist-dir dist",
                    workflow,
                )
                self.assertEqual(len(hash_verified_builds), expected_count)
                self.assertLess(
                    workflow.index(f"pip install --require-hashes -r requirements-{lock}.lock"),
                    workflow.index(builds[0]),
                )

    def test_python_support_metadata_workflows_and_audit_policy_agree(self) -> None:
        project = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
        version_source = (ROOT / "src/cpe_access_atlas/__init__.py").read_text(encoding="utf-8")
        version = re.search(r'(?m)^__version__ = "([^"]+)"$', version_source)
        self.assertIsNotNone(version)
        assert version is not None
        self.assertEqual(github_audit._CANDIDATE_RELEASE_TAG, f"v{version.group(1)}")
        prefix = "Programming Language :: Python :: 3."
        versions = tuple(
            entry.rsplit(" :: ", 1)[-1]
            for entry in project["project"]["classifiers"]
            if entry.startswith(prefix)
        )
        self.assertEqual(versions, ("3.11", "3.12", "3.13", "3.14", "3.15"))
        self.assertEqual(github_audit._RELEASE_PYTHONS, versions)
        self.assertEqual(project["project"]["requires-python"], ">=3.11,<3.16")
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
        step = step.split(
            "      - name: Upload Python 3.15 distributions for cross-platform verification\n",
            1,
        )[0]
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

        jobs = responses["actions/runs/2/attempts/1/jobs?per_page=100"]["jobs"]
        jobs.pop()
        responses["actions/runs/2/attempts/1/jobs?per_page=100"]["total_count"] = len(jobs)
        result = github_audit._audit_current_checks(_MappedGitHubApi(responses), "a" * 40)
        self.assertEqual(result.status, github_audit.STATUS_FAIL)
        self.assertIn("dependency-review", result.detail)

        responses = _successful_workflow_responses()
        dco_jobs = responses["actions/runs/5/attempts/1/jobs?per_page=100"]
        dco_jobs["jobs"][0]["conclusion"] = "failure"
        result = github_audit._audit_current_checks(_MappedGitHubApi(responses), "a" * 40)
        self.assertEqual(result.status, github_audit.STATUS_FAIL)
        self.assertIn("check-signoff", result.detail)

        responses = _successful_workflow_responses()
        runs = responses[f"actions/runs?head_sha={'a' * 40}&per_page=100"]["workflow_runs"]
        next(run for run in runs if run["name"] == "DCO")["event"] = "workflow_dispatch"
        result = github_audit._audit_workflows(_MappedGitHubApi(responses), "a" * 40)
        self.assertEqual(result.status, github_audit.STATUS_FAIL)
        self.assertIn("DCO", result.detail)

    def test_periodic_or_manual_security_run_may_skip_pr_only_dependency_review(self) -> None:
        for event in ("schedule", "workflow_dispatch"):
            with self.subTest(event=event):
                responses = _successful_workflow_responses()
                runs = responses[f"actions/runs?head_sha={'a' * 40}&per_page=100"]["workflow_runs"]
                security = next(run for run in runs if run["name"] == "Security audit")
                security["event"] = event
                result = github_audit._audit_current_checks(_MappedGitHubApi(responses), "a" * 40)
                self.assertEqual(result.status, github_audit.STATUS_PASS)

    def test_weekly_workflow_evidence_must_be_recent_and_not_future_dated(self) -> None:
        now = datetime(2026, 9, 18, 12, tzinfo=UTC)
        for workflow_name in ("CI", "Security audit", "CodeQL"):
            for created_at in ("2026-09-01T12:00:00Z", "2026-09-18T12:06:00Z"):
                with self.subTest(workflow_name=workflow_name, created_at=created_at):
                    responses = _successful_workflow_responses()
                    runs = responses[f"actions/runs?head_sha={'a' * 40}&per_page=100"][
                        "workflow_runs"
                    ]
                    workflow = next(run for run in runs if run["name"] == workflow_name)
                    workflow["created_at"] = created_at
                    api = _MappedGitHubApi(responses)
                    workflows = github_audit._audit_workflows(api, "a" * 40, now=now)
                    checks = github_audit._audit_current_checks(api, "a" * 40, now=now)
                    self.assertEqual(workflows.status, github_audit.STATUS_FAIL)
                    self.assertEqual(checks.status, github_audit.STATUS_FAIL)
                    self.assertIn("stale or future-dated", workflows.detail)
                    self.assertIn("stale or future-dated", checks.detail)

    def test_newer_workflow_failure_cannot_be_hidden_by_historical_success(self) -> None:
        responses = _successful_workflow_responses()
        collection = responses[f"actions/runs?head_sha={'a' * 40}&per_page=100"]
        failed = copy.deepcopy(collection["workflow_runs"][0])
        baseline = datetime.fromisoformat(failed["created_at"].replace("Z", "+00:00"))
        created_at = (baseline + timedelta(minutes=1)).isoformat().replace("+00:00", "Z")
        failed.update(id=10, created_at=created_at, conclusion="failure")
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
        self.assertEqual(github_audit._audit_tag_policy([ruleset]).status, github_audit.STATUS_FAIL)

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
        bound = github_audit._github_actions_check_names(
            {
                "checks": [
                    {
                        "context": "trusted",
                        "app_id": github_audit._GITHUB_ACTIONS_APP_ID,
                    },
                    {"context": "wrong-app", "app_id": 1},
                    {"context": "float-app", "app_id": float(github_audit._GITHUB_ACTIONS_APP_ID)},
                    {"name": "name-only", "app_id": github_audit._GITHUB_ACTIONS_APP_ID},
                    {"context": "", "app_id": github_audit._GITHUB_ACTIONS_APP_ID},
                    {"context": "unbound"},
                    "legacy",
                ]
            },
            "app_id",
        )
        self.assertEqual(bound, {"trusted"})
        self.assertEqual(github_audit._github_actions_check_names(None, "app_id"), set())
        self.assertEqual(
            github_audit._github_actions_check_names({"checks": None}, "app_id"), set()
        )
        self.assertEqual(github_audit._status_check_names({"contexts": [], "checks": None}), set())
        self.assertEqual(github_audit._github_actions_check_names({"checks": []}, "unknown"), set())

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
                            {
                                "context": name,
                                "integration_id": github_audit._GITHUB_ACTIONS_APP_ID,
                            }
                            for name in github_audit._REQUIRED_BRANCH_CHECKS
                        ],
                    },
                },
            ],
        }
        self.assertTrue(github_audit._ruleset_has_required_branch_controls(branch_ruleset))
        required = next(
            rule for rule in branch_ruleset["rules"] if rule["type"] == "required_status_checks"
        )["parameters"]["required_status_checks"]
        required[0]["integration_id"] = 1
        self.assertFalse(github_audit._ruleset_has_required_branch_controls(branch_ruleset))
        required[0]["integration_id"] = github_audit._GITHUB_ACTIONS_APP_ID
        context = required[0].pop("context")
        required[0]["name"] = context
        self.assertFalse(github_audit._ruleset_has_required_branch_controls(branch_ruleset))
        required[0]["context"] = required[0].pop("name")
        required[0]["integration_id"] = float(github_audit._GITHUB_ACTIONS_APP_ID)
        self.assertFalse(github_audit._ruleset_has_required_branch_controls(branch_ruleset))
        required[0]["integration_id"] = github_audit._GITHUB_ACTIONS_APP_ID
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
            "Verify tag is current main head",
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

    def test_operational_runbook_is_fail_closed_without_invented_service_levels(self) -> None:
        operations = (ROOT / "docs" / "operations.md").read_text(encoding="utf-8")
        for marker in (
            "no on-call rotation",
            "no guaranteed",
            "publication stays frozen",
            "Do not delete or move an immutable release",
            "rotate every affected credential",
            "Sensitive source material",
            "Recovery exercise gate",
            "not a claim that an exercise has occurred",
            "production-settings audit",
        ):
            with self.subTest(marker=marker):
                self.assertIn(marker, operations)
        manifest = (ROOT / "MANIFEST.in").read_text(encoding="utf-8")
        self.assertIn("recursive-include docs *.md", manifest)

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
        self.assertIn("  push:\n    branches: [main]\n", dco)
        self.assertIn("  workflow_call:\n", dco)
        self.assertIn("Signed-off-by", dco)
        self.assertIn("git rev-list", dco)
        self.assertIn("git merge-base --is-ancestor", dco)
        self.assertIn("DCO_BASELINE: eb11b6910c1126fd7639a152f233a8fb3880a4d8", dco)
        self.assertIn('commits="$(git rev-list "$range")"', dco)
        self.assertIn("git interpret-trailers --parse", dco)
        self.assertIn("git show -s --format=%ae", dco)
        self.assertIn('AUTHOR_EMAIL="$author_email" awk', dco)
        self.assertIn("-f .github/dco-signoff.awk", dco)
        self.assertIn("check-signoff", github_audit._REQUIRED_BRANCH_CHECKS)
        self.assertIn("check-signoff", github_audit._REQUIRED_CURRENT_CHECKS)

        valid = "Subject\n\nSigned-off-by: Example Person <person@example.test>\n"
        body_only = (
            "Subject\n\nSigned-off-by: Example Person <person@example.test>\n"
            "\nThis is still ordinary body text.\n"
        )
        git_executable = shutil.which("git")
        self.assertIsNotNone(git_executable)
        assert git_executable is not None
        for message, expected in ((valid, True), (body_only, False)):
            with self.subTest(expected=expected):
                result = subprocess.run(  # noqa: S603 - executable resolved via PATH.
                    [git_executable, "interpret-trailers", "--parse"],
                    input=message,
                    capture_output=True,
                    text=True,
                    check=True,
                    timeout=10,
                )
                self.assertIs(
                    "Signed-off-by: Example Person <person@example.test>" in result.stdout,
                    expected,
                )

        awk = shutil.which("awk")
        git_path = shutil.which("git")
        if awk is None and git_path is not None:
            bundled_awk = Path(git_path).parents[1] / "usr" / "bin" / "awk.exe"
            if bundled_awk.is_file():
                awk = str(bundled_awk)
        self.assertIsNotNone(awk)
        assert awk is not None
        matcher = ROOT / ".github" / "dco-signoff.awk"
        large_valid = ("Unrelated: value\n" * 10_000) + valid
        cases = (
            (valid, "person@example.test", True),
            (
                "Signed-off-by: Example Person <o'connor+tag@example.test>\n",
                "o'connor+tag@example.test",
                True,
            ),
            (valid, "other@example.test", False),
            ("Signed-off-by: Person <two@@example.test>\n", "two@@example.test", False),
            ("Signed-off-by: Person <space @example.test>\n", "space @example.test", False),
            ("Signed-off-by: Person <a@.>\n", "a@.", False),
            ("Signed-off-by: Person <.a@example.test>\n", ".a@example.test", False),
            ("Signed-off-by: Person <a..b@example.test>\n", "a..b@example.test", False),
            (valid, r"\x70erson@example.test", False),
            (valid, r"\160erson@example.test", False),
            (large_valid, "PERSON@EXAMPLE.TEST", True),
        )
        for trailers, author_email, expected in cases:
            with self.subTest(author_email=author_email, expected=expected):
                result = subprocess.run(  # noqa: S603 - resolved awk executable and fixed program.
                    [awk, "-f", str(matcher)],
                    input=trailers,
                    env={**os.environ, "AUTHOR_EMAIL": author_email},
                    capture_output=True,
                    text=True,
                    check=False,
                    timeout=10,
                )
                self.assertEqual(result.returncode == 0, expected)

    def test_public_issue_routes_cover_bugs_and_private_contact_requests(self) -> None:
        templates = ROOT / ".github" / "ISSUE_TEMPLATE"
        bug = (templates / "bug-report.yml").read_text(encoding="utf-8")
        contact = (templates / "security-contact.yml").read_text(encoding="utf-8")
        self.assertIn("Software bug report", bug)
        self.assertIn("Do not include configuration exports", bug)
        self.assertIn("Request a private security contact", contact)
        self.assertIn("Do not describe the vulnerability", contact)
        self.assertIn("required: true", contact)

    def test_installation_uses_isolated_hash_locked_reference_environment(self) -> None:
        installation = (ROOT / "docs" / "installation.md").read_text(encoding="utf-8")
        self.assertIn("--require-hashes -r requirements-ci.lock", installation)
        self.assertIn("--require-hashes -r requirements-runtime.lock", installation)
        self.assertIn("--no-deps", installation)
        self.assertIn("--no-build-isolation", installation)
        self.assertIn("Upgrade, rollback, and removal", installation)

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

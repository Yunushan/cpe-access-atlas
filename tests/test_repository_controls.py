from __future__ import annotations

import re
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

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


class RepositoryControlTests(unittest.TestCase):
    def test_workflow_actions_are_commit_pinned(self) -> None:
        pattern = re.compile(r"^uses:\s+\S+@[0-9a-f]{40}(?:\s+#.*)?$")
        for workflow in WORKFLOW_FILES:
            with self.subTest(workflow=workflow.name):
                uses_lines = [
                    line.strip().removeprefix("- ")
                    for line in workflow.read_text(encoding="utf-8").splitlines()
                    if line.strip().startswith(("uses:", "- uses:"))
                ]
                self.assertTrue(uses_lines)
                for line in uses_lines:
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

    def test_ci_and_release_enforce_formatting_and_type_checks(self) -> None:
        ci = (ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
        release = (ROOT / ".github" / "workflows" / "release.yml").read_text(encoding="utf-8")
        for workflow_text in (ci, release):
            self.assertIn("ruff format --check", workflow_text)
            self.assertIn("mypy src", workflow_text)

    def test_mypy_is_configured_in_strict_mode(self) -> None:
        pyproject = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
        self.assertIn("[tool.mypy]", pyproject)
        self.assertIn("strict = true", pyproject)

    def test_security_audits_locked_dependencies_without_local_project(self) -> None:
        security = (ROOT / ".github" / "workflows" / "security.yml").read_text(encoding="utf-8")
        self.assertIn("-r requirements-security.lock", security)
        self.assertIn("--strict", security)
        self.assertNotIn("--local", security)

    def test_codeql_compatibility_exception_is_explicit(self) -> None:
        config = (ROOT / "src" / "cpe_access_atlas" / "config.py").read_text(encoding="utf-8")
        self.assertIn("codeql[py/weak-sensitive-data-hashing]", config)
        self.assertIn("compatibility digest for the vendor", config)
        self.assertIn("password storage or password verification", config)
        self.assertIn("usedforsecurity=False", config)

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
        check_runs = [
            {"name": name, "status": "completed", "conclusion": "success"}
            for name in github_audit._REQUIRED_CURRENT_CHECKS
        ]
        check_runs.append(
            {"name": "dependency-review", "status": "completed", "conclusion": "skipped"}
        )
        result = github_audit._audit_current_checks(
            _FakeGitHubApi({"check_runs": check_runs}), "a" * 40
        )
        self.assertEqual(result.status, github_audit.STATUS_PASS)

        incomplete = check_runs[:-1]
        result = github_audit._audit_current_checks(
            _FakeGitHubApi({"check_runs": incomplete}), "a" * 40
        )
        self.assertEqual(result.status, github_audit.STATUS_FAIL)
        self.assertIn("dependency-review", result.detail)

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
            ]
        }
        self.assertTrue(github_audit._ruleset_has_required_branch_controls(branch_ruleset))
        tag_ruleset = {"rules": [{"type": "creation"}, {"type": "update"}, {"type": "deletion"}]}
        self.assertTrue(github_audit._ruleset_has_required_tag_controls(tag_ruleset))

    def test_github_production_audit_requires_annotated_main_reachable_release_tag(self) -> None:
        api = _MappedGitHubApi(
            {
                "releases/latest": {"tag_name": "v0.3.0"},
                "git/ref/tags/v0.3.0": {"object": {"type": "tag", "sha": "tag-sha"}},
                "git/tags/tag-sha": {"object": {"type": "commit", "sha": "commit-sha"}},
                "compare/main...v0.3.0": {"status": "behind"},
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

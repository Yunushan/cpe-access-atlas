from __future__ import annotations

import re
import unittest
from pathlib import Path

ROOT = Path(__file__).parents[1]
WORKFLOW_FILES = (
    ROOT / ".github" / "workflows" / "ci.yml",
    ROOT / ".github" / "workflows" / "security.yml",
    ROOT / ".github" / "workflows" / "release.yml",
    ROOT / ".github" / "workflows" / "codeql.yml",
    ROOT / ".github" / "workflows" / "dco.yml",
    ROOT / ".github" / "workflows" / "secret-scan.yml",
)


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

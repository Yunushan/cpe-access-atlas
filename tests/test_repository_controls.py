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

    def test_security_audits_locked_dependencies_without_local_project(self) -> None:
        security = (ROOT / ".github" / "workflows" / "security.yml").read_text(
            encoding="utf-8"
        )
        self.assertIn("-r requirements-security.lock", security)
        self.assertIn("--strict", security)
        self.assertNotIn("--local", security)

    def test_release_contains_required_safety_gates(self) -> None:
        release = (ROOT / ".github" / "workflows" / "release.yml").read_text(
            encoding="utf-8"
        )
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
        settings = (ROOT / "docs" / "github-production-settings.md").read_text(
            encoding="utf-8"
        )
        self.assertIn("Dependency graph", settings)
        self.assertIn("release` environment", settings)

    def test_source_distribution_manifest_includes_governance_config(self) -> None:
        manifest = (ROOT / "MANIFEST.in").read_text(encoding="utf-8")
        self.assertIn(".github/dependabot.yml", manifest)
        self.assertIn("recursive-include .github *.yml", manifest)

    def test_generated_temporary_artifacts_are_ignored(self) -> None:
        gitignore = (ROOT / ".gitignore").read_text(encoding="utf-8")
        self.assertIn(".tmp/", gitignore)


if __name__ == "__main__":
    unittest.main()

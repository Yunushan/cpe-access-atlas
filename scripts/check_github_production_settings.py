# SPDX-License-Identifier: 0BSD
"""Run a read-only GitHub production-settings audit.

This script deliberately uses ``gh api`` for administrator-visible settings
instead of making any write requests.  A missing permission is reported as
``UNVERIFIED`` rather than being mistaken for a disabled control.

Usage:
    python scripts/check_github_production_settings.py --repo OWNER/REPO
    python scripts/check_github_production_settings.py --repo OWNER/REPO --json
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
from dataclasses import asdict, dataclass
from typing import Any

STATUS_OK = "PASS"
STATUS_BAD = "FAIL"
STATUS_UNKNOWN = "UNVERIFIED"
# Backwards-readable aliases keep the result vocabulary obvious at call sites;
# values are derived from the non-secret-named constants above.
STATUS_PASS = STATUS_OK
STATUS_FAIL = STATUS_BAD
STATUS_UNVERIFIED = STATUS_UNKNOWN
_EXPECTED_WORKFLOWS = {"CI", "Security audit", "CodeQL", "Secret scan"}
_REQUIRED_RELEASE_ASSET_MARKERS = (".whl", ".tar.gz", "sbom.cdx.json", "SHA256SUMS")
_CI_CHECK_NAMES = tuple(
    f"test ({operating_system}, {python_version})"
    for operating_system in ("ubuntu-latest", "windows-latest", "macos-latest")
    for python_version in ("3.11", "3.12", "3.13", "3.14")
)
_REQUIRED_BRANCH_CHECKS = frozenset(
    (
        *_CI_CHECK_NAMES,
        "package-smoke",
        "dependency-audit",
        "dependency-review",
        "analyze",
        "gitleaks",
    )
)
_REQUIRED_CURRENT_CHECKS = frozenset(
    (*_CI_CHECK_NAMES, "package-smoke", "dependency-audit", "analyze", "gitleaks")
)


@dataclass(frozen=True)
class CheckResult:
    name: str
    status: str
    detail: str


class GitHubApi:
    """Small read-only adapter around the authenticated GitHub CLI."""

    def __init__(self, repo: str) -> None:
        self.repo = repo

    def get(self, path: str) -> tuple[Any | None, str | None]:
        executable = shutil.which("gh")
        if executable is None:
            return None, "gh CLI was not found on PATH"
        endpoint = f"repos/{self.repo}" if not path else f"repos/{self.repo}/{path}"
        try:
            completed = subprocess.run(  # noqa: S603
                [executable, "api", endpoint],
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                check=False,
                timeout=30,
            )
        except subprocess.TimeoutExpired:
            return None, "gh api timed out after 30 seconds"
        except OSError as exc:
            return None, f"unable to run gh api: {exc}"
        if completed.returncode != 0:
            message = (completed.stderr or completed.stdout or "").strip().splitlines()
            return None, message[-1] if message else "gh api failed"
        try:
            return json.loads(completed.stdout or ""), None
        except json.JSONDecodeError as exc:
            return None, f"GitHub returned invalid JSON: {exc.msg}"


def _branch_rule_matches(ruleset: dict[str, Any], ref: str) -> bool:
    conditions = ruleset.get("conditions")
    if not isinstance(conditions, dict):
        return False
    ref_name = conditions.get("ref_name")
    if not isinstance(ref_name, dict):
        return False
    includes = ref_name.get("include")
    return isinstance(includes, list) and ref in includes


def _ruleset_has_type(ruleset: dict[str, Any], rule_type: str) -> bool:
    rules = ruleset.get("rules")
    if not isinstance(rules, list):
        return False
    return any(isinstance(rule, dict) and rule.get("type") == rule_type for rule in rules)


def _status_check_names(statuses: Any) -> set[str]:
    """Normalize legacy contexts and modern required-check entries."""

    if not isinstance(statuses, dict):
        return set()
    names: set[str] = set()
    contexts = statuses.get("contexts")
    if isinstance(contexts, list):
        names.update(item for item in contexts if isinstance(item, str))
    checks = statuses.get("checks")
    if isinstance(checks, list):
        for item in checks:
            if isinstance(item, str):
                names.add(item)
            elif isinstance(item, dict):
                for key in ("context", "name"):
                    value = item.get(key)
                    if isinstance(value, str):
                        names.add(value)
                        break
    return names


def _ruleset_parameters(ruleset: dict[str, Any], rule_type: str) -> dict[str, Any]:
    rules = ruleset.get("rules")
    if not isinstance(rules, list):
        return {}
    for rule in rules:
        if isinstance(rule, dict) and rule.get("type") == rule_type:
            parameters = rule.get("parameters")
            return parameters if isinstance(parameters, dict) else {}
    return {}


def _ruleset_has_required_branch_controls(ruleset: dict[str, Any]) -> bool:
    pull_request = _ruleset_parameters(ruleset, "pull_request")
    status_checks = _ruleset_parameters(ruleset, "required_status_checks")
    required_checks = status_checks.get("required_status_checks")
    required_check_names = _status_check_names({"checks": required_checks})
    required_reviews = pull_request.get("required_approving_review_count", 0)
    code_owner = pull_request.get(
        "require_code_owner_review", pull_request.get("require_code_owner_reviews")
    )
    stale = pull_request.get(
        "dismiss_stale_reviews_on_push", pull_request.get("dismiss_stale_reviews")
    )
    conversation = pull_request.get("required_review_thread_resolution")
    strict_checks = status_checks.get("strict_required_status_checks_policy")
    return (
        type(required_reviews) is int
        and required_reviews >= 1
        and code_owner is True
        and stale is True
        and conversation is True
        and strict_checks is True
        and _REQUIRED_BRANCH_CHECKS.issubset(required_check_names)
        and _ruleset_has_type(ruleset, "deletion")
        and _ruleset_has_type(ruleset, "non_fast_forward")
    )


def _ruleset_has_required_tag_controls(ruleset: dict[str, Any]) -> bool:
    return (
        _ruleset_has_type(ruleset, "creation")
        and _ruleset_has_type(ruleset, "deletion")
        and (_ruleset_has_type(ruleset, "update") or _ruleset_has_type(ruleset, "non_fast_forward"))
    )


def _active_ruleset(rulesets: Any, ref: str, target: str) -> dict[str, Any] | None:
    if not isinstance(rulesets, list):
        return None
    for ruleset in rulesets:
        if not isinstance(ruleset, dict):
            continue
        if ruleset.get("enforcement") != "active":
            continue
        if ruleset.get("target") != target:
            continue
        if _branch_rule_matches(ruleset, ref):
            return ruleset
    return None


def _audit_branch_policy(api: GitHubApi, rulesets: Any, errors: list[str]) -> CheckResult:
    protection, error = api.get("branches/main/protection")
    if error is None and isinstance(protection, dict):
        reviews = protection.get("required_pull_request_reviews") or {}
        statuses = protection.get("required_status_checks") or {}
        if not isinstance(reviews, dict) or not isinstance(statuses, dict):
            return CheckResult(
                "main branch enforcement",
                STATUS_FAIL,
                "branch protection returned malformed review/check settings",
            )
        required_reviews = reviews.get("required_approving_review_count", 0)
        required_check_names = _status_check_names(statuses)
        enforce_admins_data = protection.get("enforce_admins")
        force_push_data = protection.get("allow_force_pushes")
        deletion_data = protection.get("allow_deletions")
        conversation_data = protection.get("required_conversation_resolution")
        enforce_admins = (
            isinstance(enforce_admins_data, dict) and enforce_admins_data.get("enabled") is True
        )
        no_force_push = (
            isinstance(force_push_data, dict) and force_push_data.get("enabled") is False
        )
        no_delete = isinstance(deletion_data, dict) and deletion_data.get("enabled") is False
        conversation = (
            isinstance(conversation_data, dict) and conversation_data.get("enabled") is True
        )
        dismiss_stale = reviews.get("dismiss_stale_reviews") is True
        code_owner = reviews.get("require_code_owner_reviews") is True
        missing_checks = sorted(_REQUIRED_BRANCH_CHECKS - required_check_names)
        if (
            required_reviews >= 1
            and not missing_checks
            and enforce_admins
            and no_force_push
            and no_delete
            and conversation
            and dismiss_stale
            and code_owner
        ):
            return CheckResult(
                "main branch enforcement", STATUS_PASS, "branch protection is enabled"
            )
        detail = "branch protection exists but does not contain every required review/check control"
        if missing_checks:
            detail += "; missing checks: " + ", ".join(missing_checks)
        return CheckResult(
            "main branch enforcement",
            STATUS_FAIL,
            detail,
        )
    ruleset = _active_ruleset(rulesets, "refs/heads/main", "branch")
    if ruleset is not None and _ruleset_has_required_branch_controls(ruleset):
        return CheckResult(
            "main branch enforcement", STATUS_PASS, "an active main-branch ruleset is present"
        )
    if ruleset is not None:
        return CheckResult(
            "main branch enforcement",
            STATUS_FAIL,
            "an active main-branch ruleset exists but lacks required review/check controls",
        )
    if error:
        if "Branch not protected" in error or "HTTP 404" in error:
            return CheckResult(
                "main branch enforcement",
                STATUS_FAIL,
                "main has no branch protection and no matching ruleset was found",
            )
        errors.append(f"main branch protection: {error}")
    return CheckResult(
        "main branch enforcement",
        STATUS_UNKNOWN,
        (
            "administrator-visible branch protection was not available and no matching "
            "ruleset was found"
        ),
    )


def _audit_tag_policy(rulesets: Any) -> CheckResult:
    ruleset = _active_ruleset(rulesets, "refs/tags/v*", "tag")
    if ruleset is not None and _ruleset_has_required_tag_controls(ruleset):
        return CheckResult(
            "release tag enforcement", STATUS_PASS, "an active v* tag ruleset is present"
        )
    if ruleset is not None:
        return CheckResult(
            "release tag enforcement",
            STATUS_FAIL,
            "the active v* tag ruleset lacks creation, update, or deletion controls",
        )
    return CheckResult(
        "release tag enforcement",
        STATUS_FAIL,
        "no active ruleset protecting refs/tags/v* was visible",
    )


def _audit_release_environment(api: GitHubApi) -> CheckResult:
    environment, error = api.get("environments/release")
    if error is not None:
        return CheckResult("release environment", STATUS_UNVERIFIED, error)
    if not isinstance(environment, dict):
        return CheckResult("release environment", STATUS_UNVERIFIED, "invalid environment response")
    rules = environment.get("protection_rules")
    has_reviewers = isinstance(rules, list) and any(
        isinstance(rule, dict) and rule.get("type") == "required_reviewers" for rule in rules
    )
    if has_reviewers and environment.get("can_admins_bypass") is False:
        return CheckResult("release environment", STATUS_PASS, "required reviewers are configured")
    return CheckResult(
        "release environment",
        STATUS_FAIL,
        "the release environment lacks required reviewers or allows administrator bypass",
    )


def _audit_security_features(repo_data: Any) -> CheckResult:
    if not isinstance(repo_data, dict):
        return CheckResult(
            "repository security features", STATUS_UNVERIFIED, "invalid repository response"
        )
    security = repo_data.get("security_and_analysis")
    if not isinstance(security, dict):
        return CheckResult(
            "repository security features",
            STATUS_UNVERIFIED,
            "security feature state requires administrator-visible repository metadata",
        )
    required = {
        "dependency_graph": "Dependency graph",
        "dependabot_security_updates": "Dependabot security updates",
        "secret_scanning": "secret scanning",
        "secret_scanning_push_protection": "secret push protection",
    }
    disabled = [
        label
        for key, label in required.items()
        if not isinstance(security.get(key), dict) or security[key].get("status") != "enabled"
    ]
    if disabled:
        return CheckResult(
            "repository security features",
            STATUS_FAIL,
            "disabled or missing: " + ", ".join(disabled),
        )
    return CheckResult(
        "repository security features", STATUS_PASS, "required security features are enabled"
    )


def _audit_actions_policy(api: GitHubApi) -> CheckResult:
    permissions, error = api.get("actions/permissions")
    if error is not None:
        return CheckResult("Actions policy", STATUS_UNVERIFIED, error)
    workflow, workflow_error = api.get("actions/permissions/workflow")
    if workflow_error is not None:
        return CheckResult("Actions policy", STATUS_UNVERIFIED, workflow_error)
    if not isinstance(permissions, dict) or not isinstance(workflow, dict):
        return CheckResult("Actions policy", STATUS_UNVERIFIED, "invalid Actions policy response")
    allowed = permissions.get("allowed_actions")
    sha_pinning = permissions.get("sha_pinning_required")
    default_permissions = workflow.get("default_workflow_permissions")
    can_approve = workflow.get("can_approve_pull_request_reviews")
    if (
        allowed in {"selected", "verified"}
        and sha_pinning is True
        and default_permissions == "read"
        and can_approve is False
    ):
        return CheckResult(
            "Actions policy",
            STATUS_PASS,
            "restricted actions, SHA pinning, and read-only defaults are enabled",
        )
    return CheckResult(
        "Actions policy",
        STATUS_FAIL,
        "Actions policy is broader than the required production baseline",
    )


def _audit_alerts(api: GitHubApi) -> list[CheckResult]:
    checks: list[CheckResult] = []
    endpoints = (
        ("Dependabot alerts", "dependabot/alerts?state=open&per_page=100"),
        ("CodeQL alerts", "code-scanning/alerts?state=open&per_page=100"),
        ("secret-scanning alerts", "secret-scanning/alerts?state=open&per_page=100"),
    )
    for name, endpoint in endpoints:
        payload, error = api.get(endpoint)
        if error is not None:
            checks.append(CheckResult(name, STATUS_UNVERIFIED, error))
        elif isinstance(payload, list) and not payload:
            checks.append(CheckResult(name, STATUS_PASS, "no open alerts"))
        elif isinstance(payload, list):
            findings: list[str] = []
            for item in payload[:3]:
                if not isinstance(item, dict):
                    continue
                rule = item.get("rule")
                rule_id = rule.get("id") if isinstance(rule, dict) else "unknown-rule"
                instance = item.get("most_recent_instance")
                location = instance.get("location") if isinstance(instance, dict) else None
                path = location.get("path") if isinstance(location, dict) else None
                findings.append(f"{rule_id}" + (f" ({path})" if path else ""))
            detail = f"{len(payload)} open alert(s)"
            if findings:
                detail += ": " + "; ".join(findings)
            checks.append(CheckResult(name, STATUS_BAD, detail))
        else:
            checks.append(CheckResult(name, STATUS_BAD, "invalid alert response"))
    return checks


def _audit_release(api: GitHubApi) -> CheckResult:
    release, error = api.get("releases/latest")
    if error is not None:
        return CheckResult("published release", STATUS_UNVERIFIED, error)
    if not isinstance(release, dict):
        return CheckResult("published release", STATUS_UNVERIFIED, "invalid release response")
    assets = release.get("assets")
    names = (
        [item.get("name", "") for item in assets if isinstance(item, dict)]
        if isinstance(assets, list)
        else []
    )
    missing = [
        marker
        for marker in _REQUIRED_RELEASE_ASSET_MARKERS
        if not any(marker in name for name in names)
    ]
    if release.get("draft") is False and release.get("prerelease") is False and not missing:
        return CheckResult(
            "published release",
            STATUS_PASS,
            f"{release.get('tag_name', 'unknown')} has release artifacts",
        )
    detail = "draft/prerelease release or missing assets"
    if missing:
        detail += ": " + ", ".join(missing)
    return CheckResult("published release", STATUS_FAIL, detail)


def _audit_release_tag(api: GitHubApi) -> CheckResult:
    release, error = api.get("releases/latest")
    if error is not None:
        return CheckResult("release tag integrity", STATUS_UNVERIFIED, error)
    if not isinstance(release, dict) or not isinstance(release.get("tag_name"), str):
        return CheckResult("release tag integrity", STATUS_UNVERIFIED, "invalid release response")
    tag_name = release["tag_name"]
    tag_ref, error = api.get(f"git/ref/tags/{tag_name}")
    if error is not None:
        return CheckResult("release tag integrity", STATUS_UNVERIFIED, error)
    if not isinstance(tag_ref, dict) or not isinstance(tag_ref.get("object"), dict):
        return CheckResult("release tag integrity", STATUS_UNVERIFIED, "invalid tag reference")
    tag_object = tag_ref["object"]
    if tag_object.get("type") != "tag" or not isinstance(tag_object.get("sha"), str):
        return CheckResult(
            "release tag integrity", STATUS_FAIL, f"{tag_name} is not an annotated tag"
        )
    annotated_tag, error = api.get(f"git/tags/{tag_object['sha']}")
    if error is not None:
        return CheckResult("release tag integrity", STATUS_UNVERIFIED, error)
    if not isinstance(annotated_tag, dict) or not isinstance(annotated_tag.get("object"), dict):
        return CheckResult("release tag integrity", STATUS_UNVERIFIED, "invalid annotated tag")
    target = annotated_tag["object"]
    if target.get("type") != "commit":
        return CheckResult(
            "release tag integrity", STATUS_FAIL, f"{tag_name} does not target a commit"
        )
    comparison, error = api.get(f"compare/main...{tag_name}")
    if error is not None:
        return CheckResult("release tag integrity", STATUS_UNVERIFIED, error)
    if not isinstance(comparison, dict):
        return CheckResult(
            "release tag integrity", STATUS_UNVERIFIED, "invalid comparison response"
        )
    if comparison.get("status") not in {"behind", "identical"}:
        return CheckResult(
            "release tag integrity",
            STATUS_FAIL,
            f"{tag_name} is not reachable from main (status={comparison.get('status', 'unknown')})",
        )
    return CheckResult(
        "release tag integrity", STATUS_PASS, f"{tag_name} is annotated and reachable from main"
    )


def _audit_workflows(api: GitHubApi, head_sha: str) -> CheckResult:
    runs, error = api.get(f"actions/runs?head_sha={head_sha}&per_page=100")
    if error is not None:
        return CheckResult("current required workflows", STATUS_UNVERIFIED, error)
    if not isinstance(runs, dict) or not isinstance(runs.get("workflow_runs"), list):
        return CheckResult(
            "current required workflows", STATUS_UNVERIFIED, "invalid workflow response"
        )
    successful = {
        str(run.get("name"))
        for run in runs["workflow_runs"]
        if isinstance(run, dict)
        and run.get("status") == "completed"
        and run.get("conclusion") == "success"
    }
    missing = sorted(_EXPECTED_WORKFLOWS - successful)
    if not missing:
        return CheckResult(
            "current required workflows",
            STATUS_PASS,
            f"all required workflows passed for {head_sha[:7]}",
        )
    return CheckResult(
        "current required workflows",
        STATUS_FAIL,
        "missing successful workflows: " + ", ".join(missing),
    )


def _audit_current_checks(api: GitHubApi, head_sha: str) -> CheckResult:
    checks, error = api.get(f"commits/{head_sha}/check-runs?per_page=100")
    if error is not None:
        return CheckResult("current required checks", STATUS_UNVERIFIED, error)
    if not isinstance(checks, dict) or not isinstance(checks.get("check_runs"), list):
        return CheckResult(
            "current required checks", STATUS_UNVERIFIED, "invalid check-run response"
        )
    successful: set[str] = set()
    skipped: set[str] = set()
    for check in checks["check_runs"]:
        if not isinstance(check, dict) or not isinstance(check.get("name"), str):
            continue
        if check.get("status") != "completed":
            continue
        if check.get("conclusion") == "success":
            successful.add(check["name"])
        elif check.get("conclusion") == "skipped":
            skipped.add(check["name"])
    missing = sorted(_REQUIRED_CURRENT_CHECKS - successful)
    if "dependency-review" not in successful and "dependency-review" not in skipped:
        missing.append("dependency-review (success or expected push skip)")
    if not missing:
        return CheckResult(
            "current required checks", STATUS_PASS, f"required check runs passed for {head_sha[:7]}"
        )
    return CheckResult(
        "current required checks", STATUS_FAIL, "missing successful checks: " + ", ".join(missing)
    )


def audit(repo: str) -> list[CheckResult]:
    api = GitHubApi(repo)
    errors: list[str] = []
    repo_data, repo_error = api.get("")
    if repo_error is not None:
        return [CheckResult("repository access", STATUS_UNVERIFIED, repo_error)]
    if not isinstance(repo_data, dict):
        return [CheckResult("repository access", STATUS_UNVERIFIED, "invalid repository response")]

    results = [
        CheckResult(
            "repository access", STATUS_PASS, f"{repo_data.get('full_name', repo)} is reachable"
        ),
        _audit_security_features(repo_data),
    ]
    rulesets, ruleset_error = api.get("rulesets")
    if ruleset_error is not None:
        results.append(CheckResult("repository rulesets", STATUS_UNVERIFIED, ruleset_error))
        rulesets = []
    else:
        results.append(
            CheckResult("repository rulesets", STATUS_PASS, "rulesets endpoint is readable")
        )
    results.append(_audit_branch_policy(api, rulesets, errors))
    results.append(_audit_tag_policy(rulesets))
    results.append(_audit_release_environment(api))
    results.append(_audit_actions_policy(api))
    results.extend(_audit_alerts(api))
    results.append(_audit_release(api))
    results.append(_audit_release_tag(api))
    head_sha, head_error = api.get("commits/main")
    if (
        head_error is not None
        or not isinstance(head_sha, dict)
        or not isinstance(head_sha.get("sha"), str)
    ):
        results.append(
            CheckResult(
                "current required workflows",
                STATUS_UNVERIFIED,
                head_error or "invalid main commit response",
            )
        )
    else:
        results.append(_audit_workflows(api, head_sha["sha"]))
        results.append(_audit_current_checks(api, head_sha["sha"]))
    if errors:
        results.extend(CheckResult("audit diagnostics", STATUS_UNVERIFIED, item) for item in errors)
    return results


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--repo",
        default=os.environ.get("GITHUB_REPOSITORY"),
        help="repository in OWNER/REPO form (defaults to GITHUB_REPOSITORY)",
    )
    parser.add_argument("--json", action="store_true", help="emit machine-readable JSON")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    if (
        not args.repo
        or "/" not in args.repo
        or args.repo.startswith("/")
        or args.repo.endswith("/")
    ):
        print("--repo OWNER/REPO is required", file=sys.stderr)
        return 2
    results = audit(args.repo)
    if args.json:
        print(json.dumps([asdict(result) for result in results], indent=2))
    else:
        for result in results:
            print(f"[{result.status:<10}] {result.name}: {result.detail}")
    return 0 if all(result.status == STATUS_PASS for result in results) else 1


if __name__ == "__main__":
    raise SystemExit(main())

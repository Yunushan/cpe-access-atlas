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
import ast
import base64
import fnmatch
import json
import os
import re
import shutil
import subprocess
import sys
import tomllib
from dataclasses import asdict, dataclass
from datetime import datetime
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
_WORKFLOW_PATHS = {
    "CI": ".github/workflows/ci.yml",
    "Security audit": ".github/workflows/security.yml",
    "CodeQL": ".github/workflows/codeql.yml",
    "Secret scan": ".github/workflows/secret-scan.yml",
}
_RELEASE_VERSION = r"[0-9]+\.[0-9]+\.[0-9]+(?:(?:a|b|rc)[0-9]+)?(?:\.post[0-9]+)?(?:\.dev[0-9]+)?"
_RELEASE_TAG = re.compile(rf"v({_RELEASE_VERSION})")
_GIT_SHA = re.compile(r"[0-9a-f]{40}")
_REPOSITORY = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?/[A-Za-z0-9_.-]{1,100}")
_ASSET_DIGEST = re.compile(r"sha256:[0-9a-f]{64}")
_RELEASE_OSES = ("ubuntu-latest", "windows-latest", "macos-latest")
_RELEASE_PYTHONS = ("3.11", "3.12", "3.13", "3.14")
_APPROVED_ACTION_REPOSITORIES = frozenset(
    {
        "actions/checkout",
        "actions/setup-python",
        "actions/upload-artifact",
        "actions/download-artifact",
        "actions/attest-build-provenance",
        "actions/dependency-review-action",
        "github/codeql-action",
        "gitleaks/gitleaks-action",
    }
)
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
_WORKFLOW_CHECKS = {
    "CI": (*_CI_CHECK_NAMES, "package-smoke"),
    "Security audit": ("dependency-audit", "dependency-review"),
    "CodeQL": ("analyze",),
    "Secret scan": ("gitleaks",),
}


@dataclass(frozen=True)
class CheckResult:
    name: str
    status: str
    detail: str


def _request_failure(completed: subprocess.CompletedProcess[str]) -> tuple[str, bool]:
    """Summarize failure metadata without copying private CLI/server diagnostics."""

    message = completed.stderr or completed.stdout or ""
    codes = set(re.findall(r"\bHTTP ([1-5][0-9]{2})\b", message))
    status = next(iter(codes)) if len(codes) == 1 else None
    suffix = f" (HTTP {status})" if status else f" (exit {completed.returncode})"
    rate_limited = status == "429" or (
        status == "403"
        and re.search(r"\brate[ -]limit(?:ed|s)?\b", message, re.IGNORECASE) is not None
    )
    if rate_limited:
        return "GitHub API rate limit reached; new requests deferred for this audit" + suffix, True
    reasons = {
        "401": "GitHub authentication required",
        "403": "GitHub API access denied",
        "404": "GitHub API resource unavailable or inaccessible",
    }
    if status is not None and status.startswith("5"):
        return "GitHub API server error" + suffix, False
    return reasons.get(status or "", "gh api request failed") + suffix, False


class GitHubApi:
    """Small read-only adapter around the authenticated GitHub CLI."""

    def __init__(self, repo: str) -> None:
        self.repo = repo
        self._cache: dict[str, Any] = {}
        self._deferred_error: str | None = None

    def get(self, path: str) -> tuple[Any | None, str | None]:
        if path in self._cache:
            return self._cache[path], None
        if self._deferred_error is not None:
            return None, self._deferred_error
        executable = shutil.which("gh")
        if executable is None:
            return None, "gh CLI was not found on PATH"
        endpoint = f"repos/{self.repo}" if not path else f"repos/{self.repo}/{path}"
        try:
            completed = subprocess.run(  # noqa: S603
                [executable, "api", "--method", "GET", endpoint],
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
            suffix = f" (OS error {exc.errno})" if type(exc.errno) is int else ""
            return None, "unable to run gh api; check local executable access" + suffix
        if completed.returncode != 0:
            error, rate_limited = _request_failure(completed)
            if rate_limited:
                self._deferred_error = error
            return None, error
        try:
            payload = json.loads(completed.stdout or "")
        except (ValueError, RecursionError):
            return None, "GitHub returned invalid or excessively nested JSON"
        self._cache[path] = payload
        return payload, None


def _get_collection(
    api: GitHubApi, path: str, key: str | None = None
) -> tuple[list[Any] | None, str | None]:
    """Fetch all pages; an incomplete response must never prove a passing audit."""

    separator = "&" if "?" in path else "?"
    endpoint = path if "per_page=" in path else f"{path}{separator}per_page=100"
    values: list[Any] = []
    expected_total: int | None = None
    for page in range(1, 101):
        payload, error = api.get(endpoint if page == 1 else f"{endpoint}&page={page}")
        if error:
            return None, error
        if key is not None:
            if not isinstance(payload, dict):
                return None, f"invalid collection response for {path}"
            records = payload.get(key)
        else:
            records = payload
        if not isinstance(records, list) or len(records) > 100:
            return None, f"invalid collection response for {path}"
        total = payload.get("total_count") if isinstance(payload, dict) else None
        if isinstance(payload, dict) and "total_count" in payload:
            if type(total) is not int or total < 0:
                return None, f"invalid collection total for {path}"
            if expected_total is not None and total != expected_total:
                return None, f"collection total changed during pagination for {path}"
            expected_total = total
        elif expected_total is not None:
            return None, f"collection total missing during pagination for {path}"
        values.extend(records)
        if expected_total is not None and len(values) > expected_total:
            return None, f"collection exceeds its reported total for {path}"
        if len(records) < 100:
            if expected_total is not None and expected_total != len(values):
                return None, f"incomplete collection response for {path}"
            return values, None
    return None, f"pagination safety limit reached for {path}"


def _load_rulesets(api: GitHubApi) -> tuple[list[Any], list[str]]:
    summaries, error = _get_collection(api, "rulesets")
    if error:
        return [], [error]
    details: list[Any] = []
    errors: list[str] = []
    seen: set[int] = set()
    for summary in summaries or []:
        if (
            not isinstance(summary, dict)
            or type(summary.get("id")) is not int
            or summary["id"] < 1
            or summary["id"] in seen
        ):
            errors.append("invalid ruleset summary")
            continue
        seen.add(summary["id"])
        detail, error = api.get(f"rulesets/{summary['id']}")
        if (
            error
            or not isinstance(detail, dict)
            or type(detail.get("id")) is not int
            or detail["id"] != summary["id"]
            or not isinstance(detail.get("rules"), list)
        ):
            errors.append(error or "invalid ruleset detail")
        else:
            details.append(detail)
    return details, errors


def _branch_rule_matches(ruleset: dict[str, Any], ref: str) -> bool:
    conditions = ruleset.get("conditions")
    if not isinstance(conditions, dict):
        return False
    ref_name = conditions.get("ref_name")
    if not isinstance(ref_name, dict):
        return False
    includes = ref_name.get("include")
    excludes = ref_name.get("exclude", [])
    if not isinstance(includes, list) or not isinstance(excludes, list):
        return False

    def matches(pattern: Any) -> bool:
        if pattern == "~ALL":
            return True
        if pattern == "~DEFAULT_BRANCH":
            return ref == "refs/heads/main"
        # A per-component match follows GitHub's pathname boundary for '*'.
        # Complex recursive patterns are evaluated by the effective-rules API
        # for main; do not guess at their meaning here.
        if not isinstance(pattern, str):
            return False
        parts, patterns = ref.split("/"), pattern.split("/")
        return len(parts) == len(patterns) and all(
            fnmatch.fnmatchcase(part, item) for part, item in zip(parts, patterns, strict=True)
        )

    return any(matches(pattern) for pattern in includes) and not any(
        matches(pattern) for pattern in excludes
    )


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
        and ruleset.get("bypass_actors") == []
    )


def _audit_branch_policy(api: GitHubApi, rulesets: Any, errors: list[str]) -> CheckResult:
    effective, effective_error = _get_collection(api, "rules/branches/main")
    if effective_error:
        errors.append(f"effective main rules: {effective_error}")
    elif effective:
        valid_ids = all(
            isinstance(rule, dict)
            and type(rule.get("ruleset_id")) is int
            and rule["ruleset_id"] > 0
            for rule in effective
        )
        ids = {rule["ruleset_id"] for rule in effective} if valid_ids else set()
        details = [
            rule
            for rule in rulesets
            if isinstance(rule, dict) and type(rule.get("id")) is int and rule["id"] in ids
        ]
        if (
            ids
            and None not in ids
            and ids == {rule.get("id") for rule in details}
            and all(isinstance(rule.get("bypass_actors"), list) for rule in details)
        ):
            combined = {
                "rules": effective,
                "bypass_actors": [
                    actor for rule in details for actor in rule.get("bypass_actors", [])
                ],
            }
            if _ruleset_has_required_branch_controls(combined):
                return CheckResult(
                    "main branch enforcement",
                    STATUS_PASS,
                    "effective main rules enforce required controls without bypass actors",
                )
        else:
            errors.append("effective main rule details or bypass actors could not be verified")
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
            type(required_reviews) is int
            and required_reviews >= 1
            and statuses.get("strict") is True
            and not missing_checks
            and enforce_admins
            and no_force_push
            and no_delete
            and conversation
            and dismiss_stale
            and code_owner
        ):
            # Administrator enforcement does not remove explicit PR bypass
            # allowances. Missing details cannot establish a no-bypass policy.
            allowances = reviews.get("bypass_pull_request_allowances")
            if not isinstance(allowances, dict) or any(
                not isinstance(allowances.get(kind), list) for kind in ("users", "teams", "apps")
            ):
                return CheckResult(
                    "main branch enforcement", STATUS_UNKNOWN, "PR bypass allowances unavailable"
                )
            if any(allowances[kind] for kind in ("users", "teams", "apps")):
                return CheckResult(
                    "main branch enforcement", STATUS_FAIL, "explicit PR bypass allowances exist"
                )
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
    branch, branch_error = api.get("branches/main")
    if (
        not branch_error
        and isinstance(branch, dict)
        and branch.get("protected") is False
        and effective == []
    ):
        return CheckResult(
            "main branch enforcement",
            STATUS_FAIL,
            "main is unprotected and has no effective rules",
        )
    if error:
        if "Branch not protected" in error and effective == []:
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


def _audit_tag_policy(
    rulesets: Any, allowed_creators: frozenset[tuple[str, int]] = frozenset()
) -> CheckResult:
    """Prove immutable v* tags separately from authorization to create them.

    A creation-rule bypass must not also bypass update/deletion restrictions.
    Combine independent rulesets only when they cover the entire namespace.
    The caller explicitly identifies trusted creation actors; role-wide grants
    are never inferred to mean a reviewed release maintainer.
    """

    if not isinstance(rulesets, list):
        return CheckResult("release tag enforcement", STATUS_UNKNOWN, "invalid ruleset list")
    immutable: set[str] = set()
    creator_sets: list[set[tuple[str, int]]] = []
    unavailable = False
    for ruleset in rulesets:
        if not isinstance(ruleset, dict):
            unavailable = True
            continue
        if ruleset.get("target") != "tag" or ruleset.get("enforcement") != "active":
            continue
        conditions = ruleset.get("conditions")
        refs = conditions.get("ref_name") if isinstance(conditions, dict) else None
        if (
            not isinstance(refs, dict)
            or not isinstance(refs.get("include"), list)
            or not isinstance(refs.get("exclude"), list)
        ):
            unavailable = True
            continue
        if refs["exclude"] or not any(
            isinstance(pattern, str) and pattern in {"~ALL", "refs/tags/*", "refs/tags/v*"}
            for pattern in refs["include"]
        ):
            if _ruleset_has_type(ruleset, "creation"):
                # A narrower creation rule may prohibit some v* releases even
                # when a full-namespace rule grants their creator permission.
                unavailable = True
            continue
        bypass = ruleset.get("bypass_actors")
        if not isinstance(bypass, list) or not isinstance(ruleset.get("rules"), list):
            unavailable = True
            continue
        if not bypass:
            immutable.update(
                kind for kind in ("update", "deletion") if _ruleset_has_type(ruleset, kind)
            )
        trusted_bypass = all(
            isinstance(actor, dict)
            and isinstance(actor.get("actor_type"), str)
            and type(actor.get("actor_id")) is int
            and (actor["actor_type"], actor["actor_id"]) in allowed_creators
            and actor.get("bypass_mode") == "always"
            for actor in bypass
        )
        if _ruleset_has_type(ruleset, "creation"):
            if not trusted_bypass:
                return CheckResult(
                    "release tag enforcement",
                    STATUS_FAIL,
                    "release creators are not explicitly trusted",
                )
            creator_sets.append({(actor["actor_type"], actor["actor_id"]) for actor in bypass})
    creators = set.intersection(*creator_sets) if creator_sets else set()
    if creators and immutable == {"update", "deletion"} and not unavailable:
        return CheckResult(
            "release tag enforcement",
            STATUS_PASS,
            "trusted creators can satisfy every v* creation rule; updates/deletions have no bypass",
        )
    return CheckResult(
        "release tag enforcement",
        STATUS_UNKNOWN if unavailable else STATUS_FAIL,
        "v* tags need an operational trusted creator and separate no-bypass "
        "update/deletion controls",
    )


def _audit_release_environment(api: GitHubApi) -> CheckResult:
    environment, error = api.get("environments/release")
    if error is not None:
        return CheckResult("release environment", STATUS_UNVERIFIED, error)
    if not isinstance(environment, dict):
        return CheckResult("release environment", STATUS_UNVERIFIED, "invalid environment response")
    rules = environment.get("protection_rules")
    bypass = environment.get("can_admins_bypass")
    if not isinstance(rules, list) or type(bypass) is not bool:
        return CheckResult("release environment", STATUS_UNKNOWN, "incomplete protection settings")
    reviewers = [
        rule
        for rule in rules
        if isinstance(rule, dict) and rule.get("type") == "required_reviewers"
    ]
    if bypass or not reviewers:
        return CheckResult(
            "release environment",
            STATUS_FAIL,
            "release requires reviewers and must disallow administrator bypass",
        )
    if len(reviewers) != 1:
        return CheckResult("release environment", STATUS_UNKNOWN, "ambiguous reviewer rules")
    rule = reviewers[0]
    members = rule.get("reviewers")
    if not isinstance(members, list) or type(rule.get("prevent_self_review")) is not bool:
        return CheckResult("release environment", STATUS_UNKNOWN, "reviewer details unavailable")
    if not members or rule["prevent_self_review"] is False:
        return CheckResult(
            "release environment",
            STATUS_FAIL,
            "release needs a nonempty reviewer list and prevention of self-review",
        )
    if any(
        not isinstance(member, dict)
        or not isinstance(member.get("type"), str)
        or member["type"] not in {"User", "Team"}
        or not isinstance(member.get("reviewer"), dict)
        or type(member["reviewer"].get("id")) is not int
        or member["reviewer"]["id"] < 1
        for member in members
    ):
        return CheckResult("release environment", STATUS_UNKNOWN, "invalid reviewer identity")
    policy = environment.get("deployment_branch_policy")
    if policy is None and "deployment_branch_policy" in environment:
        return CheckResult("release environment", STATUS_FAIL, "deployment refs are unrestricted")
    if not isinstance(policy, dict) or any(
        type(policy.get(key)) is not bool
        for key in ("protected_branches", "custom_branch_policies")
    ):
        return CheckResult(
            "release environment", STATUS_UNKNOWN, "deployment ref policy unavailable"
        )
    if policy["protected_branches"] or not policy["custom_branch_policies"]:
        return CheckResult(
            "release environment", STATUS_FAIL, "release requires selected v* tags only"
        )
    branches, error = _get_collection(
        api, "environments/release/deployment-branch-policies", "branch_policies"
    )
    if error:
        return CheckResult("release environment", STATUS_UNKNOWN, error)
    if not branches or any(
        not isinstance(branch, dict) or branch.get("type") != "tag" or branch.get("name") != "v*"
        for branch in branches
    ):
        return CheckResult(
            "release environment", STATUS_FAIL, "release must allow only the v* tag namespace"
        )
    return CheckResult(
        "release environment",
        STATUS_PASS,
        "independent reviewers, no administrator bypass, and selected v* release tags are required",
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
        "secret_scanning": "secret scanning",
        "secret_scanning_push_protection": "secret push protection",
    }
    disabled = [
        label
        for key, label in required.items()
        if isinstance(security.get(key), dict) and security[key].get("status") == "disabled"
    ]
    if disabled:
        return CheckResult(
            "repository security features",
            STATUS_FAIL,
            "disabled: " + ", ".join(disabled),
        )
    missing = [
        label
        for key, label in required.items()
        if not isinstance(security.get(key), dict) or security[key].get("status") != "enabled"
    ]
    if missing:
        return CheckResult(
            "repository security features",
            STATUS_UNVERIFIED,
            "state unavailable: " + ", ".join(missing),
        )
    return CheckResult(
        "repository security features", STATUS_PASS, "required security features are enabled"
    )


def _audit_dependency_graph(api: GitHubApi) -> CheckResult:
    payload, error = api.get("dependency-graph/sbom")
    if error:
        return CheckResult("Dependency graph", STATUS_UNVERIFIED, error)
    sbom = payload.get("sbom") if isinstance(payload, dict) else None
    if isinstance(sbom, dict) and isinstance(sbom.get("packages"), list):
        return CheckResult("Dependency graph", STATUS_PASS, "the dependency graph SBOM is readable")
    return CheckResult("Dependency graph", STATUS_UNVERIFIED, "invalid SBOM response")


def _audit_dependabot_updates(api: GitHubApi) -> CheckResult:
    payload, error = api.get("automated-security-fixes")
    if error:
        return CheckResult("Dependabot security updates", STATUS_UNVERIFIED, error)
    if isinstance(payload, dict) and payload.get("enabled") is True:
        if payload.get("paused") is False:
            return CheckResult("Dependabot security updates", STATUS_PASS, "enabled and not paused")
        if payload.get("paused") is True:
            return CheckResult("Dependabot security updates", STATUS_FAIL, "updates are paused")
    if isinstance(payload, dict) and payload.get("enabled") is False:
        return CheckResult("Dependabot security updates", STATUS_FAIL, "updates are disabled")
    return CheckResult("Dependabot security updates", STATUS_UNVERIFIED, "invalid update settings")


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
    enabled = permissions.get("enabled")
    if (
        type(enabled) is not bool
        or type(sha_pinning) is not bool
        or type(can_approve) is not bool
        or not isinstance(allowed, str)
        or allowed not in {"all", "local_only", "selected"}
        or not isinstance(default_permissions, str)
        or default_permissions not in {"read", "write"}
    ):
        return CheckResult("Actions policy", STATUS_UNKNOWN, "incomplete Actions policy response")
    if (
        not enabled
        or allowed != "selected"
        or not sha_pinning
        or can_approve
        or default_permissions != "read"
    ):
        return CheckResult(
            "Actions policy",
            STATUS_FAIL,
            "Actions policy exceeds the production baseline or Actions is disabled",
        )
    selection, error = api.get("actions/permissions/selected-actions")
    if error:
        return CheckResult("Actions policy", STATUS_UNKNOWN, error)
    if (
        not isinstance(selection, dict)
        or type(selection.get("github_owned_allowed")) is not bool
        or type(selection.get("verified_allowed")) is not bool
        or not isinstance(selection.get("patterns_allowed"), list)
        or any(not isinstance(pattern, str) for pattern in selection["patterns_allowed"])
    ):
        return CheckResult("Actions policy", STATUS_UNKNOWN, "invalid selected-actions response")
    for pattern in selection["patterns_allowed"]:
        repository = "/".join(pattern.split("@", 1)[0].split("/")[:2]).casefold()
        if repository not in _APPROVED_ACTION_REPOSITORIES:
            return CheckResult(
                "Actions policy",
                STATUS_FAIL,
                "action patterns allow unreviewed repositories or repository-wide wildcards",
            )
    if not any(
        (
            selection["github_owned_allowed"],
            selection["verified_allowed"],
            selection["patterns_allowed"],
        )
    ):
        return CheckResult("Actions policy", STATUS_FAIL, "the action selection allows no actions")
    return CheckResult(
        "Actions policy",
        STATUS_PASS,
        "selected actions allow GitHub-owned/verified creators or reviewed repositories; "
        "SHA pinning and read-only defaults are enforced",
    )


def _audit_private_reporting(api: GitHubApi) -> CheckResult:
    payload, error = api.get("private-vulnerability-reporting")
    if error:
        return CheckResult("private vulnerability reporting", STATUS_UNKNOWN, error)
    if not isinstance(payload, dict) or type(payload.get("enabled")) is not bool:
        return CheckResult(
            "private vulnerability reporting", STATUS_UNKNOWN, "invalid reporting state"
        )
    return CheckResult(
        "private vulnerability reporting",
        STATUS_PASS if payload["enabled"] else STATUS_FAIL,
        "enabled" if payload["enabled"] else "disabled; configure a confidential reporting channel",
    )


def _audit_alerts(api: GitHubApi) -> list[CheckResult]:
    checks: list[CheckResult] = []
    endpoints = (
        ("Dependabot alerts", "dependabot/alerts?state=open&per_page=100"),
        ("CodeQL alerts", "code-scanning/alerts?state=open&per_page=100"),
        ("secret-scanning alerts", "secret-scanning/alerts?state=open&per_page=100"),
    )
    for name, endpoint in endpoints:
        payload, error = _get_collection(api, endpoint)
        if error is not None:
            checks.append(CheckResult(name, STATUS_UNVERIFIED, error))
        elif not payload:
            checks.append(CheckResult(name, STATUS_PASS, "no open alerts"))
        elif all(isinstance(item, dict) for item in payload):
            # Alert payloads can contain actual secrets, excerpts, or sensitive
            # paths. Report only the count; review details in the authorized UI.
            checks.append(CheckResult(name, STATUS_BAD, f"{len(payload)} open alert(s)"))
        else:
            checks.append(CheckResult(name, STATUS_UNKNOWN, "invalid alert response"))
    return checks


class _ReleaseEvidenceError(ValueError):
    def __init__(self, detail: str, status: str = STATUS_UNKNOWN) -> None:
        super().__init__(detail)
        self.status = status


def _release_get(api: GitHubApi, path: str) -> Any:
    value, error = api.get(path)
    if error:
        raise _ReleaseEvidenceError(error)
    return value


def _latest_published_release(api: GitHubApi) -> dict[str, Any]:
    """Select by publication time, including prereleases, never releases/latest."""

    records, error = _get_collection(api, "releases")
    if error:
        raise _ReleaseEvidenceError(error)
    candidates: list[tuple[datetime, int, dict[str, Any]]] = []
    identifiers: set[int] = set()
    for release in records or []:
        if not isinstance(release, dict) or type(release.get("draft")) is not bool:
            raise _ReleaseEvidenceError("invalid release listing")
        if release["draft"]:
            continue
        identifier = release.get("id")
        published = release.get("published_at")
        if (
            type(identifier) is not int
            or identifier < 1
            or identifier in identifiers
            or type(release.get("prerelease")) is not bool
            or not isinstance(published, str)
        ):
            raise _ReleaseEvidenceError("invalid published release identity")
        try:
            timestamp = datetime.fromisoformat(published.replace("Z", "+00:00"))
        except ValueError as exc:
            raise _ReleaseEvidenceError("invalid release publication time") from exc
        if timestamp.tzinfo is None:
            raise _ReleaseEvidenceError("release publication time has no timezone")
        identifiers.add(identifier)
        candidates.append((timestamp, identifier, release))
    if not candidates:
        raise _ReleaseEvidenceError("no published release", STATUS_FAIL)
    release = max(candidates, key=lambda item: item[:2])[2]
    tag = release.get("tag_name")
    if not isinstance(tag, str) or len(tag) > 128 or _RELEASE_TAG.fullmatch(tag) is None:
        raise _ReleaseEvidenceError(
            "newest published release has an unsupported version tag", STATUS_FAIL
        )
    return release


def _object_sha(value: Any, kind: str, label: str) -> str:
    if (
        not isinstance(value, dict)
        or not isinstance(value.get("sha"), str)
        or _GIT_SHA.fullmatch(value["sha"]) is None
    ):
        raise _ReleaseEvidenceError(f"invalid {label} identity")
    if value.get("type") != kind:
        raise _ReleaseEvidenceError(f"{label} must target a {kind} object", STATUS_FAIL)
    return str(value["sha"])


def _release_commit(api: GitHubApi, release: dict[str, Any]) -> str:
    ref = _release_get(api, f"git/ref/tags/{release['tag_name']}")
    sha = _object_sha(ref.get("object") if isinstance(ref, dict) else None, "tag", "release tag")
    tag = _release_get(api, f"git/tags/{sha}")
    return _object_sha(
        tag.get("object") if isinstance(tag, dict) else None, "commit", "annotated release tag"
    )


def _release_text(api: GitHubApi, commit: str, path: str) -> str:
    """Read bounded metadata at an immutable commit without executing its code."""

    value = _release_get(api, f"contents/{path}?ref={commit}")
    if (
        not isinstance(value, dict)
        or value.get("type") != "file"
        or value.get("encoding") != "base64"
        or type(value.get("size")) is not int
        or not 0 < value["size"] <= 131072
        or not isinstance(value.get("content"), str)
        or len(value["content"]) > 262144
    ):
        raise _ReleaseEvidenceError(f"invalid or oversized release metadata: {path}")
    try:
        raw = base64.b64decode("".join(value["content"].split()), validate=True)
        text = raw.decode("utf-8")
    except ValueError as exc:
        raise _ReleaseEvidenceError(f"invalid release metadata encoding: {path}") from exc
    if len(raw) != value["size"]:
        raise _ReleaseEvidenceError(f"incomplete release metadata: {path}")
    return text


def _release_metadata(
    api: GitHubApi, release: dict[str, Any], commit: str
) -> tuple[str, tuple[str, ...]]:
    try:
        metadata = tomllib.loads(_release_text(api, commit, "pyproject.toml"))
    except tomllib.TOMLDecodeError as exc:
        raise _ReleaseEvidenceError("invalid release pyproject.toml") from exc
    project = metadata.get("project")
    if not isinstance(project, dict) or project.get("name") != "cpe-access-atlas":
        raise _ReleaseEvidenceError(
            "release metadata does not identify cpe-access-atlas", STATUS_FAIL
        )
    version = project.get("version")
    if version is None:
        dynamic: Any = metadata
        for key in ("tool", "setuptools", "dynamic", "version", "attr"):
            dynamic = dynamic.get(key) if isinstance(dynamic, dict) else None
        dynamic_fields = project.get("dynamic")
        if (
            dynamic != "cpe_access_atlas.__version__"
            or not isinstance(dynamic_fields, list)
            or "version" not in dynamic_fields
        ):
            raise _ReleaseEvidenceError("unsupported dynamic release version metadata")
        try:
            tree = ast.parse(_release_text(api, commit, "src/cpe_access_atlas/__init__.py"))
        except SyntaxError as exc:
            raise _ReleaseEvidenceError("invalid declared release version source") from exc
        assignments = [
            node
            for node in tree.body
            if isinstance(node, ast.Assign)
            and len(node.targets) == 1
            and isinstance(node.targets[0], ast.Name)
            and node.targets[0].id == "__version__"
        ]
        if len(assignments) != 1 or not isinstance(assignments[0].value, ast.Constant):
            raise _ReleaseEvidenceError("release version must be declared as one literal")
        version = assignments[0].value.value
    if not isinstance(version, str) or f"v{version}" != release["tag_name"]:
        raise _ReleaseEvidenceError(
            "release tag does not match its declared package version", STATUS_FAIL
        )
    classifiers = project.get("classifiers")
    if not isinstance(classifiers, list) or any(not isinstance(item, str) for item in classifiers):
        raise _ReleaseEvidenceError("release classifiers unavailable")
    statuses = [item for item in classifiers if item.startswith("Development Status ::")]
    valid = {
        "Development Status :: 2 - Pre-Alpha",
        "Development Status :: 3 - Alpha",
        "Development Status :: 4 - Beta",
        "Development Status :: 5 - Production/Stable",
        "Development Status :: 6 - Mature",
    }
    if len(statuses) != 1 or statuses[0] not in valid:
        raise _ReleaseEvidenceError("release requires one recognized development-status classifier")
    experimental = statuses[0] not in {
        "Development Status :: 5 - Production/Stable",
        "Development Status :: 6 - Mature",
    }
    version_is_preview = re.search(r"(?:a|b|rc)[0-9]+|\.dev[0-9]+", version) is not None
    if release["prerelease"] != (experimental or version_is_preview):
        raise _ReleaseEvidenceError(
            "release prerelease flag disagrees with metadata at its commit", STATUS_FAIL
        )
    versions = tuple(
        sorted(
            {
                item.removeprefix("Programming Language :: Python :: ")
                for item in classifiers
                if re.fullmatch(r"Programming Language :: Python :: [0-9]+\.[0-9]+", item)
            }
        )
    )
    if not versions or not set(versions).issubset(_RELEASE_PYTHONS):
        raise _ReleaseEvidenceError(
            "release Python support requires an explicit SBOM policy review"
        )
    return version, versions


def _audit_release(api: GitHubApi) -> CheckResult:
    try:
        release = _latest_published_release(api)
        commit = _release_commit(api, release)
        version, versions = _release_metadata(api, release, commit)
        assets, error = _get_collection(api, f"releases/{release['id']}/assets")
        if error:
            raise _ReleaseEvidenceError(error)
        expected = {
            f"cpe_access_atlas-{version}-py3-none-any.whl",
            f"cpe_access_atlas-{version}.tar.gz",
            "SHA256SUMS",
            *(
                f"cpe-access-atlas-{release['tag_name']}-{system}-python{python}-sbom.cdx.json"
                for system in _RELEASE_OSES
                for python in versions
            ),
        }
        found: set[str] = set()
        identifiers: set[int] = set()
        for asset in assets or []:
            if not isinstance(asset, dict) or not isinstance(asset.get("name"), str):
                raise _ReleaseEvidenceError("invalid release asset listing")
            name = asset["name"]
            if (
                name in found
                or type(asset.get("id")) is not int
                or asset["id"] < 1
                or asset["id"] in identifiers
            ):
                raise _ReleaseEvidenceError("duplicate or invalid release asset identity")
            found.add(name)
            identifiers.add(asset["id"])
            if name in expected and (
                asset.get("state") != "uploaded"
                or type(asset.get("size")) is not int
                or asset["size"] < 1
                or not isinstance(asset.get("digest"), str)
                or _ASSET_DIGEST.fullmatch(asset["digest"]) is None
            ):
                raise _ReleaseEvidenceError(
                    "required release assets must be uploaded, nonempty, and have SHA-256 digests",
                    STATUS_FAIL,
                )
        missing = sorted(expected - found)
        if missing:
            raise _ReleaseEvidenceError(
                "missing required release assets: " + ", ".join(missing), STATUS_FAIL
            )
        return CheckResult(
            "published release",
            STATUS_PASS,
            f"{release['tag_name']} classification and {len(expected)} required asset "
            "metadata records verified; "
            "download checksums and provenance still require independent verification",
        )
    except _ReleaseEvidenceError as exc:
        return CheckResult("published release", exc.status, str(exc))


def _audit_release_tag(api: GitHubApi) -> CheckResult:
    try:
        release = _latest_published_release(api)
        commit = _release_commit(api, release)
        main = _release_get(api, "commits/main")
        if (
            not isinstance(main, dict)
            or not isinstance(main.get("sha"), str)
            or _GIT_SHA.fullmatch(main["sha"]) is None
        ):
            raise _ReleaseEvidenceError("invalid main commit identity")
        comparison = _release_get(api, f"compare/{main['sha']}...{commit}")
        if not isinstance(comparison, dict) or comparison.get("status") not in (
            "behind",
            "identical",
            "ahead",
            "diverged",
        ):
            raise _ReleaseEvidenceError("invalid release commit comparison")
        if comparison["status"] not in ("behind", "identical"):
            raise _ReleaseEvidenceError("release commit is not reachable from main", STATUS_FAIL)
        base, ancestor = comparison.get("base_commit"), comparison.get("merge_base_commit")
        if (
            not isinstance(base, dict)
            or base.get("sha") != main["sha"]
            or not isinstance(ancestor, dict)
            or ancestor.get("sha") != commit
        ):
            raise _ReleaseEvidenceError(
                "release comparison does not prove the inspected immutable commits"
            )
        return CheckResult(
            "release tag integrity",
            STATUS_PASS,
            f"{release['tag_name']} is annotated and its inspected commit is reachable from main",
        )
    except _ReleaseEvidenceError as exc:
        return CheckResult("release tag integrity", exc.status, str(exc))


def _latest_workflow_runs(api: GitHubApi, head_sha: str) -> tuple[dict[str, Any], str | None]:
    if not isinstance(head_sha, str) or not _GIT_SHA.fullmatch(head_sha):
        return {}, "invalid main commit identity"
    records, error = _get_collection(
        api, f"actions/runs?head_sha={head_sha}&per_page=100", "workflow_runs"
    )
    if error:
        return {}, error
    latest: dict[str, Any] = {}
    ordering: dict[str, tuple[datetime, int, int]] = {}
    for run in records or []:
        if not isinstance(run, dict):
            return {}, "invalid workflow record"
        name = run.get("name")
        if not isinstance(name, str):
            return {}, "invalid workflow name"
        if name not in _EXPECTED_WORKFLOWS:
            continue
        event = run.get("event")
        if not isinstance(event, str):
            return {}, "invalid workflow event"
        if (
            run.get("head_sha") != head_sha
            or run.get("head_branch") != "main"
            or run.get("path") != _WORKFLOW_PATHS[name]
            or event not in {"push", "schedule", "workflow_dispatch"}
        ):
            continue
        if any(
            type(run.get(field)) is not int or run[field] < 1 for field in ("id", "run_attempt")
        ):
            return {}, "invalid workflow execution identity"
        try:
            created = datetime.fromisoformat(run["created_at"].replace("Z", "+00:00"))
            if created.tzinfo is None:
                return {}, "workflow creation time has no timezone"
        except (KeyError, AttributeError, TypeError, ValueError):
            return {}, "invalid workflow creation time"
        rank = (created, run["id"], run["run_attempt"])
        if name not in ordering or rank > ordering[name]:
            ordering[name] = rank
            latest[name] = run
    return latest, None


def _audit_workflows(api: GitHubApi, head_sha: str) -> CheckResult:
    latest, error = _latest_workflow_runs(api, head_sha)
    if error:
        return CheckResult("current required workflows", STATUS_UNVERIFIED, error)
    failed = sorted(
        name
        for name in _EXPECTED_WORKFLOWS
        if name not in latest
        or latest[name].get("status") != "completed"
        or latest[name].get("conclusion") != "success"
    )
    if not failed:
        return CheckResult(
            "current required workflows",
            STATUS_PASS,
            f"latest required main workflow executions passed for {head_sha[:7]}",
        )
    return CheckResult(
        "current required workflows",
        STATUS_FAIL,
        "latest workflows missing, incomplete, or unsuccessful: " + ", ".join(failed),
    )


def _audit_current_checks(api: GitHubApi, head_sha: str) -> CheckResult:
    # Read jobs from the exact latest workflow attempt, not arbitrary check
    # contexts from another app, an older run, or a different workflow file.
    latest, error = _latest_workflow_runs(api, head_sha)
    if error:
        return CheckResult("current required checks", STATUS_UNVERIFIED, error)
    failures: list[str] = []
    for name in sorted(_EXPECTED_WORKFLOWS):
        if name not in latest:
            failures.append(f"{name} (no main execution)")
            continue
        run = latest[name]
        run_id, attempt = run["id"], run["run_attempt"]
        jobs, error = _get_collection(
            api, f"actions/runs/{run_id}/attempts/{attempt}/jobs?per_page=100", "jobs"
        )
        if error:
            return CheckResult("current required checks", STATUS_UNVERIFIED, error)
        for required in _WORKFLOW_CHECKS[name]:
            matching = [
                job for job in jobs or [] if isinstance(job, dict) and job.get("name") == required
            ]
            if len(matching) != 1:
                failures.append(f"{required} (missing or ambiguous)")
                continue
            job = matching[0]
            conclusion = job.get("conclusion")
            if any(type(job.get(field)) is not int for field in ("run_id", "run_attempt")) or (
                conclusion is not None and not isinstance(conclusion, str)
            ):
                return CheckResult(
                    "current required checks", STATUS_UNKNOWN, "invalid workflow job metadata"
                )
            allowed = {"success"}
            if required == "dependency-review" and run["event"] == "push":
                allowed.add("skipped")
            if (
                job.get("head_sha") != head_sha
                or job.get("run_id") != run_id
                or job.get("run_attempt") != attempt
                or job.get("status") != "completed"
                or conclusion not in allowed
            ):
                failures.append(f"{required} (not a successful current-attempt job)")
    if not failures:
        return CheckResult(
            "current required checks",
            STATUS_PASS,
            f"required jobs passed in the latest workflow attempts for {head_sha[:7]}",
        )
    return CheckResult("current required checks", STATUS_FAIL, "; ".join(failures))


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
        _audit_dependency_graph(api),
        _audit_dependabot_updates(api),
        _audit_private_reporting(api),
    ]
    rulesets, ruleset_errors = _load_rulesets(api)
    if ruleset_errors:
        results.append(
            CheckResult("repository rulesets", STATUS_UNVERIFIED, "; ".join(ruleset_errors))
        )
    else:
        results.append(
            CheckResult("repository rulesets", STATUS_PASS, "all ruleset details were read")
        )
    results.append(_audit_branch_policy(api, rulesets, errors))
    results.append(
        CheckResult("release tag enforcement", STATUS_UNVERIFIED, "; ".join(ruleset_errors))
        if ruleset_errors
        else _audit_tag_policy(
            rulesets,
            frozenset({("User", repo_data["owner"]["id"])})
            if isinstance(repo_data.get("owner"), dict)
            and repo_data["owner"].get("type") == "User"
            and type(repo_data["owner"].get("id")) is int
            and repo_data["owner"]["id"] > 0
            else frozenset(),
        )
    )
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
        or not _GIT_SHA.fullmatch(head_sha["sha"])
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
        or not _REPOSITORY.fullmatch(args.repo)
        or args.repo.split("/", 1)[1] in {".", ".."}
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

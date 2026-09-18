# SPDX-License-Identifier: 0BSD
"""Run a read-only GitHub production-settings audit.

This script deliberately uses ``gh api`` for administrator-visible settings
instead of making any write requests.  A missing permission is reported as
``UNVERIFIED`` rather than being mistaken for a disabled control.

Usage:
    python scripts/check_github_production_settings.py --repo OWNER/REPO
    python scripts/check_github_production_settings.py --repo OWNER/REPO --prepublication
    python scripts/check_github_production_settings.py --repo OWNER/REPO --json
    Add --require-independent-review to opt into a multi-maintainer policy.

The default is the owner's solo-maintainer policy: automated gates remain
required, but another person's approval is not mandatory. The optional strict
profile checks independent PR and release approval instead.
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
from datetime import UTC, date, datetime, timedelta
from pathlib import Path
from typing import Any, cast

STATUS_OK = "PASS"
STATUS_BAD = "FAIL"
STATUS_UNKNOWN = "UNVERIFIED"
STATUS_DEFERRED = "DEFERRED"
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
_RELEASE_NUMBER = r"(?:0|[1-9][0-9]*)"
_RELEASE_VERSION = (
    rf"{_RELEASE_NUMBER}\.{_RELEASE_NUMBER}\.{_RELEASE_NUMBER}"
    rf"(?:(?:a|b|rc){_RELEASE_NUMBER})?"
    rf"(?:\.post{_RELEASE_NUMBER})?"
    rf"(?:\.dev{_RELEASE_NUMBER})?"
)
_RELEASE_TAG = re.compile(rf"v({_RELEASE_VERSION})")
_CANDIDATE_RELEASE_TAG = "v0.4.0a5"
_GIT_SHA = re.compile(r"[0-9a-f]{40}")
_REPOSITORY = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?/[A-Za-z0-9_.-]{1,100}")
_ASSET_DIGEST = re.compile(r"sha256:[0-9a-f]{64}")
_GIT_REF = re.compile(r"refs/(?:heads|tags)/[A-Za-z0-9][A-Za-z0-9._/-]{0,239}")
_GITHUB_ACTIONS_APP_ID = 15368
_CODEQL_RISK_POLICY_PATH = (
    Path(__file__).resolve().parents[1] / ".github" / "codeql-accepted-risks.json"
)
_CODEQL_RISK_POLICY_KEYS = frozenset({"schema_version", "repository", "accepted_risks"})
_CODEQL_RISK_KEYS = frozenset(
    {
        "alert_number",
        "rule_id",
        "security_severity_level",
        "path",
        "dismissed_reason",
        "dismissed_by",
        "dismissal_approved_by",
        "dismissed_at",
        "dismissed_comment",
        "review_by",
        "documentation",
        "compensating_controls",
        "re_review_triggers",
    }
)
_CODEQL_SECURITY_LEVELS = frozenset({"critical", "high", "medium", "low", "note", "warning"})
_CODEQL_ACCEPTED_LEVELS = frozenset({"critical", "high"})
_CODEQL_POLICY_MAX_BYTES = 65_536
_RELEASE_OSES = ("ubuntu-latest", "windows-latest", "macos-latest")
_RELEASE_PYTHONS = ("3.11", "3.12", "3.13", "3.14", "3.15")
_SECURITY_AUDIT_PYTHONS = ("3.11", "3.14")
_WEEKLY_WORKFLOW_MAX_AGE = timedelta(days=8)
_WORKFLOW_CLOCK_SKEW = timedelta(minutes=5)
_WEEKLY_WORKFLOWS = frozenset({"Security audit", "CodeQL"})
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
    for operating_system in _RELEASE_OSES
    for python_version in _RELEASE_PYTHONS
)
_SECURITY_AUDIT_CHECK_NAMES = tuple(
    f"dependency-audit ({python_version})" for python_version in _SECURITY_AUDIT_PYTHONS
)
_REQUIRED_BRANCH_CHECKS = frozenset(
    (
        *_CI_CHECK_NAMES,
        "package-smoke",
        "check-signoff",
        *_SECURITY_AUDIT_CHECK_NAMES,
        "dependency-review",
        "analyze",
        "gitleaks",
    )
)
_REQUIRED_CURRENT_CHECKS = frozenset(
    (*_CI_CHECK_NAMES, "package-smoke", *_SECURITY_AUDIT_CHECK_NAMES, "analyze", "gitleaks")
)
_WORKFLOW_CHECKS = {
    "CI": (*_CI_CHECK_NAMES, "package-smoke"),
    "Security audit": (*_SECURITY_AUDIT_CHECK_NAMES, "dependency-review"),
    "CodeQL": ("analyze",),
    "Secret scan": ("gitleaks",),
}


@dataclass(frozen=True)
class CheckResult:
    name: str
    status: str
    detail: str


@dataclass(frozen=True)
class CodeQLRiskAcceptance:
    alert_number: int
    rule_id: str
    security_severity_level: str
    path: str
    dismissed_reason: str
    dismissed_by: str
    dismissal_approved_by: str | None
    dismissed_at: str
    dismissed_comment: str
    review_by: date
    documentation: str
    compensating_controls: tuple[str, ...]
    re_review_triggers: tuple[str, ...]


@dataclass(frozen=True)
class CodeQLRiskPolicy:
    repository: str
    accepted_risks: tuple[CodeQLRiskAcceptance, ...]


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
    if status == "404" and "Branch not protected" in message:
        return "Branch not protected" + suffix, False
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


def _valid_github_ref(value: str) -> bool:
    if _GIT_REF.fullmatch(value) is None or value.endswith(("/", ".")):
        return False
    if "//" in value or "@{" in value or ".." in value:
        return False
    return all(part not in {"", ".", ".."} for part in value.split("/"))


def _policy_string_list(value: object) -> tuple[str, ...] | None:
    if not isinstance(value, list) or not value:
        return None
    if any(not isinstance(item, str) or not item or len(item) > 300 for item in value):
        return None
    items = tuple(value)
    return items if len(set(items)) == len(items) else None


def _parse_codeql_risk_policy(document: object) -> tuple[CodeQLRiskPolicy | None, str | None]:
    """Parse the exact, repository-bound accepted-risk policy as inert data."""

    if not isinstance(document, dict) or frozenset(document) != _CODEQL_RISK_POLICY_KEYS:
        return None, "accepted CodeQL risk policy has an invalid top-level schema"
    if type(document["schema_version"]) is not int or document["schema_version"] != 1:
        return None, "accepted CodeQL risk policy uses an unsupported schema version"
    repository = document["repository"]
    if (
        not isinstance(repository, str)
        or _REPOSITORY.fullmatch(repository) is None
        or repository.split("/", 1)[1] in {".", ".."}
    ):
        return None, "accepted CodeQL risk policy has an invalid repository"
    records = document["accepted_risks"]
    if not isinstance(records, list) or len(records) > 32:
        return None, "accepted CodeQL risk policy must contain 0-32 entries"

    accepted: list[CodeQLRiskAcceptance] = []
    seen: set[int] = set()
    for record in records:
        if not isinstance(record, dict) or frozenset(record) != _CODEQL_RISK_KEYS:
            return None, "accepted CodeQL risk policy entry has an invalid schema"
        number = record["alert_number"]
        if type(number) is not int or number < 1 or number in seen:
            return None, "accepted CodeQL risk policy has an invalid or duplicate alert number"
        seen.add(number)
        rule_id = record["rule_id"]
        severity = record["security_severity_level"]
        path = record["path"]
        reason = record["dismissed_reason"]
        dismissed_by = record["dismissed_by"]
        approved_by = record["dismissal_approved_by"]
        dismissed_at = record["dismissed_at"]
        comment = record["dismissed_comment"]
        review_by = record["review_by"]
        documentation = record["documentation"]
        controls = _policy_string_list(record["compensating_controls"])
        triggers = _policy_string_list(record["re_review_triggers"])
        scalar_strings = (rule_id, path, reason, dismissed_by, dismissed_at, comment, documentation)
        if any(
            not isinstance(value, str) or not value or len(value) > 1_000
            for value in scalar_strings
        ):
            return None, "accepted CodeQL risk policy entry has invalid text metadata"
        rule_id = cast(str, rule_id)
        path = cast(str, path)
        reason = cast(str, reason)
        dismissed_by = cast(str, dismissed_by)
        dismissed_at = cast(str, dismissed_at)
        comment = cast(str, comment)
        documentation = cast(str, documentation)
        if (
            not re.fullmatch(r"[a-z0-9-]+/[a-z0-9-]+", rule_id)
            or not isinstance(severity, str)
            or severity not in _CODEQL_ACCEPTED_LEVELS
            or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._/-]{0,255}", path)
            or ".." in path
            or "//" in path
            or reason != "won't fix"
            or not re.fullmatch(r"[A-Za-z0-9-]{1,39}", dismissed_by)
            or (
                approved_by is not None
                and (
                    not isinstance(approved_by, str)
                    or re.fullmatch(r"[A-Za-z0-9-]{1,39}", approved_by) is None
                )
            )
            or re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z", dismissed_at) is None
            or not documentation.startswith("docs/")
            or not re.fullmatch(r"docs/[A-Za-z0-9._/#-]{1,255}", documentation)
            or controls is None
            or triggers is None
        ):
            return None, "accepted CodeQL risk policy entry has invalid constrained metadata"
        try:
            dismissed_timestamp = datetime.strptime(dismissed_at, "%Y-%m-%dT%H:%M:%SZ").replace(
                tzinfo=UTC
            )
            review_date = date.fromisoformat(review_by) if isinstance(review_by, str) else None
        except ValueError:
            return None, "accepted CodeQL risk policy entry has invalid dates"
        if review_date is None or review_date.isoformat() != review_by:
            return None, "accepted CodeQL risk policy entry has invalid dates"
        if review_date < dismissed_timestamp.date():
            return None, "accepted CodeQL risk review date predates its dismissal"
        accepted.append(
            CodeQLRiskAcceptance(
                alert_number=number,
                rule_id=rule_id,
                security_severity_level=severity,
                path=path,
                dismissed_reason=reason,
                dismissed_by=dismissed_by,
                dismissal_approved_by=approved_by,
                dismissed_at=dismissed_at,
                dismissed_comment=comment,
                review_by=review_date,
                documentation=documentation,
                compensating_controls=controls,
                re_review_triggers=triggers,
            )
        )
    return CodeQLRiskPolicy(repository=repository, accepted_risks=tuple(accepted)), None


def _load_codeql_risk_policy(
    path: Path = _CODEQL_RISK_POLICY_PATH,
) -> tuple[CodeQLRiskPolicy | None, str | None]:
    try:
        raw = path.read_bytes()
    except OSError:
        return None, "accepted CodeQL risk policy is unreadable"
    if not raw or len(raw) > _CODEQL_POLICY_MAX_BYTES:
        return None, "accepted CodeQL risk policy is empty or exceeds its size limit"
    try:
        document = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, ValueError, RecursionError):
        return None, "accepted CodeQL risk policy is not bounded valid UTF-8 JSON"
    return _parse_codeql_risk_policy(document)


def _account_login(value: object) -> tuple[str | None, bool]:
    if value is None:
        return None, True
    if not isinstance(value, dict) or not isinstance(value.get("login"), str):
        return None, False
    login = cast(str, value["login"])
    return (login, bool(login) and len(login) <= 39)


def _evaluate_codeql_risk_acceptances(
    policy: CodeQLRiskPolicy,
    alerts: object,
    *,
    repository: str,
    expected_ref: str,
    expected_commit: str,
    now: datetime,
) -> tuple[str, ...]:
    """Return fail-closed differences between GitHub evidence and accepted risks."""

    errors: list[str] = []
    if policy.repository != repository:
        errors.append("policy repository does not match the audited repository")
    if not _valid_github_ref(expected_ref):
        errors.append("expected CodeQL ref is invalid")
    if _GIT_SHA.fullmatch(expected_commit) is None:
        errors.append("expected CodeQL commit is invalid")
    for acceptance in policy.accepted_risks:
        if now.date() > acceptance.review_by:
            errors.append(
                f"accepted CodeQL risk #{acceptance.alert_number} expired on "
                f"{acceptance.review_by.isoformat()}"
            )
    if not isinstance(alerts, list):
        return (*errors, "dismissed CodeQL alert inventory is malformed")

    expected = {item.alert_number: item for item in policy.accepted_risks}
    observed: set[int] = set()
    for alert in alerts:
        if not isinstance(alert, dict) or alert.get("state") != "dismissed":
            errors.append("dismissed CodeQL alert inventory is malformed")
            continue
        rule = alert.get("rule")
        if not isinstance(rule, dict):
            errors.append("dismissed CodeQL alert inventory has malformed rule metadata")
            continue
        severity = rule.get("security_severity_level")
        if severity is not None and not isinstance(severity, str):
            errors.append("dismissed CodeQL alert inventory has malformed severity metadata")
            continue
        if isinstance(severity, str) and severity not in _CODEQL_SECURITY_LEVELS:
            errors.append("dismissed CodeQL alert inventory has malformed severity metadata")
            continue
        if severity not in _CODEQL_ACCEPTED_LEVELS:
            continue
        number = alert.get("number")
        if type(number) is not int or number < 1 or number in observed:
            errors.append("dismissed high/critical CodeQL alert identity is invalid or duplicated")
            continue
        observed.add(number)
        expected_acceptance = expected.get(number)
        if expected_acceptance is None:
            errors.append(f"unexpected dismissed high/critical CodeQL alert #{number}")
            continue
        dismissed_by, dismissed_by_valid = _account_login(alert.get("dismissed_by"))
        approved_by, approved_by_valid = _account_login(alert.get("dismissal_approved_by"))
        instance = alert.get("most_recent_instance")
        location = instance.get("location") if isinstance(instance, dict) else None
        path = location.get("path") if isinstance(location, dict) else None
        metadata = {
            "rule_id": rule.get("id"),
            "security_severity_level": severity,
            "path": path,
            "dismissed_reason": alert.get("dismissed_reason"),
            "dismissed_by": dismissed_by,
            "dismissal_approved_by": approved_by,
            "dismissed_at": alert.get("dismissed_at"),
            "dismissed_comment": alert.get("dismissed_comment"),
        }
        expected_metadata = {
            "rule_id": expected_acceptance.rule_id,
            "security_severity_level": expected_acceptance.security_severity_level,
            "path": expected_acceptance.path,
            "dismissed_reason": expected_acceptance.dismissed_reason,
            "dismissed_by": expected_acceptance.dismissed_by,
            "dismissal_approved_by": expected_acceptance.dismissal_approved_by,
            "dismissed_at": expected_acceptance.dismissed_at,
            "dismissed_comment": expected_acceptance.dismissed_comment,
        }
        if not dismissed_by_valid or not approved_by_valid or metadata != expected_metadata:
            errors.append(f"accepted CodeQL risk #{number} metadata differs from policy")
        if not isinstance(instance, dict) or instance.get("state") != "dismissed":
            errors.append(f"accepted CodeQL risk #{number} exact instance is not dismissed")
        if (
            not isinstance(instance, dict)
            or instance.get("ref") != expected_ref
            or instance.get("commit_sha") != expected_commit
        ):
            errors.append(f"accepted CodeQL risk #{number} is not present on the exact ref/commit")
    for number in sorted(expected.keys() - observed):
        errors.append(f"accepted CodeQL risk #{number} is missing on the exact ref")
    return tuple(dict.fromkeys(errors))


def _audit_codeql_risk_acceptances(
    api: GitHubApi,
    repository: str,
    *,
    expected_ref: str,
    expected_commit: str,
    now: datetime,
    policy_path: Path = _CODEQL_RISK_POLICY_PATH,
) -> CheckResult:
    if not _valid_github_ref(expected_ref) or _GIT_SHA.fullmatch(expected_commit) is None:
        return CheckResult(
            "accepted CodeQL risks", STATUS_FAIL, "exact CodeQL ref/commit input is invalid"
        )
    policy, policy_error = _load_codeql_risk_policy(policy_path)
    if policy_error is not None or policy is None:
        return CheckResult(
            "accepted CodeQL risks", STATUS_FAIL, policy_error or "accepted-risk policy is invalid"
        )
    endpoint = f"code-scanning/alerts?state=dismissed&ref={expected_ref}&per_page=100"
    alerts, api_error = _get_collection(api, endpoint)
    if api_error is not None:
        return CheckResult("accepted CodeQL risks", STATUS_UNVERIFIED, api_error)
    differences = _evaluate_codeql_risk_acceptances(
        policy,
        alerts,
        repository=repository,
        expected_ref=expected_ref,
        expected_commit=expected_commit,
        now=now,
    )
    if differences:
        return CheckResult("accepted CodeQL risks", STATUS_FAIL, "; ".join(differences))
    if not policy.accepted_risks:
        return CheckResult(
            "accepted CodeQL risks",
            STATUS_PASS,
            f"no dismissed high/critical alerts match {expected_ref}; policy has no acceptances",
        )
    review_date = min(item.review_by for item in policy.accepted_risks)
    return CheckResult(
        "accepted CodeQL risks",
        STATUS_PASS,
        f"{len(policy.accepted_risks)} exact dismissed high/critical risk acceptance(s) "
        f"match {expected_ref}; next review due {review_date.isoformat()}",
    )


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


def _github_actions_check_names(statuses: Any, binding_field: str) -> set[str]:
    """Return checks explicitly bound to the GitHub Actions integration."""

    if not isinstance(statuses, dict) or binding_field not in {"app_id", "integration_id"}:
        return set()
    checks = statuses.get("checks")
    if not isinstance(checks, list):
        return set()
    names: set[str] = set()
    for item in checks:
        if (
            not isinstance(item, dict)
            or type(item.get(binding_field)) is not int
            or item[binding_field] != _GITHUB_ACTIONS_APP_ID
        ):
            continue
        context = item.get("context")
        if isinstance(context, str) and context:
            names.add(context)
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


def _review_policy_matches(reviews: dict[str, Any], require_independent_review: bool) -> bool:
    count = reviews.get("required_approving_review_count")
    code_owner = reviews.get("require_code_owner_review", reviews.get("require_code_owner_reviews"))
    if require_independent_review:
        return type(count) is int and count >= 1 and code_owner is True
    return (
        type(count) is int
        and count == 0
        and code_owner is False
        and reviews.get("require_last_push_approval") is False
        # This optional ruleset field is absent from classic protection and
        # older API responses. An explicit team gate must not be ignored.
        and reviews.get("required_reviewers", []) == []
    )


def _ruleset_has_required_branch_controls(
    ruleset: dict[str, Any], *, require_independent_review: bool = True
) -> bool:
    pull_request = _ruleset_parameters(ruleset, "pull_request")
    status_checks = _ruleset_parameters(ruleset, "required_status_checks")
    required_checks = status_checks.get("required_status_checks")
    required_check_names = _github_actions_check_names(
        {"checks": required_checks}, "integration_id"
    )
    stale = pull_request.get(
        "dismiss_stale_reviews_on_push", pull_request.get("dismiss_stale_reviews")
    )
    conversation = pull_request.get("required_review_thread_resolution")
    strict_checks = status_checks.get("strict_required_status_checks_policy")
    return (
        _review_policy_matches(pull_request, require_independent_review)
        and stale is True
        and conversation is True
        and strict_checks is True
        and _REQUIRED_BRANCH_CHECKS.issubset(required_check_names)
        and _ruleset_has_type(ruleset, "deletion")
        and _ruleset_has_type(ruleset, "non_fast_forward")
        and ruleset.get("bypass_actors") == []
    )


def _audit_branch_policy(
    api: GitHubApi,
    rulesets: Any,
    errors: list[str],
    *,
    require_independent_review: bool = True,
) -> CheckResult:
    ruleset_detail = "complete effective-rules evidence was unavailable"
    ruleset_verified = False
    effective, effective_error = _get_collection(api, "rules/branches/main")
    if effective_error:
        errors.append(f"effective main rules: {effective_error}")
    if not require_independent_review and (
        effective_error
        or any(
            not isinstance(rule, dict)
            or not isinstance(rule.get("type"), str)
            or re.fullmatch(r"[a-z][a-z0-9_]*", rule["type"]) is None
            or (
                rule.get("type") == "pull_request"
                and (
                    not isinstance(rule.get("parameters"), dict)
                    or not _review_policy_matches(rule["parameters"], False)
                )
            )
            for rule in effective or []
        )
    ):
        # Every effective ruleset still applies alongside classic protection.
        # A zero-approval first rule or classic fallback cannot cancel another
        # rule's mandatory approver, and missing evidence cannot prove absence.
        return CheckResult(
            "main branch enforcement",
            STATUS_UNKNOWN,
            "effective main rules do not establish a policy without mandatory human approval",
        )
    if effective:
        ruleset_detail = "effective main rules exist, but their full details could not be verified"
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
            if _ruleset_has_required_branch_controls(
                combined, require_independent_review=require_independent_review
            ):
                if require_independent_review:
                    return CheckResult(
                        "main branch enforcement",
                        STATUS_PASS,
                        "effective main rules enforce required controls without bypass actors",
                    )
                ruleset_verified = True
            ruleset_detail = (
                "effective main rules exist, but do not independently prove every required "
                "review/check control without bypass actors"
            )
        else:
            errors.append("effective main rule details or bypass actors could not be verified")
    protection, error = api.get("branches/main/protection")
    if ruleset_verified:
        # In solo mode, absence of mandatory approval must also hold for
        # classic protection. Rulesets and classic protection are cumulative.
        reviews = (
            protection.get("required_pull_request_reviews")
            if isinstance(protection, dict)
            else None
        )
        no_classic_approval = (
            error is None
            and isinstance(protection, dict)
            and "required_pull_request_reviews" in protection
            and (
                reviews is None
                or (isinstance(reviews, dict) and _review_policy_matches(reviews, False))
            )
        )
        if (error and "Branch not protected" in error) or no_classic_approval:
            return CheckResult(
                "main branch enforcement",
                STATUS_PASS,
                "effective rules enforce PR/check controls without bypass actors "
                "or mandatory approvers",
            )
        return CheckResult(
            "main branch enforcement",
            STATUS_UNKNOWN,
            "rulesets meet the solo policy, but classic protection may still require approval",
        )
    if error is None and isinstance(protection, dict):
        reviews = protection.get("required_pull_request_reviews") or {}
        statuses = protection.get("required_status_checks") or {}
        if not isinstance(reviews, dict) or not isinstance(statuses, dict):
            return CheckResult(
                "main branch enforcement",
                STATUS_FAIL,
                "branch protection returned malformed review/check settings",
            )
        required_check_names = _github_actions_check_names(statuses, "app_id")
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
        missing_checks = sorted(_REQUIRED_BRANCH_CHECKS - required_check_names)
        if (
            _review_policy_matches(reviews, require_independent_review)
            and statuses.get("strict") is True
            and not missing_checks
            and enforce_admins
            and no_force_push
            and no_delete
            and conversation
            and dismiss_stale
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
            f"complete main-branch enforcement could not be verified: {ruleset_detail}; "
            "classic branch protection was unavailable or malformed"
        ),
    )


def _audit_tag_policy(
    rulesets: Any, allowed_creators: frozenset[tuple[str, int]] = frozenset()
) -> CheckResult:
    """Prove a rotating candidate-only creation boundary and immutable v* tags.

    All noncandidate release tags must match a zero-bypass creation rule. The
    exact candidate must instead match a separate trusted-creator rule. A broad
    no-bypass rule independently prevents updates and deletions. The caller
    identifies trusted creation actors explicitly; role-wide grants are never
    inferred to mean a reviewed release maintainer.
    """

    if not isinstance(rulesets, list):
        return CheckResult("release tag enforcement", STATUS_UNKNOWN, "invalid ruleset list")
    candidate_ref = f"refs/tags/{_CANDIDATE_RELEASE_TAG}"
    quarantine = False
    immutable: set[str] = set()
    creator_sets: list[set[tuple[str, int]]] = []
    unavailable = False
    invalid_policy = False
    for ruleset in rulesets:
        if not isinstance(ruleset, dict):
            unavailable = True
            continue
        if ruleset.get("target") != "tag" or ruleset.get("enforcement") != "active":
            continue
        rules = ruleset.get("rules")
        if not isinstance(rules, list) or any(
            not isinstance(rule, dict) or not isinstance(rule.get("type"), str) for rule in rules
        ):
            unavailable = True
            continue
        rule_types = {rule["type"] for rule in rules}
        if not rule_types.intersection({"creation", "update", "deletion"}):
            continue
        conditions = ruleset.get("conditions")
        refs = conditions.get("ref_name") if isinstance(conditions, dict) else None
        if (
            not isinstance(refs, dict)
            or not isinstance(refs.get("include"), list)
            or not isinstance(refs.get("exclude"), list)
            or any(not isinstance(pattern, str) for pattern in refs["include"])
            or any(not isinstance(pattern, str) for pattern in refs["exclude"])
        ):
            unavailable = True
            continue
        bypass = ruleset.get("bypass_actors")
        if not isinstance(bypass, list):
            unavailable = True
            continue

        if rule_types == {"creation"}:
            if (
                refs["include"] == ["refs/tags/v*"]
                and refs["exclude"] == [candidate_ref]
                and not bypass
            ):
                quarantine = True
                continue
            if refs["include"] == [candidate_ref] and not refs["exclude"]:
                trusted_bypass = bool(bypass) and all(
                    isinstance(actor, dict)
                    and isinstance(actor.get("actor_type"), str)
                    and type(actor.get("actor_id")) is int
                    and (actor["actor_type"], actor["actor_id"]) in allowed_creators
                    and actor.get("bypass_mode") == "always"
                    for actor in bypass
                )
                if not trusted_bypass:
                    return CheckResult(
                        "release tag enforcement",
                        STATUS_FAIL,
                        "candidate release creators are not explicitly trusted",
                    )
                creator_sets.append({(actor["actor_type"], actor["actor_id"]) for actor in bypass})
                continue
            invalid_policy = True
            continue

        if "creation" in rule_types:
            invalid_policy = True
            continue
        if refs["include"] == ["refs/tags/v*"] and not refs["exclude"] and not bypass:
            immutable.update(rule_types.intersection({"update", "deletion"}))
        elif rule_types.intersection({"update", "deletion"}) and (
            refs["include"] == [candidate_ref] or "refs/tags/v*" in refs["include"]
        ):
            if bypass:
                return CheckResult(
                    "release tag enforcement",
                    STATUS_FAIL,
                    "release tag updates or deletions have a bypass",
                )
            invalid_policy = True
    creators = set.intersection(*creator_sets) if creator_sets else set()
    if (
        quarantine
        and creators
        and immutable == {"update", "deletion"}
        and not unavailable
        and not invalid_policy
    ):
        return CheckResult(
            "release tag enforcement",
            STATUS_PASS,
            f"only trusted creators can create {_CANDIDATE_RELEASE_TAG}; all other v* "
            "creations and every update/deletion are denied",
        )
    return CheckResult(
        "release tag enforcement",
        STATUS_UNKNOWN if unavailable else STATUS_FAIL,
        "v* tags need candidate-only trusted creation, a noncandidate creation quarantine, "
        "and broad no-bypass update/deletion controls",
    )


def _audit_release_environment(
    api: GitHubApi, *, require_independent_review: bool = True
) -> CheckResult:
    environment, error = api.get("environments/release")
    if error is not None:
        return CheckResult("release environment", STATUS_UNVERIFIED, error)
    if not isinstance(environment, dict):
        return CheckResult("release environment", STATUS_UNVERIFIED, "invalid environment response")
    rules = environment.get("protection_rules")
    bypass = environment.get("can_admins_bypass")
    if (
        not isinstance(rules, list)
        or type(bypass) is not bool
        or any(
            not isinstance(rule, dict) or not isinstance(rule.get("type"), str) for rule in rules
        )
    ):
        return CheckResult("release environment", STATUS_UNKNOWN, "incomplete protection settings")
    reviewers = [
        rule
        for rule in rules
        if isinstance(rule, dict) and rule.get("type") == "required_reviewers"
    ]
    if bypass or (require_independent_review and not reviewers):
        return CheckResult(
            "release environment",
            STATUS_FAIL,
            "release must disallow administrator bypass and meet the selected approval policy",
        )
    if not require_independent_review and reviewers:
        return CheckResult(
            "release environment",
            STATUS_FAIL,
            "solo-maintainer releases must not require another person's approval",
        )
    if require_independent_review:
        if len(reviewers) != 1:
            return CheckResult("release environment", STATUS_UNKNOWN, "ambiguous reviewer rules")
        rule = reviewers[0]
        members = rule.get("reviewers")
        if not isinstance(members, list) or type(rule.get("prevent_self_review")) is not bool:
            return CheckResult(
                "release environment", STATUS_UNKNOWN, "reviewer details unavailable"
            )
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
            "release environment", STATUS_FAIL, "release requires one exact candidate tag"
        )
    branches, error = _get_collection(
        api, "environments/release/deployment-branch-policies", "branch_policies"
    )
    if error:
        return CheckResult("release environment", STATUS_UNKNOWN, error)
    branches = cast(list[Any], branches)
    if (
        len(branches) != 1
        or not isinstance(branches[0], dict)
        or branches[0].get("type") != "tag"
        or branches[0].get("name") != _CANDIDATE_RELEASE_TAG
    ):
        return CheckResult(
            "release environment",
            STATUS_FAIL,
            f"release must allow only exact candidate tag {_CANDIDATE_RELEASE_TAG}",
        )
    return CheckResult(
        "release environment",
        STATUS_PASS,
        "selected approval policy, no administrator bypass, and exact candidate tag "
        f"{_CANDIDATE_RELEASE_TAG} is enforced",
    )


def _audit_release_immutability_setting(api: GitHubApi) -> CheckResult:
    setting, error = api.get("immutable-releases")
    if error is not None:
        return CheckResult("release immutability setting", STATUS_UNKNOWN, error)
    if not isinstance(setting, dict) or type(setting.get("enabled")) is not bool:
        return CheckResult(
            "release immutability setting", STATUS_UNKNOWN, "setting evidence is malformed"
        )
    if not setting["enabled"]:
        return CheckResult(
            "release immutability setting",
            STATUS_FAIL,
            "repository release immutability is disabled",
        )
    return CheckResult(
        "release immutability setting",
        STATUS_PASS,
        "repository release immutability is enabled for future publications",
    )


def _audit_candidate_absence(api: GitHubApi) -> CheckResult:
    candidate_ref = f"refs/tags/{_CANDIDATE_RELEASE_TAG}"
    refs, error = _get_collection(api, f"git/matching-refs/tags/{_CANDIDATE_RELEASE_TAG}")
    if error:
        return CheckResult("candidate absence", STATUS_UNKNOWN, error)
    releases, error = _get_collection(api, "releases")
    if error:
        return CheckResult("candidate absence", STATUS_UNKNOWN, error)
    refs = cast(list[Any], refs)
    releases = cast(list[Any], releases)
    if any(not isinstance(item, dict) or not isinstance(item.get("ref"), str) for item in refs):
        return CheckResult(
            "candidate absence", STATUS_UNKNOWN, "candidate ref evidence is malformed"
        )
    if any(
        not isinstance(item, dict) or not isinstance(item.get("tag_name"), str) for item in releases
    ):
        return CheckResult(
            "candidate absence", STATUS_UNKNOWN, "candidate release evidence is malformed"
        )
    if any(item["ref"] == candidate_ref for item in refs) or any(
        item["tag_name"] == _CANDIDATE_RELEASE_TAG for item in releases
    ):
        return CheckResult(
            "candidate absence",
            STATUS_FAIL,
            f"{_CANDIDATE_RELEASE_TAG} already exists as a tag or release",
        )
    return CheckResult(
        "candidate absence",
        STATUS_PASS,
        f"{_CANDIDATE_RELEASE_TAG} does not yet exist as a tag or release",
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
        if type(release.get("immutable")) is not bool:
            raise _ReleaseEvidenceError(
                "published release immutability is unavailable or malformed"
            )
        if not release["immutable"]:
            raise _ReleaseEvidenceError(
                "newest published release must have immutable assets and tag", STATUS_FAIL
            )
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
            if (
                asset.get("state") != "uploaded"
                or type(asset.get("size")) is not int
                or asset["size"] < 1
                or not isinstance(asset.get("digest"), str)
                or _ASSET_DIGEST.fullmatch(asset["digest"]) is None
            ):
                raise _ReleaseEvidenceError(
                    "release assets must be uploaded, nonempty, and have SHA-256 digests",
                    STATUS_FAIL,
                )
        missing = sorted(expected - found)
        if missing:
            raise _ReleaseEvidenceError(
                "missing required release assets: " + ", ".join(missing), STATUS_FAIL
            )
        unexpected = sorted(found - expected)
        if unexpected:
            raise _ReleaseEvidenceError(
                "unexpected release assets: " + ", ".join(unexpected), STATUS_FAIL
            )
        return CheckResult(
            "published release",
            STATUS_PASS,
            f"{release['tag_name']} immutability, classification and "
            f"{len(expected)} required asset "
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


def _weekly_workflow_is_fresh(run: dict[str, Any], now: datetime | None) -> bool:
    if now is None:
        return True
    created = datetime.fromisoformat(run["created_at"].replace("Z", "+00:00"))
    age = now - created
    return -_WORKFLOW_CLOCK_SKEW <= age <= _WEEKLY_WORKFLOW_MAX_AGE


def _audit_workflows(api: GitHubApi, head_sha: str, *, now: datetime | None = None) -> CheckResult:
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
    for name in sorted(_WEEKLY_WORKFLOWS & latest.keys()):
        if not _weekly_workflow_is_fresh(latest[name], now):
            failed.append(f"{name} (stale or future-dated)")
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


def _audit_current_checks(
    api: GitHubApi, head_sha: str, *, now: datetime | None = None
) -> CheckResult:
    # Read jobs from the exact latest workflow attempt, not arbitrary check
    # contexts from another app, an older run, or a different workflow file.
    latest, error = _latest_workflow_runs(api, head_sha)
    if error:
        return CheckResult("current required checks", STATUS_UNVERIFIED, error)
    failures: list[str] = []
    for name in sorted(_WEEKLY_WORKFLOWS & latest.keys()):
        if not _weekly_workflow_is_fresh(latest[name], now):
            failures.append(f"{name} (stale or future-dated)")
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
            if required == "dependency-review" and run["event"] in {
                "push",
                "schedule",
                "workflow_dispatch",
            }:
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


def audit(
    repo: str, *, require_independent_review: bool = False, prepublication: bool = False
) -> list[CheckResult]:
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
    results.append(
        _audit_branch_policy(
            api, rulesets, errors, require_independent_review=require_independent_review
        )
    )
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
    results.append(
        _audit_release_environment(api, require_independent_review=require_independent_review)
    )
    results.append(_audit_release_immutability_setting(api))
    results.append(_audit_actions_policy(api))
    results.extend(_audit_alerts(api))
    if prepublication:
        results.append(_audit_candidate_absence(api))
        results.append(
            CheckResult(
                "published release",
                STATUS_DEFERRED,
                "candidate artifacts do not exist yet; run the full audit after publication",
            )
        )
    else:
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
        results.append(
            CheckResult(
                "accepted CodeQL risks",
                STATUS_UNVERIFIED,
                head_error or "invalid main commit response",
            )
        )
    else:
        audit_time = datetime.now(UTC)
        results.append(
            _audit_codeql_risk_acceptances(
                api,
                repo,
                expected_ref="refs/heads/main",
                expected_commit=head_sha["sha"],
                now=audit_time,
            )
        )
        results.append(_audit_workflows(api, head_sha["sha"], now=audit_time))
        results.append(_audit_current_checks(api, head_sha["sha"], now=audit_time))
    if errors:
        results.extend(CheckResult("audit diagnostics", STATUS_UNVERIFIED, item) for item in errors)
    profile = "independent-review" if require_independent_review else "solo-maintainer"
    return [
        CheckResult(result.name, result.status, f"{profile} policy: {result.detail}")
        if result.name in {"main branch enforcement", "release environment"}
        else result
        for result in results
    ]


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--repo",
        default=os.environ.get("GITHUB_REPOSITORY"),
        help="repository in OWNER/REPO form (defaults to GITHUB_REPOSITORY)",
    )
    parser.add_argument("--json", action="store_true", help="emit machine-readable JSON")
    parser.add_argument(
        "--prepublication",
        action="store_true",
        help="defer only the candidate release-instance check until after publication",
    )
    parser.add_argument(
        "--require-independent-review",
        action="store_true",
        help="require independent PR/release approvals instead of the solo-maintainer default",
    )
    parser.add_argument(
        "--codeql-risk-ref",
        help="audit only accepted dismissed CodeQL risks on this exact GitHub ref",
    )
    parser.add_argument(
        "--codeql-risk-commit",
        help="exact 40-character commit for --codeql-risk-ref",
    )
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
    risk_arguments = (args.codeql_risk_ref, args.codeql_risk_commit)
    if (risk_arguments[0] is None) != (risk_arguments[1] is None):
        print(
            "--codeql-risk-ref and --codeql-risk-commit must be supplied together", file=sys.stderr
        )
        return 2
    if risk_arguments[0] is not None and (args.prepublication or args.require_independent_review):
        print("CodeQL risk-only mode cannot be combined with full-audit profiles", file=sys.stderr)
        return 2
    if risk_arguments[0] is not None:
        results = [
            _audit_codeql_risk_acceptances(
                GitHubApi(args.repo),
                args.repo,
                expected_ref=risk_arguments[0],
                expected_commit=cast(str, risk_arguments[1]),
                now=datetime.now(UTC),
            )
        ]
    else:
        results = audit(
            args.repo,
            require_independent_review=args.require_independent_review,
            prepublication=args.prepublication,
        )
    if args.json:
        print(json.dumps([asdict(result) for result in results], indent=2))
    else:
        for result in results:
            print(f"[{result.status:<10}] {result.name}: {result.detail}")
    accepted = {STATUS_PASS, STATUS_DEFERRED} if args.prepublication else {STATUS_PASS}
    return 0 if all(result.status in accepted for result in results) else 1


if __name__ == "__main__":
    raise SystemExit(main())

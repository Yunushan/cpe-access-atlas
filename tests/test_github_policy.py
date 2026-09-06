# SPDX-License-Identifier: 0BSD
"""API-shaped regressions for policy assurance, including permissive near misses."""

from __future__ import annotations

import copy
import re
import unittest
from pathlib import Path

from scripts import check_github_production_settings as audit


class Api:
    def __init__(self, records: dict[str, object]) -> None:
        self.records = records
        self.calls: list[str] = []

    def get(self, path: str) -> tuple[object, str | None]:
        self.calls.append(path)
        result = self.records.get(path, (None, "unavailable"))
        return result if isinstance(result, tuple) else (result, None)


def actions() -> dict[str, object]:
    return {
        "actions/permissions": {
            "enabled": True,
            "allowed_actions": "selected",
            "sha_pinning_required": True,
        },
        "actions/permissions/workflow": {
            "default_workflow_permissions": "read",
            "can_approve_pull_request_reviews": False,
        },
        "actions/permissions/selected-actions": {
            "github_owned_allowed": True,
            "verified_allowed": False,
            "patterns_allowed": ["github/codeql-action@*", "gitleaks/gitleaks-action@*"],
        },
    }


def tags(kinds: tuple[str, ...], bypass: list[object] | None = None) -> dict[str, object]:
    return {
        "target": "tag",
        "enforcement": "active",
        "conditions": {"ref_name": {"include": ["refs/tags/v*"], "exclude": []}},
        "rules": [{"type": kind} for kind in kinds],
        "bypass_actors": [] if bypass is None else bypass,
    }


def environment(*, require_independent_review: bool = True) -> dict[str, object]:
    return {
        "can_admins_bypass": False,
        "deployment_branch_policy": {"protected_branches": False, "custom_branch_policies": True},
        "protection_rules": [
            {
                "type": "required_reviewers",
                "prevent_self_review": True,
                "reviewers": [{"type": "User", "reviewer": {"id": 123}}],
            }
        ]
        if require_independent_review
        else [],
    }


def environment_api(value: object) -> Api:
    return Api(
        {
            "environments/release": value,
            "environments/release/deployment-branch-policies?per_page=100": {
                "branch_policies": [{"id": 1, "name": "v*", "type": "tag"}],
                "total_count": 1,
            },
        }
    )


def branch_protection(*, require_independent_review: bool = True) -> dict[str, object]:
    return {
        "required_pull_request_reviews": {
            "required_approving_review_count": 1 if require_independent_review else 0,
            "require_code_owner_reviews": require_independent_review,
            "require_last_push_approval": False,
            "dismiss_stale_reviews": True,
            "bypass_pull_request_allowances": {"users": [], "teams": [], "apps": []},
        },
        "required_status_checks": {
            "strict": True,
            "contexts": sorted(audit._REQUIRED_BRANCH_CHECKS),
        },
        "enforce_admins": {"enabled": True},
        "allow_force_pushes": {"enabled": False},
        "allow_deletions": {"enabled": False},
        "required_conversation_resolution": {"enabled": True},
    }


def branch_api(value: object) -> Api:
    return Api(
        {
            "branches/main/protection": value,
            "rules/branches/main?per_page=100": [],
            "branches/main": {"protected": False},
        }
    )


class GitHubPolicyTests(unittest.TestCase):
    def test_solo_classic_policy_keeps_checks_and_rejects_mandatory_approvers(self) -> None:
        baseline = branch_protection(require_independent_review=False)
        result = audit._audit_branch_policy(
            branch_api(baseline), [], [], require_independent_review=False
        )
        self.assertEqual(result.status, audit.STATUS_PASS)
        for field, value in (
            ("required_approving_review_count", 1),
            ("required_approving_review_count", True),
            ("required_approving_review_count", -1),
            ("require_code_owner_reviews", True),
            ("require_code_owner_reviews", None),
            ("require_last_push_approval", True),
            ("require_last_push_approval", None),
            ("required_reviewers", [{"id": 123}]),
            ("required_reviewers", None),
        ):
            with self.subTest(field=field, value=value):
                item = copy.deepcopy(baseline)
                item["required_pull_request_reviews"][field] = value
                self.assertEqual(
                    audit._audit_branch_policy(
                        branch_api(item), [], [], require_independent_review=False
                    ).status,
                    audit.STATUS_FAIL,
                )
        for field in ("allow_force_pushes", "allow_deletions", "enforce_admins"):
            item = copy.deepcopy(baseline)
            item[field]["enabled"] = not item[field]["enabled"]
            self.assertEqual(
                audit._audit_branch_policy(
                    branch_api(item), [], [], require_independent_review=False
                ).status,
                audit.STATUS_FAIL,
            )
        item = copy.deepcopy(baseline)
        item["required_status_checks"]["contexts"].pop()
        self.assertEqual(
            audit._audit_branch_policy(
                branch_api(item), [], [], require_independent_review=False
            ).status,
            audit.STATUS_FAIL,
        )

    def test_solo_effective_rules_cannot_hide_another_mandatory_review_gate(self) -> None:
        approval = {
            "required_approving_review_count": 0,
            "require_code_owner_review": False,
            "require_last_push_approval": False,
            "required_reviewers": [],
            "dismiss_stale_reviews_on_push": True,
            "required_review_thread_resolution": True,
        }
        rules = [
            {"type": "deletion", "ruleset_id": 1},
            {"type": "non_fast_forward", "ruleset_id": 1},
            {"type": "pull_request", "ruleset_id": 1, "parameters": approval},
            {
                "type": "required_status_checks",
                "ruleset_id": 1,
                "parameters": {
                    "strict_required_status_checks_policy": True,
                    "required_status_checks": [
                        {"context": name} for name in audit._REQUIRED_BRANCH_CHECKS
                    ],
                },
            },
        ]
        api = branch_api((None, "Branch not protected (HTTP 404)"))
        api.records["rules/branches/main?per_page=100"] = rules
        details = [{"id": 1, "bypass_actors": []}]
        self.assertEqual(
            audit._audit_branch_policy(api, details, [], require_independent_review=False).status,
            audit.STATUS_PASS,
        )
        self.assertIn("branches/main/protection", api.calls)
        for protection, expected in (
            (branch_protection(), audit.STATUS_UNKNOWN),
            ((None, "HTTP 403"), audit.STATUS_UNKNOWN),
            ((None, "HTTP 404"), audit.STATUS_UNKNOWN),
            (None, audit.STATUS_UNKNOWN),
            ({}, audit.STATUS_UNKNOWN),
            ({"required_pull_request_reviews": "invalid"}, audit.STATUS_UNKNOWN),
            ({"required_pull_request_reviews": None}, audit.STATUS_PASS),
            (branch_protection(require_independent_review=False), audit.STATUS_PASS),
        ):
            api.records["branches/main/protection"] = protection
            self.assertEqual(
                audit._audit_branch_policy(
                    api, details, [], require_independent_review=False
                ).status,
                expected,
            )
        # A sufficient classic policy cannot override a separate effective
        # mandatory approval gate, regardless of which PR rule appears first.
        api.records["branches/main/protection"] = branch_protection(
            require_independent_review=False
        )
        for extra in (
            None,
            {"type": "pull_request", "parameters": None},
            {
                "type": "pull_request",
                "parameters": {**approval, "require_last_push_approval": True},
            },
            {
                "type": "pull_request",
                "parameters": {**approval, "required_approving_review_count": 1},
            },
            {"type": "pull_request", "parameters": {**approval, "required_reviewers": [{}]}},
        ):
            for effective in ([*rules, extra], [extra, *rules]):
                api.records["rules/branches/main?per_page=100"] = effective
                self.assertEqual(
                    audit._audit_branch_policy(
                        api, details, [], require_independent_review=False
                    ).status,
                    audit.STATUS_UNKNOWN,
                )
        api.records["rules/branches/main?per_page=100"] = (None, "HTTP 403")
        self.assertEqual(
            audit._audit_branch_policy(api, details, [], require_independent_review=False).status,
            audit.STATUS_UNKNOWN,
        )

    def test_solo_malformed_rule_types_cannot_pass_through_classic_protection(self) -> None:
        entries = [{"ruleset_id": 1}]
        entries.extend(
            {"ruleset_id": 1, "type": value}
            for value in (None, True, 1, [], {}, "", " ", " pull_request", "PULL_REQUEST")
        )
        for entry in entries:
            with self.subTest(entry=entry):
                api = branch_api(branch_protection(require_independent_review=False))
                api.records["rules/branches/main?per_page=100"] = [entry]
                result = audit._audit_branch_policy(
                    api, [{"id": 1, "bypass_actors": []}], [], require_independent_review=False
                )
                self.assertEqual(result.status, audit.STATUS_UNKNOWN)
                self.assertNotIn("branches/main/protection", api.calls)

    def test_solo_release_policy_omits_approvers_but_keeps_release_boundaries(self) -> None:
        baseline = environment(require_independent_review=False)
        self.assertEqual(
            audit._audit_release_environment(
                environment_api(baseline), require_independent_review=False
            ).status,
            audit.STATUS_PASS,
        )
        for value, expected in (
            (environment(), audit.STATUS_FAIL),
            ({**baseline, "can_admins_bypass": True}, audit.STATUS_FAIL),
            ({**baseline, "deployment_branch_policy": None}, audit.STATUS_FAIL),
            ({**baseline, "protection_rules": [None]}, audit.STATUS_UNKNOWN),
            ({**baseline, "protection_rules": [{}]}, audit.STATUS_UNKNOWN),
        ):
            self.assertEqual(
                audit._audit_release_environment(
                    environment_api(value), require_independent_review=False
                ).status,
                expected,
            )
        api = environment_api(baseline)
        api.records["environments/release/deployment-branch-policies?per_page=100"] = {
            "branch_policies": [{"name": "v*", "type": "branch"}],
        }
        self.assertEqual(
            audit._audit_release_environment(api, require_independent_review=False).status,
            audit.STATUS_FAIL,
        )

    def test_branch_protection_checks_every_explicit_pr_bypass(self) -> None:
        value = branch_protection()
        self.assertEqual(
            audit._audit_branch_policy(branch_api(value), [], []).status, audit.STATUS_PASS
        )
        for kind in ("users", "teams", "apps"):
            item = copy.deepcopy(value)
            item["required_pull_request_reviews"]["bypass_pull_request_allowances"][kind] = [
                {"id": 1}
            ]
            result = audit._audit_branch_policy(branch_api(item), [], [])
            self.assertEqual(result.status, audit.STATUS_FAIL)
            self.assertIn("bypass", result.detail)
        for allowances in (None, {}, {"users": [], "teams": [], "apps": None}):
            item = copy.deepcopy(value)
            item["required_pull_request_reviews"]["bypass_pull_request_allowances"] = allowances
            self.assertEqual(
                audit._audit_branch_policy(branch_api(item), [], []).status, audit.STATUS_UNKNOWN
            )

    def test_legacy_branch_controls_and_malformed_settings_cannot_pass(self) -> None:
        for field in ("required_pull_request_reviews", "required_status_checks"):
            for invalid in ([], "invalid"):
                value = branch_protection()
                value[field] = invalid
                self.assertEqual(
                    audit._audit_branch_policy(branch_api(value), [], []).status, audit.STATUS_FAIL
                )
        for field in (
            "enforce_admins",
            "allow_force_pushes",
            "allow_deletions",
            "required_conversation_resolution",
        ):
            value = branch_protection()
            value[field]["enabled"] = not value[field]["enabled"]
            self.assertEqual(
                audit._audit_branch_policy(branch_api(value), [], []).status, audit.STATUS_FAIL
            )
        value = branch_protection()
        value["required_status_checks"]["contexts"].pop()
        result = audit._audit_branch_policy(branch_api(value), [], [])
        self.assertEqual(result.status, audit.STATUS_FAIL)
        self.assertIn("missing checks", result.detail)
        for field, changed in (
            ("required_approving_review_count", True),
            ("required_approving_review_count", 0),
            ("dismiss_stale_reviews", False),
            ("require_code_owner_reviews", False),
        ):
            value = branch_protection()
            value["required_pull_request_reviews"][field] = changed
            self.assertEqual(
                audit._audit_branch_policy(branch_api(value), [], []).status, audit.STATUS_FAIL
            )

    def test_branch_errors_are_not_confused_with_an_unprotected_branch(self) -> None:
        api = branch_api((None, "HTTP 401"))
        self.assertEqual(audit._audit_branch_policy(api, [], []).status, audit.STATUS_FAIL)
        api.records["branches/main"] = (None, "HTTP 401")
        diagnostics = []
        self.assertEqual(
            audit._audit_branch_policy(api, [], diagnostics).status, audit.STATUS_UNKNOWN
        )
        self.assertTrue(diagnostics)
        api.records["branches/main/protection"] = (None, "Branch not protected")
        self.assertEqual(audit._audit_branch_policy(api, [], []).status, audit.STATUS_FAIL)
        api.records["rules/branches/main?per_page=100"] = (None, "HTTP 401")
        self.assertEqual(audit._audit_branch_policy(api, [], []).status, audit.STATUS_UNKNOWN)
        api.records["branches/main/protection"] = None
        self.assertEqual(audit._audit_branch_policy(api, [], []).status, audit.STATUS_UNKNOWN)

    def test_incomplete_ruleset_diagnostic_does_not_claim_rules_are_absent(self) -> None:
        # Match the live ruleset-only repository: PRs/checks are enforced, but
        # independent review is optional under the solo-maintainer policy. This
        # regression exercises the opt-in independent-review baseline. A 404 from
        # classic protection is not proof that effective rules are absent.
        rules = [
            {"type": "deletion", "ruleset_id": 1},
            {"type": "non_fast_forward", "ruleset_id": 1},
            {
                "type": "pull_request",
                "ruleset_id": 1,
                "parameters": {
                    "required_approving_review_count": 0,
                    "require_code_owner_review": False,
                    "dismiss_stale_reviews_on_push": True,
                    "required_review_thread_resolution": True,
                },
            },
            {
                "type": "required_status_checks",
                "ruleset_id": 1,
                "parameters": {
                    "strict_required_status_checks_policy": True,
                    "required_status_checks": [
                        {"context": name} for name in audit._REQUIRED_BRANCH_CHECKS
                    ],
                },
            },
        ]
        for failure in ("HTTP 404", "HTTP 403", "HTTP 401"):
            with self.subTest(failure=failure):
                api = branch_api((None, failure))
                api.records["branches/main"] = {"protected": True}
                api.records["rules/branches/main?per_page=100"] = rules
                diagnostics = []
                result = audit._audit_branch_policy(
                    api, [{"id": 1, "bypass_actors": []}], diagnostics
                )
                self.assertEqual(result.status, audit.STATUS_UNKNOWN)
                self.assertIn("effective main rules exist", result.detail)
                self.assertIn("do not independently prove", result.detail)
                self.assertNotIn("no matching", result.detail)
                self.assertIn(failure, diagnostics[-1])

                # An independently sufficient classic policy must still pass;
                # a partial ruleset is not automatically an overall failure.
                api.records["branches/main/protection"] = branch_protection()
                self.assertEqual(
                    audit._audit_branch_policy(api, [{"id": 1, "bypass_actors": []}], []).status,
                    audit.STATUS_PASS,
                )

    def test_effective_branch_rules_require_full_details_and_no_bypass(self) -> None:
        rules = [
            {"type": "deletion", "ruleset_id": 1},
            {"type": "non_fast_forward", "ruleset_id": 1},
            {
                "type": "pull_request",
                "ruleset_id": 1,
                "parameters": {
                    "required_approving_review_count": 1,
                    "require_code_owner_review": True,
                    "dismiss_stale_reviews_on_push": True,
                    "required_review_thread_resolution": True,
                },
            },
            {
                "type": "required_status_checks",
                "ruleset_id": 1,
                "parameters": {
                    "strict_required_status_checks_policy": True,
                    "required_status_checks": [
                        {"context": name} for name in audit._REQUIRED_BRANCH_CHECKS
                    ],
                },
            },
        ]
        api = branch_api((None, "HTTP 401"))
        api.records["rules/branches/main?per_page=100"] = rules
        self.assertEqual(
            audit._audit_branch_policy(api, [{"id": 1, "bypass_actors": []}], []).status,
            audit.STATUS_PASS,
        )
        for details in (
            [],
            [{"id": 2, "bypass_actors": []}],
            [{"id": 1}],
            [{"id": 1, "bypass_actors": [{"actor_type": "RepositoryRole"}]}],
        ):
            result = audit._audit_branch_policy(api, details, [])
            self.assertEqual(result.status, audit.STATUS_UNKNOWN)
            self.assertIn("effective main rules exist", result.detail)
            self.assertNotIn("no matching", result.detail)

    def test_actions_inspects_the_selection_not_only_its_mode(self) -> None:
        api = Api(actions())
        self.assertEqual(audit._audit_actions_policy(api).status, audit.STATUS_PASS)
        self.assertIn("actions/permissions/selected-actions", api.calls)
        for pattern in ("*", "*/*", "actions/*", "gitleaks/*", "unreviewed/action@*"):
            with self.subTest(pattern=pattern):
                records = actions()
                records["actions/permissions/selected-actions"]["patterns_allowed"] = [pattern]
                self.assertEqual(
                    audit._audit_actions_policy(Api(records)).status, audit.STATUS_FAIL
                )

    def test_actions_selection_must_be_readable_and_well_formed(self) -> None:
        for selection in (
            (None, "HTTP 401"),
            None,
            {},
            {"patterns_allowed": []},
            {"github_owned_allowed": True, "verified_allowed": False, "patterns_allowed": [None]},
        ):
            records = actions()
            records["actions/permissions/selected-actions"] = selection
            self.assertEqual(audit._audit_actions_policy(Api(records)).status, audit.STATUS_UNKNOWN)

    def test_actions_requires_complete_enforced_baseline(self) -> None:
        for field, value in (
            ("enabled", False),
            ("allowed_actions", "all"),
            ("sha_pinning_required", False),
        ):
            records = actions()
            records["actions/permissions"][field] = value
            self.assertEqual(audit._audit_actions_policy(Api(records)).status, audit.STATUS_FAIL)
        for field in ("enabled", "allowed_actions", "sha_pinning_required"):
            for value in (None, {}, []):
                records = actions()
                records["actions/permissions"][field] = value
                self.assertEqual(
                    audit._audit_actions_policy(Api(records)).status, audit.STATUS_UNKNOWN
                )
        for endpoint in ("actions/permissions", "actions/permissions/workflow"):
            records = actions()
            records[endpoint] = (None, "HTTP 403")
            self.assertEqual(audit._audit_actions_policy(Api(records)).status, audit.STATUS_UNKNOWN)
        for field, value, expected in (
            ("default_workflow_permissions", "write", audit.STATUS_FAIL),
            ("can_approve_pull_request_reviews", True, audit.STATUS_FAIL),
            ("default_workflow_permissions", {}, audit.STATUS_UNKNOWN),
        ):
            records = actions()
            records["actions/permissions/workflow"][field] = value
            self.assertEqual(audit._audit_actions_policy(Api(records)).status, expected)

    def test_empty_action_allowance_is_not_operational(self) -> None:
        records = actions()
        records["actions/permissions/selected-actions"] = {
            "github_owned_allowed": False,
            "verified_allowed": False,
            "patterns_allowed": [],
        }
        self.assertEqual(audit._audit_actions_policy(Api(records)).status, audit.STATUS_FAIL)
        records["actions/permissions/selected-actions"]["verified_allowed"] = True
        self.assertEqual(audit._audit_actions_policy(Api(records)).status, audit.STATUS_PASS)

    def test_workflow_action_repositories_have_been_explicitly_reviewed(self) -> None:
        root = Path(__file__).resolve().parents[1]
        for path in (root / ".github/workflows").glob("*.yml"):
            for action in re.findall(r"uses:\s+([^@\s]+)@", path.read_text(encoding="utf-8")):
                self.assertIn("/".join(action.split("/")[:2]), audit._APPROVED_ACTION_REPOSITORIES)

    def test_creation_bypass_cannot_bypass_tag_immutability(self) -> None:
        owner = {"actor_type": "User", "actor_id": 123, "bypass_mode": "always"}
        trusted = frozenset({("User", 123)})
        combined = tags(("creation", "update", "deletion"), [owner])
        self.assertEqual(audit._audit_tag_policy([combined], trusted).status, audit.STATUS_FAIL)
        policies = [tags(("creation",), [owner]), tags(("update",)), tags(("deletion",))]
        self.assertEqual(audit._audit_tag_policy(policies, trusted).status, audit.STATUS_PASS)
        self.assertEqual(audit._audit_tag_policy(policies).status, audit.STATUS_FAIL)
        policies[0]["bypass_actors"] = [
            {"actor_type": "RepositoryRole", "actor_id": 4, "bypass_mode": "always"}
        ]
        self.assertEqual(audit._audit_tag_policy(policies, trusted).status, audit.STATUS_FAIL)

    def test_tag_rules_require_full_coverage_and_visible_bypasses(self) -> None:
        policy = tags(("creation", "update", "deletion"))
        self.assertEqual(audit._audit_tag_policy([policy]).status, audit.STATUS_FAIL)
        for field, value, expected in (
            ("bypass_actors", None, audit.STATUS_UNKNOWN),
            ("rules", None, audit.STATUS_UNKNOWN),
            ("conditions", None, audit.STATUS_UNKNOWN),
            ("target", "branch", audit.STATUS_FAIL),
            ("enforcement", "disabled", audit.STATUS_FAIL),
        ):
            item = copy.deepcopy(policy)
            item[field] = value
            self.assertEqual(audit._audit_tag_policy([item]).status, expected)
        for refs, expected in (
            ({"include": None, "exclude": []}, audit.STATUS_UNKNOWN),
            ({"include": ["refs/tags/v*"], "exclude": None}, audit.STATUS_UNKNOWN),
            ({"include": ["refs/tags/v*"], "exclude": ["refs/tags/v2*"]}, audit.STATUS_UNKNOWN),
            ({"include": ["refs/tags/v1*"], "exclude": []}, audit.STATUS_UNKNOWN),
        ):
            item = copy.deepcopy(policy)
            item["conditions"]["ref_name"] = refs
            self.assertEqual(audit._audit_tag_policy([item]).status, expected)
        for value in (None, {}, [None]):
            self.assertEqual(audit._audit_tag_policy(value).status, audit.STATUS_UNKNOWN)

    def test_tag_creator_must_be_authorized_by_every_creation_ruleset(self) -> None:
        owner = {"actor_type": "User", "actor_id": 1, "bypass_mode": "always"}
        other = {"actor_type": "User", "actor_id": 2, "bypass_mode": "always"}
        trusted = frozenset({("User", 1), ("User", 2)})
        policies = [
            tags(("creation",), [owner, other]),
            tags(("creation",), [owner]),
            tags(("update", "deletion")),
        ]
        self.assertEqual(audit._audit_tag_policy(policies, trusted).status, audit.STATUS_PASS)
        policies[0]["bypass_actors"] = [other]
        self.assertEqual(audit._audit_tag_policy(policies, trusted).status, audit.STATUS_FAIL)
        policies[0]["bypass_actors"] = []
        self.assertEqual(audit._audit_tag_policy(policies, trusted).status, audit.STATUS_FAIL)

    def test_release_environment_requires_real_independent_review(self) -> None:
        value = environment()
        self.assertEqual(
            audit._audit_release_environment(environment_api(value)).status,
            audit.STATUS_PASS,
        )
        for field, bad_value in (("reviewers", []), ("prevent_self_review", False)):
            item = copy.deepcopy(value)
            item["protection_rules"][0][field] = bad_value
            self.assertEqual(
                audit._audit_release_environment(Api({"environments/release": item})).status,
                audit.STATUS_FAIL,
            )
        for item, expected in (
            ({**value, "can_admins_bypass": True}, audit.STATUS_FAIL),
            ({**value, "protection_rules": []}, audit.STATUS_FAIL),
            ({**value, "protection_rules": None}, audit.STATUS_UNKNOWN),
            ({**value, "can_admins_bypass": None}, audit.STATUS_UNKNOWN),
            ((None, "HTTP 403"), audit.STATUS_UNKNOWN),
            (None, audit.STATUS_UNKNOWN),
        ):
            self.assertEqual(
                audit._audit_release_environment(Api({"environments/release": item})).status,
                expected,
            )

    def test_release_reviewer_metadata_cannot_be_missing_or_ambiguous(self) -> None:
        for reviewers in (
            None,
            [None],
            [{"type": {}}],
            [{"type": "User", "reviewer": {"id": True}}],
            [{"type": "Team", "reviewer": {"id": 0}}],
        ):
            value = environment()
            value["protection_rules"][0]["reviewers"] = reviewers
            self.assertEqual(
                audit._audit_release_environment(Api({"environments/release": value})).status,
                audit.STATUS_UNKNOWN,
            )
        value = environment()
        value["protection_rules"] *= 2
        self.assertEqual(
            audit._audit_release_environment(Api({"environments/release": value})).status,
            audit.STATUS_UNKNOWN,
        )

    def test_release_environment_must_restrict_the_actual_deployment_refs(self) -> None:
        for policy, expected in (
            (None, audit.STATUS_FAIL),
            ({}, audit.STATUS_UNKNOWN),
            ({"protected_branches": True, "custom_branch_policies": False}, audit.STATUS_FAIL),
            ({"protected_branches": False, "custom_branch_policies": False}, audit.STATUS_FAIL),
        ):
            value = environment()
            value["deployment_branch_policy"] = policy
            self.assertEqual(
                audit._audit_release_environment(environment_api(value)).status, expected
            )
        value = environment()
        del value["deployment_branch_policy"]
        self.assertEqual(
            audit._audit_release_environment(environment_api(value)).status, audit.STATUS_UNKNOWN
        )
        for policies in (
            [],
            [{"name": "*", "type": "tag"}],
            [{"name": "v*", "type": "branch"}],
            [{"name": "main", "type": "branch"}],
            [None],
            [{"name": "v*", "type": "tag"}, {"name": "*", "type": "branch"}],
        ):
            api = environment_api(environment())
            api.records["environments/release/deployment-branch-policies?per_page=100"] = {
                "branch_policies": policies
            }
            self.assertEqual(audit._audit_release_environment(api).status, audit.STATUS_FAIL)
        api = environment_api(environment())
        api.records["environments/release/deployment-branch-policies?per_page=100"] = (
            None,
            "HTTP 401",
        )
        self.assertEqual(audit._audit_release_environment(api).status, audit.STATUS_UNKNOWN)
        value = environment()
        del value["protection_rules"][0]["prevent_self_review"]
        self.assertEqual(
            audit._audit_release_environment(Api({"environments/release": value})).status,
            audit.STATUS_UNKNOWN,
        )

    def test_private_reporting_is_checked_and_inaccessibility_is_not_disabled(self) -> None:
        for value, expected in (
            ({"enabled": True}, audit.STATUS_PASS),
            ({"enabled": False}, audit.STATUS_FAIL),
            ({}, audit.STATUS_UNKNOWN),
            ({"enabled": None}, audit.STATUS_UNKNOWN),
            ((None, "HTTP 401"), audit.STATUS_UNKNOWN),
        ):
            self.assertEqual(
                audit._audit_private_reporting(
                    Api({"private-vulnerability-reporting": value})
                ).status,
                expected,
            )

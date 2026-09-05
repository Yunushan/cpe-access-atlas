# SPDX-License-Identifier: 0BSD
"""Audit transport, orchestration and hostile-evidence regressions; no GitHub I/O."""

from __future__ import annotations

import copy
import io
import json
import os
import subprocess
import unittest
from contextlib import redirect_stderr, redirect_stdout
from types import SimpleNamespace
from unittest.mock import patch

from scripts import check_github_production_settings as audit
from tests.test_github_policy import actions, branch_protection, environment_api, tags
from tests.test_github_release import Api, fixture
from tests.test_repository_controls import _successful_workflow_responses

SHA = "a" * 40
ALERT_ENDPOINTS = (
    "dependabot/alerts?state=open&per_page=100",
    "code-scanning/alerts?state=open&per_page=100",
    "secret-scanning/alerts?state=open&per_page=100",
)


def complete_fixture(*, require_independent_review: bool = False) -> dict[str, object]:
    from tests.test_github_policy import environment

    release_environment = environment(require_independent_review=require_independent_review)
    if require_independent_review:
        release_environment["protection_rules"][0]["reviewers"][0]["reviewer"]["id"] = 456
    immutable = {"id": 1, **tags(("update", "deletion"))}
    creator = {
        "id": 2,
        **tags(("creation",), [{"actor_type": "User", "actor_id": 123, "bypass_mode": "always"}]),
    }
    return {
        **fixture(),
        **actions(),
        **environment_api(release_environment).records,
        **_successful_workflow_responses(),
        "": {
            "full_name": "example/project",
            "owner": {"id": 123, "type": "User"},
            "security_and_analysis": {
                "secret_scanning": {"status": "enabled"},
                "secret_scanning_push_protection": {"status": "enabled"},
            },
        },
        "dependency-graph/sbom": {"sbom": {"packages": []}},
        "automated-security-fixes": {"enabled": True, "paused": False},
        "private-vulnerability-reporting": {"enabled": True},
        "rulesets?per_page=100": [{"id": 1}, {"id": 2}],
        "rulesets/1": immutable,
        "rulesets/2": creator,
        "rules/branches/main?per_page=100": [],
        "branches/main/protection": branch_protection(
            require_independent_review=require_independent_review
        ),
        "branches/main": {"protected": True},
        **{endpoint: [] for endpoint in ALERT_ENDPOINTS},
    }


class GitHubTransportTests(unittest.TestCase):
    def test_success_is_cached_and_every_command_is_explicitly_get_only(self) -> None:
        completed = SimpleNamespace(returncode=0, stdout='{"name":"Türkçe"}', stderr="")
        with (
            patch.object(audit.shutil, "which", return_value="synthetic-gh"),
            patch.object(audit.subprocess, "run", return_value=completed) as run,
        ):
            api = audit.GitHubApi("example/project")
            self.assertEqual(api.get(""), ({"name": "Türkçe"}, None))
            self.assertEqual(api.get(""), ({"name": "Türkçe"}, None))
            self.assertEqual(api.get("branches/main"), ({"name": "Türkçe"}, None))
        self.assertEqual(run.call_count, 2)
        for call in run.call_args_list:
            self.assertEqual(call.args[0][:4], ["synthetic-gh", "api", "--method", "GET"])
            self.assertFalse(call.kwargs.get("shell", False))
            self.assertEqual(call.kwargs["timeout"], 30)
        self.assertEqual(run.call_args.args[0][-1], "repos/example/project/branches/main")

    def test_missing_executable_does_not_start_a_process(self) -> None:
        with patch.object(audit.shutil, "which", return_value=None):
            with patch.object(audit.subprocess, "run") as run:
                payload, error = audit.GitHubApi("example/project").get("")
        self.assertIsNone(payload)
        self.assertIn("not found", error)
        run.assert_not_called()

    def test_transport_failures_and_invalid_json_are_controlled_and_not_cached(self) -> None:
        failures = (
            subprocess.TimeoutExpired("synthetic-gh", 30),
            OSError("synthetic launch failure"),
            SimpleNamespace(returncode=1, stdout="", stderr="first line\nHTTP 403"),
            SimpleNamespace(returncode=1, stdout="HTTP 401", stderr=""),
            SimpleNamespace(returncode=1, stdout="", stderr=""),
            SimpleNamespace(returncode=0, stdout="not json", stderr=""),
        )
        success = SimpleNamespace(returncode=0, stdout="[]", stderr="")
        for failure in failures:
            with self.subTest(failure=failure):
                with (
                    patch.object(audit.shutil, "which", return_value="synthetic-gh"),
                    patch.object(audit.subprocess, "run", side_effect=[failure, success]) as run,
                ):
                    api = audit.GitHubApi("example/project")
                    payload, error = api.get("rulesets")
                    self.assertIsNone(payload)
                    self.assertIsInstance(error, str)
                    self.assertEqual(api.get("rulesets"), ([], None))
                self.assertEqual(run.call_count, 2)

    def test_failed_process_diagnostics_expose_only_safe_status_metadata(self) -> None:
        private = "198.51.100.17 synthetic-private-value C:/private/synthetic-file"
        cases = (
            (f"gh: API rate limit exceeded for {private} (HTTP 403)", "HTTP 403", True),
            (f"Secondary rate-limit for {private} (HTTP 403)", "HTTP 403", True),
            (f"{private} (HTTP 429)", "HTTP 429", True),
            (f"{private} (HTTP 401)", "authentication required (HTTP 401)", False),
            (f"{private} (HTTP 403)", "access denied (HTTP 403)", False),
            (f"{private} (HTTP 404)", "unavailable or inaccessible (HTTP 404)", False),
            (
                f"Branch not protected {private} (HTTP 404)",
                "Branch not protected (HTTP 404)",
                False,
            ),
            (f"{private} (HTTP 503)", "server error (HTTP 503)", False),
            (f"{private} (HTTP 422)", "request failed (HTTP 422)", False),
            (f"{private} HTTP 999", "request failed (exit 1)", False),
            (f"{private} HTTP 401 HTTP 403", "request failed (exit 1)", False),
            (f"{private} HTTP 403 HTTP 403", "access denied (HTTP 403)", False),
            (private, "request failed (exit 1)", False),
            ("", "request failed (exit 1)", False),
        )
        for diagnostic, expected, deferred in cases:
            for stream in ("stdout", "stderr"):
                with self.subTest(expected=expected, stream=stream):
                    completed = SimpleNamespace(returncode=1, stdout="", stderr="")
                    setattr(completed, stream, diagnostic)
                    error, limited = audit._request_failure(completed)
                    self.assertIn(expected, error)
                    self.assertIs(limited, deferred)
                    for value in private.split():
                        self.assertNotIn(value, error)

    def test_local_launch_and_parse_errors_do_not_echo_private_diagnostics(self) -> None:
        private = "synthetic-private-diagnostic"
        failures = (
            OSError(13, private, "C:/private/synthetic-file"),
            OSError(private),
            SimpleNamespace(returncode=0, stdout=private, stderr=""),
        )
        for failure in failures:
            with self.subTest(kind=type(failure)):
                with (
                    patch.object(audit.shutil, "which", return_value="synthetic-gh"),
                    patch.object(audit.subprocess, "run", side_effect=[failure]),
                ):
                    payload, error = audit.GitHubApi("example/project").get("")
                self.assertIsNone(payload)
                self.assertIsInstance(error, str)
                self.assertNotIn(private, error)
                self.assertNotIn("C:/private", error)
        completed = SimpleNamespace(returncode=0, stdout="{}", stderr="")
        # Parser recursion/integer limits vary by interpreter configuration;
        # verify both failure interfaces without changing global process limits.
        for failure in (ValueError(private), RecursionError(private)):
            with (
                patch.object(audit.shutil, "which", return_value="synthetic-gh"),
                patch.object(audit.subprocess, "run", return_value=completed),
                patch.object(audit.json, "loads", side_effect=failure),
            ):
                payload, error = audit.GitHubApi("example/project").get("")
            self.assertEqual(
                (payload, error), (None, "GitHub returned invalid or excessively nested JSON")
            )

    def test_rate_limit_stops_new_requests_but_keeps_existing_successful_evidence(self) -> None:
        success = SimpleNamespace(returncode=0, stdout='{"protected":false}', stderr="")
        limited = SimpleNamespace(
            returncode=1, stdout="", stderr="gh: rate limit exceeded for 198.51.100.17 (HTTP 403)"
        )
        with (
            patch.object(audit.shutil, "which", return_value="synthetic-gh"),
            patch.object(audit.subprocess, "run", side_effect=[success, limited]) as run,
        ):
            api = audit.GitHubApi("example/project")
            self.assertEqual(api.get("branches/main"), ({"protected": False}, None))
            _, first_error = api.get("rulesets")
            self.assertIn("rate limit", first_error)
            for path in ("rulesets", "actions/permissions", "releases", "code-scanning/alerts"):
                self.assertEqual(api.get(path), (None, first_error))
            self.assertEqual(api.get("branches/main"), ({"protected": False}, None))
            self.assertEqual(run.call_count, 2)
        # A new, explicitly started audit can try again; no cross-run state or
        # permanent suppression of diagnostics is retained.
        with (
            patch.object(audit.shutil, "which", return_value="synthetic-gh"),
            patch.object(audit.subprocess, "run", return_value=success) as run,
        ):
            self.assertEqual(
                audit.GitHubApi("example/project").get("rulesets"), ({"protected": False}, None)
            )
            self.assertEqual(run.call_count, 1)


class GitHubCollectionTests(unittest.TestCase):
    def test_optional_policy_helpers_reject_malformed_and_unrelated_shapes(self) -> None:
        for ruleset in (
            {},
            {"conditions": {}},
            {"conditions": {"ref_name": {"include": None}}},
            {"conditions": {"ref_name": {"include": [], "exclude": None}}},
            {"conditions": {"ref_name": {"include": [None]}}},
        ):
            self.assertFalse(audit._branch_rule_matches(ruleset, "refs/heads/main"))
        self.assertFalse(audit._ruleset_has_type({"rules": None}, "pull_request"))
        for rules in (None, [], [None, {"type": "other"}]):
            self.assertEqual(audit._ruleset_parameters({"rules": rules}, "pull_request"), {})
        self.assertEqual(audit._status_check_names(None), set())
        self.assertEqual(
            audit._status_check_names(
                {"checks": ["legacy", None, {}, {"context": None, "name": "modern"}]}
            ),
            {"legacy", "modern"},
        )
        self.assertEqual(audit._audit_security_features(None).status, audit.STATUS_UNKNOWN)
        self.assertEqual(
            audit._audit_dependabot_updates(
                Api({"automated-security-fixes": {"enabled": True, "paused": None}})
            ).status,
            audit.STATUS_UNKNOWN,
        )
        # A rule excluding part of v* cannot itself prove namespace-wide protection.
        partial = tags(("update",))
        partial["conditions"]["ref_name"]["exclude"] = ["refs/tags/v1*"]
        self.assertEqual(audit._audit_tag_policy([partial]).status, audit.STATUS_FAIL)

    def test_collection_totals_cannot_be_malformed_or_contradict_the_records(self) -> None:
        for total in (True, -1, "1", {}, [], 1.0, None):
            with self.subTest(total=total):
                values, error = audit._get_collection(
                    Api({"jobs?per_page=100": {"jobs": [], "total_count": total}}), "jobs", "jobs"
                )
                self.assertIsNone(values)
                self.assertIn("invalid collection total", error)
        for payload in ([], {"jobs": [{}], "total_count": 0}, {"jobs": [{}] * 101}):
            with self.subTest(payload_type=type(payload)):
                values, error = audit._get_collection(
                    Api({"jobs?per_page=100": payload}), "jobs", "jobs"
                )
                self.assertIsNone(values)
                self.assertIsNotNone(error)

    def test_totals_cannot_change_or_disappear_between_pages(self) -> None:
        for second in ({"jobs": [], "total_count": 100}, {"jobs": []}):
            api = Api(
                {
                    "jobs?per_page=100": {"jobs": [{}] * 100, "total_count": 101},
                    "jobs?per_page=100&page=2": second,
                }
            )
            values, error = audit._get_collection(api, "jobs", "jobs")
            self.assertIsNone(values)
            self.assertIn("during pagination", error)

    def test_unbounded_full_pages_stop_at_the_safety_limit(self) -> None:
        api = Api({})
        with patch.object(api, "get", return_value=([{}] * 100, None)) as get:
            values, error = audit._get_collection(api, "records")
        self.assertIsNone(values)
        self.assertIn("safety limit", error)
        self.assertEqual(get.call_count, 100)
        self.assertEqual(get.call_args.args, ("records?per_page=100&page=100",))

    def test_ruleset_summaries_and_details_require_consistent_unique_identities(self) -> None:
        for summary in (None, {}, {"id": True}, {"id": 0}, {"id": []}):
            api = Api({"rulesets?per_page=100": [summary]})
            details, errors = audit._load_rulesets(api)
            self.assertEqual(details, [])
            self.assertEqual(errors, ["invalid ruleset summary"])
        for detail in (None, {}, {"id": 2, "rules": []}, {"id": True, "rules": []}):
            api = Api({"rulesets?per_page=100": [{"id": 1}], "rulesets/1": detail})
            self.assertEqual(audit._load_rulesets(api), ([], ["invalid ruleset detail"]))
        api = Api({"rulesets?per_page=100": [{"id": 1}] * 2, "rulesets/1": {"id": 1, "rules": []}})
        details, errors = audit._load_rulesets(api)
        self.assertEqual(len(details), 1)
        self.assertEqual(errors, ["invalid ruleset summary"])
        self.assertEqual(api.calls.count("rulesets/1"), 1)


class GitHubAuditIntegrationTests(unittest.TestCase):
    def run_cli(
        self, records: dict[str, object], arguments: list[str] | None = None
    ) -> tuple[int, str, str, set[str]]:
        """Run real CLI/adapter/orchestrator; replace only the external process."""

        requested: set[str] = set()

        def transport(command: list[str], **kwargs: object) -> SimpleNamespace:
            self.assertEqual(command[:4], ["synthetic-gh", "api", "--method", "GET"])
            self.assertFalse(kwargs.get("shell", False))
            prefix = "repos/example/project"
            self.assertTrue(command[4] == prefix or command[4].startswith(prefix + "/"))
            endpoint = command[4].removeprefix(prefix).removeprefix("/")
            requested.add(endpoint)
            payload = records.get(endpoint, (None, "fixture endpoint unavailable"))
            if isinstance(payload, tuple):
                return SimpleNamespace(returncode=1, stdout="", stderr=payload[1])
            return SimpleNamespace(returncode=0, stdout=json.dumps(payload), stderr="")

        out, err = io.StringIO(), io.StringIO()
        with (
            patch.object(audit.shutil, "which", return_value="synthetic-gh"),
            patch.object(audit.subprocess, "run", side_effect=transport),
            patch.dict(os.environ, {"GITHUB_REPOSITORY": "example/project"}),
            redirect_stdout(out),
            redirect_stderr(err),
        ):
            code = audit.main(["--json"] if arguments is None else arguments)
        return code, out.getvalue(), err.getvalue(), requested

    def test_complete_evidence_drives_every_audit_through_the_cli_and_get_adapter(self) -> None:
        code, output, error, requested = self.run_cli(complete_fixture())
        self.assertEqual(code, 0, output)
        results = json.loads(output)
        self.assertEqual(len(results), 17)
        self.assertEqual(len({item["name"] for item in results}), 17)
        self.assertTrue(all(item["status"] == audit.STATUS_PASS for item in results))
        self.assertEqual(error, "")
        self.assertIn("releases/2/assets?per_page=100", requested)
        self.assertIn("rulesets/2", requested)
        self.assertTrue(set(ALERT_ENDPOINTS).issubset(requested))
        code, output, error, _ = self.run_cli(complete_fixture(), ["--repo", "example/project"])
        self.assertEqual(code, 0)
        self.assertIn("[PASS", output)
        self.assertIn("current required checks", output)
        self.assertEqual(error, "")

    def test_independent_review_is_explicit_opt_in_and_profiles_are_labelled(self) -> None:
        for independent in (False, True):
            arguments = ["--json"]
            if independent:
                arguments.append("--require-independent-review")
            records = complete_fixture(require_independent_review=independent)
            code, output, _, _ = self.run_cli(records, arguments)
            self.assertEqual(code, 0, output)
            results = {item["name"]: item for item in json.loads(output)}
            profile = "independent-review" if independent else "solo-maintainer"
            for name in ("main branch enforcement", "release environment"):
                self.assertIn(profile, results[name]["detail"])
            # The opposite policy must not silently pass: solo operation
            # rejects mandatory approvers; independent mode requires them.
            opposite = complete_fixture(require_independent_review=not independent)
            code, output, _, _ = self.run_cli(opposite, arguments)
            self.assertEqual(code, 1, output)
            results = {item["name"]: item for item in json.loads(output)}
            for name in ("main branch enforcement", "release environment"):
                self.assertNotEqual(results[name]["status"], audit.STATUS_PASS)

    def test_denial_of_each_required_endpoint_cannot_produce_an_all_passing_audit(self) -> None:
        baseline = complete_fixture()
        _, _, _, endpoints = self.run_cli(baseline)
        for endpoint in sorted(endpoints):
            with self.subTest(endpoint=endpoint):
                records = copy.deepcopy(baseline)
                records[endpoint] = (None, "HTTP 403: synthetic permission denial")
                code, output, error, _ = self.run_cli(records)
                self.assertEqual(code, 1, output)
                self.assertTrue(
                    any(item["status"] == audit.STATUS_UNKNOWN for item in json.loads(output))
                )
                self.assertEqual(error, "")

    def test_real_cli_summarizes_rate_limits_without_private_details_or_more_requests(self) -> None:
        for arguments in (["--json"], ["--repo", "example/project"]):
            records = complete_fixture()
            records["dependency-graph/sbom"] = (
                None,
                "gh: API rate limit exceeded for 198.51.100.17 synthetic-private-value (HTTP 403)",
            )
            code, output, error, requested = self.run_cli(records, arguments)
            self.assertEqual(code, 1)
            self.assertIn("UNVERIFIED", output)
            self.assertIn("rate limit", output)
            self.assertNotIn("198.51.100.17", output + error)
            self.assertNotIn("synthetic-private-value", output + error)
            self.assertEqual(requested, {"", "dependency-graph/sbom"})
            self.assertEqual(error, "")

    def test_wrong_top_level_json_types_never_crash_the_full_audit(self) -> None:
        baseline = complete_fixture()
        _, _, _, endpoints = self.run_cli(baseline)
        for endpoint in sorted(endpoints):
            for value in (None, False, 1, "invalid", [], {}):
                with self.subTest(endpoint=endpoint, value=value):
                    records = copy.deepcopy(baseline)
                    records[endpoint] = value
                    code, output, error, _ = self.run_cli(records)
                    self.assertIn(code, (0, 1))
                    results = json.loads(output)
                    self.assertTrue(results)
                    self.assertTrue(
                        all(item["status"] in {"PASS", "FAIL", "UNVERIFIED"} for item in results)
                    )
                    self.assertEqual(error, "")

    def test_main_identity_and_owner_metadata_cannot_be_guessed(self) -> None:
        for sha in (None, "main", "", "a" * 39, [], True):
            records = complete_fixture()
            records["commits/main"] = {"sha": sha}
            code, output, _, _ = self.run_cli(records)
            self.assertEqual(code, 1)
            checks = {item["name"]: item for item in json.loads(output)}
            self.assertEqual(checks["current required workflows"]["status"], "UNVERIFIED")
        for owner in (None, {}, {"id": True, "type": "User"}, {"id": 123, "type": "Organization"}):
            records = complete_fixture()
            records[""]["owner"] = owner
            code, output, _, _ = self.run_cli(records)
            self.assertEqual(code, 1)
            checks = {item["name"]: item for item in json.loads(output)}
            self.assertNotEqual(checks["release tag enforcement"]["status"], "PASS")

    def test_malformed_effective_rule_identities_are_unverified_not_unhashable(self) -> None:
        for value in (None, {}, [], True, 0, "1"):
            records = complete_fixture()
            records["rules/branches/main?per_page=100"] = [
                {"type": "deletion", "ruleset_id": value}
            ]
            records["branches/main/protection"] = (None, "HTTP 403")
            code, output, _, _ = self.run_cli(records)
            self.assertEqual(code, 1)
            self.assertIn("audit diagnostics", output)
            self.assertIn("UNVERIFIED", output)

    def test_workflow_shapes_that_previously_crashed_return_unverified(self) -> None:
        for field in ("name", "event"):
            for value in (None, {}, [], True):
                records = complete_fixture()
                records[f"actions/runs?head_sha={SHA}&per_page=100"]["workflow_runs"][0][field] = (
                    value
                )
                code, output, _, _ = self.run_cli(records)
                self.assertEqual(code, 1)
                checks = {item["name"]: item for item in json.loads(output)}
                self.assertEqual(checks["current required workflows"]["status"], "UNVERIFIED")
                self.assertEqual(checks["current required checks"]["status"], "UNVERIFIED")
        for field, value in (
            ("conclusion", {}),
            ("conclusion", []),
            ("run_id", True),
            ("run_attempt", True),
        ):
            records = complete_fixture()
            records["actions/runs/1/attempts/1/jobs?per_page=100"]["jobs"][0][field] = value
            code, output, _, _ = self.run_cli(records)
            self.assertEqual(code, 1)
            checks = {item["name"]: item for item in json.loads(output)}
            self.assertEqual(checks["current required checks"]["status"], "UNVERIFIED")

    def test_workflow_identity_and_time_must_be_complete_and_well_typed(self) -> None:
        for field, value in (
            ("id", True),
            ("id", 0),
            ("run_attempt", None),
            ("created_at", None),
            ("created_at", "invalid"),
            ("created_at", "2026-09-05T10:00:00"),
        ):
            with self.subTest(field=field, value=value):
                records = complete_fixture()
                records[f"actions/runs?head_sha={SHA}&per_page=100"]["workflow_runs"][0][field] = (
                    value
                )
                result = audit._audit_workflows(Api(records), SHA)
                self.assertEqual(result.status, audit.STATUS_UNKNOWN)
        api = Api({})
        self.assertIsNotNone(audit._latest_workflow_runs(api, "invalid")[1])
        self.assertEqual(api.calls, [])
        records = complete_fixture()
        records[f"actions/runs?head_sha={SHA}&per_page=100"]["workflow_runs"][0] = None
        self.assertEqual(audit._audit_workflows(Api(records), SHA).status, audit.STATUS_UNKNOWN)

    def test_unrelated_and_older_workflows_do_not_replace_the_latest_execution(self) -> None:
        records = complete_fixture()
        payload = records[f"actions/runs?head_sha={SHA}&per_page=100"]
        older = {
            **payload["workflow_runs"][0],
            "created_at": "2026-09-04T10:00:00Z",
            "conclusion": "failure",
        }
        payload["workflow_runs"] += [older, {"name": "Unrelated workflow"}]
        payload["total_count"] += 2
        api = Api(records)
        latest, error = audit._latest_workflow_runs(api, SHA)
        self.assertIsNone(error)
        self.assertEqual(latest["CI"]["conclusion"], "success")
        self.assertEqual(audit._audit_workflows(api, SHA).status, audit.STATUS_PASS)
        # A rerun of the same execution supersedes its historical first attempt.
        rerun = {**payload["workflow_runs"][0], "run_attempt": 2, "conclusion": "failure"}
        payload["workflow_runs"].append(rerun)
        payload["total_count"] += 1
        latest, error = audit._latest_workflow_runs(api, SHA)
        self.assertIsNone(error)
        self.assertEqual(latest["CI"]["run_attempt"], 2)
        self.assertEqual(audit._audit_workflows(api, SHA).status, audit.STATUS_FAIL)

    def test_missing_workflow_and_non_push_skips_cannot_satisfy_current_checks(self) -> None:
        records = complete_fixture()
        payload = records[f"actions/runs?head_sha={SHA}&per_page=100"]
        payload["workflow_runs"].pop(0)
        payload["total_count"] -= 1
        result = audit._audit_current_checks(Api(records), SHA)
        self.assertEqual(result.status, audit.STATUS_FAIL)
        self.assertIn("CI (no main execution)", result.detail)
        records = complete_fixture()
        records[f"actions/runs?head_sha={SHA}&per_page=100"]["workflow_runs"][1]["event"] = (
            "schedule"
        )
        result = audit._audit_current_checks(Api(records), SHA)
        self.assertEqual(result.status, audit.STATUS_FAIL)
        self.assertIn("dependency-review", result.detail)

    def test_alert_counts_cover_all_pages_without_printing_sensitive_fields(self) -> None:
        records = complete_fixture()
        secret = "SYNTHETIC-ALERT-CONTENT-MUST-NOT-APPEAR"
        alert = {
            "secret": secret,
            "rule": {"id": secret},
            "most_recent_instance": {"location": {"path": secret}},
        }
        for endpoint in ALERT_ENDPOINTS:
            records[endpoint] = [alert] * 100
            records[endpoint + "&page=2"] = [alert]
        code, output, error, requested = self.run_cli(records)
        self.assertEqual(code, 1)
        self.assertNotIn(secret, output + error)
        checks = {item["name"]: item for item in json.loads(output)}
        for name in ("Dependabot alerts", "CodeQL alerts", "secret-scanning alerts"):
            self.assertEqual(checks[name]["status"], "FAIL")
            self.assertEqual(checks[name]["detail"], "101 open alert(s)")
        self.assertTrue({endpoint + "&page=2" for endpoint in ALERT_ENDPOINTS}.issubset(requested))

    def test_invalid_alert_entries_cannot_prove_a_clean_inventory(self) -> None:
        for endpoint in ALERT_ENDPOINTS:
            records = complete_fixture()
            records[endpoint] = [None]
            code, output, _, _ = self.run_cli(records)
            self.assertEqual(code, 1)
            self.assertIn("invalid alert response", output)

    def test_invalid_repository_arguments_never_reach_github(self) -> None:
        invalid = (
            "",
            "owner",
            "/owner/repo",
            "owner/repo/",
            "owner/repo/other",
            "https://github.com/owner/repo",
            "owner/repo?x=1",
            "owner/repo\n",
            "owner/..",
            "owner/.",
            "owner /repo",
            "-owner/repo",
            "a" * 40 + "/repo",
        )
        for value in invalid:
            with self.subTest(value=value):
                with patch.object(audit, "audit") as run, redirect_stderr(io.StringIO()):
                    self.assertEqual(audit.main([f"--repo={value}"]), 2)
                run.assert_not_called()
        with patch.dict(os.environ, {}, clear=True):
            with patch.object(audit, "audit") as run, redirect_stderr(io.StringIO()):
                self.assertEqual(audit.main([]), 2)
            run.assert_not_called()


if __name__ == "__main__":
    unittest.main()

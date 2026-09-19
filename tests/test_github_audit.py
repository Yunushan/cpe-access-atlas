# SPDX-License-Identifier: 0BSD
"""Audit transport, orchestration and hostile-evidence regressions; no GitHub I/O."""

from __future__ import annotations

import copy
import io
import json
import os
import subprocess
import unittest
from contextlib import ExitStack, redirect_stderr, redirect_stdout
from datetime import UTC, datetime
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace
from unittest.mock import patch

from scripts import check_github_production_settings as audit
from tests.test_github_policy import actions, branch_protection, environment_api, release_tags, tags
from tests.test_github_release import Api, fixture
from tests.test_repository_controls import _successful_workflow_responses

SHA = "a" * 40
REPOSITORY = "Yunushan/cpe-access-atlas"
CODEQL_ACCEPTED_ENDPOINT = "code-scanning/alerts?state=dismissed&ref=refs/heads/main&per_page=100"
ALERT_ENDPOINTS = (
    "dependabot/alerts?state=open&per_page=100",
    "code-scanning/alerts?state=open&per_page=100",
    "secret-scanning/alerts?state=open&per_page=100",
)


def accepted_codeql_alerts(
    *, ref: str = "refs/heads/main", commit: str = SHA
) -> list[dict[str, object]]:
    policy, error = audit._load_codeql_risk_policy()
    if error is not None or policy is None:
        raise AssertionError(error)
    return [
        {
            "number": item.alert_number,
            "state": "dismissed",
            "dismissed_reason": item.dismissed_reason,
            "dismissed_comment": item.dismissed_comment,
            "dismissed_at": item.dismissed_at,
            "dismissed_by": {"login": item.dismissed_by},
            "dismissal_approved_by": (
                {"login": item.dismissal_approved_by}
                if item.dismissal_approved_by is not None
                else None
            ),
            "rule": {
                "id": item.rule_id,
                "security_severity_level": item.security_severity_level,
            },
            "most_recent_instance": {
                "state": "dismissed",
                "ref": ref,
                "commit_sha": commit,
                "location": {"path": item.path},
            },
        }
        for item in policy.accepted_risks
    ]


def complete_fixture(*, require_independent_review: bool = False) -> dict[str, object]:
    from tests.test_github_policy import environment

    release_environment = environment(require_independent_review=require_independent_review)
    if require_independent_review:
        release_environment["protection_rules"][0]["reviewers"][0]["reviewer"]["id"] = 456
    owner = {"actor_type": "User", "actor_id": 123, "bypass_mode": "always"}
    quarantine, creator, immutable = (
        {"id": index, **ruleset} for index, ruleset in enumerate(release_tags(owner), start=1)
    )
    return {
        **fixture(),
        **actions(),
        **environment_api(release_environment).records,
        **_successful_workflow_responses(),
        "": {
            "full_name": REPOSITORY,
            "owner": {"id": 123, "type": "User"},
            "security_and_analysis": {
                "secret_scanning": {"status": "enabled"},
                "secret_scanning_push_protection": {"status": "enabled"},
            },
        },
        "dependency-graph/sbom": {"sbom": {"packages": []}},
        "automated-security-fixes": {"enabled": True, "paused": False},
        "private-vulnerability-reporting": {"enabled": True},
        "immutable-releases": {"enabled": True},
        f"git/matching-refs/tags/{audit._CANDIDATE_RELEASE_TAG}?per_page=100": [],
        "rulesets?per_page=100": [{"id": 1}, {"id": 2}, {"id": 3}],
        "rulesets/1": quarantine,
        "rulesets/2": creator,
        "rulesets/3": immutable,
        "rules/branches/main?per_page=100": [],
        "branches/main/protection": branch_protection(
            require_independent_review=require_independent_review
        ),
        "branches/main": {"protected": True},
        CODEQL_ACCEPTED_ENDPOINT: accepted_codeql_alerts(),
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


class LocalAuditSourceTests(unittest.TestCase):
    def _git(self, root: Path, *arguments: str) -> bytes:
        executable = audit.shutil.which("git")
        self.assertIsNotNone(executable)
        assert executable is not None
        completed = subprocess.run(  # noqa: S603 -- resolved Git executable, temp repository
            [executable, *arguments],
            cwd=root,
            capture_output=True,
            check=False,
            timeout=30,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr.decode(errors="replace"))
        return completed.stdout

    def _repository(self, root: Path) -> tuple[str, dict[str, bytes]]:
        contents: dict[str, bytes] = {}
        for relative in sorted(audit._REQUIRED_LOCAL_AUDIT_FILES):
            data = f"reviewed control: {relative}\n".encode()
            path = root.joinpath(*relative.split("/"))
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(data)
            contents[relative] = data
        self._git(root, "init", "--quiet")
        self._git(root, "add", "--all")
        self._git(
            root,
            "-c",
            "user.name=Audit Test",
            "-c",
            "user.email=audit@example.invalid",
            "commit",
            "--quiet",
            "-m",
            "fixture",
        )
        commit = self._git(root, "rev-parse", "HEAD").decode("ascii").strip()
        return commit, contents

    def _tree_record(
        self,
        path: str,
        *,
        mode: str = "100644",
        object_type: str = "blob",
        object_id: str = "a" * 40,
    ) -> bytes:
        return f"{mode} {object_type} {object_id}\t{path}\0".encode()

    def _git_stub(
        self,
        root: Path,
        overrides: dict[str, tuple[subprocess.CompletedProcess[bytes] | None, str | None]]
        | None = None,
    ) -> object:
        configured = overrides or {}

        def completed(
            stdout: bytes = b"", returncode: int = 0
        ) -> subprocess.CompletedProcess[bytes]:
            return subprocess.CompletedProcess([], returncode, stdout=stdout, stderr=b"")

        defaults = {
            "top": (completed(os.fsencode(root)), None),
            "head": (completed((SHA + "\n").encode("ascii")), None),
            "index": (completed(), None),
            "tree": (completed(b"synthetic tree"), None),
            "hash": (completed(("a" * 40 + "\n").encode("ascii")), None),
        }

        def run(
            _executable: str,
            _root: Path,
            arguments: list[str],
            *,
            input_data: bytes | None = None,
        ) -> tuple[subprocess.CompletedProcess[bytes] | None, str | None]:
            del input_data
            if arguments[:2] == ["rev-parse", "--show-toplevel"]:
                operation = "top"
            elif arguments[:2] == ["rev-parse", "--verify"]:
                operation = "head"
            else:
                operation = {"diff": "index", "ls-tree": "tree", "hash-object": "hash"}[
                    arguments[0]
                ]
            return configured.get(operation, defaults[operation])

        return run

    def test_local_git_failures_are_bounded_and_sanitized(self) -> None:
        failures = (
            (subprocess.TimeoutExpired("git", 30), "timed out"),
            (OSError(13, "private"), "OS error 13"),
            (OSError("private"), "unable to inspect"),
        )
        for failure, expected in failures:
            with (
                self.subTest(expected=expected),
                patch.object(audit.subprocess, "run", side_effect=failure),
            ):
                completed, error = audit._run_local_git("git", Path(), ["status"])
            self.assertIsNone(completed)
            self.assertIn(expected, error)
            self.assertNotIn("private", error)

    def test_local_control_tree_parser_rejects_every_unsafe_shape(self) -> None:
        complete = b"".join(
            self._tree_record(path) for path in sorted(audit._REQUIRED_LOCAL_AUDIT_FILES)
        )
        records, error = audit._parse_local_control_tree(complete)
        self.assertIsNone(error)
        self.assertEqual(set(records or ()), audit._REQUIRED_LOCAL_AUDIT_FILES)

        malformed = (
            b"not metadata\0",
            b"100644 blob " + b"a" * 40 + b"\t\xff\0",
        )
        unsafe = (
            self._tree_record("/absolute"),
            self._tree_record(""),
            self._tree_record("../escape"),
            self._tree_record("outside.txt"),
            self._tree_record(".github/workflows/ci.yml", object_type="tree"),
            self._tree_record(".github/workflows/ci.yml", mode="120000"),
            self._tree_record(".github/workflows/ci.yml", object_id="invalid"),
            self._tree_record(".github/workflows/ci.yml") * 2,
        )
        for raw in (*malformed, *unsafe):
            with self.subTest(raw=raw):
                records, error = audit._parse_local_control_tree(raw)
                self.assertIsNone(records)
                self.assertIsNotNone(error)

        records, error = audit._parse_local_control_tree(b"")
        self.assertIsNone(records)
        self.assertIn("missing required", error)
        with patch.object(audit, "_LOCAL_CONTROL_MAX_FILES", 0):
            records, error = audit._parse_local_control_tree(self._tree_record(".gitleaks.toml"))
        self.assertIsNone(records)
        self.assertIn("file-count", error)

    def test_local_control_inventory_rejects_unsafe_and_unbounded_files(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            inventory, error = audit._local_control_inventory(root)
            self.assertIsNone(inventory)
            self.assertIn(".github", error)

            (root / ".github").mkdir()
            inventory, error = audit._local_control_inventory(root)
            self.assertIsNone(inventory)
            self.assertIn("required local control", error)

            (root / ".gitleaks.toml").write_bytes(b"x")
            script = root / "scripts" / "check_github_production_settings.py"
            script.parent.mkdir()
            script.write_bytes(b"x")
            nested = root / ".github" / "nested"
            nested.mkdir()
            control = nested / "control.yml"
            control.write_bytes(b"x")

            original_is_symlink = Path.is_symlink
            with patch.object(
                Path,
                "is_symlink",
                lambda path: path.name == "control.yml" or original_is_symlink(path),
            ):
                inventory, error = audit._local_control_inventory(root)
            self.assertIsNone(inventory)
            self.assertIn("symbolic link", error)

            original_is_file = Path.is_file
            original_is_dir = Path.is_dir
            with (
                patch.object(
                    Path,
                    "is_file",
                    lambda path: False if path.name == "control.yml" else original_is_file(path),
                ),
                patch.object(
                    Path,
                    "is_dir",
                    lambda path: False if path.name == "control.yml" else original_is_dir(path),
                ),
            ):
                inventory, error = audit._local_control_inventory(root)
            self.assertIsNone(inventory)
            self.assertIn("not a regular file", error)

            with patch.object(Path, "rglob", side_effect=OSError("private")):
                inventory, error = audit._local_control_inventory(root)
            self.assertIsNone(inventory)
            self.assertIn("unable to inventory", error)

            with patch.object(audit, "_LOCAL_CONTROL_MAX_FILES", 0):
                inventory, error = audit._local_control_inventory(root)
            self.assertIsNone(inventory)
            self.assertIn("file-count", error)

    def test_local_source_rejects_invalid_git_and_checkout_identities(self) -> None:
        result, policy = audit._audit_local_control_checkout("invalid")
        self.assertEqual(result.status, audit.STATUS_FAIL)
        self.assertIsNone(policy)

        with TemporaryDirectory() as directory:
            root = Path(directory)
            missing = root / "missing"
            with patch.object(audit.shutil, "which", return_value="git"):
                result, policy = audit._audit_local_control_checkout(SHA, root=missing)
            self.assertEqual(result.status, audit.STATUS_UNVERIFIED)
            self.assertIsNone(policy)

            other = root / "other"
            other.mkdir()

            def completed(
                stdout: bytes = b"", returncode: int = 0
            ) -> subprocess.CompletedProcess[bytes]:
                return subprocess.CompletedProcess([], returncode, stdout=stdout, stderr=b"")

            cases = (
                ("top", (None, "synthetic top error"), "UNVERIFIED", "top error"),
                ("top", (completed(returncode=2), None), "UNVERIFIED", "root is unreadable"),
                (
                    "top",
                    (completed(os.fsencode(root / "absent")), None),
                    "UNVERIFIED",
                    "root identity",
                ),
                ("top", (completed(os.fsencode(other)), None), "FAIL", "repository root"),
                ("head", (None, "synthetic head error"), "UNVERIFIED", "head error"),
                ("head", (completed(returncode=2), None), "UNVERIFIED", "HEAD is unreadable"),
                ("head", (completed(b"\xff"), None), "UNVERIFIED", "HEAD identity"),
                ("head", (completed(b"not-a-sha"), None), "UNVERIFIED", "HEAD identity"),
                ("index", (None, "synthetic index error"), "UNVERIFIED", "index error"),
                ("index", (completed(returncode=2), None), "UNVERIFIED", "index is unreadable"),
                ("tree", (None, "synthetic tree error"), "UNVERIFIED", "tree error"),
                ("tree", (completed(returncode=2), None), "UNVERIFIED", "tree is unreadable"),
            )
            for operation, response, status, detail in cases:
                with (
                    self.subTest(operation=operation, detail=detail),
                    patch.object(audit.shutil, "which", return_value="git"),
                    patch.object(
                        audit,
                        "_run_local_git",
                        side_effect=self._git_stub(root, {operation: response}),
                    ),
                ):
                    result, policy = audit._audit_local_control_checkout(SHA, root=root)
                self.assertEqual(result.status, status)
                self.assertIn(detail, result.detail)
                self.assertIsNone(policy)

    def test_local_source_rejects_invalid_control_evidence_and_read_races(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            policy_path = root / ".github" / "codeql-accepted-risks.json"
            policy_path.parent.mkdir()
            policy_path.write_bytes(b"policy\n")
            tracked = {".github/codeql-accepted-risks.json": "a" * 40}

            with (
                patch.object(audit.shutil, "which", return_value="git"),
                patch.object(audit, "_run_local_git", side_effect=self._git_stub(root)),
                patch.object(audit, "_parse_local_control_tree", return_value=(None, "bad tree")),
            ):
                result, policy = audit._audit_local_control_checkout(SHA, root=root)
            self.assertEqual(result.status, audit.STATUS_FAIL)
            self.assertIn("bad tree", result.detail)
            self.assertIsNone(policy)

            with (
                patch.object(audit.shutil, "which", return_value="git"),
                patch.object(audit, "_run_local_git", side_effect=self._git_stub(root)),
                patch.object(audit, "_parse_local_control_tree", return_value=(tracked, None)),
                patch.object(
                    audit, "_local_control_inventory", return_value=(None, "bad inventory")
                ),
            ):
                result, policy = audit._audit_local_control_checkout(SHA, root=root)
            self.assertEqual(result.status, audit.STATUS_FAIL)
            self.assertIn("bad inventory", result.detail)
            self.assertIsNone(policy)

            many = {f".github/control-{index}.yml": "a" * 40 for index in range(10)}
            with (
                patch.object(audit.shutil, "which", return_value="git"),
                patch.object(audit, "_run_local_git", side_effect=self._git_stub(root)),
                patch.object(audit, "_parse_local_control_tree", return_value=(many, None)),
                patch.object(audit, "_local_control_inventory", return_value=(set(), None)),
            ):
                result, policy = audit._audit_local_control_checkout(SHA, root=root)
            self.assertEqual(result.status, audit.STATUS_FAIL)
            self.assertIn("and 2 more", result.detail)
            self.assertIsNone(policy)

            def run_with(
                *extra_patches: object,
                git_overrides: dict[
                    str, tuple[subprocess.CompletedProcess[bytes] | None, str | None]
                ]
                | None = None,
            ) -> tuple[audit.CheckResult, bytes | None]:
                with ExitStack() as stack:
                    stack.enter_context(patch.object(audit.shutil, "which", return_value="git"))
                    stack.enter_context(
                        patch.object(
                            audit,
                            "_run_local_git",
                            side_effect=self._git_stub(root, git_overrides),
                        )
                    )
                    stack.enter_context(
                        patch.object(
                            audit, "_parse_local_control_tree", return_value=(tracked, None)
                        )
                    )
                    stack.enter_context(
                        patch.object(
                            audit, "_local_control_inventory", return_value=(set(tracked), None)
                        )
                    )
                    for extra_patch in extra_patches:
                        stack.enter_context(extra_patch)
                    return audit._audit_local_control_checkout(SHA, root=root)

            with patch.object(audit, "_LOCAL_CONTROL_MAX_FILE_BYTES", 0):
                result, policy = run_with()
            self.assertEqual(result.status, audit.STATUS_FAIL)
            self.assertIn("file size", result.detail)
            self.assertIsNone(policy)

            with patch.object(audit, "_LOCAL_CONTROL_MAX_TOTAL_BYTES", 0):
                result, policy = run_with()
            self.assertEqual(result.status, audit.STATUS_FAIL)
            self.assertIn("size limit", result.detail)
            self.assertIsNone(policy)

            result, policy = run_with(patch.object(Path, "read_bytes", side_effect=OSError()))
            self.assertEqual(result.status, audit.STATUS_UNVERIFIED)
            self.assertIn("unreadable", result.detail)
            self.assertIsNone(policy)

            result, policy = run_with(patch.object(Path, "read_bytes", return_value=b""))
            self.assertEqual(result.status, audit.STATUS_FAIL)
            self.assertIn("changed while read", result.detail)
            self.assertIsNone(policy)

            completed = subprocess.CompletedProcess([], 2, stdout=b"", stderr=b"")
            result, policy = run_with(git_overrides={"hash": (completed, None)})
            self.assertEqual(result.status, audit.STATUS_UNVERIFIED)
            self.assertIn("unable to hash", result.detail)
            self.assertIsNone(policy)

            completed = subprocess.CompletedProcess([], 0, stdout=b"\xff", stderr=b"")
            result, policy = run_with(git_overrides={"hash": (completed, None)})
            self.assertEqual(result.status, audit.STATUS_FAIL)
            self.assertIn("differs from HEAD", result.detail)
            self.assertIsNone(policy)

            completed = subprocess.CompletedProcess([], 0, stdout=b"b" * 40, stderr=b"")
            result, policy = run_with(git_overrides={"hash": (completed, None)})
            self.assertEqual(result.status, audit.STATUS_FAIL)
            self.assertIn("differs from HEAD", result.detail)
            self.assertIsNone(policy)

    def test_local_source_binds_head_and_exact_control_blobs(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            commit, contents = self._repository(root)
            result, policy = audit._audit_local_control_checkout(commit, root=root)
            self.assertEqual(result.status, audit.STATUS_PASS)
            self.assertIn(commit, result.detail)
            self.assertIn("control files exactly match", result.detail)
            self.assertEqual(policy, contents[".github/codeql-accepted-risks.json"])

            result, policy = audit._audit_local_control_checkout("b" * 40, root=root)
            self.assertEqual(result.status, audit.STATUS_FAIL)
            self.assertIn("does not equal", result.detail)
            self.assertIsNone(policy)

        with patch.object(audit.shutil, "which", return_value=None):
            result, policy = audit._audit_local_control_checkout(SHA)
        self.assertEqual(result.status, audit.STATUS_UNVERIFIED)
        self.assertIsNone(policy)

    def test_local_source_rejects_modified_untracked_missing_and_staged_controls(self) -> None:
        mutations = ("modified", "untracked", "missing", "staged")
        for mutation in mutations:
            with self.subTest(mutation=mutation), TemporaryDirectory() as directory:
                root = Path(directory)
                commit, contents = self._repository(root)
                target = root / ".github" / "workflows" / "ci.yml"
                if mutation == "modified":
                    target.write_bytes(b"modified\n")
                elif mutation == "untracked":
                    (target.parent / "unexpected.yml").write_bytes(b"unexpected\n")
                elif mutation == "missing":
                    target.unlink()
                else:
                    target.write_bytes(b"staged\n")
                    self._git(root, "add", target.relative_to(root).as_posix())
                    target.write_bytes(contents[".github/workflows/ci.yml"])

                result, policy = audit._audit_local_control_checkout(commit, root=root)
                self.assertEqual(result.status, audit.STATUS_FAIL)
                self.assertIsNone(policy)


class GitHubAuditIntegrationTests(unittest.TestCase):
    def run_cli(
        self,
        records: dict[str, object],
        arguments: list[str] | None = None,
        *,
        local_evidence: tuple[audit.CheckResult, bytes | None] | None = None,
    ) -> tuple[int, str, str, set[str]]:
        """Run real CLI/adapter/orchestrator; replace only the external process."""

        requested: set[str] = set()

        def transport(command: list[str], **kwargs: object) -> SimpleNamespace:
            self.assertEqual(command[:4], ["synthetic-gh", "api", "--method", "GET"])
            self.assertFalse(kwargs.get("shell", False))
            prefix = f"repos/{REPOSITORY}"
            self.assertTrue(command[4] == prefix or command[4].startswith(prefix + "/"))
            endpoint = command[4].removeprefix(prefix).removeprefix("/")
            requested.add(endpoint)
            payload = records.get(endpoint, (None, "fixture endpoint unavailable"))
            if isinstance(payload, tuple):
                return SimpleNamespace(returncode=1, stdout="", stderr=payload[1])
            return SimpleNamespace(returncode=0, stdout=json.dumps(payload), stderr="")

        def verified_local_source(
            expected_commit: str,
        ) -> tuple[audit.CheckResult, bytes | None]:
            self.assertEqual(expected_commit, SHA)
            if local_evidence is not None:
                return local_evidence
            return (
                audit.CheckResult(
                    "local audit source",
                    audit.STATUS_PASS,
                    f"synthetic local controls match {expected_commit}",
                ),
                audit._CODEQL_RISK_POLICY_PATH.read_bytes(),
            )

        out, err = io.StringIO(), io.StringIO()
        with (
            patch.object(audit.shutil, "which", return_value="synthetic-gh"),
            patch.object(audit.subprocess, "run", side_effect=transport),
            patch.object(
                audit,
                "_audit_local_control_checkout",
                side_effect=verified_local_source,
            ),
            patch.dict(os.environ, {"GITHUB_REPOSITORY": REPOSITORY}),
            redirect_stdout(out),
            redirect_stderr(err),
        ):
            code = audit.main(["--json"] if arguments is None else arguments)
        return code, out.getvalue(), err.getvalue(), requested

    def test_complete_evidence_drives_every_audit_through_the_cli_and_get_adapter(self) -> None:
        code, output, error, requested = self.run_cli(complete_fixture())
        self.assertEqual(code, 0, output)
        results = json.loads(output)
        self.assertEqual(len(results), 20)
        self.assertEqual(len({item["name"] for item in results}), 20)
        self.assertTrue(all(item["status"] == audit.STATUS_PASS for item in results))
        self.assertIn(
            SHA, next(item for item in results if item["name"] == "local audit source")["detail"]
        )
        self.assertEqual(error, "")
        self.assertIn("releases/2/assets?per_page=100", requested)
        self.assertIn("immutable-releases", requested)
        self.assertIn("rulesets/2", requested)
        self.assertTrue(set(ALERT_ENDPOINTS).issubset(requested))
        self.assertIn(CODEQL_ACCEPTED_ENDPOINT, requested)
        code, output, error, _ = self.run_cli(complete_fixture(), ["--repo", REPOSITORY])
        self.assertEqual(code, 0)
        self.assertIn("[PASS", output)
        self.assertIn("current required checks", output)
        self.assertEqual(error, "")

    def test_codeql_risk_only_cli_binds_dismissals_to_the_exact_ref_and_commit(self) -> None:
        arguments = [
            "--json",
            "--codeql-risk-ref",
            "refs/heads/main",
            "--codeql-risk-commit",
            SHA,
        ]
        code, output, error, requested = self.run_cli(complete_fixture(), arguments)
        self.assertEqual((code, error), (0, ""), output)
        self.assertEqual(requested, {CODEQL_ACCEPTED_ENDPOINT})
        result = json.loads(output)
        self.assertEqual(
            [item["name"] for item in result],
            ["local audit source", "accepted CodeQL risks"],
        )
        self.assertTrue(all(item["status"] == audit.STATUS_PASS for item in result))

        for incomplete in (
            ["--codeql-risk-ref", "refs/heads/main"],
            ["--codeql-risk-commit", SHA],
            [
                "--codeql-risk-ref",
                "refs/heads/main",
                "--codeql-risk-commit",
                SHA,
                "--prepublication",
            ],
        ):
            with self.subTest(arguments=incomplete):
                code, _, error, requested = self.run_cli(complete_fixture(), incomplete)
                self.assertEqual(code, 2)
                self.assertTrue(error)
                self.assertEqual(requested, set())

    def test_unverified_local_source_blocks_full_and_risk_only_policy_audits(self) -> None:
        local_failure = (
            audit.CheckResult("local audit source", audit.STATUS_FAIL, "synthetic mismatch"),
            None,
        )
        modes = (
            None,
            [
                "--json",
                "--codeql-risk-ref",
                "refs/heads/main",
                "--codeql-risk-commit",
                SHA,
            ],
        )
        for arguments in modes:
            with self.subTest(arguments=arguments):
                code, output, error, requested = self.run_cli(
                    complete_fixture(),
                    arguments,
                    local_evidence=local_failure,
                )
                self.assertEqual((code, error), (1, ""), output)
                results = {item["name"]: item for item in json.loads(output)}
                self.assertEqual(results["local audit source"]["status"], audit.STATUS_FAIL)
                self.assertEqual(results["accepted CodeQL risks"]["status"], audit.STATUS_UNKNOWN)
                self.assertNotIn(CODEQL_ACCEPTED_ENDPOINT, requested)

    def test_accepted_codeql_risks_cover_happy_path_and_fail_closed_differences(self) -> None:
        now = datetime(2026, 9, 18, 20, tzinfo=UTC)

        def result(
            alerts: object,
            *,
            ref: str = "refs/heads/main",
            commit: str = SHA,
        ) -> audit.CheckResult:
            endpoint = f"code-scanning/alerts?state=dismissed&ref={ref}&per_page=100"
            return audit._audit_codeql_risk_acceptances(
                Api({endpoint: alerts}),
                REPOSITORY,
                expected_ref=ref,
                expected_commit=commit,
                now=now,
            )

        self.assertEqual(result(accepted_codeql_alerts()).status, audit.STATUS_PASS)
        tag_ref = "refs/tags/v0.4.0a5"
        self.assertEqual(
            result(accepted_codeql_alerts(ref=tag_ref), ref=tag_ref).status,
            audit.STATUS_PASS,
        )

        missing = accepted_codeql_alerts()[:-1]
        missing_result = result(missing)
        self.assertEqual(missing_result.status, audit.STATUS_FAIL)
        self.assertIn("missing on the exact ref", missing_result.detail)

        extra = accepted_codeql_alerts()
        unexpected = copy.deepcopy(extra[0])
        unexpected["number"] = 999
        extra.append(unexpected)
        extra_result = result(extra)
        self.assertEqual(extra_result.status, audit.STATUS_FAIL)
        self.assertIn("unexpected", extra_result.detail)

        for field, value in (("ref", "refs/heads/other"), ("commit_sha", "b" * 40)):
            mismatched = accepted_codeql_alerts()
            mismatched[0]["most_recent_instance"][field] = value
            mismatch_result = result(mismatched)
            self.assertEqual(mismatch_result.status, audit.STATUS_FAIL)
            self.assertIn("exact ref/commit", mismatch_result.detail)

        changed = accepted_codeql_alerts()
        changed[0]["dismissed_comment"] = "different assessment"
        changed_result = result(changed)
        self.assertEqual(changed_result.status, audit.STATUS_FAIL)
        self.assertIn("metadata differs", changed_result.detail)

        open_instance = accepted_codeql_alerts()
        open_instance[0]["most_recent_instance"]["state"] = "open"
        open_instance_result = result(open_instance)
        self.assertEqual(open_instance_result.status, audit.STATUS_FAIL)
        self.assertIn("exact instance is not dismissed", open_instance_result.detail)

        missing_instance = accepted_codeql_alerts()
        missing_instance[0]["most_recent_instance"] = None
        missing_instance_result = result(missing_instance)
        self.assertEqual(missing_instance_result.status, audit.STATUS_FAIL)
        self.assertIn("exact instance is not dismissed", missing_instance_result.detail)

        malformed_result = result([None])
        self.assertEqual(malformed_result.status, audit.STATUS_FAIL)
        self.assertIn("malformed", malformed_result.detail)

    def test_accepted_codeql_risk_expiry_and_policy_schema_are_fail_closed(self) -> None:
        policy, error = audit._load_codeql_risk_policy()
        self.assertIsNone(error)
        self.assertIsNotNone(policy)
        assert policy is not None
        expired = audit._evaluate_codeql_risk_acceptances(
            policy,
            accepted_codeql_alerts(),
            repository=REPOSITORY,
            expected_ref="refs/heads/main",
            expected_commit=SHA,
            now=datetime(2027, 3, 19, tzinfo=UTC),
        )
        self.assertTrue(any("expired" in item for item in expired))

        document = json.loads(audit._CODEQL_RISK_POLICY_PATH.read_text(encoding="utf-8"))
        parsed, parse_error = audit._parse_codeql_risk_policy(document)
        self.assertIsNotNone(parsed)
        self.assertIsNone(parse_error)
        malformed_documents = (
            None,
            {**document, "schema_version": 2},
            {**document, "repository": "not-a-repository"},
            {
                **document,
                "accepted_risks": [
                    {**document["accepted_risks"][0], "unexpected": True},
                ],
            },
            {
                **document,
                "accepted_risks": [
                    document["accepted_risks"][0],
                    document["accepted_risks"][0],
                ],
            },
        )
        for malformed in malformed_documents:
            with self.subTest(malformed=malformed):
                parsed, parse_error = audit._parse_codeql_risk_policy(malformed)
                self.assertIsNone(parsed)
                self.assertIsNotNone(parse_error)

    def test_empty_codeql_policy_passes_only_for_an_empty_high_risk_inventory(self) -> None:
        document = json.loads(audit._CODEQL_RISK_POLICY_PATH.read_text(encoding="utf-8"))
        document["accepted_risks"] = []
        policy, error = audit._parse_codeql_risk_policy(document)
        self.assertIsNone(error)
        self.assertIsNotNone(policy)
        assert policy is not None
        self.assertEqual(policy.accepted_risks, ())
        now = datetime(2026, 9, 18, tzinfo=UTC)
        self.assertEqual(
            audit._evaluate_codeql_risk_acceptances(
                policy,
                [],
                repository=REPOSITORY,
                expected_ref="refs/heads/main",
                expected_commit=SHA,
                now=now,
            ),
            (),
        )
        differences = audit._evaluate_codeql_risk_acceptances(
            policy,
            accepted_codeql_alerts(),
            repository=REPOSITORY,
            expected_ref="refs/heads/main",
            expected_commit=SHA,
            now=now,
        )
        self.assertEqual(len(differences), 2)
        self.assertTrue(all("unexpected" in item for item in differences))

        arguments = [
            "--json",
            "--codeql-risk-ref",
            "refs/heads/main",
            "--codeql-risk-commit",
            SHA,
        ]
        records = complete_fixture()
        records[CODEQL_ACCEPTED_ENDPOINT] = []
        with patch.object(audit, "_load_codeql_risk_policy_bytes", return_value=(policy, None)):
            code, output, error, requested = self.run_cli(records, arguments)
        self.assertEqual((code, error), (0, ""), output)
        self.assertEqual(requested, {CODEQL_ACCEPTED_ENDPOINT})
        result = next(
            item for item in json.loads(output) if item["name"] == "accepted CodeQL risks"
        )
        self.assertEqual(result["status"], audit.STATUS_PASS)
        self.assertIn("policy has no acceptances", result["detail"])

        records[CODEQL_ACCEPTED_ENDPOINT] = accepted_codeql_alerts()
        with patch.object(audit, "_load_codeql_risk_policy_bytes", return_value=(policy, None)):
            code, output, error, requested = self.run_cli(records, arguments)
        self.assertEqual((code, error), (1, ""), output)
        self.assertEqual(requested, {CODEQL_ACCEPTED_ENDPOINT})
        self.assertIn("unexpected dismissed high/critical", output)

    def test_accepted_codeql_policy_and_alert_parsers_reject_defensive_edge_cases(self) -> None:
        document = json.loads(audit._CODEQL_RISK_POLICY_PATH.read_text(encoding="utf-8"))

        top_level_cases = (
            {**document, "unexpected": True},
            {**document, "schema_version": True},
            {**document, "repository": 3},
            {**document, "repository": "owner/."},
            {**document, "accepted_risks": None},
            {**document, "accepted_risks": [document["accepted_risks"][0]] * 33},
            {**document, "accepted_risks": [None]},
        )
        for malformed in top_level_cases:
            with self.subTest(top_level=malformed):
                self.assertIsNotNone(audit._parse_codeql_risk_policy(malformed)[1])

        entry_cases: tuple[tuple[str, object], ...] = (
            ("alert_number", True),
            ("alert_number", 0),
            ("rule_id", None),
            ("dismissed_comment", ""),
            ("dismissed_comment", "x" * 1_001),
            ("rule_id", "INVALID"),
            ("security_severity_level", None),
            ("security_severity_level", "medium"),
            ("path", "/absolute"),
            ("path", "src/../secret"),
            ("path", "src//config.py"),
            ("dismissed_reason", "false positive"),
            ("dismissed_by", "bad_login"),
            ("dismissal_approved_by", 3),
            ("dismissal_approved_by", "bad_login"),
            ("dismissed_at", "not-a-date"),
            ("documentation", "README.md"),
            ("documentation", "docs/bad:name.md"),
            ("compensating_controls", []),
            ("compensating_controls", [""]),
            ("compensating_controls", ["duplicate", "duplicate"]),
            ("re_review_triggers", []),
            ("dismissed_at", "2026-99-18T16:59:24Z"),
            ("review_by", 3),
            ("review_by", "20270318"),
            ("review_by", "2026-09-17"),
        )
        for field, value in entry_cases:
            malformed = copy.deepcopy(document)
            malformed["accepted_risks"][0][field] = value
            with self.subTest(field=field, value=value):
                self.assertIsNotNone(audit._parse_codeql_risk_policy(malformed)[1])

        self.assertFalse(audit._valid_github_ref("invalid"))
        self.assertFalse(audit._valid_github_ref("refs/heads/a..b"))
        self.assertEqual(audit._policy_string_list("not-a-list"), None)
        self.assertEqual(audit._account_login({"login": 3}), (None, False))

        with TemporaryDirectory() as directory:
            root = Path(directory)
            paths = (
                root / "missing.json",
                root / "empty.json",
                root / "oversized.json",
                root / "invalid-utf8.json",
                root / "invalid-json.json",
            )
            paths[1].write_bytes(b"")
            paths[2].write_bytes(b"x" * (audit._CODEQL_POLICY_MAX_BYTES + 1))
            paths[3].write_bytes(b"\xff")
            paths[4].write_text("{", encoding="utf-8")
            for path in paths:
                with self.subTest(path=path.name):
                    self.assertIsNotNone(audit._load_codeql_risk_policy(path)[1])

        policy, error = audit._load_codeql_risk_policy()
        self.assertIsNone(error)
        assert policy is not None
        invalid_context = audit._evaluate_codeql_risk_acceptances(
            policy,
            None,
            repository="other/repository",
            expected_ref="invalid",
            expected_commit="invalid",
            now=datetime(2026, 9, 18, tzinfo=UTC),
        )
        self.assertGreaterEqual(len(invalid_context), 4)

        malformed_alerts = (
            [{"state": "open"}],
            [{"state": "dismissed", "rule": None}],
            [
                {
                    "state": "dismissed",
                    "rule": {"security_severity_level": {}},
                }
            ],
            [
                {
                    "state": "dismissed",
                    "rule": {"security_severity_level": "unknown"},
                }
            ],
            [
                {
                    "state": "dismissed",
                    "number": True,
                    "rule": {"security_severity_level": "high"},
                }
            ],
            [*accepted_codeql_alerts(), copy.deepcopy(accepted_codeql_alerts()[0])],
        )
        for alerts in malformed_alerts:
            with self.subTest(alerts=alerts):
                differences = audit._evaluate_codeql_risk_acceptances(
                    policy,
                    alerts,
                    repository=REPOSITORY,
                    expected_ref="refs/heads/main",
                    expected_commit=SHA,
                    now=datetime(2026, 9, 18, tzinfo=UTC),
                )
                self.assertTrue(differences)

        for ref, commit in (("invalid", SHA), ("refs/heads/main", "invalid")):
            result = audit._audit_codeql_risk_acceptances(
                Api({}),
                REPOSITORY,
                expected_ref=ref,
                expected_commit=commit,
                now=datetime(2026, 9, 18, tzinfo=UTC),
            )
            self.assertEqual(result.status, audit.STATUS_FAIL)

        with TemporaryDirectory() as directory:
            result = audit._audit_codeql_risk_acceptances(
                Api({}),
                REPOSITORY,
                expected_ref="refs/heads/main",
                expected_commit=SHA,
                now=datetime(2026, 9, 18, tzinfo=UTC),
                policy_path=Path(directory) / "missing.json",
            )
        self.assertEqual(result.status, audit.STATUS_FAIL)

    def test_accepted_codeql_risk_pagination_and_api_errors_are_fail_closed(self) -> None:
        now = datetime(2026, 9, 18, 20, tzinfo=UTC)
        first_page = [
            {
                "state": "dismissed",
                "rule": {"id": "py/example", "security_severity_level": "low"},
            }
        ] * 100
        records: dict[str, object] = {
            CODEQL_ACCEPTED_ENDPOINT: first_page,
            CODEQL_ACCEPTED_ENDPOINT + "&page=2": accepted_codeql_alerts(),
        }
        paginated = audit._audit_codeql_risk_acceptances(
            Api(records),
            REPOSITORY,
            expected_ref="refs/heads/main",
            expected_commit=SHA,
            now=now,
        )
        self.assertEqual(paginated.status, audit.STATUS_PASS)

        for failure_records in (
            {CODEQL_ACCEPTED_ENDPOINT: (None, "HTTP 403")},
            {
                CODEQL_ACCEPTED_ENDPOINT: first_page,
                CODEQL_ACCEPTED_ENDPOINT + "&page=2": (None, "HTTP 502"),
            },
        ):
            with self.subTest(failure_records=failure_records):
                result = audit._audit_codeql_risk_acceptances(
                    Api(failure_records),
                    REPOSITORY,
                    expected_ref="refs/heads/main",
                    expected_commit=SHA,
                    now=now,
                )
                self.assertEqual(result.status, audit.STATUS_UNVERIFIED)

    def test_prepublication_defers_only_candidate_release_instance_checks(self) -> None:
        records = complete_fixture()
        records["releases?per_page=100"][0]["immutable"] = False
        code, output, error, requested = self.run_cli(records, ["--json", "--prepublication"])
        self.assertEqual(code, 0, output)
        self.assertEqual(error, "")
        results = {item["name"]: item for item in json.loads(output)}
        self.assertEqual(results["published release"]["status"], audit.STATUS_DEFERRED)
        self.assertEqual(results["candidate absence"]["status"], audit.STATUS_PASS)
        self.assertEqual(results["release tag integrity"]["status"], audit.STATUS_PASS)
        self.assertTrue(
            all(
                item["status"] == audit.STATUS_PASS
                for name, item in results.items()
                if name != "published release"
            )
        )
        self.assertNotIn("releases/2/assets?per_page=100", requested)

        failing = copy.deepcopy(records)
        failing["private-vulnerability-reporting"] = {"enabled": False}
        code, output, _, _ = self.run_cli(failing, ["--json", "--prepublication"])
        self.assertEqual(code, 1, output)
        for immutability in ({"enabled": False}, {}, (None, "HTTP 403")):
            failing = copy.deepcopy(records)
            failing["immutable-releases"] = immutability
            code, output, _, _ = self.run_cli(failing, ["--json", "--prepublication"])
            self.assertEqual(code, 1, output)
        candidate_endpoint = f"git/matching-refs/tags/{audit._CANDIDATE_RELEASE_TAG}?per_page=100"
        candidate_ref = f"refs/tags/{audit._CANDIDATE_RELEASE_TAG}"
        for candidate_evidence in (
            [{"ref": candidate_ref}],
            [None],
            (None, "HTTP 403"),
        ):
            failing = copy.deepcopy(records)
            failing[candidate_endpoint] = candidate_evidence
            code, output, _, _ = self.run_cli(failing, ["--json", "--prepublication"])
            self.assertEqual(code, 1, output)
        failing = copy.deepcopy(records)
        failing["releases?per_page=100"].append({"tag_name": audit._CANDIDATE_RELEASE_TAG})
        code, output, _, _ = self.run_cli(failing, ["--json", "--prepublication"])
        self.assertEqual(code, 1, output)
        for release_evidence in ([None], (None, "HTTP 403")):
            failing = copy.deepcopy(records)
            failing["releases?per_page=100"] = release_evidence
            code, output, _, _ = self.run_cli(failing, ["--json", "--prepublication"])
            self.assertEqual(code, 1, output)

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
        for arguments in (["--json"], ["--repo", REPOSITORY]):
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

    def test_missing_workflow_fails_but_scheduled_pr_only_skip_is_allowed(self) -> None:
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
        self.assertEqual(result.status, audit.STATUS_PASS)

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

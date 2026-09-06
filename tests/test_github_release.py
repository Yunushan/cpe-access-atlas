# SPDX-License-Identifier: 0BSD
"""Release assurance from API-shaped evidence, without network calls or code execution."""

from __future__ import annotations

import base64
import copy
import unittest
from typing import Any

from scripts import check_github_production_settings as audit

MAIN, TAG, COMMIT = "a" * 40, "b" * 40, "c" * 40
ALPHA = "Development Status :: 3 - Alpha"
STABLE = "Development Status :: 5 - Production/Stable"


class Api:
    def __init__(self, records: dict[str, Any]) -> None:
        self.records = records
        self.calls: list[str] = []

    def get(self, path: str) -> tuple[Any, str | None]:
        self.calls.append(path)
        record = self.records.get(path, (None, "fixture endpoint unavailable"))
        return record if isinstance(record, tuple) else (record, None)


def content(text: str) -> dict[str, Any]:
    raw = text.encode("utf-8")
    return {
        "type": "file",
        "encoding": "base64",
        "size": len(raw),
        "content": base64.b64encode(raw).decode("ascii"),
    }


def metadata(version: str = "0.4.0", status: str = ALPHA) -> str:
    return f'''[project]
name = "cpe-access-atlas"
version = "{version}"
classifiers = ["{status}", "Programming Language :: Python :: 3.11",
"Programming Language :: Python :: 3.12", "Programming Language :: Python :: 3.13",
"Programming Language :: Python :: 3.14"]
'''


def fixture(version: str = "0.4.0", status: str = ALPHA) -> dict[str, Any]:
    names = [
        f"cpe_access_atlas-{version}-py3-none-any.whl",
        f"cpe_access_atlas-{version}.tar.gz",
        "SHA256SUMS",
    ]
    names += [
        f"cpe-access-atlas-v{version}-{system}-python{python}-sbom.cdx.json"
        for system in ("ubuntu-latest", "windows-latest", "macos-latest")
        for python in ("3.11", "3.12", "3.13", "3.14")
    ]
    return {
        "releases?per_page=100": [
            {
                "id": 2,
                "tag_name": f"v{version}",
                "draft": False,
                "prerelease": True,
                "published_at": "2026-09-05T10:00:00Z",
            }
        ],
        f"git/ref/tags/v{version}": {"object": {"type": "tag", "sha": TAG}},
        f"git/tags/{TAG}": {"object": {"type": "commit", "sha": COMMIT}},
        f"contents/pyproject.toml?ref={COMMIT}": content(metadata(version, status)),
        "releases/2/assets?per_page=100": [
            {
                "id": index,
                "name": name,
                "size": 123,
                "state": "uploaded",
                "digest": "sha256:" + "d" * 64,
            }
            for index, name in enumerate(names, start=1)
        ],
        "commits/main": {"sha": MAIN},
        f"compare/{MAIN}...{COMMIT}": {
            "status": "behind",
            "base_commit": {"sha": MAIN},
            "merge_base_commit": {"sha": COMMIT},
        },
    }


class GitHubReleaseTests(unittest.TestCase):
    def test_newest_published_prerelease_is_checked_instead_of_old_full_release(self) -> None:
        records = fixture()
        records["releases?per_page=100"] += [
            {
                "id": 1,
                "tag_name": "v0.3.0",
                "draft": False,
                "prerelease": False,
                "published_at": "2026-08-15T12:00:00Z",
            },
            {"id": 3, "tag_name": "v0.5.0", "draft": True, "published_at": None},
        ]
        api = Api(records)
        result = audit._audit_release(api)
        self.assertEqual(result.status, audit.STATUS_PASS)
        self.assertIn("v0.4.0", result.detail)
        self.assertIn("15 required asset", result.detail)
        self.assertNotIn("releases/latest", api.calls)
        self.assertIn(f"contents/pyproject.toml?ref={COMMIT}", api.calls)
        self.assertIn("independent verification", result.detail)
        self.assertEqual(audit._audit_release_tag(api).status, audit.STATUS_PASS)

    def test_all_release_pages_are_considered_and_timestamp_ties_are_deterministic(self) -> None:
        records = fixture()
        recent = records["releases?per_page=100"][0]
        records["releases?per_page=100"] = [{"draft": True} for _ in range(100)]
        records["releases?per_page=100&page=2"] = [recent]
        api = Api(records)
        self.assertEqual(audit._audit_release(api).status, audit.STATUS_PASS)
        self.assertIn("releases?per_page=100&page=2", api.calls)
        other = {**recent, "id": 1, "tag_name": "v0.3.0"}
        records["releases?per_page=100"] = [recent, other]
        self.assertEqual(audit._latest_published_release(Api(records))["id"], 2)

    def test_invalid_release_lists_and_unpublished_releases_never_pass(self) -> None:
        for records_value, expected in (
            ([], audit.STATUS_FAIL),
            ([{"draft": True}], audit.STATUS_FAIL),
            (None, audit.STATUS_UNKNOWN),
            ((None, "HTTP 403"), audit.STATUS_UNKNOWN),
            ([None], audit.STATUS_UNKNOWN),
            ([{}], audit.STATUS_UNKNOWN),
        ):
            result = audit._audit_release(Api({"releases?per_page=100": records_value}))
            self.assertEqual(result.status, expected)
        for key, value in (
            ("id", 0),
            ("id", True),
            ("draft", None),
            ("prerelease", None),
            ("published_at", None),
            ("published_at", "invalid"),
            ("published_at", "2026-09-05T10:00:00"),
        ):
            records = fixture()
            records["releases?per_page=100"][0][key] = value
            self.assertEqual(audit._audit_release(Api(records)).status, audit.STATUS_UNKNOWN)
        records = fixture()
        records["releases?per_page=100"] *= 2
        self.assertEqual(audit._audit_release(Api(records)).status, audit.STATUS_UNKNOWN)
        for tag in (None, "v0.4.0/../main", "latest", "v" + "1" * 129):
            records = fixture()
            records["releases?per_page=100"][0]["tag_name"] = tag
            self.assertEqual(audit._audit_release(Api(records)).status, audit.STATUS_FAIL)

    def test_release_must_have_an_annotated_tag_with_a_commit_target(self) -> None:
        for endpoint in ("git/ref/tags/v0.4.0", f"git/tags/{TAG}"):
            for value, expected in (
                ((None, "HTTP 403"), audit.STATUS_UNKNOWN),
                (None, audit.STATUS_UNKNOWN),
                ({"object": None}, audit.STATUS_UNKNOWN),
                ({"object": {"sha": []}}, audit.STATUS_UNKNOWN),
                ({"object": {"sha": "bad", "type": "tag"}}, audit.STATUS_UNKNOWN),
                ({"object": {"sha": TAG, "type": "tree"}}, audit.STATUS_FAIL),
            ):
                records = fixture()
                records[endpoint] = value
                self.assertEqual(audit._audit_release_tag(Api(records)).status, expected)

    def test_classification_and_version_come_from_the_inspected_release_commit(self) -> None:
        for version, status, prerelease, expected in (
            ("0.4.0", ALPHA, True, audit.STATUS_PASS),
            ("0.4.0", ALPHA, False, audit.STATUS_FAIL),
            ("0.4.0", STABLE, False, audit.STATUS_PASS),
            ("0.4.0", STABLE, True, audit.STATUS_FAIL),
            ("0.4.0rc1", STABLE, True, audit.STATUS_PASS),
            ("0.4.0rc1", STABLE, False, audit.STATUS_FAIL),
            ("0.4.0.dev1", STABLE, True, audit.STATUS_PASS),
        ):
            records = fixture(version, status)
            records["releases?per_page=100"][0]["prerelease"] = prerelease
            self.assertEqual(audit._audit_release(Api(records)).status, expected)
        records = fixture()
        records[f"contents/pyproject.toml?ref={COMMIT}"] = content(metadata("9.9.9"))
        self.assertEqual(audit._audit_release(Api(records)).status, audit.STATUS_FAIL)

    def test_dynamic_version_is_read_as_data_and_never_executed(self) -> None:
        text = metadata().replace('version = "0.4.0"', 'dynamic = ["version"]')
        text += '\n[tool.setuptools.dynamic.version]\nattr = "cpe_access_atlas.__version__"\n'
        records = fixture()
        records[f"contents/pyproject.toml?ref={COMMIT}"] = content(text)
        endpoint = f"contents/src/cpe_access_atlas/__init__.py?ref={COMMIT}"
        records[endpoint] = content('__version__ = "0.4.0"\n')
        self.assertEqual(audit._audit_release(Api(records)).status, audit.STATUS_PASS)
        for source in (
            '__version__ = input("must not execute")',
            '__version__ = "0.4.0"\n__version__ = "9.9.9"',
            "__version__ = [",
            "pass",
        ):
            records[endpoint] = content(source)
            self.assertEqual(audit._audit_release(Api(records)).status, audit.STATUS_UNKNOWN)
        records[endpoint] = content("__version__ = 42")
        self.assertEqual(audit._audit_release(Api(records)).status, audit.STATUS_FAIL)

    def test_incomplete_or_unsupported_metadata_is_not_silently_assumed(self) -> None:
        for text, expected in (
            ("invalid [", audit.STATUS_UNKNOWN),
            ("tool = {}", audit.STATUS_FAIL),
            (metadata().replace("cpe-access-atlas", "another-project"), audit.STATUS_FAIL),
            (
                metadata().replace('version = "0.4.0"', 'dynamic = ["version"]'),
                audit.STATUS_UNKNOWN,
            ),
            (metadata().replace('version = "0.4.0"', "dynamic = false"), audit.STATUS_UNKNOWN),
            (metadata().replace(ALPHA, "Development Status :: 7 - Inactive"), audit.STATUS_UNKNOWN),
            (metadata().replace(ALPHA, ALPHA + '", "' + STABLE), audit.STATUS_UNKNOWN),
            (metadata().replace("Python :: 3.14", "Python :: 3.16"), audit.STATUS_UNKNOWN),
            (
                '[project]\nname="cpe-access-atlas"\nversion="0.4.0"\nclassifiers=false',
                audit.STATUS_UNKNOWN,
            ),
            (
                '[project]\nname="cpe-access-atlas"\nversion="0.4.0"\nclassifiers=[1]',
                audit.STATUS_UNKNOWN,
            ),
            (
                f'[project]\nname="cpe-access-atlas"\nversion="0.4.0"\nclassifiers=["{ALPHA}"]',
                audit.STATUS_UNKNOWN,
            ),
        ):
            records = fixture()
            records[f"contents/pyproject.toml?ref={COMMIT}"] = content(text)
            self.assertEqual(audit._audit_release(Api(records)).status, expected)

    def test_contents_metadata_is_bounded_complete_and_validated(self) -> None:
        for field, value in (
            ("type", "dir"),
            ("encoding", "none"),
            ("size", True),
            ("size", 131073),
            ("content", "x" * 262145),
            ("content", None),
            ("content", "###"),
            ("content", "/w=="),
            ("size", 1),
        ):
            records = fixture()
            records[f"contents/pyproject.toml?ref={COMMIT}"][field] = value
            self.assertEqual(audit._audit_release(Api(records)).status, audit.STATUS_UNKNOWN)
        records = fixture()
        records[f"contents/pyproject.toml?ref={COMMIT}"] = (None, "HTTP 403")
        self.assertEqual(audit._audit_release(Api(records)).status, audit.STATUS_UNKNOWN)

    def test_one_bogus_filename_cannot_satisfy_all_artifact_requirements(self) -> None:
        records = fixture()
        records["releases/2/assets?per_page=100"] = [
            {
                "id": 1,
                "name": "not-a-package.whl.tar.gz.sbom.cdx.json.SHA256SUMS.txt",
                "size": 0,
                "state": "new",
            }
        ]
        result = audit._audit_release(Api(records))
        self.assertEqual(result.status, audit.STATUS_FAIL)
        self.assertIn("missing required", result.detail)
        self.assertIn("windows-latest-python3.11-sbom.cdx.json", result.detail)

    def test_every_environment_inventory_and_each_separate_distribution_is_required(self) -> None:
        baseline = fixture()
        self.assertEqual(len(baseline["releases/2/assets?per_page=100"]), 15)
        for index in range(15):
            records = copy.deepcopy(baseline)
            removed = records["releases/2/assets?per_page=100"].pop(index)
            result = audit._audit_release(Api(records))
            self.assertEqual(result.status, audit.STATUS_FAIL)
            self.assertIn(removed["name"], result.detail)

    def test_python315_release_requires_all_eighteen_assets_but_older_releases_do_not(self) -> None:
        records = fixture()
        text = metadata().replace(
            '"Programming Language :: Python :: 3.14"]',
            '"Programming Language :: Python :: 3.14", "Programming Language :: Python :: 3.15"]',
        )
        records[f"contents/pyproject.toml?ref={COMMIT}"] = content(text)
        self.assertEqual(audit._audit_release(Api(records)).status, audit.STATUS_FAIL)
        assets = records["releases/2/assets?per_page=100"]
        for index, system in enumerate(("ubuntu-latest", "windows-latest", "macos-latest"), 16):
            assets.append(
                {
                    **assets[0],
                    "id": index,
                    "name": f"cpe-access-atlas-v0.4.0-{system}-python3.15-sbom.cdx.json",
                }
            )
        result = audit._audit_release(Api(records))
        self.assertEqual(result.status, audit.STATUS_PASS)
        self.assertIn("18 required asset", result.detail)
        for index in range(15, 18):
            incomplete = copy.deepcopy(records)
            removed = incomplete["releases/2/assets?per_page=100"].pop(index)
            result = audit._audit_release(Api(incomplete))
            self.assertEqual(result.status, audit.STATUS_FAIL)
            self.assertIn(removed["name"], result.detail)
        self.assertEqual(audit._audit_release(Api(fixture())).status, audit.STATUS_PASS)

    def test_assets_must_be_nonempty_uploaded_distinct_and_digest_identified(self) -> None:
        for key, value in (
            ("size", 0),
            ("size", True),
            ("size", -1),
            ("state", "new"),
            ("digest", None),
            ("digest", "sha256:bad"),
        ):
            records = fixture()
            records["releases/2/assets?per_page=100"][0][key] = value
            self.assertEqual(audit._audit_release(Api(records)).status, audit.STATUS_FAIL)
        for key, value in (
            ("id", True),
            ("id", 0),
            ("id", 2),
            ("name", None),
            ("name", "SHA256SUMS"),
        ):
            records = fixture()
            records["releases/2/assets?per_page=100"][0][key] = value
            self.assertEqual(audit._audit_release(Api(records)).status, audit.STATUS_UNKNOWN)
        for assets in (None, [None], (None, "HTTP 403")):
            records = fixture()
            records["releases/2/assets?per_page=100"] = assets
            self.assertEqual(audit._audit_release(Api(records)).status, audit.STATUS_UNKNOWN)

    def test_reachability_uses_pinned_commits_not_a_second_mutable_tag_lookup(self) -> None:
        api = Api(fixture())
        self.assertEqual(audit._audit_release_tag(api).status, audit.STATUS_PASS)
        self.assertIn(f"compare/{MAIN}...{COMMIT}", api.calls)
        self.assertFalse(any(path.startswith("compare/main...") for path in api.calls))
        for key, value, expected in (
            ("status", "ahead", audit.STATUS_FAIL),
            ("status", "diverged", audit.STATUS_FAIL),
            ("status", None, audit.STATUS_UNKNOWN),
            ("base_commit", {"sha": "d" * 40}, audit.STATUS_UNKNOWN),
            ("merge_base_commit", {"sha": "d" * 40}, audit.STATUS_UNKNOWN),
        ):
            records = fixture()
            records[f"compare/{MAIN}...{COMMIT}"][key] = value
            self.assertEqual(audit._audit_release_tag(Api(records)).status, expected)
        for endpoint in ("commits/main", f"compare/{MAIN}...{COMMIT}"):
            for value in (None, {}, (None, "HTTP 403")):
                records = fixture()
                records[endpoint] = value
                self.assertEqual(
                    audit._audit_release_tag(Api(records)).status, audit.STATUS_UNKNOWN
                )

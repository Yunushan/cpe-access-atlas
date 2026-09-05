# GitHub production settings

The repository workflows provide the checks, but GitHub must enforce them at
the repository boundary. An administrator should apply these settings before
calling the project production-ready.

The release workflow now requires same-commit reusable CI and security workflows
before publishing, including the full OS/Python application-test matrix. That
dependency graph complements these repository controls; it does not protect
branches/tags, supply an independent approver, or verify downloaded releases.

## `main` branch

Protect `main` with:

- pull requests required before merge;
- at least one approving review, with stale approvals dismissed after new
  commits;
- code-owner review required;
- conversation resolution required;
- force-pushes and branch deletion disabled;
- no explicit users, teams, or apps allowed to bypass pull-request requirements;
- required checks for every CI matrix job, `package-smoke`, `dependency-audit`,
  `dependency-review`, CodeQL `analyze`, and secret-scan `gitleaks`.

The CI matrix checks are:

```text
test (ubuntu-latest, 3.11)
test (ubuntu-latest, 3.12)
test (ubuntu-latest, 3.13)
test (ubuntu-latest, 3.14)
test (windows-latest, 3.11)
test (windows-latest, 3.12)
test (windows-latest, 3.13)
test (windows-latest, 3.14)
test (macos-latest, 3.11)
test (macos-latest, 3.12)
test (macos-latest, 3.13)
test (macos-latest, 3.14)
```

## Releases and security

- Protect the `v*` tag pattern and restrict release-tag creation to
  maintainers.
  Use a creation ruleset with explicitly authorized creators, plus separate
  update/deletion rules with **no bypass actors**. A creator must not be able
  to replace or delete an existing release tag using the same bypass grant.
  The auditor trusts only the personal repository owner's explicit User ID
  for creation by default; it does not equate the write role with release
  authorization. A no-bypass creation rule denies all creation and must not
  be confused with an operational release-creation policy. The auditor requires
  a trusted creator who can satisfy every full-namespace creation ruleset; an
  empty or disjoint creator intersection fails. Additional narrow creation
  conditions require manual policy review instead of an assumed passing result.
- Enable the repository Dependency graph; the pull-request dependency-review
  check cannot run while it is disabled.
- Keep Dependabot alerts and security updates enabled; the repository also
  includes weekly update configuration for Python and GitHub Actions.
- Keep secret scanning and push protection enabled.
- Restrict Actions to the approved action allowlist or verified creators and
  require full-length commit-SHA pinning at the repository policy level; the
  workflow files pin their actions independently, but YAML alone cannot enforce
  this setting for future workflows.
- Configure private vulnerability reporting through GitHub Security Advisories
  or a monitored security address.
- Configure a `release` environment with required reviewers before allowing the
  release workflow's write permissions to publish artifacts.
  Require a nonempty reviewer list, prevent self-review, and disable
  administrator bypass. A real second eligible maintainer is needed for
  independent review; the PR's code-owner policy must also allow that reviewer
  to approve changes authored by the repository owner. Select deployment refs
  explicitly: allow tag pattern `v*` only, not unrestricted refs or branches.
- Publish a new version through the protected release process and independently
  verify its artifacts. The existing `v0.3.0` release predates these safeguards
  and must not be overwritten or treated as proof of the current working tree.

## Read-only evidence checks

Run the repository's read-only audit from an authenticated GitHub CLI session
with administrator-visible repository access:

```shell
python scripts/check_github_production_settings.py \
  --repo Yunushan/cpe-access-atlas
```

The command never writes to GitHub. It reports `PASS`, `FAIL`, or
`UNVERIFIED`; a missing administrator permission is intentionally not treated
as proof that a control is disabled. Use `--json` when retaining an audit
record.

The published-release check selects the newest nondraft release by publication
time, including prereleases. It resolves its annotated tag to a commit, reads
the declared package version and maturity classifiers at that immutable commit
without executing code, and compares main reachability using pinned commit IDs.
It requires distinct uploaded, nonempty wheel/sdist/checksum assets and runtime
SBOMs for every declared supported Python version on Linux, Windows, and macOS.
Required assets must have GitHub SHA-256 digest metadata. Missing, duplicated,
misnamed, or incomplete inventory records do not pass.

This is an **inventory metadata check**, not verification of downloaded bytes
or cryptographic provenance. A passing audit is not a production certificate:
follow the independent published-artifact checks in `docs/release.md` as well.

The audit reads full ruleset details and effective rules for `main`, rather
than interpreting ruleset-list summaries as policies. It checks Dependency
Graph through its SBOM endpoint and Dependabot updates through their dedicated
endpoint; absent security metadata remains unverified. Current job results
come from the latest execution and attempt of the expected workflow files on
`main`, so another workflow's matching job name or an older passing run cannot
satisfy the gate. Inaccessible rule-bypass details cannot establish enforcement.
Malformed workflow identities and inconsistent or changing pagination totals
remain unverified. The CLI accepts only an `OWNER/REPO` identifier and explicitly
uses GET requests. Alert inventories are paginated; their output contains counts
only, never secret-bearing payload fields, source excerpts, or paths. Review alert
details through an authorized confidential channel.

A missing or inaccessible classic branch-protection endpoint does not mean
rulesets are absent. When effective rules are present but incomplete, the audit
reports that distinction and keeps overall enforcement UNVERIFIED unless it
can independently establish the complete baseline from available controls.

Transport failures are also summarized from safe status metadata, not copied
from raw stdout/stderr. GitHub rate-limit messages can contain the caller's
public IP, and local launch errors can contain private paths. The audit reports
controlled authentication/access/server/transport diagnostics without those
details. A recognized HTTP 429 or rate-limit HTTP 403 stops new requests for the
rest of that audit; successfully fetched evidence remains cached, while missing
evidence stays UNVERIFIED. It does not retry in a loop or assume that throttled
checks pass. Start a new audit after resolving authentication or waiting for the
rate limit to reset; raw CLI diagnostics should be inspected only privately.

The Actions audit also reads `actions/permissions/selected-actions`. Merely
selecting the `selected` mode is insufficient: repository wildcards such as
`*` or `owner/*` are rejected. Explicit patterns are limited to the action
repositories reviewed in the script, while the GitHub-owned/verified-creator
settings remain visible policy choices. New workflow action repositories need
explicit review and an update to that allowlist. Missing policy details are
unverified, not implicitly passing. Private vulnerability reporting is audited
through its own endpoint rather than assumed available from an advisory link.

From an authenticated GitHub CLI session with repository-admin visibility:

```shell
gh api repos/Yunushan/cpe-access-atlas/branches/main/protection
gh api repos/Yunushan/cpe-access-atlas/rulesets
gh api repos/Yunushan/cpe-access-atlas/releases
gh api repos/Yunushan/cpe-access-atlas/tags
gh api repos/Yunushan/cpe-access-atlas
```

The final audit should show branch protection or an enforced ruleset, at least
one published release, a protected release-tag policy, enabled Dependabot
security updates, restricted Actions permissions with SHA-pinning enforcement,
zero open CodeQL alerts, and successful CI, security, CodeQL, package-smoke,
dependency-audit, and secret-scan check runs for the merged commit. On a push,
the dependency-review check may be skipped because it is pull-request-only;
the branch policy must still require it for pull requests. The latest release
must also use an annotated tag whose commit is reachable from `main`.

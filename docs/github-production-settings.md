# GitHub production settings

The repository workflows provide the checks, but GitHub must enforce them at
the repository boundary. An administrator should apply these settings before
calling the project production-ready.

## `main` branch

Protect `main` with:

- pull requests required before merge;
- at least one approving review, with stale approvals dismissed after new
  commits;
- code-owner review required;
- conversation resolution required;
- force-pushes and branch deletion disabled;
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
- Publish and verify the first release from a protected `v0.3.0` tag.

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

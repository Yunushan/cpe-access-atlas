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
  `dependency-review`, and CodeQL `analyze`.

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
- Configure private vulnerability reporting through GitHub Security Advisories
  or a monitored security address.
- Configure a `release` environment with required reviewers before allowing the
  release workflow's write permissions to publish artifacts.
- Publish and verify the first release from a protected `v0.2.0` tag.

## Read-only evidence checks

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
security updates, and successful CI, security, and CodeQL runs for the merged
commit.

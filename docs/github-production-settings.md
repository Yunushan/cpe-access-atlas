# GitHub production settings

The repository workflows provide the checks, but GitHub must enforce them at
the repository boundary. The owner has selected a **solo-maintainer policy**:
another person's approval is not a mandatory merge or release gate. The owner
can commit, push a feature branch, open a PR, and merge it after automated checks
pass and conversations are resolved. Direct pushes to protected `main` remain
restricted; this policy does not grant a bypass of CI or destructive protections.

The release workflow now requires same-commit reusable CI and security workflows
before publishing, including the full OS/Python application-test matrix. That
dependency graph complements these repository controls; it does not protect
branches/tags or verify downloaded releases. Independent review is useful when
available, but its absence is not a solo-maintainer policy failure.

## `main` branch

Protect `main` with:

- pull requests required before merge;
- zero required approving reviews;
- code-owner and last-push approval requirements disabled, with no mandatory
  team reviewers; CODEOWNERS may still identify the owner without blocking merges;
- stale approvals dismissed if an optional review becomes outdated;
- conversation resolution required;
- force-pushes and branch deletion disabled;
- no explicit users, teams, or apps allowed to bypass pull-request requirements;
- required DCO `check-signoff` plus every CI matrix job,
  `cross-platform-artifact-reproducibility`, `package-smoke`,
  `dependency-audit (3.11)`, `dependency-audit (3.14)`, `dependency-review`,
  CodeQL `analyze`, and secret-scan `gitleaks`.
  Bind every required check to the GitHub Actions source, rather than accepting
  an unbound legacy context with the same name. The read-only audit verifies
  GitHub Actions app/integration ID `15368`; another app cannot satisfy a
  protected check merely by copying its display name. That app ID identifies
  GitHub Actions globally, not one immutable workflow file, so branch protection
  and review of `.github/workflows/` plus `.github/dco-signoff.awk` changes remain
  part of the trust boundary.

The CI matrix checks are:

```text
test (ubuntu-latest, 3.11)
test (ubuntu-latest, 3.12)
test (ubuntu-latest, 3.13)
test (ubuntu-latest, 3.14)
test (ubuntu-latest, 3.15)
test (windows-latest, 3.11)
test (windows-latest, 3.12)
test (windows-latest, 3.13)
test (windows-latest, 3.14)
test (windows-latest, 3.15)
test (macos-latest, 3.11)
test (macos-latest, 3.12)
test (macos-latest, 3.13)
test (macos-latest, 3.14)
test (macos-latest, 3.15)
cross-platform-artifact-reproducibility
```

When adopting the Python 3.15 matrix and artifact-equality gate, first run those
jobs on the proposed branch, then add their exact names to the required checks
without removing the existing checks or DCO sign-off gate. Editing workflow YAML
does not update GitHub branch rules. The read-only audit reports missing
requirements until an authorized administrator updates the repository settings.

## Releases and security

- Enable **release immutability** in the repository's Releases settings before
  creating the next protected release tag. Tag rules protect Git references;
  they do not prevent release-asset replacement. Immutable releases protect
  both the published assets and their associated tag. The published-release
  audit requires the newest release's `immutable` field to be exactly `true`;
  `false` fails, while missing or malformed evidence stays `UNVERIFIED`.
  Enabling the setting applies to future publications and does not establish
  immutability for an existing release. Preserve older artifacts and publish
  a new version through the protected process. See
  [GitHub's release immutability guidance](https://docs.github.com/en/code-security/concepts/supply-chain-security/immutable-releases).
- For the next candidate, `v0.4.0a6`, rotate the live tag rules and release
  environment in the order below before creating its tag. The rules shown
  here are the required candidate state, not a claim that the live settings
  have already been changed.
- Protect release-tag creation with three deliberately separate rulesets:
  1. a rotating quarantine with `include: refs/tags/v*`, only
     `exclude: refs/tags/v0.4.0a6`, the creation restriction, and **no bypass
     actors**;
  2. an exact-candidate rule with only `include: refs/tags/v0.4.0a6`, no
     exclusions, the creation restriction, and the personal repository owner
     as the only always-bypass actor; and
  3. a full `refs/tags/v*` update/deletion restriction with no exclusions and
     **no bypass actors**.

  GitHub's creation restriction permits only bypass actors to create matching
  refs. Consequently, the first rule denies every noncandidate release tag,
  including tags aimed at historical workflows; the second makes the exact
  reviewed candidate operational; and the third prevents anyone, including
  the creator, from moving or deleting a release tag. The auditor trusts only
  the personal repository owner's explicit User ID for candidate creation. It
  does not equate a repository role with release authorization and does not
  infer protection from malformed, partial, or additional creation patterns.
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
- Configure a `release` environment without mandatory reviewers. The owner
  authorizes publication by creating the protected release tag after checking
  the candidate. Disable administrator bypass and select exactly the current
  candidate tag (`v0.4.0a6`), not `v*`, unrestricted refs, or branches. Update
  that one policy only when the package version advances to a reviewed candidate.
  This exact-tag boundary prevents a tag created later at an older commit from
  running that commit's historical publishing workflow with release credentials.
  It is defense in depth; the creation quarantine remains mandatory because at
  least one historical publisher did not reference the environment at all.
  Full same-commit CI, dependency/security checks, packaging validation, and
  artifact provenance remain required by the workflow.
- Publish a new version through the protected release process and independently
  verify its artifacts. Every existing release through `v0.4.0a3` predates these
  safeguards, reports `immutable: false`, and must not be overwritten or treated
  as proof of the current working tree.

## Read-only evidence checks

Run the repository's read-only audit from an authenticated GitHub CLI session
with administrator-visible repository access, using a Git checkout whose `HEAD`
is the exact current remote `main` commit. The complete local `.github` tree,
`.gitleaks.toml`, and the audit script must be clean, regular files whose bytes
match their `HEAD` blobs; do not run the retained evidence check from a feature
branch, an older checkout, a copied script, or a source archive:

```shell
python scripts/check_github_production_settings.py \
  --repo Yunushan/cpe-access-atlas
```

The command never writes to GitHub. It reports `PASS`, `FAIL`, or
`UNVERIFIED`; prepublication mode also reports one explicit `DEFERRED` result.
A missing administrator permission is intentionally not treated as proof that a
control is disabled. The `local audit source` result prints the full matching
commit and the number of byte-matched control files. A different local `HEAD`,
staged control change, modified/deleted control, extra local `.github` file,
symbolic link, unreadable Git evidence, or blob mismatch fails closed. The
accepted-risk audit parses the already captured verified policy bytes rather
than reopening a mutable path. Use `--json` when retaining an audit record.

The default audit uses the solo-maintainer policy and labels branch/release
results accordingly in both text and JSON. It requires explicit zero-approval,
no-code-owner, and no-last-push-approval settings; unreadable evidence or another
effective ruleset's approval requirement cannot silently pass. The release
environment must have no required-reviewer rule while retaining its exact-current-
candidate deployment policy and disabled administrator bypass. A broad `v*`
deployment rule fails the audit. Every mode also requires administrator-visible
`immutable-releases` evidence with `enabled: true`; prepublication mode defers
the not-yet-created candidate release instance, not this repository setting or
the integrity of the latest existing release tag. It also requires the exact
candidate to be absent from both tags and releases so a premature tag or draft
cannot be mistaken for a valid prepublication state. The script remains read-only.

When rotating from one candidate to the next, avoid a transient open namespace:

1. add the next exact trusted-creator rule while the next tag is still covered
   by the zero-bypass quarantine;
2. change the release environment's sole allowed tag to the next exact tag while
   that tag is still quarantined;
3. change the quarantine's single exclusion to the next exact tag;
4. remove the prior candidate's exact creator rule; and
5. run the prepublication audit successfully before creating the tag.

If a candidate is abandoned, rotate the controls first and never create its tag.
Already-created release tags are unaffected by adding a creation restriction and
remain protected by the separate no-bypass update/deletion rule.
After publishing, rerun the same command without `--prepublication`; all release
instance, tag, and repository checks must then report `PASS`.

If a second eligible maintainer becomes available and the owner chooses a team
policy, enable approving/code-owner reviews and independent release reviewers,
then use the optional stricter audit:

```shell
python scripts/check_github_production_settings.py \
  --repo Yunushan/cpe-access-atlas --require-independent-review
```

That profile requires approving/code-owner PR review and a nonempty release
reviewer list with self-review prevention. It is not the current mandatory
baseline, and neither profile certifies device compatibility or removes known
security limitations. GitHub documents [zero-approval PR rules](https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-rulesets/available-rules-for-rulesets).

The published-release check selects the newest nondraft release by publication
time, including prereleases. It resolves its annotated tag to a commit, reads
the declared package version and maturity classifiers at that immutable commit
without executing code, and compares main reachability using pinned commit IDs.
It requires confirmed release immutability, distinct uploaded, nonempty
wheel/sdist/checksum assets and runtime SBOMs for every declared supported Python
version on Linux, Windows, and macOS.
Required assets must have GitHub SHA-256 digest metadata. Missing, duplicated,
misnamed, or incomplete inventory records do not pass.

This is an **inventory metadata check**, not verification of downloaded bytes
or cryptographic provenance. A passing audit is not a production certificate:
follow the published-artifact checks in `docs/release.md` as well. The owner can
perform those checks in a clean environment; a second person is not required.

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

An empty **open** CodeQL inventory does not mean CodeQL found no security
issue. The repository currently has two explicit high-severity compatibility
risk acceptances, recorded by immutable alert number and exact GitHub dismissal
metadata in `.github/codeql-accepted-risks.json`. The audit separately fetches
all dismissed alerts on the exact `main` ref, requires the high/critical set to
match that policy with no additions or omissions, binds each instance to the
current commit, and fails after the earliest `review_by` date. A fixed alert is
also intentionally a policy failure until its now-stale acceptance is removed.
Transport or pagination failures remain UNVERIFIED. This control makes the
residual risk visible; it does not reclassify the vendor cryptography as safe.
If all accepted findings become fixed, remove their stale entries: an empty
`accepted_risks` list passes only when the exact-ref dismissed high/critical
inventory is also empty. Any actual high/critical dismissal then remains an
unexpected finding and fails closed.

From an authenticated GitHub CLI session with repository-admin visibility:

```shell
gh api repos/Yunushan/cpe-access-atlas/branches/main/protection
gh api repos/Yunushan/cpe-access-atlas/rulesets
gh api repos/Yunushan/cpe-access-atlas/immutable-releases
gh api repos/Yunushan/cpe-access-atlas/releases
gh api repos/Yunushan/cpe-access-atlas/tags
gh api repos/Yunushan/cpe-access-atlas
```

The final audit should show branch protection or an enforced ruleset, at least
one published release, a protected release-tag policy, enabled Dependabot
security updates, restricted Actions permissions with SHA-pinning enforcement,
zero open CodeQL alerts, and successful CI, security, CodeQL, package-smoke,
both dependency-audit matrix jobs, and secret-scan check runs for the merged commit.
The separate `accepted CodeQL risks` result must also pass. Review or replace
each acceptance before its policy expiry, and rerun the audit whenever the
protocol, compatibility evidence, compensating controls, or alert fingerprint
changes.
The latest CI, Security audit, and CodeQL executions must be no more than eight
days old (with five minutes of clock-skew tolerance), so a disabled weekly
schedule cannot leave unchanged `main` looking green indefinitely. DCO
`check-signoff` and dependency review are pull-request-only, so they have no
main-push execution; branch policy must still require both for pull requests.
The latest release
must also be immutable and use an annotated tag whose commit is reachable from
`main`.

Checking the repository's `immutable-releases` setting requires Administration
read permission. The release workflow keeps its existing restricted token
permissions and verifies the published release's `immutable` result through the
release metadata endpoint. This is a publication postcondition, not a substitute
for the administrator's prepublication settings check; an inaccessible or false
postcondition fails the workflow without deleting or replacing published assets.

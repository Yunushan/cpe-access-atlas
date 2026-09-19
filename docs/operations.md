# Operational resilience and incident response

This project is a local command-line tool. It has no hosted control plane,
background service, central database, remote telemetry, or project-operated copy
of a user's device data. Operational assets are the reviewed Git history,
repository settings, workflows, immutable releases, attestations, checksums,
SBOMs, and the maintainer accounts allowed to change or publish them.

The project currently has one maintainer, no on-call rotation, and no guaranteed
response, restoration, recovery-time, or recovery-point objective. This runbook
does not create an SLA or claim that a backup, notification route, recovery
operator, or drill exists. If the maintainer is unavailable, repository control
is uncertain, or the checks below cannot be completed, publication stays frozen
and no new production-support claim may be made.

## Sources of truth and trust boundaries

- A reviewed full Git commit identifies source. A branch name, mutable checkout,
  or downloaded archive by itself does not.
- A supported publication must be an immutable GitHub release whose annotated
  tag, assets, checksums, attestations, and commit pass the procedures in
  [the release guide](release.md).
- [The production-settings audit](github-production-settings.md) describes and
  checks the external GitHub controls. A source clone cannot restore or prove
  branch rules, tag rules, the release environment, security features, or
  account access.
- Private configuration exports, device logs, credentials, certificates,
  subscriber data, and unsanitized incident evidence are never repository
  recovery assets. They stay outside Git and GitHub under the user's control.
- A local clone, cache, workflow artifact, or previous release is not called a
  recovery copy until its identity and integrity have been verified and an
  actual restoration exercise has succeeded.

## Impact classification

Classification sets containment scope; it makes no response-time promise.

| Impact | Examples | Initial posture |
|---|---|---|
| Critical | Suspected malicious release; publishing-account, workflow, tag, or attestation compromise; public exposure of credentials or private device data | Freeze publication and affected use; preserve evidence; treat the affected trust boundary as compromised |
| High | Exploitable defect in the latest release; required security control disabled; provenance, repository settings, or release integrity cannot be established | Freeze publication and support claims until scope and a known-good boundary are established |
| Routine | Non-security CLI, packaging, documentation, or catalog defect with intact release and data boundaries | Track through the normal issue and protected-PR process |

When evidence is incomplete, use the more restrictive posture. Device damage,
loss of connectivity, exposed management access, or leaked ISP credentials is
Critical even when the software repository itself is intact.

## Declare and contain

Anyone may report a suspected security incident through the confidential route
in [the security policy](../SECURITY.md). The sole maintainer currently owns
incident declaration, publication authorization, and closure. If that person or
their trusted account is unavailable, there is no substitute incident commander:
leave release and support activity frozen rather than inferring authorization.

For a suspected incident:

1. Start a private case record with a unique identifier, UTC discovery time,
   reporter channel, affected versions/commits, observed impact, and decisions.
   Do not copy secrets, raw device exports, exploit payloads, or reporter identity
   into a public issue, commit, workflow log, or release note.
2. Stop new tags and releases. Do not delete or move an immutable release, replace
   an asset, reuse a version, rewrite shared history, or publish from an
   unreviewed workstation merely to restore service quickly.
3. Preserve the minimum necessary workflow/run identifiers, audit-log events,
   release metadata, commit IDs, checksums, attestations, and timestamps. Store
   sensitive originals outside the repository in encrypted, access-controlled
   storage; publish only a deliberately sanitized record when disclosure is safe.
4. Recover or revoke affected GitHub sessions, tokens, keys, applications, and
   environment access through their authoritative providers. Do not record
   recovery codes, token values, or private keys in the case summary.
5. If device or subscriber material may have escaped, assume it is exposed:
   isolate the affected local network where necessary, invalidate router-side
   sessions, and rotate affected router/ISP credentials through their normal
   administration channels. Repository cleanup cannot revoke a disclosed secret.
6. Do not install, import, execute, or use an artifact whose source or integrity
   is uncertain. Preserve it as evidence only in an isolated location.

## Establish the compromise boundary

Determine which identities and artifacts can still be trusted before recovery:

- resolve the reviewed source commit independently of a mutable tag;
- inspect protected-branch, protected-tag, release-environment, Actions,
  dependency, secret-scanning, private-reporting, and CodeQL settings;
- compare workflow identities, attempts, commit IDs, actor and audit-log events;
- verify every release asset against the authenticated checksum inventory and
  its constrained GitHub attestation;
- inspect accepted-risk policy and open/dismissed alert inventories on the exact
  affected ref;
- identify the earliest potentially affected commit, workflow run, credential,
  release, and user-visible operation; and
- explicitly record which prior attestations or verification results are not
  trusted. Absence of evidence is not a clean result.

Use `scripts/check_github_production_settings.py` only from a recovered,
authenticated environment with the required read visibility and an exact
checkout of the audited remote `main` commit. Its local `.github` control tree,
`.gitleaks.toml`, audit script, index, and working bytes must match that commit;
do not substitute a copied or older checker. Retain the explicit `local audit
source` commit/file-count evidence. An `UNVERIFIED`, `FAIL`, stale, or incomplete
result keeps publication frozen.

## Recover by incident type

| Incident | Recovery action | Required validation before unfreezing |
|---|---|---|
| Software or dependency defect | Prepare a reviewed fix on a protected branch and issue a new version. Consumers should point scripts or wrappers back to a previously independently verified side-by-side environment if one exists. | Complete CI/security/release gates, clean installs, catalog validation, and published-artifact verification |
| Source or workflow compromise | Restore through a reviewed commit and protected PR from a verified source; do not hide the event by rewriting shared history. | Review the full affected history and workflow trust boundary, then rerun every required workflow on the recovered `main` commit |
| Malicious or unverifiable release | Add a prominent warning to the affected release notes, tell consumers to stop using it, and publish any correction under a new version. Do not replace assets or move/delete its immutable tag. | Verify the new release's provenance, checksums, inventories, clean installs, repository settings, and immutable postcondition |
| GitHub account or repository-setting compromise | Recover the account with GitHub, revoke affected credentials, and reconstruct controls from the documented desired state. | Administrator-visible production-settings audit returns only `PASS`; a second private-reporting test and protected publication exercise succeed |
| Private device-data or credential disclosure | Restrict further access, coordinate confidentially with the affected owner/provider, invalidate sessions, and rotate every affected credential or certificate where possible. | The exposed values are no longer accepted, public copies are handled through the relevant provider, and sanitized disclosure does not repeat them |
| Repository or workstation loss | Recover only from a separately retained, verified full-history copy and separately retained release evidence. Recreate no protected tag or release namespace casually. | Commit identities, full history, required source tests, reproducible artifacts, release evidence, and all external repository controls are reverified |

If no previously verified package environment or recovery copy exists, say so.
That condition cannot be repaired by labeling a convenient artifact “known good.”

## Communication and closure

Keep vulnerability assessment private until coordinated disclosure is safe.
For an affected public release, make its editable release notes clearly identify
the impact, affected versions, stop-use or rollback guidance, and replacement
version without exposing reporter or device data. Update `SECURITY.md`,
`SUPPORT.md`, and the changelog when their supported-version statements change.

Close an incident only after containment and recovery are verified. Retain a
sanitized record containing:

- incident identifier, impact, UTC timeline, and affected versions/commits;
- the established compromise boundary and affected credential classes;
- containment, recovery, and consumer-communication decisions;
- exact verification commands and non-sensitive results;
- unresolved risks, owners, and review conditions; and
- root cause and corrective actions.

Sensitive source material remains in its separately controlled case store only
as long as necessary for response, legal, or coordinated-disclosure needs. This
repository does not claim a fixed retention guarantee.

## Operational signals

Weekly CI, dependency-audit, and CodeQL workflows exercise the unchanged default
branch. Pushes and pull requests also run the required validation and secret
scan, and CI, CodeQL, security audit, and secret scan can be dispatched manually
for recovery verification. The production-settings auditor rejects stale CI,
dependency-audit, or CodeQL evidence after eight days.

GitHub workflow status and account notifications are signals, not an on-call or
paging service. Scheduled workflows can be delayed or disabled externally, and
notification delivery depends on account settings. Before a release and during
incident recovery, inspect the current workflow attempts and run the
administrator-visible audit; do not infer health from silence.

The CLI intentionally sends no project telemetry. User-visible output, exit
status, local artifacts, and explicitly retained sanitized evidence are the only
application-level observations.

## Recovery exercise gate

The following is a requirement, not a claim that an exercise has occurred. Before
calling a release production-supported, retain a dated, sanitized record showing:

1. confidential reporting was reachable without exposing report content;
2. the maintainer could recover repository access and revoke a synthetic test
   credential without recording secret values;
3. a separately stored, verified source/release evidence set was restored into a
   clean location and its commit, checksums, and attestations were reverified;
4. the full required workflows were dispatched or triggered on the restored
   commit and completed successfully;
5. GitHub controls were reconstructed or independently checked and the complete
   production-settings audit passed;
6. a prior verified package environment was selected through the documented
   rollback procedure without modifying an immutable release; and
7. the incident record and public communication were reviewed for private data.

Record an exercise as incomplete when any item is unverified. Do not add a
hypothetical success record merely to satisfy a readiness review.

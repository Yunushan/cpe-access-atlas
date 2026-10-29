# Software and operational readiness assessment

- **Assessment date:** 2026-10-29
- **Scope:** software and operations, excluding physical device qualification
- **Score:** **89.33/100**
- **Repository:** Yunushan/cpe-access-atlas
- **Assessed main commit:** `f846bbbde0256d4fa11130102a028eb700209ecd`
- **Published version:** immutable alpha `v0.4.0a15`
- **Release source commit:** `f7f43351a59e14f4983a591216cb67870193c93e`

This assessment answers whether the software, published packages, repository
controls, documentation, recovery arrangements, and support arrangements are
ready for their stated use without requiring tests on a physical router. The
software and release gates pass. A complete owner recovery exercise and actual
support continuity are still required to reach 100 in this scope.

## Scope and meaning of the score

Physical CPE or router testing is excluded: hardware identity, privileged access,
device recovery, configuration import acceptance, preservation of WAN, DNS,
WiFi, IPTV or VoIP, external WAN isolation, and independent device reproduction.
No point in this assessment depends on obtaining a router or testing one.

Automated software tests remain included. These cover code, CLI behavior,
synthetic fixtures, private-file boundaries, package installation, CI, and
release verification. Account recovery, repository recovery, and support
continuity also remain included because they are operational requirements that
can be exercised without the product hardware.

This is the separate scope requested by the owner. The original whole-project
rubric and the completion requirements in
[`production-readiness.md`](../production-readiness.md) are unchanged. A score
of 100 here would establish the retained software and operational requirements;
it would not qualify a device or establish whole-project production support.
The project remains alpha research software with unqualified device recipes.

The score is an engineering assessment of evidenced requirements, not a
reliability probability or a certification that defects cannot exist.

## Scoring method

The category weights and operational milestones come from the fixed table in
the [archived assessment](PRODUCTION_READINESS_ASSESSMENT.md). That document
supplies the weights, not current evidence or current earned scores.

The complete 25-point exact-device category is outside this assessment,
including the 3 points previously associated with truthful device refusal
gates. The other five category weights are retained, totaling 75 raw points.
Each retained point has the same value:

```text
Scoped score = 100 × earned retained points / 75
             = 100 × (20 + 15 + 15 + 7 + 10) / 75
             = 89.333333... points out of 100
Reported score = 89.33 / 100
```

No new bonus, hidden penalty, or discretionary device exclusion is added after
scoring. Round only the final result; displayed category values are rounded for
readability.

| Category | Raw maximum | Raw earned | Maximum out of 100 | Earned out of 100 |
|---|---:|---:|---:|---:|
| Correctness and test assurance | 20 | 20 | 26.67 | 26.67 |
| Security and privacy | 15 | 15 | 20.00 | 20.00 |
| Release and consumer verification | 15 | 15 | 20.00 | 20.00 |
| Operational recovery and support | 15 | 7 | 20.00 | 9.33 |
| Documentation and contracts | 10 | 10 | 13.33 | 13.33 |
| **Total** | **75** | **67** | **100.00** | **89.33** |

## Evidence and category decisions

### Correctness and test assurance

**Earned: 20/20 raw points, equivalent to 26.67/100.**

The [required CI run on assessed main](https://github.com/Yunushan/cpe-access-atlas/actions/runs/40934452072)
passed the fifteen Windows, Linux, and macOS jobs for CPython 3.11 through 3.15,
package smoke, and cross-platform artifact equality. The configured checks
include lint, formatting, strict types, compilation, generated CLI reference,
complete unittest discovery, coverage, catalog validation, and exact-target
refusal behavior.

The [release workflow](https://github.com/Yunushan/cpe-access-atlas/actions/runs/40924940150)
also validated the exact a15 source commit. Its Python 3.15 jobs on all three
platforms used CPython 3.15.2 final. Each ran 736 discovered tests both from the
source checkout and bundled source distribution. Linux and macOS reported 18
skips; Windows reported 15. Each reported 100% configured coverage: 5,351
statements and 2,058 branches, with no missed statements or partial branches.
Skipped tests are not presented as executed tests. Reproducible artifact
comparison covers the three platform builds, not fifteen independent builds.

Local Windows full-suite and archive-test attempts encountered four failures
and two errors in the synthetic loopback TLS fixture. The hosted tests passed
on their own runners; that does not resolve the local workstation discrepancy.
Full points reflect the repository's required CI gate, and do not claim that
every workstation or every possible runtime path has passed.

Platform claims remain limited to
[`platform-support.md`](../platform-support.md). Experimental arm64 results do
not promote that platform into the required support or release matrix.

### Security and privacy

**Earned: 15/15 raw points, equivalent to 20.00/100.**

The exact-main [CodeQL](https://github.com/Yunushan/cpe-access-atlas/actions/runs/40934452099),
[dependency security audit](https://github.com/Yunushan/cpe-access-atlas/actions/runs/40934451937),
[secret scan](https://github.com/Yunushan/cpe-access-atlas/actions/runs/40934452103),
and [DCO](https://github.com/Yunushan/cpe-access-atlas/actions/runs/40934451985)
workflows passed. The administrator-visible production-settings audit was
rerun from the clean assessed main commit and returned only `PASS` results.
Its local source check verified 21 control files against their committed blobs.

The audited baseline includes protected main checks, exact-tag creation
controls, tag update/deletion restrictions, an exact-tag release environment
without administrator bypass, release immutability, pinned Actions, private
vulnerability reporting, and enabled dependency and secret controls. It found
no open Dependabot, CodeQL, or secret-scanning alerts.

Two exact dismissed CodeQL compatibility risks remain explicitly accepted under
the [versioned policy](../../.github/codeql-accepted-risks.json), with their next
review due on 2027-03-18. They concern legacy vendor configuration cryptography
and web authentication. These accepted risks are part of the current policy;
the full category score does not erase them.

The report-only [OpenSSF Scorecard run](https://github.com/Yunushan/cpe-access-atlas/actions/runs/40934454347)
could not start under the existing Actions allowlist. Its owner setting remains
deferred. It is not a required baseline check, so it is recorded here without
inventing an additional score deduction. Promotion would require a deliberate
policy change and the evidence described in the operations guide.

### Release and consumer verification

**Earned: 15/15 raw points, equivalent to 20.00/100.**

The [a15 release](https://github.com/Yunushan/cpe-access-atlas/releases/tag/v0.4.0a15)
was published on 2026-10-29 from the pinned release source commit. GitHub reports
it as immutable and as a prerelease. The assessed main commit differs from
that release only in the assurance-register documentation; the software and
release-control source being credited is the released a15 source.

The protected release workflow succeeded on attempt 2. Attempt 1 ended after
the macOS Python 3.15 SBOM job was cancelled before execution while waiting for
a runner. The failed-job retry retained successful prerequisite results and
completed the remaining validation and publication stages. Earlier failure
evidence is preserved.

The release evidence establishes:

- exact version, dated changelog, annotated tag, and reviewed commit identity;
- successful prepublication and postpublication production-settings audits;
- reproducible wheel and source archive, including cross-platform equality;
- exactly 18 published assets: wheel, source archive, checksum manifest, and
  fifteen OS/Python runtime SBOMs;
- all 17 payload entries in the authenticated manifest matching their bytes;
- independent verification of all 18 downloaded assets' provenance, constrained
  to the repository, release workflow, tag, source commit, hosted runners, and
  successful release-run attempt;
- separate clean installations of the verified published wheel and source
  archive, with isolated imports, dependency consistency, catalog validation,
  and safe CLI checks; and
- installed-artifact MCP checks for malformed Unicode, embedded sensitive-field
  redaction, and continued-session behavior.

The postpublication settings audit is an inventory/control check. It is credited
alongside the separate downloaded-byte and provenance verification, rather than
being substituted for those checks. Maintainer verification is sufficient for
this rubric; it is not described as an external security review.

### Operational recovery and support

**Earned: 7/15 raw points, equivalent to 9.33/100.**

| Existing criterion | Raw maximum | Earned | Evidence and decision |
|---|---:|---:|---|
| Runbook and publication-freeze policy | 3 | 3 | The [operations guide](../operations.md) defines incidents, containment, trust boundaries, restoration, rollback, and freeze conditions |
| Live external control audit | 2 | 2 | The complete administrator-visible audit passed against assessed main |
| Partial restore and attestation evidence | 2 | 2 | Local source restoration and package-selection rehearsals passed; their scope remains partial |
| Complete owner recovery exercise | 5 | 0 | The complete seven-step exercise has not been established |
| Actual support and access continuity | 3 | 0 | [SUPPORT.md](../../SUPPORT.md) describes one maintainer and best-effort service; an exercised continuity arrangement is not established |
| **Total** | **15** | **7** | |

The local package-selection rehearsal selected a15, a14, and then a15. Each
selection passed version, contract, public catalog, isolated-import, and
dependency checks. It verified 83 installed package files per environment
against the previously authenticated wheel bytes before and after selection.
The final selection is a15. Since a14 lacks a15's MCP privacy fix, this public
CLI rehearsal is not approval to use a14 for the privacy scenario fixed in a15.

The local restoration rehearsal restored the published a15 tag and its reachable
ancestry from a bundle into a fresh directory, verified Git integrity and all
189 source files, and reverified all 18 copied release assets' checksums and
constrained provenance. It did not restore every repository branch or prove
separate-storage custody. An initial local verifier field-name error was
corrected; its failed record was retained alongside the successful rehearsal.

Both rehearsals explicitly mark the full owner recovery exercise `INCOMPLETE`.
Same-workstation copies and a local selector do not establish account recovery,
separate recovery custody, restored-workflow completion, incident communication,
or service continuity. They earn no portion of the complete drill's five points.

### Documentation and contracts

**Earned: 10/10 raw points, equivalent to 13.33/100.**

The [output contract](../cli-output-contract.md) defines version 1 shapes,
conservative interpretation, and exit behavior. Generated CLI reference checks
passed in exact-commit CI. The release, platform, private-file, authentication,
secret-input, and evidence boundaries are documented. The
[assurance register](../enterprise-assurance.md) identifies a15 and keeps
unproven organizational and device claims unpromoted.

The separate enterprise register does not silently add a mandatory external
review, a second reviewer, an enterprise SLA, or other new deductions to this
score. Existing best-effort support limitations still prevent the operational
continuity points from being earned.

## Path to 100 without physical device testing

| Milestone | Raw points added | Scoped score after completion | Acceptance |
|---|---:|---:|---|
| Current evidenced state | 0 | **89.33** | Requirements and evidence above |
| Complete owner recovery exercise | 5 | **96.00** | Every recovery step below has a dated, reviewed receipt |
| Establish and exercise support continuity | 3 | **100.00** | The actual arrangement below exists and has been exercised |

These milestones require no router testing. The work is currently deferred at
the owner's request; documenting an intended arrangement does not complete it.

### Recovery exercise acceptance

Perform the exercise using public source/release assets and synthetic test
credentials, following the [seven-step gate](../operations.md#recovery-exercise-gate).
Retain evidence in an appropriate private store without credentials or private
report content.

| Step | Evidence required to earn the complete drill's points |
|---|---|
| 1. Confidential reporting | Dated receipt that the confidential route was reachable without exposing the report contents |
| 2. Account recovery and revocation | Authorized repository-account recovery exercised and a synthetic test credential demonstrably revoked; retain outcomes, never secret values |
| 3. Separate restoration | A separately stored source/release evidence set restored into a clean location, with custody, commit, checksum, and attestation verification |
| 4. Restored workflows | The full required workflow set triggered or dispatched on the restored exact commit and completed successfully |
| 5. External controls | A complete administrator-visible production-settings audit passes from the recovered authenticated environment and exact current main checkout |
| 6. Package rollback | A prior verified environment selected through the rollback procedure, with compatibility and safe-use boundaries reviewed |
| 7. Incident communication | A sanitized incident record and communication reviewed for private data |

The existing technical rehearsals can support preparation for steps 3 and 6.
They must be linked into an actual owner exercise with the missing conditions
completed before all five raw points are awarded. Current routine CI is not a
substitute for the required restored-workflow evidence.

### Support continuity acceptance

Define the intended software-use scope, the person or arrangement responsible
for support and repository authority, and what happens when that authority is
unavailable. Establish the actual access and recovery capability, then exercise
the handover, absence, or recovery scenario appropriate to that arrangement.
Record the outcome and align `SUPPORT.md` and the operations guide with the real
service being offered.

Do not promise a response or restoration time that is not resourced. An
enterprise SLA or mandatory independent PR reviewer is not a new requirement;
an actual, proportionate support and access-continuity arrangement is. The
current single-maintainer best-effort statement alone does not earn these three
raw points. Keep publication frozen when authority or continuity is uncertain.

## Reusing and maintaining the assessment

Use this wording when sharing the result:

> As of 2026-10-29, CPE Access Atlas scores 89.33/100 for software and operational
> readiness, excluding physical-device qualification. Software and release
> gates pass; the complete owner recovery exercise and support continuity remain
> unverified.

Always include the scope, date, assessed source commit, and released version.
After either milestone, recalculate from raw earned points using the same
75-point denominator. Preserve failed attempts and distinguish candidate,
main, published, local, and restored-source evidence.

Before retaining a score after a new release or material code/control change,
repeat the affected exact-commit CI, risk review, release verification, and
administrator-visible audit. The auditor rejects required CI/security evidence
older than eight days; the two accepted CodeQL risks must be reviewed by
2027-03-18. A new open finding, failing required gate, expired acceptance, broken
release trust, or loss of continuity requires reassessment of the affected
category. An old passing score is not ongoing evidence.

The original whole-project goal remains subject to
[`production-readiness.md`](../production-readiness.md). This separate assessment
provides a route to 100 for software and operations without redefining the
project's physical-device qualification requirements.

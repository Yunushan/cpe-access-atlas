# Production readiness requirements

Readiness is established by verified outcomes for the intended use. A numerical
assessment, successful installation, or a green workflow does not override a
missing qualification or support gate. The project remains alpha research
software, and all bundled device records remain researching or blocked.

## Software and release requirements

Before publishing a supported version, verify the actual release commit with:

- lint, formatting, strict types, compilation, generated CLI reference,
  complete tests and the unchanged statement/branch coverage gate;
- the Windows, Linux, and macOS interpreter matrix, including a rerun on a
  final Python version before claiming final-version qualification;
- dependency consistency, hashed installation of all lock sets, dependency
  audit, secret scanning, DCO, and CodeQL with reviewed unexpired acceptances;
- reproducible wheel/source builds from that immutable commit, source-archive
  test execution, and separate clean artifact installations;
- exact version/changelog validation, current main/tag/environment controls,
  and the complete administrator-visible production-settings audit;
- protected immutable publication, exact asset inventory, checksums, SBOMs,
  constrained provenance verification and installed-published-artifact checks.

Follow [the release checklist](release.md) for commands and trust boundaries.
Do not substitute another commit's receipts for the candidate. Preserve earlier
failures and identify what a successful rerun establishes. Keep release data
separate from private firmware/configuration and device identities.

The report interface follows [output contract version 1](cli-output-contract.md).
Retain the conservative interpretation of unknown decisions and observations.
Supported documentation must cover current authentication, private-file,
secret-input, and evidence boundaries in the advertised languages.

## Device outcome requirements

A configuration-import or access claim requires an exact resolved target and
the completed evidence defined in [device qualification](device-qualification.md).
That includes hardware identity, claimed access, original-state recovery,
services, local and independently observed external WAN isolation, and config
import acceptance when claiming codec compatibility. Stable status additionally
requires independent reproduction.

The current H3600P catalog's V9.0 key remains provisional; its observed V9.0.7
UI value has no authoritative physical-board mapping. Neither value may be
changed merely to make an exact-match gate pass. No method is currently
qualified for the TTN.10_260210 target. Config generation and passive evidence
analysis remain research tools; `apply` remains unavailable.

On a service-critical unit without a tested recovery path, stop at read-only
evidence. The required physical observations need an authorized operator and
recoverable hardware; a synthetic fixture or hypothetical report cannot supply
them. Keep this requirement when assessing the entire project rather than
silently changing the scope to its offline commands.

## Operational requirements

Complete every step of [the operational recovery exercise](operations.md#recovery-exercise-gate):
private reporting receipt, account recovery and synthetic credential revocation,
separate source/release restore, workflows on the restored commit, independent
control verification, trusted package rollback, and sanitized communication.
Existing USB restore and attestation receipts demonstrate useful partial work;
they do not complete the missing reporting, authority, custody, or device steps.

Record dates, exact versions/commits, commands, expected and observed outcomes,
and unresolved steps. Retain evidence in a controlled store without credentials.
Publication remains frozen during an unresolved compromise or unavailable
maintainer. The current best-effort single-maintainer policy provides no SLA
and is unsuitable for unattended or business-critical deployment; a claim for
that use needs a support and access-continuity arrangement that actually exists.

## Completion decision

An assessment may reach its maximum only after every relevant requirement above
is proven for its stated scope. Keep an overall project goal open while device,
release, operational, or support evidence remains absent. Accepting legacy vendor
protocol risks must be explicit and reviewed; an expired or unmatched acceptance
fails the release gate. Do not alter a rubric, suppress findings, remove required
functionality, or weaken tests merely to obtain a numerical target.

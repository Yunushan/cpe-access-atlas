# Changelog

All notable changes are documented here.

## Unreleased

### Security and delivery

- Hardened redaction for quoted secrets, API keys, and Basic authorization
  values.
- Added pinned CI/security/release dependency lock files and clean wheel/sdist
  installation smoke tests.
- Added dependency review, CodeQL, release metadata checks, SBOM generation,
  checksums, and build-provenance attestations.
- Added bounded workflow execution with duplicate-run cancellation and a
  regression test proving public targets are rejected before any socket opens.
- Enforced the port-count limit for direct library callers, hardened redaction
  of nonstandard authorization headers, and added release-tag/version checks.
- Removed unused Node.js setup from Python-only workflows, required release
  tags to point into `main`, and separated the locked runtime dependency SBOM
  from the audit toolchain.
- Added package repository metadata, a security-advisory contact link, and
  contribution templates that require sanitized evidence and rollback details.
- Gated publication on clean wheel and source-distribution installation smoke
  tests in the release workflow.
- Included repository governance templates in the source distribution for
  auditable release snapshots.
- Hardened library input validation against non-string values, scoped IPv6
  addresses, oversized port inputs, and unbounded port iterators; evidence
  links now require HTTPS and invalid report encodings fail cleanly.
- Pinned CI and release smoke-test build backends and locked runtime
  dependencies before installing wheel and source-distribution artifacts.
- Made dependency audits strict, rejected moderate-or-higher dependency-review
  findings, and rejected lightweight release tags.
- Added weekly Dependabot configuration for Python and GitHub Actions, plus
  dependency-consistency checks to every CI test job.
- Added release changelog-entry enforcement, explicit strict SBOM auditing,
  and boolean-timeout rejection for direct library callers.
- Added regression tests that protect pinned workflow actions, dependency
  update configuration, CI consistency checks, and release safety gates.
- Added a read-only `firmware-inspect` command that hashes private artifacts,
  checks the exact build string, optionally verifies a separately recorded
  SHA-256, and reports common image markers without executing or modifying
  firmware.
- Added private firmware-hash fields to research reports and documented why
  the externally hosted H3600P guide/VM is not exact-build evidence.

## 0.2.0 - 2026-08-11

### Changed

- Exact target lookup now requires ISP, model, hardware revision, and firmware.
- Hardware revision verification is explicit; unresolved records cannot become
  verified or stable.
- Catalog and provider JSON are validated against packaged JSON Schemas.
- CLI timeout input is finite and bounded; malformed values fail cleanly.
- Redaction covers JSON-style secrets, bearer tokens, and public IPv6 literals.
- Added a guarded `cpe-atlas redact` command for sanitizing text before sharing.
- CI adds linting, coverage enforcement, package builds, and release validation.

## 0.1.0 - 2026-08-11

### Added

- Initial Türkiye provider catalog with seven ISPs.
- Exact firmware record for Türk Telekom ZTE H3600P
  `H3600P V9.0 TTN.10_260210`.
- Fail-closed private-target policy and optional single-host port probe.
- Compatibility, evidence, and sanitized research-report commands.
- English, Turkish, German, French, and Russian documentation.
- 0BSD licensing, contribution rules, security policy, tests, and CI.

### Important limitation

No verified privileged-access method is currently public for the exact
`TTN.10_260210` firmware. The catalog records it as blocked instead of
claiming support based on methods for older firmware.

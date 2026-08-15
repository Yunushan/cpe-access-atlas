# Changelog

All notable changes are documented here.

## Unreleased

- Added a read-only GitHub production-settings audit script that distinguishes
  disabled controls from administrator permissions that are not visible.
- The audit now verifies every CI matrix check plus package smoke, dependency
  audit/review, CodeQL, and secret-scan check runs, and requires `gitleaks` in
  the protected-branch check set, instead of only checking workflow-level
  success.
- The release audit now verifies that the latest release uses an annotated tag
  whose commit is reachable from `main`.
- Pinned the pre-commit Ruff and mypy repositories to immutable commit SHAs,
  matching the workflow action supply-chain policy.
- Made the GitHub audit's CLI adapter explicitly UTF-8 and fail-safe on
  Windows, where repository metadata can contain non-CP1252 characters.
- Documented the narrowly scoped CodeQL exception for the firmware-compatible
  SHA-256 derivation path, and marked the call as non-security use for
  FIPS-aware runtimes; it is not password storage or verification.

## 0.3.0 - 2026-08-15

### Added

- Added researching-status recipe stubs for every device in the official
  device inventory (Türk Telekom, Turkcell Superonline, Türksat Kablonet)
  that did not already have one, plus one researching-status stub each for
  Millenicom and Vodafone Net; none make any access-level claim.
- Added a generated CLI reference (`docs/cli-reference.md`), produced by
  `scripts/generate_cli_reference.py` directly from the `argparse`
  definition and checked for staleness in CI and at release time.
- Added `CODE_OF_CONDUCT.md` and a `.github/workflows/dco.yml` workflow that
  requires a Developer Certificate of Origin `Signed-off-by` trailer on
  every commit in a pull request.
- Added `.github/workflows/secret-scan.yml` (gitleaks) running on every push
  and pull request, plus a `.gitleaks.toml` allowlist scoped to synthetic
  test fixtures.
- Added `.pre-commit-config.yaml` mirroring the CI lint, format, type-check,
  and catalog-validation steps for local development.
- Added a `hypothesis`-based property test suite
  (`tests/test_fuzz_properties.py`) that fuzzes `config.py`'s binary
  container decoder and `redaction.py`'s regex-based redaction with
  randomized and adversarial input to catch crashes that example-based
  tests would not think to construct.
- Marked the package `py.typed` and added a `[tool.mypy]` strict
  configuration, enforced in CI and at release time; introduced small
  `Protocol` types for the optional AES cipher dependency in place of a
  bare `object` return type.

### Changed

- Expanded the `ruff` lint rule set from `E, F, I, UP, B` to also include
  `S` (bandit-equivalent security rules), `RUF`, `SIM`, `C4`, `PTH`, `A`,
  and `ARG`, and fixed the resulting findings in `cli.py`, `config.py`,
  `private_files.py`, and `redaction.py`.
- Enforced `ruff format --check` in CI and at release time, after
  reformatting the full source and test tree.
- Fixed a latent bug where `main()` would raise `TypeError` if argparse's
  `SystemExit.code` were `None` or a non-integer value on some Python
  versions; added regression tests for both cases.

### Security and delivery

- Added the read-only `root-readiness` gate for exact-build firmware evidence;
  the TTN.10_260210 target remains fail-closed because no reproducible root
  method or recovery-tested workflow is verified.
- Added a schema-validated official ISP device inventory and `cpe-atlas devices`
  command for the four reviewed Türk Telekom, Turkcell Superonline,
  and Türksat device pages; listings remain separate from exact firmware or
  privileged-access support claims.
- Added an owner-gated, offline H3600P configuration codec and generator that
  can patch a private baseline or create a clearly experimental minimal
  artifact, with encrypted-container round-trip tests and no device I/O.
- Required an explicit acknowledgement for unencrypted generated configs,
  atomically write private artifacts with restrictive permissions where
  supported, and stopped the redactor from printing potentially sensitive
  output to the terminal.
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
- Updated the pinned setuptools build backend to 84.0.0 across packaging and
  every CI, release, and security lock file after the security audit identified
  the vulnerable 82.0.1 pin.
- Added weekly Dependabot configuration for Python and GitHub Actions, plus
  dependency-consistency checks to every CI test job.
- Added release changelog-entry enforcement, explicit strict SBOM auditing,
  and boolean-timeout rejection for direct library callers.
- Corrected the security workflow to audit the locked dependency set instead of
  treating the unpublished local project as a PyPI dependency.
- Added a protected `release` environment requirement and documented the
  Dependency Graph prerequisite for pull-request dependency review.
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

# Platform support

## Scope and support claim

This table records what the project CI actually exercised, not what the Python package format could theoretically install on. A green CI run is not a production-use endorsement; production readiness and release gates remain in [`production-readiness.md`](production-readiness.md). Platform claims are limited to the operating-system labels and CPython versions exercised below. The workflows do not pin or record CPU architecture, exact OS image revision, or Linux libc version, so this document makes no claim about those dimensions.

## Verified CI snapshot

Evidence: required CI workflow run [39669303595](https://github.com/Yunushan/cpe-access-atlas/actions/runs/39669303595), head commit `d50f43ba5445c0918ecbe4504a2ae13164e72ae1`, completed successfully on 2026-10-21. All fifteen OS/Python matrix jobs passed. The release workflow uses the same OS and Python matrices; it has not published a release for this commit. Run evidence establishes the runner labels, not an OS image or architecture guarantee.

| Operating system / runner label | Architecture | libc / filesystem detail | Python tested | Tier and current claim |
|---|---|---|---|---|
| Windows (`windows-latest`) | Runner architecture not pinned or recorded | libc not applicable; filesystem not asserted | CPython `3.11`, `3.12`, `3.13`, `3.14`, `3.15` | Tier 1: required CI passed for the listed matrix |
| Linux (`ubuntu-latest`) | Runner architecture not pinned or recorded | Ubuntu image; libc version not pinned or recorded | CPython `3.11`, `3.12`, `3.13`, `3.14`, `3.15` | Tier 1: required CI passed for the listed matrix |
| macOS (`macos-latest`) | Runner architecture not pinned or recorded | Filesystem not asserted | CPython `3.11`, `3.12`, `3.13`, `3.14`, `3.15` | Tier 1: required CI passed for the listed matrix |

Tier 1 here means required CI coverage only. It does not override the alpha status, the device-qualification gate, the operational requirements, or the release-specific evidence required by `docs/production-readiness.md`. The support matrix and release workflow must stay aligned; a platform is not added to the package's explicit OS classifiers until an actual CI/release path supports it.

## Unverified platforms

It is a configuration for prospective testing only, not evidence of an available or successful run.

| Platform target | Status | Evidence needed before claiming support |
|---|---|---|
| Linux arm64 | Configured for experimental CI only; unsupported, unverified | Review actual runtime and dependency evidence; require two consecutive green main commits before promotion |
| Linux x86_64 musl / Alpine | Unsupported, unverified | Non-required CI on the intended musl image, complete tests and hash-checked dependencies |
| Windows arm64 | Unsupported, unverified | Actual arm64 runner, full tests and dependency installation evidence |
| macOS second architecture | Unsupported, unverified | Actual runner for that architecture and full test evidence |
| FreeBSD, OpenBSD, NetBSD | Unsupported, unverified | Reviewed and SHA-pinned runner mechanism, portability audit, installed dependencies, complete tests and validation |
| illumos, OmniOS, Solaris | Unsupported, unverified | Reviewed and SHA-pinned runner mechanism, portability audit, installed dependencies, complete tests and validation |
| Android / Termux | Unsupported, unverified | Recorded run on the real Termux runtime and supported dependency set; an unrelated emulator or Linux container is insufficient |
| iOS | Unsupported | A supported, tested CLI runtime with the required filesystem/process semantics; no such target is currently provided |
| PyPy, free-threaded CPython, other Python implementations | Unsupported, unverified | Explicit interpreter matrix, dependency compatibility and full test evidence |

Do not silently skip a test or substitute an architecture, libc, operating system, emulator, or interpreter for the target named in a claim. For targets without evidence, use the JSON catalog/CLI contract only from an already supported host; do not imply that this means the target itself is supported.

## Promotion policy

1. Record the workflow run, full commit, runner image/architecture/libc where available, Python implementation and version, dependency installation method, test result, and unresolved failures.
2. Keep experimental jobs separate from required checks. New contexts stay non-required until they pass on two consecutive `main` commits and an owner deliberately updates the ruleset and audit policy.
3. Do not add a platform classifier or change a platform to supported from a local run, documentation-only change, dependency metadata, or a third-party compatibility claim.
4. Revalidate the exact released commit. A different commit's green CI is not release evidence.
5. If a security primitive used for private artifacts is unavailable, fail closed. Never weaken private-file controls to make another OS pass.

The formal release and support decision remains governed by [`production-readiness.md`](production-readiness.md) and [`release.md`](release.md).

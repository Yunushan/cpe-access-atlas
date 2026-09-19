# Contributing

Thank you for helping document owner-authorized access to ISP-provided
equipment. Participation in this project is governed by `CODE_OF_CONDUCT.md`.

## Device recipe requirements

A recipe contribution must include:

1. ISP, vendor, exact model, hardware revision, and exact firmware string.
2. The access level obtained: privileged web administration, local root shell,
   configuration recovery, or another precisely defined capability.
3. Sanitized evidence showing the method and rollback path.
4. Confirmation that WAN-side administration remains disabled.
5. Test results on the exact device and firmware.
6. A statement that the contributor owns the device or had authorization.

Do not include secrets, configuration exports, subscriber data, arbitrary
shell payloads, firmware images, or vendor-owned binaries.

## Status progression

- `researching`: evidence is incomplete or the known method is patched.
- `experimental`: implemented but not independently reproduced.
- `verified`: reproduced on the exact device and firmware with rollback.
- `stable`: independently reproduced and maintained across releases.
- `blocked`: a known technical blocker prevents the requested access.

`verified` and `stable` require hardware evidence. Mock tests alone are not
enough.

Qualified records must include a `qualification` object with `hardware`,
`access`, `recovery`, `services`, and `wan_isolation` URLs and a `tested_on`
date. Each URL must also appear in the record's reviewed `evidence` list;
the test date cannot be later than `last_reviewed`. A verified/stable record
with `offline-private-config-codec` must additionally include `config_import`.
Stable records additionally require `independent_reproduction`. Verified
records require exact hardware and no remaining blockers. Generic product
pages do not establish these outcomes: review the linked sanitized reports
against the exact ISP, hardware, firmware, and claimed access level.

The schema and loader enforce the evidence structure, not the truth of a
hardware experiment. Follow [device qualification](docs/device-qualification.md)
and retain private originals; never publish backups or device credentials.

## Development

This project currently has one maintainer. Push changes to a feature branch,
open a pull request, and merge after required automated checks pass and review
conversations are resolved. The maintainer may merge their own PR: another
person's approval is optional, not mandatory. CODEOWNERS identifies ownership
without requiring self-approval. Protected `main`, release-tag restrictions,
and CI/security gates remain in place. See [repository policy](docs/github-production-settings.md).

Use standard CPython 3.11 through 3.15:

```shell
python -m pip install --require-hashes -r requirements-ci.lock
python -m pip install -e . --no-deps --no-build-isolation
python -m ruff check src tests scripts
python -m ruff format --check src tests scripts
python -m mypy src scripts
python -m coverage run -m unittest discover -s tests -v
python -m coverage report -m
cpe-atlas validate
```

The 100% measured statement/branch coverage gate includes both the runtime and
the maintenance scripts; strict type checking covers both as well. Coverage is
not proof of complete security properties or real-device interoperability.
The GitHub audit tests use synthetic API evidence and replace external process
execution, so the test suite does not inspect or change your GitHub settings.

Optionally install the local pre-commit hooks, which run a fast subset of the
CI checks before each commit. They do not replace the complete test, coverage,
generated-reference, archive, or clean-install gates:

```shell
python -m pip install pre-commit
pre-commit install
```

Every commit in a pull request must include a Developer Certificate of
Origin (DCO) sign-off, enforced by `.github/workflows/dco.yml`. Add it
automatically with:

```shell
git commit --signoff -m "Your commit message"
```

The CI, security, release, runtime-SBOM, and artifact-build environments use the
committed lock files. When updating tooling or runtime dependencies, regenerate
the relevant lock files with a universal resolver, preserving environment
markers and package hashes. They cover Python 3.11–3.15 on Windows, Linux, and
macOS; resolving only the maintainer's interpreter misses conditional
dependencies. See [lock maintenance](docs/release.md#dependency-lock-maintenance).
Validation workflows run for pull requests and for pushes to `main`; full CI,
dependency audit, and CodeQL also exercise unchanged `main` weekly and support
the documented manual recovery checks. Pushes to feature branches are
intentionally not duplicated because the pull-request run is the required merge
evidence. Open or update a pull request before relying on CI results for a
feature branch.
Run the full validation suite and record the reason in the pull request.
Dependabot proposes updates to the direct Python constraints in
`pyproject.toml` and to GitHub Actions. It does not regenerate the custom
`requirements-*.lock` files; after accepting a constraint change, regenerate
and review every affected lock as described below. The weekly dependency audit
still scans every committed lock for known vulnerabilities.

The 3.15 jobs allow prereleases until a final interpreter is available. Run the
suite, coverage, typing, archive tests, and clean wheel/sdist installs on 3.15;
do not count successful dependency resolution as cross-platform execution.
The committed CLI reference still uses Python 3.14 as its canonical formatter;
CLI behavior and reference rendering are tested on every supported interpreter.
Use standard CPython builds; free-threaded builds and PyPy are not CI targets.

Run pip-audit under Python 3.14: its current pip-api dependency cannot import
on 3.15. The release workflow audits hash-verified, target-interpreter runtime
inventories from this separate tooling interpreter; see the release checklist.

For a release candidate, use `requirements-release.lock`, build both wheel and
sdist artifacts, run `python -m twine check dist/*`, and install each artifact
in a clean virtual environment before tagging.

All contributions are licensed under 0BSD. Add SPDX identifiers to new source
files and sign off commits with the Developer Certificate of Origin:

```text
Signed-off-by: Your Name <you@example.com>
```

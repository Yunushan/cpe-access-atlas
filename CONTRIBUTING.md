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

## Development

Use Python 3.11 or newer:

```shell
python -m pip install -r requirements-ci.lock
python -m pip install -e . --no-deps --no-build-isolation
python -m ruff check src tests
python -m ruff format --check src tests
python -m mypy src
python -m coverage run -m unittest discover -s tests -v
python -m coverage report -m
cpe-atlas validate
```

Optionally install the local pre-commit hooks, which run the same checks
before each commit:

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
the relevant lock file from a clean Python 3.14 environment, run the full
validation suite, and record the reason in the pull request. Dependabot is
configured to propose updates for these files.

For a release candidate, use `requirements-release.lock`, build both wheel and
sdist artifacts, run `python -m twine check dist/*`, and install each artifact
in a clean virtual environment before tagging.

All contributions are licensed under 0BSD. Add SPDX identifiers to new source
files and sign off commits with the Developer Certificate of Origin:

```text
Signed-off-by: Your Name <you@example.com>
```

# Installation and rollback

CPE Access Atlas is currently alpha software. A successful installation does
not make a device recipe verified and does not establish firmware, root-access,
or recovery compatibility. Use only on equipment you own or are authorized to
administer.

## Verified source checkout

For development or evaluation from a reviewed checkout, create a dedicated
virtual environment and install the hash-locked CI environment before the
project itself:

```shell
python -m venv .venv
python -m pip --python .venv install --require-hashes -r requirements-ci.lock
python -m pip --python .venv install -e . --no-deps --no-build-isolation
python -m pip --python .venv check
```

Run `.venv/bin/cpe-atlas validate` on Linux/macOS or
`.venv\Scripts\cpe-atlas.exe validate` on Windows. The `--no-deps` and
`--no-build-isolation` flags prevent a second unreviewed dependency or build
backend resolution.

### Setup and check helpers

From a reviewed source checkout, the optional helpers run the same locked
installation and local development checks without activating an environment.
Use PowerShell 7 on Windows:

```powershell
pwsh -NoProfile -File ./scripts/dev.ps1 setup -Python python
pwsh -NoProfile -File ./scripts/dev.ps1 check
```

Use Bash on Linux/macOS:

```bash
bash scripts/dev.sh setup --python python3
bash scripts/dev.sh check
```

Select a supported interpreter executable, such as `python3.14` or a full path
containing spaces. The default environment is `.venv` inside the checkout;
`-Venv .tmp/dev-env` (PowerShell) or `--venv .tmp/dev-env` (Bash) selects another
relative directory inside it. Both helpers resolve paths from their own
location, so they can also be invoked by absolute path from another directory.
An existing environment is reused; an ordinary directory is refused rather
than overwritten. Setup downloads the hash-locked development dependencies,
installs the editable checkout, checks dependency consistency, and validates
the catalog.

The helpers run Python in isolated mode and clear `PYTHONPATH`/`PYTHONHOME`
for their commands and editable-build child processes. Pip requires the selected
virtual environment, ignores inherited `PIP_*` options, and reads no global,
user, virtual-environment, or `PIP_CONFIG_FILE` configuration. This prevents
installation destination overrides from escaping the dedicated environment;
the caller's environment is restored after each command. Setup uses pip's
default PyPI index. If your organization requires a custom index or pip
certificate settings, use the direct Python commands above with its approved
explicit options instead of these helpers.

Check runs dependency consistency, Ruff lint and formatting checks, strict
typing, source compilation, the unit tests and coverage gate, and catalog
validation. Generated CLI reference freshness is checked only on Python 3.14,
the canonical formatter used by CI. These are local development checks; the
archive, clean-install, security, and release gates still run separately.
The helpers stop at the first failing command and return its exit status.

If an organization or local PowerShell policy prevents running an unsigned
script, use the direct Python commands here and in
[Contributing](../CONTRIBUTING.md#development), or the organization's approved
script-signing process. The helpers do not change execution policy.

## Published wheel

There is no production-stable PyPI distribution. Install a GitHub release only
after completing the checksum and provenance procedure in
[the release guide](release.md#published-artifact-verification). Download the
matching `requirements-runtime.lock` from that exact reviewed tag; a lock from
another commit is not equivalent evidence.

After verification, install into a new environment rather than modifying an
existing working installation:

```shell
python -m venv cpe-atlas-vX.Y.Z
python -m pip --python cpe-atlas-vX.Y.Z install --require-hashes -r requirements-runtime.lock
python -m pip --python cpe-atlas-vX.Y.Z install --no-deps ./cpe_access_atlas-X.Y.Z-py3-none-any.whl
python -m pip --python cpe-atlas-vX.Y.Z check
```

Run the environment-specific `cpe-atlas validate` command before using any
other operation. Keep the prior environment unchanged until validation and any
required offline compatibility checks succeed.

`pipx install ./cpe_access_atlas-X.Y.Z-py3-none-any.whl` is convenient for
non-production evaluation, but its ordinary dependency resolution does not
provide the repository's hash-locked reference environment. Do not treat a
successful pipx installation as release-verification evidence.

## Upgrade, rollback, and removal

Create a separate environment for every upgrade. Verify and validate the new
version before changing scripts, shortcuts, or service wrappers to reference it.
Rollback means pointing those callers back to the preserved previous
environment; do not overwrite an immutable release or reuse its version number.

To remove the tool, delete only its dedicated virtual environment after first
preserving any private input/output artifacts that the user intentionally needs.
The CLI stores no telemetry and does not require a background service. Removing
the environment does not invalidate router-side sessions that a prior
`web-evidence` run may have created; allow the device to expire the session or
invalidate it through the device's normal administration interface.

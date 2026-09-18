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

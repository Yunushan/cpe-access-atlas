# Release checklist

The release workflow runs for `v*` tags. Administrators must protect that tag
pattern before publishing. Before creating a tag:

1. Confirm the catalog, schemas, documentation, and a matching version heading
   in `CHANGELOG.md` describe the same version.
2. Run the development checks from `CONTRIBUTING.md`.
3. Build both artifacts and validate them in clean environments:

   ```shell
   python -m pip install -r requirements-release.lock
   python -m pip install -e . --no-deps --no-build-isolation
   python -m build --wheel --sdist
   python -m twine check dist/*
   ```

4. Create an annotated `vX.Y.Z` tag only after review and push it through the
   repository's protected release process.

The workflow rejects a tag unless it is annotated, exactly matches the package
version, has a matching `CHANGELOG.md` heading, and points to a commit
reachable from `main`, for example `v0.2.0` for package version `0.2.0`.

The workflow installs the locked runtime dependencies, installs the pinned
build backend from `requirements-build.lock`, and validates both freshly built
artifacts in clean environments before publishing. It then creates a CycloneDX
SBOM for the locked runtime dependencies in `requirements-runtime.lock`,
writes SHA-256 checksums, and attests the build provenance. A release is not
considered supported until its artifacts have also been installed and
validated from the published release itself.

Repository administrators should also keep these GitHub controls enabled:

- required pull-request review and passing CI, security, and CodeQL checks on
  `main`;
- signed or verified release tags and no direct pushes to `main`;
- Dependabot security updates and alerts;
- secret scanning and push protection;
- a private security reporting channel.

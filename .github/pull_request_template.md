## Change summary

<!-- Describe the user-visible or security-relevant change. -->

## Verification

- [ ] I ran the relevant tests and validation commands from `CONTRIBUTING.md`.
- [ ] Catalog changes use the exact ISP, model, hardware revision, and firmware.
- [ ] Hardware claims include sanitized evidence and a recovery/rollback path.
- [ ] I did not include credentials, configuration backups, firmware images,
      packet captures, certificates, serial numbers, or subscriber data.
- [ ] This change does not add a mutating adapter without exact-device evidence.

## Release and security impact

- [ ] Dependency or workflow changes are reflected in the appropriate lock file.
- [ ] Public documentation does not claim support beyond the evidence.
- [ ] I added or updated tests for changed behavior.

## Squash merge

- [ ] The squash commit body keeps every commit's `Signed-off-by:` line and ends
      with a `Signed-off-by:` line matching the squash author's email. A
      subject-only or single-line body fails the DCO gate on `main`
      (see `CONTRIBUTING.md`).

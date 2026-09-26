# Release checklist

The release workflow runs for `v*` tags. Administrators must protect that tag
pattern and enable GitHub **release immutability** before publishing. Confirm
the setting with an administrator-visible read-only request:

```shell
gh api repos/Yunushan/cpe-access-atlas/immutable-releases
```

The response must report `enabled: true`; missing permission or an unavailable
setting is not evidence of enforcement. Keep this administrator check outside
the release job so its token does not gain repository-administration privileges.
Before creating a tag:

1. Confirm the catalog, schemas, documentation, and the release entry in
   `CHANGELOG.md` describe the same version. The candidate must be the first H2
   immediately after the fixed changelog introduction, use the exact version
   and an ISO release date, and have no second heading-like occurrence for that
   version. `Unreleased`, displaced entries, and prefix matches fail; ordinary
   prose that merely mentions the version remains valid.
2. Run the development checks from `CONTRIBUTING.md`.
3. For early feedback, manually dispatch **Release preflight** from the
   candidate commit on `main` with the intended `vX.Y.Z` tag. This recommended,
   non-publishing workflow first rejects a non-`main` ref or invalid candidate
   metadata, then reruns the reusable source, dependency, secret, and CodeQL
   validations and confirms the commit is the current `main` head,
   requires an empty readable **open** CodeQL alert inventory, and requires the
   exact dismissed high/critical alerts on that same ref and commit to match the
   unexpired `.github/codeql-accepted-risks.json` policy. It has no contents-write,
   attestation-write, or OIDC permission and cannot create a release.
   Its result is not trusted as a publication authorization: the tag-triggered
   workflow reruns the substantive checks against the exact tagged commit.
4. Build both artifacts and validate them in clean environments:

   ```shell
   python -m pip install --require-hashes -r requirements-release.lock
   python -m pip install -e . --no-deps --no-build-isolation
   python scripts/build_reproducible.py --dist-dir dist
   python -m twine check dist/*
   ```

5. Review the candidate yourself as the solo maintainer, then create an
   annotated `vX.Y.Z` tag and push it through the protected release process.
   Before pushing, make the `release` environment's sole deployment policy that
   exact tag—not `v*`—and rotate the candidate-only tag-creation rules as
   described in `docs/github-production-settings.md`. Run the read-only
   prepublication audit before any tag is created:

   ```shell
   python scripts/check_github_production_settings.py \
     --repo Yunushan/cpe-access-atlas --prepublication
   ```

   It must exit successfully with only `published release` marked `DEFERRED`;
   every other result, including `candidate absence` and the existing latest
   release-tag integrity, must be `PASS`.
   A second person's approval is optional, not a required PR or release gate.
   Automated checks and the protected tag/environment controls still apply.

The workflow rejects a tag unless it is annotated, exactly matches the package
version, has a unique exact and dated `CHANGELOG.md` heading, and points to the
current `main` head, for example `v0.4.0a1` for package version `0.4.0a1`. A
version bump is part of every release candidate so the current workflow rejects
an older version. Workflow definitions are nevertheless resolved from the tagged
commit, so this source-level gate cannot retroactively harden old commits. The
rotating tag-creation quarantine is the mandatory external fail-closed boundary:
it blocks historical tag pushes before GitHub can select and run an old workflow.
The exact-tag `release` environment policy adds a second boundary for every
historical publisher that used that environment.

`v0.2.0` and `v0.4.0a4` are permanently skipped. Commit
`c73cbc9ce235d4cf94702130304b50bb7d33f2c4` declared `0.2.0` in a historical
publisher that did not use the `release` environment. Commit
`e7f4a6f7d373d48aaf6a3f953b37580fd492cfad` declared that unreleased version
while carrying the earlier broad publishing workflow. Never create or publish
either tag. For `v0.4.0a6`, rotate the creation quarantine to exclude only
that exact tag and bind the release environment to the same tag before the
prepublication audit. Keep the published `v0.4.0a5` tag protected by the
no-bypass update/deletion rule. A broad creation bypass or `v*` environment
rule would reopen a historical-workflow path.

Publication also depends on reusable CI, dependency-audit, secret-scan, DCO, and
CodeQL workflows, plus the runtime SBOM matrix. The reusable CI runs all fifteen
supported OS/Python test jobs, cross-platform artifact equality, and
package-smoke. Local workflow references resolve at the same commit as the
release caller, so another commit's green checks or independent push workflows
cannot satisfy this dependency graph.
No publishing job runs if a prerequisite workflow fails or is cancelled.
The pull-request-only dependency-review job remains intentionally skipped on
release-tag pushes; dependency-audit still runs and is required.
Dependency audit uses Python 3.11 and 3.14 on Linux so every supported
`python_full_version` marker branch in all five distributed lock files is
installed and scanned; one interpreter cannot activate both sides of the
pre-3.12/pre-3.13 dependency boundaries.
Validation workflows run on pull requests and on pushes to `main`; full CI,
dependency audit, and CodeQL also exercise unchanged `main` weekly and may be
dispatched for the recovery checks in `docs/operations.md`. Feature branch
pushes are not run a second time when the same commit is tested by its pull
request. The release job also queries the open CodeQL alert inventory and
scopes that query to the exact analyzed tag ref; it stops before building or
publishing if any alert remains. It then fetches dismissed alerts separately
and requires the exact high/critical set, alert numbers, dismissal metadata,
tag ref, tag commit, exact-instance dismissed state, and review dates recorded in
`.github/codeql-accepted-risks.json`. Missing, fixed-but-still-listed, expired,
changed, or additional high/critical dismissals fail. An inaccessible or
partially paginated inventory is a failure, not an implicit clean result.
Passing these gates means the two documented compatibility risks were explicitly
accepted and remain under review; it does not mean CodeQL produced zero findings.

Python 3.15 is included in both matrices, with prerelease fallback until final
is available. Each 3.15 CI job also builds wheel/sdist artifacts, tests the
bundled source archive, and installs both artifacts into separate clean virtual
environments before isolated CLI validation outside the checkout. No 3.15
failure is optional. The three operating-system builds upload distinct artifact
sets; a downstream gate requires identical filenames and SHA-256 digests. Release
validation also requires its Python 3.14 artifact pair to match all three Python
3.15 pairs before any upload. The canonical documentation and publishing-tool
interpreter remains 3.14. Final-release claims require a fresh successful matrix
on the final interpreter. Free-threaded builds are not tested.

Audit-tool compatibility is separate from runtime compatibility. The latest
published `pip-api` (0.0.34, used by pip-audit) still imports `sre_constants`,
which Python 3.15 removed ([upstream issue](https://github.com/di/pip-api/issues/294)).
Each SBOM job therefore installs `requirements-runtime.lock` **with its target
interpreter and hash verification** into a separate directory, then runs the
locked auditor on Python 3.14 with `--path` pointing only to that inventory.
It does not re-resolve runtime markers under 3.14 or import 3.15 native extensions
into 3.14. A final check requires a nonempty inventory and exact name/version
agreement with the SBOM, rejecting missing, extra, or duplicated components.
Audit failures still block publication; there are no vulnerability exemptions.

Publishing permissions remain confined to the final release job. The read-only
validation job builds, tests, and uploads a candidate bundle; the protected
publishing job neither checks out, installs, nor imports tagged project code.
It accepts only the exact wheel, source archive, fifteen named SBOMs, and a
checksum manifest listing exactly those seventeen artifacts before attestation
or publication. After the environment gate, it resolves both the annotated tag
and `refs/heads/main` again, requiring each target to remain the validated
`GITHUB_SHA` immediately before attestation. It repeats the same live checks
after attestation and immediately before publication, so a main-branch advance
during attestation also fails closed. The reusable
checks do not inherit release secrets, contents-write, attestation-write, or
OIDC permissions; only CodeQL gets the security-events permission needed to
upload its analysis. Successful analysis is not proof of an empty alert
inventory: the maintainer must still inspect and assess open security findings.
See [GitHub's reusable workflow reference](https://docs.github.com/en/actions/how-tos/reuse-automations/reuse-workflows).

Distribution builds reuse the backend already installed from the hash-verified
CI/release tooling locks. They use `--no-isolation` and disable pip index access
for the build step. Default build isolation would install the backend again
without those lockfile hashes. Keep the prerequisite tooling installation:
`--no-isolation` alone does not install missing build dependencies.

`scripts/build_reproducible.py` derives `SOURCE_DATE_EPOCH` from the reviewed
Git commit unless an explicit valid epoch is supplied. It resolves `GITHUB_SHA`
or `HEAD` to an immutable commit and materializes only that tree's Git blob bytes;
modified and untracked checkout files cannot enter the artifacts. It builds in
two separate source trees and then rewrites the wheel as platform-neutral
`ZIP_STORED` entries with a verified and regenerated `RECORD`. It rewrites the
source archive as sorted USTAR inside a fixed-header, stored-DEFLATE gzip stream,
so neither host metadata nor the host's zlib implementation affects the bytes.
Before invoking the backend, it captures the reviewed package bytes and the
project's package identity, version, Python range, dependencies, extras, console
scripts, and license. The resulting pure-Python wheel must contain exactly those
package bytes plus the expected generated metadata; unexpected top-level modules,
`.pth` files, `.data` scripts, or extra metadata fail the build. Critical
`METADATA`, `WHEEL`, entry-point, top-level-package, and license values must match
the captured source expectations. Only backend-generated text metadata receives
CRLF-to-LF normalization; reviewed package payloads remain byte-exact.

Portable path validation is applied to every component before writing: traversal,
drive-relative names, alternate data streams, Windows device/invalid names,
control or surrogate characters, non-NFC names, oversized components, and
case-insensitive file/directory hierarchy collisions fail closed. Git snapshots
are staged and published transactionally so a later blob or size failure cannot
leave a partial source tree. Links, special files, invalid records or signatures,
excessive members, expanded data, and canonical output size also fail closed.
Only the first artifact pair is published to the requested output directory, and
only after the independent byte-for-byte comparison succeeds. Matching local and
cross-platform rebuilds prove deterministic packaging of the reviewed commit
inputs; they do not replace provenance or source review.

Both CI package-smoke and the publishing job test their freshly built source
archive before installation/publication:

```shell
python scripts/check_sdist.py --dist-dir dist
```

Use the hash-locked CI or release environment. This gate requires exactly one
archive, safely extracts regular files/directories into a new disposable
directory with platform-independent path, member-count, and expanded-size
validation, and checks runtime/data, scripts, tests, schemas, documentation,
workflow/governance files, and locks against the same immutable Git commit used
by the builder. The verifier materializes Git blob bytes instead of trusting the
mutable checkout, so host line-ending conversion, local modifications, and
untracked files cannot change the expected inputs. Missing, modified, or
unexpected inputs fail before execution. Only known non-code setuptools metadata
may be additional. Root-level modules, stray source files, and bundled bytecode
are rejected; local generated bytecode is not required in the archive.

It then runs the bundled tests and the unchanged coverage threshold with the
archive's own working directory, `src`, and configuration. Missing tests cannot
silently produce a green empty test run, and the runner's editable checkout
cannot substitute for the archive's source. Each subprocess has a five-minute
timeout and any test/coverage failure stops the gate. The extracted directory
is removed afterward, including on failure.

This executes test code and is **not an untrusted-archive sandbox**. Run it only
against a locally built archive from the reviewed commit; downloading an unknown
archive and passing this helper is not independent security review.

The workflow installs the locked runtime dependencies, installs the pinned
build backend from `requirements-build.lock`, and validates both freshly built
artifacts in clean environments before publishing. A separate 15-cell matrix
creates CycloneDX SBOMs from `requirements-runtime.lock` for each supported
OS/Python combination. Artifact filenames identify the environment; a 3.14
inventory must not be used as the complete inventory for a 3.11 installation.
Publication waits for the required validation workflows and all SBOM jobs,
includes all fifteen inventories, writes SHA-256 checksums, and attests the
build provenance. A release is not
considered supported until its artifacts have also been installed and
validated from the published release itself.

For a release declaring Python 3.11–3.15, the required asset inventory is
exactly 18 files: wheel, source archive, checksum manifest, and 15 SBOMs; extra
assets fail both the publishing boundary and repository audit. The audit derives
the inventory from that release commit's classifiers; older releases declaring
only 3.11–3.14 still require 15 assets, not retroactive 3.15 inventories.

Alpha/Beta package metadata and prerelease/development version identifiers must
be published as a GitHub prerelease. Publication uses `--verify-tag` so a tag
removed after validation cannot be silently recreated by the release command.
Existing published assets are never overwritten by a rerun: release a new version
when artifacts change. Every existing release through `v0.4.0a3` predates these
safeguards and currently reports `immutable: false`.

The current `gh release create` command attaches every asset before publication:
GitHub CLI creates a draft, uploads the files, and then publishes it, which is
compatible with repository release immutability. Do not replace this with a
publish-then-upload sequence. After publication the workflow checks the release
metadata and fails unless `immutable` is exactly `true`; API failures and missing
or malformed evidence also fail. This check cannot undo a publication made while
the repository setting was disabled. Preserve that release, correct the setting,
and prepare a new version. Do not delete or replace published assets to make a
failed verification look successful. See the
[GitHub CLI release-create reference](https://cli.github.com/manual/gh_release_create).

Immediately after publication, rerun the production-settings audit without
`--prepublication`:

```shell
python scripts/check_github_production_settings.py \
  --repo Yunushan/cpe-access-atlas
```

Every result must now be `PASS`; `DEFERRED` is accepted only before the candidate
exists. A release with a failed or unverifiable postpublication audit is not a
supported release, even if the publishing job itself completed.

## Published-artifact verification

The solo maintainer may perform this verification. Use a fresh environment and
compare the downloaded artifacts against the reviewed source and trusted
provenance; "independent verification" here means evidence separate from the
build's own success report, not a mandatory second person. External review is
welcome when available but is not required to publish under this policy.

The protected release workflow also performs a post-publication copy of every
release asset into a fresh runner directory. It compares the downloaded
inventory with the exact wheel, source-archive, and OS/Python SBOM list, checks
`SHA256SUMS`, and verifies an attestation for the checksum manifest and every
listed asset. The verification constrains the signer workflow, tag ref, reviewed
commit, and runner type. A failed download, byte check, or attestation check
fails the publication job; it never replaces or deletes an immutable release.

Record the approved release commit from the reviewed source, not just a later
lookup of a mutable tag. Download the published assets into a new isolated
directory. Do not install or execute them until verification succeeds. The
following Bash example uses placeholders: replace `vX.Y.Z` and
`REVIEWED_COMMIT_SHA` with the actual approved tag and full commit ID.

```shell
gh release download vX.Y.Z --repo Yunushan/cpe-access-atlas \
  --dir .tmp/release-verification/vX.Y.Z/dist
gh attestation verify .tmp/release-verification/vX.Y.Z/dist/SHA256SUMS \
  --repo Yunushan/cpe-access-atlas \
  --signer-workflow Yunushan/cpe-access-atlas/.github/workflows/release.yml \
  --source-ref refs/tags/vX.Y.Z --source-digest REVIEWED_COMMIT_SHA \
  --deny-self-hosted-runners
```

Repeat attestation verification for the wheel, source archive, and every SBOM.
These flags constrain the signing workflow, source ref/commit, and runner type;
the command verifies the local artifact bytes against signed attestations.
See the [GitHub CLI verification reference](https://cli.github.com/manual/gh_attestation_verify).

Inspect the authenticated checksum manifest: it must list each expected wheel,
source archive, and OS/Python SBOM exactly once, with no unexpected paths. The
current workflow records `dist/`-prefixed filenames. From the isolated directory
containing `dist`, verify all listed SHA-256 values; for example, on Linux,
`sha256sum --check --strict dist/SHA256SUMS`. Any missing asset, malformed
manifest line, mismatch, untrusted signer,
wrong source commit, or unavailable attestation means verification is incomplete.

Only then repeat clean wheel/sdist installation and catalog validation using
hash-verified dependency locks from that same reviewed release commit. Preserve
verification results and cross-platform CI evidence. Checksums alone establish
consistency, not authorship; attestations do not replace source review or device
compatibility and recovery testing.

## Security incident and release revocation

Use the complete [operational-resilience runbook](operations.md) for incident
classification, containment, sensitive-evidence handling, recovery validation,
consumer communication, and closure. The summary below does not replace its
fail-closed steps or prove that a recovery exercise has occurred.

Handle a suspected vulnerability, credential compromise, or malicious release
privately until coordinated disclosure is safe. Freeze publication, preserve
logs and immutable artifacts, rotate affected GitHub credentials, and review
workflow, environment, ruleset, and audit-log changes. Do not delete or replace
an immutable asset or move its tag: publish any correction under a new version.

Use a private GitHub security advisory for assessment and the fix when
available. Mark affected public releases with a clear warning, update the
supported-version statement, and publish a patched release through the complete
protected workflow. Re-run provenance, checksum, clean-install, repository-
settings, and post-publication verification. If provenance or signing authority
may be compromised, explicitly state that prior attestations are not trusted
until the compromise boundary has been established. After disclosure, retain a
timeline and corrective-action record without exposing reporter or device data.

## Dependency lock maintenance

The lock files use exact versions, conditional dependency markers, and SHA-256
distribution hashes. CI and release installs require those hashes. Changes to
dependency constraints and their lock files must be reviewed together.
Dependabot monitors the direct Python constraints in `pyproject.toml`, but its
pip ecosystem support does not regenerate these custom `requirements-*.lock`
outputs. Treat an automated constraint pull request as an input to this manual,
reviewed lock-regeneration procedure rather than as a complete dependency
update.

The current locks were resolved with uv 0.12.10. After updating the intended
exact version pins, regenerate every affected file, for example:

```shell
uv pip compile requirements-runtime.lock --universal --python-version 3.11 \
  --generate-hashes --no-annotate --output-file requirements-runtime.lock
```

Repeat for build, CI, security, and release locks when their dependency sets
change. This command preserves existing exact pins and fills their transitive
closure; it does not automatically upgrade an explicitly pinned requirement.
Keep shared pins consistent across lock files. Review any newly resolved
transitive packages and run vulnerability audits before accepting them.

After changing an exact pin in an existing hashed file, also pass
`--upgrade-package PACKAGE` for that package when compiling. This refreshes
its distribution hashes instead of retaining hashes from the old version.
Verify the regenerated locks with real `--require-hashes` installations.

Validate clean installs and dependency consistency across the supported matrix,
including Python 3.11/3.12's typing-extensions dependency and platform-specific
release-tool dependencies. `pip check` alone does not prove a complete lock:
all active dependencies must also have exact, hashed lock entries.

Repository administrators should also keep these GitHub controls enabled:

- pull requests and passing CI, security, and CodeQL checks on `main`, with
  zero mandatory approvals under the solo-maintainer policy;
- annotated, protected release tags and no direct pushes to `main`;
- release immutability enabled, with the latest publication confirmed immutable;
- Dependabot security updates and alerts;
- secret scanning and push protection;
- a private security reporting channel.

# Security policy

## Reporting a vulnerability

Do not publish an unpatched device vulnerability, working exploit, private
configuration backup, subscriber credential, serial number, certificate,
session cookie, or ISP management endpoint in a public issue.

Use **Report a vulnerability** on the repository's
[Security Advisories page](https://github.com/Yunushan/cpe-access-atlas/security/advisories)
when private vulnerability reporting is enabled. External reporters cannot
rely on a maintainer-only advisory-draft link as a confidential intake channel.

If that button is unavailable, no private reporting address is currently
advertised. Use the
[Request a private security contact](https://github.com/Yunushan/cpe-access-atlas/issues/new?template=security-contact.yml)
form, with **no vulnerability details, exploit, attachment, or device data**.
Wait for a confidential channel before sending the report. Administrators must
enable and test private reporting before designating a release production-ready.

## Supported project versions

Only the latest published GitHub release receives security fixes during the pre-1.0
phase.

## Data handling

The CLI does not collect telemetry. The optional `doctor` network check accepts
exactly one private IP literal and tests only explicitly listed TCP ports. It
performs no discovery, subnet scan, authentication attempt, or configuration
change.

The separate `web-evidence` operation requires both the ownership/authorization
and local-HTTP acknowledgements. It performs exactly one normal web-console
login against that private IP and then makes only bounded, read-only requests
to a fixed set of status and advertised page-view endpoints. The login uses the
router's plaintext HTTP service on port 80: the password itself is not sent,
but the username, password-derived challenge response, session token, and
session cookie have no TLS protection. An attacker on the local network path
could observe or alter them, hijack the authenticated session, or use captured
login material in password-guessing attacks. Run this operation only on a
trusted, isolated LAN and use a unique router password.

Session cookies are kept only in process memory and are never included in the
evidence output. The client does not call a logout endpoint, so the router-side
session may remain valid until the device expires or otherwise invalidates it.
The operation performs no configuration change and makes no login retry.

Never commit:

- exported modem configuration files;
- packet captures from a live subscriber connection;
- PPPoE, SIP, TR-069, Wi-Fi, or web-interface credentials;
- private keys, certificates, device serial numbers, or subscriber IDs.

## Automated checks

Configured pull-request and push workflows check for dependency
vulnerabilities, dependency-file changes, and Python CodeQL findings. Release
artifacts are generated with a CycloneDX SBOM, SHA-256 checksums, and GitHub
build-provenance attestations once the release workflow is enabled for a
protected tag.

"No open CodeQL alerts" is not a claim of zero findings. High/critical alerts
dismissed as accepted compatibility risks must exactly match the numbered,
expiring policy in `.github/codeql-accepted-risks.json` on the audited ref and
commit, and the selected exact instance must itself remain dismissed. The two
inventories are gated separately; an unlisted, missing,
changed, fixed-but-still-listed, or expired acceptance fails release validation.

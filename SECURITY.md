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
advertised. Open an issue containing only a request for a private security
contact, with **no vulnerability details, exploit, attachment, or device data**.
Wait for a confidential channel before sending the report. Administrators must
enable and test private reporting before designating a release production-ready.

## Supported project versions

Only the latest tagged release receives security fixes during the pre-1.0
phase.

## Data handling

The CLI does not collect telemetry. Its optional network check accepts exactly
one private IP literal and tests only explicitly listed TCP ports. It performs
no discovery, subnet scan, authentication attempt, or configuration change.

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

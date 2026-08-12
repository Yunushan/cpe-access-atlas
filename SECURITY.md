# Security policy

## Reporting a vulnerability

Do not publish an unpatched device vulnerability, working exploit, private
configuration backup, subscriber credential, serial number, certificate,
session cookie, or ISP management endpoint in a public issue.

Until a private reporting address is configured, open a minimal [GitHub
Security Advisory draft](https://github.com/Yunushan/cpe-access-atlas/security/advisories/new)
in the repository after publication. Include only enough metadata to identify
the affected project component; keep device secrets and ISP data out of the
report.

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

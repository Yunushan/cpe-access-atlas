# Exact-device qualification

All currently bundled recipes remain unverified research records. No physical
validation was supplied during the September 17 production-readiness work.
This document defines evidence needed to change that status; it is not evidence
that an experiment has happened or instructions to import an unverified file.

## Before any device change

Use an owner-authorized spare or otherwise recoverable unit. Record exact ISP,
model, hardware revision, installed firmware and the source of those facts.
Keep original exported files and device identifiers private and separate from
generated artifacts. Establish a recovery procedure for this exact target and
verify it before considering an import. If recovery cannot be established,
stop at read-only evidence collection; do not experiment on a service-critical
router merely to complete this checklist.

The present CLI never performs imports, flashing, firmware execution or an
access-enablement operation. Its output cannot substitute for these observations.

## Required observations

| Qualification key | What the reviewed report must establish |
|---|---|
| `hardware` | Physical revision and firmware identify this exact catalog target |
| `access` | Independent verification of the claimed level; web admin, shell and UID 0 are distinct |
| `recovery` | Tested return to the original usable configuration on this exact build |
| `services` | Baseline and post-experiment WAN, DNS, Wi-Fi, and applicable IPTV/VoIP behavior; state which services are not applicable |
| `wan_isolation` | Privileged management remains unavailable from the WAN; no management exposure was added |
| `config_import` | For a configuration-codec claim, the device accepts the artifact and preserves unrelated baseline settings |
| `independent_reproduction` | For stable status, a separate reproduction identifies the same target and confirms the claimed outcomes |
| `tested_on` | Date the documented observations were completed, at or before the evidence review |

Record the tool version, exact reviewed commit, high-level procedure, expected
and observed outcomes, interruption/failure results and recovery outcome. A
matching SHA-256 or embedded firmware string establishes only artifact evidence;
it does not authenticate firmware, prove safe flashing, or show that the device
will accept a generated configuration.

## Evidence records

`qualification` maps observation names to HTTPS URLs already listed in the
recipe's `evidence`. One sanitized report can support several observations if
it explicitly records each one. Reports must identify the exact target, not
just the device family. A general vendor product page is insufficient for
recovery, root access, configuration acceptance or service preservation.

The loader checks required fields, references and dates, while maintainers
review what the evidence proves. A record must remain researching/blocked when
an observation is missing, contradictory, or inferred from another model/build.
Do not insert hypothetical results or mark evidence complete to make validation
pass. `apply` remains unavailable even when a catalog record is qualified.

Only sanitized observations belong in a contribution. Exclude original backups,
passwords, serial numbers, MAC addresses, subscriber identifiers, private keys,
certificates, packets, and ISP management endpoints. Automated redaction is
assistance; manually inspect the complete report and every attachment.

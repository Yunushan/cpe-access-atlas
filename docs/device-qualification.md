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
| `wan_isolation` | Record the local Remote Access and Global/INTERNET firewall states, then separately verify that the tested management paths are unreachable from an authorized network outside the LAN and VPN both before and after the experiment |
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

Before a recipe can be marked `verified` or `stable`, it must also contain one
`qualification_records` entry for every required observation. Each entry names
the observation and evidence URL, records the test date, and states the
expected outcome, observed outcome, interruption or failure result, and
recovery outcome. The loader checks that records are unique, link to the
recipe's evidence, and are not dated after the review. `stable` additionally
requires an independent-reproduction record. These checks make the evidence
shape explicit; they do not authenticate the report or replace human review.

For a `verified` or `stable` recipe, the `wan_isolation` record must also
capture both `_baseline` and `_post` values for
`ipv4_remote_access`, `https_remote_access`, `icmp_remote_access`,
`global_firewall`, and `internet_wan_firewall`. Each value is `on`,
`off`, `not_present`, or `unknown`; `unknown` cannot qualify the device.
IPv4 and HTTPS remote management must be `off` or `not_present` at both
times. The same record must give an
`external_test_evidence_url` distinct from its local-settings
`evidence_url`; both URLs must be listed in the recipe's evidence. Record
`external_test_vantage` as `outside_lan_and_vpn`,
`external_target_path_verified` as `yes`, a nonempty
`external_test_scope`, and `external_baseline_result` and
`external_post_result` as `unreachable`. The external report must describe
the management protocols and paths tested, how the target path was confirmed
without publishing an address, and any upstream NAT or filtering limitations.
The record's `tested_on` is the completion date of these observations. A
local setting of `off`, including Remote Access, is not an external
reachability result. A negative test through an unverified target path is
indeterminate. If either firewall is `off` before or after, the reviewed
report must explain the resulting risk and any compensating controls; do not
silently count it as
proof of isolation. These results cover the tested paths and vantage, not
every possible ISP-side route.

The loader checks required fields, references and dates, while maintainers
review what the evidence proves. A record must remain researching/blocked when
an observation is missing, contradictory, or inferred from another model/build.
Do not insert hypothetical results or mark evidence complete to make validation
pass. `apply` remains unavailable even when a catalog record is qualified.

Only sanitized observations belong in a contribution. Exclude original backups,
passwords, serial numbers, MAC addresses, subscriber identifiers, private keys,
certificates, packets, public and private IP addresses, and ISP management
endpoints. Automated redaction is
assistance; manually inspect the complete report and every attachment.

# CLI output and exit status contract

The initial machine-readable output contract is version **1**. Query it without
loading the catalog, reading a private file, or contacting a device:

```shell
cpe-atlas --output-contract-version
```

This contract version is independent of the package version reported by
`--version`. Version 1 preserves the existing top-level JSON objects and arrays;
it does not wrap them in a new envelope. Consumers should ignore additional
object fields, use field names rather than ordering, and accept additional
observational status values conservatively. Removal or incompatible type or
meaning changes to documented fields require a new contract version. Package
release notes identify additive fields and new observational statuses.

Text, whitespace, translated names, catalog counts, evidence links, and human
error wording are not stable machine interfaces. JSON goes to standard output;
command errors go to standard error. A failed command is not guaranteed to emit
JSON. Parse the complete JSON document only after checking command completion.
Do not interpret a process exit code, report hash, or observed marker as device
authorization, firmware authenticity, import acceptance, or root access.

## JSON command shapes

| Command | JSON selection | Top-level shape and interpretation |
|---|---|---|
| `providers` | `--json` | Array of provider records containing `id`, `name`, `country`, `status`, and `aliases` |
| `devices` | `--json` | Array of public listing records; `provider_id`, `vendor`, `model`, `official_name`, `category`, `network_technology`, `source_ids`, and `source_urls` are inventory, not compatibility claims |
| `recipes` | `--json` | Array of target records with status, exact catalog dimensions, access, capabilities, blockers, review date, and qualification evidence |
| `status` | `--json` | One target record with the same shape as an element of `recipes` |
| `evidence` | `--json` | Array of public evidence records containing `title` and `url` |
| `plan` | `--json` | Object containing `recipe_id`, `status`, `hardware_revision_status`, and `decision`; a STOP includes `reason` and `next_evidence`, while REVIEW REQUIRED includes `note` |
| `root-readiness` | `--json` | Object containing `target`, `decision`, `checks`, `blockers`, `required_before_any_mutation`, `device_io_attempted`, and `config_or_firmware_written`; `firmware_artifact` appears only when an artifact was supplied |
| `firmware-inspect` | `--json` | Object with size/hash, observed `version_strings` and `markers`, supplied expectations, and nullable matching results |
| `web-evidence` | Always JSON on success | Object with `target` and `web_evidence`; output is sanitized observations, never raw pages or credentials |
| `uart-evidence` | Always JSON on success | Object with `target` and `uart_evidence`; output is bounded offline observations, never a root verification |

Target records contain `id`, `status`, `confidence`, `isp`, `device`,
`hardware_revision`, `hardware_revision_status`, `firmware`, `access`,
`capabilities`, `blockers`, `last_reviewed`, `qualification`, and
`qualification_records`. They expose reviewed catalog assertions, not a live
identity check of the unit selected by the operator.

`web_evidence.host` retains the supplied private target IP. Sanitized output
excludes credentials, cookies, raw pages, and HTML input/parameter values; it
does not make the report suitable for publication without manual review and
removal of private addresses. `authenticated: true` records an accepted login
response and collection without an observed HTTP 401 or return to the login
page. It does not prove firmware identity or access to every page: a 403 can
legitimately report an authenticated account's lack of authorization. An HTTP
401 during collection fails the command without retrying the login or emitting
a successful report. A body shorter than its effective declared HTTP length
also fails rather than becoming incomplete successful evidence.

From 0.4.0a9, `web_evidence.transport` is `local-https` for the default verified
HTTPS connection or `local-http` for explicitly acknowledged plaintext mode.
The additive boolean `tls_peer_verified` is true for a successful HTTPS report
and false for HTTP. `tls_trust_source` is `system` for the default HTTPS trust,
`provided-ca` when an independently trusted CA bundle was supplied, or
`not-applicable` for HTTP. These fields describe the connection's transport and
trust selection, not firmware identity, root access, or device qualification.
No peer-certificate details are emitted. Consumers must handle unsupported
transport or trust-source values conservatively.

HTTPS uses port 443, TLS 1.2 or newer, certificate-chain validation, and target-IP
identity validation. `--tls-ca-file` accepts at most 65,536 bytes of
certificate-only ASCII PEM with at most eight certificates; it retains IP
validation. Legacy port-80 HTTP requires both `--transport http` and
`--acknowledge-local-http-authentication`. Contradictory transport options fail
before password input or network access. No redirect, retry, or fallback is
performed, and TLS setup shares the whole-request deadline. Verification errors
do not produce a successful report with `tls_peer_verified: false`.

Firmware matching results may be null when no corresponding expectation was
supplied. `firmware_evidence_matches` concerns strings and an optional supplied
hash; `firmware_identity_verified` remains false in this release. These fields
are not interchangeable. Unknown checks, null values, and missing evidence
cannot qualify a device.

UART `firmware_identity_status` is `not-observed`, `different-build-observed`,
`matched`, or `conflicting-builds-observed`. `matched` means only that the unique
observed build matches the supplied expectation, case-insensitively. A capture
containing the expected build and another build is conflicting. Any future
unknown status must be treated as unqualified. `root_access_verified` remains
false even if the log contains a shell prompt or UID-zero marker.

## Exit status

| Exit | Meaning |
|---:|---|
| 0 | The selected operation completed; its catalog or evidence may still describe a blocked or unverified target |
| 1 | An explicit firmware/hash check failed, `root-readiness` decided STOP, catalog validation failed, or a generic filesystem/text operation failed; distinguish these by the selected command and available JSON |
| 2 | Invalid arguments, missing parser-required options, policy/catalog/codec/protocol input, or a sanitized domain error; this includes missing config compatibility/legacy-crypto acknowledgements |
| 3 | Explicit ownership/private-file authorization or local-HTTP acknowledgement was refused; `apply` refuses a valid target request with 3 because no mutating adapter exists, while invalid arguments/catalog lookup still return 2 |
| 4 | An output operation was refused, including an existing destination or the application-required `redact --output` option absent |
| 130 | Interrupted by the operator; no automatic retry was attempted |

For `web-evidence`, missing ownership or the acknowledgement required by
explicit HTTP mode returns 3. HTTPS with the HTTP acknowledgement, HTTP with a
CA file, and invalid CA material return 2 before secret input or network access.
Ownership is checked before a CA file is read. The HTTPS default does not
require a local-HTTP acknowledgement.

`plan` renders a decision successfully with exit **0 even when it says STOP**.
Read `decision`; do not chain a device action after a zero exit from `plan`.
`root-readiness` reports STOP with exit 1. `status` returns 0 for a recognized
blocked record, but returns 2 when no exact recipe exists. `doctor` with probing
returns 0 after completing its observations even if ports are closed. No exit
status unlocks `apply`.

For automation, select the expected contract version, use an explicit reviewed
package version, require the documented fields, and treat every unsupported
decision or status as unqualified. Save reports only in a private trusted
directory, and manually review evidence before sharing it.

## Observed identity and unresolved catalog keys

For the current Türk Telekom H3600P record, `V9.0` is a provisional catalog key;
its hardware status remains unresolved. The repository's observed UI field is
`V9.0.7`. Do not change that observation or infer the physical board revision to
make it match the catalog. A request with `V9.0.7` correctly receives no exact
recipe. Inspect public records with `recipes --json` and use the documented
catalog key only to inspect that unresolved research record. Neither path
establishes compatibility. Follow [device qualification](device-qualification.md)
and retain a sanitized board/UI mapping before changing the hardware status.

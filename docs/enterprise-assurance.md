# Enterprise assurance register

This register is separate from the 100-point production-readiness rubric in
[`production-readiness.md`](production-readiness.md). It does not add points to,
raise, or replace that score, and it states no register score. Its items cover
organizational, external, and device evidence that code changes cannot supply.

Each item has exactly one status:

- `PASS`: the evidence is linked and was reviewed.
- `FAIL`: the evidence was reviewed and does not meet the requirement.
- `NOT-EVIDENCED`: no reviewed evidence exists. This is the default.

An item is never marked `PASS` from configuration, intent, or a planned action.

## Register

| # | Item | Status | Owner | Evidence required to pass |
|---|------|--------|-------|---------------------------|
| 1 | Named second maintainer with repository administrator access | NOT-EVIDENCED | Owner | Dated access grant with the second maintainer's role, and a verified administrator login check |
| 2 | Written support service-level agreement | NOT-EVIDENCED | Owner | A published SLA. `SUPPORT.md` currently states that issues are handled on a best-effort basis by one maintainer, so it does not meet this item |
| 3 | Access continuity: offline recovery codes held by a second trusted person | NOT-EVIDENCED | Owner | Recovery procedure naming the second holder, with a dated handover record that contains no secret values |
| 4 | Independent reproduction of at least one release build | NOT-EVIDENCED | External reviewer | A reproduction report that rebuilds a published release from its source commit and matches the published checksums |
| 5 | External security review | NOT-EVIDENCED | External reviewer | An independent review report with scope, findings, and their disposition |
| 6 | Device qualification of at least one target | NOT-EVIDENCED | Authorized operator | The evidence set in [`device-qualification.md`](device-qualification.md) for a named device and firmware. The H3600P V9.0 mapping remains provisional |

## Current state

- As of 2026-10-29, the latest published release is the immutable alpha
  [`v0.4.0a15`](https://github.com/Yunushan/cpe-access-atlas/releases/tag/v0.4.0a15),
  built from commit `f7f43351a59e14f4983a591216cb67870193c93e`. Its
  [release workflow](https://github.com/Yunushan/cpe-access-atlas/actions/runs/40924940150)
  succeeded on its second attempt after a macOS SBOM job was cancelled before
  execution on the first. Maintainer verification of the downloaded artifacts
  does not satisfy the separate external-review requirement in item 4.
- Recovery exercise and incident tabletop records are templates in
  [`operations.md`](operations.md). Both are incomplete, and no exercise or
  tabletop has been performed.
- Items 1 through 6 remain `NOT-EVIDENCED` until the evidence above is reviewed.

## Updating this register

Change a status only when the linked evidence exists and has been reviewed. Record
the date, the reviewer, and the evidence location. Do not record secret values,
recovery codes, private report content, or device identifiers beyond the
sanitized references the device evidence set already permits.

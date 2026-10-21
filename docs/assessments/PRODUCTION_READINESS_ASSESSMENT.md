> **Archived 2026-10-21.** Stale snapshot of the v0.4.0a13 assessment (88/100), not current evidence. Current completion rule: `docs/production-readiness.md`. Separate assurance register: `docs/enterprise-assurance.md`.

# CPE Access Atlas - Production-Readiness Assessment and Path to 100

**Assessment date:** 2026-10-13  
**Repository:** Yunushan/cpe-access-atlas  
**Branch:** main  
**Main commit:** d5fde1219d6145d4f0129deb05adc32ad2f7a269  
**Latest immutable published release:** v0.4.0a13, source commit f5c2e4091e9c5cf660f46dc2868d071d727afdb6, published 2026-10-10  
**Final score:** 67/100 - not yet production-qualified  

---

## Executive Summary

- **Final readiness score: 67/100. Not yet production-qualified.** The software is strong; the gaps are in physical-device, operational-recovery, and support-continuity evidence.
- This assessment is an explicit engineering judgment. It is not a reliability probability, not a security certificate, and not a promise that code can ever bring the project to 100/100.
- **Scope is the whole project**, including the primary H3600P device claims in `docs/production-readiness.md` lines 35-54; this is not silently an offline-only assessment. Every target advertised as production-supported must qualify; all other listings remain research. The primary target is not removed from scoring to improve the number.
- **Prior on-disk scores of 87/88 and an interim 42 are superseded** under an inconsistent rubric with stale claims; the score change is not a measured regression. Those numbers are not carried forward; only the table of record below stands.
- **Exact point arithmetic and fixed milestones follow.** There are no hidden penalties and no double counting.

## Scorecard

| Category | Available | Earned |
| --- | ---: | ---: |
| Correctness and test assurance | 20 | 20 |
| Security and privacy | 15 | 15 |
| Release and consumer verification | 15 | 12 |
| Exact-device qualification | 25 | 3 |
| Operational recovery and support | 15 | 7 |
| Documentation and contracts | 10 | 10 |
| **Total** | **100** | **67** |

- Security earns full points for compliance with the currently stated controls; this does not claim the absence of residual risks.
- Device qualification earned 3 points for the enforced truthful qualification and refusal gates. Outstanding 22 points: hardware 3, access level 4, recovery 5, service preservation 3, WAN isolation 4, config acceptance 2, independent reproduction 1.
- Operations earned 7 points: runbook and freeze 3, live control audit 2, documented partial restore/attestation work 2. Outstanding: 5 points for a complete drill and 3 for actual continuity.
- Release missing 3 points: publish the current hardening on main (2) and an independent published-download install receipt (1).
- Evidence-source distinction: the docs acknowledge a partial restore; a full drill is not established. Nothing here claims every backup was personally verified.
- Correctness and test assurance (20/20) rests on the exact-commit CI results and the fresh local read-only checks described below; coverage is not proof against bugs.

### Category details

- Correctness and test assurance (20/20): all exact-commit CI jobs green at CPython 3.11-3.15 with 100% branch coverage, plus clean local validate, ruff check and format checks in this read-only review; nothing outstanding in this category.
- Security and privacy (15/15): the live GitHub settings check passes 20/20 with private reporting, pinned Actions, and no open alerts; two accepted CodeQL compatibility risks are tracked with a documented re-review date. Full points mean the stated controls are in place, not that residual risks are absent.
- Release and consumer verification (12/15): immutable a13 with 18 assets, byte verification and provenance are credited; the missing 3 points are the unshipped hardening on main (2) and the unproven consumer-side install from published downloads (1).
- Exact-device qualification (3/25): the truthful qualification and refusal gates earn 3; the remaining 22 points are the hardware, access, recovery, services, isolation, config-acceptance, and independent-reproduction evidence that Phase C will re-score.
- Operational recovery and support (7/15): runbook, freeze, live control audit and documented partial restore/attestation work earn 7; the missing 8 points are the completed drill (5) and real continuity (3) that Phase B will re-score.
- Documentation and contracts (10/10): docs, contracts, and the explicit qualification and support statements are complete and truthful; nothing outstanding.

## Verified Evidence

### Live GitHub production settings check

- `python -B scripts/check_github_production_settings.py --repo Yunushan/cpe-access-atlas` exited 0 with 20 PASS results. Exact main and 18 control-file blobs matched.
- Private reporting ENABLED. Main, tag, and environment protections are active under the solo-maintainer policy with no bypass; mandatory review is not required.
- SHA-pinned Actions and read-only workflow defaults; dependency graph, Dependabot, and secret scanning enabled; no open Dependabot, CodeQL, or secret alerts.
- Two dismissed HIGH CodeQL compatibility risks are valid acceptances with next review on 2027-03-18 (`.github/codeql-accepted-risks.json` lines 5-49): config vendor key derivation and web challenge-response. Full security points do not erase these risks.

### CI on main (commit d5fde12)

- Main CI run https://github.com/Yunushan/cpe-access-atlas/actions/runs/38447825124: 15 OS/Python jobs plus package-smoke and cross-platform-artifact-reproducibility runs, all SUCCESS.
- On the same SHA: Secret scan 38447825198, Security audit 38447825128, CodeQL 38447825138, DCO 38447825141, all success.
- Main CPython 3.15 logs read via gh API: Ubuntu job 115470730100, Windows 115470730275, macOS 115470730287, all explicitly CPython 3.15.0 final. Each ran 662 tests OK (skips: 18 Ubuntu, 15 Windows, 18 macOS). Coverage: 4995 statements, 0 missed, 1916 branches, 0 partial, 100%.
- The bundled source archive runs the same passing coverage. Do not conflate skips with test-run counts; coverage is not proof against bugs. Reproducibility evidence is 3 OS builds at 3.15, not 15 builds.

### Fresh local read-only checks

- `python -B -m cpe_access_atlas validate` PASS.
- Exact-target plan with `--isp turk-telekom --model H3600P --hardware-revision V9.0 --firmware 'H3600P V9.0 TTN.10_260210'` returned STOP, no substitution.
- `python -B -m ruff check --no-cache src tests scripts` PASS; `python -B -m ruff format --check --no-cache src tests scripts` PASS (48 files already formatted).
- Bounded in-memory unterminated sensitive XML check PASS.
- Full suite, typecheck, and builds were verified via the existing exact-commit CI; they were not freshly rerun locally in this read-only audit.
- An initial optional-inspector ImportError referencing `load_catalog` was an agent inspection typo; the corrected calls are `load_recipes` and `load_providers`. Not a repository defect.
- Real counts: 62 recipes (61 researching, 1 blocked, 0 verified/stable), 7 providers.
- These local checks are read-only by design; writing experiments, hardware operations, and drills are out of scope for this review and are covered by Phases B and C.

### Release run (v0.4.0a13, commit f5c2e40)

- Release run https://github.com/Yunushan/cpe-access-atlas/actions/runs/38058034991 succeeded: validate-release job 114232802149 (clean built-wheel and sdist installs, and more) success; publish-release job 114233926848 success, including Verify published asset bytes and attestations.
- The current release is immutable (true) with 18 required assets: wheel, sdist, SHA256SUMS, and 15 OS/Python SBOMs.
- `.github/workflows/release.yml` lines 509-570: downloaded checksum and inventory plus provenance constrained by signer workflow, tag, source digest, and runner type. These checks ran successfully; they are not metadata-only.
- Main is exactly one commit ahead of the release; the decoder/UART bounds and TLS fix are not shipped in a13.
- Independent install from the published downloads is not established in this review: prepublish installs plus postpublish bytes/provenance are distinct from the separate consumer procedure in `docs/release.md` lines 303-352. This is not a claim that release validation is missing or that no CI exists.

## Findings and Priorities

### P0: Confirmed qualification gap (22 points)

- Target recipe `src/cpe_access_atlas/data/recipes/tr_turk_telekom_zte_h3600p_ttn10_260210.json` lines 5-53 is blocked: hardware revision unresolved (V9.0 vs observed UI V9.0.7) with no authoritative mapping; no root, recovery, import, services, or isolation qualification.
- Citations: `docs/device-qualification.md` lines 23-87 and `docs/production-readiness.md` lines 44-54.
- This is not claimed as a code vulnerability. Keep `apply` unavailable and the target blocked.

### P1: Incomplete operational drill (5 points)

- `docs/production-readiness.md` lines 56-66 acknowledge the USB restore/attestation is partial and do not complete reporting, authority, custody, or device.
- `docs/operations.md` lines 158-177: the seven steps require real dated receipts. Enabled private reporting is not a tested receipt; a green routine main is not a restoration exercise.

### P1: Support continuity (3 points)

- `SUPPORT.md` lines 8-13, `docs/operations.md` lines 9-14 and 48-54, and `docs/production-readiness.md` lines 67-70: no SLA and no substitute commander; best-effort support is unfit for unattended or business-critical use.
- A real, proportionate support and authority arrangement is required. Optional peer reviews are not penalized; no enterprise hosted features are invented.

### P1: Release gap (3 points)

- Difference between main and the locked release plus the unknown consumer-install receipt (release section above).

### Non-findings

- No new exploitable source defect was established; this is not proof that none exist.
- Rejected interim XML data-loss finding: `_redact_xml` (`src/cpe_access_atlas/redaction.py` lines 653-696) with explicit conservative regression tests (`tests/test_redaction.py` lines 1052-1061) intentionally suppresses ambiguous tails; an unconditional append could leak secrets.
- The cookie-bounds proposal was not a defect.
- No deductions for: absence of PyPI, GPG signing, a mandatory independent PR reviewer, the mere alpha label, or absence of ISO/SOC2.

### Score arithmetic

- 20 + 15 + 12 + 3 + 7 + 10 = 67/100.
- Phase A (release current hardening plus consumer receipt) +3 to 70.
- Phase B (complete drill plus real continuity) +8 to 78.
- Phase C (real-device qualification) +22 to 100.
- Milestones are exactly as stated; no hidden penalties and no double counting.
- No milestone is claimable before its evidence exists; if a gate regresses or evidence goes stale, that category reverts to what the evidence currently supports.

## Action Plan

Milestones below assume no regression and evidence as currently reported. The exact point tables above are fixed; there are no hidden penalties.

How to act on this document:

- Phase A is the only phase reachable by maintainer automation alone; execute it first while CI is green on main.
- Phase B requires the account owner plus a human drill and must precede any claim of recovery or continuity.
- Phase C requires an authorized operator with recoverable hardware and an independent reproducer; its 22 points remain unearned until the evidence exists. Phases A and B can earn their points separately.

### Phase A: +3 to 70 (publish current hardening; owner and maintainer automation sufficient)

- [ ] New version, changelog, and docs PR includes the hardening now on main; do not reuse, move, or overwrite immutable a13.
- [ ] Full exact-candidate gates pass, including CPython 3.15 final.
- [ ] Fail-closed candidate rotation per `docs/github-production-settings.md` lines 176-198.
- [ ] Pass the prepublication audit, publish only through the protected workflow, then pass the complete postpublication audit.
- [ ] Fresh published downloads verified: checksum and provenance lock to the same commit; clean wheel and sdist install with pip check, catalog, and safe CLI.
- [ ] Retain a sanitized receipt of commit, tag, attempt, assets, commands, and expected and observed results.
- Acceptance: a genuine consumer release of the hardening plus separate installation proof.

### Phase B: +8 to 78 (complete operational drill; account owner plus human involvement)

Seven drill requirements:

- [ ] Benign confidential reporting receipt.
- [ ] Authorized recovery capability exercised; synthetic credential revocation with no real secrets.
- [ ] Separately retained verified source and release evidence; restore on a clean location with identity and custody.
- [ ] Workflows run on the restored commit.
- [ ] Independent external control audit.
- [ ] Rollback from a prior verified package.
- [ ] Sanitized incident and communications review.
- [ ] Preserve the useful partial evidence record and state what is missing rather than inventing it.
- [ ] A support and access-continuity arrangement appropriate to the production scope exists and is exercised; freeze if unavailable.
- No fake SLA and no mandated second review. Evidence may live in a controlled store; a public docs/evidence directory is not required.
- Acceptance: every item in `docs/operations.md` lines 163-174 is proven, and continuity is real.

### Phase C: +22 to 100 (real-device evidence; qualified authorized hardware operator plus independent reproducer)

Repeat the 22-point table with actual outcomes:

- [ ] Hardware identity 3: verified identities with actual tool version and commit dates.
- [ ] Access level 4: established access with documented expected and observed results.
- [ ] Recovery 5: proven before any risky step.
- [ ] Services 3: WAN, DNS, WiFi (as applicable), IPTV/VoIP.
- [ ] Isolation 4: before and after, local plus authorized outside LAN/VPN, with verified path and NAT limitations.
- [ ] Config acceptance 2: unrelated settings preserved.
- [ ] Independent reproduction 1: a second operator reproduces before anything is declared stable.

Constraints:

- Use only owner-authorized spare or recovery-tested hardware. If recovery cannot be established, stop at read-only evidence collection; do not proceed to device changes. Do not risk a service-critical unit merely to earn points. No internet scanning.
- Keep private originals outside Git; sanitize observations.
- Evidence must show actual tool version, commit dates, expected and observed interruption and failure, and recovery-evidence URLs. Schema shape is not validation truth; human review remains.
- All actual supported targets must qualify; research listings need not pretend to be supported. The primary target currently has no established method or recovery and may remain blocked; no honest timeline or guarantee is promised.
- Keep `apply` disabled, keep the exact-match gate, and keep the 100% tests; never weaken or reweight them for the score. Stable classification and support follow only after the gates and release revalidation, not a mere label change.

## Assessment Boundaries

- Inspected: production trust boundaries; input and resource bounds; config; redaction; private containers and private files; Windows network and TLS; catalog gates; tests, CI, packaging; ops and support docs.
- Not done: hardware authentication, import, flash, or root; account recovery and revocation drills.
- Published bytes were not freshly downloaded and installed locally in this review; CI checks were credited exactly for what they executed.
- No tracked source changes came from the audit; the final diff was empty and the initially untracked other docs were kept.
- A review worker briefly wrote and deleted an extra draft despite the read-only instruction; it is not a deliverable and not evidence.
- This saved report is the approved documentation-only exception. Remediation has NOT been executed or approved.
- Preserve current files ASSESSMENT_INDEX.md, ASSESSMENT_SUMMARY.txt, READINESS_SCORECARD.txt, and the .abacusai directory untouched; they may retain stale scores.
- Bottom line: 67 now; 70 after Phase A delivery; 78 after Phase B operations; 100 only after real-device Phase C, with the caveats recorded above.

## Conclusion

CPE Access Atlas is a professionally engineered research project: 100% coverage on exact-commit CI, clean lint, format, type, and build gates, hardened and auditable GitHub controls, immutable releases with provenance, and a fail-closed catalog that truthfully refuses unverified methods. None of that is in question.

At 67/100 the project is not production-qualified. The primary device target is blocked without an established method or recovery path, the operational drill is partial, and support continuity is best-effort. No amount of commits can substitute for qualified hardware work, a completed recovery exercise, and a real support arrangement, and no honest timeline is promised.

The path to 100 is exact: Phase A (release the current hardening with consumer install proof) to 70, Phase B (complete drill plus real continuity) to 78, and Phase C (repeat the 22-point device table with actual outcomes from a qualified authorized hardware operator and an independent reproducer) to 100. Until the evidence exists, the score stays where the evidence puts it: 67/100.

## Supersession and status

- This assessment (2026-10-13) supersedes the on-disk 2026-10-10 assessment and all interim drafts; nothing else in the repository is changed by it.
- Under the documentation-only scope, no code, workflow, or setting was modified and no remediation was executed, approved, or scheduled.
- The score stands at 67/100 until the evidence for Phase A, Phase B, or Phase C exists and is re-verified against the table of record above.

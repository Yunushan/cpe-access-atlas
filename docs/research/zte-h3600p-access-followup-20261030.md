# H3600P TTN.10 access research: October 30 follow-up

Reviewed: 2026-10-30. Repository baseline:
`ac46da90f67eb3d0cb7d8ed1f766d0a12fe50a8b`.

This review found additional public evidence and completed a synthetic codec
experiment. It did not establish privileged web access or a Linux root shell
for the owner's exact device. The strongest new web-access report concerns
Superonline; a separate exact-TTN.10 report describes a CWMP failure. Neither
provides an exact-build, recovery-tested access method.

This supplements the [earlier exact-build research](zte-h3600p-ttn10-260210.md),
which contains the pinned older firmware, CWMP, factory-mode, HTTPD, UART and
flash investigations. That note's historical observations remain dated. This
follow-up does not claim that every older link or artifact was retrieved again.
The [device qualification requirements](../device-qualification.md) and
[production readiness requirements](../production-readiness.md) remain unchanged.

## Exact target and completed work

| Item | Evidence and limit |
|---|---|
| Operator and model | Türk Telekom, ZTE ZXHN H3600P V9 |
| Firmware | `H3600P V9.0 TTN.10_260210` |
| UI hardware-version field | `V9.0.7`; physical-board mapping remains unresolved |
| Catalog hardware key | Provisional `V9.0`; it must not be substituted for a proven board revision |
| Existing exports | Two private encrypted type-4 exports retained from earlier work; neither successfully decrypted |
| Operational context | Active Internet gateway; no tested exact-target recovery path |
| Work in this review | Public primary-source research, source/metadata comparison, local synthetic CBC-framing experiment |
| Work not performed | Router connections, provisioning changes, imports, flash operations, execution of downloaded third-party executables or vendor/ISP messages |

No new private configuration, firmware, account, packet or hardware artifact
was acquired. No credentials or device identifiers belong in this report.
The recipe remains blocked; `apply` remains unavailable.

Five outcomes need separate proof: privileged server-authorized web operations,
an accepted SSH/Telnet login, a general Linux shell, device-originated numeric
UID 0, and persistent access with verified service preservation and recovery.
A menu named root, an ACS acknowledgement, `uname`, or a shell-shaped prompt
does not establish all five. The existing qualification gate specifies the
required exact-device observations.

## New public evidence

### Superonline ACS guide: web-access lead, no TTN.10 qualification

A first-person [Superonline H3600P V9 guide](https://techolay.net/sosyal/konu/zte-h3600p-v9-superonline-icin-basarili-root-erisimi.224059/)
describes using an ACS application to discover parameters, change management
and account state, and obtain a privileged web login. The guide text does not
identify `TTN.10_260210` or demonstrate a Linux UID-0 session, recovery, or
preservation of subscribed services. It involves device writes, including a
management-server change; it is not a passive account-discovery procedure.

The page rendered its publication time as “Dün 18:52” when reviewed on October
30. An October 29 date is an inference from that relative rendering, not
verified absolute publication metadata. A [separate thread by the same author](https://techolay.net/sosyal/konu/superonline-h3600p-v9-icin-guncel-root-erisimi-var-mi.223424/)
names Superonline `V9.0.3P10_TR`. That adjacent report must not silently supply
the successful guide's missing firmware identity.

An independent [October 17 owner report](https://techolay.net/sosyal/konu/superonline-zte-h3600p-tam-root-yetkisi-nasil-alinir.222245/)
also identifies Superonline `V9.0.3P10_TR`. Its author reports broader web
controls while SSH, Telnet and firmware-upload access remain absent. This is
firsthand evidence that the word root in these discussions can describe a web
permission increase without demonstrating a Linux shell. Replies making
broader claims are not treated as measurements of the owner's TTN.10 device.

The actionable lead is the existence of additional operator-specific account
and provisioning behavior to inspect in matching implementation. The evidence
does not justify transplanting Superonline parameter writes to Türk Telekom.

### Exact-build ACS failure report

[Issue 10 in ods-code/tr069acs](https://github.com/ods-code/tr069acs/issues/10)
explicitly names `H3600P V9.0 TTN.10_260210` and reports a CWMP Unknown error.
GitHub metadata records creation and last update at `2026-10-13T00:29:54Z`;
the issue was open with no comments at review. This is an exact-build failure
report, not a success procedure or proof that every CWMP route is impossible.
No credential-bearing attachment or device screenshot was used.

The phrase CWMP Unknown does not locate a failure in transport, TLS,
authentication, Inform parsing, data-model discovery, or parameter permissions.
Those layers need separate evidence. A new language, XML serializer, or ACS
implementation could fix an identified client defect; it cannot establish
which failure occurred from that label alone.

### The linked ACS tool has no published implementation in its reviewed tree

The [ods-code/tr069acs tree](https://github.com/ods-code/tr069acs/tree/fe63c183af2074d415d6c82ef57a100b1ee200b6)
at `fe63c183af2074d415d6c82ef57a100b1ee200b6` contains `README.md` and
`README_EN.md`, without application source. Release
[1.1.0](https://github.com/ods-code/tr069acs/releases/tag/1.1.0), dated May 20,
points to `9c35b82a12b8f0a0cadb029916a3182426a4a6c0`. Release metadata or a
binary checksum cannot supply a source review of its requests or side effects.
No release executable was downloaded or run.

The originating [Techolay article](https://techolay.net/bircok-isp-modeminde-calisan-root-yontemi/)
demonstrates a TP-Link EX530V workflow, not an exact H3600P TTN.10 test. Its
linked 1.0.0 release points to
`36bddc21c43c8ff8b052598dff66cc6ee4f068f8`. The article's broader title is not
firmware applicability evidence. Its security-software disabling instruction
was not followed and is not part of the recommended research path.

## Offline configuration-framing experiment

The earlier research identifies two CBC models: the H3600P reference resets
the cipher for each encrypted chunk, while the previously reviewed generic
utility decrypts concatenated ciphertext. This review tested how to distinguish
them without a router or a private backup. It did not recover a missing
personalization input or select the owner's actual firmware format.

The repository already has independent encrypted single- and multi-chunk
reference fixtures, including a split at byte 64. See the
[cryptography evidence](../config-cryptography.md#cross-implementation-test-evidence)
and `tests/test_config_interop.py`. This experiment expands boundary comparisons;
it is not evidence that encrypted multi-chunk regression coverage was absent.

### Construction and observations

The local probe manually constructed an inner compressed container with
`struct` and `zlib`, rather than calling the production encoder. Its plaintext
was synthetic XML: a `DB` element containing 100 numbered rows, each with a
`PublicCounter` equal to the square of its row number. The existing key
derivation was held constant with artificial inputs; it was not independently
tested by this experiment. No derived values or identity-like inputs are
published here.

For each split pattern below, the probe encrypted the same inner bytes once
with per-chunk CBC resets and once with continuous CBC. Intermediate splits
were AES-block aligned; only the final piece needed zero padding. It then
compared the entire reconstructed inner payload and the public decoder's
returned XML against their expected values. The continuous comparison used a
separate concatenated-ciphertext decryption. There were 18 cases, all satisfying
the experiment's assertions.

Offsets count plaintext bytes from the start of the inner compressed
container. Exact payload means every inner byte matched, including unused
inner-header padding. It excludes final AES zero padding discarded using the
declared chunk lengths.

| Split offsets | Encrypted chunks | Reset fixture: payload / XML exact | Continuous fixture: payload / XML exact in current decoder |
|---|---:|---|---|
| None | 1 | Yes / Yes | Yes / Yes |
| 16 | 2 | Yes / Yes | No / No |
| 32 | 2 | Yes / Yes | No / Yes |
| 48 | 2 | Yes / Yes | No / No |
| 64 | 2 | Yes / Yes | No / No |
| 80 | 2 | Yes / Yes | No / No |
| 16, 80 | 3 | Yes / Yes | No / No |
| 32, 64 | 3 | Yes / Yes | No / No |
| 48, 80 | 3 | Yes / Yes | No / No |

All nine reset fixtures returned the expected XML. Of the continuous fixtures,
the single-chunk case is equivalent under both policies. The split at byte 32
also returned the expected XML despite a different inner payload. The other
seven continuous fixtures produced controlled configuration errors, with no
uncaught failure.

At the byte-32 boundary, the incorrectly decrypted first block of the next
chunk falls entirely within unused compressed-header padding. The parser checks
the header CRC over bytes 0–23 and reads its CRC from bytes 24–27; bytes 28–59
are unused padding. Consequently, the XML and compressed-data checks can still
pass when those padding bytes differ. This inference follows from the observed
payload comparison and the baseline parser in `src/cpe_access_atlas/config.py`.

This is a discriminator-design result, not a newly proven firmware exploit.
XML success alone does not determine CBC chunk policy. Use several boundaries
that affect checked metadata or content, and compare full expected inner bytes
when available. Do not select a codec merely because it produces recognizable
XML, silently add an alternative-format fallback, or claim TTN.10 import support
from these synthetic outcomes.

The sanitized [experiment receipt](evidence/h3600p-cbc-framing-20261030.json)
records the baseline commit, local helper hash, UTC run time and all 18
observations. The helper was an ignored local research probe, not a shipped
command or a committed regression test. The receipt does not claim that it
contains independently reproducible source or a target-device fixture.

The local runtime was CPython `3.14.5`, PyCryptodome `4.2.0`, and zlib
`1.3.1.zlib-ng`. All 11 existing `test_config_interop.py` tests passed when
rerun with the normal Windows user token. Two earlier restricted-token runs
failed the CLI's private-artifact write check; the other ten tests passed in
each run. The successful rerun did not weaken private-file controls or change
source. These checks concern the stated local codec paths, not a full-suite,
platform-support or real-device qualification claim.

### New upstream decoder work has different model evidence

Post-October-4 changes to the generic utility are relevant leads to compare,
not a blanket fix for the owner's exports. The reviewed
[October 23 change](https://github.com/mkst/zte-config-utility/commit/e3a1a7f56c2df26a02f52f72b16173d0702d9ad0)
adds a bare type-4 path for SR7410, SR7110 and SR7115 without the normal outer
header or model wrapper. The
[October 19 change](https://github.com/mkst/zte-config-utility/commit/9a9be66d8c3739aa51ed299cf6394d3188b4cda4)
adds payload type 6. The retained H3600P exports were identified as type 4;
another platform's constants or a new payload number does not resolve their
personalization or establish their cipher policy. No upstream static key
material is reproduced here.

The [H3600P decoder issue](https://github.com/mkst/zte-config-utility/issues/137)
also received a comment on October 15. Its potentially sensitive body was not
inspected, so this review makes no claim about any proposed solution in that
comment. These retrieval limits rule out describing this work as an exhaustive
review of every newly posted artifact or method.

## Route selection and language/library choices

The order below ranks useful next evidence, not probability of success.
Historical source details remain in the earlier note. None of these routes is
qualified for the current active gateway.

| Route | What could advance it | Why it does not currently solve access |
|---|---|---|
| Supported provider account or diagnostic export | Exact-build account grant, documented capability, matching implementation or recovery material | No such grant or artifact was obtained; a support request is still a draft |
| Offline backup analysis | Same-device personalization input plus independently validated derivation, framing and XML | Missing input remains; older Digi compatibility is not TTN.10 validation |
| Configuration import | Validated baseline, understood account/service rows, exact importer behavior and tested recovery | Decryption alone cannot show accepted writes or service preservation; the local generator changes SSH fields, not privileged web accounts |
| CWMP/ACS | Accepted authorized session, implemented model and writable permissions, reviewed client behavior | New success report is Superonline; exact TTN.10 issue reports failure; linked binary has no implementation in the reviewed tree |
| TR-064 | Actual authorized configuration service, descriptor and action semantics | Generic product capability and ordinary UPnP services do not establish that endpoint on this build |
| Factory/debug service | Matching server code, challenge/proof, credentials, service lifecycle and identity | Other-model examples can require an existing superadmin; an acknowledgement is not initial access or UID 0 |
| Native web implementation | Exact HTTPD, dependencies and Lua handlers; reachable authorization/execution chain | Client JavaScript and old-model advisories do not establish server behavior or process UID |
| UART/bootloader/flash acquisition | Physical board identity, applicable read method, validated dumps and recovery on a spare | A header or boot prompt does not establish a shell, accepted image or same-device secret acquisition |
| Downgrade, temporary boot or alternate firmware | Authenticated matching image, boot/update acceptance, board support and tested restoration | No matching recoverable TTN.10 route was found; H3601P material is another target |

Python with the existing cryptography and parsing libraries remains appropriate
for bounded offline format experiments. An independent C implementation can
help compare digest or container behavior if its exact implementation is
reviewed. Rust or Go can provide an alternative parser and clearer resource
bounds. None supplies an unknown per-device input, server permission, accepted
boot image, or root process identity merely by changing language.

An SSH client library is useful only after a listener, authentication method
and authorized account exist. A standards-compliant ACS or XML library can
remove known client interoperability defects but cannot make an absent or
non-writable parameter available. Emulating a firmware userland would require
matching binaries, architecture and device dependencies; successful emulation
would still not prove real-device boot, privilege or service preservation.
No new library, language runtime or device adapter was added in this review.

## Recommended next evidence and prepared requests

First seek a supported account or exact implementation acquisition. Then choose
one route using its observed prerequisites. Repeating guessed menu paths or
cross-operator writes would not resolve the current uncertainty. The following
requests are prepared text only; no email, ticket or forum message was sent.

### Provider support request draft

> I own or administer a Türk Telekom ZTE ZXHN H3600P V9 running
> H3600P V9.0 TTN.10_260210. Its UI hardware-version field reads V9.0.7; I do
> not have an authoritative mapping to a physical board revision. Please
> confirm whether this exact build has a supported customer privileged web
> account, local diagnostic export, bridge operation, or developer access.
> Please provide the applicable documented firmware/recovery process and
> clarify which subscribed services and remote-management settings it preserves.
> Please use your private support channel for any account-specific verification;
> no credentials or configuration files are included in this request.

### Vendor source/support request draft

ZTE's [open-source portal](https://opensource.ztedevices.com/) advertises a
request route for unlisted models and covered source within three years of
purchase. This is a potential acquisition channel, not evidence that it will
deliver proprietary components, personalization data or a complete flashable
image. Supply any required purchase verification privately through the vendor's
official process.

> Please identify the corresponding source release for ZTE ZXHN H3600P V9,
> Türk Telekom firmware H3600P V9.0 TTN.10_260210. Please include the covered
> kernel and applicable bootloader sources, board configuration, patches and
> build instructions needed to identify this version. Separately, please
> identify any supported route for obtaining its firmware/recovery documentation
> and customer diagnostic or developer access. The UI hardware-version field
> is V9.0.7; physical-board mapping remains unconfirmed. No device identifiers,
> secrets or private backups are attached.

The [generic H3600P product page](https://www.zte.com.cn/global/home_and_enterprise/smart_home/zxhn_h3600p.html)
lists management capabilities without an exact TTN.10 access grant. The official
[Türk Telekom manual link](https://www.turktelekom.com.tr/tt-destek/Documents/zte-h3600p-fiber-modem-ullanim-kilavuzu.pdf)
and [manual index](https://www.turktelekom.com.tr/destek/fiber-modem-kullanim-kilavuzlari)
were located, but direct retrieval timed out during this follow-up. Their
contents were not newly verified. A manual print revision is not a firmware
release or a recovery qualification.

Any obtained artifact must first be bound privately to origin, exact version
and hash. Static review should distinguish shared firmware from per-device
personalization, inspect account authorization and credential representation,
and establish accepted import types and service startup semantics. A matching
spare supplies its own personalization, not the active gateway's.

Only after exact board identity and recovery are established on an authorized
recoverable unit should a device experiment be designed. It must independently
prove the claimed web privilege, listener scope, shell and numeric UID, followed
by subscribed-service preservation, external management isolation and original
state restoration. Until then, this report supports further research rather
than an executable access procedure or a support-status promotion.

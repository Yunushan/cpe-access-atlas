# CPE Access Atlas

[English](README.md) · [Türkçe](README.tr.md) · [Deutsch](README.de.md) · [Français](README.fr.md) · [Русский](README.ru.md)

Owner-authorized, firmware-aware access research for ISP-provided modems and
routers in Türkiye.

**CPE** means customer-premises equipment. This project catalogs exact
ISP/device/firmware combinations, distinguishes web super-admin access from a
real root shell, and provides safe research tooling that fails closed when a
method is not verified.

> [!IMPORTANT]
> The initial target, Türk Telekom ZTE H3600P firmware
> `H3600P V9.0 TTN.10_260210`, is **not currently rootable by a publicly
> verified method**. Older WAN/TR-069 methods are reported patched on this
> build. The project records that fact and refuses to run an older recipe
> against it. See [Compatibility](SUPPORT.md).

## Why this project exists

ISP firmware often hides advanced settings that owners need for routing, QoS,
DNS, bridge mode, VLANs, backups, or reuse of retired hardware. Existing guides
frequently say “H3600 root” without identifying the ISP build, hardware
revision, access level, or recovery path. That makes a successful method for one
firmware look universal when it is not.

CPE Access Atlas provides:

- an exact, machine-readable ISP/device/firmware catalog;
- separate status for standard admin, privileged web admin, local shell, UID 0,
  and bootloader access;
- one-private-host validation with no discovery or subnet scanning;
- a non-mutating compatibility plan and optional explicit-port check;
- secret-free hardware research report templates;
- a tested refusal path for blocked or unverified firmware;
- English, Turkish, German, French, and Russian documentation.

It does **not** include password lists, credential guessing, leaked ISP
credentials, Internet scanning, proprietary firmware, third-party VM images,
automatic downgrade/cross-flash logic, or a claim that every listed ISP is
already supported.

## Provider scope

| Provider | Current scope |
|---|---|
| TurkNet | Cataloged; device recipes welcome |
| Turkcell Superonline | Cataloged; device recipes welcome |
| Türksat Kablonet | Cataloged; device recipes welcome |
| Türk Telekom | Cataloged; H3600P exact-build research record |
| Netspeed | Cataloged; device recipes welcome |
| Vodafone Net | Cataloged; device recipes welcome |
| Millenicom | Cataloged; device recipes welcome |

Provider scope is not a support claim. Support is always recorded for one exact
combination of ISP, model, hardware revision, firmware, and access level.

## Initial target

| Field | Value |
|---|---|
| ISP | Türk Telekom |
| Device | ZTE ZXHN H3600P V9 |
| Hardware revision | `V9.0` (verification unresolved) |
| Firmware | `H3600P V9.0 TTN.10_260210` |
| Standard local web admin | ISP-supported |
| Privileged web admin | Blocked; research required |
| Linux root shell | Not supported |
| Last evidence review | 2026-08-13 |

Public community evidence says the older provisioning interception workflow
does not work on this build. No official firmware image, safe downgrade path,
configuration decoder, or independently verified replacement method was found.
The exact record is included so the tool can identify the build and stop
instead of doing something unsafe.

## Quick start

Requirements: Python 3.11 or newer. Installation also installs the pinned
major-version range of the JSON Schema validator used by the runtime catalog
validator.

```shell
python -m pip install -e .
cpe-atlas providers
cpe-atlas devices
cpe-atlas recipes
cpe-atlas validate
```

`cpe-atlas devices` lists model names found on official Turkish ISP device
pages. These are public listing records only; they do not imply firmware
compatibility, privileged access, root access, or support for every ISP-issued
unit. See [the official device inventory](docs/official-device-inventory.md).

Check the exact target:

```shell
cpe-atlas status \
  --isp "Türk Telekom" \
  --model "ZTE H3600P" \
  --hardware-revision "V9.0" \
  --firmware "H3600P V9.0 TTN.10_260210"
```

Render the decision plan:

```shell
cpe-atlas plan \
  --isp "turk-telekom" \
  --model "H3600P" \
  --hardware-revision "V9.0" \
  --firmware "H3600P V9.0 TTN.10_260210"
```

Check root-access readiness without touching the device:

```shell
cpe-atlas root-readiness \
  --isp "turk-telekom" \
  --model "H3600P" \
  --hardware-revision "V9.0" \
  --firmware "H3600P V9.0 TTN.10_260210" \
  --firmware-input firmware.bin \
  --expected-sha256 <private-recorded-sha256>
```

This command only hashes and scans the optional firmware file as opaque bytes.
It reports `STOP` unless the catalog has an exact hardware record, a verified
exact-build root method, and the supplied artifact matches the requested build
and optional private hash. It never reads configuration XML, connects to a
device, executes firmware, generates a configuration, or flashes anything.
For the current TTN.10 record it is expected to stop; that is a safety gate,
not a root-enablement method.

Validate one local target without making a network connection:

```shell
cpe-atlas doctor --host 192.168.1.1
```

An optional port check probes only the explicitly supplied ports on that single
private IP:

```shell
cpe-atlas doctor --host 192.168.1.1 --ports 80,443 --probe
```

Generate a contribution template:

```shell
cpe-atlas report-template \
  --isp "turk-telekom" \
  --model "H3600P" \
  --hardware-revision "V9.0" \
  --firmware "H3600P V9.0 TTN.10_260210" \
  --output h3600p-research.md
```

Sanitize a text report before manual review and sharing:

```shell
cpe-atlas redact --input raw-observations.txt --output sanitized-observations.txt
```

Redaction is conservative assistance; manually review the output and any
screenshots, captures, or configuration exports before sharing.

Inspect a private firmware artifact without executing or changing it:

```shell
cpe-atlas firmware-inspect \
  --input firmware.bin \
  --expected-version "H3600P V9.0 TTN.10_260210" \
  --json
```

This records a SHA-256 hash and scans opaque bytes for the exact build string
and common image markers. It does not prove that an image is flashable,
unsigned, recoverable, or safe to modify, and no proprietary firmware belongs
in this repository or a public issue. If a hash was recorded separately, pass
it with `--expected-sha256` to verify artifact identity; a mismatch returns a
nonzero exit code.

Generate an offline configuration artifact for a device you own or administer:

```shell
cpe-atlas config-generate \
  --isp "turk-telekom" \
  --model "H3600P" \
  --hardware-revision "V9.0" \
  --firmware "H3600P V9.0 TTN.10_260210" \
  --output h3600p-config.bin \
  --allow-unencrypted \
  --i-own-or-administer-this-device
```

The command refuses credential-bearing unencrypted output unless
`--allow-unencrypted` is explicitly supplied. It prompts for the SSH password
and writes a local, base64-wrapped compressed configuration artifact. To
preserve an existing private baseline, add `--input-config config.bin`;
encrypted type-4 baselines also require the device serial, lower-case MAC
address, and the device-specific encryption passphrase. Encrypted input is
preserved by default; use `--encrypted` with the serial, MAC, and passphrase to
request encrypted output from another baseline or a new template. Passphrases
are read locally and never printed. Use `--input-xml` only with a private
decoded XML baseline. `--raw` emits the raw binary container. Generated config
files are atomically written with restrictive local permissions where the
platform exposes owner-only modes; on Windows the destination directory's ACL
remains authoritative. The destination directory must already exist.

This is an offline research tool, not a firmware image, root exploit, or device
flasher. A no-input artifact uses a minimal template and does not preserve ISP
provisioning such as Internet, VoIP, IPTV, VLAN, Wi-Fi, or TR-069 settings. The
exact TTN.10 build is still cataloged as blocked: artifact generation does not
prove that the firmware accepts the file, enables a Linux UID 0 shell, or has a
recoverable rollback path. Keep the original backup and every generated file
private; do not upload them to GitHub or include them in bug reports.

The `apply` command is deliberately fail-closed in version 0.2.0. Even after
ownership acknowledgement it refuses this blocked recipe and makes no device
change.

## Access terminology

| Term | Meaning |
|---|---|
| Standard web admin | ISP-supported local settings account |
| Privileged web admin | Hidden or elevated local web account, sometimes named `root` or `sUser` |
| Local shell | SSH, Telnet, serial, or another command shell |
| Root shell | Shell with operating-system UID 0 |
| Bootloader access | U-Boot or equivalent pre-OS control |

A working account named “root” in the web UI does not prove Linux root-shell
access.

## Safety model

The code enforces these boundaries:

- exactly one RFC1918 IPv4 or IPv6 ULA literal;
- no public addresses, hostnames, ranges, CIDRs, or target lists;
- no LAN discovery, credential retries, brute force, or spraying;
- exact firmware matching with no fallback to a “similar” recipe;
- exact hardware-revision matching with no implicit sub-revision fallback;
- JSON Schema validation plus cross-record catalog consistency checks;
- no arbitrary commands embedded in recipe data;
- non-mutating behavior by default;
- no telemetry.

Before any future verified mutation:

1. Own the equipment or obtain explicit authorization.
2. Confirm ISP, model, hardware revision, and firmware exactly.
3. Document Internet, VoIP, IPTV, VLAN, Wi-Fi, and authentication settings.
4. Establish and test a recovery path.
5. Keep configuration exports and captures private.
6. Use a unique password and keep WAN-side administration disabled.

The report redactor is conservative assistance, not a proof of sanitization.
It requires `--output`, never prints report contents to the terminal, and writes
the result with restrictive local permissions where supported. On Windows,
secure the destination directory's ACL and manually review every report,
screenshot, capture, and exported text before sharing it.

Modifying ISP-provided equipment can break connectivity, VoIP, IPTV, updates,
remote support, warranty coverage, or contractual terms. Rented or loaned
equipment requires the provider's explicit permission.

## Repository layout

```text
src/cpe_access_atlas/       CLI, policy, catalog, redaction, report generator, offline config codec
src/cpe_access_atlas/data/  Provider, official-device, and exact-firmware records
schemas/                    Recipe JSON Schema
docs/                       Architecture and research notes
tests/                      Unit and CLI behavior tests
.github/                    CI and contribution templates
```

## Support status lifecycle

- **Researching**: evidence is incomplete.
- **Experimental**: implemented, but not independently reproduced.
- **Verified**: tested on the exact device and firmware with recovery.
- **Stable**: independently reproduced and maintained.
- **Blocked**: a known technical blocker prevents the requested access.

Mock fixtures do not qualify a hardware method as verified.

## Contributing

Read [CONTRIBUTING.md](CONTRIBUTING.md) before submitting a recipe. Do not
publish configuration backups, firmware images, packet captures, passwords,
cookies, certificates, serial numbers, MAC addresses, public IPs, or subscriber
identifiers.

Security-sensitive firmware findings should not be placed in a public issue.
See [SECURITY.md](SECURITY.md).

Repository administrators should apply the [GitHub production settings
checklist](docs/github-production-settings.md) before declaring a release
production-ready.

## Research sources

- [Official ZTE H3600P product page](https://www.zte.com.cn/global/product_index/smart_home_en/home_router/zxhn-h3600p/zxhn-h3600p.html)
- [Archived h3600-root project](https://github.com/enoymuss/h3600-root)
- [TTN.10_260210 community status](https://forum.donanimhaber.com/zte-zxhn-h3600p-guncel-h298a-root-etkinlestirme--161912895-3)
- [July 2026 patched-method report](https://techolay.net/sosyal/konu/zte-zxhn-h3600p-v9-routerda-root-erisimi-nasil-alinir.204807/)
- [February H3600P guide and its TTN.8 follow-up](https://techolay.net/sosyal/konu/turk-telekom-superonline-icin-zte-h3600p-nasil-rootlanir.181032/)
- [Open H3600P configuration-decoding request](https://github.com/mkst/zte-config-utility/issues/137)
- [H298A-only CWMP proof-of-concept](https://github.com/Faharee/ZTE-H298A-Root)
- [Firmware-specific Digi H3600P research](https://orca.pet/zteh3600p/)
- [Official Türk Telekom H3600P user manual](https://www.turktelekom.com.tr/tt-destek/Documents/zte-h3600p-fiber-modem-ullanim-kilavuzu.pdf)

See the full [exact-build research note](docs/research/zte-h3600p-ttn10-260210.md).

## Independence and license

CPE Access Atlas is an independent community project and is not affiliated with
or endorsed by any listed ISP or equipment manufacturer. Product names and
trademarks belong to their owners.

Code and original documentation are released under the
[BSD Zero Clause License](LICENSE) (`0BSD`), without warranty. The license
permits broad use of the code; it does not grant permission to access equipment
you do not own or administer.

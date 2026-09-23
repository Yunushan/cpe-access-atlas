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
| Last evidence review | 2026-09-13 |

Public community evidence says the older provisioning interception workflow
does not work on this build. No official firmware image, recovery-tested
downgrade path, or independently verified replacement method was found. The
experimental offline configuration codec below is not validated for firmware
acceptance or recovery on this exact build.
The exact record is included so the tool can identify the build and stop
instead of doing something unsafe.

## Quick start

Requirements: standard CPython 3.11 through 3.15. Use a dedicated virtual environment and
the committed hash-locked dependencies so evaluation does not silently resolve
a different runtime or build backend.

CI targets standard CPython 3.11–3.15 on Windows, Linux, and macOS. Python 3.15
is currently a release candidate: local compatibility checks use 3.15.0rc2,
not a final release. CI selects a 3.15 prerelease only until final is available;
rerun the full matrix on final before claiming final-release validation.
Free-threaded Python and PyPy are not part of this support matrix. Interpreter
compatibility does not establish modem/config/firmware compatibility.

```shell
python -m venv .venv
python -m pip --python .venv install --require-hashes -r requirements-ci.lock
python -m pip --python .venv install -e . --no-deps --no-build-isolation
python -m pip --python .venv check
```

Activate it with `. .venv/bin/activate` on Linux/macOS or
`.venv\Scripts\Activate.ps1` in PowerShell. Then run:

```shell
cpe-atlas providers
cpe-atlas devices
cpe-atlas recipes
cpe-atlas validate
```

Alternatively, use the executable's full path under `.venv/bin` on Linux/macOS
and `.venv\Scripts` on Windows. See
[installation and rollback](docs/installation.md) for verified release-wheel,
upgrade, rollback, pipx, and removal guidance. There is currently no
production-stable PyPI distribution.

See [the full CLI reference](docs/cli-reference.md) for every command and
option, generated directly from the CLI so it cannot drift out of date.

`cpe-atlas devices` lists model names found on official Turkish ISP device
pages. These are public listing records only; they do not imply firmware
compatibility, privileged access, root access, or support for every ISP-issued
unit. See [the official device inventory](docs/official-device-inventory.md).

Check the exact target:

```shell
cpe-atlas status --isp "turk-telekom" --model "ZTE H3600P" --hardware-revision "V9.0" --firmware "H3600P V9.0 TTN.10_260210"
```

Render the decision plan:

```shell
cpe-atlas plan --isp "turk-telekom" --model "H3600P" --hardware-revision "V9.0" --firmware "H3600P V9.0 TTN.10_260210"
```

Check root-access readiness without touching the device:

```shell
cpe-atlas root-readiness --isp "turk-telekom" --model "H3600P" --hardware-revision "V9.0" --firmware "H3600P V9.0 TTN.10_260210" --firmware-input firmware.bin --expected-sha256 <private-recorded-sha256>
```

This command only hashes and scans the optional firmware file as opaque bytes.
Version strings and a user-supplied SHA-256 are evidence matches, not proof of
vendor authenticity or flash compatibility. JSON reports expose this distinction
as `firmware_evidence_matches`; the legacy `firmware_identity_verified` field
remains false because this release has no trusted firmware-authentication path.
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

Collect authenticated, read-only web evidence from an owned H3600P without
printing the password, cookies, parameter values, or raw pages:

```shell
cpe-atlas web-evidence --isp "turk-telekom" --model "H3600P" --hardware-revision "V9.0" --firmware "H3600P V9.0 TTN.10_260210" --host 192.168.1.1 --username admin --i-own-or-administer-this-device --acknowledge-local-http-authentication
```

The password is requested with hidden terminal input. The command makes one
normal web-console login attempt, then issues only bounded GET requests for the
authenticated root and device-status views. It also parses the page-access map
embedded by the firmware and requests the rendered `tr069`, `rsc`, user-manager,
mirror, and capture page views only when the authenticated root advertises the
same IDs. It reports response shapes, access levels, route names, parameter
names, bounded HTML field/element IDs, configuration-object IDs, Lua resource
names, and the presence of expected identity or root-research strings as
sanitized JSON. Input values and parameter values are not emitted. It never
submits those pages and does not send CWMP, configuration, shell, reboot, reset,
upload, or firmware requests or save raw responses. An incorrect password can
still contribute to the router's login lockout, so the command never retries
automatically. The HTTP acknowledgement is required because this firmware
exposes its challenge-hash login over local HTTP.

This evidence can show what the exact authenticated firmware exposes; it does
not itself enable root access or make the blocked recipe rootable.

Inspect a private UART boot capture without printing its raw lines, device
identity values, or possible credentials:

```shell
cpe-atlas uart-evidence --isp "turk-telekom" --model "H3600P" --hardware-revision "V9.0" --firmware "H3600P V9.0 TTN.10_260210" --input h3600p-uart-private.log
```

The command is offline: it opens no serial port and sends nothing to the
router. It reports only bounded metadata such as observed H3600P build strings,
U-Boot/kernel versions, SoC/hardware identifiers, memory size, secure-boot text,
and prompt-presence booleans. It never prints the input path or raw log, and an
observed prompt is not reported as verified root access.

Only attempt a new capture on an owned spare or recovery-tested unit. Public
research for an older Digi H3600P reports a 3.3 V AUX3 header at 115200 8N1,
with pin 1 VCC, pin 2 router TX, pin 3 router RX, and pin 4 GND, but explicitly
warns that newer firmware can lock serial. For the first TTN.10 observation,
power the router off before wiring, leave VCC disconnected, connect common GND
and router TX to the adapter RX only, and leave the adapter TX disconnected.
Capture one normal boot without pressing keys. Do not press `1`, enter an old
bootloader password, run `saveenv`/`nand`, or change boot arguments. Electrical
damage, warranty, and service-interruption risks remain; the published pinout
and older firmware behavior are not exact-build validation.

Generate a contribution template:

```shell
cpe-atlas report-template --isp "turk-telekom" --model "H3600P" --hardware-revision "V9.0" --firmware "H3600P V9.0 TTN.10_260210" --output h3600p-research.md
```

Sanitize a text report before manual review and sharing:

```shell
cpe-atlas redact --input raw-observations.txt --output sanitized-observations.txt
```

Redaction is conservative assistance; manually review the output and any
screenshots, captures, or exported text before sharing. The command reminds you
that unrecognized sensitive fields may remain. Keep configuration backups private;
redaction does not make a `config.bin` safe to upload. Its output path must differ
from the input report, even with `--force`, so the original is preserved.

Inspect a private firmware artifact without executing or changing it:

```shell
cpe-atlas firmware-inspect --input firmware.bin --expected-version "H3600P V9.0 TTN.10_260210" --json
```

This records a SHA-256 hash and scans opaque bytes for complete H3600P build
identifiers and common image markers. A target string embedded inside a longer
identifier (for example, `TTN.10_2602109` or `TTN.10_260210_modified`) is not an
exact match. Read-chunk boundaries are not treated as identifier boundaries.
Recognizing a string does not authenticate an image or establish its installed
version. It does not prove that an image is flashable,
unsigned, recoverable, or safe to modify, and no proprietary firmware belongs
in this repository or a public issue. If a hash was recorded separately, pass
it with `--expected-sha256` to verify artifact identity; a mismatch returns a
nonzero exit code.

Generate an offline configuration artifact for a device you own or administer:

**Encrypted-codec warning:** do not import encrypted config artifacts generated
by v0.4.0a1 or earlier; their key derivation was incorrect. Keep your original
private modem backup. The [v0.4.0a2 correction and reference tests](docs/config-cryptography.md)
do not establish safe import or root access on the exact target firmware.

```shell
cpe-atlas config-generate --isp "turk-telekom" --model "H3600P" --hardware-revision "V9.0" --firmware "H3600P V9.0 TTN.10_260210" --output h3600p-config.bin --allow-unencrypted --acknowledge-unverified-compatibility --i-own-or-administer-this-device
```

The command refuses credential-bearing unencrypted output unless
`--allow-unencrypted` is explicitly supplied. It prompts for the SSH password
and writes a local, base64-wrapped compressed configuration artifact. To
preserve an existing private baseline, add `--input-config config.bin`;
encrypted type-4 baselines also require the device serial, lower-case MAC
address, and the device-specific encryption passphrase. Encrypted input is
preserved by default; use `--encrypted` with the serial, MAC, passphrase, and
`--acknowledge-legacy-crypto` to request encrypted output from another baseline
or a new template. This acknowledgement is required because the vendor format
uses legacy SHA-256 derivation and unauthenticated CBC; it does not make the
artifact a modern secure backup. Passphrases are read locally and never
printed. To keep device identifiers out of shell history and process listings,
store exactly `{"serial":"...","mac":"..."}` in a protected UTF-8 JSON file
and pass `--identity-file` instead of `--serial` and `--mac`. The file is read
with a 1 KiB bound and its contents are never printed. Use `--input-xml` only with a private
decoded XML baseline. `--raw` emits the raw binary container. Generated config
files are atomically written with owner-only POSIX permissions or an explicit,
protected Windows ACL granted only to the creating account. On Windows, the
ACL is installed at file creation and checked through the same open handle
before any credential bytes are written; inherited group/Everyone grants are
not retained. The destination directory must already exist, remain under your
control, and support hard links for no-overwrite publication (for example,
NTFS, APFS, or ext4). Windows also requires persistent ACL support. Unsupported
filesystems fail closed. These protections do not isolate files from the same
account, elevated administrators, or an untrusted storage provider; keep every
artifact in a private, trusted local directory. The output path must differ
from the input baseline and private identity file, even with `--force`, so those
originals cannot be replaced.

For a `blocked`, `researching`, or otherwise not-exact target, the command also
requires `--acknowledge-unverified-compatibility`. This is a deliberate risk
acknowledgement, not evidence that the firmware accepts the artifact, enables
root access, preserves ISP services, or has a recovery path. It does not enable
device connections, flashing, or the fail-closed `apply` command.

Secret prompts stop with an error if hidden terminal input is unavailable;
they never fall back to visible entry. End-of-input or unreadable input also
stops the command without printing input-layer diagnostics or replacing an
existing artifact. For automation, explicitly select `--ssh-password-stdin`
and/or `--device-key-stdin` and supply the values through a private pipe or
protected file, never as command-line arguments or shell-history literals.
When both values are needed from stdin, supply the SSH password first, then
the device passphrase, one per line (LF or CRLF). The SSH password must be
8–128 printable characters; the device passphrase must be exactly 32 ASCII
characters. Stdin reads are bounded to these maximum lengths plus a line
terminator, and oversized values are rejected, not silently truncated. These
explicit stdin options do not disable terminal echo; do not use them for
interactive typing into a visible terminal.

This is an offline research tool, not a firmware image, root exploit, or device
flasher. A no-input artifact uses a minimal template and does not preserve ISP
provisioning such as Internet, VoIP, IPTV, VLAN, Wi-Fi, or TR-069 settings. The
exact TTN.10 build is still cataloged as blocked: artifact generation does not
prove that the firmware accepts the file, enables a Linux UID 0 shell, or has a
recoverable rollback path. Keep the original backup and every generated file
private; do not upload them to GitHub or include them in bug reports.

The `apply` command is deliberately fail-closed in this release. Even after
ownership acknowledgement it refuses this blocked recipe and makes no device
change.

To protect an existing private artifact at rest, use the separate authenticated
local container format:

```shell
cpe-atlas private-protect --input config.bin --output config.bin.cpap --passphrase-stdin --i-am-authorized-to-handle-this-private-file
```

New containers use format version 2 with a fresh salt, AES-GCM authentication,
and scrypt parameters `N=2^17`, `r=8`, `p=1`. The matching `private-unprotect`
command also reads legacy version-1 containers. Re-protect a successfully
restored version-1 file to migrate it; new writes always use version 2. Unknown
or excessive KDF parameters are rejected before key derivation. This container
is **not** a modem-import format and does not redact credentials, prove firmware
compatibility, or make a backup safe to publish. Keep the protected file and
passphrase separate; do not commit either one or attach them to an issue. The
passphrase must contain 12–256 Unicode characters, excluding C0/C1 controls,
line/paragraph separators, and surrogates. This policy is stable across
supported Python versions. Preserve its exact text: no Unicode normalization or
whitespace trimming occurs. Supply it through a hidden prompt or a private pipe,
never as a command-line argument. See the authenticated local-container section
of [the cryptography notes](docs/config-cryptography.md#authenticated-local-container)
for format, resource-cost, and migration details.

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
It covers common text assignments, complete Cookie/Set-Cookie headers, quoted
ZTE XML secret fields, serial/subscriber identifiers, and PEM private-key blocks.
Recognized Wi-Fi credential names include `KeyPassphrase`, `PreSharedKey`,
`wifi_psk`, and `WPA_PSK`, with common case and separator variants. These names
are matched in text assignments, JSON, XML name/value fields, and directly named
XML attributes and elements; this is not an exhaustive sensitive-field inventory.
It accepts at most 8 Mi characters of UTF-8 report text; binary backups and
unsupported or malformed formats are not safe to publish after redaction.
It requires `--output`, never prints report contents to the terminal, and writes
the result through the same owner-only artifact writer described above. Keep
the destination directory private and under your control, and manually review
every report, screenshot, capture, and exported text before sharing it.

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
production-ready. The checklist includes the read-only
`scripts/check_github_production_settings.py` audit for retaining evidence of
the administrator-visible controls. The
[operational-resilience runbook](docs/operations.md) defines the fail-closed
incident, revocation, and recovery process and identifies the recovery exercise
that remains required before a production-support claim.

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

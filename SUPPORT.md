# Compatibility and support

Support is tracked per ISP, device, hardware revision, firmware, and access
level. Listing a provider does not imply that every device is supported.

The repository also includes a separate official-device inventory for selected
Türk Telekom, Turkcell Superonline, and Türksat pages. Those records establish
only that a model was publicly listed; they do not establish an exact firmware,
working credentials, privileged access, root access, or device interchangeability.
See [the inventory notes](docs/official-device-inventory.md).

## Provider scope

| Provider | Catalog status |
|---|---|
| TurkNet | Cataloged; recipes welcome |
| Turkcell Superonline | Cataloged; recipes welcome |
| Türksat Kablonet | Cataloged; recipes welcome |
| Türk Telekom | Cataloged; one research record |
| Netspeed | Cataloged; recipes welcome |
| Vodafone Net | Cataloged; recipes welcome |
| Millenicom | Cataloged; recipes welcome |

## Initial target

| ISP | Device | Firmware | Privileged web admin | Root shell |
|---|---|---|---|---|
| Türk Telekom | ZTE H3600P V9 | `H3600P V9.0 TTN.10_260210` | Blocked / researching | Not supported |

The cataloged hardware value for this research record is
`V9.0`, but its verification status is `unresolved`. Every CLI recipe command
requires the hardware value explicitly; another revision is rejected rather
than falling back to the closest record. A recipe cannot become verified or
stable until its hardware verification status is `exact`.

### Why it is not marked supported

As of 2026-08-15:

- the archived community tool states that newer firmware is unsupported and
  limits its working range to older builds;
- community reports say the older WAN-side TR-069/DHCP method does not work on
  `TTN.10_260210`;
- a July 2026 report says the latest known method was patched by a firmware
  update;
- no reproducible method with backup and rollback evidence was found for this
  exact firmware.
- the repository's offline configuration codec is experimental and does not
  establish that a generated artifact will be accepted or preserve ISP data;
  exact field semantics, device-specific encryption inputs, and recovery remain
  unverified.
- a February H3600P guide claims Türk Telekom applicability but does not identify
  this build; its follow-up reports failure on `TTN.8_250626`.

Relevant public evidence:

- [Archived h3600-root project](https://github.com/enoymuss/h3600-root)
- [TTN.10_260210 failure report](https://forum.donanimhaber.com/zte-zxhn-h3600p-guncel-h298a-root-etkinlestirme--161912895-3)
- [July 2026 patched-method report](https://techolay.net/sosyal/konu/zte-zxhn-h3600p-v9-routerda-root-erisimi-nasil-alinir.204807/)
- [February H3600P guide and its TTN.8 follow-up](https://techolay.net/sosyal/konu/turk-telekom-superonline-icin-zte-h3600p-nasil-rootlanir.181032/)
- [Open H3600P configuration-support request](https://github.com/mkst/zte-config-utility/issues/137)
- [H298A-only CWMP proof-of-concept reviewed as a cross-model lead](https://github.com/Faharee/ZTE-H298A-Root)
- [Official ZTE H3600P product page](https://www.zte.com.cn/global/product_index/smart_home_en/home_router/zxhn-h3600p/zxhn-h3600p.html)
- [Official Türk Telekom H3600P user manual](https://www.turktelekom.com.tr/tt-destek/Documents/zte-h3600p-fiber-modem-ullanim-kilavuzu.pdf)

The CLI deliberately stops on this build. It does not silently run an older
recipe, downgrade firmware, guess credentials, or claim success based on a
different H3600/H3600P release.

For a private firmware file, `cpe-atlas root-readiness` can hash and scan the
opaque bytes against this exact record. It is a readiness gate only: it never
reads configuration contents, connects to the modem, writes a config, runs
firmware, or flashes a device. A `STOP` result is expected until exact-build
root and recovery evidence exists.

See [the research note](docs/research/zte-h3600p-ttn10-260210.md) for the
evidence needed to move this record forward.

# Official ISP device inventory

The bundled `device_inventory.json` records device names that appeared on
official Türk Telekom, Turkcell Superonline, or Türksat device pages during the
last review. It is an inventory of public listing evidence, not a compatibility
or access catalog.

Use it from the CLI:

```shell
cpe-atlas devices
cpe-atlas devices --isp "Turkcell Superonline" --json
```

The records deliberately do not contain firmware strings, credentials,
configuration backups, serial numbers, MAC addresses, firmware images, or
access procedures. A listed model still requires a separate exact recipe before
the project can make any claim about standard administration, privileged web
administration, a local shell, UID 0, or bootloader access.

## Sources reviewed

| Provider | Official source | What it establishes |
|---|---|---|
| Türk Telekom | [Modem ve Wi-Fi](https://bireysel.turktelekom.com.tr/cihazlar/modem-ve-internet) and linked product pages | Publicly listed modem, mobile-modem, mesh, and signal-extender names |
| Turkcell Superonline | [Modemler](https://www.superonline.net/kurumsal/yardim/modemler) | Publicly listed device names |
| Türksat Kablonet | [Cihazlar](https://www.turksatkablonet.com/cihazlar) and [Türksat Kablo Cihazlar](https://www.turksatkablo.com.tr/yayin-akisi.aspx/inc/inc/userUpload/sayfa/formlar/Cihazlar) | Publicly listed GPON, DOCSIS, VDSL, and mesh device names |

The provider pages may change, retire products, or show different stock by
address and campaign. `last_reviewed` is therefore evidence freshness, not a
guarantee that a device is currently orderable.

Each source also carries an expected listing count. The catalog validator checks
that every reviewed source is represented by the same number of device records;
devices appearing on two official Türksat pages are intentionally linked to
both sources but remain one provider/model record.

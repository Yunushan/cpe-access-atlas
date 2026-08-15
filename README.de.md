# CPE Access Atlas

[English](README.md) · [Türkçe](README.tr.md) · [Deutsch](README.de.md) · [Français](README.fr.md) · [Русский](README.ru.md)

Firmwarebezogene Forschung und sichere Werkzeuge für den vom Eigentümer
autorisierten Zugriff auf Modems und Router türkischer Internetanbieter.

> [!IMPORTANT]
> Für die erste Zielversion, Türk Telekom ZTE H3600P
> `H3600P V9.0 TTN.10_260210`, ist derzeit **keine öffentlich verifizierte
> Root- oder Super-Admin-Methode** bekannt. Ältere WAN/TR-069-Verfahren gelten
> bei dieser Firmware als behoben. Das Projekt erkennt die exakte Version und
> stoppt, anstatt ein älteres Verfahren auszuführen.

## Funktionsumfang

- Exakter Katalog nach Anbieter, Gerät, Hardware-Revision und Firmware.
- Getrennter Status für Standard-Webadmin, privilegierten Webadmin, lokale
  Shell, UID-0-Root und Bootloader.
- Prüfung genau einer privaten IP-Adresse ohne Netzwerkerkennung oder Scan.
- Nicht verändernder Plan und optionale Prüfung explizit angegebener Ports.
- Vorlage für bereinigte Forschungsberichte.
- Dokumentation in fünf Sprachen.

Enthalten sind weder Passwortlisten noch Brute Force, geleakte Zugangsdaten,
Internet-Scans, proprietäre Firmware, fremde VM-Abbilder oder automatisches
Downgrade/Cross-Flashing.

## Anbieter

TurkNet, Turkcell Superonline, Türksat Kablonet, Türk Telekom, Netspeed,
Vodafone Net und Millenicom sind katalogisiert. Die Nennung eines Anbieters
bedeutet nicht, dass alle seine Geräte unterstützt werden.

## Erste Zielversion

| Feld | Wert |
|---|---|
| Anbieter | Türk Telekom |
| Gerät | ZTE ZXHN H3600P V9 |
| Hardware-Revision | `V9.0` (nicht verifiziert) |
| Firmware | `H3600P V9.0 TTN.10_260210` |
| Standard-Webadmin | Vom Anbieter unterstützt |
| Privilegierter Webadmin | Blockiert; Forschung erforderlich |
| Linux-Root-Shell | Nicht unterstützt |
| Letzte Prüfung | 13.08.2026 |

Siehe [Kompatibilität](SUPPORT.md) und
[Forschungsnotiz](docs/research/zte-h3600p-ttn10-260210.md).

## Schnellstart

Python 3.11 oder neuer. Die Installation enthält auch den JSON-Schema-Validator:

```shell
python -m pip install -e .
cpe-atlas providers
cpe-atlas devices
cpe-atlas validate
cpe-atlas status --isp "Türk Telekom" --model "ZTE H3600P" \
  --hardware-revision "V9.0" \
  --firmware "H3600P V9.0 TTN.10_260210"
```

Eine private Zieladresse kann ohne Verbindung geprüft werden:

```shell
cpe-atlas doctor --host 192.168.1.1
```

Die schreibgeschützte Bereitschaftsprüfung für die exakte Firmware kann so
ausgeführt werden:

```shell
cpe-atlas root-readiness \
  --isp "turk-telekom" \
  --model "H3600P" \
  --hardware-revision "V9.0" \
  --firmware "H3600P V9.0 TTN.10_260210" \
  --firmware-input firmware.bin \
  --expected-sha256 <privat-dokumentierter-sha256>
```

Der Befehl hasht und durchsucht die Firmwaredatei nur als undurchsichtige
Bytes und gibt für den aktuellen TTN.10-Eintrag erwartungsgemäß `STOP` aus. Er
verbindet sich nicht mit dem Gerät, erzeugt keine Konfiguration und flasht
nichts. `cpe-atlas firmware-inspect` bietet dieselbe sichere Hash- und
Versionsprüfung für private Firmwaredateien. `config-generate` ist ein
Offline-Konfigurationswerkzeug und kein Root-Exploit oder Flasher; erzeugte
Dateien und vorhandene Backups müssen privat bleiben.

Der Befehl `apply` arbeitet in Version 0.3.0 absichtlich nach dem
Fail-Closed-Prinzip und ändert bei dieser blockierten Firmware nichts.

## Sicherheit und Berechtigung

Verwenden Sie das Projekt nur für eigene Geräte oder mit ausdrücklicher
Erlaubnis. Prüfen Sie Modell, Hardware und Firmware exakt, dokumentieren Sie
Internet-, VoIP-, IPTV-, VLAN- und WLAN-Einstellungen und testen Sie vor jeder
Änderung einen Wiederherstellungsweg. Veröffentlichen Sie keine
Konfigurationssicherungen, Mitschnitte, Kennwörter, Zertifikate, Seriennummern,
MAC-Adressen oder Teilnehmerkennungen.

Leih-, Miet- oder Anbietereigentum erfordert die ausdrückliche Genehmigung des
Eigentümers. Änderungen können Vertrag, Garantie, Support und
Gerätefunktionalität beeinträchtigen.

## Lizenz

Das unabhängige Projekt ist mit keinem genannten Anbieter oder Hersteller
verbunden. Code und originale Dokumentation stehen ohne Gewährleistung unter
der [BSD Zero Clause License](LICENSE) (`0BSD`). Die Lizenz erteilt keine
Berechtigung zum Zugriff auf fremde Geräte.

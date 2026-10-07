# CPE Access Atlas

[English](README.md) · [Türkçe](README.tr.md) · [Deutsch](README.de.md) · [Français](README.fr.md) · [Русский](README.ru.md)

> [!NOTE]
> Diese Übersicht wurde am 3. Oktober 2026 abgeglichen. Für aktuelle
> sicherheitskritische Einschränkungen, neue Optionen und verifizierte
> Installationsschritte gelten die [englische README](README.md), die
> [Sicherheitsrichtlinie](SECURITY.md) und die
> [Installationsanleitung](docs/installation.md) als maßgeblich.
> Alle Optionen stehen in der [englischen CLI-Referenz](docs/cli-reference.md);
> für Automatisierung gilt der [JSON- und Exit-Code-Vertrag](docs/cli-output-contract.md).

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
| Letzte Evidenzprüfung | 27.09.2026 |

`V9.0` ist ein vorläufiger, nicht verifizierter Katalogschlüssel. Die beobachtete
lokale Oberfläche nennt `V9.0.7` als Hardware-Version; die Zuordnung zur
physischen Platinenrevision und zum Schlüssel `V9.0` ist ungeklärt. Die folgenden
Beispiele wählen diesen Forschungseintrag und belegen keine Kompatibilität
anderer Revisionen. Der Übersetzungsabgleich ist keine neue Hardwareprüfung.

Siehe [Kompatibilität](SUPPORT.md) und
[Forschungsnotiz](docs/research/zte-h3600p-ttn10-260210.md).

## Schnellstart

Standard-CPython 3.11–3.15. Die Installation enthält auch den JSON-Schema-Validator:

Die CI zielt auf standard CPython 3.11–3.15 unter Windows, Linux und macOS.
Frühere lokale Kompatibilitätsprüfungen verwendeten 3.15.0rc2. Die Release-Matrix
und die Prüfmatrix nach der Wiederherstellung für [v0.4.0a9](https://github.com/Yunushan/cpe-access-atlas/releases/tag/v0.4.0a9)
liefen mit 3.15.0rc3. Diese Ergebnisse betreffen Vorabversionen und bestätigen
keine Validierung der finalen Python-Version 3.15. Die CI wählt eine
3.15-Vorabversion nur, bis die finale Version verfügbar ist; führen Sie die
gesamte Matrix mit der finalen Version erneut aus, bevor Sie eine Validierung
auf der finalen Version erklären. Free-threaded Python und PyPy sind nicht Teil
dieser Matrix. Interpreter-Kompatibilität beweist keine
Modem-/Konfigurations-/Firmware-Kompatibilität.

```shell
python -m venv .venv
python -m pip --python .venv install --require-hashes -r requirements-ci.lock
python -m pip --python .venv install -e . --no-deps --no-build-isolation
python -m pip --python .venv check
```

Aktivieren Sie die Umgebung mit `. .venv/bin/activate` unter Linux/macOS oder
`.venv\Scripts\Activate.ps1` in PowerShell. Führen Sie anschließend aus:

```shell
cpe-atlas providers
cpe-atlas devices
cpe-atlas validate
cpe-atlas status --isp "turk-telekom" --model "ZTE H3600P" --hardware-revision "V9.0" --firmware "H3600P V9.0 TTN.10_260210"
```

Die
[Installationsanleitung](docs/installation.md) beschreibt Release-Wheels,
Aktualisierung und Rollback.

Eine private Zieladresse kann ohne Verbindung geprüft werden:

```shell
cpe-atlas doctor --host 192.168.1.1
```

Die schreibgeschützte Bereitschaftsprüfung für die exakte Firmware kann so
ausgeführt werden:

```shell
cpe-atlas root-readiness --isp "turk-telekom" --model "H3600P" --hardware-revision "V9.0" --firmware "H3600P V9.0 TTN.10_260210" --firmware-input firmware.bin --expected-sha256 <privat-dokumentierter-sha256>
```

Der Befehl hasht und durchsucht die Firmwaredatei nur als undurchsichtige
Bytes und gibt für den aktuellen TTN.10-Eintrag erwartungsgemäß `STOP` aus. Er
verbindet sich nicht mit dem Gerät, erzeugt keine Konfiguration und flasht
nichts. `cpe-atlas firmware-inspect` bietet dieselbe sichere Hash- und
Versionsprüfung für private Firmwaredateien. `config-generate` ist ein
Offline-Konfigurationswerkzeug und kein Root-Exploit oder Flasher; erzeugte
Dateien und vorhandene Backups müssen privat bleiben.

**Warnung:** Importieren Sie keine verschlüsselten Konfigurationsdateien, die
mit v0.4.0a1 oder älter erzeugt wurden; die Schlüsselableitung war fehlerhaft.
Bewahren Sie das Originalbackup privat auf. Die [Korrektur in v0.4.0a2](docs/config-cryptography.md)
belegt weder einen sicheren Import noch Root-Zugriff für die genaue Firmware.
Für verschlüsselte Ausgaben ist zusätzlich `--acknowledge-legacy-crypto`
erforderlich. Das Vendor-Format verwendet eine alte SHA-256-Ableitung und
unauthentifiziertes CBC; diese Bestätigung macht es nicht zu einem modernen
sicheren Backup. Der Ausgabepfad muss sich auch mit `--force` vom privaten
Eingabe-Backup unterscheiden.

Der Befehl `apply` arbeitet in dieser Version absichtlich nach dem
Fail-Closed-Prinzip und ändert bei dieser blockierten Firmware nichts.

## Authentifizierte Web-Evidenz

Verwenden Sie den Collector nur auf einem eigenen oder ausdrücklich zur
Administration freigegebenen H3600P und über ein vertrauenswürdiges, isoliertes
oder direkt verbundenes LAN:

```shell
cpe-atlas web-evidence --isp "turk-telekom" --model "H3600P" --hardware-revision "V9.0" --firmware "H3600P V9.0 TTN.10_260210" --host 192.168.1.1 --username admin --i-own-or-administer-this-device
```

Standard ist HTTPS auf Port 443 mit mindestens TLS 1.2 und Prüfung der
Zertifikatskette sowie der angegebenen Ziel-IP anhand des Systemvertrauens.
Für eine unabhängig als vertrauenswürdig bestätigte private CA verwenden Sie
`--tls-ca-file trusted-router-ca.pem`. Erlaubt sind nur ASCII-PEM-Zertifikate,
höchstens 65.536 Byte und acht Zertifikate; die IP-Prüfung bleibt aktiv. Ein
Zertifikat aus einer ungeprüften Verbindung begründet kein unabhängiges
Vertrauen. Bei einem Prüfungsfehler wird abgebrochen, ohne Weiterleitung,
automatische Wiederholung oder Rückfall auf HTTP.

Unverschlüsseltes HTTP auf Port 80 erfordert gleichzeitig `--transport http`
und `--acknowledge-local-http-authentication`. Challenge-Antwort und Sitzung
sind dabei ungeschützt; verwenden Sie nur ein vertrauenswürdiges, isoliertes
oder direkt verbundenes LAN und ein starkes, gerätespezifisches Passwort.
HTTPS mit HTTP-Bestätigung oder HTTP mit CA-Datei wird vor Passworteingabe und
Netzwerkzugriff abgelehnt. Das Passwort wird verdeckt abgefragt. Es gibt genau
einen normalen Anmeldeversuch; ein falsches Passwort kann zur Kontosperre beitragen.

Nach der Anmeldung liest er nur feste, begrenzte GET-Ansichten der Startseite
und des Gerätestatus. Die Ansichten `tr069`, `rsc`, Benutzerverwaltung, `mirror`
und `capture` werden nur angefordert, wenn die authentifizierte Zugriffsübersicht
dieselben IDs ausweist. JSON enthält Antwortstrukturen, Zugriffsebenen,
zugelassene Namen und beobachtete Merkmale. Passwörter, Cookies, Parameterwerte
und Rohseiten werden weder ausgegeben noch gespeichert. Es werden keine
Einstellungen abgesendet und keine CWMP-, Shell-, Reset-, Neustart-, Upload-
oder Firmware-Anfragen ausgeführt. Diese Beobachtungen belegen weder Root-Zugriff
noch Gerätesupport.
JSON enthält `transport` als `local-https` oder `local-http` sowie
`tls_peer_verified` und `tls_trust_source`, aber keine Details des
Serverzertifikats. `SSLKEYLOGFILE` aktiviert keine Aufzeichnung von
TLS-Sitzungsgeheimnissen. Verifizierte HTTPS-Anmeldung und Zertifikatsbereitstellung
sind auf dem konkreten TTN.10-Gerät noch nicht nachgewiesen; ein erreichbarer
HTTPS-Port belegt sie nicht.

Das JSON-Feld `host` enthält die angegebene private IP-Adresse. Halten Sie den
Bericht privat und entfernen Sie die Adresse vor der Weitergabe. Ein
gegenüber der angegebenen Länge unvollständiger HTTP-Body oder HTTP 401 während
der Erfassung führt zum Abbruch ohne erneuten Anmeldeversuch. HTTP 403 kann
fehlende Berechtigung eines bereits
authentifizierten Kontos für die jeweilige Seite anzeigen.

## Offline-UART-Evidenz

Prüfen Sie eine bereits vorhandene private UART-Aufzeichnung, ohne ihre
Rohdaten zu veröffentlichen:

```shell
cpe-atlas uart-evidence --isp "turk-telekom" --model "H3600P" --hardware-revision "V9.0" --firmware "H3600P V9.0 TTN.10_260210" --input h3600p-uart-private.log
```

Der Befehl liest höchstens 8 MiB aus einer lokalen Datei, öffnet keinen seriellen
Port und sendet nichts an das Gerät. Er liefert nur begrenzte, zugelassene
Boot-Metadaten und Merkmale; keine Rohzeilen, Dateipfade, Zugangsdaten oder
Geheimnisse. Wenn die erwartete Firmware und ein anderer Build gemeinsam
auftreten, lautet `firmware_identity_status` `conflicting-builds-observed`.
Wiederholungen oder reine Unterschiede in Groß-/Kleinschreibung desselben Builds
sind kein Konflikt. Auch `matched` bedeutet nur eine beobachtete Versionszeichenfolge;
ein Shell-Prompt oder UID-0-Text verifiziert keinen Root-Zugriff.
`root_access_verified` bleibt immer `false`.

## Private Gerätekennung und Konfiguration

Speichern Sie genau `{"serial":"...","mac":"..."}` in einer zugriffsbeschränkten
UTF-8-JSON-Datei und verwenden Sie `--identity-file`, damit Seriennummer und
MAC-Adresse nicht in Shell-Historie oder Prozessargumenten stehen. Die Datei ist
auf 1 KiB begrenzt und ihr Inhalt wird nicht ausgegeben. Die MAC-Adresse muss
kleingeschrieben sein; `--identity-file` lässt sich nicht mit `--serial` oder
`--mac` kombinieren. Beispiel einer verschlüsselten Offline-Forschungsdatei aus
einem privaten Ausgangsbackup:

```shell
cpe-atlas config-generate --isp "turk-telekom" --model "H3600P" --hardware-revision "V9.0" --firmware "H3600P V9.0 TTN.10_260210" --input-config config.bin --identity-file device-identity.private.json --output h3600p-research.bin --encrypted --acknowledge-legacy-crypto --acknowledge-unverified-compatibility --i-own-or-administer-this-device
```

SSH-Passwort und erforderliche Gerätepassphrase werden verdeckt abgefragt.
Blockierte, unerforschte oder nicht exakt verifizierte Ziele benötigen zusätzlich
`--acknowledge-unverified-compatibility`. Diese Bestätigung beweist weder
Firmware-Akzeptanz, Root-Zugriff, Erhalt der Dienste noch Wiederherstellung.
Ohne Ausgangsbackup enthält die Minimalvorlage keine erhaltene
Internet-/VoIP-/IPTV-/VLAN-/WLAN-/TR-069-Provisionierung. Unverschlüsselte Ausgabe
mit Zugangsdaten benötigt ausdrücklich `--allow-unencrypted`. Bewahren Sie
Originalbackup, Gerätekennungsdatei und Ausgabe getrennt in einem privaten,
vertrauenswürdigen Verzeichnis auf. Auch mit `--force` darf die Ausgabe weder
das Ausgangsbackup noch die Gerätekennungsdatei ersetzen.

Wenn verdeckte Eingabe nicht verfügbar ist, stoppt der Befehl ohne sichtbaren
Eingabefallback. Für Automatisierung dienen `--ssh-password-stdin` und
`--device-key-stdin`: bei beiden zuerst das SSH-Passwort, dann die Gerätepassphrase,
jeweils auf einer eigenen LF-/CRLF-Zeile aus einer privaten Pipe oder geschützten
Datei. Das SSH-Passwort muss 8–128 druckbare Zeichen enthalten; die
Gerätepassphrase genau 32 ASCII-Zeichen. Zu lange Werte werden abgelehnt,
nicht abgeschnitten. Diese Optionen deaktivieren keine Terminalausgabe der
eingegebenen Zeichen; verwenden Sie sie nicht zum interaktiven Tippen sichtbarer
Passwörter und geben Sie Geheimnisse nie als Kommandozeilenargumente an.

## Authentifizierter Schutz lokaler Dateien

Diese Befehle verarbeiten nur private Dateien, zu deren Nutzung Sie berechtigt
sind, und fragen die Passphrase verdeckt ab:

```shell
cpe-atlas private-protect --input config.bin --output config.bin.cpap --i-am-authorized-to-handle-this-private-file
cpe-atlas private-unprotect --input config.bin.cpap --output restored-config.bin --i-am-authorized-to-handle-this-private-file
```

Neue Container verwenden Formatversion 2, einen frischen Salt, AES-GCM zur
Authentifizierung und scrypt mit `N=2^17`, `r=8`, `p=1`. `private-unprotect` liest
auch alte Container der Version 1. Zur Migration entschlüsseln Sie einen
Version-1-Container erfolgreich in eine separate private Datei und schützen
diese erneut; neue Ausgaben verwenden immer Version 2. Unbekannte oder
überhöhte KDF-Parameter werden vor der Schlüsselableitung abgelehnt.

Dieses Format ist **kein Modem-Importformat**. Es redigiert keine Geheimnisse,
beweist keine Firmware-Kompatibilität und macht Backups nicht veröffentlichbar.
Bewahren Sie Container und Passphrase getrennt auf und laden Sie beides weder
ins Repository noch in einen Fehlerbericht. Entschlüsselte Dateien und
automatisch redigierte Berichte bleiben privat; prüfen Sie sie vor jeder
Weitergabe manuell. Die Passphrase umfasst 12–256 Unicode-Zeichen ohne
C0-/C1-Steuerzeichen, Zeilen-/Absatztrenner oder Surrogate. Ihr exakter Text
bleibt erhalten; weder Unicode-Normalisierung noch Abschneiden von Leerraum
findet statt.

Bei fehlender verdeckter Eingabe wird abgebrochen. Automatisierung kann
`--passphrase-stdin` verwenden; für das Web-Passwort gibt es `--password-stdin`.
Nutzen Sie nur eine private Pipe oder geschützte Datei, keine sichtbare
interaktive Terminaleingabe: auch diese Optionen schalten das Echo nicht aus.
Details stehen in den [Kryptografie-Notizen](docs/config-cryptography.md#authenticated-local-container),
der [CLI-Referenz](docs/cli-reference.md) und dem
[JSON- und Exit-Code-Vertrag](docs/cli-output-contract.md).

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

# CPE Access Atlas

[English](README.md) · [Türkçe](README.tr.md) · [Deutsch](README.de.md) · [Français](README.fr.md) · [Русский](README.ru.md)

Recherche liée au micrologiciel et outils sûrs pour l'accès autorisé par le
propriétaire aux modems et routeurs fournis par les FAI turcs.

> [!IMPORTANT]
> Il n'existe actuellement **aucune méthode root ou super-administrateur
> publiquement vérifiée** pour la cible initiale Türk Telekom ZTE H3600P
> `H3600P V9.0 TTN.10_260210`. Les anciennes méthodes WAN/TR-069 sont signalées
> comme corrigées. Le projet reconnaît cette version exacte et s'arrête au lieu
> d'appliquer une recette plus ancienne.

## Fonctionnalités

- Catalogue exact par FAI, appareil, révision matérielle et micrologiciel.
- États distincts pour administrateur Web standard, super-administrateur Web,
  shell local, root UID 0 et chargeur de démarrage.
- Validation d'une seule adresse IP privée, sans découverte ni balayage.
- Plan sans modification et contrôle facultatif de ports explicitement fournis.
- Modèle de rapport de recherche sans secret.
- Documentation en anglais, turc, allemand, français et russe.

Le projet n'inclut ni listes de mots de passe, ni force brute, ni identifiants
divulgués, ni scan Internet, ni firmware propriétaire, ni image VM tierce, ni
downgrade automatique.

## FAI concernés

TurkNet, Turkcell Superonline, Türksat Kablonet, Türk Telekom, Netspeed,
Vodafone Net et Millenicom sont catalogués. La présence d'un FAI ne signifie
pas que tous ses appareils sont pris en charge.

## Cible initiale

| Champ | Valeur |
|---|---|
| FAI | Türk Telekom |
| Appareil | ZTE ZXHN H3600P V9 |
| Révision matérielle | `V9.0` (vérification non résolue) |
| Micrologiciel | `H3600P V9.0 TTN.10_260210` |
| Administrateur Web standard | Pris en charge par le FAI |
| Administrateur Web privilégié | Bloqué ; recherche nécessaire |
| Shell root Linux | Non pris en charge |
| Dernière révision | 13 août 2026 |

Consultez la [compatibilité](SUPPORT.md) et la
[note de recherche](docs/research/zte-h3600p-ttn10-260210.md).

## Démarrage rapide

Python 3.11 ou version ultérieure. L'installation inclut aussi le validateur
JSON Schema :

```shell
python -m pip install -e .
cpe-atlas providers
cpe-atlas devices
cpe-atlas validate
cpe-atlas status --isp "Türk Telekom" --model "ZTE H3600P" \
  --hardware-revision "V9.0" \
  --firmware "H3600P V9.0 TTN.10_260210"
```

Valider une cible privée sans établir de connexion :

```shell
cpe-atlas doctor --host 192.168.1.1
```

La vérification de préparation, en lecture seule, pour la version exacte peut
être lancée ainsi :

```shell
cpe-atlas root-readiness \
  --isp "turk-telekom" \
  --model "H3600P" \
  --hardware-revision "V9.0" \
  --firmware "H3600P V9.0 TTN.10_260210" \
  --firmware-input firmware.bin \
  --expected-sha256 <sha256-documenté-privé>
```

Cette commande hache et inspecte le fichier uniquement comme des octets
opaques ; pour l'entrée TTN.10 actuelle, `STOP` est le résultat attendu. Elle
ne se connecte pas à l'appareil, ne génère pas de configuration et ne flashe
rien. `cpe-atlas firmware-inspect` permet la même vérification sûre du hash et
de la version d'un firmware privé. `config-generate` est un outil hors ligne,
pas un exploit root ni un flasheur ; les fichiers générés et les sauvegardes
doivent rester privés.

Dans la version 0.2.0, `apply` est volontairement fermé par défaut et ne
modifie pas cette cible bloquée.

## Sécurité et autorisation

Utilisez le projet uniquement sur un appareil vous appartenant ou avec une
autorisation explicite. Vérifiez précisément matériel et firmware, consignez
les paramètres Internet, VoIP, IPTV, VLAN et Wi-Fi, et testez une procédure de
récupération avant toute modification. Ne publiez jamais sauvegardes de
configuration, captures, mots de passe, certificats, numéros de série, adresses
MAC ou identifiants d'abonné.

Un appareil loué, prêté ou appartenant au FAI exige son accord explicite. Les
modifications peuvent affecter le contrat, la garantie, l'assistance et le
fonctionnement.

## Licence

Ce projet indépendant n'est affilié à aucun FAI ou fabricant cité. Le code et
la documentation originale sont fournis sans garantie sous
[licence BSD Zero Clause](LICENSE) (`0BSD`). La licence n'autorise pas l'accès
à l'équipement d'autrui.

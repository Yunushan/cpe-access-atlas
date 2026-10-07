# CPE Access Atlas

[English](README.md) · [Türkçe](README.tr.md) · [Deutsch](README.de.md) · [Français](README.fr.md) · [Русский](README.ru.md)

> [!NOTE]
> Cette vue d'ensemble a été synchronisée le 3 octobre 2026. Pour les
> limites de sécurité, les nouvelles options et l'installation vérifiée,
> les références à jour sont le [README anglais](README.md), la
> [politique de sécurité](SECURITY.md) et le
> [guide d'installation](docs/installation.md).
> Toutes les options figurent dans la [référence CLI anglaise](docs/cli-reference.md) ;
> l'automatisation suit le [contrat JSON et codes de sortie](docs/cli-output-contract.md).

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
| Dernière révision des preuves | 27 septembre 2026 |

`V9.0` est une clé de catalogue provisoire, non vérifiée. L'interface locale
observée indique `V9.0.7` comme version matérielle ; sa correspondance avec la
révision physique de la carte et la clé `V9.0` reste inconnue. Les exemples
ci-dessous sélectionnent cette fiche de recherche et ne prouvent pas la
compatibilité d'autres révisions. La mise à jour de la traduction ne constitue
pas une nouvelle validation matérielle.

Consultez la [compatibilité](SUPPORT.md) et la
[note de recherche](docs/research/zte-h3600p-ttn10-260210.md).

## Démarrage rapide

CPython standard 3.11–3.15. L'installation inclut aussi le validateur
JSON Schema :

L'intégration continue cible CPython standard 3.11–3.15 sous Windows, Linux et
macOS. Les vérifications locales antérieures de compatibilité utilisaient
3.15.0rc2 ; les matrices de publication et de vérification après restauration
de [v0.4.0a9](https://github.com/Yunushan/cpe-access-atlas/releases/tag/v0.4.0a9)
ont été exécutées avec 3.15.0rc3. Ces résultats concernent des préversions et
ne valident pas la version finale de Python 3.15. La CI sélectionne une
préversion 3.15 uniquement jusqu'à ce que la version finale soit disponible ;
relancez la matrice complète sur la version
finale avant de déclarer une validation sur version finale. Python sans GIL et
PyPy ne font pas partie de cette matrice. La compatibilité de l'interpréteur
n'établit pas la compatibilité modem/configuration/firmware.

```shell
python -m venv .venv
python -m pip --python .venv install --require-hashes -r requirements-ci.lock
python -m pip --python .venv install -e . --no-deps --no-build-isolation
python -m pip --python .venv check
```

Activez l'environnement avec `. .venv/bin/activate` sous Linux/macOS ou
`.venv\Scripts\Activate.ps1` dans PowerShell. Exécutez ensuite :

```shell
cpe-atlas providers
cpe-atlas devices
cpe-atlas validate
cpe-atlas status --isp "turk-telekom" --model "ZTE H3600P" --hardware-revision "V9.0" --firmware "H3600P V9.0 TTN.10_260210"
```

Le
[guide d'installation](docs/installation.md) couvre les wheels publiés, la
mise à niveau et le retour arrière.

Valider une cible privée sans établir de connexion :

```shell
cpe-atlas doctor --host 192.168.1.1
```

La vérification de préparation, en lecture seule, pour la version exacte peut
être lancée ainsi :

```shell
cpe-atlas root-readiness --isp "turk-telekom" --model "H3600P" --hardware-revision "V9.0" --firmware "H3600P V9.0 TTN.10_260210" --firmware-input firmware.bin --expected-sha256 <sha256-documenté-privé>
```

Cette commande hache et inspecte le fichier uniquement comme des octets
opaques ; pour l'entrée TTN.10 actuelle, `STOP` est le résultat attendu. Elle
ne se connecte pas à l'appareil, ne génère pas de configuration et ne flashe
rien. `cpe-atlas firmware-inspect` permet la même vérification sûre du hash et
de la version d'un firmware privé. `config-generate` est un outil hors ligne,
pas un exploit root ni un flasheur ; les fichiers générés et les sauvegardes
doivent rester privés.

**Attention :** n'importez pas de configurations chiffrées générées par
v0.4.0a1 ou une version antérieure : la dérivation des clés était incorrecte.
Gardez la sauvegarde originale privée. Le [correctif v0.4.0a2](docs/config-cryptography.md)
ne prouve ni la sûreté de l'importation ni l'accès root sur ce firmware précis.
Une sortie chiffrée exige aussi `--acknowledge-legacy-crypto`. Le format
constructeur utilise une dérivation SHA-256 ancienne et CBC sans authentification;
cette confirmation n'en fait pas une sauvegarde moderne et sûre. Même avec
`--force`, le chemin de sortie doit être différent de la sauvegarde privée.

Dans cette version, `apply` refuse volontairement toute application et ne
modifie pas cette cible bloquée.

## Preuves Web authentifiées

Utilisez le collecteur uniquement sur un H3600P vous appartenant ou que vous
êtes explicitement autorisé à administrer, via un réseau local de confiance,
isolé ou directement relié :

```shell
cpe-atlas web-evidence --isp "turk-telekom" --model "H3600P" --hardware-revision "V9.0" --firmware "H3600P V9.0 TTN.10_260210" --host 192.168.1.1 --username admin --i-own-or-administer-this-device
```

HTTPS sur le port 443 est utilisé par défaut, avec TLS 1.2 au minimum et
vérification de la chaîne de certificats et de l'IP cible à partir de la
confiance système. Pour une autorité privée dont la confiance a été établie
indépendamment, ajoutez `--tls-ca-file trusted-router-ca.pem`. Seuls des
certificats PEM ASCII sont acceptés, au maximum 65 536 octets et huit
certificats ; la vérification de l'IP reste active. Un certificat obtenu par
une connexion non vérifiée ne constitue pas une source de confiance indépendante.
Tout échec arrête la collecte, sans redirection, nouvelle tentative automatique
ni repli vers HTTP.

HTTP non chiffré sur le port 80 exige à la fois `--transport http` et
`--acknowledge-local-http-authentication`. La réponse au challenge et la session
ne sont alors pas protégées : utilisez seulement un réseau local de confiance,
isolé ou directement relié, et un mot de passe fort propre au routeur. HTTPS avec
la confirmation HTTP, ou HTTP avec un fichier CA, est refusé avant la saisie du
mot de passe ou tout accès réseau. Le mot de passe est demandé sans affichage.
Une seule tentative normale est effectuée ; un mot de passe incorrect peut
néanmoins contribuer au verrouillage du compte.

Après l'authentification, seules des requêtes GET fixes et bornées lisent les
vues d'accueil et d'état de l'appareil. Les vues `tr069`, `rsc`, de gestion des
utilisateurs, `mirror` et `capture` sont demandées uniquement si la carte
d'accès authentifiée annonce les mêmes identifiants. Le JSON contient des
structures de réponse, niveaux d'accès, noms autorisés et observations de
marqueurs. Aucun mot de passe, cookie, valeur de paramètre ou page brute n'est
affiché ni enregistré. Aucune page de configuration n'est soumise ; aucune
requête CWMP, shell, réinitialisation, redémarrage, téléversement ou firmware
n'est envoyée. Ces observations ne prouvent ni l'accès root ni la prise en
charge de l'appareil.
Le JSON indique `transport` (`local-https` ou `local-http`), `tls_peer_verified`
et `tls_trust_source`, sans détails du certificat du serveur. `SSLKEYLOGFILE`
n'active pas l'enregistrement des secrets de session TLS. L'authentification
HTTPS vérifiée et le provisionnement des certificats n'ont pas encore été validés
sur l'appareil TTN.10 exact ; un port HTTPS accessible ne les prouve pas.

Le champ JSON `host` contient l'adresse IP privée fournie. Conservez le rapport
en privé et retirez cette adresse avant de le partager. Un corps HTTP plus court
que sa longueur déclarée ou une réponse HTTP 401 pendant la collecte interrompt
l'opération sans nouvelle
tentative de connexion. HTTP 403 peut indiquer qu'un compte authentifié n'est
pas autorisé à consulter la page concernée.

## Preuves UART hors ligne

Examinez un journal UART privé déjà disponible sans en publier le contenu brut :

```shell
cpe-atlas uart-evidence --isp "turk-telekom" --model "H3600P" --hardware-revision "V9.0" --firmware "H3600P V9.0 TTN.10_260210" --input h3600p-uart-private.log
```

La commande lit au plus 8 MiB d'un fichier local, n'ouvre aucun port série et
n'envoie rien à l'appareil. Elle expose seulement des métadonnées de démarrage
bornées et autorisées ainsi que des marqueurs, sans lignes brutes, chemin de
fichier, identifiants confidentiels ou secrets. Si la version attendue et une
autre version distincte sont présentes, `firmware_identity_status` devient
`conflicting-builds-observed`. Répéter la même version ou varier uniquement sa
casse ne crée pas de conflit. Même `matched` représente seulement une chaîne
de version observée ; une invite shell ou du texte UID 0 ne valide pas root.
`root_access_verified` reste toujours `false`.

## Identité privée et configuration

Pour garder le numéro de série et l'adresse MAC hors de l'historique du shell
et des arguments de processus, stockez exactement `{"serial":"...","mac":"..."}`
dans un fichier JSON UTF-8 à accès restreint, puis utilisez `--identity-file`.
Le fichier est limité à 1 KiB et son contenu n'est jamais affiché. La MAC doit
être en minuscules ; cette option ne se combine pas avec `--serial` ou `--mac`.
Exemple de génération chiffrée hors ligne à partir d'une sauvegarde privée :

```shell
cpe-atlas config-generate --isp "turk-telekom" --model "H3600P" --hardware-revision "V9.0" --firmware "H3600P V9.0 TTN.10_260210" --input-config config.bin --identity-file device-identity.private.json --output h3600p-research.bin --encrypted --acknowledge-legacy-crypto --acknowledge-unverified-compatibility --i-own-or-administer-this-device
```

Le mot de passe SSH et la phrase secrète de l'appareil, si nécessaire, sont
demandés sans affichage. Les cibles bloquées, en recherche ou non exactement
vérifiées exigent aussi `--acknowledge-unverified-compatibility`. Cet accord ne
prouve ni l'acceptation du fichier par le firmware, ni root, ni la conservation
des services, ni la récupération. Sans sauvegarde initiale, le modèle minimal
ne préserve pas le provisionnement Internet/VoIP/IPTV/VLAN/Wi-Fi/TR-069 du FAI.
Une sortie non chiffrée contenant des identifiants exige `--allow-unencrypted`.
Gardez la sauvegarde originale, le fichier d'identité et la sortie séparés dans
un répertoire privé de confiance. Même avec `--force`, la sortie ne peut pas
remplacer la sauvegarde initiale ou le fichier d'identité.

Si la saisie masquée est indisponible, la commande s'arrête sans passer à une
saisie visible. Pour l'automatisation, `--ssh-password-stdin` et
`--device-key-stdin` lisent un canal privé ou un fichier protégé. Si les deux
sont nécessaires, fournissez d'abord le mot de passe SSH, puis la phrase secrète
de l'appareil, chacun sur une ligne LF/CRLF. Le mot de passe SSH doit contenir
8–128 caractères imprimables ; la phrase de l'appareil exactement 32 caractères
ASCII. Les valeurs trop longues sont rejetées et non tronquées. Ces options
ne désactivent pas l'écho du terminal : ne les utilisez pas pour saisir
interactivement des secrets visibles et ne placez jamais de secret dans les
arguments de commande.

## Protection authentifiée des fichiers locaux

Ces commandes traitent uniquement les fichiers privés que vous êtes autorisé
à utiliser et demandent la phrase secrète sans l'afficher :

```shell
cpe-atlas private-protect --input config.bin --output config.bin.cpap --i-am-authorized-to-handle-this-private-file
cpe-atlas private-unprotect --input config.bin.cpap --output restored-config.bin --i-am-authorized-to-handle-this-private-file
```

Les nouveaux conteneurs utilisent le format version 2, un sel neuf,
l'authentification AES-GCM et scrypt avec `N=2^17`, `r=8`, `p=1`.
`private-unprotect` lit aussi les anciens conteneurs version 1. Pour migrer,
déchiffrez avec succès un conteneur version 1 dans un fichier privé distinct,
puis protégez à nouveau ce fichier ; toute nouvelle écriture utilise la version 2.
Les paramètres KDF inconnus ou excessifs sont rejetés avant la dérivation.

Ce format **n'est pas un format d'importation pour modem**. Il ne supprime pas
les secrets, ne prouve pas la compatibilité du firmware et ne rend pas une
sauvegarde publiable. Conservez le conteneur et la phrase secrète séparément ;
ne les ajoutez ni au dépôt ni à un rapport de bug. Les fichiers déchiffrés et
rapports automatiquement expurgés restent privés : contrôlez-les manuellement
avant tout partage. La phrase contient 12–256 caractères Unicode, sans contrôles
C0/C1, séparateurs de ligne/paragraphe ou substituts Unicode. Préservez son texte
exact : aucune normalisation Unicode ni suppression d'espaces n'est appliquée.

Sans saisie masquée, la commande s'arrête. Pour l'automatisation,
`--passphrase-stdin` lit la phrase de protection et `--password-stdin` le mot
de passe Web. Utilisez seulement un canal privé ou un fichier protégé : ces
options ne désactivent pas l'écho et ne servent pas à saisir un secret dans un
terminal visible. Consultez les [notes cryptographiques](docs/config-cryptography.md#authenticated-local-container),
la [référence CLI](docs/cli-reference.md) et le
[contrat JSON et codes de sortie](docs/cli-output-contract.md).

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

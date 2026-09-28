<p align="center">
  <img width="180" height="180" alt="Calm Web" src="https://github.com/user-attachments/assets/56e88ff3-1cb2-4263-80d0-ad7b493bb52c" />
</p>

<h1 align="center">Calm Web</h1>

<p align="center">
  <b>Un filtre web pour tout le PC.</b><br>
  Publicités, arnaques et logiciels de prise de contrôle à distance bloqués —<br>
  pour tous les navigateurs, tous les comptes, même ceux installés demain.
</p>

<p align="center">
  <sub><i>A system-wide web filter. Ads, scams and remote-control tools blocked, for every browser and every account.</i></sub>
</p>

<p align="center">
  <a href="https://github.com/Tontonjo/calmweb/releases/latest"><img alt="Dernière version" src="https://img.shields.io/github/v/release/Tontonjo/calmweb?label=version&color=2ea44f"></a>
  <img alt="Windows" src="https://img.shields.io/badge/Windows-10%20%7C%2011-0078d6">
  <img alt="Python" src="https://img.shields.io/badge/Python-3.12%2B-3776ab">
  <img alt="Licence" src="https://img.shields.io/badge/licence-GPL--3.0-blue">
  <img alt="Domaines filtrés" src="https://img.shields.io/badge/domaines%20filtr%C3%A9s-600%20000%2B-orange">
</p>

<p align="center">
  <a href="https://github.com/Tontonjo/calmweb/releases/latest"><b>⬇️  Télécharger la dernière version pour Windows</b></a>
</p>

<hr>

<details open>
<summary><h2>🇫🇷 &nbsp;Français</h2></summary>

### En bref

Calm Web s'installe **au niveau du système** : une fois lancé, tout ce qui sort du PC pour aller sur le web passe par lui, quel que soit le navigateur et quel que soit le compte utilisateur.

- 🛡️ **Plus de 600 000 domaines bloqués** — publicité, traçage, arnaques, malware.
- 🔒 **HTTPS obligatoire** — le trafic en clair est refusé.
- 🖥️ **Prises de contrôle à distance bloquées** — TeamViewer, AnyDesk et consorts, l'outil préféré des faux dépanneurs ([liste](https://github.com/Tontonjo/calmweb/blob/main/filters/blocklist.txt)).
- 🚫 **Adresses IP directes et ports exotiques refusés**.
- 🧘 **À installer et à oublier** — mises à jour des listes automatiques, icône discrète dans la barre des tâches.

> [!WARNING]
> Calm Web **n'est pas un antivirus** et ne garantit aucune protection totale contre le piratage ou les arnaques — il ne le prétend pas. Chaque utilisateur reste responsable de sa navigation. Calm Web ajoute un garde-fou : il bloque des techniques connues en s'appuyant sur des ressources communautaires.

### Installation

1. Télécharger la dernière version — **[⬇️ TÉLÉCHARGEMENT](https://github.com/Tontonjo/calmweb/releases/latest)** (Windows uniquement).
2. Exécuter le fichier et suivre les indications.
3. Calm Web démarre dans la barre des tâches. Il peut être nécessaire de cliquer sur <img width="24" alt="chevron" src="https://github.com/user-attachments/assets/20bafe23-b3ca-411e-8706-922b123859b2" /> en bas à droite pour voir l'icône.

### La fenêtre Calm Web

Une fois installé, Calm Web peut être oublié. **Un double-clic sur l'icône ouvre la fenêtre**, qui regroupe tout ce dont on peut avoir besoin :

| Page | Contenu |
| --- | --- |
| 🟢 **État** | Protection active ou non, gros bouton pour l'activer / la désactiver, compteurs de sites bloqués et autorisés, taille des listes, dernière mise à jour, connexions en cours |
| 📜 **Activité** | Journal en direct, coloré, filtrable (bloqués / autorisés / système), recherche par domaine, export dans un fichier texte |
| ⚙️ **Paramètres** | Un interrupteur par règle de filtrage, notifications de blocage, langue (français / anglais) et thème (système, clair, sombre) |
| 📋 **Listes** | Liste blanche, liste noire locale, **sources téléchargées** (ajouter ou retirer une liste), et « **Vérifier un domaine** » : bloqué ou non, **et par quelle liste** |
| ℹ️ **À propos** | Version, recherche de mise à jour, emplacement du fichier de configuration |

L'interface suit la langue de Windows au premier démarrage et se change à tout moment dans *Paramètres*.

Le **clic droit sur l'icône** donne les mêmes actions en raccourci : état et compteurs, activation / désactivation, interrupteurs de filtrage, édition de la configuration, rechargement des listes, mise à jour, quitter.

> [!TIP]
> **Débloquer un site.** Les listes noires sont *téléchargées* : la plupart des domaines bloqués (`teamviewer.com`, par exemple) ne se trouvent pas dans votre configuration, et les retirer de votre liste noire locale ne change donc rien. Le seul moyen de rouvrir un domaine est de l'ajouter à la **liste blanche**, qui a la priorité sur toutes les autres règles. La page *Listes → Vérifier un domaine* indique de quelle liste vient le blocage et propose un bouton **Autoriser ce site** qui s'applique immédiatement.

Après toute modification, pensez à recharger la configuration. Certains sites conservent du cache ou des connexions ouvertes : en cas de doute, redémarrez le PC.

### Comment ça marche

Calm Web démarre un [proxy](https://fr.wikipedia.org/wiki/Proxy) local (`127.0.0.1:8080`) et configure Windows pour en forcer l'usage. **Il ne casse pas les connexions sécurisées et n'installe aucun certificat tiers** : le contenu des pages n'est jamais déchiffré, seuls les noms de domaine demandés sont examinés.

Au démarrage, il télécharge plusieurs listes de blocage et rassemble tous les domaines trouvés dans une liste noire unique. Si la liste blanche ne peut pas être téléchargée, le filtrage se met **en pause** plutôt que de bloquer à l'aveugle, et reprend dès qu'une liste arrive.

Par défaut, il :

- bloque tous les domaines listés, sauf ceux de la liste blanche ;
- bloque les outils de « support à distance » régulièrement utilisés à mauvais escient ;
- bloque la navigation HTTP afin de garantir une navigation sécurisée ;
- bloque l'accès direct aux adresses IP ;
- bloque l'utilisation de ports non standards.

<details>
<summary><b>HTTP/1.1, HTTP/2 et HTTP/3 (QUIC) — le détail</b></summary>

Calm Web se place entre le navigateur et Internet, et doit donc suivre les protocoles réellement utilisés aujourd'hui :

- **HTTP/1.1** — les requêtes en clair sont analysées, filtrées puis relayées. Les en-têtes « hop-by-hop » sont retirés, `Expect: 100-continue` est laissé au serveur d'origine, et la négociation `Upgrade` est préservée pour que les **WebSockets** continuent de fonctionner.
- **HTTP/2** — négocié par ALPN *à l'intérieur* de TLS : il traverse le tunnel `CONNECT` sans être touché. Le relais ne fait aucune hypothèse sur le découpage des messages et tolère les longues périodes d'inactivité, une connexion HTTP/2 étant volontairement maintenue ouverte entre deux requêtes.
- **HTTP/3 (QUIC)** — QUIC circule sur UDP et ne peut pas passer par un proxy `CONNECT`. Tous les navigateurs courants détectent le proxy système et **retombent d'eux-mêmes sur HTTP/2 en TCP**, donc filtré.

</details>

### Tester

Envie de constater l'efficacité ? Activez Calm Web et [rendez-vous ici](https://paileactivist.github.io/toolz/adblock.html).

</details>

<details>
<summary><h2>🇬🇧 &nbsp;English</h2></summary>

### In short

Calm Web installs **at the system level**: once running, everything leaving the PC for the web goes through it, whatever the browser and whatever the user account.

- 🛡️ **Over 600,000 domains blocked** — advertising, tracking, scams, malware.
- 🔒 **HTTPS enforced** — cleartext traffic is refused.
- 🖥️ **Remote-control software blocked** — TeamViewer, AnyDesk and friends, the favourite tool of fake support scams.
- 🚫 **Direct IP addresses and unusual ports refused**.
- 🧘 **Install it and forget it** — lists refresh themselves, quiet tray icon.

> [!WARNING]
> Calm Web **is not an antivirus** and does not guarantee protection against hacking or scams. It reduces some risks by blocking known techniques, using community-maintained resources.

### Installation

Download the latest Windows build — **[⬇️ DOWNLOAD](https://github.com/Tontonjo/calmweb/releases/latest)** — run it, follow the wizard. Calm Web then lives in the system tray.

### The Calm Web window

**Double-clicking the tray icon opens the window**, which holds everything an advanced user needs:

| Page | Contents |
| --- | --- |
| 🟢 **Status** | Protection on/off with a single large button, blocked and allowed counters, list sizes, last refresh, live connections |
| 📜 **Activity** | Live colour-coded log, category filters (blocked / allowed / system), domain search, text export |
| ⚙️ **Settings** | One switch per filtering rule, block notifications, language (French/English) and theme (system/light/dark) |
| 📋 **Lists** | Whitelist, local blocklist, **downloaded sources** (add or drop a list), and *Check a domain*: blocked or not, **and which list it came from** |
| ℹ️ **About** | Version, update check, configuration file location |

The interface follows the Windows language on first run and can be changed at any time in *Settings*. Right-clicking the icon mirrors the same actions: state and counters, enable/disable, one switch per rule, edit the configuration, reload the lists, check for updates, quit.

> [!TIP]
> **Unblocking a site.** The blocklists are *downloaded*: most blocked domains (`teamviewer.com`, for instance) are not in your configuration at all, so removing them from your own blocklist changes nothing. The only way to reopen a domain is to add it to the **whitelist**, which takes priority over every other rule. *Lists → Check a domain* names the list responsible and offers an **Allow this site** button that takes effect immediately.

After making any change, remember to reload the configuration. Some websites keep cached data or open connections: if in doubt, restart the PC.

### How it works

Calm Web starts a local proxy (`127.0.0.1:8080`) and configures Windows to force its use. **It does not break secure connections and installs no third-party certificate**: page contents are never decrypted, only the requested domain names are examined.

At startup it downloads several blocklists and merges every domain found into a single blocklist. If the whitelist cannot be downloaded, filtering **pauses** rather than blocking blindly, and resumes as soon as a list arrives.

By default it:

- blocks all listed domains except those in the whitelist;
- blocks "remote support" tools that are frequently misused;
- blocks HTTP browsing to ensure secure browsing;
- blocks direct access to IP addresses;
- blocks the use of non-standard ports.

<details>
<summary><b>HTTP/1.1, HTTP/2 and HTTP/3 (QUIC) — the detail</b></summary>

- **HTTP/1.1** — cleartext requests are parsed, filtered and forwarded. Hop-by-hop headers are stripped, `Expect: 100-continue` is left to the origin server, and `Upgrade` handshakes are preserved so **WebSockets** keep working.
- **HTTP/2** — negotiated by ALPN *inside* TLS, so it rides through the `CONNECT` tunnel untouched. The relay makes no assumption about message framing and tolerates long idle periods, since an h2 connection is deliberately kept open between requests.
- **HTTP/3 (QUIC)** — QUIC runs over UDP and cannot travel through a `CONNECT` proxy. Every mainstream browser sees the system proxy and **falls back to HTTP/2 over TCP on its own**, where Calm Web filters it.

</details>

### Test it

Turn Calm Web on and [visit this page](https://paileactivist.github.io/toolz/adblock.html).

</details>

<hr>

## 📚 Listes utilisées / Block lists

**Listes noires** — modifiables depuis *Listes → Sources* ou la section `[BLOCK_SOURCES]` de `custom.cfg` :

| Source | Contenu |
| --- | --- |
| [StevenBlack/hosts](https://raw.githubusercontent.com/StevenBlack/hosts/refs/heads/master/hosts) | Publicité et traçage, référence historique |
| [easylist/listefr](https://raw.githubusercontent.com/easylist/listefr/refs/heads/master/hosts.txt) | Publicité francophone |
| [hagezi/dns-blocklists (ultimate)](https://raw.githubusercontent.com/hagezi/dns-blocklists/refs/heads/main/adblock/ultimate.txt) | Le gros du volume : pub, traçage, malware |
| [Tontonjo/calmweb](https://raw.githubusercontent.com/Tontonjo/calmweb/refs/heads/main/filters/blocklist.txt) | Liste maison : contrôle à distance, arnaques repérées |
| [URLhaus](https://urlhaus.abuse.ch/downloads/csv/) | Distribution de malware, mise à jour en continu |
| [Red Flag Domains](https://dl.red.flag.domains/pihole/red.flag.domains.txt) | Noms de domaine `.fr` récemment déposés et suspects — ajoutée séparément, mise en cache et rafraîchie une fois par jour |

**Liste blanche** — [Tontonjo/calmweb/filters/whitelist.txt](https://raw.githubusercontent.com/Tontonjo/calmweb/refs/heads/main/filters/whitelist.txt), modifiable via `[WHITELIST_SOURCES]`. Elle gagne toujours contre les listes noires.

## ⚙️ Configuration (`custom.cfg`, section `[OPTIONS]`)

Le fichier vit dans `%APPDATA%\CalmWeb` ; son emplacement exact est indiqué dans *À propos*. Toutes ces options — sauf `allow_revocation_http` — se règlent aussi depuis la fenêtre et le menu de l'icône, et sont réécrites dans le fichier à chaque changement.

| Option | Défaut | Effet |
| --- | --- | --- |
| `block_http_traffic` | `1` | Force le HTTPS. Refuse aussi les `CONNECT` vers le port 80, qui tunnelliseraient du HTTP en clair en contournant la règle. |
| `block_ip_direct` | `1` | Bloque la navigation directe vers une adresse IP (IPv4 et IPv6). |
| `block_http_other_ports` | `1` | Seuls les ports 80, 443 et 3478 (relais TURN des appels WebRTC) sont autorisés. À mettre à `0` si un bac à sable ou une application métier cesse de fonctionner. |
| `notify_on_block` | `0` | Notification système nommant le domaine et la règle lors d'un blocage — un site bloqué en HTTPS ne peut pas afficher de page d'explication, le navigateur montre seulement une erreur de connexion. Les blocages répétés sont regroupés. Désactivé par défaut : sur une page chargée de publicités, le blocage intéressant est noyé parmi des dizaines d'autres. |
| `ask_elevation` | `1` | Propose un redémarrage en administrateur au lancement, et seulement quand cela sert à quelque chose — aujourd'hui, installer les exemptions loopback. Refuser démarre Calm Web sans privilèges. Un compte standard n'est jamais sollicité. |
| `allow_revocation_http` | `1` | Laisse passer le trafic de révocation de certificats (CRL, AIA, OCSP) malgré la règle HTTPS ; ce trafic ne circule qu'en HTTP en clair. **Pas d'interrupteur dans l'interface** — c'est un réglage de diagnostic. Chaque requête autorisée apparaît dans l'onglet *Système*. Les listes noires s'appliquent toujours. |
| `language` | *(vide)* | `fr`, `en`, ou vide pour suivre Windows. |
| `theme` | `system` | `system`, `light` ou `dark`. |

Les sections `[BLOCK_SOURCES]` et `[WHITELIST_SOURCES]` listent les URL téléchargées, une par ligne. Une section absente rétablit les valeurs par défaut ; une section **vide** signifie « aucune source », ce qui est un choix délibéré.

## 🔨 Construire depuis les sources

```bat
scripts\build.cmd
```

Construit l'exécutable avec PyInstaller, puis l'installateur avec Inno Setup. Dépendances de développement : `pip install -e .[dev]`.

> [!IMPORTANT]
> **PyInstaller 6.22 ou plus récent est requis.** Python 3.14 embarque Tcl/Tk 9, dont la bibliothèque vit dans une archive zipfs à l'intérieur de la DLL plutôt que dans un dossier sur disque (`$tcl_library` renvoie `//zipfs:/lib/tcl/tcl_library`). Les versions antérieures de PyInstaller ne savent pas l'empaqueter : la construction réussit, mais l'application gelée échoue au démarrage avec `FileNotFoundError: Tcl data directory "..._MEIxxxxx\_tcl_data" not found`. Mettre à jour avec `python -m pip install --upgrade pyinstaller` ; le script de construction indique quel cas il a détecté.

Tests et style : `pytest` et `ruff check .`

## 🐞 Problèmes connus

- **Bac à sable Windows (Sandbox) inopérant** lorsque Calm Web tourne, à cause du blocage des ports. Passer `block_http_other_ports` à `0`.

## 🗺️ Feuille de route

- Tester sur Windows 10
- Un mode « discret » à l'échelle du système, sans aucune icône visible
- Permettre d'exclure un programme entier du filtrage
- Enrichir la liste de blocage au fil des arnaques découvertes — [les signalements sont bienvenus](https://github.com/Tontonjo/calmweb/issues)
- URLhaus fournit des URL et des IP ; seuls les domaines sont utilisés pour l'instant. Bloquer l'URL complète éviterait de fermer des services de partage de fichiers par ailleurs légitimes.

## 📝 Historique des versions

Voir **[CHANGELOG.md](CHANGELOG.md)**.

## 📄 Licence

[GNU General Public License v3.0](LICENSE) — Tonton Jo.


# 🛡️ CalmWeb

<div align="center">

![CalmWeb Logo](https://github.com/user-attachments/assets/3508836a-b2dd-4c0b-ac6f-93a490b5ee94)

**Un proxy web intelligent pour protéger les utilisateurs vulnérables des arnaques et logiciels malveillants**
**An intelligent web proxy to protect vulnerable users from scams and malicious software**

[🇫🇷 **Français**](#-français) • [🇺🇸 **English**](#-english)

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![Windows](https://img.shields.io/badge/platform-Windows-blue.svg)](https://www.microsoft.com/windows)
[![Stars](https://img.shields.io/github/stars/Tontonjo/calmweb)](https://github.com/Tontonjo/calmweb/stargazers)

[🎥 **Voir la démonstration**](https://www.youtube.com/watch?v=hA5_J1NefKE) • [📥 **Télécharger**](https://github.com/Tontonjo/calmweb/releases) • [🐛 **Signaler un bug**](https://github.com/Tontonjo/calmweb/issues)

</div>

---

# 🇫🇷 **Français**

## 🎯 **Pourquoi CalmWeb ?**

CalmWeb est spécialement conçu pour **protéger les personnes âgées et les utilisateurs peu expérimentés** des dangers d'Internet. Il fonctionne au niveau système, protégeant tous les navigateurs et applications.

### ✨ **Principales fonctionnalités**

- 🚫 **Blocage intelligent** : Protection contre +67,000 domaines de scams français
- 🔒 **Anti-TeamViewer** : Bloque les logiciels de contrôle à distance
- 🌐 **Système global** : Fonctionne avec tous les navigateurs
- 🇫🇷 **Mise à jour automatique** : Intégration avec red.flag.domains
- 📊 **Interface simple** : Menu système facile d'utilisation
- ⚡ **Performance** : Impact minimal sur la navigation

---

## 🚀 **Installation rapide**

### 📋 **Prérequis**
- **Windows 10/11**
- **Python 3.8+** ([📥 Télécharger](https://python.org))
  - ⚠️ **Crucial** : Cocher "Add Python to PATH" lors de l'installation

### 🪄 **Installation en 1 clic**

1. **Téléchargez** le projet CalmWeb
2. **Installez** les dépendances : `pip install requests pystray pillow psutil`
3. **Lancez** avec `start.bat` (double-clic)

```bash
# Installation manuelle
git clone https://github.com/Tontonjo/calmweb.git
cd calmweb
pip install -r requirements.txt
python program/calmweb.py
```

---

## 📖 **Guide d'utilisation**

### 🎮 **Démarrage**

Une fois installé, CalmWeb peut être lancé de plusieurs façons :

```bash
# Méthode 1 : Double-clic sur le fichier batch (recommandé)
start.bat

# Méthode 2 : Ligne de commande
python program/calmweb.py

# Méthode 3 : Depuis le dossier d'installation
cd program && python calmweb.py
```

### ⚙️ **Configuration**

CalmWeb se configure via le fichier `%APPDATA%\CalmWeb\custom.cfg` :

```ini
[BLOCK]
teamviewer.com
anydesk.com
site-arnaque.fr

[WHITELIST]
google.com
youtube.com
wikipedia.org

[OPTIONS]
block_ip_direct = 1
block_http_traffic = 1
block_http_other_ports = 1
```

**Accès rapide** : Clic droit sur l'icône systray → "Éditer configuration"

### 🎯 **Fonctionnement**

CalmWeb fonctionne comme un **proxy transparent** :

1. **Démarre** automatiquement sur `127.0.0.1:8080`
2. **Configure** Windows pour utiliser ce proxy
3. **Filtre** toutes les requêtes web en temps réel
4. **Bloque** les domaines dangereux
5. **Autorise** les sites de confiance

---

## 🛡️ **Que bloque CalmWeb ?**

### 🚫 **Blocages automatiques**

- **🌐 Domaines malveillants** : +67,000 sites de scams français ([red.flag.domains](https://red.flag.domains))
- **📡 Contrôle à distance** : TeamViewer, AnyDesk, Chrome Remote Desktop
- **🔗 Navigation par IP** : Évite les sites sans nom de domaine
- **⚠️ Ports non-standard** : Bloque les connexions suspectes
- **📋 Listes externes** :
  - [StevenBlack hosts](https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts)
  - [EasyList FR](https://raw.githubusercontent.com/easylist/listefr/master/hosts.txt)
  - [Hagezi Ultimate](https://raw.githubusercontent.com/hagezi/dns-blocklists/main/domains/ultimate.txt)

### ✅ **Sites autorisés**

- **Moteurs de recherche** : Google, Bing, DuckDuckGo
- **Réseaux sociaux** : Facebook, Twitter, YouTube
- **Services essentiels** : Banques, administrations françaises
- **E-commerce** : Amazon, sites marchands légitimes
- **[Liste complète](filters/whitelist.txt)** mise à jour régulièrement

---

## 🔧 **Interface et contrôles**

### 📱 **Menu systray**

L'icône CalmWeb dans la barre système offre :

- 🔴/🟢 **Activer/Désactiver** le blocage
- ✏️ **Éditer la configuration**
- 📋 **Afficher les logs**
- 🔄 **Recharger la configuration**
- ❌ **Quitter l'application**

### 📊 **Surveillance**

```bash
# Logs en temps réel
[14:32:20] ✅ [WHITELIST ALLOW] google.com
[14:32:25] 🚫 [PROXY BLOCK] teamviewer.com
[14:32:30] ✅ [PROXY FORWARD] youtube.com
```

---

## 🛠️ **Dépannage**

### ❓ **Problèmes courants**

<details>
<summary><strong>🐍 Python non trouvé</strong></summary>

```bash
# Solution
1. Installer Python depuis https://python.org
2. ⚠️ Cocher "Add Python to PATH"
3. Redémarrer l'ordinateur
4. Tester : python --version
```
</details>

<details>
<summary><strong>📦 Erreur de dépendances</strong></summary>

```bash
# Solution
pip install --upgrade pip
pip install -r requirements.txt
```
</details>

<details>
<summary><strong>🌐 Le proxy ne démarre pas</strong></summary>

```bash
# Vérifications
1. Port 8080 libre : netstat -an | find "8080"
2. Lancer en administrateur si nécessaire
3. Vérifier le firewall Windows
```
</details>

<details>
<summary><strong>🚫 Site légitime bloqué</strong></summary>

```bash
# Solution
1. Clic droit icône systray → "Éditer configuration"
2. Ajouter le domaine dans [WHITELIST]
3. Clic droit → "Recharger configuration"
```
</details>

### 📞 **Support avancé**

- **🐛 Bugs** : [Signaler sur GitHub](https://github.com/Tontonjo/calmweb/issues)
- **💬 Questions** : [Discussions GitHub](https://github.com/Tontonjo/calmweb/discussions)
- **📧 Contact** : Créer une issue avec le tag `support`

---

## 🏗️ **Architecture technique**

### 📊 **Composants principaux**

```
CalmWeb/
├── 🎯 Proxy HTTP(S)          # Filtrage temps réel sécurisé
├── 🛡️ Résolveur de blocklists # Gestion intelligente des listes
├── ⚙️ Détection d'éditeur     # Support multi-éditeurs (VS Code, Notepad++)
├── 📝 Système de logs        # Surveillance thread-safe
├── 🔄 Auto-updater          # Mises à jour red.flag.domains (67k+ domaines)
└── 🔒 Sécurité renforcée     # Validation d'entrées, gestion d'erreurs
```

### 🔧 **Dépendances**

| Package | Version | Usage |
|---------|---------|-------|
| `requests` | ≥2.25.0 | Téléchargement des listes |
| `pystray` | ≥0.17.0 | Interface systray |
| `pillow` | ≥8.0.0 | Gestion des icônes |
| `psutil` | ≥5.8.0 | Informations système |

---

## 🤝 **Contribuer**

### 🎯 **Comment aider**

- **🐛 Signaler des bugs** : [Issues GitHub](https://github.com/Tontonjo/calmweb/issues)
- **✨ Proposer des améliorations** : [Feature requests](https://github.com/Tontonjo/calmweb/issues/new)
- **📝 Améliorer la documentation** : Pull requests bienvenues
- **🌐 Ajouter des domaines** : Contribuer aux listes de blocage/whitelist

### 🏃‍♂️ **Développement**

```bash
# Clone du projet
git clone https://github.com/Tontonjo/calmweb.git
cd calmweb

# Installation en mode développement
pip install -r requirements.txt

# Tests (si disponibles)
python -m pytest tests/

# Lancement en mode debug
python program/calmweb.py --debug
```
---

## 📄 **Licence et crédits**

### 📜 **Licence**

Ce projet est sous licence **MIT**. Voir [LICENSE](LICENSE) pour plus de détails.

### 🙏 **Remerciements**

- **[red.flag.domains](https://red.flag.domains)** - Base de données des domaines français malveillants
- **[StevenBlack](https://github.com/StevenBlack/hosts)** - Liste de hosts complète
- **[EasyList](https://easylist.to/)** - Filtres pour les publicités
- **[Hagezi](https://github.com/hagezi/dns-blocklists)** - Listes de DNS malveillants

### 👨‍💻 **Auteur**

**[Tontonjo](https://github.com/Tontonjo)** - Créateur et mainteneur principal

---

<div align="center">

**🛡️ CalmWeb - Protection web pour tous 🛡️**

[⭐ **Star le projet**](https://github.com/Tontonjo/calmweb) • [🍴 **Fork**](https://github.com/Tontonjo/calmweb/fork) • [📥 **Download**](https://github.com/Tontonjo/calmweb/releases)

Made with ❤️ for digital safety

</div>

---

# 🇺🇸 **English**

## 🎯 **Why CalmWeb?**

CalmWeb is specifically designed to **protect elderly and inexperienced users** from Internet dangers. It works at the system level, protecting all browsers and applications.

### ✨ **Key Features**

- 🚫 **Smart Blocking**: Protection against +67,000 French scam domains
- 🔒 **Anti-TeamViewer**: Blocks remote control software
- 🌐 **System-wide**: Works with all browsers
- 🇫🇷 **Auto-update**: Integration with red.flag.domains
- 📊 **Simple Interface**: Easy-to-use system menu
- ⚡ **Performance**: Minimal impact on browsing

---

## 🚀 **Quick Installation**

### 📋 **Requirements**
- **Windows 10/11**
- **Python 3.8+** ([📥 Download](https://python.org))
  - ⚠️ **Important**: Check "Add Python to PATH" during installation

### 🪄 **1-Click Installation**

1. **Download** the CalmWeb project
2. **Install** dependencies: `pip install requests pystray pillow psutil`
3. **Launch** with `start.bat` (double-click)

```bash
# Manual installation
git clone https://github.com/Tontonjo/calmweb.git
cd calmweb
pip install -r requirements.txt
python program/calmweb.py
```

---

## 📖 **Usage Guide**

### 🎮 **Starting**

Once installed, CalmWeb can be launched in several ways:

```bash
# Method 1: Double-click batch file (recommended)
start.bat

# Method 2: Command line
python program/calmweb.py

# Method 3: From installation folder
cd program && python calmweb.py
```

### ⚙️ **Configuration**

CalmWeb is configured via the `%APPDATA%\CalmWeb\custom.cfg` file:

```ini
[BLOCK]
teamviewer.com
anydesk.com
scam-site.fr

[WHITELIST]
google.com
youtube.com
wikipedia.org

[OPTIONS]
block_ip_direct = 1
block_http_traffic = 1
block_http_other_ports = 1
```

**Quick access**: Right-click system tray icon → "Edit configuration"

### 🎯 **How it works**

CalmWeb functions as a **transparent proxy**:

1. **Starts** automatically on `127.0.0.1:8080`
2. **Configures** Windows to use this proxy
3. **Filters** all web requests in real-time
4. **Blocks** dangerous domains
5. **Allows** trusted sites

---

## 🛡️ **What does CalmWeb block?**

### 🚫 **Automatic blocking**

- **🌐 Malicious domains**: +67,000 French scam sites ([red.flag.domains](https://red.flag.domains))
- **📡 Remote control**: TeamViewer, AnyDesk, Chrome Remote Desktop
- **🔗 IP navigation**: Avoids sites without domain names
- **⚠️ Non-standard ports**: Blocks suspicious connections
- **📋 External lists**:
  - [StevenBlack hosts](https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts)
  - [EasyList FR](https://raw.githubusercontent.com/easylist/listefr/master/hosts.txt)
  - [Hagezi Ultimate](https://raw.githubusercontent.com/hagezi/dns-blocklists/main/domains/ultimate.txt)

### ✅ **Allowed sites**

- **Search engines**: Google, Bing, DuckDuckGo
- **Social networks**: Facebook, Twitter, YouTube
- **Essential services**: Banks, French administrations
- **E-commerce**: Amazon, legitimate merchant sites
- **[Complete list](filters/whitelist.txt)** regularly updated

---

## 🔧 **Interface and controls**

### 📱 **System tray menu**

The CalmWeb icon in the system bar offers:

- 🔴/🟢 **Enable/Disable** blocking
- ✏️ **Edit configuration**
- 📋 **Show logs**
- 🔄 **Reload configuration**
- ❌ **Quit application**

### 📊 **Monitoring**

```bash
# Real-time logs
[14:32:20] ✅ [WHITELIST ALLOW] google.com
[14:32:25] 🚫 [PROXY BLOCK] teamviewer.com
[14:32:30] ✅ [PROXY FORWARD] youtube.com
```

---

## 🛠️ **Troubleshooting**

### ❓ **Common issues**

<details>
<summary><strong>🐍 Python not found</strong></summary>

```bash
# Solution
1. Install Python from https://python.org
2. ⚠️ Check "Add Python to PATH"
3. Restart computer
4. Test: python --version
```
</details>

<details>
<summary><strong>📦 Dependency error</strong></summary>

```bash
# Solution
pip install --upgrade pip
pip install -r requirements.txt
```
</details>

<details>
<summary><strong>🌐 Proxy won't start</strong></summary>

```bash
# Checks
1. Port 8080 free: netstat -an | find "8080"
2. Run as administrator if needed
3. Check Windows firewall
```
</details>

<details>
<summary><strong>🚫 Legitimate site blocked</strong></summary>

```bash
# Solution
1. Right-click tray icon → "Edit configuration"
2. Add domain to [WHITELIST]
3. Right-click → "Reload configuration"
```
</details>

### 📞 **Advanced support**

- **🐛 Bugs**: [Report on GitHub](https://github.com/Tontonjo/calmweb/issues)
- **💬 Questions**: [GitHub Discussions](https://github.com/Tontonjo/calmweb/discussions)
- **📧 Contact**: Create an issue with `support` tag

---

## 🏗️ **Technical Architecture**

### 📊 **Main components**

```
CalmWeb/
├── 🎯 HTTP(S) Proxy          # Secure real-time filtering
├── 🛡️ Blocklist resolver     # Intelligent list management
├── ⚙️ Editor detection       # Multi-editor support (VS Code, Notepad++)
├── 📝 Log system            # Thread-safe monitoring
├── 🔄 Auto-updater          # red.flag.domains updates (67k+ domains)
└── 🔒 Enhanced security     # Input validation, error handling
```

### 🔧 **Dependencies**

| Package | Version | Usage |
|---------|---------|-------|
| `requests` | ≥2.25.0 | List downloading |
| `pystray` | ≥0.17.0 | System tray interface |
| `pillow` | ≥8.0.0 | Icon management |
| `psutil` | ≥5.8.0 | System information |

---

## 🤝 **Contributing**

### 🎯 **How to help**

- **🐛 Report bugs**: [GitHub Issues](https://github.com/Tontonjo/calmweb/issues)
- **✨ Suggest improvements**: [Feature requests](https://github.com/Tontonjo/calmweb/issues/new)
- **📝 Improve documentation**: Pull requests welcome
- **🌐 Add domains**: Contribute to blocking/whitelist lists

### 🏃‍♂️ **Development**

```bash
# Clone project
git clone https://github.com/Tontonjo/calmweb.git
cd calmweb

# Development installation
pip install -r requirements.txt

# Tests (if available)
python -m pytest tests/

# Launch in debug mode
python program/calmweb.py --debug
```
---

## 📄 **License and Credits**

### 📜 **License**

This project is under **MIT** license. See [LICENSE](LICENSE) for details.

### 🙏 **Thanks**

- **[red.flag.domains](https://red.flag.domains)** - French malicious domains database
- **[StevenBlack](https://github.com/StevenBlack/hosts)** - Complete hosts list
- **[EasyList](https://easylist.to/)** - Ad filters
- **[Hagezi](https://github.com/hagezi/dns-blocklists)** - Malicious DNS lists

### 👨‍💻 **Author**

**[Tontonjo](https://github.com/Tontonjo)** - Creator and main maintainer

---

<div align="center">

**🛡️ CalmWeb - Web protection for everyone 🛡️**

[⭐ **Star the project**](https://github.com/Tontonjo/calmweb) • [🍴 **Fork**](https://github.com/Tontonjo/calmweb/fork) • [📥 **Download**](https://github.com/Tontonjo/calmweb/releases)

Made with ❤️ for digital safety

</div>

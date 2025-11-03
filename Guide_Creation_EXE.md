# 🚀 Guide de création d'un .exe auto-installable CalmWeb

## 📋 Étapes complètes

### 1. **Création de l'exécutable**
```bash
# 1. Installer PyInstaller
pip install pyinstaller pillow

# 2. Créer l'exe
cd program
pyinstaller --onefile --windowed --icon=..\ressources\calmweb.png --name=CalmWeb calmweb.py
```

### 2. **Télécharger NSIS (Nullsoft Scriptable Install System)**
- Site : https://nsis.sourceforge.io/Download
- Installer NSIS sur votre système

### 3. **Compiler l'installateur**
```bash
# Avec NSIS installé
"C:\Program Files (x86)\NSIS\makensis.exe" CalmWeb_Installer.nsi
```

## ✨ Fonctionnalités de l'installateur

### 🔧 **Installation automatique**
- ✅ Copie dans `C:\Program Files\CalmWeb\`
- ✅ Création du répertoire de configuration
- ✅ Raccourcis Bureau et Menu Démarrer
- ✅ Configuration pare-feu automatique

### 🚀 **Auto-démarrage Windows**
```registry
HKLM\Software\Microsoft\Windows\CurrentVersion\Run
"CalmWeb" = "C:\Program Files\CalmWeb\CalmWeb.exe"
```

### 🛡️ **Configuration sécurisée**
- ✅ Pare-feu Windows configuré (port 8080)
- ✅ Proxy système automatique
- ✅ Validation des privilèges administrateur
- ✅ Désinstallation propre

### 🗑️ **Désinstallation complète**
- ✅ Arrêt automatique du processus
- ✅ Suppression auto-démarrage
- ✅ Nettoyage registre et raccourcis
- ✅ Réinitialisation proxy système

## 📦 Structure finale

```
CalmWeb_Installer.exe
├── Installation dans C:\Program Files\CalmWeb\
│   ├── CalmWeb.exe (application principale)
│   ├── calmweb.png (icône)
│   ├── blocklist.txt (domaines bloqués)
│   ├── whitelist.txt (domaines autorisés)
│   └── uninstall.exe (désinstalleur)
├── Configuration dans %APPDATA%\CalmWeb\
│   └── custom.cfg (configuration utilisateur)
└── Raccourcis
    ├── Bureau : CalmWeb.lnk
    └── Menu Démarrer : CalmWeb\
```

## 🎯 Avantages

1. **Installation en 1 clic** - Aucune configuration manuelle
2. **Démarrage automatique** - Protection dès le boot Windows
3. **Pare-feu configuré** - Sécurité réseau automatique
4. **Désinstallation propre** - Suppression complète sans traces
5. **Interface professionnelle** - Assistant d'installation moderne

## 🔒 Sécurité

- **Privilèges administrateur** requis pour installation
- **Signature numérique** recommandée pour distribution
- **Validation antivirus** avant publication
- **Configuration pare-feu** sécurisée

## 📋 Commandes de test

```bash
# Créer l'exe
build_exe.bat

# Tester l'exe
program\dist\CalmWeb.exe

# Créer l'installateur (après avoir installé NSIS)
"C:\Program Files (x86)\NSIS\makensis.exe" CalmWeb_Installer.nsi

# Résultat : CalmWeb_Installer.exe prêt pour distribution
```

L'installateur résultant permettra une **installation professionnelle en 1 clic avec auto-démarrage** ! 🎉
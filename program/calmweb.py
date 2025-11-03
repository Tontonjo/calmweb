#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Tonton Jo - 2025
# Join me on Youtube: https://www.youtube.com/c/tontonjo

calmweb_version = "1.0.0"


import os
import shutil
import sys
import tempfile
import time
import threading
import subprocess
import platform
import socket
import ssl
import urllib3
import tkinter as tk
from collections import deque
from datetime import datetime
from PIL import Image, ImageDraw
from pystray import Icon, MenuItem, Menu
from tkinter.scrolledtext import ScrolledText
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
import urllib.parse
import ipaddress
import traceback
import signal
import re

# Optional Windows-only imports: encapsulées pour éviter crash si non disponibles
try:
    import win32ui
    import win32gui
    import win32con
    WIN32_AVAILABLE = True
except Exception:
    WIN32_AVAILABLE = False

# === Configuration ===
# Configuration des blocklists (sera défini après les fonctions helper)
BLOCKLIST_URLS = []

WHITELIST_URLS = [
    "https://raw.githubusercontent.com/Tontonjo/calmweb/refs/heads/main/filters/whitelist.txt"
]

manual_blocked_domains = {
   # Arnaques support technique francaises
   "microsoft-assistance.fr",
   "windows-support-france.com",
   "depannage-ordinateur-gratuit.com",
   "antivirus-gratuit-telechargement.net",
   "support-technique-microsoft.fr",
   "windows-security-alert.fr",
   "computer-virus-detected.fr",

   # Arnaques financières
   "gagner-argent-facile.fr",
   "lottery-winner-millions.fr",
   "congratulations-you-won.fr",
   "paypal-security-check.fr",
   "secure-bank-verification.fr",

   # Arnaques e-commerce
   "soldes-exceptionnels.fr",
   "promotion-limitee.com",
   "offre-speciale-gratuit.fr"
}

whitelisted_domains = {
    "add.allowed.domain"
}

RELOAD_INTERVAL = 3600
PROXY_BIND_IP = "127.0.0.1"
PROXY_PORT = 8080

INSTALL_DIR = r"C:\Program Files\CalmWeb"
EXE_NAME = "calmweb.exe"
STARTUP_FOLDER = os.getenv('APPDATA', '') + r"\Microsoft\Windows\Start Menu\Programs\Startup"
CUSTOM_CFG_NAME = "custom.cfg"

USER_CFG_DIR = os.path.join(os.getenv('APPDATA') or os.path.expanduser("~"), "CalmWeb")
USER_CFG_PATH = os.path.join(USER_CFG_DIR, CUSTOM_CFG_NAME)
RED_FLAG_CACHE_PATH = os.path.join(USER_CFG_DIR, "red_flag_domains.txt")
RED_FLAG_TIMESTAMP_PATH = os.path.join(USER_CFG_DIR, "red_flag_last_update.txt")

# Global state
block_enabled = True
block_ip_direct = True      # Bloquer accès direct par IP
block_http_traffic = True   # Bloquer le HTTP (non-HTTPS)
block_http_other_ports = True
log_buffer = deque(maxlen=1000)
current_resolver = None
proxy_server = None
proxy_server_thread = None

# Internal flags
_RESOLVER_LOADING = threading.Event()
_SHUTDOWN_EVENT = threading.Event()
_CONFIG_LOCK = threading.RLock()

# === Logging ===
_LOG_LOCK = threading.Lock()

def _safe_str(obj):
    """Safely convert object to string."""
    try:
        return str(obj)
    except Exception:
        return f"<{type(obj).__name__} object>"
def log(msg):
    """
    SÉCURISÉ: Logging avec protection contre injections et sanitization.
    """
    try:
        timestamp = time.strftime("[%H:%M:%S]")
        try:
            # SÉCURITÉ: Conversion sécurisée et sanitization
            safe_msg = _safe_str(msg)

            # SÉCURITÉ: Nettoyer les caractères dangereux pour prévenir log injection
            safe_msg = _sanitize_log_message(safe_msg)

            # SÉCURITÉ: Encoder proprement pour UTF-8
            safe_msg = safe_msg.encode("utf-8", errors="replace").decode("utf-8", errors="replace")

        except Exception:
            safe_msg = "Log message conversion error"

        line = f"{timestamp} {safe_msg}"

        with _LOG_LOCK:
            # SÉCURITÉ: Vérifier la taille du buffer pour éviter DoS mémoire
            if len(log_buffer) >= 1000:
                # Si le buffer est plein, on retire les anciens messages
                try:
                    # Garder seulement les 500 derniers messages pour éviter accumulation
                    while len(log_buffer) > 500:
                        log_buffer.popleft()
                except Exception:
                    # Si problème avec deque, recréer
                    log_buffer.clear()

            # Ajout dans buffer (deque gère automatiquement la taille max)
            log_buffer.append(line)

            # Affichage console protégé
            try:
                print(line, flush=True)
            except Exception:
                # stdout peut être indisponible dans certains environnements
                pass

    except Exception:
        # Dernière ligne de défense: pas d'exception propagée
        try:
            # Tentative de signal minimal en stderr
            sys.stderr.write("Logging internal error\n")
        except Exception:
            pass


# === Extract exe icon (Windows) ===
def get_exe_icon(path, size=(64, 64)):
    """
    Récupère l’icône de l’exécutable et la convertit en PIL.Image.
    Renvoie None si impossible. Compatible non-Windows (retourne None).
    """
    if not WIN32_AVAILABLE:
        return None
    try:
        large, small = win32gui.ExtractIconEx(path, 0)
    except (OSError, AttributeError) as e:
        log(f"get_exe_icon: ExtractIconEx error: {_sanitize_log_message(str(e))}")
        return None
    except Exception as e:
        log(f"get_exe_icon: Unexpected ExtractIconEx error: {_sanitize_log_message(str(e))}")
        return None

    if (not small) and (not large):
        return None

    try:
        hicon = large[0] if large else small[0]
    except (IndexError, TypeError) as e:
        log(f"get_exe_icon: Error accessing icon handle: {_sanitize_log_message(str(e))}")
        return None
    except Exception as e:
        log(f"get_exe_icon: Unexpected icon handle error: {_sanitize_log_message(str(e))}")
        return None

    # créer DC compatible
    try:
        hdc = win32ui.CreateDCFromHandle(win32gui.GetDC(0))
        hdc_mem = hdc.CreateCompatibleDC()
        hbmp = win32ui.CreateBitmap()
        hbmp.CreateCompatibleBitmap(hdc, size[0], size[1])
        hdc_mem.SelectObject(hbmp)
        win32gui.DrawIconEx(hdc_mem.GetSafeHdc(), 0, 0, hicon, size[0], size[1], 0, 0, win32con.DI_NORMAL)
        bmpinfo = hbmp.GetInfo()
        bmpstr = hbmp.GetBitmapBits(True)
        img = Image.frombuffer(
            'RGB',
            (bmpinfo['bmWidth'], bmpinfo['bmHeight']),
            bmpstr, 'raw', 'BGRX', 0, 1
        )
    except (OSError, MemoryError, AttributeError) as e:
        log(f"get_exe_icon: conversion error: {_sanitize_log_message(str(e))}")
        img = None
    except Exception as e:
        log(f"get_exe_icon: unexpected conversion error: {_sanitize_log_message(str(e))}")
        img = None
    finally:
        try:
            win32gui.DestroyIcon(hicon)
        except (OSError, AttributeError) as e:
            log(f"get_exe_icon: DestroyIcon error: {_sanitize_log_message(str(e))}")
        except Exception as e:
            log(f"get_exe_icon: Unexpected DestroyIcon error: {_sanitize_log_message(str(e))}")

        try:
            if 'hdc_mem' in locals():
                hdc_mem.DeleteDC()
            if 'hdc' in locals():
                hdc.DeleteDC()
            win32gui.ReleaseDC(0, 0)
        except (OSError, AttributeError) as e:
            log(f"get_exe_icon: DC cleanup error: {_sanitize_log_message(str(e))}")
        except Exception as e:
            log(f"get_exe_icon: Unexpected DC cleanup error: {_sanitize_log_message(str(e))}")
    return img

# === Security and Validation Functions ===
def _validate_domain_input(domain):
    """
    SÉCURITÉ: Validation stricte des domaines pour prévenir injections.
    Retourne True si le domaine est valide et sûr.
    """
    import re

    if not domain or not isinstance(domain, str):
        return False

    # Nettoyer le domaine
    domain = domain.strip().lower()

    # Vérifications de base
    if len(domain) == 0 or len(domain) > 253:
        return False

    # Vérifier caractères autorisés seulement (alphanumériques, points, tirets)
    if not re.match(r'^[a-zA-Z0-9.-]+$', domain):
        return False

    # Vérifier structure du domaine
    if '..' in domain or domain.startswith('.') or domain.endswith('.'):
        return False

    # Vérifier chaque label du domaine
    labels = domain.split('.')
    for label in labels:
        if not label:  # label vide
            return False
        if len(label) > 63:  # RFC limit
            return False
        if label.startswith('-') or label.endswith('-'):  # tirets en début/fin interdits
            return False

    return True

def _validate_hostname_input(hostname):
    """
    SÉCURITÉ: Validation stricte des hostnames, IPs et domaines.
    """
    if not hostname or not isinstance(hostname, str):
        return False

    hostname = hostname.strip().lower()

    # Vérifier si c'est une IP valide
    try:
        import ipaddress
        ipaddress.ip_address(hostname)
        return True  # IP valide
    except ValueError:
        pass  # Pas une IP, continuer avec validation domaine

    # Valider comme domaine
    return _validate_domain_input(hostname)

def _sanitize_log_message(message):
    """
    SÉCURITÉ: Nettoie les messages de log pour prévenir injection de logs.
    """
    if not isinstance(message, str):
        message = str(message)

    # Remplacer caractères de contrôle et newlines
    sanitized = re.sub(r'[\x00-\x1f\x7f-\x9f]', '', message)
    sanitized = sanitized.replace('\n', ' ').replace('\r', ' ')

    # Limiter la longueur pour éviter spam
    if len(sanitized) > 200:
        sanitized = sanitized[:197] + "..."

    return sanitized

def _validate_file_path(path, allowed_dirs):
    """
    SÉCURITÉ: Validation des chemins de fichiers pour prévenir directory traversal.
    """
    try:
        # Normaliser le chemin
        normalized = os.path.normpath(os.path.abspath(path))

        # Vérifier qu'il n'y a pas de traversal
        if '..' in path or not any(normalized.startswith(os.path.normpath(d)) for d in allowed_dirs):
            return False

        return True
    except Exception:
        return False

# === Exceptions personnalisées ===
class CalmWebError(Exception):
    """Exception de base pour CalmWeb."""
    pass

class NetworkError(CalmWebError):
    """Erreur réseau."""
    pass

class ConfigurationError(CalmWebError):
    """Erreur de configuration."""
    pass

class SecurityError(CalmWebError):
    """Erreur de sécurité."""
    pass

class ValidationError(CalmWebError):
    """Erreur de validation des entrées."""
    pass

# === Custom config handling ===
def get_custom_cfg_path(install_dir=None):
    """
    SÉCURISÉ: Retourne le chemin du custom.cfg avec validation.
    Priorise APPDATA, sinon install_dir, sinon dossier courant.
    """
    try:
        # SÉCURITÉ: Vérifier que USER_CFG_DIR est défini et valide
        if USER_CFG_DIR and isinstance(USER_CFG_DIR, str):
            # SÉCURITÉ: Normaliser le chemin pour éviter directory traversal
            normalized_dir = os.path.normpath(USER_CFG_DIR)
            if not '..' in normalized_dir:
                return USER_CFG_PATH
    except Exception as e:
        log(f"get_custom_cfg_path: USER_CFG_DIR error: {_sanitize_log_message(str(e))}")

    # SÉCURITÉ: Valider install_dir si fourni
    if install_dir and isinstance(install_dir, str):
        try:
            normalized_install = os.path.normpath(install_dir)
            if not '..' in normalized_install and os.path.isdir(normalized_install):
                return os.path.join(normalized_install, CUSTOM_CFG_NAME)
        except Exception as e:
            log(f"get_custom_cfg_path: install_dir error: {_sanitize_log_message(str(e))}")

    # SÉCURITÉ: Fallback vers dossier courant avec validation
    try:
        current_dir = os.path.dirname(os.path.abspath(sys.argv[0]))
        normalized_current = os.path.normpath(current_dir)
        return os.path.join(normalized_current, CUSTOM_CFG_NAME)
    except Exception as e:
        log(f"get_custom_cfg_path: fallback error: {_sanitize_log_message(str(e))}")
        # Dernier recours - dossier courant
        return CUSTOM_CFG_NAME

def write_default_custom_cfg(path, blocked_set, whitelist_set):
    """
    SÉCURISÉ: Écrit un fichier custom.cfg par défaut avec validation.
    Inclut les options block_ip_direct, block_http_traffic et block_http_other_ports.
    """
    try:
        # SÉCURITÉ: Validation du chemin
        if not path or not isinstance(path, str):
            raise ValidationError("Chemin de fichier config invalide")

        # SÉCURITÉ: Normaliser le chemin et vérifier directory traversal
        normalized_path = os.path.normpath(path)
        if '..' in path:
            raise SecurityError(f"Directory traversal détecté dans chemin config: {path}")

        # SÉCURITÉ: Validation des sets d'entrée
        if not isinstance(blocked_set, (set, list, tuple)):
            blocked_set = set()
        if not isinstance(whitelist_set, (set, list, tuple)):
            whitelist_set = set()

        # Créer le répertoire parent avec permissions sécurisées
        parent_dir = os.path.dirname(normalized_path)
        if parent_dir:
            os.makedirs(parent_dir, mode=0o755, exist_ok=True)

        # SÉCURITÉ: Écriture atomique via fichier temporaire
        temp_path = normalized_path + '.tmp'

        with open(temp_path, 'w', encoding='utf-8') as f:
            # --- Section BLOCK ---
            f.write("[BLOCK]\n")
            for d in sorted(blocked_set):
                # SÉCURITÉ: Valider chaque domaine avant écriture
                if isinstance(d, str) and _validate_domain_input(d):
                    f.write(f"{d}\n")

            # --- Section WHITELIST ---
            f.write("\n[WHITELIST]\n")
            for d in sorted(whitelist_set):
                # SÉCURITÉ: Valider chaque domaine avant écriture
                if isinstance(d, str) and _validate_domain_input(d):
                    f.write(f"{d}\n")

            # --- Section OPTIONS ---
            f.write("\n[OPTIONS]\n")
            f.write("block_ip_direct = 1\n")
            f.write("block_http_traffic = 1\n")
            f.write("block_http_other_ports = 1\n")

        # SÉCURITÉ: Déplacement atomique du fichier temporaire
        if os.path.exists(temp_path):
            if os.path.exists(normalized_path):
                os.remove(normalized_path)
            os.rename(temp_path, normalized_path)

        log(f"Fichier de configuration créé avec succès")

    except (ValidationError, SecurityError):
        raise
    except OSError as e:
        raise ConfigurationError(f"Erreur système écriture config: {_sanitize_log_message(str(e))}")
    except Exception as e:
        raise ConfigurationError(f"Erreur écriture custom.cfg: {_sanitize_log_message(str(e))}")
    finally:
        # Nettoyer le fichier temporaire si il existe encore
        try:
            if 'temp_path' in locals() and os.path.exists(temp_path):
                os.remove(temp_path)
        except Exception:
            pass


def parse_custom_cfg(path):
    """
    Parse un custom.cfg simple. Renvoie (blocked_set, whitelist_set).
    SÉCURISÉ contre les injections et validé.
    """

    blocked = set()
    whitelist = set()
    global block_ip_direct, block_http_traffic, block_http_other_ports

    # valeurs par défaut
    block_ip_direct = True
    block_http_traffic = True
    block_http_other_ports = True

    # SÉCURITÉ: Validation du chemin du fichier
    try:
        # Normaliser le chemin et vérifier qu'il n'y a pas de directory traversal
        normalized_path = os.path.normpath(path)
        if '..' in normalized_path or not normalized_path.startswith((
            os.path.normpath(USER_CFG_DIR),
            os.path.normpath(INSTALL_DIR),
            os.path.normpath(os.path.dirname(os.path.abspath(sys.argv[0])))
        )):
            log(f"SÉCURITÉ: Chemin de configuration suspect rejeté: {path}")
            return blocked, whitelist
    except Exception as e:
        log(f"SÉCURITÉ: Erreur validation chemin config: {e}")
        return blocked, whitelist

    if not os.path.exists(path):
        log(f"custom.cfg introuvable à {path}")
        return blocked, whitelist

    # SÉCURITÉ: Vérifier taille du fichier (max 10MB)
    try:
        file_size = os.path.getsize(path)
        if file_size > 10 * 1024 * 1024:  # 10MB max
            log(f"SÉCURITÉ: Fichier config trop volumineux ({file_size} bytes), rejeté")
            return blocked, whitelist
    except Exception as e:
        log(f"SÉCURITÉ: Erreur vérification taille fichier: {e}")
        return blocked, whitelist

    # Regex pour validation des clés d'options - SÉCURISÉ
    OPTION_KEY_PATTERN = re.compile(r'^[a-zA-Z_][a-zA-Z0-9_]*$')

    section = None
    line_count = 0
    try:
        with open(path, 'r', encoding='utf-8', errors='ignore') as f:
            for raw in f:
                line_count += 1
                # SÉCURITÉ: Limiter nombre de lignes (max 50000)
                if line_count > 50000:
                    log(f"SÉCURITÉ: Fichier config trop de lignes (>{line_count}), arrêt du parsing")
                    break

                try:
                    # SÉCURITÉ: Limiter longueur de ligne (max 500 chars)
                    if len(raw) > 500:
                        log(f"SÉCURITÉ: Ligne {line_count} trop longue, ignorée")
                        continue

                    line = raw.strip()
                    if not line or line.startswith('#'):
                        continue

                    # SÉCURITÉ: Validation caractères - pas de caractères de contrôle
                    if any(ord(c) < 32 and c not in '\t\n\r' for c in line):
                        log(f"SÉCURITÉ: Ligne {line_count} contient caractères de contrôle, ignorée")
                        continue

                    up = line.upper()
                    if up == "[BLOCK]":
                        section = "BLOCK"
                        continue
                    elif up == "[WHITELIST]":
                        section = "WHITELIST"
                        continue
                    elif up == "[OPTIONS]":
                        section = "OPTIONS"
                        continue

                    if section == "BLOCK":
                        # SÉCURITÉ: Validation stricte des domaines
                        domain = line.lower().lstrip('.')
                        if _validate_domain_input(domain):
                            blocked.add(domain)
                        else:
                            log(f"SÉCURITÉ: Domaine bloqué invalide ligne {line_count}: {domain}")

                    elif section == "WHITELIST":
                        # SÉCURITÉ: Validation stricte des domaines
                        domain = line.lower().lstrip('.')
                        if _validate_domain_input(domain):
                            whitelist.add(domain)
                        else:
                            log(f"SÉCURITÉ: Domaine whitelist invalide ligne {line_count}: {domain}")

                    elif section == "OPTIONS":
                        try:
                            if '=' not in line:
                                continue
                            key, val = line.split('=', 1)
                            key = key.strip().lower()
                            val = val.strip().lower()

                            # SÉCURITÉ: Validation de la clé d'option
                            if not OPTION_KEY_PATTERN.match(key):
                                log(f"SÉCURITÉ: Clé option invalide ligne {line_count}: {key}")
                                continue

                            # SÉCURITÉ: Validation de la valeur (seulement boolean)
                            if val not in ("1", "0", "true", "false", "yes", "no", "on", "off"):
                                log(f"SÉCURITÉ: Valeur option invalide ligne {line_count}: {val}")
                                continue

                            enabled = val in ("1", "true", "yes", "on")

                            # SÉCURITÉ: Uniquement les options connues
                            if key == "block_ip_direct":
                                block_ip_direct = enabled
                            elif key == "block_http_traffic":
                                block_http_traffic = enabled
                            elif key == "block_http_other_ports":
                                block_http_other_ports = enabled
                            else:
                                log(f"SÉCURITÉ: Option inconnue ignorée ligne {line_count}: {key}")

                        except ValueError as e:
                            log(f"SÉCURITÉ: Erreur parsing option ligne {line_count}: {e}")
                            continue
                    else:
                        # Section inconnue - traiter comme BLOCK avec validation
                        domain = line.lower().lstrip('.')
                        if _validate_domain_input(domain):
                            blocked.add(domain)
                        else:
                            log(f"SÉCURITÉ: Domaine par défaut invalide ligne {line_count}: {domain}")

                except Exception as e:
                    log(f"SÉCURITÉ: Erreur parsing ligne {line_count}: {e}")
                    continue

        # Logging sécurisé (pas de données utilisateur dans les logs)
        log(f"custom.cfg chargé : {len(blocked)} bloqués, {len(whitelist)} whitelist")

    except Exception as e:
        log(f"SÉCURITÉ: Erreur lecture custom.cfg {_sanitize_log_message(str(e))}")

    return blocked, whitelist

def ensure_custom_cfg_exists(install_dir, default_blocked, default_whitelist):
    """
    Assure l'existence d'un custom.cfg dans APPDATA prioritairement, sinon dans le dossier d'installation.
    Renvoie le chemin utilisé.
    """
    try:
        if not os.path.isdir(USER_CFG_DIR):
            log(f"Création du répertoire de configuration : {USER_CFG_DIR}")
            os.makedirs(USER_CFG_DIR, exist_ok=True)
        if not os.path.exists(USER_CFG_PATH):
            log(f"Création du fichier de configuration : {USER_CFG_PATH}")
            write_default_custom_cfg(USER_CFG_PATH, default_blocked, default_whitelist)
        return USER_CFG_PATH
    except Exception as e:
        log(f"Erreur ensure_custom_cfg_exists (APPDATA): {e}")
    cfg_path = get_custom_cfg_path(install_dir)
    if not os.path.exists(cfg_path):
        try:
            write_default_custom_cfg(cfg_path, default_blocked, default_whitelist)
        except Exception as e:
            log(f"Erreur écriture fallback custom.cfg {cfg_path}: {e}")
    return cfg_path

def load_custom_cfg_to_globals(path):
    """
    Charge config utilisateur vers variables globales.
    """
    global manual_blocked_domains, whitelisted_domains
    blocked, whitelist = parse_custom_cfg(path)
    with _CONFIG_LOCK:
        if blocked:
            manual_blocked_domains = blocked
        if whitelist:
            whitelisted_domains = whitelist
    return manual_blocked_domains, whitelisted_domains

# === Red Flag Domains Auto-Update ===
def should_update_red_flag_domains():
    """Vérifie si red.flag.domains doit être mis à jour (quotidien)"""
    try:
        if not os.path.exists(RED_FLAG_TIMESTAMP_PATH):
            return True

        with open(RED_FLAG_TIMESTAMP_PATH, 'r') as f:
            last_update_str = f.read().strip()

        last_update = datetime.fromisoformat(last_update_str)
        now = datetime.now()

        # Mise à jour si plus de 24h ou nouveau jour
        return (now - last_update).total_seconds() > 86400 or now.date() > last_update.date()

    except Exception as e:
        log(f"Erreur vérification timestamp red.flag.domains: {e}")
        return True

def download_red_flag_domains():
    """Télécharge et cache red.flag.domains localement"""
    try:
        log("📥 Téléchargement red.flag.domains...")

        # Créer le répertoire si nécessaire
        os.makedirs(USER_CFG_DIR, exist_ok=True)

        # Télécharger avec urllib3
        http = urllib3.PoolManager()
        response = http.request(
            "GET",
            "https://dl.red.flag.domains/pihole/red.flag.domains.txt",
            timeout=urllib3.Timeout(connect=10.0, read=30.0)
        )

        if response.status == 200:
            # Sauvegarder le fichier
            with open(RED_FLAG_CACHE_PATH, 'wb') as f:
                f.write(response.data)

            # Marquer la date de mise à jour
            with open(RED_FLAG_TIMESTAMP_PATH, 'w') as f:
                f.write(datetime.now().isoformat())

            log(f"✅ red.flag.domains mis à jour ({len(response.data)} bytes)")
            return True
        else:
            log(f"❌ Échec téléchargement red.flag.domains: HTTP {response.status}")
            return False

    except Exception as e:
        log(f"❌ Erreur téléchargement red.flag.domains: {e}")
        return False

def get_red_flag_domains_path():
    """Retourne le chemin vers le fichier red.flag.domains (cache local ou URL)"""
    if should_update_red_flag_domains():
        download_red_flag_domains()

    # Utiliser le cache local s'il existe
    if os.path.exists(RED_FLAG_CACHE_PATH):
        return f"file://{RED_FLAG_CACHE_PATH}"

    # Fallback vers l'URL directe
    return "https://dl.red.flag.domains/pihole/red.flag.domains.txt"

def get_blocklist_urls():
    """Retourne la liste des URLs de blocklist avec red.flag.domains mis à jour automatiquement"""
    return [
        "https://raw.githubusercontent.com/StevenBlack/hosts/refs/heads/master/hosts",
        "https://raw.githubusercontent.com/easylist/listefr/refs/heads/master/hosts.txt",
        "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/domains/ultimate.txt",
        "https://raw.githubusercontent.com/Tontonjo/calmweb/refs/heads/main/filters/blocklist.txt",
        # Red Flag Domains - avec mise à jour automatique quotidienne
        get_red_flag_domains_path()
    ]

# Initialisation des URLs de blocklist
BLOCKLIST_URLS = get_blocklist_urls()

# === Firewall / Proxy ===
def add_firewall_rule(target_file):
    """
    SÉCURISÉ: Tente d'ajouter une règle de pare-feu via netsh avec validation.
    """
    try:
        if platform.system().lower() != 'windows':
            log("add_firewall_rule: non-Windows, skip.")
            return

        # SÉCURITÉ: Validation du chemin du fichier
        if not target_file or not isinstance(target_file, str):
            raise SecurityError("Chemin de fichier invalide pour règle firewall")

        # Normaliser et valider le chemin
        normalized_path = os.path.normpath(os.path.abspath(target_file))

        # Vérifier que le fichier existe
        if not os.path.exists(normalized_path):
            raise SecurityError(f"Fichier target inexistant: {normalized_path}")

        # Vérifier que c'est dans un répertoire autorisé
        allowed_dirs = [
            os.path.normpath(INSTALL_DIR),
            os.path.normpath(os.path.dirname(os.path.abspath(sys.argv[0])))
        ]

        if not any(normalized_path.startswith(d) for d in allowed_dirs):
            raise SecurityError(f"Chemin non autorisé pour règle firewall: {normalized_path}")

        # SÉCURITÉ: Construction sécurisée de la commande
        cmd = [
            "netsh", "advfirewall", "firewall", "add", "rule",
            "name=CalmWeb", "dir=in", "action=allow",
            f"program={normalized_path}", "profile=any"
        ]

        # SÉCURITÉ: Exécution avec timeout et flags sécurisés
        subprocess.run(
            cmd,
            check=True,
            timeout=30,  # Timeout de 30 secondes
            creationflags=subprocess.CREATE_NO_WINDOW,
            capture_output=True,
            text=True
        )

        log("Règles du pare-feu ajoutées avec succès.")

    except subprocess.TimeoutExpired:
        raise NetworkError("Timeout lors de l'ajout de la règle firewall")
    except subprocess.CalledProcessError as e:
        raise NetworkError(f"Erreur netsh firewall (code {e.returncode}): {_sanitize_log_message(str(e))}")
    except (SecurityError, NetworkError):
        raise  # Re-lever les erreurs de sécurité/réseau
    except Exception as e:
        raise NetworkError(f"Erreur firewall: {_sanitize_log_message(str(e))}")


# === Blocklist Resolver ===
class BlocklistResolver:
    def __init__(self, blocklist_urls, reload_interval=3600):
        self.blocklist_urls = list(blocklist_urls)
        self.reload_interval = max(60, int(reload_interval or 3600))
        self.blocked_domains = set()
        self.last_reload = 0
        self._lock = threading.Lock()
        self._loading_lock = threading.Lock()

        # Structures dédiées pour la whitelist:
        # - whitelisted_domains: noms de domaines / hôtes (string)
        # - whitelisted_networks: objets ip_network pour CIDR
        # Les deux sont protégées par self._lock
        self.whitelisted_domains_local = set()   # non-global copy; on fusionnera avec global si nécessaire
        self.whitelisted_networks = set()       # set(ipaddress.ip_network(...))

        # Chargement initial (tolérant)
        try:
            self._load_blocklist()
            self._load_whitelist()
        except Exception as e:
            log(f"BlocklistResolver init error: {e}")

    def _load_blocklist(self):
        """
        Télécharge et parse les blocklists. Robustesse: retries, timeouts, découpage.
        Définit self.blocked_domains atomiquement.
        """
        if self._loading_lock.locked():
            log("Blocklist load déjà en cours, skip.")
            return
        with self._loading_lock:
            _RESOLVER_LOADING.set()
            try:
                domains = set()
                http = urllib3.PoolManager(cert_reqs='CERT_REQUIRED', ssl_context=ssl.create_default_context())
                for url in self.blocklist_urls:
                    success = False
                    for attempt in range(3):
                        try:
                            log(f"⬇️ Chargement blocklist {url} (tentative {attempt+1})")

                            # Support des fichiers locaux (file://) avec validation
                            if url.startswith("file://"):
                                file_path = url[7:]  # Enlever "file://"

                                # SÉCURITÉ: Validation du chemin de fichier local
                                if not _validate_file_path(file_path, [USER_CFG_DIR]):
                                    raise SecurityError(f"Chemin de fichier non autorisé: {file_path}")

                                # SÉCURITÉ: Vérifier la taille du fichier avant lecture
                                try:
                                    file_size = os.path.getsize(file_path)
                                    if file_size > 50 * 1024 * 1024:  # 50MB max
                                        raise SecurityError(f"Fichier blocklist trop volumineux: {file_size} bytes")
                                except OSError:
                                    raise NetworkError(f"Impossible d'accéder au fichier: {file_path}")

                                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                                    content = f.read()
                            else:
                                # SÉCURITÉ: Validation de l'URL
                                if not url.startswith(('https://', 'http://')):
                                    raise SecurityError(f"URL non autorisée: {url}")

                                # Téléchargement HTTP/HTTPS classique avec timeouts stricts
                                response = http.request(
                                    "GET",
                                    url,
                                    timeout=urllib3.Timeout(connect=10.0, read=30.0),
                                    retries=urllib3.Retry(total=2, backoff_factor=1)
                                )
                                if response.status != 200:
                                    raise NetworkError(f"HTTP {response.status}")

                                # SÉCURITÉ: Vérifier la taille de la réponse
                                content_length = response.headers.get('Content-Length')
                                if content_length and int(content_length) > 50 * 1024 * 1024:  # 50MB max
                                    raise SecurityError(f"Réponse trop volumineuse: {content_length} bytes")

                                content = response.data.decode("utf-8", errors='ignore')
                            # SÉCURITÉ: Limiter le nombre de lignes traitées
                            lines_processed = 0
                            max_lines = 1000000  # 1M lignes max par fichier

                            for line in content.splitlines():
                                lines_processed += 1
                                if lines_processed > max_lines:
                                    log(f"SÉCURITÉ: Limite de lignes atteinte pour {url}: {max_lines}")
                                    break

                                try:
                                    # SÉCURITÉ: Limiter la longueur de ligne
                                    if len(line) > 500:
                                        continue

                                    line = line.split('#', 1)[0].strip()
                                    if not line:
                                        continue

                                    # SÉCURITÉ: Validation des caractères de la ligne
                                    if any(ord(c) < 32 and c not in '\t\n\r' for c in line):
                                        continue

                                    parts = line.split()
                                    domain = None

                                    if len(parts) == 1:
                                        domain = parts[0]
                                    elif len(parts) >= 2:
                                        if not self._looks_like_ip(parts[0]):
                                            domain = parts[0]
                                        else:
                                            domain = parts[1]

                                    if not domain:
                                        continue

                                    domain = domain.lower().lstrip('.')

                                    # SÉCURITÉ: Validation stricte du domaine
                                    if not _validate_domain_input(domain):
                                        continue

                                    # SÉCURITÉ: Exclure les domaines d'IP
                                    if self._looks_like_ip(domain):
                                        continue

                                    # SÉCURITÉ: Vérifier longueur RFC
                                    if len(domain) > 253:
                                        continue

                                    domains.add(domain)

                                except (UnicodeDecodeError, ValueError) as e:
                                    log(f"SÉCURITÉ: Ligne invalide ignorée: {_sanitize_log_message(str(e))}")
                                    continue
                                except Exception as e:
                                    log(f"SÉCURITÉ: Erreur parsing ligne: {_sanitize_log_message(str(e))}")
                                    continue
                            success = True
                            break
                        except (SecurityError, NetworkError) as e:
                            log(f"SÉCURITÉ: Blocklist {url} tentative {attempt+1}: {e}")
                            time.sleep(1 + attempt * 2)
                        except (urllib3.exceptions.HTTPError, urllib3.exceptions.TimeoutError, OSError) as e:
                            log(f"RÉSEAU: Blocklist {url} tentative {attempt+1}: {_sanitize_log_message(str(e))}")
                            time.sleep(1 + attempt * 2)
                        except Exception as e:
                            log(f"ERREUR: Blocklist {url} tentative {attempt+1}: {_sanitize_log_message(str(e))}")
                            time.sleep(1 + attempt * 2)
                    if not success:
                        log(f"[⚠️] Échec téléchargement blocklist depuis {url}")
                with self._lock:
                    self.blocked_domains = domains
                    self.last_reload = time.time()
                log(f"✅ {len(domains)} domaines bloqués chargés.")
            except Exception as e:
                log(f"Erreur _load_blocklist: {e}\n{traceback.format_exc()}")
            finally:
                _RESOLVER_LOADING.clear()

    def _load_whitelist(self):
        """
        Télécharge & parse les whitelists et met à jour self.whitelisted_domains_local et self.whitelisted_networks.
        - supporte: exact domains, *.example.com (on stocke "example.com"), CIDR (1.2.3.0/24), IPs.
        - mise à jour atomique des structures protégées par self._lock.
        """
        try:
            http = urllib3.PoolManager(cert_reqs='CERT_REQUIRED', ssl_context=ssl.create_default_context())
            new_domains = set()
            new_networks = set()

            # Si un ensemble global whitelisted_domains existe (global), on le prend en base
            try:
                # copie des domaines globaux si définis
                if 'whitelisted_domains' in globals():
                    for d in whitelisted_domains:
                        if isinstance(d, str) and d:
                            new_domains.add(d.lower().lstrip('.'))
            except Exception:
                pass

            for url in WHITELIST_URLS:
                for attempt in range(3):
                    try:
                        log(f"⬇️ Téléchargement whitelist {url} (tentative {attempt+1})")
                        response = http.request("GET", url, timeout=urllib3.Timeout(connect=5.0, read=10.0))
                        if response.status != 200:
                            raise Exception(f"HTTP {response.status}")
                        content = response.data.decode("utf-8", errors='ignore')
                        for line in content.splitlines():
                            try:
                                line = line.split('#', 1)[0].strip()
                                if not line:
                                    continue
                                entry = line.lower().strip()
                                # wildcard *.example.com -> store example.com
                                if entry.startswith("*."):
                                    domain = entry[2:].lstrip('.')
                                    if domain and not self._looks_like_ip(domain):
                                        new_domains.add(domain)
                                    continue
                                # CIDR or IP network
                                if '/' in entry:
                                    try:
                                        net = ipaddress.ip_network(entry, strict=False)
                                        new_networks.add(net)
                                        continue
                                    except Exception:
                                        # maybe malformed, skip
                                        continue
                                # plain IP
                                if self._looks_like_ip(entry):
                                    new_domains.add(entry)
                                    continue
                                # plain domain
                                entry = entry.lstrip('.')
                                if entry and not self._looks_like_ip(entry) and len(entry) <= 253:
                                    new_domains.add(entry)
                            except Exception:
                                continue
                        break
                    except Exception as e:
                        log(f"[⚠️] Loading whitelist failed {url} attempt {attempt+1}: {e}")
                        time.sleep(1 + attempt * 2)

            # mise à jour atomique
            with self._lock:
                self.whitelisted_domains_local = new_domains
                self.whitelisted_networks = new_networks

                # si tu veux refléter dans un global 'whitelisted_domains', fais-le ici de façon atomique :
                try:
                    if 'whitelisted_domains' in globals():
                        whitelisted_domains.clear()
                        whitelisted_domains.update(new_domains)
                except Exception:
                    pass

            log(f"✅ {len(self.whitelisted_domains_local)} domaines whitelistés chargés, {len(self.whitelisted_networks)} réseaux CIDR.")
        except Exception as e:
            log(f"[Erreur] _load_whitelist: {e}\n{traceback.format_exc()}")

    def _looks_like_ip(self, s):
        try:
            ipaddress.ip_address(s)
            return True
        except Exception:
            return False

    def is_whitelisted(self, hostname):
        """
        Vérifie si hostname est explicitement whitelisté (domain, parent domain, wildcard),
        ou appartient à un réseau CIDR whitelisté.
        - hostname peut être un IP (string) ou un fqdn.
        - gère sous-domaines : si 'example.com' est dans whitelist, 'sub.a.example.com' est autorisé.
        """
        try:
            if not hostname:
                return False
            host = hostname.strip().lower().rstrip('.')
            if not host:
                return False

            # IP direct -> check networks and exact IP whitelist
            try:
                if self._looks_like_ip(host):
                    ip_obj = ipaddress.ip_address(host)
                    with self._lock:
                        # exact IP in domain whitelist?
                        if host in self.whitelisted_domains_local:
                            return True
                        # any network contains?
                        for net in self.whitelisted_networks:
                            if ip_obj in net:
                                return True
                    return False
            except Exception:
                pass

            parts = host.split('.')
            with self._lock:
                # Check candidate suffixes: host, parent, ... top-level domain excluded if empty
                for i in range(len(parts)):
                    candidate = '.'.join(parts[i:])
                    if candidate in self.whitelisted_domains_local:
                        return True

            return False
        except Exception as e:
            log(f"is_whitelisted error for {hostname}: {e}")
            return False

    def _is_blocked(self, hostname):
        """
        Retourne True si hostname doit être bloqué.
        Priorité: whitelist -> always allow.
        Ensuite: IP direct: utilise block_ip_direct flag.
        Ensuite: check blocked_domains et manual_blocked_domains (parents inclus).
        """
        try:
            if not hostname:
                return False

            host = hostname.strip().lower().rstrip('.')
            if not host:
                return False

            # 1) Whitelist has absolute priority
            try:
                if self.is_whitelisted(host):
                    log(f"✅ [WHITELIST ALLOW] {_safe_str(hostname)} matched whitelist")
                    return False
            except Exception as e:
                log(f"_is_blocked: whitelist check failed for {hostname}: {e}")
                # en cas d'erreur, on ne bloque pas
                return False

            # 2) IP direct handling
            try:
                if self._looks_like_ip(host):
                    # If IP explicitly in global whitelisted_domains (string), allow
                    if 'whitelisted_domains' in globals() and host in whitelisted_domains:
                        log(f"✅ [WHITELIST ALLOW IP] {hostname}")
                        return False
                    # otherwise rely on flag block_ip_direct
                    return bool(block_ip_direct)
            except Exception:
                # si pb lors de detection IP, poursuivre comme hostname
                pass

            parts = host.split('.')
            # 3) Blocklist check (with parents)
            try:
                with self._lock:
                    # check exact host (host) and global manual blocked
                    if host in self.blocked_domains or host in manual_blocked_domains:
                        return True
                    # check parents
                    for i in range(1, len(parts)):
                        parent = '.'.join(parts[i:])
                        if parent in self.blocked_domains or parent in manual_blocked_domains:
                            return True
            except Exception as e:
                log(f"_is_blocked blocklist check error for {hostname}: {e}")
                return False

            return False
        except Exception as e:
            log(f"_is_blocked error for {hostname}: {e}")
            return False

    def maybe_reload_background(self):
        """
        Recharge blocklist et whitelist en background si nécessaire.
        """
        try:
            if time.time() - self.last_reload > self.reload_interval:
                if self._loading_lock.locked():
                    return
                t1 = threading.Thread(target=self._load_blocklist, daemon=True)
                t2 = threading.Thread(target=self._load_whitelist, daemon=True)
                t1.start()
                t2.start()
        except Exception as e:
            log(f"maybe_reload_background error: {e}")


# === System proxy ===
def set_system_proxy(enable=True, host=PROXY_BIND_IP, port=PROXY_PORT):
    """
    SÉCURISÉ: Met en place ou retire le proxy système avec validation.
    """
    try:
        if platform.system().lower() != 'windows':
            log("set_system_proxy: non-Windows, skip.")
            return

        # SÉCURITÉ: Validation des paramètres d'entrée
        if not isinstance(enable, bool):
            raise ValidationError("Paramètre enable doit être boolean")

        if enable:
            # SÉCURITÉ: Validation de l'host et du port
            if not host or not isinstance(host, str):
                raise ValidationError("Host proxy invalide")

            if not isinstance(port, int) or port < 1 or port > 65535:
                raise ValidationError(f"Port proxy invalide: {port}")

            # SÉCURITÉ: Validation de l'adresse IP
            try:
                import ipaddress
                ipaddress.ip_address(host)
            except ValueError:
                raise ValidationError(f"Adresse IP host invalide: {host}")

            # SÉCURITÉ: S'assurer que c'est localhost uniquement
            if host not in ['127.0.0.1', '::1']:
                raise SecurityError(f"Seuls les proxies localhost sont autorisés: {host}")

            proxy_str = f"{host}:{port}"

            # Tentative netsh avec timeout et validation
            try:
                cmd = ["netsh", "winhttp", "set", "proxy", proxy_str]
                result = subprocess.run(
                    cmd,
                    check=False,
                    timeout=15,
                    creationflags=subprocess.CREATE_NO_WINDOW,
                    capture_output=True,
                    text=True
                )
                if result.returncode != 0:
                    log(f"WARN: netsh set proxy failed (code {result.returncode})")
            except subprocess.TimeoutExpired:
                log("WARN: netsh set proxy timeout")
            except Exception as e:
                log(f"WARN: netsh set proxy error: {_sanitize_log_message(str(e))}")

            # Variables d'environnement avec timeout
            try:
                env_value = f"http://{proxy_str}"
                subprocess.run(
                    ["setx", "HTTP_PROXY", env_value],
                    check=False,
                    timeout=10,
                    creationflags=subprocess.CREATE_NO_WINDOW,
                    capture_output=True
                )
                subprocess.run(
                    ["setx", "HTTPS_PROXY", env_value],
                    check=False,
                    timeout=10,
                    creationflags=subprocess.CREATE_NO_WINDOW,
                    capture_output=True
                )
            except subprocess.TimeoutExpired:
                log("WARN: setx timeout pour variables proxy")
            except Exception as e:
                log(f"WARN: setx error: {_sanitize_log_message(str(e))}")

            # Registry Windows avec validation
            try:
                import winreg
                key = winreg.OpenKey(
                    winreg.HKEY_CURRENT_USER,
                    r"Software\Microsoft\Windows\CurrentVersion\Internet Settings",
                    0,
                    winreg.KEY_SET_VALUE
                )
                winreg.SetValueEx(key, "ProxyEnable", 0, winreg.REG_DWORD, 1)
                winreg.SetValueEx(key, "ProxyServer", 0, winreg.REG_SZ, proxy_str)
                winreg.CloseKey(key)
            except Exception as e:
                log(f"WARN: Registry set proxy error: {_sanitize_log_message(str(e))}")

            log(f"Proxy système configuré sur {proxy_str}")

        else:
            # Désactivation du proxy - Nettoyage sécurisé
            try:
                cmd = ["netsh", "winhttp", "reset", "proxy"]
                subprocess.run(
                    cmd,
                    check=False,
                    timeout=15,
                    creationflags=subprocess.CREATE_NO_WINDOW,
                    capture_output=True
                )
            except subprocess.TimeoutExpired:
                log("WARN: netsh reset proxy timeout")
            except Exception as e:
                log(f"WARN: netsh reset proxy error: {_sanitize_log_message(str(e))}")

            # Nettoyer variables d'environnement
            try:
                subprocess.run(
                    ["setx", "HTTP_PROXY", ""],
                    check=False,
                    timeout=10,
                    creationflags=subprocess.CREATE_NO_WINDOW,
                    capture_output=True
                )
                subprocess.run(
                    ["setx", "HTTPS_PROXY", ""],
                    check=False,
                    timeout=10,
                    creationflags=subprocess.CREATE_NO_WINDOW,
                    capture_output=True
                )
            except subprocess.TimeoutExpired:
                log("WARN: setx clear timeout")
            except Exception as e:
                log(f"WARN: setx clear error: {_sanitize_log_message(str(e))}")

            # Nettoyer registry
            try:
                import winreg
                key = winreg.OpenKey(
                    winreg.HKEY_CURRENT_USER,
                    r"Software\Microsoft\Windows\CurrentVersion\Internet Settings",
                    0,
                    winreg.KEY_SET_VALUE
                )
                winreg.SetValueEx(key, "ProxyEnable", 0, winreg.REG_DWORD, 0)
                winreg.SetValueEx(key, "ProxyServer", 0, winreg.REG_SZ, "")
                winreg.CloseKey(key)
            except Exception as e:
                log(f"WARN: Registry clear proxy error: {_sanitize_log_message(str(e))}")

            log("Proxy système réinitialisé.")

    except (ValidationError, SecurityError):
        raise  # Re-lever les erreurs de validation/sécurité
    except Exception as e:
        raise NetworkError(f"Erreur set_system_proxy: {_sanitize_log_message(str(e))}")

# === Helper relay (high-performance pass-through) ===
def _set_socket_opts_for_perf(sock):
    try:
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
        # Windows-specific keepalive tuning (optional)
        if platform.system().lower() == 'windows':
            # tuple: (on/off, keepalive_time_ms, keepalive_interval_ms)
            sock.ioctl(socket.SIO_KEEPALIVE_VALS, (1, 60000, 10000))
    except Exception:
        pass

def _relay_worker(src, dst, buffer_size=65536):
    """
    Relay unidirectionnel : src -> dst. Tolère erreurs et ferme sockets proprement.
    """
    try:
        while not _SHUTDOWN_EVENT.is_set():
            try:
                data = src.recv(buffer_size)
            except Exception:
                break
            if not data:
                try:
                    dst.shutdown(socket.SHUT_WR)
                except Exception:
                    pass
                break
            try:
                dst.sendall(data)
            except Exception:
                break
    except Exception:
        pass
    finally:
        try:
            dst.shutdown(socket.SHUT_WR)
        except Exception:
            pass

def full_duplex_relay(a_sock, b_sock):
    """
    Lance deux threads pour relayer a->b et b->a en blocking mode.
    Retourne quand les deux directions sont terminées.
    """
    t1 = threading.Thread(target=_relay_worker, args=(a_sock, b_sock), daemon=True)
    t2 = threading.Thread(target=_relay_worker, args=(b_sock, a_sock), daemon=True)
    t1.start()
    t2.start()
    # attendre la fin naturelle des threads (pas de timeout)
    t1.join()
    t2.join()
    # best-effort close
    try:
        a_sock.close()
    except Exception:
        pass
    try:
        b_sock.close()
    except Exception:
        pass


# === HTTP(S) Proxy Handler ===
class BlockProxyHandler(BaseHTTPRequestHandler):
    timeout = 10
    rbufsize = 0
    protocol_version = "HTTP/1.1"
    VOIP_ALLOWED_PORTS = {80, 443, 3478, 5060, 5061}  # ports VOIP/STUN/SIP autorisés

    def _extract_hostname_from_path(self, path):
        """
        SÉCURISÉ: Extraction du hostname avec validation stricte.
        """
        try:
            if not path or not isinstance(path, str):
                return None

            # SÉCURITÉ: Limiter la longueur de l'URL
            if len(path) > 2048:  # RFC recommandé
                log(f"SÉCURITÉ: URL trop longue rejetée: {len(path)} chars")
                return None

            # SÉCURITÉ: Vérifier caractères dangereux
            if any(ord(c) < 32 and c not in '\t\n\r' for c in path):
                log("SÉCURITÉ: URL contient caractères de contrôle")
                return None

            parsed = urllib.parse.urlparse(path)
            hostname = parsed.hostname

            if hostname:
                # SÉCURITÉ: Validation du hostname extrait
                if _validate_hostname_input(hostname):
                    return hostname.lower()
                else:
                    log(f"SÉCURITÉ: Hostname invalide extrait: {_sanitize_log_message(hostname)}")
                    return None

            return None

        except (ValueError, UnicodeError) as e:
            log(f"SÉCURITÉ: Erreur parsing URL: {_sanitize_log_message(str(e))}")
            return None
        except Exception as e:
            log(f"SÉCURITÉ: Erreur inattendue extraction hostname: {_sanitize_log_message(str(e))}")
            return None

    def do_CONNECT(self):
        """
        SÉCURISÉ: Gestion CONNECT avec validation stricte des entrées.
        """
        try:
            # SÉCURITÉ: Validation de base du path
            if not self.path or not isinstance(self.path, str):
                self.send_error(400, "Bad Request - path invalide")
                return

            # SÉCURITÉ: Limiter longueur path
            if len(self.path) > 256:  # CONNECT doit être court
                self.send_error(400, "Bad Request - path trop long")
                return

            # SÉCURITÉ: Vérifier format host:port
            if ':' not in self.path:
                self.send_error(400, "Bad Request - format invalide")
                return

            try:
                target_host, port_str = self.path.split(':', 1)
                target_port = int(port_str)
            except ValueError:
                self.send_error(400, "Bad Request - port invalide")
                return

            # SÉCURITÉ: Validation du port
            if target_port < 1 or target_port > 65535:
                self.send_error(400, f"Bad Request - port hors limites: {target_port}")
                return

            # SÉCURITÉ: Validation du hostname
            if not target_host or not _validate_hostname_input(target_host):
                self.send_error(400, "Bad Request - hostname invalide")
                return

            hostname = target_host.lower()

            # Continuation de la logique existante
            if current_resolver:
                current_resolver.maybe_reload_background()

            # Si whitelistée, bypass TOUTES les restrictions (ports, http flags, blocklist)
            try:
                if current_resolver and current_resolver.is_whitelisted(hostname):
                    log(f"✅ [WHITELIST BYPASS CONNECT] {hostname}:{target_port}")
                    # create connection and relay as usual without further checks
                    remote = socket.create_connection((target_host, target_port), timeout=10)
                    self.send_response(200, "Connection Established")
                    self.send_header('Connection', 'close')
                    self.end_headers()

                    conn = self.connection
                    _set_socket_opts_for_perf(conn)
                    _set_socket_opts_for_perf(remote)
                    conn.settimeout(None)
                    remote.settimeout(None)
                    conn.setblocking(True)
                    remote.setblocking(True)
                    full_duplex_relay(conn, remote)
                    return
            except Exception as e:
                # si check whitelist plante, on continue vers checks sécurisés plutôt que laisser tout passer
                log(f"[WARN] whitelist check error in CONNECT for {hostname}: {e}")

            # blocage basé sur blocklist
            if block_enabled and current_resolver and current_resolver._is_blocked(hostname):
                log(f"🚫 [Proxy BLOCK HTTPS] {hostname}")
                self.send_error(403, "Bloqué par sécurité")
                return

            # Si la cible est whitelistée, bypass tous les contrôles
            if current_resolver and current_resolver.is_whitelisted(hostname):
                log(f"✅ [WHITELIST BYPASS CONNECT] {hostname}:{target_port}")
                try:
                    remote = socket.create_connection((target_host, target_port), timeout=10)
                    self.send_response(200, "Connection Established")
                    self.send_header('Connection', 'close')
                    self.end_headers()

                    conn = self.connection
                    _set_socket_opts_for_perf(conn)
                    _set_socket_opts_for_perf(remote)
                    conn.settimeout(None)
                    remote.settimeout(None)
                    conn.setblocking(True)
                    remote.setblocking(True)
                    full_duplex_relay(conn, remote)
                    return
                except Exception as e:
                    log(f"[Whitelist bypass CONNECT error] {e}")
                    self.send_error(502, "Bad Gateway")
                    return

            # Pour les domaines NON whitelistés, appliquer les règles normales
            if block_http_other_ports and target_port not in self.VOIP_ALLOWED_PORTS:
                log(f"🚫 [Proxy BLOCK other port] {target_host}:{target_port}")
                self.send_error(403, "port non standard bloqué par sécurité")
                return

            # Autorisation normale — établir tunnel
            log(f"✅ [Proxy ALLOW HTTPS] {hostname}")

            remote = socket.create_connection((target_host, target_port), timeout=10)
            self.send_response(200, "Connection Established")
            self.send_header('Connection', 'close')
            self.end_headers()

            conn = self.connection
            _set_socket_opts_for_perf(conn)
            _set_socket_opts_for_perf(remote)
            conn.settimeout(None)
            remote.settimeout(None)
            conn.setblocking(True)
            remote.setblocking(True)
            full_duplex_relay(conn, remote)

        except (SecurityError, ValidationError) as e:
            log(f"SÉCURITÉ: CONNECT bloqué: {e}")
            try:
                self.send_error(403, "Forbidden")
            except Exception:
                pass
        except (NetworkError, OSError, socket.error) as e:
            log(f"RÉSEAU: CONNECT error: {_sanitize_log_message(str(e))}")
            try:
                self.send_error(502, "Bad Gateway")
            except Exception:
                pass
        except Exception as e:
            log(f"ERREUR: CONNECT inattendue: {_sanitize_log_message(str(e))}")
            try:
                self.send_error(500, "Internal Server Error")
            except Exception:
                pass

    def _handle_http_method(self):
        """
        SÉCURISÉ: Gestion des méthodes HTTP avec validation complète.
        """
        try:
            if current_resolver:
                current_resolver.maybe_reload_background()

            # SÉCURITÉ: Validation du path
            if not self.path or not isinstance(self.path, str):
                self.send_error(400, "Bad Request - path invalide")
                return

            # SÉCURITÉ: Limiter longueur du path
            if len(self.path) > 4096:  # RFC recommandé pour HTTP
                self.send_error(414, "URI Too Long")
                return

            hostname = self._extract_hostname_from_path(self.path)
            if not hostname:
                host_header = self.headers.get('Host', '')
                if host_header and isinstance(host_header, str):
                    # SÉCURITÉ: Validation du header Host
                    if len(host_header) > 255:  # Limite raisonnable
                        self.send_error(400, "Bad Request - Host header trop long")
                        return

                    # SÉCURITÉ: Nettoyer et valider Host header
                    try:
                        hostname = host_header.split(':', 1)[0] if host_header else None
                        if hostname and not _validate_hostname_input(hostname):
                            log(f"SÉCURITÉ: Host header invalide: {_sanitize_log_message(hostname)}")
                            self.send_error(400, "Bad Request - Host invalide")
                            return
                    except Exception:
                        self.send_error(400, "Bad Request - Host header malformé")
                        return

            if hostname:
                hostname = hostname.lower().strip()

            # Centraliser la vérification whitelist via current_resolver
            is_whitelisted = False
            try:
                if current_resolver and current_resolver.is_whitelisted(hostname):
                    is_whitelisted = True
            except Exception as e:
                log(f"_handle_http_method whitelist check error for {hostname}: {_sanitize_log_message(str(e))}")

            # Si whitelistée => bypass complet : on n'applique pas block_http_traffic, ports ni blocklist
            if is_whitelisted:
                log(f"✅ [WHITELIST BYPASS HTTP] {hostname} ({self.command} {self.path})")
                # Continue vers le forwarding normal (ne pas envoyer 403 même si block_enabled)
                # Le reste du code va établir la connexion et relayer normalement.
            else:
                # si non whitelistée, on applique les protections normales
                if block_enabled and current_resolver and current_resolver._is_blocked(hostname):
                    log(f"🚫 [Proxy BLOCK HTTP] {hostname} ({self.command} {self.path})")
                    self.send_error(403, "Bloqué par sécurité")
                    return

            # SÉCURITÉ: Continuer vers la logique de forwarding avec validation
            # du reste des paramètres (target_host, port, etc.)
            # Extraire target_host, target_port, path_only de la requête
            if isinstance(self.path, str) and self.path.startswith(("http://", "https://")):
                parsed = urllib.parse.urlparse(self.path)
                scheme = parsed.scheme
                target_host = parsed.hostname
                target_port = parsed.port or (443 if scheme == "https" else 80)
                path_only = parsed.path or "/"
                if parsed.query:
                    path_only += "?" + parsed.query
            else:
                host_hdr = self.headers.get('Host', '')
                if ':' in host_hdr:
                    target_host, port_str = host_hdr.split(':', 1)
                    try:
                        target_port = int(port_str)
                    except Exception:
                        target_port = 80
                else:
                    target_host = host_hdr
                    target_port = 80
                path_only = self.path
                scheme = "http"

            if not target_host:
                self.send_error(400, "Bad Request - target host unknown")
                return

            # Si non whitelistée et port non autorisé -> blocage si flag actif
            if (not is_whitelisted) and block_http_other_ports and target_port not in self.VOIP_ALLOWED_PORTS:
                log(f"🚫 [BLOCK other port] {target_host}:{target_port}")
                self.send_error(403, "port non standard bloqué par sécurité")
                return

            # Si non whitelistée et blocage du HTTP direct activé
            if (not is_whitelisted) and block_enabled and block_http_traffic and isinstance(self.path, str) and self.path.startswith("http://"):
                log(f"🚫 [Proxy BLOCK HTTP Traffic] {hostname}")
                self.send_error(403, "Bloqué HTTP par sécurité")
                return

            log(f"✅ [Proxy ALLOW HTTP] {target_host}:{target_port} -> {self.command} {path_only}")

            # Construire headers à forwarder
            hop_by_hop = {"proxy-connection","connection","keep-alive","transfer-encoding","te","trailers","upgrade","proxy-authorization"}
            header_lines = []
            host_header_value = target_host
            if (scheme == "http" and target_port != 80) or (scheme == "https" and target_port != 443):
                host_header_value = f"{target_host}:{target_port}"

            for k, v in self.headers.items():
                try:
                    if k.lower() in hop_by_hop:
                        continue
                    if k.lower() == 'host':
                        header_lines.append(f"Host: {host_header_value}")
                    else:
                        header_lines.append(f"{k}: {v}")
                except Exception:
                    continue

            header_lines = [line for line in header_lines if not line.lower().startswith('connection:')]
            header_lines.append("Connection: close")

            request_line = f"{self.command} {path_only} {self.request_version}\r\n"
            request_headers_raw = "\r\n".join(header_lines) + "\r\n\r\n"
            request_bytes = request_line.encode('utf-8') + request_headers_raw.encode('utf-8')

            remote = socket.create_connection((target_host, target_port), timeout=10)

            _set_socket_opts_for_perf(self.connection)
            _set_socket_opts_for_perf(remote)

            # Retirer timeout après connexion
            self.connection.settimeout(None)
            remote.settimeout(None)
            self.connection.setblocking(True)
            remote.setblocking(True)

            try:
                remote.sendall(request_bytes)
            except (OSError, socket.error) as e:
                log(f"RÉSEAU: Proxy send headers error: {_sanitize_log_message(str(e))}")
                try:
                    remote.close()
                except Exception:
                    pass
                self.send_error(502, "Bad Gateway")
                return
            except Exception as e:
                log(f"ERREUR: Proxy send headers error: {_sanitize_log_message(str(e))}")
                try:
                    remote.close()
                except Exception:
                    pass
                self.send_error(502, "Bad Gateway")
                return

            full_duplex_relay(self.connection, remote)
            try:
                remote.close()
            except Exception:
                pass

            log(f"[Proxy FORWARD DIRECT] {target_host}:{target_port} -> {self.command} {path_only}")

        except (SecurityError, ValidationError) as e:
            log(f"SÉCURITÉ: HTTP method bloqué: {e}")
            try:
                self.send_error(403, "Forbidden")
            except Exception:
                pass
        except (NetworkError, OSError, socket.error) as e:
            log(f"RÉSEAU: HTTP forward error: {_sanitize_log_message(str(e))}")
            try:
                self.send_error(502, "Bad Gateway")
            except Exception:
                pass
        except Exception as e:
            log(f"ERREUR: HTTP method inattendue: {_sanitize_log_message(str(e))}")
            try:
                self.send_error(500, "Internal Server Error")
            except Exception:
                pass

    # raccourcis pour méthodes HTTP
    def do_GET(self): self._handle_http_method()
    def do_POST(self): self._handle_http_method()
    def do_PUT(self): self._handle_http_method()
    def do_DELETE(self): self._handle_http_method()
    def do_HEAD(self): self._handle_http_method()
    def log_message(self, format, *args): return  # silence


# === GUI (tkinter logging window) ===
def show_log_window():
    """
    Fenêtre Tk qui affiche le log_buffer et se met à jour.
    """
    try:
        win = tk.Tk()
    except Exception as e:
        log(f"Impossible d'ouvrir Tkinter: {e}")
        return
    win.title("Calm Web - Journal d’activité")
    win.geometry("700x400")
    text_area = ScrolledText(win, wrap=tk.WORD)
    text_area.pack(expand=True, fill='both')
    text_area.config(state='disabled')

    def refresh_log():
        try:
            text_area.config(state='normal')
            with _LOG_LOCK:
                text_area.delete(1.0, tk.END)
                text_area.insert(tk.END, '\n'.join(log_buffer))
            text_area.see(tk.END)
            text_area.config(state='disabled')
        except Exception:
            pass
        if not _SHUTDOWN_EVENT.is_set():
            win.after(1000, refresh_log)
        else:
            try:
                win.destroy()
            except Exception:
                pass

    refresh_log()
    try:
        win.mainloop()
    except Exception:
        pass


def create_image():
    """
    Création d'une icône générique si extraction d'icône échoue
    """
    try:
        image = Image.new('RGB', (64, 64), (255, 255, 255))
        d = ImageDraw.Draw(image)
        d.rectangle([(8, 16), (56, 48)], outline=(0, 0, 0))
        d.text((18, 22), "CW", fill=(0, 0, 0))
        return image
    except Exception:
        return None

def get_default_text_editor():
    """
    SÉCURISÉ: Détecte l'éditeur de texte par défaut du système Windows.
    Retourne un tuple (chemin_editeur, arguments) ou (None, None) si aucun trouvé.
    """
    try:
        if platform.system().lower() != 'windows':
            return None, None

        import winreg

        # Essayer de récupérer l'éditeur par défaut pour les fichiers .txt
        try:
            # Ouvrir la clé pour l'association .txt
            with winreg.OpenKey(winreg.HKEY_CLASSES_ROOT, ".txt") as key:
                prog_id = winreg.QueryValue(key, None)

            # Obtenir la commande d'ouverture pour ce type de fichier
            command_key = f"{prog_id}\\shell\\open\\command"
            with winreg.OpenKey(winreg.HKEY_CLASSES_ROOT, command_key) as key:
                command = winreg.QueryValue(key, None)

            # Parser la commande pour extraire l'exécutable
            if command:
                # Gérer les guillemets et arguments
                import shlex
                parts = shlex.split(command)
                if parts:
                    editor_path = parts[0]
                    # SÉCURITÉ: Vérifier que l'éditeur existe
                    if os.path.exists(editor_path):
                        # Extraire les arguments (remplacer %1 par le fichier)
                        args = [arg for arg in parts[1:] if arg != "%1"]
                        log(f"Éditeur par défaut détecté: {editor_path}")
                        return editor_path, args

        except (OSError, WindowsError, FileNotFoundError, ValueError):
            # Ignorer les erreurs de registre et continuer avec les fallbacks
            pass

    except Exception as e:
        log(f"Erreur détection éditeur par défaut: {_sanitize_log_message(str(e))}")

    return None, None


def find_available_editor():
    """
    SÉCURISÉ: Recherche un éditeur disponible selon la hiérarchie de fallback.
    Retourne un tuple (chemin_editeur, arguments) ou (None, None) si aucun trouvé.
    """
    if platform.system().lower() != 'windows':
        return None, None

    # Hiérarchie de fallback pour Windows
    fallback_editors = [
        # 1. Notepad système (chemin complet)
        (r'C:\Windows\System32\notepad.exe', []),

        # 2. Notepad via PATH
        ('notepad.exe', []),

        # 3. WordPad
        (r'C:\Program Files\Windows NT\Accessories\wordpad.exe', []),
        (r'C:\Program Files (x86)\Windows NT\Accessories\wordpad.exe', []),

        # 4. VS Code (installations courantes)
        (r'C:\Program Files\Microsoft VS Code\Code.exe', ['--wait']),
        (r'C:\Program Files (x86)\Microsoft VS Code\Code.exe', ['--wait']),
        (os.path.expanduser(r'~\AppData\Local\Programs\Microsoft VS Code\Code.exe'), ['--wait']),

        # 5. Sublime Text
        (r'C:\Program Files\Sublime Text\sublime_text.exe', ['--wait']),
        (r'C:\Program Files (x86)\Sublime Text\sublime_text.exe', ['--wait']),

        # 6. Notepad++
        (r'C:\Program Files\Notepad++\notepad++.exe', []),
        (r'C:\Program Files (x86)\Notepad++\notepad++.exe', []),
    ]

    for editor_path, args in fallback_editors:
        try:
            # SÉCURITÉ: Vérifier que l'éditeur existe
            if editor_path == 'notepad.exe':
                # Test spécial pour notepad via PATH
                try:
                    result = subprocess.run(['where', 'notepad.exe'],
                                          capture_output=True, text=True, timeout=5)
                    if result.returncode == 0 and result.stdout.strip():
                        actual_path = result.stdout.strip().split('\n')[0]
                        if os.path.exists(actual_path):
                            log(f"Éditeur trouvé via PATH: {actual_path}")
                            return actual_path, args
                except (subprocess.TimeoutExpired, subprocess.SubprocessError):
                    continue
            else:
                if os.path.exists(editor_path):
                    log(f"Éditeur trouvé: {editor_path}")
                    return editor_path, args

        except Exception as e:
            # Continuer avec le prochain éditeur en cas d'erreur
            continue

    return None, None


def open_config_in_editor(path):
    """
    SÉCURISÉ: Ouvre le fichier de config avec détection intelligente de l'éditeur.
    Utilise un système de fallback robuste pour trouver un éditeur disponible.
    """
    try:
        # SÉCURITÉ: Validation du chemin
        if not path or not isinstance(path, str):
            raise ValidationError("Chemin de fichier invalide")

        # SÉCURITÉ: Normaliser et valider le chemin
        normalized_path = os.path.normpath(os.path.abspath(path))

        # SÉCURITÉ: Vérifier que c'est dans un répertoire autorisé
        allowed_dirs = [
            os.path.normpath(USER_CFG_DIR),
            os.path.normpath(INSTALL_DIR),
            os.path.normpath(os.path.dirname(os.path.abspath(sys.argv[0])))
        ]

        if not any(normalized_path.startswith(d) for d in allowed_dirs):
            raise SecurityError(f"Chemin non autorisé: {normalized_path}")

        # SÉCURITÉ: Vérifier le nom du fichier
        if not normalized_path.endswith(CUSTOM_CFG_NAME):
            raise SecurityError(f"Seul {CUSTOM_CFG_NAME} peut être édité")

        if not os.path.exists(normalized_path):
            log(f"custom.cfg absent, création avant ouverture")
            try:
                write_default_custom_cfg(normalized_path, manual_blocked_domains, whitelisted_domains)
            except (SecurityError, ValidationError, ConfigurationError) as e:
                log(f"ERREUR: Impossible de créer le fichier config: {e}")
                return

        # SÉCURITÉ: Lancer éditeur de manière sécurisée sur thread séparé
        def _open_secure():
            try:
                if platform.system().lower() == 'windows':
                    editor_found = False

                    # 1. Essayer Notepad système en premier
                    notepad_path = r'C:\Windows\System32\notepad.exe'
                    if os.path.exists(notepad_path):
                        try:
                            subprocess.Popen(
                                [notepad_path, normalized_path],
                                creationflags=subprocess.CREATE_NO_WINDOW
                            )
                            log("Fichier ouvert avec Notepad système")
                            editor_found = True
                        except (OSError, PermissionError) as e:
                            log(f"Erreur avec Notepad système: {_sanitize_log_message(str(e))}")

                    # 2. Si Notepad système échoue, essayer notepad via PATH
                    if not editor_found:
                        try:
                            subprocess.Popen(
                                ['notepad.exe', normalized_path],
                                creationflags=subprocess.CREATE_NO_WINDOW
                            )
                            log("Fichier ouvert avec Notepad (PATH)")
                            editor_found = True
                        except FileNotFoundError:
                            log("Notepad non trouvé dans PATH")
                        except (OSError, PermissionError) as e:
                            log(f"Erreur avec Notepad PATH: {_sanitize_log_message(str(e))}")

                    # 3. Si Notepad échoue, essayer l'éditeur par défaut du registre
                    if not editor_found:
                        default_editor, default_args = get_default_text_editor()
                        if default_editor:
                            try:
                                cmd = [default_editor] + default_args + [normalized_path]
                                subprocess.Popen(
                                    cmd,
                                    creationflags=subprocess.CREATE_NO_WINDOW
                                )
                                log("Fichier ouvert avec l'éditeur par défaut")
                                editor_found = True
                            except (OSError, PermissionError, FileNotFoundError) as e:
                                log(f"Erreur avec éditeur par défaut: {_sanitize_log_message(str(e))}")

                    # 4. Si l'éditeur par défaut échoue, essayer les autres éditeurs
                    if not editor_found:
                        fallback_editor, fallback_args = find_available_editor()
                        if fallback_editor:
                            try:
                                cmd = [fallback_editor] + fallback_args + [normalized_path]
                                subprocess.Popen(
                                    cmd,
                                    creationflags=subprocess.CREATE_NO_WINDOW
                                )
                                log("Fichier ouvert avec éditeur de fallback")
                                editor_found = True
                            except (OSError, PermissionError, FileNotFoundError) as e:
                                log(f"Erreur avec éditeur de fallback: {_sanitize_log_message(str(e))}")

                    # 5. Dernier recours: os.startfile()
                    if not editor_found:
                        try:
                            os.startfile(normalized_path)
                            log("Fichier ouvert avec l'application par défaut (os.startfile)")
                            editor_found = True
                        except (OSError, PermissionError) as e:
                            log(f"Erreur avec os.startfile: {_sanitize_log_message(str(e))}")

                    # Si aucune méthode n'a fonctionné
                    if not editor_found:
                        log("ERREUR: Aucun éditeur disponible trouvé pour ouvrir le fichier")

                else:
                    # SÉCURITÉ: Pour non-Windows, utiliser seulement xdg-open si disponible
                    try:
                        subprocess.Popen(
                            ['xdg-open', normalized_path],
                            stdout=subprocess.DEVNULL,
                            stderr=subprocess.DEVNULL
                        )
                        log("Fichier ouvert avec xdg-open")
                    except FileNotFoundError:
                        log("SÉCURITÉ: xdg-open non trouvé, impossible d'ouvrir l'éditeur")

            except Exception as e:
                log(f"ERREUR: Erreur inattendue ouverture éditeur: {_sanitize_log_message(str(e))}")

        threading.Thread(target=_open_secure, daemon=True).start()
        log("Ouverture du fichier de configuration demandée")

    except (ValidationError, SecurityError) as e:
        log(f"SÉCURITÉ: Ouverture éditeur bloquée: {e}")
    except Exception as e:
        log(f"ERREUR: Erreur ouverture éditeur: {_sanitize_log_message(str(e))}")

def reload_config_action(icon=None, item=None):
    """
    Recharge le fichier custom.cfg et relance le chargement complet des blocklists et whitelists.
    """
    try:
        cfg_path = get_custom_cfg_path(INSTALL_DIR)
        if not os.path.exists(cfg_path):
            log(f"Aucun custom.cfg trouvé à recharger : {cfg_path}")
            return

        # Recharger les variables globales depuis le fichier custom.cfg
        load_custom_cfg_to_globals(cfg_path)
        log("Configuration locale rechargée depuis le fichier utilisateur.")

        if current_resolver:
            # Lancer les deux rechargements (blocklist + whitelist) en parallèle
            threading.Thread(target=current_resolver._load_blocklist, daemon=True).start()
            threading.Thread(target=current_resolver._load_whitelist, daemon=True).start()
            log("Demande de rechargement complet des blocklists et whitelists externes (thread).")
        else:
            log("[WARN] Aucun resolver actif pour rechargement.")

    except Exception as e:
        log(f"Erreur lors du rechargement de la configuration : {e}")


def toggle_block(icon, item):
    global block_enabled
    block_enabled = not block_enabled
    state = "activé" if block_enabled else "désactivé"
    log(f"Calm Web : blocage {state}")
    try:
        set_system_proxy(enable=block_enabled)
    except Exception as e:
        log(f"Erreur lors du réglage proxy système au toggle: {e}")
    update_menu(icon)

def update_menu(icon):
    """
    Reconstruit le menu systray. Safe: encapsule entièrement les callbacks pour éviter exceptions non gérées.
    """
    try:
        icon.menu = Menu(
            MenuItem(f"Calm Web v{calmweb_version}", lambda: None, enabled=False),
            MenuItem(f"🔒 Blocage: {'✅ Activé' if block_enabled else '❌ Désactivé'}", lambda: None, enabled=False),
            MenuItem("❌ Désactiver le Blocage" if block_enabled else "✅ Activer le Blocage", toggle_block),
            MenuItem("⚙️ Config", Menu(
                MenuItem("✏️ Ouvrir / Éditer la config", lambda icon, item: threading.Thread(target=open_config_in_editor, args=(get_custom_cfg_path(INSTALL_DIR),), daemon=True).start()),
                MenuItem("🔄 Recharger la config", reload_config_action)
            )),
            MenuItem("📄 Afficher le Log", lambda: threading.Thread(target=show_log_window, daemon=True).start()),
            MenuItem("🚪 Quitter", quit_app)
        )
        try:
            icon.update_menu()
        except Exception:
            # pystray peut lancer si icône arrêtée; ignorer
            pass
    except Exception as e:
        log(f"update_menu error: {e}")

def quit_app(icon=None, item=None):
    """
    Nettoyage et sortie propre.
    """
    try:
        log("Arrêt demandé.")
        _SHUTDOWN_EVENT.set()
        # Retirer le proxy système s'il a été mis en place
        try:
            set_system_proxy(enable=False)
            log("Proxy système réinitialisé.")
        except Exception as e:
            log(f"Erreur lors de la réinitialisation du proxy système : {e}")

        if proxy_server:
            try:
                proxy_server.shutdown()
                proxy_server.server_close()
                log("Serveur proxy arrêté.")
            except Exception as e:
                log(f"Erreur arrêt proxy: {e}")

        try:
            if icon:
                icon.stop()
        except Exception:
            pass

        log("Arrêt de l'application Calm Web.")
        # donner un petit délai pour que threads terminent proprement
        time.sleep(0.2)
        # forcer exit proprement
        try:
            os._exit(0)
        except Exception:
            try:
                sys.exit(0)
            except Exception:
                pass
    except Exception as e:
        log(f"Erreur lors de l'arrêt de l'application : {e}")

# === PROXY SERVER MANAGEMENT ===
def start_proxy_server(bind_ip=PROXY_BIND_IP, port=PROXY_PORT):
    """
    Démarre ThreadingHTTPServer et retourne l'objet serveur; renvoie None en cas d'erreur.
    """
    global proxy_server, proxy_server_thread
    try:
        # Validation des paramètres
        if not bind_ip or not isinstance(port, int) or port <= 0 or port > 65535:
            log(f"ERREUR: Paramètres proxy invalides - IP: {bind_ip}, Port: {port}")
            return None

        # Test de disponibilité du port avant de créer le serveur
        test_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        test_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            test_socket.bind((bind_ip, port))
            test_socket.close()
        except Exception as bind_error:
            test_socket.close()
            log(f"ERREUR: Port {port} déjà utilisé ou inaccessible: {bind_error}")
            return None

        # Création du serveur
        log(f"Tentative de démarrage du proxy sur {bind_ip}:{port}...")
        server = ThreadingHTTPServer((bind_ip, port), BlockProxyHandler)
        proxy_server = server

        # Démarrage du thread serveur
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        proxy_server_thread = thread
        thread.start()

        # Petit délai pour s'assurer que le serveur est opérationnel
        time.sleep(0.1)

        # Vérification que le serveur écoute vraiment
        try:
            test_client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            test_client.settimeout(1.0)
            result = test_client.connect_ex((bind_ip, port))
            test_client.close()

            if result == 0:
                log(f"✓ Proxy HTTP(S) démarré et opérationnel sur {bind_ip}:{port}")
                return server
            else:
                log(f"ERREUR: Serveur créé mais n'écoute pas sur le port {port}")
                server.shutdown()
                return None
        except Exception as verify_error:
            log(f"ERREUR: Impossible de vérifier l'état du serveur: {verify_error}")
            server.shutdown()
            return None

    except Exception as e:
        log(f"ERREUR critique lors du démarrage du proxy: {e}")
        log(f"Details: {traceback.format_exc()}")
        return None

# === INSTALL / UNINSTALL / MAIN ===
def install():
    """
    Installation : copie, firewall rule, tâche planifiée, config, et lancement.
    """
    try:
        win = threading.Thread(target=show_log_window, daemon=True)
        win.start()
    except Exception:
        pass

    log("Début installation Calm Web...")

    try:
        if not os.path.exists(INSTALL_DIR):
            os.makedirs(INSTALL_DIR, exist_ok=True)
            log(f"Répertoire créé : {INSTALL_DIR}")
    except Exception as e:
        log(f"Impossible de créer INSTALL_DIR {INSTALL_DIR}: {e}")

    # Créer custom.cfg dans APPDATA si absent (avec domaines embarqués comme base)
    ensure_custom_cfg_exists(INSTALL_DIR, manual_blocked_domains, whitelisted_domains)

    # Copier le script/exe
    try:
        current_file = sys.argv[0] if getattr(sys, 'frozen', False) else os.path.abspath(__file__)
        target_file = os.path.join(INSTALL_DIR, EXE_NAME)
        try:
            shutil.copy(current_file, target_file)
            log(f"Copie terminée : {target_file}")
        except Exception as e:
            log(f"Erreur copie fichier vers {target_file} : {e}")
    except Exception as e:
        log(f"Erreur détermination current_file: {e}")

    add_firewall_rule(os.path.join(INSTALL_DIR, EXE_NAME))

    # XML de la tâche à créer
    xml_content = '''<?xml version="1.0" encoding="utf-16"?>
    <Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
      <RegistrationInfo>
        <Date>2025-10-26T10:16:48</Date>
        <Author>Tonton Jo</Author>
        <URI>CalmWeb</URI>
      </RegistrationInfo>
      <Triggers>
        <LogonTrigger>
          <StartBoundary>2025-10-26T10:16:00</StartBoundary>
          <Enabled>true</Enabled>
        </LogonTrigger>
      </Triggers>
      <Principals>
        <Principal id="Author">
          <GroupId>S-1-5-32-544</GroupId>
          <RunLevel>HighestAvailable</RunLevel>
        </Principal>
      </Principals>
      <Settings>
        <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
        <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
        <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
        <AllowHardTerminate>true</AllowHardTerminate>
        <StartWhenAvailable>false</StartWhenAvailable>
        <RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>
        <IdleSettings>
          <StopOnIdleEnd>true</StopOnIdleEnd>
          <RestartOnIdle>false</RestartOnIdle>
        </IdleSettings>
        <AllowStartOnDemand>true</AllowStartOnDemand>
        <Enabled>true</Enabled>
        <Hidden>false</Hidden>
        <RunOnlyIfIdle>false</RunOnlyIfIdle>
        <WakeToRun>false</WakeToRun>
        <ExecutionTimeLimit>PT0S</ExecutionTimeLimit>
        <Priority>7</Priority>
      </Settings>
      <Actions Context="Author">
        <Exec>
          <Command>"C:\\Program Files\\CalmWeb\\calmweb.exe"</Command>
        </Exec>
      </Actions>
    </Task>'''

    def add_task_from_xml(xml_content_inner):
        """
        SÉCURISÉ: Ajout de tâche planifiée avec validation du contenu XML.
        """
        tmp_file_path = None
        try:
            # SÉCURITÉ: Validation du contenu XML
            if not xml_content_inner or not isinstance(xml_content_inner, str):
                raise SecurityError("Contenu XML invalide")

            # SÉCURITÉ: Vérifier la taille du XML (max 10KB)
            if len(xml_content_inner) > 10 * 1024:
                raise SecurityError(f"XML trop volumineux: {len(xml_content_inner)} chars")

            # SÉCURITÉ: Validation basique du XML (contient les balises attendues)
            required_tags = ['<Task', '<Command>', '</Task>']
            if not all(tag in xml_content_inner for tag in required_tags):
                raise SecurityError("Structure XML non conforme")

            # SÉCURITÉ: Vérifier que le chemin dans Command pointe vers notre installation
            if 'C:\\Program Files\\CalmWeb\\calmweb.exe' not in xml_content_inner:
                raise SecurityError("Chemin de commande non autorisé dans XML")

            # SÉCURITÉ: Créer fichier temporaire avec permissions restreintes
            with tempfile.NamedTemporaryFile(
                delete=False,
                mode='w',
                encoding='utf-16',
                suffix='.xml',
                prefix='calmweb_task_'
            ) as tmp_file:
                tmp_file.write(xml_content_inner)
                tmp_file_path = tmp_file.name

            # SÉCURITÉ: Vérifier que le fichier a été créé
            if not os.path.exists(tmp_file_path):
                raise OSError(f"Fichier XML temporaire non créé: {tmp_file_path}")

            # SÉCURITÉ: Exécution schtasks avec timeout et validation stricte
            cmd = ["schtasks", "/Create", "/tn", "CalmWeb", "/XML", tmp_file_path, "/F"]

            try:
                subprocess.run(
                    cmd,
                    check=True,
                    timeout=30,  # Timeout de 30 secondes
                    capture_output=True,
                    text=True,
                    creationflags=subprocess.CREATE_NO_WINDOW
                )
                log("Tâche planifiée ajoutée avec succès.")

            except subprocess.TimeoutExpired:
                raise NetworkError("Timeout lors de la création de la tâche planifiée")
            except subprocess.CalledProcessError as e:
                raise NetworkError(f"Erreur schtasks (code {e.returncode}): {_sanitize_log_message(str(e))}")

        except (SecurityError, NetworkError):
            raise  # Re-lever les erreurs de sécurité/réseau
        except OSError as e:
            raise ConfigurationError(f"Erreur fichier temporaire: {_sanitize_log_message(str(e))}")
        except Exception as e:
            raise ConfigurationError(f"Erreur add_task_from_xml: {_sanitize_log_message(str(e))}")
        finally:
            # SÉCURITÉ: Nettoyer le fichier temporaire de manière sécurisée
            try:
                if tmp_file_path and os.path.exists(tmp_file_path):
                    # Écraser le contenu avant suppression pour sécurité
                    with open(tmp_file_path, 'w') as f:
                        f.write('X' * 1024)  # Écraser avec des données arbitraires
                    os.remove(tmp_file_path)
            except Exception as e:
                log(f"SÉCURITÉ: Erreur nettoyage fichier temp: {_sanitize_log_message(str(e))}")

    # SÉCURITÉ: Appel sécurisé de add_task_from_xml avec gestion d'erreurs
    try:
        add_task_from_xml(xml_content)
    except (SecurityError, NetworkError, ConfigurationError) as e:
        log(f"ERREUR: Échec création tâche planifiée: {e}")
    except Exception as e:
        log(f"ERREUR: Erreur inattendue tâche planifiée: {_sanitize_log_message(str(e))}")

    # Lancer l'exe copié (si possible)
    try:
        target_file = os.path.join(INSTALL_DIR, EXE_NAME)
        if platform.system().lower() == 'windows':
            try:
                os.startfile(target_file)
                log("Installation terminée - Calm Web démarré")
            except Exception as e:
                log(f"Impossible de démarrer automatiquement {target_file} : {e}")
        else:
            log("Installation: auto-start non supporté sur cette plateforme.")
    except Exception as e:
        log(f"Installation start error: {e}")

    time.sleep(1)
    # Ne pas forcer sys.exit brutalement ici si installé depuis UI; on essaye de quitter
    try:
        sys.exit(0)
    except Exception:
        pass

# === Run Calm Web ===
def run_calmweb():
    """
    Point d'entrée principal pour exécuter Calm Web en mode utilisateur.
    """
    global current_resolver
    try:
        cfg_path = ensure_custom_cfg_exists(INSTALL_DIR, manual_blocked_domains, whitelisted_domains)
        load_custom_cfg_to_globals(cfg_path)
    except Exception as e:
        log(f"Erreur chargement config initiale: {e}")

    try:
        resolver = BlocklistResolver(get_blocklist_urls(), RELOAD_INTERVAL)
        current_resolver = resolver
    except Exception as e:
        log(f"Erreur création resolver: {e}")

    try:
        proxy_server_instance = start_proxy_server(PROXY_BIND_IP, PROXY_PORT)
        if proxy_server_instance is None:
            log(f"ÉCHEC CRITIQUE: Le proxy n'a pas pu démarrer sur {PROXY_BIND_IP}:{PROXY_PORT}")
            log("L'application ne pourra pas fonctionner correctement")
        else:
            log(f"Proxy configuré avec succès")
    except Exception as e:
        log(f"ERREUR EXCEPTION lors du démarrage du proxy: {e}")
        log(f"Details: {traceback.format_exc()}")

    try:
        set_system_proxy(enable=block_enabled)
    except Exception as e:
        log(f"Erreur proxy système: {e}")

    # Start systray icon
    try:
        icon = Icon("calmweb")
        icon_path = sys.executable  # chemin de calmweb.exe ou python.exe
        try:
            icon.icon = get_exe_icon(icon_path) or create_image()
        except Exception:
            icon.icon = create_image()
        icon.title = "Calm Web"
        update_menu(icon)
        log(f"Calm Web démarré. Proxy sur {PROXY_BIND_IP}:{PROXY_PORT}, blocage {'activé' if block_enabled else 'désactivé'}.")
        # hook signals to allow graceful termination
        def _signal_handler(signum, frame):
            log(f"Signal {signum} reçu, arrêt.")
            quit_app(icon)
        try:
            signal.signal(signal.SIGINT, _signal_handler)
            signal.signal(signal.SIGTERM, _signal_handler)
        except Exception:
            pass
        icon.run()
    except Exception as e:
        log(f"Erreur systray / run: {e}")
        # Si la systray échoue (ex: environnement sans GUI), garder le serveur en arrière-plan
        try:
            while not _SHUTDOWN_EVENT.is_set():
                time.sleep(1)
        except KeyboardInterrupt:
            quit_app(None)

def robust_main():
    """
    Mécanisme auto-restart pour fiabilité maximale
    """
    restart_count = 0
    max_restarts = 5

    while restart_count < max_restarts:
        try:
            log(f"🚀 Démarrage CalmWeb (tentative {restart_count + 1})")

            exe_name = os.path.basename(sys.argv[0]).lower()
            if exe_name == "calmweb_proxy.exe":
                install()
            else:
                run_calmweb()

            # Si on arrive ici, tout va bien
            break

        except KeyboardInterrupt:
            log("Arrêt demandé par Ctrl+C.")
            break
        except Exception as e:
            restart_count += 1
            log(f"❌ Erreur critique (tentative {restart_count}): {e}")
            log(traceback.format_exc())

            if restart_count < max_restarts:
                log(f"🔄 Redémarrage automatique dans 5 secondes...")
                time.sleep(5)
            else:
                log(f"❌ Échec après {max_restarts} tentatives. Arrêt définitif.")
                break

    # Arrêt propre final
    try:
        quit_app(None, None)
    except Exception:
        pass
    try:
        sys.exit(1)
    except Exception:
        os._exit(1)

if __name__ == "__main__":
    robust_main()

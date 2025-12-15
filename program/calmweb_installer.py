#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Tonton Jo - 2025
# Join me on Youtube: https://www.youtube.com/c/tontonjo

from urllib.parse import urlparse
import urllib.parse
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
from pystray import Icon, MenuItem, Menu
from PIL import Image, ImageDraw
from datetime import datetime
from collections import deque
import ipaddress
import tkinter as tk
from tkinter.scrolledtext import ScrolledText
import signal
import traceback
import select
import csv
import io
import zipfile
import ctypes
import urllib3
import ssl
import socket
import platform
import subprocess
import threading
import time
import tempfile
import sys
import shutil
import os
import webbrowser
calmweb_version = "1.2.0"


# Optional Windows-only imports: encapsulées pour éviter crash si non disponibles
try:
    import win32ui
    import win32gui
    import win32con
    import win32com.client
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
    "add.blocked.domain"
}

whitelisted_domains = {
    "add.allowed.domain"
}

RELOAD_INTERVAL = 3600
PROXY_BIND_IP = "127.0.0.1"
PROXY_PORT = 8080

# Resource/connection safety limits
# skip any blocklist download larger than this
MAX_BLOCKLIST_BYTES = 25 * 1024 * 1024
MAX_PROXY_CONNECTIONS = 200              # cap concurrent proxy threads
SOCKET_IDLE_TIMEOUT = 90                 # seconds before dropping idle relays
# guardrail to avoid unbounded memory use
MAX_BLOCKED_DOMAINS = 1_500_000
# truncate persisted log if it grows too big
MAX_LOG_FILE_BYTES = 5 * 1024 * 1024
MAX_LOG_FILE_LINES = 4000

INSTALL_DIR = r"C:\Program Files\CalmWeb"
EXE_NAME = "calmweb.exe"
STARTUP_FOLDER = os.getenv('APPDATA', '') + \
    r"\Microsoft\Windows\Start Menu\Programs\Startup"
CUSTOM_CFG_NAME = "custom.cfg"

USER_CFG_DIR = os.path.join(
    os.getenv('APPDATA') or os.path.expanduser("~"), "CalmWeb")
USER_CFG_PATH = os.path.join(USER_CFG_DIR, CUSTOM_CFG_NAME)
LOG_FILE_PATH = os.path.join(USER_CFG_DIR, "calmweb_log.txt")
RED_FLAG_CACHE_PATH = os.path.join(USER_CFG_DIR, "red_flag_domains.txt")
RED_FLAG_TIMESTAMP_PATH = os.path.join(
    USER_CFG_DIR, "red_flag_last_update.txt")

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
_CONNECTION_SEMAPHORE = threading.BoundedSemaphore(MAX_PROXY_CONNECTIONS)

# === Logging ===
_LOG_LOCK = threading.Lock()


def _safe_str(obj):
    """Safely convert object to string."""
    try:
        return str(obj)
    except Exception:
        return f"<{type(obj).__name__} object>"


def log(msg):
    try:
        timestamp = time.strftime("[%H:%M:%S]")
        try:
            # Force conversion str + remplacement erreurs unicode
            safe_msg = str(msg).encode(
                "utf-8", errors="replace").decode("utf-8", errors="replace")
        except Exception:
            safe_msg = "Log message conversion error"

        line = f"{timestamp} {safe_msg}"

        with _LOG_LOCK:
            # Ajout dans buffer (deque gère automatiquement la taille max)
            log_buffer.append(line)

            # Persistance disque avec troncature simple pour éviter gonflement
            try:
                os.makedirs(USER_CFG_DIR, exist_ok=True)
                if os.path.exists(LOG_FILE_PATH) and os.path.getsize(LOG_FILE_PATH) > MAX_LOG_FILE_BYTES:
                    try:
                        with open(LOG_FILE_PATH, 'r', encoding='utf-8', errors='ignore') as lf:
                            tail_lines = deque(lf, maxlen=MAX_LOG_FILE_LINES)
                        with open(LOG_FILE_PATH, 'w', encoding='utf-8', errors='ignore') as lf:
                            lf.writelines(tail_lines)
                    except Exception:
                        pass
                with open(LOG_FILE_PATH, 'a', encoding='utf-8', errors='ignore') as lf:
                    lf.write(line + "\n")
            except Exception:
                pass

            # Affichage console protégé
            try:
                print(line, flush=True)
            except Exception:
                # stdout peut être indisponible dans certains environnements
                pass

    except Exception:
        # Dernière ligne de défense: pas d’exception propagée
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
    except Exception as e:
        log(f"get_exe_icon: ExtractIconEx error: {e}")
        return None

    if (not small) and (not large):
        return None

    try:
        hicon = large[0] if large else small[0]
    except Exception:
        return None

    # créer DC compatible
    try:
        hdc = win32ui.CreateDCFromHandle(win32gui.GetDC(0))
        hdc_mem = hdc.CreateCompatibleDC()
        hbmp = win32ui.CreateBitmap()
        hbmp.CreateCompatibleBitmap(hdc, size[0], size[1])
        hdc_mem.SelectObject(hbmp)
        win32gui.DrawIconEx(hdc_mem.GetSafeHdc(), 0, 0, hicon,
                            size[0], size[1], 0, 0, win32con.DI_NORMAL)
        bmpinfo = hbmp.GetInfo()
        bmpstr = hbmp.GetBitmapBits(True)
        img = Image.frombuffer(
            'RGB',
            (bmpinfo['bmWidth'], bmpinfo['bmHeight']),
            bmpstr, 'raw', 'BGRX', 0, 1
        )
    except Exception as e:
        log(f"get_exe_icon: conversion error: {e}")
        img = None
    finally:
        try:
            win32gui.DestroyIcon(hicon)
        except Exception:
            pass
        try:
            hdc_mem.DeleteDC()
            hdc.DeleteDC()
            win32gui.ReleaseDC(0, 0)
        except Exception:
            pass
    return img

# === Custom config handling ===


def get_custom_cfg_path(install_dir=None):
    """
    Retourne le chemin du custom.cfg: priorise APPDATA, sinon install_dir, sinon dossier courant.
    """
    try:
        if USER_CFG_DIR:
            return USER_CFG_PATH
    except Exception:
        pass
    if install_dir and os.path.isdir(install_dir):
        return os.path.join(install_dir, CUSTOM_CFG_NAME)
    return os.path.join(os.path.dirname(os.path.abspath(sys.argv[0])), CUSTOM_CFG_NAME)


def write_default_custom_cfg(path, blocked_set, whitelist_set):
    """
    Écrit un fichier custom.cfg par défaut. Ne lève pas d'exception.
    Inclut les options block_ip_direct, block_http_traffic et block_http_other_ports.
    """
    try:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, 'w', encoding='utf-8') as f:
            # --- Section BLOCK ---
            f.write("[BLOCK]\n")
            for d in sorted(blocked_set):
                f.write(f"{d}\n")

            # --- Section WHITELIST ---
            f.write("\n[WHITELIST]\n")
            for d in sorted(whitelist_set):
                f.write(f"{d}\n")
            # --- Section OPTIONS ---
            f.write("\n[OPTIONS]\n")
            f.write("block_ip_direct = 1\n")
            f.write("block_http_traffic = 1\n")
            f.write("block_http_other_ports = 1\n")

        log(f"Fichier de configuration créé : {path}")
    except Exception as e:
        log(f"Erreur écriture custom.cfg {path} : {e}")


def parse_custom_cfg(path):
    """
    Parse un custom.cfg simple. Renvoie (blocked_set, whitelist_set).
    Tolérant aux erreurs.
    """
    blocked = set()
    whitelist = set()
    global block_ip_direct, block_http_traffic, block_http_other_ports

    # valeurs par défaut
    block_ip_direct = True
    block_http_traffic = True
    block_http_other_ports = True

    if not os.path.exists(path):
        log(f"custom.cfg introuvable à {path}")
        return blocked, whitelist

    section = None
    try:
        with open(path, 'r', encoding='utf-8') as f:
            for raw in f:
                try:
                    line = raw.strip()
                    if not line or line.startswith('#'):
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
                        blocked.add(line.lower().lstrip('.'))
                    elif section == "WHITELIST":
                        whitelist.add(line.lower().lstrip('.'))
                    elif section == "OPTIONS":
                        try:
                            key, val = line.split('=', 1)
                            key = key.strip().lower()
                            val = val.strip().lower()
                            enabled = val in ("1", "true", "yes", "on")
                            if key == "block_ip_direct":
                                block_ip_direct = enabled
                            elif key == "block_http_traffic":
                                block_http_traffic = enabled
                            elif key == "block_http_other_ports":
                                block_http_other_ports = enabled
                        except Exception:
                            # ligne mal formée -> ignorer
                            pass
                    else:
                        blocked.add(line.lower().lstrip('.'))
                except Exception:
                    # ignorer une ligne problématique
                    continue

        log(
            f"custom.cfg chargé : {len(blocked)} bloqués, {len(whitelist)} whitelist, "
            f"IP block={block_ip_direct}, HTTP block={block_http_traffic}, "
            f"HTTP other ports={block_http_other_ports}"
        )
    except Exception as e:
        log(f"Erreur lecture custom.cfg {path} : {e}")

    return blocked, whitelist


def ensure_custom_cfg_exists(install_dir, default_blocked, default_whitelist):
    """
    Assure l'existence d'un custom.cfg dans APPDATA prioritairement, sinon dans le dossier d'installation.
    Renvoie le chemin utilisé.
    """
    try:
        if not os.path.isdir(USER_CFG_DIR):
            os.makedirs(USER_CFG_DIR, exist_ok=True)
        if not os.path.exists(USER_CFG_PATH):
            write_default_custom_cfg(
                USER_CFG_PATH, default_blocked, default_whitelist)
        return USER_CFG_PATH
    except Exception as e:
        log(f"Erreur ensure_custom_cfg_exists (APPDATA): {e}")
    cfg_path = get_custom_cfg_path(install_dir)
    if not os.path.exists(cfg_path):
        try:
            write_default_custom_cfg(
                cfg_path, default_blocked, default_whitelist)
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
            log(
                f"❌ Échec téléchargement red.flag.domains: HTTP {response.status}")
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
        "https://urlhaus.abuse.ch/downloads/csv/",
        # Red Flag Domains - avec mise à jour automatique quotidienne
        get_red_flag_domains_path()
    ]


# Initialisation des URLs de blocklist
BLOCKLIST_URLS = get_blocklist_urls()

# === Firewall / Proxy ===


def add_firewall_rule(target_file):
    """
    Tente d'ajouter une règle de pare-feu via netsh. Capture erreurs.
    """
    try:
        if platform.system().lower() != 'windows':
            log("add_firewall_rule: non-Windows, skip.")
            return
        subprocess.run([
            "netsh", "advfirewall", "firewall", "add", "rule",
            "name=CalmWeb", "dir=in", "action=allow",
            "program=" + target_file, "profile=any"
        ], check=True, creationflags=subprocess.CREATE_NO_WINDOW)
        log("Règles du pare-feu ajoutées.")
    except Exception as e:
        log(f"Erreur firewall : {e}")


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
        # non-global copy; on fusionnera avec global si nécessaire
        self.whitelisted_domains_local = set()
        self.whitelisted_networks = set()       # set(ipaddress.ip_network(...))

        # Chargement initial (tolérant)
        try:
            self._load_blocklist()
            self._load_whitelist()
        except Exception as e:
            log(f"BlocklistResolver init error: {e}")

    def _load_blocklist(self):
        if self._loading_lock.locked():
            log("Blocklist load déjà en cours, skip.")
            return
        with self._loading_lock:
            _RESOLVER_LOADING.set()
            try:
                domains = set()
                http = urllib3.PoolManager(
                    cert_reqs='CERT_REQUIRED', ssl_context=ssl.create_default_context())
                cap_reached = False

                for url in self.blocklist_urls:
                    success = False
                    for attempt in range(3):
                        try:
                            log(
                                f"⬇️ Chargement blocklist {url} (tentative {attempt+1})")

                            # --- Téléchargement ou lecture locale
                            if url.startswith("file://"):
                                file_path = url[7:]  # Enlever "file://"
                                with open(file_path, "rb") as f:
                                    raw_data = f.read()
                            else:
                                response = http.request(
                                    "GET", url, timeout=urllib3.Timeout(connect=5.0, read=15.0))
                                if response.status != 200:
                                    raise Exception(f"HTTP {response.status}")
                                raw_data = response.data

                            if len(raw_data) > MAX_BLOCKLIST_BYTES:
                                raise Exception(
                                    f"Payload trop volumineux ({len(raw_data)} bytes > {MAX_BLOCKLIST_BYTES})")

                            # --- Si ZIP, extraction et parsing
                            if zipfile.is_zipfile(io.BytesIO(raw_data)):
                                log(f"🗜️ Archive ZIP détectée : {url}")
                                with zipfile.ZipFile(io.BytesIO(raw_data)) as zf:
                                    for name in zf.namelist():
                                        if cap_reached:
                                            break
                                        if not name.lower().endswith((".txt", ".csv", ".log")):
                                            continue
                                        log(f"   → Lecture {name} dans l’archive ZIP")
                                        content = zf.read(name).decode(
                                            "utf-8", errors="ignore")

                                        for line in content.splitlines():
                                            if cap_reached:
                                                break
                                            if not line or line.startswith("#"):
                                                continue
                                            # --- Format CSV (ex: URLHaus)
                                            if line.startswith('"') and "," in line:
                                                try:
                                                    reader = csv.reader(
                                                        io.StringIO(line))
                                                    row = next(reader)
                                                    if len(row) >= 3:
                                                        url_candidate = row[2].strip(
                                                            '"').strip()
                                                        host = urlparse(
                                                            url_candidate).hostname
                                                        if host:
                                                            host = host.lower()
                                                            try:
                                                                ipaddress.ip_address(
                                                                    host)
                                                                domains.add(
                                                                    host)
                                                            except ValueError:
                                                                if len(host) <= 253:
                                                                    domains.add(
                                                                        host)
                                                except Exception:
                                                    continue
                                            else:
                                                # --- Format texte simple
                                                parts = line.split()
                                                if not parts:
                                                    continue
                                                domain = parts[0].strip(
                                                ).lower().lstrip(".")
                                                if not domain or len(domain) > 253:
                                                    continue
                                                if not self._looks_like_ip(domain):
                                                    domains.add(domain)

                            else:
                                # --- Fichier texte classique
                                content = raw_data.decode(
                                    "utf-8", errors="ignore")
                                for line in content.splitlines():
                                    if cap_reached:
                                        break
                                    line = line.split("#", 1)[0].strip()
                                    if not line:
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
                                    domain = domain.lower().lstrip(".")
                                    if not domain or len(domain) > 253:
                                        continue
                                    if not self._looks_like_ip(domain):
                                        domains.add(domain)
                                        if len(domains) >= MAX_BLOCKED_DOMAINS:
                                            cap_reached = True
                                            log(
                                                f"⚠️ Limite de domaines atteinte ({MAX_BLOCKED_DOMAINS}), troncature.")
                                            break

                            success = True
                            break

                        except Exception as e:
                            log(f"[Erreur] Loading {url} attempt {attempt+1}: {e}")
                            time.sleep(1 + attempt * 2)

                    if not success:
                        log(
                            f"[⚠️] Échec téléchargement blocklist depuis {url}")
                    if cap_reached:
                        break

                # --- Mise à jour atomique de la blocklist
                with self._lock:
                    self.blocked_domains = domains
                    self.last_reload = time.time()

                log(f"✅ {len(domains)} domaines/IP bloqués chargés.")

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
            http = urllib3.PoolManager(
                cert_reqs='CERT_REQUIRED', ssl_context=ssl.create_default_context())
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
                        log(
                            f"⬇️ Téléchargement whitelist {url} (tentative {attempt+1})")
                        response = http.request(
                            "GET", url, timeout=urllib3.Timeout(connect=5.0, read=10.0))
                        if response.status != 200:
                            raise Exception(f"HTTP {response.status}")
                        content = response.data.decode(
                            "utf-8", errors='ignore')
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
                                        net = ipaddress.ip_network(
                                            entry, strict=False)
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
                        log(
                            f"[⚠️] Loading whitelist failed {url} attempt {attempt+1}: {e}")
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
    Met en place ou retire le proxy système. Tolère erreurs.
    """
    try:
        if platform.system().lower() != 'windows':
            log("set_system_proxy: non-Windows, skip.")
            return
        if enable:
            proxy_str = f"{host}:{port}"
            try:
                subprocess.run(["netsh", "winhttp", "set", "proxy", proxy_str],
                               check=False, creationflags=subprocess.CREATE_NO_WINDOW)
            except Exception:
                # netsh peut échouer selon les permissions
                pass
            try:
                subprocess.run(
                    ["setx", "HTTP_PROXY", f"http://{proxy_str}"], check=False, creationflags=subprocess.CREATE_NO_WINDOW)
                subprocess.run(
                    ["setx", "HTTPS_PROXY", f"http://{proxy_str}"], check=False, creationflags=subprocess.CREATE_NO_WINDOW)
            except Exception:
                pass
            try:
                import winreg
                key = winreg.OpenKey(
                    winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Internet Settings", 0, winreg.KEY_SET_VALUE)
                winreg.SetValueEx(key, "ProxyEnable", 0, winreg.REG_DWORD, 1)
                winreg.SetValueEx(key, "ProxyServer", 0,
                                  winreg.REG_SZ, proxy_str)
                winreg.CloseKey(key)
            except Exception as e:
                log(f"set_system_proxy windows registry fail: {e}")
            log(f"Proxy système configuré sur {proxy_str}")
        else:
            try:
                subprocess.run(["netsh", "winhttp", "reset", "proxy"],
                               check=False, creationflags=subprocess.CREATE_NO_WINDOW)
            except Exception:
                pass
            try:
                subprocess.run(["setx", "HTTP_PROXY", ""], check=False,
                               creationflags=subprocess.CREATE_NO_WINDOW)
                subprocess.run(["setx", "HTTPS_PROXY", ""], check=False,
                               creationflags=subprocess.CREATE_NO_WINDOW)
            except Exception:
                pass
            try:
                import winreg
                key = winreg.OpenKey(
                    winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Internet Settings", 0, winreg.KEY_SET_VALUE)
                winreg.SetValueEx(key, "ProxyEnable", 0, winreg.REG_DWORD, 0)
                winreg.SetValueEx(key, "ProxyServer", 0, winreg.REG_SZ, "")
                winreg.CloseKey(key)
            except Exception as e:
                log(f"set_system_proxy windows registry clear fail: {e}")
            log("Proxy système réinitialisé.")
    except Exception as e:
        log(f"Erreur set_system_proxy: {e}")

# === Helper relay (high-performance pass-through) ===


def _set_socket_opts_for_perf(sock):
    try:
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
        # Windows-specific keepalive tuning (optional)
        if platform.system().lower() == 'windows':
            # tuple: (on/off, keepalive_time_ms, keepalive_interval_ms)
            sock.ioctl(socket.SIO_KEEPALIVE_VALS, (1, 60000, 10000))
        try:
            sock.settimeout(SOCKET_IDLE_TIMEOUT)
        except Exception:
            pass
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
            except socket.timeout:
                break
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
    t1 = threading.Thread(target=_relay_worker,
                          args=(a_sock, b_sock), daemon=True)
    t2 = threading.Thread(target=_relay_worker,
                          args=(b_sock, a_sock), daemon=True)
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
    # ports VOIP/STUN/SIP autorisés
    VOIP_ALLOWED_PORTS = {80, 443, 3478, 5060, 5061}

    def _extract_hostname_from_path(self, path):
        try:
            parsed = urllib.parse.urlparse(path)
            return parsed.hostname
        except Exception:
            return None

    def do_CONNECT(self):
        host_port = self.path
        target_host, target_port = host_port.split(':', 1)
        target_port = int(target_port)
        hostname = target_host.lower() if target_host else None
        try:
            if current_resolver:
                current_resolver.maybe_reload_background()

            # Si whitelistée, bypass TOUTES les restrictions (ports, http flags, blocklist)
            try:
                if current_resolver and current_resolver.is_whitelisted(hostname):
                    log(f"✅ [WHITELIST BYPASS CONNECT] {hostname}:{target_port}")
                    # create connection and relay as usual without further checks
                    remote = socket.create_connection(
                        (target_host, target_port), timeout=10)
                    self.send_response(200, "Connection Established")
                    self.send_header('Connection', 'close')
                    self.end_headers()

                    conn = self.connection
                    _set_socket_opts_for_perf(conn)
                    _set_socket_opts_for_perf(remote)
                    try:
                        conn.settimeout(SOCKET_IDLE_TIMEOUT)
                        remote.settimeout(SOCKET_IDLE_TIMEOUT)
                    except Exception:
                        pass
                    conn.setblocking(True)
                    remote.setblocking(True)
                    full_duplex_relay(conn, remote)
                    return
            except Exception as e:
                # si check whitelist plante, on continue vers checks sécurisés plutôt que laisser tout passer
                log(
                    f"[WARN] whitelist check error in CONNECT for {hostname}: {e}")

            # blocage basé sur blocklist
            if block_enabled and current_resolver and current_resolver._is_blocked(hostname):
                log(f"🚫 [Proxy BLOCK HTTPS] {hostname}")
                self.send_error(403, "Bloqué par sécurité")
                return

            # Si la cible est whitelistée, bypass tous les contrôles
            if current_resolver and current_resolver.is_whitelisted(hostname):
                log(f"✅ [WHITELIST BYPASS CONNECT] {hostname}:{target_port}")
                try:
                    remote = socket.create_connection(
                        (target_host, target_port), timeout=10)
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

                # sinon on applique les règles normales
                if block_http_other_ports and target_port not in self.VOIP_ALLOWED_PORTS:
                    log(f"🚫 [Proxy BLOCK other port] {target_host}:{target_port}")
                    self.send_error(
                        403, "port non standard bloqué par sécurité")
                    return

            # Autorisation normale — établir tunnel
            log(f"✅ [Proxy ALLOW HTTPS] {hostname}")

            remote = socket.create_connection(
                (target_host, target_port), timeout=10)
            self.send_response(200, "Connection Established")
            self.send_header('Connection', 'close')
            self.end_headers()

            conn = self.connection
            _set_socket_opts_for_perf(conn)
            _set_socket_opts_for_perf(remote)
            try:
                conn.settimeout(SOCKET_IDLE_TIMEOUT)
                remote.settimeout(SOCKET_IDLE_TIMEOUT)
            except Exception:
                pass
            conn.setblocking(True)
            remote.setblocking(True)
            full_duplex_relay(conn, remote)

        except Exception as e:
            log(f"[Proxy CONNECT error] {e}")
            try:
                self.send_error(502, "Bad Gateway")
            except Exception:
                pass

    def _handle_http_method(self):
        if current_resolver:
            current_resolver.maybe_reload_background()

        hostname = self._extract_hostname_from_path(self.path)
        if not hostname:
            host_header = self.headers.get('Host', '')
            hostname = host_header.split(':', 1)[0] if host_header else None
        if hostname:
            hostname = hostname.lower().strip()

        # Centraliser la vérification whitelist via current_resolver
        is_whitelisted = False
        try:
            if current_resolver and current_resolver.is_whitelisted(hostname):
                is_whitelisted = True
        except Exception as e:
            log(
                f"_handle_http_method whitelist check error for {hostname}: {e}")

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

        try:
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
            hop_by_hop = {"proxy-connection", "connection", "keep-alive",
                          "transfer-encoding", "te", "trailers", "upgrade", "proxy-authorization"}
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

            header_lines = [
                line for line in header_lines if not line.lower().startswith('connection:')]
            header_lines.append("Connection: close")

            request_line = f"{self.command} {path_only} {self.request_version}\r\n"
            request_headers_raw = "\r\n".join(header_lines) + "\r\n\r\n"
            request_bytes = request_line.encode(
                'utf-8') + request_headers_raw.encode('utf-8')

            remote = socket.create_connection(
                (target_host, target_port), timeout=10)

            _set_socket_opts_for_perf(self.connection)
            _set_socket_opts_for_perf(remote)

            # Retirer timeout après connexion
            try:
                self.connection.settimeout(SOCKET_IDLE_TIMEOUT)
                remote.settimeout(SOCKET_IDLE_TIMEOUT)
            except Exception:
                pass
            self.connection.setblocking(True)
            remote.setblocking(True)

            try:
                remote.sendall(request_bytes)
            except Exception as e:
                log(f"[Proxy send headers error] {e}")
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

        except Exception as e:
            log(f"[Proxy forward error] {e}\n{traceback.format_exc()}")
            try:
                self.send_error(502, "Bad Gateway")
            except Exception:
                pass

    # raccourcis pour méthodes HTTP
    def do_GET(self): self._handle_http_method()
    def do_POST(self): self._handle_http_method()
    def do_PUT(self): self._handle_http_method()
    def do_DELETE(self): self._handle_http_method()
    def do_HEAD(self): self._handle_http_method()
    def log_message(self, format, *args): return  # silence


# === Log viewer (Tk, runs in a separate process) ===
def run_log_viewer():
    """
    Fenêtre Tk autonome qui recharge le fichier de log toutes les secondes.
    S'exécute dans un processus séparé pour éviter les problèmes de thread Tk.
    """
    try:
        os.makedirs(USER_CFG_DIR, exist_ok=True)
    except Exception:
        pass

    win = tk.Tk()
    win.title("Calm Web - Log (auto-refresh)")
    win.geometry("780x440")
    text_area = ScrolledText(win, wrap=tk.WORD)
    text_area.pack(expand=True, fill='both')
    text_area.config(state='disabled')

    def refresh():
        try:
            with open(LOG_FILE_PATH, 'r', encoding='utf-8', errors='ignore') as lf:
                content = lf.read()
        except Exception as ex:
            content = f"Impossible de lire le log ({LOG_FILE_PATH}): {ex}"
        try:
            text_area.config(state='normal')
            text_area.delete(1.0, tk.END)
            text_area.insert(tk.END, content)
            text_area.see(tk.END)
            text_area.config(state='disabled')
        except Exception:
            pass
        win.after(1000, refresh)

    refresh()
    try:
        win.mainloop()
    except Exception:
        pass


def show_log_window():
    """
    Lance un sous-processus dédié avec l'option --log-viewer pour afficher le log live en Tk.
    """
    try:
        if getattr(sys, 'frozen', False):
            cmd = [sys.executable, "--log-viewer"]
        else:
            cmd = [sys.executable, os.path.abspath(__file__), "--log-viewer"]
        creationflags = 0
        if platform.system().lower() == 'windows' and hasattr(subprocess, "CREATE_NO_WINDOW"):
            creationflags = subprocess.CREATE_NO_WINDOW
        subprocess.Popen(cmd, creationflags=creationflags)
        log("Ouverture de la fenêtre de log...")
    except Exception as e:
        log(f"Impossible d'ouvrir la fenêtre de log : {e}")


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


def open_config_in_editor(path):
    """
    Ouvre le fichier de config dans le Bloc-notes (non bloquant).
    """
    try:
        if not os.path.exists(path):
            log(f"custom.cfg absent, création avant ouverture : {path}")
            write_default_custom_cfg(
                path, manual_blocked_domains, whitelisted_domains)
        # lancer Notepad sur thread séparé pour ne pas bloquer UI

        def _open():
            try:
                if platform.system().lower() == 'windows':
                    subprocess.Popen(['notepad.exe', path])
                else:
                    # fallback pour non-windows : essayer nano via cmd ou simplement ouvrir via os.startfile si disponible
                    if hasattr(os, "startfile"):
                        os.startfile(path)
                    else:
                        subprocess.Popen(
                            ['xdg-open', path], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            except Exception as e:
                log(f"Erreur ouverture éditeur pour {path} : {e}")
        threading.Thread(target=_open, daemon=True).start()
        log(f"Ouverture du fichier de configuration : {path}")
    except Exception as e:
        log(f"Erreur ouverture éditeur pour {path} : {e}")


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

        global current_resolver
        if current_resolver:
            # Lancer les deux rechargements (blocklist + whitelist) en parallèle
            threading.Thread(
                target=current_resolver._load_blocklist, daemon=True).start()
            threading.Thread(
                target=current_resolver._load_whitelist, daemon=True).start()
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
            MenuItem(f"Calm Web v{calmweb_version}",
                     lambda: None, enabled=False),
            MenuItem(
                f"🔒 Blocage: {'✅ Activé' if block_enabled else '❌ Désactivé'}", lambda: None, enabled=False),
            MenuItem(
                "❌ Désactiver le Blocage" if block_enabled else "✅ Activer le Blocage", toggle_block),
            MenuItem("⚙️ Config", Menu(
                MenuItem("✏️ Ouvrir / Éditer la config", lambda icon, item: threading.Thread(
                    target=open_config_in_editor, args=(get_custom_cfg_path(INSTALL_DIR),), daemon=True).start()),
                MenuItem("🔄 Recharger la config", reload_config_action)
            )),
            MenuItem("📄 Afficher le Log", lambda: threading.Thread(
                target=show_log_window, daemon=True).start()),
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

        global proxy_server, proxy_server_thread
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


class LimitedThreadingHTTPServer(ThreadingHTTPServer):
    """
    ThreadingHTTPServer avec limite de connexions actives via sémaphore.
    Empêche la croissance infinie du nombre de threads si des clients restent ouverts.
    """
    daemon_threads = True

    def process_request(self, request, client_address):
        acquired = _CONNECTION_SEMAPHORE.acquire(blocking=False)
        if not acquired:
            try:
                request.shutdown(socket.SHUT_RDWR)
            except Exception:
                pass
            try:
                request.close()
            except Exception:
                pass
            log("❌ Trop de connexions actives, requête refusée.")
            return
        return super().process_request(request, client_address)

    def process_request_thread(self, request, client_address):
        try:
            super().process_request_thread(request, client_address)
        finally:
            _CONNECTION_SEMAPHORE.release()


def start_proxy_server(bind_ip=PROXY_BIND_IP, port=PROXY_PORT):
    """
    Démarre ThreadingHTTPServer et retourne l'objet serveur; renvoie None en cas d'erreur.
    """
    global proxy_server, proxy_server_thread
    try:
        server = LimitedThreadingHTTPServer((bind_ip, port), BlockProxyHandler)
        proxy_server = server
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        proxy_server_thread = thread
        thread.start()
        log(f"Proxy HTTP(S) démarré sur {bind_ip}:{port}")
        return server
    except Exception as e:
        log(f"Erreur démarrage proxy: {e}")
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
    cfg_path = ensure_custom_cfg_exists(
        INSTALL_DIR, manual_blocked_domains, whitelisted_domains)

    # Copier le script/exe
    try:
        current_file = sys.argv[0] if getattr(
            sys, 'frozen', False) else os.path.abspath(__file__)
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
        try:
            with tempfile.NamedTemporaryFile(delete=False, mode='w', encoding='utf-16') as tmp_file:
                tmp_file.write(xml_content_inner)
                tmp_file_path = tmp_file.name
            if os.path.exists(tmp_file_path):
                try:
                    subprocess.run(
                        ["schtasks", "/Create", "/tn", "CalmWeb", "/XML", tmp_file_path, "/F"], check=True)
                    log(f"Tâche planifiée ajoutée avec succès.")
                except subprocess.CalledProcessError as e:
                    log(f"Erreur lors de l'ajout de la tâche planifiée : {e}")
                except Exception as e:
                    log(f"Erreur inattendue schtasks: {e}")
            else:
                log(
                    f"Erreur : le fichier XML temporaire n'a pas pu être créé à {tmp_file_path}")
        except Exception as e:
            log(f"Erreur add_task_from_xml: {e}")
        finally:
            try:
                if 'tmp_file_path' in locals() and os.path.exists(tmp_file_path):
                    os.remove(tmp_file_path)
            except Exception:
                pass

    add_task_from_xml(xml_content)

    # Lancer l'exe copié (si possible)
    try:
        target_file = os.path.join(INSTALL_DIR, EXE_NAME)
        if platform.system().lower() == 'windows':
            try:
                os.startfile(target_file)
                log("Installation terminée - Calm Web démarré")
            except Exception as e:
                log(
                    f"Impossible de démarrer automatiquement {target_file} : {e}")
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
    global current_resolver, proxy_server
    try:
        cfg_path = ensure_custom_cfg_exists(
            INSTALL_DIR, manual_blocked_domains, whitelisted_domains)
        load_custom_cfg_to_globals(cfg_path)
    except Exception as e:
        log(f"Erreur chargement config initiale: {e}")

    try:
        resolver = BlocklistResolver(get_blocklist_urls(), RELOAD_INTERVAL)
        current_resolver = resolver
    except Exception as e:
        log(f"Erreur création resolver: {e}")

    try:
        start_proxy_server(PROXY_BIND_IP, PROXY_PORT)
    except Exception as e:
        log(f"Erreur démarrage serveur proxy: {e}")

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


def main():
    """
    Mécanisme auto-restart pour fiabilité maximale
    """
    if "--log-viewer" in sys.argv:
        run_log_viewer()
        return
    restart_count = 0
    max_restarts = 5

    while restart_count < max_restarts:
        try:
            log(f"🚀 Démarrage CalmWeb (tentative {restart_count + 1})")

            exe_name = os.path.basename(sys.argv[0]).lower()
            if exe_name == "calmweb_installer.exe":
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
    main()

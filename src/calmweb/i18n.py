"""Lightweight bilingual (FR/EN) string table for the CalmWeb user interface.

The application ships in French by default because that is its primary
audience, but every user-facing string in the GUI and the tray menu goes
through :func:`t` so the language can be switched at runtime.

Usage::

    from .i18n import t
    label = t("status.protected")

The active language is stored in :data:`calmweb.config.language` and is
persisted to ``custom.cfg`` like any other option.
"""

from __future__ import annotations

import contextlib
import locale
import os
import threading

_LOCK = threading.RLock()

SUPPORTED: tuple[str, ...] = ("fr", "en")
DEFAULT_LANGUAGE: str = "fr"

_current: str = DEFAULT_LANGUAGE
_listeners: list = []


# ---------------------------------------------------------------------------
# String table
# ---------------------------------------------------------------------------

STRINGS: dict[str, dict[str, str]] = {
    # -- generic -----------------------------------------------------------
    "app.name": {"fr": "Calm Web", "en": "Calm Web"},
    "common.on": {"fr": "Activé", "en": "Enabled"},
    "common.off": {"fr": "Désactivé", "en": "Disabled"},
    "common.yes": {"fr": "Oui", "en": "Yes"},
    "common.no": {"fr": "Non", "en": "No"},
    "common.save": {"fr": "Enregistrer", "en": "Save"},
    "common.saved": {"fr": "Enregistré", "en": "Saved"},
    "common.cancel": {"fr": "Annuler", "en": "Cancel"},
    "common.close": {"fr": "Fermer", "en": "Close"},
    "common.reload": {"fr": "Recharger", "en": "Reload"},
    "common.clear": {"fr": "Effacer", "en": "Clear"},
    "common.export": {"fr": "Exporter", "en": "Export"},
    "common.unknown": {"fr": "inconnu", "en": "unknown"},
    "common.never": {"fr": "jamais", "en": "never"},
    "common.loading": {"fr": "chargement…", "en": "loading…"},
    "common.copy": {"fr": "Copier", "en": "Copy"},
    "common.search": {"fr": "Rechercher", "en": "Search"},
    # -- window / tabs -----------------------------------------------------
    "win.title": {"fr": "Calm Web — Tableau de bord", "en": "Calm Web — Dashboard"},
    "tab.status": {"fr": "État", "en": "Status"},
    "tab.activity": {"fr": "Activité", "en": "Activity"},
    "tab.settings": {"fr": "Paramètres", "en": "Settings"},
    "tab.lists": {"fr": "Listes", "en": "Lists"},
    "tab.about": {"fr": "À propos", "en": "About"},
    # -- status ------------------------------------------------------------
    "status.protected": {"fr": "Navigation protégée", "en": "Browsing protected"},
    "status.unprotected": {"fr": "Protection désactivée", "en": "Protection disabled"},
    "status.starting": {"fr": "Démarrage en cours…", "en": "Starting up…"},
    "status.sub.protected": {
        "fr": "Le filtre est actif : les sites publicitaires, malveillants et de télémétrie sont bloqués.",
        "en": "The filter is active: advertising, malicious and telemetry sites are blocked.",
    },
    "status.sub.unprotected": {
        "fr": "Votre navigation n'est pas filtrée. Aucun site n'est bloqué.",
        "en": "Your browsing is not filtered. No site is being blocked.",
    },
    "status.sub.starting": {
        "fr": "Téléchargement des listes de filtrage en cours…",
        "en": "Downloading the filter lists…",
    },
    "status.enable": {"fr": "Activer la protection", "en": "Enable protection"},
    "status.disable": {"fr": "Désactiver la protection", "en": "Disable protection"},
    "status.card.blocked": {"fr": "Bloqués", "en": "Blocked"},
    "status.card.allowed": {"fr": "Autorisés", "en": "Allowed"},
    "status.card.domains": {"fr": "Domaines filtrés", "en": "Filtered domains"},
    "status.card.uptime": {"fr": "Actif depuis", "en": "Running for"},
    "status.detail.title": {"fr": "Détails techniques", "en": "Technical details"},
    "status.detail.proxy": {"fr": "Proxy local", "en": "Local proxy"},
    "status.detail.lists": {"fr": "Listes de blocage", "en": "Blocklists"},
    "status.detail.whitelist": {"fr": "Liste blanche", "en": "Whitelist"},
    "status.detail.lastreload": {"fr": "Dernière mise à jour", "en": "Last refresh"},
    "status.detail.connections": {"fr": "Connexions actives", "en": "Active connections"},
    "status.detail.http": {"fr": "Versions HTTP", "en": "HTTP versions"},
    "status.http.value": {
        "fr": "HTTP/1.1 filtré · HTTP/2 et HTTP/3 relayés dans le tunnel TLS",
        "en": "HTTP/1.1 filtered · HTTP/2 and HTTP/3 relayed inside the TLS tunnel",
    },
    "status.refresh": {"fr": "Mettre à jour les listes", "en": "Refresh the lists"},
    # -- activity ----------------------------------------------------------
    "activity.filter.all": {"fr": "Tout", "en": "All"},
    "activity.filter.blocked": {"fr": "Bloqués", "en": "Blocked"},
    "activity.filter.allowed": {"fr": "Autorisés", "en": "Allowed"},
    "activity.filter.system": {"fr": "Système", "en": "System"},
    "activity.search": {"fr": "Filtrer par domaine…", "en": "Filter by domain…"},
    "activity.autoscroll": {"fr": "Suivre l'activité", "en": "Follow activity"},
    "activity.empty": {"fr": "Aucune activité pour le moment.", "en": "No activity yet."},
    "activity.export.done": {"fr": "Journal exporté vers :", "en": "Log exported to:"},
    "activity.count": {"fr": "{n} événement(s)", "en": "{n} event(s)"},
    "activity.reason.blocklist": {
        "fr": "liste noire téléchargée",
        "en": "downloaded blocklist",
    },
    "activity.reason.manual": {"fr": "votre liste noire", "en": "your blocklist"},
    "activity.reason.whitelist": {"fr": "liste blanche", "en": "whitelist"},
    "activity.reason.http": {"fr": "HTTP non sécurisé", "en": "insecure HTTP"},
    "activity.reason.port": {"fr": "port non standard", "en": "non-standard port"},
    "activity.reason.ip": {"fr": "adresse IP directe", "en": "direct IP address"},
    "activity.reason.invalid": {"fr": "requête invalide", "en": "invalid request"},
    "activity.reason.revocation": {
        "fr": "révocation de certificat",
        "en": "certificate revocation",
    },
    # -- block page --------------------------------------------------------
    "block.page.title": {"fr": "Site bloqué", "en": "Site blocked"},
    "block.page.note": {
        "fr": "Si vous pensez que ce site est légitime, ajoutez-le à la liste blanche",
        "en": "If you believe this site is legitimate, add it to the whitelist",
    },
    # -- settings ----------------------------------------------------------
    "settings.protection": {"fr": "Règles de filtrage", "en": "Filtering rules"},
    "settings.block_http_traffic": {
        "fr": "Bloquer la navigation HTTP non sécurisée",
        "en": "Block insecure HTTP browsing",
    },
    "settings.block_http_traffic.help": {
        "fr": "Force l'utilisation de HTTPS. Recommandé.",
        "en": "Forces the use of HTTPS. Recommended.",
    },
    "settings.block_ip_direct": {
        "fr": "Bloquer l'accès direct aux adresses IP",
        "en": "Block direct access to IP addresses",
    },
    "settings.block_ip_direct.help": {
        "fr": "Empêche de contourner le filtre en tapant une adresse IP.",
        "en": "Prevents bypassing the filter by typing a raw IP address.",
    },
    "settings.block_http_other_ports": {
        "fr": "Bloquer les ports non standards",
        "en": "Block non-standard ports",
    },
    "settings.block_http_other_ports.help": {
        "fr": "À désactiver si un bac à sable ou un logiciel métier ne fonctionne plus.",
        "en": "Turn off if a sandbox or business application stops working.",
    },
    "settings.notify_on_block": {
        "fr": "Prévenir par une notification quand un site est bloqué",
        "en": "Show a notification when a site is blocked",
    },
    "settings.notify_on_block.help": {
        "fr": "Un site bloqué en HTTPS n'affiche pas la page de blocage : le navigateur "
        "montre seulement une erreur de connexion. La notification indique le domaine et "
        "la règle. Les blocages répétés sont regroupés.",
        "en": "A site blocked over HTTPS cannot show the block page; the browser only "
        "shows a connection error. The notification names the domain and the rule. "
        "Repeated blocks are grouped together.",
    },
    "settings.interface": {"fr": "Interface", "en": "Interface"},
    "settings.language": {"fr": "Langue", "en": "Language"},
    "settings.theme": {"fr": "Thème", "en": "Theme"},
    "settings.theme.system": {"fr": "Système", "en": "System"},
    "settings.theme.light": {"fr": "Clair", "en": "Light"},
    "settings.theme.dark": {"fr": "Sombre", "en": "Dark"},
    "settings.advanced": {"fr": "Avancé", "en": "Advanced"},
    "settings.openfile": {
        "fr": "Ouvrir le fichier de configuration",
        "en": "Open the configuration file",
    },
    "settings.reloadlists": {
        "fr": "Recharger listes et configuration",
        "en": "Reload lists and configuration",
    },
    "settings.applied": {
        "fr": "Modifications enregistrées et appliquées.",
        "en": "Changes saved and applied.",
    },
    "settings.restart_hint": {
        "fr": "Certains sites gardent des connexions ouvertes : en cas de doute, "
        "fermez puis rouvrez votre navigateur.",
        "en": "Some sites keep connections open: if in doubt, close and reopen your browser.",
    },
    # -- lists -------------------------------------------------------------
    "lists.lookup.title": {"fr": "Vérifier un domaine", "en": "Check a domain"},
    "lists.lookup.placeholder": {"fr": "exemple.com", "en": "example.com"},
    "lists.lookup.button": {"fr": "Vérifier", "en": "Check"},
    "lists.lookup.blocked": {"fr": "{d} est BLOQUÉ ({src})", "en": "{d} is BLOCKED ({src})"},
    "lists.lookup.allowed": {"fr": "{d} est autorisé ({src})", "en": "{d} is allowed ({src})"},
    "lists.lookup.src.downloaded": {
        "fr": "listes téléchargées",
        "en": "downloaded lists",
    },
    "lists.lookup.src.manual": {"fr": "votre liste noire", "en": "your blocklist"},
    "lists.lookup.src.whitelist": {"fr": "votre liste blanche", "en": "your whitelist"},
    "lists.lookup.src.parent": {"fr": "via le domaine parent {p}", "en": "via parent domain {p}"},
    "lists.lookup.src.none": {"fr": "aucune liste", "en": "no list"},
    "lists.lookup.src.ip": {"fr": "adresse IP directe", "en": "direct IP address"},
    "lists.lookup.hint.downloaded": {
        "fr": "Ce domaine vient des listes téléchargées, pas de votre configuration : "
        "le retirer de votre liste noire ne change rien. Pour y accéder, ajoutez-le "
        "à la liste blanche.",
        "en": "This domain comes from the downloaded lists, not from your configuration: "
        "removing it from your blocklist changes nothing. To reach it, add it to the "
        "whitelist.",
    },
    "lists.lookup.hint.manual": {
        "fr": "Ce domaine vient de votre liste noire ci-dessous : retirez-le puis "
        "enregistrez.",
        "en": "This domain comes from your own blocklist below: remove it and save.",
    },
    "lists.lookup.hint.ip": {
        "fr": "Les adresses IP directes sont bloquées par la règle « Bloquer l'accès "
        "direct aux adresses IP » (Paramètres).",
        "en": "Direct IP addresses are blocked by the \"Block direct access to IP "
        "addresses\" rule (Settings).",
    },
    "lists.lookup.allow": {"fr": "Autoriser ce site", "en": "Allow this site"},
    "lists.lookup.allowed_now": {
        "fr": "{d} est maintenant autorisé. Si le site reste bloqué, fermez puis "
        "rouvrez votre navigateur.",
        "en": "{d} is now allowed. If the site stays blocked, close and reopen your "
        "browser.",
    },
    "lists.lookup.remove_local": {
        "fr": "Retirer de ma liste noire",
        "en": "Remove from my blocklist",
    },
    "lists.lookup.removed_local": {
        "fr": "{d} a été retiré de votre liste noire.",
        "en": "{d} was removed from your blocklist.",
    },
    "lists.whitelist.title": {"fr": "Sites toujours autorisés", "en": "Always-allowed sites"},
    "lists.whitelist.help": {
        "fr": "Un domaine par ligne. Ces sites échappent à toutes les restrictions.",
        "en": "One domain per line. These sites bypass every restriction.",
    },
    "lists.sources.title": {
        "fr": "Listes téléchargées (sources)",
        "en": "Downloaded lists (sources)",
    },
    "lists.sources.block.help": {
        "fr": "Une URL par ligne, téléchargée dans cet ordre à chaque mise à jour. "
        "Formats acceptés : hosts, domaines bruts, Adblock/AdGuard DNS, dnsmasq, CSV. "
        "Videz la zone pour ne rien télécharger.",
        "en": "One URL per line, downloaded in this order at every refresh. Accepted "
        "formats: hosts files, plain domain lists, Adblock/AdGuard DNS, dnsmasq, CSV. "
        "Empty the box to download nothing.",
    },
    "lists.sources.whitelist.help": {
        "fr": "Sources de la liste blanche. Elle a toujours priorité sur les listes noires.",
        "en": "Whitelist sources. The whitelist always wins over the blocklists.",
    },
    "lists.sources.reset": {
        "fr": "Rétablir les sources par défaut",
        "en": "Restore the default sources",
    },
    "lists.sources.dropped": {
        "fr": "{n} ligne(s) ignorée(s) : une source doit être une URL http://, https:// ou file://",
        "en": "{n} line(s) ignored: a source must be an http://, https:// or file:// URL",
    },
    "lists.blocklist.title": {"fr": "Sites toujours bloqués", "en": "Always-blocked sites"},
    "lists.blocklist.help": {
        "fr": "Un domaine par ligne, en plus des listes téléchargées.",
        "en": "One domain per line, in addition to the downloaded lists.",
    },
    # -- about -------------------------------------------------------------
    "about.version": {"fr": "Version installée", "en": "Installed version"},
    "about.check": {"fr": "Rechercher une mise à jour", "en": "Check for updates"},
    "about.checking": {"fr": "Vérification…", "en": "Checking…"},
    "about.uptodate": {"fr": "Calm Web est à jour.", "en": "Calm Web is up to date."},
    "about.project": {"fr": "Page du projet", "en": "Project page"},
    "about.configfile": {"fr": "Fichier de configuration", "en": "Configuration file"},
    "about.disclaimer": {
        "fr": "Calm Web n'est pas un antivirus et ne garantit pas une protection totale. "
        "Il réduit les risques en bloquant des techniques connues.",
        "en": "Calm Web is not an antivirus and does not guarantee total protection. "
        "It reduces risk by blocking known techniques.",
    },
    # -- tray --------------------------------------------------------------
    "tray.open": {"fr": "Ouvrir Calm Web", "en": "Open Calm Web"},
    "tray.activity": {"fr": "Afficher l'activité", "en": "Show activity"},
    "tray.settings": {"fr": "Paramètres", "en": "Settings"},
    "tray.config": {"fr": "Configuration", "en": "Configuration"},
    "tray.edit": {"fr": "Éditer le fichier", "en": "Edit the file"},
    "tray.reload": {"fr": "Recharger listes et configuration", "en": "Reload lists and settings"},
    "tray.update": {"fr": "Rechercher une mise à jour", "en": "Check for updates"},
    "tray.quit": {"fr": "Quitter", "en": "Quit"},
    "tray.state": {"fr": "Filtrage : {state}", "en": "Filtering: {state}"},
    "tray.counters": {"fr": "{b} bloqués · {a} autorisés", "en": "{b} blocked · {a} allowed"},
    "tray.tooltip.on": {
        "fr": "Calm Web — protection active ({b} bloqués)",
        "en": "Calm Web — protection active ({b} blocked)",
    },
    "tray.tooltip.off": {
        "fr": "Calm Web — protection désactivée",
        "en": "Calm Web — protection disabled",
    },
    # -- updates -----------------------------------------------------------
    "update.title": {"fr": "Mise à jour de Calm Web", "en": "Calm Web update"},
    "update.available": {
        "fr": "Une nouvelle version est disponible !",
        "en": "A new version is available!",
    },
    "update.current": {"fr": "Version actuelle", "en": "Current version"},
    "update.new": {"fr": "Nouvelle version", "en": "New version"},
    "update.size": {"fr": "Taille du téléchargement", "en": "Download size"},
    "update.notes": {"fr": "Nouveautés", "en": "What's new"},
    "update.question": {"fr": "Souhaitez-vous mettre à jour ?", "en": "Do you want to update?"},
    "update.downloading": {"fr": "Téléchargement de Calm Web {v}…", "en": "Downloading Calm Web {v}…"},
    "update.failed": {"fr": "Échec de la mise à jour : {e}", "en": "Update failed: {e}"},
    "update.uptodate": {"fr": "Application à jour !", "en": "Application is up to date!"},
    # -- misc --------------------------------------------------------------
    "alert.already_running": {
        "fr": "Calm Web est déjà en cours d'exécution.",
        "en": "Calm Web is already running.",
    },
    "notify.blocked.title": {"fr": "Connexion bloquée", "en": "Connection blocked"},
    "notify.blocked.more": {
        "fr": "{host} et {n} autre(s) domaine(s)",
        "en": "{host} and {n} more domain(s)",
    },
    "notify.loopback.title": {
        "fr": "Applications Microsoft sans accès au proxy",
        "en": "Microsoft apps cannot reach the proxy",
    },
    "notify.loopback.body": {
        "fr": "Windows empêche {n} application(s) isolée(s) — nouvel Outlook, Teams, "
        "connexion Microsoft — de joindre le proxy : elles resteront sans réseau. "
        "Relancez Calm Web en tant qu'administrateur.",
        "en": "Windows is stopping {n} isolated app(s) — new Outlook, Teams, Microsoft "
        "sign-in — from reaching the proxy: they will have no network at all. "
        "Restart Calm Web as administrator.",
    },
}


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def detect_system_language() -> str:
    """Return ``"fr"`` or ``"en"`` based on the operating-system locale."""
    with contextlib.suppress(Exception):
        tag = ""
        try:  # Windows gives the most reliable answer here
            import ctypes

            buf = ctypes.create_unicode_buffer(85)
            if ctypes.windll.kernel32.GetUserDefaultLocaleName(buf, 85):  # type: ignore[attr-defined]
                tag = buf.value or ""
        except Exception:
            tag = ""
        if not tag:
            for name in ("LC_ALL", "LC_MESSAGES", "LANG", "LANGUAGE"):
                value = os.environ.get(name)
                if value:
                    tag = value.split(":")[0].split(".")[0]
                    break
        if not tag:
            with contextlib.suppress(Exception):
                tag = locale.getlocale()[0] or ""
        tag = tag.replace("_", "-").lower()
        if tag.startswith("fr"):
            return "fr"
        if tag:
            return "en"
    return DEFAULT_LANGUAGE


def normalize(lang: str | None) -> str:
    """Coerce *lang* to a supported language code."""
    if not lang:
        return DEFAULT_LANGUAGE
    code = str(lang).strip().lower()[:2]
    return code if code in SUPPORTED else DEFAULT_LANGUAGE


def get_language() -> str:
    """Return the active language code."""
    with _LOCK:
        return _current


def set_language(lang: str | None) -> str:
    """Set the active language and notify listeners. Returns the applied code."""
    global _current
    code = normalize(lang)
    with _LOCK:
        changed = code != _current
        _current = code
        listeners = list(_listeners)
    if changed:
        for callback in listeners:
            with contextlib.suppress(Exception):
                callback(code)
    return code


def on_language_change(callback) -> None:
    """Register *callback(lang)* to run whenever the language changes."""
    with _LOCK:
        if callback not in _listeners:
            _listeners.append(callback)


def off_language_change(callback) -> None:
    """Unregister a previously registered listener."""
    with _LOCK, contextlib.suppress(ValueError):
        _listeners.remove(callback)


def t(key: str, **kwargs: object) -> str:
    """Translate *key* into the active language.

    Unknown keys return the key itself so a missing translation is visible
    but never crashes the interface.  ``kwargs`` are applied with
    :meth:`str.format`.
    """
    entry = STRINGS.get(key)
    if entry is None:
        return key
    text = entry.get(get_language()) or entry.get(DEFAULT_LANGUAGE) or key
    if kwargs:
        with contextlib.suppress(Exception):
            return text.format(**kwargs)
    return text

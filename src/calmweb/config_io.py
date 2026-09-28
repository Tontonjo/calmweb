"""CalmWeb configuration file I/O and red-flag domain helpers.

Functions that read/write custom.cfg and manage the red-flag-domains cache.
Delegates low-level cfg parsing/writing to parser.py.
"""

from __future__ import annotations

import os
import sys
from datetime import datetime

import urllib3

from . import config
from .log import log
from .net import make_pool_manager
from .parser import as_bool, parse_cfg_file, write_cfg_file

# ===================================================================
# Custom config file handling
# ===================================================================


def get_custom_cfg_path(install_dir: str | None = None) -> str:
    """Return the path to custom.cfg.

    Priority: APPDATA dir > install_dir > directory of the running executable.
    """
    if config.USER_CFG_DIR:
        return config.USER_CFG_PATH
    if install_dir and os.path.isdir(install_dir):
        return os.path.join(install_dir, config.CUSTOM_CFG_NAME)
    return os.path.join(os.path.dirname(os.path.abspath(sys.argv[0])), config.CUSTOM_CFG_NAME)


#: On/off options, with the value used for a fresh custom.cfg.
BOOL_OPTIONS: dict[str, bool] = {
    # The protection itself.  On for a fresh installation.  Saved on every
    # toggle, but forced back on at each launch (see __main__), so a manual
    # "off" never outlives a restart or reboot.
    "block_enabled": True,
    "block_ip_direct": True,
    "block_http_traffic": True,
    "block_http_other_ports": True,
    # Deliberately absent from the window and the tray menu: an escape
    # hatch for diagnosis, not a choice to put in front of the user.
    "allow_revocation_http": True,
    # Also absent from the interface: answered by the UAC prompt itself.
    "ask_elevation": True,
    "notify_on_block": False,
}

#: Free-text options, with their default value.
TEXT_OPTIONS: dict[str, str] = {
    "language": "",  # empty = follow the operating-system language
    "theme": "system",
}

# Default options written into a fresh custom.cfg
_DEFAULT_OPTIONS: dict[str, object] = {**BOOL_OPTIONS, **TEXT_OPTIONS}


def current_sources() -> tuple[list[str], list[str]]:
    """Return the source lists currently in effect, ready to be written back."""
    with config._CONFIG_LOCK:
        return list(config.blocklist_source_urls), list(config.whitelist_source_urls)


def default_sources() -> tuple[list[str], list[str]]:
    """Return a fresh copy of the built-in source lists."""
    return (
        list(config.DEFAULT_BLOCKLIST_SOURCE_URLS),
        list(config.DEFAULT_WHITELIST_SOURCE_URLS),
    )


def read_bool_option(key: str) -> bool:
    """Read one boolean option straight from custom.cfg, ahead of the full load.

    The elevation question has to be settled before anything else happens --
    before the single-instance lock above all, since an elevated copy of
    CalmWeb would collide with a lock the unprivileged one is still holding.
    That is earlier than the configuration is normally read, so this reads the
    one key it needs and leaves the rest alone.
    """
    default = bool(BOOL_OPTIONS.get(key, False))
    try:
        data = parse_cfg_file(get_custom_cfg_path(config.INSTALL_DIR))
        if key in data.options:
            return as_bool(data.options[key], default)
    except Exception as e:
        log(f"read_bool_option({key}): {e}")
    return default


def current_options() -> dict[str, object]:
    """Return the options currently in effect, ready to be written back."""
    options: dict[str, object] = {}
    for key in BOOL_OPTIONS:
        options[key] = bool(getattr(config, key, BOOL_OPTIONS[key]))
    for key, default in TEXT_OPTIONS.items():
        options[key] = str(getattr(config, key, default) or default)
    return options


def write_default_custom_cfg(
    path: str,
    blocked_set: set[str],
    whitelist_set: set[str],
) -> None:
    """Write a default custom.cfg file. Never raises."""
    block_sources, whitelist_sources = default_sources()
    write_cfg_file(
        path,
        blocked_set,
        whitelist_set,
        dict(_DEFAULT_OPTIONS),
        block_sources,
        whitelist_sources,
    )


def save_custom_cfg(
    path: str | None = None,
    blocked_set: set[str] | None = None,
    whitelist_set: set[str] | None = None,
    options: dict[str, object] | None = None,
    block_sources: list[str] | None = None,
    whitelist_sources: list[str] | None = None,
) -> str:
    """Persist the current (or supplied) settings and lists to custom.cfg.

    Used by the dashboard's *Save* buttons.  Returns the path written.
    """
    target = path or get_custom_cfg_path(config.INSTALL_DIR)
    with config._CONFIG_LOCK:
        blocked = set(blocked_set if blocked_set is not None else config.manual_blocked_domains)
        whitelist = set(
            whitelist_set if whitelist_set is not None else config.whitelisted_domains
        )
    live_block_sources, live_whitelist_sources = current_sources()
    write_cfg_file(
        target,
        blocked,
        whitelist,
        options or current_options(),
        block_sources if block_sources is not None else live_block_sources,
        whitelist_sources if whitelist_sources is not None else live_whitelist_sources,
    )
    return target


def apply_interface_options() -> None:
    """Push the interface options into the modules that consume them."""
    try:
        from .i18n import detect_system_language, normalize, set_language

        wanted = (config.language or "").strip().lower()
        set_language(normalize(wanted) if wanted else detect_system_language())
    except Exception as e:
        log(f"apply_interface_options: {e}")


def parse_custom_cfg(path: str) -> tuple[set[str], set[str]]:
    """Parse a custom.cfg file. Returns (blocked_set, whitelist_set).

    Tolerant to errors; also sets global option flags in config module.
    """
    # Reset to defaults so a removed line means "back to default"
    for key, default in BOOL_OPTIONS.items():
        setattr(config, key, default)
    for key, text_default in TEXT_OPTIONS.items():
        setattr(config, key, text_default)
    config.blocklist_source_urls, config.whitelist_source_urls = default_sources()

    data = parse_cfg_file(path)
    blocked, whitelist, options = data.blocked, data.whitelist, data.options

    # A missing section means the file predates editable sources, so the
    # defaults set above stand. A present but empty section is a choice and
    # is honoured as-is.
    if data.block_sources is not None:
        config.blocklist_source_urls = list(data.block_sources)
    if data.whitelist_sources is not None:
        config.whitelist_source_urls = list(data.whitelist_sources)

    for key, default in BOOL_OPTIONS.items():
        if key in options:
            setattr(config, key, as_bool(options[key], default))

    if "language" in options:
        config.language = str(options["language"]).strip().lower()[:2]
    if "theme" in options:
        theme = str(options["theme"]).strip().lower()
        config.theme = theme if theme in ("system", "light", "dark") else "system"

    apply_interface_options()

    if blocked or whitelist:
        log(
            f"custom.cfg chargé: {len(blocked)} blocked, {len(whitelist)} whitelisted, "
            f"Blocage IP={config.block_ip_direct}, Blocage HTTP={config.block_http_traffic}, "
            f"Ports alternatifs={config.block_http_other_ports}, "
            f"Révocation HTTP={config.allow_revocation_http}, "
            f"Notifications={config.notify_on_block}, "
            f"Sources={len(config.blocklist_source_urls)} noires / "
            f"{len(config.whitelist_source_urls)} blanches"
        )

    return blocked, whitelist


def ensure_custom_cfg_exists(
    install_dir: str,
    default_blocked: set[str],
    default_whitelist: set[str],
) -> str:
    """Ensure a custom.cfg exists (APPDATA preferred, then install_dir). Return its path."""
    try:
        if not os.path.isdir(config.USER_CFG_DIR):
            os.makedirs(config.USER_CFG_DIR, exist_ok=True)
        if not os.path.exists(config.USER_CFG_PATH):
            write_default_custom_cfg(config.USER_CFG_PATH, default_blocked, default_whitelist)
        return config.USER_CFG_PATH
    except Exception as e:
        log(f"Error in ensure_custom_cfg_exists (APPDATA): {e}")

    cfg_path = get_custom_cfg_path(install_dir)
    if not os.path.exists(cfg_path):
        try:
            write_default_custom_cfg(cfg_path, default_blocked, default_whitelist)
        except Exception as e:
            log(f"Error writing fallback custom.cfg {cfg_path}: {e}")
    return cfg_path


def load_custom_cfg_to_globals(path: str) -> tuple[set[str], set[str]]:
    """Load user config into global variables in config module.

    When the file exists the parsed sets are applied **as they are**, empty
    included.  Skipping the assignment for an empty section (as an earlier
    version did) makes it impossible to remove the last entry of a list: the
    previous set stays live and the domain keeps being blocked or allowed
    until the application is restarted.

    A missing or unreadable file leaves the current values untouched, so a
    transient read error cannot silently disable the user's own lists.
    """
    blocked, whitelist = parse_custom_cfg(path)
    if not os.path.exists(path):
        return config.manual_blocked_domains, config.whitelisted_domains

    with config._CONFIG_LOCK:
        config.manual_blocked_domains = blocked
        config.whitelisted_domains = whitelist
    return config.manual_blocked_domains, config.whitelisted_domains


# ===================================================================
# Red Flag Domains auto-update
# ===================================================================


def should_update_red_flag_domains() -> bool:
    """Check whether red.flag.domains needs updating (daily)."""
    try:
        if not os.path.exists(config.RED_FLAG_TIMESTAMP_PATH):
            return True

        with open(config.RED_FLAG_TIMESTAMP_PATH) as f:
            last_update_str = f.read().strip()

        last_update = datetime.fromisoformat(last_update_str)
        now = datetime.now()

        # Update if more than 24h elapsed or a new calendar day
        return (
            now - last_update
        ).total_seconds() > config.RED_FLAG_UPDATE_INTERVAL_SECS or now.date() > last_update.date()

    except Exception as e:
        log(f"Error checking red.flag.domains timestamp: {e}")
        return True


def download_red_flag_domains() -> bool:
    """Download and cache red.flag.domains locally."""
    try:
        log("📥 Téléchargement red.flag.domains...")

        # Create directory if needed
        os.makedirs(config.USER_CFG_DIR, exist_ok=True)

        # Download with urllib3
        http = make_pool_manager()
        response = http.request(
            "GET",
            config.RED_FLAG_DOMAINS_URL,
            timeout=urllib3.Timeout(
                connect=config.DOWNLOAD_TIMEOUT_CONNECT_SECS,
                read=config.DOWNLOAD_TIMEOUT_READ_SECS,
            ),
        )

        if response.status != 200:
            log(f"❌ Erreur de téléchargement red.flag.domains: HTTP {response.status}")
            return False

        # Save file
        with open(config.RED_FLAG_CACHE_PATH, "wb") as f:
            f.write(response.data)

        # Mark update timestamp
        with open(config.RED_FLAG_TIMESTAMP_PATH, "w") as f:
            f.write(datetime.now().isoformat())

        log(f"✅ red.flag.domains mis à jour ({len(response.data)} bytes)")
        return True

    except Exception as e:
        log(f"❌ Error downloading red.flag.domains: {e}")
        return False


def get_red_flag_domains_path() -> str:
    """Return the path to the red.flag.domains file (local cache or URL fallback)."""
    if should_update_red_flag_domains():
        download_red_flag_domains()

    # Use local cache if it exists
    if os.path.exists(config.RED_FLAG_CACHE_PATH):
        return f"file://{config.RED_FLAG_CACHE_PATH}"

    # Fallback to direct URL
    return config.RED_FLAG_DOMAINS_URL


def get_blocklist_urls() -> list[str]:
    """Return the blocklist URLs to download, in order.

    red.flag.domains is appended separately: it is cached and refreshed daily
    on its own schedule, so it is not one of the URLs the user edits.  When
    every source has been removed on purpose, nothing is appended either --
    an empty list has to stay empty.
    """
    sources = list(config.blocklist_source_urls)
    if not sources:
        return []
    return [*sources, get_red_flag_domains_path()]

"""CalmWeb configuration: constants, paths, and global runtime state."""

from __future__ import annotations

import os
import platform
import threading

# --- GitHub / Update ------------------------------------------------
GITHUB_REPO: str = "Tontonjo/calmweb"
GITHUB_RELEASES_URL: str = f"https://api.github.com/repos/{GITHUB_REPO}/releases/latest"
GITHUB_REPO_URL: str = f"https://github.com/{GITHUB_REPO}"

# ---------------------------------------------------------------------------
# Red Flag Domains
# ---------------------------------------------------------------------------

RED_FLAG_DOMAINS_URL: str = "https://dl.red.flag.domains/pihole/red.flag.domains.txt"
RED_FLAG_UPDATE_INTERVAL_SECS: int = 86400  # 24 hours

# ---------------------------------------------------------------------------
# Blocklist / whitelist source URLs
# ---------------------------------------------------------------------------

DEFAULT_BLOCKLIST_SOURCE_URLS: list[str] = [
    "https://raw.githubusercontent.com/StevenBlack/hosts/refs/heads/master/hosts",
    "https://raw.githubusercontent.com/easylist/listefr/refs/heads/master/hosts.txt",
    "https://raw.githubusercontent.com/hagezi/dns-blocklists/refs/heads/main/adblock/ultimate.txt",
    "https://raw.githubusercontent.com/Tontonjo/calmweb/refs/heads/main/filters/blocklist.txt",
    "https://urlhaus.abuse.ch/downloads/csv/",
]

DEFAULT_WHITELIST_SOURCE_URLS: list[str] = [
    "https://raw.githubusercontent.com/Tontonjo/calmweb/refs/heads/main/filters/whitelist.txt"
]

# The lists actually downloaded at each reload. They start as a copy of the
# defaults above and are replaced by the [BLOCK_SOURCES] / [WHITELIST_SOURCES]
# sections of custom.cfg when those are present, so a user can add a source,
# drop one they do not trust, or reorder them. An empty section means "none":
# it is a deliberate choice, distinct from an absent section, which restores
# the defaults.
blocklist_source_urls: list[str] = list(DEFAULT_BLOCKLIST_SOURCE_URLS)
whitelist_source_urls: list[str] = list(DEFAULT_WHITELIST_SOURCE_URLS)

# Default user-editable sets (overwritten by custom.cfg at runtime)
manual_blocked_domains: set[str] = {"add.blocked.domain"}
whitelisted_domains: set[str] = {"add.allowed.domain"}

# ---------------------------------------------------------------------------
# Timers and network
# ---------------------------------------------------------------------------

RELOAD_INTERVAL: int = 3600
PROXY_BIND_IP: str = "127.0.0.1"
PROXY_PORT: int = 8080

# ---------------------------------------------------------------------------
# Network timeouts (all values in seconds)
# ---------------------------------------------------------------------------

DOWNLOAD_TIMEOUT_CONNECT_SECS: float = 10.0
DOWNLOAD_TIMEOUT_READ_SECS: float = 30.0
BLOCKLIST_TIMEOUT_CONNECT_SECS: float = 5.0
BLOCKLIST_TIMEOUT_READ_SECS: float = 15.0
WHITELIST_TIMEOUT_CONNECT_SECS: float = 5.0
WHITELIST_TIMEOUT_READ_SECS: float = 10.0

# ---------------------------------------------------------------------------
# Proxy handler settings
# ---------------------------------------------------------------------------

PROXY_HANDLER_TIMEOUT_SECS: int = 10
PROXY_PROTOCOL_VERSION: str = "HTTP/1.1"
#: Ports a CONNECT tunnel may target: HTTP, HTTPS, and TURN over TCP
#: (3478), which browsers use to relay WebRTC calls through a proxy.
ALLOWED_CONNECT_PORTS: set[int] = {80, 443, 3478}

# ---------------------------------------------------------------------------
# Relay buffer size (bytes)
# ---------------------------------------------------------------------------

RELAY_BUFFER_SIZE_BYTES: int = 65536

#: How often an idle tunnel wakes to check on itself. Only used to notice that
#: a tunnel has gone quiet for TUNNEL_IDLE_TIMEOUT, so it can be generous:
#: every open tunnel is a thread, and hundreds of them waking every second
#: take the interpreter away from the accept loop for no benefit.
RELAY_POLL_INTERVAL_SECS: float = 5.0

# ---------------------------------------------------------------------------
# Tunnel lifetime
# ---------------------------------------------------------------------------

#: How long a CONNECT tunnel may stay completely idle before it is dropped.
#: HTTP/2 (and WebSocket) connections are deliberately kept open between
#: requests, so this has to be generous -- a short value silently breaks
#: long-polling, server-sent events and slow uploads. TCP keepalive still
#: detects peers that have really gone away, which is what actually reclaims
#: dead tunnels; this timeout is only a backstop against leaked sockets.
#:
#: Thirty minutes, because that is the floor Microsoft documents for any
#: firewall or proxy sitting in front of Exchange. Outlook keeps a MAPI/HTTP
#: notification channel open and deliberately silent between events, and the
#: previous ten minutes cut it mid-session: the mailbox stayed "connected"
#: while nothing arrived, which is the "not updated in a while" warning.
TUNNEL_IDLE_TIMEOUT: int = 1800

# ---------------------------------------------------------------------------
# Retry settings
# ---------------------------------------------------------------------------

DOWNLOAD_MAX_RETRIES: int = 3
DOWNLOAD_RETRY_BASE_DELAY_SECS: int = 1

# ---------------------------------------------------------------------------
# Socket connection timeout
# ---------------------------------------------------------------------------

SOCKET_CONNECT_TIMEOUT_SECS: int = 10

# ---------------------------------------------------------------------------
# Accept-loop watchdog
# ---------------------------------------------------------------------------

#: A dead accept loop is silent: the listening socket stays open, the tray
#: still says "active", and the operating system quietly drops every new
#: connection once the backlog fills. The client sees a SYN that is never
#: answered and retries until it times out -- which is what an application
#: reports as "cannot connect", with nothing in the proxy log to match.
#: The watchdog completes a real handshake on the listening port and puts the
#: server back on its feet when that stops working.
PROXY_HEALTHCHECK_INTERVAL_SECS: float = 15.0
PROXY_HEALTHCHECK_TIMEOUT_SECS: float = 3.0

#: Consecutive failed probes before the server is rebuilt. Two, so a single
#: unlucky moment (a burst filling the backlog) does not tear down a proxy
#: that is merely busy.
PROXY_HEALTHCHECK_FAILURES_BEFORE_RESTART: int = 2

# ---------------------------------------------------------------------------
# Resource / connection safety limits
# ---------------------------------------------------------------------------

MAX_BLOCKLIST_BYTES: int = 25 * 1024 * 1024  # skip downloads larger than this
MAX_PROXY_CONNECTIONS: int = 400  # cap concurrent proxy threads
SOCKET_IDLE_TIMEOUT: int = 90  # legacy: kept for compatibility, see TUNNEL_IDLE_TIMEOUT
MAX_BLOCKED_DOMAINS: int = 1_500_000  # guardrail to avoid unbounded memory

# ---------------------------------------------------------------------------
# Installation paths (Windows-specific paths are no-ops on other platforms)
# ---------------------------------------------------------------------------

INSTALL_DIR: str = r"C:\Program Files\CalmWeb" if platform.system() == "Windows" else ""
EXE_NAME: str = "calmweb.exe"
STARTUP_FOLDER: str = (
    os.getenv("APPDATA", "") + r"\Microsoft\Windows\Start Menu\Programs\Startup"
    if platform.system() == "Windows"
    else ""
)
CUSTOM_CFG_NAME: str = "custom.cfg"

# ---------------------------------------------------------------------------
# User config directory and derived paths
# ---------------------------------------------------------------------------

USER_CFG_DIR: str = os.path.join(os.getenv("APPDATA") or os.path.expanduser("~"), "CalmWeb")
USER_CFG_PATH: str = os.path.join(USER_CFG_DIR, CUSTOM_CFG_NAME)
RED_FLAG_CACHE_PATH: str = os.path.join(USER_CFG_DIR, "red_flag_domains.txt")
RED_FLAG_TIMESTAMP_PATH: str = os.path.join(USER_CFG_DIR, "red_flag_last_update.txt")

# ---------------------------------------------------------------------------
# Global runtime state
# ---------------------------------------------------------------------------

# Persisted in custom.cfg (see ``config_io.BOOL_OPTIONS``): a fresh
# installation starts with the protection on.  Switching it off only lasts
# until the next launch: __main__ turns it back on at every start (reboot).
block_enabled: bool = True

#: True while the protection is *paused* because no whitelist could be
#: downloaded -- a safety measure, not a decision by the user.  Kept apart
#: from ``block_enabled`` so the automatic resume, once a whitelist finally
#: loads, can never override someone who switched the protection off.
protection_paused_no_whitelist: bool = False

block_ip_direct: bool = True  # Block direct IP access
block_http_traffic: bool = True  # Block HTTP (non-HTTPS) traffic
block_http_other_ports: bool = True

# PKI revocation traffic (CRL, AIA issuer certificates, OCSP) is served over
# cleartext HTTP by design: the payload carries its own signature, and serving
# it over HTTPS would require a certificate whose own revocation status could
# not be checked. Letting ``block_http_traffic`` catch it does not protect
# anything -- it freezes certificate validation. Outlook stops at "loading
# profile" while CryptoAPI retries a CRL it will never receive.
#
# The certificate authorities are also named in the whitelist; this is the
# layer that covers the ones no list knows about. It has no switch in the
# interface -- turning it off is a diagnostic step, not a decision to put in
# front of someone -- so it lives in custom.cfg alone. Everything it lets
# through is recorded as a system event.
allow_revocation_http: bool = True

# Elevation buys exactly one thing: the loopback exemptions without which
# packaged Microsoft applications -- the new Outlook among them -- have no
# network at all while the proxy is on. Since 1.8.0 the installer sets them,
# and CalmWeb never shows a UAC prompt: it restarts elevated only when Windows
# grants it silently (administrator with a filtered token and UAC set to
# "Elevate without prompting", see platform.windows.can_elevate_silently) and
# an exemption is still missing. Setting this to 0 forbids even that.
ask_elevation: bool = True

# A blocked CONNECT cannot show a page -- the client wants a TLS tunnel, not
# HTML -- so the browser shows its own transport error and the user is left
# guessing. A desktop notification names the host and the rule instead.
#
# Off by default: on an ad-heavy page the interesting block is one among
# dozens, and a filter that interrupts is a filter people switch off. Someone
# who wants to know why a site will not load turns it on.
notify_on_block: bool = False

# --- Interface ------------------------------------------------------------
language: str = ""  # "", "fr" or "en" -- empty means "follow the system"
theme: str = "system"  # "system", "light" or "dark"

current_resolver: object | None = None
proxy_server: object | None = None
proxy_server_thread: threading.Thread | None = None

#: Set while the machine has been deliberately put back to its unproxied state
#: and the proxy stopped, without the application quitting yet -- the handover
#: to the update installer.  The proxy watchdog must not "repair" anything
#: during that window, or it would restart the server we just stopped.
update_in_progress: bool = False

# Threading primitives
_RESOLVER_LOADING = threading.Event()
_SHUTDOWN_EVENT = threading.Event()
_CONFIG_LOCK = threading.RLock()
_CONNECTION_SEMAPHORE = threading.BoundedSemaphore(MAX_PROXY_CONNECTIONS)

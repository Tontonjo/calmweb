"""Blocklist downloading, parsing, and domain resolution.

Handles hosts-file format, plain domain lists, CSV, ZIP archive
blocklists and whitelists (exact, wildcard, CIDR).  Provides
background reload on a configurable timer.
"""

from __future__ import annotations

import csv
import io
import ipaddress
import threading
import time
import traceback
import zipfile
from urllib.parse import urlparse

import urllib3

from . import config
from .log import log
from .net import make_pool_manager
from .normalize import normalize_host, normalize_whitelist_entry, parse_list_line

# ------------------------------------------------------------------
# Module-level helpers (used by both blocklist and whitelist loaders)
# ------------------------------------------------------------------

def _looks_like_ip(s: str) -> bool:
    """Return True if *s* parses as a valid IP address."""
    try:
        ipaddress.ip_address(s)
        return True
    except Exception:
        return False


def _download_content(url: str, http: urllib3.PoolManager) -> bytes | None:
    """Download from *url* (or read from ``file://``) with retries.

    Returns raw bytes or ``None`` on failure.  Handles the retry loop
    that currently exists inline in the loader methods.
    """
    for attempt in range(config.DOWNLOAD_MAX_RETRIES):
        try:
            log(f"\u2b07\ufe0f Chargement de la liste noir {url} (attempt {attempt + 1})")

            if url.startswith("file://"):
                file_path = url[7:]  # Strip "file://"
                with open(file_path, "rb") as f:
                    raw_data = f.read()
            else:
                response = http.request(
                    "GET",
                    url,
                    timeout=urllib3.Timeout(
                        connect=config.BLOCKLIST_TIMEOUT_CONNECT_SECS,
                        read=config.BLOCKLIST_TIMEOUT_READ_SECS,
                    ),
                )
                if response.status != 200:
                    raise Exception(f"HTTP {response.status}")
                raw_data = response.data

            if len(raw_data) > config.MAX_BLOCKLIST_BYTES:
                raise Exception(
                    f"Payload too large ({len(raw_data)} bytes > {config.MAX_BLOCKLIST_BYTES})"
                )

            return raw_data

        except Exception as e:
            log(f"[Erreur] Chargement {url} tentative {attempt + 1}: {e}")
            time.sleep(config.DOWNLOAD_RETRY_BASE_DELAY_SECS + attempt * 2)

    log(f"[\u26a0\ufe0f] Echec de téléchargement depuis {url}")
    return None


# ------------------------------------------------------------------
# Blocklist line parsers
# ------------------------------------------------------------------

def _parse_csv_line(line: str) -> str | None:
    """Parse a CSV line (URLHaus format) and return the hostname, or ``None``."""
    try:
        reader = csv.reader(io.StringIO(line))
        row = next(reader)
        if len(row) >= 3:
            url_candidate = row[2].strip('"').strip()
            host = urlparse(url_candidate).hostname
            if host:
                return normalize_host(host)
    except Exception:
        pass
    return None


def _parse_hosts_line(line: str) -> str | None:
    """Return the first host of a blocklist line, or ``None``.

    Every supported syntax (hosts file, plain domain, Adblock ``||domain^``,
    dnsmasq, URL) is reduced to a standard domain or IP by
    :func:`calmweb.normalize.parse_list_line`; this wrapper keeps the
    single-value shape used by callers that expect one host per line.
    """
    hosts = parse_list_line(line)
    return hosts[0] if hosts else None


# ------------------------------------------------------------------
# Blocklist content parsers
# ------------------------------------------------------------------

def _parse_text_blocklist(content: str, domains: set[str], cap_reached: bool) -> bool:
    """Parse plain text blocklist content (hosts-file format, plain domain list).

    Returns updated *cap_reached* flag.
    """
    for line in content.splitlines():
        if cap_reached:
            break
        # CSV rows (URLHaus) carry the URL in the third column.
        if line.startswith('"') and "," in line:
            host = _parse_csv_line(line)
            entries = [host] if host else []
        else:
            entries = parse_list_line(line)
        for domain in entries:
            domains.add(domain)
            if len(domains) >= config.MAX_BLOCKED_DOMAINS:
                cap_reached = True
                log(
                    f"\u26a0\ufe0f Limite de domaines atteinte ({config.MAX_BLOCKED_DOMAINS}), truncating."
                )
                break
    return cap_reached


def _parse_zip_blocklist(
    raw_data: bytes,
    url: str,
    domains: set[str],
    cap_reached: bool,
) -> bool:
    """Extract and parse ZIP archive contents.  Returns updated *cap_reached*."""
    log(f"\u2B1C ZIP archive détectée: {url}")
    with zipfile.ZipFile(io.BytesIO(raw_data)) as zf:
        for name in zf.namelist():
            if cap_reached:
                break
            if not name.lower().endswith((".txt", ".csv", ".log")):
                continue
            log(f"   -> Lecture {name} depuis archive ZIP")
            content = zf.read(name).decode("utf-8", errors="ignore")

            for line in content.splitlines():
                if cap_reached:
                    break
                if not line or line.startswith("#"):
                    continue
                # CSV format (e.g. URLHaus)
                if line.startswith('"') and "," in line:
                    host = _parse_csv_line(line)
                    if host:
                        domains.add(host)
                else:
                    # Plain text / hosts-file / Adblock format
                    domains.update(parse_list_line(line))

                if len(domains) >= config.MAX_BLOCKED_DOMAINS:
                    cap_reached = True
                    log(
                        f"\u26a0\ufe0f Limite de domaine atteinte "
                        f"({config.MAX_BLOCKED_DOMAINS}), truncating."
                    )
    return cap_reached


def _parse_blocklist_content(
    raw_data: bytes,
    url: str,
    domains: set[str],
    cap_reached: bool,
) -> bool:
    """Parse raw content and add domains to the set.

    Handles both ZIP and plain text formats.
    Returns updated *cap_reached* flag.
    """
    if zipfile.is_zipfile(io.BytesIO(raw_data)):
        return _parse_zip_blocklist(raw_data, url, domains, cap_reached)
    content = raw_data.decode("utf-8", errors="ignore")
    return _parse_text_blocklist(content, domains, cap_reached)


# ------------------------------------------------------------------
# Whitelist entry parser
# ------------------------------------------------------------------

def _parse_whitelist_entry(
    entry: str,
) -> tuple[str | None, ipaddress.IPv4Network | ipaddress.IPv6Network | None]:
    """Parse a single whitelist entry.

    Returns ``(domain, None)`` for domain/IP strings,
    ``(None, network)`` for CIDR ranges, or ``(None, None)`` if invalid.

    Wildcards (``*.example.com``), Adblock exception rules
    (``@@||example.com^``) and URLs are all reduced to a bare host.
    """
    return normalize_whitelist_entry(entry)


# ------------------------------------------------------------------
# Startup safety pause
# ------------------------------------------------------------------

def _resume_protection_if_paused() -> None:
    """End the protection pause caused by a missing whitelist.

    Called from :meth:`BlocklistResolver._load_whitelist` whenever a source
    answers.  ``tray`` is imported here rather than at module level: it
    imports the resolver back, and this is the only place that needs it.
    """
    try:
        if not config.protection_paused_no_whitelist:
            return
        from .tray import resume_protection_after_whitelist  # noqa: PLC0415

        resume_protection_after_whitelist()
    except Exception as e:
        log(f"_resume_protection_if_paused: {e}")


# ===================================================================
# BlocklistResolver
# ===================================================================

class BlocklistResolver:
    """Download, parse, and query blocklists / whitelists."""

    #: Class-level default: instances are also built with ``__new__`` (the
    #: lookup tests, for one), and querying must work before a load.
    blocked_ips: set[str] = set()

    def __init__(
        self,
        blocklist_urls: list[str],
        reload_interval: int = 3600,
    ) -> None:
        self.blocklist_urls: list[str] = list(blocklist_urls)
        self.reload_interval: int = max(60, int(reload_interval or 3600))
        self.blocked_domains: set[str] = set()
        self.blocked_ips: set[str] = set()
        self.last_reload: float = 0
        self._lock = threading.Lock()
        self._loading_lock = threading.Lock()

        # Dedicated whitelist structures
        self.whitelisted_domains_local: set[str] = set()
        self.whitelisted_networks: set[ipaddress.IPv4Network | ipaddress.IPv6Network] = set()
        self.whitelist_download_successful: bool = False

        # Initial load (tolerant of errors)
        try:
            self._load_blocklist()
            self._load_whitelist()
        except Exception as e:
            log(f"Erreur d'initialisation de BlocklistResolver: {e}")

    def set_blocklist_urls(self, urls: list[str]) -> None:
        """Replace the sources downloaded on the next reload.

        The URL list is fixed at construction so tests can pin it, but the
        user can edit the sources at runtime.  Without this the dashboard
        would save a new source, trigger a reload, and quietly download the
        old list again.
        """
        with self._lock:
            self.blocklist_urls = list(urls)

    # ------------------------------------------------------------------
    # Blocklist loading
    # ------------------------------------------------------------------

    def _load_blocklist(self) -> None:
        """Download all configured blocklists and rebuild the blocked-domains set."""
        if self._loading_lock.locked():
            log("Chargement de la liste noir déjà en cours.")
            return
        with self._loading_lock:
            config._RESOLVER_LOADING.set()
            try:
                domains: set[str] = set()
                http = make_pool_manager()
                cap_reached = False

                for url in self.blocklist_urls:
                    if cap_reached:
                        break
                    raw_data = _download_content(url, http)
                    if raw_data is None:
                        continue
                    cap_reached = _parse_blocklist_content(raw_data, url, domains, cap_reached)

                # Standard entries only: hostnames on one side, routable IP
                # addresses on the other, so each can be matched exactly.
                ips = {d for d in domains if _looks_like_ip(d)}
                names = domains - ips

                # Atomic blocklist update
                with self._lock:
                    self.blocked_domains = names
                    self.blocked_ips = ips
                    self.last_reload = time.time()

                log(f"\u2705 {len(names)} domaines et {len(ips)} IP mis en liste noire")

            except Exception as e:
                log(f"Erreur dans _load_blocklist: {e}\n{traceback.format_exc()}")

            finally:
                config._RESOLVER_LOADING.clear()

    # ------------------------------------------------------------------
    # Whitelist loading
    # ------------------------------------------------------------------

    def _load_whitelist(self) -> None:
        """Download and parse whitelists, updating local and global sets."""
        try:
            http = make_pool_manager()
            new_domains: set[str] = set()
            new_networks: set[ipaddress.IPv4Network | ipaddress.IPv6Network] = set()
            any_download_succeeded = False

            # Seed with the user's own whitelist from custom.cfg.
            #
            # ``config.whitelisted_domains`` is a set of *strings*, so a CIDR
            # range typed in ``[WHITELIST]`` arrives here as the text
            # "10.0.0.0/24".  Adding it straight to ``new_domains`` filed it
            # as a hostname, where it could only ever be compared to a domain
            # name and so matched nothing: the user's ranges were silently
            # inert while their individual addresses worked.  Every entry now
            # goes through the same parser as a downloaded line, which sends
            # ranges to ``new_networks`` and addresses to ``new_domains``.
            try:
                for d in config.whitelisted_domains:
                    if not isinstance(d, str) or not d:
                        continue
                    domain, network = _parse_whitelist_entry(d)
                    if domain is not None:
                        new_domains.add(domain)
                    elif network is not None:
                        new_networks.add(network)
            except Exception:
                pass

            for url in config.whitelist_source_urls:
                for attempt in range(config.DOWNLOAD_MAX_RETRIES):
                    try:
                        log(f"\u2b07\ufe0f Téléchargement de la liste blanche {url} (Tentative {attempt + 1})")
                        response = http.request(
                            "GET",
                            url,
                            timeout=urllib3.Timeout(
                                connect=config.WHITELIST_TIMEOUT_CONNECT_SECS,
                                read=config.WHITELIST_TIMEOUT_READ_SECS,
                            ),
                        )
                        if response.status != 200:
                            raise Exception(f"HTTP {response.status}")
                        content = response.data.decode("utf-8", errors="ignore")
                        for line in content.splitlines():
                            try:
                                line = line.split("#", 1)[0].strip()
                                if not line:
                                    continue
                                entry = line.lower().strip()
                                domain, network = _parse_whitelist_entry(entry)
                                if domain is not None:
                                    new_domains.add(domain)
                                elif network is not None:
                                    new_networks.add(network)
                            except Exception:
                                continue
                        any_download_succeeded = True
                        break
                    except Exception as e:
                        log(
                            f"[\u26a0\ufe0f] Echec de chargement de la liste blanche {url} "
                            f"Tentative {attempt + 1}: {e}"
                        )
                        time.sleep(config.DOWNLOAD_RETRY_BASE_DELAY_SECS + attempt * 2)

            # Atomic update.
            #
            # ``whitelisted_domains_local`` is the *effective* whitelist: the
            # user's entries plus everything downloaded.  ``config
            # .whitelisted_domains`` deliberately keeps holding only what the
            # user wrote in custom.cfg -- it is what the Lists page shows and
            # what gets saved back, so merging the downloaded list into it
            # would bury the user's own handful of domains under a thousand
            # others and write them all to their configuration file.
            with self._lock:
                self.whitelisted_domains_local = new_domains
                self.whitelisted_networks = new_networks
                self.whitelist_download_successful = any_download_succeeded

            # A whitelist is what the startup safety check was waiting for.
            if any_download_succeeded:
                _resume_protection_if_paused()

            log(
                f"\u2705 {len(self.whitelisted_domains_local)} domaines en liste blanche "
                f"{len(self.whitelisted_networks)} Réseaux CIDR chargés"
            )
        except Exception as e:
            self.whitelist_download_successful = False
            log(f"[Erreur] _load_whitelist: {e}\n{traceback.format_exc()}")

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _looks_like_ip(s: str) -> bool:
        return _looks_like_ip(s)

    def is_whitelisted(self, hostname: str | None) -> bool:
        """Check whether *hostname* is explicitly whitelisted."""
        try:
            if not hostname:
                return False
            host = hostname.strip().lower().rstrip(".")
            if not host:
                return False

            # Direct IP -- check networks and exact IP whitelist
            try:
                if _looks_like_ip(host):
                    ip_obj = ipaddress.ip_address(host)
                    # An address can be written several ways -- "2a03:17e0:2:ff::f:49"
                    # and "2a03:17e0:0002:00ff:0:f:49" are the same host -- while
                    # the whitelist stores the canonical form, so both are tried.
                    canonical = str(ip_obj)
                    with self._lock:
                        if (
                            host in self.whitelisted_domains_local
                            or canonical in self.whitelisted_domains_local
                        ):
                            return True
                        for net in self.whitelisted_networks:
                            if ip_obj in net:
                                return True
                    return False
            except Exception:
                pass

            parts = host.split(".")
            with self._lock:
                for i in range(len(parts)):
                    candidate = ".".join(parts[i:])
                    if candidate in self.whitelisted_domains_local:
                        return True

            return False
        except Exception as e:
            log(f"Erreur is_whitelisted {hostname}: {e}")
            return False

    def _is_blocked(self, hostname: str | None) -> bool:
        """Return True if *hostname* should be blocked."""
        try:
            if not hostname:
                return False

            host = hostname.strip().lower().rstrip(".")
            if not host:
                return False

            # 1) Whitelist has absolute priority
            try:
                if self.is_whitelisted(host):
                    log(f"\u2705 [Domaine autorisé] {host}")
                    return False
            except Exception as e:
                log(f"_is_blocked: Erreur de contrôle de la liste blanche pour {hostname}: {e}")
                return False

            # 2) Direct IP handling
            try:
                if _looks_like_ip(host):
                    if host in config.whitelisted_domains:
                        log(f"\u2705 [IP autorisée] {hostname}")
                        return False
                    with self._lock:
                        if host in self.blocked_ips:
                            return True
                    return bool(config.block_ip_direct)
            except Exception:
                pass

            parts = host.split(".")
            # 3) Blocklist check
            try:
                with self._lock:
                    if host in self.blocked_domains or host in config.manual_blocked_domains:
                        return True
                    for i in range(1, len(parts)):
                        parent = ".".join(parts[i:])
                        if (
                            parent in self.blocked_domains
                            or parent in config.manual_blocked_domains
                        ):
                            return True
            except Exception as e:
                log(f"_is_blocked Erreur de contrôle de la liste noir pour {hostname}: {e}")
                return False

            return False
        except Exception as e:
            log(f"_is_blocked erreur pour {hostname}: {e}")
            return False

    # ------------------------------------------------------------------
    # Introspection helpers (used by the dashboard)
    # ------------------------------------------------------------------

    def allow_now(self, hostname: str | None) -> bool:
        """Add *hostname* to the live whitelist straight away.

        Downloading the whitelists again takes a few seconds; this makes the
        "allow this site" action take effect on the very next request, and
        the following reload simply confirms it.
        """
        try:
            host = (hostname or "").strip().lower().rstrip(".").lstrip(".")
            if not host:
                return False
            with self._lock:
                self.whitelisted_domains_local.add(host)
            log(f"✅ [Liste blanche] {host} autorisé immédiatement")
            return True
        except Exception as e:
            log(f"allow_now({hostname}) error: {e}")
            return False

    def counts(self) -> dict[str, int | float]:
        """Return list sizes and the timestamp of the last successful reload."""
        with self._lock:
            return {
                "blocked": len(self.blocked_domains) + len(self.blocked_ips),
                "blocked_ips": len(self.blocked_ips),
                "manual": len(config.manual_blocked_domains),
                "whitelist": len(self.whitelisted_domains_local),
                "networks": len(self.whitelisted_networks),
                "last_reload": self.last_reload,
            }

    def describe(self, hostname: str | None) -> dict[str, str | bool]:
        """Explain the verdict for *hostname*: is it blocked, and by which list?

        Returns a dict with ``host``, ``blocked``, ``source`` (one of
        ``whitelist``, ``manual``, ``downloaded``, ``ip``, ``none``) and
        ``match`` -- the exact entry that matched, which may be a parent
        domain.
        """
        result: dict[str, str | bool] = {
            "host": "",
            "blocked": False,
            "source": "none",
            "match": "",
        }
        try:
            host = (hostname or "").strip().lower().rstrip(".")
            if host.startswith("[") and host.endswith("]"):
                host = host[1:-1]
            if not host:
                return result
            result["host"] = host

            # Whitelist first -- it overrides everything.
            if _looks_like_ip(host):
                ip_obj = ipaddress.ip_address(host)
                canonical = str(ip_obj)
                with self._lock:
                    if host in self.whitelisted_domains_local:
                        return {**result, "source": "whitelist", "match": host}
                    if canonical in self.whitelisted_domains_local:
                        return {**result, "source": "whitelist", "match": canonical}
                    for net in self.whitelisted_networks:
                        if ip_obj in net:
                            return {**result, "source": "whitelist", "match": str(net)}
                    if host in self.blocked_ips:
                        return {
                            **result,
                            "blocked": True,
                            "source": "downloaded",
                            "match": host,
                        }
                if config.block_ip_direct:
                    return {**result, "blocked": True, "source": "ip", "match": host}
                return result

            parts = host.split(".")
            candidates = [".".join(parts[i:]) for i in range(len(parts))]

            with self._lock:
                for candidate in candidates:
                    if candidate in self.whitelisted_domains_local:
                        return {**result, "source": "whitelist", "match": candidate}
                for candidate in candidates:
                    if candidate in config.manual_blocked_domains:
                        return {
                            **result,
                            "blocked": True,
                            "source": "manual",
                            "match": candidate,
                        }
                    if candidate in self.blocked_domains:
                        return {
                            **result,
                            "blocked": True,
                            "source": "downloaded",
                            "match": candidate,
                        }
            return result
        except Exception as e:
            log(f"describe({hostname}) error: {e}")
            return result

    def maybe_reload_background(self) -> None:
        """Reload blocklist and whitelist in background threads if interval elapsed."""
        try:
            if time.time() - self.last_reload > self.reload_interval:
                if self._loading_lock.locked():
                    return
                t1 = threading.Thread(target=self._load_blocklist, daemon=True)
                t2 = threading.Thread(target=self._load_whitelist, daemon=True)
                t1.start()
                t2.start()
        except Exception as e:
            log(f"maybe_reload_background erreur: {e}")

"""HTTP/HTTPS proxy handler with blocklist enforcement.

Protocol notes
--------------
* **HTTP/1.1** requests reach the handler in absolute form and are filtered,
  rewritten and forwarded.
* **HTTP/2** is negotiated with ALPN *inside* the TLS session, so it rides
  through the ``CONNECT`` tunnel untouched.  The tunnel is a byte relay and
  must therefore never assume request/response framing, and must tolerate
  long idle periods -- an h2 connection is deliberately kept open and idle
  between requests.
* **HTTP/3 / QUIC** cannot be carried by an HTTP/1.1 ``CONNECT`` proxy.
  Every mainstream browser detects the configured system proxy and falls
  back to HTTP/2 over TCP on its own, which is filtered normally.  No
  firewall rule is needed to force that: earlier versions blocked outbound
  UDP/443 machine-wide, which enforced a fallback that already happens and
  penalised every other application on the machine.
* **WebSockets** over plain HTTP use an ``Upgrade`` handshake; the upgrade
  headers are preserved and the connection becomes a raw relay.
"""

from __future__ import annotations

import contextlib
import html
import selectors
import socket
import threading
import time
import traceback
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

from . import config, stats
from .log import log
from .notify import notify_blocked
from .platform.windows import set_socket_keepalive

# ===================================================================
# Host / port parsing
# ===================================================================


def split_host_port(authority: str, default_port: int = 443) -> tuple[str | None, int | None]:
    """Split an ``authority`` string into ``(host, port)``.

    Correctly handles IPv6 literals, which are bracketed and contain colons::

        "example.com:8443" -> ("example.com", 8443)
        "example.com"      -> ("example.com", default_port)
        "[::1]:8080"       -> ("::1", 8080)
        "[2001:db8::1]"    -> ("2001:db8::1", default_port)

    Returns ``(None, None)`` when the authority cannot be parsed, so the
    caller can reject the request instead of silently letting it through.
    """
    try:
        value = (authority or "").strip()
        if not value:
            return None, None

        if value.startswith("["):
            end = value.find("]")
            if end == -1:
                return None, None
            host = value[1:end]
            rest = value[end + 1 :]
            if not rest:
                return host, default_port
            if not rest.startswith(":"):
                return None, None
            port_str = rest[1:]
        elif value.count(":") > 1:
            # Unbracketed IPv6 literal (illegal in a request, but seen in the
            # wild). Treat the whole value as the host.
            return value, default_port
        elif ":" in value:
            host, port_str = value.split(":", 1)
        else:
            return value, default_port

        if not port_str:
            return host, default_port
        port = int(port_str)
        if not (0 < port < 65536):
            return None, None
        return host, port
    except Exception:
        return None, None


def normalize_hostname(host: str | None) -> str | None:
    """Lowercase a hostname and strip brackets, trailing dots and whitespace."""
    if not host:
        return None
    value = host.strip().lower().rstrip(".")
    if value.startswith("[") and value.endswith("]"):
        value = value[1:-1]
    return value or None


def _connect_target(host: str) -> str:
    """Return *host* in the form :func:`socket.create_connection` expects."""
    return host


# ===================================================================
# PKI revocation traffic (CRL / AIA / OCSP)
# ===================================================================

#: Suffixes used by CRL distribution points and AIA (issuer certificate) URLs.
_REVOCATION_SUFFIXES: tuple[str, ...] = (
    ".crl",
    ".crt",
    ".cer",
    ".der",
    ".p7c",
    ".p7b",
)

#: Media type of an OCSP request sent by POST (RFC 6960 §A.1).
_OCSP_CONTENT_TYPE: str = "application/ocsp-request"

#: Alphabet of a base64 / base64url payload, padding included.
_BASE64_CHARS: frozenset[str] = frozenset(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=-_"
)

#: Windows performs every revocation fetch under this user agent.
_CRYPTOAPI_AGENT: str = "microsoft-cryptoapi"


def is_revocation_request(command: str, path_only: str, headers: Any) -> bool:
    """True when a cleartext HTTP request is a certificate revocation fetch.

    Revocation lists (CRL), issuer certificates (AIA) and OCSP are served over
    plain ``http://`` **by design**: each payload carries its own signature,
    and serving them over HTTPS would need a certificate whose own revocation
    status could not be checked without recursing.  RFC 5280 §4.2.1.13 and
    RFC 6960 §A.1 both assume cleartext.

    Catching them with the "HTTPS only" rule protects nothing and breaks
    certificate validation instead: the client receives an HTML error page
    where it expected DER, and retries until it gives up.  Outlook shows this
    as an indefinite "loading profile", because the chain validation it does
    on the first connection to Exchange never completes.  It then looks fixed
    for days once the proxy is turned off long enough for one successful
    fetch, since Windows caches a CRL for its whole validity period.

    The certificate authorities are named in the whitelist, which handles the
    ones we know about.  This is the second layer, for the ones we do not: an
    enterprise CA on an intranet, a regional authority, a CRL that moved to a
    new hostname.  Missing one is not a loud failure -- validation simply
    stalls, with nothing in the logs to point at -- which is why the shape of
    the request is worth trusting on its own.

    Only the ``block_http_traffic`` verdict is lifted for these requests; the
    blocklist and the whitelist are applied before this is ever consulted, and
    every request let through this way is recorded as a system event.
    """
    try:
        agent = (headers.get("User-Agent") or "").strip().lower()
        if agent.startswith(_CRYPTOAPI_AGENT):
            return True

        verb = (command or "").upper()

        if verb == "POST":
            content_type = (headers.get("Content-Type") or "").split(";", 1)[0]
            return content_type.strip().lower() == _OCSP_CONTENT_TYPE

        if verb not in ("GET", "HEAD"):
            return False

        target = (path_only or "").split("?", 1)[0]
        if target.lower().endswith(_REVOCATION_SUFFIXES):
            return True

        # OCSP over GET carries the DER request base64-encoded in the last path
        # segment.  DER opens with 0x30 (SEQUENCE), which base64-encodes to a
        # leading "M", and even the shortest real request is far past 40 chars.
        segment = urllib.parse.unquote(target.rsplit("/", 1)[-1])
        return (
            len(segment) >= 40
            and segment.startswith("M")
            and _BASE64_CHARS.issuperset(segment)
        )
    except Exception:
        return False


# ===================================================================
# Relay helpers (single-thread, selector based pass-through)
# ===================================================================


def _set_socket_opts_for_perf(sock: socket.socket) -> None:
    """Apply TCP_NODELAY, SO_KEEPALIVE, and platform-specific tuning."""
    with contextlib.suppress(Exception):
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
        set_socket_keepalive(sock)


def full_duplex_relay(a_sock: socket.socket, b_sock: socket.socket) -> None:
    """Relay bytes both ways between two sockets until either side closes.

    Uses a single :mod:`selectors` loop instead of two blocking threads, so a
    tunnel costs one thread rather than three.  That matters with HTTP/2,
    where a browser holds one long-lived tunnel per origin.

    An idle tunnel is **not** closed on the first quiet second: HTTP/2 and
    WebSocket connections are meant to stay open between requests.  The relay
    only gives up after :data:`config.TUNNEL_IDLE_TIMEOUT` seconds with no
    traffic at all, while TCP keepalive detects genuinely dead peers.
    """
    stats.connection_opened()
    buffer_size = config.RELAY_BUFFER_SIZE_BYTES
    idle_limit = max(30, int(getattr(config, "TUNNEL_IDLE_TIMEOUT", 1800)))

    for sock in (a_sock, b_sock):
        with contextlib.suppress(Exception):
            sock.setblocking(False)

    open_directions = {(a_sock, b_sock), (b_sock, a_sock)}
    # Idleness is measured against the clock, not counted in ticks, so the
    # wake-up interval can be chosen for cost alone. It matters: every open
    # tunnel is a thread, and a tunnel that wakes once a second only to find
    # nothing to do still takes the GIL from the accept loop. At a few hundred
    # concurrent tunnels that is enough contention to starve it.
    last_activity = time.monotonic()
    tick = config.RELAY_POLL_INTERVAL_SECS

    try:
        with selectors.DefaultSelector() as selector:
            selector.register(a_sock, selectors.EVENT_READ, b_sock)
            selector.register(b_sock, selectors.EVENT_READ, a_sock)

            while open_directions and not config._SHUTDOWN_EVENT.is_set():
                ready = selector.select(timeout=tick)
                if not ready:
                    if time.monotonic() - last_activity >= idle_limit:
                        break
                    continue
                last_activity = time.monotonic()

                for key, _mask in ready:
                    src: socket.socket = key.fileobj  # type: ignore[assignment]
                    dst: socket.socket = key.data
                    try:
                        data = src.recv(buffer_size)
                    except (BlockingIOError, InterruptedError):
                        continue
                    except Exception:
                        data = b""

                    if not data:
                        # Half close: tell the peer we are done writing but keep
                        # draining the other direction (needed for uploads that
                        # finish before the response is complete).
                        with contextlib.suppress(Exception):
                            selector.unregister(src)
                        open_directions.discard((src, dst))
                        with contextlib.suppress(Exception):
                            dst.shutdown(socket.SHUT_WR)
                        continue

                    if not _send_all(dst, data):
                        open_directions.clear()
                        break
    except Exception:
        stats.record_error()
    finally:
        for sock in (a_sock, b_sock):
            with contextlib.suppress(Exception):
                sock.shutdown(socket.SHUT_RDWR)
            with contextlib.suppress(Exception):
                sock.close()
        stats.connection_closed()


def _send_all(sock: socket.socket, data: bytes) -> bool:
    """Write *data* to a non-blocking socket. Returns False when it dies."""
    view = memoryview(data)
    deadline_ticks = 0
    while view:
        try:
            sent = sock.send(view)
            view = view[sent:]
            deadline_ticks = 0
        except (BlockingIOError, InterruptedError):
            deadline_ticks += 1
            if deadline_ticks > 600 or config._SHUTDOWN_EVENT.is_set():
                return False
            with (
                contextlib.suppress(Exception),
                selectors.DefaultSelector() as write_selector,
            ):
                write_selector.register(sock, selectors.EVENT_WRITE)
                write_selector.select(timeout=0.1)
        except Exception:
            return False
    return True


# ===================================================================
# HTTP(S) Proxy Handler
# ===================================================================


class BlockProxyHandler(BaseHTTPRequestHandler):
    """Proxy request handler with blocklist / whitelist enforcement."""

    timeout: int = config.PROXY_HANDLER_TIMEOUT_SECS
    rbufsize: int = 0
    protocol_version: str = config.PROXY_PROTOCOL_VERSION

    #: Ports a CONNECT tunnel may target (HTTP, HTTPS, TURN over TCP).
    ALLOWED_CONNECT_PORTS: set[int] = config.ALLOWED_CONNECT_PORTS

    #: Headers that must not be forwarded verbatim to the origin server.
    HOP_BY_HOP: frozenset[str] = frozenset(
        {
            "proxy-connection",
            "connection",
            "keep-alive",
            "transfer-encoding",
            "te",
            "trailers",
            "upgrade",
            "proxy-authorization",
            "proxy-authenticate",
        }
    )

    # ------------------------------------------------------------------
    # Method dispatch
    # ------------------------------------------------------------------

    #: Characters allowed in an HTTP method (RFC 9110 "token").
    _TOKEN_CHARS: frozenset[str] = frozenset(
        "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!#$%&'*+-.^_`|~"
    )

    #: Verbs with an explicit ``do_*`` method; anything else is still handled,
    #: but is worth naming in the log the first time it is seen.
    _COMMON_METHODS: frozenset[str] = frozenset(
        {"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS", "CONNECT"}
    )

    _seen_methods: set[str] = set()

    def __getattr__(self, name: str) -> Any:
        """Provide a handler for **every** HTTP verb, not just the usual ones.

        ``BaseHTTPRequestHandler`` answers ``501 Unsupported method`` on its
        own, before any CalmWeb code runs, for any verb without a matching
        ``do_*`` method.  Nothing is logged and nothing reaches the activity
        view, so the application on the other end simply retries forever and
        looks frozen.

        Real clients use far more than GET and POST: Outlook speaks
        ``RPC_IN_DATA`` / ``RPC_OUT_DATA`` for RPC-over-HTTP, Office and
        SharePoint use the WebDAV verbs (``PROPFIND``, ``MKCOL``, ``MOVE``,
        ``REPORT``…).  Any syntactically valid verb is therefore accepted and
        filtered exactly like the others.
        """
        if name.startswith("do_") and len(name) > 3:
            verb = name[3:]
            if verb and self._TOKEN_CHARS.issuperset(verb):
                return self._handle_unusual_method
        raise AttributeError(name)

    def _handle_unusual_method(self) -> None:
        """Filter and forward a request using a less common HTTP verb."""
        verb = str(self.command or "")
        if verb not in self._COMMON_METHODS and verb not in self._seen_methods:
            self._seen_methods.add(verb)
            log(f"ℹ️ Méthode HTTP peu courante prise en charge: {verb}")
            stats.record("system", detail=f"Méthode HTTP {verb}")
        self._handle_http_method()

    # ------------------------------------------------------------------
    # Parsing helpers
    # ------------------------------------------------------------------

    def _extract_hostname_from_path(self, path: str) -> str | None:
        """Extract the hostname from an absolute-form request URI."""
        try:
            return urllib.parse.urlparse(path).hostname
        except Exception:
            return None

    # ------------------------------------------------------------------
    # Framing helpers
    # ------------------------------------------------------------------

    def handle_expect_100(self) -> bool:
        """Do not answer ``Expect: 100-continue`` on the origin's behalf.

        The default implementation replies ``100 Continue`` immediately, which
        would duplicate the origin's own interim response once the request is
        forwarded.  Returning ``True`` without writing anything keeps the
        proxy transparent.
        """
        return True

    def _is_upgrade_request(self) -> bool:
        """True when the client asks to switch protocols (WebSocket, h2c…)."""
        try:
            upgrade = (self.headers.get("Upgrade") or "").strip()
            connection = (self.headers.get("Connection") or "").lower()
            return bool(upgrade) and "upgrade" in connection
        except Exception:
            return False

    # ------------------------------------------------------------------
    # Responses
    # ------------------------------------------------------------------

    def _send_block_page(self, host: str | None, reason_key: str) -> None:
        """Reply to a filtered plain-HTTP request with a readable page."""
        from .i18n import t

        try:
            safe_host = html.escape(host or "")
            reason = html.escape(t(reason_key))
            title = html.escape(t("app.name"))
            heading = html.escape(t("block.page.title"))
            note = html.escape(t("block.page.note"))
            body = (
                "<!doctype html><html><head><meta charset='utf-8'>"
                "<meta name='viewport' content='width=device-width,initial-scale=1'>"
                f"<title>{title}</title><style>"
                "body{font-family:Segoe UI,system-ui,sans-serif;background:#f4f6f8;color:#1d2430;"
                "display:flex;align-items:center;justify-content:center;height:100vh;margin:0}"
                ".card{background:#fff;border-radius:16px;padding:40px 44px;max-width:520px;"
                "box-shadow:0 12px 40px rgba(20,30,50,.12);text-align:center}"
                "h1{font-size:22px;margin:0 0 12px}p{margin:6px 0;line-height:1.55}"
                ".host{font-weight:600;word-break:break-all}"
                ".note{margin-top:18px;font-size:13px;color:#66707e}"
                ".reason{display:inline-block;margin-top:16px;padding:6px 14px;border-radius:999px;"
                "background:#fdecec;color:#a4262c;font-size:13px}"
                "</style></head><body><div class='card'>"
                f"<h1>{heading}</h1>"
                f"<p class='host'>{safe_host}</p>"
                f"<span class='reason'>{reason}</span>"
                f"<p class='note'>{note}</p>"
                "</div></body></html>"
            ).encode()

            self.send_response(403, "Blocked by security policy")
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("Connection", "close")
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(body)
        except Exception:
            with contextlib.suppress(Exception):
                self.send_error(403, "Blocked by security policy")

    def _reject(self, host: str | None, port: int, reason: str, tunnel: bool) -> None:
        """Record and answer a blocked request."""
        # ``record`` answers False for a block already reported moments ago:
        # it is still counted, it is simply not written down twice.  A single
        # refused page asks for the same host several times over -- browser
        # preconnect, the retry after the refusal, then every sub-resource --
        # and the log used to carry each one.
        first_report = stats.record("blocked", host=host or "", port=port, reason=reason,
                                    proto="CONNECT" if tunnel else self.command)
        if first_report:
            marker = {
                "blocklist": "❌ [Liste noire téléchargée]",
                "manual": "❌ [Votre liste noire]",
                "http": "❌ [Trafic non sécurisé]",
                "port": "❌ [Port non standard]",
                "ip": "❌ [Adresse IP directe]",
                "invalid": "❌ [Requête invalide]",
            }.get(reason, "❌ [Bloqué]")
            log(f"{marker} {host}:{port}" if port else f"{marker} {host}")

        self.close_connection = True
        if tunnel:
            # A CONNECT cannot carry the block page: the client wants a TLS
            # tunnel and discards the body of a 403, so the browser shows a
            # bare transport error naming neither the domain nor the rule.
            # A notification is what tells the user what happened.
            notify_blocked(host, reason)
            with contextlib.suppress(Exception):
                self.send_error(403, "Blocked by security policy")
        else:
            self._send_block_page(host, f"activity.reason.{reason}")

    # ------------------------------------------------------------------
    # Shared policy checks
    # ------------------------------------------------------------------

    @staticmethod
    def _block_reason(resolver: Any, hostname: str) -> str:
        """Name the list that actually blocked *hostname*.

        Saying only "blocklist" sends people hunting through their own
        configuration for an entry that lives in a downloaded list, so the
        reason distinguishes the downloaded lists, the user's own list and
        the direct-IP rule.
        """
        try:
            source = str(resolver.describe(hostname).get("source", ""))
            if source in ("manual", "ip"):
                return source
            if source == "downloaded":
                return "blocklist"
        except Exception:
            pass

        from .resolver import _looks_like_ip

        return "ip" if (_looks_like_ip(hostname) and config.block_ip_direct) else "blocklist"

    def _policy_verdict(self, hostname: str | None, port: int, tunnel: bool) -> str | None:
        """Return a block reason, or ``None`` when the request may proceed.

        The whitelist wins over every other rule, exactly as before.
        """
        resolver = config.current_resolver

        try:
            if resolver and resolver.is_whitelisted(hostname):
                return None
        except Exception as e:
            log(f"[WARN] whitelist check error for {hostname}: {e}")

        if not hostname:
            return "invalid"

        if config.block_enabled and resolver and resolver._is_blocked(hostname):
            return self._block_reason(resolver, hostname)

        if config.block_http_other_ports and port not in self.ALLOWED_CONNECT_PORTS:
            return "port"

        # A CONNECT to port 80 carries cleartext HTTP inside the tunnel and
        # would otherwise slip past the "HTTPS only" rule entirely.
        if tunnel and config.block_enabled and config.block_http_traffic and port == 80:
            return "http"

        return None

    # ------------------------------------------------------------------
    # CONNECT (HTTPS, HTTP/2, and HTTP/3-over-TCP fallback)
    # ------------------------------------------------------------------

    def _establish_tunnel(self, target_host: str, target_port: int) -> None:
        """Create a TCP tunnel and relay traffic bidirectionally."""
        remote = socket.create_connection(
            (_connect_target(target_host), target_port),
            timeout=config.SOCKET_CONNECT_TIMEOUT_SECS,
        )
        self.send_response(200, "Connection Established")
        self.end_headers()

        conn = self.connection
        _set_socket_opts_for_perf(conn)
        _set_socket_opts_for_perf(remote)
        # The relay owns both sockets from here on; the handler must not try
        # to read another request from a socket it no longer controls.
        self.close_connection = True
        full_duplex_relay(conn, remote)

    def do_CONNECT(self) -> None:
        """Handle HTTPS CONNECT tunnel requests."""
        target_host, target_port = split_host_port(self.path, default_port=443)
        hostname = normalize_hostname(target_host)

        if not target_host or not target_port:
            self._reject(self.path, 0, "invalid", tunnel=True)
            return

        try:
            if config.current_resolver:
                config.current_resolver.maybe_reload_background()

            reason = self._policy_verdict(hostname, target_port, tunnel=True)
            if reason is not None:
                self._reject(hostname, target_port, reason, tunnel=True)
                return

            log(f"✅ [Autorisé] {hostname}:{target_port}")
            stats.record("allowed", host=hostname or "", port=target_port, proto="CONNECT")
            self._establish_tunnel(target_host, target_port)

        except Exception as e:
            stats.record_error()
            stats.record("system", host=hostname or "", port=target_port,
                         detail=f"Connexion impossible: {e}")
            log(f"[Proxy CONNECT error] {hostname}: {e}")
            with contextlib.suppress(Exception):
                self.send_error(502, "Bad Gateway")

    # ------------------------------------------------------------------
    # Plain HTTP
    # ------------------------------------------------------------------

    def _resolve_target(self) -> tuple[str, str | None, int, str, str] | None:
        """Extract ``(target_host, hostname, target_port, path_only, scheme)``.

        Returns ``None`` (after answering the client) for malformed requests.
        """
        path = self.path if isinstance(self.path, str) else ""

        if path.startswith(("http://", "https://")):
            parsed = urllib.parse.urlparse(path)
            scheme = parsed.scheme
            default_port = 443 if scheme == "https" else 80
            try:
                target_host, target_port = parsed.hostname, parsed.port or default_port
            except ValueError:
                # urllib raises on an out-of-range port
                target_host, target_port = None, None
            path_only = parsed.path or "/"
            if parsed.query:
                path_only += "?" + parsed.query
        else:
            scheme = "http"
            target_host, target_port = split_host_port(
                self.headers.get("Host", ""), default_port=80
            )
            path_only = path or "/"

        if not target_host or not target_port:
            self._reject(self.headers.get("Host", ""), 0, "invalid", tunnel=False)
            return None

        return target_host, normalize_hostname(target_host), target_port, path_only, scheme

    def _build_forwarded_request(
        self,
        target_host: str,
        target_port: int,
        path_only: str,
        scheme: str,
    ) -> bytes:
        """Construct the HTTP request bytes to send to the remote server."""
        upgrading = self._is_upgrade_request()

        host_header_value = target_host
        if ":" in target_host and not target_host.startswith("["):
            host_header_value = f"[{target_host}]"
        if (scheme == "http" and target_port != 80) or (scheme == "https" and target_port != 443):
            host_header_value = f"{host_header_value}:{target_port}"

        header_lines: list[str] = []
        for key, value in self.headers.items():
            try:
                lowered = key.lower()
                if lowered == "host":
                    continue
                if lowered in self.HOP_BY_HOP:
                    continue
                header_lines.append(f"{key}: {value}")
            except Exception:
                continue

        header_lines.insert(0, f"Host: {host_header_value}")

        if upgrading:
            # Preserve the handshake so WebSocket (ws://) keeps working; the
            # connection becomes a raw relay right after the 101 response.
            upgrade_value = (self.headers.get("Upgrade") or "").strip()
            header_lines.append(f"Upgrade: {upgrade_value}")
            header_lines.append("Connection: Upgrade")
        else:
            header_lines.append("Connection: close")

        request_line = f"{self.command} {path_only} {self.request_version}\r\n"
        blob = "\r\n".join(header_lines) + "\r\n\r\n"
        return request_line.encode("latin-1", "replace") + blob.encode("latin-1", "replace")

    def _forward_to_remote(
        self,
        target_host: str,
        target_port: int,
        request_bytes: bytes,
    ) -> None:
        """Create the remote connection, send the request, and start the relay."""
        remote = socket.create_connection(
            (_connect_target(target_host), target_port),
            timeout=config.SOCKET_CONNECT_TIMEOUT_SECS,
        )

        _set_socket_opts_for_perf(self.connection)
        _set_socket_opts_for_perf(remote)

        try:
            remote.sendall(request_bytes)
        except Exception as e:
            stats.record_error()
            log(f"[Proxy send headers error] {e}")
            with contextlib.suppress(Exception):
                remote.close()
            with contextlib.suppress(Exception):
                self.send_error(502, "Bad Gateway")
            return

        # Any request body still sits unread in the client socket (rbufsize=0),
        # so the relay carries it through unchanged.
        self.close_connection = True
        full_duplex_relay(self.connection, remote)

    def _handle_http_method(self) -> None:
        """Filter and forward a plain HTTP request."""
        if config.current_resolver:
            config.current_resolver.maybe_reload_background()

        resolved = self._resolve_target()
        if resolved is None:
            return
        target_host, hostname, target_port, path_only, scheme = resolved

        whitelisted = False
        try:
            if config.current_resolver and config.current_resolver.is_whitelisted(hostname):
                whitelisted = True
        except Exception as e:
            log(f"whitelist check error for {hostname}: {e}")

        if whitelisted:
            log(f"✅ [Liste blanche] {hostname}")
            stats.record("allowed", host=hostname or "", port=target_port,
                         reason="whitelist", proto=self.command)
        else:
            reason = self._policy_verdict(hostname, target_port, tunnel=False)
            if reason is None and (
                config.block_enabled
                and config.block_http_traffic
                and scheme == "http"
            ):
                reason = "http"

            # Revocation traffic is exempt from the "HTTPS only" rule -- see
            # :func:`is_revocation_request`.  Every other verdict, blocklist
            # included, still stands.
            revocation = (
                reason == "http"
                and config.allow_revocation_http
                and is_revocation_request(self.command, path_only, self.headers)
            )
            if revocation:
                reason = None

            if reason is not None:
                self._reject(hostname, target_port, reason, tunnel=False)
                return

            if revocation:
                # Recorded as a system event, not an ordinary allow: this is an
                # exception to a rule the user switched on, and the switch that
                # governs it is no longer in the interface. The Système tab is
                # where it stays auditable.
                log(f"✅ [Révocation de certificat] {hostname}:{target_port}")
                stats.record("system", host=hostname or "", port=target_port,
                             reason="revocation", proto=self.command)
            else:
                stats.record("allowed", host=hostname or "", port=target_port,
                             proto=self.command)

        try:
            request_bytes = self._build_forwarded_request(
                target_host, target_port, path_only, scheme
            )
            log(f"✅ [Autorisé] {target_host}:{target_port}")
            self._forward_to_remote(target_host, target_port, request_bytes)
        except Exception as e:
            stats.record_error()
            stats.record("system", host=hostname or "", port=target_port,
                         detail=f"Connexion impossible: {e}")
            log(f"[Proxy forward error] {e}\n{traceback.format_exc()}")
            with contextlib.suppress(Exception):
                self.send_error(502, "Bad Gateway")

    # ------------------------------------------------------------------
    # HTTP method shortcuts
    # ------------------------------------------------------------------

    def do_GET(self) -> None:
        self._handle_http_method()

    def do_POST(self) -> None:
        self._handle_http_method()

    def do_PUT(self) -> None:
        self._handle_http_method()

    def do_PATCH(self) -> None:
        self._handle_http_method()

    def do_DELETE(self) -> None:
        self._handle_http_method()

    def do_HEAD(self) -> None:
        self._handle_http_method()

    def do_OPTIONS(self) -> None:
        self._handle_http_method()

    def log_message(self, format: str, *args: Any) -> None:
        """Silence default HTTP server logging."""
        return


# ===================================================================
# Server with connection limit
# ===================================================================


class LimitedThreadingHTTPServer(ThreadingHTTPServer):
    """ThreadingHTTPServer with a connection semaphore."""

    daemon_threads: bool = True
    #: Browsers open several tunnels at once; a small backlog causes stalls.
    request_queue_size: int = 512
    allow_reuse_address: bool = True

    def process_request(  # type: ignore[override]
        self,
        request: socket.socket,
        client_address: tuple[str, int],
    ) -> None:
        acquired = config._CONNECTION_SEMAPHORE.acquire(blocking=False)
        if not acquired:
            with contextlib.suppress(Exception):
                request.shutdown(socket.SHUT_RDWR)
            with contextlib.suppress(Exception):
                request.close()
            stats.record_error()
            stats.record(
                "system",
                detail=f"Limite de {config.MAX_PROXY_CONNECTIONS} connexions simultanées "
                f"atteinte — connexion refusée",
            )
            log("❌ Trop de connexions actives")
            return
        return super().process_request(request, client_address)

    def process_request_thread(
        self,
        request: socket.socket,
        client_address: tuple[str, int],
    ) -> None:
        try:
            super().process_request_thread(request, client_address)
        finally:
            config._CONNECTION_SEMAPHORE.release()


# ===================================================================
# Server entry point
# ===================================================================


def _serve_forever_supervised(server: LimitedThreadingHTTPServer) -> None:
    """Run the accept loop, and put it back on its feet if it ever falls over.

    An unsupervised accept loop fails in the worst possible way: the thread
    dies, the listening socket stays open, and the application keeps reporting
    itself as active.  New connections are queued by the operating system until
    the backlog is full and then dropped without a reset, so the client sees a
    SYN that is never answered and retries until it gives up.  Nothing is
    logged, because nothing ever reached the proxy.
    """
    consecutive_failures = 0

    while not config._SHUTDOWN_EVENT.is_set():
        try:
            server.serve_forever(poll_interval=0.2)
            return  # shutdown() was requested: a clean exit
        except Exception as e:
            consecutive_failures += 1
            stats.record_error()
            stats.record("system", detail=f"Boucle d'acceptation interrompue: {e}")
            log(f"[❌] Boucle d'acceptation interrompue: {e}\n{traceback.format_exc()}")

            if consecutive_failures >= 3:
                log("[⚠️] Boucle d'acceptation irrécupérable, reconstruction du serveur.")
                return

            if config._SHUTDOWN_EVENT.wait(1.0):
                return
            log("🔄 Reprise de la boucle d'acceptation.")


def listener_responds(
    bind_ip: str = config.PROXY_BIND_IP,
    port: int = config.PROXY_PORT,
    timeout: float | None = None,
) -> bool:
    """True when a TCP handshake with the proxy's own listening port succeeds.

    Deliberately a real connection rather than an inspection of internal state:
    what breaks is the path between the operating system's accept queue and the
    server, and only completing a handshake exercises it.
    """
    limit = config.PROXY_HEALTHCHECK_TIMEOUT_SECS if timeout is None else timeout
    try:
        with socket.create_connection((bind_ip, port), timeout=limit):
            return True
    except Exception:
        return False


def _health_check_once(bind_ip: str, port: int, failures: int) -> int:
    """Probe the listener once and act on the result. Returns the new failure count.

    Restarting is held back until
    :data:`config.PROXY_HEALTHCHECK_FAILURES_BEFORE_RESTART` consecutive probes
    have failed, so a proxy that is merely busy is not torn down.
    """
    thread = config.proxy_server_thread
    thread_dead = thread is not None and not thread.is_alive()

    if listener_responds(bind_ip, port) and not thread_dead:
        if failures:
            log("Proxy de nouveau joignable.")
            stats.record("system", detail="Proxy de nouveau joignable")
        return 0

    failures += 1
    detail = (
        "Le proxy n'accepte plus de connexions"
        if not thread_dead
        else "La boucle d'acceptation du proxy s'est arrêtée"
    )
    log(f"[⚠️] {detail} ({failures}).")
    stats.record("system", detail=f"{detail} ({failures})")

    if failures >= config.PROXY_HEALTHCHECK_FAILURES_BEFORE_RESTART:
        log("🔄 Redémarrage du serveur proxy.")
        stats.record("system", detail="Redémarrage du serveur proxy")
        if restart_proxy_server(bind_ip, port) is not None:
            return 0

    return failures


def _system_proxy_check(bind_ip: str, port: int) -> None:
    """Put the Windows proxy setting back when it has gone out from under us.

    A listening socket is only half of the protection: nothing reaches it
    unless Windows is still pointing at it.  That registry value is not
    CalmWeb's alone -- a policy refresh, another proxy tool, a VPN client or a
    hand edit in the Windows settings can clear it -- and until now nothing
    would notice.  The tray still said "protection on" while the traffic went
    straight out unfiltered.

    Silent while everything agrees; one line and a system event when it does
    not, so the Système tab records the repair.
    """
    if not config.block_enabled or config.update_in_progress:
        return

    from .platform.windows import (  # noqa: PLC0415
        enable_proxy,
        is_windows,
        system_proxy_is_active,
    )

    if not is_windows() or system_proxy_is_active(bind_ip, port):
        return

    log("[⚠️] Le proxy système n'est plus actif alors que la protection l'est; "
        "reconfiguration.")
    stats.record("system", detail="Proxy système désactivé — reconfiguration")
    enable_proxy(bind_ip, port)


def _health_check_loop(bind_ip: str, port: int) -> None:
    """Probe the listening port until shutdown."""
    failures = 0
    interval = max(5.0, float(config.PROXY_HEALTHCHECK_INTERVAL_SECS))
    while not config._SHUTDOWN_EVENT.wait(interval):
        # The proxy is down on purpose while an update installer is taking
        # over; restarting it here would put the port -- and the system proxy
        # the watchdog implies -- back seconds before the process exits.
        if config.update_in_progress:
            failures = 0
            continue
        try:
            failures = _health_check_once(bind_ip, port, failures)
        except Exception as e:  # the watchdog must never be the thing that dies
            log(f"[Proxy healthcheck error] {e}")
        try:
            _system_proxy_check(bind_ip, port)
        except Exception as e:
            log(f"[Proxy healthcheck error] {e}")


def _request_shutdown(server: LimitedThreadingHTTPServer, timeout: float = 2.0) -> None:
    """Ask *server* to stop accepting, without hanging on it if it will not.

    ``BaseServer.shutdown()`` waits, with no timeout, for the accept loop to
    acknowledge -- and this path exists precisely because the accept loop may
    never acknowledge again.  So the request is made from a throwaway thread,
    given a moment, and the socket is closed either way; closing it unblocks a
    loop stuck in ``select()`` on its own.
    """

    def _ask() -> None:
        with contextlib.suppress(Exception):
            server.shutdown()

    stopper = threading.Thread(target=_ask, daemon=True)
    stopper.start()
    stopper.join(timeout=timeout)


def stop_proxy_server(timeout: float = 2.0) -> None:
    """Stop the listening server and free the port, without hanging on it.

    Idempotent: does nothing when no server is running.  Used both by the
    ordinary shutdown and by the update handover, which has to give the port
    back before the installer starts a freshly installed copy.
    """
    server = config.proxy_server
    if server is None:
        return
    with contextlib.suppress(Exception):
        _request_shutdown(server, timeout=timeout)
    with contextlib.suppress(Exception):
        server.server_close()
    config.proxy_server = None
    config.proxy_server_thread = None
    log("Proxy server stopped.")


def restart_proxy_server(
    bind_ip: str = config.PROXY_BIND_IP,
    port: int = config.PROXY_PORT,
) -> LimitedThreadingHTTPServer | None:
    """Tear the listening socket down and build a new one on the same port."""
    old = config.proxy_server
    if old is not None:
        with contextlib.suppress(Exception):
            _request_shutdown(old)
        with contextlib.suppress(Exception):
            old.server_close()
    config.proxy_server = None
    config.proxy_server_thread = None
    return start_proxy_server(bind_ip, port, with_health_check=False)


def start_proxy_server(
    bind_ip: str = config.PROXY_BIND_IP,
    port: int = config.PROXY_PORT,
    with_health_check: bool = True,
) -> LimitedThreadingHTTPServer | None:
    """Start the threading HTTP proxy server.

    Returns the server object, or ``None`` on error.
    """
    try:
        server = LimitedThreadingHTTPServer((bind_ip, port), BlockProxyHandler)
        config.proxy_server = server
        thread = threading.Thread(
            target=_serve_forever_supervised, args=(server,), daemon=True
        )
        config.proxy_server_thread = thread
        thread.start()
        if with_health_check:
            threading.Thread(
                target=_health_check_loop, args=(bind_ip, port), daemon=True
            ).start()
        log(f"HTTP(S) proxy démarré sur {bind_ip}:{port}")
        return server
    except Exception as e:
        log(f"Erreur lors du démarrage du proxy: {e}")
        return None

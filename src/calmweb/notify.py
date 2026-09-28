"""Desktop notifications for blocked HTTPS connections.

Why this exists
---------------
A blocked ``CONNECT`` cannot show a page.  The client asked for a TLS tunnel
and expects ``200 Connection Established`` followed by raw TLS bytes; the body
of a ``403`` is discarded by every browser, which shows its own transport
error instead (``ERR_TUNNEL_CONNECTION_FAILED``, "the server unexpectedly
dropped the connection").  Nothing in that error names the domain, and nothing
names the rule, so a site CalmWeb blocked on purpose looks exactly like a site
that is down.

Showing the real block page over HTTPS would mean terminating TLS with a
certificate CalmWeb signs itself, which means installing a trusted root
certificate authority on the machine: a private key on disk able to forge any
site to that user.  That is a much larger risk than the problem it solves, so
the user is told out of band instead.

Volume is the hard part
-----------------------
A single blocked page produces dozens of blocked sub-resources within a
second, and one notification per tracker is worse than no notification at all.
Three rules keep it readable:

* only ``CONNECT`` is announced -- a blocked plain-HTTP request already
  receives the real block page, so a notification would just repeat it;
* a given host is announced at most once per :data:`HOST_COOLDOWN_SECS`;
* at most one notification per :data:`MIN_INTERVAL_SECS`, with everything
  blocked in the meantime folded into that single message.
"""

from __future__ import annotations

import threading
import time

from . import config
from .log import log

#: Shortest gap between two notifications, whatever happens in between.
MIN_INTERVAL_SECS: float = 12.0

#: How long a host stays quiet after being announced.  Long enough that
#: reloading a blocked page a few times does not notify again.
HOST_COOLDOWN_SECS: float = 300.0

#: Cap on the "recently announced" table, so a long session on an ad-heavy
#: site cannot grow it without bound.
MAX_RECENT_HOSTS: int = 512

#: Reasons worth announcing.  A malformed request is a client bug, not a
#: filtering decision, and telling the user about it helps nobody.
_ANNOUNCED_REASONS: frozenset[str] = frozenset(
    {"blocklist", "manual", "ip", "http", "port"}
)

_LOCK = threading.Lock()
_WAKE = threading.Event()

#: host -> reason, waiting to be announced.
_pending: dict[str, str] = {}
#: host -> monotonic time it was last announced.
_recent: dict[str, float] = {}
#: When the last notification went out; None until one has.
_last_sent: float | None = None
_worker: threading.Thread | None = None

#: The loopback warning is announced once per run, not once per toggle.
_loopback_announced: bool = False


def _in_cooldown(last: float | None, now: float) -> bool:
    """True when a host was announced recently enough to stay quiet.

    ``last`` is ``None`` when the host has never been announced, and that case
    has to be spelled out rather than stood in for by ``0.0``:
    :func:`time.monotonic` counts from an arbitrary origin -- system boot on
    Windows -- so ``now - 0.0`` is simply the uptime.  With a zero sentinel,
    every host would look as though it had been announced "uptime seconds
    ago", and nothing at all would notify during the first
    :data:`HOST_COOLDOWN_SECS` after every boot.
    """
    return last is not None and (now - last) < HOST_COOLDOWN_SECS


def notify_blocked(host: str | None, reason: str) -> None:
    """Queue a notification for *host*.  Returns immediately; never raises.

    Called from a proxy handler thread, so it must not block: the work is
    handed to a single background thread that owns the pacing.
    """
    try:
        if not config.notify_on_block:
            return
        if reason not in _ANNOUNCED_REASONS:
            return

        hostname = (host or "").strip().lower()
        if not hostname:
            return

        now = time.monotonic()
        with _LOCK:
            if _in_cooldown(_recent.get(hostname), now):
                return
            _recent[hostname] = now
            _prune_recent(now)
            _pending[hostname] = reason

        _ensure_worker()
        _WAKE.set()
    except Exception as e:
        log(f"notify_blocked error: {e}")


def _prune_recent(now: float) -> None:
    """Drop expired, then oldest, entries. Caller holds ``_LOCK``."""
    for hostname, seen in list(_recent.items()):
        if now - seen >= HOST_COOLDOWN_SECS:
            _recent.pop(hostname, None)

    excess = len(_recent) - MAX_RECENT_HOSTS
    if excess > 0:
        for hostname, _seen in sorted(_recent.items(), key=lambda kv: kv[1])[:excess]:
            _recent.pop(hostname, None)


def _due(now: float) -> bool:
    """True when enough time has passed since the last notification.

    Split out from the loop so the pacing rule can be checked directly rather
    than by waiting on a thread.  ``None`` means nothing has been sent yet, so
    the first notification never waits -- see :func:`_in_cooldown` for why the
    absence of a previous time cannot be written as ``0.0``.
    """
    return _last_sent is None or (now - _last_sent) >= MIN_INTERVAL_SECS


def _ensure_worker() -> None:
    """Start the delivery thread on first use. Idempotent."""
    global _worker
    with _LOCK:
        if _worker is not None and _worker.is_alive():
            return
        _worker = threading.Thread(
            target=_deliver_loop, name="calmweb-notify", daemon=True
        )
        _worker.start()


def _deliver_loop() -> None:
    """Drain ``_pending`` no faster than one notification per interval."""
    global _last_sent
    while not config._SHUTDOWN_EVENT.is_set():
        _WAKE.wait(timeout=1.0)
        _WAKE.clear()
        if config._SHUTDOWN_EVENT.is_set():
            return

        batch: dict[str, str] = {}
        with _LOCK:
            if not _pending:
                continue
            now = time.monotonic()
            if not _due(now):
                # Too soon: leave everything queued and let the next tick
                # pick it up, so the wait coalesces instead of dropping.
                continue
            batch = dict(_pending)
            _pending.clear()
            _last_sent = now

        _send(batch)


def _send(batch: dict[str, str]) -> None:
    """Push one notification describing *batch*. Never raises."""
    try:
        from .i18n import t

        hosts = list(batch)
        if not hosts:
            return

        first = hosts[0]
        if len(hosts) == 1:
            body = f"{first}\n{t(f'activity.reason.{batch[first]}')}"
        else:
            body = t("notify.blocked.more", host=first, n=len(hosts) - 1)

        from .tray import show_notification

        show_notification(t("notify.blocked.title"), body)
    except Exception as e:
        log(f"notify send error: {e}")


def notify_loopback_blocked(packages: list[str]) -> None:
    """Announce that isolated Microsoft applications cannot reach the proxy.

    Deliberately **not** governed by ``notify_on_block``.  That option covers
    individual filtering decisions: frequent, debatable, and already visible as
    a page that will not load.  This is a different animal -- a total blackout
    for the applications concerned, with no error message anywhere, because
    Windows drops their connection before the proxy can see it.  The new
    Outlook does not open at all, and nothing on screen says why.

    Announced once per run, however many times the proxy is toggled.
    """
    global _loopback_announced
    try:
        if _loopback_announced or not packages:
            return
        _loopback_announced = True

        from .i18n import t
        from .tray import show_notification

        show_notification(
            t("notify.loopback.title"),
            t("notify.loopback.body", n=len(packages)),
        )
    except Exception as e:
        log(f"notify loopback error: {e}")

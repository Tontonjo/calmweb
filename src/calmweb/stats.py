"""Runtime counters and the structured activity feed used by the GUI.

``log.log()`` keeps producing the human-readable text buffer that the raw
log view shows.  On top of that, the proxy records *structured* events
here so the dashboard can filter by category, count blocked versus
allowed requests, and explain **why** something was blocked without having
to parse localized log lines.
"""

from __future__ import annotations

import threading
import time
from collections import deque
from dataclasses import dataclass, field
from typing import Literal

EventKind = Literal["blocked", "allowed", "system"]

#: How many structured events to keep in memory.
MAX_EVENTS: int = 2000

#: Two blocks of the same host, on the same port, for the same reason, less
#: than this many seconds apart are the same block seen twice.  One refused
#: page produces several: the browser preconnects, retries the CONNECT it was
#: refused, and every frame and sub-resource of the page asks again -- which
#: is why the same line used to appear two or three times in a row in the log
#: and in the activity feed.  The repetitions are still counted (totals,
#: per-reason breakdown, most-blocked hosts); only the feed and the log are
#: spared them.
BLOCK_DEDUP_WINDOW_SECS: float = 10.0

#: Cap on the "already reported" table, so a long session on an ad-heavy site
#: cannot grow it without bound.
MAX_RECENT_BLOCKS: int = 2000


@dataclass(frozen=True)
class Event:
    """One filtering decision (or one notable system message)."""

    ts: float
    kind: EventKind
    host: str = ""
    port: int = 0
    reason: str = ""
    detail: str = ""
    proto: str = ""

    @property
    def clock(self) -> str:
        """Local ``HH:MM:SS`` timestamp."""
        return time.strftime("%H:%M:%S", time.localtime(self.ts))


@dataclass
class _Counters:
    blocked: int = 0
    allowed: int = 0
    tunnels: int = 0
    errors: int = 0
    started_at: float = field(default_factory=time.time)
    #: per-reason breakdown, e.g. ``{"blocklist": 42, "http": 3}``
    reasons: dict[str, int] = field(default_factory=dict)
    #: most frequently blocked hosts
    top_blocked: dict[str, int] = field(default_factory=dict)


_LOCK = threading.RLock()
_counters = _Counters()
_events: deque[Event] = deque(maxlen=MAX_EVENTS)
#: bumped on every change so the GUI can skip redraws when nothing happened
_revision: int = 0

#: live tunnel/relay count, maintained by the proxy
_active_connections: int = 0

#: (host, port, reason) -> time it was last shown, for the dedup above.
_recent_blocks: dict[tuple[str, int, str], float] = {}


# ---------------------------------------------------------------------------
# Recording
# ---------------------------------------------------------------------------


def _is_repeat_block(host: str, port: int, reason: str, now: float) -> bool:
    """True when this exact block was already shown less than the window ago.

    Also stamps the block as shown when it is not a repeat.  The caller holds
    ``_LOCK``.
    """
    key = (host, port, reason)
    last = _recent_blocks.get(key)
    if last is not None and (now - last) < BLOCK_DEDUP_WINDOW_SECS:
        return True

    _recent_blocks[key] = now
    if len(_recent_blocks) > MAX_RECENT_BLOCKS:
        for seen_key, seen_at in list(_recent_blocks.items()):
            if now - seen_at >= BLOCK_DEDUP_WINDOW_SECS:
                _recent_blocks.pop(seen_key, None)
        excess = len(_recent_blocks) - MAX_RECENT_BLOCKS
        if excess > 0:
            for seen_key, _seen_at in sorted(_recent_blocks.items(), key=lambda kv: kv[1])[:excess]:
                _recent_blocks.pop(seen_key, None)
    return False


def _bump_counters(kind: EventKind, host: str, reason: str) -> None:
    """Update the totals for one decision. The caller holds ``_LOCK``."""
    if kind == "blocked":
        _counters.blocked += 1
        if reason:
            _counters.reasons[reason] = _counters.reasons.get(reason, 0) + 1
        if host:
            _counters.top_blocked[host] = _counters.top_blocked.get(host, 0) + 1
            # keep the map bounded on long-running sessions
            if len(_counters.top_blocked) > 5000:
                keep = sorted(
                    _counters.top_blocked.items(), key=lambda kv: kv[1], reverse=True
                )[:1000]
                _counters.top_blocked = dict(keep)
    elif kind == "allowed":
        _counters.allowed += 1


def record(
    kind: EventKind,
    host: str = "",
    port: int = 0,
    reason: str = "",
    detail: str = "",
    proto: str = "",
) -> bool:
    """Append an event and update the counters. Never raises.

    Returns ``True`` when the event was added to the feed and ``False`` when
    it was dropped as a repeat of a block shown less than
    :data:`BLOCK_DEDUP_WINDOW_SECS` ago.  The counters are updated either way,
    so a caller can use the answer to keep the same line out of the log --
    which is the whole point: the numbers stay exact, the reading stays
    readable.
    """
    global _revision
    try:
        now = time.time()
        with _LOCK:
            repeat = kind == "blocked" and _is_repeat_block(
                host or "", int(port or 0), reason or "", now
            )
            _bump_counters(kind, host or "", reason or "")
            if repeat:
                return False

            _events.append(
                Event(
                    ts=now,
                    kind=kind,
                    host=host or "",
                    port=int(port or 0),
                    reason=reason or "",
                    detail=detail or "",
                    proto=proto or "",
                )
            )
            _revision += 1
        return True
    except Exception:  # pragma: no cover - stats must never break the proxy
        return False


def record_error() -> None:
    """Increment the error counter."""
    global _revision
    with _LOCK:
        _counters.errors += 1
        _revision += 1


def connection_opened() -> None:
    """Signal that a relay/tunnel has started."""
    global _active_connections
    with _LOCK:
        _active_connections += 1
        _counters.tunnels += 1


def connection_closed() -> None:
    """Signal that a relay/tunnel has finished."""
    global _active_connections
    with _LOCK:
        _active_connections = max(0, _active_connections - 1)


# ---------------------------------------------------------------------------
# Reading
# ---------------------------------------------------------------------------


def snapshot() -> dict[str, object]:
    """Return a consistent copy of the counters."""
    with _LOCK:
        return {
            "blocked": _counters.blocked,
            "allowed": _counters.allowed,
            "tunnels": _counters.tunnels,
            "errors": _counters.errors,
            "active": _active_connections,
            "uptime": max(0.0, time.time() - _counters.started_at),
            "reasons": dict(_counters.reasons),
            "revision": _revision,
        }


def revision() -> int:
    """Monotonic counter bumped on every recorded event."""
    with _LOCK:
        return _revision


def events(
    kinds: tuple[str, ...] | None = None,
    query: str = "",
    limit: int = 500,
) -> list[Event]:
    """Return the most recent events, newest last.

    *kinds* filters by category, *query* is a case-insensitive substring
    match on the host or detail, *limit* caps the result size.
    """
    query = (query or "").strip().lower()
    with _LOCK:
        source = list(_events)

    out: list[Event] = []
    for event in reversed(source):
        if kinds and event.kind not in kinds:
            continue
        if query and query not in f"{event.host} {event.detail} {event.reason}".lower():
            continue
        out.append(event)
        if len(out) >= limit:
            break
    out.reverse()
    return out


def top_blocked(limit: int = 10) -> list[tuple[str, int]]:
    """Return the most frequently blocked hosts."""
    with _LOCK:
        items = sorted(_counters.top_blocked.items(), key=lambda kv: kv[1], reverse=True)
    return items[:limit]


def format_uptime(seconds: float) -> str:
    """Format *seconds* as ``1 j 02:03`` / ``02:03`` for display."""
    try:
        total = int(max(0, seconds))
        days, rem = divmod(total, 86400)
        hours, rem = divmod(rem, 3600)
        minutes, secs = divmod(rem, 60)
        if days:
            return f"{days} j {hours:02d}:{minutes:02d}"
        if hours:
            return f"{hours:02d}:{minutes:02d}:{secs:02d}"
        return f"{minutes:02d}:{secs:02d}"
    except Exception:
        return "--:--"


def reset() -> None:
    """Clear counters and events (used by the GUI's *Clear* button and tests)."""
    global _counters, _revision
    with _LOCK:
        _counters = _Counters()
        _events.clear()
        _recent_blocks.clear()
        _revision += 1

"""Low-level custom.cfg parsing and writing helpers.

Each function does one clear thing so it can be tested independently.
"""

from __future__ import annotations

import os
from enum import StrEnum
from typing import NamedTuple

from .log import log
from .normalize import normalize_host, normalize_source_url, normalize_whitelist_entry


class CfgSection(StrEnum):
    """Known section headers in custom.cfg."""

    BLOCK = "BLOCK"
    WHITELIST = "WHITELIST"
    OPTIONS = "OPTIONS"
    BLOCK_SOURCES = "BLOCK_SOURCES"
    WHITELIST_SOURCES = "WHITELIST_SOURCES"


class CfgData(NamedTuple):
    """Everything a custom.cfg holds.

    ``block_sources`` and ``whitelist_sources`` are ``None`` when the file has
    no such section at all, which is what a configuration written by an older
    version looks like.  That is not the same as an empty section: the first
    means "you never chose, use the defaults", the second means "I removed
    them all on purpose".  Collapsing the two would quietly resurrect sources
    a user deleted.
    """

    blocked: set[str]
    whitelist: set[str]
    options: dict[str, str]
    block_sources: list[str] | None = None
    whitelist_sources: list[str] | None = None


# Lookup set for fast membership tests
_SECTIONS = frozenset(CfgSection)


# -------------------------------------------------------------------
# Parsing helpers
# -------------------------------------------------------------------


def _normalize_domain(raw: str) -> str:
    """Strip leading dots, lowercase, and strip whitespace."""
    return raw.strip().lower().lstrip(".")


def _parse_section_line(line: str) -> tuple[CfgSection | None, str | None]:
    """Decide whether *line* is a section header or a data value.

    Returns ``(new_section, None)`` when the line is a header like
    ``[BLOCK]``, or ``(None, value)`` when it is a regular data line.
    """
    stripped = line.strip()
    up = stripped.upper()
    # Check for known section headers
    if up.startswith("[") and up.endswith("]"):
        name = up[1:-1]
        if name in _SECTIONS:
            return CfgSection(name), None
    # Not a header -- return current section unchanged and the raw value
    return None, stripped


#: Values accepted as "true" in an option line.
TRUTHY: frozenset[str] = frozenset({"1", "true", "yes", "on"})


def as_bool(value: object, default: bool = False) -> bool:
    """Interpret a raw option value as a boolean."""
    if isinstance(value, bool):
        return value
    if value is None:
        return default
    return str(value).strip().lower() in TRUTHY


def _parse_option_line_raw(line: str) -> tuple[str, str] | None:
    """Parse a ``key = value`` option line into ``(key, raw_value)``.

    The value is kept as text so non-boolean options (``language``,
    ``theme``) survive a round trip.  Returns ``None`` for malformed lines.
    """
    if "=" not in line:
        return None
    try:
        key, val = line.split("=", 1)
        key = key.strip().lower()
        if not key:
            return None
        return key, val.strip()
    except Exception:
        return None


def _parse_option_line(line: str) -> tuple[str, bool] | None:
    """Parse a ``key = value`` option line as a boolean flag.

    Kept for callers (and tests) that only care about on/off options.
    """
    parsed = _parse_option_line_raw(line)
    if parsed is None:
        return None
    return parsed[0], as_bool(parsed[1])


def _append_source(bucket: list[str], value: str) -> None:
    """Add a validated source URL to *bucket*, preserving order, without duplicates."""
    url = normalize_source_url(value)
    if url and url not in bucket:
        bucket.append(url)


def parse_cfg_file(path: str) -> CfgData:
    """Parse a custom.cfg file at *path*.

    Option values come back as raw strings -- use :func:`as_bool` for on/off
    flags.  Tolerant to malformed lines; never raises.
    """
    blocked: set[str] = set()
    whitelist: set[str] = set()
    options: dict[str, str] = {}
    block_sources: list[str] | None = None
    whitelist_sources: list[str] | None = None

    if not os.path.exists(path):
        log(f"custom.cfg not found at {path}")
        return CfgData(blocked, whitelist, options)

    section: CfgSection | None = None
    try:
        with open(path, encoding="utf-8") as f:
            for raw in f:
                try:
                    line = raw.strip()
                    if not line or line.startswith("#"):
                        continue

                    new_section, value = _parse_section_line(line)
                    if new_section is not None:
                        section = new_section
                        # Seeing the header is what marks the section as
                        # present, even when nothing follows it.
                        if section is CfgSection.BLOCK_SOURCES and block_sources is None:
                            block_sources = []
                        elif (
                            section is CfgSection.WHITELIST_SOURCES
                            and whitelist_sources is None
                        ):
                            whitelist_sources = []
                        continue

                    # value is the stripped line content
                    if section is CfgSection.BLOCK:
                        # Keep only standard hosts: a malformed entry would
                        # silently never match anything.
                        host = normalize_host(value)
                        if host:
                            blocked.add(host)
                    elif section is CfgSection.WHITELIST:
                        host, network = normalize_whitelist_entry(value)
                        if host:
                            whitelist.add(host)
                        elif network is not None:
                            whitelist.add(str(network))
                    elif section is CfgSection.BLOCK_SOURCES and block_sources is not None:
                        _append_source(block_sources, value)
                    elif (
                        section is CfgSection.WHITELIST_SOURCES
                        and whitelist_sources is not None
                    ):
                        _append_source(whitelist_sources, value)
                    elif section is CfgSection.OPTIONS:
                        parsed = _parse_option_line_raw(value)
                        if parsed is not None:
                            options[parsed[0]] = parsed[1]
                    else:
                        # Lines before any section header go to blocked
                        blocked.add(_normalize_domain(value))
                except Exception:
                    # Skip problematic line
                    continue
    except Exception as e:
        log(f"Error reading custom.cfg {path}: {e}")

    return CfgData(blocked, whitelist, options, block_sources, whitelist_sources)


# -------------------------------------------------------------------
# Writing helper
# -------------------------------------------------------------------


def _format_option(value: object) -> str:
    """Render an option value for custom.cfg (booleans become 1/0)."""
    if isinstance(value, bool):
        return "1" if value else "0"
    return str(value)


def write_cfg_file(
    path: str,
    blocked_set: set[str],
    whitelist_set: set[str],
    options: dict[str, object],
    block_sources: list[str] | None = None,
    whitelist_sources: list[str] | None = None,
) -> None:
    """Write a complete custom.cfg file.

    Sections are written in the order BLOCK, WHITELIST, BLOCK_SOURCES,
    WHITELIST_SOURCES, OPTIONS.  Source lists keep the order they were given
    in, because that is the order they are downloaded in.

    Never raises; logs errors instead.
    """
    try:
        parent = os.path.dirname(path)
        if parent:
            os.makedirs(parent, exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            # --- BLOCK section ---
            f.write(f"[{CfgSection.BLOCK}]\n")
            for d in sorted(blocked_set):
                f.write(f"{d}\n")

            # --- WHITELIST section ---
            f.write(f"\n[{CfgSection.WHITELIST}]\n")
            for d in sorted(whitelist_set):
                f.write(f"{d}\n")

            # --- Source sections ---
            # Written even when empty so the file always shows what can be
            # edited, and so an empty list survives a round trip.
            f.write(f"\n[{CfgSection.BLOCK_SOURCES}]\n")
            for url in block_sources or []:
                f.write(f"{url}\n")

            f.write(f"\n[{CfgSection.WHITELIST_SOURCES}]\n")
            for url in whitelist_sources or []:
                f.write(f"{url}\n")

            # --- OPTIONS section ---
            f.write(f"\n[{CfgSection.OPTIONS}]\n")
            for key in sorted(options):
                f.write(f"{key} = {_format_option(options[key])}\n")

        log(f"Fichier de configuration créé: {path}")
    except Exception as e:
        log(f"Erreur de création du fichier de configuration {path}: {e}")

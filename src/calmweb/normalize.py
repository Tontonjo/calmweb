"""Normalisation of blocklist / whitelist entries.

Downloaded lists come in several formats and CalmWeb only ever matches on
a *hostname*.  A line has to be reduced to a plain domain or IP before it
is stored, otherwise entries such as ``||ads.example.com^`` are kept
verbatim and can never match a real request.

Formats handled here:

* hosts files -- ``0.0.0.0 ads.example.com``, ``127.0.0.1 a.com b.com``
* plain domain lists -- ``ads.example.com``
* Adblock / AdGuard DNS rules -- ``||ads.example.com^``, ``||a.com^$all``
* dnsmasq / Pi-hole -- ``address=/ads.example.com/0.0.0.0``
* URLs -- ``https://ads.example.com/track?x=1``
* bare IPs -- ``203.0.113.7``

Anything that is not a plain host rule (cosmetic filters, exceptions,
regexes, wildcards, path- or scope-limited rules) is rejected: applying
them at the DNS/CONNECT level would either do nothing or overblock.
"""

from __future__ import annotations

import ipaddress
import re

__all__ = [
    "normalize_domain",
    "normalize_ip",
    "normalize_host",
    "normalize_whitelist_entry",
    "parse_list_line",
    "looks_like_ip",
    "normalize_source_url",
]

# Maximum length of a fully qualified domain name.
MAX_DOMAIN_LEN = 253

# Maximum length of a list source URL. Well past any real one; the cap only
# exists so a pasted wall of text cannot end up stored as a "URL".
MAX_SOURCE_URL_LEN = 2048

# Schemes a downloadable list may use. ``file://`` is kept because the
# red.flag.domains cache is handed to the resolver that way.
SOURCE_SCHEMES = ("https://", "http://", "file://")

# A single DNS label: letters, digits, underscore and hyphen; a hyphen may
# not start or end the label.  Underscores are allowed because real service
# records (``_dmarc.example.com``) use them.
_LABEL_RE = re.compile(r"^[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?$")

# The last label: alphabetic, or a punycode ``xn--`` A-label.
_TLD_RE = re.compile(r"^(?:[a-z]{2,63}|xn--[a-z0-9-]{2,59})$")

# Hostnames that appear in every hosts file but mean nothing to a proxy.
_RESERVED_HOSTS = frozenset(
    {
        "localhost",
        "localhost.localdomain",
        "local",
        "broadcasthost",
        "ip6-localhost",
        "ip6-loopback",
        "ip6-localnet",
        "ip6-mcastprefix",
        "ip6-allnodes",
        "ip6-allrouters",
        "ip6-allhosts",
    }
)

# Suffixes that can never be reached through the proxy.
_RESERVED_SUFFIXES = (".localhost", ".localdomain", ".local", ".invalid")

# Adblock modifiers that still mean "block this whole host".  Any other
# modifier limits the rule to a resource type, a scope or a referrer, which
# a hostname-level filter cannot honour, so such rules are dropped.
_HOST_WIDE_MODIFIERS = frozenset(
    {"all", "important", "doc", "document", "popup", "badfilter-free"}
)

# Line prefixes that mark a comment or a list header.
_COMMENT_PREFIXES = ("#", "!", ";", "//", "[")

# Cosmetic / scriptlet separators -- never hostname rules.
_COSMETIC_MARKERS = ("##", "#@#", "#?#", "#$#", "#%#", "$$", "$@$")


def looks_like_ip(value: str) -> bool:
    """Return True if *value* parses as an IP address."""
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def normalize_ip(raw: str) -> str | None:
    """Return the canonical form of *raw* if it is a routable IP address.

    Loopback, unspecified, private, link-local, multicast and reserved
    addresses are rejected: they are hosts-file sinkholes or LAN addresses,
    never something worth blocking.
    """
    try:
        ip = ipaddress.ip_address(raw.strip())
    except ValueError:
        return None
    if (
        ip.is_unspecified
        or ip.is_loopback
        or ip.is_private
        or ip.is_link_local
        or ip.is_multicast
        or ip.is_reserved
    ):
        return None
    return str(ip)


def normalize_domain(raw: str) -> str | None:
    """Return *raw* as a plain lowercase domain, or ``None`` if it is not one.

    Strips a leading ``*.``, surrounding dots and whitespace, converts
    international names to punycode, and validates every label.
    """
    if not raw:
        return None
    domain = raw.strip().lower().rstrip(".")
    while domain.startswith("*."):
        domain = domain[2:]
    domain = domain.lstrip(".")
    if not domain or " " in domain or "\t" in domain:
        return None

    # International domain -> punycode, so it matches what the proxy sees.
    if not domain.isascii():
        try:
            domain = domain.encode("idna").decode("ascii").lower()
        except Exception:
            return None

    if len(domain) > MAX_DOMAIN_LEN:
        return None
    if looks_like_ip(domain):
        return None
    if domain in _RESERVED_HOSTS or domain.endswith(_RESERVED_SUFFIXES):
        return None

    labels = domain.split(".")
    # A bare label ("localhost", "router") is not a public domain.
    if len(labels) < 2:
        return None
    if not _TLD_RE.match(labels[-1]):
        return None
    for label in labels:
        if not _LABEL_RE.match(label):
            return None
    return domain


def normalize_host(raw: str) -> str | None:
    """Return *raw* as a canonical domain or routable IP, or ``None``."""
    if not raw:
        return None
    value = raw.strip().lower()
    if not value:
        return None
    # Bracketed IPv6 literal, as it appears in URLs and CONNECT targets.
    if value.startswith("[") and value.endswith("]"):
        return normalize_ip(value[1:-1])
    if looks_like_ip(value):
        return normalize_ip(value)
    return normalize_domain(value)


def _strip_scheme(token: str) -> str:
    """Reduce a full URL to its authority.

    Only applied when the token really is a URL: for a bare rule a ``/``
    means a path pattern, which is not a host rule and must be rejected.
    """
    if "://" not in token:
        return token
    token = token.split("://", 1)[1]
    # Cut the path, query and fragment.
    token = re.split(r"[/?#]", token, maxsplit=1)[0]
    # Credentials in a URL authority.
    if "@" in token:
        token = token.rsplit("@", 1)[1]
    return token


def _strip_port(token: str) -> str:
    """Remove a trailing ``:port`` (leaving bare IPv6 literals alone)."""
    if token.startswith("["):
        host, sep, _rest = token.partition("]")
        return host + sep
    if token.count(":") == 1:
        host, _sep, port = token.partition(":")
        if port.isdigit():
            return host
    return token


def _entry_to_host(token: str) -> str | None:
    """Reduce a single list token to a hostname, or ``None`` if unsupported."""
    token = token.strip()
    if not token:
        return None

    # dnsmasq / Pi-hole: address=/example.com/0.0.0.0
    if token.startswith(("address=/", "server=/", "local=/")):
        parts = token.split("/")
        if len(parts) < 2:
            return None
        token = parts[1]

    # Adblock anchors.
    if token.startswith("||"):
        token = token[2:]
    elif token.startswith("|"):
        token = token.lstrip("|")

    # A leading "*." covers the subdomains of a host; matching is already
    # suffix-based, so the bare host is the right entry to keep.  Any other
    # wildcard is rejected further down.
    while token.startswith("*."):
        token = token[2:]

    # Adblock modifiers: keep only rules that apply to the whole host.
    if "$" in token:
        token, _sep, mods = token.partition("$")
        for mod in mods.split(","):
            mod = mod.strip().lstrip("~")
            if mod and mod not in _HOST_WIDE_MODIFIERS:
                return None

    token = token.rstrip("^|")
    token = _strip_scheme(token)

    # A path, a wildcard or a regex is not a host rule.
    if not token or "/" in token or "*" in token or "^" in token:
        return None

    token = _strip_port(token)
    token = token.rstrip("^.")
    return normalize_host(token)


def parse_list_line(line: str) -> list[str]:
    """Return every domain / IP contained in one blocklist or whitelist line.

    Returns an empty list for comments, headers and rules that cannot be
    reduced to a hostname.
    """
    if not line:
        return []
    text = line.strip()
    if not text or text.startswith(_COMMENT_PREFIXES):
        return []
    # Adblock exception rules would *unblock*; they are handled by the
    # whitelist, never by the blocklist, so they are dropped here.
    if text.startswith("@@"):
        return []
    if text.startswith("/") and text.endswith("/"):
        return []
    for marker in _COSMETIC_MARKERS:
        if marker in text:
            return []

    # Inline comments (hosts files use "#", Adblock lists use " !").
    text = text.split("#", 1)[0]
    text = re.split(r"\s!", text, maxsplit=1)[0].strip()
    if not text:
        return []

    tokens = text.split()
    hosts: list[str] = []
    if len(tokens) >= 2 and looks_like_ip(tokens[0]):
        # hosts-file line: the redirect target followed by one or more names.
        for token in tokens[1:]:
            host = _entry_to_host(token)
            if host:
                hosts.append(host)
    else:
        host = _entry_to_host(tokens[0])
        if host:
            hosts.append(host)
    return hosts


def normalize_source_url(raw: str) -> str | None:
    """Validate a blocklist / whitelist **source** URL.

    This is deliberately separate from :func:`normalize_host`: a source is a
    URL to download, not a host to match, and the two must never be confused.
    An entry that is not a usable URL is dropped rather than stored, because
    a silently unusable source looks exactly like a source that returned
    nothing -- the lists just come back smaller with no explanation.

    Returns the cleaned URL, or ``None`` when it cannot be one.
    """
    try:
        value = (raw or "").strip()
        if not value or value.startswith(("#", "!", ";")):
            return None
        if len(value) > MAX_SOURCE_URL_LEN:
            return None

        # A URL never contains whitespace or control characters; a line that
        # does is a pasted fragment, not an address.
        if any(char.isspace() or ord(char) < 0x20 for char in value):
            return None

        lowered = value.lower()
        for scheme in SOURCE_SCHEMES:
            if lowered.startswith(scheme):
                # Normalise the scheme's case, keep the rest verbatim: paths
                # and query strings are case-sensitive.
                rest = value[len(scheme):]
                return scheme + rest if rest else None

        return None
    except Exception:
        return None


def normalize_whitelist_entry(
    entry: str,
) -> tuple[str | None, ipaddress.IPv4Network | ipaddress.IPv6Network | None]:
    """Normalise one whitelist entry.

    Returns ``(host, None)`` for a domain or IP, ``(None, network)`` for a
    CIDR range, or ``(None, None)`` when the entry is not usable.  Unlike
    the blocklist path, private and loopback addresses are kept: allowing a
    machine on the local network is a legitimate thing to do.
    """
    if not entry:
        return None, None
    text = entry.strip().lower()
    if not text or text.startswith(("#", "!", ";")):
        return None, None
    # Adblock exception rule: @@||example.com^
    if text.startswith("@@"):
        text = text[2:]

    candidate = text[1:-1] if text.startswith("[") and text.endswith("]") else text
    if looks_like_ip(candidate):
        return str(ipaddress.ip_address(candidate)), None

    if "/" in text and "://" not in text:
        try:
            return None, ipaddress.ip_network(text, strict=False)
        except ValueError:
            pass

    hosts = parse_list_line(text)
    return (hosts[0] if hosts else None), None

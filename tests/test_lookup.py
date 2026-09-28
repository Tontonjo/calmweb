"""Tests for BlocklistResolver.describe -- the dashboard's domain lookup.

The resolver is built with ``__new__`` so no blocklist is downloaded.
"""

from __future__ import annotations

import ipaddress
import threading

import pytest

from calmweb import config
from calmweb.resolver import BlocklistResolver


def _resolver(blocked=(), whitelist=(), networks=(), blocked_ips=()) -> BlocklistResolver:
    resolver = BlocklistResolver.__new__(BlocklistResolver)
    resolver.blocked_domains = set(blocked)
    resolver.blocked_ips = set(blocked_ips)
    resolver.whitelisted_domains_local = set(whitelist)
    resolver.whitelisted_networks = {ipaddress.ip_network(n) for n in networks}
    resolver._lock = threading.Lock()
    resolver.last_reload = 0.0
    return resolver


@pytest.fixture(autouse=True)
def _clean_config():
    manual, allowed, ip_rule = (
        config.manual_blocked_domains,
        config.whitelisted_domains,
        config.block_ip_direct,
    )
    config.manual_blocked_domains = set()
    config.whitelisted_domains = set()
    config.block_ip_direct = True
    yield
    config.manual_blocked_domains = manual
    config.whitelisted_domains = allowed
    config.block_ip_direct = ip_rule


def test_clean_domain_is_allowed():
    verdict = _resolver().describe("example.com")
    assert verdict == {"host": "example.com", "blocked": False, "source": "none", "match": ""}


def test_blocked_ip_from_a_downloaded_list_is_reported():
    verdict = _resolver(blocked_ips={"203.0.113.9"}).describe("203.0.113.9")
    assert verdict["blocked"] is True
    assert verdict["source"] == "downloaded"


def test_downloaded_list_is_reported():
    verdict = _resolver(blocked={"ads.example"}).describe("ads.example")
    assert verdict["blocked"] is True
    assert verdict["source"] == "downloaded"


def test_parent_domain_match_is_reported():
    verdict = _resolver(blocked={"tracker.example"}).describe("cdn.eu.tracker.example")
    assert verdict["blocked"] is True
    assert verdict["match"] == "tracker.example"


def test_local_blocklist_is_distinguished_from_downloaded():
    config.manual_blocked_domains = {"scam.example"}
    verdict = _resolver(blocked={"scam.example"}).describe("scam.example")
    assert verdict["source"] == "manual"


def test_whitelist_beats_blocklist():
    verdict = _resolver(blocked={"bank.example"}, whitelist={"bank.example"}).describe(
        "bank.example"
    )
    assert verdict["blocked"] is False
    assert verdict["source"] == "whitelist"


def test_direct_ip_is_blocked_when_the_rule_is_on():
    verdict = _resolver().describe("192.0.2.10")
    assert verdict["blocked"] is True
    assert verdict["source"] == "ip"


def test_direct_ip_is_allowed_when_the_rule_is_off():
    config.block_ip_direct = False
    assert _resolver().describe("192.0.2.10")["blocked"] is False


def test_whitelisted_cidr_allows_an_ip():
    verdict = _resolver(networks={"192.0.2.0/24"}).describe("192.0.2.10")
    assert verdict["blocked"] is False
    assert verdict["source"] == "whitelist"


@pytest.mark.parametrize("raw", ["EXAMPLE.com.", "  example.com  ", "example.com"])
def test_hostnames_are_normalised(raw):
    assert _resolver(blocked={"example.com"}).describe(raw)["blocked"] is True


def test_ipv6_literal_in_brackets_is_understood():
    verdict = _resolver().describe("[2001:db8::1]")
    assert verdict["host"] == "2001:db8::1"
    assert verdict["source"] == "ip"


def test_empty_input_is_safe():
    assert _resolver().describe("")["source"] == "none"
    assert _resolver().describe(None)["source"] == "none"


def test_counts_reports_list_sizes():
    config.manual_blocked_domains = {"a.example"}
    counts = _resolver(blocked={"b.example", "c.example"}, whitelist={"d.example"}).counts()
    assert counts["blocked"] == 2
    assert counts["manual"] == 1
    assert counts["whitelist"] == 1


# ===================================================================
# Whitelist ownership: the downloaded list must not swallow the user's
# ===================================================================


class _FakeResponse:
    status = 200

    def __init__(self, data: bytes) -> None:
        self.data = data


class _FakePool:
    """Stands in for urllib3.PoolManager and serves a fixed whitelist."""

    body = b"downloaded-allow.example\n*.wildcard.example\n10.0.0.0/8\n"

    def __init__(self, *args, **kwargs) -> None:
        pass

    def request(self, *args, **kwargs) -> _FakeResponse:
        return _FakeResponse(self.body)


class TestWhitelistOwnership:
    """``config.whitelisted_domains`` holds what the *user* wrote, and only that.

    It is what the Lists page shows and what gets written back to custom.cfg,
    so merging the downloaded whitelist into it would bury the user's own
    entries and copy a thousand foreign domains into their configuration.
    """

    def _load(self, monkeypatch) -> BlocklistResolver:
        import calmweb.resolver as resolver_module

        monkeypatch.setattr(resolver_module.urllib3, "PoolManager", _FakePool)
        resolver = _resolver()
        resolver.whitelist_download_successful = False
        resolver._load_whitelist()
        return resolver

    def test_user_whitelist_survives_a_download(self, monkeypatch):
        config.whitelisted_domains = {"mabanque.example"}
        self._load(monkeypatch)
        assert config.whitelisted_domains == {"mabanque.example"}

    def test_effective_whitelist_merges_both(self, monkeypatch):
        config.whitelisted_domains = {"mabanque.example"}
        resolver = self._load(monkeypatch)
        assert "mabanque.example" in resolver.whitelisted_domains_local
        assert "downloaded-allow.example" in resolver.whitelisted_domains_local
        assert "wildcard.example" in resolver.whitelisted_domains_local
        assert any(str(n) == "10.0.0.0/8" for n in resolver.whitelisted_networks)

    def test_download_success_is_recorded(self, monkeypatch):
        resolver = self._load(monkeypatch)
        assert resolver.whitelist_download_successful is True


class TestUserCidrRanges:
    """A CIDR range written in ``[WHITELIST]`` has to become a *network*.

    ``config.whitelisted_domains`` is a set of strings, so "10.0.0.0/24"
    reaches the resolver as text.  Filed as a hostname it is compared to
    domain names and matches nothing -- which is exactly what a user sees:
    the individual addresses they whitelisted work, their ranges do not.
    """

    def _load(self, monkeypatch) -> BlocklistResolver:
        import calmweb.resolver as resolver_module

        monkeypatch.setattr(resolver_module.urllib3, "PoolManager", _FakePool)
        resolver = _resolver()
        resolver.whitelist_download_successful = False
        resolver._load_whitelist()
        return resolver

    def test_ipv4_range_is_loaded_as_a_network(self, monkeypatch):
        config.whitelisted_domains = {"10.0.0.0/24"}
        resolver = self._load(monkeypatch)
        assert any(str(n) == "10.0.0.0/24" for n in resolver.whitelisted_networks)
        assert "10.0.0.0/24" not in resolver.whitelisted_domains_local

    def test_ipv6_range_allows_an_address_inside_it(self, monkeypatch):
        config.whitelisted_domains = {"2a03:17e0:2:ff::/64"}
        resolver = self._load(monkeypatch)
        assert any(str(n) == "2a03:17e0:2:ff::/64" for n in resolver.whitelisted_networks)
        assert resolver.is_whitelisted("2a03:17e0:2:ff::f:49") is True
        assert resolver.describe("2a03:17e0:2:ff::f:49")["source"] == "whitelist"

    def test_address_outside_the_range_is_not_whitelisted(self, monkeypatch):
        config.whitelisted_domains = {"2a03:17e0:2:ff::/64"}
        resolver = self._load(monkeypatch)
        assert resolver.is_whitelisted("2a03:17e0:2:fe::1") is False

    def test_plain_domains_and_addresses_still_load(self, monkeypatch):
        config.whitelisted_domains = {"mabanque.example", "203.0.113.7"}
        resolver = self._load(monkeypatch)
        assert "mabanque.example" in resolver.whitelisted_domains_local
        assert "203.0.113.7" in resolver.whitelisted_domains_local


@pytest.mark.parametrize(
    "written",
    ["2001:0db8:0000:0000:0000:0000:0000:0001", "2001:DB8::1", "[2001:db8::1]"],
)
def test_whitelisted_ipv6_matches_however_it_is_written(written):
    """The whitelist stores the canonical form; the request may not use it."""
    resolver = _resolver(whitelist={"2001:db8::1"})
    assert resolver.describe(written)["source"] == "whitelist"


# ===================================================================
# Instant allow
# ===================================================================


class TestAllowNow:
    def test_allow_now_unblocks_immediately(self):
        resolver = _resolver(blocked={"teamviewer.example"})
        assert resolver._is_blocked("teamviewer.example") is True

        assert resolver.allow_now("teamviewer.example") is True

        assert resolver.is_whitelisted("teamviewer.example") is True
        assert resolver._is_blocked("teamviewer.example") is False
        assert resolver.describe("teamviewer.example")["source"] == "whitelist"

    def test_subdomains_are_covered(self):
        resolver = _resolver(blocked={"teamviewer.example"})
        resolver.allow_now("teamviewer.example")
        assert resolver._is_blocked("download.eu.teamviewer.example") is False

    def test_input_is_normalised(self):
        resolver = _resolver(blocked={"teamviewer.example"})
        resolver.allow_now("  .TeamViewer.Example.  ")
        assert resolver.is_whitelisted("teamviewer.example") is True

    @pytest.mark.parametrize("value", ["", "   ", None])
    def test_empty_input_is_rejected(self, value):
        assert _resolver().allow_now(value) is False

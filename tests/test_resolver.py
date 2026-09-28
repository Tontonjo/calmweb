"""Tests for calmweb.resolver -- blocklist/whitelist resolution logic.

The resolver decides what gets blocked or allowed. Wrong behaviour here
means security holes (missed blocks) or broken legitimate sites
(false positives).
"""

from __future__ import annotations

import ipaddress
from unittest.mock import MagicMock, patch

import pytest

from calmweb import config
from calmweb.resolver import BlocklistResolver


def _make_resolver(
    blocked: set[str] | None = None,
    whitelisted: set[str] | None = None,
    networks: set | None = None,
) -> BlocklistResolver:
    """Create a BlocklistResolver with no URLs so no HTTP calls happen.

    Then directly populate its internal sets for deterministic testing.
    """
    r = BlocklistResolver(blocklist_urls=[], reload_interval=999999)
    if blocked is not None:
        r.blocked_domains = blocked
    if whitelisted is not None:
        r.whitelisted_domains_local = whitelisted
    if networks is not None:
        r.whitelisted_networks = networks
    return r

class TestLooksLikeIp:
    def test_valid_ipv4(self):
        assert BlocklistResolver._looks_like_ip("192.168.1.1") is True

    def test_valid_ipv6_loopback(self):
        assert BlocklistResolver._looks_like_ip("::1") is True

    def test_valid_ipv6_full(self):
        assert BlocklistResolver._looks_like_ip("2001:db8::1") is True

    def test_domain_name_returns_false(self):
        assert BlocklistResolver._looks_like_ip("example.com") is False

    def test_empty_string_returns_false(self):
        assert BlocklistResolver._looks_like_ip("") is False

    def test_invalid_ip_like_string(self):
        assert BlocklistResolver._looks_like_ip("999.999.999.999") is False

class TestIsWhitelisted:
    def test_exact_match(self):
        r = _make_resolver(whitelisted={"example.com"})
        assert r.is_whitelisted("example.com") is True

    def test_parent_domain_match(self):
        """sub.example.com should be whitelisted when example.com is."""
        r = _make_resolver(whitelisted={"example.com"})
        assert r.is_whitelisted("sub.example.com") is True

    def test_deep_subdomain_match(self):
        r = _make_resolver(whitelisted={"example.com"})
        assert r.is_whitelisted("a.b.c.example.com") is True

    def test_non_matching_domain(self):
        r = _make_resolver(whitelisted={"example.com"})
        assert r.is_whitelisted("evil.com") is False

    def test_empty_hostname(self):
        r = _make_resolver(whitelisted={"example.com"})
        assert r.is_whitelisted("") is False

    def test_none_hostname(self):
        r = _make_resolver(whitelisted={"example.com"})
        assert r.is_whitelisted(None) is False

    def test_whitelisted_ip_exact(self):
        r = _make_resolver(whitelisted={"10.0.0.1"})
        assert r.is_whitelisted("10.0.0.1") is True

    def test_cidr_range_match(self):
        net = ipaddress.ip_network("10.0.0.0/8", strict=False)
        r = _make_resolver(whitelisted=set(), networks={net})
        assert r.is_whitelisted("10.1.2.3") is True

    def test_cidr_range_no_match(self):
        net = ipaddress.ip_network("10.0.0.0/8", strict=False)
        r = _make_resolver(whitelisted=set(), networks={net})
        assert r.is_whitelisted("192.168.1.1") is False

class TestIsBlocked:
    """Tests for the _is_blocked decision logic.

    We reset the relevant config globals before each test to avoid
    cross-test pollution from the module-level mutable state.
    """

    @pytest.fixture(autouse=True)
    def _reset_config(self):
        """Ensure a clean config state for every test."""
        config.block_ip_direct = True
        config.block_enabled = True
        config.manual_blocked_domains = set()
        config.whitelisted_domains = set()
        yield
        # Restore defaults
        config.block_ip_direct = True
        config.block_enabled = True
        config.manual_blocked_domains = {"add.blocked.domain"}
        config.whitelisted_domains = {"add.allowed.domain"}

    def test_blocked_domain_returns_true(self):
        r = _make_resolver(blocked={"evil.com"})
        assert r._is_blocked("evil.com") is True

    def test_unblocked_domain_returns_false(self):
        r = _make_resolver(blocked={"evil.com"})
        assert r._is_blocked("harmless.com") is False

    def test_whitelist_overrides_blocklist(self):
        """A domain in both blocked and whitelisted sets should NOT be blocked."""
        r = _make_resolver(blocked={"overlap.com"}, whitelisted={"overlap.com"})
        assert r._is_blocked("overlap.com") is False

    def test_parent_domain_blocking(self):
        """sub.evil.com should be blocked when evil.com is blocked."""
        r = _make_resolver(blocked={"evil.com"})
        assert r._is_blocked("sub.evil.com") is True

    def test_ip_blocked_when_flag_true(self):
        config.block_ip_direct = True
        r = _make_resolver(blocked=set())
        assert r._is_blocked("93.184.216.34") is True

    def test_ip_not_blocked_when_flag_false(self):
        config.block_ip_direct = False
        r = _make_resolver(blocked=set())
        assert r._is_blocked("93.184.216.34") is False

    def test_whitelisted_ip_not_blocked_even_if_flag_true(self):
        config.block_ip_direct = True
        r = _make_resolver(blocked=set(), whitelisted={"93.184.216.34"})
        assert r._is_blocked("93.184.216.34") is False

    def test_empty_hostname_not_blocked(self):
        r = _make_resolver(blocked={"evil.com"})
        assert r._is_blocked("") is False

    def test_none_hostname_not_blocked(self):
        r = _make_resolver(blocked={"evil.com"})
        assert r._is_blocked(None) is False

    def test_manual_blocked_domains_used(self):
        """Domains in config.manual_blocked_domains are also checked."""
        config.manual_blocked_domains = {"manual-block.com"}
        r = _make_resolver(blocked=set())
        assert r._is_blocked("manual-block.com") is True

class TestBlocklistLineParsing:
    """Verify the parsing logic inside _load_blocklist by feeding
    controlled content through a file:// URL.

    We write a temporary file and use a file:// blocklist URL so the
    resolver loads it without any network access.
    """

    def _load_from_text(self, tmp_path, content: str) -> set[str]:
        """Write content to a file and have the resolver load it."""
        path = tmp_path / "blocklist.txt"
        path.write_text(content, encoding="utf-8")
        url = f"file://{path}"
        r = BlocklistResolver(blocklist_urls=[url], reload_interval=999999)
        return r.blocked_domains

    def test_hosts_format_0000(self, tmp_path):
        domains = self._load_from_text(tmp_path, "0.0.0.0 ads.example.com\n")
        assert "ads.example.com" in domains

    def test_hosts_format_127(self, tmp_path):
        domains = self._load_from_text(tmp_path, "127.0.0.1 ads.example.com\n")
        assert "ads.example.com" in domains

    def test_plain_domain_format(self, tmp_path):
        domains = self._load_from_text(tmp_path, "ads.example.com\n")
        assert "ads.example.com" in domains

    def test_comment_lines_ignored(self, tmp_path):
        domains = self._load_from_text(
            tmp_path,
            "# This is a comment\n"
            "ads.example.com\n",
        )
        assert "ads.example.com" in domains
        assert len(domains) == 1

    def test_inline_comments_stripped(self, tmp_path):
        domains = self._load_from_text(
            tmp_path,
            "ads.example.com # inline comment\n",
        )
        assert "ads.example.com" in domains

    def test_long_domain_skipped(self, tmp_path):
        long_domain = "a" * 254 + ".com"
        domains = self._load_from_text(tmp_path, f"{long_domain}\n")
        assert long_domain not in domains

    def test_leading_dots_stripped(self, tmp_path):
        domains = self._load_from_text(tmp_path, ".ads.example.com\n")
        assert "ads.example.com" in domains
        assert ".ads.example.com" not in domains


class TestWhitelistDownloadStatus:
    """Startup safety relies on whitelist_download_successful in BlocklistResolver."""

    @patch("calmweb.resolver.urllib3.PoolManager")
    def test_whitelist_download_successful_false_when_all_sources_fail(self, mock_pool_cls: MagicMock):
        http = MagicMock()
        http.request.side_effect = Exception("network down")
        mock_pool_cls.return_value = http

        r = BlocklistResolver(blocklist_urls=[], reload_interval=999999)
        assert r.whitelist_download_successful is False

    @patch("calmweb.resolver.urllib3.PoolManager")
    def test_whitelist_download_successful_true_on_success(self, mock_pool_cls: MagicMock):
        http = MagicMock()

        block_resp = MagicMock()
        block_resp.status = 200
        block_resp.data = b""

        whitelist_resp = MagicMock()
        whitelist_resp.status = 200
        whitelist_resp.data = b"good.com\n"

        http.request.side_effect = [block_resp, whitelist_resp]
        mock_pool_cls.return_value = http

        r = BlocklistResolver(blocklist_urls=["https://example.com/blocklist.txt"], reload_interval=999999)
        assert r.whitelist_download_successful is True

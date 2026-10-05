"""Tests for calmweb.domainset and the streaming blocklist loader.

Version: 1.8.4

None of these touch the network: lists are fed through file:// URLs or
directly as bytes.
"""

from __future__ import annotations

import io
import threading
import zipfile

import pytest

from calmweb import config
from calmweb import resolver as resolver_module
from calmweb.domainset import DomainHashBuilder, DomainHashSet
from calmweb.resolver import BlocklistResolver

# ===================================================================
# DomainHashSet / DomainHashBuilder
# ===================================================================


class TestDomainHashSet:
    def test_membership_and_length(self):
        index = DomainHashSet(["a.example", "b.example", "a.example"])

        assert "a.example" in index
        assert "b.example" in index
        assert "c.example" not in index
        assert len(index) == 2

    def test_empty_index_is_falsy_and_matches_nothing(self):
        index = DomainHashSet()

        assert not index
        assert len(index) == 0
        assert "a.example" not in index

    def test_non_strings_are_never_members(self):
        index = DomainHashSet(["a.example"])

        assert None not in index
        assert 42 not in index

    def test_eight_bytes_per_entry(self):
        names = [f"host{i}.example" for i in range(10_000)]

        assert DomainHashSet(names).nbytes == 8 * 10_000


class TestDomainHashBuilder:
    def test_build_deduplicates(self):
        builder = DomainHashBuilder(cap=100)
        for name in ("a.example", "b.example", "a.example"):
            assert builder.add(name) is True

        index = builder.build()

        assert len(index) == 2
        assert "a.example" in index and "b.example" in index

    def test_cap_counts_distinct_names_only(self):
        """Duplicates across lists must not exhaust the cap."""
        builder = DomainHashBuilder(cap=10)
        for _ in range(50):
            for i in range(5):
                assert builder.add(f"dup{i}.example") is True

        assert len(builder.build()) == 5

    def test_cap_stops_and_truncates(self):
        builder = DomainHashBuilder(cap=10)
        accepted = [builder.add(f"host{i}.example") for i in range(25)]

        assert accepted.count(False) >= 1
        assert builder.full is True
        assert len(builder.build()) == 10


# ===================================================================
# Streaming loader
# ===================================================================


def _bare_resolver(urls: list[str]) -> BlocklistResolver:
    """A resolver that has not loaded anything (no network at construction)."""
    resolver = BlocklistResolver.__new__(BlocklistResolver)
    resolver.blocklist_urls = list(urls)
    resolver.blocked_domains = DomainHashSet()
    resolver.blocked_ips = set()
    resolver.last_reload = 0
    resolver._lock = threading.Lock()
    resolver._loading_lock = threading.Lock()
    return resolver


@pytest.fixture(autouse=True)
def _no_trim(monkeypatch):
    calls: list[bool] = []
    monkeypatch.setattr(resolver_module, "_release_memory", lambda: calls.append(True))
    return calls


class TestStreamingLoader:
    def test_text_list_is_loaded_into_the_compact_index(self, tmp_path, _no_trim):
        path = tmp_path / "list.txt"
        path.write_text(
            "# comment\n"
            "0.0.0.0 ads.example.com\r\n"
            "||tracker.example^\n"
            "\n"
            "8.8.8.8\n",
            encoding="utf-8",
        )
        resolver = _bare_resolver([f"file://{path}"])

        resolver._load_blocklist()

        assert isinstance(resolver.blocked_domains, DomainHashSet)
        assert "ads.example.com" in resolver.blocked_domains
        assert "tracker.example" in resolver.blocked_domains
        assert "8.8.8.8" in resolver.blocked_ips
        assert "8.8.8.8" not in resolver.blocked_domains
        assert resolver.last_reload > 0
        assert _no_trim == [True]

    def test_parent_domain_blocks_subdomains(self, tmp_path):
        path = tmp_path / "list.txt"
        path.write_text("scam.example\n", encoding="utf-8")
        resolver = _bare_resolver([f"file://{path}"])
        resolver.whitelisted_domains_local = set()
        resolver.whitelisted_networks = set()
        resolver._load_blocklist()

        assert resolver._is_blocked("login.scam.example") is True
        assert resolver._is_blocked("example") is False

    def test_zip_archives_are_streamed(self, tmp_path):
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, "w") as zf:
            zf.writestr("hosts.txt", "0.0.0.0 zipped.example\n")
            zf.writestr("readme.md", "ignored.example\n")
        path = tmp_path / "list.zip"
        path.write_bytes(buffer.getvalue())
        resolver = _bare_resolver([f"file://{path}"])

        resolver._load_blocklist()

        assert "zipped.example" in resolver.blocked_domains
        assert "ignored.example" not in resolver.blocked_domains

    def test_invalid_utf8_is_skipped_not_fatal(self, tmp_path):
        path = tmp_path / "list.txt"
        path.write_bytes(b"good.example\n\xff\xfe broken\nother.example\n")
        resolver = _bare_resolver([f"file://{path}"])

        resolver._load_blocklist()

        assert "good.example" in resolver.blocked_domains
        assert "other.example" in resolver.blocked_domains

    def test_overlapping_lists_are_counted_once(self, tmp_path):
        first = tmp_path / "a.txt"
        second = tmp_path / "b.txt"
        first.write_text("a.example\nb.example\n", encoding="utf-8")
        second.write_text("b.example\nc.example\n", encoding="utf-8")
        resolver = _bare_resolver([f"file://{first}", f"file://{second}"])

        resolver._load_blocklist()

        assert len(resolver.blocked_domains) == 3

    def test_cap_is_honoured(self, tmp_path, monkeypatch):
        monkeypatch.setattr(config, "MAX_BLOCKED_DOMAINS", 10)
        path = tmp_path / "list.txt"
        path.write_text("".join(f"host{i}.example\n" for i in range(100)), encoding="utf-8")
        resolver = _bare_resolver([f"file://{path}"])

        resolver._load_blocklist()

        assert len(resolver.blocked_domains) == 10

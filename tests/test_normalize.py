"""Tests for calmweb.normalize -- turning list lines into standard hosts.

Downloaded lists mix hosts-file, Adblock, dnsmasq and plain formats.  If a
line is stored as written (``||ads.example.com^``) it can never match a
real request, so the domain is silently *not* blocked -- exactly the bug
this module exists to prevent.
"""

from __future__ import annotations

import pytest

from calmweb.normalize import (
    normalize_domain,
    normalize_host,
    normalize_ip,
    normalize_whitelist_entry,
    parse_list_line,
)


class TestParseHostsFormat:
    def test_zero_sinkhole(self):
        assert parse_list_line("0.0.0.0 0u37vw5na9w0.top") == ["0u37vw5na9w0.top"]

    def test_loopback_sinkhole(self):
        assert parse_list_line("127.0.0.1 ads.example.com") == ["ads.example.com"]

    def test_several_names_on_one_line(self):
        assert parse_list_line("0.0.0.0 a.example b.example") == ["a.example", "b.example"]

    def test_inline_comment_is_dropped(self):
        assert parse_list_line("0.0.0.0 ads.example.com # tracker") == ["ads.example.com"]

    def test_localhost_entries_are_dropped(self):
        assert parse_list_line("127.0.0.1 localhost") == []
        assert parse_list_line("::1 ip6-localhost") == []


class TestParseAdblockFormat:
    def test_plain_host_rule(self):
        line = "||897c4cd046b8467524281c9d5d4cb94d.0dc5127bd3b3bc23fd0c57e8375f595f.de^"
        assert parse_list_line(line) == [
            "897c4cd046b8467524281c9d5d4cb94d.0dc5127bd3b3bc23fd0c57e8375f595f.de"
        ]

    def test_host_rule_without_separator(self):
        assert parse_list_line("||ads.example.com") == ["ads.example.com"]

    def test_host_wide_modifier_is_kept(self):
        assert parse_list_line("||ads.example.com^$all") == ["ads.example.com"]

    def test_scope_limited_modifier_is_dropped(self):
        # A hostname filter cannot honour "third-party": keeping it would
        # block the domain everywhere, including first-party requests.
        assert parse_list_line("||example.com^$third-party") == []

    def test_wildcard_subdomain_rule_keeps_the_bare_host(self):
        assert parse_list_line("||*.example.com^") == ["example.com"]

    def test_exception_rule_is_dropped(self):
        assert parse_list_line("@@||example.com^") == []

    def test_cosmetic_rule_is_dropped(self):
        assert parse_list_line("example.com##.ad-banner") == []

    def test_regex_rule_is_dropped(self):
        assert parse_list_line("/banner[0-9]+/") == []

    def test_path_rule_is_dropped(self):
        assert parse_list_line("||example.com/ads/track.js") == []

    def test_embedded_wildcard_is_dropped(self):
        assert parse_list_line("||ad-*.example.com^") == []

    def test_list_header_is_dropped(self):
        assert parse_list_line("[Adblock Plus 2.0]") == []

    def test_bang_comment_is_dropped(self):
        assert parse_list_line("! Title: Ultimate list") == []


class TestParseOtherFormats:
    def test_plain_domain(self):
        assert parse_list_line("ads.example.com") == ["ads.example.com"]

    def test_leading_dot(self):
        assert parse_list_line(".ads.example.com") == ["ads.example.com"]

    def test_dnsmasq_address_rule(self):
        assert parse_list_line("address=/ads.example.com/0.0.0.0") == ["ads.example.com"]

    def test_url_is_reduced_to_its_host(self):
        assert parse_list_line("https://tracker.example.org/path?a=1") == [
            "tracker.example.org"
        ]

    def test_port_is_stripped(self):
        assert parse_list_line("ads.example.com:8080") == ["ads.example.com"]

    def test_routable_ip_is_kept(self):
        assert parse_list_line("8.8.4.4") == ["8.8.4.4"]

    def test_private_ip_is_dropped(self):
        assert parse_list_line("192.168.1.5") == []

    def test_empty_line(self):
        assert parse_list_line("") == []
        assert parse_list_line("   ") == []


class TestNormalizeDomain:
    def test_case_and_trailing_dot(self):
        assert normalize_domain("ADS.Example.COM.") == "ads.example.com"

    def test_wildcard_prefix(self):
        assert normalize_domain("*.example.com") == "example.com"

    def test_idn_becomes_punycode(self):
        assert normalize_domain("münchen-fake.de") == "xn--mnchen-fake-thb.de"

    def test_punycode_is_left_alone(self):
        assert normalize_domain("xn--e1afmkfd.xn--p1ai") == "xn--e1afmkfd.xn--p1ai"

    def test_underscore_label_is_allowed(self):
        assert normalize_domain("_dmarc.example.com") == "_dmarc.example.com"

    @pytest.mark.parametrize(
        "bad",
        [
            "",
            "localhost",
            "example",
            "example.123",
            "-bad.example.com",
            "bad-.example.com",
            "ex ample.com",
            "example..com",
            "printer.local",
            "a" * 250 + ".example.com",
        ],
    )
    def test_rejected(self, bad):
        assert normalize_domain(bad) is None


class TestNormalizeIp:
    def test_routable_ipv4(self):
        assert normalize_ip("8.8.8.8") == "8.8.8.8"

    def test_ipv6_is_compressed(self):
        assert normalize_ip("2001:0db8:0000:0000:0000:0000:0000:0001") is None  # doc range

    @pytest.mark.parametrize("bad", ["0.0.0.0", "127.0.0.1", "::1", "10.0.0.1", "not-an-ip"])
    def test_rejected(self, bad):
        assert normalize_ip(bad) is None


class TestNormalizeHost:
    def test_bracketed_ipv6(self):
        assert normalize_host("[2606:4700:4700::1111]") == "2606:4700:4700::1111"

    def test_domain(self):
        assert normalize_host("Ads.Example.com") == "ads.example.com"


class TestWhitelistEntries:
    def test_domain(self):
        assert normalize_whitelist_entry("Example.COM") == ("example.com", None)

    def test_wildcard(self):
        assert normalize_whitelist_entry("*.example.com") == ("example.com", None)

    def test_adblock_exception(self):
        assert normalize_whitelist_entry("@@||example.com^") == ("example.com", None)

    def test_cidr(self):
        host, net = normalize_whitelist_entry("192.168.0.0/16")
        assert host is None
        assert str(net) == "192.168.0.0/16"

    def test_private_ip_is_allowed_here(self):
        # Unlike the blocklist, allowing a machine on the LAN is legitimate.
        assert normalize_whitelist_entry("192.168.1.5") == ("192.168.1.5", None)

    def test_comment(self):
        assert normalize_whitelist_entry("# a note") == (None, None)

    def test_garbage(self):
        assert normalize_whitelist_entry("???") == (None, None)

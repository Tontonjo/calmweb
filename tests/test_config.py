"""Tests for calmweb.config_io -- custom.cfg parsing and writing.
"""

from __future__ import annotations

import os

import pytest

from calmweb import config
from calmweb.config_io import parse_custom_cfg, write_default_custom_cfg
from calmweb.parser import _normalize_domain, _parse_option_line, _parse_section_line


def _write_cfg(tmp_path, text: str) -> str:
    """Write *text* into a temporary custom.cfg and return its path."""
    path = str(tmp_path / "custom.cfg")
    with open(path, "w", encoding="utf-8") as f:
        f.write(text)
    return path

def test_parse_valid_config_all_sections(tmp_path):
    """All three sections are parsed into the correct sets / flags."""
    cfg = _write_cfg(
        tmp_path,
        "[BLOCK]\n"
        "evil.com\n"
        "bad.org\n"
        "\n"
        "[WHITELIST]\n"
        "good.com\n"
        "\n"
        "[OPTIONS]\n"
        "block_ip_direct = 0\n"
        "block_http_traffic = 1\n"
        "block_http_other_ports = false\n",
    )
    blocked, whitelist = parse_custom_cfg(cfg)

    assert blocked == {"evil.com", "bad.org"}
    assert whitelist == {"good.com"}
    assert config.block_ip_direct is False
    assert config.block_http_traffic is True
    assert config.block_http_other_ports is False

def test_parse_missing_file_returns_empty(tmp_path):
    """A non-existent path returns empty sets without raising."""
    path = str(tmp_path / "does_not_exist.cfg")
    blocked, whitelist = parse_custom_cfg(path)

    assert blocked == set()
    assert whitelist == set()


def test_parse_empty_file_returns_empty(tmp_path):
    """An empty file returns empty sets."""
    cfg = _write_cfg(tmp_path, "")
    blocked, whitelist = parse_custom_cfg(cfg)

    assert blocked == set()
    assert whitelist == set()

def test_comments_and_blanks_are_ignored(tmp_path):
    """Lines starting with # and blank lines are skipped."""
    cfg = _write_cfg(
        tmp_path,
        "# This is a comment\n"
        "\n"
        "[BLOCK]\n"
        "# another comment\n"
        "evil.com\n"
        "\n"
        "[WHITELIST]\n"
        "good.com\n",
    )
    blocked, whitelist = parse_custom_cfg(cfg)

    assert blocked == {"evil.com"}
    assert whitelist == {"good.com"}

@pytest.mark.parametrize(
    "val,expected",
    [
        ("1", True),
        ("true", True),
        ("yes", True),
        ("on", True),
        ("True", True),
        ("YES", True),
        ("ON", True),
        ("0", False),
        ("false", False),
        ("no", False),
        ("off", False),
        ("anything_else", False),
    ],
)
def test_option_boolean_parsing(tmp_path, val, expected):
    """Various truthy/falsy values are interpreted correctly."""
    cfg = _write_cfg(tmp_path, f"[OPTIONS]\nblock_ip_direct = {val}\n")
    parse_custom_cfg(cfg)

    assert config.block_ip_direct is expected

def test_malformed_option_line_no_equals(tmp_path):
    """A line with no '=' in [OPTIONS] does not crash."""
    cfg = _write_cfg(
        tmp_path,
        "[OPTIONS]\n"
        "this_line_has_no_equals_sign\n"
        "block_ip_direct = 0\n",
    )
    parse_custom_cfg(cfg)
    # The valid line still takes effect
    assert config.block_ip_direct is False

def test_domains_before_section_go_to_blocked(tmp_path):
    """Domains appearing before any [SECTION] header go to blocked set."""
    cfg = _write_cfg(tmp_path, "stray.com\n[WHITELIST]\ngood.com\n")
    blocked, whitelist = parse_custom_cfg(cfg)

    assert "stray.com" in blocked
    assert whitelist == {"good.com"}

def test_leading_dots_are_stripped(tmp_path):
    """Domains like '.example.com' are stored as 'example.com'."""
    cfg = _write_cfg(
        tmp_path,
        "[BLOCK]\n"
        ".evil.com\n"
        "..double.dot.com\n"
        "[WHITELIST]\n"
        ".good.com\n",
    )
    blocked, whitelist = parse_custom_cfg(cfg)

    assert "evil.com" in blocked
    assert "double.dot.com" in blocked
    assert "good.com" in whitelist

def test_write_then_parse_roundtrip(tmp_path):
    """write_default_custom_cfg -> parse_custom_cfg reproduces the data."""
    path = str(tmp_path / "subdir" / "custom.cfg")
    blocked_in = {"block-a.com", "block-b.org"}
    whitelist_in = {"allow-x.com", "allow-y.net"}

    write_default_custom_cfg(path, blocked_in, whitelist_in)
    assert os.path.exists(path)

    blocked_out, whitelist_out = parse_custom_cfg(path)

    assert blocked_out == blocked_in
    assert whitelist_out == whitelist_in
    # Default options should all be truthy after a fresh write
    assert config.block_ip_direct is True
    assert config.block_http_traffic is True
    assert config.block_http_other_ports is True

class TestNormalizeDomain:
    def test_strips_leading_dots(self):
        assert _normalize_domain("..evil.com") == "evil.com"

    def test_lowercases(self):
        assert _normalize_domain("EVIL.COM") == "evil.com"

    def test_strips_whitespace(self):
        assert _normalize_domain("  evil.com  ") == "evil.com"


class TestParseSectionLine:
    def test_recognises_block_header(self):
        new_section, value = _parse_section_line("[BLOCK]")
        assert new_section == "BLOCK"
        assert value is None

    def test_case_insensitive_header(self):
        new_section, _ = _parse_section_line("[whitelist]")
        assert new_section == "WHITELIST"

    def test_regular_line_returns_value(self):
        new_section, value = _parse_section_line("evil.com")
        assert new_section is None
        assert value == "evil.com"


class TestParseOptionLine:
    def test_valid_truthy(self):
        assert _parse_option_line("block_ip_direct = 1") == ("block_ip_direct", True)

    def test_valid_falsy(self):
        assert _parse_option_line("block_ip_direct = 0") == ("block_ip_direct", False)

    def test_no_equals_returns_none(self):
        assert _parse_option_line("no_equals_here") is None


# ===================================================================
# New options: QUIC flag, language and theme
# ===================================================================


class TestInterfaceOptions:
    def test_language_and_theme_round_trip(self, tmp_path):
        cfg = _write_cfg(
            tmp_path,
            "[OPTIONS]\nlanguage = en\ntheme = dark\nnotify_on_block = 1\n",
        )
        parse_custom_cfg(cfg)

        assert config.language == "en"
        assert config.theme == "dark"
        assert config.notify_on_block is True

    def test_unknown_theme_falls_back_to_system(self, tmp_path):
        cfg = _write_cfg(tmp_path, "[OPTIONS]\ntheme = neon\n")
        parse_custom_cfg(cfg)
        assert config.theme == "system"

    def test_defaults_are_restored_when_options_are_absent(self, tmp_path):
        config.notify_on_block = True
        config.theme = "dark"
        cfg = _write_cfg(tmp_path, "[BLOCK]\nevil.com\n")
        parse_custom_cfg(cfg)
        assert config.notify_on_block is False
        assert config.theme == "system"

    def test_notifications_default_to_off_in_a_fresh_file(self, tmp_path):
        path = str(tmp_path / "custom.cfg")
        write_default_custom_cfg(path, set(), set())
        parse_custom_cfg(path)
        assert config.notify_on_block is False

    def test_save_custom_cfg_writes_current_state(self, tmp_path):
        from calmweb.config_io import current_options, save_custom_cfg

        path = str(tmp_path / "saved.cfg")
        config.block_http_traffic = False
        config.language = "en"
        save_custom_cfg(
            path=path,
            blocked_set={"evil.com"},
            whitelist_set={"good.com"},
            options=current_options(),
        )

        blocked, whitelist = parse_custom_cfg(path)
        assert blocked == {"evil.com"}
        assert whitelist == {"good.com"}
        assert config.block_http_traffic is False
        assert config.language == "en"


class TestOptionValueParsing:
    def test_raw_values_are_preserved(self):
        from calmweb.parser import _parse_option_line_raw

        assert _parse_option_line_raw("language = EN") == ("language", "EN")

    def test_as_bool_accepts_the_documented_values(self):
        from calmweb.parser import as_bool

        assert as_bool("yes") is True
        assert as_bool("0") is False
        assert as_bool(None, default=True) is True
        assert as_bool(True) is True


class TestRemovingTheLastEntry:
    """Emptying a section must actually empty the live set.

    Guarding the assignment with ``if blocked:`` made the last entry of a
    list impossible to remove: the previous set stayed in memory and the
    domain kept being blocked for the rest of the session.
    """

    @pytest.fixture(autouse=True)
    def _restore(self):
        blocked, whitelist = config.manual_blocked_domains, config.whitelisted_domains
        yield
        config.manual_blocked_domains, config.whitelisted_domains = blocked, whitelist

    def test_removing_the_last_blocked_domain_takes_effect(self, tmp_path):
        from calmweb.config_io import load_custom_cfg_to_globals

        cfg = _write_cfg(tmp_path, "[BLOCK]\nteamviewer.com\n[WHITELIST]\ngood.com\n")
        load_custom_cfg_to_globals(cfg)
        assert config.manual_blocked_domains == {"teamviewer.com"}

        # The user deletes the only line of the section and saves.
        cfg = _write_cfg(tmp_path, "[BLOCK]\n[WHITELIST]\ngood.com\n")
        load_custom_cfg_to_globals(cfg)
        assert config.manual_blocked_domains == set()
        assert config.whitelisted_domains == {"good.com"}

    def test_removing_the_last_whitelisted_domain_takes_effect(self, tmp_path):
        from calmweb.config_io import load_custom_cfg_to_globals

        cfg = _write_cfg(tmp_path, "[WHITELIST]\ngood.com\n")
        load_custom_cfg_to_globals(cfg)
        assert config.whitelisted_domains == {"good.com"}

        cfg = _write_cfg(tmp_path, "[BLOCK]\nevil.com\n")
        load_custom_cfg_to_globals(cfg)
        assert config.whitelisted_domains == set()

    def test_a_missing_file_leaves_the_lists_alone(self, tmp_path):
        from calmweb.config_io import load_custom_cfg_to_globals

        config.manual_blocked_domains = {"kept.example"}
        config.whitelisted_domains = {"kept-allowed.example"}
        load_custom_cfg_to_globals(str(tmp_path / "nope.cfg"))
        assert config.manual_blocked_domains == {"kept.example"}
        assert config.whitelisted_domains == {"kept-allowed.example"}


class TestSourceUrlNormalisation:
    """A source is a URL to download, never a host to match."""

    def test_https_url_is_kept_verbatim(self):
        from calmweb.normalize import normalize_source_url

        url = "https://example.com/Lists/Hosts.TXT?v=2"
        assert normalize_source_url(url) == url

    def test_scheme_case_is_normalised_but_path_is_not(self):
        from calmweb.normalize import normalize_source_url

        assert normalize_source_url("HTTPS://Example.com/Path") == "https://Example.com/Path"

    def test_file_url_is_accepted(self):
        from calmweb.normalize import normalize_source_url

        assert normalize_source_url("file:///tmp/list.txt") == "file:///tmp/list.txt"

    @pytest.mark.parametrize(
        "value",
        [
            "",
            "   ",
            "# a comment",
            "! adblock comment",
            "example.com",
            "ftp://example.com/list.txt",
            "javascript:alert(1)",
            "https://example.com/a b.txt",
            "https://",
        ],
    )
    def test_rejected_entries(self, value):
        from calmweb.normalize import normalize_source_url

        assert normalize_source_url(value) is None

    def test_over_long_url_is_rejected(self):
        from calmweb.normalize import normalize_source_url

        assert normalize_source_url("https://example.com/" + "a" * 4000) is None


class TestEditableSources:
    """[BLOCK_SOURCES] / [WHITELIST_SOURCES] round trips."""

    @pytest.fixture(autouse=True)
    def _restore(self):
        original = (config.blocklist_source_urls, config.whitelist_source_urls)
        yield
        (config.blocklist_source_urls, config.whitelist_source_urls) = original

    def test_sources_are_read_in_order(self, tmp_path):
        cfg = _write_cfg(
            tmp_path,
            "[BLOCK_SOURCES]\n"
            "https://b.example/list.txt\n"
            "https://a.example/list.txt\n"
            "\n"
            "[WHITELIST_SOURCES]\n"
            "https://w.example/allow.txt\n",
        )
        parse_custom_cfg(cfg)
        assert config.blocklist_source_urls == [
            "https://b.example/list.txt",
            "https://a.example/list.txt",
        ]
        assert config.whitelist_source_urls == ["https://w.example/allow.txt"]

    def test_duplicates_are_dropped_keeping_the_first(self, tmp_path):
        cfg = _write_cfg(
            tmp_path,
            "[BLOCK_SOURCES]\n"
            "https://a.example/list.txt\n"
            "https://b.example/list.txt\n"
            "https://a.example/list.txt\n",
        )
        parse_custom_cfg(cfg)
        assert config.blocklist_source_urls == [
            "https://a.example/list.txt",
            "https://b.example/list.txt",
        ]

    def test_unusable_lines_are_skipped(self, tmp_path):
        cfg = _write_cfg(
            tmp_path,
            "[BLOCK_SOURCES]\n"
            "# a comment\n"
            "not-a-url\n"
            "https://ok.example/list.txt\n",
        )
        parse_custom_cfg(cfg)
        assert config.blocklist_source_urls == ["https://ok.example/list.txt"]

    def test_a_missing_section_restores_the_defaults(self, tmp_path):
        """An older custom.cfg has no source section at all."""
        config.blocklist_source_urls = ["https://stale.example/list.txt"]
        cfg = _write_cfg(tmp_path, "[BLOCK]\nevil.com\n")
        parse_custom_cfg(cfg)
        assert config.blocklist_source_urls == config.DEFAULT_BLOCKLIST_SOURCE_URLS

    def test_an_empty_section_means_no_sources(self, tmp_path):
        """Deleting every source is a choice, not a reason to restore defaults."""
        cfg = _write_cfg(tmp_path, "[BLOCK_SOURCES]\n\n[OPTIONS]\ntheme = dark\n")
        parse_custom_cfg(cfg)
        assert config.blocklist_source_urls == []
        assert config.theme == "dark"

    def test_round_trip_through_save(self, tmp_path):
        from calmweb.config_io import current_options, save_custom_cfg

        path = str(tmp_path / "saved.cfg")
        save_custom_cfg(
            path=path,
            blocked_set=set(),
            whitelist_set=set(),
            options=current_options(),
            block_sources=["https://one.example/l.txt", "https://two.example/l.txt"],
            whitelist_sources=[],
        )
        parse_custom_cfg(path)
        assert config.blocklist_source_urls == [
            "https://one.example/l.txt",
            "https://two.example/l.txt",
        ]
        assert config.whitelist_source_urls == []

    def test_a_fresh_file_carries_the_defaults(self, tmp_path):
        path = str(tmp_path / "custom.cfg")
        write_default_custom_cfg(path, set(), set())
        parse_custom_cfg(path)
        assert config.blocklist_source_urls == config.DEFAULT_BLOCKLIST_SOURCE_URLS
        assert config.whitelist_source_urls == config.DEFAULT_WHITELIST_SOURCE_URLS

    def test_no_sources_means_nothing_is_downloaded(self):
        """Red Flag Domains must not sneak back in when the user emptied the list."""
        from calmweb.config_io import get_blocklist_urls

        config.blocklist_source_urls = []
        assert get_blocklist_urls() == []

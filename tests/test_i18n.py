"""Tests for calmweb.i18n -- the bilingual string table."""

from __future__ import annotations

import pytest

from calmweb import i18n


@pytest.fixture(autouse=True)
def _restore_language():
    original = i18n.get_language()
    yield
    i18n.set_language(original)


def test_every_key_has_both_languages():
    """A missing translation would silently show French to English users."""
    missing = [
        key
        for key, values in i18n.STRINGS.items()
        if not values.get("fr") or not values.get("en")
    ]
    assert missing == []


def test_switching_language_changes_output():
    i18n.set_language("fr")
    french = i18n.t("tab.settings")
    i18n.set_language("en")
    assert i18n.t("tab.settings") != french
    assert i18n.t("tab.settings") == "Settings"


def test_unknown_key_returns_the_key():
    assert i18n.t("this.key.does.not.exist") == "this.key.does.not.exist"


def test_placeholders_are_filled():
    i18n.set_language("en")
    assert i18n.t("activity.count", n=7) == "7 event(s)"


def test_missing_placeholder_does_not_raise():
    # A caller forgetting an argument must not take the interface down.
    assert isinstance(i18n.t("activity.count"), str)


@pytest.mark.parametrize(
    "value,expected",
    [("fr", "fr"), ("FR", "fr"), ("fr-CH", "fr"), ("en", "en"), ("de", "fr"), (None, "fr")],
)
def test_normalize(value, expected):
    assert i18n.normalize(value) == expected


def test_listeners_are_notified():
    seen: list[str] = []
    i18n.set_language("fr")
    i18n.on_language_change(seen.append)
    try:
        i18n.set_language("en")
        i18n.set_language("en")  # no change -> no second notification
    finally:
        i18n.off_language_change(seen.append)
    assert seen == ["en"]

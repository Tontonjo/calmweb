"""Tests for calmweb.stats -- counters and the activity feed."""

from __future__ import annotations

import pytest

from calmweb import stats


@pytest.fixture(autouse=True)
def _clean_stats():
    stats.reset()
    yield
    stats.reset()


def test_counters_follow_recorded_events():
    stats.record("blocked", host="ads.example", reason="blocklist")
    stats.record("blocked", host="ads.example", reason="blocklist")
    stats.record("allowed", host="good.example")

    snapshot = stats.snapshot()
    assert snapshot["blocked"] == 2
    assert snapshot["allowed"] == 1
    assert snapshot["reasons"] == {"blocklist": 2}
    assert stats.top_blocked()[0] == ("ads.example", 2)


def test_events_are_returned_oldest_last():
    stats.record("allowed", host="first.example")
    stats.record("allowed", host="second.example")
    hosts = [event.host for event in stats.events()]
    assert hosts == ["first.example", "second.example"]


def test_events_can_be_filtered_by_kind_and_query():
    stats.record("blocked", host="tracker.example", reason="blocklist")
    stats.record("allowed", host="news.example")

    assert [e.host for e in stats.events(kinds=("blocked",))] == ["tracker.example"]
    assert [e.host for e in stats.events(query="NEWS")] == ["news.example"]
    assert stats.events(query="nothing-matches") == []


def test_limit_keeps_the_most_recent_events():
    for index in range(20):
        stats.record("allowed", host=f"host{index}.example")
    recent = stats.events(limit=3)
    assert [e.host for e in recent] == [
        "host17.example",
        "host18.example",
        "host19.example",
    ]


def test_active_connection_count_never_goes_negative():
    stats.connection_opened()
    stats.connection_closed()
    stats.connection_closed()
    assert stats.snapshot()["active"] == 0


def test_revision_changes_when_something_is_recorded():
    before = stats.revision()
    stats.record("system", detail="hello")
    assert stats.revision() != before


@pytest.mark.parametrize(
    "seconds,expected",
    [(0, "00:00"), (65, "01:05"), (3661, "01:01:01"), (90061, "1 j 01:01")],
)
def test_format_uptime(seconds, expected):
    assert stats.format_uptime(seconds) == expected

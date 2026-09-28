"""Tests for calmweb.notify -- pacing of block notifications.

The point of these is the throttling. A blocked page produces dozens of
blocked sub-resources in a second; the module is only useful if that turns
into one readable message.
"""

from __future__ import annotations

import sys
import types

import pytest

from calmweb import config, notify


@pytest.fixture(autouse=True)
def _isolate(monkeypatch):
    """Give each test a clean queue and a captured, synchronous delivery."""
    sent: list[dict[str, str]] = []
    monkeypatch.setattr(notify, "_pending", {})
    monkeypatch.setattr(notify, "_recent", {})
    monkeypatch.setattr(notify, "_last_sent", None)
    monkeypatch.setattr(notify, "_send", lambda batch: sent.append(dict(batch)))
    # The worker is what would make this asynchronous; the tests drain by hand.
    monkeypatch.setattr(notify, "_ensure_worker", lambda: None)
    monkeypatch.setattr(config, "notify_on_block", True)
    return sent


def _drain() -> dict[str, str]:
    """Take everything queued, as the delivery loop would."""
    batch = dict(notify._pending)
    notify._pending.clear()
    return batch


class TestQueueing:
    def test_a_blocked_host_is_queued(self):
        notify.notify_blocked("ads.example.com", "blocklist")
        assert _drain() == {"ads.example.com": "blocklist"}

    def test_the_host_is_lowercased(self):
        notify.notify_blocked("  ADS.Example.COM  ", "manual")
        assert _drain() == {"ads.example.com": "manual"}

    def test_distinct_hosts_coalesce_into_one_batch(self):
        for host in ("a.example", "b.example", "c.example"):
            notify.notify_blocked(host, "blocklist")
        assert len(_drain()) == 3

    def test_a_repeated_host_is_announced_once(self):
        for _ in range(50):
            notify.notify_blocked("ads.example.com", "blocklist")
        assert _drain() == {"ads.example.com": "blocklist"}

    def test_the_cooldown_expires(self, monkeypatch):
        notify.notify_blocked("ads.example.com", "blocklist")
        _drain()
        # Pretend the host was announced longer ago than the cooldown.
        notify._recent["ads.example.com"] -= notify.HOST_COOLDOWN_SECS + 1
        notify.notify_blocked("ads.example.com", "blocklist")
        assert _drain() == {"ads.example.com": "blocklist"}

    def test_nothing_is_queued_when_the_option_is_off(self, monkeypatch):
        monkeypatch.setattr(config, "notify_on_block", False)
        notify.notify_blocked("ads.example.com", "blocklist")
        assert _drain() == {}

    @pytest.mark.parametrize("reason", ["blocklist", "manual", "ip", "http", "port"])
    def test_filtering_decisions_are_announced(self, reason):
        notify.notify_blocked("x.example", reason)
        assert _drain() == {"x.example": reason}

    def test_a_malformed_request_is_not_announced(self):
        """"invalid" is a client bug, not a filtering decision."""
        notify.notify_blocked("x.example", "invalid")
        assert _drain() == {}

    def test_an_empty_host_is_ignored(self):
        notify.notify_blocked("", "blocklist")
        notify.notify_blocked(None, "blocklist")
        assert _drain() == {}


class TestCooldownSentinel:
    """A monotonic clock counts from an arbitrary origin, not from zero."""

    def test_a_host_never_seen_is_not_in_cooldown(self):
        assert notify._in_cooldown(None, 5.0) is False

    def test_a_recently_seen_host_is_in_cooldown(self):
        assert notify._in_cooldown(100.0, 100.0 + notify.HOST_COOLDOWN_SECS / 2) is True

    def test_the_cooldown_ends(self):
        assert notify._in_cooldown(100.0, 100.0 + notify.HOST_COOLDOWN_SECS) is False

    def test_a_freshly_booted_machine_still_notifies(self):
        """Uptime below the cooldown must not silence every host."""
        assert notify._in_cooldown(None, 3.0) is False

    def test_the_first_notification_never_waits(self, monkeypatch):
        monkeypatch.setattr(notify, "_last_sent", None)
        assert notify._due(2.0) is True


class TestRecentTablePruning:
    def test_expired_entries_are_dropped(self):
        notify._recent["old.example"] = -notify.HOST_COOLDOWN_SECS * 2
        notify.notify_blocked("new.example", "blocklist")
        assert "old.example" not in notify._recent
        assert "new.example" in notify._recent

    def test_the_table_stays_bounded(self):
        for index in range(notify.MAX_RECENT_HOSTS + 200):
            notify.notify_blocked(f"host{index}.example", "blocklist")
        assert len(notify._recent) <= notify.MAX_RECENT_HOSTS


class TestDeliveryPacing:
    """The loop's own rule: never more than one message per interval."""

    def test_nothing_is_due_right_after_a_send(self, monkeypatch):
        monkeypatch.setattr(notify, "_last_sent", 1000.0)
        assert notify._due(1000.0) is False
        assert notify._due(1000.0 + notify.MIN_INTERVAL_SECS / 2) is False

    def test_a_send_is_due_once_the_interval_has_passed(self, monkeypatch):
        monkeypatch.setattr(notify, "_last_sent", 1000.0)
        assert notify._due(1000.0 + notify.MIN_INTERVAL_SECS) is True

    def test_queued_hosts_are_kept_while_waiting(self):
        """Being early must delay the message, never discard what it names."""
        notify.notify_blocked("a.example", "blocklist")
        notify.notify_blocked("b.example", "manual")
        assert set(notify._pending) == {"a.example", "b.example"}


class TestLoopbackNotification:
    """The one failure with no other symptom deserves to be said out loud."""

    @pytest.fixture(autouse=True)
    def _isolate_loopback(self, monkeypatch):
        monkeypatch.setattr(notify, "_loopback_announced", False)
        self.sent: list[tuple[str, str]] = []
        fake_tray = types.ModuleType("calmweb.tray")
        fake_tray.show_notification = lambda title, body: self.sent.append((title, body))
        monkeypatch.setitem(sys.modules, "calmweb.tray", fake_tray)
        yield

    def test_it_announces_once(self):
        notify.notify_loopback_blocked(["Microsoft.OutlookForWindows_8wekyb3d8bbwe"])

        assert len(self.sent) == 1
        title, body = self.sent[0]
        assert title
        assert "administrateur" in body or "administrator" in body

    def test_it_does_not_repeat_on_every_toggle(self):
        notify.notify_loopback_blocked(["a"])
        notify.notify_loopback_blocked(["a"])
        notify.notify_loopback_blocked(["b"])

        assert len(self.sent) == 1

    def test_nothing_missing_means_nothing_said(self):
        notify.notify_loopback_blocked([])

        assert self.sent == []

    def test_it_ignores_the_block_notification_option(self, monkeypatch):
        """notify_on_block governs filtering decisions, not a total blackout."""
        monkeypatch.setattr(config, "notify_on_block", False)

        notify.notify_loopback_blocked(["a"])

        assert len(self.sent) == 1

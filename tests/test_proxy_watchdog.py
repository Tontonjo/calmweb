"""Tests for the accept-loop supervisor and the listening-port watchdog.

A dead accept loop is the one failure the application cannot see from the
inside: the socket stays open, the tray still says "active", and the operating
system drops new connections without a reset once the backlog fills. These
tests pin the two mechanisms that make it visible and recoverable.
"""

from __future__ import annotations

import contextlib
import socket
import threading

import pytest

from calmweb import config, proxy, stats


@pytest.fixture(autouse=True)
def _clean_state():
    original = (config.proxy_server, config.proxy_server_thread)
    config._SHUTDOWN_EVENT.clear()
    stats.reset()
    yield
    config.proxy_server, config.proxy_server_thread = original
    config._SHUTDOWN_EVENT.clear()
    stats.reset()


class _AliveThread:
    def is_alive(self) -> bool:
        return True


class _DeadThread:
    def is_alive(self) -> bool:
        return False


# ===================================================================
# listener_responds
# ===================================================================


def test_listener_responds_to_a_real_listening_socket():
    server = socket.socket()
    server.bind(("127.0.0.1", 0))
    server.listen(4)
    port = server.getsockname()[1]
    try:
        assert proxy.listener_responds("127.0.0.1", port, timeout=2.0) is True
    finally:
        server.close()


def test_listener_does_not_respond_on_a_closed_port():
    # Bind then close, so the port is almost certainly free and unlistened.
    probe = socket.socket()
    probe.bind(("127.0.0.1", 0))
    port = probe.getsockname()[1]
    probe.close()

    assert proxy.listener_responds("127.0.0.1", port, timeout=1.0) is False


# ===================================================================
# _serve_forever_supervised
# ===================================================================


class _FakeServer:
    """Stands in for the HTTP server: serve_forever plays a scripted sequence."""

    def __init__(self, outcomes: list[object]) -> None:
        self.outcomes = list(outcomes)
        self.calls = 0

    def serve_forever(self, poll_interval: float = 0.5) -> None:
        self.calls += 1
        outcome = self.outcomes.pop(0) if self.outcomes else None
        if isinstance(outcome, Exception):
            raise outcome


def test_supervisor_returns_on_a_clean_exit():
    server = _FakeServer([None])

    proxy._serve_forever_supervised(server)

    assert server.calls == 1


def test_supervisor_restarts_the_loop_after_a_crash(monkeypatch):
    monkeypatch.setattr(config._SHUTDOWN_EVENT, "wait", lambda _timeout: False)
    server = _FakeServer([RuntimeError("boom"), None])

    proxy._serve_forever_supervised(server)

    assert server.calls == 2


def test_supervisor_gives_up_instead_of_spinning(monkeypatch):
    """Three failures in a row means the socket itself is gone: hand over to the
    watchdog rather than burning a core retrying."""
    monkeypatch.setattr(config._SHUTDOWN_EVENT, "wait", lambda _timeout: False)
    server = _FakeServer([RuntimeError("boom")] * 10)

    proxy._serve_forever_supervised(server)

    assert server.calls == 3


def test_supervisor_records_the_crash_where_the_user_can_see_it(monkeypatch):
    monkeypatch.setattr(config._SHUTDOWN_EVENT, "wait", lambda _timeout: False)

    proxy._serve_forever_supervised(_FakeServer([RuntimeError("boom"), None]))

    details = [e.detail for e in stats.events(kinds=("system",))]
    assert any("Boucle d'acceptation interrompue" in d for d in details)


# ===================================================================
# _health_check_once
# ===================================================================


def test_healthy_probe_clears_the_failure_count(monkeypatch):
    monkeypatch.setattr(proxy, "listener_responds", lambda *a, **k: True)
    config.proxy_server_thread = _AliveThread()

    assert proxy._health_check_once("127.0.0.1", 8080, failures=1) == 0


def test_first_failure_only_counts(monkeypatch):
    restarts: list = []
    monkeypatch.setattr(proxy, "listener_responds", lambda *a, **k: False)
    monkeypatch.setattr(proxy, "restart_proxy_server", lambda *a: restarts.append(a))
    config.proxy_server_thread = _AliveThread()

    assert proxy._health_check_once("127.0.0.1", 8080, failures=0) == 1
    assert restarts == []


def test_second_failure_restarts_the_server(monkeypatch):
    restarts: list = []
    monkeypatch.setattr(proxy, "listener_responds", lambda *a, **k: False)
    monkeypatch.setattr(
        proxy, "restart_proxy_server", lambda *a: restarts.append(a) or object()
    )
    config.proxy_server_thread = _AliveThread()

    assert proxy._health_check_once("127.0.0.1", 8080, failures=1) == 0
    assert restarts == [("127.0.0.1", 8080)]


def test_a_dead_accept_thread_counts_as_a_failure(monkeypatch):
    """The port can still answer while nothing is being accepted."""
    monkeypatch.setattr(proxy, "listener_responds", lambda *a, **k: True)
    monkeypatch.setattr(proxy, "restart_proxy_server", lambda *a: None)
    config.proxy_server_thread = _DeadThread()

    assert proxy._health_check_once("127.0.0.1", 8080, failures=0) == 1


def test_a_failed_restart_keeps_the_failure_count(monkeypatch):
    monkeypatch.setattr(proxy, "listener_responds", lambda *a, **k: False)
    monkeypatch.setattr(proxy, "restart_proxy_server", lambda *a: None)
    config.proxy_server_thread = _AliveThread()

    assert proxy._health_check_once("127.0.0.1", 8080, failures=1) == 2


def test_recovery_is_announced(monkeypatch):
    monkeypatch.setattr(proxy, "listener_responds", lambda *a, **k: True)
    config.proxy_server_thread = _AliveThread()

    proxy._health_check_once("127.0.0.1", 8080, failures=2)

    details = [e.detail for e in stats.events(kinds=("system",))]
    assert any("joignable" in d for d in details)


# ===================================================================
# Idle tunnels are measured against the clock, not counted in ticks
# ===================================================================


def test_idle_tunnel_closes_on_elapsed_time_not_on_tick_count(monkeypatch):
    """A 30-minute timeout must not need 1800 wake-ups to be reached."""
    monkeypatch.setattr(config, "RELAY_POLL_INTERVAL_SECS", 0.01)

    clock = iter([0.0] + [10_000.0] * 100)
    monkeypatch.setattr(proxy.time, "monotonic", lambda: next(clock))

    left, right = socket.socketpair()
    try:
        done = threading.Event()
        worker = threading.Thread(
            target=lambda: (proxy.full_duplex_relay(left, right), done.set()),
            daemon=True,
        )
        worker.start()
        # Nothing is ever sent: the relay must give up on the clock alone.
        assert done.wait(timeout=5.0), "the relay never reached its idle timeout"
    finally:
        for sock in (left, right):
            with contextlib.suppress(OSError):
                sock.close()


# ===================================================================
# The system proxy setting is watched too
# ===================================================================


class _FakeWindows:
    """Stands in for calmweb.platform.windows inside _system_proxy_check."""

    def __init__(self, active: bool, *, windows: bool = True) -> None:
        self._active = active
        self._windows = windows
        self.enabled: list[tuple[str, int]] = []

    def is_windows(self) -> bool:
        return self._windows

    def system_proxy_is_active(self, host: str, port: int) -> bool:
        return self._active

    def enable_proxy(self, host: str = "127.0.0.1", port: int = 8080) -> bool:
        self.enabled.append((host, port))
        self._active = True
        return True


@pytest.fixture
def _fake_windows(monkeypatch):
    """Install a fake platform.windows the local import will pick up."""

    def _install(active: bool, **kwargs):
        fake = _FakeWindows(active, **kwargs)
        import calmweb.platform.windows as real  # noqa: PLC0415

        for name in ("is_windows", "system_proxy_is_active", "enable_proxy"):
            monkeypatch.setattr(real, name, getattr(fake, name))
        return fake

    return _install


def test_a_proxy_setting_that_went_away_is_put_back(_fake_windows, monkeypatch):
    """A listening socket is only half the protection: nothing reaches it if
    Windows has stopped pointing at it."""
    monkeypatch.setattr(config, "block_enabled", True)
    monkeypatch.setattr(config, "update_in_progress", False)
    fake = _fake_windows(active=False)

    proxy._system_proxy_check("127.0.0.1", 8080)

    assert fake.enabled == [("127.0.0.1", 8080)]
    details = [e.detail for e in stats.events(kinds=("system",))]
    assert any("désactivé" in d for d in details)


def test_nothing_happens_while_the_setting_is_intact(_fake_windows, monkeypatch):
    monkeypatch.setattr(config, "block_enabled", True)
    monkeypatch.setattr(config, "update_in_progress", False)
    fake = _fake_windows(active=True)

    proxy._system_proxy_check("127.0.0.1", 8080)

    assert fake.enabled == []
    assert stats.events(kinds=("system",)) == []


def test_protection_off_means_the_proxy_is_meant_to_be_off(_fake_windows, monkeypatch):
    monkeypatch.setattr(config, "block_enabled", False)
    fake = _fake_windows(active=False)

    proxy._system_proxy_check("127.0.0.1", 8080)

    assert fake.enabled == []


def test_an_update_in_progress_is_left_alone(_fake_windows, monkeypatch):
    """The proxy is down on purpose while the installer takes over."""
    monkeypatch.setattr(config, "block_enabled", True)
    monkeypatch.setattr(config, "update_in_progress", True)
    fake = _fake_windows(active=False)

    proxy._system_proxy_check("127.0.0.1", 8080)

    assert fake.enabled == []

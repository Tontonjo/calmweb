"""Tests for calmweb.platform.windows -- AppContainer loopback exemptions.

Version: 1.8.4

These run on any platform: everything that would touch the real system is
either guarded by ``is_windows()`` or replaced by a fake ``subprocess.run``.
"""

from __future__ import annotations

import subprocess
import sys

import pytest

from calmweb import stats
from calmweb.platform import windows

BROKER = "Microsoft.AAD.BrokerPlugin_cw5n1h2txyewy"

# A trimmed version of what "CheckNetIsolation LoopbackExempt -s" prints.
LISTING_WITH_BROKER = """List Loopback Exempted AppContainers
[1] -----------------------------------------------------------------
    Name: microsoft.aad.brokerplugin_cw5n1h2txyewy
    SID:  S-1-15-2-1234567890-1234567890
"""


class _FakeRun:
    """Records the commands it is asked to run and replays canned results."""

    def __init__(self, results: dict[str, tuple[int, str]] | None = None) -> None:
        self.calls: list[list[str]] = []
        self.results = results or {}

    def __call__(self, args, **kwargs):
        self.calls.append(list(args))
        code, out = 0, ""
        for needle, result in self.results.items():
            if any(needle in part for part in args):
                code, out = result
                break
        return subprocess.CompletedProcess(args, code, stdout=out, stderr="")


class _FakeCtypes:
    """Just enough of ctypes for windows.ctypes.windll.shell32.ShellExecuteW."""

    def __init__(self, shell_execute) -> None:
        shell32 = type("_Shell32", (), {"ShellExecuteW": staticmethod(shell_execute)})()
        self.windll = type("_Windll", (), {"shell32": shell32})()


def _names(calls: list[list[str]], flag: str) -> set[str]:
    """Package names passed to CheckNetIsolation with *flag* (``-a`` / ``-d``)."""
    return {
        part.removeprefix("-n=")
        for args in calls
        if flag in args
        for part in args
        if part.startswith("-n=")
    }


@pytest.fixture(autouse=True)
def _clean_state(monkeypatch: pytest.MonkeyPatch):
    """Pretend to be Windows, with no exemption left over from another test."""
    monkeypatch.setattr(windows, "is_windows", lambda: True)
    monkeypatch.setattr(windows, "is_admin", lambda: True)
    stats.reset()
    yield
    stats.reset()


# ===================================================================
# missing_loopback_exemptions
# ===================================================================


def test_missing_exemptions_skips_packages_already_listed(monkeypatch):
    monkeypatch.setattr(subprocess, "run", _FakeRun({"-s": (0, LISTING_WITH_BROKER)}))

    missing = windows.missing_loopback_exemptions()

    assert BROKER not in missing
    assert set(missing) == set(windows.LOOPBACK_EXEMPT_PACKAGES) - {BROKER}


def test_missing_exemptions_returns_everything_when_listing_fails(monkeypatch):
    monkeypatch.setattr(subprocess, "run", _FakeRun({"-s": (1, "access denied")}))

    assert windows.missing_loopback_exemptions() == list(windows.LOOPBACK_EXEMPT_PACKAGES)


def test_missing_exemptions_is_empty_off_windows(monkeypatch):
    monkeypatch.setattr(windows, "is_windows", lambda: False)

    assert windows.missing_loopback_exemptions() == []


# ===================================================================
# apply_loopback_exemptions
# ===================================================================


def test_apply_adds_only_the_missing_packages(monkeypatch):
    fake = _FakeRun({"-s": (0, LISTING_WITH_BROKER)})
    monkeypatch.setattr(subprocess, "run", fake)

    assert windows.apply_loopback_exemptions() is True

    added = _names(fake.calls, "-a")
    assert BROKER not in added
    assert added == set(windows.LOOPBACK_EXEMPT_PACKAGES) - {BROKER}


def test_apply_is_a_no_op_when_everything_is_exempt(monkeypatch):
    listing = "\n".join(pkg.lower() for pkg in windows.LOOPBACK_EXEMPT_PACKAGES)
    fake = _FakeRun({"-s": (0, listing)})
    monkeypatch.setattr(subprocess, "run", fake)

    assert windows.apply_loopback_exemptions() is True
    assert not any("-a" in args for args in fake.calls)


def test_apply_without_admin_changes_nothing_and_stays_quiet(monkeypatch):
    monkeypatch.setattr(windows, "is_admin", lambda: False)
    fake = _FakeRun({"-s": (0, "")})
    monkeypatch.setattr(subprocess, "run", fake)

    messages: list[str] = []
    monkeypatch.setattr(windows, "log", messages.append)

    assert windows.apply_loopback_exemptions() is False
    assert not any("-a" in args for args in fake.calls)
    # The installer owns the exemptions: a neutral line, no warning.
    assert not any("⚠" in m for m in messages)


def test_apply_reports_failure_but_keeps_going(monkeypatch):
    first = windows.LOOPBACK_EXEMPT_PACKAGES[0]
    fake = _FakeRun({"-s": (0, ""), f"-n={first}": (1, "boom")})
    monkeypatch.setattr(subprocess, "run", fake)

    assert windows.apply_loopback_exemptions() is False
    # The failure does not stop the others from being attempted.
    assert _names(fake.calls, "-a") == set(windows.LOOPBACK_EXEMPT_PACKAGES)


def test_apply_never_raises(monkeypatch):
    def explode(*_args, **_kwargs):
        raise OSError("no such executable")

    monkeypatch.setattr(subprocess, "run", explode)

    assert windows.apply_loopback_exemptions() is False


def test_apply_is_a_no_op_off_windows(monkeypatch):
    monkeypatch.setattr(windows, "is_windows", lambda: False)
    fake = _FakeRun()
    monkeypatch.setattr(subprocess, "run", fake)

    assert windows.apply_loopback_exemptions() is True
    assert fake.calls == []


# ===================================================================
# enable_proxy / disable_proxy wiring
# ===================================================================


def test_enable_proxy_applies_the_exemptions(monkeypatch):
    called: list[str] = []
    monkeypatch.setattr(windows, "_set_registry_proxy", lambda *_: None)
    monkeypatch.setattr(windows, "refresh_internet_settings", lambda: None)
    monkeypatch.setattr(
        windows, "apply_loopback_exemptions", lambda: called.append("apply") or True
    )

    windows.enable_proxy("127.0.0.1", 8080)

    assert called == ["apply"]


def test_disable_proxy_never_removes_the_exemptions(monkeypatch):
    """They are machine-wide and owned by the installer: quitting CalmWeb, or
    one user's session ending, must not cut Outlook and Teams off for all."""
    monkeypatch.setattr(windows, "_set_registry_proxy", lambda *_: None)
    monkeypatch.setattr(windows, "refresh_internet_settings", lambda: None)
    fake = _FakeRun({"-s": (0, "")})
    monkeypatch.setattr(subprocess, "run", fake)
    windows.apply_loopback_exemptions()
    fake.calls.clear()

    windows.disable_proxy()

    assert not any("-d" in args for args in fake.calls)
    assert not hasattr(windows, "remove_loopback_exemptions")


# ===================================================================
# Cross-platform safety of the subprocess helpers
# ===================================================================


def test_creationflags_constant_is_defined_everywhere():
    """The helpers must stay importable and callable off Windows."""
    assert isinstance(windows._NO_WINDOW, int)


# ===================================================================
# The packaged applications, and what the user is told
# ===================================================================


def test_packaged_outlook_and_teams_are_covered():
    """The new Outlook and Teams are AppContainers in their entirety: with the
    proxy on and no exemption they have no network at all and never open."""
    assert "Microsoft.OutlookForWindows_8wekyb3d8bbwe" in windows.LOOPBACK_EXEMPT_PACKAGES
    assert "MSTeams_8wekyb3d8bbwe" in windows.LOOPBACK_EXEMPT_PACKAGES


def test_missing_admin_rights_stay_out_of_the_activity_feed(monkeypatch):
    """Since 1.8.0 the installer sets the exemptions: nothing to report."""
    monkeypatch.setattr(windows, "is_admin", lambda: False)
    monkeypatch.setattr(subprocess, "run", _FakeRun({"-s": (0, "")}))

    windows.apply_loopback_exemptions()

    assert list(stats.events(kinds=("system",))) == []


def test_added_exemptions_reach_the_activity_feed(monkeypatch):
    monkeypatch.setattr(subprocess, "run", _FakeRun({"-s": (0, LISTING_WITH_BROKER)}))

    windows.apply_loopback_exemptions()

    details = [e.detail for e in stats.events(kinds=("system",))]
    assert any("Exemption loopback ajoutée" in d for d in details)


def test_a_refused_exemption_is_reported(monkeypatch):
    first = windows.LOOPBACK_EXEMPT_PACKAGES[0]
    monkeypatch.setattr(
        subprocess, "run", _FakeRun({"-s": (0, ""), f"-n={first}": (1, "denied")})
    )

    windows.apply_loopback_exemptions()

    details = [e.detail for e in stats.events(kinds=("system",))]
    assert any("refusée" in d for d in details)


def test_missing_admin_rights_raise_no_desktop_notification(monkeypatch):
    """The notification is gone: windows no longer imports it at all."""
    monkeypatch.setattr(windows, "is_admin", lambda: False)
    monkeypatch.setattr(subprocess, "run", _FakeRun({"-s": (0, "")}))

    assert not hasattr(windows, "notify_loopback_blocked")
    assert windows.apply_loopback_exemptions() is False


# ===================================================================
# Elevation
# ===================================================================


class TestElevation:
    """CalmWeb offers to restart elevated, and runs anyway when refused."""

    @pytest.fixture(autouse=True)
    def _frozen(self, monkeypatch):
        # Pretend to be the installed executable; a development run has nothing
        # meaningful to relaunch.
        monkeypatch.setattr(sys, "frozen", True, raising=False)
        monkeypatch.setattr(sys, "executable", r"C:\Program Files\CalmWeb\calmweb.exe")
        monkeypatch.setattr(sys, "argv", [r"C:\Program Files\CalmWeb\calmweb.exe"])
        yield

    def _shell_execute(self, monkeypatch, result: int) -> list:
        calls: list = []

        def fake(_hwnd, verb, file, params, _dir, _show):
            calls.append((verb, file, params))
            return result

        monkeypatch.setattr(
            windows, "ctypes", _FakeCtypes(fake), raising=True
        )
        return calls

    # -- elevation_would_help ------------------------------------------

    def test_no_offer_when_already_elevated(self, monkeypatch):
        monkeypatch.setattr(subprocess, "run", _FakeRun({"-s": (0, "")}))

        assert windows.elevation_would_help() is False

    def test_no_offer_once_the_exemptions_are_in_place(self, monkeypatch):
        """The prompt stops as soon as it stops buying anything."""
        monkeypatch.setattr(windows, "is_admin", lambda: False)
        monkeypatch.setattr(windows, "can_elevate_in_place", lambda: True)
        listing = "\n".join(pkg.lower() for pkg in windows.LOOPBACK_EXEMPT_PACKAGES)
        monkeypatch.setattr(subprocess, "run", _FakeRun({"-s": (0, listing)}))

        assert windows.elevation_would_help() is False

    def test_offer_when_an_exemption_is_missing(self, monkeypatch):
        """An administrator running with a filtered token, on a machine where
        UAC elevates without asking: the relaunch is silent and runs CalmWeb
        as the same user."""
        monkeypatch.setattr(windows, "is_admin", lambda: False)
        monkeypatch.setattr(windows, "can_elevate_in_place", lambda: True)
        monkeypatch.setattr(windows, "can_elevate_silently", lambda: True)
        monkeypatch.setattr(subprocess, "run", _FakeRun({"-s": (0, "")}))

        assert windows.elevation_would_help() is True

    def test_never_offer_when_uac_would_prompt(self, monkeypatch):
        """CalmWeb never shows a UAC prompt, even with an exemption missing."""
        monkeypatch.setattr(windows, "is_admin", lambda: False)
        monkeypatch.setattr(windows, "can_elevate_in_place", lambda: True)
        monkeypatch.setattr(windows, "can_elevate_silently", lambda: False)
        monkeypatch.setattr(
            windows, "missing_loopback_exemptions", lambda: pytest.fail("not needed")
        )

        assert windows.elevation_would_help() is False

    # -- relaunch_as_admin ---------------------------------------------

    def test_accepting_starts_an_elevated_copy(self, monkeypatch):
        monkeypatch.setattr(windows, "is_admin", lambda: False)
        calls = self._shell_execute(monkeypatch, result=42)

        assert windows.relaunch_as_admin() is True
        verb, file, params = calls[0]
        assert verb == "runas"
        assert file.endswith("calmweb.exe")
        # The child can never ask again, whatever it thinks of its own token.
        assert windows.NO_ELEVATE_FLAG in params

    def test_declining_is_an_answer_not_an_error(self, monkeypatch):
        """A refused UAC prompt comes back as SE_ERR_ACCESSDENIED."""
        monkeypatch.setattr(windows, "is_admin", lambda: False)
        self._shell_execute(monkeypatch, result=5)

        assert windows.relaunch_as_admin() is False

    def test_any_other_failure_also_lets_calmweb_start(self, monkeypatch):
        monkeypatch.setattr(windows, "is_admin", lambda: False)
        self._shell_execute(monkeypatch, result=2)  # SE_ERR_FNF

        assert windows.relaunch_as_admin() is False

    def test_a_development_run_is_not_relaunched(self, monkeypatch):
        monkeypatch.setattr(windows, "is_admin", lambda: False)
        monkeypatch.setattr(sys, "frozen", False, raising=False)
        calls = self._shell_execute(monkeypatch, result=42)

        assert windows.relaunch_as_admin() is False
        assert calls == []

    def test_a_failing_call_never_raises(self, monkeypatch):
        monkeypatch.setattr(windows, "is_admin", lambda: False)

        def explode(*_a, **_k):
            raise OSError("shell32 unavailable")

        monkeypatch.setattr(windows, "ctypes", _FakeCtypes(explode), raising=True)

        assert windows.relaunch_as_admin() is False

    # -- request_elevation_if_useful -----------------------------------

    def test_the_child_never_asks_again(self, monkeypatch):
        monkeypatch.setattr(windows, "is_admin", lambda: False)
        monkeypatch.setattr(sys, "argv", ["calmweb.exe", windows.NO_ELEVATE_FLAG])
        monkeypatch.setattr(windows, "relaunch_as_admin", lambda: pytest.fail("asked twice"))

        assert windows.request_elevation_if_useful() is False

    def test_it_asks_when_there_is_something_to_gain(self, monkeypatch):
        monkeypatch.setattr(windows, "elevation_would_help", lambda: True)
        monkeypatch.setattr(windows, "relaunch_as_admin", lambda: True)

        assert windows.request_elevation_if_useful() is True

    def test_it_stays_quiet_when_there_is_not(self, monkeypatch):
        monkeypatch.setattr(windows, "elevation_would_help", lambda: False)
        monkeypatch.setattr(windows, "relaunch_as_admin", lambda: pytest.fail("asked"))

        assert windows.request_elevation_if_useful() is False


# ===================================================================
# Elevation gate: who is even allowed to be asked
# ===================================================================


class _FakeToken:
    """Just enough of advapi32/kernel32 for windows.elevation_type()."""

    def __init__(self, elevation_type: int | None) -> None:
        self.elevation_type = elevation_type
        self.closed = False

    @property
    def windll(self):
        outer = self

        class _Advapi32:
            @staticmethod
            def OpenProcessToken(_process, _access, token_ref):
                return 1 if outer.elevation_type is not None else 0

            @staticmethod
            def GetTokenInformation(_token, _cls, value_ref, _size, _returned_ref):
                value_ref._obj.value = outer.elevation_type or 0
                return 1

        class _Kernel32:
            GetCurrentProcess = staticmethod(lambda: -1)

            @staticmethod
            def CloseHandle(_token):
                outer.closed = True
                return 1

        return type(
            "_Windll", (), {"advapi32": _Advapi32(), "kernel32": _Kernel32()}
        )()


class _FakeCtypesToken:
    """windows.ctypes replacement that keeps byref/sizeof working."""

    def __init__(self, elevation_type: int | None) -> None:
        import ctypes as _real

        self._real = _real
        self._token = _FakeToken(elevation_type)
        self.windll = self._token.windll

    def __getattr__(self, name):
        return getattr(self._real, name)


def _token(monkeypatch, elevation_type: int | None):
    fake = _FakeCtypesToken(elevation_type)
    monkeypatch.setattr(windows, "ctypes", fake, raising=True)
    return fake


class TestCanElevateInPlace:
    def test_an_elevated_process_needs_no_check(self, monkeypatch):
        monkeypatch.setattr(windows, "is_admin", lambda: True)

        assert windows.can_elevate_in_place() is True

    def test_a_split_token_administrator_can(self, monkeypatch):
        monkeypatch.setattr(windows, "is_admin", lambda: False)
        _token(monkeypatch, windows._ELEVATION_TYPE_LIMITED)

        assert windows.can_elevate_in_place() is True

    def test_a_standard_account_cannot(self, monkeypatch):
        """No split token and no admin rights: a prompt would ask for someone
        else's password, and the elevated copy would write the proxy into
        someone else's hive."""
        monkeypatch.setattr(windows, "is_admin", lambda: False)
        _token(monkeypatch, windows._ELEVATION_TYPE_DEFAULT)

        assert windows.can_elevate_in_place() is False

    def test_an_unreadable_token_is_treated_as_a_standard_account(self, monkeypatch):
        monkeypatch.setattr(windows, "is_admin", lambda: False)
        _token(monkeypatch, None)

        assert windows.can_elevate_in_place() is False

    def test_a_failing_call_never_raises(self, monkeypatch):
        monkeypatch.setattr(windows, "is_admin", lambda: False)

        class _Boom:
            @property
            def windll(self):
                raise OSError("advapi32 unavailable")

        monkeypatch.setattr(windows, "ctypes", _Boom(), raising=True)

        assert windows.elevation_type() == 0
        assert windows.can_elevate_in_place() is False


class TestStandardAccountIsNeverAsked:
    def test_no_offer_on_an_account_that_cannot_elevate(self, monkeypatch):
        monkeypatch.setattr(windows, "is_admin", lambda: False)
        monkeypatch.setattr(windows, "can_elevate_in_place", lambda: False)
        monkeypatch.setattr(
            subprocess, "run", lambda *a, **k: pytest.fail("checked the exemptions")
        )

        assert windows.elevation_would_help() is False

    def test_the_reason_is_logged_once_and_not_announced(self, monkeypatch):
        monkeypatch.setattr(windows, "is_admin", lambda: False)
        monkeypatch.setattr(windows, "can_elevate_in_place", lambda: False)
        monkeypatch.setattr(windows, "_STANDARD_ACCOUNT_LOGGED", False, raising=False)
        messages: list[str] = []
        monkeypatch.setattr(windows, "log", messages.append)

        windows.elevation_would_help()
        windows.elevation_would_help()

        assert len([m for m in messages if "administrateur" in m]) == 1
        assert list(stats.events(kinds=("system",))) == []

    def test_nothing_is_relaunched_for_a_standard_account(self, monkeypatch):
        monkeypatch.setattr(windows, "is_admin", lambda: False)
        monkeypatch.setattr(windows, "can_elevate_in_place", lambda: False)
        monkeypatch.setattr(sys, "argv", ["calmweb.exe"])
        monkeypatch.setattr(
            windows, "relaunch_as_admin", lambda: pytest.fail("asked a standard user")
        )

        assert windows.request_elevation_if_useful() is False


# ===================================================================
# The proxy is only on when Windows says it is
# ===================================================================


class TestSystemProxyReadback:
    def test_enable_proxy_reports_success_only_when_readable_back(self, monkeypatch):
        monkeypatch.setattr(windows, "_set_registry_proxy", lambda *_: None)
        monkeypatch.setattr(windows, "refresh_internet_settings", lambda: None)
        monkeypatch.setattr(windows, "apply_loopback_exemptions", lambda: True)
        monkeypatch.setattr(windows, "system_proxy_state", lambda: (True, "127.0.0.1:8080"))

        assert windows.enable_proxy("127.0.0.1", 8080) is True

    def test_a_write_that_did_not_take_is_reported(self, monkeypatch):
        """The old code logged success unconditionally -- this is the bug where
        CalmWeb announced a proxy Windows had never been told about."""
        monkeypatch.setattr(windows, "_set_registry_proxy", lambda *_: None)
        monkeypatch.setattr(windows, "refresh_internet_settings", lambda: None)
        monkeypatch.setattr(windows, "apply_loopback_exemptions", lambda: True)
        monkeypatch.setattr(windows, "system_proxy_state", lambda: (False, ""))

        assert windows.enable_proxy("127.0.0.1", 8080) is False
        details = [e.detail for e in stats.events(kinds=("system",))]
        assert any("non actif" in d for d in details)

    def test_another_proxy_in_the_registry_is_not_ours(self, monkeypatch):
        monkeypatch.setattr(
            windows, "system_proxy_state", lambda: (True, "proxy.corp.local:3128")
        )

        assert windows.system_proxy_is_active("127.0.0.1", 8080) is False

    def test_a_registry_write_failure_never_raises(self, monkeypatch):
        def explode(*_a, **_k):
            raise OSError("access denied")

        monkeypatch.setattr(windows, "_set_registry_proxy", explode)
        monkeypatch.setattr(windows, "refresh_internet_settings", lambda: None)
        monkeypatch.setattr(windows, "apply_loopback_exemptions", lambda: True)
        monkeypatch.setattr(windows, "system_proxy_state", lambda: (False, ""))

        assert windows.enable_proxy("127.0.0.1", 8080) is False


# ===================================================================
# Silent elevation: only when UAC would not show a prompt
# ===================================================================


class TestCanElevateSilently:
    def test_already_elevated(self, monkeypatch):
        monkeypatch.setattr(windows, "is_admin", lambda: True)

        assert windows.can_elevate_silently() is True

    def test_filtered_admin_with_elevate_without_prompting(self, monkeypatch):
        monkeypatch.setattr(windows, "is_admin", lambda: False)
        monkeypatch.setattr(windows, "can_elevate_in_place", lambda: True)
        monkeypatch.setattr(windows, "consent_prompt_behavior_admin", lambda: 0)

        assert windows.can_elevate_silently() is True

    @pytest.mark.parametrize("policy", [1, 2, 3, 4, 5, None])
    def test_any_policy_that_prompts_is_refused(self, monkeypatch, policy):
        monkeypatch.setattr(windows, "is_admin", lambda: False)
        monkeypatch.setattr(windows, "can_elevate_in_place", lambda: True)
        monkeypatch.setattr(windows, "consent_prompt_behavior_admin", lambda: policy)

        assert windows.can_elevate_silently() is False

    def test_standard_account_is_refused(self, monkeypatch):
        monkeypatch.setattr(windows, "is_admin", lambda: False)
        monkeypatch.setattr(windows, "can_elevate_in_place", lambda: False)
        monkeypatch.setattr(
            windows, "consent_prompt_behavior_admin", lambda: pytest.fail("not needed")
        )

        assert windows.can_elevate_silently() is False


# ===================================================================
# Proxy switched off on session end and after an unclean exit
# ===================================================================


class TestSessionEnd:
    @pytest.fixture
    def cleared(self, monkeypatch):
        calls: list[str] = []
        monkeypatch.setattr(
            windows, "clear_system_proxy_fast", lambda: calls.append("clear") or True
        )
        return calls

    def test_query_end_session_clears_the_proxy_and_accepts(self, cleared):
        result = windows.handle_session_message(
            windows._WM_QUERYENDSESSION, 0, lambda: pytest.fail("too early"), None
        )

        assert result == 1
        assert cleared == ["clear"]

    def test_end_session_runs_the_full_cleanup(self, cleared):
        ended: list[bool] = []
        result = windows.handle_session_message(
            windows._WM_ENDSESSION, 1, lambda: ended.append(True), None
        )

        assert result == 0
        assert ended == [True]

    def test_cancelled_shutdown_restores_the_protection(self, cleared):
        resumed: list[bool] = []
        result = windows.handle_session_message(
            windows._WM_ENDSESSION,
            0,
            lambda: pytest.fail("session did not end"),
            lambda: resumed.append(True),
        )

        assert result == 0
        assert resumed == [True]

    def test_a_failing_callback_never_raises(self, cleared):
        def explode():
            raise RuntimeError("boom")

        assert windows.handle_session_message(windows._WM_ENDSESSION, 1, explode, None) == 0

    def test_other_messages_go_to_the_default_handler(self, cleared):
        assert windows.handle_session_message(0x0001, 0, None, None) is None
        assert cleared == []

    def test_disable_proxy_writes_the_registry_before_any_child_process(self, monkeypatch):
        order: list[str] = []
        monkeypatch.setattr(
            windows, "_set_registry_proxy", lambda *_: order.append("registry")
        )
        monkeypatch.setattr(windows, "refresh_internet_settings", lambda: None)
        monkeypatch.setattr(
            subprocess, "run", lambda *_a, **_k: order.append("process")
        )

        windows.disable_proxy()

        assert order[0] == "registry"


class TestStaleProxy:
    def test_a_leftover_calmweb_proxy_is_cleared(self, monkeypatch):
        writes: list[tuple] = []
        monkeypatch.setattr(windows, "system_proxy_state", lambda: (True, "127.0.0.1:8080"))
        monkeypatch.setattr(windows, "_set_registry_proxy", lambda *a: writes.append(a))
        monkeypatch.setattr(windows, "refresh_internet_settings", lambda: None)

        assert windows.clear_stale_system_proxy() is True
        assert writes == [(0, "")]

    def test_another_proxy_is_left_alone(self, monkeypatch):
        monkeypatch.setattr(
            windows, "system_proxy_state", lambda: (True, "proxy.corp.local:3128")
        )
        monkeypatch.setattr(
            windows, "_set_registry_proxy", lambda *_: pytest.fail("not ours")
        )

        assert windows.clear_stale_system_proxy() is False

    def test_nothing_to_do_when_the_proxy_is_off(self, monkeypatch):
        monkeypatch.setattr(windows, "system_proxy_state", lambda: (False, ""))
        monkeypatch.setattr(
            windows, "_set_registry_proxy", lambda *_: pytest.fail("already off")
        )

        assert windows.clear_stale_system_proxy() is False


# ===================================================================
# Machine-wide autostart replaces the scheduled task
# ===================================================================


class TestLegacyScheduledTask:
    def test_existing_task_is_deleted(self, monkeypatch):
        fake = _FakeRun({"/Query": (0, "CalmWeb"), "/Delete": (0, "")})
        monkeypatch.setattr(subprocess, "run", fake)

        assert windows.remove_legacy_scheduled_task() is True
        assert any("/Delete" in call for call in fake.calls)

    def test_absent_task_is_not_an_error(self, monkeypatch):
        fake = _FakeRun({"/Query": (1, "")})
        monkeypatch.setattr(subprocess, "run", fake)

        assert windows.remove_legacy_scheduled_task() is True
        assert not any("/Delete" in call for call in fake.calls)

    def test_failed_deletion_is_reported(self, monkeypatch):
        fake = _FakeRun({"/Query": (0, "CalmWeb"), "/Delete": (1, "access denied")})
        monkeypatch.setattr(subprocess, "run", fake)

        assert windows.remove_legacy_scheduled_task() is False

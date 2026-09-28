"""Tests for calmweb.platform.windows -- AppContainer loopback exemptions.

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
    windows._ADDED_LOOPBACK_EXEMPTIONS.clear()
    stats.reset()
    yield
    windows._ADDED_LOOPBACK_EXEMPTIONS.clear()
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
    assert added == windows._ADDED_LOOPBACK_EXEMPTIONS


def test_apply_is_a_no_op_when_everything_is_exempt(monkeypatch):
    listing = "\n".join(pkg.lower() for pkg in windows.LOOPBACK_EXEMPT_PACKAGES)
    fake = _FakeRun({"-s": (0, listing)})
    monkeypatch.setattr(subprocess, "run", fake)

    assert windows.apply_loopback_exemptions() is True
    assert not any("-a" in args for args in fake.calls)
    assert not windows._ADDED_LOOPBACK_EXEMPTIONS


def test_apply_without_admin_changes_nothing_and_reports(monkeypatch):
    monkeypatch.setattr(windows, "is_admin", lambda: False)
    fake = _FakeRun({"-s": (0, "")})
    monkeypatch.setattr(subprocess, "run", fake)

    messages: list[str] = []
    monkeypatch.setattr(windows, "log", messages.append)

    assert windows.apply_loopback_exemptions() is False
    assert not any("-a" in args for args in fake.calls)
    assert not windows._ADDED_LOOPBACK_EXEMPTIONS
    # The user is told what to run rather than left with a silent failure.
    assert any("CheckNetIsolation LoopbackExempt -a" in m for m in messages)


def test_apply_reports_failure_but_keeps_going(monkeypatch):
    first = windows.LOOPBACK_EXEMPT_PACKAGES[0]
    fake = _FakeRun({"-s": (0, ""), f"-n={first}": (1, "boom")})
    monkeypatch.setattr(subprocess, "run", fake)

    assert windows.apply_loopback_exemptions() is False
    # The one that failed is not recorded; the others still are.
    assert first not in windows._ADDED_LOOPBACK_EXEMPTIONS
    expected = set(windows.LOOPBACK_EXEMPT_PACKAGES[1:])
    assert expected == windows._ADDED_LOOPBACK_EXEMPTIONS


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
# remove_loopback_exemptions
# ===================================================================


def test_remove_only_touches_what_this_run_added(monkeypatch):
    fake = _FakeRun({"-s": (0, LISTING_WITH_BROKER)})
    monkeypatch.setattr(subprocess, "run", fake)
    windows.apply_loopback_exemptions()
    fake.calls.clear()

    windows.remove_loopback_exemptions()

    removed = _names(fake.calls, "-d")
    # The exemption that was already there is left alone.
    assert BROKER not in removed
    assert removed == set(windows.LOOPBACK_EXEMPT_PACKAGES) - {BROKER}
    assert not windows._ADDED_LOOPBACK_EXEMPTIONS


def test_remove_is_a_no_op_when_nothing_was_added(monkeypatch):
    fake = _FakeRun()
    monkeypatch.setattr(subprocess, "run", fake)

    windows.remove_loopback_exemptions()

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


def test_disable_proxy_removes_the_exemptions(monkeypatch):
    called: list[str] = []
    monkeypatch.setattr(windows, "_set_registry_proxy", lambda *_: None)
    monkeypatch.setattr(windows, "refresh_internet_settings", lambda: None)
    monkeypatch.setattr(subprocess, "run", _FakeRun())
    monkeypatch.setattr(windows, "remove_loopback_exemptions", lambda: called.append("remove"))

    windows.disable_proxy()

    assert called == ["remove"]


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


def test_missing_admin_rights_reach_the_activity_feed(monkeypatch):
    """The log buffer is not enough: this is the one failure with no other trace."""
    monkeypatch.setattr(windows, "is_admin", lambda: False)
    monkeypatch.setattr(subprocess, "run", _FakeRun({"-s": (0, "")}))

    windows.apply_loopback_exemptions()

    details = [e.detail for e in stats.events(kinds=("system",))]
    assert any("administrateur" in d for d in details)


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


def test_missing_admin_rights_raise_a_desktop_notification(monkeypatch):
    announced: list = []
    monkeypatch.setattr(windows, "is_admin", lambda: False)
    monkeypatch.setattr(windows, "notify_loopback_blocked", announced.append)
    monkeypatch.setattr(subprocess, "run", _FakeRun({"-s": (0, "")}))

    windows.apply_loopback_exemptions()

    assert announced == [list(windows.LOOPBACK_EXEMPT_PACKAGES)]


def test_nothing_is_announced_when_the_exemptions_are_in_place(monkeypatch):
    announced: list = []
    listing = "\n".join(pkg.lower() for pkg in windows.LOOPBACK_EXEMPT_PACKAGES)
    monkeypatch.setattr(windows, "is_admin", lambda: False)
    monkeypatch.setattr(windows, "notify_loopback_blocked", announced.append)
    monkeypatch.setattr(subprocess, "run", _FakeRun({"-s": (0, listing)}))

    windows.apply_loopback_exemptions()

    assert announced == []


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
        """An administrator running with a filtered token is the one account
        the prompt is for: accepting runs CalmWeb as the same user."""
        monkeypatch.setattr(windows, "is_admin", lambda: False)
        monkeypatch.setattr(windows, "can_elevate_in_place", lambda: True)
        monkeypatch.setattr(subprocess, "run", _FakeRun({"-s": (0, "")}))

        assert windows.elevation_would_help() is True

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

    def test_the_reason_is_recorded_once(self, monkeypatch):
        monkeypatch.setattr(windows, "is_admin", lambda: False)
        monkeypatch.setattr(windows, "can_elevate_in_place", lambda: False)
        monkeypatch.setattr(windows, "_STANDARD_ACCOUNT_LOGGED", False, raising=False)

        windows.elevation_would_help()
        windows.elevation_would_help()

        details = [e.detail for e in stats.events(kinds=("system",))]
        events = [d for d in details if "administrateur" in d]
        assert len(events) == 1

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

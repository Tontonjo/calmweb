"""Windows-specific functionality for CalmWeb.

Each function has its own platform guard and returns early / is a no-op
when not running on Windows.
"""

from __future__ import annotations

import atexit
import contextlib
import ctypes
import os
import socket
import subprocess
import sys

try:  # Windows-only; importing the module elsewhere (tests, CI) must still work
    import winreg
except ImportError:  # pragma: no cover - exercised on non-Windows only
    winreg = None  # type: ignore[assignment]

from .. import stats
from ..log import log
from ..notify import notify_loopback_blocked
from . import is_windows

#: ``CREATE_NO_WINDOW`` only exists on Windows. Reading it through getattr
#: keeps every helper below importable -- and unit-testable -- elsewhere,
#: instead of raising AttributeError inside a suppressed try block.
_NO_WINDOW: int = getattr(subprocess, "CREATE_NO_WINDOW", 0)

# ===================================================================
# Firewall rule
# ===================================================================


def add_firewall_rule(target_file: str) -> None:
    """Add a Windows Firewall rule to allow CalmWeb."""
    if not is_windows():
        log("add_firewall_rule: not on Windows, skipping.")
        return
    try:
        subprocess.run(
            [
                "netsh",
                "advfirewall",
                "firewall",
                "add",
                "rule",
                "name=CalmWeb",
                "dir=in",
                "action=allow",
                "program=" + target_file,
                "profile=any",
            ],
            check=True,
            creationflags=_NO_WINDOW,
        )
        log("Règles pare-feu ajoutée")
    except Exception as e:
        log(f"Firewall error: {e}")


# ===================================================================
# Legacy QUIC firewall rule (removed feature)
# ===================================================================

#: Name of the outbound firewall rule that earlier versions installed to
#: block UDP/80 and UDP/443 and force HTTP/3 to fall back to TCP.
#:
#: The option is gone: browsers that see a system proxy already fall back to
#: HTTP/2 over TCP on their own, so the rule enforced something that happens
#: anyway, and it did so for *every* application on the machine -- including
#: ones with no HTTP fallback at all. A rule left behind by an earlier
#: version keeps blocking UDP/443 with nothing left in the interface to turn
#: it off, so it is removed at startup.
QUIC_RULE_NAME: str = "CalmWeb - Force HTTP3 fallback"


def is_admin() -> bool:
    """Return True when the process has administrator rights."""
    if not is_windows():
        return False
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())  # type: ignore[attr-defined]
    except Exception:
        return False


def _run_netsh(args: list[str]) -> tuple[int, str]:
    """Run a netsh command and return ``(returncode, output)``. Never raises."""
    try:
        completed = subprocess.run(
            ["netsh", *args],
            check=False,
            capture_output=True,
            text=True,
            creationflags=_NO_WINDOW,
        )
        return completed.returncode, (completed.stdout or "") + (completed.stderr or "")
    except Exception as e:  # pragma: no cover - depends on the host system
        return 1, str(e)


def quic_rule_present() -> bool:
    """Return True when the QUIC fallback firewall rule is installed."""
    if not is_windows():
        return False
    code, _ = _run_netsh(
        ["advfirewall", "firewall", "show", "rule", f"name={QUIC_RULE_NAME}"]
    )
    return code == 0


def remove_quic_policy() -> bool:
    """Delete the leftover QUIC firewall rule if an earlier version left one.

    Called at startup and again on shutdown.  Returns True when no rule is
    left in place.  Deleting a firewall rule needs administrator rights: when
    they are missing the rule is reported rather than silently kept, because
    the symptom -- UDP/443 blocked machine-wide with no visible cause -- is
    close to impossible to diagnose from the outside.
    """
    if not is_windows():
        return True

    try:
        if not quic_rule_present():
            return True

        if not is_admin():
            log(
                "[⚠️] Une ancienne règle pare-feu CalmWeb bloque encore UDP 443/80. "
                "Relancez CalmWeb en tant qu'administrateur pour la retirer, ou "
                f'supprimez la règle "{QUIC_RULE_NAME}" dans le pare-feu Windows.'
            )
            return False

        code, out = _run_netsh(
            ["advfirewall", "firewall", "delete", "rule", f"name={QUIC_RULE_NAME}"]
        )
        if code == 0:
            log("Ancienne règle pare-feu QUIC retirée.")
            return True
        log(f"[⚠️] Suppression de la règle QUIC impossible: {out.strip()[:200]}")
        return False
    except Exception as e:
        log(f"remove_quic_policy error: {e}")
        return False


# ===================================================================
# AppContainer loopback exemption (Windows modern authentication)
# ===================================================================

#: Package families that must be allowed to reach 127.0.0.1 while the proxy
#: is on.
#:
#: Windows runs every AppContainer (UWP / packaged) process with network
#: isolation, and that isolation forbids connections to the loopback address
#: unless the package is explicitly exempted.  A proxy listening on
#: 127.0.0.1 is therefore invisible to them: the connection is refused by
#: the OS before it reaches CalmWeb, so nothing shows up in the logs.
#:
#: This is what breaks Outlook.  Office no longer authenticates in-process:
#: it delegates to the Web Account Manager, whose broker
#: (``Microsoft.AAD.BrokerPlugin``) is an AppContainer.  With the proxy on
#: and no exemption, the broker cannot reach the network at all, so:
#:
#: * a cold start stalls on "loading profile" -- the initial token is never
#:   issued and Outlook waits on an authentication that cannot complete;
#: * a session that was opened while the proxy was off keeps running on the
#:   token it already had, then silently stops synchronising when that token
#:   expires, which surfaces as "not updated since ...".
#:
#: ``Microsoft.AccountsControl`` is the account-picker UI the broker shows,
#: and ``Microsoft.Windows.CloudExperienceHost`` handles the interactive
#: sign-in and MFA prompts; both sit on the same path.  ``windows_ie_ac_001``
#: is the legacy AppContainer identity still used by embedded web views.
#:
#: The *new* Outlook for Windows and the *new* Teams are not Win32 programs at
#: all -- they are packaged applications, so the isolation applies to the whole
#: application rather than to its sign-in step.  With the proxy on and no
#: exemption they have no network whatsoever and simply never open.
#:
#: How this looks in a capture is worth knowing, because it looks like nothing:
#: the SYN to 127.0.0.1 is dropped by the filtering platform *before* the TCP
#: stack, so there is no RST and no log line anywhere -- the client retransmits
#: twice and gives up. Two processes connecting to the same port at the same
#: second can therefore get opposite answers, one an instant SYN/ACK and the
#: other silence. That asymmetry is the fingerprint: a saturated or dead
#: listener would fail both.
LOOPBACK_EXEMPT_PACKAGES: tuple[str, ...] = (
    "Microsoft.AAD.BrokerPlugin_cw5n1h2txyewy",
    "Microsoft.AccountsControl_cw5n1h2txyewy",
    "Microsoft.Windows.CloudExperienceHost_cw5n1h2txyewy",
    "windows_ie_ac_001",
    # Packaged applications, isolated in their entirety.
    "Microsoft.OutlookForWindows_8wekyb3d8bbwe",
    "MSTeams_8wekyb3d8bbwe",
)

#: Upper bound on a single CheckNetIsolation call, so a hung helper cannot
#: freeze the proxy toggle.
CHECKNETISOLATION_TIMEOUT_SECS: int = 20

#: Exemptions added by *this* run, so shutting down only undoes our own work
#: and never removes one the user (or another proxy tool) set up.
_ADDED_LOOPBACK_EXEMPTIONS: set[str] = set()


def _run_checknetisolation(args: list[str]) -> tuple[int, str]:
    """Run CheckNetIsolation and return ``(returncode, output)``. Never raises."""
    try:
        completed = subprocess.run(
            ["CheckNetIsolation", *args],
            check=False,
            capture_output=True,
            text=True,
            timeout=CHECKNETISOLATION_TIMEOUT_SECS,
            creationflags=_NO_WINDOW,
        )
        return completed.returncode, (completed.stdout or "") + (completed.stderr or "")
    except Exception as e:  # pragma: no cover - depends on the host system
        return 1, str(e)


def loopback_exemptions_present() -> str:
    """Return the current exemption listing, lowercased ("" when unavailable)."""
    code, out = _run_checknetisolation(["LoopbackExempt", "-s"])
    return out.lower() if code == 0 else ""


def missing_loopback_exemptions() -> list[str]:
    """Return the packages in :data:`LOOPBACK_EXEMPT_PACKAGES` not yet exempted."""
    if not is_windows():
        return []
    listing = loopback_exemptions_present()
    return [pkg for pkg in LOOPBACK_EXEMPT_PACKAGES if pkg.lower() not in listing]


def apply_loopback_exemptions() -> bool:
    """Let the Windows authentication brokers reach the proxy on 127.0.0.1.

    Returns True when nothing is left to do -- either every package was
    already exempted, or this call exempted them.  Adding an exemption needs
    administrator rights; without them the packages are named in the log
    along with the command to run once, because the symptom otherwise looks
    like a CalmWeb bug with no trace anywhere: the OS refuses the connection
    before the proxy ever sees it.
    """
    if not is_windows():
        return True

    try:
        missing = missing_loopback_exemptions()
        if not missing:
            stats.record("system", detail="Exemptions loopback déjà en place")
            return True

        if not is_admin():
            commands = "  ".join(
                f'CheckNetIsolation LoopbackExempt -a -n="{pkg}"' for pkg in missing
            )
            message = (
                "Applications Microsoft isolées sans accès au proxy "
                f"({len(missing)}) — droits administrateur requis"
            )
            log(
                "[⚠️] Les applications Microsoft empaquetées (nouvel Outlook, nouveau "
                "Teams) et le courtier d'authentification n'ont pas le droit de joindre "
                "127.0.0.1, donc pas le proxy: elles restent sans réseau et Outlook ne "
                "s'ouvre pas. Relancez CalmWeb en tant qu'administrateur, ou lancez une "
                f"fois dans une invite de commandes administrateur: {commands}"
            )
            stats.record("system", detail=message)
            # The Système tab is no help to someone whose Outlook will not
            # open: they are not looking at CalmWeb, they are looking at an
            # application that does nothing. Say it out loud, once.
            notify_loopback_blocked(missing)
            return False

        complete = True
        for package in missing:
            code, out = _run_checknetisolation(["LoopbackExempt", "-a", f"-n={package}"])
            if code == 0:
                _ADDED_LOOPBACK_EXEMPTIONS.add(package)
                log(f"Exemption loopback ajoutée pour {package}")
                stats.record("system", detail=f"Exemption loopback ajoutée: {package}")
            else:
                complete = False
                log(f"[⚠️] Exemption loopback impossible pour {package}: {out.strip()[:200]}")
                stats.record("system", detail=f"Exemption loopback refusée: {package}")
        return complete
    except Exception as e:
        log(f"apply_loopback_exemptions error: {e}")
        stats.record("system", detail=f"Exemptions loopback: échec ({e})")
        return False


def remove_loopback_exemptions() -> None:
    """Undo the exemptions this run added, leaving pre-existing ones in place."""
    if not is_windows() or not _ADDED_LOOPBACK_EXEMPTIONS:
        return
    for package in sorted(_ADDED_LOOPBACK_EXEMPTIONS):
        code, out = _run_checknetisolation(["LoopbackExempt", "-d", f"-n={package}"])
        if code != 0:
            log(
                f"[⚠️] Retrait de l'exemption loopback impossible pour {package}: "
                f"{out.strip()[:200]}"
            )
    _ADDED_LOOPBACK_EXEMPTIONS.clear()


# ===================================================================
# Elevation
# ===================================================================

#: Passed to the elevated copy so it can never ask a second time, whatever
#: :func:`is_admin` reports once it is running.
NO_ELEVATE_FLAG: str = "--no-elevate"

#: ShellExecuteW returns a value of 32 or less on failure, and a UAC prompt
#: answered with "no" arrives as this one -- an answer, not an error.
_SE_ERR_ACCESSDENIED: int = 5

#: ``TOKEN_QUERY`` and the ``TokenElevationType`` information class, so the
#: token can be asked what kind of account it belongs to.
_TOKEN_QUERY: int = 0x0008
_TOKEN_ELEVATION_TYPE: int = 18

#: The three answers ``TokenElevationType`` can give.
#:
#: * ``DEFAULT`` -- no split token: either UAC is off, or this is a standard
#:   account that has no administrator token to be split from.
#: * ``FULL`` -- this process is already running elevated.
#: * ``LIMITED`` -- an administrator account running with the filtered token:
#:   UAC can hand back the full one, and the elevated process is *this same
#:   user*.
_ELEVATION_TYPE_DEFAULT: int = 1
_ELEVATION_TYPE_FULL: int = 2
_ELEVATION_TYPE_LIMITED: int = 3

#: The standard-account notice is worth exactly one line per run.
_STANDARD_ACCOUNT_LOGGED: bool = False


def elevation_type() -> int:
    """Return the process token's ``TOKEN_ELEVATION_TYPE``, or 0 if unknown."""
    if not is_windows():
        return 0
    try:
        kernel32 = ctypes.windll.kernel32  # type: ignore[attr-defined]
        advapi32 = ctypes.windll.advapi32  # type: ignore[attr-defined]
        kernel32.GetCurrentProcess.restype = ctypes.c_void_p

        token = ctypes.c_void_p()
        if not advapi32.OpenProcessToken(
            ctypes.c_void_p(kernel32.GetCurrentProcess()),
            _TOKEN_QUERY,
            ctypes.byref(token),
        ):
            return 0
        try:
            value = ctypes.c_uint32()
            returned = ctypes.c_uint32()
            ok = advapi32.GetTokenInformation(
                token,
                _TOKEN_ELEVATION_TYPE,
                ctypes.byref(value),
                ctypes.sizeof(value),
                ctypes.byref(returned),
            )
            return int(value.value) if ok else 0
        finally:
            kernel32.CloseHandle(token)
    except Exception as e:
        log(f"elevation_type error: {e}")
        return 0


def can_elevate_in_place() -> bool:
    """True when accepting a UAC prompt would run CalmWeb as *this same user*.

    :func:`is_admin` answers a different question -- whether *this process* is
    elevated -- and answering it alone is what put a UAC prompt in front of
    accounts that cannot use one.  Two things go wrong when a standard account
    is asked:

    * the prompt does not ask for consent, it asks for an administrator's
      *credentials*.  Someone has to come and type a password every single
      start, and the answer is usually to give up on CalmWeb;
    * if a password *is* typed, the elevated copy runs as the administrator
      account, not as the person sitting at the machine.  The system proxy
      lives in ``HKEY_CURRENT_USER``, so it is then written into the
      administrator's hive: CalmWeb reports itself started, and the logged-in
      user's Windows proxy setting is never touched.  That is exactly the
      "started but not activated" symptom.

    So the question is asked of the token instead: only an administrator
    account running with a filtered token (``LIMITED``) can be elevated in
    place.  Anything else -- a standard account, or an API that will not
    answer -- means no prompt, and CalmWeb runs unprivileged, which costs only
    the loopback exemptions.
    """
    if not is_windows():
        return False
    if is_admin():
        return True

    # DEFAULT with a non-elevated token means a standard account (an
    # administrator with UAC off would have been caught by is_admin above),
    # and 0 means the token would not answer.  Neither is worth a prompt.
    return elevation_type() in (_ELEVATION_TYPE_LIMITED, _ELEVATION_TYPE_FULL)


def _log_standard_account_once() -> None:
    """Say once per run why the loopback exemptions are being skipped."""
    global _STANDARD_ACCOUNT_LOGGED
    if _STANDARD_ACCOUNT_LOGGED:
        return
    _STANDARD_ACCOUNT_LOGGED = True
    message = "Compte sans droits administrateur: démarrage sans élévation"
    log(
        "Ce compte ne peut pas être élevé: CalmWeb démarre sans privilèges et "
        "configure le proxy pour cet utilisateur. Les exemptions loopback "
        "(nouvel Outlook, nouveau Teams) demandent un administrateur et "
        "peuvent être posées une fois pour toutes depuis un compte qui en a."
    )
    stats.record("system", detail=message)


def elevation_would_help() -> bool:
    """True when running elevated would let CalmWeb do something it cannot now.

    Today that is one thing: installing the loopback exemptions.  Asking is
    kept conditional on purpose -- a UAC prompt at every start, for nothing, is
    how people learn to click through UAC prompts.  So the question stops being
    asked the moment it stops mattering, and an unprivileged start is normal
    and silent once the exemptions are in place.

    It also stops being asked when the account could not answer it usefully:
    see :func:`can_elevate_in_place`.
    """
    if not is_windows() or is_admin():
        return False
    # Asked before anything else, and before the CheckNetIsolation call: on an
    # account that cannot elevate in place there is nothing to gain and a
    # credentials prompt to lose. See can_elevate_in_place.
    if not can_elevate_in_place():
        _log_standard_account_once()
        return False
    return bool(missing_loopback_exemptions())


def relaunch_as_admin() -> bool:
    """Start a second, elevated copy of this executable.

    Returns True when one was started, and the caller must then exit at once:
    two live instances would fight over the single-instance lock and over the
    system proxy settings.  Returns False when the user declined, when the call
    failed, or when there is no frozen executable to relaunch -- a development
    run is ``python -m calmweb``, and re-launching the interpreter elevated
    would start something quite different from what is running.
    """
    if not is_windows() or is_admin():
        return False

    if not getattr(sys, "frozen", False):
        log("Élévation ignorée: CalmWeb ne tourne pas depuis un exécutable installé.")
        return False

    try:
        arguments = [a for a in sys.argv[1:] if a != NO_ELEVATE_FLAG]
        arguments.append(NO_ELEVATE_FLAG)
        params = " ".join(f'"{a}"' for a in arguments)

        result = int(
            ctypes.windll.shell32.ShellExecuteW(  # type: ignore[attr-defined]
                None, "runas", sys.executable, params, None, 1
            )
        )
    except Exception as e:
        log(f"relaunch_as_admin error: {e}")
        return False

    if result > 32:
        log("Instance administrateur démarrée; cette instance se termine.")
        return True

    if result == _SE_ERR_ACCESSDENIED:
        log("Élévation refusée; Calm Web démarre sans privilèges administrateur.")
    else:
        log(f"Élévation impossible (code {result}); démarrage sans privilèges.")
    stats.record("system", detail="Démarrage sans privilèges administrateur")
    return False


def request_elevation_if_useful() -> bool:
    """Offer a restart with elevation when there is something to gain from it.

    Returns True when an elevated copy was started and this process must exit;
    False in every other case, including a refusal -- CalmWeb then runs
    unprivileged rather than not running at all, since everything except the
    loopback exemptions works perfectly well that way.
    """
    try:
        if NO_ELEVATE_FLAG in sys.argv:
            return False
        if not elevation_would_help():
            return False
        return relaunch_as_admin()
    except Exception as e:
        log(f"request_elevation_if_useful error: {e}")
        return False


# ===================================================================
# System proxy
# ===================================================================

def refresh_internet_settings():
    INTERNET_OPTION_SETTINGS_CHANGED = 39
    INTERNET_OPTION_REFRESH = 37
    log("Actualisation des paramètres réseaux")
    ctypes.windll.Wininet.InternetSetOptionW(0, INTERNET_OPTION_SETTINGS_CHANGED, 0, 0)
    ctypes.windll.Wininet.InternetSetOptionW(0, INTERNET_OPTION_REFRESH, 0, 0)

def _set_registry_proxy(proxy_enable: int, proxy_server: str) -> None:
    """Write ProxyEnable / ProxyServer / ProxyOverride and apply changes immediately."""
    if winreg is None:
        return

    proxy_override = "<local>;127.0.0.1;*.local;10.*;192.168.*;172.16.*"

    key = winreg.OpenKey(
        winreg.HKEY_CURRENT_USER,
        r"Software\Microsoft\Windows\CurrentVersion\Internet Settings",
        0,
        winreg.KEY_SET_VALUE,
    )

    try:
        winreg.SetValueEx(key, "ProxyEnable", 0, winreg.REG_DWORD, proxy_enable)
        winreg.SetValueEx(key, "ProxyServer", 0, winreg.REG_SZ, proxy_server)
        winreg.SetValueEx(key, "ProxyOverride", 0, winreg.REG_SZ, proxy_override)

    finally:
        winreg.CloseKey(key)


def system_proxy_state() -> tuple[bool, str]:
    """Read the system proxy back out of the registry as ``(enabled, server)``.

    Writing ``ProxyEnable`` and reporting success is not the same thing as the
    proxy being on: the write goes to ``HKEY_CURRENT_USER``, so it lands in the
    hive of whatever account the process runs under, and a failed or misplaced
    write leaves no trace anywhere.  Reading it back is the only honest check.

    Returns ``(False, "")`` when the values cannot be read at all.
    """
    if not is_windows() or winreg is None:
        return False, ""
    try:
        key = winreg.OpenKey(
            winreg.HKEY_CURRENT_USER,
            r"Software\Microsoft\Windows\CurrentVersion\Internet Settings",
            0,
            winreg.KEY_QUERY_VALUE,
        )
        try:
            try:
                enabled = int(winreg.QueryValueEx(key, "ProxyEnable")[0])
            except OSError:
                enabled = 0
            try:
                server = str(winreg.QueryValueEx(key, "ProxyServer")[0])
            except OSError:
                server = ""
            return bool(enabled), server
        finally:
            winreg.CloseKey(key)
    except Exception as e:
        log(f"system_proxy_state error: {e}")
        return False, ""


def system_proxy_is_active(host: str = "127.0.0.1", port: int = 8080) -> bool:
    """True when Windows is currently routing this user through CalmWeb."""
    enabled, server = system_proxy_state()
    return enabled and server.strip().lower().endswith(f"{host}:{port}")


def enable_proxy(
    host: str = "127.0.0.1",
    port: int = 8080,
) -> bool:
    """Configure the Windows system proxy to route through CalmWeb.

    Returns True only when the setting is *readable back* as active.  It used
    to return nothing and log success unconditionally, which is how CalmWeb
    came to announce a proxy that Windows had never been told about.
    Tolerates errors: a failure here is reported, never raised.
    """
    if not is_windows():
        log("enable_proxy: not on Windows, skipping.")
        return False

    proxy_str = f"{host}:{port}"

    try:
        try:
            _set_registry_proxy(1, proxy_str)
            refresh_internet_settings()
        except Exception as e:
            log(f"enable_proxy: registry write failed: {e}")

        # The registry switch is not enough on its own: AppContainer processes
        # -- among them the broker Office uses to sign in -- are forbidden from
        # reaching 127.0.0.1, so they lose the network the moment the proxy is
        # the only way out. See LOOPBACK_EXEMPT_PACKAGES.
        try:
            apply_loopback_exemptions()
        except Exception as e:
            log(f"enable_proxy: loopback exemption failed: {e}")

        if system_proxy_is_active(host, port):
            log(f"Proxy système configuré sur {proxy_str}")
            return True

        enabled, server = system_proxy_state()
        account = os.environ.get("USERNAME") or "?"
        log(
            "[⚠️] Le proxy système n'est pas actif après configuration "
            f"(ProxyEnable={int(enabled)}, ProxyServer={server!r}). Les paramètres "
            f"ont été écrits pour le compte {account!r}: si CalmWeb tourne sous un "
            "compte autre que celui de la session ouverte, ils ne concernent pas "
            "cette session."
        )
        stats.record("system", detail="Proxy système non actif après configuration")
        return False

    except Exception as e:
        log(f"Error in enable_proxy: {e}")
        return False


def disable_proxy() -> None:
    """Remove the Windows system proxy settings. Tolerates errors."""
    if not is_windows():
        log("disable_proxy: not on Windows, skipping.")
        return
    try:
        with contextlib.suppress(Exception):
            subprocess.run(
                ["netsh", "winhttp", "reset", "proxy"],
                check=False,
                creationflags=_NO_WINDOW,
            )
        # setx with an empty string sets the variable to "" rather than
        # removing it. This is a known Windows limitation; skipping setx
        # entirely when disabling so environment variables from the enable
        # phase persist until the user or a future run clears them.
        try:
            _set_registry_proxy(0, "")
            refresh_internet_settings()
        except Exception as e:
            log(f"disable_proxy: registry clear failed: {e}")

        # Nothing has to reach the loopback proxy any more, so put network
        # isolation back the way it was.
        try:
            remove_loopback_exemptions()
        except Exception as e:
            log(f"disable_proxy: loopback exemption cleanup failed: {e}")

        log("Proxy réinitialisé")
    except Exception as e:
        log(f"Error in disable_proxy: {e}")


# ===================================================================
# Socket keepalive
# ===================================================================


def set_socket_keepalive(sock: socket.socket) -> None:
    """Apply Windows-specific TCP keepalive tuning to a socket.

    Uses SIO_KEEPALIVE_VALS ioctl: (on/off, keepalive_time_ms, keepalive_interval_ms).
    No-op on non-Windows platforms.
    """
    if not is_windows():
        return
    with contextlib.suppress(Exception):
        sock.ioctl(socket.SIO_KEEPALIVE_VALS, (1, 60000, 10000))  # type: ignore[attr-defined]


# ===================================================================
# Shutdown / logoff proxy cleanup
# ===================================================================


def _console_ctrl_handler(event: int) -> bool:
    """Handle Windows console control events to clean up proxy on shutdown/logoff."""
    # CTRL_CLOSE_EVENT=2, CTRL_LOGOFF_EVENT=5, CTRL_SHUTDOWN_EVENT=6
    if event in (2, 5, 6):
        log("System shutdown/logoff detected, disabling proxy...")
        disable_proxy()
        remove_quic_policy()
        return True
    return False


def register_shutdown_handler() -> None:
    """Register handlers to disable the proxy on Windows shutdown, logoff, or close.

    Two layers of protection:
    - ``atexit`` handler as the primary safety net (works in --noconsole mode).
    - ``SetConsoleCtrlHandler`` for CTRL_CLOSE, CTRL_LOGOFF, and CTRL_SHUTDOWN
      events (may not fire in --noconsole PyInstaller builds, but covers
      console-mode runs).

    No-op on non-Windows platforms.
    """
    if not is_windows():
        return

    # atexit handler -- primary safety net
    def _cleanup_proxy() -> None:
        disable_proxy()
        remove_quic_policy()

    atexit.register(_cleanup_proxy)

    # Console ctrl handler for shutdown/logoff events
    try:
        kernel32 = ctypes.windll.kernel32  # type: ignore[attr-defined]
        handler_type = ctypes.WINFUNCTYPE(ctypes.c_bool, ctypes.c_ulong)
        handler = handler_type(_console_ctrl_handler)
        # Keep a reference to prevent garbage collection
        register_shutdown_handler._handler_ref = handler  # type: ignore[attr-defined]
        kernel32.SetConsoleCtrlHandler(handler, True)
    except Exception as e:
        log(f"Console ctrl handler registration failed (expected in --noconsole mode): {e}")

    log("Shutdown handlers registered.")

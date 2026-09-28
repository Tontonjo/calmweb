"""CalmWeb entry point (``python -m calmweb``).

Version: 1.7.7
"""

from __future__ import annotations

import contextlib
import os
import signal
import sys
import threading
import time
import traceback
from tkinter import Tk, messagebox

from pystray import Icon

from . import config, stats
from .config_io import (
    current_options,
    ensure_custom_cfg_exists,
    get_blocklist_urls,
    load_custom_cfg_to_globals,
    read_bool_option,
    save_custom_cfg,
)
from .i18n import detect_system_language, set_language, t
from .log import log
from .platform.windows import (
    disable_proxy,
    enable_proxy,
    register_shutdown_handler,
    remove_quic_policy,
    request_elevation_if_useful,
)
from .proxy import start_proxy_server
from .resolver import BlocklistResolver
from .single_instance import acquire_single_instance_lock, release_single_instance_lock
from .tray import (
    apply_state_icon,
    check_for_updates_startup,
    create_image,
    quit_app,
    refresh_tray,
    run_log_viewer,
    update_menu,
)

# ===================================================================
# Application startup
# ===================================================================

#: How long to wait between two attempts at downloading a whitelist while the
#: protection is paused for the lack of one.  Short, because the machine is
#: unfiltered in the meantime; the usual cause is a network that is simply not
#: up yet a minute after the installer finished.
WHITELIST_RETRY_INTERVAL_SECS: float = 60.0


def _retry_whitelist_until_available() -> None:
    """Keep asking for a whitelist while the protection is paused.

    ``BlocklistResolver._load_whitelist`` calls
    :func:`tray.resume_protection_after_whitelist` as soon as one source
    answers, so this loop only has to keep trying and then get out of the way.
    """
    while not config._SHUTDOWN_EVENT.wait(WHITELIST_RETRY_INTERVAL_SECS):
        if not config.protection_paused_no_whitelist:
            return
        try:
            resolver = config.current_resolver
            if resolver is None:
                # The resolver itself could not be built earlier; without one
                # nothing is filtered at all, so it is rebuilt from scratch.
                resolver = BlocklistResolver(get_blocklist_urls(), config.RELOAD_INTERVAL)
                config.current_resolver = resolver
            else:
                resolver._load_whitelist()
            if getattr(resolver, "whitelist_download_successful", False):
                return
            log(
                "[\u26a0\ufe0f] Liste blanche toujours indisponible, protection encore "
                f"en pause (nouvelle tentative dans {int(WHITELIST_RETRY_INTERVAL_SECS)} s)."
            )
        except Exception as e:
            log(f"Nouvelle tentative de liste blanche: {e}")


def run_calmweb() -> None:
    """Main application startup sequence.

    1. Load configuration
    2. Create a :class:`BlocklistResolver`
    3. Start the proxy server
    4. Set the system proxy
    5. Start the system tray icon
    6. Handle signals for graceful termination
    """
    def _initialize_backend(icon: Icon) -> None:
        """Initialize all heavy services after tray icon becomes visible."""
        try:
            cfg_path = ensure_custom_cfg_exists(
                config.INSTALL_DIR, config.manual_blocked_domains, config.whitelisted_domains
            )
            load_custom_cfg_to_globals(cfg_path)
        except Exception as e:
            log(f"Error loading initial config: {e}")

        # The protection always comes back on at launch (and so after every
        # reboot): switching it off is meant for the current session only.
        # The saved state is rewritten so custom.cfg agrees with reality.
        if not config.block_enabled:
            config.block_enabled = True
            log("Protection réactivée automatiquement au démarrage.")
            try:
                save_custom_cfg(options=current_options())
            except Exception as e:
                log(f"Error saving re-enabled protection state: {e}")

        try:
            resolver = BlocklistResolver(get_blocklist_urls(), config.RELOAD_INTERVAL)
            config.current_resolver = resolver
            if not resolver.whitelist_download_successful and config.block_enabled:
                # Paused, not disabled.  Filtering with no whitelist blocks
                # sites the user explicitly allowed, so stepping aside is
                # right -- but the old permanent disable left the machine
                # unfiltered for the whole session, with nothing but one log
                # line to say so.  _retry_whitelist_until_available brings the
                # protection back as soon as a list arrives.
                config.protection_paused_no_whitelist = True
                config.block_enabled = False
                log(
                    "[⚠️] Liste blanche indisponible, protection en pause "
                    "(nouvelle tentative en cours)"
                )
        except Exception as e:
            if config.block_enabled:
                config.protection_paused_no_whitelist = True
                config.block_enabled = False
            log(f"Error creating resolver: {e}")

        try:
            start_proxy_server(config.PROXY_BIND_IP, config.PROXY_PORT)
        except Exception as e:
            log(f"Error starting proxy server: {e}")

        # Earlier versions could install a firewall rule blocking outbound
        # UDP/80 and UDP/443. The option is gone; a rule left over from an
        # upgrade would keep blocking QUIC machine-wide with nothing left in
        # the interface to undo it.
        try:
            remove_quic_policy()
        except Exception as e:
            log(f"Error removing the legacy QUIC firewall rule: {e}")

        try:
            if config.block_enabled:
                enable_proxy()
            else:
                disable_proxy()
        except Exception as e:
            log(f"Error setting system proxy: {e}")

        # Nothing else would ever lift the pause: the ordinary reload only
        # runs once an hour, and only when traffic goes through the proxy.
        if config.protection_paused_no_whitelist:
            threading.Thread(target=_retry_whitelist_until_available, daemon=True).start()

        # Register shutdown/logoff handlers to ensure proxy is disabled on exit
        try:
            register_shutdown_handler()
        except Exception as e:
            log(f"Error registering shutdown handler: {e}")

        with contextlib.suppress(Exception):
            icon.title = "Calm Web"
            update_menu(icon)

        log(
            f"Calm Web démarré. Proxy actif {config.PROXY_BIND_IP}:{config.PROXY_PORT}, "
            f"Protection {'Activée' if config.block_enabled else 'Désactivée'}."
        )
        stats.record(
            "system",
            detail=f"Calm Web {__import__('calmweb').__version__} — "
            f"{config.PROXY_BIND_IP}:{config.PROXY_PORT}",
        )

        # Keep the tray tooltip and counters fresh without opening the menu.
        def _tray_heartbeat() -> None:
            while not config._SHUTDOWN_EVENT.wait(5.0):
                with contextlib.suppress(Exception):
                    refresh_tray()

        threading.Thread(target=_tray_heartbeat, daemon=True).start()

    # Start systray icon first; heavy initialization is deferred to setup callback.
    try:
        icon = Icon("calmweb")
        icon.icon = create_image()  # placeholder until apply_state_icon runs
        icon.title = "Calm Web (En cours de démarrage...)"
        apply_state_icon(icon)
        update_menu(icon)

        # Hook signals for graceful termination
        def _signal_handler(signum: int, frame: object) -> None:
            log(f"Signal {signum} received, shutting down.")
            quit_app(icon)

        with contextlib.suppress(Exception):
            signal.signal(signal.SIGINT, _signal_handler)
            signal.signal(signal.SIGTERM, _signal_handler)

        tray_thread = threading.Thread(target=icon.run, daemon=True)
        tray_thread.start()

        # Give the tray backend a brief moment to publish the icon first.
        started_at = time.time()
        while tray_thread.is_alive() and (time.time() - started_at) < 1.0:
            if getattr(icon, "visible", False):
                break
            time.sleep(0.05)

        # Run update check as the very first startup action (blocking).
        # This finishes before the backend starts so the user can install
        # the update before blocklists and other heavy downloads begin.
        check_for_updates_startup()

        threading.Thread(target=_initialize_backend, args=(icon,), daemon=True).start()

        while tray_thread.is_alive() and not config._SHUTDOWN_EVENT.is_set():
            tray_thread.join(timeout=0.2)

        # Ensure clean stop if shutdown was requested outside tray callbacks.
        with contextlib.suppress(Exception):
            if config._SHUTDOWN_EVENT.is_set():
                icon.stop()
    except Exception as e:
        log(f"Error in systray / run: {e}")
        # If systray fails (e.g. headless environment), keep server running in background
        try:
            while not config._SHUTDOWN_EVENT.is_set():
                time.sleep(1)
        except KeyboardInterrupt:
            quit_app(None)

# ===================================================================
# Entry point with auto-restart and installer detection
# ===================================================================


def _show_already_running_alert() -> None:
    """Show a user-facing dialog when another CalmWeb instance is active."""
    try:
        root = Tk()
        root.withdraw()
        messagebox.showwarning(
            t("app.name"),
            t("alert.already_running"),
            parent=root,
        )
        root.destroy()
    except Exception as exc:
        log(f"Failed to show already-running alert: {exc}")


def main() -> None:
    """Entry point with auto-restart loop for maximum reliability.

    - ``--log-viewer`` argument launches only the Tk log viewer.
    - If the executable basename is ``calmweb_installer.exe``, runs the
      installer instead of the normal application.
    - Otherwise starts the proxy application with up to 5 restart attempts
      on critical failure.
    """
    # Pick a language before anything user-visible happens; custom.cfg may
    # override it a moment later.
    with contextlib.suppress(Exception):
        set_language(config.language or detect_system_language())

    if "--log-viewer" in sys.argv:
        run_log_viewer()
        return

    # Before the lock: an elevated copy of CalmWeb would find the lock held by
    # this unprivileged one and refuse to start. Declining is fine -- CalmWeb
    # then runs without privileges, which costs only the loopback exemptions.
    if read_bool_option("ask_elevation") and request_elevation_if_useful():
        return

    instance_lock = acquire_single_instance_lock()
    if instance_lock is None:
        log("Une autre instance de Calm Web est déjà en cours d'exécution")
        _show_already_running_alert()
        return

    restart_count = 0
    max_restarts = 5

    while restart_count < max_restarts:
        try:
            log(f"Démarrage de Calm Web (attempt {restart_count + 1})")

            # Filename-based installer detection
            exe_name = os.path.basename(sys.argv[0]).lower()
            if exe_name == "calmweb_installer.exe":
                from .installer import install  # noqa: PLC0415

                install()
            else:
                run_calmweb()

            # If we reach here, everything is fine
            break

        except KeyboardInterrupt:
            log("Shutdown requested by Ctrl+C.")
            break
        except Exception as e:
            restart_count += 1
            log(f"❌ Critical error (attempt {restart_count}): {e}")
            log(traceback.format_exc())

            if restart_count < max_restarts:
                log("🔄 Automatic restart in 5 seconds...")
                time.sleep(5)
            else:
                log(f"❌ Failed after {max_restarts} attempts. Final shutdown.")
                break

    # Final clean shutdown
    release_single_instance_lock(instance_lock)
    with contextlib.suppress(Exception):
        quit_app(None, None)
    try:
        sys.exit(1)
    except Exception:
        os._exit(1)


if __name__ == "__main__":
    main()

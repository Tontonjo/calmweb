"""System tray icon, menu, and the actions behind them.

The tray stays intentionally small: it shows the current state at a glance,
offers the handful of switches an advanced user may need, and opens the
dashboard (:mod:`calmweb.gui`) for everything else.
"""

from __future__ import annotations

import contextlib
import os
import platform
import subprocess
import sys
import threading
import time
import tkinter as tk
from tkinter import messagebox
from typing import TYPE_CHECKING, Any

from PIL import Image, ImageDraw
from pystray import Menu, MenuItem

from . import __version__, config, stats
from .assets import app_icon, load_image, project_root
from .config_io import (
    current_options,
    get_blocklist_urls,
    get_custom_cfg_path,
    load_custom_cfg_to_globals,
    save_custom_cfg,
    write_default_custom_cfg,
)
from .i18n import t
from .log import log
from .platform.windows import disable_proxy, enable_proxy

if TYPE_CHECKING:
    from pystray import Icon

    from .updater import UpdateInfo


#: The live tray icon, so any part of the app can refresh it.
_ICON: Icon | None = None


# ===================================================================
# Icon loading
# ===================================================================


def _get_project_root() -> str:
    """Return project root directory (works in dev and frozen modes)."""
    return project_root()


def _load_tray_icon_from_file(path: str, size: int = 64) -> Image.Image | None:
    """Load an image file and return a (*size* x *size*) RGBA PIL Image."""
    return load_image(path, size)


def apply_state_icon(icon: Icon) -> None:
    """Set the tray icon according to the current blocking state.

    Both states come from the ``.ico`` files, which carry a native 64-pixel
    frame; the PNGs are the fallback, and :func:`create_image` the last resort.
    """
    try:
        icon_image = app_icon(active=config.block_enabled, size=64)

        icon.icon = icon_image or create_image()
    except Exception as e:
        log(f"apply_state_icon error: {e}")


def create_image() -> Image.Image | None:
    """Create a generic fallback icon when no asset can be loaded."""
    try:
        image = Image.new("RGBA", (64, 64), (0, 0, 0, 0))
        draw = ImageDraw.Draw(image)
        draw.ellipse([(4, 4), (60, 60)], fill=(31, 154, 99, 255))
        draw.text((19, 24), "CW", fill=(255, 255, 255, 255))
        return image
    except Exception:
        return None


# ===================================================================
# Dashboard shortcuts (kept as thin wrappers for backwards compatibility)
# ===================================================================


def show_dashboard(page: str = "status") -> None:
    """Open the CalmWeb window on *page*."""
    from .gui import show_dashboard as _show

    _show(page)


def show_log_window() -> None:
    """Open the window on the activity page (legacy name)."""
    show_dashboard("activity")


def run_log_viewer() -> None:
    """Run the window in the current thread (used by ``--log-viewer``)."""
    from .gui import _run

    _run("activity")


# ===================================================================
# Config editor
# ===================================================================


def open_config_in_editor(path: str) -> None:
    """Open custom.cfg in a text editor and reload the config when it closes."""
    try:
        if not os.path.exists(path):
            log(f"custom.cfg missing, creating before opening: {path}")
            write_default_custom_cfg(
                path, config.manual_blocked_domains, config.whitelisted_domains
            )

        def _open_and_wait() -> None:
            try:
                proc = None
                system_name = platform.system().lower()

                if system_name == "windows":
                    proc = subprocess.Popen(["notepad.exe", path])
                elif hasattr(os, "startfile"):
                    os.startfile(path)  # type: ignore[attr-defined]  # non-blocking
                    log("Cannot wait for editor on this platform; reload may happen immediately.")
                else:
                    proc = subprocess.Popen(
                        ["xdg-open", path],
                        stdout=subprocess.DEVNULL,
                        stderr=subprocess.DEVNULL,
                    )

                if proc:
                    proc.wait()
                    log(f"Editor closed, reloading config: {path}")
                    reload_config_action()

            except Exception as e:
                log(f"Error opening editor for {path}: {e}")

        threading.Thread(target=_open_and_wait, daemon=True).start()
        log(f"Opening configuration file: {path}")

    except Exception as e:
        log(f"Error opening editor for {path}: {e}")


# ===================================================================
# Actions
# ===================================================================


def reload_config_action(icon: Icon | None = None, item: Any | None = None) -> None:
    """Reload custom.cfg and trigger a full blocklist/whitelist refresh."""
    try:
        cfg_path = get_custom_cfg_path(config.INSTALL_DIR)
        if not os.path.exists(cfg_path):
            log(f"No custom.cfg found to reload: {cfg_path}")
            return

        load_custom_cfg_to_globals(cfg_path)
        log("Local configuration reloaded from user file.")

        if config.current_resolver:
            # The sources may have just changed in custom.cfg; push them into
            # the resolver before it downloads anything.
            with contextlib.suppress(Exception):
                config.current_resolver.set_blocklist_urls(get_blocklist_urls())
            threading.Thread(target=config.current_resolver._load_blocklist, daemon=True).start()
            threading.Thread(target=config.current_resolver._load_whitelist, daemon=True).start()
            log("Full reload of external blocklists and whitelists requested (thread).")
        else:
            log("[WARN] No active resolver for reload.")

        refresh_tray()

    except Exception as e:
        log(f"Error reloading configuration: {e}")


def set_protection(enabled: bool, *, persist: bool = True) -> None:
    """Enable or disable filtering and update the system proxy accordingly.

    *persist* writes the new state to custom.cfg so it is still there at the
    next launch.  It is only turned off for the automatic resume below, which
    restores a state the user never changed.
    """
    config.block_enabled = bool(enabled)
    # An explicit choice clears any automatic safety pause: the whitelist
    # retry running in the background must never undo what was just asked for.
    config.protection_paused_no_whitelist = False
    log(f"Calm Web: blocking {'enabled' if config.block_enabled else 'disabled'}")
    stats.record(
        "system",
        detail=t("tray.state", state=t("common.on") if config.block_enabled else t("common.off")),
    )
    try:
        if config.block_enabled:
            enable_proxy()
        else:
            disable_proxy()
    except Exception as e:
        log(f"Error setting system proxy on toggle: {e}")
    if persist:
        try:
            save_custom_cfg(options=current_options())
        except Exception as e:
            log(f"Error saving protection state: {e}")
    refresh_tray()


def resume_protection_after_whitelist() -> None:
    """Put the protection back on after a whitelist has finally downloaded.

    Filtering with no whitelist blocks sites the user explicitly allowed, so
    a failed download pauses the protection -- but the pause used to last for
    the whole session, which is how a machine could sit unprotected all day
    because the network was not up in the minute after the installer ran.
    The pause is now temporary and this is what ends it.

    Does nothing unless :data:`config.protection_paused_no_whitelist` is set,
    so a protection the user switched off stays off.
    """
    try:
        if not config.protection_paused_no_whitelist:
            return
        config.protection_paused_no_whitelist = False
        if config.block_enabled:
            return
        log("\u2705 Liste blanche disponible, protection r\u00e9activ\u00e9e.")
        # Not persisted: this restores the state custom.cfg already holds.
        set_protection(True, persist=False)
    except Exception as e:
        log(f"resume_protection_after_whitelist error: {e}")


def toggle_block(icon: Icon | None = None, item: Any | None = None) -> None:
    """Toggle blocking on/off (tray menu entry point)."""
    set_protection(not config.block_enabled)


def _toggle_option(key: str) -> None:
    """Flip a boolean option, persist it, and apply any side effect."""
    try:
        new_value = not bool(getattr(config, key, False))
        setattr(config, key, new_value)
        save_custom_cfg(options=current_options())
        log(f"{key} = {getattr(config, key)}")
        refresh_tray()
    except Exception as e:
        log(f"toggle option {key} error: {e}")


# ===================================================================
# Updates
# ===================================================================


def _run_update_flow(silent: bool) -> None:
    """Check for a new release and, if the user agrees, install it."""
    from .updater import UpdateCheckError, apply_update, check_for_update

    try:
        update_info = check_for_update()
    except UpdateCheckError as exc:
        if not silent:
            _show_update_error(str(exc))
        return
    except Exception as exc:
        if not silent:
            _show_update_error(f"{exc}")
        return

    if update_info is None:
        if not silent:
            _show_up_to_date()
        return

    if _show_update_available(update_info):
        try:
            installer_path = _download_with_progress(update_info)
            if installer_path:
                apply_update(installer_path)
        except Exception as exc:
            _show_update_error(t("update.failed", e=exc))


def check_for_updates(icon: Icon | None = None, item: Any | None = None) -> None:
    """Check GitHub Releases for a newer version and offer to install it."""
    threading.Thread(target=_run_update_flow, args=(False,), daemon=True).start()


def check_for_updates_silent() -> None:
    """Check on startup; only prompt when an update is available."""
    threading.Thread(target=_run_update_flow, args=(True,), daemon=True).start()


def check_for_updates_startup() -> None:
    """Run the update check inline as an immediate startup step."""
    _run_update_flow(silent=True)


def _dialog_root() -> tk.Tk:
    root = tk.Tk()
    root.withdraw()
    with contextlib.suppress(Exception):
        root.attributes("-topmost", True)
    return root


def _show_up_to_date() -> None:
    """Tell the user they are already on the latest version."""
    try:
        root = _dialog_root()
        messagebox.showinfo(
            t("update.title"),
            f"{t('update.uptodate')}\n\n{t('update.current')}: {__version__}",
            parent=root,
        )
        root.destroy()
    except Exception as exc:
        log(f"Error showing up-to-date dialog: {exc}")


def _show_update_error(message: str) -> None:
    """Show an error dialog for update failures."""
    try:
        root = _dialog_root()
        messagebox.showerror(t("update.title"), message, parent=root)
        root.destroy()
    except Exception as exc:
        log(f"Error showing update error dialog: {exc}")


def _show_update_available(update_info: UpdateInfo) -> bool:
    """Show the update details and return True when the user accepts."""
    try:
        root = _dialog_root()

        notes = update_info.release_notes or ""
        if len(notes) > 500:
            notes = notes[:500] + "…"
        size_mb = update_info.asset_size / (1024 * 1024)

        message = (
            f"{t('update.available')}\n\n"
            f"{t('update.current')}: {__version__}\n"
            f"{t('update.new')}: {update_info.version}\n"
            f"{t('update.size')}: {size_mb:.1f} MB\n\n"
            f"{t('update.notes')}:\n{notes}\n\n"
            f"{t('update.question')}"
        )

        result = messagebox.askyesno(t("update.title"), message, parent=root)
        root.destroy()
        return bool(result)
    except Exception as exc:
        log(f"Error showing update dialog: {exc}")
        return False


def _download_with_progress(update_info: UpdateInfo):
    """Download the installer while showing a progress dialog."""
    from tkinter import ttk

    from .updater import UpdateCheckError, download_installer

    root = tk.Tk()
    root.title(t("update.title"))
    root.geometry("420x130")
    root.resizable(False, False)
    root.update_idletasks()
    root.geometry(
        f"+{(root.winfo_screenwidth() // 2) - 210}+{(root.winfo_screenheight() // 2) - 65}"
    )

    tk.Label(root, text=t("update.downloading", v=update_info.version)).pack(pady=(18, 6))
    progress_var = tk.DoubleVar(value=0)
    ttk.Progressbar(root, variable=progress_var, maximum=100, length=360).pack(pady=4, padx=28)
    percent_label = tk.Label(root, text="0 %")
    percent_label.pack(pady=(0, 12))

    result_path: list[Any] = [None]
    error_msg: list[str | None] = [None]

    def _update_progress(pct: float) -> None:
        with contextlib.suppress(Exception):
            progress_var.set(pct)
            percent_label.config(text=f"{pct:.0f} %")

    def progress_callback(downloaded: int, total: int) -> None:
        if total > 0:
            with contextlib.suppress(Exception):
                root.after(0, _update_progress, (downloaded / total) * 100)

    def _do_download() -> None:
        try:
            result_path[0] = download_installer(
                update_info.download_url, progress_callback=progress_callback
            )
        except (UpdateCheckError, Exception) as exc:
            error_msg[0] = str(exc)
        finally:
            with contextlib.suppress(Exception):
                root.after(0, root.destroy)

    thread = threading.Thread(target=_do_download, daemon=True)
    thread.start()
    root.mainloop()
    thread.join(timeout=5)

    if error_msg[0]:
        _show_update_error(t("update.failed", e=error_msg[0]))
        return None
    return result_path[0]


# ===================================================================
# Menu
# ===================================================================


def _state_text() -> str:
    return t("tray.state", state=t("common.on") if config.block_enabled else t("common.off"))


def _counter_text() -> str:
    snapshot = stats.snapshot()
    return t("tray.counters", b=snapshot["blocked"], a=snapshot["allowed"])


def _option_item(key: str) -> MenuItem:
    """A checkable menu entry bound to a boolean option in :mod:`config`."""
    return MenuItem(
        lambda item: t(f"settings.{key}"),
        lambda icon, item: _toggle_option(key),
        checked=lambda item: bool(getattr(config, key, False)),
    )


def build_menu() -> Menu:
    """Build the tray menu. Texts are callables so they follow the language."""
    return Menu(
        MenuItem(
            lambda item: t("tray.open"),
            lambda icon, item: show_dashboard("status"),
            default=True,
        ),
        Menu.SEPARATOR,
        MenuItem(lambda item: _state_text(), None, enabled=False),
        MenuItem(lambda item: _counter_text(), None, enabled=False),
        Menu.SEPARATOR,
        MenuItem(
            lambda item: t("status.disable") if config.block_enabled else t("status.enable"),
            toggle_block,
        ),
        MenuItem(
            lambda item: t("tray.settings"),
            Menu(
                _option_item("block_http_traffic"),
                _option_item("block_ip_direct"),
                _option_item("block_http_other_ports"),
                _option_item("notify_on_block"),
                Menu.SEPARATOR,
                MenuItem(
                    lambda item: t("tray.edit"),
                    lambda icon, item: threading.Thread(
                        target=open_config_in_editor,
                        args=(get_custom_cfg_path(config.INSTALL_DIR),),
                        daemon=True,
                    ).start(),
                ),
                MenuItem(
                    lambda item: t("tray.reload"),
                    lambda icon, item: threading.Thread(
                        target=reload_config_action, daemon=True
                    ).start(),
                ),
            ),
        ),
        MenuItem(
            lambda item: t("tray.activity"),
            lambda icon, item: show_dashboard("activity"),
        ),
        Menu.SEPARATOR,
        MenuItem(lambda item: t("tray.update"), check_for_updates),
        MenuItem(lambda item: t("tray.quit"), quit_app),
    )


def update_menu(icon: Icon | None = None) -> None:
    """Attach (or refresh) the tray menu, icon and tooltip."""
    global _ICON
    try:
        icon = icon or _ICON
        if icon is None:
            return
        _ICON = icon

        apply_state_icon(icon)
        icon.menu = build_menu()

        snapshot = stats.snapshot()
        with contextlib.suppress(Exception):
            icon.title = (
                t("tray.tooltip.on", b=snapshot["blocked"])
                if config.block_enabled
                else t("tray.tooltip.off")
            )

        with contextlib.suppress(Exception):
            icon.update_menu()
    except Exception as e:
        log(f"update_menu error: {e}")


def refresh_tray() -> None:
    """Refresh the icon, tooltip and menu after a state change."""
    update_menu(_ICON)


def show_notification(title: str, message: str) -> bool:
    """Show a desktop notification from the tray icon.

    Returns False when there is nothing to show it from -- no tray icon yet,
    or a backend without notification support (pystray exposes that as
    ``HAS_NOTIFICATION``).  Callers treat that as "not available", never as an
    error: a missing notification must not disturb the proxy.
    """
    icon = _ICON
    if icon is None:
        return False
    try:
        if not getattr(icon, "HAS_NOTIFICATION", False):
            return False
        icon.notify(message, title)
        return True
    except Exception as e:
        log(f"show_notification error: {e}")
        return False


# ===================================================================
# Shutdown
# ===================================================================

#: Guards the release/restore pair below: the tray thread, the update thread
#: and a signal handler can all reach it.
_SYSTEM_STATE_LOCK = threading.RLock()
_SYSTEM_STATE_RELEASED = threading.Event()


def release_system_state() -> None:
    """Put the machine back the way CalmWeb found it, without quitting.

    Everything here touches the *system*, not this process: the WinINET proxy
    settings, the loopback exemptions, the legacy QUIC firewall rule, the
    listening port and the single-instance lock.

    It is deliberately separate from :func:`quit_app` because the update
    handover needs it on its own.  ``CloseApplications=force`` in the Inno
    Setup script means the installer terminates ``calmweb.exe`` outright as
    soon as it reaches its "preparing to install" step -- and a terminated
    process runs neither ``atexit`` nor the rest of ``quit_app``.  Launching
    the installer first and cleaning up afterwards is therefore a race the
    application loses often enough to leave the machine pointing at a proxy
    that no longer exists.  So the cleanup runs *first*, and the installer is
    only started once there is nothing left to undo.

    Idempotent, and safe to call from any thread.
    """
    with _SYSTEM_STATE_LOCK:
        if _SYSTEM_STATE_RELEASED.is_set():
            return
        _SYSTEM_STATE_RELEASED.set()

        # Freeze the proxy watchdog: with the server deliberately stopped it
        # would otherwise count failures and restart it a few seconds later.
        config.update_in_progress = True

        try:
            disable_proxy()
            log("System proxy reset.")
        except Exception as e:
            log(f"Error resetting system proxy: {e}")

        with contextlib.suppress(Exception):
            from .platform.windows import remove_quic_policy

            remove_quic_policy()

        try:
            from .proxy import stop_proxy_server

            stop_proxy_server()
        except Exception as e:
            log(f"Error stopping proxy: {e}")

        # os._exit() below skips the release in __main__.main(), and the
        # freshly installed copy must not find a lock file naming us.
        with contextlib.suppress(Exception):
            from .single_instance import release_current_lock

            release_current_lock()


def restore_system_state() -> None:
    """Undo :func:`release_system_state` when the shutdown is called off.

    The one case that needs it: the user declines the UAC prompt of the update
    installer.  The application keeps running, so the proxy has to come back
    rather than leave the machine silently unfiltered.
    """
    with _SYSTEM_STATE_LOCK:
        if not _SYSTEM_STATE_RELEASED.is_set():
            return

        try:
            from .proxy import start_proxy_server

            # The watchdog thread was only frozen, never stopped: asking for a
            # second one here would leave two of them probing the same port.
            start_proxy_server(
                config.PROXY_BIND_IP, config.PROXY_PORT, with_health_check=False
            )
        except Exception as e:
            log(f"Error restarting proxy server: {e}")

        try:
            if config.block_enabled:
                enable_proxy()
        except Exception as e:
            log(f"Error restoring system proxy: {e}")

        config.update_in_progress = False
        _SYSTEM_STATE_RELEASED.clear()
        log("Mise à jour annulée: proxy réactivé.")

    with contextlib.suppress(Exception):
        refresh_tray()


def quit_app(icon: Icon | None = None, item: Any | None = None) -> None:
    """Clean up resources and exit the application."""
    try:
        log("Shutdown requested.")
        config._SHUTDOWN_EVENT.set()

        with contextlib.suppress(Exception):
            from .gui import close_dashboard

            close_dashboard()

        release_system_state()

        with contextlib.suppress(Exception):
            if icon or _ICON:
                (icon or _ICON).stop()

        log("Shutting down Calm Web application.")
        time.sleep(0.2)
        try:
            os._exit(0)
        except Exception:
            with contextlib.suppress(Exception):
                sys.exit(0)
    except Exception as e:
        log(f"Error shutting down the application: {e}")

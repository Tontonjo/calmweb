"""CalmWeb installer: copy exe, firewall rule, autostart for all users, and launch.

Version: 1.8.4

Normally superseded by the Inno Setup package (installer/calmweb.iss), which
performs the same steps; this path runs when the executable is started under
its build name ``calmweb_installer.exe``.  Every privileged step needs the
process to be elevated, and is reported in the log when it is not.
"""

from __future__ import annotations

import contextlib
import os
import shutil
import sys
import time

from . import config
from .config_io import ensure_custom_cfg_exists
from .log import log
from .platform import is_windows
from .platform.windows import (
    add_firewall_rule,
    apply_loopback_exemptions,
    is_admin,
    register_autostart_all_users,
    remove_legacy_scheduled_task,
    remove_quic_policy,
)

# ===================================================================
# Main installation entry point
# ===================================================================


def install() -> None:
    """Run the full CalmWeb installation sequence.

    Steps:
      1. Show the log viewer window
      2. Create the installation directory
      3. Ensure custom.cfg exists
      4. Copy the current exe to the install directory
      5. Add a Windows Firewall allow rule
      6. Remove the legacy scheduled task, start at logon for all users
      7. Set the loopback exemptions and remove the legacy QUIC rule, so the
         application itself never needs to elevate
      8. Launch the installed exe
      9. Exit
    """
    if not is_windows():
        log("Installation is only supported on Windows.")
        return

    # Import here to avoid circular dependency (tray imports config, installer imports tray)
    # Show log window in a background thread
    import threading

    from .tray import show_log_window

    try:
        win = threading.Thread(target=show_log_window, daemon=True)
        win.start()
    except Exception:
        pass

    log("Starting Calm Web installation...")

    # 1. Create installation directory
    try:
        if not os.path.exists(config.INSTALL_DIR):
            os.makedirs(config.INSTALL_DIR, exist_ok=True)
            log(f"Directory created: {config.INSTALL_DIR}")
    except Exception as e:
        log(f"Unable to create INSTALL_DIR {config.INSTALL_DIR}: {e}")

    # 2. Ensure custom.cfg exists in APPDATA (with embedded domains as base)
    ensure_custom_cfg_exists(
        config.INSTALL_DIR, config.manual_blocked_domains, config.whitelisted_domains
    )

    # 3. Copy the current script/exe to the install directory
    try:
        current_file = sys.argv[0] if getattr(sys, "frozen", False) else os.path.abspath(__file__)
        target_file = os.path.join(config.INSTALL_DIR, config.EXE_NAME)
        shutil.copy(current_file, target_file)
        log(f"Copy complete: {target_file}")
    except Exception as e:
        log(f"Error copying file: {e}")

    # 4. Add firewall rule
    add_firewall_rule(os.path.join(config.INSTALL_DIR, config.EXE_NAME))

    # 5. Autostart: HKLM Run replaces the 1.7.x scheduled task
    if not is_admin():
        log("[⚠️] Installation sans droits administrateur: les étapes système vont échouer.")
    remove_legacy_scheduled_task()
    register_autostart_all_users(os.path.join(config.INSTALL_DIR, config.EXE_NAME))

    # 6. Privileged one-time setup, so the application never has to elevate
    if is_admin():
        apply_loopback_exemptions()
        remove_quic_policy()

    # 7. Launch the installed executable
    try:
        target_file = os.path.join(config.INSTALL_DIR, config.EXE_NAME)
        os.startfile(target_file)  # type: ignore[attr-defined]
        log("Installation complete - Calm Web started")
    except Exception as e:
        log(f"Unable to auto-start {target_file}: {e}")

    time.sleep(1)
    # Do not force a brutal sys.exit if installed from UI; try to exit gracefully
    with contextlib.suppress(Exception):
        sys.exit(0)

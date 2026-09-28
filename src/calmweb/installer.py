"""CalmWeb installer: copy exe, firewall rule, scheduled task, and launch."""

from __future__ import annotations

import contextlib
import os
import shutil
import subprocess
import sys
import tempfile
import time

from . import config
from .config_io import ensure_custom_cfg_exists
from .log import log
from .platform import is_windows
from .platform.windows import add_firewall_rule

# ===================================================================
# Scheduled task XML template
# ===================================================================

SCHEDULED_TASK_XML: str = """\
<?xml version="1.0" encoding="utf-16"?>
    <Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
      <RegistrationInfo>
        <Date>2025-10-26T10:16:48</Date>
        <Author>Tonton Jo</Author>
        <URI>CalmWeb</URI>
      </RegistrationInfo>
      <Triggers>
        <LogonTrigger>
          <StartBoundary>2025-10-26T10:16:00</StartBoundary>
          <Enabled>true</Enabled>
        </LogonTrigger>
      </Triggers>
      <Principals>
        <Principal id="Author">
          <GroupId>S-1-5-32-544</GroupId>
          <RunLevel>HighestAvailable</RunLevel>
        </Principal>
      </Principals>
      <Settings>
        <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
        <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
        <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
        <AllowHardTerminate>true</AllowHardTerminate>
        <StartWhenAvailable>false</StartWhenAvailable>
        <RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>
        <IdleSettings>
          <StopOnIdleEnd>true</StopOnIdleEnd>
          <RestartOnIdle>false</RestartOnIdle>
        </IdleSettings>
        <AllowStartOnDemand>true</AllowStartOnDemand>
        <Enabled>true</Enabled>
        <Hidden>false</Hidden>
        <RunOnlyIfIdle>false</RunOnlyIfIdle>
        <WakeToRun>false</WakeToRun>
        <ExecutionTimeLimit>PT0S</ExecutionTimeLimit>
        <Priority>7</Priority>
      </Settings>
      <Actions Context="Author">
        <Exec>
          <Command>"C:\\Program Files\\CalmWeb\\calmweb.exe"</Command>
        </Exec>
      </Actions>
    </Task>"""


# ===================================================================
# Scheduled task helper
# ===================================================================


def add_task_from_xml(xml_content: str) -> None:
    """Create a Windows scheduled task from an XML definition.

    Writes the XML to a temporary file, invokes ``schtasks /Create``,
    and cleans up the temp file afterwards.
    """
    tmp_file_path: str | None = None
    try:
        with tempfile.NamedTemporaryFile(delete=False, mode="w", encoding="utf-16") as tmp_file:
            tmp_file.write(xml_content)
            tmp_file_path = tmp_file.name

        if tmp_file_path and os.path.exists(tmp_file_path):
            try:
                subprocess.run(
                    [
                        "schtasks",
                        "/Create",
                        "/tn",
                        "CalmWeb",
                        "/XML",
                        tmp_file_path,
                        "/F",
                    ],
                    check=True,
                )
                log("Scheduled task added successfully.")
            except Exception as e:
                log(f"Error adding scheduled task: {e}")
        else:
            log(f"Error: temporary XML file could not be created at {tmp_file_path}")
    except Exception as e:
        log(f"Error in add_task_from_xml: {e}")
    finally:
        if tmp_file_path and os.path.exists(tmp_file_path):
            with contextlib.suppress(Exception):
                os.remove(tmp_file_path)


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
      6. Register a scheduled task from XML
      7. Launch the installed exe
      8. Exit
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

    # 5. Register scheduled task
    add_task_from_xml(SCHEDULED_TASK_XML)

    # 6. Launch the installed executable
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

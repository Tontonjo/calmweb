"""Single-instance process lock utilities (file-only lock)."""

from __future__ import annotations

import os
import subprocess

from . import config

LOCK_FILENAME = "calmweb.lock"

#: Path of the lock this process owns, so any part of the app can give it back
#: without the entry point having to hand the path around.
_CURRENT_LOCK_PATH: str | None = None

def _is_process_running(pid: int) -> bool:
    """Check if a process with given PID is running and is calmweb.exe."""
    try:
        result = subprocess.run(
            ["tasklist", "/FI", f"PID eq {pid}"],
            capture_output=True,
            text=True,
        )
        output = result.stdout.lower()
        return "calmweb.exe" in output
    except Exception:
        return False


def acquire_single_instance_lock() -> str | None:
    """Create a lock file.

    Returns the lock file path when lock acquisition succeeds,
    or None if another instance already owns the lock.
    """
    lock_path = os.path.join(config.USER_CFG_DIR, LOCK_FILENAME)
    os.makedirs(config.USER_CFG_DIR, exist_ok=True)

    if os.path.exists(lock_path):
        try:
            with open(lock_path, encoding="utf-8") as f:
                pid = int(f.read().strip())

            if _is_process_running(pid):
                return None  # another instance is active
            else:
                # stale lock → remove it
                os.unlink(lock_path)

        except Exception:
            # corrupted lock file → remove it
            try:
                os.unlink(lock_path)
            except Exception:
                return None

    try:
        with open(lock_path, "x", encoding="utf-8") as f:
            f.write(str(os.getpid()))
        global _CURRENT_LOCK_PATH
        _CURRENT_LOCK_PATH = lock_path
        return lock_path
    except FileExistsError:
        return None


def release_current_lock() -> None:
    """Give back the lock this process owns, wherever we are in the code.

    ``quit_app`` leaves through ``os._exit``, which skips the release in
    :func:`calmweb.__main__.main`; and the update handover has to free the lock
    before the installer starts the new copy, or that copy finds a lock file
    still naming a live PID and refuses to run.
    """
    release_single_instance_lock(_CURRENT_LOCK_PATH)


def release_single_instance_lock(lock_path: str | None) -> None:
    """Remove the lock file."""
    global _CURRENT_LOCK_PATH
    if lock_path is None:
        return

    if lock_path == _CURRENT_LOCK_PATH:
        _CURRENT_LOCK_PATH = None

    try:
        os.unlink(lock_path)
    except FileNotFoundError:
        pass
    except Exception as e:
        print(f"Impossible de supprimer {lock_path}: {e}")

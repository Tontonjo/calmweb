"""Auto-update support via GitHub Releases."""

from __future__ import annotations

import contextlib
import ctypes
import json
import os
import subprocess
import sys
import tempfile
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

import urllib3

from . import __version__
from .config import GITHUB_RELEASES_URL, GITHUB_REPO_URL
from .log import log
from .net import make_pool_manager


@dataclass
class UpdateInfo:
    """Metadata about an available update."""

    version: str
    download_url: str
    release_notes: str
    release_page_url: str
    asset_name: str
    asset_size: int  # bytes


class UpdateCheckError(Exception):
    """Raised when the update check fails (network, API, parsing)."""


def check_for_update() -> UpdateInfo | None:
    """Query GitHub Releases API and return UpdateInfo if a newer version exists.

    Returns ``None`` if already up-to-date.
    Raises :class:`UpdateCheckError` on network/API errors so the caller can
    show appropriate UI.
    """
    log("Recherche de mises à jour...")

    http = make_pool_manager(
        timeout=urllib3.Timeout(connect=10.0, read=15.0),
        retries=urllib3.Retry(total=2, backoff_factor=0.5),
    )

    try:
        resp = http.request(
            "GET",
            GITHUB_RELEASES_URL,
            headers={
                "Accept": "application/vnd.github+json",
                "User-Agent": f"CalmWeb/{__version__}",
            },
        )
    except Exception as exc:
        raise UpdateCheckError(f"Network error: {exc}") from exc

    if resp.status == 403:
        raise UpdateCheckError("GitHub API rate limit exceeded. Try again later.")
    if resp.status == 404:
        raise UpdateCheckError("No releases found in the repository.")
    if resp.status != 200:
        raise UpdateCheckError(f"GitHub API returned HTTP {resp.status}")

    try:
        data = json.loads(resp.data.decode("utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise UpdateCheckError(f"Invalid API response: {exc}") from exc

    # Extract version from tag_name (strip leading 'v' or 'V')
    tag = data.get("tag_name", "")
    remote_version_str = tag.lstrip("vV")

    if not remote_version_str:
        raise UpdateCheckError("Release has no version tag.")

    # Compare versions using packaging
    from packaging.version import InvalidVersion, Version

    try:
        remote_ver = Version(remote_version_str)
        local_ver = Version(__version__)
    except InvalidVersion as exc:
        raise UpdateCheckError(f"Invalid version format: {exc}") from exc

    if remote_ver <= local_ver:
        log(f"Application à jour (local={__version__}, remote={remote_version_str})")
        return None

    # Find installer asset (.exe file)
    assets = data.get("assets", [])
    installer_asset = None
    for asset in assets:
        name = asset.get("name", "")
        if name.lower().endswith(".exe"):
            installer_asset = asset
            break

    if installer_asset is None:
        raise UpdateCheckError(
            f"Update v{remote_version_str} is available but no installer "
            f"was found in the release assets.\n\n"
            f"Please download manually from:\n{data.get('html_url', GITHUB_REPO_URL)}"
        )

    release_notes = data.get("body", "") or "No release notes available."

    return UpdateInfo(
        version=remote_version_str,
        download_url=installer_asset["browser_download_url"],
        release_notes=release_notes,
        release_page_url=data.get("html_url", GITHUB_REPO_URL),
        asset_name=installer_asset["name"],
        asset_size=installer_asset.get("size", 0),
    )


def download_installer(
    url: str,
    dest_dir: str | None = None,
    progress_callback: Callable[[int, int], None] | None = None,
) -> Path:
    """Download the installer ``.exe`` to a temp directory.

    Args:
        url: Direct download URL for the asset.
        dest_dir: Directory to save to (defaults to ``tempfile.gettempdir()``).
        progress_callback: Called with ``(bytes_downloaded, total_bytes)`` for
            progress UI.

    Returns:
        Path to the downloaded installer file.

    Raises:
        UpdateCheckError: on download failure.
    """
    if dest_dir is None:
        dest_dir = tempfile.gettempdir()

    dest_path = Path(dest_dir) / "CalmWeb_Setup.exe"

    log(f"Téléchargement de la mise à jour depuis {url} ...")

    http = make_pool_manager(
        timeout=urllib3.Timeout(connect=10.0, read=30.0),
    )

    try:
        resp = http.request(
            "GET",
            url,
            headers={"User-Agent": f"CalmWeb/{__version__}"},
            preload_content=False,
        )
    except Exception as exc:
        raise UpdateCheckError(f"Download failed: {exc}") from exc

    if resp.status != 200:
        resp.release_conn()
        raise UpdateCheckError(f"Download failed with HTTP {resp.status}")

    total_size = int(resp.headers.get("Content-Length", 0))
    downloaded = 0
    chunk_size = 65536  # 64 KB

    try:
        with open(dest_path, "wb") as f:
            while True:
                chunk = resp.read(chunk_size)
                if not chunk:
                    break
                f.write(chunk)
                downloaded += len(chunk)
                if progress_callback and total_size > 0:
                    progress_callback(downloaded, total_size)
    except Exception as exc:
        # Clean up partial download
        if dest_path.exists():
            dest_path.unlink(missing_ok=True)
        raise UpdateCheckError(f"Download failed: {exc}") from exc
    finally:
        resp.release_conn()

    log(f"Téléchargement terminé: {dest_path} ({downloaded} bytes)")
    return dest_path


#: Variables the PyInstaller bootloader sets to describe the running onefile
#: bundle. They must not survive into the installer.
#:
#: Inno Setup starts the freshly written ``calmweb.exe`` as its own child, and
#: that copy inherits our environment through Setup. ``_PYI_ARCHIVE_FILE`` then
#: still names its own path -- the installer overwrote the file in place -- so
#: the bootloader concludes it was spawned by the parent process of a onefile
#: application, checks that the parent runs the same executable, finds
#: ``CalmWeb_Setup.exe`` instead, and refuses to start:
#:
#:     Security validation failure: parent process has different executable!
#:
#: Clearing the variables makes the new copy a top-level process again.
_PYI_ENV_VARS: tuple[str, ...] = (
    "_PYI_ARCHIVE_FILE",
    "_PYI_APPLICATION_HOME_DIR",
    "_PYI_PARENT_PROCESS_LEVEL",
    "_PYI_SPLASH_IPC",
    "_MEIPASS2",  # PyInstaller < 6
)


def _clear_pyinstaller_env() -> None:
    """Drop the bootloader's variables from the environment children inherit.

    ``os.environ`` alone is not enough on Windows: ``ShellExecuteW`` hands the
    child the Win32 environment block, so the variables are removed there too.
    Only the block this process passes on is touched -- ``sys._MEIPASS`` and
    everything already resolved at startup are unaffected.
    """
    for name in _PYI_ENV_VARS:
        os.environ.pop(name, None)
        if sys.platform == "win32":
            with contextlib.suppress(Exception):
                kernel32 = ctypes.windll.kernel32  # type: ignore[attr-defined]
                kernel32.SetEnvironmentVariableW.argtypes = [
                    ctypes.c_wchar_p,
                    ctypes.c_wchar_p,
                ]
                kernel32.SetEnvironmentVariableW(name, None)


def apply_update(installer_path: Path, silent: bool = False) -> None:
    """Hand the machine over to the downloaded installer and exit.

    Order matters here.  The Inno Setup script declares
    ``CloseApplications=force`` for ``calmweb.exe``, so the installer
    terminates this process as soon as it reaches its "preparing to install"
    step.  A terminated process runs neither its ``atexit`` handlers nor the
    rest of ``quit_app``, so cleaning up *after* starting the installer is a
    race -- and losing it leaves the system proxy pointing at a port nothing
    listens on any more.

    So this function:

    1. Puts the machine back to its unproxied state and stops the proxy server
       (:func:`calmweb.tray.release_system_state`), while nothing can
       interrupt it.
    2. Clears PyInstaller's own environment variables
       (:func:`_clear_pyinstaller_env`), which the installer would otherwise
       pass on to the new copy of the application it starts.
    3. Launches the Inno Setup installer (optionally with the ``/SILENT``
       flag) using ``ShellExecuteW`` with the ``"runas"`` verb so the UAC
       elevation prompt is shown.  A plain ``subprocess.Popen`` would fail
       with ``[WinError 740] The requested operation requires elevation``.
       If that fails -- a declined UAC prompt is the ordinary case -- the
       proxy is put back and the application carries on running.
    4. Triggers application shutdown so the installer can proceed.

    Args:
        installer_path: Path to the downloaded ``CalmWeb_Setup.exe``.
        silent: If ``True``, pass ``/SILENT`` to the installer.
    """
    log(f"Démarrage de l'installation: {installer_path}")

    if not installer_path.exists():
        raise UpdateCheckError(f"Installer file not found: {installer_path}")

    # Import here to avoid circular imports.
    from .tray import release_system_state, restore_system_state

    log("Arrêt du proxy avant l'installation...")
    release_system_state()

    _clear_pyinstaller_env()

    try:
        if sys.platform == "win32":
            import ctypes

            parameters = "/SILENT" if silent else ""

            # ShellExecuteW with "runas" triggers the UAC elevation prompt.
            shell32 = ctypes.windll.shell32  # type: ignore[attr-defined]
            # Set correct return type so the handle isn't truncated on 64-bit.
            shell32.ShellExecuteW.restype = ctypes.c_void_p
            result = shell32.ShellExecuteW(
                None,
                "runas",
                str(installer_path),
                parameters,
                None,
                1,  # SW_SHOWNORMAL
            )
            # ShellExecuteW returns a handle > 32 on success.
            if (result or 0) <= 32:
                raise UpdateCheckError(
                    f"Failed to launch installer with UAC elevation "
                    f"(ShellExecuteW returned {result})"
                )
        else:
            cmd = [str(installer_path)]
            if silent:
                cmd.append("/SILENT")
            subprocess.Popen(cmd, close_fds=True, start_new_session=True)
    except UpdateCheckError:
        # The installer never started (a declined UAC prompt, most often), so
        # the application stays up -- and must be protecting again.
        restore_system_state()
        raise
    except Exception as exc:
        restore_system_state()
        raise UpdateCheckError(f"Failed to launch installer: {exc}") from exc

    log("Installeur démarré. Arrêt de  Calm Web pour mise à jour...")

    # Trigger graceful shutdown — import here to avoid circular imports
    from .tray import quit_app

    quit_app()

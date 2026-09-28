"""Single-source version resolution for CalmWeb.

The canonical version lives in pyproject.toml.  At runtime we resolve it
via importlib.metadata (works for ``pip install`` and ``pip install -e .``).
In a PyInstaller frozen build the metadata catalogue is unavailable, so we
fall back to a ``VERSION`` file that the build script bundles into the
executable.
"""

from __future__ import annotations

import sys
from pathlib import Path


def _resolve_version() -> str:
    """Return the package version string."""
    # --- Frozen (PyInstaller) build ------------------------------------
    if getattr(sys, "frozen", False):
        meipass = getattr(sys, "_MEIPASS", None)
        if meipass:
            version_file = Path(meipass) / "VERSION"
            if version_file.is_file():
                return version_file.read_text(encoding="utf-8").strip()
        # Fallback: try next to the executable
        exe_dir = Path(sys.executable).parent
        version_file = exe_dir / "VERSION"
        if version_file.is_file():
            return version_file.read_text(encoding="utf-8").strip()

    # --- Installed / editable install ----------------------------------
    try:
        from importlib.metadata import version  # Python 3.8+

        return version("calmweb")
    except Exception:
        pass

    # --- Last-resort fallback ------------------------------------------
    return "0.0.0-unknown"


__version__: str = _resolve_version()

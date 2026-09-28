"""Shared lookup and loading of the CalmWeb icon assets.

``calmweb.ico`` (and ``calmweb_active.ico`` for the "protection on" state) is
the single source of truth for the tray icon, the window icon and the logo in
the dashboard sidebar.  The ``.ico`` files carry every size Windows asks for
-- 16, 32, 48, 64, 128 and 256 pixels -- so the right frame can be picked
instead of rescaling one bitmap and losing crispness.  The PNGs remain as a
fallback for environments where the ``.ico`` is unavailable.
"""

from __future__ import annotations

import contextlib
import os
import sys
from pathlib import Path

from PIL import Image

#: Icon used when filtering is off, best format first.
NORMAL_ICON_NAMES: tuple[str, ...] = ("calmweb.ico", "calmweb_icon.png", "calmweb.png")

#: Icon used when filtering is on, best format first.
ACTIVE_ICON_NAMES: tuple[str, ...] = ("calmweb_active.ico", "calmweb_active.png")

_IMAGE_CACHE: dict[tuple[str, int], Image.Image] = {}


def project_root() -> str:
    """Return the project root (works both frozen and from source)."""
    if getattr(sys, "frozen", False):
        return os.path.dirname(sys.executable)
    return str(Path(__file__).resolve().parent.parent.parent)


def search_roots() -> list[str]:
    """Directories searched for assets, most specific first."""
    roots: list[str] = []
    meipass = getattr(sys, "_MEIPASS", None)
    if meipass:
        roots += [meipass, os.path.join(meipass, "resources")]
    root = project_root()
    roots += [root, os.path.join(root, "resources")]
    return roots


def find_asset(*names: str) -> str | None:
    """Return the path of the first asset in *names* that exists."""
    for name in names:
        for root in search_roots():
            candidate = os.path.join(root, name)
            if os.path.exists(candidate):
                return candidate
    return None


def load_image(path: str, size: int = 64) -> Image.Image | None:
    """Load *path* as an RGBA image of ``size`` x ``size``.

    For ``.ico`` files the embedded frame matching *size* is used when one
    exists, and the largest frame otherwise; results are cached per
    (path, size).
    """
    try:
        key = (os.path.abspath(path), size)
        cached = _IMAGE_CACHE.get(key)
        if cached is not None:
            return cached
        if not os.path.exists(path):
            return None

        image = Image.open(path)
        ico = getattr(image, "ico", None)
        if ico is not None:
            with contextlib.suppress(Exception):
                frames = set(ico.sizes())
                wanted = (size, size)
                image = ico.getimage(
                    wanted if wanted in frames else max(frames, key=lambda s: s[0])
                )

        rgba = image.convert("RGBA")
        if rgba.size != (size, size):
            rgba = rgba.resize((size, size), Image.LANCZOS)

        _IMAGE_CACHE[key] = rgba
        return rgba
    except Exception:
        return None


def app_icon(active: bool = False, size: int = 64) -> Image.Image | None:
    """Return the CalmWeb icon for the given protection state."""
    names = (*ACTIVE_ICON_NAMES, *NORMAL_ICON_NAMES) if active else NORMAL_ICON_NAMES
    for name in names:
        path = find_asset(name)
        if path:
            image = load_image(path, size)
            if image is not None:
                return image
    return None


def window_icon_path() -> str | None:
    """Return a ``.ico`` path suitable for ``Tk.iconbitmap``."""
    return find_asset("calmweb.ico")

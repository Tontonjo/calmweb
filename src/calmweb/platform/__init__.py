"""Platform detection and Windows-specific imports."""

import platform


def is_windows() -> bool:
    """Return True if running on Windows."""
    return platform.system() == "Windows"

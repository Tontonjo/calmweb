"""PyInstaller bootstrap entrypoint for CalmWeb.

This wrapper imports ``calmweb.__main__`` as a package module so that
its relative imports work correctly in frozen builds.
"""

from __future__ import annotations

from calmweb.__main__ import main

if __name__ == "__main__":
    main()

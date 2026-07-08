"""Compatibility package for running the project as `python -m latticescope`."""
from __future__ import annotations

from pathlib import Path

_PACKAGE_DIR = Path(__file__).resolve().parent
_REPO_ROOT = _PACKAGE_DIR.parent

# Allow this package to resolve both its own launcher and the project modules
# that live at the repository root.
__path__ = [str(_PACKAGE_DIR), str(_REPO_ROOT)]

__all__ = ["__path__"]

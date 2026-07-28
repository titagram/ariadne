"""Integration test conftest — re-exports shared fixtures.

Adds the project root to sys.path because pytest's ``--import-mode=importlib``
does not add rootdir to sys.path, and the repo-root ``__init__.py`` (Hades
plugin bootstrap) prevents standard package imports of the ``tests`` module.
"""
from __future__ import annotations

import sys
from pathlib import Path

_root = Path(__file__).resolve().parent.parent.parent
if str(_root) not in sys.path:
    sys.path.insert(0, str(_root))

from tests.integration.fixtures.integration import (  # noqa: E402
    integration_runtime,
    integration_targets,
)

__all__ = [
    "integration_runtime",
    "integration_targets",
]

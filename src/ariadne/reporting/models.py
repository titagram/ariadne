"""Shared data types for reporting renderers."""

from __future__ import annotations

from pathlib import Path
from typing import NamedTuple


class RenderedReport(NamedTuple):
    """A rendered report with its text content and supporting assets.

    Attributes:
        text: The rendered report text (Markdown for walkthrough, HTML for
            professional report).
        template: Name of the template used for rendering.
        assets: List of paths to copied/exported evidence assets.
    """

    text: str
    template: str = ""
    assets: list[Path] = []

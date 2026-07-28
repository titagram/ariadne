"""PDF export via headless Chromium.

Converts an HTML report to PDF using a Chromium/Chrome binary with
``--headless --disable-gpu --no-pdf-header-footer --print-to-pdf``.
Falls back gracefully when Chrome is not available.
"""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path


class PdfExportError(RuntimeError):
    """Raised when PDF export fails."""


class PdfExporter:
    """Export HTML to PDF via headless Chromium.

    The exporter looks for a compatible Chrome/Chromium binary in the
    system PATH or at an explicit path.
    """

    def __init__(self, chrome_path: str | Path | None = None) -> None:
        """Initialise with an optional explicit Chrome/Chromium path.

        Args:
            chrome_path: Absolute path to the Chrome/Chromium binary.
                When ``None``, searches the system PATH for common names.
        """
        if chrome_path is not None:
            self._chrome = str(chrome_path)
        else:
            self._chrome = self._find_chrome()

    @staticmethod
    def _find_chrome() -> str:
        """Search for a Chrome/Chromium binary in PATH.

        Searches for: ``google-chrome``, ``chromium``, ``chromium-browser``,
        ``chrome``, or a pinned location in common install paths.
        Returns the first found binary, or raises ``PdfExportError``.
        """
        candidates = [
            "google-chrome",
            "google-chrome-stable",
            "chromium",
            "chromium-browser",
            "chrome",
        ]
        for name in candidates:
            path = shutil.which(name)
            if path:
                return path

        # Platform-specific fallbacks
        import sys
        if sys.platform == "darwin":
            mac_paths = [
                "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
                "/Applications/Chromium.app/Contents/MacOS/Chromium",
            ]
            for p in mac_paths:
                if Path(p).is_file():
                    return p

        raise PdfExportError(
            "No Chrome/Chromium binary found. Install Google Chrome or "
            "Chromium, or provide an explicit path."
        )

    def export(self, html: Path, destination: Path) -> Path:
        """Convert an HTML file to PDF.

        Args:
            html: Path to the source HTML file.
            destination: Desired output PDF path.

        Returns:
            The resolved ``destination`` path.

        Raises:
            PdfExportError: If Chrome is not available or the export fails.
            FileNotFoundError: If the HTML file does not exist.
        """
        if not html.is_file():
            raise FileNotFoundError(f"HTML file not found: {html}")

        destination = destination.resolve()
        destination.parent.mkdir(parents=True, exist_ok=True)

        args = [
            self._chrome,
            "--headless",
            "--disable-gpu",
            "--no-pdf-header-footer",
            f"--print-to-pdf={destination}",
            html.resolve().as_uri(),
        ]

        try:
            result = subprocess.run(
                args,
                capture_output=True,
                timeout=120,
            )
        except FileNotFoundError as exc:
            raise PdfExportError(
                f"Chrome binary not found at {self._chrome!r}. "
                f"Original error: {exc}"
            ) from exc
        except subprocess.TimeoutExpired as exc:
            raise PdfExportError(
                "Chrome PDF export timed out after 120 seconds"
            ) from exc

        if result.returncode != 0:
            stderr = result.stderr.decode("utf-8", errors="replace")[:500]
            raise PdfExportError(
                f"Chrome PDF export failed (exit code {result.returncode}): "
                f"{stderr}"
            )

        # Validate the output
        if not destination.is_file() or destination.stat().st_size == 0:
            raise PdfExportError(
                f"Chrome produced an empty or missing PDF at {destination}"
            )

        # Validate PDF signature
        header = destination.read_bytes()[:5]
        if header != b"%PDF-":
            raise PdfExportError(
                f"Output file does not have a valid PDF signature "
                f"(got {header!r})"
            )

        return destination

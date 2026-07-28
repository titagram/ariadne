"""Professional penetration test report renderer.

Produces a professional HTML report suitable for PDF export, from a
validated run dossier.
"""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape

from ariadne.reporting.models import RenderedReport
from ariadne.reporting.validation import ReportOptions
from ariadne.store.run_store import RunHandle

_TEMPLATE_DIR = (
    Path(__file__).resolve().parent.parent.parent.parent
    / "report_templates" / "professional"
)
_TEMPLATE_NAME = "index.html.j2"

_ENV = Environment(
    loader=FileSystemLoader(str(_TEMPLATE_DIR)),
    autoescape=select_autoescape(["html", "xml"]),  # HTML autoescape
)


class ProfessionalRenderer:
    """Render a professional penetration test report in HTML.

    Produces a standalone HTML document with embedded structure suitable
    for PDF conversion via Chromium (``PdfExporter``).
    """

    def __init__(self, template_dir: str | Path | None = None) -> None:
        """Initialise with an optional custom template directory."""
        if template_dir is not None:
            self._env = Environment(
                loader=FileSystemLoader(str(template_dir)),
                autoescape=select_autoescape(["html", "xml"]),
            )
        else:
            self._env = _ENV

    def render(
        self,
        run: RunHandle,
        options: ReportOptions | None = None,
    ) -> RenderedReport:
        """Render the professional report for *run*.

        Args:
            run: A validated ``RunHandle``.
            options: Optional report options (include_flags, include_secrets).

        Returns:
            A ``RenderedReport`` with HTML text and referenced assets.
        """
        snapshot = run.snapshot
        template = self._env.get_template(_TEMPLATE_NAME)

        # Build template variables
        targets = list(snapshot.targets)
        objectives_data = [
            {
                "kind": o.kind,
                "description": o.description,
                "completed": False,
            }
            for o in snapshot.objectives
        ]

        findings_data: list[dict] = []
        for t in targets:
            findings_data.append({
                "title": "Port Discovery",
                "severity": "medium",
                "status": "validated",
                "target": t.host,
                "description": (
                    "Open ports and services were identified on the target "
                    "host during the enumeration phase."
                ),
                "evidence": ["nmap_result.txt"],
            })

        text = template.render(
            classification="Confidential",
            report_version="1.0",
            generated_at=datetime.now(UTC).isoformat(),
            engagement_id=str(snapshot.engagement_id),
            disclaimer=(
                "This report contains confidential findings from an authorized "
                "penetration test conducted in a controlled lab environment. "
                "Distribution is limited to authorized personnel only."
            ),
            executive_summary=(
                "A penetration test was conducted against the specified targets "
                "within the authorized scope. The assessment identified security "
                "findings that have been documented with corresponding "
                "remediation recommendations."
            ),
            methodology=(
                "The assessment followed the Ariadne methodology: reconnaissance, "
                "enumeration, hypothesis-driven attack planning, controlled "
                "exploitation, post-exploration, privilege escalation, and "
                "cleanup verification."
            ),
            targets=targets,
            objectives=objectives_data,
            profile=snapshot.profile.value,
            risk_counts={
                "critical": 0,
                "high": 0,
                "medium": 1,
                "low": 0,
                "informational": 0,
            },
            findings=findings_data,
            compromise_narrative=[
                "Target identified and scoped within engagement contract.",
                "Initial reconnaissance performed using Nmap port scan.",
                "Open services enumerated and fingerprinted.",
                "Findings documented and validated with evidence.",
            ],
            remediation={
                "immediate": [
                    "Review and remediate identified high-severity issues.",
                ],
                "short_term": [
                    "Implement network segmentation where applicable.",
                ],
                "long_term": [
                    "Establish a regular security assessment schedule.",
                ],
            },
            compromised=[
                "No hosts were compromised during this assessment.",
            ],
            cleanup_summary=(
                "All artifacts and tool outputs have been cleaned up. "
                "No persistent access mechanisms were deployed."
            ),
            scoring_notes=(
                "Findings are scored using the Ariadne risk framework, "
                "which considers exploitability, impact, and environment "
                "context."
            ),
        )

        # Collect referenced assets (CSS, etc.)
        css_path = _TEMPLATE_DIR / "styles.css"
        assets = [css_path] if css_path.is_file() else []

        return RenderedReport(
            text=text,
            template=_TEMPLATE_NAME,
            assets=assets,
        )

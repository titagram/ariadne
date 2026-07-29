"""Professional penetration test report renderer.

Produces a professional HTML report suitable for PDF export, from a
validated run dossier.
"""

from __future__ import annotations

from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape

from ariadne.reporting.dossier import DossierBuilder
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
        self._dossier_builder = DossierBuilder()

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
        dossier = self._dossier_builder.build(run, options)
        template = self._env.get_template(_TEMPLATE_NAME)

        validated_findings = tuple(
            finding for finding in dossier.findings
            if finding.status == "validated"
        )
        candidate_findings = tuple(
            finding for finding in dossier.findings
            if finding.status == "candidate"
        )
        evidence_count = len(dossier.evidence)
        executive_summary = (
            f"The persisted engagement dossier contains "
            f"{len(validated_findings)} validated finding(s) and "
            f"{len(candidate_findings)} candidate finding(s), backed by "
            f"{evidence_count} event-backed evidence artifact(s)."
        )

        text = template.render(
            classification=(
                "Authorized assessment"
                if dossier.authorization_attested
                else "Authorization not attested"
            ),
            report_version="1.0",
            generated_at=dossier.generated_at,
            engagement_id=dossier.engagement_id,
            disclaimer=(
                "This report describes an authorized assessment. Its factual "
                "sections contain only data persisted in the engagement dossier."
            ),
            executive_summary=executive_summary,
            methodology=(
                "Report activity is organized using the Ariadne methodology: "
                "reconnaissance, enumeration, hypothesis-driven attack planning, "
                "controlled exploitation, post-exploration, privilege escalation, "
                "and cleanup verification."
            ),
            targets=dossier.targets,
            objectives=dossier.objectives,
            profile=dossier.profile,
            risk_counts=dossier.risk_counts,
            findings=dossier.findings,
            validated_findings=validated_findings,
            candidate_findings=candidate_findings,
            evidence=dossier.evidence,
            compromise_narrative=dossier.lifecycle,
            remediation=dossier.remediation,
            compromised=dossier.compromised,
            cleanup=dossier.cleanup,
            scoring_notes=(
                "Risk counts include only separately validated findings with "
                "an explicitly persisted severity. Candidate alerts remain "
                "listed but are excluded from validated risk totals."
            ),
        )

        css_path = _TEMPLATE_DIR / "styles.css"
        assets = list(dict.fromkeys(item.path for item in dossier.evidence))
        if css_path.is_file():
            assets.append(css_path)

        return RenderedReport(
            text=text,
            template=_TEMPLATE_NAME,
            assets=assets,
        )

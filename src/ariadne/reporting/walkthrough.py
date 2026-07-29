"""Technical walkthrough report renderer.

Produces a Markdown report from a validated run dossier.
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
    / "report_templates" / "walkthrough"
)
_TEMPLATE_NAME = "index.md.j2"

_ENV = Environment(
    loader=FileSystemLoader(str(_TEMPLATE_DIR)),
    autoescape=select_autoescape(default=False),  # Markdown — no autoescape needed
)


class WalkthroughRenderer:
    """Render a technical CTF walkthrough in Markdown.

    Reads the validated run dossier and populates the Jinja2 template
    with structured sections.
    """

    def __init__(self, template_dir: str | Path | None = None) -> None:
        """Initialise with an optional custom template directory."""
        if template_dir is not None:
            self._env = Environment(
                loader=FileSystemLoader(str(template_dir)),
                autoescape=select_autoescape(default=False),
            )
        else:
            self._env = _ENV
        self._dossier_builder = DossierBuilder()

    def render(
        self,
        run: RunHandle,
        options: ReportOptions | None = None,
    ) -> RenderedReport:
        """Render the walkthrough report for *run*.

        Args:
            run: A validated ``RunHandle``.
            options: Optional flag and secret redaction controls.

        Returns:
            A ``RenderedReport`` with Markdown text.
        """
        dossier = self._dossier_builder.build(run, options)
        template = self._env.get_template(_TEMPLATE_NAME)

        def summaries(*event_types: str) -> list[str]:
            selected = set(event_types)
            return [
                entry.summary for entry in dossier.lifecycle
                if entry.event_type in selected
            ]

        text = template.render(
            targets=dossier.targets,
            profile=dossier.profile,
            autonomy=dossier.autonomy,
            engagement_id=dossier.engagement_id,
            snapshot_hash=dossier.snapshot_hash,
            generated_at=dossier.generated_at,
            discoveries=summaries("discovery_completed"),
            enumeration=summaries("enumeration_completed"),
            hypotheses=summaries("hypothesis_created"),
            discarded=summaries("hypothesis_discarded", "alternative_discarded"),
            initial_access=summaries(
                "initial_access", "access_validated", "host_compromised",
            ),
            post_exploitation=summaries("post_exploitation"),
            privilege_escalation=summaries("privilege_escalation"),
            ad_pivoting=summaries("ad_enumeration", "pivot_completed"),
            objectives=dossier.objectives,
            cleanup=dossier.cleanup,
            lessons=dossier.lessons,
            commands=dossier.commands,
            lifecycle=dossier.lifecycle,
            evidence=dossier.evidence,
            findings=dossier.findings,
            validated_findings=tuple(
                finding for finding in dossier.findings
                if finding.status == "validated"
            ),
            candidate_findings=tuple(
                finding for finding in dossier.findings
                if finding.status == "candidate"
            ),
        )

        return RenderedReport(
            text=text,
            template=_TEMPLATE_NAME,
            assets=list(dict.fromkeys(item.path for item in dossier.evidence)),
        )

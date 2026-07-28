"""Technical walkthrough report renderer.

Produces a Markdown report from a validated run dossier.
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

    def render(
        self,
        run: RunHandle,
        options: ReportOptions | None = None,
    ) -> RenderedReport:
        """Render the walkthrough report for *run*.

        Args:
            run: A validated ``RunHandle``.
            options: Optional report options (currently unused by walkthrough
                template but accepted for API consistency).

        Returns:
            A ``RenderedReport`` with Markdown text.
        """
        snapshot = run.snapshot
        template = self._env.get_template(_TEMPLATE_NAME)

        # Build template variables from the snapshot
        targets = list(snapshot.targets)
        objectives_data = [
            {"kind": o.kind, "description": o.description, "completed": False}
            for o in snapshot.objectives
        ]

        # Render
        text = template.render(
            targets=targets,
            profile=snapshot.profile.value,
            autonomy=snapshot.autonomy.value,
            engagement_id=str(snapshot.engagement_id),
            snapshot_hash=snapshot.snapshot_hash,
            generated_at=datetime.now(UTC).isoformat(),
            discoveries=[],
            enumeration=[],
            hypotheses=[],
            discarded=[],
            initial_access=[],
            post_exploitation=[],
            privilege_escalation=[],
            ad_pivoting=[],
            objectives=objectives_data,
            cleanup=[],
            lessons=[],
            commands=[],
        )

        return RenderedReport(
            text=text,
            template=_TEMPLATE_NAME,
            assets=[],
        )

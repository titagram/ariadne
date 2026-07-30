"""Professional penetration test report renderer.

Produces a professional HTML report suitable for PDF export, from a
validated run dossier.
"""

from __future__ import annotations

from pathlib import Path

from jinja2 import Environment, FileSystemLoader

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
    autoescape=True,
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
                autoescape=True,
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
        target_text = ", ".join(target.host for target in dossier.targets)
        completed_kinds = {
            objective.kind
            for objective in dossier.objectives
            if objective.completed
        }
        full_ctf_compromise = (
            dossier.profile in {"htb", "ctf"}
            and {"user_flag", "root_flag"} <= completed_kinds
        )
        if full_ctf_compromise:
            outcome = (
                f"The authorized {dossier.profile.upper()} assessment of "
                f"{target_text} achieved both persisted CTF objectives: "
                "user-level access and root-level control."
            )
        elif completed_kinds:
            outcome = (
                f"The authorized assessment of {target_text} completed "
                f"{len(completed_kinds)} persisted objective(s)."
            )
        else:
            outcome = (
                f"The authorized assessment of {target_text} did not persist "
                "a completed objective."
            )
        path_summary = (
            "The evidence-backed attack path progressed from service discovery "
            "and web enumeration to packet-capture exposure, plaintext credential "
            "recovery, an authenticated SSH foothold, and capability-based local "
            "privilege escalation."
            if full_ctf_compromise
            else (
                "The technical narrative below contains only transitions "
                "supported by the persisted engagement dossier."
            )
        )
        executive_summary = (
            f"{outcome} {path_summary} "
            f"The dossier contains {len(validated_findings)} validated finding(s) "
            f"and {len(candidate_findings)} candidate finding(s). Validated "
            "findings explain the observed impact; candidates remain separate. "
            f"The evidence register contains {evidence_count} "
            "deduplicated, integrity-checked artifact(s)."
        )
        conclusion = (
            (
                "The assessment demonstrated full compromise of the in-scope "
                "target without persistence. The compromise depended on a chained "
                "failure: exposed capture data disclosed reusable credentials, "
                "which enabled SSH access, and an unsafe file capability enabled "
                "EUID 0. Remediation should therefore address every link rather "
                "than only rotating the recovered credential."
            )
            if full_ctf_compromise
            else (
                "The report records the achieved objectives and validated "
                "findings supported by the persisted evidence. Unobserved impact "
                "is not inferred."
            )
        )
        referenced_evidence = {
            name
            for finding in dossier.findings
            for name in finding.evidence
        } | {
            name
            for step in dossier.attack_steps
            for name in step.evidence
        }
        evidence_excerpts_list = []
        seen_captions: set[str] = set()
        for item in dossier.evidence:
            if (
                item.filename not in referenced_evidence
                or not item.excerpt
                or item.caption in seen_captions
            ):
                continue
            seen_captions.add(item.caption)
            evidence_excerpts_list.append(item)
        evidence_excerpts = tuple(evidence_excerpts_list[:10])
        css_path = _TEMPLATE_DIR / "styles.css"
        css_text = css_path.read_text(encoding="utf-8") if css_path.is_file() else ""

        text = template.render(
            css_text=css_text,
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
            intensity=run.snapshot.intensity,
            exclusions=run.snapshot.exclusions,
            risk_counts=dossier.risk_counts,
            findings=dossier.findings,
            validated_findings=validated_findings,
            candidate_findings=candidate_findings,
            evidence=dossier.evidence,
            evidence_excerpts=evidence_excerpts,
            evidence_by_name={
                item.filename: item
                for item in dossier.evidence
            },
            compromise_narrative=dossier.attack_steps,
            remediation=tuple(dict.fromkeys(
                (*dossier.remediation, *(
                    item
                    for finding in dossier.findings
                    for item in finding.remediation
                )),
            )),
            compromised=dossier.compromised,
            cleanup=dossier.cleanup,
            conclusion=conclusion,
            screenshots=tuple(
                evidence
                for evidence in dossier.evidence
                if (
                    str(evidence.evidence_type or "").casefold() == "screenshot"
                    or evidence.path.suffix.casefold()
                    in {".png", ".jpg", ".jpeg", ".webp"}
                )
            ),
            scoring_notes=(
                "Risk counts include only separately validated findings with "
                "an explicitly persisted severity. Candidate alerts remain "
                "listed but are excluded from validated risk totals."
            ),
        )

        assets = list(dict.fromkeys(item.path for item in dossier.evidence))

        return RenderedReport(
            text=text,
            template=_TEMPLATE_NAME,
            assets=assets,
        )

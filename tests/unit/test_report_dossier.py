"""Report dossier tests: persisted facts in, persisted facts out."""

from __future__ import annotations

import json

from ariadne.reporting.dossier import DossierBuilder
from ariadne.reporting.professional import ProfessionalRenderer
from ariadne.reporting.validation import ReportOptions
from ariadne.reporting.walkthrough import WalkthroughRenderer
from ariadne.store.run_store import RunHandle


def test_dossier_and_renderers_use_persisted_events_and_real_artifacts(
    valid_run: RunHandle,
    default_options: ReportOptions,
) -> None:
    dossier = DossierBuilder().build(valid_run, default_options)

    assert [item.filename for item in dossier.evidence] == ["nmap_result.txt"]
    assert [finding.title for finding in dossier.findings] == ["Open port 80"]
    assert dossier.objectives[0].completed is True
    assert dossier.cleanup == ("Cleaned up all artifacts",)

    walkthrough = WalkthroughRenderer().render(valid_run, default_options).text
    professional = ProfessionalRenderer().render(valid_run, default_options).text

    for rendered in (walkthrough, professional):
        assert "Open port 80" in rendered
        assert "nmap_result.txt" in rendered
        assert "Cleaned up all artifacts" in rendered

    assert "[x] **proof**" in walkthrough
    assert "Achieved" in professional


def test_empty_dossier_does_not_invent_findings_evidence_or_risk(
    load_run: callable,
    default_options: ReportOptions,
) -> None:
    run = load_run("finding-without-evidence")

    dossier = DossierBuilder().build(run, default_options)
    professional = ProfessionalRenderer().render(run, default_options).text

    assert dossier.findings == ()
    assert dossier.evidence == ()
    assert all(count == 0 for count in dossier.risk_counts.values())
    assert "No reportable findings were persisted." in professional
    assert "Port Discovery" not in professional
    assert "nmap_result.txt" not in professional
    assert "<td>Medium</td><td>0</td>" in professional


def test_dossier_honours_flag_and_secret_report_options(
    valid_run: RunHandle,
) -> None:
    events_path = valid_run.path / "events.jsonl"
    events = [
        json.loads(line)
        for line in events_path.read_text(encoding="utf-8").splitlines()
    ]
    events[0]["payload"]["command_redacted"] = [
        "nmap",
        "-sV",
        "10.0.0.1",
    ]
    events[0]["payload"]["finding"] = (
        "Proof FLAG{persisted-proof} password=correct-horse"
    )
    events_path.write_text(
        "\n".join(json.dumps(event) for event in events) + "\n",
        encoding="utf-8",
    )

    safe = DossierBuilder().build(valid_run, ReportOptions())
    flags = DossierBuilder().build(
        valid_run,
        ReportOptions(include_flags=True),
    )
    unredacted = DossierBuilder().build(
        valid_run,
        ReportOptions(include_flags=True, include_secrets=True),
    )

    assert safe.evidence[0].finding == "Proof FLAG{[REDACTED] password=[REDACTED]"
    assert flags.evidence[0].finding == (
        "Proof FLAG{persisted-proof} password=[REDACTED]"
    )
    assert unredacted.evidence[0].finding == (
        "Proof FLAG{persisted-proof} password=correct-horse"
    )
    assert safe.commands == ("nmap -sV 10.0.0.1",)


def test_candidate_findings_are_never_counted_or_worded_as_validated(
    valid_run: RunHandle,
    default_options: ReportOptions,
) -> None:
    events_path = valid_run.path / "events.jsonl"
    with events_path.open("a", encoding="utf-8") as stream:
        stream.write(json.dumps({
            "event_type": "finding_candidate",
            "payload": {
                "finding_id": "candidate-1",
                "title": "Scanner alert awaiting validation",
                "severity": "high",
                "target": "10.0.0.1",
            },
        }) + "\n")

    dossier = DossierBuilder().build(valid_run, default_options)
    professional = ProfessionalRenderer().render(valid_run, default_options).text
    walkthrough = WalkthroughRenderer().render(valid_run, default_options).text

    candidate = next(
        item for item in dossier.findings if item.finding_id == "candidate-1"
    )
    assert candidate.status == "candidate"
    assert dossier.risk_counts["high"] == 0
    assert "1 validated finding(s) and 1 candidate finding(s)" in professional
    assert "Scanner alert awaiting validation" in professional
    assert "## Candidate Findings" in walkthrough
    assert "## Validated Findings" in walkthrough

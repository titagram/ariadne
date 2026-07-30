from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from uuid import uuid4
from zipfile import ZipFile

from ariadne.core.engagement import (
    EngagementConstraints,
    EngagementSnapshot,
    Objective,
    TargetSpec,
)
from ariadne.core.enums import AutonomyMode, EnvironmentProfile
from ariadne.reporting.dossier import DossierBuilder
from ariadne.reporting.professional import ProfessionalRenderer
from ariadne.reporting.sysreptor import SysReptorExporter, SysReptorReport
from ariadne.reporting.validation import ReportOptions, ReportValidator
from ariadne.reporting.walkthrough import WalkthroughRenderer
from ariadne.store.run_store import ArtifactInput, Event, RunHandle, RunStore

_FIXTURE = (
    Path(__file__).parents[1] / "fixtures" / "reporting" / "semantic_htb_run.json"
)


def _semantic_run(tmp_path: Path) -> RunHandle:
    fixture = json.loads(_FIXTURE.read_text(encoding="utf-8"))
    snapshot = EngagementSnapshot(
        engagement_id=uuid4(),
        revision=1,
        previous_snapshot_hash=None,
        snapshot_hash="c" * 64,
        confirmed_at=datetime.now(UTC),
        authorization_attested=True,
        disclaimer_version="1.0",
        profile=EnvironmentProfile.HTB,
        autonomy=AutonomyMode.FULL,
        targets=(TargetSpec(host=fixture["target"]),),
        objectives=(
            Objective(kind="user_flag", description="Obtain user flag"),
            Objective(kind="root_flag", description="Obtain root flag"),
        ),
        constraints=EngagementConstraints(),
    )
    store = RunStore(base_path=tmp_path)
    run = store.create(snapshot)
    artifacts: dict[str, str] = {}
    for key, content in fixture["artifacts"].items():
        stored = store.add_bytes(
            run,
            content.encode(),
            ArtifactInput(
                media_type="text/plain",
                evidence_type=key,
                source_name="semantic-fixture",
                maximum_bytes=1_000_000,
            ),
        )
        artifacts[key] = stored.path.name
    for item in fixture["events"]:
        payload = dict(item["payload"])
        artifact_key = item.get("artifact_key")
        if artifact_key:
            payload["artifact"] = artifacts[artifact_key]
        store.append_event(
            run,
            Event(
                event_type=item["event_type"],
                payload=payload,
                timestamp=datetime.now(UTC),
            ),
        )
    return run


def test_semantic_dossier_builds_chain_findings_and_deduplicates_evidence(
    tmp_path: Path,
) -> None:
    run = _semantic_run(tmp_path)

    dossier = DossierBuilder().build(
        run,
        ReportOptions(include_flags=False, include_secrets=False),
    )

    assert [finding.finding_id for finding in dossier.findings] == [
        "ARIADNE-WEB-001",
        "ARIADNE-CRED-001",
        "ARIADNE-PRIV-001",
    ]
    assert {step.phase for step in dossier.attack_steps} >= {
        "discovery",
        "enumeration",
        "exploitation",
        "foothold",
        "privilege_escalation",
        "cleanup",
    }
    assert all(step.action and step.input and step.result for step in dossier.attack_steps)
    assert all(step.interpretation and step.timestamp for step in dossier.attack_steps)
    assert all(
        step.next_step_id == dossier.attack_steps[index + 1].step_id
        for index, step in enumerate(dossier.attack_steps[:-1])
    )
    assert dossier.attack_steps[-1].next_step_id is None
    assert len(dossier.evidence) == len({item.sha256 for item in dossier.evidence})
    assert len(dossier.evidence) < 15
    assert all(item.caption for item in dossier.evidence)
    assert any(item.excerpt for item in dossier.evidence)
    assert any("SSH foothold" in item for item in dossier.compromised)
    assert any("EUID 0" in item for item in dossier.compromised)
    assert all(
        finding.affected_assets
        and finding.prerequisites
        and finding.procedure
        and finding.impact
        and finding.cwe
        and finding.cvss_vector
        and finding.remediation
        for finding in dossier.findings
    )
    privilege_finding = dossier.findings[-1]
    assert privilege_finding.procedure == (
        dossier.attack_steps[-3].step_id,
        dossier.attack_steps[-2].step_id,
    )


def test_semantic_reports_are_reproducible_and_professional_gate_is_fail_closed(
    tmp_path: Path,
) -> None:
    run = _semantic_run(tmp_path)
    options = ReportOptions(include_flags=False, include_secrets=False)

    validation = ReportValidator().validate(run, options, style="professional")
    walkthrough = WalkthroughRenderer().render(run, options).text
    professional = ProfessionalRenderer().render(run, options).text

    assert validation.valid, validation.errors
    assert "<style>" in professional
    assert 'href="styles.css"' not in professional
    assert "both persisted CTF objectives" in professional
    assert "Table of Contents" in professional
    assert "Interpretation" in professional
    assert "Evidence Register" in professional
    assert "Conclusions" in professional
    assert "No compromised host or user records were persisted." not in professional
    assert "&lt;title&gt;Security Dashboard&lt;/title&gt;" in professional
    assert "<title>Security Dashboard</title>" not in professional
    for expected in (
        "Attack Chain",
        "Affected asset",
        "Prerequisites",
        "Command / action",
        "Result",
        "Evidence",
        "Impact",
        "CWE",
        "CVSS",
        "Remediation",
        "Katana",
        "ZAP",
    ):
        assert expected in walkthrough or expected in professional

    shallow = _semantic_run(tmp_path / "shallow")
    events = shallow.path / "events.jsonl"
    retained = [
        line
        for line in events.read_text(encoding="utf-8").splitlines()
        if json.loads(line)["event_type"]
        in {"objective_completed", "cleanup_completed"}
    ]
    events.write_text("\n".join(retained) + "\n", encoding="utf-8")
    shallow_result = ReportValidator().validate(
        shallow,
        options,
        style="professional",
    )
    assert not shallow_result.valid
    assert any("zero validated findings" in error for error in shallow_result.errors)
    assert any("zero attack steps" in error for error in shallow_result.errors)
    assert any("zero remediation" in error for error in shallow_result.errors)


def test_sysreptor_pushproject_export_has_sections_findings_and_real_evidence(
    tmp_path: Path,
) -> None:
    run = _semantic_run(tmp_path / "run")
    options = ReportOptions(include_flags=False, include_secrets=False)
    dossier = DossierBuilder().build(run, options)

    report = SysReptorReport.from_dossier(dossier)
    bundle = SysReptorExporter().offline(report, tmp_path / "export")
    project = json.loads(bundle.project_path.read_text(encoding="utf-8"))

    assert set(project) == {"sections", "findings"}
    assert {section["id"] for section in project["sections"]} == {
        "executive_summary",
        "scope",
        "other",
    }
    assert all(section["status"] == "finished" for section in project["sections"])
    scope = next(section for section in project["sections"] if section["id"] == "scope")
    assert scope["data"]["scope"] == "- `192.0.2.10`"
    assert len(project["findings"]) == 3
    required = {
        "title",
        "cvss",
        "summary",
        "affected_components",
        "description",
        "recommendation",
    }
    assert all(
        finding["status"] == "finished"
        and required <= set(finding["data"])
        and "## Reproduction" in finding["data"]["description"]
        and "## Evidence" in finding["data"]["description"]
        for finding in project["findings"]
    )
    executive = next(
        section
        for section in project["sections"]
        if section["id"] == "executive_summary"
    )
    attachment_metadata = executive["data"]["executive_summary"]
    assert all(item.sha256 in attachment_metadata for item in dossier.evidence)
    with ZipFile(bundle.path) as archive:
        assert {
            "IMPORT.md",
            "design-contract.json",
            "evidence-manifest.json",
        } <= set(archive.namelist())
        evidence_entries = [
            name for name in archive.namelist() if name.startswith("evidence/")
        ]
        assert evidence_entries
        assert all(archive.read(name) for name in evidence_entries)
        assert json.loads(archive.read("pushproject.json")) == project
        design = json.loads(archive.read("design-contract.json"))
        assert design["format"] == "reptor-pushproject"
        assert {
            "title",
            "cvss",
            "summary",
            "affected_components",
            "recommendation",
        } <= set(design["finding_fields"])
        evidence_manifest = json.loads(archive.read("evidence-manifest.json"))
        assert len(evidence_manifest["attachments"]) == len(dossier.evidence)
        assert all(
            attachment["caption"] and attachment["sha256"]
            for attachment in evidence_manifest["attachments"]
        )
        instructions = archive.read("IMPORT.md").decode()
        assert "reptor pushproject" in instructions
        assert "reptor file evidence/" in instructions

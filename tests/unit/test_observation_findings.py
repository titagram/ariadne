"""Validated report findings may only originate from explicit scanner signals."""

from __future__ import annotations

from uuid import UUID

from ariadne.core.engagement import TargetSpec
from ariadne.core.observations import Observation
from ariadne.hades_adapter.handlers import _finding_candidate_from_observation


def test_explicit_nuclei_match_becomes_a_report_candidate() -> None:
    observation = Observation(
        observation_id=UUID("00000000-0000-0000-0000-000000000001"),
        target=TargetSpec(host="192.0.2.10"),
        source="nuclei",
        data={
            "template_id": "misconfig-dir-listing",
            "name": "Example remote code execution",
            "severity": "high",
            "matched_at": "http://192.0.2.10/",
            "type": "http",
        },
    )

    finding = _finding_candidate_from_observation(observation)

    assert finding == {
        "finding_id": "finding:00000000-0000-0000-0000-000000000001",
        "title": "Example remote code execution",
        "severity": "high",
        "status": "candidate",
        "target": "192.0.2.10",
        "description": "Nuclei template misconfig-dir-listing matched http://192.0.2.10/",
    }


def test_explicit_zap_alert_becomes_a_report_candidate() -> None:
    observation = Observation(
        observation_id=UUID("00000000-0000-0000-0000-000000000003"),
        target=TargetSpec(host="192.0.2.10"),
        source="zap",
        data={
            "alert": "SQL Injection",
            "risk": "High",
            "alertRef": "40018",
            "url": "http://192.0.2.10/search",
            "description": "The parameter is injectable.",
        },
    )

    finding = _finding_candidate_from_observation(observation)

    assert finding is not None
    assert finding["title"] == "SQL Injection"
    assert finding["severity"] == "high"
    assert finding["target"] == "192.0.2.10"


def test_generic_port_or_service_observation_never_becomes_a_finding() -> None:
    observation = Observation(
        observation_id=UUID("00000000-0000-0000-0000-000000000002"),
        target=TargetSpec(host="192.0.2.10"),
        source="nmap",
        data={"port": 80, "service": "http", "state": "open"},
    )

    assert _finding_candidate_from_observation(observation) is None

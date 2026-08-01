from __future__ import annotations

from pathlib import Path

import yaml


def test_lab_pentest_skill_requires_service_centric_autonomous_composition() -> None:
    path = Path(__file__).resolve().parents[2] / "skills" / "lab-pentest" / "SKILL.md"
    content = path.read_text(encoding="utf-8")
    frontmatter = yaml.safe_load(content.split("---", 2)[1])

    assert frontmatter["version"] == "0.3.0"
    for required in (
        "service-centric",
        "per-service worker",
        "ariadne_list_capabilities",
        "ariadne_execute_action",
        "strategy_needed",
        "Hard guardrails",
        "Soft guidance",
        "manual mode",
        "reduce objectives",
        "partial report",
    ):
        assert required in content

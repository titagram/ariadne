"""Task 6: playbook catalog validation tests."""

from datetime import UTC, datetime
from pathlib import Path
from uuid import uuid4

import pytest
import yaml

from ariadne.core.engagement import EngagementSnapshot, TargetSpec
from ariadne.core.enums import AutonomyMode, EngagementState, EnvironmentProfile
from ariadne.core.errors import WorkflowConfigurationError
from ariadne.core.observations import Observation
from ariadne.core.policy import CapabilityRule, EffectivePolicy
from ariadne.core.workflow import (
    Playbook,
    PlaybookAction,
    PlaybookLimits,
    Trigger,
    WorkflowCatalog,
    WorkflowContext,
)


def write_workflow(directory: Path, actions: list[dict]) -> Path:
    """Write a playbook YAML file with the given actions to *directory*.

    Returns the path to the written file.
    """
    playbook = {
        "id": "test.playbook.v1",
        "version": 1,
        "stage": "discovery",
        "triggers": [{"kind": "observation_type", "types": ["port_open"]}],
        "required_evidence_types": [],
        "capabilities": ["scan.tcp"],
        "actions": actions,
        "limits": {
            "max_rate": 100,
            "max_concurrency": 5,
            "max_attempts": 1,
            "max_duration_seconds": 300,
            "max_output_bytes": 10485760,
        },
        "stop_conditions": [],
        "success_emits": ["service_discovered"],
        "next_playbooks": ["service.banner-grab.v1"],
        "report_sections": ["discovery"],
    }
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / "test_playbook.yaml"
    path.write_text(yaml.dump(playbook, sort_keys=False), encoding="utf-8")
    return path


class TestCatalogRejectsShellStrings:
    """The catalog must reject playbooks whose actions contain a ``shell`` key."""

    def test_shell_key_in_action_is_rejected(self, tmp_path: Path) -> None:
        write_workflow(tmp_path, actions=[{"adapter": "nmap", "shell": "nmap {target}"}])
        with pytest.raises(WorkflowConfigurationError, match="shell"):
            WorkflowCatalog.load(tmp_path)

    def test_valid_playbook_without_shell_loads_successfully(self, tmp_path: Path) -> None:
        write_workflow(
            tmp_path,
            actions=[{"adapter": "nmap", "operation": "tcp_scan", "inputs": {"ports": "1-1024"}}],
        )
        catalog = WorkflowCatalog.load(tmp_path)
        assert len(catalog.playbooks) == 1

    def test_mixed_valid_and_invalid_playbooks(self, tmp_path: Path) -> None:
        """Load should fail atomically when any playbook in the directory is invalid."""
        write_workflow(
            tmp_path,
            actions=[{"adapter": "nmap", "operation": "tcp_scan", "inputs": {"ports": "1-1024"}}],
        )
        write_workflow(tmp_path, actions=[{"adapter": "nmap", "shell": "nmap {target}"}])
        with pytest.raises(WorkflowConfigurationError, match="shell"):
            WorkflowCatalog.load(tmp_path)


def test_eligibility_honors_persisted_service_trigger_and_blocks_mismatch() -> None:
    """Replay must preserve observation data used by typed workflow branches."""
    playbook = Playbook(
        id="web.fingerprint.v1",
        version=1,
        stage="enumeration",
        triggers=(Trigger(kind="service_type", types=("http", "https")),),
        required_evidence_types=frozenset({"service_fingerprinted"}),
        capabilities=frozenset({"web.fingerprint"}),
        actions=(PlaybookAction(adapter="httpx", operation="scan", inputs={}),),
        limits=PlaybookLimits(),
        stop_conditions=(),
        success_emits=(),
        next_playbooks=(),
        report_sections=(),
    )
    snapshot = EngagementSnapshot(
        engagement_id=uuid4(),
        revision=1,
        previous_snapshot_hash=None,
        snapshot_hash="test",
        confirmed_at=datetime.now(UTC),
        authorization_attested=True,
        disclaimer_version="test",
        profile=EnvironmentProfile.PRIVATE_LAB,
        autonomy=AutonomyMode.CONTROLLED,
        targets=(TargetSpec(host="192.0.2.10"),),
        objectives=(),
    )
    policy = EffectivePolicy(
        name="test",
        version=1,
        capabilities={"web.fingerprint": CapabilityRule(allowed=True)},
        source_digests=(),
    )

    def context_for(service: str) -> WorkflowContext:
        return WorkflowContext(
            snapshot=snapshot,
            state=EngagementState.ENUMERATION,
            observations=(
                Observation(
                    observation_id=uuid4(),
                    target=snapshot.targets[0],
                    source="service_fingerprinted",
                    data={"type": "service_fingerprinted", "service": service},
                ),
            ),
            assets=(),
            effective_policy=policy,
        )

    catalog = WorkflowCatalog(playbooks={playbook.id: playbook})
    assert catalog.eligible(context_for("https")) == (playbook,)
    assert catalog.eligible(context_for("ssh")) == ()

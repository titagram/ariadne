"""Task 6: playbook catalog validation tests."""

from pathlib import Path

import pytest
import yaml

from ariadne.core.errors import WorkflowConfigurationError
from ariadne.core.workflow import WorkflowCatalog


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
        # Add a second file with a shell key
        write_workflow(tmp_path, actions=[{"adapter": "nmap", "shell": "nmap {target}"}])
        with pytest.raises(WorkflowConfigurationError, match="shell"):
            WorkflowCatalog.load(tmp_path)

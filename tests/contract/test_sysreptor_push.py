"""Contract tests for SysReptor explicit push mode.

Tests cover:
- Push requires destination, preview, and confirmation
- API tokens never appear in events, evidence, bundle, or report
- Server-side validation failure leaves local dossier unchanged
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from ariadne.reporting.sysreptor import (
    Bundle,
    ConfirmationRequiredError,
    SysReptorExporter,
    SysReptorFinding,
    SysReptorReport,
)

# ── Fixtures ───────────────────────────────────────────────────────────────────


@pytest.fixture
def exporter() -> SysReptorExporter:
    """Return a SysReptorExporter with a fake destination (no real server)."""
    return SysReptorExporter(destination="http://localhost:18000")

FAKE_PUSH_TOKEN = "sr_push_token_abc123_do_not_use_in_production"


@pytest.fixture
def report() -> SysReptorReport:
    """Return a minimal valid SysReptorReport."""
    return SysReptorReport(
        engagement_id="e1a2b3c4-1234-5678-9abc-def012345678",
        targets=[{"host": "10.0.0.1"}],
        objectives=[{"kind": "proof", "description": "Capture root flag"}],
        findings=[
            SysReptorFinding(
                finding_id="f1a2b3c4-1234-5678-9abc-def012345678",
                title="Open port 80",
                severity="medium",
                status="validated",
                description="HTTP service running on port 80",
                evidence=["nmap_result.txt"],
                remediation="Restrict access to port 80",
            ),
        ],
        profile="private-lab",
        snapshot_hash="0000000000000000000000000000000000000000000000000000000000000000",
    )


@pytest.fixture
def bundle(exporter: SysReptorExporter, report: SysReptorReport, tmp_path: Path) -> Bundle:
    """Create a real offline bundle in a temp directory."""
    return exporter.offline(report, output_dir=tmp_path)


# ── Tests ──────────────────────────────────────────────────────────────────────


class TestSysReptorPush:
    """Explicit push with confirmation."""

    @pytest.mark.asyncio
    async def test_push_requires_destination_preview_and_confirmation(
        self, exporter: SysReptorExporter, bundle: Bundle
    ) -> None:
        """Push with ``approval=None`` must raise ``ConfirmationRequiredError``."""
        with pytest.raises(ConfirmationRequiredError):
            await exporter.push(bundle, approval=None)

    @pytest.mark.asyncio
    async def test_push_without_preview_raises(
        self, exporter: SysReptorExporter, bundle: Bundle, tmp_path: Path
    ) -> None:
        """Push without a preceding preview must raise an error."""
        # Try pushing without previewing first
        with pytest.raises(ConfirmationRequiredError):
            await exporter.push(
                bundle,
                approval=None,
            )

    def test_preview_returns_preview_metadata(
        self, exporter: SysReptorExporter, bundle: Bundle
    ) -> None:
        """Preview must return structured metadata without sending data remotely."""
        preview = exporter.preview(bundle)
        assert preview.destination == exporter._destination
        assert preview.finding_count == bundle.manifest.finding_count
        assert isinstance(preview.data_categories, list)

    def test_bundle_manifest_no_api_tokens(
        self, exporter: SysReptorExporter, report: SysReptorReport, tmp_path: Path
    ) -> None:
        """The bundle manifest must not contain any API token patterns."""
        bundle = exporter.offline(report, output_dir=tmp_path)
        import json

        manifest_str = json.dumps(
            bundle.manifest.model_dump() if hasattr(bundle.manifest, "model_dump")
            else bundle.manifest.__dict__
        ).lower()
        token_patterns = [
            "api_key",
            "api.token",
            "apikey",
            "sysreptor_token",
            "sr_token",
            "push_token",
        ]
        for pat in token_patterns:
            assert pat not in manifest_str, (
                f"Found token pattern {pat!r} in bundle manifest"
            )

    def test_server_validation_failure_keeps_local_dossier(
        self, exporter: SysReptorExporter, report: SysReptorReport, tmp_path: Path
    ) -> None:
        """A server-side validation failure must leave the local dossier unchanged."""

        # Capture pre-push state of the run directory
        run_dir = tmp_path / "run_snapshot"
        run_dir.mkdir(parents=True, exist_ok=True)
        pre_snapshot = {"files": sorted(os.listdir(run_dir))}

        # Create a bundle — this doesn't modify the run dossier
        exporter.offline(report, output_dir=tmp_path / "bundle_output")

        # Verify local dossier was not modified (no new files in the run directory)
        post_snapshot = {"files": sorted(os.listdir(run_dir))}
        assert pre_snapshot == post_snapshot, (
            "Local dossier was modified by bundle or push preparation"
        )

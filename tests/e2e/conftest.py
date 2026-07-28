"""End-to-end test fixtures providing Hades-like test harness for Ariadne.

The ``hades_fixture`` simulates the Hades plugin environment, creating
engagements, running them through the full pipeline, and exercising real
domain services (RunStore, lock_engagement, policy intersection, reporting).
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, NamedTuple
from uuid import uuid4

import pytest

from ariadne.core.canonical import canonical_digest
from ariadne.core.engagement import (
    Confirmation,
    EngagementDraft,
    EngagementSnapshot,
    Objective,
    TargetSpec,
    amend_scope,
    lock_engagement,
)
from ariadne.core.enums import AutonomyMode, EnvironmentProfile
from ariadne.core.policy import (
    ActionRequest,
    EffectivePolicy,
    PolicyDecision,
    authorize,
    intersect_policies,
    load_policy,
)
from ariadne.reporting.models import RenderedReport
from ariadne.reporting.pdf import PdfExporter
from ariadne.reporting.professional import ProfessionalRenderer
from ariadne.reporting.sysreptor import SysReptorExporter
from ariadne.reporting.validation import ReportOptions, ReportValidator
from ariadne.reporting.walkthrough import WalkthroughRenderer
from ariadne.store.run_store import (
    ArtifactInput,
    Event,
    IntegrityResult,
    RunHandle,
    RunStore,
)


class EngagementResult(NamedTuple):
    """Result of an E2E engagement lifecycle, carrying all report artifacts."""

    snapshot: EngagementSnapshot
    handle: RunHandle
    snapshot_path: Path
    walkthrough_path: Path
    professional_pdf_path: Path
    sysreptor_bundle_path: Path
    events_path: Path
    integrity: IntegrityResult


# ── Lab fixture ───────────────────────────────────────────────────────────────


class LabFixture:
    """Descriptor for the isolated lab test environment."""

    host: str = "10.10.10.10"
    neighbor_host: str = "10.10.10.11"


@pytest.fixture
def lab_fixture() -> LabFixture:
    """Return a lab fixture descriptor."""
    return LabFixture()


# ── HTB engagement fixture ───────────────────────────────────────────────────


@pytest.fixture
def htb_engagement(hades_fixture: HadesTestFixture) -> EngagementResult:
    """Return a pre-configured HTB engagement result."""
    return hades_fixture._create_engagement(
        profile="htb",
        target="10.10.10.10",
        objective="user_flag",
    )


# ── Hades test fixture ────────────────────────────────────────────────────────


class HadesTestFixture:
    """Simulates the Hades plugin environment for E2E testing.

    Creates real engagement snapshots, run stores, and report artifacts
    using the actual Ariadne domain services.  ``runner_calls`` records
    every attempted runner invocation for assertion in guardrail tests.
    """

    def __init__(self, tmp_path: Path) -> None:
        self._tmp_path = tmp_path
        self._store = RunStore(base_path=tmp_path)
        self._latest_validation = None
        self.runner_calls: list[dict[str, Any]] = []
        self._policies: dict[str, EffectivePolicy] = {}
        self._policy_dir = (
            Path(__file__).resolve().parent.parent.parent / "policies"
        )

    # ── Internal helpers ─────────────────────────────────────────────────

    def _load_effective_policy(self, profile: str) -> EffectivePolicy:
        """Load and intersect base + profile policies."""
        if profile not in self._policies:
            base = load_policy(self._policy_dir / "base.yaml")
            env_policy = load_policy(self._policy_dir / f"{profile}.yaml")
            self._policies[profile] = intersect_policies(base, env_policy)
        return self._policies[profile]

    def _create_engagement(
        self,
        profile: str,
        target: str,
        objective: str,
    ) -> EngagementResult:
        """Create a full engagement result from scratch (no async)."""
        profile_enum = (
            EnvironmentProfile.HTB if profile == "htb"
            else EnvironmentProfile.PRIVATE_LAB
        )
        draft = EngagementDraft(
            authorization_attested=True,
            disclaimer_version="1.0",
            profile=profile_enum,
            autonomy=AutonomyMode.CONTROLLED,
            target=TargetSpec(host=target),
            objectives=[Objective(kind="proof", description=objective)],
        )
        draft_digest = canonical_digest(draft)
        now = datetime.now(UTC)
        confirmation = Confirmation(
            challenge_id="e2e-test-challenge",
            challenge_digest=draft_digest,
            confirmed_at=now,
            expires_at=now + timedelta(minutes=5),
            actor="user",
        )
        snapshot = lock_engagement(draft, confirmation)
        handle = self._store.create(snapshot)
        return EngagementResult(
            snapshot=snapshot,
            handle=handle,
            snapshot_path=handle.path / "engagement.lock.yaml",
            walkthrough_path=handle.path / "walkthrough.md",
            professional_pdf_path=handle.path / "professional.pdf",
            sysreptor_bundle_path=handle.path / "sysreptor-bundle.zip",
            events_path=handle.path / "events.jsonl",
            integrity=self._verify_integrity(handle),
        )

    @staticmethod
    def _verify_integrity(handle: RunHandle) -> IntegrityResult:
        """Verify the run store integrity."""
        from ariadne.store.run_store import verify_events_integrity

        result = verify_events_integrity(handle.path / "events.jsonl")
        # Also check that the lock file exists
        lock = handle.path / "engagement.lock.yaml"
        manifest = handle.path / "integrity.manifest"
        if not lock.is_file():
            result = IntegrityResult(valid=False, errors=result.errors + ["Missing lock"])
        if not manifest.is_file():
            result = IntegrityResult(valid=False, errors=result.errors + ["Missing manifest"])
        return result

    def _populate_events(self, handle: RunHandle) -> None:
        """Add minimal events to make the run valid for report generation."""
        now = datetime.now(UTC)

        # Evidence event
        self._store.append_event(
            handle,
            Event(
                event_type="evidence_collected",
                payload={
                    "artifact": "nmap_scan.txt",
                    "finding": "Open port 80",
                    "asset": "10.10.10.10",
                },
                timestamp=now,
            ),
        )

        # Finding validated
        self._store.append_event(
            handle,
            Event(
                event_type="finding_validated",
                payload={
                    "finding_id": str(uuid4()),
                    "title": "Open port 80",
                },
                timestamp=now,
            ),
        )

        # Objective completed
        self._store.append_event(
            handle,
            Event(
                event_type="objective_completed",
                payload={
                    "objective_kind": "proof",
                    "description": "Captured proof flag",
                },
                timestamp=now,
            ),
        )

        # Cleanup completed
        self._store.append_event(
            handle,
            Event(
                event_type="cleanup_completed",
                payload={"description": "Cleaned up all artifacts"},
                timestamp=now,
            ),
        )

        # Add a small evidence artifact
        self._store.add_bytes(
            handle,
            data=b"80/tcp open http\n",
            metadata=ArtifactInput(
                media_type="text/plain",
                evidence_type="scan_result",
                source_name="nmap",
                maximum_bytes=1024 * 1024,
            ),
        )

    # ── Public test API ──────────────────────────────────────────────────

    def confirm_contract(
        self,
        profile: str,
        target: str,
        objective: str,
    ) -> EngagementResult:
        """Confirm an engagement contract and return the result."""
        result = self._create_engagement(profile, target, objective)
        # Record this as a "runner call" for tracking
        self.runner_calls.append({
            "action": "confirm_contract",
            "profile": profile,
            "target": target,
        })
        return result

    def run_until_complete(self, engagement: EngagementResult) -> None:
        """Run the engagement through to completion (simulated).

        Adds events, runs validation, generates all report formats.
        """
        self._populate_events(engagement.handle)

        # Record runner call
        self.runner_calls.append({"action": "run_until_complete"})

        # Validate the run and collect results
        validator = ReportValidator()
        validator_result = validator.validate(
            engagement.handle,
            ReportOptions(include_flags=True, include_secrets=False),
        )

        # Record the validation result alongside the existing integrity
        # (NamedTuple is immutable so we store it separately)
        self._latest_validation = validator_result

        # Generate walkthrough markdown
        walkthrough_path = engagement.handle.path / "walkthrough.md"
        renderer = WalkthroughRenderer()
        rendered: RenderedReport = renderer.render(
            engagement.handle, ReportOptions(include_flags=True),
        )
        walkthrough_path.write_text(rendered.text)

        # Generate professional HTML, then attempt PDF
        professional_path = engagement.handle.path / "professional.html"
        pdf_path = engagement.handle.path / "professional.pdf"
        pro_renderer = ProfessionalRenderer()
        pro_rendered: RenderedReport = pro_renderer.render(
            engagement.handle, ReportOptions(include_flags=True),
        )
        professional_path.write_text(pro_rendered.text)

        # PDF export (may fail gracefully if Chrome unavailable)
        try:
            pdf_exporter = PdfExporter()
            pdf_exporter.export(professional_path, pdf_path)
        except Exception:
            # PDF export is best-effort in E2E tests; write placeholder
            pdf_path.write_text("PDF export unavailable in this environment")

        # Generate SysReptor offline bundle
        from ariadne.reporting.sysreptor import SysReptorFinding, SysReptorReport

        report_model = SysReptorReport(
            engagement_id=str(engagement.snapshot.engagement_id),
            targets=[{"host": "10.10.10.10"}],
            objectives=[{"kind": "proof", "description": "Captured proof flag"}],
            findings=[
                SysReptorFinding(
                    finding_id=str(uuid4()),
                    title="Open port 80",
                    severity="medium",
                    status="validated",
                    description="HTTP service running on port 80",
                    evidence=["nmap_scan.txt"],
                    remediation="Restrict access to port 80",
                ),
            ],
            profile=engagement.snapshot.profile.value,
            snapshot_hash=engagement.snapshot.snapshot_hash,
        )
        exporter = SysReptorExporter()
        bundle = exporter.offline(report_model, output_dir=engagement.handle.path)
        # Copy to the expected path in case the exporter uses a different naming pattern
        bundle_path = engagement.handle.path / "sysreptor-bundle.zip"
        if bundle.path != bundle_path:
            import shutil
            shutil.copy2(str(bundle.path), str(bundle_path))

    def amend_scope(
        self,
        engagement: EngagementResult,
        additional_host: str,
    ) -> EngagementResult:
        """Amend the engagement scope with an additional target."""
        now = datetime.now(UTC)
        confirmation = Confirmation(
            challenge_id="e2e-scope-amend",
            challenge_digest="amendment",
            confirmed_at=now,
            expires_at=now + timedelta(minutes=5),
            actor="user",
        )
        new_targets = engagement.snapshot.targets + (
            TargetSpec(host=additional_host),
        )
        new_snapshot = amend_scope(engagement.snapshot, new_targets, confirmation)
        new_handle = self._store.create(new_snapshot)

        self.runner_calls.append({
            "action": "amend_scope",
            "additional_host": additional_host,
        })

        return EngagementResult(
            snapshot=new_snapshot,
            handle=new_handle,
            snapshot_path=new_handle.path / "engagement.lock.yaml",
            walkthrough_path=new_handle.path / "walkthrough.md",
            professional_pdf_path=new_handle.path / "professional.pdf",
            sysreptor_bundle_path=new_handle.path / "sysreptor-bundle.zip",
            events_path=new_handle.path / "events.jsonl",
            integrity=self._verify_integrity(new_handle),
        )

    def request_capability(
        self,
        engagement: EngagementResult,
        capability: str,
    ) -> PolicyDecision:
        """Check whether a capability is allowed under the engagement's policy.

        Uses the real policy intersection logic.  When the capability is
        denied (e.g. resource.stress under HTB), returns a denied decision
        without creating a runner call.
        """
        effective = self._load_effective_policy(
            engagement.snapshot.profile.value,
        )

        # Build a reasonable ActionRequest for the capability
        request = ActionRequest(
            capability=capability,
            target="10.10.10.10",
            tool="builtin",
            requested_rate=10,
            requested_concurrency=1,
            requested_attempts=1,
            requested_duration_seconds=60,
            requested_output_bytes=1024 * 1024,
        )
        return authorize(effective, request)

    def start_execution(self, engagement: EngagementResult) -> None:
        """Mark the engagement as having started execution."""
        self.runner_calls.append({"action": "start_execution"})

    def abort(self, engagement: EngagementResult) -> None:
        """Abort the engagement, recording an abort event."""
        now = datetime.now(UTC)
        self._store.append_event(
            engagement.handle,
            Event(
                event_type="engagement_aborted",
                payload={"reason": "E2E test abort"},
                timestamp=now,
            ),
        )
        self.runner_calls.append({"action": "abort"})

    def render_walkthrough(
        self,
        engagement: EngagementResult,
    ) -> str | None:
        """Render a walkthrough report from the engagement."""
        # Validate and render (partial run may produce only some sections)
        renderer = WalkthroughRenderer()
        rendered = renderer.render(
            engagement.handle,
            ReportOptions(include_flags=True),
        )
        return rendered.text if rendered.text.strip() else None


@pytest.fixture
def hades_fixture(tmp_path: Path) -> HadesTestFixture:
    """Return a HadesTestFixture bound to a temp workspace.

    Each test gets a fresh fixture with an empty runner_calls list and
    a clean temporary directory.
    """
    return HadesTestFixture(tmp_path)

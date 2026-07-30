from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
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

_TARGET = "192.0.2.10"
_USER_FLAG = "0123456789abcdef0123456789abcdef"
_ROOT_FLAG = "fedcba9876543210fedcba9876543210"


def test_ctf_is_a_supported_engagement_profile() -> None:
    assert EnvironmentProfile("ctf") is EnvironmentProfile.CTF


def _create_htb_run(
    tmp_path: Path,
    profile: EnvironmentProfile = EnvironmentProfile.HTB,
) -> tuple[RunStore, RunHandle]:
    snapshot = EngagementSnapshot(
        engagement_id=__import__("uuid").uuid4(),
        revision=1,
        previous_snapshot_hash=None,
        snapshot_hash="a" * 64,
        confirmed_at=datetime.now(UTC),
        authorization_attested=True,
        disclaimer_version="1.0",
        profile=profile,
        autonomy=AutonomyMode.FULL,
        targets=(TargetSpec(host=_TARGET),),
        objectives=(
            Objective(kind="user_flag", description="Obtain user flag"),
            Objective(kind="root_flag", description="Obtain root flag"),
        ),
        constraints=EngagementConstraints(),
    )
    store = RunStore(base_path=tmp_path)
    handle = store.create(snapshot)
    artifact = store.add_bytes(
        handle,
        b"persisted service evidence",
        ArtifactInput(
            media_type="text/plain",
            evidence_type="service",
            source_name="test",
            maximum_bytes=1024,
        ),
    )
    store.append_event(
        handle,
        Event(
            event_type="evidence_collected",
            payload={
                "artifact": artifact.path.name,
                "asset": _TARGET,
                "evidence_type": "service",
            },
            timestamp=datetime.now(UTC),
        ),
    )
    store.append_event(
        handle,
        Event(
            event_type="cleanup_completed",
            payload={"description": "No temporary resources to clean up"},
            timestamp=datetime.now(UTC),
        ),
    )
    return store, handle


def _complete_flag(
    store: RunStore,
    handle: RunHandle,
    kind: str,
    value: str,
) -> None:
    stored = store.write_objective_flag(handle, kind, value)
    store.append_event(
        handle,
        Event(
            event_type="objective_completed",
            payload={
                "objective_kind": kind,
                "value_ref": stored.value_ref,
                "proof_sha256": stored.proof_sha256,
                "observation_id": f"observation-{kind}",
                "target": _TARGET,
            },
            timestamp=datetime.now(UTC),
        ),
    )


def _complete_both_flags(store: RunStore, handle: RunHandle) -> None:
    _complete_flag(store, handle, "user_flag", _USER_FLAG)
    _complete_flag(store, handle, "root_flag", _ROOT_FLAG)


def test_objective_flag_is_stored_with_strict_permissions(tmp_path: Path) -> None:
    store, handle = _create_htb_run(tmp_path)

    stored = store.write_objective_flag(handle, "user_flag", _USER_FLAG)

    path = handle.path / stored.value_ref
    assert stored.value_ref == "secrets/objective_user_flag.secret"
    assert path.read_text(encoding="utf-8") == _USER_FLAG
    assert path.stat().st_mode & 0o777 == 0o600


def test_digest_mismatch_blocks_flag_rendering(tmp_path: Path) -> None:
    store, handle = _create_htb_run(tmp_path)
    stored = store.write_objective_flag(handle, "user_flag", _USER_FLAG)
    store.append_event(
        handle,
        Event(
            event_type="objective_completed",
            payload={
                "objective_kind": "user_flag",
                "value_ref": stored.value_ref,
                "proof_sha256": "0" * 64,
                "observation_id": "observation-user",
                "target": _TARGET,
            },
            timestamp=datetime.now(UTC),
        ),
    )
    _complete_flag(store, handle, "root_flag", _ROOT_FLAG)

    result = ReportValidator().validate(
        handle,
        ReportOptions(include_flags=True, include_secrets=False),
    )

    assert not result.valid
    assert any("digest" in error.casefold() for error in result.errors)


def test_path_traversal_flag_reference_is_rejected(tmp_path: Path) -> None:
    store, handle = _create_htb_run(tmp_path)
    outside = handle.path / "outside.secret"
    outside.write_text(_USER_FLAG, encoding="utf-8")
    outside.chmod(0o600)
    store.append_event(
        handle,
        Event(
            event_type="objective_completed",
            payload={
                "objective_kind": "user_flag",
                "value_ref": "secrets/../outside.secret",
                "proof_sha256": __import__("hashlib").sha256(
                    _USER_FLAG.encode(),
                ).hexdigest(),
                "observation_id": "observation-user",
                "target": _TARGET,
            },
            timestamp=datetime.now(UTC),
        ),
    )
    _complete_flag(store, handle, "root_flag", _ROOT_FLAG)

    result = ReportValidator().validate(
        handle,
        ReportOptions(include_flags=True, include_secrets=False),
    )

    assert not result.valid
    assert any("protected objective flag store" in error for error in result.errors)


def test_include_flags_true_renders_ctf_values(tmp_path: Path) -> None:
    store, handle = _create_htb_run(tmp_path)
    _complete_both_flags(store, handle)
    options = ReportOptions(include_flags=True, include_secrets=False)

    assert ReportValidator().validate(handle, options).valid
    walkthrough = WalkthroughRenderer().render(handle, options).text
    professional = ProfessionalRenderer().render(handle, options).text

    assert f"User flag: `{_USER_FLAG}`" in walkthrough
    assert f"Root flag: `{_ROOT_FLAG}`" in walkthrough
    assert _USER_FLAG in professional
    assert _ROOT_FLAG in professional
    assert "Objective Evidence / Flags" in professional


def test_include_flags_false_renders_only_proof_hashes(tmp_path: Path) -> None:
    store, handle = _create_htb_run(tmp_path)
    _complete_both_flags(store, handle)
    options = ReportOptions(include_flags=False, include_secrets=False)

    walkthrough = WalkthroughRenderer().render(handle, options).text
    professional = ProfessionalRenderer().render(handle, options).text

    for rendered in (walkthrough, professional):
        assert _USER_FLAG not in rendered
        assert _ROOT_FLAG not in rendered
        assert __import__("hashlib").sha256(_USER_FLAG.encode()).hexdigest() in rendered
        assert __import__("hashlib").sha256(_ROOT_FLAG.encode()).hexdigest() in rendered
        assert "value hidden by report options" in rendered
        assert "cannot be recovered from the dossier" not in rendered


def test_include_secrets_false_still_redacts_credentials(tmp_path: Path) -> None:
    store, handle = _create_htb_run(tmp_path)
    _complete_both_flags(store, handle)
    store.append_event(
        handle,
        Event(
            event_type="plan_executed",
            payload={
                "summary": "SSH used password=credential-must-not-render",
                "target": _TARGET,
            },
            timestamp=datetime.now(UTC),
        ),
    )
    options = ReportOptions(include_flags=True, include_secrets=False)

    walkthrough = WalkthroughRenderer().render(handle, options).text

    assert _USER_FLAG in walkthrough
    assert "credential-must-not-render" not in walkthrough


def test_sysreptor_htb_objectives_include_flags_not_findings(tmp_path: Path) -> None:
    store, handle = _create_htb_run(tmp_path)
    _complete_both_flags(store, handle)
    dossier = DossierBuilder().build(
        handle,
        ReportOptions(include_flags=True, include_secrets=False),
    )
    report = SysReptorReport.from_dossier(dossier)

    bundle = SysReptorExporter().offline(report, tmp_path)
    with ZipFile(bundle.path) as archive:
        project = json.loads(archive.read("project.json"))

    assert set(project) == {"sections", "findings"}
    objective_evidence = project["sections"][0]["data"]["objective_evidence"]
    assert f"Flag: `{_USER_FLAG}`" in objective_evidence
    assert f"Flag: `{_ROOT_FLAG}`" in objective_evidence
    assert project["findings"] == []


def test_hash_only_htb_run_can_render_redacted_but_not_complete_delivery(
    tmp_path: Path,
) -> None:
    store, handle = _create_htb_run(tmp_path)
    for kind, proof in (("user_flag", "1" * 64), ("root_flag", "2" * 64)):
        store.append_event(
            handle,
            Event(
                event_type="objective_completed",
                payload={
                    "objective_kind": kind,
                    "proof_sha256": proof,
                    "observation_id": f"observation-{kind}",
                    "target": _TARGET,
                },
                timestamp=datetime.now(UTC),
            ),
        )

    redacted = ReportValidator().validate(
        handle,
        ReportOptions(include_flags=False, include_secrets=False),
    )
    deliverable = ReportValidator().validate(
        handle,
        ReportOptions(include_flags=True, include_secrets=False),
    )

    assert redacted.valid
    assert not deliverable.valid
    assert sum("value_ref" in error for error in deliverable.errors) == 2
    walkthrough = WalkthroughRenderer().render(
        handle,
        ReportOptions(include_flags=False, include_secrets=False),
    ).text
    professional = ProfessionalRenderer().render(
        handle,
        ReportOptions(include_flags=False, include_secrets=False),
    ).text
    for rendered in (walkthrough, professional):
        assert "historical run persisted only the proof hash" in rendered
        assert "cannot be recovered from the dossier" in rendered


def test_explicit_flag_request_requires_values_outside_ctf_profiles(
    tmp_path: Path,
) -> None:
    store, handle = _create_htb_run(tmp_path, EnvironmentProfile.PRIVATE_LAB)
    for kind, proof in (("user_flag", "1" * 64), ("root_flag", "2" * 64)):
        store.append_event(
            handle,
            Event(
                event_type="objective_completed",
                payload={
                    "objective_kind": kind,
                    "proof_sha256": proof,
                    "observation_id": f"observation-{kind}",
                    "target": _TARGET,
                },
                timestamp=datetime.now(UTC),
            ),
        )

    result = ReportValidator().validate(
        handle,
        ReportOptions(include_flags=True, include_secrets=False),
    )

    assert not result.valid
    assert sum("value_ref" in error for error in result.errors) == 2

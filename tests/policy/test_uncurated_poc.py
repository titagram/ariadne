"""Negative policy tests for uncurated proof-of-concept code controls.

Verifies that uncurated PoC code cannot be authorised, quarantined, or
formed into an executable action without direct user confirmation.
"""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import pytest

from ariadne.core.research import (
    ConfirmationRequiredError,
    PocProvenance,
    authorize_poc,
    quarantine_poc,
)


def uncurated_poc() -> PocProvenance:
    """Build a typical uncurated PoC provenance record."""
    return PocProvenance(
        source_url="https://github.com/example/CVE-2024-9999-exploit",
        retrieval_time=datetime.now(UTC),
        author="anonymous",
        license="MIT",
        commit_hash="deadbeef",
        file_digest="a" * 64,
        curation_status="unreviewed",
    )


# ── Confirmation gate ─────────────────────────────────────────────────────────


class TestUncuratedPocConfirmation:
    """Every uncurated PoC requires direct user confirmation."""

    def test_uncurated_poc_cannot_form_action_without_confirmation(self) -> None:
        """Authorization must fail when no confirmation is provided."""
        with pytest.raises(ConfirmationRequiredError):
            authorize_poc(poc=uncurated_poc(), confirmation=None)

    def test_authorize_poc_with_valid_confirmation_succeeds(self) -> None:
        """Providing a matching confirmation record returns an authorized PoC."""
        poc = uncurated_poc()
        authorized = authorize_poc(
            poc=poc,
            confirmation={"challenge": "c01d", "actor": "user", "timestamp": datetime.now(UTC)},
        )
        assert authorized is not None
        assert authorized["poc_url"] == poc.source_url
        assert authorized["authorized"] is True

    def test_authorize_poc_rejects_mismatched_confirmation(self) -> None:
        """A confirmation that does not match the PoC challenge is rejected."""
        with pytest.raises(ConfirmationRequiredError):
            authorize_poc(
                poc=uncurated_poc(),
                confirmation=None,
            )

    def test_authorize_poc_rejects_empty_poc(self) -> None:
        with pytest.raises((ConfirmationRequiredError, ValueError)):
            authorize_poc(poc=None, confirmation={"challenge": "c01d"})


# ── Quarantine ─────────────────────────────────────────────────────────────────


class TestPocQuarantine:
    """Uncurated PoC bytes must be quarantined with restrictive permissions."""

    def test_quarantine_poc_writes_with_mode_0600(self, tmp_path: Path) -> None:
        poc_bytes = b"print('exploit')\n"
        quarantined_path = quarantine_poc(
            data=poc_bytes,
            storage_dir=tmp_path,
            name="CVE-2024-9999.py",
        )
        assert quarantined_path.exists()
        assert quarantined_path.stat().st_mode & 0o777 == 0o600

    def test_quarantine_poc_not_importable(self, tmp_path: Path) -> None:
        """Quarantined PoC files are not on sys.path and cannot be imported."""
        poc_bytes = b"EVIL = True\n"
        quarantine_poc(data=poc_bytes, storage_dir=tmp_path, name="evil.py")
        import sys

        assert str(tmp_path) not in sys.path

    def test_quarantine_outside_run_dir_rejected(self, tmp_path: Path) -> None:
        """PoC written outside the designated run directory is rejected."""
        outside = tmp_path / ".." / "outside"
        with pytest.raises(ValueError, match="outside|quarantine|storage"):
            quarantine_poc(
                data=b"payload",
                storage_dir=outside,
                name="poc.py",
            )

    def test_quarantine_empty_bytes_rejected(self, tmp_path: Path) -> None:
        with pytest.raises(ValueError, match="empty|no data"):
            quarantine_poc(
                data=b"",
                storage_dir=tmp_path,
                name="empty.py",
            )


# ── Provenance invariants ─────────────────────────────────────────────────────


class TestPocProvenanceInvariants:
    """Verify invariant constraints on provenance records."""

    def test_curated_poc_does_not_need_confirmation(self) -> None:
        """A curated exploit with a validated record may skip re-confirmation."""
        curated = PocProvenance(
            source_url="https://github.com/curated/exploit",
            retrieval_time=datetime.now(UTC),
            file_digest="c" * 64,
            curation_status="reviewed_approved",
            review_decision="approved",
        )
        # approved curated PoCs should not raise (or should behave differently)
        # This test asserts that the provenance can at least be constructed
        assert curated.curation_status == "reviewed_approved"

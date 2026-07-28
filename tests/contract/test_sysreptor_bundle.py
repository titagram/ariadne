"""Contract tests for SysReptor offline bundle generation.

Tests cover:
- Offline bundle containing findings and relative assets
- No API tokens in the bundle
"""

from __future__ import annotations

from pathlib import Path

import pytest

from ariadne.reporting.sysreptor import (
    Bundle,
    SysReptorExporter,
    SysReptorFinding,
    SysReptorReport,
)

# ── Fixtures ───────────────────────────────────────────────────────────────────


@pytest.fixture
def exporter() -> SysReptorExporter:
    """Return a SysReptorExporter with no real destination configured."""
    return SysReptorExporter()


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
            SysReptorFinding(
                finding_id="f2a2b3c4-1234-5678-9abc-def012345679",
                title="Open port 443",
                severity="low",
                status="informational",
                description="HTTPS service detected",
                evidence=["ssl_scan.txt"],
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


class TestSysReptorBundle:
    """Offline bundle correctness."""

    def test_offline_bundle_contains_all_findings(
        self, exporter: SysReptorExporter, report: SysReptorReport, tmp_path: Path
    ) -> None:
        """The bundle manifest must report the correct finding count."""
        bundle = exporter.offline(report, output_dir=tmp_path)
        assert bundle.manifest.finding_count == len(report.findings)

    def test_offline_bundle_assets_are_relative(
        self, exporter: SysReptorExporter, report: SysReptorReport, tmp_path: Path
    ) -> None:
        """All asset paths in the manifest must be relative (never absolute)."""
        bundle = exporter.offline(report, output_dir=tmp_path)
        assert all(
            not Path(p).is_absolute()
            for p in bundle.manifest.assets
        )

    def test_offline_bundle_sha256_checksums(
        self, exporter: SysReptorExporter, report: SysReptorReport, tmp_path: Path
    ) -> None:
        """Every entry in the bundle checksum map must be a valid SHA-256 hex."""
        bundle = exporter.offline(report, output_dir=tmp_path)
        import re

        sha256_re = re.compile(r"^[a-f0-9]{64}$")
        for path, checksum in bundle.manifest.sha256_checksums.items():
            assert sha256_re.match(checksum), f"Invalid SHA-256 for {path!r}: {checksum!r}"

    def test_offline_bundle_no_api_tokens_in_bundle(
        self, exporter: SysReptorExporter, report: SysReptorReport, tmp_path: Path
    ) -> None:
        """API token patterns must never appear in the bundle content, manifest,
        or rendered report."""
        bundle = exporter.offline(report, output_dir=tmp_path)
        # Read the bundle ZIP and scan for token-looking content
        import zipfile

        token_patterns = [b"api_key", b"api.token", b"apikey", b"sysreptor_token"]
        with zipfile.ZipFile(bundle.path, "r") as zf:
            for name in zf.namelist():
                content = zf.read(name).lower()
                for pat in token_patterns:
                    assert pat not in content, (
                        f"Found token pattern {pat!r} in bundle entry {name!r}"
                    )

    def test_offline_bundle_creates_zip_file(
        self, exporter: SysReptorExporter, report: SysReptorReport, tmp_path: Path
    ) -> None:
        """The offline bundle must produce an actual ZIP file on disk."""
        bundle = exporter.offline(report, output_dir=tmp_path)
        assert bundle.path.is_file()
        import zipfile

        with zipfile.ZipFile(bundle.path, "r") as zf:
            names = zf.namelist()
        # Must contain at least a manifest and findings entries
        assert any("manifest" in n for n in names)
        assert any("findings" in n for n in names)

    def test_offline_bundle_finding_paths_match_finding_ids(
        self, exporter: SysReptorExporter, report: SysReptorReport, tmp_path: Path
    ) -> None:
        """Each finding in the bundle must have a corresponding JSON file."""
        bundle = exporter.offline(report, output_dir=tmp_path)
        import zipfile

        with zipfile.ZipFile(bundle.path, "r") as zf:
            names = set(zf.namelist())
        for finding in report.findings:
            expected = f"findings/{finding.finding_id}.json"
            assert expected in names, f"Missing finding file: {expected}"

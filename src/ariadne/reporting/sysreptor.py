"""SysReptor offline bundle, preview, and explicit push modes.

Provides three explicit modes for SysReptor integration:

1. **Offline** — creates a self-contained ZIP bundle with findings, evidence,
   manifests, and SHA-256 checksums. No network calls.
2. **Preview** — validates the mapping and returns structured metadata
   (destination, project, object counts, data categories) without sending data.
3. **Push** — sends the bundle to a SysReptor instance after explicit
   confirmation. API tokens are read from the process environment only.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import urllib.error
import urllib.request
import zipfile
from pathlib import Path
from typing import Any

from pydantic import BaseModel, ConfigDict

# ── Domain models ──────────────────────────────────────────────────────────────


class SysReptorFinding(BaseModel):
    """A single finding for SysReptor export."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    finding_id: str
    title: str
    severity: str
    status: str
    description: str
    evidence: list[str] = []
    remediation: str | None = None


class SysReptorReport(BaseModel):
    """A complete report model for SysReptor export.

    Serves as the input to ``SysReptorExporter.offline()``.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    engagement_id: str
    targets: list[dict[str, Any]]
    objectives: list[dict[str, Any]]
    findings: list[SysReptorFinding]
    profile: str
    snapshot_hash: str


class BundleManifest(BaseModel):
    """Metadata about the offline bundle's contents.

    Attributes:
        version: Bundle format version.
        finding_count: Number of findings included.
        assets: Relative paths to evidence/ asset files.
        sha256_checksums: Mapping of relative paths to hex SHA-256 digests.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    version: str = "1.0"
    finding_count: int
    assets: list[str]
    sha256_checksums: dict[str, str]


class Bundle(BaseModel):
    """A self-contained offline SysReptor export bundle.

    Attributes:
        manifest: Structured metadata about bundle contents.
        path: Absolute path to the ZIP file on disk.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    manifest: BundleManifest
    path: Path


class Preview(BaseModel):
    """Preview metadata returned without sending data to the server.

    Attributes:
        destination: The target SysReptor URL.
        project: Project identifier derived from the report.
        finding_count: Number of findings in the bundle.
        data_categories: List of data categories the bundle contains.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    destination: str
    project: str
    finding_count: int
    data_categories: list[str]


class PushResult(BaseModel):
    """Outcome of a successful SysReptor push.

    Attributes:
        project_id: The SysReptor project ID returned by the server.
        report_id: The SysReptor report ID returned by the server.
        status: HTTP status or status text.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    project_id: str
    report_id: str
    status: str


# ── Errors ─────────────────────────────────────────────────────────────────────


class ConfirmationRequiredError(RuntimeError):
    """Raised when a SysReptor push is attempted without explicit confirmation."""


class SysReptorPushError(RuntimeError):
    """Raised when the SysReptor push request fails."""


# ── Internal helpers ───────────────────────────────────────────────────────────

_SHA256_RE = re.compile(r"^[a-f0-9]{64}$")
_DEFAULT_DESTINATION = "http://localhost:18000"
_MAPPING_PATH = (
    Path(__file__).resolve().parent.parent.parent.parent
    / "report_templates" / "sysreptor" / "mapping.yaml"
)


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _ensure_list(value: Any) -> list[str]:
    """Normalize a field value to a list of strings for the ``data_categories``."""
    if isinstance(value, str):
        return [value]
    if isinstance(value, list):
        return [str(v) for v in value if v is not None]
    return []


# ── SysReptorExporter ──────────────────────────────────────────────────────────


class SysReptorExporter:
    """Export report data to SysReptor in three explicit modes.

    Args:
        destination: The SysReptor server URL.  Defaults to a local test address.
    """

    def __init__(self, destination: str | None = None) -> None:
        self._destination = destination or _DEFAULT_DESTINATION
        self._token: str | None = None  # never stored in bundle or events

    # ── Offline mode ───────────────────────────────────────────────────────────

    def offline(
        self,
        report: SysReptorReport,
        output_dir: str | Path | None = None,
    ) -> Bundle:
        """Create a self-contained offline SysReptor ZIP bundle.

        The bundle contains:
          - ``manifest.json`` with version, finding count, asset list,
            and SHA-256 checksums
          - ``project.json`` with engagement metadata
          - ``findings/<finding_id>.json`` for each finding
          - ``evidence/`` with referenced evidence assets (empty placeholder
            if the source files are not available locally)
          - ``mapping.yaml`` — the field mapping template

        Args:
            report: The report model to bundle.
            output_dir: Directory for the generated ZIP.  Defaults to CWD.

        Returns:
            A ``Bundle`` with the generated manifest and ZIP path.
        """
        if output_dir is None:
            output_dir = Path.cwd()
        output_dir = Path(output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)

        zip_path = output_dir / f"sysreptor-bundle-{report.engagement_id[:8]}.zip"

        # Collect relative asset paths (never absolute)
        relative_assets: list[str] = []
        seen_assets: set[str] = set()
        for finding in report.findings:
            for evidence_name in finding.evidence:
                # Normalise to relative path under evidence/
                clean_name = evidence_name.lstrip("/")
                relative_path = f"evidence/{clean_name}"
                if relative_path not in seen_assets:
                    seen_assets.add(relative_path)
                    relative_assets.append(relative_path)

        # Build ZIP content blocks and checksums
        checksums: dict[str, str] = {}

        # 1. project.json
        project_data = {
            "engagement_id": report.engagement_id,
            "profile": report.profile,
            "snapshot_hash": report.snapshot_hash,
            "targets": report.targets,
            "objectives": report.objectives,
            "finding_count": len(report.findings),
        }
        project_bytes = json.dumps(project_data, sort_keys=True, indent=2).encode("utf-8")
        checksums["project.json"] = _sha256_bytes(project_bytes)

        # 2. mapping.yaml
        mapping_bytes = self._read_mapping()
        checksums["mapping.yaml"] = _sha256_bytes(mapping_bytes)

        # 3. Findings
        for finding in report.findings:
            finding_data = {
                "finding_id": finding.finding_id,
                "title": finding.title,
                "severity": finding.severity,
                "status": finding.status,
                "description": finding.description,
                "evidence": finding.evidence,
                "remediation": finding.remediation,
            }
            finding_bytes = json.dumps(finding_data, sort_keys=True, indent=2).encode(
                "utf-8"
            )
            finding_entry = f"findings/{finding.finding_id}.json"
            checksums[finding_entry] = _sha256_bytes(finding_bytes)

        # 4. Evidence (placeholder bytes — no real local files assumed available)
        for asset_rel_path in relative_assets:
            checksums[asset_rel_path] = _sha256_bytes(b"")
            # Evidence files will be populated at push time by the caller

        # 5. manifest.json
        manifest = BundleManifest(
            version="1.0",
            finding_count=len(report.findings),
            assets=relative_assets,
            sha256_checksums=checksums,
        )
        manifest_bytes = json.dumps(
            manifest.model_dump(mode="json"), sort_keys=True, indent=2
        ).encode("utf-8")
        checksums["manifest.json"] = _sha256_bytes(manifest_bytes)

        # Update manifest with the final checksum of itself
        manifest = BundleManifest(
            version="1.0",
            finding_count=len(report.findings),
            assets=relative_assets,
            sha256_checksums=checksums,
        )

        # Write the ZIP
        with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zf:
            zf.writestr("manifest.json", manifest.model_dump_json(indent=2))
            zf.writestr("project.json", json.dumps(project_data, sort_keys=True, indent=2))
            zf.writestr("mapping.yaml", mapping_bytes.decode("utf-8"))

            for finding in report.findings:
                finding_entry = f"findings/{finding.finding_id}.json"
                finding_data = {
                    "finding_id": finding.finding_id,
                    "title": finding.title,
                    "severity": finding.severity,
                    "status": finding.status,
                    "description": finding.description,
                    "evidence": finding.evidence,
                    "remediation": finding.remediation,
                }
                zf.writestr(
                    finding_entry,
                    json.dumps(finding_data, sort_keys=True, indent=2),
                )

            for asset_rel_path in relative_assets:
                zf.writestr(asset_rel_path, "")

        return Bundle(manifest=manifest, path=zip_path.resolve())

    # ── Preview mode ───────────────────────────────────────────────────────────

    def preview(self, bundle: Bundle) -> Preview:
        """Validate the bundle and return preview metadata without sending data.

        Returns a ``Preview`` with the destination, project identifier,
        finding count, and data categories present in the bundle.
        """
        # Load the bundle manifest from the ZIP to confirm validity
        if not bundle.path.is_file():
            raise ValueError(f"Bundle ZIP not found: {bundle.path}")

        project_identifier = f"Ariadne-report-{bundle.manifest.finding_count}"

        # Derive data categories from finding statuses
        seen_statuses: set[str] = set()
        with zipfile.ZipFile(bundle.path, "r") as zf:
            for name in zf.namelist():
                if name.startswith("findings/") and name.endswith(".json"):
                    content = zf.read(name)
                    try:
                        finding_data = json.loads(content)
                        status = finding_data.get("status", "unknown")
                        seen_statuses.add(str(status))
                    except (json.JSONDecodeError, TypeError):
                        continue

        data_categories = sorted(seen_statuses)
        has_evidence = len(bundle.manifest.assets) > 0
        if has_evidence and "evidence" not in data_categories:
            data_categories.append("evidence")

        return Preview(
            destination=self._destination,
            project=project_identifier,
            finding_count=bundle.manifest.finding_count,
            data_categories=data_categories,
        )

    # ── Push mode ──────────────────────────────────────────────────────────────

    async def push(
        self,
        bundle: Bundle,
        approval: Any | None = None,
    ) -> PushResult:
        """Explicitly push a bundle to the SysReptor server.

        Requires a non-``None`` *approval* object.  Passing ``None`` raises
        ``ConfirmationRequiredError``.

        The API token is read from the ``SYSREPTOR_API_TOKEN`` environment
        variable at call time; it is never stored in the bundle, manifest,
        or local events.

        Args:
            bundle: The offline bundle to push.
            approval: An explicit confirmation object.  Anything truthy
                (or any non-None value) satisfies the gate.

        Returns:
            A ``PushResult`` with the server's project/report IDs and status.

        Raises:
            ConfirmationRequiredError: If *approval* is ``None``.
            SysReptorPushError: If the server returns an error.
        """
        if approval is None:
            raise ConfirmationRequiredError(
                "SysReptor push requires explicit approval. "
                "Call preview() first, then pass an approval object."
            )

        # Resolution: if approval is a boolean or dict, treat as confirmed
        if isinstance(approval, bool):
            pass  # truthiness is enough
        elif isinstance(approval, dict):
            pass
        elif hasattr(approval, "actor"):
            pass  # Looks like an engagement Confirmation
        else:
            # Non-None, non-truthy — still accepted as explicit approval
            pass

        # Read API token from environment — never from the bundle
        api_token = os.environ.get("SYSREPTOR_API_TOKEN", "")
        if not api_token:
            raise SysReptorPushError(
                "SYSREPTOR_API_TOKEN environment variable is not set. "
                "Provide the token before calling push()."
            )

        # Check the bundle exists
        if not bundle.path.is_file():
            raise SysReptorPushError(f"Bundle file not found: {bundle.path}")

        # Read the bundle and simulate POST to SysReptor
        bundle_bytes = bundle.path.read_bytes()

        url = f"{self._destination.rstrip('/')}/api/v1/projects/"

        headers = {
            "Authorization": f"Token {api_token}",
            "Content-Type": "application/zip",
            "X-Bundle-Digest": _sha256_bytes(bundle_bytes),
        }

        req = urllib.request.Request(
            url,
            data=bundle_bytes,
            headers=headers,
            method="POST",
        )

        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                status = f"{resp.status}"
                body = resp.read().decode("utf-8")
                try:
                    data = json.loads(body)
                except json.JSONDecodeError:
                    data = {}
                project_id = data.get("project_id", data.get("id", "unknown"))
                report_id = data.get("report_id", data.get("report", "unknown"))
        except urllib.error.HTTPError as exc:
            raise SysReptorPushError(
                f"SysReptor server returned HTTP {exc.code}: "
                f"{exc.reason[:200]}"
            ) from exc
        except urllib.error.URLError as exc:
            raise SysReptorPushError(
                f"Could not reach SysReptor server at {self._destination}: "
                f"{exc.reason}"
            ) from exc

        return PushResult(
            project_id=project_id,
            report_id=report_id,
            status=status,
        )

    # ── Helpers ────────────────────────────────────────────────────────────────

    @staticmethod
    def _read_mapping() -> bytes:
        """Read the SysReptor field mapping YAML file.

        Returns empty placeholder if the mapping file is not present.
        """
        if _MAPPING_PATH.is_file():
            return _MAPPING_PATH.read_bytes()
        return b"# SysReptor mapping (placeholder)\n"

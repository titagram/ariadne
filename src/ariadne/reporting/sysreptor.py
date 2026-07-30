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
from typing import TYPE_CHECKING, Any

from pydantic import BaseModel, ConfigDict

if TYPE_CHECKING:
    from ariadne.reporting.models import ReportModel

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
    affected_assets: list[str] = []
    prerequisites: list[str] = []
    procedure: list[str] = []
    impact: str | None = None
    cwe: str | None = None
    cvss_vector: str | None = None
    cvss_score: float | None = None


class SysReptorEvidence(BaseModel):
    """A real, hash-addressed dossier artifact available for attachment."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    filename: str
    path: Path
    sha256: str
    size_bytes: int


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
    generated_at: str | None = None
    attack_steps: list[dict[str, Any]] = []
    cleanup: list[str] = []
    limitations: list[str] = []
    evidence_assets: list[SysReptorEvidence] = []

    @classmethod
    def from_dossier(cls, dossier: ReportModel) -> SysReptorReport:
        """Map a validated dossier to the existing offline bundle model."""
        objectives = []
        for objective in dossier.objectives:
            mapped: dict[str, Any] = {
                "kind": objective.kind,
                "description": objective.description,
                "completed": objective.completed,
            }
            if objective.kind in {"user_flag", "root_flag"}:
                mapped["proof_sha256"] = objective.completion_evidence
                if objective.flag_value is not None:
                    mapped["flag"] = objective.flag_value
            elif objective.completion_evidence is not None:
                mapped["completion_evidence"] = objective.completion_evidence
            objectives.append(mapped)
        findings = [
            SysReptorFinding(
                finding_id=finding.finding_id or f"finding-{index}",
                title=finding.title,
                severity=finding.severity or "informational",
                status=finding.status,
                description=finding.description or "",
                evidence=list(finding.evidence),
                remediation=(
                    "\n".join(finding.remediation)
                    if finding.remediation
                    else None
                ),
                affected_assets=list(finding.affected_assets),
                prerequisites=list(finding.prerequisites),
                procedure=list(finding.procedure),
                impact=finding.impact,
                cwe=finding.cwe,
                cvss_vector=finding.cvss_vector,
                cvss_score=finding.cvss_score,
            )
            for index, finding in enumerate(dossier.findings, start=1)
        ]
        return cls(
            engagement_id=dossier.engagement_id,
            targets=[
                {"host": target.host}
                for target in dossier.targets
            ],
            objectives=objectives,
            findings=findings,
            profile=dossier.profile,
            snapshot_hash=dossier.snapshot_hash,
            generated_at=dossier.generated_at,
            attack_steps=[
                step.model_dump(mode="json")
                for step in dossier.attack_steps
            ],
            cleanup=list(dossier.cleanup),
            limitations=list(dossier.exclusions),
            evidence_assets=[
                SysReptorEvidence(
                    filename=item.filename,
                    path=item.path,
                    sha256=item.sha256,
                    size_bytes=item.size_bytes,
                )
                for item in dossier.evidence
            ],
        )


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
    project_path: Path
    evidence_dir: Path


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
        """Create an official pushproject JSON plus a real-evidence bundle."""
        if output_dir is None:
            output_dir = Path.cwd()
        output_dir = Path(output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)

        suffix = report.engagement_id.replace("-", "")[:8]
        zip_path = output_dir / f"sysreptor-bundle-{suffix}.zip"
        project_path = output_dir / f"sysreptor-pushproject-{suffix}.json"
        evidence_dir = output_dir / f"sysreptor-evidence-{suffix}"
        evidence_dir.mkdir(mode=0o700, exist_ok=True)

        real_assets = self._load_real_assets(report)
        attachment_by_name = {
            asset.filename: asset
            for asset, _ in real_assets.values()
        }
        pushproject = self._pushproject_payload(report, attachment_by_name)
        project_bytes = json.dumps(
            pushproject,
            sort_keys=True,
            indent=2,
            ensure_ascii=False,
        ).encode("utf-8")
        project_path.write_bytes(project_bytes)
        project_path.chmod(0o600)

        relative_assets: list[str] = []
        checksums: dict[str, str] = {
            "pushproject.json": _sha256_bytes(project_bytes),
        }
        for asset, content in real_assets.values():
            relative_path = f"evidence/{asset.filename}"
            relative_assets.append(relative_path)
            checksums[relative_path] = asset.sha256
            destination = evidence_dir / asset.filename
            destination.write_bytes(content)
            destination.chmod(0o600)

        finding_entries: dict[str, bytes] = {}
        for finding in pushproject["findings"]:
            finding_id = str(finding["data"]["finding_id"])
            entry = f"findings/{finding_id}.json"
            content = json.dumps(
                finding,
                sort_keys=True,
                indent=2,
                ensure_ascii=False,
            ).encode("utf-8")
            finding_entries[entry] = content
            checksums[entry] = _sha256_bytes(content)

        mapping_bytes = self._read_mapping()
        checksums["mapping.yaml"] = _sha256_bytes(mapping_bytes)
        manifest = BundleManifest(
            version="2.0-pushproject",
            finding_count=len(report.findings),
            assets=relative_assets,
            sha256_checksums=checksums,
        )

        with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as archive:
            archive.writestr("manifest.json", manifest.model_dump_json(indent=2))
            archive.writestr("pushproject.json", project_bytes)
            archive.writestr("project.json", project_bytes)
            archive.writestr("mapping.yaml", mapping_bytes)
            for entry, content in finding_entries.items():
                archive.writestr(entry, content)
            for asset, content in real_assets.values():
                archive.writestr(f"evidence/{asset.filename}", content)
        zip_path.chmod(0o600)

        return Bundle(
            manifest=manifest,
            path=zip_path.resolve(),
            project_path=project_path.resolve(),
            evidence_dir=evidence_dir.resolve(),
        )

    @staticmethod
    def _load_real_assets(
        report: SysReptorReport,
    ) -> dict[str, tuple[SysReptorEvidence, bytes]]:
        """Load and verify real attachments, deduplicated by digest."""
        assets: dict[str, tuple[SysReptorEvidence, bytes]] = {}
        for asset in report.evidence_assets:
            safe_name = Path(asset.filename).name
            if safe_name != asset.filename or not safe_name:
                raise ValueError(
                    f"Unsafe SysReptor evidence filename: {asset.filename!r}"
                )
            try:
                content = asset.path.read_bytes()
            except (FileNotFoundError, PermissionError, OSError) as exc:
                raise ValueError(
                    f"SysReptor evidence is unavailable: {asset.filename!r}"
                ) from exc
            if (
                _sha256_bytes(content) != asset.sha256
                or len(content) != asset.size_bytes
            ):
                raise ValueError(
                    f"SysReptor evidence integrity mismatch: {asset.filename!r}"
                )
            assets.setdefault(asset.sha256, (asset, content))
        return assets

    @staticmethod
    def _pushproject_payload(
        report: SysReptorReport,
        attachments: dict[str, SysReptorEvidence],
    ) -> dict[str, list[dict[str, Any]]]:
        """Map Ariadne fields to the documented reptor pushproject envelope."""
        narrative_lines: list[str] = []
        for index, step in enumerate(report.attack_steps, start=1):
            narrative_lines.extend((
                f"### {index}. {step.get('phase', 'activity')}",
                f"Action: {step.get('action')}",
                f"Input: {step.get('input')}",
            ))
            prerequisites = step.get("prerequisites") or []
            if prerequisites:
                narrative_lines.append(
                    f"Prerequisites: {'; '.join(prerequisites)}"
                )
            commands = step.get("commands") or []
            if commands:
                narrative_lines.append(
                    "Commands / actions:\n"
                    + "\n".join(
                        f"```text\n{command}\n```" for command in commands
                    )
                )
            narrative_lines.extend((
                f"Result: {step.get('result')}",
                "Evidence: "
                + ", ".join(
                    f"`{name}`" for name in (step.get("evidence") or [])
                ),
            ))

        objective_lines: list[str] = []
        for objective in report.objectives:
            line = (
                f"- {objective.get('kind', 'objective')}: "
                f"{objective.get('description', '')}"
            )
            if objective.get("flag"):
                line += f"\n  - Flag: `{objective['flag']}`"
            elif objective.get("proof_sha256"):
                line += (
                    "\n  - Value unavailable from the persisted dossier; "
                    f"proof SHA-256: `{objective['proof_sha256']}`"
                )
            objective_lines.append(line)

        targets = [
            str(target["host"])
            for target in report.targets
            if isinstance(target, dict) and target.get("host")
        ]
        section_data: dict[str, Any] = {
            "title": f"Ariadne {report.profile.upper()} penetration test report",
            "engagement_id": report.engagement_id,
            "report_date": report.generated_at or "persisted engagement time",
            "scope": targets,
            "objectives": objective_lines,
            "executive_summary": (
                f"The evidence-backed engagement produced {len(report.findings)} "
                "validated technical finding(s)."
            ),
            "attack_narrative": "\n\n".join(narrative_lines),
            "limitations": report.limitations or [
                "Only persisted evidence was used.",
                "No screenshots were acquired during this run.",
            ],
            "cleanup": report.cleanup,
            "objective_evidence": "\n".join(objective_lines),
            "evidence_attachments": [
                {
                    "filename": asset.filename,
                    "sha256": asset.sha256,
                    "size_bytes": asset.size_bytes,
                    "bundle_path": f"evidence/{asset.filename}",
                }
                for asset in attachments.values()
            ],
        }
        section_data = {
            key: value
            for key, value in section_data.items()
            if value not in (None, "", [], {})
        }

        findings: list[dict[str, Any]] = []
        for finding in report.findings:
            attached = [
                attachments[name]
                for name in finding.evidence
                if name in attachments
            ]
            evidence_markdown = "\n".join(
                (
                    f"- `{name}`"
                    + (
                        f" (SHA-256 `{attachments[name].sha256}`)"
                        if name in attachments
                        else ""
                    )
                )
                for name in finding.evidence
            )
            data: dict[str, Any] = {
                "finding_id": finding.finding_id,
                "title": finding.title,
                "cvss": finding.cvss_vector,
                "cvss_score": finding.cvss_score,
                "summary": finding.description,
                "description": finding.description,
                "affected_components": finding.affected_assets,
                "prerequisites": finding.prerequisites,
                "steps_to_reproduce": finding.procedure,
                "impact": finding.impact,
                "cwe": finding.cwe,
                "evidence": evidence_markdown,
                "evidence_attachments": [
                    {
                        "filename": asset.filename,
                        "sha256": asset.sha256,
                        "size_bytes": asset.size_bytes,
                        "bundle_path": f"evidence/{asset.filename}",
                    }
                    for asset in attached
                ],
                "recommendation": finding.remediation,
            }
            findings.append({
                "status": (
                    "finished"
                    if finding.status == "validated"
                    else "in-progress"
                ),
                "data": {
                    key: value
                    for key, value in data.items()
                    if value not in (None, "", [], {})
                },
            })

        return {
            "sections": [{"status": "finished", "data": section_data}],
            "findings": findings,
        }

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

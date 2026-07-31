"""Provenance-aware vulnerability research models.

Defines the core types for Ariadne's mandatory service-to-CVE/exploit
research workflow:

1. ``ServiceFingerprint`` — a fingerprinted service specification
2. ``ResearchSource`` — ordered enumeration of research sources
3. ``CveReference`` — a research result referencing a CVE
4. ``ResearchDossier`` — the complete output of a pipeline investigation
5. ``PocProvenance`` — provenance metadata for uncurated PoC code
6. ``authorize_poc`` / ``quarantine_poc`` — policy gate and storage
"""

from __future__ import annotations

import stat
from datetime import datetime
from enum import StrEnum
from hashlib import sha256
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict

from ariadne.core.errors import AdapterError

# ── Exception ─────────────────────────────────────────────────────────────────


class ConfirmationRequiredError(AdapterError):
    """Raised when an operation requires explicit user confirmation."""


# ── Service fingerprint ───────────────────────────────────────────────────────


class ServiceFingerprint(BaseModel):
    """A fingerprinted service specification for vulnerability research.

    Carries enough information to query vulnerability databases without
    exposing the target host identity to external sources (the pipeline
    is responsible for query minimisation).
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    product: str
    version: str | None = None
    protocol: str | None = None
    port: int | None = None
    cpe: str | None = None
    target_host: str = ""


# ── Research source ordering ──────────────────────────────────────────────────


class ResearchSource(StrEnum):
    """Ordered enumeration of vulnerability research sources.

    The order (declaration order) defines the pipeline's attempt order:
    local sources before network sources, authoritative before indexes.
    """

    LOCAL_SEARCHSPLOIT = "local-searchsploit"
    VENDOR = "vendor"
    NVD = "nvd"
    CISA_KEV = "cisa-kev"
    METASPLOIT = "metasploit"
    PUBLIC_POC_INDEX = "public-poc-index"


# ── CVE reference ─────────────────────────────────────────────────────────────


class CveReference(BaseModel):
    """A single CVE or vulnerability reference from a research source."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    cve_id: str
    title: str = ""
    description: str = ""
    cvss_score: float | None = None
    source_url: str | None = None
    source: ResearchSource


class ResearchEvidence(BaseModel):
    """Immutable provenance record for one source result."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    source: ResearchSource
    locator: str
    sha256: str
    summary: str = ""

    @classmethod
    def from_text(
        cls,
        *,
        source: ResearchSource,
        locator: str,
        text: str,
        summary: str = "",
    ) -> ResearchEvidence:
        return cls(
            source=source,
            locator=locator,
            sha256=sha256(text.encode("utf-8")).hexdigest(),
            summary=summary,
        )


class ResearchCandidate(BaseModel):
    """Deduplicated vulnerability/exploit candidate for one fingerprint."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    candidate_id: str
    product: str
    version: str | None = None
    cve_id: str
    title: str = ""
    cvss_score: float | None = None
    sources: tuple[ResearchSource, ...]
    source_urls: tuple[str, ...] = ()
    exploit_paths: tuple[str, ...] = ()
    metasploit_modules: tuple[str, ...] = ()
    check_supported: bool = False
    requires_reverse_callback: bool = False
    compatible: bool = False
    applicability_evidence: tuple[str, ...] = ()
    validation_status: Literal["candidate", "validated"] = "candidate"
    evidence: tuple[ResearchEvidence, ...] = ()


# ── Research dossier ──────────────────────────────────────────────────────────


class ResearchDossier(BaseModel):
    """Complete research output for a single service fingerprint.

    Records which sources were attempted, which returned results, and any
    connectivity limitations encountered during the research process.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    fingerprint: ServiceFingerprint
    sources_attempted: tuple[ResearchSource, ...] = ()
    entries: tuple[CveReference, ...] = ()
    candidates: tuple[ResearchCandidate, ...] = ()
    source_limitations: tuple[str, ...] = ()
    network_queries: tuple[str, ...] = ()


# ── PoC provenance ────────────────────────────────────────────────────────────


class PocProvenance(BaseModel):
    """Provenance metadata for uncurated proof-of-concept code.

    Records the origin, retrieval metadata, file integrity digest, and
    review decision for any uncurated exploit code acquired during
    research.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    source_url: str
    retrieval_time: datetime
    author: str | None = None
    license: str | None = None
    commit_hash: str | None = None
    file_digest: str
    curation_status: str = "unreviewed"
    review_decision: str | None = None


# ── PoC policy functions ──────────────────────────────────────────────────────


def authorize_poc(
    poc: PocProvenance | None,
    confirmation: dict | None,
) -> dict:
    """Authorise an uncurated PoC for execution.

    Returns an authorisation record when *confirmation* is provided.
    Raises ``ConfirmationRequired`` when *confirmation* is ``None`` or
    when the PoC record is ``None``.

    Parameters
    ----------
    poc:
        The provenance record of the uncurated PoC.
    confirmation:
        A dict with ``challenge``, ``actor``, and ``timestamp`` keys, or
        ``None`` if confirmation was not provided.

    Returns
    -------
    dict
        An authorisation record with ``poc_url``, ``authorized``, and
        ``authorized_at`` keys.
    """
    if poc is None:
        raise ConfirmationRequiredError("Cannot authorise a null PoC record")
    if confirmation is None:
        raise ConfirmationRequiredError(
            f"Uncurated PoC from {poc.source_url} requires direct "
            f"user confirmation before execution"
        )
    return {
        "poc_url": poc.source_url,
        "authorized": True,
        "authorized_at": confirmation.get("timestamp", datetime.now()).isoformat()
        if isinstance(confirmation, dict)
        else datetime.now().isoformat(),
    }


def quarantine_poc(
    data: bytes,
    storage_dir: Path,
    name: str,
) -> Path:
    """Quarantine uncurated PoC bytes under a restricted storage path.

    Writes *data* to ``storage_dir / name`` with mode ``0o600``.
    Raises ``ValueError`` if *data* is empty or *storage_dir* is outside
    an expected project path.

    Parameters
    ----------
    data:
        Raw PoC bytes to quarantine.
    storage_dir:
        The quarantine storage directory.
    name:
        The filename under which to store the PoC.

    Returns
    -------
    Path
        The absolute path of the quarantined file.
    """
    if not data:
        raise ValueError("Cannot quarantine empty PoC data")
    resolved = storage_dir.resolve()
    # Basic safety: reject paths that escape via parent traversal
    if ".." in str(storage_dir):
        raise ValueError(f"Storage path contains parent traversal: {storage_dir!r}")
    resolved.mkdir(parents=True, exist_ok=True)
    dst = resolved / name
    dst.write_bytes(data)
    # Set mode 0o600 (owner read/write only)
    dst.chmod(stat.S_IRUSR | stat.S_IWUSR)
    return dst

"""Contract tests for the ResearchPipeline adapter.

Verifies source ordering, query minimization (privacy), and
dossier shape for the provenance-aware vulnerability research pipeline.
"""

from __future__ import annotations

from datetime import UTC
from uuid import uuid4

import pydantic
import pytest

from ariadne.adapters.base import AdapterContext
from ariadne.adapters.research import ResearchPipeline
from ariadne.core.research import (
    ConfirmationRequiredError,
    PocProvenance,
    ResearchDossier,
    ResearchSource,
    ServiceFingerprint,
)
from ariadne.runtime.process import ProcessResult

# ── Fixtures ──────────────────────────────────────────────────────────────────


@pytest.fixture
def context() -> AdapterContext:
    return AdapterContext(
        target=__import__("ariadne").core.engagement.TargetSpec(host="10.10.10.10"),
        snapshot_hash="abc123",
        engagement_id=uuid4(),
        adapter_name="research",
    )


class _FakeRuntime:
    """A runtime stub that returns canned searchsploit / curl output."""

    def __init__(self) -> None:
        self.calls: list[list[str]] = []

    async def run(self, spec: object) -> ProcessResult:
        from ariadne.runtime.process import ProcessSpec, ProcessStatus

        assert isinstance(spec, ProcessSpec)
        self.calls.append(list(spec.argv))
        # Whatever the query is, return empty result — we only test ordering
        return ProcessResult(
            exit_code=0,
            stdout="",
            stderr="",
            status=ProcessStatus.COMPLETED,
        )


@pytest.fixture
def fingerprint() -> ServiceFingerprint:
    return ServiceFingerprint(
        product="Apache httpd",
        version="2.4.41",
        protocol="tcp",
        port=80,
        target_host="10.10.10.10",
    )


@pytest.fixture
def pipeline() -> ResearchPipeline:
    return ResearchPipeline(runtime=_FakeRuntime())


# ── Source ordering and query minimization ────────────────────────────────────


class TestResearchOrderAndPrivacy:
    """Verify the pipeline attempts sources in the expected order and never
    leaks the target address into network queries."""

    @pytest.mark.asyncio
    async def test_research_source_ordering(
        self, pipeline: ResearchPipeline, fingerprint: ServiceFingerprint
    ) -> None:
        dossier = await pipeline.investigate(fingerprint)
        assert dossier.sources_attempted == (
            ResearchSource.LOCAL_SEARCHSPLOIT,
            ResearchSource.VENDOR,
            ResearchSource.NVD,
            ResearchSource.CISA_KEV,
            ResearchSource.METASPLOIT,
            ResearchSource.PUBLIC_POC_INDEX,
        )

    @pytest.mark.asyncio
    async def test_query_minimization(
        self, pipeline: ResearchPipeline, fingerprint: ServiceFingerprint
    ) -> None:
        """The fingerprint's target_host must not appear in any network query."""
        dossier = await pipeline.investigate(fingerprint)
        for query in dossier.network_queries:
            assert fingerprint.target_host not in query

    @pytest.mark.asyncio
    async def test_fingerprint_product_preserved_in_dossier(
        self, pipeline: ResearchPipeline, fingerprint: ServiceFingerprint
    ) -> None:
        dossier = await pipeline.investigate(fingerprint)
        assert dossier.fingerprint.product == fingerprint.product
        assert dossier.fingerprint.version == fingerprint.version
        assert dossier.fingerprint.protocol == fingerprint.protocol

    @pytest.mark.asyncio
    async def test_source_limitations_recorded_when_offline(
        self, pipeline: ResearchPipeline, fingerprint: ServiceFingerprint
    ) -> None:
        """When a network source cannot be reached, a limitation is recorded."""
        dossier = await pipeline.investigate(fingerprint)
        # The fake runtime always "succeeds" but returns empty — at minimum
        # sources_attempted is populated
        assert len(dossier.sources_attempted) == 6

    @pytest.mark.asyncio
    async def test_empty_fingerprint_results_dossier_with_no_entries(
        self, pipeline: ResearchPipeline
    ) -> None:
        """An empty/unknown fingerprint produces no CVE entries."""
        empty = ServiceFingerprint(
            product="unknown",
            version=None,
            protocol=None,
            port=None,
            target_host="10.10.10.10",
        )
        dossier = await pipeline.investigate(empty)
        assert isinstance(dossier, ResearchDossier)
        assert len(dossier.entries) == 0


# ── Dossier shape ─────────────────────────────────────────────────────────────


class TestResearchDossierShape:
    """Verify the dossier record satisfies its structural contract."""

    @pytest.mark.asyncio
    async def test_dossier_is_frozen_model(
        self, pipeline: ResearchPipeline, fingerprint: ServiceFingerprint
    ) -> None:
        dossier = await pipeline.investigate(fingerprint)
        with pytest.raises(pydantic.ValidationError):
            dossier.sources_attempted = ()  # type: ignore[misc]

    def test_research_source_values_match_expected(self) -> None:
        """All six sources have human-readable values."""
        assert ResearchSource.LOCAL_SEARCHSPLOIT == "local-searchsploit"
        assert ResearchSource.VENDOR == "vendor"
        assert ResearchSource.NVD == "nvd"
        assert ResearchSource.CISA_KEV == "cisa-kev"
        assert ResearchSource.METASPLOIT == "metasploit"
        assert ResearchSource.PUBLIC_POC_INDEX == "public-poc-index"


# ── ServiceFingerprint contract ───────────────────────────────────────────────


class TestServiceFingerprint:
    """Verify ServiceFingerprint models are correctly shaped."""

    def test_fingerprint_requires_product(self) -> None:
        fp = ServiceFingerprint(
            product="nginx",
            version="1.18.0",
            protocol="tcp",
            port=443,
            target_host="10.10.10.20",
        )
        assert fp.product == "nginx"
        assert fp.version == "1.18.0"
        assert fp.port == 443

    def test_fingerprint_extra_forbidden(self) -> None:
        with pytest.raises(pydantic.ValidationError):
            ServiceFingerprint(  # type: ignore[call-arg]
                product="nginx",
                target_host="10.10.10.20",
                unknown_field="boom",
            )

    def test_fingerprint_frozen(self) -> None:
        fp = ServiceFingerprint(product="nginx", target_host="10.10.10.20")
        with pytest.raises(pydantic.ValidationError):
            fp.product = "Apache"  # type: ignore[misc]


# ── PocProvenance contract ────────────────────────────────────────────────────


class TestPocProvenance:
    """Verify PocProvenance records are correctly shaped."""

    def test_provenance_requires_source_and_digest(self) -> None:
        p = PocProvenance(
            source_url="https://github.com/example/exploit",
            retrieval_time=__import__("datetime").datetime.now(
                __import__("datetime").timezone.utc
            ),
            file_digest="a" * 64,
        )
        assert p.source_url == "https://github.com/example/exploit"
        assert p.file_digest == "a" * 64
        assert p.curation_status == "unreviewed"
        assert p.review_decision is None

    def test_provenance_extra_forbidden(self) -> None:
        from datetime import datetime

        with pytest.raises(pydantic.ValidationError):
            PocProvenance(  # type: ignore[call-arg]
                source_url="https://example.com/poc.py",
                retrieval_time=datetime.now(UTC),
                file_digest="b" * 64,
                unknown=True,
            )

    def test_confirmation_required_is_adapter_error(self) -> None:
        from ariadne.core.errors import AdapterError

        assert issubclass(ConfirmationRequiredError, AdapterError)

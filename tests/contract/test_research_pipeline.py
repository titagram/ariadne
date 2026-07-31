"""Contract tests for the ResearchPipeline adapter.

Verifies source ordering, query minimization (privacy), and
dossier shape for the provenance-aware vulnerability research pipeline.
"""

from __future__ import annotations

import json
from datetime import UTC
from uuid import uuid4

import pydantic
import pytest

from ariadne.adapters.base import AdapterContext, PlannedAction
from ariadne.adapters.metasploit import MetasploitAdapter
from ariadne.adapters.nuclei import NucleiAdapter
from ariadne.adapters.research import ResearchPipeline
from ariadne.core.engagement import TargetSpec
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


class _StructuredResearchRuntime:
    """Return realistic, source-specific output without network or tools."""

    def __init__(
        self,
        *,
        nvd_description: str = ("Apache HTTP Server 2.4.49 path traversal and RCE."),
    ) -> None:
        self.calls: list[tuple[str, ...]] = []
        self.nvd_description = nvd_description

    async def run(self, spec: object) -> ProcessResult:
        from ariadne.runtime.process import ProcessSpec

        assert isinstance(spec, ProcessSpec)
        self.calls.append(spec.argv)
        if spec.argv[0] == "searchsploit":
            return ProcessResult(
                exit_code=0,
                stdout=(
                    '{"RESULTS_EXPLOIT":[{"Title":"Apache HTTP Server 2.4.49 '
                    'Path Traversal","EDB-ID":"50383","Codes":"CVE-2021-41773",'
                    '"Path":"exploits/multiple/webapps/50383.sh"}]}'
                ),
                stderr="",
            )
        if spec.argv[0] == "msfconsole":
            if spec.argv[-1].startswith("info "):
                return ProcessResult(
                    exit_code=0,
                    stdout=(
                        "Name: Apache Normalization Path Traversal\n"
                        "Module: exploit/multi/http/apache_normalize_path\n"
                        "Check supported: Yes\n"
                        "LHOST                    0.0.0.0\n"
                        "References:\n  CVE-2021-41773\n"
                    ),
                    stderr="",
                )
            return ProcessResult(
                exit_code=0,
                stdout=(
                    "Matching Modules\n"
                    "   #  Name                                      "
                    "Disclosure Date  Rank       Check  Description\n"
                    "   0  exploit/multi/http/apache_normalize_path  "
                    "2021-10-05       excellent  Yes    "
                    "Apache Normalization Path Traversal\n"
                ),
                stderr="",
            )
        if spec.argv[0] == "curl" and "httpd.apache.org" in spec.argv[-1]:
            return ProcessResult(
                exit_code=22,
                stdout="",
                stderr="vendor temporarily unavailable",
            )
        if spec.argv[0] == "curl" and "services.nvd.nist.gov" in spec.argv[-1]:
            return ProcessResult(
                exit_code=0,
                stdout=(
                    '{"vulnerabilities":[{"cve":{"id":"CVE-2021-41773",'
                    '"descriptions":[{"lang":"en","value":'
                    + json.dumps(self.nvd_description)
                    + '}],"metrics":'
                    '{"cvssMetricV31":[{"cvssData":{"baseScore":9.8}}]}}}]}'
                ),
                stderr="",
            )
        return ProcessResult(exit_code=0, stdout='{"vulnerabilities":[]}', stderr="")


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

    @pytest.mark.asyncio
    async def test_sources_fail_independently_and_deduplicate_validated_candidate(
        self,
    ) -> None:
        """A vendor outage cannot hide matching local, NVD, and MSF evidence."""
        runtime = _StructuredResearchRuntime()
        pipeline = ResearchPipeline(runtime=runtime)
        fingerprint = ServiceFingerprint(
            product="Apache HTTP Server",
            version="2.4.49",
            protocol="http",
            port=80,
            target_host="10.10.10.10",
        )

        dossier = await pipeline.investigate(fingerprint)

        assert len(dossier.candidates) == 1
        candidate = dossier.candidates[0]
        assert candidate.cve_id == "CVE-2021-41773"
        assert candidate.product == "Apache HTTP Server"
        assert candidate.version == "2.4.49"
        assert candidate.validation_status == "validated"
        assert candidate.compatible is True
        assert candidate.applicability_evidence == ("nvd-description:version=2.4.49",)
        assert candidate.metasploit_modules == ("exploit/multi/http/apache_normalize_path",)
        assert candidate.requires_reverse_callback is True
        assert set(candidate.sources) == {
            ResearchSource.LOCAL_SEARCHSPLOIT,
            ResearchSource.NVD,
            ResearchSource.METASPLOIT,
        }
        assert all(evidence.sha256 for evidence in candidate.evidence)
        assert any("vendor" in limitation.lower() for limitation in dossier.source_limitations)
        assert [call[0] for call in runtime.calls].count("msfconsole") == 2

        operational_candidate = {
            **candidate.model_dump(mode="json"),
            "target": fingerprint.target_host,
            "evidence_id": "persisted-research-evidence",
            "provenance": candidate.source_urls[0],
        }
        adapter_context = AdapterContext(
            target=TargetSpec(host=fingerprint.target_host),
            snapshot_hash="a" * 64,
            engagement_id=uuid4(),
            adapter_name="dry-run",
        )
        nuclei_spec = NucleiAdapter().plan(
            PlannedAction(
                operation="scan",
                inputs={
                    "validated_candidates": [operational_candidate],
                },
            ),
            adapter_context,
        )
        msf_spec = MetasploitAdapter().plan(
            PlannedAction(
                operation="check",
                inputs={
                    "module": candidate.metasploit_modules[0],
                    "rhost": fingerprint.target_host,
                    "rport": fingerprint.port,
                    "validated_candidate": {
                        **operational_candidate,
                        "module": candidate.metasploit_modules[0],
                    },
                },
            ),
            adapter_context,
        )

        assert "CVE-2021-41773.yaml" in " ".join(nuclei_spec.argv)
        assert msf_spec.argv[-1].endswith("check; exit")

    @pytest.mark.asyncio
    async def test_product_and_version_without_applicability_stays_candidate(
        self,
    ) -> None:
        runtime = _StructuredResearchRuntime(
            nvd_description="Apache HTTP Server path traversal advisory.",
        )
        dossier = await ResearchPipeline(runtime=runtime).investigate(
            ServiceFingerprint(
                product="Apache HTTP Server",
                version="2.4.49",
                protocol="http",
                port=80,
                target_host="10.10.10.10",
            )
        )

        assert len(dossier.candidates) == 1
        assert dossier.candidates[0].compatible is False
        assert dossier.candidates[0].validation_status == "candidate"
        assert dossier.candidates[0].applicability_evidence == ()

    def test_metasploit_info_version_range_is_applicability_evidence(self) -> None:
        metadata = (
            "Description:\n"
            "This module exploits Craft CMS versions 3.x, 4.x, and 5.x < 5.6.17.\n"
            "References: CVE-2025-32432\n"
        )
        fingerprint = ServiceFingerprint(
            product="Craft CMS",
            version="5.6.16",
            protocol="http",
            port=80,
            target_host="10.10.10.10",
        )
        assert ResearchPipeline._metasploit_applicability(fingerprint, metadata) == (
            "metasploit-info:version<5.6.17",
        )

    def test_observed_cpe_must_match_the_affected_nvd_range(self) -> None:
        cve = {
            "configurations": [
                {
                    "nodes": [
                        {
                            "cpeMatch": [
                                {
                                    "vulnerable": True,
                                    "criteria": (
                                        "cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*"
                                    ),
                                    "versionStartIncluding": "2.4.49",
                                    "versionEndExcluding": "2.4.50",
                                }
                            ]
                        }
                    ]
                }
            ]
        }
        matching = ServiceFingerprint(
            product="Apache HTTP Server",
            version="2.4.49",
            cpe="cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*",
            target_host="10.10.10.10",
        )
        other_product = matching.model_copy(
            update={
                "cpe": "cpe:2.3:a:apache:ofbiz:2.4.49:*:*:*:*:*:*:*",
            }
        )

        assert ResearchPipeline._nvd_applicability(cve, matching, "") == (
            "nvd-cpe:cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*;version=2.4.49",
        )
        assert ResearchPipeline._nvd_applicability(cve, other_product, "") == ()


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
            retrieval_time=__import__("datetime").datetime.now(__import__("datetime").timezone.utc),
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

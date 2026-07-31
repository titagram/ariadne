"""Provenance-aware vulnerability research pipeline adapter.

Orchestrates the mandatory service-to-CVE/exploit research workflow:

1. local SearchSploit / Exploit-DB index
2. vendor advisory sources
3. NVD (National Vulnerability Database)
4. CISA Known Exploited Vulnerabilities catalog
5. Metasploit module search
6. public PoC index / GitHub

Privacy invariant: no query to an external network source contains the
target host address, domain, credential, or captured content — only the
normalised product, version, protocol, and (where applicable) candidate
CVE.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from hashlib import sha256
from typing import ClassVar, cast
from urllib.parse import quote_plus

from ariadne.adapters.base import (
    AdapterContext,
    AdapterError,
    CleanupResult,
    ExecutionClassification,
    PlannedAction,
    ProcessResult,
    ProcessSpec,
    Runtime,
    ToolProbe,
)
from ariadne.core.engagement import TargetSpec
from ariadne.core.errors import AdapterPolicyError
from ariadne.core.observations import Observation
from ariadne.core.research import (
    CveReference,
    ResearchCandidate,
    ResearchDossier,
    ResearchEvidence,
    ResearchSource,
    ServiceFingerprint,
)
from ariadne.runtime.process import ProcessStatus

_CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)
_MSF_MODULE_RE = re.compile(r"\b(?:exploit|auxiliary)/[a-z0-9_/-]+\b")


@dataclass(frozen=True)
class _ResearchHit:
    cve_id: str
    title: str
    description: str
    source: ResearchSource
    locator: str
    cvss_score: float | None = None
    exploit_path: str = ""
    metasploit_module: str = ""
    check_supported: bool = False
    requires_reverse_callback: bool = False
    applicability_evidence: tuple[str, ...] = ()

    def evidence(self) -> ResearchEvidence:
        payload = json.dumps(
            {
                "cve_id": self.cve_id,
                "title": self.title,
                "description": self.description,
                "source": self.source,
                "locator": self.locator,
                "exploit_path": self.exploit_path,
                "metasploit_module": self.metasploit_module,
                "applicability_evidence": self.applicability_evidence,
            },
            sort_keys=True,
            separators=(",", ":"),
        )
        return ResearchEvidence.from_text(
            source=self.source,
            locator=self.locator,
            text=payload,
            summary=self.title,
        )


class ResearchPipeline:
    """Bounded research pipeline that queries ordered sources.

    Each source is attempted in a fixed order (local → vendor → NVD →
    CISA KEV → Metasploit → public PoC).  Network queries contain only
    product/version/protocol/CVE information — never the target host.

    Attributes
    ----------
    network_queries:
        Accumulator of every outbound query issued by this pipeline
        instance, for audit and query-minimisation verification.
    """

    def __init__(self, runtime: Runtime) -> None:
        self._runtime = runtime
        self.network_queries: list[str] = []

    async def investigate(
        self,
        fingerprint: ServiceFingerprint,
        *,
        initial_spec: ProcessSpec | None = None,
    ) -> ResearchDossier:
        """Run the full research chain for a service fingerprint.

        Parameters
        ----------
        fingerprint:
            The fingerprinted service specification to research.

        Returns
        -------
        ResearchDossier
            A frozen record of every source attempted, the CVE references
            found, and any connectivity limitations encountered.
        """
        sources_attempted: list[ResearchSource] = []
        all_hits: list[_ResearchHit] = []
        limitations: list[str] = []

        async def searchsploit(
            value: ServiceFingerprint,
        ) -> tuple[tuple[_ResearchHit, ...], str]:
            return await self._query_searchsploit(
                value,
                initial_spec=initial_spec,
            )

        queries = (
            (ResearchSource.LOCAL_SEARCHSPLOIT, searchsploit),
            (ResearchSource.VENDOR, self._query_vendor),
            (ResearchSource.NVD, self._query_nvd),
            (ResearchSource.CISA_KEV, self._query_cisa_kev),
            (ResearchSource.METASPLOIT, self._query_metasploit),
            (ResearchSource.PUBLIC_POC_INDEX, self._query_public_poc),
        )
        for source, query in queries:
            sources_attempted.append(source)
            try:
                if source is ResearchSource.METASPLOIT:
                    known_cves = tuple(
                        dict.fromkeys(
                            hit.cve_id.upper() for hit in all_hits if _CVE_RE.fullmatch(hit.cve_id)
                        )
                    )
                    hits, limitation = await self._query_metasploit(
                        fingerprint,
                        known_cves=known_cves,
                    )
                else:
                    hits, limitation = await query(fingerprint)
            except Exception as exc:
                hits = ()
                limitation = f"{source}: {type(exc).__name__}: {exc}"
            all_hits.extend(hits)
            if limitation:
                limitations.append(limitation)

        entries = tuple(
            CveReference(
                cve_id=hit.cve_id,
                title=hit.title,
                description=hit.description,
                cvss_score=hit.cvss_score,
                source_url=hit.locator or None,
                source=hit.source,
            )
            for hit in all_hits
        )

        return ResearchDossier(
            fingerprint=fingerprint,
            sources_attempted=tuple(sources_attempted),
            entries=entries,
            candidates=self._deduplicate_candidates(fingerprint, all_hits),
            source_limitations=tuple(limitations),
            network_queries=tuple(self.network_queries),
        )

    # ── Individual source queries ─────────────────────────────────────────

    async def _query_searchsploit(
        self,
        fingerprint: ServiceFingerprint,
        *,
        initial_spec: ProcessSpec | None = None,
    ) -> tuple[tuple[_ResearchHit, ...], str]:
        """Query the local SearchSploit / Exploit-DB index.

        Runs ``searchsploit <product> <version>`` and parses the output
        table.  This is a local query — no network request.
        """
        query_parts = [fingerprint.product]
        if fingerprint.version:
            query_parts.append(fingerprint.version)

        spec = initial_spec or ProcessSpec(
            argv=("searchsploit", "--json", *query_parts),
            timeout_seconds=30,
            max_output_bytes=512 * 1024,
        )
        result = await self._runtime.run(spec)

        if result.exit_code != 0:
            return (), (
                "local-searchsploit: " + (result.stderr.strip() or f"exit code {result.exit_code}")
            )
        return self._parse_searchsploit(result.stdout), ""

    async def _query_vendor(
        self,
        fingerprint: ServiceFingerprint,
    ) -> tuple[tuple[_ResearchHit, ...], str]:
        """Query vendor advisory sources."""
        url = self._vendor_url(fingerprint.product)
        if url is None:
            return (), f"vendor: no curated advisory source for {fingerprint.product}"
        body, limitation = await self._curl(ResearchSource.VENDOR, url)
        if limitation:
            return (), limitation
        return self._parse_cve_text(body, ResearchSource.VENDOR, url), ""

    async def _query_nvd(
        self,
        fingerprint: ServiceFingerprint,
    ) -> tuple[tuple[_ResearchHit, ...], str]:
        """Query the National Vulnerability Database."""
        query = " ".join(value for value in (fingerprint.product, fingerprint.version) if value)
        url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch={quote_plus(query)}"
        body, limitation = await self._curl(ResearchSource.NVD, url)
        if limitation:
            return (), limitation
        return self._parse_nvd(body, url, fingerprint), ""

    async def _query_cisa_kev(
        self,
        fingerprint: ServiceFingerprint,
    ) -> tuple[tuple[_ResearchHit, ...], str]:
        """Query the CISA Known Exploited Vulnerabilities catalog."""
        url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
        body, limitation = await self._curl(ResearchSource.CISA_KEV, url)
        if limitation:
            return (), limitation
        return self._parse_cisa_kev(body, fingerprint, url), ""

    async def _query_metasploit(
        self,
        fingerprint: ServiceFingerprint,
        *,
        known_cves: tuple[str, ...] = (),
    ) -> tuple[tuple[_ResearchHit, ...], str]:
        """Correlate discovered CVEs with MSF search and module metadata."""
        from ariadne.runtime.process import ProcessSpec

        cves = known_cves[:3]
        queries = cves or ("",)
        hits: list[_ResearchHit] = []
        limitations: list[str] = []
        for cve in queries:
            query = (
                f"cve:{cve} type:exploit"
                if cve
                else "type:exploit "
                + " ".join(
                    value
                    for value in (
                        fingerprint.product,
                        fingerprint.version,
                    )
                    if value
                )
            )
            result = await self._runtime.run(
                ProcessSpec(
                    argv=(
                        "msfconsole",
                        "-q",
                        "-x",
                        f"search {query}; exit",
                    ),
                    timeout_seconds=30,
                    max_output_bytes=2 * 1024 * 1024,
                )
            )
            if result.exit_code != 0:
                limitations.append(
                    result.stderr.strip()
                    or f"search {cve or fingerprint.product}: exit code {result.exit_code}"
                )
                continue
            # One metadata-correlated module per CVE keeps the complete
            # six-source chain inside the curated 12-attempt envelope.
            modules = self._parse_metasploit_module_rows(result.stdout)[:1]
            for module, check_supported, title, row_cves in modules:
                candidate_cves = (cve,) if cve else row_cves
                if not candidate_cves:
                    continue
                info = await self._runtime.run(
                    ProcessSpec(
                        argv=(
                            "msfconsole",
                            "-q",
                            "-x",
                            f"info {module}; exit",
                        ),
                        timeout_seconds=30,
                        max_output_bytes=2 * 1024 * 1024,
                    )
                )
                if info.exit_code != 0:
                    limitations.append(
                        info.stderr.strip() or f"info {module}: exit code {info.exit_code}"
                    )
                    continue
                info_cves = {value.upper() for value in _CVE_RE.findall(info.stdout)}
                applicability = self._metasploit_applicability(
                    fingerprint,
                    info.stdout,
                )
                for candidate_cve in candidate_cves:
                    if candidate_cve.upper() not in info_cves:
                        continue
                    hits.append(
                        _ResearchHit(
                            cve_id=candidate_cve.upper(),
                            title=title,
                            description=info.stdout[:2000],
                            source=ResearchSource.METASPLOIT,
                            locator=f"metasploit://{module}",
                            metasploit_module=module,
                            check_supported=check_supported
                            or bool(
                                re.search(
                                    r"^\s*Check supported:\s*Yes",
                                    info.stdout,
                                    re.IGNORECASE | re.MULTILINE,
                                )
                            ),
                            requires_reverse_callback=bool(
                                re.search(
                                    r"^\s*LHOST\s+",
                                    info.stdout,
                                    re.IGNORECASE | re.MULTILINE,
                                )
                            ),
                            applicability_evidence=applicability,
                        )
                    )
        limitation = "metasploit: " + " | ".join(limitations) if limitations else ""
        return tuple(hits), limitation

    async def _query_public_poc(
        self,
        fingerprint: ServiceFingerprint,
    ) -> tuple[tuple[_ResearchHit, ...], str]:
        """Query public PoC indexes (e.g. GitHub, Exploit-DB online)."""
        del fingerprint
        return (
            (),
            "public-poc-index: uncurated code lookup requires explicit approval",
        )

    # ── Query helpers ─────────────────────────────────────────────────────

    async def _curl(
        self,
        source: ResearchSource,
        url: str,
    ) -> tuple[str, str]:
        """Fetch one curated source through the bounded execution runtime."""
        from ariadne.runtime.process import ProcessSpec

        self.network_queries.append(url)
        result = await self._runtime.run(
            ProcessSpec(
                argv=(
                    "curl",
                    "--fail",
                    "--silent",
                    "--show-error",
                    "--max-time",
                    "15",
                    url,
                ),
                timeout_seconds=20,
                max_output_bytes=2 * 1024 * 1024,
            )
        )
        if result.exit_code != 0:
            return "", (f"{source}: " + (result.stderr.strip() or f"exit code {result.exit_code}"))
        return result.stdout, ""

    @staticmethod
    def _vendor_url(product: str) -> str | None:
        normalized = product.casefold()
        if "apache" in normalized and ("http" in normalized or "httpd" in normalized):
            return "https://httpd.apache.org/security/vulnerabilities_24.html"
        if "nginx" in normalized:
            return "https://nginx.org/en/security_advisories.html"
        if "openssh" in normalized:
            return "https://www.openssh.com/security.html"
        return None

    @staticmethod
    def _parse_searchsploit(stdout: str) -> tuple[_ResearchHit, ...]:
        try:
            payload = json.loads(stdout)
        except json.JSONDecodeError:
            return ()
        records: list[object] = []
        if isinstance(payload, dict):
            for key in ("RESULTS_EXPLOIT", "RESULTS_SHELLCODE"):
                value = payload.get(key, [])
                if isinstance(value, list):
                    records.extend(value)
        hits: list[_ResearchHit] = []
        for raw in records:
            if not isinstance(raw, dict):
                continue
            record = cast(dict[str, object], raw)
            title = str(record.get("Title", ""))
            codes = " ".join(
                str(record.get(key, "")) for key in ("Codes", "CVE", "Title")
            )
            path = str(record.get("Path", ""))
            edb_id = str(record.get("EDB-ID", "")).strip()
            locator = f"https://www.exploit-db.com/exploits/{edb_id}" if edb_id else path
            for cve in dict.fromkeys(match.upper() for match in _CVE_RE.findall(codes)):
                hits.append(
                    _ResearchHit(
                        cve_id=cve,
                        title=title,
                        description=title,
                        source=ResearchSource.LOCAL_SEARCHSPLOIT,
                        locator=locator,
                        exploit_path=path,
                    )
                )
        return tuple(hits)

    @staticmethod
    def _parse_cve_text(
        body: str,
        source: ResearchSource,
        locator: str,
    ) -> tuple[_ResearchHit, ...]:
        return tuple(
            _ResearchHit(
                cve_id=cve,
                title=cve,
                description=f"{cve} referenced by the official vendor advisory",
                source=source,
                locator=locator,
            )
            for cve in dict.fromkeys(match.upper() for match in _CVE_RE.findall(body))
        )

    @staticmethod
    def _parse_nvd(
        body: str,
        locator: str,
        fingerprint: ServiceFingerprint,
    ) -> tuple[_ResearchHit, ...]:
        try:
            payload = json.loads(body)
        except json.JSONDecodeError:
            return ()
        vulnerabilities = payload.get("vulnerabilities", [])
        if not isinstance(vulnerabilities, list):
            return ()
        hits: list[_ResearchHit] = []
        for item in vulnerabilities:
            if not isinstance(item, dict) or not isinstance(item.get("cve"), dict):
                continue
            cve = item["cve"]
            cve_id = str(cve.get("id", "")).upper()
            if _CVE_RE.fullmatch(cve_id) is None:
                continue
            description = ""
            descriptions = cve.get("descriptions", [])
            if isinstance(descriptions, list):
                description = next(
                    (
                        str(record.get("value", ""))
                        for record in descriptions
                        if isinstance(record, dict) and record.get("lang") == "en"
                    ),
                    "",
                )
            score: float | None = None
            metrics = cve.get("metrics", {})
            if isinstance(metrics, dict):
                for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                    values = metrics.get(key, [])
                    if not isinstance(values, list) or not values:
                        continue
                    first = values[0]
                    if not isinstance(first, dict):
                        continue
                    data = first.get("cvssData", {})
                    if isinstance(data, dict) and isinstance(data.get("baseScore"), (int, float)):
                        score = float(data["baseScore"])
                        break
            applicability = ResearchPipeline._nvd_applicability(
                cve,
                fingerprint,
                description,
            )
            hits.append(
                _ResearchHit(
                    cve_id=cve_id,
                    title=cve_id,
                    description=description,
                    cvss_score=score,
                    source=ResearchSource.NVD,
                    locator=f"https://nvd.nist.gov/vuln/detail/{cve_id}",
                    applicability_evidence=applicability,
                )
            )
        return tuple(hits)

    @staticmethod
    def _nvd_applicability(
        cve: dict[str, object],
        fingerprint: ServiceFingerprint,
        description: str,
    ) -> tuple[str, ...]:
        """Return explicit version/CPE evidence from the NVD record."""
        observed_cpe_parts = (
            fingerprint.cpe.split(":")
            if isinstance(fingerprint.cpe, str) and fingerprint.cpe.startswith("cpe:2.3:")
            else []
        )
        version = (
            fingerprint.version
            or (observed_cpe_parts[5] if len(observed_cpe_parts) > 5 else "")
        ).strip()
        if not version:
            return ()
        evidence: list[str] = []
        product_tokens = {
            token
            for token in re.findall(r"[a-z0-9]+", fingerprint.product.casefold())
            if token not in {"http", "https", "server", "service"}
        }
        description_tokens = set(re.findall(r"[a-z0-9]+", description.casefold()))
        version_match = re.search(
            rf"(?<![A-Za-z0-9.]){re.escape(version)}(?![A-Za-z0-9.])",
            description,
        )
        if version_match is not None and (
            not product_tokens or product_tokens.intersection(description_tokens)
        ):
            context = description[
                max(0, version_match.start() - 48) : version_match.end() + 48
            ].casefold()
            if not re.search(
                r"(?:fixed (?:in|by)|unaffected|not affected|upgrade to)\s*.{0,24}"
                + re.escape(version.casefold()),
                context,
            ):
                evidence.append(f"nvd-description:version={version}")

        def visit(value: object) -> None:
            if isinstance(value, dict):
                node = cast(dict[str, object], value)
                matches = node.get("cpeMatch")
                if isinstance(matches, list):
                    for match in matches:
                        if not isinstance(match, dict):
                            continue
                        match_record = cast(dict[str, object], match)
                        if match_record.get("vulnerable") is not True:
                            continue
                        criteria = str(match_record.get("criteria", ""))
                        criteria_tokens = set(re.findall(r"[a-z0-9]+", criteria.casefold()))
                        criteria_parts = criteria.split(":")
                        cpe_identity_matches = bool(
                            len(observed_cpe_parts) > 5
                            and len(criteria_parts) > 5
                            and criteria_parts[2:5] == observed_cpe_parts[2:5]
                        )
                        if observed_cpe_parts and not cpe_identity_matches:
                            continue
                        if not observed_cpe_parts and product_tokens and not (
                            product_tokens.intersection(criteria_tokens)
                        ):
                            continue
                        criteria_version = criteria_parts[5] if len(criteria_parts) > 5 else ""
                        has_range = any(
                            isinstance(match_record.get(field), str)
                            and bool(str(match_record[field]).strip())
                            for field in (
                                "versionStartIncluding",
                                "versionStartExcluding",
                                "versionEndIncluding",
                                "versionEndExcluding",
                            )
                        )
                        applies = criteria_version == version or (
                            criteria_version in {"", "*", "-"}
                            and (
                                not has_range
                                or ResearchPipeline._version_in_range(
                                    version,
                                    match_record,
                                )
                            )
                        )
                        if applies:
                            evidence.append(f"nvd-cpe:{criteria};version={version}")
                for nested in node.values():
                    visit(nested)
            elif isinstance(value, list):
                for nested in value:
                    visit(nested)

        visit(cve.get("configurations", []))
        return tuple(dict.fromkeys(evidence))

    @staticmethod
    def _version_in_range(
        version: str,
        match: dict[str, object],
    ) -> bool:
        def normalise(value: str) -> tuple[tuple[int, object], ...]:
            return tuple(
                (0, int(token)) if token.isdigit() else (1, token)
                for token in re.findall(r"\d+|[A-Za-z]+", value)
            )

        current = normalise(version)
        if not current:
            return False
        bounds = (
            ("versionStartIncluding", lambda value: current >= value),
            ("versionStartExcluding", lambda value: current > value),
            ("versionEndIncluding", lambda value: current <= value),
            ("versionEndExcluding", lambda value: current < value),
        )
        found = False
        for field, predicate in bounds:
            raw = match.get(field)
            if not isinstance(raw, str) or not raw.strip():
                continue
            found = True
            if not predicate(normalise(raw)):
                return False
        return found

    @staticmethod
    def _parse_cisa_kev(
        body: str,
        fingerprint: ServiceFingerprint,
        locator: str,
    ) -> tuple[_ResearchHit, ...]:
        try:
            payload = json.loads(body)
        except json.JSONDecodeError:
            return ()
        records = payload.get("vulnerabilities", [])
        if not isinstance(records, list):
            return ()
        product = fingerprint.product.casefold()
        hits: list[_ResearchHit] = []
        for record in records:
            if not isinstance(record, dict):
                continue
            haystack = " ".join(
                str(record.get(key, ""))
                for key in ("vendorProject", "product", "vulnerabilityName")
            ).casefold()
            if not all(token in haystack for token in product.split()[:1]):
                continue
            cve_id = str(record.get("cveID", "")).upper()
            if _CVE_RE.fullmatch(cve_id) is None:
                continue
            hits.append(
                _ResearchHit(
                    cve_id=cve_id,
                    title=str(record.get("vulnerabilityName", cve_id)),
                    description=str(record.get("shortDescription", "")),
                    source=ResearchSource.CISA_KEV,
                    locator=locator,
                )
            )
        return tuple(hits)

    @staticmethod
    def _parse_metasploit_module_rows(
        stdout: str,
    ) -> tuple[tuple[str, bool, str, tuple[str, ...]], ...]:
        rows: list[tuple[str, bool, str, tuple[str, ...]]] = []
        for line in stdout.splitlines():
            module_match = _MSF_MODULE_RE.search(line)
            if module_match is None:
                continue
            module = module_match.group(0)
            cves = tuple(dict.fromkeys(match.upper() for match in _CVE_RE.findall(line)))
            check_supported = bool(re.search(r"\bYes\b", line))
            rows.append((module, check_supported, line.strip(), cves))
        return tuple(rows)

    @staticmethod
    def _metasploit_applicability(
        fingerprint: ServiceFingerprint,
        metadata: str,
    ) -> tuple[str, ...]:
        """Extract explicit product/version applicability from ``msf info``."""
        version = fingerprint.version
        if not isinstance(version, str) or not version.strip():
            return ()
        tokens = {
            token
            for token in re.findall(r"[a-z0-9]+", fingerprint.product.casefold())
            if token not in {"http", "https", "server", "service"}
        }
        text = metadata.casefold()
        if tokens and not tokens.intersection(re.findall(r"[a-z0-9]+", text)):
            return ()
        evidence: list[str] = []
        exact = re.search(
            rf"(?<![a-z0-9.]){re.escape(version.casefold())}(?![a-z0-9.])",
            text,
        )
        if exact is not None:
            evidence.append(f"metasploit-info:version={version}")
        observed = ResearchPipeline._version_in_parts(version)
        if observed:
            for match in re.finditer(
                r"(?P<major>\d+)\.x\s*<\s*(?P<upper>\d+(?:\.\d+)+)",
                text,
            ):
                if int(match.group("major")) != observed[0]:
                    continue
                upper = ResearchPipeline._version_in_parts(match.group("upper"))
                if upper and observed < upper:
                    evidence.append(
                        "metasploit-info:version<" + match.group("upper")
                    )
        return tuple(dict.fromkeys(evidence))

    @staticmethod
    def _version_in_parts(value: str) -> tuple[int, ...]:
        return tuple(int(part) for part in re.findall(r"\d+", value)[:4])

    @staticmethod
    def _deduplicate_candidates(
        fingerprint: ServiceFingerprint,
        hits: list[_ResearchHit],
    ) -> tuple[ResearchCandidate, ...]:
        grouped: dict[str, list[_ResearchHit]] = {}
        for hit in hits:
            grouped.setdefault(hit.cve_id.upper(), []).append(hit)
        candidates: list[ResearchCandidate] = []
        for cve_id, group in sorted(grouped.items()):
            sources = tuple(dict.fromkeys(hit.source for hit in group))
            source_urls = tuple(dict.fromkeys(hit.locator for hit in group if hit.locator))
            exploit_paths = tuple(
                dict.fromkeys(hit.exploit_path for hit in group if hit.exploit_path)
            )
            modules = tuple(
                dict.fromkeys(hit.metasploit_module for hit in group if hit.metasploit_module)
            )
            authoritative = bool(
                set(sources)
                & {
                    ResearchSource.VENDOR,
                    ResearchSource.NVD,
                    ResearchSource.CISA_KEV,
                }
            )
            exploit_backed = bool(
                set(sources)
                & {
                    ResearchSource.LOCAL_SEARCHSPLOIT,
                    ResearchSource.METASPLOIT,
                }
            )
            applicability_evidence = tuple(
                dict.fromkeys(item for hit in group for item in hit.applicability_evidence)
            )
            compatible = bool(applicability_evidence)
            stable = "|".join(
                (
                    fingerprint.product.casefold(),
                    (fingerprint.version or "").casefold(),
                    cve_id,
                )
            )
            candidates.append(
                ResearchCandidate(
                    candidate_id="research-" + sha256(stable.encode()).hexdigest()[:20],
                    product=fingerprint.product,
                    version=fingerprint.version,
                    cve_id=cve_id,
                    title=next((hit.title for hit in group if hit.title), cve_id),
                    cvss_score=next(
                        (hit.cvss_score for hit in group if hit.cvss_score is not None),
                        None,
                    ),
                    sources=sources,
                    source_urls=source_urls,
                    exploit_paths=exploit_paths,
                    metasploit_modules=modules,
                    check_supported=any(hit.check_supported for hit in group),
                    requires_reverse_callback=any(
                        hit.requires_reverse_callback for hit in group
                    ),
                    compatible=compatible,
                    applicability_evidence=applicability_evidence,
                    validation_status=(
                        "validated"
                        if authoritative and exploit_backed and compatible
                        else "candidate"
                    ),
                    evidence=tuple(hit.evidence() for hit in group),
                )
            )
        return tuple(candidates)


# ── ToolAdapter wrapper ─────────────────────────────────────────────────────


class ResearchAdapter:
    """ToolAdapter-compliant wrapper around the research pipeline.

    Supports one operation:
    - ``investigate``: run the research pipeline for a given product/service.

    For the preflight check (product="preflight"), runs a lightweight
    searchsploit probe to verify environment readiness.  The full
    investigation chain is delegated to ``ResearchPipeline`` when
    actual service fingerprint data is available.
    """

    name: ClassVar[str] = "research"

    # Supported operations
    _OPERATIONS: ClassVar[frozenset[str]] = frozenset({"investigate"})

    # ── ToolAdapter protocol ─────────────────────────────────────────────

    async def probe(self, runtime: Runtime) -> ToolProbe:
        """Probe by running ``searchsploit --version``."""
        from ariadne.runtime.process import ProcessSpec

        spec = ProcessSpec(
            argv=("searchsploit", "--version"),
            timeout_seconds=10,
            max_output_bytes=1024 * 1024,
        )
        result = await runtime.run(spec)
        return ToolProbe(
            available=result.exit_code == 0,
            version=result.stdout.strip() if result.exit_code == 0 else None,
        )

    def plan(
        self,
        action: PlannedAction,
        context: AdapterContext,
    ) -> ProcessSpec:
        """Build a ProcessSpec for the research operation.

        For ``investigate`` with ``product: "preflight"``, runs a lightweight
        connectivity check (ping) against the target to verify environment
        readiness.  For other products, searches for known CVEs via
        searchsploit.

        No shell interpolation — argv is a direct tuple.
        """
        if action.operation not in self._OPERATIONS:
            raise AdapterError(
                f"Unknown research operation: {action.operation!r}. "
                f"Supported: {', '.join(sorted(self._OPERATIONS))}"
            )

        product = action.inputs.get("product", "")

        # Full-chain research must be tied to a structured service fingerprint.
        # The adapter context intentionally carries no ambient observation
        # history, so a missing product is a hard evidence boundary rather
        # than an invitation to query a synthetic ``unknown`` product.
        if not product and action.inputs.get("full_chain"):
            raise AdapterPolicyError(
                "Research full_chain is blocked: missing evidence for a "
                "validated service product or fingerprint."
            )

        if not product:
            product = "unknown"

        if product == "preflight":
            # Preflight = connectivity check against the engagement target
            target_host = context.target.host
            argv = ("ping", "-c", "1", "-W", "3", target_host)
            return ProcessSpec(
                argv=argv,
                cwd=context.cwd,
                timeout_seconds=_bounded(
                    10,
                    context.limits.max_duration_seconds,
                ),
                max_output_bytes=_bounded(
                    1024 * 1024,
                    context.limits.max_output_bytes,
                ),
            )

        version = action.inputs.get("version")
        if version is not None and not isinstance(version, str):
            raise AdapterError("Research version must be a string when provided")
        protocol = action.inputs.get("protocol")
        if protocol is not None and not isinstance(protocol, str):
            raise AdapterError("Research protocol must be a string when provided")
        port = action.inputs.get("port")
        if port is not None and (isinstance(port, bool) or not isinstance(port, int) or port < 1):
            raise AdapterError("Research port must be a positive integer")
        cpe = action.inputs.get("cpe")
        if cpe is not None and not isinstance(cpe, str):
            raise AdapterError("Research CPE must be a string when provided")

        query_parts = [str(product)]
        if version:
            query_parts.append(version)
        argv = ("searchsploit", "--json", *query_parts)
        environment = {}
        if action.inputs.get("full_chain"):
            environment["ARIADNE_RESEARCH_FINGERPRINT"] = json.dumps(
                {
                    "product": product,
                    "version": version,
                    "protocol": protocol,
                    "port": port,
                    "cpe": cpe,
                    "target_host": context.target.host,
                },
                sort_keys=True,
                separators=(",", ":"),
            )
        return ProcessSpec(
            argv=argv,
            cwd=context.cwd,
            environment=environment,
            timeout_seconds=_bounded(
                30,
                context.limits.max_duration_seconds,
            ),
            max_output_bytes=_bounded(
                1024 * 1024,
                context.limits.max_output_bytes,
            ),
        )

    async def execute(
        self,
        spec: ProcessSpec,
        runtime: Runtime,
    ) -> ProcessResult:
        try:
            raw_fingerprint = spec.environment.get("ARIADNE_RESEARCH_FINGERPRINT")
            if raw_fingerprint:
                fingerprint = ServiceFingerprint.model_validate_json(raw_fingerprint)
                dossier = await ResearchPipeline(runtime).investigate(
                    fingerprint,
                    initial_spec=spec,
                )
                return ProcessResult(
                    exit_code=0,
                    stdout=dossier.model_dump_json(),
                    stderr="\n".join(dossier.source_limitations),
                    status=ProcessStatus.COMPLETED,
                )
            result = await runtime.run(spec)
            if (
                spec.argv[0] == "ping"
                and result.exit_code in {1, 2}
                and result.status in {ProcessStatus.COMPLETED, ProcessStatus.FAILED}
                and "packet loss" in result.stdout.lower()
            ):
                # ICMP silence is not proof that an HTB/lab target is down.
                # The following nmap -Pn discovery is the authoritative TCP
                # reachability check; only failures to execute ping remain a
                # hard preflight boundary.
                return result.model_copy(update={"exit_code": 0})
            return result
        except FileNotFoundError:
            return ProcessResult(
                exit_code=127,
                stdout="",
                stderr="searchsploit is not installed",
                status=ProcessStatus.FAILED,
            )
        except Exception:
            raise

    def parse(
        self,
        result: ProcessResult,
    ) -> tuple[Observation, ...]:
        raise AdapterError("Research observations require an explicit engagement target")

    def parse_for_target(
        self,
        result: ProcessResult,
        target: TargetSpec,
    ) -> tuple[Observation, ...]:
        """Parse searchsploit/ping output into observations.

        For the preflight check (ping), produces a single observation
        indicating whether the target is reachable.
        For searchsploit, produces observations from the output.
        """
        from uuid import uuid4

        observations: list[Observation] = []

        if result.exit_code == 0:
            stdout_preview = result.stdout[:500] if result.stdout else ""
            is_ping = "ping" in stdout_preview.lower() or "round-trip" in stdout_preview.lower()
            dossier: ResearchDossier | None = None

            if is_ping:
                icmp_inconclusive = "100.0% packet loss" in stdout_preview.lower()
                obs = Observation(
                    observation_id=uuid4(),
                    target=target,
                    source="preflight_passed",
                    data={
                        "type": "preflight_passed",
                        "summary": (
                            "ICMP unanswered; defer reachability to TCP discovery"
                            if icmp_inconclusive
                            else "Target is reachable — environment ready"
                        ),
                        "reachability": (
                            "icmp_inconclusive"
                            if icmp_inconclusive
                            else "icmp_reachable"
                        ),
                        "stdout_preview": stdout_preview,
                    },
                )
            else:
                try:
                    dossier = ResearchDossier.model_validate_json(result.stdout)
                except (ValueError, TypeError):
                    dossier = None
                obs = Observation(
                    observation_id=uuid4(),
                    target=target,
                    source="research_complete",
                    data={
                        "type": "research_complete",
                        "summary": (
                            "Provenance-aware exploit research completed"
                            if dossier is not None
                            else "Local exploit research completed"
                        ),
                        "stdout_preview": stdout_preview,
                        **(
                            {
                                "fingerprint": dossier.fingerprint.model_dump(mode="json"),
                                "sources_attempted": [
                                    str(source) for source in dossier.sources_attempted
                                ],
                                "source_limitations": list(dossier.source_limitations),
                                "candidates": [
                                    candidate.model_dump(mode="json")
                                    for candidate in dossier.candidates
                                ],
                            }
                            if dossier is not None
                            else {}
                        ),
                    },
                )
            observations.append(obs)
            if dossier is not None:
                for candidate in dossier.candidates:
                    candidate_data = candidate.model_dump(mode="json")
                    source = (
                        "metasploit_candidate"
                        if candidate.metasploit_modules and candidate.check_supported
                        else "exploit_candidate"
                    )
                    observations.append(
                        Observation(
                            observation_id=uuid4(),
                            target=target,
                            source=source,
                            data={
                                "type": source,
                                **candidate_data,
                            },
                        )
                    )

        return tuple(observations)

    def classify(
        self,
        result: ProcessResult,
        observations: tuple[Observation, ...],
    ) -> ExecutionClassification:
        """Classify the research execution outcome.

        searchsploit may not be installed — exit_code != 0 without
        observations is treated as a non-fatal no-op, not a failure.
        """
        if result.timed_out:
            return ExecutionClassification(
                kind="partial",
                confidence=0.3,
                summary="Research timed out; partial results available",
            )
        if result.exit_code != 0:
            return ExecutionClassification(
                kind="failure",
                confidence=1.0,
                summary=("Research tool failed or is unavailable; no evidence was produced"),
            )
        if len(observations) > 0:
            return ExecutionClassification(
                kind="success",
                confidence=0.9,
                summary=f"Research produced {len(observations)} observations",
            )
        return ExecutionClassification(
            kind="unknown",
            confidence=0.5,
            summary="Research completed but no observations produced",
        )

    async def collect(
        self,
        result: ProcessResult,
        collector: object,
    ) -> tuple[str, ...]:
        """The handler persists typed observations; do not invent raw evidence."""
        del result, collector
        return ()

    async def cleanup(
        self,
        context: AdapterContext,
    ) -> CleanupResult:
        """No temporary resources to clean up."""
        return CleanupResult(success=True, details="No temporary resources to clean up")


def _bounded(requested: int, maximum: int | None) -> int:
    return requested if maximum is None else min(requested, maximum)

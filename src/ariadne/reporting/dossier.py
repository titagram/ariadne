"""Build the canonical report model from persisted run facts.

The builder deliberately has no scanner, network, or inference dependency.
Snapshot fields, hash-chained events, and real files under ``artifacts/`` are
the only accepted inputs.
"""

from __future__ import annotations

import hashlib
import json
import re
import shlex
from collections.abc import Iterable
from pathlib import Path
from typing import Any

from ariadne.evidence.redaction import RedactionService
from ariadne.reporting.models import (
    AttackStep,
    ReportEvidence,
    ReportFinding,
    ReportLifecycleEntry,
    ReportModel,
    ReportObjective,
    ReportTarget,
)
from ariadne.reporting.validation import ReportOptions
from ariadne.store.run_store import RunHandle, resolve_objective_flag

_SEVERITIES = ("critical", "high", "medium", "low", "informational")
_FLAG_RE = re.compile(r"\b(?:HTB|FLAG|CTF)\{[^}]*\}")
_SHA256_RE = re.compile(r"^[a-f0-9]{64}$")
_ACTIVITY_EVENT_TYPES = frozenset({
    "discovery_completed",
    "enumeration_completed",
    "hypothesis_created",
    "hypothesis_discarded",
    "alternative_discarded",
    "finding_validated",
    "initial_access",
    "access_validated",
    "host_compromised",
    "post_exploitation",
    "privilege_escalation",
    "ad_enumeration",
    "pivot_completed",
    "plan_executed",
    "objective_completed",
    "cleanup_completed",
    "execution_boundary",
    "remediation_applied",
})


def _read_events(path: Path) -> list[dict[str, Any]]:
    """Read well-formed JSON object events, preserving their stored order."""
    events_path = path / "events.jsonl"
    if not events_path.is_file():
        return []

    events: list[dict[str, Any]] = []
    for line in events_path.read_text(encoding="utf-8").splitlines():
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(event, dict):
            events.append(event)
    return events


def _string(payload: dict[str, Any], *keys: str) -> str | None:
    for key in keys:
        value = payload.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    return None


def _strings(value: object) -> tuple[str, ...]:
    if isinstance(value, str) and value.strip():
        return (value.strip(),)
    if isinstance(value, (list, tuple)):
        return tuple(str(item).strip() for item in value if str(item).strip())
    return ()


class DossierBuilder:
    """Construct one factual, renderer-independent :class:`ReportModel`."""

    def __init__(self, redactor: RedactionService | None = None) -> None:
        self._redactor = redactor or RedactionService()

    def build(
        self,
        run: RunHandle,
        options: ReportOptions | None = None,
    ) -> ReportModel:
        """Build a report dossier without synthesising absent facts."""
        resolved_options = options or ReportOptions()
        events = _read_events(run.path)
        evidence = self._build_evidence(run.path, events, resolved_options)
        target_hosts = tuple(target.host for target in run.snapshot.targets)
        attack_steps = self._build_attack_steps(
            events,
            evidence,
            target_hosts,
            resolved_options,
        )
        findings = self._build_findings(
            events,
            evidence,
            attack_steps,
            target_hosts,
            resolved_options,
        )

        return ReportModel(
            engagement_id=str(run.snapshot.engagement_id),
            snapshot_hash=run.snapshot.snapshot_hash,
            generated_at=self._generated_at(run, events),
            authorization_attested=run.snapshot.authorization_attested,
            profile=run.snapshot.profile.value,
            autonomy=run.snapshot.autonomy.value,
            intensity=run.snapshot.intensity,
            exclusions=run.snapshot.exclusions,
            targets=tuple(ReportTarget(host=target.host) for target in run.snapshot.targets),
            objectives=self._build_objectives(run, events, resolved_options),
            evidence=evidence,
            findings=findings,
            attack_steps=attack_steps,
            lifecycle=self._build_lifecycle(events, resolved_options),
            cleanup=self._event_texts(
                events,
                {"cleanup_completed"},
                ("description", "summary"),
                resolved_options,
            ),
            remediation=self._event_texts(
                events,
                {"remediation_applied"},
                ("remediation", "description", "summary"),
                resolved_options,
            ),
            compromised=self._build_compromised(
                events,
                attack_steps,
                target_hosts,
                resolved_options,
            ),
            lessons=self._event_texts(
                events,
                {"lesson_learned"},
                ("lesson", "description", "summary"),
                resolved_options,
            ),
            commands=self._commands(events, resolved_options),
            risk_counts=self._risk_counts(findings),
        )

    def _sanitize(self, value: str | None, options: ReportOptions) -> str:
        if not value:
            return ""
        if options.include_secrets and options.include_flags:
            return value
        if options.include_secrets:
            return value if options.include_flags else _FLAG_RE.sub("[REDACTED]", value)
        if not options.include_flags:
            return self._redactor.redact(value).text

        protected: list[str] = []

        def protect(match: re.Match[str]) -> str:
            protected.append(match.group(0))
            return f"ARIADNE_FLAG_PLACEHOLDER_{len(protected) - 1}"

        redacted = self._redactor.redact(_FLAG_RE.sub(protect, value)).text
        for index, flag in enumerate(protected):
            redacted = redacted.replace(f"ARIADNE_FLAG_PLACEHOLDER_{index}", flag)
        return redacted

    def _build_evidence(
        self,
        run_path: Path,
        events: Iterable[dict[str, Any]],
        options: ReportOptions,
    ) -> tuple[ReportEvidence, ...]:
        artifacts_root = (run_path / "artifacts").resolve()
        collected: dict[str, ReportEvidence] = {}
        for event in events:
            if event.get("event_type") != "evidence_collected":
                continue
            payload = event.get("payload")
            if not isinstance(payload, dict):
                continue
            artifact = payload.get("artifact")
            if not isinstance(artifact, str) or not artifact.strip():
                continue
            artifact_path = (artifacts_root / artifact).resolve()
            if (
                not artifact_path.is_relative_to(artifacts_root)
                or not artifact_path.is_file()
            ):
                continue
            content = artifact_path.read_bytes()
            digest = hashlib.sha256(content).hexdigest()
            if digest in collected:
                continue
            collected[digest] = ReportEvidence(
                    filename=artifact,
                    path=artifact_path,
                    sha256=digest,
                    size_bytes=len(content),
                    finding=self._optional_sanitized(payload, "finding", options),
                    asset=self._optional_sanitized(payload, "asset", options),
                    evidence_type=self._optional_sanitized(
                        payload, "evidence_type", options,
                    ),
                    finding_id=self._optional_sanitized(payload, "finding_id", options),
                    caption=self._evidence_caption(payload),
                    excerpt=self._evidence_excerpt(content, options),
            )
        return tuple(collected.values())

    def _build_findings(
        self,
        events: Iterable[dict[str, Any]],
        evidence: tuple[ReportEvidence, ...],
        attack_steps: tuple[AttackStep, ...],
        target_hosts: tuple[str, ...],
        options: ReportOptions,
    ) -> tuple[ReportFinding, ...]:
        findings: list[ReportFinding] = []
        for event in events:
            event_type = event.get("event_type")
            if event_type not in {"finding_candidate", "finding_validated"}:
                continue
            payload = event.get("payload")
            if not isinstance(payload, dict):
                continue
            title = self._sanitize(_string(payload, "title", "finding"), options)
            if not title:
                continue
            finding_id = self._optional_sanitized(payload, "finding_id", options)
            related = tuple(
                item for item in evidence
                if (
                    finding_id
                    and item.finding_id == finding_id
                    or item.finding == title
                )
            )
            severity_raw = _string(payload, "severity")
            severity = severity_raw.lower() if severity_raw else None
            target = self._optional_sanitized(payload, "target", options)
            if target is None and related:
                target = related[0].asset
            description = self._optional_sanitized(payload, "description", options)
            if description is None and related:
                description = related[0].finding
            remediation = tuple(
                self._sanitize(item, options)
                for item in _strings(payload.get("remediation"))
            )
            findings.append(
                ReportFinding(
                    finding_id=finding_id,
                    title=title,
                    severity=severity,
                    status=(
                        "validated"
                        if event_type == "finding_validated"
                        else "candidate"
                    ),
                    target=target,
                    description=description,
                    evidence=tuple(item.filename for item in related),
                    remediation=remediation,
                ),
            )
        findings.extend(
            self._build_semantic_findings(
                events,
                evidence,
                attack_steps,
                target_hosts,
            ),
        )
        deduplicated: dict[str, ReportFinding] = {}
        for finding in findings:
            key = finding.finding_id or finding.title.casefold()
            deduplicated.setdefault(key, finding)
        return tuple(deduplicated.values())

    def _build_attack_steps(
        self,
        events: Iterable[dict[str, Any]],
        evidence: tuple[ReportEvidence, ...],
        target_hosts: tuple[str, ...],
        options: ReportOptions,
    ) -> tuple[AttackStep, ...]:
        """Reconstruct a compact attack narrative from persisted observations."""
        event_list = list(events)
        evidence_names = {item.filename for item in evidence}
        target = target_hosts[0] if target_hosts else None
        drafts: list[dict[str, Any]] = []

        def observations(*types: str) -> list[tuple[dict[str, Any], dict[str, Any]]]:
            selected = set(types)
            result: list[tuple[dict[str, Any], dict[str, Any]]] = []
            for event in event_list:
                if event.get("event_type") != "evidence_collected":
                    continue
                payload = event.get("payload")
                if not isinstance(payload, dict):
                    continue
                observation = payload.get("observation_data")
                if (
                    payload.get("evidence_type") in selected
                    and isinstance(observation, dict)
                ):
                    result.append((payload, observation))
            return result

        def artifacts(items: Iterable[tuple[dict[str, Any], dict[str, Any]]]) -> tuple[str, ...]:
            return tuple(dict.fromkeys(
                str(payload["artifact"])
                for payload, _ in items
                if payload.get("artifact") in evidence_names
            ))

        def commands(items: Iterable[tuple[dict[str, Any], dict[str, Any]]]) -> tuple[str, ...]:
            values: list[str] = []
            for payload, _ in items:
                raw = payload.get("command_redacted")
                if isinstance(raw, (list, tuple)):
                    command = shlex.join(str(part) for part in raw)
                else:
                    command = _string(payload, "command")
                sanitized = self._sanitize(command, options)
                if sanitized and sanitized not in values:
                    values.append(sanitized)
            if len(values) > 2:
                return (values[0], values[-1])
            return tuple(values)

        ports = observations("port_open")
        if ports:
            services = sorted({
                (
                    int(obs["port"]),
                    str(obs.get("service") or "unknown"),
                )
                for _, obs in ports
                if isinstance(obs.get("port"), int)
            })
            drafts.append({
                "phase": "discovery",
                "action": "Scan the authorized target for reachable TCP services.",
                "input": f"Target {target}",
                "result": "Open TCP services: " + ", ".join(
                    f"{port}/{service}" for port, service in services
                ) + ".",
                "target": target,
                "prerequisites": ("Authorized network reachability to the target.",),
                "commands": commands(ports),
                "evidence": artifacts(ports),
            })

        fingerprints = observations("service_fingerprinted", "web_technologies")
        if fingerprints:
            details: list[str] = []
            for _, observation in fingerprints:
                service = observation.get("service")
                product = observation.get("product")
                version = observation.get("version")
                url = observation.get("url")
                title = observation.get("title")
                if service:
                    details.append(
                        " ".join(
                            str(value)
                            for value in (service, product, version)
                            if value
                        ),
                    )
                elif url:
                    details.append(
                        f"{url}"
                        + (f" ({title})" if title else "")
                    )
            drafts.append({
                "phase": "enumeration",
                "action": "Fingerprint exposed services and the web application.",
                "input": "Open services identified during TCP discovery.",
                "result": "Observed: " + "; ".join(dict.fromkeys(details)) + ".",
                "target": target,
                "prerequisites": ("Completed TCP discovery.",),
                "commands": commands(fingerprints),
                "evidence": artifacts(fingerprints),
            })

        fallback_events = [
            event
            for event in event_list
            if (
                event.get("event_type") == "execution_boundary"
                and isinstance(event.get("payload"), dict)
                and event["payload"].get("adapter") == "zap"
            )
            or (
                event.get("event_type") == "plan_executed"
                and isinstance(event.get("payload"), dict)
                and event["payload"].get("action") in {"katana", "curl"}
                and event["payload"].get("operation") in {"crawl", "fetch"}
            )
        ]
        web_paths = observations("web_paths")
        if fallback_events or web_paths:
            outcomes = []
            for event in fallback_events:
                payload = event["payload"]
                tool = _string(payload, "action", "adapter") or "fallback"
                summary = self._sanitize(
                    _string(payload, "summary", "reason"),
                    options,
                )
                if summary:
                    tool_label = "ZAP" if tool.casefold() == "zap" else tool.title()
                    outcomes.append(f"{tool_label}: {summary}")
            outcomes = [item for item in outcomes if item]
            drafts.append({
                "phase": "enumeration",
                "action": (
                    "Enumerate same-host web content, recording crawler failures "
                    "and using the bounded curl fallback."
                ),
                "input": "Persisted HTTP endpoint from service fingerprinting.",
                "result": " ".join(outcomes) or "Same-host web paths were collected.",
                "target": target,
                "prerequisites": ("Reachable in-scope HTTP service.",),
                "commands": commands(web_paths),
                "evidence": artifacts(web_paths),
            })

        references = [
            item
            for item in observations("web_object_reference")
            if (
                item[1].get("status_code") == 200
                and (
                    item[1].get("download_candidate") is True
                    or "pcap" in str(item[1].get("content_type", "")).casefold()
                )
            )
        ]
        downloads = observations("web_artifact")
        if references and downloads:
            urls = tuple(dict.fromkeys(
                str(observation["url"])
                for _, observation in (*references, *downloads)
                if observation.get("url")
            ))
            drafts.append({
                "phase": "exploitation",
                "action": (
                    "Test evidence-derived numeric object references and download "
                    "the verified packet-capture object."
                ),
                "input": ", ".join(urls),
                "result": (
                    "The server returned a packet-capture object without evidence "
                    "of per-object authorization; the download was persisted and hashed."
                ),
                "target": target,
                "prerequisites": (
                    "Reachable in-scope web application.",
                    "Numeric object reference observed in same-host content.",
                ),
                "commands": commands((*references, *downloads)),
                "evidence": artifacts((*references, *downloads)),
            })

        credentials = observations("credential_material")
        if downloads and credentials:
            protocols = sorted({
                str(observation.get("protocol", "unknown")).upper()
                for _, observation in credentials
            })
            drafts.append({
                "phase": "foothold",
                "action": (
                    "Inspect the verified PCAP for the approved FTP/HTTP Basic "
                    "plaintext credential patterns."
                ),
                "input": "Downloaded, SHA-256-verified packet capture.",
                "result": (
                    f"Recovered {', '.join(protocols)} credential material into "
                    "a protected local reference; no credential value is rendered."
                ),
                "target": target,
                "prerequisites": ("Verified packet-capture artifact.",),
                "commands": commands(credentials),
                "evidence": artifacts(credentials),
            })

        foothold = observations("foothold_established")
        if credentials and foothold:
            facts = foothold[-1][1]
            drafts.append({
                "phase": "foothold",
                "action": "Authenticate to SSH using the protected credential reference.",
                "input": "Protected credential reference derived from PCAP analysis.",
                "result": (
                    "SSH foothold established"
                    + (
                        f" as UID {facts['uid']} / GID {facts['gid']}"
                        if "uid" in facts and "gid" in facts
                        else ""
                    )
                    + "; the user objective proof was persisted."
                ),
                "target": target,
                "prerequisites": (
                    "Reachable SSH service.",
                    "Credential material stored as a protected reference.",
                ),
                "commands": commands(foothold),
                "evidence": artifacts(foothold),
            })

        host_info = observations("linux_host_info", "host_info_collected")
        postex = observations("postex")
        capability_observations = [
            item
            for item in postex
            if item[1].get("type") == "privilege_escalation"
            and "cap_setuid" in str(item[1].get("capabilities", ""))
        ]
        if foothold and (host_info or capability_observations):
            capability_paths = tuple(dict.fromkeys(
                line.split("=", 1)[0].strip()
                for _, observation in capability_observations
                for line in str(observation.get("capabilities", "")).splitlines()
                if "cap_setuid" in line
            ))
            drafts.append({
                "phase": "enumeration",
                "action": "Enumerate the foothold identity and Linux file capabilities.",
                "input": "Established SSH foothold.",
                "result": (
                    "Identified a cap_setuid-enabled executable: "
                    + ", ".join(capability_paths)
                    + "."
                ),
                "target": target,
                "prerequisites": ("Established SSH foothold.",),
                "commands": commands((*host_info, *capability_observations)),
                "evidence": artifacts((*host_info, *capability_observations)),
            })

        privilege_proof = [
            item
            for item in postex
            if item[1].get("type") == "privesc_path_identified"
            and item[1].get("euid") == 0
        ]
        if capability_observations and privilege_proof:
            drafts.append({
                "phase": "privilege_escalation",
                "action": (
                    "Invoke the observed cap_setuid-enabled interpreter to set EUID "
                    "0 and read only the root objective proof."
                ),
                "input": "Verified cap_setuid capability on the enumerated executable.",
                "result": "EUID 0 was observed and the root objective proof was persisted.",
                "target": target,
                "prerequisites": (
                    "Established local foothold.",
                    "Verified cap_setuid capability.",
                ),
                "commands": commands(privilege_proof),
                "evidence": artifacts(privilege_proof),
            })

        cleanup = [
            event
            for event in event_list
            if event.get("event_type") == "cleanup_completed"
            and isinstance(event.get("payload"), dict)
        ]
        if cleanup:
            summary = self._sanitize(
                _string(cleanup[-1]["payload"], "description", "summary"),
                options,
            )
            drafts.append({
                "phase": "cleanup",
                "action": "Verify engagement cleanup and retained local evidence.",
                "input": "Completed objective and persisted engagement dossier.",
                "result": summary or "Cleanup completion was persisted.",
                "target": target,
                "prerequisites": ("Completed target-facing workflow.",),
                "commands": (),
                "evidence": (),
            })

        artifact_timestamps: dict[str, str] = {}
        for event in event_list:
            payload = event.get("payload")
            timestamp = event.get("timestamp")
            if (
                event.get("event_type") == "evidence_collected"
                and isinstance(payload, dict)
                and isinstance(payload.get("artifact"), str)
                and isinstance(timestamp, str)
            ):
                artifact_timestamps.setdefault(payload["artifact"], timestamp)
        cleanup_timestamp = next(
            (
                str(event["timestamp"])
                for event in reversed(event_list)
                if event.get("event_type") == "cleanup_completed"
                and event.get("timestamp")
            ),
            "",
        )
        fallback_timestamp = next(
            (
                str(event["timestamp"])
                for event in event_list
                if event.get("timestamp")
            ),
            "persisted-order",
        )
        for draft in drafts:
            draft["timestamp"] = next(
                (
                    artifact_timestamps[name]
                    for name in draft["evidence"]
                    if name in artifact_timestamps
                ),
                cleanup_timestamp or fallback_timestamp,
            )
            draft["interpretation"] = self._attack_step_interpretation(
                str(draft["phase"]),
                str(draft["action"]),
            )

        return tuple(
            AttackStep(
                step_id=f"step-{index:02d}",
                next_step_id=(
                    f"step-{index + 1:02d}"
                    if index < len(drafts)
                    else None
                ),
                **draft,
            )
            for index, draft in enumerate(drafts, start=1)
        )

    @staticmethod
    def _build_semantic_findings(
        events: Iterable[dict[str, Any]],
        evidence: tuple[ReportEvidence, ...],
        attack_steps: tuple[AttackStep, ...],
        target_hosts: tuple[str, ...],
    ) -> tuple[ReportFinding, ...]:
        """Create only the three evidence-chain findings accepted by this vertical."""
        event_list = list(events)
        target = target_hosts[0] if target_hosts else None
        evidence_names = {item.filename for item in evidence}

        def matching(*types: str) -> list[tuple[dict[str, Any], dict[str, Any]]]:
            selected = set(types)
            items: list[tuple[dict[str, Any], dict[str, Any]]] = []
            for event in event_list:
                payload = event.get("payload")
                if (
                    event.get("event_type") != "evidence_collected"
                    or not isinstance(payload, dict)
                    or payload.get("evidence_type") not in selected
                    or not isinstance(payload.get("observation_data"), dict)
                ):
                    continue
                items.append((payload, payload["observation_data"]))
            return items

        def artifacts(items: Iterable[tuple[dict[str, Any], dict[str, Any]]]) -> tuple[str, ...]:
            return tuple(dict.fromkeys(
                str(payload["artifact"])
                for payload, _ in items
                if payload.get("artifact") in evidence_names
            ))

        def step_ids(*phases: str) -> tuple[str, ...]:
            selected = set(phases)
            return tuple(step.step_id for step in attack_steps if step.phase in selected)

        references = [
            item
            for item in matching("web_object_reference")
            if item[1].get("status_code") == 200
            and (
                item[1].get("download_candidate") is True
                or "pcap" in str(item[1].get("content_type", "")).casefold()
            )
        ]
        downloads = matching("web_artifact")
        credentials = matching("credential_material")
        foothold = matching("foothold_established")
        postex = matching("postex")
        capability = [
            item
            for item in postex
            if item[1].get("type") == "privilege_escalation"
            and "cap_setuid" in str(item[1].get("capabilities", ""))
        ]
        root_proof = [
            item
            for item in postex
            if item[1].get("type") == "privesc_path_identified"
            and item[1].get("euid") == 0
        ]
        findings: list[ReportFinding] = []

        if references and downloads:
            urls = tuple(dict.fromkeys(
                str(observation["url"])
                for _, observation in (*references, *downloads)
                if observation.get("url")
            ))
            findings.append(ReportFinding(
                finding_id="ARIADNE-WEB-001",
                title="Numeric object reference exposes packet-capture data",
                severity="high",
                target=target,
                description=(
                    "An evidence-derived numeric download reference returned a "
                    "packet capture and allowed the object to be persisted."
                ),
                affected_assets=urls or ((target,) if target else ()),
                prerequisites=(
                    "Network access to the in-scope HTTP service.",
                    "Knowledge or enumeration of a numeric object identifier.",
                ),
                procedure=step_ids("exploitation"),
                impact=(
                    "An unauthorised user can retrieve packet captures containing "
                    "sensitive recorded traffic."
                ),
                cwe="CWE-639 / CWE-200",
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                cvss_score=7.5,
                evidence=artifacts((*references, *downloads)),
                remediation=(
                    "Enforce server-side authorization for every capture object.",
                    "Replace predictable numeric identifiers with opaque identifiers.",
                    "Do not expose packet captures through unauthenticated routes.",
                ),
            ))

        if downloads and credentials and foothold:
            findings.append(ReportFinding(
                finding_id="ARIADNE-CRED-001",
                title="Plaintext credentials disclosed through captured traffic",
                severity="critical",
                target=target,
                description=(
                    "The downloaded packet capture contained plaintext FTP "
                    "credential material. The protected reference successfully "
                    "established an SSH foothold; credential values remain redacted."
                ),
                affected_assets=tuple(
                    item for item in (target, "downloaded PCAP", "FTP/SSH services")
                    if item
                ),
                prerequisites=(
                    "Access to the exposed packet capture.",
                    "Ability to inspect FTP or HTTP Basic authentication fields.",
                ),
                procedure=step_ids("foothold"),
                impact=(
                    "Recovered credentials provide authenticated shell access and "
                    "expose the user-level objective."
                ),
                cwe="CWE-319",
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                cvss_score=9.8,
                evidence=artifacts((*downloads, *credentials, *foothold)),
                remediation=(
                    "Disable plaintext FTP and require an encrypted transfer protocol.",
                    "Rotate every credential present in historical packet captures.",
                    "Prevent capture files containing authentication data from being published.",
                    "Do not reuse service credentials for interactive SSH access.",
                ),
            ))

        if foothold and capability and root_proof:
            capability_paths = tuple(dict.fromkeys(
                line.split("=", 1)[0].strip()
                for _, observation in capability
                for line in str(observation.get("capabilities", "")).splitlines()
                if "cap_setuid" in line
            ))
            findings.append(ReportFinding(
                finding_id="ARIADNE-PRIV-001",
                title="cap_setuid interpreter enables local privilege escalation",
                severity="high",
                target=target,
                description=(
                    "A general-purpose interpreter had cap_setuid and was verified "
                    "to obtain EUID 0 from the established unprivileged foothold."
                ),
                affected_assets=tuple(
                    item for item in (target, *capability_paths) if item
                ),
                prerequisites=(
                    "Authenticated unprivileged local access.",
                    "Execution permission on the capability-enabled interpreter.",
                ),
                procedure=tuple(
                    step.step_id
                    for step in attack_steps
                    if (
                        "capabilities" in step.action.casefold()
                        or step.phase == "privilege_escalation"
                    )
                ),
                impact=(
                    "Any local user able to execute the interpreter can obtain root "
                    "privileges and access root-owned data."
                ),
                cwe="CWE-250 / CWE-269",
                cvss_vector="CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
                cvss_score=7.8,
                evidence=artifacts((*foothold, *capability, *root_proof)),
                remediation=(
                    "Remove cap_setuid from general-purpose interpreters.",
                    "Grant narrowly scoped privileges only to dedicated, audited binaries.",
                    "Audit filesystem capabilities regularly and alert on unexpected changes.",
                ),
            ))

        return tuple(findings)

    @staticmethod
    def _evidence_caption(payload: dict[str, Any]) -> str:
        """Return a concise human label without inventing artifact content."""
        evidence_type = str(payload.get("evidence_type") or "evidence")
        observation = payload.get("observation_data")
        observation_type = (
            str(observation.get("type") or "")
            if isinstance(observation, dict)
            else ""
        )
        artifact = str(payload.get("artifact") or "")
        if artifact.endswith(".download"):
            return "Verified packet-capture artifact"
        if observation_type in {"linux_host_info", "host_info_collected"}:
            return "Foothold identity enumeration"
        if observation_type == "privilege_escalation":
            return "Linux file-capability enumeration"
        if observation_type == "privesc_path_identified":
            return "EUID 0 privilege proof"
        labels = {
            "preflight_passed": "Preflight and authorization boundary evidence",
            "port_open": "TCP service discovery transcript",
            "service_fingerprinted": "Service fingerprint transcript",
            "protocol_routed": "Protocol routing decision",
            "research_complete": "Version-bound vulnerability research",
            "exploit_candidate": "Exploit candidate research",
            "httpx": "HTTP endpoint probe",
            "web_technologies": "Web technology fingerprint",
            "web_title": "HTTP title observation",
            "curl": "Bounded HTTP request transcript",
            "web_paths": "Same-host web path enumeration",
            "web_object_reference": "Numeric object-reference validation",
            "web_artifact": "Verified packet-capture download metadata",
            "credential_material": "PCAP credential analysis (values redacted)",
            "foothold_established": "Authenticated SSH foothold verification",
            "linux_host_info": "Foothold identity enumeration",
            "host_info_collected": "Host identity evidence",
            "postex": "Local privilege-escalation evidence",
        }
        return labels.get(
            evidence_type,
            evidence_type.replace("_", " ").strip().title() or "Evidence artifact",
        )

    def _evidence_excerpt(
        self,
        content: bytes,
        options: ReportOptions,
    ) -> str | None:
        """Return a bounded, redacted text preview for a report caption."""
        if not content or b"\x00" in content[:2048]:
            return None
        try:
            decoded = content.decode("utf-8")
        except UnicodeDecodeError:
            return None
        compact = "\n".join(
            line.rstrip()
            for line in decoded.splitlines()
            if line.strip()
        ).strip()
        if not compact:
            return None
        sanitized = self._sanitize(compact, options)
        if len(sanitized) > 480:
            return sanitized[:477].rstrip() + "..."
        return sanitized

    @staticmethod
    def _attack_step_interpretation(phase: str, action: str) -> str:
        """Explain why an observed step justified the next evidence-driven step."""
        normalized = action.casefold()
        if phase == "discovery":
            return (
                "The reachable services established the bounded attack surface and "
                "justified protocol-specific enumeration."
            )
        if "fingerprint" in normalized:
            return (
                "The observed HTTP stack made same-host content enumeration the "
                "next proportionate action."
            )
        if "web content" in normalized:
            return (
                "Crawler outcomes were kept distinct from findings; the bounded "
                "fallback preserved coverage without changing scope."
            )
        if "object reference" in normalized:
            return (
                "Successful retrieval linked predictable object access to a real "
                "sensitive artifact, supporting a validated data-exposure finding."
            )
        if "pcap" in normalized:
            return (
                "Plaintext authentication material converted the exposed capture "
                "from passive disclosure into a target-bound access hypothesis."
            )
        if "authenticate to ssh" in normalized:
            return (
                "Successful authentication proved credential reuse and established "
                "the unprivileged foothold required for local enumeration."
            )
        if "capabilities" in normalized:
            return (
                "A general-purpose cap_setuid interpreter crossed a local privilege "
                "boundary and justified a minimal EUID verification."
            )
        if phase == "privilege_escalation":
            return (
                "Observed EUID 0 and the root-objective proof established full target "
                "compromise without requiring persistence."
            )
        if phase == "cleanup":
            return (
                "The run retained only local evidence and recorded the final cleanup "
                "state after both objectives were addressed."
            )
        return "This persisted result determined the next evidence-driven action."

    def _build_compromised(
        self,
        events: Iterable[dict[str, Any]],
        attack_steps: tuple[AttackStep, ...],
        target_hosts: tuple[str, ...],
        options: ReportOptions,
    ) -> tuple[str, ...]:
        """Summarize proven access from lifecycle events and semantic steps."""
        values = list(self._event_texts(
            events,
            {"initial_access", "access_validated", "host_compromised"},
            ("description", "summary", "target", "asset", "user"),
            options,
        ))
        target = target_hosts[0] if target_hosts else "in-scope target"
        if any("ssh foothold" in step.result.casefold() for step in attack_steps):
            values.append(f"{target}: authenticated SSH foothold (unprivileged).")
        if any(
            step.phase == "privilege_escalation"
            and "euid 0" in step.result.casefold()
            for step in attack_steps
        ):
            values.append(f"{target}: root control proven by observed EUID 0.")
        return tuple(dict.fromkeys(values))

    def _build_objectives(
        self,
        run: RunHandle,
        events: list[dict[str, Any]],
        options: ReportOptions,
    ) -> tuple[ReportObjective, ...]:
        completions: list[dict[str, Any]] = []
        for event in events:
            if event.get("event_type") == "objective_completed":
                payload = event.get("payload")
                completions.append(payload if isinstance(payload, dict) else {})

        objectives: list[ReportObjective] = []
        for objective in run.snapshot.objectives:
            matching = [
                payload for payload in completions
                if payload.get("objective_kind") == objective.kind
                or (
                    objective.description
                    and payload.get("description") == objective.description
                )
            ]
            if not matching and len(run.snapshot.objectives) == 1 and completions:
                matching = [completions[0]]
            completion = matching[0] if matching else {}
            proof = _string(
                completion,
                "proof_sha256",
                "proof",
                "result",
                "description",
            )
            completion_evidence = (
                proof
                if proof and _SHA256_RE.fullmatch(proof)
                else self._sanitize(proof, options)
            )
            flag_value = None
            if (
                options.include_flags
                and objective.kind in {"user_flag", "root_flag"}
                and matching
            ):
                flag_value = resolve_objective_flag(
                    run.path,
                    objective.kind,
                    completion.get("value_ref"),
                    completion.get("proof_sha256") or completion.get("proof"),
                )
            objectives.append(
                ReportObjective(
                    kind=objective.kind,
                    description=self._sanitize(objective.description, options),
                    completed=bool(matching),
                    completion_evidence=completion_evidence or None,
                    flag_value=flag_value,
                    flag_value_available=bool(
                        matching
                        and isinstance(completion.get("value_ref"), str)
                        and completion["value_ref"].strip()
                    ),
                ),
            )
        return tuple(objectives)

    def _build_lifecycle(
        self,
        events: Iterable[dict[str, Any]],
        options: ReportOptions,
    ) -> tuple[ReportLifecycleEntry, ...]:
        entries: list[ReportLifecycleEntry] = []
        for event in events:
            event_type = event.get("event_type")
            payload = event.get("payload")
            if event_type not in _ACTIVITY_EVENT_TYPES or not isinstance(payload, dict):
                continue
            summary = _string(
                payload,
                "summary",
                "description",
                "finding",
                "title",
                "reason",
            )
            if summary is None and event_type == "plan_executed":
                action = _string(payload, "action")
                operation = _string(payload, "operation")
                summary = ":".join(item for item in (action, operation) if item)
            sanitized = self._sanitize(summary, options)
            if not sanitized:
                continue
            timestamp = event.get("timestamp")
            entries.append(
                ReportLifecycleEntry(
                    event_type=str(event_type),
                    summary=sanitized,
                    timestamp=str(timestamp) if timestamp else None,
                    target=self._optional_sanitized(payload, "target", options),
                    status=(
                        self._optional_sanitized(payload, "status", options)
                        or self._optional_sanitized(payload, "boundary", options)
                    ),
                ),
            )
        return tuple(entries)

    def _event_texts(
        self,
        events: Iterable[dict[str, Any]],
        event_types: set[str],
        keys: tuple[str, ...],
        options: ReportOptions,
    ) -> tuple[str, ...]:
        values: list[str] = []
        for event in events:
            if event.get("event_type") not in event_types:
                continue
            payload = event.get("payload")
            if not isinstance(payload, dict):
                continue
            value = self._sanitize(_string(payload, *keys), options)
            if value and value not in values:
                values.append(value)
        return tuple(values)

    def _commands(
        self,
        events: Iterable[dict[str, Any]],
        options: ReportOptions,
    ) -> tuple[str, ...]:
        commands: list[str] = []
        for event in events:
            payload = event.get("payload")
            if not isinstance(payload, dict):
                continue
            raw_command = payload.get("command_redacted")
            if isinstance(raw_command, (list, tuple)):
                command_value = shlex.join(str(part) for part in raw_command)
            else:
                command_value = _string(payload, "command")
            command = self._sanitize(command_value, options)
            if command and command not in commands:
                commands.append(command)
        return tuple(commands)

    @staticmethod
    def _risk_counts(findings: tuple[ReportFinding, ...]) -> dict[str, int]:
        counts = dict.fromkeys(_SEVERITIES, 0)
        for finding in findings:
            if finding.status == "validated" and finding.severity in counts:
                counts[finding.severity] += 1
        return counts

    @staticmethod
    def _generated_at(run: RunHandle, events: list[dict[str, Any]]) -> str:
        for event in reversed(events):
            timestamp = event.get("timestamp")
            if isinstance(timestamp, str) and timestamp:
                return timestamp
        return run.snapshot.confirmed_at.isoformat()

    def _optional_sanitized(
        self,
        payload: dict[str, Any],
        key: str,
        options: ReportOptions,
    ) -> str | None:
        value = self._sanitize(_string(payload, key), options)
        return value or None

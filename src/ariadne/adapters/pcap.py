"""Bounded packet-capture inspection with secret-safe credential references."""

from __future__ import annotations

import base64
import csv
import hashlib
import hmac
import json
import re
from pathlib import Path
from typing import ClassVar
from uuid import uuid4

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
from ariadne.core.observations import Observation

_PCAP_FILTER = (
    'ftp.request.command == "USER" || ftp.request.command == "PASS" || '
    "http.authorization"
)


class PcapAdapter:
    name: ClassVar[str] = "pcap"

    async def probe(self, runtime: Runtime) -> ToolProbe:
        return ToolProbe(available=True)

    def plan(self, action: PlannedAction, context: AdapterContext) -> ProcessSpec:
        if action.operation != "extract_plaintext_credentials":
            raise AdapterError(
                "Unknown packet-capture operation. "
                "Supported: extract_plaintext_credentials"
            )
        if context.run_root is None:
            raise AdapterError("Packet inspection requires a durable run root")
        artifact = action.inputs.get("artifact")
        digest = action.inputs.get("sha256")
        if (
            not isinstance(artifact, str)
            or not artifact
            or Path(artifact).name != artifact
        ):
            raise AdapterError("artifact must be one tracked artifact filename")
        path = (context.run_root.resolve() / "artifacts" / artifact).resolve()
        artifact_root = (context.run_root.resolve() / "artifacts").resolve()
        try:
            path.relative_to(artifact_root)
        except ValueError as exc:
            raise AdapterError("artifact is outside the engagement store") from exc
        if not path.is_file():
            raise AdapterError("artifact is missing from the engagement store")
        actual = hashlib.sha256(path.read_bytes()).hexdigest()
        if not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest):
            raise AdapterError("artifact digest is missing or malformed")
        if not hmac.compare_digest(actual, digest):
            raise AdapterError("artifact digest does not match persisted evidence")
        return ProcessSpec(
            argv=(
                "tshark",
                "-r",
                str(path),
                "-Y",
                _PCAP_FILTER,
                "-T",
                "fields",
                "-E",
                "separator=\t",
                "-E",
                "quote=d",
                "-E",
                "occurrence=f",
                "-e",
                "ftp.request.command",
                "-e",
                "ftp.request.arg",
                "-e",
                "http.authorization",
            ),
            timeout_seconds=60,
            max_output_bytes=2 * 1024 * 1024,
        )

    async def execute(self, spec: ProcessSpec, runtime: Runtime) -> ProcessResult:
        raw = await runtime.run(spec)
        if raw.exit_code != 0:
            return raw
        records = self._extract(raw.stdout)
        artifact = Path(spec.argv[spec.argv.index("-r") + 1]).resolve()
        run_root = artifact.parent.parent
        secret_root = run_root / "secrets"
        secret_root.mkdir(mode=0o700, exist_ok=True)
        safe_records: list[dict[str, str]] = []
        for username, password, protocol in records[:5]:
            identifier = hashlib.sha256(
                f"{protocol}\0{username}\0{password}".encode()
            ).hexdigest()[:20]
            secret = secret_root / f"credential_{identifier}.secret"
            if not secret.exists():
                secret.write_text(password, encoding="utf-8")
            secret.chmod(0o600)
            safe_records.append(
                {
                    "username": username,
                    "credential_ref": str(secret.relative_to(run_root)),
                    "protocol": protocol,
                }
            )
        sanitized = "\n".join(json.dumps(record, sort_keys=True) for record in safe_records)
        return raw.model_copy(update={"stdout": sanitized, "stderr": raw.stderr[:4096]})

    @staticmethod
    def _extract(stdout: str) -> list[tuple[str, str, str]]:
        records: list[tuple[str, str, str]] = []
        ftp_user = ""
        for row in csv.reader(stdout.splitlines(), delimiter="\t", quotechar='"'):
            row.extend("" for _ in range(max(0, 3 - len(row))))
            command, argument, authorization = row[:3]
            if command.casefold() == "user" and argument:
                ftp_user = argument
            elif command.casefold() == "pass" and ftp_user and argument:
                records.append((ftp_user, argument, "ftp"))
                ftp_user = ""
            if authorization.casefold().startswith("basic "):
                try:
                    decoded = base64.b64decode(
                        authorization.split(maxsplit=1)[1],
                        validate=True,
                    ).decode("utf-8")
                    username, password = decoded.split(":", 1)
                except (ValueError, UnicodeDecodeError):
                    continue
                if username and password:
                    records.append((username, password, "http_basic"))
        return records

    def parse(self, result: ProcessResult) -> tuple[Observation, ...]:
        return ()

    def parse_for_spec(
        self,
        result: ProcessResult,
        target: TargetSpec,
        spec: ProcessSpec,
    ) -> tuple[Observation, ...]:
        observations: list[Observation] = []
        for line in result.stdout.splitlines():
            try:
                record = json.loads(line)
            except json.JSONDecodeError:
                continue
            if not isinstance(record, dict):
                continue
            username = record.get("username")
            credential_ref = record.get("credential_ref")
            protocol = record.get("protocol")
            if not all(isinstance(value, str) and value for value in (
                username,
                credential_ref,
                protocol,
            )):
                continue
            observations.append(
                Observation(
                    observation_id=uuid4(),
                    target=target,
                    source="credential_material",
                    data={
                        "type": "credential_material",
                        "username": username,
                        "credential_ref": credential_ref,
                        "protocol": protocol,
                        "secret_persisted": True,
                        "secret_storage": "protected_local_reference",
                    },
                )
            )
        return tuple(observations)

    def classify(
        self,
        result: ProcessResult,
        observations: tuple[Observation, ...],
    ) -> ExecutionClassification:
        if result.timed_out or result.exit_code != 0:
            return ExecutionClassification(
                kind="failure",
                confidence=0.8,
                summary="Packet-capture inspection failed",
            )
        if observations:
            return ExecutionClassification(
                kind="success",
                confidence=0.9,
                summary=f"Recovered {len(observations)} protected credential reference(s)",
            )
        return ExecutionClassification(
            kind="unknown",
            confidence=0.6,
            summary="Capture contained no supported plaintext authentication exchange",
        )

    async def collect(
        self,
        result: ProcessResult,
        collector: object,
    ) -> tuple[str, ...]:
        return ()

    async def cleanup(self, context: AdapterContext) -> CleanupResult:
        return CleanupResult(
            success=True,
            details="Packet inspection created only local protected credential references",
        )

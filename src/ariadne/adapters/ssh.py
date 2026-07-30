"""Credential-referenced SSH foothold confirmation."""

from __future__ import annotations

import hashlib
import json
import re
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
from ariadne.adapters.ssh_support import ssh_process_spec
from ariadne.core.engagement import TargetSpec
from ariadne.core.observations import Observation
from ariadne.store.run_store import validate_objective_flag_value

SSH_FOOTHOLD_COMMAND = (
    "python3 -c 'import hashlib,json,os,pathlib,pwd;"
    "u=pwd.getpwuid(os.getuid()).pw_name;"
    "p=pathlib.Path.home()/\"user.txt\";"
    "v=p.read_text().strip() if p.is_file() else \"\";"
    "h=hashlib.sha256(v.encode()).hexdigest() if v else \"\";"
    "print(json.dumps({\"uid\":os.getuid(),\"gid\":os.getgid(),"
    "\"username\":u,\"user_flag\":v,\"user_flag_sha256\":h}))'"
)


class SshAdapter:
    name: ClassVar[str] = "ssh"

    async def probe(self, runtime: Runtime) -> ToolProbe:
        return ToolProbe(available=True)

    def plan(self, action: PlannedAction, context: AdapterContext) -> ProcessSpec:
        if action.operation != "authenticate":
            raise AdapterError(
                f"Unknown SSH operation: {action.operation!r}. Supported: authenticate"
            )
        return ssh_process_spec(
            inputs=action.inputs,
            context=context,
            remote_command=SSH_FOOTHOLD_COMMAND,
            timeout_seconds=30,
            max_output_bytes=64 * 1024,
        )

    async def execute(self, spec: ProcessSpec, runtime: Runtime) -> ProcessResult:
        return await runtime.run(spec)

    def parse(self, result: ProcessResult) -> tuple[Observation, ...]:
        return ()

    def parse_for_spec(
        self,
        result: ProcessResult,
        target: TargetSpec,
        spec: ProcessSpec,
    ) -> tuple[Observation, ...]:
        if result.exit_code != 0:
            return ()
        try:
            payload = json.loads(result.stdout.strip())
        except (json.JSONDecodeError, TypeError):
            return ()
        if (
            not isinstance(payload, dict)
            or isinstance(payload.get("uid"), bool)
            or not isinstance(payload.get("uid"), int)
            or not isinstance(payload.get("username"), str)
        ):
            return ()
        data: dict[str, object] = {
            "type": "foothold_established",
            "username": payload["username"],
            "uid": payload["uid"],
            "gid": payload.get("gid"),
            "method": "ssh_password",
        }
        proof = payload.get("user_flag_sha256")
        value = payload.get("user_flag")
        if (
            isinstance(proof, str)
            and re.fullmatch(r"[0-9a-f]{64}", proof)
            and isinstance(value, str)
        ):
            try:
                encoded = validate_objective_flag_value(value)
            except ValueError:
                encoded = b""
            if encoded and hashlib.sha256(encoded).hexdigest() == proof:
                data["objective_proof"] = {
                    "kind": "user_flag",
                    "description": "Target-local user objective was readable",
                    "proof_sha256": proof,
                    "value": value,
                }
        return (
            Observation(
                observation_id=uuid4(),
                target=target,
                source="foothold_established",
                data=data,
            ),
        )

    def classify(
        self,
        result: ProcessResult,
        observations: tuple[Observation, ...],
    ) -> ExecutionClassification:
        if result.timed_out:
            return ExecutionClassification(
                kind="failure",
                confidence=0.8,
                summary="SSH authentication timed out",
            )
        if result.exit_code != 0:
            return ExecutionClassification(
                kind="failure",
                confidence=0.9,
                summary="SSH credential confirmation failed",
            )
        if observations:
            return ExecutionClassification(
                kind="success",
                confidence=0.95,
                summary="SSH foothold confirmed using a protected credential reference",
            )
        return ExecutionClassification(
            kind="unknown",
            confidence=0.4,
            summary="SSH returned no structured foothold proof",
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
            details="SSH confirmation created no remote artifacts",
        )
